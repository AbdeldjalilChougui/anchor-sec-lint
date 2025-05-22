//! Lightweight model of an Anchor program extracted from Rust source with `syn`.
use proc_macro2::{Span, TokenStream, TokenTree};
use quote::ToTokens;
use std::path::{Path, PathBuf};
use syn::{spanned::Spanned, Attribute, Expr, Fields, Item, Meta, Type};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Loc {
    pub line: usize,
    pub column: usize,
}

impl Loc {
    pub fn of(span: Span) -> Self {
        let s = span.start();
        Loc { line: s.line, column: s.column + 1 }
    }
}

/// What kind of Anchor wrapper a field in an `Accounts` struct uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldKind {
    Signer,
    /// `Account<'info, T>` / `InterfaceAccount<'info, T>` / `AccountLoader<'info, T>`
    Account(String),
    SystemAccount,
    AccountInfo,
    UncheckedAccount,
    Program,
    Sysvar,
    Other(String),
}

/// One `key = value` (or bare flag) inside `#[account(...)]`.
#[derive(Debug, Clone)]
pub struct Constraint {
    pub key: String,
    pub value: Option<TokenStream>,
}

#[derive(Debug, Clone)]
pub struct AccountField {
    pub name: String,
    pub kind: FieldKind,
    pub constraints: Vec<Constraint>,
    pub docs: Vec<String>,
    pub loc: Loc,
}

impl AccountField {
    pub fn has(&self, key: &str) -> bool {
        self.constraints.iter().any(|c| c.key == key)
    }
    pub fn get(&self, key: &str) -> Option<&TokenStream> {
        self.constraints.iter().find(|c| c.key == key).and_then(|c| c.value.as_ref())
    }
    pub fn values<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a TokenStream> + 'a {
        self.constraints.iter().filter(move |c| c.key == key).filter_map(|c| c.value.as_ref())
    }
    pub fn is_mut(&self) -> bool {
        self.has("mut") || self.has("init") || self.has("init_if_needed")
    }
    pub fn has_check_doc(&self) -> bool {
        self.docs.iter().any(|d| d.trim_start().starts_with("CHECK"))
    }
}

#[derive(Debug, Clone)]
pub struct AccountsStruct {
    pub name: String,
    pub fields: Vec<AccountField>,
    /// Names of `#[instruction(...)]` arguments.
    pub ix_args: Vec<String>,
    pub loc: Loc,
}

/// A `#[account]` data struct and its fields (name, type as string).
#[derive(Debug, Clone)]
pub struct StateStruct {
    pub name: String,
    pub fields: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path: PathBuf,
    pub ast: syn::File,
    pub accounts: Vec<AccountsStruct>,
    pub state: Vec<StateStruct>,
}

pub fn parse_file(path: &Path, src: &str) -> syn::Result<SourceFile> {
    let ast = syn::parse_file(src)?;
    let mut accounts = vec![];
    let mut state = vec![];
    collect(&ast.items, &mut accounts, &mut state);
    Ok(SourceFile { path: path.to_path_buf(), ast, accounts, state })
}

fn collect(items: &[Item], accounts: &mut Vec<AccountsStruct>, state: &mut Vec<StateStruct>) {
    for item in items {
        match item {
            Item::Struct(s) => {
                if derives(&s.attrs, "Accounts") {
                    accounts.push(accounts_struct(s));
                } else if s.attrs.iter().any(|a| path_is(a, "account") || path_is(a, "zero_copy")) {
                    let fields = match &s.fields {
                        Fields::Named(n) => n
                            .named
                            .iter()
                            .map(|f| {
                                (f.ident.as_ref().unwrap().to_string(), type_str(&f.ty))
                            })
                            .collect(),
                        _ => vec![],
                    };
                    state.push(StateStruct { name: s.ident.to_string(), fields });
                }
            }
            Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    collect(inner, accounts, state);
                }
            }
            _ => {}
        }
    }
}

fn path_is(a: &Attribute, name: &str) -> bool {
    a.path().segments.last().map(|s| s.ident == name).unwrap_or(false)
}

fn derives(attrs: &[Attribute], what: &str) -> bool {
    attrs.iter().filter(|a| path_is(a, "derive")).any(|a| {
        a.meta.to_token_stream().to_string().split(|c: char| !c.is_alphanumeric() && c != '_').any(|w| w == what)
    })
}

pub fn type_str(t: &Type) -> String {
    t.to_token_stream().to_string().replace(' ', "")
}

fn accounts_struct(s: &syn::ItemStruct) -> AccountsStruct {
    let mut ix_args = vec![];
    for a in s.attrs.iter().filter(|a| path_is(a, "instruction")) {
        if let Meta::List(l) = &a.meta {
            // `#[instruction(id: u64, title: String)]` -> ["id", "title"]
            let mut prev: Option<String> = None;
            for tt in l.tokens.clone() {
                match &tt {
                    TokenTree::Punct(p) if p.as_char() == ':' => {
                        if let Some(n) = prev.take() {
                            ix_args.push(n);
                        }
                    }
                    TokenTree::Ident(i) => prev = Some(i.to_string()),
                    _ => prev = None,
                }
            }
        }
    }
    let mut fields = vec![];
    if let Fields::Named(n) = &s.fields {
        for f in &n.named {
            let docs = f
                .attrs
                .iter()
                .filter(|a| path_is(a, "doc"))
                .filter_map(|a| match &a.meta {
                    Meta::NameValue(nv) => match &nv.value {
                        Expr::Lit(l) => match &l.lit {
                            syn::Lit::Str(s) => Some(s.value()),
                            _ => None,
                        },
                        _ => None,
                    },
                    _ => None,
                })
                .collect();
            let constraints = f
                .attrs
                .iter()
                .filter(|a| path_is(a, "account"))
                .flat_map(|a| match &a.meta {
                    Meta::List(l) => parse_constraints(l.tokens.clone()),
                    _ => vec![],
                })
                .collect();
            fields.push(AccountField {
                name: f.ident.as_ref().map(|i| i.to_string()).unwrap_or_default(),
                kind: field_kind(&f.ty),
                constraints,
                docs,
                loc: Loc::of(f.ident.as_ref().map(|i| i.span()).unwrap_or_else(|| f.span())),
            });
        }
    }
    AccountsStruct { name: s.ident.to_string(), fields, ix_args, loc: Loc::of(s.ident.span()) }
}

fn field_kind(t: &Type) -> FieldKind {
    let Type::Path(p) = t else { return FieldKind::Other(type_str(t)) };
    let Some(last) = p.path.segments.last() else { return FieldKind::Other(type_str(t)) };
    let inner = || -> String {
        if let syn::PathArguments::AngleBracketed(a) = &last.arguments {
            for g in &a.args {
                if let syn::GenericArgument::Type(t) = g {
                    let s = type_str(t);
                    return s.rsplit("::").next().unwrap_or(&s).to_string();
                }
            }
        }
        String::new()
    };
    match last.ident.to_string().as_str() {
        "Signer" => FieldKind::Signer,
        "Account" | "InterfaceAccount" | "AccountLoader" => FieldKind::Account(inner()),
        "SystemAccount" => FieldKind::SystemAccount,
        "AccountInfo" => FieldKind::AccountInfo,
        "UncheckedAccount" => FieldKind::UncheckedAccount,
        "Program" | "Interface" => FieldKind::Program,
        "Sysvar" => FieldKind::Sysvar,
        "Box" => {
            // Box<Account<'info, T>>
            if let syn::PathArguments::AngleBracketed(a) = &last.arguments {
                if let Some(syn::GenericArgument::Type(t)) = a.args.first() {
                    return field_kind(t);
                }
            }
            FieldKind::Other(type_str(t))
        }
        other => FieldKind::Other(other.to_string()),
    }
}

/// Split `mut, seeds = [a, b], bump, has_one = x @ Err` on top-level commas.
pub fn parse_constraints(ts: TokenStream) -> Vec<Constraint> {
    let mut out = vec![];
    let mut cur: Vec<TokenTree> = vec![];
    let flush = |cur: &mut Vec<TokenTree>, out: &mut Vec<Constraint>| {
        if cur.is_empty() {
            return;
        }
        // key is everything before the first lone '=' (handles `a::b = c`).
        let pos = cur.iter().enumerate().position(|(i, t)| {
            matches!(t, TokenTree::Punct(p) if p.as_char() == '=' && p.spacing() == proc_macro2::Spacing::Alone)
                && !matches!(cur.get(i.wrapping_sub(1)), Some(TokenTree::Punct(q)) if matches!(q.as_char(), '=' | '!' | '<' | '>'))
        });
        let (k, v) = match pos {
            Some(p) => (&cur[..p], Some(cur[p + 1..].iter().cloned().collect::<TokenStream>())),
            None => (&cur[..], None),
        };
        let key = k.iter().cloned().collect::<TokenStream>().to_string().replace(' ', "");
        out.push(Constraint { key, value: v });
        cur.clear();
    };
    for tt in ts {
        match &tt {
            TokenTree::Punct(p) if p.as_char() == ',' => flush(&mut cur, &mut out),
            _ => cur.push(tt),
        }
    }
    flush(&mut cur, &mut out);
    out
}

/// Elements of a `seeds = [...]` value.
pub fn seed_elements(v: &TokenStream) -> Vec<TokenStream> {
    let mut it = v.clone().into_iter();
    let Some(TokenTree::Group(g)) = it.next() else { return vec![] };
    let mut out = vec![];
    let mut cur = TokenStream::new();
    for tt in g.stream() {
        match &tt {
            TokenTree::Punct(p) if p.as_char() == ',' => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.extend([tt]),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// A seed is "static" when it does not depend on any account or argument:
/// byte-string literals and SCREAMING_CASE constants.
pub fn seed_is_static(seed: &TokenStream) -> bool {
    let s = seed.to_string();
    if s.starts_with("b\"") || s.starts_with("& b\"") || s.starts_with('"') {
        return true;
    }
    let ident: String = s.trim_start_matches('&').trim().chars().take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':').collect();
    let last = ident.rsplit("::").next().unwrap_or("");
    !last.is_empty()
        && last.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && s.trim_start_matches('&').trim().len() <= ident.len() + 12 // allows `.as_ref()`
}

/// Normalised shape of a seed list: literals/constants kept, dynamic parts as `*`.
pub fn seed_shape(seeds: &[TokenStream]) -> String {
    seeds
        .iter()
        .map(|s| if seed_is_static(s) { s.to_string().replace(' ', "") } else { "*".into() })
        .collect::<Vec<_>>()
        .join(",")
}

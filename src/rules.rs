//! The lint rules. Each rule is a heuristic; findings are hints for review,
//! not proofs of a vulnerability.
use crate::model::*;
use proc_macro2::TokenStream;
use serde::Serialize;
use std::collections::BTreeMap;
use syn::visit::Visit;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Note,
    Warning,
    Error,
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Note => "note",
            Level::Warning => "warning",
            Level::Error => "error",
        }
    }
}

pub struct RuleInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub short: &'static str,
    pub help: &'static str,
    pub level: Level,
}

pub const RULES: &[RuleInfo] = &[
    RuleInfo {
        id: "ASL001",
        name: "missing-signer",
        short: "Authority-like account is not required to sign",
        help: "Use `Signer<'info>` (or the `signer` constraint) for accounts whose consent the instruction relies on.",
        level: Level::Error,
    },
    RuleInfo {
        id: "ASL002",
        name: "unchecked-account",
        short: "AccountInfo/UncheckedAccount without a CHECK comment or owner/address check",
        help: "Document why it is safe with `/// CHECK:` and constrain it with `owner =`, `address =` or `seeds =`, or use a typed `Account<'info, T>`.",
        level: Level::Error,
    },
    RuleInfo {
        id: "ASL003",
        name: "weak-seeds-or-bump",
        short: "Hard-coded or user-supplied bump, non-canonical PDA derivation, or fully static init seeds",
        help: "Use `bump` (canonical, found by Anchor) on init and `bump = account.bump` afterwards; never trust a bump passed as an argument.",
        level: Level::Warning,
    },
    RuleInfo {
        id: "ASL004",
        name: "pda-seed-collision",
        short: "Two different account types can be derived from the same seed pattern",
        help: "Give every account type a distinct static prefix (e.g. b\"vault\", b\"config\") and avoid adjacent variable-length seeds.",
        level: Level::Warning,
    },
    RuleInfo {
        id: "ASL005",
        name: "missing-has-one",
        short: "Mutable account stores an authority pubkey that is never compared to the signer",
        help: "Add `has_one = <field>` (or an equivalent `constraint`/seed) so another signer cannot pass someone else's account.",
        level: Level::Error,
    },
    RuleInfo {
        id: "ASL006",
        name: "unchecked-arithmetic",
        short: "Arithmetic on account data without checked_* operations",
        help: "Use checked_add/checked_sub/checked_mul (or saturating_*) and return an error on overflow. `overflow-checks = true` only turns overflow into a panic.",
        level: Level::Warning,
    },
];

pub fn rule(id: &str) -> &'static RuleInfo {
    RULES.iter().find(|r| r.id == id).expect("known rule")
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: &'static str,
    pub level: Level,
    pub message: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
}

const ROLE_NAMES: &[&str] = &[
    "authority", "admin", "owner", "signer", "creator", "maker", "manager", "operator",
    "governor", "initializer", "update_authority", "mint_authority", "upgrade_authority",
];

fn is_role(name: &str) -> bool {
    ROLE_NAMES.contains(&name) || name.ends_with("_authority") || name.ends_with("_admin")
}

fn ts_mentions(ts: &TokenStream, ident: &str) -> bool {
    ts.to_string().split(|c: char| !(c.is_alphanumeric() || c == '_')).any(|w| w == ident)
}

pub fn lint_file(f: &SourceFile, all_files: &[SourceFile]) -> Vec<Finding> {
    let file = f.path.display().to_string();
    let mut out = vec![];
    let mut push = |id: &'static str, level: Option<Level>, loc: Loc, msg: String| {
        out.push(Finding {
            rule_id: id,
            level: level.unwrap_or(rule(id).level),
            message: msg,
            file: file.clone(),
            line: loc.line,
            column: loc.column,
        })
    };

    let state: BTreeMap<&str, &StateStruct> = all_files
        .iter()
        .flat_map(|f| f.state.iter())
        .map(|s| (s.name.as_str(), s))
        .collect();

    for s in &f.accounts {
        let has_signer = s.fields.iter().any(|x| x.kind == FieldKind::Signer || x.has("signer"));
        let mutates_state = s.fields.iter().any(|x| matches!(x.kind, FieldKind::Account(_)) && x.has("mut"));
        if mutates_state && !has_signer {
            push("ASL001", Some(Level::Warning), s.loc, format!(
                "`{}` mutates program accounts but no account is required to sign", s.name
            ));
        }

        for fld in &s.fields {
            let signs = fld.kind == FieldKind::Signer || fld.has("signer");

            // ASL001: authority-like field that does not sign. Raw AccountInfo /
            // UncheckedAccount authorities are always suspicious; a SystemAccount
            // (often just a recipient, e.g. the maker in an escrow `take`) only
            // when nobody else signs either.
            let raw = matches!(fld.kind, FieldKind::AccountInfo | FieldKind::UncheckedAccount);
            if is_role(&fld.name)
                && !signs
                && (raw || (fld.kind == FieldKind::SystemAccount && !has_signer))
            {
                push(
                    "ASL001",
                    None,
                    fld.loc,
                    format!("`{}.{}` looks like an authority but is not a Signer", s.name, fld.name),
                );
            }
            // ASL001: typed authority account matched by has_one, but nobody signs
            for v in fld.values("has_one") {
                let target = v.to_string().split_whitespace().next().unwrap_or("").to_string();
                if let Some(t) = s.fields.iter().find(|x| x.name == target) {
                    if is_role(&t.name) && matches!(t.kind, FieldKind::Account(_)) && !has_signer {
                        push("ASL001", None, t.loc, format!(
                            "`{}.{}` is matched by `has_one` on `{}` but never signs",
                            s.name, t.name, fld.name
                        ));
                    }
                }
            }

            // ASL002: unchecked accounts
            if matches!(fld.kind, FieldKind::AccountInfo | FieldKind::UncheckedAccount) {
                let constrained = ["owner", "address", "seeds", "constraint", "init", "init_if_needed", "zero"]
                    .iter()
                    .any(|k| fld.has(k));
                if !fld.has_check_doc() {
                    push("ASL002", None, fld.loc, format!(
                        "`{}.{}` is an unchecked account without a `/// CHECK:` explanation",
                        s.name, fld.name
                    ));
                } else if !constrained {
                    push("ASL002", Some(Level::Note), fld.loc, format!(
                        "`{}.{}` has a CHECK comment but no owner/address/seeds constraint; make sure its data is never trusted",
                        s.name, fld.name
                    ));
                }
            }

            // ASL003: bumps and seeds
            if let Some(b) = fld.get("bump") {
                let bs = b.to_string();
                if bs.chars().all(|c| c.is_ascii_digit() || c == ' ' || c == 'u' || c == '8') && bs.chars().any(|c| c.is_ascii_digit()) {
                    push("ASL003", Some(Level::Error), fld.loc, format!("`{}.{}` uses a hard-coded bump `{}`", s.name, fld.name, bs));
                } else if s.ix_args.iter().any(|a| a == bs.trim()) {
                    push("ASL003", None, fld.loc, format!(
                        "`{}.{}` takes its bump from instruction argument `{}`; a non-canonical bump can create a second valid address",
                        s.name, fld.name, bs.trim()
                    ));
                }
            }
            if fld.has("init") && !fld.has("seeds::program") {
                if let Some(seeds) = fld.get("seeds") {
                    let el = seed_elements(seeds);
                    if !el.is_empty() && el.iter().all(seed_is_static) {
                        push("ASL003", Some(Level::Note), fld.loc, format!(
                            "`{}.{}` is initialised from fully static seeds: a single global account, and whoever calls first initialises it",
                            s.name, fld.name
                        ));
                    }
                }
            }

            // ASL005: missing has_one
            if let FieldKind::Account(t) = &fld.kind {
                if fld.has("mut") && !fld.has("init") {
                    if let Some(st) = state.get(t.as_str()) {
                        for (fname, fty) in &st.fields {
                            if fty != "Pubkey" {
                                continue;
                            }
                            let Some(sig) = s.fields.iter().find(|x| &x.name == fname) else { continue };
                            if !(sig.kind == FieldKind::Signer || sig.has("signer")) {
                                continue;
                            }
                            let tied = fld.values("has_one").any(|v| ts_mentions(v, fname))
                                || fld.values("constraint").any(|v| ts_mentions(v, fname))
                                || fld.values("seeds").any(|v| ts_mentions(v, fname))
                                || fld.values("close").next().is_some() && fld.values("has_one").next().is_some();
                            if !tied {
                                push("ASL005", None, fld.loc, format!(
                                    "`{}.{}` ({}) stores `{}` and `{}` signs, but they are never compared (missing `has_one = {}`)",
                                    s.name, fld.name, t, fname, fname, fname
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // ASL004: seed collisions (across all files, reported once from the file of the later one)
    // and adjacent variable-length seeds.
    for s in &f.accounts {
        for fld in &s.fields {
            let (FieldKind::Account(t), Some(seeds)) = (&fld.kind, fld.get("seeds")) else { continue };
            if fld.has("seeds::program") {
                continue;
            }
            let el = seed_elements(seeds);
            let shape = seed_shape(&el);
            for w in el.windows(2) {
                let var = |x: &TokenStream| x.to_string().contains("as_bytes");
                if var(&w[0]) && var(&w[1]) {
                    push("ASL004", None, fld.loc, format!(
                        "`{}.{}` has two adjacent variable-length seeds; (\"ab\",\"c\") and (\"a\",\"bc\") derive the same address",
                        s.name, fld.name
                    ));
                }
            }
            'outer: for g in all_files {
                for s2 in &g.accounts {
                    for f2 in &s2.fields {
                        let (FieldKind::Account(t2), Some(seeds2)) = (&f2.kind, f2.get("seeds")) else { continue };
                        if f2.has("seeds::program") || t2 == t {
                            continue;
                        }
                        if seed_shape(&seed_elements(seeds2)) == shape {
                            push("ASL004", None, fld.loc, format!(
                                "`{}.{}` ({}) and `{}.{}` ({}) use the same seed pattern [{}]",
                                s.name, fld.name, t, s2.name, f2.name, t2, shape
                            ));
                            break 'outer;
                        }
                    }
                }
            }
        }
    }

    // ASL003 (code) + ASL006: walk function bodies
    let mut v = CodeVisitor { hits: vec![], in_test: false };
    v.visit_file(&f.ast);
    for (id, level, loc, msg) in v.hits {
        push(id, level, loc, msg);
    }

    out
}

struct CodeVisitor {
    hits: Vec<(&'static str, Option<Level>, Loc, String)>,
    in_test: bool,
}

fn involves_data(e: &syn::Expr) -> bool {
    use syn::Expr::*;
    match e {
        Field(_) | MethodCall(_) | Index(_) => true,
        Paren(p) => involves_data(&p.expr),
        Unary(u) => involves_data(&u.expr),
        Cast(c) => involves_data(&c.expr),
        Binary(b) => involves_data(&b.left) || involves_data(&b.right),
        _ => false,
    }
}

impl<'ast> Visit<'ast> for CodeVisitor {
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        let is_test = m.attrs.iter().any(|a| quote::ToTokens::to_token_stream(a).to_string().contains("test"));
        let prev = self.in_test;
        self.in_test |= is_test;
        syn::visit::visit_item_mod(self, m);
        self.in_test = prev;
    }
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if f.attrs.iter().any(|a| quote::ToTokens::to_token_stream(a).to_string().contains("test")) {
            return;
        }
        syn::visit::visit_item_fn(self, f);
    }
    fn visit_item_const(&mut self, _: &'ast syn::ItemConst) {}
    fn visit_expr_binary(&mut self, b: &'ast syn::ExprBinary) {
        use syn::BinOp::*;
        if !self.in_test {
            let op = match b.op {
                AddAssign(_) => Some("+="),
                SubAssign(_) => Some("-="),
                MulAssign(_) => Some("*="),
                Add(_) if involves_data(&b.left) || involves_data(&b.right) => Some("+"),
                Sub(_) if involves_data(&b.left) || involves_data(&b.right) => Some("-"),
                Mul(_) if involves_data(&b.left) || involves_data(&b.right) => Some("*"),
                _ => None,
            };
            if let Some(op) = op {
                use syn::spanned::Spanned;
                let text = quote::ToTokens::to_token_stream(b).to_string();
                self.hits.push((
                    "ASL006",
                    None,
                    Loc::of(b.span()),
                    format!("unchecked `{}` in `{}`", op, shorten(&text)),
                ));
            }
        }
        syn::visit::visit_expr_binary(self, b);
    }
    fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*c.func {
            if p.path.segments.last().map(|s| s.ident == "create_program_address").unwrap_or(false) && !self.in_test {
                use syn::spanned::Spanned;
                self.hits.push((
                    "ASL003",
                    None,
                    Loc::of(c.span()),
                    "create_program_address with a caller-chosen bump; prefer find_program_address or a stored canonical bump".into(),
                ));
            }
        }
        syn::visit::visit_expr_call(self, c);
    }
}

fn shorten(s: &str) -> String {
    let s = s.replace(" . ", ".").replace("( ", "(").replace(" )", ")");
    if s.len() > 80 { format!("{}…", &s[..s.char_indices().nth(77).map(|x| x.0).unwrap_or(s.len())]) } else { s }
}

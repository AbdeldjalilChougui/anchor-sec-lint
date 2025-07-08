# anchor-sec-lint

> **Not audited.** This is a heuristic linter. A clean report does not mean a program is safe,
> and some findings will be false positives. Use it as a review aid, never instead of an audit.

`anchor-sec-lint` is a static checker for [Anchor](https://www.anchor-lang.com/) programs. It
parses the Rust sources with `syn`, or reads an Anchor 0.30+ IDL, and flags common Solana
account-validation mistakes. It writes text, JSON, or **SARIF 2.1.0**, so the results can show
up in GitHub code scanning.

## Rules

| id | name | default | what it looks for |
|---|---|---|---|
| ASL001 | missing-signer | error | authority-like fields (`authority`, `admin`, `owner`, `*_authority`, ...) typed `AccountInfo`/`UncheckedAccount` instead of `Signer`; `SystemAccount` authorities when nothing signs; structs that mutate program accounts with no signer at all (warning) |
| ASL002 | unchecked-account | error | `AccountInfo`/`UncheckedAccount` without a `/// CHECK:` doc. A note when a CHECK exists but there is no `owner`/`address`/`seeds`/`constraint` |
| ASL003 | weak-seeds-or-bump | warning | hard-coded `bump = 254` (error), a `bump = <instruction arg>`, `create_program_address(...)` in code, and `init` from fully static seeds (note: first caller wins) |
| ASL004 | pda-seed-collision | warning | two **different account types** with the same seed shape (e.g. `[b"user", *]`), and adjacent variable-length seeds (`[a.as_bytes(), b.as_bytes()]`) |
| ASL005 | missing-has-one | error | a mutable `Account<T>` where `T` stores a `Pubkey` field whose name matches a `Signer` in the struct, with no `has_one`, `constraint` or seed tying them together |
| ASL006 | unchecked-arithmetic | warning | `+=`, `-=`, `*=` and `+ - *` on account data / method results outside `checked_*` (test modules and consts are skipped) |

IDL mode (`*.json`) runs the signer checks on instructions: authority-named accounts that are not
`signer`, and instructions that write accounts but require no signer.

## Install

Prebuilt binaries (Linux x86_64/aarch64, macOS x86_64/arm64, Windows x86_64) are
attached to every [GitHub release](https://github.com/AbdeldjalilChougui/anchor-sec-lint/releases), with installers:

```sh
# Linux / macOS
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/AbdeldjalilChougui/anchor-sec-lint/releases/latest/download/anchor-sec-lint-installer.sh | sh
```

```powershell
# Windows
powershell -ExecutionPolicy Bypass -c "irm https://github.com/AbdeldjalilChougui/anchor-sec-lint/releases/latest/download/anchor-sec-lint-installer.ps1 | iex"
```

Or build from crates.io:

```sh
cargo install anchor-sec-lint --locked
```

### GitHub Action

```yaml
- uses: actions/checkout@v5
- uses: AbdeldjalilChougui/anchor-sec-lint@v0.1.0
  with:
    path: programs          # space-separated files/dirs and/or IDL .json files
    fail-on: warning        # error (default) | warning | note | never
```

Upload the findings to GitHub code scanning (they appear under Security → Code scanning
and as annotations on pull requests):

```yaml
name: anchor-sec-lint
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: AbdeldjalilChougui/anchor-sec-lint@v0.1.0
        with:
          path: programs
          format: sarif
          output: anchor-sec-lint.sarif
          fail-on: never    # let code scanning report; set to error to also fail the job
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: anchor-sec-lint.sarif
          category: anchor-sec-lint
```

Inputs: `path`, `format` (`text`/`json`/`sarif`), `output`, `fail-on`, `base` (SARIF path
prefix to strip, default the workspace), `args` (extra flags), `version` (defaults to the
action tag). SARIF URIs are made repo-relative automatically.

## Quick start

```bash
cargo install --path .
anchor-sec-lint programs/                    # text report, exit 1 on any error
anchor-sec-lint programs/ --fail-on warning
anchor-sec-lint programs/ -f sarif -o asl.sarif --base "$PWD"
anchor-sec-lint target/idl/my_program.json   # IDL only
```

Example on the bundled vulnerable fixture:

```
tests/fixtures/vulnerable/lib.rs:14:9: warning [ASL006 unchecked-arithmetic] unchecked `+=` in `v.balance += amount`
tests/fixtures/vulnerable/lib.rs:70:9: error [ASL005 missing-has-one] `Withdraw.vault` (Vault) stores `owner` and `owner` signs, but they are never compared (missing `has_one = owner`)
tests/fixtures/vulnerable/lib.rs:102:9: error [ASL003 weak-seeds-or-bump] `Tag.profile` uses a hard-coded bump `254`
...
```

### Suppressing a finding

Put `// asl:allow ASL00N <reason>` on the line, or the line above, of the reported field or
expression. `asl:allow all` silences every rule there.

### GitHub code scanning

Use the [GitHub Action](#github-action) above, or run the CLI yourself:

```yaml
- run: cargo install anchor-sec-lint --locked
- run: anchor-sec-lint programs -f sarif -o asl.sarif --base "$GITHUB_WORKSPACE" --fail-on never
- uses: github/codeql-action/upload-sarif@v4
  with: { sarif_file: asl.sarif }
```

## How it works

1. Every `.rs` file under the given paths is parsed with `syn` (`target/`, `node_modules/` and
   hidden directories are skipped).
2. The linter extracts `#[derive(Accounts)]` structs: field wrapper types (`Signer`, `Account<T>`,
   `UncheckedAccount`, ...), the `#[account(...)]` constraints split on top-level commas,
   `/// CHECK:` docs, and `#[instruction(...)]` argument names.
3. It also collects `#[account]` data structs, so ASL005 knows which `Pubkey` fields an account
   stores.
4. A `syn::visit` pass over function bodies finds raw arithmetic and `create_program_address`.
5. The seed shapes of all files are compared to find collisions across instructions.

## Tests

```bash
CARGO_TARGET_DIR=../../../.build-cache/cargo-sol cargo test
```

`tests/fixtures/vulnerable` must trigger all six rules and `tests/fixtures/fixed` (the same
program with the issues fixed) must be clean. The tests also cover IDL mode, the SARIF shape,
suppression comments, exit codes, and finding line numbers.

## Limitations

- These are name and shape heuristics. The linter does not track data flow, so a check done
  manually in the handler (`require_keys_eq!`) is not seen by ASL005.
- Macros that generate `Accounts` structs are not expanded.
- Seed collision detection compares shapes only. It cannot tell that two dynamic seeds always
  hold different kinds of keys.

## License

MIT © Abdeldjalil Chougui

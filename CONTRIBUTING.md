# Contributing to NexaCore OS

Thank you for considering a contribution to NexaCore OS — a generational,
AI-native operating system designed to last 25+ years. Contributions are
the engine of this project; please read this document carefully before
opening your first PR.

> **TL;DR**
> 1. Sign off your commits with `-s` (DCO).
> 2. Use Conventional Commits.
> 3. Run `cargo fmt && cargo clippy && cargo test` locally before pushing.
> 4. For substantive changes (new protocol field, breaking API, new
>    hardware backend), file an **NCIP** first — see Section 9.
> 5. Be excellent to each other ([CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)).

---

## 1. What you can contribute

NexaCore OS is currently in **Phase 0** (foundation — design v0.1 complete,
no production code yet). The most valuable contributions today are:

| Area                       | What's needed                                                         |
|----------------------------|------------------------------------------------------------------------|
| **Documentation review**   | Spotting inconsistencies between `/docs/*.md` files; suggesting clarifications. |
| **Threat model refinement**| Adversary scenarios we missed in `/docs/04a-threat-model.md`.          |
| **Cryptographic review**   | Sanity-checking the API design in `nexacore-crypto` (no implementation yet — see the backlog P1.2). |
| **NCIP drafting**           | The NCIP process is `Active` since 2026-05-10 — see [`NCIP-Process-001`](./oips/oip-process-001.md). Substantive proposals shape the spec. |
| **Bug reports**            | Even pre-code, doc bugs and link-rot count.                            |
| **Translation**            | The vision documents are English-only today; quality translations are welcome (separate `i18n/` directory, opens later). |

We are **not yet ready** to take large code patches in `nexacore-crypto`,
`nexacore-capability`, `nexacore-tee`, or `nexacore-kernel` — these need cryptographer
peer review (the backlog P3.2) before code is merged. Doc PRs are open now.

---

## 2. Project priorities

Decisions are made under the **fixed lexicographic priority**:

1. **Security** — provable, audited, defensible against the threat model.
2. **Stability** — the project must outlast individuals and institutions.
3. **Performance** — third, but not optional.

If a contribution improves performance at the cost of security, it will
be rejected. If it improves stability at the cost of velocity, it is
welcome. Refer to `/docs/01-vision.md` for the underlying philosophy.

---

## 3. Developer Certificate of Origin (DCO)

NexaCore OS uses the **Developer Certificate of Origin (DCO)** rather than a
Contributor License Agreement (CLA). This keeps the contribution flow
asymmetric in the contributor's favor: you retain copyright on your work,
and the project receives a license to use it.

**You must sign off every commit** with the `-s` flag:

```bash
git commit -s -m "feat(nexacore-types): add SessionId newtype"
```

This appends a `Signed-off-by:` trailer to your commit message that
asserts you have read and agreed to the DCO at <https://developercertificate.org/>.

Unsigned commits are rejected by the `dco.yml` GitHub Action.

### 3.1 Why DCO and not CLA

A CLA assigns rights to the project's legal entity. We don't have a legal
entity yet (its form is under evaluation — the backlog P4.1), and even
once one exists, we prefer the lighter DCO model. If a future commercial
licensing scheme requires CLA-style rights, it will be proposed via NCIP
and applied **only to new contributions** going forward.

---

## 4. Commit message format — Conventional Commits

We use [Conventional Commits 1.0.0](https://www.conventionalcommits.org/).
Format:

```
<type>(<scope>)<!>: <short description>

<optional body, wrap at 72>

<optional footers — Signed-off-by, BREAKING CHANGE, Closes #N, etc.>
```

**Types in use:**

| Type       | When                                                  |
|------------|--------------------------------------------------------|
| `feat`     | New feature, new public API                            |
| `fix`      | Bug fix                                                |
| `docs`     | Documentation only                                     |
| `chore`    | Tooling, CI, build infra, dependency bumps             |
| `refactor` | Refactor with no behavioral change                     |
| `perf`     | Performance improvement                                |
| `test`     | Tests only                                             |
| `style`    | Formatting / whitespace; rare because `cargo fmt` covers most cases |
| `build`    | Build-system changes                                   |
| `revert`   | Revert a previous commit                               |
| `ncip`      | Adds or modifies an NCIP under `/ncips/`                 |

**Scope** is the crate name (`nexacore-types`, `nexacore-crypto`, ...) or a top-level
area (`docs`, `ci`, `repo`).

**Breaking changes** require either `<type>!:` or a `BREAKING CHANGE:`
footer. Pre-1.0 we use breaking changes liberally; post-1.0 they require
an NCIP.

**Examples:**

```
feat(nexacore-crypto): wrap ed25519-dalek with zeroizing key types

Adds NexaCoreSigningKey / NexaCoreVerifyingKey newtypes that implement
Drop+Zeroize. Wire format is unchanged.

Refs #42
Signed-off-by: Jane Roe <jane@example.org>
```

```
fix(nexacore-capability)!: reject tokens with future-dated not_before

BREAKING CHANGE: tokens whose `not_before` is more than 5 seconds in
the future of the verifier's clock are now rejected. Previously they
were accepted, which created a clock-skew exploitation window.

Refs CVE-pending, see SECURITY.md
Signed-off-by: John Doe <john@example.org>
```

---

## 5. Branch naming

Branches are named by purpose:

| Prefix          | When                                          |
|-----------------|------------------------------------------------|
| `feat/<slug>`   | New feature                                    |
| `fix/<issue-id>`| Bug fix tied to an issue                       |
| `docs/<slug>`   | Documentation only                             |
| `chore/<slug>`  | Tooling / CI                                   |
| `refactor/<slug>`| Refactor                                      |
| `ncip/<ncip-id>`  | NCIP draft (e.g. `ncip/ncip-process-001`)         |
| `security/<id>` | Security-related; stays private until disclosed|

`main` is the only long-lived branch. Linear history is enforced (no
merge commits — squash-and-merge is the default).

---

## 6. Pull request workflow

1. **Open a draft PR early.** Mark it as draft (`gh pr create --draft`)
   so we can give early feedback. Don't wait until "done".
2. **Pass CI locally first** (Section 7). The CI is fast (< 10 min target);
   use it.
3. **Self-review the diff.** Read your own diff line-by-line before
   asking others. This is the highest-leverage habit you can adopt.
4. **One concern per PR.** Don't bundle unrelated refactors. We squash
   on merge, so a clean PR == a clean commit on `main`.
5. **Update docs in the same PR.** Per project policy, code and docs
   stay in sync. README and `/docs/*.md` updates should be in the same
   PR as the code change they describe.
6. **Reviewers:**
   - Pre-Phase 1 (founder solo): 1 approval (founder).
   - Phase 1 onward: 2 approvals from maintainers, 1 of whom is not
     the author or close collaborator.
   - Security-sensitive PRs (`area:crypto`, `area:capability`,
     `area:tee`): require approval from a second reviewer with
     security context.
7. **Merge:** squash-and-merge. The PR title becomes the commit title;
   ensure it conforms to Conventional Commits.

---

## 7. Local development setup

### 7.1 Toolchain

```bash
# Install rustup if needed.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Toolchain version is pinned by /rust-toolchain.toml — running cargo from
# the repo root will auto-install the right channel and components.
cargo --version  # Should report 1.85+.
```

### 7.2 The pre-PR checklist

Run these in order; each is wired into CI and a PR cannot merge with
any of them red:

```bash
cargo fmt --all -- --check                              # P0.6 rustfmt.toml policy
cargo clippy --workspace --all-targets -- -D warnings   # P0.6 clippy.toml policy
cargo test --workspace --all-features                   # P0.4 ci.yml
cargo doc --workspace --no-deps                         # P0.4 ci.yml — link/doc check
cargo deny check                                        # P0.4 audit.yml — supply chain
```

Optional but encouraged:

```bash
cargo audit                  # RustSec advisories (cargo install cargo-audit)
cargo outdated --workspace   # See if you're behind on patch versions
```

### 7.3 Editor

Any editor with `rust-analyzer` works. The repo doesn't ship `.vscode/`
or `.idea/` configs (see `.gitignore`); contributors maintain their own.

### 7.4 Pre-commit hook (recommended)

Save to `.git/hooks/pre-commit` and `chmod +x`:

```bash
#!/usr/bin/env sh
set -e
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

A managed `pre-commit` framework will land later (the backlog future).

---

## 8. Test policy

> **No code merges without tests.** This is a hard project policy
> (see user-level guidance in the founder's preferences).

For new code:

- **Unit tests** for every public function with a non-trivial branch.
- **Property tests** (`proptest`) for invariants — particularly in
  `nexacore-types`, `nexacore-crypto`, and `nexacore-capability`.
- **Compile-fail tests** (`trybuild`) for type-level guarantees that
  must not be circumvented (e.g., constructing an `EncryptedString`
  outside `nexacore-tokenization`).
- **End-to-end tests** that simulate realistic operator behavior.
  These live in `/tests/e2e/` (will be created when the first runtime
  service ships).

For bug fixes:

- A regression test that fails before the fix and passes after.

CI runs the full suite on every push. Don't `#[ignore]` flaky tests —
fix them or open an issue and remove the test.

---

## 9. NCIPs — when and how to file

If your contribution is one of the following, **file an NCIP first**:

- New protocol field, message type, or wire-format change.
- Breaking API change in any crate exported as `pub`.
- New cryptographic primitive or scheme.
- New TEE backend.
- Change to the governance model.
- New funding source category.

The NCIP process is defined in [`NCIP-Process-001`](./oips/oip-process-001.md) (`Active` since
2026-05-10). The full filing flow — branch naming, template, lifecycle, voting, editor body,
Bootstrap Period — is in that document. Quick path:

1. Open a discussion issue using the [`ncip_proposal.yml`](./.github/ISSUE_TEMPLATE/oip_proposal.yml) template so editors can pre-validate scope.
2. Branch as `ncip/<slug>` (see §6 above).
3. Copy [`ncips/ncip-template.md`](./oips/oip-template.md) → `ncips/ncip-<slug>-XXX.md` (`XXX` is a placeholder; editors assign the global number on Last Call → Active).
4. Open a PR with `Signed-off-by:` (DCO) and Conventional Commit prefix `ncip(<slug>): <title>`.
5. Iterate `Draft → Review → Last Call`; the editors merge on positive Last Call outcome.

The CI lint at `scripts/lint-ncips.py` (`ncip-lint` workflow) will validate frontmatter, sections,
and index coherence on every push touching `/ncips/`.

NCIPs are typed (per `NCIP-Process-001` §1):

- **Standards Track** — protocol, wire format, cryptographic primitive, capability format, kernel ABI, or mesh handshake changes.
- **Process** — governance, voting, editor rotation, contribution flow, release cadence.
- **Informational** — best practices, advisories, guidelines (non-binding).
- **Meta** — NCIPs about the NCIP process itself.

---

## 10. Reporting security issues

**Do not open public issues for security bugs.** Follow the procedure in
[`SECURITY.md`](SECURITY.md) instead. Public disclosure of a 0-day in a
GitHub issue gives attackers the same heads-up as the maintainers.

---

## 11. Code of Conduct

Participation in this project — issues, PRs, discussions, conferences,
or any project-affiliated forum — is governed by
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). The CoC is binding from your
first interaction onward.

---

## 12. License of contributions

By submitting a contribution under DCO sign-off, you agree that your
contribution is licensed under the project's **Apache-2.0** license
([LICENSE](LICENSE)). This is the same license under which you receive
the project, so no additional rights transfer is implied.

If your employer has IP rights over your work, you must obtain
permission to contribute (the standard "Submitter has the right to
contribute" assertion of the DCO covers this — read it).

---

## 13. Getting in touch

- **Public discussion:** GitHub Discussions (when enabled).
- **Synchronous:** none yet (no Slack / Discord / Matrix). We will adopt
  Element / Matrix once the project size justifies a moderation budget.
- **Founder:** `hello@nexacoreos.com` for time-sensitive matters that
  don't fit a public issue.

---

## 14. Changelog

- 2026-05-09 — Initial document. Aligned to project preferences (test
  policy, language conventions, priority lexicography).

---

*If something in this document is unclear or contradictory, that's a bug —
please open a `docs:` PR or issue. The document is meant to lower friction,
not raise it.*

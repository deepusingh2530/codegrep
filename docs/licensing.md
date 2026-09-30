# Licensing

codegrep is original work, but it is **not** open source under a permissive
license. This page states exactly what you may do, where the boundary sits in
time, and how to get a different answer.

## The short version

| Version | License | Commercial use |
| --- | --- | --- |
| `0.12.0` and earlier | MIT ([`LICENSE-MIT`](LICENSE-MIT)) | allowed, forever |
| first release after `0.12.0` (and all work on `main` from this change onward) | **PolyForm Noncommercial 1.0.0** ([`LICENSE`](LICENSE)) | **not permitted** |

The boundary is one-way and cannot be undone. MIT grants are irrevocable: if
you obtained 0.12.0 (or any earlier version) from crates.io, a GitHub Release,
or a clone of a pre-change commit, you keep those rights permanently, and we
cannot revoke them. If you need a commercially-usable copy and it is too late
to be one of the early users, ask for a commercial license.

## What PolyForm Noncommercial allows and forbids

The license is short and specific:

- **Permitted** — any *noncommercial* purpose, including personal use
  (research, experimentation, study, hobby projects), and use by any
  charitable organization, educational institution, public research body,
  public safety/health body, environmental organization, or government
  institution, regardless of how that organization is funded.
- **Permitted** — distributing the software, and making changes or new works
  based on it, for a noncommercial purpose.
- **Forbidden** — any use for a commercial purpose, or anything intended or
  directed toward commercial advantage or monetary compensation.
- **Also applies** — if you distribute it, you must pass along the license (or
  its URL) and the `Required Notice:` line.
- **No warranty** — it is provided as is.

### "Does that include my company scanning its own code in CI?"

Yes, that is a commercial purpose, and it is **not** permitted under these
terms. This is deliberate: the license exists to keep commercial value with
the project. If your security team needs this tool, the paths are:

1. Use `0.12.0` or earlier, which is MIT and always will be.
2. Ask for a commercial license (see below).
3. Use an alternative with a permissive license.

There is no "small teams are fine" carve-out in this license, and no usage
threshold — it is a binary permitted/not-permitted line, and that is what the
license you chose says.

## Getting a commercial license

The licensor can grant a separate commercial license (perpetual, per-seat, or
subscription — your call) covering commercial use, redistribution, and hosted
offerings. To start the conversation, open a public issue that asks for a
contact address only — no details — and a maintainer will reply privately.
Direct contact details are deliberately not published here to keep the
mailbox out of public archives.

## Distribution channels

Both remain open, and both carry these terms:

- **crates.io** — the package manifests declare
  `license = "PolyForm-Noncommercial-1.0.0"` (a valid SPDX identifier) for
  versions after 0.12.0. Be aware that many companies run license scanners
  (FOSSA, Black Duck, and similar) and automated policy gates that **block**
  non-permissive licenses in CI. That is not a defect in the package; it is
  your organization's policy, and it is also why option 2 above exists.
- **GitHub Releases** — binaries, SBOMs, and signatures are attached to each
  release, as before.
- **Source** — the repository, under these terms.

## Dependencies and sidecars are unaffected

The terms above apply to codegrep's own code, rules, fixtures, documentation,
and artwork. They do not change the licenses of anything codegrep depends on
or shells out to:

| Component | License |
| --- | --- |
| Tree-sitter grammars and parsers | MIT |
| Rust dependencies (`serde`, `regex`, `rayon`, `ignore`, …) | MIT / Apache-2.0 (enforced by `cargo deny check`) |
| Secrets sidecar (`gitleaks`) | MIT, separate process, never linked |
| SCA sidecars (`osv-scanner`, `trivy`) | Apache-2.0, separate processes |

`deny.toml` continues to allow only permissive dependency licenses. Nothing in
the dependency graph depends on a copyleft or noncommercial license, so the
change is confined to this project's own material.

## Contributions

Contributions made after this change are accepted under the terms in
[`CONTRIBUTING.md`](../CONTRIBUTING.md): you license your work to the project
so it can be distributed under these terms (or relicensed by the maintainer,
including back to a permissive license, should that ever happen). Work
contributed earlier was accepted under MIT and stays MIT for its authors.

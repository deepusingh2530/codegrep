# codegrep

Fast, fully-offline multi-language SAST scanner — a curated, original
rule corpus, a scriptable CLI, taint analysis and SARIF output. This crate
exposes both the `codegrep` command-line tool and a library API for embedding.

- **Offline-first**: no network, no telemetry, deterministic results.
- **Auditable**: original code and rules only — nothing copied from a third-party scanner or rule registry.
- **Corpus**: 27 recognized languages, a generic fallback so unrecognized
  files are still scanned, and a pass/fail accuracy fixture for every rule.
- **Licensed** under PolyForm Noncommercial 1.0.0: free for noncommercial use;
  commercial use requires a separate license. Versions 0.12.0 and earlier are MIT.

```toml
[dependencies]
codegrep = "0.12.0"
```

```rust
use codegrep::{scan, sarif_from, ScanOptions};

let report = scan(&ScanOptions {
    path: "src".into(),
    rules: "codegrep/rules".into(), // local checkout of the repo's rules/
    ..Default::default()
})?;
println!("{}", sarif_from(&report.findings));
```

CLI:

```sh
cargo install codegrep
codegrep scan . --min-severity error --error --sarif -o results.sarif
```

Rules ship as YAML in the repository's [`rules/`](https://github.com/deepusingh2530/codegrep/tree/main/rules)
directory — point `ScanOptions::rules` at a local checkout (git submodule,
clone, or vendored copy). Full documentation:
[github.com/deepusingh2530/codegrep](https://github.com/deepusingh2530/codegrep).

## License

[PolyForm Noncommercial 1.0.0](https://github.com/deepusingh2530/codegrep/blob/main/LICENSE)
— free for noncommercial use; commercial use requires a separate license from
the maintainer. Versions `0.12.0` and earlier are MIT. See
[docs/licensing.md](https://github.com/deepusingh2530/codegrep/blob/main/docs/licensing.md).

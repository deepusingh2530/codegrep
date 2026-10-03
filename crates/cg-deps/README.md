# cg-deps

Dependency manifest inventory for [scanward](https://github.com/deepusingh2530/scanward).

Parses the lockfiles and manifests a repository actually contains into a flat,
deterministic list of dependency records — name, version, ecosystem, declared
licence, and whether the project asked for it directly or it arrived
transitively.

This is the shared spine for three checks that all need exactly the same data,
so the manifests are parsed once:

- **supply-chain inventory** and SBOM export
- **licence policy** enforcement (allow/deny lists over declared licences)
- **typosquat** name analysis (a direct dependency you did not intend is the
  interesting case)

## Formats

| File | Ecosystem | Version source | Directness signal | Declared licence |
|---|---|---|---|---|
| `Cargo.lock` | cargo | resolved | workspace members' dependency lists | no |
| `Cargo.toml` | cargo | declared range | declared | yes |
| `package-lock.json`, `npm-shrinkwrap.json` | npm | resolved (v1 tree, v2/v3 `packages`) | root package's dependencies | sometimes |
| `requirements.txt`, `requirements-dev.txt` | pypi | declared | declared | no |
| `pyproject.toml` | pypi | declared (PEP 621 + Poetry) | declared | Poetry only |
| `poetry.lock` | pypi | resolved | non-dev `category` | no |
| `go.mod` | go | declared | `// indirect` marker | no |
| `go.sum` | go | — (accepted, not informative) | — | — |
| `composer.lock` | composer | resolved | `packages` vs `packages-dev` | yes |
| `Gemfile.lock` | rubygems | resolved | `DEPENDENCIES` section | no |

Deliberately not handled yet: Maven `pom.xml` and MSBuild lockfiles. They are
listed as known gaps rather than approximated, because a half-correct inventory
is worse than none for a policy decision.

## Guarantees

- **Offline and deterministic.** Everything derives from file contents; no
  registry lookup, and output order is stable.
- **Never panics.** A malformed manifest yields an empty list.
- **Nothing invented.** A version range is kept verbatim (`>=2.0`, `^1.2`);
  `license: None` means "not declared here", never "free".
- **Original code.** Two small parsers (TOML, JSON) and hand-written line
  parsers for the rest; no third-party rule or manifest content is used.

Licensed under [PolyForm Noncommercial 1.0.0](https://github.com/deepusingh2530/scanward/blob/main/LICENSE).
Versions `0.12.0` and earlier of the project were MIT.

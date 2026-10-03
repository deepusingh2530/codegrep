# Changelog

## Unreleased

- **Install parity: Homebrew tap and a published container image.**
  `docker.yml` verifies the image on every PR that touches the build (including
  a non-root assertion and a real scan of `testdata/`), and on a `v*` tag
  publishes a multi-arch, provenance-attested image to
  `ghcr.io/deepusingh2530/scanward`. A Homebrew tap (`homebrew-scanward`) installs
  the prebuilt binary with the corpus, with a `scanward-corpus` wrapper so a
  fresh install can scan immediately. Not on `homebrew/core`: core requires a
  DFSG-compatible licence, and this project is PolyForm Noncommercial.
- **`.dockerignore`**: the build context was multi-GB because `target/` was
  being sent to the daemon. It is now a few MB, and the Dockerfile caches the
  dependency layer.
- **Dockerfile**: corpus baked in at `/rules` so a bare run against a bind mount
  works with no flags, non-root by default (uid 10001), stripped binary, and
  OCI labels including the licence, so enterprise image scanners see it.
- **Release tarballs ship `rules/` and a working `scanward-corpus` wrapper**
  (0.13.1, corrected in 0.13.2). Previously a tarball user got a binary that
  could not scan anything without cloning the repository first — which also
  made a Homebrew formula unusable. The first wrapper was itself broken twice,
  and both were caught by running the published artifact rather than reading
  the YAML: it placed `--rules` *before* the subcommand (usage error), and
  `rule test` takes the corpus as a *positional* path and rejects `--rules`
  outright. It now dispatches per subcommand, passes global flags straight
  through, and skips adding its own `--rules` when the caller supplied one,
  because clap rejects a repeated flag.

- **Category map in `docs/benchmarks.md`**: a capability comparison against
  pattern-based SAST, compiled-query engines, and hosted platforms, with the
  trade stated both ways — fully offline/zero-telemetry/free/readable corpus on
  one side, cross-file taint/absence classes/supply-chain breadth/platform
  workflow on the other. Better is now a checkable claim rather than an adjective.
- Refreshed `docs/cve-coverage.md`: 114 CRITICAL/HIGH CVEs in the window, 44
  distinct CWEs, 30 covered, 14 gap candidates (down from 17).

- **`--only platform` sidecar**: submits a repository to a hosted security
  platform's API as an opt-in subprocess (never linked, credentials from
  `AIKIDO_API_KEY`, `AIKIDO_ENDPOINT` overridable). Refused under `--offline`
  like the other sidecars, absent a key, and it degrades to the offline core
  when the CLI is missing. No vendor code is vendored — the platform ships under
  AGPL-3.0 or a commercial license, neither of which is compatible with this
  project's terms, so nothing of theirs is linked, bundled, or copied.
- **8 new original rules** (`rules/{python,php,ruby,javascript}/platform-gap.yaml`)
  for vulnerability classes that hosted platform scanners are known to catch and
  that were gaps here: still-encoded path traversal (`%2e`, `%252e`,
  `decodeURIComponent`/`unquote` feeding a path join), SSRF through user-supplied
  hosts including IDN/punycode forms across Python/PHP/Ruby/JS, SQL built by
  numeric coercion, and NoSQL operator injection (`req.query` passed straight
  into a Mongoose filter). One of them closes a real hole in the demo corpus:
  `requests.get(user_url)` in `testdata/py/vuln.py` was previously undetected.

## 0.13.0 (2026-10-03)

Published as [`scanward 0.13.0`](https://crates.io/crates/scanward) ·
[`v0.13.0`](https://github.com/deepusingh2530/scanward/releases/tag/v0.13.0) ·
[`codegrep 0.13.0`](https://crates.io/crates/codegrep) is the final release under the old name.

- **Project renamed `codegrep` → `scanward`.** The old name was unownable and
  crowded: ~15 GitHub repos carried it (two unrelated 18-star grep tools), the
  bare `github.com/codegrep` namespace is an org registered in 2016, the npm
  name is a stranger's abandoned 2013 stub, and `codegrep.com` is taken — so
  users searching for the tool found other people's projects, and `npm
  codegrep` is exactly the name-squat shape users get burned by. Everything
  moved together: crate and binary name, workspace member (`crates/scanward`),
  repository (`github.com/deepusingh2530/scanward`, with the old URL
  301-redirecting), release artifact names, CLI output, SARIF tool name, docs,
  and automation. Rule text needed no changes — no rule embeds the product
  name.
- **Migration is non-breaking for suppressions**: `.codegrep-suppressions.yml`
  (and `.yaml`) is still auto-discovered, and the legacy `codegrep-ignore` /
  `codegrep-ignore-next-line` inline markers still suppress findings, checked
  after the new names. Existing repositories keep working untouched; a unit
  test locks the legacy marker in.
- The `codegrep` crate gets a final `0.13.0` pointer release naming the new
  crate, so `cargo install codegrep` and older docs land somewhere useful.
  Versions `0.12.0` and earlier remain MIT, permanently.
- **Licensing change: MIT → PolyForm Noncommercial 1.0.0** (breaking for
  commercial users, by design). The first release after `0.12.0` is licensed
  under PolyForm Noncommercial: personal, research, educational, charity,
  public-research, and government use is permitted; **commercial use is not**,
  and a commercial license can be requested from the maintainer. `0.12.0` and
  earlier were published under MIT and remain MIT permanently — an MIT grant,
  once given, cannot be revoked — so this is a forward-only boundary, recorded
  in `docs/licensing.md` and preserved verbatim in `LICENSE-MIT`.
  Distribution is unchanged: crates.io and GitHub Release binaries continue to
  ship, now carrying `license = "PolyForm-Noncommercial-1.0.0"` (a valid SPDX
  identifier) in all six crate manifests.
- Contributing terms updated accordingly: contributions are licensed to the
  project, which may relicense the whole codebase at the maintainer's
  discretion. Earlier contributions stay MIT for their authors.
- Dependency and sidecar licenses are unaffected (Tree-sitter MIT, Rust deps
  MIT/Apache-2.0 still enforced by `cargo deny check`, `gitleaks` MIT,
  `osv-scanner`/`trivy` Apache-2.0 as separate processes).
- Docs: new `docs/licensing.md`; README badge, tagline, comparison table, and
  License section; crate README; `CONTRIBUTING.md`; `docs/rule-import.md`;
  `docs/benchmarks.md`; `assets/README.md` — no remaining claim that the
  project is MIT-licensed.
- **Repository hygiene**: removes the AI agent prompt scaffolding
  (`MASTER_PROMPT.md`, `prompts/rule-generator.md`) — a repo should ship
  documentation, not prompts. The durable content was rewritten as
  documentation first: `docs/architecture.md` (scan pipeline, crate
  responsibilities, invariants, deliberate limitations, new-language
  checklist), `docs/rule-authoring.md` (engine contract for patterns, schema,
  fixtures, validation loop, coverage checklist) and `docs/README.md` (index).
  Adds `CODE_OF_CONDUCT.md`, which `CONTRIBUTING.md` referenced but which did
  not exist. No behaviour change: `scripts/rule-gen.py` builds its own prompt
  and never read `prompts/`.
- **Protected `main`: every change arrives through a pull request.** The
  default branch is now governed by a ruleset — no direct pushes, no force
  pushes, no branch deletion, linear history only, required `test` + `deny`
  checks, and review threads must be resolved before merge. Merge commits are
  disabled (squash/rebase only) and merged branches auto-delete. There is no
  bypass list, so this applies to the maintainer too: work now happens on a
  branch and lands via PR, which keeps the review trail intact.
- Adds `CONTRIBUTING.md` (PR workflow, the six local gates, rule-authoring
  and new-language checklists, severity discipline, original-content-only and
  offline-stays-offline rules) and a PR template that asks for the
  verification evidence rather than a description of the diff.
- Documentation: README gains a Contributing section; `SECURITY.md` states who
  can change the repository and which automation is allowed to write.
- **Generic fallback: no file is silently skipped.** `discover_files` no
  longer filters by extension, and `scan()` resolves a file's language with
  `Language::from_path(..).unwrap_or(Language::Generic)`. Files whose
  extension is unrecognized (`.env`, `.pem`, `.conf`, `.tfvars`, …) are read
  as the new `generic` pseudolanguage and scanned with `languages: [generic]`
  rules instead of being ignored. `Language::Generic` never comes back from
  `from_path`; generic reads are capped at 10 MB (larger files are skipped
  with a warning).
- **27 languages recognized** (was 20): added text-scanned `rust`, `swift`,
  `dart`, `elixir`, `lua`, `powershell`, `sql` to `cg-parser` (extension
  detection only — no grammars, no new dependencies), with matching variants
  in the rule corpus.
- **60 new original rules** in first-party language packs — 10 Rust, 9 Swift,
  9 Dart, 10 Elixir, 8 Lua, 8 PowerShell, 6 SQL — each with a fail and a
  pass fixture: command/eval code execution, unsafe deserialization
  (including `:erlang.binary_to_term/1` and `NSKeyedUnarchiver`), SQL
  injection, open redirect, SSRF, XSS/HTML sinks, path traversal, TLS
  validation bypasses, hardcoded SQL credentials, over-broad `GRANT`s,
  weak crypto, and predictable PRNG use. Specs are in
  `scripts/specs/langpack-*.json`.
- The portable-schema importer now maps the 7 new languages (`rust`/`rs`,
  `swift`, `dart`, `elixir`, `lua`, `powershell`/`pwsh`/`ps1`, `sql`), so
  third-party rules targeting them import instead of being dropped.
- New integration test `crates/codegrep/tests/generic_scan.rs` asserts
  generic-fallback scanning end-to-end (unknown extension → `generic`
  language + secrets finding; oversized file skipped).
- Docs: `docs/cve-coverage.md` (CVE-watch gap table: 94 CRITICAL/HIGH CVEs in
  the last 7 days, 23/40 distinct CWEs covered, 17 gap candidates),
  `docs/coverage-policy.md` (pack-growth policy + generic fallback),
  `docs/benchmarks.md`, `docs/release-cadence.md`; README now carries a
  competitor comparison table and a qualitative coverage summary.
- Gates: 62 workspace tests green, clippy `-D warnings` clean, every accuracy
  fixture green, testdata baseline unchanged, self-scan of
  `crates/` clean, and an 8-file cross-language smoke scan fires each new
  language pack through `scan()`.

## 0.12.0
- **C++ support**: `.cpp`/`.cc`/`.cxx`/`.hpp`/`.hh`/`.hxx` files are now
  recognized (`Language::Cpp`, reported as `cpp`), and C/C++ both get
  tree-sitter grammars (`tree-sitter-c`, `tree-sitter-cpp`) for
  `parse_source`/`parse_file`/`lower` — matching itself stays
  regex-on-text as always. `.c`/`.h` keep reporting `c` (they are also
  grammar-backed now).
- All 16 C rules ship `languages: ["c", "cpp"]`, so the same corpus
  covers both; the portable importer maps `cpp`/`c++` → `cpp`
  (previously dropped as unsupported).
- New integration test `tests/cpp_scan.rs` scans `.c`/`.cpp`/`.hpp`
  fixtures end-to-end through `scan()` and asserts per-extension
  `language` + rule firing; unit tests cover C-family detection,
  parsing, IR lowering, and portable `cpp` mapping.
- Version cascade for the `Language` enum extension: `cg-parser` 0.2.0
  (new public variant), `cg-ir` 0.2.0, `cg-matcher`/`cg-taint` 0.1.1
  (dependency reqs), `cg-rules` 0.2.1 (importer mapping).
- Docs: README (20 languages, ten tree-sitter languages, `C / C++`
  table row), `docs/benchmarks.md`, `docs/rule-import.md` dropped-
  language example.
- 58 tests green, clippy `-D warnings` clean, every fixture green,
  testdata baseline 26 findings unchanged, self-scan clean.

## 0.11.0
- **JUnit XML output**: `codegrep scan --junit` emits a JUnit report
  (one `<testsuite>` per file, one failed `<testcase>` per finding with
  severity in `type`, message in `message`, snippet + fix in the body)
  for direct ingestion by CI test tabs (Jenkins, GitLab, etc.).
  Findings with XML metacharacters are escaped; an empty scan emits a
  single passing placeholder so strict consumers still get a valid
  document.
- New API: `codegrep::junit_from(&[Finding]) -> String` alongside
  `sarif_from`.
- CI: JUnit artifact generated + uploaded next to the SARIF artifact.
- Docs: README usage/flags/library example, `docs/cli-migration.md`,
  `docs/benchmarks.md` outputs parity row.
- 53 tests green (2 junit unit + 1 integration among them),
  clippy `-D warnings` clean, every fixture green, testdata baseline
  26 findings unchanged, self-scan clean.

## 0.10.0
- False-positive management:
  - **Suppression files** with a required `reason` (auditable, PR-reviewable),
    optional `path`/`line`/`owner`/`expires` (YYYY-MM-DD). Auto-discovered
    `.codegrep-suppressions.yml` at the scan root, or explicit
    `--suppress FILE` (repeatable). Expired entries stop applying and warn;
    unknown keys (`exires:` typos) fail the scan instead of silently
    no-opping.
  - **Inline comments**: `# codegrep-ignore` (same line only), scoped
    `# codegrep-ignore(rule-a, rule-b)`, and `# codegrep-ignore-next-line`.
    Comment marker + word-boundary required so string literals don't count.
  - Visibility: `ScanReport.suppressed`, `--metrics` `suppressed=N`, and a
    stderr note — findings are never hidden without a trace.
- New: `ScanOptions.suppress`, `codegrep::Suppression`, `suppress` module
  (loader, expiry, inline matching); `serde_yaml` dependency added.
- `docs/suppressions.md` + README section.
- 50 tests green (6 unit + 5 FP e2e among them), clippy `-D warnings` clean,
  all fixtures green, testdata baseline 26 findings unchanged.

## 0.9.0
- Portable pattern-schema rule importer: `--config` (or
  `ScanOptions::config`) now accepts rule files written in the common
  open-source pattern schema — `patterns:` conjunctions,
  `pattern-either`, `pattern-not`/`pattern-inside`,
  `metavariable-regex`/`metavariable-comparison` objects,
  `mode: taint` with `pattern-sources`/`-sinks`/`-sanitizers` — and
  translates them into native rules at load time. Only user-supplied
  files are parsed; no third-party rule content ships with codegrep.
- Strict-by-design translation: constructs we cannot represent
  faithfully (multiple AND-ed positives, `pattern-not-inside`,
  `pattern-regex`, `focus-metavariable`, ...) skip that rule with a
  reported reason instead of being silently weakened. Unsupported
  languages drop from the language list (rule skipped if none remain).
- New APIs: `load_rule_set_report()` /
  `cg_rules::load_rules_file_report()` / `load_rules_dir_report()`
  return warnings alongside rules; `ScanReport.warnings` surfaces them
  from `scan()`. CLI prints them to stderr; `rule test` reports skips.
- `cg-rules` bumped to 0.2.0 (new public `portable` module).
- `docs/rule-import.md`: supported constructs, refusals, and known
  approximations (line-scoped negation, coarse pattern-inside).
- 40 tests green (7 portable unit + 2 importer e2e among them),
  clippy `-D warnings` clean, every fixture green.

## 0.8.0
- Library crate: `codegrep` now exposes a `src/lib.rs` API so other
  projects can embed scanning directly (git dependency, no CLI
  subprocess): `scan(&ScanOptions) -> ScanReport`, `sarif_from()`,
  `load_rule_set()`, `findings_for_rule()`, glob/severity/path-filter
  helpers, and re-exports of the `cg-*` crates. `main.rs` is now a thin
  clap wrapper (sidecars + output formatting + exit codes).
- New types: `ScanOptions` (path, rules, config, include/exclude,
  min_severity, baseline/diff_only, cache, jobs), `ScanReport`
  (findings, files_scanned, rules_loaded, elapsed_ms, cache_hits).
- `examples/scan.rs` embedding demo + integration tests
  (`tests/lib_api.rs`): scan, filters, SARIF, error handling.
- Package metadata (description/license/authors/repository) on the
  `cg-*` workspace crates.
- Published to crates.io: `codegrep 0.8.0` plus `cg-parser`, `cg-rules`,
  `cg-ir`, `cg-taint`, `cg-matcher` (0.1.0) — install with
  `cargo install codegrep`; library as `codegrep = "0.8.0"`.
- 31 tests green (4 lib unit + 4 lib integration + doc test + 23
  workspace), clippy `-D warnings` clean, every fixture green.

## 0.7.0
- Standard SAST CLI for daily use: repeatable `--config` (rule file or
  directory; remote/registry URLs refused with a clear offline-first
  error), `--exclude`/`--include` path filters (segment-aware globs
  `*`/`**`/`?` plus substring matching, directory-suffix aware),
  `--min-severity error|warning|info` floor, and `--error` to exit 1
  for CI gating.
- SARIF: `runs[0].tool.driver.rules` metadata (default level +
  `security-severity`) so GitHub code scanning ingests rule info.
- 25 unit tests (glob matcher, path-filter semantics, severity
  ordering); all fixtures green; clippy `-D warnings` clean.
- Migration doc: CLI flag mapping table.

## 0.6.0
- Bulk authoring toward registry-scale rule-count parity with a
  thousand-plus MIT-original rules (original rules only; no third-party
  rule-registry content read),
  plus a CWE gap batch (file upload CWE-434, missing auth CWE-306, JWT
  auth CWE-287, log injection CWE-117, LDAP CWE-90, CRLF CWE-93, LFI
  CWE-98, credential protection CWE-522, int overflow CWE-190, dangerous
  functions CWE-676, buffer copy CWE-120, off-by-one CWE-787) and an
  OWASP/CWE metadata normalization pass (41 fixes), plus two parity
  batches (Python/JS sinks; terraform/yaml hardening;
  ruby/java sinks + Spring actuator exposure;
  scala sinks; go web/ssh/CORS sinks;
   python deser/crypto/config sinks;
   javascript sinks;
   terraform hardening + java sinks (MyBatis ${}, JEXL, JWT key, IV,
   Kryo, OkHttp/Paths SSRF-traversal, CORS, weak TLS);
   dockerfile build hygiene + .NET sinks (LDAP/XPath/EF SQLi, XXE,
   BinaryFormatter, JWT/conn-string secrets, CORS, WebClient SSRF);
   typescript sinks to registry parity (JWT/session secrets, ReDoS,
   dynamic import, traversal, SSRF, log injection);
   php/c/bash/json fill-ins + scala gaps (Process, JDBC creds, SQL
   concat, LDAP, Random);
   kotlin/android sinks + ocaml fill (Marshal, shell/exec, SSRF,
   weak-hash/random, XXE);
    yaml/k8s/GHA hardening (hostPort, apiserver flags, PR-head
    checkout, script injection, service defaults);
    java fill-ins (Thymeleaf/RequestDispatcher/EL injection, Apache
    HttpClient SSRF, Hessian/HttpInvoker deser, JWT alg-none,
    cookie/CORS misconfig, PBKDF2-SHA1/RSA-PKCS1/DES/HmacMD5,
    transferTo upload, world-writable perms, WebClient SSRF);
    python fill-ins (JWT encode none, Flask template/directory sinks,
    paramiko/pexpect, SSRF sockets, secrets prefixes GitHub/GCP/Stripe/
    Slack/Shopify/PyPI/SendGrid, DB creds in URL, ECB-default AES);
    javascript fill-ins (spawnSync/setImmediate, vm.compileFunction,
    chmod 777, HMAC-MD5/RSA-PKCS1/PBKDF2-low, tokens GitHub/Slack/
    password/private key, res.location/download, URL creds, CORS
    origin reflection, mysql multi-statement);
    python fill-ins 2 (HMAC weak digest, asyncio exec, os.spawnv,
    Paramiko AutoAdd, Blowfish/PKCS1, AWS/Twilio/Azure/Fernet/Basic
    secrets, DRF no-auth, umask 0, pickle session serializer);
    ruby fill-ins (Psych/serialize YAML, ExecJS, Arel/where/find_by,
    redirect_back host, dir glob, pipe open, JWT/API/Basic secrets,
    RSA-PKCS1, Nokogiri noent, REXML);
    terraform fill-ins (short passwords, API auth NONE, SSM String
    type, Azure HTTPS/FTPS/TLS, lambda wildcard principal, AppSync
    API key, GKE client cert, PITR/backup/access-log/scan offs);
    python fill-ins (cleartext telnet/gRPC/Kafka/Redis/LDAP/MySQL,
    cert-verify off, weak tokens, HF/Databricks secrets, pip http
    index, Tornado XSRF/cookie secret, weak hashers, DRF throttle);
    javascript fill-ins (AsyncFunction ctor, uuid v1, AWS/Stripe/npm/
    Google secrets, bcrypt cost, lodash update/proto assign, DES,
    empty PBKDF2 salt, ws:// CSP unsafe, traversal sinks);
    python fill-ins round 2 (unsafe YAML loaders, spawn variants,
    sslmode off, amqp cleartext, IMDS literal, OAuth/GitLab/Mailgun/
    npm secrets, pathlib traversal, runpy/imp execution);
    python fill-ins round 3 (FastAPI CORS, DRF default auth, host-key
    verify off, |safe, legacy ciphers, MGF1-SHA1, webhook/bot secrets,
    docker privileged/SYS_ADMIN, OAuth grants);
    yaml fill-ins (GHA EOL node/ref context, k8s cluster-admin/kubelet/
    etcd, SSH weak algos/empty passwords, nginx autoindex/TLS1.0-1.1,
    H2 console, Grafana anon, MySQL skip-grants, Jupyter empty token);
    python fill-ins round 4 (zip-slip under ZipFile, weak key_size,
    TOTP/HOTP seeds, aiohttp ssl=False, bcrypt low rounds, dev email
    backends, unsigned boto, Vault/Groq/GCP-SA/fine-grained-GH/AWS-session
    secrets, Camellia, SAML sigs off, X-Frame/SameSite/JWT-aud off,
    passlib legacy hashes, hardcoded IV/salt, PBKDF2-SHA1, lxml entities);
    ruby fill-ins (SameSite off, Haml escape off, umask 0, DSA/weak-RSA
    keygen, legacy ciphers, TLS1.0-1.1 selection, bcrypt cost, PEM keys,
    webhooks, pry/byebug, zip-slip, verify: false, pg sslmode, S3 ACL,
    literal passwords, JSON.load, CORS *, auth skips, bearer/JWT-none,
    Net::SSH host key, SAML sigs, hardcoded IV;
    javascript fill-ins (JWT ignore-expiration, Vault/GCP-SA/AWS-session/
    fine-grained-GH/Groq secrets, Discord/Teams webhooks, TLS min version,
    strictSSL off, cleartext mqtt/amqp/redis/postgres URLs, pg ssl off,
    Mongo TLS verify off, TOTP/passphrase/api-key/basic-auth/salt literals,
    shell.exec, Reflect.set/deepExtend pollution, OAuth implicit grant,
    express dotfiles allow, RC4;
    javascript fill-ins 2 (Shopify/SendGrid/HF/Slack/Databricks/PyPI/
    Twilio secrets, trust proxy, superagent SSRF, cookie-parser literal,
    EJS raw output, NoSQL req.body query);
    ruby fill-ins 2 (SendGrid/Shopify/Slack/Stripe/Twilio secrets,
    MessagePack unpack, connection.execute SQLi, CSRF null_session,
    ERB raw output, HMAC-MD5, passphrase/TOTP literals, ransack params);
    go fill-ins (AWS/GitHub/Stripe/Slack/password/Basic/bearer/Vault/HF/
    PEM/creds-in-url/OAuth secrets, upload client filename, PKCS1 decrypt,
    ECB mode, PBKDF2/bcrypt low cost, weak RSA keygen, hardcoded IV,
    cookie-store key, JWT literal key/alg-none, SameSite none, fasthttp
    SSRF;
    java fill-ins 2 (AWS/GitHub/Stripe/Vault/passwords/Basic/bearer/
    creds-in-url secrets, commons-text StringSubstitutor, BeanShell,
    JdbcRowSetImpl gadget, RestTemplate/Socket SSRF, JPA native-query
    SQLi, zip-slip, URLClassLoader, actuator heapdump/shutdown, H2
    console, JDWP, SameSite none, hardcoded salt, RC4/DES;
    java fill-ins 3 (recovers 9 rules lost to a jvx1 group-file clobber:
    Weak Random, XStream/Fastjson deserialization, Log4Shell JNDI,
    concatenated SQL strings, CSRF-ignore annotation, DocumentBuilder/
    SAX/XMLInput XXE factories; mkrules now refuses to overwrite a group
    file missing its ids, and 19 stale fixture dirs were renamed/merged
    to their real rule ids;
    java/go fill-ins (literal SecretKeySpec, legacy TLSv1/1.1/SSLv3
    protocols, weak RSA keygen, MySQL useSSL=false, seeded math/rand,
    Mongo $where/$regex ops, Slack/npm tokens, hardcoded salt;
    typescript/php/bash/json/html fill-ins (AWS/GitHub/Basic-auth
    secrets, JWT ignore-expiration, SameSite=none, SQL concat, PHP
    literal password/salt, cURL peer-verify off, openssl/ECB modes,
    php:// wrappers, sudo NOPASSWD, insecure TLS downloads, JSON
    rejectUnauthorized/insecureSkipVerify/public ACL, external base
    href, CSS url() mixed content));
    final parity batch (dockerfile SSH-key/setuid/ENV-key/APT+pip
    cleartext; python weak TLS min-version, legacy PROTOCOL_TLS/SSLv3,
    literal SMTP/LDAP login, NoSQL operator keys, PIL bomb limit, MD5
    password const; yaml Ansible/DB-root literals, GHA
    persist-credentials, runAsNonRoot=false, docker login -p; terraform
    ECR mutable tags, Azure client_secret, TLS private key, Redis auth
    token; php ghp_ token, LDAP bind literal, INTO OUTFILE; java keystore
    literal, SHA1withRSA; go OpenAI/PyPI tokens; csharp AWS key, RSA-1024;
    plus c insecure temp, kotlin WebView JS, html cleartext object, js
    OpenAI key, scala AWS key, ocaml CERT_NONE)
- 10 new languages wired for text scanning: terraform, yaml, dockerfile,
  scala, c, ocaml, kotlin, bash, json, html (`Language::grammar()` now
  returns `Option`, so text-scanned langs need no tree-sitter dependency)
- Batch generator `scripts/mkrules.py` (JSON spec -> YAML + fail/pass
  fixtures) with specs under `scripts/specs/`; `load_rules_dir` now skips
  `tests/` fixtures
- Full pass/fail fixture suite green; metavariable-regex keys use the bare
  capture name; sink-shaped pass fixtures must not repeat their own sink
- Coverage exceptions documented in `docs/coverage-policy.md`: UAF/double
  free, OOB read, NULL deref, races, IDOR and missing-authz route checks
  need block scoping or repeated-metavar equality the matcher lacks

## 0.5.0
- 161 MIT-original rules (+50): per-category gap sweep so every language
  carries code-execution, deserialization, misconfig, open-redirect, sqli/
  cmdi, ssrf, crypto, ssti, xss and weak-crypto coverage
- 95 pass/fail fixtures, all green; `docs/coverage-policy.md` records the
  precision contract and the two deliberate exceptions (CSRF sinks only,
  secrets via generic pack)

## 0.4.0
- 111 MIT-original rules (+39): subprocess/shell, TLS, crypto, deserialization,
  NoSQL/LDAP/SQLi variants, SSRF, traversal, framework sinks across all 8 langs
- AI rule pipeline live: `prompts/rule-generator.md` + `scripts/rule-gen.py`
  (Ollama-local, schema + fail/pass fixture gate; only validated rules land)
- 63 pass/fail fixtures, all green; single+multi-arg variants audited
  across all sink rules

## 0.3.0
- 72 MIT-original rules: framework packs (Django, Flask, Express, Spring, Rails,
  Laravel) + generic secrets pack (AWS/GitHub/Slack keys, private keys, passwords)
- 43 pass/fail fixtures (`rules/tests/<id>/{fail*,pass*}`), all green via
  `codegrep rule test`
- Taint v0.3: function-scope extraction (indent + brace families), params treated
  as untrusted, one-level call summaries with two-phase fixpoint, sanitizer-aware
- Live sidecars (separate processes, license-safe): `--only secrets` runs gitleaks
  (MIT), `--only sca` runs osv-scanner (Apache-2.0), `--only all` combines
- AI side-plane live: `ai-triage/triage.py` with BYOK Anthropic/OpenAI/Ollama
  (stdlib only), offline heuristic fallback, verified autofix (re-scan gate)
- Matcher: trailing metavariables greedy (secret-format checks), single+multi-arg
  call variants across sink rules
- Zero new dependencies; core scan fully offline with no keys

## 0.2.0
- 8 languages: Python, JavaScript, TypeScript, Go, Java, Ruby, PHP, C# (Tree-sitter, offline)
- Tier-2 matcher: whole-file DOTALL matching (multi-line sinks), whitespace-insensitive patterns, `metavariable-comparison` (`$N > 1024`), coarse `pattern-inside`
- Accuracy harness: `codegrep rule test rules/` runs `rules/tests/<id>/{fail*,pass*}` fixtures (17 fixtures, 0 failures)
- Persistent content-hash cache (`~/.cache/codegrep`, `--no-cache`/`--cache-dir`), `--offline` strict mode
- 38 MIT rules with SARIF 2.1.0 + JSON output, diff-only PR scanning, GitHub Action + pre-commit hook
- Single binary: `cargo build --release -p codegrep`, Docker image, `ai-triage/` async side-plane stub

## 0.1.0
- Initial scaffold: 4 languages, Tier-1 line matcher, 10 rules, basic CLI

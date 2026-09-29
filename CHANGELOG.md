# Changelog

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
  workspace), clippy `-D warnings` clean, fixtures 2152 green.

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
  ordering); fixtures 2152 green; clippy `-D warnings` clean.
- Migration doc: CLI flag mapping table.

## 0.6.0
- 1183 MIT-original rules (+1022): bulk authoring toward registry-scale
  rule-count parity (original rules only; no third-party rule-registry content read),
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
    final parity batch to 1183 (dockerfile SSH-key/setuid/ENV-key/APT+pip
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
- 2152 pass/fail fixtures, all green; metavariable-regex keys use the bare
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

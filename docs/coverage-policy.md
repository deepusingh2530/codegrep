# Rule coverage policy

The rule corpus is organized around these categories, and every rule ships
with `rules/tests/<id>/{fail,pass}` fixtures verified by `scanward rule test`:

- code-execution, deserialization, misconfig, open-redirect
- owasp-a1-injection (SQL/LDAP/NoSQL/XPath/command), owasp-a10-ssrf,
  owasp-a2-crypto, owasp-a3-injection (SSTI/template), owasp-a3-xss,
  weak-crypto

A language carries the categories its APIs actually expose — SQL string
sinks for languages with a database driver, `os`/`Process`/`System` sinks for
languages with a process API, and so on. Deeply-used languages (Python,
JavaScript, Java, Go, PHP, Ruby) get the full 10-16 rule-per-category packs;
newly-added languages ship 6-12 focused rules first and grow weekly, driven by
the CVE gap table in [`cve-coverage.md`](cve-coverage.md) and real-world
findings. Adding a language is a scanning decision; how fast its pack grows
is a coverage-cadence decision.

Three deliberate exceptions (documented here so they read as decisions, not gaps):

1. **CSRF** — covered only where a sink-shaped finding exists
   (`django-csrf-exempt`, `spring-csrf-disabled`). CSRF elsewhere is the
   *absence* of protection (missing middleware, missing tokens), which a
   sink-pattern engine cannot assert without whole-app config analysis.
   Rails/Django defaults are protective; flagging every form would be noise.
2. **Secrets** — covered once, globally, by `rules/secrets/` with
   `languages: [generic]` (AWS/GitHub/Slack tokens, private keys, password
   assignments). Secret shapes are language-independent; duplicating them per
   language would multiply maintenance without new signal. The `generic`
   pseudolanguage applies to every discovered file — and files whose
   extension scanward doesn't recognize (`.env`, `.pem`, `.toml`, `.conf`, …)
   are scanned *as* `generic` rather than skipped, up to a 10 MB read cap.
   So the blast radius of `find`/`grep`-style blind spots is gone: 27
   languages are recognized, every other file still gets the polyglot pass.
3. **Structural absence / memory-lifetime findings** — CWE-416 (use after
   free), CWE-415 (double free), CWE-125 (OOB read), CWE-476 (NULL deref)
   and CWE-362 (race/TOCTOU) need either block-range scoping or repeated
   metavariable equality; the matcher compiles patterns to whole-file regexes
   and Rust regex forbids duplicate capture names. Route-level CWE-287/306/
   639/862/863 (missing decorator/middleware/authz check) and OWASP A04
   (insecure design) are likewise *absence* findings. These are roadmap
   (block scoping + taint event-ordering), not silent gaps: config-level
   equivalents ARE covered — CWE-306 via auth-disabled settings, CWE-287 via
   JWT verification bypasses, CWE-434 via client-filename uploads, CWE-117
   via request-data-to-log sinks.

## Precision contract

- Sink-presence rules (pattern-only) are severity WARNING / confidence
  MEDIUM or LOW unless the sink is rarely legitimate (`eval`, `unserialize`,
  `sh -c` → ERROR/HIGH).
- Taint rules (`taint:` block) carry the high-precision claims (ERROR/HIGH):
  untrusted input must reach the sink, sanitizers honored.
- Every rule ships only with a fail-fixture that triggers and a
  pass-fixture that stays silent. `rule test` fails the build otherwise.

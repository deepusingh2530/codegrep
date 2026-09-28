#!/usr/bin/env python3
# scripts/rule-gen.py — AI rule synthesizer for codegrep (Ollama-local, validated).
# License safety: specs describe vulnerability CLASSES (public facts: sink APIs,
# CWEs). The model writes ORIGINAL patterns; output is mechanically validated
# (schema + fail/pass fixtures) and never copied from any third-party registry.
# Usage: python3 scripts/rule-gen.py [--only ID] [--model qwen3:8b]
# Requires: ollama serving a small instruct model + ./target/debug/codegrep built.

import argparse, json, os, re, shutil, subprocess, sys, tempfile, urllib.request

try:
    import yaml
except ImportError:
    sys.exit("need pyyaml: pip install pyyaml")

OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CODEGREP = os.path.join(REPO, "target", "debug", "codegrep")
EXT = {"python": "py", "javascript": "js", "typescript": "ts", "go": "go",
       "java": "java", "ruby": "rb", "php": "php", "csharp": "cs", "generic": "txt"}

SYSTEM = """You write codegrep SAST rules as YAML ONLY, no prose, no fences.
Schema: id, languages, severity, category, message, fix, pattern OR pattern-either, metadata{owasp,cwe,confidence}.
Pattern mini-language: $VAR = one value, ... = filler, e.g. raw($VAR, ...).
RULES: bare code shapes, NEVER wrap in f(...). pattern-either items look like `- pattern: subprocess.run($VAR, shell=True)`.
owasp like A03:2021-Injection, cwe like CWE-78, confidence HIGH/MEDIUM/LOW, category like security:owasp-a1-injection.
Keep the dangerous API name literally in the pattern."""

# (id, lang, category, sev, owasp, cwe, conf, vuln_desc, vuln_snippet, clean_snippet)
SPECS = [
 ("py-subprocess-shell","python","security:owasp-a1-injection","ERROR","A03:2021-Injection","CWE-78","HIGH","subprocess with shell=True","subprocess.run(cmd, shell=True)",'subprocess.run(["ls", "-l"])'),
 ("py-flask-secret","python","security:secrets","WARNING","A07:2021-Auth-Failures","CWE-798","MEDIUM","hardcoded Flask secret_key","app.secret_key = \"devkey123\"","app.secret_key = os.environ.get(\"SECRET\")"),
 ("py-requests-verify-false","python","security:misconfig","WARNING","A02:2021-Crypto-Failures","CWE-295","MEDIUM","TLS verification disabled","requests.get(url, verify=False)", "requests.get(url)"),
 ("py-tempfile-mktemp","python","security:owasp-a1-injection","WARNING","A01:2021-Broken-Access-Control","CWE-377","MEDIUM","insecure mktemp race","tempfile.mktemp()","tempfile.mkstemp()"),
 ("py-jwt-none","python","security:owasp-a2-crypto","WARNING","A02:2021-Crypto-Failures","CWE-327","MEDIUM","JWT none algorithm","jwt.decode(tok, algorithms=[\"none\"])","jwt.decode(tok, algorithms=[\"HS256\"])"),
 ("py-ldap-search","python","security:owasp-a1-injection","WARNING","A03:2021-Injection","CWE-90","MEDIUM","LDAP search with user filter","conn.search_s(base, scope, user_filter)","conn.search_s(base, scope, \"(uid=admin)\")"),
 ("py-pymongo-find","python","security:owasp-a1-injection","WARNING","A03:2021-Injection","CWE-943","MEDIUM","MongoDB find with user query","collection.find(user_query)","collection.find({\"name\": \"admin\"})"),
 ("py-tarfile-extract","python","security:owasp-a1-injection","WARNING","A01:2021-Broken-Access-Control","CWE-22","MEDIUM","tar path traversal on extract","tar.extractall(path)","tar.getnames()"),
 ("py-sqlalchemy-text","python","security:owasp-a1-injection","WARNING","A03:2021-Injection","CWE-89","MEDIUM","SQLAlchemy text() with interpolated SQL","db.execute(text(query))","db.execute(text(\"SELECT 1\"))"),
 ("py-permissive-chmod","python","security:misconfig","WARNING","A05:2021-Misconfiguration","CWE-732","MEDIUM","world-writable chmod","os.chmod(p, 0o777)","os.chmod(p, 0o640)"),
 ("py-weak-random","python","security:weak-crypto","WARNING","A02:2021-Crypto-Failures","CWE-338","MEDIUM","weak PRNG for security use","token = random.random()","token = secrets.token_hex(16)"),
 ("py-ssl-unverified","python","security:misconfig","WARNING","A02:2021-Crypto-Failures","CWE-295","MEDIUM","unverified SSL context","ssl._create_unverified_context()","ssl.create_default_context()"),
 ("js-cookie-unsigned","javascript","security:misconfig","WARNING","A05:2021-Misconfiguration","CWE-565","MEDIUM","Express cookie without httpOnly","res.cookie(name, val)","res.cookie(name, val, { httpOnly: true })"),
 ("js-jwt-decode","javascript","security:owasp-a2-crypto","WARNING","A02:2021-Crypto-Failures","CWE-347","MEDIUM","JWT decoded without verification","jwt.decode(token)","jwt.verify(token, secret)"),
 ("js-nosql-findone","javascript","security:owasp-a1-injection","WARNING","A03:2021-Injection","CWE-943","MEDIUM","Mongo findOne with user query","User.findOne(userQuery)","User.findOne({ name: \"a\" })"),
 ("js-readfile-user","javascript","security:owasp-a1-injection","WARNING","A01:2021-Broken-Access-Control","CWE-22","MEDIUM","fs read on user path","fs.readFileSync(userPath)","fs.readFileSync(\"/etc/hosts\")"),
 ("js-vm-run","javascript","security:code-execution","ERROR","A03:2021-Injection","CWE-95","HIGH","vm module executes user code","vm.runInNewContext(userCode)","vm.runInNewContext(\"1+1\")"),
 ("js-unserialize","javascript","security:deserialization","ERROR","A08:2021-Integrity-Failures","CWE-502","HIGH","node-serialize unserialize on user data","unserialize(userData)","JSON.parse(userData)"),
 ("js-postmessage-star","javascript","security:misconfig","WARNING","A05:2021-Misconfiguration","CWE-942","MEDIUM","postMessage to any origin","w.postMessage(data, \"*\")","w.postMessage(data, origin)"),
 ("js-dangerously-html","javascript","security:owasp-a3-xss","WARNING","A03:2021-Injection","CWE-79","MEDIUM","React dangerouslySetInnerHTML with user HTML","<div dangerouslySetInnerHTML={{__html: userHtml}} />","<div>{userText}</div>"),
 ("js-sqlite-run","javascript","security:owasp-a1-injection","WARNING","A03:2021-Injection","CWE-89","MEDIUM","sqlite db.run with concatenated SQL","db.run(query)","db.run(\"SELECT 1\")"),
 ("ts-nosql-findone","typescript","security:owasp-a1-injection","WARNING","A03:2021-Injection","CWE-943","MEDIUM","Mongo findOne with user query","User.findOne(userQuery)","User.findOne({ name: \"a\" })"),
 ("ts-dangerously-html","typescript","security:owasp-a3-xss","WARNING","A03:2021-Injection","CWE-79","MEDIUM","React dangerouslySetInnerHTML with user HTML","<div dangerouslySetInnerHTML={{__html: userHtml}} />","<div>{userText}</div>"),
 ("ts-jwt-decode","typescript","security:owasp-a2-crypto","WARNING","A02:2021-Crypto-Failures","CWE-347","MEDIUM","JWT decoded without verification","jwt.decode(token)","jwt.verify(token, secret)"),
 ("ts-readfile-user","typescript","security:owasp-a1-injection","WARNING","A01:2021-Broken-Access-Control","CWE-22","MEDIUM","fs read on user path","fs.readFileSync(userPath)","fs.readFileSync(\"/etc/hosts\")"),
 ("go-queryrow","go","security:owasp-a1-injection","WARNING","A03:2021-Injection","CWE-89","MEDIUM","QueryRow with concatenated SQL","db.QueryRow(query)","db.QueryRow(\"SELECT 1\")"),
 ("go-md5-new","go","security:weak-crypto","WARNING","A02:2021-Crypto-Failures","CWE-327","MEDIUM","MD5 for security use","h := md5.New()","h := sha256.New()"),
 ("go-shell-c","go","security:owasp-a1-injection","WARNING","A03:2021-Injection","CWE-78","MEDIUM","shell -c with user input","exec.Command(\"sh\", \"-c\", userCmd)","exec.Command(\"ls\", \"-l\")"),
 ("go-permissive-perm","go","security:misconfig","WARNING","A05:2021-Misconfiguration","CWE-732","MEDIUM","world-writable file mode","os.WriteFile(p, d, 0777)","os.WriteFile(p, d, 0600)"),
 ("go-ssrf-get","go","security:owasp-a10-ssrf","WARNING","A10:2021-SSRF","CWE-918","MEDIUM","http.Get on user URL","http.Get(userURL)","http.Get(\"https://example.com\")"),
 ("go-gob-decode","go","security:deserialization","WARNING","A08:2021-Integrity-Failures","CWE-502","MEDIUM","gob decode of untrusted stream","gob.NewDecoder(r).Decode(&v)","json.NewDecoder(r).Decode(&v)"),
 ("go-template-html","go","security:owasp-a3-xss","WARNING","A03:2021-Injection","CWE-79","MEDIUM","template.HTML marks user string safe","template.HTML(userHTML)","template.HTMLEscapeString(userHTML)"),
 ("java-prepare-concat","java","security:owasp-a1-injection","WARNING","A03:2021-Injection","CWE-89","MEDIUM","prepareStatement with concatenated SQL","conn.prepareStatement(sql)","conn.prepareStatement(\"SELECT 1\")"),
 ("java-cookie-insecure","java","security:misconfig","WARNING","A05:2021-Misconfiguration","CWE-614","MEDIUM","cookie without Secure/HttpOnly","new Cookie(name, val)","resp.addCookie(secureCookie)"),
 ("java-send-redirect","java","security:open-redirect","WARNING","A01:2021-Broken-Access-Control","CWE-601","MEDIUM","sendRedirect to user input","resp.sendRedirect(url)","resp.sendRedirect(\"/home\")"),
 ("java-weak-md5","java","security:weak-crypto","WARNING","A02:2021-Crypto-Failures","CWE-327","MEDIUM","MD5 MessageDigest","MessageDigest.getInstance(\"MD5\")","MessageDigest.getInstance(\"SHA-256\")"),
 ("java-xml-decoder","java","security:deserialization","ERROR","A08:2021-Integrity-Failures","CWE-502","HIGH","XMLDecoder on untrusted XML","new XMLDecoder(in)","DocumentBuilderFactory.newInstance()"),
 ("java-nio-read","java","security:owasp-a1-injection","WARNING","A01:2021-Broken-Access-Control","CWE-22","MEDIUM","NIO read on user path","Files.readAllBytes(userPath)","Files.readAllBytes(Paths.get(\"/etc/hosts\"))"),
 ("ruby-send-user","ruby","security:code-execution","WARNING","A03:2021-Injection","CWE-94","MEDIUM","send with user method name","obj.send(userMethod)","obj.send(:name)"),
 ("ruby-constantize","ruby","security:code-execution","WARNING","A03:2021-Injection","CWE-94","MEDIUM","constantize on user input","userInput.constantize","\"User\".constantize"),
 ("ruby-uri-open","ruby","security:owasp-a10-ssrf","WARNING","A10:2021-SSRF","CWE-918","MEDIUM","URI.open on user URL","URI.open(userURL)","URI.open(\"https://example.com\")"),
 ("ruby-net-http-get","ruby","security:owasp-a10-ssrf","WARNING","A10:2021-SSRF","CWE-918","MEDIUM","Net::HTTP.get on user URI","Net::HTTP.get(userURI)","Net::HTTP.get(URI(\"https://example.com\"))"),
 ("ruby-order-sqli","ruby","security:owasp-a1-injection","WARNING","A03:2021-Injection","CWE-89","MEDIUM","order() with user SQL fragment","User.order(userSort)","User.order(:name)"),
 ("php-include-user","php","security:owasp-a1-injection","ERROR","A03:2021-Injection","CWE-98","HIGH","include on user path (LFI)","include $page;","include \"home.php\";"),
 ("php-extract-user","php","security:misconfig","WARNING","A08:2021-Integrity-Failures","CWE-621","MEDIUM","extract() on user array","extract($_GET);","extract($safe, EXTR_SKIP);"),
 ("php-parse-str","php","security:misconfig","WARNING","A08:2021-Integrity-Failures","CWE-621","MEDIUM","parse_str without result array","parse_str($q);","parse_str($q, $out);"),
 ("php-md5-pass","php","security:weak-crypto","WARNING","A02:2021-Crypto-Failures","CWE-327","MEDIUM","md5 for passwords","$h = md5($pw);","$h = password_hash($pw, PASSWORD_DEFAULT);"),
 ("php-curl-exec","php","security:owasp-a10-ssrf","WARNING","A10:2021-SSRF","CWE-918","MEDIUM","curl_exec on user-configured handle","curl_exec($ch);","curl_close($ch);"),
 ("php-file-get-contents","php","security:owasp-a1-injection","WARNING","A01:2021-Broken-Access-Control","CWE-22","MEDIUM","file_get_contents on user path","file_get_contents($p);","file_get_contents(\"php://input\");"),
 ("csharp-html-raw","csharp","security:owasp-a3-xss","WARNING","A03:2021-Injection","CWE-79","MEDIUM","Html.Raw on untrusted HTML","@Html.Raw(userHtml)","@userText"),
 ("csharp-mvc-redirect","csharp","security:open-redirect","WARNING","A01:2021-Broken-Access-Control","CWE-601","MEDIUM","MVC Redirect to user input","return Redirect(url);","return Redirect(\"/home\");"),
 ("csharp-sha1-create","csharp","security:weak-crypto","WARNING","A02:2021-Crypto-Failures","CWE-327","MEDIUM","SHA1 for security use","SHA1.Create()","SHA256.Create()"),
 ("csharp-proc-startinfo","csharp","security:owasp-a1-injection","WARNING","A03:2021-Injection","CWE-78","MEDIUM","ProcessStartInfo with user file name","new ProcessStartInfo(userBin)","new ProcessStartInfo(\"app\")"),
 ("csharp-response-redirect","csharp","security:open-redirect","WARNING","A01:2021-Broken-Access-Control","CWE-601","MEDIUM","Response.Redirect to user input","Response.Redirect(url);","Response.Redirect(\"/home\");"),
]


def call_llm(model, prompt):
    body = json.dumps({"model": model, "prompt": prompt, "stream": False,
                       "options": {"temperature": 0.2, "num_predict": 1500}}).encode()
    req = urllib.request.Request(OLLAMA + "/api/generate", data=body,
                                 headers={"content-type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=900)).get("response", "")


def extract_yaml(text):
    m = re.search(r"```(?:yaml)?\s*(.*?)```", text, re.S)
    t = m.group(1) if m else text
    # take from first 'id:' line
    i = t.find("\nid:")
    if i < 0 and t.startswith("id:"):
        i = 0
    t = t[i + 1:] if i > 0 else t
    # trim trailing prose after last meaningful line
    lines = [l for l in t.splitlines() if l.strip()]
    # drop obvious prose lines
    keep = [l for l in lines if re.match(r"^[\w\-'\"\s:\[\]{},.$()+*@]+$", l) or l.startswith(" ")]
    return "\n".join(keep) + "\n"


def build_prompt(spec, retry_note=""):
    rid, lang, cat, sev, owasp, cwe, conf, desc, vuln, clean = spec
    return (SYSTEM + f"""
SPEC: id {rid}; languages [{lang}]; severity {sev}; category {cat};
owasp {owasp}; cwe {cwe}; confidence {conf}; weakness: {desc}.
Vulnerable (MUST match): {vuln}
Clean (MUST NOT match): {clean}
{retry_note}""")


def normalize(doc, spec):
    rid, lang, cat, sev, owasp, cwe, conf, desc, vuln, clean = spec
    if not isinstance(doc, dict):
        return None
    doc["id"] = rid
    doc["languages"] = [lang]
    doc["severity"] = sev
    doc["category"] = cat
    md = doc.get("metadata") or {}
    md["owasp"] = owasp
    md["cwe"] = cwe
    md["confidence"] = conf
    doc["metadata"] = md
    # auto-add single-arg variant for `f($VAR, ...)` shapes
    either = doc.get("pattern-either")
    if isinstance(either, list):
        seen = {e.get("pattern") for e in either if isinstance(e, dict)}
        extra = []
        for e in either:
            p = e.get("pattern", "") if isinstance(e, dict) else ""
            if re.search(r"\(\$VAR,\s*\.\.\.\)$", p):
                solo = re.sub(r"\(\$VAR,\s*\.\.\.\)$", "($VAR)", p)
                if solo not in seen:
                    extra.append({"pattern": solo})
        doc["pattern-either"] = either + extra
    return doc


def validate(tmp, rid, lang, vuln, clean):
    """Write fixtures into tmp rules/tests/<rid>/ and run harness. Returns (ok, log)."""
    ext = EXT[lang]
    d = os.path.join(tmp, "tests", rid)
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, f"fail.{ext}"), "w").write(vuln + "\n")
    open(os.path.join(d, f"pass.{ext}"), "w").write(clear_text(clean) + "\n")
    p = subprocess.run([CODEGREP, "rule", "test", tmp], capture_output=True, text=True)
    log = p.stdout + p.stderr
    return (p.returncode == 0, log)


def clear_text(s):
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None)
    ap.add_argument("--model", default="qwen3:8b")
    args = ap.parse_args()
    rules_dir = os.path.join(REPO, "rules")
    existing = set()
    for root, _, files in os.walk(rules_dir):
        if "tests" in root:
            continue
        for f in files:
            if f.endswith((".yaml", ".yml")):
                try:
                    d = yaml.safe_load(open(os.path.join(root, f)))
                    docs = d if isinstance(d, list) else [d]
                    for r in docs:
                        existing.add(r["id"])
                except Exception:
                    pass
    ok, skipped, failed = 0, 0, []
    for spec in SPECS:
        rid, lang = spec[0], spec[1]
        if args.only and rid not in args.only.split(","):
            continue
        if rid in existing:
            skipped += 1
            continue
        target = os.path.join(rules_dir, lang if lang != "generic" else "secrets",
                              rid.split("-", 1)[1] + ".yaml")
        if os.path.exists(target):
            skipped += 1
            continue
        accepted = False
        log = ""
        for attempt in (0, 1):
            note = ("PREVIOUS OUTPUT FAILED VALIDATION — fix the pattern. "
                    f"Details:\n{log[-800:]}" if attempt else "")
            try:
                raw = call_llm(args.model, build_prompt(spec, note))
            except Exception as e:
                log = f"llm error: {e}"
                continue
            try:
                doc = normalize(yaml.safe_load(extract_yaml(raw)), spec)
            except Exception as e:
                log = f"yaml parse error: {e}\n{raw[:400]}"
                continue
            if not doc or not (doc.get("pattern") or doc.get("pattern-either")):
                log = f"no pattern in output:\n{raw[:400]}"
                continue
            tmp = tempfile.mkdtemp()
            try:
                open(os.path.join(tmp, "r.yaml"), "w").write(yaml.safe_dump(doc))
                good, log = validate(tmp, rid, lang, spec[8], spec[9])
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
            if good:
                accepted = True
                break
        if accepted:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            open(target, "w").write(yaml.safe_dump(doc))
            td = os.path.join(rules_dir, "tests", rid)
            os.makedirs(td, exist_ok=True)
            open(os.path.join(td, f"fail.{EXT[lang]}"), "w").write(spec[8] + "\n")
            open(os.path.join(td, f"pass.{EXT[lang]}"), "w").write(spec[9] + "\n")
            print(f"ACCEPT {rid}", flush=True)
            ok += 1
        else:
            print(f"REJECT {rid} :: {log[-200:]}", flush=True)
            failed.append(rid)
    print(f"done: accepted={ok} skipped={skipped} failed={len(failed)} {failed}")


if __name__ == "__main__":
    main()

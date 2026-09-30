//! End-to-end: C-family files are discovered and scanned with the C rule
//! set, with `language` reported per extension (`.c` → c, C++ extensions →
//! cpp).

use codegrep::{scan, ScanOptions};

const VULN_C: &str = r#"
#include <stdio.h>
void copy(char *dst, const char *src) {
    gets(dst);
    strcpy(dst, src);
}
"#;

const VULN_CPP: &str = r#"
#include <cstdio>
class Copier {
public:
    void copy(char *dst, const char *src) {
        gets(dst);
        strcpy(dst, src);
    }
};
"#;

#[test]
fn c_family_files_scanned_with_c_rules() {
    let dir = std::env::temp_dir().join(format!("cg-cpp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("vuln.c"), VULN_C).unwrap();
    std::fs::write(dir.join("vuln.cpp"), VULN_CPP).unwrap();
    std::fs::write(dir.join("vuln.hpp"), VULN_CPP).unwrap();

    let report = scan(&ScanOptions {
        path: dir.to_str().unwrap().to_string(),
        rules: "../../rules".into(),
        no_cache: true,
        ..Default::default()
    })
    .expect("scan must succeed");

    assert_eq!(report.files_scanned, 3, "all three C-family files discovered");
    assert!(report.rules_loaded >= 1000);

    let for_ext = |ext: &str| -> Vec<_> {
        report
            .findings
            .iter()
            .filter(|f| f.path.ends_with(ext))
            .collect()
    };
    let expect = |ext: &str, lang: &str| {
        let fs = for_ext(ext);
        assert_eq!(fs.len(), 2, "{ext} findings (gets + strcpy): {fs:?}");
        assert!(fs.iter().all(|f| f.language == lang), "{ext}: {fs:?}");
        assert!(fs.iter().any(|f| f.rule_id == "c-gets-buffer-overflow"));
        assert!(fs.iter().any(|f| f.rule_id == "c-strcpy-unbounded"));
    };
    expect(".c", "c");
    expect(".cpp", "cpp");
    expect(".hpp", "cpp");

    std::fs::remove_dir_all(&dir).ok();
}

//! codegrep parser: Tree-sitter (MIT) based, error-tolerant, offline.
//! Core 10 langs (Python, JavaScript, TypeScript, Go, Java, Ruby, PHP, C#, C,
//! C++) have tree-sitter grammars. Matching itself is regex-on-text, so
//! additional languages (terraform, yaml, dockerfile, scala, ocaml, kotlin,
//! bash, json, html) are supported via extension detection + text scan with
//! no grammar.

use anyhow::{anyhow, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    Python,
    JavaScript,
    TypeScript,
    Go,
    Java,
    Ruby,
    Php,
    CSharp,
    C,
    Cpp,
    // Text-scanned languages (no tree-sitter grammar; see module doc).
    Terraform,
    Yaml,
    Dockerfile,
    Scala,
    Ocaml,
    Kotlin,
    Bash,
    Json,
    Html,
}

impl Language {
    pub fn from_path(path: &str) -> Option<Self> {
        let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
        if path.ends_with(".py") {
            Some(Self::Python)
        } else if path.ends_with(".js") || path.ends_with(".mjs") || path.ends_with(".cjs") {
            Some(Self::JavaScript)
        } else if path.ends_with(".ts")
            || path.ends_with(".tsx")
            || path.ends_with(".mts")
            || path.ends_with(".cts")
        {
            Some(Self::TypeScript)
        } else if path.ends_with(".go") {
            Some(Self::Go)
        } else if path.ends_with(".java") {
            Some(Self::Java)
        } else if path.ends_with(".rb") {
            Some(Self::Ruby)
        } else if path.ends_with(".php") {
            Some(Self::Php)
        } else if path.ends_with(".cs") {
            Some(Self::CSharp)
        } else if path.ends_with(".tf") || path.ends_with(".tfvars") {
            Some(Self::Terraform)
        } else if path.ends_with(".yaml") || path.ends_with(".yml") {
            Some(Self::Yaml)
        } else if base.starts_with("Dockerfile") || base.ends_with("Dockerfile") {
            Some(Self::Dockerfile)
        } else if path.ends_with(".scala") {
            Some(Self::Scala)
        } else if path.ends_with(".cpp")
            || path.ends_with(".cc")
            || path.ends_with(".cxx")
            || path.ends_with(".hpp")
            || path.ends_with(".hh")
            || path.ends_with(".hxx")
        {
            Some(Self::Cpp)
        } else if path.ends_with(".c") || path.ends_with(".h") {
            Some(Self::C)
        } else if path.ends_with(".ml") || path.ends_with(".mli") {
            Some(Self::Ocaml)
        } else if path.ends_with(".kt") || path.ends_with(".kts") {
            Some(Self::Kotlin)
        } else if path.ends_with(".sh") || path.ends_with(".bash") || path.ends_with(".zsh") {
            Some(Self::Bash)
        } else if path.ends_with(".json") {
            Some(Self::Json)
        } else if path.ends_with(".html") || path.ends_with(".htm") {
            Some(Self::Html)
        } else {
            None
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Go => "go",
            Self::Java => "java",
            Self::Ruby => "ruby",
            Self::Php => "php",
            Self::CSharp => "csharp",
            Self::Terraform => "terraform",
            Self::Yaml => "yaml",
            Self::Dockerfile => "dockerfile",
            Self::Scala => "scala",
            Self::C => "c",
            Self::Cpp => "cpp",
            Self::Ocaml => "ocaml",
            Self::Kotlin => "kotlin",
            Self::Bash => "bash",
            Self::Json => "json",
            Self::Html => "html",
        }
    }

    /// Tree-sitter grammar, when one is wired. Text-scanned languages return
    /// `None` — they are matched by regex like every language is at scan time.
    pub fn grammar(&self) -> Option<tree_sitter::Language> {
        Some(match self {
            Self::Python => tree_sitter_python::LANGUAGE.into(),
            Self::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Self::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Self::Go => tree_sitter_go::LANGUAGE.into(),
            Self::Java => tree_sitter_java::LANGUAGE.into(),
            Self::Ruby => tree_sitter_ruby::LANGUAGE.into(),
            Self::Php => tree_sitter_php::LANGUAGE_PHP.into(),
            Self::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
            Self::C => tree_sitter_c::LANGUAGE.into(),
            Self::Cpp => tree_sitter_cpp::LANGUAGE.into(),
            Self::Terraform
            | Self::Yaml
            | Self::Dockerfile
            | Self::Scala
            | Self::Ocaml
            | Self::Kotlin
            | Self::Bash
            | Self::Json
            | Self::Html => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ParsedFile {
    pub language: Language,
    pub node_count: usize,
    pub has_error: bool,
    pub root_kind: String,
}

pub fn parse_source(language: Language, source: &str) -> Result<ParsedFile> {
    let mut parser = tree_sitter::Parser::new();
    let grammar = language
        .grammar()
        .ok_or_else(|| anyhow!("no tree-sitter grammar wired for {}", language.name()))?;
    parser
        .set_language(&grammar)
        .map_err(|e| anyhow!("grammar load failed for {}: {}", language.name(), e))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| anyhow!("tree-sitter parse returned None"))?;
    let root = tree.root_node();
    let mut count = 0usize;
    let mut has_error = root.has_error();
    // Iterative stack walk to avoid recursion limits on huge files.
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        count += 1;
        if n.is_error() {
            has_error = true;
        }
        let mut c = n.walk();
        for child in n.children(&mut c) {
            stack.push(child);
        }
    }
    Ok(ParsedFile {
        language,
        node_count: count,
        has_error,
        root_kind: root.kind().to_string(),
    })
}

pub fn parse_file(path: &str) -> Result<Option<ParsedFile>> {
    let lang = match Language::from_path(path) {
        Some(l) => l,
        None => return Ok(None),
    };
    let src = std::fs::read_to_string(path)?;
    // Cap single file at 2MB to bound memory; larger files are truncated for v0.1.
    let capped = if src.len() > 2_000_000 {
        &src[..2_000_000]
    } else {
        &src
    };
    Ok(Some(parse_source(lang, capped)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_python() {
        let p = parse_source(Language::Python, "x = input()\n").unwrap();
        assert!(p.node_count > 3);
        assert_eq!(p.root_kind, "module");
    }

    #[test]
    fn error_tolerant() {
        // Broken syntax must still produce a tree, not an error.
        let p = parse_source(Language::Python, "def broken(:\n  x = 1\n").unwrap();
        assert!(p.node_count > 0);
    }

    #[test]
    fn detects_languages() {
        assert_eq!(Language::from_path("a.py"), Some(Language::Python));
        assert_eq!(Language::from_path("a.go"), Some(Language::Go));
        assert_eq!(Language::from_path("A.java"), Some(Language::Java));
        assert_eq!(Language::from_path("a.rb"), Some(Language::Ruby));
        assert_eq!(Language::from_path("a.php"), Some(Language::Php));
        assert_eq!(Language::from_path("a.cs"), Some(Language::CSharp));
        assert_eq!(Language::from_path("a.rs"), None);
    }

    #[test]
    fn detects_text_scanned_languages() {
        assert_eq!(Language::from_path("main.tf"), Some(Language::Terraform));
        assert_eq!(Language::from_path("app.yaml"), Some(Language::Yaml));
        assert_eq!(Language::from_path("app.yml"), Some(Language::Yaml));
        assert_eq!(
            Language::from_path("/x/Dockerfile"),
            Some(Language::Dockerfile)
        );
        assert_eq!(
            Language::from_path("/x/Dockerfile.dev"),
            Some(Language::Dockerfile)
        );
        assert_eq!(Language::from_path("A.scala"), Some(Language::Scala));
        assert_eq!(Language::from_path("m.ml"), Some(Language::Ocaml));
        assert_eq!(Language::from_path("Main.kt"), Some(Language::Kotlin));
        assert_eq!(Language::from_path("run.sh"), Some(Language::Bash));
        assert_eq!(Language::from_path("data.json"), Some(Language::Json));
        assert_eq!(Language::from_path("index.html"), Some(Language::Html));
        // name() matches what rules declare in their `languages:` list.
        assert_eq!(Language::Yaml.name(), "yaml");
        assert_eq!(Language::Terraform.name(), "terraform");
        // Text-scanned langs have no grammar (None); core langs do (Some).
        assert!(Language::Yaml.grammar().is_none());
        assert!(Language::Python.grammar().is_some());
    }

    #[test]
    fn detects_c_family() {
        assert_eq!(Language::from_path("a.c"), Some(Language::C));
        assert_eq!(Language::from_path("a.h"), Some(Language::C));
        assert_eq!(Language::from_path("a.cpp"), Some(Language::Cpp));
        assert_eq!(Language::from_path("a.cc"), Some(Language::Cpp));
        assert_eq!(Language::from_path("a.cxx"), Some(Language::Cpp));
        assert_eq!(Language::from_path("a.hpp"), Some(Language::Cpp));
        assert_eq!(Language::from_path("a.hh"), Some(Language::Cpp));
        assert_eq!(Language::from_path("a.hxx"), Some(Language::Cpp));
        // name() matches what rules declare in their `languages:` list.
        assert_eq!(Language::C.name(), "c");
        assert_eq!(Language::Cpp.name(), "cpp");
        // Both C-family langs are grammar-backed now.
        assert!(Language::C.grammar().is_some());
        assert!(Language::Cpp.grammar().is_some());
    }

    #[test]
    fn parses_java() {
        let p = parse_source(
            Language::Java,
            "class A { void m() { Runtime.getRuntime().exec(input); } }\n",
        )
        .unwrap();
        assert!(p.node_count > 5);
        assert_eq!(p.root_kind, "program");
    }

    #[test]
    fn parses_ruby_php() {
        let r = parse_source(Language::Ruby, "system(user_input)\n").unwrap();
        assert!(r.node_count > 2);
        let p = parse_source(Language::Php, "<?php eval($x); ?>\n").unwrap();
        assert!(p.node_count > 2);
    }

    #[test]
    fn parses_csharp() {
        let c = parse_source(
            Language::CSharp,
            "class A { void M(string q) { new System.Data.SqlClient.SqlCommand(q); } }\n",
        )
        .unwrap();
        assert!(c.node_count > 5);
    }

    #[test]
    fn parses_c_family() {
        let c = parse_source(Language::C, "int main(void) { puts(buf); return 0; }\n").unwrap();
        assert!(c.node_count > 5);
        assert_eq!(c.root_kind, "translation_unit");
        let cpp = parse_source(
            Language::Cpp,
            "class A { public: void m(const char *s) { puts(s); } };\n",
        )
        .unwrap();
        assert!(cpp.node_count > 5);
        assert_eq!(cpp.root_kind, "translation_unit");
        // Error tolerance holds for C-family too.
        let broken = parse_source(Language::Cpp, "void f( { gets(x);\n").unwrap();
        assert!(broken.node_count > 0);
    }
}

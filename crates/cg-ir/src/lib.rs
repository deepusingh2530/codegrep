//! codegrep IR: own Generic AST (GNode), lowered from Tree-sitter CST.
//! Original design — not copied from any existing scanner. Named nodes only, text truncated.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Range {
    pub start_line: usize,
    pub start_col: usize,
    pub end_line: usize,
    pub end_col: usize,
    pub start_byte: usize,
    pub end_byte: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GNode {
    /// Normalized kind: e.g. "call", "function", "string", "identifier", "import", "if", "loop", "return", "assign", "other:<ts-kind>"
    pub kind: String,
    /// Raw Tree-sitter kind for debugging.
    pub ts_kind: String,
    pub text: String,
    pub range: Range,
    pub children: Vec<GNode>,
}

impl GNode {
    pub fn snippet(&self, max: usize) -> String {
        let t: String = self.text.chars().take(max).collect();
        t.replace('\n', " ")
    }
}

fn normalize_kind(ts_kind: &str) -> &str {
    match ts_kind {
        "call_expression" | "call" => "call",
        "function_definition" | "function_declaration" | "function" | "method_definition"
        | "func_declaration" => "function",
        "string" | "string_literal" | "interpreted_string_literal" => "string",
        "identifier" | "field_identifier" | "name" => "identifier",
        "import_statement" | "import_declaration" | "import" => "import",
        "if_statement" => "if",
        "for_statement" | "while_statement" | "for_clause" => "loop",
        "return_statement" => "return",
        "assignment_expression" | "assignment_statement" | "short_var_declaration"
        | "expression_statement" => "assign",
        _ => "other",
    }
}

pub fn lower(language: cg_parser::Language, source: &str) -> anyhow::Result<GNode> {
    let mut parser = tree_sitter::Parser::new();
    let grammar = language
        .grammar()
        .ok_or_else(|| anyhow::anyhow!("no grammar for {}", language.name()))?;
    parser
        .set_language(&grammar)
        .map_err(|e| anyhow::anyhow!("grammar: {e}"))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| anyhow::anyhow!("parse None"))?;
    let root = tree.root_node();
    Ok(build_node(root, source))
}

fn build_node(node: tree_sitter::Node, source: &str) -> GNode {
    let ts_kind = node.kind().to_string();
    let norm = normalize_kind(&ts_kind);
    let kind = if norm == "other" {
        format!("other:{ts_kind}")
    } else {
        norm.to_string()
    };
    let start = node.start_position();
    let end = node.end_position();
    let text: String = source[node.start_byte()..node.end_byte()]
        .chars()
        .take(512)
        .collect();
    let mut children = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        children.push(build_node(child, source));
    }
    GNode {
        kind,
        ts_kind,
        text,
        range: Range {
            start_line: start.row + 1,
            start_col: start.column,
            end_line: end.row + 1,
            end_col: end.column,
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
        },
        children,
    }
}

/// Collect all `call` nodes' callee text (first identifier-ish child) for pre-filter stats.
pub fn collect_callees(node: &GNode, out: &mut Vec<String>) {
    if node.kind == "call" {
        // Heuristic: first 64 chars up to '(' is callee.
        let callee = node.text.split('(').next().unwrap_or("").trim();
        if !callee.is_empty() {
            out.push(callee.chars().take(128).collect());
        }
    }
    for c in &node.children {
        collect_callees(c, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowers_python_call() {
        let g = lower(cg_parser::Language::Python, "cursor.execute(q)\n").unwrap();
        let mut callees = vec![];
        collect_callees(&g, &mut callees);
        assert!(callees.iter().any(|c| c.contains("execute")));
    }

    #[test]
    fn lowers_c_family_call() {
        let c = lower(cg_parser::Language::C, "int main(void) { puts(buf); }\n").unwrap();
        let mut callees = vec![];
        collect_callees(&c, &mut callees);
        assert!(callees.iter().any(|k| k.contains("puts")));

        let cpp = lower(
            cg_parser::Language::Cpp,
            "class A { public: void m(const char *s) { strcpy(dst, s); } };\n",
        )
        .unwrap();
        let mut callees2 = vec![];
        collect_callees(&cpp, &mut callees2);
        assert!(callees2.iter().any(|k| k.contains("strcpy")));
    }
}

//! Pure helpers for P1 analysis tools (call graph, impact, quality, complexity).

use std::collections::HashMap;

use serde_json::{json, Value};

/// Classify a BSL module path/URI into a 1C module type label.
pub fn classify_module_type(uri_or_path: &str) -> &'static str {
    let p = uri_or_path.replace('\\', "/").to_lowercase();
    let base = p.rsplit('/').next().unwrap_or("");

    if p.contains("/forms/") && (base == "module.bsl" || p.ends_with("form/module.bsl")) {
        return "FormModule";
    }
    match base {
        "managermodule.bsl" => return "ManagerModule",
        "objectmodule.bsl" => return "ObjectModule",
        "recordsetmodule.bsl" => return "RecordSetModule",
        "valuemanagermodule.bsl" => return "ValueManagerModule",
        "commandmodule.bsl" => return "CommandModule",
        "module.bsl" if p.contains("/commonmodules/") => return "CommonModule",
        _ => {}
    }
    if p.contains("/commonmodules/") {
        return "CommonModule";
    }
    if p.contains("/forms/") {
        return "FormModule";
    }
    "Module"
}

const BSL_ENTRY_POINTS: &[&str] = &[
    "ПриЗаписи",
    "ПриПроведении",
    "ПриОтменеПроведения",
    "ПередЗаписью",
    "ПередУдалением",
    "ПриУстановкеНовогоНомера",
    "ПриКопировании",
    "ОбработкаЗаполнения",
    "ОбработкаПроверкиЗаполнения",
    "ПриСозданииНаСервере",
    "ПриОткрытии",
    "ПриЗакрытии",
    "ПередЗаписьюНаСервере",
    "ПриЗаписиНаСервере",
    "ПослеЗаписиНаСервере",
    "ПриЧтенииНаСервере",
    "ОбработкаОповещения",
    "ОбработкаНавигационнойСсылки",
    "ОбработкаКоманды",
    "ПриВыполнении",
    "ПриНачалеРаботыСистемы",
    "ПриЗавершенииРаботыСистемы",
    "ПередНачаломРаботыСистемы",
    "ПередЗавершениемРаботыСистемы",
    "ОбработчикРегламентногоЗадания",
    "ОбработкаВызоваHTTPСервиса",
    "ОбработкаВызоваWebСервиса",
    "OnWrite",
    "Posting",
    "OnOpen",
    "OnCreateAtServer",
    "BeforeWrite",
    "OnClose",
];

pub fn is_bsl_entry_point(name: &str) -> bool {
    BSL_ENTRY_POINTS.iter().any(|e| *e == name)
}

#[derive(Debug, Clone)]
pub struct CallGraphLimits {
    pub depth_up: u32,
    pub depth_down: u32,
    pub max_nodes: usize,
}

impl Default for CallGraphLimits {
    fn default() -> Self {
        Self {
            depth_up: 5,
            depth_down: 5,
            max_nodes: 100,
        }
    }
}

pub fn item_key(item: &Value) -> String {
    let uri = item.get("uri").and_then(|v| v.as_str()).unwrap_or("");
    let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let line = item
        .pointer("/selectionRange/start/line")
        .or_else(|| item.pointer("/range/start/line"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let character = item
        .pointer("/selectionRange/start/character")
        .or_else(|| item.pointer("/range/start/character"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    format!("{uri}|{name}|{line}|{character}")
}

pub fn call_item_from_edge(edge: &Value, direction: &str) -> Option<Value> {
    let key = if direction == "up" { "from" } else { "to" };
    edge.get(key).cloned()
}

/// Call graph in both directions.
/// `expand(item, "up"|"down")` returns call-hierarchy edges.
///
/// Each direction is an iterative DFS that expands a node once.
/// An edge to a node still on the active path is a back-edge (`is_cycle`)
/// and is not followed. An edge to a node already finished on another path
/// is dropped, so a diamond contributes that node once and is not a cycle.
pub async fn build_call_graph_json<F, Fut>(
    root_item: Value,
    limits: CallGraphLimits,
    mut expand: F,
) -> Value
where
    F: FnMut(Value, &'static str) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<Value>, String>>,
{
    let mut node_count = 0usize;
    let mut cycles = 0usize;
    let mut entry_points: Vec<String> = Vec::new();
    let mut truncated = false;
    let mut truncate_reason = String::new();

    let root_name = root_item
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("(root)")
        .to_string();
    if is_bsl_entry_point(&root_name) {
        entry_points.push(root_name.clone());
    }

    let incoming = build_tree(
        &root_item,
        "up",
        limits.depth_up,
        limits.max_nodes,
        &mut node_count,
        &mut cycles,
        &mut entry_points,
        &mut truncated,
        &mut truncate_reason,
        &mut expand,
    )
    .await;

    let outgoing = build_tree(
        &root_item,
        "down",
        limits.depth_down,
        limits.max_nodes,
        &mut node_count,
        &mut cycles,
        &mut entry_points,
        &mut truncated,
        &mut truncate_reason,
        &mut expand,
    )
    .await;

    entry_points.sort();
    entry_points.dedup();

    json!({
        "root": {
            "name": root_name,
            "uri": root_item.get("uri").cloned().unwrap_or(Value::Null),
            "key": item_key(&root_item),
            "is_entry_point": is_bsl_entry_point(root_item.get("name").and_then(|v| v.as_str()).unwrap_or("")),
        },
        "incoming_tree": incoming,
        "outgoing_tree": outgoing,
        "total_nodes": node_count,
        "cycles_found": cycles,
        "entry_points_found": entry_points,
        "truncated": truncated,
        "truncate_reason": if truncate_reason.is_empty() { Value::Null } else { json!(truncate_reason) },
        "limits": {
            "depth_up": limits.depth_up,
            "depth_down": limits.depth_down,
            "max_nodes": limits.max_nodes
        }
    })
}

const COLOR_ON_PATH: u8 = 1;
const COLOR_FINISHED: u8 = 2;

struct WalkFrame {
    item: Value,
    depth: u32,
    key: String,
    edges: Vec<Value>,
    next_edge: usize,
    child_refs: Vec<Value>,
    entered: bool,
}

fn back_edge_stub(child: &Value, child_key: String) -> Value {
    json!({
        "name": child.get("name").cloned().unwrap_or(json!("")),
        "uri": child.get("uri").cloned().unwrap_or(Value::Null),
        "key": child_key,
        "is_cycle": true,
        "module_type": classify_module_type(
            child.get("uri").and_then(|v| v.as_str()).unwrap_or("")
        ),
    })
}

async fn build_tree<F, Fut>(
    root: &Value,
    direction: &'static str,
    max_depth: u32,
    max_nodes: usize,
    node_count: &mut usize,
    cycles: &mut usize,
    entry_points: &mut Vec<String>,
    truncated: &mut bool,
    truncate_reason: &mut String,
    expand: &mut F,
) -> Value
where
    F: FnMut(Value, &'static str) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<Value>, String>>,
{
    let root_key = item_key(root);
    let mut nodes: HashMap<String, Value> = HashMap::new();
    let mut children_map: HashMap<String, Vec<Value>> = HashMap::new();
    // Gray (on the active path) vs black (expanded). A gray target is a
    // back-edge. A black target was already visited and is dropped.
    let mut color: HashMap<String, u8> = HashMap::new();

    let mut stack = Vec::new();
    if max_nodes == 0 {
        *truncated = true;
        *truncate_reason = format!("max_nodes={max_nodes}");
    } else {
        stack.push(WalkFrame {
            item: root.clone(),
            depth: 0,
            key: root_key.clone(),
            edges: Vec::new(),
            next_edge: 0,
            child_refs: Vec::new(),
            entered: false,
        });
    }

    while let Some(mut frame) = stack.pop() {
        if !frame.entered {
            if *node_count >= max_nodes {
                *truncated = true;
                *truncate_reason = format!("max_nodes={max_nodes}");
                continue;
            }
            *node_count += 1;
            color.insert(frame.key.clone(), COLOR_ON_PATH);

            let name = frame
                .item
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let uri = frame.item.get("uri").and_then(|v| v.as_str()).unwrap_or("");
            let is_entry = is_bsl_entry_point(&name);
            if is_entry {
                entry_points.push(name.clone());
            }
            nodes.insert(
                frame.key.clone(),
                json!({
                    "name": name,
                    "uri": frame.item.get("uri").cloned().unwrap_or(Value::Null),
                    "key": frame.key.clone(),
                    "depth": frame.depth,
                    "direction": direction,
                    "module_type": classify_module_type(uri),
                    "is_entry_point": is_entry,
                }),
            );

            if frame.depth >= max_depth {
                children_map.insert(frame.key.clone(), Vec::new());
                color.insert(frame.key, COLOR_FINISHED);
                continue;
            }

            match expand(frame.item.clone(), direction).await {
                Ok(edges) => {
                    frame.edges = edges;
                    frame.entered = true;
                    stack.push(frame);
                }
                Err(err) => {
                    if let Some(node) = nodes.get_mut(&frame.key) {
                        if let Some(obj) = node.as_object_mut() {
                            obj.insert("error".into(), json!(err));
                        }
                    }
                    children_map.insert(frame.key.clone(), Vec::new());
                    color.insert(frame.key, COLOR_FINISHED);
                }
            }
            continue;
        }

        if frame.next_edge >= frame.edges.len() {
            children_map.insert(frame.key.clone(), frame.child_refs);
            color.insert(frame.key, COLOR_FINISHED);
            continue;
        }

        let edge = frame.edges[frame.next_edge].clone();
        frame.next_edge += 1;
        let Some(child_item) = call_item_from_edge(&edge, direction) else {
            stack.push(frame);
            continue;
        };
        let child_key = item_key(&child_item);
        match color.get(&child_key).copied() {
            Some(COLOR_ON_PATH) => {
                *cycles += 1;
                frame
                    .child_refs
                    .push(back_edge_stub(&child_item, child_key));
                stack.push(frame);
            }
            Some(COLOR_FINISHED) => {
                stack.push(frame);
            }
            _ => {
                if *node_count >= max_nodes {
                    *truncated = true;
                    *truncate_reason = format!("max_nodes={max_nodes}");
                    stack.push(frame);
                    continue;
                }
                let child_depth = frame.depth + 1;
                frame.child_refs.push(json!({ "ref": child_key.clone() }));
                stack.push(frame);
                stack.push(WalkFrame {
                    item: child_item,
                    depth: child_depth,
                    key: child_key,
                    edges: Vec::new(),
                    next_edge: 0,
                    child_refs: Vec::new(),
                    entered: false,
                });
            }
        }
    }

    fn materialize(
        key: &str,
        nodes: &HashMap<String, Value>,
        children_map: &HashMap<String, Vec<Value>>,
    ) -> Value {
        let mut node = nodes.get(key).cloned().unwrap_or(json!({ "key": key }));
        let mut kids = Vec::new();
        if let Some(refs) = children_map.get(key) {
            for r in refs {
                if r.get("is_cycle").and_then(|v| v.as_bool()) == Some(true) {
                    kids.push(r.clone());
                } else if let Some(child_key) = r.get("ref").and_then(|v| v.as_str()) {
                    kids.push(materialize(child_key, nodes, children_map));
                }
            }
        }
        if let Some(obj) = node.as_object_mut() {
            obj.insert("children".into(), Value::Array(kids));
        }
        node
    }

    materialize(&root_key, &nodes, &children_map)
}

pub fn build_symbol_impact_json(
    symbol_name: &str,
    file_path: &str,
    line: u32,
    character: u32,
    callers: &[Value],
    refs: &Value,
) -> Value {
    let mut by_type: HashMap<String, Vec<Value>> = HashMap::new();
    for edge in callers {
        let from = edge.get("from").cloned().unwrap_or(Value::Null);
        let uri = from.get("uri").and_then(|v| v.as_str()).unwrap_or("");
        let module_type = classify_module_type(uri).to_string();
        by_type.entry(module_type).or_default().push(json!({
            "name": from.get("name").cloned().unwrap_or(json!("")),
            "uri": from.get("uri").cloned().unwrap_or(Value::Null),
            "fromRanges": edge.get("fromRanges").cloned().unwrap_or(json!([]))
        }));
    }

    let ref_count = refs.as_array().map(|a| a.len()).unwrap_or(0);
    let mut grouped = serde_json::Map::new();
    for (k, mut v) in by_type {
        v.sort_by(|a, b| {
            a.get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .cmp(b.get("name").and_then(|x| x.as_str()).unwrap_or(""))
        });
        grouped.insert(k, Value::Array(v));
    }

    json!({
        "symbol": symbol_name,
        "position": { "file_path": file_path, "line": line, "character": character },
        "incoming_callers_by_module_type": grouped,
        "incoming_callers_total": callers.len(),
        "references_total": ref_count,
        "references": refs,
        "note": "Call hierarchy = direct CALL edges only. Event subscriptions / string refs in queries may be missing — complement with grep."
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplexityRow {
    pub method: String,
    pub line: u32,
    pub cyclomatic: Option<u32>,
    pub cognitive: Option<u32>,
}

fn trailing_int(title: &str) -> Option<u32> {
    let digits: String = title
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

pub fn parse_complexity_lenses(lenses: &[Value]) -> Vec<ComplexityRow> {
    let mut map: HashMap<(u32, String), ComplexityRow> = HashMap::new();

    for lens in lenses {
        let line = lens
            .pointer("/range/start/line")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let title = lens
            .pointer("/command/title")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let method = lens
            .pointer("/command/arguments/0")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let value = trailing_int(title.trim());

        let key = (line, method.clone());
        let row = map.entry(key).or_insert(ComplexityRow {
            method,
            line,
            cyclomatic: None,
            cognitive: None,
        });
        let lower = title.to_lowercase();
        if lower.contains("цикл") || lower.contains("cyclomatic") {
            row.cyclomatic = value;
        } else if lower.contains("когнитив") || lower.contains("cognitive") {
            row.cognitive = value;
        } else if row.cyclomatic.is_none() {
            row.cyclomatic = value;
        }
    }

    let mut rows: Vec<_> = map.into_values().collect();
    rows.sort_by_key(|r| r.line);
    rows
}

pub fn complexity_rows_to_json(rows: &[ComplexityRow]) -> Value {
    let flagged: Vec<_> = rows
        .iter()
        .filter(|r| r.cyclomatic.unwrap_or(0) > 20 || r.cognitive.unwrap_or(0) > 15)
        .map(|r| {
            json!({
                "method": r.method,
                "line": r.line,
                "cyclomatic": r.cyclomatic,
                "cognitive": r.cognitive
            })
        })
        .collect();
    let all: Vec<_> = rows
        .iter()
        .map(|r| {
            json!({
                "method": r.method,
                "line": r.line,
                "cyclomatic": r.cyclomatic,
                "cognitive": r.cognitive,
                "over_threshold": r.cyclomatic.unwrap_or(0) > 20 || r.cognitive.unwrap_or(0) > 15
            })
        })
        .collect();
    json!({
        "methods": all,
        "flagged": flagged,
        "thresholds": { "cyclomatic": 20, "cognitive": 15 }
    })
}

#[derive(Debug, Clone, serde::Deserialize)]
struct BslDiagnosticMeta {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    tags: Vec<String>,
}

fn diagnostic_table() -> &'static HashMap<String, BslDiagnosticMeta> {
    use std::sync::OnceLock;
    static TABLE: OnceLock<HashMap<String, BslDiagnosticMeta>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let raw = include_str!("../data/bsl_diagnostic_meta.json");
        serde_json::from_str(raw).unwrap_or_default()
    })
}

pub fn quality_categories(code: &str) -> Vec<&'static str> {
    let Some(meta) = diagnostic_table().get(code) else {
        return Vec::new();
    };
    let mut cats = Vec::new();
    if meta.kind == "SECURITY_HOTSPOT" || meta.kind == "VULNERABILITY" {
        cats.push("security");
    }
    for t in &meta.tags {
        match t.as_str() {
            "PERFORMANCE" => cats.push("performance"),
            "SQL" => cats.push("sql"),
            _ => {}
        }
    }
    cats
}

pub fn filter_quality_diagnostics(diagnostics: &[Value], wanted: &[&str]) -> Value {
    let mut out = Vec::new();
    for d in diagnostics {
        let code = d
            .get("code")
            .and_then(|c| {
                c.as_str().map(|s| s.to_string()).or_else(|| {
                    c.get("value")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
            })
            .unwrap_or_default();
        let cats = quality_categories(&code);
        if cats.is_empty() {
            continue;
        }
        if !wanted.is_empty() && !cats.iter().any(|c| wanted.contains(c)) {
            continue;
        }
        out.push(json!({
            "code": code,
            "categories": cats,
            "message": d.get("message").cloned().unwrap_or(Value::Null),
            "severity": d.get("severity").cloned().unwrap_or(Value::Null),
            "range": d.get("range").cloned().unwrap_or(Value::Null),
        }));
    }
    json!({ "diagnostics": out, "count": out.len() })
}

pub fn merge_module_health(complexity: &Value, quality: &Value) -> Value {
    json!({
        "complexity": complexity,
        "quality": quality,
        "refactor_priority": complexity
            .get("flagged")
            .cloned()
            .unwrap_or(json!([])),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::page::{present_call_graph, PageQuery};

    fn symbol(name: &str) -> Value {
        json!({
            "name": name,
            "uri": format!("file:///{name}.bsl"),
            "selectionRange": {"start": {"line": 1, "character": 0}}
        })
    }

    fn real_names(node: &Value) -> Vec<String> {
        let mut names = Vec::new();
        fn walk(node: &Value, names: &mut Vec<String>) {
            if node.get("is_cycle").and_then(|v| v.as_bool()) == Some(true) {
                return;
            }
            if let Some(name) = node.get("name").and_then(|v| v.as_str()) {
                names.push(name.to_string());
            }
            if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
                for child in children {
                    walk(child, names);
                }
            }
        }
        walk(node, &mut names);
        names
    }

    #[test]
    fn classifies_common_and_manager_modules() {
        assert_eq!(
            classify_module_type("file:///x/CommonModules/ОбщийМодульА/Ext/Module.bsl"),
            "CommonModule"
        );
        assert_eq!(
            classify_module_type("file:///x/Documents/Doc/Ext/ManagerModule.bsl"),
            "ManagerModule"
        );
        assert_eq!(
            classify_module_type("file:///x/Catalogs/X/Forms/Form/Ext/Form/Module.bsl"),
            "FormModule"
        );
    }

    #[test]
    fn parses_complexity_titles() {
        let lenses = vec![
            json!({
                "range": {"start": {"line": 3, "character": 0}},
                "command": {"title": "Цикломатическая сложность: 8", "arguments": ["ОбработатьДанные"]}
            }),
            json!({
                "range": {"start": {"line": 3, "character": 0}},
                "command": {"title": "Когнитивная сложность: 12", "arguments": ["ОбработатьДанные"]}
            }),
        ];
        let rows = parse_complexity_lenses(&lenses);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].cyclomatic, Some(8));
        assert_eq!(rows[0].cognitive, Some(12));
    }

    #[test]
    fn filters_quality_by_category() {
        let table = diagnostic_table();
        assert!(!table.is_empty());
        let (code, _) = table
            .iter()
            .find(|(_, m)| {
                m.kind == "SECURITY_HOTSPOT"
                    || m.tags.iter().any(|t| t == "SQL" || t == "PERFORMANCE")
            })
            .expect("some quality rule");
        let cats = quality_categories(code);
        assert!(!cats.is_empty());
        let diags = vec![json!({
            "code": code,
            "message": "test",
            "severity": 2,
            "range": {"start":{"line":0,"character":0},"end":{"line":0,"character":1}}
        })];
        let filtered = filter_quality_diagnostics(&diags, &cats);
        assert_eq!(filtered["count"], 1);
    }

    #[test]
    fn symbol_impact_groups_callers() {
        let callers = vec![json!({
            "from": {
                "name": "ЗапуститьЦепочку",
                "uri": "file:///CommonModules/A/Ext/Module.bsl"
            },
            "fromRanges": []
        })];
        let impact = build_symbol_impact_json(
            "ОбработатьДанные",
            "1c-src/x.bsl",
            2,
            10,
            &callers,
            &json!([]),
        );
        assert_eq!(impact["incoming_callers_total"], 1);
        assert!(impact["incoming_callers_by_module_type"]
            .get("CommonModule")
            .is_some());
    }

    #[tokio::test]
    async fn call_graph_cycle_is_a_back_edge_and_does_not_revisit() {
        let root = symbol("A");
        let other = symbol("B");
        let expands = Arc::new(AtomicUsize::new(0));
        let graph = build_call_graph_json(
            root.clone(),
            CallGraphLimits {
                depth_up: 0,
                depth_down: 10,
                max_nodes: 50,
            },
            {
                let root = root.clone();
                let other = other.clone();
                let expands = Arc::clone(&expands);
                move |item, direction| {
                    let root = root.clone();
                    let other = other.clone();
                    let expands = Arc::clone(&expands);
                    async move {
                        if direction != "down" {
                            return Ok(vec![]);
                        }
                        expands.fetch_add(1, Ordering::SeqCst);
                        if item_key(&item) == item_key(&root) {
                            Ok(vec![json!({"to": other})])
                        } else if item_key(&item) == item_key(&other) {
                            Ok(vec![json!({"to": root})])
                        } else {
                            Ok(vec![])
                        }
                    }
                }
            },
        )
        .await;

        assert_eq!(graph["cycles_found"], 1);
        assert_eq!(graph["truncated"], false);
        // Incoming root at depth 0, plus A and B. The edge back to A adds no node.
        assert_eq!(graph["total_nodes"], 3);
        assert_eq!(expands.load(Ordering::SeqCst), 2);
        assert_eq!(real_names(&graph["outgoing_tree"]), vec!["A", "B"]);
        let back = &graph["outgoing_tree"]["children"][0]["children"][0];
        assert_eq!(back["is_cycle"], true);
        assert_eq!(back["key"], item_key(&root));
        assert!(back.get("children").is_none());

        let first = present_call_graph(&graph, PageQuery::parse(None, Some(1), None).unwrap());
        assert_eq!(first["detail"], "summary");
        assert_eq!(first["total"], 2);
        assert_eq!(first["returned"], 1);
        assert_eq!(first["next_offset"], 1);
        assert_eq!(first["items"][0]["name"], "B");
        assert_eq!(first["items"][0]["is_cycle"], false);
        let second = present_call_graph(&graph, PageQuery::parse(Some(1), Some(1), None).unwrap());
        assert_eq!(second["returned"], 1);
        assert_eq!(second["items"][0]["is_cycle"], true);
        assert_eq!(second["items"][0]["key"], item_key(&root));
        assert!(second["next_offset"].is_null());

        let full = present_call_graph(&graph, PageQuery::parse(None, None, Some("full")).unwrap());
        assert_eq!(full["detail"], "full");
        assert_eq!(
            full["outgoing_tree"]["children"][0]["children"][0]["is_cycle"],
            true
        );
    }

    #[tokio::test]
    async fn call_graph_diamond_visits_the_shared_node_once() {
        let root = symbol("A");
        let b = symbol("B");
        let c = symbol("C");
        let d = symbol("D");
        let expands_d = Arc::new(AtomicUsize::new(0));
        let graph = build_call_graph_json(
            root.clone(),
            CallGraphLimits {
                depth_up: 0,
                depth_down: 10,
                max_nodes: 50,
            },
            {
                let root = root.clone();
                let b = b.clone();
                let c = c.clone();
                let d = d.clone();
                let expands_d = Arc::clone(&expands_d);
                move |item, direction| {
                    let root = root.clone();
                    let b = b.clone();
                    let c = c.clone();
                    let d = d.clone();
                    let expands_d = Arc::clone(&expands_d);
                    async move {
                        if direction != "down" {
                            return Ok(vec![]);
                        }
                        let key = item_key(&item);
                        if key == item_key(&d) {
                            expands_d.fetch_add(1, Ordering::SeqCst);
                        }
                        if key == item_key(&root) {
                            Ok(vec![json!({"to": b}), json!({"to": c})])
                        } else if key == item_key(&b) || key == item_key(&c) {
                            Ok(vec![json!({"to": d})])
                        } else {
                            Ok(vec![])
                        }
                    }
                }
            },
        )
        .await;

        assert_eq!(graph["cycles_found"], 0);
        assert_eq!(graph["truncated"], false);
        // Incoming root, plus A, B, C, and D once.
        assert_eq!(graph["total_nodes"], 5);
        assert_eq!(expands_d.load(Ordering::SeqCst), 1);
        let mut names = real_names(&graph["outgoing_tree"]);
        names.sort();
        assert_eq!(names, vec!["A", "B", "C", "D"]);
        let outgoing = &graph["outgoing_tree"];
        assert_eq!(outgoing["children"][0]["name"], "B");
        assert_eq!(outgoing["children"][0]["children"][0]["name"], "D");
        assert_eq!(
            outgoing["children"][0]["children"][0]["children"],
            json!([])
        );
        assert_eq!(outgoing["children"][1]["name"], "C");
        assert_eq!(outgoing["children"][1]["children"], json!([]));

        let summary = present_call_graph(&graph, PageQuery::parse(None, None, None).unwrap());
        assert_eq!(summary["total"], 3);
        assert_eq!(summary["returned"], 3);
        assert!(summary["next_offset"].is_null());
        let listed: Vec<_> = summary["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["name"].as_str().unwrap())
            .collect();
        assert_eq!(listed, vec!["B", "D", "C"]);
        assert!(summary["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["is_cycle"] == false));
    }

    #[tokio::test]
    async fn call_graph_join_back_to_an_open_path_is_a_back_edge() {
        let root = symbol("A");
        let b = symbol("B");
        let c = symbol("C");
        let graph = build_call_graph_json(
            root.clone(),
            CallGraphLimits {
                depth_up: 0,
                depth_down: 10,
                max_nodes: 50,
            },
            {
                let root = root.clone();
                let b = b.clone();
                let c = c.clone();
                move |item, direction| {
                    let root = root.clone();
                    let b = b.clone();
                    let c = c.clone();
                    async move {
                        if direction != "down" {
                            return Ok(vec![]);
                        }
                        let key = item_key(&item);
                        if key == item_key(&root) {
                            Ok(vec![json!({"to": b}), json!({"to": c})])
                        } else if key == item_key(&b) {
                            Ok(vec![json!({"to": c})])
                        } else if key == item_key(&c) {
                            Ok(vec![json!({"to": b})])
                        } else {
                            Ok(vec![])
                        }
                    }
                }
            },
        )
        .await;

        assert_eq!(graph["cycles_found"], 1);
        assert_eq!(graph["truncated"], false);
        assert_eq!(graph["total_nodes"], 4);
        let mut names = real_names(&graph["outgoing_tree"]);
        names.sort();
        assert_eq!(names, vec!["A", "B", "C"]);
        let b_node = &graph["outgoing_tree"]["children"][0];
        assert_eq!(b_node["name"], "B");
        assert_eq!(b_node["children"][0]["name"], "C");
        assert_eq!(b_node["children"][0]["children"][0]["is_cycle"], true);
        assert_eq!(b_node["children"][0]["children"][0]["key"], item_key(&b));
        assert_eq!(
            graph["outgoing_tree"]["children"].as_array().unwrap().len(),
            1
        );
    }
}

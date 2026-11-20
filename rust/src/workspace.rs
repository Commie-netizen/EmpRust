//! Decrypted projections are rebuilt for the unlocked session and dropped on lock.
use crate::vault::{Vault, entry_meta, s};
use anyhow::Result;
use regex::Regex;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use unicode_normalization::{UnicodeNormalization, char::is_combining_mark};
use zeroize::Zeroizing;

fn fold_search(text: &str) -> String {
    text.chars()
        .flat_map(char::to_lowercase)
        .nfkd()
        .filter(|c| !is_combining_mark(*c))
        .collect()
}
fn search_words(text: &str) -> Vec<String> {
    fold_search(text)
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}
fn search_snippet(text: &str, terms: &[String]) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut first = None;
    let mut start = 0;
    while start < chars.len() {
        while start < chars.len() && !chars[start].is_alphanumeric() {
            start += 1;
        }
        let mut end = start;
        while end < chars.len() && (chars[end].is_alphanumeric() || is_combining_mark(chars[end])) {
            end += 1;
        }
        if start < end
            && terms.contains(&fold_search(&chars[start..end].iter().collect::<String>()))
        {
            first = Some(start);
            break;
        }
        start = end;
    }
    let pos = first.unwrap_or(0);
    let begin = pos.saturating_sub(50).min(chars.len().saturating_sub(160));
    chars[begin..chars.len().min(begin + 160)]
        .iter()
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}
fn phrase_match(field: &str, phrase: &str) -> bool {
    let field = fold_search(field);
    field.match_indices(phrase).any(|(start, _)| {
        let before = field[..start].chars().next_back();
        let after = field[start + phrase.len()..].chars().next();
        !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
            && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

pub fn is_text(media: &str) -> bool {
    let m = media.split(';').next().unwrap_or("");
    m.starts_with("text/")
        || m.ends_with("+json")
        || m.ends_with("+xml")
        || [
            "application/json",
            "application/xml",
            "application/javascript",
            "application/x-python",
            "application/sql",
            "application/toml",
            "application/yaml",
            "application/x-yaml",
            "image/svg+xml",
        ]
        .contains(&m)
}
pub fn media(path: &str) -> &'static str {
    match path
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_lowercase()
        .as_str()
    {
        "md" => "text/markdown",
        "txt" | "csv" | "log" => "text/plain",
        "rs" | "py" | "js" | "ts" | "css" => "text/plain",
        "json" => "application/json",
        "yaml" | "yml" => "application/yaml",
        "toml" => "application/toml",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}
pub fn parsed(text: &str, path: &str) -> Value {
    let wiki = Regex::new(r"(!?)\[\[([^\]\n]+)\]\]").unwrap();
    let tags = Regex::new(r"(?:^|\s)#([\p{L}\p{N}_/-]+)").unwrap();
    let mut links = BTreeSet::new();
    let mut embeds = BTreeSet::new();
    for cap in wiki.captures_iter(text) {
        let target = cap[2].split('|').next().unwrap().to_owned();
        if &cap[1] == "!" {
            embeds.insert(target);
        } else {
            links.insert(target);
        }
    }
    for cap in Regex::new(r"\[[^\]\n]*\]\(([^)\n]+\.md(?:#[^)\n]*)?)\)")
        .unwrap()
        .captures_iter(text)
    {
        links.insert(cap[1].to_owned());
    }
    let headings = text
        .lines()
        .filter_map(|line| {
            line.strip_prefix('#')
                .map(|s| s.trim_start_matches('#').trim().to_owned())
        })
        .collect::<Vec<_>>();
    json!({"title":headings.first().cloned().unwrap_or_else(||path.rsplit('/').next().unwrap_or(path).trim_end_matches(".md").to_owned()),"tags":tags.captures_iter(text).map(|c|c[1].to_owned()).collect::<BTreeSet<_>>(),"links":links,"embeds":embeds,"aliases":[],"headings":headings,"words":text.split_whitespace().count()})
}
pub struct Workspace {
    pub entries: Vec<Value>,
    pub texts: BTreeMap<String, Zeroizing<String>>,
    pub parsed: BTreeMap<String, Value>,
}
impl Workspace {
    pub fn new(v: &Vault) -> Result<Self> {
        let entries = v.entries();
        let mut texts = BTreeMap::new();
        let mut docs = BTreeMap::new();
        for e in &entries {
            let id = s(e, "entry_id");
            let text = if is_text(&s(e, "media_type")) {
                Zeroizing::new(String::from_utf8_lossy(&v.read(&id, None)?).into_owned())
            } else {
                Zeroizing::new(String::new())
            };
            docs.insert(id.clone(), parsed(&text, &s(e, "path")));
            texts.insert(id, text);
        }
        Ok(Self {
            entries,
            texts,
            parsed: docs,
        })
    }
    pub fn targets(&self, id: &str, doc: Option<&Value>) -> BTreeMap<String, String> {
        let Some(source) = self.entries.iter().find(|e| e["entry_id"] == id) else {
            return BTreeMap::new();
        };
        let doc = doc.unwrap_or(&self.parsed[id]);
        let source_path = s(source, "path");
        let parent = source_path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        let mut targets = BTreeMap::new();
        for raw in doc["links"]
            .as_array()
            .unwrap()
            .iter()
            .chain(doc["embeds"].as_array().unwrap())
        {
            let raw = raw.as_str().unwrap();
            let base = raw.split('#').next().unwrap().trim();
            let normalize = |p: &str| {
                let mut parts = Vec::new();
                for part in p.split('/') {
                    match part {
                        "." | "" => {}
                        ".." => {
                            parts.pop();
                        }
                        _ => parts.push(part),
                    }
                }
                parts.join("/").to_lowercase()
            };
            let near = normalize(&format!("{parent}/{base}"));
            let direct = normalize(base);
            let stem = |p: String| p.trim_end_matches(".md").to_owned();
            let candidate = self
                .entries
                .iter()
                .find(|e| stem(s(e, "path").to_lowercase()) == stem(near.clone()))
                .or_else(|| {
                    self.entries
                        .iter()
                        .find(|e| stem(s(e, "path").to_lowercase()) == stem(direct.clone()))
                })
                .or_else(|| {
                    let candidates = self
                        .entries
                        .iter()
                        .filter(|e| {
                            stem(s(e, "path").rsplit('/').next().unwrap_or("").to_lowercase())
                                == stem(direct.clone())
                        })
                        .collect::<Vec<_>>();
                    if candidates.len() == 1 {
                        Some(candidates[0])
                    } else {
                        None
                    }
                });
            if let Some(e) = candidate {
                targets.insert(raw.to_owned(), s(e, "entry_id"));
            }
        }
        targets
    }
    pub fn graph(&self, until: Option<&str>, tags: bool) -> Value {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut unresolved = 0;
        let paths = self
            .entries
            .iter()
            .map(|e| {
                s(e, "path")
                    .split('/')
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut common = 0;
        while !paths.is_empty()
            && paths
                .iter()
                .all(|p| p.len() > common + 1 && p[common] == paths[0][common])
        {
            common += 1;
        }
        for e in &self.entries {
            let date = e["authored_at"]
                .as_str()
                .unwrap_or(e["created_at"].as_str().unwrap_or(""));
            if until.is_some_and(|u| date > u) {
                continue;
            }
            let id = s(e, "entry_id");
            let path = s(e, "path");
            let parts = path.split('/').collect::<Vec<_>>();
            let group = if parts.len() > common + 1 {
                parts[common]
            } else {
                ""
            };
            let p = &self.parsed[&id];
            let all_tags = p["tags"]
                .as_array()
                .unwrap()
                .iter()
                .chain(e["tags"].as_array().unwrap())
                .cloned()
                .collect::<Vec<_>>();
            nodes.push(json!({"id":id,"node_type":"entry","label":e["title"],"path":path,"group":group,"kind":e["kind"],"tags":all_tags,"degree":0,"words":p["words"],"created_at":e["created_at"],"updated_at":e["updated_at"],"authored_at":e["authored_at"]}));
        }
        let ids = nodes.iter().map(|n| s(n, "id")).collect::<BTreeSet<_>>();
        let mut tag_nodes = BTreeSet::new();
        for n in &nodes {
            let id = s(n, "id");
            let targets = self.targets(&id, None);
            let p = &self.parsed[&id];
            unresolved += p["links"].as_array().unwrap().len()
                + p["embeds"].as_array().unwrap().len()
                - targets.len();
            for (raw, to) in targets {
                if ids.contains(&to) {
                    let kind = if p["embeds"].as_array().unwrap().contains(&json!(raw)) {
                        "embed"
                    } else {
                        "link"
                    };
                    edges.push(json!({"source":id,"target":to,"kind":kind}));
                }
            }
            if tags {
                for tag in n["tags"].as_array().unwrap() {
                    let name = format!("tag:{}", tag.as_str().unwrap());
                    tag_nodes.insert(name.clone());
                    edges.push(json!({"source":id,"target":name,"kind":"tag"}));
                }
            }
        }
        for name in tag_nodes {
            nodes.push(json!({"id":name,"node_type":"tag","label":name.trim_start_matches("tag:"),"path":"","group":"#","kind":"note","tags":[],"degree":0,"words":0,"created_at":"1970-01-01T00:00:00Z","updated_at":"1970-01-01T00:00:00Z","authored_at":null}));
        }
        for n in &mut nodes {
            n["degree"] = json!(
                edges
                    .iter()
                    .filter(|e| e["source"] == n["id"] || e["target"] == n["id"])
                    .count()
            );
        }
        json!({"nodes":nodes,"edges":edges,"unresolved":unresolved})
    }
    pub fn entry(&self, v: &Vault, id: &str) -> Result<Value> {
        let entry = v.entry(id)?;
        let graph = self.graph(None, false);
        let edges = graph["edges"].as_array().unwrap();
        Ok(
            json!({"meta":entry_meta(entry),"parsed":self.parsed.get(id),"outlinks":edges.iter().filter(|e|e["source"]==id).map(|e|e["target"].clone()).collect::<Vec<_>>(),"backlinks":edges.iter().filter(|e|e["target"]==id).map(|e|e["source"].clone()).collect::<Vec<_>>(),"link_targets":self.targets(id,None)}),
        )
    }
    pub fn search(&self, q: &str, limit: usize) -> Vec<Value> {
        let pieces = Regex::new(r#"\"([^\"]+)\"|(\S+)"#).unwrap();
        let mut terms = Vec::new();
        let mut phrases = Vec::new();
        let mut last_prefix = None;
        for piece in pieces.captures_iter(q) {
            let quoted = piece.get(1);
            let words = search_words(quoted.or_else(|| piece.get(2)).unwrap().as_str());
            if let Some(phrase) = quoted {
                phrases.push(fold_search(phrase.as_str()));
            }
            last_prefix = if quoted.is_none() {
                words.last().cloned()
            } else {
                None
            };
            terms.extend(words);
        }
        let terms: Vec<String> = terms
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if terms.is_empty() {
            return vec![];
        }
        let mut documents = Vec::new();
        for e in &self.entries {
            let id = s(e, "entry_id");
            let text = &self.texts[&id];
            let words = search_words(&format!(
                "{} {} {}",
                s(e, "title"),
                s(e, "path"),
                text.as_str()
            ));
            let mut counts = BTreeMap::new();
            for word in &words {
                *counts.entry(word.clone()).or_insert(0usize) += 1;
            }
            let phrase_ok = phrases.iter().all(|phrase| {
                [s(e, "title"), s(e, "path"), text.to_string()]
                    .iter()
                    .any(|field| phrase_match(field, phrase))
            });
            documents.push((e, id, text, counts, words.len().max(1), phrase_ok));
        }
        let n = documents.len() as f64;
        let avg = documents.iter().map(|d| d.4).sum::<usize>() as f64 / n.max(1.0);
        let matches_term = |counts: &BTreeMap<String, usize>, term: &str| -> usize {
            if last_prefix.as_deref() == Some(term) {
                counts
                    .iter()
                    .filter(|(word, _)| word.starts_with(term))
                    .map(|(_, n)| n)
                    .sum()
            } else {
                *counts.get(term).unwrap_or(&0)
            }
        };
        let df: Vec<usize> = terms
            .iter()
            .map(|t| {
                documents
                    .iter()
                    .filter(|d| matches_term(&d.3, t) > 0)
                    .count()
            })
            .collect();
        let all = documents
            .iter()
            .any(|d| d.5 && terms.iter().all(|t| matches_term(&d.3, t) > 0));
        let mut hits = Vec::new();
        for (e, id, text, counts, length, phrase_ok) in documents {
            let matches = terms
                .iter()
                .filter(|t| matches_term(&counts, t) > 0)
                .count();
            if !phrase_ok || matches == 0 || (all && matches != terms.len()) {
                continue;
            }
            let score: f64 = terms
                .iter()
                .zip(&df)
                .map(|(term, df)| {
                    let tf = matches_term(&counts, term) as f64;
                    let idf = (1.0 + (n - *df as f64 + 0.5) / (*df as f64 + 0.5)).ln();
                    idf * tf * 2.2 / (tf + 1.2 * (0.25 + 0.75 * length as f64 / avg))
                })
                .sum();
            hits.push((score,id.clone(),json!({"entry_id":id,"title":e["title"],"path":e["path"],"snippet":search_snippet(text,&terms),"score":score,"updated_at":e["updated_at"]})));
        }
        hits.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        hits.into_iter().take(limit).map(|h| h.2).collect()
    }
    pub fn activity(&self, v: &Vault, basis: &str) -> Value {
        use chrono::{Datelike, Timelike};
        let mut days: BTreeMap<String, Value> = BTreeMap::new();
        let mut hours = vec![vec![0u64; 24]; 7];
        for e in &self.entries {
            if let Ok(versions) = v.versions(&s(e, "entry_id")) {
                for version in versions {
                    let date = if basis == "claimed" {
                        version["source_mtime"]
                            .as_str()
                            .or(version["timestamp"].as_str())
                    } else {
                        version["timestamp"].as_str()
                    };
                    if let Some(t) = date.and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok())
                    {
                        let key = t.format("%Y-%m-%d").to_string();
                        let day = days
                            .entry(key.clone())
                            .or_insert(json!({"day":key,"created":0,"updated":0,"words":0}));
                        let field = if version["version"] == 1 {
                            "created"
                        } else {
                            "updated"
                        };
                        day[field] = json!(day[field].as_u64().unwrap() + 1);
                        hours[t.weekday().num_days_from_monday() as usize][t.hour() as usize] += 1;
                    }
                }
            }
        }
        json!({"basis":basis,"days":days.into_values().collect::<Vec<_>>(),"hour_weekday":hours,"groups_by_month":{},"tags_by_month":{}})
    }
}

#[cfg(test)]
mod search_tests {
    use super::*;
    fn workspace() -> Workspace {
        let entries = vec![
            json!({"entry_id":"a","title":"Long","path":"a.md"}),
            json!({"entry_id":"b","title":"Court","path":"b.md"}),
            json!({"entry_id":"c","title":"Autre","path":"c.md"}),
        ];
        let texts = [
            ("a", format!("{} café", "mot ".repeat(100))),
            ("b", "Café et vélo".to_owned()),
            ("c", "vélo".to_owned()),
        ]
        .into_iter()
        .map(|(id, text)| (id.to_string(), Zeroizing::new(text)))
        .collect();
        Workspace {
            entries,
            texts,
            parsed: BTreeMap::new(),
        }
    }
    #[test]
    fn search_folds_accents_ranks_and_selects_relevant_snippet() {
        let w = workspace();
        let hits = w.search("CAFE", 10);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0]["entry_id"], "b");
        assert!(hits[1]["snippet"].as_str().unwrap().contains("café"));
        assert_eq!(w.search("cafe velo", 10)[0]["entry_id"], "b");
        assert_eq!(w.search("cafe inconnu", 10).len(), 2);
        assert!(w.search("!!!", 10).is_empty());
        assert!(w.search("cafe", 0).is_empty());
    }
    #[test]
    fn search_supports_final_prefix_and_quoted_phrases() {
        let w = workspace();
        assert_eq!(w.search("caf", 10).len(), 2);
        assert_eq!(w.search("\"cafe et velo\"", 10)[0]["entry_id"], "b");
        assert!(w.search("\"cafe velo\"", 10).is_empty());
        assert!(w.search("\"caf\"", 10).is_empty());
        assert_eq!(w.search("cafe vel", 10)[0]["entry_id"], "b");
    }
}

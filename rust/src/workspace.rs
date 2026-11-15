//! Decrypted projections are rebuilt for the unlocked session and dropped on lock.
use crate::vault::{Vault, entry_meta, s};
use anyhow::Result;
use regex::Regex;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

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
        let terms = q
            .to_lowercase()
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if terms.is_empty() {
            return vec![];
        }
        let mut hits = Vec::new();
        for e in &self.entries {
            let id = s(e, "entry_id");
            let text = &self.texts[&id];
            let lower =
                format!("{} {} {}", s(e, "title"), s(e, "path"), text.as_str()).to_lowercase();
            if terms.iter().all(|t| lower.contains(t)) {
                let score = terms
                    .iter()
                    .map(|t| lower.matches(t).count().min(50))
                    .sum::<usize>();
                hits.push(json!({"entry_id":id,"title":e["title"],"path":e["path"],"snippet":text.chars().take(180).collect::<String>(),"score":score,"updated_at":e["updated_at"]}));
            }
        }
        hits.sort_by_key(|h| std::cmp::Reverse(h["score"].as_u64().unwrap()));
        hits.truncate(limit);
        hits
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

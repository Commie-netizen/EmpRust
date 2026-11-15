//! UTF-8 bounded context; bytes are not a model-specific token count.
use std::collections::HashSet;
pub const BUDGET: usize = 12_000;
pub fn compact(document: &str) -> (String, bool) {
    let mut seen = HashSet::new();
    let text = document
        .split("\n\n")
        .map(str::trim)
        .filter(|p| !p.is_empty() && seen.insert(*p))
        .collect::<Vec<_>>()
        .join("\n\n");
    if text.len() <= BUDGET {
        return (text, false);
    }
    let marker = "\n[... passage omis ...]\n";
    let size = (BUDGET - 2 * marker.len()) / 3;
    let cut = |start: usize| {
        let mut a = start;
        let mut b = (start + size).min(text.len());
        while !text.is_char_boundary(a) {
            a += 1
        }
        while !text.is_char_boundary(b) {
            b -= 1
        }
        text[a..b].to_owned()
    };
    (
        [cut(0), cut((text.len() - size) / 2), cut(text.len() - size)].join(marker),
        true,
    )
}
#[cfg(test)]
mod tests {
    #[test]
    fn unicode_budget() {
        let (s, partial) = super::compact(&"é中🌍".repeat(20000));
        assert!(partial);
        assert!(s.len() <= super::BUDGET);
        assert!(!s.contains('\u{fffd}'));
    }
}

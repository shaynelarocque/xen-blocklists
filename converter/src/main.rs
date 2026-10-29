//! Converts filter lists' network rules to WebKit content-blocker rules with
//! Brave's adblock-rust, the converter Brave's own iOS browser uses.
//!
//!     xen-convert [--hosts] <list.txt> [[--standard|--hosts] <list.txt>]...
//!
//! All the lists given are read as one set, so a `$badfilter` in one switches
//! off its rule in another. Prints `{"rules": [...], "filtersUsed": n}`, the
//! blocks first and the exceptions after them. Hiding rules are left to
//! `build.py`, which also honours their exceptions.

use adblock::content_blocking::{CbRule, CbRuleEquivalent, CbType};
use adblock::lists::{parse_filters, FilterFormat, ParseOptions, RuleTypes};
use std::collections::HashSet;
use std::{env, fs, process};

/// Adblock Plus's `^`: one character that is not a letter, a digit or one
/// of `_-.%`, or the end of the address.
const SEPARATOR: &str = "[^-_.%a-z0-9]";

/// Puts back what adblock-rust's regexes lose of `^`. It escapes a `^`
/// inside a filter to a literal caret no address has, so the rule never
/// matches (`||googleapis.com^*/gen_204?`), and it drops a final one, so
/// `||ads.com^` also took `ads.community.org`.
fn with_separators(url_filter: &str, raw: &str, hosts_line: bool) -> String {
    let mut fixed = url_filter.replace("\\^", SEPARATOR);
    let pattern = raw.strip_prefix("@@").unwrap_or(raw);
    let pattern = pattern.rfind('$').map_or(pattern, |options| &pattern[..options]);
    if (hosts_line || pattern.ends_with('^')) && !fixed.ends_with('$') && !fixed.ends_with(".*") {
        fixed.push_str(&format!("({SEPARATOR}.*)?$"));
    }
    fixed
}

fn main() {
    let mut texts = vec![];
    let mut format = FilterFormat::Standard;
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--hosts" => format = FilterFormat::Hosts,
            "--standard" => format = FilterFormat::Standard,
            path => {
                let text = fs::read_to_string(path).unwrap_or_else(|error| {
                    eprintln!("xen-convert: {path}: {error}");
                    process::exit(1);
                });
                texts.push((text, format));
            }
        }
    }
    if texts.is_empty() {
        eprintln!("usage: xen-convert [--hosts] <list.txt>...");
        process::exit(2);
    }

    let mut filters = vec![];
    for (text, format) in &texts {
        let options = ParseOptions { format: *format, rule_types: RuleTypes::NetworkOnly, ..Default::default() };
        let (network, _) = parse_filters(text.lines(), true, options);
        filters.extend(network.into_iter().map(|filter| (filter, matches!(format, FilterFormat::Hosts))));
    }
    let badfiltered: HashSet<_> = filters.iter().filter(|(f, _)| f.is_badfilter()).map(|(f, _)| f.get_id()).collect();

    let (mut blocks, mut exceptions): (Vec<CbRule>, Vec<CbRule>) = (vec![], vec![]);
    let mut used = 0;
    for (filter, hosts_line) in filters {
        if filter.is_badfilter() || badfiltered.contains(&filter.get_id()) {
            continue;
        }
        let raw = filter.raw_line.as_deref().unwrap_or_default().to_string();
        let Ok(equivalent) = CbRuleEquivalent::try_from(filter) else { continue };
        used += 1;
        for mut rule in equivalent {
            rule.trigger.url_filter = with_separators(&rule.trigger.url_filter, &raw, hosts_line);
            match rule.action.typ {
                CbType::IgnorePreviousRules => exceptions.push(rule),
                _ => blocks.push(rule),
            }
        }
    }
    // adblock-rust's own conversion ends with an exception for every
    // first-party page, so a listed host's own pages still load. Xen's lists
    // have always blocked those pages, malware hosts above all, and still do.
    blocks.extend(exceptions);

    let out = serde_json::json!({ "rules": blocks, "filtersUsed": used });
    println!("{out}");
}

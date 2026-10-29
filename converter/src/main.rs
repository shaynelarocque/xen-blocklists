//! Converts filter lists' network rules to WebKit content-blocker rules with
//! Brave's adblock-rust, the converter Brave's own iOS browser uses.
//!
//!     xen-convert [--hosts] <list.txt> [[--standard|--hosts] <list.txt>]...
//!
//! All the lists given are read as one set, so a `$badfilter` in one switches
//! off its rule in another. Prints `{"rules": [...], "filtersUsed": n}`.
//! Hiding rules are left to `build.py`, which also honours their exceptions.

use adblock::content_blocking::{ignore_previous_fp_documents, CbRule};
use adblock::lists::{FilterFormat, FilterSet, ParseOptions, RuleTypes};
use std::{env, fs, process};

fn main() {
    let mut set = FilterSet::new(true);
    let mut format = FilterFormat::Standard;
    let mut lists = 0;
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--hosts" => format = FilterFormat::Hosts,
            "--standard" => format = FilterFormat::Standard,
            path => {
                let text = fs::read_to_string(path).unwrap_or_else(|error| {
                    eprintln!("xen-convert: {path}: {error}");
                    process::exit(1);
                });
                set.add_filter_list(
                    text,
                    ParseOptions {
                        format,
                        rule_types: RuleTypes::NetworkOnly,
                        ..Default::default()
                    },
                );
                lists += 1;
            }
        }
    }
    if lists == 0 {
        eprintln!("usage: xen-convert [--hosts] <list.txt>...");
        process::exit(2);
    }

    let (rules, used) = set.into_content_blocking().expect("a debug FilterSet converts");
    // adblock-rust ends the set with an exception for every first-party page,
    // so a listed host's own pages still load. Xen's lists have always
    // blocked those pages, malware hosts above all, and keep doing so.
    let catch_all = ignore_previous_fp_documents();
    let rules: Vec<CbRule> = rules.into_iter().filter(|rule| *rule != catch_all).collect();

    let out = serde_json::json!({ "rules": rules, "filtersUsed": used.len() });
    println!("{out}");
}

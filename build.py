#!/usr/bin/env python3
"""Builds Xen Browser's content-blocker lists from their authors' filter lists.

    python3 build.py [--previous MANIFEST_URL] [--allow-big-change]

Reads sources.json and, for each of Xen's lists:

1. Fetches its filter lists, following `!#include` and `!#if` as uBlock Origin
   does, for Safari on a phone. A source can drop sections it shares with
   another list (Fanboy's Annoyance List carries the cookie list inside it).
2. Converts the network filters with Brave's adblock-rust (converter/), which
   leaves out what WebKit cannot do: scriptlets, redirects, $csp, $removeparam.
3. Converts the hiding filters here, honouring their exceptions: `site#@#.ad`
   lifts `##.ad` on that site and `#@#.ad` lifts it everywhere. WebKit has no
   exception for a hiding rule of its own, so an exception narrows the rule's
   domains instead. uBlock's `:remove()`, and a `:style()` or AdGuard
   `{ ... }` that only puts an element out of sight, hide; every selector is put to WebKit
   itself (tools/selector-check.swift), and one it cannot parse is left out.
   WebKit drops a whole rule for one bad selector, so this matters.
4. Drops a rule a list earlier in the same switch already has, and splits the
   list into chunks of at most 50,000 rules. Every chunk of EasyList,
   EasyPrivacy and uBlock filters ends with the network exceptions of all
   three: WebKit applies an exception only to earlier rules in its own
   compiled list, and an ad blocker applies it to every list's.

Then it checks the result: every hiding rule parses, nothing hides the whole
page or blocks every request, every chunk compiles in WebKit
(tools/compile-check.swift), and no list grew or shrank by more than a third
since the last build (--previous) unless --allow-big-change says so.

Writes site/lists/<sha256>.json and site/manifest.json. tools/sign.swift signs
the manifest; Xen only takes lists named in a manifest signed with its key.
"""
import argparse, hashlib, json, math, re, shutil, subprocess, sys, tempfile, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

ROOT = Path(__file__).resolve().parent
WORK = ROOT / "work"
SITE = ROOT / "site"
CONVERTER = ROOT / "converter" / "target" / "release" / "xen-convert"
USER_AGENT = "xen-blocklists (+https://github.com/shaynelarocque/xen-blocklists)"

FORMAT = 1
CHUNK_LIMIT = 50_000
# WebKit drops a rule whole for one selector it cannot parse. Every selector
# here parsed on the build machine; an older iOS could still refuse one, and
# then it takes the rest of its rule with it, so rules stay small.
SELECTORS_PER_RULE = 250
BIG_CHANGE = 1 / 3

# uBlock's `!#if` tokens, as Xen is: Safari's engine, on a phone. Any token
# not here (env_chromium, env_firefox, cap_html_filtering...) is false.
TOKENS = {"env_safari": True, "env_mobile": True, "ext_ublock": True, "cap_user_stylesheet": True}

COSMETIC = re.compile(r'^(?P<domains>[^\s/|@"!$]*?)(?P<sep>#@?(?:\?|\$\??|%)?#)(?P<body>.*)$')
HTML_FILTER = re.compile(r'^[^\s/|@"!]*?\$@?\$')
ADGUARD_STYLE = re.compile(r"^(?P<selector>.+?)\s*\{(?P<style>[^{}]*)\}$")
UBLOCK_STYLE = re.compile(r":style\((?P<style>.*)\)$")
DOMAIN = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*")
NEVER_ALONE = {"html", "body", "head", ":root", "*"}
CATCH_ALL_FILTERS = {"", ".*", "^https?://", "^http://", "^https://", "^wss?://", "^[^:]+:"}


def log(message):
    print(message, flush=True)


def fail(message):
    print(f"build.py: {message}", file=sys.stderr)
    sys.exit(1)


# MARK: - Fetching

def fetch(url):
    """A filter list's text. curl, for its retries and the system's certificates."""
    result = subprocess.run(
        ["curl", "-fsSL", "--retry", "4", "--retry-delay", "5", "--max-time", "120", "-A", USER_AGENT, url],
        capture_output=True,
    )
    if result.returncode != 0:
        fail(f"could not fetch {url}: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout.decode("utf-8", errors="replace")


def holds(expression):
    """Whether a `!#if` expression holds: tokens, `!`, `&&`, `||` and brackets."""
    python = []
    for token in re.findall(r"!|&&|\|\||\(|\)|[A-Za-z0-9_]+", expression):
        python.append({"!": "not", "&&": "and", "||": "or", "(": "(", ")": ")"}.get(token) or str(TOKENS.get(token, False)))
    try:
        return bool(eval(" ".join(python) or "False", {"__builtins__": {}}))
    except SyntaxError:
        return False


def flatten(url, text, drop_sections=()):
    """A list's filters, its includes in place and its `!#if` blocks decided."""
    lines, active, dropping = [], [], False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("!#if "):
            active.append(holds(line[5:]))
            continue
        if line == "!#else":
            if active:
                active[-1] = not active[-1]
            continue
        if line == "!#endif":
            if active:
                active.pop()
            continue
        if not all(active):
            continue
        if line.startswith("!#include "):
            target = urljoin(url, line[len("!#include "):].strip())
            # As uBlock does: only a file beside the list itself.
            here, there = urlsplit(url), urlsplit(target)
            if (here.scheme, here.netloc) == (there.scheme, there.netloc) and there.path.rsplit("/", 1)[0] == here.path.rsplit("/", 1)[0]:
                lines += flatten(target, fetch(target))
            continue
        if drop_sections and line.startswith("! *** easylist:"):
            section = line[len("! *** easylist:"):].split(" ", 1)[0]
            dropping = any(section.startswith(prefix) for prefix in drop_sections)
            continue
        if dropping or not line or line.startswith("!") or line.startswith("["):
            continue
        lines.append(line)
    return lines


def header(text, field):
    match = re.search(rf"^! {field}:\s*(.+)$", text, re.MULTILINE)
    return match.group(1).strip() if match else None


# MARK: - Hiding filters

def domains_of(text):
    """A hiding filter's sites: (included, excluded, any it could not read)."""
    included, excluded, unreadable = [], [], False
    for entry in filter(None, (part.strip() for part in text.split(","))):
        negated = entry.startswith("~")
        name = entry.lstrip("~").lower()
        if not name.isascii():
            try:
                name = name.encode("idna").decode("ascii")
            except UnicodeError:
                unreadable = True
                continue
        # Entities (`google.*`) and uBlock's regex hosts have no WebKit form.
        if not DOMAIN.fullmatch(name):
            unreadable = True
            continue
        (excluded if negated else included).append(name)
    return included, excluded, unreadable


def style_hides(style):
    """Whether a style only takes its element out of sight: display: none,
    visibility: hidden, or a place thousands of pixels off the page. uBlock
    hides some ads those other ways, where a page looks for display: none."""
    properties = {}
    for declaration in style.split(";"):
        if ":" in declaration:
            name, value = declaration.split(":", 1)
            properties[name.strip().lower()] = re.sub(r"\s*!\s*important\s*$", "", value.strip().lower())
    if not properties:
        return False
    if set(properties) == {"display"}:
        return properties["display"] == "none"
    if set(properties) == {"visibility"}:
        return properties["visibility"] == "hidden"
    offscreen = any(re.fullmatch(r"-\d{3,}px", properties.get(side, "")) for side in ("top", "left"))
    return set(properties) <= {"position", "top", "left"} and properties.get("position") in ("absolute", "fixed") and offscreen


def plain_selector(separator, body):
    """(selector, own) for a filter that only hides, or (None, False).

    `own` marks a filter that hides by a style or by removing (uBlock's
    `:style()` and `:remove()`, AdGuard's `{ ... }`). uBlock treats those as
    filters of their own, which an exception to the plain selector does not
    reach: `bing.com#@#.b_ad` lifts EasyList's `bing.com##.b_ad` so that
    uBlock's `bing.com##.b_ad:style(position: absolute; top: -9999px)` can
    hide the ad instead. Here both are plain hiding, and the second stays.
    """
    own = False
    if separator == "#$#":
        style = ADGUARD_STYLE.match(body)
        if not style or not style_hides(style["style"]):
            return None, False  # other styles, or Adblock Plus's snippets
        body, own = style["selector"], True
    elif separator not in ("##", "#@#", "#?#", "#@?#"):
        return None, False  # scriptlets, JavaScript, exceptions to styles
    body = body.strip()
    if body.startswith("+js(") or body.startswith("^"):
        return None, False  # scriptlets, uBlock's HTML filters
    if body.endswith(":remove()"):
        body, own = body[: -len(":remove()")], True
    else:
        style = UBLOCK_STYLE.search(body)
        if style:
            if not style_hides(style["style"]):
                return None, False
            body, own = body[: style.start()], True
    if ":style(" in body or ":remove-attr(" in body or ":remove-class(" in body or ":matches-path(" in body:
        return None, False
    body = body.replace(":-abp-has(", ":has(").strip()
    return (body, own) if body else (None, False)


def is_under(name, parent):
    return name == parent or name.endswith("." + parent)


class Hiding:
    """One list's hiding filters, before exceptions."""

    def __init__(self):
        self.generic = []   # (selector, excluded sites, own)
        self.specific = []  # (selector, sites, own)
        self.dropped = {"mixed sites": 0, "entities only": 0}


def read_cosmetic(lines, hiding, exceptions):
    """Sorts a list's cosmetic filters into its hiding and everyone's exceptions."""
    for line in lines:
        match = COSMETIC.match(line)
        if not match:
            continue
        selector, own = plain_selector(match["sep"], match["body"])
        if selector is None:
            continue
        included, excluded, unreadable = domains_of(match["domains"])
        if "@" in match["sep"]:
            if not included and not excluded and not unreadable:
                exceptions.everywhere.add(selector)
            for name in included:
                exceptions.on.setdefault(selector, set()).add(name)
            continue
        if unreadable and not included and not excluded:
            hiding.dropped["entities only"] += 1
            continue
        if included:
            if any(is_under(x, i) for x in excluded for i in included):
                # `a.com,~b.a.com##x`: WebKit cannot leave a hole in a site.
                hiding.dropped["mixed sites"] += 1
                continue
            hiding.specific.append((selector, included, own))
        else:
            hiding.generic.append((selector, set(excluded), own))


class Exceptions:
    def __init__(self):
        self.everywhere = set()
        self.on = {}  # selector -> sites
        self.no_generic = set()   # sites where generic hiding is off
        self.no_specific = set()  # sites where their own hiding is off


PAGE_EXCEPTION = re.compile(r"^@@\|\|(?P<site>[a-z0-9.-]+)[\^/]?\$(?P<options>[^$]+)$")


def read_page_exceptions(lines, exceptions):
    """`@@||site^$generichide` and its kin: hiding switched off on a whole site.

    adblock-rust has no WebKit form for these, but a site can be left out of
    the hiding rules it switches off, which is what they mean.
    """
    for line in lines:
        match = PAGE_EXCEPTION.match(line.lower())
        if not match:
            continue
        options = set(match["options"].split(","))
        if any(option.startswith("domain=") or option.startswith("from=") for option in options):
            continue
        site = match["site"].strip(".")
        if options & {"generichide", "ghide", "elemhide", "ehide", "document", "doc"}:
            exceptions.no_generic.add(site)
        if options & {"specifichide", "shide", "elemhide", "ehide", "document", "doc"}:
            exceptions.no_specific.add(site)


def is_line_cosmetic(line):
    return bool(COSMETIC.match(line) or HTML_FILTER.match(line))


# MARK: - WebKit

def build_tool(name):
    binary = WORK / "bin" / name
    source = ROOT / "tools" / f"{name}.swift"
    if not binary.exists() or binary.stat().st_mtime < source.stat().st_mtime:
        binary.parent.mkdir(parents=True, exist_ok=True)
        log(f"Building {name}…")
        subprocess.run(["swiftc", "-O", str(source), "-o", str(binary)], check=True)
    return binary


def parses(selectors):
    """Which selectors WebKit's content-rule selector parser takes."""
    if not selectors:
        return {}
    with tempfile.TemporaryDirectory() as temp:
        asked, answers = Path(temp) / "selectors.json", Path(temp) / "answers.json"
        asked.write_text(json.dumps(selectors))
        subprocess.run([str(build_tool("selector-check")), str(asked), str(answers)], check=True)
        return dict(zip(selectors, json.loads(answers.read_text())))


def split_selector_list(selectors):
    """A selector list's top-level parts, for the whole-page check."""
    parts, current, depth, quote = [], [], 0, None
    for i, ch in enumerate(selectors):
        if quote:
            current.append(ch)
            if ch == quote and selectors[i - 1] != "\\":
                quote = None
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    parts.append("".join(current).strip())
    return parts


# MARK: - Rules

def canonical(rule):
    """A rule in one fixed form, so the same lists always hash the same."""
    trigger = dict(rule["trigger"])
    for key in ("if-domain", "unless-domain", "resource-type", "load-type", "if-top-url", "unless-top-url"):
        if key in trigger:
            trigger[key] = sorted(trigger[key])
    action = {"type": rule["action"]["type"]}
    if "selector" in rule["action"]:
        action["selector"] = rule["action"]["selector"]
    return {"trigger": trigger, "action": action}


def key_of(rule):
    return json.dumps(rule, sort_keys=True, separators=(",", ":"))


def hiding_rules(groups, keyword):
    rules = []
    for sites, selectors in groups.items():
        for start in range(0, len(selectors), SELECTORS_PER_RULE):
            trigger = {"url-filter": ".*"}
            if sites:
                trigger[keyword] = ["*" + name for name in sites]
            rules.append({"trigger": trigger, "action": {"type": "css-display-none", "selector": ", ".join(selectors[start:start + SELECTORS_PER_RULE])}})
    return rules


def convert_network(name, texts):
    paths = []
    folder = WORK / "lists" / name
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(parents=True)
    for index, lines in enumerate(texts):
        path = folder / f"{index}.txt"
        path.write_text("\n".join(line for line in lines if not is_line_cosmetic(line)) + "\n")
        paths.append(str(path))
    result = subprocess.run([str(CONVERTER), *paths], capture_output=True, check=True)
    converted = json.loads(result.stdout)
    rules = [canonical(rule) for rule in converted["rules"]]
    blocks = [rule for rule in rules if rule["action"]["type"] != "ignore-previous-rules"]
    exceptions = [rule for rule in rules if rule["action"]["type"] == "ignore-previous-rules"]
    return blocks, exceptions


def unique(rules):
    seen, kept = set(), []
    for rule in rules:
        key = key_of(rule)
        if key not in seen:
            seen.add(key)
            kept.append(rule)
    return kept


def chunks_of(body, pool):
    capacity = CHUNK_LIMIT - len(pool)
    if capacity < CHUNK_LIMIT // 5:
        fail(f"{len(pool)} exceptions leave too little room in a chunk")
    count = max(1, math.ceil(len(body) / capacity))
    size = math.ceil(len(body) / count)
    return [body[i * size:(i + 1) * size] + pool for i in range(count)]


# MARK: - Checks

def check_rules(name, rules):
    for rule in rules:
        trigger, action = rule["trigger"], rule["action"]["type"]
        if action == "block" and trigger.get("url-filter") in CATCH_ALL_FILTERS and not trigger.get("if-domain") and not trigger.get("if-top-url"):
            fail(f"{name}: a rule blocks every request: {key_of(rule)}")
        if action == "css-display-none":
            for part in split_selector_list(rule["action"]["selector"]):
                if part.lower() in NEVER_ALONE:
                    fail(f"{name}: a rule hides the whole page: {part}")


def compile_check(paths):
    result = subprocess.run([str(build_tool("compile-check")), *map(str, paths)], capture_output=True, text=True)
    sys.stdout.write(result.stdout)
    if result.returncode != 0:
        fail(f"WebKit could not compile every list:\n{result.stderr}")


def previous_manifest(url):
    if not url:
        return None
    result = subprocess.run(["curl", "-fsSL", "--retry", "3", "--max-time", "60", url], capture_output=True)
    if result.returncode != 0:
        log(f"No previous manifest at {url}; skipping the size check.")
        return None
    return json.loads(result.stdout)


def check_change(lists, previous, allowed):
    if not previous:
        return
    before = {}
    for entry in previous["lists"]:
        before[entry["list"]] = before.get(entry["list"], 0) + entry["rules"]
    problems = []
    for name, rules in lists.items():
        if name in before and before[name]:
            change = (rules - before[name]) / before[name]
            log(f"  {name}: {before[name]} → {rules} rules ({change:+.1%})")
            if abs(change) > BIG_CHANGE:
                problems.append(f"{name} went from {before[name]} to {rules} rules")
    if problems and not allowed:
        fail("lists changed more than expected; rerun with --allow-big-change if that's right:\n  " + "\n  ".join(problems))


# MARK: - Build

def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--previous", help="the published manifest, to compare list sizes with")
    parser.add_argument("--allow-big-change", action="store_true")
    parser.add_argument("--reissue", metavar="MANIFEST", help="give an earlier build's manifest a new serial, to publish it again")
    args = parser.parse_args()

    if args.reissue:
        # Xen takes only a manifest newer than its own, so putting an
        # earlier build back means numbering it anew.
        path = Path(args.reissue)
        manifest = json.loads(path.read_text())
        now = datetime.now(timezone.utc)
        manifest["serial"], manifest["generated"] = int(now.timestamp()), now.strftime("%Y-%m-%dT%H:%M:%SZ")
        path.write_text(json.dumps(manifest, indent=1, ensure_ascii=True) + "\n")
        log(f"Reissued {path} as serial {manifest['serial']}.")
        return

    if not CONVERTER.exists():
        fail("build the converter first: cargo build --release --manifest-path converter/Cargo.toml")
    config = json.loads((ROOT / "sources.json").read_text())
    started = time.time()

    # Fetch every source first: exceptions in one list reach every other.
    sources, texts, hiding, exceptions = [], {}, {}, Exceptions()
    for entry in config["lists"]:
        texts[entry["name"]] = []
        hiding[entry["name"]] = Hiding()
        for source in entry["sources"]:
            raw = fetch(source["url"])
            lines = flatten(source["url"], raw, tuple(source.get("dropSections", ())))
            texts[entry["name"]].append(lines)
            read_cosmetic(lines, hiding[entry["name"]], exceptions)
            read_page_exceptions(lines, exceptions)
            sources.append({
                "list": entry["name"],
                "url": source["url"],
                "title": header(raw, "Title"),
                "version": header(raw, "Version") or header(raw, "Last modified") or header(raw, "Updated"),
                "filters": len(lines),
                "sha256": hashlib.sha256("\n".join(lines).encode()).hexdigest(),
            })
            log(f"Fetched {source['url']} ({len(lines)} filters)")

    # Exceptions first, then ask WebKit about every selector still standing.
    lifted = narrow = 0
    for name, entry in hiding.items():
        generic = []
        for selector, excluded, own in entry.generic:
            if own:
                generic.append((selector, excluded | exceptions.no_generic))
                continue
            if selector in exceptions.everywhere:
                lifted += 1
                continue
            generic.append((selector, excluded | exceptions.on.get(selector, set()) | exceptions.no_generic))
        specific = []
        for selector, sites, own in entry.specific:
            if selector in exceptions.everywhere and not own:
                lifted += 1
                continue
            lifted_on = set() if own else exceptions.on.get(selector, set())
            kept = [site for site in sites
                    if not any(is_under(site, other) for other in lifted_on)
                    and not any(is_under(site, off) for off in exceptions.no_specific)]
            narrow += sum(1 for other in lifted_on for site in kept if is_under(other, site) and other != site)
            if kept:
                specific.append((selector, kept))
            else:
                lifted += 1
        entry.generic, entry.specific = generic, specific
    selectors = sorted({s for entry in hiding.values() for s, _ in entry.generic + entry.specific})
    log(f"Asking WebKit about {len(selectors)} selectors…")
    verdict = parses(selectors)
    usable = {s for s, ok in verdict.items() if ok and s.strip().lower() not in NEVER_ALONE}
    log(f"  Generic hiding off on {len(exceptions.no_generic)} sites, sites' own hiding off on {len(exceptions.no_specific)}.")
    log(f"  {len(usable)} parse; {len(selectors) - len(usable)} left out. {lifted} hiding filters lifted by exceptions; "
        f"{narrow} exceptions narrower than their rule's site could not apply.")

    # Network rules, then each list's rules in order, dropping what an
    # earlier list on the same switch already has.
    shared_pool = []
    network = {}
    for entry in config["lists"]:
        blocks, own = convert_network(entry["name"], texts[entry["name"]])
        network[entry["name"]] = (blocks, own)
        if entry.get("sharedExceptions"):
            shared_pool += own
    shared_pool = unique(shared_pool)

    seen = {}  # switch -> rule keys and (selector, site) pairs already in
    manifest_lists, totals, stats = [], {}, []
    out = SITE / "lists"
    shutil.rmtree(SITE, ignore_errors=True)
    out.mkdir(parents=True)
    written = []
    for entry in config["lists"]:
        name, group = entry["name"], entry["group"]
        state = seen.setdefault(group, {"rules": set(), "generic": set(), "pairs": set()})
        blocks, own = network[name]
        kept_blocks = []
        for rule in blocks:
            key = key_of(rule)
            if key not in state["rules"]:
                state["rules"].add(key)
                kept_blocks.append(rule)

        generic_groups, specific_groups = {}, {}
        for selector, excluded in hiding[name].generic:
            sites = tuple(sorted(excluded))
            if selector not in usable or (selector, sites) in state["generic"]:
                continue
            state["generic"].add((selector, sites))
            generic_groups.setdefault(sites, []).append(selector)
        for selector, sites in hiding[name].specific:
            if selector not in usable or (selector, ()) in state["generic"]:
                continue
            fresh = tuple(sorted(site for site in set(sites) if (selector, site) not in state["pairs"]))
            if not fresh:
                continue
            state["pairs"].update((selector, site) for site in fresh)
            specific_groups.setdefault(fresh, []).append(selector)
        hides = hiding_rules(generic_groups, "unless-domain") + hiding_rules(specific_groups, "if-domain")

        pool = shared_pool if entry.get("sharedExceptions") else unique(own)
        body = kept_blocks + [canonical(rule) for rule in hides]
        check_rules(name, body + pool)
        chunks = chunks_of(body, pool) if body else []
        for index, rules in enumerate(chunks, start=1):
            data = json.dumps(rules, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
            digest = hashlib.sha256(data).hexdigest()
            path = out / f"{digest}.json"
            path.write_bytes(data)
            written.append(path)
            manifest_lists.append({
                "name": f"{name}-{index}",
                "list": name,
                "group": group,
                "sha256": digest,
                "bytes": len(data),
                "rules": len(rules),
            })
        totals[name] = sum(len(rules) for rules in chunks)
        stats.append(f"  {name}: {len(kept_blocks)} blocks, {len(hides)} hiding rules, {len(pool)} exceptions, {len(chunks)} chunk(s), {totals[name]} rules")
    log("Lists:\n" + "\n".join(stats))

    # Every hiding rule whole, once more, as WebKit will read it.
    final = [rule["action"]["selector"] for path in written for rule in json.loads(path.read_text()) if rule["action"]["type"] == "css-display-none"]
    bad = [s for s, ok in parses(final).items() if not ok]
    if bad:
        fail(f"{len(bad)} hiding rules do not parse whole, e.g. {bad[0][:200]}")
    compile_check(written)
    check_change(totals, previous_manifest(args.previous), args.allow_big_change)

    now = datetime.now(timezone.utc)
    manifest = {
        "format": FORMAT,
        "serial": int(now.timestamp()),
        "generated": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lists": manifest_lists,
        "sources": sources,
    }
    (SITE / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=True) + "\n")
    shutil.copy(ROOT / "site.html", SITE / "index.html")
    log(f"Wrote {len(written)} lists, {sum(totals.values())} rules, in {time.time() - started:.0f} s.")


if __name__ == "__main__":
    main()

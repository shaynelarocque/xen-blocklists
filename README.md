# Xen Blocklists

The content-blocker lists [Xen Browser](https://shaynelarocque.com/xen) uses to block ads, trackers, cookie notices and annoyances. They're rebuilt every Monday from their authors' filter lists and published to [shaynelarocque.github.io/xen-blocklists](https://shaynelarocque.github.io/xen-blocklists/). Xen checks for new lists once a day and compiles them overnight while the phone charges, so they stay current without an app update.

## What's published

- `manifest.json` lists every chunk: its name, the switch it belongs to in Xen (`adsAndTrackers` or `cookieNotices`), its SHA-256, size and rule count. It also records each source list's version.
- `manifest.sig` is an Ed25519 signature of `manifest.json`, base64. Xen ignores any manifest it can't verify with the public key it ships with, so only this repo's workflow can change the lists Xen uses.
- `lists/<sha256>.json` is each chunk in WebKit's content-blocker format. A chunk is named by its hash, so Xen downloads and recompiles only the chunks that changed.

## How a build works

[`build.py`](build.py) reads [`sources.json`](sources.json) and, for each of Xen's lists:

1. **Fetches** its filter lists. It follows `!#include` and `!#if` the way uBlock Origin does for Safari on a phone.
2. **Converts the network filters** with Brave's [adblock-rust](https://github.com/brave/adblock-rust) ([`converter/`](converter)). It leaves out what WebKit can't do: scriptlets, redirects, `$csp`, `$removeparam`.
3. **Converts the hiding filters itself**, with their exceptions. `site#@#.ad` lifts `##.ad` on that site, and `@@||site^$generichide` switches generic hiding off there. WebKit has no exception for a hiding rule, so an exception narrows the rule's domains instead.
4. **Checks every selector with WebKit** ([`tools/selector-check.swift`](tools/selector-check.swift)) and leaves out the ones it can't parse. WebKit drops a whole rule for one bad selector.
5. **Removes duplicates and splits the list into chunks** of at most 50,000 rules. A rule a list earlier on the same switch already has is dropped. Every chunk of EasyList, EasyPrivacy and uBlock filters ends with all three lists' network exceptions, because WebKit only applies an exception to earlier rules in the same list.

Then it refuses to publish if:

- a hiding rule doesn't parse whole;
- a rule would hide the whole page or block every request;
- WebKit can't compile a chunk ([`tools/compile-check.swift`](tools/compile-check.swift));
- a list grew or shrank by more than a third since the last build.

If a build is refused, the lists already published stay in place.

## Running it

```bash
cargo build --release --manifest-path converter/Cargo.toml
python3 build.py
```

The output goes to `site/`. Building needs a Mac, because WebKit itself checks the result.

## Workflows

- **Build lists** runs every Monday, and on demand. It builds, signs and publishes the lists, and keeps each build as a release (the last 26). If a list really did change by more than a third, run it by hand with *allow big change*.
- **Roll back** republishes an earlier release under a new serial. Xen only takes a manifest newer than the one it has, so this is how to put old lists back.

Both need the `XEN_LISTS_SIGNING_KEY` secret: the base64 Ed25519 private key whose public key is built into Xen. `swiftc tools/sign.swift -o sign && ./sign --new-key` makes a new pair. Changing the key needs a Xen update.

## Credits

The lists are their authors' work, under their licences:

- [EasyList](https://easylist.to): EasyList, EasyPrivacy, the EasyList Cookie List and Fanboy's lists, under GPLv3 or CC BY-SA 3.0
- [uBlock Origin's filters](https://github.com/uBlockOrigin/uAssets), under GPLv3
- [AdGuard's filters](https://github.com/AdguardTeam/AdguardFilters), under GPLv3
- [Peter Lowe's list](https://pgl.yoyo.org/adservers/), under the terms on its site

The converted lists published here are derived from them under the same terms.

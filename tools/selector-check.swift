// Which CSS selectors WebKit can parse, asked of WebKit itself.
//
//   selector-check <selectors.json> <answers.json>
//
// Reads a JSON array of selector lists and writes a JSON array of booleans,
// one each. A selector list is good when `querySelectorAll` takes it in a
// quirks-mode document, which is how WebKit parses a content rule's
// css-display-none selector (`isValidCSSSelector`): a list it cannot parse
// drops the whole rule. Built and run by clean-hiding-rules.py.

import AppKit
import WebKit

let arguments = CommandLine.arguments
guard arguments.count == 3 else {
    FileHandle.standardError.write(Data("usage: selector-check <selectors.json> <answers.json>\n".utf8))
    exit(64)
}
let selectors = try! JSONDecoder().decode([String].self, from: Data(contentsOf: URL(fileURLWithPath: arguments[1])))

final class Loaded: NSObject, WKNavigationDelegate {
    var done: CheckedContinuation<Void, Never>?
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { done?.resume(); done = nil }
}

@MainActor
func check() async throws -> [Bool] {
    _ = NSApplication.shared
    let web = WKWebView(frame: .zero)
    let loaded = Loaded()
    web.navigationDelegate = loaded
    // No doctype: quirks mode, as WebKit parses a rule's selector.
    await withCheckedContinuation { continuation in
        loaded.done = continuation
        web.loadHTMLString("<html><body></body></html>", baseURL: nil)
    }
    let test = """
        return list.map(s => { try { document.querySelectorAll(s); return true; } catch (e) { return false; } });
        """
    var answers: [Bool] = []
    answers.reserveCapacity(selectors.count)
    for start in stride(from: 0, to: selectors.count, by: 5000) {
        let batch = Array(selectors[start..<min(start + 5000, selectors.count)])
        let result = try await web.callAsyncJavaScript(test, arguments: ["list": batch], contentWorld: .page)
        guard let flags = result as? [Bool], flags.count == batch.count else { throw CocoaError(.coderInvalidValue) }
        answers += flags
    }
    return answers
}

Task { @MainActor in
    do {
        let answers = try await check()
        try JSONEncoder().encode(answers).write(to: URL(fileURLWithPath: arguments[2]))
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("selector-check: \(error)\n".utf8))
        exit(1)
    }
}
RunLoop.main.run()

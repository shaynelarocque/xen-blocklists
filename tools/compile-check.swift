// Compiles content-blocker lists with WebKit, as Xen will on the phone.
//
//   compile-check <list.json>...
//
// Prints each list's rule count and compile time. Exits 1 if WebKit refuses
// any of them: Xen would keep its old lists rather than take a set it cannot
// compile, so a list that fails here must not ship. Built and run by build.py.

import AppKit
import WebKit

let paths = Array(CommandLine.arguments.dropFirst())
guard !paths.isEmpty else {
    FileHandle.standardError.write(Data("usage: compile-check <list.json>...\n".utf8))
    exit(64)
}

@MainActor
func compileAll() async -> Bool {
    _ = NSApplication.shared
    let folder = FileManager.default.temporaryDirectory.appending(path: "compile-check-\(UUID().uuidString)")
    try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: folder) }
    guard let store = WKContentRuleListStore(url: folder) else { return false }
    var allCompiled = true
    for path in paths {
        let name = URL(fileURLWithPath: path).lastPathComponent
        guard let json = try? String(contentsOfFile: path, encoding: .utf8) else {
            FileHandle.standardError.write(Data("\(name): unreadable\n".utf8))
            allCompiled = false
            continue
        }
        let started = Date()
        do {
            _ = try await store.compileContentRuleList(forIdentifier: "check", encodedContentRuleList: json)
            let rules = json.components(separatedBy: "\"trigger\"").count - 1
            print(String(format: "  compiled %@ (%d rules) in %.1f s", name, rules, Date().timeIntervalSince(started)))
        } catch {
            FileHandle.standardError.write(Data("\(name): \(error.localizedDescription) \((error as NSError).userInfo)\n".utf8))
            allCompiled = false
        }
    }
    return allCompiled
}

Task { @MainActor in
    exit(await compileAll() ? 0 : 1)
}
RunLoop.main.run()

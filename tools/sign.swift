// Signs a manifest with the lists' Ed25519 key, the way Xen checks it.
//
//   XEN_LISTS_SIGNING_KEY=<base64> sign <manifest.json> <manifest.sig>
//   sign --new-key
//
// The signature, base64, covers the manifest's bytes exactly as published.
// Xen holds the public key and takes no list a manifest it cannot verify
// names. --new-key prints a fresh private key and its public key.

import CryptoKit
import Foundation

func die(_ message: String) -> Never {
    FileHandle.standardError.write(Data("sign: \(message)\n".utf8))
    exit(1)
}

let arguments = CommandLine.arguments
if arguments.count == 2, arguments[1] == "--new-key" {
    let key = Curve25519.Signing.PrivateKey()
    print("private: \(key.rawRepresentation.base64EncodedString())")
    print("public:  \(key.publicKey.rawRepresentation.base64EncodedString())")
    exit(0)
}
guard arguments.count == 3 else { die("usage: sign <manifest.json> <manifest.sig> | sign --new-key") }
guard let encoded = ProcessInfo.processInfo.environment["XEN_LISTS_SIGNING_KEY"], !encoded.isEmpty,
      let raw = Data(base64Encoded: encoded.trimmingCharacters(in: .whitespacesAndNewlines)),
      let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: raw) else {
    die("XEN_LISTS_SIGNING_KEY is missing or not a base64 Ed25519 private key")
}
guard let manifest = FileManager.default.contents(atPath: arguments[1]) else { die("cannot read \(arguments[1])") }
let signature = try key.signature(for: manifest)
guard key.publicKey.isValidSignature(signature, for: manifest) else { die("the signature does not verify") }
try Data(signature.base64EncodedString().utf8).write(to: URL(fileURLWithPath: arguments[2]))
print("Signed \(arguments[1]) with key \(key.publicKey.rawRepresentation.base64EncodedString())")

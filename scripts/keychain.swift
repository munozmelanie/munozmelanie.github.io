import Foundation
import Security

// Credentials enter through stdin and leave only through stdout for the calling
// updater. The caller must capture stdout rather than displaying it.
func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8)); exit(1)
}
let arguments = CommandLine.arguments
if arguments.count != 4 { fail("Usage: keychain-helper set|get|delete <service> <account>") }
let action = arguments[1]
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: arguments[2],
    kSecAttrAccount as String: arguments[3],
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
]
if action == "get" {
    var read = query
    read[kSecReturnData as String] = true
    read[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(read as CFDictionary, &result)
    guard status == errSecSuccess, let data = result as? Data else { fail("Trousseau indisponible (code \(status)). Déverrouillez la session et réessayez.") }
    FileHandle.standardOutput.write(data)
} else if action == "set" {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard data.count >= 16 && data.count <= 256, let token = String(data: data, encoding: .utf8), token.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil else { fail("Secret invalide.") }
    let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
    if status == errSecItemNotFound {
        var item = query
        item[kSecValueData as String] = data
        let added = SecItemAdd(item as CFDictionary, nil)
        guard added == errSecSuccess else { fail("Échec du stockage dans le trousseau (code \(added)).") }
    } else if status != errSecSuccess { fail("Échec du stockage dans le trousseau (code \(status)).") }
    print("Secret enregistré dans le trousseau.")
} else if action == "delete" {
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else { fail("Échec de suppression (code \(status)).") }
    print("Secret retiré du trousseau.")
} else { fail("Commande inconnue.") }

import Foundation
import Security

// Builds a PKCS#10 certificate signing request for an EC P-256 key whose
// private half never leaves the Secure Enclave.
enum CertificateSigningRequest {
  enum Failure: Error {
    case keyGeneration(String)
    case signature(String)
  }

  // Generates a key pair under `keyTag` and returns a PEM CSR for it, with
  // `commonName` as subject. The private key is stored with the application
  // tag `<keyTag>.private`, the tag `setIdentity` reads it back with.
  static func generate(commonName: String, keyTag: String) throws -> String {
    let privateKeyTag = "\(keyTag).private"
    // A previous run may have left keys under the same tag, or a restored
    // backup may hold some that belong to another device: drop them all so
    // the lookup cannot pick one of them.
    deleteKeys(applicationTag: privateKeyTag)
    deleteKeys(applicationTag: "\(keyTag).public")

    let privateKey = try createPrivateKey(applicationTag: privateKeyTag)
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw Failure.keyGeneration("no public key")
    }
    var error: Unmanaged<CFError>?
    guard let point = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
      throw Failure.keyGeneration("\(error!.takeRetainedValue())")
    }

    let info = DER.sequence([
      DER.integerZero,
      DER.sequence([DER.set([DER.sequence([DER.oidCommonName, DER.utf8String(commonName)])])]),
      DER.sequence([DER.sequence([DER.oidEcPublicKey, DER.oidPrime256v1]), DER.bitString(point)]),
      DER.emptyAttributes,
    ])
    guard let signature = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, info as CFData, &error) as Data? else {
      throw Failure.signature("\(error!.takeRetainedValue())")
    }
    let csr = DER.sequence([info, DER.sequence([DER.oidEcdsaWithSHA256]), DER.bitString(signature)])
    return pem(csr)
  }

  static func deleteKeys(applicationTag: String) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: applicationTag,
    ]
    SecItemDelete(query as CFDictionary)
  }

  private static func createPrivateKey(applicationTag: String) throws -> SecKey {
    var privateKeyAttributes: [String: Any] = [
      kSecAttrIsPermanent as String: true,
      kSecAttrApplicationTag as String: applicationTag,
    ]
    var attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
    ]
    #if targetEnvironment(simulator)
    // No Secure Enclave: a software key, still bound to this device.
    privateKeyAttributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    #else
    var accessError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      .privateKeyUsage,
      &accessError
    ) else {
      throw Failure.keyGeneration("\(accessError!.takeRetainedValue())")
    }
    privateKeyAttributes[kSecAttrAccessControl as String] = access
    attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
    #endif
    attributes[kSecPrivateKeyAttrs as String] = privateKeyAttributes
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      throw Failure.keyGeneration("\(error!.takeRetainedValue())")
    }
    return key
  }

  private static func pem(_ der: Data) -> String {
    let body = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
    return "-----BEGIN CERTIFICATE REQUEST-----\n\(body)\n-----END CERTIFICATE REQUEST-----\n"
  }
}

// The few DER encodings a CSR needs.
private enum DER {
  static let integerZero = Data([0x02, 0x01, 0x00])
  // 2.5.4.3
  static let oidCommonName = Data([0x06, 0x03, 0x55, 0x04, 0x03])
  // 1.2.840.10045.2.1
  static let oidEcPublicKey = Data([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
  // 1.2.840.10045.3.1.7
  static let oidPrime256v1 = Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
  // 1.2.840.10045.4.3.2
  static let oidEcdsaWithSHA256 = Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])
  // [0] with no attribute
  static let emptyAttributes = Data([0xA0, 0x00])

  static func sequence(_ items: [Data]) -> Data { tlv(0x30, items.reduce(Data(), +)) }
  static func set(_ items: [Data]) -> Data { tlv(0x31, items.reduce(Data(), +)) }
  static func utf8String(_ value: String) -> Data { tlv(0x0C, Data(value.utf8)) }
  static func bitString(_ value: Data) -> Data { tlv(0x03, Data([0x00]) + value) }

  static func tlv(_ tag: UInt8, _ value: Data) -> Data {
    var out = Data([tag])
    let length = value.count
    if length < 0x80 {
      out.append(UInt8(length))
    } else {
      var bytes: [UInt8] = []
      var remaining = length
      while remaining > 0 {
        bytes.insert(UInt8(remaining & 0xFF), at: 0)
        remaining >>= 8
      }
      out.append(0x80 | UInt8(bytes.count))
      out.append(contentsOf: bytes)
    }
    out.append(value)
    return out
  }
}

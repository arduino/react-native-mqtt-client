import CocoaMQTT
import os
import Security

typealias SecKeyPerformBlock = (SecKey) -> ()

func loadX509Certificate(fromPem: String) -> SecCertificate? {
  let pemContents = fromPem
    .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
    .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
  guard let data = NSData.init(base64Encoded: pemContents, options: NSData.Base64DecodingOptions.ignoreUnknownCharacters) else
  {
    return nil
  }
  return SecCertificateCreateWithData(nil, data)
}

@objc(MqttClient)
class MqttClient : RCTEventEmitter {
  static let DEFAULT_KEY_APPLICATION_TAG = "com.github.emoto-kc-ak.react-native-mqtt-client"

  static let DEFAULT_CA_CERT_LABEL = "Root certificate of an MQTT broker"

  static let DEFAULT_CERT_LABEL = "Certificate for an MQTT client"

  static let HANDLE_KEY = "__handle"

  // Per-instance state. Each JS `MqttClient` is identified by a handle and
  // gets its own Session, so two instances can connect and disconnect
  // independently.
  class Session {
    var client: CocoaMQTT?
    var certArray: CFArray?
    var delegate: SessionDelegate?
  }

  var sessions: [String: Session] = [:]

  var hasListeners: Bool = false

  static override func moduleName() -> String! {
    return "MqttClient"
  }

  static override func requiresMainQueueSetup() -> Bool {
    return false
  }

  override func supportedEvents() -> [String] {
    return [
      "connected",
      "disconnected",
      "received-message",
      "got-error"
    ]
  }

  override func startObserving() -> Void {
    self.hasListeners = true
  }

  override func stopObserving() -> Void {
    self.hasListeners = false
  }

  private func session(forHandle handle: String) -> Session {
    if let existing = self.sessions[handle] {
      return existing
    }
    let s = Session()
    self.sessions[handle] = s
    return s
  }

  func loadPrivateKeyFromKeychain(keyTag: String, reject: RCTPromiseRejectBlock, block: SecKeyPerformBlock){
    var query: [String: AnyObject] = [
      String(kSecClass)             : kSecClassKey,
      String(kSecAttrApplicationTag): keyTag as AnyObject,
      String(kSecReturnRef)         : true as AnyObject
    ]

    if #available(iOS 10, *) {
      query[String(kSecAttrKeyType)] = kSecAttrKeyTypeECSECPrimeRandom
    } else {
      // Fallback on earlier versions
      query[String(kSecAttrKeyType)] = kSecAttrKeyTypeEC
    }

    var result : AnyObject?

    let status = SecItemCopyMatching(query as CFDictionary, &result)

    if status == errSecSuccess {
      print("\(keyTag) Key existed!")
      block((result as! SecKey?)!)
    } else {
      reject("LOAD_KEY_ERROR", "Key does not exist", nil)
    }
  }

  @objc(setIdentity:params:resolve:reject:)
  func setIdentity(handle: String, params: NSDictionary, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void
  {
    let session = self.session(forHandle: handle)
    let caCertPem: String = RCTConvert.nsString(params["caCertPem"])
    let certPem: String = RCTConvert.nsString(params["certPem"])
    let keyTag: String = RCTConvert.nsString(params["keyTag"])
    let keyStoreOptions = RCTConvert.nsDictionary(params["keyStoreOptions"])
    let caCertLabel: String = RCTConvert.nsString(keyStoreOptions?["caCertLabel"]) ?? Self.DEFAULT_CA_CERT_LABEL
    let certLabel: String = RCTConvert.nsString(keyStoreOptions?["certLabel"]) ?? Self.DEFAULT_CERT_LABEL
    let keyApplicationTag: String = RCTConvert.nsString(keyStoreOptions?["keyApplicationTag"]) ?? Self.DEFAULT_KEY_APPLICATION_TAG
    guard let caCert = loadX509Certificate(fromPem: caCertPem) else {
      reject("RANGE_ERROR", "invalid CA certificate", nil)
      return
    }
    guard let cert = loadX509Certificate(fromPem: certPem) else {
      reject("RANGE_ERROR", "invalid certificate", nil)
      return
    }

    let block: SecKeyPerformBlock = { privateKey in
      do {
        // adds the private key to the keychain
        let addKeyAttrs: [String: Any] = [
          kSecClass as String: kSecClassKey,
          kSecValueRef as String: privateKey,
          kSecAttrLabel as String: "Private key that signed an MQTT client certificate",
          kSecAttrApplicationTag as String: keyApplicationTag
        ]
        let err = SecItemAdd(addKeyAttrs as CFDictionary, nil)
        guard err == errSecSuccess || err == errSecDuplicateItem else {
          reject("INVALID_IDENTITY", "failed to add the private key to the keychain: \(err)", nil)
          return
        }
      }
      catch let error {
        reject("RANGE_ERROR", error.localizedDescription, nil)
      }
      // adds the certificate to the keychain
      let addCertAttrs: [String: Any] = [
        kSecClass as String: kSecClassCertificate,
        kSecValueRef as String: cert,
        kSecAttrLabel as String: certLabel
      ]
      var err = SecItemAdd(addCertAttrs as CFDictionary, nil)
      guard err == errSecSuccess || err == errSecDuplicateItem else {
        reject("INVALID_IDENTITY", "failed to add the certificate to the keychain: \(err)", nil)
        return
      }
      // adds the root certificate to the keychain
      // TODO: root certificate may be stored in other place,
      //       because it is public information.
      let addCaCertAttrs: [String: Any] = [
        kSecClass as String: kSecClassCertificate,
        kSecValueRef as String: caCert,
        kSecAttrLabel as String: caCertLabel
      ]
      err = SecItemAdd(addCaCertAttrs as CFDictionary, nil)
      guard err == errSecSuccess || err == errSecDuplicateItem else {
        reject("INVALID_IDENTITY", "failed to add the root certificate to the keychain: \(err)", nil)
        return
      }
      // obtains the identity
      let queryIdentityAttrs: [String: Any] = [
        kSecClass as String: kSecClassIdentity,
        kSecAttrApplicationTag as String: keyApplicationTag,
        kSecReturnRef as String: true
      ]
      var identity: CFTypeRef?
      err = SecItemCopyMatching(queryIdentityAttrs as CFDictionary, &identity)
      guard err == errSecSuccess else {
        reject("INVALID_IDENTITY", "failed to query the keychain for the identity: \(err)", nil)
        return
      }
      guard CFGetTypeID(identity) == SecIdentityGetTypeID() else {
        reject("INVALID_IDENTITY", "failed to query the keychain for the identity: type ID mismatch", nil)
        return
      }
      // remembers the identity and the CA certificate on this session only
      session.certArray = [identity!, caCert] as CFArray
      resolve(nil)
    }

    self.loadPrivateKeyFromKeychain(keyTag: keyTag, reject: reject, block: block)
  }

  @objc(loadIdentity:options:resolve:reject:)
  func loadIdentity(handle: String, options: NSDictionary?, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void
  {
    let session = self.session(forHandle: handle)
    let caCertLabel: String = RCTConvert.nsString(options?["caCertLabel"]) ?? Self.DEFAULT_CA_CERT_LABEL
    let keyApplicationTag: String = RCTConvert.nsString(options?["keyApplicationTag"]) ?? Self.DEFAULT_KEY_APPLICATION_TAG
    // queries a root certificate
    let queryCaCertAttrs: [String: Any] = [
      kSecClass as String: kSecClassCertificate,
      kSecAttrLabel as String: caCertLabel,
      kSecReturnRef as String: true
    ]
    var caCert: CFTypeRef?
    var err = SecItemCopyMatching(queryCaCertAttrs as CFDictionary, &caCert)
    guard err == errSecSuccess else {
      reject("INVALID_IDENTITY", "failed to query a root certificate: \(err)", nil)
      return
    }
    guard CFGetTypeID(caCert) == SecCertificateGetTypeID() else {
      reject("INVALID_IDENTITY", "failed to query a root certificate: type mismatch", nil)
      return
    }
    // queries an identity
    let queryIdentityAttrs: [String: Any] = [
      kSecClass as String: kSecClassIdentity,
      kSecAttrApplicationTag as String: keyApplicationTag,
      kSecReturnRef as String: true
    ]
    var identity: CFTypeRef?
    err = SecItemCopyMatching(queryIdentityAttrs as CFDictionary, &identity)
    guard err == errSecSuccess else {
      reject("INVALID_IDENTITY", "failed to query an identity: \(err)", nil)
      return
    }
    guard CFGetTypeID(identity) == SecIdentityGetTypeID() else {
      reject("INVALID_IDENTITY", "failed to query an identity: type mismatch", nil)
      return
    }
    session.certArray = [identity!, caCert!] as CFArray
    resolve(nil)
  }

  @objc(resetIdentity:options:resolve:reject:)
  func resetIdentity(handle: String, options: NSDictionary?, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void
  {
    let session = self.session(forHandle: handle)
    let caCertLabel: String = RCTConvert.nsString(options?["caCertLabel"]) ?? Self.DEFAULT_CA_CERT_LABEL
    let certLabel: String = RCTConvert.nsString(options?["certLabel"]) ?? Self.DEFAULT_CERT_LABEL
    let keyApplicationTag: String = RCTConvert.nsString(options?["keyApplicationTag"]) ?? Self.DEFAULT_KEY_APPLICATION_TAG
    // deletes a root certificate
    let queryCaCertAttrs: [String: Any] = [
      kSecClass as String: kSecClassCertificate,
      kSecAttrLabel as String: caCertLabel
    ]
    var err = SecItemDelete(queryCaCertAttrs as CFDictionary)
    guard err == errSecSuccess || err == errSecItemNotFound else {
      reject("ILLEGAL_STATE", "failed to delete a root certificate: \(err)", nil)
      return
    }
    // deletes a client certificate
    let queryCertAttrs: [String: Any] = [
      kSecClass as String: kSecClassCertificate,
      kSecAttrLabel as String: certLabel
    ]
    err = SecItemDelete(queryCertAttrs as CFDictionary)
    guard err == errSecSuccess || err == errSecItemNotFound else {
      reject("ILLEGAL_STATE", "failed to delete a certificate: \(err)", nil)
      return
    }
    // deletes a private key
    let queryKeyAttrs: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: keyApplicationTag
    ]
    err = SecItemDelete(queryKeyAttrs as CFDictionary)
    guard err == errSecSuccess || err == errSecItemNotFound else {
      reject("ILLEGAL_STATE", "failed to delete a private key: \(err)", nil)
      return
    }
    session.certArray = nil
    resolve(nil)
  }

  @objc(isIdentityStored:options:resolve:reject:)
  func isIdentityStored(handle: String, options: NSDictionary?, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void
  {
    _ = self.session(forHandle: handle)
    let caCertLabel: String = RCTConvert.nsString(options?["caCertLabel"]) ?? Self.DEFAULT_CA_CERT_LABEL
    let keyApplicationTag: String = RCTConvert.nsString(options?["keyApplicationTag"]) ?? Self.DEFAULT_KEY_APPLICATION_TAG
    // checks a root certificate
    let queryCaCertAttrs: [String: Any] = [
      kSecClass as String: kSecClassCertificate,
      kSecAttrLabel as String: caCertLabel,
      kSecReturnRef as String: true
    ]
    var caCertRef: CFTypeRef?
    var err = SecItemCopyMatching(queryCaCertAttrs as CFDictionary, &caCertRef)
    guard err == errSecSuccess || err == errSecItemNotFound else {
      // an error other than not found
      reject("INVALID_IDENTITY", "failed to query a root certificate: \(err)", nil)
      return
    }
    guard err != errSecItemNotFound else {
      resolve(false)
      return
    }
    guard CFGetTypeID(caCertRef) == SecCertificateGetTypeID() else {
      resolve(false)
      return
    }
    // checks an identity
    let queryIdentityAttrs: [String: Any] = [
      kSecClass as String: kSecClassIdentity,
      kSecAttrApplicationTag as String: keyApplicationTag,
      kSecReturnRef as String: true
    ]
    var identityRef: CFTypeRef?
    err = SecItemCopyMatching(queryIdentityAttrs as CFDictionary, &identityRef)
    guard err == errSecSuccess || err == errSecItemNotFound else {
      // an error other than not found
      reject("INVALID_IDENTITY", "failed to query an identity: \(err)", nil)
      return
    }
    guard err != errSecItemNotFound else {
      resolve(false)
      return
    }
    guard CFGetTypeID(identityRef) == SecIdentityGetTypeID() else {
      resolve(false)
      return
    }
    resolve(true)
  }

  @objc(connect:params:resolve:reject:)
  func connect(handle: String, params: NSDictionary, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    let session = self.session(forHandle: handle)
    let username = RCTConvert.nsString(params["username"])
    let password = RCTConvert.nsString(params["password"])
    let clientId: String = RCTConvert.nsString(params["clientId"])
    let reconnect: Bool = RCTConvert.bool(params["reconnect"])

    var client: CocoaMQTT?
    if username != nil && password != nil {
      let urlString = RCTConvert.nsString(params["url"]) ?? ""
      guard let url = URLComponents(string: urlString), let host = url.host, let port = url.port else {
        reject("ERROR_CONFIG", "Error parsing URL", nil)
        return
      }
      if (url.string?.hasPrefix("ws") != nil) {
        let socket = CocoaMQTTWebSocket(uri: "/mqtt")
        client = CocoaMQTT(clientID: clientId, host: host, port: UInt16(port), socket: socket)
      } else {
        client = CocoaMQTT(clientID: clientId, host: host, port: UInt16(port))
      }
    } else {
      guard let certArray = session.certArray else {
        reject("ERROR_CONFIG", "no identity is configured", nil)
        return
      }
      let host: String = RCTConvert.nsString(params["host"])
      let port: Int = RCTConvert.nsInteger(params["port"])
      client = CocoaMQTT(clientID: clientId, host: host, port: UInt16(port))
      guard let c = client else {
        reject("ERROR_CONFIG", "no client is configured", nil)
        return
      }
      c.sslSettings = [kCFStreamSSLCertificates as String: certArray]
    }
    guard let c = client else {
      reject("ERROR_CONFIG", "no client is configured", nil)
      return
    }
    c.allowUntrustCACertificate = true
    c.enableSSL = true
    c.username = username ?? ""
    c.password = password ?? ""
    c.keepAlive = 60
    let delegate = SessionDelegate(module: self, handle: handle)
    c.delegate = delegate
    c.logLevel = .debug
    c.autoReconnect = reconnect
    session.client = c
    session.delegate = delegate
    _ = c.connect()
    resolve(nil)
  }

  @objc(isConnected:resolve:reject:)
  func isConnected(handle: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void
  {
    os_log("MqttClient: isConnected")
    guard let client = self.sessions[handle]?.client else {
      resolve(false)
      return
    }
    var isConnected: Bool
    let connectionState = client.connState
    switch connectionState {
    case .connected:
      isConnected = true
    case .connecting:
      isConnected = false
    case .disconnected:
      isConnected = false
    default:
      isConnected = false
    }
    resolve(isConnected)
  }

  @objc(disconnect:)
  func disconnect(handle: String) -> Void {
    os_log("MqttClient: disconnecting")
    if let session = self.sessions.removeValue(forKey: handle) {
      session.client?.disconnect()
      // Removing the entry releases the cached certArray and SessionDelegate
      // along with the client. Reconnecting on the same JS instance therefore
      // requires setIdentity/loadIdentity to be called again for
      // identity-based auth.
    }
  }

  // https://stackoverflow.com/a/38161889
  override func invalidate() -> Void {
    os_log("MqttClient: invalidating")
    for (_, session) in self.sessions {
      session.client?.disconnect()
      session.client = nil
      session.delegate = nil
    }
    self.sessions.removeAll()
  }

  @objc(publish:topic:payload:resolve:reject:)
  func publish(handle: String, topic: String, payload: NSArray, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void
  {
    os_log("MqttClient: publishing to %s", topic)
    guard let client = self.sessions[handle]?.client else {
      reject("NO_CONNECTION", "no MQTT connection", nil)
      return
    }
    client.publish(CocoaMQTTMessage(topic: topic, payload: payload as! [UInt8], retained: true))
    resolve(nil)
  }

  @objc(subscribe:topic:resolve:reject:)
  func subscribe(handle: String, topic: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void
  {
    os_log("MqttClient: subscribing %s", topic)
    guard let client = self.sessions[handle]?.client else {
      reject("NO_CONNECTION", "no MQTT connection", nil)
      return
    }
    client.subscribe(topic)
    // TODO: subscription has not been done
    resolve(nil)
  }

  func notifyEvent(handle: String, eventName: String) -> Void {
    self.notifyEvent(handle: handle, eventName: eventName, arg: nil)
  }

  func notifyEvent(handle: String, eventName: String, arg: [String: Any]?) -> Void {
    guard self.hasListeners else { return }
    var body: [String: Any] = arg ?? [:]
    body[Self.HANDLE_KEY] = handle
    self.sendEvent(withName: eventName, body: body)
  }

  func notifyError(handle: String, code: String, message: String) -> Void {
    let arg: [String: Any] = [
      "code": code,
      "message": message
    ]
    self.notifyEvent(handle: handle, eventName: "got-error", arg: arg)
  }
}

// A per-session CocoaMQTTDelegate: each session installs its own instance so
// the delegate callbacks know which JS-side handle to route events to.
class SessionDelegate : NSObject, CocoaMQTTDelegate {
  weak var module: MqttClient?
  let handle: String

  init(module: MqttClient, handle: String) {
    self.module = module
    self.handle = handle
  }

  func mqtt(_ mqtt: CocoaMQTT, didConnectAck ack: CocoaMQTTConnAck) {
    os_log("MqttClient: didConnectAck=%s", "\(ack)")
    if ack == .accept {
      self.module?.notifyEvent(handle: self.handle, eventName: "connected")
    } else {
      self.module?.notifyError(handle: self.handle, code: "ERROR_CONNECTION", message: "\(ack)")
    }
  }

  func mqtt(_ mqtt: CocoaMQTT, didStateChangeTo state: CocoaMQTTConnState) {
    os_log("MqttClient: didStateChangeTo=%s", "\(state)")
  }

  func mqtt(_ mqtt: CocoaMQTT, didPublishMessage message: CocoaMQTTMessage, id: UInt16)
  {
    os_log("MqttClient: didPublishMessage=%s", message.string ?? "")
  }

  func mqtt(_ mqtt: CocoaMQTT, didPublishAck id: UInt16) {
    os_log("MqttClient: didPublishAck=%d", id)
  }

  func mqtt(_ mqtt: CocoaMQTT, didReceiveMessage message: CocoaMQTTMessage, id: UInt16)
  {
    os_log("MqttClient: didReceiveMessage=%s", message.string ?? "")
    let event: [String: Any] = [
      "topic": message.topic,
      "payload": message.payload
    ]
    self.module?.notifyEvent(handle: self.handle, eventName: "received-message", arg: event)
  }

  func mqtt(_ mqtt: CocoaMQTT, didSubscribeTopics success: NSDictionary, failed: [String]) {
    os_log("MqttClient: didSubscribeTopic=%s", "\(success)")
  }

  func mqtt(_ mqtt: CocoaMQTT, didUnsubscribeTopics topics: [String]) {
    os_log("MqttClient: didUnsubscribeTopic=%s", topics)
  }

  func mqtt(_ mqtt: CocoaMQTT, didReceive trust: SecTrust, completionHandler: @escaping (Bool) -> Void) {
    if mqtt.host.hasPrefix("ws") {
      completionHandler(true)
      return
    }
    var result: SecTrustResultType = .invalid
    let trustResultDetailsKey = "TrustResultDetails"
    let validityPeriodMaximumsKey = "ValidityPeriodMaximums"

    let queryCaCertAttrs: [String: Any] = [
      kSecClass as String: kSecClassCertificate,
      kSecAttrLabel as String: "arduino-ca",
      kSecReturnRef as String: true
    ]
    var caCert: CFTypeRef?
    let err = SecItemCopyMatching(queryCaCertAttrs as CFDictionary, &caCert)
    guard err == errSecSuccess else {
      completionHandler(false)
      return
    }
    guard CFGetTypeID(caCert) == SecCertificateGetTypeID() else {
      completionHandler(false)
      return
    }

    SecTrustSetAnchorCertificates(trust, [caCert] as CFArray)

    SecTrustSetAnchorCertificatesOnly(trust, false)

    if (SecTrustEvaluate(trust, &result) != errSecSuccess) {
      completionHandler(false)
      return
    }

    switch result {
    case .proceed:
      completionHandler(true)
    case .unspecified:
      completionHandler(true)
    case .recoverableTrustFailure:
      // Check the reason why the certificate is untrusted
      let secTrustCopyResult = SecTrustCopyResult(trust)! as NSDictionary
      // If TrustResultDetails is in our result we can find the possible issue
      if let trustResultDetails = secTrustCopyResult[trustResultDetailsKey] as? NSArray {
        // ValidityPeriodMaximums = 0 indicates that the period of validity of the certificate is too short
        // The maximum validity is 397 days https://support.apple.com/en-us/HT211025
        if trustResultDetails.value(forKey: validityPeriodMaximumsKey) is [NSObject] {
          completionHandler(true)
          return
        }
      }
      completionHandler(false)
    default:
      completionHandler(false)
    }
  }

  func mqttDidPing(_ mqtt: CocoaMQTT) {
    os_log("MqttClient: didPing")
  }

  func mqttDidReceivePong(_ mqtt: CocoaMQTT) {
    os_log("MqttClient: didReceivePong")
  }

  func mqttDidDisconnect(_ mqtt: CocoaMQTT, withError err: Error?) {
    os_log("MqttClient: didDisconnect")
    if err != nil {
      self.module?.notifyError(handle: self.handle, code: "ERROR_CONNECTION", message: "\(err!)")
    } else {
      self.module?.notifyEvent(handle: self.handle, eventName: "disconnected")
    }
  }
}

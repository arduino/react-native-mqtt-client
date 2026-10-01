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

// Implementation of the `MqttClient` TurboModule. MqttClient.mm adopts the
// codegen spec and forwards every call here; events go out through `emit`.
@objc(MqttClientImpl)
public class MqttClientImpl : NSObject {
  static let DEFAULT_KEY_APPLICATION_TAG = "com.github.emoto-kc-ak.react-native-mqtt-client"

  static let DEFAULT_CA_CERT_LABEL = "Root certificate of an MQTT broker"

  static let DEFAULT_CERT_LABEL = "Certificate for an MQTT client"

  static let HANDLE_KEY = "__handle"

  // Fallback for a disconnect the socket never reports back.
  static let DISCONNECT_TIMEOUT: TimeInterval = 5

  // CocoaMQTT's delegate queue: callbacks and pending promises are
  // serialised on it.
  let queue = DispatchQueue(label: "cc.arduino.react-native-mqtt-client")

  // Per-instance state. Each JS `MqttClient` is identified by a handle and
  // gets its own Session, so two instances can connect and disconnect
  // independently.
  class Session {
    var client: CocoaMQTT?
    var certArray: CFArray?
    var delegate: SessionDelegate?
  }

  var sessions: [String: Session] = [:]

  @objc public var emit: ((String, [String: Any]) -> Void)?

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
      reject("INVALID_IDENTITY", "the private key does not exist", nil)
    }
  }

  @objc(setIdentity:params:resolve:reject:)
  public func setIdentity(handle: String, params: NSDictionary, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void
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
  public func loadIdentity(handle: String, options: NSDictionary?, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void
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
  public func resetIdentity(handle: String, options: NSDictionary?, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void
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
  public func isIdentityStored(handle: String, options: NSDictionary?, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void
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
  public func connect(handle: String, params: NSDictionary, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    let session = self.session(forHandle: handle)
    let username = RCTConvert.nsString(params["username"])
    let password = RCTConvert.nsString(params["password"])
    let clientId: String = RCTConvert.nsString(params["clientId"])
    let reconnect: Bool = RCTConvert.bool(params["reconnect"])

    let c: CocoaMQTT
    if username != nil && password != nil {
      let urlString = RCTConvert.nsString(params["url"]) ?? ""
      guard let url = URLComponents(string: urlString), let scheme = url.scheme, let host = url.host, let port = url.port else {
        reject("ERROR_CONFIG", "Error parsing URL", nil)
        return
      }
      switch scheme {
      case "ws", "wss":
        let socket = CocoaMQTTWebSocket(uri: url.path.isEmpty ? "/mqtt" : url.path)
        c = CocoaMQTT(clientID: clientId, host: host, port: UInt16(port), socket: socket)
      case "tcp", "mqtt", "ssl", "mqtts":
        c = CocoaMQTT(clientID: clientId, host: host, port: UInt16(port))
      default:
        reject("ERROR_CONFIG", "unsupported URL scheme: \(scheme)", nil)
        return
      }
      c.enableSSL = ["wss", "ssl", "mqtts"].contains(scheme)
    } else {
      guard let certArray = session.certArray else {
        reject("ERROR_CONFIG", "no identity is configured", nil)
        return
      }
      let host: String = RCTConvert.nsString(params["host"])
      let port: Int = RCTConvert.nsInteger(params["port"])
      c = CocoaMQTT(clientID: clientId, host: host, port: UInt16(port))
      c.sslSettings = [kCFStreamSSLCertificates as String: certArray]
      c.enableSSL = true
    }
    c.allowUntrustCACertificate = true
    c.username = username ?? ""
    c.password = password ?? ""
    c.keepAlive = 60
    let delegate = SessionDelegate(module: self, handle: handle)
    c.delegate = delegate
    c.delegateQueue = self.queue
    c.logLevel = .warning
    c.autoReconnect = reconnect
    // CocoaMQTT's default maxAutoReconnectTimeInterval is 128s; the 1→2→4→8→
    // 16→32→64→128s backoff means a socket dropped in background can take
    // ~45s+ to recover after foreground. Cap at 5s so reconnect matches
    // perceived app latency.
    c.maxAutoReconnectTimeInterval = 5
    session.client = c
    session.delegate = delegate
    self.queue.async {
      delegate.pendingConnect = PendingPromise(resolve: resolve, reject: reject)
      if !c.connect() {
        delegate.pendingConnect = nil
        reject("ERROR_CONNECTION", "failed to open the connection", nil)
      }
    }
  }

  @objc(isConnected:resolve:reject:)
  public func isConnected(handle: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void
  {
    guard let client = self.sessions[handle]?.client else {
      resolve(false)
      return
    }
    resolve(client.connState == .connected)
  }

  @objc(disconnect:resolve:reject:)
  public func disconnect(handle: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
    os_log("MqttClient: disconnecting")
    // Removing the entry releases the cached certArray along with the
    // client. Reconnecting on the same JS instance therefore requires
    // setIdentity/loadIdentity to be called again for identity-based auth.
    guard let session = self.sessions.removeValue(forKey: handle),
          let client = session.client,
          let delegate = session.delegate else {
      resolve(nil)
      return
    }
    self.queue.async {
      guard client.connState == .connected || client.connState == .connecting else {
        // No socket to close: CocoaMQTT would never report back.
        delegate.rejectPendingOperations(code: "NO_CONNECTION", message: "disconnected")
        resolve(nil)
        return
      }
      // Keeps the session alive until the socket reports it is closed.
      delegate.closingSession = session
      delegate.pendingDisconnect = PendingPromise(resolve: resolve, reject: reject)
      client.disconnect()
      self.queue.asyncAfter(deadline: .now() + Self.DISCONNECT_TIMEOUT) {
        delegate.completeDisconnect()
      }
    }
  }

  @objc public func invalidate() -> Void {
    os_log("MqttClient: invalidating")
    for (_, session) in self.sessions {
      session.client?.disconnect()
      session.client = nil
      session.delegate = nil
    }
    self.sessions.removeAll()
  }

  @objc(publish:topic:payload:resolve:reject:)
  public func publish(handle: String, topic: String, payload: NSArray, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void
  {
    guard let session = self.sessions[handle], let client = session.client, let delegate = session.delegate else {
      reject("NO_CONNECTION", "no MQTT connection", nil)
      return
    }
    guard let bytes = payload as? [UInt8] else {
      reject("RANGE_ERROR", "payload must be an array of bytes", nil)
      return
    }
    let message = CocoaMQTTMessage(topic: topic, payload: bytes, qos: .qos1, retained: false)
    self.queue.async {
      guard client.connState == .connected else {
        reject("ERROR_PUBLISH", "client is not connected", nil)
        return
      }
      let msgid = client.publish(message)
      guard msgid > 0 else {
        reject("ERROR_PUBLISH", "the outgoing message queue is full", nil)
        return
      }
      // Resolved by the broker's PUBACK.
      delegate.pendingPublishes[UInt16(msgid)] = PendingPromise(resolve: resolve, reject: reject)
    }
  }

  @objc(subscribe:topic:resolve:reject:)
  public func subscribe(handle: String, topic: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void
  {
    guard let session = self.sessions[handle], let client = session.client, let delegate = session.delegate else {
      reject("NO_CONNECTION", "no MQTT connection", nil)
      return
    }
    self.queue.async {
      guard client.connState == .connected else {
        reject("NO_CONNECTION", "client is not connected", nil)
        return
      }
      // Resolved by the broker's SUBACK.
      delegate.pendingSubscribes[topic, default: []].append(PendingPromise(resolve: resolve, reject: reject))
      client.subscribe(topic, qos: .qos1)
    }
  }

  func notifyEvent(handle: String, eventName: String) -> Void {
    self.notifyEvent(handle: handle, eventName: eventName, arg: nil)
  }

  func notifyEvent(handle: String, eventName: String, arg: [String: Any]?) -> Void {
    var body: [String: Any] = arg ?? [:]
    body[Self.HANDLE_KEY] = handle
    self.emit?(eventName, body)
  }

  func notifyError(handle: String, code: String, message: String) -> Void {
    let arg: [String: Any] = [
      "code": code,
      "message": message
    ]
    self.notifyEvent(handle: handle, eventName: "got-error", arg: arg)
  }
}

struct PendingPromise {
  let resolve: RCTPromiseResolveBlock
  let reject: RCTPromiseRejectBlock
}

// A per-session CocoaMQTTDelegate: each session installs its own instance so
// the delegate callbacks know which JS-side handle to route events to. It
// also holds the promises waiting for a broker acknowledgement. Every member
// is only touched on MqttClientImpl.queue, CocoaMQTT's delegate queue.
class SessionDelegate : NSObject, CocoaMQTTDelegate {
  weak var module: MqttClientImpl?
  let handle: String

  var pendingConnect: PendingPromise?
  var pendingDisconnect: PendingPromise?
  var pendingPublishes: [UInt16: PendingPromise] = [:]
  var pendingSubscribes: [String: [PendingPromise]] = [:]
  var closingSession: MqttClientImpl.Session?

  init(module: MqttClientImpl, handle: String) {
    self.module = module
    self.handle = handle
  }

  func rejectPendingOperations(code: String, message: String) {
    for (_, promise) in self.pendingPublishes {
      promise.reject(code, message, nil)
    }
    self.pendingPublishes.removeAll()
    for (_, promises) in self.pendingSubscribes {
      promises.forEach { $0.reject(code, message, nil) }
    }
    self.pendingSubscribes.removeAll()
  }

  func completeDisconnect() {
    guard let promise = self.pendingDisconnect else { return }
    self.pendingDisconnect = nil
    self.closingSession = nil
    self.rejectPendingOperations(code: "NO_CONNECTION", message: "disconnected")
    promise.resolve(nil)
  }

  func mqtt(_ mqtt: CocoaMQTT, didConnectAck ack: CocoaMQTTConnAck) {
    os_log("MqttClient: didConnectAck=%s", "\(ack)")
    let pending = self.pendingConnect
    self.pendingConnect = nil
    if ack == .accept {
      pending?.resolve(nil)
      self.module?.notifyEvent(handle: self.handle, eventName: "connected")
      return
    }
    let code: String
    switch ack {
    case .notAuthorized, .badUsernameOrPassword:
      code = "ERROR_NOT_AUTHORIZED"
    default:
      code = "ERROR_CONNECTION"
    }
    // A rejected connect() reports through its promise, a refused
    // reconnection through `got-error`.
    if let pending = pending {
      pending.reject(code, "\(ack)", nil)
    } else {
      self.module?.notifyError(handle: self.handle, code: code, message: "\(ack)")
    }
  }

  func mqtt(_ mqtt: CocoaMQTT, didStateChangeTo state: CocoaMQTTConnState) {
    os_log("MqttClient: didStateChangeTo=%s", "\(state)")
  }

  func mqtt(_ mqtt: CocoaMQTT, didPublishMessage message: CocoaMQTTMessage, id: UInt16)
  {
  }

  func mqtt(_ mqtt: CocoaMQTT, didPublishAck id: UInt16) {
    self.pendingPublishes.removeValue(forKey: id)?.resolve(nil)
  }

  func mqtt(_ mqtt: CocoaMQTT, didReceiveMessage message: CocoaMQTTMessage, id: UInt16)
  {
    let event: [String: Any] = [
      "topic": message.topic,
      "payload": message.payload
    ]
    self.module?.notifyEvent(handle: self.handle, eventName: "received-message", arg: event)
  }

  func mqtt(_ mqtt: CocoaMQTT, didSubscribeTopics success: NSDictionary, failed: [String]) {
    for case let topic as String in success.allKeys {
      self.pendingSubscribes.removeValue(forKey: topic)?.forEach { $0.resolve(nil) }
    }
    for topic in failed {
      self.pendingSubscribes.removeValue(forKey: topic)?.forEach {
        $0.reject("ERROR_SUBSCRIBE", "the broker refused the subscription to \(topic)", nil)
      }
    }
  }

  func mqtt(_ mqtt: CocoaMQTT, didUnsubscribeTopics topics: [String]) {
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
  }

  func mqttDidReceivePong(_ mqtt: CocoaMQTT) {
  }

  func mqttDidDisconnect(_ mqtt: CocoaMQTT, withError err: Error?) {
    os_log("MqttClient: didDisconnect")
    if self.pendingDisconnect != nil {
      self.completeDisconnect()
      self.module?.notifyEvent(handle: self.handle, eventName: "disconnected")
      return
    }
    self.rejectPendingOperations(code: "NO_CONNECTION", message: "connection lost")
    if let pending = self.pendingConnect {
      self.pendingConnect = nil
      pending.reject("ERROR_CONNECTION", err.map { "\($0)" } ?? "connection closed", err)
      return
    }
    if err != nil {
      self.module?.notifyError(handle: self.handle, code: "ERROR_CONNECTION", message: "\(err!)")
    } else {
      self.module?.notifyEvent(handle: self.handle, eventName: "disconnected")
    }
  }
}

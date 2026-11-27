package cc.arduino.reactnative.mqtt

import android.util.Log
import com.facebook.react.bridge.*
import com.facebook.react.module.annotations.ReactModule
import org.eclipse.paho.client.mqttv3.*
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence
import javax.net.ssl.SSLSocketFactory

/**
 * An MQTT client.
 *
 * Each JS-side `MqttClient` instance owns an independent native session,
 * identified by a handle passed as the first argument to every method. The
 * native module itself remains a singleton (React Native requirement), but
 * it maintains a `handle -> Session` map so two JS instances can connect to
 * different brokers concurrently.
 *
 * Powered by the [Paho MQTT Java client](https://github.com/eclipse-paho/paho.mqtt.java),
 * used in-process: keepalive pings run on Paho's own timer thread.
 */
@ReactModule(name = RNMqttClient.NAME)
class RNMqttClient(reactContext: ReactApplicationContext)
    : NativeMqttClientSpec(reactContext) {
    companion object {
        /** Default alias for a root certificate in a key store. */
        const val DEFAULT_CA_CERT_ALIAS: String = "ca-certificate"

        /** Default alias for a private key in a key store. */
        const val DEFAULT_KEY_ALIAS: String = "private-key"

        const val NAME: String = NativeMqttClientSpec.NAME

        private const val PROTOCOL: String = "ssl"

        private const val HANDLE_KEY: String = "__handle"
    }

    // Per-instance state. Keyed by the handle the JS wrapper allocates per
    // `new MqttClient()`.
    private class Session {
        var client: MqttAsyncClient? = null
        var socketFactory: SSLSocketFactory? = null
    }

    private val sessions: MutableMap<String, Session> = HashMap()

    private fun sessionFor(handle: String): Session {
        var s = this.sessions[handle]
        if (s == null) {
            s = Session()
            this.sessions[handle] = s
        }
        return s
    }

    override fun invalidate() {
        super.invalidate()
        Log.d(NAME, "invalidate")
        for ((_, session) in this.sessions) {
            val client = session.client ?: continue
            releaseClient(client, null)
            session.client = null
        }
        this.sessions.clear()
    }

    /**
     * Sets the identity for connection.
     *
     * Cached in the session identified by `handle`. The persistent
     * Android key store entries are still keyed by the user-supplied
     * `keyStoreOptions` and remain shared across all sessions.
     */
    override fun setIdentity(handle: String, params: ReadableMap, promise: Promise) {
        try {
            val session = this.sessionFor(handle)
            val keyStoreOptions: ReadableMap? =
                    params.getOptionalMap("keyStoreOptions")
            session.socketFactory = SSLSocketFactoryUtil.createSocketFactory(
                    caCertPem = params.getRequiredString("caCertPem"),
                    certPem = params.getRequiredString("certPem"),
                    keyTag = params.getRequiredString("keyTag"),
                    caCertAlias = keyStoreOptions?.getOptionalString("caCertAlias")
                            ?: DEFAULT_CA_CERT_ALIAS
            )
            promise.resolve(null)
            return
        } catch (e: IllegalArgumentException) {
            Log.e(NAME, "invalid identity parameters", e)
            promise.reject("RANGE_ERROR", e)
            return
        } catch (e: Exception) {
            Log.e(NAME, "failed to create an SSLSocketFactory", e)
            promise.reject("INVALID_IDENTITY", e)
            return
        }
    }

    /**
     * Loads the identity stored in the Android key store.
     */
    override fun loadIdentity(handle: String, options: ReadableMap?, promise: Promise) {
        try {
            val session = this.sessionFor(handle)
            session.socketFactory = SSLSocketFactoryUtil.createSocketFactoryFromAndroidKeyStore(
                    keyAlias = options?.getOptionalString("keyAlias") ?: DEFAULT_KEY_ALIAS,
                    caCertAlias = options?.getOptionalString("caCertAlias") ?: DEFAULT_CA_CERT_ALIAS
            )
            promise.resolve(null)
            return
        } catch (e: Exception) {
            Log.e(
                    NAME,
                    "failed to load an identity from the Android key store",
                    e
            )
            promise.reject("INVALID_IDENTITY", e)
            return
        }
    }

    /**
     * Generates a key pair under `keyTag` and resolves to a PEM CSR for it.
     */
    override fun generateCSR(commonName: String, keyTag: String, promise: Promise) {
        try {
            promise.resolve(CertificateSigningRequest.generate(commonName, keyTag))
        } catch (e: Exception) {
            Log.e(NAME, "failed to generate a CSR", e)
            promise.reject("INVALID_IDENTITY", e)
        }
    }

    /**
     * Deletes the key store entries whose alias starts with one of
     * `prefixes` and with none of `keep`.
     */
    override fun deleteIdentities(prefixes: ReadableArray, keep: ReadableArray, promise: Promise) {
        try {
            val deleted = SSLSocketFactoryUtil.deleteAndroidKeyStoreEntries(
                    prefixes.toArrayList().map { it.toString() },
                    keep.toArrayList().map { it.toString() }
            )
            promise.resolve(deleted)
        } catch (e: Exception) {
            Log.e(NAME, "failed to delete identities", e)
            promise.reject("ILLEGAL_STATE", e)
        }
    }

    /**
     * Resets the identity stored in the key store.
     */
    override fun resetIdentity(handle: String, options: ReadableMap?, promise: Promise) {
        try {
            val session = this.sessionFor(handle)
            SSLSocketFactoryUtil.resetAndroidKeyStore(
                    options?.getOptionalString("caCertAlias") ?: DEFAULT_CA_CERT_ALIAS,
                    options?.getOptionalString("keyAlias") ?: DEFAULT_KEY_ALIAS
            )
            session.socketFactory = null
            promise.resolve(null)
            return
        } catch (e: IllegalArgumentException) {
            Log.e(NAME, "invalid key store options", e)
            promise.reject("RANGE_ERROR", e)
            return
        } catch (e: Exception) {
            Log.e(NAME, "failed to reset the identity", e)
            promise.reject("INVALID_IDENTITY", e)
            return
        }
    }

    /**
     * Returns whether an identity for connection is saved in the Android
     * key store.
     */
    override fun isIdentityStored(handle: String, options: ReadableMap?, promise: Promise) {
        try {
            // Touch the session so the handle is materialised even before
            // setIdentity/loadIdentity is called.
            this.sessionFor(handle)
            val result = SSLSocketFactoryUtil.isIdentityStoredInAndroidKeyStore(
                    options?.getOptionalString("caCertAlias") ?: DEFAULT_CA_CERT_ALIAS,
                    options?.getOptionalString("keyAlias") ?: DEFAULT_KEY_ALIAS
            )
            promise.resolve(result)
            return
        } catch (e: IllegalArgumentException) {
            Log.e(NAME, "invalid key store options", e)
            promise.reject("RANGE_ERROR", e)
            return
        } catch (e: Exception) {
            Log.e(NAME, "failed to test the identity", e)
            promise.reject("INVALID_IDENTITY", e)
            return
        }
    }

    /**
     * Connects to an MQTT broker.
     */
    override fun connect(handle: String, params: ReadableMap, promise: Promise) {
        val session = this.sessionFor(handle)
        // parses parameters
        val parsedParams: ConnectionParameters
        try {
            parsedParams = ConnectionParameters.parseReadableMap(params)
        } catch (e: IllegalArgumentException) {
            Log.e(NAME, "invalid connection parameters", e)
            promise.reject("RANGE_ERROR", e)
            return
        }
        // obtains a socket factory in case of identity-based connection
        val socketFactory =
            if (parsedParams.username != null && parsedParams.password != null)
                null
            else
                session.socketFactory ?: run {
                    promise.reject("ERROR_CONFIG", Exception("no identity is configured"))
                    return
                }
        // initializes a client
        try {
            val brokerUri = parsedParams.url ?: "$PROTOCOL://${parsedParams.host}:${parsedParams.port}"
            // In-memory persistence: sessions are clean, and Paho's default
            // file persistence writes to the process working directory,
            // which is not writable on Android.
            val client = MqttAsyncClient(
                    brokerUri,
                    parsedParams.clientId,
                    MemoryPersistence()
            )
            session.client = client
            client.setCallback(object : MqttCallbackExtended {
                override fun connectComplete(
                        reconnect: Boolean,
                        serverURI: String
                ) {
                    Log.d(NAME, "connectComplete")
                    this@RNMqttClient.notifyEvent(handle, "connected", null)
                }

                override fun connectionLost(cause: Throwable?) {
                    Log.d(NAME, "connectionLost", cause)
                    this@RNMqttClient.notifyError(handle, "ERROR_CONNECTION", cause)
                    if (!parsedParams.reconnect) {
                        this@RNMqttClient.notifyEvent(handle, "disconnected", null)
                    }
                }

                override fun deliveryComplete(token: IMqttDeliveryToken) {
                    Log.d(NAME, "deliveryComplete")
                }

                override fun messageArrived(
                        topic: String,
                        message: MqttMessage
                ) {
                    Log.d(NAME, "messageArrived")
                    val arg = Arguments.createMap()
                    arg.putString("topic", topic)
                    arg.putArray("payload", Arguments.fromArray(message.payload.map { it.toInt() }.toIntArray()))
                    this@RNMqttClient.notifyEvent(handle, "received-message", arg)
                }
            })
            val connectOptions = MqttConnectOptions()
            if (socketFactory != null) {
                connectOptions.socketFactory = socketFactory
            }
            if (parsedParams.username != null) {
                connectOptions.userName = parsedParams.username
            }
            if (parsedParams.password != null) {
                connectOptions.password = parsedParams.password.toCharArray()
            }
            connectOptions.isCleanSession = true
            connectOptions.isAutomaticReconnect = parsedParams.reconnect
            parsedParams.keepAlive?.let { connectOptions.keepAliveInterval = it }
            // Paho's default maxReconnectDelay is 128000ms; the 1→2→4→8→16→
            // 32→64→128s backoff means a socket dropped during Doze can take
            // ~45s+ to recover after foreground. Cap at 5s so reconnect
            // matches perceived app latency.
            connectOptions.maxReconnectDelay = 5000
            // Pin protocol to 3.1.1. When MQTT_VERSION_DEFAULT is used, Paho
            // retries a failed connect with 3.1 as a fallback and reuses the
            // same WebSocketSecureNetworkModule instance. That module's
            // PipedInputStream is initialised once in the constructor and
            // start() is not idempotent, so the retry throws
            // IOException: Already connected. Pinning the version disables
            // the fallback and surfaces the original failure to the caller.
            connectOptions.mqttVersion = MqttConnectOptions.MQTT_VERSION_3_1_1
            Log.d(NAME, "connecting to the broker")
            // Paho reports the outcome of connect() only to the listener
            // passed here, not to one set later on the returned token.
            client.connect(connectOptions, null, object : IMqttActionListener {
                override fun onSuccess(asyncActionToken: IMqttToken) {
                    Log.d(NAME, "connected, token: ${asyncActionToken}")
                    promise.resolve(null)
                }

                override fun onFailure(
                        asyncActionToken: IMqttToken,
                        cause: Throwable?
                ) {
                    val reasonCode = (cause as? MqttException)?.reasonCode
                    val rootCause = describeRootCause(cause)
                    Log.e(
                            NAME,
                            "failed to connect, token: ${asyncActionToken}, reasonCode: ${reasonCode}, rootCause: ${rootCause}",
                            cause
                    )
                    val code = when (reasonCode?.toShort()) {
                        MqttException.REASON_CODE_NOT_AUTHORIZED,
                        MqttException.REASON_CODE_FAILED_AUTHENTICATION ->
                            "ERROR_NOT_AUTHORIZED"
                        else -> "ERROR_CONNECTION"
                    }
                    val baseMessage = if (reasonCode != null) {
                        "${cause?.message ?: "MqttException"} (reasonCode=${reasonCode})"
                    } else {
                        cause?.message
                            ?: cause?.javaClass?.simpleName
                            ?: "connection failed"
                    }
                    val message = if (rootCause != null) {
                        "$baseMessage: $rootCause"
                    } else {
                        baseMessage
                    }
                    promise.reject(code, message, cause)
                }
            })
        } catch (e: MqttException) {
            Log.e(NAME, "failed to connect", e)
            promise.reject("ERROR_CONNECTION", e)
            return
        } catch (e: IllegalArgumentException) {
            Log.e(NAME, "failed to connect", e)
            promise.reject("ERROR_CONNECTION", e)
            return
        }
    }

    /**
     * Disconnects from the MQTT broker.
     *
     * Resolved right away: the session is gone, and the client finishes
     * disconnecting and closes in the background.
     */
    override fun disconnect(handle: String, promise: Promise) {
        // Remove the entry up-front so the cached socketFactory is released
        // along with the client. Reconnecting on the same JS instance
        // therefore requires setIdentity/loadIdentity to be called again for
        // identity-based auth.
        val client = this.sessions.remove(handle)?.client
        if (client == null) {
            promise.resolve(null)
            return
        }
        releaseClient(client, handle)
        promise.resolve(null)
    }

    /**
     * Publishes given data to a specified topic.
     */
    override fun publish(handle: String, topic: String, payload: ReadableArray, promise: Promise) {
        val client = this.sessions[handle]?.client
        if (client == null) {
            Log.w(NAME, "failed to publish. no MQTT connection")
            promise.reject("NO_CONNECTION", Exception("no MQTT connection"))
            return
        }

        try {
            val ints = payload.toArrayList().toArray(Array<Number>(payload.size()) { v -> v.toInt() })
            val bytes = ints.foldIndexed(ByteArray(ints.size)) { i, a, v -> a.apply { set(i, v.toByte()) } }

            client.publish(
                    topic,
                    bytes,
                    1, // qos
                    false, // not retained
                    null,
                    object : IMqttActionListener {
                        override fun onSuccess(asyncActionToken: IMqttToken) {
                            Log.d(NAME, "published, token: ${asyncActionToken}")
                            promise.resolve(null)
                        }

                        override fun onFailure(
                                asyncActionToken: IMqttToken,
                                cause: Throwable?
                        ) {
                            Log.e(
                                    NAME,
                                    "failed to publish, token: ${asyncActionToken}",
                                    cause
                            )
                            promise.reject("ERROR_PUBLISH", cause)
                        }
                    })
        } catch (e: MqttException) {
            Log.e(NAME, "failed to publish to ${topic}", e)
            promise.reject("ERROR_PUBLISH", e)
            return
        } catch (e: IllegalArgumentException) {
            Log.e(NAME, "failed to publish to $topic: invalid topic", e)
            promise.reject("ERROR_PUBLISH", e)
            return
        }
    }

    /**
     * Subscribes a specified topic.
     */
    override fun subscribe(handle: String, topic: String, promise: Promise) {
        val client = this.sessions[handle]?.client
        if (client == null) {
            promise.reject("NO_CONNECTION", Exception("no MQTT connection"))
            return
        }
        try {
            client.subscribe(
                    topic,
                    1, // qos
                    null,
                    object : IMqttActionListener {
                        override fun onSuccess(asyncActionToken: IMqttToken) {
                            Log.d(NAME, "subscribed, token: ${asyncActionToken}")
                            promise.resolve(null)
                        }

                        override fun onFailure(
                                asyncActionToken: IMqttToken,
                                cause: Throwable?
                        ) {
                            Log.e(
                                    NAME,
                                    "failed to subscribe, token: ${asyncActionToken}",
                                    cause
                            )
                            promise.reject("ERROR_SUBSCRIBE", cause)
                        }
                    })
        } catch (e: MqttException) {
            Log.e(NAME, "failed to subscribe '$topic'", e)
            promise.reject("ERROR_SUBSCRIBE", e)
            return
        } catch (e: IllegalArgumentException) {
            Log.e(NAME, "failed to subscribe '$topic': invalid topic", e)
            promise.reject("ERROR_SUBSCRIBE", e)
            return
        }
    }

    /**
     * Determines if this client is currently connected to the server.
     */
    override fun isConnected(handle: String, promise: Promise) {
        val client = this.sessions[handle]?.client
        if (client == null) {
            promise.resolve(false)
            return
        }
        try {
            val isClientConnected = client.isConnected
            promise.resolve(isClientConnected)
        } catch (e: Exception) {
            Log.e(NAME, "failed to check connection", e)
            promise.reject("ERROR_CHECK_CONNECTION", e)
            return
        }
    }

    // NativeEventEmitter calls these; events are emitted regardless of
    // listeners, so there is nothing to track.
    override fun addListener(eventName: String) {}

    override fun removeListeners(count: Double) {}

    // Notifies a `got-error` event.
    private fun notifyError(handle: String, code: String, cause: Throwable?) {
        val params = Arguments.createMap()
        params.putString("code", code)
        params.putString("message", cause?.message ?: "")
        this.notifyEvent(handle, "got-error", params)
    }

    // Disconnects and closes a client, so that it stops pinging and
    // reconnecting. A connected client sends DISCONNECT and is closed from
    // the completion callback: close() while Paho is still disconnecting
    // only marks the close as pending, and the disconnect then skips its own
    // shutdown, leaving the ping timer thread behind. `handle`, when given,
    // gets the `disconnected` event once DISCONNECT has gone out. A client
    // that is not connected (waiting between automatic reconnect attempts,
    // or in the middle of one) is shut down and closed right away, which
    // also ends its reconnect cycle.
    private fun releaseClient(client: MqttAsyncClient, handle: String?) {
        if (client.isConnected) {
            try {
                client.disconnect(null, object : IMqttActionListener {
                    override fun onSuccess(asyncActionToken: IMqttToken) {
                        Log.d(NAME, "disconnected, token: ${asyncActionToken}")
                        closeQuietly(client)
                        if (handle != null) {
                            this@RNMqttClient.notifyEvent(handle, "disconnected", null)
                        }
                    }

                    override fun onFailure(
                            asyncActionToken: IMqttToken,
                            cause: Throwable?
                    ) {
                        Log.e(
                                NAME,
                                "failed to disconnect, token: ${asyncActionToken}",
                                cause
                        )
                        closeQuietly(client)
                    }
                })
                return
            } catch (e: MqttException) {
                Log.w(NAME, "failed to disconnect, shutting the client down", e)
            }
        }
        try {
            client.disconnectForcibly(0, 0, false)
        } catch (e: MqttException) {
            Log.w(NAME, "failed to shut the MQTT client down", e)
        }
        closeQuietly(client)
    }

    private fun closeQuietly(client: MqttAsyncClient) {
        try {
            client.close()
        } catch (e: MqttException) {
            Log.w(NAME, "failed to close MQTT client", e)
        }
    }

    // Walks the exception chain and returns a compact description of the
    // deepest cause (type + message), or null if there is no wrapped cause.
    // Paho wraps low-level failures (IOException, SSLException, EOFException,
    // etc.) inside a generic MqttException(reasonCode=0), so the actual root
    // cause is otherwise hidden from JS consumers.
    private fun describeRootCause(cause: Throwable?): String? {
        if (cause == null) return null
        var current: Throwable = cause
        val seen = mutableSetOf<Throwable>(current)
        while (true) {
            val next = current.cause ?: break
            if (!seen.add(next)) break
            current = next
        }
        if (current === cause) return null
        val message = current.message
        return if (message.isNullOrBlank()) {
            current.javaClass.simpleName
        } else {
            "${current.javaClass.simpleName}: $message"
        }
    }

    // Notifies a given event. The handle is injected into the body so the JS
    // wrapper can dispatch the event only to listeners attached to the
    // corresponding instance.
    private fun notifyEvent(handle: String, eventName: String, params: WritableMap?) {
        Log.d(NAME, "notifying event $eventName for $handle")
        val body = params ?: Arguments.createMap()
        body.putString(HANDLE_KEY, handle)
        this.getReactApplicationContext().emitDeviceEvent(eventName, body)
    }

    // Parameters for connection.
    private class ConnectionParameters(
            val url: String?,
            val host: String?,
            val port: Int?,
            val clientId: String,
            val reconnect: Boolean,
            val username: String? = null,
            val password: String? = null,
            val keepAlive: Int? = null
    ) {
        companion object {
            // Parses a given object from JavaScript.
            fun parseReadableMap(params: ReadableMap): ConnectionParameters {
                val keepAlive = if (params.hasKey("keepAlive")) params.getInt("keepAlive") else null
                require(keepAlive == null || keepAlive in 1..65535) {
                    "keepAlive must be between 1 and 65535 seconds"
                }
                return ConnectionParameters(
                        url = if (params.hasKey("url")) params.getString("url") else null,
                        host = if (params.hasKey("host")) params.getString("host") else null,
                        port = if (params.hasKey("port")) params.getInt("port") else null,
                        clientId = params.getRequiredString("clientId"),
                        reconnect = params.getRequiredBoolean("reconnect"),
                        username = if (params.hasKey("username")) params.getString("username") else null,
                        password = if (params.hasKey("password")) params.getString("password") else null,
                        keepAlive = keepAlive
                )
            }
        }
    }
}

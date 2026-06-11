package com.github.emotokcak.reactnative.mqtt

import android.util.Log
import com.facebook.react.bridge.*
import com.facebook.react.modules.core.DeviceEventManagerModule.RCTDeviceEventEmitter
import info.mqtt.android.service.MqttAndroidClient
import info.mqtt.android.service.MqttTraceHandler
import org.eclipse.paho.client.mqttv3.*
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
 * Powered by [Paho MQTT for Android](https://github.com/eclipse/paho.mqtt.android).
 */
class RNMqttClient(reactContext: ReactApplicationContext)
    : ReactContextBaseJavaModule(reactContext) {
    companion object {
        /** Default alias for a root certificate in a key store. */
        const val DEFAULT_CA_CERT_ALIAS: String = "ca-certificate"

        /** Default alias for a private key in a key store. */
        const val DEFAULT_KEY_ALIAS: String = "private-key"

        private const val NAME: String = "MqttClient"

        private const val PROTOCOL: String = "ssl"

        private const val HANDLE_KEY: String = "__handle"
    }

    // Per-instance state. Keyed by the handle the JS wrapper allocates per
    // `new MqttClient()`.
    private class Session {
        var client: MqttAndroidClient? = null
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

    init {
        reactContext.addLifecycleEventListener(
                object : LifecycleEventListener {
                    override fun onHostResume() {
                        Log.d(NAME, "onHostResume")
                    }

                    override fun onHostPause() {
                        Log.d(NAME, "onHostPause")
                    }

                    override fun onHostDestroy() {
                        Log.d(NAME, "onHostDestroy")
                    }
                }
        )
    }

    override fun onCatalystInstanceDestroy() {
        super.onCatalystInstanceDestroy()
        Log.d(NAME, "onCatalystInstanceDestroy")
        for ((_, session) in this.sessions) {
            val client = session.client ?: continue
            try {
                client.disconnect()
            } catch (e: MqttException) {
                Log.e(NAME, "failed to disconnect", e)
            } catch (e: IllegalArgumentException) {
                Log.e(NAME, "failed to disconnect", e)
            }
            session.client = null
        }
        this.sessions.clear()
    }

    override fun getName(): String = NAME

    /**
     * Sets the identity for connection.
     *
     * Cached in the session identified by `handle`. The persistent
     * Android key store entries are still keyed by the user-supplied
     * `keyStoreOptions` and remain shared across all sessions.
     */
    @ReactMethod
    fun setIdentity(handle: String, params: ReadableMap, promise: Promise) {
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
    @ReactMethod
    fun loadIdentity(handle: String, options: ReadableMap?, promise: Promise) {
        try {
            val session = this.sessionFor(handle)
            session.socketFactory =
                    SSLSocketFactoryUtil.createSocketFactoryFromAndroidKeyStore()
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
        } catch (e: IllegalArgumentException) {
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
     * Resets the identity stored in the key store.
     */
    @ReactMethod
    fun resetIdentity(handle: String, options: ReadableMap?, promise: Promise) {
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
    @ReactMethod
    fun isIdentityStored(handle: String, options: ReadableMap?, promise: Promise) {
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
    @ReactMethod
    fun connect(handle: String, params: ReadableMap, promise: Promise) {
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
            val client = MqttAndroidClient(
                    this.getReactApplicationContext().getBaseContext(),
                    brokerUri,
                    parsedParams.clientId
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
            client.setTraceEnabled(true)
            client.setTraceCallback(object : MqttTraceHandler {
                override fun traceDebug(message: String?) {
                    Log.d("$NAME.trace", "$message")
                }

                override fun traceError(message: String?) {
                    Log.e("$NAME.trace", "$message")
                }

                override fun traceException(
                        message: String?,
                        e: Exception?) {
                    Log.e("$NAME.trace", "$message", e)
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
            Log.d(NAME, "connecting to the broker")
            val token = client.connect(connectOptions)
            token.setActionCallback(object : IMqttActionListener {
                override fun onSuccess(asyncActionToken: IMqttToken) {
                    Log.d(NAME, "connected, token: ${asyncActionToken}")
                    promise.resolve(null)
                }

                override fun onFailure(
                        asyncActionToken: IMqttToken,
                        cause: Throwable?
                ) {
                    Log.e(
                            NAME,
                            "failed to connect, token: ${asyncActionToken}",
                            cause
                    )
                    promise.reject("ERROR_CONNECTION", cause)
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
     */
    @ReactMethod
    fun disconnect(handle: String) {
        // Remove the entry up-front so the cached socketFactory is released
        // along with the client. Reconnecting on the same JS instance
        // therefore requires setIdentity/loadIdentity to be called again for
        // identity-based auth.
        val session = this.sessions.remove(handle)
        if (session == null) {
            Log.w(NAME, "no MQTT connection")
            return
        }
        val client = session.client
        if (client == null) {
            Log.w(NAME, "no MQTT connection")
            return
        }
        try {
            val token = client.disconnect()
            token.setActionCallback(object : IMqttActionListener {
                override fun onSuccess(asyncActionToken: IMqttToken) {
                    Log.d(NAME, "disconnected, token: ${asyncActionToken}")
                    this@RNMqttClient.notifyEvent(handle, "disconnected", null)
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
                    this@RNMqttClient.notifyError(handle, "ERROR_DISCONNECT", cause)
                }
            })
        } catch (e: MqttException) {
            Log.e(NAME, "failed to disconnect", e)
            return
        } catch (e: IllegalArgumentException) {
            // The underlying ClientHandle is already torn down — already
            // disconnected from the service's point of view. The session
            // entry was already removed above, so no further cleanup is
            // needed here.
            Log.w(NAME, "failed to disconnect: invalid client handle")
            return
        }
    }

    /**
     * Publishes given data to a specified topic.
     */
    @ReactMethod
    fun publish(handle: String, topic: String, payload: ReadableArray, promise: Promise) {
        val client = this.sessions[handle]?.client
        if (client == null) {
            Log.w(NAME, "failed to publish. no MQTT connection")
            promise.reject("NO_CONNECTION", Exception("no MQTT connection"))
            return
        }

        try {
            val ints = payload.toArrayList().toArray(Array<Number>(payload.size()) { v -> v.toInt() })
            val bytes = ints.foldIndexed(ByteArray(ints.size)) { i, a, v -> a.apply { set(i, v.toByte()) } }

            val token = client.publish(
                    topic,
                    bytes,
                    1, // qos
                    false // not retained
            )
            token.setActionCallback(object : IMqttActionListener {
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
                    this@RNMqttClient.notifyError(handle, "ERROR_PUBLISH", cause)
                    promise.reject("ERROR_PUBLISH", cause)
                }
            })
        } catch (e: MqttException) {
            Log.e(NAME, "failed to publish to ${topic}", e)
            promise.reject("ERROR_PUBLISH", e)
            return
        } catch (e: IllegalArgumentException) {
            // The underlying ClientHandle has been torn down (e.g. after
            // disconnect). Per the docstring above, publish does nothing
            // when there is no MQTT connection.
            Log.w(NAME, "failed to publish to $topic: invalid client handle")
            promise.resolve(null)
            return
        }
    }

    /**
     * Subscribes a specified topic.
     */
    @ReactMethod
    fun subscribe(handle: String, topic: String, promise: Promise) {
        val client = this.sessions[handle]?.client
        if (client == null) {
            promise.reject("NO_CONNECTION", Exception("no MQTT connection"))
            return
        }
        try {
            val token = client.subscribe(
                    topic,
                    1 // qos
            )
            token.setActionCallback(object : IMqttActionListener {
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
                    this@RNMqttClient.notifyError(handle, "ERROR_SUBSCRIBE", cause)
                    // TODO: iOS may not be able to reject this case
                    promise.reject("ERROR_SUBSCRIBE", cause)
                }
            })
        } catch (e: MqttException) {
            Log.e(NAME, "failed to subscribe '$topic'", e)
            promise.reject("ERROR_SUBSCRIBE", e)
            return
        } catch (e: IllegalArgumentException) {
            // The underlying ClientHandle has been torn down (e.g. after
            // disconnect). Treat as "no MQTT connection" — same semantics
            // as the null-client branch above.
            Log.w(NAME, "failed to subscribe '$topic': invalid client handle")
            promise.reject("NO_CONNECTION", Exception("no MQTT connection"))
            return
        }
    }

    /**
     * Determines if this client is currently connected to the server.
     */
    @ReactMethod
    fun isConnected(handle: String, promise: Promise) {
        val client = this.sessions[handle]?.client
        if (client == null) {
            promise.resolve(false)
            return
        }
        try {
            val isClientConnected = client.isConnected
            promise.resolve(isClientConnected)
        } catch (e: IllegalArgumentException) {
            // The underlying MQTT service has already torn down the
            // ClientHandle (e.g. after disconnect). Treat as disconnected.
            promise.resolve(false)
        } catch (e: Exception) {
            Log.e(NAME, "failed to check connection", e)
            promise.reject("ERROR_CHECK_CONNECTION", e)
            return
        }
    }

    // Notifies a `got-error` event.
    private fun notifyError(handle: String, code: String, cause: Throwable?) {
        val params = Arguments.createMap()
        params.putString("code", code)
        params.putString("message", cause?.message ?: "")
        this.notifyEvent(handle, "got-error", params)
    }

    // Notifies a given event. The handle is injected into the body so the JS
    // wrapper can dispatch the event only to listeners attached to the
    // corresponding instance.
    private fun notifyEvent(handle: String, eventName: String, params: WritableMap?) {
        Log.d(NAME, "notifying event $eventName for $handle")
        val body = params ?: Arguments.createMap()
        body.putString(HANDLE_KEY, handle)
        this.getReactApplicationContext()
                .getJSModule(RCTDeviceEventEmitter::class.java)
                .emit(eventName, body)
    }

    // Parameters for connection.
    private class ConnectionParameters(
            val url: String?,
            val host: String?,
            val port: Int?,
            val clientId: String,
            val reconnect: Boolean,
            val username: String? = null,
            val password: String? = null
    ) {
        companion object {
            // Parses a given object from JavaScript.
            fun parseReadableMap(params: ReadableMap): ConnectionParameters {
                return ConnectionParameters(
                        url = if (params.hasKey("url")) params.getString("url") else null,
                        host = if (params.hasKey("host")) params.getString("host") else null,
                        port = if (params.hasKey("port")) params.getInt("port") else null,
                        clientId = params.getRequiredString("clientId"),
                        reconnect = params.getRequiredBoolean("reconnect"),
                        username = if (params.hasKey("username")) params.getString("username") else null,
                        password = if (params.hasKey("password")) params.getString("password") else null
                )
            }
        }
    }
}

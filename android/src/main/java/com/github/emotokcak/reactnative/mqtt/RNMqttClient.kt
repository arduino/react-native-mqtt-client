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
 * Can connect to only one MQTT broker at the same time, so far.
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
    }

    private var socketFactory: SSLSocketFactory? = null

    private var client: MqttAndroidClient? = null

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
        try {
            this.disconnect()
        } catch (e: MqttException) {
            Log.e(NAME, "failed to disconnect", e)
        } catch (e: IllegalArgumentException) {
            Log.e(NAME, "failed to disconnect", e)
        }
    }

    override fun getName(): String = NAME

    /**
     * Sets the identity for connection.
     *
     * The following key-value pairs have to be specified in `params`.
     * - `caCertPem`: {`String`} PEM representation of a root CA certificate.
     * - `certPem`: {`String`} PEM representation of a certificate.
     * - `keyTag`: {`String`} key tag of the private key in Keystore.
     * - `keyStoreOptions`: {`ReadableMap`} options for a key store.
     *   May have the following optional key-value pairs,
     *     - `caCertAlias`: {`String`} alias for a root certificate.
     *       `DEFAULT_CA_CERT_ALIAS` if omitted.
     *
     * If there is already connection to an MQTT broker, this new identity
     * won't affect it.
     *
     * @param params
     *
     *   Parameters constituting an identity.
     *
     * @param promise
     *
     *   Promise that is resolved when the identity is set.
     */
    @ReactMethod
    fun setIdentity(params: ReadableMap, promise: Promise) {
        try {
            val keyStoreOptions: ReadableMap? =
                    params.getOptionalMap("keyStoreOptions")
            this.socketFactory = SSLSocketFactoryUtil.createSocketFactory(
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
     *
     * `options` may have the following optional key-value pairs,
     * - `caCertAlias`: (`string`)
     *   Alias associated with a root certificate to be loaded.
     *   `DEFAULT_CA_CERT_ALIAS` if omitted.
     * - `keyAlias`: (`string`)
     *   Alias associated with a private key to be loaded.
     *   `DEFAULT_KEY_ALIAS` if omitted.
     *
     * @param options
     *
     *   Options for the key store.
     *   May be omitted.
     *
     * @param promise
     *
     *   Promise that is resolved when the identity is loaded.
     */
    @ReactMethod
    fun loadIdentity(options: ReadableMap?, promise: Promise) {
        try {
            this.socketFactory =
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
     *
     * `options` may have the following optional key-value pairs,
     * - `caCertAlias`: (`string`)
     *   alias associated with a root certificate to be cleared.
     *   `DEFAULT_CA_CERT_ALIAS` if omitted.
     * - `keyAlias`: (`string`)
     *   alias associated with a private key to be cleared.
     *   `DEFAULT_KEY_ALIAS` if omitted.
     *
     * @param options
     *
     *   Options for the key store.
     *   May be omitted.
     *
     * @param promise
     *
     *   Promise that is resolved when the identity is reset.
     */
    @ReactMethod
    fun resetIdentity(options: ReadableMap?, promise: Promise) {
        try {
            SSLSocketFactoryUtil.resetAndroidKeyStore(
                    options?.getOptionalString("caCertAlias") ?: DEFAULT_CA_CERT_ALIAS,
                    options?.getOptionalString("keyAlias") ?: DEFAULT_KEY_ALIAS
            )
            this.socketFactory = null
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
     *
     * `options` may have the following optional key-value pairs,
     * - `ceCertAlias`: (`string`)
     *   alias associated with a root certificate.
     *   `DEFAULT_CA_CERT_ALIAS` if omitted.
     * - `keyAlias`: (`string`)
     *   alias associated with a private key.
     *   `DEFAULT_KEY_ALIAS` if omitted.
     *
     * @param options
     *
     *   Options for the identity key store.
     *   May be omitted.
     *
     * @param promise
     *
     *   Promise that is resolved to whether the identity given by `options`
     *   is stored in the Android key store.
     */
    @ReactMethod
    fun isIdentityStored(options: ReadableMap?, promise: Promise) {
        try {
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
     *
     * The following key-value pairs have to be specified in `params`:
     * - `clientId`: {`String`} Client ID of the device.
     * - For identity-based connection:
     *   - `host`: {`String`} Host name of the MQTT broker.
     *   - `port`: {`int`} Port of the MQTT broker.
     * - For credentials-based connection:
     *   - `url`: {`String`} Broker URL.
     *   - `username`: {`String`} Username for authentication.
     *   - `password`: {`String`} Password for authentication.
     * - `reconnect`: {`Boolean`} Reconnect if connection is lost.
     *
     * @param params
     *
     *   Parameters for connection.
     *   Please see above.
     *
     * @param promise
     *
     *   Resolved when connection has been established.
     */
    @ReactMethod
    fun connect(params: ReadableMap, promise: Promise) {
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
                this.socketFactory ?: run {
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
            this.client = client
            client.setCallback(object : MqttCallbackExtended {
                override fun connectComplete(
                        reconnect: Boolean,
                        serverURI: String
                ) {
                    Log.d(NAME, "connectComplete")
                    this@RNMqttClient.notifyEvent("connected", null)
                }

                override fun connectionLost(cause: Throwable?) {
                    Log.d(NAME, "connectionLost", cause)
                    this@RNMqttClient.notifyError("ERROR_CONNECTION", cause)
                    if (!parsedParams.reconnect) {
                        this@RNMqttClient.notifyEvent("disconnected", null)
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
                    this@RNMqttClient.notifyEvent("received-message", arg)
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
     *
     * Does nothing if there is no MQTT connection.
     */
    @ReactMethod
    fun disconnect() {
        val client = this.client
        if (client == null) {
            Log.w(NAME, "no MQTT connection")
            return
        }
        try {
            val token = client.disconnect()
            token.setActionCallback(object : IMqttActionListener {
                override fun onSuccess(asyncActionToken: IMqttToken) {
                    Log.d(NAME, "disconnected, token: ${asyncActionToken}")
                    this@RNMqttClient.client = null
                    this@RNMqttClient.notifyEvent("disconnected", null)
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
                    this@RNMqttClient.notifyError("ERROR_DISCONNECT", cause)
                }
            })
        } catch (e: MqttException) {
            Log.e(NAME, "failed to disconnect", e)
            return
        } catch (e: IllegalArgumentException) {
            // maybe Invalid ClientHandle
            Log.e(NAME, "failed to disconnect", e)
            return
        }
    }

    /**
     * Publishes given data to a specified topic.
     *
     * Does nothing if there is no MQTT connection.
     *
     * @param topic
     *
     *   Topic where to publish `payload`.
     *
     * @param payload
     *
     *   Payload to be published.
     *
     * @param promise
     *
     *   Resolved when publishing has finished.
     */
    @ReactMethod
    fun publish(topic: String, payload: ReadableArray, promise: Promise) {
        val client = this.client
        if (client == null) {
            Log.w(NAME, "failed to publish. no MQTT connection")
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
                    this@RNMqttClient.notifyError("ERROR_PUBLISH", cause)
                    promise.reject("ERROR_PUBLISH", cause)
                }
            })
        } catch (e: MqttException) {
            Log.e(NAME, "failed to publish to ${topic}", e)
            promise.reject("ERROR_PUBLISH", e)
            return
        } catch (e: IllegalArgumentException) {
            // maybe Invalid ClientHandle
            Log.e(NAME, "failed to publish to ${topic}", e)
            promise.reject("ERROR_PUBLISH", e)
            return
        }
    }

    /**
     * Subscribes a specified topic.
     *
     * @param topic
     *
     *   Topic to subscribe.
     *
     * @param promise
     *
     *   Resolved when subscription has done.
     */
    @ReactMethod
    fun subscribe(topic: String, promise: Promise) {
        val client = this.client
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
                    this@RNMqttClient.notifyError("ERROR_SUBSCRIBE", cause)
                    // TODO: iOS may not be able to reject this case
                    promise.reject("ERROR_SUBSCRIBE", cause)
                }
            })
        } catch (e: MqttException) {
            Log.e(NAME, "failed to subscribe '$topic'", e)
            promise.reject("ERROR_SUBSCRIBE", e)
            return
        } catch (e: IllegalArgumentException) {
            // maybe Invalid ClientHandle
            Log.e(NAME, "failed to subscribe '$topic'", e)
            promise.reject("ERROR_SUBSCRIBE", e)
            return
        }
    }

    /**
     * Determines if this client is currently connected to the server.
     * Returns: true if connected, false otherwise.
     *
     * @param promise
     *
     *   Resolved when check connection has done.
     */
    @ReactMethod
    fun isConnected(promise: Promise) {
        val client = this.client
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

    // Notifies a `got-error` event.
    private fun notifyError(code: String, cause: Throwable?) {
        val params = Arguments.createMap()
        params.putString("code", code)
        params.putString("message", cause?.message ?: "")
        this.notifyEvent("got-error", params)
    }

    // Notifies a given event.
    private fun notifyEvent(eventName: String, params: Any?) {
        Log.d(NAME, "notifying event $eventName")
        this.getReactApplicationContext()
                .getJSModule(RCTDeviceEventEmitter::class.java)
                .emit(eventName, params)
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


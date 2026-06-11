import {
  EmitterSubscription,
  NativeEventEmitter,
  NativeModules,
} from 'react-native';

const {MqttClient: MqttNativeModule} = NativeModules;

const eventBridge = new NativeEventEmitter(MqttNativeModule);

const HANDLE_KEY = '__handle';

const SUPPORTED_EVENTS = [
  'connected',
  'disconnected',
  'received-message',
  'got-error',
] as const;

type SupportedEvent = (typeof SUPPORTED_EVENTS)[number];

let handleCounter = 0;

function allocateHandle(): string {
  handleCounter += 1;
  return `mqtt-${handleCounter}-${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * MQTT client.
 *
 * Each instance of `MqttClient` owns an independent native session: two
 * instances can connect to different brokers at the same time, and
 * disconnecting one does not affect the other. The default export
 * (`import MqttClient from '@arduino/react-native-mqtt-client'`) is a
 * back-compat singleton — one instance among many, not the only one.
 *
 * #### Events
 *
 * Emits the following events.
 * - `"connected"`
 * - `"disconnected"`
 * - `"got-error"`
 * - `"received-message"`
 *
 * Listeners added with `addListener` are scoped to the instance they were
 * called on.
 *
 * ##### connected
 *
 * Notified when connection to an MQTT broker has been established.
 *
 * No arguments.
 *
 * ##### disconnected
 *
 * Notified when the client is disconnected from the MQTT broker.
 *
 * No arguments.
 *
 * ##### received-message
 *
 * Notified when the client has received a message from the MQTT broker.
 *
 * The argument is an object which has the following fields,
 * - `topic`: {`string`} topic of the received message.
 * - `payload`: {`number[]`} payload of the received message.
 *
 * ##### got-error
 *
 * Notified when an error has occurred.
 *
 * The argument is an object that has the following fields,
 * - `code`: {`string`} error code.
 * - `message`: {`string`} explanation of the error.
 *
 * @class MqttClient
 */
export class MqttClient {
  private readonly _handle: string;

  constructor() {
    this._handle = allocateHandle();
  }

  /**
   * Sets the identity for connection.
   *
   * Certificates and a key constituting the identity is stored in a device
   * specific keystore.
   *
   * @function setIdentity
   *
   * @param params
   *
   *   Parameters constituting an identity.
   *
   * @return Promise<void>
   *
   *   Resolved when the identity is set.
   */
  setIdentity(params: IdentityParameters): Promise<void> {
    return MqttNativeModule.setIdentity(this._handle, params);
  }

  /**
   * Loads the identity stored in a device specific key store.
   *
   * @function loadIdentity
   *
   * @param options
   *
   *   Options for the identity key store.
   *
   * @return Promise<void>
   *
   *   Resolved when the identity is loaded.
   */
  loadIdentity(options?: KeyStoreOptions): Promise<void> {
    return MqttNativeModule.loadIdentity(this._handle, options ?? null);
  }

  /**
   * Resets the identity for connection.
   *
   * Certificates and a key stored in a device specific key store are cleared.
   *
   * @function resetIdentity
   *
   * @param options
   *
   *   Options for the identity key store.
   *
   * @return Promise<void>
   *
   *   Resolved when the identity is reset.
   */
  resetIdentity(options?: KeyStoreOptions): Promise<void> {
    return MqttNativeModule.resetIdentity(this._handle, options ?? null);
  }

  /**
   * Returns whether an identity for connection is stored in a device specific
   * key store.
   *
   * @function isIdentityStored
   *
   * @param options
   *
   *   Options for the identity key store.
   *
   * @return Promise<boolean>
   *
   *   Resolved to whether the identity given by `options` is stored in
   *   a device specific key store.
   */
  isIdentityStored(options?: KeyStoreOptions): Promise<boolean> {
    return MqttNativeModule.isIdentityStored(this._handle, options ?? null);
  }

  /**
   * Connects to an MQTT broker.
   *
   * @function connect
   *
   * @param params
   *
   * @return Promise<void>
   *
   *   Resolved when connection has been established.
   */
  connect(params: ConnectionParameters): Promise<void> {
    return MqttNativeModule.connect(this._handle, params);
  }

  /**
   * Disconnects from the MQTT broker and releases the native session held
   * by this instance, including any cached identity material. To reconnect
   * on the same instance with identity-based auth, call `setIdentity` or
   * `loadIdentity` again before `connect`.
   *
   * @function disconnect
   */
  disconnect() {
    MqttNativeModule.disconnect(this._handle);
  }

  /**
   * Publishes a given payload to a specified topic.
   *
   * @function publish
   *
   * @param topic
   *
   * @param payload
   *
   * @return Promise<void>
   *
   *   Resolved when publishing has finished.
   */
  publish(topic: string, payload: number[]): Promise<void> {
    return MqttNativeModule.publish(this._handle, topic, payload);
  }

  /**
   * Subscribes a specified topic.
   *
   * @function subscribe
   *
   * @param topic
   *
   *   Topic to subscribe.
   *
   * @return {Promise<void>}
   *
   *   Resolved when subscription has done.
   */
  subscribe(topic: string): Promise<void> {
    return MqttNativeModule.subscribe(this._handle, topic);
  }

  /**
   * Determines if this client is currently connected to the server
   *
   * @function isConnected
   *
   * @return {Promise<boolean>}
   *
   *   Resolved when check connection has done.
   */
  isConnected(): Promise<boolean> {
    return MqttNativeModule.isConnected(this._handle);
  }

  /**
   * Listens for a given event from this client.
   *
   * The listener only receives events for the instance it was registered on.
   *
   * @function addListener
   */
  addListener(eventName: SupportedEvent | string, listener: ListenerFunction) {
    const handle = this._handle;
    return eventBridge.addListener(eventName, (body: any) => {
      if (body == null || body[HANDLE_KEY] !== handle) return;
      // Strip the internal __handle field before forwarding to the user's
      // listener, then preserve the original calling convention: events that
      // historically had no argument (connected/disconnected) keep doing so.
      const rest: {[key: string]: any} = {};
      let hasOther = false;
      for (const k of Object.keys(body)) {
        if (k === HANDLE_KEY) continue;
        rest[k] = body[k];
        hasOther = true;
      }
      if (hasOther) {
        listener(rest);
      } else {
        listener();
      }
    });
  }

  /**
   * Unlistens for a given event from this client.
   *
   * @function removeListener
   */
  removeListener(subscription: EmitterSubscription) {
    subscription.remove();
  }
}

/**
 * Listener function.
 */
type ListenerFunction = (...args: any[]) => void;

/**
 * Parameters constituting an identity.
 *
 * @interface IdentityParameters
 */
export type IdentityParameters = {
  /**
   * PEM representating of a CA certificate.
   *
   * @member {string} caCertPem
   */
  caCertPem: string;
  /**
   * PEM representation of a certificate.
   *
   * @member {string} certPem
   */
  certPem: string;
  /**
   * key tag of the private key in Keystore.
   *
   * @member {string} keyTag
   */
  keyTag: string;
  /**
   * Options for an identity key store.
   *
   * @member {KeyStoreOptions} keyStoreOptions
   */
  keyStoreOptions?: KeyStoreOptions;
};

/**
 * Options for an identity key store.
 */
export type KeyStoreOptions = {
  /**
   * Alias for a root certificate (Android only).
   *
   * A default value is used if omitted.
   *
   * @member {string} caCertTag
   */
  caCertAlias?: string;
  /**
   * Alias for a private key (Android only).
   *
   * A default value is used if omitted.
   *
   * @member {string} keyTag
   */
  keyAlias?: string;
  /**
   * Label associated with a certificate (iOS only).
   *
   * A default value is used if omitted.
   *
   * @member {string} caCertLabel
   */
  caCertLabel?: string;
  /**
   * Label associated with a certificate (iOS only).
   *
   * A default value is used if omitted.
   *
   * @member {string} certLabel
   */
  certLabel?: string;
  /**
   * Application tag associated with a private key (iOS only).
   *
   * A default value is used if omitted.
   *
   * @member {string} keyApplicationTag
   */
  keyApplicationTag?: string;
};

/**
 * Common parameters for MQTT broker connection.
 */
export type BaseConnectionParameters = {
  clientId: string;
  reconnect: boolean;
};

/**
 * Parameters for identity-based connection to an MQTT broker.
 */
export type IdentityBasedConnectionParameters = BaseConnectionParameters & {
  host: string;
  port: number;
};

/**
 * Parameters for credentials-based connection to an MQTT broker.
 */
export type CredentialsBasedConnectionParameters = BaseConnectionParameters & {
  url: string;
  username: string;
  password: string;
};

/**
 * Parameters for connection to an MQTT broker.
 *
 * Either identity-based (using host and port with a configured identity)
 * or credentials-based (using url with username and password).
 */
export type ConnectionParameters =
  | IdentityBasedConnectionParameters
  | CredentialsBasedConnectionParameters;

const defaultInstance = new MqttClient();

export default defaultInstance;

# react-native-mqtt-client

MQTT client for React Native application.

## Features

- Secure MQTT connection over TLS 1.2.
- Authentication of both of server and client by X.509 certificates.
- Certificates and a private key stored in a device specific key store.
  - [Android KeyStore](https://developer.android.com/training/articles/keystore#UsingAndroidKeyStore) on Android
  - [Default keychain](https://developer.apple.com/documentation/security/keychain_services/keychains) on iOS

## Dependencies

This library wraps the following libraries,

- [Paho MQTT Client for Android variant maintained by hannesa2](https://github.com/hannesa2/paho.mqtt.android) (Android)

  This library is forked as [emoto-kc-ak/paho.mqtt.android](https://github.com/emoto-kc-ak/paho.mqtt.android) to make Maven artifacts.

- [CocoaMQTT](https://github.com/emqx/CocoaMQTT) (iOS)

## Installation

```sh
npm install @arduino/react-native-mqtt-client
```

or

```sh
yarn add @arduino/react-native-mqtt-client
```

## Usage

```js
import MqttClient from '@arduino/react-native-mqtt-client';
```

The default export is a back-compat singleton. To run multiple independent
MQTT connections from the same app (different brokers or different
credentials), construct your own instances — each one owns its own native
client, its own connection lifecycle, and only delivers events to listeners
registered on it:

```js
import {MqttClient} from '@arduino/react-native-mqtt-client';

const dashboard = new MqttClient();
const device = new MqttClient();
// dashboard.disconnect() does not affect `device`, and vice versa.
```

### Configuring an identity

You have to configure an identity before connecting to an MQTT broker.
`MqttClient.setIdentity` configures an identity to communicate with an MQTT broker.
Certificates and a private key are stored in a device specific key store.

```js
MqttClient.setIdentity({
  caCertPem: IOT_CA_CERT, // PEM representation string of a root certificate
  certPem: IOT_CERT, // PEM representation string of a client certificate
  keyTag: IOT_KEY, // key tag of the private key in Keystore/Keychain
  keyStoreOptions, // options for a device specific key store. may be omitted
})
  .then(() => {
    /* handle success */
  })
  .catch(({code, message}) => {
    /* handle error */
  });
```

`keyStoreOptions` is an optional object that may have the following fields,

- `caCertAlias`: (string) Alias associated with a root certificate (Android only). See [`KeyStore.setCertificateEntry`](<https://developer.android.com/reference/java/security/KeyStore#setCertificateEntry(java.lang.String,%20java.security.cert.Certificate)>)
- `keyAlias`: (string) Alias associated with a private key (Android only). See [`KeyStore.setKeyEntry`](<https://developer.android.com/reference/java/security/KeyStore#setKeyEntry(java.lang.String,%20java.security.Key,%20char[],%20java.security.cert.Certificate[])>)
- `caCertLabel`: (string) Label associated with a root certificate (iOS only). See [`kSecAttrLabel`](https://developer.apple.com/documentation/security/ksecattrlabel)
- `certLabel`: (string) Label associated with a client certificate (iOS only). See [`kSecAttrLabel`](https://developer.apple.com/documentation/security/ksecattrlabel)
- `keyApplicationTag`: (string) Tag associated with a private key (iOS only). See [`kSecAttrApplicationTag`](https://developer.apple.com/documentation/security/ksecattrapplicationtag)

### Connecting to an MQTT broker

`MqttClient.connect` connects to an MQTT broker.

```js
MqttClient.connect({
  host: IOT_ENDPOINT, // (string) Host name of an MQTT broker to connect.
  port: IOT_PORT, // (number) Port to connect.
  clientId: IOT_DEVICE_ID, // (string) Client ID of a device connecting.
})
  .then(() => {
    /* handle success */
  })
  .catch(({code, message}) => {
    /* handle error */
  });
```

It attempts to connect to `ssl://$IOT_ENDPOINT:$IOT_PORT`.

### Publishing a message

`MqttClient.publish` publishes a message to an MQTT broker.

```js
MqttClient.publish(topic, payload)
  .then(() => {
    /* handle success */
  })
  .catch(({code, message}) => {
    /* handle error */
  });
```

Where,

- `topic`: (string) Topic where `payload` is to be published.
- `payload`: (string) Payload to be published. Usually a stringified JSON object.

### Subscribing a topic

`MqttClient.subscribe` subscribes a topic of an MQTT broker.

```js
MqttClient.subscribe(topic)
  .then(() => {
    /* handle success */
  })
  .catch(({code, message}) => {
    /* handle error */
  });
```

Where,

- `topic`: (string) Topic to subscribe.

To handle messages in the subscribed topic, you have to handle a [`receive-message` event](#received-message).

### Disconnecting from an MQTT broker

`MqttClient.disconnect` disconnects from an MQTT broker.

```js
MqttClient.disconnect();
```

### Check if client is connected to an MQTT Broker

`MqttClient.isConnected` checks if client is connected to an MQTT Broker.

```js
MqttClient.isConnected();
```

### Loading an identity

An identity stored in a device specific key store by `MqttClient.setIdentity` may be loaded by `MqttClient.loadIdentity`.

```js
MqttClient.loadIdentity(keyStoreOptions)
  .then(() => {
    /* handle success */
  })
  .catch(({code, message}) => {
    /* handle error */
  });
```

Please refer to [Configuring an identity](#configuring-an-identity) for details of `keyStoreOptions`.

### Clearing an identity

An identity stored in a device specific key store by `MqttClient.setIdentity` may be cleared by `MqttClient.resetIdentity`.

```js
MqttClient.resetIdentity(keyStoreOptions)
  .then(() => {
    /* handle success */
  })
  .catch(({code, message}) => {
    /* handle error */
  });
```

Please refer to [Configuring an identity](#configuring-an-identity) for details of `keyStoreOptions`.

### Testing if an identity is stored in a key store

`MqttClient.isIdentityStored` tests if an identity is stored in a device-specific key store.

```js
MqttClient.isIdentityStored(keyStoreOptions)
  .then(isStored => {
    /* handle success */
  })
  .catch(({code, message}) => {
    /* handle error */
  });
```

Where,

- `isStored`: (boolean) Whether an identity is stored in a device-specific key store.

Please refer to [Configuring an identity](#configuring-an-identity) for details of `keyStoreOptions`.

### Handling events

`MqttClient` emits events when its state is changed, a message is arrived, and an error has occurred.

#### connected

A `connected` event is notified when connection to an MQTT broker is established.

```js
MqttClient.addListener('connected', () => {
  /* handle connection */
});
```

#### disconnected

A `disconnected` event is notified when connection to an MQTT broker is disconnected.

```js
MqttClient.addListener('disconnected', () => {
  /* handle disconnection */
});
```

#### received-message

A `received-message` event is notified when a message is arrived from an MQTT broker.

```js
MqttClient.addListener('received-message', ({topic, payload}) => {
  /* handle message */
});
```

Where,

- `topic`: (string) Topic where a message has been published.
- `payload`: (number[]) Payload of a message.

#### got-error

A `got-error` event is notified when an error has occurred.

```js
MqttClient.addListener('got-error', err => {
  /* handle error */
});
```

## iOS Tips

### Solving pod install error

You may face an error similar to the following, when you run `pod install`.

```
[!] The following Swift pods cannot yet be integrated as static libraries:

The Swift pod `CocoaMQTT` depends upon `CocoaAsyncSocket`, which does not define modules. To opt into those targets generating module maps (which is necessary to import them from Swift when building as static libraries), you may set `use_modular_headers!` globally in your Podfile, or specify `:modular_headers => true` for particular dependencies.
```

In my case (React Native v0.63.3, CocoaPod v1.9.3), this error was solved by adding the following line to the `Podfile` of my application.

```
pod 'CocoaAsyncSocket', :modular_headers => true
```

## Developing

### Packaging

To package this library, please run the following command.

```sh
npm run prepare
```

Artifacts will be updated in the following directories,

- `lib/commonjs`
- `lib/module`
- `lib/typescript`

## Example

Sorry, the `example` directory is not maintained so far.

## License

MIT

## Acknowlegement

This project is bootstrapped with [callstack/react-native-builder-bob](https://github.com/callstack/react-native-builder-bob).

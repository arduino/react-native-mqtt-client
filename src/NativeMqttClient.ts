import type {CodegenTypes, TurboModule} from 'react-native';
import {TurboModuleRegistry} from 'react-native';

/**
 * Codegen spec of the native module.
 *
 * Every method but `addListener`/`removeListeners` takes the handle of the
 * JS-side `MqttClient` instance the call belongs to. Parameter objects are
 * typed in `index.tsx`; the native side reads them as plain maps.
 */
export interface Spec extends TurboModule {
  setIdentity(handle: string, params: CodegenTypes.UnsafeObject): Promise<void>;
  loadIdentity(
    handle: string,
    options: CodegenTypes.UnsafeObject | null,
  ): Promise<void>;
  resetIdentity(
    handle: string,
    options: CodegenTypes.UnsafeObject | null,
  ): Promise<void>;
  isIdentityStored(
    handle: string,
    options: CodegenTypes.UnsafeObject | null,
  ): Promise<boolean>;
  connect(handle: string, params: CodegenTypes.UnsafeObject): Promise<void>;
  isConnected(handle: string): Promise<boolean>;
  disconnect(handle: string): Promise<void>;
  publish(handle: string, topic: string, payload: number[]): Promise<void>;
  subscribe(handle: string, topic: string): Promise<void>;
  generateCSR(commonName: string, keyTag: string): Promise<string>;
  deleteIdentities(prefixes: string[], keep: string[]): Promise<number>;

  // Required by NativeEventEmitter.
  addListener(eventName: string): void;
  removeListeners(count: number): void;
}

export default TurboModuleRegistry.getEnforcing<Spec>('MqttClient');

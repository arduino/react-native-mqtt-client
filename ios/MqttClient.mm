#import <React/RCTEventEmitter.h>
#import <RNMqttClientSpec/RNMqttClientSpec.h>

#if __has_include(<react_native_mqtt_client/react_native_mqtt_client-Swift.h>)
#import <react_native_mqtt_client/react_native_mqtt_client-Swift.h>
#else
#import "react_native_mqtt_client-Swift.h"
#endif

// Declared here rather than in a header: the codegen header is C++, and every
// public header of the pod ends up in the umbrella header Swift imports.
@interface MqttClient : RCTEventEmitter <NativeMqttClientSpec>
@end

@implementation MqttClient {
  MqttClientImpl *_impl;
  BOOL _hasListeners;
}

RCT_EXPORT_MODULE()

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

- (instancetype)init
{
  if (self = [super init]) {
    _impl = [MqttClientImpl new];
    __weak MqttClient *weakSelf = self;
    _impl.emit = ^(NSString *eventName, NSDictionary<NSString *, id> *body) {
      MqttClient *strongSelf = weakSelf;
      if (strongSelf != nil && strongSelf->_hasListeners) {
        [strongSelf sendEventWithName:eventName body:body];
      }
    };
  }
  return self;
}

- (NSArray<NSString *> *)supportedEvents
{
  return @[ @"connected", @"disconnected", @"received-message", @"got-error" ];
}

- (void)startObserving
{
  _hasListeners = YES;
}

- (void)stopObserving
{
  _hasListeners = NO;
}

- (void)invalidate
{
  [_impl invalidate];
  [super invalidate];
}

- (void)setIdentity:(NSString *)handle
             params:(NSDictionary *)params
            resolve:(RCTPromiseResolveBlock)resolve
             reject:(RCTPromiseRejectBlock)reject
{
  [_impl setIdentity:handle params:params resolve:resolve reject:reject];
}

- (void)loadIdentity:(NSString *)handle
             options:(NSDictionary *)options
             resolve:(RCTPromiseResolveBlock)resolve
              reject:(RCTPromiseRejectBlock)reject
{
  [_impl loadIdentity:handle options:options resolve:resolve reject:reject];
}

- (void)resetIdentity:(NSString *)handle
              options:(NSDictionary *)options
              resolve:(RCTPromiseResolveBlock)resolve
               reject:(RCTPromiseRejectBlock)reject
{
  [_impl resetIdentity:handle options:options resolve:resolve reject:reject];
}

- (void)isIdentityStored:(NSString *)handle
                 options:(NSDictionary *)options
                 resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject
{
  [_impl isIdentityStored:handle options:options resolve:resolve reject:reject];
}

- (void)connect:(NSString *)handle
         params:(NSDictionary *)params
        resolve:(RCTPromiseResolveBlock)resolve
         reject:(RCTPromiseRejectBlock)reject
{
  [_impl connect:handle params:params resolve:resolve reject:reject];
}

- (void)isConnected:(NSString *)handle
            resolve:(RCTPromiseResolveBlock)resolve
             reject:(RCTPromiseRejectBlock)reject
{
  [_impl isConnected:handle resolve:resolve reject:reject];
}

- (void)disconnect:(NSString *)handle
           resolve:(RCTPromiseResolveBlock)resolve
            reject:(RCTPromiseRejectBlock)reject
{
  [_impl disconnect:handle resolve:resolve reject:reject];
}

- (void)publish:(NSString *)handle
          topic:(NSString *)topic
        payload:(NSArray *)payload
        resolve:(RCTPromiseResolveBlock)resolve
         reject:(RCTPromiseRejectBlock)reject
{
  [_impl publish:handle topic:topic payload:payload resolve:resolve reject:reject];
}

- (void)subscribe:(NSString *)handle
            topic:(NSString *)topic
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject
{
  [_impl subscribe:handle topic:topic resolve:resolve reject:reject];
}

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
  return std::make_shared<facebook::react::NativeMqttClientSpecJSI>(params);
}

@end

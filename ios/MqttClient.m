#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(MqttClient, NSObject)

RCT_EXTERN_METHOD(setIdentity:(NSString*)handle params:(NSDictionary*)params resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(loadIdentity:(NSString*)handle options:(NSDictionary*)options resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(resetIdentity:(NSString*)handle options:(NSDictionary*)options resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(isIdentityStored:(NSString*)handle options:(NSDictionary*)options resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(connect:(NSString*)handle params:(NSDictionary*)params resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(isConnected:(NSString*)handle resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(disconnect:(NSString*)handle)

RCT_EXTERN_METHOD(publish:(NSString*)handle topic:(NSString*)topic payload:(NSArray*)payload resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(subscribe:(NSString*)handle topic:(NSString*)topic resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)

@end

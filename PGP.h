//
//  NetPGP.h
//  PGP Demo
//
//  Created by James Knight on 6/9/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>

FOUNDATION_EXPORT NSString *const PGPOptionKeyType;
FOUNDATION_EXPORT NSString *const PGPOptionNumBits;
FOUNDATION_EXPORT NSString *const PGPOptionUserId;
FOUNDATION_EXPORT NSString *const PGPOptionUnlocked;

FOUNDATION_EXPORT NSString *const PGPPubringFilename;
FOUNDATION_EXPORT NSString *const PGPSecringFilename;

typedef NS_ENUM(NSUInteger, PGPMode) {
    PGPModeGenerate,
    PGPModeEncrypt,
    PGPModeDecrypt,
    PGPModeSign,
    PGPModeVerify
};

#pragma mark - PGP interface

@interface PGP : NSObject

#pragma mark Constructors

+ (instancetype)keyGenerator;
+ (instancetype)decryptorWithPrivateKey:(NSString *)armoredPrivateKey;
+ (instancetype)encryptorWithUserId:(NSString *)userId;
+ (instancetype)signerWithPrivateKey:(NSString *)armoredPrivateKey userId:(NSString *)userId;
+ (instancetype)verifier;

#pragma mark - Methods

- (void)generateKeysWithOptions:(NSDictionary *)options
                completionBlock:(void(^)(NSString *publicKeyArmored, NSString *privateKeyArmored))completionBlock
                     errorBlock:(void(^)(NSError *error))errorBlock;

- (void)decryptData:(NSData *)data
    completionBlock:(void(^)(NSData *result))completionBlock
         errorBlock:(void(^)(NSError *error))errorBlock;

- (void)encryptData:(NSData *)data
          publicKey:(NSString *)publicKey
    completionBlock:(void(^)(NSData *result))completionBlock
         errorBlock:(void(^)(NSError *error))errorBlock;

- (void)signData:(NSData *)data
       publicKey:(NSString *)publicKey
 completionBlock:(void(^)(NSData *result))completionBlock
      errorBlock:(void(^)(NSError *error))errorBlock;

- (void)verifyData:(NSData *)data
         publicKey:(NSString *)publicKey
   completionBlock:(void(^)(BOOL result))completionBlock
        errorBlock:(void(^)(NSError *error))errorBlock;

@end

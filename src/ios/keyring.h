//
//  Keyring.h
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Key.h"

@interface Keyring : NSObject

@property (nonatomic, readonly) NSArray *allPublicKeys;
@property (nonatomic, readonly) NSArray *allSecretKeys;

@property (nonatomic, readonly) NSArray *publicKeys;
@property (nonatomic, readonly) NSArray *secretKeys;

@property (nonatomic, readonly) NSArray *publicSubkeys;
@property (nonatomic, readonly) NSArray *secretSubkeys;

+ (Keyring *)keyring;

- (void)addPublicKey:(PublicKey *)publicKey forUserId:(NSString *)userId;
- (void)addSecretKey:(SecretKey *)secretKey forUserId:(NSString *)userId;

- (NSArray *)publicKeysForUserId:(NSString *)userId;
- (PublicKey *)publicKeyForKeyId:(NSString *)keyId;

- (NSArray *)secretKeysForUserId:(NSString *)userId;
- (SecretKey *)secretKeyForKeyId:(NSString *)keyId;

@end

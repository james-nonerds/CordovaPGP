//
//  Keyring.m
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Keyring.h"

@interface Keyring () {
    NSMutableDictionary *_publicKeysByUserId, *_publicKeysByKeyId;
    NSMutableDictionary *_secretKeysByUserId, *_secretKeysByKeyId;
    NSMutableDictionary *_publicSubkeysByKeyId, *_publicSubkeysByUserId;
    NSMutableDictionary *_secretSubkeysByKeyId, *_secretSubkeysByUserId;
}

- (void)addPublicSubkey:(PublicKey *)publicSubkey forUserId:(NSString *)userId;
- (void)addSecretSubkey:(SecretKey *)secretSubkey forUserId:(NSString *)userId;

@end

@implementation Keyring

+ (Keyring *)keyring {
    return [[self alloc] init];
}

- (instancetype)init {
    self = [super init];
    
    if (self != nil) {
        _publicKeysByUserId = [NSMutableDictionary dictionary];
        _publicKeysByKeyId = [NSMutableDictionary dictionary];
        
        _secretKeysByUserId = [NSMutableDictionary dictionary];
        _secretKeysByKeyId = [NSMutableDictionary dictionary];
        
        _publicSubkeysByKeyId = [NSMutableDictionary dictionary];
        _publicSubkeysByUserId = [NSMutableDictionary dictionary];
        
        _secretSubkeysByKeyId = [NSMutableDictionary dictionary];
        _secretSubkeysByUserId = [NSMutableDictionary dictionary];
    }
    
    return self;
}

- (NSArray *)allPublicKeys {
    return [[_publicKeysByKeyId allValues] arrayByAddingObjectsFromArray:[_publicSubkeysByKeyId allValues]];
}

- (NSArray *)allSecretKeys {
    return [[_secretKeysByKeyId allValues] arrayByAddingObjectsFromArray:[_secretSubkeysByKeyId allValues]];
}

- (NSArray *)publicKeys {
    return [_publicKeysByKeyId allValues];
}

- (NSArray *)secretKeys {
    return [_secretKeysByKeyId allValues];
}

- (NSArray *)publicSubkeys {
    return [_publicSubkeysByKeyId allValues];
}

- (NSArray *)secretSubkeys {
    return [_secretSubkeysByKeyId allValues];
}

- (void)addPublicKey:(PublicKey *)publicKey forUserId:(NSString *)userId {
    if (_publicKeysByUserId[userId] == nil) {
        _publicKeysByUserId[userId] = [NSMutableArray array];
    }
    
    [_publicKeysByUserId[userId] addObject:publicKey];
    _publicKeysByKeyId[publicKey.keyID] = publicKey;
    
    for (PublicKey *subkey in publicKey.subkeys) {
        [self addPublicSubkey:subkey forUserId:userId];
    }
}

- (void)addSecretKey:(SecretKey *)secretKey forUserId:(NSString *)userId {
    if (_secretKeysByUserId[userId] == nil) {
        _secretKeysByUserId[userId] = [NSMutableArray array];
    }
    
    [_secretKeysByUserId[userId] addObject:secretKey];
    _secretKeysByKeyId[secretKey.publicKey.keyID] = secretKey;
    
    for (SecretKey *subkey in secretKey.subkeys) {
        [self addSecretSubkey:subkey forUserId:userId];
    }
    
    [self addPublicKey:secretKey.publicKey forUserId:userId];
}


- (void)addPublicSubkey:(PublicKey *)publicSubkey forUserId:(NSString *)userId {
    if (_publicSubkeysByUserId[userId] == nil) {
        _publicSubkeysByUserId[userId] = [NSMutableArray array];
    }
    
    [_publicSubkeysByUserId[userId] addObject:publicSubkey];
    _publicSubkeysByKeyId[publicSubkey.keyID] = publicSubkey;
}

- (void)addSecretSubkey:(SecretKey *)secretSubkey forUserId:(NSString *)userId {
    if (_secretSubkeysByUserId[userId] == nil) {
        _secretSubkeysByUserId[userId] = [NSMutableArray array];
    }
    
    [_secretSubkeysByUserId[userId] addObject:secretSubkey];
    _secretSubkeysByKeyId[secretSubkey.publicKey.keyID] = secretSubkey;
}

- (NSArray *)publicKeysForUserId:(NSString *)userId {
    NSMutableArray *publicKeys = [NSMutableArray array];
    
    if (_publicKeysByUserId[userId]) {
        [publicKeys addObjectsFromArray:_publicKeysByUserId[userId]];
    }
    
    if (_publicSubkeysByUserId[userId]) {
        [publicKeys addObjectsFromArray:_publicSubkeysByUserId[userId]];
    }
    
    return [NSArray arrayWithArray:publicKeys];
}

- (PublicKey *)publicKeyForKeyId:(NSString *)keyId {
    return _publicKeysByKeyId[keyId] ?: _publicSubkeysByKeyId[keyId];
}

- (NSArray *)secretKeysForUserId:(NSString *)userId {
    NSMutableArray *secretKeys = [NSMutableArray array];
    
    if (_secretKeysByUserId[userId]) {
        [secretKeys addObjectsFromArray:_secretKeysByUserId[userId]];
    }
    
    if (_secretKeysByUserId[userId]) {
        [secretKeys addObjectsFromArray:_secretKeysByUserId[userId]];
    }
    
    return [NSArray arrayWithArray:secretKeys];
}

- (SecretKey *)secretKeyForKeyId:(NSString *)keyId {
    return _secretKeysByKeyId[keyId] ?: _secretSubkeysByKeyId[keyId];
}

@end

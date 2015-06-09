//
//  PGP.h
//  iOS PGP
//
//  Created by James Knight on 6/3/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PGPLib : NSObject

/**
 * openpgp.generateKeyPair
 */
+ (void)generateKeypairWithOptions:(NSDictionary *)options
                      onCompletion:(void(^)(NSDictionary *result))onCompletion
                           onError:(void(^)(NSError *error))onError;

/**
 * return openpgp.util.hexstrdump(openpgp.crypto.hash.sha256(this.get('publicKey')));
 */
+ (void)convertKeyToASCIIArmor:(NSString *)key onCompletion:(void(^)(NSString *asciiArmor))onCompletion;

/**
 * return openpgp.key.readArmored(pk).keys[0];
 */
+ (void)convertASCIIArmorToKey:(NSString *)asciiArmor onCompletion:(void(^)(NSString *key))onCompletion;

/**
 * openpgp.signAndEncryptMessage
 */
+ (void)encryptMessageToASCIIArmor:(NSString *)message withPublicKeys:(NSArray *)publicKeys onCompletion:(void(^)(NSString *asciiArmor))onCompletion;

/**
 * openpgp.decryptAndVerifyMessage
 */
+ (void)decryptASCIIArmorToMessage:(NSString *)asciiArmor onCompletion:(void(^)(NSString *message, NSString *publicKeyUsed))onCompletion;

@end

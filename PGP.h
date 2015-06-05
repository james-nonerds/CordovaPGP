//
//  PGP.h
//  iOS PGP
//
//  Created by James Knight on 6/3/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PGP : NSObject

/**
 * Generate a PGP keypair using RSA (key type 1), accepting only 256-bit AES for symmetric operations (key type 9), and accepting a userId and bit size as options.
 */
+ (void)generateKeypairWithOptions:(NSDictionary *)options
                      onCompletion:(void(^)(NSDictionary *result))onCompletion
                           onError:(void(^)(NSError *error))onError;

/**
 * Write public and private keys to ASCII Armor format (per RFC 4880).
 */
+ (void)convertKeyToASCIIArmor:(NSString *)key onCompletion:(void(^)(NSString *asciiArmor))onCompletion;

/**
 * Read public and private keys from ASCII Armor format (per RFC 4880).
 */
+ (void)convertASCIIArmorToKey:(NSString *)asciiArmor onCompletion:(void(^)(NSString *key))onCompletion;

/**
 * Given a list of public PGP keys and a plaintext message, sign & encrypt the message so that it can be decrypted by any of the keys. 
 * Return the message in ASCII Armor format.
 */
+ (void)encryptMessageToASCIIArmor:(NSString *)message withPublicKeys:(NSArray *)publicKeys onCompletion:(void(^)(NSString *asciiArmor))onCompletion;

/**
 * Given a list of public PGP keys and an encrypted message in ASCII Armor format, decrypt and verify the message. 
 * In addition to the plaintext of the message, provide a way to determine which of the keys was used to verify the signature.
 */
+ (void)decryptASCIIArmorToMessage:(NSString *)asciiArmor onCompletion:(void(^)(NSString *message, NSString *publicKeyUsed))onCompletion;

@end

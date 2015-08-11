//
//  Crypto.h
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

@class MPI, Keypair, PublicKey, SecretKey;

typedef NS_ENUM(NSUInteger, CompressionAlgorithm) {
    CompressionAlgorithmUncompressed = 0,
    CompressionAlgorithmZIP = 1,
    CompressionAlgorithmZLIB = 2,
    CompressionAlgorithmBZip2 = 3
};

typedef NS_ENUM(NSUInteger, HashAlgorithm) {
    HashAlgorithmMD5 = 1,
    HashAlgorithmSHA1 = 2,
    HashAlgorithmRipeMD = 3,
    HashAlgorithmSHA256 = 8,
    HashAlgorithmSHA384 = 9,
    HashAlgorithmSHA512 = 10,
    HashAlgorithmSHA224 = 11
};

typedef NS_ENUM(NSUInteger, PublicKeyAlgorithm) {
    PublicKeyAlgorithmRSAEncryptSign = 1,
    PublicKeyAlgorithmRSAEncrypt = 2,
    PublicKeyAlgorithmRSASign = 3,
    PublicKeyAlgorithmElGamal = 16,
    PublicKeyAlgorithmDSA = 17
};

typedef NS_ENUM(NSUInteger, SymmetricAlgorithm) {
    SymmetricAlgorithmPlaintext = 0,
    SymmetricAlgorithmIdea = 1,
    SymmetricAlgorithmTripleDES = 2,
    SymmetricAlgorithmCast5 = 3,
    SymmetricAlgorithmBlowfish = 4,
    SymmetricAlgorithmAES128 = 7,
    SymmetricAlgorithmAES192 = 8,
    SymmetricAlgorithmAES256 = 9,
    SymmetricAlgorithmTwoFish = 10
};

@interface Crypto : NSObject

// Hash:
+ (NSData *)hashData:(NSData *)data;

// RSA decrypt/encrypt:
+ (NSData *)decryptMessage:(MPI *)message withSecretKey:(SecretKey *)key;
+ (NSData *)decryptData:(NSData *)data withSecretKey:(SecretKey *)key;

+ (NSData *)encryptData:(NSData *)data withPublicKey:(PublicKey *)key;

// RSA sign/verify:
+ (NSData *)signData:(NSData *)data withSecretKey:(SecretKey *)key;
+ (BOOL)verifyData:(NSData *)messageData withSignatureData:(NSData *)signatureData withPublicKey:(PublicKey *)key;

// AES decrypt/encrypt:
+ (NSData *)generateSessionKey;

+ (NSData *)decryptData:(NSData *)data withSymmetricKey:(const Byte *)symmetricKey;
+ (NSData *)encryptData:(NSData *)data withSymmetricKey:(const Byte *)symmetricKey;

+ (NSData *)emePKCSEncodeMessage:(NSData *)message keyLength:(NSUInteger)keyLength;
+ (NSData *)emePKCSDecodeMessage:(NSData *)message;

// Generate keypair:
+ (Keypair *)generateKeypairWithBits:(int)bits;

@end

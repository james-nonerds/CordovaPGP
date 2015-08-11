//
//  Crypto.m
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <openssl/aes.h>
#import <openssl/objects.h>
#import <openssl/rsa.h>
#import <openssl/sha.h>
#import "Crypto.h"
#import "Key.h"
#import "Keypair.h"

@interface RSAWrapper : NSObject

@property (nonatomic, readonly) RSA *rsa;

+ (instancetype)rsaWithPublicKey:(PublicKey *)publicKey;
+ (instancetype)rsaWithSecretKey:(SecretKey *)secretKey;

- (instancetype)initWithPublicKey:(PublicKey *)publicKey;
- (instancetype)initWithSecretKey:(SecretKey *)secretKey;

- (instancetype)initWithN:(BIGNUM *)n
                        e:(BIGNUM *)e
                        d:(BIGNUM *)d
                        p:(BIGNUM *)p
                        q:(BIGNUM *)q;

@end

@implementation Crypto

+ (NSData *)hashData:(NSData *)data {
    Byte hash[SHA256_DIGEST_LENGTH];
    SHA256(data.bytes, data.length, hash);
    
    return [NSData dataWithBytes:hash length:SHA256_DIGEST_LENGTH];
}

#pragma mark RSA decrypt/encrypt

+ (NSData *)decryptData:(NSData *)data withSecretKey:(SecretKey *)key {
    return [self decryptBytes:data.bytes length:data.length withSecretKey:key];
}

+ (NSData *)decryptMessage:(MPI *)message withSecretKey:(SecretKey *)key {
    
    NSUInteger length = BN_num_bytes(message.bn);
    Byte mpibuf[length];
    
    memset(mpibuf, 0, length);
    
    BN_bn2bin(message.bn, mpibuf);
    
    return [self decryptBytes:mpibuf length:length withSecretKey:key];
}

+ (NSData *)decryptBytes:(const Byte *)bytes length:(NSUInteger)length withSecretKey:(SecretKey *)key {
    RSAWrapper *rsaWrapper = [RSAWrapper rsaWithSecretKey:key];
    
    if (RSA_check_key(rsaWrapper.rsa) != 1) {
        NSLog(@"Error with key.");
        return nil;
    }
    
    Byte outbuf[8192];
    
    int outLength = RSA_private_decrypt((int) length, bytes, outbuf, rsaWrapper.rsa, RSA_PKCS1_PADDING);
    
    return [NSData dataWithBytes:outbuf length:outLength];
}

+ (NSData *)encryptData:(NSData *)data withPublicKey:(PublicKey *)key {
    
    RSAWrapper *rsaWrapper = [RSAWrapper rsaWithPublicKey:key];
    
    Byte outbuf[8192];
    
    int outLength = RSA_public_encrypt((int) data.length, data.bytes, outbuf, rsaWrapper.rsa, RSA_PKCS1_PADDING);
    
    return outLength > 0 ? [NSData dataWithBytes:outbuf length:outLength] : nil;
}

#pragma mark RSA sign/verify

+ (NSData *)signData:(NSData *)data withSecretKey:(SecretKey *)key {
    
    NSUInteger keyLength = key.publicKey.n.dataLength;
    NSData *encodedData = [self emsaPKCSEncodeMessage:data algorithm:HashAlgorithmSHA256 length:keyLength];
    
    RSAWrapper *rsaWrapper = [RSAWrapper rsaWithSecretKey:key];
    
    if (RSA_check_key(rsaWrapper.rsa) != 1) {
        NSLog(@"Error with key.");
        return nil;
    }
    
    Byte outbuf[8192];
    
    NSLog(@"Sign encoded data: %@", encodedData);
    
    int outLength = RSA_private_encrypt((int) encodedData.length, encodedData.bytes, outbuf, rsaWrapper.rsa, RSA_NO_PADDING);
    
    return outLength > 0 ? [NSData dataWithBytes:outbuf length:outLength] : nil;
}

+ (BOOL)verifyData:(NSData *)messageData withSignatureData:(NSData *)signatureData withPublicKey:(PublicKey *)key {
    
    NSUInteger keyLength = key.n.dataLength;
    NSData *encodedData = [self emsaPKCSEncodeMessage:messageData algorithm:HashAlgorithmSHA256 length:keyLength];
    
    NSLog(@"Verify encoded data:\n%@", encodedData);
    
    RSAWrapper *rsaWrapper = [RSAWrapper rsaWithPublicKey:key];
    
    Byte outbuf[8192];
    int outLength = RSA_public_decrypt((int) signatureData.length, signatureData.bytes, outbuf, rsaWrapper.rsa, RSA_NO_PADDING);
    
    NSData *unsignedData = [NSData dataWithBytesNoCopy:outbuf length:outLength freeWhenDone:NO];
    
    NSLog(@"Unsigned data:\n%@", unsignedData);
    
    return [encodedData isEqual:unsignedData];
}

#pragma mark AES decrypt/encrypt

+ (NSData *)generateSessionKey {
    Byte sessionKey[kCCKeySizeAES256];
    arc4random_buf(sessionKey, kCCKeySizeAES256);
    
    return [NSData dataWithBytes:sessionKey length:kCCKeySizeAES256];
}

+ (NSData *)decryptData:(NSData *)data withSymmetricKey:(const Byte *)symmetricKey {
    NSUInteger length = data.length + kCCBlockSizeAES128;
    
    Byte outbuf[length];
    Byte iv[16];
    size_t num = 0;
    
    memset(outbuf, 0, length);
    memset(iv, 0, 16);
    
    CCCryptorStatus     err;
    CCCryptorRef        cryptor;
    
    cryptor = NULL;
    
    err = CCCryptorCreateWithMode(kCCDecrypt, kCCModeCFB, kCCAlgorithmAES, ccNoPadding, iv, symmetricKey, kCCKeySizeAES256, NULL, 0, 0, 0, &cryptor);
    
    if (err) {
        NSLog(@"Error with CCCryptor create: %i", err);
    }
    
    err = CCCryptorUpdate(cryptor, data.bytes, data.length, outbuf, length, &num);
    
    if (err) {
        NSLog(@"Error with CCCryptor update: %i", err);
    }
    
    err = CCCryptorFinal(cryptor, outbuf, length, NULL);
    
    if (err) {
        NSLog(@"Error with CCCryptor final: %i", err);
    }
    
    return [NSData dataWithBytes:outbuf length:num];
}

+ (NSData *)encryptData:(NSData *)data withSymmetricKey:(const Byte *)symmetricKey {
    Byte outbuf[data.length];
    Byte iv[16];
    size_t num = 0;
    
    memset(outbuf, 0, data.length);
    memset(iv, 0, 16);
    
    CCCryptorStatus     err;
    CCCryptorRef        cryptor;
    
    cryptor = NULL;
    
    err = CCCryptorCreateWithMode(kCCEncrypt, kCCModeCFB, kCCAlgorithmAES, ccNoPadding, iv, symmetricKey, kCCKeySizeAES256, NULL, 0, 0, 0, &cryptor);
    if (err) {
        NSLog(@"Error with CCCryptor create: %i", err);
    }
    
    err = CCCryptorUpdate(cryptor, data.bytes, data.length, outbuf, data.length, &num);
    
    if (err) {
        NSLog(@"Error with CCCryptor update: %i", err);
    }
    
    err = CCCryptorFinal(cryptor, outbuf, data.length, NULL);
    
    if (err) {
        NSLog(@"Error with CCCryptor final: %i", err);
    }
    
    return [NSData dataWithBytes:outbuf length:data.length];
}

#pragma mark Keypair

+ (Keypair *)generateKeypairWithBits:(int)bits {
    RSA *rsa;
    BIGNUM *bne;
    BN_CTX *ctx;
    
    ctx = BN_CTX_new();
    
    bne = BN_new();
    BN_set_word(bne, RSA_F4);
    
    rsa = RSA_new();
    RSA_generate_key_ex(rsa, bits, bne, NULL);
    
    NSDate *now = [NSDate date];
    NSUInteger timestamp = [now timeIntervalSince1970];
    
    MPI *n = [MPI mpiWithBIGNUM:rsa->n];
    MPI *e = [MPI mpiWithBIGNUM:rsa->e];
    
    MPI *d = [MPI mpiWithBIGNUM:rsa->d];
    MPI *p = [MPI mpiWithBIGNUM:rsa->p];
    MPI *q = [MPI mpiWithBIGNUM:rsa->q];
    MPI *u = [MPI mpiWithBIGNUM:BN_mod_inverse(NULL, rsa->p, rsa->q, ctx)];
    
    RSA_free(rsa);
    BN_CTX_free(ctx);
    
    PublicKey *publicKey = [PublicKey keyWithCreationTime:timestamp n:n e:e];
    SecretKey *secretKey = [SecretKey keyWithPublicKey:publicKey d:d p:p q:q u:u];
    
    return [Keypair keypairWithPublicKey:publicKey secretKey:secretKey];
}

#pragma mark Private

+ (NSData *)emePKCSEncodeMessage:(NSData *)message keyLength:(NSUInteger)keyLength {
    
    if (message.length > keyLength - 11) {
        return nil;
    }
    
    NSUInteger paddingLength = keyLength - message.length - 3;
    NSData *padding = [self emePKCSPaddingWithLength:paddingLength];
    
    NSUInteger encodedLength = message.length + paddingLength + 3;
    NSMutableData *encodedMessage = [NSMutableData dataWithCapacity:encodedLength];
    
    Byte header[2] = {0x00, 0x02};
    [encodedMessage appendBytes:header length:2];
    [encodedMessage appendData:padding];
    Byte zero = 0;
    [encodedMessage appendBytes:&zero length:1];
    [encodedMessage appendData:message];
    
    return [NSData dataWithData:encodedMessage];
}

+ (NSData *)emePKCSDecodeMessage:(NSData *)message {
    const Byte *bytes = message.bytes;
    
    Byte firstOctet = bytes[0];
    Byte secondOctet = bytes[1];
    
    NSUInteger i = 2;
    while (bytes[i] != 0 && i < message.length) {
        i++;
    }
    
    NSUInteger psLen = i -2;
    NSUInteger separator = bytes[i++];
    
    if (firstOctet == 0x00
        && secondOctet == 0x02
        && psLen >= 8
        && separator == 0x00) {
        // PKCS encoded:
        return [message subdataWithRange:NSMakeRange(i, message.length - i)];
    } else {
        return nil;
    }
}

#define HASH_HEADER_LENGTH 19

+ (NSData *)emsaPKCSEncodeMessage:(NSData *)message algorithm:(HashAlgorithm)algorithm length:(NSUInteger)length {
    if (algorithm != HashAlgorithmSHA256) {
        return nil;
    }
    
    Byte digest[SHA256_DIGEST_LENGTH];
    SHA256(message.bytes, message.length, digest);

    Byte hashHeader[HASH_HEADER_LENGTH] = {
        0x30, 0x31, 0x30, 0x0d,
        0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20
    };
    
    
    NSUInteger tLength = HASH_HEADER_LENGTH + SHA256_DIGEST_LENGTH;
    Byte T[tLength];
    
    memmove(T, hashHeader, HASH_HEADER_LENGTH);
    memmove(T + HASH_HEADER_LENGTH, digest, SHA256_DIGEST_LENGTH);
    
    NSMutableData *encodedMessage = [NSMutableData dataWithCapacity:length];
    
    Byte header[2] = {0x00, 0x02};
    [encodedMessage appendBytes:header length:2];
    
    NSUInteger paddingLength = length - tLength - 3;
    NSData *padding = [self emsaPKCSPaddingWithLength:paddingLength];
    [encodedMessage appendData:padding];
    
    Byte zero = 0;
    [encodedMessage appendBytes:&zero length:1];
    [encodedMessage appendBytes:T length:tLength];
    
    return [NSData dataWithData:encodedMessage];
}

+ (NSData *)emePKCSPaddingWithLength:(NSUInteger)length {
    NSMutableData *padding = [NSMutableData dataWithCapacity:length];
    
    NSUInteger paddingLength = 0;
    while (paddingLength < length) {
        Byte random = arc4random() & 0xFF;
        if (random != 0) {
            [padding appendBytes:(void *)&random length:1];
            paddingLength++;
        }
    }
    
    return [NSData dataWithData:padding];
}

+ (NSData *)emsaPKCSPaddingWithLength:(NSUInteger)length {
    NSMutableData *padding = [NSMutableData dataWithCapacity:length];
    
    for (NSUInteger i = 0; i < length; ++i) {
        Byte paddingValue = 0xFF;
        [padding appendBytes:&paddingValue length:1];
    }
    
    return [NSData dataWithData:padding];
}

@end

#pragma mark - RSAWrapper

@implementation RSAWrapper

+ (instancetype)rsaWithPublicKey:(PublicKey *)publicKey {
    return [[self alloc] initWithPublicKey:publicKey];
}

+ (instancetype)rsaWithSecretKey:(SecretKey *)secretKey {
    return [[self alloc] initWithSecretKey:secretKey];
}

- (instancetype)initWithPublicKey:(PublicKey *)publicKey {
    return [self initWithN:publicKey.n.bn
                         e:publicKey.e.bn
                         d:nil
                         p:nil
                         q:nil];
}

- (instancetype)initWithSecretKey:(SecretKey *)secretKey {
    return [self initWithN:secretKey.publicKey.n.bn
                         e:secretKey.publicKey.e.bn
                         d:secretKey.d.bn
                         p:secretKey.p.bn
                         q:secretKey.q.bn];
}

- (instancetype)initWithN:(BIGNUM *)n
                        e:(BIGNUM *)e
                        d:(BIGNUM *)d
                        p:(BIGNUM *)p
                        q:(BIGNUM *)q {
    self = [super init];
    
    if (self != nil) {
        _rsa = RSA_new();
        
        _rsa->n = BN_dup(n);
        _rsa->e = BN_dup(e);
        
        _rsa->d = BN_dup(d);
        _rsa->p = BN_dup(p);
        _rsa->q = BN_dup(q);
    }
    
    return self;
}

- (void)dealloc {
    RSA_free(_rsa);
}

@end
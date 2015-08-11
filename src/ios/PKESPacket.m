//
//  PKESPacket.m
//  OpenPGP
//
//  Created by James Knight on 6/25/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "PKESPacket.h"
#import "MPI.h"
#import "Key.h"
#import "Utility.h"

#pragma mark - PKESKeyPacket constants

#define PKESKeyPacketVersionNumber 3

#define PKESKeyPacketVersionIndex 0
#define PKESKeyPacketKeyIDIndex 1
#define PKESKeyPacketPKAIndex 9
#define PKESKeyPacketMPIIndex 10

#define PKESKeyPacketKeyIDLength 8

#pragma mark - PKESKeyPacket extension

@interface PKESKeyPacket ()

- (instancetype)initWithKeyId:(NSString *)keyId
                   encryptedM:(MPI *)encryptedM;

@end

#pragma mark - PKESKeyPacket implementation

@implementation PKESKeyPacket

+ (Packet *)packetWithBody:(NSData *)body {
    const Byte *bytes = body.bytes;
    
    // Get version number:
    NSUInteger versionNumber = bytes[PKESKeyPacketVersionIndex];
    
    if (versionNumber != PKESKeyPacketVersionNumber) {
        @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                       reason:@"Packet version not supported."
                                     userInfo:@{@"versionNumber": @(versionNumber)}];
    }
    
    // Get key ID:
    Byte keyIdBytes[PKESKeyPacketKeyIDLength];
    memcpy(keyIdBytes, bytes + PKESKeyPacketKeyIDIndex, sizeof(Byte) * PKESKeyPacketKeyIDLength);
    
    NSString *keyId = [Utility keyIDFromBytes:keyIdBytes];
    
    // Get key algorithms out:
    PublicKeyAlgorithm publicKeyAlgorithm = bytes[PKESKeyPacketPKAIndex];
    
    switch (publicKeyAlgorithm) {
        case PublicKeyAlgorithmRSAEncryptSign:
        case PublicKeyAlgorithmRSAEncrypt: {
            MPI *encryptedM = [MPI mpiFromBytes:(bytes + PKESKeyPacketMPIIndex)];
            
            return [[self alloc] initWithKeyId:keyId
                                    encryptedM:encryptedM];
        }
            
        default: {
            @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                           reason:@"Invalid public key algorithm."
                                         userInfo:@{@"publicKeyAlgorithm": @(publicKeyAlgorithm)}];
        }
    }
}

+ (PKESKeyPacket *)packetWithPublicKey:(PublicKey *)publicKey sessionKey:(NSData *)sessionKey {
    
    NSMutableData *message = [NSMutableData dataWithCapacity:sessionKey.length + 1];
    SymmetricAlgorithm algorithm = SymmetricAlgorithmAES256;
    
    [message appendBytes:&algorithm length:1];
    [message appendData:sessionKey];
    
    NSData *encryptedData = [Crypto encryptData:message withPublicKey:publicKey];
    
    MPI *encryptedM = [MPI mpiFromData:encryptedData];
    
    return [[self alloc] initWithKeyId:publicKey.keyID encryptedM:encryptedM];
}

- (instancetype)initWithKeyId:(NSString *)keyId
                   encryptedM:(MPI *)encryptedM {
    
    self = [super initWithType:PacketTypePKESKey];
    
    if (self != nil) {
        _encryptedM = encryptedM;
        _keyId = keyId;
    }
    
    return self;
}

- (NSData *)body {
    // TODO: Add PKCS encoding.
    Byte header[10];
    
    header[0] = 0x03;
    [Utility writeKeyID:self.keyId toBytes:header + 1];
    header[9] = PublicKeyAlgorithmRSAEncryptSign;
    
    NSMutableData *body = [NSMutableData data];
    [body appendBytes:header length:10];
    [body appendData:self.encryptedM.data];
    
    return [NSData dataWithData:body];
}

@end


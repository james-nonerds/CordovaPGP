//
//  OnePassSignaturePacket.m
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "OnePassSignaturePacket.h"
#import "Utility.h"

@interface OnePassSignaturePacket ()

- (instancetype)initWithSignatureType:(SignatureType)signatureType
                                keyId:(NSString *)keyId
                        hashAlgorithn:(HashAlgorithm)hashAlgorithm
                   publicKeyAlgorithm:(PublicKeyAlgorithm)publicKeyAlgorithm
                             isNested:(BOOL)isNested;

@end

@implementation OnePassSignaturePacket

+ (Packet *)packetWithBody:(NSData *)body {
    const Byte *bytes = body.bytes;
    NSUInteger currentIndex = 0;
    
    // Get version number:
    NSUInteger versionNumber = bytes[currentIndex++];
    
    if (versionNumber != 3) {
        @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                       reason:@"Packet version not supported."
                                     userInfo:@{@"versionNumber": @(versionNumber)}];
    }
    
    SignatureType signatureType = bytes[currentIndex++];
    
    PublicKeyAlgorithm publicKeyAlgorithm = bytes[currentIndex++];
    
    if (publicKeyAlgorithm != PublicKeyAlgorithmRSAEncryptSign) {
        [NSException exceptionWithName:NSInternalInconsistencyException
                                reason:@"Public key algorithm not supported."
                              userInfo:@{@"publicKeyAlgorithm": @(publicKeyAlgorithm)}];
    }
    
    HashAlgorithm hashAlgorithm = bytes[currentIndex++];
    
    if (hashAlgorithm != HashAlgorithmSHA256) {
        [NSException exceptionWithName:NSInternalInconsistencyException
                                reason:@"Hash algorithm not supported."
                              userInfo:@{@"hashAlgorithm": @(hashAlgorithm)}];
    }
    
    NSString *keyId = [Utility keyIDFromBytes:bytes + currentIndex];
    currentIndex += 8;
    
    BOOL isNested = !(bytes[currentIndex]);
    
    return [[self alloc] initWithSignatureType:signatureType
                                         keyId:keyId
                                 hashAlgorithn:hashAlgorithm
                            publicKeyAlgorithm:publicKeyAlgorithm
                                      isNested:isNested];
}

+ (OnePassSignaturePacket *)packetWithSignature:(Signature *)signature {
    return [[self alloc] initWithSignatureType:signature.type
                                         keyId:signature.keyID
                                 hashAlgorithn:HashAlgorithmSHA256
                            publicKeyAlgorithm:PublicKeyAlgorithmRSAEncryptSign
                                      isNested:NO];
}


+ (OnePassSignaturePacket *)packetWithSignatureType:(SignatureType)signatureType
                                              keyID:(NSString *)keyID
                                      hashAlgorithm:(HashAlgorithm)hashAlgorithm
                                 publicKeyAlgorithm:(PublicKeyAlgorithm)publicKeyAlgorithm {
    return [[self alloc] initWithSignatureType:signatureType
                                         keyId:keyID
                                 hashAlgorithn:hashAlgorithm
                            publicKeyAlgorithm:publicKeyAlgorithm
                                      isNested:NO];
}

- (instancetype)initWithSignatureType:(SignatureType)signatureType
                                keyId:(NSString *)keyId
                        hashAlgorithn:(HashAlgorithm)hashAlgorithm
                   publicKeyAlgorithm:(PublicKeyAlgorithm)publicKeyAlgorithm
                             isNested:(BOOL)isNested {
    
    self = [super initWithType:PacketTypeOnePassSig];
    
    if (self != nil) {
        _signatureType = signatureType;
        _keyId = keyId;
        
        _hashAlgorithm = hashAlgorithm;
        _publicKeyAlgorithm = publicKeyAlgorithm;
        
        _isNested = isNested;
    }
    
    return self;
}

- (NSData *)body {
    Byte body[13];
    
    body[0] = 0x03;
    body[1] = self.signatureType;
    body[2] = self.hashAlgorithm;
    body[3] = self.publicKeyAlgorithm;
    
    [Utility writeKeyID:self.keyId toBytes:body + 4];
    
    body[12] = self.isNested;
    
    return [NSData dataWithBytes:body length:13];
}

@end

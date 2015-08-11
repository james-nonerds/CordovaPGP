//
//  SignaturePacket.h
//  OpenPGP
//
//  Created by James Knight on 6/25/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Packet.h"

#pragma mark - SignaturePacket interface

@interface SignaturePacket : Packet

@property (nonatomic, readonly) NSUInteger versionNumber;

/// Shared properties:
@property (nonatomic, readonly) SignatureType signatureType;
@property (nonatomic, readonly) PublicKeyAlgorithm publicKeyAlgorithm;
@property (nonatomic, readonly) HashAlgorithm hashAlgorithm;
@property (nonatomic, readonly) NSUInteger signedHashValue;
@property (nonatomic, readonly) NSData *signatureData;

/// Type dependent properties:
@property (nonatomic, readonly) NSUInteger creationTime;
@property (nonatomic, readonly) NSString *keyId;
@property (nonatomic, readonly) NSUInteger keyExpirationTime;

@property (nonatomic, readonly) NSArray *preferredSymmetricAlgorithms;
@property (nonatomic, readonly) NSArray *preferredHashAlgorithms;
@property (nonatomic, readonly) NSArray *preferredCompressionAlgorithms;

@property (nonatomic, readonly) NSArray *keyFlags;
@property (nonatomic, readonly) NSArray *features;

@property (nonatomic, readonly) NSString *userId;

+ (SignaturePacket *)packetWithSignatureKey:(SecretKey *)signatureKey
                               forKeyPacket:(KeyPacket *)keyPacket
                               userIDPacket:(UserIDPacket *)userIDPacket;

+ (SignaturePacket *)packetWithSignatureKey:(SecretKey *)signatureKey
                       forLiteralDataPacket:(LiteralDataPacket *)packet;

- (NSData *)hashDataForLiteralDataPacket:(LiteralDataPacket *)literalDataPacket;
- (NSData *)hashDataForKeyPacket:(KeyPacket *)keyPacket userIDPacket:(UserIDPacket *)userIDPacket;

@end

//
//  OnePassSignaturePacket.h
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Packet.h"
#import "Signature.h"

@interface OnePassSignaturePacket : Packet

@property (nonatomic, readonly) SignatureType signatureType;
@property (nonatomic, readonly) NSString *keyId;

@property (nonatomic, readonly) HashAlgorithm hashAlgorithm;
@property (nonatomic, readonly) PublicKeyAlgorithm publicKeyAlgorithm;

@property (nonatomic, readonly) BOOL isNested;

+ (OnePassSignaturePacket *)packetWithSignature:(Signature *)signature;

+ (OnePassSignaturePacket *)packetWithSignatureType:(SignatureType)signatureType
                                              keyID:(NSString *)keyID
                                      hashAlgorithm:(HashAlgorithm)hashAlgorithm
                                 publicKeyAlgorithm:(PublicKeyAlgorithm)publicKeyAlgorithm;

@end

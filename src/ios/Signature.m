//
//  Signature.m
//  OpenPGP
//
//  Created by James Knight on 6/24/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Crypto.h"
#import "Signature.h"
#import "KeyPacket.h"
#import "LiteralDataPacket.h"
#import "PacketList.h"
#import "SignaturePacket.h"
#import "UserIDPacket.h"
#import "Utility.h"

@implementation Signature

+ (Signature *)signatureForSignaturePacket:(SignaturePacket *)signaturePacket {
    return [[self alloc] initWithType:signaturePacket.signatureType data:signaturePacket.signatureData keyID:signaturePacket.keyId];
}

+ (Signature *)signatureWithType:(SignatureType)type keyID:(NSString *)keyID {
    return [[self alloc] initWithType:type data:nil keyID:keyID];
}

- (instancetype)initWithType:(SignatureType)type data:(NSData *)data keyID:(NSString *)keyID {
    self = [super init];
    
    if (self != nil) {
        _type = type;
        _data = data;
        _keyID = keyID;
    }
    
    return self;
}

- (BOOL)verifyData:(NSData *)data withKey:(PublicKey *)publicKey {
    return [Crypto verifyData:data withSignatureData:self.data withPublicKey:publicKey];
}


@end

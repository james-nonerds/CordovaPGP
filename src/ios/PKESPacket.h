//
//  PKESPacket.h
//  OpenPGP
//
//  Created by James Knight on 6/25/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Packet.h"

#pragma mark - PKESKeyPacket interface

@interface PKESKeyPacket : Packet

@property (nonatomic, readonly) NSString *keyId;
@property (nonatomic, readonly) MPI *encryptedM;

+ (PKESKeyPacket *)packetWithPublicKey:(PublicKey *)publicKey sessionKey:(NSData *)sessionKey;

@end
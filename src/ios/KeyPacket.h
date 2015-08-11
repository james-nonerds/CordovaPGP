//
//  PublicKeyPacket.h
//  OpenPGP
//
//  Created by James Knight on 6/26/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Packet.h"
#import "Key.h"

typedef NS_ENUM(NSUInteger, KeyPacketType) {
    KeyPacketPublicKey = 6,
    KeyPacketPublicSubkey = 14,
    KeyPacketSecretKey = 5,
    KeyPacketSecretSubkey = 7
};

typedef NS_ENUM(NSUInteger, KeyType) {
    KeyTypePublic = 0,
    KeyTypeSecret = 1
};

@interface KeyPacket : Packet

@property (nonatomic, readonly) PublicKey *publicKey;
@property (nonatomic, readonly) SecretKey *secretKey;

+ (KeyPacket *)packetWithBody:(NSData *)body;

+ (KeyPacket *)packetWithPublicKey:(PublicKey *)publicKey;
+ (KeyPacket *)packetWithSecretKey:(SecretKey *)secretKey;

@end
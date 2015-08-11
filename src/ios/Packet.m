//
//  Packet.m
//  OpenPGP
//
//  Created by James Knight on 6/23/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Packet.h"
#import "PKESPacket.h"
#import "KeyPacket.h"
#import "LiteralDataPacket.h"
#import "OnePassSignaturePacket.h"
#import "SEIPDataPacket.h"
#import "SignaturePacket.h"
#import "UserIDPacket.h"

@interface Packet ()

@property (nonatomic, assign) PacketType packetType;

@end

@implementation Packet

+ (Packet *)packetWithType:(PacketType)type body:(NSData *)body {
    Packet *packet = nil;
    
    switch (type) {
        case PacketTypePKESKey:
            packet = [PKESKeyPacket packetWithBody:body];
            break;
            
        case PacketTypeSEIPData:
            packet = [SEIPDataPacket packetWithBody:body];
            break;
            
        case PacketTypeSEData:
            packet = [SEDataPacket packetWithBody:body];
            break;
            
        case PacketTypeSignature:
            packet = [SignaturePacket packetWithBody:body];
            break;
            
        case PacketTypePublicKey:
        case PacketTypePublicSubkey:
        case PacketTypeSecretKey:
        case PacketTypeSecretSubkey:
            packet = [KeyPacket packetWithBody:body];
            break;
            
        case PacketTypeUserID:
            packet = [UserIDPacket packetWithBody:body];
            break;
            
        case PacketTypeOnePassSig:
            packet = [OnePassSignaturePacket packetWithBody:body];
            break;
            
        case PacketTypeLiteralData:
            packet = [LiteralDataPacket packetWithBody:body];
            break;
            
        case PacketTypeSKESKey:
        case PacketTypeCompressedData:        case PacketTypeMarker:
        case PacketTypeTrust:
        case PacketTypeUserAttribute:
        case PacketTypeModificationDetectionCode:
        case PacketTypePrivateA:
        case PacketTypePrivateB:
        case PacketTypePrivateC:
        case PacketTypePrivateD:
        case PacketTypeReserved:
        case PacketTypeUnknown:
        default:
            @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                           reason:@"Packet type not supported."
                                         userInfo:@{@"packetType": @(type)}];
    }
    
    packet.packetType = type;
    
    return packet;
}

+ (Packet *)packetWithBody:(NSData *)body {
    @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                   reason:[NSString stringWithFormat:@"You must override this method in a subclass."]
                                 userInfo:@{@"method": NSStringFromSelector(_cmd)}];
}

+ (void)writePacketLength:(NSUInteger)length toData:(NSMutableData *)data {
    if (length <= 191) {
        Byte bytes[1];
        
        bytes[0] = length & 0xFF;
        
        [data appendBytes:bytes length:1];
        
    } else if (length >= 192 && length <= 8383) {
        Byte bytes[2];
        
        bytes[0] = (((length - 192) >> 8) & 0xFF) + 192;
        bytes[1] = (length - 192) & 0xFF;
        
        [data appendBytes:bytes length:2];
        
    } else {
        Byte bytes[5];
        
        bytes[0] = 0xFF;
        bytes[1] = (length >> 24) & 0xFF;
        bytes[2] = (length >> 16) & 0xFF;
        bytes[3] = (length >> 8) & 0xFF;
        bytes[4] = length & 0xFF;
    }
}

- (instancetype)initWithType:(PacketType)type {
    self = [super init];
    
    if (self != nil) {
        _packetType = type;
    }
    
    return self;
}

- (NSData *)body {
    @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                   reason:[NSString stringWithFormat:@"You must override this method in a subclass."]
                                 userInfo:@{@"method": NSStringFromSelector(_cmd)}];
}

- (NSData *)data {
    NSMutableData *data = [NSMutableData data];
    
    // Write the "always set" and "format 4" bits:
    Byte packetTag[1] = {0x80 | 0x40 | self.packetType};
    [data appendBytes:packetTag length:1];
    
    NSData *body = self.body;
    [Packet writePacketLength:body.length toData:data];
    
    [data appendData:body];
    
    return [NSData dataWithData:data];
}

@end














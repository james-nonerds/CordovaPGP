//
//  SEDataPacket.m
//  OpenPGP
//
//  Created by James Knight on 8/9/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "SEDataPacket.h"

@implementation SEDataPacket

+ (Packet *)packetWithBody:(NSData *)body {
    return [[self alloc] initWithEncryptedData:body];
}

+ (SEDataPacket *)packetWithEncryptedData:(NSData *)data {
    return [[self alloc] initWithEncryptedData:data];
}

- (id)initWithEncryptedData:(NSData *)encryptedData {
    self = [super initWithType:PacketTypeSEData];
    
    if (self != nil) {
        _encryptedData = encryptedData;
    }
    
    return self;
}

- (NSData *)body {
    return self.encryptedData;
}

@end

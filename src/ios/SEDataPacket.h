//
//  SEDataPacket.h
//  OpenPGP
//
//  Created by James Knight on 8/9/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Packet.h"

@protocol EncryptedDataPacket <NSObject>

- (NSData *)encryptedData;

@end

@interface SEDataPacket : Packet <EncryptedDataPacket>

@property (nonatomic, readonly) NSData *encryptedData;

+ (SEDataPacket *)packetWithEncryptedData:(NSData *)data;

@end

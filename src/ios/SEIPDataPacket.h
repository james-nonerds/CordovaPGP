//
//  SEIPDataPacket.h
//  OpenPGP
//
//  Created by James Knight on 6/25/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Packet.h"
#import "SEDataPacket.h"

#pragma mark - SEIPDataPacket interface

@interface SEIPDataPacket : Packet <EncryptedDataPacket>

@property (nonatomic, readonly) NSData *encryptedData;

+ (SEIPDataPacket *)packetWithEncryptedData:(NSData *)encryptedData;

@end


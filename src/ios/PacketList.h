//
//  Packetlist.h
//  OpenPGP
//
//  Created by James Knight on 6/23/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PacketList : NSObject

@property (nonatomic, readonly) NSData *data;
@property (nonatomic, readonly) NSArray *packets;

+ (instancetype)packetListFromData:(NSData *)data;
+ (instancetype)packetListWithPackets:(NSArray *)packets;

+ (instancetype)emptyPacketList;

@end

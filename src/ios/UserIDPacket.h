//
//  UserIDPacket.h
//  OpenPGP
//
//  Created by James Knight on 6/26/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Packet.h"

@interface UserIDPacket : Packet

@property (nonatomic, readonly) NSString *userId;

+ (UserIDPacket *)packetWithUserId:(NSString *)userId;

@end

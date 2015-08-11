//
//  Packetlist.m
//  OpenPGP
//
//  Created by James Knight on 6/23/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "PacketList.h"
#import "Packet.h"
#import "PacketReader.h"

@interface PacketList ()

@property (nonatomic, strong) NSArray *packets;

- (instancetype)initWithPackets:(NSArray *)packets;

@end

@implementation PacketList

+ (instancetype)packetListFromData:(NSData *)data {
    PacketList *packetList = nil;
    
    @try {
        PacketReader *reader = [PacketReader readerWithData:data];
        
        NSMutableArray *packets = [NSMutableArray array];
        
        while (!reader.isComplete) {
            NSError *error = nil;
            Packet *packet = [reader readPacketWithError:&error];
            
            if (error != nil) {
                NSLog(@"Error reading packet: %@", error);
                continue;
            }
            
            if (packet != nil) {
                [packets addObject:packet];
            }
        }
        
        packetList = [self packetListWithPackets:[NSArray arrayWithArray:packets]];
    }
    @catch (NSException *exception) {
        NSLog(@"Failed to read packet list: %@", exception);
    }
    
    return packetList;
}

+ (instancetype)packetListWithPackets:(NSArray *)packets {
    return [[self alloc] initWithPackets:packets];
}

+ (instancetype)emptyPacketList {
    return [[self alloc] initWithPackets:@[]];
}

- (instancetype)initWithPackets:(NSArray *)packets {
    self = [super init];
    
    if (self != nil) {
        _packets = packets;
    }
    
    return self;
}

- (NSData *)data {
    NSMutableData *data = [NSMutableData data];
    
    for (Packet *packet in self.packets) {
        [data appendData:packet.data];
    }

    return [NSData dataWithData:data];
}

@end

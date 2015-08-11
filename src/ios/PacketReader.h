//
//  PacketReader.h
//  OpenPGP
//
//  Created by James Knight on 6/23/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>

FOUNDATION_EXPORT NSString *const PacketReaderErrorDomain;

@class Packet;

@interface PacketReader : NSObject

@property (nonatomic, readonly) BOOL isComplete;

+ (instancetype)readerWithData:(NSData *)data;

- (Packet *)readPacketWithError:(NSError **)error;

@end

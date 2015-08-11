//
//  LiteralDataPacket.h
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Packet.h"

typedef NS_ENUM(Byte, DataFormat) {
    DataFormatBinary = 'b',
    DataFormatText = 't',
    DataFormatUTF8 = 'u'
};

@interface LiteralDataPacket : Packet

@property (nonatomic, readonly) DataFormat dataFormat;

@property (nonatomic, readonly) NSString *filename;
@property (nonatomic, readonly) NSUInteger date;

@property (nonatomic, readonly) NSData *literalData;
@property (nonatomic, readonly) NSString *textData;

+ (LiteralDataPacket *)packetWithText:(NSString *)text;
+ (LiteralDataPacket *)packetWithData:(NSData *)data;

@end

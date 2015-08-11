//
//  LiteralDataPacket.m
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "LiteralDataPacket.h"
#import "Utility.h"

@interface LiteralDataPacket ()

- (instancetype)initWithDataFormat:(DataFormat)dataFormat
                          filename:(NSString *)filename
                              date:(NSUInteger)date
                       literalData:(NSData *)data;

@end

@implementation LiteralDataPacket

+ (LiteralDataPacket *)packetWithText:(NSString *)text {
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    
    return [[self alloc] initWithDataFormat:DataFormatUTF8
                                   filename:@""
                                       date:[[NSDate date] timeIntervalSince1970]
                                literalData:data];
}

+ (LiteralDataPacket *)packetWithData:(NSData *)data {
    
    return [[self alloc] initWithDataFormat:DataFormatBinary
                                   filename:@""
                                       date:[[NSDate date] timeIntervalSince1970]
                                literalData:data];
}

+ (Packet *)packetWithBody:(NSData *)body {
    const Byte *bytes = body.bytes;
    NSUInteger currentIndex = 0;
    
    DataFormat dataFormat = bytes[currentIndex++];
    
    NSUInteger filenameLength = bytes[currentIndex++];
    
    NSString *filename = (filenameLength > 0) ? [Utility readString:bytes + currentIndex maxLength:filenameLength] : nil;
    currentIndex += filenameLength;
    
    NSUInteger date = [Utility readNumber:bytes + currentIndex length:4];
    currentIndex += 4;
    
    NSRange dataRange = NSMakeRange(currentIndex, body.length - currentIndex);
    NSData *literalData = [body subdataWithRange:dataRange];
    
    return [[self alloc] initWithDataFormat:dataFormat filename:filename date:date literalData:literalData];
}

- (instancetype)initWithDataFormat:(DataFormat)dataFormat
                          filename:(NSString *)filename
                              date:(NSUInteger)date
                       literalData:(NSData *)literalData {
    self = [super initWithType:PacketTypeLiteralData];
    
    if (self != nil) {
        _dataFormat = dataFormat;
        _filename = filename;
        _date = date;
        _literalData = literalData;
    }
    
    return self;
}

- (NSString *)textData {
    if (self.dataFormat == DataFormatText || self.dataFormat == DataFormatUTF8) {
        return [[NSString alloc] initWithData:self.data encoding:NSUTF8StringEncoding];
    }
    
    return nil;
}

- (NSData *)body {
    Byte header[6];
    
    header[0] = self.dataFormat;
    header[1] = 0; // Filename length.
    
    [Utility writeNumber:self.date bytes:header + 2 length:4];
    
    NSMutableData *body = [NSMutableData dataWithCapacity:self.literalData.length + 6];
    [body appendBytes:header length:6];
    [body appendData:self.literalData];
    
    return [NSData dataWithData:body];
}


@end

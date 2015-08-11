//
//  PacketReader.m
//  OpenPGP
//
//  Created by James Knight on 6/23/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "PacketReader.h"
#import "Packet.h"

NSString *const PacketReaderErrorDomain = @"PacketReaderErrorDomain";

typedef NS_ENUM(NSInteger, PacketReaderErrorCodes) {
    PacketReaderErrorPtagFormat = -1,
    PacketReaderErrorReadPastEnd = -2
};

typedef NS_ENUM(NSUInteger, PacketLength) {
    PacketLengthOneOctet,
    PacketLengthTwoOctet,
    PacketLengthFiveOctet,
    PacketLengthPartialBody
};

@interface PacketReader ()

@property (nonatomic, readonly) const Byte *bytes;

@property (nonatomic, strong) NSData *data;
@property (nonatomic, assign) NSUInteger currentIndex;

@property (nonatomic, assign) BOOL usesPartialBodyLengths;

- (id)initWithData:(NSData *)data;
- (const Byte)nextByte;

@end

@implementation PacketReader

+ (instancetype)readerWithData:(NSData *)data {
    return [[self alloc] initWithData:data];
}

- (id)initWithData:(NSData *)data {
    self = [super init];
    
    if (self != nil) {
        self.data = data;
        self.currentIndex = 0;
        self.usesPartialBodyLengths = NO;
    }
    
    return self;
}

- (Packet *)readPacketWithError:(NSError *__autoreleasing *)error {    
    PacketType type = [self readPacketTagWithError:error];
    if (*error) return nil;
    
    NSUInteger packetLength = [self readPacketLengthWithError:error];
    if (*error) return nil;
    
    NSMutableData *content = [NSMutableData data];
    
    while (packetLength > 0xFFFFFFFF) {
        NSData *partialBody = [self.data subdataWithRange:NSMakeRange(self.currentIndex, packetLength)];
        [content appendData:partialBody];
        
        self.currentIndex += packetLength;
        packetLength = [self readPacketLengthWithError:error];
        
        if (error) return nil;
    }
    
    if (packetLength > 0) {
        NSData *body = [self.data subdataWithRange:NSMakeRange(self.currentIndex, packetLength)];
        [content appendData:body];
        
        self.currentIndex += packetLength;
    }
    
    return [Packet packetWithType:type body:[NSData dataWithData:content]];
}

- (BOOL)isComplete {
    return self.currentIndex >= self.data.length;
}

- (PacketType)readPacketTagWithError:(NSError **)error {
    Byte ptag = [self nextByte];
    
    if (!(ptag & 0x80)) {
        *error = [NSError errorWithDomain:PacketReaderErrorDomain
                                     code:PacketReaderErrorPtagFormat
                                 userInfo:@{@"ptag": @(ptag)}];
        
        return PacketTypeUnknown;
    }
    
    return ptag & 0x1F;
}

- (NSUInteger)readPacketLengthWithError:(NSError **)error {
    
    const Byte firstOctet = [self nextByte];
    
    if (firstOctet >= 0 && firstOctet <= 191) {
        return firstOctet;
    } else if (firstOctet >= 224 && firstOctet <= 254) {
        return 1 << (firstOctet * 0x1F);
    }
    
    const Byte secondOctet = [self nextByte];
    
    if (firstOctet >= 192 && firstOctet <= 223) {
        return ((firstOctet - 192) << 8) + secondOctet + 192;
    }
    
    const Byte thirdOctet = [self nextByte];
    const Byte fourthOctet = [self nextByte];
    const Byte fifthOctet = [self nextByte];
    
    return (secondOctet << 24) | (thirdOctet << 16) | (fourthOctet << 8) | fifthOctet;
}

- (const Byte *)bytes {
    return self.data.bytes;
}

- (const Byte)nextByte {
    return self.bytes[self.currentIndex++];
}

@end

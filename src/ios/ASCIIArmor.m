//
//  ASCIIArmor.m
//  OpenPGP
//
//  Created by James Knight on 6/23/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "ASCIIArmor.h"
#

#pragma mark - Constants

#define CRC24_INIT 0xB704CEL
#define CRC24_POLY 0x1864CFBL

typedef NS_ENUM(NSUInteger, ASCIIArmorHeaderIndex) {
    PGPHeaderIndexKey = 0,
    PGPHeaderIndexValue = 1
};

typedef NS_ENUM(NSUInteger, ASCIIArmorReadState) {
    ASCIIArmorReadStateArmorHeader,
    ASCIIArmorReadStateHeaders,
    ASCIIArmorReadStateContent,
    ASCIIArmorReadStateFinished
};

static NSString *const PGPLineBreak = @"\r\n";
static NSString *const PGPBackupBreak = @"\n";

static NSString *const ASCIIArmorHeaderMessage =      @"-----BEGIN PGP MESSAGE-----";
static NSString *const ASCIIArmorHeaderPublicKey =    @"-----BEGIN PGP PUBLIC KEY BLOCK-----";
static NSString *const ASCIIArmorHeaderPrivateKey =   @"-----BEGIN PGP PRIVATE KEY BLOCK-----";
static NSString *const ASCIIArmorHeaderMessageXofY =  @"-----BEGIN PGP MESSAGE, PART %u/%y-----";
static NSString *const ASCIIArmorHeaderMessageX =     @"-----BEGIN PGP MESSAGE, PART %u-----";
static NSString *const ASCIIArmorHeaderSignature =    @"-----BEGIN PGP SIGNATURE-----";

static NSString *const ASCIIArmorFooterMessage =      @"-----END PGP MESSAGE-----";
static NSString *const ASCIIArmorFooterPublicKey =    @"-----END PGP PUBLIC KEY BLOCK-----";
static NSString *const ASCIIArmorFooterPrivateKey =   @"-----END PGP PRIVATE KEY BLOCK-----";
static NSString *const ASCIIArmorFooterMessageXofY =  @"-----END PGP MESSAGE, PART %u/%y-----";
static NSString *const ASCIIArmorFooterMessageX =     @"-----END PGP MESSAGE, PART %u-----";
static NSString *const ASCIIArmorFooterSignature =    @"-----END PGP SIGNATURE-----";

#pragma mark - ASCIIArmor extension


@interface ASCIIArmor ()


#pragma mark Private class methods


/// Text to ASCIIArmor:

+ (ASCIIArmorType)typeForArmorHeader:(NSString *)armorHeader;
+ (NSData *)readContentString:(NSString *)contentString checksum:(NSString *)checksum;
+ (NSUInteger)checksumForBase64Data:(NSData *)data;
+ (NSUInteger)valueForChecksumString:(NSString *)checksumString;

/// ASCIIArmor to text:

+ (NSString *)armorHeaderForType:(ASCIIArmorType)type;
+ (NSString *)checksumStringForChecksum:(NSUInteger)checksum;


#pragma mark Private init


- (id)initWithHeaderType:(ASCIIArmorType)type headers:(NSDictionary *)headers content:(NSData *)content;


@end


#pragma mark - ASCIIArmor implementation


@implementation ASCIIArmor


#pragma mark Constructors


+ (ASCIIArmor *)armorFromText:(NSString *)text {
    NSArray *lines = [text componentsSeparatedByString:PGPLineBreak];
    if (lines.count == 1) {
        lines = [text componentsSeparatedByString:PGPBackupBreak];
    }
    
    ASCIIArmorReadState state = ASCIIArmorReadStateArmorHeader;
    
    ASCIIArmorType armorHeaderType = ASCIIArmorTypeUnknown;
    NSMutableDictionary *headers = [NSMutableDictionary dictionary];
    NSMutableString *contentString = [NSMutableString string];
    NSString *checksumString = nil;
    
    for (NSString *line in lines) {
        switch (state) {
            case ASCIIArmorReadStateArmorHeader: {
                armorHeaderType = [ASCIIArmor typeForArmorHeader:line];
                
                if (armorHeaderType == ASCIIArmorTypeUnknown) {
                    NSLog(@"Text is not armored, first line is: %@", line);
                    return nil;
                }
                
                state = ASCIIArmorReadStateHeaders;
                continue;
            }
                
            case ASCIIArmorReadStateHeaders: {
                if ([line isEqualToString:@""]) {
                    state = ASCIIArmorReadStateContent;
                    continue;
                }
                
                NSArray *keyAndValue = [line componentsSeparatedByString:@": "];
                
                if (keyAndValue.count != 2) {
                    NSLog(@"Can't find headers: text on line is not properly formatted : %@", line);
                    return nil;
                }
                
                NSString *key = keyAndValue[PGPHeaderIndexKey];
                NSString *value = keyAndValue[PGPHeaderIndexValue];
                
                [headers setValue:value forKey:key];
                
                continue;
            }
                
            case ASCIIArmorReadStateContent: {
                if ([line characterAtIndex:0] == '=') {
                    checksumString = line;
                    state = ASCIIArmorReadStateFinished;
                    
                    continue;
                }
                
                [contentString appendString:line];
                
                continue;
            }
                
            case ASCIIArmorReadStateFinished: {
                continue;
            } // End case.
        } // End switch.
    } // End for loop.
    
    NSData *content = [ASCIIArmor readContentString:contentString checksum:checksumString];
    
    if (content == nil) {
        NSLog(@"Failed to read content.");
        return nil;
    }
    
    return [[self alloc] initWithHeaderType:armorHeaderType
                                    headers:[NSDictionary dictionaryWithDictionary:headers]
                                    content:content];
}

+ (ASCIIArmor *)armorFromPacketList:(PacketList *)packetList type:(ASCIIArmorType)type {
    return [[self alloc] initWithHeaderType:type
                                    headers:@{@"Version": @"OpenPGP.js v0.11.1",
                                                           @"Comment": @"http://openpgpjs.org"}
                                    content:packetList.data];
}


#pragma mark Properties


- (NSString *)text {
    NSMutableString *text = [NSMutableString string];
    
    [text appendString:[ASCIIArmor armorHeaderForType:self.type]];
    [text appendString:PGPLineBreak];
    
    for (NSString *key in self.headers) {
        NSString *value = self.headers[key];
        
        NSString *headerLine = [NSString stringWithFormat:@"%@: %@", key, value];
        
        [text appendString:headerLine];
        [text appendString:PGPLineBreak];
    }
    
    [text appendString:PGPLineBreak];
    
    NSDataBase64EncodingOptions options = NSDataBase64Encoding64CharacterLineLength | NSDataBase64EncodingEndLineWithCarriageReturn | NSDataBase64EncodingEndLineWithLineFeed;
    
    NSString *contentString = [self.content base64EncodedStringWithOptions:options];
    [text appendString:contentString];
    [text appendString:PGPLineBreak];
    
    NSUInteger checksum = [ASCIIArmor checksumForBase64Data:self.content];
    NSString *checksumString = [ASCIIArmor checksumStringForChecksum:checksum];
    
    [text appendString:checksumString];
    [text appendString:PGPLineBreak];
    
    
    NSString *footerString = [ASCIIArmor armorFooterForType:self.type];
    [text appendString:footerString];
    [text appendString:PGPLineBreak];
    
    return [NSString stringWithString:text];
}


#pragma mark Private class methods


+ (ASCIIArmorType)typeForArmorHeader:(NSString *)armorHeader {
    
    if ([armorHeader isEqualToString:ASCIIArmorHeaderMessage]) {
        
        return ASCIIArmorTypeMessage;
        
    } else if ([armorHeader isEqualToString:ASCIIArmorHeaderPublicKey]) {
        
        return ASCIIArmorTypePublicKey;
        
    } else if ([armorHeader isEqualToString:ASCIIArmorHeaderPrivateKey]) {
        
        return ASCIIArmorTypePrivateKey;
        
    } else if ([armorHeader isEqualToString:ASCIIArmorHeaderMessageXofY]) {
        
        return ASCIIArmorTypeMessageXofY;
        
    } else if ([armorHeader isEqualToString:ASCIIArmorHeaderMessageX]) {
        
        return ASCIIArmorTypeMessageX;
        
    } else if ([armorHeader isEqualToString:ASCIIArmorHeaderSignature]) {
        
        return ASCIIArmorTypeSignature;
    }
    
    return ASCIIArmorTypeUnknown;
}

+ (NSData *)readContentString:(NSString *)contentString checksum:(NSString *)checksumString {
    NSData *contentData = [[NSData alloc] initWithBase64EncodedString:contentString options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    NSUInteger contentChecksum = [ASCIIArmor checksumForBase64Data:contentData];
    NSUInteger checksum = [ASCIIArmor valueForChecksumString:checksumString];
    
    return (contentChecksum == checksum) ? contentData : nil;
}

+ (NSUInteger)checksumForBase64Data:(NSData *)data {
    unsigned const char *octets = (unsigned const char *) data.bytes;
    unsigned long len = data.length;
    
    NSUInteger crc = CRC24_INIT;
    int i;
    while (len--) {
        crc ^= (*octets++) << 16;
        for (i = 0; i < 8; i++) {
            crc <<= 1;
            if (crc & 0x1000000)
                crc ^= CRC24_POLY;
        }
    }
    
    return crc & 0xFFFFFFL;
}

+ (NSUInteger)valueForChecksumString:(NSString *)checksumString {
    NSData *checksumData = [[NSData alloc] initWithBase64EncodedString:[checksumString substringFromIndex:1] options:0];

    const Byte *octets = (const Byte *) checksumData.bytes;
    
    return  (octets[0] << 020) +
            (octets[1] << 010) +
            (octets[2] << 000);
}

+ (NSString *)armorHeaderForType:(ASCIIArmorType)type {
    switch (type) {
        case ASCIIArmorTypeMessage:
            return ASCIIArmorHeaderMessage;
            
        case ASCIIArmorTypePublicKey:
            return ASCIIArmorHeaderPublicKey;
            
        case ASCIIArmorTypePrivateKey:
            return ASCIIArmorHeaderPrivateKey;
            
        case ASCIIArmorTypeMessageX:
            return ASCIIArmorHeaderMessageX;
            
        case ASCIIArmorTypeMessageXofY:
            return ASCIIArmorHeaderMessageXofY;
            
        case ASCIIArmorTypeSignature:
            return ASCIIArmorHeaderSignature;
            
        case ASCIIArmorTypeUnknown:
            return nil;
    }
}

+ (NSString *)armorFooterForType:(ASCIIArmorType)type {
    switch (type) {
        case ASCIIArmorTypeMessage:
            return ASCIIArmorFooterMessage;
            
        case ASCIIArmorTypePublicKey:
            return ASCIIArmorFooterPublicKey;
            
        case ASCIIArmorTypePrivateKey:
            return ASCIIArmorFooterPrivateKey;
            
        case ASCIIArmorTypeMessageX:
            return ASCIIArmorFooterMessageX;
            
        case ASCIIArmorTypeMessageXofY:
            return ASCIIArmorFooterMessageXofY;
            
        case ASCIIArmorTypeSignature:
            return ASCIIArmorFooterSignature;
            
        case ASCIIArmorTypeUnknown:
            return nil;
    }
}

+ (NSString *)checksumStringForChecksum:(NSUInteger)checksum {
    Byte octets[3];
    
    octets[0] = (checksum >> 020) & 0xFF;
    octets[1] = (checksum >> 010) & 0xFF;
    octets[2] = (checksum >> 000) & 0xFF;
    
    NSData *data = [NSData dataWithBytesNoCopy:octets length:3 freeWhenDone:NO];
    NSString *base64String = [data base64EncodedStringWithOptions:0];
    
    return [@"=" stringByAppendingString:base64String];
}

- (id)initWithHeaderType:(ASCIIArmorType)type headers:(NSDictionary *)headers content:(NSData *)content {
    self = [super init];
    
    if (self != nil) {
        _type = type;
        _headers = headers;
        _content = content;
    }
    
    return self;
}


@end

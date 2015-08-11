//
//  Util.m
//  OpenPGP
//
//  Created by James Knight on 6/25/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Utility.h"

@implementation Utility

+ (NSString *)keyIDFromBytes:(const Byte *)bytes {
    static const char *hexes = "0123456789abcdef";
    
    char keyId[17];
    
    for (int i = 0; i < 8 ; i++) {
        keyId[i * 2] = hexes[(unsigned)(bytes[i] & 0xf0) >> 4];
        keyId[(i * 2) + 1] = hexes[bytes[i] & 0xf];
    }
    
    keyId[8 * 2] = 0x0;
    
    
    return [NSString stringWithCString:keyId encoding:NSUTF8StringEncoding];
}

+ (void)writeKeyID:(NSString *)keyId toBytes:(Byte *)bytes {
    
    static const char	*uppers = "0123456789ABCDEF";
    static const char	*lowers = "0123456789abcdef";
    
    const char		*hi;
    const char		*lo;
    
    uint8_t			 hichar;
    uint8_t			 lochar;
    
    size_t			 j;
    int			 i;
    
    const char *userid = [keyId cStringUsingEncoding:NSUTF8StringEncoding];
    size_t len = keyId.length;
    
    for (i = 0, j = 0 ; j < len && userid[i] && userid[i + 1] ; i += 2, j++) {
        if ((hi = strchr(uppers, userid[i])) == NULL) {
            if ((hi = strchr(lowers, userid[i])) == NULL) {
                break;
            }
            hichar = (uint8_t)(hi - lowers);
        } else {
            hichar = (uint8_t)(hi - uppers);
        }
        if ((lo = strchr(uppers, userid[i + 1])) == NULL) {
            if ((lo = strchr(lowers, userid[i + 1])) == NULL) {
                break;
            }
            lochar = (uint8_t)(lo - lowers);
        } else {
            lochar = (uint8_t)(lo - uppers);
        }
        bytes[j] = (hichar << 4) | (lochar);
    }
    
    bytes[j] = 0x0;
}

+ (NSUInteger)readNumber:(const Byte *)bytes length:(NSUInteger)length {
    NSUInteger number = 0;
    
    for (int i = 0; i < length; i++) {
        number <<= 8;
        number += bytes[i];
    }
    
    return number;
}

+ (NSString *)readString:(const Byte *)bytes maxLength:(NSUInteger)maxLength {
    char cString[maxLength + 1];
    strcpy(cString, (const char *) bytes);
    
    return [NSString stringWithCString:cString encoding:NSUTF8StringEncoding];
}

+ (NSString *)hexStringFromBytes:(const Byte *)bytes length:(NSUInteger)length {
    char output[length * 2 + 1];
    char *poutput = output;
    
    for (int i = 0; i < length; i++) {
        poutput += sprintf(poutput, "%02x", bytes[i]);
    }
    
    *poutput = '\0';
    
    return [NSString stringWithCString:output encoding:NSUTF8StringEncoding];
}

+ (void)writeNumber:(NSUInteger)number bytes:(Byte *)bytes length:(NSUInteger)length {
    NSUInteger index = 0;
    NSUInteger shift = (length - 1) * 8;
        
    while (length-- > 0) {
        bytes[index++] = (number >> shift) & 0xFF;
        shift -= 8;
    }
}

@end

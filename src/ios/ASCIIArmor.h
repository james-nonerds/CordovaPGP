//
//  ASCIIArmor.h
//  OpenPGP
//
//  Created by James Knight on 6/23/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PacketList.h"

@class PublicKey, SecretKey;

typedef NS_ENUM(NSUInteger, ASCIIArmorType) {
    ASCIIArmorTypeUnknown,
    ASCIIArmorTypeMessage,
    ASCIIArmorTypePublicKey,
    ASCIIArmorTypePrivateKey,
    ASCIIArmorTypeMessageXofY,
    ASCIIArmorTypeMessageX,
    ASCIIArmorTypeSignature
};

#pragma mark - ASCIIArmor interface

@interface ASCIIArmor : NSObject

#pragma mark Properties

/// Configurable properties:
@property (nonatomic, readonly) ASCIIArmorType type;
@property (nonatomic, readonly) NSDictionary *headers;
@property (nonatomic, readonly) NSData *content;

/// Output properties:
@property (nonatomic, readonly) NSString *text;

#pragma mark Constructors

+ (ASCIIArmor *)armorFromPacketList:(PacketList *)packetList type:(ASCIIArmorType)type;
+ (ASCIIArmor *)armorFromText:(NSString *)text;

@end

//
//  OpenPGP.m
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "OpenPGP.h"
#import "ASCIIArmor.h"
#import "Key.h"
#import "Keyring.h"
#import "Packet.h"
#import "Signature.h"
#import "PKESPacket.h"
#import "KeyPacket.h"
#import "Keypair.h"
#import "LiteralDataPacket.h"
#import "OnePassSignaturePacket.h"
#import "PacketReader.h"
#import "SEDataPacket.h"
#import "SEIPDataPacket.h"
#import "SignaturePacket.h"
#import "UserIDPacket.h"
#import "Utility.h"

@interface OpenPGP ()

+ (NSError *)errorWithCause:(NSString *)cause;

+ (void)readPublicKeyMessages:(NSArray *)publicKeyMessages intoKeyring:(Keyring *)keyring;
+ (void)readSecretKeyMessages:(NSArray *)secretKeyMessages intoKeyring:(Keyring *)keyring;

+ (void)readPublicKeyMessage:(NSString *)publicKeyMessage intoKeyring:(Keyring *)keyring;
+ (void)readSecretKeyMessage:(NSString *)secretKeyMessage intoKeyring:(Keyring *)keyring;

+ (PacketList *)decryptPacketList:(PacketList *)packetList withKeyring:(Keyring *)keyring;

@end

@implementation OpenPGP


+ (void)decryptAndVerifyMessage:(NSString *)message
                     privateKey:(NSString *)privateKey
                     publicKeys:(NSArray *)publicKeys
                completionBlock:(void (^)(NSString *decryptedMessage, NSArray *verifiedUserIds))completionBlock
                     errorBlock:(void (^)(NSError *))errorBlock {
    if (message == nil || publicKeys == nil || privateKey == nil) {
        errorBlock([OpenPGP errorWithCause:@"OpenPGP decryptAndVerifyMessage: Neither message, publicKeys, nor privateKey can be nil."]);
        return;
    }
    
    if (publicKeys.count < 1) {
        errorBlock([OpenPGP errorWithCause:@"OpenPGP decryptAndVerifyMessage: Public keys is empty."]);
        return;
    }
    
    Keyring *keyring = [Keyring keyring];
    
    [self readSecretKeyMessage:privateKey intoKeyring:keyring];
    [self readPublicKeyMessages:publicKeys intoKeyring:keyring];
    
    ASCIIArmor *asciiArmor = [ASCIIArmor armorFromText:message];
    PacketList *packetList = [PacketList packetListFromData:asciiArmor.content];
    
    PacketList *decryptedPacketList =  [self decryptPacketList:packetList withKeyring:keyring];
    
    LiteralDataPacket *literalDataPacket = nil;
    SignaturePacket *signaturePacket = nil;
    
    for (Packet *packet in decryptedPacketList.packets) {
        switch (packet.packetType) {
            case PacketTypeLiteralData:
                literalDataPacket = (LiteralDataPacket *) packet;
                break;
            
            case PacketTypeSignature:
                signaturePacket = (SignaturePacket *) packet;
                break;
                
            default:
                break;
        }
    }
    
    NSString *decryptedMessage = [[NSString alloc] initWithData:literalDataPacket.literalData encoding:NSUTF8StringEncoding];
    NSString *signatureKeyId = signaturePacket.keyId;
    
    PublicKey *publicKey = [keyring publicKeyForKeyId:signatureKeyId];
    
    NSData *literalDataPacketHashData = [signaturePacket hashDataForLiteralDataPacket:literalDataPacket];
    
    BOOL verified = [Crypto verifyData:literalDataPacketHashData
                     withSignatureData:signaturePacket.signatureData
                         withPublicKey:publicKey];
    
    NSArray *verifiedIds = verified ? @[publicKey.userId] : @[];
    
    completionBlock(decryptedMessage, verifiedIds);
}


+ (void)signAndEncryptMessage:(NSString *)message
                   privateKey:(NSString *)privateKey
                   publicKeys:(NSArray *)publicKeys
              completionBlock:(void (^)(NSString *encryptedMessage))completionBlock
                   errorBlock:(void (^)(NSError *))errorBlock {
    
    if (message == nil || publicKeys == nil || privateKey == nil) {
        errorBlock([OpenPGP errorWithCause:@"OpenPGP signAndEncryptMessage: Neither message, publicKeys, nor privateKey can be nil."]);
        return;
    }
    
    if (publicKeys.count < 1) {
        errorBlock([OpenPGP errorWithCause:@"OpenPGP decryptAndVerifyMessage: Public keys is empty."]);
        return;
    }
    
    Keyring *keyring = [Keyring keyring];
    
    [self readSecretKeyMessage:privateKey intoKeyring:keyring];
    [self readPublicKeyMessages:publicKeys intoKeyring:keyring];
    
    SecretKey *signatureKey = keyring.secretKeys.firstObject;
    
    LiteralDataPacket *literalDataPacket = [LiteralDataPacket packetWithText:message];
    
    OnePassSignaturePacket *onePassPacket = [OnePassSignaturePacket packetWithSignatureType:SignatureTypeCanonicalText keyID:signatureKey.publicKey.keyID hashAlgorithm:HashAlgorithmSHA256 publicKeyAlgorithm:PublicKeyAlgorithmRSAEncryptSign];
    
    SignaturePacket *signaturePacket = [SignaturePacket packetWithSignatureKey:signatureKey forLiteralDataPacket:literalDataPacket];
    
    PacketList *interiorPacketList = [PacketList packetListWithPackets:@[onePassPacket, literalDataPacket, signaturePacket]];
    
    NSData *sessionKey = [Crypto generateSessionKey];
    
    NSData *encryptedData = [Crypto encryptData:interiorPacketList.data withSymmetricKey:sessionKey.bytes];

    SEDataPacket *dataPacket = [SEDataPacket packetWithEncryptedData:encryptedData];
    
    NSMutableArray *packets = [NSMutableArray array];
    
    for (PublicKey *publicKey in keyring.publicKeys) {
        PKESKeyPacket *keyPacket = [PKESKeyPacket packetWithPublicKey:publicKey sessionKey:sessionKey];
        [packets addObject:keyPacket];
    }
    
    [packets addObject:dataPacket];
    
    PacketList *messagePacketList = [PacketList packetListWithPackets:[NSArray arrayWithArray:packets]];
    ASCIIArmor *messageArmor = [ASCIIArmor armorFromPacketList:messagePacketList type:ASCIIArmorTypeMessage];
    
    completionBlock(messageArmor.text);
}


+ (void)generateKeypairWithOptions:(NSDictionary *)options
                   completionBlock:(void(^)(NSString *publicKey, NSString *privateKey))completionBlock
                        errorBlock:(void(^)(NSError *error))errorBlock {
    if (!options[@"numBits"] || !options[@"userId"]) {
        errorBlock([OpenPGP errorWithCause:@"Options needs bits and userId"]);
        return;
    }
    
    NSNumber *bits = options[@"numBits"];
    NSString *userId = options[@"userId"];
    
    Keypair *keypair = [Crypto generateKeypairWithBits:bits.intValue];
    
    PacketList *publicKeyPacketList = [self exportPublicKey:keypair.publicKey
                                                     userId:userId
                                               signatureKey:keypair.secretKey];
    
    PacketList *secretKeyPacketList = [self exportSecretKey:keypair.secretKey
                                                     userId:userId];
    
    ASCIIArmor *publicKeyArmor = [ASCIIArmor armorFromPacketList:publicKeyPacketList type:ASCIIArmorTypePublicKey];
    ASCIIArmor *secretKeyArmor = [ASCIIArmor armorFromPacketList:secretKeyPacketList type:ASCIIArmorTypePrivateKey];
    
    NSString *publicKeyString = publicKeyArmor.text;
    NSString *secretKeyString = secretKeyArmor.text;
    
    completionBlock(publicKeyString, secretKeyString);
}


#pragma mark - Private

+ (PacketList *)exportPublicKey:(PublicKey *)publicKey userId:(NSString *)userId signatureKey:(SecretKey *)signatureKey {
    KeyPacket *publicKeyPacket = [KeyPacket packetWithPublicKey:publicKey];
    UserIDPacket *userIdPacket = [UserIDPacket packetWithUserId:userId];
    
    SignaturePacket *signaturePacket = [SignaturePacket packetWithSignatureKey:signatureKey
                                                                  forKeyPacket:publicKeyPacket
                                                                  userIDPacket:userIdPacket];
    
    return [PacketList packetListWithPackets:@[publicKeyPacket, userIdPacket, signaturePacket]];
}

+ (PacketList *)exportSecretKey:(SecretKey *)secretKey userId:(NSString *)userId {
    KeyPacket *secretKeyPacket = [KeyPacket packetWithSecretKey:secretKey];
    UserIDPacket *userIdPacket = [UserIDPacket packetWithUserId:userId];
    
    SignaturePacket *signaturePacket = [SignaturePacket packetWithSignatureKey:secretKey
                                                                  forKeyPacket:secretKeyPacket
                                                                  userIDPacket:userIdPacket];
    
    return [PacketList packetListWithPackets:@[secretKeyPacket, userIdPacket, signaturePacket]];
}

+ (void)readPublicKeyMessages:(NSArray *)publicKeyMessages intoKeyring:(Keyring *)keyring {
    
    for (NSString *publicKeyMessage in publicKeyMessages) {
        [self readPublicKeyMessage:publicKeyMessage intoKeyring:keyring];
    }
}

+ (void)readSecretKeyMessages:(NSArray *)secretKeyMessages intoKeyring:(Keyring *)keyring {
    
    for (NSString *secretKeyMessage in secretKeyMessages) {
        [self readSecretKeyMessage:secretKeyMessage intoKeyring:keyring];
    }
}

+ (void)readPublicKeyMessage:(NSString *)publicKeyMessage intoKeyring:(Keyring *)keyring {
    
    ASCIIArmor *armor = [ASCIIArmor armorFromText:publicKeyMessage];
    PacketList *packetList = [PacketList packetListFromData:armor.content];
    
    NSString *userId = nil;
    
    PublicKey *publicKey = nil;
    Signature *signature = nil;
    
    PublicKey *publicSubkey = nil;
    Signature *subkeySignature = nil;
    
    BOOL lastKeyWasSubkey = NO;
    
    for (Packet *packet in packetList.packets) {
        switch (packet.packetType) {
            case PacketTypeUserID:
                userId = ((UserIDPacket *) packet).userId;
                break;
                
            case PacketTypePublicKey:
                publicKey = ((KeyPacket *) packet).publicKey;
                break;
                
            case PacketTypePublicSubkey:
                publicSubkey = ((KeyPacket *) packet).publicKey;
                lastKeyWasSubkey = YES;
                break;
                
            case PacketTypeSignature:
                if (lastKeyWasSubkey) {
                    subkeySignature = [Signature signatureForSignaturePacket:(SignaturePacket *)packet];
                    lastKeyWasSubkey = NO;
                } else {
                    signature = [Signature signatureForSignaturePacket:(SignaturePacket *)packet];
                }
                break;
                
            default:
                NSLog(@"Unsupported packet type: %lu", packet.packetType);
                break;
        }
    }
    
    if (publicKey != nil) {
        publicKey.userId = userId;
    }
    
    // TODO: Verify key signatures.
    
    if (publicSubkey) {
        [publicKey addSubkey:publicSubkey];
        publicSubkey.userId = userId;
    }
    
    // TODO: Verify key.
    [keyring addPublicKey:publicKey forUserId:userId];
}

+ (void)readSecretKeyMessage:(NSString *)secretKeyMessage intoKeyring:(Keyring *)keyring {
    
    ASCIIArmor *armor = [ASCIIArmor armorFromText:secretKeyMessage];
    PacketList *packetList = [PacketList packetListFromData:armor.content];
    
    NSString *userId = nil;
    
    SecretKey *secretKey = nil;
    
    SecretKey *secretSubkey = nil;
    
    BOOL lastKeyWasSubkey = NO;
    
    for (Packet *packet in packetList.packets) {
        switch (packet.packetType) {
            case PacketTypeUserID:
                userId = ((UserIDPacket *) packet).userId;
                break;
                
            case PacketTypeSecretKey:
                secretKey = ((KeyPacket *) packet).secretKey;
                break;
                
            case PacketTypeSecretSubkey:
                secretSubkey = ((KeyPacket *) packet).secretKey;
                lastKeyWasSubkey = YES;
                break;
                
            case PacketTypeSignature:
                break;
                
            default:
                NSLog(@"Unsupported packet type: %lu", packet.packetType);
                break;
        }
    }
    
    if (secretKey != nil) {
        secretKey.userId = userId;
    }
    
    if (secretSubkey) {
        [secretKey addSubkey:secretSubkey];
        secretSubkey.userId = userId;
    }
    
    // TODO: Verify key.
    
    [keyring addSecretKey:secretKey forUserId:userId];
}


+ (PacketList *)decryptPacketList:(PacketList *)packetList withKeyring:(Keyring *)keyring {
    NSMutableArray *sessionKeyPackets = [NSMutableArray array];
    
    id<EncryptedDataPacket> dataPacket = nil;
    
    for (Packet *packet in packetList.packets) {
        switch (packet.packetType) {
            case PacketTypePKESKey: {
                [sessionKeyPackets addObject:packet];
                break;
            }
                
            case PacketTypeSEData:
            case PacketTypeSEIPData: {
                dataPacket = (id<EncryptedDataPacket>) packet;
                break;
            }
                
            default: {
                NSLog(@"Unsupported packet type: %lu", packet.packetType);
                break;
            }
        }
    }
    
    SecretKey *decryptionKey = nil;
    PKESKeyPacket *keyPacket = nil;
    
    for (PKESKeyPacket *packet in sessionKeyPackets) {
        decryptionKey = [keyring secretKeyForKeyId:packet.keyId];
        
        if (decryptionKey != nil) {
            keyPacket = packet;
            break;
        }
    }
    
    if (decryptionKey == nil) {
        return nil;
    }
    
    NSData *message = [Crypto decryptMessage:keyPacket.encryptedM withSecretKey:decryptionKey];
    
    const Byte *bytes = message.bytes;
    
    SymmetricAlgorithm symmetricAlgorithm = bytes[0];
    
    if (symmetricAlgorithm != SymmetricAlgorithmAES256) {
        @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                       reason:@"Unsupported symmetric algorithm."
                                     userInfo:@{@"symmetricAlgorithm": @(symmetricAlgorithm)}];
    }
    
//    NSUInteger checksum = [Utility readNumber:bytes + currentIndex length:2];
//    currentIndex += 2;
    
    // TODO: CHECK CHECKSUM.
    
    const Byte *sessionKey = bytes + 1;
    NSData *decryptedData = [Crypto decryptData:dataPacket.encryptedData withSymmetricKey:sessionKey];
    
    if (((Packet *)dataPacket).packetType == PacketTypeSEIPData) {
        
        NSUInteger sz_pre = kCCBlockSizeAES128 + 2;
        NSUInteger sz_mdc_hash = 20; // SHA1
        NSUInteger sz_mdc = 2 + sz_mdc_hash;
        NSUInteger sz_plaintext =  decryptedData.length - sz_pre - sz_mdc;
        
        // TODO: Verify plaintext integrity.
        
        decryptedData = [decryptedData subdataWithRange:NSMakeRange(sz_pre, sz_plaintext)];
    }
    
    return [PacketList packetListFromData:decryptedData];
}

+ (NSError *)errorWithCause:(NSString *)cause {
    return [NSError errorWithDomain:@"OpenPGP"
                               code:-1
                           userInfo:@{@"cause": cause}];
}

@end

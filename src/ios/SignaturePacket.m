//
//  SignaturePacket.m
//  OpenPGP
//
//  Created by James Knight on 6/25/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "SignaturePacket.h"
#import "Key.h"
#import "KeyPacket.h"
#import "LiteralDataPacket.h"
#import "MPI.h"
#import "UserIDPacket.h"
#import "Utility.h"

#pragma mark - SignaturePacket constants

typedef NS_ENUM(NSUInteger, SubpacketLength) {
    PacketLengthOneOctet,
    PacketLengthTwoOctet,
    PacketLengthFiveOctet
};

typedef NS_ENUM(NSUInteger, SignatureSubpacketType) {
    SignatureSubpacketReservedA = 0,
    SignatureSubpacketReservedB = 1,
    SignatureSubpacketCreationTime = 2,
    SignatureSubpacketExpirationTime = 3,
    SignatureSubpacketExportableCertification = 4,
    SignatureSubpacketTrustSignature = 5,
    SignatureSubpacketRegularExpression = 6,
    SignatureSubpacketRevocable = 7,
    SignatureSubpacketReservedC = 8,
    SignatureSubpacketKeyExpirationTime = 9,
    SignatureSubpacketPlaceholder = 10,
    SignatureSubpacketPreferredSymmetricAlgorithms = 11,
    SignatureSubpacketRevocationKey = 12,
    SignatureSubpacketReservedD = 13,
    SignatureSubpacketReservedE = 14,
    SignatureSubpacketReservedF = 15,
    SignatureSubpacketIssuer = 16,
    SignatureSubpacketReservedG = 17,
    SignatureSubpacketReservedH = 18,
    SignatureSubpacketReservedI = 19,
    SignatureSubpacketNotationData = 20,
    SignatureSubpacketPreferredHashAlgorithms = 21,
    SignatureSubpacketPreferredCompressionAlgorithms = 22,
    SignatureSubpacketKeyServerPreferences = 23,
    SignatureSubpacketPreferredKeyServer = 24,
    SignatureSubpacketPrimaryUserID = 25,
    SignatureSubpacketPolicyURI = 26,
    SignatureSubpacketKeyFlags = 27,
    SignatureSubpacketUserID = 28,
    SignatureSubpacketReasonForRevocation = 29,
    SignatureSubpacketFeatures = 30,
    SignatureSubpacketSignatureTarge = 31,
    SignatureSubpacketEmbeddedSignature = 32,
    SignatureSubpacketPrivateA = 100,
    SignatureSubpacketPrivateB = 101,
    SignatureSubpacketPrivateC = 102,
    SignatureSubpacketPrivateD = 103,
    SignatureSubpacketPrivateE = 104,
    SignatureSubpacketPrivateF = 105,
    SignatureSubpacketPrivateG = 106,
    SignatureSubpacketPrivateH = 107,
    SignatureSubpacketPrivateI = 108,
    SignatureSubpacketPrivateJ = 109,
    SignatureSubpacketPrivateK = 110
};

#define SignaturePacketVersionIndex 0

#define SignaturePacketV3HashLengthIndex 1
#define SignaturePacketV3SignatureTypeIndex 2
#define SignaturePacketV3CreationTimeIndex 3
#define SignaturePacketV3KeyIDIndex 7
#define SignaturePacketV3PKAlgorithmIndex 15
#define SignaturePacketV3HashAlgorithmIndex 16
#define SignaturePacketV3SignedHashIndex 17
#define SignaturePacketV3MPIIndex 19

#define SignaturePacketV4SignatureTypeIndex 1
#define SignaturePacketV4PKAlgorithmIndex 2
#define SignaturePacketV4HashAlgorithmIndex 3
#define SignaturePacketV4HashedSubpacketCountIndex 4

#define SignaturePacketV3HashLength 5

#pragma mark - SignaturePacket extension


@interface SignaturePacket ()

@property (nonatomic, readonly) NSData *hashData;
@property (nonatomic, assign) NSUInteger signedHashValue;
@property (nonatomic, strong) NSData *signatureData;

+ (NSUInteger)readPacketLength:(const Byte *)bytes index:(NSUInteger *)index;

- (void)readSubpackets:(NSData *)subpackets;


@end


#pragma mark - SignaturePacket implementation


@implementation SignaturePacket

+ (Packet *)packetWithBody:(NSData *)body {
    const Byte *bytes = body.bytes;
    
    NSUInteger versionNumber = bytes[SignaturePacketVersionIndex];
    
    switch (versionNumber) {
        case 3: {
            NSUInteger hashLength = bytes[SignaturePacketV3HashLengthIndex];
            
            if (hashLength != SignaturePacketV3HashLength) {
                [NSException exceptionWithName:NSInternalInconsistencyException
                                        reason:@"Packet version not supported."
                                      userInfo:@{@"versionNumber": @(versionNumber)}];
            }
            
            SignatureType signatureType = bytes[SignaturePacketV3SignatureTypeIndex];
            NSUInteger creationTime = [Utility readNumber:bytes + SignaturePacketV3CreationTimeIndex
                                                  length:4];
            
            NSString *keyId = [Utility keyIDFromBytes:bytes + SignaturePacketV3KeyIDIndex];
            
            PublicKeyAlgorithm publicKeyAlgorithm = bytes[SignaturePacketV3PKAlgorithmIndex];
            
            if (publicKeyAlgorithm != PublicKeyAlgorithmRSAEncryptSign) {
                [NSException exceptionWithName:NSInternalInconsistencyException
                                        reason:@"Public key algorithm not supported."
                                      userInfo:@{@"publicKeyAlgorithm": @(publicKeyAlgorithm)}];
            }
            
            HashAlgorithm hashAlgorithm = bytes[SignaturePacketV3HashAlgorithmIndex];
            
            if (hashAlgorithm != HashAlgorithmSHA256) {
                [NSException exceptionWithName:NSInternalInconsistencyException
                                        reason:@"Hash algorithm not supported."
                                      userInfo:@{@"hashAlgorithm": @(hashAlgorithm)}];
            }
            
            NSUInteger signedHashValue = [Utility readNumber:bytes + SignaturePacketV3SignedHashIndex
                                                      length:2];
            
            MPI *encryptedM = [MPI mpiFromBytes:(bytes + SignaturePacketV3MPIIndex)];
            
            return [[self alloc] initV3WithSignatureType:signatureType
                                      publicKeyAlgorithm:publicKeyAlgorithm
                                           hashAlgorithm:hashAlgorithm
                                            creationTime:creationTime
                                                   keyId:keyId
                                         signedHashValue:signedHashValue
                                                    data:encryptedM.data];
        }
            
        case 4: {
            SignatureType signatureType = bytes[SignaturePacketV4SignatureTypeIndex];
            
            PublicKeyAlgorithm publicKeyAlgorithm = bytes[SignaturePacketV4PKAlgorithmIndex];
            
            if (publicKeyAlgorithm != PublicKeyAlgorithmRSAEncryptSign) {
                [NSException exceptionWithName:NSInternalInconsistencyException
                                        reason:@"Public key algorithm not supported."
                                      userInfo:@{@"publicKeyAlgorithm": @(publicKeyAlgorithm)}];
            }
            
            HashAlgorithm hashAlgorithm = bytes[SignaturePacketV4HashAlgorithmIndex];
            
            if (hashAlgorithm != HashAlgorithmSHA256) {
                [NSException exceptionWithName:NSInternalInconsistencyException
                                        reason:@"Hash algorithm not supported."
                                      userInfo:@{@"hashAlgorithm": @(hashAlgorithm)}];
            }
            
            // Get hashed subpackets out:
            
            NSUInteger hashedSubpacketLength = [Utility readNumber:bytes + SignaturePacketV4HashedSubpacketCountIndex length:2];
            
            NSUInteger hashedSubpacketIndex = SignaturePacketV4HashedSubpacketCountIndex + 2;
            NSRange hashedSubpacketRange = NSMakeRange(hashedSubpacketIndex, hashedSubpacketLength);
            
            NSData *hashedSubpackets = [body subdataWithRange:hashedSubpacketRange];
            
            // Close off "hashed data":
            NSUInteger unhashedSubpacketCountIndex = hashedSubpacketIndex + hashedSubpacketLength;
            
            // Get unhashed subpackets out:
            NSUInteger unhashedSubpacketLength = [Utility readNumber:(bytes + unhashedSubpacketCountIndex) length:2];
            NSUInteger unhashedSubpacketIndex = unhashedSubpacketCountIndex + 2;
            NSRange unhashedSubpacketRange = NSMakeRange(unhashedSubpacketIndex, unhashedSubpacketLength);
            
            NSData *unhashedSubpackets = [body subdataWithRange:unhashedSubpacketRange];
            
            // Get signed hash value:
        
            NSUInteger hashValueIndex = unhashedSubpacketIndex + unhashedSubpacketLength;
            NSUInteger signedHashValue = [Utility readNumber:(bytes + hashValueIndex) length:2];
            
            // Get MPI:
            MPI *encryptedM = [MPI mpiFromBytes:(bytes + hashValueIndex + 2)];
            
            return [[self alloc] initV4WithSignatureType:signatureType
                                      publicKeyAlgorithm:publicKeyAlgorithm
                                           hashAlgorithm:hashAlgorithm
                                        hashedSubpackets:hashedSubpackets
                                      unhashedSubpackets:unhashedSubpackets
                                         signedHashValue:signedHashValue
                                                    data:encryptedM.mpiData
                                                   keyID:nil];
        }
            
        default: {
            @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                           reason:@"Packet version not supported."
                                         userInfo:@{@"versionNumber": @(versionNumber)}];
        }
    }
    
    return nil;
}

+ (SignaturePacket *)packetWithSignatureKey:(SecretKey *)signatureKey
                       forLiteralDataPacket:(LiteralDataPacket *)literalDataPacket {
    
    NSDate *creationTime = [NSDate date];
    
    SignaturePacket *packet = [[self alloc] initWithVersionNumber:4
                                                    signatureType:SignatureTypeCanonicalText
                                               publicKeyAlgorithm:PublicKeyAlgorithmRSAEncryptSign
                                                    hashAlgorithm:HashAlgorithmSHA256
                                                     creationTime:creationTime
                                     preferredSymmetricAlgorithms:nil
                                                      issuerKeyID:signatureKey.publicKey.keyID
                                          preferredHashAlgorithms:nil
                                   preferredCompressionAlgorithms:nil
                                                         keyFlags:nil
                                                         features:nil];
    
    NSData *hashData = [packet hashDataForLiteralDataPacket:literalDataPacket];
    NSData *hashedData = [Crypto hashData:hashData];
    
    const Byte *hashedBytes = hashedData.bytes;
    packet.signedHashValue = (hashedBytes[0] << 8) & hashedBytes[1];
    packet.signatureData = [Crypto signData:hashData withSecretKey:signatureKey];
    
    return packet;
}

- (NSData *)hashDataForLiteralDataPacket:(LiteralDataPacket *)literalDataPacket {
    
    NSMutableData *signatureData = [NSMutableData data];
    
    Byte header[4];
    header[0] = 0x04;
    header[1] = SignatureTypeCanonicalText;
    header[2] = PublicKeyAlgorithmRSAEncryptSign;
    header[3] = HashAlgorithmSHA256;
    
    [signatureData appendBytes:header length:4];
    
    NSData *hashedSubpacketData = [self hashedSubpacketData];
    
    [signatureData appendData:hashedSubpacketData];
    
    Byte trailer[6];
    
    trailer[0] = 0x04;
    trailer[1] = 0xFF;
    [Utility writeNumber:signatureData.length bytes:trailer + 2 length:4];
    
    NSMutableData *hashData = [NSMutableData data];
    [hashData appendData:literalDataPacket.data];
    [hashData appendData:signatureData];
    [hashData appendBytes:trailer length:6];
    
    return [NSData dataWithData:hashData];
}

+ (SignaturePacket *)packetWithSignatureKey:(SecretKey *)signatureKey
                               forKeyPacket:(KeyPacket *)keyPacket
                               userIDPacket:(UserIDPacket *)userIDPacket {
    
    NSDate *creationTime = [NSDate date];
    
    SignaturePacket *packet = [[self alloc] initWithVersionNumber:4
                                                    signatureType:SignatureTypeUserIDCertificationGeneric
                                               publicKeyAlgorithm:PublicKeyAlgorithmRSAEncryptSign
                                                    hashAlgorithm:HashAlgorithmSHA256
                                                     creationTime:creationTime
                                     preferredSymmetricAlgorithms:@[@(SymmetricAlgorithmAES256)]
                                                      issuerKeyID:signatureKey.publicKey.keyID
                                          preferredHashAlgorithms:@[@(HashAlgorithmSHA256)]
                                   preferredCompressionAlgorithms:@[@(CompressionAlgorithmUncompressed)]
                                                         keyFlags:@[@(0x01), @(0x02), @(0x04), @(0x08), @(0x20)]
                                                         features:nil];
    
    NSData *hashData = [packet hashDataForKeyPacket:keyPacket userIDPacket:userIDPacket];
    
    NSData *hashedData = [Crypto hashData:hashData];
    
    const Byte *hashedBytes = hashedData.bytes;
    packet.signedHashValue = (hashedBytes[0] << 8) & hashedBytes[1];
    packet.signatureData = [Crypto signData:hashData withSecretKey:signatureKey];
    
    return packet;
}


- (NSData *)hashDataForKeyPacket:(KeyPacket *)keyPacket
                    userIDPacket:(UserIDPacket *)userIDPacket {
    
    NSMutableData *signatureData = [NSMutableData data];
    
    Byte header[4];
    header[0] = 0x04;
    header[1] = SignatureTypeUserIDCertificationGeneric;
    header[2] = PublicKeyAlgorithmRSAEncryptSign;
    header[3] = HashAlgorithmSHA256;
    
    [signatureData appendBytes:header length:4];
    
    NSData *hashedSubpacketData = [self hashedSubpacketData];
    
    [signatureData appendData:hashedSubpacketData];
    
    Byte trailer[6];
    
    trailer[0] = 0x04;
    trailer[1] = 0xFF;
    [Utility writeNumber:signatureData.length bytes:trailer + 2 length:4];
    
    NSMutableData *hashData = [NSMutableData data];
    
    // Append key data:
    
    NSData *keyData = keyPacket.data;
    
    Byte keyHeader[3];
    
    keyHeader[0] = 0x99;
    [Utility writeNumber:keyData.length bytes:keyHeader + 1 length:2];
    
    [hashData appendBytes:keyHeader length:3];
    [hashData appendData:keyData];
    
    // Append user id data:
    
    NSData *userIDData = userIDPacket.data;
    
    Byte userIdHeader[5];
    
    userIdHeader[0] = 0xB4;
    [Utility writeNumber:userIDData.length bytes:userIdHeader + 1 length:4];
    
    [hashData appendBytes:userIdHeader length:5];
    [hashData appendData:userIDData];
    
    
    [hashData appendData:signatureData];
    [hashData appendBytes:trailer length:6];
    
    return [NSData dataWithData:hashData];
}

+ (NSData *)hashedSubpacketDataForSignature:(SignaturePacket *)signaturePacket {
    NSMutableData *data = [NSMutableData data];
    
    // Creation time subpacket:
    Byte creationTimeSubpacket[6];
    
    creationTimeSubpacket[0] = 5;
    creationTimeSubpacket[1] = SignatureSubpacketCreationTime;
    
    NSUInteger creationTime = signaturePacket.creationTime ?: [[NSDate date] timeIntervalSince1970];
    [Utility writeNumber:creationTime bytes:creationTimeSubpacket + 2 length:4];
    
    [data appendBytes:creationTimeSubpacket length:6];
    
    // Symmetric algorithms subpacket:
    if (signaturePacket.preferredSymmetricAlgorithms && signaturePacket.preferredSymmetricAlgorithms.count > 0) {
        Byte preferredSymmetricAlgorithmsSubpacket[2 + signaturePacket.preferredSymmetricAlgorithms.count];
        
        preferredSymmetricAlgorithmsSubpacket[0] = 1 + signaturePacket.preferredSymmetricAlgorithms.count;
        preferredSymmetricAlgorithmsSubpacket[1] = SignatureSubpacketPreferredSymmetricAlgorithms;
        
        for (int i = 0; i < signaturePacket.preferredSymmetricAlgorithms.count; ++i) {
            preferredSymmetricAlgorithmsSubpacket[i + 2] = [signaturePacket.preferredSymmetricAlgorithms[i] unsignedCharValue];
        }
        
        [data appendBytes:preferredSymmetricAlgorithmsSubpacket length:2 + signaturePacket.preferredSymmetricAlgorithms.count];
    }
    
    // Hash algorithms subpacket:
    if (signaturePacket.preferredHashAlgorithms && signaturePacket.preferredHashAlgorithms.count > 0) {
        Byte preferredHashAlgorithmsSubpacket[2 + signaturePacket.preferredHashAlgorithms.count];
        
        preferredHashAlgorithmsSubpacket[0] = 1 + signaturePacket.preferredHashAlgorithms.count;
        preferredHashAlgorithmsSubpacket[1] = SignatureSubpacketPreferredHashAlgorithms;
        
        for (int i = 0; i < signaturePacket.preferredHashAlgorithms.count; ++i) {
            preferredHashAlgorithmsSubpacket[i + 2] = [signaturePacket.preferredHashAlgorithms[i] unsignedCharValue];
        }
        
        [data appendBytes:preferredHashAlgorithmsSubpacket length:2 + signaturePacket.preferredHashAlgorithms.count];
    }
    
    // Compression algorithms subpacket:
    if (signaturePacket.preferredCompressionAlgorithms && signaturePacket.preferredCompressionAlgorithms.count > 0) {
        Byte preferredCompressionAlgorithmsSubpacket[2 + signaturePacket.preferredCompressionAlgorithms.count];
        
        preferredCompressionAlgorithmsSubpacket[0] = 1 + signaturePacket.preferredCompressionAlgorithms.count;
        preferredCompressionAlgorithmsSubpacket[1] = SignatureSubpacketPreferredCompressionAlgorithms;
        
        for (int i = 0; i < signaturePacket.preferredCompressionAlgorithms.count; ++i) {
            preferredCompressionAlgorithmsSubpacket[i + 2] = [signaturePacket.preferredCompressionAlgorithms[i] unsignedCharValue];
        }
        
        [data appendBytes:preferredCompressionAlgorithmsSubpacket length:2 + signaturePacket.preferredCompressionAlgorithms.count];
    }
    
    if (signaturePacket.keyFlags && signaturePacket.keyFlags.count > 0) {
        Byte keyFlagsSubpacket[3];
        
        keyFlagsSubpacket[0] = 2;
        keyFlagsSubpacket[1] = SignatureSubpacketKeyFlags;
        keyFlagsSubpacket[2] = 0x00;
        
        for (int i = 0; i < signaturePacket.keyFlags.count; ++i) {
            keyFlagsSubpacket[2] |= [signaturePacket.keyFlags[i] unsignedCharValue];
        }
        
        [data appendBytes:keyFlagsSubpacket length:3];
    }
    // Key Flags:
    
    if (signaturePacket.features) {
        // Features:
        Byte features[3];
        
        features[0] = 2;
        features[1] = SignatureSubpacketFeatures;
        features[2] = 0x01;
        
        [data appendBytes:features length:3];
    }
    
    return [NSData dataWithData:data];
}

+ (NSUInteger)readPacketLength:(const Byte *)bytes index:(NSUInteger *)index {
    
    NSUInteger currentIndex = *index;
    const Byte firstOctet = bytes[currentIndex++];
    
    if (firstOctet >= 0 && firstOctet <= 191) {
        *index = currentIndex;
        return firstOctet;
    }
    
    const Byte secondOctet = bytes[currentIndex++];
    
    if (firstOctet >= 192 && firstOctet <= 254) {
        *index = currentIndex;
        return ((firstOctet - 192) << 8) + secondOctet + 192;
    }
    
    const Byte thirdOctet = bytes[currentIndex++];
    const Byte fourthOctet = bytes[currentIndex++];
    const Byte fifthOctet = bytes[currentIndex++];
    
    *index = currentIndex;
    return (secondOctet << 24) | (thirdOctet << 16) | (fourthOctet << 8) | fifthOctet;
}

- (instancetype)initV3WithSignatureType:(SignatureType)signatureType
                     publicKeyAlgorithm:(PublicKeyAlgorithm)publicKeyAlgorithm
                          hashAlgorithm:(HashAlgorithm)hashAlgorithm
                           creationTime:(NSUInteger)creationTime
                                  keyId:(NSString *)keyId
                        signedHashValue:(NSUInteger)signedHashValue
                                   data:(NSData *)data {
    
    self = [self initWithVersionNumber:3
                         signatureType:signatureType
                    publicKeyAlgorithm:publicKeyAlgorithm
                         hashAlgorithm:hashAlgorithm
                       signedHashValue:signedHashValue
                                  data:data
                                 keyID:nil];
    
    if (self != nil) {
        _keyId = keyId;
        _creationTime = creationTime;
    }
    
    return self;
}

- (instancetype)initV4WithSignatureType:(SignatureType)signatureType
                     publicKeyAlgorithm:(PublicKeyAlgorithm)publicKeyAlgorithm
                          hashAlgorithm:(HashAlgorithm)hashAlgorithm
                       hashedSubpackets:(NSData *)hashedSubpackets
                     unhashedSubpackets:(NSData *)unhashedSubpackets
                        signedHashValue:(NSUInteger)signedHashValue
                                   data:(NSData *)data
                                  keyID:(NSString *)keyID {
    
    self = [self initWithVersionNumber:4
                         signatureType:signatureType
                    publicKeyAlgorithm:publicKeyAlgorithm
                         hashAlgorithm:hashAlgorithm
                       signedHashValue:signedHashValue
                                  data:data
                                 keyID:keyID];
    
    if (self != nil) {
        [self readSubpackets:hashedSubpackets];
        [self readSubpackets:unhashedSubpackets];
    }
    
    return self;
}

- (instancetype)initWithVersionNumber:(NSUInteger)versionNumber
                        signatureType:(SignatureType)signatureType
                   publicKeyAlgorithm:(PublicKeyAlgorithm)publicKeyAlgorithm
                        hashAlgorithm:(HashAlgorithm)hashAlgorithm
                      signedHashValue:(NSUInteger)signedHashValue
                                 data:(NSData *)data
                                keyID:(NSString *)keyID {
    self = [super initWithType:PacketTypeSignature];
    
    if (self != nil) {
        _versionNumber = versionNumber;
        _signatureType = signatureType;
        _publicKeyAlgorithm = publicKeyAlgorithm;
        _hashAlgorithm = hashAlgorithm;
        _signedHashValue = signedHashValue;
        _signatureData = data;
        _keyId = keyID;
    }
    
    return self;
}

- (instancetype)initWithVersionNumber:(NSUInteger)versionNumber
                        signatureType:(SignatureType)signatureType
                   publicKeyAlgorithm:(PublicKeyAlgorithm)publicKeyAlgorithm
                        hashAlgorithm:(HashAlgorithm)hashAlgorithm
                         creationTime:(NSDate *)creationTime preferredSymmetricAlgorithms:(NSArray *)preferredSymmetricAlgorithms
                          issuerKeyID:(NSString *)issuerKeyID
              preferredHashAlgorithms:(NSArray *)preferredHashAlgorithms
       preferredCompressionAlgorithms:(NSArray *)preferredCompressionAlgorithms
                             keyFlags:(NSArray *)keyFlags
                             features:(NSArray *)features {
    self = [super initWithType:PacketTypeSignature];
    
    if (self != nil) {
        _versionNumber = versionNumber;
        _signatureType = signatureType;
        
        _publicKeyAlgorithm = publicKeyAlgorithm;
        _hashAlgorithm = hashAlgorithm;
        
        _creationTime = creationTime ? [creationTime timeIntervalSince1970] : [[NSDate date] timeIntervalSince1970];
        _keyId = issuerKeyID;
        
        _preferredSymmetricAlgorithms = preferredSymmetricAlgorithms;
        _preferredHashAlgorithms = preferredHashAlgorithms;
        _preferredCompressionAlgorithms = preferredCompressionAlgorithms;
        
        _keyFlags = keyFlags;
        _features = features;
    }
    
    return self;
}



- (void)readSubpackets:(NSData *)subpackets {
    const Byte *bytes = subpackets.bytes;
    NSUInteger currentIndex = 0;
    
    while (currentIndex < subpackets.length) {
        NSUInteger packetLength = [SignaturePacket readPacketLength:bytes index:&currentIndex];
        SignatureSubpacketType type = bytes[currentIndex++];
        
        const Byte *packetBytes = bytes + currentIndex;
        
        switch(type) {
            case SignatureSubpacketCreationTime: {
                _creationTime = [Utility readNumber:packetBytes length:4];
                break;
            }
                
            case SignatureSubpacketIssuer: {
                _keyId = [Utility keyIDFromBytes:packetBytes];
                
                break;
            }
                
            case SignatureSubpacketPreferredSymmetricAlgorithms: {
                NSMutableArray *array = [NSMutableArray array];
                
                for (int i = 0; i < packetLength - 1; i++) {
                    SymmetricAlgorithm symmetricAlgorithm = packetBytes[i];
                    [array addObject:@(symmetricAlgorithm)];
                }
                
                _preferredSymmetricAlgorithms = [NSArray arrayWithArray:array];
                
                break;
            }
                
            case SignatureSubpacketPreferredHashAlgorithms: {
                
                NSMutableArray *array = [NSMutableArray array];
                
                for (int i = 0; i < packetLength - 1; i++) {
                    HashAlgorithm hashAlgorithm = packetBytes[i];
                    [array addObject:@(hashAlgorithm)];
                }
                
                _preferredHashAlgorithms = [NSArray arrayWithArray:array];
                
                break;
            }
                
            case SignatureSubpacketPreferredCompressionAlgorithms: {
                
                NSMutableArray *array = [NSMutableArray array];
                
                for (int i = 0; i < packetLength - 1; i++) {
                    CompressionAlgorithm compressionAlgorithm = packetBytes[i];
                    [array addObject:@(compressionAlgorithm)];
                }
                
                _preferredCompressionAlgorithms = [NSArray arrayWithArray:array];
                
                break;
            }
                
            case SignatureSubpacketUserID: {
                char userID[packetLength];
                strcpy(userID, (const char *) packetBytes);
                
                _userId = [NSString stringWithCString:userID encoding:NSUTF8StringEncoding];
                
                break;
            }
                
            case SignatureSubpacketKeyFlags: {
                NSMutableArray *array = [NSMutableArray array];
                
                for (int i = 0; i < packetLength - 1; i++) {
                    NSUInteger flag = packetBytes[i];
                    [array addObject:@(flag)];
                }
                
                _keyFlags = [NSArray arrayWithArray:array];
                
                break;
            }
                
            case SignatureSubpacketFeatures: {
                NSMutableArray *array = [NSMutableArray array];
                
                for (int i = 0; i < packetLength - 1; i++) {
                    NSUInteger flag = packetBytes[i];
                    [array addObject:@(flag)];
                }
                
                _features = [NSArray arrayWithArray:array];
                
                break;
            }
                
            default:
                break;
        }
        
        currentIndex += packetLength - 1;
    }
}

- (NSData *)body {
    NSMutableData *data = [NSMutableData data];
    
    Byte header[6];
    
    header[0] = 4;
    header[1] = self.signatureType;
    header[2] = self.publicKeyAlgorithm;
    header[3] = self.hashAlgorithm;
    
    NSData *hashedSubpacketData = [self hashedSubpacketData];
    
    header[4] = (hashedSubpacketData.length >> 8) & 0xFF;
    header[5] = hashedSubpacketData.length & 0xFF;
    
    [data appendBytes:header length:6];
    [data appendData:hashedSubpacketData];
    
    Byte secondHeader[4];
    
    // Unhashed length:
    secondHeader[0] = 0;
    secondHeader[1] = 0;
    
    // Left 16 bits of signed hash:
    secondHeader[2] = (self.signedHashValue >> 8) & 0xFF;
    secondHeader[3] = self.signedHashValue & 0xFF;
    
    [data appendBytes:secondHeader length:4];
    
    MPI *mpi = [MPI mpiFromData:self.signatureData];
    [data appendData:mpi.data];
    
    return [NSData dataWithData:data];
}

- (NSData *)hashedSubpacketData {
    NSMutableData *data = [NSMutableData data];
    
    [self writeCreationTime:data];
    
    if (self.preferredSymmetricAlgorithms) {
        [self writeSymmetricAlgorithms:data];
    }
    
    if (self.keyId) {
        [self writeKeyID:data];        
    }
    
    if (self.preferredHashAlgorithms) {
        [self writeHashAlgorithms:data];
    }
    
    if (self.preferredCompressionAlgorithms) {
        [self writeCompressionAlgorithms:data];
    }
    
    if (self.keyFlags) {
        [self writeKeyFlags:data];
    }
    
    if (self.features) {
        [self writeFeatures:data];
    }
    
    return [NSData dataWithData:data];
}

- (void)writeKeyID:(NSMutableData *)data {
    Byte subpacket[11];
    
    subpacket[0] = 9;
    subpacket[1] = SignatureSubpacketIssuer;
    
    [Utility writeKeyID:self.keyId toBytes:subpacket + 2];
    
    [data appendBytes:subpacket length:10];
}

- (void)writeCreationTime:(NSMutableData *)data {
    Byte subpacket[6];
    
    subpacket[0] = 5;
    subpacket[1] = SignatureSubpacketCreationTime;
    
    [Utility writeNumber:self.creationTime bytes:subpacket + 2 length:4];
    
    [data appendBytes:subpacket length:6];
}

- (void)writeSymmetricAlgorithms:(NSMutableData *)data {
    NSUInteger algorithmCount = self.preferredSymmetricAlgorithms.count;
    NSUInteger byteCount = algorithmCount + 2;
    
    Byte *subpacket = calloc(byteCount, sizeof(Byte));
    
    subpacket[0] = algorithmCount + 1;
    subpacket[1] = SignatureSubpacketPreferredSymmetricAlgorithms;
    
    for (int i = 0; i < algorithmCount; ++i) {
        NSNumber *number = self.preferredSymmetricAlgorithms[i];
        SymmetricAlgorithm algorithm = (SymmetricAlgorithm) number.unsignedIntegerValue;
        
        subpacket[i + 2] = algorithm;
    }
    
    [data appendBytes:subpacket length:byteCount];
    
    free(subpacket);
}

- (void)writeHashAlgorithms:(NSMutableData *)data {
    
    NSUInteger algorithmCount = self.preferredHashAlgorithms.count;
    NSUInteger byteCount = algorithmCount + 2;
    
    Byte *subpacket = calloc(byteCount, sizeof(Byte));
    
    subpacket[0] = algorithmCount + 1;
    subpacket[1] = SignatureSubpacketPreferredHashAlgorithms;
    
    for (int i = 0; i < algorithmCount; ++i) {
        NSNumber *number = self.preferredHashAlgorithms[i];
        HashAlgorithm algorithm = (HashAlgorithm) number.unsignedIntegerValue;
        
        subpacket[i + 2] = algorithm;
    }
    
    [data appendBytes:subpacket length:byteCount];
    
    free(subpacket);
}


- (void)writeCompressionAlgorithms:(NSMutableData *)data {
    
    NSUInteger algorithmCount = self.preferredCompressionAlgorithms.count;
    NSUInteger byteCount = algorithmCount + 2;
    
    Byte *subpacket = calloc(byteCount, sizeof(Byte));
    
    subpacket[0] = algorithmCount + 1;
    subpacket[1] = SignatureSubpacketPreferredCompressionAlgorithms;
    
    for (int i = 0; i < algorithmCount; ++i) {
        NSNumber *number = self.preferredCompressionAlgorithms[i];
        CompressionAlgorithm algorithm = (CompressionAlgorithm) number.unsignedIntegerValue;
        
        subpacket[i + 2] = algorithm;
    }
    
    [data appendBytes:subpacket length:byteCount];
    
    free(subpacket);
}

- (void)writeKeyFlags:(NSMutableData *)data {
    
    NSUInteger flagCount = self.keyFlags.count;
    NSUInteger byteCount = flagCount + 2;
    
    Byte *subpacket = calloc(byteCount, sizeof(Byte));
    
    subpacket[0] = flagCount + 1;
    subpacket[1] = SignatureSubpacketKeyFlags;
    
    for (int i = 0; i < flagCount; ++i) {
        subpacket[i + 2] = ((NSNumber *) self.keyFlags[i]).unsignedIntegerValue;
    }
    
    [data appendBytes:subpacket length:byteCount];
    
    free(subpacket);
}

- (void)writeFeatures:(NSMutableData *)data {
    
    NSUInteger featureCount = self.features.count;
    NSUInteger byteCount = featureCount + 2;
    
    Byte *subpacket = calloc(byteCount, sizeof(Byte));
    
    subpacket[0] = featureCount + 1;
    subpacket[1] = SignatureSubpacketFeatures;
    
    for (int i = 0; i < featureCount; ++i) {
        subpacket[i + 2] = ((NSNumber *) self.features[i]).unsignedIntegerValue;
    }
    
    [data appendBytes:subpacket length:byteCount];
    
    free(subpacket);
}

@end





//
//  Key.m
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <openssl/sha.h>
#import "Key.h"
#import "Utility.h"

@interface Key () {
    NSMutableArray *_subkeys;
}

@end

@implementation Key

- (instancetype)init {
    self = [super init];
    
    if (self != nil) {
        _subkeys = [NSMutableArray array];
    }
    
    return self;
}

- (void)addSubkey:(Key *)subkey {
    [_subkeys addObject:subkey];
}

- (NSArray *)subkeys {
    return [NSArray arrayWithArray:_subkeys];
}

@end

@interface PublicKey ()

- (instancetype)initWithCreationTime:(NSUInteger)creationTime
                                   n:(MPI *)n
                                   e:(MPI *)e;

@end

@interface PublicKey () {
    NSString *_fingerprint, *_keyID;
}

@end

@implementation PublicKey

+ (PublicKey *)keyWithCreationTime:(NSUInteger)creationTime n:(MPI *)n e:(MPI *)e {
    return [[self alloc] initWithCreationTime:creationTime n:n e:e];
}

- (instancetype)initWithCreationTime:(NSUInteger)creationTime
                                   n:(MPI *)n
                                   e:(MPI *)e {
    
    self = [self init];
    
    if (self != nil) {
        _fingerprint = _keyID = nil;
        _creationTime = creationTime;
        _n = n;
        _e = e;
    }
    
    return self;
}

- (NSString *)fingerprint {
    if (_fingerprint == nil) {
        NSMutableData *keyData = [NSMutableData data];
        
        Byte header[6];
        header[0] = 4;
        
        [Utility writeNumber:self.creationTime bytes:header + 1 length:4];
        header[5] = 0x01;
        
        [keyData appendBytes:header length:6];
        [keyData appendData:self.n.data];
        [keyData appendData:self.e.data];
        
        NSMutableData *fingerprintData = [NSMutableData data];
        
        Byte fingerprintHeader[3];
        fingerprintHeader[0] = 0x99;
        fingerprintHeader[1] = (keyData.length >> 8) & 0xFF;
        fingerprintHeader[2] = keyData.length & 0xFF;
        
        [fingerprintData appendBytes:fingerprintHeader length:3];
        [fingerprintData appendData:keyData];
        
        Byte fingerprintOutput[SHA_DIGEST_LENGTH];
        SHA1(fingerprintData.bytes, fingerprintData.length, fingerprintOutput);
        
        _fingerprint = [Utility hexStringFromBytes:fingerprintOutput length:SHA_DIGEST_LENGTH];
    }
    
    return _fingerprint;
}

- (NSString *)keyID {
    if (_keyID == nil) {
        NSString *fingerprint = self.fingerprint;
        _keyID = [fingerprint substringWithRange:NSMakeRange(fingerprint.length - 16, 16)];
    }
    
    return _keyID;
}

@end

@interface SecretKey ()

- (instancetype)initWithPublicKey:(PublicKey *)publicKey
                                d:(MPI *)d
                                p:(MPI *)p
                                q:(MPI *)q
                                u:(MPI *)u;

@end

@implementation SecretKey

+ (SecretKey *)keyWithPublicKey:(PublicKey *)publicKey
                              d:(MPI *)d
                              p:(MPI *)p
                              q:(MPI *)q
                              u:(MPI *)u {
    
    return [[self alloc] initWithPublicKey:publicKey
                                         d:d
                                         p:p
                                         q:q
                                         u:u];
}

- (instancetype)initWithPublicKey:(PublicKey *)publicKey
                                d:(MPI *)d
                                p:(MPI *)p
                                q:(MPI *)q
                                u:(MPI *)u {
    
    self = [super init];
    
    if (self != nil) {
        _publicKey = publicKey;
        _d = d;
        _p = p;
        _q = q;
        _u = u;
    }
    
    return self;
}



@end
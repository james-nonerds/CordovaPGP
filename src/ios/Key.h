//
//  Key.h
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MPI.h"

@interface Key : NSObject

@property (nonatomic, strong) NSString *userId;
@property (nonatomic, readonly) NSArray *subkeys;

- (void)addSubkey:(Key *)subkey;

@end

@interface PublicKey : Key

@property (nonatomic, readonly) NSUInteger creationTime;

@property (nonatomic, readonly) NSString *fingerprint;
@property (nonatomic, readonly) NSString *keyID;

@property (nonatomic, readonly) MPI *n;
@property (nonatomic, readonly) MPI *e;

+ (PublicKey *)keyWithCreationTime:(NSUInteger)creationTime
                                 n:(MPI *)n
                                 e:(MPI *)e;

@end

@interface SecretKey : Key

@property (nonatomic, readonly) PublicKey *publicKey;

@property (nonatomic, readonly) MPI *d;
@property (nonatomic, readonly) MPI *p;
@property (nonatomic, readonly) MPI *q;
@property (nonatomic, readonly) MPI *u;

+ (SecretKey *)keyWithPublicKey:(PublicKey *)publicKey
                              d:(MPI *)d
                              p:(MPI *)p
                              q:(MPI *)q
                              u:(MPI *)u;

@end


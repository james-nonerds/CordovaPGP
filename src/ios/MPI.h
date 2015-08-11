//
//  MPI.h
//  OpenPGP
//
//  Created by James Knight on 6/24/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <openssl/BN.h>

@interface MPI : NSObject

@property (nonatomic, readonly) NSUInteger length;
@property (nonatomic, readonly) NSUInteger dataLength;
@property (nonatomic, readonly) BIGNUM *bn;

@property (nonatomic, readonly) NSData *data;
@property (nonatomic, readonly) NSData *mpiData;

+ (MPI *)mpiFromData:(NSData *)data;

+ (MPI *)mpiFromBytes:(const Byte *)bytes byteCount:(NSUInteger)byteCount;
+ (MPI *)mpiFromBytes:(const Byte *)bytes;

+ (MPI *)mpiWithBIGNUM:(BIGNUM *)bn;

@end

//
//  MPI.m
//  OpenPGP
//
//  Created by James Knight on 6/24/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "MPI.h"

@interface MPI () {
    BIGNUM *_bn;
}

- (id)initWithBIGNUM:(BIGNUM *)bn length:(NSUInteger)length;

@end

@implementation MPI

+ (MPI *)mpiFromData:(NSData *)data {
    return [self mpiFromBytes:data.bytes byteCount:data.length];
}

+ (MPI *)mpiFromBytes:(const Byte *)bytes byteCount:(NSUInteger)length {
    BIGNUM *bn = BN_bin2bn(bytes, (int) length, NULL);
    return [[self alloc] initWithBIGNUM:bn length:length];
}

+ (MPI *)mpiFromBytes:(const Byte *)bytes {
    NSUInteger bitCount = (bytes[0] << 8) | bytes[1];
    NSUInteger length = (bitCount + 7) / 8;  // Taken from NetPGP, poor man's CEIL.
    
    Byte mpiBytes[length];
    memcpy(mpiBytes, bytes + 2, length);
    
    BIGNUM *bn = BN_bin2bn(mpiBytes, (int) length, NULL);
    
    return [[self alloc] initWithBIGNUM:bn length:length + 2];
}

+ (MPI *)mpiWithBIGNUM:(BIGNUM *)bn {
    return [[self alloc] initWithBIGNUM:bn length:BN_num_bytes(bn)];
}


- (id)initWithBIGNUM:(BIGNUM *)bn length:(NSUInteger)length {
    self = [super init];
    
    if (self != nil) {
        _bn = BN_dup(bn);
        _length = length;
    }
    
    return self;
}

- (void)dealloc {
    BN_free(_bn);
    _bn = NULL;
}

- (BIGNUM *)bn {
    return _bn;
}

- (NSData *)data {
    NSUInteger len = BN_num_bytes(_bn);
    Byte *bytes = calloc(len + 2, sizeof(Byte));
    
    NSUInteger bitCount = BN_num_bits(_bn);
    bytes[0] = (bitCount >> 8) & 0xFF;
    bytes[1] = bitCount & 0xFF;
    
    BN_bn2bin(_bn, bytes + 2);
    
    return [NSData dataWithBytesNoCopy:bytes length:len + 2 freeWhenDone:YES];
}

- (NSData *)mpiData {
    NSUInteger len = BN_num_bytes(_bn);
    
    Byte *bytes = calloc(len, sizeof(Byte));
    BN_bn2bin(_bn, bytes);
    
    return [NSData dataWithBytesNoCopy:bytes length:len freeWhenDone:YES];
}

- (NSUInteger)dataLength {
    return BN_num_bytes(self.bn);
}

@end

//
//  Keypair.m
//  OpenPGP
//
//  Created by James Knight on 8/1/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "Keypair.h"

@implementation Keypair

+ (Keypair *)keypairWithPublicKey:(PublicKey *)publicKey secretKey:(SecretKey *)secretKey {
    return [[self alloc] initWithPublicKey:publicKey secretKey:secretKey];
}

- (instancetype)initWithPublicKey:(PublicKey *)publicKey secretKey:(SecretKey *)secretKey {
    self = [super init];
    
    if (self != nil) {
        _publicKey = publicKey;
        _secretKey = secretKey;
    }
    
    return self;
}

@end

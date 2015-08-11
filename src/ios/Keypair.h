//
//  Keypair.h
//  OpenPGP
//
//  Created by James Knight on 8/1/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>

@class PublicKey, SecretKey;

@interface Keypair : NSObject

@property (nonatomic, readonly) PublicKey *publicKey;
@property (nonatomic, readonly) SecretKey *secretKey;

+ (Keypair *)keypairWithPublicKey:(PublicKey *)publicKey secretKey:(SecretKey *)secretKey;

@end

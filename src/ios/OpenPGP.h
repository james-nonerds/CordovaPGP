//
//  OpenPGP.h
//  OpenPGP
//
//  Created by James Knight on 6/27/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface OpenPGP : NSObject

+ (void)decryptAndVerifyMessage:(NSString *)message
                     privateKey:(NSString *)privateKey
                     publicKeys:(NSArray *)publicKeys
                completionBlock:(void (^)(NSString *decryptedMessage, NSArray *verifiedUserIds))completionBlock
                     errorBlock:(void (^)(NSError *))errorBlock;


+ (void)signAndEncryptMessage:(NSString *)message
                   privateKey:(NSString *)privateKey
                   publicKeys:(NSArray *)publicKeys
              completionBlock:(void (^)(NSString *encryptedMessage))completionBlock
                   errorBlock:(void (^)(NSError *))errorBlock;


+ (void)generateKeypairWithOptions:(NSDictionary *)options
                   completionBlock:(void(^)(NSString *publicKey, NSString *privateKey))completionBlock
                        errorBlock:(void(^)(NSError *error))errorBlock;

@end

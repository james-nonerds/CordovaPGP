//
//  ViewController.m
//  PGP Demo
//
//  Created by James Knight on 6/4/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "ViewController.h"
#import "PGPLib.h"
#import "PGP.h"

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    NSString *userId = @"James Knight <james@jknight.co>";
    
    NSDictionary *options = @{@"keyType": @1,
                              @"numBits": @1024,
                              @"userId": userId,
                              @"unlocked": @NO};
    
    PGP *keyGenerator = [PGP keyGenerator];
    [keyGenerator generateKeysWithOptions:options completionBlock:^(NSString *publicKeyArmored, NSString *privateKeyArmored) {
        // Print result:
        NSLog(@"Public key:\n%@", publicKeyArmored);
        NSLog(@"Private key:\n%@", privateKeyArmored);
        
        NSString *testMessage = @"Testing message encryption.";
        
        // Encrypt the test message using the new key:
        PGP *encryptor = [PGP encryptorWithUserId:userId];
        [encryptor encryptData:[testMessage dataUsingEncoding:NSUTF8StringEncoding]
                     publicKey:publicKeyArmored
               completionBlock:^(NSData *result) {
                   NSLog(@"Encrypted message:\n%@", [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding]);
                   
                   PGP *decryptor = [PGP decryptorWithArmoredPrivateKey:privateKeyArmored];
                   
                   
                   // Decrypt the result:
                   [decryptor decryptData:result
                          completionBlock:^(NSData *result) {
                              NSLog(@"Decrypted message:\n%@", [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding]);
                   }
                               errorBlock:^(NSError *error) {
                                   NSLog(@"Error decrypting: %@", error);
                               }];
                   
              }
                    errorBlock:^(NSError *error) {
                        NSLog(@"Error encrypting: %@", error);
              }];
        
    } errorBlock:^(NSError *error) {
        NSLog(@"Error generating key: %@", error);
    }];
}

@end

//
//  ViewController.m
//  PGP Demo
//
//  Created by James Knight on 6/4/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "ViewController.h"
#import "PGP.h"

static NSString *const PGPUserId = @"James Knight <james@jknight.co>";

@interface ViewController ()

- (void)testKeyGeneration;

- (void)testEncryptionDecryptionWithPublicKey:(NSString *)publicKey
                                   privateKey:(NSString *)privateKey;

- (void)testSignAndVerifyWithPublicKey:(NSString *)publicKey
                             privateKey:(NSString *)privateKey;



@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self testKeyGeneration];
}

- (void)testKeyGeneration {
    NSDictionary *options = @{@"keyType": @1,
                              @"numBits": @1024,
                              @"userId": PGPUserId,
                              @"unlocked": @NO};
    
    PGP *keyGenerator = [PGP keyGenerator];
    [keyGenerator generateKeysWithOptions:options completionBlock:^(NSString *publicKeyArmored, NSString *privateKeyArmored) {
        // Print result:
        NSLog(@"Generated keys.");
        NSLog(@"Public key:\n%@", publicKeyArmored);
        NSLog(@"Private key:\n%@", privateKeyArmored);
        
        [self testEncryptionDecryptionWithPublicKey:publicKeyArmored privateKey:privateKeyArmored];
        [self testSignAndVerifyWithPublicKey:publicKeyArmored privateKey:privateKeyArmored];
        
        NSString *publicPath = [[NSBundle mainBundle] pathForResource:@"pubkey" ofType:@"gpg"];
        NSString *publicKey = [NSString stringWithContentsOfFile:publicPath encoding:NSUTF8StringEncoding error:nil];
        
        NSString *privatePath = [[NSBundle mainBundle] pathForResource:@"seckey" ofType:@"gpg"];
        NSString *privateKey = [NSString stringWithContentsOfFile:privatePath encoding:NSUTF8StringEncoding error:nil];
        
//        [self testSignAndVerifyWithPublicKey:publicKey privateKey:privateKey];
        
    } errorBlock:^(NSError *error) {
        NSLog(@"Error generating key: %@", error);
    }];
}

- (void)testEncryptionDecryptionWithPublicKey:(NSString *)publicKey
                                   privateKey:(NSString *)privateKey {
    NSString *testMessage = @"Testing encryption/decryption.";
    
    // Encrypt the test message using the new key:
    PGP *encryptor = [PGP encryptorWithUserId:PGPUserId];
    [encryptor encryptData:[testMessage dataUsingEncoding:NSUTF8StringEncoding]
                 publicKey:publicKey
           completionBlock:^(NSData *result) {
               PGP *decryptor = [PGP decryptorWithPrivateKey:privateKey];
               
               // Decrypt the result:
               [decryptor decryptData:result
                      completionBlock:^(NSData *result) {
                          NSString *decryptedMessage = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
                          NSLog(@"Decrypted message:\n%@", decryptedMessage);
                          if ([decryptedMessage isEqualToString:testMessage]) {
                              NSLog(@"SUCCESS: Source and result are equal.");
                          } else {
                              NSLog(@"FAILURE: Source and result are not equal.");
                              NSLog(@"Source: %@\n@Result: %@", testMessage, decryptedMessage);
                          }
                      } errorBlock:^(NSError *error) {
                          NSLog(@"FAILURE: Error decrypting.");
                      }];
               
           } errorBlock:^(NSError *error) {
               NSLog(@"FAILURE: Error encrypting.");
           }];
}


- (void)testSignAndVerifyWithPublicKey:(NSString *)publicKey
                             privateKey:(NSString *)privateKey {
    NSString *testMessage = @"Testing signing/verifying.";
    
    PGP *signer = [PGP signerWithPrivateKey:privateKey userId:PGPUserId];
    [signer signData:[testMessage dataUsingEncoding:NSUTF8StringEncoding] publicKey:publicKey completionBlock:^(NSData *result) {
         NSLog(@"Signed data: %@",  [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding]);
         
         PGP *verifier = [PGP verifier];
        [verifier verifyData:result publicKey:publicKey completionBlock:^(BOOL verified) {
            
             
         } errorBlock:^(NSError *error) {
             
         }];
     } errorBlock:^(NSError *error) {
              NSLog(@"FAILURE: Error signing.");
     }];
}

@end

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
    [self testMultipleEncryption];
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
        
    } errorBlock:^(NSError *error) {
        NSLog(@"Error generating key: %@", error);
    }];
}

- (void)testEncryptionDecryptionWithPublicKey:(NSString *)publicKey
                                   privateKey:(NSString *)privateKey {
    NSString *testMessage = @"Testing encryption/decryption.";
    
    // Encrypt the test message using the new key:
    PGP *encryptor = [PGP encryptor];
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

- (void)testMultipleEncryption {
    NSString *suzyPath = [[NSBundle mainBundle] pathForResource:@"suzy" ofType:@"gpg"];
    NSString *suzySecretPath = [[NSBundle mainBundle] pathForResource:@"suzysecret" ofType:@"gpg"];
    NSString *suzyPublic = [NSString stringWithContentsOfFile:suzyPath encoding:NSUTF8StringEncoding error:nil];
    NSString *suzyPrivate = [NSString stringWithContentsOfFile:suzySecretPath encoding:NSUTF8StringEncoding error:nil];
    
    NSString *bobPath = [[NSBundle mainBundle] pathForResource:@"bob" ofType:@"gpg"];
    NSString *bobSecretPath = [[NSBundle mainBundle] pathForResource:@"bobsecret" ofType:@"gpg"];
    NSString *bobPublic = [NSString stringWithContentsOfFile:bobPath encoding:NSUTF8StringEncoding error:nil];
    NSString *bobPrivate = [NSString stringWithContentsOfFile:bobSecretPath encoding:NSUTF8StringEncoding error:nil];
    
    NSString *stevePath = [[NSBundle mainBundle] pathForResource:@"steve" ofType:@"gpg"];
    NSString *steveSecretPath = [[NSBundle mainBundle] pathForResource:@"stevesecret" ofType:@"gpg"];
    NSString *stevePublic = [NSString stringWithContentsOfFile:stevePath encoding:NSUTF8StringEncoding error:nil];
    NSString *stevePrivate = [NSString stringWithContentsOfFile:steveSecretPath encoding:NSUTF8StringEncoding error:nil];
    
    NSString *testMessage = @"Testing multiple recipient encryption.";
    
    PGP *encyptor = [PGP encryptor];
    [encyptor encryptData:[testMessage dataUsingEncoding:NSUTF8StringEncoding]
               publicKeys:@[suzyPublic, bobPublic, stevePublic]
          completionBlock:^(NSData *result) {
              NSLog(@"Encrypted string: %@", [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding]);
              
              PGP *suzyDecryptor = [PGP decryptorWithPrivateKey:suzyPrivate];
              PGP *bobDecryptor = [PGP decryptorWithPrivateKey:bobPrivate];
              PGP *steveDecryptor = [PGP decryptorWithPrivateKey:stevePrivate];
              
              [suzyDecryptor decryptData:result completionBlock:^(NSData *result) {
                  NSString *decryptedMessage = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
                  NSLog(@"Decrypted message:\n%@", decryptedMessage);
                  if ([decryptedMessage isEqualToString:testMessage]) {
                      NSLog(@"SUCCESS: Suzy Source and result are equal.");
                  } else {
                      NSLog(@"FAILURE: Source and result are not equal.");
                      NSLog(@"Source: %@\n@Result: %@", testMessage, decryptedMessage);
                  }
                  
              } errorBlock:^(NSError *error) {
                  NSLog(@"FAILURE: Error decrypting Suzy.");
              }];
              
              [bobDecryptor decryptData:result completionBlock:^(NSData *result) {
                  
                  NSString *decryptedMessage = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
                  NSLog(@"Decrypted message:\n%@", decryptedMessage);
                  if ([decryptedMessage isEqualToString:testMessage]) {
                      NSLog(@"SUCCESS: Bob Source and result are equal.");
                  } else {
                      NSLog(@"FAILURE: Source and result are not equal.");
                      NSLog(@"Source: %@\n@Result: %@", testMessage, decryptedMessage);
                  }
              } errorBlock:^(NSError *error) {
                  NSLog(@"FAILURE: Error decrypting Bob.");
              }];
              
              [steveDecryptor decryptData:result completionBlock:^(NSData *result) {
                  
                  NSString *decryptedMessage = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
                  NSLog(@"Decrypted message:\n%@", decryptedMessage);
                  if ([decryptedMessage isEqualToString:testMessage]) {
                      NSLog(@"SUCCESS: Steve Source and result are equal.");
                  } else {
                      NSLog(@"FAILURE: Source and result are not equal.");
                      NSLog(@"Source: %@\n@Result: %@", testMessage, decryptedMessage);
                  }
              } errorBlock:^(NSError *error) {
                  NSLog(@"FAILURE: Error decrypting Steve.");
              }];
              
          } errorBlock:^(NSError *error) {
              NSLog(@"FAILURE: Error encrypting.");
          }];
}

@end

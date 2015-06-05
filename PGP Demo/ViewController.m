//
//  ViewController.m
//  PGP Demo
//
//  Created by James Knight on 6/4/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "ViewController.h"
#import "PGP.h"

@interface ViewController ()

@end

/* @param {module:enums.publicKey} [options.keyType=module:enums.publicKey.rsa_encrypt_sign]    to indicate what type of key to make.
*                             RSA is 1. See {@link http://tools.ietf.org/html/rfc4880#section-9.1}
    * @param {Integer} options.numBits    number of bits for the key creation. (should be 1024+, generally)
        * @param {String}  options.userId     assumes already in form of "User Name <username@email.com>"
    * @param {Boolean} [options.unlocked=false]    The secret part of the generated key is unlocked
 */
@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    NSDictionary *options = @{@"keyType": @1,
                              @"numBits": @1024,
                              @"userId": @"James Knight <james@jknight.co>",
                              @"unlocked": @NO};
    
    [PGP generateKeypairWithOptions:options onCompletion:^(NSDictionary *result) {
        NSLog(@"Success: %@", result);
    } onError:^(NSError *error) {
        NSLog(@"Failed to generate keypair: %@", error);
    }];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end

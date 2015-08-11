//
//  CordovaPGP.m
//  PGP Demo
//
//  Created by James Knight on 6/11/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import "CordovaPGP.h"
#import "OpenPGP.h"

typedef void (^CordovaPGPErrorBlock)(NSError *);


#pragma mark - CordovaPGP extension


@interface CordovaPGP ()

- (void(^)(NSError *))createErrorBlockForCommand:(CDVInvokedUrlCommand *)command;

@end


#pragma mark - CordovaPGP implementation


@implementation CordovaPGP


#pragma mark Methods


- (void)generateKeyPair:(CDVInvokedUrlCommand *)command {
    
    // Define error callback:
    CordovaPGPErrorBlock errorBlock = [self createErrorBlockForCommand:command];
    
    // Perform command:
    [self.commandDelegate runInBackground:^{
        NSDictionary *options = [command.arguments objectAtIndex:0];
        
        [OpenPGP generateKeypairWithOptions:options completionBlock:^(NSString *publicKey, NSString *privateKey) {
            
            NSDictionary *keys = @{@"privateKeyArmored": privateKey,
                                   @"publicKeyArmored": publicKey};
            
            CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                          messageAsDictionary:keys];
            
            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
            
        } errorBlock:errorBlock];
    }];
}


- (void)signAndEncryptMessage:(CDVInvokedUrlCommand *)command {
    
    // Define error callback:
    CordovaPGPErrorBlock errorBlock = [self createErrorBlockForCommand:command];
    
    // Perform command:
    [self.commandDelegate runInBackground:^{
        
        // Get the arguments from the command:
        NSArray *publicKeys = [command.arguments objectAtIndex:0];
        NSString *privateKey = [command.arguments objectAtIndex:1];
        NSString *text = [command.arguments objectAtIndex:2];
        
        [OpenPGP signAndEncryptMessage:text privateKey:privateKey publicKeys:publicKeys completionBlock:^(NSString *encryptedMessage) {
            
            CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                              messageAsString:encryptedMessage];
            
            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
            
        } errorBlock:errorBlock];
    }];
}


- (void)decryptAndVerifyMessage:(CDVInvokedUrlCommand *)command {
    
    // Define error callback:
    CordovaPGPErrorBlock errorBlock = [self createErrorBlockForCommand:command];
    
    // Perform command:
    [self.commandDelegate runInBackground:^{
        
        // Get the arguments from the command:
        NSString *privateKey = [command.arguments objectAtIndex:0];
        NSArray *publicKeys = [command.arguments objectAtIndex:1];
        NSString *msg = [command.arguments objectAtIndex:2];
        
        [OpenPGP decryptAndVerifyMessage:msg privateKey:privateKey publicKeys:publicKeys completionBlock:^(NSString *decryptedMessage, NSArray *verifiedUserIds) {
            
            NSArray *signatures = @[@{@"userId": verifiedUserIds.firstObject,
                                      @"valid": @YES}];
            
            NSDictionary *result = @{@"text": decryptedMessage,
                                     @"signatures": signatures};
            
            CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                          messageAsDictionary:result];
            
            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
            
        } errorBlock:errorBlock];
    }];
}


#pragma mark Private methods


- (void(^)(NSError *error))createErrorBlockForCommand:(CDVInvokedUrlCommand *)command {
    return ^(NSError *error) {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                                          messageAsString:error.description];
        
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    };
}

@end

//
//  HPPGP.m
//  iOS PGP
//
//  Created by James Knight on 6/3/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <netpgp.h>
#import "PGP.h"

static NSString *_homedir = nil;

#pragma mark - Helper functions

dispatch_queue_t getBackgroundQueue() {
    return dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0);
}

void dispatch_to_background(void (^block)()) {
    dispatch_async(getBackgroundQueue(), block);
}

void dispatch_to_main(void (^block)()) {
    dispatch_async(dispatch_get_main_queue(), block);
}

#pragma mark - PGP extension

@interface PGP ()

+ (netpgp_t *)initNetPGP;
+ (void)endNetPGP:(netpgp_t *)netpgp;

+ (NSString *)homedir;

+ (NSString *)generateTemporaryKeyId;
+ (NSString *)pathForKeyId:(NSString *)keyId;

+ (NSError *)errorWithCause:(NSString *)cause;

@end

#pragma mark - PGP implementation

@implementation PGP

#pragma mark Methods

/**
 * Generates a new OpenPGP key pair. Currently only supports RSA keys.
 * Primary and subkey will be of same type.
 * @param {module:enums.publicKey} [options.keyType=module:enums.publicKey.rsa_encrypt_sign]    to indicate what type of key to make.
 *                             RSA is 1. See {@link http://tools.ietf.org/html/rfc4880#section-9.1}
 * @param {Integer} options.numBits    number of bits for the key creation. (should be 1024+, generally)
 * @param {String}  options.userId     assumes already in form of "User Name <username@email.com>"
 * @param {Boolean} [options.unlocked=false]    The secret part of the generated key is unlocked
 * @return {Promise<Object>} {key: module:key~Key, privateKeyArmored: String, publicKeyArmored: String}
 * @static
 */

+ (void)generateKeypairWithOptions:(NSDictionary *)options
                      onCompletion:(void(^)(NSDictionary *result))onCompletion
                           onError:(void(^)(NSError *error))onError {
    
    // Execute on background queue:
    dispatch_to_background(^{
        // Make sure the key type passed in is RSA:
        NSNumber *keyType = options[@"keyType"] ?: @0;
        if (keyType.integerValue != 1) {
            dispatch_to_main(^{
                onError([self errorWithCause:[NSString stringWithFormat:@"Key type '%li' passed in, only key type '1' (RSA) supported.", (long) keyType.integerValue]]);
            });
        }
        
        netpgp_t *netpgp = [self initNetPGP];
        
        if (netpgp) {
            netpgp_setvar(netpgp, "userid checks", "skip");
            
            NSNumber *numBits = options[@"numBits"] ?: @0;
            NSString *userId = options[@"userId"] ?: @"";
            
            char keyName[userId.length + 1]; //+1 for terminating NULL character
            strcpy(keyName, userId.UTF8String);
            
            // Generate the key:
            if (!netpgp_generate_key(netpgp, keyName, numBits.intValue)) {
                // Generate failed:
                dispatch_to_main(^{
                    onError([self errorWithCause:@"Generate key failed."]);
                });
                
                [self endNetPGP:netpgp];
                return;
            }
            
            char *generated_id = netpgp_getvar(netpgp, "generated userid");
            
            NSString *generatedId = [NSString stringWithUTF8String:generated_id];
            NSString *keyFile = [generatedId stringByAppendingPathComponent:@"secring.gpg"];
            NSString *path = [[self homedir] stringByAppendingPathComponent:keyFile];
            
            netpgp_import_key(netpgp, (char *) path.UTF8String);
            
            // Export the key:
            char *key_data = netpgp_export_key(netpgp, keyName);
            NSString *keyString;
            
            if (!key_data) {
                // Could't find the key:
                dispatch_to_main(^{
                    onError([self errorWithCause:@"Couldn't find generated key."]);
                });
                
                [self endNetPGP:netpgp];
                return;
                
            } else {
                keyString = [NSString stringWithCString:key_data encoding:NSASCIIStringEncoding];
                free(key_data);
            }
        
            dispatch_to_main(^{
                onCompletion(nil);
            });
            
        } else {
            dispatch_to_main(^{
                onError([self errorWithCause:@"netpgp failed to init"]);
            });
        }
        
        [self endNetPGP:netpgp];
    });
}

+ (void)convertKeyToASCIIArmor:(NSString *)key onCompletion:(void (^)(NSString *))onCompletion {
    
}

+ (void)convertASCIIArmorToKey:(NSString *)asciiArmor onCompletion:(void (^)(NSString *))onCompletion {
    
}

+ (void)encryptMessageToASCIIArmor:(NSString *)message withPublicKeys:(NSArray *)publicKeys onCompletion:(void (^)(NSString *))onCompletion {
    
}

+ (void)decryptASCIIArmorToMessage:(NSString *)asciiArmor onCompletion:(void (^)(NSString *, NSString *))onCompletion {
    
}

#pragma mark Private

+ (netpgp_t *)initNetPGP {
    NSLog(@"Initializing NetPGP");
    netpgp_t *netpgp = (netpgp_t *) calloc(1, sizeof(netpgp_t));
    
    // Set the secret key ring path:
    netpgp_set_homedir(netpgp, (char *) [self homedir].UTF8String, NULL, 0);
    
    // User 4MB page for memory file:
    netpgp_setvar(netpgp, "max mem alloc", "4194304");
    netpgp_setvar(netpgp, "hash", "sha256");
    
    if (!netpgp_init(netpgp)) {
        NSLog(@"NetPGP failed to initialize.");
        free(netpgp);
        
        return NULL;
    }
    
    return netpgp;
}

+ (void)endNetPGP:(netpgp_t *)netpgp {
    NSLog(@"Ending NetPGP");
    
    if (netpgp != NULL) {
        netpgp_end(netpgp);
        free(netpgp);
    }
}

+ (NSString *)homedir {
    static dispatch_once_t once_token;
    
    dispatch_once(&once_token, ^{
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *documentDirectoryPath = ([paths count] > 0) ? [paths objectAtIndex:0] : nil;
        
#if TARGET_IPHONE_SIMULATOR
        if (![[NSFileManager defaultManager] fileExistsAtPath:documentDirectoryPath]) {
            [[NSFileManager defaultManager] createDirectoryAtPath:documentDirectoryPath withIntermediateDirectories:YES attributes:nil error:nil];
        }
#endif
        
        _homedir = documentDirectoryPath;
    });
    
    return _homedir;
}

+ (NSString *)generateTemporaryKeyId {
    return [NSUUID UUID].UUIDString;
}

+ (NSString *)pathForKeyId:(NSString *)keyId {
    return [[self homedir] stringByAppendingPathComponent:keyId];
}

+ (NSError *)errorWithCause:(NSString *)cause {
    return [NSError errorWithDomain:@"PGP"
                               code:-1
                           userInfo:@{@"reason": cause}];
}


@end

//
//  HPPGP.m
//  iOS PGP
//
//  Created by James Knight on 6/3/15.
//  Copyright (c) 2015 Gradient. All rights reserved.
//

#import <netpgp.h>
#import "PGPLib.h"

typedef NS_ENUM(NSUInteger, PGPKeytype) {
    PGPKeytypePrivate,
    PGPKeytypePublic
};

static NSString *const PGPPubringFilename = @"pubring.gpg";
static NSString *const PGPSecringFilename = @"secring.gpg";

static NSString *_homedir = nil;
static NSString *_secring = nil;
static NSString *_pubring = nil;

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

@interface PGPLib ()

+ (netpgp_t *)initNetPGP;
+ (netpgp_t *)initNetPGPWithOptions:(NSDictionary *)options;

+ (void)endNetPGP:(netpgp_t *)netpgp;

+ (NSString *)loadKeyWithType:(PGPKeytype)type forUserId:(NSString *)userId error:(NSError **)error;

+ (NSString *)homedirPath;
+ (NSString *)pubringPathForHomedir:(NSString *)homedir;
+ (NSString *)secringPathForHomedir:(NSString *)homedir;

+ (NSError *)errorWithCause:(NSString *)cause;

@end

#pragma mark - PGP implementation

@implementation PGPLib

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
            
            // Generate the key:
            if (!netpgp_generate_key(netpgp, (char *) userId.UTF8String, numBits.intValue)) {
                // Generate failed:
                dispatch_to_main(^{
                    onError([self errorWithCause:@"Generate key failed."]);
                });
                
                [self endNetPGP:netpgp];
                return;
            }
            
            // Get the generated ID from the keys:
            NSString *generatedId = [NSString stringWithUTF8String:netpgp_getvar(netpgp, "generated userid")];
            
            netpgp_t *netpgp_seckey = [self initNetPGPWithOptions:@{@"need seckey": @YES,
                                                                    @"homedir": [[self homedirPath] stringByAppendingPathComponent:generatedId]}];
            
            
            netpgp_list_keys(netpgp_seckey, 0);
//            char *test = netpgp_export_seckey(netpgp_seckey, (char *) generatedId.UTF8String);
//            NSLog(@"%s", test);

            char message[256];
            strcpy(message, "Hello!");
            
            char output[256];
            
            netpgp_encrypt_memory(netpgp_seckey, userId.UTF8String, message, 256, output, 256, 0);
            
            NSLog(@"%@", [NSString stringWithUTF8String:output]);
            
            char decrypt[256];
            
            netpgp_decrypt_memory(netpgp_seckey, output, 256, decrypt, 256, 0);
            
            NSLog(@"%@", [NSString stringWithUTF8String:decrypt]);
            
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

+ (NSString *)loadKeyWithType:(PGPKeytype)type forUserId:(NSString *)userId error:(NSError **)error {
    NSString *keyDirectory = [[self homedirPath] stringByAppendingPathComponent:userId];
    NSString *keyPath;
    
    switch (type) {
        case PGPKeytypePublic:
            keyPath = [keyDirectory stringByAppendingPathComponent:PGPPubringFilename];
            break;
            
        case PGPKeytypePrivate:
            keyPath = [keyDirectory stringByAppendingPathComponent:PGPSecringFilename];
            break;
    }
    
    return [NSString stringWithContentsOfFile:keyPath encoding:NSUTF8StringEncoding error:error];
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
    return [self initNetPGPWithOptions:nil];
}

+ (netpgp_t *)initNetPGPWithOptions:(NSDictionary *)options {
    options = options ?: @{};
    
    NSLog(@"Initializing NetPGP");
    netpgp_t *netpgp = (netpgp_t *) calloc(1, sizeof(netpgp_t));
    
    NSString *homedir = [options objectForKey:@"homedir"] ?: [self homedirPath];
    netpgp_set_homedir(netpgp, (char *) homedir.UTF8String, NULL, 0);
    
    netpgp_setvar(netpgp, "pubring", (char *) [self pubringPathForHomedir:homedir].UTF8String);
    netpgp_setvar(netpgp, "secring", (char *) [self secringPathForHomedir:homedir].UTF8String);
    
    // User 4MB page for memory file:
    netpgp_setvar(netpgp, "max mem alloc", "4194304");
    netpgp_setvar(netpgp, "hash", "sha256");
    
    if ([options objectForKey:@"need seckey"]) {
        netpgp_setvar(netpgp, "need seckey", "1");
    }
    
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

+ (NSString *)pathForKeyId:(NSString *)keyId {
    return [[self homedirPath] stringByAppendingPathComponent:keyId];
}

+ (NSError *)errorWithCause:(NSString *)cause {
    return [NSError errorWithDomain:@"PGPLib"
                               code:-1
                           userInfo:@{@"reason": cause}];
}

+ (NSString *)homedirPath {
    static dispatch_once_t once_token;
    
    dispatch_once(&once_token, ^{
        // Don't save keys, make sure we remove the last '/':
        NSURL *temporaryUrl = [NSURL fileURLWithPath:NSTemporaryDirectory()];
        NSString *homedir = [temporaryUrl.path stringByAppendingPathComponent:@"keys"];
        
        if (![[NSFileManager defaultManager] fileExistsAtPath:homedir]) {
            [[NSFileManager defaultManager] createDirectoryAtPath:homedir withIntermediateDirectories:YES attributes:nil error:nil];
        }
        
        _homedir = homedir;
    });
    
    return _homedir;
}

+ (NSString *)secringPathForHomedir:(NSString *)homedir {
    NSString *secring = [homedir stringByAppendingPathComponent:PGPSecringFilename];
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:secring]) {
        [[NSFileManager defaultManager] createFileAtPath:secring
                                                contents:nil
                                              attributes:@{NSFilePosixPermissions: [NSNumber numberWithShort:0600]}];
    }
    
    return secring;
}

+ (NSString *)pubringPathForHomedir:(NSString *)homedir {
    
    NSString *pubring = [homedir stringByAppendingPathComponent:PGPPubringFilename];
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:pubring]) {
        [[NSFileManager defaultManager] createFileAtPath:pubring
                                                contents:nil
                                              attributes:@{NSFilePosixPermissions: [NSNumber numberWithShort:0600]}];
    }
    
    return pubring;
}

@end

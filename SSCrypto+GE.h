/*
 Copyright (c) 2003-2006, Septicus Software All rights reserved.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are
 met:
 
 * Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer. 
 * Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution. 
 * Neither the name of Septicus Software nor the names of its contributors
 may be used to endorse or promote products derived from this software
 without specific prior written permission.
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
//
//  SSCrypto+GE.h
//  Xpeek
//
//  Created by Aidan Steele on 15/01/11.
//  Copyright 2011 Glass Echidna. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "SSCrypto.h"
#import <openssl/x509v3.h>
#import "SSCrypto+GE_Helpers.h"

typedef enum {
	kSSCryptoDataTypePrivateKey = 0,
	kSSCryptoDataTypeX509Certificate = 1,
} SSCryptoDataType;

@interface NSData (SSCrypto_GE)

- (BIO *)bio;
+ (id)dataWithBio:(BIO *)bio;
+ (id)dataWithCSSMData:(CSSM_DATA)cssmData;

@end

@interface SSCrypto ()

+ (SecKeyRef)SecKeyCreatePrivateKeyWithLength:(NSUInteger)lengthInBits;
+ (SecCertificateRef)certificateWithBaseCertificate:(SecCertificateRef)baseCert 
							   modifiedByDictionary:(NSDictionary *)dictionary 
									 withPrivateKey:(SecKeyRef)privateKey 
										   signedBy:(CFTypeRef)signer;

+ (NSData *)convertData:(NSData *)data ofType:(SSCryptoDataType)type fromFormat:(SSCryptoDataFormat)from toFormat:(SSCryptoDataFormat)to;

#pragma mark -
#pragma mark To be deprecated?
+ (SecIdentityRef)SecIdentityCreateWithDictionary:(NSDictionary *)dictionary signedByIdentity:(SecIdentityRef)signerIdentity;
+ (SecKeyRef)SecKeyCreateWithPrivateKeyBytes:(NSData *)privateKey format:(SSCryptoDataFormat)format;

+ (NSData *)X509CertificateForDictionary:(NSDictionary *)dictionary WithPrivateKey:(NSData *)privateKey;
+ (NSData *)X509CertificateForDictionary:(NSDictionary *)dictionary 
									  WithFormat:(SSCryptoDataFormat)certFormat 
								  WithPrivateKey:(NSData *)privateKey 
								   signedWithKey:(NSData *)caPrivateKey
									   keyFormat:(SSCryptoDataFormat)keyFormat;

@end

OSStatus SecKeyCreateWithCSSMKey(const CSSM_KEY *key, SecKeyRef* keyRef);
SecIdentityRef SecIdentityCreate(CFAllocatorRef allocator, SecCertificateRef certificate, SecKeyRef privateKey);
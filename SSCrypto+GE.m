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
//  SSCrypto+GE.m
//  Xpeek
//
//  Created by Aidan Steele on 15/01/11.
//  Copyright 2011 Glass Echidna. All rights reserved.
//

#import "SSCrypto+GE.h"
#import "CollectionUtils.h"
#import "NSFileManager+DirectoryLocations.h"

@implementation NSData (SSCrypto_GE)

- (BIO *)bio {
	BIO *bio = BIO_new_mem_buf((unsigned char *)[self bytes], [self length]);
	return bio;
}

+ (id)dataWithBio:(BIO *)bio {
	const char *bytes = NULL;
	NSUInteger length = BIO_get_mem_data(bio, &bytes);
	return [NSData dataWithBytes:bytes length:length];
}

+ (id)dataWithCSSMData:(CSSM_DATA)cssmData {
	return [NSData dataWithBytes:cssmData.Data length:cssmData.Length];
}

@end

@interface SSCrypto (GEPrivate)

static SecKeychainRef keychain = NULL; // TODO: global variable!
+ (void)generateCSSMKey:(CSSM_KEY *)key fromPrivateKey:(NSData *)privateKey format:(SSCryptoDataFormat)format;
+ (void)populateX509:(X509 *)x509 withDictionary:(NSDictionary *)dictionary;
+ (NSData *)dataFromSecKey:(SecKeyRef)keyRef;// withCSP:(CSSM_CSP_HANDLE)cspHandle;
+ (NSData *)openSSLPrivateKeyDataWithFormat:(SSCryptoDataFormat)format fromSecKeyData:(NSData *)data;

@end

void add_X509v3_ext(X509 *x, int nid, char *value);
CSSM_CSP_HANDLE initCSSM(BOOL raw);

@implementation SSCrypto (GE)

#pragma mark -
#pragma mark API methods

+ (SecKeyRef)SecKeyCreatePrivateKeyWithLength:(NSUInteger)lengthInBits {
	SecKeyRef public = NULL, private = NULL;
	SecKeyCreatePair(keychain, 
					 CSSM_ALGID_RSA, 
					 lengthInBits, 
					 0, 
					 CSSM_KEYUSE_ENCRYPT|CSSM_KEYUSE_VERIFY|CSSM_KEYUSE_WRAP,
					 CSSM_KEYATTR_EXTRACTABLE|CSSM_KEYATTR_PERMANENT,
					 CSSM_KEYUSE_ANY,
					 CSSM_KEYATTR_EXTRACTABLE|CSSM_KEYATTR_PERMANENT,
					 NULL, 
					 &public, 
					 &private);
	
	if (public) CFRelease(public);
	return private;
}

+ (SecCertificateRef)certificateWithBaseCertificate:(SecCertificateRef)baseCert 
							   modifiedByDictionary:(NSDictionary *)dictionary 
									 withPrivateKey:(SecKeyRef)privateKey 
										   signedBy:(CFTypeRef)signer {

	NSData *privateKeyData = [SSCrypto dataFromSecKey:privateKey];
	privateKeyData = [SSCrypto openSSLPrivateKeyDataWithFormat:kSSCryptoDataFormatDER fromSecKeyData:privateKeyData];
	
	SecKeyRef signerKey = NULL;
	BOOL releaseKey = NO;
	if (CFGetTypeID(signer) == SecKeyGetTypeID()) {
		signerKey = (SecKeyRef)signer;
	} else if (CFGetTypeID(signer) == SecIdentityGetTypeID()) {
		SecIdentityCopyPrivateKey((SecIdentityRef)signer, &signerKey);
		releaseKey = YES;
	} else {
		return NULL;
	}
	
	NSData *signerPrivateKeyData = [SSCrypto dataFromSecKey:signerKey];
	signerPrivateKeyData = [SSCrypto openSSLPrivateKeyDataWithFormat:kSSCryptoDataFormatDER fromSecKeyData:signerPrivateKeyData];
	
	BIO *bio_pkey = [privateKeyData bio];
	BIO *bio_spkey = [signerPrivateKeyData bio];
	
	EVP_PKEY *spk = d2i_PrivateKey_bio(bio_spkey, NULL);
	EVP_PKEY *pk = d2i_PrivateKey_bio(bio_pkey, NULL);
	
	X509 *x = NULL;
	if (baseCert) {
		CSSM_DATA certCSSMData = {0};
		SecCertificateGetData(baseCert, &certCSSMData);
		NSData *baseCertData = [NSData dataWithCSSMData:certCSSMData];
		BIO *bio_base = [baseCertData bio];
		
		x = d2i_X509_bio(bio_base, NULL);
	} else {
		x = X509_new();
		
		X509_set_version(x, 2);
		ASN1_INTEGER_set(X509_get_serialNumber(x), 0);
		X509_gmtime_adj(X509_get_notBefore(x), 0);
		X509_gmtime_adj(X509_get_notAfter(x), (long)60*60*24*365);
	}
	
	int loc = X509_get_ext_by_NID(x, NID_authority_key_identifier, -1);
	X509_delete_ext(x, loc);
	
	loc = X509_get_ext_by_NID(x, NID_subject_key_identifier, -1);
	X509_delete_ext(x, loc);
	
	[SSCrypto populateX509:x withDictionary:dictionary];
	
	if ([privateKeyData isEqualToData:signerPrivateKeyData]) {
		// self-signed, we'll assume it's a cert. authority
		add_X509v3_ext(x, NID_basic_constraints, "critical,CA:TRUE");
		add_X509v3_ext(x, NID_netscape_cert_type, "sslCA");
	}
	
	//add_X509v3_ext(x, NID_key_usage, "critical,keyCertSign,cRLSign");
	add_X509v3_ext(x, NID_subject_key_identifier, "hash");
	
	X509_set_pubkey(x, pk);
	X509_sign(x, spk, EVP_md5());
	
	BIO *bio_x509 = BIO_new(BIO_s_mem());
	i2d_X509_bio(bio_x509, x);
	NSData *certData = [NSData dataWithBio:bio_x509];
	
	BIO_free(bio_x509);
	if (releaseKey) CFRelease(signerKey);
	
	SecCertificateRef certificate = SecCertificateCreateWithData(kCFAllocatorDefault, (CFDataRef)certData);
	return certificate;
}


+ (NSData *)convertData:(NSData *)data 
				 ofType:(SSCryptoDataType)type 
			 fromFormat:(SSCryptoDataFormat)from 
			   toFormat:(SSCryptoDataFormat)to {
	void *dataStructure = NULL;
	
	BIO *fbio = [data bio];
	BIO *tbio = BIO_new(BIO_s_mem());
	
	switch (type) {
		case kSSCryptoDataTypePrivateKey:
			switch (from) {
				case kSSCryptoDataFormatDER:
					dataStructure = d2i_PrivateKey_bio(fbio, NULL);
					break;
				case kSSCryptoDataFormatPEM:
					dataStructure = PEM_read_bio_PrivateKey(fbio, NULL, NULL, NULL);
					break;
				default:
					return nil;
			}
			break;
			
		case kSSCryptoDataTypeX509Certificate:
			switch (from) {
				case kSSCryptoDataFormatDER:
					dataStructure = d2i_X509_bio(fbio, NULL);
					break;
				case kSSCryptoDataFormatPEM:
					dataStructure = PEM_read_bio_X509(fbio, NULL, NULL, NULL);
					break;
				default:
					return nil;
			}
			break;
			
		default:
			return nil;
	}
	
	switch (type) {
		case kSSCryptoDataTypePrivateKey:
			switch (to) {
				case kSSCryptoDataFormatDER:
					i2d_PrivateKey_bio(tbio, dataStructure);
					break;
				case kSSCryptoDataFormatPEM:
					PEM_write_bio_PrivateKey(tbio, dataStructure, NULL, NULL, 0, NULL, NULL);
					break;
				default:
					return nil;
			}
			break;
			
		case kSSCryptoDataTypeX509Certificate:
			switch (to) {
				case kSSCryptoDataFormatDER:
					i2d_X509_bio(tbio, dataStructure);
					break;
				case kSSCryptoDataFormatPEM:
					PEM_write_bio_X509(tbio, dataStructure);
					break;
				default:
					return nil;
			}
			break;
			
		default:
			return nil;	
	}
	
	NSData *retData = [NSData dataWithBio:tbio];
	
	BIO_free(fbio);
	BIO_free(tbio);
	
	return retData;
}

#pragma mark -
#pragma mark Utility methods

+ (void)initialize {
	if (self == [SSCrypto class]) {
		NSString *dir = [[NSFileManager defaultManager] applicationSupportDirectory];
		NSString *keychainPath = [dir stringByAppendingPathComponent:@"xpeek-keychain"];
		
		SecKeychainCreate([keychainPath UTF8String], 8, "password", NO, NULL, &keychain);
	}
}

+ (NSData *)dataFromSecKey:(SecKeyRef)keyRef {
	CSSM_RETURN crtn = 0;
	CSSM_CSP_HANDLE cspHandle = 0;
	CSSM_KEY *cssmKey = NULL;
	CSSM_WRAP_KEY wrappedKey = {0};
	CSSM_CC_HANDLE ccHandle = 0;
	
	
	CSSM_ACCESS_CREDENTIALS *creds = NULL;
	OSStatus err = SecKeyGetCredentials(keyRef,
                                        CSSM_ACL_AUTHORIZATION_IMPORT_WRAPPED,
                                        kSecCredentialTypeDefault,
                                        &creds);
	
	SecKeyGetCSSMKey(keyRef, (const CSSM_KEY **)&cssmKey);
	SecKeyGetCSPHandle(keyRef, &cspHandle);;
	
	crtn = CSSM_CSP_CreateSymmetricContext(cspHandle, 
									CSSM_ALGID_NONE,
									CSSM_ALGMODE_NONE, 
									creds, 
									NULL, 
									NULL, 
									CSSM_PADDING_NONE, 
									0, 
									&ccHandle);
	
	if (crtn) cssmPerror("CSSM_CSP_CreateSymmetricContext", crtn);

	crtn = CSSM_WrapKey(ccHandle, 
				 creds, 
				 cssmKey, 
				 NULL, 
				 &wrappedKey);

	if (crtn) cssmPerror("CSSM_WrapKey", crtn);
	
	return [NSData dataWithBytes:wrappedKey.KeyData.Data length:wrappedKey.KeyData.Length];
}

+ (NSData *)openSSLPrivateKeyDataWithFormat:(SSCryptoDataFormat)format fromSecKeyData:(NSData *)data {
	PKCS8_PRIV_KEY_INFO *p8 = NULL;
	EVP_PKEY *pkey = NULL;
	
	BIO *fbio = [data bio];
	BIO *tbio = BIO_new(BIO_s_mem());
	
	p8 = d2i_PKCS8_PRIV_KEY_INFO_bio(fbio, NULL);
	pkey = EVP_PKCS82PKEY(p8);
	
	i2d_PrivateKey_bio(tbio, pkey);
	NSData *pkeyData = [NSData dataWithBio:tbio];
	
	if (format != kSSCryptoDataFormatDER) {
		return [SSCrypto convertData:pkeyData
							  ofType:kSSCryptoDataTypePrivateKey
						  fromFormat:kSSCryptoDataFormatDER 
							toFormat:format];
		
	}
	
	return pkeyData;
}

CSSM_CSP_HANDLE initCSSM(BOOL raw)	{ // true ==> CSP, false ==> CSP/DL
	static CSSM_VERSION vers = {2, 0};
	static const CSSM_GUID testGuid = {0xFADE, 0, 0, {1, 2, 3, 4, 5, 6, 7, 0}};
	CSSM_GUID guid = testGuid;
	
	static CSSM_CSP_HANDLE cspHand = 0;
	
	if (cspHand) return cspHand;
	
	CSSM_RETURN	crtn;
	CSSM_PVC_MODE pvcPolicy = CSSM_PVC_NONE;
	
	crtn = CSSM_Init(&vers, 
					 CSSM_PRIVILEGE_SCOPE_NONE,
					 &testGuid,
					 CSSM_KEY_HIERARCHY_NONE,
					 &pvcPolicy,
					 NULL /* reserved */);
	if(crtn != CSSM_OK) 
	{
		cssmPerror("CSSM_Init", crtn);
		return 0;
	}
	
	guid = (raw) ? gGuidAppleCSP : gGuidAppleCSPDL;
	
	crtn = CSSM_ModuleLoad(&guid,
						   CSSM_KEY_HIERARCHY_NONE,
						   NULL,			// eventHandler
						   NULL);			// AppNotifyCallbackCtx
	if(crtn) {
		cssmPerror("CSSM_ModuleLoad", crtn);
		return 0;
	}
	
	
	crtn = CSSM_ModuleAttach (&guid,
							  &vers,
							  &memFuncs,			// memFuncs
							  0,					// SubserviceID
							  CSSM_SERVICE_CSP,	
							  0,					// AttachFlags
							  CSSM_KEY_HIERARCHY_NONE,
							  NULL,				// FunctionTable
							  0,					// NumFuncTable
							  NULL,				// reserved
							  &cspHand);
	if(crtn) {
		cssmPerror("CSSM_ModuleAttach", crtn);
		return 0;
	}
	return cspHand;
}

+ (void)generateCSSMKey:(CSSM_KEY *)key fromPrivateKey:(NSData *)privateKey format:(SSCryptoDataFormat)format {
	CSSM_KEY wrappedKey;
	CSSM_KEY unwrappedKey;
	CSSM_KEY_SIZE keySize;
	CSSM_ACCESS_CREDENTIALS	creds;
	CSSM_DATA descData = {0, NULL};
	CSSM_KEYHEADER_PTR hdr = &wrappedKey.KeyHeader;
	CSSM_CC_HANDLE ccHand = 0;
	CSSM_CSP_HANDLE cspHand = 0;
	CSSM_RETURN crtn = 0;
	
	NSData *canonicalDERPrivateKey = privateKey;
	if (format != kSSCryptoDataFormatDER) {
		canonicalDERPrivateKey = [SSCrypto convertData:privateKey 
												ofType:kSSCryptoDataTypePrivateKey 
											fromFormat:format 
											  toFormat:kSSCryptoDataFormatDER];
	}
	
	cspHand = initCSSM(NO);
	CSSM_CSP_HANDLE rawHand = initCSSM(YES); 
	
	/* importing a raw key into the CSPDL involves a NULL unwrap */
	memset(&unwrappedKey, 0, sizeof(CSSM_KEY));
	memset(&wrappedKey, 0, sizeof(CSSM_KEY));
	
	/* set up the imported key to look like a CSSM_KEY */
	hdr->HeaderVersion 			= CSSM_KEYHEADER_VERSION;
	hdr->BlobType 				= CSSM_KEYBLOB_RAW;
	hdr->AlgorithmId		 	= CSSM_ALGID_RSA;
	hdr->KeyClass 				= CSSM_KEYCLASS_PRIVATE_KEY;
	hdr->KeyAttr 				= CSSM_KEYATTR_EXTRACTABLE;
	hdr->KeyUsage 				= CSSM_KEYUSE_ANY;
	hdr->Format 				= CSSM_KEYBLOB_RAW_FORMAT_PKCS1; // CSSM_KEYBLOB_RAW_FORMAT_NONE	
	wrappedKey.KeyData.Data 	= (unsigned char *)[canonicalDERPrivateKey bytes];
	wrappedKey.KeyData.Length 	= [canonicalDERPrivateKey length];
	
	crtn = CSSM_QueryKeySizeInBits(rawHand, CSSM_INVALID_HANDLE, &wrappedKey, &keySize);
	if (crtn) cssmPerror("CSSM_QueryKeySizeInBits", crtn);
	
	hdr->LogicalKeySizeInBits = 2048;//keySize.LogicalKeySizeInBits;
	
	memset(&creds, 0, sizeof(CSSM_ACCESS_CREDENTIALS));
	crtn = CSSM_CSP_CreateSymmetricContext(cspHand,
										   CSSM_ALGID_NONE,			// unwrapAlg
										   CSSM_ALGMODE_NONE,			// unwrapMode
										   &creds,
										   NULL, 						// unwrappingKey
										   NULL,						// initVector
										   CSSM_PADDING_NONE, 			// unwrapPad
										   0,							// Params
										   &ccHand);
	if (crtn) cssmPerror("CSSM_CSP_CreateSymmetricContext", crtn);
	
	/* do the NULL unwrap */
	CSSM_KEYATTR_FLAGS attrFlags = CSSM_KEYATTR_RETURN_REF /*| CSSM_KEYATTR_SENSITIVE*/ | CSSM_KEYATTR_EXTRACTABLE;
	
	crtn = CSSM_UnwrapKey(ccHand,
						  NULL,				// PublicKey
						  &wrappedKey,
						  CSSM_KEYUSE_ANY,
						  attrFlags,
						  NULL,
						  NULL,				// CredAndAclEntry
						  &unwrappedKey,
						  &descData);		// required
	
	if (crtn != CSSM_OK) cssmPerror("CSSM_UnwrapKey", crtn);
	//if (cspHand) CSSM_ModuleDetach(cspHand);
	
	*key = unwrappedKey;
}

void add_X509v3_ext(X509 *x, int nid, char *value) {
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	
	X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex) return;
	
	X509_add_ext(x, ex, -1);
	X509_EXTENSION_free(ex);
	//return 1;
}

#define NSFORMAT8(x, v...) [[NSString stringWithFormat:x, v] UTF8String]
#define EXISTS(x) ([dictionary objectForKey:x] != nil)
+ (void)populateX509:(X509 *)x509 withDictionary:(NSDictionary *)dictionary {
	enum nameType { nameTypeIssuer, nameTypeSubject };
	
	void(^nameBlock)(enum nameType, BOOL)  = ^ (enum nameType type, BOOL destructive) { 
		NSString *nameKey = (NSString *)((type == nameTypeIssuer) ? kSSCryptoX509Issuer : kSSCryptoX509Subject);
		NSDictionary *nameDictionary = [dictionary objectForKey:nameKey];
		
		X509_NAME *name = NULL;
		if (destructive) {
			name = X509_NAME_new();
		} else {
			name = (type == nameTypeIssuer) ? X509_get_issuer_name(x509) : X509_get_subject_name(x509);
		}
		
		for (NSString *key in nameDictionary) {
			NSString *value = [nameDictionary objectForKey:key];
			X509_NAME_add_entry_by_txt(name, [key UTF8String], MBSTRING_UTF8, (const unsigned char *)[value UTF8String], -1, -1, 0);
		}
		
		if (destructive) {
			int ret = (type == nameTypeIssuer) ? X509_set_issuer_name(x509, name) : X509_set_subject_name(x509, name);
		}
	};
	
	BOOL hasSubject = ([dictionary objectForKey:kSSCryptoX509Subject] != nil);
	BOOL hasIssuer = ([dictionary objectForKey:kSSCryptoX509Issuer] != nil);
	
	nameBlock(nameTypeSubject, hasSubject); // do subject name
	nameBlock(nameTypeIssuer, hasIssuer); // do issuer name
	
	if (EXISTS(kSSCryptoX509SubjectAlternativeName)) 
		add_X509v3_ext(x509, NID_subject_alt_name, NSFORMAT8(@"DNS:%@", [dictionary objectForKey:kSSCryptoX509SubjectAlternativeName]));
	
}

@end

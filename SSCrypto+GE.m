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
#import "SSCrypto+GE_Helpers.h"

OSStatus SecKeyCreateWithCSSMKey(const CSSM_KEY *key, SecKeyRef* keyRef);
SecIdentityRef SecIdentityCreate(CFAllocatorRef allocator, SecCertificateRef certificate, SecKeyRef privateKey);

@interface SSCrypto (GEPrivate)

+ (void)generateCSSMKey:(CSSM_KEY *)key fromPrivateKey:(NSData *)privateKey format:(SSCryptoDataFormat)format;

@end

CSSM_CSP_HANDLE initCSSM()	{ // true ==> CSP, false ==> CSP/DL
	static CSSM_VERSION vers = {2, 0};
	static const CSSM_GUID testGuid = {0xFADE, 0, 0, {1, 2, 3, 4, 5, 6, 7, 0}};
	
	CSSM_CSP_HANDLE cspHand;
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
	
	crtn = CSSM_ModuleLoad(&gGuidAppleCSP,
						   CSSM_KEY_HIERARCHY_NONE,
						   NULL,			// eventHandler
						   NULL);			// AppNotifyCallbackCtx
	if(crtn) {
		cssmPerror("CSSM_ModuleLoad", crtn);
		return 0;
	}
	
	
	crtn = CSSM_ModuleAttach (&gGuidAppleCSP,
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

int add_X509v3_ext(X509 *cert, int nid, char *value) {
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex) return 0;
	
	X509_add_ext(cert, ex, -1);
	X509_EXTENSION_free(ex);
	return 1;
}

@implementation SSCrypto (GE)

+ (NSData *)convertData:(NSData *)data 
				 ofType:(SSCryptoDataType)type 
			 fromFormat:(SSCryptoDataFormat)from 
			   toFormat:(SSCryptoDataFormat)to {
	void *dataStructure = NULL;
	
	BIO *fbio = BIO_new_mem_buf((unsigned char *)[data bytes], [data length]);
	BIO *tbio = BIO_new(BIO_s_mem());
	
	switch (type) {
		case kSSCryptoDataTypePrivateKey:
			switch (from) {
				case kSSCryptoDataFormatDER:
					d2i_PrivateKey_bio(fbio, (EVP_PKEY **)&dataStructure);
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
					d2i_X509_bio(fbio, (X509 **)&dataStructure);
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
	
	char *tbio_bytes = NULL;
	int tbio_length = 0;
	tbio_length = BIO_get_mem_data(tbio, &tbio_bytes);
	NSData *retData = [NSData dataWithBytes:tbio_bytes length:tbio_length];
	
	BIO_free(fbio);
	BIO_free(tbio);
	
	return retData;
}

+ (SecKeyRef)SecKeyCreateWithPrivateKeyBytes:(NSData *)privateKey format:(SSCryptoDataFormat)format {
	CSSM_KEY cssmKey;
	SecKeyRef keyRef;
	
	[SSCrypto generateCSSMKey:&cssmKey fromPrivateKey:privateKey format:format];
	SecKeyCreateWithCSSMKey(&cssmKey, &keyRef);
	
	return keyRef;
}

+ (SecIdentityRef)SecIdentityCreateWithPrivateKeyBytes:(NSData *)privateKey format:(SSCryptoDataFormat)format {
	NSData *certDataDER = [SSCrypto generateX509CertificateWithFormat:kSSCryptoDataFormatDER 
													   WithPrivateKey:privateKey 
															keyFormat:format];
	
	SecCertificateRef certRef = SecCertificateCreateWithData(NULL, (CFDataRef)certDataDER);
	SecKeyRef keyRef = [SSCrypto SecKeyCreateWithPrivateKeyBytes:privateKey format:format];
	
	return SecIdentityCreate(kCFAllocatorDefault, certRef, keyRef);
}

+ (void)generateCSSMKey:(CSSM_KEY *)key fromPrivateKey:(NSData *)privateKey format:(SSCryptoDataFormat)format  {
	CSSM_KEY wrappedKey;
	CSSM_KEY unwrappedKey;
	CSSM_KEY_SIZE keySize;
	CSSM_ACCESS_CREDENTIALS	creds;
	CSSM_DATA labelData;
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
	
	cspHand = initCSSM();
	
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
	
	crtn = CSSM_QueryKeySizeInBits(cspHand, CSSM_INVALID_HANDLE, &wrappedKey, &keySize);
	if (crtn) cssmPerror("CSSM_QueryKeySizeInBits", crtn);
	
	hdr->LogicalKeySizeInBits = keySize.LogicalKeySizeInBits;
	
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
	crtn = CSSM_UnwrapKey(ccHand,
						  NULL,				// PublicKey
						  &wrappedKey,
						  CSSM_KEYUSE_ANY,
						  CSSM_KEYATTR_RETURN_REF | CSSM_KEYATTR_SENSITIVE | CSSM_KEYATTR_EXTRACTABLE,
						  NULL,,
						  NULL,				// CredAndAclEntry
						  &unwrappedKey,
						  &descData);		// required
	
	if (crtn != CSSM_OK) cssmPerror("CSSM_UnwrapKey", crtn);
	if (cspHand) CSSM_ModuleDetach(cspHand);
	
	*key = unwrappedKey;
}

+ (NSData *)generateX509CertificateWithPrivateKey:(NSData *)privateKey {
	return [SSCrypto generateX509CertificateWithFormat:kSSCryptoDataFormatPEM 
										WithPrivateKey:privateKey 
											 keyFormat:kSSCryptoDataFormatPEM];
}

+ (NSData *)generateX509CertificateWithFormat:(SSCryptoDataFormat)certFormat 
							   WithPrivateKey:(NSData *)privateKey 
									keyFormat:(SSCryptoDataFormat)keyFormat {
	EVP_PKEY *pk = NULL;
	X509 *x = NULL;
	X509_NAME *name = NULL;
	BIO *bio_pk = NULL;
	BIO *bio_x509 = NULL;
	char *bio_x509_data = NULL;
	
	bio_pk = BIO_new_mem_buf((unsigned char *)[privateKey bytes], [privateKey length]);
	
	switch (keyFormat) {
		case kSSCryptoDataFormatDER:
			d2i_PrivateKey_bio(bio_pk, &pk);
			break;
			
		case kSSCryptoDataFormatPEM:
			pk = PEM_read_bio_PrivateKey(bio_pk, NULL, NULL, NULL);
			break;
			
		default:
			return nil;
	}

	int serial = 0;
	int days = 365;
	
	x = X509_new();
	
	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
	X509_gmtime_adj(X509_get_notBefore(x), 0);
	X509_gmtime_adj(X509_get_notAfter(x), (long)60*60*24*days);
	X509_set_pubkey(x, pk);
	
	name = X509_get_subject_name(x);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *)"UK", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"OpenSSL Group", -1, -1, 0);
	
	X509_set_issuer_name(x, name);
	
	add_X509v3_ext(x, NID_basic_constraints, "critical,CA:TRUE");
	add_X509v3_ext(x, NID_key_usage, "critical,keyCertSign,cRLSign");
	add_X509v3_ext(x, NID_subject_key_identifier, "hash");
	add_X509v3_ext(x, NID_netscape_cert_type, "sslCA");
	add_X509v3_ext(x, NID_netscape_comment, "example comment extension");
	
	X509_sign(x, pk, EVP_md5());
	
	bio_x509 = BIO_new(BIO_s_mem());
	
	switch (certFormat) {
		case kSSCryptoDataFormatDER:
			i2d_X509_bio(bio_x509, x);
			break;
			
		case kSSCryptoDataFormatPEM:
			PEM_write_bio_X509(bio_x509, x);
			break;
			
		default:
			return nil;
	}
	
	int bio_x509_length = BIO_get_mem_data(bio_x509, &bio_x509_data);
	NSData *x509_data = [NSData dataWithBytes:bio_x509_data length:bio_x509_length];
	
	BIO_free(bio_pk);
	BIO_free(bio_x509);
	
	return x509_data;
}


@end

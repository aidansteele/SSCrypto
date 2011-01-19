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
/*
 *  SSCrypto+GE_Helpers.h
 *  Xpeek
 *
 *  Created by Aidan Steele on 16/01/11.
 *  Copyright 2011 Glass Echidna. All rights reserved.
 *
 */
#import <Foundation/Foundation.h>
#import <Security/Security.h>

void *AppMalloc(CSSM_SIZE size, void *allocRef);
void AppFree(void *mem_ptr, void *allocRef);
void *AppRealloc(void *ptr, CSSM_SIZE size, void *allocRef);
void *AppCalloc(uint32 num, CSSM_SIZE size, void *allocRef);

CSSM_API_MEMORY_FUNCS memFuncs;

extern const NSString *kSSCryptoX509Subject;
extern const NSString *kSSCryptoX509Issuer;

extern const NSString *kSSCryptoX509CommonName;
extern const NSString *kSSCryptoX509Organisation;
extern const NSString *kSSCryptoX509OrganisationUnit;
extern const NSString *kSSCryptoX509State;
extern const NSString *kSSCryptoX509Country;
extern const NSString *kSSCryptoX509Locality;
extern const NSString *kSSCryptoX509EmailAddress;

extern const NSString *kSSCryptoX509SerialNumber;
extern const NSString *kSSCryptoX509NotValidBefore;
extern const NSString *kSSCryptoX509NotValidAfter;

extern const NSString *kSSCryptoX509KeyUsage;
extern const NSString *kSSCryptoX509KeyUsageSignature;
extern const NSString *kSSCryptoX509KeyUsageNonRepudiation;
extern const NSString *kSSCryptoX509KeyUsageKeyAgreement;
extern const NSString *kSSCryptoX509KeyUsageCertificateSigning;
extern const NSString *kSSCryptoX509KeyUsageCRLSigning;
extern const NSString *kSSCryptoX509KeyUsageKeyEncipherment;
extern const NSString *kSSCryptoX509KeyUsageDataEncipherment;
extern const NSString *kSSCryptoX509KeyUsageEncipherOnly;
extern const NSString *kSSCryptoX509KeyUsageDecipherOnly;

extern const NSString *kSSCryptoX509ExtendedKeyUsage;
extern const NSString *kSSCryptoX509ExtendedKeyUsageSSLClient;
extern const NSString *kSSCryptoX509ExtendedKeyUsageSSLServer;
extern const NSString *kSSCryptoX509ExtendedKeyUsageCodeSigning;
extern const NSString *kSSCryptoX509ExtendedKeyUsagePKInitClient;
extern const NSString *kSSCryptoX509ExtendedKeyUsagePKInitServer;
extern const NSString *kSSCryptoX509ExtendedKeyUsageIChatSigning;
extern const NSString *kSSCryptoX509ExtendedKeyUsageIChatEncryption;
extern const NSString *kSSCryptoX509ExtendedKeyUsageDotMacEmailSigning;
extern const NSString *kSSCryptoX509ExtendedKeyUsageDotMacEmailEncryption;
extern const NSString *kSSCryptoX509ExtendedKeyUsageEmailProtection;

extern const NSString *kSSCryptoX509BasicConstraints;
extern const NSString *kSSCryptoX509BasicConstraintsCertificateAuthority;
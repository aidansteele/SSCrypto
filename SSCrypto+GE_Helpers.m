/*
 *  SSCrypto+GE_Helpers.m
 *  Xpeek
 *
 *  Created by Aidan Steele on 16/01/11.
 *  Copyright 2011 Glass Echidna. All rights reserved.
 *
 */

#include "SSCrypto+GE_Helpers.h"

/*
 * Standard app-level memory functions required by CDSA.
 */
void *AppMalloc(CSSM_SIZE size, void *allocRef) {
	return malloc(size);
}

void AppFree(void *mem_ptr, void *allocRef) {
	free(mem_ptr);
 	return;
}

void *AppRealloc(void *ptr, CSSM_SIZE size, void *allocRef) {
	return realloc(ptr, size);
}

void *AppCalloc(uint32 num, CSSM_SIZE size, void *allocRef) {
	return calloc(num, size);
}

CSSM_API_MEMORY_FUNCS memFuncs = {
	AppMalloc,
	AppFree,
	AppRealloc,
 	AppCalloc,
 	NULL
};

const NSString *kSSCryptoX509Subject = @"kSSCryptoX509Subject";
const NSString *kSSCryptoX509Issuer = @"kSSCryptoX509Issuer";

const NSString *kSSCryptoX509CommonName = @"CN";//@"kSSCryptoX509CommonName";
const NSString *kSSCryptoX509Organisation = @"O";//@"kSSCryptoX509Organisation";
const NSString *kSSCryptoX509OrganisationUnit = @"OU";//@"kSSCryptoX509OrganisationUnit";
const NSString *kSSCryptoX509State = @"ST";//@"kSSCryptoX509State";
const NSString *kSSCryptoX509Country = @"C";//@"kSSCryptoX509Country";
const NSString *kSSCryptoX509Locality = @"L";//@"kSSCryptoX509Locality";
const NSString *kSSCryptoX509EmailAddress = @"kSSCryptoX509EmailAddress";

const NSString *kSSCryptoX509SerialNumber = @"kSSCryptoX509SerialNumber";
const NSString *kSSCryptoX509NotValidBefore = @"kSSCryptoX509NotValidBefore";
const NSString *kSSCryptoX509NotValidAfter = @"kSSCryptoX509NotValidAfter";

const NSString *kSSCryptoX509KeyUsage = @"kSSCryptoX509KeyUsage";
const NSString *kSSCryptoX509KeyUsageSignature = @"kSSCryptoX509KeyUsageSignature";
const NSString *kSSCryptoX509KeyUsageNonRepudiation = @"kSSCryptoX509KeyUsageNonRepudiation";
const NSString *kSSCryptoX509KeyUsageKeyAgreement = @"kSSCryptoX509KeyUsageKeyAgreement";
const NSString *kSSCryptoX509KeyUsageCertificateSigning = @"kSSCryptoX509KeyUsageCertificateSigning";
const NSString *kSSCryptoX509KeyUsageCRLSigning = @"kSSCryptoX509KeyUsageCRLSigning";
const NSString *kSSCryptoX509KeyUsageKeyEncipherment = @"kSSCryptoX509KeyUsageKeyEncipherment";
const NSString *kSSCryptoX509KeyUsageDataEncipherment = @"kSSCryptoX509KeyUsageDataEncipherment";
const NSString *kSSCryptoX509KeyUsageEncipherOnly = @"kSSCryptoX509KeyUsageEncipherOnly";
const NSString *kSSCryptoX509KeyUsageDecipherOnly = @"kSSCryptoX509KeyUsageDecipherOnly";

const NSString *kSSCryptoX509ExtendedKeyUsage = @"kSSCryptoX509ExtendedKeyUsage";
const NSString *kSSCryptoX509ExtendedKeyUsageSSLClient = @"kSSCryptoX509ExtendedKeyUsageSSLClient";
const NSString *kSSCryptoX509ExtendedKeyUsageSSLServer = @"kSSCryptoX509ExtendedKeyUsageSSLServer";
const NSString *kSSCryptoX509ExtendedKeyUsageCodeSigning = @"kSSCryptoX509ExtendedKeyUsageCodeSigning";
const NSString *kSSCryptoX509ExtendedKeyUsagePKInitClient = @"kSSCryptoX509ExtendedKeyUsagePKInitClient";
const NSString *kSSCryptoX509ExtendedKeyUsagePKInitServer = @"kSSCryptoX509ExtendedKeyUsagePKInitServer";
const NSString *kSSCryptoX509ExtendedKeyUsageIChatSigning = @"kSSCryptoX509ExtendedKeyUsageIChatSigning";
const NSString *kSSCryptoX509ExtendedKeyUsageIChatEncryption = @"kSSCryptoX509ExtendedKeyUsageIChatEncryption";
const NSString *kSSCryptoX509ExtendedKeyUsageDotMacEmailSigning = @"kSSCryptoX509ExtendedKeyUsageDotMacEmailSigning";
const NSString *kSSCryptoX509ExtendedKeyUsageDotMacEmailEncryption = @"kSSCryptoX509ExtendedKeyUsageDotMacEmailEncryption";
const NSString *kSSCryptoX509ExtendedKeyUsageEmailProtection = @"kSSCryptoX509ExtendedKeyUsageEmailProtection";

const NSString *kSSCryptoX509BasicConstraints = @"kSSCryptoX509BasicConstraints";
const NSString *kSSCryptoX509BasicConstraintsCertificateAuthority = @"kSSCryptoX509BasicConstraintsCertificateAuthority";
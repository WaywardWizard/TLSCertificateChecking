/*
 * certVerifier.c
 *
 *  Created on: 13 May 2018
 *      Author: Ben Tomlin
 *   Student #: 834198
 */
#include "certVerifier.h"
#include "regexTool.h"
#include "logger.h"
#include "csvTool.h"
#include "dataStructure.h" // Provides dsa_t - "dynamic string array".

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

/*
#include <openssl/x509_vfy.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <time.h>


/* A wildcard is any contiguous sequence of WILDCARD not located after a literal '.'*/
#define WILDCARD "*"
#define WILDCARD_MATCHER "[^.]*[" WILDCARD "]+"
#define WILDCARD_MATCHES "[A-Za-z0-9-]"
#define ALLOWABLE_DOMAIN_CHAR "[A-Z*.a-z0-9-]+"

#define DN_MATCH 10239
#define DN_NOMATCH 2398

#define BITS_PER_BYTE 8
#define OUTPUT_FILENAME "output.csv"
#define MIN_ALLOWABLE_KEYLENGTH 2048

/* Maximum Possible length of text usage identifiers - 1 */
#define CERT_USAGE_BUFFER_LEN 512


X509* loadCertificate(char* path);
int verifyDomainName(dsa_t* a, const char* domain);
char* convertWildcardExpressionToRegex(const char* wString);
char* getASNString(const ASN1_STRING* s);
int verifyTimeValidity(const X509* cert);
void programExit(char* m, int status);
int getPublicKeyLength(const X509* cert);
char* getCommonName(const X509* cert);
dsa_t* getSubjectAlternativeName(const X509* cert);
BASIC_CONSTRAINTS* getBasicConstraints(const X509* cert);
EXTENDED_KEY_USAGE* getExtendedKeyUsage(const X509* cert);
int validateCertificate(const char* cPath, const char* domain, dsa_t* requiredKeyUsage);
int verifyExtendedKeyUsage(const X509* cert, dsa_t* requiredKeyUsage);

int main(int argc, char** argv) {

	/* Initialize*/
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	OPENSSL_config(NULL);

	/* String boolean value representation, 0|1*/
	char* certificateValidString=malloc(sizeof(char)*2); // null and 1|0 char
	int certificateValid;
	dsa_t* row;

	FILE* csv = fopen(argv[1],"r");
	FILE* outputCsv = fopen(OUTPUT_FILENAME, "w");

	/* Define usage requirements of certificates being validated. */
	dsa_t* usageRequirement = create_dsa();
	appendto_dsa(usageRequirement, "TLS Web Server Authentication");

	/* Iterate over certificates of CSV file */
	while((row=readRow(csv))!=NULL) {

		/*Extract certificate validation parameters */
		const char* certificatePath=getItem_dsa(row,0);
		const char* domain=getItem_dsa(row,1);

		/*Validate*/
		certificateValid=validateCertificate(certificatePath, domain, usageRequirement);
		snprintf(certificateValidString, ((size_t)2), "%d", certificateValid);

		/*Mutate input row to output row form and write out */
		appendto_dsa(row, certificateValidString);
		writeRow(outputCsv, row);
	}

	/* Cleanup */
	fclose(csv);
	fclose(outputCsv);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	return(0);
}

int validateCertificate(const char* cPath, const char* domain, dsa_t* requiredKeyUsage) {
	/**
	 * Validate certificate at <cPath> for <domain>
	 *
	 * A certificate is valid if,
	 * 		*) It is valid for current time.
	 * 		*) PKey for certificale has length >=2048bit
	 * 		*) Basic Constraints show CA:False
	 * 		*) Extended usage shows TLS Web Server Authentication
	 *
	 * ARGS:
	 * 		cPath - path to certificate to check
	 * 		domain - domain name against which to check certificate
	 *
	 * RETN:
	 * 		1 - Certificate valid for <domain>
	 * 		0 - Certificate invalid
	 *
	 * ASSN:
	 * 		All certificates have subject RSA keys
	 */

	const X509* cert = loadCertificate(cPath);

	/* Extract domain names */
	dsa_t* altName = getSubjectAlternativeName(cert);
	char* dName = getCommonName(cert);
	appendto_dsa(altName, dName);
	free(dName);

	/* Inspect certificate */
	int dateValid=(verifyTimeValidity(cert)==CT_VALID);
	int keyLength=getPublicKeyLength(cert);
	int keyLengthValid=(keyLength>=MIN_ALLOWABLE_KEYLENGTH);
	int domainValid = verifyDomainName(altName, domain);
	BASIC_CONSTRAINTS* certificateBasicConstraints = getBasicConstraints(cert);
	int basicConstraintCA = certificateBasicConstraints->ca;
	int usageValid = verifyExtendedKeyUsage(cert, requiredKeyUsage);

	/* Check validity */
	int certValid = dateValid \
			&& keyLengthValid
			&& (domainValid==DN_MATCH)
			&& !basicConstraintCA
			&& usageValid;

	return(certValid);
}

X509* loadCertificate(char* path){
	/**
	 * load certificate at <path>
	 */

	X509* cert = NULL;
	BIO* cBio = BIO_new(BIO_s_file());

	if (!(BIO_read_filename(cBio, path))){
		programExit("Failed to read certificate", EXIT_CERTLOAD_FAIL);
	}

	if (!(cert = PEM_read_bio_X509(cBio, NULL, 0 ,NULL))) {
		programExit("Failed to read certificate", EXIT_CERTLOAD_FAIL);
	}

	BIO_free(cBio);
	return cert;
}

dsa_t* getSubjectAlternativeName(const X509* cert) {

	dsa_t* a=create_dsa();

	/* Check for subject alternative name - data for san is a sequence
	 * of general names. (4.2.1.6 RFC5280) A sequence is represented internally in
	 * openssl as a STACK_OF(<seq_type>). We convert the serialized data to internal rep here. */
    STACK_OF(GENERAL_NAME)* saName = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    GENERAL_NAME* altName;

    while((altName=sk_GENERAL_NAME_pop(saName))!=NULL){
    	unsigned char* buffer;
    	/* Write any domain names (decoded from ia5string) into the dynamic string array */
    	if(altName->type==GEN_DNS){
			ASN1_STRING_to_UTF8(&buffer, altName->d.dNSName);
    		writeto_dsa(a, (char*)buffer, a->length);
    		free(buffer);
    	}
    }
    return(a);

}

EXTENDED_KEY_USAGE* getExtendedKeyUsage(const X509* cert) {
	return((EXTENDED_KEY_USAGE*)X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL));
}

int verifyExtendedKeyUsage(const X509* cert, dsa_t* usageRequired){
	/**
	 * Check <cert> is valid for <usageRequired>
	 *
	 * ARGS:
	 * 	cert - Certificate to check
	 * 	usageRequired - List of text usage identifiers to check
	 *
	 * RETN:
	 * 	1 - indicate cert is valid for all given usages. Otherwise 0
	 */

	EXTENDED_KEY_USAGE* certUsages = getExtendedKeyUsage(cert);
	const char* requiredUsageIdentifier;
	char certUsageIdBuffer[CERT_USAGE_BUFFER_LEN];
	int nCertUsage = sk_ASN1_OBJECT_num(certUsages);

	int hasCurrentRequiredUsage=0;

	/* Check each required usage is covered by the certificate */
	for(int ix=0;ix<(usageRequired->length);ix++){

		requiredUsageIdentifier=getItem_dsa(usageRequired, ix);

		/* Search for required usage in certificate usages */
		for(int ux=0;ux<nCertUsage;ux++){

			/* Extract certificate usage */
			const ASN1_OBJECT* certUsageItem = sk_ASN1_OBJECT_value(certUsages, ux);
			i2t_ASN1_OBJECT(certUsageIdBuffer, CERT_USAGE_BUFFER_LEN, certUsageItem);

			/* Check against usage needed */
			if (strcasecmp(certUsageIdBuffer, requiredUsageIdentifier)==0) {
				hasCurrentRequiredUsage=1;
				break;
			}
		}
		/* Search failed */
		if(!hasCurrentRequiredUsage){
			return(0);
		}
	}
	return(1);
}

BASIC_CONSTRAINTS* getBasicConstraints(const X509* cert) {
	return((BASIC_CONSTRAINTS*)X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL));
}

char* getCommonName(const X509* cert) {
	/**
	 * Return the common name for a certificate. Null if none.
	 */

	int lastpos=-1;
	int cnIndex;

	/* If the certificate has no subject Common Name it's invalid */
	X509_NAME* subject = X509_get_subject_name(cert);
	if ((cnIndex = X509_NAME_get_index_by_NID(subject,NID_commonName,lastpos))<0){
		return(NULL);
	}

	/* Extract the subject common name */
	X509_NAME_ENTRY* name=X509_NAME_get_entry(subject, cnIndex); // No need to free
	ASN1_STRING* cName = X509_NAME_ENTRY_get_data(name);		 //
	char* commonName = getASNString(cName);

	return(commonName);
}

int verifyDomainName(dsa_t* altNames, const char* domain){
	/**
	 * Given a list of domain names, check that the given domain matches any one of them.
	 *
	 * ARG:
	 * 	<nameList> - List of names, may contain wildcards
	 * 	<domain>   - domain to check names against for a match
	 *
	 * RETURN:
	 * 	DN_MATCH - <domain> matches some name in <nameList>
	 * 	DN_NOMATCH - <domain> does not match some name in <nameList>
	 */
	char* domainRegex=NULL;

	/* Check if certificate domain names match <domain> */
	for(int ix=0;ix<(altNames->length);ix++){
		domainRegex=convertWildcardExpressionToRegex(getItem_dsa(altNames, ix));
		int matchStatus = isMatch(domainRegex,domain);
		free(domainRegex);
		if(matchStatus==MATCH){
			return(DN_MATCH);
		}
	}
	return(DN_NOMATCH);
}

char* convertWildcardExpressionToRegex(const char* wString){
	/**
	 * Replace any wildcards found in <wString> with an equivalent ERE.
	 *
	 * wString must be null terminated. Wildcards are standins for any number
	 * of chars in WILDCARD_MATCHES (valid domain name chars)
	 *
	 * Wildcards can only occur in the leftmost portion of <wString>, where a
	 * portion is delineated with a '.' (as per WILDCARD_MATCHER)
	 *
	 * RETN:
	 *	 Return converted expression. Must be free'd
	 */
	char* buffer;
	char* result=strdup(wString);

	while((buffer=replaceMatch(WILDCARD_MATCHER, result, WILDCARD_MATCHES))!=NULL){
		free(result);
		result=buffer;
	}

	/* Return a copy of wString if it contains no wildcards. */
	return(result);
}

char* getASNString(const ASN1_STRING* s) {
	/**
	 * Return null terminated copy of asn1 string
	 */
	char* str;
	int needNull=0;
	int length=ASN1_STRING_length(s);

	/* String is empty*/
	if (length==0){
		str=malloc(sizeof(char)*1);
		str[0]='\0';

	} else {
		/* Note get0_data result should not be freed as per man page */
		const char* data=ASN1_STRING_data(s);

		/* Add a null byte if necessary */
		if(data[length-1]!='\0'){
			needNull=1;
		}

		str=malloc(sizeof(char)*(length+needNull));
		memcpy(str, data, length);

		/* Terminate with a null byte */
		if (needNull){
			str[length]='\0';
		}
	}
	return(str);
}

int verifyTimeValidity(const X509* cert){
	/**
	 * Given a certificate, verify it's valid for the current time
	 */

	int nDayBefore, nSecBefore, nDayAfter, nSecAfter;
	ASN1_TIME_diff(&nDayBefore, &nSecBefore, X509_get_notBefore(cert), NULL);
	ASN1_TIME_diff(&nDayAfter, &nSecAfter, NULL, X509_get_notAfter(cert));

	/* Time should be within not before and not after */
	if(nDayBefore<0 || nSecBefore<0 || nDayAfter<0 || nSecAfter<0){
		return(CT_INVALID);
	}

	/* Current time is within the certificate validity period.*/
	return(CT_VALID);
}

int getPublicKeyLength(const X509* cert){
	EVP_PKEY evpKey = X509_get_pubkey(cert);
	RSA* rsaKey = EVP_PKEY_get1_RSA(evpKey);
	EVP_PKEY_free(evpKey);
	RSA_free(rsaKey);
	int size = RSA_size(rsaKey)*BITS_PER_BYTE;
	/* 1.1 version: return(RSA_bits(EVP_PKEY_get1_RSA(X509_get_pubkey(cert))));*/
	return(size);
}

void programExit(char* m, int status) {
	mylog(m);
	exit(status);
}

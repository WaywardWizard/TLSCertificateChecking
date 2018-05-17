/*
 * certVericator.c
 *
 *  Created on: 13 May 2018
 *      Author: Ben Tomlin
 *   Student #: 834198
 */
#include "certVerifier.h"
#include "regexTool.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <openssl/objects.h>

#include <stdio.h>
#include <string.h>
#include <regex.h>
#include <time.h>

#define WILDCARD '*'
#define WILDCARD_MATCHES "[A-Za-z0-9-]"

X509* loadCertificate(char* path);
int verifyCommonName(X509* cert, char* testDomain);
char* convertWildcardExpressionToRegex(char* wString);
char* getASNString(ASN1_STRING* s);
int verifyValidity(X509* cert);
void programExit(char* m);
int getPublicKeyLength(X509* cert);


int main(int argc, char** argv) {

	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	char* cPath="certificates/testone.crt";
	X509* cert = loadCertificate(cPath);
	int nameValid=(verifyCommonName(cert, "derp.com")==CN_VALID);
	int dateValid=(verifyValidity(cert)==CT_VALID);
	int keyLength=getPublicKeyLength(cert);
	int block=1;
}


/**
 * Given a path to a certificate, load it into an X509 structure
 * and return it.
 */
X509* loadCertificate(char* path){

	X509* cert = NULL;
	BIO* cBio = BIO_new(BIO_s_file());

	if (!(BIO_read_filename(cBio, path))){
		programExit("Failed to read certificate");
	}

	if (!NULL){
		programExit("!NULL is true");
	}

	if (!(cert = PEM_read_bio_X509(cBio, NULL, 0 ,NULL))) {
		programExit("Failed to read certificate");
	}

	BIO_free(cBio);
	return cert;
}


int verifyCommonName(X509* cert, char* testDomain) {
	/**
	 * Check the given testDomain is covered by the certificate subject common
	 * name.
	 */

	int lastpos=-1;
	int cnIndex;

	/* If the certificate has no subject Common Name it's invalid */
	X509_NAME* subject = X509_get_subject_name(cert);
	if ((cnIndex = X509_NAME_get_index_by_NID(subject,NID_commonName,lastpos))<0){
		return(CN_INVALID);
	}

	/* Extract the subject common name */
	X509_NAME_ENTRY* name=X509_NAME_get_entry(subject, cnIndex);
	ASN1_STRING* cName = X509_NAME_ENTRY_get_data(name);
	char* commonName = getASNString(cName);

	/* Check the common name is valid. Convert common name to regex that shall
	 * match any domain name which it covers */
	char* commonNameRegex=convertWildcardExpressionToRegex(commonName);
	free(commonName);

	/* Check if certificate domain regex matches the domain */
	if(isMatch(commonNameRegex,testDomain)){
		return(CN_VALID);
	}
	return(CN_INVALID);
}


char* convertWildcardExpressionToRegex(char* wString){
	/**
	 * Replace any wildcards found in wString with an equivalent ERE.
	 *
	 * wString must be null terminated.
	 *
	 * Wildcards are standins for any number of chars in WILDCARD_MATCHES
	 *
	 * Return converted expression. Must be free'd
	 */

	/* Return the string it'self if it contains no wildcards*/
	if (strchr(wString,WILDCARD)==NULL){
		return(strdup(wString));
	}

	/* Replace wildcard with it's equivalent regex */

	/* Count wildcards in string */
	int lastCharMatched=0;
	int nWildCard=0;
	for (char* scanner=wString;
			strchr(scanner, WILDCARD)!=NULL;
			scanner=(strchr(scanner,WILDCARD))+1){

		if (*scanner == WILDCARD){
			if(!lastCharMatched){nWildCard++;}
			lastCharMatched=1;
		} else {
			lastCharMatched=0;
		}
	}

	/* Calculate string length of regex to be returned */
	int regexLength=strlen(wString)\
						+ ((strlen(WILDCARD_MATCHES)-1)*nWildCard) + 1;

	char* convertedString=malloc(sizeof(char)*regexLength);
	char* cScanner=convertedString;
	char* wildcardReplacement=WILDCARD_MATCHES;
	int   wildcardReplacementLength=strlen(wildcardReplacement);

	/* Assemble regex from source string*/
	char* lastMatch=wString;
	char* scanner=wString;
	for (;strchr(scanner, WILDCARD)!=NULL; scanner=(strchr(scanner,WILDCARD)+1)) {

		int delta = scanner-lastMatch-(lastMatch!=wString);

		/* Ignoring the wildcard, copy everything from the last wildcard to current wc.*/
		memcpy(cScanner,scanner, delta);
		cScanner+=delta;

		/* Replace wildcard with equivalent regex */
		memcpy(cScanner,wildcardReplacement, wildcardReplacementLength);
		cScanner+=wildcardReplacementLength;

		lastMatch=scanner;
	}

	/* Write remainder of source string and terminate with a null byte */
	memcpy(cScanner,scanner,strlen(scanner));
	cScanner+=strlen(scanner);
	cScanner[0]='\0';

	return(convertedString);
}


char* getASNString(ASN1_STRING* s) {
	/**
	 * Return null terminated copy of asn1 string
	 */
	char* str;
	int needNull=0;
	int l = ASN1_STRING_length(s);

	/* String is empty*/
	if (l==0){
		str=malloc(sizeof(char)*1);
		str[0]='\0';

	} else {
		/* Note this data should not be freed as per man page */
		const char* data=ASN1_STRING_get0_data(s);

		/* Add a null byte if necessary */
		if(data[l-1]!='\0'){
			needNull=1;
		}

		str=malloc(sizeof(char)*(l+needNull));
		memcpy(str, data, l);

		/* Terminate with a null byte */
		if (needNull){
			str[l]='\0';
		}
	}

	return(str);
}


int verifyValidity(X509* cert){
	/**
	 * Given a certificate, verify it's valid for the current time
	 */
	int now = time(NULL);

	/* Time should be earlier than or equal to current time */
	if(X509_cmp_current_time(X509_get0_notBefore(cert))>0){
		return(CT_INVALID);
	}

	/* Time should be later than or equal to current time */
	if(X509_cmp_current_time(X509_get0_notAfter(cert))<0){
		return(CT_INVALID);
	}
	/* Current time is within the certificate validity period.*/
	return(CT_VALID);
}


int getPublicKeyLength(X509* cert){
	return(RSA_bits(EVP_PKEY_get0_RSA(X509_get0_pubkey(cert))));
}

void programExit(char* m) {
	printf(m);
}


/*
 * certVericator.c
 *
 *  Created on: 13 May 2018
 *      Author: Ben Tomlin
 *   Student #: 834198
 */
#include "certVerifier.h"
#include "regexTool.h"
#include "logger.h"
#include "dataStructure.h" // Provides dsa_t - "dynamic string array".

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/x509_vfy.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>


#include <openssl/objects.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <time.h>

#define WILDCARD '*'
#define WILDCARD_MATCHES "[A-Za-z0-9-]"
#define ALLOWABLE_DOMAIN_CHAR "[A-Z*.a-z0-9-]+"

#define DN_MATCH 10239
#define DN_NOMATCH 2398


X509* loadCertificate(char* path);
int verifyDomainName(dsa_t* a, char* domain);
char* convertWildcardExpressionToRegex(char* wString);
char* getASNString(const ASN1_STRING* s);
int verifyTimeValidity(const X509* cert);
void programExit(char* m, int status);
int getPublicKeyLength(const X509* cert);
char* getCommonName(const X509* cert);
dsa_t* getSubjectAlternativeName(const X509* cert);
BASIC_CONSTRAINTS* getBasicConstraints(const X509* cert);
EXTENDED_KEY_USAGE* getExtendedKeyUsage(const X509* cert);

int main(int argc, char** argv) {

	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	char* cPath="test/certificates/testnine.crt";
	const X509* cert = loadCertificate(cPath);
	int dateValid=(verifyTimeValidity(cert)==CT_VALID);
	int keyLength=getPublicKeyLength(cert);

	/* Extract domain names */
	dsa_t* altName = getSubjectAlternativeName(cert);
	char* dName = getCommonName(cert);
	writeto_dsa(altName, dName, altName->length);
	free(dName);
	BASIC_CONSTRAINTS* bc = getBasicConstraints(cert);
	EXTENDED_KEY_USAGE* ku = getExtendedKeyUsage(cert);
	int n = sk_ASN1_OBJECT_num(ku);
	char* dataValue=malloc(sizeof(char)*1024);
	dataValue=(char*)realloc(dataValue, OBJ_obj2txt(dataValue, 1024, sk_ASN1_OBJECT_pop(ku), 0));

	verifyDomainName(altName, "derp.com");
}


/**
 * Given a path to a certificate, load it into an X509 structure
 * and return it.
 */
X509* loadCertificate(char* path){

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

int verifyDomainName(dsa_t* a, char* domain){
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
	for(int ix=0;ix<(a->length);ix++){
		domainRegex=convertWildcardExpressionToRegex(a->array[ix]);
		int matchStatus = isMatch(domainRegex,domain);
		if(matchStatus==MATCH){
			free(domainRegex);
			return(DN_MATCH);
		}
		free(domainRegex);
	}
	return(DN_NOMATCH);
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
		const char* data=ASN1_STRING_get0_data(s);

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

int getPublicKeyLength(const X509* cert){
	return(RSA_bits(EVP_PKEY_get0_RSA(X509_get0_pubkey(cert))));
}

void programExit(char* m, int status) {
	mylog(m);
	exit(status);
}

/*
 * Author: 			Ben Tomlin
 * Student Id:		btomlin
 * Student Nbr:		834198
 * Date:			Apr 2018
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "regexTool.h"
#include "logger.h"
#include "dataStructure.h"

#define true 1
#define false 0

dsa_t* extractAllMatch(const char* regex, const char* searchString){
	dsa_t* array=create_dsa();
	int ix=0;
	char* buffer;
	while( (searchString=extractMatch(regex, searchString, &buffer))!=NULL){
		writeto_dsa(array, buffer, ix++);
	}
	return(array);
}

const char* extractMatch(const char* regex, const char* searchString, char** destination) {
	/**
	 * Search <string> for match with <regex> Write match into <destination>
	 *
	 * Terminates if an error occured
	 *
	 * ARGUMENT:
	 *
	 * 	destination - 	this is an allocated pointer address. *destination will be
	 * 	allocated, and then the match will be written into the allocated memory.
	 * 	The match will be terminated with a null byte.
	 *
	 * 	searchString - string to search
	 *
	 * 	regex		 - Posix ERE to match with
	 *
	 * RETURN:
	 * 		NULL if no match.
	 * 		Else, pointer to remainder of search string. This is the first character
	 * 		after the match
	 *
	 * NOTE:
	 * 	always uses extended regexes
	 */

	regmatch_t* match = findMatch(regex,searchString);

	/* Allocate destination memory & write match into destination */
	if (match!=NULL) {
		int matchSize = (*match).rm_eo-(*match).rm_so;
		*destination = malloc(matchSize+1);
		strncpy(*destination, searchString+match->rm_so, matchSize);
		(*destination)[matchSize]='\0';
		return(searchString+match->rm_eo);
	}

	free(match);

	/* No match found */
	return(NULL);
}

regmatch_t* findMatch(const char* regex, const char* searchString) {
	/**
	 * Search <string> for match with <regex> and return a structure encoding its address
	 *
	 * Program terminates if <regex> cannot be compiled
	 *
	 * ARGUMENT:
	 * 	searchString - string to search
	 * 	regex		 - Posix ERE to match with. $ metachar ignored.
	 *
	 * RETURN:
	 * 		NULL if no match.
	 * 		regmatch_t* match location. User is responsible for freeing this
	 *
	 * NOTE:
	 * 	always uses extended regexes.
	 */
	regex_t rx;
	regmatch_t* match=malloc(sizeof(regmatch_t));

	int errSize=100; // Default error message size
	int error = regcomp(&rx, regex, REG_EXTENDED);
	int matchSize;

	/* Check compilation sucessful */
	if(error!=0){
		char errorMessage[errSize];
		regerror(error,&rx,errorMessage,errSize);
		mylog("Regex compilation error");
		mylog(errorMessage);
		exit(EREGCOMP);
	}

	/* Match */
	error = regexec(&rx,searchString, 1, match, REG_NOTEOL);
	regfree(&rx);

	if (error!=REG_NOMATCH) {
		return(match);
	}

	/* No match found */
	return(NULL);
}

char* jumpMatch(const char* regex, const char* searchString) {
	/**
	 * Return location of string remainder, after a given match. Used to count matches
	 */

	regmatch_t* match = findMatch(regex, searchString);
	char* remainder=NULL;

	if(match!=NULL){
		const char* remainder = searchString+match->rm_eo;
		free(match);
	}

	return(remainder);
}

int isMatch(const char* regex, const char* searchString){
	/**
	 * Return true/false indicating wether <regex> matches <searchString>
	 */
	regex_t rx;
	regmatch_t match;
	int errSize=100; // Default error message size
	int error = regcomp(&rx, regex, REG_EXTENDED);
	int matchSize;

	/* Check compilation sucessful */
	if(error!=0){
		char errorMessage[errSize];
		regerror(error,&rx,errorMessage,errSize);
		mylog("Regex compilation error");
		mylog(errorMessage);
		exit(EREGCOMP);
	}

	/* Match */
	error = regexec(&rx,searchString, 1, &match, 0);
	regfree(&rx);

	/* Return indicating if a match was found */
	if(error!=REG_NOMATCH){
		return MATCH;
	}
	return NOMATCH;
}

char* replaceMatch(const char* regex, const char* source, char* replacement) {
	/**
	 * Replace all match of <regex> in <source> with <replacement>
	 *
	 * ARGS:
	 * 	<regex> null terminated regext to match
	 * 	<source> source string
	 * 	<replacement> string to replace entire match with
	 *
	 * RETN:
	 * 	NULL if no matches. Else source with the first match replaced. User must free.
	 *
	 * NOTE:
	 * 	all arguments must be null terminated
	 */
	regmatch_t* match = findMatch(regex, source);
	if(match==NULL){return(NULL);}
	int matchLength = match->rm_eo-match->rm_so;
	int matchPrefixLength = match->rm_so;
	int replacementLength=strlen(replacement);
	int sourceLength=strlen(source);
	int resultLength=(sourceLength-matchLength+replacementLength);

	/* Memory for new string, assumes match never contains terminating null byte */
	char* newString = malloc(sizeof(char)*(resultLength+1));

	/* Assemble new string */
	char* newStringScanner = newString;

	/* Copy over what lies before match */
	if(match->rm_so>0){
		memcpy(newStringScanner, source, matchPrefixLength);
	}
	newStringScanner+=matchPrefixLength;

	memcpy(newStringScanner, replacement, replacementLength);
	newStringScanner+=replacementLength;

	strcpy(newStringScanner, source+match->rm_eo);

	free(match);
	return(newString);
}

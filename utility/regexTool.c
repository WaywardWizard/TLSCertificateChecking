/*
 * Author: 			Ben Tomlin
 * Student Id:		btomlin
 * Student Nbr:		834198
 * Date:			Apr 2018
 */

#include <regex.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "regexTool.h"
#include "logger.h"
#include "dataStructure.h"

#define true 1
#define false 0

dsa_t* extractAllMatch(char* regex, char* searchString){
	dsa_t* array=create_dsa();
	int ix=0;
	char* buffer;
	while( (searchString=extractMatch(regex, searchString, &buffer))!=NULL){
		writeto_dsa(array, buffer, ix++);
	}
	return(array);
}

char*
extractMatch(char* regex, char* searchString, char** destination) {
	/**
	 * Search <string> for match with <regex> Write match into <destination>
	 *
	 * Terminates if an error occured
	 *
	 * ARGUMENT:
	 * 	destination - this is an allocated pointer address. *destination will be
	 * 	allocated, and then the match will be written into the allocated memory.
	 * 	The match will be terminated with a null byte.
	 *
	 * 	searchString - string to search
	 * 	regex		 - Posix ERE to match with
	 *
	 * RETURN:
	 * 		NULL if no match.
	 * 		Else, pointer to remainder of search string.
	 *
	 * NOTE:
	 * 	always uses extended regexes
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

	/* Allocate destination memory & write match into destination */
	if (error!=REG_NOMATCH) {
		matchSize = match.rm_eo-match.rm_so;
		*destination = malloc(matchSize+1);
		strncpy(*destination, searchString+match.rm_so, matchSize);
		(*destination)[matchSize]='\0';
		return(searchString+match.rm_eo);
	}

	/* No match found */
	return(NULL);
}

int isMatch(char* regex, char* searchString){
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

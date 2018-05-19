/*
 * Author: 			Ben Tomlin
 * Student Id:		btomlin
 * Student Nbr:		834198
 * Date:			Apr 2018
 */

#ifndef UTILITY_REGEXTOOL_H_
#define UTILITY_REGEXTOOL_H_

#include "dataStructure.h"
#include <regex.h>

#define EREGCOMP 889
#define MATCH 1
#define NOMATCH 0

const char* extractMatch(const char* regex, const char* searchString, char** destination);
dsa_t* extractAllMatch(const char* regex, const char* searchString);
int isMatch(const char* regex, const char* searchString);
regmatch_t* findMatch(const char* regex, const char* searchString);
char* jumpMatch(const char* regex, const char* searchString);
char* replaceMatch(const char* regex, const char* source, char* replacement);

#endif /* UTILITY_REGEXTOOL_H_ */

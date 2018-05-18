/*
 * Author: 			Ben Tomlin
 * Student Id:		btomlin
 * Student Nbr:		834198
 * Date:			Apr 2018
 */

#ifndef UTILITY_REGEXTOOL_H_
#define UTILITY_REGEXTOOL_H_

#include "dataStructure.h"

#define EREGCOMP 889
#define MATCH 1
#define NOMATCH 0

char* extractMatch(char* regex, char* searchString, char** destination);
dsa_t* extractAllMatch(char* regex, char* searchString);
int isMatch(char* regex, char* searchString);

#endif /* UTILITY_REGEXTOOL_H_ */

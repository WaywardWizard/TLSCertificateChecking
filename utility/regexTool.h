/*
 * Author: 			Ben Tomlin
 * Student Id:		btomlin
 * Student Nbr:		834198
 * Date:			Apr 2018
 */

#ifndef UTILITY_REGEXTOOL_H_
#define UTILITY_REGEXTOOL_H_

#define EREGCOMP 889

char* extractMatch(char* regex, char* searchString, char** destination);
int isMatch(char* regex, char* searchString);

#endif /* UTILITY_REGEXTOOL_H_ */

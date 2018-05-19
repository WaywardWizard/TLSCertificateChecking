/*
 * csvTool.h
 *
 *  Created on: 13 May 2018
 *      Author: Ben Tomlin
 *   Student #: 834198
 */
#include <stdlib.h>
#include <stdio.h>
#include "dataStructure.h"

#ifndef CSVTOOL_H_
#define CSVTOOL_H_

dsa_t* readRow(FILE *f);
void writeRow(FILE *f, dsa_t* row);

#endif /* CSVTOOL_H_ */

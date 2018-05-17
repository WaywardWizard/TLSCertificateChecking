/*
 * csvTool.h
 *
 *  Created on: 13 May 2018
 *      Author: Ben Tomlin
 *   Student #: 834198
 */
#include <stdlib.h>

#ifndef CSVTOOL_H_
#define CSVTOOL_H_

typedef struct CSVFile CSVFile_t;

struct CSVFile {
	int nCol;
	int nRow;
	int rx;
	int cx;
	FILE *source;
	char separator=',';
	char** header=NULL;
};

CSVFile_t* initCsv(char* path);
char** readRow(CSVFile_t *f);
int writeRow(CSVFile_t *f, row);

#endif /* CSVTOOL_H_ */

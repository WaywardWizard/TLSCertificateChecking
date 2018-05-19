/*
 * csvTool.c
 *
 *  Created on: 13 May 2018
 *      Author: Ben Tomlin
 *   Student #: 834198
 */

#include <stdio.h>
#include "dataStructure.h"
#include <stdlib.h>
#include <string.h>

#define CSV_BUFFER_SIZE 1024
#define CSV_DEFAULT_FS ','

/*
 * 1) Load csv file
 * 2) Read line, return a char**
 * 3) Write line, given a char**
 */

dsa_t* readRow(FILE* csv) {
	/**
	 * Read a row of <csv> and return its cells as an array.
	 *
	 * A row is read in a buffered manner. Rows may be delimited with
	 * '\n' or an EOF. Cells are delimited with CSV_DEFUALT_FS or row
	 * delimiters.
	 *
	 * Empty rows are ignored, and the next row is read
	 */

	if (feof(csv)!=0) {return(NULL);}

	char buffer[CSV_BUFFER_SIZE];
	dsa_t* leftoverBuffer=create_dsa();
	char* leftover;
	char* leftoverScanner;
	char* bufferScanner;
	char* cellEnd;
	char* cellStart=buffer;
	char* cell;
	dsa_t* rowData = create_dsa();
	int cellLength;
	int leftoverLength=0;
	int lastCellLength=0;
	int haveRow=0;
	int eofReached;

	/* Read in text of csv file */
	do{
		fgets(buffer, CSV_BUFFER_SIZE, csv);

		/* Move to the next row if current row empty */
		if(strlen(buffer)==0){return(readRow(csv));}

		/* Test for remaining row data */
		if ((buffer[strlen(buffer)-1]=='\n') || (feof(csv)!=0)){haveRow=1;}
		bufferScanner=buffer;

		/* Break text into cells and write to dsa */
		while((cellEnd=strchr(bufferScanner, CSV_DEFAULT_FS))!=NULL){

			cellLength=cellEnd-cellStart;
			cell = malloc(sizeof(char)*(cellLength+1));

			/* This cell contains the leftover from prior fgets reads that did not complete the line*/
			if (leftoverBuffer->length>0) {

				/* Find leftover length */
				leftoverLength=0;
				for(int lx=0;lx<leftoverBuffer->length-1;lx++){
					leftoverLength+=strlen(getItem_dsa(leftoverBuffer,lx));
				}

				/* Reassemble leftover */
				leftover=leftoverScanner=malloc(sizeof(char)*(leftoverLength+1));
				for(int lx=(leftoverBuffer->length-1);lx>=0;lx--){
					const char* leftoverFragment=getItem_dsa(leftoverBuffer, lx);
					strcat(leftoverScanner, leftoverFragment);
					leftoverScanner+=strlen(leftoverFragment);
				}

				/* Put leftover in cell, and clear leftover buffer */
				cell = realloc(cell, sizeof(char)*(leftoverLength+cellLength+1));
				memcpy(cell, leftoverScanner, leftoverLength);
				cell+=leftoverLength;
				delete_dsa(leftoverBuffer);
				leftoverBuffer=create_dsa();
			} // break up cells while

			/* Extract cell from row */
			memcpy(cell, bufferScanner, cellLength);
			cell[cellLength]='\0';
			/* Jump up to last FS match, and one beyond it */
			bufferScanner+=cellLength+1;
			appendto_dsa(rowData, cell);
		}

		/* Stash leftover if we dont have the whole cell */
		if(!haveRow){
			appendto_dsa(leftoverBuffer, cellEnd+1);

		/* Extract final cell, which is delimited with \n or EOF */
		} else {
			/* This does not include the final new line if present */
			eofReached = (feof(csv)!=0);
			lastCellLength = (buffer+strlen(buffer))-bufferScanner-!eofReached;
			cell = malloc(sizeof(char)*(lastCellLength+1));
			memcpy(cell, bufferScanner, lastCellLength);
			cell[lastCellLength]='\0';
			appendto_dsa(rowData, cell);
		}
	} while(!haveRow);

	delete_dsa(leftoverBuffer);
	return(rowData);
}


void writeRow(FILE* csv, dsa_t* row) {
	/**
	 * Write array content of <row> into <csv>
	 */
	for(int ix=0;ix<row->length;ix++){
		const char* element = getItem_dsa(row, ix);
		if(ix!=0){fputc(CSV_DEFAULT_FS, csv);}
		fputs(element, csv);
	}
	fputc('\n', csv);
}

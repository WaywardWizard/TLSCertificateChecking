/**
 * Author: Ben Tomlin
 * 	   SN: 834198
 * 	 Date: 08/10/16
 *
 * 	 Note: This code was written by myself in 2016 for a prior assignment
 */
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "dataStructure.h"

# define DYN_ARRAY_INIT_LENGTH 2
# define EXIT_MALLOC_FAIL 111

int grow_array(void** array, int reqd_sz, size_t unit_sz);
int get_newsize_geometric_growth(int required_size);
void malloc_fail();

void append_dsa(dsa_t* dest, dsa_t* source) {
	/**
	 * Assuming <dest> and <source> are contiguous, add the elements of <source> to <dest>
	 */
	for(int ix=0;ix<source->length;ix++){
		writeto_dsa(dest, source->array[ix],dest->length);
	}
}

void appendto_dsa(dsa_t* array, char* word){
	writeto_dsa(array, word, array->length);
}

void
writeto_dsa(dsa_t *array, char* word, int ix){
    /* DESC: Writes a string to dynamic string array at a given index. If a
     *       string already exists at the index, overwrites.
     *
     * INPT: dsa_t *array - A dynamic string array
     *       char *word   - String to write
     *       int ix       - indice/Location in which to write string
     *
     * OTPT: void
     */

    int new_size, fx;
    int word_length=(int)strlen(word);
    assert(array!=NULL);

    /* If dynamic array is not large enough, geometrically increase size*/
    if (ix>=array->size) {
        new_size=grow_array((void**)&array->array, 1+ix, sizeof(char*));
        array->array=(char**)array->array;

        /* Initialize newly allocated memory */
        for (fx=array->size; fx<new_size; fx++) {
            array->array[fx]=NULL;
        }
        array->size=new_size;
    }

    /* Allocate memory for string if required*/
    if (array->array[ix]==NULL) {
        array->array[ix]=(char*)malloc(sizeof(char)*(1+word_length));
    /* Reallocate if overwriting string */
    } else {
        array->array[ix]=(char*)realloc(array->array[ix],
                                                sizeof(char)*(1+word_length));
    }
    if (array->array[ix]==NULL) {
        malloc_fail();
    }

    /* Copy the string to the allocated memory */
    strcpy(array->array[ix], word);
    if (ix+1>array->length) {
        array->length=ix+1;
    }
}

dsa_t*
create_dsa() {
    /* DESC: Creates an dynamic string array
     * OTPT: dsa_t * - Pointer to dynamic string array*/
    int fx;

    /* Allocate memory for array structure.*/
    dsa_t* array;
    array=(dsa_t*)malloc(sizeof(*array));
    if (array==NULL) {
        malloc_fail();
    }

    /* Allocate memory for strings in array & null init */
    array->array=(char**)malloc(DYN_ARRAY_INIT_LENGTH*sizeof(char*));
    for (fx=0; fx<DYN_ARRAY_INIT_LENGTH; fx++) {
        array->array[fx]=NULL;
    }
    if (array->array==NULL) {
        malloc_fail();
    }
    array->size=DYN_ARRAY_INIT_LENGTH;
    array->length=0;
    return(array);
}

void
delete_dsa(dsa_t* array) {
    /* DESC: Deletes dynamic string array
     * OTPT: void
     */

    int ix;
    if (array==NULL) {return;}
    /* Free all strings from memory */
    for (ix=0;ix<array->length;ix++) {
        free(array->array[ix]);
    }
    free(array);
    array=NULL;
}

const char* getItem_dsa(dsa_t* array, int index) {
	/**
	 * Return a const char* to item at index. Null if index invalid or has nothing
	 */
	if(index>=array->size){return(NULL);}
	return((const char*)(array->array[index]));
}

int
grow_array(void** array, int reqd_sz, size_t unit_sz) {
    /* DESC: Grows an array geometrically to the required size
     *       Returns the new size
     *
     * INPT: void** array - pointer to mallocd void* pointer
     *
     *       int required_sz - new minimmum size required. 1base count of units
     *       array will be required to hold.
     *
     *       int unit_sz - size of objects being stored in array
     *
     * OTPT: int - the new size of array
     *
     */
    int new_sz;
    new_sz=get_newsize_geometric_growth(reqd_sz);

    /* Update the address (inside whatever struct being operated on) that points
     * to the mallocd array. */
    *array=realloc(*array, new_sz*unit_sz);
    if (*array==NULL) {
        malloc_fail();
    }
    return(new_sz);
}

int get_newsize_geometric_growth(int required_size) {
    /* DESC: Returns a new size of an array given a required size such that
     *       growth will be geometric. Skips steps of growth when possible to
     *       prevent unnecessary memory read write operations.
     *
     * INPT: int required_size - The minimum count of elements the array is to
     *       hold.
     *
     * OTPT: int - the new size.
     */
    return((int)pow(2,((int)log2(required_size))+1));
}

void malloc_fail() {
    printf("Malloc failed to allocate memory. Program terminating\n");
    exit(EXIT_MALLOC_FAIL);
}


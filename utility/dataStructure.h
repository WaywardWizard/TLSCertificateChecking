/*
 * dataStructure.h
 *
 *  Created on: 17 May 2018
 *      Author: Ben Tomlin
 *   Student #: 834198
 */

#ifndef UTILITY_DATASTRUCTURE_H_
#define UTILITY_DATASTRUCTURE_H_

typedef struct dynamic_string_array dsa_t;
struct dynamic_string_array {
    char** array;
    int size;       /*element capacity */
    int length;     /*number of elements held*/
};

dsa_t *create_dsa();
void writeto_dsa(dsa_t *array, char* word, int ix);
void delete_dsa(dsa_t* array);
void append_dsa(dsa_t* dest, dsa_t* source);

#endif /* UTILITY_DATASTRUCTURE_H_ */

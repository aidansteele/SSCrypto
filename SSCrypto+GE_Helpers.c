/*
 *  SSCrypto+GE_Helpers.c
 *  Xpeek
 *
 *  Created by Aidan Steele on 16/01/11.
 *  Copyright 2011 Glass Echidna. All rights reserved.
 *
 */

#include "SSCrypto+GE_Helpers.h"

/*
 * Standard app-level memory functions required by CDSA.
 */
void *AppMalloc(CSSM_SIZE size, void *allocRef) {
	return malloc(size);
}

void AppFree(void *mem_ptr, void *allocRef) {
	free(mem_ptr);
 	return;
}

void *AppRealloc(void *ptr, CSSM_SIZE size, void *allocRef) {
	return realloc(ptr, size);
}

void *AppCalloc(uint32 num, CSSM_SIZE size, void *allocRef) {
	return calloc(num, size);
}

CSSM_API_MEMORY_FUNCS memFuncs = {
	AppMalloc,
	AppFree,
	AppRealloc,
 	AppCalloc,
 	NULL
};
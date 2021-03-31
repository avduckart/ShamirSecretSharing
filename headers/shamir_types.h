#pragma once

#ifndef __SHAMIR_TYPES_H__
#define __SHAMIR_TYPES_H__

#include <openssl/bn.h>

#include "multithreading.h"

#define _K 3
#define _N 5

typedef struct
{
    BIGNUM* coeffs[_K];
} polynom_t;

typedef struct {
    BIGNUM* shadow;
    BIGNUM* id;
}part_t;

typedef struct {
    part_t* parts;
    const polynom_t* pol;
    BIGNUM* mod;
    int success;
    mutex_t mtx;

}share_data_t;


typedef struct {
    BIGNUM* secret;
    const part_t* part[_K];
    BIGNUM* mod;
    int success;
    mutex_t* mtx;
}restore_data_t;

typedef enum reults {
    SUCCESS,
    SOME_PART_IS_NULL,
    MODULE_IS_NULL,
    OUTPUT_ADDRESS_IS_NULL,
    ANY_PARTS_ARE_SAME,
    TIMEOUT_ERROR,
    MUTEX_EXITED_ERROR,
    WAIT_FAILED_ERROR,
    INPUT_ADDRESS_IS_NULL,
    DEADLOCK,
    THREAD_IS_NOT_A_JOINABLE,
    THREAD_COULD_BE_FOUND,
    MUTEX_ERROR
} result_t;

#endif //__SHAMIR_TYPES_H__

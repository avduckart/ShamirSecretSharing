#ifndef __SHAMIR_TYPES_H__
#define __SHAMIR_TYPES_H__

#include <openssl/bn.h>
#include <openssl/err.h>

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

typedef enum results {
    SUCCESS,
    OUT_OF_MEMORY,
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

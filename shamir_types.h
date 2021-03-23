#pragma once

#ifndef __SHAMIR_TYPES_H__
#define __SHAMIR_TYPES_H__

#include "openssl/bn.h"

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

#endif //__SHAMIR_TYPES_H__

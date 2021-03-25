#pragma once

#ifndef __TYPES_H__
#define __TYPES_H__

#include "../shamir_types.h"

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

typedef void(*proc_t)(void*);

#endif //__TYPES_H__ 

#pragma once

#ifndef __CALC_H__
#define __CALC_H__

#include <assert.h>
#include <shamir_scheme.h>

#include "multithreading.h"

#define secure_alloc(type, var, func)   type * var = func(); if(!var) { data->success = 0xF0; goto err;}
#define BN_secure_alloc(var)            secure_alloc(BIGNUM, var, BN_secure_new)
#define CTX_secure_alloc(var)           secure_alloc(BN_CTX, var, BN_CTX_new)
#define secure_free(func, var)          if(var) func(var);
#define BN_secure_free(var)             secure_free(BN_clear_free, var);
#define CTX_secure_free(var)            secure_free(BN_CTX_free, var);
#define handler(func)                   if(!func) { data->success = ERR_get_error(); goto err;}
#define check(cond, status)             if(cond) return status;
#define is_null(ptr, status)            check(!ptr, status);

typedef struct {
    part_t* parts;
    const polynom_t* pol;
    BIGNUM* mod;
    long success;
    mutex_t mtx;
}share_data_t;

typedef struct{
    BIGNUM* index[_K];
    BIGNUM* shadow;
} base_polynom_t;

typedef struct {
    BIGNUM* secret;
    base_polynom_t* base_pol;
    const BIGNUM* mod;
    BN_MONT_CTX* mont;
    long success;
    mutex_t* mtx;
}restore_data_t;

void calc_a0(share_data_t*);
void calc_a1(share_data_t*);
void calc_a2(share_data_t*);
void calc_free_term(restore_data_t *data);
void run_calc(thread_t*, const share_data_t*);
void zero_part(part_t*);
void zero_parts(part_t*);
void close_threads(thread_t*);
result_t ready_to_write_parts(part_t*);
result_t thread_handler(int);

void(*calc[])(share_data_t*) = { calc_a0, calc_a1, calc_a2 };

// П(x - xj)/(xi - xj)
void calc_free_term(restore_data_t* data)
{
    assert(data);

    CTX_secure_alloc(ctx);
    BN_secure_alloc(a);
    BN_secure_alloc(b);
    BN_secure_alloc(num);
    BN_secure_alloc(denom);
    BN_secure_alloc(term);

    handler(BN_mod_mul_montgomery(num, data->base_pol->index[1], data->base_pol->index[2], data->mont, ctx));

    handler(BN_mod_sub(a, data->base_pol->index[0], data->base_pol->index[1], data->mod, ctx));
    handler(BN_mod_sub(b, data->base_pol->index[0], data->base_pol->index[2], data->mod, ctx));
    handler(BN_mod_mul_montgomery(denom, a, b, data->mont, ctx));

    handler(BN_mod_inverse(denom, denom, data->mod, ctx));
    handler(BN_to_montgomery(denom, denom, data->mont, ctx));
    handler(BN_to_montgomery(denom, denom, data->mont, ctx));

    handler(BN_mod_mul_montgomery(term, denom, num, data->mont, ctx));

    handler(BN_mod_mul_montgomery(num, term, data->base_pol->shadow, data->mont, ctx));
    handler(BN_from_montgomery(term, num, data->mont, ctx));

    syncronized(*data->mtx,
                handler(BN_mod_add(data->secret, data->secret, term, data->mod, ctx)));

    err:
    BN_secure_free(term);
    BN_secure_free(a);
    BN_secure_free(b);
    BN_secure_free(denom);
    BN_secure_free(num);
    CTX_secure_free(ctx);
}

// F(1) = a0, ..., F(5) = a0
void calc_a0(share_data_t* data)
{
    assert(data);

    CTX_secure_alloc(ctx);

    for(size_t i = 1; i <= _N; i++) {
        handler(BN_set_word(data->parts[i - 1].id, i));
        syncronized(data->mtx,
                    handler(BN_mod_add(data->parts[i-1].shadow, data->parts[i-1].shadow, data->pol->coeffs[0], data->mod, ctx))
        );
    }

    err:
    CTX_secure_free(ctx);
}

// F(1) += 1*a1, ..., F(5) += 5*a1
void calc_a1(share_data_t* data)
{
    assert(data);

    BN_secure_alloc(term);
    CTX_secure_alloc(ctx);

    BN_zero(term);
    for(size_t i = 1; i <= _N; i++) {
        handler(BN_mod_add(term, term, data->pol->coeffs[1], data->mod, ctx));
        syncronized(data->mtx,
                    handler(BN_mod_add(data->parts[i - 1].shadow, data->parts[i - 1].shadow, term, data->mod, ctx))
        );
    }

    err:
    CTX_secure_free(ctx);
    BN_secure_free(term);
}

// F(1) += a2, ..., F(5) += 25*a2
void calc_a2(share_data_t* data)
{
    assert(data);

    CTX_secure_alloc(ctx);
    BN_secure_alloc(term);
    BN_secure_alloc(d);
    BN_secure_alloc(dd);

    BN_copy(d, data->pol->coeffs[2]);
    handler(BN_mod_add(dd, data->pol->coeffs[2], data->pol->coeffs[2], data->mod, ctx));

    BN_zero(term);
    for(size_t i = 1; i <= _N; i++) {
        handler(BN_mod_add(term, term, d, data->mod, ctx));
        syncronized(data->mtx,
                    handler(BN_mod_add(data->parts[i - 1].shadow, data->parts[i - 1].shadow, term, data->mod, ctx))
        );
        if(i != _N)
            handler(BN_mod_add(d, d, dd, data->mod, ctx));
    }

    err:
    BN_secure_free(d);
    BN_secure_free(dd);
    BN_secure_free(term);
    CTX_secure_free(ctx);
}


void close_threads(thread_t* threads)
{
    assert(threads);

    for(size_t i=0; i < _K; i++)
        close_thread(threads[i]);
}

result_t thread_handler(int cause)
{
    result_t ret = SUCCESS;
    switch (cause) {
#if defined _WIN32 && defined _MSC_VER
    case WAIT_ABANDONED_0:
        ret = MUTEX_EXITED_ERROR;
        break;
    case WAIT_TIMEOUT:
        ret = TIMEOUT_ERROR;
        break;
    case WAIT_FAILED:
        ret = WAIT_FAILED_ERROR;
#elif defined __linux__
    case EDEADLK :
        ret = DEADLOCK;
        break;
    case EINVAL :
        ret = THREAD_IS_NOT_A_JOINABLE;
        break;
    case ESRCH :
        ret = THREAD_COULD_BE_FOUND;
#else
    #define
#endif
    }
    return ret;
}

result_t ready_to_write_parts(part_t* parts)
{
    for (size_t i = 1; i <= _N; i++)
        is_null(&parts[i - 1], OUTPUT_ADDRESS_IS_NULL);

    return SUCCESS;
}

void zero_part(part_t* part)
{
    assert(part);

    BN_zero(part->id);
    BN_zero(part->shadow);
}

void zero_parts(part_t* parts)
{
    for (size_t i = 1; i <= _N; i++)
        zero_part(&parts[i - 1]);
}

void run_calc(thread_t* threads, const share_data_t* data)
{
    for (size_t i = 0; i < _K; i++)
        create_thread(&threads[i], (void* (*)(void*)) calc[i], (share_data_t*)data);
}

#undef secure_alloc
#undef secure_free
#undef handler

#endif //__CALC_H__

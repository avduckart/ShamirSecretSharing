#pragma once

#ifndef __CALC_H__
#define __CALC_H__

#include <assert.h>
#include <shamir_scheme.h>

#define secure_alloc(type, var, func)   type * var = func(); if(!var) { data->success = 0xF0; return;}
#define secure_free(func, var)          if(var) func(var);
#define check(cond, status)             if(cond) return status;
#define is_null(ptr, status)            check(!ptr, status);

void calc_a0(share_data_t*);
void calc_a1(share_data_t*);
void calc_a2(share_data_t*);
void calc_term(restore_data_t*);
void run_calc(thread_t*, const share_data_t*);
void zero_part(part_t*);
void zero_parts(part_t*);
void close_threads(thread_t*);
result_t ready_to_write_parts(part_t*);
result_t handler(int);

void(*calc[])(share_data_t*) = { calc_a0, calc_a1, calc_a2 };

void calc_term(restore_data_t* data)
{
    assert(data);

    secure_alloc(BN_CTX, ctx, BN_CTX_new);
    secure_alloc(BN_MONT_CTX, mont, BN_MONT_CTX_new);
    BN_MONT_CTX_set(mont, data->mod, ctx);

    secure_alloc(BIGNUM, id0, BN_secure_new);
    secure_alloc(BIGNUM, id1, BN_secure_new);
    secure_alloc(BIGNUM, id2, BN_secure_new);
    secure_alloc(BIGNUM, sh0, BN_secure_new);
    secure_alloc(BIGNUM, num, BN_secure_new);

    BN_to_montgomery(id0, data->part[0]->id, mont, ctx);
    BN_to_montgomery(id1, data->part[1]->id, mont, ctx);
    BN_to_montgomery(id2, data->part[2]->id, mont, ctx);
    BN_to_montgomery(sh0, data->part[0]->shadow, mont, ctx);

    BN_mod_mul_montgomery(num, id1, id2, mont, ctx);

    BN_mod_sub(id1, id0, id1, data->mod, ctx);
    BN_mod_sub(id0, id0, id2, data->mod, ctx);
    BN_mod_mul_montgomery(id1, id1, id0, mont, ctx);

    BN_mod_inverse(id1, id1, data->mod, ctx);
    BN_to_montgomery(id1, id1, mont, ctx);
    BN_to_montgomery(id1, id1, mont, ctx);

    BN_mod_mul_montgomery(id1, id1, num, mont, ctx);

    BN_mod_mul_montgomery(id1, id1, sh0, mont, ctx);
    BN_from_montgomery(id1, id1, mont, ctx);

    syncronized(*data->mtx,
        BN_mod_add(data->secret, data->secret, id1, data->mod, ctx));

    secure_free(BN_clear_free, num);
    secure_free(BN_clear_free, sh0);
    secure_free(BN_clear_free, id0);
    secure_free(BN_clear_free, id1);
    secure_free(BN_clear_free, id2);
    secure_free(BN_MONT_CTX_free, mont);
    secure_free(BN_CTX_free, ctx);
}

// F(1) = a0, ..., F(5) = a0
void calc_a0(share_data_t* data)
{
    assert(data);

    secure_alloc(BN_CTX, ctx, BN_CTX_new);

    for(size_t i = 1; i <= _N; i++) {
        BN_set_word(data->parts[i - 1].id, i);
        syncronized(data->mtx,
            BN_mod_add(data->parts[i-1].shadow, data->parts[i-1].shadow, data->pol->coeffs[0], data->mod, ctx)
        );
    }

    secure_free(BN_CTX_free, ctx);
}

// F(1) += 1*a1, ..., F(5) += 5*a1
void calc_a1(share_data_t* data)
{
    assert(data);

    secure_alloc(BIGNUM, term, BN_secure_new);
    secure_alloc(BN_CTX, ctx, BN_CTX_new);

    BN_zero(term);
    for(size_t i = 1; i <= _N; i++) {
        BN_mod_add(term, term, data->pol->coeffs[1], data->mod, ctx);
        syncronized(data->mtx,
            BN_mod_add(data->parts[i - 1].shadow, data->parts[i - 1].shadow, term, data->mod, ctx)
        );
    }

    secure_free(BN_CTX_free, ctx);
    secure_free(BN_clear_free, term);
}

// F(1) += a2, ..., F(5) += 25*a2
void calc_a2(share_data_t* data)
{
    assert(data);

    secure_alloc(BIGNUM, term, BN_secure_new);
    secure_alloc(BN_CTX, ctx, BN_CTX_new);
    secure_alloc(BIGNUM, d, BN_secure_new);
    secure_alloc(BIGNUM, dd, BN_secure_new);

    BN_copy(d, data->pol->coeffs[2]);
    BN_mod_add(dd, data->pol->coeffs[2], data->pol->coeffs[2], data->mod, ctx);

    BN_zero(term);
    for(size_t i = 1; i <= _N; i++) {
        BN_mod_add(term, term, d, data->mod, ctx);
        syncronized(data->mtx,
            BN_mod_add(data->parts[i - 1].shadow, data->parts[i - 1].shadow, term, data->mod, ctx)
        );
        if(i != _N)
            BN_mod_add(d, d, dd, data->mod, ctx);
    }

    secure_free(BN_clear_free, d);
    secure_free(BN_clear_free, dd);
    secure_free(BN_clear_free, term);
    secure_free(BN_CTX_free, ctx);
}


void close_threads(thread_t* threads)
{
    assert(threads);

    for(size_t i=0; i < _K; i++)
        close_thread(threads[i]);
}

result_t handler(int cause)
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

#endif //__CALC_H__

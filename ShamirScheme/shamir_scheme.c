#include <assert.h>

#include "../shamir_scheme.h"
#include "../errors.h"
#include "multithreading.h"
#include "types.h"

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
int is_ready_to_write_parts(part_t*);
void close_threads(thread_t*);
int handler(int);

int construct_polynom(polynom_t* pol, const BIGNUM* mod)
{
    is_null(pol, OUTPUT_ADDRESS_IS_NULL);
    is_null(mod, MODULE_IS_NULL);

    for (int i = 0; i < _K; i++) {
        pol->coeffs[i] = BN_secure_new();
        BN_rand_range(pol->coeffs[i], mod);
    }

    return SUCCESS;
}

int destruct_polynom(polynom_t* pol)
{
    is_null(pol, OUTPUT_ADDRESS_IS_NULL);

    for (int i = 0; i < _K; i++) 
        BN_clear_free(pol->coeffs[i]);

    return SUCCESS;
}

int share_secret(part_t* parts, const polynom_t* pol, const BIGNUM* mod)
{
    is_null(pol, INPUT_ADDRESS_IS_NULL);
    is_null(mod, MODULE_IS_NULL);

    int ready = is_ready_to_write_parts(parts);
    check(ready, ready);

    zero_parts(parts);

    mutex_t mtx;
    mutex_init(mtx);
    thread_t threads[_K];
    share_data_t data = { parts, pol, (BIGNUM*)mod, 0, mtx };
    run_calc(threads, &data);

    int ret = handler(join(threads));
    close_threads(threads);

    mutex_destroy(mtx);

    return data.success|ret;
}

int restore_secret(BIGNUM* secret, const part_t* part1, const part_t* part2, const part_t* part3, const BIGNUM* mod)
{
    is_null(secret, OUTPUT_ADDRESS_IS_NULL);
    is_null(mod, MODULE_IS_NULL);
    check(!part1 || !part2 || !part3, INPUT_ADDRESS_IS_NULL);
    check(part1 == part2 || part1 == part3 || part2 == part3, ANY_PARTS_ARE_SAME);

    BN_zero(secret);

    mutex_t mtx;
    mutex_init(mtx);
    int success = 0;
    thread_t threads[_K];
    restore_data_t data[_K] = {
        {secret, {part1, part2, part3}, (BIGNUM*)mod, 0, mtx},
        {secret, {part2, part1, part3}, (BIGNUM*)mod, 0, mtx},
        {secret, {part3, part2, part1}, (BIGNUM*)mod, 0, mtx}
    };

    for (int i = 0; i < _K; i++) {
        create_thread(threads[i], (void* (*)(void*)) calc_term, &data[i]);
        success |= data[i].success;
    }

    int ret = handler(join(threads));

    close_threads(threads);

    mutex_destroy(mtx);

    return success|ret;
}

void calc_term(restore_data_t* data)
{
    assert(data);

    secure_alloc(BN_CTX, ctx, BN_CTX_new);
    secure_alloc(BIGNUM, num, BN_secure_new);
    BN_mod_mul(num, data->part[1]->id, data->part[2]->id, data->mod, ctx);

    secure_alloc(BIGNUM, term, BN_secure_new);
    secure_alloc(BIGNUM, denom, BN_secure_new);
    BN_mod_sub(denom, data->part[0]->id, data->part[1]->id, data->mod, ctx);
    BN_mod_sub(term, data->part[0]->id, data->part[2]->id, data->mod, ctx);
    BN_mod_mul(denom, denom, term, data->mod, ctx);

    BN_mod_inverse(term, denom, data->mod, ctx);
    secure_free(BN_clear_free, denom);

    BN_mod_mul(term, term, num, data->mod, ctx);
    secure_free(BN_clear_free, num);
     
    BN_mod_mul(term, term, data->part[0]->shadow, data->mod, ctx);

    syncronized(data->mtx, 
        BN_mod_add(data->secret, data->secret, term, data->mod, ctx));

    secure_free(BN_clear_free, term);
    secure_free(BN_CTX_free, ctx);
}

// F(1) = a0, ..., F(5) = a0
void calc_a0(share_data_t* data)
{
    assert(data);

    secure_alloc(BN_CTX, ctx, BN_CTX_new);

    for(int i = 1; i <= _N; i++) {
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
    for(int i = 1; i <= _N; i++) {
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
    for(int i = 1; i <= _N; i++) {
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

    for(int i=0; i < _K; i++)
        if(threads[i])
            close_thread(threads[i]);
}

int handler(int cause)
{
    int ret = SUCCESS;
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

int is_ready_to_write_parts(part_t* parts)
{
    for (int i = 1; i <= _N; i++)
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
    for (int i = 1; i <= _N; i++)
        zero_part(&parts[i - 1]);
}

void run_calc(thread_t* threads, const share_data_t* data)
{
    void(*calc[])(share_data_t*) = { calc_a0, calc_a1, calc_a2 };

    for (int i = 0; i < _K; i++)
        create_thread(threads[i], (void* (*)(void*)) calc[i], (share_data_t*)data);
}

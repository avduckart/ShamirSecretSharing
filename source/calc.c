#pragma once

#include <assert.h>

#include "calc.h"

void(*calc[])(share_data_t*) = { calc_a0, calc_a1, calc_a2 };

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

    syncronized(*data->mtx,
        BN_mod_add(data->secret, data->secret, term, data->mod, ctx));

    secure_free(BN_clear_free, term);
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

#include <stdio.h>

#include <shamir_scheme.h>

#include "calc.h"


#define secure_alloc(type, var, func)       type * var = func(); if(!var) return OUT_OF_MEMORY;
#define MONT_CTX_secure_alloc(var)          secure_alloc(BN_MONT_CTX, var, BN_MONT_CTX_new)
#define handler(func)                       if(!func) { ret = ERR_get_error(); goto err;}
#define BN_secure_mont_assign(var, val)     secure_alloc(BIGNUM, var, BN_secure_new); handler(BN_to_montgomery(var, val, mont, ctx))
#define secure_free(func, var)              if(var) {func(var); var = NULL};
#define MONT_CTX_secure_free(var)           secure_free(BN_MONT_CTX_free, var);


result_t construct_polynom(polynom_t* pol, const BIGNUM* mod)
{
    is_null(pol, OUTPUT_ADDRESS_IS_NULL);
    is_null(mod, MODULE_IS_NULL);

    result_t ret = SUCCESS;

    for (size_t i = 0; i < _K; i++) {
        pol->coeffs[i] = BN_secure_new();
        handler(BN_rand_range(pol->coeffs[i], mod));
    }

    err:
    return ret;
}

result_t destruct_polynom(polynom_t* pol)
{
    is_null(pol, OUTPUT_ADDRESS_IS_NULL);

    for (size_t i = 0; i < _K; i++) 
        BN_secure_free(pol->coeffs[i]);

    return SUCCESS;
}

result_t share_secret(part_t* parts, const polynom_t* pol, const BIGNUM* mod)
{
    is_null(pol, INPUT_ADDRESS_IS_NULL);
    is_null(mod, MODULE_IS_NULL);
    is_null(parts, OUTPUT_ADDRESS_IS_NULL);

    int ready = ready_to_write_parts(parts);
    check(ready, ready);

    zero_parts(parts);

    mutex_t mtx;
    mutex_init(mtx);
    thread_t threads[_K];
    share_data_t data = { parts, pol, (BIGNUM*)mod, 0, mtx };
    run_calc(threads, &data);

    int ret = thread_handler(join(threads));
    close_threads(threads);

    mutex_destroy(mtx);

    return data.success|ret;
}

result_t restore_secret(BIGNUM* secret, const part_t* part1, const part_t* part2, const part_t* part3, const BIGNUM* mod)
{
    is_null(secret, OUTPUT_ADDRESS_IS_NULL);
    is_null(mod, MODULE_IS_NULL);
    check(!part1 || !part2 || !part3, INPUT_ADDRESS_IS_NULL);
    check(part1 == part2 || part1 == part3 || part2 == part3, ANY_PARTS_ARE_SAME);

    result_t ret = SUCCESS;

    BN_zero(secret);

    CTX_secure_alloc(ctx);
    MONT_CTX_secure_alloc(mont);
    handler(BN_MONT_CTX_set(mont, mod, ctx));

    BN_secure_mont_assign(id0, part1->id);
    BN_secure_mont_assign(sh0, part1->shadow);
    BN_secure_mont_assign(id1, part2->id);
    BN_secure_mont_assign(sh1, part2->shadow);
    BN_secure_mont_assign(id2, part3->id);
    BN_secure_mont_assign(sh2, part3->shadow);

    mutex_t mtx;
    mutex_init(mtx);
    thread_t threads[_K];
    base_polynom_t l1 = {{id0, id1, id2}, sh0};
    base_polynom_t l2 = {{id1, id0, id2}, sh1};
    base_polynom_t l3 = {{id2, id1, id0}, sh2};
    restore_data_t data[_K] = {
            {secret, &l1, mod, mont, 0, &mtx},
            {secret, &l2, mod, mont, 0, &mtx},
            {secret, &l3, mod, mont, 0, &mtx}
    };

    for (size_t i = 0; i < _K; i++) {
        create_thread(&threads[i], (void* (*)(void*)) calc_free_term, &data[i]);
        ret |= data[i].success;
    }

    result_t thread_status = thread_handler(join(threads));

    close_threads(threads);

    mutex_destroy(mtx);

    err:
    BN_secure_free(id0);
    BN_secure_free(id1);
    BN_secure_free(id2);

    BN_secure_free(sh0);
    BN_secure_free(sh1);
    BN_secure_free(sh2);

    MONT_CTX_secure_free(mont);
    CTX_secure_free(ctx);

    return thread_status|ret;
}

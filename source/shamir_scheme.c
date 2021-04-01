#include <assert.h>
#include <stdio.h>

#include <shamir_scheme.h>

#define "calc.h"

result_t construct_polynom(polynom_t* pol, const BIGNUM* mod)
{
    is_null(pol, OUTPUT_ADDRESS_IS_NULL);
    is_null(mod, MODULE_IS_NULL);

    for (size_t i = 0; i < _K; i++) {
        pol->coeffs[i] = BN_secure_new();
        BN_rand_range(pol->coeffs[i], mod);
    }

    return SUCCESS;
}

result_t destruct_polynom(polynom_t* pol)
{
    is_null(pol, OUTPUT_ADDRESS_IS_NULL);

    for (size_t i = 0; i < _K; i++) 
        BN_clear_free(pol->coeffs[i]);

    return SUCCESS;
}

result_t share_secret(part_t* parts, const polynom_t* pol, const BIGNUM* mod)
{
    is_null(pol, INPUT_ADDRESS_IS_NULL);
    is_null(mod, MODULE_IS_NULL);

    int ready = ready_to_write_parts(parts);
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

result_t restore_secret(BIGNUM* secret, const part_t* part1, const part_t* part2, const part_t* part3, const BIGNUM* mod)
{
    is_null(secret, OUTPUT_ADDRESS_IS_NULL);
    is_null(mod, MODULE_IS_NULL);
    check(!part1 || !part2 || !part3, INPUT_ADDRESS_IS_NULL);
    check(part1 == part2 || part1 == part3 || part2 == part3, ANY_PARTS_ARE_SAME);

    BN_zero(secret);

    mutex_t mtx;
    mutex_init(mtx);
    result_t success = 0;
    thread_t threads[_K];
    restore_data_t data[_K] = {
        {secret, {part1, part2, part3}, (BIGNUM*)mod, 0, &mtx},
        {secret, {part2, part1, part3}, (BIGNUM*)mod, 0, &mtx},
        {secret, {part3, part2, part1}, (BIGNUM*)mod, 0, &mtx}
    };

    for (size_t i = 0; i < _K; i++) {
        create_thread(&threads[i], (void* (*)(void*)) calc_term, &data[i]);
        success |= data[i].success;
    }

    int ret = handler(join(threads));

    close_threads(threads);

    mutex_destroy(mtx);

    return success|ret;
}

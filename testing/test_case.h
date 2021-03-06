#pragma once

#include <gtest/gtest.h>
#include <shamir_scheme.h>

#include "macros.h"

TEST(TestCase, etalon_value_test)
{
    BIGNUM* mod;
    BIGNUM* a0;
    BIGNUM* a1;
    BIGNUM* a2;

    BN_secure_assign(mod, 13);
    BN_secure_assign(a0, 11);
    BN_secure_assign(a1, 8);
    BN_secure_assign(a2, 7);
    polynom_t pol = { a0, a1, a2 };

    BIGNUM* e_id[_N];
    BIGNUM* e_sh[_N];
    part_t parts[_N];
    for (int i = 0; i < _N; i++)
    {
        e_sh[i] = BN_new();
        e_id[i] = BN_new();

        BN_set_word(e_id[i], i + 1);

        parts[i].shadow = BN_secure_new();
        parts[i].id = BN_secure_new();
    }

    BN_secure_assign(e_sh[0], 0);
    BN_secure_assign(e_sh[1], 3);
    BN_secure_assign(e_sh[2], 7);
    BN_secure_assign(e_sh[3], 12);
    BN_secure_assign(e_sh[4], 5);

    part_t e_parts[] = {
        {e_sh[0], e_id[0]},
        {e_sh[1], e_id[1]},
        {e_sh[2], e_id[2]},
        {e_sh[3], e_id[3]},
        {e_sh[4], e_id[4]} };

    ASSERT_EQ(SUCCESS, share_secret(parts, &pol, mod));

    for (size_t i = 0; i < _N; i++) {
        ASSERT_EQ(0, BN_cmp(e_parts[i].id, parts[i].id));
        ASSERT_EQ(0, BN_cmp(e_parts[i].shadow, parts[i].shadow));
    }

    int ret;
    BIGNUM* secret;
    BN_secure_alloc(secret);
    for (size_t i = 0; i < _N; i++) {
        for (size_t j = 0; j < _N; j++) {
            for (size_t l = 0; l < _N; l++) {
                ret = restore_secret(secret, &parts[i], &parts[j], &parts[l], mod);
                if (i == j || i == l || j == l)
                    ASSERT_EQ(ANY_PARTS_ARE_SAME, ret);
                else
                    ASSERT_EQ(0, BN_cmp(secret, pol.coeffs[0]));
            }
        }
    }

    BN_secure_free(secret);

    for (size_t i = 0; i < _N; i++)
    {
        BN_secure_free(parts[i].shadow);
        BN_secure_free(parts[i].id);

        BN_secure_free(e_id[i]);
        BN_secure_free(e_sh[i]);
    }

    BN_secure_free(a0);
    BN_secure_free(a1);
    BN_secure_free(a2);
    BN_secure_free(mod);
};

TEST(TestCase, construct_polynom_test) {
    const BIGNUM* mod = BN_get0_nist_prime_256();
    polynom_t pol;

    ASSERT_EQ(OUTPUT_ADDRESS_IS_NULL, construct_polynom(NULL, mod));
    ASSERT_EQ(MODULE_IS_NULL, construct_polynom(&pol, NULL));
    ASSERT_EQ(SUCCESS, construct_polynom(&pol, mod));

    ASSERT_EQ(SUCCESS, destruct_polynom(&pol));
}

TEST(TestCase, destruct_polynom_test) {
    polynom_t pol;

    ASSERT_EQ(SUCCESS, construct_polynom(&pol, BN_get0_nist_prime_256()));

    ASSERT_EQ(OUTPUT_ADDRESS_IS_NULL, destruct_polynom(NULL));
    ASSERT_EQ(SUCCESS, destruct_polynom(&pol));
}

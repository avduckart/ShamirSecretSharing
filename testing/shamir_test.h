#pragma once

#include <gtest/gtest.h>
#include <shamir_scheme.h>

class ShamirTest : public ::testing::Test
{   
protected:
    part_t parts[_N];
    const BIGNUM* mod;
    BIGNUM* secret;
    polynom_t pol;

    void SetUp()
    {
        mod = BN_get0_nist_prime_256();
        construct_polynom(&pol, mod);
        secret = BN_new();
        for (int i = 0; i < _N; i++)
        {
            parts[i].shadow = BN_secure_new();
            parts[i].id = BN_secure_new();
        }
    }
    void TearDown()
    {
        for (int i = 0; i < _N; i++) {
            BN_clear_free(parts[i].shadow);
            BN_clear_free(parts[i].id);
        }
        BN_free(secret);
        destruct_polynom(&pol);
    }
};

TEST_F(ShamirTest, share_secret_test) {
    
    ASSERT_EQ(OUTPUT_ADDRESS_IS_NULL, share_secret(NULL, &pol, mod));
    ASSERT_EQ(INPUT_ADDRESS_IS_NULL, share_secret(parts, NULL, mod));
    ASSERT_EQ(MODULE_IS_NULL, share_secret(parts, &pol, NULL));
    ASSERT_EQ(SUCCESS, share_secret(parts, &pol, mod));
}

TEST_F(ShamirTest, restore_secret_test) {
    
    ASSERT_EQ(SUCCESS, share_secret(parts, &pol, mod));
    
    ASSERT_EQ(OUTPUT_ADDRESS_IS_NULL, restore_secret(NULL, &parts[0], &parts[1], &parts[2], mod));
    ASSERT_EQ(MODULE_IS_NULL, restore_secret(secret, &parts[0], &parts[1], &parts[2], NULL));
    ASSERT_EQ(INPUT_ADDRESS_IS_NULL, restore_secret(secret, NULL, &parts[1], &parts[2], mod));
    ASSERT_EQ(INPUT_ADDRESS_IS_NULL, restore_secret(secret, &parts[0], NULL, &parts[2], mod));
    ASSERT_EQ(INPUT_ADDRESS_IS_NULL, restore_secret(secret, &parts[0], &parts[1], NULL, mod));
    ASSERT_EQ(ANY_PARTS_ARE_SAME, restore_secret(secret, &parts[0], &parts[0], &parts[2], mod));
    ASSERT_EQ(ANY_PARTS_ARE_SAME, restore_secret(secret, &parts[0], &parts[1], &parts[1], mod));
    ASSERT_EQ(ANY_PARTS_ARE_SAME, restore_secret(secret, &parts[0], &parts[1], &parts[0], mod));
    ASSERT_EQ(SUCCESS, restore_secret(secret, &parts[0], &parts[1], &parts[2], mod));
}

TEST_F(ShamirTest, share_restore_test) {
    
    share_secret(parts, &pol, mod);

    int ret;
    for (int i = 0; i < _N; i++) {
        for (int j = 0; j < _N; j++) {
            for (int l = 0; l < _N; l++)
            {
                ret = restore_secret(secret, &parts[i], &parts[j], &parts[l], mod);
                if (i == j || i == l || j == l)
                    ASSERT_EQ(ANY_PARTS_ARE_SAME, ret);
                else
                    ASSERT_EQ(0, BN_cmp(secret, pol.coeffs[0]));
            }
        }
    }
} 

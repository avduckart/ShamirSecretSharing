#pragma once

#ifndef __MACROS_H__
#define __MACROS_H__

#define BN_secure_alloc(var)        var = BN_new(); ASSERT_TRUE(var)
#define BN_secure_assign(var,val)   BN_secure_alloc(var); ASSERT_TRUE(BN_set_word(var, val))
#define BN_secure_free(var)         if(var) {BN_free(var); var = NULL;}

#endif //__MACROS_H__

#pragma once

#ifndef __SHAMIR_SCHEME_H__
#define __SHAMIR_SCHEME_H__

#define BUILD_DLL

//Windows
#if defined _WIN32 && defined _MSC_VER
    #if defined BUILD_DLL
        #define DLLEXPORT __declspec(dllexport)
    #endif
//Unix
#elif defined __linux__
    #if defined BUILD_DLL
        #define DLLEXPORT __attribute__ ((visibility ("default")))
    #endif	
//Other
#else	
    #define DLLEXPORT 
#endif

#include <openssl/rand.h>
#include <openssl/bn.h>

#include "shamir_types.h"

#ifdef __cplusplus
extern "C" {
#endif
    
DLLEXPORT int construct_polynom(polynom_t*, const BIGNUM*);
DLLEXPORT int destruct_polynom(polynom_t*);
DLLEXPORT int share_secret(part_t*, const polynom_t*, const BIGNUM*);
DLLEXPORT int restore_secret(BIGNUM*, const part_t*, const part_t*, const part_t*, const BIGNUM*);

#ifdef __cplusplus
}
#endif

#endif //__SHAMIR_SCHEME_H__
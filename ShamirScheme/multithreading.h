#pragma once

#ifndef __THREADING_H__
#define __THREADING_H__

#if defined _WIN32 && defined _MSC_VER
    #include <windows.h>
    #define create_thread(thread, func, data) thread = CreateThread(NULL, 0, func, data, 0, NULL)
    #define join(threads) WaitForMultipleObjects(_K, threads, TRUE, INFINITE)
    #define thread_t HANDLE
    #define close_thread(thread) CloseHandle(thread)
    #define mutex_t HANDLE
    #define mutex_init(mtx) mtx = CreateMutex(NULL, FALSE, NULL); if (!mtx) return MUTEX_ERROR
    #define mutex_destroy(mtx) CloseHandle(mtx);
    #define mutex_lock(mutex) WaitForSingleObject(mutex, INFINITE) // TODO îáđŕáîňŕňü
    #define mutex_unlock(mutex) ReleaseMutex(mutex)
#elif defined __linux__ 
    #include <pthread.h>
    #define thread_t pthread_t

    int unix_join(thread_t* threads)
    {
        int status = MODULE_IS_NULL;
        for (int i = 0; i < _K; i++)
        {
            status = pthread_join(threads[i], NULL);
            if (status != SUCCESS)
                break;
        }

        return status;
    }

    #include <asm/errno.h>
    #define create_thread(thread, func, data) pthread_create(thread, NULL, func, data)
    #define join(threads) unix_join(threads)
    #define close_thread(thread) pthread_cancel(thread)
    #define mutex_t pthread_mutex_t
    #define mutex_init(mtx) pthread_mutex_init(&mtx, NULL);
    #define mutex_destroy(mtx) pthread_mutex_destroy(&mtx);
    #define mutex_lock(mutex) pthread_mutex_lock(&mutex)
    #define mutex_unlock(mutex) pthread_mutex_unlock(&mutex)
#else	
    #define
#endif

#define syncronized(mutex, body) mutex_lock(mutex); body; mutex_unlock(mutex)

#endif //__THREADING_H__

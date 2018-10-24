#ifndef encrypt_common_h
#define encrypt_common_h

#include <cipher/ssr_cipher_names.h>
#include <cache.h>
#define MAX_KEY_LENGTH 64



#define safe_free(ptr)        \
    do {                    \
        if (ptr) {          \
            free(ptr);      \
            (ptr) = NULL;   \
        }                   \
    } while (0)

#ifdef WIN32
#include <windows.h>
#endif

#endif  // encrypt_common_h
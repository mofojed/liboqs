/**
 * \file rand.h
 * \brief Header defining the generic OQS PRNG
 */

#ifndef __OQS_MEMORY_H
#define __OQS_MEMORY_H

#include <stddef.h>
#include <stdint.h>

enum OQS_MEM_alg_name {
  OQS_MEM_alg_clean_memset,
  OQS_MEM_alg_clean_volatile,
  OQS_MEM_alg_clean_volatile2,
  OQS_MEM_alg_clean_volatile3,
  OQS_MEM_alg_clean_sodium,
#if defined(HAVE_EXPLICIT_BZERO)
  OQS_MEM_alg_clean_explicit_bzero,
#endif
#if defined(HAVE_MEMSET_S)
  OQS_MEM_alg_clean_memset_s,
#endif
#ifdef _WIN32
  OQS_MEM_alg_clean_SecureZeroMemory,
#endif
  OQS_MEM_alg_clean_default
};

typedef void (*OQS_MEM_clean_func)(void * const ptr, const size_t len);

void OQS_MEM_clean_memset(void * const ptr, const size_t len);
void OQS_MEM_clean_sodium(void * const pnt, const size_t len);
void OQS_MEM_clean_volatile(void * const ptr, const size_t len);
void OQS_MEM_clean_volatile2(void * const ptr, const size_t len);
void OQS_MEM_clean_volatile3(void * const ptr, const size_t len);

/** Platform specific */

#if defined(HAVE_EXPLICIT_BZERO)
void OQS_MEM_clean_explicit_bzero(void * const pnt, const size_t len);
#endif

#if defined(HAVE_MEMSET_S)
void OQS_MEM_clean_memset_s(void * const pnt, const size_t len);
#endif

#ifdef _WIN32
void OQS_MEM_clean_SecureZeroMemory(void * const pnt, const size_t len);
#endif

void OQS_MEM_clean(void * const ptr, const size_t len);

OQS_MEM_clean_func OQS_MEM_func(enum OQS_MEM_alg_name alg_name);

#endif

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "mem.h"


typedef void *(*memset_t)(void *, int, size_t);

static volatile memset_t memset_func = memset;

void OQS_MEM_clean_volatile(void *const ptr, const size_t len) {
	memset_func(ptr, 0, len);
}

void OQS_MEM_clean_volatile2(void *const ptr, const size_t len) {
	void *(*volatile const volatile_memset)(void *, int, size_t) = memset;
	volatile_memset(ptr, 0, len);
}

void OQS_MEM_clean_volatile3(void *const ptr, const size_t len) {
	void *volatile const ptrv = ptr;
	memset(ptrv, 0, len);
}

void OQS_MEM_clean_memset(void *const ptr, const size_t len) {
	memset(ptr, 0, len);
}

void OQS_MEM_clean_sodium(void *const pnt, const size_t len) {
	volatile unsigned char *volatile pnt_ =
	    (volatile unsigned char *volatile) pnt;
	size_t i = (size_t) 0U;

	while (i < len) {
		pnt_[i++] = 0U;
	}
}

void OQS_MEM_clean(void *const ptr, const size_t len) {
	memset_func(ptr, 0, len);
}

#if defined(HAVE_MEMSET_S)
void OQS_MEM_clean_memset_s(void *const pnt, const size_t len) {
	if (0U < len && memset_s(pnt, (rsize_t) len, 0, (rsize_t) len) != 0) {
		abort(); /* LCOV_EXCL_LINE */
	}
}
#endif

#ifdef _WIN32
void OQS_MEM_clean_SecureZeroMemory(void *const pnt, const size_t len) {
	SecureZeroMemory(pnt, len);
}
#endif

#if defined(HAVE_EXPLICIT_BZERO)
void OQS_MEM_clean_explicit_bzero(void *const pnt, const size_t len) {
	explicit_bzero(pnt, len);
}
#endif

OQS_MEM_clean_func OQS_MEM_func(enum OQS_MEM_alg_name alg_name) {
	switch (alg_name) {
	case OQS_MEM_alg_clean_memset:
		return &OQS_MEM_clean_memset;
	case OQS_MEM_alg_clean_volatile:
		return &OQS_MEM_clean_volatile;
	case OQS_MEM_alg_clean_volatile2:
		return &OQS_MEM_clean_volatile2;
	case OQS_MEM_alg_clean_volatile3:
		return &OQS_MEM_clean_volatile3;
	case OQS_MEM_alg_clean_sodium:
		return &OQS_MEM_clean_sodium;
#if defined(HAVE_EXPLICIT_BZERO)
	case OQS_MEM_alg_clean_explicit_bzero:
		return &OQS_MEM_clean_explicit_bzero;
#endif
#if defined(HAVE_MEMSET_S)
	case OQS_MEM_alg_clean_memset_s:
		return &OQS_MEM_clean_memset_s;
#endif
#ifdef _WIN32
	case OQS_MEM_alg_clean_SecureZeroMemory:
		return OQS_MEM_clean_SecureZeroMemory;
#endif
	case OQS_MEM_alg_clean_default:
		return OQS_MEM_clean;
	default:
		assert(0);
		return NULL; // avoid the warning of potentialy uninitialized variable in VS
	}
}

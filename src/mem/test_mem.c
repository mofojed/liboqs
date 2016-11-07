#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <oqs/mem.h>

#include "../ds_benchmark.h"

struct mem_testcase {
  enum OQS_MEM_alg_name alg_name;
  const char *name;
};

/* Add new testcases here */
struct mem_testcase mem_testcases[] = {
  { OQS_MEM_alg_clean_memset, "memset" },
  { OQS_MEM_alg_clean_volatile, "volatile" },
  { OQS_MEM_alg_clean_volatile2, "volatile2" },
  { OQS_MEM_alg_clean_volatile3, "volatile3" },
  { OQS_MEM_alg_clean_sodium, "sodium" },
#if defined(HAVE_EXPLICIT_BZERO)
  { OQS_MEM_alg_clean_explicit_bzero, "explicit_bzero" },
#endif
#if defined(HAVE_MEMSET_S)
  { OQS_MEM_alg_clean_memset_s, "memset_s" },
#endif
#ifdef _WIN32
  { OQS_MEM_alg_clean_SecureZeroMemory, "SecureZeroMemory" },
#endif
};

#define MEM_TEST_SMALL_BLOCK_SIZE 0x1000L
#define MEM_TEST_LARGE_BLOCK_SIZE 0x1000000L
#define MEM_BENCH_SECONDS 1

static int mem_test_clean_wrapper(enum OQS_MEM_alg_name alg_name, const char *name) {

  OQS_MEM_clean_func mem_clean = OQS_MEM_func(alg_name);
  if (mem_clean == NULL) {
    fprintf(stderr, "mem_clean is NULL\n");
    return 0;
  }

  printf("================================================================================\n");
  printf("Testing %s\n", name);
  printf("================================================================================\n");
  
  PRINT_TIMER_HEADER
  TIME_OPERATION_SECONDS({ char *buff = malloc(MEM_TEST_SMALL_BLOCK_SIZE); mem_clean(buff, MEM_TEST_SMALL_BLOCK_SIZE); free(buff); }, "small block", MEM_BENCH_SECONDS);
  TIME_OPERATION_SECONDS({ char *buff = malloc(MEM_TEST_LARGE_BLOCK_SIZE); mem_clean(buff, MEM_TEST_LARGE_BLOCK_SIZE); free(buff); }, "large block", MEM_BENCH_SECONDS);
  PRINT_TIMER_FOOTER

  return 1;

}

int main() {

  int success;

  size_t mem_testcases_len = sizeof(mem_testcases) / sizeof(struct mem_testcase);
  for (size_t i = 0; i < mem_testcases_len; i++) {
    success = mem_test_clean_wrapper(mem_testcases[i].alg_name, mem_testcases[i].name);
    if (success != 1) {
      goto err;
    }
  }

  success = 1;
  goto cleanup;

err:
  success = 0;
  fprintf(stderr, "ERROR!\n");

cleanup:

  return (success == 1) ? EXIT_SUCCESS : EXIT_FAILURE;

}

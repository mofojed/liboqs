#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

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


// Memory stack inspection 
// https://github.com/jpouellet/signify-osx/blob/master/src/regress/lib/libc/explicit_bzero/explicit_bzero.c
static const char secret[24] = {
  0x4e, 0x65, 0x76, 0x65, 0x72, 0x20, 0x67, 0x6f, 
  0x6e, 0x6e, 0x61, 0x20, 0x67, 0x69, 0x76, 0x65, 
  0x20, 0x79, 0x6f, 0x75, 0x20, 0x75, 0x70, 0x2c,
};

static char altstack[SIGSTKSZ + sizeof(secret)];

static void setup_stack(void) {
  const stack_t sigstk = {
    .ss_sp = altstack,
    .ss_size = sizeof(altstack),
  };

  assert(0 == sigaltstack(&sigstk, NULL));
}

static void assert_on_stack(void) {
  stack_t cursigstk;
  assert(0 == sigaltstack(NULL, &cursigstk));
  assert(SS_ONSTACK == (cursigstk.ss_flags & (SS_DISABLE|SS_ONSTACK)));
}


static void call_on_stack(void (*fn)(int)) {
  /*
   * This is a bit more complicated than strictly necessary, but
   * it ensures we don't have any flaky test failures due to
   * inherited signal masks/actions/etc.
   *
   * On systems where SA_ONSTACK is not supported, this could
   * alternatively be implemented using makecontext() or
   * pthread_attr_setstack().
   */

  const struct sigaction sigact = {
    .sa_handler = fn,
    .sa_flags = SA_ONSTACK,
  };

  struct sigaction oldsigact;
  sigset_t sigset, oldsigset;

  /* First, block all signals. */
  assert(0 == sigemptyset(&sigset));
  assert(0 == sigfillset(&sigset));
  assert(0 == sigprocmask(SIG_BLOCK, &sigset, &oldsigset));

  /* Next setup the signal handler for SIGUSR1. */
  assert(0 == sigaction(SIGUSR1, &sigact, &oldsigact));

  /* Raise SIGUSR1 and momentarily unblock it to run the handler. */
  assert(0 == raise(SIGUSR1));
  assert(0 == sigdelset(&sigset, SIGUSR1));
  assert(-1 == sigsuspend(&sigset));

  /* Restore the original signal action, stack, and mask. */
  assert(0 == sigaction(SIGUSR1, &oldsigact, NULL));
  assert(0 == sigprocmask(SIG_SETMASK, &oldsigset, NULL));
}

static void write_secret(char *buf, size_t len) {
  memcpy(buf, secret, len);
}

static char *mem_test_clean(OQS_MEM_clean_func mem_clean) {
  char buf[sizeof(secret)];

  write_secret(buf, sizeof(buf));
  
  char *res = memmem(altstack, sizeof(altstack), buf, sizeof(buf));
  
  if (NULL != mem_clean) {
    mem_clean(buf, sizeof(buf));
  } else {
    // Fallback to memset
    // With optimizations enabled, this (should) get optimized out
    memset(buf, 0, sizeof(buf));
  }
  return res;
}

// Test check to verify the secret is where we expect it to be if things aren't zero'ed out
static int mem_test_correctness_noclean() {
  printf("No Clean\t");
#ifdef __OPTIMIZE__
  char *buf = mem_test_clean(NULL);
  
  if (0 == memcmp(buf, secret, sizeof(secret))) {
    printf("PASSED\n");
    return 1;
  } else {
    printf("FAILED\n");
    return 0;
  }
#else
  printf("SKIPPED (no optimizations)\n");
  return 1;
#endif
}

static int mem_test_correctness_clean(enum OQS_MEM_alg_name alg_name, const char *name) {  
  OQS_MEM_clean_func mem_clean = OQS_MEM_func(alg_name);
  if (mem_clean == NULL) {
    fprintf(stderr, "mem_clean is NULL\n");
    return 0;
  }

  assert_on_stack();

  printf("%s\t", name);

  char *buf = mem_test_clean(mem_clean);
  
  if (0 != memcmp(buf, secret, sizeof(secret))) {
    printf("PASSED\n");
    return 1;
  } else {
    printf("FAILED\n");
    return 0;
  }
}

static int mem_test_bench_clean(enum OQS_MEM_alg_name alg_name, const char *name) {

  OQS_MEM_clean_func mem_clean = OQS_MEM_func(alg_name);
  if (mem_clean == NULL) {
    fprintf(stderr, "mem_clean is NULL\n");
    return 0;
  }

  printf("================================================================================\n");
  printf("Benchmark Tests: %s\n", name);
  printf("================================================================================\n");
  
  PRINT_TIMER_HEADER
  TIME_OPERATION_SECONDS({ char *buff = malloc(MEM_TEST_SMALL_BLOCK_SIZE); mem_clean(buff, MEM_TEST_SMALL_BLOCK_SIZE); free(buff); }, "small block", MEM_BENCH_SECONDS);
  TIME_OPERATION_SECONDS({ char *buff = malloc(MEM_TEST_LARGE_BLOCK_SIZE); mem_clean(buff, MEM_TEST_LARGE_BLOCK_SIZE); free(buff); }, "large block", MEM_BENCH_SECONDS);
  PRINT_TIMER_FOOTER
  printf("\n");

  return 1;

}

static void mem_test_correctness() {
  size_t i;
  size_t mem_testcases_len = sizeof(mem_testcases) / sizeof(struct mem_testcase);

  printf("================================================================================\n");
  printf("Memory Cleaning Correctness Test\n");
  printf("================================================================================\n");

  mem_test_correctness_noclean();

  for (i = 0; i < mem_testcases_len; i++) {
    if (mem_test_correctness_clean(mem_testcases[i].alg_name, mem_testcases[i].name) != 1) {
      goto err;
    }
  }

  printf("All memory cleaning correctness tests passed.\n\n");

err:
  return;
}

int main() {

  int success;
  size_t i;
  size_t mem_testcases_len = sizeof(mem_testcases) / sizeof(struct mem_testcase);

  setup_stack();
  call_on_stack(mem_test_correctness);

  for (i = 0; i < mem_testcases_len; i++) {
    success = mem_test_bench_clean(mem_testcases[i].alg_name, mem_testcases[i].name);
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

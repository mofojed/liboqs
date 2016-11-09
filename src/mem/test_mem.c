#include <assert.h>
#include <errno.h>
#include <setjmp.h>
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

/** The secret that we write out to the stack. After cleaning, we shouldn't be able to find it in our stack */
static const char secret[24] = {
	0x4e, 0x65, 0x76, 0x65, 0x72, 0x20, 0x67, 0x6f,
	0x6e, 0x6e, 0x61, 0x20, 0x67, 0x69, 0x76, 0x65,
	0x20, 0x79, 0x6f, 0x75, 0x20, 0x75, 0x70, 0x2c,
};

/* Number of times to write the secret */
#define MEM_STACK_SIZE (SIGSTKSZ + sizeof(secret))

/** Memory allocated for our stack */
static char stack_buf[MEM_STACK_SIZE];

/** Verify that we're on the custom stack */
static void assert_on_stack(void) {
	stack_t current_stack;
	assert(0 == sigaltstack(NULL, &current_stack));
	assert(SS_ONSTACK == (current_stack.ss_flags & SS_ONSTACK));
}

/** Call the provided signal handler on a custom stack */
static void call_on_stack(void (*fn)(int)) {
	const stack_t stack = {
		.ss_sp = stack_buf,
		.ss_size = sizeof(stack_buf),
	};

	const struct sigaction action = {
		.sa_handler = fn,
		.sa_flags = SA_ONSTACK,
	};

	stack_t old_stack;
	struct sigaction old_action;

	// Set up the stack and signal handler
	assert(0 == sigaltstack(&stack, &old_stack));
	assert(0 == sigaction(SIGUSR1, &action, &old_action));

	// Raise the signal. This will only return after the signal handler has returned
	assert(0 == raise(SIGUSR1));

	// Restore the previouse state, disable our alt stack
	sigaction(SIGUSR1, &old_action, NULL);
	sigaltstack(&old_stack, NULL);
}

/**
 * Test a provided memory clean algorithm. Must be called from the custom stack.
 * First writes the secret to the stack, then runs the provided cleaning algorithm.
 * If no cleaning algorithm is provided, just falls back to using memset.
 *
 * Returns the address of where the secret was written. If memory cleaning was successful,
 * the secret should no longer be readable.
 */
static char *mem_test_clean(OQS_MEM_clean_func mem_clean) {
	char buf[sizeof(secret)];
	char *res;

	assert_on_stack();

	memcpy(buf, secret, sizeof(secret));

	res = memmem(stack_buf, MEM_STACK_SIZE, buf, sizeof(buf));

	if (NULL != mem_clean) {
		mem_clean(buf, sizeof(buf));
	} else {
		// Fallback to memset
		// With optimizations enabled, this gets optimized out
		memset(buf, 0, sizeof(buf));
	}

	return res;
}

/**
 * Verify the secret is where we expect it to be if things aren't zero'ed out properly
 * This implementation uses memset, which should get optimized out. If optimizations aren't enabled,
 * this test is skipped.
 */
static int mem_test_correctness_noclean() {
#ifdef __OPTIMIZE__
	char *buf;

	buf = mem_test_clean(NULL);

	printf("%-30s", "No Clean");
	if (0 == memcmp(buf, secret, sizeof(secret))) {
		// The secret is still present, memset was optimized out (as we predicted)
		printf("PASSED\n");
		return 1;
	} else {
		printf("FAILED\n");
		return 0;
	}
#else
	printf("%-30s", "No Clean");
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

	printf("%-30s", name);

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

static void mem_test_correctness_signal_handler(int arg) {
	(void)(arg);
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

	call_on_stack(mem_test_correctness_signal_handler);

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

# RaPLT test suite Makefile
# Runs on Linux x86_64 without Android NDK

CC      = gcc
CFLAGS  = -std=gnu11 -Wall -Wextra -g -O0 -D_GNU_SOURCE \
          -Wno-unused-parameter -Wno-unused-function \
          -Wno-unused-but-set-variable -Wno-unused-variable
INCLUDE = -I../include -I. -Itest_stubs
LDFLAGS = -ldl -lpthread -lm

RA_SRC  = ../src
RA_OBJS = $(RA_SRC)/raplt_core.o $(RA_SRC)/raplt_elf.o \
          $(RA_SRC)/raplt_hash.o $(RA_SRC)/raplt_signal.o \
          $(RA_SRC)/raplt_util.o $(RA_SRC)/raplt_recon.o \
          $(RA_SRC)/raplt_cfi.o $(RA_SRC)/raplt_dlopen.o \
          $(RA_SRC)/raplt_mremap.o

LDFLAGS = -ldl -lpthread -lm

TESTS   = test_elf test_hash test_sleb128 test_core \
          test_got_patch test_batch test_signal_safety \
          test_hook test_region
TARGETS = libtestfixture.so libtest_hook_caller.so $(TESTS)

.PHONY: all clean test

all: $(TARGETS)

libtestfixture.so: test_fixture.c
	$(CC) $(CFLAGS) -shared -fPIC -fvisibility=default \
		-o $@ $< $(LDFLAGS)

libtest_hook_caller.so: test_hook_caller.c
	$(CC) $(CFLAGS) -shared -fPIC -fvisibility=default \
		-o $@ $< $(LDFLAGS) -L. -ltestfixture -Wl,-rpath=.

# compile raplt objects
$(RA_SRC)/raplt_core.o: $(RA_SRC)/raplt_core.c
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $<

$(RA_SRC)/raplt_elf.o: $(RA_SRC)/raplt_elf.c
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $<

$(RA_SRC)/raplt_hash.o: $(RA_SRC)/raplt_hash.c
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $<

$(RA_SRC)/raplt_signal.o: $(RA_SRC)/raplt_signal.c
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $<

$(RA_SRC)/raplt_util.o: $(RA_SRC)/raplt_util.c
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $<

$(RA_SRC)/raplt_recon.o: $(RA_SRC)/raplt_recon.c
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $<

$(RA_SRC)/raplt_cfi.o: $(RA_SRC)/raplt_cfi.c
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $<

$(RA_SRC)/raplt_dlopen.o: $(RA_SRC)/raplt_dlopen.c
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $<

$(RA_SRC)/raplt_mremap.o: $(RA_SRC)/raplt_mremap.c
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $<

# standalone tests (no raplt library needed)
test_sleb128: test_sleb128.c test_runner.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# tests that need raplt objects
test_elf: test_elf.c test_runner.h $(RA_SRC)/raplt_elf.o $(RA_SRC)/raplt_hash.o $(RA_SRC)/raplt_util.o $(RA_SRC)/raplt_recon.o libtestfixture.so
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(RA_SRC)/raplt_elf.o $(RA_SRC)/raplt_hash.o $(RA_SRC)/raplt_util.o $(RA_SRC)/raplt_recon.o $(LDFLAGS)

test_hash: test_hash.c test_runner.h $(RA_SRC)/raplt_hash.o $(RA_SRC)/raplt_elf.o
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(RA_SRC)/raplt_hash.o $(RA_SRC)/raplt_elf.o $(LDFLAGS)

test_core: test_core.c test_runner.h $(RA_OBJS) libtestfixture.so
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(RA_OBJS) $(LDFLAGS)

test_got_patch: test_got_patch.c test_runner.h $(RA_OBJS) libtestfixture.so
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(RA_OBJS) $(LDFLAGS)

test_batch: test_batch.c test_runner.h $(RA_SRC)/raplt_util.o
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(RA_SRC)/raplt_util.o $(LDFLAGS)

test_signal_safety: test_signal_safety.c test_runner.h $(RA_SRC)/raplt_signal.o $(RA_SRC)/raplt_util.o
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(RA_SRC)/raplt_signal.o $(RA_SRC)/raplt_util.o $(LDFLAGS)

test_hook: test_hook.c test_runner.h $(RA_OBJS) libtestfixture.so libtest_hook_caller.so
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(RA_OBJS) $(LDFLAGS)

test_region: test_region.c test_runner.h $(RA_OBJS) libtestfixture.so
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(RA_OBJS) $(LDFLAGS)

test: $(TARGETS)
	@./run_tests.sh

clean:
	rm -f $(TARGETS) $(RA_OBJS) *.o

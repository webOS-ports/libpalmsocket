# @@@LICENSE
#
# Copyright (c) 2026 Herman van Hazendonk <github.com@herrie.org>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# LICENSE@@@
#
# Standalone test harness for libpalmsocket.
#
# Builds the library sources directly (no webOS cmake modules needed)
# together with the tests, against a selectable OpenSSL:
#
#   make check                          # system OpenSSL
#   make check OPENSSL_PREFIX=/opt/ossl # a specific OpenSSL install
#   make check ASAN=1                   # AddressSanitizer+UBSan build
#   make stress ITER=200 PAYLOAD=1048576
#
# DEPS_INC/DEPS_LIB must point at directories providing PmLogLib.h,
# PmStateMachineEngine/ headers and the corresponding shared libs;
# ./run_matrix.sh bootstraps them automatically on a host machine.

REPO      := $(abspath ../..)
BUILD     ?= build
CC        ?= gcc

OPENSSL_PREFIX ?=
DEPS_INC  ?= $(abspath deps-build/include)
DEPS_LIB  ?= $(abspath deps-build/lib)
ASAN      ?= 0
ITER      ?= 3
PAYLOAD   ?= 262144

PKG_CFLAGS := $(shell pkg-config --cflags glib-2.0 libcares 2>/dev/null || \
                      pkg-config --cflags glib-2.0)
PKG_LIBS   := $(shell pkg-config --libs glib-2.0 libcares 2>/dev/null || \
                      echo "$$(pkg-config --libs glib-2.0) -lcares")

CFLAGS  += -O1 -g -fPIC -Wall -Wextra -Wno-deprecated-declarations \
           -I$(REPO)/include/public/palmsocket -I$(REPO)/src -I. \
           -I$(DEPS_INC) $(PKG_CFLAGS)
LDFLAGS += -L$(DEPS_LIB) -Wl,-rpath,$(DEPS_LIB)
LDLIBS  += -lPmStateMachineEngine -lPmLogLib $(PKG_LIBS) -lpthread

ifneq ($(OPENSSL_PREFIX),)
  CFLAGS  += -I$(OPENSSL_PREFIX)/include
  LDFLAGS += -L$(OPENSSL_PREFIX)/lib -Wl,-rpath,$(OPENSSL_PREFIX)/lib
endif
LDLIBS += -lssl -lcrypto

ifeq ($(ASAN),1)
  CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
  LDFLAGS += -fsanitize=address,undefined
endif

LIB_SRCS  := $(wildcard $(REPO)/src/*.c)
LIB_OBJS  := $(patsubst $(REPO)/src/%.c,$(BUILD)/lib/%.o,$(LIB_SRCS))

TESTS     := test_io_buf test_hostname test_cert_store test_loopback
TEST_BINS := $(addprefix $(BUILD)/,$(TESTS))

.PHONY: all check stress clean

all: $(TEST_BINS)

$(BUILD)/lib/%.o: $(REPO)/src/%.c
	@mkdir -p $(BUILD)/lib
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%: %.c $(LIB_OBJS)
	@mkdir -p $(BUILD)
	@$(CC) $(CFLAGS) $< $(LIB_OBJS) $(LDFLAGS) $(LDLIBS) -o $@

check: all
	@fail=0; \
	for t in $(TESTS); do \
	    if [ "$$t" = "test_loopback" ]; then \
	        ./$(BUILD)/$$t $(ITER) $(PAYLOAD) || fail=1; \
	    else \
	        ./$(BUILD)/$$t || fail=1; \
	    fi; \
	done; \
	exit $$fail

stress: $(BUILD)/test_loopback
	./$(BUILD)/test_loopback $(ITER) $(PAYLOAD)

clean:
	rm -rf $(BUILD)

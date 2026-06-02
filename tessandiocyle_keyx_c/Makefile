# TessanDioKey V18 — Native C Makefile (no external crypto deps except ref_c randombytes+fips202)

CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -I.

# Our native V18 files
SRC = reduce.c ntt.c cbd.c verify.c symmetric.c poly.c polyvec.c \
      indcpa.c kem.c graph.c reconcile.c protocol.c tessandiocyle_keyx.c \
      merkle.c trapdoor.c secure.c

# External SHAKE/SHA3 + randombytes (copied locally from ref_c)
REF_SRC = fips202.c randombytes.c

TEST_DIR = tests
TARGET   = $(TEST_DIR)/cli_test.exe

ifeq ($(OS),Windows_NT)
    RM = del /Q
    CLEAN_TARGET = $(subst /,\,$(TARGET))
else
    RM = rm -f
    CLEAN_TARGET = $(TARGET)
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(TEST_DIR)/cli_test.c $(SRC) $(REF_SRC)
	$(CC) $(CFLAGS) -o $@ $(TEST_DIR)/cli_test.c $(SRC) $(REF_SRC)

clean:
	$(RM) $(CLEAN_TARGET)

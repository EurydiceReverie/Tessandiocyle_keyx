# TessanDioKey V18 — Pure C++ Native Makefile
CXX      = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -Isrc

SRC = src/shake.cpp src/ntt.cpp src/cbd.cpp src/indcpa.cpp src/kem.cpp \
      src/graph.cpp src/reconcile.cpp src/protocol.cpp src/merkle.cpp \
      src/trapdoor.cpp src/random.cpp

TARGET = cli_test.exe

ifeq ($(OS),Windows_NT)
    RM = del /Q
else
    RM = rm -f
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): tests/cli_test.cpp $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ tests/cli_test.cpp $(SRC)

clean:
	$(RM) $(TARGET)

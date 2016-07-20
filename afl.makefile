# Makefile for building opener for use with AFL

PWD = $(shell pwd)

# for special "dump mode"
#EXTRA_FLAGS="-D_AFL_DUMP -D_XOPEN_SOURCE=600"

# for using the SHIM
EXTRA_FLAGS="-D_AFL_PERSISTENT_SHIM -DOPENER_WITH_TRACES -DOPENER_TRACE_LEVEL=8"


all: depends bin/posix/src/ports/POSIX/OpENer


afl:
	git clone https://github.com/mirrorer/afl.git

afl/afl-clang: afl
	make -C afl

bin/posix/src/ports/POSIX/OpENer: afl/afl-clang
	cd bin/posix/; cmake -DCMAKE_C_FLAGS=$(EXTRA_FLAGS) -DCMAKE_C_COMPILER:FILEPATH=$(PWD)/afl/afl-clang -DOpENer_PLATFORM:STRING="POSIX" -DCMAKE_BUILD_TYPE:STRING="" ../../source
	cd bin/posix/; make

.PHONY: depends
depends:
	sudo apt-get install clang make cmake build-essential




PWD = $(shell pwd)
.PHONY: dump fuzz

depends:
	sudo apt-get install clang
	git clone https://github.com/mirrorer/afl.git

dump:
	cd bin/posix/
	cmake -DCMAKE_C_FLAGS="-D_AFL_DUMP -D_XOPEN_SOURCE=600" -DCMAKE_C_COMPILER:FILEPATH=$(PWD)/afl-*/afl-clang -DOpENer_PLATFORM:STRING="POSIX" -DCMAKE_BUILD_TYPE:STRING="" ../../source
	cd $(PWD)

fuzz:
	cd bin/posix
	cmake -DCMAKE_C_FLAGS="-D_AFL_PERSISTENT_SHIM -DOPENER_WITH_TRACES -DOPENER_TRACE_LEVEL=8" -DCMAKE_C_COMPILER:FILEPATH=$(PWD)/afl-*/afl-clang -DOpENer_PLATFORM:STRING="POSIX" -DCMAKE_BUILD_TYPE:STRING="" ../../source
	cd $(PWD)


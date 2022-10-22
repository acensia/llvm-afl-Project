AFL_LLVM=${CURDIR}/../afl-2.33b/afl-clang-fast
AFL_FUZZ=${CURDIR}/../afl-2.33b/afl-fuzz

all: bin-weak bin-strong bin-long

llvm:
	(cd ${CURDIR}/../afl-2.33b/llvm_mode && make)

llvm-mod:
	(cd ${CURDIR}/../afl-2.33b/llvm_mode && make)

bin-weak: test.c 
	${AFL_LLVM} -std=c99 -D COND_WEAK $< -o $@

runafl-weak: bin-weak
	${AFL_FUZZ} -i ${CURDIR}/input -o ${CURDIR}/output-weak ${CURDIR}/$< @@

bin-strong: test.c 
	${AFL_LLVM} -std=c99 -O0 $< -o $@

runafl-strong: bin-strong
	${AFL_FUZZ} -i ${CURDIR}/input -o ${CURDIR}/output-strong ${CURDIR}/$< @@

bin-long: test.c
	${AFL_LLVM} -std=c99 -D COND_LONG $< -o $@

runafl-long: bin-long
	${AFL_FUZZ} -i ${CURDIR}/input -o ${CURDIR}/output-long ${CURDIR}/$< @@

bin-mul: test.c
	${AFL_LLVM} -std=c99 -D COND_WEAK -D COND_MUL $< -o $@

runafl-mul: bin-mul
	${AFL_FUZZ} -i ${CURDIR}/input -o ${CURDIR}/output-mul ${CURDIR}/$< @@

rebuild:
	(make clean && make llvm && make bin-strong)

.phony: bin-weak bin-strong runafl-weak runafl-strong clean bin-lng runafl-long

clean:
	rm -rf bin-weak bin-strong bin-long  
	rm -rf output-weak output-strong output-long 

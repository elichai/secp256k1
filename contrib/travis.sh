#!/bin/sh -ex

if [ -n "$HOST" ]
then
    export USE_HOST="--host=$HOST"
fi
if [ "$HOST" = "i686-linux-gnu" ]
then
    export CC="$CC -m32"
fi

./configure \
    --enable-experimental="$EXPERIMENTAL" --enable-endomorphism="$ENDOMORPHISM" \
    --with-field="$FIELD" --with-bignum="$BIGNUM" --with-asm="$ASM" --with-scalar="$SCALAR" \
    --enable-ecmult-static-precomputation="$STATICPRECOMPUTATION" --with-ecmult-gen-precision="$ECMULTGENPRECISION" \
    --enable-module-ecdh="$ECDH" --enable-module-recovery="$RECOVERY" "$EXTRAFLAGS" "$USE_HOST"

if [ -n "$BUILD" ]
then
    make -j2 "$BUILD"
fi
if [ -n "$VALGRIND" ]
then
   make -j2
# the `--error-exitcode` is required to make the test fail if valgrind found errors, otherwise it'll return 0 (http://valgrind.org/docs/manual/manual-core.html)
   valgrind --error-exitcode=42 ./tests 16
   valgrind --error-exitcode=42 ./exhaustive_tests
   fi
if [ -n "$BENCH" ]
then
    if [ -n "$VALGRIND" ]
    then
        EXEC='libtool --mode=execute valgrind --error-exitcode=42'
    else
        EXEC=
    fi
    $EXEC ./bench_ecmult >> bench.log 2>&1
    $EXEC ./bench_internal >> bench.log 2>&1
    $EXEC ./bench_sign >> bench.log 2>&1
    $EXEC ./bench_verify >> bench.log 2>&1
    if [ "$RECOVERY" = "yes" ]
    then
        $EXEC ./bench_recover >> bench.log 2>&1
    fi
    if [ "$ECDH" = "yes" ]
    then
        $EXEC ./bench_ecdh >> bench.log 2>&1
    fi
fi
if [ -n "$CTIMETEST" ]
then
   libtool --mode=execute valgrind --error-exitcode=42 ./valgrind_ctime_test > valgrind_ctime_test.log 2>&1
fi

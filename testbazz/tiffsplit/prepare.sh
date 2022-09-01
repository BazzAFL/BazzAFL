TARGET=tiffsplit
FUZZER=afl-fuzz
# cd ../.. && make clean && make
cd ../.. && make $FUZZER
cp -f $FUZZER programs/$TARGET/$FUZZER
cd testbazz/$TARGET

rm -rf out/

# AFL_NO_UI=1 timeout 24h ./afl-fuzz -i in -z 4 -o out ./tiffsplit @@

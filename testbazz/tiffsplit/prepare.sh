TARGET=tiffsplit
FUZZER=afl-fuzz
cd ../.. && make $FUZZER
cp -f $FUZZER testbazz/$TARGET/$FUZZER
cd testbazz/$TARGET

# rm -rf out/

# AFL_NO_UI=1 timeout 24h ./afl-fuzz -i in_tif -z 4 -o out ./tiffsplit @@

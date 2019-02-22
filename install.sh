make clean
./bootstrap.sh && ./configure
sed -i 's/-lm/-lm -lpthread/g' Makefile
make

#! /bin/sh

make clean

mkdir -p obj/amd64

x86_64-cros-linux-gnu-clang++  -Os -pipe  -march=tremont -g -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wall -Os -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -c hx_util_src/main.cpp -o obj/amd64/main.o
x86_64-cros-linux-gnu-clang++  -Os -pipe  -march=tremont -g -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wall -Os -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE  -c hx_util_src/hx_dev_api.cpp -o obj/amd64/hx_dev_api.o
x86_64-cros-linux-gnu-clang++  -Os -pipe  -march=tremont -g -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wall -Os -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE  -c hx_util_src/hx_i2c_func.cpp -o obj/amd64/hx_i2c_func.o
x86_64-cros-linux-gnu-clang++  -Os -pipe  -march=tremont -g -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wall -Os -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -c hx_util_src/hx_hid_func.cpp -o obj/amd64/hx_hid_func.o
x86_64-cros-linux-gnu-clang++  -Os -pipe  -march=tremont -g -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wall -Os -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -Wl,-O2 -Wl,--as-needed  -Wl,--gc-sections -Wl,--icf=all obj/amd64/main.o obj/amd64/hx_dev_api.o obj/amd64/hx_i2c_func.o obj/amd64/hx_hid_func.o  -o hx_util_amd64


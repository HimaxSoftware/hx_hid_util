#! /bin/sh

make clean

mkdir -p obj/armv8

aarch64-cros-linux-gnu-clang++  -Os -pipe  -march=armv8-a+crc+crypto -mtune=cortex-a55 -ftree-vectorize -g -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wall -Os -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE   -c hx_util_src/main.cpp -o obj/armv8/main.o
aarch64-cros-linux-gnu-clang++  -Os -pipe  -march=armv8-a+crc+crypto -mtune=cortex-a55 -ftree-vectorize -g -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wall -Os -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE   -c hx_util_src/hx_dev_api.cpp -o obj/armv8/hx_dev_api.o
aarch64-cros-linux-gnu-clang++  -Os -pipe  -march=armv8-a+crc+crypto -mtune=cortex-a55 -ftree-vectorize -g -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wall -Os -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE   -c hx_util_src/hx_i2c_func.cpp -o obj/armv8/hx_i2c_func.o
aarch64-cros-linux-gnu-clang++  -Os -pipe  -march=armv8-a+crc+crypto -mtune=cortex-a55 -ftree-vectorize -g -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wall -Os -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE   -c hx_util_src/hx_hid_func.cpp -o obj/armv8/hx_hid_func.o
aarch64-cros-linux-gnu-clang++  -Os -pipe  -march=armv8-a+crc+crypto -mtune=cortex-a55 -ftree-vectorize -g -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wall -Os -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE  -Wl,-O2 -Wl,--as-needed  -Wl,--gc-sections -Wl,--icf=all obj/armv8/main.o obj/armv8/hx_dev_api.o obj/armv8/hx_i2c_func.o obj/armv8/hx_hid_func.o  -o hx_util_arm64

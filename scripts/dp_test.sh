#!/bin/bash
make clean;make;scp hx_util tylor@hxse-upx-arl01.local:/home/tylor/www/hx_util;ssh -t tylor@hxse-upx-arl01.local "cd www;chmod 751 hx_util;sudo ./hx_util -l -S 0x9 -D -Y -o log"

###########################################
# Simple Makefile for hx_util
#
# 2021-09-16
###########################################

AP	= hx_util

all: $(AP)

CXXFLAGS	+= -Wall -Os -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE 

CPPOBJS  	= hx_util_src/main.o \
			hx_util_src/hx_dev_api.o \
			hx_util_src/hx_i2c_func.o \
			hx_util_src/hx_hid_func.o

OBJS      	= $(CPPOBJS)

$(AP): $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ $(LIBS) -o $(AP)

$(CPPOBJS): %.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(AP)

.PHONY: clean

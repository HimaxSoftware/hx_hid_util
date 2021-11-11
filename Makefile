###########################################
# Simple Makefile for hx_util
#
# chenyt
# 2021-09-16
###########################################

AP	= hx_util

all: $(AP)

CXXFLAGS	?= -Wall -Os

CPPOBJS  	= hx_util_src/main.o \
			hx_util_src/hx_dev_api.o \
			hx_util_src/hx_i2c_func.o \

OBJS      	= $(CPPOBJS)
LIBS		= -pthread -lrt

$(AP): $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ $(LIBS) -o $(AP)

$(CPPOBJS): %.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(AP)

.PHONY: clean

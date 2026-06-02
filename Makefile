###########################################
# Simple Makefile for hx_util
#
# 2021-09-16
###########################################

AP	= hx_util
APE = hx_util-e
all: $(AP)

OBJ_DIR = obj

CXXFLAGS	+= -Wall -Os -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -ffunction-sections -fdata-sections
LDFLAGS     += -Wl,--gc-sections

CPPOBJS  	= $(OBJ_DIR)/main.o \
			$(OBJ_DIR)/hx_dev_api.o \
			$(OBJ_DIR)/hx_i2c_func.o \
			$(OBJ_DIR)/hx_hid_func.o

OBJS      	= $(CPPOBJS)

ARCH_SEL	?= $(ARCH)

ifeq ($(strip $(ARCH_SEL)),)
ARCH_SEL	:= $(shell uname -m)
endif

ifeq ($(ARCH_SEL),arm64)
	DEFAULT_CXX	= aarch64-linux-gnu-g++
	DEFAULT_CC	= aarch64-linux-gnu-gcc
	DEFAULT_OBJCOPY	= aarch64-linux-gnu-objcopy
	DEFAULT_STRIP	= aarch64-linux-gnu-strip
	OBJCOPY_INFO	:= $(shell $(DEFAULT_OBJCOPY) --info 2>/dev/null)
	DEFAULT_OBJDUMP	= aarch64-linux-gnu-objdump
	ifneq ($(findstring elf64-littleaarch64,$(OBJCOPY_INFO)),)
OBJCOPY_FMT	= elf64-littleaarch64
	else
OBJCOPY_FMT	= elf64-little
	endif
else ifeq ($(ARCH_SEL),aarch64)
	DEFAULT_CXX	= aarch64-linux-gnu-g++
	DEFAULT_CC	= aarch64-linux-gnu-gcc
	DEFAULT_OBJCOPY	= aarch64-linux-gnu-objcopy
	DEFAULT_STRIP	= aarch64-linux-gnu-strip
	DEFAULT_OBJDUMP	= aarch64-linux-gnu-objdump
	OBJCOPY_INFO	:= $(shell $(DEFAULT_OBJCOPY) --info 2>/dev/null)
	ifneq ($(findstring elf64-littleaarch64,$(OBJCOPY_INFO)),)
OBJCOPY_FMT	= elf64-littleaarch64
	else
OBJCOPY_FMT	= elf64-little
	endif
else ifeq ($(ARCH_SEL),x86_64)
	DEFAULT_CXX	= g++
	DEFAULT_CC	= cc
	DEFAULT_OBJCOPY	= objcopy
	DEFAULT_STRIP	= strip
	DEFAULT_OBJDUMP	= objdump
OBJCOPY_FMT	= elf64-x86-64
else
$(error Unsupported ARCH '$(ARCH_SEL)'; use x86_64, arm64, or aarch64)
endif

ifeq ($(origin CXX), default)
CXX		= $(DEFAULT_CXX)
endif

ifeq ($(origin CC), default)
CC		= $(DEFAULT_CC)
endif

ifneq ($(filter undefined default,$(origin OBJCOPY)),)
OBJCOPY		= $(DEFAULT_OBJCOPY)
endif

ifneq ($(filter undefined default,$(origin STRIP)),)
STRIP       = $(DEFAULT_STRIP)
endif

$(AP): $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ $(LIBS) -o $(AP)
	$(STRIP) -s $(AP)

$(CPPOBJS): $(OBJ_DIR)/%.o: hx_util_src/%.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@

ifeq ($(MAKECMDGOALS),embd)
CUSTOMER    ?= $(error Please specify a CUSTOMER when building the embedded version, e.g. make embd CUSTOMER=customer1)
PROJECT     ?= $(error Please specify a PROJECT when building the embedded version, e.g. make embd PROJECT=project1)
endif

embd: $(APE)

EMBD_OBJ_DIR = obje

CPPEOBJS  	= $(EMBD_OBJ_DIR)/main.o \
			$(EMBD_OBJ_DIR)/hx_dev_api.o \
			$(EMBD_OBJ_DIR)/hx_i2c_func.o \
			$(EMBD_OBJ_DIR)/hx_hid_func.o

ENCODE_PY	= python3 hx_util_src/encode.py
CFLAGS      += -ffunction-sections -fdata-sections
# CFLAGS      += -DLZ4_DEBUG=2
FWLZ4       = $(EMBD_OBJ_DIR)/temp.rc
FW_SIZE_HDR = $(EMBD_OBJ_DIR)/embed_size.h
FWOBJS      = $(EMBD_OBJ_DIR)/temp.rco
LZ4			= lz4
COBJS		= $(EMBD_OBJ_DIR)/lz4.o
EOBJS      	= $(FWOBJS) $(CPPEOBJS) $(COBJS)
$(FW_SIZE_HDR): $(FWOBJS)
	@size=`$(DEFAULT_OBJDUMP) $< -t | awk '/_binary_$(EMBD_OBJ_DIR)_temp_rc_size/ { printf "%d\\n", "0x" $$1; found=1; exit } END { exit found ? 0 : 1 }'` && \
	echo "#define RSRC_SIZE ($$size)" > $@
	@start=`$(DEFAULT_OBJDUMP) $< -t | awk '/_binary_$(EMBD_OBJ_DIR)_temp_rc_start/ { printf "%s\\n", $$5; found=1; exit } END { exit found ? 0 : 1 }'` && \
	echo "#define RSRC_START $$start" >> $@
	@orig_size=`stat -c %s resource/temp.bin` && \
	echo "#define ORIG_SIZE ($$orig_size)" >> $@
$(CPPEOBJS): $(EMBD_OBJ_DIR)/%.o: hx_util_src/%.cpp
	$(CXX) $(CXXFLAGS) -D_EMBEDDED_FW_ -DTARGET_CUSTOMER=\"$(CUSTOMER)\" -DTARGET_PROJECT=\"$(PROJECT)\" $(CPPFLAGS) -include $(FW_SIZE_HDR) -c $< -o $@

$(CPPEOBJS): $(FW_SIZE_HDR)

$(FWLZ4): $(EMBD_OBJ_DIR)/%.rc: resource/%.bin
	$(ENCODE_PY) $< $@ resource/xor.key

$(FWOBJS): $(EMBD_OBJ_DIR)/%.rco: $(EMBD_OBJ_DIR)/%.rc
	$(OBJCOPY) -I binary -O $(OBJCOPY_FMT) --add-section .note.GNU-stack=/dev/null --set-section-flags .note.GNU-stack=contents,readonly $< $@

$(COBJS): $(EMBD_OBJ_DIR)/%.o: hx_util_src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(APE): $(EOBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ $(LIBS) -o $(APE)
	$(STRIP) -s $(APE)


clean:
	rm -rf $(OBJS) $(AP) $(APE) $(FWLZ4) $(FW_SIZE_HDR) $(FWOBJS) $(COBJS) $(EOBJS) $(OBJ_DIR) $(EMBD_OBJ_DIR)
	mkdir -p $(OBJ_DIR) $(EMBD_OBJ_DIR)

.PHONY: clean embd

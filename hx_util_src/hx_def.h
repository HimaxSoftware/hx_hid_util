/*
 * Copyright (C) 2021 Himax Technologies, Limited.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef	__HX_DEF_H__
#define	__HX_DEF_H__

/* since long is 4bytes on windows64, but is 8bytes on linux 64 */
typedef unsigned char  uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int   uint32_t;
typedef signed char  int8_t;
typedef signed short int16_t;
typedef signed int   int32_t;


enum or_option {
	OPTION_CMP_VER = 1 << 0,
	OPTION_REBIND = 1 << 1,
	OPTION_ALL_LEN = 1 << 2,
	OPTION_INFO = 1 << 3,
	OPTION_FW_VER = 1 << 4,
	OPTION_PID = 1 << 5,
	OPTION_HID_FORCE_UPDATE = 1 << 6,
	OPTION_HID_SET_DATA_TYPE = 1 << 7,
	OPTION_HID_SHOW_REPORT = 1 << 8,
	OPTION_HID_SELF_TEST = 1 << 9,
	OPTION_HID_SELF_TEST_UPPER_BOUND = 1 << 10,
	OPTION_HID_SELF_TEST_LOWER_BOUND = 1 << 11
};

const int mutual_shift_bit = 12;

enum mutual_option {
	OPTION_NONE = ((1 << mutual_shift_bit) - 1),
	OPTION_UPDATE = (1 + 0) << mutual_shift_bit,
	OPTION_READ_REG = (1 + 1) << mutual_shift_bit,
	OPTION_WRITE_REG = (1 + 2) << mutual_shift_bit,
	OPTION_STATUS = (1 + 3) << mutual_shift_bit,
	OPTION_HID_MAIN_UPDATE = (1 + 4) << mutual_shift_bit,
	OPTION_HID_BL_UPDATE = (1 + 5) << mutual_shift_bit,
	OPTION_HID_ALL_UPDATE = (1 + 6) << mutual_shift_bit,
	OPTION_HID_INFO = (1 + 7) << mutual_shift_bit,
	OPTION_HID_READ_REG = (1 + 8) << mutual_shift_bit,
	OPTION_HID_WRITE_REG = (1 + 9) << mutual_shift_bit,
	OPTION_HID_SHOW_DIAG = (1 + 10) << mutual_shift_bit,
	OPTION_HID_SELF_TEST_CRITERIA_FILE = (1 + 11) << mutual_shift_bit,
	OPTION_HID_SHOW_PID_BY_HID_INFO = (1 + 12) << mutual_shift_bit,
	OPTION_HID_SHOW_FW_VER_BY_HID_INFO = (1 + 13) << mutual_shift_bit,
	OPTION_MUTUAL_FILTER = ~OPTION_NONE
};

#define HID_CFG_ID						(0x05)
#define HID_REG_RW_ID					(0x06)
#define HID_TOUCH_MONITOR_SEL_ID		(0x07)
#define HID_TOUCH_MONITOR_ID			(0x08)
#define HID_TOUCH_MONITOR_PARTIAL_ID	(0x09)
#define HID_FW_UPDATE_ID				(0x0A)
#define HID_FW_UPDATE_HANDSHAKING_ID	(0x0B)
#define HID_SELF_TEST_ID				(0x0C)
#define HID_INPUT_RD_EN_ID				(0x31)

#define HID_SELF_TEST_SHORT			(0x11)
#define HID_SELF_TEST_OPEN			(0x12)
#define HID_SELF_TEST_MICRO_OPEN	(0x13)
#define HID_SELF_TEST_RAWDATA		(0x21)
#define HID_SELF_TEST_NOISE			(0x22)

typedef	struct optdata {
	uint32_t options;
	char *fw_path;
	char dev_path[64];
	uint16_t pid;
	uint16_t vid;
	uint16_t bus;
	uint32_t w_addr_size;
	union {
		uint32_t i;
		uint8_t b[4];
	} w_reg_addr;
	uint32_t w_data_size;
	union {
		uint32_t i;
		uint8_t b[4];
	} w_reg_data;

	uint32_t r_addr_size;
	union {
		uint32_t i;
		uint8_t b[4];
	} r_reg_addr;
	union {
		uint32_t i;
		uint8_t b[4];
	} param;
	union {
		uint32_t i;
		uint8_t b[4];
	} input_en;

	int32_t self_test_spec_max;
	int32_t self_test_spec_min;
	char *criteria_path;
} OPTDATA;

typedef struct hxfw {
	uint8_t *data;
	uint32_t len;
} HXFW;

typedef struct devinfo {
	uint32_t vid;
	uint32_t pid;
} DEVINFO;

typedef struct __attribute__((__packed__)) hx_hid_fw_unit {
	uint8_t cmd;
	uint16_t bin_start_offset;
	uint16_t unit_sz;
} hx_hid_fw_unit_t;

typedef struct __attribute__((__packed__)) hx_hid_info_t {
	hx_hid_fw_unit_t main_mapping[9];
	hx_hid_fw_unit_t bl_mapping;
	uint8_t passwd[2];
	uint8_t cid[2];
	uint8_t panel_ver;
	uint8_t fw_ver[2];
	uint8_t ic_sign;
	char customer[12];
	char project[12];
	char fw_major[12];
	char fw_minor[12];
	char date[12];
	char ic_sign_2[12];
	uint8_t vid[2];
	uint8_t pid[2];
	uint8_t cfg_info[32];
	uint8_t cfg_version;
	uint8_t disp_version;
	uint8_t rx;
	uint8_t tx;
	uint16_t yres;
	uint16_t xres;
	uint8_t pt_num;
	uint8_t mkey_num;
	uint8_t debug_info[78];
} hx_hid_info;

typedef enum param_type {
	ONE_PARAM = 1,
	MORE_PARAM
} param_t;

enum fw_update_error_code {
	FWUP_ERROR_NO_ERROR = 0x77,
	FWUP_ERROR_MCU_00 = 0x00,
	FWUP_ERROR_MCU_A0 = 0xA0,
	FWUP_ERROR_NO_BL = 0xC1,
	FWUP_ERROR_NO_MAIN = 0xC2,
	FWUP_ERROR_BL = 0xB2,
	FWUP_ERROR_PW = 0xB3,
	FWUP_ERROR_ERASE_FLASH = 0xB4,
	FWUP_ERROR_FLASH_PROGRAMMING = 0xB5,
	FWUP_ERROR_NO_DEVICE = 0xFFFFFF00,
	FWUP_ERROR_LOAD_FW_BIN = 0xFFFFFF01,
	FWUP_ERROR_INITIAL = 0xFFFFFF02,
	FWUP_ERROR_POLLING_TIMEOUT = 0xFFFFFF03,
	FWUP_ERROR_FW_TRANSFER = 0xFFFFFF04
};

typedef struct hx_criteria_template {
	const char *keyword;
	bool activated;
	param_t type; // 1 : 1 param, 2 : params more than 1
	uint32_t rx;
	uint32_t tx;
	int32_t default_value;
	uint32_t param_count;
	int32_t *param_data;
} hx_criteria_t;

typedef struct hx_ic_fw_layout_mapping {
	const char ic_sign_2[12];
	const hx_hid_fw_unit_t *fw_table;
} hx_ic_fw_layout_mapping_t;

void hx_printf(const char *fmt, ...);

#endif

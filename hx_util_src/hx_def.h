/*
 * Copyright (C) 2021 Himax Technologies, Inc.
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

/* define for device control */
#define OPTION_UPDATE        0x01
#define OPTION_CMP_VER       0x02
#define	OPTION_REBIND        0x04
/* define for info from the device */
#define OPTION_INFO          0x10
#define OPTION_FW_VER        0x20
#define OPTION_PID           0x40
#define	OPTION_STATUS        0x80

typedef	struct optdata {
	uint32_t options;
	char *fw_path;
	char dev_path[64];
} OPTDATA;

typedef struct hxfw {
	uint8_t *data;
	uint32_t len;
} HXFW;

typedef struct devinfo {
	uint32_t vid;
	uint32_t pid;
} DEVINFO;

void hx_printf(const char *fmt, ...);

#endif

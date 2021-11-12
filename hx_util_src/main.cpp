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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <getopt.h>
#include <stdarg.h>

#include "hx_def.h"
#include "hx_dev_api.h"

#define HX_UTIL_NAME "Himax Update Utility"
#define HX_UTIL_VER "V1.0.2"

#define HX_UTIL_OPT	"hd:u:cbivps"

static struct option long_option[] = {
	{"help", 0, NULL, 'h'},
	{"device", 1, NULL, 'd'},
	{"update", 1, NULL, 'u'},
	{"compare", 0, NULL, 'c'},
	{"rebind", 0, NULL, 'b'},
	{"info", 0, NULL, 'i'},
	{"fw-ver", 0, NULL, 'v'},
	{"pid", 0, NULL, 'p'},
	{"status", 0, NULL, 's'},
	{0, 0, 0, 0},
};

int g_show_dbg_log = 0;

void print_version()
{
	printf("%s %s\n", HX_UTIL_NAME, HX_UTIL_VER);
}

void print_help(const char *prog_name)
{
	print_version();

	printf("\nUsage: %s [OPTIONS] [FW_PATH|DEV_PATH|SUB-ARGU]\n", prog_name);
	printf("\t-h, --help\tOption description.\n");
	printf("\t-d, --device\ti2c device file associated with the device.\n");
	printf("\t-u, --update\tUpdate firmware with verification.\n");
	printf("\t-c, --compare\tCompare firmware version before updating.\n");
	printf("\t-b, --rebind\tRebind driver after updating firmware.\n");
	printf("\t-i, --info\tShow the device information.\n");
	printf("\t-v, --fw-ver\tRead the firmware version from device.\n");
	printf("\t-p, --pid\tRead the product id from device.\n");
	printf("\t-s, --status\tShow IC status.\n");
}

void hx_printf(const char *fmt, ...)
{
	if (!g_show_dbg_log)
		return;

	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

unsigned long get_current_ms()
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

int check_privilege()
{
	uid_t uid = getuid();
	uid_t euid = geteuid();

	if (uid == 0 || euid == 0)
		return 0;

	return 1;
}

int parse_options(int argc, char *argv[], OPTDATA *optp)
{
	int opt;
	int index;
	char *val = 0;

	while ((opt = getopt_long(argc, argv, HX_UTIL_OPT, long_option, &index)) != -1) {
		switch (opt) {
		case 'h':
			print_help(argv[0]);
			return 1;
		case 'd':
			/* there would be the 0x20 in the leading sometimes */
			val = optarg;
			hx_printf("device path = %s\n", val);
			while (*val == 0x20)
				val++;

			if (memcmp("/dev", val, 4))
				sprintf(optp->dev_path, "/dev/%s", val);
			else
				strcpy(optp->dev_path, val);
			break;
		case 'u':
			optp->options |= OPTION_UPDATE;
			optp->fw_path = optarg;
			break;
		case 'c':
			optp->options |= OPTION_CMP_VER;
			break;
		case 'b':
			optp->options |= OPTION_REBIND;
			break;
		case 'i':
			optp->options|= OPTION_INFO;
			g_show_dbg_log = 1;
			break;
		case 'v':
			optp->options |= OPTION_FW_VER;
			break;
		case 'p':
			optp->options |= OPTION_PID;
			break;
		case 's':
			optp->options |= OPTION_STATUS;
		default:
			break;
		}
	}

	if (optind != argc) {
		int i = 0;
		while (i < argc) {
			printf("%s ", argv[i]);
			i++;
		}
		printf("\n");

		print_help(argv[0]);
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	int info_option = OPTION_INFO | OPTION_FW_VER | OPTION_PID;
	OPTDATA opt_data;
	DEVINFO dev_info;
	unsigned long time_s;

	memset((void*) &opt_data, 0, sizeof(OPTDATA));
	memset(&dev_info, 0, sizeof(DEVINFO));
	
	if (parse_options(argc, argv, &opt_data)) {
		return 1;
	}

	if (!(opt_data.options & info_option))
		print_version();

	if (check_privilege()) {
		printf("Need root authority to execute this utility!\n");
		return 1;
	}

	time_s = get_current_ms();

	if (opt_data.options & OPTION_UPDATE)
		ret = burn_firmware(&dev_info, &opt_data);
	else if (opt_data.options & info_option)
		ret = show_info(&dev_info, &opt_data);
	else if (opt_data.options & OPTION_STATUS)
		ret = show_status(&opt_data);

	if (opt_data.options & OPTION_UPDATE) {
		if (!ret && (opt_data.options & OPTION_REBIND)) {
			if (rebind_driver(&dev_info)) {
				printf("Faild to rebind driver !\n");
				return 1;
			}
		}

		printf("It takes %ums\n", (unsigned int) (get_current_ms() - time_s));
	}

	return ret;
}


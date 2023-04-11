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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <stdarg.h>
#include <errno.h>

#include "hx_def.h"
#include "hx_dev_api.h"

#define HX_UTIL_NAME "Himax Update Utility"
#define HX_UTIL_VER "V1.0.5"

#define HX_UTIL_OPT	"hd:u:acbivpslr:w:U:FB:A:IR:W:S:DT:M:N:C:E:P"

static struct option long_option[] = {
	{"help", 0, NULL, 'h'},
	{"device", 1, NULL, 'd'},
	{"update", 1, NULL, 'u'},
	{"all", 0, NULL, 'a'},
	{"compare", 0, NULL, 'c'},
	{"rebind", 0, NULL, 'b'},
	{"info", 0, NULL, 'i'},
	{"fw-ver", 0, NULL, 'v'},
	{"pid", 0, NULL, 'p'},
	{"status", 0, NULL, 's'},
	{"log", 0, NULL, 'l'},
	{"read-reg", 1, NULL, 'r'},
	{"write-reg", 1, NULL, 'w'},

	{"hid-update", 1, NULL, 'U'},
	{"hid-force-update", 0, NULL, 'F'},
	{"hid-bootloader-update", 1, NULL, 'B'},
	{"hid-all-update", 1, NULL, 'A'},

	{"hid-info", 0, NULL, 'I'},
	{"hid-read-reg", 1, NULL, 'R'},
	{"hid-write-reg", 1, NULL, 'W'},
	{"hid-set-data-type", 1, NULL, 'S'},
	{"hid-show-diag", 0, NULL, 'D'},
	{"hid-self-test", 1, NULL, 'T'},
	{"hid-self-test-max", 1, NULL, 'M'},
	{"hid-self-test-min", 1, NULL, 'N'},
	{"hid-self-test-criteria-file", 1, NULL, 'C'},
	{"hid-set-touch-RD-report-en", 1, NULL, 'E'},

	{"hid-show-report-descriptor", 0, NULL, 'P'},
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
	printf("\t-a, --all\tUpdate entire firmware\n");
	printf("\t-c, --compare\tCompare firmware version before updating.\n");
	printf("\t-b, --rebind\tRebind driver after updating firmware.\n");
	printf("\t-i, --info\tShow the device information.\n");
	printf("\t-v, --fw-ver\tRead the firmware version from device.\n");
	printf("\t-p, --pid\tRead the product id from device.\n");
	printf("\t-s, --status\tShow IC status.\n");
	printf("\t-l, --log\tShow debug log.\n");
	printf("\t-r, --read-reg\tRead 4 bytes from IC reg using AHB.\n");
	printf("\t-w, --write-reg\tWrite 4 bytes to IC reg using AHB. 1st 4 bytes address(0xHHHHHHHH), 2nd 4 bytes data(0xHHHHHHHH)\n");

	printf("\t-U, --hid-update\tUpdate FW main code using HID.\n");
	printf("\t-F, --hid-force-update\tForce update FW using HID.\n");
	printf("\t-B, --hid-bootloader-update\tUpdate bootloader only using HID.\n");
	printf("\t-A, --hid-all-update\tUpdate FW main and BL code using HID.\n");

	printf("\t-I, --hid-info\tShow FW info using HID.\n");
	printf("\t-R, --hid-read-reg\tRead 4 bytes from IC reg using HID.\n");
	printf("\t-W, --hid-write-reg\tWrite 4 bytes to IC reg using HID. 1st 4 bytes address(0xHHHHHHHH), 2nd 4 bytes data(0xHHHHHHHH)\n");
	printf("\t-S, --hid-set-data-type\tUse with -D, set data type for -D.\n");
	printf("\t-D, --hid-show-diag\tShow touch data using HID. Ex \"-S type -D\" or \"-D\"\n");
	printf("\t-T, --hid-self-test\tRun self test when show data by DIAG, combined with -D using HID.\n");
	printf("\t-M, --hid-self-test-max\tUse with -T for single test type's upperbond.\n");
	printf("\t-N, --hid-self-test-min\tUse with -T for single test type's lowerbond.\n");
	printf("\t-C, --hid-self-test-criteria-file\tIndependent option, run self test with assign criteria file.\n");
	printf("\t-E, --hid-set-touch-RD-report-en\tDisable enable touch input report descriptor in next request RD.\n");

	printf("\t-P, --hid-show-report-descriptor\tShow report descriptor of HID.\n");
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
			optp->options = OPTION_UPDATE | (optp->options & OPTION_NONE);
			optp->fw_path = optarg;
			break;
		case 'a':
			optp->options |= OPTION_ALL_LEN;
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
			optp->options = OPTION_STATUS | (optp->options & OPTION_NONE);
			break;
		case 'l':
			g_show_dbg_log = 1;
			break;
		case 'r':
			if (sscanf(optarg, "0x%X", &(optp->r_reg_addr.i)) == EOF) {
				optp->r_reg_addr.i = 0;
				hx_printf("parsing read address error!\n");
				break;
			}
			optp->r_addr_size = 4;
			optp->options = OPTION_READ_REG | (optp->options & OPTION_NONE);
			break;
		case 'w':
			if (optp->w_addr_size == 0) {
				if (sscanf(optarg, "0x%X", &(optp->w_reg_addr.i)) == EOF) {
					optp->w_reg_addr.i = 0;
					hx_printf("parsing write address error!\n");
					break;
				}
				optp->w_addr_size = 4;
				break;
			} else {
				if (sscanf(optarg, "0x%X", &(optp->w_reg_data.i)) == EOF) {
					optp->w_reg_data.i = 0;
					hx_printf("parsing write data error!\n");
					break;
				}
				optp->w_data_size = 4;
			}
			optp->options = OPTION_WRITE_REG | (optp->options & OPTION_NONE);
			break;
		case 'U':
			optp->options = OPTION_HID_MAIN_UPDATE | (optp->options & OPTION_NONE);
			optp->fw_path = optarg;
			break;
		case 'F':
			optp->options |= OPTION_HID_FORCE_UPDATE;
			// optp->fw_path = optarg;
			break;
		case 'B':
			optp->options = OPTION_HID_BL_UPDATE | (optp->options & OPTION_NONE);
			optp->fw_path = optarg;
			break;
		case 'A':
			optp->options = OPTION_HID_ALL_UPDATE | (optp->options & OPTION_NONE);
			optp->fw_path = optarg;
			break;
		case 'I':
			optp->options = OPTION_HID_INFO | (optp->options & OPTION_NONE);
			break;
		case 'R':
			if (sscanf(optarg, "0x%X", &(optp->r_reg_addr.i)) == EOF) {
				optp->r_reg_addr.i = 0;
				hx_printf("parsing read address error!\n");
				break;
			}
			optp->r_addr_size = 4;
			optp->options = OPTION_HID_READ_REG | (optp->options & OPTION_NONE);
			break;
		case 'W':
			if (optp->w_addr_size == 0) {
				if (sscanf(optarg, "0x%X", &(optp->w_reg_addr.i)) == EOF) {
					optp->w_reg_addr.i = 0;
					hx_printf("parsing write address error!\n");
					break;
				}
				optp->w_addr_size = 4;
				break;
			} else {
				if (sscanf(optarg, "0x%X", &(optp->w_reg_data.i)) == EOF) {
					optp->w_reg_data.i = 0;
					hx_printf("parsing write data error!\n");
					break;
				}
				optp->w_data_size = 4;
			}
			optp->options = OPTION_HID_WRITE_REG | (optp->options & OPTION_NONE);
			break;
		case 'S':
			if (sscanf(optarg, "0x%X", &(optp->param.i)) == EOF) {
				optp->param.i = 0;
				hx_printf("parsing data type error!\n");
				break;
			}
			optp->options |= OPTION_HID_SET_DATA_TYPE;
			break;
		case 'D':
			optp->options = OPTION_HID_SHOW_DIAG | (optp->options & OPTION_NONE);
			break;
		case 'T':
			if (sscanf(optarg, "0x%X", &(optp->param.i)) == EOF) {
				optp->param.i = 0;
				hx_printf("parsing self test type error!\n");
				break;
			}
			optp->options |= OPTION_HID_SELF_TEST;
			break;
		case 'M':
			if (sscanf(optarg, "%d", &(optp->self_test_spec_max)) == EOF) {
				hx_printf("parsing self test type upper bond error!\n");
				break;
			}
			optp->options |= OPTION_HID_SELF_TEST_UPPER_BOUND;
			break;
		case 'N':
			if (sscanf(optarg, "%d", &(optp->self_test_spec_min)) == EOF) {
				hx_printf("parsing self test type lower bond error!\n");
				break;
			}
			optp->options |= OPTION_HID_SELF_TEST_LOWER_BOUND;
			break;
		case 'C':
			struct stat sb;
			if (stat(optarg, &sb) != 0) {
				hx_printf("File %s not exist!\n", optarg);
				break;
			} else if (S_ISDIR(sb.st_mode) > 0) {
				hx_printf("%s is not file!\n", optarg);
				break;
			}
			optp->criteria_path = optarg;
			optp->options = OPTION_HID_SELF_TEST_CRITERIA_FILE | (optp->options & OPTION_NONE);
			break;
		case 'E':
			if (sscanf(optarg, "%d", &(optp->input_en.i)) == EOF) {
				optp->input_en.i = 0;
				hx_printf("parsing touch input RD en error!\n");
				break;
			}
			optp->options |= OPTION_HID_SET_TOUCH_INPUT_RD_EN;
			break;
		case 'P':
			optp->options |= OPTION_HID_SHOW_REPORT;
			break;

		default:
			break;
		}
	}

	if ((optp->options & OPTION_HID_SELF_TEST) == OPTION_HID_SELF_TEST) {
		if ((optp->options & OPTION_HID_SELF_TEST_UPPER_BOUND) == 0) {
			optp->self_test_spec_max = 65535;
		}
		if ((optp->options & OPTION_HID_SELF_TEST_LOWER_BOUND) == 0) {
			optp->self_test_spec_min = -65535;
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

	time_s = get_current_ms();

	if (!(opt_data.options & info_option))
		print_version();

	if (opt_data.options & info_option) {
		ret = show_info(&dev_info, &opt_data);
		if (ret != 0) {
			goto MAIN_END;
		}
	}

	if (opt_data.options & OPTION_HID_SET_DATA_TYPE) {
		ret = hid_set_data_type(opt_data);
		if (ret < 0) {
			goto MAIN_END;
		}
	}

	if (opt_data.options & OPTION_HID_SHOW_REPORT) {
		ret = hid_print_report_descriptor(opt_data);
		if (ret < 0) {
			goto MAIN_END;
		}
	}

	if (opt_data.options & OPTION_HID_SET_TOUCH_INPUT_RD_EN) {
		ret = hid_set_input_RD_en(opt_data, dev_info);
		if (ret < 0) {
			goto MAIN_END;
		}
	}

	if ((opt_data.options & OPTION_MUTUAL_FILTER) == OPTION_UPDATE)
		ret = burn_firmware(&dev_info, &opt_data);
	else if ((opt_data.options & OPTION_MUTUAL_FILTER) == OPTION_HID_SELF_TEST_CRITERIA_FILE) {
		ret = hid_self_test_by_criteria_file(opt_data);
	} else if ((opt_data.options & OPTION_MUTUAL_FILTER) == OPTION_READ_REG) {
		ret = read_reg(opt_data);
	} else if ((opt_data.options & OPTION_MUTUAL_FILTER) == OPTION_WRITE_REG) {
		ret = write_reg(opt_data);
	} else if ((opt_data.options & OPTION_MUTUAL_FILTER) == OPTION_STATUS)
		ret = show_status(&opt_data);
	else if ((opt_data.options & OPTION_MUTUAL_FILTER) == OPTION_HID_INFO) {
		ret = hid_show_fw_info(opt_data);
	} else if ((opt_data.options & OPTION_MUTUAL_FILTER) == OPTION_HID_WRITE_REG) {
		ret = hid_write_reg(opt_data);
	} else if ((opt_data.options & OPTION_MUTUAL_FILTER) == OPTION_HID_READ_REG) {
		ret = hid_read_reg(opt_data);
	} else if ((opt_data.options & OPTION_MUTUAL_FILTER) == OPTION_HID_SHOW_DIAG) {
		ret = hid_show_diag(opt_data);
	} else if ((opt_data.options & OPTION_MUTUAL_FILTER) == OPTION_HID_MAIN_UPDATE) {
		int errorCode = 0;
		ret = hid_main_update(opt_data, dev_info, errorCode);
	} else if ((opt_data.options & OPTION_MUTUAL_FILTER) == OPTION_HID_BL_UPDATE) {
		int errorCode = 0;
		ret = hid_bl_update(opt_data, dev_info, errorCode);
	} else if ((opt_data.options & OPTION_MUTUAL_FILTER) == OPTION_HID_ALL_UPDATE) {
		int errorCode = 0;
		ret = hid_main_update(opt_data, dev_info, errorCode);
		if (ret == 0) {
			ret = hid_bl_update(opt_data, dev_info, errorCode);
		} else if (errorCode == FWUP_ERROR_NO_BL) {
			ret = hid_bl_update(opt_data, dev_info, errorCode);
			if (ret == 0) {
				ret = hid_main_update(opt_data, dev_info, errorCode);
			}
		}
	}

	if (opt_data.options & OPTION_REBIND) {
		if (hid_update_DEVINFO(dev_info) != 0) {
			printf("Failed to get device info!\n");
			return -ENODEV;
		}
		if (rebind_driver(&dev_info)) {
			printf("Faild to rebind driver !\n");
			return 1;
		}

		printf("It takes %ums\n", (unsigned int) (get_current_ms() - time_s));
	}
MAIN_END:

	return ret;
}


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
#include <malloc.h>
#include <string.h>

#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include "i2c-dev.h"
#include <sys/ioctl.h>
#include <linux/hidraw.h>


#include "hx_def.h"

char *g_hid_path;
long g_hidfd = -1;
struct hid_id_size_mapping_t {
	uint8_t id;
	uint16_t sz;
} g_hid_id_size_mapping[15];
int g_hid_id_sz_mapping_count = 0;

int hx_get_hid_fd()
{
	return g_hidfd;
}

int hx_scan_open_hidraw(OPTDATA& optdata)
{
	int found = 0;
	int dev_no = 0;
	int fd = 0;
	int ret;
	static char hidraw_path[64];
	char dev_dir[] = "/dev";
	struct hidraw_devinfo dinfo;

	if (g_hidfd > 0)
		return 0;

	// hx_printf("Scan HIDRAW device in %s ...\n", dev_dir);

	do {
		memset(hidraw_path, 0, sizeof(hidraw_path));
		sprintf(hidraw_path, "%s/hidraw%d", dev_dir, dev_no);

		if (access(hidraw_path, F_OK) != 0) {
			hx_printf("f%s device node not exist!\n", hidraw_path);

			break;
		}

		fd = open(hidraw_path, O_RDWR|O_DSYNC|O_NONBLOCK);
		if (fd < 0) {
			hx_printf("failed to open %s!\n", hidraw_path);

			break;
		}

		ret = ioctl(fd, HIDIOCGRAWINFO, &dinfo);
		if (ret != 0) {
			hx_printf("failed to get info from %s!\n", hidraw_path);
			close(fd);

			break;
		}
		/* hx_printf("hidraw info, bus type : %d, vendor : 0x%04X, product : 0x%04X\n", \
		 *	dinfo.bustype, dinfo.vendor, dinfo.product); */
		if (dinfo.vendor == 0x4858 || dinfo.vendor == 0x3558) {
			found = 1;
			// *hidpath = hidraw_path;
			// *hidfd = fd;

			g_hidfd = fd;
			g_hid_path = hidraw_path;
			optdata.vid = dinfo.vendor;
			optdata.pid = dinfo.product;
			optdata.bus = dinfo.bustype;
			break;
		}
		dev_no++;
	} while(dev_no < 10);

	if (found == 0)
		return -EIO;

	return 0; 
}

void hx_hid_close(void)
{
	if (g_hidfd > 0) {
		close(g_hidfd);
		g_hidfd = -1;
		g_hid_id_sz_mapping_count = 0;
	}
}

int hx_hid_set_feature(int id, uint8_t *data, int32_t len)
{
	int ret;
	uint8_t *outdata;
	int id_sz;
	
	// if (id > 0xF)
		// id_sz = 2;
	// else
		id_sz = 1;
		
	outdata = (uint8_t *)malloc(len + id_sz);

	if (outdata == NULL)
		return -ENOMEM;

	outdata[0] = id;
	if (id_sz > 1)
		outdata[1] = id;
	memcpy(outdata + id_sz, data, len);

	ret = ioctl(g_hidfd, HIDIOCSFEATURE(len+id_sz), outdata);
	if (ret < 0)
		return ret;

	free(outdata);

	return 0;
}

int hx_hid_get_feature(int id, uint8_t *data, int32_t len)
{
	int ret;

	if (data == NULL)
		return -ENOMEM;
	
	uint8_t *indata = (uint8_t *)malloc(len + 1);
	if (indata == NULL)
		return -ENOMEM;
	indata[0] = id;
	ret = ioctl(g_hidfd, HIDIOCGFEATURE(len+1), indata);
	if (ret < 0)
		return ret;

	memcpy(data, indata + 1, len);

	free(indata);

	return 0;
}

int hx_hid_read(uint8_t *data, int32_t len)
{
	return read(g_hidfd, data, len);
}

int hx_hid_set_output(int id, int32_t idLen, uint8_t *data, int32_t dataLen)
{
	int ret;

	if (data == NULL)
		return -ENOMEM;

	uint8_t *outdata = (uint8_t *)malloc(idLen + dataLen);
	if (outdata == NULL)
		return -ENOMEM;
	if (idLen > 0)
		memcpy(outdata, &id, idLen);
	memcpy(outdata + idLen, data, dataLen);

	ret = write(g_hidfd, outdata, idLen + dataLen);
	free(outdata);
	if (ret < 0)
		return ret;
	// sync();

	return (ret == (idLen + dataLen))?0:-EIO;
}

static int calculate_prop_value(uint8_t *data, int len)
{
	int32_t value = 0;
	int32_t dlen = (len - 1)>4?4:(len - 1);
	for (int j = 0; j < dlen; j++) {
		value = (value << 8) + data[dlen - 1 - j];
	}

	return value;
}

int hx_hid_print_RD(void)
{
	int rdsize, ret;
	struct hidraw_report_descriptor rd;
	uint8_t itemDesc;
	int16_t current_id = -1;
	int32_t current_bit_size = -1;
	int32_t current_count = -1;
	int16_t current_desc_size = -1; 
	uint8_t current_desc[255] = {0};
	uint32_t current_value;
	uint32_t current_usage_page = 0;
	const char *collection_type[] = {
		"Physical",
		"Application",
		"Logical",
		"Report",
		"Named Array",
		"Usage Switch",
		"Usage Modifier"
	};
	const char *usage_page[] = {
		"undefined",
		"Generic Desktop",
		"Simulation Controls",
		"VR Controls",
		"Sports Controlsy",
		"Game Controls",
		"Generic Device Controls",
		"Keyboard/Keypad Controls",
		"LED",
		"Button",
		"Ordinal",
		"Telephony Device",
		"Consumer",
		"Digitizers",
		"Reserved",
		"PID",
		"Unicode"
	};

	ret = ioctl(g_hidfd, HIDIOCGRDESCSIZE, &rdsize);
	if (ret < 0)
		return ret;

	rd.size = rdsize;
	if (ioctl(g_hidfd, HIDIOCGRDESC, &rd) < 0) {
		return ret;
	}

	itemDesc = rd.value[0];
	for (int i = 0, tidx = 0, last_tidx = 0; i < rd.size; i++) {
		if (i == tidx) {
			if (i > 0) {
				itemDesc = rd.value[last_tidx];
				switch (itemDesc & 0xFC) {
					case 0xA0:
						current_value = calculate_prop_value(current_desc, current_desc_size);
						hx_printf("// Collection (%s)", collection_type[current_value]);
						break;
					case 0xC0:
						hx_printf("// End Collection");
						break;
					case 0x04:
						current_value = calculate_prop_value(current_desc, current_desc_size);
						if (current_value < sizeof(usage_page)/sizeof(char *))
							hx_printf("// Usage Page (%s)", usage_page[current_value]);
						else if ((current_value >= 0xFF00) && (current_value <= 0xFFFF)) {
							hx_printf("// Usage Page (Vendor-defined)");
						} else
							hx_printf("// Usage Page (0x%04X)", current_value);
						current_usage_page = current_value;
						break;
					case 0xB4:
						hx_printf("// Pop");
						break;
					case 0xA4:
						hx_printf("// Push");
						break;
					case 0x54:
						current_value = calculate_prop_value(current_desc, current_desc_size);
						hx_printf("// %s (%d)", "Unit Exponent", current_value);
						break;
					case 0x64:
						current_value = calculate_prop_value(current_desc, current_desc_size);
						hx_printf("// %s (%d)", "Unit", current_value);
						break;
					case 0x80:
						hx_printf("// %s (ID: %d, sz: %d bits(%d bytes))", "Input", current_id, current_bit_size*current_count, current_bit_size*current_count/8);
						break;
					case 0xB0:
						hx_printf("// %s (ID: %d, sz: %d bits(%d bytes))", "Feature", current_id, current_bit_size*current_count, current_bit_size*current_count/8);
						break;
					case 0x90:
						hx_printf("// %s (ID: %d, sz: %d bits(%d bytes))", "Output", current_id, current_bit_size*current_count, current_bit_size*current_count/8);
						break;
					case 0x84:
						hx_printf("// %s (%d)", "Report ID", current_desc[0]);
						current_id = current_desc[0];
						break;
					case 0x74:
						current_value = calculate_prop_value(current_desc, current_desc_size);
						hx_printf("// %s (%d)", "Report Size", current_value);
						current_bit_size = current_value;
						break;
					case 0x94:
						current_value = calculate_prop_value(current_desc, current_desc_size);
						hx_printf("// %s (%d)", "Report Count", current_value);
						current_count = current_value;
						break;
					case 0x08:
						current_value = calculate_prop_value(current_desc, current_desc_size);
						if (current_usage_page == 0x01) {
							switch (current_value) {
							case 1:
								hx_printf("// %s (%s)", "Usage", "Pointer");
								break;
							case 2:
								hx_printf("// %s (%s)", "Usage", "Mouse");
								break;
							case 4:
								hx_printf("// %s (%s)", "Usage", "Joystck");
								break;
							case 5:
								hx_printf("// %s (%s)", "Usage", "Game Pad");
								break;
							case 6:
								hx_printf("// %s (%s)", "Usage", "Keyboard");
								break;
							case 7:
								hx_printf("// %s (%s)", "Usage", "Keypad");
								break;
							case 8:
								hx_printf("// %s (%s)", "Usage", "Multi-axis Controller");
								break;
							case 9:
								hx_printf("// %s (%s)", "Usage", "Tablet PC System Controls");
								break;
							case 0x3A:
								hx_printf("// %s (%s)", "Usage", "Counted Buffer");
								break;
							case 0x80:
								hx_printf("// %s (%s)", "Usage", "System Control");
								break;
							default:
								hx_printf("// %s (0x%X)", "Usage", current_value);
							}
						} else if (current_usage_page == 0x0D) {
							switch (current_value) {
							case 1:
								hx_printf("// %s (%s)", "Usage", "Digitizer");
								break;
							case 2:
								hx_printf("// %s (%s)", "Usage", "Pen");
								break;
							case 3:
								hx_printf("// %s (%s)", "Usage", "Light Pen");
								break;
							case 4:
								hx_printf("// %s (%s)", "Usage", "Touch Screen");
								break;
							case 5:
								hx_printf("// %s (%s)", "Usage", "Touch Pad");
								break;
							case 6:
								hx_printf("// %s (%s)", "Usage", "White Board");
								break;
							case 7:
								hx_printf("// %s (%s)", "Usage", "Coordinate Measuring Machine");
								break;
							case 8:
								hx_printf("// %s (%s)", "Usage", "3D Digitizer");
								break;
							case 9:
								hx_printf("// %s (%s)", "Usage", "Stereo Plotter");
								break;
							case 0xC:
								hx_printf("// %s (%s)", "Usage", "Multiple Point Digitizer");
								break;
							case 0x20:
								hx_printf("// %s (%s)", "Usage", "Stylus");
								break;
							case 0x21:
								hx_printf("// %s (%s)", "Usage", "Puck");
								break;
							case 0x22:
								hx_printf("// %s (%s)", "Usage", "Finger");
								break;
							case 0x39:
								hx_printf("// %s (%s)", "Usage", "Tablet Function Keys");
								break;
							case 0x3A:
								hx_printf("// %s (%s)", "Usage", "Program Change Keys");
								break;
							case 0x55:
								hx_printf("// %s (%s)", "Usage", "Contact Count Maximum");
								break;
							case 0xC5:
								hx_printf("// %s (%s)", "Usage", "WIN8 Device Certification");
								break;
							default:
								hx_printf("// %s (0x%X)", "Usage", current_value);
							}
						} else
							hx_printf("// %s (0x%X)", "Usage", current_value);
						break;
					case 0x24:
						current_value = calculate_prop_value(current_desc, current_desc_size);
						hx_printf("// %s (%d)", "Logical Maximum", current_value);
						break;
					case 0x14:
						current_value = calculate_prop_value(current_desc, current_desc_size);
						hx_printf("// %s (%d)", "Logical Minimum", current_value);
						break;
					case 0x34:
						current_value = calculate_prop_value(current_desc, current_desc_size);
						hx_printf("// %s (%d)", "Physical Minimum", current_value);
						break;
					case 0x44:
						current_value = calculate_prop_value(current_desc, current_desc_size);
						hx_printf("// %s (%d)", "Physical Maximum", current_value);
						break;
					// default:
				};
			}
			hx_printf("\n");
			if (rd.value[i] == 0xFE)
				current_desc_size = rd.value[i + 1] + 3;
			else
				current_desc_size = (((rd.value[i] & 0x03) == 0x03)?4:(rd.value[i] & 0x03)) + 1;

			last_tidx = tidx;
			tidx += current_desc_size;
		} else {
			if ((i - last_tidx - 1) < sizeof(current_desc))
				current_desc[i - last_tidx - 1] = rd.value[i];
		}
		hx_printf(" 0x%02X,", rd.value[i]);
		if (i == (rd.size - 1)) {
			itemDesc = rd.value[last_tidx];
			if (itemDesc == 0xC0)
				hx_printf("// End Collection");
			else
				hx_printf("// Unusal Ending.....");
		}
	}
	hx_printf("\n");

	return 0;
}

int hx_hid_parse_RD_for_idsz(void)
{
	int rdsize, ret;
	struct hidraw_report_descriptor rd;
	uint8_t itemDesc;
	int16_t current_id = -1;
	int32_t current_bit_size = -1;
	int32_t current_count = -1;
	int16_t current_desc_size = -1; 
	uint8_t current_desc[255] = {0};
	uint32_t current_value;
	// uint32_t current_usage_page = 0;
	int c_id = -1;
	int32_t c_size = -1;
	
	ret = ioctl(g_hidfd, HIDIOCGRDESCSIZE, &rdsize);
	if (ret < 0)
		return ret;

	rd.size = rdsize;
	if (ioctl(g_hidfd, HIDIOCGRDESC, &rd) < 0) {
		return ret;
	}

	itemDesc = rd.value[0];
	for (int i = 0, tidx = 0, last_tidx = 0; i < rd.size; i++) {
		if (i == tidx) {
			if (i > 0) {
				itemDesc = rd.value[last_tidx];
				switch (itemDesc & 0xFC) {
					case 0x04:
						current_value = calculate_prop_value(current_desc, current_desc_size);
						// current_usage_page = current_value;
						break;
					case 0x80:
						g_hid_id_size_mapping[g_hid_id_sz_mapping_count].id = current_id;
						g_hid_id_size_mapping[g_hid_id_sz_mapping_count++].sz = current_bit_size*current_count/8;
						break;
					case 0xB0:
						g_hid_id_size_mapping[g_hid_id_sz_mapping_count].id = current_id;
						g_hid_id_size_mapping[g_hid_id_sz_mapping_count++].sz = current_bit_size*current_count/8;
						break;
					case 0x90:
						g_hid_id_size_mapping[g_hid_id_sz_mapping_count].id = current_id;
						g_hid_id_size_mapping[g_hid_id_sz_mapping_count++].sz = current_bit_size*current_count/8;
						break;
					case 0x84:
						current_id = current_desc[0];
						break;
					case 0x74:
						current_value = calculate_prop_value(current_desc, current_desc_size);
						current_bit_size = current_value;
						break;
					case 0x94:
						current_value = calculate_prop_value(current_desc, current_desc_size);
						current_count = current_value;
						break;
					default:
						break;
				};
			}
			if (rd.value[i] == 0xFE)
				current_desc_size = rd.value[i + 1] + 3;
			else
				current_desc_size = (((rd.value[i] & 0x03) == 0x03)?4:(rd.value[i] & 0x03)) + 1;

			last_tidx = tidx;
			tidx += current_desc_size;
		} else {
			if ((i - last_tidx - 1) < sizeof(current_desc))
				current_desc[i - last_tidx - 1] = rd.value[i];
		}
	}
	hx_printf("Mappings:\n");
	for (int i = 0; i < g_hid_id_sz_mapping_count; i++) {
		if (g_hid_id_size_mapping[i].id != c_id) {
			if (c_id != -1) {
				hx_printf("id: %d, size: %d\n", c_id, c_size);
			}
			c_id = g_hid_id_size_mapping[i].id;
			c_size = g_hid_id_size_mapping[i].sz;
		} else {
			c_size += g_hid_id_size_mapping[i].sz;
		}
	}

	return 0;
}

int hx_hid_get_size_by_id(int id)
{
	if (g_hid_id_sz_mapping_count <= 0)
		return -EFAULT;
	
	for (int i = 0; i < g_hid_id_sz_mapping_count; i++) {
		if (g_hid_id_size_mapping[i].id == id)
			return g_hid_id_size_mapping[i].sz;
	}

	return -ENODATA;
}

int hx_hid_write_reg(uint32_t addr, uint32_t data, OPTDATA& opt_data)
{
	int ret;
	uint8_t reg_n_data[9];

	reg_n_data[0] = 0x01;
	memcpy(reg_n_data + 1, &addr, 4);
	memcpy(reg_n_data + 1 + 4, &data, 4);

	if (g_hidfd < 0) {
		if (hx_scan_open_hidraw(opt_data) < 0) {
			return -EIO;
		}
	}

	ret = hx_hid_set_feature(HID_REG_RW_ID, reg_n_data, sizeof(reg_n_data));
	if (ret == 0) {
		hx_printf("%s %08X:%08X\n", "Write done", *(uint32_t *)&(reg_n_data[1]), *(uint32_t *)&(reg_n_data[5]));
	} else {
		hx_printf("%s %08X:%08X\n", "Write failed", *(uint32_t *)&(reg_n_data[1]), *(uint32_t *)&(reg_n_data[5]));
	}

	return ret;
}

bool pollingForResult(uint8_t featureId, uint8_t *expectedData, uint32_t expectDataLength,
                            uint32_t interval_ms, uint32_t timeout_s, uint8_t *received_data, int* nDataReceived)
{
    bool result = true;
    time_t now = time(NULL);
    time_t start = now;
    uint8_t* data = NULL;// new uint8_t[expectDataLength];
	*nDataReceived = 0;

polling_again:
    if (data == NULL)
        data = (uint8_t *)malloc(expectDataLength);
    if (hx_hid_get_feature(featureId, data, expectDataLength) != 0) {
        // Sleep(interval_ms);
        // sleep_for(milliseconds(interval_ms));
		usleep(interval_ms * 1000);
    }
    else {
        bool cmp = true;
        // hx_printf("Data received(%d bytes): ", expectDataLength);
        for (uint32_t i = 0; i < expectDataLength; i++) {
            if (data[i] != expectedData[i]) {
                cmp = false;
                // hx_printf("\n expect: %02X, received: %02X\n", expectedData[i], data[i]);
                break;
            }
            if ((i > 0) && (i % 16 == 0))
                ;//hx_printf("\n");

            // hx_printf("%02X ", data[i]);
        }
        // hx_printf("\n");
		// received_data.resize(expectDataLength);
		*nDataReceived = expectDataLength;
        for (uint32_t i = 0; i < expectDataLength; i++)
            received_data[i] = data[i];
        free(data);
        return cmp;
    }

    now = time(NULL);
    if (now - start >= timeout_s) {
        result = false;
    }
    else {
        goto polling_again;
    }
    free(data);
    return result;
}

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

#include "hx_def.h"

#define DEFAULT_I2C_BUS "/dev/i2c-13"
#define HX_ACPI_NAME "i2c-HX"
#define HX_I2C_ADDR 0x4F
#define TARGET_I2C_ADDR 0x48

#define MAX_DEV 16

char g_dev_path[64];
long devfd = -1;

int hx_scan_i2c_adaptor_path(int *adaptor_no)
{
	DIR	*d;
	struct dirent *dir;
	int found = 0;
	int adp_no = 0;
	char dev_path[64];

	/* i2c device path in sysfs */
	char dev_sysfs_adapter_path[] = "/sys/bus/i2c/devices";

	hx_printf("Scan I2C device in adapter path...\n");

	adp_no = 0;
	while (adp_no < MAX_DEV) {
		sprintf(dev_path, "%s/i2c-%d", dev_sysfs_adapter_path, adp_no);
		d = opendir(dev_path);
		if (d) {
			char slave_dev[16];
			strcpy(slave_dev, HX_ACPI_NAME);

			hx_printf("scan %s\n", dev_path);

		//	sprintf(slave_dev, "%d-00%02X", adp_no, HX_I2C_ADDR);
			while ((dir = readdir(d)) != NULL) {
				if (memcmp(dir->d_name, slave_dev, strlen(slave_dev)) == 0) {
					found = 1;
					break;
				}
			}
		}
		closedir(d);

		if (found)
			break;

		adp_no ++;
	}

	*adaptor_no = adp_no;

	return found;
}
#if 0
int hx_scan_i2c_hid_path(int *adaptor_no)
{
	DIR	*d;
	struct dirent *dir;
	int found = 0;
	int dev_addr = 0;

	/* hid over i2c driver path in sysfs */
	char dev_sysfs_hid_path[] = "/sys/bus/i2c/drivers/i2c_hid";

	d = opendir(dev_sysfs_hid_path);
	if (d) {
		hx_printf("Scan I2C device in hid path...\n");

		while ((dir = readdir(d)) != NULL) {
			sscanf(dir->d_name, "%d-%x", adaptor_no, &dev_addr);
			if (dev_addr == HX_I2C_ADDR) {
				found = 1;
				break;
			}
		}
		closedir(d);
	}

	return found;
}
#endif
int	 hx_scan_i2c_device(char *devp)
{
	int found = 0;
	int adaptor_no = -1;

	if (devp != NULL) {
		strcpy(g_dev_path, devp);
		hx_printf("show i2c dev path %s\n", g_dev_path);
		return 0;
	}

	strcpy(g_dev_path, DEFAULT_I2C_BUS);

//	found = hx_scan_i2c_hid_path(&adaptor_no);

//	if (!found)
		found = hx_scan_i2c_adaptor_path(&adaptor_no);

	if (!found) {
		hx_printf("Use the default i2c-dev: %s\n", g_dev_path);
	} else {
		sprintf(g_dev_path, "/dev/i2c-%d", adaptor_no);
		hx_printf("find device on %s\n", g_dev_path);
	}

	return 0;
}

int	hx_open_i2c_device(void)
{
	unsigned long funcs = 0;

	devfd = open(g_dev_path, O_RDWR);
	if (devfd < 0) {
		printf("Can't open i2c device %s\n", g_dev_path);
		return 1;
	}

	if (ioctl(devfd, I2C_FUNCS, &funcs) < 0) {
		printf("Can't get the i2c funcs !\n");
		close(devfd);
		devfd = -1;
		return 1;
	}

	if (!(funcs & I2C_FUNC_I2C)) {
		printf("Oops, no I2C function support !\n");
		close(devfd);
		devfd = -1;
		return 1;
	}

	return 0;
}

int	hx_close_i2c_device(void)
{
	if (devfd >= 0) {
		close(devfd);
		return 0;
	} else {
		fprintf(stderr, "devfd is invalid !!\n");
		return 1;
	}
}

int hx_i2c_write(uint8_t *buf, uint32_t size)
{
	int err = -1;
	struct i2c_rdwr_ioctl_data i2c_rdwr_data;
	struct i2c_msg msgs[1];

	if (!buf) {
		fprintf(stderr, "%s: pointer is null\n", __func__);
		return err;
	}

	msgs[0].addr = TARGET_I2C_ADDR;
	msgs[0].flags = 0; //I2C_M_IGNORE_NAK;
	msgs[0].len = size;
	msgs[0].buf = (char*)buf;

	i2c_rdwr_data.msgs = msgs;
	i2c_rdwr_data.nmsgs = 1;

	err = ioctl(devfd, I2C_RDWR, &i2c_rdwr_data);

	if (err < 0) {
		fprintf(stderr, "%s: ioctl operation failed: (%d)\n", __func__, err);
		return err;
	}

	return err;
}

int hx_i2c_read(uint8_t *txbuf, uint32_t txlen, uint8_t *rxbuf, uint32_t rxlen)
{
	int err = -1;
	struct i2c_rdwr_ioctl_data	i2c_rdwr_data;
	struct i2c_msg msgs[2];

	if (!txbuf || !rxbuf) {
		fprintf(stderr, "%s: pointer is null\n", __func__);
		return err;
	}

	msgs[0].addr = TARGET_I2C_ADDR;
	msgs[0].flags = 0;
	msgs[0].len = txlen;
	msgs[0].buf = (char*)txbuf;

	msgs[1].addr = TARGET_I2C_ADDR;
	msgs[1].flags = I2C_M_RD;
	msgs[1].len = rxlen;
	msgs[1].buf = (char*)rxbuf;

	i2c_rdwr_data.msgs = msgs;
	i2c_rdwr_data.nmsgs = 2;

	err = ioctl(devfd, I2C_RDWR, &i2c_rdwr_data);
	if (err < 0) {
		fprintf(stderr, "%s: ioctl operation failed: (%d)\n", __func__, err);
		return err;
	}

	return err;
}

int hid_i2c_write(uint8_t *buf, uint32_t size)
{
	int err = -1;
	struct i2c_rdwr_ioctl_data i2c_rdwr_data;
	struct i2c_msg msgs[1];

	if (!buf) {
		fprintf(stderr, "%s: pointer is null\n", __func__);
		return err;
	}

	msgs[0].addr = HX_I2C_ADDR;
	msgs[0].flags = 0; //I2C_M_IGNORE_NAK;
	msgs[0].len = size;
	msgs[0].buf = (char*)buf;

	i2c_rdwr_data.msgs = msgs;
	i2c_rdwr_data.nmsgs = 1;

	err = ioctl(devfd, I2C_RDWR, &i2c_rdwr_data);

	if (err < 0) {
		fprintf(stderr, "%s: ioctl operation failed: (%d)\n", __func__, err);
		return err;
	}

	return err;
}

int hid_i2c_read(uint8_t *txbuf, uint32_t txlen, uint8_t *rxbuf, uint32_t rxlen)
{
	int err = -1;
	struct i2c_rdwr_ioctl_data	i2c_rdwr_data;
	struct i2c_msg msgs[2];

	if (!txbuf || !rxbuf) {
		fprintf(stderr, "%s: pointer is null\n", __func__);
		return err;
	}

	msgs[0].addr = HX_I2C_ADDR;
	msgs[0].flags = 0;
	msgs[0].len = txlen;
	msgs[0].buf = (char*)txbuf;

	msgs[1].addr = HX_I2C_ADDR;
	msgs[1].flags = I2C_M_RD;
	msgs[1].len = rxlen;
	msgs[1].buf = (char*)rxbuf;

	i2c_rdwr_data.msgs = msgs;
	i2c_rdwr_data.nmsgs = 2;

	err = ioctl(devfd, I2C_RDWR, &i2c_rdwr_data);
	if (err < 0) {
		fprintf(stderr, "%s: ioctl operation failed: (%d)\n", __func__, err);
		return err;
	}

	return err;
}

/*
 * Copyright (C) 2025 Himax Technologies, Limited.
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <time.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <endian.h>
#include <sys/time.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <linux/hidraw.h>


#include "hx_def.h"
#include "hx_ic.h"
#include "hx_i2c_func.h"
#include "hx_hid_func.h"

typedef enum access_type {
	ACCESS_AHB,
	ACCESS_HID
} access_t;

uint8_t hx_buf[FLASH_RW_MAX_LEN];

enum {
  PAGE_ERASE = 0b1,
  SECTOR_ERASE = 0b10,
  BLOCK_ERASE = 0b100
};

typedef struct flash_info {
	uint32_t id;
	uint16_t write_delay;
	uint16_t chip_erase_delay;
	uint16_t block_erase_delay;
	uint16_t sector_erase_delay;
	uint16_t size;
	uint8_t block_protect_mask;
	uint8_t erase_abilities;
} flash_info_t;

flash_info_t gFlash_table[] = {
/* Base on HX flash support list v2.45 */
  { 0x001128c2,  10,  1880,  800,  58,   256, 0b00111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x00121068,   7,     8,    8,   8,   256, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001220C2,  10,  2000,  700,  60,   256, 0b00001100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001223C2,  10,  2800,  480,  40,   256, 0b00111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001228C2,  40, 12500, 1000, 100,   256, 0b00111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001230EF,  10,   500,  150,  30,   256, 0b00001100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x0012381C,   2,  1000,  150,  40,   256, 0b00111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x00124085,   8,     8,    8,   8,   256, 0b01111100, BLOCK_ERASE|SECTOR_ERASE|PAGE_ERASE },
  { 0x0012409D,   2,   750,  200,  70,   256, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001240C4,   2,     5,    3,   3,   256, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001240C8,   5,  1250,  300,  50,   256, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001240EF,   2,   500,  120,  30,   256, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x00124485,   8,     8,    8,   8,   256, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x0012600B,  80,  3000,  800, 110,   256, 0b00001100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x00126085,   8,     8,    8,   8,   256, 0b01111100, BLOCK_ERASE|SECTOR_ERASE|PAGE_ERASE },
  { 0x001260C8,   5,  2500,  800, 150,   256, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001260ef,   1,   750,  250, 120,   256, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x0013105E,   5,  3000,  400,  90,   512, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x00131068,   7,     8,    8,   8,   512, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x00132085,   8,  3000,  300,  50,   512, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001323C2,  10,  2800,  480,  40,   512, 0b00111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001328A1,  10,  1500,  200,  45,   512, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001328C2,  10,  2700,  480,  40,   512, 0b00111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x0013301C,   5,  2500, 2000,  50,   512, 0b00111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001330EF,  10,  1000,  150,  30,   512, 0b00010000, BLOCK_ERASE|SECTOR_ERASE },
  { 0x0013381C,   2,  2000,  150,  40,   512, 0b00111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x0013409D,   2,  1500,  200,  70,   512, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001340C4,   2,     5,    3,   3,   512, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001340C8,   5,  2500,  300,  50,   512, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001340EF,  10,  1000,  150,  30,   512, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x0013605E,   1,  2000,  200,  35,   512, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x00136085,   8,    16,   16,  16,   512, 0b01111100, BLOCK_ERASE|SECTOR_ERASE|PAGE_ERASE },
  { 0x001360C8,   5,  6000,  800, 150,   512, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001360EF,   1,  1000,  180,  45,   512, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x0014301C,   5,  5000, 2000,  50,  1024, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x00144020,  10,  3000,  200,  40,  1024, 0b00011000, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001440A1,  10,  6000,  400,  60,  1024, 0b00011000, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001440C8,   5,  5000,  300,  50,  1024, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001440EF,  15,  2000,  180,  50,  1024, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x00146085,   8,    80,   16,  16,  1024, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x0014609D,   2,  2000,  150,  70,  1024, 0b00111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001460C4,   2,     5,    3,   3,  1024, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001460EF,   1,  3000,  180,  45,  1024, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001523C2,  10, 12000,  450,  38,  2048, 0b00111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001540C8,   5, 10000,  300,  50,  2048, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001540EF,  10,  5000,  150,  45,  2048, 0b00011000, BLOCK_ERASE|SECTOR_ERASE },
  { 0x0015609D,   2,  4000,  150,  70,  2048, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001560C4,   2,     5,    2,   2,  2048, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001560C8,   2,  4500,  200,  40,  2048, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001640C8,   5, 15000,  300,  50,  4096, 0b01111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x0016609D,   2,  8000,  150,  70,  4096, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x0016701C,  10, 18000, 2000,  50,  4096, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x00168AEF,   2, 10000,  200,  45,  4096, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x00174AEF,  10, 20000,  150,  45,  8192, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x0017609D,   2, 16000,  150,  70,  8192, 0b00111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001770EF,  10, 20000,  150,  45,  8192, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x00182001, 140, 33000, 2080, 130, 16384, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x0018BA20,   2, 38000,  150,  50, 16384, 0b01110000, BLOCK_ERASE|SECTOR_ERASE },
  { 0x001960ef,   2,  9000,  200,  50,   256, 0b00101000, BLOCK_ERASE|SECTOR_ERASE },
  { 0x003225C2,  40,  1250,  500,  30,   256, 0b00011100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x0052117F,   5,   750,  250, 120,   256, 0b00111100, BLOCK_ERASE|SECTOR_ERASE },
  { 0x00000000,   5,  1000,  150,  45,   256, 0b00000000, BLOCK_ERASE|SECTOR_ERASE },// for else
};

#define FLASH_TABLE_SIZE (sizeof(gFlash_table)/sizeof(gFlash_table[0]))
static flash_info_t *gFlash_info = &gFlash_table[FLASH_TABLE_SIZE - 1];

int _hid_reg_write(uint32_t addr, uint32_t data);
int _hid_reg_read(uint32_t addr, uint32_t* data);
enum layout_type_t get_layout_type(hx_hid_ic_layout_header *layout);

int himax_sum8(uint8_t *buf, uint32_t len)
{
	uint32_t i;
	uint8_t sum = 0;

	for (i = 0; i < len; i++) {
		sum += buf[i];
	}

	return sum;
}

int himax_free_fw(HXFW *fwp)
{
	if (fwp) {
		if (fwp->data) {
			free(fwp->data);
			fwp->data = NULL;
			hx_printf("free fw data\n");
		}
	} else {
		hx_printf("fwp is NULL\n");
		return 1;
	}

	return 0;
}

bool himax_check_fw_header(HXFW *fwp)
{
	int i, j, count, checksum;
	uint32_t map_code;
	uint32_t faddr;

	if (fwp->len < 1024) {
		printf("fw header length is too short\n");
		return false;
	}

	if (!(fwp->data[14] == 0x56 || fwp->data[14] == 0x87) || himax_sum8(&fwp->data[0], 16) != 0) {
		hx_printf("there is no fw header\n");
		return false;
	}
	// printf("fw header found\n");
	for (i = 0; i < 1024; i += 16) {
		count = 0;
		checksum = 0;
		for (j = i; j < i+16; j++) {
			if (fwp->data[j] == 0)
				count++;
			checksum += fwp->data[j];
		}

		if (count == 16) {
			hx_printf("header end at offset: %d\n", i);
			break;
		} else if (checksum % 0x100) {
			printf("header parse failed: checksum fail at offset %d\n", i);
			fwp->is_info_valid = false;
			return false;
		} else {
			map_code = fwp->data[i] + (fwp->data[i+1]<<8) + (fwp->data[i+2]<<16) + (fwp->data[i+3]<<24);
			faddr = fwp->data[i+4] + (fwp->data[i+5]<<8) + (fwp->data[i+6]<<16) + (fwp->data[i+7]<<24);
			switch (map_code) {
			case 0x10000000:
				// printf("map_code = %08X, faddr = %08X\n", map_code, faddr);
				fwp->cid = fwp->data[faddr]<<8 | fwp->data[faddr+1];
			//	printf("fw_ver_bin = %08X\n", fw_ver_bin);
				break;
			case 0x10000100:
				// printf("map_code = %08X, faddr = %08X\n", map_code, faddr);
				fwp->fw_ver = fwp->data[faddr]<<8 | fwp->data[faddr+1];
				break;
			case 0x10000600:
				// printf("map_code = %08X, faddr = %08X\n", map_code, faddr);
				fwp->tp_cfg_ver = fwp->data[faddr];
				fwp->dd_cfg_ver = fwp->data[faddr+1];
				break;
			case 0x10000300:
				// printf("map_code = %08X, faddr = %08X\n", map_code, faddr);
				fwp->vid = fwp->data[faddr + 12] << 8 | fwp->data[faddr + 13];
				fwp->pid = fwp->data[faddr + 14] << 8 | fwp->data[faddr + 15];
				memcpy(fwp->ic_id, &fwp->data[faddr], 12);
				break;
			case 0x10000200:
				// printf("map_code = %08X, faddr = %08X\n", map_code, faddr);
				fwp->ic_sign_a = fwp->data[faddr];
				memcpy(fwp->customer, &fwp->data[faddr+1], 12);
				memcpy(fwp->project, &fwp->data[faddr+13], 12);
				break;
			}
		}
	}
	fwp->is_info_valid = true;
	hx_printf("fw header parse success\n");

	return true;
}

int himax_load_fw(char *path, HXFW *fwp)
{
	FILE* fp = NULL;

	if (!path || !fwp) {
		printf("%s: parameters error!!\n", __func__);
		return 1;
	}

	fp = fopen(path, "rb");
	if (!fp) {
		printf("open firmware fail\n");
		return 1;
	}

	/* set file ptr to the end */
	fseek(fp, 0, SEEK_END);
	fwp->len = ftell(fp);

	printf("fw len = %d\n", fwp->len);

	/* set the file ptr the beginning */
	rewind(fp);

	fwp->data = (uint8_t*)malloc(fwp->len + 32);
	if (!fwp->data) {
		printf("alloc memory fail\n");
		fclose(fp);
		return 1;
	}

	if (fread(fwp->data, 1, fwp->len, fp) == fwp->len)	{
		fclose(fp);
		hx_printf("read fw data success\n");
		himax_check_fw_header(fwp);
		return 0;
	} else {
		printf("read fw data error\n");
	//	himax_free_fw(fwp);
		free(fwp->data);
		fclose(fp);
		return 1;
	}
}

int himax_scan_device(OPTDATA *optp)
{
	char *devp = NULL;

	if (!optp) {
		hx_printf("%s: parameter error\n", __func__);
		return 1;
	}

	if (strlen(optp->dev_path))
		devp = optp->dev_path;

	hx_scan_i2c_device(devp);

	if (hx_open_i2c_device())
		return 1;

	return 0;
}

static void himax_burst_enable(uint8_t auto_add_4_byte)
{
	int ret;

	hx_buf[0] = ic_adr_conti;
	hx_buf[1] = ic_cmd_conti;
	ret = hx_i2c_write(HX_DEFAULT_I2C_ADDR, hx_buf, 2);
	if (ret < 0) {
		fprintf(stderr, "%s: bus access fail!\n", __func__);
		return;
	}

	hx_buf[0] = ic_adr_incr4;
	hx_buf[1] = ic_cmd_incr4 | auto_add_4_byte;
	ret = hx_i2c_write(HX_DEFAULT_I2C_ADDR, hx_buf, 2);
	if (ret < 0) {
		fprintf(stderr, "%s: bus access fail!\n", __func__);
		return;
	}
}

int ahb_reg_read(uint32_t addr, uint8_t *buf, uint32_t len)
{
	int ret = -1;
	uint8_t addr_t[4] = {0};

	addr_t[0] = addr & 0xFF;
	addr_t[1] = (addr >> 8) & 0xFF;
	addr_t[2] = (addr >> 16) & 0xFF;
	addr_t[3] = (addr >> 24) & 0xFF;

	if (addr == flash_addr_spi200_data)
		himax_burst_enable(0);
	else if (len > 4)
		himax_burst_enable(1);
	else
		himax_burst_enable(0);

//	hx_buf[0] = 0x00;
	hx_buf[0] = ic_adr_ahb_addr_byte_0;
	memcpy(hx_buf+1, addr_t, 4);
	ret = hx_i2c_write(HX_DEFAULT_I2C_ADDR, hx_buf, 5);
	if (ret < 0) {
		fprintf(stderr, "set address fail\n");
		return ret;
	}

//	hx_buf[0] = 0x0C;
//	hx_buf[1] = 0x00;
	hx_buf[0] = ic_adr_ahb_access_direction;
	hx_buf[1] = ic_cmd_ahb_access_direction_read;
	ret = hx_i2c_write(HX_DEFAULT_I2C_ADDR, hx_buf, 2);
	if (ret < 0) {
		fprintf(stderr, "set direction fail\n");
		return ret;
	}

//	hx_buf[0] = 0x08;
	hx_buf[0] = ic_adr_ahb_rdata_byte_0;
	ret = hx_i2c_read(HX_DEFAULT_I2C_ADDR, hx_buf, 1, buf, len);
	if (ret < 0) {
		fprintf(stderr, "read data fail\n");
		return ret;
	}

	return 0;
}

int ahb_reg_write(uint32_t addr, uint8_t *val, uint32_t len)
{
	int ret = -1;
	uint8_t addr_t[4] = {0};

	addr_t[0] = addr & 0xFF;
	addr_t[1] = (addr >> 8) & 0xFF;
	addr_t[2] = (addr >> 16) & 0xFF;
	addr_t[3] = (addr >> 24) & 0xFF;

	if (addr == flash_addr_spi200_data)
		himax_burst_enable(0);
	else if (len > 4)
		himax_burst_enable(1);
	else
		himax_burst_enable(0);

//	hx_buf[0] = 0x00;
	hx_buf[0] = ic_adr_ahb_addr_byte_0;
	memcpy(hx_buf+1, addr_t, 4);
	memcpy(hx_buf+5, val, len);
	ret = hx_i2c_write(HX_DEFAULT_I2C_ADDR, hx_buf, len+5);
	if (ret < 0) {
		fprintf(stderr, "%s: write i2c fail!\n", __func__);
		return ret;
	}

	return 0;
}

void himax_parse_assign_cmd(uint32_t addr, uint8_t *cmd, uint32_t len)
{

	switch (len) {
	case 1:
		cmd[0] = addr;
		break;
	case 2:
		cmd[0] = addr & 0xFF;
		cmd[1] = (addr >> 8) & 0xFF;
		break;
	case 4:
		cmd[0] = addr & 0xFF;
		cmd[1] = (addr >> 8) & 0xFF;
		cmd[2] = (addr >> 16) & 0xFF;
		cmd[3] = (addr >> 24) & 0xFF;
		break;
	default:
		printf("%s: input length fault,len = %d!\n", __func__, len);
	}
}

int himax_reg_write(uint32_t addr, uint32_t data, access_t type)
{
	int ret;
	uint8_t tmp[4] = {0};

	if (type == ACCESS_AHB) {
		himax_parse_assign_cmd(data, tmp, 4);
		ret = ahb_reg_write(addr, tmp, 4);
	} else if (type == ACCESS_HID) {
		ret = _hid_reg_write(addr, data);
	} else {
		hx_printf("%s: access type error!\n", __func__);
		return -EINVAL;
	}

	return ret;
}

int himax_reg_read(uint32_t addr, uint32_t *data, access_t type)
{
	int ret;
	uint8_t tmp[4] = {0};

	if (type == ACCESS_AHB) {
		ret = ahb_reg_read(addr, tmp, 4);
		if (ret == 0)
			*data = tmp[0] | (tmp[1]<<8) | (tmp[2]<<16) | (tmp[3]<<24);
	} else if (type == ACCESS_HID) {
		ret = _hid_reg_read(addr, data);
	} else {
		hx_printf("%s: access type error!\n", __func__);
		return -EINVAL;
	}

	return ret;
}

bool himax_update_check(HXFW *fwp, hx_hid_info* hid_info = NULL)
{
	uint8_t tmp_data[4];
	uint32_t fw_ver_ic = 0;
	uint32_t fw_ver_bin = 0;

	if (hid_info == NULL) {
		ahb_reg_read(ic_adr_cs_central_state, tmp_data, 4);
		if (tmp_data[0] != 0x05) {
			printf("ic state = %X\n", tmp_data[0]);
			return true;
		} else {
			ahb_reg_read(fw_addr_fw_vendor_addr, tmp_data, 4);
			fw_ver_ic = tmp_data[2]<<8 | tmp_data[3];
		//	printf("fw_ver_ic = %08X\n", fw_ver_ic);
		}
	} else {
		fw_ver_ic = hid_info->cid;
	}

	if (!fwp->is_info_valid) {
		printf("fw header check fail, force update\n");
		return true;
	} else if (hid_info != NULL) {
		if (strncmp(fwp->ic_id, hid_info->ic_sign_2, 12) != 0 ||
			strncmp(fwp->customer, hid_info->customer, 12) != 0 ||
			strncmp(fwp->project, hid_info->project, 12) != 0) {
				printf("compatibility check fail:\n Device: ic_id=%s, customer=%s, project=%s\n"
			           " Firmware: ic_id=%s, customer=%s, project=%s\n",
			           hid_info->ic_sign_2, hid_info->customer, hid_info->project,
					   fwp->ic_id, fwp->customer, fwp->project);
			return false;
		}
	}

	fw_ver_bin = fwp->cid;

	printf("fw_ver_bin = %08X; fw_ver_ic = %08X\n", fw_ver_bin, fw_ver_ic);

	if (fw_ver_bin > fw_ver_ic)
		return true;

	return false;
}

static bool himax_wait_wip(uint32_t Timing)
{
	uint8_t tmp_data[4];
	uint32_t retry_cnt = 0;

	uint8_t trans_fmt[4] = {0};
	uint8_t trans_ctrl1[4] = {0};
	uint8_t cmd1[4] = {0};

	himax_parse_assign_cmd(flash_data_spi200_trans_fmt, trans_fmt, 4);
	himax_parse_assign_cmd(flash_data_spi200_trans_ctrl_1, trans_ctrl1, 4);
	himax_parse_assign_cmd(flash_data_spi200_cmd_1, cmd1, 4);

	ahb_reg_write(flash_addr_spi200_trans_fmt, trans_fmt, 4);

	do {
		ahb_reg_write(flash_addr_spi200_trans_ctrl,
			trans_ctrl1, 4);

		ahb_reg_write(flash_addr_spi200_cmd, cmd1, 4);

		tmp_data[0] = tmp_data[1] = tmp_data[2] = tmp_data[3] = 0xFF;
		ahb_reg_read(flash_addr_spi200_data,
			tmp_data, 4);

		if ((tmp_data[0] & 0x01) == 0x00)
			return true;

		retry_cnt++;

		if (tmp_data[0] != 0x00 || tmp_data[1] != 0x00
		|| tmp_data[2] != 0x00 || tmp_data[3] != 0x00)
			printf("%s: retry:%d, bf[0]=%d, bf[1]=%d,bf[2]=%d, bf[3]=%d\n",
			__func__, retry_cnt, tmp_data[0], tmp_data[1], tmp_data[2], tmp_data[3]);

		if (retry_cnt > 100) {
			printf("%s: Wait wip error!\n", __func__);
			return false;
		}

	//	msleep(Timing);
		usleep(Timing * 1000);
	} while ((tmp_data[0] & 0x01) == 0x01);

	return true;
}
#if 0
static void himax_init_psl(void)
{
	ahb_reg_write(pic_op->addr_psl, pic_op->data_rst,
		sizeof(pic_op->data_rst));
	printf("%s: power saving level reset OK!\n", __func__);
}
#endif
static void himax_system_reset(void)
{
	uint8_t tmp_data[4] = {0};
	int retry = 0;

	ahb_reg_write(fw_addr_ctrl_fw, tmp_data, 4);

	do {
		tmp_data[0] = 0x55;
		tmp_data[1] = 0; tmp_data[2] = 0; tmp_data[3] = 0;
		ahb_reg_write(fw_addr_system_reset, tmp_data, 4);

		usleep(10000);

		ahb_reg_read(fw_addr_flag_reset_event, tmp_data, 4);
		printf("%s:Read status from IC = %X,%X\n", __func__, tmp_data[0], tmp_data[1]);
	} while ((tmp_data[1] != 0x02 || tmp_data[0] != 0x00) && retry++ < 5);
}

[[maybe_unused]]
static void himax_enter_safe_mode(void)
{
	int ret = 0;

	/**
	 * I2C_password[7:0] set Enter safe mode : 0x31 ==> 0x27 0x95
	 */
	hx_buf[0] = ic_adr_i2c_psw_lb;
	hx_buf[1] = ic_cmd_i2c_psw_lb;
	hx_buf[2] = ic_cmd_i2c_psw_ub;
	ret = hx_i2c_write(HX_DEFAULT_I2C_ADDR, hx_buf, 3);
	if (ret < 0)
		printf("%s: bus access fail!\n", __func__);
}

[[maybe_unused]]
static void himax_safe_mode_reset(void)
{
	int ret = 0;
	uint8_t tmp_data[4];
	int retry = 0;
	uint8_t data_clear[4] = {0};

	ahb_reg_write(fw_addr_ctrl_fw, data_clear, 4);
	do {
		/* reset code*/
		himax_enter_safe_mode();

		/**
		 * I2C_password[7:0] set Enter safe mode : 0x31 ==> 0x00
		 */
		hx_buf[0] = ic_adr_i2c_psw_lb;
		hx_buf[1] = 0x00;
		ret = hx_i2c_write(HX_DEFAULT_I2C_ADDR, hx_buf, 2);
		if (ret < 0)
			printf("%s: bus access fail!\n", __func__);

		usleep(10000);

		ahb_reg_read(fw_addr_flag_reset_event, tmp_data, 4);
		printf("%s:Read status from IC = %X,%X\n", __func__, tmp_data[0], tmp_data[1]);
	} while ((tmp_data[1] != 0x02 || tmp_data[0] != 0x00) && retry++ < 5);
}

static void himax_sense_on(uint8_t FlashMode)
{
	int ret = 0;

	uint8_t data_clear[4] = {0};

	printf("Enter %s\n", __func__);

	ahb_reg_write(fw_addr_ctrl_fw, data_clear, 4);
	usleep(10000);
	if (!FlashMode) {
		himax_system_reset();
	} else {
		hx_buf[0] = ic_adr_i2c_psw_lb;
		hx_buf[1] = 0x00;
		ret = hx_i2c_write(HX_DEFAULT_I2C_ADDR, hx_buf, 2);
		if (ret < 0) {
			printf("%s: cmd=%x bus access fail!\n",
			__func__, ic_adr_i2c_psw_lb);
		}

		// hx_buf[0] = ic_adr_i2c_psw_ub;
		// hx_buf[1] = 0X00;
		// ret = hx_i2c_write(HX_DEFAULT_I2C_ADDR, hx_buf, 2);
		// if (ret < 0) {
		// 	printf("%s: cmd=%x bus access fail!\n",
		// 		__func__, ic_adr_i2c_psw_ub);
		// }
	}
}

static bool himax_sense_off(bool check_en)
{
	uint8_t cnt = 0;
	uint8_t tmp_data[4];
	int ret = 0;

	uint8_t fw_stop[4];

	himax_parse_assign_cmd(fw_data_fw_stop, fw_stop, 4);

	do {
		if (cnt == 0 || (tmp_data[0] != 0xA5 && tmp_data[0] != 0x00 && tmp_data[0] != 0x87))
			ahb_reg_write(fw_addr_ctrl_fw, fw_stop, 4);

		/* check fw status */
		ahb_reg_read(ic_adr_cs_central_state, tmp_data, 4);
		if (tmp_data[0] != 0x05) {
			printf("%s: Do not need wait FW, Status = 0x%02X!\n",
					__func__, tmp_data[0]);
			break;
		}

		usleep(10 * 1000);

		ahb_reg_read(fw_addr_ctrl_fw, tmp_data, 4);

		printf("%s: cnt = %d, data[0] = 0x%02X!\n", __func__, cnt, tmp_data[0]);

	} while (tmp_data[0] != 0x87 && (++cnt < 35) && check_en == true);

	cnt = 0;

	do {
		/**
		 *I2C_password[7:0] set Enter safe mode : 0x31 ==> 0x27
		 */
		hx_buf[0] = ic_adr_i2c_psw_lb;
		hx_buf[1] = ic_cmd_i2c_psw_lb;
		hx_buf[2] = ic_cmd_i2c_psw_ub;
		ret = hx_i2c_write(HX_DEFAULT_I2C_ADDR, hx_buf, 3);
		if (ret < 0) {
			printf("%s: bus access fail!\n", __func__);
			return false;
		}

		// /**
		//  *I2C_password[15:8] set Enter safe mode :0x32 ==> 0x95
		//  */
		// hx_buf[0] = ic_adr_i2c_psw_ub;
		// hx_buf[1] = ic_cmd_i2c_psw_ub;
		// ret = hx_i2c_write(HX_DEFAULT_I2C_ADDR, hx_buf, 2);
		// if (ret < 0) {
		// 	printf("%s: bus access fail!\n", __func__);
		// 	return false;
		// }

		/**
		 *Check enter_save_mode
		 */
		ahb_reg_read(ic_adr_cs_central_state, tmp_data, 4);
		printf("%s: Check enter_save_mode data[0]=%X\n",
				__func__, tmp_data[0]);

		if (tmp_data[0] == 0x0C) {
			/**
			 *Reset TCON
			 */
			tmp_data[3] = 0x00;
			tmp_data[2] = 0x00;
			tmp_data[1] = 0x00;
			tmp_data[0] = 0x00;
			ahb_reg_write(ic_adr_tcon_on_rst, tmp_data, 4);
			usleep(1000);
			return true;
		}
		usleep(10 * 1000);
		himax_system_reset();
	} while (cnt++ < 5);

	return false;
}

[[maybe_unused]]
static bool himax_flash_sector_erase(uint32_t start_addr, uint32_t length)
{
	uint32_t page_prog_start = 0;
	uint32_t sector_size = 0x1000;

	uint8_t tmp_data[4] = {0};

	uint8_t psl_rst[4];
	uint8_t trans_fmt[4];
	uint8_t trans_ctrl2[4];
	uint8_t cmd2[4];
	uint8_t trans_ctrl3[4];
	uint8_t cmd5[4];

	himax_parse_assign_cmd(ic_cmd_rst, psl_rst, 4);
	himax_parse_assign_cmd(flash_data_spi200_trans_fmt, trans_fmt, 4);
	himax_parse_assign_cmd(flash_data_spi200_trans_ctrl_2, trans_ctrl2, 4);
	himax_parse_assign_cmd(flash_data_spi200_cmd_2, cmd2, 4);
	himax_parse_assign_cmd(flash_data_spi200_trans_ctrl_3, trans_ctrl3, 4);
	himax_parse_assign_cmd(flash_data_spi200_cmd_5, cmd5, 4);

//	himax_init_psl();
	ahb_reg_write(ic_adr_psl, psl_rst, 4);
	printf("%s: power saving level reset OK!\n", __func__);

	ahb_reg_write(flash_addr_spi200_trans_fmt,
		trans_fmt, 4);

	for (page_prog_start = start_addr;
	page_prog_start < start_addr + length;
	page_prog_start = page_prog_start + sector_size) {
		ahb_reg_write(flash_addr_spi200_trans_ctrl,
			trans_ctrl2, 4);
		ahb_reg_write(flash_addr_spi200_cmd,
			cmd2, 4);

		tmp_data[3] = (page_prog_start >> 24)&0xFF;
		tmp_data[2] = (page_prog_start >> 16)&0xFF;
		tmp_data[1] = (page_prog_start >> 8)&0xFF;
		tmp_data[0] = page_prog_start&0xFF;
		ahb_reg_write(flash_addr_spi200_addr,
			tmp_data, 4);

		ahb_reg_write(flash_addr_spi200_trans_ctrl,
			trans_ctrl3, 4);
		ahb_reg_write(flash_addr_spi200_cmd,
			cmd5, 4);
		usleep(100000);

		if (!himax_wait_wip(100)) {
			printf("%s: Erase Fail\n", __func__);
			return false;
		}
	}

	printf("%s: END\n", __func__);
	return true;
}
#if 1
static bool himax_flash_block_erase(uint32_t start_addr, uint32_t length)
{
	uint32_t page_prog_start = 0;
	uint32_t block_size = 0x10000;

	uint8_t tmp_data[4] = {0};

	uint8_t psl_rst[4];
	uint8_t trans_fmt[4];
	uint8_t trans_ctrl2[4];
	uint8_t cmd2[4];
	uint8_t trans_ctrl3[4];
	uint8_t cmd4[4];

	himax_parse_assign_cmd(ic_cmd_rst, psl_rst, 4);
	himax_parse_assign_cmd(flash_data_spi200_trans_fmt, trans_fmt, 4);
	himax_parse_assign_cmd(flash_data_spi200_trans_ctrl_2, trans_ctrl2, 4);
	himax_parse_assign_cmd(flash_data_spi200_cmd_2, cmd2, 4);
	himax_parse_assign_cmd(flash_data_spi200_trans_ctrl_3, trans_ctrl3, 4);
	himax_parse_assign_cmd(flash_data_spi200_cmd_4, cmd4, 4);

//	himax_init_psl();
	ahb_reg_write(ic_adr_psl, psl_rst, 4);
	printf("%s: power saving level reset OK!\n", __func__);

	ahb_reg_write(flash_addr_spi200_trans_fmt,
		trans_fmt, 4);

	for (page_prog_start = start_addr;
	page_prog_start < start_addr + length;
	page_prog_start = page_prog_start + block_size) {
		ahb_reg_write(flash_addr_spi200_trans_ctrl,
			trans_ctrl2, 4);
		ahb_reg_write(flash_addr_spi200_cmd,
			cmd2, 4);

		tmp_data[3] = (page_prog_start >> 24)&0xFF;
		tmp_data[2] = (page_prog_start >> 16)&0xFF;
		tmp_data[1] = (page_prog_start >> 8)&0xFF;
		tmp_data[0] = page_prog_start & 0xFF;
		ahb_reg_write(flash_addr_spi200_addr,
			tmp_data, 4);

		ahb_reg_write(flash_addr_spi200_trans_ctrl,
			trans_ctrl3, 4);
		ahb_reg_write(flash_addr_spi200_cmd,
			cmd4, 4);
		usleep(1000 * gFlash_info->block_erase_delay);

		if (!himax_wait_wip(gFlash_info->block_erase_delay)) {
			printf("%s: Erase Fail\n", __func__);
			return false;
		}
	}

	printf("%s: END\n", __func__);
	return true;
}
#endif
static void himax_flash_programming(uint8_t *FW_content, uint32_t FW_Size)
{
	uint32_t page_prog_start = 0;
//	int i = 0;
	uint8_t tmp_data[4];
	int ret = 0;

	uint8_t trans_fmt[4];
	uint8_t trans_ctrl2[4];
	uint8_t cmd2[4];
	uint8_t trans_ctrl4[4];
	uint8_t cmd6[4];

	himax_parse_assign_cmd(flash_data_spi200_trans_fmt, trans_fmt, 4);
	himax_parse_assign_cmd(flash_data_spi200_trans_ctrl_2, trans_ctrl2, 4);
	himax_parse_assign_cmd(flash_data_spi200_cmd_2, cmd2, 4);
	himax_parse_assign_cmd(flash_data_spi200_trans_ctrl_4, trans_ctrl4, 4);
	himax_parse_assign_cmd(flash_data_spi200_cmd_6, cmd6, 4);

	/* 4 bytes for padding*/
//	g_core_fp.fp_interface_on();
	hx_printf("%s: start programming...\n", __func__);

	ahb_reg_write(flash_addr_spi200_trans_fmt,
		trans_fmt, 4);

	for (page_prog_start = 0; page_prog_start < FW_Size;
	page_prog_start += FLASH_RW_MAX_LEN) {
		ahb_reg_write(flash_addr_spi200_trans_ctrl,
			trans_ctrl2, 4);
		ahb_reg_write(flash_addr_spi200_cmd,
			cmd2, 4);

		 /*Programmable size = 1 page = 256 bytes,*/
		 /*word_number = 256 byte / 4 = 64*/
		ahb_reg_write(flash_addr_spi200_trans_ctrl,
			trans_ctrl4, 4);

		/* Flash start address 1st : 0x0000_0000*/
		if (page_prog_start < 0x100) {
			tmp_data[3] = 0x00;
			tmp_data[2] = 0x00;
			tmp_data[1] = 0x00;
			tmp_data[0] = (uint8_t)page_prog_start;
		} else if (page_prog_start >= 0x100
		&& page_prog_start < 0x10000) {
			tmp_data[3] = 0x00;
			tmp_data[2] = 0x00;
			tmp_data[1] = (uint8_t)(page_prog_start >> 8);
			tmp_data[0] = (uint8_t)page_prog_start;
		} else if (page_prog_start >= 0x10000
		&& page_prog_start < 0x1000000) {
			tmp_data[3] = 0x00;
			tmp_data[2] = (uint8_t)(page_prog_start >> 16);
			tmp_data[1] = (uint8_t)(page_prog_start >> 8);
			tmp_data[0] = (uint8_t)page_prog_start;
		}
		ahb_reg_write(flash_addr_spi200_addr,
			tmp_data, 4);

		ret = ahb_reg_write(flash_addr_spi200_data,
			&FW_content[page_prog_start], 16);
		if (ret < 0) {
			printf("%s: bus access fail!\n", __func__);
			return;
		}

		ahb_reg_write(flash_addr_spi200_cmd,
			cmd6, 4);

	//	for (i = 0; i < 5; i++) {
	//		ret = ahb_reg_write(flash_addr_spi200_data,
	//			&FW_content[page_prog_start+16+(i*PROGRAM_SZ)],
	//			PROGRAM_SZ);
	//		if (ret < 0) {
	//			printf("%s: bus access fail!\n", __func__);
	//			return;
	//		}
	//	}

		ret = ahb_reg_write(flash_addr_spi200_data,
			&FW_content[page_prog_start+16], 240);
		if (ret < 0) {
			printf("%s: bus access fail!\n", __func__);
			return;
		}
		usleep(1000 * gFlash_info->write_delay);

		if (!himax_wait_wip(1))
			printf("%s:Flash_Programming Fail\n", __func__);

	}
}

static uint32_t himax_check_CRC(uint32_t start_addr, uint32_t reload_length)
{
	uint32_t result = 0;
	uint8_t tmp_addr[4] = {0};
	uint8_t tmp_data[4] = {0};
	int cnt = 0, ret = 0;
	uint32_t length = reload_length / 4;

	himax_parse_assign_cmd(start_addr, tmp_addr, 4);

	ret = ahb_reg_write(fw_addr_reload_addr_from,
		tmp_addr, 4);
	if (ret < 0) {
		printf("%s: bus access fail!\n", __func__);
		return 1;
	}

	tmp_data[3] = 0x00;
	tmp_data[2] = 0x99;
	tmp_data[1] = (length >> 8);
	tmp_data[0] = length;
	ret = ahb_reg_write(fw_addr_reload_addr_cmd_beat,
		tmp_data, 4);
	if (ret < 0) {
		printf("%s: bus access fail!\n", __func__);
		return 1;
	}
	cnt = 0;

	do {
		ret = ahb_reg_read(fw_addr_reload_status,
			tmp_data, 4);
		if (ret < 0) {
			printf("%s: bus access fail!\n", __func__);
			return 1;
		}

		if ((tmp_data[0] & 0x01) != 0x01) {
			ret = ahb_reg_read(fw_addr_reload_crc32_result,
				tmp_data, 4);
			if (ret < 0) {
				printf("%s: bus access fail!\n", __func__);
				return 1;
			}
			printf("%s: data[3]=%X,data[2]=%X,data[1]=%X,data[0]=%X\n",
				__func__, tmp_data[3], tmp_data[2], tmp_data[1],
				tmp_data[0]);

			result = ((tmp_data[3] << 24)
					+ (tmp_data[2] << 16)
					+ (tmp_data[1] << 8)
					+ tmp_data[0]);
			goto END;
		} else {
			printf("Waiting for HW ready!\n");
			usleep(1000);
		}

	} while (cnt++ < 100);
END:
	return result;
}

static bool get_flash_id(int32_t *flash_id, access_t access_mode)
{
	const uint32_t reg_10_addr = 0x80000010;
	const uint32_t reg_20_addr = 0x80000020;
	const uint32_t reg_24_addr = 0x80000024;
	const uint32_t reg_2c_addr = 0x8000002C;
	const uint32_t reg_10_data = 0x00020780;
	const uint32_t reg_20_data = 0x42000002;
	const uint32_t reg_24_data = 0x9F;
	uint8_t tmp_data[4] = {0};
	int ret;

	ret = himax_reg_write(reg_10_addr, reg_10_data, access_mode);// set CMD 0x00020780
	ret |= himax_reg_write(reg_20_addr, reg_20_data, access_mode);// set CMD 0x42000002
	ret |= himax_reg_write(reg_24_addr, reg_24_data, access_mode);// set CMD 0x9F

	usleep(1000);

	ret |= himax_reg_read(reg_2c_addr, (uint32_t *)tmp_data, access_mode);

	if (ret != 0) {
		hx_printf("%s: bus access fail!\n", __func__);
		*flash_id = -1;
		return false;
	}

	*flash_id = (tmp_data[0]) | (tmp_data[1] << 8)
		| (tmp_data[2] << 16) | (tmp_data[3] << 24);

	return true;
}

static bool match_flash_id(int32_t flash_id)
{
	long unsigned int i = 0;

	if (flash_id < 0)
		return false;

	for (i = 0; i < FLASH_TABLE_SIZE; i++) {
		if (gFlash_table[i].id == (uint32_t)flash_id) {
			gFlash_info = &gFlash_table[i];
			return true;
		}
		if (gFlash_table[i].id == 0x00000000U) {
			hx_printf("%s: Not support this flash ID: %08X\n",
				__func__, flash_id);
			return false;
		}
	}

	return false;
}

static int16_t get_block_protect_mask(int32_t flash_id)
{
	long unsigned int i = 0;
	int16_t block_protect_mask = -1;

	if (flash_id < 0)
		return 0;

	for (i = 0; i < FLASH_TABLE_SIZE; i++) {
		block_protect_mask = gFlash_table[i].block_protect_mask;
		if (gFlash_table[i].id == (uint32_t)flash_id) {
			break;
		}
		if (gFlash_table[i].id == 0x00000000U) {
			hx_printf("%s: Not support this flash ID: %08X\n",
				__func__, flash_id);
		}
	}

	return block_protect_mask;
}

static uint16_t get_write_delay(int32_t flash_id)
{
	long unsigned int i = 0;
	uint16_t write_delay;

	if (flash_id < 0)
		return gFlash_table[FLASH_TABLE_SIZE - 1].write_delay;

	for (i = 0; i < FLASH_TABLE_SIZE; i++) {
		write_delay = gFlash_table[i].write_delay;
		if (gFlash_table[i].id == (uint32_t)flash_id)
			break;

		if (gFlash_table[i].id == 0x00000000U)
			hx_printf("%s: Not support this flash ID: %08X\n",
				__func__, flash_id);
	}

	return write_delay;
}

static int32_t get_flash_status(int32_t flash_id, access_t access_mode)
{
	const uint32_t reg_10_addr = 0x80000010;
	const uint32_t reg_20_addr = 0x80000020;
	const uint32_t reg_24_addr = 0x80000024;
	const uint32_t reg_2c_addr = 0x8000002C;
	const uint32_t reg_10_data = 0x00020780;
	const uint32_t reg_20_data = 0x42000000;
	const uint32_t reg_24_data = 0x05;
	int ret;
	int16_t block_protect_mask;
	uint8_t tmp_data[4] = {0};

	if (flash_id < 0)
		return 0;

	block_protect_mask = get_block_protect_mask(flash_id);
	if (block_protect_mask < 0) {
		return 0;
	}

	ret = himax_reg_write(reg_10_addr, reg_10_data, access_mode);// set CMD 0x00020780
	ret |= himax_reg_write(reg_20_addr, reg_20_data, access_mode);// set CMD 0x42000000
	ret |= himax_reg_write(reg_24_addr, reg_24_data, access_mode);// set CMD 0x05
	ret |= himax_reg_read(reg_2c_addr, (uint32_t *)tmp_data, access_mode);

	if (ret != 0) {
		hx_printf("%s: bus access fail!\n", __func__);
		return -1;
	}

	tmp_data[0] = tmp_data[0] & block_protect_mask;
	if (tmp_data[0] != 0) {
		hx_printf("%s: Flash is locked! reg_2c=0x%02X, mask=0x%02X\n",
			__func__, tmp_data[0], block_protect_mask);
		return 1;
	} else {
		hx_printf("%s: Flash is unlocked! reg_2c=0x%02X, mask=0x%02X\n",
			__func__, tmp_data[0], block_protect_mask);
	}

	return 0;
}

static bool switch_write_protect(bool enable, access_t access_mode)
{
	const uint32_t reg_wp_addr = 0x900880BC;
	uint8_t tmp_data[4] = {0};
	int ret;

	ret = himax_reg_read(reg_wp_addr, (uint32_t *)tmp_data, access_mode);
	if (ret != 0) {
		hx_printf("%s: bus access fail!\n", __func__);
		return false;
	}

	if (enable)
		tmp_data[0] |= 0x01;
	else
		tmp_data[0] &= 0xFE;

	ret = himax_reg_write(reg_wp_addr, *(uint32_t *)tmp_data, access_mode);

	return ret == 0;
}

static bool switch_block_protect(int32_t flash_id, bool enable, access_t access_mode)
{
	const uint32_t reg_10_addr = 0x80000010;
	const uint32_t reg_20_addr = 0x80000020;
	const uint32_t reg_24_addr = 0x80000024;
	const uint32_t reg_2c_addr = 0x8000002C;
	const uint32_t reg_10_data = 0x00020780;
	const uint32_t reg_20_data_1 = 0x47000000;
	const uint32_t reg_20_data_2 = 0x41000000;
	const uint32_t reg_20_data_3 = 0x42000000;
	const uint32_t reg_24_data_1 = 0x06;
	const uint32_t reg_24_data_2 = 0x01;
	const uint32_t reg_24_data_3 = 0x05;
	uint8_t tmp_data[4] = {0};
	int16_t block_protect_mask;
	int ret;
	int i = 0;
	int max_retry = 100;

	if (enable) {
		if (flash_id >= 0)
			block_protect_mask = get_block_protect_mask(flash_id);
		else
			block_protect_mask = 0x00;
	} else {
		block_protect_mask = 0x00;
	}

	ret = himax_reg_write(reg_10_addr, reg_10_data, access_mode);// set CMD 0x00020780
	ret |= himax_reg_write(reg_20_addr, reg_20_data_1, access_mode);// set CMD 0x47000000
	ret |= himax_reg_write(reg_24_addr, reg_24_data_1, access_mode);// set CMD 0x06
	ret |= himax_reg_write(reg_20_addr, reg_20_data_2, access_mode);// set CMD 0x41000000
	ret |= himax_reg_write(reg_2c_addr, block_protect_mask, access_mode);// set CMD to block_protect_mask
	ret |= himax_reg_write(reg_24_addr, reg_24_data_2, access_mode);// set CMD 0x01
	usleep(get_write_delay(flash_id) * 1000);

	ret |= himax_reg_write(reg_20_addr, reg_20_data_3, access_mode);// set CMD 0x42000000
	if (ret != 0) {
		hx_printf("%s: bus access fail!\n", __func__);
		return false;
	}
	do {
		ret = himax_reg_write(reg_24_addr, reg_24_data_3, access_mode);// set CMD 0x05
		if (ret != 0) {
			hx_printf("%s: bus access fail!\n", __func__);
			return false;
		}

		ret = himax_reg_read(reg_2c_addr, (uint32_t *)tmp_data, access_mode);
		if (ret != 0) {
			hx_printf("%s: bus access fail!\n", __func__);
			return false;
		}
		if ((tmp_data[0] & 0x03) == 0)
			break;

		usleep(1000);
	} while (i++ < max_retry);

	if (i < max_retry) {
		hx_printf("%s: Switch block protect %s success!\n",
			__func__, enable ? "enable" : "disable");
		return true;
	}

	hx_printf("%s: Switch block protect %s fail!\n",
			__func__, enable ? "enable" : "disable");

	return false;
}

static int unlock_flash(access_t access_mode)
{
	int32_t flash_id;

	if (!get_flash_id(&flash_id, access_mode)) {
		printf("%s: Get flash ID fail!\n", __func__);
	}

	if (get_flash_status(flash_id, access_mode) > 0) {
		if (!switch_write_protect(false, access_mode)) {
			printf("%s: Switch write protect disable fail!\n", __func__);
			return -1;
		}

		if (!switch_block_protect(flash_id, false, access_mode)) {
			printf("%s: Switch block protect disable fail!\n", __func__);
			return -1;
		}

		if (get_flash_status(flash_id, access_mode) > 0) {
			printf("%s: Unlock flash fail!\n", __func__);
			return -1;
		}
	} else {
		printf("%s: Flash is already unlocked!\n", __func__);
	}

	return 0;
}

int himax_fw_update(uint8_t *fw, uint32_t len)
{
	int result = -1;
	int32_t flash_id = -1;
	uint8_t tmp_data[4] = {0x01, 0x00, 0x00, 0x00};

	// himax_system_reset();

	himax_sense_off(true);

	if (get_flash_id(&flash_id, ACCESS_AHB)) {
		if (!match_flash_id(flash_id)) {
			printf("%s: Not supported flash ID: %08X, use default settings\n", __func__, flash_id);
		}
	}
	if (gFlash_info->block_protect_mask != 0)
		unlock_flash(ACCESS_AHB);

//	himax_flash_speed_set(HX_FLASH_SPEED_12p5M);
	ahb_reg_write(flash_clk_setup_addr, tmp_data, 4);

	// himax_flash_sector_erase(0x00, len);
	himax_flash_block_erase(0, len);

	himax_flash_programming(fw, len);

	if (himax_check_CRC(fw_addr_program_reload_from, len) == 0) {
		result = 0;
		printf("%s: FW update succeed!.\n", __func__);
	} else {
		printf("%s: FW update failed: CRC check fail.\n", __func__);
	}

	return result;
}

static int himax_read_fw_status(void)
{
	uint8_t data_t[4] = {0};

	ahb_reg_read(fw_addr_fw_dbg_msg_addr, data_t, 4);
	printf("0x%08X = 0x%02X, 0x%02X, 0x%02X, 0x%02X\n",
		fw_addr_fw_dbg_msg_addr, data_t[0], data_t[1], data_t[2], data_t[3]);

	ahb_reg_read(fw_addr_chk_fw_status, data_t, 4);
	printf("0x%08X = 0x%02X, 0x%02X, 0x%02X, 0x%02X\n",
		fw_addr_chk_fw_status, data_t[0], data_t[1], data_t[2], data_t[3]);

	ahb_reg_read(fw_addr_chk_dd_status, data_t, 4);
	printf("0x%08X = 0x%02X, 0x%02X, 0x%02X, 0x%02X\n",
		fw_addr_chk_dd_status, data_t[0], data_t[1], data_t[2], data_t[3]);

	ahb_reg_read(fw_addr_flag_reset_event, data_t, 4);
	printf("0x%08X = 0x%02X, 0x%02X, 0x%02X, 0x%02X\n",
		fw_addr_flag_reset_event, data_t[0], data_t[1], data_t[2], data_t[3]);

	return 0;
}

static int himax_power_on_init(void)
{
	int ret = -1;
	uint8_t tmp_data[4] = {0x01, 0x00, 0x00, 0x00};
	uint8_t retry = 0;

	uint8_t data_clear[4];

	himax_parse_assign_cmd(fw_data_clear, data_clear, 4);

	/*RawOut select initial*/
	ahb_reg_write(fw_addr_raw_out_sel,
		data_clear, 4);
	/*DSRAM func initial*/
	ahb_reg_write(fw_addr_sorting_mode_en,
		data_clear, 4);
	/*N frame initial*/
	/* reset N frame back to default value 1 for normal mode */
	ahb_reg_write(fw_addr_set_frame_addr, tmp_data, 4);
	/*FW reload done initial*/
	ahb_reg_write(driver_addr_fw_define_2nd_flash_reload,
		data_clear, 4);

	himax_sense_on(0x00);

	printf("%s: waiting for FW reload data\n", __func__);

	while (retry++ < 30) {
		ahb_reg_read(driver_addr_fw_define_2nd_flash_reload,
			tmp_data, 4);

		/* use all 4 bytes to compare */
		if ((tmp_data[3] == 0x00 && tmp_data[2] == 0x00 &&
			tmp_data[1] == 0x72 && tmp_data[0] == 0xC0)) {
			printf("\n%s: FW reload done\n", __func__);
			ret = 0;
			break;
		}
		printf("%s: wait FW reload %d times\n", __func__, retry);
		himax_read_fw_status();
		usleep(10000);
	}

	return ret;
}

static void himax_read_fw_ver(void)
{
	uint8_t data[12] = {0};

	ahb_reg_read(fw_addr_fw_ver_addr, data, 4);
	printf("PANEL_VER : %X\n", data[0]);
	printf("FW_VER : %X\n", (data[1] << 8 | data[2]));

	ahb_reg_read(fw_addr_fw_cfg_addr, data, 4);
	printf("TOUCH_VER : %X\n", data[2]);
	printf("DISPLAY_VER : %X\n", data[3]);

//	ahb_reg_read(fw_addr_vid_pid_addr, data, 4);
//	printf("DEVICE VID : %X\n", data[0] << 8 | data[1]);
//	printf("DEVICE PID : %X\n", data[2] << 8 | data[3]);

	ahb_reg_read(fw_addr_fw_vendor_addr, data, 4);
	printf("CID_VER : %X\n", (data[2] << 8 | data[3]));

	ahb_reg_read(fw_addr_cus_info, data, 12);
	printf("Cusomer ID = %s\n", data);

	ahb_reg_read(fw_addr_proj_info, data, 12);
	printf("Project ID = %s\n", data);
}

int ahb_update_logic(HXFW *fw, DEVINFO *devp, OPTDATA *optp)
{
	int ret = 0;
	uint8_t tmp_data[4] = {0};
	uint32_t burnlen = 0;
	bool crc_pass = false;

	if (himax_scan_device(optp)) {
		printf("scan device fail\n");
		return -ENODEV;
	}

	// check communication with IC
	hx_buf[0] = ic_adr_conti;
	ret = hx_i2c_read(HX_DEFAULT_I2C_ADDR, hx_buf, 1, tmp_data, 1);
	if (ret < 0) {
		printf("communication check fail\n");
		ret = -EIO;
		goto exit;
	}

	ahb_reg_read(fw_addr_vid_pid_addr, tmp_data, 4);
	devp->vid = tmp_data[0] << 8 | tmp_data[1];
	printf("vid = %X\n", devp->vid);
	devp->pid = tmp_data[2] << 8 | tmp_data[3];
	printf("pid = %X\n", devp->pid);
	ahb_reg_read(fw_addr_fw_id_ver_addr, tmp_data, 4);
	printf("fwid = %X\n", tmp_data[0] << 8 | tmp_data[1]);
	printf("fwver = %X\n", tmp_data[2] << 8 | tmp_data[3]);

	if(is_opt_set(optp, OPTION_CMP_VER)) {
		if (!himax_update_check(fw)) {
			printf("don't need update\n");
			ret = 0;
			goto exit;
		}
	}

	if(is_opt_set(optp, OPTION_ALL_LEN))
		burnlen = fw->len;
	else
		burnlen = 0x3C000;

	printf("burn length is %d\n", burnlen);

//	himax_fw_update(fw.data, fw.len);
	if (himax_fw_update(fw->data, burnlen) == 0)
		crc_pass = true;


//	g_core_fp.fp_reload_disable(0);
	himax_parse_assign_cmd(driver_data_fw_define_flash_reload_en, tmp_data, 4);
	ahb_reg_write(driver_addr_fw_define_flash_reload, tmp_data, 4);

	ret = himax_power_on_init();
	if (!ret) {
		himax_read_fw_ver();
		ahb_reg_read(fw_addr_vid_pid_addr, tmp_data, 4);
		devp->vid = tmp_data[0] << 8 | tmp_data[1];
		printf("vid = %X\n", devp->vid);
		devp->pid = tmp_data[2] << 8 | tmp_data[3];
		printf("pid = %X\n", devp->pid);
		ahb_reg_read(fw_addr_fw_id_ver_addr, tmp_data, 4);
		printf("fwid = %X\n", tmp_data[0] << 8 | tmp_data[1]);
		printf("fwver = %X\n", tmp_data[2] << 8 | tmp_data[3]);
	}

	if (crc_pass && !ret) {
		printf("Firmware update succeed and reload done!\n");
	} else if (crc_pass && ret) {
		printf("Firmware update succeed but reload fail!\n");
		ret = 0;
	} else {
		printf("Firmware update failed!\n");
	}
exit:
	hx_close_i2c_device();

	return ret;
}

int show_fw_info(OPTDATA& opt_data)
{
	HXFW fw = {0};
	int ret;

	if (himax_load_fw(opt_data.fw_path, &fw)) {
		printf("load firmware fail\n");
		return -EIO;
	}
	// printf("Firmware file: %s loaded\n", opt_data.fw_path);
	if (fw.is_info_valid) {
		printf("Firmware Info:\n");
		printf("  IC ID: %s\n", fw.ic_id);
		printf("  IC sign A: %c\n", fw.ic_sign_a);
		printf("  Project: %s\n", fw.project);
		printf("  Customer: %s\n", fw.customer);
		printf("  Vendor ID: %04X\n", fw.vid);
		printf("  Product ID: %04X\n", fw.pid);
		printf("  CID Version: %04X\n", fw.cid);
		printf("  Firmware Version: %04X\n", fw.fw_ver);
		printf("  TP config Version: %02X\n", fw.tp_cfg_ver);
		printf("  Display config Version: %02X\n", fw.dd_cfg_ver);
	}

	himax_free_fw(&fw);

	return ret;
}

int burn_firmware(DEVINFO *devp, OPTDATA *optp)
{
	int ret = 0;
	int i = 0;
	HXFW fw = {0};

	if (!devp || !optp) {
		printf("%s: parameter error\n", __func__);
		return 1;
	}

	if (himax_load_fw(optp->fw_path, &fw)) {
		printf("load firmware fail\n");
		return 1;
	}

	do {
		ret = ahb_update_logic(&fw, devp, optp);
		if (ret == 0) {
			printf("Firmware update succeed!\n");
			break;
		}
		printf("Firmware update attempt %d failed, retrying...\n", i + 1);
	} while (i++ < 2);

	himax_free_fw(&fw);

	return ret;
}

int show_info(DEVINFO *devp, OPTDATA *optp)
{
	int ret = -1;
	uint8_t data[4];

	if (!devp || !optp) {
		fprintf(stderr, "%s: parameter fail\n", __func__);
		return ret;
	}

	if (himax_scan_device(optp))
		return ret;

//	ahb_reg_read(ic_adr_cs_central_state, data, 4);
//	if (data[0] != 0x05) {
//		printf("recovery mode\n");
//		goto exit;
//	}

//	if (optp->options & OPTION_PID) {
//		ahb_reg_read(fw_addr_vid_pid_addr, data, 4);
//		printf("%4X", data[2] << 8 | data[3]);
//	} else if (optp->options & OPTION_FW_VER) {
//		ahb_reg_read(fw_addr_fw_vendor_addr, data, 4);
//		printf("%04X", (data[2] << 8 | data[3]));
//	}

	ret = ahb_reg_read(fw_addr_fw_id_ver_addr, data, 4);
	if (ret)
		goto exit;

	if(is_opt_set(optp, OPTION_PID)) {
		printf("%04X", data[0] << 8 | data[1]);
	} else if(is_opt_set(optp, OPTION_FW_VER)) {
		printf("%04X", (data[2] << 8 | data[3]));
	}

	if(is_opt_set(optp, (OPTION_PID | OPTION_FW_VER))) {
		printf("\n");
		ret = 0;
		goto exit;
	}

	himax_read_fw_ver();

exit:
	hx_close_i2c_device();

	return ret;
}

int update_info_by_hid(DEVINFO& devp, OPTDATA& opt_data)
{
	int ret = -1;
	struct __attribute__((packed)) {
		uint8_t id;
		uint16_t length;
		hx_hid_info info;
	} hx_hid_info_data;
	uint8_t hx_hid_request_info_seq[] = {
        0x05, 0x00, 0x30 | HID_CFG_ID, 0x02, 0x06, 0x00
	};
	uint8_t possible_hid_i2c_addrs[] = { 0x41, 0x4f };
	bool read_success = false;

	if (himax_scan_device(&opt_data))
		return ret;

	if (opt_data.hid_i2c_addr != 0) {
		if (hid_i2c_read(opt_data.hid_i2c_addr, hx_hid_request_info_seq, sizeof(hx_hid_request_info_seq), (uint8_t *)&hx_hid_info_data, sizeof(hx_hid_info_data)) >= 0) {
			read_success = true;
		}
	} else {
		for (size_t i = 0; i < sizeof(possible_hid_i2c_addrs); i++) {
			if (hid_i2c_read(possible_hid_i2c_addrs[i], hx_hid_request_info_seq, sizeof(hx_hid_request_info_seq), (uint8_t *)&hx_hid_info_data, sizeof(hx_hid_info_data)) >= 0) {
				read_success = true;
				opt_data.hid_i2c_addr = possible_hid_i2c_addrs[i];
				break;
			}
		}
	}

	if (read_success) {
		memcpy(&opt_data.hid_info, &hx_hid_info_data.info, sizeof(hx_hid_info));
		opt_data.hid_info.cid = be16toh(opt_data.hid_info.cid);
		opt_data.hid_info.fw_ver = be16toh(opt_data.hid_info.fw_ver);
		opt_data.hid_info.vid = be16toh(opt_data.hid_info.vid);
		opt_data.hid_info.pid = be16toh(opt_data.hid_info.pid);
		opt_data.hid_info.yres = be16toh(opt_data.hid_info.yres);
		opt_data.hid_info.xres = be16toh(opt_data.hid_info.xres);
		opt_data.hid_info.pen_yres = be16toh(opt_data.hid_info.pen_yres);
		opt_data.hid_info.pen_xres = be16toh(opt_data.hid_info.pen_xres);
		opt_data.hid_info.flash_fw_size = be16toh(opt_data.hid_info.flash_fw_size);
		ret = 0;
	}

	hx_close_i2c_device();

	return ret;
}

size_t calculateMappingEntries(hx_hid_fw_unit_t* table, int totalSize)
{
	size_t actual_entries = 0;

	for (size_t i = 0; i < (totalSize / sizeof(hx_hid_fw_unit_t)); i++) {
		if (table[i].unit_sz != 0)
			actual_entries++;
		else
			break;
	}

	return actual_entries;
}

int show_info_by_hid(DEVINFO& devp, OPTDATA& opt_data)
{
	int ret = -1;
	struct __attribute__((packed)) {
		uint8_t id;
		uint16_t length;
		hx_hid_info info;
	} hx_hid_info_data;
	uint8_t hx_hid_request_info_seq[] = {
        0x05, 0x00, 0x30 | HID_CFG_ID, 0x02, 0x06, 0x00
	};

	if (himax_scan_device(&opt_data))
		return ret;

	if (hid_i2c_read(opt_data.hid_i2c_addr, hx_hid_request_info_seq, sizeof(hx_hid_request_info_seq), (uint8_t *)&hx_hid_info_data, sizeof(hx_hid_info_data)) < 0) {
		printf("read hid info fail\n");
		goto out;
	}

	hx_hid_info_data.info.cid = be16toh(hx_hid_info_data.info.cid);
	hx_hid_info_data.info.fw_ver = be16toh(hx_hid_info_data.info.fw_ver);
	hx_hid_info_data.info.vid = be16toh(hx_hid_info_data.info.vid);
	hx_hid_info_data.info.pid = be16toh(hx_hid_info_data.info.pid);
	hx_hid_info_data.info.yres = be16toh(hx_hid_info_data.info.yres);
	hx_hid_info_data.info.xres = be16toh(hx_hid_info_data.info.xres);
	hx_hid_info_data.info.pen_yres = be16toh(hx_hid_info_data.info.pen_yres);
	hx_hid_info_data.info.pen_xres = be16toh(hx_hid_info_data.info.pen_xres);
	hx_hid_info_data.info.flash_fw_size = be16toh(hx_hid_info_data.info.flash_fw_size);

	hx_printf("HID address: 0x%02x\n", opt_data.hid_i2c_addr);
	hx_printf("%s : %02X %02X\n", "passwd", hx_hid_info_data.info.passwd[0], hx_hid_info_data.info.passwd[1]);
	hx_printf("%s : %04X\n", "cid", hx_hid_info_data.info.cid);
	hx_printf("%s : %02X\n", "panel_ver", hx_hid_info_data.info.panel_ver);
	hx_printf("%s : %04X\n", "fw_ver", hx_hid_info_data.info.fw_ver);
	hx_printf("%s : %C\n", "ic_sign", hx_hid_info_data.info.ic_sign);
	hx_printf("%s : %s\n", "customer", hx_hid_info_data.info.customer);
	hx_printf("%s : %s\n", "project", hx_hid_info_data.info.project);
	hx_printf("%s : %s\n", "fw_major", hx_hid_info_data.info.fw_major);
	hx_printf("%s : %s\n", "fw_minor", hx_hid_info_data.info.fw_minor);
	hx_printf("%s : %s\n", "date", hx_hid_info_data.info.date);
	hx_printf("%s : %s\n", "ic_sign_2", hx_hid_info_data.info.ic_sign_2);
	hx_printf("%s : %04X\n", "vid", hx_hid_info_data.info.vid);
	hx_printf("%s : %04X\n", "pid", hx_hid_info_data.info.pid);
	// hx_printf("%s : %02X.%02X.%02X\n", "DD init version",
	// 		  hx_hid_info_data.info.dd_cfg_info.config_version[0],
	// 		  hx_hid_info_data.info.dd_cfg_info.config_version[1],
	// 		  hx_hid_info_data.info.dd_cfg_info.config_version[2]);
	hx_printf("%s : %02X\n", "Config version", hx_hid_info_data.info.cfg_version);
	hx_printf("%s : %02X\n", "Display version", hx_hid_info_data.info.disp_version);
	hx_printf("%s : %d\n", "RX", hx_hid_info_data.info.rx);
	hx_printf("%s : %d\n", "TX", hx_hid_info_data.info.tx);
	hx_printf("%s : %d\n", "YRES ", hx_hid_info_data.info.yres);
	hx_printf("%s : %d\n", "XRES", hx_hid_info_data.info.xres);
	hx_printf("%s : %d\n", "PT_NUM", hx_hid_info_data.info.pt_num);
	hx_printf("%s : %d\n", "MKEY_NUM", hx_hid_info_data.info.mkey_num);
	hx_printf("%s : %d\n", "PEN_NUM", hx_hid_info_data.info.pen_num);
	hx_printf("%s : %d\n", "PEN_YRES", hx_hid_info_data.info.pen_yres);
	hx_printf("%s : %d\n", "PEN_XRES", hx_hid_info_data.info.pen_xres);
	// hx_printf("%s : %02X\n", "LTDI_IC_NUM", hx_hid_info_data.info.ltdi_ic_num);
	hx_printf("%s : %d\n", "FlashFwSize", hx_hid_info_data.info.flash_fw_size);
	hx_printf("FW layout : \n");
	for (int i = 0; i < (int)calculateMappingEntries(hx_hid_info_data.info.main_mapping, sizeof(hx_hid_info_data.info.main_mapping)); i++)
		hx_printf("\t%2X - start : %08X, Size %d kB\n", \
			hx_hid_info_data.info.main_mapping[i].cmd, hx_hid_info_data.info.main_mapping[i].bin_start_offset * 1024, \
			hx_hid_info_data.info.main_mapping[i].unit_sz);
	if (calculateMappingEntries(&hx_hid_info_data.info.display_mapping, sizeof(hx_hid_info_data.info.display_mapping)) > 0)
		hx_printf("\t%2X - start : %08X, Size %d kB\n", \
			hx_hid_info_data.info.display_mapping.cmd, hx_hid_info_data.info.display_mapping.bin_start_offset * 1024, \
			hx_hid_info_data.info.display_mapping.unit_sz);
	hx_printf("\t%2X - start : %08X, Size %d kB\n", \
			hx_hid_info_data.info.bl_mapping.cmd, hx_hid_info_data.info.bl_mapping.bin_start_offset * 1024, \
			hx_hid_info_data.info.bl_mapping.unit_sz);
	memcpy(&opt_data.hid_info, &hx_hid_info_data.info, sizeof(hx_hid_info));
	if (!g_show_dbg_log)
		hx_printf("%s : %04X\n", "CID", hx_hid_info_data.info.cid);

out:
	hx_close_i2c_device();

	return ret;
}

int show_status(OPTDATA *optp)
{
	int ret = -1;

	if (!optp) {
		printf("%s: parameter fail\n", __func__);
		return ret;
	}

	if (himax_scan_device(optp))
		return ret;

	ret	= himax_read_fw_status();

	hx_close_i2c_device();

	return ret;
}


/*
 * Find the HID device directory name under /sys/bus/hid/devices
 * by matching BUS:VID:PID prefix.
 *
 * @bus: Linux HID bus id.
 * @vid: Vendor ID.
 * @pid: Product ID.
 * @device_name: Output buffer for matched device directory name.
 *
 * Return: 1 if found, 0 otherwise.
 */
int find_hid_dev_name(int bus, int vid, int pid, char *device_name)
{
	int ret = 0;
	struct dirent * dev_dir_entry;
	DIR * dev_dir;
	char device_ids[32];

	snprintf(device_ids, 15, "%04X:%04X:%04X", bus, vid, pid);

	dev_dir = opendir("/sys/bus/hid/devices");
	if (!dev_dir) {
		printf("open dev dir failed !\n");
		return 0;
	}

	while ((dev_dir_entry = readdir(dev_dir)) != NULL) {
		if (!strncmp(dev_dir_entry->d_name, device_ids, 14)) {
			strcpy(device_name, dev_dir_entry->d_name);
			ret = 1;
			break;
		}
	}
	closedir(dev_dir);

	return ret;
}

/*
 * Find the I2C device name associated with a given HID device directory.
 *
 * It scans /sys/bus/i2c/devices, resolves each symbolic link target,
 * and checks whether the target directory contains @hid_dev_name.
 * If matched, the corresponding I2C device directory name is copied to
 * @driver_name.
 *
 * @hid_dev_name: HID device directory name to match.
 * @driver_name: Output buffer for matched I2C device name.
 *
 * Return: 1 if found, 0 otherwise.
 */
int find_device_name(char *hid_dev_name, char *driver_name)
{
	char dev_path[] = "/sys/bus/i2c/devices/";

	struct dirent *devs_dir_entry;
	DIR *devs_dir;
	struct dirent *dev_dir_entry;
	DIR *dev_dir;
	int device_found = 0;
	ssize_t sz;
	char tmp_buf[256];
	char tmp_path[288];

	devs_dir = opendir(dev_path);
	if (!devs_dir) {
		printf("can open device path: %s\n", dev_path);
		return 0;
	}

	while ((devs_dir_entry = readdir(devs_dir)) != NULL) {
		if (devs_dir_entry->d_type != DT_LNK)
			continue;

		sz = readlinkat(dirfd(devs_dir), devs_dir_entry->d_name, tmp_buf, sizeof(tmp_buf) - 1);
		if (sz < 0)
			continue;

		tmp_buf[sz] = 0;

		snprintf(tmp_path, sizeof(tmp_path), "%s%s", dev_path, tmp_buf);
		dev_dir = opendir(tmp_path);
		if (!dev_dir)
			continue;

		while ((dev_dir_entry = readdir(dev_dir)) != NULL) {
			if (!strcmp(dev_dir_entry->d_name, hid_dev_name)) {
				strcpy(driver_name, devs_dir_entry->d_name);
				device_found = 1;
				break;
			}
		}
		closedir(dev_dir);

		if (device_found)
			break;
	}
	closedir(devs_dir);

	return device_found;
}

int write_devname_to_sys_attr(const char *attr, const char *action)
{
	int fd;
	ssize_t size;

	fd = open(attr, O_WRONLY);
	if (fd < 0) {
		printf("%s: open file error !", __func__);
		return 0;
	}

	for (;;) {
		size = write(fd, action, strlen(action));
		if (size < 0) {
			if (errno == EINTR)
				continue;

			close(fd);
			return 0;
		}
		break;
	}

	close(fd);

	return (size == (ssize_t) strlen(action));
}

int rebind_driver(DEVINFO *devp)
{
	int bus = 0x18;// i2c bus
	int vendor = devp->vid;
	int product = devp->pid;
	char hid_dev_name[64];
	char driver_path[64];
	char i2c_dev_name[64];
	char attr_str[128];

	printf("Start to rebind driver !\n");

	if (!find_hid_dev_name(bus, vendor, product, hid_dev_name)) {
		printf("Not found hid device: 0x%x:0x%x:0x%x\n", bus, vendor, product);
		return 1;
	}

	DIR* dir = opendir("/sys/bus/i2c/drivers/i2c_hid/");
	if (dir) {
		strcpy(driver_path, "/sys/bus/i2c/drivers/i2c_hid/");
		closedir(dir);
	} else {
		dir = opendir("/sys/bus/i2c/drivers/i2c_hid_acpi/");
		if (dir) {
			strcpy(driver_path, "/sys/bus/i2c/drivers/i2c_hid_acpi/");
			closedir(dir);
		} else {
			dir = opendir("/sys/bus/i2c/drivers/i2c_hid_of/");
			if (dir) {
				strcpy(driver_path, "/sys/bus/i2c/drivers/i2c_hid_of/");
				closedir(dir);
			} else {
				printf("No desire path exist!\n");
				return -EACCES;
			}
		}
	}

	if (!find_device_name(hid_dev_name, i2c_dev_name)) {
		printf("find device name failed %s\n", hid_dev_name);
		return 1;
	}

	snprintf(attr_str, sizeof(attr_str), "%s%s", driver_path, "unbind");

	if (!write_devname_to_sys_attr(attr_str, i2c_dev_name)) {
		printf("failed to unbind HID device %s %s\n", attr_str, i2c_dev_name);
		// return 1;
	} else {
		usleep(300000);
	}

	snprintf(attr_str, sizeof(attr_str), "%s%s", driver_path, "bind");

	if (!write_devname_to_sys_attr(attr_str, i2c_dev_name)) {
		printf("failed to bind HID device %s %s\n", attr_str, i2c_dev_name);
		return 1;
	}

	usleep(300000);

	printf("Rebind driver is done !\n");

	return 0;
}

int reg_read(OPTDATA& opt_data)
{
	int ret;
	uint8_t data[4] = {0};

	if (himax_scan_device(&opt_data) == 0) {
		ret = ahb_reg_read(opt_data.r_reg_addr.i, data, sizeof(data));
		if (ret == 0) {
			hx_printf("%s %08X:%08X\n", "Read done", *(uint32_t *)&(opt_data.r_reg_addr.b[0]), *(uint32_t *)&(data[0]));
		} else {
			hx_printf("%s %08X\n", "Read failed", *(uint32_t *)&(opt_data.r_reg_addr.b[0]));
		}
	} else {
		return -ENODEV;
	}
	hx_close_i2c_device();

	return ret;
}

int reg_write(OPTDATA& opt_data)
{
	int ret;
	if (himax_scan_device(&opt_data) == 0) {
		ret = ahb_reg_write(opt_data.w_reg_addr.i, opt_data.w_reg_data.b, opt_data.w_data_size);
		if (ret == 0) {
			hx_printf("%s %08X:%08X\n", "Write done", *(uint32_t *)&(opt_data.w_reg_addr.b[0]), *(uint32_t *)&(opt_data.w_reg_data.b[0]));
		} else {
			hx_printf("%s %08X:%08X\n", "Write failed", *(uint32_t *)&(opt_data.w_reg_addr.b[0]), *(uint32_t *)&(opt_data.w_reg_data.b[0]));
		}
	} else  {
		return -ENODEV;
	}
	hx_close_i2c_device();

	return ret;
}

static const hx_hid_fw_unit_t fw_main_121A[9] = {
	{
		.cmd = 0xA1,
		.bin_start_offset = 0,
		.unit_sz = 127,
	},
	{
		.cmd = 0xA2,
		.bin_start_offset = 129,
		.unit_sz = 111,
	},
};

static const hx_hid_fw_unit_t fw_bl_121A[1] = {
	{
		.cmd = 0xAB,
		.bin_start_offset = 240,
		.unit_sz = 12,
	},
};

static const hx_hid_fw_unit_t fw_main_102J[9] = {
	{
		.cmd = 0xA1,
		.bin_start_offset = 0,
		.unit_sz = 72,
	},
	{
		.cmd = 0xA2,
		.bin_start_offset = 72,
		.unit_sz = 72,
	},
	{
		.cmd = 0xA3,
		.bin_start_offset = 144,
		.unit_sz = 72,
	},
	{
		.cmd = 0xA4,
		.bin_start_offset = 216,
		.unit_sz = 24,
	},
};

static const hx_hid_fw_unit_t fw_bl_102J[1] = {
	{
		.cmd = 0xAB,
		.bin_start_offset = 240,
		.unit_sz = 12,
	},
};

#define TO_STRING(x)	#x
#define IC_SIGN_TO_CHAR(x)	TO_STRING(x)[0] \
							, TO_STRING(x)[1] \
							, TO_STRING(x)[2] \
							, TO_STRING(x)[3] \
							, TO_STRING(x)[4] \
							, TO_STRING(x)[5] \
							, TO_STRING(x)[6] \
							, TO_STRING(x)[7] \
							, TO_STRING(x)[8]

static const hx_ic_fw_layout_mapping_t g_ic_main_code_mapping_table[] = {
	{
		.ic_sign_2 = {IC_SIGN_TO_CHAR(HX83121-A)},
		.fw_table = &fw_main_121A[0],
		.table_sz = sizeof(fw_main_121A),
	},
	{
		.ic_sign_2 = {IC_SIGN_TO_CHAR(HX83102-J)},
		.fw_table = &fw_main_102J[0],
		.table_sz = sizeof(fw_main_102J),
	}
};

static const hx_ic_fw_layout_mapping_t g_ic_bl_code_mapping_table[] = {
	{
		.ic_sign_2 = {IC_SIGN_TO_CHAR(HX83121-A)},
		.fw_table = &fw_bl_121A[0],
		.table_sz = sizeof(fw_bl_121A),
	},
	{
		.ic_sign_2 = {IC_SIGN_TO_CHAR(HX83102-J)},
		.fw_table = &fw_bl_102J[0],
		.table_sz = sizeof(fw_bl_102J),
	}
};

int _hid_reg_write(uint32_t addr, uint32_t data)
{
	int ret;
	uint8_t reg_n_data[9];

	reg_n_data[0] = 0x1;// 1: write reg
	memcpy(reg_n_data + 1, &addr, 4);
	memcpy(reg_n_data + 5, &data, 4);

	ret = hx_hid_set_feature(HID_REG_RW_ID, reg_n_data, sizeof(reg_n_data));
	if (ret == 0) {
		hx_printf("%s %08X:%08X\n", "Write done", addr, data);
	} else {
		hx_printf("%s %08X:%08X\n", "Write failed", addr, data);
	}

	return ret;
}

int hid_reg_write(OPTDATA& opt_data)
{
	int ret;

	if (hx_scan_open_hidraw(opt_data) == 0) {
		ret = _hid_reg_write(opt_data.w_reg_addr.i, opt_data.w_reg_data.i);

		hx_hid_close();
		return ret;
	}

	return -ENODEV;
}

int _hid_reg_read(uint32_t addr, uint32_t* data)
{
	int ret;
	uint8_t reg_n_data[9] = {0};

	reg_n_data[0] = 0x0;// 0: read reg
	memcpy(reg_n_data + 1, &addr, 4);

	ret = hx_hid_set_feature(HID_REG_RW_ID, reg_n_data, sizeof(reg_n_data));
	if (ret == 0) {
		;//hx_printf("%s %08X:%08X\n", "Write done", *(uint32_t *)&(reg_n_data[1]), *(uint32_t *)&(reg_n_data[5]));
	} else {
		hx_printf("%s %08X\n", "Write failed", addr);
		return ret;
	}

	ret = hx_hid_get_feature(HID_REG_RW_ID, reg_n_data, sizeof(reg_n_data));
	if (ret == 0) {
		*data = *(uint32_t *)&(reg_n_data[5]);
	} else {
		hx_printf("%s %08X\n", "Read failed", addr);
	}

	return ret;
}

int hid_reg_read(OPTDATA& opt_data)
{
	int ret;
	uint32_t data;

	if (hx_scan_open_hidraw(opt_data) == 0) {
		ret = _hid_reg_read(opt_data.r_reg_addr.i, &data);
		if (ret == 0)
			hx_printf("%s %08X:%08X\n", "Read done", opt_data.r_reg_addr.i, data);
	} else {
		return -ENODEV;
	}
	hx_hid_close();

	return ret;
}

int hid_update_fw_info(OPTDATA& opt_data)
{
	hx_hid_ic_layout_header *layout_info = NULL;
	int layout_info_sz = 0;
	int ret = hx_hid_get_feature(HID_CFG_ID, (uint8_t *)&opt_data.hid_info, sizeof(opt_data.hid_info));
	if (ret != 0)
		opt_data.is_hid_info_valid = false;
	else
		opt_data.is_hid_info_valid = true;

	opt_data.hid_info.cid = be16toh(opt_data.hid_info.cid);
	opt_data.hid_info.fw_ver = be16toh(opt_data.hid_info.fw_ver);
	opt_data.hid_info.vid = be16toh(opt_data.hid_info.vid);
	opt_data.hid_info.pid = be16toh(opt_data.hid_info.pid);
	opt_data.hid_info.yres = be16toh(opt_data.hid_info.yres);
	opt_data.hid_info.xres = be16toh(opt_data.hid_info.xres);
	opt_data.hid_info.pen_yres = be16toh(opt_data.hid_info.pen_yres);
	opt_data.hid_info.pen_xres = be16toh(opt_data.hid_info.pen_xres);
	opt_data.hid_info.flash_fw_size = be16toh(opt_data.hid_info.flash_fw_size);

	layout_info_sz = hx_hid_get_size_by_id(HID_IC_LAYOUT_INFO_ID);
	if (layout_info_sz > 0) {
		layout_info = (hx_hid_ic_layout_header *)malloc(layout_info_sz);
		if (layout_info) {
			ret = hx_hid_get_feature(HID_IC_LAYOUT_INFO_ID, (uint8_t *)layout_info, layout_info_sz);
			if (ret == 0) {
				free(opt_data.hid_layout_info);
				opt_data.hid_layout_info = layout_info;
				opt_data.hid_layout_info_sz = layout_info_sz;
			} else {
				free(layout_info);
				layout_info = NULL;
			}
			// opt_data.hid_layout_info->ic_direction.desc.data[0] = 1;
			// opt_data.hid_layout_info->ic_direction.desc.data[1] = 1;
			// opt_data.hid_layout_info->total_tx_rx_ic_num.desc.layout.rx_num = 1;
			// opt_data.hid_layout_info->total_tx_rx_ic_num.desc.layout.tx_num = 2;
			// opt_data.hid_layout_info->total_tx_rx.desc.layout.rx_num = opt_data.hid_info.rx;
			// opt_data.hid_layout_info->total_tx_rx.desc.layout.tx_num = opt_data.hid_info.tx * 2;
		}
	} else {
		layout_info_sz = sizeof(hx_hid_ic_layout_header) + sizeof(hx_ic_layout_desc);
		layout_info = (hx_hid_ic_layout_header *)malloc(layout_info_sz);
		memset(layout_info, 0, layout_info_sz);
		layout_info->all_ic_num.desc_type = IC_LAYOUT_DESC_TYPE_ALL_IC_NUM;
		layout_info->all_ic_num.desc.data[0] = 1;
		layout_info->ic_direction.desc_type = IC_LAYOUT_DESC_TYPE_IC_DIRECTION;
		layout_info->total_tx_rx_ic_num.desc_type = IC_LAYOUT_DESC_TYPE_TOTAL_TX_RX_IC_NUM;
		layout_info->total_tx_rx_ic_num.desc.layout.rx_num = 1;
		layout_info->total_tx_rx_ic_num.desc.layout.tx_num = 1;
		layout_info->total_tx_rx.desc_type = IC_LAYOUT_DESC_TYPE_TOTAL_TX_RX;
		layout_info->total_tx_rx.desc.layout.rx_num = opt_data.hid_info.rx;
		layout_info->total_tx_rx.desc.layout.tx_num = opt_data.hid_info.tx;
		layout_info->ic_tx_rx[0].desc_type = IC_LAYOUT_DESC_TYPE_MASTER_TX_RX;
		layout_info->ic_tx_rx[0].desc.layout.rx_num = opt_data.hid_info.rx;
		layout_info->ic_tx_rx[0].desc.layout.tx_num = opt_data.hid_info.tx;
		opt_data.hid_layout_info = layout_info;
		opt_data.hid_layout_info_sz = layout_info_sz;
	}
	if (layout_info)
		opt_data.hid_layout_type = get_layout_type(layout_info);

	return ret;
}

int hid_show_fw_info(OPTDATA& opt_data)
{
	int ret;
	hx_hid_info info;
	hx_hid_ic_layout_header *layout_info = NULL;
	hx_ic_layout_desc *desc = NULL;
	int layout_info_sz = 0;

	if (hx_scan_open_hidraw(opt_data) == 0) {
		if (hx_hid_parse_RD_for_idsz(opt_data) < 0) {
			printf("parse hid RD fail\n");
			hx_hid_close();
			return -EIO;
		}
		ret = hx_hid_get_feature(HID_CFG_ID, (uint8_t *)&info, sizeof(info));
		if (ret == 0) {
			info.cid = be16toh(info.cid);
			info.fw_ver = be16toh(info.fw_ver);
			info.vid = be16toh(info.vid);
			info.pid = be16toh(info.pid);
			info.yres = be16toh(info.yres);
			info.xres = be16toh(info.xres);
			info.pen_yres = be16toh(info.pen_yres);
			info.pen_xres = be16toh(info.pen_xres);
			info.flash_fw_size = be16toh(info.flash_fw_size);
			memcpy(&opt_data.hid_info, &info, sizeof(info));
			opt_data.is_hid_info_valid = true;
			if (is_opt_set(&opt_data, OPTION_HID_SHOW_PID_BY_HID_INFO)) {
				printf("%04X\n", opt_data.hid_info.pid);
			} else if (is_opt_set(&opt_data, OPTION_HID_SHOW_FW_VER_BY_HID_INFO)) {
				printf("%04X\n", opt_data.hid_info.cid);
			} else {
				printf("%s : %02X %02X\n", "passwd", info.passwd[0], info.passwd[1]);
				printf("%s : %04X\n", "cid", opt_data.hid_info.cid);
				printf("%s : %02X\n", "panel_ver", info.panel_ver);
				printf("%s : %04X\n", "fw_ver", opt_data.hid_info.fw_ver);
				printf("%s : %C\n", "ic_sign", info.ic_sign);
				printf("%s : %s\n", "customer", info.customer);
				printf("%s : %s\n", "project", info.project);
				printf("%s : %s\n", "fw_major", info.fw_major);
				printf("%s : %s\n", "fw_minor", info.fw_minor);
				printf("%s : %s\n", "date", info.date);
				printf("%s : %s\n", "ic_sign_2", info.ic_sign_2);
				printf("%s : %04X\n", "vid", opt_data.hid_info.vid);
				printf("%s : %04X\n", "pid", opt_data.hid_info.pid);
				// printf("%s : %02X.%02X.%02X\n", "DD init code version",
				// 			info.dd_cfg_info.config_version[0], info.dd_cfg_info.config_version[1],	info.dd_cfg_info.config_version[2]);
				printf("%s : %02X\n", "Config version", info.cfg_version);
				printf("%s : %02X\n", "Display version", info.disp_version);
				printf("%s : %d\n", "RX", info.rx);
				printf("%s : %d\n", "TX", info.tx);
				printf("%s : %d\n", "YRES ", info.yres);
				printf("%s : %d\n", "XRES", info.xres);
				printf("%s : %d\n", "PT_NUM", info.pt_num);
				printf("%s : %d\n", "MKEY_NUM", info.mkey_num);
				printf("%s : %d\n", "PEN_NUM", info.pen_num);
				printf("%s : %d\n", "PEN_YRES", info.pen_yres);
				printf("%s : %d\n", "PEN_XRES", info.pen_xres);
				// printf("%s : %02X\n", "LTDI_IC_NUM", info.ltdi_ic_num);
				printf("%s : %d\n", "FlashFwSize", info.flash_fw_size);
				printf("FW layout : \n");
				for (int i = 0; i < (int)calculateMappingEntries(info.main_mapping, sizeof(info.main_mapping)); i++)
					printf("\t%2X - start : %08X, Size %d kB\n", \
						info.main_mapping[i].cmd, info.main_mapping[i].bin_start_offset * 1024, \
						info.main_mapping[i].unit_sz);
				if (calculateMappingEntries(&info.display_mapping, sizeof(info.display_mapping)) > 0)
					printf("\t%2X - start : %08X, Size %d kB\n", \
						info.display_mapping.cmd, info.display_mapping.bin_start_offset * 1024, \
						info.display_mapping.unit_sz);
				printf("\t%2X - start : %08X, Size %d kB\n", \
						info.bl_mapping.cmd, info.bl_mapping.bin_start_offset * 1024, \
						info.bl_mapping.unit_sz);

				layout_info_sz = hx_hid_get_size_by_id(HID_IC_LAYOUT_INFO_ID);
				if (layout_info_sz > 0) {
					layout_info = (hx_hid_ic_layout_header *)malloc(layout_info_sz);
					if (layout_info) {
						ret = hx_hid_get_feature(HID_IC_LAYOUT_INFO_ID, (uint8_t *)layout_info, layout_info_sz);
						if (ret == 0) {
							if (opt_data.hid_layout_info)
								free(opt_data.hid_layout_info);

							printf("IC layout info : \n");
							size_t ic_num = layout_info->all_ic_num.desc.data[0];
							// printf("    Header          : %02X %02X %02X\n", layout_info->header.desc_type, layout_info->header.desc.data[0], layout_info->header.desc.data[1]);
							printf("    All IC Num.        : %d\n", layout_info->all_ic_num.desc.data[0]);
							printf("    Master IC location : %s-%s\n",
							layout_info->ic_direction.desc.data[0]?"LEFT":"RIGHT",
							layout_info->ic_direction.desc.data[1]?"TOP":"BOTTOM");
							printf("    Total IC Num.      : RX: %d, TX: %d\n", layout_info->total_tx_rx_ic_num.desc.data[0], layout_info->total_tx_rx_ic_num.desc.data[1]);
							printf("    Total RX TX Num.   : RX CH: %d, TX CH: %d\n", layout_info->total_tx_rx.desc.data[0], layout_info->total_tx_rx.desc.data[1]);
							for (int i = 0; i < (int)ic_num; i++) {
								desc = &layout_info->ic_tx_rx[i];
								if (i == 0)
									printf("    Master RX TX Num.  : RX CH: %d, TX CH: %d\n", desc->desc.layout.rx_num, desc->desc.layout.tx_num);
								else
									printf("    Slave %1d RX TX Num. : RX CH: %d, TX CH: %d\n", i, desc->desc.layout.rx_num, desc->desc.layout.tx_num);
							}
							opt_data.hid_layout_info = layout_info;
							opt_data.hid_layout_info_sz = layout_info_sz;
							opt_data.hid_layout_type = get_layout_type(layout_info);
						} else {
							hx_printf("Failed to get IC layout info from HID\n");
							free(layout_info);
							layout_info = NULL;
							hx_hid_close();
							return -EIO;
						}
					} else {
						hx_printf("Memory allocation for layout info failed(request size: %d)\n", layout_info_sz);
					}
				} else {
					hx_printf("No layout info found from HID, use default layout\n");
					layout_info_sz = sizeof(hx_hid_ic_layout_header) + sizeof(hx_ic_layout_desc);
					layout_info = (hx_hid_ic_layout_header *)malloc(layout_info_sz);
					memset(layout_info, 0, layout_info_sz);
					layout_info->all_ic_num.desc_type = IC_LAYOUT_DESC_TYPE_ALL_IC_NUM;
					layout_info->all_ic_num.desc.data[0] = 1;
					layout_info->ic_direction.desc_type = IC_LAYOUT_DESC_TYPE_IC_DIRECTION;
					layout_info->total_tx_rx_ic_num.desc_type = IC_LAYOUT_DESC_TYPE_TOTAL_TX_RX_IC_NUM;
					layout_info->total_tx_rx_ic_num.desc.layout.rx_num = 1;
					layout_info->total_tx_rx_ic_num.desc.layout.tx_num = 1;
					layout_info->total_tx_rx.desc_type = IC_LAYOUT_DESC_TYPE_TOTAL_TX_RX;
					layout_info->total_tx_rx.desc.layout.rx_num = info.rx;
					layout_info->total_tx_rx.desc.layout.tx_num = info.tx;
					layout_info->ic_tx_rx[0].desc_type = IC_LAYOUT_DESC_TYPE_MASTER_TX_RX;
					layout_info->ic_tx_rx[0].desc.layout.rx_num = info.rx;
					layout_info->ic_tx_rx[0].desc.layout.tx_num = info.tx;
					opt_data.hid_layout_info = layout_info;
					opt_data.hid_layout_info_sz = layout_info_sz;
					opt_data.hid_layout_type = get_layout_type(layout_info);
				}
			}
		}

		hx_hid_close();
		return 0;
	} else {
		return -ENODEV;
	}
}

int hid_show_version(OPTDATA& opt_data)
{
	int ret;

	if (hx_scan_open_hidraw(opt_data) == 0) {
		// ret = hx_hid_get_feature(HID_CFG_ID, (uint8_t *)&info, 255);
		ret = hid_update_fw_info(opt_data);
		if (ret == 0) {
			printf("%s : %02X %02X\n", "vid", opt_data.hid_info.vid >> 8, opt_data.hid_info.vid & 0xFF);
			printf("%s : %02X %02X\n", "pid", opt_data.hid_info.pid >> 8, opt_data.hid_info.pid & 0xFF);
			printf("%s : %02X %02X\n", "firmware verison", opt_data.hid_info.cid >> 8, opt_data.hid_info.cid & 0xFF);
		}

		hx_hid_close();
		return 0;
	} else {
		return -ENODEV;
	}
}

int hid_core_update_logic(HXFW *hxfw, OPTDATA& opt_data, DEVINFO& dinfo, uint8_t uCmd,
						  hx_hid_fw_unit_t *fw_entry_table, size_t fw_units_sz,
						  const hx_ic_fw_layout_mapping_t *fallback_mapping_table, size_t fallback_table_sz,
						  int& lastError)
{
	bool bGoUpdate = false;
	bool bHandshakePresent = false;
	bool useFwInfoEntries = false;
	time_t start, now;
	uint8_t recevied_data[2] = {0};
	int nDataRecevied = 0;
	const uint32_t pollingInterval = 300;
	uint32_t writeSize;
	uint32_t fwStartLoc;
	uint32_t outputTimes;
	int fw_entries = 0;
	int sz;
	lastError = FWUP_ERROR_NO_ERROR;

	sz = hx_hid_get_size_by_id(HID_FW_UPDATE_ID);
	bHandshakePresent = (hx_hid_get_size_by_id(HID_FW_UPDATE_HANDSHAKING_ID) == 1)?true:false;
	if ((sz > 0) && bHandshakePresent) {
		if (opt_data.is_hid_info_valid) {
			fw_entries = calculateMappingEntries(fw_entry_table, fw_units_sz);
			if (fw_entries > 0)
				useFwInfoEntries = true;
		}

		if (!useFwInfoEntries && opt_data.is_hid_info_valid && fallback_mapping_table && fallback_table_sz > 0) {
			for (size_t i = 0; i < fallback_table_sz; i++) {
				if (memcmp(fallback_mapping_table[i].ic_sign_2, opt_data.hid_info.ic_sign_2, sizeof(opt_data.hid_info.ic_sign_2)) == 0) {
					fw_entries = calculateMappingEntries((hx_hid_fw_unit_t *)fallback_mapping_table[i].fw_table, fallback_mapping_table[i].table_sz);
					fw_entry_table = (hx_hid_fw_unit_t *)fallback_mapping_table[i].fw_table;
					break;
				}
			}
		}

		if (!is_opt_set(&opt_data, OPTION_FORCE_UPDATE)) {
			if (opt_data.is_hid_info_valid)
				bGoUpdate = himax_update_check(hxfw, &opt_data.hid_info);
			else
				bGoUpdate = false;
		} else {
			if (fw_entries == 0) {
				if (fallback_mapping_table && fallback_table_sz > 0) {
					fw_entries = calculateMappingEntries((hx_hid_fw_unit_t *)fallback_mapping_table[0].fw_table, fallback_mapping_table[0].table_sz);
					fw_entry_table = (hx_hid_fw_unit_t *)fallback_mapping_table[0].fw_table;
				} else {
					hx_printf("No valid firmware layout info found, can't continue update!\n");
					lastError = FWUP_ERROR_NO_DEVICE;
					return -EIO;
				}
			}
			bGoUpdate = true;
		}

		if (bGoUpdate && (fw_entries > 0)) {
			uint8_t cmd = 0;
			if(hx_hid_get_feature(HID_FW_UPDATE_HANDSHAKING_ID, &cmd, 1) == 0)
				hx_printf("ID %02X read %02X\n", HID_FW_UPDATE_HANDSHAKING_ID, cmd);
			unlock_flash(ACCESS_HID);
			cmd = uCmd;
			if (hx_hid_set_feature(HID_FW_UPDATE_HANDSHAKING_ID, &cmd, 1) != 0) {
				hx_printf("Initial HID FW update failed!\n");
				lastError = FWUP_ERROR_INITIAL;
				return -EIO;
			} else {
				hx_printf("Initializing HID FW update....\n");
				usleep(100 * 1000);
				unlock_flash(ACCESS_HID);
			}
			for (int i = 0; i < fw_entries; i++) {
				start = time(NULL);
POLL_AGAIN:
				cmd = fw_entry_table[i].cmd;
				if (!pollingForResult(HID_FW_UPDATE_HANDSHAKING_ID, &cmd, 1, pollingInterval, 7,
					recevied_data, &nDataRecevied)) {
					if (nDataRecevied > 0) {
						if ((recevied_data[0] == FWUP_ERROR_MCU_A0)||(recevied_data[0] == FWUP_ERROR_MCU_00)) {
							now = time(NULL);
							if (now - start >= 7) {
								lastError = recevied_data[0];
								goto POLL_FAILED;
							}
							usleep(pollingInterval * 1000);
							goto POLL_AGAIN;
						} else if (recevied_data[0] == FWUP_ERROR_NO_BL) {
							hx_printf("Can't update Main code due to no Bootloader(0x%02X)!\n", recevied_data[0]);
						} else if (recevied_data[0] == FWUP_ERROR_NO_MAIN) {
							hx_printf("Can't update Bootloader due to no Main code(0x%02X)!\n", recevied_data[0]);
						}
						hx_printf("polling for 0x%X, but result(0x%X) not expected!\n", cmd, recevied_data[0]);
						lastError = recevied_data[0];
						return -EIO;
					}
POLL_FAILED:
					hx_printf("Polling for 0x%X timeout!\n", cmd);
					lastError = FWUP_ERROR_POLLING_TIMEOUT;
					return -EIO;
				}
				writeSize = fw_entry_table[i].unit_sz * 1024;
				fwStartLoc = fw_entry_table[i].bin_start_offset * 1024;
				outputTimes = writeSize / sz;
				for (uint32_t i = 0; i < outputTimes; i++) {
					hx_printf("[new]Sending trunk %d/%d of %d kb\r", i + 1, outputTimes, writeSize / 1024);
					// if (hx_hid_set_output(HID_FW_UPDATE_ID, 1, hxfw.data + fwStartLoc + i * sz, sz) != 0) {
					if (hx_hid_set_feature(HID_FW_UPDATE_ID, hxfw->data + fwStartLoc + i * sz, sz) != 0) {
						// cmd failed, go out
						hx_printf("send firmware trunk: %d/%d of %d kb failed!\n", i + 1, outputTimes, writeSize);
						lastError = FWUP_ERROR_FW_TRANSFER;
						return -EIO;
					}
					usleep(100);
				}
				hx_printf("\n");
			}
			cmd = 0xB1;
			if (!pollingForResult(HID_FW_UPDATE_HANDSHAKING_ID, &cmd, 1, pollingInterval, 30,
				 recevied_data, &nDataRecevied)) {
				if (nDataRecevied > 0) {
					hx_printf("polling for 0xB1, but result(0x%X) not expected!\n", recevied_data[0]);
					if (recevied_data[0] == FWUP_ERROR_BL) {
						hx_printf("Update failed\n");
					} else if (recevied_data[0] == FWUP_ERROR_PW) {
						hx_printf("Update failed, reason PW\n");
					} else if (recevied_data[0] == FWUP_ERROR_ERASE_FLASH) {
						hx_printf("Update failed, reason erase flash\n");
					} else if (recevied_data[0] == FWUP_ERROR_FLASH_PROGRAMMING) {
						hx_printf("Update failed, flash programming\n");
					}
					lastError = recevied_data[0];
					return -EIO;
				}
				hx_printf("Polling for B1 timeout!\n");
				lastError = FWUP_ERROR_POLLING_TIMEOUT;
				return -EIO;
			} else {
				hx_printf("Update succeed!\n");
				usleep(500 * 1000);
				opt_data.options |= OPTION_REBIND;
				dinfo.pid = opt_data.pid;
				dinfo.vid = opt_data.vid;
				lastError = FWUP_ERROR_NO_ERROR;
			}
		} else {
			hx_printf("Version identical, update no go!\n");
			return 1;
		}
	}

	return 0;
}

int hid_main_update(OPTDATA& opt_data, DEVINFO& dinfo, int& lastError)
{
	HXFW hxfw = {0};
	int ret = 0;

	if (himax_load_fw(opt_data.fw_path, &hxfw) != 0) {
		ret = -ENODATA;
		lastError = FWUP_ERROR_LOAD_FW_BIN;
		goto LOAD_FW_FAILED;
	}

	ret = hx_scan_open_hidraw(opt_data);
	if (ret != 0) {
		printf("Failed to open hidraw device!\n");
		goto HID_PREPARE_FAILED;
	}

	ret = hx_hid_parse_RD_for_idsz(opt_data);
	if (ret != 0) {
		printf("Failed to parse hidraw RD for id and size!\n");
		hx_hid_close();
		goto HID_PREPARE_FAILED;
	}

	ret = hid_update_fw_info(opt_data);
	if (ret != 0) {
		printf("Failed to get FW info before update!\n");
	}

	ret = hid_core_update_logic(&hxfw, opt_data, dinfo, UPDATE_CMD_MAIN, opt_data.hid_info.main_mapping, sizeof(opt_data.hid_info.main_mapping),
								g_ic_main_code_mapping_table, sizeof(g_ic_main_code_mapping_table), lastError);

	hx_hid_close();
HID_PREPARE_FAILED:
	himax_free_fw(&hxfw);
LOAD_FW_FAILED:

	return ret;
}

/*
int hid_bl_update_logic(HXFW *hxfw, OPTDATA& opt_data, DEVINFO& dinfo, int& lastError)
{
	hx_hid_info oinfo;
	bool bOinfoValid = false;
	bool bGoUpdate = false;
	time_t start, now;
	uint8_t recevied_data[2] = {0};
	int nDataRecevied = 0;
	const uint32_t pollingInterval = 10;
	uint32_t writeSize;
	uint32_t fwStartLoc;
	uint32_t outputTimes;
	const uint8_t bl_update_cmd = 0x77;
	int fw_entries = 0;
	hx_hid_fw_unit_t* fw_entry_table = NULL;
	lastError = FWUP_ERROR_NO_ERROR;

	int sz = hx_hid_get_size_by_id(HID_FW_UPDATE_ID);
	bool bHandshakePresent = (hx_hid_get_size_by_id(HID_FW_UPDATE_HANDSHAKING_ID) == 1)?true:false;
	if ((sz > 0) && bHandshakePresent) {
		bGoUpdate = true;
		bool useFwInfoEntries = true;
		if (hx_hid_get_feature(HID_CFG_ID, (uint8_t *)&oinfo, 255) == 0) {
			fw_entries = calculateMappingEntries(&oinfo.bl_mapping, sizeof(oinfo.bl_mapping));
			if (fw_entries > 0) {
				useFwInfoEntries = true;
				fw_entry_table = &oinfo.bl_mapping;
			}
			bOinfoValid = true;
		} else {
			bOinfoValid = false;
			useFwInfoEntries = false;
		}
		if (!useFwInfoEntries && bOinfoValid) {
			for (size_t i = 0; i < sizeof(g_ic_bl_code_mapping_table)/sizeof(hx_ic_fw_layout_mapping_t); i++) {
				if (memcmp(g_ic_bl_code_mapping_table[i].ic_sign_2, oinfo.ic_sign_2, sizeof(oinfo.ic_sign_2)) == 0) {
					fw_entries = calculateMappingEntries((hx_hid_fw_unit_t *)g_ic_bl_code_mapping_table[i].fw_table, sizeof(hx_hid_fw_unit_t)* 1);
					fw_entry_table = (hx_hid_fw_unit_t *)g_ic_bl_code_mapping_table[i].fw_table;
					break;
				}
			}
		}
		if (fw_entries == 0) {
			fw_entries = calculateMappingEntries((hx_hid_fw_unit_t *)fw_bl_121A, sizeof(hx_hid_fw_unit_t)* 1);
			fw_entry_table = (hx_hid_fw_unit_t *)fw_bl_121A;
		}
		if (bGoUpdate) {
			uint8_t cmd = 0;
			if(hx_hid_get_feature(HID_FW_UPDATE_HANDSHAKING_ID, &cmd, 1) == 0)
				hx_printf("ID %02X read %02X\n", HID_FW_UPDATE_HANDSHAKING_ID, cmd);
			unlock_flash(ACCESS_HID);
			cmd = bl_update_cmd;
			if (hx_hid_set_feature(HID_FW_UPDATE_HANDSHAKING_ID, &cmd, 1) != 0) {
				hx_printf("Initial HID FW update failed!\n");
				lastError = FWUP_ERROR_INITIAL;
				return -EIO;
			} else {
				hx_printf("Initializing HID FW update....\n");
				// usleep(1500 * 1000);
				usleep(100 * 1000);
				unlock_flash(ACCESS_HID);
			}
			for (int i = 0; i < fw_entries; i++) {
				start = time(NULL);

POLL_BL_AGAIN:
				cmd = fw_entry_table[i].cmd;
				if (!pollingForResult(HID_FW_UPDATE_HANDSHAKING_ID, &cmd, 1, pollingInterval, 7,
					recevied_data, &nDataRecevied)) {
					if (nDataRecevied > 0) {
						if ((recevied_data[0] == FWUP_ERROR_MCU_A0)||(recevied_data[0] == FWUP_ERROR_MCU_00)) {
							now = time(NULL);
							if (now - start >= 7) {
								lastError = recevied_data[0];
								goto POLL_BL_FAILED;
							}
							usleep(pollingInterval * 1000);
							goto POLL_BL_AGAIN;
						} else if (recevied_data[0] == FWUP_ERROR_NO_BL) {
							hx_printf("Can't update Main code due to no Bootloader(0x%02X)!\n", recevied_data[0]);
						} else if (recevied_data[0] == FWUP_ERROR_NO_MAIN) {
							hx_printf("Can't update Bootloader due to no Main code(0x%02X)!\n", recevied_data[0]);
						}
						hx_printf("polling for 0x%X, but result(0x%X) not expected!\n", cmd, recevied_data[0]);
						lastError = recevied_data[0];
						return -EIO;
					}
POLL_BL_FAILED:
					hx_printf("Polling for 0x%X timeout!\n", cmd);
					lastError = FWUP_ERROR_POLLING_TIMEOUT;
					return -EIO;
				}
				writeSize = fw_entry_table[i].unit_sz * 1024;
				fwStartLoc = fw_entry_table[i].bin_start_offset * 1024;
				outputTimes = writeSize / sz;
				for (uint32_t i = 0; i < outputTimes; i++) {
					hx_printf("[new]Sending trunk %d/%d of %d kb\r", i + 1, outputTimes, writeSize / 1024);
					// if (hx_hid_set_output(HID_FW_UPDATE_ID, 1, hxfw.data + fwStartLoc + i * sz, sz) != 0) {
					if (hx_hid_set_feature(HID_FW_UPDATE_ID, hxfw->data + fwStartLoc + i * sz, sz) != 0) {
						// cmd failed, go out
						hx_printf("send firmware trunk: %d/%d of %d kb failed!\n", i + 1, outputTimes, writeSize);
						lastError = FWUP_ERROR_FW_TRANSFER;
						return -EIO;
					}
					usleep(100);
				}
				hx_printf("\n");
			}
			cmd = 0xB1;
			if (!pollingForResult(HID_FW_UPDATE_HANDSHAKING_ID, &cmd, 1, pollingInterval, 30,
				 recevied_data, &nDataRecevied)) {
				if (nDataRecevied > 0) {
					hx_printf("polling for 0xB1, but result(0x%X) not expected!\n", recevied_data[0]);
					if (recevied_data[0] == FWUP_ERROR_BL) {
						hx_printf("Update failed\n");
					} else if (recevied_data[0] == FWUP_ERROR_PW) {
						hx_printf("Update failed, wrong PW\n");
					} else if (recevied_data[0] == FWUP_ERROR_ERASE_FLASH) {
						hx_printf("Update failed, erase flash\n");
					} else if (recevied_data[0] == FWUP_ERROR_FLASH_PROGRAMMING) {
						hx_printf("Update failed, flash programming\n");
					}
					lastError = recevied_data[0];
					return -EIO;
				}
				hx_printf("Polling for B1 timeout!\n");
				lastError = FWUP_ERROR_POLLING_TIMEOUT;
				return -EIO;
			} else {
				hx_printf("Bootloader update succeed!\n");
				usleep(500 * 1000);
				opt_data.options |= OPTION_REBIND;
				dinfo.pid = opt_data.pid;
				dinfo.vid = opt_data.vid;
				lastError = FWUP_ERROR_NO_ERROR;
			}
		}
	}

	return 0;
}
*/

int hid_bl_update(OPTDATA& opt_data, DEVINFO& dinfo, int& lastError)
{
	HXFW hxfw = {0};
	int ret = 0;

	if (himax_load_fw(opt_data.fw_path, &hxfw) != 0) {
		ret = -ENODATA;
		lastError = FWUP_ERROR_LOAD_FW_BIN;
		goto LOAD_FW_FAILED;
	}

	ret = hx_scan_open_hidraw(opt_data);
	if (ret != 0) {
		printf("Failed to open hidraw device!\n");
		goto HID_PREPARE_FAILED;
	}

	ret = hx_hid_parse_RD_for_idsz(opt_data);
	if (ret != 0) {
		printf("Failed to parse hidraw RD for id and size!\n");
		hx_hid_close();
		goto HID_PREPARE_FAILED;
	}

	ret = hid_update_fw_info(opt_data);
	if (ret != 0) {
		printf("Failed to get FW info before update!\n");
	}

	ret = hid_core_update_logic(&hxfw, opt_data, dinfo, UPDATE_CMD_BL, &opt_data.hid_info.bl_mapping, sizeof(opt_data.hid_info.bl_mapping),
								g_ic_bl_code_mapping_table, sizeof(g_ic_bl_code_mapping_table), lastError);

	hx_hid_close();
HID_PREPARE_FAILED:
	himax_free_fw(&hxfw);
LOAD_FW_FAILED:

	return ret;
}

int hid_dd_update(OPTDATA& opt_data, DEVINFO& dinfo, int& lastError)
{
	HXFW hxfw = {0};
	int ret = 0;

	if (himax_load_fw(opt_data.fw_path, &hxfw) != 0) {
		ret = -ENODATA;
		lastError = FWUP_ERROR_LOAD_FW_BIN;
		goto LOAD_FW_FAILED;
	}

	ret = hx_scan_open_hidraw(opt_data);
	if (ret != 0) {
		printf("Failed to open hidraw device!\n");
		goto HID_PREPARE_FAILED;
	}

	ret = hx_hid_parse_RD_for_idsz(opt_data);
	if (ret != 0) {
		printf("Failed to parse hidraw RD for id and size!\n");
		hx_hid_close();
		goto HID_PREPARE_FAILED;
	}

	ret = hid_update_fw_info(opt_data);
	if (ret != 0) {
		printf("Failed to get FW info before update!\n");
	}

	if (opt_data.is_hid_info_valid) {
		if (opt_data.hid_info.display_mapping.cmd != 0xAD) {
			printf("No display mapping in FW layout, can't continue update!\n");
			lastError = FWUP_ERROR_FW_INFO_INVALID;
			hx_hid_close();
			goto HID_PREPARE_FAILED;
		} else if (opt_data.hid_info.display_mapping.unit_sz * 1024 != hxfw.len) {
			printf("Display rom size in firmware info is different from actual firmware size, can't continue update!\n");
			lastError = FWUP_ERROR_FW_SIZE_MISMATCH;
			hx_hid_close();
			goto HID_PREPARE_FAILED;
		}
	}

	ret = hid_core_update_logic(&hxfw, opt_data, dinfo, UPDATE_CMD_DD, &opt_data.hid_info.display_mapping, sizeof(opt_data.hid_info.display_mapping),
								NULL, 0, lastError);

	hx_hid_close();
HID_PREPARE_FAILED:
	himax_free_fw(&hxfw);
LOAD_FW_FAILED:

	return ret;
}

int hid_fw_update_logic(HXFW *hxfw, OPTDATA& opt_data, DEVINFO& dinfo, int& lastError)
{
	int ret;

	ret = hid_core_update_logic(hxfw, opt_data, dinfo, UPDATE_CMD_MAIN, opt_data.hid_info.main_mapping, sizeof(opt_data.hid_info.main_mapping),
								g_ic_main_code_mapping_table, sizeof(g_ic_main_code_mapping_table), lastError);
	if (ret == 0) {
		usleep(100 * 1000);
		ret = hid_core_update_logic(hxfw, opt_data, dinfo, UPDATE_CMD_BL, &opt_data.hid_info.bl_mapping, sizeof(opt_data.hid_info.bl_mapping),
									g_ic_bl_code_mapping_table, sizeof(g_ic_bl_code_mapping_table), lastError);
		if (ret < 0) {
			printf("BL code update failed after Main update!\n");
		} else if (ret > 0) {
			printf("Main code version identical, no need to update!\n");
			ret = 0;
		} else {
			printf("BL code update succeed after Main update!\n");
			ret = 0;
		}
	} else if (lastError == FWUP_ERROR_NO_BL) {
		printf("No Bootloader found(Main ok), try to update Bootloader first!\n");
		ret = hid_core_update_logic(hxfw, opt_data, dinfo, UPDATE_CMD_BL, &opt_data.hid_info.bl_mapping, sizeof(opt_data.hid_info.bl_mapping),
									g_ic_bl_code_mapping_table, sizeof(g_ic_bl_code_mapping_table), lastError);
		if (ret < 0) {
			printf("Bootloader update failed! Update main is risky, aborting!\n");
			return ret;
		}
		// ret = hid_main_update_logic(hxfw, opt_data, dinfo, lastError);
		ret = hid_core_update_logic(hxfw, opt_data, dinfo, UPDATE_CMD_MAIN, opt_data.hid_info.main_mapping, sizeof(opt_data.hid_info.main_mapping),
									g_ic_main_code_mapping_table, sizeof(g_ic_main_code_mapping_table), lastError);
		if (ret < 0) {
			printf("Main code update failed!\n");
		} else if (ret > 0) {
			printf("Main code version identical, no need to update!\n");
			ret = 0;
		} else {
			printf("Main code update succeed!\n");
			ret = 0;
		}
	}

	return ret;
}

int hid_fw_update(OPTDATA& opt_data, DEVINFO& dinfo, int& lastError)
{
	HXFW hxfw = {0};
	int ret = 0;

	if (himax_load_fw(opt_data.fw_path, &hxfw) != 0) {
		ret = -ENODATA;
		lastError = FWUP_ERROR_LOAD_FW_BIN;
		goto LOAD_FW_FAILED;
	}
	ret = hid_fw_update_logic(&hxfw, opt_data, dinfo, lastError);

	himax_free_fw(&hxfw);

LOAD_FW_FAILED:
	return ret;
}

int hid_set_data_type(OPTDATA& opt_data)
{
	int ret;

	if (hx_scan_open_hidraw(opt_data) == 0) {
		uint32_t type = opt_data.param.i | opt_data.ic_select << 16;
#if 0
		#define fw_addr_raw_out_sel                 0x100072EC
		#define HID_RAW_OUT_DELTA					0x29

		ret = hx_hid_reg_write(fw_addr_raw_out_sel, HID_RAW_OUT_DELTA, opt_data);
		if (ret < 0) {
			hx_hid_close();
			return -EIO;
		}
#else
		ret = hx_hid_set_feature(HID_TOUCH_MONITOR_SEL_ID, (uint8_t *)&type, 4);
		if (ret < 0) {
			hx_hid_close();
			return -EIO;
		}
#endif
		hx_hid_close();
		return 0;
	} else {
		return -ENODEV;
	}
}

int hid_print_report_descriptor(OPTDATA& opt_data)
{
	int ret;

	if (hx_scan_open_hidraw(opt_data) == 0) {
		ret = hx_hid_print_RD();
		if (ret < 0) {
			hx_hid_close();
			return -EIO;
		}

		return 0;
	} else {
		return -ENODEV;
	}
}

static int hx_hid_parse_criteria_file(OPTDATA& opt_data, hx_criteria_t** result, uint32_t* nKeyword)
{
	static hx_criteria_t hx_criteria_table[] = {
		{
			.keyword = "RAW_BS_FRAME",
			.activated = false,
			.type = ONE_PARAM,
			.default_value = 8,
		},
		{
			.keyword = "NOISE_BS_FRAME",
			.activated = false,
			.type = ONE_PARAM,
			.default_value = 8,
		},
		{
			.keyword = "ACT_IDLE_BS_FRAME",
			.activated = false,
			.type = ONE_PARAM,
			.default_value = 1,
		},
		{
			.keyword = "LP_BS_FRAME",
			.activated = false,
			.type = ONE_PARAM,
			.default_value = 1,
		},
		{
			.keyword = "LP_IDLE_BS_FRAME",
			.activated = false,
			.type = ONE_PARAM,
			.default_value = 1,
		},
		{
			.keyword = "NORMAL_N_FRAME",
			.activated = false,
			.type = ONE_PARAM,
			.default_value = 60,
		},
		{
			.keyword = "IDLE_N_FRAME",
			.activated = false,
			.type = ONE_PARAM,
			.default_value = 10,
		},
		{
			.keyword = "LP_RAW_N_FRAME",
			.activated = false,
			.type = ONE_PARAM,
			.default_value = 1,
		},
		{
			.keyword = "LP_NOISE_N_FRAME",
			.activated = false,
			.type = ONE_PARAM,
			.default_value = 1,
		},
		{
			.keyword = "LP_IDLE_RAW_N_FRAME",
			.activated = false,
			.type = ONE_PARAM,
			.default_value = 1,
		},
		{
			.keyword = "LP_IDLE_NOISE_N_FRAME",
			.activated = false,
			.type = ONE_PARAM,
			.default_value = 1,
		},
		{
			.keyword = "CRITERIA_RAW_BPN_MIN",
			.activated = false,
			.type = MORE_PARAM,
			.default_value = 5,
		},
		{
			.keyword = "CRITERIA_RAW_BPN_MAX",
			.activated = false,
			.type = MORE_PARAM,
			.default_value = 90,
		},
		{
			.keyword = "CRITERIA_RAW_MIN",
			.activated = false,
			.type = MORE_PARAM,
			.default_value = -32768,
		},
		{
			.keyword = "CRITERIA_RAW_MAX",
			.activated = false,
			.type = MORE_PARAM,
			.default_value = 32768,
		},
		{
			.keyword = "CRITERIA_SHORT_MIN",
			.activated = false,
			.type = MORE_PARAM,
			.default_value = 0,
		},
		{
			.keyword = "CRITERIA_SHORT_MAX",
			.activated = false,
			.type = MORE_PARAM,
			.default_value = 150,
		},
		{
			.keyword = "CRITERIA_OPEN_MIN",
			.activated = false,
			.type = MORE_PARAM,
			.default_value = 0,
		},
		{
			.keyword = "CRITERIA_OPEN_MAX",
			.activated = false,
			.type = MORE_PARAM,
			.default_value = 500,
		},
		{
			.keyword = "CRITERIA_MICRO_OPEN_MIN",
			.activated = false,
			.type = MORE_PARAM,
			.default_value = 0,
		},
		{
			.keyword = "CRITERIA_MICRO_OPEN_MAX",
			.activated = false,
			.type = MORE_PARAM,
			.default_value = 150,
		},
		{
			.keyword = "CRITERIA_NOISE_WT_MIN",
			.activated = false,
			.type = MORE_PARAM,
			.default_value = -200,
		},
		{
			.keyword = "CRITERIA_NOISE_WT_MAX",
			.activated = false,
			.type = MORE_PARAM,
			.default_value = 300,
		},
		{
			.keyword = "CRITERIA_NOISE",
			.activated = false,
			.type = MORE_PARAM,
			.default_value = 0,
		}
	};
	FILE *criteria_fp;
	const int max_rx_count = 128;
	const int max_tx_count = 128;
	char line[8 * max_rx_count + 256] = {0};
	char *tok = NULL;
	char *endptr;
	bool keyword_match;
	unsigned int current_idx;
	// int tok_idx;
	uint32_t rx_cnt;

	/* Clean up */
	for (unsigned int i = 0; i < sizeof(hx_criteria_table)/sizeof(hx_criteria_t); i++) {
		hx_criteria_table[i].activated = false;
	}

	criteria_fp = fopen(opt_data.criteria_path, "r");
	if (criteria_fp != NULL) {
		current_idx = 0;
		while (fgets(line, sizeof(line), criteria_fp) != NULL) {
			tok = strtok(line, ",");
			if (tok == NULL) {
				continue;
			}
			// tok_idx = 0;
START_KEYWORD_MATCH:
			keyword_match = false;
			for (unsigned int i = 0; i < sizeof(hx_criteria_table)/sizeof(hx_criteria_t); i++) {
				if (strcmp(tok, hx_criteria_table[i].keyword/*, strlen(hx_criteria_table[i].keyword) + 1*/) == 0) {
					keyword_match = true;
					current_idx = i;
					break;
				}
			}

			if (keyword_match) {
				switch (hx_criteria_table[current_idx].type) {
					case ONE_PARAM:
						tok = strtok(NULL, ",");
						if (tok != NULL) {
							// tok_idx++;
							hx_criteria_table[current_idx].default_value = strtoul(tok, &endptr, 0);
							if (errno == 0 && endptr != tok && *endptr == '\0') {
								hx_criteria_table[current_idx].activated = true;
							} else {
								hx_printf("Reading 1 parameter failed!\n");
							}
						} else {
							hx_printf("Parsing parameter failed!\n");
						}
						break;
					case MORE_PARAM:
						hx_criteria_table[current_idx].param_data = NULL;
						hx_criteria_table[current_idx].param_data = (int32_t *)malloc(max_rx_count * max_tx_count * sizeof(int32_t));
						if (hx_criteria_table[current_idx].param_data == NULL) {
							hx_printf("Memoey insufficient!\n");
							break;
						}
						hx_criteria_table[current_idx].param_count = 0;
						tok = strtok(NULL, ",");
						rx_cnt = 0;
						while (tok != NULL) {
							// tok_idx++;
							hx_criteria_table[current_idx].param_data[hx_criteria_table[current_idx].param_count] = strtoul(tok, &endptr, 0);
							if (errno == 0 && endptr != tok && *endptr == '\0') {
								hx_criteria_table[current_idx].param_count++;
								rx_cnt++;
							}

							tok = strtok(NULL, ",");
						};
						if (hx_criteria_table[current_idx].param_count > 0) {
							hx_criteria_table[current_idx].rx = rx_cnt;
							hx_criteria_table[current_idx].tx = 1;
							hx_criteria_table[current_idx].activated = true;
							rx_cnt = 0;
						} else {
							free(hx_criteria_table[current_idx].param_data);
							hx_criteria_table[current_idx].param_data = NULL;
							break;
						}

						while (fgets(line, sizeof(line), criteria_fp) != NULL) {
							if(line[0] != ',') {
								tok = strtok(line, ",");
								if (tok == NULL)
									continue;
								// tok_idx = 0;
								goto START_KEYWORD_MATCH;
							}
							tok = strtok(line + 1, ",");
							if (tok == NULL)
								continue;
							// tok_idx = 0;
							// rx_cnt = 0;
							hx_criteria_table[current_idx].param_data[hx_criteria_table[current_idx].param_count] = strtoul(tok, &endptr, 0);
							if (errno == 0 && endptr != tok && *endptr == '\0') {
								hx_criteria_table[current_idx].param_count++;
								rx_cnt++;

								tok = strtok(NULL, ",");
								while (tok != NULL) {
									// tok_idx++;
									hx_criteria_table[current_idx].param_data[hx_criteria_table[current_idx].param_count] = strtoul(tok, &endptr, 0);
									if (errno == 0 && endptr != tok && *endptr == '\0') {
										hx_criteria_table[current_idx].param_count++;
										rx_cnt++;
									}

									tok = strtok(NULL, ",");
								};
								if (rx_cnt > 0) {
									hx_criteria_table[current_idx].tx++;
									if (rx_cnt != hx_criteria_table[current_idx].rx)
										hx_printf("Warning : rx count not equal!(%d != %d)\n", hx_criteria_table[current_idx].rx, rx_cnt);
									rx_cnt = 0;
								} else {
									hx_printf("Warning : not value parsed!\n");
								}
							} else {
								hx_printf("Warning : not value parsed!\n");
							}

						};

						break;
					default:
						hx_printf("No match parameter type! Ignore.\n");
				}
			}
		}
#if 0
		for (int i = 0; i < sizeof(hx_criteria_table)/sizeof(hx_criteria_t); i++) {
			if (hx_criteria_table[i].activated) {
				hx_printf("%s found\n", hx_criteria_table[i].keyword);
				if (hx_criteria_table[i].type == ONE_PARAM) {
					hx_printf("critera : %d\n", hx_criteria_table[i].default_value);
				} else if (hx_criteria_table[i].type == MORE_PARAM) {
					hx_printf("rx : %d, tx : %d, value count : %d",
						hx_criteria_table[i].rx, hx_criteria_table[i].tx,
						hx_criteria_table[i].param_count);
					for (int j = 0; j < hx_criteria_table[i].param_count; j++) {
						if ((j % hx_criteria_table[i].rx) == 0) {
							hx_printf("\n[TX%02d]:", (j / hx_criteria_table[i].rx)+1);
						}
						if (j != (hx_criteria_table[i].param_count - 1))
							hx_printf(" %5d,", hx_criteria_table[i].param_data[j]);
						else
							hx_printf(" %5d", hx_criteria_table[i].param_data[j]);
					}
					hx_printf("\n");
				}
			}
		}
#endif
		fclose(criteria_fp);
		*result = hx_criteria_table;
		*nKeyword = sizeof(hx_criteria_table)/sizeof(hx_criteria_t);
		return 0;
	} else {
		*result = NULL;
		*nKeyword = 0;
		return -EIO;
	}
}

void log(FILE *fp, const char *fmt, ...)
{
	va_list ap;

	if (fp == NULL)
		return;

	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
}

enum layout_type_t get_layout_type(hx_hid_ic_layout_header *layout)
{
	if (layout->ic_tx_rx[0].desc.layout.rx_num == layout->total_tx_rx.desc.layout.rx_num &&
		layout->ic_tx_rx[0].desc.layout.tx_num == layout->total_tx_rx.desc.layout.tx_num) {
		hx_printf("SINGLE panel layout detected!\n");
		return SINGLE;
	}

	if (layout->ic_tx_rx[0].desc.layout.rx_num == layout->total_tx_rx.desc.layout.rx_num) {
		hx_printf("DIMENSION_1D_TX panel layout detected!\n");
		return DIMENSION_1D_TX;
	}

	if (layout->ic_tx_rx[0].desc.layout.tx_num == layout->total_tx_rx.desc.layout.tx_num) {
		hx_printf("DIMENSION_1D_RX panel layout detected!\n");
		return DIMENSION_1D_RX;
	}

	hx_printf("DIMENSION_2D panel layout detected!\n");
	return DIMENSION_2D;
}


int place_frame_in_full_map(uint16_t *full_map, uint16_t *frame, int frame_pos_rx, int frame_pos_tx,
							enum layout_type_t ltype, hx_hid_ic_layout_header *layout)
{
	uint full_map_pos_x;
	uint full_map_pos_y;
	uint origin_x = layout->ic_direction.desc.data[0];
	uint origin_y = layout->ic_direction.desc.data[1];
	uint ic_idx = 0;
	uint acc_rx_num = 0, acc_tx_num = 0;
	uint cur_rx_num = 0, cur_tx_num = 0;
	uint full_rx = layout->total_tx_rx.desc.layout.rx_num;
	uint full_tx = layout->total_tx_rx.desc.layout.tx_num;

	if (ltype == DIMENSION_1D_RX) {
		ic_idx = frame_pos_rx;
		for (uint i = 0; i < ic_idx; i++) {
			acc_rx_num += layout->ic_tx_rx[i].desc.layout.rx_num;
		}
		cur_rx_num = layout->ic_tx_rx[ic_idx].desc.layout.rx_num;
		cur_tx_num = layout->ic_tx_rx[ic_idx].desc.layout.tx_num;
	} else if (ltype == DIMENSION_1D_TX) {
		ic_idx = frame_pos_tx;
		for (uint i = 0; i < ic_idx; i++) {
			acc_tx_num += layout->ic_tx_rx[i].desc.layout.tx_num;
		}
		cur_tx_num = layout->ic_tx_rx[ic_idx].desc.layout.tx_num;
		cur_rx_num = layout->ic_tx_rx[ic_idx].desc.layout.rx_num;
	} else if (ltype == DIMENSION_2D) {
		hx_printf("Error : 2D layout not supported in current version!\n");
		return -1;
	} else if (ltype == SINGLE) {
		acc_rx_num = 0;
		acc_tx_num = 0;
		cur_rx_num = layout->ic_tx_rx[0].desc.layout.rx_num;
		cur_tx_num = layout->ic_tx_rx[0].desc.layout.tx_num;
	} else {
		hx_printf("Error : invalid layout type(%d)\n", ltype);
		return -1;
	}

	if ((acc_rx_num + cur_rx_num) > full_rx) {
		hx_printf("Error : frame_pos_rx(%d) + rx_num(%d) > full_rx(%d)\n", frame_pos_rx, cur_rx_num, full_rx);
		return -1;
	}
	if ((acc_tx_num + cur_tx_num) > full_tx) {
		hx_printf("Error : frame_pos_tx(%d) + tx_num(%d) > full_tx(%d)\n", frame_pos_tx, cur_tx_num, full_tx);
		return -1;
	}
	// origin type: 0,0 => right-bottom
	//              0,1 => right-top
	//              1,0 => left-bottom
	//              1,1 => left-top
	switch (origin_x) {
		case 0:
			full_map_pos_x = acc_rx_num;
			break;
		case 1:
			full_map_pos_x = full_rx - (acc_rx_num + cur_rx_num);
			break;
		default:
			hx_printf("Error : origin_x(%d) invalid\n", origin_x);
			return -1;
	}
	switch (origin_y) {
		case 0:
			full_map_pos_y = acc_tx_num;
			break;
		case 1:
			full_map_pos_y = full_tx - (acc_tx_num + cur_tx_num);
			break;
		default:
			hx_printf("Error : origin_y(%d) invalid\n", origin_y);
			return -1;
	}
	for (uint i = 0; i < cur_tx_num; i++)
		memcpy(full_map + full_map_pos_y * full_rx + i * full_rx + full_map_pos_x,
		frame + i * cur_rx_num,
		cur_rx_num * sizeof(uint16_t));

	return 0;
}

typedef struct hid_self_test_support_item {
	const char *name;
	bool hasLowerBond;
	const char *lower_bond_keyword;
	bool hasUpperBond;
	const char *upper_bond_keyword;
	uint32_t hid_switch;
	bool testResult;
	bool activated;
	int32_t fail_rx;
	int32_t fail_tx;
	int32_t fail_v;
} hid_self_test_support_item_t;

bool compare_result(uint8_t *frame_data, hid_self_test_support_item_t *test_item, bool bUpperBondFound,
	int32_t *upperBond_data, bool bLowerBondFound, int32_t *lowerBond_data, unsigned int rx_num, unsigned int tx_num)
{
	union { int32_t i; uint16_t s[2]; } usdata;

	hx_printf("\nFull map:\n");
	hx_printf("       ");
	for(uint j = 0; j < rx_num; j++) {
		hx_printf(" RX[%02d]", j + 1);
	}
	for (uint j = 0; j < (rx_num * tx_num); j++) {
		if ((j % rx_num) == 0) {
			hx_printf("\nTX[%02d]:", j/rx_num + 1);
		}
		usdata.i =
			(int16_t)frame_data[j * 2] + (((int16_t)frame_data[j * 2 + 1]) << 8);
		if (test_item->hid_switch == HID_SELF_TEST_NOISE)
			usdata.i = *(int16_t *)&(usdata.s[0]);

		hx_printf(" %6d", usdata.i);
	}
	hx_printf("\n");

	test_item->testResult = true;
	for (unsigned int j = 0; j < rx_num * tx_num; j++) {
		usdata.i =
			(int16_t)frame_data[j * 2] + (((int16_t)frame_data[j * 2 + 1]) << 8);
		if (test_item->hid_switch == HID_SELF_TEST_NOISE)
			usdata.i = *(int16_t *)&(usdata.s[0]);
		if ((test_item->hasUpperBond) && bUpperBondFound) {
			if (usdata.i > upperBond_data[j]) {
				test_item->testResult = false;
				test_item->fail_rx = (j % rx_num) + 1;
				test_item->fail_tx = j/rx_num + 1;
				test_item->fail_v = usdata.i;
			} else {
				test_item->testResult &= true;
			}
		}
		if ((test_item->hasLowerBond) && bLowerBondFound) {
			if (usdata.i < lowerBond_data[j]) {
				test_item->testResult = false;
				test_item->fail_rx = (j % rx_num) + 1;
				test_item->fail_tx = j/rx_num + 1;
				test_item->fail_v = usdata.i;
			} else {
				test_item->testResult &= true;
			}
		}
	}

	return test_item->testResult;
}

void print_full_map(uint8_t *frame_data, uint full_rx, uint full_tx, bool signed_data, uint16_t rotate, FILE *fp)
{
	// Print full map, with rotation if degree is 90/180/270
	uint out_rx = full_rx;
	uint out_tx = full_tx;
	uint16_t deg = rotate % 360;
	union { int32_t i; uint16_t s[2]; } usdata;

	if (deg == 90 || deg == 270) {
		out_rx = full_tx;
		out_tx = full_rx;
	}

	hx_printf("\nFull map:\n");
	log(fp, "\nFull map:\n");
	hx_printf("       ");
	log(fp, "       ");
	for (uint j = 0; j < out_rx; j++) {
		switch (deg) {
		case 0:
			hx_printf(" RX[%02d]", j + 1);
			log(fp, " RX[%02d]", j + 1);
			break;
		case 90:
			hx_printf(" TX[%02d]", out_rx - j);
			log(fp, " TX[%02d]", out_rx - j);
			break;
		case 180:
			hx_printf(" RX[%02d]", out_rx - j);
			log(fp, " RX[%02d]", out_rx - j);
			break;
		case 270:
			hx_printf(" TX[%02d]", j + 1);
			log(fp, " TX[%02d]", j + 1);
			break;
		}
	}

	for (uint y = 0; y < out_tx; y++) {
		switch (deg) {
		case 0:
			hx_printf("\nTX[%02d]:", y + 1);
			log(fp, "\nTX[%02d]:", y + 1);
			break;
		case 90:
			hx_printf("\nRX[%02d]:", y + 1);
			log(fp, "\nRX[%02d]:", y + 1);
			break;
		case 180:
			hx_printf("\nTX[%02d]:", out_tx - y);
			log(fp, "\nTX[%02d]:", out_tx - y);
			break;
		case 270:
			hx_printf("\nRX[%02d]:", out_tx - y);
			log(fp, "\nRX[%02d]:", out_tx - y);
			break;
		}

		for (uint x = 0; x < out_rx; x++) {
			uint src_rx = x;
			uint src_tx = y;

			switch (deg) {
			case 0:
				break;
			case 90:
				src_rx = y;
				src_tx = full_tx - 1 - x;
				break;
			case 180:
				src_rx = full_rx - 1 - x;
				src_tx = full_tx - 1 - y;
				break;
			case 270:
				src_rx = full_rx - 1 - y;
				src_tx = x;
				break;
			default:
				src_rx = x;
				src_tx = y;
				break;
			}

			uint idx = (src_tx * full_rx + src_rx) * 2;
			// int32_t v = (int16_t)frame_data[idx] + (((int16_t)frame_data[idx + 1]) << 8);
			// if (!signed_data)
				// v = (uint16_t)v;
			usdata.i =
			(int16_t)frame_data[idx] + (((int16_t)frame_data[idx + 1]) << 8);
			if (signed_data)
				usdata.i = *(int16_t *)&(usdata.s[0]);

			hx_printf(" %6d", usdata.i);
			log(fp, " %6d", usdata.i);
		}
	}

	hx_printf("\n");
	log(fp, "\n");
}

bool compare_result_with_fixed_bounds(uint8_t *frame_data, hid_self_test_support_item_t *test_item,
	int32_t upperBond, int32_t lowerBond, bool signed_data,	unsigned int rx_num, unsigned int tx_num,
	uint16_t rotate, FILE *fp)
{
	union { int32_t i; uint16_t s[2]; } usdata;
#if 0
	hx_printf("\nFull map:\n");
	log(fp, "\nFull map:\n");
	hx_printf("       ");
	log(fp, "       ");
	for(uint j = 0; j < rx_num; j++) {
		hx_printf(" RX[%02d]", j + 1);
		log(fp, " RX[%02d]", j + 1);
	}
	for (uint j = 0; j < (rx_num * tx_num); j++) {
		if ((j % rx_num) == 0) {
			hx_printf("\nTX[%02d]:", j/rx_num + 1);
			log(fp, "\nTX[%02d]:", j/rx_num + 1);
		}
		usdata.i =
			(int16_t)frame_data[j * 2] + (((int16_t)frame_data[j * 2 + 1]) << 8);
		if (test_item->hid_switch == HID_SELF_TEST_NOISE || signed_data)
			usdata.i = *(int16_t *)&(usdata.s[0]);

		hx_printf(" %6d", usdata.i);
		log(fp, " %6d", usdata.i);
	}
	hx_printf("\n");
	log(fp, "\n");
#else
	print_full_map(frame_data, rx_num, tx_num, test_item->hid_switch == HID_SELF_TEST_NOISE || signed_data, rotate, fp);
#endif
	test_item->testResult = true;
	for (unsigned int j = 0; j < rx_num * tx_num; j++) {
		usdata.i =
			(int16_t)frame_data[j * 2] + (((int16_t)frame_data[j * 2 + 1]) << 8);
		if (signed_data)
			usdata.i = *(int16_t *)&(usdata.s[0]);
		if (test_item->hasUpperBond) {
			if (usdata.i > upperBond) {
				test_item->testResult = false;
				test_item->fail_rx = (j % rx_num) + 1;
				test_item->fail_tx = j/rx_num + 1;
				test_item->fail_v = usdata.i;
			} else {
				test_item->testResult &= true;
			}
		}
		if (test_item->hasLowerBond) {
			if (usdata.i < lowerBond) {
				test_item->testResult = false;
				test_item->fail_rx = (j % rx_num) + 1;
				test_item->fail_tx = j/rx_num + 1;
				test_item->fail_v = usdata.i;
			} else {
				test_item->testResult &= true;
			}
		}
	}

	return test_item->testResult;
}

bool get_raw_data(uint32_t single_frame_sz, uint16_t type,
	bool signed_data, bool polling_for_ready, uint32_t self_test_id_sz,
	uint8_t *full_data,	hx_hid_ic_layout_header *ic_layout, enum layout_type_t ltype,
	bool rx_rev, bool tx_rev, int retry_limit, bool bPrintData, FILE *fp)
{
	int poll_cnt = 0;
	int ret;
	union { uint32_t i; uint8_t b[4]; } cmd;
	union { uint32_t i; uint8_t b[4]; } recv;
	union { int32_t i; uint16_t s[2]; } usdata;
	const uint32_t pollingInterval = 100;
	const unsigned int header = 5;
	int nDataRecv = 0;
	uint8_t lastState;
	int debug_start_loc;
	int retry_cnt = 0;
	uint correct_frames = 0;
	uint8_t *frame_buffer = NULL;
	uint8_t *frame_ptr;
	uint rx_ic_num, tx_ic_num, full_rx_num, full_tx_num;
	uint current_rx_num, current_tx_num;
	uint acc_rx_num, acc_tx_num;

	rx_ic_num = ic_layout->total_tx_rx_ic_num.desc.layout.rx_num;
	tx_ic_num = ic_layout->total_tx_rx_ic_num.desc.layout.tx_num;
	full_rx_num = ic_layout->total_tx_rx.desc.layout.rx_num;
	full_tx_num = ic_layout->total_tx_rx.desc.layout.tx_num;
	// hx_printf("%s: rx_ic_num = %d, tx_ic_num = %d, rx_num = %d, tx_num = %d\n", __func__, rx_ic_num, tx_ic_num, rx_num, tx_num);
	// hx_printf("%s: single_frame_sz = %d, id size: %d\n", __func__, single_frame_sz, self_test_id_sz);
	frame_buffer = (uint8_t *)malloc(rx_ic_num * tx_ic_num * single_frame_sz);
	if (frame_buffer == NULL) {
		hx_printf("Memory insufficient!\n");
		return false;
	}
	frame_ptr = frame_buffer;
	for (unsigned int tra_rx_ic = 0; tra_rx_ic < rx_ic_num; tra_rx_ic++) {
		for (unsigned int tra_tx_ic = 0; tra_tx_ic < tx_ic_num; tra_tx_ic++) {
			retry_cnt = 0;
RESTART_ALL_PROC:
			if (tra_rx_ic != 0 || tra_tx_ic != 0) {
				cmd.i = (tra_tx_ic << 20) | (tra_rx_ic << 16) | type;
				// cmd.i = (tra_rx_ic << 20) | (tra_tx_ic << 16) | type;
				ret = hx_hid_set_feature(HID_TOUCH_MONITOR_SEL_ID, cmd.b, sizeof(cmd.b));
				if (ret < 0) {
					retry_cnt++;
					if (retry_cnt >= retry_limit) {
						hx_printf("Set feature failed!\n");
						free(frame_buffer);
						return false;
					}
					goto RESTART_ALL_PROC;
				}
				if (polling_for_ready) {
					poll_cnt = 0;
RESTART_POLL_PROC:
					if (poll_cnt >= retry_limit) {
						hx_printf("Polling for 0xFF timeout!\n");
						free(frame_buffer);
						return false;
					}
					nDataRecv = 0;
					cmd.i = 0xFF;
					cmd.i = htole32(cmd.i);
					lastState = 0x0;
					if (!pollingForResult(HID_SELF_TEST_ID, cmd.b, self_test_id_sz, pollingInterval, 7, recv.b, &nDataRecv)) {
						if (nDataRecv == 0) {
							hx_printf("polling result recv nothing.\n");
							log(fp, "polling result recv nothing.\n");
							poll_cnt++;
							goto RESTART_POLL_PROC;
						} else if (nDataRecv > 0) {
							recv.i = le32toh(recv.i);
							if ((recv.b[0] & 0xF0) == 0xF0) {
								switch (recv.b[0]) {
								case 0xF1:
									if (lastState != recv.b[0]) {
										hx_printf("[0x%02X] self test init stage.\n", recv.b[0]);
										log(fp, "[0x%02X] self test init stage.\n", recv.b[0]);
									}
									break;
								case 0xF2:
									if (lastState != recv.b[0]) {
										hx_printf("[0x%02X] self test started.\n", recv.b[0]);
										log(fp, "[0x%02X] self test started.\n", recv.b[0]);
									}
									break;
								case 0xF3:
									if (lastState != recv.b[0]) {
										hx_printf("[0x%02X] self test on going.\n", recv.b[0]);
										log(fp, "[0x%02X] self test on going.\n", recv.b[0]);
									}
									break;
								case 0xF4:
									if (lastState != recv.b[0]) {
										hx_printf("[0x%02X] Still load slave data.....\n", recv.b[0]);
										log(fp, "[0x%02X] Still load slave data.....\n", recv.b[0]);
									}
									poll_cnt++;
									goto RESTART_POLL_PROC;
									break;
								case 0xFF:
									if (lastState != recv.b[0]) {
										hx_printf("[0x%02X] process finish.\n", recv.b[0]);
										log(fp, "[0x%02X] process finish.\n", recv.b[0]);
									}
									break;
								default:
									hx_printf("self test undefined stage.(0x%02X)\n", recv.b[0]);
									log(fp, "self test undefined stage.(0x%02X)\n", recv.b[0]);
								};
								lastState = recv.b[0];
								usleep(16 * 1000);
								// continue;
							} else if ((recv.b[0] & 0xF0) == 0xE0) {
								switch (recv.b[0]) {
								case 0xE1:
									hx_printf("[0x%02X] self test not support!\n", recv.b[0]);
									log(fp, "[0x%02X] self test not support!\n", recv.b[0]);
									break;
								case 0xEF:
									hx_printf("[0x%02X] self test error!\n", recv.b[0]);
									log(fp, "[0x%02X] self test error!\n", recv.b[0]);
									break;
								default:
									hx_printf("self test undefined error(%02X)!\n", recv.b[0]);
									log(fp, "self test undefined error(%02X)!\n", recv.b[0]);
								};
								free(frame_buffer);
								return false;
							} else {
								hx_printf("self test return undefined value!(0x%02X)\n", recv.b[0]);
								log(fp, "self test return undefined value!(0x%02X)\n", recv.b[0]);
								free(frame_buffer);
								return false;
							}
						}
					} else {
						//process completed
						hx_printf("[0x%02X] process finish.\n", recv.b[0]);
						log(fp, "[0x%02X] process finish.\n", recv.b[0]);
						// break;
					}
				}
			}
			retry_cnt = 0;
			while (retry_cnt++ < retry_limit) {
				if (retry_cnt > 1)
					usleep(19 * 1000);

				ret = hx_hid_get_feature(HID_TOUCH_MONITOR_ID, frame_ptr, single_frame_sz);
				if ((ret == 0) && (frame_ptr[1] == 0x5A) && (frame_ptr[2] == 0xA5)) {
					if (place_frame_in_full_map((uint16_t *)full_data, (uint16_t *)(frame_ptr + header),
						tra_rx_ic, tra_tx_ic, ltype, ic_layout) != 0) {
						hx_printf("place frame in full map failed!\n");
						log(fp, "place frame in full map failed!\n");
						free(frame_buffer);
						return false;
					}
					correct_frames++;
					frame_ptr += single_frame_sz;
					break;
				}
			}
		}
	}

	if (bPrintData) {
		frame_ptr = frame_buffer;
		acc_rx_num = 0;
		acc_tx_num = 0;
		for (uint i = 0; i < correct_frames; i++, frame_ptr += single_frame_sz) {
			// hx_printf("Header: 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n", frame_ptr[0], frame_ptr[1], frame_ptr[2], frame_ptr[3], frame_ptr[4]);
			current_rx_num = ic_layout->ic_tx_rx[i].desc.layout.rx_num;
			current_tx_num = ic_layout->ic_tx_rx[i].desc.layout.tx_num;
			hx_printf("Current Ic RX: %d, TX: %d\n", current_rx_num, current_tx_num);
			hx_printf("       ");
			log(fp, "       ");
			for(uint j = acc_rx_num; j < (current_rx_num + acc_rx_num); j++) {
				hx_printf(" RX[%02d]", j + 1);
				log(fp, " RX[%02d]", j + 1);
			}
			for (uint j = 0; j < (current_rx_num * current_tx_num); j++) {
				if ((j % current_rx_num) == 0) {
					hx_printf("\nTX[%02d]:", j/current_rx_num + 1 + acc_tx_num);
					log(fp, "\nTX[%02d]:", j/current_rx_num + 1 + acc_tx_num);
				}
				usdata.i =
					(int16_t)frame_ptr[header + j * 2] + (((int16_t)frame_ptr[header + j * 2 + 1]) << 8);
				if (signed_data)
					usdata.i = *(int16_t *)&(usdata.s[0]);
				hx_printf(" %6d", usdata.i);
				log(fp, " %6d", usdata.i);
			}

			debug_start_loc = header + (current_rx_num * current_tx_num) * 2;
			for (uint j = 0; j < (current_rx_num + current_tx_num); j++) {
				if ((j % current_rx_num) == 0) {
					hx_printf("\n DEBUG:");
					log(fp, "\n DEBUG:");
				}
				hx_printf(" %6d", ((int16_t)frame_ptr[debug_start_loc + j * 2]) + (((int16_t)frame_ptr[debug_start_loc + j * 2 + 1]) << 8));
				log(fp, " %6d", ((int16_t)frame_ptr[debug_start_loc + j * 2]) + (((int16_t)frame_ptr[debug_start_loc + j * 2 + 1]) << 8));
			}
			hx_printf("\n");
			log(fp, "\n");
			switch (ltype) {
			case DIMENSION_1D_RX:
				acc_rx_num += current_rx_num;
				break;
			case DIMENSION_1D_TX:
				acc_tx_num += current_tx_num;
				break;
			default:
				// SINGLE is the same, and 2D is not supported in current version
				break;
			};
		}
	}

	if (correct_frames == rx_ic_num * tx_ic_num) {
		if (rx_rev) {
			uint16_t *tmp = (uint16_t *)malloc(full_rx_num * full_tx_num * 2);
			if (tmp == NULL) {
				hx_printf("RX Reverse failed, Memory insufficient!\n");
				free(frame_buffer);
				return false;
			}
			for (uint i = 0; i < full_tx_num; i++) {
				for (uint j = 0; j < full_rx_num; j++) {
					tmp[i * full_rx_num + j] = ((uint16_t *)full_data)[(i + 1) * full_rx_num - j - 1];
				}
			}
			memcpy(full_data, tmp, full_rx_num * full_tx_num * 2);
			free(tmp);
		}
		if (tx_rev) {
			uint16_t *tmp = (uint16_t *)malloc(full_rx_num * full_tx_num * 2);
			if (tmp == NULL) {
				hx_printf("TX Reverse failed, Memory insufficient!\n");
				free(frame_buffer);
				return false;
			}
			for (uint i = 0; i < full_rx_num; i++) {
				for (uint j = 0; j < full_tx_num; j++) {
					tmp[j * full_rx_num + i] = ((uint16_t *)full_data)[(full_tx_num - j - 1) * full_rx_num + i];
				}
			}
			memcpy(full_data, tmp, full_rx_num * full_tx_num * 2);
			free(tmp);
		}
		free(frame_buffer);
		return true;
	} else {
		free(frame_buffer);
		return false;
	}
}

int hid_self_test_by_criteria_file(OPTDATA& opt_data)
{
	static hid_self_test_support_item_t test_items[] = {
		{
			.name = "Short",
			.hasLowerBond = true,
			.lower_bond_keyword = "CRITERIA_SHORT_MIN",
			.hasUpperBond = true,
			.upper_bond_keyword = "CRITERIA_SHORT_MAX",
			.hid_switch = HID_SELF_TEST_SHORT,
			.testResult = false,
		},
		{
			.name = "Open",
			.hasLowerBond = true,
			.lower_bond_keyword = "CRITERIA_OPEN_MIN",
			.hasUpperBond = true,
			.upper_bond_keyword = "CRITERIA_OPEN_MAX",
			.hid_switch = HID_SELF_TEST_OPEN,
			.testResult = false,
		},
		{
			.name = "Micro Open",
			.hasLowerBond = true,
			.lower_bond_keyword = "CRITERIA_MICRO_OPEN_MIN",
			.hasUpperBond = true,
			.upper_bond_keyword = "CRITERIA_MICRO_OPEN_MAX",
			.hid_switch = HID_SELF_TEST_MICRO_OPEN,
			.testResult = false,
		},
		{
			.name = "Rawdata",
			.hasLowerBond = true,
			.lower_bond_keyword = "CRITERIA_RAW_MIN",
			.hasUpperBond = true,
			.upper_bond_keyword = "CRITERIA_RAW_MAX",
			.hid_switch = HID_SELF_TEST_RAWDATA,
			.testResult = false,
		},
		{
			.name = "Noise",
			.hasLowerBond = false,
			.lower_bond_keyword = NULL,
			.hasUpperBond = true,
			.upper_bond_keyword = "CRITERIA_NOISE",
			.hid_switch = HID_SELF_TEST_NOISE,
			.testResult = false,
		}
	};
	int ret = 0;
	const uint32_t pollingInterval = 100;
	hx_criteria_t *hx_criteria_table = NULL;
	uint32_t nKeyword;
	uint8_t *frame = NULL;
	uint8_t *cmd = NULL;
	uint8_t *recv = NULL;
	int nDataRecv = 0;
	const int retry_limit = 200;
	const int sw_mode_retry_limit = 3;
	const uint32_t sw_mode_retry_interval_us = 500 * 1000;
	uint retry_cnt = 0;
	uint sw_mode_retry_cnt = 0;
	int total_sz;
	int frame_sz;
	bool bLowerBondFound;
	int32_t *lowerBond_data;
	bool bUpperBondFound;
	int32_t *upperBond_data;
	// bool bSelfTestCompleted = false;
	uint8_t lastState;
	uint rx_num;
	uint tx_num;
	char fname_only[128] = {0};
	char tmp_output_pathname[1024] = {0};
	char final_output_pathname[1024] = {0};
	bool is_output_file;
	time_t t = time(NULL);
	struct tm *dtime = localtime(&t);
	struct timeval tv;
	FILE *fp = NULL;
	bool overall_result = true;
	uint tx_ic_num = 1;
	uint rx_ic_num = 1;
	uint32_t stage_limit = 10;
	hx_hid_ic_layout_header *layout_info = NULL;

	is_output_file = is_opt_set(&opt_data, OPTION_OUTPUT_PATH);
	gettimeofday(&tv, NULL);
	if (hx_hid_parse_criteria_file(opt_data, &hx_criteria_table, &nKeyword) == 0) {
		if (hx_scan_open_hidraw(opt_data) == 0) {
			if (hx_hid_parse_RD_for_idsz(opt_data) == 0) {
				ret = hid_update_fw_info(opt_data);
				if (ret == 0) {
					if (opt_data.hid_layout_info == 0) {
						hx_printf("IC layout error!\n");
						return -ENOMEM;
					}
					rx_num = opt_data.hid_layout_info->total_tx_rx.desc.layout.rx_num;
					tx_num = opt_data.hid_layout_info->total_tx_rx.desc.layout.tx_num;
					tx_ic_num = opt_data.hid_layout_info->total_tx_rx_ic_num.desc.layout.tx_num;
					rx_ic_num = opt_data.hid_layout_info->total_tx_rx_ic_num.desc.layout.rx_num;

					frame_sz = hx_hid_get_size_by_id(HID_TOUCH_MONITOR_ID);
					if (frame_sz > 0) {
						total_sz = rx_num * tx_num * 2;
						frame = (uint8_t *)malloc(total_sz);
						if (frame == NULL) {
							ret = -ENOMEM;
							goto CRITERIA_NO_MEM_FAILED;
						}
						int stSz = hx_hid_get_size_by_id(HID_SELF_TEST_ID);
						if (stSz > 0) {
							cmd = (uint8_t *)malloc(stSz);
							recv = (uint8_t *)malloc(stSz);
							if ((cmd == NULL) || (recv == NULL)) {
								ret = -ENOMEM;
								goto CRITERIA_NO_MEM_FAILED;
							}
							if (is_output_file) {
								snprintf(fname_only, sizeof(fname_only), "%d%02d%02d%02d%02d%02d%03d.txt",
									dtime->tm_year+1900, dtime->tm_mon+1, dtime->tm_mday, dtime->tm_hour,
									dtime->tm_min, dtime->tm_sec, (int)(tv.tv_usec/1000));
								snprintf(tmp_output_pathname, sizeof(tmp_output_pathname), "%s/%s%s",
									opt_data.output_path, "hx_mp_test_log_", fname_only);
								fp = fopen(tmp_output_pathname, "w");
							}

							for (uint32_t i = 0; i < sizeof(test_items)/sizeof(hid_self_test_support_item_t); i++) {
								bLowerBondFound = false;
								lowerBond_data = NULL;
								bUpperBondFound = false;
								upperBond_data = NULL;
								if (test_items[i].hasLowerBond) {
									for (unsigned int j = 0; j < nKeyword; j++) {
										if (strcmp(hx_criteria_table[j].keyword, test_items[i].lower_bond_keyword/*, strlen(test_items[i].lower_bond_keyword)*/) == 0) {
											if (hx_criteria_table[j].activated && (hx_criteria_table[j].rx == (rx_num * rx_ic_num)) && (hx_criteria_table[j].tx == (tx_num * tx_ic_num))) {
												bLowerBondFound = hx_criteria_table[j].activated;
												if (bLowerBondFound)
													lowerBond_data = hx_criteria_table[j].param_data;
											}
										}
									}
									if (!bLowerBondFound) {
										hx_printf("%s: Required Lower Bond not found or channel not match(require rx:%d, tx:%d). Ignore!\n",
											test_items[i].name, rx_num * rx_ic_num, tx_num * tx_ic_num);
										log(fp, "Required Lower Bond not found or channel not match(require rx:%d, tx:%d). Ignore!\n",
											rx_num * rx_ic_num, tx_num * tx_ic_num);
										goto NEXT_ITEM;
									}
								}

								if (test_items[i].hasUpperBond) {
									for (unsigned int j = 0; j < nKeyword; j++) {
										if (strcmp(hx_criteria_table[j].keyword, test_items[i].upper_bond_keyword) == 0) {
											if (hx_criteria_table[j].activated && (hx_criteria_table[j].rx == (rx_num * rx_ic_num))
												&& (hx_criteria_table[j].tx == (tx_num * tx_ic_num))) {
												bUpperBondFound = hx_criteria_table[j].activated;
												if (bUpperBondFound)
													upperBond_data = hx_criteria_table[j].param_data;
											}
										}
									}
									if (!bUpperBondFound) {
										hx_printf("%s: Required Upper Bond not found or channel not match(require rx:%d, tx:%d). Ignore!\n",
											test_items[i].name, rx_num * rx_ic_num, tx_num * tx_ic_num);
										log(fp, "Required Upper Bond not found or channel not match(require rx:%d, tx:%d). Ignore!\n",
											rx_num * rx_ic_num, tx_num * tx_ic_num);
										goto NEXT_ITEM;
									}
								}
								if ((bLowerBondFound == test_items[i].hasLowerBond) && (bUpperBondFound == test_items[i].hasUpperBond)) {
									test_items[i].activated = true;
								} else {
									test_items[i].activated = false;
								}

								if (!test_items[i].activated) {
									hx_printf("Required boundary condition not found, ignore %s test.\n", test_items[i].name);
									log(fp, "Required boundary condition not found, ignore %s test.\n", test_items[i].name);
									goto NEXT_ITEM;
								}

								hx_printf("start %s test(cmd : 0x%X):\n", test_items[i].name, test_items[i].hid_switch);
								log(fp, "start %s test(cmd : 0x%X):\n", test_items[i].name, test_items[i].hid_switch);
								// if ((test_items[i].hid_switch == HID_SELF_TEST_RAWDATA) || (test_items[i].hid_switch == HID_SELF_TEST_NOISE)) {
								// 	cmd[0] = 0x01;
								// 	ret = hx_hid_set_feature(HID_SELF_TEST_ID, cmd, stSz);
								// 	if (ret == 0) {
								// 		hx_printf("Reset self test succeed.\n");
								// 	} else {
								// 		hx_printf("Reset self test failed.\n");
								// 	}
								// 	usleep(500*1000);
								// }
								sw_mode_retry_cnt = 0;
SW_MODE_RETRY_START:
								lastState = 0x0;
								memset(cmd, 0, stSz);
								cmd[0] = test_items[i].hid_switch;
								ret = hx_hid_set_feature(HID_SELF_TEST_ID, cmd, stSz);
								if (ret == 0) {
									nDataRecv = 0;
									cmd[0] = 0xFF;
									// bSelfTestCompleted = false;
									for (retry_cnt = 0; retry_cnt < retry_limit; retry_cnt++) {
										if (!pollingForResult(HID_SELF_TEST_ID, cmd, stSz, pollingInterval, 7,	recv, &nDataRecv)) {
											if (nDataRecv == 0) {
												hx_printf("polling result recv nothing.\n");
												log(fp, "polling result recv nothing.\n");
												//continue;
											} else if (nDataRecv > 0) {
												if ((recv[0] & 0xF0) == 0xF0) {
													switch (recv[0]) {
													case 0xF1:
													case 0xF2:
													case 0xF3:
														if (lastState != recv[0] && recv[0] == 0xF1) {
															hx_printf("self test init stage.\n");
															log(fp, "self test init stage.\n");
															retry_cnt = 0;
															stage_limit = 10;
														} else if (lastState != recv[0] && recv[0] == 0xF2) {
															hx_printf("self test started.\n");
															log(fp, "self test started.\n");
															retry_cnt = 0;
															stage_limit = 10;
														} else if (lastState != recv[0] && recv[0] == 0xF3) {
															hx_printf("self test on going.\n");
															log(fp, "self test on going.\n");
															retry_cnt = 0;
															stage_limit = retry_limit - 1;
														}
														if ((retry_cnt >= stage_limit) && (sw_mode_retry_cnt < sw_mode_retry_limit)) {
															hx_printf("Switch mode, retry %d.\n", sw_mode_retry_cnt);
															log(fp, "Switch mode, retry %d.\n", sw_mode_retry_cnt);
															cmd[0] = 0x01;
															ret = hx_hid_set_feature(HID_SELF_TEST_ID, cmd, stSz);
															if (ret == 0) {
																hx_printf("Reset self test succeed.\n");
																log(fp, "Reset self test succeed.\n");
																usleep(sw_mode_retry_interval_us);
																sw_mode_retry_cnt++;
																if (sw_mode_retry_cnt == sw_mode_retry_limit) {
																	hx_printf("Switch mode retry limit reached, next.\n");
																	log(fp, "Switch mode retry limit reached, next.\n");
																	goto NEXT_ITEM;
																} else {
																	goto SW_MODE_RETRY_START;
																}
															} else {
																hx_printf("Reset self test failed.\n");
																log(fp, "Reset self test failed.\n");
															}
														}
														break;
													case 0xFF:
														if (lastState != recv[0]) {
															hx_printf("self test finish.\n");
															log(fp, "self test finish.\n");
														}
														break;
													default:
														hx_printf("self test undefined stage.(0x%02X)\n", recv[0]);
														log(fp, "self test undefined stage.(0x%02X)\n", recv[0]);
													};
													lastState = recv[0];
													usleep(16 * 1000);
													// continue;
												} else if ((recv[0] & 0xF0) == 0xE0) {
													switch (recv[0]) {
													case 0xE1:
														hx_printf("self test not support!\n");
														log(fp, "self test not support!\n");
														break;
													case 0xEF:
														hx_printf("self test error!\n");
														log(fp, "self test error!\n");
														break;
													default:
														hx_printf("self test undefined error(%02X)!\n", recv[0]);
														log(fp, "self test undefined error(%02X)!\n", recv[0]);
													};
													goto NEXT_ITEM;
												} else {
													hx_printf("self test return undefined value!(0x%02X)\n", recv[0]);
													log(fp, "self test return undefined value!(0x%02X)\n", recv[0]);
													goto NEXT_ITEM;
												}
											} else {
												hx_printf("shouldn't be here!!!\n");
												log(fp, "shouldn't be here!!!\n");
											}
										} else {
											//test completed
											// bSelfTestCompleted = true;
											hx_printf("Self test completed.\n");
											log(fp, "Self test completed.\n");
											break;
										}
									}

									if (retry_cnt == retry_limit) {
										hx_printf("Couldn't get %s result, ignore this test item!\n", test_items[i].name);
										log(fp, "Couldn't get %s result, ignore this test item!\n", test_items[i].name);
										goto NEXT_ITEM;
									}

									// hx_printf("Start to get raw data for compare....\n");
									if (get_raw_data(frame_sz, 0, test_items[i].hid_switch == HID_SELF_TEST_NOISE,
										true, stSz,	frame, opt_data.hid_layout_info, opt_data.hid_layout_type,
										is_opt_set(&opt_data, OPTION_HID_RX_REVERSE),
										is_opt_set(&opt_data, OPTION_HID_TX_REVERSE),
										retry_limit, true, fp)) {
										compare_result(frame, &test_items[i], bUpperBondFound,
											upperBond_data, bLowerBondFound, lowerBond_data, opt_data.hid_layout_info->total_tx_rx.desc.layout.rx_num,
											opt_data.hid_layout_info->total_tx_rx.desc.layout.tx_num);
										hx_printf("Test Item : %s, result %s!\n", test_items[i].name, test_items[i].testResult?"Succeed":"Failed");
										log(fp, "Test Item : %s, result %s!\n", test_items[i].name, test_items[i].testResult?"Succeed":"Failed");
										if (!test_items[i].testResult) {
											hx_printf("(rx:%d, tx:%d) : %d\n",
												test_items[i].fail_rx, test_items[i].fail_tx, test_items[i].fail_v);
											log(fp, "(rx:%d, tx:%d) : %d\n",
												test_items[i].fail_rx, test_items[i].fail_tx, test_items[i].fail_v);
										}
									} else {
										hx_printf("Failed to get data for compare!\n");
										log(fp, "Failed to get data for compare!\n");
										goto NEXT_ITEM;
									}
								} else {
									hx_printf("Failed to issue self test command.\n");
									log(fp, "Failed to issue self test command.\n");
								}
NEXT_ITEM:
								usleep(0);
							}
							cmd[0] = 0x01;
							ret = hx_hid_set_feature(HID_SELF_TEST_ID, cmd, stSz);
							if (ret == 0) {
								hx_printf("Reset self test....\n");
								log(fp, "Reset self test....\n");
							} else {
								hx_printf("Reset self test failed!\n");
								log(fp, "Reset self test failed!\n");
							}
						}
					}
				}
				for (uint32_t i = 0; i < sizeof(test_items)/sizeof(hid_self_test_support_item_t); i++) {
					if (test_items[i].activated) {
						overall_result &= test_items[i].testResult;
						printf("%s test result : %s! ", test_items[i].name, test_items[i].testResult?"Pass":"Fail");
						log(fp, "%s test result : %s! ", test_items[i].name, test_items[i].testResult?"Pass":"Fail");
						if (!test_items[i].testResult) {
							printf("fail sample (rx : %d, tx : %d) : %d\n", test_items[i].fail_rx, test_items[i].fail_tx, test_items[i].fail_v);
							log(fp, "fail sample (rx : %d, tx : %d) : %d\n", test_items[i].fail_rx, test_items[i].fail_tx, test_items[i].fail_v);
						} else {
							printf("\n");
							log(fp, "\n");
						}
					}
				}
				if (fp != NULL) {
					fclose(fp);
					snprintf(final_output_pathname, sizeof(final_output_pathname), "%s/%s_%s%s",
						opt_data.output_path, overall_result?"PASS":"FAIL","hx_mp_test_log_", fname_only);
					if (rename(tmp_output_pathname, final_output_pathname) == 0)
						hx_printf("Log file saved to %s\n", final_output_pathname);
					else
						hx_printf("Failed to rename log file from %s to %s\n", tmp_output_pathname, final_output_pathname);
				}
			} else {
				hx_printf("Id parsing failed, return!\n");
				ret = -ENODATA;
			}

CRITERIA_NO_MEM_FAILED:
			free(layout_info);
			free(frame);
			free(cmd);
			free(recv);
			hx_hid_close();
		} else {
			hx_printf("Failed to open HIDRAW!\n");
			return -ENODEV;
		}
		for (unsigned int i = 0; i < nKeyword; i++) {
			if (hx_criteria_table[i].activated && (hx_criteria_table[i].type == MORE_PARAM)) {
				free(hx_criteria_table[i].param_data);
			}
		}

		return ret;
	} else {
		hx_printf("%s open failed!\n");

		return -EIO;
	}
}

int hid_show_diag(OPTDATA& opt_data)
{
	int ret = 0;
	bool bSelfTestCompleted = false;
	const uint32_t pollingInterval = 100;
	bool bTestPass = true;
	uint8_t *frame = NULL;
	uint8_t *cmd = NULL;
	uint8_t *recv = NULL;
	int nDataRecv;
	const int retry_limit = 20;
	int stSz = 0;
	int frame_sz;
	int total_sz;
	int rx_num;
	int tx_num;
	int tx_ic_num = 1;
	int rx_ic_num = 1;
	int total_rx_num;
	int total_tx_num;
	bool signed_data = false;
	hid_self_test_support_item_t test_item = {
		.name = "Custom",
		.hasLowerBond = true,
		.hasUpperBond = true,
		.testResult = false,
		.activated = true,
	};
	time_t t = time(NULL);
	struct tm *dtime = localtime(&t);
	struct timeval tv;
	FILE *fp = NULL;
	char fname_only[128] = {0};
	char tmp_output_pathname[1024] = {0};
	bool is_output_file = is_opt_set(&opt_data, OPTION_OUTPUT_PATH);

	if (is_output_file) {
		gettimeofday(&tv, NULL);
		snprintf(fname_only, sizeof(fname_only), "%d%02d%02d%02d%02d%02d%03d.txt",
				 dtime->tm_year+1900, dtime->tm_mon+1, dtime->tm_mday, dtime->tm_hour,
				 dtime->tm_min, dtime->tm_sec, (int)(tv.tv_usec/1000));
		snprintf(tmp_output_pathname, sizeof(tmp_output_pathname), "%s/%s%s",
				 opt_data.output_path, "hx_raw_log_", fname_only);
		fp = fopen(tmp_output_pathname, "w");
	}

	if (hx_scan_open_hidraw(opt_data) == 0) {
		if (hx_hid_parse_RD_for_idsz(opt_data) == 0) {
			ret = hid_update_fw_info(opt_data);
			if (ret == 0) {
				rx_num = opt_data.hid_info.rx;
				tx_num = opt_data.hid_info.tx;
				total_rx_num = rx_num * rx_ic_num;
				total_tx_num = tx_num * tx_ic_num;
				// tx_ic_num = ((info.ic_num & 0xF0) >> 4) + 1;
				// rx_ic_num = (info.ic_num & 0x0F) + 1;
				if (opt_data.hid_layout_info != 0) {
					tx_ic_num = opt_data.hid_layout_info->total_tx_rx_ic_num.desc.layout.tx_num;
					rx_ic_num = opt_data.hid_layout_info->total_tx_rx_ic_num.desc.layout.rx_num;
					total_rx_num = opt_data.hid_layout_info->total_tx_rx.desc.layout.rx_num;
					total_tx_num = opt_data.hid_layout_info->total_tx_rx.desc.layout.tx_num;
				}

				frame_sz = hx_hid_get_size_by_id(HID_TOUCH_MONITOR_ID);
				if (frame_sz > 0) {
					total_sz = /*frame_sz +*/ total_rx_num * total_tx_num * 2;
					frame = (uint8_t *)malloc(total_sz);
					if (frame == NULL) {
						ret = -ENOMEM;
						goto DIAG_FUNC_END;
					}
					if (is_opt_set(&opt_data, OPTION_HID_SELF_TEST)) {
						int stSz = hx_hid_get_size_by_id(HID_SELF_TEST_ID);
						if (stSz > 0) {
							cmd = (uint8_t *)malloc(stSz);
							if (cmd != NULL) {
								cmd[0] = opt_data.param.i;
								ret = hx_hid_set_feature(HID_SELF_TEST_ID, cmd, stSz);

								if (ret == 0) {
									recv = (uint8_t *)malloc(stSz);
									if (recv == NULL) {
										ret = -ENOMEM;
										free(frame);
										free(cmd);
										goto DIAG_FUNC_END;
									}
									nDataRecv = 0;
									cmd[0] = 0xFF;
POLL_AGAIN:
									if (!pollingForResult(HID_SELF_TEST_ID, cmd, stSz, pollingInterval, 7,	recv, &nDataRecv)) {
										if (nDataRecv == 0) {
											goto POLL_AGAIN;
										} else if (nDataRecv > 0) {
											if ((recv[0] & 0xF0) == 0xF0) {
												usleep(16 * 1000);
												goto POLL_AGAIN;
											}
										}
									} else {
										bSelfTestCompleted = true;
									}
									free(recv);
								}
								free(cmd);
							} else {
								ret = -ENOMEM;
								free(cmd);
								free(frame);
								goto DIAG_FUNC_END;
							}
						} else {
							ret = -ENODATA;
							free(frame);
							goto DIAG_FUNC_END;
						}
					}
					if (is_opt_set(&opt_data, OPTION_HID_SELF_TEST) && !bSelfTestCompleted) {
						ret = -EIO;
						free(frame);
						goto DIAG_FUNC_END;
					}

					if ((bSelfTestCompleted && (opt_data.param.i == 0x22)) ||
						is_opt_set(&opt_data, OPTION_HID_PARTIAL_DISPLAY_SIGNED))
						signed_data = true;
					if (get_raw_data(frame_sz, opt_data.param.i, signed_data, false, stSz, frame,
						opt_data.hid_layout_info, opt_data.hid_layout_type,
						is_opt_set(&opt_data, OPTION_HID_RX_REVERSE), is_opt_set(&opt_data, OPTION_HID_TX_REVERSE),
						retry_limit, true, fp)) {
						// bTestPass = compare_result(frame + frame_sz, &test_item, false, NULL, false, NULL, rx_num * rx_ic_num, tx_num * tx_ic_num);
						bTestPass = compare_result_with_fixed_bounds(frame, &test_item,
																	 opt_data.self_test_spec_max,
																	 opt_data.self_test_spec_min,
																	 signed_data,
																	 opt_data.hid_layout_info->total_tx_rx.desc.layout.rx_num,
																	 opt_data.hid_layout_info->total_tx_rx.desc.layout.tx_num,
																	 opt_data.rotate_degree,
																	 fp);
					} else {
						hx_printf("Failed to get data\n");
					}

					if (is_opt_set(&opt_data, OPTION_HID_SELF_TEST)) {
						if (bSelfTestCompleted) {
							if (bTestPass) {
								printf("Self test of 0x%02X PASS!\n", opt_data.param.i);
							} else {
								printf("Self test of 0x%02X Failed! (rx:%d, tx:%d) : %d\n",
								opt_data.param.i, test_item.fail_rx , test_item.fail_tx, test_item.fail_v);
							}
						}

						stSz = hx_hid_get_size_by_id(HID_SELF_TEST_ID);
						if (stSz > 0) {
							cmd = (uint8_t *)malloc(stSz);
							if (cmd != NULL) {
								cmd[0] = 0x01;
								ret = hx_hid_set_feature(HID_SELF_TEST_ID, cmd, stSz);
								free(cmd);
							}
						}
					}

					free(frame);
				}
			} else {
				ret = -ENODATA;
			}
		} else {
			hx_printf("ID parsing failed, return!\n");
			ret = -ENODATA;
		}
	} else {
		if(fp)
			fclose(fp);
		return -ENODEV;
	}

DIAG_FUNC_END:
	if(fp)
		fclose(fp);
	hx_hid_close();

	return ret;
}

int hid_show_specify_diag(OPTDATA& opt_data)
{
	const unsigned int header = 5;
	int ret = 0;
	bool bSelfTestCompleted = false;
	const uint32_t pollingInterval = 100;
	bool bTestPass = true;
	struct {
		int32_t rx;
		int32_t tx;
		int32_t v;
	} fail_p;
	uint8_t *frame = NULL;
	uint8_t *cmd = NULL;
	uint8_t *recv = NULL;
	int nDataRecv;
	const int retry_limit = 20;
	int retry_cnt;
	union { int32_t i; uint16_t s[2]; } usdata;
	int debug_start_loc;
	int stSz;
	int frame_sz;
	int rx_num;
	int tx_num;

	if (hx_scan_open_hidraw(opt_data) == 0) {
		if (hx_hid_parse_RD_for_idsz(opt_data) == 0) {
			if (hid_update_fw_info(opt_data) == 0) {
				rx_num = opt_data.hid_info.rx;
				tx_num = opt_data.hid_info.tx;

				frame_sz = hx_hid_get_size_by_id(HID_TOUCH_MONITOR_ID);
				if (frame_sz > 0) {
					frame = (uint8_t *)malloc(frame_sz);
					if (frame == NULL) {
						ret = -ENOMEM;
						goto DIAG_FUNC_END;
					}
					if (is_opt_set(&opt_data, OPTION_HID_SELF_TEST)) {
						int stSz = hx_hid_get_size_by_id(HID_SELF_TEST_ID);
						if (stSz > 0) {
							cmd = (uint8_t *)malloc(stSz);
							if (cmd != NULL) {
								cmd[0] = opt_data.param.i;
								ret = hx_hid_set_feature(HID_SELF_TEST_ID, cmd, stSz);

								if (ret == 0) {
									recv = (uint8_t *)malloc(stSz);
									if (recv == NULL) {
										ret = -ENOMEM;
										free(frame);
										goto DIAG_FUNC_END;
									}
									nDataRecv = 0;
									cmd[0] = 0xFF;
POLL_AGAIN:
									if (!pollingForResult(HID_SELF_TEST_ID, cmd, stSz, pollingInterval, 7,	recv, &nDataRecv)) {
										if (nDataRecv == 0) {
											goto POLL_AGAIN;
										} else if (nDataRecv > 0) {
											if ((recv[0] & 0xF0) == 0xF0) {
												usleep(16 * 1000);
												goto POLL_AGAIN;
											}
										}
									} else {
										bSelfTestCompleted = true;
									}
									free(recv);
								}
								free(cmd);
							} else {
								ret = -ENOMEM;
								free(frame);
								goto DIAG_FUNC_END;
							}
						} else {
							ret = -ENODATA;
							free(frame);
							goto DIAG_FUNC_END;
						}
					}
					if (is_opt_set(&opt_data, OPTION_HID_SELF_TEST) && !bSelfTestCompleted) {
						ret = -EIO;
						free(frame);
						goto DIAG_FUNC_END;
					}

					retry_cnt = 0;
					while (retry_cnt++ < retry_limit) {
						ret = hx_hid_get_feature(HID_TOUCH_MONITOR_ID, frame, frame_sz);
						if (ret == 0) {
							hx_printf("header : %02X %02X %02X %02X %02X\nData:\n",
								frame[0], frame[1], frame[2], frame[3], frame[4]);
							if ((frame[1] == 0x5A) && (frame[2] == 0xA5)) {
								hx_printf("       ");
								for(int i = 0; i < rx_num; i++) {
									hx_printf(" RX[%02d]", i + 1);
								}
								for (int i = 0; i < (rx_num * tx_num); i++) {
									if ((i % rx_num) == 0)
										hx_printf("\nTX[%02d]:", i/rx_num + 1);

									usdata.i =
										(int16_t)frame[header + i * 2] + (((int16_t)frame[header + i * 2 + 1]) << 8);

									if ((bSelfTestCompleted && (opt_data.param.i == 0x22)) ||
										is_opt_set(&opt_data, OPTION_HID_PARTIAL_DISPLAY_SIGNED))
										usdata.i = *(int16_t *)&(usdata.s[0]);
									if ((usdata.i > opt_data.self_test_spec_max) ||
										(usdata.i < opt_data.self_test_spec_min)) {
										bTestPass = false;
										fail_p.rx = (i % rx_num) + 1;
										fail_p.tx = i/rx_num + 1;
										fail_p.v = usdata.i;
									}
									hx_printf(" %6d", (usdata.i));
								}

								debug_start_loc = header + (rx_num * tx_num) * 2;
								for (int i = 0; i < (rx_num + tx_num); i++) {
									if ((i % rx_num) == 0)
										hx_printf("\n DEBUG:");
									hx_printf(" %6d", ((int16_t)frame[debug_start_loc + i * 2]) + (((int16_t)frame[debug_start_loc + i * 2 + 1]) << 8));
								}
								hx_printf("\n");
								break;
							} else {
								usleep(16 * 1000);
							}
						} else {
							break;
						}
					}

					if (is_opt_set(&opt_data, OPTION_HID_SELF_TEST)) {
						if (bSelfTestCompleted) {
							if (bTestPass) {
								printf("Self test of 0x%02X PASS!\n", opt_data.param.i);
							} else {
								printf("Self test of 0x%02X Failed! (rx:%d, tx:%d) : %d\n",
								opt_data.param.i, fail_p.rx, fail_p.tx, fail_p.v);
							}
						}

						stSz = hx_hid_get_size_by_id(HID_SELF_TEST_ID);
						if (stSz > 0) {
							cmd = (uint8_t *)malloc(stSz);
							if (cmd != NULL) {
								cmd[0] = 0x01;
								ret = hx_hid_set_feature(HID_SELF_TEST_ID, cmd, stSz);
								free(cmd);
							}
						}
					}

					free(frame);
				}
			} else {
				ret = -ENODATA;
			}
		} else {
			hx_printf("ID parsing failed, return!\n");
			ret = -ENODATA;
		}
	} else {
		return -ENODEV;
	}

DIAG_FUNC_END:
	hx_hid_close();

	return ret;
}

int hid_set_input_RD_en(OPTDATA& opt_data, DEVINFO& dinfo)
{
	int ret;
	uint8_t read_back[4] = {0};

	if (hx_scan_open_hidraw(opt_data) == 0) {
		if (hx_hid_parse_RD_for_idsz(opt_data) == 0) {
			int sz = hx_hid_get_size_by_id(HID_INPUT_RD_EN_ID);
			if (sz > 0) {
				ret = hx_hid_get_feature(HID_INPUT_RD_EN_ID, read_back, sz);
				if (ret < 0) {
					hx_printf("Read back failed!\n");
					ret = -EIO;
				} else {
					hx_printf("current : %d\n", read_back[0]);
				}
				uint32_t en = opt_data.input_en.b[0];
				if (en != read_back[0]) {
					ret = hx_hid_set_feature(HID_INPUT_RD_EN_ID, (uint8_t *)&en, sz);
					if (ret < 0) {
						ret = -EIO;
						goto END_SET_RD_EN;
					}
					hx_printf("set ID %d to %d\n", HID_INPUT_RD_EN_ID, en);
					ret = hx_hid_get_feature(HID_INPUT_RD_EN_ID, read_back, sz);
					if (ret < 0) {
						hx_printf("Read back failed!\n");
						ret = -EIO;
					} else {
						hx_printf("Read ID %d back : %X\n", HID_INPUT_RD_EN_ID, read_back[0]);
						opt_data.options |= OPTION_REBIND;
						ret = 0;
					}
				}
			} else {
				ret = -ENOENT;
			}
		} else {
			ret = -ENOENT;
		}
END_SET_RD_EN:
		hx_hid_close();
		return ret;
	} else {
		return -ENODEV;
	}
}

int hid_update_DEVINFO(DEVINFO& oinfo)
{
	int found = 0;
	int dev_no = 0;
	int fd = 0;
	int ret;
	static char hidraw_path[64];
	char dev_dir[] = "/dev";
	struct hidraw_devinfo dinfo;

	fd = hx_get_hid_fd();
	if (fd > 0) {
		ret = ioctl(fd, HIDIOCGRAWINFO, &dinfo);
		if (ret != 0) {
			hx_printf("failed to get info from %s!\n", hidraw_path);
			return -EBADF;
		} else {
			oinfo.pid = dinfo.product;
			oinfo.vid = dinfo.vendor;
			return 0;
		}
	} else {
		do {
			memset(hidraw_path, 0, sizeof(hidraw_path));
			snprintf(hidraw_path, sizeof(hidraw_path), "%s/hidraw%d", dev_dir, dev_no);

			if (access(hidraw_path, F_OK) != 0) {
				hx_printf("f%s device node not exist!\n", hidraw_path);
				break;
			}

			fd = open(hidraw_path, O_RDWR|O_DSYNC);
			if (fd < 0) {
				hx_printf("failed to open %s!\n", hidraw_path);
				dev_no++;
				continue;
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
				break;
			} else {
				close(fd);
			}
			dev_no++;
		} while(dev_no < 10);

		if (found == 0)
			return -EIO;
		else {
			oinfo.pid = dinfo.product;
			oinfo.vid = dinfo.vendor;
			close(fd);
		}

	}

	// hx_printf("Scan HIDRAW device in %s ...\n", dev_dir);

	return 0;
}

int hid_polling_partial_data(OPTDATA& optdata, bool& loopEn)
{
	int ret = 0;
	int partial_data_sz = 0;
	unsigned int buffer_sz = 0;
	bool display_data = false;
	int save_fd = -1;
	uint8_t *partial_data = NULL;
	int total_sz = 0;
	int full_cycle = 0;
	uint16_t value;
	char* buffer = NULL;
	int stringLen = 0;

	if (hx_scan_open_hidraw(optdata) < 0) {
		return -EIO;
	}

	if (hx_hid_parse_RD_for_idsz(optdata) < 0) {
		ret = -EFAULT;
		goto SETUP_FAILED;
	}

	partial_data_sz = hx_hid_get_size_by_id(HID_TOUCH_MONITOR_PARTIAL_ID);
	if (partial_data_sz <= 0) {
		hx_printf("No partial data ID in RD!\n");
		ret = -EFAULT;
		goto SETUP_FAILED;
	}

	if (hid_update_fw_info(optdata) != 0) {
		hx_printf("Get HID_CFG_ID failed!\n");
		ret = -EFAULT;
		goto SETUP_FAILED;
	}
	total_sz = ((int)optdata.hid_info.rx * (int)optdata.hid_info.tx + (int)optdata.hid_info.rx + (int)optdata.hid_info.tx) * 2;

	if (is_opt_set(&optdata, OPTION_OUTPUT_PATH)) {
		save_fd = open(optdata.output_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
		if (save_fd < 0) {
			hx_printf("Open %s failed!\n", optdata.output_path);
			ret = -EFAULT;
			goto SETUP_FAILED;
		}
	}

	partial_data = (uint8_t *)malloc((unsigned int)partial_data_sz);
	if (partial_data == NULL) {
		hx_printf("Allocate memory for partial data failed!\n");
		ret = -ENOMEM;
		goto ALLOCATE_FAILED;
	}

	if (is_opt_set(&optdata, OPTION_HID_PARTIAL_DISPLAY) || is_opt_set(&optdata, OPTION_OUTPUT_PATH)) {
		buffer_sz = (((unsigned int)partial_data_sz - 1) / 2 - 2) * 7 + 50 + 1;
		buffer = (char *)malloc(buffer_sz);

		if (buffer == NULL) {
			hx_printf("Allocate memory for string buffer failed!\n");
			ret = -ENOMEM;
			goto ALLOCATE_BUF_FAILED;
		}
		stringLen = buffer_sz;
	}

	if (is_opt_set(&optdata, OPTION_HID_PARTIAL_DISPLAY))
		display_data = true;

	full_cycle = total_sz / (((unsigned int)partial_data_sz - 1) / 2 - 2);
	if ((total_sz % (((unsigned int)partial_data_sz - 1) / 2 - 2)) > 0)
		full_cycle++;
	hx_printf("total_sz = %d, partial_data_sz = %d, full_cycle = %d\n", total_sz, partial_data_sz, full_cycle);

	while (loopEn) {
		ret = hx_hid_get_feature(HID_TOUCH_MONITOR_PARTIAL_ID, partial_data, partial_data_sz);
		if (ret != 0) {
			hx_printf("Get partial data failed!\n");
			usleep(100);
			continue;
		}

		if (partial_data[0] > full_cycle) {
			hx_printf("index overflow(%02X)! Ignore.\n", partial_data[0]);
			usleep(100);
			continue;
		}

		if (buffer != NULL) {
			memset(buffer, 0, buffer_sz);
			stringLen = 0;
			stringLen += snprintf(buffer + stringLen, buffer_sz - stringLen, "%02X (%02X %02X %02X %02X) : ", partial_data[0], partial_data[1], partial_data[2], partial_data[3], partial_data[4]);
			for (unsigned int i = 5; i < (unsigned int)partial_data_sz; i += 2) {
				value = (uint16_t)partial_data[i] | ((uint16_t)partial_data[i + 1] << 8);
				stringLen += snprintf(buffer + stringLen, buffer_sz - stringLen, "%5d ", value);
			}
			stringLen += snprintf(buffer + stringLen, buffer_sz - stringLen, "\n");

			if (display_data) {
				hx_printf("%s", buffer);
			}

			if (save_fd >= 0) {
				ret = (int)write(save_fd, buffer, strlen(buffer));
				if (ret != (int)strlen(buffer)) {
					hx_printf("Write partial data to file failed!\n");
					break;
				}
			}
		}

		usleep(optdata.partial_en_polling_rate * 1000);
	}

	free(buffer);
ALLOCATE_BUF_FAILED:
	free(partial_data);
ALLOCATE_FAILED:
	if (save_fd >= 0)
		close(save_fd);
SETUP_FAILED:
	hx_hid_close();

	return ret;
}

static void print_data(OPTDATA& opt_data, float *frame, int32_t rx_num, int32_t tx_num, bool printInt = false)
{
	hx_printf("       ");
	for(int i = 0; i < rx_num; i++) {
		hx_printf(" RX[%02d]", i + 1);
	}
	for (int i = 0; i < (rx_num * tx_num); i++) {
		if ((i % rx_num) == 0)
			hx_printf("\nTX[%02d]:", i/rx_num + 1);

		if (printInt)
			hx_printf(" %6d", *(int16_t *)&frame[i]);
		else
			hx_printf(" %6.2f", frame[i]);
	}
	hx_printf("\n");
}

static float frame_avg(float *frame, int32_t rx_num, int32_t tx_num)
{
	float avg = 0.0f;

	for (int i = 0; i < rx_num * tx_num; i++) {
		avg += frame[i];
	}

	return avg / (rx_num * tx_num);
}

struct pv_t {
	int32_t x;
	int32_t y;
	float v;
};

static struct pv_t* frame_max(float *frame, int32_t rx_num, int32_t tx_num)
{
	float max = -1000;
	int32_t x = 0;
	int32_t y = 0;
	static struct pv_t pv;

	for (int i = 0; i < rx_num * tx_num; i++) {
		if (frame[i] > max) {
			max = frame[i];
			x = (i / rx_num);
			y = (i % rx_num);
		}
	}

	pv.x = x;
	pv.y = y;
	pv.v = max;

	return &pv;
}

static void frame_sqrt(float *in, float *out, uint32_t sz)
{
	for (uint32_t i = 0; i < sz; i++) {
		out[i] = sqrt(in[i]);
	}
}

static float snr_cal(float signal, float noise)
{
	return 20 * log10(signal / noise);
}

int hid_snr_calculation(OPTDATA& opt_data)
{
	int ret = 0;
	int rx_num;
	int tx_num;
	int mutual_sz;
	uint8_t *frame = NULL;
	float *base_frame = NULL;
	float *f_tmp_frame = NULL;
	float *signal_frames = NULL;
	float *signal_average_frame = NULL;
	float *statistic_frames = NULL;
	int32_t n_frames;
	int32_t retry_cnt;
	float untouched_sd_avg;
	float untouched_sd_avg_max;
	float untouched_sd_max_avg;
	int16_t untouched_sd_max;
	float touched_avg_max;
	float touched_signal_avg;
	int16_t touched_max;
	float frame_signal;
	float block_signal;
	float noise_sd_avg;
	float noise_sd_max;
	// float max_snr;
	float max_avg_snr;
	float avg_snr;
	bool collected;
	int total_sz;
	int frame_sz;
	int stSz;
	bool bret;
	struct pv_t *pv;
	const int32_t retry_limit = 10;
	union {
		uint32_t i;
		uint16_t s[2];
		uint8_t b[4];
	} tmp_data;
	enum {
		touched_sd_frame = 0,
		un_touched_sd_frame,
		statics_MAX
	};
	enum {
		base_frame_idx = 0,
		signal_average_frame_idx,
		tmp_frame_idx,
		IDX_MAX
	};

	if (hx_scan_open_hidraw(opt_data) < 0) {
		return -EIO;
	}

	if (hx_hid_parse_RD_for_idsz(opt_data) < 0) {
		ret = -EFAULT;
		goto SETUP_FAILED;
	}

	stSz = hx_hid_get_size_by_id(HID_SELF_TEST_ID);
	if (stSz <= 0) {
		hx_printf("No HID_SELF_TEST_ID in RD!\n");
		ret = -EFAULT;
		goto SETUP_FAILED;
	}

	if (hid_update_fw_info(opt_data) != 0) {
		hx_printf("Get HID_CFG_ID failed!\n");
		ret = -EFAULT;
		goto SETUP_FAILED;
	} else {
		if (opt_data.hid_layout_info == 0) {
			hx_printf("IC layout error!\n");
			ret = -ENOMEM;
			goto SETUP_FAILED;
		}
		rx_num = opt_data.hid_layout_info->total_tx_rx.desc.layout.rx_num;
		tx_num = opt_data.hid_layout_info->total_tx_rx.desc.layout.tx_num;
	}

	mutual_sz = rx_num * tx_num;
	if (mutual_sz <= 0) {
		hx_printf("Mutual size is incorrect!\n");
		ret = -EFAULT;
		goto SETUP_FAILED;
	}

	frame_sz = hx_hid_get_size_by_id(HID_TOUCH_MONITOR_ID);
	if (frame_sz <= 0) {
		hx_printf("Size of HID_TOUCH_MONITOR_ID is incorrect!\n");
		ret = -EFAULT;
		goto SETUP_FAILED;
	}

	if (hx_hid_get_size_by_id(HID_TOUCH_MONITOR_ID) <= 0) {
		hx_printf("No HID_TOUCH_MONITOR_ID in RD!\n");
		ret = -EFAULT;
		goto SETUP_FAILED;
	}

	tmp_data.i = HID_DIAG_RAW_DATA;
	ret = hx_hid_set_feature(HID_TOUCH_MONITOR_SEL_ID, tmp_data.b, 4);
	if (ret < 0) {
		hx_printf("Set HID_TOUCH_MONITOR_SEL_ID to 0x%02X failed!\n", tmp_data.i);
		ret = -EFAULT;
		goto SET_DATA_TYPE_FAILED;
	}

	// Force Active
	uint8_t reg_n_data[9];
	reg_n_data[0] = 0x1;// 1: write reg
	opt_data.w_reg_addr.i = 0x10007FD4;
	opt_data.w_addr_size = 4;
	/* 0xABABABAB : force idle
	 * 0xCDCDCDCD : force active
	 * 0x00000000 : normal operation
	 */
	opt_data.w_reg_data.i = 0xCDCDCDCD;
	opt_data.w_data_size = 4;
	memcpy(reg_n_data + 1, &(opt_data.w_reg_addr.b[0]), opt_data.w_addr_size);
	memcpy(reg_n_data + 1 + 4, &(opt_data.w_reg_data.b[0]), opt_data.w_data_size);
	ret = hx_hid_set_feature(HID_REG_RW_ID, reg_n_data, sizeof(reg_n_data));
	if (ret < 0) {
		hx_printf("Set force active failed!\n");
		ret = -EFAULT;
		goto FORCE_ACTIVE_FAILED;
	}

	total_sz = mutual_sz * 2;
	frame = (uint8_t *)malloc(total_sz);
	if (frame == NULL) {
		hx_printf("Allocate memory for frame failed!\n");
		ret = -ENOMEM;
		goto ALLOCATE_FAILED;
	}

	base_frame = (float *)malloc(mutual_sz * sizeof(float) * IDX_MAX);
	if (base_frame == NULL) {
		hx_printf("Allocate memory for base frame failed!\n");
		ret = -ENOMEM;
		goto ALLOCATE_BASE_FAILED;
	}
	memset(base_frame, 0, mutual_sz * sizeof(float) * IDX_MAX);
	signal_average_frame = (float *)((uint8_t *)base_frame + mutual_sz * sizeof(float) * signal_average_frame_idx);
	f_tmp_frame = (float *)((uint8_t *)base_frame + mutual_sz * sizeof(float) * tmp_frame_idx);

	signal_frames = (float *)malloc(mutual_sz * sizeof(float) * opt_data.snr_signal_noise_frames);
	if (signal_frames == NULL) {
		hx_printf("Allocate memory for signal frames failed!\n");
		ret = -ENOMEM;
		goto ALLOCATE_SIGNAL_FAILED;
	}
	memset(signal_frames, 0, mutual_sz * sizeof(float) * opt_data.snr_signal_noise_frames);

	statistic_frames = (float *)malloc(mutual_sz * sizeof(float) * statics_MAX);
	if (statistic_frames == NULL) {
		hx_printf("Allocate memory for noise frames failed!\n");
		ret = -ENOMEM;
		goto ALLOCATE_STATISTIC_FAILED;
	}
	memset(statistic_frames, 0, mutual_sz * sizeof(float) * statics_MAX);

	hx_printf("Collecting un-touched data to calculate base data, please leave the panel clean!\n");
	hx_printf("Press ENTER when ready...\n");
	getchar();
	retry_cnt = 0;
	n_frames = 0;
	untouched_sd_max_avg = 0;
	untouched_sd_max = 0;
	collected = false;
	while (n_frames <= (opt_data.snr_base_frames + opt_data.snr_ignore_frames + opt_data.snr_signal_noise_frames)) {
		if (retry_cnt >= retry_limit) {
			hx_printf("Get base frame failed!\n");
			break;
		}

		bret = get_raw_data(frame_sz, HID_DIAG_RAW_DATA, true, false, stSz, frame, opt_data.hid_layout_info,
			opt_data.hid_layout_type,
			is_opt_set(&opt_data, OPTION_HID_RX_REVERSE),
			is_opt_set(&opt_data, OPTION_HID_TX_REVERSE), retry_limit, true, NULL);
		if (!bret) {
			hx_printf("Get frame failed!\n");
			goto GET_BASE_FAILED;
		}
		if (n_frames == (opt_data.snr_base_frames + opt_data.snr_ignore_frames + opt_data.snr_signal_noise_frames)) {
			for (int i = 0; i < mutual_sz; i++) {
				statistic_frames[un_touched_sd_frame * mutual_sz + i] =
					statistic_frames[un_touched_sd_frame * mutual_sz + i] / opt_data.snr_signal_noise_frames;
			}
			hx_printf("Base frame calculated, un-touched statistic calculated, total get %d frames and ignore %d frames\n",
				n_frames, opt_data.snr_ignore_frames);
			hx_printf("Base frame:\n");
			print_data(opt_data, base_frame, rx_num, tx_num, true);
			hx_printf("Un-touched statistic:\n");
			hx_printf("SD frame:\n");
			frame_sqrt(&statistic_frames[un_touched_sd_frame * mutual_sz],
				f_tmp_frame, mutual_sz);
			print_data(opt_data, f_tmp_frame, rx_num, tx_num);

			untouched_sd_avg = frame_avg(f_tmp_frame, rx_num, tx_num);
			untouched_sd_avg_max = frame_max(f_tmp_frame, rx_num, tx_num)->v;
			hx_printf("Un-touched Standard Deviation Noise AVG: %f, "
				"Standard Deviation Noise MAX: %f\n",
				untouched_sd_avg, untouched_sd_avg_max);

			hx_printf("Un-touched Average of Max Noise: %f, Max noise: %d\n", untouched_sd_max_avg, untouched_sd_max);

			collected = true;
			break;
		} else if (n_frames >= (opt_data.snr_ignore_frames + opt_data.snr_base_frames)) {
			uint16_t *tmp_frame = (uint16_t *)(frame + frame_sz);
			float tmp;
			float max = -1000;
			if (n_frames == (opt_data.snr_ignore_frames + opt_data.snr_base_frames)) {
				for (int i = 0; i < mutual_sz; i++) {
					base_frame[i] = base_frame[i] / (float)opt_data.snr_base_frames;
				}
			}
			// calculate Standard Deviation
			for (int i = 0; i < mutual_sz; i++) {
				tmp = (float)tmp_frame[i] - base_frame[i];
				if (tmp > max)
					max = tmp;
				if (tmp > untouched_sd_max)
					untouched_sd_max = tmp;
				tmp *= tmp;
				statistic_frames[un_touched_sd_frame * mutual_sz + i] += tmp;
			}
			untouched_sd_max_avg += max;
		} else if (n_frames >= (opt_data.snr_ignore_frames)) {
			uint16_t *tmp_frame = (uint16_t *)(frame);
			for (int i = 0; i < mutual_sz; i++) {
				base_frame[i] += tmp_frame[i];
			}
		}
		n_frames++;
	}
	if (collected) {
		hx_printf("Start SNR test, please put the finger at desire position on panel and keep the position.\n");
		hx_printf("Press ENTER when ready...\n");
		getchar();
		retry_cnt = 0;
		n_frames = 0;
		collected = false;
		int32_t sig_idx = 0;
		while (n_frames <= opt_data.snr_signal_noise_frames + opt_data.snr_ignore_frames) {
			if (retry_cnt >= retry_limit) {
				hx_printf("Get base frame failed!\n");
				break;
			}

			bret = get_raw_data(frame_sz, HID_DIAG_RAW_DATA, true, false, stSz, frame,
				opt_data.hid_layout_info, opt_data.hid_layout_type,
				is_opt_set(&opt_data, OPTION_HID_RX_REVERSE), is_opt_set(&opt_data, OPTION_HID_TX_REVERSE),
				retry_limit, true, NULL);
			if (!bret) {
				hx_printf("Get frame failed!\n");
				goto GET_BASE_FAILED;
			}
			if (n_frames == (opt_data.snr_signal_noise_frames + opt_data.snr_ignore_frames)) {
				hx_printf("Touched frames collected, total get %d frames and ignore %d frames\n",
					n_frames, opt_data.snr_ignore_frames);
				collected = true;
				break;
			} else if (n_frames >= (opt_data.snr_ignore_frames)) {
				uint16_t *tmp_frame;
				float tmp;
				for (int i = 0; i < mutual_sz; i++) {
					tmp_frame = (uint16_t *)(frame);
					tmp = tmp_frame[i];
					tmp = tmp - base_frame[i];

					// if (tmp < opt_data.snr_touch_threshold) {
					// 	tmp = 0;
					// }

					signal_frames[sig_idx * mutual_sz + i] = tmp;
					signal_average_frame[i] += signal_frames[sig_idx * mutual_sz + i];
					// signal_average_frame[i] += fabs(signal_frames[sig_idx * mutual_sz + i]);
				}
				// print_data(opt_data, &(signal_frames[sig_idx * mutual_sz]), rx_num, tx_num);
				sig_idx++;
			}
			n_frames++;
		}
		for (int i = 0; i < mutual_sz; i++) {
			signal_average_frame[i] = signal_average_frame[i] / sig_idx;
		}

		touched_avg_max = 0;
		touched_max = 0;
		frame_signal = 0.0f;
		block_signal = 0.0f;
		touched_signal_avg = 0.0f;
		if (collected) {
			int32_t x;
			int32_t y;
			hx_printf("Signal average frame:\n");
			print_data(opt_data, signal_average_frame, rx_num, tx_num);
			for (int i = 0; i < opt_data.snr_signal_noise_frames; i++) {
				float tmp;
				float max = 0;
				// print_data(opt_data, (uint16_t *)&(signal_frames[i * mutual_sz]), rx_num, tx_num, false);
				pv = frame_max(&(signal_frames[i * mutual_sz]), rx_num, tx_num);
				if (i == 0) {
					x = pv->x;
					y = pv->y;
					frame_signal = pv->v;
					block_signal = pv->v;
				} else {
					frame_signal += pv->v;
					block_signal += signal_frames[i * mutual_sz + x * rx_num + y];
				}

				// calculate Standard deviation
				float local_avg = 0.0f;
				int32_t touched_block_count = 0;
				for (int j = 0; j < mutual_sz; j++) {
					tmp = signal_frames[i * mutual_sz + j];
					if (opt_data.snr_touch_threshold >= 0) {
						if (tmp > opt_data.snr_touch_threshold) {
							touched_block_count++;
							local_avg += tmp;
						}
					} else {
						touched_block_count++;
						local_avg += tmp;
					}
					if (tmp > max)
						max = tmp;
					if (tmp > touched_max)
						touched_max = tmp;
					tmp -= signal_average_frame[j];
					tmp *= tmp;
					statistic_frames[touched_sd_frame * mutual_sz + j] += tmp;
				}
				touched_avg_max += max;
				touched_signal_avg += local_avg / touched_block_count;
			}
			for (int i = 0; i < mutual_sz; i++) {
				statistic_frames[touched_sd_frame * mutual_sz + i] =
					statistic_frames[touched_sd_frame * mutual_sz + i] / opt_data.snr_signal_noise_frames;
			}
			touched_avg_max = touched_avg_max / opt_data.snr_signal_noise_frames;
			touched_signal_avg = touched_signal_avg / opt_data.snr_signal_noise_frames;
			frame_signal = frame_signal / opt_data.snr_signal_noise_frames;
			block_signal = block_signal / opt_data.snr_signal_noise_frames;
			hx_printf("Touched statistic:\n");
			hx_printf("Noise SD frame:\n");
			frame_sqrt(&statistic_frames[touched_sd_frame * mutual_sz],
				f_tmp_frame, mutual_sz);
			print_data(opt_data, f_tmp_frame, rx_num, tx_num);
			noise_sd_avg = frame_avg(f_tmp_frame, rx_num, tx_num);
			noise_sd_max = frame_max(f_tmp_frame, rx_num, tx_num)->v;
			hx_printf("Noise SD AVG: %f, Noise SD MAX: %f\n",
				noise_sd_avg, noise_sd_max);

			hx_printf("Touched Average of Max Noise: %f, Max noise: %d\n", touched_avg_max, touched_max);

			hx_printf("[Signal]Touched Signal=> average MAX signal: %f, average signal: %f\n",
				frame_signal, touched_signal_avg);
			hx_printf("[Noise]Un-touched Standard Deviation Noise AVG: %f\n", untouched_sd_avg);

			// max_snr = snr_cal(block_signal, untouched_sd_avg);
			max_avg_snr = snr_cal(frame_signal, untouched_sd_avg);
			avg_snr = snr_cal(touched_signal_avg, untouched_sd_avg);

			hx_printf("TouchedSignal-to-UntouchedNoiseSD SNR:\n");
			hx_printf("Average of MAX SNR: %f, Average SNR: %f\n", max_avg_snr, avg_snr);

			// max_snr = snr_cal(block_signal, noise_sd_avg);
			// max_avg_snr = snr_cal(frame_signal, noise_sd_avg);
			// avg_snr = snr_cal(touched_signal_avg, noise_sd_avg);

			// hx_printf("TouchedSignal-to-TouchedNoise SNR:\n");
			// hx_printf("[SD base]Max SNR: %f, Max of Average SNR: %f, Average SNR: %f\n", max_snr, max_avg_snr, avg_snr);
		}
	}

GET_BASE_FAILED:
	free(statistic_frames);
ALLOCATE_STATISTIC_FAILED:
	free(signal_frames);
ALLOCATE_SIGNAL_FAILED:
	free(base_frame);
ALLOCATE_BASE_FAILED:
	free(frame);
ALLOCATE_FAILED:
	opt_data.w_reg_data.i = 0;
	memcpy(reg_n_data + 1 + 4, &(opt_data.w_reg_data.b[0]), opt_data.w_data_size);
	ret = hx_hid_set_feature(HID_REG_RW_ID, reg_n_data, sizeof(reg_n_data));
	if (ret < 0) {
		hx_printf("Set normal mode failed!\n");
	}
FORCE_ACTIVE_FAILED:
	tmp_data.i = HID_DIAG_NORAML_DATA;
	ret = hx_hid_set_feature(HID_TOUCH_MONITOR_SEL_ID, tmp_data.b, 4);
	if (ret < 0) {
		hx_printf("Set HID_TOUCH_MONITOR_SEL_ID to 0x%02X failed!\n", tmp_data.i);
	}
SET_DATA_TYPE_FAILED:
SETUP_FAILED:
	hx_hid_close();

	return ret;
}

int hid_himax_identify(OPTDATA& opt_data)
{
	const char hx_identy[] = "HXHIDI2C";
	int ret;
	int id_sz;
	uint8_t temp[12] = {0};

	if (hx_scan_open_hidraw(opt_data) == 0) {
		if (hx_hid_parse_RD_for_idsz(opt_data) == 0) {
			id_sz = hx_hid_get_size_by_id(HID_HIMAX_IDENT_ID);
			if (id_sz > 0)
				ret = hx_hid_get_feature(HID_HIMAX_IDENT_ID, temp, id_sz);
			else {
				printf("No 0x%02X in RD!\n", HID_HIMAX_IDENT_ID);
				ret = -ENOENT;
				goto SETUP_FAILED;
			}

			if (ret < 0) {
				printf("Get 0x%02X failed!\n", HID_HIMAX_IDENT_ID);
				ret = -EFAULT;
				goto SETUP_FAILED;
			}
			hx_printf("Read back : ");
			for (int i = 0; i < id_sz; i++) {
				hx_printf("%c ", temp[i]);
			}
			hx_printf("\n");
			if (memcmp(temp, hx_identy, id_sz) == 0) {
				printf("Himax device found!\n");
				ret = 0;
			} else {
				printf("Himax device not found!\n");
				ret = -ENODEV;
			}
		} else {
			ret = -ENOENT;
		}
SETUP_FAILED:
		hx_hid_close();
		return ret;
	} else {
		printf("No Himax device found!\n");
		return -ENODEV;
	}
}

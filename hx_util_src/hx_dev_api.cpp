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
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>
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

uint8_t hx_buf[FLASH_RW_MAX_LEN];

int himax_free_fw(HXFW *fwp)
{
	if (fwp) {
		if (fwp->data) {
			free(fwp->data);
			printf("free fw data\n");
		}
	} else {
		printf("fwp is NULL\n");
		return 1;
	}

	return 0;
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
	ret = hx_i2c_write(hx_buf, 2);
	if (ret < 0) {
		fprintf(stderr, "%s: bus access fail!\n", __func__);
		return;
	}

	hx_buf[0] = ic_adr_incr4;
	hx_buf[1] = ic_cmd_incr4 | auto_add_4_byte;
	ret = hx_i2c_write(hx_buf, 2);
	if (ret < 0) {
		fprintf(stderr, "%s: bus access fail!\n", __func__);
		return;
	}
}

int himax_register_read(uint32_t addr, uint8_t *buf, uint32_t len)
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
	ret = hx_i2c_write(hx_buf, 5);
	if (ret < 0) {
		fprintf(stderr, "set address fail\n");
		return ret;
	}

//	hx_buf[0] = 0x0C;
//	hx_buf[1] = 0x00;
	hx_buf[0] = ic_adr_ahb_access_direction;
	hx_buf[1] = ic_cmd_ahb_access_direction_read;
	ret = hx_i2c_write(hx_buf, 2);
	if (ret < 0) {
		fprintf(stderr, "set direction fail\n");
		return ret;
	}

//	hx_buf[0] = 0x08;
	hx_buf[0] = ic_adr_ahb_rdata_byte_0;
	ret = hx_i2c_read(hx_buf, 1, buf, len);
	if (ret < 0) {
		fprintf(stderr, "read data fail\n");
		return ret;
	}

	return 0;
}

int himax_register_write(uint32_t addr, uint8_t *val, uint32_t len)
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
	ret = hx_i2c_write(hx_buf, len+5);
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

int himax_update_check(HXFW *fwp, hx_hid_info* hid_info = NULL)
{
	uint8_t *dp = NULL;
	uint16_t i;
	uint16_t j;
	uint16_t checksum;
	uint8_t count;
	uint32_t map_code = 0;
	unsigned long faddr = 0;
	uint8_t tmp_data[4];
	uint32_t fw_ver_ic = 0;
	uint32_t fw_ver_bin = 0;

	if (hid_info == NULL) {
		himax_register_read(ic_adr_cs_central_state, tmp_data, 4);
		if (tmp_data[0] != 0x05) {
			printf("ic state = %X\n", tmp_data[0]);
			return 1;
		} else {
			himax_register_read(fw_addr_fw_vendor_addr, tmp_data, 4);
			fw_ver_ic = tmp_data[2]<<8 | tmp_data[3];
		//	printf("fw_ver_ic = %08X\n", fw_ver_ic);
		}
	} else {
		fw_ver_ic = (hid_info->cid[0] << 8) | hid_info->cid[1];
	}

	dp = fwp->data;

	if (!(dp[0] == 0x00 && dp[1] == 0x00
	&& dp[2] == 0x00 && dp[3] == 0x00
	&& dp[4] == 0x00 && dp[5] == 0x00
	&& dp[6] == 0x00 && dp[7] == 0x00
	&& dp[14] == 0x87)) {
		printf("there is no fw header, force update\n");
		return 1;
	}

	for (i = 0; i < 1024; i += 16) {
		count = 0;
		checksum = 0;
		for (j = i; j < i+16; j++) {
			if (dp[j] == 0)
				count++;
			checksum += dp[j];
		}

		if (count == 16) {
			printf("header end in %d, did not find version\n", i);
			return 1;
		} else if (checksum % 0x100) {
			printf("checksum fail in %d\n", i);
		} else {
			map_code = dp[i] + (dp[i+1]<<8) + (dp[i+2]<<16) + (dp[i+3]<<24);
			faddr = dp[i+4] + (dp[i+5]<<8) + (dp[i+6]<<16) + (dp[i+7]<<24);
			if (map_code == 0x10000000) {
				fw_ver_bin = dp[faddr]<<8 | dp[faddr+1];
			//	printf("fw_ver_bin = %08X\n", fw_ver_bin);
				break;
			}
		}
	}

	printf("fw_ver_bin = %08X; fw_ver_ic = %08X\n", fw_ver_bin, fw_ver_ic);

	if (fw_ver_bin > fw_ver_ic)
		return 1;

	return 0;
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

	himax_register_write(flash_addr_spi200_trans_fmt, trans_fmt, 4);

	do {
		himax_register_write(flash_addr_spi200_trans_ctrl,
			trans_ctrl1, 4);

		himax_register_write(flash_addr_spi200_cmd, cmd1, 4);

		tmp_data[0] = tmp_data[1] = tmp_data[2] = tmp_data[3] = 0xFF;
		himax_register_read(flash_addr_spi200_data,
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
	himax_register_write(pic_op->addr_psl, pic_op->data_rst,
		sizeof(pic_op->data_rst));
	printf("%s: power saving level reset OK!\n", __func__);
}
#endif
static void himax_system_reset(void)
{
	int ret = 0;
	uint8_t tmp_data[4];
	int retry = 0;

	uint8_t data_clear[4] = {0};

	himax_register_write(fw_addr_ctrl_fw, data_clear, 4);
	do {
		/* reset code*/
		/**
		 * I2C_password[7:0] set Enter safe mode : 0x31 ==> 0x27
		 */
		hx_buf[0] = ic_adr_i2c_psw_lb;
		hx_buf[1] = ic_cmd_i2c_psw_lb;
		ret = hx_i2c_write(hx_buf, 2);
		if (ret < 0)
			printf("%s: bus access fail!\n", __func__);

		/**
		 * I2C_password[15:8] set Enter safe mode :0x32 ==> 0x95
		 */
		hx_buf[0] = ic_adr_i2c_psw_ub;
		hx_buf[1] = ic_cmd_i2c_psw_ub;
		ret = hx_i2c_write(hx_buf, 2);
		if (ret < 0)
			printf("%s: bus access fail!\n", __func__);

		/**
		 * I2C_password[7:0] set Enter safe mode : 0x31 ==> 0x00
		 */
		hx_buf[0] = ic_adr_i2c_psw_lb;
		hx_buf[1] = 0x00;
		ret = hx_i2c_write(hx_buf, 2);
		if (ret < 0)
			printf("%s: bus access fail!\n", __func__);

		usleep(10000);

		himax_register_read(fw_addr_flag_reset_event, tmp_data, 4);
		printf("%s:Read status from IC = %X,%X\n", __func__, tmp_data[0], tmp_data[1]);
	} while ((tmp_data[1] != 0x02 || tmp_data[0] != 0x00) && retry++ < 5);
}

static void himax_sense_on(uint8_t FlashMode)
{
	int ret = 0;

	uint8_t data_clear[4] = {0};

	printf("Enter %s\n", __func__);

	himax_register_write(fw_addr_ctrl_fw, data_clear, 4);
	usleep(10000);
	if (!FlashMode) {
		himax_system_reset();
	} else {
		hx_buf[0] = ic_adr_i2c_psw_lb;
		hx_buf[1] = 0x00;
		ret = hx_i2c_write(hx_buf, 2);
		if (ret < 0) {
			printf("%s: cmd=%x bus access fail!\n",
			__func__, ic_adr_i2c_psw_lb);
		}

		hx_buf[0] = ic_adr_i2c_psw_ub;
		hx_buf[1] = 0X00;
		ret = hx_i2c_write(hx_buf, 2);
		if (ret < 0) {
			printf("%s: cmd=%x bus access fail!\n",
				__func__, ic_adr_i2c_psw_ub);
		}
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
			himax_register_write(fw_addr_ctrl_fw, fw_stop, 4);

		usleep(10000);

		/* check fw status */
		himax_register_read(ic_adr_cs_central_state, tmp_data, 4);
		if (tmp_data[0] != 0x05) {
			printf("%s: Do not need wait FW, Status = 0x%02X!\n",
					__func__, tmp_data[0]);
			break;
		}

		himax_register_read(fw_addr_ctrl_fw, tmp_data, 4);

		printf("%s: cnt = %d, data[0] = 0x%02X!\n", __func__, cnt, tmp_data[0]);

	} while (tmp_data[0] != 0x87 && (++cnt < 35) && check_en == true);

	cnt = 0;

	do {
		/**
		 *I2C_password[7:0] set Enter safe mode : 0x31 ==> 0x27
		 */
		hx_buf[0] = ic_adr_i2c_psw_lb;
		hx_buf[1] = ic_cmd_i2c_psw_lb;
		ret = hx_i2c_write(hx_buf, 2);
		if (ret < 0) {
			printf("%s: bus access fail!\n", __func__);
			return false;
		}

		/**
		 *I2C_password[15:8] set Enter safe mode :0x32 ==> 0x95
		 */
		hx_buf[0] = ic_adr_i2c_psw_ub;
		hx_buf[1] = ic_cmd_i2c_psw_ub;
		ret = hx_i2c_write(hx_buf, 2);
		if (ret < 0) {
			printf("%s: bus access fail!\n", __func__);
			return false;
		}

		/**
		 *Check enter_save_mode
		 */
		himax_register_read(ic_adr_cs_central_state, tmp_data, 4);
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
			himax_register_write(ic_adr_tcon_on_rst, tmp_data, 4);
			usleep(1000);
			return true;
		}
		usleep(5000);
	} while (cnt++ < 5);

	return false;
}

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
	himax_register_write(ic_adr_psl, psl_rst, 4);
	printf("%s: power saving level reset OK!\n", __func__);

	himax_register_write(flash_addr_spi200_trans_fmt,
		trans_fmt, 4);

	for (page_prog_start = start_addr;
	page_prog_start < start_addr + length;
	page_prog_start = page_prog_start + sector_size) {
		himax_register_write(flash_addr_spi200_trans_ctrl,
			trans_ctrl2, 4);
		himax_register_write(flash_addr_spi200_cmd,
			cmd2, 4);

		tmp_data[3] = (page_prog_start >> 24)&0xFF;
		tmp_data[2] = (page_prog_start >> 16)&0xFF;
		tmp_data[1] = (page_prog_start >> 8)&0xFF;
		tmp_data[0] = page_prog_start&0xFF;
		himax_register_write(flash_addr_spi200_addr,
			tmp_data, 4);

		himax_register_write(flash_addr_spi200_trans_ctrl,
			trans_ctrl3, 4);
		himax_register_write(flash_addr_spi200_cmd,
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
#if 0
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
	himax_register_write(ic_adr_psl, psl_rst, 4);
	printf("%s: power saving level reset OK!\n", __func__);

	himax_register_write(flash_addr_spi200_trans_fmt,
		trans_fmt, 4);

	for (page_prog_start = start_addr;
	page_prog_start < start_addr + length;
	page_prog_start = page_prog_start + block_size) {
		himax_register_write(flash_addr_spi200_trans_ctrl,
			trans_ctrl2, 4);
		himax_register_write(flash_addr_spi200_cmd,
			cmd2, 4);

		tmp_data[3] = (page_prog_start >> 24)&0xFF;
		tmp_data[2] = (page_prog_start >> 16)&0xFF;
		tmp_data[1] = (page_prog_start >> 8)&0xFF;
		tmp_data[0] = page_prog_start&0xFF;
		himax_register_write(flash_addr_spi200_addr,
			tmp_data, 4);

		himax_register_write(flash_addr_spi200_trans_ctrl,
			trans_ctrl3, 4);
		himax_register_write(flash_addr_spi200_cmd,
			cmd4, 4);
		usleep(200000);

		if (!himax_wait_wip(100)) {
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

	himax_register_write(flash_addr_spi200_trans_fmt,
		trans_fmt, 4);

	for (page_prog_start = 0; page_prog_start < FW_Size;
	page_prog_start += FLASH_RW_MAX_LEN) {
		himax_register_write(flash_addr_spi200_trans_ctrl,
			trans_ctrl2, 4);
		himax_register_write(flash_addr_spi200_cmd,
			cmd2, 4);

		 /*Programmable size = 1 page = 256 bytes,*/
		 /*word_number = 256 byte / 4 = 64*/
		himax_register_write(flash_addr_spi200_trans_ctrl,
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
		himax_register_write(flash_addr_spi200_addr,
			tmp_data, 4);

		ret = himax_register_write(flash_addr_spi200_data,
			&FW_content[page_prog_start], 16);
		if (ret < 0) {
			printf("%s: bus access fail!\n", __func__);
			return;
		}

		himax_register_write(flash_addr_spi200_cmd,
			cmd6, 4);

	//	for (i = 0; i < 5; i++) {
	//		ret = himax_register_write(flash_addr_spi200_data,
	//			&FW_content[page_prog_start+16+(i*PROGRAM_SZ)],
	//			PROGRAM_SZ);
	//		if (ret < 0) {
	//			printf("%s: bus access fail!\n", __func__);
	//			return;
	//		}
	//	}

		ret = himax_register_write(flash_addr_spi200_data,
			&FW_content[page_prog_start+16], 240);
		if (ret < 0) {
			printf("%s: bus access fail!\n", __func__);
			return;
		}

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

	ret = himax_register_write(fw_addr_reload_addr_from,
		tmp_addr, 4);
	if (ret < 0) {
		printf("%s: bus access fail!\n", __func__);
		return 1;
	}

	tmp_data[3] = 0x00;
	tmp_data[2] = 0x99;
	tmp_data[1] = (length >> 8);
	tmp_data[0] = length;
	ret = himax_register_write(fw_addr_reload_addr_cmd_beat,
		tmp_data, 4);
	if (ret < 0) {
		printf("%s: bus access fail!\n", __func__);
		return 1;
	}
	cnt = 0;

	do {
		ret = himax_register_read(fw_addr_reload_status,
			tmp_data, 4);
		if (ret < 0) {
			printf("%s: bus access fail!\n", __func__);
			return 1;
		}

		if ((tmp_data[0] & 0x01) != 0x01) {
			ret = himax_register_read(fw_addr_reload_crc32_result,
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

int himax_fw_update(uint8_t *fw, uint32_t len)
{
	int result = -1;
	uint8_t tmp_data[4] = {0x01, 0x00, 0x00, 0x00};

	himax_system_reset();

	himax_sense_off(true);

//	himax_flash_speed_set(HX_FLASH_SPEED_12p5M);
	himax_register_write(flash_clk_setup_addr, tmp_data, 4);

	himax_flash_sector_erase(0x00, len);

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

	himax_register_read(fw_addr_fw_dbg_msg_addr, data_t, 4);
	printf("0x%08X = 0x%02X, 0x%02X, 0x%02X, 0x%02X\n",
		fw_addr_fw_dbg_msg_addr, data_t[0], data_t[1], data_t[2], data_t[3]);

	himax_register_read(fw_addr_chk_fw_status, data_t, 4);
	printf("0x%08X = 0x%02X, 0x%02X, 0x%02X, 0x%02X\n",
		fw_addr_chk_fw_status, data_t[0], data_t[1], data_t[2], data_t[3]);

	himax_register_read(fw_addr_chk_dd_status, data_t, 4);
	printf("0x%08X = 0x%02X, 0x%02X, 0x%02X, 0x%02X\n",
		fw_addr_chk_dd_status, data_t[0], data_t[1], data_t[2], data_t[3]);

	himax_register_read(fw_addr_flag_reset_event, data_t, 4);
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
	himax_register_write(fw_addr_raw_out_sel,
		data_clear, 4);
	/*DSRAM func initial*/
	himax_register_write(fw_addr_sorting_mode_en,
		data_clear, 4);
	/*N frame initial*/
	/* reset N frame back to default value 1 for normal mode */
	himax_register_write(fw_addr_set_frame_addr, tmp_data, 4);
	/*FW reload done initial*/
	himax_register_write(driver_addr_fw_define_2nd_flash_reload,
		data_clear, 4);

	himax_sense_on(0x00);

	printf("%s: waiting for FW reload data\n", __func__);

	while (retry++ < 30) {
		himax_register_read(driver_addr_fw_define_2nd_flash_reload,
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

	himax_register_read(fw_addr_fw_ver_addr, data, 4);
	printf("PANEL_VER : %X\n", data[0]);
	printf("FW_VER : %X\n", (data[1] << 8 | data[2]));

	himax_register_read(fw_addr_fw_cfg_addr, data, 4);
	printf("TOUCH_VER : %X\n", data[2]);
	printf("DISPLAY_VER : %X\n", data[3]);

//	himax_register_read(fw_addr_vid_pid_addr, data, 4);
//	printf("DEVICE VID : %X\n", data[0] << 8 | data[1]);
//	printf("DEVICE PID : %X\n", data[2] << 8 | data[3]);

	himax_register_read(fw_addr_fw_vendor_addr, data, 4);
	printf("CID_VER : %X\n", (data[2] << 8 | data[3]));

	himax_register_read(fw_addr_cus_info, data, 12);
	printf("Cusomer ID = %s\n", data);

	himax_register_read(fw_addr_proj_info, data, 12);
	printf("Project ID = %s\n", data);
}

int burn_firmware(DEVINFO *devp, OPTDATA *optp)
{
	int ret = 0;
	HXFW fw;
	uint8_t tmp_data[4] = {0};
	uint32_t burnlen = 0;

	if (!devp || !optp) {
		printf("%s: parameter error\n", __func__);
		return 1;
	}

	if (himax_load_fw(optp->fw_path, &fw)) {
		printf("load firmware fail\n");
		return 1;
	}

	if (himax_scan_device(optp)) {
		printf("scan device fail\n");
		ret = 1;
		goto exit;
	}

	// check communication with IC
	hx_buf[0] = ic_adr_conti;
	ret = hx_i2c_read(hx_buf, 1, tmp_data, 1);
	if (ret < 0) {
		printf("communication check fail\n");
		ret = 1;
		goto exit;
	}

	himax_register_read(fw_addr_vid_pid_addr, tmp_data, 4);
	devp->vid = tmp_data[0] << 8 | tmp_data[1];
	printf("vid = %X\n", devp->vid);
	devp->pid = tmp_data[2] << 8 | tmp_data[3];
	printf("pid = %X\n", devp->pid);
	himax_register_read(fw_addr_fw_id_ver_addr, tmp_data, 4);
	printf("fwid = %X\n", tmp_data[0] << 8 | tmp_data[1]);
	printf("fwver = %X\n", tmp_data[2] << 8 | tmp_data[3]);

	if(is_opt_set(optp, OPTION_CMP_VER)) {
		if (!himax_update_check(&fw)) {
			printf("don't need update\n");
			ret = 1;
			goto exit;
		}
	}

	if(is_opt_set(optp, OPTION_ALL_LEN))
		burnlen = fw.len;
	else
		burnlen = 0x3C000;

	printf("burn length is %d\n", burnlen);

//	himax_fw_update(fw.data, fw.len);
	himax_fw_update(fw.data, burnlen);

//	g_core_fp.fp_reload_disable(0);
	himax_parse_assign_cmd(driver_data_fw_define_flash_reload_en, tmp_data, 4);
	himax_register_write(driver_addr_fw_define_flash_reload, tmp_data, 4);

	ret = himax_power_on_init();
	if (!ret) {
		himax_read_fw_ver();
		himax_register_read(fw_addr_vid_pid_addr, tmp_data, 4);
		devp->vid = tmp_data[0] << 8 | tmp_data[1];
		printf("vid = %X\n", devp->vid);
		devp->pid = tmp_data[2] << 8 | tmp_data[3];
		printf("pid = %X\n", devp->pid);
		himax_register_read(fw_addr_fw_id_ver_addr, tmp_data, 4);
		printf("fwid = %X\n", tmp_data[0] << 8 | tmp_data[1]);
		printf("fwver = %X\n", tmp_data[2] << 8 | tmp_data[3]);
	}

exit:
	hx_close_i2c_device();

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

//	himax_register_read(ic_adr_cs_central_state, data, 4);
//	if (data[0] != 0x05) {
//		printf("recovery mode\n");
//		goto exit;
//	}

//	if (optp->options & OPTION_PID) {
//		himax_register_read(fw_addr_vid_pid_addr, data, 4);
//		printf("%4X", data[2] << 8 | data[3]);
//	} else if (optp->options & OPTION_FW_VER) {
//		himax_register_read(fw_addr_fw_vendor_addr, data, 4);
//		printf("%04X", (data[2] << 8 | data[3]));
//	}

	ret = himax_register_read(fw_addr_fw_id_ver_addr, data, 4);
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

		sz = readlinkat(dirfd(devs_dir), devs_dir_entry->d_name, tmp_buf, 256);
		if (sz < 0)
			continue;

		tmp_buf[sz] = 0;

		sprintf(tmp_path, "%s%s", dev_path, tmp_buf);
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

			return 0;
		}
		break;
	}

	close(fd);

	return (size == (ssize_t) strlen(action));
}

int rebind_driver(DEVINFO *devp)
{
	int bus = 0x18;
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

	sprintf(attr_str, "%s%s", driver_path, "unbind");

	if (!write_devname_to_sys_attr(attr_str, i2c_dev_name)) {
		printf("failed to unbind HID device %s %s\n", attr_str, i2c_dev_name);
		return 1;
	}

	usleep(300000);

	sprintf(attr_str, "%s%s", driver_path, "bind");

	if (!write_devname_to_sys_attr(attr_str, i2c_dev_name)) {
		printf("failed to bind HID device %s %s\n", attr_str, i2c_dev_name);
		return 1;
	}

	usleep(300000);

	printf("Rebind driver is done !\n");

	return 0;
}

int read_reg(OPTDATA& opt_data)
{
	int ret;
	uint8_t data[4] = {0};

	if (himax_scan_device(&opt_data) == 0) {
		ret = himax_register_read(opt_data.r_reg_addr.i, data, sizeof(data));
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

int write_reg(OPTDATA& opt_data)
{
	int ret;
	if (himax_scan_device(&opt_data) == 0) {
		ret = himax_register_write(opt_data.w_reg_addr.i, opt_data.w_reg_data.b, opt_data.w_data_size);
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
	},
	{
		.ic_sign_2 = {IC_SIGN_TO_CHAR(HX83102-J)},
		.fw_table = &fw_main_102J[0],
	}
};

static const hx_ic_fw_layout_mapping_t g_ic_bl_code_mapping_table[] = {
	{
		.ic_sign_2 = {IC_SIGN_TO_CHAR(HX83121-A)},
		.fw_table = &fw_bl_121A[0],
	},
	{
		.ic_sign_2 = {IC_SIGN_TO_CHAR(HX83102-J)},
		.fw_table = &fw_bl_102J[0],
	}
};

int calculateMappingEntries(hx_hid_fw_unit_t* table, int totalSize)
{
	int actual_entries = 0;

	for (int i = 0; i < (totalSize / sizeof(hx_hid_fw_unit_t)); i++) {
		if (table[i].unit_sz != 0)
			actual_entries++;
		else
			break;
	}

	return actual_entries;
}

int hid_write_reg(OPTDATA& opt_data)
{
	int ret;
	uint8_t reg_n_data[9];

	reg_n_data[0] = 0x1;// 1: write reg
	memcpy(reg_n_data + 1, &(opt_data.w_reg_addr.b[0]), opt_data.w_addr_size);
	memcpy(reg_n_data + 1 + 4, &(opt_data.w_reg_data.b[0]), opt_data.w_data_size);

	if (hx_scan_open_hidraw(opt_data) == 0) {
		ret = hx_hid_set_feature(HID_REG_RW_ID, reg_n_data, sizeof(reg_n_data));
		if (ret == 0) {
			hx_printf("%s %08X:%08X\n", "Write done", *(uint32_t *)&(reg_n_data[1]), *(uint32_t *)&(reg_n_data[5]));
		} else {
			hx_printf("%s %08X:%08X\n", "Write failed", *(uint32_t *)&(reg_n_data[1]), *(uint32_t *)&(reg_n_data[5]));
		}

		hx_hid_close();
		return ret;
	} else {
		return -ENODEV;
	}
}

int hid_read_reg(OPTDATA& opt_data)
{
	int ret;
	uint8_t reg_n_data[9] = {0};

	reg_n_data[0] = 0x0;// 0: read reg
	memcpy(reg_n_data + 1, &(opt_data.r_reg_addr.b[0]), 4);

	if (hx_scan_open_hidraw(opt_data) == 0) {
		ret = hx_hid_set_feature(HID_REG_RW_ID, reg_n_data, sizeof(reg_n_data));
		if (ret == 0) {
			;//hx_printf("%s %08X:%08X\n", "Write done", *(uint32_t *)&(reg_n_data[1]), *(uint32_t *)&(reg_n_data[5]));
		} else {
			hx_printf("%s %08X:%08X\n", "Write failed", *(uint32_t *)&(reg_n_data[1]), *(uint32_t *)&(reg_n_data[5]));
			goto R_REG_FUNC_END;
		}
		ret = hx_hid_get_feature(HID_REG_RW_ID, reg_n_data, sizeof(reg_n_data));
		if (ret == 0) {
			hx_printf("%s %08X:%08X\n", "Read done", *(uint32_t *)&(reg_n_data[1]), *(uint32_t *)&(reg_n_data[5]));
		} else {
			hx_printf("%s %08X:%08X\n", "Read failed", *(uint32_t *)&(reg_n_data[1]), *(uint32_t *)&(reg_n_data[5]));
		}
	} else {
		return -ENODEV;
	}
R_REG_FUNC_END:
	hx_hid_close();

	return ret;
}

int hid_show_fw_info(OPTDATA& opt_data)
{
	int ret;
	hx_hid_info info;

	if (hx_scan_open_hidraw(opt_data) == 0) {
		ret = hx_hid_get_feature(HID_CFG_ID, (uint8_t *)&info, 255);
		if (ret == 0) {
			if (is_opt_set(&opt_data, OPTION_HID_SHOW_PID_BY_HID_INFO)) {
				printf("%02X%02X\n", info.pid[0], info.pid[1]);
			} else if (is_opt_set(&opt_data, OPTION_HID_SHOW_FW_VER_BY_HID_INFO)) {
				printf("%02X%02X\n", info.cid[0], info.cid[1]);
			} else {
				hx_printf("%s : %02X %02X\n", "passwd", info.passwd[0], info.passwd[1]);
				hx_printf("%s : %02X %02X\n", "cid", info.cid[0], info.cid[1]);
				hx_printf("%s : %02X\n", "panel_ver", info.panel_ver);
				hx_printf("%s : %02X %02X\n", "fw_ver", info.fw_ver[0], info.fw_ver[1]);
				hx_printf("%s : %C\n", "ic_sign", info.ic_sign);
				hx_printf("%s : %s\n", "customer", info.customer);
				hx_printf("%s : %s\n", "project", info.project);
				hx_printf("%s : %s\n", "fw_major", info.fw_major);
				hx_printf("%s : %s\n", "fw_minor", info.fw_minor);
				hx_printf("%s : %s\n", "date", info.date);
				hx_printf("%s : %s\n", "ic_sign_2", info.ic_sign_2);
				hx_printf("%s : %02X %02X\n", "vid", info.vid[0], info.vid[1]);
				hx_printf("%s : %02X %02X\n", "pid", info.pid[0], info.pid[1]);
				hx_printf("%s : %02X\n", "Config version", info.cfg_version);
				hx_printf("%s : %02X\n", "Display version", info.disp_version);
				hx_printf("%s : %d\n", "RX", info.rx);
				hx_printf("%s : %d\n", "TX", info.tx);
				info.yres = be16toh(info.yres);
				hx_printf("%s : %d\n", "YRES ", info.yres);
				info.xres = be16toh(info.xres);
				hx_printf("%s : %d\n", "XRES", info.xres);
				hx_printf("%s : %d\n", "PT_NUM", info.pt_num);
				hx_printf("%s : %d\n", "MKEY_NUM", info.mkey_num);
				hx_printf("%s : %d\n", "PEN_NUM", info.pen_num);
				info.pen_yres = be16toh(info.pen_yres);
				hx_printf("%s : %d\n", "PEN_YRES", info.pen_yres);
				info.pen_xres = be16toh(info.pen_xres);
				hx_printf("%s : %d\n", "PEN_XRES", info.pen_xres);
				hx_printf("%s : %02X\n", "LTDI_IC_NUM", info.ic_num);
				hx_printf("FW layout : \n");
				for (int i = 0; i < 9; i++)
					hx_printf("\t%2X - start : %08X, Size %d kB\n", \
						info.main_mapping[i].cmd, info.main_mapping[i].bin_start_offset * 1024, \
						info.main_mapping[i].unit_sz);
				hx_printf("\t%2X - start : %08X, Size %d kB\n", \
						info.bl_mapping.cmd, info.bl_mapping.bin_start_offset * 1024, \
						info.bl_mapping.unit_sz);
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
	hx_hid_info info;

	if (hx_scan_open_hidraw(opt_data) == 0) {
		ret = hx_hid_get_feature(HID_CFG_ID, (uint8_t *)&info, 255);
		if (ret == 0) {
			printf("%s : %02X %02X\n", "vid", info.vid[0], info.vid[1]);
			printf("%s : %02X %02X\n", "pid", info.pid[0], info.pid[1]);
			printf("%s : %02X %02X\n", "firmware verison", info.cid[0], info.cid[1]);
		}

		hx_hid_close();
		return 0;
	} else {
		return -ENODEV;
	}
}

int hid_main_update(OPTDATA& opt_data, DEVINFO& dinfo, int& lastError)
{
	hx_hid_info oinfo;
	bool bOinfoValid = false;
	bool bGoUpdate = false;
	HXFW hxfw;
	time_t start, now;
	uint8_t recevied_data[2] = {0};
	int nDataRecevied = 0;
	const uint32_t pollingInterval = 300;
	uint32_t writeSize;
	uint32_t fwStartLoc;
	uint32_t outputTimes;
	const uint8_t main_update_cmd = 0x55;
	int ret = 0;
	int fw_entries = 0;
	hx_hid_fw_unit_t* fw_entry_table = NULL;
	lastError = FWUP_ERROR_NO_ERROR;

	if (himax_load_fw(opt_data.fw_path, &hxfw) != 0) {
		ret = -ENODATA;
		lastError = FWUP_ERROR_LOAD_FW_BIN;
		goto LOAD_FW_FAILED;
	}

	if (hx_scan_open_hidraw(opt_data) == 0) {
		if (hx_hid_parse_RD_for_idsz() == 0) {
			int sz = hx_hid_get_size_by_id(HID_FW_UPDATE_ID);
			bool bHandshakePresent = (hx_hid_get_size_by_id(HID_FW_UPDATE_HANDSHAKING_ID) == 1)?true:false;
			if ((sz > 0) && bHandshakePresent) {
				bool useFwInfoEntries = true;

				if (hx_hid_get_feature(HID_CFG_ID, (uint8_t *)&oinfo, 255) == 0) {
					fw_entries = calculateMappingEntries(oinfo.main_mapping, sizeof(oinfo.main_mapping));
					if (fw_entries > 0) {
						useFwInfoEntries = true;
						fw_entry_table = oinfo.main_mapping;
					}

					bOinfoValid = true;
				} else {
					bOinfoValid = false;
					useFwInfoEntries = false;
				}

				if (!useFwInfoEntries && bOinfoValid) {
					for (int i = 0; i < sizeof(g_ic_main_code_mapping_table)/sizeof(hx_ic_fw_layout_mapping_t); i++) {
						if (memcmp(g_ic_main_code_mapping_table[i].ic_sign_2, oinfo.ic_sign_2, sizeof(oinfo.ic_sign_2)) == 0) {
							fw_entries = calculateMappingEntries((hx_hid_fw_unit_t *)g_ic_main_code_mapping_table[i].fw_table, sizeof(hx_hid_fw_unit_t)* 9);
							fw_entry_table = (hx_hid_fw_unit_t *)g_ic_main_code_mapping_table[i].fw_table;
							break;
						}
					}
				}

				if (!is_opt_set(&opt_data, OPTION_HID_FORCE_UPDATE)) {
					if (bOinfoValid)
						bGoUpdate = (himax_update_check(&hxfw, &oinfo) > 0)?true:false;
					else
						bGoUpdate = false;
				} else {
					if (fw_entries == 0) {
						fw_entries = calculateMappingEntries((hx_hid_fw_unit_t *)fw_main_121A, sizeof(hx_hid_fw_unit_t)* 9);
						fw_entry_table = (hx_hid_fw_unit_t *)fw_main_121A;
					}
					bGoUpdate = true;
				}

				if (bGoUpdate && (fw_entries > 0)) {
					uint8_t cmd = 0;

					if(hx_hid_get_feature(HID_FW_UPDATE_HANDSHAKING_ID, &cmd, 1) == 0)
						hx_printf("ID %02X read %02X\n", HID_FW_UPDATE_HANDSHAKING_ID, cmd);

					cmd = main_update_cmd;
					if (hx_hid_set_feature(HID_FW_UPDATE_HANDSHAKING_ID, &cmd, 1) != 0) {
						hx_printf("Initial HID FW update failed!\n");
						lastError = FWUP_ERROR_INITIAL;
						goto HID_FW_UPDATE_END;
					} else {
						hx_printf("Initializing HID FW update....\n");
						// usleep(1500 * 1000);
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
								ret = -EIO;
								goto HID_FW_UPDATE_END;
							}
POLL_FAILED:
							hx_printf("Polling for 0x%X timeout!\n", cmd);
							lastError = FWUP_ERROR_POLLING_TIMEOUT;
							ret = -EIO;
							goto HID_FW_UPDATE_END;
						}

						writeSize = fw_entry_table[i].unit_sz * 1024;
						fwStartLoc = fw_entry_table[i].bin_start_offset * 1024;
						outputTimes = writeSize / sz;
						for (uint32_t i = 0; i < outputTimes; i++) {
							hx_printf("[new]Sending trunk %d/%d of %d kb\r", i + 1, outputTimes, writeSize / 1024);
							// if (hx_hid_set_output(HID_FW_UPDATE_ID, 1, hxfw.data + fwStartLoc + i * sz, sz) != 0) {
							if (hx_hid_set_feature(HID_FW_UPDATE_ID, hxfw.data + fwStartLoc + i * sz, sz) != 0) {
								// cmd failed, go out
								hx_printf("send firmware trunk: %d/%d of %d kb failed!\n", i + 1, outputTimes, writeSize);
								ret = -EIO;
								lastError = FWUP_ERROR_FW_TRANSFER;
								goto HID_FW_UPDATE_END;
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

							ret = -EIO;
							goto HID_FW_UPDATE_END;
						}
						hx_printf("Polling for B1 timeout!\n");
						lastError = FWUP_ERROR_POLLING_TIMEOUT;
						ret = -EIO;
						goto HID_FW_UPDATE_END;
					} else {
						hx_printf("Update succeed!\n");
						ret = 0;
						usleep(500 * 1000);
						opt_data.options |= OPTION_REBIND;
						dinfo.pid = opt_data.pid;
						dinfo.vid = opt_data.vid;
						lastError = FWUP_ERROR_NO_ERROR;
					}
				} else {
					hx_printf("Version identical, update no go!\n");
					ret = 1;
				}
			}
		}
	} else {
		himax_free_fw(&hxfw);
		lastError = FWUP_ERROR_NO_DEVICE;
		return -ENODEV;
	}
HID_FW_UPDATE_END:
	hx_hid_close();
	himax_free_fw(&hxfw);
LOAD_FW_FAILED:
	return ret;
}

int hid_bl_update(OPTDATA& opt_data, DEVINFO& dinfo, int& lastError)
{
	hx_hid_info oinfo;
	bool bOinfoValid = false;
	bool bGoUpdate = false;
	HXFW hxfw;
	time_t start, now;
	uint8_t recevied_data[2] = {0};
	int nDataRecevied = 0;
	const uint32_t pollingInterval = 10;
	uint32_t writeSize;
	uint32_t fwStartLoc;
	uint32_t outputTimes;
	const uint8_t bl_update_cmd = 0x77;
	int ret = 0;
	int fw_entries = 0;
	hx_hid_fw_unit_t* fw_entry_table = NULL;
	lastError = FWUP_ERROR_NO_ERROR;

	if (himax_load_fw(opt_data.fw_path, &hxfw) != 0) {
		ret = -ENODATA;
		lastError = FWUP_ERROR_LOAD_FW_BIN;
		goto LOAD_FW_FAILED;
	}

	if (hx_scan_open_hidraw(opt_data) == 0) {
		if (hx_hid_parse_RD_for_idsz() == 0) {
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
					for (int i = 0; i < sizeof(g_ic_bl_code_mapping_table)/sizeof(hx_ic_fw_layout_mapping_t); i++) {
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

					cmd = bl_update_cmd;
					if (hx_hid_set_feature(HID_FW_UPDATE_HANDSHAKING_ID, &cmd, 1) != 0) {
						hx_printf("Initial HID FW update failed!\n");
						lastError = FWUP_ERROR_INITIAL;
						goto HID_BL_UPDATE_END;
					} else {
						hx_printf("Initializing HID FW update....\n");
						// usleep(1500 * 1000);
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
								ret = -EIO;
								lastError = recevied_data[0];
								goto HID_BL_UPDATE_END;
							}
POLL_BL_FAILED:
							hx_printf("Polling for 0x%X timeout!\n", cmd);
							lastError = FWUP_ERROR_POLLING_TIMEOUT;
							ret = -EIO;
							goto HID_BL_UPDATE_END;
						}

						writeSize = fw_entry_table[i].unit_sz * 1024;
						fwStartLoc = fw_entry_table[i].bin_start_offset * 1024;
						outputTimes = writeSize / sz;
						for (uint32_t i = 0; i < outputTimes; i++) {
							hx_printf("[new]Sending trunk %d/%d of %d kb\r", i + 1, outputTimes, writeSize / 1024);
							// if (hx_hid_set_output(HID_FW_UPDATE_ID, 1, hxfw.data + fwStartLoc + i * sz, sz) != 0) {
							if (hx_hid_set_feature(HID_FW_UPDATE_ID, hxfw.data + fwStartLoc + i * sz, sz) != 0) {
								// cmd failed, go out
								hx_printf("send firmware trunk: %d/%d of %d kb failed!\n", i + 1, outputTimes, writeSize);
								ret = -EIO;
								lastError = FWUP_ERROR_FW_TRANSFER;
								goto HID_BL_UPDATE_END;
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
							ret = -EIO;
							goto HID_BL_UPDATE_END;
						}
						hx_printf("Polling for B1 timeout!\n");
						lastError = FWUP_ERROR_POLLING_TIMEOUT;
						ret = -EIO;
						goto HID_BL_UPDATE_END;
					} else {
						hx_printf("Bootloader update succeed!\n");
						ret = 0;
						usleep(500 * 1000);
						opt_data.options |= OPTION_REBIND;
						dinfo.pid = opt_data.pid;
						dinfo.vid = opt_data.vid;
						lastError = FWUP_ERROR_NO_ERROR;
					}
				}
			}
		}
	} else {
		himax_free_fw(&hxfw);
		lastError = FWUP_ERROR_NO_DEVICE;
		return -ENODEV;
	}
HID_BL_UPDATE_END:
	hx_hid_close();
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

		ret = hx_hid_write_reg(fw_addr_raw_out_sel, HID_RAW_OUT_DELTA, opt_data);
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
							if (sscanf(tok, "%d", &(hx_criteria_table[current_idx].default_value)) > 0) {
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

							if (sscanf(tok, "%d", &(hx_criteria_table[current_idx].param_data[hx_criteria_table[current_idx].param_count])) > 0) {
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
							if (sscanf(tok, "%d", &(hx_criteria_table[current_idx].param_data[hx_criteria_table[current_idx].param_count])) > 0) {
								hx_criteria_table[current_idx].param_count++;
								rx_cnt++;

								tok = strtok(NULL, ",");
								while (tok != NULL) {
									// tok_idx++;

									if (sscanf(tok, "%d", &(hx_criteria_table[current_idx].param_data[hx_criteria_table[current_idx].param_count])) > 0) {
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

int place_frame_in_full_map(uint16_t *full_map, uint16_t *frame, int full_rx, int full_tx,
	int frame_pos_rx, int frame_pos_tx, int rx_num, int tx_num)
{
	if ((frame_pos_rx + rx_num) > full_rx) {
		hx_printf("Error : frame_pos_rx(%d) + rx_num(%d) > full_rx(%d)\n", frame_pos_rx, rx_num, full_rx);
		return -1;
	}
	if ((frame_pos_tx + tx_num) > full_tx) {
		hx_printf("Error : frame_pos_tx(%d) + tx_num(%d) > full_tx(%d)\n", frame_pos_tx, tx_num, full_tx);
		return -1;
	}
	for (int i = 0; i < tx_num; i++)
		memcpy(full_map + frame_pos_tx * full_rx + i * full_rx + frame_pos_rx,
		frame + i * rx_num, rx_num * sizeof(uint16_t));

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
	for(int j = 0; j < rx_num; j++) {
		hx_printf(" RX[%02d]", j + 1);
	}
	for (int j = 0; j < (rx_num * tx_num); j++) {
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

bool compare_result_with_fixed_bounds(uint8_t *frame_data, hid_self_test_support_item_t *test_item,
	int32_t upperBond, int32_t lowerBond, bool signed_data,	unsigned int rx_num, unsigned int tx_num)
{
	union { int32_t i; uint16_t s[2]; } usdata;

	hx_printf("\nFull map:\n");
	hx_printf("       ");
	for(int j = 0; j < rx_num; j++) {
		hx_printf(" RX[%02d]", j + 1);
	}
	for (int j = 0; j < (rx_num * tx_num); j++) {
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

bool get_raw_data(uint8_t *frame_data, uint32_t frame_sz, uint16_t type,
	bool signed_data, bool polling_for_ready, uint32_t self_test_id_sz,
	uint8_t *full_data,	int rx_ic_num, int tx_ic_num, int rx_num, int tx_num,
	bool rx_rev, bool tx_rev, int retry_limit, bool bPrintData, FILE *fp)
{
	int retry_cnt = 0;
	int poll_cnt = 0;
	int correct_frames = 0;
	int ret;
	union { uint32_t i; uint8_t b[4]; } cmd;
	union { uint32_t i; uint8_t b[4]; } recv;
	union { int32_t i; uint16_t s[2]; } usdata;
	const uint32_t pollingInterval = 100;
	const unsigned int header = 5;
	int nDataRecv = 0;
	uint8_t lastState;
	int debug_start_loc;

	for (unsigned int tra_rx_ic = 0; tra_rx_ic < rx_ic_num; tra_rx_ic++) {
		for (unsigned int tra_tx_ic = 0; tra_tx_ic < tx_ic_num; tra_tx_ic++) {
			retry_cnt = 0;
RESTART_ALL_PROC:
			if (tra_rx_ic != 0 || tra_tx_ic != 0) {
				cmd.i = (tra_tx_ic << 20) | tra_rx_ic << 16 | type;
				ret = hx_hid_set_feature(HID_TOUCH_MONITOR_SEL_ID, cmd.b, sizeof(cmd.b));
				if (ret < 0) {
					retry_cnt++;
					if (retry_cnt >= retry_limit) {
						hx_printf("Set feature failed!\n");
						return false;
					}
					goto RESTART_ALL_PROC;
				}
				if (polling_for_ready) {
					poll_cnt = 0;
RESTART_POLL_PROC:
					if (poll_cnt >= retry_limit) {
						hx_printf("Polling for 0xFF timeout!\n");
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
								return false;
							} else {
								hx_printf("self test return undefined value!(0x%02X)\n", recv.b[0]);
								log(fp, "self test return undefined value!(0x%02X)\n", recv.b[0]);
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
				ret = hx_hid_get_feature(HID_TOUCH_MONITOR_ID, frame_data, frame_sz);
				if ((ret == 0) && (frame_data[1] == 0x5A) && (frame_data[2] == 0xA5)) {
					correct_frames++;
					if (bPrintData) {
						hx_printf("       ");
						for(int j = 0; j < rx_num; j++) {
							hx_printf(" RX[%02d]", j + 1);
							log(fp, " RX[%02d]", j + 1);
						}
						for (int j = 0; j < (rx_num * tx_num); j++) {
							if ((j % rx_num) == 0) {
								hx_printf("\nTX[%02d]:", j/rx_num + 1);
								log(fp, "\nTX[%02d]:", j/rx_num + 1);
							}
							usdata.i =
								(int16_t)frame_data[header + j * 2] + (((int16_t)frame_data[header + j * 2 + 1]) << 8);
							if (signed_data)
								usdata.i = *(int16_t *)&(usdata.s[0]);

							hx_printf(" %6d", usdata.i);
							log(fp, " %6d", usdata.i);
						}

						debug_start_loc = header + (rx_num * tx_num) * 2;
						for (unsigned int j = 0; j < (rx_num + tx_num); j++) {
							if ((j % rx_num) == 0) {
								hx_printf("\n DEBUG:");
								log(fp, "\n DEBUG:");
							}
							hx_printf(" %6d", ((int16_t)frame_data[debug_start_loc + j * 2]) + (((int16_t)frame_data[debug_start_loc + j * 2 + 1]) << 8));
							log(fp, " %6d", ((int16_t)frame_data[debug_start_loc + j * 2]) + (((int16_t)frame_data[debug_start_loc + j * 2 + 1]) << 8));
						}
						hx_printf("\n");
						log(fp, "\n");
					}
					if (place_frame_in_full_map((uint16_t *)full_data, (uint16_t *)(frame_data + header), rx_ic_num * rx_num,
						tx_ic_num * tx_num, tra_rx_ic * rx_num, tra_tx_ic * tx_num, rx_num, tx_num) != 0) {
						hx_printf("place frame in full map failed!\n");
						log(fp, "place frame in full map failed!\n");
						return false;
					}
					break;
				}
			}
		}
	}

	if (correct_frames == rx_ic_num * tx_ic_num) {
		if (rx_rev) {
			uint16_t *tmp = (uint16_t *)malloc(rx_num * tx_num * rx_ic_num * tx_ic_num * 2);
			if (tmp == NULL) {
				hx_printf("RX Reverse failed, Memory insufficient!\n");
				return false;
			}
			for (int i = 0; i < tx_num * tx_ic_num; i++) {
				for (int j = 0; j < rx_num * rx_ic_num; j++) {
					tmp[i * rx_num * rx_ic_num + j] = ((uint16_t *)full_data)[(i + 1) * rx_num * rx_ic_num - j - 1];
				}
			}
			memcpy(full_data, tmp, rx_num * tx_num * rx_ic_num * tx_ic_num * 2);
			free(tmp);
		}
		if (tx_rev) {
			uint16_t *tmp = (uint16_t *)malloc(rx_num * tx_num * rx_ic_num * tx_ic_num * 2);
			if (tmp == NULL) {
				hx_printf("TX Reverse failed, Memory insufficient!\n");
				return false;
			}
			for (int i = 0; i < rx_num * rx_ic_num; i++) {
				for (int j = 0; j < tx_num * tx_ic_num; j++) {
					tmp[j * rx_num * rx_ic_num + i] = ((uint16_t *)full_data)[(tx_num * tx_ic_num - j - 1) * rx_num * rx_ic_num + i];
				}
			}
			memcpy(full_data, tmp, rx_num * tx_num * rx_ic_num * tx_ic_num * 2);
			free(tmp);
		}
		return true;
	} else {
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
	hx_hid_info info;
	int ret = 0;
	const uint32_t pollingInterval = 100;
	hx_criteria_t *hx_criteria_table = NULL;
	uint32_t nKeyword;
	uint8_t *frame = NULL;
	uint8_t *cmd = NULL;
	uint8_t *recv = NULL;
	int nDataRecv = 0;
	const int retry_limit = 500;
	int retry_cnt = 0;
	int total_sz;
	int frame_sz;
	bool bLowerBondFound;
	int32_t *lowerBond_data;
	bool bUpperBondFound;
	int32_t *upperBond_data;
	// bool bSelfTestCompleted = false;
	uint8_t lastState;
	int rx_num;
	int tx_num;
	char fname_only[128] = {0};
	char tmp_output_pathname[1024] = {0};
	char final_output_pathname[1024] = {0};
	bool is_output_file;
	time_t t = time(NULL);
	struct tm *dtime = localtime(&t);
	struct timeval tv;
	FILE *fp = NULL;
	bool overall_result = true;
	int tx_ic_num;
	int rx_ic_num;

	is_output_file = is_opt_set(&opt_data, OPTION_HID_CRITERIA_OUTPUT_PATH);
	gettimeofday(&tv, NULL);
	if (hx_hid_parse_criteria_file(opt_data, &hx_criteria_table, &nKeyword) == 0) {
		if (hx_scan_open_hidraw(opt_data) == 0) {
			if (hx_hid_parse_RD_for_idsz() == 0) {
				if (hx_hid_get_feature(HID_CFG_ID, (uint8_t *)&info, hx_hid_get_size_by_id(HID_CFG_ID)) == 0) {
					rx_num = info.rx;
					tx_num = info.tx;
					tx_ic_num = ((info.ic_num & 0xF0) >> 4) + 1;
					rx_ic_num = (info.ic_num & 0x0F) + 1;

					frame_sz = hx_hid_get_size_by_id(HID_TOUCH_MONITOR_ID);
					if (frame_sz > 0) {
						total_sz = frame_sz + rx_num * tx_num * rx_ic_num * tx_ic_num * 2;
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
									opt_data.criteria_output_path, "hx_mp_test_log_", fname_only);
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
								memset(cmd, 0, stSz);
								cmd[0] = test_items[i].hid_switch;
								ret = hx_hid_set_feature(HID_SELF_TEST_ID, cmd, stSz);
								if (ret == 0) {
									nDataRecv = 0;
									cmd[0] = 0xFF;
									lastState = 0x0;
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
														if (lastState != recv[0]) {
															hx_printf("self test init stage.\n");
															log(fp, "self test init stage.\n");
														}
														break;
													case 0xF2:
														if (lastState != recv[0]) {
															hx_printf("self test started.\n");
															log(fp, "self test started.\n");
														}
														break;
													case 0xF3:
														if (lastState != recv[0]) {
															hx_printf("self test on going.\n");
															log(fp, "self test on going.\n");
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
									if (get_raw_data(frame, frame_sz, 0, test_items[i].hid_switch == HID_SELF_TEST_NOISE,
										true, stSz,	frame + frame_sz, rx_ic_num, tx_ic_num, rx_num, tx_num,
										is_opt_set(&opt_data, OPTION_HID_RX_REVERSE),
										is_opt_set(&opt_data, OPTION_HID_TX_REVERSE),
										retry_limit, true, fp)) {
										compare_result(frame + frame_sz, &test_items[i], bUpperBondFound,
											upperBond_data, bLowerBondFound, lowerBond_data, rx_num * rx_ic_num,
											tx_num * tx_ic_num);
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
						opt_data.criteria_output_path, overall_result?"PASS":"FAIL","hx_mp_test_log_", fname_only);
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
	hx_hid_info info;
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
	int tx_ic_num;
	int rx_ic_num;
	bool signed_data = false;
	hid_self_test_support_item_t test_item = {
		.name = "Custom",
		.hasLowerBond = true,
		.hasUpperBond = true,
		.testResult = false,
		.activated = true,
	};

	if (hx_scan_open_hidraw(opt_data) == 0) {
		if (hx_hid_parse_RD_for_idsz() == 0) {
			if (hx_hid_get_feature(HID_CFG_ID, (uint8_t *)&info, hx_hid_get_size_by_id(HID_CFG_ID)) == 0) {
				rx_num = info.rx;
				tx_num = info.tx;
				tx_ic_num = ((info.ic_num & 0xF0) >> 4) + 1;
				rx_ic_num = (info.ic_num & 0x0F) + 1;

				frame_sz = hx_hid_get_size_by_id(HID_TOUCH_MONITOR_ID);
				if (frame_sz > 0) {
					total_sz = frame_sz + rx_num * tx_num * rx_ic_num * tx_ic_num * 2;
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

					if ((bSelfTestCompleted && (opt_data.param.i == 0x22)) ||
						is_opt_set(&opt_data, OPTION_HID_PARTIAL_DISPLAY_SIGNED))
						signed_data = true;
					if (get_raw_data(frame, frame_sz, opt_data.param.i, signed_data, false, stSz, frame + frame_sz,
						rx_ic_num, tx_ic_num, rx_num, tx_num,
						is_opt_set(&opt_data, OPTION_HID_RX_REVERSE), is_opt_set(&opt_data, OPTION_HID_TX_REVERSE),
						retry_limit, true, NULL)) {
						// bTestPass = compare_result(frame + frame_sz, &test_item, false, NULL, false, NULL, rx_num * rx_ic_num, tx_num * tx_ic_num);
						bTestPass = compare_result_with_fixed_bounds(frame + frame_sz, &test_item, opt_data.self_test_spec_max, opt_data.self_test_spec_min, signed_data, rx_num * rx_ic_num, tx_num * tx_ic_num);
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
		return -ENODEV;
	}

DIAG_FUNC_END:
	hx_hid_close();

	return ret;
}

int hid_show_specify_diag(OPTDATA& opt_data)
{
	hx_hid_info info;
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
		if (hx_hid_parse_RD_for_idsz() == 0) {
			if (hx_hid_get_feature(HID_CFG_ID, (uint8_t *)&info, hx_hid_get_size_by_id(HID_CFG_ID)) == 0) {
				rx_num = info.rx;
				tx_num = info.tx;

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
		if (hx_hid_parse_RD_for_idsz() == 0) {
			// if (hx_hid_get_feature(HID_CFG_ID, (uint8_t *)&oinfo, 255) == 0)
				// hx_printf("got dev info\n");

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
			sprintf(hidraw_path, "%s/hidraw%d", dev_dir, dev_no);

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
	bool display_data = false;
	int save_fd = -1;
	uint8_t *partial_data = NULL;
	hx_hid_info info;
	int total_sz = 0;
	int full_cycle = 0;
	uint16_t value;
	char* buffer = NULL;
	int stringLen = 0;

	if (hx_scan_open_hidraw(optdata) < 0) {
		return -EIO;
	}

	if (hx_hid_parse_RD_for_idsz() < 0) {
		ret = -EFAULT;
		goto SETUP_FAILED;
	}

	partial_data_sz = hx_hid_get_size_by_id(HID_TOUCH_MONITOR_PARTIAL_ID);
	if (partial_data_sz <= 0) {
		hx_printf("No partial data ID in RD!\n");
		ret = -EFAULT;
		goto SETUP_FAILED;
	}

	if (hx_hid_get_feature(HID_CFG_ID, (uint8_t *)&info, hx_hid_get_size_by_id(HID_CFG_ID)) != 0) {
		hx_printf("Get HID_CFG_ID failed!\n");
		ret = -EFAULT;
		goto SETUP_FAILED;
	}
	total_sz = ((int)info.rx * (int)info.tx + (int)info.rx + (int)info.tx) * 2;

	if (is_opt_set(&optdata, OPTION_HID_PARTIAL_SAVE_FILE)) {
		save_fd = open(optdata.partial_save_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
		if (save_fd < 0) {
			hx_printf("Open %s failed!\n", optdata.partial_save_file);
			ret = -EFAULT;
			goto SETUP_FAILED;
		}
	}

	partial_data = (uint8_t *)malloc(partial_data_sz);
	if (partial_data == NULL) {
		hx_printf("Allocate memory for partial data failed!\n");
		ret = -ENOMEM;
		goto ALLOCATE_FAILED;
	}

	if (is_opt_set(&optdata, OPTION_HID_PARTIAL_DISPLAY) || is_opt_set(&optdata, OPTION_HID_PARTIAL_SAVE_FILE)) {
		buffer = (char *)malloc(((partial_data_sz - 1) / 2 - 2) * 7 + 50 + 1);

		if (buffer == NULL) {
			hx_printf("Allocate memory for string buffer failed!\n");
			ret = -ENOMEM;
			goto ALLOCATE_BUF_FAILED;
		}
		stringLen = ((partial_data_sz - 1) / 2 - 2) * 7 + 50 + 1;
	}

	if (is_opt_set(&optdata, OPTION_HID_PARTIAL_DISPLAY))
		display_data = true;

	full_cycle = total_sz / ((partial_data_sz - 1) / 2 - 2);
	if ((total_sz % ((partial_data_sz - 1) / 2 - 2)) > 0)
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
			memset(buffer, 0, stringLen);
			stringLen = 0;
			stringLen += sprintf(buffer + stringLen, "%02X (%02X %02X %02X %02X) : ", partial_data[0], partial_data[1], partial_data[2], partial_data[3], partial_data[4]);
			for (int i = 5; i < partial_data_sz; i += 2) {
				value = (uint16_t)partial_data[i] | ((uint16_t)partial_data[i + 1] << 8);
				stringLen += sprintf(buffer + stringLen, "%5d ", value);
			}
			stringLen += sprintf(buffer + stringLen, "\n");

			if (display_data) {
				hx_printf("%s", buffer);
			}

			if (save_fd > 0) {
				ret = write(save_fd, buffer, strlen(buffer));
				if (ret != strlen(buffer)) {
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
	if (save_fd > 0)
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
			hx_printf(" %6d", (int16_t)frame[i]);
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
	for (int i = 0; i < sz; i++) {
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
	hx_hid_info info;
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
	int32_t tx_ic_num;
	int32_t rx_ic_num;
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

	if (hx_hid_parse_RD_for_idsz() < 0) {
		ret = -EFAULT;
		goto SETUP_FAILED;
	}

	stSz = hx_hid_get_size_by_id(HID_SELF_TEST_ID);
	if (stSz <= 0) {
		hx_printf("No HID_SELF_TEST_ID in RD!\n");
		ret = -EFAULT;
		goto SETUP_FAILED;
	}

	if (hx_hid_get_feature(HID_CFG_ID, (uint8_t *)&info, hx_hid_get_size_by_id(HID_CFG_ID)) != 0) {
		hx_printf("Get HID_CFG_ID failed!\n");
		ret = -EFAULT;
		goto SETUP_FAILED;
	}

	tx_ic_num = ((info.ic_num & 0xF0) >> 4) + 1;
	rx_ic_num = (info.ic_num & 0x0F) + 1;
	rx_num = info.rx;
	tx_num = info.tx;
	mutual_sz = rx_num * tx_num * rx_ic_num * tx_ic_num;
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

	total_sz = frame_sz + rx_num * tx_num * rx_ic_num * tx_ic_num * 2;
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

		bret = get_raw_data(frame, frame_sz, HID_DIAG_RAW_DATA, true, false, stSz, frame + frame_sz, rx_ic_num, tx_ic_num, rx_num, tx_num,
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
			uint16_t *tmp_frame = (uint16_t *)(frame + frame_sz);
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

			bret = get_raw_data(frame, frame_sz, HID_DIAG_RAW_DATA, true, false, stSz, frame + frame_sz,
				rx_ic_num, tx_ic_num, rx_num, tx_num,
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
					tmp_frame = (uint16_t *)(frame + frame_sz);
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
		if (hx_hid_parse_RD_for_idsz() == 0) {
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

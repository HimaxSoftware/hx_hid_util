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
#include <dirent.h>

#include "hx_def.h"
#include "hx_ic.h"
#include "hx_i2c_func.h"

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

int himax_update_check(HXFW *fwp)
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

	himax_register_read(ic_adr_cs_central_state, tmp_data, 4);
	if (tmp_data[0] != 0x05) {
		printf("ic state = %X\n", tmp_data[0]);
		return 1;
	} else {
		himax_register_read(fw_addr_fw_vendor_addr, tmp_data, 4);
		fw_ver_ic = tmp_data[2]<<8 | tmp_data[3];
	//	printf("fw_ver_ic = %08X\n", fw_ver_ic);
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

	if (himax_check_CRC(fw_addr_program_reload_from, len) == 0)
		result = 0;

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

	if (optp->options & OPTION_CMP_VER) {
		if (!himax_update_check(&fw)) {
			printf("don't need update\n");
			ret = 1;
			goto exit;
		}
	}

	if (optp->options & OPTION_ALL_LEN)
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

	if (optp->options & OPTION_PID) {
		printf("%04X", data[0] << 8 | data[1]);
	} else if (optp->options & OPTION_FW_VER) {
		printf("%04X", (data[2] << 8 | data[3]));
	}

	if (optp->options & (OPTION_PID | OPTION_FW_VER)) {
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

//	strcpy(driver_path, "/sys/bus/i2c/drivers/i2c_hid/");
	strcpy(driver_path, "/sys/bus/i2c/drivers/i2c_hid_acpi/");

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


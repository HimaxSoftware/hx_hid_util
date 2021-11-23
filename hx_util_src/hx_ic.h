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

#ifndef __HX_IC_REG_H__
#define __HX_IC_REG_H__

//=============HX83121A==============
/* CORE_IC */
#define ic_adr_ahb_addr_byte_0           0x00
#define ic_adr_ahb_rdata_byte_0          0x08
#define ic_adr_ahb_access_direction      0x0c
#define ic_adr_conti                     0x13
#define ic_adr_incr4                     0x0D
#define ic_adr_i2c_psw_lb                0x31
#define ic_adr_i2c_psw_ub                0x32
#define ic_cmd_ahb_access_direction_read 0x00
#define ic_cmd_conti                     0x31
#define ic_cmd_incr4                     0x12
#define ic_cmd_i2c_psw_lb                0x27
#define ic_cmd_i2c_psw_ub                0x95
#define ic_adr_tcon_on_rst               0x80020020
#define ic_addr_adc_on_rst               0x80020094
#define ic_adr_psl                       0x900000A0
#define ic_adr_cs_central_state          0x900000A8
#define ic_cmd_rst                       0x00000000

/* CORE_IC */

/* CORE_FW */
#define fw_addr_system_reset                0x90000018
#define fw_addr_ctrl_fw                     0x9000005c
#define fw_addr_flag_reset_event            0x900000e4

#define fw_addr_program_reload_from         0x00000000
#define fw_addr_program_reload_to           0x08000000
#define fw_addr_program_reload_page_write   0x0000fb00
#define fw_addr_raw_out_sel                 0x100072EC
#define fw_addr_reload_status               0x80050000
#define fw_addr_reload_crc32_result         0x80050018
#define fw_addr_reload_addr_from            0x80050020
#define fw_addr_reload_addr_cmd_beat        0x80050028

#define fw_data_clear                       0x00000000
#define fw_data_fw_stop                     0x000000A5

#define fw_addr_set_frame_addr              0x10007294

#define fw_addr_sorting_mode_en             0x10007f04
#define fw_addr_fw_mode_status              0x10007088
#define fw_addr_icid_addr                   0x900000d0
#define fw_addr_fw_ver_addr                 0x10007004
#define fw_addr_fw_cfg_addr                 0x10007084
#define fw_addr_fw_vendor_addr              0x10007000
#define fw_addr_cus_info                    0x10007008
#define fw_addr_proj_info                   0x10007014
#define fw_addr_vid_pid_addr                0x10007050
#define fw_addr_fw_id_ver_addr              0x10007054
#define fw_addr_fw_state_addr               0x900000f8
#define fw_addr_fw_dbg_msg_addr             0x10007f40
#define fw_addr_chk_fw_status               0x900000a8
#define fw_addr_chk_dd_status               0x900000E8
/* CORE_FW */

/* CORE_FLASH */
#define FLASH_RW_MAX_LEN               256
//#define PROGRAM_SZ                     48

#define flash_addr_ctrl_base           0x80000000
#define flash_addr_spi200_trans_fmt    (flash_addr_ctrl_base + 0x10)
#define flash_addr_spi200_trans_ctrl   (flash_addr_ctrl_base + 0x20)
#define flash_addr_spi200_cmd          (flash_addr_ctrl_base + 0x24)
#define flash_addr_spi200_addr         (flash_addr_ctrl_base + 0x28)
#define flash_addr_spi200_data         (flash_addr_ctrl_base + 0x2c)
#define flash_addr_spi200_fifo_rst     (flash_addr_ctrl_base + 0x30)
#define flash_addr_spi200_rst_status   (flash_addr_ctrl_base + 0x34)
#define flash_addr_spi200_flash_speed  (flash_addr_ctrl_base + 0x40)
#define flash_addr_spi200_bt_num       (flash_addr_ctrl_base + 0xe8)
#define flash_data_spi200_txfifo_rst   0x00000004
#define flash_data_spi200_rxfifo_rst   0x00000002
#define flash_data_spi200_trans_fmt    0x00020780
#define flash_data_spi200_trans_ctrl_1 0x42000003
#define flash_data_spi200_trans_ctrl_2 0x47000000
#define flash_data_spi200_trans_ctrl_3 0x67000000
#define flash_data_spi200_trans_ctrl_4 0x610ff000
#define flash_data_spi200_trans_ctrl_5 0x694002ff
#define flash_data_spi200_trans_ctrl_6 0x42000000
#define flash_data_spi200_trans_ctrl_7 0x6940020f
#define flash_data_spi200_cmd_1        0x00000005
#define flash_data_spi200_cmd_2        0x00000006
#define flash_data_spi200_cmd_3        0x000000C7
#define flash_data_spi200_cmd_4        0x000000D8
#define flash_data_spi200_cmd_5        0x00000020
#define flash_data_spi200_cmd_6        0x00000002
#define flash_data_spi200_cmd_7        0x0000003b
#define flash_data_spi200_cmd_8        0x00000003
#define flash_data_spi200_addr         0x00000000
#define flash_clk_setup_addr           0x80000040
/* CORE_FLASH */

/* CORE_DRIVER */
#define driver_addr_fw_define_flash_reload              0x10007f00
#define driver_addr_fw_define_2nd_flash_reload          0x100072c0
#define driver_data_fw_define_flash_reload_dis          0x0000a55a
#define driver_data_fw_define_flash_reload_en           0x00000000

/* CORE_DRIVER */
//================================

#endif


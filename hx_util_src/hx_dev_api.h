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

#ifndef	__HX_DEV_API_H__
#define	__HX_DEV_API_H__

int burn_firmware(DEVINFO *devp, OPTDATA *optp);
int show_info(DEVINFO *devp, OPTDATA *optp);
int show_status(OPTDATA *optp);
int rebind_driver(DEVINFO *devp);
int read_reg(OPTDATA& opt_data);
int write_reg(OPTDATA& opt_data);

int hid_update_DEVINFO(DEVINFO& oinfo);
int hid_set_data_type(OPTDATA& opt_data);
int hid_print_report_descriptor(OPTDATA& opt_data);
int hid_main_update(OPTDATA& opt_data, DEVINFO& dinfo, int& errorCode);
int hid_bl_update(OPTDATA& opt_data, DEVINFO& dinfo, int& errorCode);
int hid_self_test_by_criteria_file(OPTDATA& opt_data);
int hid_show_fw_info(OPTDATA& opt_data);
int hid_write_reg(OPTDATA& opt_data);
int hid_read_reg(OPTDATA& opt_data);
int hid_show_diag(OPTDATA& opt_data);
int hid_set_input_RD_en(OPTDATA& opt_data, DEVINFO& dinfo);
#endif

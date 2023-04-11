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

#ifndef	__HX_HID_FUNC_H__
#define	__HX_HID_FUNC_H__

int hx_get_hid_fd(void);
int hx_scan_hidraw(char **devpath, int *devfd);
int hx_scan_open_hidraw(OPTDATA& optdata);
void hx_hid_close(void);

int hx_hid_set_output(int id, int32_t idLen, uint8_t *data, int32_t dataLen);
int hx_hid_get_feature(int id, uint8_t *data, int32_t len);
int hx_hid_set_feature(int id, uint8_t *data, int32_t len);
int hx_hid_parse_RD_for_idsz(void);
int hx_hid_get_size_by_id(int id);
int hx_hid_print_RD(void);
int hx_hid_write_reg(uint32_t addr, uint32_t data, OPTDATA& optdata);
bool pollingForResult(uint8_t featureId, uint8_t *expectedData, uint32_t expectDataLength,
                uint32_t interval_ms, uint32_t timeout_s, uint8_t *received_data, int* nDataReceived);

#endif


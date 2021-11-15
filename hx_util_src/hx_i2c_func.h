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

#ifndef	__HX_I2C_FUNC_H__
#define	__HX_I2C_FUNC_H__

int hx_scan_i2c_device(char *devp);
int hx_open_i2c_device(void);
int hx_close_i2c_device(void);

int hx_i2c_write(uint8_t *pbuf, uint32_t buf_size);
int hx_i2c_read(uint8_t *txbuf, uint32_t txlen, uint8_t *rxbuf, uint32_t rxlen);

#endif


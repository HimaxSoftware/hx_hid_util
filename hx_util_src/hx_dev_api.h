/*
 * Copyright (C) 2021 Himax Technologies, Inc.
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

#endif

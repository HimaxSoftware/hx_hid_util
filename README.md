# hx_hid_util  
A Linux tool to operate himax's controller to get info or upgrade FW only.  
This source have been compiled and verified under Ubuntu 14.04.  
  
Just get the whole project and enter the "hx_hid_util" folder.  
  make: to build the exectue project "hx_util".  
  make clean: to clean the whole project.  
  
Himax Update Utility  
Copyright 2023 Himax Technologies, Limited. (http://www.himax.com.tw/).  

# ChangeLog

All notable changes to this project will be documented in this file.  
  
The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.1.0/)  
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).  

## [1.3.0]
### Added
- SNR option -n to calculate SNR on target device.  
- hid_show_version option -f to correct customer view of firmware version.
- Pen information supported by firmware in hid_show_fw_info function.
- Pen resolution and LTDI_IC_NUM info in INFO struct.
- Single IC raw data acquisition option -J.
- RX reverse -x and TX reverse option -y.
- Himax IC check option -z.
### Changed
- Extend all raw data acquisition method to LTDI batch read if IC is LTDI.
- Refactor all option check statement to is_opt_set function.
- Disable/Enable HID input after re-flash FW if -e specified.
- Wording in README.md, remove unnecessary "Add" in Added section.
- Added another applicable VID(0x3558) of Himax.

## [1.2.5] - 2023-08-16
### Added
- Self test log output to specified folder after each test.
- Check FW version, if identical, skip FW upgrade.
### Fixed
- A Report descriptor parsing issue which cause some ID can't be parsed correctly.

## [1.2.1] - 2023-05-29
### Added
- A partial raw data mode for contiuously read part of raw data for debug purpose. Full raw data acquisition took too much time and block finger report.
- Signed integer display for raw data by option "-Y".

## [1.1.5] - 2023-05-11
### Fixed
- Show Self test result even debug log option is not enabled.

## [1.1.4] - 2023-04-28
### Fixed
- Also find device in /sys/bus/i2c/drivers/i2c_hid_of/ when rebind.

## [1.1.3] - 2023-04-25
### Fixed
- Build warnings when compiling in Chromium project.

## [1.1.2] - 2023-04-21
### Changed
- Remove password check when reading FW info.
### Removed
- Report descriptor input field switch function.

## [1.1.1] - 2023-04-18
### Added
- PID display option by HIDRAW using "-P" option.
- FW verison display option by HIDRAW using "-V" option.

## [1.1.0] - 2023-04-14
### Added
- Functions by HIDRAW interface.
### Changed
- Option system modified by using 32bit integer slice.

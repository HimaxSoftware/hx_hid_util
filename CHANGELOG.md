# ChangeLog

All notable changes to this project will be documented in this file.  
  
The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.1.0/)  
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).  

## [1.3.6] - 2025-04-24
### Changed
- Reduce criteria test retry times (500->200) to reduce retry period.
- Reduce reset period from 1s to 0.5s in criteria test.
- Adjust reset and retry limit by stage, F1~F2 is 10 and F3 is 199 times. Each
  stage consume different time.

## [1.3.5] - 2025-04-23
### Added
- Reset and retry to switch mode failed case in criteria test. Most retry 3 times,
  next item when all failed.
- Delay 10ms after get raw data failed(0x08), leave time for data preparation.

## [1.3.4] - 2025-02-27
### Fixed
- Add succeed message when i2c fw update success. Which will fix himax touch update
  script in chromeos update process result false negative issue.

## [1.3.3] - 2025-02-06
### Fixed
- Remove additional version info when using -V and -P option.

## [1.3.2] - 2025-01-31
### Changed
- Separate changelog from README.md to Changelog.md.

## [1.3.1] - 2025-01-16
### Changed
- Update year of license header in modified files.

## [1.3.0] - 2025-01-07
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
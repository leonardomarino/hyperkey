# Automatic Clipboard Clearing Feature

## Overview

This document describes the automatic clipboard clearing feature implemented in HyperKey v2.2.

## Implementation Date
2026-02-03

## Feature Description

HyperKey now automatically clears the clipboard after a configurable timeout period to enhance security. This addresses the risk of passwords remaining in the clipboard indefinitely, potentially exposing them to:
- Clipboard history tools
- Password managers that log clipboard contents
- Cloud sync services
- Other applications monitoring clipboard

## User Interface

### Command-Line Options

1. **`--clipboard-timeout SECONDS`**
   - Sets the number of seconds to wait before clearing clipboard
   - Default: 30 seconds
   - Valid range: 1-3600 seconds (1 second to 1 hour)
   - Example: `./hyperkey.py seed.jpg yellow banking --clipboard-timeout 20`

2. **`--no-clipboard-clear`**
   - Disables automatic clipboard clearing entirely
   - Password remains in clipboard until manually overwritten
   - Shows warning messages about clipboard security
   - Example: `./hyperkey.py seed.jpg green email --no-clipboard-clear`

### User Experience

When clipboard clearing is enabled (default):
1. Password is generated and copied to clipboard
2. User sees: `[+] Copied to clipboard`
3. Countdown timer displays: `[!] Clearing in 30s (press Enter to skip)...`
4. Timer updates every second
5. After timeout, clipboard is cleared and user sees: `[+] Clipboard cleared`
6. User can press Enter at any time to exit early without clearing

When clipboard clearing is disabled:
1. Password is generated and copied to clipboard
2. User sees: `[+] Copied to clipboard`
3. Warning messages displayed:
   - `[!] WARNING: Password remains in clipboard until overwritten`
   - `[!] Clipboard may be logged by password managers or sync services`

## Technical Implementation

### New Functions

1. **`secure_clear_clipboard()`** (lines 260-272)
   - Overwrites clipboard with empty string
   - Returns True on success, False on failure
   - Handles exceptions gracefully

2. **`clipboard_timeout_handler(timeout_seconds, output)`** (lines 275-360)
   - Displays countdown timer
   - Monitors for user key press (Enter) to exit early
   - Clears clipboard after timeout
   - Cross-platform implementation:
     - Unix/Linux: Uses `termios`, `tty`, and `select`
     - Windows: Uses `msvcrt` module
   - Returns True if cleared after timeout, False if user exited early

### Modified Functions

1. **`main()`** function
   - Added argparse for better command-line parsing
   - New arguments: `--clipboard-timeout` and `--no-clipboard-clear`
   - Integrated clipboard timeout handler into clipboard workflow
   - Validates timeout value (clamped to 1-3600 seconds)

### Cross-Platform Compatibility

**Unix/Linux/macOS:**
- Uses `termios` to set terminal to raw mode
- Uses `select.select()` for non-blocking keyboard input
- Restores terminal settings in finally block

**Windows:**
- Uses `msvcrt.kbhit()` to check for key presses
- Uses `msvcrt.getch()` to consume key press
- Polling-based approach with 0.1s sleep intervals

## Test Coverage

Added 5 new unit tests (17 total):

1. **`test_secure_clear_clipboard()`**
   - Tests clipboard clearing function with mock pyperclip
   - Verifies success/failure return values
   - Tests with clipboard enabled and disabled
   - Tests exception handling

2. **`test_clipboard_timeout_handler()`**
   - Mocks time progression and terminal operations
   - Verifies clipboard is cleared after timeout
   - Tests countdown display logic

3. **`test_clipboard_timeout_early_exit()`**
   - Simulates user pressing Enter during countdown
   - Verifies clipboard is NOT cleared on early exit
   - Tests early exit detection logic

4. **`test_main_with_no_clipboard_clear()`**
   - Tests `--no-clipboard-clear` flag
   - Verifies timeout handler is NOT called
   - Verifies warning messages are displayed

5. **`test_main_with_clipboard_timeout()`**
   - Tests `--clipboard-timeout` option with custom value
   - Verifies timeout handler is called with correct value
   - Tests argument parsing

**Test Results:** All 17 tests passing (100% success rate)

## Security Considerations

### Benefits
- Reduces window of exposure for passwords in clipboard
- Configurable timeout allows users to balance security and convenience
- User feedback via countdown timer
- Early exit option for quick password entry

### Limitations
- Cannot prevent clipboard history tools from logging before clearing
- Cannot prevent other applications from reading clipboard during timeout
- Python's garbage collection may not immediately free memory
- Some operating systems/desktop environments may cache clipboard contents

### Recommendations for Users
1. Disable clipboard history features in your operating system:
   - macOS: Disable clipboard managers like Paste, CopyClip, etc.
   - Windows: Disable "Clipboard history" in Settings > System > Clipboard
   - Linux: Disable clipboard managers like Clipit, Parcellite, etc.

2. Use shorter timeout values for high-security accounts:
   - Green policy (daily accounts): 30s (default)
   - Yellow policy (financial): 20s
   - Red policy (critical): 10s

3. Consider `--no-clipboard-clear` only for:
   - Automated scripts where timeout would block execution
   - Environments where clipboard security is not a concern
   - Testing and development

## Version History

### v2.2 (Current)
- ✓ Automatic clipboard clearing implemented
- ✓ Configurable timeout (1-3600 seconds)
- ✓ Countdown timer with early exit
- ✓ Cross-platform support (Unix/Windows)
- ✓ Comprehensive test coverage
- ✓ Full documentation

### Future Enhancements (Proposed)
- Secure memory locking for clipboard contents
- Clipboard monitoring to detect unauthorized access
- Integration with platform-specific secure clipboard APIs
- Configurable policies per service (different timeouts for different accounts)
- Audio/visual notifications when clipboard is cleared

## Files Modified

1. **`hyperkey.py`**
   - Added imports: `time`, `argparse`, `select`
   - Added functions: `secure_clear_clipboard()`, `clipboard_timeout_handler()`
   - Modified: `main()` function for argparse and clipboard integration
   - Updated version to v2.2

2. **`tests/test_hyperkey.py`**
   - Added imports: `time`, `call` (from unittest.mock)
   - Added 5 new test methods
   - Modified existing tests to mock clipboard timeout handler

3. **`README.md`**
   - Updated Features section
   - Updated Usage section with new options and examples
   - Added Clipboard Security section
   - Updated Changelog for v2.2

4. **`SECURITY_FIXES.md`**
   - Updated clipboard security section (item #3)
   - Marked items #1 and #2 as implemented in Future Improvements
   - Updated test count (17 tests)
   - Added v2.2 enhancements

5. **`CLIPBOARD_FEATURE.md`** (new)
   - This document

## Migration Guide

### For Existing Users

**No Breaking Changes:**
- Default behavior now includes 30-second clipboard clearing
- To maintain v2.1 behavior: use `--no-clipboard-clear` flag
- All existing scripts/commands work with new default behavior

**Recommended Actions:**
1. Test the new feature with default 30s timeout
2. Adjust timeout based on your needs using `--clipboard-timeout`
3. Update any automation scripts that rely on clipboard persistence
4. Review clipboard security settings in your OS

### For Script Authors

**Example:** Simple password generation
```bash
# Old (v2.1)
./hyperkey.py seed.jpg green myservice

# New (v2.2) - same command, now with 30s auto-clear
./hyperkey.py seed.jpg green myservice

# New (v2.2) - maintain old behavior
./hyperkey.py seed.jpg green myservice --no-clipboard-clear
```

**Example:** Automated scripts
```bash
# For automation, disable clearing to avoid blocking
./hyperkey.py seed.jpg green myservice --no-clipboard-clear | tail -1
```

**Example:** High-security accounts
```bash
# Use shorter timeout for sensitive accounts
./hyperkey.py seed.jpg red root-account --clipboard-timeout 10
```

## Known Issues

None currently identified.

## Support

For issues or questions about this feature:
1. Check the README.md for usage examples
2. Run `./hyperkey.py --help` for command-line options
3. Review test cases in `tests/test_hyperkey.py` for expected behavior
4. Report bugs at: https://github.com/leonardomarino/hyperkey/issues

# Security Fixes Applied

This document summarizes the critical security issues that were identified and fixed in HyperKey.

## Date: 2026-02-03

## Critical Security Issues Fixed

### 1. URL Validation Bypass (FIXED)
**Location:** `hyperkey.py:266-289`

**Issue:** The original code checked if the URL was HTTPS using `.lower()` but then passed the original (potentially mixed-case) URL to `urlopen()`. This could allow bypass attempts using mixed-case protocols like `HTTP://` or `HtTp://`.

**Fix:**
- Added proper URL normalization
- Validates that the protocol is correctly formatted
- Normalizes to lowercase `https://` before fetching
- Added warning message about using remote seed files

**Test Coverage:** Manual validation of URL parsing logic

---

### 2. Missing Input Validation (FIXED)
**Location:** `hyperkey.py:256-302` (new function added)

**Issue:** The code accepted arbitrary service names and passphrases without validation, which could lead to:
- Path traversal attacks (`../etc/passwd`)
- Memory exhaustion (extremely long inputs)
- Impossible policy requirements causing infinite loops

**Fix:**
Added comprehensive `validate_inputs()` function that checks:
- Service name is not empty and ≤ 256 characters
- Service name doesn't contain path traversal characters (`..`, `/`, `\`)
- Passphrase is ≥ 8 characters (minimum security) and ≤ 1024 characters
- Policy requirements are mathematically achievable
- Minimum character requirements don't exceed password length
- Number of required unique symbols doesn't exceed available symbols

**Test Coverage:**
- `test_validate_empty_service()`
- `test_validate_service_path_traversal()`
- `test_validate_weak_passphrase()`
- `test_validate_excessive_lengths()`
- `test_validate_impossible_policy()`
- `test_validate_valid_inputs()`

---

### 3. Clipboard Security (COMPLETELY REMOVED in v2.3) ✓
**Location:** N/A (clipboard functionality removed)

**Original Issue:** Passwords were copied to clipboard without warning or automatic clearing:
- Clipboard managers may log passwords
- Cloud sync services may upload clipboard contents
- Other applications can access clipboard
- Password remains until explicitly overwritten

**v2.1 Fix:** Added explicit warnings when password is copied to clipboard

**v2.2 Enhancement:** Implemented automatic clipboard clearing with configurable timeout

**v2.3 Solution (CURRENT):**
- **Completely removed clipboard functionality** for maximum security
- Passwords are now **only displayed on screen** - never copied to clipboard
- Eliminates all clipboard-related security risks:
  - No clipboard history logging
  - No password manager interception
  - No cloud sync exposure
  - No application eavesdropping
- **Removed dependencies:** pyperclip no longer required
- **Simplified codebase:** Removed ~110 lines of clipboard-related code

**Test Coverage:**
- Clipboard-specific tests removed (no longer applicable)
- Core functionality tests maintained (12 tests passing)

---

### 4. Incomplete Android Code Path (COMPLETELY REMOVED in v2.3) ✓
**Location:** N/A (Android code removed)

**Issue:** The `droidMain()` function silently exited with code 0 without generating a password, creating a security hole where users might think a password was generated when it wasn't.

**v2.1 Fix:**
- Added error message explaining Android support is not implemented
- Changed exit code to 1 (error) instead of 0 (success)
- Provides guidance to use standard CLI interface

**v2.3 Solution (CURRENT):**
- **Completely removed all Android/Termux code** (~15 lines removed)
- Removed `droidMain()` function
- Removed Android import and DROID_ENABLED flag
- Simplified main execution block
- HyperKey is now a pure desktop CLI tool

**Test Coverage:** Not applicable (Android code removed)

---

## Additional Security Enhancements

### 5. Improved Error Handling
**Location:** `hyperkey.py:21` (import), `hyperkey.py:318-339` (exception handling)

**Enhancement:** Added proper exception handling for network errors:
- `HTTPError` - catches HTTP status errors (404, 500, etc.)
- `URLError` - catches connection failures
- `FileNotFoundError` - explicit handling for missing seed files
- `PermissionError` - explicit handling for access denied errors

---

### 6. Dependency Management
**New File:** `requirements.txt`

**Enhancement:**
- Created proper dependency file with version pinning
- Updated CI/CD workflow to use `requirements.txt`
- Ensures reproducible builds and security updates

---

## Test Suite Enhancements

**v2.1:** Added 6 new test cases covering:
1. Empty service name validation
2. Path traversal attack prevention
3. Weak passphrase rejection
4. Excessive length handling
5. Impossible policy detection
6. Valid input acceptance

**v2.2:** Added 5 clipboard-related test cases (later removed in v2.3)

**v2.3:** Removed clipboard tests, maintained core functionality tests

**Test Results:** All 12 tests passing (100% success rate)

---

## Verification

To verify the fixes are working:

```bash
# Run the test suite
python3 -m unittest discover -v -s tests

# Test input validation manually
./hyperkey.py test.jpg green "../etc/passwd"  # Should reject
./hyperkey.py test.jpg green "myservice" "short"  # Should reject (passphrase too short)

# Test URL validation
./hyperkey.py HTTP://example.com/seed.bin green myservice  # Should reject
```

---

## Recommendations for Users

1. **Always use local seed files** instead of remote URLs when possible
2. **Use strong passphrases** of at least 12 characters with mixed character types
3. **Manually copy passwords** from screen output when needed - no clipboard risks
4. **Validate your seed file integrity** regularly with checksums
5. **Keep secure backups** of your seed file in multiple locations

---

## Future Security Improvements

Consider implementing:
1. ~~Automatic clipboard clearing after timeout~~ ✓ **IMPLEMENTED in v2.2, REMOVED in v2.3**
2. ~~Option to disable clipboard entirely~~ ✓ **IMPLEMENTED in v2.3** (clipboard removed completely)
3. Secure memory locking (if platform supports it)
4. Rate limiting for repeated password generation attempts
5. Optional audit logging for security-critical environments
6. Integration with hardware security modules (HSM) for enterprise use

---

## Change Summary

### v2.1-v2.2
- **Files Modified:** 3 (`hyperkey.py`, `tests/test_hyperkey.py`, `.github/workflows/ci.yml`)
- **Files Added:** 2 (`requirements.txt`, `SECURITY_FIXES.md`)
- **Lines Added:** ~140
- **Tests Added:** 6 validation + 5 clipboard test cases
- **Security Issues Fixed:** 4 critical, 2 enhancements

### v2.3 (Current)
- **Files Modified:** 4 (`hyperkey.py`, `tests/test_hyperkey.py`, `README.md`, `SECURITY_FIXES.md`)
- **Files Removed:** 1 (`CLIPBOARD_FEATURE.md`)
- **Lines Removed:** ~125 (110 clipboard + 15 Android)
- **Dependencies Removed:** pyperclip
- **Security Enhancements:**
  - Eliminated all clipboard-related attack vectors
  - Removed unimplemented Android code path
- **Tests:** 12 core tests maintained (5 clipboard tests removed)
- **Platform Support:** Desktop-only (Windows, macOS, Linux)

All changes significantly improve security posture while simplifying the codebase.

use core::ffi::c_int;

use axerrno::LinuxError;
use kmod::capi_fn;

const KSTRTOX_OVERFLOW: u32 = 1 << 31;
const ULLONG_MAX: u64 = u64::MAX;
const INT_MAX: usize = i32::MAX as usize;

/// Helper: convert character to lowercase
#[inline]
fn to_lower(c: u8) -> u8 {
    if c.is_ascii_uppercase() { c + 32 } else { c }
}

/// Helper: check if character is a hex digit
#[inline]
fn is_xdigit(c: u8) -> bool {
    c.is_ascii_digit() || (b'a'..=b'f').contains(&c) || (b'A'..=b'F').contains(&c)
}

/// Parse integer fixup radix - auto-detect base from string prefix
/// # Arguments
/// - s: input string
/// - base: pointer to base value (will be modified)
/// # Returns
/// Updated string pointer (after prefix if detected)
#[inline(never)]
pub unsafe extern "C" fn _parse_integer_fixup_radix(
    mut s: *const core::ffi::c_char,
    base: *mut u32,
) -> *const core::ffi::c_char {
    if *base == 0 {
        let first = *s as u8;
        if first == b'0' {
            let second = *s.add(1) as u8;
            if to_lower(second) == b'x' && is_xdigit(*s.add(2) as u8) {
                *base = 16;
            } else {
                *base = 8;
            }
        } else {
            *base = 10;
        }
    }
    if *base == 16 && *s as u8 == b'0' && to_lower(*s.add(1) as u8) == b'x' {
        s = s.add(2);
    }
    s
}

/// Parse integer with limit on number of characters
/// # Arguments
/// - s: input string
/// - base: the radix
/// - p: pointer to result
/// - max_chars: maximum characters to parse
/// # Returns
/// Number of characters consumed (possibly with KSTRTOX_OVERFLOW bit set)
#[inline(never)]
pub unsafe extern "C" fn _parse_integer_limit(
    mut s: *const core::ffi::c_char,
    base: u32,
    p: *mut u64,
    mut max_chars: usize,
) -> u32 {
    let mut res: u64 = 0;
    let mut rv: u32 = 0;

    while max_chars > 0 {
        let c = *s as u8;
        let lc = to_lower(c);
        let val: u32;

        if c.is_ascii_digit() {
            val = (c - b'0') as u32;
        } else if (b'a'..=b'f').contains(&lc) {
            val = (lc - b'a' + 10) as u32;
        } else {
            break;
        }

        if val >= base {
            break;
        }

        // Check for overflow only if we are within range of it in the max base we support (16)
        if res & (!0u64 << 60) != 0
            && res > (ULLONG_MAX - val as u64) / base as u64 {
                rv |= KSTRTOX_OVERFLOW;
            }
        // res = res * base as u64 + val as u64;
        res = res.wrapping_mul(base as u64).wrapping_add(val as u64);
        rv += 1;
        s = s.add(1);
        max_chars -= 1;
    }
    *p = res;
    rv
}

/// Parse integer without character limit
/// # Arguments
/// - s: input string
/// - base: the radix
/// - p: pointer to result
/// # Returns
/// Number of characters consumed (possibly with KSTRTOX_OVERFLOW bit set)
#[inline(never)]
pub unsafe extern "C" fn _parse_integer(
    s: *const core::ffi::c_char,
    base: u32,
    p: *mut u64,
) -> u32 {
    _parse_integer_limit(s, base, p, INT_MAX)
}

/// Internal function: convert unsigned long long
fn kstrtoull_internal(s: *const core::ffi::c_char, base: u32, res: *mut u64) -> c_int {
    let mut s = s;
    let mut _base = base;
    let mut _res: u64 = 0;

    unsafe {
        s = _parse_integer_fixup_radix(s, &mut _base);
        let rv = _parse_integer(s, _base, &mut _res);

        if rv & KSTRTOX_OVERFLOW != 0 {
            return -(LinuxError::ERANGE as c_int);
        }
        if rv == 0 {
            return -(LinuxError::EINVAL as c_int);
        }
        s = s.add(rv as usize);
        if *s as u8 == b'\n' {
            s = s.add(1);
        }
        if *s != 0 {
            return -(LinuxError::EINVAL as c_int);
        }
        *res = _res;
    }
    0
}

/// kstrtoull - convert a string to an unsigned long long
/// # Arguments
/// - s: The start of the string. The string must be null-terminated, and may also
///   include a single newline before its terminating null. The first character
///   may also be a plus sign, but not a minus sign.
/// - base: The number base to use. The maximum supported base is 16. If base is
///   given as 0, then the base of the string is automatically detected with the
///   conventional semantics - If it begins with 0x the number will be parsed as a
///   hexadecimal (case insensitive), if it otherwise begins with 0, it will be
///   parsed as an octal number. Otherwise it will be parsed as a decimal.
/// - res: Where to write the result of the conversion on success.
///
/// # Returns
/// 0 on success, -ERANGE on overflow and -EINVAL on parsing error.
#[capi_fn]
#[inline(never)]
pub unsafe extern "C" fn kstrtoull(s: *const core::ffi::c_char, base: u32, res: *mut u64) -> c_int {
    let s = if !s.is_null() && *s as u8 == b'+' {
        s.add(1)
    } else {
        s
    };
    kstrtoull_internal(s, base, res)
}

/// kstrtoll - convert a string to a long long
/// # Arguments
/// - s: The start of the string. The string must be null-terminated, and may also
///   include a single newline before its terminating null. The first character
///   may also be a plus sign or a minus sign.
/// - base: The number base to use. The maximum supported base is 16. If base is
///   given as 0, then the base of the string is automatically detected.
/// - res: Where to write the result of the conversion on success.
///
/// # Returns
/// 0 on success, -ERANGE on overflow and -EINVAL on parsing error.
#[capi_fn]
#[inline(never)]
pub unsafe extern "C" fn kstrtoll(s: *const core::ffi::c_char, base: u32, res: *mut i64) -> c_int {
    if s.is_null() {
        return -(LinuxError::EINVAL as c_int);
    }

    if *s as u8 == b'-' {
        let mut tmp: u64 = 0;
        let rv = kstrtoull_internal(s.add(1), base, &mut tmp);
        if rv < 0 {
            return rv;
        }
        let tmp_signed = -(tmp as i64);
        if tmp_signed > 0 {
            return -(LinuxError::ERANGE as c_int);
        }
        unsafe {
            *res = tmp_signed;
        }
    } else {
        let mut tmp: u64 = 0;
        let rv = kstrtoull(s, base, &mut tmp);
        if rv < 0 {
            return rv;
        }
        if (tmp as i64) < 0 {
            return -(LinuxError::ERANGE as c_int);
        }
        unsafe {
            *res = tmp as i64;
        }
    }
    0
}

/// Internal function for kstrtoul
fn _kstrtoul_internal(s: *const core::ffi::c_char, base: u32, res: *mut u32) -> c_int {
    let mut tmp: u64 = 0;
    let rv = unsafe { kstrtoull(s, base, &mut tmp) };
    if rv < 0 {
        return rv;
    }
    if tmp != tmp as u32 as u64 {
        return -(LinuxError::ERANGE as c_int);
    }
    unsafe {
        *res = tmp as u32;
    }
    0
}

/// Internal function for kstrtol
fn _kstrtol_internal(s: *const core::ffi::c_char, base: u32, res: *mut i32) -> c_int {
    let mut tmp: i64 = 0;
    let rv = unsafe { kstrtoll(s, base, &mut tmp) };
    if rv < 0 {
        return rv;
    }
    if tmp != tmp as i32 as i64 {
        return -(LinuxError::ERANGE as c_int);
    }
    unsafe {
        *res = tmp as i32;
    }
    0
}

/// kstrtouint - convert a string to an unsigned int
/// # Returns
/// 0 on success, -ERANGE on overflow and -EINVAL on parsing error.
#[capi_fn]
#[inline(never)]
pub unsafe extern "C" fn kstrtouint(
    s: *const core::ffi::c_char,
    base: u32,
    res: *mut u32,
) -> c_int {
    _kstrtoul_internal(s, base, res)
}

/// kstrtoint - convert a string to an int
/// # Returns
/// 0 on success, -ERANGE on overflow and -EINVAL on parsing error.
#[capi_fn]
#[inline(never)]
pub unsafe extern "C" fn kstrtoint(s: *const core::ffi::c_char, base: u32, res: *mut i32) -> c_int {
    _kstrtol_internal(s, base, res)
}

/// kstrtou16 - convert a string to an unsigned short
/// # Returns
/// 0 on success, -ERANGE on overflow and -EINVAL on parsing error.
#[capi_fn]
#[inline(never)]
pub unsafe extern "C" fn kstrtou16(s: *const core::ffi::c_char, base: u32, res: *mut u16) -> c_int {
    let mut tmp: u64 = 0;
    let rv = unsafe { kstrtoull(s, base, &mut tmp) };
    if rv < 0 {
        return rv;
    }
    if tmp != tmp as u16 as u64 {
        return -(LinuxError::ERANGE as c_int);
    }
    unsafe {
        *res = tmp as u16;
    }
    0
}

/// kstrtos16 - convert a string to a short
/// # Returns
/// 0 on success, -ERANGE on overflow and -EINVAL on parsing error.
#[capi_fn]
#[inline(never)]
pub unsafe extern "C" fn kstrtos16(s: *const core::ffi::c_char, base: u32, res: *mut i16) -> c_int {
    let mut tmp: i64 = 0;
    let rv = unsafe { kstrtoll(s, base, &mut tmp) };
    if rv < 0 {
        return rv;
    }
    if tmp != tmp as i16 as i64 {
        return -(LinuxError::ERANGE as c_int);
    }
    unsafe {
        *res = tmp as i16;
    }
    0
}

/// kstrtou8 - convert a string to an unsigned char
/// # Returns
/// 0 on success, -ERANGE on overflow and -EINVAL on parsing error.
#[capi_fn]
#[inline(never)]
pub unsafe extern "C" fn kstrtou8(s: *const core::ffi::c_char, base: u32, res: *mut u8) -> c_int {
    let mut tmp: u64 = 0;
    let rv = unsafe { kstrtoull(s, base, &mut tmp) };
    if rv < 0 {
        return rv;
    }
    if tmp != tmp as u8 as u64 {
        return -(LinuxError::ERANGE as c_int);
    }
    unsafe {
        *res = tmp as u8;
    }
    0
}

/// kstrtos8 - convert a string to a signed char
/// # Returns
/// 0 on success, -ERANGE on overflow and -EINVAL on parsing error.
#[capi_fn]
#[inline(never)]
pub unsafe extern "C" fn kstrtos8(s: *const core::ffi::c_char, base: u32, res: *mut i8) -> c_int {
    let mut tmp: i64 = 0;
    let rv = unsafe { kstrtoll(s, base, &mut tmp) };
    if rv < 0 {
        return rv;
    }
    if tmp != tmp as i8 as i64 {
        return -(LinuxError::ERANGE as c_int);
    }
    unsafe {
        *res = tmp as i8;
    }
    0
}

/// kstrtobool - convert common user inputs into boolean values
/// # Arguments
/// - s: input string
/// - res: result
/// # Returns
/// 0 if successful, -EINVAL otherwise
/// This routine returns 0 iff the first character is one of 'YyTt1NnFf0', or
/// [oO][NnFf] for "on" and "off". Otherwise it will return -EINVAL.  Value
/// pointed to by res is updated upon finding a match
#[capi_fn]
#[inline(never)]
pub unsafe extern "C" fn kstrtobool(s: *const core::ffi::c_char, res: *mut bool) -> c_int {
    if s.is_null() || res.is_null() {
        return -(LinuxError::EINVAL as c_int);
    }
    let first_char = *s as u8;

    match first_char {
        b'y' | b'Y' | b't' | b'T' | b'1' => {
            *res = true;
            0
        }
        b'n' | b'N' | b'f' | b'F' | b'0' => {
            *res = false;
            0
        }
        b'o' | b'O' => {
            let second_char = *s.add(1) as u8;
            match second_char {
                b'n' | b'N' => {
                    *res = true;
                    0
                }
                b'f' | b'F' => {
                    *res = false;
                    0
                }
                _ => -(LinuxError::EINVAL as c_int),
            }
        }
        _ => -(LinuxError::EINVAL as c_int),
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_int;

    #[test]
    fn test_kstrtobool() {
        use super::kstrtobool;
        let test_cases = [
            (c"y", true),
            (c"Y", true),
            (c"t", true),
            (c"T", true),
            (c"1", true),
            (c"n", false),
            (c"N", false),
            (c"f", false),
            (c"F", false),
            (c"0", false),
            (c"on", true),
            (c"ON", true),
            (c"off", false),
            (c"OFF", false),
        ];
        for (input, expected) in test_cases.iter() {
            let mut result: bool = false;
            let ret_code = unsafe { kstrtobool(input.as_ptr(), &mut result as *mut bool) };
            assert_eq!(ret_code, 0, "Input: {:?}", input);
            assert_eq!(result, *expected, "Input: {:?}", input);
        }
        // Test invalid inputs
        let invalid_inputs = [c"", c"maybe", c"2", c"o"];
        for input in invalid_inputs.iter() {
            let mut result: bool = false;
            let ret_code = unsafe { kstrtobool(input.as_ptr(), &mut result as *mut bool) };
            assert_eq!(
                ret_code,
                -(super::LinuxError::EINVAL as c_int),
                "Input: {:?}",
                input
            );
        }

        // Test null pointer inputs
        let mut result: bool = false;
        let ret_code = unsafe { kstrtobool(core::ptr::null(), &mut result as *mut bool) };
        assert_eq!(
            ret_code,
            -(super::LinuxError::EINVAL as c_int),
            "Null string pointer"
        );
    }

    #[test]
    fn test_kstrtoull() {
        use super::kstrtoull;
        let mut result: u64 = 0;

        // Test decimal
        let ret = unsafe { kstrtoull(c"123".as_ptr(), 10, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 123);

        // Test hexadecimal with prefix
        let ret = unsafe { kstrtoull(c"0x1a".as_ptr(), 0, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 26);

        // Test octal with prefix
        let ret = unsafe { kstrtoull(c"0777".as_ptr(), 0, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 511);

        // Test with leading plus sign
        let ret = unsafe { kstrtoull(c"+456".as_ptr(), 10, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 456);

        // Test with newline
        let ret = unsafe { kstrtoull(c"789\n".as_ptr(), 10, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 789);

        // Test invalid input
        let ret = unsafe { kstrtoull(c"abc".as_ptr(), 10, &mut result) };
        assert!(ret < 0);

        // Test overflow
        let ret = unsafe { kstrtoull(c"18446744073709551616".as_ptr(), 10, &mut result) };
        assert!(ret < 0);
    }

    #[test]
    fn test_kstrtoll() {
        use super::kstrtoll;
        let mut result: i64 = 0;

        // Test positive decimal
        let ret = unsafe { kstrtoll(c"123".as_ptr(), 10, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 123);

        // Test negative decimal
        let ret = unsafe { kstrtoll(c"-456".as_ptr(), 10, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, -456);

        // Test with leading plus sign
        let ret = unsafe { kstrtoll(c"+789".as_ptr(), 10, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 789);

        // Test hexadecimal
        let ret = unsafe { kstrtoll(c"-0x10".as_ptr(), 0, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, -16);

        // Test invalid input
        let ret = unsafe { kstrtoll(c"xyz".as_ptr(), 10, &mut result) };
        assert!(ret < 0);
    }

    #[test]
    fn test_kstrtouint() {
        use super::kstrtouint;
        let mut result: u32 = 0;

        // Test basic conversion
        let ret = unsafe { kstrtouint(c"123".as_ptr(), 10, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 123);

        // Test hexadecimal
        let ret = unsafe { kstrtouint(c"0xff".as_ptr(), 0, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 255);

        // Test with newline
        let ret = unsafe { kstrtouint(c"456\n".as_ptr(), 10, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 456);

        // Test invalid input
        let ret = unsafe { kstrtouint(c"invalid".as_ptr(), 10, &mut result) };
        assert!(ret < 0);
    }

    #[test]
    fn test_kstrtoint() {
        use super::kstrtoint;
        let mut result: i32 = 0;

        // Test positive
        let ret = unsafe { kstrtoint(c"789".as_ptr(), 10, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 789);

        // Test negative
        let ret = unsafe { kstrtoint(c"-123".as_ptr(), 10, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, -123);

        // Test hexadecimal
        let ret = unsafe { kstrtoint(c"0x20".as_ptr(), 0, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 32);

        // Test invalid input
        let ret = unsafe { kstrtoint(c"notint".as_ptr(), 10, &mut result) };
        assert!(ret < 0);
    }

    #[test]
    fn test_kstrtou16() {
        use super::kstrtou16;
        let mut result: u16 = 0;

        // Test basic conversion
        let ret = unsafe { kstrtou16(c"65535".as_ptr(), 10, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 65535);

        // Test hexadecimal
        let ret = unsafe { kstrtou16(c"0xffff".as_ptr(), 0, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 65535);

        // Test overflow
        let ret = unsafe { kstrtou16(c"65536".as_ptr(), 10, &mut result) };
        assert!(ret < 0);

        // Test invalid input
        let ret = unsafe { kstrtou16(c"notu16".as_ptr(), 10, &mut result) };
        assert!(ret < 0);
    }

    #[test]
    fn test_kstrtos16() {
        use super::kstrtos16;
        let mut result: i16 = 0;

        // Test positive
        let ret = unsafe { kstrtos16(c"32767".as_ptr(), 10, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 32767);

        // Test negative
        let ret = unsafe { kstrtos16(c"-32768".as_ptr(), 10, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, -32768);

        // Test hexadecimal
        let ret = unsafe { kstrtos16(c"0x100".as_ptr(), 0, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 256);

        // Test overflow
        let ret = unsafe { kstrtos16(c"32768".as_ptr(), 10, &mut result) };
        assert!(ret < 0);
    }

    #[test]
    fn test_kstrtou8() {
        use super::kstrtou8;
        let mut result: u8 = 0;

        // Test basic conversion
        let ret = unsafe { kstrtou8(c"255".as_ptr(), 10, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 255);

        // Test hexadecimal
        let ret = unsafe { kstrtou8(c"0xff".as_ptr(), 0, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 255);

        // Test overflow
        let ret = unsafe { kstrtou8(c"256".as_ptr(), 10, &mut result) };
        assert!(ret < 0);

        // Test invalid input
        let ret = unsafe { kstrtou8(c"notu8".as_ptr(), 10, &mut result) };
        assert!(ret < 0);
    }

    #[test]
    fn test_kstrtos8() {
        use super::kstrtos8;
        let mut result: i8 = 0;

        // Test positive
        let ret = unsafe { kstrtos8(c"127".as_ptr(), 10, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 127);

        // Test negative
        let ret = unsafe { kstrtos8(c"-128".as_ptr(), 10, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, -128);

        // Test hexadecimal
        let ret = unsafe { kstrtos8(c"0x10".as_ptr(), 0, &mut result) };
        assert_eq!(ret, 0);
        assert_eq!(result, 16);

        // Test overflow
        let ret = unsafe { kstrtos8(c"128".as_ptr(), 10, &mut result) };
        assert!(ret < 0);
    }
}

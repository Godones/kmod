use crate::{ModuleErr, Result};
use alloc::ffi::CString;
use axerrno::LinuxError;
use core::ffi::{
    CStr, c_char, c_int, c_long, c_short, c_uchar, c_uint, c_ulong, c_ulonglong, c_ushort, c_void,
};
use kmod::{KernelParam, ParamOpsFlags, cdata};
use paste::paste;

pub trait KernelParamValue: Sized {
    fn parse(s: &str) -> Result<Self>;
    fn format(self, buf: *mut u8) -> Result<usize>;
}

fn parse_base<T>(s: &str) -> Result<T>
where
    T: TryFrom<i128>,
{
    let s = s.trim();

    let v = if s.starts_with("0x") || s.starts_with("0X") {
        i128::from_str_radix(&s[2..], 16)
    } else if s.starts_with('0') && s.len() > 1 {
        i128::from_str_radix(&s[1..], 8)
    } else {
        s.parse::<i128>()
    }
    .map_err(|_| ModuleErr::EINVAL)?;

    T::try_from(v).map_err(|_| ModuleErr::EINVAL)
}

fn common_parse<T: KernelParamValue>(val: *const c_char) -> Result<T> {
    let c_str = unsafe { CStr::from_ptr(val) };
    let s = c_str.to_str().map_err(|_| ModuleErr::EINVAL)?;
    let v = T::parse(s)?;
    Ok(v)
}

fn common_set<T: KernelParamValue>(val: *const c_char, kp: *const kmod::kernel_param) -> c_int {
    let v = match common_parse::<T>(val) {
        Ok(v) => v,
        Err(_) => return -(ModuleErr::EINVAL as c_int),
    };
    let arg_ptr = unsafe { kp.as_ref().unwrap().__bindgen_anon_1.arg };
    unsafe {
        *(arg_ptr as *mut T) = v;
    }
    0
}

/// Macro to define standard kernel parameter operations for a given type.
///
/// See <https://elixir.bootlin.com/linux/v6.6/source/kernel/params.c#L218>
macro_rules! impl_macro {
    ($name: ident, $type: ident, $format:expr) => {
        #[repr(transparent)]
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        #[allow(non_camel_case_types)]
        struct $name($type);

        impl KernelParamValue for $name {
            fn parse(s: &str) -> Result<Self> {
                let v = parse_base::<$type>(s)?;
                Ok($name(v))
            }

            fn format(self, buf: *mut u8) -> Result<usize> {
                let s = alloc::format!($format, self.0);
                let bytes = s.as_bytes();
                unsafe {
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
                }
                Ok(bytes.len())
            }
        }
        paste! {
            unsafe extern "C" fn [<param_set_$name>](
                val: *const c_char,
                kp: *const kmod::kernel_param,
            ) -> c_int {
                common_set::<$name>(val, kp)
            }

            unsafe extern "C" fn [<param_get_$name>](
                buffer: *mut c_char,
                kp: *const kmod::kernel_param,
            ) -> c_int {
                let arg_ptr = unsafe { kp.as_ref().unwrap().__bindgen_anon_1.arg };
                let v = unsafe { *(arg_ptr as *const $name) };
                let len = v.format(buffer as *mut u8).unwrap_or(0);
                len as c_int
            }

            #[cdata]
            static [<param_ops_$name>]: kmod::kernel_param_ops = kmod::kernel_param_ops {
                set: Some([<param_set_$name>]),
                get: Some([<param_get_$name>]),
                flags: 0,
                free: None,
            };
        }
    };
}

// STANDARD_PARAM_DEF(byte,	unsigned char,		"%hhu",		kstrtou8);
// STANDARD_PARAM_DEF(short,	short,			"%hi",		kstrtos16);
// STANDARD_PARAM_DEF(ushort,	unsigned short,		"%hu",		kstrtou16);
// STANDARD_PARAM_DEF(int,		int,			"%i",		kstrtoint);
// STANDARD_PARAM_DEF(uint,	unsigned int,		"%u",		kstrtouint);
// STANDARD_PARAM_DEF(long,	long,			"%li",		kstrtol);
// STANDARD_PARAM_DEF(ulong,	unsigned long,		"%lu",		kstrtoul);
// STANDARD_PARAM_DEF(ullong,	unsigned long long,	"%llu",		kstrtoull);
// STANDARD_PARAM_DEF(hexint,	unsigned int,		"%#08x", 	kstrtouint);
impl_macro!(byte, c_uchar, "{}\n");
impl_macro!(short, c_short, "{}\n");
impl_macro!(ushort, c_ushort, "{}\n");
impl_macro!(int, c_int, "{}\n");
impl_macro!(uint, c_uint, "{}\n");
impl_macro!(long, c_long, "{}\n");
impl_macro!(ulong, c_ulong, "{}\n");
impl_macro!(ullong, c_ulonglong, "{}\n");
impl_macro!(hexint, c_uint, "{:#08x}\n");

fn maybe_kfree_parameter(arg: *mut c_char) {
    unsafe {
        if !arg.is_null() {
            let _ = alloc::ffi::CString::from_raw(arg);
        }
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
#[allow(non_camel_case_types)]
struct charp(*mut c_char);

impl PartialEq for charp {
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            let s1 = if self.0.is_null() {
                ""
            } else {
                CStr::from_ptr(self.0).to_str().unwrap_or("")
            };
            let s2 = if other.0.is_null() {
                ""
            } else {
                CStr::from_ptr(other.0).to_str().unwrap_or("")
            };
            s1 == s2
        }
    }
}

impl KernelParamValue for charp {
    fn parse(s: &str) -> Result<Self> {
        if s.len() > 1024 {
            return Err(ModuleErr::ENOSPC);
        }
        let c_string = alloc::ffi::CString::new(s).map_err(|_| ModuleErr::EINVAL)?;
        let ptr = c_string.into_raw();
        Ok(charp(ptr))
    }

    fn format(self, buf: *mut u8) -> Result<usize> {
        unsafe {
            let c_str = CStr::from_ptr(self.0);
            let s = alloc::format!("{}\n", c_str.to_str().map_err(|_| ModuleErr::EINVAL)?);
            let bytes = s.as_bytes();
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
            Ok(bytes.len())
        }
    }
}

unsafe extern "C" fn param_set_charp(val: *const c_char, kp: *const kmod::kernel_param) -> c_int {
    let v = common_parse::<charp>(val);
    let v = match v {
        Ok(v) => v,
        Err(_) => return -(ModuleErr::EINVAL as c_int),
    };

    let arg_ptr = unsafe { kp.as_ref().unwrap().__bindgen_anon_1.arg };
    unsafe {
        // Free the old string if any
        let old_ptr = *(arg_ptr as *mut *mut c_char);
        if !old_ptr.is_null() {
            let old_str = alloc::ffi::CString::from_raw(old_ptr);
            drop(old_str);
        }
        *(arg_ptr as *mut charp) = v;
    }
    0
}

unsafe extern "C" fn param_get_charp(buffer: *mut c_char, kp: *const kmod::kernel_param) -> c_int {
    let arg_ptr = unsafe { kp.as_ref().unwrap().__bindgen_anon_1.arg };
    let v = unsafe { *(arg_ptr as *const charp) };
    let len = v.format(buffer as _).unwrap_or(0);
    len as c_int
}

unsafe extern "C" fn param_free_charp(arg: *mut c_void) {
    maybe_kfree_parameter(*(arg as *mut *mut c_char));
}

#[cdata]
static param_ops_charp: kmod::kernel_param_ops = kmod::kernel_param_ops {
    set: Some(param_set_charp),
    get: Some(param_get_charp),
    flags: 0,
    free: Some(param_free_charp),
};

impl KernelParamValue for bool {
    // One of =[yYnN01]
    fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        // No equals means "set"...
        match s {
            "y" | "Y" | "1" | "" => Ok(true),
            "n" | "N" | "0" => Ok(false),
            _ => Err(ModuleErr::EINVAL),
        }
    }

    fn format(self, buf: *mut u8) -> Result<usize> {
        let s = if self { b"1\n" } else { b"0\n" };
        let bytes = s;
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
        }
        Ok(bytes.len())
    }
}

unsafe extern "C" fn param_set_bool(val: *const c_char, kp: *const kmod::kernel_param) -> c_int {
    let val = if val.is_null() {
        c"".as_ptr() // No argument means "set"
    } else {
        val
    };
    common_set::<bool>(val, kp)
}

unsafe extern "C" fn param_get_bool(buffer: *mut c_char, kp: *const kmod::kernel_param) -> c_int {
    let arg_ptr = unsafe { kp.as_ref().unwrap().__bindgen_anon_1.arg };
    let v = unsafe { *(arg_ptr as *const bool) };
    let len = v.format(buffer as _).unwrap_or(0);
    len as c_int
}

#[cdata]
static param_ops_bool: kmod::kernel_param_ops = kmod::kernel_param_ops {
    set: Some(param_set_bool),
    get: Some(param_get_bool),
    flags: ParamOpsFlags::KERNEL_PARAM_OPS_FL_NOARG as u32,
    free: None,
};

/// Parse a string to get a param value pair.
/// You can use " around spaces, but can't escape ".
/// Hyphens and underscores equivalent in parameter names.
fn next_arg(mut args: &mut [u8]) -> Result<(&CStr, Option<&CStr>, &mut [u8])> {
    let mut equals = None;
    let mut in_quote = false;
    let mut quoted = false;

    if args[0] == b'"' {
        args = &mut args[1..];
        in_quote = true;
        quoted = true;
    }

    let mut idx = 0;
    while args[idx] != b'\0' {
        let b = args[idx];
        if b.is_ascii_whitespace() && !in_quote {
            break;
        }
        if equals.is_none() && b == b'=' {
            equals = Some(idx);
        }
        if b == b'"' {
            in_quote = !in_quote;
        }
        idx += 1;
    }
    let param_start = args.as_ptr();
    let val_start = if let Some(equals_idx) = equals {
        // Split at equals
        args[equals_idx] = b'\0';
        let mut val_idx = equals_idx + 1;
        // Don't include quotes in value.
        if args[val_idx] == b'"' {
            val_idx += 1;
            if args[idx - 1] == b'"' {
                args[idx - 1] = b'\0';
            }
        }
        let val_start = unsafe { args.as_ptr().add(val_idx) };
        Some(val_start)
    } else {
        None
    };

    if quoted && idx > 0 && args[idx - 1] == b'"' {
        args[idx - 1] = b'\0';
    }
    if args[idx] != b'\0' {
        args[idx] = b'\0';
        args = &mut args[idx + 1..];
    } else {
        args = &mut args[idx..];
    }

    args = skip_spaces(args);

    let (param, val) = unsafe {
        let param = CStr::from_ptr(param_start as _);
        let val = val_start.map(|v| CStr::from_ptr(v as _));
        (param, val)
    };
    Ok((param, val, args))
}

fn skip_spaces(mut args: &mut [u8]) -> &mut [u8] {
    while let Some(&b) = args.first() {
        if b.is_ascii_whitespace() {
            args = &mut args[1..];
        } else {
            break;
        }
    }
    args
}

fn dash2underscore(c: u8) -> u8 {
    if c == b'-' { b'_' } else { c }
}

/// See <https://elixir.bootlin.com/linux/v6.6/source/kernel/params.c#L85>
fn parameqn(a: &CStr, b: &CStr, n: usize) -> bool {
    let a_bytes = a.to_bytes();
    let b_bytes = b.to_bytes();
    if a_bytes.len() < n || b_bytes.len() < n {
        return false;
    }

    for i in 0..n {
        if dash2underscore(a_bytes[i]) != dash2underscore(b_bytes[i]) {
            return false;
        }
    }
    true
}

fn parameq(a: &CStr, b: &CStr) -> bool {
    parameqn(a, b, a.to_bytes().len())
}

fn parse_one(
    param: &CStr,
    val: Option<&CStr>,
    doing: &str,
    params: &mut [KernelParam],
    min_level: i16,
    max_level: i16,
) -> Result<()> {
    for kp in params.iter_mut() {
        let name = kp.raw_name();
        if parameq(name, param) {
            if kp.level() < min_level || kp.level() > max_level {
                return Ok(());
            }
            let param_ops_flags = unsafe { kp.param_ops_flags() };
            // No one handled NULL, so do it here.
            if val.is_none()
                && param_ops_flags & (ParamOpsFlags::KERNEL_PARAM_OPS_FL_NOARG as u32) == 0
            {
                log::warn!(
                    "[{}] Parameter '{}' requires an argument",
                    doing,
                    name.to_str().unwrap(),
                );
                return Err(LinuxError::EINVAL);
            }
            log::debug!(
                "[{}] handling {} with {:?}\n",
                doing,
                param.to_str().unwrap(),
                kp.ops().set
            );
            let set = kp.ops().set.unwrap();
            let res = unsafe {
                set(
                    val.map_or(core::ptr::null(), |v| v.as_ptr()),
                    kp.raw_kernel_param(),
                )
            };
            if res < 0 {
                return Err(LinuxError::try_from(-res).unwrap());
            } else {
                return Ok(());
            }
        }
    }
    Err(LinuxError::ENOENT)
}

pub(crate) fn parse_args(
    doing: &str,
    args: CString,
    params: &mut [KernelParam],
    min_level: i16,
    max_level: i16,
) -> Result<CString> {
    let mut args = args.into_bytes_with_nul();
    let mut args = args.as_mut_slice();
    // skip spaces
    args = skip_spaces(args);
    if args.is_empty() {
        return Ok(CString::new("").unwrap());
    }

    while args[0] != b'\0' {
        let (param, val, new_args) = next_arg(args)?;
        args = new_args;
        // Stop at --
        if val.is_none() && param.to_bytes() == b"--" {
            // Remove the NUL terminator from the end of args before creating CString
            let args_without_nul = if args.last() == Some(&b'\0') {
                &args[..args.len() - 1]
            } else {
                args
            };
            return Ok(CString::new(args_without_nul).unwrap());
        }
        let res = parse_one(param, val, doing, params, min_level, max_level);
        match res {
            Err(LinuxError::ENOENT) => {
                log::error!(
                    "[{}]: Unknown parameter '{}'",
                    doing,
                    param.to_str().unwrap()
                );
                return Err(LinuxError::ENOENT);
            }
            Err(LinuxError::ENOSPC) => {
                log::error!(
                    "[{}]: '{:?}' too large for parameter '{}'",
                    doing,
                    val,
                    param.to_str().unwrap()
                );
                return Err(LinuxError::ENOSPC);
            }
            Err(e) => {
                log::error!(
                    "[{}]: '{:?}' invalid for parameter '{}'",
                    doing,
                    val,
                    param.to_str().unwrap()
                );
                return Err(e);
            }
            Ok(()) => { /* Parsed successfully */ }
        }
    }
    Ok(CString::new("").unwrap())
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned;

    use super::*;

    fn test_param<V: KernelParamValue + core::fmt::Debug + PartialEq>(
        s: &str,
        expected: V,
        excepted_str: &str,
    ) {
        let parsed = V::parse(s).expect("Failed to parse");
        assert_eq!(parsed, expected);

        let mut buf = [0u8; 64];
        let len = parsed.format(buf.as_mut_ptr()).expect("Failed to format");
        let formatted = core::str::from_utf8(&buf[..len]).expect("Invalid UTF-8");
        assert_eq!(formatted, excepted_str);
    }

    #[test]
    fn test_byte_param() {
        test_param("255", byte(255), "255\n");
        test_param("0x7F", byte(127), "127\n");
        test_param("0377", byte(255), "255\n");
    }

    #[test]
    fn test_short_param() {
        test_param("32767", short(32767), "32767\n");
        test_param("-32768", short(-32768), "-32768\n");
        test_param("0x7FFF", short(32767), "32767\n");
        test_param("077777", short(32767), "32767\n");
    }
    #[test]
    fn test_ushort_param() {
        test_param("65535", ushort(65535), "65535\n");
        test_param("0xFFFF", ushort(65535), "65535\n");
        test_param("0177777", ushort(65535), "65535\n");
    }

    #[test]
    fn test_int_param() {
        test_param("2147483647", int(2147483647), "2147483647\n");
        test_param("-2147483648", int(-2147483648), "-2147483648\n");
        test_param("0x7FFFFFFF", int(2147483647), "2147483647\n");
        test_param("017777777777", int(2147483647), "2147483647\n");
    }

    #[test]
    fn test_uint_param() {
        test_param("4294967295", uint(4294967295), "4294967295\n");
        test_param("0xFFFFFFFF", uint(4294967295), "4294967295\n");
        test_param("037777777777", uint(4294967295), "4294967295\n");
    }

    #[test]
    fn test_long_param() {
        test_param(
            "9223372036854775807",
            long(9223372036854775807),
            "9223372036854775807\n",
        );
        test_param(
            "-9223372036854775808",
            long(-9223372036854775808),
            "-9223372036854775808\n",
        );
        test_param(
            "0x7FFFFFFFFFFFFFFF",
            long(9223372036854775807),
            "9223372036854775807\n",
        );
        test_param(
            "0777777777777777777777",
            long(9223372036854775807),
            "9223372036854775807\n",
        );
    }

    #[test]
    fn test_ulong_param() {
        test_param(
            "18446744073709551615",
            ulong(18446744073709551615),
            "18446744073709551615\n",
        );
        test_param(
            "0xFFFFFFFFFFFFFFFF",
            ulong(18446744073709551615),
            "18446744073709551615\n",
        );
        test_param(
            "01777777777777777777777",
            ulong(18446744073709551615),
            "18446744073709551615\n",
        );
    }
    #[test]
    fn test_ullong_param() {
        test_param(
            "18446744073709551615",
            ullong(18446744073709551615),
            "18446744073709551615\n",
        );
        test_param(
            "0xFFFFFFFFFFFFFFFF",
            ullong(18446744073709551615),
            "18446744073709551615\n",
        );
        test_param(
            "01777777777777777777777",
            ullong(18446744073709551615),
            "18446744073709551615\n",
        )
    }

    #[test]
    fn test_hexint_param() {
        test_param("0xDEADBEEF", hexint(0xDEADBEEF), "0xdeadbeef\n");
        test_param("0Xdeadbeef", hexint(0xDEADBEEF), "0xdeadbeef\n");
    }

    #[test]
    fn test_charp_param() {
        let original_str = "Hello, Kernel Param!";
        let expected = charp(alloc::ffi::CString::new(original_str).unwrap().into_raw());
        test_param(original_str, expected, "Hello, Kernel Param!\n");
    }

    #[test]
    fn test_bool_param() {
        test_param("y", true, "1\n");
        test_param("Y", true, "1\n");
        test_param("1", true, "1\n");
        test_param("", true, "1\n");
        test_param("n", false, "0\n");
        test_param("N", false, "0\n");
        test_param("0", false, "0\n");
    }

    #[test]
    fn test_parameq() {
        let a = CString::new("param-name").unwrap();
        let b = CString::new("param_name").unwrap();
        let c = CString::new("paramname").unwrap();
        assert!(parameq(&a, &b));
        assert!(!parameq(&a, &c));
    }

    #[test]
    fn test_next_arg() {
        let mut args = b"param1=val1 param2=\"val 2\" param3=val3\0".to_owned();
        let args_slice = args.as_mut_slice();
        let (param, val, rest) = next_arg(args_slice).expect("Failed to parse arg1");
        assert_eq!(param, c"param1");
        assert_eq!(val, Some(c"val1"));
        assert_eq!(rest, b"param2=\"val 2\" param3=val3\0");
        let (param, val, rest) = next_arg(rest).expect("Failed to parse arg2");
        assert_eq!(param, c"param2");
        assert_eq!(val, Some(c"val 2"));
        assert_eq!(rest, b"param3=val3\0");
        let (param, val, rest) = next_arg(rest).expect("Failed to parse arg3");
        assert_eq!(param, c"param3");
        assert_eq!(val, Some(c"val3"));
        assert_eq!(rest, b"\0");
    }

    #[test]
    fn test_next_arg_no_value() {
        let mut args = b"param1 param2=\"val 2\" -- param3=val3\0".to_owned();
        let args_slice = args.as_mut_slice();
        let (param, val, rest) = next_arg(args_slice).expect("Failed to parse arg1");
        assert_eq!(param, c"param1");
        assert_eq!(val, None);
        assert_eq!(rest, b"param2=\"val 2\" -- param3=val3\0");
        let (param, val, rest) = next_arg(rest).expect("Failed to parse arg2");
        assert_eq!(param, c"param2");
        assert_eq!(val, Some(c"val 2"));
        assert_eq!(rest, b"-- param3=val3\0");
    }

    // Helper function to create test kernel params
    // Note: This is a simplified approach that uses unsafe code to create mock KernelParam structures for testing
    fn create_test_param_int(name: &'static CStr, value_ptr: *mut c_int) -> KernelParam {
        unsafe extern "C" {
            #[allow(improper_ctypes)]
            static param_ops_int: kmod::kernel_param_ops;
        }

        // Use mem::transmute to bypass the type system for testing
        // This is safe in test context as we control all the types
        let param_raw: kmod::kernel_param = unsafe {
            let mut param = core::mem::MaybeUninit::<kmod::kernel_param>::zeroed();
            let p = param.as_mut_ptr();
            (*p).name = name.as_ptr() as *mut c_char;
            (*p).mod_ = core::ptr::null_mut();
            (*p).ops = &param_ops_int;
            (*p).perm = 0;
            (*p).level = 0;
            (*p).flags = 0;
            // Set the union field arg
            core::ptr::write(
                &mut (*p).__bindgen_anon_1 as *mut _ as *mut *mut core::ffi::c_void,
                value_ptr as *mut core::ffi::c_void,
            );
            param.assume_init()
        };

        KernelParam::from_raw(param_raw)
    }

    fn create_test_param_bool(name: &'static CStr, value_ptr: *mut bool) -> KernelParam {
        let param_raw: kmod::kernel_param = unsafe {
            let mut param = core::mem::MaybeUninit::<kmod::kernel_param>::zeroed();
            let p = param.as_mut_ptr();
            (*p).name = name.as_ptr() as *mut c_char;
            (*p).mod_ = core::ptr::null_mut();
            (*p).ops = &param_ops_bool;
            (*p).perm = 0;
            (*p).level = 0;
            (*p).flags = 0;
            core::ptr::write(
                &mut (*p).__bindgen_anon_1 as *mut _ as *mut *mut core::ffi::c_void,
                value_ptr as *mut core::ffi::c_void,
            );
            param.assume_init()
        };

        KernelParam::from_raw(param_raw)
    }

    fn create_test_param_charp(name: &'static CStr, value_ptr: *mut *mut c_char) -> KernelParam {
        unsafe extern "C" {
            #[allow(improper_ctypes)]
            static param_ops_charp: kmod::kernel_param_ops;
        }

        let param_raw: kmod::kernel_param = unsafe {
            let mut param = core::mem::MaybeUninit::<kmod::kernel_param>::zeroed();
            let p = param.as_mut_ptr();
            (*p).name = name.as_ptr() as *mut c_char;
            (*p).mod_ = core::ptr::null_mut();
            (*p).ops = &param_ops_charp;
            (*p).perm = 0;
            (*p).level = 0;
            (*p).flags = 0;
            core::ptr::write(
                &mut (*p).__bindgen_anon_1 as *mut _ as *mut *mut core::ffi::c_void,
                value_ptr as *mut core::ffi::c_void,
            );
            param.assume_init()
        };

        KernelParam::from_raw(param_raw)
    }

    fn create_test_params() -> alloc::vec::Vec<KernelParam> {
        use core::ffi::c_char;

        // Create static variables for parameter storage
        static mut TEST_INT: c_int = 0;
        static mut TEST_BOOL: bool = false;
        static mut TEST_STR: *mut c_char = core::ptr::null_mut();

        // Reset static variables before each test
        // Safety: This is safe because we're in a test context and control access
        unsafe {
            TEST_INT = 0;
            TEST_BOOL = false;
            if !TEST_STR.is_null() {
                let _ = CString::from_raw(TEST_STR);
                TEST_STR = core::ptr::null_mut();
            }

            let int_param = create_test_param_int(c"test_int", &raw mut TEST_INT);
            let bool_param = create_test_param_bool(c"test_bool", &raw mut TEST_BOOL);
            let str_param = create_test_param_charp(c"test_str", &raw mut TEST_STR);

            alloc::vec![int_param, bool_param, str_param]
        }
    }

    #[test]
    fn test_parse_args_single_int() {
        let mut params = create_test_params();
        let args = CString::new("test_int=42").unwrap();
        let result = parse_args("test", args, &mut params, i16::MIN, i16::MAX);
        assert!(result.is_ok());

        // Verify the value was set
        let arg_ptr = unsafe { params[0].raw_kernel_param().__bindgen_anon_1.arg };
        let value = unsafe { *(arg_ptr as *const c_int) };
        assert_eq!(value, 42);
    }

    #[test]
    fn test_parse_args_multiple_params() {
        let mut params = create_test_params();
        let args = CString::new("test_int=123 test_bool=y test_str=hello").unwrap();
        let result = parse_args("test", args, &mut params, i16::MIN, i16::MAX);
        assert!(result.is_ok());

        // Verify int value
        let int_ptr = unsafe { params[0].raw_kernel_param().__bindgen_anon_1.arg };
        let int_val = unsafe { *(int_ptr as *const c_int) };
        assert_eq!(int_val, 123);

        // Verify bool value
        let bool_ptr = unsafe { params[1].raw_kernel_param().__bindgen_anon_1.arg };
        let bool_val = unsafe { *(bool_ptr as *const bool) };
        assert_eq!(bool_val, true);

        // Verify string value
        let str_ptr = unsafe { params[2].raw_kernel_param().__bindgen_anon_1.arg };
        let str_val = unsafe { *(str_ptr as *const *mut c_char) };
        assert!(!str_val.is_null());
        let c_str = unsafe { CStr::from_ptr(str_val) };
        assert_eq!(c_str.to_str().unwrap(), "hello");
    }

    #[test]
    fn test_parse_args_with_quotes() {
        let mut params = create_test_params();
        let args = CString::new("test_str=\"hello world\"").unwrap();
        let result = parse_args("test", args, &mut params, i16::MIN, i16::MAX);
        assert!(result.is_ok());

        let str_ptr = unsafe { params[2].raw_kernel_param().__bindgen_anon_1.arg };
        let str_val = unsafe { *(str_ptr as *const *mut c_char) };
        assert!(!str_val.is_null());
        let c_str = unsafe { CStr::from_ptr(str_val) };
        assert_eq!(c_str.to_str().unwrap(), "hello world");
    }

    #[test]
    fn test_parse_args_bool_no_value() {
        let mut params = create_test_params();
        let args = CString::new("test_bool").unwrap();
        let result = parse_args("test", args, &mut params, i16::MIN, i16::MAX);
        assert!(result.is_ok());

        let bool_ptr = unsafe { params[1].raw_kernel_param().__bindgen_anon_1.arg };
        let bool_val = unsafe { *(bool_ptr as *const bool) };
        assert_eq!(bool_val, true);
    }

    #[test]
    fn test_parse_args_double_dash() {
        let mut params = create_test_params();
        let args = CString::new("test_int=10 -- test_bool=y").unwrap();
        let result = parse_args("test", args, &mut params, i16::MIN, i16::MAX);
        assert!(result.is_ok());

        // Check that only test_int was processed
        let int_ptr = unsafe { params[0].raw_kernel_param().__bindgen_anon_1.arg };
        let int_val = unsafe { *(int_ptr as *const c_int) };
        assert_eq!(int_val, 10);

        // The remaining args should be returned (with leading space)
        let remaining = result.unwrap();
        assert_eq!(remaining.to_str().unwrap(), "test_bool=y");
    }

    #[test]
    fn test_parse_args_unknown_param() {
        let mut params = create_test_params();
        let args = CString::new("unknown_param=123").unwrap();
        let result = parse_args("test", args, &mut params, i16::MIN, i16::MAX);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), LinuxError::ENOENT);
    }

    #[test]
    fn test_parse_args_invalid_value() {
        let mut params = create_test_params();
        let args = CString::new("test_int=not_a_number").unwrap();
        let result = parse_args("test", args, &mut params, i16::MIN, i16::MAX);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_args_hyphen_underscore() {
        let mut params = create_test_params();
        // test-int should match test_int
        let args = CString::new("test-int=999").unwrap();
        let result = parse_args("test", args, &mut params, i16::MIN, i16::MAX);
        assert!(result.is_ok());

        let int_ptr = unsafe { params[0].raw_kernel_param().__bindgen_anon_1.arg };
        let int_val = unsafe { *(int_ptr as *const c_int) };
        assert_eq!(int_val, 999);
    }

    #[test]
    fn test_parse_args_hex_values() {
        let mut params = create_test_params();
        let args = CString::new("test_int=0xFF").unwrap();
        let result = parse_args("test", args, &mut params, i16::MIN, i16::MAX);
        assert!(result.is_ok());

        let int_ptr = unsafe { params[0].raw_kernel_param().__bindgen_anon_1.arg };
        let int_val = unsafe { *(int_ptr as *const c_int) };
        assert_eq!(int_val, 255);
    }

    #[test]
    fn test_parse_args_empty_string() {
        let mut params = create_test_params();
        let args = CString::new("").unwrap();
        let result = parse_args("test", args, &mut params, i16::MIN, i16::MAX);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_str().unwrap(), "");
    }

    #[test]
    fn test_parse_args_spaces() {
        let mut params = create_test_params();
        let args = CString::new("  test_int=50  test_bool=n  ").unwrap();
        let result = parse_args("test", args, &mut params, i16::MIN, i16::MAX);
        assert!(result.is_ok());

        let int_ptr = unsafe { params[0].raw_kernel_param().__bindgen_anon_1.arg };
        let int_val = unsafe { *(int_ptr as *const c_int) };
        assert_eq!(int_val, 50);

        let bool_ptr = unsafe { params[1].raw_kernel_param().__bindgen_anon_1.arg };
        let bool_val = unsafe { *(bool_ptr as *const bool) };
        assert_eq!(bool_val, false);
    }
}

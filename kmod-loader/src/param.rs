use crate::{ModuleErr, Result};
use core::ffi::{
    CStr, c_char, c_int, c_long, c_short, c_uchar, c_uint, c_ulong, c_ulonglong, c_ushort,
};
use paste::paste;

/// Macro to define standard kernel parameter operations for a given type.
/// ```c
/// #define STANDARD_PARAM_DEF(name, type, format, strtolfn)      		\
///	int param_set_##name(const char *val, const struct kernel_param *kp) \
///	{								\
///		return strtolfn(val, 0, (type *)kp->arg);		\
///	}								\
///	int param_get_##name(char *buffer, const struct kernel_param *kp) \
///	{								\
///		return scnprintf(buffer, PAGE_SIZE, format "\n",	\
///				*((type *)kp->arg));			\
///	}								\
///	const struct kernel_param_ops param_ops_##name = {			\
///		.set = param_set_##name,				\
///		.get = param_get_##name,				\
///	};								\
///	EXPORT_SYMBOL(param_set_##name);				\
///	EXPORT_SYMBOL(param_get_##name);				\
///	EXPORT_SYMBOL(param_ops_##name)
/// ```
/// See <https://elixir.bootlin.com/linux/v6.6/source/kernel/params.c#L218>
///
#[macro_export]
macro_rules! standard_param_def {
    ($name:ident, $type:ty, $format:expr, $strtolfn:ident) => {};
}

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
                // write_number(buf, self.0)
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
                let c_str = unsafe { CStr::from_ptr(val) };
                let s = c_str.to_str();
                let s = match s {
                    Ok(s) => s,
                    Err(_) => return ModuleErr::EINVAL as c_int,
                };
                let v = $name::parse(s).unwrap_or($name(0 as $type));
                let arg_ptr = unsafe { kp.as_ref().unwrap().__bindgen_anon_1.arg };
                unsafe {
                    *(arg_ptr as *mut $name) = v;
                }
                0
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

            #[unsafe(no_mangle)]
            #[used]
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

#[cfg(test)]
mod tests {
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
}

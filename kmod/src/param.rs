use core::ffi::CStr;
pub use kbindings::{kernel_param, kernel_param_ops};
/// The `KernelParam` struct represents a kernel module parameter.
///
/// See <https://elixir.bootlin.com/linux/v6.6/source/include/linux/moduleparam.h#L69>
#[repr(transparent)]
pub struct KernelParam(kbindings::kernel_param);

impl KernelParam {
    pub fn name(&self) -> &str {
        unsafe {
            let c_str = core::ffi::CStr::from_ptr(self.0.name);
            c_str.to_str().unwrap_or_default()
        }
    }

    pub fn raw_name(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.0.name) }
    }

    /// Returns a pointer to the argument value.
    ///
    /// # Safety
    /// This function is unsafe because it accesses an union field. User
    /// must ensure that the correct field is accessed based on the context.
    pub unsafe fn arg_ptr(&self) -> *mut core::ffi::c_void {
        unsafe { self.0.__bindgen_anon_1.arg }
    }
}

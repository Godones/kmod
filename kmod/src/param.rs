use core::ffi::CStr;
pub use kbindings::{kernel_param, kernel_param_ops};
/// The `KernelParam` struct represents a kernel module parameter.
///
/// See <https://elixir.bootlin.com/linux/v6.6/source/include/linux/moduleparam.h#L69>
#[repr(transparent)]
pub struct KernelParam(kbindings::kernel_param);

impl Default for KernelParam {
    fn default() -> Self {
        let mut param = core::mem::MaybeUninit::<kbindings::kernel_param>::uninit();
        let param = unsafe {
            core::ptr::write_bytes(param.as_mut_ptr(), 0, 1);
            param.assume_init()
        };
        KernelParam(param)
    }
}

impl KernelParam {
    pub fn name(&self) -> &str {
        unsafe {
            let c_str = core::ffi::CStr::from_ptr(self.0.name);
            c_str.to_str().unwrap_or_default()
        }
    }

    /// Create a KernelParam from a raw kernel_param structure.
    ///
    /// # Safety
    /// This function is unsafe because it assumes the provided kernel_param
    /// is properly initialized and valid.
    pub fn from_raw(param: kbindings::kernel_param) -> Self {
        KernelParam(param)
    }

    pub fn raw_kernel_param(&self) -> &kbindings::kernel_param {
        &self.0
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

    pub fn level(&self) -> i16 {
        self.0.level as _
    }

    /// Returns the flags of the parameter operations.
    ///
    /// # Safety
    /// This function is unsafe because it dereferences a raw pointer. User must ensure
    /// that the `ops` pointer is valid.
    pub unsafe fn param_ops_flags(&self) -> u32 {
        self.0.ops.as_ref().unwrap().flags
    }

    /// Returns a reference to the parameter operations.
    pub fn ops(&self) -> &kbindings::kernel_param_ops {
        unsafe { self.0.ops.as_ref().unwrap() }
    }
}

/// Flags available for kernel_param_ops
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum ParamOpsFlags {
    /// NOARG - the parameter allows for no argument (foo instead of foo=1)
    KERNEL_PARAM_OPS_FL_NOARG = 1 << 0,
}

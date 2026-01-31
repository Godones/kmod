use crate::KernelParam;

/// The `Module` struct represents a kernel module.
///
/// See <https://elixir.bootlin.com/linux/v6.6/source/include/linux/module.h#L402>
#[repr(transparent)]
#[derive(Default)]
pub struct Module(kbindings::module);


unsafe impl Send for Module {}
unsafe impl Sync for Module {}

impl Module {
    /// Creates a new `Module` instance with the given initialization and exit functions.
    pub const fn new(
        init_fn: Option<unsafe extern "C" fn() -> core::ffi::c_int>,
        exit_fn: Option<unsafe extern "C" fn()>,
    ) -> Self {
        let mut module = core::mem::MaybeUninit::<kbindings::module>::uninit();
        let mut module = unsafe {
            core::ptr::write_bytes(module.as_mut_ptr(), 0, 1);
            module.assume_init()
        };
        module.init = init_fn;
        module.exit = exit_fn;
        Module(module)
    }

    pub fn init_fn(&self) -> Option<unsafe extern "C" fn() -> core::ffi::c_int> {
        self.0.init
    }

    pub fn exit_fn(&self) -> Option<unsafe extern "C" fn()> {
        self.0.exit
    }

    pub fn take_init_fn(&mut self) -> Option<unsafe extern "C" fn() -> core::ffi::c_int> {
        
        self.0.init.take()
    }

    pub fn take_exit_fn(&mut self) -> Option<unsafe extern "C" fn()> {
        
        self.0.exit.take()
    }

    pub fn name(&self) -> &str {
        let c_str = unsafe { core::ffi::CStr::from_ptr(self.0.name.as_ptr()) };
        c_str.to_str().unwrap_or("unknown")
    }

    pub fn raw_mod(&mut self) -> &mut kbindings::module {
        &mut self.0
    }

    pub fn params_mut(&mut self) -> &mut [KernelParam] {
        unsafe { core::slice::from_raw_parts_mut(self.0.kp as _, self.0.num_kp as usize) }
    }
}

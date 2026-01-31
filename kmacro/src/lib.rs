//! Macro definitions for kernel module functions.
use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Ident, LitStr, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

/// Attribute macro to mark the initialization function of a kernel module. It
/// places the function in the `.text.init` section.
/// # Example:
/// ```ignore
/// #[init_fn]
/// fn init() -> i32 { ... }
/// ```
#[proc_macro_attribute]
pub fn init_fn(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as syn::ItemFn);
    let func_name = &func.sig.ident;
    quote! {
        unsafe extern "C" fn init_module() -> core::ffi::c_int {
            #func_name() as core::ffi::c_int
        }
        #[unsafe(link_section = ".text.init")]
        #func
    }
    .into()
}

/// Attribute macro to mark the cleanup function of a kernel module. It places
/// the function in the `.text.exit` section.
/// # Example:
/// ```ignore
/// #[exit_fn]
/// fn cleanup() { ... }
/// ```
#[proc_macro_attribute]
pub fn exit_fn(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as syn::ItemFn);
    let func_name = &func.sig.ident;
    quote! {
        unsafe extern "C" fn cleanup_module() {
            #func_name()
        }
        #[unsafe(link_section = ".text.exit")]
        #func
    }
    .into()
}

/// Attribute macro to mark a C API function. It places the function in the
/// `.c.text` section and applies `no_mangle`.
/// # Example:
/// ```ignore
/// #[capi_fn]
/// unsafe extern "C" fn my_capi_function(arg: i32) -> i32 { ... }
/// ```
#[proc_macro_attribute]
pub fn capi_fn(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as syn::ItemFn);
    quote! {
        #[unsafe(no_mangle)]
        #[unsafe(link_section = ".c.text")]
        #func
    }
    .into()
}

/// Attribute macro to mark a C static data item. It places the item in the
/// `.c.data` section and applies `no_mangle` and `used`.
/// # Example:
/// ```ignore
/// #[cdata]
/// static MY_CDATA: i32 = 42;
/// ```
#[proc_macro_attribute]
pub fn cdata(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let data = parse_macro_input!(item as syn::ItemStatic);
    quote! {
        #[unsafe(no_mangle)]
        #[used]
        #[unsafe(link_section = ".c.data")]
        #data
    }
    .into()
}

struct ModuleArgs {
    name: Option<LitStr>,
    version: Option<LitStr>,
    license: Option<LitStr>,
    description: Option<LitStr>,
}

impl Parse for ModuleArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut name = None;
        let mut version = None;
        let mut license = None;
        let mut description = None;
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Token![:]>()?;

            match key.to_string().as_str() {
                "name" => {
                    let value: LitStr = input.parse()?;
                    name = Some(value);
                }
                "version" => {
                    let value: LitStr = input.parse()?;
                    version = Some(value);
                }
                "license" => {
                    let value: LitStr = input.parse()?;
                    license = Some(value);
                }
                "description" => {
                    let value: LitStr = input.parse()?;
                    description = Some(value);
                }
                _ => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!("Unknown field: {}", key),
                    ));
                }
            }

            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(ModuleArgs {
            name,
            version,
            license,
            description,
        })
    }
}

/// Macro to declare module metadata in the `.modinfo` section.
///
/// # Example:
/// ```ignore
/// module! {
///     name: "hello",
///     version: "1.0.0",
///     license: "GPL",
///     description: "A simple hello world kernel module",
/// }
/// ```
///
/// Parameters can be in any order, for example:
/// ```ignore
/// module! {
///     name: "hello",
///     description: "A simple hello world kernel module",
///     license: "GPL",
///     version: "1.0.0"
/// }
/// ```
#[proc_macro]
pub fn module(item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(item as ModuleArgs);

    let name = args.name.expect("name is required");
    let version = args.version.expect("version is required");
    let license = args.license.expect("license is required");
    let description = args.description.expect("description is required");

    // Build complete byte arrays for each modinfo entry
    let mut name_array = b"name=".to_vec();
    name_array.extend_from_slice(name.value().as_bytes());
    name_array.push(0);

    let mut version_array = b"version=".to_vec();
    version_array.extend_from_slice(version.value().as_bytes());
    version_array.push(0);

    let mut license_array = b"license=".to_vec();
    license_array.extend_from_slice(license.value().as_bytes());
    license_array.push(0);

    let mut description_array = b"description=".to_vec();
    description_array.extend_from_slice(description.value().as_bytes());
    description_array.push(0);

    let name_len = name_array.len();
    let version_len = version_array.len();
    let license_len = license_array.len();
    let description_len = description_array.len();

    quote! {
        #[used]
        #[unsafe(link_section = ".modinfo")]
        static MODULE_NAME: [u8; #name_len] = [#(#name_array),*];
        #[used]
        #[unsafe(link_section = ".modinfo")]
        static MODULE_VERSION: [u8; #version_len] = [#(#version_array),*];
        #[used]
        #[unsafe(link_section = ".modinfo")]
        static MODULE_LICENSE: [u8; #license_len] = [#(#license_array),*];
        #[used]
        #[unsafe(link_section = ".modinfo")]
        static MODULE_DESCRIPTION: [u8; #description_len] = [#(#description_array),*];
        #[used]
        #[unsafe(link_section = ".gnu.linkonce.this_module")]
        static __this_module: kmod::Module = kmod::Module::new(Some(init_module), Some(cleanup_module));
    }
    .into()
}

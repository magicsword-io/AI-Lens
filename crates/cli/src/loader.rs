use anyhow::{bail, Context, Result};
use libloading::{Library, Symbol};
use serde_json::Value;
use std::{
    ffi::{c_char, CStr},
    path::PathBuf,
};

type Process = unsafe extern "C" fn(*const u8, usize) -> *mut c_char;
type Free = unsafe extern "C" fn(*mut c_char);

pub struct Engine(Library);
impl Engine {
    pub fn load() -> Result<Self> {
        let name = if cfg!(target_os = "windows") {
            "agent_lens_engine.dll"
        } else if cfg!(target_os = "macos") {
            "libagent_lens_engine.dylib"
        } else {
            "libagent_lens_engine.so"
        };
        let path: PathBuf = std::env::current_exe()?
            .parent()
            .context("missing executable directory")?
            .join(name);
        // SAFETY: Only load the user's trusted companion library by absolute path,
        // never a library selected by a hook payload or the working directory.
        let lib = unsafe { Library::new(&path) }.context("cannot load companion engine library")?;
        let version: Symbol<unsafe extern "C" fn() -> u32> =
            unsafe { lib.get(b"agent_lens_abi_version\0") }?;
        if unsafe { version() } != 1 {
            bail!("incompatible engine ABI");
        }
        Ok(Self(lib))
    }
    pub fn call(&self, request: &Value) -> Result<Value> {
        let bytes = serde_json::to_vec(request)?;
        // SAFETY: Symbols are checked before use and library lives for entire call.
        // Input is borrowed for the call; output is NUL-terminated and freed by
        // the same library allocator, including on JSON decoding failure.
        unsafe {
            let process: Symbol<Process> = self.0.get(b"agent_lens_process\0")?;
            let free: Symbol<Free> = self.0.get(b"agent_lens_free\0")?;
            let ptr = process(bytes.as_ptr(), bytes.len());
            if ptr.is_null() {
                bail!("engine returned null");
            }
            let decoded = serde_json::from_slice::<Value>(CStr::from_ptr(ptr).to_bytes());
            free(ptr);
            let envelope = decoded.context("invalid engine response")?;
            if envelope["ok"] != true {
                bail!(
                    "engine rejected request: {}",
                    envelope["error"].as_str().unwrap_or("unknown error")
                );
            }
            Ok(envelope["result"].clone())
        }
    }
}

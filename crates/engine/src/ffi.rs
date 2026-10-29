//! Versioned C boundary. Allocation and deallocation stay in this library.
use serde_json::{json, Value};
use std::ffi::{c_char, CString};

#[no_mangle]
pub extern "C" fn agent_lens_abi_version() -> u32 {
    1
}

/// # Safety
/// `input` must address `len` readable bytes for this call. The returned pointer
/// must be released exactly once by `agent_lens_free`, before unloading the DLL.
#[no_mangle]
pub unsafe extern "C" fn agent_lens_process(input: *const u8, len: usize) -> *mut c_char {
    let result = std::panic::catch_unwind(|| -> anyhow::Result<Value> {
        anyhow::ensure!(
            !input.is_null() && len <= 2 * 1024 * 1024,
            "invalid ABI input"
        );
        // SAFETY: Caller guarantees readable input for len bytes; bounded above.
        let bytes = unsafe { std::slice::from_raw_parts(input, len) };
        let request: Value = serde_json::from_slice(bytes)?;
        match request.get("operation").and_then(Value::as_str) {
            Some("validate_rules") => {
                let rule_ids = crate::validate_rules(
                    request["rules_yaml"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("missing rules"))?,
                )?;
                Ok(json!({"valid":true,"rule_ids":rule_ids}))
            }
            Some("config") if matches!(request["agent"].as_str(), Some("copilot" | "cowork")) => {
                let executable = request["executable"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing executable"))?;
                let args: Vec<String> = serde_json::from_value(request["args"].clone())?;
                crate::adapters::config_argv(request["agent"].as_str().unwrap(), executable, &args)
            }
            Some("config") => crate::adapters::config(
                request["agent"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing agent"))?,
                request["command"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing command"))?,
            ),
            None => crate::process(&request),
            _ => anyhow::bail!("unknown operation"),
        }
    });
    let envelope = match result {
        Ok(Ok(value)) => json!({"ok":true,"result":value}),
        // Do not export parser diagnostics that might contain input secrets.
        Ok(Err(_)) => json!({"ok":false,"error":"invalid request, agent event or rules"}),
        Err(_) => json!({"ok":false,"error":"engine panic contained"}),
    };
    match CString::new(envelope.to_string()) {
        Ok(value) => value.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
/// `ptr` must be null or an unfreed pointer returned by `agent_lens_process` from
/// this same loaded library instance. It cannot be retained after this call.
#[no_mangle]
pub unsafe extern "C" fn agent_lens_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        // SAFETY: Caller gives back this DLL's allocation exactly once.
        drop(unsafe { CString::from_raw(ptr) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_input_and_panics_do_not_cross_abi() {
        unsafe {
            let ptr = agent_lens_process(std::ptr::null(), 0);
            let value: Value =
                serde_json::from_slice(std::ffi::CStr::from_ptr(ptr).to_bytes()).unwrap();
            assert_eq!(value["ok"], false);
            agent_lens_free(ptr);
            agent_lens_free(std::ptr::null_mut());
        }
    }
}

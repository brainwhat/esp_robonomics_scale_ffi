use parity_scale_codec::{Decode, Encode};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::slice;

// --- Struct Definitions ---

/// A simple struct that will be encoded and decoded.
/// It needs to derive Encode, Decode, and typically Debug and PartialEq.
/// Clone is added for convenience if needed, but not strictly for this FFI.
#[derive(Encode, Decode, Debug, PartialEq, Clone)]
struct MyStruct {
    data: String,
}

/// Represents the result of a SCALE encoding operation.
/// This struct is passed back to C, containing a pointer to the encoded bytes
/// and the length of the byte buffer.
#[repr(C)]
pub struct ScaleEncodedResult {
    /// Pointer to the start of the byte array.
    /// This memory is allocated by Rust and must be freed by calling `free_scale_encoded_result`.
    ptr: *mut u8,
    /// Length of the byte array.
    len: usize,
}

// --- Encoding Function ---

/// Encodes a C string into the SCALE format using `MyStruct`.
///
/// # Arguments
/// * `input_c_str`: A pointer to a null-terminated C string.
///
/// # Returns
/// A `ScaleEncodedResult` struct containing the pointer to the encoded bytes and their length.
/// If input is NULL or invalid UTF-8, returns a result with a NULL pointer and 0 length.
/// The caller is responsible for freeing the `ptr` field of the returned struct
/// by calling `free_scale_encoded_result`.
#[no_mangle]
pub extern "C" fn encode_string_to_scale(input_c_str: *const c_char) -> ScaleEncodedResult {
    // Ensure the input pointer is not null
    if input_c_str.is_null() {
        eprintln!("Rust: encode_string_to_scale received a null input_c_str.");
        return ScaleEncodedResult {
            ptr: ptr::null_mut(),
            len: 0,
        };
    }

    // Convert the C string to a Rust CStr
    let c_str = unsafe { CStr::from_ptr(input_c_str) };

    // Convert CStr to a Rust String
    let rust_string = match c_str.to_str() {
        Ok(s) => s.to_owned(),
        Err(e) => {
            eprintln!(
                "Rust: Failed to convert C string to Rust string (Invalid UTF-8): {}",
                e
            );
            return ScaleEncodedResult {
                ptr: ptr::null_mut(),
                len: 0,
            };
        }
    };

    // Create an instance of MyStruct
    let my_struct_instance = MyStruct { data: rust_string };

    // Encode the struct into a Vec<u8>
    let encoded_bytes: Vec<u8> = my_struct_instance.encode();

    // Convert the Vec<u8> into a boxed slice and get its raw parts.
    // This transfers ownership of the memory to the C caller.
    let mut leaky_boxed_slice = encoded_bytes.into_boxed_slice();
    let ptr = leaky_boxed_slice.as_mut_ptr();
    let len = leaky_boxed_slice.len();

    // Prevent Rust from dropping the memory when leaky_boxed_slice goes out of scope.
    // The C code is now responsible for this memory via `free_scale_encoded_result`.
    std::mem::forget(leaky_boxed_slice);

    ScaleEncodedResult { ptr, len }
}

// --- Decoding Function ---

/// Decodes SCALE encoded bytes (expected to be `MyStruct`) back into a C string.
///
/// # Arguments
/// * `bytes_ptr`: A pointer to the byte array containing SCALE encoded data.
/// * `bytes_len`: The length of the byte array.
///
/// # Returns
/// A pointer to a null-terminated C string containing the decoded data.
/// If decoding fails, or the input pointer is null, or length is 0, returns a NULL pointer.
/// The caller is responsible for freeing the returned C string
/// by calling `free_decoded_string`.
#[no_mangle]
pub extern "C" fn decode_scale_to_string(bytes_ptr: *const u8, bytes_len: usize) -> *mut c_char {
    // Ensure the input pointer is not null and length is not zero
    if bytes_ptr.is_null() {
        eprintln!("Rust: decode_scale_to_string received a null bytes_ptr.");
        return ptr::null_mut();
    }
    if bytes_len == 0 {
        eprintln!("Rust: decode_scale_to_string received bytes_len of 0.");
        return ptr::null_mut(); // Or handle as an empty struct if that's valid
    }

    // Create a Rust slice from the raw C pointer and length
    let byte_slice = unsafe { slice::from_raw_parts(bytes_ptr, bytes_len) };

    // Attempt to decode the byte slice into MyStruct
    // Note: `&mut &byte_slice[..]` is used because `Decode::decode` expects a mutable reference to a type that implements `Input`.
    // Slices `&[u8]` implement `Input`, so `&mut &[u8]` works.
    match MyStruct::decode(&mut &byte_slice[..]) {
        Ok(decoded_struct) => {
            // Convert the decoded Rust String into a CString (null-terminated)
            match CString::new(decoded_struct.data) {
                Ok(c_string) => {
                    // Transfer ownership of the CString's buffer to C.
                    // C must call `free_decoded_string` to release this memory.
                    c_string.into_raw()
                }
                Err(e) => {
                    // This happens if the Rust string contains interior null bytes.
                    eprintln!(
                        "Rust: Failed to create CString (string contained null bytes): {}",
                        e
                    );
                    ptr::null_mut()
                }
            }
        }
        Err(e) => {
            eprintln!("Rust: Failed to decode MyStruct from bytes: {}", e);
            ptr::null_mut()
        }
    }
}

// --- Memory Freeing Functions ---

/// Frees the memory allocated by `encode_string_to_scale` for `ScaleEncodedResult`.
///
/// # Arguments
/// * `result`: The `ScaleEncodedResult` struct whose `ptr` field needs to be freed.
#[no_mangle]
pub extern "C" fn free_scale_encoded_result(result: ScaleEncodedResult) {
    if !result.ptr.is_null() {
        unsafe {
            // Reconstruct the Boxed slice from the raw parts and let Rust drop it,
            // which deallocates the memory.
            let _ = Box::from_raw(slice::from_raw_parts_mut(result.ptr, result.len));
            // println!("Rust: Freed encoded result memory at {:p}", result.ptr); // For debugging
        }
    }
}

/// Frees the memory allocated by `decode_scale_to_string` for a C string.
///
/// # Arguments
/// * `c_str_ptr`: A pointer to a C string previously returned by `decode_scale_to_string`.
#[no_mangle]
pub extern "C" fn free_decoded_string(c_str_ptr: *mut c_char) {
    if !c_str_ptr.is_null() {
        unsafe {
            // Reconstruct the CString from the raw pointer and let Rust drop it,
            // which deallocates the memory.
            let _ = CString::from_raw(c_str_ptr);
            // println!("Rust: Freed decoded string memory at {:p}", c_str_ptr); // For debugging
        }
    }
}

#![no_std] // Indicates that we are not using the standard library

// If you need allocation (e.g., for Vec<u8>) and are using esp-alloc
// #[cfg(feature = "esp-alloc")]
// #[global_allocator]
// static ALLOCATOR: esp_alloc::EspHeap = esp_alloc::EspHeap::empty();

// fn init_heap() {
//     #[cfg(feature = "esp-alloc")]
//     {
//         const HEAP_SIZE: usize = 32 * 1024; // 32KB
//         static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
//         unsafe {
//             ALLOCATOR.init(core::ptr::addr_of_mut!(HEAP) as *mut u8, HEAP_SIZE);
//         }
//     }
// }

use core::ffi::{c_char, c_int, c_void};
use core::slice;
use parity_scale_codec::{Compact, Decode, Encode};

// Example structure to encode/decode
#[derive(Encode, Decode, Debug, PartialEq)]
struct MyData {
    id: u32,
    value: Compact<u64>,
    payload: [u8; 4],
}

/// Decodes data from a buffer into a MyData struct.
/// The caller is responsible for allocating and freeing the MyDataFFI struct.
///
/// # Safety
/// - `in_buffer` must be a valid pointer to a readable buffer of `buffer_len` bytes containing SCALE encoded MyData.
/// - `out_id`, `out_value`, `out_payload_ptr` must be valid pointers to write the decoded data.
///
/// Returns 0 on success, negative on error.
#[no_mangle]
pub unsafe extern "C" fn decode_my_data(
    in_buffer: *const u8,
    buffer_len: usize,
    out_id: *mut u32,
    out_value: *mut u64,
    out_payload_ptr: *mut u8, // Pointer to a 4-byte writable buffer
) -> c_int {
    if in_buffer.is_null() || out_id.is_null() || out_value.is_null() || out_payload_ptr.is_null() {
        return -1; // Null pointer error
    }

    let input_slice = unsafe { slice::from_raw_parts(in_buffer, buffer_len) };

    match MyData::decode(&mut &input_slice[..]) {
        Ok(data) => {
            unsafe {
                *out_id = data.id;
                *out_value = data.value.0; // Access inner value of Compact
                core::ptr::copy_nonoverlapping(
                    data.payload.as_ptr(),
                    out_payload_ptr,
                    data.payload.len(),
                );
            }
            0 // Success
        }
        Err(_) => -2, // Decoding error
    }
}

// Helper function to free memory allocated by Rust (if you were to return Vec<u8>::into_raw_parts)
// This example doesn't directly need it if C side manages buffers, but good to know.
// #[no_mangle]
// pub unsafe extern "C" fn free_rust_buffer(ptr: *mut u8, len: usize, capacity: usize) {
//     if ptr.is_null() {
//         return;
//     }
//     // Reconstruct the Vec and let it drop, freeing the memory
//     let _ = unsafe { Vec::from_raw_parts(ptr, len, capacity) };
// }

/// Panic handler for `no_std` environments.
/// This is required when not linking against the standard library.
#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // On panic, loop indefinitely. You might want to trigger a specific ESP32 panic or reset.
    // For ESP-IDF targets, you might use esp_idf_sys::esp_panic_handler
    loop {}
}

#![no_std]

// Narrow C ABI bridge for socket string decoding.
// The returned buffer is allocated by Android libc malloc(), so existing C free()
// (including the project's secure-zeroing --wrap=free) remains the owner.
use core::ffi::{c_char, c_int, c_void};
use core::ptr;

const MAX_WIRE_STRING: usize = 1024 * 1024;

unsafe extern "C" {
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    fn malloc(size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
}

unsafe fn read_exact(fd: c_int, mut dst: *mut u8, mut remaining: usize) -> bool {
    while remaining != 0 {
        let n = read(fd, dst.cast(), remaining);
        if n <= 0 {
            return false;
        }
        let consumed = n as usize;
        if consumed > remaining {
            return false;
        }
        dst = dst.add(consumed);
        remaining -= consumed;
    }
    true
}

#[no_mangle]
pub unsafe extern "C" fn read_string(fd: c_int) -> *mut c_char {
    let mut length: usize = 0;

    // Wire format is native size_t followed by exactly that many bytes.
    if !read_exact(fd, (&mut length as *mut usize).cast(), core::mem::size_of::<usize>()) {
        return ptr::null_mut();
    }

    // Reject malformed or hostile lengths before addition/allocation.
    if length > MAX_WIRE_STRING || length.checked_add(1).is_none() {
        return ptr::null_mut();
    }

    let allocation = malloc(length + 1) as *mut u8;
    if allocation.is_null() {
        return ptr::null_mut();
    }

    if !read_exact(fd, allocation, length) {
        // Wipe partially received bytes before returning memory to libc.
        for index in 0..length {
            ptr::write_volatile(allocation.add(index), 0);
        }
        free(allocation.cast());
        return ptr::null_mut();
    }

    allocation.add(length).write(0);
    allocation.cast()
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

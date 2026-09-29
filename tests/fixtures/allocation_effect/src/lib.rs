#![feature(allocator_api)]

use std::alloc::{AllocError, Allocator, Global, GlobalAlloc, Layout, System};
use std::ptr::NonNull;

pub fn boxed() -> Box<u32> {
    Box::new(7)
}

pub fn vector(value: u32) -> Vec<u32> {
    let mut values = Vec::new();
    values.push(value);
    values
}

pub fn text(value: char) -> String {
    let mut text = String::new();
    text.push(value);
    text
}

pub fn direct() -> *mut u8 {
    // SAFETY: the layout is nonzero and valid.
    unsafe { std::alloc::alloc(Layout::new::<u64>()) }
}

pub fn direct_zeroed() -> *mut u8 {
    // SAFETY: the layout is nonzero and valid.
    unsafe { std::alloc::alloc_zeroed(Layout::new::<u64>()) }
}

pub fn reallocated(ptr: *mut u8) -> *mut u8 {
    // SAFETY: caller supplies a pointer allocated with the specified layout.
    unsafe { std::alloc::realloc(ptr, Layout::new::<u64>(), 16) }
}

/// # Allocations
///
/// Allocates a box for the returned value.
pub fn documented() -> Box<u32> {
    Box::new(8)
}

pub fn justified() -> *mut u8 {
    // ALLOCATION: this function is explicitly allowed to allocate a buffer.
    // SAFETY: the layout is nonzero and valid.
    unsafe { std::alloc::alloc(Layout::new::<u64>()) }
}

struct Custom;

struct CustomAllocator;

unsafe impl Allocator for CustomAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        Global.allocate(layout)
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // SAFETY: this forwards the allocator contract to Global.
        unsafe { Global.deallocate(ptr, layout) }
    }

    unsafe fn grow(
        &self,
        _ptr: NonNull<u8>,
        _old_layout: Layout,
        _new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        Err(AllocError)
    }

    unsafe fn grow_zeroed(
        &self,
        _ptr: NonNull<u8>,
        _old_layout: Layout,
        _new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        Err(AllocError)
    }

    unsafe fn shrink(
        &self,
        _ptr: NonNull<u8>,
        _old_layout: Layout,
        _new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        Err(AllocError)
    }
}

pub fn custom_allocator() -> Result<NonNull<[u8]>, AllocError> {
    CustomAllocator.allocate(Layout::new::<u64>())
}

pub unsafe fn only_grow(ptr: NonNull<u8>) -> Result<NonNull<[u8]>, AllocError> {
    // SAFETY: caller supplies a block allocated with the old layout.
    unsafe { CustomAllocator.grow(ptr, Layout::new::<u64>(), Layout::new::<u128>()) }
}

pub unsafe fn only_grow_zeroed(ptr: NonNull<u8>) -> Result<NonNull<[u8]>, AllocError> {
    // SAFETY: caller supplies a block allocated with the old layout.
    unsafe { CustomAllocator.grow_zeroed(ptr, Layout::new::<u64>(), Layout::new::<u128>()) }
}

pub unsafe fn only_shrink(ptr: NonNull<u8>) -> Result<NonNull<[u8]>, AllocError> {
    // SAFETY: caller supplies a block allocated with the old layout.
    unsafe { CustomAllocator.shrink(ptr, Layout::new::<u128>(), Layout::new::<u64>()) }
}

unsafe impl GlobalAlloc for Custom {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: this forwards the allocator contract to System.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: this forwards the allocator contract to System.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, _ptr: *mut u8, _layout: Layout, _new_size: usize) -> *mut u8 {
        std::ptr::null_mut()
    }
}

pub fn custom() -> *mut u8 {
    // SAFETY: the layout is nonzero and valid.
    unsafe { Custom.alloc(Layout::new::<u64>()) }
}

pub unsafe fn only_custom_realloc(ptr: *mut u8) -> *mut u8 {
    // SAFETY: caller supplies a block allocated with the specified layout.
    unsafe { Custom.realloc(ptr, Layout::new::<u64>(), 16) }
}

pub fn stack_only(value: u32) -> u32 {
    value + 1
}

pub fn only_dealloc(ptr: *mut u8) {
    // SAFETY: caller supplies a pointer from this allocator and layout.
    unsafe { std::alloc::dealloc(ptr, Layout::new::<u64>()) }
}

mod hole;
pub(crate) mod layout;

use self::layout::Layout;
use core::mem;
#[cfg(feature = "use_spin")]
use core::ops::Deref;
use core::ptr::NonNull;
use hole::{Hole, HoleList};
#[cfg(feature = "use_spin")]
use spinning_top::Spinlock;

/// A fixed size heap backed by a linked list of free memory blocks.
pub struct Heap {
    bottom: usize,
    size: usize,
    used: usize,
    holes: HoleList,
}

impl Heap {
    /// Creates an empty heap. All allocate calls will return `None`.
    pub fn empty() -> Heap {
        Heap {
            bottom: 0,
            size: 0,
            used: 0,
            holes: HoleList::empty(),
        }
    }

    /// Initializes an empty heap
    ///
    /// # Unsafety
    ///
    /// This function must be called at most once and must only be used on an
    /// empty heap.
    pub unsafe fn init(&mut self, heap_bottom: usize, heap_size: usize) {
        self.bottom = heap_bottom;
        self.size = heap_size;
        self.used = 0;
        self.holes = HoleList::new(heap_bottom, heap_size);
    }

    /// Creates a new heap with the given `bottom` and `size`. The bottom address must be valid
    /// and the memory in the `[heap_bottom, heap_bottom + heap_size)` range must not be used for
    /// anything else. This function is unsafe because it can cause undefined behavior if the
    /// given address is invalid.
    pub unsafe fn new(heap_bottom: usize, heap_size: usize) -> Heap {
        if heap_size < HoleList::min_size() {
            Self::empty()
        } else {
            Heap {
                bottom: heap_bottom,
                size: heap_size,
                used: 0,
                holes: HoleList::new(heap_bottom, heap_size),
            }
        }
    }

    /// Align layout. Returns a layout with size increased to
    /// fit at least `HoleList::min_size` and proper alignment of a `Hole`.
    fn align_layout(layout: Layout) -> Layout {
        let mut size = layout.size();
        if size < HoleList::min_size() {
            size = HoleList::min_size();
        }
        let size = align_up(size, mem::align_of::<Hole>());
        Layout::from_size_align(size, layout.align()).unwrap()
    }

    /// Allocates a chunk of the given size with the given alignment. Returns a pointer to the
    /// beginning of that chunk if it was successful. Else it returns `None`.
    /// This function scans the list of free memory blocks and uses the first block that is big
    /// enough. The runtime is in O(n) where n is the number of free blocks, but it should be
    /// reasonably fast for small allocations.
    pub fn allocate_first_fit(&mut self, layout: Layout) -> Result<NonNull<u8>, ()> {
        let aligned_layout = Self::align_layout(layout);
        let res = self.holes.allocate_first_fit(aligned_layout);
        if res.is_ok() {
            self.used += aligned_layout.size();
        }
        res
    }

    /// Frees the given allocation. `ptr` must be a pointer returned
    /// by a call to the `allocate_first_fit` function with identical size and alignment. Undefined
    /// behavior may occur for invalid arguments, thus this function is unsafe.
    ///
    /// This function walks the list of free memory blocks and inserts the freed block at the
    /// correct place. If the freed block is adjacent to another free block, the blocks are merged
    /// again. This operation is in `O(n)` since the list needs to be sorted by address.
    pub unsafe fn deallocate(&mut self, ptr: NonNull<u8>, layout: Layout) {
        let aligned_layout = Self::align_layout(layout);
        self.holes.deallocate(ptr, aligned_layout);
        self.used -= aligned_layout.size();
    }

    /// Returns the bottom address of the heap.
    pub fn bottom(&self) -> usize {
        self.bottom
    }

    /// Returns the size of the heap.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Return the top address of the heap
    pub fn top(&self) -> usize {
        self.bottom + self.size
    }

    /// Returns the size of the used part of the heap
    pub fn used(&self) -> usize {
        self.used
    }

    /// Returns the size of the free part of the heap
    pub fn free(&self) -> usize {
        self.size - self.used
    }

    /// Extends the size of the heap by creating a new hole at the end
    ///
    /// # Unsafety
    ///
    /// The new extended area must be valid
    pub unsafe fn extend(&mut self, by: usize) {
        let top = self.top();
        let layout = Layout::from_size_align(by, 1).unwrap();
        self.holes
            .deallocate(NonNull::new_unchecked(top as *mut u8), layout);
        self.size += by;
    }
}

/// Align downwards. Returns the greatest x with alignment `align`
/// so that x <= addr. The alignment must be a power of 2.
pub fn align_down(addr: usize, align: usize) -> usize {
    if align.is_power_of_two() {
        addr & !(align - 1)
    } else if align == 0 {
        addr
    } else {
        panic!("`align` must be a power of 2");
    }
}

/// Align upwards. Returns the smallest x with alignment `align`
/// so that x >= addr. The alignment must be a power of 2.
pub fn align_up(addr: usize, align: usize) -> usize {
    align_down(addr + align - 1, align)
}

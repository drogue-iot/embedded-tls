use core::sync::atomic::{AtomicBool, Ordering};

pub trait SplitState: Clone {
    fn same(&self, other: &Self) -> bool;
    fn is_open(&self) -> bool;
    fn set_open(&self, open: bool);
}

pub struct SplitConnectionState {
    is_open: AtomicBool,
}

impl Default for SplitConnectionState {
    #[inline]
    fn default() -> Self {
        Self {
            is_open: AtomicBool::new(true),
        }
    }
}

impl SplitState for &SplitConnectionState {
    fn is_open(&self) -> bool {
        self.is_open.load(Ordering::Acquire)
    }

    fn set_open(&self, open: bool) {
        self.is_open.store(open, Ordering::Release);
    }

    fn same(&self, other: &Self) -> bool {
        core::ptr::eq(self, other)
    }
}

#[cfg(feature = "std")]
pub use stdlib::ManagedSplitState;

#[cfg(feature = "std")]
mod stdlib {
    use super::*;
    use std::sync::Arc;

    #[derive(Clone)]
    pub struct ManagedSplitState(Arc<SplitConnectionState>);
    impl Default for ManagedSplitState {
        #[inline]
        fn default() -> Self {
            Self(Arc::new(SplitConnectionState::default()))
        }
    }

    impl SplitState for ManagedSplitState {
        fn is_open(&self) -> bool {
            self.0.as_ref().is_open()
        }

        fn set_open(&self, open: bool) {
            self.0.as_ref().set_open(open)
        }

        fn same(&self, other: &Self) -> bool {
            Arc::ptr_eq(&self.0, &other.0)
        }
    }
}

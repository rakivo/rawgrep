//! - With `debug_assertions` **on**: behaves exactly like `container[index]`
//!   (bounds-checked, panics with a `#[track_caller]` location on OOB).
//!
//! - With `debug_assertions` **off**: behaves like
//!   `container.get_unchecked(index)` / `get_unchecked_mut(index)` no
//!   bounds check, UB if the index/range is out of bounds.

use std::slice::SliceIndex;

pub trait Index_<I> {
    type Output: ?Sized;

    fn get_(&self, index: I) -> &Self::Output;
}

pub trait IndexMut_<I>: Index_<I> {
    fn get_mut_(&mut self, index: I) -> &mut Self::Output;
}

impl<T, I> Index_<I> for [T]
where
    I: SliceIndex<[T]>,
{
    type Output = I::Output;

    #[inline(always)]
    #[cfg_attr(debug_assertions, track_caller)]
    fn get_(&self, index: I) -> &I::Output {
        #[cfg(debug_assertions)]             { &self[index] }
        #[cfg(not(debug_assertions))] unsafe { self.get_unchecked(index) }
    }
}

impl<T, I> IndexMut_<I> for [T]
where
    I: SliceIndex<[T]>,
{
    #[inline(always)]
    #[cfg_attr(debug_assertions, track_caller)]
    fn get_mut_(&mut self, index: I) -> &mut I::Output {
        #[cfg(debug_assertions)]             { &mut self[index] }
        #[cfg(not(debug_assertions))] unsafe { self.get_unchecked_mut(index) }
    }
}

impl<I> Index_<I> for str
where
    I: SliceIndex<str>,
{
    type Output = I::Output;

    #[inline(always)]
    #[cfg_attr(debug_assertions, track_caller)]
    fn get_(&self, index: I) -> &I::Output {
        #[cfg(debug_assertions)]             { &self[index] }
        #[cfg(not(debug_assertions))] unsafe { self.get_unchecked(index) }
    }
}

impl<I> IndexMut_<I> for str
where
    I: SliceIndex<str>,
{
    #[inline(always)]
    #[cfg_attr(debug_assertions, track_caller)]
    fn get_mut_(&mut self, index: I) -> &mut I::Output {
        #[cfg(debug_assertions)]             { &mut self[index] }
        #[cfg(not(debug_assertions))] unsafe { self.get_unchecked_mut(index) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_by_usize() {
        let v = [1, 2, 3];
        assert_eq!(*v.get_(1), 2);
    }

    #[test]
    fn index_by_range() {
        let v = [1, 2, 3, 4];
        assert_eq!(v.get_(1..3), &[2, 3]);
        assert_eq!(v.get_(..2), &[1, 2]);
        assert_eq!(v.get_(2..), &[3, 4]);
        assert_eq!(v.get_(..), &[1, 2, 3, 4][..]);
        assert_eq!(v.get_(1..=2), &[2, 3]);
    }

    #[test]
    fn index_mut() {
        let mut v = vec![1, 2, 3];
        *v.get_mut_(0) = 42;
        assert_eq!(v[0], 42);

        let s = v.get_mut_(1..3);
        s[0] = 7;
        assert_eq!(v, vec![42, 7, 3]);
    }

    #[test]
    fn arrays() {
        let mut arr = [1, 2, 3, 4];
        assert_eq!(*arr.get_(2), 3);
        *arr.get_mut_(2) = 99;
        assert_eq!(arr[2], 99);
    }

    #[test]
    fn strings() {
        let s = String::from("hello world");
        assert_eq!(s.get_(0..5), "hello");
    }

    #[test]
    #[should_panic]
    fn debug_still_panics_on_oob() {
        // In a debug build this must panic, same as `v[10]` would.
        let v = [1, 2, 3];
        _ = v.get_(10);
    }
}

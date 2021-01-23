// Adapted from arweaver https://github.com/rootmos/arweaver/blob/master/src/types.rs
// The UNLICENSE © Gustav Behm
// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org/>

use num_bigint::BigUint;
use std::fmt;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Winstons(BigUint);

impl Winstons {
    pub fn decode<T: AsRef<[u8]>>(t: T) -> Result<Self, String> {
        BigUint::parse_bytes(t.as_ref(), 10)
            .map(Self)
            .ok_or("a non-negative decimal number of Winstons".to_string())
    }
}

impl fmt::Display for Winstons {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Add for Winstons {
    type Output = Winstons;
    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl std::ops::Add for &Winstons {
    type Output = Winstons;
    fn add(self, other: Self) -> Winstons {
        Winstons(self.0.to_owned() + other.0.to_owned())
    }
}

impl<T> From<T> for Winstons
where
    T: Into<BigUint>,
{
    #[inline]
    fn from(t: T) -> Self {
        Self(t.into())
    }
}

impl AsRef<Winstons> for Winstons {
    #[inline]
    fn as_ref(&self) -> &Self {
        self
    }
}

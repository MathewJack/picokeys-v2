// Copyright © 2018–2026 Trevor Spiteri

// This library is free software: you can redistribute it and/or
// modify it under the terms of either
//
//   * the Apache License, Version 2.0 or
//   * the MIT License
//
// at your option.
//
// You should have recieved copies of the Apache License and the MIT
// License along with the library. If not, see
// <https://www.apache.org/licenses/LICENSE-2.0> and
// <https://opensource.org/licenses/MIT>.

use crate::from_str::ParseFixedError;
use crate::traits::{Fixed, FixedSigned, FixedUnsigned, FromFixed, ToFixed};
use crate::types::extra::{LeEqU8, LeEqU16, LeEqU32, LeEqU64, LeEqU128};
use crate::{
    FixedI8, FixedI16, FixedI32, FixedI64, FixedI128, FixedU8, FixedU16, FixedU32, FixedU64,
    FixedU128,
};
use core::fmt::{
    Binary, Debug, Display, Formatter, LowerExp, LowerHex, Octal, Result as FmtResult, UpperExp,
    UpperHex,
};
use core::iter::{Product, Sum};
use core::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};
use core::str::FromStr;

/// Provides arithmetic operations that panic on overflow even when
/// debug assertions are disabled.
///
/// The underlying value can be retrieved through the `.0` index.
///
/// # Examples
///
/// This panics even when debug assertions are disabled.
///
/// ```rust,should_panic
/// use fixed::types::I16F16;
/// use fixed::Strict;
/// let max = Strict(I16F16::MAX);
/// let delta = Strict(I16F16::DELTA);
/// let _overflow = max + delta;
/// ```
#[repr(transparent)]
#[derive(Clone, Copy, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Strict<F>(pub F);

#[deprecated(since = "1.30.0", note = "renamed to `Strict`")]
/// Provides arithmetic operations that panic on overflow even when
/// debug assertions are disabled.
pub type Unwrapped<F> = Strict<F>;

impl<F: Fixed> Strict<F> {
    /// Zero.
    ///
    /// See also <code>FixedI32::[ZERO][FixedI32::ZERO]</code> and
    /// <code>FixedU32::[ZERO][FixedU32::ZERO]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// assert_eq!(Strict::<I16F16>::ZERO, Strict(I16F16::ZERO));
    /// ```
    pub const ZERO: Strict<F> = Strict(F::ZERO);

    /// The difference between any two successive representable numbers, <i>Δ</i>.
    ///
    /// See also <code>FixedI32::[DELTA][FixedI32::DELTA]</code> and
    /// <code>FixedU32::[DELTA][FixedU32::DELTA]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// assert_eq!(Strict::<I16F16>::DELTA, Strict(I16F16::DELTA));
    /// ```
    pub const DELTA: Strict<F> = Strict(F::DELTA);

    /// The smallest value that can be represented.
    ///
    /// See also <code>FixedI32::[MIN][FixedI32::MIN]</code> and
    /// <code>FixedU32::[MIN][FixedU32::MIN]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// assert_eq!(Strict::<I16F16>::MIN, Strict(I16F16::MIN));
    /// ```
    pub const MIN: Strict<F> = Strict(F::MIN);

    /// The largest value that can be represented.
    ///
    /// See also <code>FixedI32::[MAX][FixedI32::MAX]</code> and
    /// <code>FixedU32::[MAX][FixedU32::MAX]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// assert_eq!(Strict::<I16F16>::MAX, Strict(I16F16::MAX));
    /// ```
    pub const MAX: Strict<F> = Strict(F::MAX);

    /// [`true`] if the type is signed.
    ///
    /// See also <code>FixedI32::[IS\_SIGNED][FixedI32::IS_SIGNED]</code> and
    /// <code>FixedU32::[IS\_SIGNED][FixedU32::IS_SIGNED]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::{I16F16, U16F16};
    /// use fixed::Strict;
    /// assert!(Strict::<I16F16>::IS_SIGNED);
    /// assert!(!Strict::<U16F16>::IS_SIGNED);
    /// ```
    pub const IS_SIGNED: bool = F::IS_SIGNED;

    /// The number of integer bits.
    ///
    /// See also <code>FixedI32::[INT\_NBITS][FixedI32::INT_NBITS]</code> and
    /// <code>FixedU32::[INT\_NBITS][FixedU32::INT_NBITS]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// assert_eq!(Strict::<I16F16>::INT_NBITS, I16F16::INT_NBITS);
    /// ```
    pub const INT_NBITS: u32 = F::INT_NBITS;

    /// The number of fractional bits.
    ///
    /// See also <code>FixedI32::[FRAC\_NBITS][FixedI32::FRAC_NBITS]</code> and
    /// <code>FixedU32::[FRAC\_NBITS][FixedU32::FRAC_NBITS]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// assert_eq!(Strict::<I16F16>::FRAC_NBITS, I16F16::FRAC_NBITS);
    /// ```
    pub const FRAC_NBITS: u32 = F::FRAC_NBITS;

    /// Creates a fixed-point number that has a bitwise representation
    /// identical to the given integer.
    ///
    /// See also <code>FixedI32::[from\_bits][FixedI32::from_bits]</code> and
    /// <code>FixedU32::[from\_bits][FixedU32::from_bits]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// assert_eq!(Strict::<I16F16>::from_bits(0x1C), Strict(I16F16::from_bits(0x1C)));
    /// ```
    #[inline]
    pub fn from_bits(bits: F::Bits) -> Strict<F> {
        Strict(F::from_bits(bits))
    }

    /// Creates an integer that has a bitwise representation identical
    /// to the given fixed-point number.
    ///
    /// See also <code>FixedI32::[to\_bits][FixedI32::to_bits]</code> and
    /// <code>FixedU32::[to\_bits][FixedU32::to_bits]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let s = Strict(I16F16::from_bits(0x1C));
    /// assert_eq!(s.to_bits(), 0x1C);
    /// ```
    #[inline]
    pub fn to_bits(self) -> F::Bits {
        self.0.to_bits()
    }

    /// Converts a fixed-point number from big endian to the target’s
    /// endianness.
    ///
    /// See also <code>FixedI32::[from\_be][FixedI32::from_be]</code> and
    /// <code>FixedU32::[from\_be][FixedU32::from_be]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let s = Strict(I16F16::from_bits(0x1234_5678));
    /// if cfg!(target_endian = "big") {
    ///     assert_eq!(Strict::from_be(s), s);
    /// } else {
    ///     assert_eq!(Strict::from_be(s), s.swap_bytes());
    /// }
    /// ```
    #[inline]
    pub fn from_be(s: Self) -> Self {
        Strict(F::from_be(s.0))
    }

    /// Converts a fixed-point number from little endian to the
    /// target’s endianness.
    ///
    /// See also <code>FixedI32::[from\_le][FixedI32::from_le]</code> and
    /// <code>FixedU32::[from\_le][FixedU32::from_le]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let s = Strict(I16F16::from_bits(0x1234_5678));
    /// if cfg!(target_endian = "little") {
    ///     assert_eq!(Strict::from_le(s), s);
    /// } else {
    ///     assert_eq!(Strict::from_le(s), s.swap_bytes());
    /// }
    /// ```
    #[inline]
    pub fn from_le(s: Self) -> Self {
        Strict(F::from_le(s.0))
    }

    /// Converts `self` to big endian from the target’s endianness.
    ///
    /// See also <code>FixedI32::[to\_be][FixedI32::to_be]</code> and
    /// <code>FixedU32::[to\_be][FixedU32::to_be]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let s = Strict(I16F16::from_bits(0x1234_5678));
    /// if cfg!(target_endian = "big") {
    ///     assert_eq!(s.to_be(), s);
    /// } else {
    ///     assert_eq!(s.to_be(), s.swap_bytes());
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub fn to_be(self) -> Self {
        Strict(self.0.to_be())
    }

    /// Converts `self` to little endian from the target’s endianness.
    ///
    /// See also <code>FixedI32::[to\_le][FixedI32::to_le]</code> and
    /// <code>FixedU32::[to\_le][FixedU32::to_le]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let s = Strict(I16F16::from_bits(0x1234_5678));
    /// if cfg!(target_endian = "little") {
    ///     assert_eq!(s.to_le(), s);
    /// } else {
    ///     assert_eq!(s.to_le(), s.swap_bytes());
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub fn to_le(self) -> Self {
        Strict(self.0.to_le())
    }

    /// Reverses the byte order of the fixed-point number.
    ///
    /// See also <code>FixedI32::[swap\_bytes][FixedI32::swap_bytes]</code> and
    /// <code>FixedU32::[swap\_bytes][FixedU32::swap_bytes]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let s = Strict(I16F16::from_bits(0x1234_5678));
    /// let swapped = Strict(I16F16::from_bits(0x7856_3412));
    /// assert_eq!(s.swap_bytes(), swapped);
    /// ```
    #[inline]
    #[must_use]
    pub fn swap_bytes(self) -> Self {
        Strict(self.0.swap_bytes())
    }

    /// Creates a fixed-point number from its representation
    /// as a byte array in big endian.
    ///
    /// See also
    /// <code>FixedI32::[from\_be\_bytes][FixedI32::from_be_bytes]</code> and
    /// <code>FixedU32::[from\_be\_bytes][FixedU32::from_be_bytes]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let bytes = [0x12, 0x34, 0x56, 0x78];
    /// assert_eq!(
    ///     Strict::<I16F16>::from_be_bytes(bytes),
    ///     Strict::<I16F16>::from_bits(0x1234_5678)
    /// );
    /// ```
    #[inline]
    pub fn from_be_bytes(bytes: F::Bytes) -> Self {
        Strict(F::from_be_bytes(bytes))
    }

    /// Creates a fixed-point number from its representation
    /// as a byte array in little endian.
    ///
    /// See also
    /// <code>FixedI32::[from\_le\_bytes][FixedI32::from_le_bytes]</code> and
    /// <code>FixedU32::[from\_le\_bytes][FixedU32::from_le_bytes]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let bytes = [0x78, 0x56, 0x34, 0x12];
    /// assert_eq!(
    ///     Strict::<I16F16>::from_le_bytes(bytes),
    ///     Strict::<I16F16>::from_bits(0x1234_5678)
    /// );
    /// ```
    #[inline]
    pub fn from_le_bytes(bytes: F::Bytes) -> Self {
        Strict(F::from_le_bytes(bytes))
    }

    /// Creates a fixed-point number from its representation
    /// as a byte array in native endian.
    ///
    /// See also
    /// <code>FixedI32::[from\_ne\_bytes][FixedI32::from_ne_bytes]</code> and
    /// <code>FixedU32::[from\_ne\_bytes][FixedU32::from_ne_bytes]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let bytes = if cfg!(target_endian = "big") {
    ///     [0x12, 0x34, 0x56, 0x78]
    /// } else {
    ///     [0x78, 0x56, 0x34, 0x12]
    /// };
    /// assert_eq!(
    ///     Strict::<I16F16>::from_ne_bytes(bytes),
    ///     Strict::<I16F16>::from_bits(0x1234_5678)
    /// );
    /// ```
    #[inline]
    pub fn from_ne_bytes(bytes: F::Bytes) -> Self {
        Strict(F::from_ne_bytes(bytes))
    }

    /// Returns the memory representation of this fixed-point
    /// number as a byte array in big-endian byte order.
    ///
    /// See also <code>FixedI32::[to\_be\_bytes][FixedI32::to_be_bytes]</code>
    /// and <code>FixedU32::[to\_be\_bytes][FixedU32::to_be_bytes]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// assert_eq!(
    ///     Strict::<I16F16>::from_bits(0x1234_5678).to_be_bytes(),
    ///     [0x12, 0x34, 0x56, 0x78]
    /// );
    /// ```
    #[inline]
    pub fn to_be_bytes(self) -> F::Bytes {
        self.0.to_be_bytes()
    }

    /// Returns the memory representation of this fixed-point
    /// number as a byte array in little-endian byte order.
    ///
    /// See also <code>FixedI32::[to\_le\_bytes][FixedI32::to_le_bytes]</code>
    /// and <code>FixedU32::[to\_le\_bytes][FixedU32::to_le_bytes]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// assert_eq!(
    ///     Strict::<I16F16>::from_bits(0x1234_5678).to_le_bytes(),
    ///     [0x78, 0x56, 0x34, 0x12]
    /// );
    /// ```
    #[inline]
    pub fn to_le_bytes(self) -> F::Bytes {
        self.0.to_le_bytes()
    }

    /// Returns the memory representation of this fixed-point
    /// number as a byte array in native-endian byte order.
    ///
    /// See also <code>FixedI32::[to\_ne\_bytes][FixedI32::to_ne_bytes]</code>
    /// and <code>FixedU32::[to\_ne\_bytes][FixedU32::to_ne_bytes]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let bytes = if cfg!(target_endian = "big") {
    ///     [0x12, 0x34, 0x56, 0x78]
    /// } else {
    ///     [0x78, 0x56, 0x34, 0x12]
    /// };
    /// assert_eq!(
    ///     Strict::<I16F16>::from_bits(0x1234_5678).to_ne_bytes(),
    ///     bytes
    /// );
    /// ```
    #[inline]
    pub fn to_ne_bytes(self) -> F::Bytes {
        self.0.to_ne_bytes()
    }

    /// Strict conversion from another number.
    ///
    /// The other number can be:
    ///
    ///   * A fixed-point number. Any extra fractional bits are
    ///     discarded, which rounds towards &minus;∞.
    ///   * An integer of type [`i8`], [`i16`], [`i32`], [`i64`], [`i128`],
    ///     [`isize`], [`u8`], [`u16`], [`u32`], [`u64`], [`u128`], or
    ///     [`usize`].
    ///   * A floating-point number of type
    ///     <code>[half]::[f16][half::f16]</code>,
    ///     <code>[half]::[bf16][half::bf16]</code>, [`f32`], [`f64`] or
    ///     [`F128`]. For this conversion, the method rounds to the nearest,
    ///     with ties rounding to even.
    ///   * Any other number `src` for which [`ToFixed`] is
    ///     implemented, in which case this method returns
    ///     <code>[Strict]\(src.[strict\_to\_fixed][ToFixed::strict_to_fixed]\())</code>.
    ///
    /// See also
    /// <code>FixedI32::[strict\_from\_num][FixedI32::strict_from_num]</code>
    /// and
    /// <code>FixedU32::[strict\_from\_num][FixedU32::strict_from_num]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the value does not fit.
    ///
    /// For floating-point numbers, also panics if the value is not [finite].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::{I4F4, I16F16};
    /// use fixed::Strict;
    /// let src = I16F16::from_num(1.75);
    /// let dst = Strict::<I4F4>::from_num(src);
    /// assert_eq!(dst, Strict(I4F4::from_num(1.75)));
    /// ```
    ///
    /// The following panics even when debug assertions are disabled.
    ///
    /// ```should_panic
    /// use fixed::types::{I4F4, I16F16};
    /// use fixed::Strict;
    /// let src = I16F16::from_bits(0x1234_5678);
    /// let _overflow = Strict::<I4F4>::from_num(src);
    /// ```
    ///
    /// [`F128`]: crate::F128
    /// [finite]: f64::is_finite
    #[inline]
    #[track_caller]
    pub fn from_num<Src: ToFixed>(src: Src) -> Strict<F> {
        Strict(src.strict_to_fixed())
    }

    /// Converts a fixed-point number to another number, panicking on
    /// overflow.
    ///
    /// The other number can be:
    ///
    ///   * Another fixed-point number. Any extra fractional bits are
    ///     discarded, which rounds towards &minus;∞.
    ///   * An integer of type [`i8`], [`i16`], [`i32`], [`i64`], [`i128`],
    ///     [`isize`], [`u8`], [`u16`], [`u32`], [`u64`], [`u128`], or
    ///     [`usize`]. Any fractional bits are discarded, which rounds
    ///     towards &minus;∞.
    ///   * A floating-point number of type
    ///     <code>[half]::[f16][half::f16]</code>,
    ///     <code>[half]::[bf16][half::bf16]</code>, [`f32`], [`f64`] or
    ///     [`F128`]. For this conversion, the method rounds to the nearest,
    ///     with ties rounding to even.
    ///   * Any other type `Dst` for which [`FromFixed`] is
    ///     implemented, in which case this method returns
    ///     <code>Dst::[strict\_from\_fixed][FromFixed::strict_from_fixed]\(self.0)</code>.
    ///
    /// See also
    /// <code>FixedI32::[strict\_to\_num][FixedI32::strict_to_num]</code>
    /// and
    /// <code>FixedU32::[strict\_to\_num][FixedU32::strict_to_num]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::{I16F16, I4F4};
    /// use fixed::Strict;
    /// let src = Strict(I4F4::from_num(1.75));
    /// assert_eq!(src.to_num::<I16F16>(), I16F16::from_num(1.75));
    /// ```
    ///
    /// The following panics even when debug assertions are disabled.
    ///
    /// ```should_panic
    /// use fixed::types::{I2F6, I4F4};
    /// use fixed::Strict;
    /// let src = Strict(I4F4::MAX);
    /// let _overflow = src.to_num::<I2F6>();
    /// ```
    ///
    /// [`F128`]: crate::F128
    #[inline]
    #[track_caller]
    pub fn to_num<Dst: FromFixed>(self) -> Dst {
        Dst::strict_from_fixed(self.0)
    }

    /// Parses a string slice containing decimal digits to return a fixed-point number.
    ///
    /// Rounding is to the nearest, with ties rounded to even.
    ///
    /// See also
    /// <code>FixedI32::[strict\_from\_str][FixedI32::strict_from_str]</code>
    /// and
    /// <code>FixedU32::[strict\_from\_str][FixedU32::strict_from_str]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the value does not fit or if there is a parsing error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// // 16 + 3/4 = 16.75
    /// let check = Strict(I8F8::from_bits((16 << 8) + (3 << 8) / 4));
    /// assert_eq!(Strict::<I8F8>::from_str_dec("16.75"), check);
    /// ```
    ///
    /// The following panics because of a parsing error.
    ///
    /// ```rust,should_panic
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// let _error = Strict::<I8F8>::from_str_dec("1.2.");
    /// ```
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn from_str_dec(src: &str) -> Strict<F> {
        Strict(F::strict_from_str(src))
    }

    /// Parses a string slice containing binary digits to return a fixed-point number.
    ///
    /// Rounding is to the nearest, with ties rounded to even.
    ///
    /// See also
    /// <code>FixedI32::[strict\_from\_str\_binary][FixedI32::strict_from_str_binary]</code>
    /// and
    /// <code>FixedU32::[strict\_from\_str\_binary][FixedU32::strict_from_str_binary]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the value does not fit or if there is a parsing error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// let check = Strict(I8F8::from_bits(0b1110001 << (8 - 1)));
    /// assert_eq!(Strict::<I8F8>::from_str_binary("111000.1"), Ok(check));
    /// ```
    ///
    /// The following panics because of a parsing error.
    ///
    /// ```rust,should_panic
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// let _error = Strict::<I8F8>::from_str_binary("1.2");
    /// ```
    ///
    /// # Compatibility note
    ///
    /// This method either returns [`Ok`] or panics, and never returns [`Err`].
    /// In version 2, this method will not return a [`Result`], but will return
    /// the fixed-point number directly similarly to [`from_str_dec`].
    ///
    /// [`from_str_dec`]: Self::from_str_dec
    #[inline]
    #[track_caller]
    pub fn from_str_binary(src: &str) -> Result<Strict<F>, ParseFixedError> {
        Ok(Strict(F::strict_from_str_binary(src)))
    }

    /// Parses a string slice containing octal digits to return a fixed-point number.
    ///
    /// Rounding is to the nearest, with ties rounded to even.
    ///
    /// See also
    /// <code>FixedI32::[strict\_from\_str\_octal][FixedI32::strict_from_str_octal]</code>
    /// and
    /// <code>FixedU32::[strict\_from\_str\_octal][FixedU32::strict_from_str_octal]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the value does not fit or if there is a parsing error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// let check = Strict(I8F8::from_bits(0o1654 << (8 - 3)));
    /// assert_eq!(Strict::<I8F8>::from_str_octal("165.4"), Ok(check));
    /// ```
    ///
    /// The following panics because of a parsing error.
    ///
    /// ```rust,should_panic
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// let _error = Strict::<I8F8>::from_str_octal("1.8");
    /// ```
    ///
    /// # Compatibility note
    ///
    /// This method either returns [`Ok`] or panics, and never returns [`Err`].
    /// In version 2, this method will not return a [`Result`], but will return
    /// the fixed-point number directly similarly to [`from_str_dec`].
    ///
    /// [`from_str_dec`]: Self::from_str_dec
    #[inline]
    #[track_caller]
    pub fn from_str_octal(src: &str) -> Result<Strict<F>, ParseFixedError> {
        Ok(Strict(F::strict_from_str_octal(src)))
    }

    /// Parses a string slice containing hexadecimal digits to return a fixed-point number.
    ///
    /// Rounding is to the nearest, with ties rounded to even.
    ///
    /// See also
    /// <code>FixedI32::[strict\_from\_str\_hex][FixedI32::strict_from_str_hex]</code>
    /// and
    /// <code>FixedU32::[strict\_from\_str\_hex][FixedU32::strict_from_str_hex]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the value does not fit or if there is a parsing error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// let check = Strict(I8F8::from_bits(0xFFE));
    /// assert_eq!(Strict::<I8F8>::from_str_hex("F.FE"), Ok(check));
    /// ```
    ///
    /// The following panics because of a parsing error.
    ///
    /// ```rust,should_panic
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// let _error = Strict::<I8F8>::from_str_hex("1.G");
    /// ```
    ///
    /// # Compatibility note
    ///
    /// This method either returns [`Ok`] or panics, and never returns [`Err`].
    /// In version 2, this method will not return a [`Result`], but will return
    /// the fixed-point number directly similarly to [`from_str_dec`].
    ///
    /// [`from_str_dec`]: Self::from_str_dec
    #[inline]
    #[track_caller]
    pub fn from_str_hex(src: &str) -> Result<Strict<F>, ParseFixedError> {
        Ok(Strict(F::strict_from_str_hex(src)))
    }

    /// Parses an ASCII-byte slice containing decimal digits to return a fixed-point number.
    ///
    /// Rounding is to the nearest, with ties rounded to even.
    ///
    /// See also
    /// <code>FixedI32::[strict\_from\_ascii][FixedI32::strict_from_ascii]</code>
    /// and
    /// <code>FixedU32::[strict\_from\_ascii][FixedU32::strict_from_ascii]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the value does not fit or if there is a parsing error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// // 16 + 3/4 = 16.75
    /// let check = Strict(I8F8::from_bits((16 << 8) + (3 << 8) / 4));
    /// assert_eq!(Strict::<I8F8>::from_ascii(b"16.75"), check);
    /// ```
    ///
    /// The following panics because of a parsing error.
    ///
    /// ```rust,should_panic
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// let _error = Strict::<I8F8>::from_ascii(b"1.2.");
    /// ```
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn from_ascii(src: &[u8]) -> Strict<F> {
        Strict(F::strict_from_ascii(src))
    }

    /// Parses an ASCII-byte slice containing binary digits to return a fixed-point number.
    ///
    /// Rounding is to the nearest, with ties rounded to even.
    ///
    /// See also
    /// <code>FixedI32::[strict\_from\_ascii\_binary][FixedI32::strict_from_ascii_binary]</code>
    /// and
    /// <code>FixedU32::[strict\_from\_ascii\_binary][FixedU32::strict_from_ascii_binary]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the value does not fit or if there is a parsing error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// let check = Strict(I8F8::from_bits(0b1110001 << (8 - 1)));
    /// assert_eq!(Strict::<I8F8>::from_ascii_binary(b"111000.1"), check);
    /// ```
    ///
    /// The following panics because of a parsing error.
    ///
    /// ```rust,should_panic
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// let _error = Strict::<I8F8>::from_ascii_binary(b"1.2");
    /// ```
    #[inline]
    #[track_caller]
    pub fn from_ascii_binary(src: &[u8]) -> Strict<F> {
        Strict(F::strict_from_ascii_binary(src))
    }

    /// Parses an ASCII-byte slice containing octal digits to return a fixed-point number.
    ///
    /// Rounding is to the nearest, with ties rounded to even.
    ///
    /// See also
    /// <code>FixedI32::[strict\_from\_ascii\_octal][FixedI32::strict_from_ascii_octal]</code>
    /// and
    /// <code>FixedU32::[strict\_from\_ascii\_octal][FixedU32::strict_from_ascii_octal]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the value does not fit or if there is a parsing error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// let check = Strict(I8F8::from_bits(0o1654 << (8 - 3)));
    /// assert_eq!(Strict::<I8F8>::from_ascii_octal(b"165.4"), check);
    /// ```
    ///
    /// The following panics because of a parsing error.
    ///
    /// ```rust,should_panic
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// let _error = Strict::<I8F8>::from_ascii_octal(b"1.8");
    /// ```
    #[inline]
    #[track_caller]
    pub fn from_ascii_octal(src: &[u8]) -> Strict<F> {
        Strict(F::strict_from_ascii_octal(src))
    }

    /// Parses an ASCII-byte slice containing hexadecimal digits to return a fixed-point number.
    ///
    /// Rounding is to the nearest, with ties rounded to even.
    ///
    /// See also
    /// <code>FixedI32::[strict\_from\_ascii\_hex][FixedI32::strict_from_ascii_hex]</code>
    /// and
    /// <code>FixedU32::[strict\_from\_ascii\_hex][FixedU32::strict_from_ascii_hex]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the value does not fit or if there is a parsing error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// let check = Strict(I8F8::from_bits(0xFFE));
    /// assert_eq!(Strict::<I8F8>::from_ascii_hex(b"F.FE"), check);
    /// ```
    ///
    /// The following panics because of a parsing error.
    ///
    /// ```rust,should_panic
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// let _error = Strict::<I8F8>::from_ascii_hex(b"1.G");
    /// ```
    #[inline]
    #[track_caller]
    pub fn from_ascii_hex(src: &[u8]) -> Strict<F> {
        Strict(F::strict_from_ascii_hex(src))
    }

    /// Returns the integer part.
    ///
    /// Note that since the numbers are stored in two’s complement,
    /// negative numbers with non-zero fractional parts will be
    /// rounded towards &minus;∞, except in the case where there are no
    /// integer bits, for example for the type
    /// <code>[Strict]&lt;[I0F16]&gt;</code>, where the return
    /// value is always zero.
    ///
    /// See also <code>FixedI32::[int][FixedI32::int]</code> and
    /// <code>FixedU32::[int][FixedU32::int]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// assert_eq!(Strict(I16F16::from_num(12.25)).int(), Strict(I16F16::from_num(12)));
    /// assert_eq!(Strict(I16F16::from_num(-12.25)).int(), Strict(I16F16::from_num(-13)));
    /// ```
    ///
    /// [I0F16]: crate::types::I0F16
    #[inline]
    #[must_use]
    pub fn int(self) -> Strict<F> {
        Strict(self.0.int())
    }

    /// Returns the fractional part.
    ///
    /// Note that since the numbers are stored in two’s complement,
    /// the returned fraction will be non-negative for negative
    /// numbers, except in the case where there are no integer bits,
    /// for example for the type
    /// <code>[Strict]&lt;[I0F16]&gt;</code>, where the return
    /// value is always equal to `self`.
    ///
    /// See also <code>FixedI32::[frac][FixedI32::frac]</code> and
    /// <code>FixedU32::[frac][FixedU32::frac]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// assert_eq!(Strict(I16F16::from_num(12.25)).frac(), Strict(I16F16::from_num(0.25)));
    /// assert_eq!(Strict(I16F16::from_num(-12.25)).frac(), Strict(I16F16::from_num(0.75)));
    /// ```
    ///
    /// [I0F16]: crate::types::I0F16
    #[inline]
    #[must_use]
    pub fn frac(self) -> Strict<F> {
        Strict(self.0.frac())
    }

    /// Rounds to the next integer towards 0.
    ///
    /// See also
    /// <code>FixedI32::[round\_to\_zero][FixedI32::round_to_zero]</code> and
    /// <code>FixedU32::[round\_to\_zero][FixedU32::round_to_zero]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let three = Strict(I16F16::from_num(3));
    /// assert_eq!(Strict(I16F16::from_num(3.9)).round_to_zero(), three);
    /// assert_eq!(Strict(I16F16::from_num(-3.9)).round_to_zero(), -three);
    /// ```
    #[inline]
    #[must_use]
    pub fn round_to_zero(self) -> Strict<F> {
        Strict(self.0.round_to_zero())
    }

    /// Strict ceil. Rounds to the next integer towards +∞, panicking
    /// on overflow.
    ///
    /// See also
    /// <code>FixedI32::[strict\_ceil][FixedI32::strict_ceil]</code> and
    /// <code>FixedU32::[strict\_ceil][FixedU32::strict_ceil]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the result does not fit.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let two_half = Strict(I16F16::from_num(5) / 2);
    /// assert_eq!(two_half.ceil(), Strict(I16F16::from_num(3)));
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let _overflow = Strict(I16F16::MAX).ceil();
    /// ```
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn ceil(self) -> Strict<F> {
        Strict(self.0.strict_ceil())
    }

    /// Strict floor. Rounds to the next integer towards &minus;∞,
    /// panicking on overflow.
    ///
    /// Overflow can only occur for signed numbers with zero integer
    /// bits.
    ///
    /// See also
    /// <code>FixedI32::[strict\_floor][FixedI32::strict_floor]</code> and
    /// <code>FixedU32::[strict\_floor][FixedU32::strict_floor]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the result does not fit.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let two_half = Strict(I16F16::from_num(5) / 2);
    /// assert_eq!(two_half.floor(), Strict(I16F16::from_num(2)));
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I0F32;
    /// use fixed::Strict;
    /// let _overflow = Strict(I0F32::MIN).floor();
    /// ```
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn floor(self) -> Strict<F> {
        Strict(self.0.strict_floor())
    }

    /// Strict round. Rounds to the next integer to the nearest,
    /// with ties rounded away from zero, and panics on overflow.
    ///
    /// See also
    /// <code>FixedI32::[strict\_round][FixedI32::strict_round]</code> and
    /// <code>FixedU32::[strict\_round][FixedU32::strict_round]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the result does not fit.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let two_half = Strict(I16F16::from_num(5) / 2);
    /// assert_eq!(two_half.round(), Strict(I16F16::from_num(3)));
    /// assert_eq!((-two_half).round(), Strict(I16F16::from_num(-3)));
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let _overflow = Strict(I16F16::MAX).round();
    /// ```
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn round(self) -> Strict<F> {
        Strict(self.0.strict_round())
    }

    /// Strict round. Rounds to the next integer to the nearest, with ties
    /// rounded to even, and panics on overflow.
    ///
    /// See also
    /// <code>FixedI32::[strict\_round\_ties\_even][FixedI32::strict_round_ties_even]</code>
    /// and
    /// <code>FixedU32::[strict\_round\_ties\_even][FixedU32::strict_round_ties_even]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the result does not fit.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let two_half = Strict(I16F16::from_num(2.5));
    /// assert_eq!(two_half.round_ties_even(), Strict(I16F16::from_num(2)));
    /// let three_half = Strict(I16F16::from_num(3.5));
    /// assert_eq!(three_half.round_ties_even(), Strict(I16F16::from_num(4)));
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let max = Strict(I16F16::MAX);
    /// let _overflow = max.round_ties_even();
    /// ```
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn round_ties_even(self) -> Strict<F> {
        Strict(self.0.strict_round_ties_even())
    }

    /// Returns the number of ones in the binary representation.
    ///
    /// See also <code>FixedI32::[count\_ones][FixedI32::count_ones]</code> and
    /// <code>FixedU32::[count\_ones][FixedU32::count_ones]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let s = Strict(I16F16::from_bits(0x00FF_FF00));
    /// assert_eq!(s.count_ones(), s.0.count_ones());
    /// ```
    #[inline]
    #[doc(alias("popcount", "popcnt"))]
    pub fn count_ones(self) -> u32 {
        self.0.count_ones()
    }

    /// Returns the number of zeros in the binary representation.
    ///
    /// See also <code>FixedI32::[count\_zeros][FixedI32::count_zeros]</code>
    /// and <code>FixedU32::[count\_zeros][FixedU32::count_zeros]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let s = Strict(I16F16::from_bits(0x00FF_FF00));
    /// assert_eq!(s.count_zeros(), s.0.count_zeros());
    /// ```
    #[inline]
    pub fn count_zeros(self) -> u32 {
        self.0.count_zeros()
    }

    /// Returns the number of leading ones in the binary representation.
    ///
    /// See also <code>FixedI32::[leading\_ones][FixedI32::leading_ones]</code>
    /// and <code>FixedU32::[leading\_ones][FixedU32::leading_ones]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::U16F16;
    /// use fixed::Strict;
    /// let s = Strict(U16F16::from_bits(0xFF00_00FF));
    /// assert_eq!(s.leading_ones(), s.0.leading_ones());
    /// ```
    #[inline]
    pub fn leading_ones(self) -> u32 {
        self.0.leading_ones()
    }

    /// Returns the number of leading zeros in the binary representation.
    ///
    /// See also
    /// <code>FixedI32::[leading\_zeros][FixedI32::leading_zeros]</code> and
    /// <code>FixedU32::[leading\_zeros][FixedU32::leading_zeros]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let s = Strict(I16F16::from_bits(0x00FF_FF00));
    /// assert_eq!(s.leading_zeros(), s.0.leading_zeros());
    /// ```
    #[inline]
    pub fn leading_zeros(self) -> u32 {
        self.0.leading_zeros()
    }

    /// Returns the number of trailing ones in the binary representation.
    ///
    /// See also
    /// <code>FixedI32::[trailing\_ones][FixedI32::trailing_ones]</code> and
    /// <code>FixedU32::[trailing\_ones][FixedU32::trailing_ones]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::U16F16;
    /// use fixed::Strict;
    /// let s = Strict(U16F16::from_bits(0xFF00_00FF));
    /// assert_eq!(s.trailing_ones(), s.0.trailing_ones());
    /// ```
    #[inline]
    pub fn trailing_ones(self) -> u32 {
        self.0.trailing_ones()
    }

    /// Returns the number of trailing zeros in the binary representation.
    ///
    /// See also
    /// <code>FixedI32::[trailing\_zeros][FixedI32::trailing_zeros]</code> and
    /// <code>FixedU32::[trailing\_zeros][FixedU32::trailing_zeros]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let s = Strict(I16F16::from_bits(0x00FF_FF00));
    /// assert_eq!(s.trailing_zeros(), s.0.trailing_zeros());
    /// ```
    #[inline]
    pub fn trailing_zeros(self) -> u32 {
        self.0.trailing_zeros()
    }

    /// Returns the square root.
    ///
    /// See also
    /// <code>FixedI32::[strict\_sqrt][FixedI32::strict_sqrt]</code> and
    /// <code>FixedU32::[strict\_sqrt][FixedU32::strict_sqrt]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the number is negative, or on overflow.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I0F32;
    /// use fixed::Strict;
    /// assert_eq!(Strict(I0F32::lit("0b0.0001")).sqrt().0, I0F32::lit("0b0.01"));
    /// ```
    ///
    /// The following panics because the input value is negative.
    ///
    /// ```should_panic
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let neg = Strict(I16F16::from_num(-1));
    /// let _sqrt_neg = neg.sqrt();
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I0F32;
    /// use fixed::Strict;
    /// let u = Strict(I0F32::from_num(0.25));
    /// let _overflow = u.sqrt();
    /// ```
    #[inline]
    #[track_caller]
    pub fn sqrt(self) -> Self {
        Strict(self.0.strict_sqrt())
    }

    /// Integer base-2 logarithm, rounded down.
    ///
    /// See also <code>FixedI32::[int\_log2][FixedI32::int_log2]</code> and
    /// <code>FixedU32::[int\_log2][FixedU32::int_log2]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the fixed-point number is ≤&nbsp;0.
    #[inline]
    #[track_caller]
    #[doc(alias("ilog2"))]
    pub fn int_log2(self) -> i32 {
        self.0.int_log2()
    }

    /// Integer base-10 logarithm, rounded down.
    ///
    /// See also <code>FixedI32::[int\_log10][FixedI32::int_log10]</code> and
    /// <code>FixedU32::[int\_log10][FixedU32::int_log10]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the fixed-point number is ≤&nbsp;0.
    #[inline]
    #[track_caller]
    #[doc(alias("ilog10"))]
    pub fn int_log10(self) -> i32 {
        self.0.int_log10()
    }

    /// Integer logarithm to the specified base, rounded down.
    ///
    /// See also <code>FixedI32::[int\_log][FixedI32::int_log]</code> and
    /// <code>FixedU32::[int\_log][FixedU32::int_log]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the fixed-point number is ≤&nbsp;0 or if the base is <&nbsp;2.
    #[inline]
    #[track_caller]
    #[doc(alias("ilog"))]
    pub fn int_log(self, base: u32) -> i32 {
        self.0.int_log(base)
    }

    /// Reverses the order of the bits of the fixed-point number.
    ///
    /// See also <code>FixedI32::[reverse\_bits][FixedI32::reverse_bits]</code>
    /// and <code>FixedU32::[reverse\_bits][FixedU32::reverse_bits]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let i = I16F16::from_bits(0x1234_5678);
    /// assert_eq!(Strict(i).reverse_bits(), Strict(i.reverse_bits()));
    /// ```
    #[inline]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn reverse_bits(self) -> Strict<F> {
        Strict(self.0.reverse_bits())
    }

    /// Shifts to the left by `n` bits, strict the truncated bits to the right end.
    ///
    /// See also <code>FixedI32::[rotate\_left][FixedI32::rotate_left]</code>
    /// and <code>FixedU32::[rotate\_left][FixedU32::rotate_left]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let i = I16F16::from_bits(0x00FF_FF00);
    /// assert_eq!(Strict(i).rotate_left(12), Strict(i.rotate_left(12)));
    /// ```
    #[inline]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn rotate_left(self, n: u32) -> Strict<F> {
        Strict(self.0.rotate_left(n))
    }

    /// Shifts to the right by `n` bits, strict the truncated bits to the left end.
    ///
    /// See also <code>FixedI32::[rotate\_right][FixedI32::rotate_right]</code>
    /// and <code>FixedU32::[rotate\_right][FixedU32::rotate_right]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let i = I16F16::from_bits(0x00FF_FF00);
    /// assert_eq!(Strict(i).rotate_right(12), Strict(i.rotate_right(12)));
    /// ```
    #[inline]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn rotate_right(self, n: u32) -> Strict<F> {
        Strict(self.0.rotate_right(n))
    }

    /// Returns [`true`] if the number is zero.
    ///
    /// See also <code>FixedI32::[is\_zero][FixedI32::is_zero]</code> and
    /// <code>FixedU32::[is\_zero][FixedU32::is_zero]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// assert!(Strict(I16F16::ZERO).is_zero());
    /// assert!(!Strict(I16F16::from_num(4.3)).is_zero());
    /// ```
    #[inline]
    pub fn is_zero(self) -> bool {
        self.0.is_zero()
    }

    /// Returns the distance from `self` to `other`.
    ///
    /// See also
    /// <code>FixedI32::[strict\_dist][FixedI32::strict_dist]</code> and
    /// <code>FixedU32::[strict\_dist][FixedU32::strict_dist]</code>.
    ///
    /// # Panics
    ///
    /// Panics on overflow.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// type St = Strict<I16F16>;
    /// assert_eq!(St::from_num(-1).dist(St::from_num(4)), St::from_num(5));
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// type St = Strict<I16F16>;
    /// let _overflow = St::MIN.dist(St::ZERO);
    /// ```
    #[inline]
    #[track_caller]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn dist(self, other: Strict<F>) -> Strict<F> {
        Strict(self.0.strict_dist(other.0))
    }

    /// Returns the mean of `self` and `other`.
    ///
    /// See also <code>FixedI32::[mean][FixedI32::mean]</code> and
    /// <code>FixedU32::[mean][FixedU32::mean]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let three = Strict(I16F16::from_num(3));
    /// let four = Strict(I16F16::from_num(4));
    /// assert_eq!(three.mean(four), Strict(I16F16::from_num(3.5)));
    /// assert_eq!(three.mean(-four), Strict(I16F16::from_num(-0.5)));
    /// ```
    #[inline]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn mean(self, other: Strict<F>) -> Strict<F> {
        Strict(self.0.mean(other.0))
    }

    /// Compute the hypotenuse of a right triange.
    ///
    /// See also
    /// <code>FixedI32::[strict\_hypot][FixedI32::strict_hypot]</code> and
    /// <code>FixedU32::[strict\_hypot][FixedU32::strict_hypot]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// type St = Strict<I8F8>;
    /// // hypot(3, 4) == 5
    /// assert_eq!(St::from_num(3).hypot(St::from_num(4)), St::from_num(5));
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// type St = Strict<I8F8>;
    /// // hypot(88, 105) == 137, which does not fit
    /// let _overflow = St::from_num(88).hypot(St::from_num(105));
    /// ```
    #[inline]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn hypot(self, other: Strict<F>) -> Strict<F> {
        Strict(self.0.strict_hypot(other.0))
    }

    /// Returns the reciprocal (inverse), 1/`self`.
    ///
    /// See also
    /// <code>FixedI32::[strict\_recip][FixedI32::strict_recip]</code> and
    /// <code>FixedU32::[strict\_recip][FixedU32::strict_recip]</code>.
    ///
    /// # Panics
    ///
    /// Panics if `self` is zero or on overflow.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I8F24;
    /// use fixed::Strict;
    /// let quarter = Strict(I8F24::from_num(0.25));
    /// assert_eq!(quarter.recip(), Strict(I8F24::from_num(4)));
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I8F24;
    /// use fixed::Strict;
    /// let frac_1_512 = Strict(I8F24::ONE / 512);
    /// let _overflow = frac_1_512.recip();
    /// ```
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn recip(self) -> Strict<F> {
        Strict(self.0.strict_recip())
    }

    /// Returns the next multiple of `other`.
    ///
    /// See also
    /// <code>FixedI32::[strict\_next\_multiple\_of][FixedI32::strict_next_multiple_of]</code>
    /// and
    /// <code>FixedU32::[strict\_next\_multiple\_of][FixedU32::strict_next_multiple_of]</code>.
    ///
    /// # Panics
    ///
    /// Panics if `other` is zero or on overflow.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let one_point_5 = Strict::<I16F16>::from_num(1.5);
    /// let four = Strict::<I16F16>::from_num(4);
    /// let four_point_5 = Strict::<I16F16>::from_num(4.5);
    /// assert_eq!(four.next_multiple_of(one_point_5), four_point_5);
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```rust,should_panic
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let two = Strict::<I16F16>::from_num(2);
    /// let max = Strict::<I16F16>::MAX;
    /// let _overflow = max.next_multiple_of(two);
    /// ```
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn next_multiple_of(self, other: Strict<F>) -> Strict<F> {
        Strict(self.0.strict_next_multiple_of(other.0))
    }

    /// Multiply and add. Returns `self` × `mul` + `add`.
    ///
    /// See also
    /// <code>FixedI32::[strict\_mul\_add][FixedI32::strict_mul_add]</code>
    /// and
    /// <code>FixedU32::[strict\_mul\_add][FixedU32::strict_mul_add]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the result does not fit.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let half = Strict(I16F16::from_num(0.5));
    /// let three = Strict(I16F16::from_num(3));
    /// let four = Strict(I16F16::from_num(4));
    /// assert_eq!(three.mul_add(half, four), Strict(I16F16::from_num(5.5)));
    /// // max × 1.5 - max = max / 2, which does not overflow
    /// let max = Strict(I16F16::MAX);
    /// assert_eq!(max.mul_add(Strict(I16F16::from_num(1.5)), -max), max / 2);
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let one = Strict(I16F16::ONE);
    /// let max = Strict(I16F16::MAX);
    /// let _overflow = max.mul_add(one, one);
    /// ```
    #[inline]
    #[track_caller]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn mul_add(self, mul: Strict<F>, add: Strict<F>) -> Strict<F> {
        Strict(self.0.strict_mul_add(mul.0, add.0))
    }

    /// Adds `self` to the product `a`&nbsp;×&nbsp;`b`.
    ///
    /// See also
    /// <code>FixedI32::[strict\_add\_prod][FixedI32::strict_add_prod]</code>
    /// and
    /// <code>FixedU32::[strict\_add\_prod][FixedU32::strict_add_prod]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the result does not fit.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let half = Strict(I16F16::from_num(0.5));
    /// let three = Strict(I16F16::from_num(3));
    /// let four = Strict(I16F16::from_num(4));
    /// assert_eq!(three.add_prod(four, half), Strict(I16F16::from_num(5)));
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let max = Strict(I16F16::MAX);
    /// let _overflow = max.add_prod(max, Strict(I16F16::from_num(3)));
    /// ```
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn add_prod(self, a: Strict<F>, b: Strict<F>) -> Strict<F> {
        Strict(self.0.strict_add_prod(a.0, b.0))
    }

    /// Multiply and accumulate. Adds (`a` × `b`) to `self`.
    ///
    /// See also
    /// <code>FixedI32::[strict\_mul\_acc][FixedI32::strict_mul_acc]</code>
    /// and
    /// <code>FixedU32::[strict\_mul\_acc][FixedU32::strict_mul_acc]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the result does not fit.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let mut acc = Strict(I16F16::from_num(3));
    /// acc.mul_acc(Strict(I16F16::from_num(4)), Strict(I16F16::from_num(0.5)));
    /// assert_eq!(acc, Strict(I16F16::from_num(5)));
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let mut acc = Strict(I16F16::MAX);
    /// acc.mul_acc(Strict(I16F16::MAX), Strict(I16F16::from_num(3)));
    /// ```
    #[inline]
    #[track_caller]
    pub fn mul_acc(&mut self, a: Strict<F>, b: Strict<F>) {
        self.0.strict_mul_acc(a.0, b.0);
    }

    /// Euclidean division.
    ///
    /// See also
    /// <code>FixedI32::[strict\_div\_euclid][FixedI32::strict_div_euclid]</code>
    /// and
    /// <code>FixedU32::[strict\_div\_euclid][FixedU32::strict_div_euclid]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the divisor is zero, or if the division results in overflow.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let num = Strict(I16F16::from_num(7.5));
    /// let den = Strict(I16F16::from_num(2));
    /// assert_eq!(num.div_euclid(den), Strict(I16F16::from_num(3)));
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let quarter = Strict(I16F16::from_num(0.25));
    /// let _overflow = Strict(I16F16::MAX).div_euclid(quarter);
    /// ```
    #[inline]
    #[track_caller]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn div_euclid(self, divisor: Strict<F>) -> Strict<F> {
        Strict(self.0.strict_div_euclid(divisor.0))
    }

    /// Remainder for Euclidean division.
    ///
    /// See also
    /// <code>FixedI32::[strict\_rem\_euclid][FixedI32::strict_rem_euclid]</code>
    /// and
    /// <code>FixedU32::[strict\_rem\_euclid][FixedU32::strict_rem_euclid]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the divisor is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let num = Strict(I16F16::from_num(7.5));
    /// let den = Strict(I16F16::from_num(2));
    /// assert_eq!(num.rem_euclid(den), Strict(I16F16::from_num(1.5)));
    /// assert_eq!((-num).rem_euclid(den), Strict(I16F16::from_num(0.5)));
    /// ```
    #[inline]
    #[track_caller]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn rem_euclid(self, divisor: Strict<F>) -> Strict<F> {
        Strict(self.0.strict_rem_euclid(divisor.0))
    }

    /// Euclidean division by an integer.
    ///
    /// See also
    /// <code>FixedI32::[strict\_div\_euclid\_int][FixedI32::strict_div_euclid_int]</code>
    /// and
    /// <code>FixedU32::[strict\_div\_euclid\_int][FixedU32::strict_div_euclid_int]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the divisor is zero or if the division results in overflow.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let num = Strict(I16F16::from_num(7.5));
    /// assert_eq!(num.div_euclid_int(2), Strict(I16F16::from_num(3)));
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let min = Strict(I16F16::MIN);
    /// let _overflow = min.div_euclid_int(-1);
    /// ```
    #[inline]
    #[track_caller]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn div_euclid_int(self, divisor: F::Bits) -> Strict<F> {
        Strict(self.0.strict_div_euclid_int(divisor))
    }

    /// Remainder for Euclidean division.
    ///
    /// See also
    /// <code>FixedI32::[strict\_rem\_euclid\_int][FixedI32::strict_rem_euclid_int]</code>
    /// and
    /// <code>FixedU32::[strict\_rem\_euclid\_int][FixedU32::strict_rem_euclid_int]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the divisor is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let num = Strict(I16F16::from_num(7.5));
    /// assert_eq!(num.rem_euclid_int(2), Strict(I16F16::from_num(1.5)));
    /// assert_eq!((-num).rem_euclid_int(2), Strict(I16F16::from_num(0.5)));
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I8F8;
    /// use fixed::Strict;
    /// let num = Strict(I8F8::from_num(-7.5));
    /// // -128 ≤ Fix < 128, so the answer 192.5 overflows
    /// let _overflow = num.rem_euclid_int(200);
    /// ```
    #[inline]
    #[track_caller]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn rem_euclid_int(self, divisor: F::Bits) -> Strict<F> {
        Strict(self.0.strict_rem_euclid_int(divisor))
    }

    /// Unbounded shift left. Computes `self << rhs`, without bounding the value
    /// of `rhs`.
    ///
    /// See also
    /// <code>FixedI32::[unbounded\_shl][FixedI32::unbounded_shl]</code> and
    /// <code>FixedU32::[unbounded\_shl][FixedU32::unbounded_shl]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// type St = Strict<I16F16>;
    /// let num = Strict(I16F16::from_num(1.5));
    /// assert_eq!(num.unbounded_shl(5), num << 5);
    /// assert_eq!(num.unbounded_shl(32), St::ZERO);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn unbounded_shl(self, rhs: u32) -> Strict<F> {
        Strict(self.0.unbounded_shl(rhs))
    }

    /// Unbounded shift right. Computes `self >> rhs`, without bounding the
    /// value of `rhs`.
    ///
    /// See also
    /// <code>FixedI32::[unbounded\_shr][FixedI32::unbounded_shr]</code> and
    /// <code>FixedU32::[unbounded\_shr][FixedU32::unbounded_shr]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// type St = Strict<I16F16>;
    /// let num = Strict(I16F16::from_num(1.5));
    /// assert_eq!(num.unbounded_shr(5), num >> 5);
    /// assert_eq!(num.unbounded_shr(32), St::ZERO);
    /// assert_eq!((-num).unbounded_shr(5), (-num) >> 5);
    /// assert_eq!((-num).unbounded_shr(32), -St::DELTA);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn unbounded_shr(self, rhs: u32) -> Strict<F> {
        Strict(self.0.unbounded_shr(rhs))
    }

    /// Linear interpolation between `start` and `end`.
    ///
    /// See also
    /// <code>FixedI32::[strict\_lerp][FixedI32::strict_lerp]</code> and
    /// <code>FixedU32::[strict\_lerp][FixedU32::strict_lerp]</code>.
    ///
    /// # Panics
    ///
    /// Panics on overflow.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// type St = Strict<I16F16>;
    /// assert_eq!(St::from_num(0.5).lerp(St::ZERO, St::MAX), St::MAX / 2);
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// type St = Strict<I16F16>;
    /// let _overflow = St::from_num(1.5).lerp(St::ZERO, St::MAX);
    /// ```
    #[inline]
    #[track_caller]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn lerp(self, start: Strict<F>, end: Strict<F>) -> Strict<F> {
        Strict(self.0.strict_lerp(start.0, end.0))
    }

    /// Inverse linear interpolation between `start` and `end`.
    ///
    /// See also
    /// <code>FixedI32::[strict\_inv\_lerp][FixedI32::strict_inv_lerp]</code> and
    /// <code>FixedU32::[strict\_inv\_lerp][FixedU32::strict_inv_lerp]</code>.
    ///
    /// # Panics
    ///
    /// Panics when `start`&nbsp;=&nbsp;`end` or when the results overflows.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// type St = Strict<I16F16>;
    /// assert_eq!(
    ///     St::from_num(25).inv_lerp(St::from_num(20), St::from_num(40)),
    ///     St::from_num(0.25)
    /// );
    /// ```
    ///
    /// The following panics because `start`&nbsp;=&nbsp;`end`.
    ///
    /// ```should_panic
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// type St = Strict<I16F16>;
    /// let two = St::from_num(2);
    /// let _zero_range = two.inv_lerp(two, two);
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// type St = Strict<I16F16>;
    /// let _overflow = St::MAX.inv_lerp(St::ZERO, St::from_num(0.5));
    /// ```
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn inv_lerp(self, start: Strict<F>, end: Strict<F>) -> Strict<F> {
        Strict(self.0.strict_inv_lerp(start.0, end.0))
    }

    /// Strict round. Rounds to the next integer to the nearest, with ties
    /// rounded to even, and panics on overflow.
    ///
    /// # Panics
    ///
    /// Panics if the result does not fit.
    #[inline]
    #[track_caller]
    #[must_use]
    #[deprecated(since = "1.28.0", note = "renamed to `round_ties_even`")]
    pub fn round_ties_to_even(self) -> Strict<F> {
        self.round_ties_even()
    }
}

impl<F: FixedSigned> Strict<F> {
    /// Returns the bit pattern of `self` reinterpreted as an unsigned
    /// fixed-point number of the same size.
    ///
    /// See also <code>FixedI32::[cast\_unsigned][FixedU32::cast_unsigned]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::{I16F16, U16F16};
    /// use fixed::Strict;
    ///
    /// let n = Strict(-I16F16::DELTA);
    /// assert_eq!(n.cast_unsigned(), Strict(U16F16::MAX));
    /// ```
    #[must_use]
    #[inline]
    pub fn cast_unsigned(self) -> Strict<F::Unsigned> {
        Strict(self.0.cast_unsigned())
    }

    /// Returns the number of bits required to represent the value.
    ///
    /// The number of bits required includes an initial one for
    /// negative numbers, and an initial zero for non-negative
    /// numbers.
    ///
    /// See also <code>FixedI32::[signed\_bits][FixedI32::signed_bits]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I4F4;
    /// use fixed::Strict;
    /// assert_eq!(Strict(I4F4::from_num(-3)).signed_bits(), 7);      // “_101.0000”
    /// assert_eq!(Strict(I4F4::from_num(-1)).signed_bits(), 5);      // “___1.0000”
    /// assert_eq!(Strict(I4F4::from_num(-0.0625)).signed_bits(), 1); // “____.___1”
    /// assert_eq!(Strict(I4F4::from_num(0)).signed_bits(), 1);       // “____.___0”
    /// assert_eq!(Strict(I4F4::from_num(0.0625)).signed_bits(), 2);  // “____.__01”
    /// assert_eq!(Strict(I4F4::from_num(1)).signed_bits(), 6);       // “__01.0000”
    /// assert_eq!(Strict(I4F4::from_num(3)).signed_bits(), 7);       // “_011.0000”
    /// ```
    #[inline]
    pub fn signed_bits(self) -> u32 {
        self.0.signed_bits()
    }

    /// Returns [`true`] if the number is >&nbsp;0.
    ///
    /// See also <code>FixedI32::[is\_positive][FixedI32::is_positive]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// assert!(Strict(I16F16::from_num(4.3)).is_positive());
    /// assert!(!Strict(I16F16::ZERO).is_positive());
    /// assert!(!Strict(I16F16::from_num(-4.3)).is_positive());
    /// ```
    #[inline]
    pub fn is_positive(self) -> bool {
        self.0.is_positive()
    }

    /// Returns [`true`] if the number is <&nbsp;0.
    ///
    /// See also <code>FixedI32::[is\_negative][FixedI32::is_negative]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// assert!(!Strict(I16F16::from_num(4.3)).is_negative());
    /// assert!(!Strict(I16F16::ZERO).is_negative());
    /// assert!(Strict(I16F16::from_num(-4.3)).is_negative());
    /// ```
    #[inline]
    pub fn is_negative(self) -> bool {
        self.0.is_negative()
    }

    /// Strict absolute value. Returns the absolute value, panicking
    /// on overflow.
    ///
    /// Overflow can only occur when trying to find the absolute value
    /// of the minimum value.
    ///
    /// See also
    /// <code>FixedI32::[strict\_abs][FixedI32::strict_abs]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the result does not fit.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// assert_eq!(Strict(I16F16::from_num(-5)).abs(), Strict(I16F16::from_num(5)));
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// let _overflow = Strict(I16F16::MIN).abs();
    /// ```
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn abs(self) -> Strict<F> {
        Strict(self.0.strict_abs())
    }

    /// Returns a number representing the sign of `self`.
    ///
    /// See also
    /// <code>FixedI32::[strict\_signum][FixedI32::strict_signum]</code>.
    ///
    /// # Panics
    ///
    /// Panics
    ///   * if the value is positive and the fixed-point number has zero
    ///     or one integer bits such that it cannot hold the value 1.
    ///   * if the value is negative and the fixed-point number has zero
    ///     integer bits, such that it cannot hold the value &minus;1.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::I16F16;
    /// use fixed::Strict;
    /// assert_eq!(Strict(<I16F16>::from_num(-3.9)).signum(), Strict(I16F16::NEG_ONE));
    /// assert_eq!(Strict(<I16F16>::ZERO).signum(), Strict(I16F16::ZERO));
    /// assert_eq!(Strict(<I16F16>::from_num(3.9)).signum(), Strict(I16F16::ONE));
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::I1F31;
    /// use fixed::Strict;
    /// let _overflow = Strict(<I1F31>::from_num(0.5)).signum();
    /// ```
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn signum(self) -> Strict<F> {
        Strict(self.0.strict_signum())
    }

    /// Addition with an unsigned fixed-point number.
    ///
    /// See also
    /// <code>FixedI32::[strict\_add\_unsigned][FixedI32::strict_add_unsigned]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the result does not fit.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::{I16F16, U16F16};
    /// use fixed::Strict;
    /// assert_eq!(
    ///     Strict::<I16F16>::from_num(-5).add_unsigned(U16F16::from_num(3)),
    ///     Strict::<I16F16>::from_num(-2)
    /// );
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```rust,should_panic
    /// use fixed::types::{I16F16, U16F16};
    /// use fixed::Strict;
    /// let _overflow = Strict::<I16F16>::ZERO.add_unsigned(U16F16::MAX);
    /// ```
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn add_unsigned(self, rhs: F::Unsigned) -> Strict<F> {
        Strict(self.0.strict_add_unsigned(rhs))
    }

    /// Subtraction with an unsigned fixed-point number.
    ///
    /// See also
    /// <code>FixedI32::[strict\_sub\_unsigned][FixedI32::strict_sub_unsigned]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the result does not fit.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::{I16F16, U16F16};
    /// use fixed::Strict;
    /// assert_eq!(
    ///     Strict::<I16F16>::from_num(3).sub_unsigned(U16F16::from_num(5)),
    ///     Strict::<I16F16>::from_num(-2)
    /// );
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```rust,should_panic
    /// use fixed::types::{I16F16, U16F16};
    /// use fixed::Strict;
    /// let _overflow = Strict::<I16F16>::ZERO.sub_unsigned(U16F16::MAX);
    /// ```
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn sub_unsigned(self, rhs: F::Unsigned) -> Strict<F> {
        Strict(self.0.strict_sub_unsigned(rhs))
    }
}

impl<F: FixedUnsigned> Strict<F> {
    /// Returns the bit pattern of `self` reinterpreted as a signed fixed-point
    /// number of the same size.
    ///
    /// See also <code>FixedU32::[cast\_signed][FixedU32::cast_signed]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::{I16F16, U16F16};
    /// use fixed::Strict;
    ///
    /// let n = Strict(U16F16::MAX);
    /// assert_eq!(n.cast_signed(), Strict(-I16F16::DELTA));
    /// ```
    #[must_use]
    #[inline]
    pub fn cast_signed(self) -> Strict<F::Signed> {
        Strict(self.0.cast_signed())
    }

    /// Returns the number of bits required to represent the value.
    ///
    /// See also
    /// <code>FixedU32::[significant\_bits][FixedU32::significant_bits]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::U4F4;
    /// use fixed::Strict;
    /// assert_eq!(Strict(U4F4::from_num(0)).significant_bits(), 0);      // “____.____”
    /// assert_eq!(Strict(U4F4::from_num(0.0625)).significant_bits(), 1); // “____.___1”
    /// assert_eq!(Strict(U4F4::from_num(1)).significant_bits(), 5);      // “___1.0000”
    /// assert_eq!(Strict(U4F4::from_num(3)).significant_bits(), 6);      // “__11.0000”
    /// ```
    #[inline]
    pub fn significant_bits(self) -> u32 {
        self.0.significant_bits()
    }

    /// Returns [`true`] if the fixed-point number is
    /// 2<sup><i>k</i></sup> for some integer <i>k</i>.
    ///
    /// See also
    /// <code>FixedU32::[is\_power\_of\_two][FixedU32::is_power_of_two]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::U16F16;
    /// use fixed::Strict;
    /// assert!(Strict(U16F16::from_num(0.5)).is_power_of_two());
    /// assert!(Strict(U16F16::from_num(4)).is_power_of_two());
    /// assert!(!Strict(U16F16::from_num(5)).is_power_of_two());
    /// ```
    #[inline]
    pub fn is_power_of_two(self) -> bool {
        self.0.is_power_of_two()
    }

    /// Returns the highest one in the binary representation, or zero
    /// if `self` is zero.
    ///
    /// If `self`&nbsp;>&nbsp;0, the highest one is equal to the largest power
    /// of two that is ≤&nbsp;`self`.
    ///
    /// See also <code>FixedU32::[highest\_one][FixedU32::highest_one]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::U16F16;
    /// use fixed::Strict;
    /// type T = Strict<U16F16>;
    /// assert_eq!(T::from_bits(0b11_0010).highest_one(), T::from_bits(0b10_0000));
    /// assert_eq!(T::from_num(0.3).highest_one(), T::from_num(0.25));
    /// assert_eq!(T::from_num(4).highest_one(), T::from_num(4));
    /// assert_eq!(T::from_num(6.5).highest_one(), T::from_num(4));
    /// assert_eq!(T::ZERO.highest_one(), T::ZERO);
    /// ```
    #[inline]
    #[must_use]
    pub fn highest_one(self) -> Strict<F> {
        Strict(self.0.highest_one())
    }

    /// Returns the smallest power of two that is ≥&nbsp;`self`.
    ///
    /// See also
    /// <code>FixedU32::[strict\_next\_power\_of\_two][FixedU32::strict_next_power_of_two]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the next power of two is too large to fit.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::U16F16;
    /// use fixed::Strict;
    /// type T = Strict<U16F16>;
    /// assert_eq!(T::from_bits(0b11_0010).next_power_of_two(), T::from_bits(0b100_0000));
    /// assert_eq!(T::from_num(0.3).next_power_of_two(), T::from_num(0.5));
    /// assert_eq!(T::from_num(4).next_power_of_two(), T::from_num(4));
    /// assert_eq!(T::from_num(6.5).next_power_of_two(), T::from_num(8));
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```should_panic
    /// use fixed::types::U16F16;
    /// use fixed::Strict;
    /// let _overflow = Strict(U16F16::MAX).next_power_of_two();
    /// ```
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn next_power_of_two(self) -> Strict<F> {
        Strict(self.0.strict_next_power_of_two())
    }

    /// Addition with an signed fixed-point number.
    ///
    /// See also
    /// <code>FixedU32::[strict\_add\_signed][FixedU32::strict_add_signed]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the result does not fit.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::{I16F16, U16F16};
    /// use fixed::Strict;
    /// assert_eq!(
    ///     Strict::<U16F16>::from_num(5).add_signed(I16F16::from_num(-3)),
    ///     Strict::<U16F16>::from_num(2)
    /// );
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```rust,should_panic
    /// use fixed::types::{I16F16, U16F16};
    /// use fixed::Strict;
    /// let _overflow = Strict::<U16F16>::ZERO.add_signed(-I16F16::DELTA);
    /// ```
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn add_signed(self, rhs: F::Signed) -> Strict<F> {
        Strict(self.0.strict_add_signed(rhs))
    }

    /// Subtraction with an signed fixed-point number.
    ///
    /// See also
    /// <code>FixedU32::[strict\_sub\_signed][FixedU32::strict_sub_signed]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the result does not fit.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fixed::types::{I16F16, U16F16};
    /// use fixed::Strict;
    /// assert_eq!(
    ///     Strict::<U16F16>::from_num(5).sub_signed(I16F16::from_num(-3)),
    ///     Strict::<U16F16>::from_num(8)
    /// );
    /// ```
    ///
    /// The following panics because of overflow.
    ///
    /// ```rust,should_panic
    /// use fixed::types::{I16F16, U16F16};
    /// use fixed::Strict;
    /// let _overflow = Strict::<U16F16>::ZERO.sub_signed(I16F16::DELTA);
    /// ```
    #[inline]
    #[track_caller]
    #[must_use]
    pub fn sub_signed(self, rhs: F::Signed) -> Strict<F> {
        Strict(self.0.strict_sub_signed(rhs))
    }
}

impl<F: Fixed> Display for Strict<F> {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        Display::fmt(&self.0, f)
    }
}

impl<F: Fixed> Debug for Strict<F> {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        Debug::fmt(&self.0, f)
    }
}

impl<F: Fixed> Binary for Strict<F> {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        Binary::fmt(&self.0, f)
    }
}

impl<F: Fixed> Octal for Strict<F> {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        Octal::fmt(&self.0, f)
    }
}

impl<F: Fixed> LowerHex for Strict<F> {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        LowerHex::fmt(&self.0, f)
    }
}

impl<F: Fixed> UpperHex for Strict<F> {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        UpperHex::fmt(&self.0, f)
    }
}

impl<F: Fixed> LowerExp for Strict<F> {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        LowerExp::fmt(&self.0, f)
    }
}

impl<F: Fixed> UpperExp for Strict<F> {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        UpperExp::fmt(&self.0, f)
    }
}

impl<F: Fixed> From<F> for Strict<F> {
    /// Wraps a fixed-point number.
    #[inline]
    fn from(src: F) -> Strict<F> {
        Strict(src)
    }
}

impl<F: Fixed> FromStr for Strict<F> {
    type Err = ParseFixedError;
    /// Parses a string slice containing decimal digits to return a fixed-point number.
    ///
    /// Rounding is to the nearest, with ties rounded to even.
    ///
    /// This method either returns [`Ok`] or panics, and never returns [`Err`].
    /// The inherent method
    /// <code>[Strict]&lt;F>::[from\_str\_dec][Strict::from_str_dec]</code>
    /// returns the value directly instead of a [`Result`].
    ///
    /// # Panics
    ///
    /// Panics if the value does not fit or if there is a parsing error.
    #[inline]
    #[track_caller]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Strict(F::strict_from_str(s)))
    }
}

macro_rules! op {
    ($strict:ident, $Op:ident $op:ident, $OpAssign:ident $op_assign:ident) => {
        impl<F: Fixed> $Op<Strict<F>> for Strict<F> {
            type Output = Strict<F>;
            #[inline]
            #[track_caller]
            fn $op(self, other: Strict<F>) -> Strict<F> {
                Strict((self.0).$strict(other.0))
            }
        }
        impl<F: Fixed> $Op<Strict<F>> for &Strict<F> {
            type Output = Strict<F>;
            #[inline]
            #[track_caller]
            fn $op(self, other: Strict<F>) -> Strict<F> {
                Strict((self.0).$strict(other.0))
            }
        }
        impl<F: Fixed> $Op<&Strict<F>> for Strict<F> {
            type Output = Strict<F>;
            #[inline]
            #[track_caller]
            fn $op(self, other: &Strict<F>) -> Strict<F> {
                Strict((self.0).$strict(other.0))
            }
        }
        impl<F: Fixed> $Op<&Strict<F>> for &Strict<F> {
            type Output = Strict<F>;
            #[inline]
            #[track_caller]
            fn $op(self, other: &Strict<F>) -> Strict<F> {
                Strict((self.0).$strict(other.0))
            }
        }
        impl<F: Fixed> $OpAssign<Strict<F>> for Strict<F> {
            #[inline]
            #[track_caller]
            fn $op_assign(&mut self, other: Strict<F>) {
                self.0 = (self.0).$strict(other.0);
            }
        }
        impl<F: Fixed> $OpAssign<&Strict<F>> for Strict<F> {
            #[inline]
            #[track_caller]
            fn $op_assign(&mut self, other: &Strict<F>) {
                self.0 = (self.0).$strict(other.0);
            }
        }
        impl<F: Fixed> $OpAssign<F> for Strict<F> {
            #[inline]
            #[track_caller]
            fn $op_assign(&mut self, other: F) {
                self.0 = (self.0).$strict(other);
            }
        }
        impl<F: Fixed> $OpAssign<&F> for Strict<F> {
            #[inline]
            #[track_caller]
            fn $op_assign(&mut self, other: &F) {
                self.0 = (self.0).$strict(*other);
            }
        }
    };
}

macro_rules! op_bitwise {
    ($Op:ident $op:ident, $OpAssign:ident $op_assign:ident) => {
        impl<F> $Op<Strict<F>> for Strict<F>
        where
            F: $Op<F, Output = F>,
        {
            type Output = Strict<F>;
            #[inline]
            fn $op(self, other: Strict<F>) -> Strict<F> {
                Strict((self.0).$op(other.0))
            }
        }
        impl<F> $Op<Strict<F>> for &Strict<F>
        where
            for<'a> &'a F: $Op<F, Output = F>,
        {
            type Output = Strict<F>;
            #[inline]
            fn $op(self, other: Strict<F>) -> Strict<F> {
                Strict((self.0).$op(other.0))
            }
        }
        impl<F> $Op<&Strict<F>> for Strict<F>
        where
            for<'a> F: $Op<&'a F, Output = F>,
        {
            type Output = Strict<F>;
            #[inline]
            fn $op(self, other: &Strict<F>) -> Strict<F> {
                Strict((self.0).$op(&other.0))
            }
        }
        impl<F> $Op<&Strict<F>> for &Strict<F>
        where
            for<'a, 'b> &'a F: $Op<&'b F, Output = F>,
        {
            type Output = Strict<F>;
            #[inline]
            fn $op(self, other: &Strict<F>) -> Strict<F> {
                Strict((self.0).$op(&other.0))
            }
        }
        impl<F> $OpAssign<Strict<F>> for Strict<F>
        where
            F: $OpAssign<F>,
        {
            #[inline]
            fn $op_assign(&mut self, other: Strict<F>) {
                (self.0).$op_assign(other.0);
            }
        }
        impl<F> $OpAssign<&Strict<F>> for Strict<F>
        where
            for<'a> F: $OpAssign<&'a F>,
        {
            #[inline]
            fn $op_assign(&mut self, other: &Strict<F>) {
                (self.0).$op_assign(&other.0);
            }
        }
        impl<F> $OpAssign<F> for Strict<F>
        where
            F: $OpAssign<F>,
        {
            #[inline]
            fn $op_assign(&mut self, other: F) {
                (self.0).$op_assign(other);
            }
        }
        impl<F> $OpAssign<&F> for Strict<F>
        where
            for<'a> F: $OpAssign<&'a F>,
        {
            #[inline]
            fn $op_assign(&mut self, other: &F) {
                (self.0).$op_assign(other);
            }
        }
    };
}

macro_rules! op_shift {
    (
        $Op:ident $op:ident, $OpAssign:ident $op_assign:ident;
        $($Rhs:ident),*
    ) => { $(
        impl<F> $Op<$Rhs> for Strict<F>
        where
            F: $Op<u32, Output = F>,
        {
            type Output = Strict<F>;
            #[inline]
            #[track_caller]
            fn $op(self, other: $Rhs) -> Strict<F> {
                let nbits = size_of::<F>() as u32 * 8;
                let checked = other as u32 % nbits;
                assert!(checked as $Rhs == other, "overflow");
                Strict((self.0).$op(checked))
            }
        }
        impl<F> $Op<$Rhs> for &Strict<F>
        where
            for<'a> &'a F: $Op<u32, Output = F>,
        {
            type Output = Strict<F>;
            #[inline]
            #[track_caller]
            fn $op(self, other: $Rhs) -> Strict<F> {
                let nbits = size_of::<F>() as u32 * 8;
                let checked = other as u32 % nbits;
                assert!(checked as $Rhs == other, "overflow");
                Strict((self.0).$op(checked))
            }
        }
        impl<F> $Op<&$Rhs> for Strict<F>
        where
            F: $Op<u32, Output = F>,
        {
            type Output = Strict<F>;
            #[inline]
            #[track_caller]
            fn $op(self, other: &$Rhs) -> Strict<F> {
                let nbits = size_of::<F>() as u32 * 8;
                let checked = *other as u32 % nbits;
                assert!(checked as $Rhs == *other, "overflow");
                Strict((self.0).$op(checked))
            }
        }
        impl<F> $Op<&$Rhs> for &Strict<F>
        where
            for<'a> &'a F: $Op<u32, Output = F>,
        {
            type Output = Strict<F>;
            #[inline]
            #[track_caller]
            fn $op(self, other: &$Rhs) -> Strict<F> {
                let nbits = size_of::<F>() as u32 * 8;
                let checked = *other as u32 % nbits;
                assert!(checked as $Rhs == *other, "overflow");
                Strict((self.0).$op(checked))
            }
        }
        impl<F> $OpAssign<$Rhs> for Strict<F>
        where
            F: $OpAssign<u32>,
        {
            #[inline]
            #[track_caller]
            fn $op_assign(&mut self, other: $Rhs) {
                let nbits = size_of::<F>() as u32 * 8;
                let checked = other as u32 % nbits;
                assert!(checked as $Rhs == other, "overflow");
                (self.0).$op_assign(checked);
            }
        }
        impl<F> $OpAssign<&$Rhs> for Strict<F>
        where
            F: $OpAssign<u32>,
        {
            #[inline]
            #[track_caller]
            fn $op_assign(&mut self, other: &$Rhs) {
                let nbits = size_of::<F>() as u32 * 8;
                let checked = *other as u32 % nbits;
                assert!(checked as $Rhs == *other, "overflow");
                (self.0).$op_assign(checked);
            }
        }
    )* };
}

impl<F: Fixed> Neg for Strict<F> {
    type Output = Strict<F>;
    #[inline]
    #[track_caller]
    fn neg(self) -> Strict<F> {
        Strict((self.0).strict_neg())
    }
}

impl<F: Fixed> Neg for &Strict<F> {
    type Output = Strict<F>;
    #[inline]
    #[track_caller]
    fn neg(self) -> Strict<F> {
        Strict((self.0).strict_neg())
    }
}
op! { strict_add, Add add, AddAssign add_assign }
op! { strict_sub, Sub sub, SubAssign sub_assign }
op! { strict_mul, Mul mul, MulAssign mul_assign }
op! { strict_div, Div div, DivAssign div_assign }
op! { strict_rem, Rem rem, RemAssign rem_assign }

impl<F> Not for Strict<F>
where
    F: Not<Output = F>,
{
    type Output = Strict<F>;
    #[inline]
    fn not(self) -> Strict<F> {
        Strict((self.0).not())
    }
}
impl<F> Not for &Strict<F>
where
    for<'a> &'a F: Not<Output = F>,
{
    type Output = Strict<F>;
    #[inline]
    fn not(self) -> Strict<F> {
        Strict((self.0).not())
    }
}
op_bitwise! { BitAnd bitand, BitAndAssign bitand_assign }
op_bitwise! { BitOr bitor, BitOrAssign bitor_assign }
op_bitwise! { BitXor bitxor, BitXorAssign bitxor_assign }

op_shift! {
    Shl shl, ShlAssign shl_assign;
    i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize
}
op_shift! {
    Shr shr, ShrAssign shr_assign;
    i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize
}

impl<F: Fixed> Sum<Strict<F>> for Strict<F> {
    #[track_caller]
    fn sum<I>(iter: I) -> Strict<F>
    where
        I: Iterator<Item = Strict<F>>,
    {
        iter.fold(Strict(F::ZERO), Add::add)
    }
}

impl<'a, F: 'a + Fixed> Sum<&'a Strict<F>> for Strict<F> {
    #[track_caller]
    fn sum<I>(iter: I) -> Strict<F>
    where
        I: Iterator<Item = &'a Strict<F>>,
    {
        iter.fold(Strict(F::ZERO), Add::add)
    }
}

impl<F: Fixed> Product<Strict<F>> for Strict<F> {
    #[track_caller]
    fn product<I>(mut iter: I) -> Strict<F>
    where
        I: Iterator<Item = Strict<F>>,
    {
        match iter.next() {
            None => match 1.overflowing_to_fixed() {
                (_, true) => panic!("overflow"),
                (ans, false) => Strict(ans),
            },
            Some(first) => iter.fold(first, Mul::mul),
        }
    }
}

impl<'a, F: 'a + Fixed> Product<&'a Strict<F>> for Strict<F> {
    #[track_caller]
    fn product<I>(mut iter: I) -> Strict<F>
    where
        I: Iterator<Item = &'a Strict<F>>,
    {
        match iter.next() {
            None => match 1.overflowing_to_fixed() {
                (_, true) => panic!("overflow"),
                (ans, false) => Strict(ans),
            },
            Some(first) => iter.fold(*first, Mul::mul),
        }
    }
}

// The following cannot be implemented for Strict<F> where F: Fixed,
// otherwise there will be a conflicting implementation error. For
// example we cannot implement both these without triggering E0119:
//
//     impl<F: Fixed> Op<F::Bits> for Strict<F> { /* ... */ }
//     impl<F: Fixed> Op<&F::Bits> for Strict<F> { /* ... */ }
//
// To work around this, we provide implementations like this:
//
//     impl<Frac> Op<i8> for Strict<FixedI8<Frac>> { /* ... */ }
//     impl<Frac> Op<&i8> for Strict<FixedI8<Frac>> { /* ... */ }
//     impl<Frac> Op<i16> for Strict<FixedI16<Frac>> { /* ... */ }
//     impl<Frac> Op<&i16> for Strict<FixedI16<Frac>> { /* ... */ }
//     ...

macro_rules! op_bits {
    (
        $Fixed:ident($Bits:ident $(, $LeEqU:ident)*)::$strict:ident,
        $Op:ident $op:ident,
        $OpAssign:ident $op_assign:ident
    ) => {
        impl<Frac $(: $LeEqU)*> $Op<$Bits> for Strict<$Fixed<Frac>> {
            type Output = Strict<$Fixed<Frac>>;
            #[inline]
            #[track_caller]
            fn $op(self, other: $Bits) -> Strict<$Fixed<Frac>> {
                Strict((self.0).$strict(other))
            }
        }
        impl<Frac $(: $LeEqU)*> $Op<$Bits> for &Strict<$Fixed<Frac>> {
            type Output = Strict<$Fixed<Frac>>;
            #[inline]
            #[track_caller]
            fn $op(self, other: $Bits) -> Strict<$Fixed<Frac>> {
                Strict((self.0).$strict(other))
            }
        }
        impl<Frac $(: $LeEqU)*> $Op<&$Bits> for Strict<$Fixed<Frac>> {
            type Output = Strict<$Fixed<Frac>>;
            #[inline]
            #[track_caller]
            fn $op(self, other: &$Bits) -> Strict<$Fixed<Frac>> {
                Strict((self.0).$strict(*other))
            }
        }
        impl<Frac $(: $LeEqU)*> $Op<&$Bits> for &Strict<$Fixed<Frac>> {
            type Output = Strict<$Fixed<Frac>>;
            #[inline]
            #[track_caller]
            fn $op(self, other: &$Bits) -> Strict<$Fixed<Frac>> {
                Strict((self.0).$strict(*other))
            }
        }
        impl<Frac $(: $LeEqU)*> $OpAssign<$Bits> for Strict<$Fixed<Frac>> {
            #[inline]
            #[track_caller]
            fn $op_assign(&mut self, other: $Bits) {
                self.0 = (self.0).$strict(other);
            }
        }
        impl<Frac $(: $LeEqU)*> $OpAssign<&$Bits> for Strict<$Fixed<Frac>> {
            #[inline]
            #[track_caller]
            fn $op_assign(&mut self, other: &$Bits) {
                self.0 = (self.0).$strict(*other);
            }
        }
    };
}

macro_rules! ops {
    ($Fixed:ident($Bits:ident, $LeEqU:ident)) => {
        op_bits! { $Fixed($Bits)::strict_mul_int, Mul mul, MulAssign mul_assign }
        op_bits! { $Fixed($Bits)::strict_div_int, Div div, DivAssign div_assign }
        op_bits! { $Fixed($Bits, $LeEqU)::strict_rem_int, Rem rem, RemAssign rem_assign }
    };
}
ops! { FixedI8(i8, LeEqU8) }
ops! { FixedI16(i16, LeEqU16) }
ops! { FixedI32(i32, LeEqU32) }
ops! { FixedI64(i64, LeEqU64) }
ops! { FixedI128(i128, LeEqU128) }
ops! { FixedU8(u8, LeEqU8) }
ops! { FixedU16(u16, LeEqU16) }
ops! { FixedU32(u32, LeEqU32) }
ops! { FixedU64(u64, LeEqU64) }
ops! { FixedU128(u128, LeEqU128) }

//! `defmt` support for all binary fixed-point types in `fixed`.  Set the `defmt` feature to enable.
//!
//! ```
//! # #[cfg(any())] {
//! use fixed::types::I16F16;
//!
//! let val = I16F16::from_num(3.125);
//! defmt::error!("val = {}", val);        // → “val = 3.125”
//! # }
//! ```
//!
//! ## Implementation notes
//! * Delegates to each type’s `core::fmt::Display`, so you see the fixed-point
//!   string (e.g. “-42.5”), **not** the raw storage bits.
//! * To minimise log bandwidth you can switch the body of `format()` to
//!   `write!(f, "{:#x}", self.to_bits())` and decode on the host.

/// Blanket‑implements [`defmt::Format`] for every signed **and** unsigned
/// binary fixed‑point base type (`8‒128 bit`). `Frac` is a type‑level unsigned
/// integer from the [`typenum`](https://docs.rs/typenum) crate.
macro_rules! impl_fixed_defmt {
    ($($Base:ident),+ $(,)?) => {
        $(
            impl<Frac> defmt::Format for crate::$Base<Frac>
            where
                crate::$Base<Frac>: core::fmt::Display,
            {
                #[inline]
                fn format(&self, f: defmt::Formatter<'_>) {
                    // Safe & infallible; we rely on the existing `Display` impl.
                    defmt::write!(f, "{}", defmt::Display2Format(self));
                }
            }

            impl<Frac> defmt::Format for crate::Wrapping<crate::$Base<Frac>>
            where
                crate::Wrapping<crate::$Base<Frac>>: core::fmt::Display,
            {
                #[inline]
                fn format(&self, f: defmt::Formatter<'_>) {
                    // Safe & infallible; we rely on the existing `Display` impl.
                    defmt::write!(f, "{}", defmt::Display2Format(self));
                }
            }

            impl<Frac> defmt::Format for crate::Strict<crate::$Base<Frac>>
            where
                crate::Strict<crate::$Base<Frac>>: core::fmt::Display,
            {
                #[inline]
                fn format(&self, f: defmt::Formatter<'_>) {
                    // Safe & infallible; we rely on the existing `Display` impl.
                    defmt::write!(f, "{}", defmt::Display2Format(self));
                }
            }

            impl<Frac> defmt::Format for crate::Saturating<crate::$Base<Frac>>
            where
                crate::Saturating<crate::$Base<Frac>>: core::fmt::Display,
            {
                #[inline]
                fn format(&self, f: defmt::Formatter<'_>) {
                    // Safe & infallible; we rely on the existing `Display` impl.
                    defmt::write!(f, "{}", defmt::Display2Format(self));
                }
            }
        )+
    };
}

// Signed and unsigned, 8‑ through 128‑bit storage words.
impl_fixed_defmt!(
    FixedI8, FixedI16, FixedI32, FixedI64, FixedI128, FixedU8, FixedU16, FixedU32, FixedU64,
    FixedU128,
);

// -----------------------------------------------------------------------------
//                                   Unit tests
// -----------------------------------------------------------------------------
// These tests run with `cargo test --features defmt` on the host and cover:
// 1. Compile‑time evidence that every alias implements `defmt::Format`.
// 2. Runtime checks of representative values for each alias to ensure the
//    `Display` implementation (and therefore `defmt`) emits the expected text.

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::types::{I8F0, I8F8, I16F16, I32F32, I64F64, U8F8, U16F16, U32F32, U64F64};
    use defmt::Format;
    use std::string::ToString;

    // ---------------------------------------------------------------
    // 1. Trait‑presence compile‑checks
    // ---------------------------------------------------------------
    fn assert_format<T: Format>() {}

    #[test]
    fn every_public_alias_implements_format() {
        // Signed
        assert_format::<I8F0>();
        assert_format::<I8F8>();
        assert_format::<I16F16>();
        assert_format::<I32F32>();
        assert_format::<I64F64>();
        // Unsigned
        assert_format::<U8F8>();
        assert_format::<U16F16>();
        assert_format::<U32F32>();
        assert_format::<U64F64>();
    }

    // ---------------------------------------------------------------
    // 2. Helper macro for runtime string tests
    // ---------------------------------------------------------------
    macro_rules! check_values {
        ($Alias:ty, [$(($val:expr, $expect:expr)),+ $(,)?]) => {
            $(
                assert_eq!(<$Alias>::from_num($val).to_string(), $expect);
            )+
        };
    }

    // ---------------------------------------------------------------
    // 3. Per‑alias tests
    // ---------------------------------------------------------------

    #[test]
    fn i8f0_display() {
        check_values!(I8F0, [(0.0, "0"), (-1.0, "-1"), (7.0, "7"), (-8.0, "-8")]);
    }

    #[test]
    fn i8f8_display() {
        check_values!(
            I8F8,
            [
                (0.0, "0"),
                (-0.5, "-0.5"),
                (42.25, "42.25"),
                (-42.25, "-42.25")
            ]
        );
    }

    #[test]
    fn i16f16_display() {
        check_values!(
            I16F16,
            [(0.0, "0"), (-3.125, "-3.125"), (32767.5, "32767.5")]
        );
    }

    #[test]
    fn i32f32_display() {
        check_values!(I32F32, [(1.5, "1.5"), (-1.5, "-1.5")]);
    }

    #[test]
    fn i64f64_display() {
        check_values!(I64F64, [(1.0, "1"), (1.25, "1.25")]);
    }

    #[test]
    fn u8f8_display() {
        check_values!(U8F8, [(0.0, "0"), (0.75, "0.75"), (255.5, "255.5")]);
    }

    #[test]
    fn u16f16_display() {
        check_values!(U16F16, [(1.5, "1.5"), (65535.9961, "65535.9961")]);
    }

    #[test]
    fn u32f32_display() {
        check_values!(U32F32, [(1.5, "1.5"), (65535.75_f64, "65535.75")]);
    }

    #[test]
    fn u64f64_display() {
        check_values!(U64F64, [(1.0, "1")]);
    }

    #[test]
    fn ensure_defmt_impl_not_recursive() {
        let val = I16F16::from_num(1.0);
        // would cause stack overflow if method is wrongly recursive
        defmt::error!("val = {}", val);
    }

    // Allow linking during testing.

    #[defmt::global_logger]
    struct Logger;

    defmt::timestamp!("{=u64:us}", 0);

    unsafe impl defmt::Logger for Logger {
        fn acquire() {}
        unsafe fn flush() {}
        unsafe fn release() {}
        unsafe fn write(_bytes: &[u8]) {}
    }
}

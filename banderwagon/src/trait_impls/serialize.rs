use crate::Element;
use ark_ec::CurveGroup;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsProjective, Fq};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Valid};
impl CanonicalSerialize for Element {
    fn serialize_with_mode<W: std::io::prelude::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        match compress {
            ark_serialize::Compress::Yes => {
                writer.write_all(&self.to_bytes())?;
                Ok(())
            }
            ark_serialize::Compress::No => self.0.into_affine().serialize_uncompressed(writer),
        }
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        match compress {
            ark_serialize::Compress::Yes => Element::compressed_serialized_size(),
            ark_serialize::Compress::No => self.0.uncompressed_size(),
        }
    }
}

impl Valid for Element {
    fn check(&self) -> Result<(), SerializationError> {
        let affine_point = self.0.into_affine();

        // 1. Field validation: check that x and y coordinates are valid field elements
        let mut x_bytes = [0u8; 32];
        affine_point.x.serialize_compressed(&mut x_bytes[..])?;
        Fq::deserialize_compressed(&x_bytes[..])?;

        let mut y_bytes = [0u8; 32];
        affine_point.y.serialize_compressed(&mut y_bytes[..])?;
        Fq::deserialize_compressed(&y_bytes[..])?;

        // 2. Check if point is on curve
        if !affine_point.is_on_curve() {
            return Err(SerializationError::InvalidData);
        }

        // 3. Check if point is in the correct subgroup
        if !self.subgroup_check() {
            return Err(SerializationError::InvalidData);
        }

        Ok(())
    }
}

impl CanonicalDeserialize for Element {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        fn deserialize_with_no_validation<R: std::io::prelude::Read>(
            mut reader: R,
            compress: ark_serialize::Compress,
        ) -> Result<Element, SerializationError> {
            match compress {
                ark_serialize::Compress::Yes => {
                    let mut bytes = [0u8; Element::compressed_serialized_size()];
                    if let Err(err) = reader.read_exact(&mut bytes) {
                        return Err(SerializationError::IoError(err));
                    }

                    match Element::from_bytes(&bytes) {
                        Some(element) => Ok(element),
                        None => Err(SerializationError::InvalidData),
                    }
                }
                ark_serialize::Compress::No => {
                    let point = EdwardsProjective::deserialize_uncompressed(reader)?;
                    Ok(Element(point))
                }
            }
        }

        match validate {
            ark_serialize::Validate::Yes => {
                let element = deserialize_with_no_validation(reader, compress)?;
                element.check()?;
                Ok(element)
            }
            ark_serialize::Validate::No => deserialize_with_no_validation(reader, compress),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{twisted_edwards::TECurveConfig, AdditiveGroup, PrimeGroup};
    use ark_ed_on_bls12_381_bandersnatch::BandersnatchConfig;
    use ark_ff::{Field, One, Zero};
    use ark_serialize::Valid;

    // Helper functions for creating invalid points (borrowed from element.rs tests)

    fn points_at_infinity() -> [EdwardsProjective; 2] {
        let d = BandersnatchConfig::COEFF_D;
        let a = BandersnatchConfig::COEFF_A;
        let sqrt_da = (d / a).sqrt().unwrap();

        let p1 = EdwardsProjective::new_unchecked(sqrt_da, Fq::zero(), Fq::one(), Fq::zero());
        let p2 = EdwardsProjective::new_unchecked(-sqrt_da, Fq::zero(), Fq::one(), Fq::zero());

        [p1, p2]
    }

    // Create a point not on the curve by violating the curve equation
    fn point_not_on_curve() -> EdwardsProjective {
        // Pick arbitrary x, y values that don't satisfy the curve equation
        // Bandersnatch curve: a*x^2 + y^2 = 1 + d*x^2*y^2
        let x = Fq::from(2u64);
        let y = Fq::from(3u64);

        // Create the point without curve validation
        EdwardsProjective::new_unchecked(x, y, x * y, Fq::one())
    }

    #[test]
    fn test_check_valid_elements_pass() {
        // Test generator element
        let generator = Element::prime_subgroup_generator();
        assert!(generator.check().is_ok());

        // Test zero element
        let zero = Element::zero();
        assert!(zero.check().is_ok());

        // Test some multiples of generator (should all be valid)
        use ark_ed_on_bls12_381_bandersnatch::Fr;

        // Test elements created through serialization roundtrip (which normalizes them)
        // This is the proper way to create valid elements that should pass validation
        let scalars_to_test = [1u64, 2, 3, 5, 100, 1000];

        for scalar in scalars_to_test {
            let original = Element::prime_subgroup_generator() * Fr::from(scalar);
            let bytes = original.to_bytes();
            let normalized = Element::from_bytes(&bytes).expect(&format!(
                "Failed to deserialize element with scalar {}",
                scalar
            ));

            // The normalized element should pass our validation
            assert!(
                normalized.check().is_ok(),
                "Normalized element with scalar {} failed check",
                scalar
            );
        }

        // Test element created from bytes (which includes full validation)
        let bytes = generator.to_bytes();
        let from_bytes = Element::from_bytes(&bytes).unwrap();
        assert!(from_bytes.check().is_ok());
    }

    #[test]
    fn test_check_point_not_on_curve_fails() {
        let invalid_point = point_not_on_curve();
        let invalid_element = Element(invalid_point);

        let result = invalid_element.check();
        assert!(result.is_err());
        assert!(matches!(result, Err(SerializationError::InvalidData)));
    }

    #[test]
    fn test_check_point_not_in_subgroup_fails() {
        // Create a point that includes infinity component (as done in element.rs test)
        // This approach avoids the direct affine conversion issue with infinity points
        let point = points_at_infinity()[0];
        let gen = EdwardsProjective::generator();
        let gen2 = gen.double().double(); // gen * 4

        let res = point + gen + gen2;
        let element = Element(res);

        // This point should fail subgroup check
        assert!(
            !element.subgroup_check(),
            "Point with infinity component should fail subgroup check"
        );

        let result = element.check();
        assert!(result.is_err());
        assert!(matches!(result, Err(SerializationError::InvalidData)));
    }

    #[test]
    fn test_check_roundtrip_validation() {
        let generator = Element::prime_subgroup_generator();

        // Test compressed roundtrip
        let compressed_bytes = generator.to_bytes();
        let from_compressed = Element::from_bytes(&compressed_bytes).unwrap();
        assert!(from_compressed.check().is_ok());

        // Test uncompressed roundtrip
        let uncompressed_bytes = generator.to_bytes_uncompressed();
        let from_uncompressed = Element::from_bytes_unchecked_uncompressed(uncompressed_bytes);
        assert!(from_uncompressed.check().is_ok());

        // Verify they're the same point
        assert_eq!(from_compressed, from_uncompressed);
    }

    #[test]
    fn test_check_deserialize_with_validation() {
        use std::io::Cursor;

        let generator = Element::prime_subgroup_generator();
        let mut serialized = Vec::new();
        generator.serialize_compressed(&mut serialized).unwrap();

        // Test deserialization with validation enabled
        let cursor = Cursor::new(serialized.clone());
        let deserialized = Element::deserialize_with_mode(
            cursor,
            ark_serialize::Compress::Yes,
            ark_serialize::Validate::Yes,
        )
        .unwrap();
        assert_eq!(generator, deserialized);

        // Test deserialization without validation (should still work for valid data)
        let cursor = Cursor::new(serialized);
        let deserialized_no_validation = Element::deserialize_with_mode(
            cursor,
            ark_serialize::Compress::Yes,
            ark_serialize::Validate::No,
        )
        .unwrap();
        assert_eq!(generator, deserialized_no_validation);
    }
}

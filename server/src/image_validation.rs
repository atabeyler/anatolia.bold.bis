//! Real validation for a probe image upload — magic-byte sniffing plus an
//! actual decode, not just "the byte slice is non-empty". See CLAUDE.md's
//! image-upload hardening requirement. Only ever called on the raw bytes
//! before anything derives a face embedding from them; the raw bytes
//! themselves are never persisted or logged (see `search.rs`).
//!
//! Validation also sanitizes: the returned bytes are a fresh re-encode of
//! the decoded pixel data, not the original upload, which strips any
//! EXIF/XMP metadata (GPS coordinates, device make/model, timestamps) a
//! phone camera embeds before the image is used anywhere downstream.

/// 10 MB — comfortably above a real phone-camera JPEG, well below
/// anything that should ever hit this endpoint.
const MAX_IMAGE_BYTES: usize = 10 * 1024 * 1024;
const MIN_DIMENSION: u32 = 32;
const MAX_DIMENSION: u32 = 8000;
/// Decompression-bomb guard: rejects an image whose *decoded* pixel count
/// would be disproportionate to its compressed size (e.g. a tiny PNG that
/// expands to gigabytes in memory), independent of the width/height caps
/// above (a very wide, very short image could pass those individually).
const MAX_PIXELS: u64 = 40_000_000;

/// Validates `bytes` as a genuine, decodable JPEG/PNG/WEBP probe image and
/// returns a sanitized re-encode of it (see module docs — this strips EXIF
/// metadata). Returns the stable error code to surface to the client on
/// failure — never a raw decode-library error message.
pub fn validate_and_sanitize_probe_image(bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err("IMAGE_TOO_LARGE");
    }
    if sniff_format(bytes).is_none() {
        return Err("UNSUPPORTED_IMAGE_TYPE");
    }

    let decoded = image::load_from_memory(bytes).map_err(|_| "IMAGE_DECODE_FAILED")?;
    let (width, height) = (decoded.width(), decoded.height());
    if width < MIN_DIMENSION
        || height < MIN_DIMENSION
        || width > MAX_DIMENSION
        || height > MAX_DIMENSION
    {
        return Err("IMAGE_DIMENSIONS_INVALID");
    }
    if (width as u64) * (height as u64) > MAX_PIXELS {
        return Err("IMAGE_DIMENSIONS_INVALID");
    }

    // `image`'s encoders don't carry EXIF/XMP chunks over from the
    // decoded representation, so re-encoding (always to PNG, regardless
    // of the original container format) is sufficient sanitization on
    // its own — no separate metadata-stripping step is needed.
    let mut sanitized = Vec::new();
    decoded
        .write_to(
            &mut std::io::Cursor::new(&mut sanitized),
            image::ImageFormat::Png,
        )
        .map_err(|_| "IMAGE_DECODE_FAILED")?;
    Ok(sanitized)
}

/// Magic-byte sniff for the three formats this endpoint accepts. Checked
/// before the (more expensive) full decode so an unsupported type is
/// rejected with a specific code rather than a generic decode failure.
fn sniff_format(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("jpeg");
    }
    if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("png");
    }
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("webp");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bytes_are_rejected_as_unsupported() {
        assert_eq!(
            validate_and_sanitize_probe_image(&[]),
            Err("UNSUPPORTED_IMAGE_TYPE")
        );
    }

    #[test]
    fn random_bytes_are_rejected_as_unsupported() {
        assert_eq!(
            validate_and_sanitize_probe_image(b"not an image at all"),
            Err("UNSUPPORTED_IMAGE_TYPE")
        );
    }

    #[test]
    fn oversized_payload_is_rejected_before_decoding() {
        let mut fake_jpeg = vec![0xFF, 0xD8, 0xFF];
        fake_jpeg.resize(MAX_IMAGE_BYTES + 1, 0);
        assert_eq!(
            validate_and_sanitize_probe_image(&fake_jpeg),
            Err("IMAGE_TOO_LARGE")
        );
    }

    #[test]
    fn truncated_jpeg_with_valid_magic_bytes_fails_to_decode() {
        let truncated = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        assert_eq!(
            validate_and_sanitize_probe_image(&truncated),
            Err("IMAGE_DECODE_FAILED")
        );
    }

    #[test]
    fn a_real_small_png_decodes_but_is_rejected_for_dimensions() {
        // 1x1 PNG — decodes fine, but fails the minimum-dimension check.
        let png_1x1: &[u8] = &[
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00,
            0x00, 0x90, 0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08,
            0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D,
            0xB0, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
        ];
        assert_eq!(
            validate_and_sanitize_probe_image(png_1x1),
            Err("IMAGE_DIMENSIONS_INVALID")
        );
    }

    #[test]
    fn a_real_png_of_valid_dimensions_passes() {
        let mut buf = Vec::new();
        let img = image::RgbImage::from_pixel(64, 64, image::Rgb([120, 130, 140]));
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
            .unwrap();
        let sanitized = validate_and_sanitize_probe_image(&buf).expect("valid image");
        let redecoded = image::load_from_memory(&sanitized).expect("sanitized output decodes");
        assert_eq!((redecoded.width(), redecoded.height()), (64, 64));
    }

    #[test]
    fn exif_metadata_is_not_present_in_sanitized_output() {
        // A JPEG carrying an APP1/EXIF segment with a GPS marker string.
        // The sanitized re-encode must not contain the marker bytes.
        let mut jpeg = Vec::new();
        let img = image::RgbImage::from_pixel(64, 64, image::Rgb([10, 20, 30]));
        image::DynamicImage::ImageRgb8(img)
            .write_to(
                &mut std::io::Cursor::new(&mut jpeg),
                image::ImageFormat::Jpeg,
            )
            .unwrap();

        let marker = b"GPSLatitudeMarker12345";
        let mut exif_payload = Vec::new();
        exif_payload.extend_from_slice(b"Exif\x00\x00");
        exif_payload.extend_from_slice(marker);
        let mut segment = Vec::new();
        segment.push(0xFF);
        segment.push(0xE1); // APP1
        let len = (exif_payload.len() + 2) as u16;
        segment.extend_from_slice(&len.to_be_bytes());
        segment.extend_from_slice(&exif_payload);

        // Splice the fake APP1 segment right after the JPEG SOI marker.
        let mut with_exif = jpeg[0..2].to_vec();
        with_exif.extend_from_slice(&segment);
        with_exif.extend_from_slice(&jpeg[2..]);

        let sanitized = validate_and_sanitize_probe_image(&with_exif).expect("valid image");
        assert!(!sanitized
            .windows(marker.len())
            .any(|window| window == marker));
    }
}

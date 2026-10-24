use super::*;

fn rate(fps: u32) -> FrameRate {
    FrameRate::new(fps, 1).unwrap_or_else(|error| panic!("valid fixture rejected: {error}"))
}
fn hevc(width: u32, height: u32, fps: u32, level: u8) -> VideoFormat {
    VideoFormat {
        codec: Codec::Hevc,
        profile: Profile::HevcMain,
        level,
        h264_constraints: 0,
        geometry: Geometry::uncropped(width, height),
        tier: Tier::Main,
        chroma: Chroma::Yuv420,
        bit_depth: BitDepth::Eight,
        color: Color::SDR_BT709_LIMITED,
        width,
        height,
        frame_rate: rate(fps),
        max_kbps: 20_000,
    }
}
fn set(formats: &[VideoFormat]) -> FormatSet {
    FormatSet::new(formats.to_vec())
        .unwrap_or_else(|error| panic!("valid fixture rejected: {error}"))
}

#[test]
fn exact_intersection_does_not_invent_four_k_at_120_from_two_probed_modes() {
    let four_k60 = hevc(3840, 2160, 60, 153);
    let qhd120 = hevc(2560, 1440, 120, 153);
    let four_k120 = hevc(3840, 2160, 120, 156);
    let encoder = set(&[four_k60, qhd120]);
    let decoder = set(&[four_k60, qhd120, four_k120]);
    let common = encoder.intersection(&decoder);
    assert!(!common.contains(&four_k120));
    assert_eq!(
        common
            .select(&[four_k120, qhd120])
            .unwrap_or_else(|error| panic!("valid fixture rejected: {error}")),
        Some(qhd120)
    );
}

#[test]
fn main10_and_444_are_independent_and_require_exact_intersection() {
    let main8 = hevc(1920, 1080, 60, 123);
    let main10 = VideoFormat {
        profile: Profile::HevcMain10,
        bit_depth: BitDepth::Ten,
        ..main8
    };
    let color444 = VideoFormat {
        profile: Profile::HevcRange444,
        chroma: Chroma::Yuv444,
        ..main10
    };
    main10
        .validate()
        .unwrap_or_else(|error| panic!("valid fixture rejected: {error}"));
    color444
        .validate()
        .unwrap_or_else(|error| panic!("valid fixture rejected: {error}"));
    let common = set(&[main8, main10, color444]).intersection(&set(&[main8]));
    assert_eq!(
        common
            .select(&[color444, main10, main8])
            .unwrap_or_else(|error| panic!("valid fixture rejected: {error}")),
        Some(main8)
    );
    assert!(
        VideoFormat {
            chroma: Chroma::Yuv444,
            ..main10
        }
        .validate()
        .is_err()
    );
    assert!(
        VideoFormat {
            bit_depth: BitDepth::Ten,
            ..main8
        }
        .validate()
        .is_err()
    );
}

#[test]
fn hdr_requires_independent_depth_primaries_and_transfer() {
    let base = hevc(1920, 1080, 60, 123);
    let hdr = VideoFormat {
        profile: Profile::HevcMain10,
        bit_depth: BitDepth::Ten,
        color: Color {
            primaries: Primaries::Bt2020,
            transfer: Transfer::Pq,
            matrix: Matrix::Bt2020NonConstant,
            range: Range::Limited,
        },
        ..base
    };
    hdr.validate()
        .unwrap_or_else(|error| panic!("valid fixture rejected: {error}"));
    assert!(
        VideoFormat {
            bit_depth: BitDepth::Eight,
            ..hdr
        }
        .validate()
        .is_err()
    );
    assert!(
        VideoFormat {
            color: Color {
                primaries: Primaries::Bt709,
                ..hdr.color
            },
            ..hdr
        }
        .validate()
        .is_err()
    );
    assert_ne!(
        base.digest()
            .unwrap_or_else(|error| panic!("valid fixture rejected: {error}")),
        hdr.digest()
            .unwrap_or_else(|error| panic!("valid fixture rejected: {error}"))
    );
}

#[test]
fn legacy_defaults_preserve_actual_distinct_color_conversions() {
    let vp8 = VideoFormat::legacy_vp8(641, 481, rate(30), 4000)
        .unwrap_or_else(|error| panic!("valid fixture rejected: {error}"));
    assert_eq!(vp8.color, Color::LEGACY_VP8_BT601);
    assert_eq!(vp8.bit_depth, BitDepth::Eight);
    assert_eq!(vp8.chroma, Chroma::Yuv420);
    let h264 = VideoFormat::legacy_h264(42, 1920, 1080, rate(60), 12_000)
        .unwrap_or_else(|error| panic!("valid fixture rejected: {error}"));
    assert_eq!(h264.color, Color::SDR_BT709_LIMITED);
    assert!(VideoFormat::legacy_h264(42, 641, 481, rate(30), 4000).is_err());
    assert!(
        VideoFormat {
            color: Color::SDR_BT709_LIMITED,
            ..vp8
        }
        .validate()
        .is_err()
    );
}

#[test]
fn rational_framerate_is_canonical_and_bounded() {
    assert_eq!(
        FrameRate::new(120_000, 2002)
            .unwrap_or_else(|error| panic!("valid fixture rejected: {error}")),
        FrameRate::new(60_000, 1001)
            .unwrap_or_else(|error| panic!("valid fixture rejected: {error}"))
    );
    assert!(FrameRate::new(0, 1).is_err());
    assert!(FrameRate::new(1, 0).is_err());
    assert!(FrameRate::new(145, 1).is_err());
    assert!(FrameRate::new(144, 1).is_ok());
    assert!(FrameRate::new(u32::MAX, 1).is_err());
    let raw = FrameRate {
        numerator: 120,
        denominator: 2,
    };
    assert!(
        VideoFormat {
            frame_rate: raw,
            ..hevc(1920, 1080, 60, 123)
        }
        .validate()
        .is_err()
    );
}

#[test]
fn level_picture_sample_rate_tier_and_bitrate_are_enforced() {
    assert!(hevc(3840, 2160, 60, 153).validate().is_ok());
    assert!(hevc(3840, 2160, 120, 153).validate().is_err());
    assert!(hevc(3840, 2160, 120, 156).validate().is_ok());
    assert!(
        VideoFormat {
            tier: Tier::High,
            max_kbps: 1000,
            ..hevc(640, 360, 30, 63)
        }
        .validate()
        .is_err()
    );
    assert!(
        VideoFormat {
            max_kbps: 40_001,
            ..hevc(1920, 1080, 60, 153)
        }
        .validate()
        .is_err()
    );
    assert!(VideoFormat::legacy_h264(41, 1920, 1080, rate(60), 12_000).is_err());
    assert!(VideoFormat::legacy_h264(42, 1920, 1080, rate(60), 12_000).is_ok());
}

#[test]
fn geometry_and_high_bit_depth_have_conservative_raw_budget() {
    let base = hevc(1920, 1080, 60, 123);
    for (width, height) in [(0, 1080), (1920, 0), (u32::MAX, u32::MAX), (8192, 8192)] {
        assert!(
            VideoFormat {
                width,
                height,
                ..base
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        VideoFormat {
            width: 1921,
            ..base
        }
        .validate()
        .is_err()
    );
    assert!(
        VideoFormat {
            profile: Profile::H264Baseline,
            ..base
        }
        .validate()
        .is_err()
    );
    assert!(VideoFormat { level: 255, ..base }.validate().is_err());
    assert!(
        VideoFormat {
            max_kbps: 0,
            ..base
        }
        .validate()
        .is_err()
    );
}

#[test]
fn rgba16_budget_is_checked_independently_of_eight_bit_budget() {
    let dci4k = hevc(4096, 2160, 60, 153);
    dci4k
        .validate()
        .unwrap_or_else(|error| panic!("valid fixture rejected: {error}")); // RGBA8=35389440 bytes, within64MiB.
    assert!(
        VideoFormat {
            profile: Profile::HevcMain10,
            bit_depth: BitDepth::Ten,
            ..dci4k
        }
        .validate()
        .is_err()
    ); // RGBA16=70778880 bytes, beyond64MiB.
}

#[test]
fn hevc_display_area_cannot_hide_padded_coded_picture_limit() {
    let display = VideoFormat {
        max_kbps: 100,
        ..hevc(190, 194, 1, 30)
    };
    // Display area 36860 fits level1 MaxLumaPs36864, but minimum 8x8
    // coded192x200 has38400 samples. Restricted catalog rejects the display
    // geometry, and explicit coded geometry fails the actual level bound.
    assert!(display.validate().is_err());
    assert!(
        VideoFormat {
            width: 192,
            height: 200,
            ..display
        }
        .validate()
        .is_err()
    );
}

#[test]
fn hevc_display_rate_cannot_hide_padded_coded_sample_rate_limit() {
    let display = VideoFormat {
        frame_rate: FrameRate::new(301, 10)
            .unwrap_or_else(|error| panic!("valid fixture rejected: {error}")),
        max_kbps: 1000,
        ..hevc(510, 240, 30, 60)
    };
    // Display510x240x30.1=3684240 fits level2 MaxLumaSr3686400;
    // coded512x240x30.1=3698688 exceeds it.
    assert!(display.validate().is_err());
    assert!(
        VideoFormat {
            width: 512,
            ..display
        }
        .validate()
        .is_err()
    );
}

#[test]
fn digest_has_stable_field_order_big_endian_encoding_and_domain() {
    let format = VideoFormat::legacy_vp8(640, 480, rate(30), 4000)
        .unwrap_or_else(|error| panic!("valid fixture rejected: {error}"));
    let expected = [
        0, 2, 1, 1, 0, 0, 0, 1, 8, 0, 0, 3, 1, 0, 0, 2, 128, 0, 0, 1, 224, 0, 0, 2, 128, 0, 0, 1,
        224, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 30, 0, 0, 0, 1, 0, 0, 15,
        160,
    ];
    assert_eq!(format.canonical(), expected);
    let mut hash = Sha256::new();
    hash.update(b"nestlink/media-format/v2\0");
    hash.update(expected);
    let expected_digest: [u8; 32] = hash.finalize().into();
    assert_eq!(
        format
            .digest()
            .unwrap_or_else(|error| panic!("valid fixture rejected: {error}")),
        expected_digest
    );
    // Independent Python hashlib result over the explicit57 bytes above and
    // literal domain, not generated via Rust canonical()/digest().
    let golden = [
        0x40, 0xa5, 0x52, 0x9b, 0xe8, 0x4a, 0xb1, 0x2a, 0x2a, 0xb1, 0x87, 0x8d, 0x78, 0xe8, 0xe,
        0x46, 0xab, 0x36, 0xb1, 0x56, 0xd2, 0x72, 0x82, 0x3, 0xa5, 0x61, 0xcd, 0x18, 0xc2, 0xa5,
        0x1b, 0xd5,
    ];
    assert_eq!(
        format
            .digest()
            .unwrap_or_else(|error| panic!("valid fixture rejected: {error}")),
        golden
    );
    assert_ne!(
        format
            .digest()
            .unwrap_or_else(|error| panic!("valid fixture rejected: {error}")),
        set(&[format]).digest()
    );
}

#[test]
fn canonical_set_digest_ignores_wire_order_but_binds_every_format_field() {
    let a = hevc(1920, 1080, 60, 123);
    let b = hevc(2560, 1440, 120, 153);
    assert_eq!(set(&[a, b]).digest(), set(&[b, a]).digest());
    for changed in [
        VideoFormat {
            max_kbps: 19_999,
            ..a
        },
        VideoFormat {
            color: Color {
                range: Range::Full,
                ..a.color
            },
            ..a
        },
        VideoFormat {
            frame_rate: rate(30),
            ..a
        },
    ] {
        assert_ne!(set(&[a]).digest(), set(&[changed]).digest());
    }
    assert_ne!(
        FormatSet::new(vec![])
            .unwrap_or_else(|error| panic!("valid fixture rejected: {error}"))
            .digest(),
        set(&[a]).digest()
    );
}

#[test]
fn empty_no_common_duplicates_and_excess_entries_are_distinct_outcomes() {
    let a = hevc(1920, 1080, 60, 123);
    assert!(FormatSet::new(vec![a, a]).is_err());
    assert!(FormatSet::new(vec![a; MAX_FORMATS + 1]).is_err());
    assert_eq!(
        set(&[a])
            .intersection(&set(&[]))
            .select(&[a])
            .unwrap_or_else(|error| panic!("valid fixture rejected: {error}")),
        None
    );
    assert!(set(&[a]).select(&[a; MAX_FORMATS + 1]).is_err());
    assert!(
        set(&[a])
            .select(&[VideoFormat { level: 255, ..a }])
            .is_err()
    );
    assert!(FormatSet::from_versioned(0, vec![a]).is_err());
    assert!(FormatSet::from_versioned(1, vec![a]).is_err());
    assert_eq!(
        FormatSet::from_versioned(2, vec![a])
            .unwrap_or_else(|error| panic!("valid fixture rejected: {error}")),
        set(&[a])
    );
    assert!(Codec::try_from(0).is_err());
    assert!(Chroma::try_from(u32::MAX).is_err());
}

#[test]
fn syntax_support_is_not_a_backend_capability_announcement() {
    let hevc = hevc(1920, 1080, 60, 123);
    hevc.validate()
        .unwrap_or_else(|error| panic!("valid fixture rejected: {error}"));
    // Merely accepting this syntax does not inject it into either endpoint's
    // runtime-probed set or their signed common set.
    let legacy = VideoFormat::legacy_h264(42, 1920, 1080, rate(60), 12_000)
        .unwrap_or_else(|error| panic!("valid fixture rejected: {error}"));
    assert_eq!(
        set(&[legacy])
            .select(&[hevc])
            .unwrap_or_else(|error| panic!("valid fixture rejected: {error}")),
        None
    );
}

#[test]
fn observed_h264_digest_binds_constraint_flags_and_crop_origin() {
    let a = VideoFormat::h264_observed(
        42,
        0xc0,
        Geometry {
            coded_width: 1920,
            coded_height: 1088,
            crop: [0, 0, 0, 8],
        },
        1920,
        1080,
        rate(60),
        12_000,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let b = VideoFormat {
        h264_constraints: 0x40,
        ..a
    };
    let c = VideoFormat {
        geometry: Geometry {
            crop: [0, 0, 8, 0],
            ..a.geometry
        },
        ..a
    };
    assert_ne!(a.digest().ok(), b.digest().ok());
    assert_ne!(a.digest().ok(), c.digest().ok());
    assert!(!set(&[a]).contains(&b));
    assert!(!set(&[a]).contains(&c));
    assert!(
        VideoFormat {
            h264_constraints: 3,
            ..a
        }
        .validate()
        .is_err()
    );
    assert!(
        VideoFormat {
            geometry: Geometry {
                crop: [0, 0, 0, u32::MAX],
                ..a.geometry
            },
            ..a
        }
        .validate()
        .is_err()
    );
    assert!(
        VideoFormat {
            geometry: Geometry {
                crop: [0, 0, 0, 7],
                ..a.geometry
            },
            ..a
        }
        .validate()
        .is_err()
    );
    assert!(
        VideoFormat {
            level: 11,
            h264_constraints: 0x10,
            ..a
        }
        .validate()
        .is_err()
    );
}

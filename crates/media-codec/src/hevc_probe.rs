//! Restricted diagnostic HEVC Annex-B validator, not the product network parser.
//! Main8 4:2:0, single layer, IDR-only, no reorder; unsupported syntax fails closed.
use std::io;
fn rejection(code: &'static str, detail: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("hevc_probe_rejection code={code} {detail}"),
    )
}
struct Bits {
    bytes: Vec<u8>,
    pos: usize,
    field: &'static str,
}
impl Bits {
    fn new(nal: &[u8]) -> io::Result<Self> {
        if nal.len() < 3 || nal.len() > 65536 {
            return Err(rejection(
                "rbsp.nal_size",
                format!("actual={} min=3 max=65536", nal.len()),
            ));
        }
        let mut bytes = Vec::with_capacity(nal.len() - 2);
        let mut zeros = 0;
        for (i, b) in nal[2..].iter().copied().enumerate() {
            if zeros >= 2 {
                if b == 3 {
                    if nal.get(i + 3).is_none_or(|v| *v > 3) {
                        return Err(rejection(
                            "rbsp.emulation_prevention",
                            format!("nal_byte={} next={:?}", i + 2, nal.get(i + 3)),
                        ));
                    }
                    zeros = 0;
                    continue;
                }
                if b <= 2 {
                    return Err(rejection(
                        "rbsp.unescaped_start_code",
                        format!("nal_byte={} value={b}", i + 2),
                    ));
                }
            }
            bytes.push(b);
            zeros = if b == 0 { zeros + 1 } else { 0 };
        }
        Ok(Self {
            bytes,
            pos: 0,
            field: "unassigned",
        })
    }
    fn read(&mut self, n: usize) -> io::Result<u32> {
        if n > 32 || self.pos + n > self.bytes.len() * 8 {
            return Err(rejection(
                "bits.bounds",
                format!(
                    "field={} rbsp_bit={} requested={} available_bits={}",
                    self.field,
                    self.pos,
                    n,
                    self.bytes.len() * 8
                ),
            ));
        }
        let mut v = 0;
        for _ in 0..n {
            v = (v << 1) | u32::from((self.bytes[self.pos / 8] >> (7 - self.pos % 8)) & 1);
            self.pos += 1;
        }
        Ok(v)
    }
    fn ue(&mut self, max: u32) -> io::Result<u32> {
        let mut z = 0;
        while self.read(1)? == 0 {
            z += 1;
            if z > 24 {
                return Err(rejection(
                    "bits.ue_prefix",
                    format!(
                        "field={} rbsp_bit={} zeros={z} max=24",
                        self.field, self.pos
                    ),
                ));
            }
        }
        let v = ((1u32 << z) - 1) + self.read(z)?;
        if v > max {
            return Err(rejection(
                "bits.ue_value",
                format!(
                    "field={} rbsp_bit={} actual={v} max={max}",
                    self.field, self.pos
                ),
            ));
        }
        Ok(v)
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Sps {
    pub profile: u32,
    pub level: u32,
    pub width: u32,
    pub height: u32,
    pub vps: u32,
    pub id: u32,
}
fn sps(nal: &[u8], width: u32, height: u32) -> io::Result<Sps> {
    let mut b = Bits::new(nal)?;
    b.field = "sps.vps_id";
    let vps = b.read(4)?;
    b.field = "sps.max_sub_layers_minus1";
    let layers = b.read(3)?;
    b.field = "sps.temporal_id_nesting";
    b.read(1)?;
    if layers != 0 {
        return Err(rejection(
            "sps.temporal_sublayers",
            format!("actual={layers} required=0 rbsp_bit={}", b.pos),
        ));
    }
    b.field = "ptl.profile_space";
    let space = b.read(2)?;
    if space != 0 {
        return Err(rejection(
            "sps.profile_space",
            format!("actual={space} required=0 rbsp_bit={}", b.pos),
        ));
    }
    b.field = "ptl.tier_flag";
    b.read(1)?;
    b.field = "ptl.profile_idc";
    let profile = b.read(5)?;
    b.field = "ptl.compatibility";
    b.read(32)?;
    b.field = "ptl.constraints_hi";
    b.read(32)?;
    b.field = "ptl.constraints_lo";
    b.read(16)?;
    b.field = "ptl.level_idc";
    let level = b.read(8)?;
    if profile != 1 || !matches!(level, 30 | 60 | 63 | 90 | 93 | 120 | 123 | 150 | 153) {
        return Err(rejection(
            "sps.profile_level",
            format!(
                "profile={profile} required_profile=1 level={level} accepted_levels=30,60,63,90,93,120,123,150,153 rbsp_bit={}",
                b.pos
            ),
        ));
    }
    b.field = "sps.id";
    let id = b.ue(15)?;
    b.field = "sps.chroma_format_idc";
    let chroma = b.ue(3)?;
    if chroma != 1 {
        return Err(rejection(
            "sps.chroma",
            format!("actual={chroma} required=1 rbsp_bit={}", b.pos),
        ));
    }
    b.field = "sps.pic_width_in_luma_samples";
    let coded_width = b.ue(8192)?;
    b.field = "sps.pic_height_in_luma_samples";
    let coded_height = b.ue(8192)?;
    let (mut left, mut right, mut top, mut bottom) = (0u32, 0u32, 0u32, 0u32);
    b.field = "sps.conformance_window_flag";
    if b.read(1)? != 0 {
        b.field = "sps.conf_win_left_offset";
        left = b.ue(4096)?;
        b.field = "sps.conf_win_right_offset";
        right = b.ue(4096)?;
        b.field = "sps.conf_win_top_offset";
        top = b.ue(4096)?;
        b.field = "sps.conf_win_bottom_offset";
        bottom = b.ue(4096)?;
    }
    let visible_width = coded_width.checked_sub((left + right) * 2).ok_or_else(|| {
        rejection(
            "sps.crop_width_underflow",
            format!("coded={coded_width} left={left} right={right}"),
        )
    })?;
    let visible_height = coded_height
        .checked_sub((top + bottom) * 2)
        .ok_or_else(|| {
            rejection(
                "sps.crop_height_underflow",
                format!("coded={coded_height} top={top} bottom={bottom}"),
            )
        })?;
    if visible_width != width || visible_height != height || left != 0 || top != 0 {
        return Err(rejection(
            "sps.geometry",
            format!(
                "coded={coded_width}x{coded_height} crop_units={left},{right},{top},{bottom} visible={visible_width}x{visible_height} required={width}x{height} require_origin=0,0 rbsp_bit={}",
                b.pos
            ),
        ));
    }
    b.field = "sps.bit_depth_luma_minus8";
    let luma = b.ue(8)?;
    if luma != 0 {
        return Err(rejection(
            "sps.luma_depth",
            format!("minus8={luma} required=0 rbsp_bit={}", b.pos),
        ));
    }
    b.field = "sps.bit_depth_chroma_minus8";
    let chroma_depth = b.ue(8)?;
    if chroma_depth != 0 {
        return Err(rejection(
            "sps.chroma_depth",
            format!("minus8={chroma_depth} required=0 rbsp_bit={}", b.pos),
        ));
    }
    b.field = "sps.log2_max_pic_order_cnt_lsb_minus4";
    let poc_bits = b.ue(12)? as usize + 4;
    b.field = "sps.sub_layer_ordering_info_present_flag";
    b.read(1)?;
    b.field = "sps.max_dec_pic_buffering_minus1";
    b.ue(16)?;
    b.field = "sps.max_num_reorder_pics";
    let reorder = b.ue(16)?;
    if reorder != 0 {
        return Err(rejection(
            "sps.reorder",
            format!("actual={reorder} required=0 rbsp_bit={}", b.pos),
        ));
    }
    b.field = "sps.max_latency_increase_plus1";
    b.ue(65535)?;
    for field in [
        "sps.log2_min_luma_coding_block_size_minus3",
        "sps.log2_diff_max_min_luma_coding_block_size",
        "sps.log2_min_luma_transform_block_size_minus2",
        "sps.log2_diff_max_min_luma_transform_block_size",
        "sps.max_transform_hierarchy_depth_inter",
        "sps.max_transform_hierarchy_depth_intra",
    ] {
        b.field = field;
        b.ue(6)?;
    }
    b.field = "sps.scaling_list_enabled_flag";
    if b.read(1)? != 0 {
        b.field = "sps.scaling_list_data_present_flag";
        if b.read(1)? != 0 {
            return Err(rejection(
                "sps.custom_scaling_list",
                format!("rbsp_bit={}", b.pos),
            ));
        }
    }
    b.field = "sps.amp_enabled_flag";
    b.read(1)?;
    b.field = "sps.sample_adaptive_offset_enabled_flag";
    b.read(1)?;
    b.field = "sps.pcm_enabled_flag";
    if b.read(1)? != 0 {
        b.field = "sps.pcm_sample_bit_depth_luma_minus1";
        b.read(4)?;
        b.field = "sps.pcm_sample_bit_depth_chroma_minus1";
        b.read(4)?;
        b.field = "sps.log2_min_pcm_luma_coding_block_size_minus3";
        b.ue(6)?;
        b.field = "sps.log2_diff_max_min_pcm_luma_coding_block_size";
        b.ue(6)?;
        b.field = "sps.pcm_loop_filter_disabled_flag";
        b.read(1)?;
    }
    b.field = "sps.num_short_term_ref_pic_sets";
    let sets = b.ue(64)?;
    for i in 0..sets {
        b.field = "sps.inter_ref_pic_set_prediction_flag";
        if i > 0 && b.read(1)? != 0 {
            return Err(rejection(
                "sps.predicted_rps",
                format!("set={i} rbsp_bit={}", b.pos),
            ));
        }
        b.field = "sps.num_negative_pics";
        let neg = b.ue(16)?;
        b.field = "sps.num_positive_pics";
        let pos = b.ue(16)?;
        if neg + pos > 16 {
            return Err(rejection(
                "sps.rps_count",
                format!(
                    "set={i} negative={neg} positive={pos} max_total=16 rbsp_bit={}",
                    b.pos
                ),
            ));
        }
        for _ in 0..neg + pos {
            b.field = "sps.delta_poc_minus1";
            b.ue(65535)?;
            b.field = "sps.used_by_curr_pic_flag";
            b.read(1)?;
        }
    }
    b.field = "sps.long_term_ref_pics_present_flag";
    if b.read(1)? != 0 {
        b.field = "sps.num_long_term_ref_pics_sps";
        let n = b.ue(16)?;
        for _ in 0..n {
            b.field = "sps.lt_ref_pic_poc_lsb_sps";
            b.read(poc_bits)?;
            b.field = "sps.used_by_curr_pic_lt_sps_flag";
            b.read(1)?;
        }
    }
    b.field = "sps.temporal_mvp_enabled_flag";
    b.read(1)?;
    b.field = "sps.strong_intra_smoothing_enabled_flag";
    b.read(1)?;
    b.field = "sps.vui_parameters_present_flag";
    if b.read(1)? != 0 {
        b.field = "vui.aspect_ratio_info_present_flag";
        if b.read(1)? != 0 {
            b.field = "vui.aspect_ratio_idc";
            if b.read(8)? == 255 {
                b.field = "vui.sar_width";
                b.read(16)?;
                b.field = "vui.sar_height";
                b.read(16)?;
            }
        }
        b.field = "vui.overscan_info_present_flag";
        if b.read(1)? != 0 {
            b.field = "vui.overscan_appropriate_flag";
            b.read(1)?;
        }
        b.field = "vui.video_signal_type_present_flag";
        if b.read(1)? != 0 {
            b.field = "vui.video_format";
            b.read(3)?;
            b.field = "vui.video_full_range_flag";
            if b.read(1)? != 0 {
                return Err(rejection(
                    "sps.full_range",
                    format!("actual=1 required=0 rbsp_bit={}", b.pos),
                ));
            }
            b.field = "vui.colour_description_present_flag";
            if b.read(1)? != 0 {
                for field in [
                    "vui.colour_primaries",
                    "vui.transfer_characteristics",
                    "vui.matrix_coeffs",
                ] {
                    b.field = field;
                    let actual = b.read(8)?;
                    if actual != 1 {
                        return Err(rejection(
                            "sps.color",
                            format!(
                                "field={field} actual={actual} required=1 rbsp_bit={}",
                                b.pos
                            ),
                        ));
                    }
                }
            }
        }
    }
    Ok(Sps {
        profile,
        level,
        width: visible_width,
        height: visible_height,
        vps,
        id,
    })
}
#[derive(Clone, Default)]
pub(crate) struct Validator {
    vps: Option<u32>,
    sps: Option<Sps>,
    pps: Option<u32>,
}
impl Validator {
    pub fn info(&self) -> Option<Sps> {
        self.sps
    }
    pub fn validate(&mut self, data: &[u8], width: u32, height: u32) -> io::Result<()> {
        self.validate_inner(data,width,height).map_err(|error| {
            let inventory=match crate::h264::nals(data) {
                Ok(nals)=>format!("nal_count={} first16={:?}",nals.len(),nals.iter().take(16)
                    .map(|nal| (nal.first().map(|v|(v>>1)&63),nal.len())).collect::<Vec<_>>()),
                Err(_)=>"nal_inventory=invalid_annex_b".into(),
            };
            io::Error::new(io::ErrorKind::InvalidData,format!("hevc_probe_au_rejected target={width}x{height} au_bytes={} {inventory} cause=({error})",data.len()))
        })
    }
    fn validate_inner(&mut self, data: &[u8], width: u32, height: u32) -> io::Result<()> {
        let mut next = self.clone();
        let mut slices = 0;
        let nals = crate::h264::nals(data)
            .map_err(|_| rejection("au.annex_b", "bounded Annex-B splitting failed"))?;
        for (index, nal) in nals.into_iter().enumerate() {
            if nal.len() < 3 || nal[0] & 0x81 != 0 || nal[1] != 1 {
                return Err(rejection(
                    "nal.header",
                    format!(
                        "index={index} bytes={} byte0={:?} byte1={:?} required_forbidden=0 required_layer=0 required_temporal_id_plus1=1",
                        nal.len(),
                        nal.first(),
                        nal.get(1)
                    ),
                ));
            } // forbidden/layer/temporal ID.
            let kind = (nal[0] >> 1) & 63;
            match kind {
                32 => {
                    let mut b = Bits::new(nal)?;
                    b.field = "vps.id";
                    next.vps = Some(b.read(4)?);
                }
                33 => {
                    let info = sps(nal, width, height)?;
                    if next.vps != Some(info.vps) {
                        return Err(rejection(
                            "sps.vps_reference",
                            format!("sps_vps={} current_vps={:?}", info.vps, next.vps),
                        ));
                    }
                    next.sps = Some(info);
                }
                34 => {
                    let mut b = Bits::new(nal)?;
                    b.field = "pps.id";
                    let pps = b.ue(63)?;
                    b.field = "pps.sps_id";
                    let sps = b.ue(15)?;
                    if next.sps.is_none_or(|v| v.id != sps) {
                        return Err(rejection(
                            "pps.sps_reference",
                            format!("pps_sps={sps} current_sps={:?}", next.sps.map(|v| v.id)),
                        ));
                    }
                    next.pps = Some(pps);
                }
                19 | 20 => {
                    let mut b = Bits::new(nal)?;
                    b.field = "slice.first_slice_segment_in_pic_flag";
                    if b.read(1)? != 1 {
                        return Err(rejection(
                            "idr.not_first_slice",
                            format!(
                                "nal_index={index} nal_kind={kind} required_first_slice=1 rbsp_bit={}",
                                b.pos
                            ),
                        ));
                    }
                    b.field = "slice.no_output_of_prior_pics_flag";
                    b.read(1)?;
                    b.field = "slice.pps_id";
                    let pps = b.ue(63)?;
                    if next.pps != Some(pps) {
                        return Err(rejection(
                            "idr.pps_reference",
                            format!("slice_pps={pps} current_pps={:?}", next.pps),
                        ));
                    }
                    slices += 1;
                }
                35 | 38 | 39 | 40 => {} // AUD/filler/SEI do not count as decoded pictures.
                _ => {
                    return Err(rejection(
                        "nal.unsupported_type",
                        format!(
                            "index={index} actual_kind={kind} allowed_vcl=19,20 bytes={}",
                            nal.len()
                        ),
                    ));
                }
            }
        }
        if slices != 1 || next.sps.is_none() {
            return Err(rejection(
                "au.picture_count_or_missing_sps",
                format!(
                    "idr_slices={slices} required=1 sps_present={}",
                    next.sps.is_some()
                ),
            ));
        }
        *self = next;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(full_range: bool, depth: u32, matrix: u32) -> Vec<u8> {
        fixture_ptl(full_range, depth, matrix, 1, 120, 0)
    }
    fn fixture_ptl(
        full_range: bool,
        depth: u32,
        matrix: u32,
        profile: u32,
        level: u32,
        layers: u32,
    ) -> Vec<u8> {
        fn bits(out: &mut Vec<u8>, n: usize, v: u32) {
            for shift in (0..n).rev() {
                out.push(((v >> shift) & 1) as u8);
            }
        }
        fn ue(out: &mut Vec<u8>, v: u32) {
            let n = (32 - (v + 1).leading_zeros()) as usize;
            out.extend(std::iter::repeat_n(0, n - 1));
            bits(out, n, v + 1);
        }
        let mut b = Vec::new();
        bits(&mut b, 4, 0);
        bits(&mut b, 3, layers);
        bits(&mut b, 1, 1);
        bits(&mut b, 2, 0);
        bits(&mut b, 1, 0);
        bits(&mut b, 5, profile);
        bits(&mut b, 32, 0);
        bits(&mut b, 32, 0);
        bits(&mut b, 16, 0);
        bits(&mut b, 8, level);
        ue(&mut b, 0);
        ue(&mut b, 1);
        ue(&mut b, 640);
        ue(&mut b, 480);
        bits(&mut b, 1, 0);
        ue(&mut b, depth);
        ue(&mut b, depth);
        ue(&mut b, 4);
        bits(&mut b, 1, 0);
        ue(&mut b, 0);
        ue(&mut b, 0);
        ue(&mut b, 0);
        for _ in 0..6 {
            ue(&mut b, 0);
        }
        bits(&mut b, 1, 0);
        bits(&mut b, 1, 1);
        bits(&mut b, 1, 1);
        bits(&mut b, 1, 0);
        ue(&mut b, 0);
        bits(&mut b, 1, 0);
        bits(&mut b, 1, 1);
        bits(&mut b, 1, 1);
        bits(&mut b, 1, 1);
        bits(&mut b, 1, 0);
        bits(&mut b, 1, 0);
        bits(&mut b, 1, 1);
        bits(&mut b, 3, 5);
        bits(&mut b, 1, u32::from(full_range));
        bits(&mut b, 1, 1);
        bits(&mut b, 8, 1);
        bits(&mut b, 8, 1);
        bits(&mut b, 8, matrix);
        bits(&mut b, 1, 1);
        while b.len() % 8 != 0 {
            b.push(0);
        }
        let raw = b
            .chunks_exact(8)
            .map(|c| c.iter().fold(0, |v, b| (v << 1) | b))
            .collect::<Vec<u8>>();
        let mut nal = vec![0x42, 1];
        let mut zeros = 0;
        for byte in raw {
            if zeros >= 2 && byte <= 3 {
                nal.push(3);
                zeros = 0;
            }
            nal.push(byte);
            zeros = if byte == 0 { zeros + 1 } else { 0 };
        }
        nal
    }
    fn access_unit(sps: Vec<u8>, picture: &[u8]) -> Vec<u8> {
        let mut au = Vec::new();
        for nal in [
            vec![0x40, 1, 0x08],
            sps,
            vec![0x44, 1, 0xe0],
            picture.to_vec(),
        ] {
            au.extend([0, 0, 1]);
            au.extend(nal);
        }
        au
    }
    #[test]
    fn diagnostic_codes_preserve_main8_sdr_and_restricted_sps_rejections() -> io::Result<()> {
        assert!(sps(&fixture(false, 0, 1), 640, 480).is_ok());
        for (nal, code, detail) in [
            (fixture(true, 0, 1), "sps.full_range", "actual=1"),
            (fixture(false, 2, 1), "sps.luma_depth", "minus8=2"),
            (fixture(false, 0, 9), "sps.color", "field=vui.matrix_coeffs"),
            (
                fixture_ptl(false, 0, 1, 2, 120, 0),
                "sps.profile_level",
                "profile=2",
            ),
            (
                fixture_ptl(false, 0, 1, 1, 156, 0),
                "sps.profile_level",
                "level=156",
            ),
            (
                fixture_ptl(false, 0, 1, 1, 120, 1),
                "sps.temporal_sublayers",
                "actual=1",
            ),
        ] {
            let error = sps(&nal, 640, 480)
                .err()
                .ok_or_else(|| io::Error::other("invalid SPS accepted"))?;
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            let text = error.to_string();
            assert!(text.contains(code), "{text}");
            assert!(text.contains(detail), "{text}");
        }
        let error = sps(&fixture(false, 0, 1), 1280, 720)
            .err()
            .ok_or_else(|| io::Error::other("foreign geometry accepted"))?;
        assert!(error.to_string().contains("sps.geometry"));
        let error = sps(&[0x42, 1, 0x01], 640, 480)
            .err()
            .ok_or_else(|| io::Error::other("truncated SPS accepted"))?;
        let text = error.to_string();
        assert!(
            text.contains("bits.bounds")
                && text.contains("rbsp_bit=")
                && text.contains("field=ptl.profile_space"),
            "{text}"
        );
        Ok(())
    }
    #[test]
    fn au_diagnostics_classify_nal_type_slice_count_and_do_not_commit_bad_state() -> io::Result<()>
    {
        let valid = access_unit(fixture(false, 0, 1), &[0x28, 1, 0xb0]);
        let mut validator = Validator::default();
        validator.validate(&valid, 640, 480)?;
        let original = validator
            .info()
            .ok_or_else(|| io::Error::other("missing accepted SPS"))?;
        let mut two = valid.clone();
        two.extend([0, 0, 1, 0x28, 1, 0xb0]);
        for (bad, code) in [
            (
                access_unit(fixture(false, 0, 1), &[0x02, 1, 0xb0]),
                "nal.unsupported_type",
            ),
            (
                access_unit(fixture(false, 0, 1), &[0x28, 2, 0xb0]),
                "nal.header",
            ),
            (
                access_unit(fixture(false, 0, 1), &[0x28, 1, 0x30]),
                "idr.not_first_slice",
            ),
            (two, "au.picture_count_or_missing_sps"),
            (
                access_unit(fixture(false, 0, 9), &[0x28, 1, 0xb0]),
                "sps.color",
            ),
        ] {
            let text = validator
                .validate(&bad, 640, 480)
                .err()
                .ok_or_else(|| io::Error::other("unsupported AU accepted"))?
                .to_string();
            assert!(
                text.contains(code)
                    && text.contains("au_bytes=")
                    && text.contains("nal_count=")
                    && text.contains("first16="),
                "{text}"
            );
            let retained = validator
                .info()
                .ok_or_else(|| io::Error::other("accepted state lost"))?;
            assert_eq!(
                (
                    retained.profile,
                    retained.level,
                    retained.width,
                    retained.height
                ),
                (
                    original.profile,
                    original.level,
                    original.width,
                    original.height
                )
            );
        }
        let mut parameters_only = valid.clone();
        parameters_only.truncate(parameters_only.len() - 6);
        assert!(
            Validator::default()
                .validate(&parameters_only, 640, 480)
                .err()
                .is_some_and(|e| e.to_string().contains("idr_slices=0"))
        );
        Ok(())
    }
    #[test]
    fn restricted_main8_sps_and_explicit_color_conflicts() -> io::Result<()> {
        let info = sps(&fixture(false, 0, 1), 640, 480)?;
        assert_eq!(
            (info.profile, info.level, info.width, info.height),
            (1, 120, 640, 480)
        );
        assert!(sps(&fixture(true, 0, 1), 640, 480).is_err());
        assert!(sps(&fixture(false, 2, 1), 640, 480).is_err());
        assert!(sps(&fixture(false, 0, 9), 640, 480).is_err());
        assert!(sps(&fixture(false, 0, 1), 1280, 720).is_err());
        Ok(())
    }
    #[test]
    fn h264_and_truncated_hevc_are_rejected() {
        let mut v = Validator::default();
        assert!(v.validate(&[0, 0, 1, 0x65, 0x80], 640, 480).is_err());
        assert!(v.validate(&[0, 0, 1, 0x42, 1, 0], 640, 480).is_err());
    }
}

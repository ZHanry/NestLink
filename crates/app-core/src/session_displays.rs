//! Default display set for an already authorized desktop session.
use nestlink_protocol::{
    ContractError,
    native_displays::{
        DISPLAY_TOTAL_BYTES, DisplayDescriptor, validate_candidates, validate_displays,
    },
};

pub(crate) fn default_session_displays(
    candidates: &[DisplayDescriptor],
) -> Result<(Vec<DisplayDescriptor>, u32), ContractError> {
    validate_candidates(candidates)?;
    // Desktop APIs place the primary display at the origin. Fall back to the
    // first stable source for portal and synthetic catalogs without an origin.
    let initial = candidates
        .iter()
        .find(|display| {
            display.left <= 0
                && display.top <= 0
                && i64::from(display.left) + i64::from(display.width) > 0
                && i64::from(display.top) + i64::from(display.height) > 0
        })
        .unwrap_or(&candidates[0]);
    let bytes =
        |display: &DisplayDescriptor| u64::from(display.width) * u64::from(display.height) * 4;
    let mut total = bytes(initial);
    let mut displays = vec![initial.clone()];
    for display in candidates.iter().filter(|d| d.source != initial.source) {
        if total + bytes(display) <= DISPLAY_TOTAL_BYTES {
            total += bytes(display);
            displays.push(display.clone());
        }
    }
    displays.sort_by_key(|display| display.source);
    validate_displays(&displays)?;
    Ok((displays, initial.source))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn display(source: u32, left: i32) -> DisplayDescriptor {
        DisplayDescriptor {
            source,
            left,
            top: 0,
            width: 4096,
            height: 4096,
            label: format!("Display {source}"),
        }
    }

    #[test]
    fn primary_is_initial_even_when_it_is_not_the_first_source() {
        let candidates = [display(1, -4096), display(2, 0)];
        let (allowed, initial) = default_session_displays(&candidates).expect("valid displays");
        assert_eq!(allowed, candidates);
        assert_eq!(initial, 2);
    }

    #[test]
    fn oversized_desktop_keeps_primary_and_a_bounded_stable_subset() {
        let candidates = [display(1, -8192), display(2, -4096), display(3, 0)];
        let (allowed, initial) = default_session_displays(&candidates).expect("bounded displays");
        assert_eq!(initial, 3);
        assert_eq!(allowed, vec![candidates[0].clone(), candidates[2].clone()]);
        assert!(default_session_displays(&[]).is_err());
        assert!(default_session_displays(&[candidates[0].clone(), candidates[0].clone()]).is_err());
    }
}

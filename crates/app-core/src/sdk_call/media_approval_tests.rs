//! Review predicates only. These format fixtures are not hardware evidence.
use super::*;
use nestlink_protocol::{
    Path, Permission,
    media_authority::FrozenMediaScope,
    media_format::{FormatSet, FrameRate, VideoFormat},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn scope() -> Result<FrozenMediaScope> {
    let mut ptl = [0; 12];
    ptl[0] = 1;
    ptl[11] = 120;
    let format = VideoFormat::hevc_main8_observed(ptl, 640, 480, FrameRate::new(30, 1)?, 4000)?;
    let set = FormatSet::new(vec![format])?;
    Ok(FrozenMediaScope {
        version: nestlink_protocol::media_authority::HEVC_FORMAT_VERSION,
        controller_revision: 1,
        host_revision: 2,
        formats: vec![format.encode()?],
        sha256: set.digest().to_vec(),
    })
}
fn view() -> RemoteView {
    RemoteView {
        id: random_id(),
        controller_device_id: random_id(),
        host_device_id: random_id(),
        permissions: vec![Permission::View as i32, Permission::Input as i32],
        paths: vec![Path::Direct as i32],
        nonce: "current-review-nonce".into(),
        policy_revision: 7,
        expires_at_unix_ms: 2000,
        status: "pending".into(),
        lease_sequence: 0,
        connection_generation: 1,
        trust_revision: None,
        password_revision: None,
    }
}
fn choice() -> ApprovalChoice {
    ApprovalChoice {
        approved: true,
        permissions: vec![Permission::View as i32],
        paths: vec![Path::Direct as i32],
    }
}

#[test]
fn review_rejects_changed_nonce_revision_scope_host_state_or_deadline_before_probe() -> Result {
    let view = view();
    let scope = scope()?;
    let choice = choice();
    let check = |current: &RemoteView,
                 local: &str,
                 expected: (&str, u64),
                 current_scope: Option<&FrozenMediaScope>,
                 now| {
        validate_media_review(
            current,
            local,
            expected,
            &choice,
            &scope,
            current_scope,
            now,
        )
    };
    let expected = (view.nonce.as_str(), view.policy_revision);
    assert!(check(&view, &view.host_device_id, expected, Some(&scope), 1000).is_ok());
    assert!(check(&view, &random_id(), expected, Some(&scope), 1000).is_err());
    assert!(
        check(
            &view,
            &view.host_device_id,
            ("old", view.policy_revision),
            Some(&scope),
            1000
        )
        .is_err()
    );
    assert!(
        check(
            &view,
            &view.host_device_id,
            (&view.nonce, 6),
            Some(&scope),
            1000
        )
        .is_err()
    );
    assert!(check(&view, &view.host_device_id, expected, None, 1000).is_err());
    assert!(check(&view, &view.host_device_id, expected, Some(&scope), 2000).is_err());
    let mut replaced = scope.clone();
    replaced.host_revision += 1;
    assert!(check(&view, &view.host_device_id, expected, Some(&replaced), 1000).is_err());
    let mut closed = view.clone();
    closed.status = "approved".into();
    assert!(check(&closed, &view.host_device_id, expected, Some(&scope), 1000).is_err());
    Ok(())
}

#[test]
fn approved_media_requires_view_and_exact_permission_path_subsets() -> Result {
    let view = view();
    let scope = scope()?;
    let check = |choice: &ApprovalChoice| {
        validate_media_review(
            &view,
            &view.host_device_id,
            (&view.nonce, view.policy_revision),
            choice,
            &scope,
            Some(&scope),
            1000,
        )
    };
    assert!(check(&choice()).is_ok());
    for permissions in [
        vec![],
        vec![Permission::Input as i32],
        vec![Permission::View as i32, Permission::FileWrite as i32],
        vec![Permission::View as i32, Permission::View as i32],
        vec![Permission::View as i32, Permission::Unspecified as i32],
        vec![Permission::View as i32, i32::MAX],
    ] {
        assert!(
            check(&ApprovalChoice {
                permissions,
                ..choice()
            })
            .is_err()
        );
    }
    for paths in [
        vec![],
        vec![Path::Relay as i32],
        vec![Path::Direct as i32, Path::Direct as i32],
        vec![i32::MAX],
    ] {
        assert!(check(&ApprovalChoice { paths, ..choice() }).is_err());
    }
    // A local rejection needs no configured GPU or direction probe.
    assert!(
        check(&ApprovalChoice {
            approved: false,
            permissions: vec![],
            paths: vec![]
        })
        .is_ok()
    );
    Ok(())
}

use super::*;
use nestlink_protocol::network::PeerPair;
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn pair() -> Result<(InstallationIdentity, InstallationIdentity, Binding), ContractError> {
    let mut first = InstallationIdentity::generate();
    let mut second = InstallationIdentity::generate();
    if first.fingerprint() > second.fingerprint() { std::mem::swap(&mut first, &mut second); }
    let peers = PeerPair::new(PeerId(first.fingerprint()), PeerId(second.fingerprint()))?;
    Ok((first, second, Binding {
        deployment: [1; 32], space: [2; 32], session: [3; 32], permit: [4; 32],
        path_grant: [5; 32], transport_group: [6; 32], peers,
        original_route: [7; 32], candidate_route: [8; 32],
        original_connection: [9; 32], control_connection: [10; 32],
        business_generation: 11, previous_path_epoch: 12, next_path_epoch: 13,
        expires_at_unix_ms: 20_000,
    }))
}

#[test]
fn bilateral_commit_retries_are_identical_and_old_epoch_has_finite_revocable_grace() -> TestResult {
    let (first, second, binding) = pair()?;
    let mut a = Transcript::new(binding.clone(), binding.peers.first, second.public_key(), 30_000, 10_000)?;
    let mut b = Transcript::new(binding.clone(), binding.peers.second, first.public_key(), 30_000, 10_000)?;
    // Both owners trigger in the same turn. There is exactly one writer.
    assert!(b.propose(&second, 10_000, true).is_err());
    let proposal = a.propose(&first, 10_000, true)?;
    assert_eq!(a.propose(&first, 10_001, true)?, proposal);
    let accepted = b.receive(&second, &proposal, 10_002, true)?.ok_or("missing accepted")?;
    assert_eq!(b.receive(&second, &proposal, 10_003, true)?, Some(accepted.clone()));
    let commit = a.receive(&first, &accepted, 10_004, true)?.ok_or("missing commit")?;
    assert_eq!(a.receive(&first, &accepted, 10_005, true)?, Some(commit.clone()));
    assert!(a.receipt().is_none());
    let committed = b.receive(&second, &commit, 10_006, true)?.ok_or("missing committed")?;
    let drain = b.receipt().ok_or("missing receipt")?.old_path_drain_until_unix_ms;
    // Lost final confirmation is retried with the exact same challenge and
    // never restarts the receive grace.
    assert_eq!(b.receive(&second, &commit, 10_100, true)?, Some(committed.clone()));
    assert_eq!(b.receipt().ok_or("missing receipt")?.old_path_drain_until_unix_ms, drain);
    assert!(a.receive(&first, &committed, 10_101, true)?.is_none());
    let receipt = a.receipt().ok_or("missing receipt")?.clone();
    assert_eq!(receipt.binding.business_generation, 11);
    assert!(receipt.accepts_path_epoch(12, 10_101, true));
    assert!(receipt.accepts_path_epoch(13, 10_351, true));
    assert!(!receipt.accepts_path_epoch(12, 10_351, true));
    assert!(!receipt.accepts_path_epoch(13, 10_102, false));
    assert!(!receipt.accepts_path_epoch(13, 30_000, true));
    assert!(!receipt.accepts_path_epoch(11, 10_102, true));
    assert!(!receipt.accepts_path_epoch(14, 10_102, true));
    Ok(())
}

#[test]
fn mismatched_scope_challenge_signature_and_late_confirmation_cannot_commit() -> TestResult {
    for mutation in 0..8 {
        let (first, second, binding) = pair()?;
        let mut a = Transcript::new(binding.clone(), binding.peers.first, second.public_key(), 30_000, 10_000)?;
        let mut b = Transcript::new(binding.clone(), binding.peers.second, first.public_key(), 30_000, 10_000)?;
        let proposal = a.propose(&first, 10_000, true)?;
        let mut accepted = b.receive(&second, &proposal, 10_001, true)?.ok_or("missing accepted")?;
        match mutation {
            0 => accepted.binding.transport_group[0] ^= 1,
            1 => accepted.binding.original_connection[0] ^= 1,
            2 => accepted.binding.control_connection[0] ^= 1,
            3 => accepted.binding.business_generation += 1,
            4 => accepted.proposal[0] ^= 1,
            5 => accepted.binding.expires_at_unix_ms += 1,
            6 => accepted.kind = Kind::Committed,
            _ => {},
        }
        accepted.signature = second.sign_network_migration(&accepted)?;
        if mutation == 7 { accepted.signature[0] ^= 1; }
        assert!(a.receive(&first, &accepted, 10_002, true).is_err());
        assert!(a.receipt().is_none());
    }
    let (first, second, binding) = pair()?;
    let mut a = Transcript::new(binding.clone(), binding.peers.first, second.public_key(), 30_000, 10_000)?;
    let mut b = Transcript::new(binding.clone(), binding.peers.second, first.public_key(), 30_000, 10_000)?;
    let proposal = a.propose(&first, 10_000, true)?;
    let accepted = b.receive(&second, &proposal, 10_001, true)?.ok_or("missing accepted")?;
    let commit = a.receive(&first, &accepted, 10_002, true)?.ok_or("missing commit")?;
    let committed = b.receive(&second, &commit, 10_003, true)?.ok_or("missing committed")?;
    assert!(a.receive(&first, &committed, 12_000, true).is_err());
    assert_eq!(a.phase(), Phase::Closed);
    assert!(a.receipt().is_none());
    assert!(a.receive(&first, &committed, 12_001, true).is_err());
    Ok(())
}

#[test]
fn revocation_clock_rollback_and_fresh_control_connections_are_independent() -> TestResult {
    let (first, second, binding) = pair()?;
    for mutation in 0..3 {
        let mut a = Transcript::new(binding.clone(), binding.peers.first, second.public_key(), 30_000, 10_000)?;
        let mut b = Transcript::new(binding.clone(), binding.peers.second, first.public_key(), 30_000, 10_000)?;
        let proposal = a.propose(&first, 10_000, true)?;
        let accepted = b.receive(&second, &proposal, 10_001, true)?.ok_or("missing accepted")?;
        let now = if mutation == 0 { 9_999 } else { 10_002 };
        if mutation == 2 { a.expected.control_connection[0] ^= 1; }
        assert!(a.receive(&first, &accepted, now, mutation != 1).is_err());
        assert!(a.receipt().is_none());
    }
    Ok(())
}

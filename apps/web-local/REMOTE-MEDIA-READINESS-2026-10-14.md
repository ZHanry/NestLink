# Browser remote media readiness (2026-10-14)

2026-10-15 status correction: browser input, file and text clipboard workflows are
implemented in the current source. Their authorization, bounded storage, Promise
ownership and actual-browser development evidence are tracked in
[WEB-BUSINESS.md](../../docs/refactor/WEB-BUSINESS.md). The remaining items below
describe product acceptance, and must not be read as missing implementations of
those workflows.

## Current implementation

The web remote-view page now owns the temporary browser endpoint lifecycle: it registers an endpoint, requests host approval, obtains the verified permit, creates the receive-only WebRTC controller peer, displays remote tracks, monitors control/lease state, and revokes the temporary endpoint and session during cleanup. The peer exchanges signed SDP, checks the selected ICE path against the permit, uses trusted managed TURN credentials when relay is allowed, and restarts ICE after a detected network change.

The native SDK contains a host-side WebRTC answerer with mutual endpoint proof and video/audio source binding. `app-core` now includes a browser-host actor, and the current working tree wires host startup/status through the daemon and desktop surfaces. The daemon has Windows and Linux display-capture provider paths for supported desktop environments. These host integration changes are awaiting the root task's consolidated compile and security regression run; code presence is not a platform acceptance result.

Managed TURN now has a complete control path for signed credentials, peer candidate submissions, node resource snapshots, exact peer allowlists, and binding expiry. Each signed peer binding has its own monotonic deadline. A repeated binding does not gain time from later polls, an omitted binding clears forwarding authority, and the service closes an active allocation after binding expiry while preserving the separate TURN grant lease.

## Remaining acceptance gaps

- Input, file transfer and clipboard need acceptance with an installed native host
  using the same frozen artifacts and supported stable browsers.
- No real browser-to-native-host media end-to-end acceptance run has been completed. Codec negotiation, screen/audio capture, page lifecycle, and relay behavior still need validation with actual browser and host devices.
- The current capture path uses its configured/default display source; display selection UI and multi-monitor choice are not provided.
- Windows, X11, and Wayland capture behavior needs runtime validation on each supported host environment. A successful cross-target compile does not establish capture permissions or device behavior.
- Public TURN DNS, firewall/NAT routing, certificates, and external-network reachability remain deployment checks. The sample configuration does not prove those external conditions.

## Verification boundary

The managed browser TURN/wasm path passed an earlier checkpoint. The peer-binding deadline work and recent host actor/provider wiring still require the root task's consolidated Rust checks. The repository has focused signaling, identity, TURN service, and host-peer tests, but those are not a real browser-to-host media test. Windows signing, Android signing/device checks, and external-network acceptance depend on the separately documented certificates and test equipment; Android 10 is outside the requested acceptance scope.

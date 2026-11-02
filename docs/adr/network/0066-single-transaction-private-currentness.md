# ADR 0066: Reuse one verified lease in each current authority readback

Status: implemented; awaiting exact-source GitHub-hosted validation.

The release-profile origin-window observation at source 8a35c4e, run
41441918578, kept the original 100 enrolled installations, 20 pairs, 1000-target
simultaneous assertion, three waves, signed lease duration and three-second
handshakes. It reached 598 ready application flows before original authority
expired. It remains failed, separately from the original pair-window burst.
No complete wave or capacity qualification follows from those observations.

The production current-private-service HTTP handler previously read the same
immutable business lease once directly and a second time inside the network
path readback. The lease helper itself verified its returned signed bytes again,
and the network helper verified them once more. This duplicated database policy
reads and signature verification within one serialized Store request. None of
those repetitions could observe an intervening management mutation.

Reuse the existing sealed VerifiedPrivateServiceLease within that single call.
The same original stored bytes are verified once. The original login, account,
host/consumer membership, approval, exact ACL, selected path, policy epoch,
original signed deadline, network snapshot and relay checks all still execute.
One immediate SQLite transaction produces the signed lease and network path.
The existing standalone lease and path APIs delegate to the same helpers and
retain their wire output. The HTTP response shape and delegation remain intact.

There is no cache, new dependency, background worker, mutation retry, extended
authority or altered admission budget. Every later request independently reads
the current database. Both sides of each application handshake still recheck
current authority before and after proof. A shared cached response or removing
those checks would change revocation behavior and is rejected. Increasing the
original handshake or lease deadline would change the retained experiment.

The new storage regression compares the complete original signed lease and
network bytes, then requires expiry, a corrupted stored signature and ACL
revocation to fail while the original cumulative reservation remains held.
Existing real HTTP/Quinn private-service, multiplex and relay regressions retain
their original assertions. All automated validation runs on GitHub-hosted
Actions. This implementation alone demonstrates no latency or capacity result.

package com.zhanry.nestlink

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BrowserHostDataTest {
    private val request = "00000000-0000-0000-0000-000000000001"
    private val session = "00000000-0000-0000-0000-000000000002"
    private val replacement = "00000000-0000-0000-0000-000000000005"
    private fun proof(session: String = this.session, digest: Int = 3): String = JSONObject()
        .put("request_id", request).put("session_id", session)
        .put("controller_device_id", "00000000-0000-0000-0000-000000000003").put("host_device_id", "00000000-0000-0000-0000-000000000004")
        .put("controller_key_sha256", JSONArray(List(32) { 1 }))
        .put("host_key_sha256", JSONArray(List(32) { 2 }))
        .put("permit_sha256", JSONArray(List(32) { digest }))
        .put("connection_generation", 8L).toString()
    private fun binding(session: String = this.session, digest: Int = 3) =
        HostCaptureBinding.BrowserHost(request, 8L, proof(session, digest))

    @Test fun grantIsOneUseAndCannotCrossDirection() {
        val owner = binding()
        val grant = BrowserSafGrantRegistry().issue(12, owner, BrowserSafDirection.Share)
        assertTrue(grant.consume(12, owner, BrowserSafDirection.Share))
        assertFalse(grant.consume(12, owner, BrowserSafDirection.Share))
        val wrong = BrowserSafGrantRegistry().issue(12, owner, BrowserSafDirection.Export, "received-artifact")
        assertFalse(wrong.consume(12, owner, BrowserSafDirection.Share))
        assertFalse(wrong.consume(12, owner, BrowserSafDirection.Export))
    }

    @Test fun completeProofAndOwnerTagFenceSameRequestAndGeneration() {
        val owner = binding()
        for (replacement in listOf<HostCaptureBinding>(binding(replacement), binding(digest = 9), HostCaptureBinding.NativeSession(owner.requestId, owner.connectionGeneration, owner.bindingJson))) {
            val grant = BrowserSafGrantRegistry().issue(12, owner, BrowserSafDirection.Share)
            assertFalse(grant.consume(12, replacement, BrowserSafDirection.Share))
        }
        assertFalse(BrowserSafGrantRegistry().issue(12, owner, BrowserSafDirection.Share).consume(13, owner, BrowserSafDirection.Share))
    }

    @Test fun oldPickerBlocksNewPickerUntilItsOwnResultIsConsumed() {
        val registry = BrowserSafGrantRegistry()
        val old = registry.issue(12, binding(), BrowserSafDirection.Export, "received")
        assertTrue(registry.hasPending())
        assertTrue(runCatching { registry.issue(12, binding(replacement), BrowserSafDirection.Share) }.isFailure)
        assertEquals(null, registry.take(BrowserSafDirection.Share))
        assertEquals(old, registry.take(BrowserSafDirection.Export))
        assertFalse(old.consume(12, binding(replacement), BrowserSafDirection.Export))
        assertFalse(registry.hasPending())
        registry.issue(12, binding(replacement), BrowserSafDirection.Share)
    }

    @Test fun exportRequiresAnArtifactAndShareCannotSmuggleAnArtifact() {
        assertTrue(runCatching { BrowserSafGrantRegistry().issue(12, binding(), BrowserSafDirection.Export) }.isFailure)
        assertTrue(runCatching { BrowserSafGrantRegistry().issue(12, binding(), BrowserSafDirection.Share, "unexpected") }.isFailure)
    }

    @Test fun everyDigestAndSessionIsPartOfProof() {
        val full = proof()
        assertTrue(sameBrowserProofJson(full, JSONObject(full).toString()))
        assertFalse(sameBrowserProofJson(full, proof(replacement)))
        for (hash in listOf("controller_key_sha256", "host_key_sha256", "permit_sha256")) {
            val changed = JSONObject(full).put(hash, JSONArray(List(32) { 7 })).toString()
            assertFalse(sameBrowserProofJson(full, changed))
            val validByte = JSONObject(full).getJSONArray(hash).getLong(0)
            for (overflow in listOf(validByte + 0x1_0000_0000L, validByte - 0x1_0000_0000L)) {
                val malformed = JSONObject(full).put(hash, JSONArray(List(32) { overflow })).toString()
                assertFalse(sameBrowserProofJson(full, malformed))
                assertFalse(sameBrowserProofJson(malformed, full))
                assertFalse(HostCaptureBinding.BrowserHost(request, 8L, malformed).hasExactProof())
            }
        }
        assertFalse(sameBrowserProofJson(full, JSONObject(full).put("core_generation", 99).toString()))
        assertFalse(sameBrowserProofJson(full, JSONObject(full).put("permit_sha256", JSONArray(List(31) { 3 })).toString()))
    }

    @Test fun localBindingWrapperCannotRenameAnOtherwiseMatchingProof() {
        val valid = binding()
        val wrongRequest = valid.copy(requestId = replacement)
        val wrongGeneration = valid.copy(connectionGeneration = valid.connectionGeneration + 1)
        for (wrong in listOf(wrongRequest, wrongGeneration)) {
            assertFalse(wrong.hasExactProof())
            assertTrue(runCatching { BrowserSafGrantRegistry().issue(12, wrong, BrowserSafDirection.Share) }.isFailure)
        }
        assertTrue(valid.hasExactProof())
        assertFalse(sameBrowserProofJson(valid.bindingJson, JSONObject(valid.bindingJson).put("connection_generation", "8").toString()))
        assertFalse(sameBrowserProofJson(valid.bindingJson, JSONObject(valid.bindingJson).put("permit_sha256", JSONArray(List(32) { "3" })).toString()))
    }

    @Test fun browserFileStatusRejectsNativeIdentityAndReplacementProof() {
        val owner = binding()
        val payload = JSONObject().put("identity", JSONObject().put("browser_binding", JSONObject(owner.bindingJson)))
            .put("receive_approved", false).put("reserved_bytes", 3)
            .put("artifacts", JSONArray().put(JSONObject().put("id", "received").put("kind", "receive").put("display_name", "a.txt")
                .put("phase", "received").put("size", 3).put("published", true).put("verified", true).put("owner_stopped", true).put("cleanup_pending", false)
                .put("error", JSONObject.NULL).put("cleanup_error", JSONObject.NULL)))
            .put("exports", JSONArray())
        assertTrue(parseBrowserHostFiles(payload.toString(), owner).artifacts.single().canExport())
        assertTrue(runCatching { parseBrowserHostFiles(payload.toString(), binding(replacement)) }.isFailure)
        payload.put("identity", JSONObject().put("binding", JSONObject().put("request_id", owner.requestId).put("connection_generation", owner.connectionGeneration)).put("core_generation", 9))
        assertTrue(runCatching { parseBrowserHostFiles(payload.toString(), owner) }.isFailure)
    }

    @Test fun localClipboardSelectionCannotExceedSignedDirection() {
        val owner = binding()
        val data = JSONObject().put("files_available", true).put("clipboard_available", true)
            .put("permitted_file_read", true).put("permitted_file_write", false)
            .put("permitted_clipboard_read", true).put("permitted_clipboard_write", false)
            .put("local_clipboard_read", true).put("local_clipboard_write", false).put("clipboard_restart_required", false)
        val payload = JSONObject().put("binding", JSONObject(owner.bindingJson)).put("data", data)
        assertTrue(parseBrowserHostData(payload.toString(), owner).localRead)
        data.put("local_clipboard_write", true)
        assertTrue(runCatching { parseBrowserHostData(payload.toString(), owner) }.isFailure)
    }

    @Test fun latePickerDoesNotTouchAProviderWhenLiveDirectionEndedBeforeCorePublication() {
        for (direction in listOf(BrowserSafDirection.Share, BrowserSafDirection.Export)) {
            val owner = binding()
            val grant = BrowserSafGrantRegistry().issue(12, owner, direction, if (direction == BrowserSafDirection.Export) "received" else null)
            assertTrue(grant.consume(12, owner, direction))
            val coreStillConnected = owner.hasExactProof()
            var liveDirection = false
            var providerCalls = 0
            val authorize = { coreStillConnected && liveDirection }
            for (providerOperation in listOf("query", "open", "fstat", "detach")) {
                assertTrue(runCatching { browserSafProviderCall(authorize) { providerCalls++; providerOperation } }.isFailure)
            }
            assertEquals(0, providerCalls)
            liveDirection = true
            assertEquals("authorized", browserSafProviderCall(authorize) { providerCalls++; "authorized" })
            assertEquals(1, providerCalls)
            liveDirection = false
            assertTrue(runCatching { browserSafProviderCall(authorize) { providerCalls++ } }.isFailure)
            assertEquals(1, providerCalls)
        }
    }

    @Test fun failedCreatedTargetIsRetainedForMissingGrantReplacementAndNoCurrentBinding() {
        for (scenario in listOf("missing-grant", "replaced-owner", "no-current-binding")) {
            val grant = if (scenario == "missing-grant") null else BrowserSafGrantRegistry().issue(12, binding(), BrowserSafDirection.Export, "received")
            val callbackOwner = when (scenario) {
                "replaced-owner" -> binding(replacement)
                "no-current-binding" -> null
                else -> binding()
            }
            assertFalse(grant?.consume(12, callbackOwner, BrowserSafDirection.Export) == true)
            val targets = BrowserSafCleanupRegistry<String>()
            val originHandle = grant?.handle ?: 0L
            val retained = requireNotNull(targets.retain(originHandle, "created-local-uri", "chosen.txt"))
            assertEquals(null, targets.retain(originHandle, "created-local-uri", "duplicate callback"))
            val receipt = cleanupCreatedSafDestination(deleteDocument = { false }, clearDocument = { error("provider refused cleanup") })
            assertFalse(receipt.complete)
            targets.finish(retained.id, receipt)
            assertTrue(targets.hasRetained())
            assertEquals("created-local-uri", targets.state.value.single().target)
            assertEquals(receipt.detail, targets.state.value.single().detail)
            assertEquals(retained.id, targets.retry(retained.id)?.id)
            assertEquals(null, targets.retry(retained.id))
            targets.finish(retained.id, SafDestinationCleanupReceipt(true, "deleted after retry"))
            assertFalse(targets.hasRetained())
        }
    }

    @Test fun submittedExportKeepsCleanupReceiptUntilRealJoinAndFailedCleanupCanRetryAfterClose() {
        val targets = BrowserSafCleanupRegistry<String>()
        val retained = requireNotNull(targets.retain(12, "export-local-uri", "received.txt"))
        val terminal = NativeSafExportRow(exportId = "export", phase = "cancelled", copiedBytes = 0, totalBytes = 3, error = null, ownerStopped = false, destinationCleanupComplete = false, destinationCleanupError = "provider refused cleanup")
        assertFalse(targets.observe(retained.id, terminal))
        assertEquals(null, targets.retry(retained.id))
        assertTrue(targets.state.value.single().busy)
        assertTrue(targets.observe(retained.id, terminal.copy(ownerStopped = true)))
        // The native worker/handle may now close; the independent target remains.
        assertTrue(targets.hasRetained())
        assertFalse(targets.state.value.single().busy)
        assertEquals("provider refused cleanup", targets.state.value.single().detail)
        assertEquals(retained.id, targets.retry(retained.id)?.id)
        targets.finish(retained.id, SafDestinationCleanupReceipt(false, "still blocked"))
        assertTrue(targets.hasRetained())
        assertEquals(retained.id, targets.retry(retained.id)?.id)
        targets.finish(retained.id, SafDestinationCleanupReceipt(true, "cleared and synced"))
        assertTrue(targets.state.value.isEmpty())
    }
}

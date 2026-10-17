package com.zhanry.nestlink

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ServiceManagementTest {
    private val context = ServiceContextRow(7, "account-a", "session-a")
    private val draft = ServiceEditorDraft(
        id = "service-one", name = "Home app", hostDeviceId = "host-two", edgeNodeId = "edge-one",
        ingress = "29100", sources = "192.0.2.0/24\n2001:db8::/32",
    )
    private fun row(revision: Long = 3, definition: ServiceDefinitionRow = draft.definition(), approval: String = "pending") =
        ServiceRow(draft.id, revision, definition, approval, "not_published", null, null)
    private fun responseJson(service: ServiceRow = row(), status: String = "succeeded", effect: String = "none"): JSONObject {
        val definition = service.definition.json()
        val record = JSONObject().put("id", service.id).put("revision", service.revision).put("definition", definition)
            .put("approval", service.approval).put("publication", service.publication)
            .put("target_id", JSONObject.NULL).put("approval_expires_at_unix_ms", JSONObject.NULL)
        return JSONObject().put("context", context.json()).put("snapshot_revision", 21)
            .put("services", JSONObject().put("data", JSONObject().put("security_epoch", 2)
                .put("services", org.json.JSONArray().put(record)).put("next_id", JSONObject.NULL).put("more", false))
                .put("loading", JSONObject.NULL).put("error", JSONObject.NULL))
            .put("selected_service", JSONObject().put("data", record).put("loading", JSONObject.NULL).put("error", JSONObject.NULL))
            .put("operation", JSONObject().put("id", 11).put("status", status).put("remote_effect", effect)
                .put("failure", JSONObject.NULL))
    }

    @Test
    fun createEncodesTheStableIdAndIndependentAclWithoutTargetAuthority() {
        val first = draft.command()
        val retry = draft.command()
        assertEquals("create_service", first.getString("action"))
        val create = first.getJSONObject("parameters").getJSONObject("create")
        assertEquals("service-one", create.getString("id"))
        assertEquals(create.getString("id"), retry.getJSONObject("parameters").getJSONObject("create").getString("id"))
        val definition = create.getJSONObject("definition")
        assertEquals(2, definition.getJSONArray("allowed_sources").length())
        assertFalse(definition.has("target"))
        assertFalse(definition.has("local_target"))
        assertFalse(definition.has("approved"))
        assertEquals(0, draft.copy(sources = "").command().getJSONObject("parameters").getJSONObject("create").getJSONObject("definition").getJSONArray("allowed_sources").length())
    }

    @Test
    fun publicationAndApprovalRemainIndependentRealResponseFacts() {
        val parsed = parseServiceManagement(responseJson(row(approval = "approved_target")).toString())
        val actual = requireNotNull(parsed.selected)
        assertEquals("目标已批准", serviceApprovalLabel(actual.approval))
        assertEquals("未发布", servicePublicationLabel(actual.publication))
        assertTrue(servicePublicationLabel("published_elsewhere").contains("待核验"))
        assertEquals(context, parsed.context)
    }

    @Test
    fun committedMutationWithFailedRefreshReconcilesOnlyItsActualDefinition() {
        val response = parseServiceManagement(responseJson(row(9), "failed", "committed").toString())
        val reconciled = draft.reconcile(response)
        assertEquals(9L, reconciled.revision)
        assertEquals(draft.id, reconciled.id)
        assertEquals(draft.name, reconciled.name)
        assertTrue(reconciled.unchanged())
        assertTrue(response.operation.notice().contains("配置已经保存"))
        val update = reconciled.copy(name = "Updated name").command()
        assertEquals("update_service", update.getString("action"))
        assertEquals(9L, update.getJSONObject("parameters").getJSONObject("update").getLong("expected_revision"))
    }

    @Test
    fun responseLossKeepsTheSameCreateAndAllInput() {
        val original = draft.copy(name = "A retained draft")
        val unresolved = parseServiceManagement(responseJson(row(), "failed", "unknown").toString())
        val kept = original.reconcile(unresolved)
        assertEquals(original, kept)
        assertNull(kept.revision)
        assertTrue(unresolved.operation.notice().contains("尚未确认"))
        assertEquals("create_service", kept.command().getString("action"))
    }

    @Test
    fun otherIdsDefinitionsRevocationsAndOlderRevisionsCannotOverwriteEditor() {
        val editing = ServiceEditorDraft.edit(row(8)).copy(name = "Unsent edit")
        for (candidate in listOf(
            row(9), row(9, editing.definition(), "revoked"), row(7, editing.definition()),
            row(9, editing.definition()).copy(id = "different-service"),
        )) {
            assertEquals(editing, editing.reconcile(parseServiceManagement(responseJson(candidate).toString())))
        }
    }

    @Test
    fun commandEnvelopeCarriesExactCoreAccountSessionAndPaginationContext() {
        val request = JSONObject(serviceRequest(context, serviceListCommand("service-one")))
        assertEquals("session-a", request.getJSONObject("context").getString("session_id"))
        assertEquals(7L, request.getJSONObject("context").getLong("generation"))
        assertEquals("service-one", request.getJSONObject("command").getJSONObject("parameters").getString("after_id"))
        assertTrue(JSONObject(serviceRequest(null, serviceListCommand())).isNull("context"))
    }

    @Test
    fun serviceReplyMustMatchHandleAccountSessionAndGenerationAtUiApplication() {
        val binding = ServiceActionBinding(handle = 42L, context = context, authRevision = 5L)
        fun current(
            responseContext: ServiceContextRow = context,
            liveContext: ServiceContextRow = context,
            handle: Long = 42L,
            accountId: String = "account-a",
            uiContext: ServiceContextRow? = context,
            authRevision: Long = 5L,
        ) = serviceResponseIsCurrent(
            binding, responseContext, liveContext, handle, accountId, uiContext, authRevision,
        )

        assertTrue(current())
        val loggedInAgain = context.copy(sessionId = "session-b", generation = 8L)
        assertFalse(current(liveContext = loggedInAgain))
        assertFalse(current(responseContext = loggedInAgain))
        assertFalse(current(uiContext = loggedInAgain))
        assertFalse(current(liveContext = context.copy(generation = 8L)))
        assertFalse(current(handle = 43L))
        assertFalse(current(accountId = "account-b"))
        assertFalse(current(authRevision = 6L))
    }

    @Test
    fun serviceContextQueryPreservesSessionAndGeneration() {
        assertEquals(context, parseServiceContext(context.json().toString()))
        assertThrows(IllegalArgumentException::class.java) {
            parseServiceContext(context.json().put("generation", 0).toString())
        }
    }

    @Test
    fun malformedPaginationCannotBeDisplayedAsACompleteSuccessfulPage() {
        val response = responseJson()
        response.getJSONObject("services").getJSONObject("data").put("more", true)
        assertThrows(IllegalArgumentException::class.java) { parseServiceManagement(response.toString()) }
    }

    @Test
    fun structuredFailuresAreKeptAndBadFormNumbersDoNotBecomeDefaults() {
        val response = responseJson(status = "failed")
        response.getJSONObject("operation").put("failure", JSONObject().put("kind", "rejected").put("code", "revision_conflict"))
        assertTrue(requireNotNull(parseServiceManagement(response.toString()).operation.failure).contains("revision_conflict"))
        assertThrows(IllegalStateException::class.java) { draft.copy(bytesPerSecond = "not a number").command() }
        assertThrows(IllegalArgumentException::class.java) { draft.copy(sources = "not-cidr").command() }
    }
}

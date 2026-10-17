package com.zhanry.nestlink

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.Rule
import org.junit.rules.TemporaryFolder
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.io.FileInputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class NativeFileStateTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()
    private val identityJson = """
        {"identity":{"binding":{"request_id":"request-1","connection_generation":9},"core_generation":12},"read":true,"write":true,"host":false}
    """.trimIndent()

    @Test
    fun identityParserKeepsOnlyTheCoreIdentityForJniCalls() {
        val identity = requireNotNull(parseNativeFileSessionIdentity(identityJson))
        assertEquals("request-1", identity.requestId)
        assertEquals(9L, identity.connectionGeneration)
        assertEquals(12L, identity.coreGeneration)
        assertTrue(identity.canRead)
        assertTrue(identity.canWrite)
        assertFalse(identity.identityJson.contains("\"read\""))
        assertNull(parseNativeFileSessionIdentity(null))
        assertNull(parseNativeFileSessionIdentity("{"))
    }

    @Test
    fun identitiesFromReplacedSessionGenerationsDoNotCompareEqual() {
        val original = requireNotNull(parseNativeFileSessionIdentity(identityJson))
        val replacement = requireNotNull(
            parseNativeFileSessionIdentity(identityJson.replace("\"core_generation\":12", "\"core_generation\":13")),
        )
        assertNotEquals(original, replacement)
    }

    @Test
    fun parsesRemoteRootsAndRejectsMalformedRootPayloads() {
        assertEquals(
            listOf(NativeFileRootRow("root-1", "用户文件")),
            parseNativeFileRoots("""{"roots":[{"root_id":"root-1","display_name":"用户文件"}]}"""),
        )
        runCatching { parseNativeFileRoots("{}") }.onSuccess { error("missing roots must fail closed") }
    }

    @Test
    fun directoryPagesMustMatchTheActiveRequestAndConnectionGeneration() {
        val identity = requireNotNull(parseNativeFileSessionIdentity(identityJson))
        val page = parseNativeFileBrowsePage(
            """{"session":{"request_id":"request-1","connection_generation":9},"browse_id":"browse-1","root_id":"root-1","directory":"资料","snapshot_id":"snapshot-1","offset":0,"total_entries":2,"has_more":false,"entries":[{"name":"子目录","directory":true,"size":null,"modified_unix_ms":0},{"name":"笔记.txt","directory":false,"size":1024,"modified_unix_ms":1}]}""",
            identity,
        )
        assertEquals("browse-1", page.browseId)
        assertEquals("snapshot-1", page.snapshotId)
        assertEquals(2, page.entries.size)
        assertTrue(page.entries[0].directory)
        assertEquals(1024L, page.entries[1].size)

        val stale = """{"session":{"request_id":"request-1","connection_generation":8},"browse_id":"browse-1","root_id":"root-1","directory":"","snapshot_id":"snapshot-1","offset":0,"total_entries":0,"has_more":false,"entries":[]}"""
        assertTrue(runCatching { parseNativeFileBrowsePage(stale, identity) }.isFailure)
    }

    @Test
    fun taskAndSafExportParsersKeepProgressAndTerminalState() {
        val task = parseNativeFileTask(
            """{"task_id":"task-1","kind":"download","phase":"completed","confirmed_bytes":2048,"total_bytes":2048,"finished":true,"error":null}""",
            "archive.zip",
        )
        assertEquals("archive.zip", task.displayName)
        assertEquals("completed", task.phase)
        assertEquals(2048L, task.confirmedBytes)
        assertTrue(task.finished)

        val closingTask = parseNativeFileTask(
            """{"task_id":"task-2","kind":"download","phase":"cancelled","confirmed_bytes":0,"total_bytes":null,"finished":true,"owner_stopped":false,"error":null}""",
            "partial.zip",
        )
        assertTrue(closingTask.finished)
        assertFalse(closingTask.ownerStopped)
        assertFalse(MobileState(fileTask = closingTask).canStartAnotherFileTask())

        val export = parseNativeSafExport(
            """{"export_id":"export-1","phase":"running","copied_bytes":512,"total_bytes":2048,"error":null,"private_cleanup_complete":false,"private_cleanup_error":null,"destination_cleanup_complete":false,"destination_cleanup_error":null}""",
            "task-1",
        )
        assertEquals("export-1", export.exportId)
        assertEquals("task-1", export.taskId)
        assertEquals(512L, export.copiedBytes)
        assertEquals(2048L, export.totalBytes)
        assertFalse(export.privateCleanupComplete)
        assertFalse(export.destinationCleanupComplete)
        assertFalse(export.ownerStopped)
        assertTrue(export.ownerRetained())
    }

    @Test
    fun pathAndDocumentNameHelpersKeepSafInputsPortable() {
        assertEquals("", parentRemoteDirectory("folder"))
        assertEquals("a", parentRemoteDirectory("a/b"))
        assertEquals("a/b/c.txt", remoteChildPath("a/b", "c.txt"))
        assertTrue(isPortableDocumentName("报告 2026.txt"))
        assertFalse(isPortableDocumentName("../outside"))
        assertFalse(isPortableDocumentName(" padded "))
        assertEquals("1.0 KiB", formatFileBytes(1024))
    }

    @Test
    fun completedPrivateDownloadsRemainAvailableWhileTheNextTransferStarts() {
        val task = NativeFileTaskRow("task-1", "download", "archive.zip", "completed", 10, 10, true, null)
        assertTrue(MobileState(fileTask = task).canStartAnotherFileTask())
        assertFalse(
            MobileState(
                fileTask = task,
                fileTasks = listOf(task, task.copy(taskId = "task-2", finished = false, phase = "running")),
            ).canStartAnotherFileTask(),
        )
        assertFalse(
            MobileState(
                fileTask = task,
                safExport = NativeSafExportRow("export-1", "running", 10, 10, null),
            ).canStartAnotherFileTask(),
        )
        assertTrue(
            MobileState(
                fileTask = task,
                safExport = NativeSafExportRow("export-1", "completed", 10, 10, null, ownerStopped = true),
            ).canStartAnotherFileTask(),
        )
    }

    @Test
    fun terminalSafStatusDoesNotReleaseTheOwnerBeforeActualJoin() {
        val task = NativeFileTaskRow("task-1", "download", "archive.zip", "completed", 10, 10, true, null)
        for (phase in listOf("completed", "cancelled", "failed")) {
            val terminal = parseNativeSafExport(
                """{"export_id":"export-1","phase":"$phase","copied_bytes":10,"total_bytes":10,"error":null,"owner_stopped":false,"private_cleanup_complete":false,"private_cleanup_error":null,"destination_cleanup_complete":true,"destination_cleanup_error":null}""",
                task.taskId,
            )
            assertTrue(terminal.ownerRetained())
            assertFalse(MobileState(fileTasks = listOf(task), fileExports = mapOf(task.taskId to terminal)).canStartAnotherFileTask())

            val joined = parseNativeSafExport(
                """{"export_id":"export-1","phase":"$phase","copied_bytes":10,"total_bytes":10,"error":null,"owner_stopped":true,"private_cleanup_complete":false,"private_cleanup_error":"private cleanup must be retried","destination_cleanup_complete":true,"destination_cleanup_error":null}""",
                task.taskId,
            )
            assertTrue(joined.ownerStopped)
            assertFalse(joined.ownerRetained())
            assertFalse(joined.privateCleanupComplete)
            assertEquals("private cleanup must be retried", joined.privateCleanupError)
            assertTrue(MobileState(fileTasks = listOf(task), fileExports = mapOf(task.taskId to joined)).canStartAnotherFileTask())
        }

        val withoutJoinReceipt = parseNativeSafExport(
            """{"export_id":"export-1","phase":"completed","copied_bytes":10,"total_bytes":10,"error":null}""",
        )
        assertTrue(withoutJoinReceipt.ownerRetained())
    }

    @Test
    fun safStartupCleanupFallsBackToClearingAndKeepsFailureHonest() {
        var cleared = false
        val deleted = cleanupCreatedSafDestination({ true }, { cleared = true })
        assertTrue(deleted.complete)
        assertFalse(cleared)
        assertTrue(deleted.detail.contains("已删除"))

        val truncated = cleanupCreatedSafDestination({ error("provider cannot delete") }, { cleared = true })
        assertTrue(truncated.complete)
        assertTrue(cleared)
        assertTrue(truncated.detail.contains("为空文件"))

        val failed = cleanupCreatedSafDestination({ false }, { error("provider cannot truncate") })
        assertFalse(failed.complete)
        assertTrue(failed.detail.contains("未能确认"))
    }

    @Test
    fun safPreparationKeepsTheSameFileOwnerAcrossShutdownTimeout() = runBlocking {
        val handle = 91_003L
        val source = temporaryFolder.newFile("saf-preparation.bin")
        val acquired = CountDownLatch(1)
        val release = CountDownLatch(1)
        val fileClosed = AtomicBoolean()
        val actualWorker = launch(NonCancellable + Dispatchers.IO, start = CoroutineStart.LAZY) {
            FileInputStream(source).use {
                acquired.countDown()
                check(release.await(5, TimeUnit.SECONDS)) { "fixture file owner was not released" }
            }
            fileClosed.set(true)
        }
        NativeSafPickerOwners.retain(handle, actualWorker)
        actualWorker.start()
        try {
            assertTrue(acquired.await(5, TimeUnit.SECONDS))
            NativeSafPickerOwners.beginClose(handle)
            val pending = runCatching { NativeSafPickerOwners.awaitAllStopped(50L) }.exceptionOrNull()
            assertTrue(pending is IllegalStateException)
            assertTrue(NativeSafPickerOwners.isClosing(handle))
            assertTrue(NativeSafPickerOwners.hasRetainedOwners())
            assertFalse(actualWorker.isCompleted)
            assertFalse(fileClosed.get())
            assertFalse(MobileState().canStartAnotherFileTask())
            assertTrue(runCatching { NativeSafPickerOwners.completeClose(handle) }.isFailure)

            release.countDown()
            NativeSafPickerOwners.awaitAllStopped()
            NativeSafPickerOwners.completeClose(handle)
            assertTrue(fileClosed.get())
            assertTrue(actualWorker.isCompleted)
            assertFalse(NativeSafPickerOwners.isClosing(handle))
            assertFalse(NativeSafPickerOwners.hasRetainedOwners())
        } finally {
            release.countDown()
            actualWorker.join()
            NativeSafPickerOwners.completeClose(handle)
        }
    }

    @Test
    fun taskHistoryRetainsUnexportedDownloadsAndUpdatesByTaskId() {
        val completed = NativeFileTaskRow("task-1", "download", "archive.zip", "completed", 10, 10, true, null)
        val started = MobileState().withNativeFileTask(completed, selectLatest = true)
        val updated = started.withNativeFileTask(completed.copy(confirmedBytes = 10))
        assertEquals(listOf(completed.copy(confirmedBytes = 10)), updated.fileTasks)
        assertEquals("task-1", updated.fileTask?.taskId)
    }
}

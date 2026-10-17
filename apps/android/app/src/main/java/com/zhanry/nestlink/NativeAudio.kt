package com.zhanry.nestlink

import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioPlaybackCaptureConfiguration
import android.media.AudioTimestamp
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import android.media.projection.MediaProjection
import android.os.Process
import androidx.annotation.Keep
import java.util.ArrayDeque
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.math.max

internal const val NATIVE_AUDIO_RATE = 48_000
internal const val NATIVE_AUDIO_CHANNELS = 2
internal const val NATIVE_AUDIO_CHUNK_FRAMES = 960
internal const val NATIVE_AUDIO_PCM_BYTES = NATIVE_AUDIO_CHUNK_FRAMES * NATIVE_AUDIO_CHANNELS * 2
internal const val NATIVE_AUDIO_CAPTURE_PACKET_BYTES = 16 + NATIVE_AUDIO_PCM_BYTES
internal const val NATIVE_AUDIO_QUEUE_CHUNKS = 5

/** Thread-safe queue shared by Kotlin audio workers and the synchronous JNI device adapter. */
internal class BoundedAudioPcmQueue(
    private val packetBytes: Int,
    private val capacity: Int = NATIVE_AUDIO_QUEUE_CHUNKS,
) {
    private val packets = ArrayDeque<ByteArray>(capacity)
    private var accepting = true
    private var dropped = 0L

    init {
        require(packetBytes > 0)
        require(capacity in 1..NATIVE_AUDIO_QUEUE_CHUNKS)
    }

    @Synchronized
    fun offer(packet: ByteArray): Boolean {
        if (!accepting || packet.size != packetBytes) return false
        if (packets.size == capacity) {
            packets.removeFirst().fill(0)
            dropped++
        }
        packets.addLast(packet.copyOf())
        return true
    }

    @Synchronized
    fun poll(): ByteArray? = packets.pollFirst()

    @Synchronized
    fun stopAndClear() {
        accepting = false
        while (packets.isNotEmpty()) packets.removeFirst().fill(0)
    }

    @Synchronized
    fun size(): Int = packets.size

    @Synchronized
    fun droppedPackets(): Long = dropped

    @Synchronized
    fun isAccepting(): Boolean = accepting
}

/** Stable public JVM methods are called by android-bridge through JNI. */
abstract class NativeAudioEndpoint(
    private val boundRequestId: String,
    private val boundConnectionGeneration: Long,
    private val boundRole: String,
    private val captureLeaseActive: () -> Boolean = { true },
) {
    @Volatile protected var active = true
        private set
    private var cleanupComplete = false
    private var cleanupAttempts = 0
    private var cleanupFailureObserved = false
    private var lastCleanupFailure: String? = null

    @Keep
    fun isActive(): Boolean {
        if (!active) return false
        if (!runCatching(captureLeaseActive).getOrDefault(false)) {
            active = false
            return false
        }
        return active
    }

    @Keep
    fun matchesBinding(requestId: String, connectionGeneration: Long, role: String): Boolean =
        requestId == boundRequestId && connectionGeneration == boundConnectionGeneration && role == boundRole

    @Keep
    open fun pollCaptureChunk(): ByteArray? = null

    @Keep
    open fun enqueuePlaybackChunk(pcm: ByteArray): Boolean = false

    /** Queue facts are separate from unknown speaker hardware latency. */
    @Keep
    open fun playbackTiming(): LongArray = longArrayOf(-1L, -1L, -1L)

    @Keep
    @Synchronized
    fun resetAndAwait(): Boolean {
        if (cleanupComplete) return true
        active = false
        cleanupAttempts++
        val stopped = runCatching { stopEndpoint() }.getOrElse { failure ->
            lastCleanupFailure = failure.message ?: failure.javaClass.simpleName
            false
        }
        if (stopped) {
            cleanupComplete = true
            lastCleanupFailure = null
        } else {
            cleanupFailureObserved = true
            if (lastCleanupFailure == null) lastCleanupFailure = "Android audio device cleanup is not confirmed"
        }
        return cleanupComplete
    }

    @Synchronized
    internal fun cleanupAttempts(): Int = cleanupAttempts

    @Synchronized
    internal fun cleanupFailureObserved(): Boolean = cleanupFailureObserved

    @Synchronized
    internal fun lastCleanupFailure(): String? = lastCleanupFailure

    protected fun markInactive() {
        active = false
    }

    protected abstract fun stopEndpoint(): Boolean
}

/** Projection-bound system-playback capture; it never opens the microphone input source. */
class NativeAudioCaptureEndpoint private constructor(
    private val recorder: AudioRecord,
    requestId: String,
    connectionGeneration: Long,
    captureLeaseActive: () -> Boolean,
) : NativeAudioEndpoint(requestId, connectionGeneration, "HostCapture", captureLeaseActive) {
    private val queue = BoundedAudioPcmQueue(NATIVE_AUDIO_CAPTURE_PACKET_BYTES)
    private val failure = AtomicReference<String?>(null)
    private var recorderReleased = false
    private val thread = Thread(::captureLoop, "nestlink-audio-record").apply {
        priority = Thread.MAX_PRIORITY - 2
        start()
    }

    @Keep
    override fun pollCaptureChunk(): ByteArray? {
        if (!isActive()) {
            queue.stopAndClear()
            return null
        }
        return queue.poll()
    }

    override fun stopEndpoint(): Boolean {
        queue.stopAndClear()
        runCatching {
            if (recorder.recordingState == AudioRecord.RECORDSTATE_RECORDING) recorder.stop()
        }
        if (!recorderReleased) {
            runCatching { recorder.release(); recorderReleased = true }
        }
        try {
            thread.join(AUDIO_JOIN_TIMEOUT_MS)
            if (thread.isAlive) {
                thread.interrupt()
                thread.join(AUDIO_JOIN_TIMEOUT_MS)
            }
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        return recorderReleased && !thread.isAlive
    }

    private fun captureLoop() {
        Process.setThreadPriority(Process.THREAD_PRIORITY_AUDIO)
        val samples = ShortArray(NATIVE_AUDIO_CHUNK_FRAMES * NATIVE_AUDIO_CHANNELS)
        var capturedFrames = 0L
        val timestamp = AudioTimestamp()
        try {
            while (isActive()) {
                var offset = 0
                while (offset < samples.size && isActive()) {
                    val count = recorder.read(samples, offset, samples.size - offset, AudioRecord.READ_BLOCKING)
                    if (count < 0) throw IllegalStateException("AudioRecord.read failed with code ${count}")
                    if (count == 0) continue
                    offset += count
                }
                if (!isActive()) break
                if (offset != samples.size) throw IllegalStateException("AudioRecord returned a partial PCM chunk")
                val packet = ByteArray(NATIVE_AUDIO_CAPTURE_PACKET_BYTES)
                putLongLe(packet, 0, capturedFrames)
                val readCompleted = System.nanoTime()
                // Use the actual AudioRecord frame/time pair when available.
                // Before the first driver timestamp, read completion minus the
                // chunk duration is an estimate; no hardware latency is claimed.
                val firstSampleNanos = if (recorder.getTimestamp(timestamp, AudioTimestamp.TIMEBASE_MONOTONIC) == AudioRecord.SUCCESS &&
                    timestamp.framePosition >= capturedFrames
                ) {
                    val framesAfterStart = Math.subtractExact(timestamp.framePosition, capturedFrames)
                    Math.subtractExact(timestamp.nanoTime, Math.multiplyExact(framesAfterStart, 1_000_000_000L) / NATIVE_AUDIO_RATE)
                } else Math.subtractExact(readCompleted, 20_000_000L)
                putLongLe(packet, 8, firstSampleNanos)
                var destination = 16
                for (sample in samples) {
                    val value = sample.toInt()
                    packet[destination++] = value.toByte()
                    packet[destination++] = (value shr 8).toByte()
                }
                if (!queue.offer(packet)) packet.fill(0)
                capturedFrames += NATIVE_AUDIO_CHUNK_FRAMES
                samples.fill(0)
            }
        } catch (problem: Throwable) {
            if (isActive()) failure.compareAndSet(null, problem.message ?: "AudioRecord capture failed")
        } finally {
            samples.fill(0)
            if (!isActive()) queue.stopAndClear()
            if (failure.get() != null) {
                markInactive()
                queue.stopAndClear()
            }
        }
    }

    companion object {
        private const val AUDIO_JOIN_TIMEOUT_MS = 2_000L

        fun create(
            projection: MediaProjection,
            requestId: String,
            connectionGeneration: Long,
            captureLeaseActive: () -> Boolean = { true },
        ): NativeAudioCaptureEndpoint {
            val configuration = AudioPlaybackCaptureConfiguration.Builder(projection)
                .addMatchingUsage(AudioAttributes.USAGE_MEDIA)
                .addMatchingUsage(AudioAttributes.USAGE_GAME)
                .addMatchingUsage(AudioAttributes.USAGE_UNKNOWN)
                .build()
            val format = AudioFormat.Builder()
                .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                .setSampleRate(NATIVE_AUDIO_RATE)
                .setChannelMask(AudioFormat.CHANNEL_IN_STEREO)
                .build()
            val minimum = AudioRecord.getMinBufferSize(
                NATIVE_AUDIO_RATE,
                AudioFormat.CHANNEL_IN_STEREO,
                AudioFormat.ENCODING_PCM_16BIT,
            )
            check(minimum > 0) { "Android does not support 48 kHz stereo playback capture" }
            val recorder = AudioRecord.Builder()
                .setAudioFormat(format)
                .setBufferSizeInBytes(max(minimum, NATIVE_AUDIO_PCM_BYTES * NATIVE_AUDIO_QUEUE_CHUNKS))
                .setAudioPlaybackCaptureConfig(configuration)
                .build()
            check(recorder.state == AudioRecord.STATE_INITIALIZED) {
                recorder.release()
                "Android AudioRecord could not initialize playback capture"
            }
            try {
                recorder.startRecording()
                check(recorder.recordingState == AudioRecord.RECORDSTATE_RECORDING) {
                    "Android AudioRecord did not start playback capture"
                }
                return NativeAudioCaptureEndpoint(
                    recorder, requestId, connectionGeneration, captureLeaseActive,
                )
            } catch (failure: Throwable) {
                runCatching { recorder.stop() }
                recorder.release()
                throw failure
            }
        }
    }
}

/** Playback capture owner scoped to the complete, tagged BrowserHost permit binding. */
@Keep
internal class BrowserHostAudioCaptureEndpoint private constructor(
    private val bindingJson: String,
    private val delegate: NativeAudioCaptureEndpoint,
) {
    /** The service registry retains this exact recorder until reset and worker join succeed. */
    internal fun nativeEndpointForCleanup(): NativeAudioCaptureEndpoint = delegate

    @Keep
    fun matchesBinding(expectedBindingJson: String): Boolean =
        expectedBindingJson == bindingJson &&
            runCatching { HostCaptureBinding.browserHost(expectedBindingJson) }.isSuccess

    @Keep
    fun isActive(): Boolean = delegate.isActive()

    @Keep
    fun pollCaptureChunk(): ByteArray? = delegate.pollCaptureChunk()

    @Keep
    @Synchronized
    fun resetAndAwait(expectedBindingJson: String): Boolean =
        matchesBinding(expectedBindingJson) && delegate.resetAndAwait()

    companion object {
        fun create(
            projection: MediaProjection,
            bindingJson: String,
            captureLeaseActive: () -> Boolean,
        ): BrowserHostAudioCaptureEndpoint {
            val binding = HostCaptureBinding.browserHost(bindingJson)
            return BrowserHostAudioCaptureEndpoint(
                bindingJson,
                NativeAudioCaptureEndpoint.create(
                    projection,
                    binding.requestId,
                    binding.connectionGeneration,
                    captureLeaseActive,
                ),
            )
        }
    }
}

/** One approved controller audio route owns one bounded AudioTrack playback endpoint. */
class NativeAudioPlaybackEndpoint private constructor(
    private val track: AudioTrack,
    requestId: String,
    connectionGeneration: Long,
) : NativeAudioEndpoint(requestId, connectionGeneration, "ControllerPlayback") {
    private val queue = BoundedAudioPcmQueue(NATIVE_AUDIO_PCM_BYTES, capacity = 1)
    private val writtenFrames = AtomicLong(0)
    private val pendingWriteFrames = AtomicLong(0)
    private val failure = AtomicReference<String?>(null)
    private var trackReleased = false
    private val thread = Thread(::playbackLoop, "nestlink-audio-track").apply {
        priority = Thread.MAX_PRIORITY - 2
        start()
    }

    @Keep
    override fun enqueuePlaybackChunk(pcm: ByteArray): Boolean {
        if (!isActive() || !queue.offer(pcm)) return false
        return true
    }

    @Keep
    override fun playbackTiming(): LongArray {
        if (!isActive()) return longArrayOf(-1L, -1L, -1L)
        val queued = nativeAudioHardwareQueuedFrames(writtenFrames.get(), track.playbackHeadPosition)
        val software = queue.size().toLong() * NATIVE_AUDIO_CHUNK_FRAMES + pendingWriteFrames.get()
        return longArrayOf(software, queued, -1L)
    }

    override fun stopEndpoint(): Boolean {
        queue.stopAndClear()
        runCatching {
            track.pause()
            track.flush()
            track.stop()
        }
        if (!trackReleased) {
            runCatching { track.release(); trackReleased = true }
        }
        try {
            thread.join(AUDIO_JOIN_TIMEOUT_MS)
            if (thread.isAlive) thread.interrupt()
            if (thread.isAlive) thread.join(AUDIO_JOIN_TIMEOUT_MS)
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        return trackReleased && !thread.isAlive
    }

    private fun playbackLoop() {
        Process.setThreadPriority(Process.THREAD_PRIORITY_AUDIO)
        try {
            while (isActive()) {
                val packet = queue.poll()
                if (packet == null) {
                    Thread.sleep(2)
                    continue
                }
                try {
                    var offset = 0
                    pendingWriteFrames.set((packet.size / (NATIVE_AUDIO_CHANNELS * 2)).toLong())
                    while (offset < packet.size && isActive()) {
                        val written = track.write(packet, offset, packet.size - offset, AudioTrack.WRITE_BLOCKING)
                        if (written < 0) throw IllegalStateException("AudioTrack.write failed with code ${written}")
                        if (written == 0) Thread.sleep(2) else {
                            check(written % (NATIVE_AUDIO_CHANNELS * 2) == 0) { "AudioTrack returned partial interleaved frame" }
                            offset += written
                            writtenFrames.addAndGet((written / (NATIVE_AUDIO_CHANNELS * 2)).toLong())
                            pendingWriteFrames.set(((packet.size - offset) / (NATIVE_AUDIO_CHANNELS * 2)).toLong())
                        }
                    }
                } finally {
                    pendingWriteFrames.set(0)
                    packet.fill(0)
                }
            }
        } catch (problem: Throwable) {
            if (isActive()) failure.compareAndSet(null, problem.message ?: "AudioTrack playback failed")
        } finally {
            if (failure.get() != null) {
                markInactive()
                queue.stopAndClear()
            }
        }
    }

    companion object {
        private const val AUDIO_JOIN_TIMEOUT_MS = 2_000L

        fun create(requestId: String, connectionGeneration: Long): NativeAudioPlaybackEndpoint {
            val format = AudioFormat.Builder()
                .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                .setSampleRate(NATIVE_AUDIO_RATE)
                .setChannelMask(AudioFormat.CHANNEL_OUT_STEREO)
                .build()
            val minimum = AudioTrack.getMinBufferSize(
                NATIVE_AUDIO_RATE,
                AudioFormat.CHANNEL_OUT_STEREO,
                AudioFormat.ENCODING_PCM_16BIT,
            )
            check(minimum in 1..(NATIVE_AUDIO_PCM_BYTES * 3)) { "Android AudioTrack minimum buffer exceeds the 60ms native queue budget" }
            val track = AudioTrack.Builder()
                .setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_MEDIA)
                        .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
                        .build(),
                )
                .setAudioFormat(format)
                .setBufferSizeInBytes(max(minimum, NATIVE_AUDIO_PCM_BYTES * 2))
                .setTransferMode(AudioTrack.MODE_STREAM)
                .build()
            check(track.state == AudioTrack.STATE_INITIALIZED) {
                track.release()
                "Android AudioTrack could not initialize"
            }
            try {
                check(track.bufferSizeInFrames <= 2880) { "Android AudioTrack buffer exceeds the 60ms native queue budget" }
                track.play()
                return NativeAudioPlaybackEndpoint(track, requestId, connectionGeneration)
            } catch (failure: Throwable) {
                track.release()
                throw failure
            }
        }
    }
}

private fun putLongLe(destination: ByteArray, offset: Int, value: Long) {
    for (index in 0..7) destination[offset + index] = (value ushr (index * 8)).toByte()
}

/** AudioTrack's unsigned 32-bit head wraps; an inconsistent snapshot stays unknown. */
internal fun nativeAudioHardwareQueuedFrames(submittedFrames: Long, playbackHeadPosition: Int): Long {
    require(submittedFrames >= 0L)
    val played = playbackHeadPosition.toLong() and 0xffff_ffffL
    val queued = ((submittedFrames and 0xffff_ffffL) - played) and 0xffff_ffffL
    return queued.takeIf { it <= 2880L } ?: -1L
}

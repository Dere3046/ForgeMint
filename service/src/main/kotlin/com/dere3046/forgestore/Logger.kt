package com.dere3046.forgestore

import android.util.Base64
import android.util.Log
import java.io.BufferedWriter
import java.io.File
import java.io.FileWriter
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import org.json.JSONObject

object Logger {
    const val TAG = "ForgeStore"

    @Volatile var enabled = false
    @Volatile var verbose = false

    private const val RATE_LIMIT_BURST = 15
    private const val RATE_LIMIT_WINDOW_MS = 1000L
    private val windowStart = AtomicLong(System.currentTimeMillis())
    private val windowCount = AtomicInteger(0)
    private val suppressedCount = AtomicInteger(0)

    @PublishedApi
    internal fun acquireLogPermit(): Boolean {
        val now = System.currentTimeMillis()
        val start = windowStart.get()
        if (now - start > RATE_LIMIT_WINDOW_MS) {
            if (windowStart.compareAndSet(start, now)) {
                val suppressed = suppressedCount.getAndSet(0)
                windowCount.set(1)
                if (suppressed > 0) {
                    Log.i(TAG, "[rate-limit] suppressed $suppressed log messages in previous window")
                }
                return true
            }
        }
        val count = windowCount.incrementAndGet()
        if (count <= RATE_LIMIT_BURST) return true
        suppressedCount.incrementAndGet()
        return false
    }

    fun d(msg: String) {
        if (!enabled || !verbose) return
        if (!acquireLogPermit()) return
        Log.d(TAG, msg)
    }

    inline fun d(msg: () -> String) {
        if (!enabled || !verbose) return
        if (!acquireLogPermit()) return
        Log.d(TAG, msg())
    }

    fun i(msg: String) {
        if (!enabled) return
        if (!acquireLogPermit()) return
        Log.i(TAG, msg)
    }

    inline fun i(msg: () -> String) {
        if (!enabled) return
        if (!acquireLogPermit()) return
        Log.i(TAG, msg())
    }

    fun v(msg: String) {
        if (!enabled || !verbose) return
        if (!acquireLogPermit()) return
        Log.v(TAG, msg)
    }

    inline fun v(msg: () -> String) {
        if (!enabled || !verbose) return
        if (!acquireLogPermit()) return
        Log.v(TAG, msg())
    }

    fun w(msg: String) {
        if (!enabled) return
        Log.w(TAG, msg)
    }

    fun w(msg: String, t: Throwable) {
        if (!enabled) return
        Log.w(TAG, msg, t)
    }

    fun e(msg: String) {
        if (!enabled) return
        Log.e(TAG, msg)
    }

    fun e(msg: String, t: Throwable) {
        if (!enabled) return
        Log.e(TAG, msg, t)
    }

    fun isUidLogged(uid: Int): Boolean = enabled && verbose && !ConfigManager.shouldSkip(uid)

    fun uidLog(uid: Int, txId: Long?, event: String, detail: String) {
        if (!isUidLogged(uid)) return
        val correlation = txId?.let { " tx=$it" } ?: ""
        Log.d(TAG, "[${label(uid)}$correlation] $event: $detail")
        if (ConfigManager.isDiagnosticFile) {
            runCatching { uidWriter(uid).append(jsonRecord(uid, txId, event, detail, null)) }
        }
    }

    inline fun uidLog(uid: Int, txId: Long?, event: String, detail: () -> String) {
        if (!isUidLogged(uid)) return
        uidLog(uid, txId, event, detail())
    }

    fun uidLogRaw(uid: Int, txId: Long?, event: String, detail: String, raw: ByteArray) {
        if (!isUidLogged(uid)) return
        val correlation = txId?.let { " tx=$it" } ?: ""
        Log.d(TAG, "[${label(uid)}$correlation] $event: $detail (raw ${raw.size}B)")
        if (ConfigManager.isDiagnosticFile) {
            runCatching {
                val encoded = Base64.encodeToString(raw, Base64.NO_WRAP)
                uidWriter(uid).append(jsonRecord(uid, txId, event, detail, encoded))
            }
        }
    }

    private fun label(uid: Int): String =
        ConfigManager.getPackagesForUid(uid).firstOrNull() ?: "uid:$uid"

    const val DIAGNOSTIC_DIR = "/data/media/0/ForgeStore"

    private val uidLogDir = File(DIAGNOSTIC_DIR)
    private const val UID_LOG_MAX_BYTES = 4L * 1024 * 1024
    private val uidWriters = ConcurrentHashMap<Int, UidLogFile>()

    private val recordClock =
        DateTimeFormatter.ofPattern("MM-dd HH:mm:ss.SSS").withZone(ZoneId.systemDefault())

    private fun jsonRecord(
        uid: Int,
        txId: Long?,
        event: String,
        detail: String,
        rawB64: String?,
    ): String =
        JSONObject()
            .apply {
                put("ts", recordClock.format(Instant.now()))
                put("uid", uid)
                put("pkg", label(uid))
                txId?.let { put("tx", it) }
                put("event", event)
                put("detail", detail)
                rawB64?.let { put("raw_b64", it) }
            }
            .toString()

    private fun uidWriter(uid: Int): UidLogFile =
        uidWriters.computeIfAbsent(uid) { key ->
            UidLogFile(key, uidLogDir).also { file ->
                val packages =
                    ConfigManager.getPackagesForUid(key).joinToString().ifEmpty { "<unresolved>" }
                runCatching {
                    file.append(jsonRecord(key, null, "session", "packages=[$packages]", null))
                }
            }
        }

    private class UidLogFile(uid: Int, private val logDir: File) {
        private val primary = File(logDir, "forgestore-uid-$uid.ndjson")
        private val rotated = File(logDir, "forgestore-uid-$uid.ndjson.1")
        private var writer: BufferedWriter? = null
        private var size = 0L

        @Synchronized
        fun append(jsonLine: String) {
            runCatching {
                val out = writer ?: open()
                out.write(jsonLine)
                out.write("\n")
                out.flush()
                size += jsonLine.length + 1
                if (size >= UID_LOG_MAX_BYTES) rotate()
            }
        }

        private fun open(): BufferedWriter {
            logDir.mkdirs()
            val out = BufferedWriter(FileWriter(primary, true))
            writer = out
            size = primary.length()
            return out
        }

        private fun rotate() {
            runCatching {
                writer?.flush()
                writer?.close()
            }
            writer = null
            runCatching {
                if (rotated.exists()) rotated.delete()
                primary.renameTo(rotated)
            }
            size = 0L
        }
    }
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

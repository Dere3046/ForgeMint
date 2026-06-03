package com.dere3046.forgemint

import android.os.Build
import android.os.FileObserver
import android.os.ServiceManager
import java.io.File
import java.util.concurrent.ConcurrentHashMap

object ConfigManager {

    enum class Mode { GENERATE, PATCH, AUTO }

    private const val CONFIG_DIR = "/data/adb/forgemint"
    private const val TARGET_FILE = "target.txt"
    private const val TEE_STATUS_FILE = "tee_status.txt"

    private val configRoot = File(CONFIG_DIR)
    private val targetFile = File(configRoot, TARGET_FILE)
    private val teeStatusFile = File(configRoot, TEE_STATUS_FILE)

    @Volatile private var packageModes = mapOf<String, Mode>()
    @Volatile private var isTeBroken: Boolean? = null
    private val uidPackageCache = ConcurrentHashMap<Int, List<String>>()

    private var observer: FileObserver? = null

    fun initialize() {
        configRoot.mkdirs()
        Logger.i("Config root: ${configRoot.absolutePath}")
        loadTargetPackages()
        loadTeeStatus()
        startObserver()
        Logger.i("Config initialized: ${packageModes.size} packages")
    }

    fun shouldGenerate(uid: Int): Boolean = getModeForUid(uid) == Mode.GENERATE ||
            (getModeForUid(uid) == Mode.AUTO && isTeBroken == true)

    fun shouldPatch(uid: Int): Boolean = getModeForUid(uid) == Mode.PATCH ||
            (getModeForUid(uid) == Mode.AUTO && isTeBroken != true)

    fun shouldSkip(uid: Int): Boolean = getModeForUid(uid) == null

    private fun getModeForUid(uid: Int): Mode? {
        val packages = getPackagesForUid(uid)
        if (packages.isEmpty()) return null
        if (isTeBroken == null) loadTeeStatus()
        for (pkg in packages) {
            packageModes[pkg]?.let { return it }
        }
        return null
    }

    private fun loadTargetPackages() {
        if (!targetFile.exists()) {
            Logger.w("target.txt not found: ${targetFile.absolutePath}")
            return
        }
        try {
            val newModes = mutableMapOf<String, Mode>()
            targetFile.readLines().forEach { line ->
                val trimmed = line.trim()
                if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEach
                when {
                    trimmed.endsWith("!") -> {
                        val pkg = trimmed.removeSuffix("!").trim()
                        if (pkg.isNotEmpty()) newModes[pkg] = Mode.GENERATE
                    }
                    trimmed.endsWith("?") -> {
                        val pkg = trimmed.removeSuffix("?").trim()
                        if (pkg.isNotEmpty()) newModes[pkg] = Mode.PATCH
                    }
                    else -> {
                        if (trimmed.isNotEmpty()) newModes[trimmed] = Mode.AUTO
                    }
                }
            }
            packageModes = newModes
            uidPackageCache.clear()
            Logger.i("Loaded ${newModes.size} package modes")
        } catch (e: Exception) {
            Logger.e("Failed to load target.txt", e)
        }
    }

    fun checkTeeStatus() {
        isTeBroken = try {
            val result = TeeChecker.isTeeFunctional()
            teeStatusFile.writeText("tee_broken=${!result}")
            Logger.i("TEE status: ${if (result) "functional" else "broken"}")
            !result
        } catch (e: Exception) {
            Logger.e("TEE check failed", e)
            true
        }
    }

    private fun loadTeeStatus() {
        isTeBroken = if (teeStatusFile.exists()) {
            teeStatusFile.readText().trim() == "tee_broken=true"
        } else null
    }

    private fun getPackagesForUid(uid: Int): List<String> {
        return uidPackageCache.getOrPut(uid) {
            try {
                val pmBinder = ServiceManager.getService("package") ?: return@getOrPut emptyList()
                val pm = android.content.pm.IPackageManager.Stub.asInterface(pmBinder)
                pm.getPackagesForUid(uid)?.toList() ?: emptyList()
            } catch (e: Exception) {
                Logger.w("Failed to get packages for UID $uid", e)
                emptyList()
            }
        }
    }

    private fun startObserver() {
        observer?.stopWatching()
        observer = object : FileObserver(configRoot, CLOSE_WRITE or MOVED_TO) {
            override fun onEvent(event: Int, path: String?) {
                if (path == TARGET_FILE) {
                    Logger.i("target.txt changed, reloading")
                    loadTargetPackages()
                }
                if (path == TEE_STATUS_FILE) {
                    loadTeeStatus()
                }
            }
        }.apply { startWatching() }
    }
}

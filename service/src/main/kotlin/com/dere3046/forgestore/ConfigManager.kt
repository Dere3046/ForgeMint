/*
 * This file is part of ForgeStore
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2026 TheGeniusClub
 */

package com.dere3046.forgestore

import android.os.FileObserver
import android.os.ServiceManager
import java.io.File
import java.util.concurrent.ConcurrentHashMap

object ConfigManager {

    enum class Mode { GENERATE, PATCH, AUTO }

    data class CustomPatchLevel(
        val system: String?,
        val vendor: String?,
        val boot: String?,
        val all: String?,
    )

    private const val CONFIG_DIR = "/data/adb/forge_store"
    private const val TARGET_FILE = "target.txt"
    private const val TEE_STATUS_FILE = "tee_status.txt"
    private const val PATCH_FILE = "security_patch.txt"
    private const val KEYBOX_FILE = "keybox.xml"
    private const val CONFIG_FILE = "config"

    private val configDefaults = mapOf(
        "debug" to false,
        "verbose_log" to false,
        "fallback" to false,
        "whitelist_mode" to false,
        "strict_keybox" to false,
        "diagnostic_file" to false,
        "full_attest_chain" to false,
        "harvester_enabled" to false,
        "harvester_override" to false,
        "harvester_telephony" to false,
        "harvester_strongbox" to false,
    )
    private val intConfigDefaults = mapOf(
        "keybox_min_certs" to 2,
    )
    private val stringConfigDefaults = mapOf(
        "harvester_file" to "/data/adb/forge_store/device_profile.json",
    )
    private val configMap = ConcurrentHashMap<String, Boolean>()
    private val intConfigMap = ConcurrentHashMap<String, Int>()
    private val stringConfigMap = ConcurrentHashMap<String, String>()

    private val configRoot = File(CONFIG_DIR)
    private val targetFile = File(configRoot, TARGET_FILE)
    private val teeStatusFile = File(configRoot, TEE_STATUS_FILE)
    private val patchFile = File(configRoot, PATCH_FILE)
    private val keyboxFile = File(configRoot, KEYBOX_FILE)

    @Volatile private var packageModes = mapOf<String, Mode>()
    @Volatile private var uidModes = mapOf<Int, Mode>()
    @Volatile private var isTeBroken: Boolean? = null
    @Volatile private var globalPatchLevel: CustomPatchLevel? = null
    private val uidPackageCache = ConcurrentHashMap<Int, List<String>>()

    private var observer: FileObserver? = null

    fun initConfig() {
        configRoot.mkdirs()
        loadConfig()
    }

    fun initialize() {
        configRoot.mkdirs()
        loadConfig()
        Logger.d("Config root: ${configRoot.absolutePath}")
        loadTargetPackages()
        loadSecurityPatchLevels()
        loadTeeStatus()
        startObserver()
        Logger.i("Config initialized: ${packageModes.size} packages, ${uidModes.size} uids, global patch level: ${globalPatchLevel != null}")
    }

    private fun loadConfig() {
        configDefaults.entries.forEach { configMap.put(it.key, it.value) }
        intConfigDefaults.entries.forEach { intConfigMap.put(it.key, it.value) }
        stringConfigDefaults.entries.forEach { stringConfigMap.put(it.key, it.value) }
        val configFile = File(configRoot, CONFIG_FILE)
        if (!configFile.exists()) return
        try {
            for (line in configFile.readLines()) {
                val trimmed = line.trim()
                if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
                val eqIdx = trimmed.indexOf('=')
                if (eqIdx < 0) continue
                val key = trimmed.substring(0, eqIdx).trim()
                val value = trimmed.substring(eqIdx + 1).trim()
                if (key in configDefaults) {
                    configMap[key] = value == "true"
                } else if (key in intConfigDefaults) {
                    value.toIntOrNull()?.let { intConfigMap[key] = it }
                } else if (key in stringConfigDefaults) {
                    stringConfigMap[key] = value
                }
            }
        } catch (e: Exception) {
            Logger.e("Failed to load config", e)
        }
    }

    private fun getBool(key: String): Boolean = configMap[key] ?: configDefaults[key] ?: false

    private fun getInt(key: String): Int = intConfigMap[key] ?: intConfigDefaults[key] ?: 0

    private fun getString(key: String): String = stringConfigMap[key] ?: stringConfigDefaults[key] ?: ""

    val isDebugEnabled: Boolean get() = getBool("debug")
    val isVerboseLog: Boolean get() = getBool("verbose_log")
    val isFallbackEnabled: Boolean get() = getBool("fallback")
    val isWhitelistMode: Boolean get() = getBool("whitelist_mode")
    val isStrictKeybox: Boolean get() = getBool("strict_keybox")
    val isDiagnosticFile: Boolean get() = getBool("diagnostic_file")
    val isFullAttestChain: Boolean get() = getBool("full_attest_chain")
    val keyboxMinCerts: Int get() = getInt("keybox_min_certs").coerceAtLeast(1)

    val harvesterEnabled: Boolean get() = getBool("harvester_enabled")
    val harvesterOverride: Boolean get() = getBool("harvester_override")
    val harvesterTelephony: Boolean get() = getBool("harvester_telephony")
    val harvesterStrongBox: Boolean get() = getBool("harvester_strongbox")
    val harvesterFile: String get() = getString("harvester_file")

    fun shouldGenerate(uid: Int): Boolean = getModeForUid(uid) == Mode.GENERATE

    fun shouldPatch(uid: Int): Boolean = getModeForUid(uid) == Mode.PATCH

    fun shouldSkip(uid: Int): Boolean = getModeForUid(uid) == null

    fun getPatchLevelForUid(uid: Int): CustomPatchLevel? = globalPatchLevel

    fun getPackagesForUid(uid: Int): List<String> {
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

    private fun getModeForUid(uid: Int): Mode? {
        val explicit = getExplicitModeForUid(uid)
        return if (isWhitelistMode) {
            if (explicit != null) null else resolveAuto(Mode.AUTO)
        } else {
            explicit?.let { resolveAuto(it) }
        }
    }

    private fun getExplicitModeForUid(uid: Int): Mode? {
        uidModes[uid]?.let { return it }
        val packages = uidPackageCache[uid] ?: getPackagesForUid(uid)
        if (packages.isEmpty()) return null
        if (isTeBroken == null) loadTeeStatus()
        val userId = uid / 100000
        for (pkg in packages) {
            val key = if (userId == 0) pkg else "$pkg@$userId"
            packageModes[key]?.let { return it }
        }
        return null
    }

    private fun resolveAuto(mode: Mode): Mode =
        when (mode) {
            Mode.AUTO -> if (isTeBroken == true) Mode.GENERATE else Mode.PATCH
            else -> mode
        }

    private fun loadTargetPackages() {
        if (!targetFile.exists()) {
            Logger.w("target.txt not found: ${targetFile.absolutePath}")
            return
        }
        try {
            val newPackageModes = mutableMapOf<String, Mode>()
            val newUidModes = mutableMapOf<Int, Mode>()
            targetFile.readLines().forEach { line ->
                val trimmed = line.trim()
                if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEach
                var entry = trimmed
                val mode =
                    when {
                        trimmed.endsWith("!") -> {
                            entry = trimmed.dropLast(1).trim()
                            Mode.GENERATE
                        }
                        trimmed.endsWith("?") -> {
                            entry = trimmed.dropLast(1).trim()
                            Mode.PATCH
                        }
                        else -> Mode.AUTO
                    }
                if (entry.startsWith("uid:")) {
                    entry.substring(4).trim().toIntOrNull()?.let { uid ->
                        newUidModes[uid] = mode
                    }
                } else {
                    val at = entry.indexOf('@')
                    if (at >= 0) {
                        val pkg = entry.substring(0, at).trim()
                        val user = entry.substring(at + 1).trim().toIntOrNull()
                        if (pkg.isNotEmpty() && user != null && user >= 0) {
                            newPackageModes[if (user == 0) pkg else "$pkg@$user"] = mode
                        }
                    } else if (entry.isNotEmpty()) {
                        newPackageModes[entry] = mode
                    }
                }
            }
            packageModes = newPackageModes
            uidModes = newUidModes
            uidPackageCache.clear()
            Logger.d("Loaded ${newPackageModes.size} package modes, ${newUidModes.size} uid modes")
        } catch (e: Exception) {
            Logger.e("Failed to load target.txt", e)
        }
    }

    private fun loadSecurityPatchLevels() {
        if (!patchFile.exists()) return
        try {
            var sys: String? = null
            var ven: String? = null
            var boo: String? = null
            var all: String? = null

            for (line in patchFile.readLines()) {
                val trimmed = line.trim()
                if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
                val eqIdx = trimmed.indexOf('=')
                if (eqIdx < 0) continue
                val key = trimmed.substring(0, eqIdx).trim().lowercase()
                val value = trimmed.substring(eqIdx + 1).trim()
                when (key) {
                    "system" -> sys = value
                    "vendor" -> ven = value
                    "boot" -> boo = value
                    "all" -> all = value
                }
            }

            if (sys != null || ven != null || boo != null || all != null) {
                globalPatchLevel = CustomPatchLevel(sys, ven, boo, all)
                Logger.i("Loaded global patch level: system=${sys} vendor=${ven} boot=${boo} all=${all}")
            }
        } catch (e: Exception) {
            Logger.e("Failed to load $PATCH_FILE", e)
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
                if (path == PATCH_FILE) {
                    Logger.i("security_patch.txt changed, reloading")
                    loadSecurityPatchLevels()
                }
                if (path == KEYBOX_FILE) {
                    Logger.i("keybox.xml changed, clearing caches")
                    KeyboxReader.clearCache()
                }
                if (path == CONFIG_FILE) {
                    Logger.i("config changed, reloading")
                    loadConfig()
                }
            }
        }.apply { startWatching() }
    }
}

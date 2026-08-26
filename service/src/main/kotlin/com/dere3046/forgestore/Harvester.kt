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

import android.hardware.security.keymint.SecurityLevel
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.cert.X509CertificateHolder
import org.json.JSONObject

object Harvester {

    data class DeviceIds(
        val brand: ByteArray? = null,
        val device: ByteArray? = null,
        val product: ByteArray? = null,
        val serial: ByteArray? = null,
        val imei: ByteArray? = null,
        val meid: ByteArray? = null,
        val manufacturer: ByteArray? = null,
        val model: ByteArray? = null,
        val secondImei: ByteArray? = null,
    )

    data class Profile(
        val harvestFailed: Boolean,
        val verifiedBootKey: ByteArray,
        val verifiedBootHash: ByteArray,
        val deviceLocked: Boolean,
        val verifiedBootState: Int,
        val attestationSecurityLevel: Int,
        val keymasterSecurityLevel: Int,
        val strongBoxAvailable: Boolean,
        val strongBoxAttestationVersion: Int,
        val attestationVersion: Int,
        val keymasterVersion: Int,
        val osVersion: Int?,
        val osPatchLevel: Int?,
        val vendorPatchLevel: Int?,
        val bootPatchLevel: Int?,
        val moduleHash: ByteArray?,
        val brand: String,
        val device: String,
        val product: String,
        val manufacturer: String,
        val model: String,
        val serial: String,
        val imei: String,
        val meid: String,
        val imei2: String,
        val harvestedAt: Long,
    ) {
        fun toDeviceIds(): DeviceIds {
            return DeviceIds(
                brand = brand.toByteArrayOrNull(),
                device = device.toByteArrayOrNull(),
                product = product.toByteArrayOrNull(),
                serial = serial.toByteArrayOrNull(),
                imei = imei.toByteArrayOrNull(),
                meid = meid.toByteArrayOrNull(),
                manufacturer = manufacturer.toByteArrayOrNull(),
                model = model.toByteArrayOrNull(),
                secondImei = imei2.toByteArrayOrNull(),
            )
        }
    }

    @Volatile
    private var profile: Profile? = null

    fun initialize() {
        if (!ConfigManager.harvesterEnabled) return
        profile = loadProfile() ?: buildProfile()
        profile?.let { saveProfile(it) }
    }

    fun current(): Profile? = profile

    fun harvestedDeviceIds(): DeviceIds {
        val p = if (ConfigManager.harvesterEnabled && ConfigManager.harvesterOverride) profile else null
        return p?.toDeviceIds() ?: DeviceIds()
    }

    fun resolveDeviceIds(uid: Int, params: KeyMintAttestation): DeviceIds {
        val p = if (ConfigManager.harvesterEnabled && ConfigManager.harvesterOverride) profile else null
        return DeviceIds(
            brand = choose(p?.brand, params.brand),
            device = choose(p?.device, params.device),
            product = choose(p?.product, params.product),
            serial = choose(p?.serial, params.serial),
            imei = choose(p?.imei, params.imei),
            meid = choose(p?.meid, params.meid),
            manufacturer = choose(p?.manufacturer, params.manufacturer),
            model = choose(p?.model, params.model),
            secondImei = choose(p?.imei2, params.secondImei),
        )
    }

    private fun choose(harvested: String?, original: ByteArray?): ByteArray? {
        if (original == null) return null
        if (!harvested.isNullOrBlank()) return harvested.toByteArray(Charsets.UTF_8)
        return original
    }

    private fun buildProfile(): Profile? {
        val data = DeviceAttestationService.cachedData
        val supplemented = if (data == null) null else if (ConfigManager.harvesterTelephony) supplementTelephony(data) else data
        if (supplemented == null) return fallbackProfile()

        val strongBox = if (ConfigManager.harvesterStrongBox) probeStrongBox() else (false to null)
        return Profile(
            harvestFailed = false,
            verifiedBootKey = supplemented.verifiedBootKey ?: AttestationBuilder.bootKey,
            verifiedBootHash = supplemented.verifiedBootHash ?: AttestationBuilder.bootHash,
            deviceLocked = supplemented.deviceLocked ?: true,
            verifiedBootState = supplemented.verifiedBootState ?: 0,
            attestationSecurityLevel = supplemented.attestVersion?.let { SecurityLevel.TRUSTED_ENVIRONMENT } ?: SecurityLevel.TRUSTED_ENVIRONMENT,
            keymasterSecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
            strongBoxAvailable = supplemented.strongBoxAvailable ?: strongBox.first,
            strongBoxAttestationVersion = supplemented.strongBoxAttestationVersion ?: strongBox.second ?: supplemented.attestVersion ?: 0,
            attestationVersion = supplemented.attestVersion ?: AndroidDeviceUtils.aospAttestVersion ?: 300,
            keymasterVersion = supplemented.keymasterVersion ?: AndroidDeviceUtils.aospAttestVersion ?: 300,
            osVersion = supplemented.osVersion,
            osPatchLevel = supplemented.osPatchLevel,
            vendorPatchLevel = supplemented.vendorPatchLevel,
            bootPatchLevel = supplemented.bootPatchLevel,
            moduleHash = supplemented.moduleHash ?: AndroidDeviceUtils.moduleHash,
            brand = supplemented.brand ?: systemProp("ro.product.brand", Build.BRAND),
            device = supplemented.device ?: systemProp("ro.product.device", Build.DEVICE),
            product = supplemented.product ?: systemProp("ro.product.name", Build.PRODUCT),
            manufacturer = supplemented.manufacturer ?: systemProp("ro.product.manufacturer", Build.MANUFACTURER),
            model = supplemented.model ?: systemProp("ro.product.model", Build.MODEL),
            serial = supplemented.serial ?: "",
            imei = supplemented.imei ?: "",
            meid = supplemented.meid ?: "",
            imei2 = supplemented.imei2 ?: "",
            harvestedAt = System.currentTimeMillis(),
        )
    }

    private fun fallbackProfile(): Profile {
        return Profile(
            harvestFailed = true,
            verifiedBootKey = AttestationBuilder.bootKey,
            verifiedBootHash = AttestationBuilder.bootHash,
            deviceLocked = true,
            verifiedBootState = 0,
            attestationSecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
            keymasterSecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
            strongBoxAvailable = false,
            strongBoxAttestationVersion = fabricatedAttestationVersion(),
            attestationVersion = fabricatedAttestationVersion(),
            keymasterVersion = fabricatedAttestationVersion(),
            osVersion = AndroidDeviceUtils.osVersion,
            osPatchLevel = AndroidDeviceUtils.getPatchLevel(0),
            vendorPatchLevel = AndroidDeviceUtils.getVendorPatchLevelLong(0),
            bootPatchLevel = AndroidDeviceUtils.getBootPatchLevelLong(0),
            moduleHash = AndroidDeviceUtils.moduleHash,
            brand = systemProp("ro.product.brand", Build.BRAND),
            device = systemProp("ro.product.device", Build.DEVICE),
            product = systemProp("ro.product.name", Build.PRODUCT),
            manufacturer = systemProp("ro.product.manufacturer", Build.MANUFACTURER),
            model = systemProp("ro.product.model", Build.MODEL),
            serial = "",
            imei = "",
            meid = "",
            imei2 = "",
            harvestedAt = System.currentTimeMillis(),
        )
    }

    private fun fabricatedAttestationVersion(): Int {
        return when {
            Build.VERSION.SDK_INT <= 27 -> 2
            Build.VERSION.SDK_INT <= 29 -> 3
            Build.VERSION.SDK_INT == 30 -> 4
            Build.VERSION.SDK_INT <= 32 -> 100
            Build.VERSION.SDK_INT == 33 -> 200
            Build.VERSION.SDK_INT <= 35 -> 300
            Build.VERSION.SDK_INT == 36 -> 400
            else -> 500
        }
    }

    private fun probeStrongBox(): Pair<Boolean, Int?> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return false to null
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val alias = "ForgeStore_StrongBoxProbe"
            runCatching { keyStore.deleteEntry(alias) }
            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setIsStrongBoxBacked(true)
                .setAttestationChallenge(ByteArray(16))
                .build()
            kpg.initialize(spec)
            kpg.generateKeyPair()
            val chain = keyStore.getCertificateChain(alias)
            keyStore.deleteEntry(alias)
            val leaf = chain?.firstOrNull() as? X509Certificate ?: return false to null
            true to parseAttestVersion(leaf)
        } catch (_: Exception) {
            false to null
        }
    }

    private fun parseAttestVersion(leaf: X509Certificate): Int? {
        return runCatching {
            val holder = X509CertificateHolder(leaf.encoded)
            val ext = holder.getExtension(AttestationConstants.ATTESTATION_OID_OBJ) ?: return null
            val seq = ASN1Sequence.getInstance(ext.extnValue.octets)
            ASN1Integer.getInstance(
                seq.toArray()[AttestationConstants.KEY_DESCRIPTION_ATTESTATION_VERSION_INDEX]
            ).positiveValue.toInt()
        }.getOrNull()
    }

    private fun supplementTelephony(data: DeviceAttestationService.AttestationData?): DeviceAttestationService.AttestationData? {
        if (data == null) return null
        val serial = data.serial ?: systemProp("ro.serialno", "")
        val imei = data.imei ?: phoneSubInfoId("getDeviceIdForPhone", 0)
        val imei2 = data.imei2 ?: phoneSubInfoId("getDeviceIdForPhone", 1)
        val meid = data.meid ?: phoneSubInfoId("getMeidForSubscriber", 0)
        val finalImei2 = if (imei2.isNullOrBlank() || imei2 == imei) "" else imei2
        return data.copy(
            serial = serial?.takeIf { it.isNotBlank() },
            imei = imei?.takeIf { it.isNotBlank() },
            imei2 = finalImei2?.takeIf { it.isNotBlank() },
            meid = meid?.takeIf { it.isNotBlank() },
        )
    }

    private fun phoneSubInfoId(methodName: String, slot: Int): String? {
        return runCatching {
            val sm = Class.forName("android.os.ServiceManager")
            val binder = sm.getMethod("getService", String::class.java)
                .invoke(null, "iphonesubinfo") as? android.os.IBinder ?: return null
            val stub = Class.forName("com.android.internal.telephony.IPhoneSubInfo\$Stub")
            val service = stub.getMethod("asInterface", android.os.IBinder::class.java).invoke(null, binder)
            val method = Class.forName("com.android.internal.telephony.IPhoneSubInfo").methods.firstOrNull {
                it.name == methodName && it.parameterTypes.firstOrNull() == Int::class.javaPrimitiveType
            } ?: return null
            val args = method.parameterTypes.map { t ->
                when (t) {
                    Int::class.javaPrimitiveType -> slot
                    String::class.java -> "android"
                    else -> return null
                }
            }
            method.invoke(service, *args.toTypedArray()) as? String
        }.getOrNull()
    }

    private fun systemProp(name: String, fallback: String): String {
        return runCatching {
            val cls = Class.forName("android.os.SystemProperties")
            val m = cls.getMethod("get", String::class.java, String::class.java)
            val value = m.invoke(null, name, fallback) as String
            value.ifBlank { fallback }
        }.getOrElse { fallback }
    }

    private fun loadProfile(): Profile? {
        val file = File(ConfigManager.harvesterFile)
        if (!file.exists()) return null
        return runCatching {
            val o = JSONObject(file.readText())
            Profile(
                harvestFailed = o.optBoolean("harvestFailed", true),
                verifiedBootKey = decodeB64(o.optString("verifiedBootKey", "")) ?: ByteArray(32),
                verifiedBootHash = decodeB64(o.optString("verifiedBootHash", "")) ?: ByteArray(32),
                deviceLocked = o.optBoolean("deviceLocked", true),
                verifiedBootState = o.optInt("verifiedBootState", 0),
                attestationSecurityLevel = o.optInt("attestationSecurityLevel", SecurityLevel.TRUSTED_ENVIRONMENT),
                keymasterSecurityLevel = o.optInt("keymasterSecurityLevel", SecurityLevel.TRUSTED_ENVIRONMENT),
                strongBoxAvailable = o.optBoolean("strongBoxAvailable", false),
                strongBoxAttestationVersion = o.optInt("strongBoxAttestationVersion", fabricatedAttestationVersion()),
                attestationVersion = o.optInt("attestationVersion", fabricatedAttestationVersion()),
                keymasterVersion = o.optInt("keymasterVersion", fabricatedAttestationVersion()),
                osVersion = if (o.has("osVersion")) o.getInt("osVersion") else null,
                osPatchLevel = if (o.has("osPatchLevel")) o.getInt("osPatchLevel") else null,
                vendorPatchLevel = if (o.has("vendorPatchLevel")) o.getInt("vendorPatchLevel") else null,
                bootPatchLevel = if (o.has("bootPatchLevel")) o.getInt("bootPatchLevel") else null,
                moduleHash = decodeB64(o.optString("moduleHash", "")),
                brand = o.optString("brand", ""),
                device = o.optString("device", ""),
                product = o.optString("product", ""),
                manufacturer = o.optString("manufacturer", ""),
                model = o.optString("model", ""),
                serial = o.optString("serial", ""),
                imei = o.optString("imei", ""),
                meid = o.optString("meid", ""),
                imei2 = o.optString("imei2", ""),
                harvestedAt = o.optLong("harvestedAt", System.currentTimeMillis()),
            )
        }.getOrElse {
            Logger.w("Failed to load harvester profile", it)
            null
        }
    }

    private fun saveProfile(p: Profile) {
        val file = File(ConfigManager.harvesterFile)
        val tmp = File(file.parentFile, "${file.name}.tmp")
        runCatching {
            file.parentFile?.mkdirs()
            tmp.writeText(toJson(p).toString(2))
            tmp.renameTo(file)
        }.onFailure {
            Logger.w("Failed to save harvester profile", it)
        }
    }

    private fun toJson(p: Profile): JSONObject {
        return JSONObject().apply {
            put("harvestFailed", p.harvestFailed)
            put("verifiedBootKey", encodeB64(p.verifiedBootKey))
            put("verifiedBootHash", encodeB64(p.verifiedBootHash))
            put("deviceLocked", p.deviceLocked)
            put("verifiedBootState", p.verifiedBootState)
            put("attestationSecurityLevel", p.attestationSecurityLevel)
            put("keymasterSecurityLevel", p.keymasterSecurityLevel)
            put("strongBoxAvailable", p.strongBoxAvailable)
            put("strongBoxAttestationVersion", p.strongBoxAttestationVersion)
            put("attestationVersion", p.attestationVersion)
            put("keymasterVersion", p.keymasterVersion)
            p.osVersion?.let { put("osVersion", it) }
            p.osPatchLevel?.let { put("osPatchLevel", it) }
            p.vendorPatchLevel?.let { put("vendorPatchLevel", it) }
            p.bootPatchLevel?.let { put("bootPatchLevel", it) }
            p.moduleHash?.let { put("moduleHash", encodeB64(it)) }
            put("brand", p.brand)
            put("device", p.device)
            put("product", p.product)
            put("manufacturer", p.manufacturer)
            put("model", p.model)
            put("serial", p.serial)
            put("imei", p.imei)
            put("meid", p.meid)
            put("imei2", p.imei2)
            put("harvestedAt", p.harvestedAt)
        }
    }

    private fun encodeB64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    private fun decodeB64(value: String): ByteArray? {
        if (value.isBlank()) return null
        return runCatching { Base64.getDecoder().decode(value) }.getOrNull()
    }

}

private fun String.toByteArrayOrNull(): ByteArray? =
    if (isBlank()) null else toByteArray(Charsets.UTF_8)

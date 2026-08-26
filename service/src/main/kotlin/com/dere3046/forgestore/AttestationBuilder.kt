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

import android.os.Build
import android.os.ServiceManager
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object AttestationBuilder {

    val bootKey: ByteArray
        get() = AndroidDeviceUtils.bootKey
    val bootHash: ByteArray
        get() = AndroidDeviceUtils.bootHash

    val osVersion: Int
        get() = AndroidDeviceUtils.osVersion

    fun getAttestVersion(securityLevel: Int): Int {
        return AndroidDeviceUtils.getAttestVersion(securityLevel)
    }

    fun getKeymasterVersion(securityLevel: Int): Int {
        return AndroidDeviceUtils.getKeymasterVersion(securityLevel)
    }

    fun buildAttestationExtension(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): org.bouncycastle.asn1.x509.Extension {
        val keyDescription = buildKeyDescription(params, uid, securityLevel)
        return org.bouncycastle.asn1.x509.Extension(
            AttestationConstants.ATTESTATION_OID_OBJ,
            false,
            DEROctetString(keyDescription.encoded),
        )
    }

    fun buildRootOfTrust(originalRootOfTrust: ASN1Encodable? = null): DERSequence {
        val rootElements = arrayOfNulls<ASN1Encodable>(4)
        val normalizedBootKey = if (bootKey.size > 32) {
            java.security.MessageDigest.getInstance("SHA-256").digest(bootKey)
        } else {
            bootKey
        }
        rootElements[AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX] =
            DEROctetString(normalizedBootKey)
        rootElements[AttestationConstants.ROOT_OF_TRUST_DEVICE_LOCKED_INDEX] =
            ASN1Boolean.TRUE
        rootElements[AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX] =
            ASN1Enumerated(0)
        rootElements[AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX] =
            DEROctetString(bootHash)
        return DERSequence(rootElements)
    }

    fun getSimulatedHardwareProperties(uid: Int): Map<Int, DERTaggedObject?> {
        val props = mutableMapOf<Int, DERTaggedObject?>()

        props[AttestationConstants.TAG_OS_VERSION] = DERTaggedObject(
            true, AttestationConstants.TAG_OS_VERSION,
            ASN1Integer(osVersion.toLong()),
        )

        val osPatch = AndroidDeviceUtils.getPatchLevel(uid)
        props[AttestationConstants.TAG_OS_PATCHLEVEL] =
            if (osPatch != AndroidDeviceUtils.DO_NOT_REPORT) {
                DERTaggedObject(
                    true, AttestationConstants.TAG_OS_PATCHLEVEL,
                    ASN1Integer(osPatch.toLong()),
                )
            } else {
                null
            }

        val vendorPatch = AndroidDeviceUtils.getVendorPatchLevelLong(uid)
        props[AttestationConstants.TAG_VENDOR_PATCHLEVEL] =
            if (vendorPatch != AndroidDeviceUtils.DO_NOT_REPORT) {
                DERTaggedObject(
                    true, AttestationConstants.TAG_VENDOR_PATCHLEVEL,
                    ASN1Integer(vendorPatch.toLong()),
                )
            } else {
                null
            }

        val bootPatch = AndroidDeviceUtils.getBootPatchLevelLong(uid)
        props[AttestationConstants.TAG_BOOT_PATCHLEVEL] =
            if (bootPatch != AndroidDeviceUtils.DO_NOT_REPORT) {
                DERTaggedObject(
                    true, AttestationConstants.TAG_BOOT_PATCHLEVEL,
                    ASN1Integer(bootPatch.toLong()),
                )
            } else {
                null
            }

        return props
    }

    fun getPatchLevel(uid: Int): Int = AndroidDeviceUtils.getPatchLevel(uid)

    fun getPatchLevelLong(uid: Int): Int = AndroidDeviceUtils.getVendorPatchLevelLong(uid)

    private fun buildKeyDescription(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): DERSequence {
        val ver = getAttestVersion(securityLevel)
        val kmVer = getKeymasterVersion(securityLevel)
        val teeEnforced = buildTeeEnforcedList(params, uid, securityLevel)
        val softwareEnforced = buildSoftwareEnforcedList(params, uid, securityLevel)
        val creationTime = System.currentTimeMillis()

        val uniqueId = if (params.includeUniqueId == true && params.attestationChallenge != null) {
            computeUniqueId(creationTime, getApplicationId(uid))
        } else {
            ByteArray(0)
        }

        val fields = arrayOf(
            ASN1Integer(ver.toLong()),
            ASN1Enumerated(securityLevel),
            ASN1Integer(kmVer.toLong()),
            ASN1Enumerated(securityLevel),
            DEROctetString(params.attestationChallenge ?: ByteArray(0)),
            DEROctetString(uniqueId),
            softwareEnforced,
            teeEnforced,
        )
        return DERSequence(fields)
    }

    private val hbk: ByteArray by lazy {
        val file = java.io.File("/data/adb/forge_store", "hbk")
        if (file.exists() && file.length() == 32L) {
            file.readBytes()
        } else {
            Logger.w("hbk not found, generating ephemeral hbk")
            ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        }
    }

    private fun computeUniqueId(creationTimeMs: Long, aaidDer: ByteArray): ByteArray {
        val temporalCounter = creationTimeMs / 2592000000L
        val message = ByteBuffer.allocate(8 + aaidDer.size + 1)
            .putLong(temporalCounter)
            .put(aaidDer)
            .put(0x00.toByte())
            .array()
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(hbk, "HmacSHA256"))
        return mac.doFinal(message).copyOf(16)
    }

    private fun buildTeeEnforcedList(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): DERSequence {
        val list = mutableListOf<ASN1Encodable>(
            DERTaggedObject(true, AttestationConstants.TAG_PURPOSE,
                DERSet(params.purpose.map { ASN1Integer(it.toLong()) }.toTypedArray())),
            DERTaggedObject(true, AttestationConstants.TAG_ALGORITHM,
                ASN1Integer(params.algorithm.toLong())),
            DERTaggedObject(true, AttestationConstants.TAG_KEY_SIZE,
                ASN1Integer(params.keySize.toLong())),
            DERTaggedObject(true, AttestationConstants.TAG_DIGEST,
                DERSet(params.digest.map { ASN1Integer(it.toLong()) }.toTypedArray())),
        )

        if (params.ecCurve != null) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_EC_CURVE,
                ASN1Integer(params.ecCurve.toLong())))
        }
        if (params.blockMode.isNotEmpty()) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_BLOCK_MODE,
                DERSet(params.blockMode.map { ASN1Integer(it.toLong()) }.toTypedArray())))
        }
        if (params.padding.isNotEmpty()) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_PADDING,
                DERSet(params.padding.map { ASN1Integer(it.toLong()) }.toTypedArray())))
        }
        if (params.rsaPublicExponent != null) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_RSA_PUBLIC_EXPONENT,
                ASN1Integer(params.rsaPublicExponent.toLong())))
        }

        val attestVersion = getAttestVersion(securityLevel)

        if (params.rsaOaepMgfDigest.isNotEmpty() && attestVersion >= 100) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_RSA_OAEP_MGF_DIGEST,
                DERSet(params.rsaOaepMgfDigest.map { ASN1Integer(it.toLong()) }.toTypedArray())))
        }
        if (params.rollbackResistance == true && attestVersion >= 3) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ROLLBACK_RESISTANCE,
                DERNull.INSTANCE))
        }
        if (params.earlyBootOnly == true && attestVersion >= 4) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_EARLY_BOOT_ONLY,
                DERNull.INSTANCE))
        }
        if (params.noAuthRequired == true) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_NO_AUTH_REQUIRED,
                DERNull.INSTANCE))
        }
        if (params.allowWhileOnBody == true) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ALLOW_WHILE_ON_BODY,
                DERNull.INSTANCE))
        }
        if (params.trustedUserPresenceRequired == true && attestVersion >= 3) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_TRUSTED_USER_PRESENCE_REQUIRED,
                DERNull.INSTANCE))
        }
        if (params.trustedConfirmationRequired == true && attestVersion >= 3) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_TRUSTED_CONFIRMATION_REQUIRED,
                DERNull.INSTANCE))
        }

        list.addAll(listOf(
            DERTaggedObject(true, AttestationConstants.TAG_ORIGIN,
                ASN1Integer((params.origin ?: 0).toLong())),
            DERTaggedObject(true, AttestationConstants.TAG_ROOT_OF_TRUST, buildRootOfTrust(null)),
        ))

        val simulated = getSimulatedHardwareProperties(uid)
        simulated.values.filterNotNull().forEach { list.add(it) }

        params.brand?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_BRAND, DEROctetString(it)))
        }
        params.device?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_DEVICE, DEROctetString(it)))
        }
        params.product?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_PRODUCT, DEROctetString(it)))
        }
        params.serial?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_SERIAL, DEROctetString(it)))
        }
        params.imei?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_IMEI, DEROctetString(it)))
        }
        params.meid?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_MEID, DEROctetString(it)))
        }
        params.manufacturer?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_MANUFACTURER, DEROctetString(it)))
        }
        params.model?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_MODEL, DEROctetString(it)))
        }
        if (attestVersion >= 300) {
            params.secondImei?.let {
                list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_ID_SECOND_IMEI, DEROctetString(it)))
            }
        }
        return DERSequence(list.sortedBy { (it as DERTaggedObject).tagNo }.toTypedArray())
    }

    private fun buildSoftwareEnforcedList(
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
        creationTimeMs: Long = System.currentTimeMillis(),
    ): DERSequence {
        val list = mutableListOf<ASN1Encodable>(
            DERTaggedObject(true, AttestationConstants.TAG_CREATION_DATETIME,
                ASN1Integer(creationTimeMs)),
        )
        if (params.attestationChallenge != null) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ATTESTATION_APPLICATION_ID,
                DEROctetString(getApplicationId(uid))))
        }
        if (getAttestVersion(securityLevel) >= 400) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_MODULE_HASH,
                DEROctetString(AndroidDeviceUtils.moduleHash)))
        }
        if (params.callerNonce == true) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_CALLER_NONCE,
                DERNull.INSTANCE))
        }
        params.activeDateTime?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ACTIVE_DATETIME,
                ASN1Integer(it.time)))
        }
        params.originationExpireDateTime?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_ORIGINATION_EXPIRE_DATETIME,
                ASN1Integer(it.time)))
        }
        params.usageExpireDateTime?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_USAGE_EXPIRE_DATETIME,
                ASN1Integer(it.time)))
        }
        params.usageCountLimit?.let {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_USAGE_COUNT_LIMIT,
                ASN1Integer(it.toLong())))
        }
        if (params.unlockedDeviceRequired == true) {
            list.add(DERTaggedObject(true, AttestationConstants.TAG_UNLOCKED_DEVICE_REQUIRED,
                DERNull.INSTANCE))
        }
        return DERSequence(list.sortedBy { (it as DERTaggedObject).tagNo }.toTypedArray())
    }

    private data class DigestWrapper(val digest: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            return digest.contentEquals((other as DigestWrapper).digest)
        }
        override fun hashCode(): Int = digest.contentHashCode()
    }

    private fun getApplicationId(uid: Int): ByteArray {
        val appUid = uid % 100000
        if (appUid == 0 || appUid == 1000) {
            return buildApplicationIdDer(listOf("AndroidSystem" to 1L), emptySet())
        }

        try {
            val pm = getPackageManager()
            val packages = pm.getPackagesForUid(uid) ?: return emptyAppId()
            val userId = uid / 100000

            val sha256 = MessageDigest.getInstance("SHA-256")
            val packageInfoList = mutableListOf<DERSequence>()
            val signatureDigests = mutableSetOf<DigestWrapper>()

            for (pkg in packages) {
                val pi = try {
                    getPackageInfoReflect(pm, pkg, userId)
                } catch (_: Exception) { continue }

                val pkgName = pi.packageName
                val vc = pi.longVersionCode

                packageInfoList.add(
                    DERSequence(arrayOf(
                        DEROctetString(pkgName.toByteArray(Charsets.UTF_8)),
                        ASN1Integer(vc),
                    ))
                )

                pi.signingInfo?.signingCertificateHistory?.forEach { sig ->
                    signatureDigests.add(DigestWrapper(sha256.digest(sig.toByteArray())))
                }
            }

            if (packageInfoList.isEmpty()) return emptyAppId()

            return DERSequence(arrayOf(
                DERSet(packageInfoList.toTypedArray()),
                DERSet(signatureDigests.map { DEROctetString(it.digest) }.toTypedArray()),
            )).encoded
        } catch (_: Exception) { return emptyAppId() }
    }

    private fun buildApplicationIdDer(
        packages: List<Pair<String, Long>>,
        digests: Set<DigestWrapper>,
    ): ByteArray {
        val packageInfoList =
            packages.map { (name, version) ->
                DERSequence(
                    arrayOf(
                        DEROctetString(name.toByteArray(Charsets.UTF_8)),
                        ASN1Integer(version),
                    )
                )
            }
        val applicationIdSequence =
            DERSequence(
                arrayOf(
                    DERSet(packageInfoList.toTypedArray()),
                    DERSet(digests.map { DEROctetString(it.digest) }.toTypedArray()),
                )
            )
        return applicationIdSequence.encoded
    }

    private fun getPackageInfoReflect(pm: android.content.pm.PackageManager, pkg: String, userId: Int): android.content.pm.PackageInfo {
        val flags = android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES.toLong()
        return try {
            pm.javaClass.getMethod("getPackageInfo", String::class.java, java.lang.Long.TYPE, Int::class.javaPrimitiveType!!)
                .invoke(pm, pkg, flags, userId) as android.content.pm.PackageInfo
        } catch (_: Exception) {
            pm.javaClass.getMethod("getPackageInfo", String::class.java, Int::class.javaPrimitiveType!!, Int::class.javaPrimitiveType!!)
                .invoke(pm, pkg, flags.toInt(), userId) as android.content.pm.PackageInfo
        }
    }

    private fun getPackageManager(): android.content.pm.PackageManager {
        val atClass = Class.forName("android.app.ActivityThread")
        val at = atClass.getMethod("systemMain").invoke(null)
        val ctx = atClass.getMethod("getSystemContext").invoke(at) as android.content.Context
        return ctx.packageManager
    }

    private fun emptyAppId(): ByteArray {
        val sha256 = MessageDigest.getInstance("SHA-256")
        return DERSequence(arrayOf(
            DERSet(arrayOf<DERSequence>()),
            DERSet(arrayOf(DEROctetString(sha256.digest(ByteArray(0))))),
        )).encoded
    }

    private fun readModuleHash(): ByteArray {
        val value = try {
            val cls = Class.forName("android.os.SystemProperties")
            val m = cls.getMethod("get", String::class.java, String::class.java)
            m.invoke(null, "ro.boot.avb_modules_hash", "") as String
        } catch (_: Exception) { "" }
        if (value.isNotEmpty()) {
            val bytes = hexStringToByteArray(value)
            persistBootFile("module_hash.bin", bytes)
            return bytes
        }
        DeviceAttestationService.cachedData?.moduleHash?.let { return it }
        readBootFile("module_hash.bin")?.let { return it }
        return randomBytes(32).also { persistBootFile("module_hash.bin", it) }
    }

    private fun randomBytes(size: Int): ByteArray {
        return java.security.SecureRandom().run { ByteArray(size).also { nextBytes(it) } }
    }

    private fun persistBootFile(name: String, value: ByteArray) {
        try {
            java.io.File("/data/adb/forge_store", name).writeBytes(value)
        } catch (_: Exception) {}
    }

    private fun readBootFile(name: String): ByteArray? {
        try {
            val file = java.io.File("/data/adb/forge_store", name)
            if (file.exists() && file.length() == 32L) return file.readBytes()
        } catch (_: Exception) {}
        return null
    }

    private fun initBootKey(): ByteArray {
        val value = try {
            val cls = Class.forName("android.os.SystemProperties")
            val m = cls.getMethod("get", String::class.java, String::class.java)
            m.invoke(null, "ro.boot.vbmeta.public_key_digest", "") as String
        } catch (_: Exception) { "" }
        if (value.isNotEmpty() && value.length >= 64) {
            val bytes = hexStringToByteArray(value)
            persistBootFile("boot_key.bin", bytes)
            return bytes
        }
        DeviceAttestationService.cachedData?.verifiedBootKey?.let { return it }
        readBootFile("boot_key.bin")?.let { return it }
        return randomBytes(32).also { persistBootFile("boot_key.bin", it) }
    }

    private fun initBootHash(): ByteArray {
        val value = try {
            val cls = Class.forName("android.os.SystemProperties")
            val m = cls.getMethod("get", String::class.java, String::class.java)
            m.invoke(null, "ro.boot.vbmeta.digest", "") as String
        } catch (_: Exception) { "" }
        if (value.isNotEmpty() && value.length >= 64) {
            val bytes = hexStringToByteArray(value)
            persistBootFile("boot_hash.bin", bytes)
            return bytes
        }
        DeviceAttestationService.cachedData?.verifiedBootHash?.let { return it }
        readBootFile("boot_hash.bin")?.let { return it }
        return randomBytes(32).also { persistBootFile("boot_hash.bin", it) }
    }

    private fun hexStringToByteArray(s: String): ByteArray {
        val len = s.length
        val data = ByteArray(len / 2)
        for (i in 0 until len step 2) {
            data[i / 2] = ((Character.digit(s[i], 16) shl 4) + Character.digit(s[i + 1], 16)).toByte()
        }
        return data
    }
}

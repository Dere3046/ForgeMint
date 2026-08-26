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
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.cert.X509CertificateHolder

object DeviceAttestationService {

    data class AttestationData(
        val moduleHash: ByteArray?,
        val verifiedBootKey: ByteArray?,
        val verifiedBootHash: ByteArray?,
        val attestVersion: Int?,
        val keymasterVersion: Int?,
        val osVersion: Int?,
        val osPatchLevel: Int?,
        val vendorPatchLevel: Int?,
        val bootPatchLevel: Int?,
        val cannotAttestIds: Boolean,
        val deviceLocked: Boolean? = null,
        val verifiedBootState: Int? = null,
        val strongBoxAvailable: Boolean? = null,
        val strongBoxAttestationVersion: Int? = null,
        val brand: String? = null,
        val device: String? = null,
        val product: String? = null,
        val manufacturer: String? = null,
        val model: String? = null,
        val serial: String? = null,
        val imei: String? = null,
        val meid: String? = null,
        val imei2: String? = null,
    )

    private const val TEE_CHECK_KEY_ALIAS = "ForgeStore_AttestationCheck"

    val isTeeFunctional: Boolean by lazy { checkTeeFunctionality() }
    val cachedData: AttestationData? by lazy { fetchAttestationData() }

    fun setup() {
        Logger.i("TEE check: functional=${isTeeFunctional}")
        if (cachedData != null) {
            Logger.d("TEE attestation cache: osVersion=${cachedData!!.osVersion} osPatch=${cachedData!!.osPatchLevel}")
        } else {
            Logger.w("TEE attestation cache unavailable, using fallbacks")
        }
    }

    private fun checkTeeFunctionality(): Boolean {
        if (tryGenerateTeeKey(deviceProperties = true)) return true
        return tryGenerateTeeKey(deviceProperties = false)
    }

    private fun tryGenerateTeeKey(deviceProperties: Boolean): Boolean {
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            runCatching { keyStore.deleteEntry(TEE_CHECK_KEY_ALIAS) }
            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val challenge = ByteArray(16).apply { SecureRandom().nextBytes(this) }
            val specBuilder = KeyGenParameterSpec.Builder(TEE_CHECK_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
            if (deviceProperties && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                specBuilder.setDevicePropertiesAttestationIncluded(true)
            }
            kpg.initialize(specBuilder.build())
            kpg.generateKeyPair()
            Logger.i("TEE functionality check passed deviceProperties=$deviceProperties")
            true
        } catch (_: Exception) {
            Logger.w("TEE functionality check failed deviceProperties=$deviceProperties")
            false
        }
    }

    private fun getAttestationCertificate(): X509Certificate? {
        if (!isTeeFunctional) return null
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val certChain = keyStore.getCertificateChain(TEE_CHECK_KEY_ALIAS)
            if (certChain.isNullOrEmpty()) {
                Logger.w("No certificate chain for TEE check key")
                null
            } else {
                keyStore.deleteEntry(TEE_CHECK_KEY_ALIAS)
                certChain[0] as X509Certificate
            }
        } catch (_: Exception) { null }
    }

    private fun fetchAttestationData(): AttestationData? {
        val leafCert = getAttestationCertificate() ?: return null
        return try {
            val leafHolder = X509CertificateHolder(leafCert.encoded)
            val extension = leafHolder.getExtension(AttestationConstants.ATTESTATION_OID_OBJ) ?: return null
            val keyDescriptionSeq = ASN1Sequence.getInstance(extension.extnValue.octets)
            val fields = keyDescriptionSeq.toArray()

            val attestVersion = ASN1Integer.getInstance(
                fields[AttestationConstants.KEY_DESCRIPTION_ATTESTATION_VERSION_INDEX]
            ).positiveValue.toInt()
            val keymasterVersion = ASN1Integer.getInstance(
                fields[AttestationConstants.KEY_DESCRIPTION_KEYMINT_VERSION_INDEX]
            ).positiveValue.toInt()

            var moduleHash: ByteArray? = null
            var verifiedBootKey: ByteArray? = null
            var verifiedBootHash: ByteArray? = null
            var osVersion: Int? = null
            var osPatchLevel: Int? = null
            var vendorPatchLevel: Int? = null
            var bootPatchLevel: Int? = null
            var deviceLocked: Boolean? = null
            var verifiedBootState: Int? = null

            val softwareEnforced = ASN1Sequence.getInstance(
                fields[AttestationConstants.KEY_DESCRIPTION_SOFTWARE_ENFORCED_INDEX]
            )
            moduleHash = softwareEnforced.toArray()
                .firstOrNull { (it as? ASN1TaggedObject)?.tagNo == AttestationConstants.TAG_MODULE_HASH }
                ?.let { ASN1OctetString.getInstance((it as ASN1TaggedObject).baseObject).octets }

            val teeEnforced = ASN1Sequence.getInstance(
                fields[AttestationConstants.KEY_DESCRIPTION_TEE_ENFORCED_INDEX]
            )
            teeEnforced.forEach { element ->
                val tagged = element as ASN1TaggedObject
                when (tagged.tagNo) {
                    AttestationConstants.TAG_ROOT_OF_TRUST -> {
                        val rotSeq = ASN1Sequence.getInstance(tagged.baseObject.toASN1Primitive())
                        if (rotSeq.size() >= 4) {
                            verifiedBootKey = ASN1OctetString.getInstance(
                                rotSeq.getObjectAt(AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX)
                            ).octets
                            verifiedBootHash = ASN1OctetString.getInstance(
                                rotSeq.getObjectAt(AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX)
                            ).octets
                            deviceLocked =
                                ASN1Boolean.getInstance(rotSeq.getObjectAt(AttestationConstants.ROOT_OF_TRUST_DEVICE_LOCKED_INDEX))
                                    .isTrue
                            verifiedBootState =
                                ASN1Enumerated.getInstance(rotSeq.getObjectAt(AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX))
                                    .value
                                    .toInt()
                        }
                    }
                    AttestationConstants.TAG_OS_VERSION -> {
                        osVersion = ASN1Integer.getInstance(tagged.baseObject.toASN1Primitive()).positiveValue.toInt()
                    }
                    AttestationConstants.TAG_OS_PATCHLEVEL -> {
                        osPatchLevel = ASN1Integer.getInstance(tagged.baseObject.toASN1Primitive()).positiveValue.toInt()
                    }
                    AttestationConstants.TAG_VENDOR_PATCHLEVEL -> {
                        vendorPatchLevel = ASN1Integer.getInstance(tagged.baseObject.toASN1Primitive()).positiveValue.toInt()
                    }
                    AttestationConstants.TAG_BOOT_PATCHLEVEL -> {
                        bootPatchLevel = ASN1Integer.getInstance(tagged.baseObject.toASN1Primitive()).positiveValue.toInt()
                    }
                }
            }

            if (verifiedBootKey?.all { it == 0.toByte() } == true) verifiedBootKey = null
            if (verifiedBootHash?.all { it == 0.toByte() } == true) verifiedBootHash = null

            val softwareElements = softwareEnforced.toArray().toList()
            val teeElements = teeEnforced.toArray().toList()

            Logger.d("Parsed TEE attestation: ver=$attestVersion os=$osVersion osPatch=$osPatchLevel")
            AttestationData(
                moduleHash = moduleHash,
                verifiedBootKey = verifiedBootKey,
                verifiedBootHash = verifiedBootHash,
                attestVersion = attestVersion,
                keymasterVersion = keymasterVersion,
                osVersion = osVersion,
                osPatchLevel = osPatchLevel,
                vendorPatchLevel = vendorPatchLevel,
                bootPatchLevel = bootPatchLevel,
                cannotAttestIds = false,
                deviceLocked = deviceLocked,
                verifiedBootState = verifiedBootState,
                brand = idFrom(softwareElements, teeElements, AttestationConstants.TAG_ATTESTATION_ID_BRAND),
                device = idFrom(softwareElements, teeElements, AttestationConstants.TAG_ATTESTATION_ID_DEVICE),
                product = idFrom(softwareElements, teeElements, AttestationConstants.TAG_ATTESTATION_ID_PRODUCT),
                manufacturer = idFrom(softwareElements, teeElements, AttestationConstants.TAG_ATTESTATION_ID_MANUFACTURER),
                model = idFrom(softwareElements, teeElements, AttestationConstants.TAG_ATTESTATION_ID_MODEL),
                serial = idFrom(softwareElements, teeElements, AttestationConstants.TAG_ATTESTATION_ID_SERIAL),
                imei = idFrom(softwareElements, teeElements, AttestationConstants.TAG_ATTESTATION_ID_IMEI),
                meid = idFrom(softwareElements, teeElements, AttestationConstants.TAG_ATTESTATION_ID_MEID),
                imei2 = idFrom(softwareElements, teeElements, AttestationConstants.TAG_ATTESTATION_ID_SECOND_IMEI),
            )
        } catch (e: Exception) {
            Logger.e("Failed to parse TEE attestation data", e)
            AttestationData(null, null, null, null, null, null, null, null, null, true)
        }
    }

    private fun idFrom(software: List<ASN1Encodable>, tee: List<ASN1Encodable>, tag: Int): String? {
        for (elements in listOf(software, tee)) {
            val element = elements.firstOrNull { (it as? ASN1TaggedObject)?.tagNo == tag } ?: continue
            return runCatching {
                String(
                    ASN1OctetString.getInstance((element as ASN1TaggedObject).baseObject).octets,
                    Charsets.UTF_8,
                )
            }.getOrNull()
        }
        return null
    }
}

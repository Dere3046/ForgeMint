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

import android.os.Parcel
import android.os.Parcelable
import android.security.keystore.KeyProperties
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.PublicKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Null
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.system.keystore2.Authorization

object AttestationPatcher {

    fun patchCertificateChain(
        originalChain: Array<Certificate>?,
        uid: Int,
        notBefore: java.util.Date? = null,
        notAfter: java.util.Date? = null,
    ): Array<Certificate> {
        if (originalChain.isNullOrEmpty()) {
            Logger.w("patchCertificateChain: null or empty chain for UID $uid")
            return originalChain ?: emptyArray()
        }

        return runCatching {
            val originalLeaf = originalChain[0] as X509Certificate
            val originalLeafHolder = X509CertificateHolder(originalLeaf.encoded)

            val parsed = parseAttestationExtension(originalLeafHolder) ?: return originalChain

            val keybox = getKeyboxForAlgorithm(originalLeaf.sigAlgName)

            val patchedLeaf = createPatchedLeafCertificate(
                originalLeafHolder, parsed, keybox, uid,
                notBefore, notAfter,
            )

            val newChain = listOf(patchedLeaf) + keybox.certificates
            Logger.d("Patched cert chain for UID $uid, chain size=${newChain.size}")
            newChain.toTypedArray()
        }.getOrElse {
            Logger.e("Failed to patch certificate chain for UID $uid", it)
            originalChain
        }
    }

    fun formatAsn1Primitive(obj: ASN1Encodable?): String {
        val primitive = obj?.toASN1Primitive()
        return when (primitive) {
            null -> "NULL"
            is ASN1Integer -> primitive.value.toString()
            is ASN1Enumerated -> primitive.value.toString()
            is ASN1Boolean -> primitive.isTrue.toString()
            is ASN1Null -> "NULL"
            is ASN1OctetString -> {
                val bytes = primitive.octets
                if (bytes.all { it >= 32 && it < 127 }) {
                    "\"${String(bytes, StandardCharsets.UTF_8)}\""
                } else if (bytes.isEmpty()) {
                    "\"\""
                } else {
                    "#${bytes.toHex()}"
                }
            }
            is ASN1TaggedObject ->
                "[TAG ${primitive.tagNo}]${formatAsn1Primitive(primitive.baseObject)}"
            is ASN1Sequence ->
                primitive.map { formatAsn1Primitive(it) }
                    .joinToString(prefix = "[", postfix = "]", separator = ", ")
            is ASN1Set ->
                primitive.map { formatAsn1Primitive(it) }
                    .joinToString(prefix = "{", postfix = "}", separator = ", ")
            else -> primitive.toString()
        }
    }

    private val attestTagNames: Map<Int, String> by lazy {
        AttestationConstants::class.java.fields
            .filter { it.name.startsWith("TAG_") && it.type == Int::class.java }
            .associate { (it.get(null) as Int) to it.name.removePrefix("TAG_") }
    }

    fun formatAttestationExtension(cert: X509Certificate): String? {
        val rawExtension = cert.getExtensionValue(AttestationConstants.ATTESTATION_OID) ?: return null
        return runCatching {
            val keyDescriptionDer = ASN1OctetString.getInstance(rawExtension).octets
            formatKeyDescription(ASN1Sequence.getInstance(keyDescriptionDer))
        }.getOrElse { "<unparseable attestation extension: ${it.message}>" }
    }

    fun formatCertChain(chain: List<Certificate>): String =
        chain.mapIndexed { index, cert ->
            val x509 = cert as? X509Certificate ?: return@mapIndexed "[$index] <non-X509>"
            "[$index] subject=${x509.subjectX500Principal.name} " +
                "issuer=${x509.issuerX500Principal.name} " +
                "serial=${x509.serialNumber.toString(16)} " +
                "notBefore=${x509.notBefore} notAfter=${x509.notAfter}"
        }.joinToString(separator = " ; ")

    fun formatChainVerification(chain: List<Certificate>): String {
        if (chain.size < 2) return "<single cert; nothing to chain-verify>"
        return (0 until chain.size - 1).joinToString(separator = " ; ") { i ->
            val child = chain[i] as? X509Certificate ?: return@joinToString "[$i]<non-X509>"
            val parent = chain[i + 1] as? X509Certificate ?: return@joinToString "[$i]<parent non-X509>"
            val outcome =
                runCatching {
                    child.verify(parent.publicKey)
                    "OK"
                }.getOrElse { "FAIL(${it.javaClass.simpleName}: ${it.message?.take(80)})" }
            val rsaSizes =
                (parent.publicKey as? RSAPublicKey)?.let {
                    val sigBytes = child.signature.size
                    val modBytes = (it.modulus.bitLength() + 7) / 8
                    " sig=${sigBytes}B mod=${modBytes}B" +
                        if (sigBytes > modBytes) " OVERSIZE" else ""
                } ?: ""
            "[$i]${describeKey(child.publicKey)}<-[${i + 1}]${describeKey(parent.publicKey)}:" +
                "$outcome$rsaSizes"
        }
    }

    fun formatChainKeys(chain: List<Certificate>): String =
        chain.mapIndexed { index, cert ->
            val x509 = cert as? X509Certificate ?: return@mapIndexed "[$index]<non-X509>"
            "[$index]${describeKey(x509.publicKey)} " +
                "subj=${x509.subjectX500Principal.name} " +
                "iss=${x509.issuerX500Principal.name} " +
                "sigLen=${x509.signature.size}B"
        }.joinToString(separator = " ; ")

    private fun describeKey(key: PublicKey): String =
        when (key) {
            is RSAPublicKey -> "RSA${key.modulus.bitLength()}"
            is ECPublicKey -> "EC${key.params.curve.field.fieldSize}"
            else -> key.algorithm
        }

    private fun formatKeyDescription(seq: ASN1Sequence): String {
        val fields = seq.toArray()
        return "attestVer=${formatAsn1Primitive(fields[AttestationConstants.KEY_DESCRIPTION_ATTESTATION_VERSION_INDEX])} " +
            "attestSecLvl=${formatSecurityLevel(fields[AttestationConstants.KEY_DESCRIPTION_ATTESTATION_SECURITY_LEVEL_INDEX])} " +
            "kmVer=${formatAsn1Primitive(fields[AttestationConstants.KEY_DESCRIPTION_KEYMINT_VERSION_INDEX])} " +
            "kmSecLvl=${formatSecurityLevel(fields[AttestationConstants.KEY_DESCRIPTION_KEYMINT_SECURITY_LEVEL_INDEX])} " +
            "challenge=${formatAsn1Primitive(fields[AttestationConstants.KEY_DESCRIPTION_ATTESTATION_CHALLENGE_INDEX])} " +
            "uniqueId=${formatAsn1Primitive(fields[AttestationConstants.KEY_DESCRIPTION_UNIQUE_ID_INDEX])} " +
            "sw=${formatAuthorizationList(fields[AttestationConstants.KEY_DESCRIPTION_SOFTWARE_ENFORCED_INDEX])} " +
            "tee=${formatAuthorizationList(fields[AttestationConstants.KEY_DESCRIPTION_TEE_ENFORCED_INDEX])}"
    }

    private fun formatSecurityLevel(obj: ASN1Encodable): String {
        val level = (obj.toASN1Primitive() as? ASN1Enumerated)?.value?.toInt()
        val name =
            when (level) {
                0 -> "Software"
                1 -> "TEE"
                2 -> "StrongBox"
                else -> "?"
            }
        return "$level($name)"
    }

    private fun formatAuthorizationList(obj: ASN1Encodable): String {
        val seq = obj.toASN1Primitive() as? ASN1Sequence ?: return formatAsn1Primitive(obj)
        return seq.map { element ->
            val tagged = element as? ASN1TaggedObject ?: return@map formatAsn1Primitive(element)
            val name = attestTagNames[tagged.tagNo] ?: "TAG"
            val value =
                if (tagged.tagNo == AttestationConstants.TAG_ROOT_OF_TRUST) {
                    formatRootOfTrust(tagged.baseObject)
                } else {
                    formatAsn1Primitive(tagged.baseObject)
                }
            "${tagged.tagNo}($name)=$value"
        }.joinToString(prefix = "[", postfix = "]", separator = ", ")
    }

    private fun formatRootOfTrust(obj: ASN1Encodable): String {
        val fields = (obj.toASN1Primitive() as? ASN1Sequence)?.toArray()
            ?: return formatAsn1Primitive(obj)
        val state = fields.getOrNull(AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX)
        val stateName =
            when ((state?.toASN1Primitive() as? ASN1Enumerated)?.value?.toInt()) {
                0 -> "Verified"
                1 -> "SelfSigned"
                2 -> "Unverified"
                3 -> "Failed"
                else -> "?"
            }
        return "[bootKey=${formatAsn1Primitive(fields.getOrNull(AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX))}, " +
            "deviceLocked=${formatAsn1Primitive(fields.getOrNull(AttestationConstants.ROOT_OF_TRUST_DEVICE_LOCKED_INDEX))}, " +
            "verifiedBootState=${formatAsn1Primitive(state)}($stateName), " +
            "bootHash=${formatAsn1Primitive(fields.getOrNull(AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX))}]"
    }

    private fun signatureAlgorithmFor(signingKey: java.security.PrivateKey): String {
        return when (signingKey) {
            is java.security.interfaces.ECPrivateKey -> "SHA256withECDSA"
            is java.security.interfaces.RSAPrivateKey -> "SHA256withRSA"
            else -> throw IllegalArgumentException("Unsupported keybox signing key type: ${signingKey.algorithm}")
        }
    }

    private fun getKeyboxForAlgorithm(algorithm: String): CertificateBuilder.KeyboxData {
        val keyType = when {
            algorithm.contains("RSA", ignoreCase = true) -> KeyProperties.KEY_ALGORITHM_RSA
            algorithm.contains("EC", ignoreCase = true) -> KeyProperties.KEY_ALGORITHM_EC
            else -> algorithm
        }

        val matching = KeyboxReader.loadKeybox(
            when (keyType) {
                KeyProperties.KEY_ALGORITHM_RSA -> android.hardware.security.keymint.Algorithm.RSA
                else -> android.hardware.security.keymint.Algorithm.EC
            }
        )
        if (matching != null) return matching
        if (!ConfigManager.isFallbackEnabled) {
            throw IllegalArgumentException("No '$keyType' attestation key and fallback disabled")
        }

        return KeyboxReader.loadAnyKeybox()?.also {
            Logger.d("No '$keyType' attestation key; re-signing under available keybox key")
        } ?: throw IllegalArgumentException("No usable attestation key (requested '$keyType')")
    }

    private fun createPatchedLeafCertificate(
        originalLeafHolder: X509CertificateHolder,
        parsed: ParsedAttestation,
        keybox: CertificateBuilder.KeyboxData,
        uid: Int,
        notBefore: java.util.Date? = null,
        notAfter: java.util.Date? = null,
    ): Certificate {
        val newIssuer = X509CertificateHolder(keybox.certificates[0].encoded).subject

        val builder = X509v3CertificateBuilder(
            newIssuer,
            originalLeafHolder.serialNumber,
            notBefore ?: originalLeafHolder.notBefore,
            notAfter ?: originalLeafHolder.notAfter,
            originalLeafHolder.subject,
            originalLeafHolder.subjectPublicKeyInfo,
        )

        val patchedExtension = createPatchedAttestationExtension(parsed, uid)

        originalLeafHolder.extensions.extensionOIDs.forEach {
            builder.addExtension(
                if (it.id == AttestationConstants.ATTESTATION_OID) patchedExtension
                else originalLeafHolder.getExtension(it)
            )
        }

        val signer = JcaContentSignerBuilder(signatureAlgorithmFor(keybox.keyPair.private))
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(keybox.keyPair.private)
        val newCert = JcaX509CertificateConverter().getCertificate(builder.build(signer))

        val sigBytes = (newCert as X509Certificate).signature
        Logger.d("Patched leaf cert signature: ${sigBytes.toHex()}")

        return newCert
    }

    private fun parseAttestationExtension(certHolder: X509CertificateHolder): ParsedAttestation? {
        val extension = certHolder.getExtension(AttestationConstants.ATTESTATION_OID_OBJ) ?: return null
        val sequence = ASN1Sequence.getInstance(extension.extnValue.octets)
        val allFields = sequence.toArray()

        val softwareEnforced = allFields[AttestationConstants.KEY_DESCRIPTION_SOFTWARE_ENFORCED_INDEX] as? ASN1Sequence
        val teeEnforced = allFields[AttestationConstants.KEY_DESCRIPTION_TEE_ENFORCED_INDEX] as ASN1Sequence
        val softwareElements = softwareEnforced?.toArray()?.toList()
        val teeElements = teeEnforced.toArray().toList()

        var originalRootOfTrust: ASN1Encodable? = null
        for (element in teeElements) {
            val tagged = element as? ASN1TaggedObject ?: continue
            if (tagged.tagNo == AttestationConstants.TAG_ROOT_OF_TRUST) {
                originalRootOfTrust = tagged.baseObject.toASN1Primitive()
                break
            }
        }
        if (originalRootOfTrust == null) {
            for (element in softwareElements.orEmpty()) {
                val tagged = element as? ASN1TaggedObject ?: continue
                if (tagged.tagNo == AttestationConstants.TAG_ROOT_OF_TRUST) {
                    originalRootOfTrust = tagged.baseObject.toASN1Primitive()
                    break
                }
            }
        }
        return ParsedAttestation(allFields, teeElements, softwareElements, originalRootOfTrust)
    }

    private fun sequenceContainsRootOfTrust(seq: ASN1Encodable): Boolean {
        if (seq !is ASN1Sequence) return false
        return seq.any { element ->
            (element as? ASN1TaggedObject)?.tagNo == AttestationConstants.TAG_ROOT_OF_TRUST
        }
    }

    private fun createPatchedAttestationExtension(parsed: ParsedAttestation, uid: Int): Extension {
        val (allFields, teeElements, softwareElements, originalRootOfTrust) = parsed

        val overrides = mutableMapOf<Int, DERTaggedObject>()
        val removeTags = mutableSetOf<Int>()

        val newRootOfTrust = AttestationBuilder.buildRootOfTrust(originalRootOfTrust)
        overrides[AttestationConstants.TAG_ROOT_OF_TRUST] =
            DERTaggedObject(true, AttestationConstants.TAG_ROOT_OF_TRUST, newRootOfTrust)

        val simulatedProperties = AttestationBuilder.getSimulatedHardwareProperties(uid)
        for ((tag, value) in simulatedProperties) {
            if (value != null) {
                overrides[tag] = value
            } else {
                removeTags.add(tag)
            }
        }

        val idOverrides = buildDeviceIdOverrides(Harvester.harvestedDeviceIds())

        val (patchedSoftware, _) = patchAuthorizationList(softwareElements.orEmpty(), overrides, removeTags)
        val (patchedTee, _) = patchAuthorizationList(teeElements, overrides, removeTags, insertMissing = true)

        val finalSoftware = replaceOnly(patchedSoftware, idOverrides)
        val finalTee = replaceOnly(patchedTee, idOverrides)

        allFields[AttestationConstants.KEY_DESCRIPTION_SOFTWARE_ENFORCED_INDEX] =
            DERSequence(finalSoftware.toTypedArray())
        allFields[AttestationConstants.KEY_DESCRIPTION_TEE_ENFORCED_INDEX] =
            DERSequence(finalTee.toTypedArray())

        val patchedSequence = DERSequence(allFields)
        val patchedOctets = DEROctetString(patchedSequence)

        return Extension(
            AttestationConstants.ATTESTATION_OID_OBJ,
            false, patchedOctets,
        )
    }

    private fun patchAuthorizationList(
        elements: List<ASN1Encodable>,
        overrides: Map<Int, DERTaggedObject>,
        removeTags: Set<Int>,
        insertMissing: Boolean = false,
    ): Pair<List<ASN1Encodable>, Set<Int>> {
        val seen = mutableSetOf<Int>()
        val out = mutableListOf<ASN1Encodable>()

        for (element in elements) {
            val tagged = element as? DERTaggedObject
            val tag = tagged?.tagNo
            if (tag != null && tag in removeTags) continue
            if (tag != null && tag in overrides) {
                out.add(overrides[tag]!!)
                seen.add(tag)
            } else {
                out.add(element)
            }
        }

        if (insertMissing) {
            for (tag in overrides.keys.sorted()) {
                if (tag in seen) continue
                val elem = overrides[tag]!!
                val index = out.indexOfFirst {
                    ((it as? DERTaggedObject)?.tagNo ?: Int.MAX_VALUE) > tag
                }
                if (index < 0) out.add(elem) else out.add(index, elem)
                seen.add(tag)
            }
        }

        return out to seen
    }

    private fun buildDeviceIdOverrides(ids: Harvester.DeviceIds): Map<Int, DERTaggedObject> {
        val map = mutableMapOf<Int, DERTaggedObject>()
        fun put(tag: Int, value: ByteArray?) {
            if (value != null) {
                map[tag] = DERTaggedObject(true, tag, DEROctetString(value))
            }
        }
        put(AttestationConstants.TAG_ATTESTATION_ID_BRAND, ids.brand)
        put(AttestationConstants.TAG_ATTESTATION_ID_DEVICE, ids.device)
        put(AttestationConstants.TAG_ATTESTATION_ID_PRODUCT, ids.product)
        put(AttestationConstants.TAG_ATTESTATION_ID_SERIAL, ids.serial)
        put(AttestationConstants.TAG_ATTESTATION_ID_IMEI, ids.imei)
        put(AttestationConstants.TAG_ATTESTATION_ID_MEID, ids.meid)
        put(AttestationConstants.TAG_ATTESTATION_ID_MANUFACTURER, ids.manufacturer)
        put(AttestationConstants.TAG_ATTESTATION_ID_MODEL, ids.model)
        put(AttestationConstants.TAG_ATTESTATION_ID_SECOND_IMEI, ids.secondImei)
        return map
    }

    private fun replaceOnly(elements: List<ASN1Encodable>, overrides: Map<Int, DERTaggedObject>): List<ASN1Encodable> {
        return elements.map { element ->
            val tagged = element as? DERTaggedObject
            val tag = tagged?.tagNo
            if (tag != null && tag in overrides) overrides[tag]!! else element
        }
    }

    private data class ParsedAttestation(
        val allFields: Array<ASN1Encodable>,
        val teeEnforcedElements: List<ASN1Encodable>,
        val softwareEnforcedElements: List<ASN1Encodable>?,
        val rootOfTrust: ASN1Encodable?,
    )

    fun patchAuthorizations(
        authorizations: Array<Authorization>?,
        callingUid: Int,
    ): Array<Authorization>? {
        if (authorizations == null) return null

        val osPatch = AndroidDeviceUtils.getPatchLevel(callingUid)
        val vendorPatch = AndroidDeviceUtils.getVendorPatchLevelLong(callingUid)
        val bootPatch = AndroidDeviceUtils.getBootPatchLevelLong(callingUid)

        val patched = authorizations.map { auth ->
            val replacement = when (auth.keyParameter.tag) {
                Tag.OS_PATCHLEVEL ->
                    if (osPatch != AndroidDeviceUtils.DO_NOT_REPORT) osPatch else null
                Tag.VENDOR_PATCHLEVEL ->
                    if (vendorPatch != AndroidDeviceUtils.DO_NOT_REPORT) vendorPatch else null
                Tag.BOOT_PATCHLEVEL ->
                    if (bootPatch != AndroidDeviceUtils.DO_NOT_REPORT) bootPatch else null
                else -> null
            }
            if (replacement != null) {
                Authorization().apply {
                    keyParameter = KeyParameter().apply {
                        tag = auth.keyParameter.tag
                        value = KeyParameterValue.integer(replacement)
                    }
                    securityLevel = auth.securityLevel
                }
            } else {
                auth
            }
        }.toTypedArray()

        return normalizeAuthorizationLayout(patched)
    }

    private fun normalizeAuthorizationLayout(authorizations: Array<Authorization>): Array<Authorization> {
        if (authorizations.size < 2) return authorizations
        if (!flatStrideFingerprintMatches(marshalTypedArray(authorizations))) return authorizations
        val n = authorizations.size
        for (src in 1 until n) {
            val candidate = moveAuthorization(authorizations, src, 0)
            if (!flatStrideFingerprintMatches(marshalTypedArray(candidate))) return candidate
        }
        for (src in 0 until n) {
            for (dst in 0 until n) {
                if (src == dst) continue
                val candidate = moveAuthorization(authorizations, src, dst)
                if (!flatStrideFingerprintMatches(marshalTypedArray(candidate))) return candidate
            }
        }
        return authorizations
    }

    private fun moveAuthorization(
        authorizations: Array<Authorization>,
        src: Int,
        dst: Int,
    ): Array<Authorization> {
        val reordered = authorizations.toMutableList()
        reordered.add(dst, reordered.removeAt(src))
        return reordered.toTypedArray()
    }

    private fun marshalTypedArray(authorizations: Array<Authorization>): ByteArray {
        val parcel = Parcel.obtain()
        return try {
            parcel.writeTypedArray(authorizations.map { it as Parcelable }.toTypedArray(), 0)
            parcel.marshall()
        } finally {
            parcel.recycle()
        }
    }

    private fun flatStrideFingerprintMatches(marshalled: ByteArray): Boolean =
        runCatching {
            val parcel = ByteBuffer.wrap(marshalled).order(ByteOrder.LITTLE_ENDIAN)
            val count = parcel.getInt(0)
            if (count !in 1..MAX_AUTH_COUNT) return@runCatching false
            var off = 4
            var lastSec = 0L
            var lastTag = 0L
            var lastUnion = 0L
            repeat(count) {
                lastSec = u32(parcel, off)
                lastTag = u32(parcel, off + 4)
                lastUnion = u32(parcel, off + 8)
                off += FLAT_STRIDE_HEADER
                off = alignWord(off + flatPayloadSize(parcel, off, lastUnion))
            }
            off = skipDriftedByteArray(parcel, off)
            off = skipDriftedByteArray(parcel, off)
            val modtime = parcel.getLong(alignWord(off))
            val unknownUnion = lastUnion !in 0..14
            modtime > HIGH_MODTIME ||
                (modtime == SENTINEL_MODTIME &&
                    lastSec == 4L && lastTag == 1L && lastUnion == 32L && unknownUnion)
        }.getOrDefault(false)

    private fun flatPayloadSize(parcel: ByteBuffer, off: Int, union: Long): Int =
        when {
            union in 1..11 -> 4
            union == 12L || union == 13L -> 8
            union == 14L -> alignWord(off + 4 + parcel.getInt(off)) - off
            else -> 0
        }

    private fun skipDriftedByteArray(parcel: ByteBuffer, off: Int): Int {
        if (parcel.getInt(off) == 0) return off + 4
        val lengthPos = off + 4
        return alignWord(lengthPos + 4 + parcel.getInt(lengthPos))
    }

    private fun u32(parcel: ByteBuffer, off: Int): Long =
        parcel.getInt(off).toLong() and 0xFFFFFFFFL

    private fun alignWord(off: Int): Int = (off + 3) and 3.inv()

    private const val FLAT_STRIDE_HEADER = 12
    private const val MAX_AUTH_COUNT = 256
    private const val SENTINEL_MODTIME = 4_294_967_297L
    private const val HIGH_MODTIME = 4_999_999_999L
}

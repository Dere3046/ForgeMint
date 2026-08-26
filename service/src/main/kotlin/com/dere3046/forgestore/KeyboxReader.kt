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

import android.hardware.security.keymint.Algorithm
import android.security.keystore.KeyProperties
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.util.io.pem.PemReader
import java.io.ByteArrayInputStream
import java.io.File
import java.io.StringReader
import java.security.KeyPair
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.util.concurrent.ConcurrentHashMap
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserFactory

object KeyboxReader {

    private const val KEYBOX_FILE = "/data/adb/forge_store/keybox.xml"

    private var keyboxCache: ConcurrentHashMap<String, CertificateBuilder.KeyboxData>? = null

    fun loadKeybox(algorithm: Int? = null): CertificateBuilder.KeyboxData? {
        if (algorithm != null) {
            val algoKey = algoToKey(algorithm) ?: return null
            val cache = keyboxCache ?: reload()
            if (cache.isEmpty()) return null
            return cache[algoKey]?.also { logKeybox(it, algoKey) }
        }
        return singleKey()?.also { logKeybox(it, "any") }
    }

    private fun logKeybox(keybox: CertificateBuilder.KeyboxData, algorithm: String) {
        val serials = keybox.certificates.joinToString(", ") { cert ->
            (cert as? X509Certificate)?.serialNumber?.toString(16) ?: "?"
        }
        Logger.i("Using $algorithm keybox; attestation cert serials (hex): $serials")
    }
    private fun algoToKey(algo: Int): String? = when (algo) {
        Algorithm.RSA -> KeyProperties.KEY_ALGORITHM_RSA
        Algorithm.EC -> KeyProperties.KEY_ALGORITHM_EC
        else -> {
            Logger.w("algoToKey: unknown algorithm $algo")
            null
        }
    }

    private fun singleKey(): CertificateBuilder.KeyboxData? {
        val cache = keyboxCache ?: reload()
        return cache.values.firstOrNull()
    }

    fun loadAnyKeybox(): CertificateBuilder.KeyboxData? {
        val cache = keyboxCache ?: reload()
        return cache[KeyProperties.KEY_ALGORITHM_EC]
            ?: cache.values.firstOrNull()
            ?.also { logKeybox(it, "any-fallback") }
    }

    private fun reload(): ConcurrentHashMap<String, CertificateBuilder.KeyboxData> {
        val file = File(KEYBOX_FILE)
        if (!file.exists()) {
            Logger.w("Keybox file not found: $KEYBOX_FILE")
            return ConcurrentHashMap()
        }
        return try {
            val xmlContent = file.readText().trimStart('\uFEFF', '\uFFFE', ' ')
            val map = parseXml(xmlContent)
            keyboxCache = map
            map
        } catch (e: Exception) {
            Logger.e("Failed to load keybox", e)
            ConcurrentHashMap()
        }
    }

    fun clearCache() { keyboxCache = null }

    private fun parseXml(xmlContent: String): ConcurrentHashMap<String, CertificateBuilder.KeyboxData> {
        val found = ConcurrentHashMap<String, CertificateBuilder.KeyboxData>()
        var malformedKey = false
        val parser = XmlPullParserFactory.newInstance().newPullParser().apply {
            setInput(StringReader(xmlContent))
        }

        var currentAlgorithm: String? = null
        var currentPrivateKeyPem: String? = null
        val currentCerts = mutableListOf<String>()
        var insideKeyPem = false
        var insideCert = false
        val minCerts = ConfigManager.keyboxMinCerts

        var event = parser.eventType
        while (event != XmlPullParser.END_DOCUMENT) {
            when (event) {
                XmlPullParser.START_TAG -> when (parser.name) {
                    "Key" -> {
                        currentAlgorithm = parser.getAttributeValue(null, "algorithm")
                        currentPrivateKeyPem = null
                        currentCerts.clear()
                    }
                    "PrivateKey" -> insideKeyPem = true
                    "Certificate" -> insideCert = true
                }
                XmlPullParser.TEXT -> {
                    if (parser.isWhitespace) { event = parser.next(); continue }
                    if (insideKeyPem) currentPrivateKeyPem = parser.text
                    if (insideCert) currentCerts.add(parser.text)
                }
                XmlPullParser.END_TAG -> when (parser.name) {
                    "PrivateKey" -> insideKeyPem = false
                    "Certificate" -> insideCert = false
                    "Key" -> {
                        val algo = currentAlgorithm
                        val pem = currentPrivateKeyPem
                        val certPems = currentCerts.toList()

                        if (algo == null || pem == null || certPems.size < minCerts) {
                            malformedKey = true
                            Logger.w("Skipping keybox entry '$algo': need key and at least $minCerts certificates, found ${certPems.size}")
                        } else {
                            runCatching {
                                val keyPair = parsePemKeyPair(pem) ?: return@runCatching
                                val certs = certPems.map { parsePemCert(it) }
                                if (certs.any { it == null }) {
                                    malformedKey = true
                                    Logger.w("Skipping keybox entry '$algo': one or more certificates failed to parse")
                                    return@runCatching
                                }
                                val certList = certs.filterNotNull()

                                val derivedAlgo = when (keyPair.private) {
                                    is RSAPrivateKey -> KeyProperties.KEY_ALGORITHM_RSA
                                    is ECPrivateKey -> KeyProperties.KEY_ALGORITHM_EC
                                    else -> return@runCatching
                                }

                                val normalizedXmlAlgorithm =
                                    when {
                                        algo.contains("RSA", ignoreCase = true) -> KeyProperties.KEY_ALGORITHM_RSA
                                        algo.contains("EC", ignoreCase = true) -> KeyProperties.KEY_ALGORITHM_EC
                                        else -> algo
                                    }
                                if (normalizedXmlAlgorithm != derivedAlgo) {
                                    Logger.w("Key algorithm mismatch in keybox.xml: tag='$algo' actual='$derivedAlgo'; using actual")
                                }
                                if (found.containsKey(derivedAlgo)) {
                                    Logger.w("Duplicate $derivedAlgo keybox entry; later entry wins")
                                }

                                found[derivedAlgo] = CertificateBuilder.KeyboxData(keyPair, certList)
                            }.onFailure {
                                malformedKey = true
                                Logger.w("Skipping keybox entry '$algo'", it)
                            }
                        }
                    }
                }
            }
            event = parser.next()
        }

        if (malformedKey && ConfigManager.isStrictKeybox) {
            Logger.w("strict_keybox=true and malformed entry detected; dropping entire keybox file")
            return ConcurrentHashMap()
        }

        Logger.d("Parsed ${found.size} keys from keybox.xml")
        return found
    }

    private fun parsePemKeyPair(pem: String): KeyPair? {
        return try {
            PEMParser(StringReader(cleanPem(pem))).use { parser ->
                val obj = parser.readObject()
                if (obj is org.bouncycastle.openssl.PEMKeyPair) {
                    JcaPEMKeyConverter().getKeyPair(obj)
                } else {
                    Logger.e("parsePemKeyPair: unexpected PEM object: ${obj?.javaClass?.name}")
                    null
                }
            }
        } catch (e: Exception) {
            Logger.e("Failed to parse PEM key pair", e)
            null
        }
    }

    private fun parsePemCert(pem: String): X509Certificate? {
        return try {
            PemReader(StringReader(cleanPem(pem))).use { reader ->
                val obj = reader.readPemObject()
                CertificateFactory.getInstance("X.509")
                    .generateCertificate(ByteArrayInputStream(obj.content)) as X509Certificate
            }
        } catch (e: Exception) {
            Logger.e("Failed to parse PEM certificate", e)
            null
        }
    }

    private fun cleanPem(pem: String): String =
        pem.trim().lines().joinToString("\n") { it.trim() }
}

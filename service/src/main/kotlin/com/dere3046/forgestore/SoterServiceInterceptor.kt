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

import android.os.IBinder
import android.os.Parcel
import android.util.Base64
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyPairGenerator

object SoterServiceInterceptor : BinderInterceptor() {
    const val DESCRIPTOR = "com.tencent.soter.soterserver.ISoterService"

    private const val TX_GENERATE_APP_SECURE_KEY = 1
    private const val TX_GET_APP_SECURE_KEY = 2
    private const val TX_HAS_ASK_ALREADY = 3
    private const val TX_GENERATE_AUTH_KEY = 4
    private const val TX_REMOVE_AUTH_KEY = 5
    private const val TX_GET_AUTH_KEY = 6
    private const val TX_REMOVE_ALL_AUTH_KEY = 7
    private const val TX_HAS_AUTH_KEY = 8
    private const val TX_INIT_SIGH = 9
    private const val TX_FINISH_SIGN = 10
    private const val TX_GET_DEVICE_ID = 11
    private const val TX_GET_VERSION = 12
    private const val TX_GET_EXTRA_PARAM = 13

    private const val SOTER_OK = 0
    private const val SIGNATURE_LEN = 256
    private const val CPU_ID = "0000000000000000"

    private val methodNames =
        mapOf(
            TX_GENERATE_APP_SECURE_KEY to "generateAppSecureKey",
            TX_GET_APP_SECURE_KEY to "getAppSecureKey",
            TX_HAS_ASK_ALREADY to "hasAskAlready",
            TX_GENERATE_AUTH_KEY to "generateAuthKey",
            TX_REMOVE_AUTH_KEY to "removeAuthKey",
            TX_GET_AUTH_KEY to "getAuthKey",
            TX_REMOVE_ALL_AUTH_KEY to "removeAllAuthKey",
            TX_HAS_AUTH_KEY to "hasAuthKey",
            TX_INIT_SIGH to "initSigh",
            TX_FINISH_SIGN to "finishSign",
            TX_GET_DEVICE_ID to "getDeviceId",
            TX_GET_VERSION to "getVersion",
            TX_GET_EXTRA_PARAM to "getExtraParam",
        )

    val interceptedCodes: IntArray = methodNames.keys.toIntArray()

    private val exportBlob: ByteArray by lazy { buildExportBlob() }
    private val deviceIdBlob = "FORGESTORE-SOTER-0001".toByteArray(Charsets.UTF_8)
    private val signatureBlob = ByteArray(SIGNATURE_LEN)

    private fun buildExportBlob(): ByteArray {
        val pubKey =
            runCatching {
                    val generator = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
                    Base64.encodeToString(generator.generateKeyPair().public.encoded, Base64.NO_WRAP)
                }
                .getOrDefault("")
        val json =
            """{"pub_key":"$pubKey","counter":0,"cpu_id":"$CPU_ID","uid":0}"""
                .toByteArray(Charsets.UTF_8)
        val lengthPrefix = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(json.size).array()
        return lengthPrefix + json + signatureBlob
    }

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        val method = methodNames[code]
        if (method == null) {
            logTransaction(txId, "code=$code", callingUid, callingPid, skipPost = true)
            return TransactionResult.ContinueAndSkipPost
        }
        logTransaction(txId, method, callingUid, callingPid)
        captureRequest(callingUid, txId, method, data)

        return when (code) {
            TX_GENERATE_APP_SECURE_KEY,
            TX_GENERATE_AUTH_KEY,
            TX_REMOVE_AUTH_KEY,
            TX_REMOVE_ALL_AUTH_KEY -> forgedReply(callingUid, txId, method) { writeInt(SOTER_OK) }
            TX_GET_VERSION -> forgedReply(callingUid, txId, method) { writeInt(1) }
            TX_HAS_ASK_ALREADY,
            TX_HAS_AUTH_KEY -> forgedReply(callingUid, txId, method) { writeInt(1) }
            TX_GET_APP_SECURE_KEY,
            TX_GET_AUTH_KEY ->
                forgedReply(callingUid, txId, method) {
                    writeInt(1)
                    writeInt(SOTER_OK)
                    writeByteArray(exportBlob)
                    writeInt(exportBlob.size)
                }
            TX_INIT_SIGH ->
                forgedReply(callingUid, txId, method) {
                    writeInt(1)
                    writeLong(1L)
                    writeInt(SOTER_OK)
                }
            TX_FINISH_SIGN ->
                forgedReply(callingUid, txId, method) {
                    writeInt(1)
                    writeInt(SOTER_OK)
                    writeByteArray(signatureBlob)
                    writeInt(signatureBlob.size)
                }
            TX_GET_DEVICE_ID ->
                forgedReply(callingUid, txId, method) {
                    writeInt(1)
                    writeInt(SOTER_OK)
                    writeByteArray(deviceIdBlob)
                    writeInt(deviceIdBlob.size)
                }
            TX_GET_EXTRA_PARAM ->
                forgedReply(callingUid, txId, method) {
                    writeInt(1)
                    writeValue("optical")
                }
            else -> TransactionResult.ContinueAndSkipPost
        }
    }

    private fun captureRequest(uid: Int, txId: Long, method: String, data: Parcel) {
        if (!Logger.isUidLogged(uid)) return
        runCatching { data.marshall() }
            .onSuccess { raw ->
                Logger.uidLogRaw(uid, txId, "$method-request", "len=${raw.size}", raw)
            }
    }

    private fun forgedReply(
        uid: Int,
        txId: Long,
        method: String,
        body: Parcel.() -> Unit,
    ): TransactionResult.OverrideReply {
        val reply = Parcel.obtain()
        reply.writeNoException()
        reply.body()
        if (Logger.isUidLogged(uid)) {
            runCatching { reply.marshall() }
                .onSuccess { raw ->
                    Logger.uidLogRaw(uid, txId, "$method-reply", "len=${raw.size}", raw)
                }
        }
        return TransactionResult.OverrideReply(reply)
    }
}

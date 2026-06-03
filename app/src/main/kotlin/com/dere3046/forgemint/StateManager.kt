package com.dere3046.forgemint

import android.os.IBinder
import android.system.keystore2.KeyMetadata
import java.security.KeyPair
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap

object StateManager {

    data class KeyEntry(
        val uid: Int,
        val alias: String,
        val nspace: Long,
        val metadata: KeyMetadata,
        val keyPair: KeyPair,
        val securityLevel: Int,
        val securityLevelBinder: IBinder,
        val certChain: List<X509Certificate>,
    )

    private val cache = ConcurrentHashMap<String, KeyEntry>()

    fun store(entry: KeyEntry) {
        cache[key(entry.uid, entry.alias)] = entry
    }

    fun lookup(uid: Int, alias: String): KeyEntry? = cache[key(uid, alias)]

    fun lookupByNspace(uid: Int, nspace: Long): KeyEntry? {
        return cache.values.find { it.uid == uid && it.nspace == nspace }
    }

    fun remove(uid: Int, alias: String) { cache.remove(key(uid, alias)) }

    fun listForUid(uid: Int): List<KeyEntry> {
        return cache.values.filter { it.uid == uid }
    }

    private fun key(uid: Int, alias: String) = "$uid:$alias"
}

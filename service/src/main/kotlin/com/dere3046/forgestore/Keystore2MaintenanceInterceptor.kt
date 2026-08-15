package com.dere3046.forgestore

import android.os.IBinder
import android.os.Parcel
import android.security.maintenance.IKeystoreMaintenance
import android.system.keystore2.Domain
import android.system.keystore2.KeyDescriptor

class Keystore2MaintenanceInterceptor(
    private val teeInterceptor: KeyMintInterceptor,
    private val strongBoxInterceptor: KeyMintInterceptor?,
) : BinderInterceptor() {

    private val stubClass = IKeystoreMaintenance.Stub::class.java

    private val CLEAR_NAMESPACE_TRANSACTION = resolveCode("TRANSACTION_clearNamespace")
    private val DELETE_ALL_KEYS_TRANSACTION = resolveCode("TRANSACTION_deleteAllKeys")
    private val MIGRATE_KEY_NAMESPACE_TRANSACTION = resolveCode("TRANSACTION_migrateKeyNamespace")

    val interceptedCodes: IntArray
        get() = listOfNotNull(
            CLEAR_NAMESPACE_TRANSACTION.takeIf { it > 0 },
            DELETE_ALL_KEYS_TRANSACTION.takeIf { it > 0 },
            MIGRATE_KEY_NAMESPACE_TRANSACTION.takeIf { it > 0 },
        ).toIntArray()

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        when (code) {
            CLEAR_NAMESPACE_TRANSACTION -> handleClearNamespace(data)
            DELETE_ALL_KEYS_TRANSACTION -> {
                teeInterceptor.clearAllGeneratedKeys("maintenance.deleteAllKeys")
                strongBoxInterceptor?.clearAllGeneratedKeys("maintenance.deleteAllKeys")
            }
            MIGRATE_KEY_NAMESPACE_TRANSACTION -> handleMigrateKeyNamespace(data, callingUid)
        }
        return TransactionResult.ContinueAndSkipPost
    }

    private fun handleClearNamespace(data: Parcel) {
        data.enforceInterface(IKeystoreMaintenance.DESCRIPTOR)
        val domain = data.readInt()
        val nspace = data.readLong()
        if (domain == Domain.APP) {
            teeInterceptor.clearNamespaceKeys(nspace.toInt())
            strongBoxInterceptor?.clearNamespaceKeys(nspace.toInt())
        }
    }

    private fun handleMigrateKeyNamespace(data: Parcel, callingUid: Int) {
        data.enforceInterface(IKeystoreMaintenance.DESCRIPTOR)
        val source = data.readTypedObject(KeyDescriptor.CREATOR) ?: return
        val destination = data.readTypedObject(KeyDescriptor.CREATOR) ?: return
        val srcId = resolveSyntheticKeyId(source, callingUid) ?: return
        val owner = interceptorOwning(srcId) ?: return

        val dstId = resolveDestinationKeyId(destination, callingUid)
        if (dstId == null) {
            KeyMintInterceptor.cleanupKeyData(owner, srcId)
        } else {
            owner.migrateGeneratedKey(srcId, dstId)
        }
    }

    private fun resolveSyntheticKeyId(descriptor: KeyDescriptor, callingUid: Int): StateManager.KeyIdentifier? =
        when {
            descriptor.alias != null -> StateManager.KeyIdentifier(callingUid, descriptor.alias)
            descriptor.domain == Domain.KEY_ID -> {
                teeInterceptor.generatedKeys.values
                    .firstOrNull { it.uid == callingUid && it.nspace == descriptor.nspace }
                    ?.let { StateManager.KeyIdentifier(it.uid, it.alias) }
                    ?: strongBoxInterceptor?.generatedKeys?.values
                        ?.firstOrNull { it.uid == callingUid && it.nspace == descriptor.nspace }
                        ?.let { StateManager.KeyIdentifier(it.uid, it.alias) }
            }
            else -> null
        }

    private fun resolveDestinationKeyId(
        descriptor: KeyDescriptor,
        callingUid: Int,
    ): StateManager.KeyIdentifier? {
        val alias = descriptor.alias ?: return null
        if (descriptor.domain != Domain.APP) return null
        val uid = if (descriptor.nspace > 0) descriptor.nspace.toInt() else callingUid
        return StateManager.KeyIdentifier(uid, alias)
    }

    private fun interceptorOwning(keyId: StateManager.KeyIdentifier): KeyMintInterceptor? {
        if (teeInterceptor.ownsSyntheticKey(keyId)) return teeInterceptor
        if (strongBoxInterceptor?.ownsSyntheticKey(keyId) == true) return strongBoxInterceptor
        return null
    }

    private fun resolveCode(name: String): Int {
        return try {
            stubClass.getDeclaredField(name)
                .apply { isAccessible = true }
                .getInt(null)
        } catch (e: Exception) {
            Logger.e("Failed to resolve $name", e)
            -1
        }
    }
}

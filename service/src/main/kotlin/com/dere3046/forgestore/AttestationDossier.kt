package com.dere3046.forgestore

import android.hardware.security.keymint.Tag
import android.system.keystore2.Authorization
import java.security.cert.Certificate
import java.security.cert.X509Certificate

object AttestationDossier {

    fun log(uid: Int, txId: Long, path: String, chain: List<Certificate>) {
        if (!Logger.isUidLogged(uid)) return
        val leaf = chain.firstOrNull() as? X509Certificate
        val extension =
            leaf?.let { AttestationPatcher.formatAttestationExtension(it) }
                ?: "<no attestation extension>"
        Logger.uidLog(uid, txId, "attest", "path=$path depth=${chain.size} $extension")
        Logger.uidLog(uid, txId, "keybox", "file=keybox.xml")
        Logger.uidLog(uid, txId, "chain", AttestationPatcher.formatCertChain(chain))
        Logger.uidLog(uid, txId, "chain-verify", AttestationPatcher.formatChainVerification(chain))
        Logger.uidLog(uid, txId, "props", AndroidDeviceUtils.describeSources(uid))
    }

    fun logAuthShape(uid: Int, txId: Long, authorizations: Array<Authorization>?) {
        if (!Logger.isUidLogged(uid)) return
        val auths = authorizations ?: return
        val shape = auths.joinToString(",") { "${tagName(it.keyParameter.tag)}/${it.securityLevel}" }
        Logger.uidLog(uid, txId, "auth-shape", "n=${auths.size} [$shape]")
    }

    private fun tagName(tag: Int): String =
        when (tag) {
            Tag.PURPOSE -> "PURPOSE"
            Tag.ALGORITHM -> "ALGORITHM"
            Tag.KEY_SIZE -> "KEY_SIZE"
            Tag.DIGEST -> "DIGEST"
            Tag.PADDING -> "PADDING"
            Tag.EC_CURVE -> "EC_CURVE"
            Tag.RSA_PUBLIC_EXPONENT -> "RSA_PUBLIC_EXPONENT"
            Tag.NO_AUTH_REQUIRED -> "NO_AUTH_REQUIRED"
            Tag.ORIGIN -> "ORIGIN"
            Tag.OS_VERSION -> "OS_VERSION"
            Tag.OS_PATCHLEVEL -> "OS_PATCHLEVEL"
            Tag.VENDOR_PATCHLEVEL -> "VENDOR_PATCHLEVEL"
            Tag.BOOT_PATCHLEVEL -> "BOOT_PATCHLEVEL"
            Tag.CREATION_DATETIME -> "CREATION_DATETIME"
            Tag.ROOT_OF_TRUST -> "ROOT_OF_TRUST"
            Tag.USER_ID -> "USER_ID"
            Tag.USAGE_COUNT_LIMIT -> "USAGE_COUNT_LIMIT"
            Tag.UNLOCKED_DEVICE_REQUIRED -> "UNLOCKED_DEVICE_REQUIRED"
            Tag.ACTIVE_DATETIME -> "ACTIVE_DATETIME"
            else -> "tag${tag and 0x0FFFFFFF}"
        }
}

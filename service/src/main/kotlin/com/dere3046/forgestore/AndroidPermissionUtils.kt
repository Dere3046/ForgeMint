package com.dere3046.forgestore

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager

object AndroidPermissionUtils {

    @SuppressLint("PrivateApi", "DiscouragedPrivateApi")
    private fun getGlobalContext(): Context? {
        return try {
            val activityThreadClass = Class.forName("android.app.ActivityThread")
            val currentActivityThreadMethod =
                activityThreadClass.getDeclaredMethod("currentActivityThread")
            currentActivityThreadMethod.isAccessible = true
            val activityThread = currentActivityThreadMethod.invoke(null)

            if (activityThread == null) {
                Logger.w("Reflection: ActivityThread.currentActivityThread() returned null")
                return null
            }

            val getApplicationMethod = activityThreadClass.getDeclaredMethod("getApplication")
            getApplicationMethod.isAccessible = true
            val application = getApplicationMethod.invoke(activityThread) as? Context

            if (application != null) return application

            val getSystemContextMethod = activityThreadClass.getDeclaredMethod("getSystemContext")
            getSystemContextMethod.isAccessible = true
            getSystemContextMethod.invoke(activityThread) as? Context
        } catch (e: Exception) {
            Logger.e("Reflection failed to get global context for permission check", e)
            null
        }
    }

    fun hasPermission(uid: Int, permission: String): Boolean {
        val context =
            getGlobalContext()
                ?: run {
                    Logger.w("AndroidPermissionUtils: Context is null, failing permission check safely.")
                    return false
                }

        val result = context.checkPermission(permission, -1, uid)
        return result == PackageManager.PERMISSION_GRANTED
    }

    fun hasDeviceAttestationPermission(uid: Int): Boolean {
        return hasPermission(uid, "android.permission.READ_PRIVILEGED_PHONE_STATE")
    }

    fun hasUniqueIdAttestationPermission(uid: Int): Boolean {
        return hasPermission(uid, "android.permission.REQUEST_UNIQUE_ID_ATTESTATION")
    }

    fun hasManageUsersPermission(uid: Int): Boolean {
        return hasPermission(uid, "android.permission.MANAGE_USERS")
    }

    fun hasDumpPermission(uid: Int): Boolean {
        return hasPermission(uid, "android.permission.DUMP")
    }
}

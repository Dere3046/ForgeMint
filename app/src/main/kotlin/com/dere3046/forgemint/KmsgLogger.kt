package com.dere3046.forgemint

import android.util.Log

object KmsgLogger {

    private var available = false

    fun init() {
        try {
            System.loadLibrary("forgemint_kmsg")
            available = true
        } catch (_: UnsatisfiedLinkError) {
            Log.w("ForgeMint", "kmsg native lib not available, falling back to logcat")
        }
    }

    fun write(priority: Int, tag: String, message: String): Boolean {
        return if (available) nativeLog(priority, tag, message) else false
    }

    @JvmStatic
    private external fun nativeLog(priority: Int, tag: String, message: String): Boolean
}

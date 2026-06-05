package com.dere3046.forgemint

import android.util.Log

object Logger {
    private const val TAG = "ForgeMint"

    fun d(msg: String) {
        if (!KmsgLogger.write(7, TAG, msg)) Log.d(TAG, msg)
    }

    fun i(msg: String) {
        if (!KmsgLogger.write(5, TAG, msg)) Log.i(TAG, msg)
    }

    fun w(msg: String) {
        if (!KmsgLogger.write(4, TAG, msg)) Log.w(TAG, msg)
    }

    fun w(msg: String, t: Throwable) {
        Log.w(TAG, msg, t)
    }

    fun e(msg: String, t: Throwable? = null) {
        if (t != null) {
            Log.e(TAG, msg, t)
        } else {
            if (!KmsgLogger.write(3, TAG, msg)) Log.e(TAG, msg)
        }
    }
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

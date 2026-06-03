package com.dere3046.forgemint

import android.util.Log

object Logger {
    private const val TAG = "ForgeMint"

    fun d(msg: String) = Log.d(TAG, msg)
    fun i(msg: String) = Log.i(TAG, msg)
    fun w(msg: String) = Log.w(TAG, msg)
    fun w(msg: String, t: Throwable) = Log.w(TAG, msg, t)
    fun e(msg: String, t: Throwable? = null) = if (t != null) Log.e(TAG, msg, t) else Log.e(TAG, msg)
}

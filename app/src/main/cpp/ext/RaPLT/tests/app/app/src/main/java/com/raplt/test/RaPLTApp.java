package com.raplt.test;

import android.app.Application;
import android.content.Context;

public class RaPLTApp extends Application {
    static { System.loadLibrary("jni"); }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        nativeInit();
    }

    private native void nativeInit();
}

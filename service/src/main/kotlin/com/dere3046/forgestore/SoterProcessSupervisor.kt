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

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicBoolean

object SoterProcessSupervisor {
    private const val SOTER_PACKAGE = "com.tencent.soter.soterserver"
    private const val INJECTION_COMMAND =
        "exec ./lib/libinject.so `pidof $SOTER_PACKAGE` ./lib/libforgestore.so"
    private const val REBIND_DELAY_MS = 1000L
    private const val REBIND_MAX_MS = 30_000L

    private val started = AtomicBoolean(false)
    private var rebindDelay = REBIND_DELAY_MS
    private lateinit var context: Context
    private lateinit var handler: Handler
    private val executor = Executor { command -> handler.post(command) }

    fun start(context: Context) {
        if (!started.compareAndSet(false, true)) return
        this.context = context
        handler = Handler(HandlerThread("soter-supervisor").apply { start() }.looper)
        handler.post { bind() }
    }

    private val connection =
        object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                Logger.d("SOTER service connected; mounting forge")
                service?.let(::mount)
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                Logger.d("SOTER service disconnected; rebinding")
                scheduleRetry()
            }

            override fun onBindingDied(name: ComponentName?) {
                Logger.d("SOTER binding died; rebinding")
                scheduleRetry()
            }

            override fun onNullBinding(name: ComponentName?) {
                Logger.d("SOTER onBind returned null; rebinding")
                scheduleRetry()
            }
        }

    private fun bind() {
        val intent = Intent(SoterServiceInterceptor.DESCRIPTOR).setPackage(SOTER_PACKAGE)
        val bound =
            runCatching {
                    context.bindService(intent, Context.BIND_AUTO_CREATE, executor, connection)
                }
                .getOrDefault(false)
        if (!bound) {
            Logger.w("SOTER bind failed; retrying")
            scheduleRetry()
        }
    }

    private fun scheduleRetry() {
        val delay = rebindDelay
        rebindDelay = (rebindDelay * 2).coerceAtMost(REBIND_MAX_MS)
        handler.postDelayed({ rebind() }, delay)
    }

    private fun rebind() {
        runCatching { context.unbindService(connection) }
        bind()
    }

    private fun mount(soterBinder: IBinder) {
        var backdoor = BinderInterceptor.getBackdoor(soterBinder)
        if (backdoor == null) {
            Logger.d("SOTER backdoor absent; injecting libforgestore.so")
            if (!injectLibrary()) {
                Logger.w("SOTER injection failed; scheduling rebind")
                scheduleRetry()
                return
            }
            backdoor = BinderInterceptor.getBackdoor(soterBinder)
        }
        if (backdoor == null) {
            Logger.w("SOTER backdoor handshake failed; scheduling rebind")
            scheduleRetry()
            return
        }
        val registered =
            BinderInterceptor.register(
                backdoor,
                soterBinder,
                SoterServiceInterceptor,
                SoterServiceInterceptor.interceptedCodes,
            )
        if (!registered) {
            Logger.w("SOTER register failed; scheduling rebind")
            scheduleRetry()
            return
        }
        rebindDelay = REBIND_DELAY_MS
        Logger.d("SOTER forge mounted; handshake ok")
    }

    private fun injectLibrary(): Boolean =
        runCatching {
                Runtime.getRuntime().exec(arrayOf("/system/bin/sh", "-c", INJECTION_COMMAND)).waitFor() == 0
            }
            .getOrElse {
                Logger.w("SOTER inject exec failed: $it")
                false
            }
}

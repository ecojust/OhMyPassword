package com.ecojust.ohmypassword.discovery

import android.app.Activity
import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.WindowManager
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import app.tauri.plugin.Invoke
import org.json.JSONArray
import java.net.Inet4Address
import java.util.UUID
import java.util.ArrayDeque

@InvokeArg
class StartArgs { var deviceId:String = ""; var name:String = ""; var port:Int = 17842 }

@TauriPlugin
class DiscoveryPlugin(private val activity:Activity):Plugin(activity) {
    private val nsd = activity.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val handler = Handler(Looper.getMainLooper())
    // All state, including cache expiry, belongs to the Activity UI thread.
    private val found = mutableMapOf<String,JSObject>()
    private val seenAt = mutableMapOf<String,Long>()
    private val pending = ArrayDeque<NsdServiceInfo>()
    private val queued = mutableSetOf<String>()
    // Old Android NSD cannot cancel a resolver. Keep it across scan/stop/start.
    private var resolvingGeneration:Int? = null
    private var discovery:NsdManager.DiscoveryListener? = null
    private var registration:NsdManager.RegistrationListener? = null
    private var scanStop:Runnable? = null
    private var ownId = ""
    private var generation = 0
    private var active = false
    private var scanning = false
    private var foreground = true
    private val type = "_ohmypassword._tcp."
    private val cacheTtlMs = 660_000L

    override fun load(webView:WebView) {
        activity.runOnUiThread { activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }
    override fun onPause(activity:AppCompatActivity) { foreground=false;stopInternal() }
    override fun onResume(activity:AppCompatActivity) { foreground=true }
    override fun onDestroy(activity:AppCompatActivity) { stopInternal() }

    // Publish continuously while unlocked; discovery browsing is a separate,
    // bounded operation requested by the shared service's 300-second scheduler.
    @Command
    fun start(invoke:Invoke) {
        val args = invoke.parseArgs(StartArgs::class.java)
        if(runCatching{UUID.fromString(args.deviceId)}.isFailure || args.port !in 1..65535) {
            invoke.reject("Invalid discovery identity");return
        }
        activity.runOnUiThread {
            if(!foreground){invoke.reject("应用已进入后台");return@runOnUiThread}
            stopInternal();ownId=args.deviceId;active=true
            val listener=object:NsdManager.RegistrationListener {
                override fun onServiceRegistered(info:NsdServiceInfo) {}
                override fun onRegistrationFailed(info:NsdServiceInfo,code:Int) {}
                override fun onServiceUnregistered(info:NsdServiceInfo) {}
                override fun onUnregistrationFailed(info:NsdServiceInfo,code:Int) {}
            }
            registration=listener
            val service=NsdServiceInfo().apply {
                serviceName="omp-${args.deviceId}";serviceType=type;port=args.port
                setAttribute("protocol","3");setAttribute("device_id",args.deviceId)
            }
            try { nsd.registerService(service,NsdManager.PROTOCOL_DNS_SD,listener);invoke.resolve(JSObject()) }
            catch (_:Exception) { stopInternal();invoke.reject("局域网服务发布失败，请检查网络权限") }
        }
    }
    @Command
    fun scan(invoke:Invoke) {
        activity.runOnUiThread {
            if(!active || !foreground){invoke.reject("请在前台解锁密码本后检测设备");return@runOnUiThread}
            stopBrowsing();pruneCache();scanning=true
            val current=generation
            val listener=object:NsdManager.DiscoveryListener {
                override fun onDiscoveryStarted(serviceType:String) {}
                override fun onDiscoveryStopped(serviceType:String) {}
                override fun onStartDiscoveryFailed(serviceType:String,errorCode:Int) {
                    activity.runOnUiThread { if(generation==current)stopBrowsing() }
                }
                override fun onStopDiscoveryFailed(serviceType:String,errorCode:Int) {}
                override fun onServiceLost(info:NsdServiceInfo) {
                    activity.runOnUiThread {
                        if(current!=generation)return@runOnUiThread
                        found.remove(info.serviceName);seenAt.remove(info.serviceName)
                        queued.remove(info.serviceName);pending.removeAll{it.serviceName==info.serviceName}
                    }
                }
                override fun onServiceFound(info:NsdServiceInfo) {
                    activity.runOnUiThread {
                        if(!active || !scanning || current!=generation || (found.size+queued.size>=64 && !found.containsKey(info.serviceName)) || info.serviceName=="omp-$ownId")return@runOnUiThread
                        if(!queued.add(info.serviceName))return@runOnUiThread
                        pending.addLast(info);resolveNext()
                    }
                }
            }
            discovery=listener
            try {
                nsd.discoverServices(type,NsdManager.PROTOCOL_DNS_SD,listener)
                val finish=Runnable { if(generation==current)stopBrowsing() }
                scanStop=finish;handler.postDelayed(finish,20_000L)
                invoke.resolve(JSObject())
            } catch (_:Exception) { stopBrowsing();invoke.reject("局域网检测失败，请检查网络权限") }
        }
    }
    @Suppress("DEPRECATION")
    private fun resolveNext() {
        if(!active || !scanning || resolvingGeneration!=null || pending.isEmpty())return
        val info=pending.removeFirst();val current=generation;resolvingGeneration=current
        try {
            nsd.resolveService(info,object:NsdManager.ResolveListener {
                override fun onResolveFailed(service:NsdServiceInfo,errorCode:Int) {
                    activity.runOnUiThread{resolved(current,info.serviceName,null)}
                }
                override fun onServiceResolved(service:NsdServiceInfo) {
                    activity.runOnUiThread{resolved(current,info.serviceName,service)}
                }
            })
        } catch (_:Exception) { resolved(current,info.serviceName,null) }
    }
    private fun resolved(current:Int,name:String,info:NsdServiceInfo?) {
        if(resolvingGeneration==current)resolvingGeneration=null
        if(active && scanning && current==generation) {
            if(info!=null && queued.contains(name))remember(info)
            queued.remove(name)
        }
        resolveNext()
    }
    @Suppress("DEPRECATION")
    private fun remember(info:NsdServiceInfo) {
        val id=info.attributes["device_id"]?.toString(Charsets.UTF_8)?:return
        val protocol=info.attributes["protocol"]?.toString(Charsets.UTF_8)?:return
        if(protocol!="3" || id==ownId || runCatching{UUID.fromString(id)}.isFailure)return
        val host=info.host
        if(host !is Inet4Address || !host.isSiteLocalAddress || info.port !in 1..65535)return
        found[info.serviceName]=JSObject().apply {
            put("id",id);put("name","OhMyPassword");put("endpoint","${host.hostAddress}:${info.port}")
            put("last_seen",System.currentTimeMillis().coerceAtLeast(0L))
        }
        seenAt[info.serviceName]=SystemClock.elapsedRealtime()
    }
    private fun pruneCache() {
        val now=SystemClock.elapsedRealtime()
        val expired=seenAt.filterValues{now-it>=cacheTtlMs}.keys.toList()
        for(name in expired){seenAt.remove(name);found.remove(name)}
    }
    @Command fun peers(invoke:Invoke) {
        activity.runOnUiThread {
            pruneCache();val list=JSONArray();for(item in found.values.take(64))list.put(item)
            invoke.resolve(JSObject().apply{put("peers",list)})
        }
    }
    @Command fun stop(invoke:Invoke) {activity.runOnUiThread{stopInternal();invoke.resolve(JSObject())}}
    private fun stopBrowsing() {
        scanning=false;generation+=1;scanStop?.let{handler.removeCallbacks(it)};scanStop=null
        discovery?.let{runCatching{nsd.stopServiceDiscovery(it)}};discovery=null
        pending.clear();queued.clear()
    }
    private fun stopInternal() {
        active=false;stopBrowsing()
        registration?.let{runCatching{nsd.unregisterService(it)}};registration=null
        found.clear();seenAt.clear()
    }
}

package com.ecojust.ohmypassword.discovery

import android.app.Activity
import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
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
import java.util.concurrent.ConcurrentHashMap

@InvokeArg
class StartArgs { var deviceId:String = ""; var name:String = ""; var port:Int = 17842 }

@TauriPlugin
class DiscoveryPlugin(private val activity:Activity):Plugin(activity) {
    private val nsd = activity.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val found = ConcurrentHashMap<String,JSObject>()
    private val pending = ArrayDeque<NsdServiceInfo>()
    private val queued = mutableSetOf<String>()
    // Keep the in-flight resolver across stop/start: old NSD cannot cancel it.
    private var resolvingGeneration:Int? = null
    private var discovery:NsdManager.DiscoveryListener? = null
    private var registration:NsdManager.RegistrationListener? = null
    private var ownId = ""
    private var generation = 0
    private var active = false
    private var foreground = true
    private val type = "_ohmypassword._tcp."

    override fun load(webView:WebView) {
        activity.runOnUiThread { activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }
    override fun onPause(activity:AppCompatActivity) { foreground=false;stopInternal() }
    override fun onResume(activity:AppCompatActivity) { foreground=true }
    override fun onDestroy(activity:AppCompatActivity) { stopInternal() }

    @Command
    fun start(invoke:Invoke) {
        val args = invoke.parseArgs(StartArgs::class.java)
        if(runCatching{ UUID.fromString(args.deviceId) }.isFailure || args.port !in 1..65535) { invoke.reject("Invalid discovery identity");return }
        activity.runOnUiThread {
            if(!foreground){invoke.reject("应用已进入后台");return@runOnUiThread}
            stopInternal(); ownId=args.deviceId; active=true; generation+=1
            val current=generation
            val registrationListener=object:NsdManager.RegistrationListener {
                override fun onServiceRegistered(info:NsdServiceInfo) {}
                override fun onRegistrationFailed(info:NsdServiceInfo,code:Int) {}
                override fun onServiceUnregistered(info:NsdServiceInfo) {}
                override fun onUnregistrationFailed(info:NsdServiceInfo,code:Int) {}
            }
            registration=registrationListener
            val service=NsdServiceInfo().apply {
                serviceName="omp-${args.deviceId}"; serviceType=type; port=args.port
                setAttribute("protocol","1");setAttribute("device_id",args.deviceId)
            }
            val listener=object:NsdManager.DiscoveryListener {
                override fun onDiscoveryStarted(serviceType:String) {}
                override fun onDiscoveryStopped(serviceType:String) {}
                override fun onStartDiscoveryFailed(serviceType:String,errorCode:Int) {
                    activity.runOnUiThread { if(generation==current) active=false }
                }
                override fun onStopDiscoveryFailed(serviceType:String,errorCode:Int) {}
                override fun onServiceLost(serviceInfo:NsdServiceInfo) {
                    activity.runOnUiThread {
                        if(current!=generation)return@runOnUiThread
                        found.remove(serviceInfo.serviceName)
                        queued.remove(serviceInfo.serviceName)
                        pending.removeAll { it.serviceName==serviceInfo.serviceName }
                    }
                }
                override fun onServiceFound(serviceInfo:NsdServiceInfo) {
                    activity.runOnUiThread {
                        if(!active || current!=generation || found.size+queued.size>=64 || serviceInfo.serviceName=="omp-$ownId")return@runOnUiThread
                        if(!queued.add(serviceInfo.serviceName))return@runOnUiThread
                        pending.addLast(serviceInfo)
                        resolveNext()
                    }
                }
            }
            discovery=listener
            try {
                nsd.registerService(service,NsdManager.PROTOCOL_DNS_SD,registrationListener)
                nsd.discoverServices(type,NsdManager.PROTOCOL_DNS_SD,listener)
                invoke.resolve(JSObject())
            } catch (_:Exception) { stopInternal();invoke.reject("局域网发现不可用，请检查网络权限") }
        }
    }
    // All resolver state is confined to the Activity UI thread. Older NSD
    // implementations allow one resolveService request at a time.
    @Suppress("DEPRECATION")
    private fun resolveNext() {
        if(!active || resolvingGeneration!=null || pending.isEmpty())return
        val info=pending.removeFirst()
        val current=generation
        resolvingGeneration=current
        try {
            nsd.resolveService(info,object:NsdManager.ResolveListener {
                override fun onResolveFailed(service:NsdServiceInfo,errorCode:Int) {
                    activity.runOnUiThread { resolved(current,info.serviceName,null) }
                }
                override fun onServiceResolved(service:NsdServiceInfo) {
                    activity.runOnUiThread { resolved(current,info.serviceName,service) }
                }
            })
        } catch (_:Exception) { resolved(current,info.serviceName,null) }
    }
    private fun resolved(current:Int,serviceName:String,info:NsdServiceInfo?) {
        if(resolvingGeneration==current)resolvingGeneration=null
        if(active && current==generation) {
            if(info!=null && queued.contains(serviceName))remember(info)
            queued.remove(serviceName)
        }
        resolveNext()
    }
    @Suppress("DEPRECATION")
    private fun remember(info:NsdServiceInfo) {
        val id=info.attributes["device_id"]?.toString(Charsets.UTF_8)?:return
        val protocol=info.attributes["protocol"]?.toString(Charsets.UTF_8)?:return
        if(protocol!="1" || id==ownId || runCatching{UUID.fromString(id)}.isFailure)return
        val host=info.host
        if(host !is Inet4Address || !host.isSiteLocalAddress || info.port !in 1..65535)return
        found[info.serviceName]=JSObject().apply {
            put("id",id);put("name",info.attributes["name"]?.toString(Charsets.UTF_8)?.take(64)?:"OhMyPassword")
            put("endpoint","${host.hostAddress}:${info.port}")
        }
    }
    @Command fun peers(invoke:Invoke) {
        val list=JSONArray();for(item in found.values.take(64))list.put(item)
        invoke.resolve(JSObject().apply{put("peers",list)})
    }
    @Command fun stop(invoke:Invoke) {activity.runOnUiThread{stopInternal();invoke.resolve(JSObject())}}
    private fun stopInternal() {
        active=false;generation+=1
        discovery?.let{runCatching{nsd.stopServiceDiscovery(it)}};discovery=null
        registration?.let{runCatching{nsd.unregisterService(it)}};registration=null
        pending.clear();queued.clear();found.clear()
    }
}

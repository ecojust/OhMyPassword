import Foundation
import Tauri
import UIKit
import WebKit
import Darwin

private struct StartArgs:Decodable {let deviceId:String;let name:String;let port:UInt16}
private struct FoundPeer:Encodable {let id:String;let name:String;let endpoint:String;let last_seen:UInt64}
private struct PeerResponse:Encodable {let peers:[FoundPeer]}

class DiscoveryPlugin:Plugin,NetServiceBrowserDelegate,NetServiceDelegate {
    private var browser:NetServiceBrowser?
    private var published:NetService?
    private var resolving:[String:NetService]=[:]
    private var found:[String:FoundPeer]=[:]
    private var seenAt:[String:TimeInterval]=[:]
    private var scanStop:DispatchWorkItem?
    private var ownId=""
    private var active=false
    private var cover:UIView?
    private var observers:[NSObjectProtocol]=[]
    private weak var webview:WKWebView?
    private let type="_ohmypassword._tcp."
    private let cacheTtl:TimeInterval=660

    override func load(webview:WKWebView) {
        self.webview=webview
        observers.append(NotificationCenter.default.addObserver(forName:UIApplication.willResignActiveNotification,object:nil,queue:.main){[weak self] _ in
            self?.stopInternal()
            guard let self=self,let window=self.webview?.window else{return}
            let overlay=UIView(frame:window.bounds);overlay.backgroundColor=UIColor(red:0.96,green:0.97,blue:0.95,alpha:1)
            overlay.autoresizingMask=[.flexibleWidth,.flexibleHeight]
            let label=UILabel(frame:overlay.bounds);label.text="OhMyPassword · 已锁定";label.textAlignment = .center;label.textColor = .darkGray;label.autoresizingMask=[.flexibleWidth,.flexibleHeight]
            overlay.addSubview(label);window.addSubview(overlay);self.cover=overlay
        })
        observers.append(NotificationCenter.default.addObserver(forName:UIApplication.didBecomeActiveNotification,object:nil,queue:.main){[weak self] _ in
            self?.cover?.removeFromSuperview();self?.cover=nil
        })
    }
    deinit {for observer in observers{NotificationCenter.default.removeObserver(observer)}}
    // Publishing keeps this device visible between bounded scan windows.
    @objc public func start(_ invoke:Invoke) throws {
        let args=try invoke.parseArgs(StartArgs.self)
        guard UUID(uuidString:args.deviceId) != nil,args.port>0 else{invoke.reject("Invalid discovery identity");return}
        DispatchQueue.main.async {[weak self] in
            guard let self=self else{return}
            guard UIApplication.shared.applicationState == .active else{invoke.reject("应用已进入后台");return}
            self.stopInternal();self.ownId=args.deviceId;self.active=true
            let service=NetService(domain:"local.",type:self.type,name:"omp-\(args.deviceId)",port:Int32(args.port))
            service.delegate=self
            service.setTXTRecord(NetService.data(fromTXTRecord:["protocol":Data("3".utf8),"device_id":Data(args.deviceId.utf8)]))
            self.published=service;service.publish();invoke.resolve()
        }
    }
    @objc public func scan(_ invoke:Invoke) {
        DispatchQueue.main.async {[weak self] in
            guard let self=self else{return}
            guard self.active,UIApplication.shared.applicationState == .active else{invoke.reject("请在前台解锁密码本后检测设备");return}
            self.stopBrowsing();self.pruneCache()
            let browser=NetServiceBrowser();browser.delegate=self;self.browser=browser
            browser.searchForServices(ofType:self.type,inDomain:"local.")
            let finish=DispatchWorkItem{[weak self,weak browser] in
                guard let self=self,let browser=browser,self.browser===browser else{return}
                self.stopBrowsing()
            }
            self.scanStop=finish;DispatchQueue.main.asyncAfter(deadline:.now()+20,execute:finish)
            invoke.resolve()
        }
    }
    @objc public func peers(_ invoke:Invoke) {
        DispatchQueue.main.async {[weak self] in
            self?.pruneCache();let values=self.map{Array($0.found.values)} ?? []
            invoke.resolve(PeerResponse(peers:values))
        }
    }
    @objc public func stop(_ invoke:Invoke) {DispatchQueue.main.async{[weak self] in self?.stopInternal();invoke.resolve()}}
    private func stopBrowsing() {
        scanStop?.cancel();scanStop=nil
        browser?.delegate=nil;browser?.stop();browser=nil
        for service in resolving.values{service.delegate=nil;service.stop()};resolving.removeAll()
    }
    private func stopInternal() {
        active=false;stopBrowsing();published?.stop();published=nil;found.removeAll();seenAt.removeAll()
    }
    private func pruneCache() {
        let now=ProcessInfo.processInfo.systemUptime
        for name in Array(seenAt.keys) {
            if now-(seenAt[name] ?? 0)>=cacheTtl {seenAt.removeValue(forKey:name);found.removeValue(forKey:name)}
        }
    }
    func netServiceBrowser(_ browser:NetServiceBrowser,didFind service:NetService,moreComing:Bool) {
        guard active,self.browser===browser,resolving.count<64,service.name != "omp-\(ownId)" else{return}
        guard found.count<64 || found[service.name] != nil else{return}
        service.delegate=self;resolving[service.name]=service;service.resolve(withTimeout:5)
    }
    func netServiceBrowser(_ browser:NetServiceBrowser,didRemove service:NetService,moreComing:Bool) {
        guard self.browser===browser else{return}
        resolving.removeValue(forKey:service.name)?.stop();found.removeValue(forKey:service.name);seenAt.removeValue(forKey:service.name)
    }
    func netServiceDidResolveAddress(_ service:NetService) {
        guard active,browser != nil,resolving[service.name]===service,let txt=service.txtRecordData() else{return}
        let data=NetService.dictionary(fromTXTRecord:txt)
        guard let protocolData=data["protocol"],String(data:protocolData,encoding:.utf8)=="3",let idData=data["device_id"],let id=String(data:idData,encoding:.utf8),UUID(uuidString:id) != nil,id != ownId,service.port>0,service.port<=65535 else{return}
        for address in service.addresses ?? [] {
            var host=[CChar](repeating:0,count:Int(NI_MAXHOST))
            let ok:Bool=address.withUnsafeBytes{buffer in
                guard buffer.count>=MemoryLayout<sockaddr_in>.size,let raw=buffer.baseAddress else{return false}
                let socket=raw.assumingMemoryBound(to:sockaddr.self)
                guard socket.pointee.sa_family==sa_family_t(AF_INET) else{return false}
                return getnameinfo(socket,socklen_t(address.count),&host,socklen_t(NI_MAXHOST),nil,0,NI_NUMERICHOST)==0
            }
            if ok {
                found[service.name]=FoundPeer(id:id,name:"OhMyPassword",endpoint:"\(String(cString:host)):\(service.port)",last_seen:UInt64(max(0,Date().timeIntervalSince1970*1000)))
                seenAt[service.name]=ProcessInfo.processInfo.systemUptime;break
            }
        }
    }
    func netService(_ sender:NetService,didNotResolve errorDict:[String:NSNumber]) {
        if resolving[sender.name]===sender{resolving.removeValue(forKey:sender.name)}
    }
}
@_cdecl("init_plugin_discovery")
public func initPlugin() -> Plugin {DiscoveryPlugin()}

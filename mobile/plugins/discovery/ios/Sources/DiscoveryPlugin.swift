import Foundation
import Tauri
import UIKit
import WebKit
import Darwin

private struct StartArgs: Decodable { let deviceId:String; let name:String; let port:UInt16 }
private struct FoundPeer: Encodable { let id:String; let name:String; let endpoint:String }
private struct PeerResponse: Encodable { let peers:[FoundPeer] }

class DiscoveryPlugin: Plugin, NetServiceBrowserDelegate, NetServiceDelegate {
    private var browser:NetServiceBrowser?
    private var published:NetService?
    private var resolving:[String:NetService]=[:]
    private var found:[String:FoundPeer]=[:]
    private var ownId=""
    private var active=false
    private var cover:UIView?
    private var observers:[NSObjectProtocol]=[]
    private weak var webview:WKWebView?
    private let type="_ohmypassword._tcp."

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
    deinit { for observer in observers{NotificationCenter.default.removeObserver(observer)} }
    @objc public func start(_ invoke:Invoke) throws {
        let args=try invoke.parseArgs(StartArgs.self)
        guard UUID(uuidString:args.deviceId) != nil,args.port>0 else{invoke.reject("Invalid discovery identity");return}
        DispatchQueue.main.async {[weak self] in
            guard let self=self else{return}
            guard UIApplication.shared.applicationState == .active else{invoke.reject("应用已进入后台");return}
            self.stopInternal();self.ownId=args.deviceId;self.active=true
            let service=NetService(domain:"local.",type:self.type,name:"omp-\(args.deviceId)",port:Int32(args.port))
            service.delegate=self
            service.setTXTRecord(NetService.data(fromTXTRecord:["protocol":Data("1".utf8),"device_id":Data(args.deviceId.utf8)]))
            self.published=service;service.publish()
            let browser=NetServiceBrowser();browser.delegate=self;self.browser=browser
            browser.searchForServices(ofType:self.type,inDomain:"local.")
            invoke.resolve()
        }
    }
    @objc public func peers(_ invoke:Invoke) {
        DispatchQueue.main.async {[weak self] in
            let values=self.map{Array($0.found.values)} ?? []
            invoke.resolve(PeerResponse(peers:values))
        }
    }
    @objc public func stop(_ invoke:Invoke) {DispatchQueue.main.async{[weak self] in self?.stopInternal();invoke.resolve()}}
    private func stopInternal(){
        active=false;browser?.stop();browser=nil;published?.stop();published=nil
        for service in resolving.values{service.stop()};resolving.removeAll();found.removeAll()
    }
    func netServiceBrowser(_ browser:NetServiceBrowser,didFind service:NetService,moreComing:Bool){
        guard active,resolving.count<64,service.name != "omp-\(ownId)" else{return}
        service.delegate=self;resolving[service.name]=service;service.resolve(withTimeout:5)
    }
    func netServiceBrowser(_ browser:NetServiceBrowser,didRemove service:NetService,moreComing:Bool){
        resolving.removeValue(forKey:service.name)?.stop();found.removeValue(forKey:service.name)
    }
    func netServiceDidResolveAddress(_ service:NetService){
        guard active,let txt=service.txtRecordData() else{return}
        let data=NetService.dictionary(fromTXTRecord:txt)
        guard let protocolData=data["protocol"],String(data:protocolData,encoding:.utf8)=="1",let idData=data["device_id"],let id=String(data:idData,encoding:.utf8),UUID(uuidString:id) != nil,id != ownId,service.port>0,service.port<=65535 else{return}
        let name=data["name"].flatMap{String(data:$0,encoding:.utf8)} ?? "OhMyPassword"
        for address in service.addresses ?? [] {
            var host=[CChar](repeating:0,count:Int(NI_MAXHOST))
            let ok:Bool=address.withUnsafeBytes{buffer in
                guard buffer.count>=MemoryLayout<sockaddr_in>.size,let raw=buffer.baseAddress else{return false}
                let socket=raw.assumingMemoryBound(to:sockaddr.self)
                guard socket.pointee.sa_family==sa_family_t(AF_INET) else{return false}
                return getnameinfo(socket,socklen_t(address.count),&host,socklen_t(NI_MAXHOST),nil,0,NI_NUMERICHOST)==0
            }
            if ok {found[service.name]=FoundPeer(id:id,name:String(name.prefix(64)),endpoint:"\(String(cString:host)):\(service.port)");break}
        }
    }
    func netService(_ sender:NetService,didNotResolve errorDict:[String:NSNumber]){resolving.removeValue(forKey:sender.name)}
}
@_cdecl("init_plugin_discovery")
public func initPlugin() -> Plugin { DiscoveryPlugin() }

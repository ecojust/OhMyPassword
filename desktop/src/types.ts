export interface Version { counter:number; device_id:string; modified_at?:number }
export interface VaultStatus { initialized:boolean; locked:boolean; device_id:string; device_name:string; entry_count:number; peer_count:number }
export interface ServiceStatus { local_endpoint:string; lan_port:number; running:boolean; last_sync:number|null; last_error:string|null; discovered:Array<{id:string;name:string;endpoint:string}> }
export interface AppStatus { vault:VaultStatus; service:ServiceStatus|null; service_error:string|null; local_addresses:string[]; mobile:boolean }
export interface EntrySummary { id:string; hostname:string; title:string; username:string; version:Version; deleted:boolean; conflict_count:number }
export interface Entry { id:string; hostname:string; title:string; username:string; password:string; notes:string; version:Version; deleted:boolean }
export interface EntryInput { id:string|null; hostname:string; title:string; username:string; password:string; notes:string }
export interface Peer { device_id:string; name:string; endpoint:string }
export interface Client { id:string; name:string; origin:string }
export interface Grant { client:Client; token:string }
export interface Invitation { code:string; expires_at:number; endpoint:string }

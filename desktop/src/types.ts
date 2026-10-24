export interface Version { counter:number; device_id:string; modified_at?:number }
export interface VaultStatus { initialized:boolean; locked:boolean; device_id:string; device_name:string; entry_count:number; peer_count:number }
export interface DiscoveredPeer { id:string; name:string; endpoint:string; last_seen:number }
export type MergeState = 'waiting'|'awaiting_confirmation'|'merging'|'completed'|'rejected'|'failed'|'expired';
export interface MergeSession { id:string; peer_id:string; peer_name:string; endpoint:string; direction:'incoming'|'outgoing'; state:MergeState; verification_code:string|null; created_at:number; expires_at:number; completed_at:number|null; error:string|null; received_count?:number|null; changed_count?:number|null; source_count?:number|null }
export interface ServiceStatus { local_endpoint:string; lan_port:number; running:boolean; last_error:string|null; discovery_generation:number; last_discovery_at:number|null; next_discovery_at:number|null; discovering:boolean; discovered:DiscoveredPeer[]; merges:MergeSession[] }
export interface AppStatus { vault:VaultStatus; service:ServiceStatus|null; service_error:string|null; local_addresses:string[]; mobile:boolean }
export interface EntrySummary { id:string; hostname:string; title:string; username:string; version:Version; deleted:boolean; conflict_count:number }
export interface Entry { id:string; hostname:string; title:string; username:string; password:string; notes:string; version:Version; deleted:boolean }
export interface EntryInput { id:string|null; hostname:string; title:string; username:string; password:string; notes:string }

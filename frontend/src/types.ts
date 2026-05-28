export interface DashboardStats {
  threats_detected: number;
  threats_change_pct: number;
  participating_countries: number;
  new_countries: number;
  ai_response_rate: number;
  ai_response_change: number;
  avg_share_time_minutes: number;
  share_time_change: number;
}

export interface AIMetrics {
  detection_accuracy: number;
  false_positive_rate: number;
  avg_classification_seconds: number;
  attribution_accuracy: number;
}

export interface PlatformMetrics {
  total_threats: number;
  today_threats: number;
  high_risk_rate: number;
  attribution_rate: number;
  active_sources: number;
  avg_detection_lag_hours: number;
  today_ioc_sum: number;
  updated_at: string;
}

export interface ThreatFeed {
  id: number;
  title: string;
  severity: string;
  threat_type: string;
  actor: string | null;
  description: string | null;
  ioc_count: number;
  source?: string;
  detected_at: string | null;
  created_at: string;
}

export interface ThreatDetail {
  id: number;
  title: string;
  severity: string;
  threat_type: string;
  source: string;
  ioc_value: string | null;
  ioc_type: string | null;
  country_code: string | null;
  actor_tag: string | null;
  description: string | null;
  ioc_count: number;
  detected_at: string;
  shared_at: string | null;
  is_active: boolean;
  tlp_level: string;
  mitre_tactic: string | null;
  mitre_tactic_id: string | null;
  mitre_technique: string | null;
  mitre_technique_id: string | null;
}

export interface AutoResponse {
  id: number;
  threat_id: number;
  action_type: string;
  action_detail: string | null;
  status: string;
  executed_at: string;
}

export interface ThreatListResponse {
  total: number;
  page: number;
  page_size: number;
  items: ThreatDetail[];
}

export interface ThreatCreateRequest {
  title: string;
  severity: string;
  threat_type: string;
  source: string;
  ioc_value?: string;
  ioc_type?: string;
  country_code?: string;
  actor_tag?: string;
  description?: string;
  ioc_count?: number;
}

export interface ThreatDistribution {
  type: string;
  percentage: number;
  color: string;
}

export interface CountryShare {
  country: string;
  country_code: string;
  ioc_shared: number;
}

export interface ThreatActor {
  name: string;
  active: boolean;
}

export interface Agency {
  id: number;
  name: string;
  country: string;
  country_code: string;
  agency_type: string;
  contact_email: string | null;
  is_active: boolean;
}

export interface ShareCreate {
  agency_ids: number[];
  note?: string;
  from_agency?: string;
}

export interface ShareOut {
  id: number;
  threat_id: number;
  from_agency: string;
  to_agency_id: number;
  to_agency_name: string;
  shared_at: string;
  note: string | null;
  status: string;
  confirmed_at: string | null;
  tlp_level: string;
}

export interface AIAnalysis {
  id: number;
  threat_id: number;
  risk_score: number;
  risk_level: string;
  summary: string;
  attack_vector: string | null;
  target_sectors: string | null;
  recommendations: string | null;
  ioc_analysis: string | null;
  attribution: string | null;
  confidence_score: number;
  is_fallback: boolean;
  analyzed_at: string;
}

export interface WSMessage {
  type: 'new_threat' | 'stats_update';
  data: any;
}

export interface AttackMapEntry {
  country_code: string;
  country_name: string;
  count: number;
}

export interface TopAttacker {
  ip: string;
  count: number;
  country_code: string | null;
  severity: string | null;
  threat_type: string | null;
}

export interface GeoRiskEntry {
  country_code: string;
  country_name: string;
  score: number;
  level: string;
  trend: string;
  factors: string[];
}

export interface EconomicIndicator {
  name: string;
  value: number;
  change: number;
  category: string;
  unit: string;
}

// Graph types
export interface GraphNode {
  id: string;
  type: 'threat' | 'actor' | 'ioc' | 'campaign';
  label: string;
  color: string;
  size: number;
  data: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: 'uses' | 'targets' | 'related_to';
  label: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  total_nodes: number;
  total_edges: number;
}

// Prediction types
export interface TrendDataPoint {
  date: string;
  count: number;
}

export interface ForecastPoint {
  date: string;
  predicted_count: number;
  confidence: number;
  lower_bound: number;
  upper_bound: number;
}

export interface HotspotEntry {
  threat_type?: string;
  country_code?: string;
  source?: string;
  severity?: string;
  count: number;
}

// SIEM types
export interface SIEMLog {
  id: number;
  url: string;
  threat_id: number | null;
  status_code: number | null;
  success: boolean;
  format: string;
  sent_at: string;
  response: string | null;
}

// Dark web types
export interface DarkwebEntry {
  title: string;
  url: string;
  description: string;
  source: string;
  query: string;
  found_at: string;
  error?: boolean;
}

export interface BreachEntry {
  name: string;
  title: string;
  domain: string;
  breach_date: string;
  added_date: string;
  pwn_count: number;
  data_classes: string[];
  is_verified: boolean;
  is_sensitive: boolean;
  description: string;
  logo_path: string;
}

// Mirrors backend/osint_board/schemas/api.py and catalog/*.yaml.

export type EntityType = string;

export interface ModuleSpec {
  id: string;
  name: string;
  url: string | null;
  description: string;
  source_type: 'free_api' | 'tiered_api' | 'commercial_api' | 'internal' | 'tool';
  category: string;
  mode: 'lookup' | 'feed' | 'extract';
  access: string;
  status: 'active' | 'verify' | 'changed' | 'defunct';
  consumes: EntityType[];
  produces: EntityType[];
  geo: 'direct' | 'derived' | 'none';
  layer: string | null;
  phase: 1 | 2 | 3 | 4;
  priority: 'high' | 'normal' | 'low';
  replacement: string[];
  cadence?: string | null;
  requires_authorization?: boolean;
  notes?: string | null;
  implementation_status: 'implemented' | 'planned' | 'retired';
}

export interface Coverage {
  implemented: number;
  planned: number;
  retired: number;
  total: number;
  by_phase: Record<string, Record<string, number>>;
}

export interface Detection {
  type: EntityType;
  value: string;
  normalized: string;
  confidence: number;
  meta: Record<string, unknown>;
}

export interface QueryPlan {
  raw: string;
  text: string;
  terms: string[];
  phrases: string[];
  detections: Detection[];
  layers: string[];
  types: EntityType[];
  since: string | null;
  until: string | null;
  near: { lat: number; lon: number; radius_m: number } | null;
  intents: string[];
}

export interface SearchHit {
  id: string;
  type: EntityType;
  value: string;
  label: string;
  layer: string | null;
  investigation_id: string | null;
  has_geo: boolean;
  precision: string | null;
  lat: number | null;
  lon: number | null;
  last_seen_ts: number;
  confidence: number;
  degree: number;
  score: number;
  why: 'exact' | 'prefix' | 'fuzzy' | 'geo';
}

export interface Suggestion {
  kind: 'run_module' | 'fly_to' | 'filter' | 'create_entity';
  label: string;
  payload: Record<string, unknown>;
}

export interface SearchResponse {
  plan: QueryPlan;
  hits: SearchHit[];
  live: Record<string, unknown>[];
  suggestions: Suggestion[];
  took_ms: number;
}

export interface GeoFeature {
  type: 'Feature';
  id: string;
  geometry: { type: 'Point'; coordinates: [number, number] | [number, number, number] } | null;
  properties: Record<string, unknown> & { layer: string; name?: string; entity_type?: string; time?: string };
}

export interface FeatureCollection {
  type: 'FeatureCollection';
  features: GeoFeature[];
  layer: string | null;
  count: number;
  generated_at: string | null;
}

export interface Health {
  status: string;
  version: string;
  services: Record<string, string>;
}

/** Delta pushed over /api/stream for live layers. */
export interface LiveDelta {
  t: 'track' | 'event';
  id: string;
  lon: number;
  lat: number;
  alt: number | null;
  hdg?: number | null;
  spd?: number | null;
  ts: string;
  name?: string;
  props?: Record<string, unknown>;
}

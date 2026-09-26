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

/**
 * One live item for a layer (backend/osint_board/feeds/db_sink.py). `props` carries the item's scalar meta plus
 * `precision`, `geo_source` and `entity_type`; it is a partial update, merged over what the client already has.
 */
export interface LiveDelta {
  t: 'track' | 'event';
  id: string;
  lon: number;
  lat: number;
  /** metres above the WGS84 ellipsoid; null when unknown or on the ground */
  alt: number | null;
  /** track/heading in degrees (tracks only) */
  hdg?: number | null;
  /** ground speed in the layer's unit, knots for vessels and aircraft (tracks only) */
  spd?: number | null;
  /** ISO time of the position fix / observation */
  ts: string;
  name?: string;
  props?: Record<string, unknown>;
}

/**
 * Frames on /api/stream (backend/osint_board/api/routes/stream.py). The sink publishes one `batch` per write and
 * layer; a legacy single delta is a `LiveDelta` with a `layer`; `{type: 'error'}` precedes a server-side close.
 */
export interface LiveBatchFrame {
  t: 'batch';
  layer: string;
  items: LiveDelta[];
}

export type LiveDeltaFrame = LiveDelta & { layer: string };

export interface StreamErrorFrame {
  type: 'error';
  message: string;
}

/** Client-side stream status: `connecting` until the socket proves itself, `down` after the server reported an error. */
export type StreamState = { state: 'connecting' } | { state: 'live' } | { state: 'down'; message: string };

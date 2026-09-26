import { Button, Chip, Surface } from '@heroui/react';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Clock, Crosshair, Play, X } from 'lucide-react';
import { useEffect, useState } from 'react';

import { api } from '../api/client';
import { liveMaxAgeS } from '../globe/liveCache';
import { getLayer } from '../layers/registry';
import { formatAge, formatAltitude, formatCoord, formatDuration, formatTime } from '../lib/format';
import { useStore } from '../state/store';
import { AIRCRAFT_KEYS, AIRCRAFT_OLD_POSITION_S, distanceSinceKm, isAircraft, lookupValue, num } from './aircraft';
import { AircraftSection } from './AircraftSection';

const HIDDEN = new Set(['layer', 'name', 'line1', 'line2']);

/** Local time, re-read every `periodMs` while `enabled` (drives the "seen … ago" readout). */
function useNow(periodMs: number, enabled: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!enabled) return;
    setNow(Date.now());
    const t = setInterval(() => setNow(Date.now()), periodMs);
    return () => clearInterval(t);
  }, [periodMs, enabled]);
  return now;
}

export function InspectorPanel() {
  const selected = useStore((s) => s.selected);
  const select = useStore((s) => s.select);
  const requestFlyTo = useStore((s) => s.requestFlyTo);
  const skewMs = useStore((s) => s.clockSkewMs);
  const timeWindow = useStore((s) => s.timeWindow);
  const entityType = selected ? String(selected.props['entity_type'] ?? selected.props['type'] ?? '') : '';
  const layer = selected ? getLayer(selected.layer) : undefined;
  const live = layer?.update === 'stream';
  const now = useNow(1000, !!selected?.ts && live);

  const { data: modules } = useQuery({
    queryKey: ['modules-for', entityType],
    queryFn: () => api.modules({ consumes: entityType, status: 'implemented' }),
    enabled: !!entityType,
  });

  if (!selected) return null;
  const precision = String(selected.props['precision'] ?? selected.props['geo_precision'] ?? 'exact');
  const coarse = ['city', 'region', 'country'].includes(precision);
  const aircraft = isAircraft(entityType, selected.props);
  const skip = (k: string) => HIDDEN.has(k) || (aircraft && AIRCRAFT_KEYS.has(k));
  // ages are measured on the server's clock: feature times come from the server and its sources
  const ageS = live && selected.ts !== undefined ? Math.max(0, (now + skewMs - selected.ts) / 1000) : null;
  const oldPosition = aircraft && !selected.stale && ageS !== null && ageS > AIRCRAFT_OLD_POSITION_S && selected.props['on_ground'] !== true;
  const movedKm = oldPosition ? distanceSinceKm(num(selected.props['speed']), ageS) : null;

  return (
    <Surface variant="secondary" className="panel w-80 max-h-[calc(100vh-7rem)] overflow-y-auto p-3 text-sm">
      <div className="mb-2 flex items-start gap-2">
        <span className="mt-1 inline-block h-2.5 w-2.5 rounded-full" style={{ background: layer?.color ?? '#fff' }} />
        <div className="min-w-0 flex-1">
          <div className="truncate font-semibold">{selected.name}</div>
          <div className="text-xs opacity-60">
            {layer?.name ?? selected.layer}
            {entityType ? ` · ${entityType}` : ''}
          </div>
        </div>
        <Button size="sm" variant="ghost" isIconOnly aria-label="Close" onPress={() => select(null)}>
          <X size={14} />
        </Button>
      </div>

      <div className="mb-2 flex items-center gap-2 font-mono text-xs">
        <Crosshair size={12} />
        {formatCoord(selected.lat, selected.lon)}
        <span className="opacity-60">alt {formatAltitude(selected.alt)}</span>
        <Button size="sm" variant="ghost" onPress={() => requestFlyTo({ lat: selected.lat, lon: selected.lon, alt: selected.alt ?? undefined })}>
          go
        </Button>
      </div>

      {ageS !== null && (
        <div className="mb-2 flex items-center gap-2 text-xs opacity-80">
          <Clock size={12} /> seen {formatAge(ageS)}
          {!selected.stale && <span className="opacity-60">· updating live</span>}
        </div>
      )}

      {selected.stale && layer && (
        <div className="mb-2 flex items-center gap-2 rounded bg-yellow-500/10 p-2 text-xs text-yellow-200">
          <AlertTriangle size={14} className="shrink-0" />
          No update for over {formatDuration(liveMaxAgeS(layer.maxAgeS, timeWindow))}: it has left the live layer. This is its last
          known state.
        </div>
      )}

      {oldPosition && (
        <div className="mb-2 flex items-center gap-2 rounded bg-yellow-500/10 p-2 text-xs text-yellow-200">
          <AlertTriangle size={14} className="shrink-0" />
          Position is {formatDuration(ageS)} old
          {movedKm !== null && movedKm >= 1 ? `: at its ground speed the aircraft is about ${movedKm.toFixed(0)} km further on.` : '.'}
        </div>
      )}

      {coarse && (
        <div className="mb-2 flex items-center gap-2 rounded bg-yellow-500/10 p-2 text-xs text-yellow-200">
          <AlertTriangle size={14} /> {precision}-level placement: the halo shows the uncertainty, not a pin.
        </div>
      )}

      {aircraft && <AircraftSection props={selected.props} alt={selected.alt} />}

      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
        {Object.entries(selected.props)
          .filter(([k, v]) => !skip(k) && v !== null && v !== undefined && v !== '')
          .slice(0, 40)
          .map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="opacity-60">{k}</dt>
              <dd className="break-all font-mono">{k === 'time' ? formatTime(String(v)) : typeof v === 'object' ? JSON.stringify(v) : String(v)}</dd>
            </div>
          ))}
      </dl>

      {modules && modules.length > 0 && (
        <div className="mt-3 border-t border-white/10 pt-2">
          <div className="mb-1 text-xs uppercase tracking-wide opacity-60">Enrich with</div>
          <div className="flex flex-wrap gap-1">
            {modules.map((m) => (
              <Button
                key={m.id}
                size="sm"
                variant="ghost"
                onPress={() =>
                  void api
                    .runModule(m.id, { entity_type: entityType, value: lookupValue(entityType, selected.name, selected.props) })
                    .catch((e: Error) => console.warn(e.message))
                }
              >
                <Play size={12} /> {m.name}
              </Button>
            ))}
          </div>
          <Chip size="sm" variant="tertiary" className="mt-2">
            <Chip.Label>{modules.length} implemented modules accept {entityType}</Chip.Label>
          </Chip>
        </div>
      )}
    </Surface>
  );
}

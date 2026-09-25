import { Button, Chip, Label, Separator, Surface, Switch } from '@heroui/react';
import { Layers } from 'lucide-react';

import { tiledInRange } from '../globe/viewport';
import { ALTITUDE_STOPS, altitudeColor, GROUND_COLOR, UNKNOWN_ALTITUDE_COLOR } from '../layers/colors';
import { GROUP_LABELS, LAYERS } from '../layers/registry';
import type { LayerSpec } from '../layers/types';
import { parseAttribution } from '../lib/attribution';
import { useStore, type TimeWindow } from '../state/store';

const GROUP_ORDER: LayerSpec['group'][] = ['live', 'events', 'static', 'investigation'];
const WINDOWS: TimeWindow[] = ['1h', '24h', '7d', '30d'];

const ALTITUDE_TOP_M = ALTITUDE_STOPS[ALTITUDE_STOPS.length - 1]![0];
const LEGEND_STEPS = 16;
const ALTITUDE_GRADIENT = `linear-gradient(to right, ${Array.from({ length: LEGEND_STEPS + 1 }, (_, i) => {
  const t = i / LEGEND_STEPS;
  return `${altitudeColor(t * ALTITUDE_TOP_M)} ${(t * 100).toFixed(1)}%`;
}).join(', ')})`;

/** The aircraft colour key: the altitude ramp plus the ground and unknown-altitude colours. */
function AltitudeLegend() {
  const swatch = (color: string, label: string) => (
    <span className="flex items-center gap-1">
      <span className="inline-block h-2 w-2 rounded-full" style={{ background: color }} />
      {label}
    </span>
  );
  return (
    <div className="pl-10 text-[10px] leading-tight opacity-70">
      <div className="h-1.5 w-full rounded" style={{ background: ALTITUDE_GRADIENT }} />
      <div className="flex justify-between">
        <span>0</span>
        <span>{(ALTITUDE_TOP_M / 2000).toFixed(1)} km</span>
        <span>{(ALTITUDE_TOP_M / 1000).toFixed(0)} km+</span>
      </div>
      <div className="flex gap-3">
        {swatch(GROUND_COLOR, 'on ground')}
        {swatch(UNKNOWN_ALTITUDE_COLOR, 'altitude unknown')}
      </div>
    </div>
  );
}

export function LayerPanel() {
  const visible = useStore((s) => s.visible);
  const counts = useStore((s) => s.counts);
  const setLayerVisible = useStore((s) => s.setLayerVisible);
  const timeWindow = useStore((s) => s.timeWindow);
  const setTimeWindow = useStore((s) => s.setTimeWindow);
  const zoomedIn = useStore((s) => tiledInRange(s.viewport));

  return (
    <Surface variant="secondary" className="panel w-64 max-h-[calc(100vh-7rem)] overflow-y-auto p-3 text-sm">
      <div className="mb-2 flex items-center gap-2 font-semibold">
        <Layers size={16} /> Layers
      </div>
      <div className="mb-3 flex gap-1">
        {WINDOWS.map((w) => (
          <Button key={w} size="sm" variant={w === timeWindow ? 'primary' : 'ghost'} onPress={() => setTimeWindow(w)}>
            {w}
          </Button>
        ))}
      </div>
      {GROUP_ORDER.map((group) => {
        const layers = LAYERS.filter((l) => l.group === group);
        if (layers.length === 0) return null;
        return (
          <div key={group} className="mb-3">
            <div className="mb-1 text-xs uppercase tracking-wide opacity-60">{GROUP_LABELS[group]}</div>
            <Separator className="mb-2" />
            <ul className="flex flex-col gap-1.5">
              {layers.map((l) => (
                <li key={l.id} className="flex flex-col gap-0.5">
                  <div className="flex items-center gap-2">
                    <Switch size="sm" isSelected={!!visible[l.id]} onChange={(on) => setLayerVisible(l.id, on)}>
                      <Switch.Content>
                        <Switch.Control>
                          <Switch.Thumb />
                        </Switch.Control>
                        <Label className="flex items-center gap-2">
                          <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: l.color }} title={l.description} />
                          {l.name}
                        </Label>
                      </Switch.Content>
                    </Switch>
                    {visible[l.id] && l.tiled && !zoomedIn ? (
                      <Chip size="sm" variant="soft" className="ml-auto">
                        <Chip.Label>zoom in</Chip.Label>
                      </Chip>
                    ) : (
                      visible[l.id] &&
                      counts[l.id] !== undefined && (
                        <Chip size="sm" variant="soft" className="ml-auto">
                          <Chip.Label>{counts[l.id]}</Chip.Label>
                        </Chip>
                      )
                    )}
                  </div>
                  {visible[l.id] && l.colorBy.attribute === 'altitude_m' && <AltitudeLegend />}
                  {/* data licences (ODbL, CC BY-SA, provider terms) require the credit while the data is shown */}
                  {visible[l.id] && l.attribution && (
                    <p className="pl-10 text-[10px] leading-tight opacity-50">
                      {parseAttribution(l.attribution).map((part, i) =>
                        part.href ? (
                          <a key={i} href={part.href} target="_blank" rel="noopener noreferrer" className="underline">
                            {part.text}
                          </a>
                        ) : (
                          <span key={i}>{part.text}</span>
                        ),
                      )}
                    </p>
                  )}
                </li>
              ))}
            </ul>
          </div>
        );
      })}
    </Surface>
  );
}

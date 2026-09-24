import { Button, Chip, Label, Separator, Surface, Switch } from '@heroui/react';
import { Layers } from 'lucide-react';

import { GROUP_LABELS, LAYERS } from '../layers/registry';
import type { LayerSpec } from '../layers/types';
import { useStore, type TimeWindow } from '../state/store';

const GROUP_ORDER: LayerSpec['group'][] = ['live', 'events', 'static', 'investigation'];
const WINDOWS: TimeWindow[] = ['1h', '24h', '7d', '30d'];

export function LayerPanel() {
  const visible = useStore((s) => s.visible);
  const counts = useStore((s) => s.counts);
  const setLayerVisible = useStore((s) => s.setLayerVisible);
  const timeWindow = useStore((s) => s.timeWindow);
  const setTimeWindow = useStore((s) => s.setTimeWindow);

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
                <li key={l.id} className="flex items-center gap-2">
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
                  {visible[l.id] && counts[l.id] !== undefined && (
                    <Chip size="sm" variant="soft" className="ml-auto">
                      <Chip.Label>{counts[l.id]}</Chip.Label>
                    </Chip>
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

import { Chip } from '@heroui/react';
import { useQuery } from '@tanstack/react-query';

import { api } from '../api/client';
import { formatDistance } from '../lib/format';
import { useStore } from '../state/store';

export function StatusBar() {
  const mpp = useStore((s) => s.metersPerPixel);
  const clock = useStore((s) => s.clockIso);
  const counts = useStore((s) => s.counts);
  const visible = useStore((s) => s.visible);
  const { data: health } = useQuery({ queryKey: ['health'], queryFn: api.health, refetchInterval: 30_000 });
  const total = Object.entries(counts).reduce((acc, [id, n]) => acc + (visible[id] ? n : 0), 0);

  return (
    <div className="panel mx-3 mb-9 flex w-fit items-center gap-3 px-3 py-1 font-mono text-xs">
      <span>WGS84 · 1:1 scale</span>
      <span className="opacity-80">{mpp ? `1 px ≈ ${formatDistance(mpp)}` : ''}</span>
      <span className="opacity-80">{clock ? clock.replace('T', ' ').replace(/\.\d+Z$/, 'Z') : ''}</span>
      <span className="opacity-80">{total.toLocaleString()} features</span>
      <Chip size="sm" variant="soft" color={health ? (health.services['database'] === 'ok' ? 'success' : 'warning') : 'default'}>
        <Chip.Label>{health ? `api ${health.version} · db ${health.services['database'] ?? '?'} · ${health.services['search']}` : 'api …'}</Chip.Label>
      </Chip>
    </div>
  );
}

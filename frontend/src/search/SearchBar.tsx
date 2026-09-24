import { Button, Chip, Kbd, SearchField, Surface } from '@heroui/react';
import { useQuery } from '@tanstack/react-query';
import { Crosshair, Play } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

import { api } from '../api/client';
import type { SearchHit, Suggestion } from '../api/types';
import { useStore } from '../state/store';

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export function SearchBar() {
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const debounced = useDebounced(q.trim(), 150);
  const requestFlyTo = useStore((s) => s.requestFlyTo);
  const select = useStore((s) => s.select);

  const { data, isFetching } = useQuery({
    queryKey: ['search', debounced],
    queryFn: () => api.search(debounced),
    enabled: debounced.length > 1,
    placeholderData: (prev) => prev,
  });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
        setOpen(true);
      }
      if (e.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const onHit = (h: SearchHit) => {
    if (h.lat !== null && h.lon !== null) requestFlyTo({ lat: h.lat, lon: h.lon });
    select({ id: h.id, layer: h.layer ?? 'investigation', name: h.value, lat: h.lat ?? 0, lon: h.lon ?? 0, props: { type: h.type, precision: h.precision } });
    setOpen(false);
  };

  const onSuggestion = (s: Suggestion) => {
    if (s.kind === 'fly_to' && typeof s.payload.lat === 'number' && typeof s.payload.lon === 'number') {
      requestFlyTo({ lat: s.payload.lat, lon: s.payload.lon });
      setOpen(false);
    } else if (s.kind === 'run_module') {
      void api.runModule(String(s.payload.module), { entity_type: String(s.payload.type), value: String(s.payload.value) }).catch((err: Error) => {
        console.warn(err.message);
      });
    }
  };

  const plan = data?.plan;

  return (
    <div className="relative">
      <SearchField
        aria-label="Search entities, coordinates, MMSI, ICAO24, NORAD, filters"
        value={q}
        onChange={(v) => {
          setQ(v);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        fullWidth
      >
        <SearchField.Group>
          <SearchField.SearchIcon />
          <SearchField.Input ref={inputRef} placeholder="Search: 203.0.113.7 · example.com · mmsi:366999999 · 48.85,2.35 · layer:fires since:24h" />
          <Kbd variant="light" className="hidden sm:inline-flex">
            <Kbd.Abbr keyValue="command" />
            <Kbd.Content>K</Kbd.Content>
          </Kbd>
          <SearchField.ClearButton />
        </SearchField.Group>
      </SearchField>

      {open && data && debounced.length > 1 && (
        <Surface variant="secondary" className="panel absolute left-0 right-0 top-full z-20 mt-2 max-h-[60vh] overflow-y-auto p-2 text-sm">
          {plan && (
            <div className="mb-2 flex flex-wrap items-center gap-1 px-1 text-xs opacity-80">
              {plan.detections.slice(0, 4).map((d) => (
                <Chip key={`${d.type}:${d.normalized}`} size="sm" color={d.confidence >= 0.6 ? 'accent' : 'default'} variant="soft">
                  <Chip.Label>
                    {d.type} · {d.normalized} · {(d.confidence * 100).toFixed(0)}%
                  </Chip.Label>
                </Chip>
              ))}
              {plan.intents.map((i) => (
                <Chip key={i} size="sm" variant="tertiary">
                  <Chip.Label>{i}</Chip.Label>
                </Chip>
              ))}
              <span className="ml-auto">{isFetching ? '…' : `${data.took_ms} ms`}</span>
            </div>
          )}
          {data.hits.length === 0 && <div className="px-2 py-3 opacity-70">No indexed entities match. Try a suggestion below.</div>}
          <ul className="flex flex-col">
            {data.hits.map((h) => (
              <li key={h.id}>
                <button
                  type="button"
                  onClick={() => onHit(h)}
                  className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left hover:bg-white/10"
                >
                  <Chip size="sm" variant="soft">
                    <Chip.Label>{h.type}</Chip.Label>
                  </Chip>
                  <span className="truncate font-mono">{h.value}</span>
                  {h.has_geo && <Crosshair size={14} className="ml-auto opacity-70" />}
                  <span className="text-xs opacity-60">{h.why}</span>
                </button>
              </li>
            ))}
          </ul>
          {data.suggestions.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1 border-t border-white/10 px-1 pt-2">
              {data.suggestions.map((s) => (
                <Button key={s.label} size="sm" variant={s.kind === 'fly_to' ? 'primary' : 'ghost'} onPress={() => onSuggestion(s)}>
                  {s.kind === 'fly_to' ? <Crosshair size={14} /> : s.kind === 'run_module' ? <Play size={14} /> : null}
                  {s.label}
                </Button>
              ))}
            </div>
          )}
        </Surface>
      )}
    </div>
  );
}

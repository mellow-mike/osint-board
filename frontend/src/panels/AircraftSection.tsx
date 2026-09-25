import { Chip } from '@heroui/react';
import { Radio, ShieldAlert } from 'lucide-react';
import type { ReactNode } from 'react';

import { formatAltitude, formatFeet, formatFlightLevel, formatHeading, formatSpeedKt, formatVerticalRate } from '../lib/format';
import { num, POSITION_SOURCE_LABELS, squawkAlert, text } from './aircraft';

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="contents">
      <dt className="opacity-60">{label}</dt>
      <dd className="break-all font-mono">{children}</dd>
    </div>
  );
}

/** Aircraft facts with units: altitude in ft/FL and m, speed in kt, track in degrees, vertical rate in ft/min. */
export function AircraftSection({ props, alt }: { props: Record<string, unknown>; alt: number | null | undefined }) {
  const onGround = props['on_ground'] === true;
  const altitude = num(props['altitude_m']) ?? (onGround ? null : (alt ?? null));
  const altSource = text(props['alt_source']);
  const baro = num(props['alt_baro_m']);
  const squawk = text(props['squawk']);
  const alert = squawkAlert(squawk);
  const emergency = text(props['emergency']);
  const positionSource = text(props['position_source']);
  const mlat = props['mlat'] === true || positionSource === 'mlat';
  const type = [text(props['type_code']), text(props['type_desc'])].filter(Boolean).join(' · ');

  return (
    <div className="mb-2 border-b border-white/10 pb-2">
      <div className="mb-1.5 flex flex-wrap items-center gap-1">
        {alert && (
          <Chip size="sm" color="danger" variant="primary">
            <ShieldAlert size={12} />
            <Chip.Label>
              squawk {squawk} · {alert}
            </Chip.Label>
          </Chip>
        )}
        {emergency && (
          <Chip size="sm" color="danger" variant="soft">
            <Chip.Label>emergency: {emergency}</Chip.Label>
          </Chip>
        )}
        {onGround && (
          <Chip size="sm" variant="soft">
            <Chip.Label>on ground</Chip.Label>
          </Chip>
        )}
        {positionSource && (
          <Chip size="sm" color={mlat ? 'warning' : 'default'} variant="soft">
            <Radio size={12} />
            <Chip.Label>{POSITION_SOURCE_LABELS[positionSource] ?? positionSource}</Chip.Label>
          </Chip>
        )}
      </div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
        <Row label="callsign">{text(props['callsign']) ?? '—'}</Row>
        <Row label="icao24">{text(props['icao24']) ?? '—'}</Row>
        {text(props['registration']) && <Row label="registration">{text(props['registration'])}</Row>}
        {type && <Row label="type">{type}</Row>}
        {text(props['operator']) && <Row label="operator">{text(props['operator'])}</Row>}
        <Row label="altitude">
          {onGround ? (
            'on ground'
          ) : altitude === null ? (
            'unknown'
          ) : (
            <>
              {formatFeet(altitude)} · {formatAltitude(altitude)}
              {altSource && <span className="opacity-60"> ({altSource})</span>}
            </>
          )}
        </Row>
        {!onGround && baro !== null && (
          <Row label="pressure alt">
            {formatFlightLevel(baro)} · {formatFeet(baro)}
          </Row>
        )}
        <Row label="ground speed">{formatSpeedKt(num(props['speed']))}</Row>
        <Row label="track">{formatHeading(num(props['heading']))}</Row>
        {!onGround && <Row label="vertical rate">{formatVerticalRate(num(props['vertical_rate_fpm']))}</Row>}
        <Row label="squawk">
          {squawk === null ? '—' : <span className={alert ? 'font-semibold text-red-400' : undefined}>{squawk}</span>}
        </Row>
        <Row label="source">
          {text(props['source']) ?? '—'}
          {mlat && <span className="opacity-60"> (multilaterated, street precision)</span>}
        </Row>
      </dl>
    </div>
  );
}

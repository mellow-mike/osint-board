import { describe, expect, it } from 'vitest';

import { parseAttribution } from './attribution';

describe('parseAttribution', () => {
  it('turns markdown-style links into link parts and keeps the text between them', () => {
    expect(parseAttribution('Aircraft: [adsb.lol](https://adsb.lol) ([ODbL 1.0](https://opendatacommons.org/licenses/odbl/1-0/)) · x')).toEqual([
      { text: 'Aircraft: ' },
      { text: 'adsb.lol', href: 'https://adsb.lol' },
      { text: ' (' },
      { text: 'ODbL 1.0', href: 'https://opendatacommons.org/licenses/odbl/1-0/' },
      { text: ') · x' },
    ]);
  });

  it('leaves plain text and non-http targets alone', () => {
    expect(parseAttribution('USGS')).toEqual([{ text: 'USGS' }]);
    expect(parseAttribution('[x](javascript:alert(1))')).toEqual([{ text: '[x](javascript:alert(1))' }]);
  });
});

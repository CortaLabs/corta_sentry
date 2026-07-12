import {describe,it,expect} from 'vitest';
import {ago,human,scanSpec,stamp} from './console';

describe('console formatting and scan input',()=>{
  it('normalizes and bounds targets and ports',()=>expect(scanSpec(' 127.0.0.1,127.0.0.1, ::1 ','80, 443, 0, 70000, nope,80')).toEqual({targets:['127.0.0.1','::1'],ports:[80,443]}));
  it('renders domain names without changing their uncertainty',()=>expect(human('potentially_applicable')).toBe('Potentially Applicable'));
  it('formats deterministic relative time',()=>expect(ago('2026-07-12T12:00:00Z',Date.parse('2026-07-12T12:05:00Z'))).toBe('5m ago'));
  it('uses an explicit empty timestamp marker',()=>expect(stamp('')).toBe('—'));
});

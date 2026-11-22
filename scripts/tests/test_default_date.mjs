import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const appSource=await readFile(new URL('../../public/app.js',import.meta.url),'utf8');
const { defaultDate }=await import('data:text/javascript;base64,'+Buffer.from(appSource).toString('base64'));

const manifest = {latestDate:'2026-11-24',days:{'2026-11-24':{},'2026-11-20':{},'2026-11-23':{}}};
// Publishing Tuesday early must not replace Monday on Sunday or Monday.
assert.equal(defaultDate(manifest,new Date('2026-11-22T21:00:00Z')),'2026-11-23');
assert.equal(defaultDate(manifest,new Date('2026-11-23T08:00:00Z')),'2026-11-23');
assert.equal(defaultDate(manifest,new Date('2026-11-23T22:59:59Z')),'2026-11-23');
assert.equal(defaultDate(manifest,new Date('2026-11-23T23:00:00Z')),'2026-11-24');
assert.equal(defaultDate(manifest,new Date('2026-11-24T08:00:00Z')),'2026-11-24');
// With no current or future preparation, show the latest one and its stale notice.
assert.equal(defaultDate(manifest,new Date('2026-11-25T08:00:00Z')),'2026-11-24');
// An explicit missing-day notice remains visible instead of skipping ahead.
assert.equal(defaultDate({...manifest,days:{...manifest.days,'2026-11-22':{status:'missing'}}},new Date('2026-11-22T12:00:00Z')),'2026-11-22');
// Midnight in Paris also works while daylight saving time applies.
const summer={latestDate:'2027-06-15',days:{'2027-06-14':{},'2027-06-15':{}}};
assert.equal(defaultDate(summer,new Date('2027-06-14T21:59:59Z')),'2027-06-14');
assert.equal(defaultDate(summer,new Date('2027-06-14T22:00:00Z')),'2027-06-15');
console.log('9 date-selection scenarios passed');

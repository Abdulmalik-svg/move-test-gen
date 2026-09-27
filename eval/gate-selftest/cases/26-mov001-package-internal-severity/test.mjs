#!/usr/bin/env node
/**
 * MOV-001 reports a missing capability on every public-family function, but
 * how severe it is depends on whether a transaction can call it directly.
 *
 * `public(package)` / `public(friend)` without `entry` cannot be a transaction
 * target, so an unguarded &mut there is only reachable through a public
 * caller -- which MOV-001 checks on its own. Those are reported as LOW
 * (still visible, pointing at the callers) instead of HIGH.
 *
 * Anything a transaction can call directly -- `public`, `public entry`,
 * `public(package) entry`, `public(friend) entry` -- stays HIGH.
 *
 * Wrapped signatures go through the fallback path in check(), so both
 * shapes are pinned. The capability exemption still applies everywhere.
 */
import { check } from '../../../../rules/mov-001-missing-access-control.mjs';

const oneLine = (decl, params) =>
  `module demo::m {\n    ${decl} f${params} { }\n}\n`;
const wrapped = (decl) =>
  `module demo::m {\n    ${decl} f(\n        pool: &mut Pool,\n        amount: u64,\n    ) { }\n}\n`;

const unguarded = '(pool: &mut Pool, amount: u64)';
const guarded = '(_: &AdminCap, pool: &mut Pool, amount: u64)';

const cases = [
  // [source, expected severity (null = no finding), why]
  [oneLine('public fun', unguarded),                'HIGH', 'public fun is a transaction target'],
  [oneLine('public entry fun', unguarded),          'HIGH', 'public entry is a transaction target'],
  [oneLine('public(package) entry fun', unguarded), 'HIGH', 'entry defeats the package restriction'],
  [oneLine('public(friend) entry fun', unguarded),  'HIGH', 'entry defeats the friend restriction'],
  [oneLine('public(package) fun', unguarded),       'LOW',  'package-internal: reported, not externally callable'],
  [oneLine('public(friend) fun', unguarded),        'LOW',  'friend-internal: reported, not externally callable'],
  [wrapped('public fun'),                           'HIGH', 'wrapped public fun (fallback path)'],
  [wrapped('public(package) fun'),                  'LOW',  'wrapped public(package) fun (fallback path)'],
  [oneLine('public(package) fun', guarded),         null,   'capability exemption still applies'],
];

let failed = 0;
for (const [src, want, why] of cases) {
  const got = check(src, 'demo.move').filter(x => x.rule === 'MOV-001');
  const ok = want === null
    ? got.length === 0
    : got.length === 1 && got[0].severity === want;
  if (!ok) {
    failed++;
    const seen = got.map(x => x.severity).join(',') || 'none';
    console.log(`  expected ${want ?? 'none'}, got ${seen} — ${why}`);
  }
}

if (failed) {
  console.log(`${failed} MOV-001 visibility case(s) failed`);
  process.exit(1);
}
console.log('MOV-001 severity by visibility pinned (HIGH for transaction targets, LOW for package-internal)');
process.exit(0);

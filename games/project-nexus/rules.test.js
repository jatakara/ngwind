'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const rules = require('./rules.js');

test('touch/click coordinates scale to logical grid', () => {
  const rect = { left: 100, top: 50, width: 400, height: 240 };
  assert.deepEqual(rules.pointerToCell(250, 140, rect), { x: 300, y: 180 });
  assert.deepEqual(rules.pointerToCell(100, 50, rect), { x: 20, y: 20 });
  assert.equal(rules.pointerToCell(500, 140, rect), null);
  assert.equal(rules.pointerToCell(250, 290, rect), null);
  assert.equal(rules.pointerToCell(250, 140, { ...rect, width: 0 }), null);
});

test('placement requires funds and excludes path, edges, and occupied tiles', () => {
  const spot = { x: 300, y: 180 };
  assert.equal(rules.canPlaceTower(spot, [], 20), true);
  assert.equal(rules.canPlaceTower(spot, [], 19), false);
  assert.equal(rules.canPlaceTower({ x: 300, y: 220 }, [], 100), false);
  assert.equal(rules.canPlaceTower({ x: 20, y: 180 }, [], 100), false);
  assert.equal(rules.canPlaceTower({ x: 780, y: 180 }, [], 100), false);
  assert.equal(rules.canPlaceTower(spot, [spot], 100), false);
  assert.equal(rules.canPlaceTower({ x: NaN, y: 180 }, [], 100), false);
});

test('targeting prioritizes closest to core and excludes already-doomed targets', () => {
  const tower = { x: 300, y: 180 };
  const front = { x: 340, y: 240, hp: 1 };
  const rear = { x: 270, y: 240, hp: 2 };
  assert.equal(rules.selectTarget(tower, [rear, front], []), front);
  assert.equal(rules.selectTarget(tower, [rear, front], [{ target: front }]), rear);
  assert.equal(rules.selectTarget(tower, [rear, front], [{ target: front }, { target: rear }, { target: rear }]), null);
});

test('target selection ignores out-of-range and defeated enemies', () => {
  const tower = { x: 300, y: 180 };
  assert.equal(rules.selectTarget(tower, [{ x: 800, y: 240, hp: 2 }], []), null);
  assert.equal(rules.selectTarget(tower, [{ x: 320, y: 240, hp: 0 }], []), null);
});


test('placement rejects non-grid positions even with sufficient credits', () => {
  assert.equal(rules.canPlaceTower({ x: 301, y: 180 }, [], 100), false);
  assert.equal(rules.canPlaceTower({ x: 300, y: 181 }, [], 100), false);
  assert.equal(rules.canPlaceTower({ x: 300, y: 180 }, [], 100), true);
});

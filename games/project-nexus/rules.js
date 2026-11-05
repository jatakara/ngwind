/* Browser global + CommonJS export: zero dependencies, works from file://. */
(function (root, factory) {
  'use strict';
  const rules = factory();
  if (typeof module === 'object' && module.exports) module.exports = rules;
  root.NexusRules = rules;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const WIDTH = 800, HEIGHT = 480, CELL = 40, LANE = 240;
  const COST = 20, RANGE = 175;
  const distance = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);

  function pointerToCell(clientX, clientY, rect) {
    if (!rect || ![clientX, clientY, rect.left, rect.top, rect.width, rect.height].every(Number.isFinite)
      || rect.width <= 0 || rect.height <= 0) return null;
    const px = (clientX - rect.left) * WIDTH / rect.width;
    const py = (clientY - rect.top) * HEIGHT / rect.height;
    if (px < 0 || py < 0 || px >= WIDTH || py >= HEIGHT) return null;
    return { x: Math.floor(px / CELL) * CELL + CELL / 2,
      y: Math.floor(py / CELL) * CELL + CELL / 2 };
  }

  function canPlaceTower(cell, towers, credits) {
    return !!cell && Number.isFinite(cell.x) && Number.isFinite(cell.y)
      && Number.isFinite(credits) && credits >= COST
      && cell.x >= 80 && cell.x <= 720 && cell.y >= 0 && cell.y < HEIGHT
      && (cell.x - CELL / 2) % CELL === 0 && (cell.y - CELL / 2) % CELL === 0
      && Math.abs(cell.y - LANE) >= 38
      && !towers.some(t => distance(t, cell) < CELL);
  }

  function selectTarget(tower, enemies, bullets, range = RANGE) {
    if (!tower || !Number.isFinite(range) || range <= 0) return null;
    const incoming = new Map();
    for (const bullet of bullets) {
      incoming.set(bullet.target, (incoming.get(bullet.target) || 0) + 1);
    }
    let best = null;
    for (const enemy of enemies) {
      if (enemy.hp <= (incoming.get(enemy) || 0) || distance(tower, enemy) >= range) continue;
      if (!best || enemy.x > best.x) best = enemy;
    }
    return best;
  }

  return Object.freeze({ pointerToCell, canPlaceTower, selectTarget, COST, RANGE });
});

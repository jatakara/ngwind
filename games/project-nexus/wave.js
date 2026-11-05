/* Pure wave progression rules, shared by browser and Node tests. */
(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.NexusWave = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  function initial() { return { hp: 100, credits: 50, score: 0, wave: 1, dead: false }; }
  function start(state, running) {
    if (running || state.dead) return null;
    return { remaining: 4 + state.wave * 2, spawn: 0.1 };
  }
  function escape(state) {
    if (state.dead) return state;
    const hp = Math.max(0, state.hp - 15);
    return { ...state, hp, dead: hp === 0 };
  }
  function defeat(state) {
    if (state.dead) return state;
    return { ...state, score: state.score + 10, credits: state.credits + 5 };
  }
  function finish(state, running, remaining, enemiesCount) {
    if (!running || remaining !== 0 || enemiesCount !== 0 || state.dead) return null;
    return { ...state, wave: state.wave + 1, credits: state.credits + 15 };
  }
  return Object.freeze({ initial, start, escape, defeat, finish });
});

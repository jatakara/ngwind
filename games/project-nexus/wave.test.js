'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const wave = require('./wave.js');
test('reset restores baseline', () => { assert.deepEqual(wave.initial(), {hp:100,credits:50,score:0,wave:1,dead:false}); });
test('wave cannot start twice or after defeat', () => {
 const s=wave.initial();assert.deepEqual(wave.start(s,false),{remaining:6,spawn:.1});
 assert.equal(wave.start(s,true),null);assert.equal(wave.start({...s,dead:true},false),null);
});
test('escape clamps health and prevents victory after defeat', () => {
 let s=wave.initial();for(let i=0;i<7;i++)s=wave.escape(s);
 assert.equal(s.hp,0);assert.equal(s.dead,true);assert.equal(wave.finish(s,true,0,0),null);
});
test('wave victory only when all enemies have spawned and been eliminated', () => {
 const s=wave.initial();assert.equal(wave.finish(s,true,1,0),null);
 assert.equal(wave.finish(s,true,0,1),null);assert.equal(wave.finish(s,false,0,0),null);
 assert.deepEqual(wave.finish(s,true,0,0),{...s,wave:2,credits:65});
});
test('defeat awards points and credits without mutating original state', () => {
 const s=wave.initial();const next=wave.defeat(s);
 assert.equal(s.score,0);assert.equal(next.score,10);assert.equal(next.credits,55);
});

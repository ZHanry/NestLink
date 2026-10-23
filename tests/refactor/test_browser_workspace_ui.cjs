'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { assertVisibleGeometry, assertStable } = require('../../scripts/lib/refactor-browser-workspace-ui.cjs');

function geometry() {
  return { viewport: { width: 390, height: 844 }, document_width: 390, items: {
    stop: { count: 1, visible: true, hit: true, disabled: false,
      rect: { x: 250, y: 90, width: 64, height: 28 } },
    canvas: { count: 1, visible: true, hit: false,
      rect: { x: 0, y: 168, width: 390, height: 566 } },
  } };
}

test('an intentional drawer may cover the canvas while fixed actions remain usable', () => {
  assert.doesNotThrow(() => assertVisibleGeometry(geometry(), ['stop', 'canvas'], ['stop']));
});

test('absent, duplicated or hidden actions never count as a successful layout', () => {
  for (const mutation of [value => delete value.items.stop,
    value => { value.items.stop.count = 2; }, value => { value.items.stop.visible = false; }]) {
    const value = geometry();
    mutation(value);
    assert.throws(() => assertVisibleGeometry(value, ['stop']));
  }
});

test('offscreen and covered actions fail even if a DOM click could call their handler', () => {
  for (const mutation of [value => { value.items.stop.rect.y = 830; },
    value => { value.items.stop.rect.x = -8; }, value => { value.items.stop.hit = false; },
    value => { value.document_width = 405; }]) {
    const value = geometry();
    mutation(value);
    assert.throws(() => assertVisibleGeometry(value, ['stop']));
  }
});

test('missing and nonfinite evidence fails closed', () => {
  for (const mutation of [value => delete value.viewport,
    value => { value.items.stop.rect.height = 0; }, value => { value.items.stop.rect.width = NaN; }]) {
    const value = geometry();
    mutation(value);
    assert.throws(() => assertVisibleGeometry(value, ['stop']));
  }
});

test('content updates may not shift fixed controls or resize the canvas', () => {
  for (const key of ['stop', 'canvas']) {
    for (const field of ['x', 'y', 'width', 'height']) {
      const before = geometry(), after = geometry();
      after.items[key].rect[field] += 1;
      assert.throws(() => assertStable(before, after, ['stop', 'canvas']));
    }
  }
});

test('stability checks reject missing rectangles and comparisons across viewport sizes', () => {
  const missing = geometry();
  delete missing.items.stop.rect;
  assert.throws(() => assertStable(geometry(), missing, ['stop']));
  const resized = geometry();
  resized.viewport.width = 760;
  assert.throws(() => assertStable(geometry(), resized, ['stop']));
  assert.doesNotThrow(() => assertStable(geometry(), geometry(), ['stop', 'canvas']));
});

// 验证真实合并函数，不依赖浏览器事件时序或重写一份业务逻辑。
import ts from 'typescript';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
const source = ts.transpileModule(
  readFileSync('src/reverse-state.ts', 'utf8'),
  {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
  },
).outputText;
const { mergeReverseJobs } = await import(
  'data:text/javascript;base64,' + Buffer.from(source).toString('base64')
);
const job = {
  id: 'one',
  caseId: 'a',
  createdAt: '2026-10-28T01:00:00Z',
  state: 'running',
  revision: 1,
};
let value = mergeReverseJobs([], [job], 'a');
value = mergeReverseJobs(
  value,
  [{ ...job, state: 'completed', revision: 3, content: 'evidence preserved' }],
  'a',
);
value = mergeReverseJobs(value, [{ ...job, revision: 2 }], 'a');
assert.equal(value[0].state, 'completed');
assert.equal(value[0].content, 'evidence preserved');
assert.equal(
  mergeReverseJobs(
    value,
    [{ ...job, id: 'foreign', caseId: 'b', revision: 99 }],
    'a',
  ).length,
  1,
);
assert.deepEqual(mergeReverseJobs(value, [], 'b'), []);
assert.equal(
  mergeReverseJobs(
    [{ ...job, state: 'failed', revision: 0 }],
    [{ ...job, revision: 0 }],
    'a',
  )[0].state,
  'failed',
);
const many = Array.from({ length: 130 }, (_, n) => ({
  ...job,
  id: String(n).padStart(3, '0'),
}));
assert.equal(mergeReverseJobs([], many, 'a').length, 100);
assert.equal(mergeReverseJobs([], many, 'a')[0].id, '129');
console.log('7 UI state regression assertions passed');

const journalSource = ts.transpileModule(
  readFileSync('src/draft-journal.ts', 'utf8'),
  {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
  },
).outputText;
const journal = await import(
  'data:text/javascript;base64,' + Buffer.from(journalSource).toString('base64')
);
const entries = new Map();
const storage = {
  getItem: (k) => entries.get(k) ?? null,
  setItem: (k, v) => entries.set(k, v),
  removeItem: (k) => entries.delete(k),
};
const key = journal.draftBackupKey('/workspace A', 'incident-1');
assert.notEqual(key, journal.draftBackupKey('/workspace B', 'incident-1'));
journal.writeDraftBackup(storage, key, { text: 'first' }, 'v1');
journal.writeDraftBackup(storage, key, { text: 'second' }, 'v1');
journal.acknowledgeDraftBackup(storage, key, { text: 'first' });
assert.equal(journal.readDraftBackup(storage, key).draft.text, 'second');
journal.acknowledgeDraftBackup(storage, key, { text: 'second' });
assert.equal(journal.readDraftBackup(storage, key), null);
console.log('3 report recovery regression assertions passed');

const structureSource = ts.transpileModule(
  readFileSync('src/report-structure.ts', 'utf8'),
  {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
  },
).outputText;
const structure = await import(
  'data:text/javascript;base64,' +
    Buffer.from(structureSource).toString('base64')
);
const section = (id, parentId = null) => ({
  id,
  parentId,
  title: id,
  body: 'preserved ' + id,
  nodeIds: ['evidence-node'],
  owner: 'owner',
  status: 'todo',
  startedAt: '',
  completedAt: '',
});
const tree = [
  section('a'),
  section('a1', 'a'),
  section('a2', 'a'),
  section('b'),
  section('b1', 'b'),
];
const moved = structure.moveSection(tree, 'b', -1);
assert.deepEqual(
  moved.map((s) => s.id),
  ['b', 'b1', 'a', 'a1', 'a2'],
);
assert.strictEqual(moved[1].nodeIds, tree[4].nodeIds);
assert.strictEqual(structure.moveSection(tree, 'a', -1), tree);
assert.deepEqual(
  structure.moveSection(tree, 'a2', -1).map((s) => s.id),
  ['a', 'a2', 'a1', 'b', 'b1'],
);
assert.strictEqual(structure.moveSection(tree, 'a2', 1), tree);
assert.deepEqual(structure.sectionNumbers(moved), {
  b: '1.',
  b1: '1.1',
  a: '2.',
  a1: '2.1',
  a2: '2.2',
});
assert.equal(structure.sectionBlock(tree, 'a').rows.length, 3);
assert.equal(structure.sectionBlock(tree, 'a1').rows.length, 1);
console.log('8 report structure regression assertions passed');

const localSource = ts.transpileModule(
  readFileSync('src/local-analysis-state.ts', 'utf8'),
  {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
  },
).outputText;
const { mergeLocalJobs, localRunning } = await import(
  'data:text/javascript;base64,' + Buffer.from(localSource).toString('base64')
);
const local = {
  id: 'local',
  caseId: 'case-a',
  startedAt: '2026-10-30T01:00:00Z',
  state: 'running',
  revision: 1,
};
const terminal = {
  ...local,
  state: 'completed',
  revision: 4,
  evidenceId: 'saved',
};
let localJobs = mergeLocalJobs([terminal], [local]);
assert.equal(localJobs[0].state, 'completed');
assert.equal(localJobs[0].evidenceId, 'saved');
assert.equal(
  mergeLocalJobs([terminal], [{ ...local, revision: 4 }])[0].state,
  'completed',
);
assert.equal(
  mergeLocalJobs(localJobs, [
    { ...local, id: 'other', caseId: 'case-b', revision: 2 },
  ]).length,
  2,
);
assert.equal(
  mergeLocalJobs(
    [],
    Array.from({ length: 120 }, (_, n) => ({ ...local, id: String(n) })),
  ).length,
  80,
);
assert.equal(localRunning({ ...local, state: 'cancelling' }), true);
assert.equal(localRunning(terminal), false);
console.log('7 local analysis state assertions passed');

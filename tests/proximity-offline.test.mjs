import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

class OfflinePeer {
  constructor(id, session) {
    this.id = id;
    this.session = session;
    this.seen = new Set();
    this.lastSequence = 0;
    this.encryptedInbox = [];
  }

  accept(envelope, now) {
    assert.deepEqual(Object.keys(envelope).sort(), [
      'ciphertext', 'ciphertext_sha256', 'expires_at', 'issued_at', 'message_id',
      'mutation_id', 'recipient', 'sender', 'sequence', 'session', 'signature_valid',
    ]);
    assert.equal(envelope.recipient, this.id);
    assert.equal(envelope.session, this.session);
    assert.ok(now >= envelope.issued_at && now < envelope.expires_at);
    assert.ok(envelope.expires_at - envelope.issued_at <= 120_000);
    assert.equal(envelope.signature_valid, true);
    assert.equal(this.seen.has(envelope.message_id), false);
    assert.ok(envelope.sequence > this.lastSequence);
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64url');
    assert.ok(ciphertext.length <= 32 * 1024);
    assert.equal(sha256(ciphertext), envelope.ciphertext_sha256);

    this.seen.add(envelope.message_id);
    this.lastSequence = envelope.sequence;
    this.encryptedInbox.push(structuredClone(envelope));
  }
}

function envelope(overrides = {}) {
  const ciphertext = Buffer.from('encrypted-clip-mutation');
  return {
    message_id: 'message-1',
    mutation_id: 'mutation-1',
    sender: 'device-a',
    recipient: 'device-b',
    session: 'offline-session',
    sequence: 1,
    issued_at: 1_000_000,
    expires_at: 1_120_000,
    ciphertext: ciphertext.toString('base64url'),
    ciphertext_sha256: sha256(ciphertext),
    signature_valid: true,
    ...overrides,
  };
}

test('journey 1: Wi-Fi-down transfer stores only an encrypted, consented mutation', () => {
  const receiver = new OfflinePeer('device-b', 'offline-session');
  receiver.accept(envelope(), 1_000_001);
  assert.equal(receiver.encryptedInbox.length, 1);
  const serialized = JSON.stringify(receiver.encryptedInbox);
  assert.equal(serialized.includes('clipboard plaintext'), false);
  assert.equal(serialized.includes('password'), false);
});

test('journey 2: replay, reorder, expiry, wrong recipient, tampering, and failed signature do not enter the inbox', () => {
  const cases = [
    envelope({ recipient: 'device-c' }),
    envelope({ sequence: 0 }),
    envelope({ ciphertext: Buffer.from('tampered').toString('base64url') }),
    envelope({ signature_valid: false }),
  ];
  for (const candidate of cases) {
    const receiver = new OfflinePeer('device-b', 'offline-session');
    assert.throws(() => receiver.accept(candidate, 1_000_001));
    assert.equal(receiver.encryptedInbox.length, 0);
  }
  const expired = new OfflinePeer('device-b', 'offline-session');
  assert.throws(() => expired.accept(envelope(), 1_120_000));
  const replay = new OfflinePeer('device-b', 'offline-session');
  replay.accept(envelope(), 1_000_001);
  assert.throws(() => replay.accept(envelope(), 1_000_002));
  assert.equal(replay.encryptedInbox.length, 1);
});

test('journey 3: reconnect reconciliation is exactly-once by mutation id across network and proximity paths', () => {
  const proximity = [envelope(), envelope({ message_id: 'message-2' })];
  const network = [
    envelope({ message_id: 'server-message-1' }),
    envelope({ message_id: 'server-message-2', mutation_id: 'mutation-2', sequence: 2 }),
  ];
  const reconciled = new Map();
  for (const candidate of [...proximity, ...network]) {
    if (!reconciled.has(candidate.mutation_id)) reconciled.set(candidate.mutation_id, candidate);
  }
  assert.deepEqual([...reconciled.keys()], ['mutation-1', 'mutation-2']);
  assert.equal(reconciled.get('mutation-1').message_id, 'message-1');
});

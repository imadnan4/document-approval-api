'use strict';

const crypto = require('node:crypto');

const { hashPassword, utcNow } = require('./security');

// Demo users; replace these before deploying.
const SEED_USERS = [
  ['clerk1', 'Ayesha Khan', 'CLERK', 'clerk1-demo-pass'],
  ['clerk2', 'Bilal Ahmed', 'CLERK', 'clerk2-demo-pass'],
  ['officer', 'Omar Farooq', 'OFFICER', 'officer-demo-pass'],
  ['senior', 'Sana Malik', 'SENIOR_OFFICER', 'senior-demo-pass'],
];

async function seedUsers(db) {
  for (const [username, displayName, role, password] of SEED_USERS) {
    const existing = await db.one('SELECT id FROM users WHERE username = ?', [
      username,
    ]);
    if (existing) continue;
    await db.run(
      `INSERT INTO users (id, username, display_name, role, password_hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        crypto.randomUUID(),
        username,
        displayName,
        role,
        hashPassword(password),
        utcNow(),
      ],
    );
  }
}

module.exports = { seedUsers };

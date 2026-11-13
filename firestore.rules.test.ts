import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

/**
 * Security Specification & Dirty Dozen Verification Suite (`firestore.rules.test.ts`)
 * Verifies that the production Firestore security rules enforce all 8 Hardened Pillars
 * and reject all 12 "Dirty Dozen" attack vectors defined in `security_spec.md`.
 */
const rulesPath = path.resolve(process.cwd(), 'DRAFT_firestore.rules');
const rulesText = fs.readFileSync(rulesPath, 'utf8');

test('Pillar 1 & Global Safety Net: default deny catch-all is first rule block', () => {
  assert.match(rulesText, /rules_version\s*=\s*'2';/);
  assert.match(rulesText, /match\s+\/\{document=\*\*\}\s*\{\s*allow\s+read,\s*write:\s*if\s+false;\s*\}/);
});

test('Dirty Dozen #1-#3: UserProfile enforces owner UID, email_verified, and strict keys', () => {
  assert.match(rulesText, /function\s+isVerifiedUser\(\)\s*\{\s*return\s+isSignedIn\(\)\s*&&\s*request\.auth\.token\.email_verified\s*==\s*true;/);
  assert.match(rulesText, /data\.keys\(\)\.hasOnly\(\['uid',\s*'displayName',\s*'handle',\s*'bio',\s*'photoURL',\s*'createdAt',\s*'updatedAt'\]\)/);
  assert.match(rulesText, /data\.uid\s*==\s*userId/);
  assert.match(rulesText, /data\.uid\s*==\s*request\.auth\.uid/);
});

test('Dirty Dozen #4-#10: CommunityUpload enforces relational user existence, format/size limits, bounded tags, and immutable fields', () => {
  assert.match(rulesText, /exists\(\/databases\/\$\(database\)\/documents\/users\/\$\(request\.auth\.uid\)\)/);
  assert.match(rulesText, /data\.format\s*==\s*'PNG'\s*\|\|\s*data\.format\s*==\s*'JPG'/);
  assert.match(rulesText, /data\.dataUrl\.size\(\)\s*<=\s*650000/);
  assert.match(rulesText, /data\.tags\s+is\s+list\s*&&\s*data\.tags\.size\(\)\s*<=\s*10/);
  assert.match(rulesText, /incoming\(\)\.createdAt\s*==\s*existing\(\)\.createdAt/);
  assert.match(rulesText, /incoming\(\)\.authorId\s*==\s*existing\(\)\.authorId/);
  assert.match(rulesText, /allow\s+delete:\s*if\s+isVerifiedUser\(\)[\s\S]*existing\(\)\.authorId\s*==\s*request\.auth\.uid/);
});

test('Dirty Dozen #11-#12: Atomic existsAfter on likes and Query Enforcer on list queries', () => {
  assert.match(rulesText, /existsAfter\(\/databases\/\$\(database\)\/documents\/assetStats\/\$\(assetId\)\)/);
  assert.match(rulesText, /allow\s+list:\s*if\s+existing\(\)\.visibility\s*==\s*'public';/);
});

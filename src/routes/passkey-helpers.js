/**
 * passkey-helpers — Re-exports parseDevice for backward compatibility.
 *
 * The parseDevice logic has been moved to SessionManager to avoid duplication.
 * This module re-exports it so existing consumers (tests) don't need changes.
 * New code should import directly from SessionManager.
 */
const { parseDevice } = require('../auth/SessionManager');
module.exports = { parseDevice };

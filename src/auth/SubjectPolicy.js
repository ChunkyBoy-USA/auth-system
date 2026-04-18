/**
 * SubjectPolicy — Strategy/Policy pattern for subject types.
 *
 * Each subject type (Member, CommunityStaff, PlatformStaff) has its own
 * policy class encapsulating its permissions and behavior. Adding a new
 * subject type means adding a new class here, not scattering if/else
 * checks throughout the codebase (Open/Closed Principle).
 *
 * Also used to derive display labels, authorization decisions, and
 * any future per-subject-type behavior.
 */

const { getSubjectById } = require('../db/models');

/**
 * Base policy class. Subclasses override specific permissions.
 * Unknown subject types fall back to a read-only default policy.
 */
class BaseSubjectPolicy {
  /**
   * @param {string} type - The subject type string (e.g. 'member')
   * @param {string} label - Human-readable display name
   */
  constructor(type, label) {
    this.type = type;
    this.label = label;
  }

  /** Whether this subject can view admin-level resources. */
  canViewAdmin() {
    return false;
  }

  /** Whether this subject can manage other users. */
  canManageUsers() {
    return false;
  }

  /** Whether this subject can access platform-wide analytics. */
  canViewAnalytics() {
    return false;
  }

  /** Permissions list for API responses / UI menus. */
  getPermissions() {
    return [];
  }
}

// ─── Concrete policies ─────────────────────────────────────────────────────────

class MemberPolicy extends BaseSubjectPolicy {
  constructor() {
    super('member', 'Member');
  }

  getPermissions() {
    return ['profile:read', 'profile:write', 'sessions:read', 'sessions:delete'];
  }
}

class CommunityStaffPolicy extends BaseSubjectPolicy {
  constructor() {
    super('community_staff', 'Community Staff');
  }

  canViewAdmin() {
    return true;
  }

  getPermissions() {
    return [
      'profile:read', 'profile:write',
      'sessions:read', 'sessions:delete',
      'community:moderate',
    ];
  }
}

class PlatformStaffPolicy extends BaseSubjectPolicy {
  constructor() {
    super('platform_staff', 'Platform Staff');
  }

  canViewAdmin() {
    return true;
  }

  canManageUsers() {
    return true;
  }

  canViewAnalytics() {
    return true;
  }

  getPermissions() {
    return [
      'profile:read', 'profile:write',
      'sessions:read', 'sessions:delete',
      'community:moderate',
      'platform:admin',
      'analytics:read',
    ];
  }
}

// ─── Registry ────────────────────────────────────────────────────────────────

const POLICY_MAP = {
  member: MemberPolicy,
  community_staff: CommunityStaffPolicy,
  platform_staff: PlatformStaffPolicy,
};

/**
 * Resolve the policy for a given subject type string.
 * Falls back to a read-only BaseSubjectPolicy for unknown types.
 *
 * @param {string} type
 * @returns {BaseSubjectPolicy}
 */
function resolvePolicy(type) {
  const PolicyClass = POLICY_MAP[type] || BaseSubjectPolicy;
  return new PolicyClass(type, type);
}

/**
 * Build a policy from a user object (looks up subject type from DB).
 *
 * @param {object} user - User row from the database
 * @returns {BaseSubjectPolicy}
 */
function policyForUser(user) {
  const subject = getSubjectById(user.subject_id);
  return resolvePolicy(subject?.type || 'member');
}

module.exports = {
  BaseSubjectPolicy,
  MemberPolicy,
  CommunityStaffPolicy,
  PlatformStaffPolicy,
  resolvePolicy,
  policyForUser,
};

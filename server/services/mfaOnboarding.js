const db = require('../db');
const passkeyService = require('./passkeyService');
const totpService = require('./totpService');
const twoFactorAuth = require('./twoFactorAuth');

/** At least one second-factor method can be added on this server. */
function canAddSecondFactor() {
    return totpService.isAvailable() || passkeyService.isAvailable();
}

/**
 * Report whether the account should be offered MFA enrollment after signing
 * in. Only local accounts created with the onboarding marker qualify, and the
 * offer is withheld while the account already has a second factor (an
 * authenticator app or a passkey) or no method can be added.
 */
function isPending(user) {
    return Boolean(
        user?.mfaOnboardingPending === true
        && user.passwordHash
        && !user.oidcId
        && !twoFactorAuth.hasSecondFactor(user)
        && canAddSecondFactor()
    );
}

/**
 * Public account details for the signed-in user only. Administrator user
 * listings keep using db.users.toPublic so they never include this state.
 */
function toOwnAccount(user) {
    const account = db.users.toPublic(user);
    if (!account) return account;
    return { ...account, mfaOnboardingPending: isPending(user) };
}

module.exports = { isPending, toOwnAccount };

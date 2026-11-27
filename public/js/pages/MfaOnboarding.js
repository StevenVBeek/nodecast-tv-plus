class MfaOnboardingPage {
    constructor(app) {
        this.app = app;
        this.page = document.getElementById('page-mfa-onboarding');
        this.dialog = document.getElementById('mfa-onboarding-skip-dialog');

        document.getElementById('mfa-onboarding-continue')?.addEventListener('click', () => this.continueToEnrollment());
        document.getElementById('mfa-onboarding-skip')?.addEventListener('click', () => this.openSkipDialog());
        document.getElementById('mfa-onboarding-skip-back')?.addEventListener('click', () => this.closeSkipDialog());
        document.getElementById('mfa-onboarding-skip-confirm')?.addEventListener('click', () => this.finishSkip());
        this.dialog?.addEventListener('click', event => {
            if (event.target === this.dialog) this.closeSkipDialog();
        });
        document.addEventListener('keydown', event => {
            if (event.key === 'Escape' && !this.dialog?.classList.contains('hidden')) this.closeSkipDialog();
        });
    }

    show() {
        document.body.classList.add('mfa-onboarding-active');
        document.getElementById('mfa-onboarding-heading')?.focus({ preventScroll: true });
    }

    hide() {
        document.body.classList.remove('mfa-onboarding-active');
        this.closeSkipDialog(false);
    }

    async recordChoice() {
        NodeCastOnboarding.completeMfaPrompt();
        const user = this.app.currentUser;
        if (user?.mfaOnboardingPending !== true) return;
        user.mfaOnboardingPending = false;
        try {
            await API.account.completeMfaOnboarding();
        } catch (err) {
            // The prompt may return on a later visit, but saving the choice
            // must never keep the account out of the application.
            console.warn('[Onboarding] Unable to save the MFA prompt choice:', err.message);
        }
    }

    async continueToEnrollment() {
        if (this.recording) return;
        this.recording = true;
        try {
            await this.recordChoice();
        } finally {
            this.recording = false;
        }
        this.app.pages.account.requestMethodChoiceOnNextShow();
        this.app.navigateTo('account', true);
    }

    openSkipDialog() {
        if (!this.dialog) return;
        this.dialog.classList.remove('hidden');
        document.getElementById('mfa-onboarding-skip-confirm')?.focus();
    }

    closeSkipDialog(restoreFocus = true) {
        if (!this.dialog) return;
        this.dialog.classList.add('hidden');
        if (restoreFocus) document.getElementById('mfa-onboarding-skip')?.focus();
    }

    async finishSkip() {
        if (this.recording) return;
        this.recording = true;
        try {
            await this.recordChoice();
        } finally {
            this.recording = false;
        }
        this.closeSkipDialog(false);
        this.app.navigateTo('home', true);
    }
}

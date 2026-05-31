package com.reimagineafrica.auth.enums;

/**
 * All SACCOS platform roles.
 *
 * These are embedded in every JWT as the `roles` claim.
 * Every downstream service reads this claim to enforce @PreAuthorize rules.
 */
public enum Role {

    // Member self-service — apply for loans, view statements, consent as guarantor
    MEMBER,

    // Reviews and approves/rejects loan applications at officer level
    LOAN_OFFICER,

    // Votes on loan applications in committee review
    COMMITTEE_MEMBER,

    // Final loan approval sign-off
    CHAIRPERSON,

    // Manages dividends, reconciliation, financial reports
    TREASURER,

    // Votes on dividend declarations and governance matters
    BOARD_MEMBER,

    // Operational oversight — dashboards, reports, no transaction authority
    MANAGER,

    // Read-only access to all financial data for compliance
    AUDITOR,

    // Full platform access — user management, SACCO config
    ADMIN,

    // Service-to-service calls — internal microservices use this account
    SYSTEM
}

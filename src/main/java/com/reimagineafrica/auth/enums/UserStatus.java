package com.reimagineafrica.auth.enums;

public enum UserStatus {
    ACTIVE,
    INACTIVE,
    SUSPENDED,      // Admin suspended — cannot login
    LOCKED,         // Auto-locked after too many failed attempts
    PENDING_SETUP   // Created but password not yet set
}

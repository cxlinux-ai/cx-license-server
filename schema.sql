-- CX License Server Database Schema
-- Cloudflare D1 (SQLite)

CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT UNIQUE NOT NULL,
    tier TEXT NOT NULL DEFAULT 'core_plus',
    customer_id TEXT,
    customer_email TEXT,
    organization TEXT,
    systems_allowed INTEGER DEFAULT 2,
    issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    active INTEGER DEFAULT 1,
    stripe_subscription_id TEXT,
    stripe_customer_id TEXT,
    referral_code TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS activations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id INTEGER NOT NULL,
    hardware_id TEXT NOT NULL,
    device_name TEXT,
    platform TEXT,
    hostname TEXT,
    active INTEGER DEFAULT 1,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (license_id) REFERENCES licenses(id),
    UNIQUE(license_id, hardware_id)
);

CREATE TABLE IF NOT EXISTS validation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT,
    hardware_id TEXT,
    action TEXT NOT NULL,
    success INTEGER NOT NULL,
    error_message TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Referral System Tables

CREATE TABLE IF NOT EXISTS referrers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    referral_code TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    name TEXT,
    payout_email TEXT,
    payout_method TEXT DEFAULT 'paypal',
    commission_rate REAL DEFAULT 0.10,
    total_earned REAL DEFAULT 0,
    total_paid REAL DEFAULT 0,
    active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS referrals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    referrer_id INTEGER NOT NULL,
    license_id INTEGER NOT NULL,
    amount_paid REAL NOT NULL,
    commission REAL NOT NULL,
    paid INTEGER DEFAULT 0,
    paid_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (referrer_id) REFERENCES referrers(id),
    FOREIGN KEY (license_id) REFERENCES licenses(id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key);
CREATE INDEX IF NOT EXISTS idx_licenses_customer ON licenses(customer_id);
CREATE INDEX IF NOT EXISTS idx_licenses_referral ON licenses(referral_code);
CREATE INDEX IF NOT EXISTS idx_activations_license ON activations(license_id);
CREATE INDEX IF NOT EXISTS idx_activations_hardware ON activations(hardware_id);
CREATE INDEX IF NOT EXISTS idx_validation_log_key ON validation_log(license_key);
CREATE INDEX IF NOT EXISTS idx_referrers_code ON referrers(referral_code);
CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals(referrer_id);

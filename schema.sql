-- CX Linux License Server Database Schema
-- D1 SQLite

-- Licenses table
CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT UNIQUE NOT NULL,
    tier TEXT NOT NULL DEFAULT 'core',
    customer_id TEXT NOT NULL,
    customer_email TEXT,
    organization TEXT,
    systems_allowed INTEGER DEFAULT 2,
    active INTEGER DEFAULT 1,
    expires_at TEXT NOT NULL,
    stripe_subscription_id TEXT,
    stripe_customer_id TEXT,
    referral_code TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Device activations
CREATE TABLE IF NOT EXISTS activations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id INTEGER NOT NULL,
    hardware_id TEXT NOT NULL,
    device_name TEXT,
    platform TEXT,
    hostname TEXT,
    active INTEGER DEFAULT 1,
    first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
    last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (license_id) REFERENCES licenses(id),
    UNIQUE(license_id, hardware_id)
);

-- Validation logs
CREATE TABLE IF NOT EXISTS validation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT,
    hardware_id TEXT,
    action TEXT NOT NULL,
    success INTEGER NOT NULL,
    error_message TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Referrers (affiliates)
CREATE TABLE IF NOT EXISTS referrers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    referral_code TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    payout_email TEXT,
    payout_method TEXT DEFAULT 'paypal',
    total_earned REAL DEFAULT 0,
    total_paid REAL DEFAULT 0,
    active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Referral transactions
CREATE TABLE IF NOT EXISTS referrals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    referrer_id INTEGER NOT NULL,
    license_id INTEGER NOT NULL,
    amount_paid REAL NOT NULL,
    commission REAL NOT NULL,
    paid INTEGER DEFAULT 0,
    paid_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (referrer_id) REFERENCES referrers(id),
    FOREIGN KEY (license_id) REFERENCES licenses(id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key);
CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(customer_email);
CREATE INDEX IF NOT EXISTS idx_licenses_subscription ON licenses(stripe_subscription_id);
CREATE INDEX IF NOT EXISTS idx_activations_license ON activations(license_id);
CREATE INDEX IF NOT EXISTS idx_activations_hardware ON activations(hardware_id);
CREATE INDEX IF NOT EXISTS idx_referrers_code ON referrers(referral_code);
CREATE INDEX IF NOT EXISTS idx_referrers_email ON referrers(email);
CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals(referrer_id);
CREATE INDEX IF NOT EXISTS idx_referrals_unpaid ON referrals(paid) WHERE paid = 0;

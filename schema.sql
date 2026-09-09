CREATE DATABASE IF NOT EXISTS week02_board
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE week02_board;

CREATE TABLE IF NOT EXISTS fraud_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    message TEXT NOT NULL,
    scam_type VARCHAR(50) NOT NULL,
    risk_score INT NOT NULL DEFAULT 0,
    risk_level VARCHAR(20) NOT NULL,
    detected_keywords VARCHAR(500),
    memo TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
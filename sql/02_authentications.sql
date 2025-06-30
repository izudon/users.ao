CREATE TABLE authentications (
    id BINARY(16) NOT NULL PRIMARY KEY,
    registration_id VARCHAR(8) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    user_id VARCHAR(6) DEFAULT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_authentications_registration_id_subject UNIQUE (registration_id, subject),
    CONSTRAINT fk_authentications_user_id FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT ck_authentications_user_id CHECK (user_id  REGEXP '^[0-9]{6}$')
);

-- coding: latin-1
-- ###############################################################################
-- Copyright (c) 2023 European Commission
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--    http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- ###############################################################################
--
-- TS5/TS6 migration: Wallet Relying Party -> Wallet Relying Party + Wallet Relying Party Service
--
-- Upgrades a database created with the pre-TS5/TS6 relying_party_reg.sql to the TS5/TS6 schema.
-- New databases do not need it: relying_party_reg.sql already creates the TS5/TS6 schema.
--
-- Usage (MariaDB only; uses MariaDB IF [NOT] EXISTS clauses and RENAME INDEX):
--     mariadb -u <user> -p <database> < app/migrations/ts5_ts6_migration.sql
--
-- What it does:
--   1. Creates wallet_relying_party_service.
--   2. Every existing Wallet Relying Party gets ONE service with the SAME id, so every child row keeps
--      its value (only the column is renamed). Mapping:
--          id                       = wallet_relying_party.id
--          wallet_relying_party_id  = wallet_relying_party.id
--          service_trade_name       = trade_name, or CONCAT('WRP ', id) when trade_name is NULL
--          service_identifier       = CONCAT('wrp-', id)
--          email / phone            = first email / phone of the provider's legal entity, or ''
--          is_intermediary          = wallet_relying_party.is_intermediary
--          user_id                  = wallet_relying_party.user_id
--      This data copy runs in a single transaction.
--   3. Child tables (wrp_entitlement, wrp_intended_use, wrp_intermediary, wrp_provided_attestation,
--      wrp_srv_description, wrp_support_uri): wrp_id -> wrp_service_id, with the foreign key moved to
--      wallet_relying_party_service. wrp_intermediary.intermediary_wrp_id now references the service.
--      Existing foreign keys are looked up in information_schema (their names are not assumed).
--   4. Creates wrp_sub_entitlement and wrp_servedwrpservices.
--   5. Drops wallet_relying_party.is_intermediary (only after every WRP has its service).
--   6. Lists the services whose values were generated or left empty, for manual correction.
--
-- Transactions / re-runs:
--   MariaDB commits implicitly on every DDL statement, so the migration as a whole cannot be one
--   transaction. Instead every step is idempotent and checks the current state before acting:
--   if the script stops half-way, run it again and it continues where it stopped. Running it on an
--   already migrated database changes nothing and only prints the review list again.
--   access_certificate.wrp_id still references wallet_relying_party and is not changed.

DELIMITER $$

DROP PROCEDURE IF EXISTS ts5_ts6_drop_fks $$
-- Drops every foreign key of p_table(p_column) that references p_ref_table.
CREATE PROCEDURE ts5_ts6_drop_fks(IN p_table VARCHAR(64), IN p_column VARCHAR(64), IN p_ref_table VARCHAR(64))
BEGIN
    DECLARE fk_name VARCHAR(64);

    fk_loop: LOOP
        SET fk_name = (
            SELECT CONSTRAINT_NAME
            FROM information_schema.KEY_COLUMN_USAGE
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = p_table
              AND COLUMN_NAME = p_column
              AND REFERENCED_TABLE_NAME = p_ref_table
            LIMIT 1
        );

        IF fk_name IS NULL THEN
            LEAVE fk_loop;
        END IF;

        SET @ts5_ts6_sql = CONCAT('ALTER TABLE `', p_table, '` DROP FOREIGN KEY `', fk_name, '`');
        PREPARE stmt FROM @ts5_ts6_sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END LOOP;
END $$

DROP PROCEDURE IF EXISTS ts5_ts6_relink $$
-- Moves p_table.p_old_column (-> wallet_relying_party.id) to p_table.p_new_column (-> wallet_relying_party_service.id).
-- p_old_column = p_new_column only moves the foreign key (wrp_intermediary.intermediary_wrp_id).
CREATE PROCEDURE ts5_ts6_relink(IN p_table VARCHAR(64), IN p_old_column VARCHAR(64), IN p_new_column VARCHAR(64),
                                IN p_fk_name VARCHAR(64))
BEGIN
    -- 1. drop the foreign keys to wallet_relying_party (old and, after a partial run, new column)
    CALL ts5_ts6_drop_fks(p_table, p_old_column, 'wallet_relying_party');
    CALL ts5_ts6_drop_fks(p_table, p_new_column, 'wallet_relying_party');

    -- 2. rename the column (values are kept: service id = WRP id)
    IF p_old_column <> p_new_column AND EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = p_table AND COLUMN_NAME = p_old_column
    ) THEN
        SET @ts5_ts6_sql = CONCAT('ALTER TABLE `', p_table, '` CHANGE COLUMN `', p_old_column, '` `',
                                  p_new_column, '` int(11) NOT NULL');
        PREPARE stmt FROM @ts5_ts6_sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;

    -- 3. rename the index named after the old column (same names as relying_party_reg.sql)
    IF p_old_column <> p_new_column
       AND EXISTS (SELECT 1 FROM information_schema.STATISTICS
                   WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = p_table AND INDEX_NAME = p_old_column)
       AND NOT EXISTS (SELECT 1 FROM information_schema.STATISTICS
                       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = p_table AND INDEX_NAME = p_new_column)
    THEN
        SET @ts5_ts6_sql = CONCAT('ALTER TABLE `', p_table, '` RENAME INDEX `', p_old_column, '` TO `', p_new_column, '`');
        PREPARE stmt FROM @ts5_ts6_sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;

    -- 4. add the foreign key to wallet_relying_party_service
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.KEY_COLUMN_USAGE
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = p_table AND COLUMN_NAME = p_new_column
          AND REFERENCED_TABLE_NAME = 'wallet_relying_party_service'
    ) THEN
        SET @ts5_ts6_sql = CONCAT('ALTER TABLE `', p_table, '` ADD CONSTRAINT `', p_fk_name, '` FOREIGN KEY (`',
                                  p_new_column, '`) REFERENCES `wallet_relying_party_service` (`id`)');
        PREPARE stmt FROM @ts5_ts6_sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END $$

DROP PROCEDURE IF EXISTS ts5_ts6_copy_services $$
-- One service per Wallet Relying Party, same id. Runs only while wallet_relying_party.is_intermediary
-- still exists (i.e. until the migration has finished).
CREATE PROCEDURE ts5_ts6_copy_services()
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    IF EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'wallet_relying_party' AND COLUMN_NAME = 'is_intermediary'
    ) THEN
        -- a service that already uses a WRP id must belong to that WRP, otherwise the mapping is ambiguous
        IF EXISTS (
            SELECT 1
            FROM wallet_relying_party wrp
            JOIN wallet_relying_party_service s ON s.id = wrp.id
            WHERE NOT (s.wallet_relying_party_id <=> wrp.id)
        ) THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'ts5_ts6_migration: wallet_relying_party_service already has rows whose id matches a different Wallet Relying Party. Aborting.';
        END IF;

        START TRANSACTION;

        INSERT INTO wallet_relying_party_service
            (id, wallet_relying_party_id, service_trade_name, service_identifier, email, phone, is_intermediary, user_id)
        SELECT
            wrp.id,
            wrp.id,
            COALESCE(wrp.trade_name, CONCAT('WRP ', wrp.id)),
            CONCAT('wrp-', wrp.id),
            COALESCE((
                SELECT lee.email
                FROM provider p
                JOIN legal_entity_email lee ON lee.legal_entity_id = p.legal_entity_id
                WHERE p.id = wrp.provider_id
                ORDER BY lee.id
                LIMIT 1
            ), ''),
            COALESCE((
                SELECT lep.phone
                FROM provider p
                JOIN legal_entity_phone lep ON lep.legal_entity_id = p.legal_entity_id
                WHERE p.id = wrp.provider_id
                ORDER BY lep.id
                LIMIT 1
            ), ''),
            wrp.is_intermediary,
            wrp.user_id
        FROM wallet_relying_party wrp
        WHERE NOT EXISTS (SELECT 1 FROM wallet_relying_party_service s WHERE s.id = wrp.id);

        COMMIT;
    END IF;
END $$

DROP PROCEDURE IF EXISTS ts5_ts6_finish $$
-- Drops wallet_relying_party.is_intermediary once every WRP has its service.
CREATE PROCEDURE ts5_ts6_finish()
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'wallet_relying_party' AND COLUMN_NAME = 'is_intermediary'
    ) THEN
        IF EXISTS (
            SELECT 1 FROM wallet_relying_party wrp
            WHERE NOT EXISTS (SELECT 1 FROM wallet_relying_party_service s WHERE s.id = wrp.id)
        ) THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'ts5_ts6_migration: some Wallet Relying Parties have no service; is_intermediary was not dropped.';
        END IF;

        ALTER TABLE `wallet_relying_party` DROP COLUMN `is_intermediary`;
    END IF;
END $$

DELIMITER ;

-- 1. Wallet Relying Party Service ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `wallet_relying_party_service` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `wallet_relying_party_id` int(11) DEFAULT NULL,
  `service_trade_name` varchar(255) NOT NULL,
  `service_identifier` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `phone` varchar(255) NOT NULL,
  `is_intermediary` tinyint(1) NOT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `wallet_relying_party_id` (`wallet_relying_party_id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `wallet_relying_party_service_ibfk_1` FOREIGN KEY (`wallet_relying_party_id`) REFERENCES `wallet_relying_party` (`id`),
  CONSTRAINT `wallet_relying_party_service_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `user` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 2. One service per Wallet Relying Party (single transaction) -----------------------------------
CALL ts5_ts6_copy_services();

-- 3. Child tables: wrp_id -> wrp_service_id ---------------------------------------------------
CALL ts5_ts6_relink('wrp_entitlement',          'wrp_id', 'wrp_service_id', 'wrp_entitlement_ibfk_1');
CALL ts5_ts6_relink('wrp_intended_use',         'wrp_id', 'wrp_service_id', 'wrp_intended_use_ibfk_1');
CALL ts5_ts6_relink('wrp_intermediary',         'wrp_id', 'wrp_service_id', 'wrp_intermediary_ibfk_1');
CALL ts5_ts6_relink('wrp_intermediary',         'intermediary_wrp_id', 'intermediary_wrp_id', 'wrp_intermediary_ibfk_2');
CALL ts5_ts6_relink('wrp_provided_attestation', 'wrp_id', 'wrp_service_id', 'wrp_provided_attestation_ibfk_1');
CALL ts5_ts6_relink('wrp_srv_description',      'wrp_id', 'wrp_service_id', 'wrp_srv_description_ibfk_1');
CALL ts5_ts6_relink('wrp_support_uri',          'wrp_id', 'wrp_service_id', 'wrp_support_uri_ibfk_1');

-- 4. New TS5/TS6 tables ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `wrp_sub_entitlement` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `wrp_service_id` int(11) NOT NULL,
  `sub_entitlement` text NOT NULL,
  PRIMARY KEY (`id`),
  KEY `wrp_service_id` (`wrp_service_id`),
  CONSTRAINT `wrp_sub_entitlement_ibfk_1` FOREIGN KEY (`wrp_service_id`) REFERENCES `wallet_relying_party_service` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `wrp_servedwrpservices` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `wrp_service_id` int(11) NOT NULL,
  `servedWRPServices` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `wrp_service_id` (`wrp_service_id`),
  KEY `servedWRPServices` (`servedWRPServices`),
  CONSTRAINT `wrp_servedwrpservices_ibfk_1` FOREIGN KEY (`wrp_service_id`) REFERENCES `wallet_relying_party_service` (`id`),
  CONSTRAINT `wrp_servedwrpservices_ibfk_2` FOREIGN KEY (`servedWRPServices`) REFERENCES `wallet_relying_party_service` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 5. is_intermediary now lives in the service ----------------------------------------------------
CALL ts5_ts6_finish();

DROP PROCEDURE IF EXISTS ts5_ts6_drop_fks;
DROP PROCEDURE IF EXISTS ts5_ts6_relink;
DROP PROCEDURE IF EXISTS ts5_ts6_copy_services;
DROP PROCEDURE IF EXISTS ts5_ts6_finish;

-- 6. Services with generated or empty values (review and correct manually) -----------------------
SELECT
    s.id                       AS wrp_service_id,
    s.wallet_relying_party_id,
    s.service_trade_name,
    s.service_identifier,
    s.email,
    s.phone,
    CONCAT_WS(', ',
        IF(wrp.trade_name IS NULL AND s.service_trade_name = CONCAT('WRP ', s.id), 'service_trade_name generated', NULL),
        IF(s.service_identifier = CONCAT('wrp-', s.id), 'service_identifier generated', NULL),
        IF(s.email = '', 'email empty', NULL),
        IF(s.phone = '', 'phone empty', NULL)
    ) AS needs_review
FROM wallet_relying_party_service s
LEFT JOIN wallet_relying_party wrp ON wrp.id = s.wallet_relying_party_id
WHERE (wrp.trade_name IS NULL AND s.service_trade_name = CONCAT('WRP ', s.id))
   OR s.service_identifier = CONCAT('wrp-', s.id)
   OR s.email = ''
   OR s.phone = ''
ORDER BY s.id;

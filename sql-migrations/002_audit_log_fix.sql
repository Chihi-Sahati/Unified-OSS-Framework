-- ============================================================================
-- Migration: 002_audit_log_fix.sql
-- Description: Fix audit_log table for tamper-evident hash chaining
-- 
-- This migration addresses the mismatch between the AuditLogger class
-- expectations and the database schema. The original schema had only
-- 'integrity_hash' column, but AuditLogger expects 'previous_hash' and
-- 'current_hash' columns for proper hash chain implementation.
--
-- Version: 1.0.0
-- Date: 2024-03-15
-- Author: Unified OSS Framework Consortium
-- ============================================================================

-- ============================================================================
-- STEP 1: Add new columns for tamper-evident hash chaining
-- ============================================================================

-- Add previous_hash column if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'audit_log' 
        AND column_name = 'previous_hash'
    ) THEN
        ALTER TABLE audit_log ADD COLUMN previous_hash VARCHAR(64);
        RAISE NOTICE 'Added previous_hash column to audit_log table';
    ELSE
        RAISE NOTICE 'previous_hash column already exists in audit_log table';
    END IF;
END $$;

-- Add current_hash column if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'audit_log' 
        AND column_name = 'current_hash'
    ) THEN
        ALTER TABLE audit_log ADD COLUMN current_hash VARCHAR(64);
        RAISE NOTICE 'Added current_hash column to audit_log table';
    ELSE
        RAISE NOTICE 'current_hash column already exists in audit_log table';
    END IF;
END $$;

-- Add chain_validated column if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'audit_log' 
        AND column_name = 'chain_validated'
    ) THEN
        ALTER TABLE audit_log ADD COLUMN chain_validated BOOLEAN DEFAULT FALSE;
        RAISE NOTICE 'Added chain_validated column to audit_log table';
    ELSE
        RAISE NOTICE 'chain_validated column already exists in audit_log table';
    END IF;
END $$;

-- ============================================================================
-- STEP 2: Migrate existing data
-- ============================================================================

-- For existing rows, set previous_hash to NULL (they are the genesis entries
-- or cannot be linked to previous entries). Mark them as not validated.
-- If there was an old integrity_hash column, we can optionally preserve it.

DO $$
BEGIN
    -- Update existing rows to have chain_validated = FALSE if not already set
    UPDATE audit_log 
    SET chain_validated = FALSE 
    WHERE chain_validated IS NULL;
    
    -- Set previous_hash to NULL for existing rows (genesis entries)
    UPDATE audit_log 
    SET previous_hash = NULL 
    WHERE previous_hash IS NULL;
    
    RAISE NOTICE 'Migrated existing audit_log data for hash chaining';
END $$;

-- ============================================================================
-- STEP 3: Remove old integrity_hash column if it exists
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'audit_log' 
        AND column_name = 'integrity_hash'
    ) THEN
        -- Optionally backup integrity_hash data before dropping
        -- For now, we'll just drop it since the new columns replace it
        ALTER TABLE audit_log DROP COLUMN integrity_hash;
        RAISE NOTICE 'Removed obsolete integrity_hash column from audit_log table';
    ELSE
        RAISE NOTICE 'integrity_hash column does not exist, no action needed';
    END IF;
END $$;

-- ============================================================================
-- STEP 4: Create indexes for hash lookups and validation
-- ============================================================================

-- Create index for previous_hash lookups (for chain traversal)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE tablename = 'audit_log' 
        AND indexname = 'idx_audit_previous_hash'
    ) THEN
        CREATE INDEX idx_audit_previous_hash ON audit_log(previous_hash) 
        WHERE previous_hash IS NOT NULL;
        RAISE NOTICE 'Created idx_audit_previous_hash index';
    ELSE
        RAISE NOTICE 'idx_audit_previous_hash index already exists';
    END IF;
END $$;

-- Create index for current_hash lookups (for integrity verification)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE tablename = 'audit_log' 
        AND indexname = 'idx_audit_current_hash'
    ) THEN
        CREATE INDEX idx_audit_current_hash ON audit_log(current_hash) 
        WHERE current_hash IS NOT NULL;
        RAISE NOTICE 'Created idx_audit_current_hash index';
    ELSE
        RAISE NOTICE 'idx_audit_current_hash index already exists';
    END IF;
END $$;

-- Create index for chain validation queries
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE tablename = 'audit_log' 
        AND indexname = 'idx_audit_chain_validated'
    ) THEN
        CREATE INDEX idx_audit_chain_validated ON audit_log(chain_validated) 
        WHERE chain_validated = FALSE;
        RAISE NOTICE 'Created idx_audit_chain_validated index';
    ELSE
        RAISE NOTICE 'idx_audit_chain_validated index already exists';
    END IF;
END $$;

-- ============================================================================
-- STEP 5: Add comments for documentation
-- ============================================================================

COMMENT ON COLUMN audit_log.previous_hash IS 'SHA-256 hash of the previous audit entry in the chain. NULL for the first entry or legacy entries.';
COMMENT ON COLUMN audit_log.current_hash IS 'SHA-256 hash of this audit entry, computed from timestamp, action, entity data, and previous_hash for tamper detection.';
COMMENT ON COLUMN audit_log.chain_validated IS 'Indicates whether this entry has been validated as part of the hash chain integrity check. FALSE indicates pending validation.';

-- ============================================================================
-- STEP 6: Verify migration
-- ============================================================================

DO $$
DECLARE
    col_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO col_count
    FROM information_schema.columns 
    WHERE table_name = 'audit_log' 
    AND column_name IN ('previous_hash', 'current_hash', 'chain_validated');
    
    IF col_count = 3 THEN
        RAISE NOTICE 'Migration completed successfully: All 3 new columns exist in audit_log table';
    ELSE
        RAISE WARNING 'Migration may be incomplete: Expected 3 columns, found %', col_count;
    END IF;
END $$;

-- ============================================================================
-- MIGRATION COMPLETE
-- ============================================================================

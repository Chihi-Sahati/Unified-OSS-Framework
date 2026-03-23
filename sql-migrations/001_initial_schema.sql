-- ============================================================================
-- PostgreSQL/TimescaleDB Schema for Unified OSS Framework
-- YANG Integration & FCAPS Management
-- 
-- Version: 1.0.0
-- Date: 2024-03-01
-- Author: Unified OSS Framework Consortium
-- 
-- This migration script creates the complete database schema for:
-- - YANG model instance storage
-- - FCAPS Fault Management (alarms)
-- - FCAPS Configuration Management
-- - FCAPS Performance Management (metrics with TimescaleDB)
-- - FCAPS Security Management (audit, threats)
-- - FCAPS Accounting Management
-- ============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "timescaledb" CASCADE;

-- ============================================================================
-- ENUM TYPE DEFINITIONS
-- ============================================================================

-- Vendor enumeration
CREATE TYPE vendor_type AS ENUM ('ERICSSON', 'HUAWEI', 'CALCULATED', 'UNKNOWN');

-- Alarm severity enumeration
CREATE TYPE alarm_severity_type AS ENUM (
    'INDETERMINATE', 'CRITICAL', 'MAJOR', 'MINOR', 'WARNING'
);

-- Alarm state enumeration
CREATE TYPE alarm_state_type AS ENUM (
    'ACTIVE', 'ACKNOWLEDGED', 'CLEARED', 'RESOLVING'
);

-- Alarm probable cause enumeration
CREATE TYPE alarm_probable_cause_type AS ENUM (
    'UNKNOWN', 'HARDWARE_FAILURE', 'SOFTWARE_ERROR', 'NETWORK_FAILURE',
    'CONFIGURATION_ERROR', 'PERFORMANCE_DEGRADATION', 'ENVIRONMENTAL_ISSUE',
    'SECURITY_INCIDENT', 'RESOURCE_EXHAUSTION', 'COMMUNICATION_FAILURE'
);

-- Configuration status enumeration
CREATE TYPE config_status_type AS ENUM (
    'DRAFT', 'PENDING_APPROVAL', 'APPROVED', 'STAGED', 'DEPLOYED', 
    'FAILED', 'ROLLED_BACK'
);

-- Metric aggregation type enumeration
CREATE TYPE metric_aggregation_type AS ENUM (
    'COUNTER', 'GAUGE', 'HISTOGRAM', 'RATE'
);

-- Quality indicator enumeration
CREATE TYPE quality_indicator_type AS ENUM (
    'GOOD', 'DEGRADED', 'UNAVAILABLE', 'SUSPECT'
);

-- Threshold status enumeration
CREATE TYPE threshold_status_type AS ENUM (
    'NORMAL', 'WARNING', 'CRITICAL'
);

-- Security event type enumeration
CREATE TYPE security_event_type AS ENUM (
    'USER_LOGIN', 'USER_LOGOUT', 'CONFIGURATION_CHANGE', 'ALARM_MANAGEMENT',
    'POLICY_MODIFICATION', 'SECURITY_INCIDENT', 'ACCOUNT_MODIFICATION',
    'PERMISSION_CHANGE', 'DATA_ACCESS', 'API_CALL', 'EXPORT_OPERATION'
);

-- Action status enumeration
CREATE TYPE action_status_type AS ENUM (
    'SUCCESS', 'FAILURE', 'PARTIAL', 'DENIED', 'TIMEOUT'
);

-- Threat category enumeration
CREATE TYPE threat_category_type AS ENUM (
    'BRUTE_FORCE_ATTACK', 'UNAUTHORIZED_ACCESS', 'PRIVILEGE_ESCALATION',
    'DATA_EXFILTRATION', 'MALWARE_DETECTION', 'ANOMALOUS_BEHAVIOR',
    'CONFIGURATION_TAMPERING', 'INJECTION_ATTACK', 'CROSS_SITE_SCRIPTING',
    'DENIAL_OF_SERVICE'
);

-- Threat severity enumeration
CREATE TYPE threat_severity_type AS ENUM (
    'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'
);

-- Account status enumeration
CREATE TYPE account_status_type AS ENUM (
    'ACTIVE', 'SUSPENDED', 'LOCKED', 'DISABLED', 'PENDING_ACTIVATION', 'EXPIRED'
);

-- Invoice status enumeration
CREATE TYPE invoice_status_type AS ENUM (
    'DRAFT', 'ISSUED', 'PAID', 'PARTIAL', 'OVERDUE', 'DISPUTED', 
    'CANCELLED', 'CREDITED'
);

-- ============================================================================
-- BASE YANG MODEL INSTANCES TABLE
-- ============================================================================

CREATE TABLE cim_yang_instances (
    instance_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    yang_module_name VARCHAR(255) NOT NULL,
    yang_container_path TEXT NOT NULL,
    source_vendor vendor_type NOT NULL,
    instance_data JSONB NOT NULL,
    instance_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_modified TIMESTAMP WITH TIME ZONE,
    is_valid BOOLEAN DEFAULT TRUE,
    validation_errors TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT unique_yang_instance UNIQUE (yang_container_path, source_vendor)
);

-- Indexes for YANG instances
CREATE INDEX idx_cim_instances_module ON cim_yang_instances(yang_module_name);
CREATE INDEX idx_cim_instances_vendor ON cim_yang_instances(source_vendor);
CREATE INDEX idx_cim_instances_timestamp ON cim_yang_instances(instance_timestamp DESC);
CREATE INDEX idx_cim_instances_path_gin ON cim_yang_instances USING GIN(instance_data);
CREATE INDEX idx_cim_instances_valid ON cim_yang_instances(is_valid);

COMMENT ON TABLE cim_yang_instances IS 'Base table for storing YANG model instances in normalized CIM format';

-- ============================================================================
-- FAULT MANAGEMENT TABLES (FCAPS-F)
-- ============================================================================

-- Main alarms table
CREATE TABLE alarms (
    alarm_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_vendor vendor_type NOT NULL,
    alarm_type VARCHAR(128) NOT NULL,
    alarm_severity alarm_severity_type NOT NULL,
    alarm_state alarm_state_type NOT NULL,
    probable_cause alarm_probable_cause_type,
    affected_resource TEXT NOT NULL,
    affected_resource_id VARCHAR(128),
    detection_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    acknowledgment_timestamp TIMESTAMP WITH TIME ZONE,
    clearance_timestamp TIMESTAMP WITH TIME ZONE,
    vendor_alarm_code VARCHAR(100),
    vendor_alarm_name VARCHAR(256),
    source_node_ip INET,
    source_node_name VARCHAR(128),
    
    -- Correlation data
    correlation_id UUID,
    root_cause_alarm_id UUID,
    correlation_confidence DECIMAL(4,2),
    correlated_alarm_ids UUID[] DEFAULT '{}',
    
    -- Impact assessment
    affected_services TEXT,
    customer_count INTEGER,
    estimated_revenue_impact DECIMAL(12,2),
    sla_breach_indicator BOOLEAN DEFAULT FALSE,
    
    -- Remedial actions
    suggested_actions TEXT[] DEFAULT '{}',
    executed_actions TEXT[] DEFAULT '{}',
    action_status VARCHAR(20) DEFAULT 'PENDING',
    
    -- Escalation data
    escalation_level SMALLINT DEFAULT 0,
    escalation_group VARCHAR(64),
    escalation_timestamp TIMESTAMP WITH TIME ZONE,
    escalation_ticket_id VARCHAR(64),
    
    -- Additional data
    alarm_data JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT fk_root_cause_alarm FOREIGN KEY(root_cause_alarm_id) 
        REFERENCES alarms(alarm_id) ON DELETE SET NULL
);

-- Indexes for alarms
CREATE INDEX idx_alarms_severity ON alarms(alarm_severity);
CREATE INDEX idx_alarms_state ON alarms(alarm_state);
CREATE INDEX idx_alarms_resource ON alarms(affected_resource);
CREATE INDEX idx_alarms_timestamp ON alarms(detection_timestamp DESC);
CREATE INDEX idx_alarms_vendor ON alarms(source_vendor);
CREATE INDEX idx_alarms_correlation ON alarms(correlation_id) WHERE correlation_id IS NOT NULL;
CREATE INDEX idx_alarms_gin ON alarms USING GIN(alarm_data);
CREATE INDEX idx_alarms_active ON alarms(alarm_severity, detection_timestamp DESC) 
    WHERE alarm_state IN ('ACTIVE', 'ACKNOWLEDGED');

-- Alarm audit trail table
CREATE TABLE alarm_audit_trail (
    audit_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alarm_id UUID NOT NULL REFERENCES alarms(alarm_id) ON DELETE CASCADE,
    transition_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    previous_state alarm_state_type,
    new_state alarm_state_type NOT NULL,
    changed_by VARCHAR(128) NOT NULL,
    change_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_alarm_audit_alarm ON alarm_audit_trail(alarm_id);
CREATE INDEX idx_alarm_audit_timestamp ON alarm_audit_trail(transition_timestamp DESC);

-- Alarm correlation rules table
CREATE TABLE alarm_correlation_rules (
    rule_id VARCHAR(64) PRIMARY KEY,
    description TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    priority SMALLINT DEFAULT 50,
    match_criteria JSONB NOT NULL,
    correlation_action JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE alarms IS 'FCAPS-F: Fault management alarm records with cross-vendor normalization';

-- ============================================================================
-- CONFIGURATION MANAGEMENT TABLES (FCAPS-C)
-- ============================================================================

-- Configuration profiles table
CREATE TABLE configuration_profiles (
    profile_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    profile_name VARCHAR(128) UNIQUE NOT NULL,
    description TEXT,
    profile_version VARCHAR(16) DEFAULT '1.0',
    target_vendors TEXT,
    applicable_resource_types TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    profile_type VARCHAR(32) NOT NULL,
    profile_data JSONB NOT NULL,
    vendor_mappings JSONB,
    created_by VARCHAR(128),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_modified_by VARCHAR(128),
    last_modified_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_config_profiles_type ON configuration_profiles(profile_type);
CREATE INDEX idx_config_profiles_enabled ON configuration_profiles(enabled);

-- Active configurations table
CREATE TABLE configurations (
    config_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_vendor vendor_type NOT NULL,
    target_resource TEXT NOT NULL,
    source_profile VARCHAR(128) REFERENCES configuration_profiles(profile_name),
    config_status config_status_type NOT NULL,
    config_data JSONB NOT NULL,
    config_version INTEGER DEFAULT 1,
    deployment_timestamp TIMESTAMP WITH TIME ZONE,
    deployed_by_user VARCHAR(128),
    
    -- Validation state
    is_valid BOOLEAN DEFAULT TRUE,
    validation_errors TEXT,
    validation_warnings TEXT,
    last_validation_time TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT unique_config_resource UNIQUE (target_resource, source_vendor)
);

CREATE INDEX idx_config_status ON configurations(config_status);
CREATE INDEX idx_config_resource ON configurations(target_resource);
CREATE INDEX idx_config_vendor ON configurations(source_vendor);
CREATE INDEX idx_config_timestamp ON configurations(deployment_timestamp DESC);
CREATE INDEX idx_config_data_gin ON configurations USING GIN(config_data);

-- Configuration change requests table
CREATE TABLE configuration_change_requests (
    change_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    change_title VARCHAR(256) NOT NULL,
    requester VARCHAR(128) NOT NULL,
    request_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    status config_status_type NOT NULL,
    priority VARCHAR(16) DEFAULT 'MEDIUM',
    reason TEXT NOT NULL,
    proposed_changes JSONB NOT NULL,
    impact_analysis JSONB,
    
    -- Approval chain
    approval_required BOOLEAN DEFAULT TRUE,
    current_stage SMALLINT,
    approval_chain JSONB,
    
    -- Deployment tracking
    deployment_status config_status_type,
    deployment_start_time TIMESTAMP WITH TIME ZONE,
    deployment_completion_time TIMESTAMP WITH TIME ZONE,
    deployment_errors TEXT,
    rollback_triggered BOOLEAN DEFAULT FALSE,
    rollback_reason TEXT,
    
    -- Scheduling
    scheduled_start_time TIMESTAMP WITH TIME ZONE,
    scheduled_end_time TIMESTAMP WITH TIME ZONE,
    actual_start_time TIMESTAMP WITH TIME ZONE,
    actual_end_time TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_change_request_status ON configuration_change_requests(status);
CREATE INDEX idx_change_request_requester ON configuration_change_requests(requester);
CREATE INDEX idx_change_request_timestamp ON configuration_change_requests(request_timestamp DESC);

-- Network policies table
CREATE TABLE network_policies (
    policy_id VARCHAR(64) PRIMARY KEY,
    policy_name VARCHAR(256) NOT NULL,
    policy_type VARCHAR(32) NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    applicable_vendors TEXT,
    applicable_resource_scope TEXT,
    policy_priority INTEGER DEFAULT 1000,
    effective_start_time TIMESTAMP WITH TIME ZONE,
    effective_end_time TIMESTAMP WITH TIME ZONE,
    policy_rules JSONB NOT NULL,
    
    -- Metrics
    times_applied BIGINT DEFAULT 0,
    times_triggered_exception BIGINT DEFAULT 0,
    last_applied_timestamp TIMESTAMP WITH TIME ZONE,
    compliance_rate DECIMAL(5,2),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_policies_type ON network_policies(policy_type);
CREATE INDEX idx_policies_enabled ON network_policies(enabled);

COMMENT ON TABLE configurations IS 'FCAPS-C: Configuration management with version control and audit';

-- ============================================================================
-- PERFORMANCE MANAGEMENT TABLES (FCAPS-P)
-- ============================================================================

-- Metrics table (TimescaleDB hypertable)
CREATE TABLE metrics (
    metric_id BIGSERIAL,
    metric_uuid UUID DEFAULT uuid_generate_v4(),
    metric_name VARCHAR(256) NOT NULL,
    metric_path TEXT NOT NULL,
    source_vendor vendor_type NOT NULL,
    metric_value DECIMAL(18,6) NOT NULL,
    unit_of_measurement VARCHAR(32),
    measurement_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    collection_interval_seconds INTEGER,
    aggregation_type metric_aggregation_type,
    quality_indicator quality_indicator_type DEFAULT 'GOOD',
    
    -- Vendor-specific metadata
    vendor_metric_id VARCHAR(128),
    vendor_metric_name VARCHAR(256),
    vendor_unit VARCHAR(32),
    conversion_formula TEXT,
    
    -- Threshold status
    threshold_status threshold_status_type DEFAULT 'NORMAL',
    
    -- Additional metadata
    metadata JSONB,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (metric_id, measurement_timestamp)
);

-- Convert to TimescaleDB hypertable
SELECT create_hypertable('metrics', 'measurement_timestamp', 
    if_not_exists => TRUE,
    chunk_time_interval => INTERVAL '1 day'
);

-- Compression policy for metrics (compress after 7 days)
ALTER TABLE metrics SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'metric_path, source_vendor'
);

SELECT add_compression_policy('metrics', INTERVAL '7 days', if_not_exists => TRUE);

-- Indexes for metrics
CREATE INDEX idx_metrics_path_time ON metrics(metric_path, measurement_timestamp DESC);
CREATE INDEX idx_metrics_vendor_time ON metrics(source_vendor, measurement_timestamp DESC);
CREATE INDEX idx_metrics_name_time ON metrics(metric_name, measurement_timestamp DESC);
CREATE INDEX idx_metrics_quality ON metrics(quality_indicator);
CREATE INDEX idx_metrics_threshold ON metrics(threshold_status) WHERE threshold_status != 'NORMAL';

-- KPI definitions table
CREATE TABLE kpi_definitions (
    kpi_id VARCHAR(64) PRIMARY KEY,
    kpi_name VARCHAR(256) NOT NULL,
    description TEXT,
    kpi_category VARCHAR(32) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    business_owner VARCHAR(128),
    target_value DECIMAL(12,2),
    
    -- Calculation
    source_metrics TEXT[] NOT NULL,
    calculation_formula TEXT NOT NULL,
    aggregation_method VARCHAR(32) DEFAULT 'AVG',
    aggregation_window_seconds INTEGER DEFAULT 900,
    calculation_frequency_seconds INTEGER DEFAULT 300,
    
    -- Thresholds
    warning_threshold DECIMAL(12,2),
    critical_threshold DECIMAL(12,2),
    threshold_direction VARCHAR(20) DEFAULT 'ABOVE_THRESHOLD',
    sustained_violation_window_seconds INTEGER DEFAULT 60,
    
    -- Alert policy
    alert_enabled BOOLEAN DEFAULT TRUE,
    alert_severity VARCHAR(16) DEFAULT 'MAJOR',
    notification_groups TEXT,
    auto_ticket_creation BOOLEAN DEFAULT FALSE,
    ticket_assignment_group VARCHAR(128),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_kpi_category ON kpi_definitions(kpi_category);
CREATE INDEX idx_kpi_enabled ON kpi_definitions(enabled);

-- KPI values table (TimescaleDB hypertable)
CREATE TABLE kpi_values (
    kpi_value_id BIGSERIAL,
    kpi_id VARCHAR(64) NOT NULL REFERENCES kpi_definitions(kpi_id),
    calculated_value DECIMAL(12,2) NOT NULL,
    calculation_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    threshold_status threshold_status_type DEFAULT 'NORMAL',
    previous_value DECIMAL(12,2),
    change_percent DECIMAL(6,2),
    trend_direction VARCHAR(20),
    data_quality quality_indicator_type,
    source_data JSONB,
    
    PRIMARY KEY (kpi_value_id, calculation_timestamp)
);

SELECT create_hypertable('kpi_values', 'calculation_timestamp', 
    if_not_exists => TRUE,
    chunk_time_interval => INTERVAL '1 day'
);

CREATE INDEX idx_kpi_values_kpi_time ON kpi_values(kpi_id, calculation_timestamp DESC);
CREATE INDEX idx_kpi_values_status ON kpi_values(threshold_status);

-- Performance reports table
CREATE TABLE performance_reports (
    report_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    report_name VARCHAR(256),
    report_type VARCHAR(16) NOT NULL,
    generation_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    report_period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    report_period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    generated_by VARCHAR(128),
    
    -- Report content
    kpi_summary JSONB,
    vendor_comparison JSONB,
    anomaly_detection JSONB,
    recommendations JSONB,
    
    -- Output URLs
    report_html_url TEXT,
    report_pdf_url TEXT,
    report_csv_url TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_perf_reports_type ON performance_reports(report_type);
CREATE INDEX idx_perf_reports_period ON performance_reports(report_period_start, report_period_end);

COMMENT ON TABLE metrics IS 'FCAPS-P: Performance metrics with TimescaleDB time-series optimization';

-- ============================================================================
-- SECURITY MANAGEMENT TABLES (FCAPS-S)
-- ============================================================================

-- User accounts table
CREATE TABLE user_accounts (
    user_id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(128) NOT NULL,
    email VARCHAR(256) UNIQUE NOT NULL,
    department VARCHAR(128),
    job_title VARCHAR(128),
    
    -- Authentication
    auth_method VARCHAR(32) NOT NULL,
    password_hash TEXT,
    last_password_change TIMESTAMP WITH TIME ZONE,
    password_expiry_days SMALLINT,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_method VARCHAR(16),
    certificate_fingerprint TEXT,
    
    -- Account status
    account_status account_status_type NOT NULL DEFAULT 'PENDING_ACTIVATION',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_by VARCHAR(64),
    last_login_timestamp TIMESTAMP WITH TIME ZONE,
    last_login_ip INET,
    failed_login_count SMALLINT DEFAULT 0,
    account_expiry TIMESTAMP WITH TIME ZONE,
    
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON user_accounts(email);
CREATE INDEX idx_users_status ON user_accounts(account_status);

-- Roles table
CREATE TABLE roles (
    role_name VARCHAR(64) PRIMARY KEY,
    display_name VARCHAR(128) NOT NULL,
    description TEXT,
    privilege_level SMALLINT NOT NULL,
    permissions TEXT[] DEFAULT '{}',
    inherited_roles TEXT[] DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_modified TIMESTAMP WITH TIME ZONE
);

-- User role assignments table
CREATE TABLE user_role_assignments (
    assignment_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(64) NOT NULL REFERENCES user_accounts(user_id) ON DELETE CASCADE,
    role_name VARCHAR(64) NOT NULL REFERENCES roles(role_name) ON DELETE CASCADE,
    assignment_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    assigned_by VARCHAR(64) NOT NULL,
    expiry_timestamp TIMESTAMP WITH TIME ZONE,
    justification TEXT,
    
    CONSTRAINT unique_user_role UNIQUE (user_id, role_name)
);

CREATE INDEX idx_user_roles_user ON user_role_assignments(user_id);
CREATE INDEX idx_user_roles_role ON user_role_assignments(role_name);

-- Access control policies table
CREATE TABLE access_control_policies (
    policy_id VARCHAR(64) PRIMARY KEY,
    policy_name VARCHAR(128) NOT NULL,
    description TEXT,
    priority INTEGER DEFAULT 5000,
    enabled BOOLEAN DEFAULT TRUE,
    subject TEXT NOT NULL,
    resource TEXT NOT NULL,
    action VARCHAR(16) NOT NULL,
    effect VARCHAR(16) NOT NULL,
    condition TEXT,
    created_by VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_acp_priority ON access_control_policies(priority);
CREATE INDEX idx_acp_enabled ON access_control_policies(enabled);

-- Audit log table with tamper-evident hash chaining
CREATE TABLE audit_log (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    event_type security_event_type NOT NULL,
    actor_user_id VARCHAR(64) NOT NULL,
    actor_username VARCHAR(128),
    actor_source_ip INET,
    actor_user_agent TEXT,
    actor_session_id VARCHAR(64),
    target_resource TEXT,
    target_resource_type VARCHAR(64),
    action_performed VARCHAR(512) NOT NULL,
    action_status action_status_type NOT NULL,
    status_detail TEXT,
    
    -- Change tracking
    previous_value TEXT,
    new_value TEXT,
    change_diff TEXT,
    
    -- Correlation
    correlation_id UUID,
    
    -- Tamper-evident hash chain columns
    previous_hash VARCHAR(64),  -- Hash of previous audit entry for chain integrity
    current_hash VARCHAR(64),   -- Hash of current entry for integrity verification
    chain_validated BOOLEAN DEFAULT FALSE,  -- Whether the hash chain has been validated
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- TimescaleDB hypertable for audit log
SELECT create_hypertable('audit_log', 'event_timestamp', 
    if_not_exists => TRUE,
    chunk_time_interval => INTERVAL '1 month'
);

CREATE INDEX idx_audit_user ON audit_log(actor_user_id);
CREATE INDEX idx_audit_timestamp ON audit_log(event_timestamp DESC);
CREATE INDEX idx_audit_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_status ON audit_log(action_status);
CREATE INDEX idx_audit_resource ON audit_log(target_resource);

-- Indexes for hash chain lookups and validation
CREATE INDEX idx_audit_previous_hash ON audit_log(previous_hash) WHERE previous_hash IS NOT NULL;
CREATE INDEX idx_audit_current_hash ON audit_log(current_hash) WHERE current_hash IS NOT NULL;
CREATE INDEX idx_audit_chain_validated ON audit_log(chain_validated) WHERE chain_validated = FALSE;

-- Security events table
CREATE TABLE security_events (
    event_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    threat_category threat_category_type NOT NULL,
    severity threat_severity_type NOT NULL,
    description TEXT NOT NULL,
    affected_user VARCHAR(64),
    affected_resource TEXT,
    source_ip INET,
    detection_method VARCHAR(128),
    detection_confidence DECIMAL(4,2),
    
    -- Status tracking
    status VARCHAR(16) DEFAULT 'NEW',
    assigned_to VARCHAR(64),
    recommended_action TEXT,
    related_events UUID[] DEFAULT '{}',
    
    -- Evidence
    log_entries TEXT,
    network_capture TEXT,
    additional_data JSONB,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_security_events_severity ON security_events(severity);
CREATE INDEX idx_security_events_timestamp ON security_events(event_timestamp DESC);
CREATE INDEX idx_security_events_status ON security_events(status);
CREATE INDEX idx_security_events_category ON security_events(threat_category);

-- Compliance requirements table
CREATE TABLE compliance_requirements (
    requirement_id VARCHAR(64) PRIMARY KEY,
    standard VARCHAR(32) NOT NULL,
    requirement_text TEXT NOT NULL,
    responsible_department VARCHAR(128),
    responsible_owner VARCHAR(64),
    implemented_controls TEXT[],
    
    -- Compliance status
    is_compliant BOOLEAN,
    compliance_percentage SMALLINT,
    last_audit_date TIMESTAMP WITH TIME ZONE,
    next_audit_date TIMESTAMP WITH TIME ZONE,
    findings TEXT,
    remediation_status VARCHAR(16),
    remediation_deadline TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_compliance_standard ON compliance_requirements(standard);
CREATE INDEX idx_compliance_status ON compliance_requirements(is_compliant);

COMMENT ON TABLE audit_log IS 'FCAPS-S: Comprehensive security audit trail with TimescaleDB optimization';

-- ============================================================================
-- ACCOUNTING MANAGEMENT TABLES (FCAPS-A)
-- ============================================================================

-- Resource usage records table
CREATE TABLE resource_usage_records (
    usage_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    resource_id TEXT NOT NULL,
    resource_name VARCHAR(256),
    resource_type VARCHAR(32) NOT NULL,
    measurement_period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    measurement_period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    quantity_consumed DECIMAL(18,6) NOT NULL,
    unit_of_measure VARCHAR(32) NOT NULL,
    peak_consumption DECIMAL(18,6),
    average_consumption DECIMAL(18,6),
    minimum_consumption DECIMAL(18,6),
    allocated_capacity DECIMAL(18,6),
    utilization_percent DECIMAL(6,2),
    
    source_vendor vendor_type NOT NULL,
    source_collection_method VARCHAR(32),
    billing_applicable BOOLEAN DEFAULT TRUE,
    
    -- Cost allocation
    cost_center VARCHAR(64),
    department VARCHAR(128),
    project_code VARCHAR(64),
    business_unit VARCHAR(128),
    
    -- Pricing
    rate_card_id VARCHAR(64),
    calculated_cost DECIMAL(12,2),
    currency VARCHAR(3) DEFAULT 'USD',
    
    -- Data quality
    data_completeness_percent DECIMAL(5,2),
    estimated_vs_measured VARCHAR(16),
    confidence_score DECIMAL(4,2),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- TimescaleDB hypertable for usage records
SELECT create_hypertable('resource_usage_records', 'measurement_period_start', 
    if_not_exists => TRUE,
    chunk_time_interval => INTERVAL '1 month'
);

CREATE INDEX idx_usage_resource ON resource_usage_records(resource_id);
CREATE INDEX idx_usage_type ON resource_usage_records(resource_type);
CREATE INDEX idx_usage_period ON resource_usage_records(measurement_period_start, measurement_period_end);
CREATE INDEX idx_usage_vendor ON resource_usage_records(source_vendor);
CREATE INDEX idx_usage_cost_center ON resource_usage_records(cost_center);

-- Licenses table
CREATE TABLE licenses (
    license_id VARCHAR(64) PRIMARY KEY,
    license_name VARCHAR(256) NOT NULL,
    vendor vendor_type NOT NULL,
    license_type VARCHAR(32) NOT NULL,
    total_capacity INTEGER,
    used_capacity INTEGER,
    available_capacity INTEGER,
    utilization_percent DECIMAL(6,2),
    purchase_date TIMESTAMP WITH TIME ZONE,
    expiry_date TIMESTAMP WITH TIME ZONE,
    renewal_date TIMESTAMP WITH TIME ZONE,
    annual_cost DECIMAL(12,2),
    contract_number VARCHAR(64),
    assigned_resources TEXT[],
    
    -- Compliance
    is_compliant BOOLEAN DEFAULT TRUE,
    overage_quantity INTEGER,
    overage_cost DECIMAL(12,2),
    warning_threshold_percent SMALLINT DEFAULT 80,
    alert_sent BOOLEAN DEFAULT FALSE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_licenses_vendor ON licenses(vendor);
CREATE INDEX idx_licenses_expiry ON licenses(expiry_date);
CREATE INDEX idx_licenses_utilization ON licenses(utilization_percent DESC);

-- Invoices table
CREATE TABLE invoices (
    invoice_id VARCHAR(64) PRIMARY KEY,
    invoice_number VARCHAR(32) UNIQUE NOT NULL,
    billing_period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    billing_period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    issue_date TIMESTAMP WITH TIME ZONE,
    due_date TIMESTAMP WITH TIME ZONE,
    customer_id VARCHAR(64) NOT NULL,
    customer_name VARCHAR(256),
    billing_contact VARCHAR(256),
    
    -- Line items
    line_items JSONB NOT NULL DEFAULT '[]',
    
    -- Amounts
    subtotal DECIMAL(14,2) NOT NULL,
    adjustments JSONB,
    tax_amount DECIMAL(12,2),
    total_amount_due DECIMAL(14,2) NOT NULL,
    currency VARCHAR(3) DEFAULT 'USD',
    
    -- Payment status
    payment_status invoice_status_type NOT NULL,
    amount_paid DECIMAL(14,2) DEFAULT 0,
    amount_outstanding DECIMAL(14,2),
    payment_timestamp TIMESTAMP WITH TIME ZONE,
    payment_reference VARCHAR(64),
    
    -- Discounts
    early_payment_discount_percent DECIMAL(4,2),
    loyalty_discount_percent DECIMAL(4,2),
    volume_discount_percent DECIMAL(4,2),
    
    notes TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_invoices_customer ON invoices(customer_id);
CREATE INDEX idx_invoices_status ON invoices(payment_status);
CREATE INDEX idx_invoices_period ON invoices(billing_period_start, billing_period_end);
CREATE INDEX idx_invoices_due ON invoices(due_date) WHERE payment_status NOT IN ('PAID', 'CANCELLED');

-- Cost centers table
CREATE TABLE cost_centers (
    cost_center_id VARCHAR(64) PRIMARY KEY,
    cost_center_name VARCHAR(256) NOT NULL,
    department VARCHAR(128),
    business_unit VARCHAR(128),
    manager VARCHAR(64),
    budget_amount DECIMAL(14,2),
    budget_period VARCHAR(16),
    spent_amount DECIMAL(14,2) DEFAULT 0,
    remaining_budget DECIMAL(14,2),
    budget_utilization_percent DECIMAL(6,2),
    alert_threshold_percent SMALLINT DEFAULT 80,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Rate cards table
CREATE TABLE rate_cards (
    rate_card_id VARCHAR(64) PRIMARY KEY,
    rate_card_name VARCHAR(256) NOT NULL,
    effective_start_date TIMESTAMP WITH TIME ZONE,
    effective_end_date TIMESTAMP WITH TIME ZONE,
    currency VARCHAR(3) DEFAULT 'USD',
    rates JSONB NOT NULL,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE resource_usage_records IS 'FCAPS-A: Resource usage tracking with TimescaleDB optimization';

-- ============================================================================
-- TOPOLOGY AND INVENTORY TABLE
-- ============================================================================

CREATE TABLE topology_inventory (
    element_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_vendor vendor_type NOT NULL,
    element_type VARCHAR(100) NOT NULL,
    element_name VARCHAR(255),
    cim_path TEXT NOT NULL,
    vendor_element_id VARCHAR(255),
    parent_element_id UUID,
    element_data JSONB NOT NULL,
    last_discovered TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT fk_parent FOREIGN KEY(parent_element_id) 
        REFERENCES topology_inventory(element_id) ON DELETE SET NULL
);

CREATE INDEX idx_topology_vendor ON topology_inventory(source_vendor);
CREATE INDEX idx_topology_type ON topology_inventory(element_type);
CREATE INDEX idx_topology_path ON topology_inventory(cim_path);
CREATE INDEX idx_topology_parent ON topology_inventory(parent_element_id);
CREATE INDEX idx_topology_active ON topology_inventory(is_active);
CREATE INDEX idx_topology_gin ON topology_inventory USING GIN(element_data);

COMMENT ON TABLE topology_inventory IS 'Network topology and inventory from multiple vendors';

-- ============================================================================
-- SEMANTIC MAPPING RULES TABLE
-- ============================================================================

CREATE TABLE semantic_mapping_rules (
    rule_id VARCHAR(64) PRIMARY KEY,
    rule_name VARCHAR(256) NOT NULL,
    rule_type VARCHAR(32) NOT NULL,
    description TEXT,
    source_vendor vendor_type NOT NULL,
    source_yang_path TEXT NOT NULL,
    target_cim_path TEXT NOT NULL,
    priority INTEGER DEFAULT 50,
    enabled BOOLEAN DEFAULT TRUE,
    
    -- Mapping configuration
    transformation_type VARCHAR(32) NOT NULL, -- DIRECT, AGGREGATION, CONDITIONAL, ENUMERATION, UNIT_CONVERSION
    transformation_config JSONB NOT NULL,
    
    -- Statistics
    times_applied BIGINT DEFAULT 0,
    times_failed BIGINT DEFAULT 0,
    last_applied TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_mapping_rules_vendor ON semantic_mapping_rules(source_vendor);
CREATE INDEX idx_mapping_rules_source ON semantic_mapping_rules(source_yang_path);
CREATE INDEX idx_mapping_rules_target ON semantic_mapping_rules(target_cim_path);
CREATE INDEX idx_mapping_rules_enabled ON semantic_mapping_rules(enabled);

COMMENT ON TABLE semantic_mapping_rules IS 'Semantic mapping rules for YANG to CIM transformation';

-- ============================================================================
-- FUNCTIONS AND PROCEDURES
-- ============================================================================

-- Function to update timestamps
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to all relevant tables
CREATE TRIGGER update_cim_instances_timestamp
    BEFORE UPDATE ON cim_yang_instances
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER update_alarms_timestamp
    BEFORE UPDATE ON alarms
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER update_configurations_timestamp
    BEFORE UPDATE ON configurations
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER update_security_events_timestamp
    BEFORE UPDATE ON security_events
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();

-- Function to calculate alarm statistics
CREATE OR REPLACE FUNCTION get_alarm_statistics()
RETURNS TABLE (
    severity alarm_severity_type,
    active_count BIGINT,
    acknowledged_count BIGINT,
    cleared_count BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        a.alarm_severity,
        COUNT(*) FILTER (WHERE a.alarm_state = 'ACTIVE') as active_count,
        COUNT(*) FILTER (WHERE a.alarm_state = 'ACKNOWLEDGED') as acknowledged_count,
        COUNT(*) FILTER (WHERE a.alarm_state = 'CLEARED') as cleared_count
    FROM alarms a
    GROUP BY a.alarm_severity
    ORDER BY a.alarm_severity;
END;
$$ LANGUAGE plpgsql;

-- Function to aggregate metrics
CREATE OR REPLACE FUNCTION aggregate_metrics(
    p_metric_name VARCHAR,
    p_start_time TIMESTAMP WITH TIME ZONE,
    p_end_time TIMESTAMP WITH TIME ZONE,
    p_aggregation VARCHAR DEFAULT 'AVG'
)
RETURNS TABLE (
    bucket TIMESTAMP WITH TIME ZONE,
    aggregated_value DECIMAL(18,6),
    sample_count BIGINT
) AS $$
BEGIN
    IF p_aggregation = 'AVG' THEN
        RETURN QUERY
        SELECT 
            time_bucket('1 hour', m.measurement_timestamp) as bucket,
            AVG(m.metric_value) as aggregated_value,
            COUNT(*) as sample_count
        FROM metrics m
        WHERE m.metric_name = p_metric_name
          AND m.measurement_timestamp BETWEEN p_start_time AND p_end_time
        GROUP BY bucket
        ORDER BY bucket;
    ELSIF p_aggregation = 'SUM' THEN
        RETURN QUERY
        SELECT 
            time_bucket('1 hour', m.measurement_timestamp) as bucket,
            SUM(m.metric_value) as aggregated_value,
            COUNT(*) as sample_count
        FROM metrics m
        WHERE m.metric_name = p_metric_name
          AND m.measurement_timestamp BETWEEN p_start_time AND p_end_time
        GROUP BY bucket
        ORDER BY bucket;
    ELSIF p_aggregation = 'MAX' THEN
        RETURN QUERY
        SELECT 
            time_bucket('1 hour', m.measurement_timestamp) as bucket,
            MAX(m.metric_value) as aggregated_value,
            COUNT(*) as sample_count
        FROM metrics m
        WHERE m.metric_name = p_metric_name
          AND m.measurement_timestamp BETWEEN p_start_time AND p_end_time
        GROUP BY bucket
        ORDER BY bucket;
    ELSIF p_aggregation = 'MIN' THEN
        RETURN QUERY
        SELECT 
            time_bucket('1 hour', m.measurement_timestamp) as bucket,
            MIN(m.metric_value) as aggregated_value,
            COUNT(*) as sample_count
        FROM metrics m
        WHERE m.metric_name = p_metric_name
          AND m.measurement_timestamp BETWEEN p_start_time AND p_end_time
        GROUP BY bucket
        ORDER BY bucket;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- Active alarms view
CREATE OR REPLACE VIEW v_active_alarms AS
SELECT 
    a.alarm_id,
    a.alarm_severity,
    a.alarm_type,
    a.affected_resource,
    a.source_vendor,
    a.detection_timestamp,
    a.vendor_alarm_name,
    a.alarm_state,
    a.escalation_level,
    EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - a.detection_timestamp))/3600 as hours_active
FROM alarms a
WHERE a.alarm_state IN ('ACTIVE', 'ACKNOWLEDGED')
ORDER BY a.alarm_severity, a.detection_timestamp DESC;

-- Metric summary view
CREATE OR REPLACE VIEW v_metric_summary AS
SELECT DISTINCT ON (m.metric_name)
    m.metric_name,
    m.metric_value as latest_value,
    m.unit_of_measurement,
    m.measurement_timestamp,
    m.threshold_status,
    m.source_vendor
FROM metrics m
ORDER BY m.metric_name, m.measurement_timestamp DESC;

-- Security dashboard view
CREATE OR REPLACE VIEW v_security_dashboard AS
SELECT 
    COUNT(*) FILTER (WHERE se.status = 'NEW') as new_events,
    COUNT(*) FILTER (WHERE se.status = 'INVESTIGATING') as investigating_events,
    COUNT(*) FILTER (WHERE se.severity = 'CRITICAL') as critical_events,
    COUNT(*) FILTER (WHERE se.severity = 'HIGH') as high_events,
    COUNT(*) FILTER (WHERE se.event_timestamp > CURRENT_TIMESTAMP - INTERVAL '24 hours') as events_last_24h
FROM security_events se;

-- Compliance summary view
CREATE OR REPLACE VIEW v_compliance_summary AS
SELECT 
    cr.standard,
    COUNT(*) as total_requirements,
    COUNT(*) FILTER (WHERE cr.is_compliant = TRUE) as compliant_count,
    COUNT(*) FILTER (WHERE cr.is_compliant = FALSE) as non_compliant_count,
    ROUND(AVG(cr.compliance_percentage)::numeric, 2) as avg_compliance_percent
FROM compliance_requirements cr
GROUP BY cr.standard
ORDER BY cr.standard;

-- ============================================================================
-- DATA RETENTION POLICIES
-- ============================================================================

-- Add retention policies for TimescaleDB tables
SELECT add_retention_policy('metrics', INTERVAL '90 days', if_not_exists => TRUE);
SELECT add_retention_policy('kpi_values', INTERVAL '365 days', if_not_exists => TRUE);
SELECT add_retention_policy('audit_log', INTERVAL '365 days', if_not_exists => TRUE);
SELECT add_retention_policy('resource_usage_records', INTERVAL '365 days', if_not_exists => TRUE);

-- ============================================================================
-- INITIAL SEED DATA
-- ============================================================================

-- Insert default roles
INSERT INTO roles (role_name, display_name, description, privilege_level, permissions) VALUES
('GUEST', 'Guest', 'Read-only access to limited views', 0, ARRAY['READ:ALARMS:OWN', 'READ:METRICS:OWN']),
('OPERATOR', 'Operator', 'Standard operations access', 5, ARRAY['READ:ALARMS:ALL', 'WRITE:ALARMS:ALL', 'READ:CONFIG:OWN', 'READ:METRICS:ALL', 'EXECUTE:RPC:BASIC']),
('ENGINEER', 'Network Engineer', 'Engineering level access', 7, ARRAY['READ:ALARMS:ALL', 'WRITE:ALARMS:ALL', 'READ:CONFIG:ALL', 'WRITE:CONFIG:OWN', 'READ:METRICS:ALL', 'READ:SECURITY:OWN', 'EXECUTE:RPC:STANDARD']),
('ADMIN', 'Administrator', 'Full administrative access', 8, ARRAY['READ:*:ALL', 'WRITE:*:ALL', 'EXECUTE:RPC:ALL', 'ADMIN:USERS:ALL']),
('SUPER_ADMIN', 'Super Administrator', 'System management access', 10, ARRAY['ADMIN:*:ALL', 'SYSTEM:*:ALL']);

-- Insert default compliance standards
INSERT INTO compliance_requirements (requirement_id, standard, requirement_text, responsible_department) VALUES
('SOC2-001', 'SOC2', 'Access controls must be implemented and documented', 'IT Security'),
('SOC2-002', 'SOC2', 'Audit logging must be enabled for all security-relevant events', 'IT Security'),
('ISO27001-001', 'ISO27001', 'Information security policy must be established', 'IT Governance'),
('ISO27001-002', 'ISO27001', 'Risk assessment methodology must be defined', 'Risk Management'),
('GDPR-001', 'GDPR', 'Personal data processing must have legal basis', 'Legal'),
('GDPR-002', 'GDPR', 'Data subject access requests must be handled within 30 days', 'Data Protection');

-- ============================================================================
-- SCHEMA VERSION TRACKING
-- ============================================================================

CREATE TABLE schema_versions (
    version_id SERIAL PRIMARY KEY,
    version_number VARCHAR(16) NOT NULL,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    description TEXT,
    applied_by VARCHAR(64)
);

INSERT INTO schema_versions (version_number, description, applied_by) 
VALUES ('1.0.0', 'Initial schema creation for FCAPS management', 'migration_script');

-- ============================================================================
-- END OF MIGRATION
-- ============================================================================

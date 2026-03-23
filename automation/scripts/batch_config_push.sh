#!/bin/bash
#
# Unified OSS Framework - Batch Configuration Push Script
# Dr. Houda Chihi - IEEE Member, TechWomen 2019 Fellow
#
# This script performs batch configuration push to multiple network elements
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
AUTOMATION_DIR="$PROJECT_ROOT/automation"
LOG_DIR="$PROJECT_ROOT/logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/batch_push_$TIMESTAMP.log"

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

# Usage
usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Options:
    -c, --config-file FILE    Configuration YAML file
    -h, --hosts-file FILE     Hosts file with NE list
    -p, --parallel NUM        Number of parallel operations (default: 5)
    -d, --dry-run             Validate without applying changes
    -v, --verbose             Enable verbose output
    --help                    Show this help message

Example:
    $(basename "$0") -c config.yaml -h hosts.yaml -p 10

EOF
    exit 1
}

# Parse arguments
CONFIG_FILE=""
HOSTS_FILE=""
PARALLEL=5
DRY_RUN=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config-file)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -h|--hosts-file)
            HOSTS_FILE="$2"
            shift 2
            ;;
        -p|--parallel)
            PARALLEL="$2"
            shift 2
            ;;
        -d|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate inputs
if [[ -z "$CONFIG_FILE" ]]; then
    log_error "Configuration file is required"
    usage
fi

if [[ -z "$HOSTS_FILE" ]]; then
    log_error "Hosts file is required"
    usage
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    log_error "Configuration file not found: $CONFIG_FILE"
    exit 1
fi

if [[ ! -f "$HOSTS_FILE" ]]; then
    log_error "Hosts file not found: $HOSTS_FILE"
    exit 1
fi

# Start batch operation
log "Starting batch configuration push..."
log "Configuration: $CONFIG_FILE"
log "Hosts: $HOSTS_FILE"
log "Parallel: $PARALLEL"
log "Dry Run: $DRY_RUN"

# Build command
CMD="python3 $AUTOMATION_DIR/netconf_config_push.py batch"
CMD="$CMD --hosts-file $HOSTS_FILE"
CMD="$CMD --config-file $CONFIG_FILE"
CMD="$CMD --parallel $PARALLEL"

if [[ "$DRY_RUN" == true ]]; then
    CMD="$CMD --dry-run"
fi

if [[ "$VERBOSE" == true ]]; then
    CMD="$CMD --verbose"
fi

# Execute
log "Executing: $CMD"
$CMD

# Check result
if [[ $? -eq 0 ]]; then
    log_success "Batch configuration push completed successfully"
    exit 0
else
    log_error "Batch configuration push failed"
    exit 1
fi

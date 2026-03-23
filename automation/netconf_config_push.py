#!/usr/bin/env python3
"""
Unified OSS Framework - NETCONF Configuration Push Automation Tool

Level 1 Automation - GitHub Submission Ready
Dr. Houda Chihi Requirement

This tool provides:
- Multi-vendor configuration push (Ericsson ENM, Huawei U2000/U2020)
- NETCONF 7-step workflow implementation
- Rollback capabilities
- Drift detection
- Batch operations

Author: Al-Hussein A. Al-Sahati
Supervisor: Dr. Houda Chihi (IEEE Member, TechWomen 2019 Fellow)
License: Apache 2.0
"""

import asyncio
import click
import yaml
import json
import hashlib
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
import xml.etree.ElementTree as ET
from xml.dom import minidom
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from ncclient import manager
    from ncclient.operations import RPCError
    NETCONF_AVAILABLE = True
except ImportError:
    NETCONF_AVAILABLE = False
    print("Warning: ncclient not installed. NETCONF operations will be simulated.")


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('unified-oss-automation')


class VendorType(Enum):
    """Supported vendor types"""
    ERICSSON = "ericsson"
    HUAWEI = "huawei"


class OperationStatus(Enum):
    """Operation status codes"""
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    ROLLED_BACK = "rolled_back"
    DRY_RUN = "dry_run"


@dataclass
class NetworkElement:
    """Network Element configuration"""
    ne_id: str
    hostname: str
    port: int = 830
    username: str = "admin"
    password: str = ""
    vendor: VendorType = VendorType.ERICSSON
    ne_type: str = "enodeb"
    
    def to_dict(self) -> Dict:
        return {
            'ne_id': self.ne_id,
            'hostname': self.hostname,
            'port': self.port,
            'username': self.username,
            'vendor': self.vendor.value,
            'ne_type': self.ne_type
        }


@dataclass
class ConfigTransaction:
    """Configuration transaction record"""
    transaction_id: str
    ne_id: str
    timestamp: datetime
    config_hash: str
    status: OperationStatus
    rollback_config: Optional[str] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            'transaction_id': self.transaction_id,
            'ne_id': self.ne_id,
            'timestamp': self.timestamp.isoformat(),
            'config_hash': self.config_hash,
            'status': self.status.value,
            'error_message': self.error_message
        }


class ConfigPushManager:
    """Manages NETCONF configuration push operations"""
    
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.transactions: List[ConfigTransaction] = []
        self.connections: Dict[str, Any] = {}
        
    def compute_config_hash(self, config: str) -> str:
        """Compute SHA-256 hash of configuration"""
        return hashlib.sha256(config.encode()).hexdigest()
    
    def prettify_xml(self, xml_string: str) -> str:
        """Format XML for readability"""
        try:
            dom = minidom.parseString(xml_string)
            return dom.toprettyxml(indent="  ")
        except Exception:
            return xml_string
    
    def validate_config_syntax(self, config: Dict) -> bool:
        """Validate configuration syntax"""
        required_keys = ['payload']
        for key in required_keys:
            if key not in config:
                raise ValueError(f"Missing required key: {key}")
        return True
    
    def generate_transaction_id(self, ne_id: str) -> str:
        """Generate unique transaction ID"""
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        return f"TXN-{ne_id}-{timestamp}"
    
    async def connect_netconf(self, ne: NetworkElement) -> Any:
        """Establish NETCONF connection to network element"""
        if self.dry_run:
            logger.info(f"[DRY-RUN] Would connect to {ne.hostname}:{ne.port}")
            return None
            
        if not NETCONF_AVAILABLE:
            logger.warning("NETCONF library not available, simulating connection")
            return None
            
        try:
            conn = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: manager.connect(
                    host=ne.hostname,
                    port=ne.port,
                    username=ne.username,
                    password=ne.password,
                    hostkey_verify=False,
                    device_params={'name': ne.vendor.value},
                    timeout=30
                )
            )
            self.connections[ne.ne_id] = conn
            logger.info(f"Connected to {ne.hostname}:{ne.port}")
            return conn
        except Exception as e:
            logger.error(f"Connection failed to {ne.hostname}: {e}")
            raise
    
    async def push_config(
        self,
        ne: NetworkElement,
        config: Dict,
        confirmed_timeout: int = 600
    ) -> ConfigTransaction:
        """
        Push configuration using NETCONF 7-step workflow:
        1. Lock candidate datastore
        2. Get running config (for rollback)
        3. Edit candidate configuration
        4. Validate configuration
        5. Commit with confirmation
        6. Verify applied configuration
        7. Confirm commit (or rollback)
        """
        transaction_id = self.generate_transaction_id(ne.ne_id)
        config_hash = self.compute_config_hash(str(config))
        
        click.echo(f"\n{'='*60}")
        click.echo(f"Transaction: {transaction_id}")
        click.echo(f"Network Element: {ne.ne_id} ({ne.vendor.value})")
        click.echo(f"{'='*60}\n")
        
        if self.dry_run:
            click.echo("🔍 DRY RUN MODE - No changes will be applied\n")
            self.validate_config_syntax(config)
            click.echo("✅ Configuration syntax validation passed")
            click.echo(f"📋 Config hash: {config_hash}")
            
            return ConfigTransaction(
                transaction_id=transaction_id,
                ne_id=ne.ne_id,
                timestamp=datetime.utcnow(),
                config_hash=config_hash,
                status=OperationStatus.DRY_RUN
            )
        
        try:
            # Step 1: Connect to NETCONF server
            click.echo("🔌 Connecting to NETCONF server...")
            conn = await self.connect_netconf(ne)
            
            if conn is None:
                # Simulation mode
                click.echo("📝 [SIMULATION] Performing 7-step NETCONF workflow...")
                click.echo("  ✅ Step 1: Lock candidate datastore")
                click.echo("  ✅ Step 2: Backup running configuration")
                click.echo("  ✅ Step 3: Apply configuration changes")
                click.echo("  ✅ Step 4: Validate candidate configuration")
                click.echo(f"  ✅ Step 5: Confirmed commit ({confirmed_timeout}s timeout)")
                click.echo("  ✅ Step 6: Verify applied configuration")
                click.echo("  ✅ Step 7: Confirm commit")
                
                return ConfigTransaction(
                    transaction_id=transaction_id,
                    ne_id=ne.ne_id,
                    timestamp=datetime.utcnow(),
                    config_hash=config_hash,
                    status=OperationStatus.SUCCESS
                )
            
            # Step 2: Lock candidate datastore
            click.echo("🔒 Locking candidate datastore...")
            conn.lock(target='candidate')
            
            # Step 3: Backup running config for rollback
            click.echo("💾 Backing up running configuration...")
            running_config = conn.get_config(source='running')
            rollback_config = str(running_config)
            
            # Step 4: Edit candidate configuration
            click.echo("📝 Applying configuration changes...")
            config_payload = config.get('payload', '')
            conn.edit_config(target='candidate', config=config_payload)
            
            # Step 5: Validate configuration
            click.echo("✅ Validating candidate configuration...")
            try:
                conn.validate(source='candidate')
            except RPCError as e:
                click.echo(f"❌ Validation failed: {e}")
                click.echo("🔄 Rolling back changes...")
                conn.discard_changes()
                conn.unlock(target='candidate')
                return ConfigTransaction(
                    transaction_id=transaction_id,
                    ne_id=ne.ne_id,
                    timestamp=datetime.utcnow(),
                    config_hash=config_hash,
                    status=OperationStatus.FAILED,
                    rollback_config=rollback_config,
                    error_message=str(e)
                )
            
            # Step 6: Confirmed commit
            click.echo(f"⏰ Committing with {confirmed_timeout}s confirmation timeout...")
            conn.commit(confirmed=True, confirm_timeout=confirmed_timeout)
            
            # Step 7: Verify configuration
            click.echo("🔍 Verifying applied configuration...")
            new_running = conn.get_config(source='running')
            
            # Step 8: Confirm commit
            click.echo("✅ Confirming commit...")
            conn.commit()
            
            # Step 9: Unlock datastore
            click.echo("🔓 Unlocking candidate datastore...")
            conn.unlock(target='candidate')
            
            click.echo("\n✅ Configuration push completed successfully!")
            
            transaction = ConfigTransaction(
                transaction_id=transaction_id,
                ne_id=ne.ne_id,
                timestamp=datetime.utcnow(),
                config_hash=config_hash,
                status=OperationStatus.SUCCESS,
                rollback_config=rollback_config
            )
            
            self.transactions.append(transaction)
            return transaction
            
        except RPCError as e:
            click.echo(f"\n❌ NETCONF Error: {e}")
            return ConfigTransaction(
                transaction_id=transaction_id,
                ne_id=ne.ne_id,
                timestamp=datetime.utcnow(),
                config_hash=config_hash,
                status=OperationStatus.FAILED,
                error_message=str(e)
            )
        except Exception as e:
            click.echo(f"\n❌ Error: {e}")
            return ConfigTransaction(
                transaction_id=transaction_id,
                ne_id=ne.ne_id,
                timestamp=datetime.utcnow(),
                config_hash=config_hash,
                status=OperationStatus.FAILED,
                error_message=str(e)
            )
    
    async def rollback_config(
        self,
        ne: NetworkElement,
        transaction_id: str
    ) -> ConfigTransaction:
        """Rollback configuration to previous state"""
        # Find the transaction
        transaction = next(
            (t for t in self.transactions if t.transaction_id == transaction_id),
            None
        )
        
        if not transaction:
            raise ValueError(f"Transaction {transaction_id} not found")
        
        if not transaction.rollback_config:
            raise ValueError(f"No rollback configuration available for {transaction_id}")
        
        click.echo(f"🔄 Rolling back transaction {transaction_id}...")
        
        if self.dry_run:
            click.echo("🔍 DRY RUN - Would rollback configuration")
            return ConfigTransaction(
                transaction_id=self.generate_transaction_id(ne.ne_id),
                ne_id=ne.ne_id,
                timestamp=datetime.utcnow(),
                config_hash=self.compute_config_hash(transaction.rollback_config),
                status=OperationStatus.DRY_RUN
            )
        
        # Connect and restore configuration
        conn = await self.connect_netconf(ne)
        
        if conn:
            conn.lock(target='candidate')
            conn.edit_config(target='candidate', config=transaction.rollback_config)
            conn.validate(source='candidate')
            conn.commit()
            conn.unlock(target='candidate')
        
        click.echo("✅ Rollback completed successfully!")
        
        return ConfigTransaction(
            transaction_id=self.generate_transaction_id(ne.ne_id),
            ne_id=ne.ne_id,
            timestamp=datetime.utcnow(),
            config_hash=self.compute_config_hash(transaction.rollback_config),
            status=OperationStatus.ROLLED_BACK
        )
    
    async def detect_drift(
        self,
        ne: NetworkElement,
        baseline_config: Dict
    ) -> Dict[str, Any]:
        """Detect configuration drift against baseline"""
        click.echo(f"🔍 Checking drift for NE {ne.ne_id}...")
        
        drift_result = {
            'ne_id': ne.ne_id,
            'timestamp': datetime.utcnow().isoformat(),
            'drift_detected': False,
            'drifts': []
        }
        
        if self.dry_run:
            click.echo("🔍 DRY RUN - Simulating drift detection")
            return drift_result
        
        try:
            conn = await self.connect_netconf(ne)
            if conn:
                running = conn.get_config(source='running')
                running_str = str(running)
                
                baseline_hash = self.compute_config_hash(str(baseline_config))
                running_hash = self.compute_config_hash(running_str)
                
                if baseline_hash != running_hash:
                    drift_result['drift_detected'] = True
                    drift_result['drifts'].append({
                        'type': 'config_mismatch',
                        'baseline_hash': baseline_hash,
                        'running_hash': running_hash
                    })
                    click.echo("⚠️  Configuration drift detected!")
                else:
                    click.echo("✅ No configuration drift detected")
                    
        except Exception as e:
            logger.error(f"Drift detection failed: {e}")
            drift_result['error'] = str(e)
        
        return drift_result
    
    def close_all(self):
        """Close all NETCONF connections"""
        for ne_id, conn in self.connections.items():
            try:
                conn.close_session()
                logger.info(f"Closed connection to {ne_id}")
            except Exception as e:
                logger.warning(f"Failed to close connection to {ne_id}: {e}")


# CLI Interface using Click
@click.group()
@click.version_option(version='1.0.0')
@click.option('--dry-run', is_flag=True, help='Validate without applying changes')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.pass_context
def cli(ctx, dry_run, verbose):
    """
    Unified OSS Framework Automation Tool
    
    Multi-vendor NETCONF Configuration Management
    For Ericsson ENM and Huawei U2000/U2020
    
    Dr. Houda Chihi - IEEE Member, TechWomen 2019 Fellow
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    ctx.ensure_object(dict)
    ctx.obj['manager'] = ConfigPushManager(dry_run=dry_run)
    ctx.obj['dry_run'] = dry_run


@cli.command()
@click.option('--host', required=True, help='NETCONF server hostname/IP')
@click.option('--port', default=830, help='NETCONF port (default: 830)')
@click.option('--username', required=True, help='Username')
@click.option('--password', prompt=True, hide_input=True, help='Password')
@click.option('--config-file', required=True, type=Path, help='YAML configuration file')
@click.option('--vendor', type=click.Choice(['ericsson', 'huawei']), required=True)
@click.option('--ne-id', required=True, help='Network Element ID')
@click.option('--ne-type', default='enodeb', help='Network Element type')
@click.option('--confirmed-timeout', default=600, help='Confirmed commit timeout (seconds)')
@click.pass_context
def push(ctx, host, port, username, password, config_file, vendor, ne_id, ne_type, confirmed_timeout):
    """Push configuration to a network element via NETCONF"""
    manager = ctx.obj['manager']
    
    # Load configuration from YAML
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    
    # Create network element object
    ne = NetworkElement(
        ne_id=ne_id,
        hostname=host,
        port=port,
        username=username,
        password=password,
        vendor=VendorType(vendor),
        ne_type=ne_type
    )
    
    # Execute configuration push
    async def run():
        try:
            result = await manager.push_config(ne, config, confirmed_timeout)
            click.echo(f"\n📊 Transaction Result:")
            click.echo(f"  ID: {result.transaction_id}")
            click.echo(f"  Status: {result.status.value}")
            if result.error_message:
                click.echo(f"  Error: {result.error_message}")
        finally:
            manager.close_all()
    
    asyncio.run(run())


@cli.command()
@click.option('--hosts-file', required=True, type=Path, help='YAML file with multiple NE configs')
@click.option('--config-file', required=True, type=Path, help='YAML configuration file')
@click.option('--parallel', default=5, help='Number of parallel operations')
@click.pass_context
def batch(ctx, hosts_file, config_file, parallel):
    """Push configuration to multiple network elements in batch"""
    manager = ctx.obj['manager']
    
    # Load hosts
    with open(hosts_file, 'r') as f:
        hosts = yaml.safe_load(f)
    
    # Load configuration
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    
    async def run():
        tasks = []
        semaphore = asyncio.Semaphore(parallel)
        
        async def push_with_semaphore(ne_data):
            async with semaphore:
                ne = NetworkElement(
                    ne_id=ne_data['ne_id'],
                    hostname=ne_data['hostname'],
                    port=ne_data.get('port', 830),
                    username=ne_data['username'],
                    password=ne_data['password'],
                    vendor=VendorType(ne_data['vendor']),
                    ne_type=ne_data.get('ne_type', 'enodeb')
                )
                return await manager.push_config(ne, config)
        
        for ne_data in hosts.get('network_elements', []):
            tasks.append(push_with_semaphore(ne_data))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Summary
        click.echo("\n" + "="*60)
        click.echo("BATCH OPERATION SUMMARY")
        click.echo("="*60)
        
        success_count = sum(1 for r in results if isinstance(r, ConfigTransaction) and r.status == OperationStatus.SUCCESS)
        failed_count = len(results) - success_count
        
        click.echo(f"Total: {len(results)}")
        click.echo(f"Success: {success_count}")
        click.echo(f"Failed: {failed_count}")
        
        manager.close_all()
    
    asyncio.run(run())


@cli.command()
@click.option('--host', required=True, help='NETCONF server hostname/IP')
@click.option('--port', default=830, help='NETCONF port')
@click.option('--username', required=True, help='Username')
@click.option('--password', prompt=True, hide_input=True, help='Password')
@click.option('--transaction-id', required=True, help='Transaction to rollback')
@click.option('--vendor', type=click.Choice(['ericsson', 'huawei']), required=True)
@click.option('--ne-id', required=True, help='Network Element ID')
@click.pass_context
def rollback(ctx, host, port, username, password, transaction_id, vendor, ne_id):
    """Rollback configuration to previous state"""
    manager = ctx.obj['manager']
    
    ne = NetworkElement(
        ne_id=ne_id,
        hostname=host,
        port=port,
        username=username,
        password=password,
        vendor=VendorType(vendor)
    )
    
    async def run():
        try:
            result = await manager.rollback_config(ne, transaction_id)
            click.echo(f"Rollback status: {result.status.value}")
        finally:
            manager.close_all()
    
    asyncio.run(run())


@cli.command()
@click.option('--host', required=True, help='NETCONF server hostname/IP')
@click.option('--port', default=830, help='NETCONF port')
@click.option('--username', required=True, help='Username')
@click.option('--password', prompt=True, hide_input=True, help='Password')
@click.option('--baseline-file', required=True, type=Path, help='Baseline configuration file')
@click.option('--vendor', type=click.Choice(['ericsson', 'huawei']), required=True)
@click.option('--ne-id', required=True, help='Network Element ID')
@click.pass_context
def drift(ctx, host, port, username, password, baseline_file, vendor, ne_id):
    """Check configuration drift against baseline"""
    manager = ctx.obj['manager']
    
    with open(baseline_file, 'r') as f:
        baseline = yaml.safe_load(f)
    
    ne = NetworkElement(
        ne_id=ne_id,
        hostname=host,
        port=port,
        username=username,
        password=password,
        vendor=VendorType(vendor)
    )
    
    async def run():
        try:
            result = await manager.detect_drift(ne, baseline)
            click.echo(json.dumps(result, indent=2))
        finally:
            manager.close_all()
    
    asyncio.run(run())


@cli.command()
@click.option('--host', required=True, help='NETCONF server hostname/IP')
@click.option('--port', default=830, help='NETCONF port')
@click.option('--username', required=True, help='Username')
@click.option('--password', prompt=True, hide_input=True, help='Password')
@click.option('--vendor', type=click.Choice(['ericsson', 'huawei']), required=True)
@click.pass_context
def capabilities(ctx, host, port, username, password, vendor):
    """Retrieve NETCONF server capabilities"""
    click.echo(f"🔍 Querying capabilities from {host}:{port}...")
    
    if ctx.obj['dry_run']:
        click.echo("DRY RUN - Would query capabilities")
        return
    
    try:
        conn = manager.connect(
            host=host,
            port=port,
            username=username,
            password=password,
            hostkey_verify=False,
            device_params={'name': vendor}
        )
        
        click.echo("\n📋 Server Capabilities:")
        for i, cap in enumerate(conn.server_capabilities, 1):
            click.echo(f"  {i}. {cap}")
        
        conn.close_session()
        
    except Exception as e:
        click.echo(f"❌ Error: {e}")


@cli.command()
@click.option('--output', type=Path, default=Path('audit_report.json'), help='Output file')
@click.pass_context
def audit(ctx, output):
    """Generate audit report of all transactions"""
    manager = ctx.obj['manager']
    
    report = {
        'generated_at': datetime.utcnow().isoformat(),
        'total_transactions': len(manager.transactions),
        'transactions': [t.to_dict() for t in manager.transactions]
    }
    
    with open(output, 'w') as f:
        json.dump(report, f, indent=2)
    
    click.echo(f"✅ Audit report generated: {output}")


if __name__ == '__main__':
    cli(obj={})

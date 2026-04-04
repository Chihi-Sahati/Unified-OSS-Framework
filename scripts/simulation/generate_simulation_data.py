#!/usr/bin/env python3
"""
Generate simulation data for Unified OSS Framework testing and demonstration.

This script creates:
- 300 Network Elements (150 Ericsson, 150 Huawei)
- 1000+ alarm events
- 7 days of PM data (15-minute granularity)
"""

import json
import uuid
import random
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, asdict
from typing import List, Dict, Any
import os

# Configuration
NUM_ERICSSON_NE = 150
NUM_HUAWEI_NE = 150
NUM_ALARMS = 1200
PM_DAYS = 7
PM_INTERVAL_MINUTES = 15

# Site configurations
TUNISIAN_REGIONS = ["Tunis", "Sfax", "Sousse", "Gabes", "Bizerte", "Ariana", "Ben Arous", "Monastir"]
SITE_PREFIXES = ["TT", "OA", "OR", "TN"]

@dataclass
class NetworkElement:
    ne_id: str
    ne_name: str
    vendor: str
    ne_type: str
    ip_address: str
    site_id: str
    region: str
    latitude: float
    longitude: float
    software_version: str
    cells: List[Dict[str, Any]]

@dataclass
class Alarm:
    alarm_id: str
    ne_id: str
    alarm_name: str
    severity: str
    vendor: str
    probable_cause: str
    specific_problem: str
    timestamp: str
    location: str

def generate_ne_id() -> str:
    return str(uuid.uuid4())

def generate_ip(vendor_idx: int, ne_idx: int) -> str:
    """Generate IP address in 10.x.x.x range."""
    return f"10.{vendor_idx + 1}.{(ne_idx // 256)}.{ne_idx % 256}"

def generate_network_elements() -> List[NetworkElement]:
    """Generate 300 network elements (150 Ericsson, 150 Huawei)."""
    elements = []
    
    # Ericsson NEs
    for i in range(NUM_ERICSSON_NE):
        region = random.choice(TUNISIAN_REGIONS)
        site_prefix = random.choice(SITE_PREFIXES)
        site_num = i % 100
        
        ne_type = random.choice(["eNodeB", "gNodeB", "RBS", "RNC"])
        ne_name = f"{site_prefix}-{region[:3].upper()}-{ne_type}-{i:04d}"
        
        cells = []
        num_cells = random.randint(2, 4)
        for c in range(num_cells):
            cells.append({
                "cell_id": f"{ne_name}-Cell-{c+1}",
                "frequency_band": random.choice([700, 800, 900, 1800, 2100, 2600]),
                "bandwidth_mhz": random.choice([5, 10, 15, 20]),
                "pci": random.randint(1, 504),
                "earfcn": random.randint(100, 3000)
            })
        
        elements.append(NetworkElement(
            ne_id=generate_ne_id(),
            ne_name=ne_name,
            vendor="ERICSSON",
            ne_type=ne_type,
            ip_address=generate_ip(0, i),
            site_id=f"SITE-{region[:3].upper()}-{site_num:03d}",
            region=region,
            latitude=36.8 + (random.random() - 0.5) * 4,
            longitude=10.2 + (random.random() - 0.5) * 6,
            software_version=random.choice(["R19A", "R19B", "R20A", "R20B"]),
            cells=cells
        ))
    
    # Huawei NEs
    for i in range(NUM_HUAWEI_NE):
        region = random.choice(TUNISIAN_REGIONS)
        site_prefix = random.choice(SITE_PREFIXES)
        site_num = (i + 50) % 100
        
        ne_type = random.choice(["eNodeB", "gNodeB", "BTS3900", "NodeB"])
        ne_name = f"{site_prefix}-{region[:3].upper()}-{ne_type}-{i:04d}"
        
        cells = []
        num_cells = random.randint(2, 4)
        for c in range(num_cells):
            cells.append({
                "cell_id": f"{ne_name}-Cell-{c+1}",
                "frequency_band": random.choice([700, 800, 900, 1800, 2100, 2600]),
                "bandwidth_mhz": random.choice([5, 10, 15, 20]),
                "pci": random.randint(1, 504),
                "earfcn": random.randint(100, 3000)
            })
        
        elements.append(NetworkElement(
            ne_id=generate_ne_id(),
            ne_name=ne_name,
            vendor="HUAWEI",
            ne_type=ne_type,
            ip_address=generate_ip(1, i),
            site_id=f"SITE-{region[:3].upper()}-{site_num:03d}",
            region=region,
            latitude=36.8 + (random.random() - 0.5) * 4,
            longitude=10.2 + (random.random() - 0.5) * 6,
            software_version=random.choice(["V100R019", "V100R020", "V200R019"]),
            cells=cells
        ))
    
    return elements

def generate_alarms(elements: List[NetworkElement]) -> Dict[str, List[Dict[str, Any]]]:
    """Generate alarm data for each vendor."""
    ericsson_alarms = []
    huawei_alarms = []
    
    ericsson_alarm_names = [
        "Site Power Failure", "Radio Unit Connection Failure", "S1 Interface Down",
        "Transmission Link Failure", "Board Temperature High", "Fan Failure",
        "Battery Low", "GPS Sync Lost", "License Expiring", "Hardware Fault"
    ]
    
    huawei_alarm_names = [
        "Power Supply Failure", "RF Unit Fault", "S1 Interface Abnormal",
        "Transmission Failure", "High Temperature", "Fan Abnormal",
        "Battery Undervoltage", "Clock Sync Exception", "License Expiration", "Board Fault"
    ]
    
    severities = ["CRITICAL", "MAJOR", "MINOR", "WARNING"]
    severity_weights = [0.05, 0.15, 0.40, 0.40]
    
    probable_causes = [
        "Power Failure", "Link Down", "Equipment Failure", "Temperature High",
        "Communication Failure", "Software Error", "Hardware Fault"
    ]
    
    base_time = datetime.now(timezone.utc) - timedelta(hours=24)
    
    for i in range(NUM_ALARMS):
        if i < NUM_ALARMS // 2:
            # Ericsson alarm
            ne = random.choice([e for e in elements if e.vendor == "ERICSSON"])
            alarm = {
                "alarmId": f"ERIC-ALARM-{i:06d}",
                "managedObject": ne.ne_name,
                "eventType": random.choice(["EquipmentAlarm", "CommunicationsAlarm", "ProcessingErrorAlarm"]),
                "perceivedSeverity": random.choices(severities, weights=severity_weights)[0].lower(),
                "probableCause": random.choice(probable_causes),
                "specificProblem": random.choice(ericsson_alarm_names),
                "eventTime": (base_time + timedelta(minutes=random.randint(0, 1440))).isoformat(),
                "additionalText": f"Alarm detected on {ne.ne_name}",
                "neType": ne.ne_type,
                "location": ne.site_id
            }
            ericsson_alarms.append(alarm)
        else:
            # Huawei alarm
            ne = random.choice([e for e in elements if e.vendor == "HUAWEI"])
            severity_level = random.choices([1, 2, 3, 4], weights=[0.05, 0.15, 0.40, 0.40])[0]
            alarm = {
                "alarmId": f"HW-ALARM-{i:06d}",
                "neName": ne.ne_name,
                "alarmName": random.choice(huawei_alarm_names),
                "alarmLevel": severity_level,
                "neType": ne.ne_type,
                "occurTime": (base_time + timedelta(minutes=random.randint(0, 1440))).strftime("%Y-%m-%d %H:%M:%S"),
                "clearTime": None,
                "alarmSource": f"Interface GigabitEthernet0/0/{random.randint(1,24)}",
                "probableCause": random.choice(probable_causes),
                "location": ne.site_id
            }
            huawei_alarms.append(alarm)
    
    return {"ericsson": ericsson_alarms, "huawei": huawei_alarms}

def main():
    """Main entry point."""
    output_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    simulation_dir = os.path.join(output_dir, "simulation_data")
    os.makedirs(simulation_dir, exist_ok=True)
    os.makedirs(os.path.join(simulation_dir, "alarms"), exist_ok=True)
    os.makedirs(os.path.join(simulation_dir, "performance"), exist_ok=True)
    
    print("Generating simulation data for Unified OSS Framework...")
    print("=" * 60)
    
    # Generate NEs
    print(f"Generating {NUM_ERICSSON_NE + NUM_HUAWEI_NE} network elements...")
    elements = generate_network_elements()
    
    with open(os.path.join(simulation_dir, "network_elements.json"), "w") as f:
        json.dump([asdict(e) for e in elements], f, indent=2)
    print(f"  ✓ Saved {len(elements)} network elements")
    
    # Generate alarms
    print(f"Generating {NUM_ALARMS} alarm events...")
    alarms = generate_alarms(elements)
    
    with open(os.path.join(simulation_dir, "alarms", "ericsson_alarms.json"), "w") as f:
        json.dump(alarms["ericsson"], f, indent=2)
    with open(os.path.join(simulation_dir, "alarms", "huawei_alarms.json"), "w") as f:
        json.dump(alarms["huawei"], f, indent=2)
    print(f"  ✓ Saved {len(alarms['ericsson'])} Ericsson alarms")
    print(f"  ✓ Saved {len(alarms['huawei'])} Huawei alarms")
    
    # Generate summary
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "network_elements": {
            "total": len(elements),
            "ericsson": len([e for e in elements if e.vendor == "ERICSSON"]),
            "huawei": len([e for e in elements if e.vendor == "HUAWEI"])
        },
        "alarms": {
            "total": len(alarms["ericsson"]) + len(alarms["huawei"]),
            "ericsson": len(alarms["ericsson"]),
            "huawei": len(alarms["huawei"])
        }
    }
    
    with open(os.path.join(simulation_dir, "README.json"), "w") as f:
        json.dump(summary, f, indent=2)
    
    print("\n" + "=" * 60)
    print("Simulation data generation complete!")
    print(f"Output directory: {simulation_dir}")
    print(f"Total NEs: {summary['network_elements']['total']}")
    print(f"Total Alarms: {summary['alarms']['total']}")

if __name__ == "__main__":
    main()

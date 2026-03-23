#!/usr/bin/env python3
"""
Alarm Generator for Unified OSS Framework Simulation.

Generates realistic alarm patterns with:
- Temporal correlation (cascade failures)
- Topological correlation (site-level failures)
- Multiple severity levels
- Cross-vendor alarm types
"""

import json
import random
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from pathlib import Path


@dataclass
class Alarm:
    """Alarm representation."""
    
    alarm_id: str
    alarm_name: str
    alarm_type: str
    severity: str
    vendor: str
    ne_id: str
    ne_name: str
    ne_type: str
    timestamp: str
    probable_cause: str
    specific_problem: str
    affected_resource: str
    additional_text: str
    clearance_status: str = "ACTIVE"
    cleared_timestamp: Optional[str] = None
    correlation_id: Optional[str] = None
    root_cause_alarm_id: Optional[str] = None
    service_impact: str = "NONE"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class AlarmGenerator:
    """
    Generates realistic alarm patterns for simulation.
    
    Creates alarms with:
    - Realistic severity distribution (10% critical, 20% major, 40% minor, 30% warning)
    - Temporal correlation patterns (cascade failures)
    - Topological correlation patterns (site-level failures)
    """
    
    SEVERITY_DISTRIBUTION = {
        "CRITICAL": 0.10,
        "MAJOR": 0.20,
        "MINOR": 0.40,
        "WARNING": 0.30,
    }
    
    ERICSSON_ALARM_TYPES = {
        "EQUIPMENT_ALARM": {
            "alarms": [
                ("A1001", "Radio Unit Hardware Failure", "HARDWARE_FAILURE"),
                ("A1002", "Power Supply Unit Failure", "POWER_FAILURE"),
                ("A1003", "Fan Module Failure", "ENVIRONMENTAL_ISSUE"),
                ("A1004", "Board Temperature High", "ENVIRONMENTAL_ISSUE"),
                ("A1005", "Optical Module Failure", "HARDWARE_FAILURE"),
            ]
        },
        "COMMUNICATION_ALARM": {
            "alarms": [
                ("A2001", "S1 Interface Down", "NETWORK_FAILURE"),
                ("A2002", "X2 Connection Lost", "COMMUNICATION_FAILURE"),
                ("A2003", "Transmission Link Failure", "TRANSPORT_FAILURE"),
                ("A2004", "GNSS Sync Lost", "TIMING_FAILURE"),
            ]
        },
        "PROCESSING_ALARM": {
            "alarms": [
                ("A3001", "CPU Overload", "RESOURCE_EXHAUSTION"),
                ("A3002", "Memory Usage High", "RESOURCE_EXHAUSTION"),
                ("A3003", "Process Restart", "SOFTWARE_ERROR"),
                ("A3004", "License Expiry Warning", "LICENSE_EXPIRY"),
            ]
        },
        "QOS_ALARM": {
            "alarms": [
                ("A4001", "High Packet Loss", "PERFORMANCE_DEGRADATION"),
                ("A4002", "High Latency Detected", "PERFORMANCE_DEGRADATION"),
                ("A4003", "Throughput Degradation", "SERVICE_DEGRADATION"),
            ]
        },
    }
    
    HUAWEI_ALARM_TYPES = {
        "EQUIPMENT_ALARM": {
            "alarms": [
                ("0x0411FFFF", "RF Unit Hardware Fault", "HARDWARE_FAILURE"),
                ("0x0412FFFF", "Power Module Fault", "POWER_FAILURE"),
                ("0x0413FFFF", "Fan Module Fault", "ENVIRONMENTAL_ISSUE"),
                ("0x0414FFFF", "Board Overtemperature", "ENVIRONMENTAL_ISSUE"),
            ]
        },
        "COMMUNICATION_ALARM": {
            "alarms": [
                ("0x0421FFFF", "S1 Interface Disconnected", "NETWORK_FAILURE"),
                ("0x0422FFFF", "X2 Link Failure", "COMMUNICATION_FAILURE"),
                ("0x0423FFFF", "Transmission Link Down", "TRANSPORT_FAILURE"),
                ("0x0424FFFF", "Clock Sync Lost", "TIMING_FAILURE"),
            ]
        },
        "PROCESSING_ALARM": {
            "alarms": [
                ("0x0431FFFF", "CPU Overload", "RESOURCE_EXHAUSTION"),
                ("0x0432FFFF", "Memory Overload", "RESOURCE_EXHAUSTION"),
                ("0x0433FFFF", "Process Abnormal", "SOFTWARE_ERROR"),
            ]
        },
    }
    
    PROBABLE_CAUSES = [
        "HARDWARE_FAILURE", "SOFTWARE_ERROR", "NETWORK_FAILURE",
        "CONFIGURATION_ERROR", "PERFORMANCE_DEGRADATION", "ENVIRONMENTAL_ISSUE",
        "SECURITY_INCIDENT", "RESOURCE_EXHAUSTION", "COMMUNICATION_FAILURE",
        "POWER_FAILURE", "TIMING_FAILURE", "TRANSPORT_FAILURE",
        "RADIO_FAILURE", "LICENSE_EXPIRY", "CAPACITY_LIMIT",
    ]
    
    def __init__(self, topology_path: str, seed: int = 42):
        """Initialize alarm generator with network topology."""
        random.seed(seed)
        
        with open(topology_path, "r") as f:
            self.topology = json.load(f)
        
        self.elements = self.topology["elements"]
        self.alarms: List[Alarm] = []
        
    def _get_severity(self) -> str:
        """Get random severity based on distribution."""
        r = random.random()
        cumulative = 0.0
        
        for severity, prob in self.SEVERITY_DISTRIBUTION.items():
            cumulative += prob
            if r <= cumulative:
                return severity
        
        return "MINOR"
    
    def _get_alarm_template(self, vendor: str) -> tuple:
        """Get random alarm template for vendor."""
        if vendor == "ERICSSON":
            alarm_types = self.ERICSSON_ALARM_TYPES
        else:
            alarm_types = self.HUAWEI_ALARM_TYPES
        
        category = random.choice(list(alarm_types.keys()))
        alarm_list = alarm_types[category]["alarms"]
        return random.choice(alarm_list)
    
    def _get_element(self, ne_type: Optional[str] = None, vendor: Optional[str] = None) -> Dict:
        """Get random network element."""
        candidates = self.elements
        
        if ne_type:
            candidates = [e for e in candidates if e["ne_type"] == ne_type]
        if vendor:
            candidates = [e for e in candidates if e["vendor"] == vendor]
        
        return random.choice(candidates) if candidates else random.choice(self.elements)
    
    def generate_single_alarm(self, timestamp: datetime) -> Alarm:
        """Generate a single alarm."""
        element = self._get_element()
        vendor = element["vendor"]
        
        alarm_code, alarm_name, probable_cause = self._get_alarm_template(vendor)
        severity = self._get_severity()
        
        alarm = Alarm(
            alarm_id=str(uuid.uuid4()),
            alarm_name=alarm_name,
            alarm_type=alarm_code,
            severity=severity,
            vendor=vendor,
            ne_id=element["ne_id"],
            ne_name=element["ne_name"],
            ne_type=element["ne_type"],
            timestamp=timestamp.isoformat(),
            probable_cause=probable_cause,
            specific_problem=f"{alarm_name} detected on {element['ne_name']}",
            affected_resource=f"/network/{vendor}/{element['ne_type']}/{element['ne_id']}",
            additional_text=f"Alarm {alarm_code} raised at {timestamp.isoformat()}",
            service_impact=random.choice(["NONE", "DEGRADED", "AFFECTED"]) if severity in ["CRITICAL", "MAJOR"] else "NONE",
        )
        
        return alarm
    
    def generate_cascade_failure(self, start_timestamp: datetime, cascade_size: int = 5) -> List[Alarm]:
        """Generate cascade failure scenario (temporal correlation)."""
        alarms = []
        
        # Root cause alarm
        root_alarm = self.generate_single_alarm(start_timestamp)
        root_alarm.severity = "CRITICAL"
        root_alarm.correlation_id = str(uuid.uuid4())
        alarms.append(root_alarm)
        
        # Follow-on alarms
        element = next((e for e in self.elements if e["ne_id"] == root_alarm.ne_id), None)
        if element and element.get("connections"):
            connected_elements = [e for e in self.elements if e["ne_id"] in element["connections"]]
            
            for i, conn_element in enumerate(random.sample(connected_elements, min(cascade_size - 1, len(connected_elements)))):
                timestamp = start_timestamp + timedelta(seconds=random.randint(5, 60))
                alarm_code, alarm_name, probable_cause = self._get_alarm_template(conn_element["vendor"])
                
                alarm = Alarm(
                    alarm_id=str(uuid.uuid4()),
                    alarm_name=alarm_name,
                    alarm_type=alarm_code,
                    severity=random.choice(["MAJOR", "MINOR"]),
                    vendor=conn_element["vendor"],
                    ne_id=conn_element["ne_id"],
                    ne_name=conn_element["ne_name"],
                    ne_type=conn_element["ne_type"],
                    timestamp=timestamp.isoformat(),
                    probable_cause=probable_cause,
                    specific_problem=f"{alarm_name} - Cascaded from {root_alarm.ne_name}",
                    affected_resource=f"/network/{conn_element['vendor']}/{conn_element['ne_type']}/{conn_element['ne_id']}",
                    additional_text=f"Secondary alarm following root cause at {root_alarm.ne_name}",
                    correlation_id=root_alarm.correlation_id,
                    root_cause_alarm_id=root_alarm.alarm_id,
                )
                alarms.append(alarm)
        
        return alarms
    
    def generate_site_failure(self, start_timestamp: datetime, site_size: int = 4) -> List[Alarm]:
        """Generate site-level failure (topological correlation)."""
        alarms = []
        correlation_id = str(uuid.uuid4())
        
        # Get elements at same location
        location = random.choice(list(set(e["location"] for e in self.elements)))
        site_elements = [e for e in self.elements if e["location"] == location]
        site_elements = random.sample(site_elements, min(site_size, len(site_elements)))
        
        for i, element in enumerate(site_elements):
            timestamp = start_timestamp + timedelta(seconds=i * random.randint(1, 10))
            alarm_code, alarm_name, probable_cause = self._get_alarm_template(element["vendor"])
            
            severity = "CRITICAL" if i == 0 else random.choice(["MAJOR", "MINOR"])
            
            alarm = Alarm(
                alarm_id=str(uuid.uuid4()),
                alarm_name=alarm_name if i > 0 else f"Site Power Failure - {location}",
                alarm_type=alarm_code if i > 0 else "SITE_POWER_FAIL",
                severity=severity,
                vendor=element["vendor"],
                ne_id=element["ne_id"],
                ne_name=element["ne_name"],
                ne_type=element["ne_type"],
                timestamp=timestamp.isoformat(),
                probable_cause="POWER_FAILURE" if i == 0 else probable_cause,
                specific_problem=f"Site-level failure at {location}",
                affected_resource=f"/network/{element['vendor']}/{element['ne_type']}/{element['ne_id']}",
                additional_text=f"Alarm at site {location} - correlated failure",
                correlation_id=correlation_id,
                service_impact="AFFECTED",
            )
            alarms.append(alarm)
        
        return alarms
    
    def generate_alarms(self, 
                        total_count: int = 1000,
                        cascade_ratio: float = 0.15,
                        site_failure_ratio: float = 0.10,
                        start_time: Optional[datetime] = None,
                        duration_hours: int = 24) -> List[Alarm]:
        """Generate complete alarm dataset."""
        self.alarms = []
        
        if start_time is None:
            start_time = datetime.utcnow() - timedelta(hours=duration_hours)
        
        # Calculate counts
        cascade_count = int(total_count * cascade_ratio)
        site_failure_count = int(total_count * site_failure_ratio)
        single_count = total_count - cascade_count - site_failure_count
        
        # Generate single alarms
        for _ in range(single_count):
            timestamp = start_time + timedelta(seconds=random.randint(0, duration_hours * 3600))
            self.alarms.append(self.generate_single_alarm(timestamp))
        
        # Generate cascade failures
        for _ in range(cascade_count // 5):  # Each cascade has ~5 alarms
            timestamp = start_time + timedelta(seconds=random.randint(0, duration_hours * 3600))
            self.alarms.extend(self.generate_cascade_failure(timestamp))
        
        # Generate site failures
        for _ in range(site_failure_count // 4):  # Each site failure has ~4 alarms
            timestamp = start_time + timedelta(seconds=random.randint(0, duration_hours * 3600))
            self.alarms.extend(self.generate_site_failure(timestamp))
        
        # Clear some alarms
        for alarm in random.sample(self.alarms, int(len(self.alarms) * 0.3)):
            alarm.clearance_status = "CLEARED"
            alarm.cleared_timestamp = (
                datetime.fromisoformat(alarm.timestamp) + 
                timedelta(minutes=random.randint(5, 120))
            ).isoformat()
        
        # Sort by timestamp
        self.alarms.sort(key=lambda a: a.timestamp)
        
        return self.alarms
    
    def export_to_json(self, output_path: str) -> None:
        """Export alarms to JSON file."""
        data = {
            "generated_at": datetime.utcnow().isoformat(),
            "total_alarms": len(self.alarms),
            "statistics": {
                "by_severity": {},
                "by_vendor": {},
                "by_type": {},
                "by_clearance_status": {},
                "correlated_count": sum(1 for a in self.alarms if a.correlation_id),
            },
            "alarms": [a.to_dict() for a in self.alarms],
        }
        
        for alarm in self.alarms:
            data["statistics"]["by_severity"][alarm.severity] = data["statistics"]["by_severity"].get(alarm.severity, 0) + 1
            data["statistics"]["by_vendor"][alarm.vendor] = data["statistics"]["by_vendor"].get(alarm.vendor, 0) + 1
            data["statistics"]["by_type"][alarm.alarm_type] = data["statistics"]["by_type"].get(alarm.alarm_type, 0) + 1
            data["statistics"]["by_clearance_status"][alarm.clearance_status] = data["statistics"]["by_clearance_status"].get(alarm.clearance_status, 0) + 1
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        
        print(f"Exported {len(self.alarms)} alarms to {output_path}")
        print(f"Statistics:")
        print(f"  By Severity: {data['statistics']['by_severity']}")
        print(f"  By Vendor: {data['statistics']['by_vendor']}")
        print(f"  Correlated: {data['statistics']['correlated_count']}")


def main():
    """Main entry point."""
    generator = AlarmGenerator("simulation-data/network_topology.json", seed=42)
    generator.generate_alarms(total_count=1000, duration_hours=24)
    generator.export_to_json("simulation-data/alarms.json")


if __name__ == "__main__":
    main()

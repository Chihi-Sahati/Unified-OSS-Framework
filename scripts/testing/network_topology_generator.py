#!/usr/bin/env python3
"""
Network Topology Generator for Unified OSS Framework Simulation.

Generates realistic network topology with 300 network elements
including RAN (eNodeB, gNodeB) and CORE (MME, SGW, PGW, AMF, SMF, UPF).
"""

import json
import random
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path


@dataclass
class NetworkElement:
    """Network element representation."""
    
    ne_id: str
    ne_name: str
    ne_type: str
    vendor: str
    ip_address: str
    location: str
    region: str
    latitude: float
    longitude: float
    mcc: int
    mnc: int
    status: str = "OPERATIONAL"
    software_version: str = ""
    capabilities: List[str] = field(default_factory=list)
    connections: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class NetworkTopologyGenerator:
    """
    Generates realistic network topology for simulation.
    
    Creates 300 network elements with proper distribution:
    - 200 RAN elements (eNodeB, gNodeB, BTS, NodeB)
    - 100 CORE elements (MME, SGW, PGW, HSS, AMF, SMF, UPF, UDM, NRF)
    """
    
    VENDORS = ["ERICSSON", "HUAWEI"]
    
    RAN_TYPES = {
        "ENODEB": {"weight": 40, "tech": "4G"},
        "GNODEB": {"weight": 30, "tech": "5G"},
        "NODEB": {"weight": 15, "tech": "3G"},
        "BTS": {"weight": 15, "tech": "2G"},
    }
    
    CORE_TYPES = {
        "MME": {"weight": 15, "vendor": "BOTH"},
        "SGW": {"weight": 12, "vendor": "BOTH"},
        "PGW": {"weight": 12, "vendor": "BOTH"},
        "HSS": {"weight": 10, "vendor": "BOTH"},
        "PCRF": {"weight": 8, "vendor": "BOTH"},
        "AMF": {"weight": 10, "vendor": "BOTH"},
        "SMF": {"weight": 10, "vendor": "BOTH"},
        "UPF": {"weight": 10, "vendor": "BOTH"},
        "UDM": {"weight": 5, "vendor": "BOTH"},
        "NRF": {"weight": 3, "vendor": "BOTH"},
        "DRA": {"weight": 3, "vendor": "HUAWEI"},
        "STP": {"weight": 2, "vendor": "HUAWEI"},
    }
    
    REGIONS = {
        "NORTH": {"cities": ["BEIJING", "TIANJIN", "SHIJIAZHUANG"], "lat_range": (39.0, 42.0), "lon_range": (115.0, 118.0)},
        "EAST": {"cities": ["SHANGHAI", "HANGZHOU", "NANJING"], "lat_range": (30.0, 33.0), "lon_range": (118.0, 122.0)},
        "SOUTH": {"cities": ["GUANGZHOU", "SHENZHEN", "FOSHAN"], "lat_range": (22.0, 24.0), "lon_range": (113.0, 115.0)},
        "WEST": {"cities": ["CHENGDU", "CHONGQING", "XIAN"], "lat_range": (29.0, 35.0), "lon_range": (103.0, 109.0)},
        "CENTRAL": {"cities": ["WUHAN", "ZHENGZHOU", "CHANGSHA"], "lat_range": (30.0, 35.0), "lon_range": (112.0, 116.0)},
    }
    
    def __init__(self, seed: int = 42):
        """Initialize generator with random seed."""
        random.seed(seed)
        self.elements: List[NetworkElement] = []
        self.mcc = 460  # China MCC
        
    def _generate_ip(self) -> str:
        """Generate random IP address."""
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    def _generate_ne_name(self, ne_type: str, region: str, index: int) -> str:
        """Generate network element name."""
        prefix = ne_type[:3].upper()
        return f"{prefix}-{region[:2].upper()}-{index:04d}"
    
    def _get_software_version(self, vendor: str, ne_type: str) -> str:
        """Get software version for vendor/element type."""
        if vendor == "ERICSSON":
            if ne_type in ["ENODEB", "GNODEB"]:
                return random.choice(["R21A", "R22A", "R23A"])
            else:
                return random.choice(["V17.0", "V18.0", "V19.0"])
        else:  # HUAWEI
            if ne_type in ["ENODEB", "GNODEB"]:
                return random.choice(["V100R015", "V100R016", "V100R017"])
            else:
                return random.choice(["V900R015", "V900R016", "V900R017"])
    
    def _get_capabilities(self, ne_type: str, vendor: str) -> List[str]:
        """Get capabilities for network element."""
        base_caps = ["NETCONF", "SNMP"]
        
        if ne_type in ["ENODEB", "GNODEB"]:
            base_caps.extend(["FLEX_MULTIPLEXER", "CARRIER_AGGREGATION", "MIMO"])
            if ne_type == "GNODEB":
                base_caps.extend(["NR_SA", "NR_NSA", "SLICE_SUPPORT"])
        elif ne_type == "MME":
            base_caps.extend(["S1AP", "S11", "S6A", "DIAMETER"])
        elif ne_type == "AMF":
            base_caps.extend(["N1", "N2", "N11", "SBI"])
        elif ne_type == "SMF":
            base_caps.extend(["N4", "N7", "SBI"])
        elif ne_type == "UPF":
            base_caps.extend(["N3", "N4", "N6", "N9"])
        
        return base_caps
    
    def generate_ran_elements(self, count: int = 200) -> List[NetworkElement]:
        """Generate RAN network elements."""
        elements = []
        
        # Calculate distribution by type
        total_weight = sum(t["weight"] for t in self.RAN_TYPES.values())
        type_counts = {}
        for ne_type, info in self.RAN_TYPES.items():
            type_counts[ne_type] = int(count * info["weight"] / total_weight)
        
        index = 1
        for ne_type, type_count in type_counts.items():
            for _ in range(type_count):
                region = random.choice(list(self.REGIONS.keys()))
                region_info = self.REGIONS[region]
                city = random.choice(region_info["cities"])
                vendor = random.choice(self.VENDORS)
                mnc = random.choice([0, 1, 2, 3])  # Major Chinese operators
                
                ne = NetworkElement(
                    ne_id=str(uuid.uuid4()),
                    ne_name=self._generate_ne_name(ne_type, region, index),
                    ne_type=ne_type,
                    vendor=vendor,
                    ip_address=self._generate_ip(),
                    location=city,
                    region=region,
                    latitude=random.uniform(*region_info["lat_range"]),
                    longitude=random.uniform(*region_info["lon_range"]),
                    mcc=self.mcc,
                    mnc=mnc,
                    software_version=self._get_software_version(vendor, ne_type),
                    capabilities=self._get_capabilities(ne_type, vendor),
                )
                elements.append(ne)
                index += 1
        
        return elements
    
    def generate_core_elements(self, count: int = 100) -> List[NetworkElement]:
        """Generate CORE network elements."""
        elements = []
        
        # Calculate distribution by type
        total_weight = sum(t["weight"] for t in self.CORE_TYPES.values())
        type_counts = {}
        for ne_type, info in self.CORE_TYPES.items():
            type_counts[ne_type] = max(1, int(count * info["weight"] / total_weight))
        
        index = 1
        for ne_type, type_count in type_counts.items():
            info = self.CORE_TYPES[ne_type]
            
            for _ in range(type_count):
                region = random.choice(list(self.REGIONS.keys()))
                region_info = self.REGIONS[region]
                city = random.choice(region_info["cities"])
                
                # Vendor assignment
                if info["vendor"] == "HUAWEI":
                    vendor = "HUAWEI"
                elif info["vendor"] == "ERICSSON":
                    vendor = "ERICSSON"
                else:
                    vendor = random.choice(self.VENDORS)
                
                ne = NetworkElement(
                    ne_id=str(uuid.uuid4()),
                    ne_name=self._generate_ne_name(ne_type, region, index),
                    ne_type=ne_type,
                    vendor=vendor,
                    ip_address=self._generate_ip(),
                    location=city,
                    region=region,
                    latitude=random.uniform(*region_info["lat_range"]),
                    longitude=random.uniform(*region_info["lon_range"]),
                    mcc=self.mcc,
                    mnc=0,  # Core elements serve all MNCs
                    software_version=self._get_software_version(vendor, ne_type),
                    capabilities=self._get_capabilities(ne_type, vendor),
                )
                elements.append(ne)
                index += 1
        
        return elements
    
    def establish_connections(self, elements: List[NetworkElement]) -> None:
        """Establish logical connections between elements."""
        ran_elements = [e for e in elements if e.ne_type in self.RAN_TYPES]
        core_elements = [e for e in elements if e.ne_type in self.CORE_TYPES]
        
        # Connect RAN to CORE
        for ran in ran_elements:
            # Find matching MME/AMF based on region and vendor
            mme_candidates = [e for e in core_elements if e.ne_type == "MME" and 
                             (e.region == ran.region or e.vendor == ran.vendor)]
            amf_candidates = [e for e in core_elements if e.ne_type == "AMF" and 
                             (e.region == ran.region or e.vendor == ran.vendor)]
            
            if ran.ne_type in ["GNODEB"] and amf_candidates:
                ran.connections.extend([e.ne_id for e in random.sample(amf_candidates, min(2, len(amf_candidates)))])
            elif mme_candidates:
                ran.connections.extend([e.ne_id for e in random.sample(mme_candidates, min(2, len(mme_candidates)))])
        
        # Connect CORE elements
        mme_list = [e for e in core_elements if e.ne_type == "MME"]
        sgw_list = [e for e in core_elements if e.ne_type == "SGW"]
        pgw_list = [e for e in core_elements if e.ne_type == "PGW"]
        hss_list = [e for e in core_elements if e.ne_type == "HSS"]
        amf_list = [e for e in core_elements if e.ne_type == "AMF"]
        smf_list = [e for e in core_elements if e.ne_type == "SMF"]
        upf_list = [e for e in core_elements if e.ne_type == "UPF"]
        udm_list = [e for e in core_elements if e.ne_type == "UDM"]
        nrf_list = [e for e in core_elements if e.ne_type == "NRF"]
        
        # EPC connections
        for mme in mme_list:
            mme.connections.extend([e.ne_id for e in random.sample(sgw_list, min(2, len(sgw_list)))])
            mme.connections.extend([e.ne_id for e in random.sample(hss_list, min(2, len(hss_list)))])
        
        for sgw in sgw_list:
            sgw.connections.extend([e.ne_id for e in random.sample(pgw_list, min(2, len(pgw_list)))])
        
        # 5GC connections
        for amf in amf_list:
            amf.connections.extend([e.ne_id for e in random.sample(smf_list, min(2, len(smf_list)))])
            amf.connections.extend([e.ne_id for e in random.sample(udm_list, min(1, len(udm_list)))])
            amf.connections.extend([e.ne_id for e in nrf_list])
        
        for smf in smf_list:
            smf.connections.extend([e.ne_id for e in random.sample(upf_list, min(3, len(upf_list)))])
            smf.connections.extend([e.ne_id for e in nrf_list])
        
        for upf in upf_list:
            upf.connections.extend([e.ne_id for e in nrf_list])
    
    def generate_topology(self, total_elements: int = 300) -> List[NetworkElement]:
        """Generate complete network topology."""
        ran_count = int(total_elements * 0.67)  # ~200 RAN elements
        core_count = total_elements - ran_count  # ~100 CORE elements
        
        self.elements = self.generate_ran_elements(ran_count)
        self.elements.extend(self.generate_core_elements(core_count))
        
        self.establish_connections(self.elements)
        
        return self.elements
    
    def export_to_json(self, output_path: str) -> None:
        """Export topology to JSON file."""
        data = {
            "generated_at": datetime.utcnow().isoformat(),
            "total_elements": len(self.elements),
            "statistics": {
                "by_vendor": {},
                "by_type": {},
                "by_region": {},
            },
            "elements": [e.to_dict() for e in self.elements],
        }
        
        # Calculate statistics
        for e in self.elements:
            data["statistics"]["by_vendor"][e.vendor] = data["statistics"]["by_vendor"].get(e.vendor, 0) + 1
            data["statistics"]["by_type"][e.ne_type] = data["statistics"]["by_type"].get(e.ne_type, 0) + 1
            data["statistics"]["by_region"][e.region] = data["statistics"]["by_region"].get(e.region, 0) + 1
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        
        print(f"Exported {len(self.elements)} network elements to {output_path}")
        print(f"Statistics:")
        print(f"  By Vendor: {data['statistics']['by_vendor']}")
        print(f"  By Type: {data['statistics']['by_type']}")
        print(f"  By Region: {data['statistics']['by_region']}")


def main():
    """Main entry point."""
    generator = NetworkTopologyGenerator(seed=42)
    generator.generate_topology(total_elements=300)
    generator.export_to_json("simulation-data/network_topology.json")


if __name__ == "__main__":
    main()

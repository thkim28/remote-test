import csv
import random
from pathlib import Path

COLUMNS = [
    "asset_id",
    "label",
    "nmap_tcpdump_text",
    "bytes_in",
    "bytes_out",
    "pkts_in",
    "pkts_out",
    "flows_5m",
    "uniq_dst",
    "diurnal_ratio",
    "server_role_ratio",
    "port_22",
    "port_80",
    "port_443",
    "proto_tcp",
    "proto_udp",
]

LABELS = ["server", "workstation", "iot", "network_device"]
BANNERS = [
    "22/tcp open ssh OpenSSH 8.2p1",
    "80/tcp open http Apache httpd 2.4.41",
    "443/tcp open https nginx 1.18.0",
    "53/udp open domain BIND 9.16.1",
    "21/tcp open ftp vsftpd 3.0.3",
    "3306/tcp open mysql MySQL 5.7.31",
    "1883/tcp open mqtt Mosquitto 1.6.9",
    "161/udp open snmp SNMPv2c",
    "8080/tcp open http-proxy Squid 4.10",
    "5900/tcp open vnc VNC protocol 3.8",
]


def generate_dummy_data(path: Path, rows: int = 100) -> None:
    """Generate a CSV file with synthetic asset data."""
    random.seed(42)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(COLUMNS)
        for i in range(rows):
            asset_id = f"asset_{i + 1:03d}"
            label = LABELS[i % len(LABELS)]
            banner = random.choice(BANNERS)
            bytes_in = random.randint(1_000_000, 1_000_000_000)
            bytes_out = random.randint(1_000_000, 1_000_000_000)
            pkts_in = random.randint(1_000, 1_000_000)
            pkts_out = random.randint(1_000, 1_000_000)
            flows_5m = random.randint(0, 500)
            uniq_dst = random.randint(1, 100)
            diurnal_ratio = round(random.uniform(0, 1), 3)
            server_role_ratio = round(random.uniform(0, 1), 3)
            port_22 = random.randint(0, 1)
            port_80 = random.randint(0, 1)
            port_443 = random.randint(0, 1)
            proto_tcp = random.randint(0, 1)
            proto_udp = random.randint(0, 1)
            writer.writerow([
                asset_id,
                label,
                banner,
                bytes_in,
                bytes_out,
                pkts_in,
                pkts_out,
                flows_5m,
                uniq_dst,
                diurnal_ratio,
                server_role_ratio,
                port_22,
                port_80,
                port_443,
                proto_tcp,
                proto_udp,
            ])


def validate_csv(path: Path) -> None:
    """Validate header, missing values, and data types of the CSV."""
    with path.open() as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != COLUMNS:
            raise ValueError(f"Invalid header: {reader.fieldnames}")
        for line_no, row in enumerate(reader, start=2):
            for col in COLUMNS:
                if row[col] in ("", None):
                    raise ValueError(f"Missing value in column {col} at line {line_no}")
            int_cols = [
                "bytes_in",
                "bytes_out",
                "pkts_in",
                "pkts_out",
                "flows_5m",
                "uniq_dst",
                "port_22",
                "port_80",
                "port_443",
                "proto_tcp",
                "proto_udp",
            ]
            float_cols = ["diurnal_ratio", "server_role_ratio"]
            for col in int_cols:
                int(row[col])
            for col in float_cols:
                float(row[col])


if __name__ == "__main__":
    data_path = Path("data/sample_assets.csv")
    generate_dummy_data(data_path)
    validate_csv(data_path)
    row_count = sum(1 for _ in open(data_path)) - 1
    print(f"Generated {data_path} with {row_count} rows. Validation passed.")

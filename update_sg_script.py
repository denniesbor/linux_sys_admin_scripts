#!/usr/bin/env python3
import subprocess
import json
import os
from dotenv import load_dotenv

load_dotenv()

# Replace with your actual values:
AWS_PROFILE = "default"              # or a named profile if not "default"
SEC_GROUP_ID = os.getenv("SECURITY_GROUP_ID")          # The Security Group ID that holds both rules
RULE_ID_SSH = os.getenv("RULE_ID_SSH")       # Security Group Rule ID for SSH
RULE_ID_UDP = os.getenv("RULE_ID_UDP")       # Security Group Rule ID for WireGuard
DESCRIPTION = "Auto-Updated by Script"  # Any description you want
LAST_IP_FILE = os.path.expanduser("~/Desktop/mosepro/.last_ip")

def get_public_ip():
    """Return the current public IPv4 address as a string, or None if failure."""
    try:
        ip = subprocess.check_output(["curl", "-4", "-s", "https://checkip.amazonaws.com"])
        return ip.decode("utf-8").strip()
    except subprocess.CalledProcessError as e:
        print("Error retrieving public IP:", e)
        return None

def read_last_ip():
    """Return the previously stored IP if it exists, else None."""
    if os.path.exists(LAST_IP_FILE):
        with open(LAST_IP_FILE, "r") as f:
            return f.read().strip()
    return None

def write_last_ip(ip):
    """Write the current IP to file for future checks."""
    with open(LAST_IP_FILE, "w") as f:
        f.write(ip)

def update_sg_rules(ip):
    """
    Modify both the SSH (tcp/22) and WireGuard (udp/51820) rule IDs to the new IP (ip/32).
    """
    # Build the JSON array of rules to modify
    rules_data = [
        {
            "SecurityGroupRuleId": RULE_ID_SSH,
            "SecurityGroupRule": {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "CidrIpv4": f"{ip}/32",
                "Description": DESCRIPTION
            }
        },
        {
            "SecurityGroupRuleId": RULE_ID_UDP,
            "SecurityGroupRule": {
                "IpProtocol": "udp",
                "FromPort": 51820,
                "ToPort": 51820,
                "CidrIpv4": f"{ip}/32",
                "Description": DESCRIPTION
            }
        }
    ]

    rules_json = json.dumps(rules_data)

    cmd = [
        "aws", "ec2", "modify-security-group-rules",
        "--group-id", SEC_GROUP_ID,
        "--security-group-rules", rules_json
    ]
    if AWS_PROFILE != "default":
        cmd.extend(["--profile", AWS_PROFILE])

    try:
        subprocess.run(cmd, check=True)
        print(f"Updated rules for SSH and UDP to {ip}/32 in SG {SEC_GROUP_ID}.")
    except subprocess.CalledProcessError as e:
        print(f"Error updating security group rules: {e}")

def main():
    current_ip = get_public_ip()
    if not current_ip:
        print("Failed to retrieve public IP. Exiting.")
        return

    last_ip = read_last_ip()
    if current_ip == last_ip:
        print(f"IP unchanged ({current_ip}). No update needed.")
    else:
        print(f"IP changed from {last_ip} to {current_ip}. Updating SG rules...")
        update_sg_rules(current_ip)
        write_last_ip(current_ip)

if __name__ == "__main__":
    main()

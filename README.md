# Enhancing Security in Software-Defined Networks Using Machine Learning to Detect and Classify DDoS Attacks

This project presents a Machine Learning-based security solution for Software-Defined Networks (SDNs) that detects and classifies DDoS (Distributed Denial of Service) attacks using traffic analysis from `.pcap` files.

## Overview

The increasing complexity of modern network threats calls for intelligent, adaptive defense mechanisms. This project integrates a machine learning classifier with SDN architecture to automatically detect malicious traffic and dynamically react by applying security policies to block or redirect high-risk IP addresses.

## Project Structure

- **PCAP Files**  
  - `normal_traffic2.pcap` – Captured normal traffic  
  - `single_node_attack_traffic.pcap` – Captured DDoS traffic (e.g., SYN flood)

- **ML Model**  
  - Built using `XGBoost` classifier  
  - Trained on extracted features from `.pcap` files  
  - Predicts whether a given packet belongs to normal or attack traffic

- **Feature Set**
  - Packet Length  
  - Protocol Type  
  - Time-To-Live (TTL)  
  - Source IP (converted to category)  
  - Destination IP (converted to category)

- **Risk Classification**
  - High Risk IPs → Blocked at SDN firewall via flow rules  
  - Medium Risk IPs → Redirected to CAPTCHA verification  
  - Low Risk IPs → Logged and monitored

## How It Works

1. Extracts features from `.pcap` files using Scapy.  
2. Trains an ML model using XGBoost with realistic hyperparameters.  
3. Evaluates model accuracy, precision, recall, and F1-score.  
4. Analyzes source IPs to determine their risk level based on packet volume.  
5. Generates appropriate mitigation actions:
   - High Risk → Flow rule to drop packets
   - Medium Risk → Redirect to CAPTCHA IP
   - Visualizations using Seaborn and Matplotlib

## Output Includes

- Model Accuracy Report  
- Confusion Matrix  
- Attack Distribution Chart  
- Top 10 Malicious IPs with Risk Levels  
- Suggested `ovs-ofctl` commands to apply mitigation rules

## Example Commands (for Mininet/OpenFlow switches)

```bash
# Block High-Risk IP
sudo ovs-ofctl add-flow s1 "priority=100,ip,nw_src=10.0.0.5,actions=drop"

# Redirect Medium-Risk IP to CAPTCHA page
sudo ovs-ofctl add-flow s1 "priority=90,ip,nw_src=10.0.0.8,actions=mod_nw_dst:10.0.0.100,output:1"

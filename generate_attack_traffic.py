#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import random
import os
import subprocess
from threading import Thread, Event

# Global stop event for coordinating threads
stop_event = Event()

def generate_attack_traffic(net):
    # Kill any existing tcpdump processes
    os.system('sudo pkill -f tcpdump')
    time.sleep(1)
    
    # Create a dedicated directory with proper permissions
    capture_dir = '/tmp/mininet_capture'
    os.system(f'sudo rm -rf {capture_dir}')
    os.system(f'sudo mkdir -p {capture_dir}')
    os.system(f'sudo chmod 777 {capture_dir}')
    
    capture_file = f'{capture_dir}/ddos_attack_traffic.pcap'
    
    # Start tcpdump without rotation options
    info("*** Starting tcpdump to capture attack traffic\n")
    tcpdump_cmd = f'sudo tcpdump -i any -U -w {capture_file} port not 22'
    
    # Start tcpdump in a separate process and redirect output
    with open(f'{capture_dir}/tcpdump.log', 'w') as log_file:
        tcpdump_process = subprocess.Popen(
            tcpdump_cmd, 
            shell=True,
            stdout=log_file,
            stderr=log_file
        )
    
    # Give tcpdump time to start
    time.sleep(3)
    
    # Verify tcpdump is running
    if tcpdump_process.poll() is not None:
        info("*** ERROR: tcpdump failed to start or terminated prematurely\n")
        with open(f'{capture_dir}/tcpdump.log', 'r') as log_file:
            info(f"*** tcpdump log: {log_file.read()}\n")
        return
    
    # List of all hosts
    hosts = [net.get(f'h{i}') for i in range(1, 31)]
    
    # Select target hosts (one from each switch segment)
    target_hosts = [hosts[5], hosts[15], hosts[25]]  # h6, h16, h26
    
    # Select attacker hosts (all remaining hosts)
    attacker_hosts = [h for h in hosts if h not in target_hosts]
    
    # Install hping3 if not already installed
    for attacker in attacker_hosts[:1]:
        attacker.cmd('which hping3 || apt-get update && apt-get install -y hping3')
    
    # Thread to monitor file size
    def monitor_file_size():
        while not stop_event.is_set():
            if os.path.exists(capture_file):
                current_size = os.path.getsize(capture_file)
                info(f"*** Current capture size: {current_size/1000000:.2f} MB\n")
                
                if current_size >= 95000000:  # 95MB (close to 100MB)
                    info("*** Reached 95MB (approaching 100MB limit), stopping capture\n")
                    stop_event.set()
                    break
            
            time.sleep(5)
    
    # Start monitoring thread
    monitor_thread = Thread(target=monitor_file_size)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    # Function to launch DDoS attacks
    def launch_ddos_attacks():
        attack_round = 0
        
        while not stop_event.is_set():
            # Target a different host in each round
            target = target_hosts[attack_round % 3]
            info(f"*** Starting DDoS attack round {attack_round+1} targeting {target.name}\n")
            
            # 1. SYN Flood Attack
            info(f"*** Launching SYN Flood attack on {target.name}\n")
            syn_attackers = attacker_hosts[:9]
            syn_processes = []
            
            for attacker in syn_attackers:
                info(f"*** {attacker.name} launching SYN flood on {target.name}\n")
                # Using parameters from search result [2]
                attack_proc = attacker.popen(
                    f'hping3 -S -p 80 --flood --rand-source {target.IP()} > /dev/null 2>&1'
                )
                syn_processes.append(attack_proc)
            
            # Let SYN flood run for 30 seconds
            attack_start = time.time()
            while time.time() - attack_start < 30 and not stop_event.is_set():
                time.sleep(2)
                if os.path.exists(capture_file) and os.path.getsize(capture_file) >= 95000000:
                    stop_event.set()
                    break
            
            # Stop SYN flood processes
            for proc in syn_processes:
                try:
                    proc.terminate()
                except:
                    pass
            
            # Clean up before next attack
            os.system('sudo pkill -f "hping3 -S"')
            time.sleep(2)
            
            if stop_event.is_set():
                break
                
            # 2. UDP Flood Attack
            info(f"*** Launching UDP Flood attack on {target.name}\n")
            udp_attackers = attacker_hosts[9:18]
            udp_processes = []
            
            for attacker in udp_attackers:
                info(f"*** {attacker.name} launching UDP flood on {target.name}\n")
                # Using parameters from search result [2]
                attack_proc = attacker.popen(
                    f'hping3 --udp -p 53 --flood -d 65495 --rand-source {target.IP()} > /dev/null 2>&1'
                )
                udp_processes.append(attack_proc)
            
            # Let UDP flood run for 30 seconds
            attack_start = time.time()
            while time.time() - attack_start < 30 and not stop_event.is_set():
                time.sleep(2)
                if os.path.exists(capture_file) and os.path.getsize(capture_file) >= 95000000:
                    stop_event.set()
                    break
            
            # Stop UDP flood processes
            for proc in udp_processes:
                try:
                    proc.terminate()
                except:
                    pass
            
            # Clean up before next attack
            os.system('sudo pkill -f "hping3 --udp"')
            time.sleep(2)
            
            if stop_event.is_set():
                break
                
            # 3. SMURF Attack (ICMP Flood with spoofed source)
            info(f"*** Launching SMURF attack on {target.name}\n")
            icmp_attackers = attacker_hosts[18:]
            icmp_processes = []
            
            for attacker in icmp_attackers:
                info(f"*** {attacker.name} launching SMURF attack on {target.name}\n")
                # Using parameters from search result [2]
                attack_proc = attacker.popen(
                    f'hping3 --icmp --flood -d 65495 {target.IP()} -a {target.IP()} > /dev/null 2>&1'
                )
                icmp_processes.append(attack_proc)
            
            # Let ICMP flood run for 30 seconds
            attack_start = time.time()
            while time.time() - attack_start < 30 and not stop_event.is_set():
                time.sleep(2)
                if os.path.exists(capture_file) and os.path.getsize(capture_file) >= 95000000:
                    stop_event.set()
                    break
            
            # Stop ICMP flood processes
            for proc in icmp_processes:
                try:
                    proc.terminate()
                except:
                    pass
            
            # Clean up
            os.system('sudo pkill -f "hping3 --icmp"')
            
            # Short pause between attack rounds
            time.sleep(5)
            
            attack_round += 1
            
            # Check if we've reached the file size limit
            if os.path.exists(capture_file) and os.path.getsize(capture_file) >= 95000000:
                info("*** Approaching 100MB file size limit, stopping attack traffic\n")
                stop_event.set()
                break
    
    # Start attack thread
    attack_thread = Thread(target=launch_ddos_attacks)
    attack_thread.daemon = True
    attack_thread.start()
    
    # Wait for stop event or maximum duration
    max_duration = 600  # 10 minutes maximum
    start_time = time.time()
    
    while not stop_event.is_set() and time.time() - start_time < max_duration:
        time.sleep(5)
    
    # Set stop event if it wasn't already set
    stop_event.set()
    
    # Stop tcpdump
    info("*** Stopping packet capture\n")
    if tcpdump_process.poll() is None:
        tcpdump_process.terminate()
    os.system('sudo pkill -f tcpdump')
    
    # Kill any remaining attack processes
    os.system('sudo pkill -f hping3')
    
    # Copy the capture file to the current directory
    if os.path.exists(capture_file):
        info(f"*** Copying capture file to current directory\n")
        os.system(f'sudo cp {capture_file} .')
        os.system('sudo chmod 666 ddos_attack_traffic.pcap')
        final_size = os.path.getsize('ddos_attack_traffic.pcap') if os.path.exists('ddos_attack_traffic.pcap') else 0
        info(f"*** Final capture size: {final_size/1000000:.2f} MB\n")
    else:
        info("*** ERROR: No capture file was created\n")
    
    info("*** Attack traffic generation completed\n")

def topology():
    # Create network
    net = Mininet(controller=Controller, link=TCLink)
    
    info('*** Adding controller\n')
    c0 = net.addController('c0')
    
    info('*** Adding switches\n')
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    
    info('*** Adding hosts\n')
    hosts = []
    for i in range(1, 31):
        host = net.addHost(f'h{i}', ip=f'10.0.0.{i}/8')
        hosts.append(host)
    
    info('*** Creating links\n')
    # Connect switches in a line
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    
    # Connect hosts to switches (10 hosts per switch)
    for i in range(10):
        net.addLink(hosts[i], s1)
        net.addLink(hosts[i+10], s2)
        net.addLink(hosts[i+20], s3)
    
    info('*** Starting network\n')
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    
    info('*** Generating attack traffic\n')
    generate_attack_traffic(net)
    
    info('*** Running CLI\n')
    CLI(net)
    
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    topology()

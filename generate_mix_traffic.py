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
import signal
import sys
from threading import Thread, Event

# Global stop event for coordinating threads
stop_event = Event()
is_attack_active = False

def generate_mixed_traffic(net):
    global is_attack_active
    
    # Kill any existing tcpdump processes
    os.system('sudo pkill -f tcpdump')
    time.sleep(1)
    
    # Create a dedicated directory with proper permissions
    capture_dir = '/tmp/mininet_capture'
    os.system(f'sudo rm -rf {capture_dir}')
    os.system(f'sudo mkdir -p {capture_dir}')
    os.system(f'sudo chmod 777 {capture_dir}')
    
    capture_file = f'{capture_dir}/ddos_mixed_traffic.pcap'
    
    # Start tcpdump without rotation options, manually control file size
    info("*** Starting tcpdump to capture mixed normal and attack traffic\n")
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
    
    # Select target hosts for DDoS attack
    target_hosts = [hosts[5], hosts[15], hosts[25]]  # h6, h16, h26
    
    # Select attacker hosts (about 60% of hosts)
    attacker_indices = [0, 1, 2, 3, 7, 8, 9, 10, 11, 12, 13, 17, 18, 19, 20, 21, 22, 23]
    attacker_hosts = [hosts[i] for i in attacker_indices]
    
    # Remaining hosts for normal traffic
    normal_hosts = [h for h in hosts if h not in attacker_hosts and h not in target_hosts]
    
    info("*** Creating test files for HTTP transfers\n")
    hosts[0].cmd('dd if=/dev/urandom of=/tmp/largefile bs=1M count=10')
    
    # Start HTTP servers on some hosts
    info("*** Starting HTTP servers\n")
    http_servers = []
    for i in [1, 11, 21]:  # One host per switch segment
        info(f"*** Starting HTTP server on h{i}\n")
        server = hosts[i-1]
        server_process = server.popen('cd /tmp && python -m SimpleHTTPServer 80')
        http_servers.append(server_process)
    
    # Function to generate background normal traffic
    def generate_normal_traffic():
        info("*** Starting normal background traffic generation\n")
        
        while not stop_event.is_set():
            # Reduce traffic during attacks but don't stop completely
            if is_attack_active:
                # Generate less traffic during attacks
                if random.random() > 0.7:  # 30% chance to generate traffic during attack
                    src = random.choice(normal_hosts)
                    dst = random.choice([h for h in normal_hosts if h != src])
                    
                    # Simple traffic during attacks
                    info(f"*** Normal traffic during attack: {src.name} pinging {dst.name}\n")
                    src.cmd(f'timeout 2s ping -c 2 {dst.IP()} > /dev/null 2>&1')
                
                time.sleep(2)
                continue
            
            # Normal traffic when no attack is happening
            src = random.choice(normal_hosts)
            dst = random.choice([h for h in hosts if h != src and h not in attacker_hosts])
            
            # Choose a random traffic type
            traffic_type = random.randint(1, 4)
            
            if traffic_type == 1:  # Ping
                info(f"*** Normal traffic: {src.name} pinging {dst.name}\n")
                src.cmd(f'timeout 5s ping -c 3 {dst.IP()} > /dev/null 2>&1')
                
            elif traffic_type == 2:  # HTTP
                if dst.name in ['h1', 'h11', 'h21']:  # If dst is a web server
                    info(f"*** Normal traffic: {src.name} requesting HTTP from {dst.name}\n")
                    src.cmd(f'timeout 10s wget -q -O /dev/null {dst.IP()}:80/largefile > /dev/null 2>&1')
                    
            elif traffic_type == 3:  # DNS query
                info(f"*** Normal traffic: {src.name} performing DNS query\n")
                src.cmd('timeout 3s host google.com > /dev/null 2>&1')
                
            elif traffic_type == 4:  # Iperf bandwidth test
                dst_choice = random.choice([h for h in normal_hosts if h != src])
                info(f"*** Normal traffic: Bandwidth test from {src.name} to {dst_choice.name}\n")
                dst_choice.cmd('timeout 10s iperf -s -p 5001 > /dev/null 2>&1 &')
                time.sleep(0.5)
                src.cmd(f'timeout 8s iperf -c {dst_choice.IP()} -p 5001 -t 5 > /dev/null 2>&1')
                dst_choice.cmd('pkill -f "iperf -s"')
            
            # Random sleep between traffic generation
            time.sleep(random.uniform(1.0, 3.0))
            
            # Check if we've reached the file size limit
            if os.path.exists(capture_file) and os.path.getsize(capture_file) >= 95000000:  # 95MB
                info("*** Approaching 100MB file size limit, stopping normal traffic\n")
                stop_event.set()
                break
    
    # Function to launch DDoS attacks
    def launch_ddos_attacks():
        global is_attack_active
        
        info("*** Preparing for DDoS attacks\n")
        
        # Give some time for normal traffic to establish
        time.sleep(15)
        
        # Install hping3 if not already installed
        for attacker in attacker_hosts[:1]:
            attacker.cmd('which hping3 || apt-get update && apt-get install -y hping3')
        
        attack_round = 0
        while not stop_event.is_set() and attack_round < 3:
            # Target a different host in each round
            target = target_hosts[attack_round % 3]
            info(f"*** Starting DDoS attack round {attack_round+1} targeting {target.name}\n")
            
            # Mark attack as active
            is_attack_active = True
            
            # Divide attackers into groups
            attackers_per_type = len(attacker_hosts) // 3
            
            # 1. SYN Flood Attack
            info(f"*** Launching SYN Flood attack on {target.name}\n")
            syn_attackers = attacker_hosts[:attackers_per_type]
            syn_processes = []
            
            for attacker in syn_attackers:
                info(f"*** {attacker.name} launching SYN flood on {target.name}\n")
                # SYN flood targeting web server port
                attack_proc = attacker.popen(
                    f'hping3 -S -p 80 --flood --rand-source {target.IP()} > /dev/null 2>&1'
                )
                syn_processes.append(attack_proc)
            
            # Let SYN flood run for 20 seconds
            attack_start = time.time()
            while time.time() - attack_start < 20 and not stop_event.is_set():
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
            udp_attackers = attacker_hosts[attackers_per_type:2*attackers_per_type]
            udp_processes = []
            
            for attacker in udp_attackers:
                info(f"*** {attacker.name} launching UDP flood on {target.name}\n")
                # UDP flood targeting DNS port
                attack_proc = attacker.popen(
                    f'hping3 --udp -p 53 --flood --rand-source {target.IP()} > /dev/null 2>&1'
                )
                udp_processes.append(attack_proc)
            
            # Let UDP flood run for 20 seconds
            attack_start = time.time()
            while time.time() - attack_start < 20 and not stop_event.is_set():
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
                
            # 3. ICMP Flood Attack
            info(f"*** Launching ICMP Flood attack on {target.name}\n")
            icmp_attackers = attacker_hosts[2*attackers_per_type:]
            icmp_processes = []
            
            for attacker in icmp_attackers:
                info(f"*** {attacker.name} launching ICMP flood on {target.name}\n")
                # ICMP flood (ping flood)
                attack_proc = attacker.popen(
                    f'hping3 --icmp --flood {target.IP()} > /dev/null 2>&1'
                )
                icmp_processes.append(attack_proc)
            
            # Let ICMP flood run for 20 seconds
            attack_start = time.time()
            while time.time() - attack_start < 20 and not stop_event.is_set():
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
            
            # Mark attack as no longer active
            is_attack_active = False
            
            # Allow some normal traffic between attack rounds
            time.sleep(10)
            
            attack_round += 1
            
            # Check if we've reached the file size limit
            if os.path.exists(capture_file) and os.path.getsize(capture_file) >= 95000000:
                info("*** Approaching 100MB file size limit, stopping attack traffic\n")
                stop_event.set()
                break
    
    # Thread to monitor file size
    def monitor_file_size():
        while not stop_event.is_set():
            if os.path.exists(capture_file):
                current_size = os.path.getsize(capture_file)
                info(f"*** Current capture size: {current_size/1000000:.2f} MB\n")
                
                if current_size >= 95000000:  # 95MB
                    info("*** Reached 95MB (approaching 100MB limit), stopping capture\n")
                    stop_event.set()
                    break
            
            time.sleep(5)
    
    # Start monitoring thread
    monitor_thread = Thread(target=monitor_file_size)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    # Start normal traffic thread
    normal_thread = Thread(target=generate_normal_traffic)
    normal_thread.daemon = True
    normal_thread.start()
    
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
    
    # Stop HTTP servers
    for server in http_servers:
        try:
            server.terminate()
        except:
            pass
    
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
        os.system('sudo chmod 666 ddos_mixed_traffic.pcap')
        final_size = os.path.getsize('ddos_mixed_traffic.pcap') if os.path.exists('ddos_mixed_traffic.pcap') else 0
        info(f"*** Final capture size: {final_size/1000000:.2f} MB\n")
    else:
        info("*** ERROR: No capture file was created\n")
    
    # Clean up any remaining processes
    os.system('sudo pkill -f "python -m SimpleHTTPServer"')
    os.system('sudo pkill -f "iperf"')
    os.system('sudo pkill -f "wget"')
    
    info("*** Mixed traffic generation completed\n")

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
    
    info('*** Generating mixed normal and attack traffic\n')
    generate_mixed_traffic(net)
    
    info('*** Running CLI\n')
    CLI(net)
    
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    topology()


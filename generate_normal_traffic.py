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
import glob
from threading import Thread

def generate_traffic(net):
    # Kill any existing tcpdump processes
    os.system('sudo pkill -f tcpdump')
    time.sleep(1)
    
    # Create a dedicated directory with proper permissions
    capture_dir = '/tmp/mininet_capture'
    os.system(f'sudo rm -rf {capture_dir}')
    os.system(f'sudo mkdir -p {capture_dir}')
    os.system(f'sudo chmod 777 {capture_dir}')
    
    capture_file = f'{capture_dir}/normal_traffic.pcap'
    
    # Start tcpdump with explicit output file and flush option
    info("*** Starting tcpdump to capture normal traffic\n")
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
    
    # Test if tcpdump is actually capturing by generating some test traffic
    info("*** Testing tcpdump capture...\n")
    os.system('ping -c 5 127.0.0.1 > /dev/null')
    time.sleep(2)
    
    # Check if the capture file exists and is growing
    if not os.path.exists(capture_file) or os.path.getsize(capture_file) == 0:
        info("*** ERROR: tcpdump is not creating a capture file\n")
        info("*** Trying alternative approach with tshark...\n")
        
        # Kill tcpdump and try tshark instead
        tcpdump_process.terminate()
        time.sleep(1)
        
        # Try using tshark instead
        tshark_cmd = f'sudo tshark -i any -w {capture_file} port not 22'
        with open(f'{capture_dir}/tshark.log', 'w') as log_file:
            tcpdump_process = subprocess.Popen(
                tshark_cmd,
                shell=True,
                stdout=log_file,
                stderr=log_file
            )
        
        time.sleep(3)
        os.system('ping -c 5 127.0.0.1 > /dev/null')
        time.sleep(2)
        
        if not os.path.exists(capture_file) or os.path.getsize(capture_file) == 0:
            info("*** ERROR: Both tcpdump and tshark failed to create capture files\n")
            info("*** Trying direct capture on s1 interface...\n")
            
            # Try capturing directly on a switch interface
            s1 = net.get('s1')
            s1_interfaces = s1.cmd('ls /sys/class/net').strip().split()
            capture_interface = next((i for i in s1_interfaces if i != 'lo'), 's1-eth1')
            
            s1.cmd(f'sudo tcpdump -i {capture_interface} -U -w {capture_file} &')
            time.sleep(2)
    
    # Verify again
    if not os.path.exists(capture_file) or os.path.getsize(capture_file) == 0:
        info("*** WARNING: Still no capture file. Continuing anyway...\n")
    else:
        info(f"*** Capture file created successfully: {capture_file}\n")
    
    # List of all hosts
    hosts = [net.get(f'h{i}') for i in range(1, 31)]
    
    # Create a large file for HTTP transfers
    info("*** Creating test files\n")
    hosts[0].cmd('dd if=/dev/urandom of=/tmp/largefile bs=1M count=10')
    
    # Start HTTP servers
    info("*** Starting HTTP servers\n")
    http_servers = []
    for i in [1, 11, 21]:
        info(f"*** Starting HTTP server on h{i}\n")
        server = hosts[i-1]
        server_process = server.popen('cd /tmp && python -m SimpleHTTPServer 80')
        http_servers.append(server_process)
    
    # Generate traffic in sequence to avoid overwhelming the system
    
    # 1. Ping traffic
    info("*** Generating ping traffic\n")
    for _ in range(30):
        src = random.choice(hosts)
        dst = random.choice(hosts)
        if src != dst:
            info(f"*** {src.name} pinging {dst.name}\n")
            # Use timeout to prevent hanging
            src.cmd(f'timeout 5s ping -c 5 {dst.IP()} > /dev/null')
    
    # Check capture file size
    if os.path.exists(capture_file):
        info(f"*** Current capture size: {os.path.getsize(capture_file)/1000000:.2f} MB\n")
    
    # 2. HTTP traffic
    info("*** Generating HTTP traffic\n")
    for _ in range(30):
        src = random.choice(hosts)
        dst_idx = random.choice([0, 10, 20])
        dst = hosts[dst_idx]
        if src != dst:
            info(f"*** {src.name} requesting HTTP from h{dst_idx+1}\n")
            # Use timeout to prevent hanging
            src.cmd(f'timeout 10s wget -q -O /dev/null {dst.IP()}:80/largefile')
    
    # Check capture file size
    if os.path.exists(capture_file):
        info(f"*** Current capture size: {os.path.getsize(capture_file)/1000000:.2f} MB\n")
    
    # 3. DNS-like queries
    info("*** Generating DNS-like traffic\n")
    for _ in range(30):
        src = random.choice(hosts)
        info(f"*** {src.name} performing DNS query\n")
        # Use timeout to prevent hanging
        src.cmd('timeout 3s host google.com > /dev/null')
    
    # 4. File transfers with iperf instead of netcat (more reliable)
    info("*** Generating file transfer traffic with iperf\n")
    for _ in range(20):
        sender = random.choice(hosts)
        receiver = random.choice(hosts)
        if sender != receiver:
            info(f"*** Bandwidth test from {sender.name} to {receiver.name}\n")
            # Start iperf server with timeout
            receiver.cmd('timeout 10s iperf -s -p 5001 > /dev/null 2>&1 &')
            time.sleep(0.5)
            # Run iperf client with timeout
            sender.cmd(f'timeout 8s iperf -c {receiver.IP()} -p 5001 -t 5 -n 10M > /dev/null 2>&1')
            # Kill the server
            receiver.cmd('pkill -f "iperf -s"')
            time.sleep(0.5)
    
    # Check capture file size
    if os.path.exists(capture_file):
        info(f"*** Current capture size: {os.path.getsize(capture_file)/1000000:.2f} MB\n")
    
    # 5. Generate more intensive traffic until we reach ~100MB
    info("*** Generating intensive traffic to reach target size\n")
    target_size = 100 * 1000000  # 100MB in bytes
    max_time = 600  # 10 minutes maximum
    start_time = time.time()
    
    while True:
        if os.path.exists(capture_file):
            current_size = os.path.getsize(capture_file)
            info(f"*** Current capture size: {current_size/1000000:.2f} MB\n")
            if current_size >= target_size:
                info("*** Reached target file size\n")
                break
        
        # Check timeout
        if time.time() - start_time > max_time:
            info("*** Maximum time reached, stopping capture\n")
            break
        
        # Generate more traffic - use a mix of protocols
        for _ in range(5):
            src = random.choice(hosts)
            dst = random.choice(hosts)
            if src != dst:
                # Use timeout to prevent hanging
                src.cmd(f'timeout 5s ping -c 10 -s 1400 {dst.IP()} > /dev/null 2>&1')
        
        for _ in range(3):
            src = random.choice(hosts)
            dst_idx = random.choice([0, 10, 20])
            dst = hosts[dst_idx]
            if src != dst:
                # Use timeout to prevent hanging
                src.cmd(f'timeout 10s wget -q -O /dev/null {dst.IP()}:80/largefile > /dev/null 2>&1')
        
        # Add some UDP traffic
        for _ in range(2):
            sender = random.choice(hosts)
            receiver = random.choice(hosts)
            if sender != receiver:
                port = random.randint(5000, 6000)
                # Use timeout and background the process
                receiver.cmd(f'timeout 5s nc -ul {port} > /dev/null 2>&1 &')
                time.sleep(0.5)
                # Send some UDP data with timeout
                sender.cmd(f'timeout 3s dd if=/dev/urandom bs=1M count=2 | nc -u {receiver.IP()} {port} > /dev/null 2>&1')
                time.sleep(0.5)
                # Kill any remaining nc processes
                receiver.cmd('pkill -f "nc -ul"')
    
    # Stop HTTP servers
    for server in http_servers:
        server.terminate()
    
    # Stop tcpdump
    info("*** Stopping packet capture\n")
    if tcpdump_process.poll() is None:
        tcpdump_process.terminate()
    os.system('sudo pkill -f tcpdump')
    os.system('sudo pkill -f tshark')
    
    # Copy the capture file to the current directory
    if os.path.exists(capture_file):
        info(f"*** Copying capture file to current directory\n")
        os.system(f'sudo cp {capture_file} .')
        os.system('sudo chmod 666 normal_traffic.pcap')
        info(f"*** Final capture size: {os.path.getsize('normal_traffic.pcap')/1000000:.2f} MB\n")
    else:
        info("*** ERROR: No capture file was created\n")
    
    # Clean up any remaining processes
    os.system('sudo pkill -f "python -m SimpleHTTPServer"')
    os.system('sudo pkill -f "nc -l"')
    os.system('sudo pkill -f "nc -ul"')
    os.system('sudo pkill -f "wget"')
    os.system('sudo pkill -f "iperf"')
    
    info("*** Traffic generation completed\n")

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
    
    info('*** Generating traffic\n')
    generate_traffic(net)
    
    info('*** Running CLI\n')
    CLI(net)
    
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    topology()


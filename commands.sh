################################################################################
# COMPLETE GNS3 BUS TOPOLOGY - STEP-BY-STEP CONFIGURATION
################################################################################
#
# TOPOLOGY DIAGRAM:
# Alpine1 [eth0] ←→ [eth0] OVS1 [eth1] ←→ [eth0] OVS2 [eth1] ←→ [eth0] OVS3 [eth1] ←→ [eth0] OVS4 [eth1] ←→ [eth0] Alpine2
#
# IP ADDRESSING TABLE:
# ┌──────────┬────────────┬──────────────┬─────────────────────────┐
# │ Device   │ Interface  │ IP Address   │ Connects To             │
# ├──────────┼────────────┼──────────────┼─────────────────────────┤
# │ Alpine1  │ eth0       │ 10.0.1.2/24  │ OVS1 eth0               │
# │ OVS1     │ eth0       │ 10.0.1.1/24  │ Alpine1 eth0            │
# │ OVS1     │ eth1       │ 10.0.2.1/24  │ OVS2 eth0               │
# │ OVS2     │ eth0       │ 10.0.2.2/24  │ OVS1 eth1               │
# │ OVS2     │ eth1       │ 10.0.3.1/24  │ OVS3 eth0               │
# │ OVS3     │ eth0       │ 10.0.3.2/24  │ OVS2 eth1               │
# │ OVS3     │ eth1       │ 10.0.4.1/24  │ OVS4 eth0               │
# │ OVS4     │ eth0       │ 10.0.4.2/24  │ OVS3 eth1               │
# │ OVS4     │ eth1       │ 10.0.5.1/24  │ Alpine2 eth0            │
# │ Alpine2  │ eth0       │ 10.0.5.2/24  │ OVS4 eth1               │
# └──────────┴────────────┴──────────────┴─────────────────────────┘
#
################################################################################

################################################################################
# STEP 1: CONFIGURE OVS-1
################################################################################
# OVS-1 acts as the GATEWAY for Alpine1 and routes traffic to downstream networks
#
# Interface Assignment:
#   eth0 = 10.0.1.1/24  (Connected to Alpine1)
#   eth1 = 10.0.2.1/24  (Connected to OVS2)
#
# Static Routes Needed:
#   10.0.3.0/24 via 10.0.2.2 (OVS2's eth0) - to reach OVS2-OVS3 link
#   10.0.4.0/24 via 10.0.2.2 (OVS2's eth0) - to reach OVS3-OVS4 link
#   10.0.5.0/24 via 10.0.2.2 (OVS2's eth0) - to reach Alpine2 network
################################################################################

# --- Execute on OVS-1 ---

# Stop existing network services
rc-service networking stop 2>/dev/null

# Remove any OVS bridges (clean slate)
for br in $(ovs-vsctl list-br); do 
    ovs-vsctl del-br $br
done

# Clear any existing IP addresses
ip addr flush dev eth0 2>/dev/null
ip addr flush dev eth1 2>/dev/null

# CRITICAL: Enable IP forwarding (allows routing between interfaces)
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.ip_forward=1

# Assign IP addresses
ip addr add 10.0.1.1/24 dev eth0    # Interface facing Alpine1
ip addr add 10.0.2.1/24 dev eth1    # Interface facing OVS2

# Bring interfaces up
ip link set eth0 up
ip link set eth1 up

# Add static routes to downstream networks (all via OVS2)
ip route add 10.0.3.0/24 via 10.0.2.2 dev eth1    # To reach OVS2-OVS3 link
ip route add 10.0.4.0/24 via 10.0.2.2 dev eth1    # To reach OVS3-OVS4 link
ip route add 10.0.5.0/24 via 10.0.2.2 dev eth1    # To reach Alpine2 network

# Verify configuration
echo "============================================"
echo "OVS-1 Configuration Summary"
echo "============================================"
echo "Interface eth0 (to Alpine1):"
ip addr show eth0 | grep "inet "
echo ""
echo "Interface eth1 (to OVS2):"
ip addr show eth1 | grep "inet "
echo ""
echo "Routing Table:"
ip route show
echo "============================================"

################################################################################
# STEP 2: CONFIGURE OVS-2
################################################################################
# OVS-2 is a MIDDLE ROUTER connecting OVS1 and OVS3
#
# Interface Assignment:
#   eth0 = 10.0.2.2/24  (Connected to OVS1)
#   eth1 = 10.0.3.1/24  (Connected to OVS3)
#
# Static Routes Needed:
#   10.0.1.0/24 via 10.0.2.1 (OVS1's eth1) - to reach Alpine1 network
#   10.0.4.0/24 via 10.0.3.2 (OVS3's eth0) - to reach OVS3-OVS4 link
#   10.0.5.0/24 via 10.0.3.2 (OVS3's eth0) - to reach Alpine2 network
################################################################################

# --- Execute on OVS-2 ---

# Stop existing network services
rc-service networking stop 2>/dev/null

# Remove any OVS bridges
for br in $(ovs-vsctl list-br); do 
    ovs-vsctl del-br $br
done

# Clear existing IP addresses
ip addr flush dev eth0 2>/dev/null
ip addr flush dev eth1 2>/dev/null

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.ip_forward=1

# Assign IP addresses
ip addr add 10.0.2.2/24 dev eth0    # Interface facing OVS1
ip addr add 10.0.3.1/24 dev eth1    # Interface facing OVS3

# Bring interfaces up
ip link set eth0 up
ip link set eth1 up

# Add static routes
ip route add 10.0.1.0/24 via 10.0.2.1 dev eth0    # To reach Alpine1 (via OVS1)
ip route add 10.0.4.0/24 via 10.0.3.2 dev eth1    # To reach OVS3-OVS4 link
ip route add 10.0.5.0/24 via 10.0.3.2 dev eth1    # To reach Alpine2 (via OVS3)

# Verify configuration
echo "============================================"
echo "OVS-2 Configuration Summary"
echo "============================================"
echo "Interface eth0 (to OVS1):"
ip addr show eth0 | grep "inet "
echo ""
echo "Interface eth1 (to OVS3):"
ip addr show eth1 | grep "inet "
echo ""
echo "Routing Table:"
ip route show
echo "============================================"

################################################################################
# STEP 3: CONFIGURE OVS-3
################################################################################
# OVS-3 is a MIDDLE ROUTER connecting OVS2 and OVS4
#
# Interface Assignment:
#   eth0 = 10.0.3.2/24  (Connected to OVS2)
#   eth1 = 10.0.4.1/24  (Connected to OVS4)
#
# Static Routes Needed:
#   10.0.1.0/24 via 10.0.3.1 (OVS2's eth1) - to reach Alpine1 network
#   10.0.2.0/24 via 10.0.3.1 (OVS2's eth1) - to reach OVS1-OVS2 link
#   10.0.5.0/24 via 10.0.4.2 (OVS4's eth0) - to reach Alpine2 network
################################################################################

# --- Execute on OVS-3 ---

# Stop existing network services
rc-service networking stop 2>/dev/null

# Remove any OVS bridges
for br in $(ovs-vsctl list-br); do 
    ovs-vsctl del-br $br
done

# Clear existing IP addresses
ip addr flush dev eth0 2>/dev/null
ip addr flush dev eth1 2>/dev/null

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.ip_forward=1

# Assign IP addresses
ip addr add 10.0.3.2/24 dev eth0    # Interface facing OVS2
ip addr add 10.0.4.1/24 dev eth1    # Interface facing OVS4

# Bring interfaces up
ip link set eth0 up
ip link set eth1 up

# Add static routes
ip route add 10.0.1.0/24 via 10.0.3.1 dev eth0    # To reach Alpine1 (via OVS2)
ip route add 10.0.2.0/24 via 10.0.3.1 dev eth0    # To reach OVS1-OVS2 link
ip route add 10.0.5.0/24 via 10.0.4.2 dev eth1    # To reach Alpine2 (via OVS4)

# Verify configuration
echo "============================================"
echo "OVS-3 Configuration Summary"
echo "============================================"
echo "Interface eth0 (to OVS2):"
ip addr show eth0 | grep "inet "
echo ""
echo "Interface eth1 (to OVS4):"
ip addr show eth1 | grep "inet "
echo ""
echo "Routing Table:"
ip route show
echo "============================================"

################################################################################
# STEP 4: CONFIGURE OVS-4
################################################################################
# OVS-4 acts as the GATEWAY for Alpine2 and routes traffic to upstream networks
#
# Interface Assignment:
#   eth0 = 10.0.4.2/24  (Connected to OVS3)
#   eth1 = 10.0.5.1/24  (Connected to Alpine2)
#
# Static Routes Needed:
#   10.0.1.0/24 via 10.0.4.1 (OVS3's eth1) - to reach Alpine1 network
#   10.0.2.0/24 via 10.0.4.1 (OVS3's eth1) - to reach OVS1-OVS2 link
#   10.0.3.0/24 via 10.0.4.1 (OVS3's eth1) - to reach OVS2-OVS3 link
################################################################################

# --- Execute on OVS-4 ---

# Stop existing network services
rc-service networking stop 2>/dev/null

# Remove any OVS bridges
for br in $(ovs-vsctl list-br); do 
    ovs-vsctl del-br $br
done

# Clear existing IP addresses
ip addr flush dev eth0 2>/dev/null
ip addr flush dev eth1 2>/dev/null

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.ip_forward=1

# Assign IP addresses
ip addr add 10.0.4.2/24 dev eth0    # Interface facing OVS3
ip addr add 10.0.5.1/24 dev eth1    # Interface facing Alpine2

# Bring interfaces up
ip link set eth0 up
ip link set eth1 up

# Add static routes (all upstream networks via OVS3)
ip route add 10.0.1.0/24 via 10.0.4.1 dev eth0    # To reach Alpine1
ip route add 10.0.2.0/24 via 10.0.4.1 dev eth0    # To reach OVS1-OVS2 link
ip route add 10.0.3.0/24 via 10.0.4.1 dev eth0    # To reach OVS2-OVS3 link

# Verify configuration
echo "============================================"
echo "OVS-4 Configuration Summary"
echo "============================================"
echo "Interface eth0 (to OVS3):"
ip addr show eth0 | grep "inet "
echo ""
echo "Interface eth1 (to Alpine2):"
ip addr show eth1 | grep "inet "
echo ""
echo "Routing Table:"
ip route show
echo "============================================"

################################################################################
# STEP 5: CONFIGURE ALPINE LINUX 1 (LEFT END HOST)
################################################################################
# Alpine1 is an END HOST connected to OVS1
#
# Interface Assignment:
#   eth0 = 10.0.1.2/24  (Connected to OVS1's eth0)
#
# Gateway:
#   Default gateway = 10.0.1.1 (OVS1's eth0)
#   This allows Alpine1 to reach ALL other networks via OVS1
################################################################################

# --- Execute on Alpine1 ---

# Stop existing network services
rc-service networking stop 2>/dev/null

# Clear existing IP address
ip addr flush dev eth0 2>/dev/null

# Assign IP address
ip addr add 10.0.1.2/24 dev eth0    # IP address for Alpine1

# Bring interface up
ip link set eth0 up

# Add default gateway (points to OVS1)
ip route add default via 10.0.1.1 dev eth0

# Verify configuration
echo "============================================"
echo "Alpine1 Configuration Summary"
echo "============================================"
echo "Interface eth0:"
ip addr show eth0 | grep "inet "
echo ""
echo "Routing Table:"
ip route show
echo "============================================"

################################################################################
# STEP 6: CONFIGURE ALPINE LINUX 2 (RIGHT END HOST)
################################################################################
# Alpine2 is an END HOST connected to OVS4
#
# Interface Assignment:
#   eth0 = 10.0.5.2/24  (Connected to OVS4's eth1)
#
# Gateway:
#   Default gateway = 10.0.5.1 (OVS4's eth1)
#   This allows Alpine2 to reach ALL other networks via OVS4
################################################################################

# --- Execute on Alpine2 ---

# Stop existing network services
rc-service networking stop 2>/dev/null

# Clear existing IP address
ip addr flush dev eth0 2>/dev/null

# Assign IP address
ip addr add 10.0.5.2/24 dev eth0    # IP address for Alpine2

# Bring interface up
ip link set eth0 up

# Add default gateway (points to OVS4)
ip route add default via 10.0.5.1 dev eth0

# Verify configuration
echo "============================================"
echo "Alpine2 Configuration Summary"
echo "============================================"
echo "Interface eth0:"
ip addr show eth0 | grep "inet "
echo ""
echo "Routing Table:"
ip route show
echo "============================================"

################################################################################
# STEP 7: CONNECTIVITY TESTING
################################################################################

# ===== TEST FROM ALPINE1 =====
# Execute these commands on Alpine1 to verify end-to-end connectivity

echo ""
echo "###############################################"
echo "# TESTING FROM ALPINE1 (10.0.1.2)"
echo "###############################################"
echo ""

# Test 1: Ping OVS1 (first hop)
echo "Test 1: Ping OVS1 eth0 (10.0.1.1)..."
ping -c 2 10.0.1.1
echo ""

# Test 2: Ping OVS1's other interface
echo "Test 2: Ping OVS1 eth1 (10.0.2.1)..."
ping -c 2 10.0.2.1
echo ""

# Test 3: Ping OVS2 eth0
echo "Test 3: Ping OVS2 eth0 (10.0.2.2)..."
ping -c 2 10.0.2.2
echo ""

# Test 4: Ping OVS2 eth1
echo "Test 4: Ping OVS2 eth1 (10.0.3.1)..."
ping -c 2 10.0.3.1
echo ""

# Test 5: Ping OVS3 eth0
echo "Test 5: Ping OVS3 eth0 (10.0.3.2)..."
ping -c 2 10.0.3.2
echo ""

# Test 6: Ping OVS3 eth1
echo "Test 6: Ping OVS3 eth1 (10.0.4.1)..."
ping -c 2 10.0.4.1
echo ""

# Test 7: Ping OVS4 eth0
echo "Test 7: Ping OVS4 eth0 (10.0.4.2)..."
ping -c 2 10.0.4.2
echo ""

# Test 8: Ping OVS4 eth1
echo "Test 8: Ping OVS4 eth1 (10.0.5.1)..."
ping -c 2 10.0.5.1
echo ""

# Test 9: Ping Alpine2 (FINAL DESTINATION)
echo "Test 9: Ping Alpine2 (10.0.5.2) - END TO END TEST..."
ping -c 4 10.0.5.2
echo ""

# Test 10: Traceroute to Alpine2
echo "Test 10: Traceroute to Alpine2..."
traceroute 10.0.5.2
echo ""

# ===== TEST FROM ALPINE2 (REVERSE PATH) =====
# Execute these commands on Alpine2 to verify reverse connectivity

echo ""
echo "###############################################"
echo "# TESTING FROM ALPINE2 (10.0.5.2)"
echo "###############################################"
echo ""

# Test 1: Ping OVS4 (first hop)
echo "Test 1: Ping OVS4 eth1 (10.0.5.1)..."
ping -c 2 10.0.5.1
echo ""

# Test 2: Ping OVS4 eth0
echo "Test 2: Ping OVS4 eth0 (10.0.4.2)..."
ping -c 2 10.0.4.2
echo ""

# Test 3: Ping Alpine1 (END TO END - REVERSE)
echo "Test 3: Ping Alpine1 (10.0.1.2) - REVERSE PATH TEST..."
ping -c 4 10.0.1.2
echo ""

# Test 4: Traceroute to Alpine1
echo "Test 4: Traceroute to Alpine1..."
traceroute 10.0.1.2
echo ""

################################################################################
# STEP 8: MAKE CONFIGURATION PERSISTENT (SURVIVES REBOOT)
################################################################################

# ===== OVS-1 PERSISTENT CONFIGURATION =====
# Execute on OVS-1:

mkdir -p /etc/local.d

cat > /etc/local.d/network-config.start << 'EOF'
#!/bin/sh
echo 1 > /proc/sys/net/ipv4/ip_forward
sleep 2
ip addr flush dev eth0 2>/dev/null
ip addr flush dev eth1 2>/dev/null
ip addr add 10.0.1.1/24 dev eth0
ip addr add 10.0.2.1/24 dev eth1
ip link set eth0 up
ip link set eth1 up
sleep 1
ip route add 10.0.3.0/24 via 10.0.2.2 dev eth1 2>/dev/null
ip route add 10.0.4.0/24 via 10.0.2.2 dev eth1 2>/dev/null
ip route add 10.0.5.0/24 via 10.0.2.2 dev eth1 2>/dev/null
echo "OVS-1 network configuration complete"
EOF

chmod +x /etc/local.d/network-config.start
rc-update add local default

# ===== OVS-2 PERSISTENT CONFIGURATION =====
# Execute on OVS-2:

mkdir -p /etc/local.d

cat > /etc/local.d/network-config.start << 'EOF'
#!/bin/sh
echo 1 > /proc/sys/net/ipv4/ip_forward
sleep 2
ip addr flush dev eth0 2>/dev/null
ip addr flush dev eth1 2>/dev/null
ip addr add 10.0.2.2/24 dev eth0
ip addr add 10.0.3.1/24 dev eth1
ip link set eth0 up
ip link set eth1 up
sleep 1
ip route add 10.0.1.0/24 via 10.0.2.1 dev eth0 2>/dev/null
ip route add 10.0.4.0/24 via 10.0.3.2 dev eth1 2>/dev/null
ip route add 10.0.5.0/24 via 10.0.3.2 dev eth1 2>/dev/null
echo "OVS-2 network configuration complete"
EOF

chmod +x /etc/local.d/network-config.start
rc-update add local default

# ===== OVS-3 PERSISTENT CONFIGURATION =====
# Execute on OVS-3:

mkdir -p /etc/local.d

cat > /etc/local.d/network-config.start << 'EOF'
#!/bin/sh
echo 1 > /proc/sys/net/ipv4/ip_forward
sleep 2
ip addr flush dev eth0 2>/dev/null
ip addr flush dev eth1 2>/dev/null
ip addr add 10.0.3.2/24 dev eth0
ip addr add 10.0.4.1/24 dev eth1
ip link set eth0 up
ip link set eth1 up
sleep 1
ip route add 10.0.1.0/24 via 10.0.3.1 dev eth0 2>/dev/null
ip route add 10.0.2.0/24 via 10.0.3.1 dev eth0 2>/dev/null
ip route add 10.0.5.0/24 via 10.0.4.2 dev eth1 2>/dev/null
echo "OVS-3 network configuration complete"
EOF

chmod +x /etc/local.d/network-config.start
rc-update add local default

# ===== OVS-4 PERSISTENT CONFIGURATION =====
# Execute on OVS-4:

mkdir -p /etc/local.d

cat > /etc/local.d/network-config.start << 'EOF'
#!/bin/sh
echo 1 > /proc/sys/net/ipv4/ip_forward
sleep 2
ip addr flush dev eth0 2>/dev/null
ip addr flush dev eth1 2>/dev/null
ip addr add 10.0.4.2/24 dev eth0
ip addr add 10.0.5.1/24 dev eth1
ip link set eth0 up
ip link set eth1 up
sleep 1
ip route add 10.0.1.0/24 via 10.0.4.1 dev eth0 2>/dev/null
ip route add 10.0.2.0/24 via 10.0.4.1 dev eth0 2>/dev/null
ip route add 10.0.3.0/24 via 10.0.4.1 dev eth0 2>/dev/null
echo "OVS-4 network configuration complete"
EOF

chmod +x /etc/local.d/network-config.start
rc-update add local default

################################################################################
# TROUBLESHOOTING GUIDE
################################################################################

# If connectivity fails, check these on EACH OVS device:

# 1. Verify IP forwarding is enabled (should return 1)
cat /proc/sys/net/ipv4/ip_forward

# 2. Check all interfaces are UP and have correct IPs
ip addr show

# 3. Verify routing table has all static routes
ip route show

# 4. Check interface status
ip link show

# 5. Test connectivity to DIRECTLY CONNECTED neighbors
# From OVS-1: ping 10.0.2.2 (should reach OVS2)
# From OVS-2: ping 10.0.2.1 (OVS1) and ping 10.0.3.2 (OVS3)
# From OVS-3: ping 10.0.3.1 (OVS2) and ping 10.0.4.2 (OVS4)
# From OVS-4: ping 10.0.4.1 (should reach OVS3)

# 6. Use tcpdump to see if packets are arriving
# On OVS-2: tcpdump -i eth0 icmp
# Then ping from Alpine1

################################################################################
# CONFIGURATION COMPLETE! 
# You should now have full connectivity between Alpine1 and Alpine2
################################################################################
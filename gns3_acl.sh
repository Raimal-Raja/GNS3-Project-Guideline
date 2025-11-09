# On each OVS device (OVS1, OVS2, OVS3, OVS4):

# Save the Python script
cat > /root/acl_manager.py << 'EOF'
# [Paste the python app code]
EOF

# Make it executable
chmod +x /root/acl_manager.py

# Run it (must be root)
python3 /root/acl_manager.py
```

### **2. Features Overview**

The application provides:

✅ **Add ACL Rules:**
- Blackhole routes (block specific IPs/networks)
- ICMP control (enable/disable ping)
- Interface forwarding control
- Reverse path filtering (anti-spoofing)
- Rate limiting

✅ **Remove ACL Rules:**
- Clean removal of blackhole routes and rules

✅ **View Current Rules:**
- Display all active ACL configurations
- Show routing tables, ICMP status, forwarding status

✅ **Test Connectivity:**
- Built-in ping testing

✅ **Quick Templates:**
- Block VPC1 → VPC2
- Block subnet access
- Disable ICMP
- Full security setup

### **3. Example Usage Scenarios**

**Scenario 1: Block VPC1 from reaching VPC2**
```
Run on OVS1:
1. Choose option 5 (Templates)
2. Choose option 1 (Block VPC1 from VPC2)
```

**Scenario 2: Disable ping on OVS3**
```
Run on OVS3:
1. Choose option 1 (Add ACL Rule)
2. Choose option 2 (ICMP Control)
3. Choose 'd' (disable)
```

**Scenario 3: View all active rules**
```
Choose option 3 (View ACL Rules)
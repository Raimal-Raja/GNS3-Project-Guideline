#🚀 Quick Start:
On Your Ubuntu Host Machine:
bash# 1. Install dependencies
sudo apt-get update
sudo apt-get install python3-paramiko -y

# 2. Save the application
nano gns3_acl_manager.py
# (Copy the artifact code)

# 3. Make it executable
chmod +x gns3_acl_manager.py

# 4. Run it
python3 gns3_acl_manager.py

## On Each GNS3 OVS Device (via console):
bash# Enable SSH
apk add openssh
ssh-keygen -A
passwd  # Set password (e.g., "gns3acl")
rc-service sshd start
rc-update add sshd default
```

---

## ✨ **Key Features:**

✅ **Remote Control** - Manage all 4 OVS devices from your Ubuntu host  
✅ **No Device Login** - All operations via SSH from one interface  
✅ **Batch Operations** - Apply rules to all devices simultaneously  
✅ **Quick Templates** - Pre-configured ACL scenarios  
✅ **Real-time Testing** - Built-in connectivity testing  
✅ **Persistent Config** - Saves connection settings in JSON  
✅ **Color-coded UI** - Easy to read status indicators  

---

## 🎯 **Architecture:**
```
Ubuntu Host Machine (You)
        |
        | SSH (Paramiko)
        |
        ├─→ OVS1 (port 5000) - 10.0.1.1, 10.0.2.1
        ├─→ OVS2 (port 5001) - 10.0.2.2, 10.0.3.1
        ├─→ OVS3 (port 5002) - 10.0.3.2, 10.0.4.1
        └─→ OVS4 (port 5003) - 10.0.4.2, 10.0.5.1
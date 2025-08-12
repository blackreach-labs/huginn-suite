# 📋 SMB Wordlist Functionality - Complete

The SMB page on the Reconnaissance & Enumeration page now includes dynamic wordlist functionality that appears based on the scan type selection.

## 🎯 **How SMB Wordlist Works**

### **Dynamic Field Visibility**
- **Hidden by Default**: Wordlist field is hidden for "Basic Info" and "Vulnerability Scan"
- **Visible for Share Enumeration**: Wordlist field appears when "Share Enumeration" is selected
- **Purpose**: Used for brute-forcing additional SMB shares beyond standard enumeration

### **Wordlist Population**
- **SMB-Specific Priority**: Wordlists containing "share" or "smb" in filename are listed first
- **Default Option**: "Default SMB shares" uses built-in common share names
- **General Wordlists**: Other wordlists available as "General: filename.txt"
- **Auto-Selection**: Attempts to select "shares-top100.txt" if available

### **Scan Type Behavior**
1. **Basic Info**: Only checks SMB ports, no share enumeration
2. **Share Enumeration**: 
   - Standard `net view` enumeration
   - **Plus wordlist brute-force** if wordlist selected
3. **Vulnerability Scan**: Standard enumeration + vulnerability checks

## 🔧 **Technical Implementation**

### **Configuration (tool_configs.json)**
```json
"smb": {
  "rows": [
    {
      "label": "Wordlist:",
      "controls": [
        {"type": "combobox", "name": "smb_wordlist", "items": [], "stretch": true, "visible": false}
      ]
    }
  ]
}
```

### **Dynamic Field Toggle**
```python
def toggle_smb_scan_fields(self, tool_key, scan_type):
    """Toggle SMB scan type specific fields"""
    show_wordlist = (scan_type == "Share Enumeration")
    
    if 'smb_wordlist' in controls:
        controls['smb_wordlist'].setVisible(show_wordlist)
```

### **Wordlist Population Logic**
```python
# SMB-specific wordlists first
if 'share' in filename.lower() or 'smb' in filename.lower():
    wordlist_combo.addItem(filename, filepath)

# General wordlists as fallback
wordlist_combo.addItem(f"General: {filename}", filepath)
```

### **SMB Worker Enhancement**
```python
def __init__(self, target, scan_type="Basic Info", wordlist_path=None, ...):
    self.scan_type = scan_type
    self.wordlist_path = wordlist_path

def _bruteforce_shares(self, results):
    """Brute force SMB shares using wordlist"""
    if self.wordlist_path:
        # Read wordlist file
        with open(self.wordlist_path, 'r') as f:
            share_names = [line.strip() for line in f]
    else:
        # Use default share names
        share_names = ['ADMIN$', 'C$', 'D$', 'E$', 'IPC$', 'NETLOGON', 'SYSVOL', ...]
```

## 🚀 **User Workflow**

### **Step-by-Step Usage**
1. **Navigate**: Go to Reconnaissance & Enumeration → Service Enumeration → SMB
2. **Select Scan Type**: Choose "Share Enumeration" from dropdown
3. **Wordlist Appears**: Wordlist field becomes visible automatically
4. **Choose Wordlist**: 
   - Select "Default SMB shares" for built-in list
   - Choose SMB-specific wordlist (e.g., "shares-top100.txt")
   - Select general wordlist if needed
5. **Configure Auth**: Set authentication if needed (Anonymous/Credentials)
6. **Run Scan**: Press Enter or click Run button

### **What Happens During Scan**
1. **Standard Enumeration**: `net view \\target` to find accessible shares
2. **Wordlist Brute-Force**: Tests each wordlist entry with `net use \\target\share`
3. **Results Collection**: Both standard and brute-forced shares collected
4. **Asset Integration**: All discovered shares added to asset inventory

## 📊 **Expected Output**

### **Share Enumeration with Wordlist**
```
[SMB SCAN] Starting SMB enumeration on 192.168.1.100
Checking SMB ports...
Found SMB ports: 445 (SMB over TCP), 139 (NetBIOS Session)
Enumerating SMB shares...
Found 3 shares
Share: ADMIN$
Share: C$
Share: IPC$
Brute forcing SMB shares with wordlist...
Found share: NETLOGON
Found share: SYSVOL
Found share: Users
Brute force found 3 additional shares
SMB enumeration completed. 6 results collected and assets updated.
```

### **Basic Info (No Wordlist)**
```
[SMB SCAN] Starting SMB enumeration on 192.168.1.100
Checking SMB ports...
Found SMB ports: 445 (SMB over TCP), 139 (NetBIOS Session)
SMB enumeration completed. 2 results collected and assets updated.
```

## 🔍 **Wordlist Sources**

### **Built-in Default Shares**
- **Administrative**: ADMIN$, C$, D$, E$
- **System**: IPC$, NETLOGON, SYSVOL
- **Services**: print$, fax$
- **User**: Users, Public

### **Wordlist Files** (if available in resources/wordlists/)
- **shares-top100.txt**: Top 100 common share names
- **smb-shares.txt**: Comprehensive SMB share list
- **General wordlists**: Any .txt file can be used

## ✅ **Test Results**

**All 4/4 tests passed:**
- ✅ SMB wordlist field found in configuration
- ✅ SMB scan type toggle functionality found
- ✅ SMB worker supports wordlist parameter
- ✅ SMB brute force shares method found

## 🎯 **Benefits**

- **Comprehensive Discovery**: Finds both accessible and hidden shares
- **Flexible Options**: Use default list or custom wordlists
- **Efficient UI**: Field only appears when relevant
- **Integrated Results**: All shares stored in centralized database
- **Asset Correlation**: Shares automatically added to asset inventory

The SMB wordlist functionality provides comprehensive share discovery capabilities while maintaining a clean, context-aware user interface that only shows relevant options based on the selected scan type.

---

**📋 SMB wordlist functionality complete and ready for comprehensive share enumeration!**
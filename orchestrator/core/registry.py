"""
The central registry for all scanner tools available to the orchestrator.
Each entry defines the tool's command, dependencies, and behavior.
"""

# Placeholders:
#   {target}        : The primary, sanitized target (e.g., 192_168_1_1)
#   {scan_target}   : The specific sub-target for the command (e.g., http://192.168.1.1:8080)
#   {file_target}   : A filesystem-safe name derived from the scan_target (e.g., http_192_168_1_1_8080)
#   {output_file}   : The final, calculated output file path. The command_builder replaces the
#                     path in the template with this value.

SCANNERS = [
    # --------------------------------------------------------------------
    # CORE ENUMERATION TOOLS (Usually run first)
    # --------------------------------------------------------------------
    {
        "name": "nmap",
        "cmd_template": "nmap -sT -sV -T4 -oX orchestrator/output/raw/{target}_nmap.xml {target}",
        "enabled": True, "requires_url": False, "mode": "active", "depends_on": []
    },
    {
        "name": "whatweb",
        "cmd_template": "whatweb -a 3 --log-json orchestrator/output/raw/{file_target}_whatweb.json {scan_target}",
        "enabled": True, "requires_url": True, "mode": "active", "depends_on": ["nmap"]
    },
    {
        "name": "nuclei",
        "cmd_template": "nuclei -target {scan_target} -jsonl -o orchestrator/output/raw/{file_target}_nuclei.jsonl -silent",
        "enabled": True, "requires_url": True, "mode": "active", "depends_on": ["nmap"]
    },

    # --------------------------------------------------------------------
    # DYNAMICALLY TRIGGERED TOOLS (Disabled by default)
    # These are activated by the rules engine based on findings.
    # --------------------------------------------------------------------
    {
        "name": "vulners",
        "cmd_template": "nmap --script vulners -oX orchestrator/output/raw/{target}_vulners.xml {target}",
        "enabled": True, "requires_url": False, "mode": "active", "depends_on": ["nmap"]
    },
    {
	    "name": "nmap-ssh-scripts",
	    "cmd_template": "nmap -p 22 --script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos -oX orchestrator/output/raw/{target}_nmap_ssh.xml {target}",
	    "enabled": True,
	    "requires_url": False, 
	    "mode": "active", 
	    "depends_on": ["nmap"] # This is the fix! It must depend on the base nmap scan.
    },
    {
        "name": "nmap-ftp-scripts",
        "cmd_template": "nmap -p 21 --script ftp-anon,ftp-vsftpd-backdoor -oX orchestrator/output/raw/{target}_nmap_ftp.xml {target}",
        "enabled": True, "requires_url": False, "mode": "active", "depends_on": ["nmap"]
    },
    {
        "name": "nmap-smb-scripts",
        "cmd_template": "nmap -p 139,445 --script smb-os-discovery,smb-vuln-* -oX orchestrator/output/raw/{target}_nmap_smb.xml {target}",
        "enabled": True, "requires_url": False, "mode": "active", "depends_on": ["nmap"]
    },
    {
        "name": "enum4linux",
        "cmd_template": "enum4linux -a {target}", # Output is redirected by runner, so no -o flag needed
        "enabled": True, "requires_url": False, "mode": "active", "depends_on": ["nmap"]
    },
    {
        "name": "sqlmap",
        "cmd_template": "sqlmap -u {scan_target} --batch --output-dir= orchestrator/output/raw/{file_target}_sqlmap --risk=2 --level=2",
        "enabled": True, "requires_url": True, "mode": "active", "depends_on": ["nuclei"] # Or other discovery tool
    },

    # --------------------------------------------------------------------
    # OTHER AVAILABLE TOOLS (Can be enabled manually)
    # --------------------------------------------------------------------
   
    {
        "name": "sslyze",
        "cmd_template": "sslyze --json_out=orchestrator/output/raw/{file_target}_sslyze.json {scan_target}",
        "enabled": True, "requires_url": False, "requires_tls_ports": True, "mode": "active", "depends_on": ["nmap"]
    },
    {
        "name": "wapiti",
        "cmd_template": "wapiti -u {scan_target} -f json -o orchestrator/output/raw/{file_target}_wapiti.json",
        "enabled": True, "requires_url": True, "mode": "active", "depends_on": ["whatweb"]
    },
    {
        "name": "skipfish",
        "cmd_template": "skipfish -d 3 -o orchestrator/output/raw/{file_target}_skipfish {scan_target}",
        "enabled": True, "requires_url": True, "mode": "active", "depends_on": ["whatweb"]
    },
    {
        "name": "searchsploit",
        "cmd_template": "",
        "enabled": True,
        "requires_url": False,
        "mode": "active",
        "internal": True,
        # Run after all other discovery scanners so it can use the full finding set.
        "depends_on": [
            "nmap",
            "whatweb",
            "nuclei",
            "vulners",
            "nmap-ssh-scripts",
            "nmap-ftp-scripts",
            "nmap-smb-scripts",
            "enum4linux",
            "sqlmap",
            "sslyze",
            "wapiti",
            "skipfish",
        ],
    },
]


# This map helps the engine find the actual executable name on the system.
TOOL_BINARIES = {
    'nmap': 'nmap',
    'vulners': 'nmap',
    'nmap-ssh-scripts': 'nmap',
    'nmap-ftp-scripts': 'nmap',
    'nmap-smb-scripts': 'nmap',
    'whatweb': 'whatweb',
    'nuclei': 'nuclei',
    'sslyze': 'sslyze',
    'sqlmap': 'sqlmap',
    'enum4linux': 'enum4linux',
    'wapiti': 'wapiti',
    'skipfish': 'skipfish',
    'searchsploit': 'searchsploit',
}

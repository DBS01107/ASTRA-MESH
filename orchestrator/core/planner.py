def decide_next_scans(capabilities):
    scans = set()

    for c in capabilities:
        if c.capability == "remote_auth_surface":
            scans.add("nmap-ssh-scripts")

        if c.capability == "linux_host":
            scans.add("linux-enum")

        if c.capability == "web_attack_surface":
            scans.add("nikto")

    return list(scans)

import dns.resolver

domain = "google.com"

def check_dmarc(domain):
    dmarc_domain = "_dmarc." + domain
    
    try:
        resolved_dns = dns.resolver.resolve(dmarc_domain, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
        print("Error:", e)
        return
        
    for record in resolved_dns:
        policy_records = str(record).split(";")
        
        for part in policy_records:
            clean_record = part.strip()
        
            if clean_record.startswith("p="):
                policy = clean_record.split("=")[1]
                
                print("DMARC Policy:", policy)
                
                if policy == "reject":
                    print("Meaning: Mail failing DMARC should be rejected")
                elif policy == "quarantine":
                    print("Meaning: Mail failing DMARC should be quarantined")
                elif policy == "none":
                    print("Meaning: No special handling requested for mail failing DMARC.")

def check_spf(domain):
    
    try:
        resolved_dns = dns.resolver.resolve(domain, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
        print("Error:", e)
        return
    
    spf_found = False
    
    for record in resolved_dns:
        record_text = str(record)
        
        if "v=spf1" in record_text:
            spf_found = True
            if "-all" in record_text:
                print("SPF policy: Fail")
            elif "~all" in record_text:
                print("SPF policy: Soft Fail")
            elif "?all" in record_text:
                print("SPF policy: Neutral")
            elif "+all" in record_text:
                print("SPF policy: Pass")
        
    if not spf_found:
        print("SPF policy: Not Found")

def check_a(domain):
    
    try:
        resolved_dns = dns.resolver.resolve(domain, "A")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
        print("Error:", e)
        return
    
    for record in resolved_dns:
        print("A:", record.address)

def check_aaaa(domain):
    
    try:
        resolved_dns = dns.resolver.resolve(domain, "AAAA")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
        print("Error:", e)
        return
    
    for record in resolved_dns:
        print("AAAA:", record.address)

def check_mx(domain):
    
    try:
        resolved_dns = dns.resolver.resolve(domain, "MX")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
        print("Error:", e)
        return
    
    for record in resolved_dns:
        print(f"MX: <{record.exchange}> (Preference:{record.preference})")

def check_ns(domain):
    
    try:
        resolved_dns = dns.resolver.resolve(domain, "NS")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
        print("Error:", e)
        return
    
    for record in resolved_dns:
        print("NS:", record.target)

check_a(domain)
check_aaaa(domain)
check_mx(domain)
check_ns(domain)
check_dmarc(domain)
check_spf(domain)
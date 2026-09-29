import dns.resolver

def main():
    domain = input("Please enter a domain: ").strip()
    
    try:
        dns.resolver.resolve(domain, "A")
    except dns.resolver.NXDOMAIN:
        print("Domain does not exist")
        exit()
    except dns.resolver.LifetimeTimeout:
        print("Connection Timed Out")
        exit()
    return domain

def check_dmarc(domain):
    dmarc_domain = "_dmarc." + domain
    
    try:
        resolved_dns = dns.resolver.resolve(dmarc_domain, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        print("DMARC: Not found")
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
    except dns.resolver.NXDOMAIN:
        print("Domain does not exist")
        return
    except dns.resolver.NoAnswer:
        print("SPF policy: Not Found")
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
    except dns.resolver.NoAnswer:
        print("A: Not found")
        return
    except dns.resolver.NXDOMAIN:
        print("Domain does not exist")
        return
        
    for record in resolved_dns:
        print("A:", record.address)

def check_aaaa(domain):
    
    try:
        resolved_dns = dns.resolver.resolve(domain, "AAAA")
    except dns.resolver.NoAnswer:
        print("AAAA: Not found")
        return
    except dns.resolver.NXDOMAIN:
        print("Domain does not exist")
        return
    
    for record in resolved_dns:
        print("AAAA:", record.address)

def check_mx(domain):
    
    try:
        resolved_dns = dns.resolver.resolve(domain, "MX")
    except dns.resolver.NoAnswer:
        print("MX: Not found")
        return
    except dns.resolver.NXDOMAIN:
        print("Domain does not exist")
        return
    
    for record in resolved_dns:
        print(f"MX: <{record.exchange}> (Preference:{record.preference})")

def check_ns(domain):
    
    try:
        resolved_dns = dns.resolver.resolve(domain, "NS")
    except dns.resolver.NoAnswer:
        print("NS: Not found")
        return
    except dns.resolver.NXDOMAIN:
        print("Domain does not exist")
        return
    
    for record in resolved_dns:
        print("NS:", record.target)

def check_cname(domain):
    
    try:
        resolved_dns = dns.resolver.resolve(domain, "CNAME")
    except dns.resolver.NXDOMAIN:
        print("Domain does not exist")
        return
    except dns.resolver.NoAnswer:
        print("CNAME: Not found")
        return
    
    for record in resolved_dns:
        print("CNAME:", record.target)        

def check_soa(domain):
    
    try:
        resolved_dns = dns.resolver.resolve(domain, "SOA")
    except dns.resolver.NoAnswer:
        print("SOA: Not found")
        return
    except dns.resolver.NXDOMAIN:
        print("Domain does not exist")
        return

    for record in resolved_dns:
        print("Primary nameserver:", record.mname)
        print("Responsible:", record.rname)
        print("Serial:", record.serial)
        print("Refresh:", record.refresh, "seconds")
        print("Retry:", record.retry, "seconds")
        print("Expire:", record.expire, "seconds")
        print("Minimum:", record.minimum, "seconds")


if __name__ == "__main__":
    domain = main()
    print("======= Address and Routing =======")
    check_a(domain)
    check_aaaa(domain)
    check_cname(domain)
    print()
    print("======= Email =======")
    check_mx(domain)
    check_dmarc(domain)
    check_spf(domain)
    print()
    print("======= Zone and Authority =======")
    check_soa(domain)
    check_ns(domain)
    print()
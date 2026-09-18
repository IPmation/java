package com.ipmation;

import java.util.Collections;
import java.util.List;

/**
 * Structured result of a domain WHOIS lookup.
 */
public final class WhoisInfo {

    private final String domain;
    private final String registrar;
    private final List<String> status;
    private final String created;
    private final String updated;
    private final String expires;
    private final List<String> nameservers;
    private final String dnssec;

    public WhoisInfo(String domain, String registrar, List<String> status,
                     String created, String updated, String expires,
                     List<String> nameservers, String dnssec) {
        this.domain = domain;
        this.registrar = registrar;
        this.status = status != null ? List.copyOf(status) : Collections.emptyList();
        this.created = created;
        this.updated = updated;
        this.expires = expires;
        this.nameservers = nameservers != null ? List.copyOf(nameservers) : Collections.emptyList();
        this.dnssec = dnssec;
    }

    public String getDomain()            { return domain; }
    public String getRegistrar()         { return registrar; }
    public List<String> getStatus()      { return status; }
    public String getCreated()           { return created; }
    public String getUpdated()           { return updated; }
    public String getExpires()           { return expires; }
    public List<String> getNameservers() { return nameservers; }
    public String getDnssec()            { return dnssec; }

    @Override
    public String toString() {
        return "WhoisInfo{domain=" + domain + ", registrar=" + registrar + "}";
    }
}

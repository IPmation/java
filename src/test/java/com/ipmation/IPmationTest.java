package com.ipmation;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Basic integration tests for the ipmation package.
 *
 * <p>These tests require network access to ipinfo.io, rdap.org, and
 * Cloudflare DNS-over-HTTPS.
 */
class IPmationTest {

    @Test
    void lookupIPReturnsStructuredData() throws Exception {
        IPInfo info = IPmation.lookupIP("8.8.8.8");
        assertEquals("8.8.8.8", info.getIp());
        assertNotNull(info.getCountry());
        assertNotNull(info.getAsn());
        assertNotNull(info.getIsp());
    }

    @Test
    void lookupWhoisReturnsRegistrar() throws Exception {
        WhoisInfo record = IPmation.lookupWhois("example.com");
        assertEquals("example.com", record.getDomain().toLowerCase());
        assertNotNull(record.getRegistrar());
    }

    @Test
    void lookupDnsReturnsRecords() throws Exception {
        List<String> answers = IPmation.lookupDns("example.com", "A");
        assertNotNull(answers);
        assertFalse(answers.isEmpty());
    }

    @Test
    void lookupDnsRejectsUnknownRecordType() {
        assertThrows(IOException.class, () -> IPmation.lookupDns("example.com", "INVALID"));
    }
}

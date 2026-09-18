<h1>
  <img src="https://raw.githubusercontent.com/ipmation/assets/main/icon.svg" width="28" height="28" alt="IPmation" style="vertical-align:middle;margin-right:8px" />
  IPmation Java Library
</h1>

A Java library for IP address, WHOIS, and DNS lookups.

Provides three query methods with a consistent interface. Queries public
APIs and returns structured results. No local database, no caching layer,
no persistent state.

## Requirements

- Java 11 or later
- Maven 3.6 or later

## Installation

Clone the repository and build locally:

```bash
git clone https://github.com/ipmation/java.git
cd java
mvn install
```

Then add the dependency to your project:

```xml
<dependency>
    <groupId>com.ipmation</groupId>
    <artifactId>ipmation</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Usage

```java
import com.ipmation.IPmation;
import com.ipmation.IPInfo;
import com.ipmation.WhoisInfo;

import java.util.List;

public class Example {
    public static void main(String[] args) throws Exception {
        IPInfo info = IPmation.lookupIP("8.8.8.8");
        System.out.println(info.getCity() + " " + info.getCountry());

        IPInfo me = IPmation.lookupIP();
        System.out.println(me.getIp());

        WhoisInfo record = IPmation.lookupWhois("example.com");
        System.out.println(record.getRegistrar());

        List<String> answers = IPmation.lookupDns("example.com", "MX");
        answers.forEach(System.out::println);
    }
}
```

## API Reference

| Method | Return type | Description |
| :--- | :--- | :--- |
| `lookupIP(String ip)` | `IPInfo` | Returns geolocation, ISP, ASN, and timezone for the given IP. |
| `lookupIP()` | `IPInfo` | Resolves the caller's public IP address. |
| `lookupWhois(String domain)` | `WhoisInfo` | Returns registrar, status, dates, name servers, and DNSSEC status. |
| `lookupDns(String domain, String type)` | `List<String>` | Returns DNS records. Supported types: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`. |

## Data Sources

This library does not maintain its own data. All queries are forwarded to
public APIs.

| Data | Source |
| :--- | :--- |
| IP geolocation, ISP, ASN | [ipinfo.io](https://ipinfo.io) |
| Domain registration | [rdap.org](https://rdap.org) |
| DNS records | [Cloudflare DNS-over-HTTPS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/) |

## Scope

This library is not:

- An official SDK. It is a thin wrapper around public APIs.
- A self-hosted solution. Availability depends on the upstream sources listed above.
- A data provider. No IP data is stored, cached, or redistributed.

## Limitations

- IP geolocation accuracy is city-level.
- The free ipinfo.io tier enforces rate limits.
- RDAP coverage is incomplete. Certain country-code TLDs (`.cn`, `.me`) may return no data.
- DNS queries are routed through a public DoH endpoint and depend on its availability.

## License

MIT

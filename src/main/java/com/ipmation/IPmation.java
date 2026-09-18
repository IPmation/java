package com.ipmation;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * IPmation — a Java library for IP, WHOIS, and DNS lookups.
 *
 * <p>All queries are forwarded to public APIs and results are normalized
 * into the data models defined in this package.
 */
public final class IPmation {

    private static final String IPINFO_BASE = "https://ipinfo.io";
    private static final String RDAP_BASE = "https://rdap.org";
    private static final String DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";

    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private static final HttpClient CLIENT = HttpClient.newBuilder()
            .connectTimeout(TIMEOUT)
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    private IPmation() {
        // Utility class.
    }

    /**
     * Looks up information for the given IP address.
     *
     * @param ip the IPv4 or IPv6 address to query
     * @return an {@link IPInfo} instance
     * @throws IOException if the request fails or the API returns an error
     * @throws InterruptedException if the request is interrupted
     */
    public static IPInfo lookupIP(String ip) throws IOException, InterruptedException {
        if (ip == null) {
            ip = "";
        }
        ip = ip.trim();

        String url = ip.isEmpty()
                ? IPINFO_BASE + "/json"
                : IPINFO_BASE + "/" + ip + "/json";

        JsonObject data = getJson(url);

        if (data.has("error")) {
            String message = "unknown error";
            JsonObject error = data.getAsJsonObject("error");
            if (error.has("message")) {
                message = error.get("message").getAsString();
            }
            throw new IOException("IP lookup failed: " + message);
        }

        String org = getString(data, "org");
        String[] parts = splitOrg(org);

        return new IPInfo(
                getStringOrDefault(data, "ip", "Unknown"),
                getString(data, "city"),
                getString(data, "region"),
                getString(data, "country"),
                getString(data, "postal"),
                getString(data, "timezone"),
                getString(data, "loc"),
                parts[1],
                parts[0]
        );
    }

    /**
     * Resolves the caller's public IP address.
     *
     * @return an {@link IPInfo} instance
     * @throws IOException if the request fails or the API returns an error
     * @throws InterruptedException if the request is interrupted
     */
    public static IPInfo lookupIP() throws IOException, InterruptedException {
        return lookupIP("");
    }

    /**
     * Looks up domain registration data via RDAP.
     *
     * @param domain the domain name to query
     * @return a {@link WhoisInfo} instance
     * @throws IOException if the domain is not found or the API returns an error
     * @throws InterruptedException if the request is interrupted
     */
    public static WhoisInfo lookupWhois(String domain) throws IOException, InterruptedException {
        String normalized = normalizeDomain(domain);
        String url = RDAP_BASE + "/domain/" + normalized;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(TIMEOUT)
                .header("Accept", "application/rdap+json, application/json")
                .GET()
                .build();

        HttpResponse<String> response = CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 404) {
            throw new IOException("Domain not found, or its registry does not support RDAP.");
        }
        if (response.statusCode() != 200) {
            throw new IOException("Lookup failed: HTTP " + response.statusCode());
        }

        JsonObject data = JsonParser.parseString(response.body()).getAsJsonObject();

        if (data.has("errorCode")) {
            String title = getString(data, "title");
            String description = getString(data, "description");
            throw new IOException(title != null ? title : (description != null ? description : "Lookup failed."));
        }

        String name = getString(data, "ldhName");
        if (name == null) name = getString(data, "unicodeName");
        if (name == null) name = "Unknown";

        return new WhoisInfo(
                name,
                extractRegistrar(data),
                extractStatus(data),
                extractEventDate(data, "registration"),
                extractEventDate(data, "last changed"),
                extractEventDate(data, "expiration"),
                extractNameservers(data),
                extractDnssec(data)
        );
    }

    /**
     * Queries DNS records for a domain.
     *
     * @param domain the domain name to query
     * @param recordType one of {@code A}, {@code AAAA}, {@code CNAME}, {@code MX}, {@code TXT}, or {@code NS}
     * @return a list of record values
     * @throws IOException if the record type is unsupported or the query fails
     * @throws InterruptedException if the request is interrupted
     */
    public static List<String> lookupDns(String domain, String recordType)
            throws IOException, InterruptedException {

        String type = recordType.toUpperCase();
        if (!isSupportedDnsType(type)) {
            throw new IOException("Unsupported record type: " + type);
        }

        String encodedName = URLEncoder.encode(domain, StandardCharsets.UTF_8);
        String url = DOH_ENDPOINT + "?name=" + encodedName + "&type=" + type;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(TIMEOUT)
                .header("Accept", "application/dns-json")
                .GET()
                .build();

        HttpResponse<String> response = CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException("DNS query failed: HTTP " + response.statusCode());
        }

        JsonObject data = JsonParser.parseString(response.body()).getAsJsonObject();
        int status = data.has("Status") ? data.get("Status").getAsInt() : 0;

        if (status == 3) {
            throw new IOException("Domain does not exist.");
        }
        if (status != 0) {
            throw new IOException("DNS query returned status " + status + ".");
        }

        List<String> answers = new ArrayList<>();
        if (data.has("Answer")) {
            JsonArray array = data.getAsJsonArray("Answer");
            for (JsonElement element : array) {
                JsonObject answer = element.getAsJsonObject();
                if (answer.has("data")) {
                    answers.add(answer.get("data").getAsString());
                }
            }
        }
        return answers;
    }

    private static JsonObject getJson(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(TIMEOUT)
                .GET()
                .build();

        HttpResponse<String> response = CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException("Request failed: HTTP " + response.statusCode());
        }

        return JsonParser.parseString(response.body()).getAsJsonObject();
    }

    private static String[] splitOrg(String org) {
        if (org == null || org.isEmpty()) {
            return new String[]{null, null};
        }
        int space = org.indexOf(' ');
        if (space > 0 && org.substring(0, space).toUpperCase().startsWith("AS")) {
            return new String[]{org.substring(0, space), org.substring(space + 1)};
        }
        return new String[]{null, org};
    }

    private static String normalizeDomain(String domain) {
        String result = domain.trim().toLowerCase();
        for (String prefix : new String[]{"https://", "http://", "www."}) {
            if (result.startsWith(prefix)) {
                result = result.substring(prefix.length());
            }
        }
        int slash = result.indexOf('/');
        return slash >= 0 ? result.substring(0, slash) : result;
    }

    private static boolean isSupportedDnsType(String type) {
        switch (type) {
            case "A":
            case "NS":
            case "CNAME":
            case "MX":
            case "TXT":
            case "AAAA":
                return true;
            default:
                return false;
        }
    }

    private static String extractRegistrar(JsonObject data) {
        if (!data.has("entities")) return null;
        JsonArray entities = data.getAsJsonArray("entities");
        for (JsonElement element : entities) {
            JsonObject entity = element.getAsJsonObject();
            if (!entity.has("roles")) continue;
            JsonArray roles = entity.getAsJsonArray("roles");
            boolean isRegistrar = false;
            for (JsonElement role : roles) {
                if ("registrar".equals(role.getAsString())) {
                    isRegistrar = true;
                    break;
                }
            }
            if (!isRegistrar) continue;
            if (!entity.has("vcardArray")) continue;
            JsonArray vcard = entity.getAsJsonArray("vcardArray");
            if (vcard.size() < 2) continue;
            JsonArray vcardData = vcard.get(1).getAsJsonArray();
            for (JsonElement item : vcardData) {
                JsonArray entry = item.getAsJsonArray();
                if (entry.size() >= 4 && "fn".equals(entry.get(0).getAsString())) {
                    return entry.get(3).getAsString();
                }
            }
        }
        return null;
    }

    private static List<String> extractStatus(JsonObject data) {
        List<String> result = new ArrayList<>();
        if (!data.has("status")) return result;
        for (JsonElement element : data.getAsJsonArray("status")) {
            result.add(element.getAsString());
        }
        return result;
    }

    private static String extractEventDate(JsonObject data, String action) {
        if (!data.has("events")) return null;
        for (JsonElement element : data.getAsJsonArray("events")) {
            JsonObject event = element.getAsJsonObject();
            if (action.equals(getString(event, "eventAction"))) {
                String date = getString(event, "eventDate");
                return date != null && date.length() >= 10 ? date.substring(0, 10) : null;
            }
        }
        return null;
    }

    private static List<String> extractNameservers(JsonObject data) {
        List<String> result = new ArrayList<>();
        if (!data.has("nameservers")) return result;
        for (JsonElement element : data.getAsJsonArray("nameservers")) {
            JsonObject ns = element.getAsJsonObject();
            String name = getString(ns, "ldhName");
            if (name != null) {
                result.add(name.toLowerCase());
            }
        }
        return result;
    }

    private static String extractDnssec(JsonObject data) {
        if (!data.has("secureDNS")) return "Unsigned";
        JsonObject secureDns = data.getAsJsonObject("secureDNS");
        if (secureDns.has("delegationSigned") && secureDns.get("delegationSigned").getAsBoolean()) {
            return "Signed";
        }
        return "Unsigned";
    }

    private static String getString(JsonObject object, String key) {
        if (object.has(key) && !object.get(key).isJsonNull()) {
            return object.get(key).getAsString();
        }
        return null;
    }

    private static String getStringOrDefault(JsonObject object, String key, String fallback) {
        String value = getString(object, key);
        return value != null ? value : fallback;
    }
}

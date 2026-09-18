package com.ipmation;

/**
 * Structured result of an IP address lookup.
 */
public final class IPInfo {

    private final String ip;
    private final String city;
    private final String region;
    private final String country;
    private final String postal;
    private final String timezone;
    private final String loc;
    private final String isp;
    private final String asn;

    public IPInfo(String ip, String city, String region, String country,
                  String postal, String timezone, String loc, String isp, String asn) {
        this.ip = ip;
        this.city = city;
        this.region = region;
        this.country = country;
        this.postal = postal;
        this.timezone = timezone;
        this.loc = loc;
        this.isp = isp;
        this.asn = asn;
    }

    public String getIp()       { return ip; }
    public String getCity()     { return city; }
    public String getRegion()   { return region; }
    public String getCountry()  { return country; }
    public String getPostal()   { return postal; }
    public String getTimezone() { return timezone; }
    public String getLoc()      { return loc; }
    public String getIsp()      { return isp; }
    public String getAsn()      { return asn; }

    @Override
    public String toString() {
        return "IPInfo{ip=" + ip + ", city=" + city + ", country=" + country + "}";
    }
}

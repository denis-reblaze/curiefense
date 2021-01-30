use lazy_static::lazy_static;
use maxminddb::{
    geoip2::{Asn, Country},
    Reader,
};
use std::net::IpAddr;

lazy_static! {
    // as they are lazy, these loads will not be triggered in test mode
    static ref ASN: Reader<Vec<u8>> =
        Reader::open_readfile("/config/current/config/maxmind/GeoLite2-ASN.mmdb").unwrap();
    static ref COUNTRY: Reader<Vec<u8>> =
        Reader::open_readfile("/config/current/config/maxmind/GeoLite2-Country.mmdb").unwrap();
}

/// Retrieves the english name of the country associated with this IP
#[cfg(not(test))]
pub fn get_country(addr: IpAddr) -> Option<String> {
    let mcountry: Option<Country> = COUNTRY.lookup(addr).ok();
    Some(mcountry?.country?.iso_code?.to_lowercase())
}

#[cfg(not(test))]
pub fn get_asn(addr: IpAddr) -> Option<Asn> {
    ASN.lookup(addr).ok()
}

#[cfg(test)]
pub fn get_country(_addr: IpAddr) -> Option<String> {
    None
}

#[cfg(test)]
pub fn get_asn(_addr: IpAddr) -> Option<Asn> {
    None
}

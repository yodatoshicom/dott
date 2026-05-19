pub const ALL_TLDS: &[&str] = &[
    "com", "net", "org", "io", "dev", "app", "co", "ai", "me", "so", "gg", "cc", "cv", "xyz",
    "live", "computer", "sh", "fm", "fyi", "work",
];

pub fn tld_rank(domain: &str) -> u8 {
    let tld = domain.rsplit('.').next().unwrap_or("");
    match tld {
        "com" => 0,
        "io" => 1,
        "dev" => 2,
        "ai" => 3,
        "app" => 4,
        "co" => 5,
        "net" => 6,
        "org" => 7,
        "me" => 8,
        "so" => 9,
        "gg" => 10,
        "cc" => 11,
        "xyz" => 12,
        "cv" => 13,
        "live" => 14,
        "computer" => 15,
        "sh" => 16,
        "fm" => 17,
        "fyi" => 18,
        "work" => 19,
        _ => 99,
    }
}

// short names in these TLDs are almost always registrar-priced as premium (e.g. go.ai = $20k+).
// heuristic only — RDAP/WHOIS will still say "available", but checkout will hit the user with a surprise.
pub fn is_likely_premium(domain: &str) -> bool {
    let Some((name, tld)) = domain.rsplit_once('.') else {
        return false;
    };
    name.len() <= 4 && matches!(tld, "ai" | "io" | "app" | "dev" | "co" | "cv")
}

pub fn tld_price(tld: &str) -> Option<&'static str> {
    // Registration prices from Porkbun, April 2026
    match tld {
        "com" => Some("$11.08"),
        "net" => Some("$12.52"),
        "org" => Some("$10.74"),
        "io" => Some("$51.80"),
        "dev" => Some("$12.87"),
        "app" => Some("$14.93"),
        "co" => Some("$25.03"),
        "ai" => Some("$82.70"),
        "me" => Some("$17.27"),
        "so" => Some("€55.22"),
        "gg" => Some("$51.80"),
        "cc" => Some("$8.55"),
        "xyz" => Some("$12.98"),
        "cv" => Some("$8.03"),
        "live" => Some("$26.26"),
        "computer" => Some("$31.41"),
        "sh" => Some("$46.65"),
        "fm" => Some("$87.85"),
        "fyi" => Some("$5.66"),
        "work" => Some("$10.81"),
        _ => None,
    }
}

pub fn rdap_url(name: &str, tld: &str) -> Option<String> {
    match tld {
        "com" => Some(format!("https://rdap.verisign.com/com/v1/domain/{}.{}", name, tld)),
        "net" => Some(format!("https://rdap.verisign.com/net/v1/domain/{}.{}", name, tld)),
        "org" => Some(format!(
            "https://rdap.publicinterestregistry.org/rdap/domain/{}.{}",
            name, tld
        )),
        "io" => Some(format!(
            "https://rdap.identitydigital.services/rdap/domain/{}.{}",
            name, tld
        )),
        "dev" => Some(format!("https://pubapi.registry.google/rdap/domain/{}.{}", name, tld)),
        "app" => Some(format!("https://pubapi.registry.google/rdap/domain/{}.{}", name, tld)),
        "ai" => Some(format!(
            "https://rdap.identitydigital.services/rdap/domain/{}.{}",
            name, tld
        )),
        "me" => Some(format!(
            "https://rdap.identitydigital.services/rdap/domain/{}.{}",
            name, tld
        )),
        "cc" => Some(format!(
            "https://tld-rdap.verisign.com/cc/v1/domain/{}.{}",
            name, tld
        )),
        "xyz" => Some(format!("https://rdap.centralnic.com/xyz/domain/{}.{}", name, tld)),
        "cv" => Some(format!("https://rdap.nic.cv/domain/{}.{}", name, tld)),
        "live" => Some(format!(
            "https://rdap.identitydigital.services/rdap/domain/{}.{}",
            name, tld
        )),
        "computer" => Some(format!(
            "https://rdap.identitydigital.services/rdap/domain/{}.{}",
            name, tld
        )),
        "fm" => Some(format!("https://rdap.centralnic.com/fm/domain/{}.{}", name, tld)),
        "fyi" => Some(format!(
            "https://rdap.identitydigital.services/rdap/domain/{}.{}",
            name, tld
        )),
        "work" => Some(format!(
            "https://rdap.identitydigital.services/rdap/domain/{}.{}",
            name, tld
        )),
        "sh" => None, // rdap.nic.sh doesn't resolve — use WHOIS only
        "gg" => None, // rdap.gg returns HTML — use WHOIS only
        _ => Some(format!("https://rdap.org/domain/{}.{}", name, tld)),
    }
}

pub fn whois_server(tld: &str) -> Option<&'static str> {
    match tld {
        // only list servers confirmed working — dead servers cause 4s timeouts
        "com" => Some("whois.verisign-grs.com"),
        "net" => Some("whois.verisign-grs.com"),
        "org" => Some("whois.pir.org"),
        "io" => Some("whois.nic.io"),
        "co" => Some("whois.registry.co"),
        "ai" => Some("whois.nic.ai"),
        "me" => Some("whois.nic.me"),
        "so" => Some("whois.nic.so"),
        "cc" => Some("whois.nic.cc"),
        "xyz" => Some("whois.nic.xyz"),
        "gg" => Some("whois.gg"),
        "sh" => Some("whois.nic.sh"),
        "fm" => Some("whois.nic.fm"),
        _ => None,
    }
}

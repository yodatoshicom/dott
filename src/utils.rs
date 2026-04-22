// find the first YYYY-MM-DD pattern in a string
pub fn parse_date(s: &str) -> Option<String> {
    let b = s.as_bytes();
    for i in 0..b.len().saturating_sub(9) {
        if b[i..i + 4].iter().all(|c| c.is_ascii_digit())
            && b[i + 4] == b'-'
            && b[i + 5..i + 7].iter().all(|c| c.is_ascii_digit())
            && b[i + 7] == b'-'
            && b[i + 8..i + 10].iter().all(|c| c.is_ascii_digit())
        {
            return Some(s[i..i + 10].to_string());
        }
    }
    None
}

// parse "26th February 2015" (anywhere in s) → "2015-02-26".
// whois.gg publishes dates in prose, so parse_date (ISO-only) can't read them.
pub fn parse_prose_date(s: &str) -> Option<String> {
    const MONTHS: [&str; 12] = [
        "january",
        "february",
        "march",
        "april",
        "may",
        "june",
        "july",
        "august",
        "september",
        "october",
        "november",
        "december",
    ];
    let lower = s.to_lowercase();
    let tokens: Vec<&str> = lower.split_whitespace().collect();
    if tokens.len() < 3 {
        return None;
    }
    for i in 0..=tokens.len() - 3 {
        let Ok(day) = tokens[i]
            .trim_end_matches(char::is_alphabetic)
            .parse::<u32>()
        else {
            continue;
        };
        if !(1..=31).contains(&day) {
            continue;
        }
        let Some(month_idx) = MONTHS.iter().position(|m| *m == tokens[i + 1]) else {
            continue;
        };
        let Ok(year) = tokens[i + 2].parse::<u32>() else {
            continue;
        };
        if !(1900..2100).contains(&year) {
            continue;
        }
        return Some(format!("{:04}-{:02}-{:02}", year, month_idx + 1, day));
    }
    None
}

pub fn date_to_epoch_days(y: i64, m: i64, d: i64) -> i64 {
    let a = (14 - m) / 12;
    let y2 = y + 4800 - a;
    let m2 = m + 12 * a - 3;
    let jdn = d + (153 * m2 + 2) / 5 + 365 * y2 + y2 / 4 - y2 / 100 + y2 / 400 - 32045;
    jdn - 2440588
}

pub fn days_until(date_str: &str) -> Option<i64> {
    let p: Vec<i64> = date_str
        .splitn(3, '-')
        .map(|s| s.parse().ok())
        .collect::<Option<Vec<_>>>()?;
    let target = date_to_epoch_days(p[0], p[1], p[2]);
    let today = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64
        / 86400;
    Some(target - today)
}

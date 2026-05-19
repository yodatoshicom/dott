use colored::*;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType},
};
use futures::future::join_all;
use reqwest::Client;
use std::{
    fs,
    io::{self, BufRead, IsTerminal, Write},
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
mod cli;
mod config;
mod model;
mod utils;

use clap::Parser;
use cli::Cli;
use config::{ALL_TLDS, is_likely_premium, rdap_url, tld_price, tld_rank, whois_server};
use model::{Availability, DomainDates, WatchEntry};
use utils::{days_until, parse_date, parse_prose_date};

async fn whois_check(name: &str, tld: &str) -> Availability {
    let server = match whois_server(tld) {
        Some(s) => s,
        None    => return Availability::Unknown,
    };
    let addr  = format!("{}:43", server);
    let query = format!("{}.{}\r\n", name, tld);

    // some registries (e.g. whois.registry.co) are slow to accept — give them more time
    let connect_secs = match server {
        "whois.registry.co" => 8,
        _ => 4,
    };

    let mut stream = match tokio::time::timeout(
        Duration::from_secs(connect_secs),
        TcpStream::connect(&addr),
    ).await {
        Ok(Ok(s)) => s,
        _         => return Availability::Unknown,
    };

    // CentralNic (whois.registry.co) sends a banner on connect — drain it before querying
    if server == "whois.registry.co" {
        let mut banner = vec![0u8; 512];
        let _ = tokio::time::timeout(
            Duration::from_millis(300),
            stream.read(&mut banner),
        ).await;
    }

    if stream.write_all(query.as_bytes()).await.is_err() {
        return Availability::Unknown;
    }

    let mut response = String::new();
    let _ = tokio::time::timeout(
        Duration::from_secs(8),
        stream.read_to_string(&mut response),
    ).await;

    let lower = response.to_lowercase();
    // check Taken first: CentralNic's .co footer contains the word "available"
    // in boilerplate, which otherwise tripped the Available heuristic.
    if lower.contains("domain name:") || lower.contains("domain:") {
        let dates = if tld == "gg" {
            // whois.gg is "registered until cancelled" — no expiry published.
            // registration date is prose: "Registered on 26th February 2015".
            let registered = response.lines()
                .find(|l| l.to_lowercase().contains("registered on"))
                .and_then(parse_prose_date);
            DomainDates { registered, updated: None, expires: None }
        } else {
            let extract = |keyword: &str| -> Option<String> {
                response.lines()
                    .find(|l| l.to_lowercase().contains(keyword))
                    .and_then(|l| l.find(':').map(|i| &l[i+1..]))
                    .and_then(|s| parse_date(s.trim()))
            };
            DomainDates {
                registered: extract("creat").or_else(|| extract("registered:")),
                updated:    extract("updat").or_else(|| extract("last modified").or_else(|| extract("changed:"))),
                expires:    extract("expir").or_else(|| extract("paid-till")).or_else(|| extract("renewal")),
            }
        };
        Availability::Taken(dates)
    } else if lower.contains("no match")
        || lower.contains("not found")
        || lower.contains("no entries found")
        || lower.contains("object does not exist")
        || lower.contains("domain not found")
        || lower.contains("available")
    {
        Availability::Available
    } else {
        Availability::Unknown
    }
}

async fn dns_check(client: &Client, name: &str, tld: &str) -> Availability {
    let url = format!("https://cloudflare-dns.com/dns-query?name={}.{}&type=NS", name, tld);
    let res = client
        .get(&url)
        .header("Accept", "application/dns-json")
        .timeout(Duration::from_secs(4))
        .send().await;
    match res {
        Ok(r) => {
            let json: serde_json::Value = r.json().await.unwrap_or_default();
            // Status=0 alone isn't enough: some registries (e.g. .fm) return NOERROR
            // with empty Answer for non-existent domains. Require actual NS records.
            let has_ns = json["Answer"].as_array().is_some_and(|a| !a.is_empty());
            match json["Status"].as_i64() {
                Some(0) if has_ns => Availability::Taken(DomainDates::default()),
                _ => Availability::Unknown,
            }
        }
        Err(_) => Availability::Unknown,
    }
}

async fn http_query(client: &Client, url: &str, sem: &Semaphore) -> Availability {
    let _permit = sem.acquire().await.unwrap();
    match client.get(url).header("User-Agent", "Mozilla/5.0").header("Accept", "application/json").timeout(Duration::from_secs(5)).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            match status {
                200 => {
                    let dates = serde_json::from_str::<serde_json::Value>(&body).ok()
                        .and_then(|j| j["events"].as_array().cloned())
                        .map(|events| {
                            let find = |keyword: &str| -> Option<String> {
                                events.iter()
                                    .find(|e| e["eventAction"].as_str()
                                        .map(|a| a == keyword)
                                        .unwrap_or(false))
                                    .and_then(|e| e["eventDate"].as_str())
                                    .and_then(|d| parse_date(d))
                            };
                            DomainDates {
                                registered: find("registration"),
                                updated:    find("last changed"),
                                expires:    events.iter()
                                    .find(|e| e["eventAction"].as_str()
                                        .map(|a| a.contains("expir"))
                                        .unwrap_or(false))
                                    .and_then(|e| e["eventDate"].as_str())
                                    .and_then(|d| parse_date(d)),
                            }
                        })
                        .unwrap_or_default();
                    Availability::Taken(dates)
                }
                404 => {
                    if body.contains("Blocked") || body.contains("blocked") {
                        Availability::Protected
                    } else {
                        Availability::Available
                    }
                }
                _ => Availability::Unknown,
            }
        }
        Err(_) => Availability::Unknown,
    }
}

fn merge_dates(a: DomainDates, b: DomainDates) -> DomainDates {
    DomainDates {
        registered: a.registered.or(b.registered),
        updated:    a.updated.or(b.updated),
        expires:    a.expires.or(b.expires),
    }
}

fn merge_results(rdap: Availability, whois: Availability, dns: Availability) -> Availability {
    // DNS Taken (active NS records) = definitely registered; pull dates from RDAP/WHOIS if present
    if matches!(dns, Availability::Taken(_)) {
        let dates = match (rdap, whois) {
            (Availability::Taken(a), Availability::Taken(b)) => merge_dates(a, b),
            (Availability::Taken(a), _) => a,
            (_, Availability::Taken(b)) => b,
            _ => DomainDates::default(),
        };
        return Availability::Taken(dates);
    }

    let rdap_vs_whois = match (rdap, whois) {
        (Availability::Unknown, whois)                     => whois,
        (Availability::Taken(a), Availability::Taken(b))   => Availability::Taken(merge_dates(a, b)),
        (rdap, _)                                          => rdap,
    };

    match rdap_vs_whois {
        Availability::Unknown => dns,
        other => other,
    }
}

// 60s in-session cache, keyed on (name, tld). Avoids re-fetching when interactive searches overlap
// (e.g. typing `foo` then `foo+` would otherwise re-query foo.com/io/dev/app/co).
type Cache = Arc<std::sync::Mutex<std::collections::HashMap<(String, &'static str), (std::time::Instant, Availability)>>>;

const CACHE_TTL: Duration = Duration::from_secs(60);

fn new_cache() -> Cache {
    Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()))
}

async fn check_domain_cached(
    client: Client,
    name: String,
    tld: &'static str,
    sem: Arc<Semaphore>,
    cache: Option<Cache>,
) -> (String, Availability) {
    if let Some(ref c) = cache {
        if let Ok(map) = c.lock() {
            if let Some((t, av)) = map.get(&(name.clone(), tld)) {
                if t.elapsed() < CACHE_TTL {
                    return (format!("{}.{}", name, tld), av.clone());
                }
            }
        }
    }
    let (domain, av) = check_domain(client, name.clone(), tld, sem).await;
    if let Some(ref c) = cache {
        if let Ok(mut map) = c.lock() {
            map.insert((name, tld), (std::time::Instant::now(), av.clone()));
        }
    }
    (domain, av)
}

async fn check_domain(client: Client, name: String, tld: &'static str, sem: Arc<Semaphore>) -> (String, Availability) {
    let domain = format!("{}.{}", name, tld);

    let rdap_fut = async {
        let Some(primary) = rdap_url(&name, tld) else {
            return Availability::Unknown;
        };
        let result = http_query(&client, &primary, &sem).await;
        match result {
            Availability::Unknown => {
                let fallback = format!("https://rdap.org/domain/{}.{}", name, tld);
                if fallback != primary { http_query(&client, &fallback, &sem).await }
                else { Availability::Unknown }
            }
            other => other,
        }
    };

    // WHOIS is the slowest source (TCP read can hang up to 8s). Spawn it cancellable
    // and only await if RDAP couldn't give us a confident answer.
    let whois_handle = tokio::spawn({
        let name = name.clone();
        async move { whois_check(&name, tld).await }
    });

    let (rdap_result, dns_result) = tokio::join!(
        rdap_fut,
        dns_check(&client, &name, tld)
    );

    let whois_result = if matches!(rdap_result, Availability::Unknown) {
        whois_handle.await.unwrap_or(Availability::Unknown)
    } else {
        whois_handle.abort();
        Availability::Unknown
    };

    (domain, merge_results(rdap_result, whois_result, dns_result))
}

fn format_result(domain: &str, availability: &Availability, pad: usize) -> String {
    let padded = format!("{:<width$}", domain, width = pad);
    match availability {
        Availability::Available   => {
            let tld = domain.rsplit('.').next().unwrap_or("");
            let price_str = tld_price(tld)
                .map(|p| format!("  {}/yr.", p).truecolor(100, 210, 210).to_string())
                .unwrap_or_default();
            let premium_str = if is_likely_premium(domain) {
                "  ⚠ likely premium".truecolor(220, 170, 60).to_string()
            } else {
                String::new()
            };
            format!("  {}  {}{}{}", "✓".bright_green().bold(), padded.bright_white().bold(), price_str, premium_str)
        }
        Availability::Protected   => format!("  {}  {}  {}", "★".bright_yellow().bold(), padded.truecolor(60, 60, 80), "brand protected".truecolor(80, 80, 100)),
        Availability::Unknown     => format!("  {}  {}", "?".bright_yellow(), padded.truecolor(100, 100, 80)),
        Availability::Taken(dates) => {
            let mut info = String::new();
            if let Some(ref d) = dates.registered { info.push_str(&format!("  reg {}", d)); }
            if let Some(ref d) = dates.updated    { info.push_str(&format!("  upd {}", d)); }
            let exp_str = dates.expires.as_ref().map(|d| {
                let label = format!("  exp {}", d);
                match days_until(d) {
                    Some(n) if n < 90  => label.truecolor(220, 100, 60).to_string(),
                    Some(n) if n < 365 => label.truecolor(200, 170, 60).to_string(),
                    _                  => label.truecolor(110, 100, 150).to_string(),
                }
            });
            let meta = info.truecolor(110, 100, 150).to_string()
                + exp_str.as_deref().unwrap_or("");
            if dates.registered.is_none() && dates.updated.is_none() && dates.expires.is_none() {
                format!("  {}  {}", "✗".truecolor(70, 70, 90), padded.truecolor(60, 60, 80))
            } else {
                format!("  {}  {}{}", "✗".truecolor(70, 70, 90), padded.truecolor(60, 60, 80), meta)
            }
        }
    }
}

fn generate_suggestions(keywords: &[String]) -> Vec<String> {
    let prefixes = ["get", "try", "use", "go", "my", "the", "run", "hey"];
    let suffixes = ["hq", "app", "lab", "hub", "base"];
    let mut names = Vec::new();
    for kw in keywords {
        names.push(kw.clone());
        for p in &prefixes { names.push(format!("{}{}", p, kw)); }
        for s in &suffixes { names.push(format!("{}{}", kw, s)); }
    }
    if keywords.len() >= 2 {
        names.push(keywords.join(""));
        names.push(keywords.join("-"));
    }
    let mut seen = std::collections::HashSet::new();
    names.retain(|n| seen.insert(n.clone()));
    names.truncate(14);
    names
}

fn print_help() {
    let row = |c: &str, desc: &str| {
        println!("    {}{}",
            format!("{:<20}", c).bright_white(),
            desc.truecolor(110, 110, 140)
        );
    };
    println!();
    println!("  {}", "search".truecolor(80, 80, 100));
    row("name",              "check name across all TLDs");
    row("name.tld",          "check a single domain");
    row("name+",             "suggest prefix/suffix variants");
    row("+",                 "suggest for last searched name");
    println!();
    println!("  {}", "watchlist".truecolor(80, 80, 100));
    row("/watch <domain>",   "get notified when a domain frees up");
    row("/unwatch <domain>", "stop watching");
    row("/list",             "show watchlist");
    println!();
    println!("  {}", "other".truecolor(80, 80, 100));
    row("/help",             "show this help");
    row("exit, q",           "quit (also esc)");
    println!();
}

fn print_cat() {
    println!();
    println!("{}", "   ____       _   _ ".truecolor(255, 155, 0));
    println!("{}", "  |  _ \\  ___| |_| |_".truecolor(255, 60, 90));
    println!("{}", "  | | | |/ _ \\ __| __|".truecolor(180, 50, 230));
    println!("{}", "  | |_| | (_) | |_| |_".truecolor(80, 130, 255));
    println!("{}", format!("  |____/ \\___/ \\__|\\__|  v{}", env!("CARGO_PKG_VERSION")).truecolor(50, 215, 235));
    println!();
    println!("{}", "  private domain search..".truecolor(80, 80, 110));
    println!("{}", "  type a name and hit enter. /help for commands.".truecolor(110, 105, 140));
    println!();
    println!();
}

// read a line with raw mode — handles typing, backspace, enter, esc/ctrl-c
fn read_input(prompt: &str) -> Option<String> {
    let mut buf = String::new();

    print!("{}", prompt);
    io::stdout().flush().unwrap();

    enable_raw_mode().unwrap();

    let result = loop {
        let Ok(Event::Key(key)) = event::read() else { continue };
        match key.code {
            KeyCode::Esc => break None,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break None,
            KeyCode::Enter => {
                println!();
                break Some(buf.clone());
            }
            KeyCode::Backspace => {
                if !buf.is_empty() {
                    buf.pop();
                    execute!(io::stdout(), cursor::MoveLeft(1), Clear(ClearType::UntilNewLine)).unwrap();
                }
            }
            KeyCode::Char(c) => {
                buf.push(c);
                print!("{}", c);
                io::stdout().flush().unwrap();
            }
            _ => {}
        }
    };

    disable_raw_mode().unwrap();
    result
}

async fn search_and_print(client: &Client, name: &str, tld_list: Vec<&'static str>, plain: bool, cache: Option<&Cache>) {
    let sem = Arc::new(Semaphore::new(10));

    if plain {
        let tasks: Vec<_> = tld_list.iter().map(|tld| {
            check_domain_cached(client.clone(), name.to_string(), tld, sem.clone(), cache.cloned())
        }).collect();
        let results = join_all(tasks).await;
        for (domain, av) in &results {
            println!("{} {}", domain, av.as_str());
        }
        return;
    }

    // Pin each TLD to a fixed row (tld_rank order, so .com is always on top) and stream
    // results into their slot as each check completes. Each pending row gets its own
    // animated spinner; finished rows hold their result.
    let mut tlds = tld_list;
    tlds.sort_by_key(|t| tld_rank(t));
    let n = tlds.len();
    let pad = tlds.iter().map(|t| name.len() + 1 + t.len()).max().unwrap_or(0);

    const FRAMES: [&str; 10] = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"];

    println!();
    {
        let mut out = io::stdout();
        for tld in &tlds {
            let domain = format!("{}.{}", name, tld);
            let padded = format!("{:<width$}", domain, width = pad);
            let _ = writeln!(
                out,
                "  {}  {}",
                FRAMES[0].truecolor(160, 120, 220),
                padded.truecolor(80, 80, 100)
            );
        }
        let _ = out.flush();
    }

    let io_lock = Arc::new(std::sync::Mutex::new(()));
    let done: Arc<Vec<AtomicBool>> = Arc::new((0..n).map(|_| AtomicBool::new(false)).collect());
    let spinning = Arc::new(AtomicBool::new(true));

    // Tick task: every 80ms, repaint each still-pending row with the next spinner frame.
    // Skips rows that have flipped done[i], so finished rows never flicker.
    let tick_handle = {
        let spinning = spinning.clone();
        let done = done.clone();
        let io_lock = io_lock.clone();
        let tlds_t = tlds.clone();
        let name_t = name.to_string();
        tokio::spawn(async move {
            let mut frame = 0usize;
            while spinning.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(80)).await;
                frame = frame.wrapping_add(1);
                let _g = io_lock.lock().unwrap();
                let mut out = io::stdout();
                for (i, d) in done.iter().enumerate() {
                    if d.load(Ordering::Relaxed) { continue; }
                    let up = (n - i) as u16;
                    let domain = format!("{}.{}", name_t, tlds_t[i]);
                    let padded = format!("{:<width$}", domain, width = pad);
                    let _ = execute!(
                        out,
                        cursor::MoveUp(up),
                        cursor::MoveToColumn(0),
                        Clear(ClearType::CurrentLine),
                    );
                    let _ = write!(
                        out,
                        "  {}  {}",
                        FRAMES[frame % FRAMES.len()].truecolor(160, 120, 220),
                        padded.truecolor(80, 80, 100)
                    );
                    let _ = execute!(out, cursor::MoveToNextLine(up));
                }
                let _ = out.flush();
            }
        })
    };

    let task_handles: Vec<_> = tlds.iter().enumerate().map(|(i, tld)| {
        let tld = *tld;
        let client = client.clone();
        let name_s = name.to_string();
        let sem = sem.clone();
        let cache = cache.cloned();
        let io_lock = io_lock.clone();
        let done = done.clone();
        tokio::spawn(async move {
            let (domain, av) = check_domain_cached(client, name_s, tld, sem, cache).await;
            let final_line = format_result(&domain, &av, pad);
            {
                let _g = io_lock.lock().unwrap();
                let mut out = io::stdout();
                let up = (n - i) as u16;
                let _ = execute!(
                    out,
                    cursor::MoveUp(up),
                    cursor::MoveToColumn(0),
                    Clear(ClearType::CurrentLine),
                );
                let _ = write!(out, "{}", final_line);
                let _ = execute!(out, cursor::MoveToNextLine(up));
                let _ = out.flush();
                done[i].store(true, Ordering::Relaxed);
            }
            (domain, av)
        })
    }).collect();

    let mut results: Vec<(String, Availability)> = Vec::with_capacity(n);
    for h in task_handles {
        if let Ok(r) = h.await { results.push(r); }
    }

    spinning.store(false, Ordering::Relaxed);
    let _ = tick_handle.await;

    let available_count = results.iter()
        .filter(|(_, a)| matches!(a, Availability::Available))
        .count();

    println!();
    println!(
        "  {} available  ·  {} checked  ·  {} {}",
        available_count.to_string().bright_green().bold(),
        n.to_string().truecolor(80, 80, 100),
        "/help".truecolor(140, 130, 180),
        "for commands".truecolor(80, 80, 100)
    );
    println!();
}

fn installed_via_brew() -> bool {
    let exe = std::env::current_exe().unwrap_or_default();
    let path = exe.to_string_lossy();
    path.contains("/Cellar/") || path.contains("/homebrew/") || path.contains("/linuxbrew/")
}

async fn print_update(handle: tokio::task::JoinHandle<Option<String>>) {
    if let Ok(Some(version)) = handle.await {
        let hint = if installed_via_brew() {
            format!("brew upgrade dott  (v{})", version)
        } else {
            format!("github.com/yodatoshicom/dott/releases  (v{})", version)
        };
        println!(
            "  {} {}\n",
            "update available →".truecolor(100, 95, 130),
            hint.bright_white()
        );
    }
}

fn watchlist_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".dott").join("watchlist.json")
}

fn load_watchlist() -> Vec<WatchEntry> {
    let path = watchlist_path();
    if !path.exists() { return Vec::new(); }
    serde_json::from_str(&fs::read_to_string(path).unwrap_or_default()).unwrap_or_default()
}

fn save_watchlist(entries: &[WatchEntry]) {
    let path = watchlist_path();
    if let Some(parent) = path.parent() { let _ = fs::create_dir_all(parent); }
    let _ = fs::write(path, serde_json::to_string_pretty(entries).unwrap_or_default());
}

fn send_notification(title: &str, body: &str) {
    let script = format!("display notification {} with title {}",
        serde_json::to_string(body).unwrap_or_default(),
        serde_json::to_string(title).unwrap_or_default());
    let _ = std::process::Command::new("osascript").arg("-e").arg(&script).output();
}

fn install_launch_agent() {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let plist_path = PathBuf::from(&home).join("Library").join("LaunchAgents").join("com.dott.watch.plist");
    let binary = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("dott")).to_string_lossy().to_string();

    // if plist exists and already points to the current binary, leave it alone.
    // otherwise it's stale (binary moved, `brew upgrade`, `cargo install` from a new path) — unload and rewrite.
    if let Ok(existing) = fs::read_to_string(&plist_path) {
        if existing.contains(&binary) { return; }
        let _ = std::process::Command::new("launchctl").arg("unload").arg(&plist_path).output();
    }

    let plist = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.dott.watch</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
        <string>--background-check</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict><key>Hour</key><integer>9</integer><key>Minute</key><integer>0</integer></dict>
</dict>
</plist>"#);
    if let Some(parent) = plist_path.parent() { let _ = fs::create_dir_all(parent); }
    if fs::write(&plist_path, plist).is_ok() {
        let _ = std::process::Command::new("launchctl").arg("load").arg(&plist_path).output();
    }
}

async fn cmd_watch(client: &Client, domain: &str) {
    if !domain.contains('.') {
        println!("\n  {} please specify a full domain, e.g. {}\n", "!".bright_yellow(), format!("dott --watch {}.com", domain).bright_white());
        return;
    }
    let domain = domain.to_lowercase();
    let mut entries = load_watchlist();
    let first_domain = entries.is_empty();

    if entries.iter().any(|e| e.domain == domain) {
        println!("\n  {} {} is already being watched\n", "·".truecolor(100, 100, 120), domain.bright_white());
        return;
    }

    let parts: Vec<&str> = domain.rsplitn(2, '.').collect();
    let tld_str = if parts.len() == 2 { parts[0] } else { "com" };
    let name_str = if parts.len() == 2 { parts[1] } else { domain.as_str() };
    let tld: &'static str = ALL_TLDS.iter().find(|&&t| t == tld_str).copied().unwrap_or("com");
    let (_, status) = check_domain(client.clone(), name_str.to_string(), tld, Arc::new(Semaphore::new(1))).await;
    let status_str = status.as_str().to_string();

    entries.push(WatchEntry { domain: domain.clone(), last_status: status_str.clone() });
    save_watchlist(&entries);
    install_launch_agent();

    println!("\n  {} watching {}", "✓".bright_green().bold(), domain.bright_white().bold());
    if status_str == "available" {
        println!("  {} it's available right now — go register it!", "·".bright_green());
    } else {
        println!("  {} {}", "·".truecolor(80, 80, 100), "you'll get a notification when it becomes available".truecolor(100, 100, 130));
    }

    if first_domain {
        send_notification("dott", &format!("Now watching {} — you'll be notified when it's available.", domain));
        println!("  {} {}", "·".truecolor(80, 80, 100), "test notification sent — if you didn't see it, allow notifications for Script Editor in:".truecolor(100, 100, 130));
        println!("  {}  {}", " ", "System Settings → Notifications → Script Editor".bright_white());
        let _ = std::process::Command::new("open")
            .arg("x-apple.systempreferences:com.apple.preference.notifications")
            .output();
    }
    println!();
}

async fn cmd_unwatch(domain: &str) {
    let domain = domain.to_lowercase();
    let mut entries = load_watchlist();
    let before = entries.len();
    entries.retain(|e| e.domain != domain);
    if entries.len() == before {
        println!("\n  {} {} not in watchlist\n", "·".truecolor(100, 100, 120), domain);
        return;
    }
    save_watchlist(&entries);
    println!("\n  {} stopped watching {}\n", "✓".bright_green().bold(), domain.bright_white().bold());
}

fn cmd_watching_list() {
    let entries = load_watchlist();
    println!();
    if entries.is_empty() {
        println!("  {} no domains being watched", "·".truecolor(100, 100, 120));
        println!("  {} use {} to start\n", "·".truecolor(80, 80, 100), "dott --watch <domain>".bright_white());
        return;
    }
    println!("  {}\n", "watching:".truecolor(80, 80, 100));
    for e in &entries {
        let status_colored = match e.last_status.as_str() {
            "available"  => e.last_status.bright_green().to_string(),
            "taken"      => e.last_status.truecolor(60, 60, 80).to_string(),
            "protected"  => e.last_status.bright_yellow().to_string(),
            _            => e.last_status.truecolor(100, 100, 80).to_string(),
        };
        println!("  {}  {}  {}", "·".truecolor(100, 100, 120), e.domain.bright_white(), status_colored);
    }
    println!();
}

async fn cmd_background_check(client: &Client) {
    let mut entries = load_watchlist();
    if entries.is_empty() { return; }
    let sem = Arc::new(Semaphore::new(5));
    let domains: Vec<(String, &'static str)> = entries.iter().map(|e| {
        let parts: Vec<&str> = e.domain.rsplitn(2, '.').collect();
        let tld_str = if parts.len() == 2 { parts[0] } else { "com" };
        let name = if parts.len() == 2 { parts[1] } else { e.domain.as_str() };
        let tld = ALL_TLDS.iter().find(|&&t| t == tld_str).copied().unwrap_or("com");
        (name.to_string(), tld)
    }).collect();
    let tasks: Vec<_> = domains.iter().map(|(name, tld)| {
        check_domain(client.clone(), name.clone(), tld, sem.clone())
    }).collect();
    let results = join_all(tasks).await;
    let mut changed = false;
    for (entry, (_, status)) in entries.iter_mut().zip(results.iter()) {
        let new_status = status.as_str();
        if new_status != entry.last_status {
            if new_status == "available" {
                send_notification("dott — available!", &format!("{} is now available to register!", entry.domain));
            }
            entry.last_status = new_status.to_string();
            changed = true;
        }
    }
    if changed { save_watchlist(&entries); }
}

async fn check_for_update(client: Client) -> Option<String> {
    let res = client
        .get("https://api.github.com/repos/yodatoshicom/dott/releases/latest")
        .header("User-Agent", "dott")
        .timeout(Duration::from_secs(3))
        .send().await.ok()?;
    let json: serde_json::Value = res.json().await.ok()?;
    let latest = json["tag_name"].as_str()?.trim_start_matches('v').to_string();
    let current = env!("CARGO_PKG_VERSION");
    let parse_ver = |s: &str| -> Option<(u32, u32, u32)> {
        let mut parts = s.split('.');
        Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
    };
    if parse_ver(&latest)? > parse_ver(current)? { Some(latest) } else { None }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let client = Client::new();

    if cli.background_check { cmd_background_check(&client).await; return; }
    if let Some(ref domain) = cli.watch    { cmd_watch(&client, domain).await; return; }
    if let Some(ref domain) = cli.unwatch  { cmd_unwatch(domain).await; return; }
    if cli.watching { cmd_watching_list(); return; }

    // ── pipe mode: read names from stdin, always plain output ──
    if cli.name.is_none() && cli.suggest.is_none() && !io::stdin().is_terminal() {
        let default_tlds: Vec<&'static str> = if let Some(ref t) = cli.tlds {
            t.split(',').filter_map(|s| ALL_TLDS.iter().find(|&&x| x == s.trim()).copied()).collect()
        } else {
            ALL_TLDS.to_vec()
        };
        for line in io::stdin().lock().lines() {
            let Ok(line) = line else { continue };
            let line = line.trim();
            if line.is_empty() { continue; }
            let (name, tlds) = if let Some(dot) = line.rfind('.') {
                let tld_str = &line[dot+1..];
                match ALL_TLDS.iter().find(|&&t| t == tld_str).copied() {
                    Some(tld) => (line[..dot].to_string(), vec![tld]),
                    None => continue,
                }
            } else {
                (line.to_string(), default_tlds.clone())
            };
            search_and_print(&client, &name, tlds, true, None).await;
        }
        return;
    }

    let update_check = tokio::spawn(check_for_update(client.clone()));

    // ── one-shot mode ──────────────────────────────────────────
    if let Some(keywords) = cli.suggest {
        println!();
        println!("{}", "  · d o t t ·".bright_magenta().bold());
        println!();
        println!("  {} {}\n", "generating for:".truecolor(80, 80, 100), keywords.join(", ").bright_white());
        let suggestions = generate_suggestions(&keywords);
        let tlds: Vec<&'static str> = vec!["com", "io", "dev", "app", "co"];
        let sem = Arc::new(Semaphore::new(10));
        let tasks: Vec<_> = suggestions.iter().flat_map(|name| {
            let name = name.clone(); let client = client.clone(); let sem = sem.clone();
            tlds.iter().map(move |tld| check_domain(client.clone(), name.clone(), tld, sem.clone()))
        }).collect();
        let results = join_all(tasks).await;
        let available: Vec<&str> = results.iter()
            .filter(|(_, a)| matches!(a, Availability::Available))
            .map(|(d, _)| d.as_str()).collect();
        if cli.plain {
            for (domain, av) in &results {
                println!("{} {}", domain, av.as_str());
            }
        } else if available.is_empty() {
            println!("  {} nothing available\n", "✗".truecolor(80, 80, 100));
        } else {
            for d in &available { println!("  {}  {}", "✓".bright_green().bold(), d.bright_white().bold()); }
            println!("\n  {} available\n", available.len().to_string().bright_green().bold());
        }
        print_update(update_check).await;
        return;
    }

    if let Some(raw) = cli.name {
        println!();
        println!("{}", "  · d o t t ·".bright_magenta().bold());
        println!();
        let name = if let Some(dot) = raw.find('.') { raw[..dot].to_string() } else { raw };
        let tld_list: Vec<&'static str> = if let Some(ref t) = cli.tlds {
            t.split(',').filter_map(|s| ALL_TLDS.iter().find(|&&x| x == s.trim()).copied()).collect()
        } else {
            ALL_TLDS.to_vec()
        };
        search_and_print(&client, &name, tld_list, cli.plain, None).await;
        print_update(update_check).await;
        return;
    }

    // ── interactive mode ───────────────────────────────────────
    print_cat();

    let cache = new_cache();
    let mut last_name: Option<String> = None;

    loop {
        let prompt = format!("  {} ", "›".bright_magenta().bold());
        match read_input(&prompt) {
            None => {
                println!("\n  {}\n", "bye 🐱".truecolor(180, 140, 200));
                print_update(update_check).await;
                break;
            }
            Some(input) => {
                let input = input.trim().to_string();
                if input.is_empty() { continue; }
                if input == "exit" || input == "quit" || input == "q" {
                    println!("\n  {}\n", "bye 🐱".truecolor(180, 140, 200));
                    print_update(update_check).await;
                    break;
                }

                // 'name+' → suggest ; bare '+' reuses the last searched name
                if let Some(raw) = input.strip_suffix('+') {
                    let name = if raw.is_empty() {
                        match last_name.clone() {
                            Some(n) => n,
                            None => {
                                println!("  {}\n", "search for a name first".truecolor(100, 100, 120));
                                continue;
                            }
                        }
                    } else if let Some(dot) = raw.find('.') {
                        raw[..dot].to_string()
                    } else {
                        raw.to_string()
                    };
                    println!("  {} {}", "suggesting for:".truecolor(80, 80, 100), name.bright_white());
                    let suggestions = generate_suggestions(&[name.clone()]);
                    let tlds: Vec<&'static str> = vec!["com", "io", "dev", "app", "co"];
                    let sem = Arc::new(Semaphore::new(10));
                    let tasks: Vec<_> = suggestions.iter().flat_map(|n| {
                        let n = n.clone();
                        let client = client.clone();
                        let sem = sem.clone();
                        let cache = cache.clone();
                        tlds.iter().map(move |tld| check_domain_cached(client.clone(), n.clone(), tld, sem.clone(), Some(cache.clone())))
                    }).collect();
                    let results = join_all(tasks).await;
                    let available: Vec<&str> = results.iter()
                        .filter(|(_, a)| matches!(a, Availability::Available))
                        .map(|(d, _)| d.as_str())
                        .collect();
                    println!();
                    if available.is_empty() {
                        println!("  {}  nothing available\n", "✗".truecolor(80, 80, 100));
                    } else {
                        for d in &available {
                            println!("  {}  {}", "✓".bright_green().bold(), d.bright_white().bold());
                        }
                        println!();
                        println!("  {} available\n", available.len().to_string().bright_green().bold());
                    }
                    continue;
                }

                // /watch <domain>, /unwatch <domain>, /list
                if let Some(domain) = input.strip_prefix("/watch ") {
                    cmd_watch(&client, domain.trim()).await;
                    continue;
                }
                if let Some(domain) = input.strip_prefix("/unwatch ") {
                    cmd_unwatch(domain.trim()).await;
                    continue;
                }
                if input == "/list" {
                    cmd_watching_list();
                    continue;
                }
                if input == "/help" {
                    print_help();
                    continue;
                }

                // strip TLD if included
                let name = if let Some(dot) = input.find('.') {
                    input[..dot].to_string()
                } else {
                    input
                };
                search_and_print(&client, &name, ALL_TLDS.to_vec(), false, Some(&cache)).await;
                last_name = Some(name);

                println!();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_date_iso() {
        assert_eq!(parse_date("2026-04-19"), Some("2026-04-19".to_string()));
    }

    #[test]
    fn parse_date_embedded_in_timestamp() {
        assert_eq!(parse_date("Expires: 2027-01-15T00:00:00Z"), Some("2027-01-15".to_string()));
    }

    #[test]
    fn parse_date_returns_first_match() {
        assert_eq!(parse_date("reg 2020-01-01 exp 2030-12-31"), Some("2020-01-01".to_string()));
    }

    #[test]
    fn parse_date_none() {
        assert_eq!(parse_date("no dates here"), None);
        assert_eq!(parse_date(""), None);
        assert_eq!(parse_date("2026-1-1"), None); // non-zero-padded rejected
    }

    fn dates_with_expiry(exp: &str) -> DomainDates {
        DomainDates { registered: None, updated: None, expires: Some(exp.to_string()) }
    }

    #[test]
    fn dns_taken_overrides_all_unknown() {
        let out = merge_results(
            Availability::Unknown,
            Availability::Unknown,
            Availability::Taken(DomainDates::default()),
        );
        assert!(matches!(out, Availability::Taken(_)));
    }

    #[test]
    fn dns_taken_keeps_whois_expiry() {
        let out = merge_results(
            Availability::Unknown,
            Availability::Taken(dates_with_expiry("2027-01-01")),
            Availability::Taken(DomainDates::default()),
        );
        match out {
            Availability::Taken(d) => assert_eq!(d.expires.as_deref(), Some("2027-01-01")),
            _ => panic!("expected Taken with WHOIS expiry preserved"),
        }
    }

    #[test]
    fn rdap_wins_but_whois_fills_gaps() {
        let rdap = DomainDates {
            registered: Some("2020-01-01".into()),
            updated:    None,
            expires:    Some("2026-01-01".into()),
        };
        let whois = DomainDates {
            registered: Some("2019-05-05".into()),
            updated:    Some("2024-06-06".into()),
            expires:    Some("2027-12-31".into()),
        };
        let out = merge_results(
            Availability::Taken(rdap),
            Availability::Taken(whois),
            Availability::Unknown,
        );
        match out {
            Availability::Taken(d) => {
                assert_eq!(d.registered.as_deref(), Some("2020-01-01")); // RDAP wins
                assert_eq!(d.updated.as_deref(),    Some("2024-06-06")); // WHOIS fills gap
                assert_eq!(d.expires.as_deref(),    Some("2026-01-01")); // RDAP wins
            }
            _ => panic!("expected Taken"),
        }
    }

    #[test]
    fn rdap_available_beats_everything() {
        let out = merge_results(
            Availability::Available,
            Availability::Taken(DomainDates::default()),
            Availability::Unknown,
        );
        assert!(matches!(out, Availability::Available));
    }

    #[test]
    fn whois_fallback_when_rdap_unknown() {
        let out = merge_results(
            Availability::Unknown,
            Availability::Taken(dates_with_expiry("2027-01-01")),
            Availability::Unknown,
        );
        match out {
            Availability::Taken(d) => assert_eq!(d.expires.as_deref(), Some("2027-01-01")),
            _ => panic!("expected Taken from WHOIS fallback"),
        }
    }

    #[test]
    fn premium_heuristic_flags_short_names_in_premium_tlds() {
        assert!(is_likely_premium("go.ai"));
        assert!(is_likely_premium("x.io"));
        assert!(is_likely_premium("app.dev"));
        assert!(is_likely_premium("four.co"));
    }

    #[test]
    fn premium_heuristic_ignores_long_names_and_other_tlds() {
        assert!(!is_likely_premium("mystartup.ai"));   // too long
        assert!(!is_likely_premium("go.com"));          // not a flagged TLD
        assert!(!is_likely_premium("go.xyz"));          // not a flagged TLD
        assert!(!is_likely_premium("noseparator"));     // no TLD
    }

    #[test]
    fn all_unknown_stays_unknown() {
        let out = merge_results(Availability::Unknown, Availability::Unknown, Availability::Unknown);
        assert!(matches!(out, Availability::Unknown));
    }
}

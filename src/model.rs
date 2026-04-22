#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct WatchEntry {
    pub domain: String,
    pub last_status: String,
}

#[derive(Debug, Clone, Default)]
pub struct DomainDates {
    pub registered: Option<String>,
    pub updated: Option<String>,
    pub expires: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Availability {
    Available,
    Protected,
    Taken(DomainDates),
    Unknown,
}

impl Availability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Availability::Available => "available",
            Availability::Protected => "protected",
            Availability::Taken(_) => "taken",
            Availability::Unknown => "unknown",
        }
    }
}

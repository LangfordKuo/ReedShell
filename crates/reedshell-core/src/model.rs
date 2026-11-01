use serde::{Deserialize, Serialize};

/// Subscription plan attached to an account.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Plan {
    #[default]
    Free,
    Pro,
}

impl Plan {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Pro => "pro",
        }
    }
}

impl std::str::FromStr for Plan {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "free" => Ok(Self::Free),
            "pro" => Ok(Self::Pro),
            _ => Err(()),
        }
    }
}

/// Platform identifier reported by a client during device enrollment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DevicePlatform {
    Windows,
    Macos,
    Android,
    Ios,
    Web,
    #[default]
    Unknown,
}

impl DevicePlatform {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Web => "web",
            Self::Unknown => "unknown",
        }
    }
}

impl std::str::FromStr for DevicePlatform {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "windows" => Ok(Self::Windows),
            "macos" => Ok(Self::Macos),
            "android" => Ok(Self::Android),
            "ios" => Ok(Self::Ios),
            "web" => Ok(Self::Web),
            "unknown" => Ok(Self::Unknown),
            _ => Err(()),
        }
    }
}

/// Lifecycle state of an account.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    #[default]
    Active,
    Suspended,
    PendingDelete,
}

impl UserStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::PendingDelete => "pending_delete",
        }
    }
}

impl std::str::FromStr for UserStatus {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "pending_delete" => Ok(Self::PendingDelete),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_round_trips() {
        for platform in [
            DevicePlatform::Windows,
            DevicePlatform::Macos,
            DevicePlatform::Android,
            DevicePlatform::Ios,
            DevicePlatform::Web,
            DevicePlatform::Unknown,
        ] {
            let value = platform.as_str();
            let parsed: DevicePlatform = value.parse().expect("known platform must parse");
            assert_eq!(platform, parsed);
        }
    }

    #[test]
    fn plan_round_trips() {
        for plan in [Plan::Free, Plan::Pro] {
            let value = plan.as_str();
            let parsed: Plan = value.parse().expect("known plan must parse");
            assert_eq!(plan, parsed);
        }
    }
}

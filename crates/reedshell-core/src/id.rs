use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use ulid::Ulid;

macro_rules! ulid_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Ulid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Ulid::new())
            }

            #[must_use]
            pub fn from_ulid(value: Ulid) -> Self {
                Self(value)
            }

            #[must_use]
            pub fn as_ulid(self) -> Ulid {
                self.0
            }

            #[must_use]
            pub fn to_string_value(self) -> String {
                self.0.to_string()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl FromStr for $name {
            type Err = crate::error::CoreError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Ulid::from_string(value)
                    .map(Self)
                    .map_err(|_| crate::error::CoreError::InvalidId)
            }
        }
    };
}

ulid_id!(UserId);
ulid_id!(DeviceId);
ulid_id!(ItemId);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_text() {
        let id = UserId::new();
        let text = id.to_string();
        let parsed: UserId = text.parse().expect("generated id must parse");
        assert_eq!(id, parsed);
    }

    #[test]
    fn rejects_invalid_text() {
        assert!("not-a-ulid".parse::<DeviceId>().is_err());
    }
}

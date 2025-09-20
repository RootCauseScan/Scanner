use serde::de::Deserializer;
use serde::Deserialize;

pub mod compiled;
pub mod json;
pub mod semgrep;
pub mod yaml;

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum LanguageField {
    Single(String),
    Multiple(Vec<String>),
}

pub(crate) fn deserialize_languages<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<LanguageField>::deserialize(deserializer)?;
    Ok(value.map(|lang| match lang {
        LanguageField::Single(s) => vec![s],
        LanguageField::Multiple(list) => list,
    }))
}

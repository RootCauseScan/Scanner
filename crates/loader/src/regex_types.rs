use fancy_regex::Regex as FancyRegex;
use pcre2::bytes::Regex as Pcre2Regex;
use regex::Regex;

#[derive(Debug, Clone)]
pub enum AnyRegex {
    Std(Regex),
    Fancy(FancyRegex),
    Pcre2(Pcre2Regex),
}

pub struct AnyMatch<'a> {
    text: &'a str,
}

impl<'a> AnyMatch<'a> {
    pub fn as_str(&self) -> &'a str {
        self.text
    }
}

pub struct AnyCaptures<'a> {
    get_fn: Box<dyn Fn(usize) -> Option<AnyMatch<'a>> + 'a>,
}

impl<'a> AnyCaptures<'a> {
    pub fn get(&self, idx: usize) -> Option<AnyMatch<'a>> {
        (self.get_fn)(idx)
    }
}

impl AnyRegex {
    pub fn is_fancy(&self) -> bool {
        matches!(self, Self::Fancy(_))
    }

    pub fn is_pcre2(&self) -> bool {
        matches!(self, Self::Pcre2(_))
    }

    pub fn is_match(&self, text: &str) -> bool {
        match self {
            Self::Std(r) => r.is_match(text),
            Self::Fancy(r) => r.is_match(text).unwrap_or(false),
            Self::Pcre2(r) => r.is_match(text.as_bytes()).unwrap_or(false),
        }
    }

    pub fn find_iter<'a>(&'a self, text: &'a str) -> Box<dyn Iterator<Item = (usize, usize)> + 'a> {
        match self {
            Self::Std(r) => Box::new(r.find_iter(text).map(|m| (m.start(), m.end()))),
            Self::Fancy(r) => Box::new(
                r.find_iter(text)
                    .filter_map(|m| m.ok())
                    .map(|m| (m.start(), m.end())),
            ),
            Self::Pcre2(r) => Box::new(
                r.find_iter(text.as_bytes())
                    .filter_map(|m| m.ok())
                    .map(|m| (m.start(), m.end())),
            ),
        }
    }

    pub fn captures<'a>(&'a self, text: &'a str) -> Option<AnyCaptures<'a>> {
        match self {
            Self::Std(r) => r.captures(text).map(|caps| AnyCaptures {
                get_fn: Box::new(move |idx| caps.get(idx).map(|m| AnyMatch { text: m.as_str() })),
            }),
            Self::Fancy(r) => match r.captures(text) {
                Ok(Some(caps)) => Some(AnyCaptures {
                    get_fn: Box::new(move |idx| {
                        caps.get(idx).map(|m| AnyMatch { text: m.as_str() })
                    }),
                }),
                _ => None,
            },
            Self::Pcre2(r) => match r.captures(text.as_bytes()) {
                Ok(Some(caps)) => Some(AnyCaptures {
                    get_fn: Box::new(move |idx| {
                        caps.get(idx).map(|m| {
                            let text_str = std::str::from_utf8(m.as_bytes()).unwrap_or("");
                            AnyMatch { text: text_str }
                        })
                    }),
                }),
                _ => None,
            },
        }
    }
}

impl From<Regex> for AnyRegex {
    fn from(r: Regex) -> Self {
        AnyRegex::Std(r)
    }
}

impl From<FancyRegex> for AnyRegex {
    fn from(r: FancyRegex) -> Self {
        AnyRegex::Fancy(r)
    }
}

impl From<Pcre2Regex> for AnyRegex {
    fn from(r: Pcre2Regex) -> Self {
        AnyRegex::Pcre2(r)
    }
}

pub mod regex_ext {
    pub type Regex = crate::regex_types::AnyRegex;
}

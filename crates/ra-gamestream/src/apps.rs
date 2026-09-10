//! `/applist` parsing.

use crate::xml::Root;
use crate::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct App {
    pub id: u32,
    pub title: String,
    pub hdr_supported: bool,
    /// Apollo only.
    pub uuid: Option<String>,
}

/// Apollo returns a single fake app with this ID when the caller lacks the
/// `list` permission.
pub const PERMISSION_DENIED_APP_ID: u32 = 114514;

pub fn parse_applist(body: &str) -> Result<Vec<App>> {
    let root = Root::parse(body)?;
    let mut apps = Vec::new();
    for node in root.root().children().filter(|n| n.is_element() && n.tag_name().name() == "App") {
        let text = |name: &str| {
            node.children()
                .find(|c| c.is_element() && c.tag_name().name() == name)
                .and_then(|c| c.text())
                .map(|s| s.trim().to_string())
        };
        let title = text("AppTitle").unwrap_or_default();
        // Apollo "legacy ordering" pads titles with zero-width characters.
        let title: String = title.chars().filter(|c| !matches!(c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}')).collect();
        apps.push(App {
            id: text("ID").and_then(|s| s.parse().ok()).unwrap_or(0),
            title,
            hdr_supported: text("IsHdrSupported").as_deref() == Some("1"),
            uuid: text("UUID"),
        });
    }
    Ok(apps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_apps() {
        let xml = r#"<root status_code="200">
<App><IsHdrSupported>1</IsHdrSupported><AppTitle>Desktop</AppTitle><UUID>abc</UUID><IDX>0</IDX><ID>1</ID></App>
<App><IsHdrSupported>0</IsHdrSupported><AppTitle>&#8203;Steam</AppTitle><ID>2</ID></App>
</root>"#;
        let apps = parse_applist(xml).unwrap();
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0], App { id: 1, title: "Desktop".into(), hdr_supported: true, uuid: Some("abc".into()) });
        assert_eq!(apps[1].title, "Steam");
    }
}

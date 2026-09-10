//! Tiny helpers for the `<root status_code=.. status_message=..>` XML that
//! GameStream servers return.

use crate::{Error, Result};

pub struct Root<'a> {
    doc: roxmltree::Document<'a>,
}

impl<'a> Root<'a> {
    /// Parse and verify `status_code == 200`.
    pub fn parse(body: &'a str) -> Result<Self> {
        let doc = roxmltree::Document::parse(body).map_err(|e| Error::Xml(e.to_string()))?;
        let root = doc.root_element();
        if root.tag_name().name() != "root" {
            return Err(Error::Xml(format!("unexpected root element <{}>", root.tag_name().name())));
        }
        let code: i32 = root.attribute("status_code").unwrap_or("0").parse().unwrap_or(0);
        if code != 200 {
            return Err(Error::Status {
                code,
                message: root.attribute("status_message").unwrap_or("").to_string(),
            });
        }
        Ok(Self { doc })
    }

    /// Text of the first direct child of `<root>` named `name`.
    pub fn child(&self, name: &str) -> Option<&str> {
        self.doc
            .root_element()
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == name)
            .and_then(|n| n.text())
    }

    pub fn require(&self, name: &'static str) -> Result<&str> {
        self.child(name).ok_or(Error::Missing(name))
    }

    pub fn root(&self) -> roxmltree::Node<'_, 'a> {
        self.doc.root_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ok_and_error() {
        let ok = r#"<?xml version="1.0"?><root status_code="200"><paired>1</paired></root>"#;
        assert_eq!(Root::parse(ok).unwrap().child("paired"), Some("1"));
        let bad = r#"<root status_code="403" status_message="Pairing is disabled"/>"#;
        match Root::parse(bad).map(|_| ()) {
            Err(Error::Status { code: 403, message }) => assert_eq!(message, "Pairing is disabled"),
            other => panic!("unexpected {other:?}"),
        }
    }
}

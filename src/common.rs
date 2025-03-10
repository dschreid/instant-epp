//! Common data types included in EPP Requests and Responses

use std::borrow::Cow;

use instant_xml::{Accumulate, FromXml, ToXml};

use crate::request::Extension;

pub(crate) const EPP_XMLNS: &str = "urn:ietf:params:xml:ns:epp-1.0";

#[derive(Debug, Eq, PartialEq, ToXml)]
pub struct NoExtension;

impl<'xml> FromXml<'xml> for NoExtension {
    fn matches(_: instant_xml::Id<'_>, _: Option<instant_xml::Id<'_>>) -> bool {
        false
    }

    fn deserialize<'cx>(
        _: &mut Self::Accumulator,
        _: &'static str,
        _: &mut instant_xml::Deserializer<'cx, 'xml>,
    ) -> Result<(), instant_xml::Error> {
        unreachable!()
    }

    type Accumulator = NoExtensionAccumulator;
    const KIND: instant_xml::Kind = instant_xml::Kind::Element;
}

#[derive(Default)]
pub struct NoExtensionAccumulator;

impl Accumulate<NoExtension> for NoExtensionAccumulator {
    fn try_done(self, _: &'static str) -> Result<NoExtension, instant_xml::Error> {
        Ok(NoExtension)
    }
}

impl Extension for NoExtension {
    type Response = Self;
}

/// The `<option>` type in EPP XML login requests
#[derive(Debug, Eq, FromXml, PartialEq, ToXml)]
#[xml(rename = "options", ns(EPP_XMLNS))]
pub struct Options<'a> {
    /// The EPP version being used
    pub version: Cow<'a, str>,
    /// The language that will be used during EPP transactions
    pub lang: Cow<'a, str>,
}

impl<'a> Options<'a> {
    /// Creates an Options object with version and lang data
    pub fn build(version: &'a str, lang: &'a str) -> Self {
        Self {
            version: version.into(),
            lang: lang.into(),
        }
    }
}

/// The `<svcExtension>` type in EPP XML
#[derive(Debug, Eq, FromXml, PartialEq, ToXml)]
#[xml(rename = "svcExtension", ns(EPP_XMLNS))]
pub struct ServiceExtension<'a> {
    /// The service extension URIs being represented by `<extURI>` in EPP XML
    #[xml(rename = "extURI")]
    pub ext_uris: Vec<Cow<'a, str>>,
}

/// The `<svcs>` type in EPP XML
#[derive(Debug, Eq, FromXml, PartialEq, ToXml)]
#[xml(rename = "svcs", ns(EPP_XMLNS))]
pub struct Services<'a> {
    /// The service URIs being used by this EPP session represented by `<objURI>` in EPP XML
    #[xml(rename = "objURI")]
    pub obj_uris: Vec<Cow<'a, str>>,
    // The `<svcExtension>` being used in this EPP session
    #[xml(rename = "svcExtension")]
    pub svc_ext: Option<ServiceExtension<'a>>,
}

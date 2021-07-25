//! Types for EPP domain transfer request

use epp_client_macros::*;

use crate::epp::object::data::{AuthInfo, Period};
use crate::epp::object::{ElementName, EppObject, StringValue, StringValueTrait};
use crate::epp::request::Command;
use crate::epp::xml::EPP_DOMAIN_XMLNS;
use serde::{Deserialize, Serialize};

/// Type that represents the <epp> request for transfer request for domain
pub type EppDomainTransferRequest = EppObject<Command<DomainTransfer>>;
/// Type that represents the <epp> request for transfer approval for domains
pub type EppDomainTransferApprove = EppObject<Command<DomainTransfer>>;
/// Type that represents the <epp> request for transfer rejection for domains
pub type EppDomainTransferReject = EppObject<Command<DomainTransfer>>;
/// Type that represents the <epp> request for transfer request cancellation for domains
pub type EppDomainTransferCancel = EppObject<Command<DomainTransfer>>;
/// Type that represents the <epp> request for transfer request query for domains
pub type EppDomainTransferQuery = EppObject<Command<DomainTransfer>>;

/// Type for elements under the domain <transfer> tag
#[derive(Serialize, Deserialize, Debug)]
pub struct DomainTransferData {
    /// XML namespace for domain commands
    xmlns: String,
    /// The name of the domain under transfer
    name: StringValue,
    /// The period of renewal upon a successful transfer
    /// Only applicable in case of a transfer request
    period: Option<Period>,
    /// The authInfo for the domain under transfer
    /// Only applicable to domain transfer and domain transfer query requests
    #[serde(rename = "authInfo")]
    auth_info: Option<AuthInfo>,
}

#[derive(Serialize, Deserialize, Debug, ElementName)]
#[element_name(name = "transfer")]
/// Type for EPP XML <transfer> command for domains
pub struct DomainTransfer {
    /// The transfer operation to perform indicated by the 'op' attr
    /// The values are one of transfer, approve, reject, cancel, or query
    #[serde(rename = "op")]
    operation: String,
    /// The data under the <transfer> tag in the transfer request
    #[serde(rename = "transfer")]
    domain: DomainTransferData,
}

impl EppDomainTransferRequest {
    /// Creates a new EppObject for domain transfer request corresponding to the <epp> tag in EPP XML
    pub fn request(
        name: &str,
        years: u16,
        auth_password: &str,
        client_tr_id: &str,
    ) -> EppDomainTransferRequest {
        EppObject::build(Command::<DomainTransfer> {
            command: DomainTransfer {
                operation: "request".to_string(),
                domain: DomainTransferData {
                    xmlns: EPP_DOMAIN_XMLNS.to_string(),
                    name: name.to_string_value(),
                    period: Some(Period::new(years)),
                    auth_info: Some(AuthInfo::new(auth_password)),
                },
            },
            client_tr_id: client_tr_id.to_string_value(),
        })
    }

    /// Sets the period for renewal in case of a successful transfer
    pub fn set_period(&mut self, period: Period) {
        self.data.command.domain.period = Some(period);
    }
}

impl EppDomainTransferApprove {
    /// Creates a new EppObject for domain transfer approval corresponding to the <epp> tag in EPP XML
    pub fn approve(name: &str, client_tr_id: &str) -> EppDomainTransferApprove {
        EppObject::build(Command::<DomainTransfer> {
            command: DomainTransfer {
                operation: "approve".to_string(),
                domain: DomainTransferData {
                    xmlns: EPP_DOMAIN_XMLNS.to_string(),
                    name: name.to_string_value(),
                    period: None,
                    auth_info: None,
                },
            },
            client_tr_id: client_tr_id.to_string_value(),
        })
    }
}

impl EppDomainTransferCancel {
    /// Creates a new EppObject for domain transfer request cancellation corresponding to the <epp> tag in EPP XML
    pub fn cancel(name: &str, client_tr_id: &str) -> EppDomainTransferCancel {
        EppObject::build(Command::<DomainTransfer> {
            command: DomainTransfer {
                operation: "cancel".to_string(),
                domain: DomainTransferData {
                    xmlns: EPP_DOMAIN_XMLNS.to_string(),
                    name: name.to_string_value(),
                    period: None,
                    auth_info: None,
                },
            },
            client_tr_id: client_tr_id.to_string_value(),
        })
    }
}

impl EppDomainTransferReject {
    /// Creates a new EppObject for domain transfer rejection corresponding to the <epp> tag in EPP XML
    pub fn reject(name: &str, client_tr_id: &str) -> EppDomainTransferReject {
        EppObject::build(Command::<DomainTransfer> {
            command: DomainTransfer {
                operation: "reject".to_string(),
                domain: DomainTransferData {
                    xmlns: EPP_DOMAIN_XMLNS.to_string(),
                    name: name.to_string_value(),
                    period: None,
                    auth_info: None,
                },
            },
            client_tr_id: client_tr_id.to_string_value(),
        })
    }
}

impl EppDomainTransferQuery {
    /// Creates a new EppObject for domain transfer request query corresponding to the <epp> tag in EPP XML
    pub fn query(name: &str, auth_password: &str, client_tr_id: &str) -> EppDomainTransferQuery {
        EppObject::build(Command::<DomainTransfer> {
            command: DomainTransfer {
                operation: "query".to_string(),
                domain: DomainTransferData {
                    xmlns: EPP_DOMAIN_XMLNS.to_string(),
                    name: name.to_string_value(),
                    period: None,
                    auth_info: Some(AuthInfo::new(auth_password)),
                },
            },
            client_tr_id: client_tr_id.to_string_value(),
        })
    }
}

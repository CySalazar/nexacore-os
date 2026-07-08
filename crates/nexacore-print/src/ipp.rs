//! IPP (Internet Printing Protocol, RFC 8011) message encode/decode and the
//! common client operations (WS2-13.1 / .3).
//!
//! An IPP message is a binary envelope: a 2-byte version, a 2-byte
//! operation-id (request) or status-code (response), a 4-byte request-id, a
//! sequence of attribute groups, and an end-of-attributes delimiter — optionally
//! followed by the document data. Encode and decode are byte-exact and every
//! read is `.get()`-checked, so a truncated/malformed message returns an error
//! rather than panicking. The transport (HTTP POST to the printer) is the
//! caller's job; this module owns the message body.

use alloc::{string::String, vec::Vec};

// ── Delimiter (group) tags ───────────────────────────────────────────────────

/// `operation-attributes-tag`.
pub const TAG_OPERATION: u8 = 0x01;
/// `job-attributes-tag`.
pub const TAG_JOB: u8 = 0x02;
/// `end-of-attributes-tag`.
pub const TAG_END: u8 = 0x03;
/// `printer-attributes-tag`.
pub const TAG_PRINTER: u8 = 0x04;
/// `unsupported-attributes-tag`.
pub const TAG_UNSUPPORTED: u8 = 0x05;

// ── Value tags (the subset NexaCore emits/reads) ─────────────────────────────

/// `integer` value tag.
pub const VAL_INTEGER: u8 = 0x21;
/// `boolean` value tag.
pub const VAL_BOOLEAN: u8 = 0x22;
/// `enum` value tag.
pub const VAL_ENUM: u8 = 0x23;
/// `textWithoutLanguage` value tag.
pub const VAL_TEXT: u8 = 0x41;
/// `nameWithoutLanguage` value tag.
pub const VAL_NAME: u8 = 0x42;
/// `keyword` value tag.
pub const VAL_KEYWORD: u8 = 0x44;
/// `uri` value tag.
pub const VAL_URI: u8 = 0x45;
/// `charset` value tag.
pub const VAL_CHARSET: u8 = 0x47;
/// `naturalLanguage` value tag.
pub const VAL_NATURAL_LANGUAGE: u8 = 0x48;
/// `mimeMediaType` value tag.
pub const VAL_MIME: u8 = 0x49;

/// An IPP operation id (request) — RFC 8011 §5.4.15 (WS2-13.1/.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum IppOperation {
    /// `Print-Job` — submit a job with its document in one request.
    PrintJob = 0x0002,
    /// `Get-Printer-Attributes`.
    GetPrinterAttributes = 0x000B,
    /// `Create-Job` — open a job to receive documents.
    CreateJob = 0x0005,
    /// `Send-Document` — append a document to a created job.
    SendDocument = 0x0006,
    /// `Get-Job-Attributes`.
    GetJobAttributes = 0x0009,
    /// `Cancel-Job`.
    CancelJob = 0x0008,
}

/// An IPP status code (response) — RFC 8011 §13.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum IppStatus {
    /// `successful-ok`.
    Ok = 0x0000,
    /// `client-error-bad-request`.
    BadRequest = 0x0400,
    /// `client-error-not-found`.
    NotFound = 0x0406,
    /// `server-error-internal-error`.
    InternalError = 0x0500,
}

impl IppStatus {
    /// Map a raw status code to a known [`IppStatus`], if recognized.
    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            0x0000 => Some(Self::Ok),
            0x0400 => Some(Self::BadRequest),
            0x0406 => Some(Self::NotFound),
            0x0500 => Some(Self::InternalError),
            _ => None,
        }
    }
}

/// Why an IPP message could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IppError {
    /// The byte stream ended before a full field.
    Truncated,
    /// A field had an invalid value (e.g. a name longer than the buffer).
    Malformed,
}

impl core::fmt::Display for IppError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated IPP message",
            Self::Malformed => "malformed IPP message",
        })
    }
}

impl core::error::Error for IppError {}

/// One IPP attribute: a value tag, a name, and the raw value bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute {
    /// The value tag (`VAL_*`).
    pub value_tag: u8,
    /// The attribute name (empty for additional values of a 1setOf).
    pub name: String,
    /// The raw value bytes (big-endian integers; UTF-8 for string types).
    pub value: Vec<u8>,
}

impl Attribute {
    /// An `integer`/`enum` attribute.
    #[must_use]
    pub fn integer(name: &str, value: i32) -> Self {
        Self {
            value_tag: VAL_INTEGER,
            name: String::from(name),
            value: value.to_be_bytes().to_vec(),
        }
    }

    /// A string-valued attribute (keyword/uri/charset/name/text/…).
    #[must_use]
    pub fn string(value_tag: u8, name: &str, value: &str) -> Self {
        Self {
            value_tag,
            name: String::from(name),
            value: value.as_bytes().to_vec(),
        }
    }

    /// Interpret the value as a big-endian `i32`.
    #[must_use]
    pub fn as_integer(&self) -> Option<i32> {
        let b: [u8; 4] = self.value.get(..4)?.try_into().ok()?;
        Some(i32::from_be_bytes(b))
    }

    /// Interpret the value as a UTF-8 string.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        core::str::from_utf8(&self.value).ok()
    }
}

/// One delimiter-tagged group of attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttributeGroup {
    /// The delimiter tag (`TAG_OPERATION`/`TAG_JOB`/`TAG_PRINTER`/…).
    pub tag: u8,
    /// The attributes in this group, in order.
    pub attributes: Vec<Attribute>,
}

impl AttributeGroup {
    /// Find the first attribute named `name` in this group.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.name == name)
    }
}

/// A decoded IPP message body (without the trailing document data).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IppMessage {
    /// Protocol major version (2 for IPP/2.0).
    pub version_major: u8,
    /// Protocol minor version.
    pub version_minor: u8,
    /// Operation-id (request) or status-code (response).
    pub operation_or_status: u16,
    /// Request id, echoed by the printer in its response.
    pub request_id: u32,
    /// Attribute groups, in order.
    pub groups: Vec<AttributeGroup>,
}

impl IppMessage {
    /// The standard operation-attributes group every request opens with:
    /// `attributes-charset` (utf-8) and `attributes-natural-language` (en).
    #[must_use]
    fn operation_header() -> AttributeGroup {
        AttributeGroup {
            tag: TAG_OPERATION,
            attributes: alloc::vec![
                Attribute::string(VAL_CHARSET, "attributes-charset", "utf-8"),
                Attribute::string(VAL_NATURAL_LANGUAGE, "attributes-natural-language", "en"),
            ],
        }
    }

    /// Build a `Get-Printer-Attributes` request (WS2-13.1).
    #[must_use]
    pub fn get_printer_attributes(request_id: u32, printer_uri: &str) -> Self {
        let mut op = Self::operation_header();
        op.attributes
            .push(Attribute::string(VAL_URI, "printer-uri", printer_uri));
        Self::request(IppOperation::GetPrinterAttributes, request_id, op)
    }

    /// Build a `Create-Job` request (WS2-13.3).
    #[must_use]
    pub fn create_job(request_id: u32, printer_uri: &str, job_name: &str) -> Self {
        let mut op = Self::operation_header();
        op.attributes
            .push(Attribute::string(VAL_URI, "printer-uri", printer_uri));
        op.attributes
            .push(Attribute::string(VAL_NAME, "job-name", job_name));
        Self::request(IppOperation::CreateJob, request_id, op)
    }

    /// Build a `Send-Document` request for `job_id` (WS2-13.3).
    #[must_use]
    pub fn send_document(
        request_id: u32,
        printer_uri: &str,
        job_id: i32,
        document_format: &str,
        last_document: bool,
    ) -> Self {
        let mut op = Self::operation_header();
        op.attributes
            .push(Attribute::string(VAL_URI, "printer-uri", printer_uri));
        op.attributes.push(Attribute::integer("job-id", job_id));
        op.attributes.push(Attribute::string(
            VAL_MIME,
            "document-format",
            document_format,
        ));
        op.attributes.push(Attribute {
            value_tag: VAL_BOOLEAN,
            name: String::from("last-document"),
            value: alloc::vec![u8::from(last_document)],
        });
        Self::request(IppOperation::SendDocument, request_id, op)
    }

    fn request(operation: IppOperation, request_id: u32, group: AttributeGroup) -> Self {
        Self {
            version_major: 2,
            version_minor: 0,
            operation_or_status: operation as u16,
            request_id,
            groups: alloc::vec![group],
        }
    }

    /// Encode the message body to its byte representation (WS2-13.1/.3).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version_major);
        out.push(self.version_minor);
        out.extend_from_slice(&self.operation_or_status.to_be_bytes());
        out.extend_from_slice(&self.request_id.to_be_bytes());
        for group in &self.groups {
            out.push(group.tag);
            for attr in &group.attributes {
                out.push(attr.value_tag);
                // name-length (2 BE) + name
                let name = attr.name.as_bytes();
                out.extend_from_slice(&(name.len() as u16).to_be_bytes());
                out.extend_from_slice(name);
                // value-length (2 BE) + value
                out.extend_from_slice(&(attr.value.len() as u16).to_be_bytes());
                out.extend_from_slice(&attr.value);
            }
        }
        out.push(TAG_END);
        out
    }

    /// Decode a message body from bytes (WS2-13.1/.3).
    ///
    /// # Errors
    ///
    /// [`IppError::Truncated`] on a short buffer, [`IppError::Malformed`] on an
    /// inconsistent field.
    pub fn from_bytes(data: &[u8]) -> Result<Self, IppError> {
        let mut r = Reader::new(data);
        let version_major = r.u8()?;
        let version_minor = r.u8()?;
        let operation_or_status = r.u16()?;
        let request_id = r.u32()?;

        let mut groups: Vec<AttributeGroup> = Vec::new();
        loop {
            let tag = r.u8()?;
            if tag == TAG_END {
                break;
            }
            if !is_delimiter(tag) {
                return Err(IppError::Malformed);
            }
            let mut group = AttributeGroup {
                tag,
                attributes: Vec::new(),
            };
            // Attributes until the next delimiter or end tag.
            while !is_delimiter_or_end(r.peek()?) {
                let value_tag = r.u8()?;
                let name_len = r.u16()? as usize;
                let name = r.utf8(name_len)?;
                let value_len = r.u16()? as usize;
                let value = r.bytes(value_len)?.to_vec();
                group.attributes.push(Attribute {
                    value_tag,
                    name,
                    value,
                });
            }
            groups.push(group);
        }

        Ok(Self {
            version_major,
            version_minor,
            operation_or_status,
            request_id,
            groups,
        })
    }

    /// Find a group by its delimiter tag.
    #[must_use]
    pub fn group(&self, tag: u8) -> Option<&AttributeGroup> {
        self.groups.iter().find(|g| g.tag == tag)
    }
}

const fn is_delimiter(tag: u8) -> bool {
    matches!(tag, TAG_OPERATION | TAG_JOB | TAG_PRINTER | TAG_UNSUPPORTED)
}

const fn is_delimiter_or_end(tag: u8) -> bool {
    tag == TAG_END || is_delimiter(tag)
}

/// A bounds-checked big-endian byte reader.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn u8(&mut self) -> Result<u8, IppError> {
        let b = *self.data.get(self.pos).ok_or(IppError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn peek(&self) -> Result<u8, IppError> {
        self.data.get(self.pos).copied().ok_or(IppError::Truncated)
    }

    fn u16(&mut self) -> Result<u16, IppError> {
        let b: [u8; 2] = self.bytes(2)?.try_into().map_err(|_| IppError::Truncated)?;
        Ok(u16::from_be_bytes(b))
    }

    fn u32(&mut self) -> Result<u32, IppError> {
        let b: [u8; 4] = self.bytes(4)?.try_into().map_err(|_| IppError::Truncated)?;
        Ok(u32::from_be_bytes(b))
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], IppError> {
        let end = self.pos.checked_add(n).ok_or(IppError::Malformed)?;
        let slice = self.data.get(self.pos..end).ok_or(IppError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn utf8(&mut self, n: usize) -> Result<String, IppError> {
        let slice = self.bytes(n)?;
        core::str::from_utf8(slice)
            .map(String::from)
            .map_err(|_| IppError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_printer_attributes_round_trips() {
        let msg = IppMessage::get_printer_attributes(7, "ipp://printer.local/ipp/print");
        let bytes = msg.to_bytes();
        let back = IppMessage::from_bytes(&bytes).unwrap();
        assert_eq!(back, msg);
        assert_eq!(
            back.operation_or_status,
            IppOperation::GetPrinterAttributes as u16
        );
        assert_eq!(back.request_id, 7);
        let op = back.group(TAG_OPERATION).unwrap();
        assert_eq!(
            op.get("printer-uri").unwrap().as_text(),
            Some("ipp://printer.local/ipp/print")
        );
    }

    #[test]
    fn create_job_carries_job_name() {
        let msg = IppMessage::create_job(1, "ipp://p/ipp/print", "invoice.pdf");
        let back = IppMessage::from_bytes(&msg.to_bytes()).unwrap();
        let op = back.group(TAG_OPERATION).unwrap();
        assert_eq!(op.get("job-name").unwrap().as_text(), Some("invoice.pdf"));
        assert_eq!(back.operation_or_status, IppOperation::CreateJob as u16);
    }

    #[test]
    fn send_document_carries_job_id_and_format() {
        let msg = IppMessage::send_document(2, "ipp://p/ipp/print", 42, "application/pdf", true);
        let back = IppMessage::from_bytes(&msg.to_bytes()).unwrap();
        let op = back.group(TAG_OPERATION).unwrap();
        assert_eq!(op.get("job-id").unwrap().as_integer(), Some(42));
        assert_eq!(
            op.get("document-format").unwrap().as_text(),
            Some("application/pdf")
        );
        assert_eq!(op.get("last-document").unwrap().value, alloc::vec![1]);
    }

    #[test]
    fn decode_a_printer_response_with_attributes() {
        // Hand-build a response: version 2.0, status ok, request-id 7, a
        // printer-attributes group with printer-state(3=idle) and a keyword.
        let response = IppMessage {
            version_major: 2,
            version_minor: 0,
            operation_or_status: IppStatus::Ok as u16,
            request_id: 7,
            groups: alloc::vec![AttributeGroup {
                tag: TAG_PRINTER,
                attributes: alloc::vec![
                    Attribute {
                        value_tag: VAL_ENUM,
                        name: String::from("printer-state"),
                        value: 3i32.to_be_bytes().to_vec(),
                    },
                    Attribute::string(VAL_KEYWORD, "printer-state-reasons", "none"),
                ],
            }],
        };
        let back = IppMessage::from_bytes(&response.to_bytes()).unwrap();
        assert_eq!(
            IppStatus::from_code(back.operation_or_status),
            Some(IppStatus::Ok)
        );
        let printer = back.group(TAG_PRINTER).unwrap();
        assert_eq!(printer.get("printer-state").unwrap().as_integer(), Some(3));
        assert_eq!(
            printer.get("printer-state-reasons").unwrap().as_text(),
            Some("none")
        );
    }

    #[test]
    fn truncated_message_errs() {
        assert_eq!(
            IppMessage::from_bytes(&[0x02, 0x00]),
            Err(IppError::Truncated)
        );
    }

    #[test]
    fn malformed_group_tag_errs() {
        // version+op+reqid then a bogus 0x77 delimiter.
        let bytes = alloc::vec![2, 0, 0, 0x0B, 0, 0, 0, 1, 0x77];
        assert_eq!(IppMessage::from_bytes(&bytes), Err(IppError::Malformed));
    }
}

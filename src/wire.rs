//! Protobuf wire codec and the CloudKit request framing.
//!
//! CloudKit's daemon protocol is protobuf with a varint length prefix, sent as
//! one gzip member. The field numbers are what matter; every message in this
//! crate is written by hand so the signed and framed bytes stay under control.

use std::io::Read;
use std::io::Write;

use crate::error::{Error, Result};

#[derive(Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn uint64(&mut self, field: u32, value: u64) -> &mut Self {
        self.key(field, 0);
        self.varint(value);
        self
    }

    pub fn int64(&mut self, field: u32, value: i64) -> &mut Self {
        self.uint64(field, value as u64)
    }

    pub fn boolean(&mut self, field: u32, value: bool) -> &mut Self {
        self.uint64(field, value as u64)
    }

    pub fn bytes(&mut self, field: u32, value: &[u8]) -> &mut Self {
        self.key(field, 2);
        self.varint(value.len() as u64);
        self.buf.extend_from_slice(value);
        self
    }

    pub fn string(&mut self, field: u32, value: &str) -> &mut Self {
        self.bytes(field, value.as_bytes())
    }

    pub fn message(&mut self, field: u32, value: &Writer) -> &mut Self {
        self.bytes(field, &value.buf)
    }

    pub fn fixed64(&mut self, field: u32, value: u64) -> &mut Self {
        self.key(field, 1);
        self.buf.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    fn key(&mut self, field: u32, wire: u8) {
        self.varint(((field as u64) << 3) | wire as u64);
    }

    fn varint(&mut self, mut value: u64) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                self.buf.push(byte);
                return;
            }
            self.buf.push(byte | 0x80);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value<'a> {
    Varint(u64),
    Fixed64(u64),
    Bytes(&'a [u8]),
}

#[derive(Debug, Clone, Copy)]
pub struct Field<'a> {
    pub number: u32,
    pub value: Value<'a>,
}

impl<'a> Field<'a> {
    pub fn bytes(self) -> Result<&'a [u8]> {
        match self.value {
            Value::Bytes(value) => Ok(value),
            _ => Err(Error::Message(format!(
                "protobuf field {} is not bytes",
                self.number
            ))),
        }
    }

    pub fn string(self) -> Result<&'a str> {
        std::str::from_utf8(self.bytes()?)
            .map_err(|error| Error::Message(format!("protobuf string is not UTF-8: {error}")))
    }

    pub fn varint(self) -> Result<u64> {
        match self.value {
            Value::Varint(value) | Value::Fixed64(value) => Ok(value),
            Value::Bytes(_) => Err(Error::Message(format!(
                "protobuf field {} is not a number",
                self.number
            ))),
        }
    }

    pub fn message(self) -> Result<Reader<'a>> {
        Ok(Reader::new(self.bytes()?))
    }
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Field<'a>>> {
        loop {
            if self.pos >= self.data.len() {
                return Ok(None);
            }
            let key = self.varint()?;
            let number = (key >> 3) as u32;
            let wire = (key & 7) as u8;
            let value = match wire {
                0 => Value::Varint(self.varint()?),
                1 => {
                    self.need(8)?;
                    let bytes: [u8; 8] = self.data[self.pos..self.pos + 8].try_into().unwrap();
                    self.pos += 8;
                    Value::Fixed64(u64::from_le_bytes(bytes))
                }
                2 => {
                    let len = self.varint()? as usize;
                    self.need(len)?;
                    let bytes = &self.data[self.pos..self.pos + len];
                    self.pos += len;
                    Value::Bytes(bytes)
                }
                5 => {
                    self.need(4)?;
                    self.pos += 4;
                    continue;
                }
                other => {
                    return Err(Error::Message(format!(
                        "unsupported protobuf wire type {other}"
                    )))
                }
            };
            return Ok(Some(Field { number, value }));
        }
    }

    pub fn fields(mut self) -> Result<Vec<Field<'a>>> {
        let mut out = Vec::new();
        while let Some(field) = self.next()? {
            out.push(field);
        }
        Ok(out)
    }

    fn need(&self, len: usize) -> Result<()> {
        if self.pos + len > self.data.len() {
            return Err(Error::Message("truncated protobuf message".into()));
        }
        Ok(())
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            if self.pos >= self.data.len() {
                return Err(Error::Message("truncated protobuf varint".into()));
            }
            let byte = self.data[self.pos];
            self.pos += 1;
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift >= 64 {
                return Err(Error::Message("protobuf varint is too long".into()));
            }
        }
    }
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        if *pos >= data.len() {
            return Err(Error::Message("truncated protobuf varint".into()));
        }
        let byte = data[*pos];
        *pos += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            return Err(Error::Message("protobuf varint is too long".into()));
        }
    }
}

/// A varint length prefix followed by the message bytes.
pub fn encode_delimited(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

/// Split a delimited stream into its messages.
pub fn decode_delimited(data: &[u8]) -> Result<Vec<&[u8]>> {
    let mut pos = 0;
    let mut out = Vec::new();
    while pos < data.len() {
        let len = read_varint(data, &mut pos)? as usize;
        if pos + len > data.len() {
            return Err(Error::Message("truncated delimited frame".into()));
        }
        out.push(&data[pos..pos + len]);
        pos += len;
    }
    Ok(out)
}

pub fn gzip(payload: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(payload)?;
    Ok(encoder.finish()?)
}

pub fn gunzip(payload: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = flate2::read::GzDecoder::new(payload);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

/// A response may already be decompressed by the HTTP stack. Detect the gzip
/// magic instead of trusting the header.
pub fn maybe_gunzip(payload: Vec<u8>) -> Result<Vec<u8>> {
    if payload.starts_with(&[0x1f, 0x8b]) {
        gunzip(&payload)
    } else {
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        let mut writer = Writer::new();
        writer.uint64(1, 300).uint64(2, 0).uint64(3, u64::MAX);
        let mut reader = Reader::new(writer.as_slice());
        assert_eq!(reader.next().unwrap().unwrap().varint().unwrap(), 300);
        assert_eq!(reader.next().unwrap().unwrap().varint().unwrap(), 0);
        assert_eq!(
            reader.next().unwrap().unwrap().varint().unwrap(),
            u64::MAX
        );
        assert!(reader.next().unwrap().is_none());
    }

    #[test]
    fn nested_message() {
        let mut inner = Writer::new();
        inner.string(1, "item").uint64(2, 7);
        let mut outer = Writer::new();
        outer.message(213, &inner);
        let mut reader = Reader::new(outer.as_slice());
        let field = reader.next().unwrap().unwrap();
        assert_eq!(field.number, 213);
        let mut nested = field.message().unwrap();
        assert_eq!(nested.next().unwrap().unwrap().string().unwrap(), "item");
        assert_eq!(nested.next().unwrap().unwrap().varint().unwrap(), 7);
    }

    #[test]
    fn delimited_round_trip() {
        let payload = b"cloudkit";
        let framed = encode_delimited(payload);
        assert_eq!(decode_delimited(&framed).unwrap(), vec![payload.as_slice()]);
    }

    #[test]
    fn gzip_round_trip() {
        let payload = b"the quick brown fox".repeat(20);
        let compressed = gzip(&payload).unwrap();
        assert!(compressed.starts_with(&[0x1f, 0x8b]));
        assert_eq!(maybe_gunzip(compressed).unwrap(), payload);
        assert_eq!(maybe_gunzip(payload.clone()).unwrap(), payload);
    }
}

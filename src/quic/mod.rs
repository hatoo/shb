//! shb's own QUIC client
//!
//! quinn-proto is a complete QUIC implementation: server and client, path
//! migration, several congestion controllers, datagrams. A benchmark client
//! needs none of that, and profiling put roughly three quarters of shb's
//! userspace work inside it. This is the subset shb actually uses, written
//! against the same rustls primitives quinn-proto uses for the crypto.

// Built bottom-up, so parts of this are unused until the connection lands
#![allow(dead_code)]

pub mod crypto;
pub mod frame;
pub mod packet;
pub mod recovery;
pub mod stream;
pub mod transport;
pub mod varint;

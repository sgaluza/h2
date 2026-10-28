//! Client options that shape the request HEADERS frame like Chrome does:
//! pseudo-header order (:method, :authority, :scheme, :path) and PRIORITY.

use h2_support::prelude::*;
use tokio::io::{AsyncReadExt, DuplexStream};

const PREFACE_LEN: usize = 24;
const FRAME_HEADERS: u8 = 0x1;
const FLAG_PRIORITY: u8 = 0x20;

/// Fail the test instead of hanging when the client stops sending frames
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// HPACK bytes of the first two request header fields (static table, see RFC 7541 appendix A)
const HPACK_METHOD_GET: u8 = 0x82;
const HPACK_SCHEME_HTTPS: u8 = 0x87;
const HPACK_AUTHORITY_LITERAL: u8 = 0x41;

struct HeadersFrame {
    flags: u8,
    payload: Vec<u8>,
}

/// Read frames sent by the client until `count` HEADERS frames are seen
async fn read_headers_frames(srv: &mut DuplexStream, count: usize) -> Vec<HeadersFrame> {
    let mut preface = [0u8; PREFACE_LEN];
    srv.read_exact(&mut preface).await.unwrap();
    let mut frames = Vec::with_capacity(count);
    while frames.len() < count {
        let mut head = [0u8; 9];
        srv.read_exact(&mut head).await.unwrap();
        let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let mut payload = vec![0u8; len];
        srv.read_exact(&mut payload).await.unwrap();
        if head[3] == FRAME_HEADERS {
            frames.push(HeadersFrame {
                flags: head[4],
                payload,
            });
        }
    }
    frames
}

/// Send `count` GET requests with the builder and capture their HEADERS frames
async fn capture_requests_headers(builder: client::Builder, count: usize) -> Vec<HeadersFrame> {
    let (io, mut srv) = tokio::io::duplex(64 * 1024);
    let (mut client, conn) = builder.handshake::<_, Bytes>(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut responses = Vec::with_capacity(count);
    for _ in 0..count {
        let request = Request::get("https://example.com/").body(()).unwrap();
        responses.push(client.send_request(request, true).unwrap());
    }

    tokio::time::timeout(READ_TIMEOUT, read_headers_frames(&mut srv, count))
        .await
        .expect("client did not send the request HEADERS in time")
}

/// Send one GET request with the builder and capture its HEADERS frame
async fn capture_request_headers(builder: client::Builder) -> HeadersFrame {
    capture_requests_headers(builder, 1).await.remove(0)
}

#[tokio::test]
async fn default_request_headers_unchanged() {
    let frame = capture_request_headers(client::Builder::new()).await;

    assert_eq!(frame.flags & FLAG_PRIORITY, 0, "no PRIORITY by default");
    assert_eq!(frame.payload[..2], [HPACK_METHOD_GET, HPACK_SCHEME_HTTPS]);
}

#[tokio::test]
async fn pseudo_header_authority_first() {
    let mut builder = client::Builder::new();
    builder.pseudo_header_authority_first(true);
    let frame = capture_request_headers(builder).await;

    assert_eq!(frame.flags & FLAG_PRIORITY, 0);
    assert_eq!(
        frame.payload[..2],
        [HPACK_METHOD_GET, HPACK_AUTHORITY_LITERAL]
    );
}

#[tokio::test]
async fn headers_priority_like_chrome() {
    let mut builder = client::Builder::new();
    // Chrome: exclusive dependency on stream 0, weight 256
    builder.headers_priority(0, 256, true);
    builder.pseudo_header_authority_first(true);
    let frame = capture_request_headers(builder).await;

    assert_eq!(frame.flags & FLAG_PRIORITY, FLAG_PRIORITY);
    // E bit + stream dependency 0, then weight - 1
    assert_eq!(frame.payload[..5], [0x80, 0x00, 0x00, 0x00, 0xff]);
    assert_eq!(
        frame.payload[5..7],
        [HPACK_METHOD_GET, HPACK_AUTHORITY_LITERAL]
    );
}

#[tokio::test]
async fn headers_priority_skips_self_dependency() {
    // A stream must not depend on itself, peers treat it as PROTOCOL_ERROR
    // (RFC 9113 section 5.3.1), so stream 1 is sent without PRIORITY here
    let mut builder = client::Builder::new();
    builder.headers_priority(1, 256, true);
    let frames = capture_requests_headers(builder, 2).await;

    assert_eq!(
        frames[0].flags & FLAG_PRIORITY,
        0,
        "stream 1 depends on itself"
    );
    assert_eq!(frames[1].flags & FLAG_PRIORITY, FLAG_PRIORITY);
    assert_eq!(frames[1].payload[..5], [0x80, 0x00, 0x00, 0x01, 0xff]);
}

#[tokio::test]
async fn headers_priority_masks_reserved_bit() {
    // Stream ids are 31-bit, the top bit of dependency_id is ignored instead of panicking
    let mut builder = client::Builder::new();
    builder.headers_priority(u32::MAX, 256, false);
    let frame = capture_request_headers(builder).await;

    assert_eq!(frame.flags & FLAG_PRIORITY, FLAG_PRIORITY);
    // not exclusive, dependency 0x7fffffff
    assert_eq!(frame.payload[..5], [0x7f, 0xff, 0xff, 0xff, 0xff]);
}

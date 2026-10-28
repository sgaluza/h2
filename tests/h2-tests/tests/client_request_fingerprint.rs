//! Client options that shape the request HEADERS frame like Chrome does:
//! pseudo-header order (:method, :authority, :scheme, :path) and PRIORITY.

use h2_support::prelude::*;
use tokio::io::{AsyncReadExt, DuplexStream};

const PREFACE_LEN: usize = 24;
const FRAME_HEADERS: u8 = 0x1;
const FLAG_PRIORITY: u8 = 0x20;

/// HPACK bytes of the first two request header fields (static table, see RFC 7541 appendix A)
const HPACK_METHOD_GET: u8 = 0x82;
const HPACK_SCHEME_HTTPS: u8 = 0x87;
const HPACK_AUTHORITY_LITERAL: u8 = 0x41;

struct HeadersFrame {
    flags: u8,
    payload: Vec<u8>,
}

/// Read frames sent by the client until the first HEADERS frame
async fn read_first_headers(srv: &mut DuplexStream) -> HeadersFrame {
    let mut preface = [0u8; PREFACE_LEN];
    srv.read_exact(&mut preface).await.unwrap();
    loop {
        let mut head = [0u8; 9];
        srv.read_exact(&mut head).await.unwrap();
        let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let mut payload = vec![0u8; len];
        srv.read_exact(&mut payload).await.unwrap();
        if head[3] == FRAME_HEADERS {
            return HeadersFrame {
                flags: head[4],
                payload,
            };
        }
    }
}

/// Send one GET request with the builder and capture its HEADERS frame
async fn capture_request_headers(builder: client::Builder) -> HeadersFrame {
    let (io, mut srv) = tokio::io::duplex(64 * 1024);
    let (mut client, conn) = builder.handshake::<_, Bytes>(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let request = Request::get("https://example.com/").body(()).unwrap();
    let _response = client.send_request(request, true).unwrap();

    read_first_headers(&mut srv).await
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

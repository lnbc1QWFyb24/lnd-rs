// Include generated prost/tonic code. build.rs emits package modules into OUT_DIR.
pub mod lnrpc {
    #![allow(clippy::all, clippy::pedantic)]
    include!(concat!(env!("OUT_DIR"), "/lnrpc.rs"));
}

pub mod signrpc {
    #![allow(clippy::all, clippy::pedantic)]
    include!(concat!(env!("OUT_DIR"), "/signrpc.rs"));
}

pub mod walletrpc {
    #![allow(clippy::all, clippy::pedantic)]
    include!(concat!(env!("OUT_DIR"), "/walletrpc.rs"));
}

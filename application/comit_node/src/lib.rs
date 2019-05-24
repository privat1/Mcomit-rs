#![warn(unused_extern_crates, missing_debug_implementations, rust_2018_idioms)]
#![deny(unsafe_code)]

// Cannot do `#[strum_discriminants(derive(strum_macros::EnumString))]` at the
// moment. Hence we need to `#[macro_use]` in order to derive strum macros on a
// an enum created by `strum_discriminants`.
#[macro_use]
extern crate strum_macros;

pub mod bam_api;
pub mod bam_ext;
pub mod btsieve;
pub mod comit_client;
pub mod comit_i_routes;
pub mod http_api;
pub mod libp2p_bam;
pub mod load_settings;
pub mod logging;
pub mod network;
pub mod node_id;
pub mod seed;
pub mod settings;
pub mod swap_protocols;

fn var_or_default(name: &str, default: String) -> String {
    match std::env::var(name) {
        Ok(value) => {
            log::info!("Set {}={}", name, value);
            value
        }
        Err(_) => {
            log::warn!(
                "{} is not set, falling back to default: '{}' ",
                name,
                default
            );
            default
        }
    }
}

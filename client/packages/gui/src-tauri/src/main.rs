// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use tauri::async_runtime::spawn;
use tauri::State;
use tokio::net::TcpStream;
use tokio_util::udp::UdpFramed;

use protocol::codec::PadCodec;

use std::fmt::Display;
use std::sync::Mutex;

struct Connection {
    ctrl_socket: Mutex<Option<TcpStream>>,
    ctrl_protocol: Mutex<protocol::connection::Connection>,
    pad_socket: Mutex<Option<UdpFramed<PadCodec>>>,
}

#[tauri::command]
async fn connect(ip: String, port: u16, state: State<'_, Connection>) -> Result<(), String> {
    let mut state_lock = state.ctrl_socket.lock().unwrap();
    state_lock.replace(
        TcpStream::connect((ip.as_str(), port))
            .await
            .map_err(|e| e.to_string())?,
    );
    Ok(())
}

enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

impl Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Disconnected => write!(f, "Disconnected"),
            ConnectionState::Connecting => write!(f, "Connecting"),
            ConnectionState::Connected => write!(f, "Connected"),
            ConnectionState::Disconnecting => write!(f, "Disconnecting"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConnectionStateEvent {
    state: String,
    error: Option<String>,
}

enum Events {
    ConnectionState(ConnectionState),
}

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

use std::fmt;
use std::path::{Path, PathBuf};

use byteorder::{ByteOrder, NetworkEndian};
use log::debug;
use tokio::{
    fs::File,
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

const HEADER_LEN: usize = std::mem::size_of::<u16>();
const MAX_MSG_LEN: u16 = u16::MAX - 1;

pub async fn send_config_script(
    socket: impl AsRef<Path>,
    script: impl AsRef<Path>,
) -> Result<String, Error> {
    debug!("sending '{}'", script.as_ref().display());

    let mut file = File::open(&script).await?;
    let meta = file.metadata().await?;

    let size = meta.len();
    if size > u64::from(MAX_MSG_LEN) {
        return Err(Error::Size(SizeError {
            script: script.as_ref().to_owned(),
            size,
        }));
    }

    let packet = create_packet(&mut file, size as u16).await?;
    let mut stream = UnixStream::connect(&socket).await?;
    stream.write_all(&packet).await?;

    // read_u16 assumes big-endian
    let resp_size = stream.read_u16().await?;
    let mut recv_buf = vec![0u8; MAX_MSG_LEN as usize];
    stream
        .read_exact(&mut recv_buf[0..resp_size as usize])
        .await?;

    Ok(String::from_utf8_lossy(&recv_buf[0..resp_size as usize]).into_owned())
}

async fn create_packet<R: Unpin + AsyncReadExt>(r: &mut R, len: u16) -> Result<Vec<u8>, io::Error> {
    let mut packet = vec![0u8; HEADER_LEN + MAX_MSG_LEN as usize];
    let end = HEADER_LEN + len as usize;

    NetworkEndian::write_u16(&mut packet[0..HEADER_LEN], len);
    r.read_exact(&mut packet[HEADER_LEN..end]).await?;

    packet.truncate(end);
    Ok(packet)
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Size(SizeError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o error: {}", e),
            Error::Size(e) => write!(
                f,
                "script '{}' too large: {} > {}",
                e.script.display(),
                e.size,
                MAX_MSG_LEN
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Size(e) => Some(e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<SizeError> for Error {
    fn from(e: SizeError) -> Error {
        Error::Size(e)
    }
}

#[derive(Debug)]
pub struct SizeError {
    script: PathBuf,
    size: u64,
}

impl fmt::Display for SizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "script '{}' too large: {} > {}",
            self.script.display(),
            self.size,
            MAX_MSG_LEN
        )
    }
}

impl std::error::Error for SizeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use tempdir::TempDir;
    use tokio::net::UnixListener;
    use tokio::stream::StreamExt;
    use tokio::sync::oneshot;

    use super::*;

    #[tokio::test]
    async fn test_send_config_script() {
        let tmp = TempDir::new("gtctl").expect("tempdir failed");
        let data = b"test";

        let script_path = tmp.path().join("input");
        let mut file = File::create(&script_path)
            .await
            .expect("create file failed");
        file.write_all(data).await.expect("write failed");
        drop(file);

        let socket = tmp.path().join("socket");
        let (tx, rx) = oneshot::channel();
        {
            let socket = socket.clone();
            tokio::spawn(async move { echo_server(&socket, tx).await });
        }

        rx.await.expect("error waiting for server");

        let resp = send_config_script(&socket, &script_path)
            .await
            .expect("send script failed");
        assert_eq!(data, resp.as_bytes());

        stop_server(&socket).await;
    }

    async fn echo_server(path: impl AsRef<Path>, ready: oneshot::Sender<()>) {
        let mut lis = UnixListener::bind(&path).expect("bind failed");
        ready.send(()).expect("send ready failed");
        while let Some(stream) = lis.next().await {
            let mut stream = stream.expect("stream error");
            tokio::spawn(async move {
                let req_size = stream.read_u16().await.expect("read u16 failed");
                let packet = create_packet(&mut stream, req_size)
                    .await
                    .expect("create packet failed");
                if packet == b"stop" {
                    return;
                }
                stream.write_all(&packet).await.expect("write reply failed");
            });
        }
    }

    async fn stop_server(socket: impl AsRef<Path>) {
        let mut stream = UnixStream::connect(&socket).await.expect("connect failed");
        stream
            .write_all(b"stop")
            .await
            .expect("failed to write stop command");
    }
}

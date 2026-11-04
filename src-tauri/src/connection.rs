//! 每次 read 的空闲超时不能阻止持续滴入字节的连接占用线程。
//! 同时限定空闲时间和整条连接的绝对截止时间，供 TLS 客户端/服务端共用。
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

pub struct DeadlineSocket {
    socket: TcpStream,
    deadline: Instant,
    idle: Duration,
}
impl DeadlineSocket {
    pub fn new(socket: TcpStream, total: Duration, idle: Duration) -> Self {
        Self {
            socket,
            deadline: Instant::now() + total,
            idle,
        }
    }
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .map(|left| left.min(self.idle))
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "connection deadline exceeded"))
    }
}
impl Read for DeadlineSocket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(bytes)
    }
}
impl Write for DeadlineSocket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.socket.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn continuously_dripped_bytes_cannot_extend_the_connection_deadline() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            for _ in 0..30 {
                if stream.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let (socket, _) = listener.accept().unwrap();
        let mut stream = DeadlineSocket::new(
            socket,
            Duration::from_millis(180),
            Duration::from_millis(100),
        );
        let start = Instant::now();
        let error = stream.read_exact(&mut [0u8; 128]).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        assert!(start.elapsed() < Duration::from_millis(700));
        // The expired budget also blocks writes; TLS cannot restart the clock.
        assert_eq!(
            stream.write_all(b"reply").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        drop(stream);
        sender.join().unwrap();
    }
}

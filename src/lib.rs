use anyhow::Result;
use ed25519_dalek::{ed25519::signature::SignerMut, SigningKey};

const MTU: usize = 1024;

/// ICMP Tunnel 版本
#[derive(Debug, Clone)]
pub enum IcmpTunnelVersion {
    V1,
}

/// ICMP隧道构建器
#[derive(Debug, Clone)]
pub struct IcmpTunnelBuilder {
    pub version: IcmpTunnelVersion,
    pub sign_key: SigningKey,
    icmp_id: u16,
    icmp_seq: u16,
}

impl IcmpTunnelBuilder {
    /// 创建一个新的ICMP隧道构建器
    pub fn new(version: i8, icmp_id: u16, sign_key: SigningKey) -> Self {
        let version = match version {
            1 => IcmpTunnelVersion::V1,
            _ => panic!("Unsupported version: {}", version),
        };
        let icmp_seq = 0;
        Self {
            version,
            sign_key,
            icmp_id,
            icmp_seq,
        }
    }

    /// 构建ICMP隧道数据包
    pub fn build_packet(&mut self, data: &[u8]) -> Result<([u8; MTU], usize)> {
        match self.version {
            IcmpTunnelVersion::V1 => self.build_packet_v1(data),
        }
    }

    pub fn build_packet_v1(&mut self, data: &[u8]) -> Result<([u8; MTU], usize)> {
        let total_len = 8 + 73 + data.len();
        if total_len > MTU {
            return Err(anyhow::anyhow!("Data too large: {}", data.len()));
        }
        let mut buffer = [0u8; MTU];

        let mut offset = 0;

        // 构造ICMP头（8字节）
        buffer[offset] = 8; // ICMP类型：Echo请求
        offset += 1;
        buffer[offset] = 0; // 代码：0
        offset += 1;
        let checksum_pos = offset;
        offset += 2; // 预留校验和位置

        // 注意：必须使用大端序写入多字节字段
        buffer[offset..offset + 2].copy_from_slice(&self.icmp_id.to_be_bytes());
        offset += 2;
        buffer[offset..offset + 2].copy_from_slice(&self.icmp_seq.to_be_bytes());
        offset += 2;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 构造隧道头 (73字节)
        buffer[offset] = 1; // 版本号
        offset += 1;
        buffer[offset..offset + 4].copy_from_slice(&(timestamp as u32).to_be_bytes()); // 时间戳
        offset += 4;
        let sign_pos = offset;
        offset += 64; // 预留签名字段
        buffer[offset..offset + 4].copy_from_slice(&(data.len() as u32).to_be_bytes());
        offset += 4;

        // 添加数据并计算总长度
        buffer[offset..offset + data.len()].copy_from_slice(data);
        offset += data.len();

        // 计算签名
        let signature = self.sign_key.sign(data).to_bytes();
        buffer[sign_pos..sign_pos + 64].copy_from_slice(&signature);

        // 计算校验和（仅ICMP头+数据部分）
        let checksum = checksum(&buffer[..offset]);
        buffer[checksum_pos..checksum_pos + 2].copy_from_slice(&checksum.to_be_bytes());

        // 递增序列号
        self.icmp_seq = self.icmp_seq.wrapping_add(1);

        Ok((buffer, offset))
    }
}

/// 计算校验和（RFC 1071）
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i < data.len() {
        let word = if i + 1 < data.len() {
            ((data[i] as u32) << 8) | (data[i + 1] as u32)
        } else {
            (data[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
        i += if i + 1 < data.len() { 2 } else { 1 };
    }

    // 折叠进位
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::{icmp::echo_request::MutableEchoRequestPacket, ip::IpNextHeaderProtocols};
    use pnet_transport::TransportChannelType::Layer4;
    use pnet_transport::{transport_channel, TransportProtocol};
    use std::{net::IpAddr, time::Duration};

    #[test]
    fn test_basic_packet() {
        let data = b"test data";

        let sign_key = SigningKey::from_bytes(&[0u8; 32]);
        let mut builder = IcmpTunnelBuilder::new(1, 0, sign_key);
        let (packet, send_len) = builder.build_packet(data).unwrap();

        // 验证ICMP头
        assert_eq!(packet[0], 8); // Type
        assert_eq!(packet[1], 0); // Code
        assert_eq!(&packet[4..6], &0u16.to_be_bytes()); // ID
        assert_eq!(&packet[6..8], &0u16.to_be_bytes()); // Initial seq

        // 验证数据
        assert_eq!(&packet[81..81 + data.len()], data);

        println!("{:?}", packet[..send_len].to_vec());
    }

    #[test]
    fn test_tunnel() {
        let target_ip: IpAddr = "127.0.0.1".parse().unwrap();
        println!("icpm echo request to target ip:{:#?}", target_ip);

        let sign_key = SigningKey::from_bytes(&[0u8; 32]);
        let mut builder = IcmpTunnelBuilder::new(1, 0, sign_key);

        let protocol = Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
        let (mut tx, _) = match transport_channel(4096, protocol) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => panic!("Error happened: {}", e),
        };

        loop {
            let (mut packet, send_len) = builder.build_packet(b"test a1231").unwrap();
            let icmp_packet = MutableEchoRequestPacket::new(&mut packet[..send_len]).unwrap();
            tx.send_to(&icmp_packet, target_ip).unwrap();
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

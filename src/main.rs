// Uncomment this block to pass the first stage
use std::net::UdpSocket;

use bytebuffer::ByteBuffer;

#[derive(Default)]
struct DnsPacketHeader {
    id: u16,
    qr_indicator: u8,
    opcode: u8,
    authorative_answer: u8,
    truncation: u8,
    recursion_desired: u8,
    recursion_available: u8,
    reserved: u8,
    response_code: u8,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}

impl DnsPacketHeader {
    fn to_bytes(&self) -> ByteBuffer {
        let id_b = self.id.to_be_bytes();
        let flags_b1 = (self.qr_indicator << 7) | (self.opcode << 3) | (self.authorative_answer << 2) | (self.truncation << 1) | (self.recursion_desired);
        let flags_b2 = (self.recursion_available << 7) | (self.reserved << 4) | (self.response_code);
        let qc_b = self.question_count.to_be_bytes();
        let anc_b = self.answer_count.to_be_bytes();
        let auc_b = self.authority_count.to_be_bytes();
        let adc_b = self.additional_count.to_be_bytes();

        let mut buf = ByteBuffer::new();
        buf.write_bytes(&id_b);
        buf.write_u8(flags_b1);
        buf.write_u8(flags_b2);
        buf.write_bytes(&qc_b);
        buf.write_bytes(&anc_b);
        buf.write_bytes(&auc_b);
        buf.write_bytes(&adc_b);

        buf
    }
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                println!("{}", buf.iter().take(size).map(|b| format!("{0:02X}", b)).collect::<String>());

                if size < 12 {
                    return;
                }

                let mut tmp = [0; 12];
                tmp.copy_from_slice(&buf[..12]);
                // let received_header = DnsPacketHeader::from_bytes(tmp);

                let mut data_len = size - 12;
                let mut data: Vec<u8> = buf[12..size].to_vec();

                // let response_header = DnsPacketHeader::new()
                //     .with_id(1234)
                //     .with_qr_indicator(1)
                //     .with_opcode(0)
                //     .with_authorative_answer(0)
                //     .with_truncation(0)
                //     .with_recursion_desired(0)
                //     .with_recursion_available(0)
                //     .with_reserved(0)
                //     .with_response_code(0)
                //     .with_question_count(0)
                //     .with_answer_count(0)
                //     .with_authority_count(0)
                //     .with_additional_count(0);

                let response_header = DnsPacketHeader {
                    id: 1234,
                    qr_indicator: 1,
                    ..Default::default()
                };

                let header_bytes = response_header.to_bytes();
                let response_header_raw = header_bytes.as_bytes();
                let mut response: Vec<u8> = response_header_raw.to_vec();

                let hex_string: String = response.iter().map(|b| format!("{0:02X}", b)).collect();
                println!("Sending {hex_string}");
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}

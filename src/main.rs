// Uncomment this block to pass the first stage
use std::net::UdpSocket;

use modular_bitfield::{bitfield, specifiers::*};

#[bitfield]
struct DnsPacketHeader {
    id: B16,
    qr_indicator: B1,
    opcode: B4,
    authorative_answer: B1,
    truncation: B1,
    recursion_desired: B1,
    recursion_available: B1,
    reserved: B3,
    response_code: B4,
    question_count: B16,
    answer_count: B16,
    authority_count: B16,
    additional_count: B16,
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
                let received_header = DnsPacketHeader::from_bytes(tmp);

                let mut data_len = size - 12;
                let mut data: Vec<u8> = buf[12..size].to_vec();

                let response_header = DnsPacketHeader::new()
                    .with_id(1234)
                    .with_qr_indicator(1)
                    .with_opcode(0)
                    .with_authorative_answer(0)
                    .with_truncation(0)
                    .with_recursion_desired(0)
                    .with_recursion_available(0)
                    .with_reserved(0)
                    .with_response_code(0)
                    .with_question_count(0)
                    .with_answer_count(0)
                    .with_authority_count(0)
                    .with_additional_count(0);

                let response_header_raw: [u8; 12] = response_header.into_bytes();
                let mut response: Vec<u8> = response_header_raw.to_vec();
                let tmp = response[0];
                response[0] = response[1];
                response[1] = tmp;
                response[2] = response[2] << 7;
                // response.append(&mut data);

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

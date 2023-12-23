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

    fn from_bytes(data: &[u8]) -> Self {
        let mut buf = ByteBuffer::from(data);

        let id = buf.read_u16().unwrap();
        let flags1 = buf.read_u8().unwrap();
        let flags2 = buf.read_u8().unwrap();
        let qc = buf.read_u16().unwrap();
        let anc = buf.read_u16().unwrap();
        let auc = buf.read_u16().unwrap();
        let adc = buf.read_u16().unwrap();

        Self {
            id,
            qr_indicator: flags1 >> 7,
            opcode: (flags1 >> 3) & 0b1111,
            authorative_answer: (flags1 >> 2) & 1,
            truncation: (flags1 >> 1) & 1,
            recursion_desired: flags1 & 1,
            recursion_available: flags2 >> 7,
            reserved: (flags2 >> 4) & 0b111,
            response_code: flags2 & 0b1111,
            question_count: qc,
            answer_count: anc,
            authority_count: auc,
            additional_count: adc,
        }
    }
}

#[derive(Default, Debug)]
struct Question {
    name: String,
    record_type: u16,
    class: u16,
}

impl From<&[u8]> for Question {
    fn from(value: &[u8]) -> Self {
        let mut segment_done = true;
        let mut length = 0;

        let mut name = String::new();
        let mut i = 0;
        for &b in value {
            i += 1;
            if b == 0 {
                break;
            }
            if segment_done {
                if !name.is_empty() {
                    name += ".";
                }
                length = b;
                continue;
            }
            name += std::str::from_utf8(&[b]).unwrap();
            length -= 1;
            segment_done = length == 0;
        }
        let record_type = ((value[i] as u16) << 8) | (value[i+1] as u16);
        let class = ((value[i+2] as u16) << 8) | (value[i+3] as u16);

        Self {
            name,
            record_type,
            class,
        }
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

                let rec_header = DnsPacketHeader::from_bytes(&buf[..12]);

                let response_header = DnsPacketHeader {
                    id: 1234,
                    qr_indicator: rec_header.qr_indicator,
                    question_count: rec_header.question_count,
                    ..Default::default()
                };

                let header_bytes = response_header.to_bytes();
                let response_header_raw = header_bytes.as_bytes();
                let mut response: Vec<u8> = response_header_raw.to_vec();

                if size > 12 {
                    let question = Question::from(&buf[12..size]);
                    dbg!(&question);
                    response.append(&mut buf[12..size].to_vec());
                }

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

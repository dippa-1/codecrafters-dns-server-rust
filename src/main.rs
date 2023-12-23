// Uncomment this block to pass the first stage
use std::{net::UdpSocket, ops::Index, io::Write};

use bytebuffer::ByteBuffer;
use nom::{FindSubstring, InputIter, AsBytes};

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

impl Question {
    fn to_byte_buffer(&self) -> ByteBuffer {
        let mut buf = ByteBuffer::new();
        buf.write_bytes(domain_to_byte_buffer(&self.name).as_bytes());
        buf.write_u16(self.record_type);
        buf.write_u16(self.class);

        buf
    }
}

fn u8_to_name(raw: &[u8]) -> String {
    let mut segment_done = true;
    let mut length = 0;

    let mut name = String::new();
    let mut i = 0;
    dbg!(&raw);
    for &b in raw {
        i += 1;
        if b == 0 {
            break;
        }
        if segment_done {
            if !name.is_empty() {
                name += ".";
            }
            length = b;
            segment_done = false;
            continue;
        }
        name += std::str::from_utf8(&[b]).unwrap();
        length -= 1;
        segment_done = length == 0;
    }

    name
}

impl From<&[u8]> for Question {
    fn from(value: &[u8]) -> Self {
        let name = u8_to_name(value);
        let after_name = value.position(|b| b == 0).and_then(|i| Some(i + 1)).unwrap();
        let record_type = ((value[after_name] as u16) << 8) | (value[after_name+1] as u16);
        let class = ((value[after_name+2] as u16) << 8) | (value[after_name+3] as u16);

        Self {
            name,
            record_type,
            class,
        }
    }
}

fn domain_to_byte_buffer(domain: &str) -> ByteBuffer {
    let mut buf = domain.split('.').filter_map(|label| {
        let len: u8 = label.len() as u8;
        if len == 0 {
            return None;
        }

        let mut buf = ByteBuffer::new();
        buf.write_u8(len);
        buf.write_string(label);

        Some(buf)
    }).reduce(|acc, e| {
        let mut buf = ByteBuffer::from(acc);
        buf.write_bytes(e.as_bytes());
        buf
    }).unwrap();
    buf.write_u8(0);
    dbg!(&buf);

    buf
}

#[derive(Default, Debug)]
struct Answer {
    name: String,
    record_type: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>,
}

impl Answer {
    fn to_byte_buffer(&self) -> ByteBuffer {
        let mut buf = ByteBuffer::new();
        buf.write_bytes(domain_to_byte_buffer(&self.name).as_bytes());
        buf.write_u16(self.record_type);
        buf.write_u16(self.class);
        buf.write_u32(self.ttl);
        buf.write_u16(self.rdlength);
        buf.write_bytes(self.rdata.as_bytes());

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

                // let mut data_len = size - 12;
                // let mut data: Vec<u8> = buf[12..size].to_vec();

                let rec_header = DnsPacketHeader::from_bytes(&buf[..12]);

                let response_header = DnsPacketHeader {
                    id: 1234,
                    qr_indicator: 1,
                    question_count: rec_header.question_count,
                    answer_count: rec_header.question_count,
                    ..Default::default()
                };

                let header_bytes = response_header.to_bytes();
                let response_header_raw = header_bytes.as_bytes();
                let mut response: Vec<u8> = response_header_raw.to_vec();

                if size > 12 {
                    let question = Question::from(&buf[12..size]);
                    dbg!(&question);
                    let q_buf = question.to_byte_buffer();
                    response.append(&mut q_buf.as_bytes().to_vec());

                    let ip: [u8; 4] = [8,8,8,8];
                    let answer = Answer {
                        name: question.name.clone(),
                        record_type: question.record_type,
                        class: question.class,
                        ttl: 60,
                        rdlength: 4,
                        rdata: ip.to_vec(),
                    };
                    dbg!(&answer);
                    let answer_buf = answer.to_byte_buffer();
                    response.append(&mut answer_buf.as_bytes().to_vec());
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

use {
    anyhow::anyhow,
    clap::{command, Parser},
    hickory_proto::{
        op::{Edns, Header, ResponseCode},
        rr::{
            rdata::{
                opt::{EdnsCode, EdnsOption},
                A, AAAA, CNAME, NS, PTR, SOA, TXT,
            },
            Name, RData, Record, RecordType,
        },
    },
    hickory_server::{
        authority::{MessageResponse, MessageResponseBuilder},
        server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    },
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    std::{
        io,
        net::{Ipv4Addr, SocketAddr},
        str::FromStr,
        time::{SystemTime, UNIX_EPOCH},
    },
    tokio::{
        net::{TcpListener, UdpSocket},
        time::Duration,
    },
    tracing_subscriber::EnvFilter,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Answer {
    pub name: String,
    #[serde(rename = "TTL")]
    pub ttl: i32,
    #[serde(rename = "type")]
    pub answer_type: i32,
    pub data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Question {
    pub name: String,
    #[serde(rename = "type")]
    pub question_type: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DNSEntity {
    #[serde(rename = "Status")]
    pub status: Option<i32>,
    #[serde(rename = "TC")]
    pub tc: Option<bool>,
    #[serde(rename = "RD")]
    pub rd: Option<bool>,
    #[serde(rename = "RA")]
    pub ra: Option<bool>,
    #[serde(rename = "AD")]
    pub ad: Option<bool>,
    #[serde(rename = "CD")]
    pub cd: Option<bool>,
    #[serde(rename = "Question")]
    pub question: Option<Question>,
    #[serde(rename = "Answer")]
    pub answer: Option<Vec<Answer>>,
}

#[derive(Parser, Debug)]
#[command(version = "1.0", about, long_about = None)]
struct Args {
    /// Account ID for the DNS control panel, not the Alibaba Cloud account ID
    #[arg(long)]
    account_id: String,

    /// AccessKey Secret for the DNS control panel
    #[arg(long = "access-key-secret")]
    access_key_secret: String,

    /// AccessKey ID for the DNS control panel
    #[arg(long = "access-key-id")]
    access_key_id: String,

    /// Timeout duration in milliseconds for waiting on replies
    #[arg(short, long, default_value_t = 1000)]
    timeout: u64,

    /// Server address to set
    #[arg(short, long, default_value = "223.5.5.5")]
    server: String,

    /// Listening address and port
    #[arg(short, long, default_value_t = 16883)]
    port: u16,
}
#[derive(Clone, Debug)]
struct DnsProxy {
    server: String,
    account_id: String,
    access_key_id: String,
    access_key_secret: String,
    timeout: u64,
}
impl DnsProxy {
    fn new(
        server: String,
        account_id: String,
        access_key_id: String,
        access_key_secret: String,
        timeout: u64,
    ) -> Self {
        DnsProxy {
            server,
            account_id,
            access_key_id,
            access_key_secret,
            timeout,
        }
    }

    fn failure_response() -> anyhow::Result<ResponseInfo> {
        let mut header = Header::new();
        header.set_response_code(ResponseCode::ServFail);
        Ok(header.into())
    }

    async fn get_dns_entity(
        &self,
        name: &str,
        rtype: &str,
        ecs: Option<String>,
    ) -> anyhow::Result<Option<DNSEntity>> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let mut hasher = Sha256::new();
        hasher.update(format!(
            "{}{}{}{}{}",
            self.account_id, self.access_key_secret, ts, name, self.access_key_id
        ));
        let key: String = format!("{:X}", hasher.finalize());

        let mut url = format!(
            "http://{}/resolve?name={}&type={}&uid={}&ak={}&key={}&ts={}",
            self.server, name, rtype, self.account_id, self.access_key_id, key, ts
        );

        if let Some(ecs) = ecs {
            if !ecs.trim().is_empty() {
                url += &format!("&edns_client_subnet={}/24", ecs);
            }
        }

        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            // .header("User-Agent", "ArashiDNS.Aha/0.1")
            .send()
            .await?;
        let text = response.text().await?;
        tracing::info!("[ali_response]: {}", text);
        Ok(sonic_rs::from_str::<DNSEntity>(&text).ok())
    }

    fn extract_address(input: &str) -> Option<String> {
        tracing::info!("{}", input);
        input
            .split(',')
            .map(|part| part.trim())
            .find(|&part| part.starts_with("C"))
            .and_then(|addr_part| addr_part.split_whitespace().last())
            .and_then(|addr| Some(addr.to_string()))
    }

    async fn get_response(
        &self,
        request: &Request,
    ) -> anyhow::Result<(Vec<Record>, Vec<Record>, Vec<Record>, Vec<Record>)> {
        let quest = request.request_info().query.original().clone();
        let edns: Option<String> = match request.edns() {
            Some(edns) => {
                let opt: Option<&EdnsOption> = edns.option(EdnsCode::Subnet);
                if let Some(opt) = opt {
                    if let EdnsOption::Subnet(client_subnet) = opt {
                        Self::extract_address(&format!("{:?}", client_subnet))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            None => None,
        };

        match quest.query_type() {
            RecordType::A
            | RecordType::AAAA
            | RecordType::CNAME
            | RecordType::NS
            | RecordType::SOA
            | RecordType::TXT
            | RecordType::PTR => {
                let dns_entity = self
                    .get_dns_entity(
                        &quest.name().to_utf8(),
                        &quest.query_type().to_string(),
                        edns,
                    )
                    .await?;
                if let Some(dns_entity) = dns_entity {
                    if let Some(answer_list) = dns_entity.answer {
                        let mut answers: Vec<Record> = Vec::new();
                        let mut name_servers: Vec<Record> = Vec::new();
                        let mut soa: Vec<Record> = Vec::new();
                        for answer in answer_list {
                            let (record_type, data) = match answer.answer_type {
                                1 => (RecordType::A, RData::A(A::from_str(&answer.data)?)),
                                2 => (RecordType::NS, RData::NS(NS(Name::from_str(&answer.data)?))),
                                5 => (
                                    RecordType::CNAME,
                                    RData::CNAME(CNAME(Name::from_str(&answer.data)?)),
                                ),
                                6 => {
                                    let parts: Vec<&str> = answer.data.split_whitespace().collect();
                                    if parts.len() != 7 {
                                        continue;
                                    }
                                    let mname = Name::from_str(parts[0]).unwrap();
                                    let rname = Name::from_str(parts[1]).unwrap();
                                    let serial = parts[2].parse::<u32>().unwrap();
                                    let refresh = parts[3].parse::<i32>().unwrap();
                                    let retry = parts[4].parse::<i32>().unwrap();
                                    let expire = parts[5].parse::<i32>().unwrap();
                                    let minimum = parts[6].parse::<u32>().unwrap();
                                    (
                                        RecordType::SOA,
                                        RData::SOA(SOA::new(
                                            mname, rname, serial, refresh, retry, expire, minimum,
                                        )),
                                    )
                                }
                                12 => (
                                    RecordType::PTR,
                                    RData::PTR(PTR(Name::from_str(&answer.data)?)),
                                ),
                                16 => (RecordType::TXT, RData::TXT(TXT::new(vec![answer.data]))),
                                28 => {
                                    (RecordType::AAAA, RData::AAAA(AAAA::from_str(&answer.data)?))
                                }
                                _ => continue,
                            };
                            let mut record = Record::new();
                            record
                                .set_name(Name::from_str(&answer.name)?)
                                .set_rr_type(record_type)
                                .set_dns_class(quest.query_class())
                                .set_ttl(answer.ttl as u32)
                                .set_data(Some(data));
                            match quest.query_type() {
                                RecordType::SOA => {
                                    soa.push(record);
                                }
                                RecordType::NS => {
                                    name_servers.push(record);
                                }
                                _ => {
                                    answers.push(record);
                                }
                            }
                        }
                        let additionals = vec![];

                        // let mut buffer = Vec::with_capacity(512);
                        // let mut encoder = BinEncoder::new(&mut buffer);
                        // return Ok(result.destructive_emit(&mut encoder)?);
                        return Ok((answers, name_servers, soa, additionals));
                    }
                }
                return Err(anyhow!("No DNS entity found"));
            }
            _ => {
                tracing::info!("unsupport query type: {:?}", quest.query_type());
                return Err(anyhow!("No DNS entity found"));
            }
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_file(true)
        .with_line_number(true)
        .with_target(false)
        .init();
    let args = Args::parse();

    let timeout = Duration::from_millis(args.timeout);
    let helper = DnsProxy::new(
        args.server,
        args.account_id,
        args.access_key_id,
        args.access_key_secret,
        args.timeout,
    );
    let bind_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), args.port);
    let socket = UdpSocket::bind(bind_addr).await.unwrap();
    let dns_handler = DnsHandler::new(helper);
    let mut server = hickory_server::ServerFuture::new(dns_handler);
    server.register_socket(socket);
    server.register_listener(TcpListener::bind(bind_addr).await.unwrap(), timeout);

    let _ = server.block_until_done().await;
}

#[derive(Clone, Debug)]
pub struct DnsHandler {
    helper: DnsProxy,
}
impl DnsHandler {
    pub(crate) fn new(helper: DnsProxy) -> Self {
        DnsHandler { helper }
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let res = self.helper.get_response(request).await;
        match res {
            Ok((answer, name_servers, soa, additionals)) => {
                let header = request.request_info().header.clone();
                let response = MessageResponseBuilder::from_message_request(request);
                let result = response.build(header, &answer, &name_servers, &soa, &additionals);

                let result = send_response(None, result, response_handle).await;
                match result {
                    Ok(result) => result,
                    Err(e) => {
                        tracing::error!("Error sending response: {}", e);
                        DnsProxy::failure_response().unwrap()
                    }
                }
            }
            Err(e) => {
                tracing::error!("Error handling request: {}", e);
                DnsProxy::failure_response().unwrap()
            }
        }
    }
}
#[allow(unused_mut, unused_variables)]
async fn send_response<'a, R: ResponseHandler>(
    response_edns: Option<Edns>,
    mut response: MessageResponse<
        '_,
        'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
    >,
    mut response_handle: R,
) -> io::Result<ResponseInfo> {
    response_handle.send_response(response).await
}

// tests
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_dns_entity() {
        let helper = DnsProxy::new(
            "127.0.0.1:8053".to_string(),
            "your_account_id".to_string(),
            "your_access_key_id".to_string(),
            "your_access_key_secret".to_string(),
            5000,
        );
        let res = helper
            .get_dns_entity("www.baidu.com", &RecordType::A.to_string(), None)
            .await;
        assert!(res.is_ok());
    }
}

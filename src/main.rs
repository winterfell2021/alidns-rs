use {
    anyhow::anyhow,
    clap::{command, Parser},
    faststr::FastStr,
    hickory_proto::{
        op::{Edns, Header, ResponseCode},
        rr::{
            rdata::{
                opt::{EdnsCode, EdnsOption},
                A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT,
            },
            Name, RData, Record, RecordType,
        },
        serialize::binary::{BinDecoder, Restrict},
    },
    hickory_server::{
        authority::{MessageResponse, MessageResponseBuilder},
        server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    },
    idna::domain_to_ascii,
    rand::prelude::SliceRandom,
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    std::{
        io,
        net::SocketAddr,
        str::FromStr,
        sync::LazyLock,
        time::{SystemTime, UNIX_EPOCH},
    },
    tokio::{
        net::{TcpListener, UdpSocket},
        time::Duration,
    },
    tracing_subscriber::EnvFilter,
};

const SERVER: LazyLock<Vec<FastStr>> = LazyLock::new(|| {
    ["223.5.5.5", "223.6.6.6"]
        .iter()
        .map(|x| FastStr::new(x))
        .collect()
});
#[macro_export]
macro_rules! formatx {
    ($($arg:expr),*) => {{
        let mut s = String::new();
        $(_formatx_internal!(s, $arg);)*
        s
    }};
}

macro_rules! _formatx_internal {
    ($s:expr, $arg:expr) => {{
        $s.push_str(&format!("{}", $arg));
    }};
    ($s:expr, $arg:literal) => {{
        $s.push_str($arg);
    }};
}

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
    server: FastStr,

    /// Listening address and port
    #[arg(short, long, default_value = "127.0.0.1:16883")]
    listen: String,

    /// whether to balance between servers
    #[arg(short, long, default_value_t = false)]
    rand: bool,

    /// whether to use https
    #[arg(long, default_value_t = false)]
    https: bool,

    /// whether to use http2
    #[arg(long, default_value_t = false)]
    http2: bool,
}

#[derive(Clone, Debug)]
struct DnsProxy {
    server: FastStr,
    account_id: String,
    access_key_id: String,
    access_key_secret: String,
    rand: bool,
    https: bool,
    http2: bool,
}
impl DnsProxy {
    fn new(
        server: FastStr,
        account_id: String,
        access_key_id: String,
        access_key_secret: String,
        rand: bool,
        https: bool,
        http2: bool,
    ) -> Self {
        DnsProxy {
            server,
            account_id,
            access_key_id,
            access_key_secret,
            rand,
            https,
            http2,
        }
    }

    fn failure_response() -> anyhow::Result<ResponseInfo> {
        let mut header = Header::new();
        header.set_response_code(ResponseCode::ServFail);
        Ok(header.into())
    }

    fn server(&self) -> FastStr {
        if self.rand {
            SERVER.choose(&mut rand::thread_rng()).unwrap().clone()
        } else {
            self.server.clone()
        }
    }
    fn build_url(
        &self,
        name: &str,
        rtype: &str,
        key: &str,
        ts: &str,
        ecs: Option<String>,
    ) -> String {
        let mut url: String = String::new();
        if self.https || self.http2 {
            url.push_str("https://");
        } else {
            url.push_str("http://");
        }
        url.push_str(&formatx!(
            &self.server(),
            "/resolve?name=",
            name,
            "&type=",
            rtype,
            "&uid=",
            self.account_id,
            "&ak=",
            self.access_key_id,
            "&key=",
            key,
            "&ts=",
            ts
        ));
        if let Some(ecs) = ecs {
            if !ecs.trim().is_empty() {
                url.push_str(&formatx!("&edns_client_subnet=", ecs, "/24"));
            }
        }
        url
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
        let name = if name.chars().any(|c| !c.is_ascii()) {
            domain_to_ascii(name).map_err(|_| anyhow!("Invalid domain name"))?
        } else {
            name.to_string()
        };
        let mut hasher = Sha256::new();
        hasher.update(format!(
            "{}{}{}{}{}",
            self.account_id, self.access_key_secret, ts, name, self.access_key_id
        ));
        let key: String = format!("{:X}", hasher.finalize());

        let url = self.build_url(&name, rtype, &key, &ts, ecs);

        let mut builder = reqwest::Client::builder();
        if self.http2 {
            builder = builder.use_rustls_tls();
        }
        let client = builder.build()?;
        let mut builder = client.get(&url);
        if self.http2 {
            builder = builder.version(reqwest::Version::HTTP_2);
        }
        let response = builder.send().await?;
        let text = response.text().await?;
        tracing::info!("[ali_response]: {}", text);
        Ok(sonic_rs::from_str::<DNSEntity>(&text).ok())
    }

    fn extract_address(input: &str) -> Option<String> {
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
            | RecordType::PTR
            | RecordType::MX
            | RecordType::SRV => {
                let dns_entity = self
                    .get_dns_entity(
                        &quest.name().to_utf8(),
                        &quest.query_type().to_string(),
                        edns,
                    )
                    .await?;
                if let Some(dns_entity) = dns_entity {
                    if dns_entity.status.unwrap_or(1) != 0 {
                        return Err(anyhow!("no such record"));
                    }
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
                                15 => {
                                    let parts: Vec<&str> = answer.data.split_whitespace().collect();
                                    if parts.len() != 2 {
                                        continue;
                                    }
                                    (
                                        RecordType::MX,
                                        RData::MX(MX::new(
                                            parts[0].parse::<u16>().unwrap(),
                                            Name::from_str(parts[1])?,
                                        )),
                                    )
                                }
                                33 => {
                                    let parts: Vec<&str> = answer.data.split_whitespace().collect();
                                    if parts.len() != 4 {
                                        continue;
                                    }
                                    let priority = parts[0].parse::<u16>().unwrap();
                                    let weight = parts[1].parse::<u16>().unwrap();
                                    let port = parts[2].parse::<u16>().unwrap();
                                    let target = Name::from_str(parts[3]).unwrap();
                                    (
                                        RecordType::SRV,
                                        RData::SRV(SRV::new(priority, weight, port, target)),
                                    )
                                }
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
                return Err(anyhow!("unsupport query type: {:?}", quest.query_type()));
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
        args.rand,
        args.https,
        args.http2,
    );
    let bind_addr: SocketAddr = SocketAddr::from_str(&args.listen).unwrap();
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
            Err(_) => {
                // tracing::error!("Error handling request: {}", e);
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
            "127.0.0.1:8053".into(),
            "your_account_id".to_string(),
            "your_access_key_id".to_string(),
            "your_access_key_secret".to_string(),
            false,
            false,
            false,
        );
        let res = helper
            .get_dns_entity("www.baidu.com", &RecordType::A.to_string(), None)
            .await;
        assert!(res.is_ok());
    }
}

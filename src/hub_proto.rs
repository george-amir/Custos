//! Pre-generated `prost` + `tonic` bindings for `proto/custos_hub.proto` (`custos.hub.v1`).
//! Vendored directly in source so `cargo install custos` and `cargo add custos` work
//! out-of-the-box without requiring an external `protoc` C++ binary on the host machine.

#![allow(
    unused_variables,
    dead_code,
    missing_docs,
    clippy::wildcard_imports,
    clippy::let_unit_value
)]

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IpSignal {
    /// 4 bytes (IPv4) or 16 bytes (IPv6)
    #[prost(bytes = "vec", tag = "1")]
    pub ip: ::prost::alloc::vec::Vec<u8>,
    /// 1 byte varint
    #[prost(enumeration = "ThreatClassProto", tag = "2")]
    pub threat: i32,
    /// 4 bytes
    #[prost(float, tag = "3")]
    pub noul: f32,
    /// 4 bytes
    #[prost(float, tag = "4")]
    pub confidence: f32,
    #[prost(uint32, tag = "5")]
    pub suggested_ttl_secs: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignatureSignal {
    #[prost(string, tag = "1")]
    pub method: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub path_prefix: ::prost::alloc::string::String,
    #[prost(enumeration = "ThreatClassProto", tag = "3")]
    pub threat: i32,
    #[prost(float, tag = "4")]
    pub confidence: f32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignalBatch {
    #[prost(string, tag = "1")]
    pub node_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub api_token: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "3")]
    pub ip_signals: ::prost::alloc::vec::Vec<IpSignal>,
    #[prost(message, repeated, tag = "4")]
    pub signature_signals: ::prost::alloc::vec::Vec<SignatureSignal>,
}

#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct PushAck {
    #[prost(uint32, tag = "1")]
    pub accepted_ips: u32,
    #[prost(uint32, tag = "2")]
    pub accepted_signatures: u32,
    #[prost(uint32, tag = "3")]
    pub rejected_canary: u32,
    #[prost(uint64, tag = "4")]
    pub latest_seq: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PullRequest {
    #[prost(string, tag = "1")]
    pub node_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub since_seq: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IpBanDelta {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub ip: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration = "ThreatClassProto", tag = "3")]
    pub threat: i32,
    #[prost(float, tag = "4")]
    pub noul: f32,
    #[prost(float, tag = "5")]
    pub confidence: f32,
    #[prost(uint32, tag = "6")]
    pub ttl_secs: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignatureDelta {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    #[prost(string, tag = "2")]
    pub method: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub path_prefix: ::prost::alloc::string::String,
    #[prost(enumeration = "ThreatClassProto", tag = "4")]
    pub threat: i32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HubDeltaBatch {
    #[prost(uint64, tag = "1")]
    pub latest_seq: u64,
    #[prost(message, repeated, tag = "2")]
    pub ip_deltas: ::prost::alloc::vec::Vec<IpBanDelta>,
    #[prost(message, repeated, tag = "3")]
    pub signature_deltas: ::prost::alloc::vec::Vec<SignatureDelta>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeStreamMessage {
    #[prost(string, tag = "1")]
    pub node_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub since_seq: u64,
    #[prost(message, optional, tag = "3")]
    pub signals: ::core::option::Option<SignalBatch>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ThreatClassProto {
    ThreatClassUnspecified = 0,
    BenignTraffic = 1,
    CredentialStuffing = 2,
    SqliOrInjection = 3,
    PathTraversalLfi = 4,
    VulnerabilityScanner = 5,
    ApiEnumerationIdor = 6,
    Layer7Dos = 7,
}

impl ThreatClassProto {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::ThreatClassUnspecified => "THREAT_CLASS_UNSPECIFIED",
            Self::BenignTraffic => "BENIGN_TRAFFIC",
            Self::CredentialStuffing => "CREDENTIAL_STUFFING",
            Self::SqliOrInjection => "SQLI_OR_INJECTION",
            Self::PathTraversalLfi => "PATH_TRAVERSAL_LFI",
            Self::VulnerabilityScanner => "VULNERABILITY_SCANNER",
            Self::ApiEnumerationIdor => "API_ENUMERATION_IDOR",
            Self::Layer7Dos => "LAYER7_DOS",
        }
    }

    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "THREAT_CLASS_UNSPECIFIED" => Some(Self::ThreatClassUnspecified),
            "BENIGN_TRAFFIC" => Some(Self::BenignTraffic),
            "CREDENTIAL_STUFFING" => Some(Self::CredentialStuffing),
            "SQLI_OR_INJECTION" => Some(Self::SqliOrInjection),
            "PATH_TRAVERSAL_LFI" => Some(Self::PathTraversalLfi),
            "VULNERABILITY_SCANNER" => Some(Self::VulnerabilityScanner),
            "API_ENUMERATION_IDOR" => Some(Self::ApiEnumerationIdor),
            "LAYER7_DOS" => Some(Self::Layer7Dos),
            _ => None,
        }
    }
}

pub mod custos_hub_service_client {
    use tonic::codegen::http::Uri;
    use tonic::codegen::*;

    #[derive(Debug, Clone)]
    pub struct CustosHubServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }

    impl CustosHubServiceClient<tonic::transport::Channel> {
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }

    impl<T> CustosHubServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }

        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }

        pub async fn push_signals(
            &mut self,
            request: impl tonic::IntoRequest<super::SignalBatch>,
        ) -> std::result::Result<tonic::Response<super::PushAck>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::unknown(format!("Service was not ready: {}", e.into()))
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/custos.hub.v1.CustosHubService/PushSignals");
            let mut req = request.into_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "custos.hub.v1.CustosHubService",
                "PushSignals",
            ));
            self.inner.unary(req, path, codec).await
        }

        pub async fn pull_deltas(
            &mut self,
            request: impl tonic::IntoRequest<super::PullRequest>,
        ) -> std::result::Result<tonic::Response<super::HubDeltaBatch>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::unknown(format!("Service was not ready: {}", e.into()))
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/custos.hub.v1.CustosHubService/PullDeltas");
            let mut req = request.into_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "custos.hub.v1.CustosHubService",
                "PullDeltas",
            ));
            self.inner.unary(req, path, codec).await
        }

        pub async fn stream_intel(
            &mut self,
            request: impl tonic::IntoStreamingRequest<Message = super::NodeStreamMessage>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::HubDeltaBatch>>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::unknown(format!("Service was not ready: {}", e.into()))
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/custos.hub.v1.CustosHubService/StreamIntel");
            let mut req = request.into_streaming_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "custos.hub.v1.CustosHubService",
                "StreamIntel",
            ));
            self.inner.streaming(req, path, codec).await
        }
    }
}

pub mod custos_hub_service_server {
    use tonic::codegen::*;

    #[async_trait]
    pub trait CustosHubService: std::marker::Send + std::marker::Sync + 'static {
        async fn push_signals(
            &self,
            request: tonic::Request<super::SignalBatch>,
        ) -> std::result::Result<tonic::Response<super::PushAck>, tonic::Status>;

        async fn pull_deltas(
            &self,
            request: tonic::Request<super::PullRequest>,
        ) -> std::result::Result<tonic::Response<super::HubDeltaBatch>, tonic::Status>;

        type StreamIntelStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::HubDeltaBatch, tonic::Status>,
            > + std::marker::Send
            + 'static;

        async fn stream_intel(
            &self,
            request: tonic::Request<tonic::Streaming<super::NodeStreamMessage>>,
        ) -> std::result::Result<tonic::Response<Self::StreamIntelStream>, tonic::Status>;
    }

    #[derive(Debug)]
    pub struct CustosHubServiceServer<T> {
        inner: Arc<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }

    impl<T> CustosHubServiceServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }

        pub fn from_arc(inner: Arc<T>) -> Self {
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
    }

    impl<T, B> tonic::codegen::Service<http::Request<B>> for CustosHubServiceServer<T>
    where
        T: CustosHubService,
        B: Body + std::marker::Send + 'static,
        B::Error: Into<StdError> + std::marker::Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;

        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            match req.uri().path() {
                "/custos.hub.v1.CustosHubService/PushSignals" => {
                    struct PushSignalsSvc<T: CustosHubService>(pub Arc<T>);
                    impl<T: CustosHubService> tonic::server::UnaryService<super::SignalBatch> for PushSignalsSvc<T> {
                        type Response = super::PushAck;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SignalBatch>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CustosHubService>::push_signals(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = PushSignalsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/custos.hub.v1.CustosHubService/PullDeltas" => {
                    struct PullDeltasSvc<T: CustosHubService>(pub Arc<T>);
                    impl<T: CustosHubService> tonic::server::UnaryService<super::PullRequest> for PullDeltasSvc<T> {
                        type Response = super::HubDeltaBatch;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::PullRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CustosHubService>::pull_deltas(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = PullDeltasSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/custos.hub.v1.CustosHubService/StreamIntel" => {
                    struct StreamIntelSvc<T: CustosHubService>(pub Arc<T>);
                    impl<T: CustosHubService>
                        tonic::server::StreamingService<super::NodeStreamMessage>
                        for StreamIntelSvc<T>
                    {
                        type Response = super::HubDeltaBatch;
                        type ResponseStream = T::StreamIntelStream;
                        type Future =
                            BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<tonic::Streaming<super::NodeStreamMessage>>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CustosHubService>::stream_intel(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = StreamIntelSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    let mut response = http::Response::new(empty_body());
                    let headers = response.headers_mut();
                    headers.insert(
                        tonic::Status::GRPC_STATUS,
                        (tonic::Code::Unimplemented as i32).into(),
                    );
                    headers.insert(
                        http::header::CONTENT_TYPE,
                        tonic::metadata::GRPC_CONTENT_TYPE,
                    );
                    Ok(response)
                }),
            }
        }
    }

    impl<T> Clone for CustosHubServiceServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
                max_decoding_message_size: self.max_decoding_message_size,
                max_encoding_message_size: self.max_encoding_message_size,
            }
        }
    }

    pub const SERVICE_NAME: &str = "custos.hub.v1.CustosHubService";

    impl<T> tonic::server::NamedService for CustosHubServiceServer<T> {
        const NAME: &'static str = SERVICE_NAME;
    }
}

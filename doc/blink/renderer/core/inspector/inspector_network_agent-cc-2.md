Response:
The user wants to understand the functionality of the provided C++ code snippet from `inspector_network_agent.cc`. This is the third part of a four-part series, so I should focus on summarizing the functionality covered in this specific segment while keeping the overall context of a network agent in mind.

Here's a breakdown of the functionalities within this snippet:

1. **Handling `DidReceiveData`:** Processes received data chunks, potentially buffering it, and notifying the frontend. It also handles streaming data.
2. **Handling `DidReceiveBlob`:** Deals with receiving data as a Blob.
3. **Handling `DidReceiveEncodedDataLength`:** Records the encoded data length.
4. **Handling `DidFinishLoading`:**  Marks the completion of loading, potentially sending remaining buffered data and notifying the frontend.
5. **Handling `DidReceiveCorsRedirectResponse`:** Processes CORS redirect responses.
6. **Handling `DidFailLoading`:** Reports loading failures, including handling specific cases like Trust Token cache hits.
7. **Handling Script imports and responses:**  Specific handling for script resources.
8. **Determining Navigation requests:** A utility function to identify navigation requests.
9. **Handling XHR (XMLHttpRequest) requests:** Includes tracking XHR requests for potential replay.
10. **Handling EventSource requests:**  Detects and reports EventSource events.
11. **Building Initiator Objects:** Creates objects representing the origin of network requests, crucial for debugging.
12. **Determining Protocol:**  Identifies the network protocol used for a request.
13. **Handling WebSocket events:**  Tracking the lifecycle and messages of WebSockets.
14. **Handling WebTransport events:** Tracking the lifecycle of WebTransport connections.

Based on this, I can formulate the summary. I also need to consider the connections to Javascript, HTML, and CSS, provide examples, and address potential user errors.
```cpp
not_modified && cached_resource && cached_resource->EncodedSize()) {
    DidReceiveData(
        identifier, loader,
        base::SpanOrSize<const char>(cached_resource->EncodedSize()));
  }
}

static bool IsErrorStatusCode(int status_code) {
  return status_code >= 400;
}

protocol::Response InspectorNetworkAgent::streamResourceContent(
    const String& request_id,
    protocol::Binary* buffered_data) {
  NetworkResourcesData::ResourceData const* resource_data =
      resources_data_->Data(request_id);

  if (!resource_data) {
    return protocol::Response::InvalidParams(
        "Request with the provided ID does not exists");
  }

  if (resource_data->HasContent()) {
    return protocol::Response::InvalidParams(
        "Request with the provided ID has already finished loading");
  }

  streaming_request_ids_.insert(request_id);

  const std::optional<SegmentedBuffer>& data = resource_data->Data();
  if (data) {
    *buffered_data =
        protocol::Binary::fromVector(data->CopyAs<Vector<uint8_t>>());
  }
  return protocol::Response::Success();
}

void InspectorNetworkAgent::DidReceiveData(uint64_t identifier,
                                           DocumentLoader* loader,
                                           base::SpanOrSize<const char> data) {
  String request_id = RequestId(loader, identifier);
  Maybe<protocol::Binary> binary_data;

  if (auto data_span = data.span(); data_span) {
    NetworkResourcesData::ResourceData const* resource_data =
        resources_data_->Data(request_id);
    if (resource_data && !resource_data->HasContent() &&
        (!resource_data->CachedResource() ||
         resource_data->CachedResource()->GetDataBufferingPolicy() ==
             kDoNotBufferData ||
         IsErrorStatusCode(resource_data->HttpStatusCode()))) {
      resources_data_->MaybeAddResourceData(request_id, *data_span);
    }

    if (streaming_request_ids_.Contains(request_id)) {
      binary_data = protocol::Binary::fromSpan(base::as_bytes(*data_span));
    }
  }

  GetFrontend()->dataReceived(
      request_id, base::TimeTicks::Now().since_origin().InSecondsF(),
      static_cast<int>(data.size()),
      static_cast<int>(
          resources_data_->GetAndClearPendingEncodedDataLength(request_id)),
      std::move(binary_data));
}

void InspectorNetworkAgent::DidReceiveBlob(uint64_t identifier,
                                           DocumentLoader* loader,
                                           scoped_refptr<BlobDataHandle> blob) {
  String request_id = RequestId(loader, identifier);
  resources_data_->BlobReceived(request_id, std::move(blob));
}

void InspectorNetworkAgent::DidReceiveEncodedDataLength(
    DocumentLoader* loader,
    uint64_t identifier,
    size_t encoded_data_length) {
  String request_id = RequestId(loader, identifier);
  resources_data_->AddPendingEncodedDataLength(request_id, encoded_data_length);
}

void InspectorNetworkAgent::DidFinishLoading(
    uint64_t identifier,
    DocumentLoader* loader,
    base::TimeTicks monotonic_finish_time,
    int64_t encoded_data_length,
    int64_t decoded_body_length) {
  String request_id = RequestId(loader, identifier);
  streaming_request_ids_.erase(request_id);

  NetworkResourcesData::ResourceData const* resource_data =
      resources_data_->Data(request_id);

  int pending_encoded_data_length = static_cast<int>(
      resources_data_->GetAndClearPendingEncodedDataLength(request_id));
  if (pending_encoded_data_length > 0) {
    GetFrontend()->dataReceived(
        request_id, base::TimeTicks::Now().since_origin().InSecondsF(), 0,
        pending_encoded_data_length);
  }

  if (resource_data && !resource_data->HasContent() &&
      (!resource_data->CachedResource() ||
       resource_data->CachedResource()->GetDataBufferingPolicy() ==
           kDoNotBufferData ||
       IsErrorStatusCode(resource_data->HttpStatusCode()))) {
    resources_data_->MaybeAddResourceData(request_id,
                                          base::span_from_cstring(""));
  }

  resources_data_->MaybeDecodeDataToContent(request_id);
  if (monotonic_finish_time.is_null())
    monotonic_finish_time = base::TimeTicks::Now();

  // TODO(npm): Use base::TimeTicks in Network.h.
  GetFrontend()->loadingFinished(
      request_id, monotonic_finish_time.since_origin().InSecondsF(),
      encoded_data_length);
}

void InspectorNetworkAgent::DidReceiveCorsRedirectResponse(
    uint64_t identifier,
    DocumentLoader* loader,
    const ResourceResponse& response,
    Resource* resource) {
  // Update the response and finish loading
  DidReceiveResourceResponse(identifier, loader, response, resource);
  DidFinishLoading(identifier, loader, base::TimeTicks(),
                   URLLoaderClient::kUnknownEncodedDataLength, 0);
}

void InspectorNetworkAgent::DidFailLoading(
    CoreProbeSink* sink,
    uint64_t identifier,
    DocumentLoader* loader,
    const ResourceError& error,
    const base::UnguessableToken& devtools_frame_or_worker_token) {
  String request_id = RequestId(loader, identifier);
  streaming_request_ids_.erase(request_id);

  // A Trust Token redemption can be served from cache if a valid
  // Signed-Redemption-Record is present. In this case the request is aborted
  // with a special error code. Sementically, the request did succeed, so that
  // is what we report to the frontend.
  if (error.IsTrustTokenCacheHit()) {
    GetFrontend()->requestServedFromCache(request_id);
    GetFrontend()->loadingFinished(
        request_id, base::TimeTicks::Now().since_origin().InSecondsF(), 0);
    return;
  }

  bool canceled = error.IsCancellation();

  protocol::Maybe<String> blocked_reason = BuildBlockedReason(error);
  auto cors_error_status = error.CorsErrorStatus();
  protocol::Maybe<protocol::Network::CorsErrorStatus>
      protocol_cors_error_status;
  if (cors_error_status) {
    protocol_cors_error_status = BuildCorsErrorStatus(*cors_error_status);
  }
  GetFrontend()->loadingFailed(
      request_id, base::TimeTicks::Now().since_origin().InSecondsF(),
      InspectorPageAgent::ResourceTypeJson(
          resources_data_->GetResourceType(request_id)),
      error.LocalizedDescription(), canceled, std::move(blocked_reason),
      std::move(protocol_cors_error_status));
}

void InspectorNetworkAgent::ScriptImported(uint64_t identifier,
                                           const String& source_string) {
  resources_data_->SetResourceContent(
      IdentifiersFactory::SubresourceRequestId(identifier), source_string);
}

void InspectorNetworkAgent::DidReceiveScriptResponse(uint64_t identifier) {
  resources_data_->SetResourceType(
      IdentifiersFactory::SubresourceRequestId(identifier),
      InspectorPageAgent::kScriptResource);
}

// static
bool InspectorNetworkAgent::IsNavigation(DocumentLoader* loader,
                                         uint64_t identifier) {
  return loader && loader->MainResourceIdentifier() == identifier;
}

void InspectorNetworkAgent::WillLoadXHR(ExecutionContext* execution_context,
                                        const AtomicString& method,
                                        const KURL& url,
                                        bool async,
                                        const HTTPHeaderMap& headers,
                                        bool include_credentials) {
  DCHECK(!pending_request_type_);
  pending_xhr_replay_data_ = MakeGarbageCollected<XHRReplayData>(
      execution_context, method, UrlWithoutFragment(url), async,
      include_credentials);
  for (const auto& header : headers)
    pending_xhr_replay_data_->AddHeader(header.key, header.value);
}

void InspectorNetworkAgent::DidFinishXHR(XMLHttpRequest* xhr) {
  replay_xhrs_.erase(xhr);
}

void InspectorNetworkAgent::WillSendEventSourceRequest() {
  DCHECK(!pending_request_type_);
  pending_request_type_ = InspectorPageAgent::kEventSourceResource;
}

void InspectorNetworkAgent::WillDispatchEventSourceEvent(
    uint64_t identifier,
    const AtomicString& event_name,
    const AtomicString& event_id,
    const String& data) {
  GetFrontend()->eventSourceMessageReceived(
      IdentifiersFactory::SubresourceRequestId(identifier),
      base::TimeTicks::Now().since_origin().InSecondsF(),
      event_name.GetString(), event_id.GetString(), data);
}

std::unique_ptr<protocol::Network::Initiator>
InspectorNetworkAgent::BuildInitiatorObject(
    Document* document,
    const FetchInitiatorInfo& initiator_info,
    int max_async_depth) {
  if (initiator_info.is_imported_module && !initiator_info.referrer.empty()) {
    std::unique_ptr<protocol::Network::Initiator> initiator_object =
        protocol::Network::Initiator::create()
            .setType(protocol::Network::Initiator::TypeEnum::Script)
            .build();
    initiator_object->setUrl(initiator_info.referrer);
    initiator_object->setLineNumber(
        initiator_info.position.line_.ZeroBasedInt());
    initiator_object->setColumnNumber(
        initiator_info.position.column_.ZeroBasedInt());
    return initiator_object;
  }

  bool was_requested_by_stylesheet =
      initiator_info.name == fetch_initiator_type_names::kCSS ||
      initiator_info.name == fetch_initiator_type_names::kUacss;
  if (was_requested_by_stylesheet && !initiator_info.referrer.empty()) {
    std::unique_ptr<protocol::Network::Initiator> initiator_object =
        protocol::Network::Initiator::create()
            .setType(protocol::Network::Initiator::TypeEnum::Parser)
            .build();
    if (initiator_info.position != TextPosition::BelowRangePosition()) {
      initiator_object->setLineNumber(
          initiator_info.position.line_.ZeroBasedInt());
      initiator_object->setColumnNumber(
          initiator_info.position.column_.ZeroBasedInt());
    }
    initiator_object->setUrl(initiator_info.referrer);
    return initiator_object;
  }

  // We skip stack checking for stylesheet-initiated requests as it may
  // represent the cause of a style recalculation rather than the actual
  // resources themselves. See crbug.com/918196.
  if (!was_requested_by_stylesheet) {
    std::unique_ptr<v8_inspector::protocol::Runtime::API::StackTrace>
        current_stack_trace =
            CaptureSourceLocation(document ? document->GetExecutionContext()
                                           : nullptr)
                ->BuildInspectorObject(max_async_depth);
    if (current_stack_trace) {
      std::unique_ptr<protocol::Network::Initiator> initiator_object =
          protocol::Network::Initiator::create()
              .setType(protocol::Network::Initiator::TypeEnum::Script)
              .build();
      if (initiator_info.position != TextPosition::BelowRangePosition()) {
        initiator_object->setLineNumber(
            initiator_info.position.line_.ZeroBasedInt());
        initiator_object->setColumnNumber(
            initiator_info.position.column_.ZeroBasedInt());
      }
      initiator_object->setStack(std::move(current_stack_trace));
      return initiator_object;
    }
  }

  while (document && !document->GetScriptableDocumentParser())
    document = document->LocalOwner() ? document->LocalOwner()->ownerDocument()
                                      : nullptr;
  if (document && document->GetScriptableDocumentParser()) {
    std::unique_ptr<protocol::Network::Initiator> initiator_object =
        protocol::Network::Initiator::create()
            .setType(protocol::Network::Initiator::TypeEnum::Parser)
            .build();
    initiator_object->setUrl(UrlWithoutFragment(document->Url()).GetString());
    if (TextPosition::BelowRangePosition() != initiator_info.position) {
      initiator_object->setLineNumber(
          initiator_info.position.line_.ZeroBasedInt());
      initiator_object->setColumnNumber(
          initiator_info.position.column_.ZeroBasedInt());
    } else {
      initiator_object->setLineNumber(document->GetScriptableDocumentParser()
                                          ->GetTextPosition()
                                          .line_.ZeroBasedInt());
      initiator_object->setColumnNumber(document->GetScriptableDocumentParser()
                                            ->GetTextPosition()
                                            .column_.ZeroBasedInt());
    }
    return initiator_object;
  }

  return protocol::Network::Initiator::create()
      .setType(protocol::Network::Initiator::TypeEnum::Other)
      .build();
}

String InspectorNetworkAgent::GetProtocolAsString(
    const ResourceResponse& response) {
  String protocol = response.AlpnNegotiatedProtocol();
  if (protocol.empty() || protocol == "unknown") {
    if (response.WasFetchedViaSPDY()) {
      protocol = "h2";
    } else if (response.IsHTTP()) {
      protocol = "http";
      if (response.HttpVersion() ==
          ResourceResponse::HTTPVersion::kHTTPVersion_0_9) {
        protocol = "http/0.9";
      } else if (response.HttpVersion() ==
                 ResourceResponse::HTTPVersion::kHTTPVersion_1_0) {
        protocol = "http/1.0";
      } else if (response.HttpVersion() ==
                 ResourceResponse::HTTPVersion::kHTTPVersion_1_1) {
        protocol = "http/1.1";
      }
    } else {
      protocol = response.CurrentRequestUrl().Protocol();
    }
  }
  return protocol;
}

void InspectorNetworkAgent::WillCreateP2PSocketUdp(
    std::optional<base::UnguessableToken>* devtools_token) {
  *devtools_token = devtools_token_;
}

void InspectorNetworkAgent::WillCreateWebSocket(
    ExecutionContext* execution_context,
    uint64_t identifier,
    const KURL& request_url,
    const String&,
    std::optional<base::UnguessableToken>* devtools_token) {
  *devtools_token = devtools_token_;
  std::unique_ptr<v8_inspector::protocol::Runtime::API::StackTrace>
      current_stack_trace =
          CaptureSourceLocation(execution_context)->BuildInspectorObject();
  if (!current_stack_trace) {
    GetFrontend()->webSocketCreated(
        IdentifiersFactory::SubresourceRequestId(identifier),
        UrlWithoutFragment(request_url).GetString());
    return;
  }

  std::unique_ptr<protocol::Network::Initiator> initiator_object =
      protocol::Network::Initiator::create()
          .setType(protocol::Network::Initiator::TypeEnum::Script)
          .build();
  initiator_object->setStack(std::move(current_stack_trace));
  GetFrontend()->webSocketCreated(
      IdentifiersFactory::SubresourceRequestId(identifier),
      UrlWithoutFragment(request_url).GetString(), std::move(initiator_object));
}

void InspectorNetworkAgent::WillSendWebSocketHandshakeRequest(
    ExecutionContext*,
    uint64_t identifier,
    network::mojom::blink::WebSocketHandshakeRequest* request) {
  DCHECK(request);
  HTTPHeaderMap headers;
  for (auto& header : request->headers)
    headers.Add(AtomicString(header->name), AtomicString(header->value));
  std::unique_ptr<protocol::Network::WebSocketRequest> request_object =
      protocol::Network::WebSocketRequest::create()
          .setHeaders(BuildObjectForHeaders(headers))
          .build();
  GetFrontend()->webSocketWillSendHandshakeRequest(
      IdentifiersFactory::SubresourceRequestId(identifier),
      base::TimeTicks::Now().since_origin().InSecondsF(),
      base::Time::Now().InSecondsFSinceUnixEpoch(), std::move(request_object));
}

void InspectorNetworkAgent::DidReceiveWebSocketHandshakeResponse(
    ExecutionContext*,
    uint64_t identifier,
    network::mojom::blink::WebSocketHandshakeRequest* request,
    network::mojom::blink::WebSocketHandshakeResponse* response) {
  DCHECK(response);

  HTTPHeaderMap response_headers;
  for (auto& header : response->headers) {
    HTTPHeaderMap::AddResult add_result = response_headers.Add(
        AtomicString(header->name), AtomicString(header->value));
    if (!add_result.is_new_entry) {
      // Protocol expects the "\n" separated format.
      add_result.stored_value->value =
          add_result.stored_value->value + "\n" + header->value;
    }
  }

  std::unique_ptr<protocol::Network::WebSocketResponse> response_object =
      protocol::Network::WebSocketResponse::create()
          .setStatus(response->status_code)
          .setStatusText(response->status_text)
          .setHeaders(BuildObjectForHeaders(response_headers))
          .build();
  if (!response->headers_text.empty())
    response_object->setHeadersText(response->headers_text);

  if (request) {
    HTTPHeaderMap request_headers;
    for (auto& header : request->headers) {
      request_headers.Add(AtomicString(header->name),
                          AtomicString(header->value));
    }
    response_object->setRequestHeaders(BuildObjectForHeaders(request_headers));
    if (!request->headers_text.empty())
      response_object->setRequestHeadersText(request->headers_text);
  }

  GetFrontend()->webSocketHandshakeResponseReceived(
      IdentifiersFactory::SubresourceRequestId(identifier),
      base::TimeTicks::Now().since_origin().InSecondsF(),
      std::move(response_object));
}

void InspectorNetworkAgent::DidCloseWebSocket(ExecutionContext*,
                                              uint64_t identifier) {
  GetFrontend()->webSocketClosed(
      IdentifiersFactory::SubresourceRequestId(identifier),
      base::TimeTicks::Now().since_origin().InSecondsF());
}

void InspectorNetworkAgent::DidReceiveWebSocketMessage(
    uint64_t identifier,
    int op_code,
    bool masked,
    const Vector<base::span<const char>>& data) {
  size_t size = 0;
  for (const auto& span : data) {
    size += span.size();
  }
  Vector<char> flatten;
  flatten.reserve(base::checked_cast<wtf_size_t>(size));
  for (const auto& span : data) {
    flatten.AppendSpan(span);
  }
  GetFrontend()->webSocketFrameReceived(
      IdentifiersFactory::SubresourceRequestId(identifier),
      base::TimeTicks::Now().since_origin().InSecondsF(),
      WebSocketMessageToProtocol(op_code, masked, flatten));
}

void InspectorNetworkAgent::DidSendWebSocketMessage(
    uint64_t identifier,
    int op_code,
    bool masked,
    base::span<const char> payload) {
  GetFrontend()->webSocketFrameSent(
      IdentifiersFactory::SubresourceRequestId(identifier),
      base::TimeTicks::Now().since_origin().InSecondsF(),
      WebSocketMessageToProtocol(op_code, masked, payload));
}

void InspectorNetworkAgent::DidReceiveWebSocketMessageError(
    uint64_t identifier,
    const String& error_message) {
  GetFrontend()->webSocketFrameError(
      IdentifiersFactory::SubresourceRequestId(identifier),
      base::TimeTicks::Now().since_origin().InSecondsF(), error_message);
}

void InspectorNetworkAgent::WebTransportCreated(
    ExecutionContext* execution_context,
    uint64_t transport_id,
    const KURL& request_url) {
  std::unique_ptr<v8_inspector::protocol::Runtime::API::StackTrace>
      current_stack_trace =
          CaptureSourceLocation(execution_context)->BuildInspectorObject();
  if (!current_stack_trace) {
    GetFrontend()->webTransportCreated(
        IdentifiersFactory::SubresourceRequestId(transport_id),
        UrlWithoutFragment(request_url).GetString(),
        base::TimeTicks::Now().since_origin().InSecondsF());
    return;
  }

  std::unique_ptr<protocol::Network::Initiator> initiator_object =
      protocol::Network::Initiator::create()
          .setType(protocol::Network::Initiator::TypeEnum::Script)
          .build();
  initiator_object->setStack(std::move(current_stack_trace));
  GetFrontend()->webTransportCreated(
      IdentifiersFactory::SubresourceRequestId(transport_id),
      UrlWithoutFragment(request_url).GetString(),
      base::TimeTicks::Now().since_origin().InSecondsF(),
      std::move(initiator_object));
}

void InspectorNetworkAgent::WebTransportConnectionEstablished(
    uint64_t transport_id) {
  GetFrontend()->webTransportConnectionEstablished(
      IdentifiersFactory::SubresourceRequestId(transport_id),
      base::TimeTicks::Now().since_origin().InSecondsF());
}

void InspectorNetworkAgent::WebTransportClosed(uint64_t transport_id) {
  GetFrontend()->webTransportClosed(
      IdentifiersFactory::SubresourceRequestId(transport_id),
      base::TimeTicks::Now().since_origin().InSecondsF());
}

protocol::Response InspectorNetworkAgent::enable(
    Maybe<int> total_buffer_size,
    Maybe<int> resource_buffer_size,
    Maybe<int> max_post_data_size) {
  total_buffer_size_.Set(total_buffer_size.value_or(kDefaultTotalBufferSize));
  resource_buffer_size_.Set(
      resource_buffer_size.value_or(kDefaultResourceBufferSize));
  max_post_data_size_.Set(max_post_data_size.value_or(0));
  Enable();
  return protocol::Response::Success();
}

void InspectorNetworkAgent::Enable() {
  if (!GetFrontend())
    return;
  enabled_.Set(true);
  resources_data_->SetResourcesDataSizeLimits(total_buffer_size_.Get(),
                                              resource_buffer_size_.Get());
  instrumenting_agents_->AddInspectorNetworkAgent(this);
}

protocol::Response InspectorNetworkAgent::disable() {
  DCHECK(!pending_request_type_);
  if (IsMainThread())
    GetNetworkStateNotifier().ClearOverride();
  instrumenting_agents_->RemoveInspectorNetworkAgent(this);
  agent_state_.ClearAllFields();
  resources_data_->Clear();
  streaming_request_ids_.clear();
  clearAcceptedEncodingsOverride();
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::setExtraHTTPHeaders(
    std::unique_ptr<protocol::Network::Headers> headers) {
  extra_request_headers_.Clear();
  std::unique_ptr<protocol::DictionaryValue> in = headers->toValue();
  for (size_t i = 0; i < in->size(); ++i) {
    const auto& entry = in->at(i);
    String value;
    if (entry.second && entry.second->asString(&value))
      extra_request_headers_.Set(entry.first, value);
  }
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::setAttachDebugStack(bool enabled) {
  if (enabled && !enabled_.Get())
    return protocol::Response::InvalidParams("Domain must be enabled");
  attach_debug_stack_enabled_.Set(enabled);
  return protocol::Response::Success();
}

bool InspectorNetworkAgent::CanGetResponseBodyBlob(const String& request_id) {
  NetworkResourcesData::ResourceData const* resource_data =
      resources_data_->Data(request_id);
  BlobDataHandle* blob =
      resource_data ? resource_data->DownloadedFileBlob() : nullptr;
  if (!blob)
    return false;
  if (worker_or_worklet_global_scope_) {
    return true;
  }
  LocalFrame* frame = IdentifiersFactory::FrameById(inspected_frames_,
                                                    resource_data->FrameId());
  return frame && frame->GetDocument();
}

void InspectorNetworkAgent::GetResponseBodyBlob(
    const String& request_id,
    std::unique_ptr<GetResponseBodyCallback> callback) {
  NetworkResourcesData::ResourceData const* resource_data =
      resources_data_->Data(request_id);
  BlobDataHandle* blob = resource_data->DownloadedFileBlob();
  ExecutionContext* context = GetTargetExecutionContext();
  if (!context) {
    callback->sendFailure(protocol::Response::InternalError());
    return;
  }
  InspectorFileReaderLoaderClient* client =
      MakeGarbageCollected<InspectorFileReaderLoaderClient>(
          blob, context->GetTaskRunner(TaskType::kFileReading),
          WTF::BindOnce(
              ResponseBodyFileReaderLoaderDone, resource_data->MimeType(),
              resource_data->TextEncodingName(), std::move(callback)));
  client->Start();
}

void InspectorNetworkAgent::getResponseBody(
    const String& request_id,
    std::unique_ptr<GetResponseBodyCallback> callback) {
  if (CanGetResponseBodyBlob(request_id)) {
    GetResponseBodyBlob(request_id, std::move(callback));
    return;
  }

  String content;
  bool base64_encoded;
  protocol::Response response =
      GetResponseBody(request_id, &content, &base64_encoded);
  if (response.IsSuccess()) {
    callback->sendSuccess(content, base64_encoded);
  } else {
    callback->sendFailure(response);
  }
}

protocol::Response InspectorNetworkAgent::setBlockedURLs(
    std::unique_ptr<protocol::Array<String>> urls) {
  blocked_urls_.Clear();
  for (const String& url : *urls)
    blocked_urls_.Set(url, true);
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::replayXHR(const String& request_id) {
  String actual_request_id = request_id;

  XHRReplayData* xhr_replay_data = resources_data_->XhrReplayData(request_id);
  auto* data = resources_data_->Data(request_id);
  if (!xhr_replay_data || !data) {
    return protocol::Response::ServerError(
        "Given id does not correspond to XHR");
  }

  ExecutionContext* execution_context = xhr_replay_data->GetExecutionContext();
  if (!execution_context || execution_context->IsContextDestroyed()) {
    resources_data_->SetXHRReplayData(request_id, nullptr);
    return protocol::Response::ServerError("Document is already detached");
  }

  XMLHttpRequest* xhr = XMLHttpRequest::Create(execution_context);

  execution_context->RemoveURLFromMemoryCache(xhr_replay_data->Url());

  xhr->open(xhr_replay_data->Method(), xhr_replay_data->Url(),
            xhr_replay_data->Async(), IGNORE_EXCEPTION_FOR_TESTING);
  if (xhr_replay_data->IncludeCredentials())
    xhr->setWithCredentials(true, IGNORE_EXCEPTION_FOR_TESTING);
  for (const auto& header : xhr_replay_data->Headers()) {
    xhr->setRequestHeader(header.key, header.value,
                          IGNORE_EXCEPTION_FOR_TESTING);
  }
  xhr->SendForInspectorXHRReplay(data ? data->PostData() : nullptr,
                                 IGNORE_EXCEPTION_FOR_TESTING);

  replay_xhrs_.insert(xhr);
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::canClearBrowserCache(bool* result) {
  *result = true;
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::canClearBrowserCookies(bool* result) {
  *result = true;
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::setAcceptedEncodings(
    std::unique_ptr<protocol::Array<protocol::Network::ContentEncoding>>
        encodings) {
  HashSet<String> accepted_encodings;
  for (const protocol::Network::ContentEncoding& encoding : *encodings) {
    String value = AcceptedEncodingFromProtocol(encoding);
    if (value.IsNull()) {
      return protocol::Response::InvalidParams("Unknown encoding type: " +
                                               encoding.Utf8());
    }
    accepted_encodings.insert(value);
  }
  // If invoked with an empty list, it means none of the encodings should be
  // accepted. See InspectorNetworkAgent::PrepareRequest.
  if (accepted_encodings.empty())
    accepted_encodings.insert("none");

  // Set the inspector state.
  accepted_encodings_.Clear();
  for (auto encoding : accepted_encodings)
    accepted_encodings_.Set(encoding, true);

  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::clearAcceptedEncodingsOverride() {
  accepted_encodings_.Clear();
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::emulateNetworkConditions(
    bool offline,
    double latency,
    double download_throughput,
    double upload_throughput,
    Maybe<String> connection_type,
    Maybe<double> packet_loss,
    Maybe<int> packet_queue_length,
    Maybe<bool> packet_reordering) {
  WebConnectionType type = kWebConnectionTypeUnknown;
  if (connection_type.has_value()) {
    type = ToWebConnectionType(connection_type.value());
    if (type == kWebConnectionTypeUnknown)
      return protocol::Response::ServerError("Unknown connection type");
  }

  if (worker_or_worklet_global_scope_) {
    if (worker_or_worklet_global_scope_->IsServiceWorkerGlobalScope() ||
        worker_or_worklet_global_scope_->IsSharedWorkerGlobalScope()) {
      // In service workers and shared workers, we don't inspect the main thread
      // so we must post a task there to make it possible to use
      // NetworkStateNotifier.
      PostCrossThreadTask(
          *Thread::MainThread()->GetTaskRunner(
              MainThreadTaskRunnerRestricted()),
          FROM_HERE,
          CrossThreadBindOnce(SetNetworkStateOverride, offline, latency,
                              download_throughput, upload_throughput, type));
      return protocol::Response::Success();
    }
    return protocol::Response::ServerError("Not supported");
  }

  SetNetworkStateOverride(offline, latency, download_throughput,
                          upload_throughput, type);

  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::setCacheDisabled(
    bool cache_disabled) {
  // TODO(ananta)
  // We should extract network cache state into a global entity which can be
  // queried from FrameLoader and other places.
  cache_disabled_.Set(cache_disabled);
  if (cache_disabled && IsMainThread())
    MemoryCache::Get()->EvictResources();
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::setBypassServiceWorker(bool bypass) {
  bypass_service_worker_.Set(bypass);
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::getCertificate(
    const String& origin,
    std::unique_ptr<protocol::Array<String>>* certificate) {
  *certificate = std::make_unique<protocol::Array<String>>();
  scoped_refptr<const SecurityOrigin> security_origin =
      SecurityOrigin::CreateFromString(origin);
  for (auto& resource : resources_data_->Resources()) {
    scoped_refptr<const SecurityOrigin> resource_origin =
        SecurityOrigin::Create(resource->RequestedURL());
    net::X509Certificate* cert = resource->Certificate();
    if (resource_origin->IsSameOriginWith(security_origin.get()) &&
### 提示词
```
这是目录为blink/renderer/core/inspector/inspector_network_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
not_modified && cached_resource && cached_resource->EncodedSize()) {
    DidReceiveData(
        identifier, loader,
        base::SpanOrSize<const char>(cached_resource->EncodedSize()));
  }
}

static bool IsErrorStatusCode(int status_code) {
  return status_code >= 400;
}

protocol::Response InspectorNetworkAgent::streamResourceContent(
    const String& request_id,
    protocol::Binary* buffered_data) {
  NetworkResourcesData::ResourceData const* resource_data =
      resources_data_->Data(request_id);

  if (!resource_data) {
    return protocol::Response::InvalidParams(
        "Request with the provided ID does not exists");
  }

  if (resource_data->HasContent()) {
    return protocol::Response::InvalidParams(
        "Request with the provided ID has already finished loading");
  }

  streaming_request_ids_.insert(request_id);

  const std::optional<SegmentedBuffer>& data = resource_data->Data();
  if (data) {
    *buffered_data =
        protocol::Binary::fromVector(data->CopyAs<Vector<uint8_t>>());
  }
  return protocol::Response::Success();
}

void InspectorNetworkAgent::DidReceiveData(uint64_t identifier,
                                           DocumentLoader* loader,
                                           base::SpanOrSize<const char> data) {
  String request_id = RequestId(loader, identifier);
  Maybe<protocol::Binary> binary_data;

  if (auto data_span = data.span(); data_span) {
    NetworkResourcesData::ResourceData const* resource_data =
        resources_data_->Data(request_id);
    if (resource_data && !resource_data->HasContent() &&
        (!resource_data->CachedResource() ||
         resource_data->CachedResource()->GetDataBufferingPolicy() ==
             kDoNotBufferData ||
         IsErrorStatusCode(resource_data->HttpStatusCode()))) {
      resources_data_->MaybeAddResourceData(request_id, *data_span);
    }

    if (streaming_request_ids_.Contains(request_id)) {
      binary_data = protocol::Binary::fromSpan(base::as_bytes(*data_span));
    }
  }

  GetFrontend()->dataReceived(
      request_id, base::TimeTicks::Now().since_origin().InSecondsF(),
      static_cast<int>(data.size()),
      static_cast<int>(
          resources_data_->GetAndClearPendingEncodedDataLength(request_id)),
      std::move(binary_data));
}

void InspectorNetworkAgent::DidReceiveBlob(uint64_t identifier,
                                           DocumentLoader* loader,
                                           scoped_refptr<BlobDataHandle> blob) {
  String request_id = RequestId(loader, identifier);
  resources_data_->BlobReceived(request_id, std::move(blob));
}

void InspectorNetworkAgent::DidReceiveEncodedDataLength(
    DocumentLoader* loader,
    uint64_t identifier,
    size_t encoded_data_length) {
  String request_id = RequestId(loader, identifier);
  resources_data_->AddPendingEncodedDataLength(request_id, encoded_data_length);
}

void InspectorNetworkAgent::DidFinishLoading(
    uint64_t identifier,
    DocumentLoader* loader,
    base::TimeTicks monotonic_finish_time,
    int64_t encoded_data_length,
    int64_t decoded_body_length) {
  String request_id = RequestId(loader, identifier);
  streaming_request_ids_.erase(request_id);

  NetworkResourcesData::ResourceData const* resource_data =
      resources_data_->Data(request_id);

  int pending_encoded_data_length = static_cast<int>(
      resources_data_->GetAndClearPendingEncodedDataLength(request_id));
  if (pending_encoded_data_length > 0) {
    GetFrontend()->dataReceived(
        request_id, base::TimeTicks::Now().since_origin().InSecondsF(), 0,
        pending_encoded_data_length);
  }

  if (resource_data && !resource_data->HasContent() &&
      (!resource_data->CachedResource() ||
       resource_data->CachedResource()->GetDataBufferingPolicy() ==
           kDoNotBufferData ||
       IsErrorStatusCode(resource_data->HttpStatusCode()))) {
    resources_data_->MaybeAddResourceData(request_id,
                                          base::span_from_cstring(""));
  }

  resources_data_->MaybeDecodeDataToContent(request_id);
  if (monotonic_finish_time.is_null())
    monotonic_finish_time = base::TimeTicks::Now();

  // TODO(npm): Use base::TimeTicks in Network.h.
  GetFrontend()->loadingFinished(
      request_id, monotonic_finish_time.since_origin().InSecondsF(),
      encoded_data_length);
}

void InspectorNetworkAgent::DidReceiveCorsRedirectResponse(
    uint64_t identifier,
    DocumentLoader* loader,
    const ResourceResponse& response,
    Resource* resource) {
  // Update the response and finish loading
  DidReceiveResourceResponse(identifier, loader, response, resource);
  DidFinishLoading(identifier, loader, base::TimeTicks(),
                   URLLoaderClient::kUnknownEncodedDataLength, 0);
}

void InspectorNetworkAgent::DidFailLoading(
    CoreProbeSink* sink,
    uint64_t identifier,
    DocumentLoader* loader,
    const ResourceError& error,
    const base::UnguessableToken& devtools_frame_or_worker_token) {
  String request_id = RequestId(loader, identifier);
  streaming_request_ids_.erase(request_id);

  // A Trust Token redemption can be served from cache if a valid
  // Signed-Redemption-Record is present. In this case the request is aborted
  // with a special error code. Sementically, the request did succeed, so that
  // is what we report to the frontend.
  if (error.IsTrustTokenCacheHit()) {
    GetFrontend()->requestServedFromCache(request_id);
    GetFrontend()->loadingFinished(
        request_id, base::TimeTicks::Now().since_origin().InSecondsF(), 0);
    return;
  }

  bool canceled = error.IsCancellation();

  protocol::Maybe<String> blocked_reason = BuildBlockedReason(error);
  auto cors_error_status = error.CorsErrorStatus();
  protocol::Maybe<protocol::Network::CorsErrorStatus>
      protocol_cors_error_status;
  if (cors_error_status) {
    protocol_cors_error_status = BuildCorsErrorStatus(*cors_error_status);
  }
  GetFrontend()->loadingFailed(
      request_id, base::TimeTicks::Now().since_origin().InSecondsF(),
      InspectorPageAgent::ResourceTypeJson(
          resources_data_->GetResourceType(request_id)),
      error.LocalizedDescription(), canceled, std::move(blocked_reason),
      std::move(protocol_cors_error_status));
}

void InspectorNetworkAgent::ScriptImported(uint64_t identifier,
                                           const String& source_string) {
  resources_data_->SetResourceContent(
      IdentifiersFactory::SubresourceRequestId(identifier), source_string);
}

void InspectorNetworkAgent::DidReceiveScriptResponse(uint64_t identifier) {
  resources_data_->SetResourceType(
      IdentifiersFactory::SubresourceRequestId(identifier),
      InspectorPageAgent::kScriptResource);
}

// static
bool InspectorNetworkAgent::IsNavigation(DocumentLoader* loader,
                                         uint64_t identifier) {
  return loader && loader->MainResourceIdentifier() == identifier;
}

void InspectorNetworkAgent::WillLoadXHR(ExecutionContext* execution_context,
                                        const AtomicString& method,
                                        const KURL& url,
                                        bool async,
                                        const HTTPHeaderMap& headers,
                                        bool include_credentials) {
  DCHECK(!pending_request_type_);
  pending_xhr_replay_data_ = MakeGarbageCollected<XHRReplayData>(
      execution_context, method, UrlWithoutFragment(url), async,
      include_credentials);
  for (const auto& header : headers)
    pending_xhr_replay_data_->AddHeader(header.key, header.value);
}

void InspectorNetworkAgent::DidFinishXHR(XMLHttpRequest* xhr) {
  replay_xhrs_.erase(xhr);
}

void InspectorNetworkAgent::WillSendEventSourceRequest() {
  DCHECK(!pending_request_type_);
  pending_request_type_ = InspectorPageAgent::kEventSourceResource;
}

void InspectorNetworkAgent::WillDispatchEventSourceEvent(
    uint64_t identifier,
    const AtomicString& event_name,
    const AtomicString& event_id,
    const String& data) {
  GetFrontend()->eventSourceMessageReceived(
      IdentifiersFactory::SubresourceRequestId(identifier),
      base::TimeTicks::Now().since_origin().InSecondsF(),
      event_name.GetString(), event_id.GetString(), data);
}

std::unique_ptr<protocol::Network::Initiator>
InspectorNetworkAgent::BuildInitiatorObject(
    Document* document,
    const FetchInitiatorInfo& initiator_info,
    int max_async_depth) {
  if (initiator_info.is_imported_module && !initiator_info.referrer.empty()) {
    std::unique_ptr<protocol::Network::Initiator> initiator_object =
        protocol::Network::Initiator::create()
            .setType(protocol::Network::Initiator::TypeEnum::Script)
            .build();
    initiator_object->setUrl(initiator_info.referrer);
    initiator_object->setLineNumber(
        initiator_info.position.line_.ZeroBasedInt());
    initiator_object->setColumnNumber(
        initiator_info.position.column_.ZeroBasedInt());
    return initiator_object;
  }

  bool was_requested_by_stylesheet =
      initiator_info.name == fetch_initiator_type_names::kCSS ||
      initiator_info.name == fetch_initiator_type_names::kUacss;
  if (was_requested_by_stylesheet && !initiator_info.referrer.empty()) {
    std::unique_ptr<protocol::Network::Initiator> initiator_object =
        protocol::Network::Initiator::create()
            .setType(protocol::Network::Initiator::TypeEnum::Parser)
            .build();
    if (initiator_info.position != TextPosition::BelowRangePosition()) {
      initiator_object->setLineNumber(
          initiator_info.position.line_.ZeroBasedInt());
      initiator_object->setColumnNumber(
          initiator_info.position.column_.ZeroBasedInt());
    }
    initiator_object->setUrl(initiator_info.referrer);
    return initiator_object;
  }

  // We skip stack checking for stylesheet-initiated requests as it may
  // represent the cause of a style recalculation rather than the actual
  // resources themselves. See crbug.com/918196.
  if (!was_requested_by_stylesheet) {
    std::unique_ptr<v8_inspector::protocol::Runtime::API::StackTrace>
        current_stack_trace =
            CaptureSourceLocation(document ? document->GetExecutionContext()
                                           : nullptr)
                ->BuildInspectorObject(max_async_depth);
    if (current_stack_trace) {
      std::unique_ptr<protocol::Network::Initiator> initiator_object =
          protocol::Network::Initiator::create()
              .setType(protocol::Network::Initiator::TypeEnum::Script)
              .build();
      if (initiator_info.position != TextPosition::BelowRangePosition()) {
        initiator_object->setLineNumber(
            initiator_info.position.line_.ZeroBasedInt());
        initiator_object->setColumnNumber(
            initiator_info.position.column_.ZeroBasedInt());
      }
      initiator_object->setStack(std::move(current_stack_trace));
      return initiator_object;
    }
  }

  while (document && !document->GetScriptableDocumentParser())
    document = document->LocalOwner() ? document->LocalOwner()->ownerDocument()
                                      : nullptr;
  if (document && document->GetScriptableDocumentParser()) {
    std::unique_ptr<protocol::Network::Initiator> initiator_object =
        protocol::Network::Initiator::create()
            .setType(protocol::Network::Initiator::TypeEnum::Parser)
            .build();
    initiator_object->setUrl(UrlWithoutFragment(document->Url()).GetString());
    if (TextPosition::BelowRangePosition() != initiator_info.position) {
      initiator_object->setLineNumber(
          initiator_info.position.line_.ZeroBasedInt());
      initiator_object->setColumnNumber(
          initiator_info.position.column_.ZeroBasedInt());
    } else {
      initiator_object->setLineNumber(document->GetScriptableDocumentParser()
                                          ->GetTextPosition()
                                          .line_.ZeroBasedInt());
      initiator_object->setColumnNumber(document->GetScriptableDocumentParser()
                                            ->GetTextPosition()
                                            .column_.ZeroBasedInt());
    }
    return initiator_object;
  }

  return protocol::Network::Initiator::create()
      .setType(protocol::Network::Initiator::TypeEnum::Other)
      .build();
}

String InspectorNetworkAgent::GetProtocolAsString(
    const ResourceResponse& response) {
  String protocol = response.AlpnNegotiatedProtocol();
  if (protocol.empty() || protocol == "unknown") {
    if (response.WasFetchedViaSPDY()) {
      protocol = "h2";
    } else if (response.IsHTTP()) {
      protocol = "http";
      if (response.HttpVersion() ==
          ResourceResponse::HTTPVersion::kHTTPVersion_0_9) {
        protocol = "http/0.9";
      } else if (response.HttpVersion() ==
                 ResourceResponse::HTTPVersion::kHTTPVersion_1_0) {
        protocol = "http/1.0";
      } else if (response.HttpVersion() ==
                 ResourceResponse::HTTPVersion::kHTTPVersion_1_1) {
        protocol = "http/1.1";
      }
    } else {
      protocol = response.CurrentRequestUrl().Protocol();
    }
  }
  return protocol;
}

void InspectorNetworkAgent::WillCreateP2PSocketUdp(
    std::optional<base::UnguessableToken>* devtools_token) {
  *devtools_token = devtools_token_;
}

void InspectorNetworkAgent::WillCreateWebSocket(
    ExecutionContext* execution_context,
    uint64_t identifier,
    const KURL& request_url,
    const String&,
    std::optional<base::UnguessableToken>* devtools_token) {
  *devtools_token = devtools_token_;
  std::unique_ptr<v8_inspector::protocol::Runtime::API::StackTrace>
      current_stack_trace =
          CaptureSourceLocation(execution_context)->BuildInspectorObject();
  if (!current_stack_trace) {
    GetFrontend()->webSocketCreated(
        IdentifiersFactory::SubresourceRequestId(identifier),
        UrlWithoutFragment(request_url).GetString());
    return;
  }

  std::unique_ptr<protocol::Network::Initiator> initiator_object =
      protocol::Network::Initiator::create()
          .setType(protocol::Network::Initiator::TypeEnum::Script)
          .build();
  initiator_object->setStack(std::move(current_stack_trace));
  GetFrontend()->webSocketCreated(
      IdentifiersFactory::SubresourceRequestId(identifier),
      UrlWithoutFragment(request_url).GetString(), std::move(initiator_object));
}

void InspectorNetworkAgent::WillSendWebSocketHandshakeRequest(
    ExecutionContext*,
    uint64_t identifier,
    network::mojom::blink::WebSocketHandshakeRequest* request) {
  DCHECK(request);
  HTTPHeaderMap headers;
  for (auto& header : request->headers)
    headers.Add(AtomicString(header->name), AtomicString(header->value));
  std::unique_ptr<protocol::Network::WebSocketRequest> request_object =
      protocol::Network::WebSocketRequest::create()
          .setHeaders(BuildObjectForHeaders(headers))
          .build();
  GetFrontend()->webSocketWillSendHandshakeRequest(
      IdentifiersFactory::SubresourceRequestId(identifier),
      base::TimeTicks::Now().since_origin().InSecondsF(),
      base::Time::Now().InSecondsFSinceUnixEpoch(), std::move(request_object));
}

void InspectorNetworkAgent::DidReceiveWebSocketHandshakeResponse(
    ExecutionContext*,
    uint64_t identifier,
    network::mojom::blink::WebSocketHandshakeRequest* request,
    network::mojom::blink::WebSocketHandshakeResponse* response) {
  DCHECK(response);

  HTTPHeaderMap response_headers;
  for (auto& header : response->headers) {
    HTTPHeaderMap::AddResult add_result = response_headers.Add(
        AtomicString(header->name), AtomicString(header->value));
    if (!add_result.is_new_entry) {
      // Protocol expects the "\n" separated format.
      add_result.stored_value->value =
          add_result.stored_value->value + "\n" + header->value;
    }
  }

  std::unique_ptr<protocol::Network::WebSocketResponse> response_object =
      protocol::Network::WebSocketResponse::create()
          .setStatus(response->status_code)
          .setStatusText(response->status_text)
          .setHeaders(BuildObjectForHeaders(response_headers))
          .build();
  if (!response->headers_text.empty())
    response_object->setHeadersText(response->headers_text);

  if (request) {
    HTTPHeaderMap request_headers;
    for (auto& header : request->headers) {
      request_headers.Add(AtomicString(header->name),
                          AtomicString(header->value));
    }
    response_object->setRequestHeaders(BuildObjectForHeaders(request_headers));
    if (!request->headers_text.empty())
      response_object->setRequestHeadersText(request->headers_text);
  }

  GetFrontend()->webSocketHandshakeResponseReceived(
      IdentifiersFactory::SubresourceRequestId(identifier),
      base::TimeTicks::Now().since_origin().InSecondsF(),
      std::move(response_object));
}

void InspectorNetworkAgent::DidCloseWebSocket(ExecutionContext*,
                                              uint64_t identifier) {
  GetFrontend()->webSocketClosed(
      IdentifiersFactory::SubresourceRequestId(identifier),
      base::TimeTicks::Now().since_origin().InSecondsF());
}

void InspectorNetworkAgent::DidReceiveWebSocketMessage(
    uint64_t identifier,
    int op_code,
    bool masked,
    const Vector<base::span<const char>>& data) {
  size_t size = 0;
  for (const auto& span : data) {
    size += span.size();
  }
  Vector<char> flatten;
  flatten.reserve(base::checked_cast<wtf_size_t>(size));
  for (const auto& span : data) {
    flatten.AppendSpan(span);
  }
  GetFrontend()->webSocketFrameReceived(
      IdentifiersFactory::SubresourceRequestId(identifier),
      base::TimeTicks::Now().since_origin().InSecondsF(),
      WebSocketMessageToProtocol(op_code, masked, flatten));
}

void InspectorNetworkAgent::DidSendWebSocketMessage(
    uint64_t identifier,
    int op_code,
    bool masked,
    base::span<const char> payload) {
  GetFrontend()->webSocketFrameSent(
      IdentifiersFactory::SubresourceRequestId(identifier),
      base::TimeTicks::Now().since_origin().InSecondsF(),
      WebSocketMessageToProtocol(op_code, masked, payload));
}

void InspectorNetworkAgent::DidReceiveWebSocketMessageError(
    uint64_t identifier,
    const String& error_message) {
  GetFrontend()->webSocketFrameError(
      IdentifiersFactory::SubresourceRequestId(identifier),
      base::TimeTicks::Now().since_origin().InSecondsF(), error_message);
}

void InspectorNetworkAgent::WebTransportCreated(
    ExecutionContext* execution_context,
    uint64_t transport_id,
    const KURL& request_url) {
  std::unique_ptr<v8_inspector::protocol::Runtime::API::StackTrace>
      current_stack_trace =
          CaptureSourceLocation(execution_context)->BuildInspectorObject();
  if (!current_stack_trace) {
    GetFrontend()->webTransportCreated(
        IdentifiersFactory::SubresourceRequestId(transport_id),
        UrlWithoutFragment(request_url).GetString(),
        base::TimeTicks::Now().since_origin().InSecondsF());
    return;
  }

  std::unique_ptr<protocol::Network::Initiator> initiator_object =
      protocol::Network::Initiator::create()
          .setType(protocol::Network::Initiator::TypeEnum::Script)
          .build();
  initiator_object->setStack(std::move(current_stack_trace));
  GetFrontend()->webTransportCreated(
      IdentifiersFactory::SubresourceRequestId(transport_id),
      UrlWithoutFragment(request_url).GetString(),
      base::TimeTicks::Now().since_origin().InSecondsF(),
      std::move(initiator_object));
}

void InspectorNetworkAgent::WebTransportConnectionEstablished(
    uint64_t transport_id) {
  GetFrontend()->webTransportConnectionEstablished(
      IdentifiersFactory::SubresourceRequestId(transport_id),
      base::TimeTicks::Now().since_origin().InSecondsF());
}

void InspectorNetworkAgent::WebTransportClosed(uint64_t transport_id) {
  GetFrontend()->webTransportClosed(
      IdentifiersFactory::SubresourceRequestId(transport_id),
      base::TimeTicks::Now().since_origin().InSecondsF());
}

protocol::Response InspectorNetworkAgent::enable(
    Maybe<int> total_buffer_size,
    Maybe<int> resource_buffer_size,
    Maybe<int> max_post_data_size) {
  total_buffer_size_.Set(total_buffer_size.value_or(kDefaultTotalBufferSize));
  resource_buffer_size_.Set(
      resource_buffer_size.value_or(kDefaultResourceBufferSize));
  max_post_data_size_.Set(max_post_data_size.value_or(0));
  Enable();
  return protocol::Response::Success();
}

void InspectorNetworkAgent::Enable() {
  if (!GetFrontend())
    return;
  enabled_.Set(true);
  resources_data_->SetResourcesDataSizeLimits(total_buffer_size_.Get(),
                                              resource_buffer_size_.Get());
  instrumenting_agents_->AddInspectorNetworkAgent(this);
}

protocol::Response InspectorNetworkAgent::disable() {
  DCHECK(!pending_request_type_);
  if (IsMainThread())
    GetNetworkStateNotifier().ClearOverride();
  instrumenting_agents_->RemoveInspectorNetworkAgent(this);
  agent_state_.ClearAllFields();
  resources_data_->Clear();
  streaming_request_ids_.clear();
  clearAcceptedEncodingsOverride();
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::setExtraHTTPHeaders(
    std::unique_ptr<protocol::Network::Headers> headers) {
  extra_request_headers_.Clear();
  std::unique_ptr<protocol::DictionaryValue> in = headers->toValue();
  for (size_t i = 0; i < in->size(); ++i) {
    const auto& entry = in->at(i);
    String value;
    if (entry.second && entry.second->asString(&value))
      extra_request_headers_.Set(entry.first, value);
  }
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::setAttachDebugStack(bool enabled) {
  if (enabled && !enabled_.Get())
    return protocol::Response::InvalidParams("Domain must be enabled");
  attach_debug_stack_enabled_.Set(enabled);
  return protocol::Response::Success();
}

bool InspectorNetworkAgent::CanGetResponseBodyBlob(const String& request_id) {
  NetworkResourcesData::ResourceData const* resource_data =
      resources_data_->Data(request_id);
  BlobDataHandle* blob =
      resource_data ? resource_data->DownloadedFileBlob() : nullptr;
  if (!blob)
    return false;
  if (worker_or_worklet_global_scope_) {
    return true;
  }
  LocalFrame* frame = IdentifiersFactory::FrameById(inspected_frames_,
                                                    resource_data->FrameId());
  return frame && frame->GetDocument();
}

void InspectorNetworkAgent::GetResponseBodyBlob(
    const String& request_id,
    std::unique_ptr<GetResponseBodyCallback> callback) {
  NetworkResourcesData::ResourceData const* resource_data =
      resources_data_->Data(request_id);
  BlobDataHandle* blob = resource_data->DownloadedFileBlob();
  ExecutionContext* context = GetTargetExecutionContext();
  if (!context) {
    callback->sendFailure(protocol::Response::InternalError());
    return;
  }
  InspectorFileReaderLoaderClient* client =
      MakeGarbageCollected<InspectorFileReaderLoaderClient>(
          blob, context->GetTaskRunner(TaskType::kFileReading),
          WTF::BindOnce(
              ResponseBodyFileReaderLoaderDone, resource_data->MimeType(),
              resource_data->TextEncodingName(), std::move(callback)));
  client->Start();
}

void InspectorNetworkAgent::getResponseBody(
    const String& request_id,
    std::unique_ptr<GetResponseBodyCallback> callback) {
  if (CanGetResponseBodyBlob(request_id)) {
    GetResponseBodyBlob(request_id, std::move(callback));
    return;
  }

  String content;
  bool base64_encoded;
  protocol::Response response =
      GetResponseBody(request_id, &content, &base64_encoded);
  if (response.IsSuccess()) {
    callback->sendSuccess(content, base64_encoded);
  } else {
    callback->sendFailure(response);
  }
}

protocol::Response InspectorNetworkAgent::setBlockedURLs(
    std::unique_ptr<protocol::Array<String>> urls) {
  blocked_urls_.Clear();
  for (const String& url : *urls)
    blocked_urls_.Set(url, true);
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::replayXHR(const String& request_id) {
  String actual_request_id = request_id;

  XHRReplayData* xhr_replay_data = resources_data_->XhrReplayData(request_id);
  auto* data = resources_data_->Data(request_id);
  if (!xhr_replay_data || !data) {
    return protocol::Response::ServerError(
        "Given id does not correspond to XHR");
  }

  ExecutionContext* execution_context = xhr_replay_data->GetExecutionContext();
  if (!execution_context || execution_context->IsContextDestroyed()) {
    resources_data_->SetXHRReplayData(request_id, nullptr);
    return protocol::Response::ServerError("Document is already detached");
  }

  XMLHttpRequest* xhr = XMLHttpRequest::Create(execution_context);

  execution_context->RemoveURLFromMemoryCache(xhr_replay_data->Url());

  xhr->open(xhr_replay_data->Method(), xhr_replay_data->Url(),
            xhr_replay_data->Async(), IGNORE_EXCEPTION_FOR_TESTING);
  if (xhr_replay_data->IncludeCredentials())
    xhr->setWithCredentials(true, IGNORE_EXCEPTION_FOR_TESTING);
  for (const auto& header : xhr_replay_data->Headers()) {
    xhr->setRequestHeader(header.key, header.value,
                          IGNORE_EXCEPTION_FOR_TESTING);
  }
  xhr->SendForInspectorXHRReplay(data ? data->PostData() : nullptr,
                                 IGNORE_EXCEPTION_FOR_TESTING);

  replay_xhrs_.insert(xhr);
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::canClearBrowserCache(bool* result) {
  *result = true;
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::canClearBrowserCookies(bool* result) {
  *result = true;
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::setAcceptedEncodings(
    std::unique_ptr<protocol::Array<protocol::Network::ContentEncoding>>
        encodings) {
  HashSet<String> accepted_encodings;
  for (const protocol::Network::ContentEncoding& encoding : *encodings) {
    String value = AcceptedEncodingFromProtocol(encoding);
    if (value.IsNull()) {
      return protocol::Response::InvalidParams("Unknown encoding type: " +
                                               encoding.Utf8());
    }
    accepted_encodings.insert(value);
  }
  // If invoked with an empty list, it means none of the encodings should be
  // accepted. See InspectorNetworkAgent::PrepareRequest.
  if (accepted_encodings.empty())
    accepted_encodings.insert("none");

  // Set the inspector state.
  accepted_encodings_.Clear();
  for (auto encoding : accepted_encodings)
    accepted_encodings_.Set(encoding, true);

  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::clearAcceptedEncodingsOverride() {
  accepted_encodings_.Clear();
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::emulateNetworkConditions(
    bool offline,
    double latency,
    double download_throughput,
    double upload_throughput,
    Maybe<String> connection_type,
    Maybe<double> packet_loss,
    Maybe<int> packet_queue_length,
    Maybe<bool> packet_reordering) {
  WebConnectionType type = kWebConnectionTypeUnknown;
  if (connection_type.has_value()) {
    type = ToWebConnectionType(connection_type.value());
    if (type == kWebConnectionTypeUnknown)
      return protocol::Response::ServerError("Unknown connection type");
  }

  if (worker_or_worklet_global_scope_) {
    if (worker_or_worklet_global_scope_->IsServiceWorkerGlobalScope() ||
        worker_or_worklet_global_scope_->IsSharedWorkerGlobalScope()) {
      // In service workers and shared workers, we don't inspect the main thread
      // so we must post a task there to make it possible to use
      // NetworkStateNotifier.
      PostCrossThreadTask(
          *Thread::MainThread()->GetTaskRunner(
              MainThreadTaskRunnerRestricted()),
          FROM_HERE,
          CrossThreadBindOnce(SetNetworkStateOverride, offline, latency,
                              download_throughput, upload_throughput, type));
      return protocol::Response::Success();
    }
    return protocol::Response::ServerError("Not supported");
  }

  SetNetworkStateOverride(offline, latency, download_throughput,
                          upload_throughput, type);

  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::setCacheDisabled(
    bool cache_disabled) {
  // TODO(ananta)
  // We should extract network cache state into a global entity which can be
  // queried from FrameLoader and other places.
  cache_disabled_.Set(cache_disabled);
  if (cache_disabled && IsMainThread())
    MemoryCache::Get()->EvictResources();
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::setBypassServiceWorker(bool bypass) {
  bypass_service_worker_.Set(bypass);
  return protocol::Response::Success();
}

protocol::Response InspectorNetworkAgent::getCertificate(
    const String& origin,
    std::unique_ptr<protocol::Array<String>>* certificate) {
  *certificate = std::make_unique<protocol::Array<String>>();
  scoped_refptr<const SecurityOrigin> security_origin =
      SecurityOrigin::CreateFromString(origin);
  for (auto& resource : resources_data_->Resources()) {
    scoped_refptr<const SecurityOrigin> resource_origin =
        SecurityOrigin::Create(resource->RequestedURL());
    net::X509Certificate* cert = resource->Certificate();
    if (resource_origin->IsSameOriginWith(security_origin.get()) && cert) {
      (*certificate)
          ->push_back(Base64Encode(
              net::x509_util::CryptoBufferAsSpan(cert->cert_buffer())));
      for (const auto& buf : cert->intermediate_buffers()) {
        (*certificate)
            ->push_back(
                Base64Encode(net::x509_util::CryptoBufferAsSpan(buf.get())));
      }
      return protocol::Response::Success();
    }
  }
  return protocol::Response::Success();
}

void InspectorNetworkAgent::DidCommitLoad(LocalFrame* frame,
                                          DocumentLoader* loader) {
  DCHECK(IsMainThread());
  if (loader->GetFrame() != inspected_frames_->Root())
    return;

  if (cache_disabled_.Get())
    MemoryCache::Get()->EvictResources();

  resources_data_->Clear(IdentifiersFactory::LoaderId(loader));
}

void InspectorNetworkAgent::FrameScheduledNavigation(LocalFrame* frame,
                                                     const KURL&,
                                                     base::TimeDelta,
                                                     ClientNavigationReason) {
  // For navigations, we limit async stack trace to depth 1 to avoid the
  // base::Value depth limits with Mojo serialization / parsing.
  // See http://crbug.com/809996.
  frame_navigation_initiator_map_.Set(
      IdentifiersFactory::FrameId(frame),
      BuildInitiatorObject(frame->GetDocument(), FetchInitiatorInfo(),
                           /*max_async_depth=*/1));
}

void InspectorNetworkAgent::FrameClearedScheduledNavigation(LocalFrame* frame) {
  frame_navigation_initiator_map_.erase(IdentifiersFactory::FrameId(frame));
}

protocol::Response InspectorNetworkAgent::GetResponseBody(
    const String& request_id,
    String* content,
    bool* base64_encoded) {
  NetworkResourcesData::ResourceData const* resource_data =
      resources_data_->Data(request_id);
  if (!resource_data) {
    return protocol::Response::ServerError(
        "No resource with given identifier found");
  }

  if (resource_data->HasContent()) {
    *content = resource_data->Content();
    *base64_encoded = resource_data->Base64Encoded();
    return protocol::Response::Success();
  }

  if (resource_data->IsContentEvicted()) {
    return protocol::Response::ServerError(
        "Request content was evicted from inspector cache");
  }

  if (resource_data->CachedResource() &&
      InspectorPageAgent::CachedResourceContent(resource_data->CachedResource(),
                                                content, base64_encoded)) {
    return protocol::Response::Success();
  }

  return protocol::Response::ServerError(
      "No data found for resource with given identifier");
}

protocol::Response InspectorNetworkAgent::searchInResponseBody(
    const String& request_id,
    const String& query,
    Maybe<bool> case_sensitive,
    Maybe<bool> is_regex,
    std::unique_ptr<
        protocol::Array<v8_inspector::protocol::Debugger::API::SearchMatch>>*
        matches) {
  String content;
  bool base64_encoded;
  protocol::Response response =
      GetResponseBody(request_id, &content, &base64_encoded);
```
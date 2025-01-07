Response: The user wants to understand the functionality of the C++ code provided in `dispatch.cc`. I need to break down the code into logical parts and explain what each part does. Since the user also asked about its relation to JavaScript, I should look for concepts or functionalities within the C++ code that map to interactions or concepts in a typical JavaScript environment, especially in the context of debugging or browser interaction.

Here's a plan:

1. **Explain `DispatchResponse`:** Describe the purpose of this struct and the different static methods for creating error or success responses.
2. **Explain `Dispatchable`:** Describe how it parses CBOR-encoded messages and extracts information like `id`, `method`, and `params`. Highlight the error handling during parsing.
3. **Explain the helper functions for creating responses and notifications:** Describe `CreateErrorResponse`, `CreateResponse`, and `CreateNotification`, and how they serialize data.
4. **Explain `DomainDispatcher`:** Describe its role in handling commands within a specific domain and managing communication with the frontend.
5. **Explain `UberDispatcher`:** Describe its role in routing commands to the correct `DomainDispatcher` based on the domain.
6. **Relate to JavaScript:** Explain how these C++ components might be involved in the communication between the browser's DevTools frontend (written in JavaScript) and the V8 engine. Use a JavaScript example to illustrate a potential scenario.
这个C++源代码文件 `dispatch.cc` 的主要功能是 **处理和分发 Chrome DevTools Protocol (CDP) 消息**。 它定义了用于表示消息、错误状态、以及执行消息路由的关键类和数据结构。  该文件位于 V8 引擎的 `third_party/inspector_protocol/crdtp` 目录下，表明它与 V8 的调试和检查功能密切相关。

以下是其主要功能的归纳：

**1. `DispatchResponse`**:  定义了表示消息处理结果的状态码和错误信息的类。它提供了一组静态方法用于创建不同类型的响应，例如：
    * `Success()`: 表示操作成功。
    * `FallThrough()`: 表示当前处理器无法处理该消息，需要传递给下一个处理器。
    * `ParseError()`, `InvalidRequest()`, `MethodNotFound()`, `InvalidParams()`, `InternalError()`, `ServerError()`, `SessionNotFound()`: 表示不同类型的错误。

**2. `Dispatchable`**:  实现了一个浅层解析器，用于解析 CBOR (Concise Binary Object Representation) 编码的 DevTools 消息。 它的主要职责是：
    * 接收 CBOR 格式的字节流。
    * 验证消息是否为有效的 CBOR 对象。
    * 提取消息中的关键属性，例如 `id` (请求 ID), `method` (调用的方法名), `params` (方法参数), 和 `sessionId` (会话 ID)。
    * 检查消息是否包含必要的属性（例如 `id` 和 `method`）。
    * 如果解析过程中发生错误，则记录错误状态。
    * 提供 `DispatchError()` 方法，根据解析状态返回相应的 `DispatchResponse`。

**3. 创建协议响应和通知的辅助函数**: 提供了一些方便的函数，用于创建符合 CDP 协议规范的响应和通知消息：
    * `CreateErrorResponse()`: 创建一个包含错误信息的响应消息。
    * `CreateResponse()`: 创建一个包含处理结果的成功响应消息。
    * `CreateNotification()`: 创建一个单向的通知消息。
    这些函数负责将数据序列化为 CBOR 格式。

**4. `DomainDispatcher`**: 负责在一个特定的 **域 (Domain)** 内分发消息。 在 CDP 中，不同的功能被组织到不同的域下，例如 `Debugger`, `Runtime`, `Network` 等。 `DomainDispatcher` 的主要职责是：
    * 接收属于其域的消息。
    * 根据消息的 `method` 找到相应的处理函数。
    * 调用处理函数来处理消息。
    * 管理与前端 (DevTools) 的通信通道 (`FrontendChannel`)，用于发送响应和通知。
    * 提供 `weakPtr()` 方法来管理弱引用，防止内存泄漏。

**5. `UberDispatcher`**: 充当一个顶层的消息分发器，负责将消息路由到正确的 `DomainDispatcher`。它的主要职责是：
    * 接收所有传入的 CDP 消息。
    * 解析消息的 `method` 属性，确定消息所属的域。
    * 根据域将消息转发给相应的 `DomainDispatcher`。
    * 如果找不到对应的域或方法，则发送 "MethodNotFound" 错误响应。
    * 使用 `WireBackend()` 方法将 `DomainDispatcher` 注册到 `UberDispatcher` 中。

**它与 JavaScript 的关系**

`dispatch.cc` 中定义的类和功能是 V8 引擎处理来自 Chrome DevTools 前端 (用 JavaScript 编写) 的请求的核心部分。  DevTools 前端通过 WebSocket 连接向 V8 发送符合 CDP 协议的消息，这些消息通常用于调试、性能分析等。

**JavaScript 示例：**

假设在 DevTools 的 JavaScript 代码中，用户点击了一个按钮来设置断点。 这会触发一个发送到 V8 的 CDP 消息，如下所示 (以 JSON 格式表示，实际传输时通常是 CBOR)：

```javascript
{
  "id": 123,
  "method": "Debugger.setBreakpointByUrl",
  "params": {
    "lineNumber": 10,
    "urlRegex": ".*myfile.js"
  }
}
```

**在 C++ 代码中的处理流程：**

1. **接收消息**:  V8 引擎接收到这个 CBOR 编码的消息。
2. **`Dispatchable` 解析**: `Dispatchable` 类会将这个 CBOR 消息解析，提取出 `id` (123), `method` ("Debugger.setBreakpointByUrl"), 和 `params` (包含 `lineNumber` 和 `urlRegex` 的对象)。
3. **`UberDispatcher` 路由**: `UberDispatcher` 接收到解析后的消息。它会根据 `method` 中的 "Debugger" 部分，将消息路由到负责 "Debugger" 域的 `DomainDispatcher` 实例。
4. **`DomainDispatcher` 分发**:  "Debugger" 域的 `DomainDispatcher` 接收到消息。它会根据 `method` 的剩余部分 "setBreakpointByUrl"，找到相应的 C++ 处理函数。
5. **执行处理函数**:  这个处理函数会调用 V8 引擎的调试器 API 来设置断点。
6. **发送响应**:  处理完成后，C++ 代码会使用 `CreateResponse()` 创建一个包含结果的 CDP 响应消息，并将其发送回 DevTools 前端。  如果发生错误，则会使用 `CreateErrorResponse()` 发送错误响应。  例如，成功设置断点的响应可能如下所示：

```javascript
{
  "id": 123,
  "result": {
    "breakpointId": "some_unique_id",
    "locations": [...]
  }
}
```

**总结:**

`dispatch.cc` 中的代码是 V8 引擎中处理 DevTools 协议消息的关键基础设施。 它负责解析消息、将其路由到正确的处理程序，并生成响应。 这使得 JavaScript 编写的 DevTools 前端能够与 V8 引擎进行有效的通信和交互，实现调试、性能分析等功能。

Prompt: 
```
这是目录为v8/third_party/inspector_protocol/crdtp/dispatch.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dispatch.h"

#include <cassert>
#include "cbor.h"
#include "error_support.h"
#include "find_by_first.h"
#include "frontend_channel.h"
#include "protocol_core.h"

namespace v8_crdtp {
// =============================================================================
// DispatchResponse - Error status and chaining / fall through
// =============================================================================

// static
DispatchResponse DispatchResponse::Success() {
  DispatchResponse result;
  result.code_ = DispatchCode::SUCCESS;
  return result;
}

// static
DispatchResponse DispatchResponse::FallThrough() {
  DispatchResponse result;
  result.code_ = DispatchCode::FALL_THROUGH;
  return result;
}

// static
DispatchResponse DispatchResponse::ParseError(std::string message) {
  DispatchResponse result;
  result.code_ = DispatchCode::PARSE_ERROR;
  result.message_ = std::move(message);
  return result;
}

// static
DispatchResponse DispatchResponse::InvalidRequest(std::string message) {
  DispatchResponse result;
  result.code_ = DispatchCode::INVALID_REQUEST;
  result.message_ = std::move(message);
  return result;
}

// static
DispatchResponse DispatchResponse::MethodNotFound(std::string message) {
  DispatchResponse result;
  result.code_ = DispatchCode::METHOD_NOT_FOUND;
  result.message_ = std::move(message);
  return result;
}

// static
DispatchResponse DispatchResponse::InvalidParams(std::string message) {
  DispatchResponse result;
  result.code_ = DispatchCode::INVALID_PARAMS;
  result.message_ = std::move(message);
  return result;
}

// static
DispatchResponse DispatchResponse::InternalError() {
  DispatchResponse result;
  result.code_ = DispatchCode::INTERNAL_ERROR;
  result.message_ = "Internal error";
  return result;
}

// static
DispatchResponse DispatchResponse::ServerError(std::string message) {
  DispatchResponse result;
  result.code_ = DispatchCode::SERVER_ERROR;
  result.message_ = std::move(message);
  return result;
}

// static
DispatchResponse DispatchResponse::SessionNotFound(std::string message) {
  DispatchResponse result;
  result.code_ = DispatchCode::SESSION_NOT_FOUND;
  result.message_ = std::move(message);
  return result;
}

// =============================================================================
// Dispatchable - a shallow parser for CBOR encoded DevTools messages
// =============================================================================
Dispatchable::Dispatchable(span<uint8_t> serialized) : serialized_(serialized) {
  Status s = cbor::CheckCBORMessage(serialized);
  if (!s.ok()) {
    status_ = {Error::MESSAGE_MUST_BE_AN_OBJECT, s.pos};
    return;
  }
  cbor::CBORTokenizer tokenizer(serialized);
  if (tokenizer.TokenTag() == cbor::CBORTokenTag::ERROR_VALUE) {
    status_ = tokenizer.Status();
    return;
  }

  // We checked for the envelope start byte above, so the tokenizer
  // must agree here, since it's not an error.
  assert(tokenizer.TokenTag() == cbor::CBORTokenTag::ENVELOPE);

  // Before we enter the envelope, we save the position that we
  // expect to see after we're done parsing the envelope contents.
  // This way we can compare and produce an error if the contents
  // didn't fit exactly into the envelope length.
  const size_t pos_past_envelope =
      tokenizer.Status().pos + tokenizer.GetEnvelopeHeader().outer_size();
  tokenizer.EnterEnvelope();
  if (tokenizer.TokenTag() == cbor::CBORTokenTag::ERROR_VALUE) {
    status_ = tokenizer.Status();
    return;
  }
  if (tokenizer.TokenTag() != cbor::CBORTokenTag::MAP_START) {
    status_ = {Error::MESSAGE_MUST_BE_AN_OBJECT, tokenizer.Status().pos};
    return;
  }
  assert(tokenizer.TokenTag() == cbor::CBORTokenTag::MAP_START);
  tokenizer.Next();  // Now we should be pointed at the map key.
  while (tokenizer.TokenTag() != cbor::CBORTokenTag::STOP) {
    switch (tokenizer.TokenTag()) {
      case cbor::CBORTokenTag::DONE:
        status_ =
            Status{Error::CBOR_UNEXPECTED_EOF_IN_MAP, tokenizer.Status().pos};
        return;
      case cbor::CBORTokenTag::ERROR_VALUE:
        status_ = tokenizer.Status();
        return;
      case cbor::CBORTokenTag::STRING8:
        if (!MaybeParseProperty(&tokenizer))
          return;
        break;
      default:
        // We require the top-level keys to be UTF8 (US-ASCII in practice).
        status_ = Status{Error::CBOR_INVALID_MAP_KEY, tokenizer.Status().pos};
        return;
    }
  }
  tokenizer.Next();
  if (!has_call_id_) {
    status_ = Status{Error::MESSAGE_MUST_HAVE_INTEGER_ID_PROPERTY,
                     tokenizer.Status().pos};
    return;
  }
  if (method_.empty()) {
    status_ = Status{Error::MESSAGE_MUST_HAVE_STRING_METHOD_PROPERTY,
                     tokenizer.Status().pos};
    return;
  }
  // The contents of the envelope parsed OK, now check that we're at
  // the expected position.
  if (pos_past_envelope != tokenizer.Status().pos) {
    status_ = Status{Error::CBOR_ENVELOPE_CONTENTS_LENGTH_MISMATCH,
                     tokenizer.Status().pos};
    return;
  }
  if (tokenizer.TokenTag() != cbor::CBORTokenTag::DONE) {
    status_ = Status{Error::CBOR_TRAILING_JUNK, tokenizer.Status().pos};
    return;
  }
}

bool Dispatchable::ok() const {
  return status_.ok();
}

DispatchResponse Dispatchable::DispatchError() const {
  // TODO(johannes): Replace with DCHECK / similar?
  if (status_.ok())
    return DispatchResponse::Success();

  if (status_.IsMessageError())
    return DispatchResponse::InvalidRequest(status_.Message());
  return DispatchResponse::ParseError(status_.ToASCIIString());
}

bool Dispatchable::MaybeParseProperty(cbor::CBORTokenizer* tokenizer) {
  span<uint8_t> property_name = tokenizer->GetString8();
  if (SpanEquals(SpanFrom("id"), property_name))
    return MaybeParseCallId(tokenizer);
  if (SpanEquals(SpanFrom("method"), property_name))
    return MaybeParseMethod(tokenizer);
  if (SpanEquals(SpanFrom("params"), property_name))
    return MaybeParseParams(tokenizer);
  if (SpanEquals(SpanFrom("sessionId"), property_name))
    return MaybeParseSessionId(tokenizer);
  status_ =
      Status{Error::MESSAGE_HAS_UNKNOWN_PROPERTY, tokenizer->Status().pos};
  return false;
}

bool Dispatchable::MaybeParseCallId(cbor::CBORTokenizer* tokenizer) {
  if (has_call_id_) {
    status_ = Status{Error::CBOR_DUPLICATE_MAP_KEY, tokenizer->Status().pos};
    return false;
  }
  tokenizer->Next();
  if (tokenizer->TokenTag() != cbor::CBORTokenTag::INT32) {
    status_ = Status{Error::MESSAGE_MUST_HAVE_INTEGER_ID_PROPERTY,
                     tokenizer->Status().pos};
    return false;
  }
  call_id_ = tokenizer->GetInt32();
  has_call_id_ = true;
  tokenizer->Next();
  return true;
}

bool Dispatchable::MaybeParseMethod(cbor::CBORTokenizer* tokenizer) {
  if (!method_.empty()) {
    status_ = Status{Error::CBOR_DUPLICATE_MAP_KEY, tokenizer->Status().pos};
    return false;
  }
  tokenizer->Next();
  if (tokenizer->TokenTag() != cbor::CBORTokenTag::STRING8) {
    status_ = Status{Error::MESSAGE_MUST_HAVE_STRING_METHOD_PROPERTY,
                     tokenizer->Status().pos};
    return false;
  }
  method_ = tokenizer->GetString8();
  tokenizer->Next();
  return true;
}

bool Dispatchable::MaybeParseParams(cbor::CBORTokenizer* tokenizer) {
  if (params_seen_) {
    status_ = Status{Error::CBOR_DUPLICATE_MAP_KEY, tokenizer->Status().pos};
    return false;
  }
  params_seen_ = true;
  tokenizer->Next();
  if (tokenizer->TokenTag() == cbor::CBORTokenTag::NULL_VALUE) {
    tokenizer->Next();
    return true;
  }
  if (tokenizer->TokenTag() != cbor::CBORTokenTag::ENVELOPE) {
    status_ = Status{Error::MESSAGE_MAY_HAVE_OBJECT_PARAMS_PROPERTY,
                     tokenizer->Status().pos};
    return false;
  }
  params_ = tokenizer->GetEnvelope();
  tokenizer->Next();
  return true;
}

bool Dispatchable::MaybeParseSessionId(cbor::CBORTokenizer* tokenizer) {
  if (!session_id_.empty()) {
    status_ = Status{Error::CBOR_DUPLICATE_MAP_KEY, tokenizer->Status().pos};
    return false;
  }
  tokenizer->Next();
  if (tokenizer->TokenTag() != cbor::CBORTokenTag::STRING8) {
    status_ = Status{Error::MESSAGE_MAY_HAVE_STRING_SESSION_ID_PROPERTY,
                     tokenizer->Status().pos};
    return false;
  }
  session_id_ = tokenizer->GetString8();
  tokenizer->Next();
  return true;
}

namespace {
class ProtocolError : public Serializable {
 public:
  explicit ProtocolError(DispatchResponse dispatch_response)
      : dispatch_response_(std::move(dispatch_response)) {}

  void AppendSerialized(std::vector<uint8_t>* out) const override {
    Status status;
    std::unique_ptr<ParserHandler> encoder = cbor::NewCBOREncoder(out, &status);
    encoder->HandleMapBegin();
    if (has_call_id_) {
      encoder->HandleString8(SpanFrom("id"));
      encoder->HandleInt32(call_id_);
    }
    encoder->HandleString8(SpanFrom("error"));
    encoder->HandleMapBegin();
    encoder->HandleString8(SpanFrom("code"));
    encoder->HandleInt32(static_cast<int32_t>(dispatch_response_.Code()));
    encoder->HandleString8(SpanFrom("message"));
    encoder->HandleString8(SpanFrom(dispatch_response_.Message()));
    if (!data_.empty()) {
      encoder->HandleString8(SpanFrom("data"));
      encoder->HandleString8(SpanFrom(data_));
    }
    encoder->HandleMapEnd();
    encoder->HandleMapEnd();
    assert(status.ok());
  }

  void SetCallId(int call_id) {
    has_call_id_ = true;
    call_id_ = call_id;
  }
  void SetData(std::string data) { data_ = std::move(data); }

 private:
  const DispatchResponse dispatch_response_;
  std::string data_;
  int call_id_ = 0;
  bool has_call_id_ = false;
};
}  // namespace

// =============================================================================
// Helpers for creating protocol cresponses and notifications.
// =============================================================================

std::unique_ptr<Serializable> CreateErrorResponse(
    int call_id,
    DispatchResponse dispatch_response) {
  auto protocol_error =
      std::make_unique<ProtocolError>(std::move(dispatch_response));
  protocol_error->SetCallId(call_id);
  return protocol_error;
}

std::unique_ptr<Serializable> CreateErrorResponse(
    int call_id,
    DispatchResponse dispatch_response,
    const DeserializerState& state) {
  auto protocol_error =
      std::make_unique<ProtocolError>(std::move(dispatch_response));
  protocol_error->SetCallId(call_id);
  // TODO(caseq): should we plumb the call name here?
  protocol_error->SetData(state.ErrorMessage(MakeSpan("params")));
  return protocol_error;
}

std::unique_ptr<Serializable> CreateErrorNotification(
    DispatchResponse dispatch_response) {
  return std::make_unique<ProtocolError>(std::move(dispatch_response));
}

namespace {
class Response : public Serializable {
 public:
  Response(int call_id, std::unique_ptr<Serializable> params)
      : call_id_(call_id), params_(std::move(params)) {}

  void AppendSerialized(std::vector<uint8_t>* out) const override {
    Status status;
    std::unique_ptr<ParserHandler> encoder = cbor::NewCBOREncoder(out, &status);
    encoder->HandleMapBegin();
    encoder->HandleString8(SpanFrom("id"));
    encoder->HandleInt32(call_id_);
    encoder->HandleString8(SpanFrom("result"));
    if (params_) {
      params_->AppendSerialized(out);
    } else {
      encoder->HandleMapBegin();
      encoder->HandleMapEnd();
    }
    encoder->HandleMapEnd();
    assert(status.ok());
  }

 private:
  const int call_id_;
  std::unique_ptr<Serializable> params_;
};

class Notification : public Serializable {
 public:
  Notification(const char* method, std::unique_ptr<Serializable> params)
      : method_(method), params_(std::move(params)) {}

  void AppendSerialized(std::vector<uint8_t>* out) const override {
    Status status;
    std::unique_ptr<ParserHandler> encoder = cbor::NewCBOREncoder(out, &status);
    encoder->HandleMapBegin();
    encoder->HandleString8(SpanFrom("method"));
    encoder->HandleString8(SpanFrom(method_));
    encoder->HandleString8(SpanFrom("params"));
    if (params_) {
      params_->AppendSerialized(out);
    } else {
      encoder->HandleMapBegin();
      encoder->HandleMapEnd();
    }
    encoder->HandleMapEnd();
    assert(status.ok());
  }

 private:
  const char* method_;
  std::unique_ptr<Serializable> params_;
};
}  // namespace

std::unique_ptr<Serializable> CreateResponse(
    int call_id,
    std::unique_ptr<Serializable> params) {
  return std::make_unique<Response>(call_id, std::move(params));
}

std::unique_ptr<Serializable> CreateNotification(
    const char* method,
    std::unique_ptr<Serializable> params) {
  return std::make_unique<Notification>(method, std::move(params));
}

// =============================================================================
// DomainDispatcher - Dispatching betwen protocol methods within a domain.
// =============================================================================
DomainDispatcher::WeakPtr::WeakPtr(DomainDispatcher* dispatcher)
    : dispatcher_(dispatcher) {}

DomainDispatcher::WeakPtr::~WeakPtr() {
  if (dispatcher_)
    dispatcher_->weak_ptrs_.erase(this);
}

DomainDispatcher::Callback::~Callback() = default;

void DomainDispatcher::Callback::dispose() {
  backend_impl_ = nullptr;
}

DomainDispatcher::Callback::Callback(
    std::unique_ptr<DomainDispatcher::WeakPtr> backend_impl,
    int call_id,
    span<uint8_t> method,
    span<uint8_t> message)
    : backend_impl_(std::move(backend_impl)),
      call_id_(call_id),
      method_(method),
      message_(message.begin(), message.end()) {}

void DomainDispatcher::Callback::sendIfActive(
    std::unique_ptr<Serializable> partialMessage,
    const DispatchResponse& response) {
  if (!backend_impl_ || !backend_impl_->get())
    return;
  backend_impl_->get()->sendResponse(call_id_, response,
                                     std::move(partialMessage));
  backend_impl_ = nullptr;
}

void DomainDispatcher::Callback::fallThroughIfActive() {
  if (!backend_impl_ || !backend_impl_->get())
    return;
  backend_impl_->get()->channel()->FallThrough(call_id_, method_,
                                               SpanFrom(message_));
  backend_impl_ = nullptr;
}

DomainDispatcher::DomainDispatcher(FrontendChannel* frontendChannel)
    : frontend_channel_(frontendChannel) {}

DomainDispatcher::~DomainDispatcher() {
  clearFrontend();
}

void DomainDispatcher::sendResponse(int call_id,
                                    const DispatchResponse& response,
                                    std::unique_ptr<Serializable> result) {
  if (!frontend_channel_)
    return;
  std::unique_ptr<Serializable> serializable;
  if (response.IsError()) {
    serializable = CreateErrorResponse(call_id, response);
  } else {
    serializable = CreateResponse(call_id, std::move(result));
  }
  frontend_channel_->SendProtocolResponse(call_id, std::move(serializable));
}

void DomainDispatcher::ReportInvalidParams(const Dispatchable& dispatchable,
                                           const DeserializerState& state) {
  assert(!state.status().ok());
  if (frontend_channel_) {
    frontend_channel_->SendProtocolResponse(
        dispatchable.CallId(),
        CreateErrorResponse(
            dispatchable.CallId(),
            DispatchResponse::InvalidParams("Invalid parameters"), state));
  }
}

void DomainDispatcher::clearFrontend() {
  frontend_channel_ = nullptr;
  for (auto& weak : weak_ptrs_)
    weak->dispose();
  weak_ptrs_.clear();
}

std::unique_ptr<DomainDispatcher::WeakPtr> DomainDispatcher::weakPtr() {
  auto weak = std::make_unique<DomainDispatcher::WeakPtr>(this);
  weak_ptrs_.insert(weak.get());
  return weak;
}

// =============================================================================
// UberDispatcher - dispatches between domains (backends).
// =============================================================================
UberDispatcher::DispatchResult::DispatchResult(bool method_found,
                                               std::function<void()> runnable)
    : method_found_(method_found), runnable_(runnable) {}

void UberDispatcher::DispatchResult::Run() {
  if (!runnable_)
    return;
  runnable_();
  runnable_ = nullptr;
}

UberDispatcher::UberDispatcher(FrontendChannel* frontend_channel)
    : frontend_channel_(frontend_channel) {
  assert(frontend_channel);
}

UberDispatcher::~UberDispatcher() = default;

constexpr size_t kNotFound = std::numeric_limits<size_t>::max();

namespace {
size_t DotIdx(span<uint8_t> method) {
  const void* p = memchr(method.data(), '.', method.size());
  return p ? reinterpret_cast<const uint8_t*>(p) - method.data() : kNotFound;
}
}  // namespace

UberDispatcher::DispatchResult UberDispatcher::Dispatch(
    const Dispatchable& dispatchable) const {
  span<uint8_t> method = FindByFirst(redirects_, dispatchable.Method(),
                                     /*default_value=*/dispatchable.Method());
  size_t dot_idx = DotIdx(method);
  if (dot_idx != kNotFound) {
    span<uint8_t> domain = method.subspan(0, dot_idx);
    span<uint8_t> command = method.subspan(dot_idx + 1);
    DomainDispatcher* dispatcher = FindByFirst(dispatchers_, domain);
    if (dispatcher) {
      std::function<void(const Dispatchable&)> dispatched =
          dispatcher->Dispatch(command);
      if (dispatched) {
        return DispatchResult(
            true, [dispatchable, dispatched = std::move(dispatched)]() {
              dispatched(dispatchable);
            });
      }
    }
  }
  return DispatchResult(false, [this, dispatchable]() {
    frontend_channel_->SendProtocolResponse(
        dispatchable.CallId(),
        CreateErrorResponse(dispatchable.CallId(),
                            DispatchResponse::MethodNotFound(
                                "'" +
                                std::string(dispatchable.Method().begin(),
                                            dispatchable.Method().end()) +
                                "' wasn't found")));
  });
}

template <typename T>
struct FirstLessThan {
  bool operator()(const std::pair<span<uint8_t>, T>& left,
                  const std::pair<span<uint8_t>, T>& right) {
    return SpanLessThan(left.first, right.first);
  }
};

void UberDispatcher::WireBackend(
    span<uint8_t> domain,
    const std::vector<std::pair<span<uint8_t>, span<uint8_t>>>&
        sorted_redirects,
    std::unique_ptr<DomainDispatcher> dispatcher) {
  auto it = redirects_.insert(redirects_.end(), sorted_redirects.begin(),
                              sorted_redirects.end());
  std::inplace_merge(redirects_.begin(), it, redirects_.end(),
                     FirstLessThan<span<uint8_t>>());
  auto jt = dispatchers_.insert(dispatchers_.end(),
                                std::make_pair(domain, std::move(dispatcher)));
  std::inplace_merge(dispatchers_.begin(), jt, dispatchers_.end(),
                     FirstLessThan<std::unique_ptr<DomainDispatcher>>());
}

}  // namespace v8_crdtp

"""

```
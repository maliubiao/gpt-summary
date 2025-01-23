Response:
Let's break down the thought process for analyzing the `dispatch.cc` file.

1. **Understanding the Request:** The core request is to analyze the functionality of the `dispatch.cc` file. Key points to address are: its purpose, how it relates to JavaScript (if at all), examples, code logic, and common user errors related to its functionality.

2. **Initial Skim and Keyword Identification:**  I first skimmed through the code looking for recurring keywords and patterns. I noticed:
    * `#include`:  This tells me it's C++ and depends on other modules. The included headers like `"cbor.h"`, `"error_support.h"`, `"frontend_channel.h"`, and `"protocol_core.h"` are strong indicators of its role in handling communication, likely with a debugging or instrumentation protocol (DevTools).
    * `DispatchResponse`: This struct and its static factory methods (`Success`, `FallThrough`, `ParseError`, etc.) clearly define different outcomes of a dispatching process.
    * `Dispatchable`: This class seems responsible for parsing incoming messages, likely in a binary format (CBOR). The member variables like `call_id_`, `method_`, `params_`, and `session_id_` point towards a request-response or event-based communication pattern.
    * `DomainDispatcher`: This suggests a structure for handling commands within specific "domains."
    * `UberDispatcher`:  The "Uber" prefix often indicates a central coordinator, suggesting it manages dispatching across multiple `DomainDispatcher` instances.
    * CBOR related functions: `cbor::CheckCBORMessage`, `cbor::CBORTokenizer`, `cbor::NewCBOREncoder`. This confirms the use of Concise Binary Object Representation (CBOR) for message serialization.
    * `Serializable`: This interface indicates a mechanism for converting objects into a byte stream.
    * `FrontendChannel`: This likely represents the communication channel with the "frontend" – in the context of V8, this is very likely the Chrome DevTools or a similar debugging interface.

3. **High-Level Functionality Deduction:** Based on the keywords and structure, I formed a high-level understanding: This code is responsible for taking incoming messages (likely from a debugging tool), parsing them (using CBOR), and dispatching them to the appropriate handler within V8. It also handles the creation of responses, including error responses.

4. **Relationship to JavaScript:**  The "inspector_protocol" and the mention of DevTools strongly suggest a connection to JavaScript debugging. V8, as a JavaScript engine, needs a way to communicate its internal state and allow for debugging actions. This code likely forms the lower-level communication infrastructure for the DevTools Protocol (CDP).

5. **Illustrative JavaScript Example:** To solidify the JavaScript connection, I imagined a typical DevTools scenario: setting a breakpoint. The user initiates this action in the browser's DevTools (JavaScript frontend). This action gets translated into a CDP message sent to the V8 backend. The `dispatch.cc` code would handle parsing this message and routing it to the breakpoint-handling logic within V8.

6. **Code Logic Walkthrough (Key Classes):** I focused on the core classes and their interactions:
    * **`DispatchResponse`:**  Simple enum-like structure for representing different dispatch outcomes.
    * **`Dispatchable`:**  Crucial for parsing incoming CBOR messages. I noted its error handling during parsing and its extraction of key information like `id`, `method`, and `params`. I also identified the CBOR parsing steps and the potential for errors.
    * **`DomainDispatcher`:**  Responsible for handling commands within a specific domain (e.g., "Debugger," "Runtime"). I paid attention to how it receives and processes commands and sends responses back through the `FrontendChannel`.
    * **`UberDispatcher`:** The central point for routing messages to the correct `DomainDispatcher`. The logic of splitting the method name into domain and command is key here.

7. **Assumptions, Inputs, and Outputs:** For the code logic, I created a simplified scenario: an incoming message with a specific `id`, `method`, and `params`. I then traced how `UberDispatcher` and `DomainDispatcher` would process this message and generate a response.

8. **Common User Errors:** I thought about common mistakes when *using* or *interacting with* the DevTools Protocol. These aren't errors *within* this C++ code, but rather errors developers might make when using the tools that *rely* on this code:
    * Incorrect method names in the DevTools console.
    * Providing parameters in the wrong format or of the wrong type.
    * Receiving errors and not understanding their meaning.

9. **Torque Consideration:** I addressed the specific prompt about the `.tq` extension. Since the file is `.cc`, it's C++, not Torque. I explained what Torque is and its purpose in V8.

10. **Refinement and Structuring:**  Finally, I organized the information logically, using headings and bullet points for clarity. I ensured that I addressed all the specific points in the original request. I also tried to use clear and concise language, avoiding overly technical jargon where possible.

Essentially, I followed a process of reading the code, identifying key components, understanding their relationships, inferring the overall purpose, and then providing concrete examples and explanations to illustrate the functionality. The initial focus on keywords and included headers was crucial for quickly establishing the context and purpose of the code.
The C++ source code file `v8/third_party/inspector_protocol/crdtp/dispatch.cc` plays a crucial role in the communication between the V8 JavaScript engine and debugging/instrumentation tools, primarily through the Chrome DevTools Protocol (CDP). Here's a breakdown of its functionality:

**Core Functionality:**

1. **Message Parsing and Dispatching:**
   - The primary responsibility of this file is to receive serialized DevTools Protocol messages (encoded in CBOR - Concise Binary Object Representation) and dispatch them to the appropriate handlers within V8.
   - It defines the `Dispatchable` class, which acts as a lightweight parser for these CBOR messages. `Dispatchable` extracts key information like message ID, method name, parameters, and session ID.
   - It implements the `UberDispatcher` class, which acts as a central router. The `UberDispatcher` examines the "method" field of an incoming message and forwards it to the correct `DomainDispatcher`.
   - It defines the `DomainDispatcher` class, responsible for handling messages within a specific domain of the DevTools Protocol (e.g., "Debugger", "Runtime", "Profiler").

2. **Response and Notification Handling:**
   - The code provides mechanisms for creating and sending responses to protocol requests and for sending asynchronous notifications.
   - The `DispatchResponse` class encapsulates the status of a dispatch operation (success, error, etc.). It provides static methods to create various types of responses (Success, ParseError, MethodNotFound, etc.).
   - Helper functions like `CreateErrorResponse`, `CreateResponse`, and `CreateNotification` simplify the process of creating properly formatted protocol messages.

3. **Error Handling:**
   - The code incorporates error handling during message parsing and dispatching.
   - The `Dispatchable` class checks the validity of the CBOR message format and extracts information. If errors occur during parsing (e.g., invalid CBOR, missing fields), it stores an error status.
   - The `DispatchResponse` class allows for specifying different error types and messages.

4. **Session Management (Potentially):**
   - The presence of `session_id_` in the `Dispatchable` class suggests that this code might be involved in managing different debugging sessions.

**If `v8/third_party/inspector_protocol/crdtp/dispatch.cc` ended with `.tq`:**

If the file extension were `.tq`, it would indeed be a V8 Torque source code file. Torque is V8's domain-specific language for implementing built-in functions and runtime code. In that case, the file would likely contain the *implementation* logic for handling specific DevTools Protocol commands, rather than just the dispatching mechanism.

**Relationship to JavaScript and Examples:**

This C++ code directly facilitates the interaction between JavaScript code running in V8 and developer tools. Here's how it works with JavaScript and an example:

**Scenario:** A developer sets a breakpoint in their JavaScript code using the Chrome DevTools.

1. **DevTools Action:** The developer clicks to set a breakpoint in the "Sources" panel of Chrome DevTools.
2. **Frontend Message:** The DevTools frontend (written in JavaScript/HTML/CSS) sends a DevTools Protocol message to the V8 backend. This message is typically a JSON object serialized as CBOR. An example message might look like this (in a JSON representation before CBOR encoding):

   ```json
   {
     "id": 123,
     "method": "Debugger.setBreakpointByUrl",
     "params": {
       "lineNumber": 10,
       "urlRegex": ".*my_script.js"
     }
   }
   ```

3. **C++ Processing in `dispatch.cc`:**
   - V8 receives this CBOR-encoded message.
   - The `Dispatchable` class parses the raw byte stream, extracting the `id` (123), `method` ("Debugger.setBreakpointByUrl"), and `params`.
   - The `UberDispatcher` receives the parsed `Dispatchable` object. It identifies "Debugger" as the domain and "setBreakpointByUrl" as the command.
   - The `UberDispatcher` forwards the message to the `DomainDispatcher` responsible for the "Debugger" domain.
   - The "Debugger" `DomainDispatcher` (likely in another C++ file) has a handler registered for the "setBreakpointByUrl" command. This handler receives the message parameters.
4. **V8 Execution:** The handler in the "Debugger" domain interacts with V8's internal debugger API to actually set the breakpoint at the specified location.
5. **Response:** The "Debugger" domain handler might send a response back to the DevTools, indicating success or failure. This response is created using functions like `CreateResponse` and sent back through the `FrontendChannel`. An example success response (JSON representation):

   ```json
   {
     "id": 123,
     "result": {
       "breakpointId": "some_unique_id",
       "locations": [...]
     }
   }
   ```

**JavaScript Example (Illustrative - not directly interacting with this C++):**

While JavaScript doesn't directly call functions in `dispatch.cc`, the DevTools frontend uses JavaScript to construct and send these protocol messages. For instance, the DevTools might have JavaScript code that looks something like this (simplified):

```javascript
// Inside the Chrome DevTools frontend
function setBreakpoint(urlRegex, lineNumber) {
  const message = {
    id: generateMessageId(),
    method: "Debugger.setBreakpointByUrl",
    params: {
      urlRegex: urlRegex,
      lineNumber: lineNumber
    }
  };
  sendOverWebSocket(JSON.stringify(message)); // This would be CBOR encoded in reality
}

// When the user clicks the "set breakpoint" button:
setBreakpoint(".*my_script.js", 10);
```

**Code Logic Reasoning (Hypothetical):**

**Assumption:** An incoming CBOR message with the following structure (simplified JSON representation):

```json
{
  "id": 456,
  "method": "Runtime.evaluate",
  "params": {
    "expression": "1 + 1"
  }
}
```

**Input to `Dispatchable`:** The raw CBOR-encoded bytes of the above JSON.

**Processing within `Dispatchable`:**

1. The constructor of `Dispatchable` receives the byte span.
2. It uses `cbor::CheckCBORMessage` to verify the basic CBOR structure.
3. A `cbor::CBORTokenizer` is created to iterate through the CBOR tokens.
4. It expects a top-level map.
5. It iterates through the map keys ("id", "method", "params").
6. When it encounters "id", `MaybeParseCallId` extracts the integer 456.
7. When it encounters "method", `MaybeParseMethod` extracts the string "Runtime.evaluate".
8. When it encounters "params", `MaybeParseParams` extracts the nested object.

**Output of `Dispatchable`:**  A `Dispatchable` object where:

- `call_id_` is 456.
- `method_` is a span representing "Runtime.evaluate".
- `params_` is a span representing the CBOR encoding of `{"expression": "1 + 1"}`.

**Processing within `UberDispatcher`:**

1. The `Dispatch` method receives the `Dispatchable` object.
2. It splits the `method_` ("Runtime.evaluate") into the domain "Runtime" and the command "evaluate".
3. It looks up the `DomainDispatcher` associated with the "Runtime" domain.
4. Assuming a "Runtime" `DomainDispatcher` exists and has a handler for "evaluate", it prepares to call that handler.

**Common User Programming Errors (Relating to the Protocol):**

While developers don't directly interact with this C++ code, they can make errors when interacting with the DevTools Protocol, which this code helps to process:

1. **Incorrect Method Names:**  Typing the method name wrong when using the DevTools console or sending raw protocol messages.
   ```javascript
   // Incorrect method name:
   sendMessageToBackend({ method: "Debgger.pause" }); // Should be "Debugger.pause"
   ```
   The `UberDispatcher` would likely report a "MethodNotFound" error.

2. **Invalid Parameter Types or Structures:** Providing parameters that don't match the expected schema for a particular method.
   ```javascript
   // Incorrect parameter type (lineNumber should be a number):
   sendMessageToBackend({
     method: "Debugger.setBreakpointByUrl",
     params: { lineNumber: "10", urlRegex: ".*" }
   });
   ```
   The `DomainDispatcher` or the specific handler might report an "InvalidParams" error, potentially with details about the type mismatch. The `DeserializerState` mentioned in the code is likely used to help pinpoint these parameter errors.

3. **Missing Required Parameters:**  Not including all the necessary parameters for a protocol method.
   ```javascript
   // Missing the 'urlRegex' parameter:
   sendMessageToBackend({ method: "Debugger.setBreakpointByUrl", params: { lineNumber: 10 } });
   ```
   This would also likely result in an "InvalidParams" error.

4. **Sending Messages with Incorrect Formatting (if manually constructing them):** If a developer tries to manually construct and send CBOR-encoded messages without following the correct structure, the `Dispatchable` class would likely fail to parse the message, resulting in a "ParseError".

In summary, `v8/third_party/inspector_protocol/crdtp/dispatch.cc` is a fundamental piece of V8's debugging infrastructure. It acts as the message router and dispatcher for the Chrome DevTools Protocol, enabling communication between the developer tools and the JavaScript engine. It handles the low-level details of parsing and routing messages, allowing other parts of V8 to focus on implementing the actual debugging functionality.

### 提示词
```
这是目录为v8/third_party/inspector_protocol/crdtp/dispatch.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/third_party/inspector_protocol/crdtp/dispatch.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```
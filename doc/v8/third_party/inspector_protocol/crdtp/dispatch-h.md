Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Initial Scan for Keywords and Structure:**  My first step is always to quickly scan the code for keywords and structural elements. I look for:
    * `#ifndef`, `#define`, `#endif`:  Indicates a header guard, standard practice in C++.
    * `#include`:  Dependencies on other headers.
    * `namespace`:  Organization and potential for related functionality.
    * `class`, `enum class`:  Core building blocks of object-oriented programming in C++.
    * Comments:  Clues about the purpose of different sections.
    * Names like `Dispatch`, `Response`, `Error`, `Callback`, `Dispatcher`: Suggest the primary function is handling and routing messages.

2. **Identify the Core Purpose (Based on Names and Comments):** The file name `dispatch.h` and the prominent use of "Dispatch" in class names immediately point towards a message dispatching mechanism. The comments reinforce this, mentioning "DevTools messages" and "command handlers."  The `// =============================================================================` separators help delineate logical sections.

3. **Analyze Key Classes and Enums:** I start diving into the most important declarations:

    * **`DispatchCode`:** This enum clearly defines different outcomes of a dispatch operation (success, fall-through, various error types). The comments referencing XMLRPC codes provide context and suggest this is related to remote procedure calls or similar communication.

    * **`DispatchResponse`:** This class represents the result of a command execution. It holds a `DispatchCode` and a message. The static factory methods (`Success`, `ParseError`, etc.) are a common pattern for creating objects with specific states.

    * **`Dispatchable`:**  This class seems to handle the *incoming* message. The comment about "shallow parser for CBOR encoded DevTools messages" is crucial. It extracts top-level fields like `method`, `id`, `sessionId`, and `params`. The `ok()` and `DispatchError()` methods indicate error handling during parsing.

    * **Helper Functions (e.g., `CreateErrorResponse`, `CreateNotification`):** These functions are clearly for constructing standard response and notification messages, which aligns with the dispatching theme. The use of `Serializable` suggests a common interface for representing these messages.

    * **`DomainDispatcher`:** This class looks responsible for handling dispatching *within* a specific "domain" (likely a feature area of the DevTools protocol). The `Dispatch` virtual method is the key here, taking a command name and returning a function to execute it. The `Callback` nested class suggests asynchronous operations or handling of results.

    * **`UberDispatcher`:** This class appears to be the central coordinator, dispatching messages *between* different domains. The `Dispatch` method and the `WireBackend` function are key to understanding its role. The `redirects_` member suggests the possibility of routing commands to different handlers.

4. **Consider the Context (v8/third_party/inspector_protocol/crdtp/):** The directory structure provides valuable context. "v8" indicates this is part of the V8 JavaScript engine. "third_party" suggests it's related to external components or protocols. "inspector_protocol" and "crdtp" strongly imply this is connected to the Chrome DevTools Protocol.

5. **Address Specific Questions from the Prompt:**

    * **Functionality Listing:** Based on the class analysis, I can list the main functions.

    * **`.tq` Extension:**  The prompt asks about `.tq`. I recognize this as the extension for V8 Torque files, which are used for a type-safe, low-level language within V8. Since this file is `.h`, it's a standard C++ header, *not* a Torque file. I need to explicitly state this.

    * **Relationship to JavaScript:**  The connection to the Chrome DevTools Protocol is the crucial link to JavaScript. The DevTools are used to debug and inspect JavaScript code running in V8. Therefore, this code is part of the infrastructure that *enables* the DevTools to interact with V8. I need to provide JavaScript examples of how DevTools are used.

    * **Code Logic Inference (Input/Output):**  For `Dispatchable`, I can create a hypothetical CBOR-encoded message and trace how the parser might extract the `method`, `callId`, etc.

    * **Common Programming Errors:**  Relating this back to common programming errors requires thinking about how this code might be misused or what mistakes developers might make *when interacting with or extending* this kind of system. Incorrectly formatting messages, not handling errors, and mismatches between expected and actual data are good examples.

6. **Structure and Refine the Answer:**  Finally, I organize the information logically, using clear headings and bullet points. I ensure the language is precise and avoids jargon where possible. I double-check that I've addressed all the specific points raised in the original prompt.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe `Dispatchable` is a base class for different dispatchers."  **Correction:**  Looking at its members, it's clearly a parser for the incoming message, not a dispatcher itself.

* **Initial thought:** "The error codes might be arbitrary." **Correction:** The comment explicitly links them to XMLRPC, providing important context.

* **Initial thought:** "The JavaScript connection might be indirect." **Refinement:** The direct connection is through the Chrome DevTools Protocol, which is used to inspect *running* JavaScript.

By following this structured approach, I can systematically analyze the code and generate a comprehensive and accurate explanation of its functionality and context.
This header file `v8/third_party/inspector_protocol/crdtp/dispatch.h` defines core components for dispatching messages within the Chrome DevTools Protocol (CRDP) implementation in V8. Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Defines `DispatchCode` Enum:** This enum represents the outcome of a dispatch operation, including success, fall-through (allowing other handlers to process the message), and various standard error codes (similar to XML-RPC errors).

2. **Defines `DispatchResponse` Class:** This class encapsulates the result of a command handler's execution. It contains a `DispatchCode` and an optional error message. It provides static factory methods for creating `DispatchResponse` objects representing different outcomes (success, various errors like `ParseError`, `MethodNotFound`, `InvalidParams`, etc.). This allows for a standardized way to signal the result of processing a DevTools command.

3. **Defines `Dispatchable` Class:** This class acts as a lightweight parser for incoming CBOR (Concise Binary Object Representation) encoded DevTools messages. It extracts essential top-level fields from the message:
    * `Method()`: The fully qualified command name (e.g., "Page.enable").
    * `SessionId()`:  An identifier for a specific debugging session.
    * `CallId()`: A unique ID for the request, used for matching responses.
    * `Params()`: The raw CBOR payload containing the parameters for the command.
    `Dispatchable` doesn't fully deserialize the `Params()`; it just provides access to the raw bytes. It also handles basic parsing errors and provides a `DispatchError()` method to generate an appropriate error response if parsing fails.

4. **Provides Helper Functions for Creating Responses and Notifications:**
    * `CreateErrorResponse()`: Creates a standardized error response to a command.
    * `CreateErrorNotification()`: Creates a standardized error notification (not tied to a specific request).
    * `CreateResponse()`: Creates a successful response to a command, including the result parameters.
    * `CreateNotification()`: Creates a notification (an event sent from the backend to the frontend) with a given method name and optional parameters.

5. **Defines `DomainDispatcher` Class:** This is an abstract base class for dispatchers that handle messages within a specific DevTools domain (e.g., "Page", "Runtime", "Debugger").
    * It has a `Dispatch()` method (pure virtual) that takes a command name (without the domain prefix) and returns a function to handle that command. This function will parse the parameters and execute the corresponding logic.
    * It provides methods for sending responses (`sendResponse`) and reporting invalid parameters (`ReportInvalidParams`).
    * It manages a `FrontendChannel` for sending messages back to the DevTools frontend.
    * It uses a `WeakPtr` mechanism to manage its lifetime.

6. **Defines `UberDispatcher` Class:** This class acts as a central dispatcher, routing incoming messages to the appropriate `DomainDispatcher` based on the domain specified in the command name.
    * It has a `Dispatch()` method that takes a `Dispatchable` object and determines which `DomainDispatcher` should handle the message.
    * It uses `WireBackend()` to register `DomainDispatcher` instances for specific domains.
    * It also handles command redirects, allowing certain commands to be routed to different handlers.

**Is `v8/third_party/inspector_protocol/crdtp/dispatch.h` a Torque source file?**

No, it is **not** a Torque source file. The file extension is `.h`, which is the standard extension for C++ header files. Torque source files in V8 typically have the extension `.tq`.

**Relationship to JavaScript and JavaScript Examples:**

This header file is fundamental to the communication between the V8 JavaScript engine and the Chrome DevTools frontend. When you use the DevTools to inspect and debug JavaScript code, the following happens (simplified):

1. **DevTools Frontend Sends a Command:**  When you click a button in the DevTools (e.g., "Pause" in the debugger), the frontend sends a command to the V8 backend. This command is typically formatted according to the Chrome DevTools Protocol (CRDP) and encoded in JSON or CBOR.

2. **V8 Receives and Parses the Command:** V8 receives this message. The `Dispatchable` class (or similar logic) parses the incoming message to extract the method name (e.g., "Debugger.pause"), the session ID, and the parameters.

3. **`UberDispatcher` Routes the Command:** The `UberDispatcher` examines the method name ("Debugger.pause") and identifies the responsible `DomainDispatcher` (in this case, likely a `DebuggerDomainDispatcher`).

4. **`DomainDispatcher` Executes the Command:** The `DebuggerDomainDispatcher`'s `Dispatch()` method (or its generated implementation) finds the appropriate handler for the "pause" command. This handler executes the necessary logic within V8 to pause JavaScript execution.

5. **V8 Sends a Response or Notification:**
    * **Response:** If the command expects a response (e.g., a request for the current call stack), the handler uses the helper functions (`CreateResponse`) to create a response message containing the data.
    * **Notification:**  V8 can also send asynchronous notifications (events) to the frontend (e.g., "Debugger.paused" when the execution is actually paused). The helper functions (`CreateNotification`) are used for this.

**JavaScript Example:**

While you don't directly interact with these C++ classes in your JavaScript code, the effects are very visible when using the DevTools. Here's how a DevTools interaction relates:

```javascript
// This is JavaScript code running in the browser or Node.js
function myFunction() {
  debugger; // Set a breakpoint
  console.log("Hello from myFunction");
}

myFunction();
```

When the JavaScript execution reaches the `debugger;` statement, the following happens behind the scenes, involving the code in `dispatch.h`:

1. The DevTools frontend (if open and connected) receives a notification from V8 similar to:
   ```json
   {
     "method": "Debugger.paused",
     "params": {
       "callFrames": [ /* ... information about the call stack ... */ ],
       "reason": "debuggerStatement",
       // ... other details ...
     }
   }
   ```
   This notification was likely created using `CreateNotification("Debugger.paused", ...)` in the C++ backend.

2. If you then step over a line in the DevTools, the frontend sends a command like:
   ```json
   {
     "id": 123,
     "method": "Debugger.stepOver"
   }
   ```
   This JSON message will be received by V8, parsed by something similar to `Dispatchable`, routed by `UberDispatcher` to the `DebuggerDomainDispatcher`, and the corresponding C++ handler for "stepOver" will be executed.

3. Eventually, V8 might send another "Debugger.paused" notification when the execution stops at the next line.

**Code Logic Inference (Hypothetical Example):**

**Input (CBOR encoded message for `Dispatchable`):**

Let's imagine a simplified CBOR representation of the "Runtime.evaluate" command:

```
{
  "id": 1,
  "method": "Runtime.evaluate",
  "params": {
    "expression": "1 + 1"
  }
}
```

Encoded in CBOR (simplified representation, actual CBOR is binary):

```
[
  1,          // id: 1
  "Runtime.evaluate", // method: "Runtime.evaluate"
  {            // params: {
    "expression": "1 + 1"
  }
]
```

**Processing by `Dispatchable`:**

1. The `Dispatchable` constructor receives the raw CBOR bytes.
2. It uses a `CBORTokenizer` to iterate through the top-level map.
3. It identifies the "id" field and extracts the value `1` into `call_id_`.
4. It identifies the "method" field and stores a span pointing to the bytes representing "Runtime.evaluate" in `method_`.
5. It identifies the "params" field and stores a span pointing to the bytes representing the parameters object in `params_`.
6. `ok()` would return `true` if the basic structure is valid.

**Output of `Dispatchable`:**

* `CallId()`: `1`
* `Method()`: Span of bytes representing "Runtime.evaluate"
* `Params()`: Span of bytes representing the CBOR encoded parameters object.

**Processing by `UberDispatcher` and `DomainDispatcher` (Conceptual):**

1. `UberDispatcher::Dispatch()` receives the `Dispatchable` object.
2. It extracts the method name "Runtime.evaluate".
3. It looks up the `RuntimeDomainDispatcher` (assuming it's registered).
4. It calls `RuntimeDomainDispatcher::Dispatch("evaluate")`.
5. The `RuntimeDomainDispatcher`'s `Dispatch()` returns a function (or closure) that knows how to handle the "evaluate" command.
6. This function is executed, taking the `Params()` from the `Dispatchable` and potentially deserializing the parameters to a more structured object.
7. The "evaluate" handler executes the JavaScript code "1 + 1" within V8.
8. The handler then uses `CreateResponse(1, ...)` to send a response back to the DevTools frontend, potentially containing the result `{ "result": { "type": "number", "value": 2 } }`.

**User-Common Programming Errors (Related to DevTools/CRDP Interaction):**

While you don't directly write code against these C++ classes in typical web development, understanding their role helps in debugging issues related to DevTools:

1. **Incorrectly formatted DevTools Protocol messages:** If you're manually sending commands to the DevTools backend (e.g., via a WebSocket), sending malformed JSON or CBOR will lead to parsing errors handled by `Dispatchable`, resulting in error responses like `InvalidRequest`.

   ```javascript
   // Example of a malformed message (missing quotes around method)
   const ws = new WebSocket('ws://localhost:9229/devtools/browser/...');
   ws.send({ id: 1, method: Debugger.pause }); // Error!
   ```

2. **Sending commands to non-existent methods or domains:**  Trying to call a method that isn't defined in the CRDP will result in a `MethodNotFound` error.

   ```javascript
   // Assuming "NoSuchDomain.doSomething" doesn't exist
   ws.send({ id: 2, method: "NoSuchDomain.doSomething" });
   ```

3. **Providing invalid parameters for a command:** If the parameters you send don't match the expected types or structure for a given command, the `DomainDispatcher` will likely report `InvalidParams`.

   ```javascript
   // "Debugger.setBreakpointByUrl" expects a 'lineNumber' to be a number
   ws.send({
     id: 3,
     method: "Debugger.setBreakpointByUrl",
     params: { url: "my-script.js", lineNumber: "not a number" }
   });
   ```

4. **Mismatched `callId` in responses:** If you're implementing a custom DevTools client, incorrectly handling the `callId` can lead to confusion about which response corresponds to which request.

In summary, `v8/third_party/inspector_protocol/crdtp/dispatch.h` defines the core message dispatching mechanism for the Chrome DevTools Protocol within the V8 JavaScript engine. It handles parsing incoming commands, routing them to the appropriate handlers, and creating standardized responses and notifications, enabling the powerful debugging and inspection capabilities of the Chrome DevTools.

### 提示词
```
这是目录为v8/third_party/inspector_protocol/crdtp/dispatch.h的一个v8源代码， 请列举一下它的功能, 
如果v8/third_party/inspector_protocol/crdtp/dispatch.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CRDTP_DISPATCH_H_
#define V8_CRDTP_DISPATCH_H_

#include <cassert>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_set>
#include "export.h"
#include "serializable.h"
#include "span.h"
#include "status.h"

namespace v8_crdtp {
class DeserializerState;
class ErrorSupport;
class FrontendChannel;
namespace cbor {
class CBORTokenizer;
}  // namespace cbor

// =============================================================================
// DispatchResponse - Error status and chaining / fall through
// =============================================================================
enum class DispatchCode {
  SUCCESS = 1,
  FALL_THROUGH = 2,
  // For historical reasons, these error codes correspond to commonly used
  // XMLRPC codes (e.g. see METHOD_NOT_FOUND in
  // https://github.com/python/cpython/blob/main/Lib/xmlrpc/client.py).
  PARSE_ERROR = -32700,
  INVALID_REQUEST = -32600,
  METHOD_NOT_FOUND = -32601,
  INVALID_PARAMS = -32602,
  INTERNAL_ERROR = -32603,
  SERVER_ERROR = -32000,
  SESSION_NOT_FOUND = SERVER_ERROR - 1,
};

// Information returned by command handlers. Usually returned after command
// execution attempts.
class DispatchResponse {
 public:
  const std::string& Message() const { return message_; }

  DispatchCode Code() const { return code_; }

  bool IsSuccess() const { return code_ == DispatchCode::SUCCESS; }
  bool IsFallThrough() const { return code_ == DispatchCode::FALL_THROUGH; }
  bool IsError() const { return code_ < DispatchCode::SUCCESS; }

  static DispatchResponse Success();
  static DispatchResponse FallThrough();

  // Indicates that a message could not be parsed. E.g., malformed JSON.
  static DispatchResponse ParseError(std::string message);

  // Indicates that a request is lacking required top-level properties
  // ('id', 'method'), has top-level properties of the wrong type, or has
  // unknown top-level properties.
  static DispatchResponse InvalidRequest(std::string message);

  // Indicates that a protocol method such as "Page.bringToFront" could not be
  // dispatched because it's not known to the (domain) dispatcher.
  static DispatchResponse MethodNotFound(std::string message);

  // Indicates that the params sent to a domain handler are invalid.
  static DispatchResponse InvalidParams(std::string message);

  // Used for application level errors, e.g. within protocol agents.
  static DispatchResponse InternalError();

  // Used for application level errors, e.g. within protocol agents.
  static DispatchResponse ServerError(std::string message);

  // Indicate that session with the id specified in the protocol message
  // was not found (e.g. because it has already been detached).
  static DispatchResponse SessionNotFound(std::string message);

 private:
  DispatchResponse() = default;
  DispatchCode code_;
  std::string message_;
};

// =============================================================================
// Dispatchable - a shallow parser for CBOR encoded DevTools messages
// =============================================================================

// This parser extracts only the known top-level fields from a CBOR encoded map;
// method, id, sessionId, and params.
class Dispatchable {
 public:
  // This constructor parses the |serialized| message. If successful,
  // |ok()| will yield |true|, and |Method()|, |SessionId()|, |CallId()|,
  // |Params()| can be used to access, the extracted contents. Otherwise,
  // |ok()| will yield |false|, and |DispatchError()| can be
  // used to send a response or notification to the client.
  explicit Dispatchable(span<uint8_t> serialized);

  // The serialized message that we just parsed.
  span<uint8_t> Serialized() const { return serialized_; }

  // Yields true if parsing was successful. This is cheaper than calling
  // ::DispatchError().
  bool ok() const;

  // If !ok(), returns a DispatchResponse with appropriate code and error
  // which can be sent to the client as a response or notification.
  DispatchResponse DispatchError() const;

  // Top level field: the command to be executed, fully qualified by
  // domain. E.g. "Page.createIsolatedWorld".
  span<uint8_t> Method() const { return method_; }
  // Used to identify protocol connections attached to a specific
  // target. See Target.attachToTarget, Target.setAutoAttach.
  span<uint8_t> SessionId() const { return session_id_; }
  // The call id, a sequence number that's used in responses to indicate
  // the request to which the response belongs.
  int32_t CallId() const { return call_id_; }
  bool HasCallId() const { return has_call_id_; }
  // The payload of the request in CBOR format. The |Dispatchable| parser does
  // not parse into this; it only provides access to its raw contents here.
  span<uint8_t> Params() const { return params_; }

 private:
  bool MaybeParseProperty(cbor::CBORTokenizer* tokenizer);
  bool MaybeParseCallId(cbor::CBORTokenizer* tokenizer);
  bool MaybeParseMethod(cbor::CBORTokenizer* tokenizer);
  bool MaybeParseParams(cbor::CBORTokenizer* tokenizer);
  bool MaybeParseSessionId(cbor::CBORTokenizer* tokenizer);

  span<uint8_t> serialized_;

  Status status_;

  bool has_call_id_ = false;
  int32_t call_id_;
  span<uint8_t> method_;
  bool params_seen_ = false;
  span<uint8_t> params_;
  span<uint8_t> session_id_;
};

// =============================================================================
// Helpers for creating protocol cresponses and notifications.
// =============================================================================

// The resulting notifications can be sent to a protocol client,
// usually via a FrontendChannel (see frontend_channel.h).

std::unique_ptr<Serializable> CreateErrorResponse(
    int callId,
    DispatchResponse dispatch_response);

std::unique_ptr<Serializable> CreateErrorNotification(
    DispatchResponse dispatch_response);

std::unique_ptr<Serializable> CreateResponse(
    int callId,
    std::unique_ptr<Serializable> params);

std::unique_ptr<Serializable> CreateNotification(
    const char* method,
    std::unique_ptr<Serializable> params = nullptr);

// =============================================================================
// DomainDispatcher - Dispatching betwen protocol methods within a domain.
// =============================================================================

// This class is subclassed by |DomainDispatcherImpl|, which we generate per
// DevTools domain. It contains routines called from the generated code,
// e.g. ::MaybeReportInvalidParams, which are optimized for small code size.
// The most important method is ::Dispatch, which implements method dispatch
// by command name lookup.
class DomainDispatcher {
 public:
  class WeakPtr {
   public:
    explicit WeakPtr(DomainDispatcher*);
    ~WeakPtr();
    DomainDispatcher* get() { return dispatcher_; }
    void dispose() { dispatcher_ = nullptr; }

   private:
    DomainDispatcher* dispatcher_;
  };

  class Callback {
   public:
    virtual ~Callback();
    void dispose();

   protected:
    // |method| must point at static storage (a C++ string literal in practice).
    Callback(std::unique_ptr<WeakPtr> backend_impl,
             int call_id,
             span<uint8_t> method,
             span<uint8_t> message);

    void sendIfActive(std::unique_ptr<Serializable> partialMessage,
                      const DispatchResponse& response);
    void fallThroughIfActive();

   private:
    std::unique_ptr<WeakPtr> backend_impl_;
    int call_id_;
    // Subclasses of this class are instantiated from generated code which
    // passes a string literal for the method name to the constructor. So the
    // storage for |method| is the binary of the running process.
    span<uint8_t> method_;
    std::vector<uint8_t> message_;
  };

  explicit DomainDispatcher(FrontendChannel*);
  virtual ~DomainDispatcher();

  // Given a |command_name| without domain qualification, looks up the
  // corresponding method. If the method is not found, returns nullptr.
  // Otherwise, Returns a closure that will parse the provided
  // Dispatchable.params() to a protocol object and execute the
  // apprpropriate method. If the parsing fails it will issue an
  // error response on the frontend channel, otherwise it will execute the
  // command.
  virtual std::function<void(const Dispatchable&)> Dispatch(
      span<uint8_t> command_name) = 0;

  // Sends a response to the client via the channel.
  void sendResponse(int call_id,
                    const DispatchResponse&,
                    std::unique_ptr<Serializable> result = nullptr);

  void ReportInvalidParams(const Dispatchable& dispatchable,
                           const DeserializerState& state);

  FrontendChannel* channel() { return frontend_channel_; }

  void clearFrontend();

  std::unique_ptr<WeakPtr> weakPtr();

 private:
  FrontendChannel* frontend_channel_;
  std::unordered_set<WeakPtr*> weak_ptrs_;
};

// =============================================================================
// UberDispatcher - dispatches between domains (backends).
// =============================================================================
class UberDispatcher {
 public:
  // Return type for ::Dispatch.
  class DispatchResult {
   public:
    DispatchResult(bool method_found, std::function<void()> runnable);

    // Indicates whether the method was found, that is, it could be dispatched
    // to a backend registered with this dispatcher.
    bool MethodFound() const { return method_found_; }

    // Runs the dispatched result. This will send the appropriate error
    // responses if the method wasn't found or if something went wrong during
    // parameter parsing.
    void Run();

   private:
    bool method_found_;
    std::function<void()> runnable_;
  };

  // |frontend_hannel| can't be nullptr.
  explicit UberDispatcher(FrontendChannel* frontend_channel);
  virtual ~UberDispatcher();

  // Dispatches the provided |dispatchable| considering all redirects and domain
  // handlers registered with this uber dispatcher. Also see |DispatchResult|.
  // |dispatchable.ok()| must hold - callers must check this separately and
  // deal with errors.
  DispatchResult Dispatch(const Dispatchable& dispatchable) const;

  // Invoked from generated code for wiring domain backends; that is,
  // connecting domain handlers to an uber dispatcher.
  // See <domain-namespace>::Dispatcher::Wire(UberDispatcher*,Backend*).
  FrontendChannel* channel() const {
    assert(frontend_channel_);
    return frontend_channel_;
  }

  // Invoked from generated code for wiring domain backends; that is,
  // connecting domain handlers to an uber dispatcher.
  // See <domain-namespace>::Dispatcher::Wire(UberDispatcher*,Backend*).
  void WireBackend(span<uint8_t> domain,
                   const std::vector<std::pair<span<uint8_t>, span<uint8_t>>>&,
                   std::unique_ptr<DomainDispatcher> dispatcher);

 private:
  DomainDispatcher* findDispatcher(span<uint8_t> method);
  FrontendChannel* const frontend_channel_;
  // Pairs of ascii strings of the form ("Domain1.method1","Domain2.method2")
  // indicating that the first element of each pair redirects to the second.
  // Sorted by first element.
  std::vector<std::pair<span<uint8_t>, span<uint8_t>>> redirects_;
  // Domain dispatcher instances, sorted by their domain name.
  std::vector<std::pair<span<uint8_t>, std::unique_ptr<DomainDispatcher>>>
      dispatchers_;
};
}  // namespace v8_crdtp

#endif  // V8_CRDTP_DISPATCH_H_
```
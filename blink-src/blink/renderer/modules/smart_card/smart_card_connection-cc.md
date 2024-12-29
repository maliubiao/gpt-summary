Response:
Let's break down the thought process to analyze the `SmartCardConnection.cc` file.

1. **Understand the Core Purpose:** The file name `smart_card_connection.cc` immediately suggests its primary function: managing a connection to a smart card reader. The surrounding directory `blink/renderer/modules/smart_card/` reinforces this, placing it within the Blink rendering engine's smart card module.

2. **Identify Key Classes:**  The code defines the `SmartCardConnection` class as the central entity. Look for other important classes or structs. `TransactionState` stands out as it seems to manage the lifecycle of a smart card transaction.

3. **Analyze Public Methods (the API):**  These methods represent the actions that can be performed on a smart card connection. List them and their basic purpose:
    * `disconnect()`: Closes the connection.
    * `transmit()`: Sends data to the smart card and receives a response.
    * `status()`: Retrieves the current status of the smart card reader.
    * `control()`: Sends control commands to the smart card reader.
    * `getAttribute()`: Retrieves attributes of the smart card.
    * `setAttribute()`: Sets attributes of the smart card.
    * `startTransaction()`: Begins a secure transaction with the smart card.

4. **Examine Private Methods and Helper Functions:** These methods support the public API and handle the internal logic. Note the naming conventions and what they seem to be doing:
    * `OnDisconnectDone`, `OnPlainResult`, `OnDataResult`, `OnStatusDone`, `OnBeginTransactionDone`, `OnEndTransactionDone`: These are callback functions, likely triggered by asynchronous Mojo calls. They handle the results of operations.
    * `ToMojomDisposition`, `ToMojoSmartCardProtocol`, `ToV8ConnectionState`: These are conversion functions, translating between Blink/V8 types and Mojo types (for inter-process communication).
    * `TransactionFulfilledFunction`, `TransactionRejectedFunction`: These look like promise fulfillment/rejection handlers specifically for the `startTransaction` callback.
    * `SetOperationInProgress`, `ClearOperationInProgress`, `EnsureConnection`: These seem to manage the state of ongoing operations and ensure the connection is valid.
    * `CloseMojoConnection`: Handles the disconnection at the Mojo level.
    * `OnTransactionCallbackDone`, `OnTransactionCallbackFailed`: These handle the completion or failure of the JavaScript callback provided to `startTransaction`.
    * `EndTransaction`:  A core function for finalizing a transaction.

5. **Look for Interactions with External Systems:** The `#include` directives and the use of `mojo::` namespace are strong indicators of interaction with the Chromium Mojo system. This suggests the smart card functionality is likely implemented in a separate process.

6. **Identify Relationships to Web Technologies (JavaScript, HTML, CSS):**  Consider how this C++ code is exposed to the web.
    * **JavaScript:** The file uses V8 bindings (`V8SmartCardConnection`, `V8SmartCardDisposition`, etc.). The public methods of `SmartCardConnection` will likely be exposed as methods on a JavaScript object. The callbacks in `startTransaction` are direct JavaScript function calls. Promises are heavily used, a core JavaScript concept for asynchronous operations.
    * **HTML:** While this specific C++ file doesn't directly interact with HTML rendering, the smart card API it implements is likely triggered by JavaScript code within a web page. Think about a hypothetical scenario where a user clicks a button, and that click triggers JavaScript that calls a smart card function.
    * **CSS:**  No direct relationship with CSS for this particular file. Smart card functionality is about data processing and interaction with hardware, not visual presentation.

7. **Trace User Interaction (Debugging Perspective):** Think about how a user's actions might lead to this code being executed. Start from the user's perspective in the browser and trace down:
    * User inserts a smart card into a reader.
    * A web page uses JavaScript to access the smart card API.
    * JavaScript calls a method like `navigator.smartCard.connect()`.
    * This eventually leads to the creation of a `SmartCardConnection` object in the Blink renderer process.
    * The user then might interact with the web page, triggering calls to methods like `transmit()` or `startTransaction()`.

8. **Consider Potential Errors and Usage Mistakes:** Analyze the code for error handling and potential misuse scenarios:
    * Calling methods on a disconnected connection.
    * Starting a transaction while another is active.
    * Providing invalid data to methods (e.g., detached ArrayBuffers).
    * Not handling promise rejections properly in JavaScript.
    * Errors in the JavaScript transaction callback.
    * Cancellation of transactions via an `AbortSignal`.

9. **Examine `TransactionState` in Detail:** This nested class is crucial for managing transaction lifecycles. Understand its purpose: holding the Mojo remote, managing the start transaction promise, and handling the callback.

10. **Logical Inference (Hypothetical Input/Output):**  For methods like `transmit()`, think about what would happen with a given input. For example, if `transmit()` receives an `ArrayBuffer` containing `0x00 0xA4 0x04 0x00`, what would the expected output be?  This often depends on the specific smart card protocol, but the code handles the generic aspects of sending data and receiving a response.

11. **Review for Specific Language Features:** Note the use of `WTF::BindOnce`, `WrapWeakPersistent`, `WrapPersistent`, `ScriptPromise`, `DOMArrayBuffer`, etc. These are common Blink idioms and data structures.

By following these steps, you can systematically analyze the provided C++ code and understand its functionality, its relationship to web technologies, potential errors, and how user actions might trigger its execution. The key is to break down the code into smaller, manageable parts and to consider the context in which it operates within the larger Chromium project.
This C++ source file, `smart_card_connection.cc`, within the Chromium Blink rendering engine, implements the functionality for managing a single connection to a smart card reader. It acts as a bridge between the web platform's JavaScript API for smart cards and the underlying operating system's smart card services (likely accessed via Mojo IPC).

Here's a breakdown of its functionalities:

**Core Functionality:**

* **Establishing and Managing a Connection:** The `SmartCardConnection` class represents an active connection to a specific smart card reader. It holds a Mojo remote (`connection_`) to communicate with the browser process, which in turn interacts with the system's smart card drivers.
* **Disconnecting:** The `disconnect()` method allows closing the connection to the smart card reader. It supports different disconnection dispositions (e.g., leave the card, reset, unpower, eject).
* **Transmitting Data:** The `transmit()` method sends data (represented as an `ArrayBuffer`) to the smart card and receives a response. It allows specifying the communication protocol (T0, T1, or RAW).
* **Getting Status:** The `status()` method retrieves the current status of the smart card connection, including the reader name, card state (e.g., present, powered, specific protocol), and the Answer To Reset (ATR).
* **Sending Control Codes:** The `control()` method sends specific control commands (with optional data) to the smart card reader. These codes are typically specific to the smart card driver or the reader.
* **Getting and Setting Attributes:** The `getAttribute()` and `setAttribute()` methods allow retrieving and setting specific attributes of the smart card reader or the connected card. These attributes are identified by a tag.
* **Managing Transactions:** The `startTransaction()` method initiates a transaction with the smart card. A transaction ensures that a series of operations are performed atomically. It takes a JavaScript callback function that will be executed within the transaction.
* **Handling Asynchronous Operations:** Most of the methods return `ScriptPromise` objects, indicating that the operations are asynchronous and their results will be available later. This is essential for a non-blocking web experience.

**Relationship with JavaScript, HTML, and CSS:**

This C++ code is a crucial part of the implementation of the Web Smart Card API, which is exposed to JavaScript in web pages.

* **JavaScript:**
    * **Direct Exposure:** The methods in `SmartCardConnection` are directly called by JavaScript code using the `navigator.smartCard` API. For example, in JavaScript:
        ```javascript
        navigator.smartCard.request().then(reader => {
          return reader.connect();
        }).then(connection => {
          // Call methods from SmartCardConnection.cc
          connection.transmit(sendBuffer);
          connection.startTransaction(async () => { /* ... */ });
          connection.disconnect('reset');
        });
        ```
    * **Callbacks:** The `startTransaction()` method takes a JavaScript function as an argument. This function is executed by the C++ code when the transaction begins. The result of this callback (a `SmartCardDisposition`) influences how the transaction is finalized.
    * **Promises:** The asynchronous nature of the smart card operations is reflected in JavaScript Promises. The C++ code resolves or rejects these promises based on the outcome of the underlying operations.
    * **Data Representation:**  `DOMArrayBuffer` is used to represent binary data exchanged between JavaScript and C++. This allows JavaScript to send and receive raw data to and from the smart card.

* **HTML:** HTML itself doesn't directly interact with this code. However, user interactions within an HTML page (e.g., clicking a button) can trigger JavaScript code that then uses the Smart Card API, ultimately leading to the execution of the C++ code in this file.

* **CSS:** CSS has no direct relationship with this backend logic for smart card interaction. CSS is responsible for the visual presentation of the web page.

**Logical Reasoning (Hypothetical Input and Output):**

Let's consider the `transmit()` method:

* **Hypothetical Input:**
    * `send_buffer`: A JavaScript `ArrayBuffer` containing the APDU (Application Protocol Data Unit) for selecting an application on the smart card, e.g., `[0x00, 0xA4, 0x04, 0x00, 0x06, 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01]`.
    * `options`:  `null` or an object specifying the protocol, e.g., `{ protocol: 'T0' }`.

* **Logical Steps:**
    1. The JavaScript `transmit()` call reaches the C++ `SmartCardConnection::transmit()` method.
    2. The `send_buffer` is converted into a `Vector<uint8_t>`.
    3. The specified protocol (or the active protocol) is used.
    4. A Mojo IPC call is made to the browser process to transmit the data.
    5. The browser process interacts with the smart card driver.
    6. The smart card processes the APDU and returns a response.
    7. The browser process sends the response back to the renderer process via Mojo.
    8. The `OnDataResult()` callback in `SmartCardConnection.cc` is invoked.

* **Hypothetical Output:**
    * If the transmission is successful, the promise associated with the `transmit()` call in JavaScript will be resolved with a new `ArrayBuffer` containing the smart card's response APDU, e.g., `[0x90, 0x00]` (indicating success).
    * If there's an error (e.g., communication error, card not present), the promise will be rejected with a `DOMException`.

**User and Programming Common Usage Errors:**

* **Calling methods on a disconnected connection:**  The code checks for a valid connection using `EnsureConnection()` and throws an `InvalidStateError` if the connection is closed.
    * **Example:**
        ```javascript
        navigator.smartCard.request().then(reader => {
          return reader.connect();
        }).then(connection => {
          connection.disconnect();
          connection.transmit(sendBuffer); // Error: InvalidStateError
        });
        ```
* **Starting a transaction when another is already active:** The code checks for an existing `transaction_state_` and throws an `InvalidStateError`.
    * **Example:**
        ```javascript
        connection.startTransaction(() => {});
        connection.startTransaction(() => {}); // Error: InvalidStateError
        ```
* **Providing an invalid `send_buffer`:** The `transmit()` method checks if the `send_buffer` is detached or null and throws a `TypeError`.
    * **Example:**
        ```javascript
        let buffer = new ArrayBuffer(10);
        // ... some operation that detaches the buffer ...
        connection.transmit(buffer); // Error: TypeError
        ```
* **Not handling promise rejections:** If a smart card operation fails, the JavaScript promise will be rejected. If the developer doesn't handle this rejection with `.catch()`, it can lead to unhandled promise rejections.
* **Errors in the transaction callback:** If the JavaScript callback provided to `startTransaction()` throws an error, the transaction will be ended with a reset disposition. The C++ code includes `try_catch` blocks to handle exceptions in the callback.
* **Incorrect protocol selection:** Specifying an incorrect protocol in `transmit()` might lead to communication errors with the smart card.

**User Operation Steps Leading to This Code (Debugging Perspective):**

Let's trace a user interaction that leads to the `transmit()` method being called:

1. **User inserts a smart card into a reader connected to their computer.**
2. **User navigates to a web page that uses the Web Smart Card API.**
3. **JavaScript code on the web page requests access to a smart card reader:**
   ```javascript
   navigator.smartCard.request().then(reader => { /* ... */ });
   ```
4. **The user grants permission for the web page to access the smart card reader.**
5. **JavaScript code connects to a specific reader:**
   ```javascript
   reader.connect().then(connection => { /* ... */ });
   ```
   * This step likely involves creating an instance of `SmartCardConnection` in the C++ code.
6. **JavaScript code wants to send data to the smart card:**
   ```javascript
   let sendBuffer = new Uint8Array([0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10, 0x01]).buffer;
   connection.transmit(sendBuffer).then(responseBuffer => {
     // Process the response
   }).catch(error => {
     // Handle the error
   });
   ```
7. **The `connection.transmit(sendBuffer)` call in JavaScript translates into a call to the `SmartCardConnection::transmit()` method in this C++ file.**
8. **The C++ code interacts with the underlying smart card services via Mojo to send the data.**

By understanding these steps, developers can set breakpoints in this C++ file (e.g., in the `transmit()` method) during debugging to inspect the data being sent, the state of the connection, and the interaction with the smart card service. They can also use browser developer tools to observe the JavaScript calls and promise resolutions/rejections.

Prompt: 
```
这是目录为blink/renderer/modules/smart_card/smart_card_connection.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/smart_card/smart_card_connection.h"

#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_smart_card_connection_status.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_smart_card_disposition.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_smart_card_protocol.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_smart_card_transaction_callback.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_smart_card_transaction_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_smart_card_transmit_options.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/modules/smart_card/smart_card_cancel_algorithm.h"
#include "third_party/blink/renderer/modules/smart_card/smart_card_context.h"
#include "third_party/blink/renderer/modules/smart_card/smart_card_error.h"
#include "third_party/blink/renderer/modules/smart_card/smart_card_util.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_associated_remote.h"

namespace blink {
namespace {
constexpr char kDisconnected[] = "Is disconnected.";
constexpr char kTransactionAlreadyExists[] =
    "This connection already has an active transaction.";
constexpr char kTransactionEndedWithPendingOperation[] =
    "Transaction callback returned while an operation was still in progress.";

using device::mojom::blink::SmartCardConnectionState;
using device::mojom::blink::SmartCardDisposition;
using device::mojom::blink::SmartCardProtocol;
using device::mojom::blink::SmartCardStatusPtr;

SmartCardDisposition ToMojomDisposition(
    const V8SmartCardDisposition& disposition) {
  switch (disposition.AsEnum()) {
    case V8SmartCardDisposition::Enum::kLeave:
      return SmartCardDisposition::kLeave;
    case V8SmartCardDisposition::Enum::kReset:
      return SmartCardDisposition::kReset;
    case V8SmartCardDisposition::Enum::kUnpower:
      return SmartCardDisposition::kUnpower;
    case V8SmartCardDisposition::Enum::kEject:
      return SmartCardDisposition::kEject;
  }
}

device::mojom::blink::SmartCardProtocol ToMojoSmartCardProtocol(
    const V8SmartCardProtocol& protocol) {
  switch (protocol.AsEnum()) {
    case blink::V8SmartCardProtocol::Enum::kRaw:
      return device::mojom::blink::SmartCardProtocol::kRaw;
    case blink::V8SmartCardProtocol::Enum::kT0:
      return device::mojom::blink::SmartCardProtocol::kT0;
    case blink::V8SmartCardProtocol::Enum::kT1:
      return device::mojom::blink::SmartCardProtocol::kT1;
  }
}

std::optional<V8SmartCardConnectionState::Enum> ToV8ConnectionState(
    SmartCardConnectionState state,
    SmartCardProtocol protocol) {
  switch (state) {
    case SmartCardConnectionState::kAbsent:
      return V8SmartCardConnectionState::Enum::kAbsent;
    case SmartCardConnectionState::kPresent:
      return V8SmartCardConnectionState::Enum::kPresent;
    case SmartCardConnectionState::kSwallowed:
      return V8SmartCardConnectionState::Enum::kSwallowed;
    case SmartCardConnectionState::kPowered:
      return V8SmartCardConnectionState::Enum::kPowered;
    case SmartCardConnectionState::kNegotiable:
      return V8SmartCardConnectionState::Enum::kNegotiable;
    case SmartCardConnectionState::kSpecific:
      switch (protocol) {
        case SmartCardProtocol::kUndefined:
          LOG(ERROR)
              << "Invalid Status result: (state=specific, protocol=undefined)";
          return std::nullopt;
        case SmartCardProtocol::kT0:
          return V8SmartCardConnectionState::Enum::kT0;
        case SmartCardProtocol::kT1:
          return V8SmartCardConnectionState::Enum::kT1;
        case SmartCardProtocol::kRaw:
          return V8SmartCardConnectionState::Enum::kRaw;
      }
  }
}

class TransactionFulfilledFunction
    : public ThenCallable<IDLNullable<V8SmartCardDisposition>,
                          TransactionFulfilledFunction> {
 public:
  explicit TransactionFulfilledFunction(SmartCardConnection* connection)
      : connection_(connection) {
    SetExceptionContext(ExceptionContext(v8::ExceptionContext::kOperation,
                                         "SmartCardConnection",
                                         "startTransaction"));
  }

  void React(ScriptState*,
             const std::optional<V8SmartCardDisposition>& disposition) {
    connection_->OnTransactionCallbackDone(
        disposition ? ToMojomDisposition(*disposition)
                    : SmartCardDisposition::kReset);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(connection_);
    ThenCallable<IDLNullable<V8SmartCardDisposition>,
                 TransactionFulfilledFunction>::Trace(visitor);
  }

 private:
  Member<SmartCardConnection> connection_;
};

class TransactionRejectedFunction
    : public ThenCallable<IDLAny, TransactionRejectedFunction> {
 public:
  explicit TransactionRejectedFunction(SmartCardConnection* connection)
      : connection_(connection) {}

  void React(ScriptState*, ScriptValue value) {
    connection_->OnTransactionCallbackFailed(value);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(connection_);
    ThenCallable<IDLAny, TransactionRejectedFunction>::Trace(visitor);
  }

 private:
  Member<SmartCardConnection> connection_;
};

}  // anonymous namespace

/////
// SmartCardConnection::TransactionState

class SmartCardConnection::TransactionState final
    : public GarbageCollected<TransactionState> {
 public:
  TransactionState(
      ScriptPromiseResolver<IDLUndefined>* start_transaction_request,
      mojo::PendingAssociatedRemote<device::mojom::blink::SmartCardTransaction>
          pending_remote,
      ExecutionContext* execution_context);
  ~TransactionState();
  void Trace(Visitor*) const;
  void SetCallbackException(DOMExceptionCode, const String& message);
  void SetCallbackException(const ScriptValue& exception);
  void SettleStartTransaction(
      device::mojom::blink::SmartCardResultPtr end_transaction_result);
  void RejectStartTransaction(DOMExceptionCode exception_code,
                              const String& message);
  bool HasPendingEnd() const;
  void SetPendingEnd(device::mojom::blink::SmartCardDisposition);
  device::mojom::blink::SmartCardDisposition TakePendingEnd();

  void EndTransaction(
      device::mojom::blink::SmartCardDisposition,
      base::OnceCallback<void(device::mojom::blink::SmartCardResultPtr)>);

  ScriptPromiseResolver<IDLUndefined>* GetStartTransactionRequest() const {
    return start_transaction_request_.Get();
  }

 private:
  Member<ScriptPromiseResolver<IDLUndefined>> start_transaction_request_;
  HeapMojoAssociatedRemote<device::mojom::blink::SmartCardTransaction>
      transaction_;
  ScriptValue callback_exception_;
  std::optional<device::mojom::blink::SmartCardDisposition> pending_end_;
};

SmartCardConnection::TransactionState::~TransactionState() = default;

SmartCardConnection::TransactionState::TransactionState(
    ScriptPromiseResolver<IDLUndefined>* start_transaction_request,
    mojo::PendingAssociatedRemote<device::mojom::blink::SmartCardTransaction>
        pending_remote,
    ExecutionContext* execution_context)
    : start_transaction_request_(start_transaction_request),
      transaction_(execution_context) {
  transaction_.Bind(std::move(pending_remote), execution_context->GetTaskRunner(
                                                   TaskType::kMiscPlatformAPI));
}

void SmartCardConnection::TransactionState::Trace(Visitor* visitor) const {
  visitor->Trace(start_transaction_request_);
  visitor->Trace(transaction_);
  visitor->Trace(callback_exception_);
}

void SmartCardConnection::TransactionState::SetCallbackException(
    DOMExceptionCode code,
    const String& message) {
  ScriptState* script_state = start_transaction_request_->GetScriptState();
  v8::Isolate* isolate = script_state->GetIsolate();

  callback_exception_ = ScriptValue(
      isolate, V8ThrowDOMException::CreateOrEmpty(isolate, code, message));
}

void SmartCardConnection::TransactionState::SetCallbackException(
    const ScriptValue& exception) {
  callback_exception_ = exception;
}

void SmartCardConnection::TransactionState::SettleStartTransaction(
    device::mojom::blink::SmartCardResultPtr end_transaction_result) {
  CHECK(!pending_end_);

  if (!callback_exception_.IsEmpty()) {
    start_transaction_request_->Reject(callback_exception_);
  } else if (end_transaction_result->is_error()) {
    SmartCardError::MaybeReject(start_transaction_request_,
                                end_transaction_result->get_error());
  } else {
    start_transaction_request_->Resolve();
  }
}

void SmartCardConnection::TransactionState::RejectStartTransaction(
    DOMExceptionCode exception_code,
    const String& message) {
  start_transaction_request_->RejectWithDOMException(exception_code, message);
}

bool SmartCardConnection::TransactionState::HasPendingEnd() const {
  return pending_end_.has_value();
}

void SmartCardConnection::TransactionState::SetPendingEnd(
    SmartCardDisposition disposition) {
  CHECK(!pending_end_);
  pending_end_ = disposition;
}

SmartCardDisposition SmartCardConnection::TransactionState::TakePendingEnd() {
  CHECK(pending_end_);
  SmartCardDisposition disposition = *pending_end_;
  pending_end_.reset();
  return disposition;
}

void SmartCardConnection::TransactionState::EndTransaction(
    SmartCardDisposition disposition,
    base::OnceCallback<void(device::mojom::blink::SmartCardResultPtr)>
        callback) {
  CHECK(!pending_end_);
  transaction_->EndTransaction(disposition, std::move(callback));
}

/////
// SmartCardConnection

SmartCardConnection::SmartCardConnection(
    mojo::PendingRemote<device::mojom::blink::SmartCardConnection>
        pending_connection,
    device::mojom::blink::SmartCardProtocol active_protocol,
    SmartCardContext* smart_card_context,
    ExecutionContext* execution_context)
    : ExecutionContextClient(execution_context),
      connection_(execution_context),
      active_protocol_(active_protocol),
      smart_card_context_(smart_card_context) {
  connection_.Bind(
      std::move(pending_connection),
      execution_context->GetTaskRunner(TaskType::kMiscPlatformAPI));
  connection_.set_disconnect_handler(WTF::BindOnce(
      &SmartCardConnection::CloseMojoConnection, WrapWeakPersistent(this)));
}

ScriptPromise<IDLUndefined> SmartCardConnection::disconnect(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  return disconnect(
      script_state,
      V8SmartCardDisposition(V8SmartCardDisposition::Enum::kLeave),
      exception_state);
}

ScriptPromise<IDLUndefined> SmartCardConnection::disconnect(
    ScriptState* script_state,
    const V8SmartCardDisposition& disposition,
    ExceptionState& exception_state) {
  if (!smart_card_context_->EnsureNoOperationInProgress(exception_state) ||
      !EnsureConnection(exception_state)) {
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  SetOperationInProgress(resolver);

  connection_->Disconnect(
      ToMojomDisposition(disposition),
      WTF::BindOnce(&SmartCardConnection::OnDisconnectDone,
                    WrapPersistent(this), WrapPersistent(resolver)));

  return resolver->Promise();
}

ScriptPromise<DOMArrayBuffer> SmartCardConnection::transmit(
    ScriptState* script_state,
    const DOMArrayPiece& send_buffer,
    SmartCardTransmitOptions* options,
    ExceptionState& exception_state) {
  if (!smart_card_context_->EnsureNoOperationInProgress(exception_state) ||
      !EnsureConnection(exception_state)) {
    return EmptyPromise();
  }

  if (send_buffer.IsDetached() || send_buffer.IsNull()) {
    exception_state.ThrowTypeError("Invalid send buffer.");
    return EmptyPromise();
  }

  device::mojom::blink::SmartCardProtocol protocol = active_protocol_;
  if (options->hasProtocol()) {
    protocol = ToMojoSmartCardProtocol(options->protocol());
  }

  if (protocol == device::mojom::blink::SmartCardProtocol::kUndefined) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "No active protocol.");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<DOMArrayBuffer>>(
      script_state, exception_state.GetContext());
  SetOperationInProgress(resolver);

  Vector<uint8_t> send_vector;
  send_vector.Append(send_buffer.Bytes(),
                     static_cast<wtf_size_t>(send_buffer.ByteLength()));

  connection_->Transmit(
      protocol, send_vector,
      WTF::BindOnce(&SmartCardConnection::OnDataResult, WrapPersistent(this),
                    WrapPersistent(resolver)));

  return resolver->Promise();
}

ScriptPromise<SmartCardConnectionStatus> SmartCardConnection::status(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!smart_card_context_->EnsureNoOperationInProgress(exception_state) ||
      !EnsureConnection(exception_state)) {
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<SmartCardConnectionStatus>>(
          script_state, exception_state.GetContext());
  SetOperationInProgress(resolver);

  connection_->Status(WTF::BindOnce(&SmartCardConnection::OnStatusDone,
                                    WrapPersistent(this),
                                    WrapPersistent(resolver)));

  return resolver->Promise();
}

ScriptPromise<DOMArrayBuffer> SmartCardConnection::control(
    ScriptState* script_state,
    uint32_t control_code,
    const DOMArrayPiece& data,
    ExceptionState& exception_state) {
  if (!smart_card_context_->EnsureNoOperationInProgress(exception_state) ||
      !EnsureConnection(exception_state)) {
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<DOMArrayBuffer>>(
      script_state, exception_state.GetContext());
  SetOperationInProgress(resolver);

  Vector<uint8_t> data_vector;

  // Note that there are control codes which require no input data.
  // Thus sending an empty data vector is fine.
  if (!data.IsDetached() && !data.IsNull() && data.ByteLength() > 0u) {
    data_vector.AppendSpan(data.ByteSpan());
  }

  connection_->Control(
      control_code, data_vector,
      WTF::BindOnce(&SmartCardConnection::OnDataResult, WrapPersistent(this),
                    WrapPersistent(resolver)));

  return resolver->Promise();
}

ScriptPromise<DOMArrayBuffer> SmartCardConnection::getAttribute(
    ScriptState* script_state,
    uint32_t tag,
    ExceptionState& exception_state) {
  if (!smart_card_context_->EnsureNoOperationInProgress(exception_state) ||
      !EnsureConnection(exception_state)) {
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<DOMArrayBuffer>>(
      script_state, exception_state.GetContext());
  SetOperationInProgress(resolver);

  connection_->GetAttrib(
      tag, WTF::BindOnce(&SmartCardConnection::OnDataResult,
                         WrapPersistent(this), WrapPersistent(resolver)));

  return resolver->Promise();
}

ScriptPromise<IDLUndefined> SmartCardConnection::setAttribute(
    ScriptState* script_state,
    uint32_t tag,
    const DOMArrayPiece& data,
    ExceptionState& exception_state) {
  if (!smart_card_context_->EnsureNoOperationInProgress(exception_state) ||
      !EnsureConnection(exception_state)) {
    return EmptyPromise();
  }

  if (data.IsDetached() || data.IsNull()) {
    exception_state.ThrowTypeError("Invalid data.");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  SetOperationInProgress(resolver);

  Vector<uint8_t> data_vector;
  data_vector.AppendSpan(data.ByteSpan());

  connection_->SetAttrib(
      tag, data_vector,
      WTF::BindOnce(&SmartCardConnection::OnPlainResult, WrapPersistent(this),
                    WrapPersistent(resolver)));

  return resolver->Promise();
}

ScriptPromise<IDLUndefined> SmartCardConnection::startTransaction(
    ScriptState* script_state,
    V8SmartCardTransactionCallback* transaction_callback,
    SmartCardTransactionOptions* options,
    ExceptionState& exception_state) {
  if (!smart_card_context_->EnsureNoOperationInProgress(exception_state) ||
      !EnsureConnection(exception_state)) {
    return EmptyPromise();
  }

  if (transaction_state_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kTransactionAlreadyExists);
    return EmptyPromise();
  }

  AbortSignal* signal = options->getSignalOr(nullptr);
  if (signal && signal->aborted()) {
    return ScriptPromise<IDLUndefined>::Reject(script_state,
                                               signal->reason(script_state));
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  SetOperationInProgress(resolver);

  AbortSignal::AlgorithmHandle* abort_handle = nullptr;
  if (signal) {
    abort_handle = signal->AddAlgorithm(
        MakeGarbageCollected<SmartCardCancelAlgorithm>(smart_card_context_));
  }

  connection_->BeginTransaction(WTF::BindOnce(
      &SmartCardConnection::OnBeginTransactionDone, WrapPersistent(this),
      WrapPersistent(resolver), WrapPersistent(transaction_callback),
      WrapPersistent(signal), WrapPersistent(abort_handle)));

  return resolver->Promise();
}

void SmartCardConnection::OnOperationInProgressCleared() {
  if (!transaction_state_ || !transaction_state_->HasPendingEnd()) {
    return;
  }

  EndTransaction(transaction_state_->TakePendingEnd());
}

void SmartCardConnection::OnTransactionCallbackDone(
    SmartCardDisposition disposition) {
  CHECK(transaction_state_);

  if (smart_card_context_->IsOperationInProgress()) {
    transaction_state_->SetCallbackException(
        DOMExceptionCode::kInvalidStateError,
        kTransactionEndedWithPendingOperation);
    transaction_state_->SetPendingEnd(disposition);
  } else {
    EndTransaction(disposition);
  }
}

void SmartCardConnection::OnTransactionCallbackFailed(
    const ScriptValue& exception) {
  CHECK(transaction_state_);

  transaction_state_->SetCallbackException(exception);

  if (smart_card_context_->IsOperationInProgress()) {
    transaction_state_->SetPendingEnd(SmartCardDisposition::kReset);
  } else {
    EndTransaction(SmartCardDisposition::kReset);
  }
}

void SmartCardConnection::Trace(Visitor* visitor) const {
  visitor->Trace(connection_);
  visitor->Trace(ongoing_request_);
  visitor->Trace(smart_card_context_);
  visitor->Trace(transaction_state_);
  ScriptWrappable::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
}

void SmartCardConnection::SetOperationInProgress(
    ScriptPromiseResolverBase* resolver) {
  smart_card_context_->SetConnectionOperationInProgress(resolver);

  if (ongoing_request_ == resolver) {
    return;
  }
  CHECK_EQ(ongoing_request_, nullptr);
  ongoing_request_ = resolver;
}

void SmartCardConnection::ClearOperationInProgress(
    ScriptPromiseResolverBase* resolver) {
  CHECK_EQ(ongoing_request_, resolver);
  ongoing_request_ = nullptr;

  smart_card_context_->ClearConnectionOperationInProgress(resolver);
}

bool SmartCardConnection::EnsureConnection(
    ExceptionState& exception_state) const {
  if (!connection_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kDisconnected);
    return false;
  }
  return true;
}

void SmartCardConnection::OnDisconnectDone(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    device::mojom::blink::SmartCardResultPtr result) {
  ClearOperationInProgress(resolver);

  if (result->is_error()) {
    SmartCardError::MaybeReject(resolver, result->get_error());
    return;
  }

  CHECK(connection_.is_bound());
  connection_.reset();

  resolver->Resolve();
}

void SmartCardConnection::OnPlainResult(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    device::mojom::blink::SmartCardResultPtr result) {
  ClearOperationInProgress(resolver);

  if (result->is_error()) {
    SmartCardError::MaybeReject(resolver, result->get_error());
    return;
  }

  resolver->Resolve();
}

void SmartCardConnection::OnDataResult(
    ScriptPromiseResolver<DOMArrayBuffer>* resolver,
    device::mojom::blink::SmartCardDataResultPtr result) {
  ClearOperationInProgress(resolver);

  if (result->is_error()) {
    SmartCardError::MaybeReject(resolver, result->get_error());
    return;
  }

  resolver->Resolve(DOMArrayBuffer::Create(result->get_data()));
}

void SmartCardConnection::OnStatusDone(
    ScriptPromiseResolver<SmartCardConnectionStatus>* resolver,
    device::mojom::blink::SmartCardStatusResultPtr result) {
  ClearOperationInProgress(resolver);

  if (result->is_error()) {
    SmartCardError::MaybeReject(resolver, result->get_error());
    return;
  }

  const SmartCardStatusPtr& mojo_status = result->get_status();

  std::optional<V8SmartCardConnectionState::Enum> connection_state =
      ToV8ConnectionState(mojo_status->state, mojo_status->protocol);

  if (!connection_state.has_value()) {
    SmartCardError::MaybeReject(
        resolver, device::mojom::blink::SmartCardError::kInternalError);
    return;
  }

  auto* status = SmartCardConnectionStatus::Create();
  status->setReaderName(mojo_status->reader_name);
  status->setState(connection_state.value());
  if (!mojo_status->answer_to_reset.empty()) {
    status->setAnswerToReset(
        DOMArrayBuffer::Create(mojo_status->answer_to_reset));
  }
  resolver->Resolve(status);
}

void SmartCardConnection::OnBeginTransactionDone(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    V8SmartCardTransactionCallback* transaction_callback,
    AbortSignal* signal,
    AbortSignal::AlgorithmHandle* abort_handle,
    device::mojom::blink::SmartCardTransactionResultPtr result) {
  CHECK(!transaction_state_);
  ClearOperationInProgress(resolver);

  if (signal && abort_handle) {
    signal->RemoveAlgorithm(abort_handle);
  }

  if (result->is_error()) {
    if (signal && signal->aborted() &&
        result->get_error() ==
            device::mojom::blink::SmartCardError::kCancelled) {
      RejectWithAbortionReason(resolver, signal);
    } else {
      SmartCardError::MaybeReject(resolver, result->get_error());
    }
    return;
  }

  transaction_state_ = MakeGarbageCollected<TransactionState>(
      resolver, std::move(result->get_transaction()), GetExecutionContext());

  ScriptState* script_state = resolver->GetScriptState();
  if (!IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                     script_state)) {
    // Can't run the transaction callback function.
    EndTransaction(SmartCardDisposition::kLeave);
    return;
  }

  ScriptState::Scope scope(script_state);
  v8::TryCatch try_catch(script_state->GetIsolate());
  auto transaction_result = transaction_callback->Invoke(nullptr);

  if (transaction_result.IsNothing()) {
    if (try_catch.HasCaught()) {
      transaction_state_->SetCallbackException(
          ScriptValue(script_state->GetIsolate(), try_catch.Exception()));
    } else {
      // Shouldn't happen, but technically possible.
      transaction_state_->SetCallbackException(
          DOMExceptionCode::kOperationError,
          "Could not run the given transaction callback function.");
    }
    EndTransaction(SmartCardDisposition::kLeave);
    return;
  }

  auto promise = transaction_result.FromJust();
  promise.Then(script_state,
               MakeGarbageCollected<TransactionFulfilledFunction>(this),
               MakeGarbageCollected<TransactionRejectedFunction>(this));
}

void SmartCardConnection::OnEndTransactionDone(
    device::mojom::blink::SmartCardResultPtr end_transaction_result) {
  CHECK(transaction_state_);
  ClearOperationInProgress(transaction_state_->GetStartTransactionRequest());

  transaction_state_->SettleStartTransaction(std::move(end_transaction_result));
  transaction_state_ = nullptr;
}

void SmartCardConnection::CloseMojoConnection() {
  connection_.reset();

  if (!ongoing_request_) {
    return;
  }

  ScriptState* script_state = ongoing_request_->GetScriptState();
  if (IsInParallelAlgorithmRunnable(ongoing_request_->GetExecutionContext(),
                                    script_state)) {
    ScriptState::Scope script_state_scope(script_state);
    ongoing_request_->RejectWithDOMException(
        DOMExceptionCode::kInvalidStateError, kDisconnected);
  }

  ClearOperationInProgress(ongoing_request_);
}

void SmartCardConnection::EndTransaction(SmartCardDisposition disposition) {
  CHECK(!smart_card_context_->IsOperationInProgress());
  CHECK(transaction_state_);

  if (!connection_.is_bound()) {
    transaction_state_->RejectStartTransaction(
        DOMExceptionCode::kInvalidStateError,
        "Cannot end transaction with an invalid connection.");
    transaction_state_ = nullptr;
    return;
  }

  transaction_state_->EndTransaction(
      disposition, WTF::BindOnce(&SmartCardConnection::OnEndTransactionDone,
                                 WrapPersistent(this)));

  SetOperationInProgress(transaction_state_->GetStartTransactionRequest());
}

}  // namespace blink

"""

```
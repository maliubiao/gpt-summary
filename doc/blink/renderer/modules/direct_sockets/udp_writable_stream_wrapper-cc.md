Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `udp_writable_stream_wrapper.cc` within the Chromium Blink engine, specifically concerning its interaction with JavaScript, HTML, and CSS. The prompt also asks for examples, logical reasoning, common errors, and debugging tips.

**2. Initial Code Scan and Key Terms Identification:**

The first step is to quickly scan the code and identify important keywords and classes. This involves looking for:

* **Class names:** `UDPWritableStreamWrapper`, `WritableStreamWrapper`, `UDPMessage`, `UDPSocketMojoRemote`
* **Namespaces:** `blink`, `network`, `net`
* **Methods:** `Write`, `CloseStream`, `ErrorStream`, `OnSend`, `OnAbortSignal`
* **Data structures/types:** `ScriptPromise`, `ScriptValue`, `DOMArrayPiece`, `net::HostPortPair`, `base::span`
* **Mojom:** `network::mojom::blink::RestrictedUDPSocketMode`, `mojom/direct_sockets/direct_sockets.mojom-blink.h`
* **Callbacks:** `CloseOnceCallback`
* **Error handling:** `ExceptionState`, `DOMExceptionCode::kNetworkError`, `net::Error`
* **JavaScript/Web Streams API related terms:** "WritableStream", "chunk", "abort signal"
* **UDP-specific terms:** "UDP", "send", "remoteAddress", "remotePort", "DNS query"

**3. Deconstructing the Class `UDPWritableStreamWrapper`:**

The core of the analysis revolves around understanding what this class does.

* **Purpose:** The name "UDPWritableStreamWrapper" strongly suggests that it's responsible for providing a writeable stream interface over a UDP socket. The "Wrapper" part indicates it's likely adapting an underlying UDP socket implementation for use within the Blink rendering engine.

* **Constructor:**  The constructor takes a `ScriptState`, a `CloseOnceCallback`, a `UDPSocketMojoRemote`, and a `RestrictedUDPSocketMode`. This tells us that the wrapper is initialized with information about the JavaScript context, how to handle closing, the underlying UDP socket (likely an interface to the network stack), and the operational mode of the socket (BOUND, CONNECTED, or NONE).

* **`Write` Method:** This is the crucial method for sending data. It takes a `ScriptValue` (representing the data from JavaScript) and an `ExceptionState`. It performs the following steps:
    * Creates a `UDPMessage` from the JavaScript input.
    * Validates the message structure (`data`, `remoteAddress`, `remotePort`, `dnsQueryType`) based on the `mode_`.
    * Extracts the data payload.
    * Creates a `ScriptPromise` to represent the asynchronous operation.
    * Calls `udp_socket_->get()->SendTo` or `Send` to send the data using the underlying UDP socket.
    * Stores the `ScriptPromiseResolver` to resolve or reject the promise later.

* **`OnSend` Method:** This is the callback invoked when the underlying UDP socket's send operation completes. It checks the result and either resolves or rejects the promise.

* **`CloseStream` Method:** Handles closing the stream.

* **`ErrorStream` Method:** Handles errors during sending, rejects the promise, and potentially errors the entire writable stream.

* **`OnAbortSignal` Method:** Handles abort signals from the associated JavaScript AbortSignal.

* **`HasPendingWrite`:**  Indicates if a write operation is currently in progress.

**4. Connecting to JavaScript, HTML, and CSS:**

The prompt specifically asks about the relationship with web technologies. The key connection is through the **Web Streams API**.

* **JavaScript:** The `UDPWritableStreamWrapper` provides the underlying implementation for a `WritableStream` object that can be used in JavaScript. The `Write` method is directly invoked when JavaScript code calls `writableStream.getWriter().write(chunk)`. The `ScriptPromise` returned by `Write` is what the JavaScript Promise resolves or rejects.

* **HTML:** While not directly related to rendering HTML, the Direct Sockets API (which this code is part of) is accessed via JavaScript, which is embedded within HTML. Therefore, the functionality enabled by this code allows JavaScript running in a web page to interact with UDP sockets.

* **CSS:**  There's generally no direct relationship between this C++ code and CSS. CSS is for styling, while this code handles network communication.

**5. Logical Reasoning and Examples:**

The `Write` method involves significant logical checks based on the socket mode and the presence of optional fields in the `UDPMessage`. Providing concrete examples helps illustrate these checks:

* **Assumptions:** The JavaScript code is attempting to send data via a `WritableStream` backed by this C++ wrapper.

* **Input/Output Example (CONNECTED mode):**
    * **Input (JavaScript):** `writer.write({ data: new Uint8Array([1, 2, 3]) });`
    * **Output (C++):** Successfully sends the data. `dest_addr` will be empty.
    * **Input (JavaScript - Error):** `writer.write({ data: new Uint8Array([1, 2, 3]), remoteAddress: '127.0.0.1', remotePort: 8080 });`
    * **Output (C++):** Throws a `TypeError` because `remoteAddress` and `remotePort` are not allowed in CONNECTED mode.

* **Input/Output Example (BOUND mode):**
    * **Input (JavaScript):** `writer.write({ data: new Uint8Array([1, 2, 3]), remoteAddress: '192.168.1.10', remotePort: 53 });`
    * **Output (C++):** Successfully sends the data to the specified address and port.
    * **Input (JavaScript - Error):** `writer.write({ data: new Uint8Array([1, 2, 3]) });`
    * **Output (C++):** Throws a `TypeError` because `remoteAddress` and `remotePort` are required in BOUND mode.

**6. Common User/Programming Errors:**

Identifying potential mistakes helps developers avoid pitfalls:

* **Incorrect `UDPMessage` format:** Missing or incorrectly formatted fields.
* **Mode mismatch:** Trying to specify remote address in CONNECTED mode or not specifying it in BOUND mode.
* **Empty data:** Attempting to send an empty `Uint8Array`.
* **Not handling promise rejections:**  Failing to catch errors that occur during the send operation.
* **Race conditions:**  Though not explicitly shown in this code snippet, issues could arise if the socket is closed or errors out while a write is pending.

**7. Debugging Clues and User Operations:**

Understanding how a user's actions lead to this code is essential for debugging:

* **User Action:** A user interacts with a web page that uses the Direct Sockets API (via JavaScript). This could involve initiating a connection, sending data, etc.
* **JavaScript API Call:** The JavaScript code uses the `WritableStream` obtained from the Direct Sockets API to send data using `writer.write()`.
* **Blink Binding:**  The JavaScript call is intercepted by Blink's JavaScript bindings and routed to the corresponding C++ implementation, which is the `UDPWritableStreamWrapper::Write` method.
* **Mojo Communication:** The `UDPWritableStreamWrapper` interacts with the underlying UDP socket implementation (likely in the browser process) using Mojo.

**8. Refinement and Organization:**

The final step involves organizing the information logically and clearly. Using headings, bullet points, and code snippets enhances readability. The process also involves refining the language to be precise and avoid jargon where possible. For example, explicitly stating the connection to the Web Streams API and clarifying the role of Mojo communication.
This C++ source file, `udp_writable_stream_wrapper.cc`, within the Chromium Blink engine, implements a wrapper around a UDP socket to provide a `WritableStream` interface that can be used by JavaScript. Essentially, it bridges the gap between the low-level UDP socket operations and the higher-level Web Streams API available in JavaScript.

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Provides a Writable Stream for UDP Sockets:** The primary function is to encapsulate a UDP socket and present it as a `WritableStream`. This allows JavaScript code to send data over UDP using the familiar Streams API.

2. **Manages Asynchronous Writes:**  UDP socket operations are asynchronous. This wrapper handles the asynchronous nature of sending data, using Promises to notify JavaScript when a send operation completes successfully or fails.

3. **Handles UDP Message Formatting:** It takes a JavaScript object (of type `UDPMessage`) as input for writing. This object contains the data to send and optionally the destination address and port. It then extracts and validates this information before sending.

4. **Supports Different UDP Socket Modes:** The wrapper takes a `RestrictedUDPSocketMode` as a parameter, which can be `BOUND`, `CONNECTED`, or `NONE`. This influences how the destination address and port are handled.
    * **CONNECTED:** The socket is connected to a specific remote address and port. Therefore, the `UDPMessage` should only contain the `data`.
    * **BOUND:** The socket is bound to a local address and port but not connected. Each `UDPMessage` must specify the `remoteAddress` and `remotePort`.
    * **NONE:**  Similar to `BOUND`, each message needs the destination.

5. **Handles DNS Resolution Hints (Optional):** The `UDPMessage` can optionally include a `dnsQueryType` to hint at the desired IP address family (IPv4 or IPv6) when resolving the destination address.

6. **Error Handling:**  It catches errors from the underlying UDP socket operations and reports them to the JavaScript Promise, resulting in the rejection of the promise and potentially an error event on the stream.

7. **Manages Stream Lifecycle:** It handles the closing of the stream and propagates errors that might occur.

**Relationship with JavaScript, HTML, and CSS:**

This C++ code is directly related to **JavaScript** through the **Web Streams API**. Here's how:

* **JavaScript API:**  JavaScript code can obtain a `WritableStream` object that is backed by this `UDPWritableStreamWrapper`. This is likely exposed through a browser API related to Direct Sockets.

* **`WritableStream` Usage:** JavaScript can then use the standard `WritableStream` methods like `getWriter()` and `write()` to send data. The `write()` method will eventually call the `UDPWritableStreamWrapper::Write` method in C++.

* **`UDPMessage` Interface:**  JavaScript creates objects conforming to the `UDPMessage` interface to specify the data and destination for sending. This interface is defined in a related IDL file (likely `direct_sockets.mojom-blink`).

**Example:**

Let's imagine JavaScript code interacting with this wrapper:

```javascript
// Assuming 'udpSocket' is an object representing the UDP socket with a writable stream
const writer = udpSocket.writable.getWriter();

// Sending data to a specific address and port (assuming the socket is in BOUND mode)
writer.write({
  data: new Uint8Array([0x01, 0x02, 0x03]),
  remoteAddress: "192.168.1.100",
  remotePort: 53
});

// Sending data on a connected socket
writer.write({ data: new Uint8Array([0x04, 0x05, 0x06]) });

writer.close();
```

In this example, when `writer.write()` is called, the JavaScript engine will eventually invoke the `UDPWritableStreamWrapper::Write` method in C++, passing the JavaScript object as a `ScriptValue`. The C++ code will then:

1. Convert the `ScriptValue` to a `UDPMessage` object.
2. Validate the message content based on the socket's mode.
3. Extract the data and destination information.
4. Call the underlying UDP socket's `SendTo` or `Send` method.
5. Manage the Promise associated with the `write()` operation.

**Relationship with HTML and CSS:**

There's no direct relationship between this C++ code and **HTML** or **CSS**. This code deals with the underlying network communication mechanism. HTML provides the structure of the web page, and CSS provides the styling. JavaScript, however, acts as the bridge, using the APIs exposed by this C++ code to interact with network functionalities.

**Logical Reasoning and Examples:**

**Hypothetical Input (from JavaScript):**

```javascript
// Assuming udpSocket is in BOUND mode
udpSocket.writable.getWriter().write({
  data: new Uint8Array([97, 98, 99]), // ASCII for 'abc'
  remoteAddress: "example.com",
  remotePort: 1234,
  dnsQueryType: "ipv4"
});
```

**Processing in `UDPWritableStreamWrapper::Write` (Simplified):**

1. **Receive `ScriptValue`:** The C++ code receives the JavaScript object as a `ScriptValue`.
2. **Create `UDPMessage`:** It attempts to create a `UDPMessage` object from the `ScriptValue`.
3. **Validation:**
   - Checks if `data` is present and not empty.
   - Checks if `remoteAddress` and `remotePort` are present (since the mode is BOUND).
   - Checks if `dnsQueryType` is a valid value ("ipv4" maps to `net::DnsQueryType::A`).
4. **Extract Data:** Extracts the `Uint8Array`'s underlying buffer.
5. **Call `SendTo`:** Calls the underlying UDP socket's `SendTo` method with:
   - `data`: The byte array `[97, 98, 99]`.
   - `dest_addr`: A `net::HostPortPair` created from "example.com" and 1234.
   - `dns_query_type`: `net::DnsQueryType::A`.
6. **Return Promise:** Returns a Promise that will be resolved or rejected based on the success of the `SendTo` operation.

**Hypothetical Output (if successful):**

The `SendTo` operation on the underlying UDP socket will succeed, and the Promise returned to JavaScript will be resolved.

**Hypothetical Output (if `remoteAddress` is missing in BOUND mode):**

The validation step in `UDPWritableStreamWrapper::Write` will fail, and a `TypeError` DOMException will be thrown in JavaScript, rejecting the Promise.

**User or Programming Common Usage Errors:**

1. **Incorrect `UDPMessage` Structure:**
   - **Error:**  JavaScript code calls `write()` with an object that doesn't have the `data` property, or has incorrect property names.
   - **Example:** `writer.write({ payload: new Uint8Array([1, 2, 3]) });` (Should be `data`)
   - **Result:** The `UDPMessage::Create` method will likely throw an exception, or the checks for `message->hasData()` will fail, leading to a `TypeError`.

2. **Mode Mismatch for Destination:**
   - **Error:**  In `CONNECTED` mode, providing `remoteAddress` and `remotePort`.
   - **Example (CONNECTED mode):** `writer.write({ data: ..., remoteAddress: "...", remotePort: ... });`
   - **Result:** The code in `UDPWritableStreamWrapper::Write` will detect this and throw a `TypeError`.
   - **Error:** In `BOUND` mode, not providing `remoteAddress` and `remotePort`.
   - **Example (BOUND mode):** `writer.write({ data: new Uint8Array([1, 2, 3]) });`
   - **Result:** The code will detect this and throw a `TypeError`.

3. **Sending Empty Data:**
   - **Error:**  Calling `write()` with an empty `Uint8Array`.
   - **Example:** `writer.write({ data: new Uint8Array() });`
   - **Result:** The code explicitly checks for empty data and throws a `TypeError`.

4. **Not Handling Promise Rejections:**
   - **Error:** JavaScript code doesn't attach a `.catch()` handler to the Promise returned by `writer.write()`.
   - **Result:** If the send operation fails (e.g., network error, invalid address), the unhandled rejection might lead to an error in the browser's developer console.

**User Operation Steps to Reach Here (Debugging Clues):**

1. **User Interaction:** The user interacts with a web page that utilizes the Direct Sockets API. This could involve clicking a button, filling a form, or the page automatically trying to send data.

2. **JavaScript API Call:** The JavaScript code in the web page uses the Direct Sockets API to obtain a UDP socket object (let's call it `udpSocket`). This likely involves calling a browser-provided API function.

3. **Get Writable Stream:** The JavaScript code accesses the `writable` property of the `udpSocket` object to get a `WritableStream`.

4. **Get Writer:** The JavaScript code calls `getWriter()` on the `WritableStream` to get a `WritableStreamDefaultWriter`.

5. **Call `write()`:** The JavaScript code calls the `write()` method of the `WritableStreamDefaultWriter`, passing a `UDPMessage` object as an argument.

6. **Blink Binding:** The JavaScript engine in Blink intercepts the `write()` call. Due to the binding between the JavaScript `WritableStream` and the C++ `UDPWritableStreamWrapper`, the execution is routed to the `UDPWritableStreamWrapper::Write` method in this C++ file.

**Debugging Tips:**

* **Set Breakpoints:** Place breakpoints in `UDPWritableStreamWrapper::Write` and related methods to inspect the values of variables, especially the `UDPMessage`, the socket mode, and the data being sent.
* **Check Network Logs:** Use the browser's developer tools (Network tab) to observe the UDP traffic being sent. Filter by UDP if possible.
* **Inspect JavaScript Errors:** Look for any `TypeError` exceptions thrown in the JavaScript console, as these often indicate problems with the `UDPMessage` format or mode mismatches.
* **Examine Mojo Communication:** If familiar with Chromium's internals, you can inspect the Mojo messages being passed between the renderer process (where Blink runs) and the browser process (where the underlying UDP socket implementation likely resides). This can help pinpoint issues in the communication between the wrapper and the socket.
* **Verify Socket State:** Ensure the underlying UDP socket is properly bound or connected before attempting to send data. The `DCHECK(udp_socket_->get().is_bound());` in the `Write` method suggests this is a requirement.

In summary, `udp_writable_stream_wrapper.cc` is a crucial component for enabling JavaScript to send data over UDP sockets using the Web Streams API within the Chromium browser. It handles the complexities of asynchronous operations, message formatting, and different socket modes, bridging the gap between high-level JavaScript and low-level network operations.

### 提示词
```
这是目录为blink/renderer/modules/direct_sockets/udp_writable_stream_wrapper.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/direct_sockets/udp_writable_stream_wrapper.h"

#include "base/metrics/histogram_functions.h"
#include "net/base/net_errors.h"
#include "third_party/blink/public/mojom/direct_sockets/direct_sockets.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_typedefs.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_socket_dns_query_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_udp_message.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/execution_context_lifecycle_observer.h"
#include "third_party/blink/renderer/core/streams/underlying_sink_base.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_controller.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_piece.h"
#include "third_party/blink/renderer/modules/direct_sockets/stream_wrapper.h"
#include "third_party/blink/renderer/modules/direct_sockets/udp_socket_mojo_remote.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"

namespace blink {

// UDPWritableStreamWrapper definition

UDPWritableStreamWrapper::UDPWritableStreamWrapper(
    ScriptState* script_state,
    CloseOnceCallback on_close,
    const Member<UDPSocketMojoRemote> udp_socket,
    network::mojom::blink::RestrictedUDPSocketMode mode)
    : WritableStreamWrapper(script_state),
      on_close_(std::move(on_close)),
      udp_socket_(udp_socket),
      mode_(mode) {
  ScriptState::Scope scope(script_state);

  auto* sink = WritableStreamWrapper::MakeForwardingUnderlyingSink(this);
  SetSink(sink);

  auto* writable = WritableStream::CreateWithCountQueueingStrategy(
      script_state, sink, /*high_water_mark=*/1);
  SetWritable(writable);
}

bool UDPWritableStreamWrapper::HasPendingWrite() const {
  return !!write_promise_resolver_;
}

void UDPWritableStreamWrapper::Trace(Visitor* visitor) const {
  visitor->Trace(udp_socket_);
  visitor->Trace(write_promise_resolver_);
  WritableStreamWrapper::Trace(visitor);
}

void UDPWritableStreamWrapper::OnAbortSignal() {
  if (write_promise_resolver_) {
    write_promise_resolver_->Reject(
        Controller()->signal()->reason(GetScriptState()));
    write_promise_resolver_ = nullptr;
  }
}

ScriptPromise<IDLUndefined> UDPWritableStreamWrapper::Write(
    ScriptValue chunk,
    ExceptionState& exception_state) {
  DCHECK(udp_socket_->get().is_bound());

  UDPMessage* message = UDPMessage::Create(GetScriptState()->GetIsolate(),
                                           chunk.V8Value(), exception_state);
  if (exception_state.HadException()) {
    return EmptyPromise();
  }

  if (!message->hasData()) {
    exception_state.ThrowTypeError("UDPMessage: missing 'data' field.");
    return EmptyPromise();
  }

  std::optional<net::HostPortPair> dest_addr;
  if (message->hasRemoteAddress() && message->hasRemotePort()) {
    if (mode_ == network::mojom::RestrictedUDPSocketMode::CONNECTED) {
      exception_state.ThrowTypeError(
          "UDPMessage: 'remoteAddress' and 'remotePort' must not be specified "
          "in 'connected' mode.");
      return EmptyPromise();
    }
    dest_addr = net::HostPortPair(message->remoteAddress().Utf8(),
                                  message->remotePort());
  } else if (message->hasRemoteAddress() || message->hasRemotePort()) {
    exception_state.ThrowTypeError(
        "UDPMessage: either none or both 'remoteAddress' and 'remotePort' "
        "fields must be specified.");
    return EmptyPromise();
  } else if (mode_ == network::mojom::RestrictedUDPSocketMode::BOUND) {
    exception_state.ThrowTypeError(
        "UDPMessage: 'remoteAddress' and 'remotePort' must be specified "
        "in 'bound' mode.");
    return EmptyPromise();
  }

  auto dns_query_type = net::DnsQueryType::UNSPECIFIED;
  if (message->hasDnsQueryType()) {
    if (mode_ == network::mojom::RestrictedUDPSocketMode::CONNECTED) {
      exception_state.ThrowTypeError(
          "UDPMessage: 'dnsQueryType' must not be specified "
          "in 'connected' mode.");
      return EmptyPromise();
    }
    switch (message->dnsQueryType().AsEnum()) {
      case V8SocketDnsQueryType::Enum::kIpv4:
        dns_query_type = net::DnsQueryType::A;
        break;
      case V8SocketDnsQueryType::Enum::kIpv6:
        dns_query_type = net::DnsQueryType::AAAA;
        break;
    }
  }

  DOMArrayPiece array_piece(message->data());
  base::span<const uint8_t> data{array_piece.Bytes(), array_piece.ByteLength()};

  if (data.empty()) {
    exception_state.ThrowTypeError(
        "UDPMessage: 'data' field must not be empty.");
    return EmptyPromise();
  }

  DCHECK(!write_promise_resolver_);
  write_promise_resolver_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
          GetScriptState(), exception_state.GetContext());

  auto callback = WTF::BindOnce(&UDPWritableStreamWrapper::OnSend,
                                WrapWeakPersistent(this));
  if (dest_addr) {
    udp_socket_->get()->SendTo(data, *dest_addr, dns_query_type,
                               std::move(callback));
  } else {
    udp_socket_->get()->Send(data, std::move(callback));
  }
  return write_promise_resolver_->Promise();
}

void UDPWritableStreamWrapper::OnSend(int32_t result) {
  if (write_promise_resolver_) {
    if (result == net::Error::OK) {
      write_promise_resolver_->Resolve();
      write_promise_resolver_ = nullptr;
    } else {
      ErrorStream(result);
    }
    DCHECK(!write_promise_resolver_);
  }
}

void UDPWritableStreamWrapper::CloseStream() {
  if (GetState() != State::kOpen) {
    return;
  }
  SetState(State::kClosed);
  DCHECK(!write_promise_resolver_);

  std::move(on_close_).Run(/*exception=*/ScriptValue());
}

void UDPWritableStreamWrapper::ErrorStream(int32_t error_code) {
  if (GetState() != State::kOpen) {
    return;
  }
  SetState(State::kAborted);

  // Error codes are negative.
  base::UmaHistogramSparse("DirectSockets.UDPWritableStreamError", -error_code);

  auto* script_state = write_promise_resolver_
                           ? write_promise_resolver_->GetScriptState()
                           : GetScriptState();
  // Scope is needed because there's no ScriptState* on the call stack for
  // ScriptValue.
  ScriptState::Scope scope{script_state};

  auto exception = ScriptValue(
      script_state->GetIsolate(),
      V8ThrowDOMException::CreateOrDie(script_state->GetIsolate(),
                                       DOMExceptionCode::kNetworkError,
                                       String{"Stream aborted by the remote: " +
                                              net::ErrorToString(error_code)}));

  if (write_promise_resolver_) {
    write_promise_resolver_->Reject(exception);
    write_promise_resolver_ = nullptr;
  } else {
    Controller()->error(script_state, exception);
  }

  std::move(on_close_).Run(exception);
}

}  // namespace blink
```
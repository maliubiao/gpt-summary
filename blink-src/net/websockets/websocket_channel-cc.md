Response:
The user wants to understand the functionality of the `websocket_channel.cc` file in Chromium's networking stack. I need to analyze the provided code snippet and identify its core responsibilities. I also need to relate its functionality to JavaScript, provide examples with hypothetical inputs and outputs, explain potential user errors, and describe how user actions lead to this code. Finally, I need to summarize the functionality as requested in "Part 1".

Here's a breakdown of the analysis:

1. **Core Functionality:** The code manages the lifecycle of a WebSocket connection, handling tasks like initiating connections, sending and receiving data frames, managing the closing handshake, and error handling.

2. **Relationship with JavaScript:**  JavaScript's `WebSocket` API is the primary way web pages interact with WebSockets. This C++ code likely implements the underlying network logic triggered by JavaScript API calls.

3. **Logic and Examples:**  Consider the flow of sending or receiving a message. How does the data get formatted, and what are the expected outcomes?

4. **User Errors:**  What actions by a web developer using the `WebSocket` API could lead to errors handled by this code?

5. **User Actions as Debugging Clues:**  Trace the sequence of steps a user takes in a browser that eventually leads to the execution of this C++ code.

6. **Summarization:** Concisely describe the main responsibilities of the `WebSocketChannel` class based on the provided code.
```
功能列举:
```
这个C++源代码文件 `websocket_channel.cc` 定义了 `WebSocketChannel` 类，它在 Chromium 的网络栈中负责管理单个 WebSocket 连接的生命周期。其主要功能包括：

1. **建立连接:**
   - 发起 WebSocket 连接请求 (`SendAddChannelRequest`, `SendAddChannelRequestWithSuppliedCallback`).
   - 处理连接建立过程中的成功 (`OnConnectSuccess`) 和失败 (`OnConnectFailure`)。
   - 处理 TLS 证书错误 (`OnSSLCertificateError`) 和 HTTP 认证 (`OnAuthRequired`)。
   - 传递连接建立握手请求信息 (`OnStartOpeningHandshake`).
   - 与 `WebSocketStream` 合作，后者负责底层的 socket 连接和握手协议。

2. **发送数据帧:**
   - 将要发送的数据封装成 WebSocket 数据帧 (`SendFrame`).
   - 管理发送缓冲区 (`SendBuffer`).
   - 调用 `WebSocketStream` 的方法将帧写入 socket (`WriteFrames`).
   - 处理写入完成的回调 (`OnWriteDone`).
   - 进行 UTF-8 编码验证，确保发送的文本消息符合规范。

3. **接收数据帧:**
   - 调用 `WebSocketStream` 的方法从 socket 读取数据帧 (`ReadFrames`).
   - 处理读取完成的回调 (`OnReadDone`).
   - 解析接收到的 WebSocket 帧头和负载 (`HandleFrame`).
   - 根据帧的操作码 (opcode) 执行相应的处理 (`HandleFrameByState`):
     - 处理数据帧 (文本、二进制、延续帧) (`HandleDataFrame`).
     - 响应 Ping 帧，发送 Pong 帧.
     - 处理 Pong 帧 (虽然目前看起来没有特定操作).
     - 处理 Close 帧 (`HandleCloseFrame`).
   - 进行 UTF-8 编码验证，确保接收到的文本消息符合规范。

4. **关闭连接:**
   - 发起关闭握手 (`StartClosingHandshake`).
   - 发送 Close 帧 (`SendClose`).
   - 响应服务器发起的关闭握手 (`RespondToClosingHandshake`).
   - 处理关闭握手超时 (`CloseTimeout`).
   - 管理连接关闭的状态转换。

5. **错误处理:**
   - 处理各种网络错误和 WebSocket 协议错误。
   - 当发生错误时，通知上层 (通常是渲染进程) (`event_interface_->OnFailChannel`).

6. **状态管理:**
   - 维护 WebSocket 连接的当前状态 (`state_`)，例如 `FRESHLY_CONSTRUCTED`, `CONNECTING`, `CONNECTED`, `SEND_CLOSED`, `CLOSE_WAIT`, `CLOSED` 等。

7. **日志记录:**
   - 使用 `net::NetLogWithSource` 记录网络事件，用于调试和监控。

```
```
与javascript的功能的关系举例说明:
```
`WebSocketChannel` 的功能是 JavaScript `WebSocket` API 的底层实现支撑。当 JavaScript 代码中使用 `WebSocket` 对象进行连接、发送和接收数据时，最终会调用到 `WebSocketChannel` 的相应方法。

**举例说明:**

1. **JavaScript 发起连接:**
   ```javascript
   const ws = new WebSocket('ws://example.com/socket');
   ```
   -  **C++ 对应:** 这段 JavaScript 代码会在浏览器内部触发一系列操作，最终会调用到 `WebSocketChannel::SendAddChannelRequest` 或 `WebSocketChannel::SendAddChannelRequestWithSuppliedCallback`，开始 WebSocket 连接的建立过程。

2. **JavaScript 发送文本消息:**
   ```javascript
   ws.send('Hello, WebSocket!');
   ```
   - **C++ 对应:**  `ws.send()` 在底层会将消息传递给 Chromium 的网络栈，最终会调用到 `WebSocketChannel::SendFrame` 方法。`SendFrame` 会将 "Hello, WebSocket!" 封装成一个文本类型的 WebSocket 数据帧，并将其添加到发送缓冲区。

3. **JavaScript 接收消息:**
   ```javascript
   ws.onmessage = (event) => {
     console.log('Received message:', event.data);
   };
   ```
   - **C++ 对应:** 当 `WebSocketChannel` 通过底层的 socket 接收到数据帧后，`WebSocketChannel::OnReadDone` 和 `WebSocketChannel::HandleFrame` 会被调用来解析数据帧。如果是文本数据帧，`WebSocketChannel::HandleDataFrame` 会提取出消息内容，并通过 `event_interface_->OnDataFrame` 将数据传递给上层 (通常是渲染进程)，最终触发 JavaScript 的 `onmessage` 事件，并将接收到的数据 ( `event.data`) 传递给 JavaScript。

4. **JavaScript 关闭连接:**
   ```javascript
   ws.close(1000, 'Normal closure');
   ```
   - **C++ 对应:**  `ws.close()` 会调用到 `WebSocketChannel::StartClosingHandshake` 方法，并传入关闭代码 (1000) 和原因 ('Normal closure')。`StartClosingHandshake` 会构造一个 Close 帧，并调用 `WebSocketChannel::SendClose` 发送给服务器。

**总结:**  `WebSocketChannel` 就像是 `WebSocket` API 的 C++ 后端引擎，负责处理所有与网络通信和 WebSocket 协议相关的底层操作，而 JavaScript 的 `WebSocket` API 提供了方便开发者使用的接口。
```
```
逻辑推理的假设输入与输出:
```
**场景：客户端发送一个文本消息 "Test Message"**

**假设输入:**

- `fin`: `true` (假设这是一个完整的消息，不是分片发送)
- `op_code`: `WebSocketFrameHeader::kOpCodeText`
- `buffer`: 一个 `IOBuffer`，包含字符串 "Test Message"
- `buffer_size`: 12

**逻辑推理过程:**

1. `WebSocketChannel::SendFrame` 被调用，传入上述参数。
2. 首先检查连接状态，假设当前状态为 `CONNECTED`。
3. 进行 UTF-8 验证，"Test Message" 是有效的 UTF-8 字符串，验证通过。
4. `WebSocketChannel::SendFrameInternal` 被调用。
5. 创建一个 `WebSocketFrame` 对象，设置 `fin` 为 `true`，`opcode` 为 `kOpCodeText`，`payload_length` 为 12。
6. 将数据复制到 frame 的 payload 中。
7. 将该 frame 添加到 `data_to_send_next_` (如果当前没有正在发送的数据) 或 `data_being_sent_` 的发送缓冲区中。
8. 如果没有其他数据正在发送，则调用 `WebSocketChannel::WriteFrames`。
9. `WebSocketChannel::WriteFrames` 调用 `stream_->WriteFrames` 将 frame 发送到网络。

**假设输出 (如果发送成功):**

- `stream_->WriteFrames` 返回 `OK` 或 `ERR_IO_PENDING`。
- 如果返回 `OK`，`WebSocketChannel::OnWriteDone` 会被同步调用。
- 如果返回 `ERR_IO_PENDING`，当数据发送完成时，`WebSocketChannel::OnWriteDone` 会被异步调用。
- 在 `OnWriteDone` 中，如果没有更多数据要发送，`data_being_sent_` 会被重置，并且 `event_interface_->OnSendDataFrameDone()` 会被调用，通知上层数据发送完成。

**场景：服务器发送一个关闭帧，状态码 1000，原因 "Goodbye"**

**假设输入 (接收到的帧数据):**

- `frame->header.opcode`: `WebSocketFrameHeader::kOpCodeClose`
- `frame->header.final`: `true`
- `frame->payload`: 包含关闭状态码 (0x03E8，即 1000 的大端表示) 和原因字符串 "Goodbye"。

**逻辑推理过程:**

1. `WebSocketChannel::OnReadDone` 被调用，处理从 socket 读取到的数据。
2. 遍历 `read_frames_` 中的帧，`WebSocketChannel::HandleFrame` 被调用。
3. `HandleFrame` 检查帧是否被 masking (服务器发送的不能被 masking)。
4. `HandleFrameByState` 被调用，根据 `opcode` ( `kOpCodeClose`) 进入相应的处理分支。
5. `WebSocketChannel::HandleCloseFrame` 被调用。
6. `ParseClose` 函数解析 payload，提取出 code 1000 和 reason "Goodbye"。
7. 根据当前的 `state_` 执行相应的操作。例如，如果 `state_` 是 `CONNECTED`，则设置 `has_received_close_frame_` 为 `true`，保存 `received_close_code_` 和 `received_close_reason_`。如果当前没有待发送的数据，则调用 `RespondToClosingHandshake`。

**假设输出:**

- 如果当前状态是 `CONNECTED` 且没有待发送的数据，`RespondToClosingHandshake` 会被调用，它会发送一个 Close 帧作为响应，并将状态转换为 `RECV_CLOSED`。
- 上层会通过 `event_interface_->OnClose` (具体方法名可能不同) 收到关闭通知，包含状态码 1000 和原因 "Goodbye"。
```
```
涉及用户或者编程常见的使用错误:
```
**1. 发送无效的关闭状态码:**

- **用户操作/编程错误:** 在 JavaScript 中调用 `ws.close()` 时，传入了无效的关闭状态码。例如，传入 1006 (保留状态码) 或者超出允许范围的数字。
- **C++ 处理:** `WebSocketChannel::StartClosingHandshake` 中的 `IsStrictlyValidCloseStatusCode` 函数会检测到这个错误。
- **C++ 行为:**  `WebSocketChannel` 会发送一个状态码为 1011 (Internal Server Error) 的 Close 帧，并可能记录错误日志。

**2. 发送过长的关闭原因:**

- **用户操作/编程错误:** 在 JavaScript 中调用 `ws.close()` 时，传入的关闭原因字符串长度超过了 `kMaximumCloseReasonLength` (123 字节)。
- **C++ 处理:** `WebSocketChannel::StartClosingHandshake` 会检查原因字符串的长度。
- **C++ 行为:** `WebSocketChannel` 会发送一个状态码为 1011 的 Close 帧，原因字符串可能被截断或忽略，并可能记录错误日志。

**3. 在连接关闭后尝试发送数据:**

- **用户操作/编程错误:** JavaScript 代码在 `WebSocket` 连接的 `onclose` 事件触发后，仍然尝试调用 `ws.send()` 发送数据。
- **C++ 处理:** `WebSocketChannel::SendFrame` 会检查连接状态。如果连接处于关闭状态 (`InClosingState()` 返回 `true`)。
- **C++ 行为:**  `SendFrame` 会直接返回，不会发送数据，并可能记录警告日志。

**4. 接收到服务器发送的 Masked 帧:**

- **服务器编程错误 (用户通常无法控制):**  WebSocket 协议规定服务器不能发送 Masked 帧。如果客户端 (`WebSocketChannel`) 接收到这样的帧。
- **C++ 处理:** `WebSocketChannel::HandleFrame` 会检测到 `frame->header.masked` 为真。
- **C++ 行为:** `WebSocketChannel` 会认为这是一个协议错误，调用 `FailChannel` 关闭连接，并发送一个状态码为 1002 (Protocol Error) 的 Close 帧。

**5. 发送包含无效 UTF-8 字符的文本消息:**

- **用户操作/编程错误:** JavaScript 代码尝试通过 WebSocket 发送包含无效 UTF-8 编码的字符串。
- **C++ 处理:** `WebSocketChannel::SendFrame` 中会使用 `StreamingUtf8Validator` 验证发送的文本数据。
- **C++ 行为:** 如果检测到无效的 UTF-8 字符，`WebSocketChannel` 会调用 `FailChannel` 关闭连接，并可能发送一个状态码为 1009 (Message Too Big) 的 Close 帧 (虽然错误信息中提到的是 "Going Away"，实际可能使用其他更合适的错误码)。

**6. 接收到非预期的延续帧或未完成的消息序列:**

- **服务器编程错误 (用户通常无法控制):** 服务器发送了错误的帧序列，例如在没有起始文本或二进制帧的情况下发送了延续帧，或者消息分片没有以 final 位为 true 的帧结束。
- **C++ 处理:** `WebSocketChannel::HandleDataFrame` 会根据 `expecting_to_handle_continuation_` 状态来判断是否收到了预期的帧。
- **C++ 行为:** 如果收到非预期的延续帧或开始了一个新的消息但之前的消息未完成，`WebSocketChannel` 会调用 `FailChannel` 关闭连接，并发送一个状态码为 1002 (Protocol Error) 的 Close 帧。

```
```
用户操作是如何一步步的到达这里，作为调试线索:
```
为了说明用户操作如何一步步到达 `websocket_channel.cc` 中的代码，我们以一个典型的 WebSocket 使用场景为例：用户在一个网页上与 WebSocket 服务器进行交互。

**场景：用户在网页上点击一个按钮，导致发送一条消息到 WebSocket 服务器。**

1. **用户操作:** 用户在浏览器中打开一个包含 WebSocket 功能的网页，并点击了网页上的一个按钮。

2. **JavaScript 事件处理:** 按钮的点击事件被 JavaScript 代码捕获。

3. **调用 WebSocket API:** JavaScript 的事件处理函数中，调用了 `WebSocket` 对象的 `send()` 方法来发送消息。例如：
   ```javascript
   const socket = new WebSocket('ws://example.com/socket');
   // ... (连接建立后)
   document.getElementById('sendButton').addEventListener('click', () => {
     socket.send('Hello from the user!');
   });
   ```

4. **浏览器内部处理 (Renderer Process):**  JavaScript 的 `socket.send()` 调用会触发浏览器渲染进程 (Renderer Process) 中的相关代码，对要发送的数据进行初步处理。

5. **传递到网络进程 (Network Process):** 渲染进程会将要发送的 WebSocket 消息通过 IPC (Inter-Process Communication) 传递给浏览器进程的网络服务 (Network Service)，该服务运行在独立的网络进程中。

6. **创建 WebSocketChannel (如果尚未存在):**  网络进程接收到发送消息的请求后，会找到与该 WebSocket 连接对应的 `WebSocketChannel` 对象。如果连接尚未建立，则会先创建 `WebSocketChannel` 并开始连接握手。

7. **调用 WebSocketChannel::SendFrame:**  网络进程中的代码最终会调用到 `net/websockets/websocket_channel.cc` 文件中的 `WebSocketChannel::SendFrame` 方法。

8. **帧的构建和发送:** 在 `SendFrame` 方法中，消息 "Hello from the user!" 会被封装成一个 WebSocket 数据帧（文本帧）。帧头会包含操作码 (Text)、FIN 位等信息。数据会被放入帧的 payload 中。

9. **调用 WebSocketStream::WriteFrames:** `WebSocketChannel` 会调用其内部持有的 `WebSocketStream` 对象的 `WriteFrames` 方法，将构建好的 WebSocket 帧传递给 `WebSocketStream` 进行进一步处理和发送。

10. **Socket 写入:** `WebSocketStream` 负责将 WebSocket 帧的数据写入底层的 TCP socket 连接。

11. **数据传输:** 数据通过网络传输到 WebSocket 服务器。

**调试线索:**

当需要调试 WebSocket 相关问题时，以上步骤可以作为线索：

- **检查 JavaScript 代码:** 确认 `WebSocket` 对象是否正确创建，`send()` 方法是否被正确调用，以及要发送的数据是否符合预期。
- **使用浏览器开发者工具:**  浏览器的 Network 面板可以查看 WebSocket 连接的详细信息，包括发送和接收的帧数据、状态码等。这有助于确认数据是否到达了网络层。
- **抓包分析 (如 Wireshark):** 可以捕获网络数据包，查看实际发送和接收的 WebSocket 帧的结构和内容，确认是否符合协议规范。
- **查看 Chromium 网络日志 (net-internals):**  在浏览器的地址栏输入 `chrome://net-internals/#sockets` 和 `chrome://net-internals/#events` 可以查看底层的 socket 连接信息和网络事件日志，包括 WebSocket 相关的事件，例如连接建立、帧的发送和接收等。这些日志可以提供 `WebSocketChannel` 和 `WebSocketStream` 内部操作的详细信息。
- **设置断点:**  在 `websocket_channel.cc` 的关键方法（例如 `SendFrame`, `OnReadDone`, `HandleFrame`）设置断点，可以跟踪代码的执行流程，查看变量的值，帮助理解数据是如何被处理的，以及在哪个环节出现了问题。

通过以上步骤和调试工具，可以逐步定位 WebSocket 通信过程中出现的问题，例如是 JavaScript 代码错误、网络连接问题、服务器端错误，还是 Chromium 网络栈的内部错误。
```
```
功能归纳 (第1部分):
```
`net/websockets/websocket_channel.cc` 的主要功能是作为 Chromium 网络栈中 WebSocket 连接的核心管理模块。它负责 WebSocket 连接的建立、数据帧的发送和接收（包括 UTF-8 验证）、以及连接关闭握手的处理。 它将上层（通常是渲染进程中的 JavaScript WebSocket API）的请求转换为底层的 WebSocket 协议操作，并与 `WebSocketStream` 协同工作来完成实际的网络数据传输。此外，它还处理连接过程中的错误和状态管理，并提供日志记录以辅助调试。
```

Prompt: 
```
这是目录为net/websockets/websocket_channel.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/websockets/websocket_channel.h"

#include <limits.h>  // for INT_MAX
#include <stddef.h>
#include <string.h>

#include <algorithm>
#include <iterator>
#include <ostream>
#include <string_view>
#include <utility>
#include <vector>

#include "base/big_endian.h"
#include "base/check.h"
#include "base/check_op.h"
#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/numerics/byte_conversions.h"
#include "base/numerics/safe_conversions.h"
#include "base/ranges/algorithm.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/http/http_response_headers.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "net/storage_access_api/status.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/websockets/websocket_errors.h"
#include "net/websockets/websocket_event_interface.h"
#include "net/websockets/websocket_frame.h"
#include "net/websockets/websocket_handshake_request_info.h"
#include "net/websockets/websocket_handshake_response_info.h"
#include "net/websockets/websocket_stream.h"

namespace net {
class AuthChallengeInfo;
class AuthCredentials;
class SSLInfo;

namespace {

using base::StreamingUtf8Validator;

constexpr size_t kWebSocketCloseCodeLength = 2;
// Timeout for waiting for the server to acknowledge a closing handshake.
constexpr int kClosingHandshakeTimeoutSeconds = 60;
// We wait for the server to close the underlying connection as recommended in
// https://tools.ietf.org/html/rfc6455#section-7.1.1
// We don't use 2MSL since there're server implementations that don't follow
// the recommendation and wait for the client to close the underlying
// connection. It leads to unnecessarily long time before CloseEvent
// invocation. We want to avoid this rather than strictly following the spec
// recommendation.
constexpr int kUnderlyingConnectionCloseTimeoutSeconds = 2;

using ChannelState = WebSocketChannel::ChannelState;

// Maximum close reason length = max control frame payload -
//                               status code length
//                             = 125 - 2
constexpr size_t kMaximumCloseReasonLength = 125 - kWebSocketCloseCodeLength;

// Check a close status code for strict compliance with RFC6455. This is only
// used for close codes received from a renderer that we are intending to send
// out over the network. See ParseCloseFrame() for the restrictions on incoming
// close codes. The |code| parameter is type int for convenience of
// implementation; the real type is uint16_t. Code 1005 is treated specially; it
// cannot be set explicitly by Javascript but the renderer uses it to indicate
// we should send a Close frame with no payload.
bool IsStrictlyValidCloseStatusCode(int code) {
  static constexpr int kInvalidRanges[] = {
      // [BAD, OK)
      0,    1000,   // 1000 is the first valid code
      1006, 1007,   // 1006 MUST NOT be set.
      1014, 3000,   // 1014 unassigned; 1015 up to 2999 are reserved.
      5000, 65536,  // Codes above 5000 are invalid.
  };
  const int* const kInvalidRangesEnd =
      kInvalidRanges + std::size(kInvalidRanges);

  DCHECK_GE(code, 0);
  DCHECK_LT(code, 65536);
  const int* upper = std::upper_bound(kInvalidRanges, kInvalidRangesEnd, code);
  DCHECK_NE(kInvalidRangesEnd, upper);
  DCHECK_GT(upper, kInvalidRanges);
  DCHECK_GT(*upper, code);
  DCHECK_LE(*(upper - 1), code);
  return ((upper - kInvalidRanges) % 2) == 0;
}

// Sets |name| to the name of the frame type for the given |opcode|. Note that
// for all of Text, Binary and Continuation opcode, this method returns
// "Data frame".
void GetFrameTypeForOpcode(WebSocketFrameHeader::OpCode opcode,
                           std::string* name) {
  switch (opcode) {
    case WebSocketFrameHeader::kOpCodeText:    // fall-thru
    case WebSocketFrameHeader::kOpCodeBinary:  // fall-thru
    case WebSocketFrameHeader::kOpCodeContinuation:
      *name = "Data frame";
      break;

    case WebSocketFrameHeader::kOpCodePing:
      *name = "Ping";
      break;

    case WebSocketFrameHeader::kOpCodePong:
      *name = "Pong";
      break;

    case WebSocketFrameHeader::kOpCodeClose:
      *name = "Close";
      break;

    default:
      *name = "Unknown frame type";
      break;
  }

  return;
}

base::Value::Dict NetLogFailParam(uint16_t code,
                                  std::string_view reason,
                                  std::string_view message) {
  base::Value::Dict dict;
  dict.Set("code", code);
  dict.Set("reason", reason);
  dict.Set("internal_reason", message);
  return dict;
}

class DependentIOBuffer : public WrappedIOBuffer {
 public:
  DependentIOBuffer(scoped_refptr<IOBufferWithSize> buffer, size_t offset)
      : WrappedIOBuffer(buffer->span().subspan(offset)),
        buffer_(std::move(buffer)) {}

 private:
  ~DependentIOBuffer() override {
    // Prevent `data_` from dangling should this destructor remove the
    // last reference to `buffer_`.
    data_ = nullptr;
  }

  scoped_refptr<IOBufferWithSize> buffer_;
};

}  // namespace

// A class to encapsulate a set of frames and information about the size of
// those frames.
class WebSocketChannel::SendBuffer {
 public:
  SendBuffer() = default;

  // Add a WebSocketFrame to the buffer and increase total_bytes_.
  void AddFrame(std::unique_ptr<WebSocketFrame> chunk,
                scoped_refptr<IOBuffer> buffer);

  // Return a pointer to the frames_ for write purposes.
  std::vector<std::unique_ptr<WebSocketFrame>>* frames() { return &frames_; }

 private:
  // References of each WebSocketFrame.data;
  std::vector<scoped_refptr<IOBuffer>> buffers_;
  // The frames_ that will be sent in the next call to WriteFrames().
  // Note: The frames_ can contain non-owning pointers to buffers_.
  std::vector<std::unique_ptr<WebSocketFrame>> frames_;

  // The total size of the payload data in |frames_|. This will be used to
  // measure the throughput of the link.
  // TODO(ricea): Measure the throughput of the link.
  uint64_t total_bytes_ = 0;
};

void WebSocketChannel::SendBuffer::AddFrame(
    std::unique_ptr<WebSocketFrame> frame,
    scoped_refptr<IOBuffer> buffer) {
  total_bytes_ += frame->header.payload_length;
  frames_.push_back(std::move(frame));
  buffers_.push_back(std::move(buffer));
}

// Implementation of WebSocketStream::ConnectDelegate that simply forwards the
// calls on to the WebSocketChannel that created it.
class WebSocketChannel::ConnectDelegate
    : public WebSocketStream::ConnectDelegate {
 public:
  explicit ConnectDelegate(WebSocketChannel* creator) : creator_(creator) {}

  ConnectDelegate(const ConnectDelegate&) = delete;
  ConnectDelegate& operator=(const ConnectDelegate&) = delete;

  void OnCreateRequest(URLRequest* request) override {
    creator_->OnCreateURLRequest(request);
  }

  void OnURLRequestConnected(URLRequest* request,
                             const TransportInfo& info) override {
    creator_->OnURLRequestConnected(request, info);
  }

  void OnSuccess(
      std::unique_ptr<WebSocketStream> stream,
      std::unique_ptr<WebSocketHandshakeResponseInfo> response) override {
    creator_->OnConnectSuccess(std::move(stream), std::move(response));
    // |this| may have been deleted.
  }

  void OnFailure(const std::string& message,
                 int net_error,
                 std::optional<int> response_code) override {
    creator_->OnConnectFailure(message, net_error, response_code);
    // |this| has been deleted.
  }

  void OnStartOpeningHandshake(
      std::unique_ptr<WebSocketHandshakeRequestInfo> request) override {
    creator_->OnStartOpeningHandshake(std::move(request));
  }

  void OnSSLCertificateError(
      std::unique_ptr<WebSocketEventInterface::SSLErrorCallbacks>
          ssl_error_callbacks,
      int net_error,
      const SSLInfo& ssl_info,
      bool fatal) override {
    creator_->OnSSLCertificateError(std::move(ssl_error_callbacks), net_error,
                                    ssl_info, fatal);
  }

  int OnAuthRequired(const AuthChallengeInfo& auth_info,
                     scoped_refptr<HttpResponseHeaders> headers,
                     const IPEndPoint& remote_endpoint,
                     base::OnceCallback<void(const AuthCredentials*)> callback,
                     std::optional<AuthCredentials>* credentials) override {
    return creator_->OnAuthRequired(auth_info, std::move(headers),
                                    remote_endpoint, std::move(callback),
                                    credentials);
  }

 private:
  // A pointer to the WebSocketChannel that created this object. There is no
  // danger of this pointer being stale, because deleting the WebSocketChannel
  // cancels the connect process, deleting this object and preventing its
  // callbacks from being called.
  const raw_ptr<WebSocketChannel> creator_;
};

WebSocketChannel::WebSocketChannel(
    std::unique_ptr<WebSocketEventInterface> event_interface,
    URLRequestContext* url_request_context)
    : event_interface_(std::move(event_interface)),
      url_request_context_(url_request_context),
      closing_handshake_timeout_(
          base::Seconds(kClosingHandshakeTimeoutSeconds)),
      underlying_connection_close_timeout_(
          base::Seconds(kUnderlyingConnectionCloseTimeoutSeconds)) {}

WebSocketChannel::~WebSocketChannel() {
  // The stream may hold a pointer to read_frames_, and so it needs to be
  // destroyed first.
  stream_.reset();
  // The timer may have a callback pointing back to us, so stop it just in case
  // someone decides to run the event loop from their destructor.
  close_timer_.Stop();
}

void WebSocketChannel::SendAddChannelRequest(
    const GURL& socket_url,
    const std::vector<std::string>& requested_subprotocols,
    const url::Origin& origin,
    const SiteForCookies& site_for_cookies,
    StorageAccessApiStatus storage_access_api_status,
    const IsolationInfo& isolation_info,
    const HttpRequestHeaders& additional_headers,
    NetworkTrafficAnnotationTag traffic_annotation) {
  SendAddChannelRequestWithSuppliedCallback(
      socket_url, requested_subprotocols, origin, site_for_cookies,
      storage_access_api_status, isolation_info, additional_headers,
      traffic_annotation,
      base::BindOnce(&WebSocketStream::CreateAndConnectStream));
}

void WebSocketChannel::SetState(State new_state) {
  DCHECK_NE(state_, new_state);

  state_ = new_state;
}

bool WebSocketChannel::InClosingState() const {
  // The state RECV_CLOSED is not supported here, because it is only used in one
  // code path and should not leak into the code in general.
  DCHECK_NE(RECV_CLOSED, state_)
      << "InClosingState called with state_ == RECV_CLOSED";
  return state_ == SEND_CLOSED || state_ == CLOSE_WAIT || state_ == CLOSED;
}

WebSocketChannel::ChannelState WebSocketChannel::SendFrame(
    bool fin,
    WebSocketFrameHeader::OpCode op_code,
    scoped_refptr<IOBuffer> buffer,
    size_t buffer_size) {
  DCHECK_LE(buffer_size, static_cast<size_t>(INT_MAX));
  DCHECK(stream_) << "Got SendFrame without a connection established; fin="
                  << fin << " op_code=" << op_code
                  << " buffer_size=" << buffer_size;

  if (InClosingState()) {
    DVLOG(1) << "SendFrame called in state " << state_
             << ". This may be a bug, or a harmless race.";
    return CHANNEL_ALIVE;
  }

  DCHECK_EQ(state_, CONNECTED);

  DCHECK(WebSocketFrameHeader::IsKnownDataOpCode(op_code))
      << "Got SendFrame with bogus op_code " << op_code << " fin=" << fin
      << " buffer_size=" << buffer_size;

  if (op_code == WebSocketFrameHeader::kOpCodeText ||
      (op_code == WebSocketFrameHeader::kOpCodeContinuation &&
       sending_text_message_)) {
    StreamingUtf8Validator::State state = outgoing_utf8_validator_.AddBytes(
        base::make_span(buffer->bytes(), buffer_size));
    if (state == StreamingUtf8Validator::INVALID ||
        (state == StreamingUtf8Validator::VALID_MIDPOINT && fin)) {
      // TODO(ricea): Kill renderer.
      FailChannel("Browser sent a text frame containing invalid UTF-8",
                  kWebSocketErrorGoingAway, "");
      return CHANNEL_DELETED;
      // |this| has been deleted.
    }
    sending_text_message_ = !fin;
    DCHECK(!fin || state == StreamingUtf8Validator::VALID_ENDPOINT);
  }

  return SendFrameInternal(fin, op_code, std::move(buffer), buffer_size);
  // |this| may have been deleted.
}

ChannelState WebSocketChannel::StartClosingHandshake(
    uint16_t code,
    const std::string& reason) {
  if (InClosingState()) {
    // When the associated renderer process is killed while the channel is in
    // CLOSING state we reach here.
    DVLOG(1) << "StartClosingHandshake called in state " << state_
             << ". This may be a bug, or a harmless race.";
    return CHANNEL_ALIVE;
  }
  if (has_received_close_frame_) {
    // We reach here if the client wants to start a closing handshake while
    // the browser is waiting for the client to consume incoming data frames
    // before responding to a closing handshake initiated by the server.
    // As the client doesn't want the data frames any more, we can respond to
    // the closing handshake initiated by the server.
    return RespondToClosingHandshake();
  }
  if (state_ == CONNECTING) {
    // Abort the in-progress handshake and drop the connection immediately.
    stream_request_.reset();
    SetState(CLOSED);
    DoDropChannel(false, kWebSocketErrorAbnormalClosure, "");
    return CHANNEL_DELETED;
  }
  DCHECK_EQ(state_, CONNECTED);

  DCHECK(!close_timer_.IsRunning());
  // This use of base::Unretained() is safe because we stop the timer in the
  // destructor.
  close_timer_.Start(
      FROM_HERE, closing_handshake_timeout_,
      base::BindOnce(&WebSocketChannel::CloseTimeout, base::Unretained(this)));

  // Javascript actually only permits 1000 and 3000-4999, but the implementation
  // itself may produce different codes. The length of |reason| is also checked
  // by Javascript.
  if (!IsStrictlyValidCloseStatusCode(code) ||
      reason.size() > kMaximumCloseReasonLength) {
    // "InternalServerError" is actually used for errors from any endpoint, per
    // errata 3227 to RFC6455. If the renderer is sending us an invalid code or
    // reason it must be malfunctioning in some way, and based on that we
    // interpret this as an internal error.
    if (SendClose(kWebSocketErrorInternalServerError, "") == CHANNEL_DELETED)
      return CHANNEL_DELETED;
    DCHECK_EQ(CONNECTED, state_);
    SetState(SEND_CLOSED);
    return CHANNEL_ALIVE;
  }
  if (SendClose(code, StreamingUtf8Validator::Validate(reason)
                          ? reason
                          : std::string()) == CHANNEL_DELETED)
    return CHANNEL_DELETED;
  DCHECK_EQ(CONNECTED, state_);
  SetState(SEND_CLOSED);
  return CHANNEL_ALIVE;
}

void WebSocketChannel::SendAddChannelRequestForTesting(
    const GURL& socket_url,
    const std::vector<std::string>& requested_subprotocols,
    const url::Origin& origin,
    const SiteForCookies& site_for_cookies,
    StorageAccessApiStatus storage_access_api_status,
    const IsolationInfo& isolation_info,
    const HttpRequestHeaders& additional_headers,
    NetworkTrafficAnnotationTag traffic_annotation,
    WebSocketStreamRequestCreationCallback callback) {
  SendAddChannelRequestWithSuppliedCallback(
      socket_url, requested_subprotocols, origin, site_for_cookies,
      storage_access_api_status, isolation_info, additional_headers,
      traffic_annotation, std::move(callback));
}

void WebSocketChannel::SetClosingHandshakeTimeoutForTesting(
    base::TimeDelta delay) {
  closing_handshake_timeout_ = delay;
}

void WebSocketChannel::SetUnderlyingConnectionCloseTimeoutForTesting(
    base::TimeDelta delay) {
  underlying_connection_close_timeout_ = delay;
}

void WebSocketChannel::SendAddChannelRequestWithSuppliedCallback(
    const GURL& socket_url,
    const std::vector<std::string>& requested_subprotocols,
    const url::Origin& origin,
    const SiteForCookies& site_for_cookies,
    StorageAccessApiStatus storage_access_api_status,
    const IsolationInfo& isolation_info,
    const HttpRequestHeaders& additional_headers,
    NetworkTrafficAnnotationTag traffic_annotation,
    WebSocketStreamRequestCreationCallback callback) {
  DCHECK_EQ(FRESHLY_CONSTRUCTED, state_);
  if (!socket_url.SchemeIsWSOrWSS()) {
    // TODO(ricea): Kill the renderer (this error should have been caught by
    // Javascript).
    event_interface_->OnFailChannel("Invalid scheme", ERR_FAILED, std::nullopt);
    // |this| is deleted here.
    return;
  }
  socket_url_ = socket_url;
  auto connect_delegate = std::make_unique<ConnectDelegate>(this);
  stream_request_ = std::move(callback).Run(
      socket_url_, requested_subprotocols, origin, site_for_cookies,
      storage_access_api_status, isolation_info, additional_headers,
      url_request_context_.get(), NetLogWithSource(), traffic_annotation,
      std::move(connect_delegate));
  SetState(CONNECTING);
}

void WebSocketChannel::OnCreateURLRequest(URLRequest* request) {
  event_interface_->OnCreateURLRequest(request);
}

void WebSocketChannel::OnURLRequestConnected(URLRequest* request,
                                             const TransportInfo& info) {
  event_interface_->OnURLRequestConnected(request, info);
}

void WebSocketChannel::OnConnectSuccess(
    std::unique_ptr<WebSocketStream> stream,
    std::unique_ptr<WebSocketHandshakeResponseInfo> response) {
  DCHECK(stream);
  DCHECK_EQ(CONNECTING, state_);

  stream_ = std::move(stream);

  SetState(CONNECTED);

  // |stream_request_| is not used once the connection has succeeded.
  stream_request_.reset();

  event_interface_->OnAddChannelResponse(
      std::move(response), stream_->GetSubProtocol(), stream_->GetExtensions());
  // |this| may have been deleted after OnAddChannelResponse.
}

void WebSocketChannel::OnConnectFailure(const std::string& message,
                                        int net_error,
                                        std::optional<int> response_code) {
  DCHECK_EQ(CONNECTING, state_);

  // Copy the message before we delete its owner.
  std::string message_copy = message;

  SetState(CLOSED);
  stream_request_.reset();

  event_interface_->OnFailChannel(message_copy, net_error, response_code);
  // |this| has been deleted.
}

void WebSocketChannel::OnSSLCertificateError(
    std::unique_ptr<WebSocketEventInterface::SSLErrorCallbacks>
        ssl_error_callbacks,
    int net_error,
    const SSLInfo& ssl_info,
    bool fatal) {
  event_interface_->OnSSLCertificateError(
      std::move(ssl_error_callbacks), socket_url_, net_error, ssl_info, fatal);
}

int WebSocketChannel::OnAuthRequired(
    const AuthChallengeInfo& auth_info,
    scoped_refptr<HttpResponseHeaders> response_headers,
    const IPEndPoint& remote_endpoint,
    base::OnceCallback<void(const AuthCredentials*)> callback,
    std::optional<AuthCredentials>* credentials) {
  return event_interface_->OnAuthRequired(
      auth_info, std::move(response_headers), remote_endpoint,
      std::move(callback), credentials);
}

void WebSocketChannel::OnStartOpeningHandshake(
    std::unique_ptr<WebSocketHandshakeRequestInfo> request) {
  event_interface_->OnStartOpeningHandshake(std::move(request));
}

ChannelState WebSocketChannel::WriteFrames() {
  int result = OK;
  do {
    // This use of base::Unretained is safe because this object owns the
    // WebSocketStream and destroying it cancels all callbacks.
    result = stream_->WriteFrames(
        data_being_sent_->frames(),
        base::BindOnce(base::IgnoreResult(&WebSocketChannel::OnWriteDone),
                       base::Unretained(this), false));
    if (result != ERR_IO_PENDING) {
      if (OnWriteDone(true, result) == CHANNEL_DELETED)
        return CHANNEL_DELETED;
      // OnWriteDone() returns CHANNEL_DELETED on error. Here |state_| is
      // guaranteed to be the same as before OnWriteDone() call.
    }
  } while (result == OK && data_being_sent_);
  return CHANNEL_ALIVE;
}

ChannelState WebSocketChannel::OnWriteDone(bool synchronous, int result) {
  DCHECK_NE(FRESHLY_CONSTRUCTED, state_);
  DCHECK_NE(CONNECTING, state_);
  DCHECK_NE(ERR_IO_PENDING, result);
  DCHECK(data_being_sent_);
  switch (result) {
    case OK:
      if (data_to_send_next_) {
        data_being_sent_ = std::move(data_to_send_next_);
        if (!synchronous)
          return WriteFrames();
      } else {
        data_being_sent_.reset();
        event_interface_->OnSendDataFrameDone();
      }
      return CHANNEL_ALIVE;

    // If a recoverable error condition existed, it would go here.

    default:
      DCHECK_LT(result, 0)
          << "WriteFrames() should only return OK or ERR_ codes";

      stream_->Close();
      SetState(CLOSED);
      DoDropChannel(false, kWebSocketErrorAbnormalClosure, "");
      return CHANNEL_DELETED;
  }
}

ChannelState WebSocketChannel::ReadFrames() {
  DCHECK(stream_);
  DCHECK(state_ == CONNECTED || state_ == SEND_CLOSED || state_ == CLOSE_WAIT);
  DCHECK(read_frames_.empty());
  if (is_reading_) {
    return CHANNEL_ALIVE;
  }

  if (!InClosingState() && has_received_close_frame_) {
    DCHECK(!event_interface_->HasPendingDataFrames());
    // We've been waiting for the client to consume the frames before
    // responding to the closing handshake initiated by the server.
    if (RespondToClosingHandshake() == CHANNEL_DELETED) {
      return CHANNEL_DELETED;
    }
  }

  // TODO(crbug.com/41479064): Remove this CHECK.
  CHECK(event_interface_);
  while (!event_interface_->HasPendingDataFrames()) {
    DCHECK(stream_);
    // This use of base::Unretained is safe because this object owns the
    // WebSocketStream, and any pending reads will be cancelled when it is
    // destroyed.
    const int result = stream_->ReadFrames(
        &read_frames_,
        base::BindOnce(base::IgnoreResult(&WebSocketChannel::OnReadDone),
                       base::Unretained(this), false));
    if (result == ERR_IO_PENDING) {
      is_reading_ = true;
      return CHANNEL_ALIVE;
    }
    if (OnReadDone(true, result) == CHANNEL_DELETED) {
      return CHANNEL_DELETED;
    }
    DCHECK_NE(CLOSED, state_);
    // TODO(crbug.com/41479064): Remove this CHECK.
    CHECK(event_interface_);
  }
  return CHANNEL_ALIVE;
}

ChannelState WebSocketChannel::OnReadDone(bool synchronous, int result) {
  DVLOG(3) << "WebSocketChannel::OnReadDone synchronous?" << synchronous
           << ", result=" << result
           << ", read_frames_.size=" << read_frames_.size();
  DCHECK_NE(FRESHLY_CONSTRUCTED, state_);
  DCHECK_NE(CONNECTING, state_);
  DCHECK_NE(ERR_IO_PENDING, result);
  switch (result) {
    case OK:
      // ReadFrames() must use ERR_CONNECTION_CLOSED for a closed connection
      // with no data read, not an empty response.
      DCHECK(!read_frames_.empty())
          << "ReadFrames() returned OK, but nothing was read.";
      for (auto& read_frame : read_frames_) {
        if (HandleFrame(std::move(read_frame)) == CHANNEL_DELETED)
          return CHANNEL_DELETED;
      }
      read_frames_.clear();
      DCHECK_NE(CLOSED, state_);
      if (!synchronous) {
        is_reading_ = false;
        if (!event_interface_->HasPendingDataFrames()) {
          return ReadFrames();
        }
      }
      return CHANNEL_ALIVE;

    case ERR_WS_PROTOCOL_ERROR:
      // This could be kWebSocketErrorProtocolError (specifically, non-minimal
      // encoding of payload length) or kWebSocketErrorMessageTooBig, or an
      // extension-specific error.
      FailChannel("Invalid frame header", kWebSocketErrorProtocolError,
                  "WebSocket Protocol Error");
      return CHANNEL_DELETED;

    default:
      DCHECK_LT(result, 0)
          << "ReadFrames() should only return OK or ERR_ codes";

      stream_->Close();
      SetState(CLOSED);

      uint16_t code = kWebSocketErrorAbnormalClosure;
      std::string reason = "";
      bool was_clean = false;
      if (has_received_close_frame_) {
        code = received_close_code_;
        reason = received_close_reason_;
        was_clean = (result == ERR_CONNECTION_CLOSED);
      }

      DoDropChannel(was_clean, code, reason);
      return CHANNEL_DELETED;
  }
}

ChannelState WebSocketChannel::HandleFrame(
    std::unique_ptr<WebSocketFrame> frame) {
  if (frame->header.masked) {
    // RFC6455 Section 5.1 "A client MUST close a connection if it detects a
    // masked frame."
    FailChannel(
        "A server must not mask any frames that it sends to the "
        "client.",
        kWebSocketErrorProtocolError, "Masked frame from server");
    return CHANNEL_DELETED;
  }
  const WebSocketFrameHeader::OpCode opcode = frame->header.opcode;
  DCHECK(!WebSocketFrameHeader::IsKnownControlOpCode(opcode) ||
         frame->header.final);
  if (frame->header.reserved1 || frame->header.reserved2 ||
      frame->header.reserved3) {
    FailChannel(
        base::StringPrintf("One or more reserved bits are on: reserved1 = %d, "
                           "reserved2 = %d, reserved3 = %d",
                           static_cast<int>(frame->header.reserved1),
                           static_cast<int>(frame->header.reserved2),
                           static_cast<int>(frame->header.reserved3)),
        kWebSocketErrorProtocolError, "Invalid reserved bit");
    return CHANNEL_DELETED;
  }

  // Respond to the frame appropriately to its type.
  return HandleFrameByState(opcode, frame->header.final,
                            base::as_chars(frame->payload));
}

ChannelState WebSocketChannel::HandleFrameByState(
    const WebSocketFrameHeader::OpCode opcode,
    bool final,
    base::span<const char> payload) {
  DCHECK_NE(RECV_CLOSED, state_)
      << "HandleFrame() does not support being called re-entrantly from within "
         "SendClose()";
  DCHECK_NE(CLOSED, state_);
  if (state_ == CLOSE_WAIT) {
    std::string frame_name;
    GetFrameTypeForOpcode(opcode, &frame_name);

    // FailChannel() won't send another Close frame.
    FailChannel(frame_name + " received after close",
                kWebSocketErrorProtocolError, "");
    return CHANNEL_DELETED;
  }
  switch (opcode) {
    case WebSocketFrameHeader::kOpCodeText:  // fall-thru
    case WebSocketFrameHeader::kOpCodeBinary:
    case WebSocketFrameHeader::kOpCodeContinuation:
      return HandleDataFrame(opcode, final, std::move(payload));

    case WebSocketFrameHeader::kOpCodePing:
      DVLOG(1) << "Got Ping of size " << payload.size();
      if (state_ == CONNECTED) {
        auto buffer = base::MakeRefCounted<IOBufferWithSize>(payload.size());
        base::ranges::copy(payload, buffer->data());
        return SendFrameInternal(true, WebSocketFrameHeader::kOpCodePong,
                                 std::move(buffer), payload.size());
      }
      DVLOG(3) << "Ignored ping in state " << state_;
      return CHANNEL_ALIVE;

    case WebSocketFrameHeader::kOpCodePong:
      DVLOG(1) << "Got Pong of size " << payload.size();
      // There is no need to do anything with pong messages.
      return CHANNEL_ALIVE;

    case WebSocketFrameHeader::kOpCodeClose: {
      uint16_t code = kWebSocketNormalClosure;
      std::string reason;
      std::string message;
      if (!ParseClose(payload, &code, &reason, &message)) {
        FailChannel(message, code, reason);
        return CHANNEL_DELETED;
      }
      // TODO(ricea): Find a way to safely log the message from the close
      // message (escape control codes and so on).
      return HandleCloseFrame(code, reason);
    }

    default:
      FailChannel(base::StringPrintf("Unrecognized frame opcode: %d", opcode),
                  kWebSocketErrorProtocolError, "Unknown opcode");
      return CHANNEL_DELETED;
  }
}

ChannelState WebSocketChannel::HandleDataFrame(
    WebSocketFrameHeader::OpCode opcode,
    bool final,
    base::span<const char> payload) {
  DVLOG(3) << "WebSocketChannel::HandleDataFrame opcode=" << opcode
           << ", final?" << final << ", data=" << (void*)payload.data()
           << ", size=" << payload.size();
  if (state_ != CONNECTED) {
    DVLOG(3) << "Ignored data packet received in state " << state_;
    return CHANNEL_ALIVE;
  }
  if (has_received_close_frame_) {
    DVLOG(3) << "Ignored data packet as we've received a close frame.";
    return CHANNEL_ALIVE;
  }
  DCHECK(opcode == WebSocketFrameHeader::kOpCodeContinuation ||
         opcode == WebSocketFrameHeader::kOpCodeText ||
         opcode == WebSocketFrameHeader::kOpCodeBinary);
  const bool got_continuation =
      (opcode == WebSocketFrameHeader::kOpCodeContinuation);
  if (got_continuation != expecting_to_handle_continuation_) {
    const std::string console_log = got_continuation
        ? "Received unexpected continuation frame."
        : "Received start of new message but previous message is unfinished.";
    const std::string reason = got_continuation
        ? "Unexpected continuation"
        : "Previous data frame unfinished";
    FailChannel(console_log, kWebSocketErrorProtocolError, reason);
    return CHANNEL_DELETED;
  }
  expecting_to_handle_continuation_ = !final;
  WebSocketFrameHeader::OpCode opcode_to_send = opcode;
  if (!initial_frame_forwarded_ &&
      opcode == WebSocketFrameHeader::kOpCodeContinuation) {
    opcode_to_send = receiving_text_message_
                         ? WebSocketFrameHeader::kOpCodeText
                         : WebSocketFrameHeader::kOpCodeBinary;
  }
  if (opcode == WebSocketFrameHeader::kOpCodeText ||
      (opcode == WebSocketFrameHeader::kOpCodeContinuation &&
       receiving_text_message_)) {
    // This call is not redundant when size == 0 because it tells us what
    // the current state is.
    StreamingUtf8Validator::State state =
        incoming_utf8_validator_.AddBytes(base::as_byte_span(payload));
    if (state == StreamingUtf8Validator::INVALID ||
        (state == StreamingUtf8Validator::VALID_MIDPOINT && final)) {
      FailChannel("Could not decode a text frame as UTF-8.",
                  kWebSocketErrorProtocolError, "Invalid UTF-8 in text frame");
      return CHANNEL_DELETED;
    }
    receiving_text_message_ = !final;
    DCHECK(!final || state == StreamingUtf8Validator::VALID_ENDPOINT);
  }
  if (payload.size() == 0U && !final)
    return CHANNEL_ALIVE;

  initial_frame_forwarded_ = !final;
  // Sends the received frame to the renderer process.
  event_interface_->OnDataFrame(final, opcode_to_send, payload);
  return CHANNEL_ALIVE;
}

ChannelState WebSocketChannel::HandleCloseFrame(uint16_t code,
                                                const std::string& reason) {
  DVLOG(1) << "Got Close with code " << code;
  switch (state_) {
    case CONNECTED:
      has_received_close_frame_ = true;
      received_close_code_ = code;
      received_close_reason_ = reason;
      if (event_interface_->HasPendingDataFrames()) {
        // We have some data to be sent to the renderer before sending this
        // frame.
        return CHANNEL_ALIVE;
      }
      return RespondToClosingHandshake();

    case SEND_CLOSED:
      SetState(CLOSE_WAIT);
      DCHECK(close_timer_.IsRunning());
      close_timer_.Stop();
      // This use of base::Unretained() is safe because we stop the timer
      // in the destructor.
      close_timer_.Start(FROM_HERE, underlying_connection_close_timeout_,
                         base::BindOnce(&WebSocketChannel::CloseTimeout,
                                        base::Unretained(this)));

      // From RFC6455 section 7.1.5: "Each endpoint
      // will see the status code sent by the other end as _The WebSocket
      // Connection Close Code_."
      has_received_close_frame_ = true;
      received_close_code_ = code;
      received_close_reason_ = reason;
      break;

    default:
      LOG(DFATAL) << "Got Close in unexpected state " << state_;
      break;
  }
  return CHANNEL_ALIVE;
}

ChannelState WebSocketChannel::RespondToClosingHandshake() {
  DCHECK(has_received_close_frame_);
  DCHECK_EQ(CONNECTED, state_);
  SetState(RECV_CLOSED);
  if (SendClose(received_close_code_, received_close_reason_) ==
      CHANNEL_DELETED)
    return CHANNEL_DELETED;
  DCHECK_EQ(RECV_CLOSED, state_
"""


```
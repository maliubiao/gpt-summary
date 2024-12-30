Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Goal:**

The core request is to understand the purpose of the `quic_frame.cc` file within the Chromium QUIC stack. Specifically, the prompt asks for:

* **Functionality:** What does this file *do*?
* **Relationship to JavaScript:**  How does this C++ code interact with JavaScript (in a web browser context)?
* **Logic and I/O:**  Examples of inputs and outputs of the code's logic.
* **Common User/Programming Errors:** How could someone misuse this code?
* **Debugging Context:** How does a user end up interacting with this code?

**2. Initial Code Scan and Keyword Identification:**

I'll first quickly read through the code, looking for key terms and structures. I notice:

* `#include`:  This tells me about dependencies on other QUIC components (frames, constants, types, platform APIs).
* `namespace quic`:  This indicates the code belongs to the QUIC library.
* `class QuicFrame`: This is the central data structure.
* Constructors for various frame types:  This strongly suggests the file is responsible for representing different kinds of QUIC frames.
* `DeleteFrames`, `DeleteFrame`:  Functions for memory management related to frames.
* `RemoveFramesForStream`:  Filtering frames based on stream ID.
* `IsControlFrame`, `GetControlFrameId`, `SetControlFrameId`: Functions for identifying and managing control frames.
* `CopyRetransmittableControlFrame`, `CopyQuicFrame`, `CopyQuicFrames`:  Functions for creating copies of frames.
* `operator<<`: Overloading the output stream operator, indicating a way to print frame information.
* `QuicFrameToString`, `QuicFramesToString`: Helper functions for converting frames to strings.
* `QUIC_FRAME_DEBUG`, `QUICHE_CHECK`, `QUICHE_DCHECK`, `QUIC_BUG`, `QUIC_LOG`:  Debugging and error handling macros.

**3. Inferring Core Functionality:**

Based on the keywords and structures, I can infer that `quic_frame.cc` defines the `QuicFrame` class, which acts as a container for different types of QUIC protocol frames. The file provides mechanisms for:

* **Creating `QuicFrame` objects:**  Constructors for each specific frame type.
* **Managing memory:**  Deleting dynamically allocated frame data.
* **Classifying frames:** Distinguishing between different frame types (data vs. control).
* **Accessing frame properties:** Getting the control frame ID.
* **Modifying frame properties:** Setting the control frame ID.
* **Copying frames:** Creating independent copies of frames, which is important for retransmission and other operations.
* **Debugging and logging:** Providing ways to inspect frame contents.

**4. Connecting to JavaScript:**

This is where the understanding of the browser's network stack comes in. I know that:

* **JavaScript interacts with web servers using APIs like `fetch` or `XMLHttpRequest`.**
* **The browser's network stack handles the underlying protocol negotiation and data transfer.**
* **QUIC is a transport protocol used by Chrome.**

Therefore, the connection is *indirect*. JavaScript doesn't directly manipulate `QuicFrame` objects. Instead:

* When a JavaScript application makes a network request, the browser's network stack, including the QUIC implementation, will generate and process QUIC frames.
* This C++ code is part of that QUIC implementation.
* The frames defined here are the *low-level units of communication* in the QUIC protocol.

**Example Scenario (JavaScript to C++):**

Imagine a user clicks a link in a web page.

1. **JavaScript:** The browser's rendering engine detects the click and initiates a network request using `fetch`.
2. **Browser Network Stack (C++):**  The request is routed to the network stack. If the connection to the server uses QUIC, the QUIC implementation in C++ will:
   * **Potentially send a `STREAM_FRAME`** containing the HTTP request headers and data.
   * **Receive `ACK_FRAME`s** acknowledging data sent by the client.
   * **Receive `STREAM_FRAME`s** containing the HTTP response data.
3. **`quic_frame.cc` Role:** The code in this file is responsible for creating, managing, and processing these `STREAM_FRAME`s, `ACK_FRAME`s, and other frame types involved in the QUIC communication.

**5. Logic Examples (Inputs and Outputs):**

I'll focus on a couple of illustrative functions:

* **`IsControlFrame`:**
    * **Input:** A `QuicFrameType` (e.g., `RST_STREAM_FRAME`, `STREAM_FRAME`).
    * **Output:** `true` if the type represents a control frame, `false` otherwise.
    * **Example:** Input: `RST_STREAM_FRAME`, Output: `true`. Input: `STREAM_FRAME`, Output: `false`.

* **`GetControlFrameId`:**
    * **Input:** A `QuicFrame` object.
    * **Output:** The `control_frame_id` of the frame if it's a control frame, `kInvalidControlFrameId` otherwise.
    * **Assumption:**  This function assumes the input `QuicFrame` is valid and correctly initialized.
    * **Example:** Input: A `QuicFrame` object where `frame.type == RST_STREAM_FRAME` and `frame.rst_stream_frame->control_frame_id = 123`. Output: `123`. Input: A `QuicFrame` object where `frame.type == STREAM_FRAME`. Output: `kInvalidControlFrameId`.

**6. Common Errors:**

I consider potential pitfalls related to memory management and frame usage:

* **Memory Leaks:** If `DeleteFrame` or `DeleteFrames` are not called appropriately for dynamically allocated frames, memory leaks can occur.
* **Incorrect Frame Type Usage:**  Trying to access members of a frame assuming a specific type when it's actually a different type (e.g., accessing `frame.rst_stream_frame` when `frame.type` is `STREAM_FRAME`). The code has checks to prevent some of these issues.
* **Modifying Inlined Frames:** The code indicates that some frames are "inlined" and shouldn't be deleted directly. Trying to delete these would be an error.
* **Accessing Control Frame IDs of Non-Control Frames:**  The `GetControlFrameId` function handles this, but directly accessing the `control_frame_id` member without checking the frame type could lead to issues.

**7. Debugging Context (User Path):**

I trace a typical user interaction leading to this code being relevant during debugging:

1. **User Action:** A user experiences a network issue while browsing a website (e.g., a page load fails, a video stalls).
2. **Bug Report/Investigation:** The user (or a developer) reports the issue. Debugging begins.
3. **Network Inspection:** The developer uses browser developer tools (Network tab) or a network packet analyzer (like Wireshark) to inspect the network traffic.
4. **QUIC Identification:** The developer identifies that the connection uses the QUIC protocol.
5. **Frame Analysis:** To understand the low-level communication, the developer might need to examine the specific QUIC frames being exchanged.
6. **Source Code Examination:**  If a bug is suspected in the QUIC implementation itself, developers might need to look at the Chromium source code, including files like `quic_frame.cc`, to understand how frames are created, processed, and handled. The logging and debugging macros in the code become crucial here.

**8. Structuring the Answer:**

Finally, I organize the information logically, following the prompts in the original request. I use clear headings, bullet points, and code examples where appropriate to make the explanation easy to understand. I emphasize the indirect relationship between this C++ code and JavaScript. I also ensure I address all the specific points raised in the prompt.
这个文件 `net/third_party/quiche/src/quiche/quic/core/frames/quic_frame.cc` 是 Chromium 网络栈中 QUIC 协议实现的关键部分，它定义和管理了 QUIC 协议中各种不同类型的帧（frames）。

以下是它的主要功能：

**1. 定义 `QuicFrame` 类:**

* `QuicFrame` 类是一个联合体 (union) 或类似结构，用于表示所有可能的 QUIC 帧类型。  它包含各种不同帧类型的成员变量，例如 `padding_frame`，`stream_frame`，`crypto_frame` 等。
* 它还包含一个 `type` 成员变量，用于指示当前 `QuicFrame` 对象实际存储的是哪种类型的帧。

**2. 提供构造函数:**

* 针对每一种可能的 QUIC 帧类型，`QuicFrame` 类都提供了相应的构造函数。这允许方便地创建特定类型的 `QuicFrame` 对象。例如，`QuicFrame(QuicStreamFrame stream_frame)` 用于创建一个包含数据流帧的 `QuicFrame`。

**3. 管理帧的生命周期 (内存管理):**

* `DeleteFrames(QuicFrames* frames)` 函数用于释放一个 `QuicFrames` 容器中所有帧的内存。
* `DeleteFrame(QuicFrame* frame)` 函数用于释放单个 `QuicFrame` 对象的内存。这个函数会根据帧的 `type` 来判断需要释放哪些内部指针指向的内存。
* **注意:**  一些帧类型（例如 `PADDING_FRAME`, `MTU_DISCOVERY_FRAME` 等）是被“内联”存储的，它们的内存直接包含在 `QuicFrame` 对象中，因此不需要单独 `delete`。代码中有针对这种情况的判断。

**4. 操作帧集合:**

* `RemoveFramesForStream(QuicFrames* frames, QuicStreamId stream_id)` 函数用于从一个 `QuicFrames` 容器中移除属于特定流 ID 的所有 `STREAM_FRAME`。

**5. 判断帧的类型:**

* `IsControlFrame(QuicFrameType type)` 函数用于判断给定的帧类型是否是控制帧。控制帧用于管理连接的状态，而不是传输用户数据。

**6. 获取和设置控制帧 ID:**

* `GetControlFrameId(const QuicFrame& frame)` 函数用于获取控制帧的 ID。不是所有帧都有控制帧 ID。
* `SetControlFrameId(QuicControlFrameId control_frame_id, QuicFrame* frame)` 函数用于设置控制帧的 ID。

**7. 复制帧:**

* `CopyRetransmittableControlFrame(const QuicFrame& frame)` 函数用于复制可以被重传的控制帧。
* `CopyQuicFrame(quiche::QuicheBufferAllocator* allocator, const QuicFrame& frame)` 函数用于创建一个 `QuicFrame` 的深拷贝，需要提供内存分配器。
* `CopyQuicFrames(quiche::QuicheBufferAllocator* allocator, const QuicFrames& frames)` 函数用于复制一个 `QuicFrames` 容器。

**8. 格式化输出:**

* `operator<<(std::ostream& os, const QuicFrame& frame)` 重载了输出流操作符，使得可以将 `QuicFrame` 对象方便地输出到流中（例如，用于日志记录）。
* `QuicFrameToString(const QuicFrame& frame)` 和 `QuicFramesToString(const QuicFrames& frames)` 函数将帧或帧集合转换为字符串表示。

**与 JavaScript 功能的关系：**

`quic_frame.cc` 文件中的代码是 C++ 实现，与 JavaScript 的交互是 **间接的**。

* **JavaScript 发起网络请求:**  在浏览器中运行的 JavaScript 代码可以通过 `fetch` API 或 `XMLHttpRequest` 对象发起网络请求。
* **浏览器网络栈处理:**  当请求的目标服务器支持 QUIC 协议时，浏览器的网络栈会使用 QUIC 进行通信。
* **C++ QUIC 实现:** `quic_frame.cc` 文件是 Chromium QUIC 实现的一部分。当浏览器需要发送或接收 QUIC 数据时，会创建和解析各种 `QuicFrame` 对象。
* **数据传递:**  例如，当 JavaScript 通过 `fetch` 发送 POST 请求时，请求体的数据最终会被封装成 `STREAM_FRAME` 发送给服务器。当服务器返回数据时，数据会通过 `STREAM_FRAME` 接收，然后传递给 JavaScript。
* **控制信息:**  QUIC 连接的管理（例如，流量控制、拥塞控制、连接关闭等）也通过不同的控制帧（如 `WINDOW_UPDATE_FRAME`, `CONNECTION_CLOSE_FRAME`）来实现。这些帧的创建和处理也在 `quic_frame.cc` 中有所涉及。

**举例说明:**

假设一个 JavaScript 应用使用 `fetch` 向服务器发送一些数据：

```javascript
fetch('https://example.com/api', {
  method: 'POST',
  body: 'some data to send'
});
```

在浏览器内部，当这个请求通过 QUIC 发送时，以下（简化的）过程可能发生：

1. **JavaScript:** `fetch` API 调用。
2. **浏览器网络栈 (C++):**  网络栈识别到需要使用 QUIC 连接。
3. **QUIC 实现 (C++):**
   *  Chromium 的 QUIC 代码会创建一个 `QuicStreamFrame` 对象，将 `'some data to send'` 放入 `data` 字段。
   *  创建一个 `QuicFrame` 对象，其 `type` 为 `STREAM_FRAME`，并将上面创建的 `QuicStreamFrame` 赋值给 `stream_frame` 成员。
   *  这个 `QuicFrame` 对象会被进一步处理，例如序列化成网络字节流并发送出去。
4. **网络传输:**  `STREAM_FRAME` 通过网络发送到服务器。

反过来，当服务器返回数据时，接收到的 QUIC 数据包会被解析成 `QuicFrame` 对象，如果是一个包含响应数据的 `STREAM_FRAME`，那么其 `stream_frame.data` 字段就包含了服务器返回的数据，然后这些数据会被传递回 JavaScript 的 `fetch` Promise 中。

**逻辑推理 (假设输入与输出):**

假设输入是一个 `QuicFrame` 对象，其 `type` 是 `RST_STREAM_FRAME`，并且 `rst_stream_frame` 指向一个有效的 `QuicRstStreamFrame` 对象，其 `stream_id` 为 5，`error_code` 为 10：

**假设输入:**

```c++
QuicRstStreamFrame rst_frame;
rst_frame.stream_id = 5;
rst_frame.error_code = 10;
QuicFrame frame(&rst_frame);
```

**调用 `QuicFrameToString(frame)` 的输出:**

```
type { RST_STREAM_FRAME } stream_id: 5, error_code: 10, details: ''
```

**涉及用户或者编程常见的使用错误:**

1. **忘记释放动态分配的帧内存:** 如果创建了指向堆内存的帧（例如，使用 `new`），但在不再使用时忘记调用 `DeleteFrame`，会导致内存泄漏。

   ```c++
   QuicFrame* frame = new QuicFrame(new QuicRstStreamFrame());
   // ... 使用 frame ...
   // 忘记 delete frame;  // 错误！
   ```

2. **访问错误的帧类型成员:**  `QuicFrame` 是一个联合体，访问与当前 `type` 不匹配的成员会导致未定义的行为。

   ```c++
   QuicFrame frame(QuicPaddingFrame(5));
   // 错误地访问 stream_frame 成员，因为 frame 的类型是 PADDING_FRAME
   QuicStreamId stream_id = frame.stream_frame.stream_id;
   ```

3. **在不应该删除内联帧时尝试删除:**  尝试删除 `PADDING_FRAME` 等内联帧会导致错误。`DeleteFrame` 中有检查，但如果直接操作内存可能会出错。

   ```c++
   QuicFrame frame(QuicPaddingFrame(5));
   // 错误！padding_frame 是内联的，不需要 delete
   // delete &frame.padding_frame;
   ```

4. **在多线程环境下不安全地操作 `QuicFrame` 对象:**  如果多个线程同时修改或访问同一个 `QuicFrame` 对象，可能会导致数据竞争。需要使用适当的同步机制。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户操作:** 用户在 Chrome 浏览器中访问一个网站，该网站使用了 HTTPS，并且浏览器和服务器之间协商使用了 QUIC 协议。
2. **网络请求:** 用户点击链接、提交表单或浏览器自动加载资源，导致浏览器发起网络请求。
3. **QUIC 连接建立和数据传输:** 浏览器和服务器之间建立 QUIC 连接。数据以 QUIC 数据包的形式进行传输，每个数据包包含一个或多个 `QuicFrame`。
4. **遇到问题:**  可能出现以下情况，导致开发者需要查看 `quic_frame.cc` 的代码进行调试：
   * **连接错误或中断:**  QUIC 连接意外断开，可能是因为接收到了 `CONNECTION_CLOSE_FRAME`。
   * **数据传输问题:**  数据包丢失、乱序或损坏，可能涉及到 `STREAM_FRAME` 的处理。
   * **性能问题:**  网络延迟高，可能需要分析流量控制和拥塞控制相关的帧，例如 `WINDOW_UPDATE_FRAME`，`BLOCKED_FRAME` 等。
   * **协议错误:**  QUIC 实现的 bug 导致发送或接收了不符合协议规范的帧。
5. **调试过程:**
   * **网络抓包:** 开发者可以使用 Wireshark 等工具抓取网络数据包，查看实际传输的 QUIC 帧的内容和顺序。
   * **Chromium 内部日志:** Chromium 提供了内部日志记录机制，可以查看 QUIC 相关的日志信息，包括发送和接收的帧的类型和内容。
   * **源代码调试:**  如果怀疑是 QUIC 实现的 bug，开发者可能需要使用 GDB 等调试器，并结合 Chromium 的源代码进行调试，单步执行到 `quic_frame.cc` 中的代码，查看 `QuicFrame` 对象的创建、解析和处理过程。

例如，如果用户报告网页加载缓慢，开发者可能会抓包看到大量的 `RETRANSMISSION` 帧，然后通过查看 Chromium 的 QUIC 日志或者调试源代码，发现某个 `RST_STREAM_FRAME` 被错误地发送，导致连接中的某个流被重置，从而影响了页面加载。这时，对 `quic_frame.cc` 中 `RST_STREAM_FRAME` 的处理逻辑的理解就至关重要。

总而言之，`quic_frame.cc` 是 QUIC 协议在 Chromium 中实现的核心组件，它负责定义和管理 QUIC 通信的基本单元——帧。理解这个文件的功能对于理解 QUIC 协议的工作原理以及调试 QUIC 相关的网络问题至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/frames/quic_frame.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/frames/quic_frame.h"

#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include "quiche/quic/core/frames/quic_new_connection_id_frame.h"
#include "quiche/quic/core/frames/quic_reset_stream_at_frame.h"
#include "quiche/quic/core/frames/quic_retire_connection_id_frame.h"
#include "quiche/quic/core/frames/quic_rst_stream_frame.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/platform/api/quiche_mem_slice.h"
#include "quiche/common/quiche_buffer_allocator.h"

namespace quic {

QuicFrame::QuicFrame() {}

QuicFrame::QuicFrame(QuicPaddingFrame padding_frame)
    : padding_frame(padding_frame) {}

QuicFrame::QuicFrame(QuicStreamFrame stream_frame)
    : stream_frame(stream_frame) {}

QuicFrame::QuicFrame(QuicHandshakeDoneFrame handshake_done_frame)
    : handshake_done_frame(handshake_done_frame) {}

QuicFrame::QuicFrame(QuicCryptoFrame* crypto_frame)
    : type(CRYPTO_FRAME), crypto_frame(crypto_frame) {}

QuicFrame::QuicFrame(QuicAckFrame* frame) : type(ACK_FRAME), ack_frame(frame) {}

QuicFrame::QuicFrame(QuicMtuDiscoveryFrame frame)
    : mtu_discovery_frame(frame) {}

QuicFrame::QuicFrame(QuicStopWaitingFrame frame) : stop_waiting_frame(frame) {}

QuicFrame::QuicFrame(QuicPingFrame frame) : ping_frame(frame) {}

QuicFrame::QuicFrame(QuicRstStreamFrame* frame)
    : type(RST_STREAM_FRAME), rst_stream_frame(frame) {}

QuicFrame::QuicFrame(QuicConnectionCloseFrame* frame)
    : type(CONNECTION_CLOSE_FRAME), connection_close_frame(frame) {}

QuicFrame::QuicFrame(QuicGoAwayFrame* frame)
    : type(GOAWAY_FRAME), goaway_frame(frame) {}

QuicFrame::QuicFrame(QuicWindowUpdateFrame frame)
    : window_update_frame(frame) {}

QuicFrame::QuicFrame(QuicBlockedFrame frame) : blocked_frame(frame) {}

QuicFrame::QuicFrame(QuicNewConnectionIdFrame* frame)
    : type(NEW_CONNECTION_ID_FRAME), new_connection_id_frame(frame) {}

QuicFrame::QuicFrame(QuicRetireConnectionIdFrame* frame)
    : type(RETIRE_CONNECTION_ID_FRAME), retire_connection_id_frame(frame) {}

QuicFrame::QuicFrame(QuicMaxStreamsFrame frame) : max_streams_frame(frame) {}

QuicFrame::QuicFrame(QuicStreamsBlockedFrame frame)
    : streams_blocked_frame(frame) {}

QuicFrame::QuicFrame(QuicPathResponseFrame frame)
    : path_response_frame(frame) {}

QuicFrame::QuicFrame(QuicPathChallengeFrame frame)
    : path_challenge_frame(frame) {}

QuicFrame::QuicFrame(QuicStopSendingFrame frame) : stop_sending_frame(frame) {}

QuicFrame::QuicFrame(QuicMessageFrame* frame)
    : type(MESSAGE_FRAME), message_frame(frame) {}

QuicFrame::QuicFrame(QuicNewTokenFrame* frame)
    : type(NEW_TOKEN_FRAME), new_token_frame(frame) {}

QuicFrame::QuicFrame(QuicAckFrequencyFrame* frame)
    : type(ACK_FREQUENCY_FRAME), ack_frequency_frame(frame) {}

QuicFrame::QuicFrame(QuicResetStreamAtFrame* frame)
    : type(RESET_STREAM_AT_FRAME), reset_stream_at_frame(frame) {}

void DeleteFrames(QuicFrames* frames) {
  for (QuicFrame& frame : *frames) {
    DeleteFrame(&frame);
  }
  frames->clear();
}

void DeleteFrame(QuicFrame* frame) {
#if QUIC_FRAME_DEBUG
  // If the frame is not inlined, check that it can be safely deleted.
  if (frame->type != PADDING_FRAME && frame->type != MTU_DISCOVERY_FRAME &&
      frame->type != PING_FRAME && frame->type != MAX_STREAMS_FRAME &&
      frame->type != STOP_WAITING_FRAME &&
      frame->type != STREAMS_BLOCKED_FRAME && frame->type != STREAM_FRAME &&
      frame->type != HANDSHAKE_DONE_FRAME &&
      frame->type != WINDOW_UPDATE_FRAME && frame->type != BLOCKED_FRAME &&
      frame->type != STOP_SENDING_FRAME &&
      frame->type != PATH_CHALLENGE_FRAME &&
      frame->type != PATH_RESPONSE_FRAME) {
    QUICHE_CHECK(!frame->delete_forbidden) << *frame;
  }
#endif  // QUIC_FRAME_DEBUG
  switch (frame->type) {
    // Frames smaller than a pointer are inlined, so don't need to be deleted.
    case PADDING_FRAME:
    case MTU_DISCOVERY_FRAME:
    case PING_FRAME:
    case MAX_STREAMS_FRAME:
    case STOP_WAITING_FRAME:
    case STREAMS_BLOCKED_FRAME:
    case STREAM_FRAME:
    case HANDSHAKE_DONE_FRAME:
    case WINDOW_UPDATE_FRAME:
    case BLOCKED_FRAME:
    case STOP_SENDING_FRAME:
    case PATH_CHALLENGE_FRAME:
    case PATH_RESPONSE_FRAME:
      break;
    case ACK_FRAME:
      delete frame->ack_frame;
      break;
    case RST_STREAM_FRAME:
      delete frame->rst_stream_frame;
      break;
    case CONNECTION_CLOSE_FRAME:
      delete frame->connection_close_frame;
      break;
    case GOAWAY_FRAME:
      delete frame->goaway_frame;
      break;
    case NEW_CONNECTION_ID_FRAME:
      delete frame->new_connection_id_frame;
      break;
    case RETIRE_CONNECTION_ID_FRAME:
      delete frame->retire_connection_id_frame;
      break;
    case MESSAGE_FRAME:
      delete frame->message_frame;
      break;
    case CRYPTO_FRAME:
      delete frame->crypto_frame;
      break;
    case NEW_TOKEN_FRAME:
      delete frame->new_token_frame;
      break;
    case ACK_FREQUENCY_FRAME:
      delete frame->ack_frequency_frame;
      break;
    case RESET_STREAM_AT_FRAME:
      delete frame->reset_stream_at_frame;
      break;
    case NUM_FRAME_TYPES:
      QUICHE_DCHECK(false) << "Cannot delete type: " << frame->type;
  }
}

void RemoveFramesForStream(QuicFrames* frames, QuicStreamId stream_id) {
  auto it = frames->begin();
  while (it != frames->end()) {
    if (it->type != STREAM_FRAME || it->stream_frame.stream_id != stream_id) {
      ++it;
      continue;
    }
    it = frames->erase(it);
  }
}

bool IsControlFrame(QuicFrameType type) {
  switch (type) {
    case RST_STREAM_FRAME:
    case GOAWAY_FRAME:
    case WINDOW_UPDATE_FRAME:
    case BLOCKED_FRAME:
    case STREAMS_BLOCKED_FRAME:
    case MAX_STREAMS_FRAME:
    case PING_FRAME:
    case STOP_SENDING_FRAME:
    case NEW_CONNECTION_ID_FRAME:
    case RETIRE_CONNECTION_ID_FRAME:
    case HANDSHAKE_DONE_FRAME:
    case ACK_FREQUENCY_FRAME:
    case NEW_TOKEN_FRAME:
    case RESET_STREAM_AT_FRAME:
      return true;
    default:
      return false;
  }
}

QuicControlFrameId GetControlFrameId(const QuicFrame& frame) {
  switch (frame.type) {
    case RST_STREAM_FRAME:
      return frame.rst_stream_frame->control_frame_id;
    case GOAWAY_FRAME:
      return frame.goaway_frame->control_frame_id;
    case WINDOW_UPDATE_FRAME:
      return frame.window_update_frame.control_frame_id;
    case BLOCKED_FRAME:
      return frame.blocked_frame.control_frame_id;
    case STREAMS_BLOCKED_FRAME:
      return frame.streams_blocked_frame.control_frame_id;
    case MAX_STREAMS_FRAME:
      return frame.max_streams_frame.control_frame_id;
    case PING_FRAME:
      return frame.ping_frame.control_frame_id;
    case STOP_SENDING_FRAME:
      return frame.stop_sending_frame.control_frame_id;
    case NEW_CONNECTION_ID_FRAME:
      return frame.new_connection_id_frame->control_frame_id;
    case RETIRE_CONNECTION_ID_FRAME:
      return frame.retire_connection_id_frame->control_frame_id;
    case HANDSHAKE_DONE_FRAME:
      return frame.handshake_done_frame.control_frame_id;
    case ACK_FREQUENCY_FRAME:
      return frame.ack_frequency_frame->control_frame_id;
    case NEW_TOKEN_FRAME:
      return frame.new_token_frame->control_frame_id;
    case RESET_STREAM_AT_FRAME:
      return frame.reset_stream_at_frame->control_frame_id;
    default:
      return kInvalidControlFrameId;
  }
}

void SetControlFrameId(QuicControlFrameId control_frame_id, QuicFrame* frame) {
  switch (frame->type) {
    case RST_STREAM_FRAME:
      frame->rst_stream_frame->control_frame_id = control_frame_id;
      return;
    case GOAWAY_FRAME:
      frame->goaway_frame->control_frame_id = control_frame_id;
      return;
    case WINDOW_UPDATE_FRAME:
      frame->window_update_frame.control_frame_id = control_frame_id;
      return;
    case BLOCKED_FRAME:
      frame->blocked_frame.control_frame_id = control_frame_id;
      return;
    case PING_FRAME:
      frame->ping_frame.control_frame_id = control_frame_id;
      return;
    case STREAMS_BLOCKED_FRAME:
      frame->streams_blocked_frame.control_frame_id = control_frame_id;
      return;
    case MAX_STREAMS_FRAME:
      frame->max_streams_frame.control_frame_id = control_frame_id;
      return;
    case STOP_SENDING_FRAME:
      frame->stop_sending_frame.control_frame_id = control_frame_id;
      return;
    case NEW_CONNECTION_ID_FRAME:
      frame->new_connection_id_frame->control_frame_id = control_frame_id;
      return;
    case RETIRE_CONNECTION_ID_FRAME:
      frame->retire_connection_id_frame->control_frame_id = control_frame_id;
      return;
    case HANDSHAKE_DONE_FRAME:
      frame->handshake_done_frame.control_frame_id = control_frame_id;
      return;
    case ACK_FREQUENCY_FRAME:
      frame->ack_frequency_frame->control_frame_id = control_frame_id;
      return;
    case NEW_TOKEN_FRAME:
      frame->new_token_frame->control_frame_id = control_frame_id;
      return;
    case RESET_STREAM_AT_FRAME:
      frame->reset_stream_at_frame->control_frame_id = control_frame_id;
      return;
    default:
      QUIC_BUG(quic_bug_12594_1)
          << "Try to set control frame id of a frame without control frame id";
  }
}

QuicFrame CopyRetransmittableControlFrame(const QuicFrame& frame) {
  QuicFrame copy;
  switch (frame.type) {
    case RST_STREAM_FRAME:
      copy = QuicFrame(new QuicRstStreamFrame(*frame.rst_stream_frame));
      break;
    case GOAWAY_FRAME:
      copy = QuicFrame(new QuicGoAwayFrame(*frame.goaway_frame));
      break;
    case WINDOW_UPDATE_FRAME:
      copy = QuicFrame(QuicWindowUpdateFrame(frame.window_update_frame));
      break;
    case BLOCKED_FRAME:
      copy = QuicFrame(QuicBlockedFrame(frame.blocked_frame));
      break;
    case PING_FRAME:
      copy = QuicFrame(QuicPingFrame(frame.ping_frame.control_frame_id));
      break;
    case STOP_SENDING_FRAME:
      copy = QuicFrame(QuicStopSendingFrame(frame.stop_sending_frame));
      break;
    case NEW_CONNECTION_ID_FRAME:
      copy = QuicFrame(
          new QuicNewConnectionIdFrame(*frame.new_connection_id_frame));
      break;
    case RETIRE_CONNECTION_ID_FRAME:
      copy = QuicFrame(
          new QuicRetireConnectionIdFrame(*frame.retire_connection_id_frame));
      break;
    case STREAMS_BLOCKED_FRAME:
      copy = QuicFrame(QuicStreamsBlockedFrame(frame.streams_blocked_frame));
      break;
    case MAX_STREAMS_FRAME:
      copy = QuicFrame(QuicMaxStreamsFrame(frame.max_streams_frame));
      break;
    case HANDSHAKE_DONE_FRAME:
      copy = QuicFrame(
          QuicHandshakeDoneFrame(frame.handshake_done_frame.control_frame_id));
      break;
    case ACK_FREQUENCY_FRAME:
      copy = QuicFrame(new QuicAckFrequencyFrame(*frame.ack_frequency_frame));
      break;
    case NEW_TOKEN_FRAME:
      copy = QuicFrame(new QuicNewTokenFrame(*frame.new_token_frame));
      break;
    case RESET_STREAM_AT_FRAME:
      copy =
          QuicFrame(new QuicResetStreamAtFrame(*frame.reset_stream_at_frame));
      break;
    default:
      QUIC_BUG(quic_bug_10533_1)
          << "Try to copy a non-retransmittable control frame: " << frame;
      copy = QuicFrame(QuicPingFrame(kInvalidControlFrameId));
      break;
  }
  return copy;
}

QuicFrame CopyQuicFrame(quiche::QuicheBufferAllocator* allocator,
                        const QuicFrame& frame) {
  QuicFrame copy;
  switch (frame.type) {
    case PADDING_FRAME:
      copy = QuicFrame(QuicPaddingFrame(frame.padding_frame));
      break;
    case RST_STREAM_FRAME:
      copy = QuicFrame(new QuicRstStreamFrame(*frame.rst_stream_frame));
      break;
    case CONNECTION_CLOSE_FRAME:
      copy = QuicFrame(
          new QuicConnectionCloseFrame(*frame.connection_close_frame));
      break;
    case GOAWAY_FRAME:
      copy = QuicFrame(new QuicGoAwayFrame(*frame.goaway_frame));
      break;
    case WINDOW_UPDATE_FRAME:
      copy = QuicFrame(QuicWindowUpdateFrame(frame.window_update_frame));
      break;
    case BLOCKED_FRAME:
      copy = QuicFrame(QuicBlockedFrame(frame.blocked_frame));
      break;
    case STOP_WAITING_FRAME:
      copy = QuicFrame(QuicStopWaitingFrame(frame.stop_waiting_frame));
      break;
    case PING_FRAME:
      copy = QuicFrame(QuicPingFrame(frame.ping_frame.control_frame_id));
      break;
    case CRYPTO_FRAME:
      copy = QuicFrame(new QuicCryptoFrame(*frame.crypto_frame));
      break;
    case STREAM_FRAME:
      copy = QuicFrame(QuicStreamFrame(frame.stream_frame));
      break;
    case ACK_FRAME:
      copy = QuicFrame(new QuicAckFrame(*frame.ack_frame));
      break;
    case MTU_DISCOVERY_FRAME:
      copy = QuicFrame(QuicMtuDiscoveryFrame(frame.mtu_discovery_frame));
      break;
    case NEW_CONNECTION_ID_FRAME:
      copy = QuicFrame(
          new QuicNewConnectionIdFrame(*frame.new_connection_id_frame));
      break;
    case MAX_STREAMS_FRAME:
      copy = QuicFrame(QuicMaxStreamsFrame(frame.max_streams_frame));
      break;
    case STREAMS_BLOCKED_FRAME:
      copy = QuicFrame(QuicStreamsBlockedFrame(frame.streams_blocked_frame));
      break;
    case PATH_RESPONSE_FRAME:
      copy = QuicFrame(QuicPathResponseFrame(frame.path_response_frame));
      break;
    case PATH_CHALLENGE_FRAME:
      copy = QuicFrame(QuicPathChallengeFrame(frame.path_challenge_frame));
      break;
    case STOP_SENDING_FRAME:
      copy = QuicFrame(QuicStopSendingFrame(frame.stop_sending_frame));
      break;
    case MESSAGE_FRAME:
      copy = QuicFrame(new QuicMessageFrame(frame.message_frame->message_id));
      copy.message_frame->data = frame.message_frame->data;
      copy.message_frame->message_length = frame.message_frame->message_length;
      for (const auto& slice : frame.message_frame->message_data) {
        quiche::QuicheBuffer buffer =
            quiche::QuicheBuffer::Copy(allocator, slice.AsStringView());
        copy.message_frame->message_data.push_back(
            quiche::QuicheMemSlice(std::move(buffer)));
      }
      break;
    case NEW_TOKEN_FRAME:
      copy = QuicFrame(new QuicNewTokenFrame(*frame.new_token_frame));
      break;
    case RETIRE_CONNECTION_ID_FRAME:
      copy = QuicFrame(
          new QuicRetireConnectionIdFrame(*frame.retire_connection_id_frame));
      break;
    case HANDSHAKE_DONE_FRAME:
      copy = QuicFrame(
          QuicHandshakeDoneFrame(frame.handshake_done_frame.control_frame_id));
      break;
    case ACK_FREQUENCY_FRAME:
      copy = QuicFrame(new QuicAckFrequencyFrame(*frame.ack_frequency_frame));
      break;
    case RESET_STREAM_AT_FRAME:
      copy =
          QuicFrame(new QuicResetStreamAtFrame(*frame.reset_stream_at_frame));
      break;
    default:
      QUIC_BUG(quic_bug_10533_2) << "Cannot copy frame: " << frame;
      copy = QuicFrame(QuicPingFrame(kInvalidControlFrameId));
      break;
  }
  return copy;
}

QuicFrames CopyQuicFrames(quiche::QuicheBufferAllocator* allocator,
                          const QuicFrames& frames) {
  QuicFrames copy;
  for (const auto& frame : frames) {
    copy.push_back(CopyQuicFrame(allocator, frame));
  }
  return copy;
}

std::ostream& operator<<(std::ostream& os, const QuicFrame& frame) {
  switch (frame.type) {
    case PADDING_FRAME: {
      os << "type { PADDING_FRAME } " << frame.padding_frame;
      break;
    }
    case RST_STREAM_FRAME: {
      os << "type { RST_STREAM_FRAME } " << *(frame.rst_stream_frame);
      break;
    }
    case CONNECTION_CLOSE_FRAME: {
      os << "type { CONNECTION_CLOSE_FRAME } "
         << *(frame.connection_close_frame);
      break;
    }
    case GOAWAY_FRAME: {
      os << "type { GOAWAY_FRAME } " << *(frame.goaway_frame);
      break;
    }
    case WINDOW_UPDATE_FRAME: {
      os << "type { WINDOW_UPDATE_FRAME } " << frame.window_update_frame;
      break;
    }
    case BLOCKED_FRAME: {
      os << "type { BLOCKED_FRAME } " << frame.blocked_frame;
      break;
    }
    case STREAM_FRAME: {
      os << "type { STREAM_FRAME } " << frame.stream_frame;
      break;
    }
    case ACK_FRAME: {
      os << "type { ACK_FRAME } " << *(frame.ack_frame);
      break;
    }
    case STOP_WAITING_FRAME: {
      os << "type { STOP_WAITING_FRAME } " << frame.stop_waiting_frame;
      break;
    }
    case PING_FRAME: {
      os << "type { PING_FRAME } " << frame.ping_frame;
      break;
    }
    case CRYPTO_FRAME: {
      os << "type { CRYPTO_FRAME } " << *(frame.crypto_frame);
      break;
    }
    case MTU_DISCOVERY_FRAME: {
      os << "type { MTU_DISCOVERY_FRAME } ";
      break;
    }
    case NEW_CONNECTION_ID_FRAME:
      os << "type { NEW_CONNECTION_ID } " << *(frame.new_connection_id_frame);
      break;
    case RETIRE_CONNECTION_ID_FRAME:
      os << "type { RETIRE_CONNECTION_ID } "
         << *(frame.retire_connection_id_frame);
      break;
    case MAX_STREAMS_FRAME:
      os << "type { MAX_STREAMS } " << frame.max_streams_frame;
      break;
    case STREAMS_BLOCKED_FRAME:
      os << "type { STREAMS_BLOCKED } " << frame.streams_blocked_frame;
      break;
    case PATH_RESPONSE_FRAME:
      os << "type { PATH_RESPONSE } " << frame.path_response_frame;
      break;
    case PATH_CHALLENGE_FRAME:
      os << "type { PATH_CHALLENGE } " << frame.path_challenge_frame;
      break;
    case STOP_SENDING_FRAME:
      os << "type { STOP_SENDING } " << frame.stop_sending_frame;
      break;
    case MESSAGE_FRAME:
      os << "type { MESSAGE_FRAME }" << *(frame.message_frame);
      break;
    case NEW_TOKEN_FRAME:
      os << "type { NEW_TOKEN_FRAME }" << *(frame.new_token_frame);
      break;
    case HANDSHAKE_DONE_FRAME:
      os << "type { HANDSHAKE_DONE_FRAME } " << frame.handshake_done_frame;
      break;
    case ACK_FREQUENCY_FRAME:
      os << "type { ACK_FREQUENCY_FRAME } " << *(frame.ack_frequency_frame);
      break;
    case RESET_STREAM_AT_FRAME:
      os << "type { RESET_STREAM_AT_FRAME } " << *(frame.reset_stream_at_frame);
      break;
    default: {
      QUIC_LOG(ERROR) << "Unknown frame type: " << frame.type;
      break;
    }
  }
  return os;
}

QUICHE_EXPORT std::string QuicFrameToString(const QuicFrame& frame) {
  std::ostringstream os;
  os << frame;
  return os.str();
}

std::string QuicFramesToString(const QuicFrames& frames) {
  std::ostringstream os;
  for (const QuicFrame& frame : frames) {
    os << frame;
  }
  return os.str();
}

}  // namespace quic

"""

```
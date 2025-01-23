Response:
Let's break down the thought process for analyzing this C++ code and answering the user's request.

**1. Understanding the Goal:**

The user wants to understand the functionality of `quic_chromium_packet_writer.cc` within the Chromium networking stack, specifically looking for:

* **Core Functionality:** What does this code do?
* **Relationship to JavaScript:** Is there any interaction, direct or indirect?
* **Logic and Data Flow:**  Can we infer inputs and outputs for key functions?
* **Common Errors:** What mistakes could a user or programmer make that involve this code?
* **Debugging Context:** How does user interaction lead to this code being executed?

**2. Initial Code Scan and Keyword Recognition:**

My first step is to quickly scan the code for keywords and familiar patterns related to networking and QUIC:

* `#include`: This tells us about dependencies (other C++ files). I see `net/quic/...`, `net/base/...`, `base/...`. This immediately points to the code being part of Chromium's QUIC implementation and interacting with lower-level network primitives.
* `namespace net`:  Confirms it's in the `net` namespace, a common place for networking code in Chromium.
* `class QuicChromiumPacketWriter`: The main class. Its name suggests its role: writing QUIC packets.
* `DatagramClientSocket`:  A fundamental networking socket. This class is *using* a socket to send data.
* `WritePacket`, `WritePacketToSocketImpl`, `OnWriteComplete`:  Keywords related to the packet writing process.
* `ReusableIOBuffer`: A custom buffer management class, probably for efficiency.
* `UMA_HISTOGRAM...`:  Metrics gathering. This is important for understanding the code's behavior in production.
* `delegate_`:  A common pattern for delegation/callbacks. This class likely interacts with other components through a delegate.
* `retry_timer_`:  Indicates a retry mechanism, likely for handling transient network issues.
* `ERR_IO_PENDING`, `ERR_MSG_TOO_BIG`, `ERR_NO_BUFFER_SPACE`:  Error codes.
* `kMaxOutgoingPacketSize`:  A constant defining the maximum packet size.
* `kTrafficAnnotation`:  Related to privacy and data usage policies.

**3. Deconstructing the Core Functionality:**

Based on the keywords and structure, I start to form a mental model of the class's purpose:

* **Sending QUIC Packets:** The primary function is to take a QUIC packet (represented as a buffer) and send it over a `DatagramClientSocket`.
* **Buffer Management:** The `ReusableIOBuffer` suggests optimization by reusing buffers to avoid frequent allocations.
* **Asynchronous Operations:** The use of callbacks (`write_callback_`, `OnWriteComplete`) and handling of `ERR_IO_PENDING` indicates asynchronous I/O.
* **Error Handling and Retries:** The code explicitly handles write errors (`HandleWriteError`) and implements a retry mechanism for `ERR_NO_BUFFER_SPACE`.
* **Delegation:** The `delegate_` allows this class to notify other components about write success, errors, and blocking/unblocking events.

**4. Addressing Specific Questions:**

* **JavaScript Relationship:** I look for any direct interaction with JavaScript APIs. There are none. However, I understand that Chromium's networking stack powers the web browser, and JavaScript running in a web page will indirectly trigger this code when making network requests over QUIC. This is the crucial indirect link.
* **Logic and Data Flow (WritePacket):** I focus on the `WritePacket` function.
    * **Input:** `buffer`, `buf_len`, `self_address`, `peer_address`. I can infer example values.
    * **Process:** Setting the packet in the reusable buffer, calling `WritePacketToSocketImpl`.
    * **Output:** `quic::WriteResult`, indicating success, blocking, or error.
* **Common Errors:** I analyze error handling: `ERR_NO_BUFFER_SPACE` (leading to retries), other write errors handled by the delegate, and potential issues with the `ReusableIOBuffer` (null pointer, insufficient size, multiple references).
* **User Operation to Code Execution:** I think about how a user action (like clicking a link) would initiate a network request. This request might be handled by a higher-level QUIC component (`QuicChromiumClientSession`, as mentioned in the comments), which would eventually delegate the packet writing to `QuicChromiumPacketWriter`.

**5. Structuring the Answer:**

I organize the information according to the user's request:

* **功能 (Functionality):**  Start with a high-level summary and then detail the key aspects (writing packets, buffer management, error handling, etc.).
* **与 JavaScript 的关系 (Relationship with JavaScript):** Clearly explain the *indirect* relationship via the browser's networking stack. Provide a concrete example.
* **逻辑推理 (Logic Inference):** Choose a key function (`WritePacket`) and provide assumed inputs and outputs to illustrate the data flow.
* **用户或编程常见的使用错误 (Common User/Programming Errors):** Focus on errors related to buffer usage and network issues.
* **用户操作是如何一步步的到达这里 (How User Actions Lead Here):** Trace a typical user interaction leading to packet writing.

**6. Refinement and Review:**

I reread the code and my answer to ensure accuracy and clarity. I check for any missed details or potential misunderstandings. For instance, I notice the traffic annotation comments, which are important for understanding the context of the packet writing.

This methodical approach, combining code analysis, domain knowledge (networking, QUIC), and attention to the specific questions, allows me to generate a comprehensive and informative answer. The process is iterative; I might revisit earlier steps if I discover new information or need to refine my understanding.
好的，让我们来分析一下 `net/quic/quic_chromium_packet_writer.cc` 这个文件。

**功能 (Functionality):**

这个文件的核心功能是 **将 QUIC 数据包写入底层网络套接字 (Socket)**。更具体地说，`QuicChromiumPacketWriter` 类负责：

1. **管理用于发送数据包的缓冲区:** 它使用 `ReusableIOBuffer` 来高效地管理用于发送数据包的内存缓冲区。这种设计旨在减少内存分配和复制的开销。
2. **与 `DatagramClientSocket` 交互:** 它使用 `DatagramClientSocket` 这个 Chromium 的网络抽象类来实际执行网络写入操作。
3. **处理写操作的结果:** 它处理来自 `DatagramClientSocket` 的写操作完成的回调，并根据结果通知其委托 (delegate)。
4. **处理写错误和重试:**  当发生网络写入错误时，例如 `ERR_NO_BUFFER_SPACE`（没有可用缓冲区空间），它可以实现重试机制。它使用一个定时器来延迟重试，并限制重试次数。
5. **支持强制阻塞写操作:**  提供一个机制 `force_write_blocked_` 来模拟写阻塞的情况，这可能用于测试或流量控制。
6. **提供获取最大包大小的方法:**  `GetMaxPacketSize` 方法返回允许发送的最大 QUIC 数据包大小。
7. **处理 Socket 关闭事件:**  `OnSocketClosed` 方法用于当底层的 `DatagramClientSocket` 关闭时进行清理。

**与 JavaScript 的关系 (Relationship with JavaScript):**

`QuicChromiumPacketWriter` 本身是用 C++ 编写的，**它与 JavaScript 没有直接的交互**。然而，它在 Chromium 浏览器中扮演着关键的角色，而 Chromium 最终会执行 JavaScript 代码。它们之间的关系是 **间接的**。

当你在网页中执行 JavaScript 代码发起一个网络请求（例如，使用 `fetch` API 或 `XMLHttpRequest`），如果浏览器决定使用 QUIC 协议来建立连接，那么底层的网络栈就会使用 `QuicChromiumPacketWriter` 来发送 QUIC 数据包。

**举例说明:**

1. **JavaScript 发起请求:** 你在网页的 JavaScript 中写下如下代码：
   ```javascript
   fetch('https://example.com/data.json')
     .then(response => response.json())
     .then(data => console.log(data));
   ```

2. **浏览器处理:** 浏览器接收到这个请求。如果浏览器和 `example.com` 之间协商使用 QUIC 协议，那么 Chromium 的 QUIC 实现就会被激活。

3. **创建 QUIC 会话:** Chromium 会创建一个 `QuicChromiumClientSession` 对象来管理与服务器的 QUIC 连接。

4. **创建 QUIC 流:**  对于这个 HTTP 请求，会创建一个或多个 QUIC 流 (`QuicChromiumClientStream`).

5. **数据写入:** 当需要发送 HTTP 请求头或请求体时，`QuicChromiumClientStream` 会将数据交给更底层的 QUIC 组件进行封装成 QUIC 数据包。

6. **`QuicChromiumPacketWriter` 发送:** 最终，`QuicChromiumPacketWriter` 会被调用，将封装好的 QUIC 数据包通过 `DatagramClientSocket` 发送到网络上。

**逻辑推理 (Logic Inference):**

让我们分析 `WritePacket` 函数的逻辑。

**假设输入:**

* `buffer`: 指向包含要发送的 QUIC 数据包内容的字符数组的指针 (例如，HTTP 请求头)。
* `buf_len`: 要发送的数据包的长度 (例如，请求头的字节数)。
* `self_address`: 本地 IP 地址和端口。
* `peer_address`: 目标服务器的 IP 地址和端口。

**处理过程:**

1. `CHECK(!IsWriteBlocked());`: 检查当前是否因为之前的写操作被阻塞。
2. `SetPacket(buffer, buf_len);`: 将要发送的数据复制到 `packet_` (一个 `ReusableIOBuffer`) 中。这里会尝试复用已有的缓冲区，如果缓冲区太小或者正在被其他地方使用，可能会分配一个新的缓冲区。
3. `return WritePacketToSocketImpl();`: 调用 `WritePacketToSocketImpl` 来实际执行网络写入操作。

**`WritePacketToSocketImpl` 的可能输出:**

* **成功发送 (同步):** 如果 `socket_->Write` 返回非负值，表示数据包已成功发送。`WriteResult` 的 `status` 将是 `quic::WRITE_STATUS_OK`，`error_code` 将是 `OK` (0)。
* **发送被阻塞 (异步):** 如果 `socket_->Write` 返回 `ERR_IO_PENDING`，表示写操作正在进行中，需要等待回调。`WriteResult` 的 `status` 将是 `quic::WRITE_STATUS_BLOCKED_DATA_BUFFERED`，`error_code` 将是 `ERR_IO_PENDING`。
* **发送错误:** 如果 `socket_->Write` 返回其他负值，表示发生了网络错误。`WriteResult` 的 `status` 将是 `quic::WRITE_STATUS_ERROR`，`error_code` 将是相应的错误码 (例如，`ERR_NETWORK_CHANGED`)。

**涉及用户或者编程常见的使用错误 (Common User/Programming Errors):**

虽然用户通常不会直接操作 `QuicChromiumPacketWriter`，但编程错误可能会导致与此相关的行为。

1. **底层 Socket 错误:**  如果底层的 `DatagramClientSocket` 出现问题（例如，网络连接断开，Socket 被意外关闭），`QuicChromiumPacketWriter` 的写操作将会失败。这通常不是直接的编程错误，而是网络环境问题。

2. **缓冲区管理问题 (理论上):**  虽然 `ReusableIOBuffer` 旨在简化缓冲区管理，但如果上层代码没有正确地管理数据生命周期，可能会导致写入时访问无效内存。然而，Chromium 的 QUIC 代码对此有严格的控制，这种情况不太可能发生。

3. **过度依赖同步写入:**  如果错误地假设 `WritePacket` 总是同步完成，而没有处理 `WRITE_STATUS_BLOCKED_DATA_BUFFERED` 的情况，可能会导致逻辑错误。正确的做法是使用异步回调机制。

4. **忽略或错误处理写错误:**  如果上层代码没有正确处理 `OnWriteError` 回调，可能会导致数据丢失或连接不稳定。

**用户操作是如何一步步的到达这里，作为调试线索 (How User Actions Lead Here as Debugging Clues):**

假设用户报告了一个网页加载缓慢或失败的问题，并且怀疑是 QUIC 连接的问题。以下是用户操作如何最终导致 `QuicChromiumPacketWriter` 被调用的步骤，可以作为调试线索：

1. **用户在浏览器地址栏输入 URL 并按下回车:**  这是最常见的用户操作。

2. **DNS 查询:** 浏览器首先需要解析域名对应的 IP 地址。

3. **建立连接:** 浏览器尝试与服务器建立连接。如果支持 QUIC，浏览器会尝试进行 QUIC 握手。这涉及到发送初始的 QUIC 数据包。

4. **QUIC 会话建立:** `QuicChromiumClientSession` 对象被创建来管理 QUIC 连接。

5. **HTTP 请求:** 当连接建立后，浏览器会创建一个或多个 `QuicChromiumClientStream` 来发送 HTTP 请求。

6. **数据包封装:**  `QuicChromiumClientStream` 将 HTTP 请求头和内容传递给 QUIC 封装层。

7. **`QuicChromiumPacketWriter` 调用:**  QUIC 封装层最终调用 `QuicChromiumPacketWriter::WritePacket` 或 `QuicChromiumPacketWriter::WritePacketToSocket` 来将封装好的 QUIC 数据包通过底层的 `DatagramClientSocket` 发送出去。

8. **网络传输:** 数据包通过网络传输到服务器。

**调试线索:**

* **网络抓包 (如 Wireshark):** 可以捕获网络数据包，查看是否发送了 QUIC 数据包，以及数据包的内容和传输情况。
* **Chrome 的内部页面 (chrome://net-internals/#quic):**  这个页面提供了关于 QUIC 连接的详细信息，包括连接状态、统计数据、错误信息等。可以查看是否有连接建立失败、数据包丢失或重传等问题。
* **Chrome 的开发者工具 (F12):**  在 "Network" 选项卡中，可以查看请求的协议是否是 "h3" (HTTP/3 over QUIC)。
* **断点调试:** 如果有 Chromium 的源代码，可以在 `QuicChromiumPacketWriter` 的关键函数中设置断点，例如 `WritePacket` 和 `OnWriteComplete`，来观察数据包的发送过程和结果。

总而言之，`QuicChromiumPacketWriter` 是 Chromium QUIC 协议栈中负责实际发送数据包的关键组件。它与 JavaScript 没有直接联系，但对于任何使用 QUIC 协议的网络请求来说，它都在幕后发挥着重要作用。理解其功能和可能的错误情况，有助于调试 QUIC 相关的网络问题。

### 提示词
```
这是目录为net/quic/quic_chromium_packet_writer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_chromium_packet_writer.h"

#include <string>
#include <utility>

#include "base/check_op.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/sparse_histogram.h"
#include "base/task/sequenced_task_runner.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/quic/quic_chromium_client_session.h"
#include "net/traffic_annotation/network_traffic_annotation.h"

namespace net {

namespace {

enum NotReusableReason {
  NOT_REUSABLE_NULLPTR = 0,
  NOT_REUSABLE_TOO_SMALL = 1,
  NOT_REUSABLE_REF_COUNT = 2,
  NUM_NOT_REUSABLE_REASONS = 3,
};

const int kMaxRetries = 12;  // 2^12 = 4 seconds, which should be a LOT.

void RecordNotReusableReason(NotReusableReason reason) {
  UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.WritePacketNotReusable", reason,
                            NUM_NOT_REUSABLE_REASONS);
}

void RecordRetryCount(int count) {
  UMA_HISTOGRAM_EXACT_LINEAR("Net.QuicSession.RetryAfterWriteErrorCount2",
                             count, kMaxRetries + 1);
}

const net::NetworkTrafficAnnotationTag kTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("quic_chromium_packet_writer", R"(
        semantics {
          sender: "QUIC Packet Writer"
          description:
            "A QUIC packet is written to the wire based on a request from "
            "a QUIC stream."
          trigger:
            "A request from QUIC stream."
          data: "Any data sent by the stream."
          destination: OTHER
          destination_other: "Any destination choosen by the stream."
        }
        policy {
          cookies_allowed: NO
          setting: "This feature cannot be disabled in settings."
          policy_exception_justification:
            "Essential for network access."
        }
        comments:
          "All requests that are received by QUIC streams have network traffic "
          "annotation, but the annotation is not passed to the writer function "
          "due to technial overheads. Please see QuicChromiumClientSession and "
          "QuicChromiumClientStream classes for references."
    )");

}  // namespace

QuicChromiumPacketWriter::ReusableIOBuffer::ReusableIOBuffer(size_t capacity)
    : IOBufferWithSize(capacity), capacity_(capacity) {}

QuicChromiumPacketWriter::ReusableIOBuffer::~ReusableIOBuffer() = default;

void QuicChromiumPacketWriter::ReusableIOBuffer::Set(const char* buffer,
                                                     size_t buf_len) {
  CHECK_LE(buf_len, capacity_);
  CHECK(HasOneRef());
  size_ = buf_len;
  std::memcpy(data(), buffer, buf_len);
}

QuicChromiumPacketWriter::QuicChromiumPacketWriter(
    DatagramClientSocket* socket,
    base::SequencedTaskRunner* task_runner)
    : socket_(socket),
      packet_(base::MakeRefCounted<ReusableIOBuffer>(
          quic::kMaxOutgoingPacketSize)) {
  retry_timer_.SetTaskRunner(task_runner);
  write_callback_ = base::BindRepeating(
      &QuicChromiumPacketWriter::OnWriteComplete, weak_factory_.GetWeakPtr());
}

QuicChromiumPacketWriter::~QuicChromiumPacketWriter() = default;

void QuicChromiumPacketWriter::set_force_write_blocked(
    bool force_write_blocked) {
  force_write_blocked_ = force_write_blocked;
  if (!IsWriteBlocked() && delegate_ != nullptr)
    delegate_->OnWriteUnblocked();
}

void QuicChromiumPacketWriter::SetPacket(const char* buffer, size_t buf_len) {
  if (!packet_) [[unlikely]] {
    packet_ = base::MakeRefCounted<ReusableIOBuffer>(
        std::max(buf_len, static_cast<size_t>(quic::kMaxOutgoingPacketSize)));
    RecordNotReusableReason(NOT_REUSABLE_NULLPTR);
  }
  if (packet_->capacity() < buf_len) [[unlikely]] {
    packet_ = base::MakeRefCounted<ReusableIOBuffer>(buf_len);
    RecordNotReusableReason(NOT_REUSABLE_TOO_SMALL);
  }
  if (!packet_->HasOneRef()) [[unlikely]] {
    packet_ = base::MakeRefCounted<ReusableIOBuffer>(
        std::max(buf_len, static_cast<size_t>(quic::kMaxOutgoingPacketSize)));
    RecordNotReusableReason(NOT_REUSABLE_REF_COUNT);
  }
  packet_->Set(buffer, buf_len);
}

quic::WriteResult QuicChromiumPacketWriter::WritePacket(
    const char* buffer,
    size_t buf_len,
    const quic::QuicIpAddress& self_address,
    const quic::QuicSocketAddress& peer_address,
    quic::PerPacketOptions* /*options*/,
    const quic::QuicPacketWriterParams& /*params*/) {
  CHECK(!IsWriteBlocked());
  SetPacket(buffer, buf_len);
  return WritePacketToSocketImpl();
}

void QuicChromiumPacketWriter::WritePacketToSocket(
    scoped_refptr<ReusableIOBuffer> packet) {
  CHECK(!force_write_blocked_);
  CHECK(!IsWriteBlocked());
  packet_ = std::move(packet);
  quic::WriteResult result = WritePacketToSocketImpl();
  if (result.error_code != ERR_IO_PENDING)
    OnWriteComplete(result.error_code);
}

quic::WriteResult QuicChromiumPacketWriter::WritePacketToSocketImpl() {
  base::TimeTicks now = base::TimeTicks::Now();

  // When the connection is closed, the socket is cleaned up. If socket is
  // invalidated, packets should not be written to the socket.
  CHECK(socket_);
  int rv = socket_->Write(packet_.get(), packet_->size(), write_callback_,
                          kTrafficAnnotation);

  if (MaybeRetryAfterWriteError(rv))
    return quic::WriteResult(quic::WRITE_STATUS_BLOCKED_DATA_BUFFERED,
                             ERR_IO_PENDING);

  if (rv < 0 && rv != ERR_IO_PENDING && delegate_ != nullptr) {
    // If write error, then call delegate's HandleWriteError, which
    // may be able to migrate and rewrite packet on a new socket.
    // HandleWriteError returns the outcome of that rewrite attempt.
    rv = delegate_->HandleWriteError(rv, std::move(packet_));
    DCHECK(packet_ == nullptr);
  }

  quic::WriteStatus status = quic::WRITE_STATUS_OK;
  if (rv < 0) {
    if (rv != ERR_IO_PENDING) {
      status = quic::WRITE_STATUS_ERROR;
    } else {
      status = quic::WRITE_STATUS_BLOCKED_DATA_BUFFERED;
      write_in_progress_ = true;
    }
  }

  base::TimeDelta delta = base::TimeTicks::Now() - now;
  if (status == quic::WRITE_STATUS_OK) {
    UMA_HISTOGRAM_TIMES("Net.QuicSession.PacketWriteTime.Synchronous", delta);
  } else if (quic::IsWriteBlockedStatus(status)) {
    UMA_HISTOGRAM_TIMES("Net.QuicSession.PacketWriteTime.Asynchronous", delta);
  }

  return quic::WriteResult(status, rv);
}

void QuicChromiumPacketWriter::RetryPacketAfterNoBuffers() {
  DCHECK_GT(retry_count_, 0);
  if (socket_) {
    quic::WriteResult result = WritePacketToSocketImpl();
    if (result.error_code != ERR_IO_PENDING) {
      OnWriteComplete(result.error_code);
    }
  }
}

bool QuicChromiumPacketWriter::IsWriteBlocked() const {
  return (force_write_blocked_ || write_in_progress_);
}

void QuicChromiumPacketWriter::SetWritable() {
  write_in_progress_ = false;
}

std::optional<int> QuicChromiumPacketWriter::MessageTooBigErrorCode() const {
  return ERR_MSG_TOO_BIG;
}

void QuicChromiumPacketWriter::OnWriteComplete(int rv) {
  DCHECK_NE(rv, ERR_IO_PENDING);
  write_in_progress_ = false;
  if (delegate_ == nullptr)
    return;

  if (rv < 0) {
    if (MaybeRetryAfterWriteError(rv))
      return;

    // If write error, then call delegate's HandleWriteError, which
    // may be able to migrate and rewrite packet on a new socket.
    // HandleWriteError returns the outcome of that rewrite attempt.
    rv = delegate_->HandleWriteError(rv, std::move(packet_));
    DCHECK(packet_ == nullptr);
    if (rv == ERR_IO_PENDING) {
      // Set write blocked back as write error is encountered in this writer,
      // delegate may be able to handle write error but this writer will never
      // be used to write any new data.
      write_in_progress_ = true;
      return;
    }
  }
  if (retry_count_ != 0) {
    RecordRetryCount(retry_count_);
    retry_count_ = 0;
  }

  if (rv < 0)
    delegate_->OnWriteError(rv);
  else if (!force_write_blocked_)
    delegate_->OnWriteUnblocked();
}

bool QuicChromiumPacketWriter::MaybeRetryAfterWriteError(int rv) {
  if (rv != ERR_NO_BUFFER_SPACE)
    return false;

  if (retry_count_ >= kMaxRetries) {
    RecordRetryCount(retry_count_);
    return false;
  }

  retry_timer_.Start(
      FROM_HERE, base::Milliseconds(UINT64_C(1) << retry_count_),
      base::BindOnce(&QuicChromiumPacketWriter::RetryPacketAfterNoBuffers,
                     weak_factory_.GetWeakPtr()));
  retry_count_++;
  write_in_progress_ = true;
  return true;
}

quic::QuicByteCount QuicChromiumPacketWriter::GetMaxPacketSize(
    const quic::QuicSocketAddress& peer_address) const {
  return quic::kMaxOutgoingPacketSize;
}

bool QuicChromiumPacketWriter::SupportsReleaseTime() const {
  return false;
}

bool QuicChromiumPacketWriter::IsBatchMode() const {
  return false;
}

bool QuicChromiumPacketWriter::SupportsEcn() const {
  return false;
}

quic::QuicPacketBuffer QuicChromiumPacketWriter::GetNextWriteLocation(
    const quic::QuicIpAddress& self_address,
    const quic::QuicSocketAddress& peer_address) {
  return {nullptr, nullptr};
}

quic::WriteResult QuicChromiumPacketWriter::Flush() {
  return quic::WriteResult(quic::WRITE_STATUS_OK, 0);
}

bool QuicChromiumPacketWriter::OnSocketClosed(DatagramClientSocket* socket) {
  if (socket_ == socket) {
    socket_ = nullptr;
    return true;
  }
  return false;
}

}  // namespace net
```
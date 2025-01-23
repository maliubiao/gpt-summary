Response:
The user wants to understand the functionality of the `net/spdy/spdy_session.cc` file in the Chromium network stack. They've asked for a summary of its features, its relationship to JavaScript, examples of logical reasoning (input/output), common usage errors, debugging guidance, and a concise summary of the provided code snippet as part 3 of a 4-part series.

Here's a breakdown of how to approach this:

1. **Identify Core Functionality:** The code deals with managing a Spdy (or HTTP/2) session. This includes reading and writing data, handling frames, managing streams, and error handling.

2. **JavaScript Relationship:**  Consider how a browser using this code interacts with JavaScript. JavaScript initiates network requests, and this C++ code handles the underlying protocol.

3. **Logical Reasoning (Input/Output):** Look for functions that take inputs and produce outputs, especially those related to processing network data or managing session state. Think about specific actions and their consequences.

4. **Common Usage Errors:**  These are usually related to misconfigurations, incorrect usage of the API (though this is internal Chromium code), or issues arising from the network protocol itself.

5. **Debugging Guidance:** Trace how user actions (e.g., clicking a link) lead to this code being executed. Focus on the entry points and the flow of execution.

6. **Summarize the Snippet:**  Focus on the code provided, which mainly covers enqueuing priority frames, the read loop, and the write loop.

**Mental Sandbox:**

*   **Reading:** The `DoReadLoop` function seems critical. It reads data from the socket and processes it. What are the different states? How does it handle errors?
*   **Writing:**  Similarly, `DoWriteLoop` handles sending data. How does it queue frames? What happens when a write completes?
*   **Prioritization:** The `EnqueuePriorityFrame` function is in the snippet. How does this affect the write queue?
*   **JavaScript Trigger:**  A user clicks a link. This triggers a network request in JavaScript. How does that translate to actions within `SpdySession`?

**Constraint Checklist & Confidence Score:**

*   List functions: Yes
*   JavaScript relation: Yes
*   JavaScript examples: Yes
*   Logical reasoning: Yes
*   Input/output examples: Yes
*   Common errors: Yes
*   Debugging steps: Yes
*   Summarize functionality (part 3): Yes

Confidence Score: 5/5

**Strategizing complete. Proceeding with response generation.**

这是 `net/spdy/spdy_session.cc` 文件的第三部分，主要负责 **Spdy 会话的读写循环和数据处理**。

**主要功能归纳:**

1. **优先级帧的入队:** `EnqueuePriorityFrame` 函数用于将优先级帧（PRIORITY frame）添加到写入队列中，并确保它们以最高优先级发送。

2. **读取循环 (`PumpReadLoop`, `DoReadLoop`, `DoRead`, `DoReadComplete`):**
    *   **从套接字读取数据:**  `DoRead` 尝试从底层的套接字读取数据到缓冲区 `read_buffer_`。它使用 `ReadIfReady` 进行非阻塞读取，如果不支持则回退到阻塞的 `Read`。
    *   **处理读取结果:** `DoReadComplete` 处理读取操作的结果。如果读取到数据，它会将数据传递给 Spdy 帧解析器 (`buffered_spdy_framer_`) 进行处理。
    *   **处理连接关闭和错误:** 如果读取结果为 0，则表示连接已关闭。如果结果小于 0，则表示发生了读取错误。
    *   **控制读取速率:** 为了避免阻塞事件循环，读取循环会在读取一定量的数据或经过一定时间后让出控制权，并通过 `PostTask` 重新调度自身。

3. **写入循环 (`PumpWriteLoop`, `MaybePostWriteLoop`, `DoWriteLoop`, `DoWrite`, `DoWriteComplete`):**
    *   **管理写入状态:**  `write_state_` 跟踪当前的写入状态。`MaybePostWriteLoop` 用于启动写入循环。
    *   **从队列中取出待发送帧:** `DoWrite` 从写入队列 (`write_queue_`) 中取出下一个待发送的 Spdy 帧。
    *   **激活流:** 如果待发送的是 HEADERS 帧，则会激活关联的流，分配流 ID，并将其添加到活动流的映射中。
    *   **执行写入操作:** `socket_->Write` 用于将帧数据写入底层的套接字。
    *   **处理写入完成:** `DoWriteComplete` 处理写入操作的结果。如果写入成功，它会更新已发送的字节数，并在整个帧发送完成后通知相关的流。如果写入失败，则会触发会话的关闭流程。
    *   **流量控制:**  写入循环会考虑流量控制，确保不会发送超过对端允许的数据量。

4. **会话初始数据的发送 (`SendInitialData`):**  该函数用于在会话建立初期发送必要的帧，例如连接前缀、SETTINGS 帧和 WINDOW\_UPDATE 帧。

5. **处理 SETTINGS 帧 (`HandleSetting`):**  该函数处理接收到的 SETTINGS 帧，并根据设置更新会话的状态，例如头部表大小、最大并发流数、初始窗口大小等。

6. **更新流的发送窗口大小 (`UpdateStreamsSendWindowSize`):**  根据接收到的 SETTINGS 帧中初始窗口大小的更新，调整所有活动和已创建但未激活的流的发送窗口大小。

7. **连接状态检查 (`MaybeCheckConnectionStatus`, `MaybeSendPrefacePing`, `WritePingFrame`, `PlanToCheckPingStatus`, `CheckPingStatus`):**
    *   **发送 PING 帧:**  为了检测连接是否仍然存活，会定期发送 PING 帧。
    *   **检查 PING 响应:**  `CheckPingStatus` 检查是否在预期时间内收到了 PING 帧的响应。如果超时，则认为连接可能已断开。

8. **发送 WINDOW\_UPDATE 帧 (`SendWindowUpdateFrame`):**  用于增加对端的流或会话接收窗口大小，从而允许对端发送更多数据。

9. **获取新的流 ID (`GetNewStreamId`):**  用于为新的 Spdy 流分配唯一的 ID。

10. **帧的入队 (`EnqueueSessionWrite`, `EnqueueWrite`):**
    *   `EnqueueSessionWrite` 用于入队会话级别的帧，例如 SETTINGS、WINDOW\_UPDATE、PING、GOAWAY 和 RST\_STREAM 帧。此类帧通常具有更高的优先级。
    *   `EnqueueWrite` 是一个更通用的入队函数，用于将各种类型的帧添加到写入队列。

11. **流的管理 (`InsertCreatedStream`, `ActivateCreatedStream`, `InsertActivatedStream`, `DeleteStream`):**
    *   管理已创建但尚未激活的流 (`created_streams_`)。
    *   激活流，分配流 ID，并将其添加到活动流的映射 (`active_streams_`)。
    *   删除流，清理相关资源。

12. **错误处理和会话关闭 (`DoDrainSession`):**  当发生错误时，该函数会清理会话状态，发送 GOAWAY 帧（如果适用），并通知相关的组件。

13. **记录统计信息 (`RecordHistograms`, `RecordProtocolErrorHistogram`):**  用于记录会话的各种统计信息，例如流的数量、错误类型等，以便进行性能分析和问题诊断。

**与 JavaScript 的关系 (举例说明):**

虽然这段 C++ 代码本身不直接包含 JavaScript，但它是 Chrome 浏览器网络栈的一部分，负责处理 HTTP/2 或 SPDY 协议。JavaScript 通过浏览器提供的 API (例如 `fetch` API 或 `XMLHttpRequest`) 发起网络请求。

*   **用户在网页上点击一个链接:**
    1. JavaScript 代码捕获到点击事件。
    2. JavaScript 调用 `fetch` 或其他网络 API 发起对新 URL 的请求。
    3. 浏览器内核的网络栈判断需要使用 HTTP/2/SPDY 协议连接服务器。
    4. `SpdySession` 对象被创建或复用。
    5. JavaScript 发起的请求信息（例如 HTTP 头部）会被转换成 SPDY/HTTP/2 的 HEADERS 帧。
    6. `EnqueueWrite` 会被调用，将 HEADERS 帧添加到写入队列。
    7. `DoWriteLoop` 和 `DoWrite` 会将该帧通过 socket 发送给服务器。
    8. 服务器的响应帧（例如 DATA 帧）通过 socket 被 `DoReadLoop` 和 `DoReadComplete` 读取和解析。
    9. 解析后的数据最终会传递回 JavaScript，触发 `fetch` API 的 `then()` 回调或者 `XMLHttpRequest` 的 `onload` 事件。

*   **JavaScript 发起 WebSocket 连接升级:**
    1. JavaScript 代码创建 `WebSocket` 对象，并指定一个 `http2` 或 `spdy` 的 URL 方案（虽然实际的 WebSocket 协议握手可能发生在 HTTP/1.1 之上，但这里假设是基于 HTTP/2 的 CONNECT 协议）。
    2. 网络栈可能会使用 `SpdySession` 来建立与服务器的连接。
    3. JavaScript 的请求会被转换为 HTTP/2 的 CONNECT 方法的请求帧。
    4. `SpdySession` 处理连接的建立和数据传输。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. **`EnqueuePriorityFrame`:**  传入一个表示 PRIORITY 帧的 `SpdySerializedFrame` 对象。
2. **`DoRead` 从套接字读取到数据:**  读取到一段包含完整 HTTP/2 HEADERS 帧的数据。
3. **`DoWrite` 准备发送 HEADERS 帧:**  队列中下一个要发送的帧是新创建的流的 HEADERS 帧。
4. **`HandleSetting` 接收到服务器发送的 SETTINGS 帧:** 其中包含 `SETTINGS_MAX_CONCURRENT_STREAMS` 的新值。

**输出:**

1. **`EnqueuePriorityFrame`:**  PRIORITY 帧会被添加到 `write_queue_` 的头部，确保优先发送。
2. **`DoRead` 从套接字读取到数据:** `DoReadComplete` 会被调用，并将读取到的字节数传递给帧解析器，解析器会回调 `SpdySession` 的 `OnHeaders` 方法来处理该帧。
3. **`DoWrite` 准备发送 HEADERS 帧:**  会调用 `ActivateCreatedStream` 分配新的流 ID，并将该流添加到 `active_streams_` 中。
4. **`HandleSetting` 接收到服务器发送的 SETTINGS 帧:**  `max_concurrent_streams_` 的值会被更新，并且会调用 `ProcessPendingStreamRequests` 尝试创建之前因为并发限制而等待的流。

**用户或编程常见的使用错误 (举例说明):**

由于 `SpdySession` 是 Chromium 内部的网络组件，普通用户不会直接操作它。编程错误通常发生在 Chromium 内部开发中。

1. **在不应该调用时调用 `EnqueueWrite`:** 例如，在会话已经进入 `STATE_DRAINING` 状态后尝试发送数据，会导致数据被丢弃。
2. **错误地处理帧解析器的错误:** 如果 `buffered_spdy_framer_->ProcessInput` 返回错误，但 `SpdySession` 没有正确地处理并关闭会话，可能会导致状态不一致。
3. **没有正确处理流量控制:**  在高吞吐量的场景下，如果没有正确地发送 WINDOW\_UPDATE 帧，可能会导致连接被阻塞。
4. **在多线程环境下不安全地访问 `SpdySession` 的状态:**  虽然 `SpdySession` 主要在网络线程上运行，但如果不小心在其他线程访问其状态，可能会导致数据竞争。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在 Chrome 浏览器中输入一个 HTTPS URL 并按下回车键。**
2. **DNS 解析开始，查找目标服务器的 IP 地址。**
3. **TCP 连接建立 (如果尚未建立)。**
4. **TLS 握手开始，协商加密参数。**
5. **在 TLS 握手期间，ALPN (Application-Layer Protocol Negotiation) 扩展可能会协商使用 HTTP/2 或 SPDY 协议。**
6. **如果协商成功，`SpdySessionPool` 会创建一个 `SpdySession` 对象来管理与服务器的 HTTP/2/SPDY 连接。**
7. **`SpdySession::Initialize` 会被调用，初始化会话的状态。**
8. **`SpdySession::EstablishConnection` 会开始建立连接，包括发送连接前缀和初始的 SETTINGS 帧 (`SendInitialData`)。**
9. **当服务器发送响应帧时，底层的 socket 会接收到数据，并触发读取事件。**
10. **网络线程上的 IO 循环会调用 `SpdySession::PumpReadLoop` 开始读取循环。**
11. **`DoRead` 从 socket 读取数据。**
12. **`DoReadComplete` 调用 `buffered_spdy_framer_->ProcessInput` 解析接收到的帧。**
13. **根据接收到的帧类型，会调用 `SpdySession` 相应的处理函数，例如 `OnHeaders`, `OnData`, `OnSettings` 等。**
14. **当 JavaScript 发起新的网络请求时，`SpdySession::TryCreateStream` 会尝试创建一个新的 `SpdyStream`。**
15. **如果可以创建流，请求的头部数据会被封装成 HEADERS 帧，并通过 `EnqueueWrite` 加入写入队列。**
16. **`SpdySession::PumpWriteLoop` 开始写入循环，并通过 `DoWrite` 将帧数据写入 socket。**

通过查看网络日志 (chrome://net-export/) 和开发者工具的网络面板，可以追踪用户操作导致的请求，并查看是否使用了 HTTP/2/SPDY 协议，以及相关的帧交换信息，从而定位到 `SpdySession` 的执行。设置断点在 `SpdySession` 的关键函数中，例如 `DoReadComplete`, `DoWriteComplete`, `OnHeaders`, `OnData` 等，可以更详细地了解代码的执行流程。

### 提示词
```
这是目录为net/spdy/spdy_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
y must
  // be serialized. We do this by queueing all PRIORITY frames at HIGHEST
  // priority.
  EnqueueWrite(HIGHEST, spdy::SpdyFrameType::PRIORITY,
               std::make_unique<SimpleBufferProducer>(
                   std::make_unique<SpdyBuffer>(std::move(frame))),
               base::WeakPtr<SpdyStream>(),
               kSpdySessionCommandsTrafficAnnotation);
}

void SpdySession::PumpReadLoop(ReadState expected_read_state, int result) {
  CHECK(!in_io_loop_);
  if (availability_state_ == STATE_DRAINING) {
    return;
  }
  std::ignore = DoReadLoop(expected_read_state, result);
}

int SpdySession::DoReadLoop(ReadState expected_read_state, int result) {
  CHECK(!in_io_loop_);
  CHECK_EQ(read_state_, expected_read_state);

  in_io_loop_ = true;

  int bytes_read_without_yielding = 0;
  const base::TimeTicks yield_after_time =
      time_func_() + base::Milliseconds(kYieldAfterDurationMilliseconds);

  // Loop until the session is draining, the read becomes blocked, or
  // the read limit is exceeded.
  while (true) {
    switch (read_state_) {
      case READ_STATE_DO_READ:
        CHECK_EQ(result, OK);
        result = DoRead();
        break;
      case READ_STATE_DO_READ_COMPLETE:
        if (result > 0)
          bytes_read_without_yielding += result;
        result = DoReadComplete(result);
        break;
      default:
        NOTREACHED() << "read_state_: " << read_state_;
    }

    if (availability_state_ == STATE_DRAINING)
      break;

    if (result == ERR_IO_PENDING)
      break;

    if (read_state_ == READ_STATE_DO_READ &&
        (bytes_read_without_yielding > kYieldAfterBytesRead ||
         time_func_() > yield_after_time)) {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE,
          base::BindOnce(&SpdySession::PumpReadLoop, weak_factory_.GetWeakPtr(),
                         READ_STATE_DO_READ, OK));
      result = ERR_IO_PENDING;
      break;
    }
  }

  CHECK(in_io_loop_);
  in_io_loop_ = false;

  return result;
}

int SpdySession::DoRead() {
  DCHECK(!read_buffer_);
  CHECK(in_io_loop_);

  CHECK(socket_);
  read_state_ = READ_STATE_DO_READ_COMPLETE;
  read_buffer_ = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  int rv = socket_->ReadIfReady(
      read_buffer_.get(), kReadBufferSize,
      base::BindOnce(&SpdySession::PumpReadLoop, weak_factory_.GetWeakPtr(),
                     READ_STATE_DO_READ));
  if (rv == ERR_IO_PENDING) {
    read_buffer_ = nullptr;
    read_state_ = READ_STATE_DO_READ;
    return rv;
  }
  if (rv == ERR_READ_IF_READY_NOT_IMPLEMENTED) {
    // Fallback to regular Read().
    return socket_->Read(
        read_buffer_.get(), kReadBufferSize,
        base::BindOnce(&SpdySession::PumpReadLoop, weak_factory_.GetWeakPtr(),
                       READ_STATE_DO_READ_COMPLETE));
  }
  return rv;
}

int SpdySession::DoReadComplete(int result) {
  DCHECK(read_buffer_);
  CHECK(in_io_loop_);

  // Parse a frame.  For now this code requires that the frame fit into our
  // buffer (kReadBufferSize).
  // TODO(mbelshe): support arbitrarily large frames!

  if (result == 0) {
    DoDrainSession(ERR_CONNECTION_CLOSED, "Connection closed");
    return ERR_CONNECTION_CLOSED;
  }

  if (result < 0) {
    DoDrainSession(
        static_cast<Error>(result),
        base::StringPrintf("Error %d reading from socket.", -result));
    return result;
  }
  CHECK_LE(result, kReadBufferSize);

  last_read_time_ = time_func_();

  DCHECK(buffered_spdy_framer_.get());
  char* data = read_buffer_->data();
  while (result > 0) {
    uint32_t bytes_processed =
        buffered_spdy_framer_->ProcessInput(data, result);
    result -= bytes_processed;
    data += bytes_processed;

    if (availability_state_ == STATE_DRAINING) {
      return ERR_CONNECTION_CLOSED;
    }

    DCHECK_EQ(buffered_spdy_framer_->spdy_framer_error(),
              http2::Http2DecoderAdapter::SPDY_NO_ERROR);
  }

  read_buffer_ = nullptr;
  read_state_ = READ_STATE_DO_READ;
  return OK;
}

void SpdySession::PumpWriteLoop(WriteState expected_write_state, int result) {
  CHECK(!in_io_loop_);
  DCHECK_EQ(write_state_, expected_write_state);

  DoWriteLoop(expected_write_state, result);

  if (availability_state_ == STATE_DRAINING && !in_flight_write_ &&
      write_queue_.IsEmpty()) {
    pool_->RemoveUnavailableSession(GetWeakPtr());  // Destroys |this|.
    return;
  }
}

void SpdySession::MaybePostWriteLoop() {
  if (write_state_ == WRITE_STATE_IDLE) {
    CHECK(!in_flight_write_);
    write_state_ = WRITE_STATE_DO_WRITE;
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&SpdySession::PumpWriteLoop, weak_factory_.GetWeakPtr(),
                       WRITE_STATE_DO_WRITE, OK));
  }
}

int SpdySession::DoWriteLoop(WriteState expected_write_state, int result) {
  CHECK(!in_io_loop_);
  DCHECK_NE(write_state_, WRITE_STATE_IDLE);
  DCHECK_EQ(write_state_, expected_write_state);

  in_io_loop_ = true;

  // Loop until the session is closed or the write becomes blocked.
  while (true) {
    switch (write_state_) {
      case WRITE_STATE_DO_WRITE:
        DCHECK_EQ(result, OK);
        result = DoWrite();
        break;
      case WRITE_STATE_DO_WRITE_COMPLETE:
        result = DoWriteComplete(result);
        break;
      case WRITE_STATE_IDLE:
      default:
        NOTREACHED() << "write_state_: " << write_state_;
    }

    if (write_state_ == WRITE_STATE_IDLE) {
      DCHECK_EQ(result, ERR_IO_PENDING);
      break;
    }

    if (result == ERR_IO_PENDING)
      break;
  }

  CHECK(in_io_loop_);
  in_io_loop_ = false;

  return result;
}

int SpdySession::DoWrite() {
  CHECK(in_io_loop_);

  DCHECK(buffered_spdy_framer_);
  if (in_flight_write_) {
    DCHECK_GT(in_flight_write_->GetRemainingSize(), 0u);
  } else {
    // Grab the next frame to send.
    spdy::SpdyFrameType frame_type = spdy::SpdyFrameType::DATA;
    std::unique_ptr<SpdyBufferProducer> producer;
    base::WeakPtr<SpdyStream> stream;
    if (!write_queue_.Dequeue(&frame_type, &producer, &stream,
                              &in_flight_write_traffic_annotation_)) {
      write_state_ = WRITE_STATE_IDLE;
      return ERR_IO_PENDING;
    }

    if (stream.get())
      CHECK(!stream->IsClosed());

    // Activate the stream only when sending the HEADERS frame to
    // guarantee monotonically-increasing stream IDs.
    if (frame_type == spdy::SpdyFrameType::HEADERS) {
      CHECK(stream.get());
      CHECK_EQ(stream->stream_id(), 0u);
      std::unique_ptr<SpdyStream> owned_stream =
          ActivateCreatedStream(stream.get());
      InsertActivatedStream(std::move(owned_stream));

      if (stream_hi_water_mark_ > kLastStreamId) {
        CHECK_EQ(stream->stream_id(), kLastStreamId);
        // We've exhausted the stream ID space, and no new streams may be
        // created after this one.
        MakeUnavailable();
        StartGoingAway(kLastStreamId, ERR_HTTP2_PROTOCOL_ERROR);
      }
    }

    in_flight_write_ = producer->ProduceBuffer();
    if (!in_flight_write_) {
      NOTREACHED();
    }
    in_flight_write_frame_type_ = frame_type;
    in_flight_write_frame_size_ = in_flight_write_->GetRemainingSize();
    DCHECK_GE(in_flight_write_frame_size_, spdy::kFrameMinimumSize);
    in_flight_write_stream_ = stream;
  }

  write_state_ = WRITE_STATE_DO_WRITE_COMPLETE;

  scoped_refptr<IOBuffer> write_io_buffer =
      in_flight_write_->GetIOBufferForRemainingData();
  return socket_->Write(
      write_io_buffer.get(), in_flight_write_->GetRemainingSize(),
      base::BindOnce(&SpdySession::PumpWriteLoop, weak_factory_.GetWeakPtr(),
                     WRITE_STATE_DO_WRITE_COMPLETE),
      NetworkTrafficAnnotationTag(in_flight_write_traffic_annotation_));
}

int SpdySession::DoWriteComplete(int result) {
  CHECK(in_io_loop_);
  DCHECK_NE(result, ERR_IO_PENDING);
  DCHECK_GT(in_flight_write_->GetRemainingSize(), 0u);

  if (result < 0) {
    DCHECK_NE(result, ERR_IO_PENDING);
    in_flight_write_.reset();
    in_flight_write_frame_type_ = spdy::SpdyFrameType::DATA;
    in_flight_write_frame_size_ = 0;
    in_flight_write_stream_.reset();
    in_flight_write_traffic_annotation_.reset();
    write_state_ = WRITE_STATE_DO_WRITE;
    DoDrainSession(static_cast<Error>(result), "Write error");
    return OK;
  }

  // It should not be possible to have written more bytes than our
  // in_flight_write_.
  DCHECK_LE(static_cast<size_t>(result), in_flight_write_->GetRemainingSize());

  if (result > 0) {
    in_flight_write_->Consume(static_cast<size_t>(result));
    if (in_flight_write_stream_.get())
      in_flight_write_stream_->AddRawSentBytes(static_cast<size_t>(result));

    // We only notify the stream when we've fully written the pending frame.
    if (in_flight_write_->GetRemainingSize() == 0) {
      // It is possible that the stream was cancelled while we were
      // writing to the socket.
      if (in_flight_write_stream_.get()) {
        DCHECK_GT(in_flight_write_frame_size_, 0u);
        in_flight_write_stream_->OnFrameWriteComplete(
            in_flight_write_frame_type_, in_flight_write_frame_size_);
      }

      // Cleanup the write which just completed.
      in_flight_write_.reset();
      in_flight_write_frame_type_ = spdy::SpdyFrameType::DATA;
      in_flight_write_frame_size_ = 0;
      in_flight_write_stream_.reset();
    }
  }

  write_state_ = WRITE_STATE_DO_WRITE;
  return OK;
}

void SpdySession::NotifyRequestsOfConfirmation(int rv) {
  for (auto& callback : waiting_for_confirmation_callbacks_) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(std::move(callback), rv));
  }
  waiting_for_confirmation_callbacks_.clear();
  in_confirm_handshake_ = false;
}

void SpdySession::SendInitialData() {
  DCHECK(enable_sending_initial_data_);
  DCHECK(buffered_spdy_framer_.get());

  // Prepare initial SETTINGS frame.  Only send settings that have a value
  // different from the protocol default value.
  spdy::SettingsMap settings_map;
  for (auto setting : initial_settings_) {
    if (!IsSpdySettingAtDefaultInitialValue(setting.first, setting.second)) {
      settings_map.insert(setting);
    }
  }
  if (enable_http2_settings_grease_) {
    spdy::SpdySettingsId greased_id = 0x0a0a +
                                      0x1000 * base::RandGenerator(0xf + 1) +
                                      0x0010 * base::RandGenerator(0xf + 1);
    uint32_t greased_value = base::RandGenerator(
        static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) + 1);
    // Let insertion silently fail if `settings_map` already contains
    // `greased_id`.
    settings_map.emplace(greased_id, greased_value);
  }
  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_SEND_SETTINGS, [&] {
    return NetLogSpdySendSettingsParams(&settings_map);
  });
  std::unique_ptr<spdy::SpdySerializedFrame> settings_frame(
      buffered_spdy_framer_->CreateSettings(settings_map));

  // Prepare initial WINDOW_UPDATE frame.
  // Make sure |session_max_recv_window_size_ - session_recv_window_size_|
  // does not underflow.
  DCHECK_GE(session_max_recv_window_size_, session_recv_window_size_);
  DCHECK_GE(session_recv_window_size_, 0);
  DCHECK_EQ(0, session_unacked_recv_window_bytes_);
  std::unique_ptr<spdy::SpdySerializedFrame> window_update_frame;
  const bool send_window_update =
      session_max_recv_window_size_ > session_recv_window_size_;
  if (send_window_update) {
    const int32_t delta_window_size =
        session_max_recv_window_size_ - session_recv_window_size_;
    session_recv_window_size_ += delta_window_size;
    net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_UPDATE_RECV_WINDOW, [&] {
      return NetLogSpdySessionWindowUpdateParams(delta_window_size,
                                                 session_recv_window_size_);
    });

    last_recv_window_update_ = base::TimeTicks::Now();
    session_unacked_recv_window_bytes_ += delta_window_size;
    net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_SEND_WINDOW_UPDATE, [&] {
      return NetLogSpdyWindowUpdateFrameParams(
          spdy::kSessionFlowControlStreamId,
          session_unacked_recv_window_bytes_);
    });
    window_update_frame = buffered_spdy_framer_->CreateWindowUpdate(
        spdy::kSessionFlowControlStreamId, session_unacked_recv_window_bytes_);
    session_unacked_recv_window_bytes_ = 0;
  }

  // Create a single frame to hold connection prefix, initial SETTINGS frame,
  // and optional initial WINDOW_UPDATE frame, so that they are sent on the wire
  // in a single packet.
  size_t initial_frame_size =
      spdy::kHttp2ConnectionHeaderPrefixSize + settings_frame->size();
  if (send_window_update)
    initial_frame_size += window_update_frame->size();
  auto initial_frame_data = std::make_unique<char[]>(initial_frame_size);
  size_t offset = 0;

  memcpy(initial_frame_data.get() + offset, spdy::kHttp2ConnectionHeaderPrefix,
         spdy::kHttp2ConnectionHeaderPrefixSize);
  offset += spdy::kHttp2ConnectionHeaderPrefixSize;

  memcpy(initial_frame_data.get() + offset, settings_frame->data(),
         settings_frame->size());
  offset += settings_frame->size();

  if (send_window_update) {
    memcpy(initial_frame_data.get() + offset, window_update_frame->data(),
           window_update_frame->size());
  }

  auto initial_frame = std::make_unique<spdy::SpdySerializedFrame>(
      std::move(initial_frame_data), initial_frame_size);
  EnqueueSessionWrite(HIGHEST, spdy::SpdyFrameType::SETTINGS,
                      std::move(initial_frame));
}

void SpdySession::HandleSetting(uint32_t id, uint32_t value) {
  switch (id) {
    case spdy::SETTINGS_HEADER_TABLE_SIZE:
      buffered_spdy_framer_->UpdateHeaderEncoderTableSize(value);
      break;
    case spdy::SETTINGS_MAX_CONCURRENT_STREAMS:
      max_concurrent_streams_ =
          std::min(static_cast<size_t>(value), kMaxConcurrentStreamLimit);
      ProcessPendingStreamRequests();
      break;
    case spdy::SETTINGS_INITIAL_WINDOW_SIZE: {
      if (value > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())) {
        net_log_.AddEventWithIntParams(
            NetLogEventType::HTTP2_SESSION_INITIAL_WINDOW_SIZE_OUT_OF_RANGE,
            "initial_window_size", value);
        return;
      }

      // spdy::SETTINGS_INITIAL_WINDOW_SIZE updates initial_send_window_size_
      // only.
      int32_t delta_window_size =
          static_cast<int32_t>(value) - stream_initial_send_window_size_;
      stream_initial_send_window_size_ = static_cast<int32_t>(value);
      UpdateStreamsSendWindowSize(delta_window_size);
      net_log_.AddEventWithIntParams(
          NetLogEventType::HTTP2_SESSION_UPDATE_STREAMS_SEND_WINDOW_SIZE,
          "delta_window_size", delta_window_size);
      break;
    }
    case spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL:
      if ((value != 0 && value != 1) || (support_websocket_ && value == 0)) {
        DoDrainSession(
            ERR_HTTP2_PROTOCOL_ERROR,
            "Invalid value for spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL.");
        return;
      }
      if (value == 1) {
        support_websocket_ = true;
      }
      break;
    case spdy::SETTINGS_DEPRECATE_HTTP2_PRIORITIES:
      if (value != 0 && value != 1) {
        DoDrainSession(
            ERR_HTTP2_PROTOCOL_ERROR,
            "Invalid value for spdy::SETTINGS_DEPRECATE_HTTP2_PRIORITIES.");
        return;
      }
      if (settings_frame_received_) {
        if (value != (deprecate_http2_priorities_ ? 1 : 0)) {
          DoDrainSession(ERR_HTTP2_PROTOCOL_ERROR,
                         "spdy::SETTINGS_DEPRECATE_HTTP2_PRIORITIES value "
                         "changed after first SETTINGS frame.");
          return;
        }
      } else {
        if (value == 1) {
          deprecate_http2_priorities_ = true;
        }
      }
      break;
  }
}

void SpdySession::UpdateStreamsSendWindowSize(int32_t delta_window_size) {
  for (const auto& value : active_streams_) {
    if (!value.second->AdjustSendWindowSize(delta_window_size)) {
      DoDrainSession(
          ERR_HTTP2_FLOW_CONTROL_ERROR,
          base::StringPrintf(
              "New spdy::SETTINGS_INITIAL_WINDOW_SIZE value overflows "
              "flow control window of stream %d.",
              value.second->stream_id()));
      return;
    }
  }

  for (SpdyStream* const stream : created_streams_) {
    if (!stream->AdjustSendWindowSize(delta_window_size)) {
      DoDrainSession(
          ERR_HTTP2_FLOW_CONTROL_ERROR,
          base::StringPrintf(
              "New spdy::SETTINGS_INITIAL_WINDOW_SIZE value overflows "
              "flow control window of stream %d.",
              stream->stream_id()));
      return;
    }
  }
}

void SpdySession::MaybeCheckConnectionStatus() {
  if (NetworkChangeNotifier::IsDefaultNetworkActive())
    CheckConnectionStatus();
  else
    check_connection_on_radio_wakeup_ = true;
}

void SpdySession::MaybeSendPrefacePing() {
  if (ping_in_flight_ || check_ping_status_pending_ ||
      !enable_ping_based_connection_checking_) {
    return;
  }

  // If there has been no read activity in the session for some time,
  // then send a preface-PING.
  if (time_func_() > last_read_time_ + connection_at_risk_of_loss_time_)
    WritePingFrame(next_ping_id_, false);
}

void SpdySession::SendWindowUpdateFrame(spdy::SpdyStreamId stream_id,
                                        uint32_t delta_window_size,
                                        RequestPriority priority) {
  ActiveStreamMap::const_iterator it = active_streams_.find(stream_id);
  if (it != active_streams_.end()) {
    CHECK_EQ(it->second->stream_id(), stream_id);
  } else {
    CHECK_EQ(stream_id, spdy::kSessionFlowControlStreamId);
  }

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_SEND_WINDOW_UPDATE, [&] {
    return NetLogSpdyWindowUpdateFrameParams(stream_id, delta_window_size);
  });

  DCHECK(buffered_spdy_framer_.get());
  std::unique_ptr<spdy::SpdySerializedFrame> window_update_frame(
      buffered_spdy_framer_->CreateWindowUpdate(stream_id, delta_window_size));
  EnqueueSessionWrite(priority, spdy::SpdyFrameType::WINDOW_UPDATE,
                      std::move(window_update_frame));
}

void SpdySession::WritePingFrame(spdy::SpdyPingId unique_id, bool is_ack) {
  DCHECK(buffered_spdy_framer_.get());
  std::unique_ptr<spdy::SpdySerializedFrame> ping_frame(
      buffered_spdy_framer_->CreatePingFrame(unique_id, is_ack));
  EnqueueSessionWrite(HIGHEST, spdy::SpdyFrameType::PING,
                      std::move(ping_frame));

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_PING, [&] {
    return NetLogSpdyPingParams(unique_id, is_ack, "sent");
  });

  if (!is_ack) {
    DCHECK(!ping_in_flight_);

    ping_in_flight_ = true;
    ++next_ping_id_;
    PlanToCheckPingStatus();
    last_ping_sent_time_ = time_func_();
  }
}

void SpdySession::PlanToCheckPingStatus() {
  if (check_ping_status_pending_)
    return;

  check_ping_status_pending_ = true;
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&SpdySession::CheckPingStatus, weak_factory_.GetWeakPtr(),
                     time_func_()),
      hung_interval_);
}

void SpdySession::CheckPingStatus(base::TimeTicks last_check_time) {
  CHECK(!in_io_loop_);
  DCHECK(check_ping_status_pending_);

  if (!ping_in_flight_) {
    // A response has been received for the ping we had sent.
    check_ping_status_pending_ = false;
    return;
  }

  const base::TimeTicks now = time_func_();
  if (now > last_read_time_ + hung_interval_ ||
      last_read_time_ < last_check_time) {
    check_ping_status_pending_ = false;
    DoDrainSession(ERR_HTTP2_PING_FAILED, "Failed ping.");
    return;
  }

  // Check the status of connection after a delay.
  const base::TimeDelta delay = last_read_time_ + hung_interval_ - now;
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&SpdySession::CheckPingStatus, weak_factory_.GetWeakPtr(),
                     now),
      delay);
}

spdy::SpdyStreamId SpdySession::GetNewStreamId() {
  CHECK_LE(stream_hi_water_mark_, kLastStreamId);
  spdy::SpdyStreamId id = stream_hi_water_mark_;
  stream_hi_water_mark_ += 2;
  return id;
}

void SpdySession::EnqueueSessionWrite(
    RequestPriority priority,
    spdy::SpdyFrameType frame_type,
    std::unique_ptr<spdy::SpdySerializedFrame> frame) {
  DCHECK(frame_type == spdy::SpdyFrameType::RST_STREAM ||
         frame_type == spdy::SpdyFrameType::SETTINGS ||
         frame_type == spdy::SpdyFrameType::WINDOW_UPDATE ||
         frame_type == spdy::SpdyFrameType::PING ||
         frame_type == spdy::SpdyFrameType::GOAWAY);
  DCHECK(IsSpdyFrameTypeWriteCapped(frame_type));
  if (write_queue_.num_queued_capped_frames() >
      session_max_queued_capped_frames_) {
    LOG(WARNING)
        << "Draining session due to exceeding max queued capped frames";
    // Use ERR_CONNECTION_CLOSED to avoid sending a GOAWAY frame since that
    // frame would also exceed the cap.
    DoDrainSession(ERR_CONNECTION_CLOSED, "Exceeded max queued capped frames");
    return;
  }
  auto buffer = std::make_unique<SpdyBuffer>(std::move(frame));
  EnqueueWrite(priority, frame_type,
               std::make_unique<SimpleBufferProducer>(std::move(buffer)),
               base::WeakPtr<SpdyStream>(),
               kSpdySessionCommandsTrafficAnnotation);
  if (greased_http2_frame_ && frame_type == spdy::SpdyFrameType::SETTINGS) {
    net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_SEND_GREASED_FRAME, [&] {
      return NetLogSpdyGreasedFrameParams(
          /* stream_id = */ 0, greased_http2_frame_.value().type,
          greased_http2_frame_.value().flags,
          greased_http2_frame_.value().payload.length(), priority);
    });

    EnqueueWrite(
        priority,
        static_cast<spdy::SpdyFrameType>(greased_http2_frame_.value().type),
        std::make_unique<GreasedBufferProducer>(base::WeakPtr<SpdyStream>(),
                                                &greased_http2_frame_.value(),
                                                buffered_spdy_framer_.get()),
        base::WeakPtr<SpdyStream>(), kSpdySessionCommandsTrafficAnnotation);
  }
}

void SpdySession::EnqueueWrite(
    RequestPriority priority,
    spdy::SpdyFrameType frame_type,
    std::unique_ptr<SpdyBufferProducer> producer,
    const base::WeakPtr<SpdyStream>& stream,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  if (availability_state_ == STATE_DRAINING)
    return;

  write_queue_.Enqueue(priority, frame_type, std::move(producer), stream,
                       traffic_annotation);
  MaybePostWriteLoop();
}

void SpdySession::InsertCreatedStream(std::unique_ptr<SpdyStream> stream) {
  CHECK_EQ(stream->stream_id(), 0u);
  auto it = created_streams_.lower_bound(stream.get());
  CHECK(it == created_streams_.end() || *it != stream.get());
  created_streams_.insert(it, stream.release());
}

std::unique_ptr<SpdyStream> SpdySession::ActivateCreatedStream(
    SpdyStream* stream) {
  CHECK_EQ(stream->stream_id(), 0u);
  auto it = created_streams_.find(stream);
  CHECK(it != created_streams_.end());
  stream->set_stream_id(GetNewStreamId());
  std::unique_ptr<SpdyStream> owned_stream(stream);
  created_streams_.erase(it);
  return owned_stream;
}

void SpdySession::InsertActivatedStream(std::unique_ptr<SpdyStream> stream) {
  spdy::SpdyStreamId stream_id = stream->stream_id();
  CHECK_NE(stream_id, 0u);
  std::pair<ActiveStreamMap::iterator, bool> result =
      active_streams_.emplace(stream_id, stream.get());
  CHECK(result.second);
  std::ignore = stream.release();
}

void SpdySession::DeleteStream(std::unique_ptr<SpdyStream> stream, int status) {
  if (in_flight_write_stream_.get() == stream.get()) {
    // If we're deleting the stream for the in-flight write, we still
    // need to let the write complete, so we clear
    // |in_flight_write_stream_| and let the write finish on its own
    // without notifying |in_flight_write_stream_|.
    in_flight_write_stream_.reset();
  }

  write_queue_.RemovePendingWritesForStream(stream.get());
  if (stream->detect_broken_connection())
    MaybeDisableBrokenConnectionDetection();
  stream->OnClose(status);

  if (availability_state_ == STATE_AVAILABLE) {
    ProcessPendingStreamRequests();
  }
}

void SpdySession::RecordHistograms() {
  UMA_HISTOGRAM_CUSTOM_COUNTS("Net.SpdyStreamsPerSession",
                              streams_initiated_count_, 1, 300, 50);
  UMA_HISTOGRAM_CUSTOM_COUNTS("Net.SpdyStreamsAbandonedPerSession",
                              streams_abandoned_count_, 1, 300, 50);
  UMA_HISTOGRAM_BOOLEAN("Net.SpdySession.ServerSupportsWebSocket",
                        support_websocket_);
  if (IsGoogleHostWithAlpnH3(spdy_session_key_.host_port_pair().host())) {
    LogSessionCreationInitiatorToHistogram(session_creation_initiator_,
                                           streams_initiated_count_ > 0);
  }
}

void SpdySession::RecordProtocolErrorHistogram(
    SpdyProtocolErrorDetails details) {
  UMA_HISTOGRAM_ENUMERATION("Net.SpdySessionErrorDetails2", details,
                            NUM_SPDY_PROTOCOL_ERROR_DETAILS);
  if (base::EndsWith(host_port_pair().host(), "google.com",
                     base::CompareCase::INSENSITIVE_ASCII)) {
    UMA_HISTOGRAM_ENUMERATION("Net.SpdySessionErrorDetails_Google2", details,
                              NUM_SPDY_PROTOCOL_ERROR_DETAILS);
  }
}

void SpdySession::DcheckGoingAway() const {
#if DCHECK_IS_ON()
  DCHECK_GE(availability_state_, STATE_GOING_AWAY);
  for (int i = MINIMUM_PRIORITY; i <= MAXIMUM_PRIORITY; ++i) {
    DCHECK(pending_create_stream_queues_[i].empty());
  }
  DCHECK(created_streams_.empty());
#endif
}

void SpdySession::DcheckDraining() const {
  DcheckGoingAway();
  DCHECK_EQ(availability_state_, STATE_DRAINING);
  DCHECK(active_streams_.empty());
}

void SpdySession::DoDrainSession(Error err, const std::string& description) {
  if (availability_state_ == STATE_DRAINING) {
    return;
  }
  MakeUnavailable();

  // Mark host_port_pair requiring HTTP/1.1 for subsequent connections.
  if (err == ERR_HTTP_1_1_REQUIRED) {
    http_server_properties_->SetHTTP11Required(
        url::SchemeHostPort(url::kHttpsScheme, host_port_pair().host(),
                            host_port_pair().port()),
        spdy_session_key_.network_anonymization_key());
  }

  // If |err| indicates an error occurred, inform the peer that we're closing
  // and why. Don't GOAWAY on a graceful or idle close, as that may
  // unnecessarily wake the radio. We could technically GOAWAY on network errors
  // (we'll probably fail to actually write it, but that's okay), however many
  // unit-tests would need to be updated.
  if (err != OK &&
      err != ERR_ABORTED &&  // Used by SpdySessionPool to close idle sessions.
      err != ERR_NETWORK_CHANGED &&  // Used to deprecate sessions on IP change.
      err != ERR_SOCKET_NOT_CONNECTED && err != ERR_HTTP_1_1_REQUIRED &&
      err != ERR_CONNECTION_CLOSED && err != ERR_CONNECTION_RESET) {
    // Enqueue a GOAWAY to inform the peer of why we're closing the connection.
    spdy::SpdyGoAwayIR goaway_ir(/* last_good_stream_id = */ 0,
                                 MapNetErrorToGoAwayStatus(err), description);
    auto frame = std::make_unique<spdy::SpdySerializedFrame>(
        buffered_spdy_framer_->SerializeFrame(goaway_ir));
    EnqueueSessionWrite(HIGHEST, spdy::SpdyFrameType::GOAWAY, std::move(frame));
  }

  availability_state_ = STATE_DRAINING;
  error_on_close_ = err;

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_CLOSE, [&] {
    return NetLogSpdySessionCloseParams(err, description);
  });

  base::UmaHistogramSparse("Net.SpdySession.ClosedOnError", -err);

  if (err == OK) {
    // We ought to be going away already, as this is a graceful close.
    DcheckGoingAway();
  } else {
    StartGoingAway(0, err);
  }
  DcheckDraining();
  MaybePostWriteLoop();
}

void SpdySession::LogAbandonedStream(SpdyStream* stream, Error status) {
  DCHECK(stream);
  stream->LogStreamError(status, "Abandoned.");
  // We don't increment the streams abandoned counter here. If the
  // stream isn't active (i.e., it hasn't written anything to the wire
  // yet) then it's as if it never existed. If it is active, then
  // LogAbandonedActiveStream() will increment the counters.
}

void SpdySession::LogAbandonedActiveStream(ActiveStreamMap::const_iterator it,
                                           Error status) {
  DCHECK_GT(it->first, 0u);
  LogAbandonedStream(it->second, status);
  ++streams_abandoned_count_;
}

void SpdySession::CompleteStreamRequest(
    const base::WeakPtr<SpdyStreamRequest>& pending_request) {
  // Abort if the request has already been cancelled.
  if (!pending_request)
    return;

  base::WeakPtr<SpdyStream> stream;
  int rv = TryCreateStream(pending_request, &stream);

  if (rv == OK) {
    DCHECK(stream);
    pending_request->OnRequestCompleteSuccess(stream);
    return;
  }
  DCHECK(!stream);

  if (rv != ERR_IO_PENDING) {
    pending_request->OnRequestCompleteFailure(rv);
  }
}

void SpdySession::OnError(
    http2::Http2DecoderAdapter::SpdyFramerError spdy_framer_error) {
  CHECK(in_io_loop_);

  RecordProtocolErrorHistogram(
      MapFramerErrorToProtocolError(spdy_framer_error));
  std::string description = base::StringPrintf(
      "Framer error: %d (%s).", spdy_framer_error,
      http2::Http2DecoderAdapter::SpdyFramerErrorToString(spdy_framer_error));
  DoDrainSession(MapFramerErrorToNetError(spdy_framer_error), description);
}

void SpdySession::OnStreamError(spdy::SpdyStreamId stream_id,
                                const std::string& description) {
  CHECK(in_io_loop_);

  auto it = active_streams_.find(stream_id);
  if (it == active_streams_.end()) {
    // We still want to send a frame to reset the stream even if we
    // don't know anything about it.
    EnqueueResetStreamFrame(stream_id, IDLE, spdy::ERROR_CODE_PROTOCOL_ERROR,
                            description);
    return;
  }

  ResetStreamIterator(it, ERR_HTTP2_PROTOCOL_ERROR, description);
}

void SpdySession::OnPing(spdy::SpdyPingId unique_id, bool is_ack) {
  CHECK(in_io_loop_);

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_PING, [&] {
    return NetLogSpdyPingParams(unique_id, is_ack, "received");
  });

  // Send response to a PING from server.
  if (!is_ack) {
    WritePingFrame(unique_id, true);
    return;
  }

  if (!ping_in_flight_) {
    RecordProtocolErrorHistogram(PROTOCOL_ERROR_UNEXPECTED_PING);
    DoDrainSession(ERR_HTTP2_PROTOCOL_ERROR, "Unexpected PING ACK.");
    return;
  }

  ping_in_flight_ = false;

  // Record RTT in histogram when there are no more pings in flight.
  base::TimeDelta ping_duration = time_func_() - last_ping_sent_time_;
  if (network_quality_estimator_) {
    network_quality_estimator_->RecordSpdyPingLatency(host_port_pair(),
                                                      ping_duration);
  }
}

void SpdySession::OnRstStream(spdy::SpdyStreamId stream_id,
                              spdy::SpdyErrorCode error_code) {
  CHECK(in_io_loop_);

  // Use sparse histogram to record the unlikely case that a server sends
  // an unknown error code.
  base::UmaHistogramSparse("Net.SpdySession.RstStreamReceived", error_code);

  net_log_.AddEvent(NetLogEventType::HTTP2_SESSION_RECV_RST_STREAM, [&] {
    return NetLogSpdyRecvRstStreamParams(stream_id, error_code);
  });

  auto it = active_streams_.find(stream_id);
  if (it == active_streams_.end()) {
    // NOTE:  it may just be that the stream was cancelled.
    LOG(WARNING) << "Received RST for invalid stream" << stream_id;
    return;
  }

  DCHECK(it->second);
  CHECK_EQ(it->second->stream_id(), stream_id);

  if (error_code == spdy::ERROR_CODE_NO_ERROR) {
    CloseActiveStreamIterator(it, ERR_HTTP2_RST_STREAM_NO_ERROR_RECEIVED);
  } else if (error_code == spdy::ERROR_CODE_REFUSED_STREAM) {
    CloseActiveStreamIterator(it, ERR_HTTP2_SERVER_REFUSED_STREAM);
  } else if (error_code == spdy::ERROR_CODE_HTTP_1_1_REQUIRED) {
    // TODO(bnc): Record histogram with number of open streams capped at 50.
    it->second->LogStreamError(ERR_HTTP_1_1_REQUIRED,
                               "Closing session because server reset stream "
                               "with ERR_HTTP_1_1_REQUIRED.");
    DoDrainSession(ERR_HTTP_1_1_REQUIRED, "HTTP_1_1_REQUIRED for stream.");
  } else {
    RecordProtocolErrorHistogram(
        PROTOCOL_ERROR_RST_STREAM_FOR_NON_ACTIVE_STREAM);
    it->second->LogStreamError(ERR_HTTP2_PROTOCOL_ERROR,
                               "Server reset stream.");
    // TODO(mbelshe): Map from Spdy-protocol err
```
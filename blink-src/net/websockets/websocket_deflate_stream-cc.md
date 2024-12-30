Response:
Let's break down the thought process for analyzing the `websocket_deflate_stream.cc` file and generating the response.

**1. Understanding the Core Functionality:**

The first step is to grasp the fundamental purpose of this class. The name "WebSocketDeflateStream" strongly suggests it handles the "deflate" compression mechanism for WebSocket communication. Reading the initial comments and the constructor confirms this. It wraps another `WebSocketStream` to add compression/decompression capabilities.

**Key Observations from Initial Scan:**

* It takes a `WebSocketStream`, `WebSocketDeflateParameters`, and `WebSocketDeflatePredictor` in its constructor. These are its dependencies.
* It has `ReadFrames` and `WriteFrames` methods, mirroring the interface of a `WebSocketStream`, hinting at its role as a decorator or wrapper.
* It uses `deflater_` and `inflater_` objects, confirming the compression/decompression responsibility.
* The presence of a `predictor_` suggests some optimization or intelligent decision-making related to compression.

**2. Deconstructing the `ReadFrames` Path:**

* **Entry Point:** The `ReadFrames` method is the entry point for receiving data.
* **Chaining:** It calls the underlying `stream_->ReadFrames`. This reinforces the wrapper pattern.
* **Callback:**  The `OnReadComplete` method is used as a callback after the underlying stream reads data.
* **Inflation:**  The `InflateAndReadIfNecessary` and `Inflate` methods are called to handle decompression.
* **`Inflate` Method Logic:**  This method iterates through received frames, checking the `reserved1` flag to determine if a frame is compressed. It uses the `inflater_` to decompress compressed frames, potentially splitting them into multiple smaller frames.

**3. Deconstructing the `WriteFrames` Path:**

* **Entry Point:** The `WriteFrames` method handles sending data.
* **Deflation:** It calls the `Deflate` method to compress frames.
* **Conditional Writing:** After deflation, it calls the underlying `stream_->WriteFrames` to send the (potentially) compressed frames.
* **`Deflate` Method Logic:**  This is more complex. It involves the `predictor_` to decide whether to compress a message. It handles different writing states (uncompressed, compressed, possibly compressed). It uses the `deflater_` to compress data and potentially splits compressed messages into multiple frames.

**4. Identifying Relationships with JavaScript:**

* **Browser Implementation:**  Knowing that Chromium's network stack underlies Chrome and other browsers, the connection to JavaScript becomes clear. JavaScript's WebSocket API interacts with this underlying C++ implementation.
* **Compression Negotiation:** The initial handshake and extension negotiation are crucial. The `WebSocketDeflateParameters` are likely a result of this negotiation.
* **Data Handling:**  When a JavaScript application sends or receives WebSocket messages, the browser's WebSocket implementation uses classes like `WebSocketDeflateStream` to handle compression if it was negotiated.

**5. Considering Logic and Edge Cases:**

* **Assumptions:** The code assumes proper WebSocket framing and adherence to the deflate extension.
* **Input/Output Examples:**  Thinking about different scenarios is crucial. Uncompressed messages, single compressed frames, multi-frame compressed messages, and the initial handshake are all relevant.
* **Error Handling:**  The code checks for errors from the deflater and inflater (`ERR_WS_PROTOCOL_ERROR`). This points to potential issues.

**6. Identifying User and Programming Errors:**

* **Incorrect Server Configuration:**  Mismatched compression parameters on the client and server are a likely source of errors.
* **Prematurely Closing the Connection:**  Interrupting the data flow can lead to incomplete compression/decompression.
* **Sending Invalid Frames:**  While this class might handle compression, it relies on the underlying layers for basic frame validity.

**7. Tracing User Actions (Debugging):**

* **Network Panel:**  The browser's network panel is the primary tool for observing WebSocket communication.
* **Debugging Tools:**  Using breakpoints and logging within the Chromium codebase (if access is available) would allow developers to step through the `WebSocketDeflateStream`'s methods.
* **NetLog:**  The mention of `NetLogWithSource` highlights Chromium's internal logging system, which can provide detailed information about network events.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the low-level zlib details. However, realizing the file is part of a larger network stack, the focus should shift to its role within the WebSocket context.
*  The `predictor_` initially seemed like a minor detail, but understanding its purpose in optimizing compression (avoiding it when ineffective) became important.
*  Connecting the C++ code to the JavaScript API requires understanding the browser's architecture and how these pieces fit together.

By following these steps – understanding the core function, deconstructing the main pathways, relating it to the user and programming context, and considering error scenarios – a comprehensive analysis of the `websocket_deflate_stream.cc` file can be achieved. The iterative nature of this process, including self-correction, is crucial for generating an accurate and insightful response.
这个文件 `net/websockets/websocket_deflate_stream.cc` 是 Chromium 网络栈中用于处理 WebSocket 连接的 "permessage-deflate" 扩展的核心组件。它的主要功能是**在 WebSocket 消息的发送和接收过程中进行压缩和解压缩操作**，以减少网络传输的数据量，提高通信效率。

以下是该文件的功能详细列表：

**核心功能：**

1. **压缩 (Deflate)：**
   - 在发送 WebSocket 消息之前，使用 DEFLATE 算法对消息负载（payload）进行压缩。
   - 支持 "client_no_context_takeover" 和 "server_no_context_takeover" 模式，控制压缩上下文的重用。
   - 使用 `WebSocketDeflater` 类执行实际的压缩操作。
   - 可以根据 `WebSocketDeflatePredictor` 的预测，决定是否对消息进行压缩，以及如何进行压缩。

2. **解压缩 (Inflate)：**
   - 在接收到 WebSocket 消息之后，如果消息被压缩了（通过检查 RSV1 标志），则使用 DEFLATE 算法对消息负载进行解压缩。
   - 使用 `WebSocketInflater` 类执行实际的解压缩操作。

3. **作为 WebSocketStream 的包装器 (Wrapper)：**
   - `WebSocketDeflateStream` 类实现了 `WebSocketStream` 接口，并包装了一个底层的 `WebSocketStream` 对象。
   - 这使得它可以拦截 `ReadFrames` 和 `WriteFrames` 操作，在数据传递给底层流之前或之后执行压缩/解压缩。

4. **状态管理：**
   - 维护当前读写操作的状态（例如，是否正在处理一个压缩消息）。
   - 跟踪当前正在读或写的消息的操作码 (opcode)。

5. **预测 (Prediction)：**
   - 使用 `WebSocketDeflatePredictor` 来预测压缩是否会带来收益。这有助于避免对已知无法有效压缩的数据进行压缩，节省 CPU 资源。

**与 JavaScript 功能的关系：**

`WebSocketDeflateStream` 的功能直接影响到 JavaScript 中 WebSocket API 的使用。当 JavaScript 代码通过 `WebSocket` 对象发送或接收消息时，如果 WebSocket 连接协商使用了 "permessage-deflate" 扩展，那么浏览器底层的网络栈就会使用 `WebSocketDeflateStream` 来处理压缩和解压缩。

**举例说明：**

假设一个 JavaScript 应用通过 WebSocket 发送一个大的文本消息：

```javascript
const ws = new WebSocket('wss://example.com', ['...']); // 假设协商了 permessage-deflate

ws.onopen = () => {
  const largeMessage = '...'.repeat(1000); // 一个很大的字符串
  ws.send(largeMessage);
};

ws.onmessage = (event) => {
  console.log('Received:', event.data);
};
```

**发送过程 (涉及 `WebSocketDeflateStream::WriteFrames` 和 `Deflate`)：**

1. JavaScript 调用 `ws.send(largeMessage)`。
2. 浏览器网络栈接收到这个消息。
3. 如果 "permessage-deflate" 扩展被启用，`WebSocketDeflateStream::WriteFrames` 会被调用。
4. `Deflate` 方法会被调用来处理消息的压缩。
5. `WebSocketDeflatePredictor` 可能会被调用来判断是否应该压缩这个消息。
6. `WebSocketDeflater` 会使用 DEFLATE 算法压缩 `largeMessage` 的内容。
7. 压缩后的数据会通过底层的 `stream_->WriteFrames` 发送到服务器。

**接收过程 (涉及 `WebSocketDeflateStream::ReadFrames` 和 `Inflate`)：**

1. 服务器发送压缩后的 WebSocket 数据帧。
2. 浏览器网络栈接收到数据帧。
3. `WebSocketDeflateStream::ReadFrames` 会被调用。
4. `OnReadComplete` 回调会被触发。
5. `InflateAndReadIfNecessary` 和 `Inflate` 方法会被调用来处理消息的解压缩。
6. `Inflate` 方法会检查接收到的帧的 RSV1 标志，如果设置了，则表示该帧被压缩。
7. `WebSocketInflater` 会使用 DEFLATE 算法解压缩帧的负载。
8. 解压缩后的数据会传递给 JavaScript 的 `ws.onmessage` 回调。

**逻辑推理 (假设输入与输出)：**

**假设输入 (发送)：**

- `frames`: 一个包含单个 `WebSocketFrame` 对象的 `std::vector`，该帧包含一个大的文本消息（例如，10KB）。
- 假设 `WebSocketDeflatePredictor` 预测压缩会带来收益。

**逻辑输出 (发送)：**

- `frames`:  `std::vector` 中的 `WebSocketFrame` 对象会被修改。
    - 原始负载会被压缩后的负载替换。
    - `header.reserved1` 标志会被设置为 `true`，表示该帧被压缩。
    - `header.payload_length` 会更新为压缩后负载的长度。

**假设输入 (接收)：**

- `frames`: 一个包含单个 `WebSocketFrame` 对象的 `std::vector`，该帧的 `header.reserved1` 为 `true`，且负载是之前发送的 10KB 文本消息的压缩版本（例如，3KB）。

**逻辑输出 (接收)：**

- `frames`: `std::vector` 中的 `WebSocketFrame` 对象会被修改。
    - 压缩后的负载会被解压缩后的原始负载替换（10KB）。
    - `header.reserved1` 标志会被设置为 `false`。
    - `header.payload_length` 会更新为解压缩后负载的长度。

**用户或编程常见的使用错误：**

1. **服务端配置错误：** 如果客户端和服务端对 "permessage-deflate" 的参数配置不一致（例如，窗口大小、是否启用上下文接管），会导致压缩/解压缩失败，从而引发连接错误或消息解析错误。
   - **例子：** 客户端请求使用 "client_no_context_takeover"，但服务端配置为必须使用上下文接管。

2. **中间代理不支持压缩：** 有些网络代理可能不支持或错误地处理使用了 "permessage-deflate" 扩展的 WebSocket 连接，导致消息损坏或连接中断。
   - **例子：** 用户在一个使用了不支持压缩的代理的网络环境下尝试建立 WebSocket 连接。

3. **手动修改帧数据：**  如果开发者尝试在发送或接收过程中手动修改 WebSocket 帧的负载，而没有考虑到压缩的影响，可能会导致解压缩失败。
   - **例子：** 在 `onmessage` 回调中，假设开发者错误地尝试访问 `event.data` 的一部分，而没有意识到这部分数据仍然是压缩的。

4. **资源耗尽：**  极端情况下，如果发送非常大的不可压缩数据，`WebSocketDeflateStream` 仍然会尝试压缩，这可能会消耗大量的 CPU 资源，甚至导致性能问题。`WebSocketDeflatePredictor` 的作用就是尝试避免这种情况。

**用户操作是如何一步步到达这里，作为调试线索：**

1. **用户打开一个网页，该网页使用了 WebSocket 连接。**
2. **网页的 JavaScript 代码创建了一个 `WebSocket` 对象，并指定了包含 "permessage-deflate" 的子协议或扩展列表。**
   ```javascript
   const ws = new WebSocket('wss://example.com', ['...']); //  'permessage-deflate' 可能在子协议列表中
   // 或者通过 Sec-WebSocket-Extensions 头部协商
   ```
3. **浏览器发起 WebSocket 握手请求，并在请求头中包含 `Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits` 等信息。**
4. **服务器接受了客户端的 "permessage-deflate" 扩展请求，并在握手响应头中包含了相应的 `Sec-WebSocket-Extensions` 信息。**
5. **WebSocket 连接建立后，当 JavaScript 代码调用 `ws.send()` 发送消息时，或者当服务器发送消息时，数据会经过 `WebSocketDeflateStream` 进行处理。**

**调试线索：**

- **查看浏览器开发者工具的网络面板：**
    - 检查 WebSocket 连接的 "Frames" 选项卡，查看发送和接收的帧数据。
    - 观察帧的 RSV1 标志是否被设置，以判断是否使用了压缩。
    - 检查握手请求和响应头，确认 "permessage-deflate" 扩展是否成功协商。
- **使用 Chromium 的 `net-internals` 工具 (chrome://net-internals/#events)：**
    - 可以查看更底层的网络事件，包括 WebSocket 帧的发送和接收，以及压缩/解压缩操作的详细信息。
    - 搜索与 "WebSocketDeflateStream" 相关的事件，例如 "ws_deflate_compress" 和 "ws_deflate_uncompress"。
- **在 Chromium 源代码中添加日志：** 如果可以访问 Chromium 的源代码，可以在 `WebSocketDeflateStream` 的相关方法中添加 `DVLOG` 或 `LOG` 输出，以跟踪压缩和解压缩的流程，以及 `WebSocketDeflatePredictor` 的预测结果。
- **抓包分析 (Wireshark)：** 使用网络抓包工具可以捕获 WebSocket 通信的数据包，分析帧的结构和负载，验证是否进行了压缩。压缩后的数据通常是不可读的二进制数据。

总而言之，`net/websockets/websocket_deflate_stream.cc` 是 Chromium 实现 WebSocket 压缩扩展的关键部分，它在 JavaScript WebSocket API 和底层的网络传输之间扮演着桥梁的角色，负责高效地压缩和解压缩 WebSocket 消息。 了解它的功能有助于理解 WebSocket 的性能优化机制，并能为调试相关问题提供有价值的线索。

Prompt: 
```
这是目录为net/websockets/websocket_deflate_stream.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/websockets/websocket_deflate_stream.h"

#include <stdint.h>

#include <algorithm>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/check_op.h"
#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/logging.h"
#include "base/memory/scoped_refptr.h"
#include "base/notreached.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/websockets/websocket_deflate_parameters.h"
#include "net/websockets/websocket_deflate_predictor.h"
#include "net/websockets/websocket_deflater.h"
#include "net/websockets/websocket_frame.h"
#include "net/websockets/websocket_inflater.h"
#include "net/websockets/websocket_stream.h"

namespace net {
class NetLogWithSource;

namespace {

constexpr int kWindowBits = 15;
constexpr size_t kChunkSize = 4 * 1024;

}  // namespace

WebSocketDeflateStream::WebSocketDeflateStream(
    std::unique_ptr<WebSocketStream> stream,
    const WebSocketDeflateParameters& params,
    std::unique_ptr<WebSocketDeflatePredictor> predictor)
    : stream_(std::move(stream)),
      deflater_(params.client_context_take_over_mode()),
      inflater_(kChunkSize, kChunkSize),
      predictor_(std::move(predictor)) {
  DCHECK(stream_);
  DCHECK(params.IsValidAsResponse());
  int client_max_window_bits = 15;
  if (params.is_client_max_window_bits_specified()) {
    DCHECK(params.has_client_max_window_bits_value());
    client_max_window_bits = params.client_max_window_bits();
  }
  deflater_.Initialize(client_max_window_bits);
  inflater_.Initialize(kWindowBits);
}

WebSocketDeflateStream::~WebSocketDeflateStream() = default;

int WebSocketDeflateStream::ReadFrames(
    std::vector<std::unique_ptr<WebSocketFrame>>* frames,
    CompletionOnceCallback callback) {
  read_callback_ = std::move(callback);
  inflater_outputs_.clear();
  int result = stream_->ReadFrames(
      frames, base::BindOnce(&WebSocketDeflateStream::OnReadComplete,
                             base::Unretained(this), base::Unretained(frames)));
  if (result < 0)
    return result;
  DCHECK_EQ(OK, result);
  DCHECK(!frames->empty());

  return InflateAndReadIfNecessary(frames);
}

int WebSocketDeflateStream::WriteFrames(
    std::vector<std::unique_ptr<WebSocketFrame>>* frames,
    CompletionOnceCallback callback) {
  deflater_outputs_.clear();
  int result = Deflate(frames);
  if (result != OK)
    return result;
  if (frames->empty())
    return OK;
  return stream_->WriteFrames(frames, std::move(callback));
}

void WebSocketDeflateStream::Close() { stream_->Close(); }

std::string WebSocketDeflateStream::GetSubProtocol() const {
  return stream_->GetSubProtocol();
}

std::string WebSocketDeflateStream::GetExtensions() const {
  return stream_->GetExtensions();
}

const NetLogWithSource& WebSocketDeflateStream::GetNetLogWithSource() const {
  return stream_->GetNetLogWithSource();
}

void WebSocketDeflateStream::OnReadComplete(
    std::vector<std::unique_ptr<WebSocketFrame>>* frames,
    int result) {
  if (result != OK) {
    frames->clear();
    std::move(read_callback_).Run(result);
    return;
  }

  int r = InflateAndReadIfNecessary(frames);
  if (r != ERR_IO_PENDING)
    std::move(read_callback_).Run(r);
}

int WebSocketDeflateStream::Deflate(
    std::vector<std::unique_ptr<WebSocketFrame>>* frames) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_write;
  // Store frames of the currently processed message if writing_state_ equals to
  // WRITING_POSSIBLY_COMPRESSED_MESSAGE.
  std::vector<std::unique_ptr<WebSocketFrame>> frames_of_message;
  for (size_t i = 0; i < frames->size(); ++i) {
    DCHECK(!(*frames)[i]->header.reserved1);
    if (!WebSocketFrameHeader::IsKnownDataOpCode((*frames)[i]->header.opcode)) {
      frames_to_write.push_back(std::move((*frames)[i]));
      continue;
    }
    if (writing_state_ == NOT_WRITING)
      OnMessageStart(*frames, i);

    std::unique_ptr<WebSocketFrame> frame(std::move((*frames)[i]));
    predictor_->RecordInputDataFrame(frame.get());

    if (writing_state_ == WRITING_UNCOMPRESSED_MESSAGE) {
      if (frame->header.final)
        writing_state_ = NOT_WRITING;
      predictor_->RecordWrittenDataFrame(frame.get());
      frames_to_write.push_back(std::move(frame));
      current_writing_opcode_ = WebSocketFrameHeader::kOpCodeContinuation;
    } else {
      if (!frame->payload.empty() &&
          !deflater_.AddBytes(base::as_chars(frame->payload).data(),
                              frame->payload.size())) {
        DVLOG(1) << "WebSocket protocol error. "
                 << "deflater_.AddBytes() returns an error.";
        return ERR_WS_PROTOCOL_ERROR;
      }
      if (frame->header.final && !deflater_.Finish()) {
        DVLOG(1) << "WebSocket protocol error. "
                 << "deflater_.Finish() returns an error.";
        return ERR_WS_PROTOCOL_ERROR;
      }

      if (writing_state_ == WRITING_COMPRESSED_MESSAGE) {
        if (deflater_.CurrentOutputSize() >= kChunkSize ||
            frame->header.final) {
          int result = AppendCompressedFrame(frame->header, &frames_to_write);
          if (result != OK)
            return result;
        }
        if (frame->header.final)
          writing_state_ = NOT_WRITING;
      } else {
        DCHECK_EQ(WRITING_POSSIBLY_COMPRESSED_MESSAGE, writing_state_);
        bool final = frame->header.final;
        frames_of_message.push_back(std::move(frame));
        if (final) {
          int result = AppendPossiblyCompressedMessage(&frames_of_message,
                                                       &frames_to_write);
          if (result != OK)
            return result;
          frames_of_message.clear();
          writing_state_ = NOT_WRITING;
        }
      }
    }
  }
  DCHECK_NE(WRITING_POSSIBLY_COMPRESSED_MESSAGE, writing_state_);
  frames->swap(frames_to_write);
  return OK;
}

void WebSocketDeflateStream::OnMessageStart(
    const std::vector<std::unique_ptr<WebSocketFrame>>& frames,
    size_t index) {
  WebSocketFrame* frame = frames[index].get();
  current_writing_opcode_ = frame->header.opcode;
  DCHECK(current_writing_opcode_ == WebSocketFrameHeader::kOpCodeText ||
         current_writing_opcode_ == WebSocketFrameHeader::kOpCodeBinary);
  WebSocketDeflatePredictor::Result prediction =
      predictor_->Predict(frames, index);

  switch (prediction) {
    case WebSocketDeflatePredictor::DEFLATE:
      writing_state_ = WRITING_COMPRESSED_MESSAGE;
      return;
    case WebSocketDeflatePredictor::DO_NOT_DEFLATE:
      writing_state_ = WRITING_UNCOMPRESSED_MESSAGE;
      return;
    case WebSocketDeflatePredictor::TRY_DEFLATE:
      writing_state_ = WRITING_POSSIBLY_COMPRESSED_MESSAGE;
      return;
  }
  NOTREACHED();
}

int WebSocketDeflateStream::AppendCompressedFrame(
    const WebSocketFrameHeader& header,
    std::vector<std::unique_ptr<WebSocketFrame>>* frames_to_write) {
  const WebSocketFrameHeader::OpCode opcode = current_writing_opcode_;
  scoped_refptr<IOBufferWithSize> compressed_payload =
      deflater_.GetOutput(deflater_.CurrentOutputSize());
  if (!compressed_payload.get()) {
    DVLOG(1) << "WebSocket protocol error. "
             << "deflater_.GetOutput() returns an error.";
    return ERR_WS_PROTOCOL_ERROR;
  }
  deflater_outputs_.push_back(compressed_payload);
  auto compressed = std::make_unique<WebSocketFrame>(opcode);
  compressed->header.CopyFrom(header);
  compressed->header.opcode = opcode;
  compressed->header.final = header.final;
  compressed->header.reserved1 =
      (opcode != WebSocketFrameHeader::kOpCodeContinuation);
  compressed->payload = compressed_payload->span();
  compressed->header.payload_length = compressed_payload->size();

  current_writing_opcode_ = WebSocketFrameHeader::kOpCodeContinuation;
  predictor_->RecordWrittenDataFrame(compressed.get());
  frames_to_write->push_back(std::move(compressed));
  return OK;
}

int WebSocketDeflateStream::AppendPossiblyCompressedMessage(
    std::vector<std::unique_ptr<WebSocketFrame>>* frames,
    std::vector<std::unique_ptr<WebSocketFrame>>* frames_to_write) {
  DCHECK(!frames->empty());

  const WebSocketFrameHeader::OpCode opcode = current_writing_opcode_;
  scoped_refptr<IOBufferWithSize> compressed_payload =
      deflater_.GetOutput(deflater_.CurrentOutputSize());
  if (!compressed_payload.get()) {
    DVLOG(1) << "WebSocket protocol error. "
             << "deflater_.GetOutput() returns an error.";
    return ERR_WS_PROTOCOL_ERROR;
  }
  deflater_outputs_.push_back(compressed_payload);

  uint64_t original_payload_length = 0;
  for (size_t i = 0; i < frames->size(); ++i) {
    WebSocketFrame* frame = (*frames)[i].get();
    // Asserts checking that frames represent one whole data message.
    DCHECK(WebSocketFrameHeader::IsKnownDataOpCode(frame->header.opcode));
    DCHECK_EQ(i == 0,
              WebSocketFrameHeader::kOpCodeContinuation !=
              frame->header.opcode);
    DCHECK_EQ(i == frames->size() - 1, frame->header.final);
    original_payload_length += frame->header.payload_length;
  }
  if (original_payload_length <=
      static_cast<uint64_t>(compressed_payload->size())) {
    // Compression is not effective. Use the original frames.
    for (auto& frame : *frames) {
      predictor_->RecordWrittenDataFrame(frame.get());
      frames_to_write->push_back(std::move(frame));
    }
    frames->clear();
    return OK;
  }
  auto compressed = std::make_unique<WebSocketFrame>(opcode);
  compressed->header.CopyFrom((*frames)[0]->header);
  compressed->header.opcode = opcode;
  compressed->header.final = true;
  compressed->header.reserved1 = true;
  compressed->payload = compressed_payload->span();
  compressed->header.payload_length = compressed_payload->size();

  predictor_->RecordWrittenDataFrame(compressed.get());
  frames_to_write->push_back(std::move(compressed));
  return OK;
}

int WebSocketDeflateStream::Inflate(
    std::vector<std::unique_ptr<WebSocketFrame>>* frames) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  std::vector<std::unique_ptr<WebSocketFrame>> frames_passed;
  frames->swap(frames_passed);
  for (auto& frame_passed : frames_passed) {
    std::unique_ptr<WebSocketFrame> frame(std::move(frame_passed));
    frame_passed = nullptr;
    DVLOG(3) << "Input frame: opcode=" << frame->header.opcode
             << " final=" << frame->header.final
             << " reserved1=" << frame->header.reserved1
             << " payload_length=" << frame->header.payload_length;

    if (!WebSocketFrameHeader::IsKnownDataOpCode(frame->header.opcode)) {
      frames_to_output.push_back(std::move(frame));
      continue;
    }

    if (reading_state_ == NOT_READING) {
      if (frame->header.reserved1)
        reading_state_ = READING_COMPRESSED_MESSAGE;
      else
        reading_state_ = READING_UNCOMPRESSED_MESSAGE;
      current_reading_opcode_ = frame->header.opcode;
    } else {
      if (frame->header.reserved1) {
        DVLOG(1) << "WebSocket protocol error. "
                 << "Receiving a non-first frame with RSV1 flag set.";
        return ERR_WS_PROTOCOL_ERROR;
      }
    }

    if (reading_state_ == READING_UNCOMPRESSED_MESSAGE) {
      if (frame->header.final)
        reading_state_ = NOT_READING;
      current_reading_opcode_ = WebSocketFrameHeader::kOpCodeContinuation;
      frames_to_output.push_back(std::move(frame));
    } else {
      DCHECK_EQ(reading_state_, READING_COMPRESSED_MESSAGE);
      if (!frame->payload.empty() &&
          !inflater_.AddBytes(base::as_chars(frame->payload).data(),
                              frame->payload.size())) {
        DVLOG(1) << "WebSocket protocol error. "
                 << "inflater_.AddBytes() returns an error.";
        return ERR_WS_PROTOCOL_ERROR;
      }
      if (frame->header.final) {
        if (!inflater_.Finish()) {
          DVLOG(1) << "WebSocket protocol error. "
                   << "inflater_.Finish() returns an error.";
          return ERR_WS_PROTOCOL_ERROR;
        }
      }
      // TODO(yhirano): Many frames can be generated by the inflater and
      // memory consumption can grow.
      // We could avoid it, but avoiding it makes this class much more
      // complicated.
      while (inflater_.CurrentOutputSize() >= kChunkSize ||
             frame->header.final) {
        size_t size = std::min(kChunkSize, inflater_.CurrentOutputSize());
        auto inflated =
            std::make_unique<WebSocketFrame>(WebSocketFrameHeader::kOpCodeText);
        scoped_refptr<IOBufferWithSize> data = inflater_.GetOutput(size);
        inflater_outputs_.push_back(data);
        bool is_final = !inflater_.CurrentOutputSize() && frame->header.final;
        if (!data.get()) {
          DVLOG(1) << "WebSocket protocol error. "
                   << "inflater_.GetOutput() returns an error.";
          return ERR_WS_PROTOCOL_ERROR;
        }
        inflated->header.CopyFrom(frame->header);
        inflated->header.opcode = current_reading_opcode_;
        inflated->header.final = is_final;
        inflated->header.reserved1 = false;
        inflated->payload = data->span();
        inflated->header.payload_length = data->size();
        DVLOG(3) << "Inflated frame: opcode=" << inflated->header.opcode
                 << " final=" << inflated->header.final
                 << " reserved1=" << inflated->header.reserved1
                 << " payload_length=" << inflated->header.payload_length;
        frames_to_output.push_back(std::move(inflated));
        current_reading_opcode_ = WebSocketFrameHeader::kOpCodeContinuation;
        if (is_final)
          break;
      }
      if (frame->header.final)
        reading_state_ = NOT_READING;
    }
  }
  frames->swap(frames_to_output);
  return frames->empty() ? ERR_IO_PENDING : OK;
}

int WebSocketDeflateStream::InflateAndReadIfNecessary(
    std::vector<std::unique_ptr<WebSocketFrame>>* frames) {
  int result = Inflate(frames);
  while (result == ERR_IO_PENDING) {
    DCHECK(frames->empty());

    result = stream_->ReadFrames(
        frames,
        base::BindOnce(&WebSocketDeflateStream::OnReadComplete,
                       base::Unretained(this), base::Unretained(frames)));
    if (result < 0)
      break;
    DCHECK_EQ(OK, result);
    DCHECK(!frames->empty());

    result = Inflate(frames);
  }
  if (result < 0)
    frames->clear();
  return result;
}

}  // namespace net

"""

```
Response:
Let's break down the request and the provided code to construct a comprehensive answer.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the `websocket_inflater.cc` file within the Chromium networking stack. Key aspects they are interested in are:

* **Functionality:** What does this code *do*?
* **Relationship to JavaScript:** How does this low-level C++ code connect to web browser functionality, specifically concerning JavaScript?
* **Logical Reasoning (Input/Output):**  Can we provide examples of how this code processes data?
* **Common Errors:** What mistakes might developers or users make that could involve this code?
* **Debugging:** How does a user's action lead to this code being executed?

**2. Initial Code Analysis (Skimming and Identifying Key Components):**

I first scanned the code for keywords and structure:

* **`#include` directives:**  `zlib.h` immediately stands out, indicating compression/decompression.
* **Class Names:** `WebSocketInflater`, `OutputBuffer`, `InputQueue`. These suggest the core purpose is related to inflating (decompressing) data in a WebSocket context.
* **Methods:** `Initialize`, `AddBytes`, `Finish`, `GetOutput`, `InflateWithFlush`, `Inflate`, `InflateChokedInput`. These describe the life cycle and operational steps of the inflater.
* **Data Structures:**  `input_queue_`, `output_buffer_`. These manage the flow of data.
* **`z_stream`:** This confirms the use of zlib for deflation/inflation.
* **`IOBufferWithSize`:**  Indicates handling of network buffers.

**3. Connecting the Dots (Building the Functional Explanation):**

Based on the keywords and structure, I formed a hypothesis: This code is responsible for decompressing data received over a WebSocket connection that has been compressed using the DEFLATE algorithm.

I then went through the methods to confirm this hypothesis and detail the steps:

* **`Initialize`:** Sets up the zlib decompression stream. The `-window_bits` parameter is important for the "permessage-deflate" extension in WebSockets.
* **`AddBytes`:** Feeds compressed data into the inflater. It handles cases where the input needs to be queued.
* **`Finish`:**  Signals the end of the compressed data stream, adding specific bytes as per the RFC.
* **`GetOutput`:** Retrieves the decompressed data. It manages the `output_buffer_` and handles cases where more input needs to be processed (`InflateChokedInput`).
* **`InflateWithFlush` and `Inflate`:** These are the core decompression functions using the zlib library. The `flush` parameter is important for managing the decompression process. `InflateWithFlush` is a wrapper to ensure data is pushed out.
* **`InflateChokedInput`:**  Handles the situation where the input queue has data waiting to be decompressed.

**4. Addressing the JavaScript Connection:**

This requires understanding how WebSockets work in a browser. The browser's JavaScript WebSocket API handles the high-level connection. The browser's *internal* networking stack (where this C++ code resides) handles the lower-level details, including compression. The connection is that the JavaScript API triggers the browser's networking layer, which then uses components like `WebSocketInflater` when decompression is needed.

**5. Developing Logical Reasoning (Input/Output Examples):**

I needed to create concrete examples to illustrate how the functions work. This involved:

* **Hypothetical Compressed Data:**  A simple example like `[0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]` (a minimal compressed string "A").
* **Step-by-step execution:**  Walking through how `AddBytes`, `Finish`, and `GetOutput` would process this data.
* **Illustrating the buffering:** Showing how `input_queue_` and `output_buffer_` would be used.

**6. Identifying Common Errors:**

I considered potential pitfalls:

* **Incorrect `window_bits`:**  A mismatch between the server and client configuration.
* **Incomplete compressed data:** Not sending all the compressed bytes.
* **Not calling `Finish`:** Leading to incomplete decompression.
* **Requesting too much output:**  Trying to read more data than is available.

**7. Tracing User Actions to the Code (Debugging Clues):**

This requires outlining the user's interaction with a web page:

* **Opening a webpage:** This initiates the process.
* **JavaScript WebSocket connection:**  The crucial step where the compression extension is negotiated.
* **Server sending compressed data:** This triggers the need for decompression.
* **Browser receiving data:** This is when the `WebSocketInflater` comes into play.

**8. Structuring the Answer:**

Finally, I organized the information logically, using headings and bullet points to make it easy to read and understand. I included:

* A concise summary of the file's purpose.
* Detailed explanations of the key functions.
* The JavaScript connection with an example.
* The input/output examples with clear assumptions.
* Common usage errors.
* The step-by-step user action trace.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focusing solely on the decompression algorithm.
* **Correction:** Realizing the importance of the WebSocket context and the interaction with JavaScript.
* **Initial thought:**  Providing overly technical details about zlib.
* **Correction:**  Focusing on the *purpose* of the zlib calls within the `WebSocketInflater` class.
* **Initial thought:**  Overlooking the buffering mechanisms (`input_queue_`, `output_buffer_`).
* **Correction:**  Highlighting their role in managing the flow of data, especially when input arrives in chunks.

By following these steps of understanding the request, analyzing the code, connecting the concepts, and structuring the answer, I aimed to provide a comprehensive and helpful explanation.
这个文件 `net/websockets/websocket_inflater.cc` 是 Chromium 网络栈中专门用于 **解压缩通过 WebSocket 连接接收到的压缩数据** 的组件。 它实现了 WebSocket 的 `permessage-deflate` 扩展，该扩展允许在 WebSocket 消息帧级别使用 DEFLATE 算法进行压缩，以减少网络传输的数据量。

以下是它的主要功能：

1. **初始化解压缩器:**
   - `Initialize(int window_bits)` 函数负责初始化 zlib 解压缩库。 `window_bits` 参数控制 zlib 使用的滑动窗口大小，这个参数需要在客户端和服务器端保持一致。

2. **添加压缩数据:**
   - `AddBytes(const char* data, size_t size)` 函数接收从网络接收到的压缩数据块。
   - 它会将数据添加到内部的 `input_queue_` 中，或者如果当前没有待处理的输入，则直接尝试解压缩。
   - 如果解压缩过程中 `inflate` 函数返回 `Z_BUF_ERROR`，表示输出缓冲区已满，则将剩余的输入数据放入 `input_queue_` 中，等待后续处理。

3. **完成解压缩 (添加尾部标记):**
   - `Finish()` 函数用于指示压缩数据流的结束。它会向解压缩器添加特定的尾部字节 (`\x00\x00\xff\xff`)，这是 `permessage-deflate` 扩展要求的，用于确保 zlib 能正确完成解压缩。

4. **获取解压缩后的数据:**
   - `GetOutput(size_t size)` 函数尝试从内部的 `output_buffer_` 中获取最多 `size` 字节的解压缩后的数据。
   - 如果 `output_buffer_` 中的数据不足，它会尝试从 `input_queue_` 中读取压缩数据并进行解压缩，直到满足请求的大小或没有更多输入数据。

5. **内部解压缩逻辑:**
   - `InflateWithFlush(const char* next_in, size_t avail_in)` 和 `Inflate(const char* next_in, size_t avail_in, int flush)` 函数是实际调用 zlib 库进行解压缩的核心部分。
   - `Inflate` 函数将输入数据提供给 zlib 的 `inflate` 函数，并将解压缩后的数据写入内部的 `output_buffer_`。
   - `InflateWithFlush` 在解压缩后会检查输出缓冲区是否为空，如果为空，则会使用 `Z_SYNC_FLUSH` 再次调用 `Inflate` 以确保所有数据都被处理。

6. **处理阻塞的输入:**
   - `InflateChokedInput()` 函数用于处理 `input_queue_` 中缓存的压缩数据。当输出缓冲区满导致解压缩暂停时，后续调用 `GetOutput` 会触发此函数，尝试解压缩队列中的数据。

7. **管理输入和输出缓冲区:**
   - 内部的 `InputQueue` 类用于管理接收到的压缩数据，它允许缓冲多个数据块。
   - 内部的 `OutputBuffer` 类是一个环形缓冲区，用于存储解压缩后的数据。

**与 JavaScript 功能的关系：**

`WebSocketInflater` 本身是一个 C++ 组件，JavaScript 代码不能直接调用它。但是，它在幕后支持了浏览器提供的 WebSocket API 的功能。当 JavaScript 代码使用 `WebSocket` API 与支持 `permessage-deflate` 扩展的服务器建立连接并接收到压缩的消息时，浏览器底层的网络栈就会使用 `WebSocketInflater` 来解压缩这些数据，然后将解压缩后的数据传递给 JavaScript 代码。

**举例说明：**

假设一个 JavaScript 代码创建了一个 WebSocket 连接并接收到了一条压缩的消息：

```javascript
const websocket = new WebSocket('wss://example.com', ['permessage-deflate']);

websocket.onmessage = (event) => {
  console.log('Received message:', event.data);
};
```

当浏览器接收到来自服务器的压缩 WebSocket 帧时，底层的网络栈会执行以下步骤（涉及到 `WebSocketInflater`）：

1. **接收压缩数据:** 网络层接收到包含压缩数据的 TCP 包。
2. **传递给 WebSocket 处理器:**  接收到的数据被传递给 WebSocket 协议的处理器。
3. **使用 `WebSocketInflater` 解压缩:** WebSocket 处理器检测到 `permessage-deflate` 扩展被使用，并调用 `WebSocketInflater::AddBytes()` 将压缩数据提供给解压缩器。
4. **解压缩过程:** `WebSocketInflater` 使用 zlib 库进行解压缩，并将解压缩后的数据存储在内部的 `output_buffer_` 中。
5. **获取解压缩后的数据:** 当 JavaScript 的 `onmessage` 事件被触发时，浏览器会从 `WebSocketInflater` 的 `output_buffer_` 中获取解压缩后的数据。
6. **传递给 JavaScript:** 解压缩后的数据最终作为 `event.data` 传递给 JavaScript 的 `onmessage` 回调函数。

**逻辑推理，假设输入与输出：**

**假设输入:**  接收到一段经过 DEFLATE 压缩的 WebSocket 消息帧内容，例如表示字符串 "Hello" 的压缩字节序列（假设使用 `-15` 的 `window_bits`）： `\x78\x9c\xfb\x48\xcd\xc9\xc9\x07\x00\x05\xfb\x01\x13`

**步骤:**

1. **`AddBytes(data, data.length)` 被调用:** `WebSocketInflater` 接收到上述压缩数据。
2. **`InflateWithFlush` 或 `Inflate` 被调用:**  `WebSocketInflater` 调用 zlib 的 `inflate` 函数进行解压缩。
3. **解压缩过程:** zlib 将压缩数据解压缩为原始的 "Hello" 字符串。
4. **数据存储到 `output_buffer_`:** 解压缩后的 "Hello" 被存储到 `WebSocketInflater` 的内部输出缓冲区 `output_buffer_` 中。
5. **`GetOutput(5)` 被调用:** 当需要获取数据时，例如浏览器准备将消息传递给 JavaScript，`GetOutput(5)` (假设 "Hello" 长度为 5) 被调用。
6. **输出:** `GetOutput` 函数从 `output_buffer_` 中读取 "Hello" 并返回一个包含 "Hello" 的 `IOBufferWithSize`。

**用户或编程常见的使用错误：**

1. **服务器和客户端的 `window_bits` 配置不一致:** 如果客户端和服务器配置的 `window_bits` 值不同，解压缩将会失败，导致消息解析错误或连接中断。
   - **例子:**  服务器配置了 `window_bits = 15`，而客户端代码中（或者浏览器内部实现）初始化 `WebSocketInflater` 时使用了不同的值。
2. **没有调用 `Finish()`:** 如果在接收完所有压缩数据后没有调用 `Finish()`，zlib 可能无法完成解压缩，导致部分数据丢失或解压错误。
   - **例子:**  在处理分片的压缩消息时，忘记在最后一个分片处理完毕后调用 `Finish()`。
3. **过早或错误地调用 `GetOutput()`:**  在没有足够的数据被解压缩之前就尝试获取输出，可能会导致获取到空数据或部分数据。
   - **例子:**  在 `AddBytes()` 之后立即调用 `GetOutput()`，而此时解压缩过程可能尚未完成。
4. **假设压缩总是发生:**  虽然客户端请求了 `permessage-deflate` 扩展，但服务器可能选择不压缩某些消息。代码需要能够处理未压缩的消息，而 `WebSocketInflater` 只应该用于处理压缩的数据。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中访问一个网页:**  例如，用户在 Chrome 浏览器中输入一个网址并访问。
2. **网页中的 JavaScript 代码尝试建立 WebSocket 连接:** 网页中的 JavaScript 代码创建了一个 `WebSocket` 对象，并指定了 `'permessage-deflate'` 子协议，表示希望使用压缩。
   ```javascript
   const websocket = new WebSocket('wss://example.com', ['permessage-deflate']);
   ```
3. **浏览器与服务器进行 WebSocket 握手:** 浏览器发送握手请求，其中包含对 `permessage-deflate` 扩展的支持。
4. **服务器同意使用压缩扩展:** 服务器在握手响应中也包含了 `permessage-deflate` 扩展的确认信息。
5. **服务器发送压缩的 WebSocket 消息帧:**  当服务器需要向客户端发送数据时，它会使用 DEFLATE 算法压缩消息内容，并将其封装在 WebSocket 帧中发送。
6. **浏览器网络栈接收到压缩数据:**  Chrome 浏览器的网络栈接收到来自服务器的 TCP 数据包，其中包含压缩的 WebSocket 帧。
7. **WebSocket 协议处理器识别压缩标志:**  网络栈中的 WebSocket 协议处理器解析接收到的帧头，识别出该帧使用了 `permessage-deflate` 扩展。
8. **创建或使用 `WebSocketInflater` 实例:**  WebSocket 协议处理器会创建一个 `WebSocketInflater` 实例（如果尚未创建）来处理解压缩。
9. **调用 `WebSocketInflater::AddBytes()`:**  接收到的压缩数据（消息帧的 payload 部分）被传递给 `WebSocketInflater` 的 `AddBytes()` 函数。
10. **解压缩过程 (`InflateWithFlush` 或 `Inflate`):** `WebSocketInflater` 内部使用 zlib 库进行解压缩。
11. **解压缩后的数据存储:** 解压缩后的数据被存储在 `WebSocketInflater` 的 `output_buffer_` 中。
12. **触发 `onmessage` 事件:** 当解压缩完成并且可以提供完整消息时，浏览器会触发 JavaScript `WebSocket` 对象的 `onmessage` 事件。
13. **调用 `WebSocketInflater::GetOutput()`:**  在触发 `onmessage` 事件之前，浏览器会调用 `WebSocketInflater::GetOutput()` 来获取解压缩后的数据。
14. **JavaScript 代码处理接收到的数据:**  JavaScript 的 `onmessage` 回调函数接收到解压缩后的数据 `event.data`。

**调试线索:**

如果在 WebSocket 通信中遇到消息解析错误或者乱码，并且确认服务器端使用了 `permessage-deflate` 扩展，那么可以怀疑 `WebSocketInflater` 的解压缩过程出现了问题。调试时可以关注以下几点：

- **确认客户端和服务器是否成功协商了 `permessage-deflate` 扩展。** 检查 WebSocket 连接的握手过程。
- **检查服务器发送的压缩数据是否符合 DEFLATE 格式。** 可以使用 Wireshark 等网络抓包工具捕获 WebSocket 数据包，并分析压缩数据的内容。
- **在 Chromium 源代码中添加断点，跟踪 `WebSocketInflater` 的 `AddBytes`、`Inflate`、`GetOutput` 等函数的执行流程，查看输入和输出的数据。**
- **检查 `window_bits` 的配置是否正确。** 确保客户端和服务器使用了相同的 `window_bits` 值。
- **查看 zlib 库的返回值，判断解压缩过程中是否出现了错误。**

总而言之，`net/websockets/websocket_inflater.cc` 文件在 Chromium 中扮演着关键的角色，它负责高效地解压缩 WebSocket 通信中的压缩数据，从而优化网络性能并减少带宽消耗。理解其工作原理对于调试 WebSocket 相关的问题至关重要。

Prompt: 
```
这是目录为net/websockets/websocket_inflater.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/websockets/websocket_inflater.h"

#include <string.h>

#include <algorithm>
#include <vector>

#include "base/check.h"
#include "base/check_op.h"
#include "net/base/io_buffer.h"
#include "third_party/zlib/zlib.h"

namespace net {

namespace {

class ShrinkableIOBufferWithSize : public IOBufferWithSize {
 public:
  explicit ShrinkableIOBufferWithSize(size_t size) : IOBufferWithSize(size) {}

  void Shrink(int new_size) {
    CHECK_GE(new_size, 0);
    CHECK_LE(new_size, size_);
    size_ = new_size;
  }

 private:
  ~ShrinkableIOBufferWithSize() override = default;
};

}  // namespace

WebSocketInflater::WebSocketInflater()
    : input_queue_(kDefaultInputIOBufferCapacity),
      output_buffer_(kDefaultBufferCapacity) {}

WebSocketInflater::WebSocketInflater(size_t input_queue_capacity,
                                     size_t output_buffer_capacity)
    : input_queue_(input_queue_capacity),
      output_buffer_(output_buffer_capacity) {
  DCHECK_GT(input_queue_capacity, 0u);
  DCHECK_GT(output_buffer_capacity, 0u);
}

bool WebSocketInflater::Initialize(int window_bits) {
  DCHECK_LE(8, window_bits);
  DCHECK_GE(15, window_bits);
  stream_ = std::make_unique<z_stream>();
  memset(stream_.get(), 0, sizeof(*stream_));
  int result = inflateInit2(stream_.get(), -window_bits);
  if (result != Z_OK) {
    inflateEnd(stream_.get());
    stream_.reset();
    return false;
  }
  return true;
}

WebSocketInflater::~WebSocketInflater() {
  if (stream_) {
    inflateEnd(stream_.get());
    stream_.reset();
  }
}

bool WebSocketInflater::AddBytes(const char* data, size_t size) {
  if (!size)
    return true;

  if (!input_queue_.IsEmpty()) {
    // choked
    input_queue_.Push(data, size);
    return true;
  }

  int result = InflateWithFlush(data, size);
  if (stream_->avail_in > 0)
    input_queue_.Push(&data[size - stream_->avail_in], stream_->avail_in);

  return result == Z_OK || result == Z_BUF_ERROR;
}

bool WebSocketInflater::Finish() {
  return AddBytes("\x00\x00\xff\xff", 4);
}

scoped_refptr<IOBufferWithSize> WebSocketInflater::GetOutput(size_t size) {
  auto buffer = base::MakeRefCounted<ShrinkableIOBufferWithSize>(size);
  size_t num_bytes_copied = 0;

  while (num_bytes_copied < size && output_buffer_.Size() > 0) {
    size_t num_bytes_to_copy =
        std::min(output_buffer_.Size(), size - num_bytes_copied);
    output_buffer_.Read(&buffer->data()[num_bytes_copied], num_bytes_to_copy);
    num_bytes_copied += num_bytes_to_copy;
    int result = InflateChokedInput();
    if (result != Z_OK && result != Z_BUF_ERROR)
      return nullptr;
  }
  buffer->Shrink(num_bytes_copied);
  return buffer;
}

int WebSocketInflater::InflateWithFlush(const char* next_in, size_t avail_in) {
  int result = Inflate(next_in, avail_in, Z_NO_FLUSH);
  if (result != Z_OK && result != Z_BUF_ERROR)
    return result;

  if (CurrentOutputSize() > 0)
    return result;
  // CurrentOutputSize() == 0 means there is no data to be output,
  // so we should make sure it by using Z_SYNC_FLUSH.
  return Inflate(reinterpret_cast<const char*>(stream_->next_in),
                 stream_->avail_in,
                 Z_SYNC_FLUSH);
}

int WebSocketInflater::Inflate(const char* next_in,
                               size_t avail_in,
                               int flush) {
  stream_->next_in = reinterpret_cast<Bytef*>(const_cast<char*>(next_in));
  stream_->avail_in = avail_in;

  int result = Z_BUF_ERROR;
  do {
    std::pair<char*, size_t> tail = output_buffer_.GetTail();
    if (!tail.second)
      break;

    stream_->next_out = reinterpret_cast<Bytef*>(tail.first);
    stream_->avail_out = tail.second;
    result = inflate(stream_.get(), flush);
    output_buffer_.AdvanceTail(tail.second - stream_->avail_out);
    if (result == Z_STREAM_END) {
      // Received a block with BFINAL set to 1. Reset the decompression state.
      result = inflateReset(stream_.get());
    } else if (tail.second == stream_->avail_out) {
      break;
    }
  } while (result == Z_OK || result == Z_BUF_ERROR);
  return result;
}

int WebSocketInflater::InflateChokedInput() {
  if (input_queue_.IsEmpty())
    return InflateWithFlush(nullptr, 0);

  int result = Z_BUF_ERROR;
  while (!input_queue_.IsEmpty()) {
    std::pair<char*, size_t> top = input_queue_.Top();

    result = InflateWithFlush(top.first, top.second);
    input_queue_.Consume(top.second - stream_->avail_in);

    if (result != Z_OK && result != Z_BUF_ERROR)
      return result;

    if (stream_->avail_in > 0) {
      // There are some data which are not consumed.
      break;
    }
  }
  return result;
}

WebSocketInflater::OutputBuffer::OutputBuffer(size_t capacity)
    : capacity_(capacity),
      buffer_(capacity_ + 1)  // 1 for sentinel
{}

WebSocketInflater::OutputBuffer::~OutputBuffer() = default;

size_t WebSocketInflater::OutputBuffer::Size() const {
  return (tail_ + buffer_.size() - head_) % buffer_.size();
}

std::pair<char*, size_t> WebSocketInflater::OutputBuffer::GetTail() {
  DCHECK_LT(tail_, buffer_.size());
  return std::pair(&buffer_[tail_],
                   std::min(capacity_ - Size(), buffer_.size() - tail_));
}

void WebSocketInflater::OutputBuffer::Read(char* dest, size_t size) {
  DCHECK_LE(size, Size());

  size_t num_bytes_copied = 0;
  if (tail_ < head_) {
    size_t num_bytes_to_copy = std::min(size, buffer_.size() - head_);
    DCHECK_LT(head_, buffer_.size());
    memcpy(&dest[num_bytes_copied], &buffer_[head_], num_bytes_to_copy);
    AdvanceHead(num_bytes_to_copy);
    num_bytes_copied += num_bytes_to_copy;
  }

  if (num_bytes_copied == size)
    return;
  DCHECK_LE(head_, tail_);
  size_t num_bytes_to_copy = size - num_bytes_copied;
  DCHECK_LE(num_bytes_to_copy, tail_ - head_);
  DCHECK_LT(head_, buffer_.size());
  memcpy(&dest[num_bytes_copied], &buffer_[head_], num_bytes_to_copy);
  AdvanceHead(num_bytes_to_copy);
  num_bytes_copied += num_bytes_to_copy;
  DCHECK_EQ(size, num_bytes_copied);
  return;
}

void WebSocketInflater::OutputBuffer::AdvanceHead(size_t advance) {
  DCHECK_LE(advance, Size());
  head_ = (head_ + advance) % buffer_.size();
}

void WebSocketInflater::OutputBuffer::AdvanceTail(size_t advance) {
  DCHECK_LE(advance + Size(), capacity_);
  tail_ = (tail_ + advance) % buffer_.size();
}

WebSocketInflater::InputQueue::InputQueue(size_t capacity)
    : capacity_(capacity) {}

WebSocketInflater::InputQueue::~InputQueue() = default;

std::pair<char*, size_t> WebSocketInflater::InputQueue::Top() {
  DCHECK(!IsEmpty());
  if (buffers_.size() == 1) {
    return std::pair(&buffers_.front()->data()[head_of_first_buffer_],
                     tail_of_last_buffer_ - head_of_first_buffer_);
  }
  return std::pair(&buffers_.front()->data()[head_of_first_buffer_],
                   capacity_ - head_of_first_buffer_);
}

void WebSocketInflater::InputQueue::Push(const char* data, size_t size) {
  if (!size)
    return;

  size_t num_copied_bytes = 0;
  if (!IsEmpty())
    num_copied_bytes += PushToLastBuffer(data, size);

  while (num_copied_bytes < size) {
    DCHECK(IsEmpty() || tail_of_last_buffer_ == capacity_);

    buffers_.push_back(base::MakeRefCounted<IOBufferWithSize>(capacity_));
    tail_of_last_buffer_ = 0;
    num_copied_bytes +=
        PushToLastBuffer(&data[num_copied_bytes], size - num_copied_bytes);
  }
}

void WebSocketInflater::InputQueue::Consume(size_t size) {
  DCHECK(!IsEmpty());
  DCHECK_LE(size + head_of_first_buffer_, capacity_);

  head_of_first_buffer_ += size;
  if (head_of_first_buffer_ == capacity_) {
    buffers_.pop_front();
    head_of_first_buffer_ = 0;
  }
  if (buffers_.size() == 1 && head_of_first_buffer_ == tail_of_last_buffer_) {
    buffers_.pop_front();
    head_of_first_buffer_ = 0;
    tail_of_last_buffer_ = 0;
  }
}

size_t WebSocketInflater::InputQueue::PushToLastBuffer(const char* data,
                                                       size_t size) {
  DCHECK(!IsEmpty());
  size_t num_bytes_to_copy = std::min(size, capacity_ - tail_of_last_buffer_);
  if (!num_bytes_to_copy)
    return 0;
  IOBufferWithSize* buffer = buffers_.back().get();
  memcpy(&buffer->data()[tail_of_last_buffer_], data, num_bytes_to_copy);
  tail_of_last_buffer_ += num_bytes_to_copy;
  return num_bytes_to_copy;
}

}  // namespace net

"""

```
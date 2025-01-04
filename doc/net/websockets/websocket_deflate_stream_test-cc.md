Response:
My thinking process to analyze the C++ code and answer the user's request follows these steps:

1. **Understand the Goal:** The user wants to understand the purpose of the `websocket_deflate_stream_test.cc` file in Chromium's network stack. They are particularly interested in its relationship to JavaScript, any logical inferences made, common user/programming errors, and how a user action might lead to this code being executed. The request also explicitly asks for a summary of the file's functionality as the first part of a two-part explanation.

2. **High-Level Overview:** I start by scanning the `#include` statements and the overall structure of the code. This quickly reveals that it's a C++ unit test file using Google Test (`gtest`). The included headers (`net/websockets/websocket_deflate_stream.h`, `net/websockets/websocket_deflater.h`, etc.) tell me this file is specifically testing the `WebSocketDeflateStream` class, which is involved in compressing and decompressing WebSocket messages.

3. **Identify Key Components:**  I look for the main classes and functions within the test file:
    * **`MockWebSocketStream`:** This is a mock object simulating the underlying WebSocket stream. It allows the tests to control the input and output of raw WebSocket frames without involving the actual network.
    * **`WebSocketDeflatePredictorMock`:** Another mock object, this one simulates the predictor that decides whether to compress a frame. The tests can set expectations for how this predictor should behave.
    * **`WebSocketDeflateStreamTest`:** The base test fixture providing setup and helper functions.
    * **Derived Test Fixtures (`WebSocketDeflateStreamWithDoNotTakeOverContextTest`, `WebSocketDeflateStreamWithClientWindowBitsTest`):**  These indicate specific scenarios being tested, such as disabling context takeover or testing different window bit sizes.
    * **Helper Functions (`AppendTo`, `ToString`):** These simplify the creation of WebSocket frames and their string representation for easier comparison in tests.
    * **Test Cases (`TEST_F`):** These are the individual unit tests covering different aspects of the `WebSocketDeflateStream`'s functionality.
    * **Stubs (`ReadFramesStub`, `WriteFramesStub`):** These are controlled substitutes for the `ReadFrames` and `WriteFrames` methods of `MockWebSocketStream`, enabling precise control over asynchronous operations.

4. **Analyze Functionality by Test Cases:** The most effective way to understand the file's purpose is to examine the individual test cases. I read through the names of the test cases and their code to deduce what aspects of `WebSocketDeflateStream` are being verified. For example:
    * `ReadFailedImmediately`, `ReadUncompressedFrameImmediately`, `ReadCompressedFrameAsync`: These tests focus on the `ReadFrames` functionality and how it handles immediate failures, uncompressed frames, and asynchronous operations with compressed frames.
    * Tests involving `MergeMultipleFramesInReadFrames`, `SplitToMultipleFramesInReadFrames`: These explore how the stream handles fragmented compressed messages.
    * Tests checking for errors like `ReadInvalidCompressedPayload`, `Reserved1TurnsOnDuringReadingCompressedContinuationFrame`: These ensure proper error handling.
    * Tests with "Write" in their name (in Part 2) will likely cover the `WriteFrames` functionality.

5. **Address Specific User Questions:**  Now I can systematically address each part of the user's request:

    * **Functionality:** Summarize the main purpose, which is to test the `WebSocketDeflateStream` class. This class handles the compression and decompression of WebSocket messages based on the DEFLATE algorithm. It interacts with an underlying `WebSocketStream` and a `WebSocketDeflatePredictor`.

    * **Relationship with JavaScript:**  Recognize that this C++ code is part of the browser's internal implementation. JavaScript uses the `WebSocket` API. The connection is that *this C++ code is what makes the compression feature of the WebSocket API work under the hood*. Provide an example of how a JavaScript application might negotiate and send compressed messages.

    * **Logical Inference (Hypothetical Input/Output):** Select a representative test case, like `ReadCompressedFrameImmediately`. Describe the "input" as the mocked `ReadFrames` returning a compressed frame, and the "output" as the `deflate_stream_` successfully decompressing it into an uncompressed frame.

    * **Common Errors:** Think about typical errors when dealing with compression, such as:
        * Sending a compressed frame without negotiating the extension.
        * Sending invalid compressed data.
        * Mismatched compression parameters.

    * **User Operation and Debugging:** Explain the chain of events: A user action in a web page triggers JavaScript code that uses the `WebSocket` API. The browser then negotiates the `permessage-deflate` extension. When data is sent or received, the `WebSocketDeflateStream` class comes into play to handle compression/decompression. This helps a developer understand where to look during debugging.

6. **Structure the Answer:** Organize the information clearly using headings and bullet points to make it easy to read and understand. Address each part of the user's request explicitly.

7. **Review and Refine:**  Read through the answer to ensure accuracy, clarity, and completeness. Check for any jargon that might need further explanation. Ensure the summary in Part 1 is concise and accurate.

By following these steps, I can effectively analyze the C++ code and provide a comprehensive answer that addresses all aspects of the user's request. The key is to understand the role of unit tests, identify the core components being tested, and then connect the low-level C++ implementation to the higher-level concepts that a web developer using JavaScript would be familiar with.
好的，这是对文件 `net/websockets/websocket_deflate_stream_test.cc` 的功能进行归纳和分析的第 1 部分。

**文件功能归纳:**

`websocket_deflate_stream_test.cc` 是 Chromium 网络栈中用于测试 `WebSocketDeflateStream` 类的单元测试文件。`WebSocketDeflateStream` 的主要职责是在 WebSocket 连接上进行基于 DEFLATE 算法的消息压缩和解压缩。

**具体功能点:**

1. **测试 `WebSocketDeflateStream` 的读取功能 (解压缩):**  该文件包含了大量的测试用例，用于验证 `WebSocketDeflateStream` 在接收到不同类型的 WebSocket 帧时，其解压缩行为是否正确。 这些测试覆盖了以下场景：
    * **未压缩的帧:**  验证 `WebSocketDeflateStream` 能正确地传递未压缩的帧。
    * **压缩的帧:** 验证 `WebSocketDeflateStream` 能正确地解压缩完整的压缩帧。
    * **压缩的帧片段:**  验证 `WebSocketDeflateStream` 能正确地处理和合并压缩的帧片段。
    * **无效的压缩数据:** 验证 `WebSocketDeflateStream` 能检测并处理无效的压缩数据，抛出相应的错误。
    * **空帧:** 验证 `WebSocketDeflateStream` 能正确处理压缩和未压缩的空帧。
    * **控制帧穿插:** 验证 `WebSocketDeflateStream` 在处理数据帧时，能正确地跳过和传递控制帧。
    * **大数据量压缩:** 验证 `WebSocketDeflateStream` 能处理需要拆分成多个帧的大数据量压缩消息。
    * **在压缩延续帧中错误地设置 RSV1 标志:** 验证 `WebSocketDeflateStream` 能检测到违反协议的情况。
    * **连续的压缩和未压缩消息:** 验证 `WebSocketDeflateStream` 能在连续接收压缩和未压缩消息时正确处理。

2. **使用 Mock 对象进行隔离测试:**  为了更好地进行单元测试，该文件使用了 `MockWebSocketStream` 和 `WebSocketDeflatePredictorMock` 两个 Mock 对象：
    * `MockWebSocketStream`: 模拟底层的 WebSocket 流，允许测试用例控制接收到的帧和验证发送出去的帧。
    * `WebSocketDeflatePredictorMock`: 模拟压缩预测器，用于决定是否应该压缩某个帧。这允许测试用例验证 `WebSocketDeflateStream` 是否正确地与预测器进行交互。

3. **测试异步操作:**  部分测试用例模拟了异步的读取操作，验证 `WebSocketDeflateStream` 在等待底层 `WebSocketStream` 返回数据时的行为。

4. **覆盖不同的配置:**  定义了 `WebSocketDeflateStreamWithDoNotTakeOverContextTest` 和 `WebSocketDeflateStreamWithClientWindowBitsTest` 等派生测试类，用于测试在不同配置下的 `WebSocketDeflateStream`，例如禁用上下文接管和使用不同的窗口大小。

**与 Javascript 的关系及举例说明:**

虽然这个文件是 C++ 代码，但它直接关系到 Javascript 中 `WebSocket` API 的功能。 当 Javascript 代码使用 `WebSocket` 连接并启用了 `permessage-deflate` 扩展时，浏览器底层（Chromium 的网络栈）就会使用 `WebSocketDeflateStream` 来处理消息的压缩和解压缩。

**举例说明:**

假设一个 Javascript 客户端尝试建立一个支持 `permessage-deflate` 扩展的 WebSocket 连接：

```javascript
const ws = new WebSocket('wss://example.com', ['chat', 'permessage-deflate']);

ws.onopen = () => {
  const message = 'This is a long message that should be compressed.';
  ws.send(message);
};

ws.onmessage = (event) => {
  console.log('Received:', event.data);
};
```

在这个场景下，当 `ws.send(message)` 被调用时，如果 `permessage-deflate` 扩展协商成功，那么 Chromium 的网络栈就会使用 `WebSocketDeflateStream` 来压缩 `message` 的内容，然后再将压缩后的数据发送到服务器。  同样地，当接收到来自服务器的压缩消息时，`WebSocketDeflateStream` 会负责解压缩数据，然后 `ws.onmessage` 事件中的 `event.data` 才会是原始的未压缩消息。

**逻辑推理 (假设输入与输出):**

**假设输入:**  `MockWebSocketStream` 模拟接收到一个压缩的文本帧，其 payload 为 `"\xf2\x48\xcd\xc9\xc9\x07\x00"` (这是 "Hello" 压缩后的结果)。

**预期输出:** `deflate_stream_->ReadFrames` 方法成功返回，并且输出的 `WebSocketFrame` 对象的 payload 为 `"Hello"`, `header.reserved1` 为 `false` (表示已解压缩)。

**用户或编程常见的使用错误举例:**

1. **服务器和客户端压缩配置不匹配:**  如果客户端请求使用 `permessage-deflate`，但服务器没有启用或者使用了不同的配置（例如窗口大小），可能导致压缩/解压缩失败或连接错误。
2. **在没有协商扩展的情况下发送压缩数据:**  如果客户端或服务器在 WebSocket 连接建立时没有成功协商 `permessage-deflate` 扩展，但仍然尝试发送带有 RSV1 标志的压缩数据，这将违反 WebSocket 协议，导致连接中断。  `websocket_deflate_stream_test.cc` 中的某些测试用例会验证这种错误的检测。
3. **处理解压缩后的数据时未考虑到分片:** 尽管 `WebSocketDeflateStream` 会尝试合并压缩的分片，但开发者在处理 `onmessage` 事件接收到的数据时，仍然需要考虑消息可能被分片接收的情况，即使没有使用压缩。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中访问一个支持 WebSocket 的网站。**
2. **网页中的 Javascript 代码创建了一个 `WebSocket` 对象，并尝试连接到服务器，同时请求 `permessage-deflate` 扩展。**
3. **浏览器（Chromium）的网络栈发起 TCP 连接和 WebSocket 握手。**
4. **如果服务器也支持 `permessage-deflate` 扩展，握手过程中会协商成功。**
5. **之后，当 Javascript 代码调用 `ws.send()` 发送消息时，并且如果消息符合压缩的条件（取决于 `WebSocketDeflatePredictor` 的判断），`WebSocketDeflateStream` 会被用来压缩消息。**
6. **当浏览器接收到来自服务器的 WebSocket 帧时，如果该帧的 RSV1 标志被设置，表明是压缩数据，`WebSocketDeflateStream` 会被用来解压缩数据。**

在调试过程中，如果怀疑压缩/解压缩有问题，开发者可能会查看 Chromium 的网络日志 (chrome://net-export/)，或者使用 Wireshark 等工具抓包分析 WebSocket 帧的内容，查看 RSV1 标志是否正确设置，以及压缩数据的格式是否符合预期。 如果涉及到 Chromium 内部的调试，开发者可能会在 `WebSocketDeflateStream` 的相关代码中设置断点，例如在 `ReadFrames` 或进行解压缩操作的地方，来跟踪数据的处理流程。  `websocket_deflate_stream_test.cc` 中的测试用例可以帮助开发者理解 `WebSocketDeflateStream` 的预期行为，从而辅助调试。

**总结 (Part 1 的功能):**

总而言之，`websocket_deflate_stream_test.cc` 的主要功能是 **全面测试 `WebSocketDeflateStream` 类的解压缩功能**，确保它能够正确地处理各种合法的和非法的压缩数据，以及在不同的场景下都能按照 WebSocket 协议的规定工作。 它通过使用 Mock 对象隔离依赖，并覆盖了同步和异步的操作，为 `WebSocketDeflateStream` 的稳定性和正确性提供了保障。

Prompt: 
```
这是目录为net/websockets/websocket_deflate_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/websockets/websocket_deflate_stream.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/containers/circular_deque.h"
#include "base/containers/heap_array.h"
#include "base/containers/span.h"
#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/test/mock_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/log/net_log_with_source.h"
#include "net/test/gtest_util.h"
#include "net/websockets/websocket_deflate_parameters.h"
#include "net/websockets/websocket_deflate_predictor.h"
#include "net/websockets/websocket_deflater.h"
#include "net/websockets/websocket_frame.h"
#include "net/websockets/websocket_stream.h"
#include "net/websockets/websocket_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {
namespace {

using ::testing::_;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::Return;

typedef uint32_t FrameFlag;
constexpr FrameFlag kNoFlag = 0;
constexpr FrameFlag kFinal = 1;
constexpr FrameFlag kReserved1 = 2;
// We don't define values for other flags because we don't need them.

// The value must equal to the value of the corresponding
// constant in websocket_deflate_stream.cc
constexpr size_t kChunkSize = 4 * 1024;
constexpr int kWindowBits = 15;

std::string ToString(IOBufferWithSize* buffer) {
  return std::string(buffer->data(), buffer->size());
}

std::string ToString(const scoped_refptr<IOBufferWithSize>& buffer) {
  return ToString(buffer.get());
}

std::string ToString(const WebSocketFrame* frame) {
  return std::string(base::as_string_view(frame->payload));
}

std::string ToString(const std::unique_ptr<WebSocketFrame>& frame) {
  return ToString(frame.get());
}

class MockWebSocketStream : public WebSocketStream {
 public:
  MOCK_METHOD2(ReadFrames,
               int(std::vector<std::unique_ptr<WebSocketFrame>>*,
                   CompletionOnceCallback));
  MOCK_METHOD2(WriteFrames,
               int(std::vector<std::unique_ptr<WebSocketFrame>>*,
                   CompletionOnceCallback));

  MOCK_METHOD0(Close, void());
  MOCK_CONST_METHOD0(GetSubProtocol, std::string());
  MOCK_CONST_METHOD0(GetExtensions, std::string());
  MOCK_CONST_METHOD0(GetNetLogWithSource, NetLogWithSource&());
};

// This mock class relies on some assumptions.
//  - RecordInputDataFrame is called after the corresponding WriteFrames
//    call.
//  - RecordWrittenDataFrame is called before writing the frame.
class WebSocketDeflatePredictorMock : public WebSocketDeflatePredictor {
 public:
  WebSocketDeflatePredictorMock() = default;

  WebSocketDeflatePredictorMock(const WebSocketDeflatePredictorMock&) = delete;
  WebSocketDeflatePredictorMock& operator=(
      const WebSocketDeflatePredictorMock&) = delete;

  ~WebSocketDeflatePredictorMock() override {
    // Verify whether all expectaions are consumed.
    if (!frames_to_be_input_.empty()) {
      ADD_FAILURE() << "There are missing frames to be input.";
      return;
    }
    if (!frames_written_.empty()) {
      ADD_FAILURE() << "There are extra written frames.";
      return;
    }
  }

  // WebSocketDeflatePredictor functions.
  Result Predict(const std::vector<std::unique_ptr<WebSocketFrame>>& frames,
                 size_t frame_index) override {
    return result_;
  }
  void RecordInputDataFrame(const WebSocketFrame* frame) override {
    if (!WebSocketFrameHeader::IsKnownDataOpCode(frame->header.opcode)) {
      ADD_FAILURE() << "Control frames should not be recorded.";
      return;
    }
    if (frame->header.reserved1) {
      ADD_FAILURE() << "Input frame may not be compressed.";
      return;
    }
    if (frames_to_be_input_.empty()) {
      ADD_FAILURE() << "Unexpected input data frame";
      return;
    }
    if (frame != frames_to_be_input_.front()) {
      ADD_FAILURE() << "Input data frame does not match the expectation.";
      return;
    }
    frames_to_be_input_.pop_front();
  }
  void RecordWrittenDataFrame(const WebSocketFrame* frame) override {
    if (!WebSocketFrameHeader::IsKnownDataOpCode(frame->header.opcode)) {
      ADD_FAILURE() << "Control frames should not be recorded.";
      return;
    }
    frames_written_.push_back(frame);
  }

  // Sets |result_| for the |Predict| return value.
  void set_result(Result result) { result_ = result; }

  // Adds |frame| as an expectation of future |RecordInputDataFrame| call.
  void AddFrameToBeInput(const WebSocketFrame* frame) {
    if (!WebSocketFrameHeader::IsKnownDataOpCode(frame->header.opcode))
      return;
    frames_to_be_input_.push_back(frame);
  }
  // Verifies that |frame| is recorded in order.
  void VerifySentFrame(const WebSocketFrame* frame) {
    if (!WebSocketFrameHeader::IsKnownDataOpCode(frame->header.opcode))
      return;
    if (frames_written_.empty()) {
      ADD_FAILURE() << "There are missing frames to be written.";
      return;
    }
    if (frame != frames_written_.front()) {
      ADD_FAILURE() << "Written data frame does not match the expectation.";
      return;
    }
    frames_written_.pop_front();
  }
  void AddFramesToBeInput(
      const std::vector<std::unique_ptr<WebSocketFrame>>& frames) {
    for (const auto& frame : frames)
      AddFrameToBeInput(frame.get());
  }
  void VerifySentFrames(
      const std::vector<std::unique_ptr<WebSocketFrame>>& frames) {
    for (const auto& frame : frames)
      VerifySentFrame(frame.get());
  }
  // Call this method in order to disable checks in the destructor when
  // WriteFrames fails.
  void Clear() {
    frames_to_be_input_.clear();
    frames_written_.clear();
  }

 private:
  Result result_ = DEFLATE;
  // Data frames which will be recorded by |RecordInputFrames|.
  // Pushed by |AddFrameToBeInput| and popped and verified by
  // |RecordInputFrames|.
  base::circular_deque<const WebSocketFrame*> frames_to_be_input_;
  // Data frames recorded by |RecordWrittenFrames|.
  // Pushed by |RecordWrittenFrames| and popped and verified by
  // |VerifySentFrame|.
  base::circular_deque<const WebSocketFrame*> frames_written_;
};

class WebSocketDeflateStreamTest : public ::testing::Test {
 public:
  WebSocketDeflateStreamTest() = default;
  ~WebSocketDeflateStreamTest() override = default;

  void SetUp() override {
    Initialize(WebSocketDeflater::TAKE_OVER_CONTEXT, kWindowBits);
  }

 protected:
  // Initialize deflate_stream_ with the given parameters.
  void Initialize(WebSocketDeflater::ContextTakeOverMode mode,
                  int window_bits) {
    WebSocketDeflateParameters parameters;
    if (mode == WebSocketDeflater::DO_NOT_TAKE_OVER_CONTEXT) {
      parameters.SetClientNoContextTakeOver();
    }
    parameters.SetClientMaxWindowBits(window_bits);
    auto mock_stream =
        std::make_unique<testing::StrictMock<MockWebSocketStream>>();
    auto predictor = std::make_unique<WebSocketDeflatePredictorMock>();
    mock_stream_ = mock_stream.get();
    predictor_ = predictor.get();
    deflate_stream_ = std::make_unique<WebSocketDeflateStream>(
        std::move(mock_stream), parameters, std::move(predictor));
  }

  void AppendTo(std::vector<std::unique_ptr<WebSocketFrame>>* frames,
                WebSocketFrameHeader::OpCode opcode,
                FrameFlag flag) {
    auto frame = std::make_unique<WebSocketFrame>(opcode);
    frame->header.final = (flag & kFinal);
    frame->header.reserved1 = (flag & kReserved1);
    frames->push_back(std::move(frame));
  }

  void AppendTo(std::vector<std::unique_ptr<WebSocketFrame>>* frames,
                WebSocketFrameHeader::OpCode opcode,
                FrameFlag flag,
                const std::string& data) {
    auto frame = std::make_unique<WebSocketFrame>(opcode);
    frame->header.final = (flag & kFinal);
    frame->header.reserved1 = (flag & kReserved1);
    auto buffer =
        base::HeapArray<uint8_t>::CopiedFrom(base::as_byte_span(data));
    frame->payload = buffer.as_span();
    data_buffers.push_back(std::move(buffer));
    frame->header.payload_length = data.size();
    frames->push_back(std::move(frame));
  }

  std::unique_ptr<WebSocketDeflateStream> deflate_stream_;
  // Owned by |deflate_stream_|.
  raw_ptr<MockWebSocketStream> mock_stream_ = nullptr;
  // Owned by |deflate_stream_|.
  raw_ptr<WebSocketDeflatePredictorMock> predictor_ = nullptr;

  std::vector<base::HeapArray<uint8_t>> data_buffers;
};

// Since WebSocketDeflater with DoNotTakeOverContext is well tested at
// websocket_deflater_test.cc, we have only a few tests for this configuration
// here.
class WebSocketDeflateStreamWithDoNotTakeOverContextTest
    : public WebSocketDeflateStreamTest {
 public:
  WebSocketDeflateStreamWithDoNotTakeOverContextTest() = default;
  ~WebSocketDeflateStreamWithDoNotTakeOverContextTest() override = default;

  void SetUp() override {
    Initialize(WebSocketDeflater::DO_NOT_TAKE_OVER_CONTEXT, kWindowBits);
  }
};

class WebSocketDeflateStreamWithClientWindowBitsTest
    : public WebSocketDeflateStreamTest {
 public:
  WebSocketDeflateStreamWithClientWindowBitsTest() = default;
  ~WebSocketDeflateStreamWithClientWindowBitsTest() override = default;

  // Overridden to postpone the call to Initialize().
  void SetUp() override {}

  // This needs to be called explicitly from the tests.
  void SetUpWithWindowBits(int window_bits) {
    Initialize(WebSocketDeflater::TAKE_OVER_CONTEXT, window_bits);
  }

  // Add a frame which will be compressed to a smaller size if the window
  // size is large enough.
  void AddCompressibleFrameString() {
    const std::string word = "Chromium";
    const std::string payload = word + std::string(256, 'a') + word;
    AppendTo(&frames_, WebSocketFrameHeader::kOpCodeText, kFinal, payload);
    predictor_->AddFramesToBeInput(frames_);
  }

 protected:
  std::vector<std::unique_ptr<WebSocketFrame>> frames_;
};

// ReadFrameStub is a stub for WebSocketStream::ReadFrames.
// It returns |result_| and |frames_to_output_| to the caller and
// saves parameters to |frames_passed_| and |callback_|.
class ReadFramesStub {
 public:
  explicit ReadFramesStub(int result) : result_(result) {}

  ReadFramesStub(int result,
                 std::vector<std::unique_ptr<WebSocketFrame>>* frames_to_output)
      : result_(result) {
    frames_to_output_.swap(*frames_to_output);
  }

  int Call(std::vector<std::unique_ptr<WebSocketFrame>>* frames,
           CompletionOnceCallback callback) {
    DCHECK(frames->empty());
    frames_passed_ = frames;
    callback_ = std::move(callback);
    frames->swap(frames_to_output_);
    return result_;
  }

  int result() const { return result_; }
  CompletionOnceCallback& callback() { return callback_; }
  std::vector<std::unique_ptr<WebSocketFrame>>* frames_passed() {
    return frames_passed_;
  }

 private:
  int result_;
  CompletionOnceCallback callback_;
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output_;
  raw_ptr<std::vector<std::unique_ptr<WebSocketFrame>>> frames_passed_;
};

// WriteFramesStub is a stub for WebSocketStream::WriteFrames.
// It returns |result_| and |frames_| to the caller and
// saves |callback| parameter to |callback_|.
class WriteFramesStub {
 public:
  explicit WriteFramesStub(WebSocketDeflatePredictorMock* predictor,
                           int result)
      : result_(result), predictor_(predictor) {}

  int Call(std::vector<std::unique_ptr<WebSocketFrame>>* frames,
           CompletionOnceCallback callback) {
    frames_.insert(frames_.end(), std::make_move_iterator(frames->begin()),
                   std::make_move_iterator(frames->end()));
    frames->clear();
    callback_ = std::move(callback);
    predictor_->VerifySentFrames(frames_);
    return result_;
  }

  int result() const { return result_; }
  CompletionOnceCallback& callback() { return callback_; }
  std::vector<std::unique_ptr<WebSocketFrame>>* frames() { return &frames_; }

 private:
  int result_;
  CompletionOnceCallback callback_;
  std::vector<std::unique_ptr<WebSocketFrame>> frames_;
  raw_ptr<WebSocketDeflatePredictorMock> predictor_;
};

TEST_F(WebSocketDeflateStreamTest, ReadFailedImmediately) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Return(ERR_FAILED));
  }
  EXPECT_THAT(deflate_stream_->ReadFrames(&frames, CompletionOnceCallback()),
              IsError(ERR_FAILED));
}

TEST_F(WebSocketDeflateStreamTest, ReadUncompressedFrameImmediately) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kFinal,
           "hello");
  ReadFramesStub stub(OK, &frames_to_output);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, CompletionOnceCallback()),
              IsOk());
  ASSERT_EQ(1u, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
  EXPECT_TRUE(frames[0]->header.final);
  EXPECT_FALSE(frames[0]->header.reserved1);
  EXPECT_EQ("hello", ToString(frames[0]));
}

TEST_F(WebSocketDeflateStreamTest, ReadUncompressedFrameAsync) {
  ReadFramesStub stub(ERR_IO_PENDING);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  base::MockCallback<CompletionOnceCallback> mock_callback;
  base::MockCallback<base::OnceClosure> checkpoint;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
    EXPECT_CALL(checkpoint, Run());
    EXPECT_CALL(mock_callback, Run(OK));
  }
  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, mock_callback.Get()),
              IsError(ERR_IO_PENDING));
  ASSERT_EQ(0u, frames.size());

  checkpoint.Run();

  AppendTo(stub.frames_passed(),
           WebSocketFrameHeader::kOpCodeText,
           kFinal,
           "hello");
  std::move(stub.callback()).Run(OK);
  ASSERT_EQ(1u, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
  EXPECT_TRUE(frames[0]->header.final);
  EXPECT_FALSE(frames[0]->header.reserved1);
  EXPECT_EQ("hello", ToString(frames[0]));
}

TEST_F(WebSocketDeflateStreamTest, ReadFailedAsync) {
  ReadFramesStub stub(ERR_IO_PENDING);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  base::MockCallback<CompletionOnceCallback> mock_callback;
  base::MockCallback<base::OnceClosure> checkpoint;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
    EXPECT_CALL(checkpoint, Run());
    EXPECT_CALL(mock_callback, Run(ERR_FAILED));
  }
  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, mock_callback.Get()),
              IsError(ERR_IO_PENDING));
  ASSERT_EQ(0u, frames.size());

  checkpoint.Run();

  AppendTo(stub.frames_passed(),
           WebSocketFrameHeader::kOpCodeText,
           kFinal,
           "hello");
  std::move(stub.callback()).Run(ERR_FAILED);
  ASSERT_EQ(0u, frames.size());
}

TEST_F(WebSocketDeflateStreamTest, ReadCompressedFrameImmediately) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kFinal | kReserved1,
           std::string("\xf2\x48\xcd\xc9\xc9\x07\x00", 7));
  ReadFramesStub stub(OK, &frames_to_output);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, CompletionOnceCallback()),
              IsOk());
  ASSERT_EQ(1u, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
  EXPECT_TRUE(frames[0]->header.final);
  EXPECT_FALSE(frames[0]->header.reserved1);
  EXPECT_EQ("Hello", ToString(frames[0]));
}

TEST_F(WebSocketDeflateStreamTest, ReadCompressedFrameAsync) {
  ReadFramesStub stub(ERR_IO_PENDING);

  base::MockCallback<CompletionOnceCallback> mock_callback;
  base::MockCallback<base::OnceClosure> checkpoint;
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
    EXPECT_CALL(checkpoint, Run());
    EXPECT_CALL(mock_callback, Run(OK));
  }
  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, mock_callback.Get()),
              IsError(ERR_IO_PENDING));

  checkpoint.Run();

  AppendTo(stub.frames_passed(),
           WebSocketFrameHeader::kOpCodeText,
           kFinal | kReserved1,
           std::string("\xf2\x48\xcd\xc9\xc9\x07\x00", 7));
  std::move(stub.callback()).Run(OK);

  ASSERT_EQ(1u, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
  EXPECT_TRUE(frames[0]->header.final);
  EXPECT_FALSE(frames[0]->header.reserved1);
  EXPECT_EQ("Hello", ToString(frames[0]));
}

TEST_F(WebSocketDeflateStreamTest,
       ReadCompressedFrameFragmentImmediatelyButInflaterReturnsPending) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  const std::string data1("\xf2", 1);
  const std::string data2("\x48\xcd\xc9\xc9\x07\x00", 6);
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kReserved1,
           data1);
  ReadFramesStub stub1(OK, &frames_to_output), stub2(ERR_IO_PENDING);
  base::MockCallback<CompletionOnceCallback> mock_callback;
  base::MockCallback<base::OnceClosure> checkpoint;
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub1, &ReadFramesStub::Call))
        .WillOnce(Invoke(&stub2, &ReadFramesStub::Call));
    EXPECT_CALL(checkpoint, Run());
    EXPECT_CALL(mock_callback, Run(OK));
  }
  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, mock_callback.Get()),
              IsError(ERR_IO_PENDING));
  ASSERT_EQ(0u, frames.size());

  AppendTo(stub2.frames_passed(),
           WebSocketFrameHeader::kOpCodeText,
           kFinal,
           data2);

  checkpoint.Run();
  std::move(stub2.callback()).Run(OK);

  ASSERT_EQ(1u, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
  EXPECT_TRUE(frames[0]->header.final);
  EXPECT_FALSE(frames[0]->header.reserved1);
  EXPECT_EQ("Hello", ToString(frames[0]));
}

TEST_F(WebSocketDeflateStreamTest, ReadInvalidCompressedPayload) {
  const std::string data("\xf2\x48\xcdINVALID", 10);
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kFinal | kReserved1,
           data);
  ReadFramesStub stub(OK, &frames_to_output);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
  }
  ASSERT_EQ(ERR_WS_PROTOCOL_ERROR,
            deflate_stream_->ReadFrames(&frames, CompletionOnceCallback()));
  ASSERT_EQ(0u, frames.size());
}

TEST_F(WebSocketDeflateStreamTest, MergeMultipleFramesInReadFrames) {
  const std::string data1("\xf2\x48\xcd", 3);
  const std::string data2("\xc9\xc9\x07\x00", 4);
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kReserved1,
           data1);
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeContinuation,
           kFinal,
           data2);
  ReadFramesStub stub(OK, &frames_to_output);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, CompletionOnceCallback()),
              IsOk());
  ASSERT_EQ(1u, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
  EXPECT_TRUE(frames[0]->header.final);
  EXPECT_FALSE(frames[0]->header.reserved1);
  EXPECT_EQ("Hello", ToString(frames[0]));
}

TEST_F(WebSocketDeflateStreamTest, ReadUncompressedEmptyFrames) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kNoFlag);
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeContinuation,
           kFinal);
  ReadFramesStub stub(OK, &frames_to_output);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, CompletionOnceCallback()),
              IsOk());
  ASSERT_EQ(2u, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
  EXPECT_FALSE(frames[0]->header.final);
  EXPECT_FALSE(frames[0]->header.reserved1);
  EXPECT_EQ("", ToString(frames[0]));
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeContinuation,
            frames[1]->header.opcode);
  EXPECT_TRUE(frames[1]->header.final);
  EXPECT_FALSE(frames[1]->header.reserved1);
  EXPECT_EQ("", ToString(frames[1]));
}

TEST_F(WebSocketDeflateStreamTest, ReadCompressedEmptyFrames) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kReserved1,
           std::string("\x02\x00", 1));
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeContinuation,
           kFinal);
  ReadFramesStub stub(OK, &frames_to_output);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, CompletionOnceCallback()),
              IsOk());
  ASSERT_EQ(1u, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
  EXPECT_TRUE(frames[0]->header.final);
  EXPECT_FALSE(frames[0]->header.reserved1);
  EXPECT_EQ("", ToString(frames[0]));
}

TEST_F(WebSocketDeflateStreamTest,
       ReadCompressedFrameFollowedByEmptyFrame) {
  const std::string data("\xf2\x48\xcd\xc9\xc9\x07\x00", 7);
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kReserved1,
           data);
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeContinuation,
           kFinal);
  ReadFramesStub stub(OK, &frames_to_output);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, CompletionOnceCallback()),
              IsOk());
  ASSERT_EQ(1u, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
  EXPECT_TRUE(frames[0]->header.final);
  EXPECT_FALSE(frames[0]->header.reserved1);
  EXPECT_EQ("Hello", ToString(frames[0]));
}

TEST_F(WebSocketDeflateStreamTest, ReadControlFrameBetweenDataFrames) {
  const std::string data1("\xf2\x48\xcd", 3);
  const std::string data2("\xc9\xc9\x07\x00", 4);
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kReserved1,
           data1);
  AppendTo(&frames_to_output, WebSocketFrameHeader::kOpCodePing, kFinal);
  AppendTo(&frames_to_output, WebSocketFrameHeader::kOpCodeText, kFinal, data2);
  ReadFramesStub stub(OK, &frames_to_output);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, CompletionOnceCallback()),
              IsOk());
  ASSERT_EQ(2u, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodePing, frames[0]->header.opcode);
  EXPECT_TRUE(frames[0]->header.final);
  EXPECT_FALSE(frames[0]->header.reserved1);
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[1]->header.opcode);
  EXPECT_TRUE(frames[1]->header.final);
  EXPECT_FALSE(frames[1]->header.reserved1);
  EXPECT_EQ("Hello", ToString(frames[1]));
}

TEST_F(WebSocketDeflateStreamTest, SplitToMultipleFramesInReadFrames) {
  WebSocketDeflater deflater(WebSocketDeflater::TAKE_OVER_CONTEXT);
  deflater.Initialize(kWindowBits);
  constexpr size_t kSize = kChunkSize * 3;
  const std::string original_data(kSize, 'a');
  deflater.AddBytes(original_data.data(), original_data.size());
  deflater.Finish();

  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeBinary,
           kFinal | kReserved1,
           ToString(deflater.GetOutput(deflater.CurrentOutputSize())));

  ReadFramesStub stub(OK, &frames_to_output);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
  }

  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, CompletionOnceCallback()),
              IsOk());
  ASSERT_EQ(3u, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeBinary, frames[0]->header.opcode);
  EXPECT_FALSE(frames[0]->header.final);
  EXPECT_FALSE(frames[0]->header.reserved1);
  EXPECT_EQ(kChunkSize, static_cast<size_t>(frames[0]->header.payload_length));
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeContinuation,
            frames[1]->header.opcode);
  EXPECT_FALSE(frames[1]->header.final);
  EXPECT_FALSE(frames[1]->header.reserved1);
  EXPECT_EQ(kChunkSize, static_cast<size_t>(frames[1]->header.payload_length));
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeContinuation,
            frames[2]->header.opcode);
  EXPECT_TRUE(frames[2]->header.final);
  EXPECT_FALSE(frames[2]->header.reserved1);
  EXPECT_EQ(kChunkSize, static_cast<size_t>(frames[2]->header.payload_length));
  EXPECT_EQ(original_data,
            ToString(frames[0]) + ToString(frames[1]) + ToString(frames[2]));
}

TEST_F(WebSocketDeflateStreamTest, InflaterInternalDataCanBeEmpty) {
  WebSocketDeflater deflater(WebSocketDeflater::TAKE_OVER_CONTEXT);
  deflater.Initialize(kWindowBits);
  const std::string original_data(kChunkSize, 'a');
  deflater.AddBytes(original_data.data(), original_data.size());
  deflater.Finish();

  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeBinary,
           kReserved1,
           ToString(deflater.GetOutput(deflater.CurrentOutputSize())));
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeBinary,
           kFinal,
           "");

  ReadFramesStub stub(OK, &frames_to_output);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
  }

  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, CompletionOnceCallback()),
              IsOk());
  ASSERT_EQ(2u, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeBinary, frames[0]->header.opcode);
  EXPECT_FALSE(frames[0]->header.final);
  EXPECT_FALSE(frames[0]->header.reserved1);
  EXPECT_EQ(kChunkSize, static_cast<size_t>(frames[0]->header.payload_length));

  EXPECT_EQ(WebSocketFrameHeader::kOpCodeContinuation,
            frames[1]->header.opcode);
  EXPECT_TRUE(frames[1]->header.final);
  EXPECT_FALSE(frames[1]->header.reserved1);
  EXPECT_EQ(0u, static_cast<size_t>(frames[1]->header.payload_length));
  EXPECT_EQ(original_data, ToString(frames[0]) + ToString(frames[1]));
}

TEST_F(WebSocketDeflateStreamTest,
       Reserved1TurnsOnDuringReadingCompressedContinuationFrame) {
  const std::string data1("\xf2\x48\xcd", 3);
  const std::string data2("\xc9\xc9\x07\x00", 4);
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kReserved1,
           data1);
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeContinuation,
           kFinal | kReserved1,
           data2);
  ReadFramesStub stub(OK, &frames_to_output);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
  }
  ASSERT_EQ(ERR_WS_PROTOCOL_ERROR,
            deflate_stream_->ReadFrames(&frames, CompletionOnceCallback()));
}

TEST_F(WebSocketDeflateStreamTest,
       Reserved1TurnsOnDuringReadingUncompressedContinuationFrame) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kNoFlag,
           "hello");
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeContinuation,
           kFinal | kReserved1,
           "world");
  ReadFramesStub stub(OK, &frames_to_output);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
  }
  ASSERT_EQ(ERR_WS_PROTOCOL_ERROR,
            deflate_stream_->ReadFrames(&frames, CompletionOnceCallback()));
}

TEST_F(WebSocketDeflateStreamTest, ReadCompressedMessages) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kFinal | kReserved1,
           std::string(
               "\x4a\xce\xcf\x2d\x28\x4a\x2d\x2e\x4e\x4d\x31\x04\x00", 13));
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kFinal | kReserved1,
           std::string("\x4a\x86\x33\x8d\x00\x00", 6));
  ReadFramesStub stub(OK, &frames_to_output);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, CompletionOnceCallback()),
              IsOk());
  ASSERT_EQ(2u, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
  EXPECT_TRUE(frames[0]->header.final);
  EXPECT_FALSE(frames[0]->header.reserved1);
  EXPECT_EQ("compressed1", ToString(frames[0]));
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[1]->header.opcode);
  EXPECT_TRUE(frames[1]->header.final);
  EXPECT_FALSE(frames[1]->header.reserved1);
  EXPECT_EQ("compressed2", ToString(frames[1]));
}

TEST_F(WebSocketDeflateStreamTest, ReadUncompressedMessages) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kFinal,
           "uncompressed1");
  AppendTo(&frames_to_output,
           WebSocketFrameHeader::kOpCodeText,
           kFinal,
           "uncompressed2");
  ReadFramesStub stub(OK, &frames_to_output);
  std::vector<std::unique_ptr<WebSocketFrame>> frames;

  {
    InSequence s;
    EXPECT_CALL(*mock_stream_, ReadFrames(&frames, _))
        .WillOnce(Invoke(&stub, &ReadFramesStub::Call));
  }
  ASSERT_THAT(deflate_stream_->ReadFrames(&frames, CompletionOnceCallback()),
              IsOk());
  ASSERT_EQ(2u, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
  EXPECT_TRUE(frames[0]->header.final);
  EXPECT_FALSE(frames[0]->header.reserved1);
  EXPECT_EQ("uncompressed1", ToString(frames[0]));
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[1]->header.opcode);
  EXPECT_TRUE(frames[1]->header.final);
  EXPECT_FALSE(frames[1]->header.reserved1);
  EXPECT_EQ("uncompressed2", ToString(frames[1]));
}

TEST_F(WebSocketDeflateStreamTest,
       ReadCompressedMessageThenUncompressedMessage) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames_to_output;
  AppendTo(&frames_to_output,
           WebSock
"""


```
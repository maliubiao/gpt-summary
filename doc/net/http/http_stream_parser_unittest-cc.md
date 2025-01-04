Response:
Let's break down the thought process for analyzing the provided C++ code snippet and fulfilling the request.

**1. Understanding the Core Request:**

The central task is to analyze the `http_stream_parser_unittest.cc` file and describe its functionality, potential connections to JavaScript, logical reasoning with inputs/outputs, common usage errors, debugging context, and finally, a summary of its function for this first part.

**2. Initial Code Scan and Keyword Identification:**

My first step is always to quickly scan the code for recognizable keywords and patterns:

* **`unittest`:** This immediately signals that the file contains unit tests. The core function is *testing*.
* **`net/http/http_stream_parser.h`:**  This confirms the file is testing the `HttpStreamParser` class.
* **`TEST(HttpStreamParser, ...)`:** This is the standard Google Test macro for defining individual test cases.
* **`MockWrite`, `MockRead`, `SequencedSocketData`, `CreateConnectedSocket`:** These indicate the use of mocking for simulating network socket behavior. The tests aren't hitting real network connections.
* **`UploadDataStream`, `ChunkedUploadDataStream`, `ElementsUploadDataStream`:** These classes relate to handling request bodies.
* **`HttpRequestHeaders`, `HttpResponseInfo`:**  These are standard HTTP concepts and data structures.
* **`EXPECT_...`, `ASSERT_...`:** These are Google Test assertion macros, confirming expectations within the tests.
* **`EncodeChunk`:**  This function seems specific to encoding data for chunked transfer encoding.
* **`ShouldMergeRequestHeadersAndBody`:** This function likely determines optimization strategies related to sending headers and body together.
* **`SentBytes`:**  This hints at tests focused on tracking the number of bytes sent.
* **Asynchronous operations (`ASYNC`, `ERR_IO_PENDING`, `base::RunLoop().RunUntilIdle()`):**  Indicates testing of asynchronous behavior.

**3. Deconstructing the Request - Addressing Each Point:**

Now, I systematically address each part of the request:

* **Functionality:** Based on the keywords and test names, the primary function is clearly *testing the `HttpStreamParser` class*. It validates various aspects like sending requests, handling different types of request bodies (with and without errors, synchronous and asynchronous), encoding chunked data, and determining header/body merging.

* **Relationship to JavaScript:** This requires careful consideration. The `HttpStreamParser` is a *low-level C++ component* within Chromium's networking stack. It doesn't directly execute JavaScript. However, *JavaScript running in a browser makes HTTP requests*, and *this C++ code is responsible for the underlying mechanics of sending those requests*. The connection is indirect but crucial. Examples could involve `fetch()` API calls in JavaScript resulting in this code being executed.

* **Logical Reasoning (Hypothetical Input/Output):** I select a simple test case, like `EncodeChunk_ShortPayload`, and imagine the input (the payload string) and the expected output (the chunked encoded string). This demonstrates how the code transforms data. I also consider scenarios like `ShouldMergeRequestHeadersAndBody` with different body types.

* **Common Usage Errors:**  This requires thinking about how developers might misuse the HTTP protocol or the underlying C++ API. For example, providing an incorrectly sized buffer to `EncodeChunk` or forgetting to handle asynchronous operations properly with `UploadDataStream`.

* **User Operation and Debugging:**  This connects the low-level C++ to higher-level browser actions. A user typing a URL, clicking a link, or JavaScript making an API call can all lead to HTTP requests. I then think about debugging steps, such as setting breakpoints in this C++ code or examining network logs in the browser's developer tools.

* **Summarization for Part 1:** The goal is to provide a concise overview of the file's purpose based on the analysis of the first part of the code. It focuses on testing the sending of HTTP requests and handling request bodies.

**4. Structuring the Response:**

I organize the findings into clear sections as requested: Functionality, JavaScript Relationship, Logical Reasoning, Usage Errors, Debugging, and Summary. This makes the information easier to understand.

**5. Refinement and Iteration:**

I mentally review my answers for clarity, accuracy, and completeness. For example, I ensure the JavaScript examples are relevant and not too technical. I double-check the input/output examples for logical consistency.

**Self-Correction/Refinement Example during the thought process:**

Initially, I might just say "it handles HTTP requests."  However, that's too broad. I then refine it to be more specific based on the code: "It tests the sending of HTTP requests, including handling different types of request bodies and the encoding of chunked data."  I also realize the JavaScript connection is indirect, so I emphasize that it's the underlying mechanism rather than direct interaction.

By following these steps, I can systematically analyze the code snippet and generate a comprehensive and accurate response that addresses all aspects of the prompt. The key is to break down the complex task into smaller, manageable parts and to leverage my understanding of software testing, networking concepts, and the relationship between different layers of a software system.
好的，我们来分析一下 `net/http/http_stream_parser_unittest.cc` 文件的功能。

**功能归纳**

这个 C++ 文件是 Chromium 网络栈中 `net/http/http_stream_parser.h` 的单元测试文件。它的主要功能是：

1. **测试 `HttpStreamParser` 类的各种功能。**  `HttpStreamParser` 负责将 HTTP 请求发送到网络，并解析接收到的 HTTP 响应。
2. **模拟网络连接行为。** 它使用 `MockWrite` 和 `MockRead` 来模拟网络 socket 的写入和读取操作，避免了实际的网络请求。
3. **测试发送不同类型的 HTTP 请求。** 包括 GET 和 POST 请求，以及带有不同 `Content-Length` 和 `Transfer-Encoding` 的请求。
4. **测试处理请求体（request body）。**  它测试了 `UploadDataStream` 的各种实现，例如：
    *  内存中的数据 (`UploadBytesElementReader`)
    *  分块传输的数据 (`ChunkedUploadDataStream`)
    *  从文件中读取的数据 (`UploadFileElementReader`)
    *  在初始化或读取时发生错误的情况。
5. **测试同步和异步操作。**  它涵盖了同步和异步的网络操作，以及 `UploadDataStream` 的初始化和读取。
6. **测试分块编码（chunked encoding）。**  包括编码分块数据 (`EncodeChunk`) 的正确性。
7. **测试合并请求头和请求体的策略 (`ShouldMergeRequestHeadersAndBody`)。**  验证在满足特定条件时，是否应该将请求头和较小的请求体合并到一个写操作中。
8. **测试 `sent_bytes()` 方法。** 验证 `HttpStreamParser` 正确跟踪已发送的字节数，包括发送请求头和请求体。
9. **测试在发送请求过程中发生错误的情况。**  模拟 socket 写入错误和 `UploadDataStream` 读取错误。
10. **作为 `HttpStreamParser` 功能正确性的验证工具。**  通过各种测试用例确保 `HttpStreamParser` 在不同场景下都能正常工作。

**与 JavaScript 功能的关系**

虽然这个 C++ 文件本身不包含任何 JavaScript 代码，但它所测试的 `HttpStreamParser` 类是浏览器网络功能的核心组件，与 JavaScript 发起的网络请求密切相关。

**举例说明：**

当 JavaScript 代码在浏览器中执行 `fetch()` API 或 `XMLHttpRequest` 对象发起一个 HTTP 请求时，底层的网络操作最终会由 Chromium 的网络栈来处理。`HttpStreamParser` 就参与了这个过程：

1. **JavaScript 发起请求：**  JavaScript 代码调用 `fetch()` 并指定请求方法（如 "POST"）、URL、请求头和请求体（如果需要）。
2. **传递到 C++ 层：** 浏览器内核会将这些信息传递到 C++ 网络栈。
3. **`HttpStreamParser` 处理：**  `HttpStreamParser` 接收到请求信息，负责格式化 HTTP 请求报文（包括请求行、请求头和请求体），并将其写入底层的 socket 进行发送。
4. **单元测试验证：**  `http_stream_parser_unittest.cc` 中的测试用例就像是针对这个过程的“压力测试”。例如，`TEST(HttpStreamParser, SentBytesPost)` 模拟了一个 JavaScript 发起带有请求体的 POST 请求的场景，验证 `HttpStreamParser` 是否正确发送了请求头和请求体，并计算了发送的字节数。

**用户操作如何一步步到达这里 (作为调试线索)**

当开发者在调试与网络请求相关的问题时，可能会需要查看 `HttpStreamParser` 的行为。以下是用户操作如何一步步“到达”这里，作为调试线索：

1. **用户在浏览器中执行某些操作，触发网络请求：**
   *  用户在地址栏输入 URL 并回车。
   *  用户点击网页上的链接。
   *  网页上的 JavaScript 代码使用 `fetch()` 或 `XMLHttpRequest` 发起 API 请求。
2. **请求进入 Chromium 网络栈：**  浏览器内核将请求信息传递给网络栈。
3. **`HttpStreamParser` 被创建和使用：**  根据请求的协议和连接状态，可能会创建一个 `HttpStreamParser` 实例来处理该请求的发送和响应的接收。
4. **调试场景：** 开发者可能在以下情况下需要关注 `HttpStreamParser`：
   * **请求发送失败或发送不完整：**  如果开发者发现某些请求没有正确发送，或者发送的数据不完整，他们可能会怀疑 `HttpStreamParser` 在构建请求报文或写入 socket 时出现了问题。
   * **请求头或请求体格式错误：**  如果服务器返回错误，指出请求头或请求体格式不正确，开发者可能会检查 `HttpStreamParser` 是否正确格式化了这些部分。
   * **分块传输问题：**  如果请求使用了分块传输编码，开发者可能会检查 `HttpStreamParser` 是否正确编码了数据块。
   * **性能问题：**  在某些情况下，开发者可能会关注请求发送的效率，例如是否合并了请求头和较小的请求体。
5. **调试步骤：**
   * **设置断点：** 开发者可以在 `HttpStreamParser` 相关的代码中设置断点，例如 `SendRequest` 方法或写入 socket 的地方。
   * **查看网络日志：**  Chromium 的 `net-internals` 工具 (chrome://net-internals/#events) 提供了详细的网络事件日志，可以查看请求的发送过程，包括 `HttpStreamParser` 的操作。
   * **分析单元测试：**  `http_stream_parser_unittest.cc` 中的测试用例可以帮助开发者理解 `HttpStreamParser` 在各种情况下的预期行为，从而辅助他们定位问题。如果某个测试用例失败，可能意味着 `HttpStreamParser` 的某个功能存在 bug。

**逻辑推理 (假设输入与输出)**

让我们以 `TEST(HttpStreamParser, EncodeChunk_ShortPayload)` 为例进行逻辑推理：

**假设输入：**

* `kPayload`: 字符串 "foo\x00\x11\x22" (长度为 6)
* `output`: 一个大小为 `kOutputSize` 的字符数组

**预期输出：**

* `num_bytes_written`:  11 (分块编码后的字符串长度)
* `output` 的前 11 个字节包含字符串 "6\r\nfoo\x00\x11\x22\r\n"

**逻辑：**

`HttpStreamParser::EncodeChunk` 函数接收一个 payload 和一个输出 buffer。对于短 payload，它应该执行以下操作：

1. 计算 payload 的十六进制长度（这里是 6，十六进制也是 6）。
2. 将长度转换为字符串并加上 "\r\n" 前缀（"6\r\n"）。
3. 将 payload 复制到输出 buffer 中。
4. 加上 "\r\n" 后缀。
5. 返回写入的字节数。

**常见的使用错误举例**

以下是一些用户或编程中可能遇到的与 `HttpStreamParser` 相关的常见错误（虽然用户不会直接操作 `HttpStreamParser`，但理解其背后的逻辑有助于避免错误）：

1. **`UploadDataStream` 的使用不当：**
   * **忘记初始化 `UploadDataStream`：**  在调用 `SendRequest` 之前，必须正确初始化 `UploadDataStream`。例如，对于 `ElementsUploadDataStream`，需要添加 `UploadElementReader`。
   * **在异步初始化完成前发送请求：**  如果 `UploadDataStream` 的初始化是异步的，必须等待初始化完成才能发送请求。测试用例 `TEST(HttpStreamParser, InitAsynchronousUploadDataStream)` 就演示了这种情况。
   * **分块发送数据时，忘记发送最后一个空 chunk：**  对于 `Transfer-Encoding: chunked` 的请求，必须以一个大小为 0 的 chunk 结束。
   * **在 `UploadDataStream` 读取数据时发生错误，没有正确处理：**  测试用例 `TEST(HttpStreamParser, DataReadErrorSynchronous)` 和 `TEST(HttpStreamParser, DataReadErrorAsynchronous)` 模拟了这种情况。

2. **请求头设置错误：**
   * **`Content-Length` 与实际请求体大小不符：**  如果指定了 `Content-Length`，其值必须与实际发送的请求体字节数一致。
   * **同时设置 `Content-Length` 和 `Transfer-Encoding: chunked`：**  这两种方式是互斥的。

3. **缓冲区大小不足：**
   * **在使用 `EncodeChunk` 时，提供的输出缓冲区太小，无法容纳编码后的 chunk 数据。** 测试用例 `TEST(HttpStreamParser, EncodeChunk_TooLargePayload)` 演示了这种情况。

**总结 (针对第 1 部分)**

总而言之，`net/http/http_stream_parser_unittest.cc` 文件的主要功能是**全面测试 `HttpStreamParser` 类的各种请求发送功能，包括处理不同类型的请求方法、请求头、请求体，以及模拟各种同步和异步的网络操作和错误场景。** 它是保证 Chromium 网络栈 HTTP 请求发送功能正确性和健壮性的重要组成部分。虽然 JavaScript 开发者不会直接接触到这个 C++ 文件，但它所测试的功能是支撑 JavaScript 发起网络请求的基础。

Prompt: 
```
这是目录为net/http/http_stream_parser_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/http/http_stream_parser.h"

#include <stdint.h>

#include <algorithm>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/containers/span.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/functional/bind.h"
#include "base/memory/ref_counted.h"
#include "base/numerics/safe_conversions.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/task_environment.h"
#include "net/base/chunked_upload_data_stream.h"
#include "net/base/elements_upload_data_stream.h"
#include "net/base/io_buffer.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/base/upload_data_stream.h"
#include "net/base/upload_file_element_reader.h"
#include "net/http/http_connection_info.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/stream_socket.h"
#include "net/test/gtest_util.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

const size_t kOutputSize = 1024;  // Just large enough for this test.
// The number of bytes that can fit in a buffer of kOutputSize.
const size_t kMaxPayloadSize =
    kOutputSize - HttpStreamParser::kChunkHeaderFooterSize;

// Helper method to create a connected ClientSocketHandle using |data|.
// Modifies |data|.
std::unique_ptr<StreamSocket> CreateConnectedSocket(SequencedSocketData* data) {
  data->set_connect_data(MockConnect(SYNCHRONOUS, OK));

  auto socket =
      std::make_unique<MockTCPClientSocket>(AddressList(), nullptr, data);

  TestCompletionCallback callback;
  EXPECT_THAT(socket->Connect(callback.callback()), IsOk());

  return socket;
}

class ReadErrorUploadDataStream : public UploadDataStream {
 public:
  enum class FailureMode { SYNC, ASYNC };

  explicit ReadErrorUploadDataStream(FailureMode mode)
      : UploadDataStream(true, 0), async_(mode) {}

  ReadErrorUploadDataStream(const ReadErrorUploadDataStream&) = delete;
  ReadErrorUploadDataStream& operator=(const ReadErrorUploadDataStream&) =
      delete;

 private:
  void CompleteRead() { UploadDataStream::OnReadCompleted(ERR_FAILED); }

  // UploadDataStream implementation:
  int InitInternal(const NetLogWithSource& net_log) override { return OK; }

  int ReadInternal(IOBuffer* buf, int buf_len) override {
    if (async_ == FailureMode::ASYNC) {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(&ReadErrorUploadDataStream::CompleteRead,
                                    weak_factory_.GetWeakPtr()));
      return ERR_IO_PENDING;
    }
    return ERR_FAILED;
  }

  void ResetInternal() override {}

  const FailureMode async_;

  base::WeakPtrFactory<ReadErrorUploadDataStream> weak_factory_{this};
};

TEST(HttpStreamParser, DataReadErrorSynchronous) {
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, 0, "POST / HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Content-Length: 12\r\n\r\n"),
  };

  SequencedSocketData data(base::span<MockRead>(), writes);
  std::unique_ptr<StreamSocket> stream_socket = CreateConnectedSocket(&data);

  ReadErrorUploadDataStream upload_data_stream(
      ReadErrorUploadDataStream::FailureMode::SYNC);

  // Test upload progress before init.
  UploadProgress progress = upload_data_stream.GetUploadProgress();
  EXPECT_EQ(0u, progress.size());
  EXPECT_EQ(0u, progress.position());

  ASSERT_THAT(upload_data_stream.Init(TestCompletionCallback().callback(),
                                      NetLogWithSource()),
              IsOk());

  // Test upload progress after init.
  progress = upload_data_stream.GetUploadProgress();
  EXPECT_EQ(0u, progress.size());
  EXPECT_EQ(0u, progress.position());

  scoped_refptr<GrowableIOBuffer> read_buffer =
      base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), false /* is_reused */,
                          GURL("http://localhost"), "POST", &upload_data_stream,
                          read_buffer.get(), NetLogWithSource());

  HttpRequestHeaders headers;
  headers.SetHeader("Content-Length", "12");

  HttpResponseInfo response;
  TestCompletionCallback callback;
  int result = parser.SendRequest("POST / HTTP/1.1\r\n", headers,
                                  TRAFFIC_ANNOTATION_FOR_TESTS, &response,
                                  callback.callback());
  EXPECT_THAT(callback.GetResult(result), IsError(ERR_FAILED));

  progress = upload_data_stream.GetUploadProgress();
  EXPECT_EQ(0u, progress.size());
  EXPECT_EQ(0u, progress.position());

  EXPECT_EQ(CountWriteBytes(writes), parser.sent_bytes());
}

TEST(HttpStreamParser, DataReadErrorAsynchronous) {
  base::test::TaskEnvironment task_environment;

  MockWrite writes[] = {
      MockWrite(ASYNC, 0, "POST / HTTP/1.1\r\n"),
      MockWrite(ASYNC, 1, "Content-Length: 12\r\n\r\n"),
  };

  SequencedSocketData data(base::span<MockRead>(), writes);
  std::unique_ptr<StreamSocket> stream_socket = CreateConnectedSocket(&data);

  ReadErrorUploadDataStream upload_data_stream(
      ReadErrorUploadDataStream::FailureMode::ASYNC);
  ASSERT_THAT(upload_data_stream.Init(TestCompletionCallback().callback(),
                                      NetLogWithSource()),
              IsOk());

  HttpRequestInfo request;

  scoped_refptr<GrowableIOBuffer> read_buffer =
      base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), false /* is_reused */,
                          GURL("http://localhost"), "POST", &upload_data_stream,
                          read_buffer.get(), NetLogWithSource());

  HttpRequestHeaders headers;
  headers.SetHeader("Content-Length", "12");

  HttpResponseInfo response;
  TestCompletionCallback callback;
  int result = parser.SendRequest("POST / HTTP/1.1\r\n", headers,
                                  TRAFFIC_ANNOTATION_FOR_TESTS, &response,
                                  callback.callback());
  EXPECT_THAT(result, IsError(ERR_IO_PENDING));

  UploadProgress progress = upload_data_stream.GetUploadProgress();
  EXPECT_EQ(0u, progress.size());
  EXPECT_EQ(0u, progress.position());

  EXPECT_THAT(callback.GetResult(result), IsError(ERR_FAILED));

  EXPECT_EQ(CountWriteBytes(writes), parser.sent_bytes());
}

class InitAsyncUploadDataStream : public ChunkedUploadDataStream {
 public:
  explicit InitAsyncUploadDataStream(int64_t identifier)
      : ChunkedUploadDataStream(identifier) {}

  InitAsyncUploadDataStream(const InitAsyncUploadDataStream&) = delete;
  InitAsyncUploadDataStream& operator=(const InitAsyncUploadDataStream&) =
      delete;

 private:
  void CompleteInit() { UploadDataStream::OnInitCompleted(OK); }

  int InitInternal(const NetLogWithSource& net_log) override {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&InitAsyncUploadDataStream::CompleteInit,
                                  weak_factory_.GetWeakPtr()));
    return ERR_IO_PENDING;
  }

  base::WeakPtrFactory<InitAsyncUploadDataStream> weak_factory_{this};
};

TEST(HttpStreamParser, InitAsynchronousUploadDataStream) {
  base::test::TaskEnvironment task_environment;

  InitAsyncUploadDataStream upload_data_stream(0);

  TestCompletionCallback callback;
  int result = upload_data_stream.Init(callback.callback(), NetLogWithSource());
  ASSERT_THAT(result, IsError(ERR_IO_PENDING));

  // Should be empty progress while initialization is in progress.
  UploadProgress progress = upload_data_stream.GetUploadProgress();
  EXPECT_EQ(0u, progress.size());
  EXPECT_EQ(0u, progress.position());
  EXPECT_THAT(callback.GetResult(result), IsOk());

  // Initialization complete.
  progress = upload_data_stream.GetUploadProgress();
  EXPECT_EQ(0u, progress.size());
  EXPECT_EQ(0u, progress.position());

  static const char kChunk[] = "Chunk 1";
  MockWrite writes[] = {
      MockWrite(ASYNC, 0, "POST / HTTP/1.1\r\n"),
      MockWrite(ASYNC, 1, "Transfer-Encoding: chunked\r\n\r\n"),
      MockWrite(ASYNC, 2, "7\r\nChunk 1\r\n"),
  };

  SequencedSocketData data(base::span<MockRead>(), writes);
  std::unique_ptr<StreamSocket> stream_socket = CreateConnectedSocket(&data);

  scoped_refptr<GrowableIOBuffer> read_buffer =
      base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), false /* is_reused */,
                          GURL("http://localhost"), "POST", &upload_data_stream,
                          read_buffer.get(), NetLogWithSource());

  HttpRequestHeaders headers;
  headers.SetHeader("Transfer-Encoding", "chunked");

  HttpResponseInfo response;
  TestCompletionCallback callback1;
  int result1 = parser.SendRequest("POST / HTTP/1.1\r\n", headers,
                                   TRAFFIC_ANNOTATION_FOR_TESTS, &response,
                                   callback1.callback());
  EXPECT_EQ(ERR_IO_PENDING, result1);
  base::RunLoop().RunUntilIdle();
  upload_data_stream.AppendData(base::byte_span_from_cstring(kChunk), true);

  // Check progress after read completes.
  progress = upload_data_stream.GetUploadProgress();
  EXPECT_EQ(0u, progress.size());
  EXPECT_EQ(7u, progress.position());

  // Check progress after reset.
  upload_data_stream.Reset();
  progress = upload_data_stream.GetUploadProgress();
  EXPECT_EQ(0u, progress.size());
  EXPECT_EQ(0u, progress.position());
}

// The empty payload is how the last chunk is encoded.
TEST(HttpStreamParser, EncodeChunk_EmptyPayload) {
  char output[kOutputSize];

  const std::string_view kPayload = "";
  const std::string_view kExpected = "0\r\n\r\n";
  const int num_bytes_written = HttpStreamParser::EncodeChunk(
      kPayload, base::as_writable_byte_span(output));
  ASSERT_EQ(kExpected.size(), static_cast<size_t>(num_bytes_written));
  EXPECT_EQ(kExpected, std::string_view(output, num_bytes_written));
}

TEST(HttpStreamParser, EncodeChunk_ShortPayload) {
  char output[kOutputSize];

  const std::string kPayload("foo\x00\x11\x22", 6);
  // 11 = payload size + sizeof("6") + CRLF x 2.
  const std::string kExpected("6\r\nfoo\x00\x11\x22\r\n", 11);
  const int num_bytes_written = HttpStreamParser::EncodeChunk(
      kPayload, base::as_writable_byte_span(output));
  ASSERT_EQ(kExpected.size(), static_cast<size_t>(num_bytes_written));
  EXPECT_EQ(kExpected, std::string_view(output, num_bytes_written));
}

TEST(HttpStreamParser, EncodeChunk_LargePayload) {
  char output[kOutputSize];

  const std::string kPayload(1000, '\xff');  // '\xff' x 1000.
  // 3E8 = 1000 in hex.
  const std::string kExpected = "3E8\r\n" + kPayload + "\r\n";
  const int num_bytes_written = HttpStreamParser::EncodeChunk(
      kPayload, base::as_writable_byte_span(output));
  ASSERT_EQ(kExpected.size(), static_cast<size_t>(num_bytes_written));
  EXPECT_EQ(kExpected, std::string_view(output, num_bytes_written));
}

TEST(HttpStreamParser, EncodeChunk_FullPayload) {
  char output[kOutputSize];

  const std::string kPayload(kMaxPayloadSize, '\xff');
  // 3F4 = 1012 in hex.
  const std::string kExpected = "3F4\r\n" + kPayload + "\r\n";
  const int num_bytes_written = HttpStreamParser::EncodeChunk(
      kPayload, base::as_writable_byte_span(output));
  ASSERT_EQ(kExpected.size(), static_cast<size_t>(num_bytes_written));
  EXPECT_EQ(kExpected, std::string_view(output, num_bytes_written));
}

TEST(HttpStreamParser, EncodeChunk_TooLargePayload) {
  char output[kOutputSize];

  // The payload is one byte larger the output buffer size.
  const std::string kPayload(kMaxPayloadSize + 1, '\xff');
  const int num_bytes_written = HttpStreamParser::EncodeChunk(
      kPayload, base::as_writable_byte_span(output));
  ASSERT_THAT(num_bytes_written, IsError(ERR_INVALID_ARGUMENT));
}

TEST(HttpStreamParser, ShouldMergeRequestHeadersAndBody_NoBody) {
  // Shouldn't be merged if upload data is non-existent.
  ASSERT_FALSE(HttpStreamParser::ShouldMergeRequestHeadersAndBody("some header",
                                                                  nullptr));
}

TEST(HttpStreamParser, ShouldMergeRequestHeadersAndBody_EmptyBody) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  std::unique_ptr<UploadDataStream> body(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers),
                                                 0));
  ASSERT_THAT(body->Init(CompletionOnceCallback(), NetLogWithSource()), IsOk());
  // Shouldn't be merged if upload data is empty.
  ASSERT_FALSE(HttpStreamParser::ShouldMergeRequestHeadersAndBody(
      "some header", body.get()));
}

TEST(HttpStreamParser, ShouldMergeRequestHeadersAndBody_ChunkedBody) {
  const std::string payload = "123";
  auto body = std::make_unique<ChunkedUploadDataStream>(0);
  body->AppendData(base::as_byte_span(payload), true);
  ASSERT_THAT(
      body->Init(TestCompletionCallback().callback(), NetLogWithSource()),
      IsOk());
  // Shouldn't be merged if upload data carries chunked data.
  ASSERT_FALSE(HttpStreamParser::ShouldMergeRequestHeadersAndBody(
      "some header", body.get()));
}

TEST(HttpStreamParser, ShouldMergeRequestHeadersAndBody_FileBody) {
  base::test::TaskEnvironment task_environment(
      base::test::TaskEnvironment::MainThreadType::IO);

  // Create an empty temporary file.
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath temp_file_path;
  ASSERT_TRUE(
      base::CreateTemporaryFileInDir(temp_dir.GetPath(), &temp_file_path));

  {
    std::vector<std::unique_ptr<UploadElementReader>> element_readers;

    element_readers.push_back(std::make_unique<UploadFileElementReader>(
        base::SingleThreadTaskRunner::GetCurrentDefault().get(), temp_file_path,
        0, 0, base::Time()));

    std::unique_ptr<UploadDataStream> body(
        std::make_unique<ElementsUploadDataStream>(std::move(element_readers),
                                                   0));
    TestCompletionCallback callback;
    ASSERT_THAT(body->Init(callback.callback(), NetLogWithSource()),
                IsError(ERR_IO_PENDING));
    ASSERT_THAT(callback.WaitForResult(), IsOk());
    // Shouldn't be merged if upload data carries a file, as it's not in-memory.
    ASSERT_FALSE(HttpStreamParser::ShouldMergeRequestHeadersAndBody(
        "some header", body.get()));
  }

  // UploadFileElementReaders may post clean-up tasks on destruction.
  base::RunLoop().RunUntilIdle();
}

TEST(HttpStreamParser, ShouldMergeRequestHeadersAndBody_SmallBodyInMemory) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  const std::string payload = "123";
  element_readers.push_back(
      std::make_unique<UploadBytesElementReader>(base::as_byte_span(payload)));

  std::unique_ptr<UploadDataStream> body(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers),
                                                 0));
  ASSERT_THAT(body->Init(CompletionOnceCallback(), NetLogWithSource()), IsOk());
  // Yes, should be merged if the in-memory body is small here.
  ASSERT_TRUE(HttpStreamParser::ShouldMergeRequestHeadersAndBody(
      "some header", body.get()));
}

TEST(HttpStreamParser, ShouldMergeRequestHeadersAndBody_LargeBodyInMemory) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  const std::string payload(10000, 'a');  // 'a' x 10000.
  element_readers.push_back(
      std::make_unique<UploadBytesElementReader>(base::as_byte_span(payload)));

  std::unique_ptr<UploadDataStream> body(
      std::make_unique<ElementsUploadDataStream>(std::move(element_readers),
                                                 0));
  ASSERT_THAT(body->Init(CompletionOnceCallback(), NetLogWithSource()), IsOk());
  // Shouldn't be merged if the in-memory body is large here.
  ASSERT_FALSE(HttpStreamParser::ShouldMergeRequestHeadersAndBody(
      "some header", body.get()));
}

TEST(HttpStreamParser, SentBytesNoHeaders) {
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n\r\n"),
  };

  SequencedSocketData data(base::span<MockRead>(), writes);
  std::unique_ptr<StreamSocket> stream_socket = CreateConnectedSocket(&data);

  scoped_refptr<GrowableIOBuffer> read_buffer =
      base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), false /* is_reused */,
                          GURL("http://localhost"), "GET",
                          /*upload_data_stream=*/nullptr, read_buffer.get(),
                          NetLogWithSource());

  HttpResponseInfo response;
  TestCompletionCallback callback;
  EXPECT_EQ(OK, parser.SendRequest("GET / HTTP/1.1\r\n", HttpRequestHeaders(),
                                   TRAFFIC_ANNOTATION_FOR_TESTS, &response,
                                   callback.callback()));

  EXPECT_EQ(CountWriteBytes(writes), parser.sent_bytes());
}

TEST(HttpStreamParser, SentBytesWithHeaders) {
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, 0,
                "GET / HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Connection: Keep-Alive\r\n\r\n"),
  };

  SequencedSocketData data(base::span<MockRead>(), writes);
  std::unique_ptr<StreamSocket> stream_socket = CreateConnectedSocket(&data);

  scoped_refptr<GrowableIOBuffer> read_buffer =
      base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), false /* is_reused */,
                          GURL("http://localhost"), "GET",
                          /*upload_data_stream=*/nullptr, read_buffer.get(),
                          NetLogWithSource());

  HttpRequestHeaders headers;
  headers.SetHeader("Host", "localhost");
  headers.SetHeader("Connection", "Keep-Alive");

  HttpResponseInfo response;
  TestCompletionCallback callback;
  EXPECT_EQ(OK, parser.SendRequest("GET / HTTP/1.1\r\n", headers,
                                   TRAFFIC_ANNOTATION_FOR_TESTS, &response,
                                   callback.callback()));

  EXPECT_EQ(CountWriteBytes(writes), parser.sent_bytes());
}

TEST(HttpStreamParser, SentBytesWithHeadersMultiWrite) {
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Host: localhost\r\n"),
      MockWrite(SYNCHRONOUS, 2, "Connection: Keep-Alive\r\n\r\n"),
  };

  SequencedSocketData data(base::span<MockRead>(), writes);
  std::unique_ptr<StreamSocket> stream_socket = CreateConnectedSocket(&data);

  scoped_refptr<GrowableIOBuffer> read_buffer =
      base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), false /* is_reused */,
                          GURL("http://localhost"), "GET",
                          /*upload_data_stream=*/nullptr, read_buffer.get(),
                          NetLogWithSource());

  HttpRequestHeaders headers;
  headers.SetHeader("Host", "localhost");
  headers.SetHeader("Connection", "Keep-Alive");

  HttpResponseInfo response;
  TestCompletionCallback callback;

  EXPECT_EQ(OK, parser.SendRequest("GET / HTTP/1.1\r\n", headers,
                                   TRAFFIC_ANNOTATION_FOR_TESTS, &response,
                                   callback.callback()));

  EXPECT_EQ(CountWriteBytes(writes), parser.sent_bytes());
}

TEST(HttpStreamParser, SentBytesWithErrorWritingHeaders) {
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Host: localhost\r\n"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET, 2),
  };

  SequencedSocketData data(base::span<MockRead>(), writes);
  std::unique_ptr<StreamSocket> stream_socket = CreateConnectedSocket(&data);

  scoped_refptr<GrowableIOBuffer> read_buffer =
      base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), false /* is_reused */,
                          GURL("http://localhost"), "GET",
                          /*upload_data_stream=*/nullptr, read_buffer.get(),
                          NetLogWithSource());

  HttpRequestHeaders headers;
  headers.SetHeader("Host", "localhost");
  headers.SetHeader("Connection", "Keep-Alive");

  HttpResponseInfo response;
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_CONNECTION_RESET,
            parser.SendRequest("GET / HTTP/1.1\r\n", headers,
                               TRAFFIC_ANNOTATION_FOR_TESTS, &response,
                               callback.callback()));

  EXPECT_EQ(CountWriteBytes(writes), parser.sent_bytes());
}

TEST(HttpStreamParser, SentBytesPost) {
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, 0, "POST / HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Content-Length: 12\r\n\r\n"),
      MockWrite(SYNCHRONOUS, 2, "hello world!"),
  };

  SequencedSocketData data(base::span<MockRead>(), writes);
  std::unique_ptr<StreamSocket> stream_socket = CreateConnectedSocket(&data);

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello world!")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);
  ASSERT_THAT(upload_data_stream.Init(TestCompletionCallback().callback(),
                                      NetLogWithSource()),
              IsOk());

  scoped_refptr<GrowableIOBuffer> read_buffer =
      base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), false /* is_reused */,
                          GURL("http://localhost"), "POST", &upload_data_stream,
                          read_buffer.get(), NetLogWithSource());

  HttpRequestHeaders headers;
  headers.SetHeader("Content-Length", "12");

  HttpResponseInfo response;
  TestCompletionCallback callback;
  EXPECT_EQ(OK, parser.SendRequest("POST / HTTP/1.1\r\n", headers,
                                   TRAFFIC_ANNOTATION_FOR_TESTS, &response,
                                   callback.callback()));

  EXPECT_EQ(CountWriteBytes(writes), parser.sent_bytes());

  UploadProgress progress = upload_data_stream.GetUploadProgress();
  EXPECT_EQ(12u, progress.size());
  EXPECT_EQ(12u, progress.position());
}

TEST(HttpStreamParser, SentBytesChunkedPostError) {
  base::test::TaskEnvironment task_environment;

  static const char kChunk[] = "Chunk 1";

  MockWrite writes[] = {
      MockWrite(ASYNC, 0, "POST / HTTP/1.1\r\n"),
      MockWrite(ASYNC, 1, "Transfer-Encoding: chunked\r\n\r\n"),
      MockWrite(ASYNC, 2, "7\r\nChunk 1\r\n"),
      MockWrite(SYNCHRONOUS, ERR_FAILED, 3),
  };

  SequencedSocketData data(base::span<MockRead>(), writes);
  std::unique_ptr<StreamSocket> stream_socket = CreateConnectedSocket(&data);

  ChunkedUploadDataStream upload_data_stream(0);
  ASSERT_THAT(upload_data_stream.Init(TestCompletionCallback().callback(),
                                      NetLogWithSource()),
              IsOk());

  scoped_refptr<GrowableIOBuffer> read_buffer =
      base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), false /* is_reused */,
                          GURL("http://localhost"), "POST", &upload_data_stream,
                          read_buffer.get(), NetLogWithSource());

  HttpRequestHeaders headers;
  headers.SetHeader("Transfer-Encoding", "chunked");

  HttpResponseInfo response;
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING, parser.SendRequest("POST / HTTP/1.1\r\n", headers,
                                               TRAFFIC_ANNOTATION_FOR_TESTS,
                                               &response, callback.callback()));

  base::RunLoop().RunUntilIdle();
  upload_data_stream.AppendData(base::byte_span_from_cstring(kChunk), false);

  base::RunLoop().RunUntilIdle();
  // This write should fail.
  upload_data_stream.AppendData(base::byte_span_from_cstring(kChunk), false);
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_FAILED));

  EXPECT_EQ(CountWriteBytes(writes), parser.sent_bytes());

  UploadProgress progress = upload_data_stream.GetUploadProgress();
  EXPECT_EQ(0u, progress.size());
  EXPECT_EQ(14u, progress.position());
}

// Test to ensure the HttpStreamParser state machine does not get confused
// when sending a request with a chunked body with only one chunk that becomes
// available asynchronously.
TEST(HttpStreamParser, AsyncSingleChunkAndAsyncSocket) {
  base::test::TaskEnvironment task_environment;

  static const char kChunk[] = "Chunk";

  MockWrite writes[] = {
      MockWrite(ASYNC, 0,
                "GET /one.html HTTP/1.1\r\n"
                "Transfer-Encoding: chunked\r\n\r\n"),
      MockWrite(ASYNC, 1, "5\r\nChunk\r\n"),
      MockWrite(ASYNC, 2, "0\r\n\r\n"),
  };

  // The size of the response body, as reflected in the Content-Length of the
  // MockRead below.
  static const int kBodySize = 8;

  MockRead reads[] = {
      MockRead(ASYNC, 3, "HTTP/1.1 200 OK\r\n"),
      MockRead(ASYNC, 4, "Content-Length: 8\r\n\r\n"),
      MockRead(ASYNC, 5, "one.html"),
      MockRead(SYNCHRONOUS, 0, 6),  // EOF
  };

  ChunkedUploadDataStream upload_stream(0);
  ASSERT_THAT(upload_stream.Init(TestCompletionCallback().callback(),
                                 NetLogWithSource()),
              IsOk());

  SequencedSocketData data(reads, writes);
  std::unique_ptr<StreamSocket> stream_socket = CreateConnectedSocket(&data);

  scoped_refptr<GrowableIOBuffer> read_buffer =
      base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), false /* is_reused */,
                          GURL("http://localhost"), "POST", &upload_stream,
                          read_buffer.get(), NetLogWithSource());

  HttpRequestHeaders request_headers;
  request_headers.SetHeader("Transfer-Encoding", "chunked");

  HttpResponseInfo response_info;
  TestCompletionCallback callback;
  // This will attempt to Write() the initial request and headers, which will
  // complete asynchronously.
  ASSERT_EQ(ERR_IO_PENDING,
            parser.SendRequest("GET /one.html HTTP/1.1\r\n", request_headers,
                               TRAFFIC_ANNOTATION_FOR_TESTS, &response_info,
                               callback.callback()));

  // Complete the initial request write.  Callback should not have been invoked.
  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(callback.have_result());

  // Now append the only chunk and wait for the callback.
  upload_stream.AppendData(base::byte_span_from_cstring(kChunk), true);
  ASSERT_THAT(callback.WaitForResult(), IsOk());

  // Attempt to read the response status and the response headers.
  ASSERT_THAT(parser.ReadResponseHeaders(callback.callback()),
              IsError(ERR_IO_PENDING));
  ASSERT_THAT(callback.WaitForResult(), IsOk());

  // Finally, attempt to read the response body.
  auto body_buffer = base::MakeRefCounted<IOBufferWithSize>(kBodySize);
  ASSERT_EQ(ERR_IO_PENDING,
            parser.ReadResponseBody(body_buffer.get(), kBodySize,
                                    callback.callback()));
  ASSERT_EQ(kBodySize, callback.WaitForResult());

  EXPECT_EQ(CountWriteBytes(writes), parser.sent_bytes());
  EXPECT_EQ(CountReadBytes(reads), parser.received_bytes());
}

// Test to ensure the HttpStreamParser state machine does not get confused
// when sending a request with a chunked body with only one chunk that is
// available synchronously.
TEST(HttpStreamParser, SyncSingleChunkAndAsyncSocket) {
  base::test::TaskEnvironment task_environment;

  static const char kChunk[] = "Chunk";

  MockWrite writes[] = {
      MockWrite(ASYNC, 0,
                "GET /one.html HTTP/1.1\r\n"
                "Transfer-Encoding: chunked\r\n\r\n"),
      MockWrite(ASYNC, 1, "5\r\nChunk\r\n"),
      MockWrite(ASYNC, 2, "0\r\n\r\n"),
  };

  // The size of the response body, as reflected in the Content-Length of the
  // MockRead below.
  static const int kBodySize = 8;

  MockRead reads[] = {
      MockRead(ASYNC, 3, "HTTP/1.1 200 OK\r\n"),
      MockRead(ASYNC, 4, "Content-Length: 8\r\n\r\n"),
      MockRead(ASYNC, 5, "one.html"),
      MockRead(SYNCHRONOUS, 0, 6),  // EOF
  };

  ChunkedUploadDataStream upload_stream(0);
  ASSERT_THAT(upload_stream.Init(TestCompletionCallback().callback(),
                                 NetLogWithSource()),
              IsOk());
  // Append the only chunk.
  upload_stream.AppendData(base::byte_span_from_cstring(kChunk), true);

  SequencedSocketData data(reads, writes);
  std::unique_ptr<StreamSocket> stream_socket = CreateConnectedSocket(&data);

  scoped_refptr<GrowableIOBuffer> read_buffer =
      base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), false /* is_reused */,
                          GURL("http://localhost"), "GET", &upload_stream,
                          read_buffer.get(), NetLogWithSource());

  HttpRequestHeaders request_headers;
  request_headers.SetHeader("Transfer-Encoding", "chunked");

  HttpResponseInfo response_info;
  TestCompletionCallback callback;
  // This will attempt to Write() the initial request and headers, which will
  // complete asynchronously.
  ASSERT_EQ(ERR_IO_PENDING,
            parser.SendRequest("GET /one.html HTTP/1.1\r\n", request_headers,
                               TRAFFIC_ANNOTATION_FOR_TESTS, &response_info,
                               callback.callback()));
  ASSERT_THAT(callback.WaitForResult(), IsOk());

  // Attempt to read the response status and the response headers.
  ASSERT_THAT(parser.ReadResponseHeaders(callback.callback()),
              IsError(ERR_IO_PENDING));
  ASSERT_THAT(callback.WaitForResult(), IsOk());

  // Finally, attempt to read the response body.
  auto body_buffer = base::MakeRefCounted<IOBufferWithSize>(kBodySize);
  ASSERT_EQ(ERR_IO_PENDING,
            parser.ReadResponseBody(body_buffer.get(), kBodySize,
                                    callback.callback()));
  ASSERT_EQ(kBodySize, callback.WaitForResult());

  EXPECT_EQ(CountWriteBytes(writes), parser.sent_bytes());
  EXPECT_EQ(CountReadBytes(reads), parser.received_bytes());
}

// Test to ensure the HttpStreamParser state machine does not get confused
// when sending a request with a chunked body, where chunks become available
// asynchronously, over a socket where writes may also complete
// asynchronously.
// This is a regression test for http://crbug.com/132243
TEST(HttpStreamParser, AsyncChunkAndAsyncSocketWithMultipleChunks) {
  base::test::TaskEnvironment task_environment;

  // The chunks that will be written in the request, as reflected in the
  // MockWrites below.
  static const char kChunk1[] = "Chunk 1";
  static const char kChunk2[] = "Chunky 2";
  static const char kChunk3[] = "Test 3";

  MockWrite writes[] = {
      MockWrite(ASYNC, 0,
                "GET /one.html HTTP/1.1\r\n"
                "Transfer-Encoding: chunked\r\n\r\n"),
      MockWrite(ASYNC, 1, "7\r\nChunk 1\r\n"),
      MockWrite(ASYNC, 2, "8\r\nChunky 2\r\n"),
      MockWrite(ASYNC, 3, "6\r\nTest 3\r\n"),
      MockWrite(ASYNC, 4, "0\r\n\r\n"),
  };

  // The size of the response body, as reflected in the Content-Length of the
  // MockRead below.
  static const int kBodySize = 8;

  MockRead reads[] = {
    MockRead(ASYNC, 5, "HTTP/1.1 200 OK\r\n"),
    MockRead(ASYNC, 6, "Content-Length: 8\r\n\r\n"),
    MockRead(ASYNC, 7, "one.html"),
    MockRead(SYNCHRONOUS, 0, 8),  // EOF
  };

  ChunkedUploadDataStream upload_stream(0);
  upload_stream.AppendData(base::byte_span_from_cstring(kChunk1), false);
  ASSERT_THAT(upload_stream.Init(TestCompletionCallback().callback(),
                                 NetLogWithSource()),
              IsOk());

  SequencedSocketData data(reads, writes);
  std::unique_ptr<StreamSocket> stream_socket = CreateConnectedSocket(&data);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://localhost");
  request_info.upload_data_stream = &upload_stream;

  scoped_refptr<GrowableIOBuffer> read_buffer =
      base::MakeRefCounted<GrowableIOBuffer>();
  HttpStreamParser parser(stream_socket.get(), false /* is_reused */,
                          GURL("http://localhost"), "GET", &u
"""


```
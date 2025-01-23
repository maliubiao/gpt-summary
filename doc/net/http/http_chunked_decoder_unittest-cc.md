Response:
Let's break down the thought process for analyzing this C++ unit test file.

**1. Understanding the Goal:**

The primary goal is to understand the purpose and functionality of the code being tested. Since it's a unit test, we know it's testing a specific component in isolation. The filename `http_chunked_decoder_unittest.cc` and the presence of `HttpChunkedDecoder` in the code strongly suggest this file tests the decoding of HTTP chunked transfer encoding.

**2. Initial Code Scan and Keyword Identification:**

* **`#include "net/http/http_chunked_decoder.h"`:**  Confirms the target of the tests.
* **`TEST(HttpChunkedDecoderTest, ...)`:**  Standard Google Test macro indicating individual test cases.
* **`RunTest(...)` and `RunTestUntilFailure(...)`:** Helper functions encapsulating common test logic. This hints at different success/failure scenarios.
* **Input arrays of `const char* const inputs[]`:**  The primary way test cases provide input to the decoder. These look like strings representing parts of a chunked HTTP response body.
* **`expected_output`:**  The expected decoded content.
* **`expected_eof`:**  Whether the decoder should reach the end-of-file marker.
* **`bytes_after_eof`:** How many extra bytes are present after the EOF marker.
* **`decoder.FilterBuf(...)`:**  The core function being tested, taking input and presumably returning the number of bytes processed or an error code.
* **Error checking with `EXPECT_GE(n, 0)` and `EXPECT_THAT(n, IsError(ERR_INVALID_CHUNKED_ENCODING))`:**  Verifies the correct behavior (success or specific error).
* **Various test case names like `Basic`, `OneChunk`, `Typical`, `Incremental`, `LF_InsteadOf_CRLF`, `Extensions`, `Trailers`, `InvalidChunkSize_...`, `ReallyBigChunks`, `BasicExtraData`, etc.:** These names provide clues about the specific aspects of the chunked decoding being tested (basic functionality, edge cases, invalid input formats).
* **Comments about compatibility with different browsers (Firefox, IE, Safari, Opera):** Highlights that the implementation needs to handle variations in how different clients/servers implement chunked encoding.

**3. Deciphering the Test Logic (`RunTest` and `RunTestUntilFailure`):**

* **`RunTest`:** Iterates through the input strings, feeds them to the `decoder.FilterBuf`, appends the successful output, and then checks the final decoded output, EOF status, and extra bytes. This represents a successful decoding scenario.
* **`RunTestUntilFailure`:**  Similar to `RunTest`, but expects `decoder.FilterBuf` to return an error (`ERR_INVALID_CHUNKED_ENCODING`) at a specific input index. This represents testing error handling for invalid chunked encoding.

**4. Analyzing Individual Test Cases:**

Start with the simpler test cases and progress to the more complex ones:

* **`Basic`:**  A simple, complete chunked response. Good starting point.
* **`OneChunk`:**  Tests decoding a single chunk.
* **`Typical`:**  A more realistic scenario with multiple chunks.
* **`Incremental` and `Incremental2`:**  Focus on how the decoder handles input being fed in small fragments. Important for network streams.
* **`LF_InsteadOf_CRLF`:**  Tests tolerance (or lack thereof) for line feeds instead of carriage return line feeds. The comments about browser compatibility are crucial here.
* **`Extensions`:**  Tests handling of optional chunk extensions.
* **`Trailers` and `TrailersUnfinished`:**  Tests handling of HTTP trailers after the last chunk.
* **`InvalidChunkSize_...`:**  A series of tests specifically designed to check how the decoder handles various invalid formats for the chunk size. The comments about browser compatibility are very important in understanding *why* these tests exist.
* **`ReallyBigChunks`:** Tests handling of very large chunk sizes to ensure there are no integer overflows or other issues.
* **`BasicExtraData` and related tests:** Focus on handling extra data after the end of the chunked body.
* **`LongChunkLengthLine` and `LongLengthLengthLine`:** Test limits on the length of the chunk size line and extension lines.

**5. Identifying Functionality and JavaScript Relevance:**

* **Functionality:**  The primary function is to decode HTTP responses encoded with chunked transfer encoding. It takes raw byte streams as input and produces the original unchunked data. It also needs to handle errors gracefully.
* **JavaScript Relevance:** Browsers (and therefore JavaScript running in them) rely on the network stack to fetch resources. When a server responds with `Transfer-Encoding: chunked`, this `HttpChunkedDecoder` is part of the process that makes that data available to the JavaScript. JavaScript itself doesn't directly interact with this C++ code, but its ability to receive HTTP responses depends on it working correctly.

**6. Constructing Examples and Scenarios:**

Based on the test cases and understanding of HTTP chunked encoding, we can create hypothetical scenarios involving user actions, network requests, and how this decoder plays a role.

**7. Identifying Potential Errors:**

The "InvalidChunkSize" test cases are excellent sources for common errors. Users (or rather, server implementations) might incorrectly format the chunk size. Network issues could also lead to incomplete or corrupted chunks.

**8. Tracing User Actions to the Decoder:**

This involves understanding the typical flow of a web request and where the chunked decoder fits in.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just about decoding."  **Correction:**  It's also about error handling, tolerance of minor variations in the specification, and performance with large chunks.
* **Initial thought:** "JavaScript directly calls this code." **Correction:**  JavaScript interacts with higher-level browser APIs. The C++ network stack works behind the scenes.
* **Focus on the "why":**  The comments about browser compatibility are key to understanding why certain tests for seemingly "invalid" formats exist. The decoder needs to be robust enough to handle the realities of the web, where servers may not strictly adhere to the RFC.

By following these steps, moving from the general to the specific, and continuously refining the understanding based on the code and its context, we can arrive at a comprehensive analysis of the provided unit test file.
这个文件 `net/http/http_chunked_decoder_unittest.cc` 是 Chromium 网络栈的一部分，它的主要功能是**测试 `HttpChunkedDecoder` 类的功能**。`HttpChunkedDecoder` 负责解码 HTTP 响应中使用了 "chunked" 传输编码的数据。

**以下是这个文件的功能详细列表：**

1. **单元测试框架:**  它使用 Google Test 框架（gtest）来组织和执行测试用例。每个 `TEST` 宏定义了一个独立的测试场景。

2. **测试 `HttpChunkedDecoder::FilterBuf()` 方法:**  这是 `HttpChunkedDecoder` 类的核心方法，负责接收包含 chunked 编码数据的缓冲区，并返回已解码的字节数。测试用例会模拟不同的输入场景来验证 `FilterBuf()` 的正确性。

3. **验证各种合法的 chunked 编码格式:**  测试用例涵盖了基本的 chunked 编码格式，包括：
    * 单个 chunk。
    * 多个 chunk。
    * 增量接收数据的情况。
    * 带有 chunk 扩展的情况。
    * 带有 trailer header 的情况。

4. **验证各种非法的 chunked 编码格式和错误处理:**  测试用例还包含各种故意构造的错误输入，以测试 `HttpChunkedDecoder` 的错误处理能力，例如：
    * 无效的 chunk 大小格式（例如，非十六进制字符、前导或尾随空格/制表符、负数、过大）。
    * 缺少分隔符 (`\r\n`)。
    * 连续的 `\r\n`。
    * 过长的 chunk 大小行或扩展行。

5. **测试 EOF（End-of-File）的检测:**  测试用例验证 `HttpChunkedDecoder` 能正确识别 chunked 编码的结束标志 (`0\r\n\r\n`)，并设置 `reached_eof()` 状态。

6. **测试额外数据处理:**  测试用例验证 `HttpChunkedDecoder` 在 chunked 编码结束后遇到额外数据时能正确处理，并记录 `bytes_after_eof()` 的值。

7. **兼容性测试:** 一些测试用例的注释提到了不同浏览器（Firefox, IE, Safari, Opera）对某些非标准 chunked 编码的处理方式，这表明 Chromium 的实现需要考虑一定的兼容性。

**与 JavaScript 功能的关系及举例说明:**

JavaScript 在浏览器中运行，当它通过 `fetch` API 或 `XMLHttpRequest` 发起 HTTP 请求并接收到服务器的响应时，如果响应头中包含 `Transfer-Encoding: chunked`，那么 Chromium 的网络栈就会使用 `HttpChunkedDecoder` 来解码响应体。

**举例说明:**

假设一个 JavaScript 代码发起一个 HTTP GET 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.text())
  .then(data => console.log(data));
```

如果 `https://example.com/data` 的服务器返回的响应头包含 `Transfer-Encoding: chunked`，例如：

```
HTTP/1.1 200 OK
Content-Type: text/plain
Transfer-Encoding: chunked

5\r\n
hello\r\n
6\r\n
 world\r\n
0\r\n
\r\n
```

那么，在 Chromium 的网络栈中，`HttpChunkedDecoder` 会接收到 `5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n` 这部分数据，并将其解码为 "hello world"。  最终，JavaScript 的 `data` 变量会接收到解码后的字符串 "hello world"。

**逻辑推理、假设输入与输出:**

**假设输入：** `const char* const inputs[] = {"4\r\n", "test\r\n", "0\r\n\r\n"};`

**逻辑推理：** `HttpChunkedDecoder` 会首先读取 "4\r\n"，解析出 chunk 大小为 4。然后读取接下来的 4 个字节 "test"。接着读取 "0\r\n\r\n"，识别出这是最后一个 chunk，表示数据结束。

**预期输出：**
* `RunTest` 函数中的 `result` 字符串会是 "test"。
* `decoder.reached_eof()` 会返回 `true`。
* `decoder.bytes_after_eof()` 会返回 0。

**涉及用户或编程常见的使用错误及举例说明:**

虽然用户（开发者）通常不会直接操作 `HttpChunkedDecoder`，但服务器端的程序员在实现 HTTP 服务时可能会犯一些常见的错误，导致生成无效的 chunked 编码数据。Chromium 的 `HttpChunkedDecoder` 需要能够处理这些错误。

**举例说明：**

1. **错误地计算 chunk 大小：**
   服务器发送：`A\r\nhello\r\n0\r\n\r\n` （预期大小为 10，实际发送 5 字节 "hello"）
   Chromium 的 `HttpChunkedDecoder` 会检测到实际接收的字节数与声明的 chunk 大小不符，并可能返回 `ERR_INVALID_CHUNKED_ENCODING`。

2. **忘记发送最后的 `0\r\n\r\n` 结束符：**
   服务器发送：`5\r\nhello\r\n`
   Chromium 的 `HttpChunkedDecoder` 会一直等待结束符，`reached_eof()` 会保持 `false`，导致请求无法正常完成。

3. **Chunk 大小格式错误：**
   服务器发送：`0x5\r\nhello\r\n0\r\n\r\n` (使用 "0x" 前缀)
   Chromium 的 `HttpChunkedDecoder` 会因为无法解析 chunk 大小而返回 `ERR_INVALID_CHUNKED_ENCODING`。

**用户操作是如何一步步到达这里的，作为调试线索:**

当用户在浏览器中访问一个网站或执行某些操作时，浏览器会发起 HTTP 请求。如果服务器响应使用了 chunked 编码，以下步骤可能会导致代码执行到 `HttpChunkedDecoder`：

1. **用户在地址栏输入 URL 或点击链接。**
2. **浏览器解析 URL，查找 DNS，建立 TCP 连接。**
3. **浏览器发送 HTTP 请求到服务器。**
4. **服务器处理请求并生成 HTTP 响应。**
5. **服务器决定使用 chunked 编码发送响应体，并在响应头中设置 `Transfer-Encoding: chunked`。**
6. **浏览器接收到响应头，识别出使用了 chunked 编码。**
7. **浏览器开始接收响应体的数据流。**
8. **网络栈的底层模块接收到来自网络的数据包。**
9. **网络栈的 HTTP 解析模块负责处理 HTTP 协议，并将接收到的数据传递给 `HttpChunkedDecoder` 进行解码。**
10. **`HttpChunkedDecoder` 的 `FilterBuf()` 方法被调用，传入接收到的数据块。**
11. **`FilterBuf()` 方法解析 chunk 大小，提取 chunk 数据，并缓存或输出解码后的数据。**
12. **如果 chunked 编码结束，`HttpChunkedDecoder` 会标记 EOF。**
13. **解码后的数据最终传递给浏览器渲染引擎或 JavaScript 代码。**

**作为调试线索：**

* 如果用户报告页面加载缓慢或内容不完整，可能是因为 chunked 编码解码过程中遇到了问题。
* 可以使用浏览器的开发者工具（Network 标签）查看响应头，确认是否使用了 chunked 编码。
* 如果怀疑是 chunked 编码的问题，可以尝试捕获网络数据包（例如，使用 Wireshark）来查看原始的 chunked 编码数据，并与 `HttpChunkedDecoder` 的测试用例进行对比，寻找可能的错误。
* 在 Chromium 的源代码中设置断点在 `HttpChunkedDecoder::FilterBuf()` 方法中，可以逐步跟踪 chunked 数据的解码过程，查看中间状态和变量值，从而定位问题。

总而言之，`net/http/http_chunked_decoder_unittest.cc` 这个文件通过大量的测试用例，确保了 Chromium 的 `HttpChunkedDecoder` 能够正确、可靠地解码各种合法的和非法的 chunked 编码数据，这对于保证网络请求的正常进行至关重要。

### 提示词
```
这是目录为net/http/http_chunked_decoder_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2006-2008 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/http/http_chunked_decoder.h"

#include <memory>
#include <string>
#include <vector>

#include "base/format_macros.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/stringprintf.h"
#include "net/base/net_errors.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

typedef testing::Test HttpChunkedDecoderTest;

void RunTest(const char* const inputs[],
             size_t num_inputs,
             const char* expected_output,
             bool expected_eof,
             int bytes_after_eof) {
  HttpChunkedDecoder decoder;
  EXPECT_FALSE(decoder.reached_eof());

  std::string result;

  for (size_t i = 0; i < num_inputs; ++i) {
    std::string input = inputs[i];
    int n = decoder.FilterBuf(base::as_writable_byte_span(input));
    EXPECT_GE(n, 0);
    if (n > 0)
      result.append(input.data(), n);
  }

  EXPECT_EQ(expected_output, result);
  EXPECT_EQ(expected_eof, decoder.reached_eof());
  EXPECT_EQ(bytes_after_eof, decoder.bytes_after_eof());
}

// Feed the inputs to the decoder, until it returns an error.
void RunTestUntilFailure(const char* const inputs[],
                         size_t num_inputs,
                         size_t fail_index) {
  HttpChunkedDecoder decoder;
  EXPECT_FALSE(decoder.reached_eof());

  for (size_t i = 0; i < num_inputs; ++i) {
    std::string input = inputs[i];
    int n = decoder.FilterBuf(base::as_writable_byte_span(input));
    if (n < 0) {
      EXPECT_THAT(n, IsError(ERR_INVALID_CHUNKED_ENCODING));
      EXPECT_EQ(fail_index, i);
      return;
    }
  }
  FAIL();  // We should have failed on the |fail_index| iteration of the loop.
}

TEST(HttpChunkedDecoderTest, Basic) {
  const char* const inputs[] = {
    "B\r\nhello hello\r\n0\r\n\r\n"
  };
  RunTest(inputs, std::size(inputs), "hello hello", true, 0);
}

TEST(HttpChunkedDecoderTest, OneChunk) {
  const char* const inputs[] = {
    "5\r\nhello\r\n"
  };
  RunTest(inputs, std::size(inputs), "hello", false, 0);
}

TEST(HttpChunkedDecoderTest, Typical) {
  const char* const inputs[] = {
    "5\r\nhello\r\n",
    "1\r\n \r\n",
    "5\r\nworld\r\n",
    "0\r\n\r\n"
  };
  RunTest(inputs, std::size(inputs), "hello world", true, 0);
}

TEST(HttpChunkedDecoderTest, Incremental) {
  const char* const inputs[] = {
    "5",
    "\r",
    "\n",
    "hello",
    "\r",
    "\n",
    "0",
    "\r",
    "\n",
    "\r",
    "\n"
  };
  RunTest(inputs, std::size(inputs), "hello", true, 0);
}

// Same as above, but group carriage returns with previous input.
TEST(HttpChunkedDecoderTest, Incremental2) {
  const char* const inputs[] = {
    "5\r",
    "\n",
    "hello\r",
    "\n",
    "0\r",
    "\n\r",
    "\n"
  };
  RunTest(inputs, std::size(inputs), "hello", true, 0);
}

TEST(HttpChunkedDecoderTest, LF_InsteadOf_CRLF) {
  // Compatibility: [RFC 7230 - Invalid]
  // {Firefox3} - Valid
  // {IE7, Safari3.1, Opera9.51} - Invalid
  const char* const inputs[] = {
    "5\nhello\n",
    "1\n \n",
    "5\nworld\n",
    "0\n\n"
  };
  RunTest(inputs, std::size(inputs), "hello world", true, 0);
}

TEST(HttpChunkedDecoderTest, Extensions) {
  const char* const inputs[] = {
    "5;x=0\r\nhello\r\n",
    "0;y=\"2 \"\r\n\r\n"
  };
  RunTest(inputs, std::size(inputs), "hello", true, 0);
}

TEST(HttpChunkedDecoderTest, Trailers) {
  const char* const inputs[] = {
    "5\r\nhello\r\n",
    "0\r\n",
    "Foo: 1\r\n",
    "Bar: 2\r\n",
    "\r\n"
  };
  RunTest(inputs, std::size(inputs), "hello", true, 0);
}

TEST(HttpChunkedDecoderTest, TrailersUnfinished) {
  const char* const inputs[] = {
    "5\r\nhello\r\n",
    "0\r\n",
    "Foo: 1\r\n"
  };
  RunTest(inputs, std::size(inputs), "hello", false, 0);
}

TEST(HttpChunkedDecoderTest, InvalidChunkSize_TooBig) {
  const char* const inputs[] = {
    // This chunked body is not terminated.
    // However we will fail decoding because the chunk-size
    // number is larger than we can handle.
    "48469410265455838241\r\nhello\r\n",
    "0\r\n\r\n"
  };
  RunTestUntilFailure(inputs, std::size(inputs), 0);
}

TEST(HttpChunkedDecoderTest, InvalidChunkSize_0X) {
  const char* const inputs[] = {
    // Compatibility [RFC 7230 - Invalid]:
    // {Safari3.1, IE7} - Invalid
    // {Firefox3, Opera 9.51} - Valid
    "0x5\r\nhello\r\n",
    "0\r\n\r\n"
  };
  RunTestUntilFailure(inputs, std::size(inputs), 0);
}

TEST(HttpChunkedDecoderTest, ChunkSize_TrailingSpace) {
  const char* const inputs[] = {
    // Compatibility [RFC 7230 - Invalid]:
    // {IE7, Safari3.1, Firefox3, Opera 9.51} - Valid
    //
    // At least yahoo.com depends on this being valid.
    "5      \r\nhello\r\n",
    "0\r\n\r\n"
  };
  RunTest(inputs, std::size(inputs), "hello", true, 0);
}

TEST(HttpChunkedDecoderTest, InvalidChunkSize_TrailingTab) {
  const char* const inputs[] = {
    // Compatibility [RFC 7230 - Invalid]:
    // {IE7, Safari3.1, Firefox3, Opera 9.51} - Valid
    "5\t\r\nhello\r\n",
    "0\r\n\r\n"
  };
  RunTestUntilFailure(inputs, std::size(inputs), 0);
}

TEST(HttpChunkedDecoderTest, InvalidChunkSize_TrailingFormFeed) {
  const char* const inputs[] = {
    // Compatibility [RFC 7230- Invalid]:
    // {Safari3.1} - Invalid
    // {IE7, Firefox3, Opera 9.51} - Valid
    "5\f\r\nhello\r\n",
    "0\r\n\r\n"
  };
  RunTestUntilFailure(inputs, std::size(inputs), 0);
}

TEST(HttpChunkedDecoderTest, InvalidChunkSize_TrailingVerticalTab) {
  const char* const inputs[] = {
    // Compatibility [RFC 7230 - Invalid]:
    // {Safari 3.1} - Invalid
    // {IE7, Firefox3, Opera 9.51} - Valid
    "5\v\r\nhello\r\n",
    "0\r\n\r\n"
  };
  RunTestUntilFailure(inputs, std::size(inputs), 0);
}

TEST(HttpChunkedDecoderTest, InvalidChunkSize_TrailingNonHexDigit) {
  const char* const inputs[] = {
    // Compatibility [RFC 7230 - Invalid]:
    // {Safari 3.1} - Invalid
    // {IE7, Firefox3, Opera 9.51} - Valid
    "5H\r\nhello\r\n",
    "0\r\n\r\n"
  };
  RunTestUntilFailure(inputs, std::size(inputs), 0);
}

TEST(HttpChunkedDecoderTest, InvalidChunkSize_LeadingSpace) {
  const char* const inputs[] = {
    // Compatibility [RFC 7230 - Invalid]:
    // {IE7} - Invalid
    // {Safari 3.1, Firefox3, Opera 9.51} - Valid
    " 5\r\nhello\r\n",
    "0\r\n\r\n"
  };
  RunTestUntilFailure(inputs, std::size(inputs), 0);
}

TEST(HttpChunkedDecoderTest, InvalidLeadingSeparator) {
  const char* const inputs[] = {
    "\r\n5\r\nhello\r\n",
    "0\r\n\r\n"
  };
  RunTestUntilFailure(inputs, std::size(inputs), 0);
}

TEST(HttpChunkedDecoderTest, InvalidChunkSize_NoSeparator) {
  const char* const inputs[] = {
    "5\r\nhello",
    "1\r\n \r\n",
    "0\r\n\r\n"
  };
  RunTestUntilFailure(inputs, std::size(inputs), 1);
}

TEST(HttpChunkedDecoderTest, InvalidChunkSize_Negative) {
  const char* const inputs[] = {
    "8\r\n12345678\r\n-5\r\nhello\r\n",
    "0\r\n\r\n"
  };
  RunTestUntilFailure(inputs, std::size(inputs), 0);
}

TEST(HttpChunkedDecoderTest, InvalidChunkSize_Plus) {
  const char* const inputs[] = {
    // Compatibility [RFC 7230 - Invalid]:
    // {IE7, Safari 3.1} - Invalid
    // {Firefox3, Opera 9.51} - Valid
    "+5\r\nhello\r\n",
    "0\r\n\r\n"
  };
  RunTestUntilFailure(inputs, std::size(inputs), 0);
}

TEST(HttpChunkedDecoderTest, InvalidConsecutiveCRLFs) {
  const char* const inputs[] = {
    "5\r\nhello\r\n",
    "\r\n\r\n\r\n\r\n",
    "0\r\n\r\n"
  };
  RunTestUntilFailure(inputs, std::size(inputs), 1);
}

TEST(HttpChunkedDecoderTest, ReallyBigChunks) {
  // Number of bytes sent through the chunked decoder per loop iteration. To
  // minimize runtime, should be the square root of the chunk lengths, below.
  const size_t kWrittenBytesPerIteration = 0x10000;

  // Length of chunks to test. Must be multiples of kWrittenBytesPerIteration.
  int64_t kChunkLengths[] = {
      // Overflows when cast to a signed int32.
      0x0c0000000,
      // Overflows when cast to an unsigned int32.
      0x100000000,
  };

  for (int64_t chunk_length : kChunkLengths) {
    HttpChunkedDecoder decoder;
    EXPECT_FALSE(decoder.reached_eof());

    // Feed just the header to the decode.
    std::string chunk_header =
        base::StringPrintf("%" PRIx64 "\r\n", chunk_length);
    std::vector<char> data(chunk_header.begin(), chunk_header.end());
    EXPECT_EQ(OK, decoder.FilterBuf(base::as_writable_byte_span(data)));
    EXPECT_FALSE(decoder.reached_eof());

    // Set |data| to be kWrittenBytesPerIteration long, and have a repeating
    // pattern.
    data.clear();
    data.reserve(kWrittenBytesPerIteration);
    for (size_t i = 0; i < kWrittenBytesPerIteration; i++) {
      data.push_back(static_cast<char>(i));
    }

    // Repeatedly feed the data to the chunked decoder. Since the data doesn't
    // include any chunk lengths, the decode will never have to move the data,
    // and should run fairly quickly.
    for (int64_t total_written = 0; total_written < chunk_length;
         total_written += kWrittenBytesPerIteration) {
      EXPECT_EQ(kWrittenBytesPerIteration,
                base::checked_cast<size_t>(
                    decoder.FilterBuf(base::as_writable_byte_span(data).first(
                        kWrittenBytesPerIteration))));
      EXPECT_FALSE(decoder.reached_eof());
    }

    // Chunk terminator and the final chunk.
    char final_chunk[] = "\r\n0\r\n\r\n";
    EXPECT_EQ(OK, decoder.FilterBuf(base::as_writable_byte_span(final_chunk)));
    EXPECT_TRUE(decoder.reached_eof());

    // Since |data| never included any chunk headers, it should not have been
    // modified.
    for (size_t i = 0; i < kWrittenBytesPerIteration; i++) {
      EXPECT_EQ(static_cast<char>(i), data[i]);
    }
  }
}

TEST(HttpChunkedDecoderTest, ExcessiveChunkLen) {
  // Smallest number that can't be represented as a signed int64.
  const char* const inputs[] = {"8000000000000000\r\nhello\r\n"};
  RunTestUntilFailure(inputs, std::size(inputs), 0);
}

TEST(HttpChunkedDecoderTest, ExcessiveChunkLen2) {
  // Smallest number that can't be represented as an unsigned int64.
  const char* const inputs[] = {"10000000000000000\r\nhello\r\n"};
  RunTestUntilFailure(inputs, std::size(inputs), 0);
}

TEST(HttpChunkedDecoderTest, BasicExtraData) {
  const char* const inputs[] = {
    "5\r\nhello\r\n0\r\n\r\nextra bytes"
  };
  RunTest(inputs, std::size(inputs), "hello", true, 11);
}

TEST(HttpChunkedDecoderTest, IncrementalExtraData) {
  const char* const inputs[] = {
    "5",
    "\r",
    "\n",
    "hello",
    "\r",
    "\n",
    "0",
    "\r",
    "\n",
    "\r",
    "\nextra bytes"
  };
  RunTest(inputs, std::size(inputs), "hello", true, 11);
}

TEST(HttpChunkedDecoderTest, MultipleExtraDataBlocks) {
  const char* const inputs[] = {
    "5\r\nhello\r\n0\r\n\r\nextra",
    " bytes"
  };
  RunTest(inputs, std::size(inputs), "hello", true, 11);
}

// Test when the line with the chunk length is too long.
TEST(HttpChunkedDecoderTest, LongChunkLengthLine) {
  int big_chunk_length = HttpChunkedDecoder::kMaxLineBufLen;
  auto big_chunk = std::make_unique<char[]>(big_chunk_length + 1);
  memset(big_chunk.get(), '0', big_chunk_length);
  big_chunk[big_chunk_length] = 0;
  const char* const inputs[] = {
    big_chunk.get(),
    "5"
  };
  RunTestUntilFailure(inputs, std::size(inputs), 1);
}

// Test when the extension portion of the line with the chunk length is too
// long.
TEST(HttpChunkedDecoderTest, LongLengthLengthLine) {
  int big_chunk_length = HttpChunkedDecoder::kMaxLineBufLen;
  auto big_chunk = std::make_unique<char[]>(big_chunk_length + 1);
  memset(big_chunk.get(), '0', big_chunk_length);
  big_chunk[big_chunk_length] = 0;
  const char* const inputs[] = {
    "5;",
    big_chunk.get()
  };
  RunTestUntilFailure(inputs, std::size(inputs), 1);
}

}  // namespace

}  // namespace net
```
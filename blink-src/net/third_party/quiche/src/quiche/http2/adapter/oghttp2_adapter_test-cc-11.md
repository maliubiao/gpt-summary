Response:
Let's break down the thought process to analyze this C++ test file for an HTTP/2 adapter.

1. **Understand the Goal:** The core goal is to understand what this specific C++ file `oghttp2_adapter_test.cc` does within the Chromium networking stack. Since it ends with `_test.cc`, the primary function is *testing*. Specifically, it's testing the `OgHttp2Adapter`.

2. **Identify Key Components:**  The filename itself points to the central component: `OgHttp2Adapter`. The `test.cc` suffix indicates that it contains unit tests for this adapter. Looking at the `#include` directives (though not provided in the prompt, a real analysis would start there) would confirm dependencies like gtest (`testing::*`), standard C++ libraries, and likely other Quiche/Chromium HTTP/2 related headers.

3. **Examine Test Structure:**  The code is organized into `TEST` and `TEST_P` macros, which are characteristic of Google Test. This tells us we're dealing with individual test cases and parameterized tests, respectively.

4. **Analyze Individual Tests (High-Level):**  Read through the names of the tests. They often give a good idea of what's being tested:

    * `PaddedDataFrames` -> Testing how the adapter handles padded data frames.
    * `NoopHeaderValidatorTest` -> Testing the behavior when header validation is disabled.
    * `NegativeFlowControlStreamResumption` ->  Testing how the adapter handles negative flow control and stream resumption.
    * `SetCookieRoundtrip` -> Testing the handling of `Set-Cookie` headers in both directions.

5. **Dive Deeper into Test Logic (Key Patterns):** Look for recurring patterns within the test cases:

    * **Setup:**  Creating `TestVisitor` (a mock object likely used to observe interactions with the adapter) and `OgHttp2Adapter` instances with specific options.
    * **Input:**  Constructing HTTP/2 frame sequences using `TestFrameSequence`. These represent the bytes the adapter will process.
    * **Expectations:**  Using `EXPECT_CALL` from Google Mock to define the expected interactions with the `TestVisitor`. This is crucial for verifying the adapter's behavior.
    * **Processing:** Calling `adapter->ProcessBytes()` to feed the input frames to the adapter.
    * **Assertions:**  Using `EXPECT_EQ`, `EXPECT_TRUE`, `ASSERT_EQ`, `EXPECT_THAT`, etc., to check the results of the processing (e.g., return values, visitor data).
    * **Sending (and more Expectations):** Calling `adapter->Send()` and setting further expectations on `OnBeforeFrameSent` and `OnFrameSent` to verify the adapter's output.

6. **Connect to HTTP/2 Concepts:**  Recognize the HTTP/2 concepts being tested:

    * **Frames:** HEADERS, DATA, SETTINGS, WINDOW_UPDATE, etc.
    * **Streams:**  The use of stream IDs (1, 3, 5, etc.).
    * **Padding:** The `PaddedDataFrames` test specifically targets padding.
    * **Header Validation:** The `NoopHeaderValidatorTest` explicitly disables validation.
    * **Flow Control:** The `NegativeFlowControlStreamResumption` test deals with window sizes and their impact.
    * **`Set-Cookie` Headers:**  A specific HTTP header field with particular handling requirements.
    * **Client and Server Perspectives:** The tests often set the `perspective` option to simulate client or server behavior.

7. **Address Specific Questions:**  Now, go back and explicitly answer the questions in the prompt:

    * **Functionality:** Summarize the observed testing activities. It tests the parsing and generation of HTTP/2 frames, header handling, flow control, and the adapter's behavior in different scenarios.
    * **Relationship to JavaScript:** While this C++ code doesn't directly *execute* JavaScript, it's part of the underlying infrastructure that enables JavaScript in a browser to communicate over HTTP/2. The example of `Set-Cookie` shows how the parsing in this C++ code affects how cookies are made available to JavaScript.
    * **Logical Reasoning (Input/Output):**  Pick a specific test (like `PaddedDataFrames`) and describe the input frames and the expected `OnFrameHeader`, `OnBeginDataForStream`, `OnDataForStream`, `OnDataPaddingLength` callbacks on the visitor.
    * **Common Usage Errors:** Think about what could go wrong when *using* an HTTP/2 adapter. Submitting data when the flow control window is zero, or sending invalid header combinations (which the `NoopHeaderValidatorTest` addresses indirectly).
    * **User Operation to Reach Here (Debugging):**  Imagine a scenario where a website using HTTP/2 is behaving unexpectedly. The developer might use browser developer tools to inspect network traffic, revealing unusual frames or errors. This could lead a Chromium developer to investigate the `OgHttp2Adapter` and its tests.
    * **Final Summary (Part 12 of 12):** Emphasize that this is the *testing* component. It ensures the adapter behaves correctly, which is critical for the overall stability and functionality of the HTTP/2 implementation.

8. **Refine and Organize:** Structure the answer clearly with headings and bullet points to make it easy to read and understand.

By following this thought process, we can systematically analyze the C++ test file and provide a comprehensive answer to the prompt's questions. The key is to understand the purpose of testing, the structure of the tests, and the underlying HTTP/2 concepts being validated.
这是位于 `net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc` 的 Chromium 网络栈源代码文件，它主要的功能是**对 `OgHttp2Adapter` 类进行单元测试**。`OgHttp2Adapter` 是一个 HTTP/2 协议的适配器，它负责在底层的 HTTP/2 协议实现和上层应用之间进行转换和适配。

由于这是第 12 部分，也是最后一部分，我们可以推断这个文件包含了 `OgHttp2Adapter` 的各种功能和边界情况的测试用例。

下面详细列举其功能，并尝试关联 JavaScript、进行逻辑推理、说明常见错误，并提供调试线索：

**功能列举:**

1. **HTTP/2 帧的解析和生成测试:**
   - 测试 `OgHttp2Adapter` 能否正确解析收到的 HTTP/2 帧 (如 HEADERS, DATA, SETTINGS, WINDOW_UPDATE 等)。
   - 测试 `OgHttp2Adapter` 能否根据上层指令生成正确的 HTTP/2 帧。

2. **HTTP/2 首部处理测试:**
   - 测试 `OgHttp2Adapter` 如何处理 HTTP/2 首部 (headers)，包括请求首部和响应首部。
   - 测试首部的有效性校验（虽然其中一个测试用例 `NoopHeaderValidatorTest` 禁用了校验，但其他测试隐含了校验逻辑）。
   - 测试特殊首部字段的处理，如 `Set-Cookie` (在 `SetCookieRoundtrip` 测试中)。

3. **HTTP/2 数据流管理测试:**
   - 测试 `OgHttp2Adapter` 如何管理 HTTP/2 数据流 (streams)，包括创建、发送和接收数据。
   - 测试数据流的结束标志 (FIN)。
   - 测试数据流的优先级和依赖关系 (虽然这个文件中没有直接体现，但 `OgHttp2Adapter` 的功能可能包含)。

4. **HTTP/2 流控测试:**
   - 测试 `OgHttp2Adapter` 如何处理 HTTP/2 的流控机制，包括发送和接收窗口更新帧 (WINDOW_UPDATE)。
   - 测试在流控窗口为负时，数据流的恢复 (`NegativeFlowControlStreamResumption` 测试)。
   - 测试填充 (padding) 对流控的影响 (`PaddedDataFrames` 测试)。

5. **HTTP/2 设置 (SETTINGS) 帧处理测试:**
   - 测试 `OgHttp2Adapter` 如何处理 HTTP/2 的设置帧，包括发送和接收。
   - 测试对 `INITIAL_WINDOW_SIZE` 等关键设置的处理。

6. **客户端和服务端视角测试:**
   - 测试 `OgHttp2Adapter` 在作为客户端和服务器时的不同行为。

7. **错误处理测试 (可能隐含):**
   - 虽然这里没有明确的错误处理测试用例，但通过构造各种输入，可以间接地测试 `OgHttp2Adapter` 对异常情况的处理能力。

**与 JavaScript 功能的关系及举例说明:**

`OgHttp2Adapter` 本身是用 C++ 编写的，不直接包含 JavaScript 代码。但是，它在浏览器网络栈中扮演着关键角色，使得 JavaScript 代码能够通过 HTTP/2 协议与服务器进行通信。

**举例说明 (Set-Cookie):**

`SetCookieRoundtrip` 测试验证了 `OgHttp2Adapter` 能否正确处理 `Set-Cookie` 首部。当 JavaScript 代码通过 `fetch` 或 `XMLHttpRequest` 发起 HTTP/2 请求后，服务器返回的响应可能包含 `Set-Cookie` 首部。

- **C++ (OgHttp2Adapter):** `OgHttp2Adapter` 负责解析服务器发送的包含 `Set-Cookie` 首部的 HTTP/2 帧。`SetCookieRoundtrip` 测试确保 `OgHttp2Adapter` 能正确解析多个 `Set-Cookie` 首部，并且不会将它们错误地合并成一个。
- **JavaScript:** 浏览器内核在解析 `OgHttp2Adapter` 传递过来的首部信息后，会将 `Set-Cookie` 的值存储到 Cookie 存储中。后续 JavaScript 代码可以使用 `document.cookie` 或 `navigator.cookieEnabled` 等 API 来访问和操作这些 Cookie。

**假设输入与输出 (逻辑推理):**

**测试用例：`PaddedDataFrames`**

**假设输入:**  构造一个包含 HEADERS 帧和一个或多个 DATA 帧的 HTTP/2 帧序列，其中 DATA 帧包含填充 (padding)。

```
// 假设生成的帧序列 (简化表示)：
SETTINGS 帧 (客户端序言)
HEADERS 帧 (Stream ID 1，包含请求首部)
DATA 帧 (Stream ID 1，数据 "a"，padding 长度 254)
DATA 帧 (Stream ID 1，数据 "a"，padding 长度 254)
... (重复多次直到总大小接近 62KB)
```

**预期输出 (对 `visitor` 的调用):**

```
OnFrameHeader(0, 0, SETTINGS, 0)
OnSettingsStart()
OnSettingsEnd()
OnFrameHeader(1, _, HEADERS, 4)
OnBeginHeadersForStream(1)
OnHeaderForStream(1, _, _) (调用 4 次，对应请求首部)
OnEndHeadersForStream(1)
OnFrameHeader(1, _, DATA, 0x8) // 0x8 表示存在 padding
OnBeginDataForStream(1, _)
OnDataForStream(1, "a")
OnDataPaddingLength(1, 254)
// ... (对每个 DATA 帧重复 OnFrameHeader, OnBeginDataForStream, OnDataForStream, OnDataPaddingLength)
```

**涉及用户或编程常见的使用错误及举例说明:**

1. **未处理流控:**  上层应用如果忽略 `OgHttp2Adapter` 的流控信号 (如 `want_write()`)，可能会导致发送缓冲区溢出或违反 HTTP/2 协议。

   **例子:**  上层应用在 `OgHttp2Adapter` 返回 `want_write() == false` 时仍然尝试发送大量数据，这可能导致连接错误或数据丢失。

2. **错误的首部字段:**  如果上层应用提供了不符合 HTTP/2 规范的首部字段，`OgHttp2Adapter` (如果启用了首部校验) 可能会拒绝处理该请求或响应。

   **例子:**  提供包含非法字符或格式错误的 `:method` 首部。

3. **不正确的状态转换:**  HTTP/2 状态机有明确的转换规则。上层应用如果以不正确的顺序调用 `OgHttp2Adapter` 的方法，可能会导致协议错误。

   **例子:**  在没有发送 HEADERS 帧的情况下尝试发送 DATA 帧。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设一个用户在 Chrome 浏览器中访问一个使用了 HTTP/2 协议的网站，并且该网站的某个功能出现了问题，例如数据加载缓慢或请求失败。

1. **用户发起操作:** 用户在浏览器地址栏输入网址或点击链接。
2. **浏览器解析 URL 并建立连接:** Chrome 浏览器解析 URL，确定需要使用 HTTP/2 协议，并与服务器建立 TCP 连接和 TLS 握手。
3. **HTTP/2 连接建立:**  在 TLS 连接之上，浏览器和服务器进行 HTTP/2 连接的初始化，包括发送连接序言 (包含 SETTINGS 帧)。 这部分由 `OgHttp2Adapter` (或其底层的 Quiche 库) 处理。
4. **JavaScript 发起请求:** 网页上的 JavaScript 代码使用 `fetch` 或 `XMLHttpRequest` 发起 HTTP 请求。
5. **请求帧生成:** Chrome 浏览器网络栈中的更上层模块将 JavaScript 的请求信息转换为 HTTP/2 的 HEADERS 帧和可能的 DATA 帧。 `OgHttp2Adapter` 负责将这些上层表示转换为实际的 HTTP/2 帧字节流。
6. **帧的发送和接收:** `OgHttp2Adapter` 将生成的帧发送给服务器，并接收服务器返回的帧。
7. **帧的解析:** `OgHttp2Adapter` 解析接收到的 HTTP/2 帧，并将其转换回上层可以理解的数据结构。
8. **JavaScript 接收响应:**  解析后的响应数据最终传递给 JavaScript 代码。

**调试线索:** 如果在这个过程中出现问题，例如：

- **请求被拒绝或超时:**  可能是请求帧生成错误、首部字段不合法或流控问题。
- **数据加载不完整或错误:**  可能是 DATA 帧处理错误、流控问题或填充处理错误。
- **连接中断:**  可能是 SETTINGS 帧处理错误或协议违规。

开发者可以通过以下方式进行调试，并可能最终涉及到 `oghttp2_adapter_test.cc` 中的测试用例：

- **Chrome 的 `net-internals` 工具:**  可以查看详细的网络请求和响应信息，包括 HTTP/2 帧的内容。
- **抓包工具 (如 Wireshark):**  可以捕获实际的网络数据包，分析 HTTP/2 帧的结构和内容。
- **Chromium 源代码调试:**  对于 Chromium 的开发者，可以直接调试 `OgHttp2Adapter` 的代码，查看帧的解析和生成过程。`oghttp2_adapter_test.cc` 中的测试用例可以帮助理解 `OgHttp2Adapter` 的预期行为，并用于验证修复后的代码。

**归纳其功能 (作为第 12 部分，共 12 部分):**

作为测试文件的最后一部分，`oghttp2_adapter_test.cc` 的功能是**对 `OgHttp2Adapter` 进行全面的单元测试，覆盖其核心的 HTTP/2 协议处理能力，包括帧的解析和生成、首部处理、流管理、流控、设置帧处理以及客户端和服务端视角下的行为。**  它的存在保证了 `OgHttp2Adapter` 的正确性和健壮性，从而确保了基于 Chromium 的浏览器能够可靠地进行 HTTP/2 通信。  这部分测试是整个 `OgHttp2Adapter` 开发和维护过程中至关重要的一环。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第12部分，共12部分，请归纳一下它的功能

"""
nsisting
  // of padding.
  size_t total_size = 0;
  while (total_size < 62 * 1024) {
    seq.Data(1, "a", /*fin=*/false, /*padding=*/254);
    total_size += 255;
  }
  const std::string frames = seq.Serialize();

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0x8))
      .Times(testing::AtLeast(1));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _)).Times(testing::AtLeast(1));
  EXPECT_CALL(visitor, OnDataForStream(1, "a")).Times(testing::AtLeast(1));
  EXPECT_CALL(visitor, OnDataPaddingLength(1, _)).Times(testing::AtLeast(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(result, frames.size());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  // Since most of the flow control window consumed is padding, the adapter
  // generates window updates.
  EXPECT_CALL(visitor, OnBeforeFrameSent(WINDOW_UPDATE, 1, _, 0x0)).Times(1);
  EXPECT_CALL(visitor, OnFrameSent(WINDOW_UPDATE, 1, _, 0x0, 0)).Times(1);
  EXPECT_CALL(visitor, OnBeforeFrameSent(WINDOW_UPDATE, 0, _, 0x0)).Times(1);
  EXPECT_CALL(visitor, OnFrameSent(WINDOW_UPDATE, 0, _, 0x0, 0)).Times(1);

  const int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS,
                            SpdyFrameType::WINDOW_UPDATE,
                            SpdyFrameType::WINDOW_UPDATE}));
}

// Verifies that NoopHeaderValidator allows several header combinations that
// would otherwise be invalid.
TEST(OgHttp2AdapterTest, NoopHeaderValidatorTest) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  options.validate_http_headers = false;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/1"},
                                           {"content-length", "7"},
                                           {"content-length", "7"}},
                                          /*fin=*/false)
                                 .Headers(3,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/3"},
                                           {"content-length", "11"},
                                           {"content-length", "13"}},
                                          /*fin=*/false)
                                 .Headers(5,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "foo.com"},
                                           {":path", "/"},
                                           {"host", "bar.com"}},
                                          /*fin=*/true)
                                 .Headers(7,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/"},
                                           {"Accept", "uppercase, oh boy!"}},
                                          /*fin=*/false)
                                 .Headers(9,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "ex|ample.com"},
                                           {":path", "/"}},
                                          /*fin=*/false)
                                 .Headers(11,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/"},
                                           {"content-length", "nan"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/1"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "content-length", "7"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "content-length", "7"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  // Stream 3
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":path", "/3"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, "content-length", "11"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, "content-length", "13"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  // Stream 5
  EXPECT_CALL(visitor, OnFrameHeader(5, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(5));
  EXPECT_CALL(visitor, OnHeaderForStream(5, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(5, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(5, ":authority", "foo.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(5, ":path", "/"));
  EXPECT_CALL(visitor, OnHeaderForStream(5, "host", "bar.com"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(5));
  EXPECT_CALL(visitor, OnEndStream(5));
  // Stream 7
  EXPECT_CALL(visitor, OnFrameHeader(7, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(7));
  EXPECT_CALL(visitor, OnHeaderForStream(7, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(7, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(7, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(7, ":path", "/"));
  EXPECT_CALL(visitor, OnHeaderForStream(7, "Accept", "uppercase, oh boy!"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(7));
  // Stream 9
  EXPECT_CALL(visitor, OnFrameHeader(9, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(9));
  EXPECT_CALL(visitor, OnHeaderForStream(9, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(9, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(9, ":authority", "ex|ample.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(9, ":path", "/"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(9));
  // Stream 11
  EXPECT_CALL(visitor, OnFrameHeader(11, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(11));
  EXPECT_CALL(visitor, OnHeaderForStream(11, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(11, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(11, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(11, ":path", "/"));
  EXPECT_CALL(visitor, OnHeaderForStream(11, "content-length", "nan"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(11));
  EXPECT_CALL(visitor, OnEndStream(11));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));
}

TEST_P(OgHttp2AdapterDataTest, NegativeFlowControlStreamResumption) {
  TestVisitor visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames =
      TestFrameSequence()
          .ClientPreface({{INITIAL_WINDOW_SIZE, 128u * 1024u}})
          .WindowUpdate(0, 1 << 20)
          .Headers(1,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/one"}},
                   /*fin=*/true)
          .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor,
              OnSetting(Http2Setting{Http2KnownSettingsId::INITIAL_WINDOW_SIZE,
                                     128u * 1024u}));
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 1 << 20));

  // Stream 1
  EXPECT_CALL(visitor,
              OnFrameHeader(1, _, HEADERS, END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  // Submit a response for the stream.
  visitor.AppendPayloadForStream(1, std::string(70000, 'a'));
  auto body = std::make_unique<VisitorDataSource>(visitor, 1);
  int submit_result =
      adapter->SubmitResponse(1, ToHeaders({{":status", "200"}}),
                              GetParam() ? nullptr : std::move(body), false);
  ASSERT_EQ(0, submit_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, END_HEADERS_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, END_HEADERS_FLAG, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0)).Times(5);

  adapter->Send();
  EXPECT_FALSE(adapter->want_write());

  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor,
              OnSetting(Http2Setting{Http2KnownSettingsId::INITIAL_WINDOW_SIZE,
                                     64u * 1024u}));
  EXPECT_CALL(visitor, OnSettingsEnd());

  // Processing these SETTINGS will cause stream 1's send window to become
  // negative.
  adapter->ProcessBytes(TestFrameSequence()
                            .Settings({{INITIAL_WINDOW_SIZE, 64u * 1024u}})
                            .Serialize());
  EXPECT_TRUE(adapter->want_write());
  EXPECT_LT(adapter->GetStreamSendWindowSize(1), 0);

  visitor.AppendPayloadForStream(1, "Stream should be resumed.");
  adapter->ResumeStream(1);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, ACK_FLAG));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, ACK_FLAG, 0));
  adapter->Send();
  EXPECT_FALSE(adapter->want_write());

  // Upon receiving the WINDOW_UPDATE, stream 1 should be ready to write.
  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(1, 10000));
  adapter->ProcessBytes(TestFrameSequence().WindowUpdate(1, 10000).Serialize());
  EXPECT_TRUE(adapter->want_write());
  EXPECT_GT(adapter->GetStreamSendWindowSize(1), 0);

  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));
  adapter->Send();
}

// Verifies that Set-Cookie headers are not folded in either the sending or
// receiving direction.
TEST(OgHttp2AdapterTest, SetCookieRoundtrip) {
  TestVisitor client_visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  auto client_adapter = OgHttp2Adapter::Create(client_visitor, options);

  TestVisitor server_visitor;
  options.perspective = Perspective::kServer;
  auto server_adapter = OgHttp2Adapter::Create(server_visitor, options);

  // Set-Cookie is a response headers. For the server to respond, the client
  // needs to send a request to open the stream.
  const std::vector<Header> request_headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id1 =
      client_adapter->SubmitRequest(request_headers, nullptr, true, nullptr);
  ASSERT_GT(stream_id1, 0);

  // Client visitor expectations on send.
  // Client preface with SETTINGS.
  EXPECT_CALL(client_visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(client_visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  // The client request.
  EXPECT_CALL(client_visitor,
              OnBeforeFrameSent(HEADERS, stream_id1, _,
                                END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(client_visitor,
              OnFrameSent(HEADERS, stream_id1, _,
                          END_STREAM_FLAG | END_HEADERS_FLAG, 0));

  EXPECT_EQ(0, client_adapter->Send());

  // Server visitor expectations on receive.
  // Client preface (empty SETTINGS)
  EXPECT_CALL(server_visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(server_visitor, OnSettingsStart());
  EXPECT_CALL(server_visitor,
              OnSetting(Http2Setting{Http2KnownSettingsId::ENABLE_PUSH, 0u}));
  EXPECT_CALL(server_visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(server_visitor, OnFrameHeader(stream_id1, _, HEADERS, 5));
  EXPECT_CALL(server_visitor, OnBeginHeadersForStream(stream_id1));
  EXPECT_CALL(server_visitor, OnHeaderForStream).Times(4);
  EXPECT_CALL(server_visitor, OnEndHeadersForStream(stream_id1));
  EXPECT_CALL(server_visitor, OnEndStream(stream_id1));

  // The server adapter processes the client's output.
  ASSERT_EQ(client_visitor.data().size(),
            server_adapter->ProcessBytes(client_visitor.data()));

  // Response headers contain two individual Set-Cookie fields.
  const std::vector<Header> response_headers =
      ToHeaders({{":status", "200"},
                 {"set-cookie", "chocolate_chip=yummy"},
                 {"set-cookie", "macadamia_nut=okay"}});

  EXPECT_EQ(0, server_adapter->SubmitResponse(stream_id1, response_headers,
                                              nullptr, true));

  // Server visitor expectations on send.
  // Server preface with initial SETTINGS.
  EXPECT_CALL(server_visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(server_visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  // SETTINGS ack
  EXPECT_CALL(server_visitor, OnBeforeFrameSent(SETTINGS, 0, 0, ACK_FLAG));
  EXPECT_CALL(server_visitor, OnFrameSent(SETTINGS, 0, 0, ACK_FLAG, 0));
  // Stream 1 response.
  EXPECT_CALL(server_visitor,
              OnBeforeFrameSent(HEADERS, stream_id1, _,
                                END_STREAM_FLAG | END_HEADERS_FLAG));
  EXPECT_CALL(server_visitor,
              OnFrameSent(HEADERS, stream_id1, _,
                          END_STREAM_FLAG | END_HEADERS_FLAG, 0));
  // Stream 1 is complete.
  EXPECT_CALL(server_visitor,
              OnCloseStream(stream_id1, Http2ErrorCode::HTTP2_NO_ERROR));

  EXPECT_EQ(0, server_adapter->Send());

  // Client visitor expectations on receive.
  // Server preface with initial SETTINGS.
  EXPECT_CALL(client_visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(client_visitor, OnSettingsStart());
  EXPECT_CALL(client_visitor,
              OnSetting(Http2Setting{
                  Http2KnownSettingsId::ENABLE_CONNECT_PROTOCOL, 1u}));
  EXPECT_CALL(client_visitor, OnSettingsEnd());
  // SETTINGS ack.
  EXPECT_CALL(client_visitor, OnFrameHeader(0, 0, SETTINGS, ACK_FLAG));
  EXPECT_CALL(client_visitor, OnSettingsAck());
  // Stream 1 response.
  EXPECT_CALL(client_visitor, OnFrameHeader(stream_id1, _, HEADERS, 5));
  EXPECT_CALL(client_visitor, OnBeginHeadersForStream(stream_id1));
  EXPECT_CALL(client_visitor, OnHeaderForStream(stream_id1, ":status", "200"));
  // Note that the Set-Cookie headers are delivered individually.
  EXPECT_CALL(client_visitor, OnHeaderForStream(stream_id1, "set-cookie",
                                                "chocolate_chip=yummy"));
  EXPECT_CALL(client_visitor, OnHeaderForStream(stream_id1, "set-cookie",
                                                "macadamia_nut=okay"));
  EXPECT_CALL(client_visitor, OnEndHeadersForStream(stream_id1));
  EXPECT_CALL(client_visitor, OnEndStream(stream_id1));
  EXPECT_CALL(client_visitor,
              OnCloseStream(stream_id1, Http2ErrorCode::HTTP2_NO_ERROR));

  // The client adapter processes the server's output.
  ASSERT_EQ(server_visitor.data().size(),
            client_adapter->ProcessBytes(server_visitor.data()));
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2

"""


```
Response:
Let's break down the request and the provided C++ code to fulfill the user's needs.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the C++ code located at `net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_stream_body_manager_test.cc`. Specifically, they are interested in:

* **Functionality:** What does this code *do*?
* **JavaScript Relevance:** Is there any connection to JavaScript?
* **Logic and Reasoning:** Can we infer behavior through examples with inputs and outputs?
* **Common Errors:** What mistakes do users or programmers make when using this (or related) code?
* **Debugging:** How does a user end up at this point in the code during debugging?

**2. Analyzing the C++ Code:**

* **Filename:** `quic_spdy_stream_body_manager_test.cc` strongly suggests this is a *test* file for a class named `QuicSpdyStreamBodyManager`. The "test.cc" suffix is a common convention.
* **Includes:** The included headers provide clues:
    * `<algorithm>`, `<numeric>`, `<string>`, `<vector>`: Standard C++ library components.
    * `"absl/base/macros.h"`, `"absl/strings/string_view.h"`:  Abseil library, likely used for utility functions and string handling.
    * `"quiche/quic/platform/api/quic_expect_bug.h"`, `"quiche/quic/platform/api/quic_logging.h"`, `"quiche/quic/platform/api/quic_test.h"`: QUIC-specific testing and logging infrastructure.
    * `"quiche/quic/core/http/quic_spdy_stream_body_manager.h"`: This confirms the class being tested.
* **Namespace:** The code resides in `quic::test`, indicating it's part of the QUIC library's testing framework.
* **Test Fixture:** The `QuicSpdyStreamBodyManagerTest` class inherits from `QuicTest`, setting up a testing environment. It contains a member `body_manager_` of type `QuicSpdyStreamBodyManager`.
* **Test Cases (using `TEST_F`):**  The code defines several test cases:
    * `HasBytesToRead`: Checks if the manager correctly identifies when there's data to read.
    * `ConsumeMoreThanAvailable`: Tests how the manager handles attempts to consume more data than available (expecting a QUIC bug).
    * `OnBodyConsumed`: Tests consuming data in various chunks.
    * `PeekBody`: Tests peeking at the data without consuming it.
    * `ReadBody`: Tests reading data into buffers.
    * `Clear`: Tests clearing the manager's internal state.
* **Assertions:** The tests use `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, and `EXPECT_QUIC_BUG` to verify expected behavior.

**3. Connecting to the User's Questions:**

* **Functionality:** This file tests the `QuicSpdyStreamBodyManager` class. This class is likely responsible for managing the body of an HTTP stream within the QUIC protocol. It handles receiving, storing, and providing access to the data.
* **JavaScript Relevance:**  QUIC is a transport protocol. JavaScript, in the context of web browsers, uses network protocols like HTTP over QUIC. While this *specific* C++ code isn't directly written in or executed by JavaScript, it's a crucial part of the underlying infrastructure that makes network communication possible for JavaScript applications. The browser's network stack (written in C++) implements QUIC, and this code is part of that.
* **Logic and Reasoning:** The test cases themselves provide excellent examples of input and expected output. We can elaborate on some of these.
* **Common Errors:**  The `ConsumeMoreThanAvailable` test explicitly demonstrates a common error: trying to read more data than is available.
* **Debugging:** We can construct a scenario where a developer would be looking at this code.

**4. Structuring the Response:**

Now, we can organize the information into a clear and helpful answer, addressing each point in the user's request. This involves:

* Starting with a concise summary of the file's purpose.
* Explaining the functionality of the `QuicSpdyStreamBodyManager` class based on the tests.
* Detailing the connection to JavaScript.
* Providing concrete examples of input and output based on the test cases.
* Illustrating common usage errors.
* Creating a debugging scenario.

**5. Refinement and Language:**

Finally, we review the generated response, ensuring it's clear, accurate, and uses appropriate technical terms. We make sure the examples are easy to understand and the debugging scenario is realistic. We also ensure the tone is helpful and informative. For example, instead of just saying "it manages the body", we can be more specific about actions like "receiving," "buffering," and "providing access to."
这个C++源代码文件 `quic_spdy_stream_body_manager_test.cc` 的主要功能是**测试 `QuicSpdyStreamBodyManager` 类的功能**。

`QuicSpdyStreamBodyManager` 类很可能负责**管理 QUIC (Quick UDP Internet Connections) 协议中 SPDY (Speedy) 流的 HTTP 消息体 (body) 部分**。  它处理接收到的消息体数据，并提供方法来读取、查看和管理这些数据。

下面列举一下该测试文件中测试的 `QuicSpdyStreamBodyManager` 的主要功能，以及与 JavaScript 的潜在关系、逻辑推理、常见错误和调试线索：

**`QuicSpdyStreamBodyManager` 的主要功能 (根据测试用例推断):**

* **`HasBytesToRead()`:** 检查是否还有未读取的消息体字节。
* **`ReadableBytes()`:** 返回当前可读取的消息体字节数。
* **`total_body_bytes_received()`:** 返回已接收到的消息体总字节数。
* **`OnNonBody(header_length)`:**  处理非消息体部分的数据，例如 HTTP 头部。返回可以立即处理的长度（通常是第一个帧的头部可以直接处理）。
* **`OnBody(body)`:** 接收并存储消息体数据。
* **`OnBodyConsumed(bytes)`:** 标记指定数量的字节已被消费/读取。
* **`PeekBody(iovecs, iov_len)`:** 查看消息体数据，但不实际消费/读取它们。使用 `iovec` 结构体来指定存储数据的缓冲区。
* **`ReadBody(iovecs, iov_len, total_bytes_read)`:** 读取消息体数据到指定的缓冲区。`iovec` 结构体用于指定多个不连续的缓冲区。
* **`Clear()`:** 清空消息体管理器，丢弃已接收但未读取的数据。

**与 JavaScript 的关系：**

虽然这个 C++ 文件本身不是 JavaScript 代码，但它所测试的 `QuicSpdyStreamBodyManager` 类是 Chromium 网络栈的一部分，而 Chromium 是 Chrome 浏览器和 Node.js 等 JavaScript 运行环境的基础。

* **浏览器中的网络请求:** 当 JavaScript 代码在浏览器中发起一个使用 HTTP/3 (基于 QUIC) 的网络请求时，浏览器底层的网络栈（用 C++ 实现）会处理 QUIC 连接的建立、数据传输等。`QuicSpdyStreamBodyManager` 就参与了接收和管理服务器返回的 HTTP 响应体。
* **Node.js 中的网络请求:**  Node.js 的 `http` 或 `https` 模块底层也可能使用类似的网络栈来实现 HTTP/3 支持。如果 Node.js 应用通过 HTTP/3 接收数据，那么类似的 C++ 代码会在底层处理消息体的接收。

**举例说明：**

假设一个 JavaScript 代码发起了一个 HTTP GET 请求，服务器返回一个包含 JSON 数据的响应体：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中，底层的 C++ `QuicSpdyStreamBodyManager` 可能参与如下：

1. **接收数据:**  服务器发送的 HTTP 响应体数据（JSON 字符串）会被 QUIC 协议分片传输。`QuicSpdyStreamBodyManager::OnBody()` 会被调用多次，接收这些数据片段。
2. **缓冲数据:** 接收到的数据会被 `QuicSpdyStreamBodyManager` 缓存起来。
3. **提供读取:** 当 JavaScript 调用 `response.json()` 时，底层的 C++ 代码会通过类似 `QuicSpdyStreamBodyManager::ReadBody()` 的方法，将缓存的 JSON 数据提供给 JavaScript 解析器。

**逻辑推理 (假设输入与输出):**

**假设输入：**

1. **`OnNonBody(3)`:**  接收到 3 字节的头部信息。
2. **`OnBody("hello")`:** 接收到字符串 "hello" 作为消息体。
3. **`OnBody("world")`:** 接收到字符串 "world" 作为消息体的后续部分。
4. **`OnBodyConsumed(5)`:**  标记前 5 个字节已被读取。

**预期输出：**

*   在 `OnNonBody(3)` 之后，`HasBytesToRead()` 为 `false`，`ReadableBytes()` 为 `0`。
*   在第一个 `OnBody("hello")` 之后，`HasBytesToRead()` 为 `true`，`ReadableBytes()` 为 `5`，`total_body_bytes_received()` 为 `5`。
*   在第二个 `OnBody("world")` 之后，`HasBytesToRead()` 为 `true`，`ReadableBytes()` 为 `10`，`total_body_bytes_received()` 为 `10`。
*   在 `OnBodyConsumed(5)` 之后，`HasBytesToRead()` 为 `true`，`ReadableBytes()` 为 `5`。如果之后调用 `ReadBody` 读取数据，会返回 "world"。

**涉及用户或者编程常见的使用错误：**

* **读取超过可用字节数:**  `TEST_F(QuicSpdyStreamBodyManagerTest, ConsumeMoreThanAvailable)`  测试了这种情况。如果用户（或者代码中的逻辑）尝试调用 `OnBodyConsumed` 或 `ReadBody` 读取超过当前可用的字节数，可能会导致程序错误或未定义的行为。在测试代码中，使用了 `EXPECT_QUIC_BUG` 来预期这种错误。

    **例子:**  假设接收到 5 字节的消息体，但错误地调用了 `body_manager_.OnBodyConsumed(10)`. 这会触发一个 "Not enough available body to consume." 的错误。

* **未正确处理 `iovec`:** 在使用 `PeekBody` 或 `ReadBody` 时，如果提供的 `iovec` 结构体配置不正确（例如，指向无效的内存区域，或者指定的长度超出缓冲区大小），会导致程序崩溃或其他内存错误。

* **在数据完全接收前尝试读取:**  如果在消息体尚未完全接收完成时就尝试读取数据，可能会读取到不完整的数据。应用程序需要根据协议或上下文来判断何时消息体接收完成。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

假设开发者正在调试一个 Chrome 浏览器中，使用 HTTP/3 请求某个大型文件时遇到的下载问题。可能的调试步骤如下：

1. **用户在 Chrome 浏览器中访问一个 URL，该 URL 的服务器支持 HTTP/3。**
2. **Chrome 的网络栈尝试建立 QUIC 连接。**
3. **连接建立成功后，浏览器发送 HTTP/3 请求。**
4. **服务器开始返回 HTTP 响应，包括头部和消息体数据。**
5. **Chromium 网络栈中的 QUIC 实现接收到来自服务器的数据包。**
6. **这些数据包被解析，属于特定 HTTP 流的消息体部分的数据会被传递给 `QuicSpdyStreamBodyManager` 实例。**  此时，可能会调用 `OnBody()` 来添加接收到的数据。
7. **在接收消息体的过程中，可能出现各种问题，例如数据包丢失、乱序、连接中断等。**
8. **开发者可能注意到下载速度异常缓慢，或者下载的文件不完整。**
9. **开发者可能会使用 Chrome 的 `chrome://net-internals/#quic` 工具来查看 QUIC 连接的详细信息，包括流的状态、接收到的字节数等。**
10. **如果怀疑是消息体管理部分出了问题，开发者可能会在 Chromium 的源代码中设置断点，例如在 `quic_spdy_stream_body_manager_test.cc` 文件中的测试用例中，或者在 `QuicSpdyStreamBodyManager` 类的 `OnBody`、`ReadBody` 等方法中。**
11. **通过单步调试，开发者可以观察 `QuicSpdyStreamBodyManager` 是如何接收、存储和提供消息体数据的，以及在出现问题时，内部状态的变化。** 例如，他们可能会检查 `ReadableBytes()` 的值是否符合预期，或者在调用 `ReadBody` 时，读取到的数据是否正确。
12. **如果 `ConsumeMoreThanAvailable` 测试用例中的断言被触发，可能意味着代码中存在尝试读取过多数据的逻辑错误。**

总而言之，`quic_spdy_stream_body_manager_test.cc` 是 QUIC 协议 HTTP/3 实现中非常重要的一个测试文件，它确保了消息体管理的核心逻辑的正确性，这对于浏览器和依赖 Chromium 网络栈的应用（包括 JavaScript 运行环境）的稳定可靠运行至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_stream_body_manager_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/quic_spdy_stream_body_manager.h"

#include <algorithm>
#include <numeric>
#include <string>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace quic {

namespace test {

namespace {

class QuicSpdyStreamBodyManagerTest : public QuicTest {
 protected:
  QuicSpdyStreamBodyManager body_manager_;
};

TEST_F(QuicSpdyStreamBodyManagerTest, HasBytesToRead) {
  EXPECT_FALSE(body_manager_.HasBytesToRead());
  EXPECT_EQ(body_manager_.ReadableBytes(), 0u);
  EXPECT_EQ(0u, body_manager_.total_body_bytes_received());

  const QuicByteCount header_length = 3;
  EXPECT_EQ(header_length, body_manager_.OnNonBody(header_length));

  EXPECT_FALSE(body_manager_.HasBytesToRead());
  EXPECT_EQ(body_manager_.ReadableBytes(), 0u);
  EXPECT_EQ(0u, body_manager_.total_body_bytes_received());

  std::string body(1024, 'a');
  body_manager_.OnBody(body);

  EXPECT_TRUE(body_manager_.HasBytesToRead());
  EXPECT_EQ(body_manager_.ReadableBytes(), 1024u);
  EXPECT_EQ(1024u, body_manager_.total_body_bytes_received());
}

TEST_F(QuicSpdyStreamBodyManagerTest, ConsumeMoreThanAvailable) {
  std::string body(1024, 'a');
  body_manager_.OnBody(body);
  size_t bytes_to_consume = 0;
  EXPECT_QUIC_BUG(bytes_to_consume = body_manager_.OnBodyConsumed(2048),
                  "Not enough available body to consume.");
  EXPECT_EQ(0u, bytes_to_consume);
}

TEST_F(QuicSpdyStreamBodyManagerTest, OnBodyConsumed) {
  struct {
    std::vector<QuicByteCount> frame_header_lengths;
    std::vector<const char*> frame_payloads;
    std::vector<QuicByteCount> body_bytes_to_read;
    std::vector<QuicByteCount> expected_return_values;
  } const kOnBodyConsumedTestData[] = {
      // One frame consumed in one call.
      {{2}, {"foobar"}, {6}, {6}},
      // Two frames consumed in one call.
      {{3, 5}, {"foobar", "baz"}, {9}, {14}},
      // One frame consumed in two calls.
      {{2}, {"foobar"}, {4, 2}, {4, 2}},
      // Two frames consumed in two calls matching frame boundaries.
      {{3, 5}, {"foobar", "baz"}, {6, 3}, {11, 3}},
      // Two frames consumed in two calls,
      // the first call only consuming part of the first frame.
      {{3, 5}, {"foobar", "baz"}, {5, 4}, {5, 9}},
      // Two frames consumed in two calls,
      // the first call consuming the entire first frame and part of the second.
      {{3, 5}, {"foobar", "baz"}, {7, 2}, {12, 2}},
  };

  for (size_t test_case_index = 0;
       test_case_index < ABSL_ARRAYSIZE(kOnBodyConsumedTestData);
       ++test_case_index) {
    const std::vector<QuicByteCount>& frame_header_lengths =
        kOnBodyConsumedTestData[test_case_index].frame_header_lengths;
    const std::vector<const char*>& frame_payloads =
        kOnBodyConsumedTestData[test_case_index].frame_payloads;
    const std::vector<QuicByteCount>& body_bytes_to_read =
        kOnBodyConsumedTestData[test_case_index].body_bytes_to_read;
    const std::vector<QuicByteCount>& expected_return_values =
        kOnBodyConsumedTestData[test_case_index].expected_return_values;

    for (size_t frame_index = 0; frame_index < frame_header_lengths.size();
         ++frame_index) {
      // Frame header of first frame can immediately be consumed, but not the
      // other frames.  Each test case start with an empty
      // QuicSpdyStreamBodyManager.
      EXPECT_EQ(frame_index == 0 ? frame_header_lengths[frame_index] : 0u,
                body_manager_.OnNonBody(frame_header_lengths[frame_index]));
      body_manager_.OnBody(frame_payloads[frame_index]);
    }

    for (size_t call_index = 0; call_index < body_bytes_to_read.size();
         ++call_index) {
      EXPECT_EQ(expected_return_values[call_index],
                body_manager_.OnBodyConsumed(body_bytes_to_read[call_index]));
    }

    EXPECT_FALSE(body_manager_.HasBytesToRead());
    EXPECT_EQ(body_manager_.ReadableBytes(), 0u);
  }
}

TEST_F(QuicSpdyStreamBodyManagerTest, PeekBody) {
  struct {
    std::vector<QuicByteCount> frame_header_lengths;
    std::vector<const char*> frame_payloads;
    size_t iov_len;
  } const kPeekBodyTestData[] = {
      // No frames, more iovecs than frames.
      {{}, {}, 1},
      // One frame, same number of iovecs.
      {{3}, {"foobar"}, 1},
      // One frame, more iovecs than frames.
      {{3}, {"foobar"}, 2},
      // Two frames, fewer iovecs than frames.
      {{3, 5}, {"foobar", "baz"}, 1},
      // Two frames, same number of iovecs.
      {{3, 5}, {"foobar", "baz"}, 2},
      // Two frames, more iovecs than frames.
      {{3, 5}, {"foobar", "baz"}, 3},
  };

  for (size_t test_case_index = 0;
       test_case_index < ABSL_ARRAYSIZE(kPeekBodyTestData); ++test_case_index) {
    const std::vector<QuicByteCount>& frame_header_lengths =
        kPeekBodyTestData[test_case_index].frame_header_lengths;
    const std::vector<const char*>& frame_payloads =
        kPeekBodyTestData[test_case_index].frame_payloads;
    size_t iov_len = kPeekBodyTestData[test_case_index].iov_len;

    QuicSpdyStreamBodyManager body_manager;

    for (size_t frame_index = 0; frame_index < frame_header_lengths.size();
         ++frame_index) {
      // Frame header of first frame can immediately be consumed, but not the
      // other frames.  Each test case uses a new QuicSpdyStreamBodyManager
      // instance.
      EXPECT_EQ(frame_index == 0 ? frame_header_lengths[frame_index] : 0u,
                body_manager.OnNonBody(frame_header_lengths[frame_index]));
      body_manager.OnBody(frame_payloads[frame_index]);
    }

    std::vector<iovec> iovecs;
    iovecs.resize(iov_len);
    size_t iovs_filled = std::min(frame_payloads.size(), iov_len);
    ASSERT_EQ(iovs_filled,
              static_cast<size_t>(body_manager.PeekBody(&iovecs[0], iov_len)));
    for (size_t iovec_index = 0; iovec_index < iovs_filled; ++iovec_index) {
      EXPECT_EQ(frame_payloads[iovec_index],
                absl::string_view(
                    static_cast<const char*>(iovecs[iovec_index].iov_base),
                    iovecs[iovec_index].iov_len));
    }
  }
}

TEST_F(QuicSpdyStreamBodyManagerTest, ReadBody) {
  struct {
    std::vector<QuicByteCount> frame_header_lengths;
    std::vector<const char*> frame_payloads;
    std::vector<std::vector<QuicByteCount>> iov_lengths;
    std::vector<QuicByteCount> expected_total_bytes_read;
    std::vector<QuicByteCount> expected_return_values;
  } const kReadBodyTestData[] = {
      // One frame, one read with smaller iovec.
      {{4}, {"foo"}, {{2}}, {2}, {2}},
      // One frame, one read with same size iovec.
      {{4}, {"foo"}, {{3}}, {3}, {3}},
      // One frame, one read with larger iovec.
      {{4}, {"foo"}, {{5}}, {3}, {3}},
      // One frame, one read with two iovecs, smaller total size.
      {{4}, {"foobar"}, {{2, 3}}, {5}, {5}},
      // One frame, one read with two iovecs, same total size.
      {{4}, {"foobar"}, {{2, 4}}, {6}, {6}},
      // One frame, one read with two iovecs, larger total size in last iovec.
      {{4}, {"foobar"}, {{2, 6}}, {6}, {6}},
      // One frame, one read with extra iovecs, body ends at iovec boundary.
      {{4}, {"foobar"}, {{2, 4, 4, 3}}, {6}, {6}},
      // One frame, one read with extra iovecs, body ends not at iovec boundary.
      {{4}, {"foobar"}, {{2, 7, 4, 3}}, {6}, {6}},
      // One frame, two reads with two iovecs each, smaller total size.
      {{4}, {"foobarbaz"}, {{2, 1}, {3, 2}}, {3, 5}, {3, 5}},
      // One frame, two reads with two iovecs each, same total size.
      {{4}, {"foobarbaz"}, {{2, 1}, {4, 2}}, {3, 6}, {3, 6}},
      // One frame, two reads with two iovecs each, larger total size.
      {{4}, {"foobarbaz"}, {{2, 1}, {4, 10}}, {3, 6}, {3, 6}},
      // Two frames, one read with smaller iovec.
      {{4, 3}, {"foobar", "baz"}, {{8}}, {8}, {11}},
      // Two frames, one read with same size iovec.
      {{4, 3}, {"foobar", "baz"}, {{9}}, {9}, {12}},
      // Two frames, one read with larger iovec.
      {{4, 3}, {"foobar", "baz"}, {{10}}, {9}, {12}},
      // Two frames, one read with two iovecs, smaller total size.
      {{4, 3}, {"foobar", "baz"}, {{4, 3}}, {7}, {10}},
      // Two frames, one read with two iovecs, same total size.
      {{4, 3}, {"foobar", "baz"}, {{4, 5}}, {9}, {12}},
      // Two frames, one read with two iovecs, larger total size in last iovec.
      {{4, 3}, {"foobar", "baz"}, {{4, 6}}, {9}, {12}},
      // Two frames, one read with extra iovecs, body ends at iovec boundary.
      {{4, 3}, {"foobar", "baz"}, {{4, 6, 4, 3}}, {9}, {12}},
      // Two frames, one read with extra iovecs, body ends not at iovec
      // boundary.
      {{4, 3}, {"foobar", "baz"}, {{4, 7, 4, 3}}, {9}, {12}},
      // Two frames, two reads with two iovecs each, reads end on frame
      // boundary.
      {{4, 3}, {"foobar", "baz"}, {{2, 4}, {2, 1}}, {6, 3}, {9, 3}},
      // Three frames, three reads, extra iovecs, no iovec ends on frame
      // boundary.
      {{4, 3, 6},
       {"foobar", "bazquux", "qux"},
       {{4, 3}, {2, 3}, {5, 3}},
       {7, 5, 4},
       {10, 5, 10}},
  };

  for (size_t test_case_index = 0;
       test_case_index < ABSL_ARRAYSIZE(kReadBodyTestData); ++test_case_index) {
    const std::vector<QuicByteCount>& frame_header_lengths =
        kReadBodyTestData[test_case_index].frame_header_lengths;
    const std::vector<const char*>& frame_payloads =
        kReadBodyTestData[test_case_index].frame_payloads;
    const std::vector<std::vector<QuicByteCount>>& iov_lengths =
        kReadBodyTestData[test_case_index].iov_lengths;
    const std::vector<QuicByteCount>& expected_total_bytes_read =
        kReadBodyTestData[test_case_index].expected_total_bytes_read;
    const std::vector<QuicByteCount>& expected_return_values =
        kReadBodyTestData[test_case_index].expected_return_values;

    QuicSpdyStreamBodyManager body_manager;

    std::string received_body;

    for (size_t frame_index = 0; frame_index < frame_header_lengths.size();
         ++frame_index) {
      // Frame header of first frame can immediately be consumed, but not the
      // other frames.  Each test case uses a new QuicSpdyStreamBodyManager
      // instance.
      EXPECT_EQ(frame_index == 0 ? frame_header_lengths[frame_index] : 0u,
                body_manager.OnNonBody(frame_header_lengths[frame_index]));
      body_manager.OnBody(frame_payloads[frame_index]);
      received_body.append(frame_payloads[frame_index]);
    }

    std::string read_body;

    for (size_t call_index = 0; call_index < iov_lengths.size(); ++call_index) {
      // Allocate single buffer for iovecs.
      size_t total_iov_length = std::accumulate(iov_lengths[call_index].begin(),
                                                iov_lengths[call_index].end(),
                                                static_cast<size_t>(0));
      std::string buffer(total_iov_length, 'z');

      // Construct iovecs pointing to contiguous areas in the buffer.
      std::vector<iovec> iovecs;
      size_t offset = 0;
      for (size_t iov_length : iov_lengths[call_index]) {
        QUICHE_CHECK(offset + iov_length <= buffer.size());
        iovecs.push_back({&buffer[offset], iov_length});
        offset += iov_length;
      }

      // Make sure |total_bytes_read| differs from |expected_total_bytes_read|.
      size_t total_bytes_read = expected_total_bytes_read[call_index] + 12;
      EXPECT_EQ(
          expected_return_values[call_index],
          body_manager.ReadBody(&iovecs[0], iovecs.size(), &total_bytes_read));
      read_body.append(buffer.substr(0, total_bytes_read));
    }

    EXPECT_EQ(received_body.substr(0, read_body.size()), read_body);
    EXPECT_EQ(read_body.size() < received_body.size(),
              body_manager.HasBytesToRead());
  }
}

TEST_F(QuicSpdyStreamBodyManagerTest, Clear) {
  const QuicByteCount header_length = 3;
  EXPECT_EQ(header_length, body_manager_.OnNonBody(header_length));

  std::string body("foo");
  body_manager_.OnBody(body);

  EXPECT_TRUE(body_manager_.HasBytesToRead());

  body_manager_.Clear();

  EXPECT_FALSE(body_manager_.HasBytesToRead());

  iovec iov;
  size_t total_bytes_read = 5;
  EXPECT_EQ(0, body_manager_.PeekBody(&iov, 1));
  EXPECT_EQ(0u, body_manager_.ReadBody(&iov, 1, &total_bytes_read));
}

}  // anonymous namespace

}  // namespace test

}  // namespace quic

"""

```
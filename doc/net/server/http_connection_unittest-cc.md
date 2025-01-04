Response:
Let's break down the thought process for analyzing the `http_connection_unittest.cc` file.

1. **Understand the Core Purpose:** The filename `http_connection_unittest.cc` immediately tells us this is a unit test file for something related to `HttpConnection`. The `.cc` extension indicates C++ code. The `_unittest` suffix is a common convention for unit test files.

2. **Identify Key Classes Under Test:**  Scanning the `#include` statements reveals the primary class being tested: `net/server/http_connection.h`. Deeper within the code, the test names and the instantiation of objects like `HttpConnection::ReadIOBuffer` and `HttpConnection::QueuedWriteIOBuffer` confirm these are the specific components being tested.

3. **Analyze Individual Tests:** Go through each `TEST` block systematically. For each test:
    * **Understand the Test Name:** The test name (e.g., `ReadIOBuffer_SetCapacity`) provides a high-level idea of what's being tested.
    * **Identify the Actions:** Look for the key methods being called on the objects under test (e.g., `SetCapacity`, `IncreaseCapacity`, `DidRead`, `DidConsume`, `Append`).
    * **Identify the Assertions:**  The `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE` statements are crucial. They define the expected behavior of the methods being tested. These are the core of the test logic.
    * **Infer the Functionality:** Based on the actions and assertions, deduce the functionality being validated. For example, `ReadIOBuffer_SetCapacity` is testing the ability to change the buffer's capacity, and the assertions verify the capacity is updated correctly.

4. **Look for Patterns and Common Themes:** Notice that several tests focus on `ReadIOBuffer` and `QueuedWriteIOBuffer`. Recognize that these likely represent different ways of managing data associated with an HTTP connection (reading and writing). Observe the consistent use of `scoped_refptr` for memory management.

5. **Address Specific Requirements of the Prompt:** Now, specifically address each part of the prompt:

    * **Functionality Listing:**  Summarize the purpose of each test into a concise list of functionalities. Group related tests together (e.g., all `ReadIOBuffer` tests).

    * **Relationship to JavaScript:**  Think about how HTTP connections are used in a web browser environment where JavaScript plays a central role. Consider:
        * Fetch API:  JavaScript uses `fetch` to make HTTP requests. The `HttpConnection` on the server side handles these requests.
        * WebSockets:  While this specific file doesn't directly test WebSockets, the underlying concepts of managing data flow are similar.
        * Server-Sent Events (SSE): Similar to WebSockets, SSE relies on HTTP for unidirectional communication.

    * **Logic Reasoning (Hypothetical Input/Output):** For a simple test like `ReadIOBuffer_SetCapacity`, create a scenario:
        * **Input:**  A `ReadIOBuffer` object, a desired new capacity (e.g., 256).
        * **Action:** Call `SetCapacity(256)`.
        * **Output:** Assert that `GetCapacity()` returns 256.

    * **User/Programming Errors:** Think about common mistakes developers might make when working with buffers or network connections:
        * Incorrect buffer sizes.
        * Not handling data consumption correctly.
        * Exceeding buffer limits.

    * **User Operations and Debugging:**  Trace the user's actions that might lead to this code being executed on the server:
        * User types a URL and hits enter.
        * JavaScript `fetch` calls.
        * Form submissions.
        * Opening a WebSocket connection.
        * Receiving SSE.
        Then, consider debugging scenarios: how would a developer know they need to look at `HttpConnection` code?  Think about server-side logging, network inspection tools, and breakpoints.

6. **Structure and Refine:** Organize the findings into a clear and readable format. Use headings and bullet points for better presentation. Ensure the language is precise and avoids jargon where possible. For example, instead of just saying "buffer manipulation," be more specific, like "testing setting the capacity of the read buffer."

7. **Review and Verify:**  Read through the analysis to ensure accuracy and completeness. Double-check the interpretations of the test cases and the connections to JavaScript and user behavior.

**Self-Correction Example During the Process:**

Initially, I might just list the test names as the functionalities. However, on review, I realize that's too granular. I should group related tests under broader functional categories, like "Testing setting the capacity of the read buffer" encompassing both `ReadIOBuffer_SetCapacity` and `ReadIOBuffer_SetCapacity_WithData`. This provides a higher-level understanding of what the file is doing. Similarly, when thinking about JavaScript, I might initially focus only on `fetch`. But then, I'd broaden the scope to include other relevant web technologies that utilize HTTP.
这个文件 `net/server/http_connection_unittest.cc` 是 Chromium 网络栈中用于测试 `net::HttpConnection` 及其相关辅助类功能的单元测试文件。它的主要目的是确保 `HttpConnection` 及其组件（如 `ReadIOBuffer` 和 `QueuedWriteIOBuffer`）按照预期工作，处理各种边缘情况，并防止引入 bug。

以下是该文件的功能列表：

1. **测试 `HttpConnection::ReadIOBuffer` 的功能:**
   - **设置容量 (`SetCapacity`)**: 验证能否正确设置读缓冲区的容量，包括初始状态和已写入数据后的状态。
   - **增加容量 (`IncreaseCapacity`)**: 测试动态增加读缓冲区容量的机制，包括达到最大容量限制的情况，以及调整最大容量限制后的行为。
   - **读取数据 (`DidRead`)**: 模拟从网络读取数据到缓冲区，并验证缓冲区的状态（已读大小、剩余容量等）是否正确更新。
   - **消费数据 (`DidConsume`)**: 模拟处理或消费缓冲区中的数据，并验证缓冲区状态的更新，以及在消费后容量的可能缩减行为。
   - **读取和消费的组合测试 (`ReadIOBuffer_DidRead_DidConsume`)**: 综合测试读取和消费数据后缓冲区的状态变化，包括容量缩减、起始指针的移动等。

2. **测试 `HttpConnection::QueuedWriteIOBuffer` 的功能:**
   - **追加数据 (`Append`)**: 测试向写入缓冲区队列中添加数据的功能，验证添加后缓冲区的大小和内容。
   - **消费数据 (`DidConsume`)**: 测试从写入缓冲区队列中消费（发送）数据的功能，验证消费后缓冲区的大小和内容变化。
   - **追加和消费的组合测试 (`QueuedWriteIOBuffer_Append_DidConsume`)**: 综合测试追加和消费数据后缓冲区的状态变化。
   - **最大总大小限制 (`TotalSizeLimit`)**: 验证写入缓冲区队列的最大大小限制功能，以及超出限制时的行为。
   - **数据指针稳定性 (`DataPointerStability`)**:  这是一个回归测试，确保在添加和消费数据后，指向缓冲区数据的指针仍然有效和稳定，特别是在底层队列调整内存布局时。

**与 JavaScript 功能的关系：**

这个文件直接测试的是服务器端的 C++ 代码，但它所测试的功能是 HTTP 连接的基础，而 HTTP 连接是 Web 浏览器（运行 JavaScript 代码）与服务器通信的核心机制。

**举例说明：**

当 JavaScript 代码使用 `fetch` API 发起一个 HTTP 请求时，浏览器底层会建立一个 HTTP 连接。服务器端的 `HttpConnection` 类负责处理这个连接上的数据接收和发送。

- **`HttpConnection::ReadIOBuffer`**:  当服务器接收到来自浏览器的请求数据（例如，请求头、请求体）时，数据会被读取到 `ReadIOBuffer` 中。JavaScript 的 `fetch` API 的请求体数据最终会通过网络到达服务器，并被读取到这个缓冲区中。
- **`HttpConnection::QueuedWriteIOBuffer`**: 当服务器需要向浏览器发送响应数据（例如，响应头、响应体）时，这些数据会被添加到 `QueuedWriteIOBuffer` 中，然后通过网络发送回浏览器。JavaScript 的 `fetch` API 接收到的响应数据，就是服务器通过这个缓冲区发送过来的。

**逻辑推理 (假设输入与输出)：**

**示例 1: `HttpConnectionTest.ReadIOBuffer_SetCapacity`**

* **假设输入:**
    * 创建了一个 `HttpConnection::ReadIOBuffer` 对象。
    * 调用 `SetCapacity(256)`。
* **预期输出:**
    * `buffer->GetCapacity()` 返回 256。
    * `buffer->RemainingCapacity()` 返回 256。
    * `buffer->GetSize()` 返回 0。

**示例 2: `HttpConnectionTest.QueuedWriteIOBuffer_Append_DidConsume`**

* **假设输入:**
    * 创建了一个 `HttpConnection::QueuedWriteIOBuffer` 对象。
    * 调用 `Append("hello")`。
    * 调用 `DidConsume(2)`。
* **预期输出:**
    * `buffer->GetSizeToWrite()` 返回 3 ("llo"的长度)。
    * `buffer->total_size()` 返回 3。
    * `std::string_view(buffer->data(), buffer->GetSizeToWrite())` 的内容是 "llo"。

**涉及用户或编程常见的使用错误：**

1. **缓冲区溢出 (可能由 `ReadIOBuffer`引起):**
   * **错误:** 假设服务器在处理接收到的数据时，没有正确检查 `ReadIOBuffer` 中数据的实际大小，而是盲目地读取超过实际大小的数据。
   * **用户操作:** 用户发送一个非常大的 HTTP 请求体，而服务器端的代码没有正确处理分块传输或限制请求体大小，导致尝试写入超过缓冲区容量的数据。
   * **后果:** 可能导致程序崩溃、安全漏洞等。

2. **写入缓冲区超出限制 (由 `QueuedWriteIOBuffer`引起):**
   * **错误:** 服务器端尝试向 `QueuedWriteIOBuffer` 中添加过多的数据，超出了其设置的最大容量限制。
   * **用户操作:**  服务器端尝试发送一个非常大的 HTTP 响应，而 `QueuedWriteIOBuffer` 的最大容量设置过小。
   * **后果:** `Append` 操作会失败，导致响应发送不完整或失败。

3. **未正确消费缓冲区数据:**
   * **错误:** 在处理完 `ReadIOBuffer` 或 `QueuedWriteIOBuffer` 中的数据后，没有调用 `DidConsume` 来更新缓冲区的状态。
   * **后果:**  对于 `ReadIOBuffer`，可能导致后续读取操作从错误的位置开始。对于 `QueuedWriteIOBuffer`，可能导致重复发送数据或内存泄漏。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在使用浏览器访问一个网页时遇到了问题，可能导致开发人员需要调试服务器端的 `HttpConnection` 代码：

1. **用户在浏览器地址栏输入 URL 并按下回车，或者点击了一个链接。**
2. **浏览器解析 URL，并尝试与服务器建立 TCP 连接。**
3. **TCP 连接建立后，浏览器发送 HTTP 请求（可能是 GET 或 POST 请求）。**
4. **请求数据通过网络传输到达服务器。**
5. **服务器的网络层接收到数据，并将其传递给 `HttpConnection` 对象进行处理。**
6. **`HttpConnection` 对象使用 `ReadIOBuffer` 来接收和存储请求的数据（请求头、请求体）。**
7. **服务器的业务逻辑处理请求，并生成 HTTP 响应。**
8. **响应数据被添加到 `HttpConnection` 对象的 `QueuedWriteIOBuffer` 中。**
9. **`HttpConnection` 对象将 `QueuedWriteIOBuffer` 中的数据发送回浏览器。**
10. **浏览器接收到响应数据，并渲染网页。**

**调试线索:**

如果在上述过程中出现问题，例如：

* **请求数据不完整或丢失:**  可能与 `ReadIOBuffer` 的读取逻辑或容量管理有关。
* **服务器响应发送失败或不完整:** 可能与 `QueuedWriteIOBuffer` 的追加、消费或最大容量限制有关。
* **性能问题:**  频繁的缓冲区扩容或内存拷贝可能导致性能下降，需要检查 `IncreaseCapacity` 的逻辑。

当开发人员怀疑是 HTTP 连接层面的问题时，他们可能会：

* **查看服务器端的日志:** 查找与连接处理、数据接收/发送相关的错误信息。
* **使用网络抓包工具 (如 Wireshark):**  检查客户端和服务器之间实际传输的 HTTP 数据，对比预期的数据。
* **在服务器端代码中设置断点:**  在 `HttpConnection` 及其相关类的关键方法（如 `DidRead`, `DidConsume`, `Append`, `SetCapacity`, `IncreaseCapacity`）设置断点，观察缓冲区的状态变化，验证数据流是否按预期进行。

因此，`http_connection_unittest.cc` 文件中的测试用例正是为了覆盖这些关键路径和边界情况，帮助开发人员在开发阶段就发现潜在的问题，确保 `HttpConnection` 的稳定性和正确性。

Prompt: 
```
这是目录为net/server/http_connection_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/server/http_connection.h"

#include <string>
#include <string_view>

#include "base/memory/ref_counted.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

std::string GetTestString(int size) {
  std::string test_string;
  for (int i = 0; i < size; ++i) {
    test_string.push_back('A' + (i % 26));
  }
  return test_string;
}

TEST(HttpConnectionTest, ReadIOBuffer_SetCapacity) {
  scoped_refptr<HttpConnection::ReadIOBuffer> buffer =
      base::MakeRefCounted<HttpConnection::ReadIOBuffer>();
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kInitialBufSize + 0,
            buffer->GetCapacity());
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kInitialBufSize + 0,
            buffer->RemainingCapacity());
  EXPECT_EQ(0, buffer->GetSize());

  const int kNewCapacity = HttpConnection::ReadIOBuffer::kInitialBufSize + 128;
  buffer->SetCapacity(kNewCapacity);
  EXPECT_EQ(kNewCapacity, buffer->GetCapacity());
  EXPECT_EQ(kNewCapacity, buffer->RemainingCapacity());
  EXPECT_EQ(0, buffer->GetSize());
}

TEST(HttpConnectionTest, ReadIOBuffer_SetCapacity_WithData) {
  scoped_refptr<HttpConnection::ReadIOBuffer> buffer =
      base::MakeRefCounted<HttpConnection::ReadIOBuffer>();
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kInitialBufSize + 0,
            buffer->GetCapacity());
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kInitialBufSize + 0,
            buffer->RemainingCapacity());

  // Write arbitrary data up to kInitialBufSize.
  const std::string kReadData(
      GetTestString(HttpConnection::ReadIOBuffer::kInitialBufSize));
  memcpy(buffer->data(), kReadData.data(), kReadData.size());
  buffer->DidRead(kReadData.size());
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kInitialBufSize + 0,
            buffer->GetCapacity());
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kInitialBufSize -
                static_cast<int>(kReadData.size()),
            buffer->RemainingCapacity());
  EXPECT_EQ(static_cast<int>(kReadData.size()), buffer->GetSize());
  EXPECT_EQ(kReadData,
            std::string_view(buffer->StartOfBuffer(), buffer->GetSize()));

  // Check if read data in the buffer is same after SetCapacity().
  const int kNewCapacity = HttpConnection::ReadIOBuffer::kInitialBufSize + 128;
  buffer->SetCapacity(kNewCapacity);
  EXPECT_EQ(kNewCapacity, buffer->GetCapacity());
  EXPECT_EQ(kNewCapacity - static_cast<int>(kReadData.size()),
            buffer->RemainingCapacity());
  EXPECT_EQ(static_cast<int>(kReadData.size()), buffer->GetSize());
  EXPECT_EQ(kReadData,
            std::string_view(buffer->StartOfBuffer(), buffer->GetSize()));
}

TEST(HttpConnectionTest, ReadIOBuffer_IncreaseCapacity) {
  scoped_refptr<HttpConnection::ReadIOBuffer> buffer =
      base::MakeRefCounted<HttpConnection::ReadIOBuffer>();
  EXPECT_TRUE(buffer->IncreaseCapacity());
  const int kExpectedInitialBufSize =
      HttpConnection::ReadIOBuffer::kInitialBufSize *
      HttpConnection::ReadIOBuffer::kCapacityIncreaseFactor;
  EXPECT_EQ(kExpectedInitialBufSize, buffer->GetCapacity());
  EXPECT_EQ(kExpectedInitialBufSize, buffer->RemainingCapacity());
  EXPECT_EQ(0, buffer->GetSize());

  // Increase capacity until it fails.
  while (buffer->IncreaseCapacity());
  EXPECT_FALSE(buffer->IncreaseCapacity());
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kDefaultMaxBufferSize + 0,
            buffer->max_buffer_size());
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kDefaultMaxBufferSize + 0,
            buffer->GetCapacity());

  // Enlarge capacity limit.
  buffer->set_max_buffer_size(buffer->max_buffer_size() * 2);
  EXPECT_TRUE(buffer->IncreaseCapacity());
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kDefaultMaxBufferSize *
                HttpConnection::ReadIOBuffer::kCapacityIncreaseFactor,
            buffer->GetCapacity());

  // Shrink capacity limit. It doesn't change capacity itself.
  buffer->set_max_buffer_size(
      HttpConnection::ReadIOBuffer::kDefaultMaxBufferSize / 2);
  EXPECT_FALSE(buffer->IncreaseCapacity());
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kDefaultMaxBufferSize *
                HttpConnection::ReadIOBuffer::kCapacityIncreaseFactor,
            buffer->GetCapacity());
}

TEST(HttpConnectionTest, ReadIOBuffer_IncreaseCapacity_WithData) {
  scoped_refptr<HttpConnection::ReadIOBuffer> buffer =
      base::MakeRefCounted<HttpConnection::ReadIOBuffer>();
  EXPECT_TRUE(buffer->IncreaseCapacity());
  const int kExpectedInitialBufSize =
      HttpConnection::ReadIOBuffer::kInitialBufSize *
      HttpConnection::ReadIOBuffer::kCapacityIncreaseFactor;
  EXPECT_EQ(kExpectedInitialBufSize, buffer->GetCapacity());
  EXPECT_EQ(kExpectedInitialBufSize, buffer->RemainingCapacity());
  EXPECT_EQ(0, buffer->GetSize());

  // Write arbitrary data up to kExpectedInitialBufSize.
  std::string kReadData(GetTestString(kExpectedInitialBufSize));
  memcpy(buffer->data(), kReadData.data(), kReadData.size());
  buffer->DidRead(kReadData.size());
  EXPECT_EQ(kExpectedInitialBufSize, buffer->GetCapacity());
  EXPECT_EQ(kExpectedInitialBufSize - static_cast<int>(kReadData.size()),
            buffer->RemainingCapacity());
  EXPECT_EQ(static_cast<int>(kReadData.size()), buffer->GetSize());
  EXPECT_EQ(kReadData,
            std::string_view(buffer->StartOfBuffer(), buffer->GetSize()));

  // Increase capacity until it fails and check if read data in the buffer is
  // same.
  while (buffer->IncreaseCapacity());
  EXPECT_FALSE(buffer->IncreaseCapacity());
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kDefaultMaxBufferSize + 0,
            buffer->max_buffer_size());
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kDefaultMaxBufferSize + 0,
            buffer->GetCapacity());
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kDefaultMaxBufferSize -
                static_cast<int>(kReadData.size()),
            buffer->RemainingCapacity());
  EXPECT_EQ(static_cast<int>(kReadData.size()), buffer->GetSize());
  EXPECT_EQ(kReadData,
            std::string_view(buffer->StartOfBuffer(), buffer->GetSize()));
}

TEST(HttpConnectionTest, ReadIOBuffer_DidRead_DidConsume) {
  scoped_refptr<HttpConnection::ReadIOBuffer> buffer =
      base::MakeRefCounted<HttpConnection::ReadIOBuffer>();
  const char* start_of_buffer = buffer->StartOfBuffer();
  EXPECT_EQ(start_of_buffer, buffer->data());

  // Read data.
  const int kReadLength = 128;
  const std::string kReadData(GetTestString(kReadLength));
  memcpy(buffer->data(), kReadData.data(), kReadLength);
  buffer->DidRead(kReadLength);
  // No change in total capacity.
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kInitialBufSize + 0,
            buffer->GetCapacity());
  // Change in unused capacity because of read data.
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kInitialBufSize - kReadLength,
            buffer->RemainingCapacity());
  EXPECT_EQ(kReadLength, buffer->GetSize());
  // No change in start pointers of read data.
  EXPECT_EQ(start_of_buffer, buffer->StartOfBuffer());
  // Change in start pointer of unused buffer.
  EXPECT_EQ(start_of_buffer + kReadLength, buffer->data());
  // Test read data.
  EXPECT_EQ(kReadData, std::string(buffer->StartOfBuffer(), buffer->GetSize()));

  // Consume data partially.
  const int kConsumedLength = 32;
  ASSERT_LT(kConsumedLength, kReadLength);
  buffer->DidConsume(kConsumedLength);
  // Capacity reduced because read data was too small comparing to capacity.
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kInitialBufSize /
                HttpConnection::ReadIOBuffer::kCapacityIncreaseFactor,
            buffer->GetCapacity());
  // Change in unused capacity because of read data.
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kInitialBufSize /
                HttpConnection::ReadIOBuffer::kCapacityIncreaseFactor -
                kReadLength + kConsumedLength,
            buffer->RemainingCapacity());
  // Change in read size.
  EXPECT_EQ(kReadLength - kConsumedLength, buffer->GetSize());
  // Start data could be changed even when capacity is reduced.
  start_of_buffer = buffer->StartOfBuffer();
  // Change in start pointer of unused buffer.
  EXPECT_EQ(start_of_buffer + kReadLength - kConsumedLength, buffer->data());
  // Change in read data.
  EXPECT_EQ(kReadData.substr(kConsumedLength),
            std::string(buffer->StartOfBuffer(), buffer->GetSize()));

  // Read more data.
  const int kReadLength2 = 64;
  buffer->DidRead(kReadLength2);
  // No change in total capacity.
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kInitialBufSize /
                HttpConnection::ReadIOBuffer::kCapacityIncreaseFactor,
            buffer->GetCapacity());
  // Change in unused capacity because of read data.
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kInitialBufSize /
                HttpConnection::ReadIOBuffer::kCapacityIncreaseFactor -
                kReadLength + kConsumedLength - kReadLength2,
            buffer->RemainingCapacity());
  // Change in read size
  EXPECT_EQ(kReadLength - kConsumedLength + kReadLength2, buffer->GetSize());
  // No change in start pointer of read part.
  EXPECT_EQ(start_of_buffer, buffer->StartOfBuffer());
  // Change in start pointer of unused buffer.
  EXPECT_EQ(start_of_buffer + kReadLength - kConsumedLength + kReadLength2,
            buffer->data());

  // Consume data fully.
  buffer->DidConsume(kReadLength - kConsumedLength + kReadLength2);
  // Capacity reduced again because read data was too small.
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kInitialBufSize /
                HttpConnection::ReadIOBuffer::kCapacityIncreaseFactor /
                HttpConnection::ReadIOBuffer::kCapacityIncreaseFactor,
            buffer->GetCapacity());
  EXPECT_EQ(HttpConnection::ReadIOBuffer::kInitialBufSize /
                HttpConnection::ReadIOBuffer::kCapacityIncreaseFactor /
                HttpConnection::ReadIOBuffer::kCapacityIncreaseFactor,
            buffer->RemainingCapacity());
  // All reverts to initial because no data is left.
  EXPECT_EQ(0, buffer->GetSize());
  // Start data could be changed even when capacity is reduced.
  start_of_buffer = buffer->StartOfBuffer();
  EXPECT_EQ(start_of_buffer, buffer->data());
}

TEST(HttpConnectionTest, QueuedWriteIOBuffer_Append_DidConsume) {
  scoped_refptr<HttpConnection::QueuedWriteIOBuffer> buffer =
      base::MakeRefCounted<HttpConnection::QueuedWriteIOBuffer>();
  EXPECT_TRUE(buffer->IsEmpty());
  EXPECT_EQ(0, buffer->GetSizeToWrite());
  EXPECT_EQ(0, buffer->total_size());

  const std::string kData("data to write");
  EXPECT_TRUE(buffer->Append(kData));
  EXPECT_FALSE(buffer->IsEmpty());
  EXPECT_EQ(static_cast<int>(kData.size()), buffer->GetSizeToWrite());
  EXPECT_EQ(static_cast<int>(kData.size()), buffer->total_size());
  // First data to write is same to kData.
  EXPECT_EQ(kData, std::string_view(buffer->data(), buffer->GetSizeToWrite()));

  const std::string kData2("more data to write");
  EXPECT_TRUE(buffer->Append(kData2));
  EXPECT_FALSE(buffer->IsEmpty());
  // No change in size to write.
  EXPECT_EQ(static_cast<int>(kData.size()), buffer->GetSizeToWrite());
  // Change in total size.
  EXPECT_EQ(static_cast<int>(kData.size() + kData2.size()),
            buffer->total_size());
  // First data to write has not been changed. Same to kData.
  EXPECT_EQ(kData, std::string_view(buffer->data(), buffer->GetSizeToWrite()));

  // Consume data partially.
  const int kConsumedLength = kData.length() - 1;
  buffer->DidConsume(kConsumedLength);
  EXPECT_FALSE(buffer->IsEmpty());
  // Change in size to write.
  EXPECT_EQ(static_cast<int>(kData.size()) - kConsumedLength,
            buffer->GetSizeToWrite());
  // Change in total size.
  EXPECT_EQ(static_cast<int>(kData.size() + kData2.size()) - kConsumedLength,
            buffer->total_size());
  // First data to write has shrinked.
  EXPECT_EQ(kData.substr(kConsumedLength),
            std::string_view(buffer->data(), buffer->GetSizeToWrite()));

  // Consume first data fully.
  buffer->DidConsume(kData.size() - kConsumedLength);
  EXPECT_FALSE(buffer->IsEmpty());
  // Now, size to write is size of data added second.
  EXPECT_EQ(static_cast<int>(kData2.size()), buffer->GetSizeToWrite());
  // Change in total size.
  EXPECT_EQ(static_cast<int>(kData2.size()), buffer->total_size());
  // First data to write has changed to kData2.
  EXPECT_EQ(kData2, std::string_view(buffer->data(), buffer->GetSizeToWrite()));

  // Consume second data fully.
  buffer->DidConsume(kData2.size());
  EXPECT_TRUE(buffer->IsEmpty());
  EXPECT_EQ(0, buffer->GetSizeToWrite());
  EXPECT_EQ(0, buffer->total_size());
}

TEST(HttpConnectionTest, QueuedWriteIOBuffer_TotalSizeLimit) {
  scoped_refptr<HttpConnection::QueuedWriteIOBuffer> buffer =
      base::MakeRefCounted<HttpConnection::QueuedWriteIOBuffer>();
  EXPECT_EQ(HttpConnection::QueuedWriteIOBuffer::kDefaultMaxBufferSize + 0,
            buffer->max_buffer_size());

  // Set total size limit very small.
  buffer->set_max_buffer_size(10);

  const int kDataLength = 4;
  const std::string kData(kDataLength, 'd');
  EXPECT_TRUE(buffer->Append(kData));
  EXPECT_EQ(kDataLength, buffer->total_size());
  EXPECT_TRUE(buffer->Append(kData));
  EXPECT_EQ(kDataLength * 2, buffer->total_size());

  // Cannot append more data because it exceeds the limit.
  EXPECT_FALSE(buffer->Append(kData));
  EXPECT_EQ(kDataLength * 2, buffer->total_size());

  // Consume data partially.
  const int kConsumedLength = 2;
  buffer->DidConsume(kConsumedLength);
  EXPECT_EQ(kDataLength * 2 - kConsumedLength, buffer->total_size());

  // Can add more data.
  EXPECT_TRUE(buffer->Append(kData));
  EXPECT_EQ(kDataLength * 3 - kConsumedLength, buffer->total_size());

  // Cannot append more data because it exceeds the limit.
  EXPECT_FALSE(buffer->Append(kData));
  EXPECT_EQ(kDataLength * 3 - kConsumedLength, buffer->total_size());

  // Enlarge limit.
  buffer->set_max_buffer_size(20);
  // Can add more data.
  EXPECT_TRUE(buffer->Append(kData));
  EXPECT_EQ(kDataLength * 4 - kConsumedLength, buffer->total_size());
}

TEST(HttpConnectionTest, QueuedWriteIOBuffer_DataPointerStability) {
  // This is a regression test that makes sure that QueuedWriteIOBuffer deals
  // with base::queue's semantics differences vs. std::queue right, and still
  // makes sure our data() pointers are stable.
  scoped_refptr<HttpConnection::QueuedWriteIOBuffer> buffer =
      base::MakeRefCounted<HttpConnection::QueuedWriteIOBuffer>();

  // We append a short string to make it fit within any short string
  // optimization, so that if the underlying queue moves the std::string,
  // the data should change.
  buffer->Append("abcdefgh");

  // Read part of it, to make sure this handles the case of data() pointing
  // to something other than start of string right.
  buffer->DidConsume(3);
  const char* old_data = buffer->data();
  EXPECT_EQ("defgh", std::string_view(buffer->data(), 5));

  // Now append a whole bunch of other things to make the underlying queue
  // grow, and likely need to move stuff around in memory.
  for (int i = 0; i < 256; ++i)
    buffer->Append("some other string data");

  // data() should still be right.
  EXPECT_EQ("defgh", std::string_view(buffer->data(), 5));

  // ... it should also be bitwise the same, since the IOBuffer can get passed
  // to async calls and then have Append's come in.
  EXPECT_TRUE(buffer->data() == old_data);
}

}  // namespace
}  // namespace net

"""

```
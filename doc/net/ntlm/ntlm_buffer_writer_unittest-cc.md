Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The primary goal is to understand the functionality of the C++ code under test (`net/ntlm/ntlm_buffer_writer.h`) by examining its unit tests. The request also asks to identify connections to JavaScript, illustrate logical reasoning with examples, point out common usage errors, and suggest debugging steps.

2. **Identify the Core Class:**  The file name (`ntlm_buffer_writer_unittest.cc`) and the inclusion of `"net/ntlm/ntlm_buffer_writer.h"` immediately tell us the core class being tested is `NtlmBufferWriter`.

3. **Analyze Test Cases (The Heart of Understanding):**  The most direct way to understand `NtlmBufferWriter`'s functionality is by looking at the `TEST` macros. Each `TEST` case focuses on a specific aspect:

    * **Initialization:** How is the class initialized? What are the initial states of its members (length, buffer size, cursor)?
    * **EmptyWrite:** What happens when writing zero bytes to the buffer?  This highlights edge cases and how the class handles empty operations.
    * **Write16, Write32, Write64:**  These test writing different integer types. Notice the endianness (little-endian) is implied by the `expected` values. The tests check both successful writes and attempts to write past the end of the buffer.
    * **WriteBytes:** Tests writing a raw byte array. Similar to integer writes, it checks success and out-of-bounds writes.
    * **WriteSecurityBuffer:**  This suggests `SecurityBuffer` is a related concept within the NTLM context. The test checks how this structured data is written.
    * **WriteString Variants (WriteNarrowString, WriteUtf16String, WriteUtf8AsUtf16String):**  These are crucial for understanding how the class handles different string encodings. The "AsUtf16" variant suggests potential encoding conversions.
    * **WriteSignature, WriteMessageType, WriteAvPairHeader:**  These tests indicate that `NtlmBufferWriter` is used for constructing NTLM protocol messages, which have specific structures and fields. The names of these methods hint at the data they write.

4. **Infer Functionality from Tests:** Based on the test cases, we can infer the key functions and purposes of `NtlmBufferWriter`:

    * **Buffer Management:**  It manages a byte buffer of a fixed size.
    * **Writing Data:** It provides methods to write various data types (integers, byte arrays, strings) into the buffer.
    * **Cursor Tracking:** It maintains a cursor to track the current write position.
    * **Bounds Checking:** It prevents writing beyond the allocated buffer size.
    * **NTLM Protocol Support:**  The `WriteSignature`, `WriteMessageType`, and `WriteAvPairHeader` methods strongly suggest its use in constructing NTLM messages.

5. **Address Specific Questions:** Now, let's address the specific parts of the request:

    * **Functionality Listing:** This is a summary of the inferences made in step 4.
    * **JavaScript Relationship:**  Think about where NTLM is used. It's often involved in authentication, especially in corporate environments. Browsers (which heavily involve JavaScript) interact with servers requiring NTLM authentication. So, while this *specific* C++ code isn't directly in JavaScript, its *purpose* is to facilitate a protocol that JavaScript-based web applications might use. The `fetch` API example illustrates this indirect relationship.
    * **Logical Reasoning (Input/Output):**  Choose a simple test case (like `Write16`). State the initial conditions (buffer size, input value) and predict the output (the byte sequence in the buffer). This demonstrates how the code transforms data.
    * **Common Usage Errors:** Focus on the bounds-checking aspects. The tests for "PastEob" (past end of buffer) directly point to a common error: trying to write more data than the buffer can hold.
    * **User Steps and Debugging:** Consider the context where NTLM is used in a browser. A user trying to access an internal website protected by NTLM is a good starting point. Then, think about where things could go wrong and how this specific code might be involved (e.g., constructing the authentication messages).

6. **Structure the Response:**  Organize the findings logically, addressing each part of the request clearly. Use headings and bullet points to improve readability. Provide concrete examples for JavaScript interaction, input/output, and usage errors.

7. **Refine and Review:**  Read through the generated response to ensure clarity, accuracy, and completeness. Make sure the examples are easy to understand and directly related to the code being analyzed. For instance, initially, I might just say "NTLM is used for authentication," but the `fetch` API example with `credentials: 'include'` makes the connection to JavaScript much more concrete.

By following this process, we can systematically analyze the C++ test file and provide a comprehensive answer that addresses all aspects of the request. The key is to understand the *purpose* of the code and how the tests validate that purpose.
这个文件 `net/ntlm/ntlm_buffer_writer_unittest.cc` 是 Chromium 项目中网络栈的一部分，专门用于测试 `net/ntlm/ntlm_buffer_writer.h` 中定义的 `NtlmBufferWriter` 类的功能。 `NtlmBufferWriter` 类很可能用于在构建 NTLM 认证协议消息时，方便地将各种数据写入到缓冲区中。

以下是该文件的功能列表：

1. **测试 `NtlmBufferWriter` 类的初始化**:
   - 验证创建 `NtlmBufferWriter` 对象时，其长度、缓冲区大小、游标位置以及是否可以写入等状态是否正确。

2. **测试空写入**:
   - 验证向 `NtlmBufferWriter` 写入零字节数据时的行为，包括对零大小缓冲区和非零大小缓冲区的处理。

3. **测试写入不同大小的整数 (16位, 32位, 64位)**:
   - 验证 `WriteUInt16`, `WriteUInt32`, `WriteUInt64` 方法是否能将指定大小的整数以小端字节序正确写入缓冲区。
   - 测试当写入的数据超过缓冲区剩余空间时的行为。

4. **测试写入字节数组**:
   - 验证 `WriteBytes` 方法是否能将字节数组正确写入缓冲区。
   - 测试当写入的字节数组超过缓冲区剩余空间时的行为。

5. **测试写入 `SecurityBuffer`**:
   - 验证 `WriteSecurityBuffer` 方法是否能将 `SecurityBuffer` 结构体（包含长度和偏移量）以特定的格式写入缓冲区。
   - 测试当写入 `SecurityBuffer` 时超过缓冲区剩余空间的行为。

6. **测试写入字符串 (窄字符串和 UTF-16 字符串)**:
   - 验证 `WriteUtf8String` (窄字符串) 和 `WriteUtf16String` 方法是否能将字符串以相应的编码格式写入缓冲区。
   - 验证 `WriteUtf8AsUtf16String` 方法是否能将 UTF-8 字符串转换为 UTF-16 格式并写入缓冲区。
   - 测试当写入字符串时超过缓冲区剩余空间的行为。

7. **测试写入 NTLM 签名**:
   - 验证 `WriteSignature` 方法是否能将预定义的 NTLM 签名（"NTLMSSP\0"）写入缓冲区。
   - 测试当缓冲区空间不足以写入签名时的行为。

8. **测试写入消息类型**:
   - 验证 `WriteMessageType` 方法是否能将 NTLM 消息类型枚举值作为 32 位整数写入缓冲区。
   - 测试当缓冲区空间不足以写入消息类型时的行为。

9. **测试写入 AV Pair Header**:
   - 验证 `WriteAvPairHeader` 方法是否能将 AV Pair 的类型和值以特定的格式写入缓冲区。
   - 测试当缓冲区空间不足以写入 AV Pair Header 时的行为。

**与 JavaScript 功能的关系**

NTLM 是一种认证协议，常用于 Windows 环境下的身份验证。在 Web 开发中，当用户尝试访问需要 NTLM 认证的资源时，浏览器会与服务器进行 NTLM 握手。 Chromium 的网络栈负责处理这些底层的认证协议，包括 NTLM。

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所测试的功能直接影响到浏览器如何处理 NTLM 认证，这最终会影响到 JavaScript 发起的网络请求的行为。

**举例说明**:

假设一个使用 JavaScript 的网页尝试通过 `fetch` API 访问一个需要 NTLM 认证的内部网站：

```javascript
fetch('https://internal.example.com/secure-resource', {
  credentials: 'include' // 指示浏览器包含认证信息
})
.then(response => {
  if (response.ok) {
    return response.text();
  } else {
    throw new Error('Network response was not ok.');
  }
})
.then(data => console.log(data))
.catch(error => console.error('There has been a problem with your fetch operation:', error));
```

当浏览器执行这段 JavaScript 代码时，如果服务器返回需要 NTLM 认证的挑战，Chromium 的网络栈就会介入，并使用类似 `NtlmBufferWriter` 这样的类来构建发送给服务器的 NTLM 响应消息。 `NtlmBufferWriter` 确保了消息的格式正确，例如，将用户名、域名、工作站等信息按照 NTLM 协议要求的格式写入缓冲区。

**逻辑推理 (假设输入与输出)**

**测试 `WriteUInt16`:**

* **假设输入**:
    * `NtlmBufferWriter` 初始化时缓冲区大小为 2 字节。
    * 调用 `writer.WriteUInt16(0x1234)`。
* **预期输出**:
    * 缓冲区的前 2 个字节内容为 `0x34`, `0x12` (小端字节序)。
    * `writer.IsEndOfBuffer()` 返回 `true`。

**测试 `WriteUtf8String`:**

* **假设输入**:
    * `NtlmBufferWriter` 初始化时缓冲区大小为 5 字节。
    * 调用 `writer.WriteUtf8String("hello")`。
* **预期输出**:
    * 缓冲区的前 5 个字节内容为 `'h'`, `'e'`, `'l'`, `'l'`, `'o'` (ASCII 编码)。
    * `writer.IsEndOfBuffer()` 返回 `true`。

**用户或编程常见的使用错误**

1. **缓冲区溢出**: 开发者在调用 `NtlmBufferWriter` 的写入方法时，没有检查剩余空间是否足够，导致写入的数据超过了缓冲区的容量。

   ```c++
   NtlmBufferWriter writer(5);
   std::string long_string = "this is a long string";
   // 错误：尝试写入超过缓冲区大小的字符串
   writer.WriteUtf8String(long_string); // 这会导致断言失败或未定义行为
   ```

2. **假设缓冲区足够大**: 在构建 NTLM 消息时，开发者可能错误地假设缓冲区总是足够容纳所有需要写入的数据，而没有进行必要的空间检查。

   ```c++
   NtlmBufferWriter writer(100); // 假设 100 字节足够
   // ... 写入了一些数据 ...
   std::string user_name = GetUserNameFromInput(); // 用户名可能很长
   // 如果用户名很长，可能导致缓冲区溢出
   writer.WriteUtf8String(user_name);
   ```

3. **错误地计算所需缓冲区大小**: 在初始化 `NtlmBufferWriter` 时，开发者可能错误地估计了需要写入的总数据量，导致缓冲区大小不足。

   ```c++
   size_t buffer_size = CalculateInitialBufferSize(); // 计算可能不准确
   NtlmBufferWriter writer(buffer_size);
   // ... 后续写入操作可能因为空间不足而失败
   ```

**用户操作如何一步步到达这里，作为调试线索**

假设用户尝试访问一个内部网站 `https://internal.example.com`，该网站配置为需要 NTLM 认证。以下是可能导致与 `NtlmBufferWriter` 相关的代码被执行的步骤：

1. **用户在浏览器地址栏输入 URL `https://internal.example.com` 并回车。**
2. **浏览器向服务器发起连接请求。**
3. **服务器返回 HTTP 401 Unauthorized 响应，并在 `WWW-Authenticate` 头中指示需要 NTLM 认证。**
4. **Chromium 的网络栈检测到需要 NTLM 认证。**
5. **Chromium 开始 NTLM 握手的第一步，构造一个 Type 1 (Negotiate) 消息。**
6. **在构造 Type 1 消息的过程中，可能会使用 `NtlmBufferWriter` 类来将消息的各个部分（例如，NTLM 签名、消息类型、协商标志等）写入到缓冲区中。**
7. **构造好的 Type 1 消息被发送到服务器。**
8. **服务器收到 Type 1 消息后，返回 Type 2 (Challenge) 消息。**
9. **Chromium 接收到 Type 2 消息，并根据挑战信息构造 Type 3 (Authenticate) 消息。**
10. **在构造 Type 3 消息的过程中，`NtlmBufferWriter` 再次被使用，用于写入用户名、域名、工作站、NTLM 响应等信息。**
11. **构造好的 Type 3 消息被发送到服务器。**
12. **服务器验证 Type 3 消息中的凭据，如果验证成功，则返回用户请求的资源。**

**调试线索**:

如果在调试 NTLM 认证相关的问题时，发现认证失败或行为异常，可以关注以下几点，这可能与 `NtlmBufferWriter` 的使用有关：

* **抓包分析**: 使用网络抓包工具（如 Wireshark）查看浏览器发送的 NTLM 消息的格式是否正确，是否符合 NTLM 协议规范。如果消息格式错误，可能是 `NtlmBufferWriter` 在写入数据时出现了问题。
* **Chromium 网络日志**: 启用 Chromium 的网络日志（通过 `chrome://net-export/` 或命令行参数），查看更详细的网络请求和响应信息，包括 NTLM 握手的过程。
* **断点调试**: 如果有 Chromium 的源代码，可以在 `NtlmBufferWriter` 的相关方法中设置断点，查看缓冲区的内容以及写入过程中的变量值，以确定是否发生了预期的写入操作。
* **检查缓冲区大小和剩余空间**: 在关键的写入操作之前，检查 `NtlmBufferWriter` 的缓冲区大小和剩余空间，确保有足够的空间写入数据。
* **验证写入的数据**: 检查写入到缓冲区的数据是否与预期一致，例如，整数是否以正确的字节序写入，字符串是否以正确的编码写入。

总而言之，`net/ntlm/ntlm_buffer_writer_unittest.cc` 文件通过各种测试用例，确保了 `NtlmBufferWriter` 类能够正确地将不同类型的数据写入到缓冲区中，这对于 Chromium 正确实现 NTLM 认证协议至关重要，并间接影响到用户在浏览器中使用 JavaScript 访问需要 NTLM 认证资源的行为。

### 提示词
```
这是目录为net/ntlm/ntlm_buffer_writer_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/ntlm/ntlm_buffer_writer.h"

#include "base/strings/utf_string_conversions.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net::ntlm {

namespace {

// Helper method to get a raw pointer to the buffer.
const uint8_t* GetBufferPtr(const NtlmBufferWriter& writer) {
  return writer.GetBuffer().data();
}

// Helper method to get a byte at a specific index in the buffer.
uint8_t GetByteFromBuffer(const NtlmBufferWriter& writer, size_t index) {
  EXPECT_TRUE(index < writer.GetLength());
  return writer.GetBuffer()[index];
}

}  // namespace

TEST(NtlmBufferWriterTest, Initialization) {
  NtlmBufferWriter writer(1);

  ASSERT_EQ(1u, writer.GetLength());
  ASSERT_EQ(1u, writer.GetBuffer().size());
  ASSERT_EQ(0u, writer.GetCursor());
  ASSERT_FALSE(writer.IsEndOfBuffer());
  ASSERT_TRUE(writer.CanWrite(1));
  ASSERT_FALSE(writer.CanWrite(2));
}

TEST(NtlmBufferWriterTest, EmptyWrite) {
  NtlmBufferWriter writer(0);

  ASSERT_EQ(0u, writer.GetLength());
  ASSERT_EQ(0u, writer.GetBuffer().size());
  ASSERT_EQ(0u, writer.GetCursor());
  ASSERT_EQ(nullptr, GetBufferPtr(writer));

  // An empty (zero-byte) write into a zero-byte writer should succeed as a
  // no-op.
  std::vector<uint8_t> b;
  ASSERT_TRUE(writer.CanWrite(0));
  ASSERT_TRUE(writer.WriteBytes(b));

  ASSERT_EQ(0u, writer.GetLength());
  ASSERT_EQ(0u, writer.GetBuffer().size());
  ASSERT_EQ(0u, writer.GetCursor());
  ASSERT_EQ(nullptr, GetBufferPtr(writer));

  // An empty (zero-byte) write into a non-zero-byte writer should succeed as
  // a no-op.
  NtlmBufferWriter writer2(1);
  ASSERT_EQ(1u, writer2.GetLength());
  ASSERT_EQ(1u, writer2.GetBuffer().size());
  ASSERT_EQ(0u, writer2.GetCursor());
  ASSERT_NE(nullptr, GetBufferPtr(writer2));

  ASSERT_TRUE(writer2.CanWrite(0));
  ASSERT_TRUE(writer2.WriteBytes(b));

  ASSERT_EQ(1u, writer2.GetLength());
  ASSERT_EQ(1u, writer2.GetBuffer().size());
  ASSERT_EQ(0u, writer2.GetCursor());
  ASSERT_NE(nullptr, GetBufferPtr(writer2));
}

TEST(NtlmBufferWriterTest, Write16) {
  uint8_t expected[2] = {0x22, 0x11};
  const uint16_t value = 0x1122;

  NtlmBufferWriter writer(sizeof(uint16_t));

  ASSERT_TRUE(writer.WriteUInt16(value));
  ASSERT_TRUE(writer.IsEndOfBuffer());
  ASSERT_EQ(std::size(expected), writer.GetLength());
  ASSERT_FALSE(writer.WriteUInt16(value));

  ASSERT_EQ(0,
            memcmp(expected, writer.GetBuffer().data(), std::size(expected)));
}

TEST(NtlmBufferWriterTest, Write16PastEob) {
  NtlmBufferWriter writer(sizeof(uint16_t) - 1);

  ASSERT_FALSE(writer.WriteUInt16(0));
  ASSERT_EQ(0u, writer.GetCursor());
}

TEST(NtlmBufferWriterTest, Write32) {
  uint8_t expected[4] = {0x44, 0x33, 0x22, 0x11};
  const uint32_t value = 0x11223344;

  NtlmBufferWriter writer(sizeof(uint32_t));

  ASSERT_TRUE(writer.WriteUInt32(value));
  ASSERT_TRUE(writer.IsEndOfBuffer());
  ASSERT_FALSE(writer.WriteUInt32(value));

  ASSERT_EQ(0, memcmp(expected, GetBufferPtr(writer), std::size(expected)));
}

TEST(NtlmBufferWriterTest, Write32PastEob) {
  NtlmBufferWriter writer(sizeof(uint32_t) - 1);

  ASSERT_FALSE(writer.WriteUInt32(0));
  ASSERT_EQ(0u, writer.GetCursor());
}

TEST(NtlmBufferWriterTest, Write64) {
  uint8_t expected[8] = {0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
  const uint64_t value = 0x1122334455667788;

  NtlmBufferWriter writer(sizeof(uint64_t));

  ASSERT_TRUE(writer.WriteUInt64(value));
  ASSERT_TRUE(writer.IsEndOfBuffer());
  ASSERT_FALSE(writer.WriteUInt64(value));

  ASSERT_EQ(0, memcmp(expected, GetBufferPtr(writer), std::size(expected)));
}

TEST(NtlmBufferWriterTest, Write64PastEob) {
  NtlmBufferWriter writer(sizeof(uint64_t) - 1);

  ASSERT_FALSE(writer.WriteUInt64(0));
  ASSERT_EQ(0u, writer.GetCursor());
}

TEST(NtlmBufferWriterTest, WriteBytes) {
  uint8_t expected[8] = {0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};

  NtlmBufferWriter writer(std::size(expected));

  ASSERT_TRUE(writer.WriteBytes(expected));
  ASSERT_EQ(0, memcmp(GetBufferPtr(writer), expected, std::size(expected)));
  ASSERT_TRUE(writer.IsEndOfBuffer());
  ASSERT_FALSE(writer.WriteBytes(base::make_span(expected, 1u)));

  ASSERT_EQ(0, memcmp(expected, GetBufferPtr(writer), std::size(expected)));
}

TEST(NtlmBufferWriterTest, WriteBytesPastEob) {
  uint8_t buffer[8];

  NtlmBufferWriter writer(std::size(buffer) - 1);

  ASSERT_FALSE(writer.WriteBytes(buffer));
}

TEST(NtlmBufferWriterTest, WriteSecurityBuffer) {
  uint8_t expected[8] = {0x22, 0x11, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55};
  uint16_t length = 0x1122;
  uint32_t offset = 0x55667788;

  NtlmBufferWriter writer(kSecurityBufferLen);

  ASSERT_TRUE(writer.WriteSecurityBuffer(SecurityBuffer(offset, length)));
  ASSERT_TRUE(writer.IsEndOfBuffer());
  ASSERT_FALSE(writer.WriteSecurityBuffer(SecurityBuffer(offset, length)));

  ASSERT_EQ(0, memcmp(expected, GetBufferPtr(writer), std::size(expected)));
}

TEST(NtlmBufferWriterTest, WriteSecurityBufferPastEob) {
  SecurityBuffer sec_buf;
  NtlmBufferWriter writer(kSecurityBufferLen - 1);

  ASSERT_FALSE(writer.WriteSecurityBuffer(sec_buf));
}

TEST(NtlmBufferWriterTest, WriteNarrowString) {
  uint8_t expected[8] = {'1', '2', '3', '4', '5', '6', '7', '8'};
  std::string value("12345678");

  NtlmBufferWriter writer(value.size());

  ASSERT_TRUE(writer.WriteUtf8String(value));
  ASSERT_TRUE(writer.IsEndOfBuffer());
  ASSERT_FALSE(writer.WriteUtf8String(value));

  ASSERT_EQ(0, memcmp(expected, GetBufferPtr(writer), std::size(expected)));
}

TEST(NtlmBufferWriterTest, WriteAsciiStringPastEob) {
  std::string str("12345678");
  NtlmBufferWriter writer(str.length() - 1);

  ASSERT_FALSE(writer.WriteUtf8String(str));
}

TEST(NtlmBufferWriterTest, WriteUtf16String) {
  uint8_t expected[16] = {'1', 0, '2', 0, '3', 0, '4', 0,
                          '5', 0, '6', 0, '7', 0, '8', 0};
  std::u16string value = u"12345678";

  NtlmBufferWriter writer(value.size() * 2);

  ASSERT_TRUE(writer.WriteUtf16String(value));
  ASSERT_TRUE(writer.IsEndOfBuffer());
  ASSERT_FALSE(writer.WriteUtf16String(value));

  ASSERT_EQ(0, memcmp(expected, GetBufferPtr(writer), std::size(expected)));
}

TEST(NtlmBufferWriterTest, WriteUtf16StringPastEob) {
  std::u16string str = u"12345678";
  NtlmBufferWriter writer((str.length() * 2) - 1);

  ASSERT_FALSE(writer.WriteUtf16String(str));
}

TEST(NtlmBufferWriterTest, WriteUtf8AsUtf16String) {
  uint8_t expected[16] = {'1', 0, '2', 0, '3', 0, '4', 0,
                          '5', 0, '6', 0, '7', 0, '8', 0};
  std::string input = "12345678";

  NtlmBufferWriter writer(input.size() * 2);

  ASSERT_TRUE(writer.WriteUtf8AsUtf16String(input));
  ASSERT_TRUE(writer.IsEndOfBuffer());
  ASSERT_FALSE(writer.WriteUtf8AsUtf16String(input));

  ASSERT_EQ(0, memcmp(expected, GetBufferPtr(writer), std::size(expected)));
}

TEST(NtlmBufferWriterTest, WriteSignature) {
  uint8_t expected[8] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
  NtlmBufferWriter writer(kSignatureLen);

  ASSERT_TRUE(writer.WriteSignature());
  ASSERT_TRUE(writer.IsEndOfBuffer());

  ASSERT_EQ(0, memcmp(expected, GetBufferPtr(writer), std::size(expected)));
}

TEST(NtlmBufferWriterTest, WriteSignaturePastEob) {
  NtlmBufferWriter writer(1);

  ASSERT_FALSE(writer.WriteSignature());
}

TEST(NtlmBufferWriterTest, WriteMessageType) {
  NtlmBufferWriter writer(4);

  ASSERT_TRUE(writer.WriteMessageType(MessageType::kNegotiate));
  ASSERT_TRUE(writer.IsEndOfBuffer());
  ASSERT_EQ(static_cast<uint32_t>(MessageType::kNegotiate),
            GetByteFromBuffer(writer, 0));
  ASSERT_EQ(0, GetByteFromBuffer(writer, 1));
  ASSERT_EQ(0, GetByteFromBuffer(writer, 2));
  ASSERT_EQ(0, GetByteFromBuffer(writer, 3));
}

TEST(NtlmBufferWriterTest, WriteMessageTypePastEob) {
  NtlmBufferWriter writer(sizeof(uint32_t) - 1);

  ASSERT_FALSE(writer.WriteMessageType(MessageType::kNegotiate));
}

TEST(NtlmBufferWriterTest, WriteAvPairHeader) {
  const uint8_t expected[4] = {0x06, 0x00, 0x11, 0x22};
  NtlmBufferWriter writer(std::size(expected));

  ASSERT_TRUE(writer.WriteAvPairHeader(TargetInfoAvId::kFlags, 0x2211));
  ASSERT_TRUE(writer.IsEndOfBuffer());

  ASSERT_EQ(0, memcmp(expected, GetBufferPtr(writer), std::size(expected)));
}

TEST(NtlmBufferWriterTest, WriteAvPairHeaderPastEob) {
  NtlmBufferWriter writer(kAvPairHeaderLen - 1);

  ASSERT_FALSE(writer.WriteAvPairHeader(TargetInfoAvId::kFlags, 0x2211));
  ASSERT_EQ(0u, writer.GetCursor());
}

}  // namespace net::ntlm
```
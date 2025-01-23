Response:
Let's break down the thought process for analyzing this C++ unittests file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to JavaScript (if any), logical reasoning (with input/output examples), common usage errors, and debugging information (how a user might reach this code).

2. **Identify the Core Subject:** The filename `ntlm_buffer_reader_unittest.cc` immediately tells us this file contains unit tests for a class named `NtlmBufferReader`. The `ntlm` namespace further suggests this class is related to the NTLM authentication protocol.

3. **Examine the Includes:**  The included headers provide valuable context:
    * `"net/ntlm/ntlm_buffer_reader.h"`: This confirms the existence and location of the class being tested.
    * `"base/strings/utf_string_conversions.h"`: While not directly used in these tests, it hints that the `NtlmBufferReader` *might* handle string conversions, possibly related to usernames or domain names in NTLM. This is a weak connection, but worth noting.
    * `"testing/gtest/include/gtest/gtest.h"`: This confirms the use of Google Test for unit testing.

4. **Analyze the Test Cases (the heart of the functionality):** Iterate through each `TEST` function and summarize its purpose. Look for patterns and groupings:
    * **Initialization and Basic Properties:** `Initialization`, `EmptyBuffer`, `NullBuffer` test the initial state and edge cases of the `NtlmBufferReader`. They check things like cursor position, buffer length, and the ability to read.
    * **Reading Data:** `Read16`, `Read32`, `Read64`, `ReadBytes`, `ReadSecurityBuffer` test reading specific data types and structures from the buffer. Pay attention to endianness (little-endian is implied by the byte order in the tests).
    * **Security Buffers:**  Several tests focus on `SecurityBuffer` (`ReadSecurityBuffer`, `ReadSecurityBufferPastEob`, `ReadPayloadAsBufferReader`, `ReadPayloadBadOffset`, `ReadPayloadBadLength`, `SkipSecurityBuffer`, etc.). This highlights the importance of `SecurityBuffer` in the NTLM protocol, likely representing variable-length data fields with length and offset.
    * **Skipping Data:** `SkipBytes`, `SkipSecurityBuffer` test the ability to advance the cursor without reading the data.
    * **NTLM Specifics:** `MatchSignature`, `ReadMessageType`, `ReadTargetInfo` and its variants, `MatchMessageType`, `MatchMessageHeader` directly test functionalities related to the NTLM protocol's structure (signature, message types, target information). The `AvPair` structure is a key element here.
    * **Matching Data:** `MatchZeros`, `MatchEmptySecurityBuffer` test for specific patterns in the buffer.

5. **Identify the Core Functionality of `NtlmBufferReader`:** Based on the tests, the class provides:
    * **Buffer Management:**  Holding a buffer of data and tracking a current read position (cursor).
    * **Reading Primitive Types:**  Reading fixed-size integers (16, 32, 64 bits) in little-endian order.
    * **Reading Byte Sequences:**  Reading a specified number of raw bytes.
    * **Reading Security Buffers:**  Interpreting the length and offset of variable-length data within the buffer.
    * **Skipping Data:**  Advancing the cursor by a specified number of bytes or over a security buffer.
    * **Matching Patterns:**  Checking for specific byte sequences (signature) or zero-filled regions.
    * **Reading NTLM-Specific Structures:** Reading message types and target information (AV pairs).

6. **Assess the JavaScript Connection:**  Look for direct interactions or shared concepts. In this case, the connection is weak. NTLM is a server-side authentication protocol. JavaScript in a browser might *initiate* an NTLM authentication by sending a request that eventually gets processed by code involving `NtlmBufferReader` on the server side. Focus on the *initiation* of the process in a browser scenario.

7. **Construct Logical Reasoning Examples:** For key functionalities, create simple input buffers and expected outputs based on the test logic. This demonstrates understanding of how the reading and skipping functions work. Think about boundary conditions (end of buffer).

8. **Identify Common Usage Errors:** Consider how a programmer using `NtlmBufferReader` might misuse it. Focus on buffer overflows, incorrect offset/length calculations, and failing to check return values.

9. **Develop the Debugging Scenario:**  Imagine a user encountering an NTLM authentication issue. Trace the steps from user action (trying to access a resource) to the point where `NtlmBufferReader` might be involved in parsing the server's response.

10. **Structure the Output:** Organize the findings into clear sections as requested by the prompt: Functionality, JavaScript relation, logical reasoning, usage errors, and debugging. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Maybe `NtlmBufferReader` is used in the browser's JavaScript engine for NTLM."  **Correction:** While the *initiation* might happen in the browser, the *processing* of the NTLM messages is more likely server-side. Focus on the network interaction.
* **Overemphasis on string conversions:** Initially, the inclusion of `utf_string_conversions.h` might suggest a strong string handling focus. **Correction:** The tests don't directly use this. Acknowledge it, but don't overstate its current role in the *tested* functionality.
* **Too complex logical reasoning:**  Start with simple examples. Avoid overly convoluted scenarios. The goal is to illustrate the basic operation.
* **Vague usage errors:**  Be specific. Instead of "using it wrong," identify concrete mistakes like "reading past the end of the buffer."

By following these steps and engaging in some self-correction, we arrive at a comprehensive and accurate analysis of the `ntlm_buffer_reader_unittest.cc` file.
这个文件 `net/ntlm/ntlm_buffer_reader_unittest.cc` 是 Chromium 网络栈中用于测试 `NtlmBufferReader` 类的单元测试文件。 `NtlmBufferReader` 类的作用是**从一个字节缓冲区中读取 NTLM 协议相关的各种数据结构和字段**。

以下是 `ntlm_buffer_reader_unittest.cc` 中测试的主要功能点：

**核心功能测试:**

* **初始化 (Initialization):** 测试 `NtlmBufferReader` 对象的初始化状态，例如缓冲区长度、当前读取位置（游标）、是否到达缓冲区末尾以及是否可以读取指定长度的数据。
* **空缓冲区 (EmptyBuffer):**  测试处理空缓冲区的情况。
* **空指针缓冲区 (NullBuffer):** 测试处理空指针缓冲区的情况。
* **读取基本数据类型 (Read16, Read32, Read64):** 测试从缓冲区读取 16 位、32 位和 64 位无符号整数（小端序）。
* **读取字节数组 (ReadBytes):** 测试从缓冲区读取指定长度的字节数组。
* **读取安全缓冲区 (ReadSecurityBuffer):**  测试读取 NTLM 协议中常用的 `SecurityBuffer` 结构，该结构包含长度和偏移量，指向缓冲区中的实际数据。同时也测试了读取安全缓冲区时超出缓冲区末尾的情况。
* **读取安全缓冲区指向的有效载荷 (ReadPayloadAsBufferReader):** 测试读取 `SecurityBuffer` 结构指向的实际数据，并将其封装成一个新的 `NtlmBufferReader` 对象。同时也测试了偏移量或长度超出缓冲区范围的情况。
* **跳过安全缓冲区 (SkipSecurityBuffer):** 测试跳过 `SecurityBuffer` 结构占用的 8 个字节。同时也测试了跳过时超出缓冲区末尾的情况。
* **带验证地跳过安全缓冲区 (SkipSecurityBufferWithValidation):** 测试跳过 `SecurityBuffer` 结构，并验证其长度和偏移量是否有效，即指向的有效载荷是否在缓冲区内。
* **跳过指定字节数 (SkipBytes):** 测试跳过指定数量的字节。同时也测试了跳过时超出缓冲区末尾的情况。
* **匹配签名 (MatchSignature):** 测试匹配 NTLM 消息头的固定签名 "NTLMSSP\0"。
* **读取消息类型 (ReadMessageType):** 测试读取 NTLM 消息类型（Negotiate, Challenge, Authenticate）。同时也测试了读取无效消息类型的情况。
* **读取目标信息 (ReadTargetInfo):** 测试读取 NTLM 协议中的目标信息字段，该字段包含一系列 AV Pair (Attribute-Value Pair)。
* **读取目标信息有效载荷 (ReadTargetInfoPayload):** 测试读取 `SecurityBuffer` 指向的目标信息有效载荷。
* **匹配消息类型 (MatchMessageType):** 测试匹配指定的 NTLM 消息类型。
* **匹配消息头 (MatchMessageHeader):** 测试匹配包含签名的完整 NTLM 消息头。
* **匹配零字节 (MatchZeros):** 测试匹配指定数量的零字节。
* **匹配空安全缓冲区 (MatchEmptySecurityBuffer):** 测试匹配长度和偏移量都为零的 `SecurityBuffer`。
* **读取 AV Pair 头 (ReadAvPairHeader):** 测试读取目标信息中的 AV Pair 的头信息（属性 ID 和长度）。

**与 Javascript 的关系:**

`NtlmBufferReader` 本身是用 C++ 编写的，直接在 JavaScript 中无法使用。但是，它在 Chromium 浏览器中扮演着重要的角色，最终会影响到 JavaScript 的行为，尤其是在处理需要 NTLM 认证的网络请求时。

例如，当 JavaScript 代码发起一个需要 NTLM 认证的 HTTP 请求时，Chromium 的网络栈会处理认证过程。在这个过程中，服务器可能会返回包含 NTLM 协议数据的响应。`NtlmBufferReader` 就被用来解析这些 NTLM 消息，提取关键信息，例如服务器的质询 (Challenge)。

**举例说明:**

假设一个内部网站需要 NTLM 认证。

1. **用户在浏览器地址栏输入网站地址或点击链接。**
2. **JavaScript 发起一个 HTTP 请求到该网站。**
3. **服务器返回一个 401 Unauthorized 响应，并带有 `WWW-Authenticate: NTLM` 头信息。**
4. **Chromium 的网络栈识别出需要进行 NTLM 认证。**
5. **Chromium 构建一个 NTLM Negotiate 消息并发送给服务器。**
6. **服务器返回一个 NTLM Challenge 消息。**
7. **Chromium 的 C++ 网络栈接收到 Challenge 消息，并使用 `NtlmBufferReader` 来解析这个消息，提取服务器的质询信息，例如 `Challenge` 字段、`Target Name` 等。**
8. **Chromium 根据 Challenge 信息，结合用户的凭据（用户名和密码），构建一个 NTLM Authenticate 消息。**
9. **Chromium 将 Authenticate 消息发送给服务器。**
10. **服务器验证通过后，返回请求的资源。**
11. **JavaScript 接收到服务器返回的资源数据。**

在这个过程中，虽然 JavaScript 代码本身没有直接使用 `NtlmBufferReader`，但它的行为（发起网络请求）触发了 Chromium 网络栈中 C++ 代码的执行，而 `NtlmBufferReader` 正是在这个底层过程中发挥作用，帮助解析服务器返回的 NTLM 消息。

**逻辑推理与假设输入输出:**

**测试用例: `TEST(NtlmBufferReaderTest, ReadUInt32)`**

* **假设输入:** 一个包含 4 个字节的缓冲区，内容为 `0x44, 0x33, 0x22, 0x11`。
* **操作:** 创建一个 `NtlmBufferReader` 对象，将该缓冲区作为输入。调用 `ReadUInt32` 方法。
* **预期输出:**  `ReadUInt32` 方法返回 `true`，并将读取到的 32 位无符号整数存储到输出参数中，值为 `0x11223344` (小端序)。读取器的游标移动了 4 个字节，并到达缓冲区末尾。

**测试用例: `TEST(NtlmBufferReaderTest, SkipBytes)`**

* **假设输入:** 一个包含 8 个字节的缓冲区，内容任意。
* **操作:** 创建一个 `NtlmBufferReader` 对象，将该缓冲区作为输入。调用 `SkipBytes(8)` 方法。
* **预期输出:** `SkipBytes` 方法返回 `true`，读取器的游标移动了 8 个字节，并到达缓冲区末尾。如果调用 `SkipBytes(9)`，则返回 `false`。

**用户或编程常见的使用错误:**

1. **尝试读取超出缓冲区末尾的数据:**
   * **示例:** 缓冲区长度为 10，但尝试读取 12 个字节。
   * **对应测试用例:** 例如 `Read16`、`Read32`、`ReadBytes` 等测试用例中，在成功读取后再次尝试读取会失败。
   * **调试线索:**  程序崩溃或返回错误，检查 `NtlmBufferReader` 的 `CanRead` 方法返回值。

2. **假设安全缓冲区的偏移量或长度超出实际缓冲区范围:**
   * **示例:** `SecurityBuffer` 的偏移量指向缓冲区外，或者长度加上偏移量超出了缓冲区大小。
   * **对应测试用例:** `ReadSecurityBufferPastEob`, `ReadPayloadBadOffset`, `ReadPayloadBadLength` 等测试用例覆盖了这些情况。
   * **调试线索:** 解析 NTLM 消息失败，检查 `SecurityBuffer` 的 `length` 和 `offset` 字段是否合理。

3. **未正确处理 `Read` 方法的返回值:**
   * **示例:**  假设 `ReadUInt32` 一定会成功，而没有检查其返回值，当缓冲区剩余空间不足时，会导致未定义的行为。
   * **调试线索:**  程序逻辑错误，例如使用了未被正确赋值的变量。

4. **假设 NTLM 消息的结构总是符合预期:**
   * **示例:**  假设目标信息中一定包含某个特定的 AV Pair，但实际情况并非如此。
   * **调试线索:**  解析出的信息不完整或不正确，仔细检查 NTLM 协议规范以及服务器返回的实际数据。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在使用 Chromium 浏览器访问一个需要 NTLM 认证的内部网站时遇到问题，例如无法登录或页面加载失败。以下是如何逐步到达 `ntlm_buffer_reader_unittest.cc` 代码的可能路径：

1. **用户尝试访问内部网站 (输入网址或点击链接)。**
2. **浏览器发起 HTTP 请求。**
3. **服务器返回需要 NTLM 认证的响应 (401 Unauthorized)。**
4. **Chromium 网络栈开始处理 NTLM 认证流程。**
5. **在处理服务器返回的 NTLM Challenge 消息时，相关的 C++ 代码会被调用。**
6. **如果解析 Challenge 消息的过程中出现错误 (例如，缓冲区数据格式不符合预期)，开发人员可能会怀疑 `NtlmBufferReader` 的实现是否存在 bug。**
7. **为了验证 `NtlmBufferReader` 的正确性，开发人员会运行 `ntlm_buffer_reader_unittest.cc` 中的单元测试。**
8. **如果某个单元测试失败，表明 `NtlmBufferReader` 在处理特定类型的输入时存在问题。**
9. **开发人员会查看失败的测试用例，分析其输入和预期输出，从而定位 `NtlmBufferReader` 代码中的错误。**
10. **开发人员可能会编写新的测试用例来复现用户遇到的问题，以便更好地调试和修复 bug。**

因此，虽然用户本身不会直接接触到 `ntlm_buffer_reader_unittest.cc` 这个文件，但他们遇到的 NTLM 认证问题可能会促使开发人员使用这个单元测试文件来诊断和解决底层 C++ 代码中的问题。这个文件是开发人员保证 `NtlmBufferReader` 功能正确性的重要工具。

### 提示词
```
这是目录为net/ntlm/ntlm_buffer_reader_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/ntlm/ntlm_buffer_reader.h"

#include "base/strings/utf_string_conversions.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net::ntlm {

TEST(NtlmBufferReaderTest, Initialization) {
  const uint8_t buf[1] = {0};
  NtlmBufferReader reader(buf);

  ASSERT_EQ(std::size(buf), reader.GetLength());
  ASSERT_EQ(0u, reader.GetCursor());
  ASSERT_FALSE(reader.IsEndOfBuffer());
  ASSERT_TRUE(reader.CanRead(1));
  ASSERT_FALSE(reader.CanRead(2));
  ASSERT_TRUE(reader.CanReadFrom(0, 1));
  ASSERT_TRUE(reader.CanReadFrom(SecurityBuffer(0, 1)));
  ASSERT_FALSE(reader.CanReadFrom(1, 1));
  ASSERT_FALSE(reader.CanReadFrom(SecurityBuffer(1, 1)));
  ASSERT_FALSE(reader.CanReadFrom(0, 2));
  ASSERT_FALSE(reader.CanReadFrom(SecurityBuffer(0, 2)));

  // With length=0 the offset can be out of bounds.
  ASSERT_TRUE(reader.CanReadFrom(99, 0));
  ASSERT_TRUE(reader.CanReadFrom(SecurityBuffer(99, 0)));
}

TEST(NtlmBufferReaderTest, EmptyBuffer) {
  std::vector<uint8_t> b;
  NtlmBufferReader reader(b);

  ASSERT_EQ(0u, reader.GetCursor());
  ASSERT_EQ(0u, reader.GetLength());
  ASSERT_TRUE(reader.CanRead(0));
  ASSERT_FALSE(reader.CanRead(1));
  ASSERT_TRUE(reader.IsEndOfBuffer());

  // A read from an empty (zero-byte) source into an empty (zero-byte)
  // destination buffer should succeed as a no-op.
  std::vector<uint8_t> dest;
  ASSERT_TRUE(reader.ReadBytes(dest));

  // A read from a non-empty source into an empty (zero-byte) destination
  // buffer should succeed as a no-op.
  std::vector<uint8_t> b2{0x01};
  NtlmBufferReader reader2(b2);
  ASSERT_EQ(0u, reader2.GetCursor());
  ASSERT_EQ(1u, reader2.GetLength());

  ASSERT_TRUE(reader2.CanRead(0));
  ASSERT_TRUE(reader2.ReadBytes(dest));

  ASSERT_EQ(0u, reader2.GetCursor());
  ASSERT_EQ(1u, reader2.GetLength());
}

TEST(NtlmBufferReaderTest, NullBuffer) {
  NtlmBufferReader reader;

  ASSERT_EQ(0u, reader.GetCursor());
  ASSERT_EQ(0u, reader.GetLength());
  ASSERT_TRUE(reader.CanRead(0));
  ASSERT_FALSE(reader.CanRead(1));
  ASSERT_TRUE(reader.IsEndOfBuffer());

  // A read from a null source into an empty (zero-byte) destination buffer
  // should succeed as a no-op.
  std::vector<uint8_t> dest;
  ASSERT_TRUE(reader.ReadBytes(dest));
}

TEST(NtlmBufferReaderTest, Read16) {
  const uint8_t buf[2] = {0x22, 0x11};
  const uint16_t expected = 0x1122;

  NtlmBufferReader reader(buf);

  uint16_t actual;
  ASSERT_TRUE(reader.ReadUInt16(&actual));
  ASSERT_EQ(expected, actual);
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.ReadUInt16(&actual));
}

TEST(NtlmBufferReaderTest, Read32) {
  const uint8_t buf[4] = {0x44, 0x33, 0x22, 0x11};
  const uint32_t expected = 0x11223344;

  NtlmBufferReader reader(buf);

  uint32_t actual;
  ASSERT_TRUE(reader.ReadUInt32(&actual));
  ASSERT_EQ(expected, actual);
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.ReadUInt32(&actual));
}

TEST(NtlmBufferReaderTest, Read64) {
  const uint8_t buf[8] = {0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
  const uint64_t expected = 0x1122334455667788;

  NtlmBufferReader reader(buf);

  uint64_t actual;
  ASSERT_TRUE(reader.ReadUInt64(&actual));
  ASSERT_EQ(expected, actual);
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.ReadUInt64(&actual));
}

TEST(NtlmBufferReaderTest, ReadBytes) {
  const uint8_t expected[8] = {0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
  uint8_t actual[8];

  NtlmBufferReader reader(expected);

  ASSERT_TRUE(reader.ReadBytes(actual));
  ASSERT_EQ(0, memcmp(actual, expected, std::size(actual)));
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.ReadBytes(base::make_span(actual, 1u)));
}

TEST(NtlmBufferReaderTest, ReadSecurityBuffer) {
  const uint8_t buf[8] = {0x22, 0x11, 0xFF, 0xEE, 0x88, 0x77, 0x66, 0x55};
  const uint16_t length = 0x1122;
  const uint32_t offset = 0x55667788;

  NtlmBufferReader reader(buf);

  SecurityBuffer sec_buf;
  ASSERT_TRUE(reader.ReadSecurityBuffer(&sec_buf));
  ASSERT_EQ(length, sec_buf.length);
  ASSERT_EQ(offset, sec_buf.offset);
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.ReadSecurityBuffer(&sec_buf));
}

TEST(NtlmBufferReaderTest, ReadSecurityBufferPastEob) {
  const uint8_t buf[7] = {0};
  NtlmBufferReader reader(buf);

  SecurityBuffer sec_buf;
  ASSERT_FALSE(reader.ReadSecurityBuffer(&sec_buf));
}

TEST(NtlmBufferReaderTest, ReadPayloadAsBufferReader) {
  const uint8_t buf[8] = {0xff, 0xff, 0x11, 0x22, 0x33, 0x44, 0xff, 0xff};
  const uint32_t expected = 0x44332211;
  NtlmBufferReader reader(buf);
  ASSERT_EQ(0u, reader.GetCursor());

  // Create a security buffer with offset 2 and length 4.
  SecurityBuffer sec_buf(2, 4);
  NtlmBufferReader sub_reader;
  ASSERT_EQ(0u, sub_reader.GetLength());
  ASSERT_EQ(0u, sub_reader.GetCursor());

  // Read the 4 non-0xff bytes from the middle of |buf|.
  ASSERT_TRUE(reader.ReadPayloadAsBufferReader(sec_buf, &sub_reader));

  // |reader| cursor should not move.
  ASSERT_EQ(0u, reader.GetCursor());
  ASSERT_EQ(sec_buf.length, sub_reader.GetLength());
  ASSERT_EQ(0u, sub_reader.GetCursor());

  // Read from the payload in |sub_reader|.
  uint32_t actual;
  ASSERT_TRUE(sub_reader.ReadUInt32(&actual));
  ASSERT_EQ(expected, actual);
  ASSERT_TRUE(sub_reader.IsEndOfBuffer());
}

TEST(NtlmBufferReaderTest, ReadPayloadBadOffset) {
  const uint8_t buf[4] = {0};
  NtlmBufferReader reader(buf);

  NtlmBufferReader sub_reader;
  ASSERT_FALSE(
      reader.ReadPayloadAsBufferReader(SecurityBuffer(4, 1), &sub_reader));
}

TEST(NtlmBufferReaderTest, ReadPayloadBadLength) {
  const uint8_t buf[4] = {0};
  NtlmBufferReader reader(buf);

  NtlmBufferReader sub_reader;
  ASSERT_FALSE(
      reader.ReadPayloadAsBufferReader(SecurityBuffer(3, 2), &sub_reader));
}

TEST(NtlmBufferReaderTest, SkipSecurityBuffer) {
  const uint8_t buf[kSecurityBufferLen] = {0};

  NtlmBufferReader reader(buf);
  ASSERT_TRUE(reader.SkipSecurityBuffer());
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.SkipSecurityBuffer());
}

TEST(NtlmBufferReaderTest, SkipSecurityBufferPastEob) {
  // The buffer is one byte shorter than security buffer.
  const uint8_t buf[kSecurityBufferLen - 1] = {0};

  NtlmBufferReader reader(buf);
  ASSERT_FALSE(reader.SkipSecurityBuffer());
}

TEST(NtlmBufferReaderTest, SkipSecurityBufferWithValidationEmpty) {
  const uint8_t buf[kSecurityBufferLen] = {0, 0, 0, 0, 0, 0, 0, 0};

  NtlmBufferReader reader(buf);
  ASSERT_TRUE(reader.SkipSecurityBufferWithValidation());
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.SkipSecurityBufferWithValidation());
}

TEST(NtlmBufferReaderTest, SkipSecurityBufferWithValidationValid) {
  // A valid security buffer that points to the 1 payload byte.
  const uint8_t buf[kSecurityBufferLen + 1] = {
      0x01, 0, 0x01, 0, kSecurityBufferLen, 0, 0, 0, 0xFF};

  NtlmBufferReader reader(buf);
  ASSERT_TRUE(reader.SkipSecurityBufferWithValidation());
  ASSERT_EQ(kSecurityBufferLen, reader.GetCursor());
  ASSERT_FALSE(reader.SkipSecurityBufferWithValidation());
}

TEST(NtlmBufferReaderTest,
     SkipSecurityBufferWithValidationPayloadLengthPastEob) {
  // Security buffer with length that points past the end of buffer.
  const uint8_t buf[kSecurityBufferLen + 1] = {
      0x02, 0, 0x02, 0, kSecurityBufferLen, 0, 0, 0, 0xFF};

  NtlmBufferReader reader(buf);
  ASSERT_FALSE(reader.SkipSecurityBufferWithValidation());
}

TEST(NtlmBufferReaderTest,
     SkipSecurityBufferWithValidationPayloadOffsetPastEob) {
  // Security buffer with offset that points past the end of buffer.
  const uint8_t buf[kSecurityBufferLen + 1] = {
      0x02, 0, 0x02, 0, kSecurityBufferLen + 1, 0, 0, 0, 0xFF};

  NtlmBufferReader reader(buf);
  ASSERT_FALSE(reader.SkipSecurityBufferWithValidation());
}

TEST(NtlmBufferReaderTest,
     SkipSecurityBufferWithValidationZeroLengthPayloadOffsetPastEob) {
  // Security buffer with offset that points past the end of buffer but
  // length is 0.
  const uint8_t buf[kSecurityBufferLen] = {0, 0, 0, 0, kSecurityBufferLen + 1,
                                           0, 0, 0};

  NtlmBufferReader reader(buf);
  ASSERT_TRUE(reader.SkipSecurityBufferWithValidation());
  ASSERT_EQ(kSecurityBufferLen, reader.GetCursor());
}

TEST(NtlmBufferReaderTest, SkipBytes) {
  const uint8_t buf[8] = {0};

  NtlmBufferReader reader(buf);

  ASSERT_TRUE(reader.SkipBytes(std::size(buf)));
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.SkipBytes(std::size(buf)));
}

TEST(NtlmBufferReaderTest, SkipBytesPastEob) {
  const uint8_t buf[8] = {0};

  NtlmBufferReader reader(buf);

  ASSERT_FALSE(reader.SkipBytes(std::size(buf) + 1));
}

TEST(NtlmBufferReaderTest, MatchSignatureTooShort) {
  const uint8_t buf[7] = {0};

  NtlmBufferReader reader(buf);

  ASSERT_TRUE(reader.CanRead(7));
  ASSERT_FALSE(reader.MatchSignature());
}

TEST(NtlmBufferReaderTest, MatchSignatureNoMatch) {
  // The last byte should be a 0.
  const uint8_t buf[8] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0xff};
  NtlmBufferReader reader(buf);

  ASSERT_TRUE(reader.CanRead(8));
  ASSERT_FALSE(reader.MatchSignature());
}

TEST(NtlmBufferReaderTest, MatchSignatureOk) {
  const uint8_t buf[8] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
  NtlmBufferReader reader(buf);

  ASSERT_TRUE(reader.MatchSignature());
  ASSERT_TRUE(reader.IsEndOfBuffer());
}

TEST(NtlmBufferReaderTest, ReadInvalidMessageType) {
  // Only 0x01, 0x02, and 0x03 are valid message types.
  const uint8_t buf[4] = {0x04, 0, 0, 0};
  NtlmBufferReader reader(buf);

  MessageType message_type;
  ASSERT_FALSE(reader.ReadMessageType(&message_type));
}

TEST(NtlmBufferReaderTest, ReadMessageTypeNegotiate) {
  const uint8_t buf[4] = {static_cast<uint8_t>(MessageType::kNegotiate), 0, 0,
                          0};
  NtlmBufferReader reader(buf);

  MessageType message_type;
  ASSERT_TRUE(reader.ReadMessageType(&message_type));
  ASSERT_EQ(MessageType::kNegotiate, message_type);
  ASSERT_TRUE(reader.IsEndOfBuffer());
}

TEST(NtlmBufferReaderTest, ReadMessageTypeChallenge) {
  const uint8_t buf[4] = {static_cast<uint8_t>(MessageType::kChallenge), 0, 0,
                          0};
  NtlmBufferReader reader(buf);

  MessageType message_type;
  ASSERT_TRUE(reader.ReadMessageType(&message_type));
  ASSERT_EQ(MessageType::kChallenge, message_type);
  ASSERT_TRUE(reader.IsEndOfBuffer());
}

TEST(NtlmBufferReaderTest, ReadTargetInfoEolOnly) {
  // Buffer contains only an EOL terminator.
  const uint8_t buf[4] = {0, 0, 0, 0};

  NtlmBufferReader reader(buf);

  std::vector<AvPair> av_pairs;
  ASSERT_TRUE(reader.ReadTargetInfo(std::size(buf), &av_pairs));
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_TRUE(av_pairs.empty());
}

TEST(NtlmBufferReaderTest, ReadTargetInfoEmpty) {
  NtlmBufferReader reader;

  std::vector<AvPair> av_pairs;
  ASSERT_TRUE(reader.ReadTargetInfo(0, &av_pairs));
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_TRUE(av_pairs.empty());
}

TEST(NtlmBufferReaderTest, ReadTargetInfoTimestampAndEolOnly) {
  // Buffer contains a timestamp av pair and an EOL terminator.
  const uint8_t buf[16] = {0x07, 0,    0x08, 0,    0x11, 0x22, 0x33, 0x44,
                           0x55, 0x66, 0x77, 0x88, 0,    0,    0,    0};
  const uint64_t expected_timestamp = 0x8877665544332211;

  NtlmBufferReader reader(buf);

  std::vector<AvPair> av_pairs;
  ASSERT_TRUE(reader.ReadTargetInfo(std::size(buf), &av_pairs));
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_EQ(1u, av_pairs.size());

  // Verify the timestamp av pair.
  ASSERT_EQ(TargetInfoAvId::kTimestamp, av_pairs[0].avid);
  ASSERT_EQ(sizeof(uint64_t), av_pairs[0].avlen);
  ASSERT_EQ(sizeof(uint64_t), av_pairs[0].buffer.size());
  ASSERT_EQ(expected_timestamp, av_pairs[0].timestamp);
}

TEST(NtlmBufferReaderTest, ReadTargetInfoFlagsAndEolOnly) {
  // Buffer contains a flags av pair with the MIC bit and an EOL terminator.
  const uint8_t buf[12] = {0x06, 0, 0x04, 0, 0x02, 0, 0, 0, 0, 0, 0, 0};

  NtlmBufferReader reader(buf);

  std::vector<AvPair> av_pairs;
  ASSERT_TRUE(reader.ReadTargetInfo(std::size(buf), &av_pairs));
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_EQ(1u, av_pairs.size());

  // Verify the flags av pair.
  ASSERT_EQ(TargetInfoAvId::kFlags, av_pairs[0].avid);
  ASSERT_EQ(sizeof(TargetInfoAvFlags), av_pairs[0].avlen);
  ASSERT_EQ(TargetInfoAvFlags::kMicPresent, av_pairs[0].flags);
}

TEST(NtlmBufferReaderTest, ReadTargetInfoTooSmall) {
  // Target info must least contain enough space for a terminator pair.
  const uint8_t buf[3] = {0};

  NtlmBufferReader reader(buf);

  std::vector<AvPair> av_pairs;
  ASSERT_FALSE(reader.ReadTargetInfo(std::size(buf), &av_pairs));
}

TEST(NtlmBufferReaderTest, ReadTargetInfoInvalidTimestampSize) {
  // Timestamps must be 64 bits/8 bytes. A timestamp av pair with a
  // different length is invalid.
  const uint8_t buf[15] = {0x07, 0,    0x07, 0, 0x11, 0x22, 0x33, 0x44,
                           0x55, 0x66, 0x77, 0, 0,    0,    0};

  NtlmBufferReader reader(buf);

  std::vector<AvPair> av_pairs;
  ASSERT_FALSE(reader.ReadTargetInfo(std::size(buf), &av_pairs));
}

TEST(NtlmBufferReaderTest, ReadTargetInfoInvalidTimestampPastEob) {
  // The timestamp avlen is correct but would read past the end of the buffer.
  const uint8_t buf[11] = {0x07, 0,    0x08, 0,    0x11, 0x22,
                           0x33, 0x44, 0x55, 0x66, 0x77};

  NtlmBufferReader reader(buf);

  std::vector<AvPair> av_pairs;
  ASSERT_FALSE(reader.ReadTargetInfo(std::size(buf), &av_pairs));
}

TEST(NtlmBufferReaderTest, ReadTargetInfoOtherField) {
  // A domain name AvPair containing the string L'ABCD' followed by
  // a terminating AvPair.
  const uint8_t buf[16] = {0x02, 0, 0x08, 0, 'A', 0, 'B', 0,
                           'C',  0, 'D',  0, 0,   0, 0,   0};

  NtlmBufferReader reader(buf);

  std::vector<AvPair> av_pairs;
  ASSERT_TRUE(reader.ReadTargetInfo(std::size(buf), &av_pairs));
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_EQ(1u, av_pairs.size());

  // Verify the domain name AvPair.
  ASSERT_EQ(TargetInfoAvId::kDomainName, av_pairs[0].avid);
  ASSERT_EQ(8, av_pairs[0].avlen);
  ASSERT_EQ(0, memcmp(buf + 4, av_pairs[0].buffer.data(), 8));
}

TEST(NtlmBufferReaderTest, ReadTargetInfoNoTerminator) {
  // A domain name AvPair containing the string L'ABCD' but there is no
  // terminating AvPair.
  const uint8_t buf[12] = {0x02, 0, 0x08, 0, 'A', 0, 'B', 0, 'C', 0, 'D', 0};

  NtlmBufferReader reader(buf);

  std::vector<AvPair> av_pairs;
  ASSERT_FALSE(reader.ReadTargetInfo(std::size(buf), &av_pairs));
}

TEST(NtlmBufferReaderTest, ReadTargetInfoTerminatorAtLocationOtherThanEnd) {
  // Target info contains [flags, terminator, domain, terminator]. This
  // should fail because the terminator should only appear at the end.
  const uint8_t buf[] = {0x06, 0, 0x04, 0, 0x02, 0, 0,   0, 0,   0,
                         0,    0, 0x02, 0, 0x08, 0, 'A', 0, 'B', 0,
                         'C',  0, 'D',  0, 0,    0, 0,   0};

  NtlmBufferReader reader(buf);

  std::vector<AvPair> av_pairs;
  ASSERT_FALSE(reader.ReadTargetInfo(std::size(buf), &av_pairs));
}

TEST(NtlmBufferReaderTest, ReadTargetInfoTerminatorNonZeroLength) {
  // A flags Av Pair followed by a terminator pair with a non-zero length.
  const uint8_t buf[] = {0x06, 0, 0x04, 0, 0x02, 0, 0, 0, 0, 0, 0x01, 0};

  NtlmBufferReader reader(buf);

  std::vector<AvPair> av_pairs;
  ASSERT_FALSE(reader.ReadTargetInfo(std::size(buf), &av_pairs));
}

TEST(NtlmBufferReaderTest, ReadTargetInfoTerminatorNonZeroLength2) {
  // A flags Av Pair followed by a terminator pair with a non-zero length,
  // but otherwise in bounds payload. Terminator pairs must have zero
  // length, so this is not valid.
  const uint8_t buf[] = {0x06, 0,    0x04, 0,    0x02, 0, 0, 0, 0,
                         0,    0x01, 0,    0xff, 0,    0, 0, 0};

  NtlmBufferReader reader(buf);

  std::vector<AvPair> av_pairs;
  ASSERT_FALSE(reader.ReadTargetInfo(std::size(buf), &av_pairs));
}

TEST(NtlmBufferReaderTest, ReadTargetInfoEmptyPayload) {
  // Security buffer with no payload.
  const uint8_t buf[] = {0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00};

  NtlmBufferReader reader(buf);

  std::vector<AvPair> av_pairs;
  ASSERT_TRUE(reader.ReadTargetInfoPayload(&av_pairs));
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_TRUE(av_pairs.empty());
}

TEST(NtlmBufferReaderTest, ReadTargetInfoEolOnlyPayload) {
  // Security buffer with an EOL payload
  const uint8_t buf[] = {0x04, 0x00, 0x04, 0x00, 0x08, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  NtlmBufferReader reader(buf);

  std::vector<AvPair> av_pairs;
  ASSERT_TRUE(reader.ReadTargetInfoPayload(&av_pairs));
  ASSERT_FALSE(reader.IsEndOfBuffer());

  // Should only have advanced over the security buffer.
  ASSERT_EQ(kSecurityBufferLen, reader.GetCursor());
  ASSERT_TRUE(av_pairs.empty());
}

TEST(NtlmBufferReaderTest, ReadTargetInfoTooShortPayload) {
  // Security buffer with a payload too small to contain any pairs.
  const uint8_t buf[] = {0x03, 0x00, 0x03, 0x00, 0x08, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00};

  NtlmBufferReader reader(buf);

  std::vector<AvPair> av_pairs;
  ASSERT_FALSE(reader.ReadTargetInfoPayload(&av_pairs));
}

TEST(NtlmBufferReaderTest, ReadTargetInfoFlagsPayload) {
  // Security buffer followed by a 12 byte payload containing a flags AvPair
  // with the MIC bit, followed by a terminator pair.
  const uint8_t buf[] = {0x0c, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x00,
                         0x00, 0x06, 0,    0x04, 0,    0x02, 0,
                         0,    0,    0,    0,    0,    0};

  NtlmBufferReader reader(buf);

  std::vector<AvPair> av_pairs;
  ASSERT_TRUE(reader.ReadTargetInfoPayload(&av_pairs));
  ASSERT_FALSE(reader.IsEndOfBuffer());

  // Should only have advanced over the security buffer.
  ASSERT_EQ(kSecurityBufferLen, reader.GetCursor());

  // Contains a single flags AVPair containing the MIC bit.
  ASSERT_EQ(1u, av_pairs.size());
  ASSERT_EQ(TargetInfoAvFlags::kMicPresent, av_pairs[0].flags);
}

TEST(NtlmBufferReaderTest, ReadTargetInfoFlagsPayloadWithPaddingBetween) {
  // Security buffer followed by a 12 byte payload containing a flags AvPair
  // with the MIC bit, followed by a terminator pair. 5 bytes of 0xff padding
  // are between the SecurityBuffer and the payload to test when the payload
  // is not contiguous.
  const uint8_t buf[] = {0x0c, 0x00, 0x0c, 0x00, 0x0c, 0x00, 0x00, 0x00,
                         0xff, 0xff, 0xff, 0xff, 0x06, 0,    0x04, 0,
                         0x02, 0,    0,    0,    0,    0,    0,    0};
  NtlmBufferReader reader(buf);

  std::vector<AvPair> av_pairs;
  ASSERT_TRUE(reader.ReadTargetInfoPayload(&av_pairs));
  ASSERT_FALSE(reader.IsEndOfBuffer());

  // Should only have advanced over the security buffer.
  ASSERT_EQ(kSecurityBufferLen, reader.GetCursor());

  // Contains a single flags AVPair containing the MIC bit.
  ASSERT_EQ(1u, av_pairs.size());
  ASSERT_EQ(TargetInfoAvFlags::kMicPresent, av_pairs[0].flags);
}

TEST(NtlmBufferReaderTest, ReadMessageTypeAuthenticate) {
  const uint8_t buf[4] = {static_cast<uint8_t>(MessageType::kAuthenticate), 0,
                          0, 0};
  NtlmBufferReader reader(buf);

  MessageType message_type;
  ASSERT_TRUE(reader.ReadMessageType(&message_type));
  ASSERT_EQ(MessageType::kAuthenticate, message_type);
  ASSERT_TRUE(reader.IsEndOfBuffer());
}

TEST(NtlmBufferReaderTest, MatchMessageTypeAuthenticate) {
  const uint8_t buf[4] = {static_cast<uint8_t>(MessageType::kAuthenticate), 0,
                          0, 0};
  NtlmBufferReader reader(buf);

  ASSERT_TRUE(reader.MatchMessageType(MessageType::kAuthenticate));
  ASSERT_TRUE(reader.IsEndOfBuffer());
}

TEST(NtlmBufferReaderTest, MatchMessageTypeInvalid) {
  // Only 0x01, 0x02, and 0x03 are valid message types.
  const uint8_t buf[4] = {0x04, 0, 0, 0};
  NtlmBufferReader reader(buf);

  ASSERT_FALSE(reader.MatchMessageType(MessageType::kAuthenticate));
}

TEST(NtlmBufferReaderTest, MatchMessageTypeMismatch) {
  const uint8_t buf[4] = {static_cast<uint8_t>(MessageType::kChallenge), 0, 0,
                          0};
  NtlmBufferReader reader(buf);

  ASSERT_FALSE(reader.MatchMessageType(MessageType::kAuthenticate));
}

TEST(NtlmBufferReaderTest, MatchAuthenticateHeader) {
  const uint8_t buf[12] = {
      'N', 'T', 'L',
      'M', 'S', 'S',
      'P', 0,   static_cast<uint8_t>(MessageType::kAuthenticate),
      0,   0,   0};
  NtlmBufferReader reader(buf);

  ASSERT_TRUE(reader.MatchMessageHeader(MessageType::kAuthenticate));
  ASSERT_TRUE(reader.IsEndOfBuffer());
}

TEST(NtlmBufferReaderTest, MatchAuthenticateHeaderMisMatch) {
  const uint8_t buf[12] = {
      'N', 'T', 'L',
      'M', 'S', 'S',
      'P', 0,   static_cast<uint8_t>(MessageType::kChallenge),
      0,   0,   0};
  NtlmBufferReader reader(buf);

  ASSERT_FALSE(reader.MatchMessageType(MessageType::kAuthenticate));
}

TEST(NtlmBufferReaderTest, MatchZeros) {
  const uint8_t buf[6] = {0, 0, 0, 0, 0, 0};

  NtlmBufferReader reader(buf);

  ASSERT_TRUE(reader.MatchZeros(std::size(buf)));
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.MatchZeros(1));
}

TEST(NtlmBufferReaderTest, MatchZerosFail) {
  const uint8_t buf[6] = {0, 0, 0, 0, 0, 0xFF};

  NtlmBufferReader reader(buf);

  ASSERT_FALSE(reader.MatchZeros(std::size(buf)));
}

TEST(NtlmBufferReaderTest, MatchEmptySecurityBuffer) {
  const uint8_t buf[kSecurityBufferLen] = {0, 0, 0, 0, 0, 0, 0, 0};

  NtlmBufferReader reader(buf);

  ASSERT_TRUE(reader.MatchEmptySecurityBuffer());
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.MatchEmptySecurityBuffer());
}

TEST(NtlmBufferReaderTest, MatchEmptySecurityBufferLengthZeroOffsetEnd) {
  const uint8_t buf[kSecurityBufferLen] = {0, 0, 0, 0, 0x08, 0, 0, 0};

  NtlmBufferReader reader(buf);

  ASSERT_TRUE(reader.MatchEmptySecurityBuffer());
  ASSERT_TRUE(reader.IsEndOfBuffer());
}

TEST(NtlmBufferReaderTest, MatchEmptySecurityBufferLengthZeroPastEob) {
  const uint8_t buf[kSecurityBufferLen] = {0, 0, 0, 0, 0x09, 0, 0, 0};

  NtlmBufferReader reader(buf);

  ASSERT_FALSE(reader.MatchEmptySecurityBuffer());
}

TEST(NtlmBufferReaderTest, MatchEmptySecurityBufferLengthNonZeroLength) {
  const uint8_t buf[kSecurityBufferLen + 1] = {0x01, 0, 0, 0,   0x08,
                                               0,    0, 0, 0xff};

  NtlmBufferReader reader(buf);

  ASSERT_FALSE(reader.MatchEmptySecurityBuffer());
}

TEST(NtlmBufferReaderTest, ReadAvPairHeader) {
  const uint8_t buf[4] = {0x06, 0x00, 0x11, 0x22};

  NtlmBufferReader reader(buf);

  TargetInfoAvId actual_avid;
  uint16_t actual_avlen;
  ASSERT_TRUE(reader.ReadAvPairHeader(&actual_avid, &actual_avlen));
  ASSERT_EQ(TargetInfoAvId::kFlags, actual_avid);
  ASSERT_EQ(0x2211, actual_avlen);
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.ReadAvPairHeader(&actual_avid, &actual_avlen));
}

TEST(NtlmBufferReaderTest, ReadAvPairHeaderPastEob) {
  const uint8_t buf[3] = {0x06, 0x00, 0x11};

  NtlmBufferReader reader(buf);

  TargetInfoAvId avid;
  uint16_t avlen;
  ASSERT_FALSE(reader.ReadAvPairHeader(&avid, &avlen));
}

}  // namespace net::ntlm
```
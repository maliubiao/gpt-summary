Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The primary goal is to understand the functionality of `quic_data_writer_test.cc`. This usually involves determining what class or functionality is being tested and how the tests are structured.

2. **Identify the Target Class:** The filename itself is a strong indicator: `quic_data_writer_test.cc`. The inclusion of `#include "quiche/quic/core/quic_data_writer.h"` confirms that the tests are for the `QuicDataWriter` class.

3. **Infer `QuicDataWriter`'s Purpose:** Based on the name, `QuicDataWriter` likely handles writing data in a specific format, probably for the QUIC protocol. Keywords like "data," "write," and "QUIC" point to this.

4. **Examine the Test Structure:**
    * **Includes:**  The included headers provide context. `cstdint`, `cstring`, `string`, `vector` are standard C++ headers. Headers starting with `quiche/quic/` are specific to the QUIC implementation. `quiche_endian.h` suggests handling byte order. `quic_test.h` and `quic_test_utils.h` indicate a testing framework.
    * **Namespaces:** The code is within `quic::test`. This is a common practice to organize test code.
    * **Test Fixture:** `class QuicDataWriterTest : public QuicTestWithParam<TestParams> {};` indicates the use of a parameterized test fixture. This means the tests will be run with different parameter values (in this case, endianness).
    * **Parameterization:** The `TestParams` struct and `GetTestParams()` function show that the tests are run with both network byte order and host byte order. This is crucial for network protocols.
    * **Individual Tests:**  Look for `TEST_P` macros. Each `TEST_P` defines a specific test case. The names of the tests (`SanityCheckUFloat16Consts`, `WriteUFloat16`, `ReadUFloat16`, etc.) give clues about what functionality is being tested.
    * **Assertions:** Inside the tests, look for `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_LT`, `EXPECT_GT`, etc. These are assertion macros that check if the code behaves as expected.

5. **Analyze Individual Test Cases (Iterative Process):**  Go through the tests one by one and understand what they are verifying. Look for:
    * **Setup:**  How is the `QuicDataWriter` initialized? What input data is used?
    * **Action:** What methods of `QuicDataWriter` are being called?
    * **Verification:** What are the expected outputs? How are the results being compared?

6. **Identify Key Functionalities Based on Test Names:**
    * `WriteUFloat16`, `ReadUFloat16`, `RoundTripUFloat16`: Testing writing and reading of a specific floating-point format (`UFloat16`).
    * `WriteConnectionId`, `LengthPrefixedConnectionId`: Testing writing connection IDs, with and without a length prefix.
    * `WriteTag`: Testing writing a 4-byte tag.
    * `Write16BitUnsignedIntegers`, `Write24BitUnsignedIntegers`, etc.: Testing writing unsigned integers of different sizes.
    * `WriteBytes`: Testing writing raw byte arrays.
    * `StreamId1`, `WriteVarInt62`, `PeekVarInt62Length`: Testing writing and reading variable-length integers (often used for stream IDs).
    * `Seek`: Testing the ability to move the write pointer within the buffer.
    * `PayloadReads`: Testing reading the payload using `QuicDataReader`.
    * `StringPieceVarInt62`: Testing writing a string with a preceding variable-length integer indicating its length.
    * `WriteRandomBytes`, `WriteInsecureRandomBytes`: Testing writing random data.

7. **Relate to JavaScript (if applicable):**  Consider where these functionalities might be relevant in a browser or web context involving JavaScript:
    * **Data Serialization:**  JavaScript often needs to serialize data to send over a network. Understanding how `QuicDataWriter` handles different data types (integers, strings, custom formats) is relevant. Think of `JSON.stringify()` as a higher-level serialization mechanism.
    * **Network Communication:** QUIC is a transport protocol used in web browsers. JavaScript interacting with network APIs will implicitly rely on the underlying networking stack, including components like `QuicDataWriter`.
    * **Binary Data Handling:**  JavaScript has `ArrayBuffer` and `DataView` for working with binary data. The concepts of byte order (endianness) are also relevant in JavaScript when dealing with binary data.

8. **Construct Examples and Scenarios:** Based on the identified functionalities, create examples illustrating how they might be used and potential errors. Think about:
    * **Input/Output:** For specific writing functions, what input leads to what byte sequence?
    * **User Errors:** What happens if the buffer is too small? What if the byte order is wrong?

9. **Trace User Operations (Debugging):** Think about how a user action in a browser might eventually lead to the execution of code involving `QuicDataWriter`. Consider the layers involved:
    * User clicks a link or enters a URL.
    * The browser resolves the domain name.
    * A connection is established (potentially using QUIC).
    * The browser sends a request (HTTP/3 over QUIC).
    * `QuicDataWriter` would be used to format the QUIC packets containing the HTTP request headers and body.

10. **Review and Refine:**  Go back through the analysis, ensuring the explanations are clear, accurate, and cover the key aspects of the file. Double-check the examples and scenarios.

This systematic approach, combining code inspection with an understanding of the underlying concepts and the broader context of web development, allows for a comprehensive analysis of the test file.
这个文件 `net/third_party/quiche/src/quiche/quic/core/quic_data_writer_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专门用于测试 `QuicDataWriter` 类的功能。 `QuicDataWriter` 的作用是将各种数据类型（如整数、连接ID、字节序列等）按照指定的格式写入到一块内存缓冲区中，以便后续通过网络发送。

**主要功能列表:**

1. **测试基本数据类型的写入:**
   - 测试写入不同大小的无符号整数 (8位, 16位, 24位, 32位, 40位, 48位, 56位, 64位)。
   - 测试写入时考虑字节序 (大端或小端)。
   - 测试写入 `UFloat16` 这种自定义的 16 位浮点数格式。

2. **测试 QUIC 特有数据结构的写入:**
   - 测试写入 `QuicConnectionId` (QUIC 连接ID)。
   - 测试写入带长度前缀的 `QuicConnectionId`。
   - 测试写入 `QuicTag` (4字节标识符)。
   - 测试写入变长整数 (`VarInt62`)，常用于表示 Stream ID 等。

3. **测试字节序列的写入:**
   - 测试写入指定长度的字节数组。
   - 测试随机字节的写入。

4. **测试写入时的边界情况和错误处理:**
   - 测试写入超过缓冲区大小的数据。
   - 测试 `Seek` 操作，即移动写入指针到缓冲区的特定位置。
   - 测试 `Seek` 操作的边界情况，例如试图移动到缓冲区之外。

5. **测试与 `QuicDataReader` 的互操作性:**
   - 许多测试用例都会写入数据后，立即使用 `QuicDataReader` 读取这些数据，验证写入和读取的一致性。

**与 JavaScript 的功能关系:**

虽然 `QuicDataWriter` 是 C++ 代码，直接在 JavaScript 环境中不可用，但它所实现的功能与 JavaScript 在网络通信中处理二进制数据息息相关。

* **数据序列化:**  在 Web 应用中，JavaScript 需要将各种数据（如数字、字符串、对象）转换为可以通过网络发送的二进制格式。虽然 JavaScript 通常使用 `JSON.stringify()` 等进行高级序列化，但在底层网络协议层面，数据最终需要被编码成字节流。`QuicDataWriter` 的功能类似于在 C++ 中实现这种底层的数据编码。

* **WebAssembly (Wasm):** 如果 Web 应用使用了 WebAssembly，那么 Wasm 模块可能会使用类似 `QuicDataWriter` 的功能来构建网络数据包。在这种情况下，JavaScript 代码会调用 Wasm 模块的函数，而 Wasm 模块内部可能会使用类似的二进制数据写入逻辑。

**举例说明:**

假设一个 JavaScript 应用需要通过 QUIC 发送一个包含 Stream ID 和一些数据的消息。

1. **JavaScript (概念性):**
   ```javascript
   const streamId = 12345;
   const data = new Uint8Array([0x01, 0x02, 0x03]);

   // 某种底层的 QUIC 库（可能是 Wasm）会处理数据编码
   const packet = new QuicPacketBuilder();
   packet.writeVarInt62(streamId);
   packet.writeBytes(data);
   const binaryPacket = packet.build();

   // 将 binaryPacket 发送出去
   sendOverQuic(binaryPacket);
   ```

2. **C++ (`QuicDataWriter` 的作用):** 在底层的 C++ QUIC 库中，`QuicDataWriter` 会负责 `packet.writeVarInt62(streamId)` 和 `packet.writeBytes(data)` 这些操作的实际实现。

   - `writeVarInt62(streamId)` 会将 `12345` 编码成变长整数的字节序列（例如 `0x80 0x71 0x39`）。
   - `writeBytes(data)` 会将 `[0x01, 0x02, 0x03]` 这三个字节直接写入缓冲区。

**逻辑推理、假设输入与输出:**

**测试用例： `TEST_P(QuicDataWriterTest, WriteUInt32)`**

**假设输入:**

- `in_memory32 = 0x11223344` (32位无符号整数)
- `GetParam().endianness = quiche::NETWORK_BYTE_ORDER` (大端字节序)
- 缓冲区 `buffer32` 的大小为 4 字节。

**逻辑推理:**

`QuicDataWriter` 会将 `0x11223344` 按照大端字节序写入 `buffer32`。大端字节序意味着高位字节在前，低位字节在后。

**预期输出:**

`buffer32` 的内容为 `{0x11, 0x22, 0x33, 0x44}`。

**假设输入:**

- `in_memory32 = 0x11223344`
- `GetParam().endianness = quiche::HOST_BYTE_ORDER` (假设主机是小端字节序)
- 缓冲区 `buffer32` 的大小为 4 字节。

**逻辑推理:**

`QuicDataWriter` 会将 `0x11223344` 按照小端字节序写入 `buffer32`。小端字节序意味着低位字节在前，高位字节在后。

**预期输出:**

`buffer32` 的内容为 `{0x44, 0x33, 0x22, 0x11}`。

**用户或编程常见的使用错误举例:**

1. **缓冲区溢出:**

   ```c++
   char buffer[4];
   QuicDataWriter writer(4, buffer);
   writer.WriteUInt64(0x1122334455667788); // 错误！需要 8 字节
   ```

   **后果:**  写入操作可能会覆盖缓冲区后面的内存，导致程序崩溃或出现不可预测的行为。

2. **字节序错误:**

   假设客户端使用小端序写入数据，而服务器期望大端序：

   **客户端 C++:**
   ```c++
   char buffer[4];
   QuicDataWriter writer(4, buffer, quiche::HOST_BYTE_ORDER);
   writer.WriteUInt32(0x11223344); // 写入 {0x44, 0x33, 0x22, 0x11} (小端)
   ```

   **服务器 C++:**
   ```c++
   char buffer[4];
   QuicDataReader reader(buffer, 4, quiche::NETWORK_BYTE_ORDER);
   uint32_t value;
   reader.ReadUInt32(&value); // 读取时会按大端解析
   ```

   **结果:** 服务器读取到的 `value` 将会是 `0x44332211`，而不是期望的 `0x11223344`，导致数据解析错误。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个使用 QUIC 协议的网站。**
2. **浏览器开始与服务器建立 QUIC 连接。**
3. **在连接建立和数据传输过程中，浏览器需要发送各种 QUIC 帧（Frame），例如:**
   - `CRYPTO` 帧（用于 TLS 握手）。
   - `STREAM` 帧（用于发送 HTTP 请求和响应数据）。
   - `ACK` 帧（用于确认接收到的数据包）。
4. **当浏览器需要构建一个 QUIC 数据包来发送这些帧时，会使用 `QuicDataWriter` 来将帧的内容写入到数据包的缓冲区中。**
   - 例如，如果要发送一个包含 HTTP 请求头的 `STREAM` 帧：
     - 首先，可能会写入 Stream ID (使用 `WriteVarInt62`)。
     - 然后，写入表示请求头长度的信息。
     - 接着，写入实际的 HTTP 请求头字节序列 (使用 `WriteBytes`)。
5. **如果在这个过程中出现问题，例如写入的数据长度计算错误，或者字节序处理不当，就可能需要在 `quic_data_writer_test.cc` 中编写或调试相关的测试用例，以验证 `QuicDataWriter` 的行为是否符合预期。**
6. **开发人员可能会设置断点在 `QuicDataWriter` 的相关方法中，例如 `WriteUInt32` 或 `WriteBytes`，来检查写入的数据和缓冲区状态。**
7. **通过查看 `quic_data_writer_test.cc` 中的测试用例，可以了解 `QuicDataWriter` 的正确用法和预期行为，从而帮助定位和修复实际网络通信中遇到的问题。**

总而言之，`quic_data_writer_test.cc` 是 QUIC 协议实现中一个非常重要的测试文件，它确保了 `QuicDataWriter` 类能够正确地将各种数据编码成网络传输所需的二进制格式，是保证 QUIC 连接稳定可靠的关键组成部分。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_data_writer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_data_writer.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/quiche_endian.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

namespace quic {
namespace test {
namespace {

char* AsChars(unsigned char* data) { return reinterpret_cast<char*>(data); }

struct TestParams {
  explicit TestParams(quiche::Endianness endianness) : endianness(endianness) {}

  quiche::Endianness endianness;
};

// Used by ::testing::PrintToStringParamName().
std::string PrintToString(const TestParams& p) {
  return absl::StrCat(
      (p.endianness == quiche::NETWORK_BYTE_ORDER ? "Network" : "Host"),
      "ByteOrder");
}

std::vector<TestParams> GetTestParams() {
  std::vector<TestParams> params;
  for (quiche::Endianness endianness :
       {quiche::NETWORK_BYTE_ORDER, quiche::HOST_BYTE_ORDER}) {
    params.push_back(TestParams(endianness));
  }
  return params;
}

class QuicDataWriterTest : public QuicTestWithParam<TestParams> {};

INSTANTIATE_TEST_SUITE_P(QuicDataWriterTests, QuicDataWriterTest,
                         ::testing::ValuesIn(GetTestParams()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicDataWriterTest, SanityCheckUFloat16Consts) {
  // Check the arithmetic on the constants - otherwise the values below make
  // no sense.
  EXPECT_EQ(30, kUFloat16MaxExponent);
  EXPECT_EQ(11, kUFloat16MantissaBits);
  EXPECT_EQ(12, kUFloat16MantissaEffectiveBits);
  EXPECT_EQ(UINT64_C(0x3FFC0000000), kUFloat16MaxValue);
}

TEST_P(QuicDataWriterTest, WriteUFloat16) {
  struct TestCase {
    uint64_t decoded;
    uint16_t encoded;
  };
  TestCase test_cases[] = {
      // Small numbers represent themselves.
      {0, 0},
      {1, 1},
      {2, 2},
      {3, 3},
      {4, 4},
      {5, 5},
      {6, 6},
      {7, 7},
      {15, 15},
      {31, 31},
      {42, 42},
      {123, 123},
      {1234, 1234},
      // Check transition through 2^11.
      {2046, 2046},
      {2047, 2047},
      {2048, 2048},
      {2049, 2049},
      // Running out of mantissa at 2^12.
      {4094, 4094},
      {4095, 4095},
      {4096, 4096},
      {4097, 4096},
      {4098, 4097},
      {4099, 4097},
      {4100, 4098},
      {4101, 4098},
      // Check transition through 2^13.
      {8190, 6143},
      {8191, 6143},
      {8192, 6144},
      {8193, 6144},
      {8194, 6144},
      {8195, 6144},
      {8196, 6145},
      {8197, 6145},
      // Half-way through the exponents.
      {0x7FF8000, 0x87FF},
      {0x7FFFFFF, 0x87FF},
      {0x8000000, 0x8800},
      {0xFFF0000, 0x8FFF},
      {0xFFFFFFF, 0x8FFF},
      {0x10000000, 0x9000},
      // Transition into the largest exponent.
      {0x1FFFFFFFFFE, 0xF7FF},
      {0x1FFFFFFFFFF, 0xF7FF},
      {0x20000000000, 0xF800},
      {0x20000000001, 0xF800},
      {0x2003FFFFFFE, 0xF800},
      {0x2003FFFFFFF, 0xF800},
      {0x20040000000, 0xF801},
      {0x20040000001, 0xF801},
      // Transition into the max value and clamping.
      {0x3FF80000000, 0xFFFE},
      {0x3FFBFFFFFFF, 0xFFFE},
      {0x3FFC0000000, 0xFFFF},
      {0x3FFC0000001, 0xFFFF},
      {0x3FFFFFFFFFF, 0xFFFF},
      {0x40000000000, 0xFFFF},
      {0xFFFFFFFFFFFFFFFF, 0xFFFF},
  };
  int num_test_cases = sizeof(test_cases) / sizeof(test_cases[0]);

  for (int i = 0; i < num_test_cases; ++i) {
    char buffer[2];
    QuicDataWriter writer(2, buffer, GetParam().endianness);
    EXPECT_TRUE(writer.WriteUFloat16(test_cases[i].decoded));
    uint16_t result = *reinterpret_cast<uint16_t*>(writer.data());
    if (GetParam().endianness == quiche::NETWORK_BYTE_ORDER) {
      result = quiche::QuicheEndian::HostToNet16(result);
    }
    EXPECT_EQ(test_cases[i].encoded, result);
  }
}

TEST_P(QuicDataWriterTest, ReadUFloat16) {
  struct TestCase {
    uint64_t decoded;
    uint16_t encoded;
  };
  TestCase test_cases[] = {
      // There are fewer decoding test cases because encoding truncates, and
      // decoding returns the smallest expansion.
      // Small numbers represent themselves.
      {0, 0},
      {1, 1},
      {2, 2},
      {3, 3},
      {4, 4},
      {5, 5},
      {6, 6},
      {7, 7},
      {15, 15},
      {31, 31},
      {42, 42},
      {123, 123},
      {1234, 1234},
      // Check transition through 2^11.
      {2046, 2046},
      {2047, 2047},
      {2048, 2048},
      {2049, 2049},
      // Running out of mantissa at 2^12.
      {4094, 4094},
      {4095, 4095},
      {4096, 4096},
      {4098, 4097},
      {4100, 4098},
      // Check transition through 2^13.
      {8190, 6143},
      {8192, 6144},
      {8196, 6145},
      // Half-way through the exponents.
      {0x7FF8000, 0x87FF},
      {0x8000000, 0x8800},
      {0xFFF0000, 0x8FFF},
      {0x10000000, 0x9000},
      // Transition into the largest exponent.
      {0x1FFE0000000, 0xF7FF},
      {0x20000000000, 0xF800},
      {0x20040000000, 0xF801},
      // Transition into the max value.
      {0x3FF80000000, 0xFFFE},
      {0x3FFC0000000, 0xFFFF},
  };
  int num_test_cases = sizeof(test_cases) / sizeof(test_cases[0]);

  for (int i = 0; i < num_test_cases; ++i) {
    uint16_t encoded_ufloat = test_cases[i].encoded;
    if (GetParam().endianness == quiche::NETWORK_BYTE_ORDER) {
      encoded_ufloat = quiche::QuicheEndian::HostToNet16(encoded_ufloat);
    }
    QuicDataReader reader(reinterpret_cast<char*>(&encoded_ufloat), 2,
                          GetParam().endianness);
    uint64_t value;
    EXPECT_TRUE(reader.ReadUFloat16(&value));
    EXPECT_EQ(test_cases[i].decoded, value);
  }
}

TEST_P(QuicDataWriterTest, RoundTripUFloat16) {
  // Just test all 16-bit encoded values. 0 and max already tested above.
  uint64_t previous_value = 0;
  for (uint16_t i = 1; i < 0xFFFF; ++i) {
    // Read the two bytes.
    uint16_t read_number = i;
    if (GetParam().endianness == quiche::NETWORK_BYTE_ORDER) {
      read_number = quiche::QuicheEndian::HostToNet16(read_number);
    }
    QuicDataReader reader(reinterpret_cast<char*>(&read_number), 2,
                          GetParam().endianness);
    uint64_t value;
    // All values must be decodable.
    EXPECT_TRUE(reader.ReadUFloat16(&value));
    // Check that small numbers represent themselves
    if (i < 4097) {
      EXPECT_EQ(i, value);
    }
    // Check there's monotonic growth.
    EXPECT_LT(previous_value, value);
    // Check that precision is within 0.5% away from the denormals.
    if (i > 2000) {
      EXPECT_GT(previous_value * 1005, value * 1000);
    }
    // Check we're always within the promised range.
    EXPECT_LT(value, UINT64_C(0x3FFC0000000));
    previous_value = value;
    char buffer[6];
    QuicDataWriter writer(6, buffer, GetParam().endianness);
    EXPECT_TRUE(writer.WriteUFloat16(value - 1));
    EXPECT_TRUE(writer.WriteUFloat16(value));
    EXPECT_TRUE(writer.WriteUFloat16(value + 1));
    // Check minimal decoding (previous decoding has previous encoding).
    uint16_t encoded1 = *reinterpret_cast<uint16_t*>(writer.data());
    uint16_t encoded2 = *reinterpret_cast<uint16_t*>(writer.data() + 2);
    uint16_t encoded3 = *reinterpret_cast<uint16_t*>(writer.data() + 4);
    if (GetParam().endianness == quiche::NETWORK_BYTE_ORDER) {
      encoded1 = quiche::QuicheEndian::NetToHost16(encoded1);
      encoded2 = quiche::QuicheEndian::NetToHost16(encoded2);
      encoded3 = quiche::QuicheEndian::NetToHost16(encoded3);
    }
    EXPECT_EQ(i - 1, encoded1);
    // Check roundtrip.
    EXPECT_EQ(i, encoded2);
    // Check next decoding.
    EXPECT_EQ(i < 4096 ? i + 1 : i, encoded3);
  }
}

TEST_P(QuicDataWriterTest, WriteConnectionId) {
  QuicConnectionId connection_id =
      TestConnectionId(UINT64_C(0x0011223344556677));
  char big_endian[] = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  };
  EXPECT_EQ(connection_id.length(), ABSL_ARRAYSIZE(big_endian));
  ASSERT_LE(connection_id.length(), 255);
  char buffer[255];
  QuicDataWriter writer(connection_id.length(), buffer, GetParam().endianness);
  EXPECT_TRUE(writer.WriteConnectionId(connection_id));
  quiche::test::CompareCharArraysWithHexError(
      "connection_id", buffer, connection_id.length(), big_endian,
      connection_id.length());

  QuicConnectionId read_connection_id;
  QuicDataReader reader(buffer, connection_id.length(), GetParam().endianness);
  EXPECT_TRUE(
      reader.ReadConnectionId(&read_connection_id, ABSL_ARRAYSIZE(big_endian)));
  EXPECT_EQ(connection_id, read_connection_id);
}

TEST_P(QuicDataWriterTest, LengthPrefixedConnectionId) {
  QuicConnectionId connection_id =
      TestConnectionId(UINT64_C(0x0011223344556677));
  char length_prefixed_connection_id[] = {
      0x08, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  };
  EXPECT_EQ(ABSL_ARRAYSIZE(length_prefixed_connection_id),
            kConnectionIdLengthSize + connection_id.length());
  char buffer[kConnectionIdLengthSize + 255] = {};
  QuicDataWriter writer(ABSL_ARRAYSIZE(buffer), buffer);
  EXPECT_TRUE(writer.WriteLengthPrefixedConnectionId(connection_id));
  quiche::test::CompareCharArraysWithHexError(
      "WriteLengthPrefixedConnectionId", buffer, writer.length(),
      length_prefixed_connection_id,
      ABSL_ARRAYSIZE(length_prefixed_connection_id));

  // Verify that writing length then connection ID produces the same output.
  memset(buffer, 0, ABSL_ARRAYSIZE(buffer));
  QuicDataWriter writer2(ABSL_ARRAYSIZE(buffer), buffer);
  EXPECT_TRUE(writer2.WriteUInt8(connection_id.length()));
  EXPECT_TRUE(writer2.WriteConnectionId(connection_id));
  quiche::test::CompareCharArraysWithHexError(
      "Write length then ConnectionId", buffer, writer2.length(),
      length_prefixed_connection_id,
      ABSL_ARRAYSIZE(length_prefixed_connection_id));

  QuicConnectionId read_connection_id;
  QuicDataReader reader(buffer, ABSL_ARRAYSIZE(buffer));
  EXPECT_TRUE(reader.ReadLengthPrefixedConnectionId(&read_connection_id));
  EXPECT_EQ(connection_id, read_connection_id);

  // Verify that reading length then connection ID produces the same output.
  uint8_t read_connection_id_length2 = 33;
  QuicConnectionId read_connection_id2;
  QuicDataReader reader2(buffer, ABSL_ARRAYSIZE(buffer));
  ASSERT_TRUE(reader2.ReadUInt8(&read_connection_id_length2));
  EXPECT_EQ(connection_id.length(), read_connection_id_length2);
  EXPECT_TRUE(reader2.ReadConnectionId(&read_connection_id2,
                                       read_connection_id_length2));
  EXPECT_EQ(connection_id, read_connection_id2);
}

TEST_P(QuicDataWriterTest, EmptyConnectionIds) {
  QuicConnectionId empty_connection_id = EmptyQuicConnectionId();
  char buffer[2];
  QuicDataWriter writer(ABSL_ARRAYSIZE(buffer), buffer, GetParam().endianness);
  EXPECT_TRUE(writer.WriteConnectionId(empty_connection_id));
  EXPECT_TRUE(writer.WriteUInt8(1));
  EXPECT_TRUE(writer.WriteConnectionId(empty_connection_id));
  EXPECT_TRUE(writer.WriteUInt8(2));
  EXPECT_TRUE(writer.WriteConnectionId(empty_connection_id));
  EXPECT_FALSE(writer.WriteUInt8(3));

  EXPECT_EQ(buffer[0], 1);
  EXPECT_EQ(buffer[1], 2);

  QuicConnectionId read_connection_id = TestConnectionId();
  uint8_t read_byte;
  QuicDataReader reader(buffer, ABSL_ARRAYSIZE(buffer), GetParam().endianness);
  EXPECT_TRUE(reader.ReadConnectionId(&read_connection_id, 0));
  EXPECT_EQ(read_connection_id, empty_connection_id);
  EXPECT_TRUE(reader.ReadUInt8(&read_byte));
  EXPECT_EQ(read_byte, 1);
  // Reset read_connection_id to something else to verify that
  // ReadConnectionId properly sets it back to empty.
  read_connection_id = TestConnectionId();
  EXPECT_TRUE(reader.ReadConnectionId(&read_connection_id, 0));
  EXPECT_EQ(read_connection_id, empty_connection_id);
  EXPECT_TRUE(reader.ReadUInt8(&read_byte));
  EXPECT_EQ(read_byte, 2);
  read_connection_id = TestConnectionId();
  EXPECT_TRUE(reader.ReadConnectionId(&read_connection_id, 0));
  EXPECT_EQ(read_connection_id, empty_connection_id);
  EXPECT_FALSE(reader.ReadUInt8(&read_byte));
}

TEST_P(QuicDataWriterTest, WriteTag) {
  char CHLO[] = {
      'C',
      'H',
      'L',
      'O',
  };
  const int kBufferLength = sizeof(QuicTag);
  char buffer[kBufferLength];
  QuicDataWriter writer(kBufferLength, buffer, GetParam().endianness);
  writer.WriteTag(kCHLO);
  quiche::test::CompareCharArraysWithHexError("CHLO", buffer, kBufferLength,
                                              CHLO, kBufferLength);

  QuicTag read_chlo;
  QuicDataReader reader(buffer, kBufferLength, GetParam().endianness);
  reader.ReadTag(&read_chlo);
  EXPECT_EQ(kCHLO, read_chlo);
}

TEST_P(QuicDataWriterTest, Write16BitUnsignedIntegers) {
  char little_endian16[] = {0x22, 0x11};
  char big_endian16[] = {0x11, 0x22};
  char buffer16[2];
  {
    uint16_t in_memory16 = 0x1122;
    QuicDataWriter writer(2, buffer16, GetParam().endianness);
    writer.WriteUInt16(in_memory16);
    quiche::test::CompareCharArraysWithHexError(
        "uint16_t", buffer16, 2,
        GetParam().endianness == quiche::NETWORK_BYTE_ORDER ? big_endian16
                                                            : little_endian16,
        2);

    uint16_t read_number16;
    QuicDataReader reader(buffer16, 2, GetParam().endianness);
    reader.ReadUInt16(&read_number16);
    EXPECT_EQ(in_memory16, read_number16);
  }

  {
    uint64_t in_memory16 = 0x0000000000001122;
    QuicDataWriter writer(2, buffer16, GetParam().endianness);
    writer.WriteBytesToUInt64(2, in_memory16);
    quiche::test::CompareCharArraysWithHexError(
        "uint16_t", buffer16, 2,
        GetParam().endianness == quiche::NETWORK_BYTE_ORDER ? big_endian16
                                                            : little_endian16,
        2);

    uint64_t read_number16;
    QuicDataReader reader(buffer16, 2, GetParam().endianness);
    reader.ReadBytesToUInt64(2, &read_number16);
    EXPECT_EQ(in_memory16, read_number16);
  }
}

TEST_P(QuicDataWriterTest, Write24BitUnsignedIntegers) {
  char little_endian24[] = {0x33, 0x22, 0x11};
  char big_endian24[] = {0x11, 0x22, 0x33};
  char buffer24[3];
  uint64_t in_memory24 = 0x0000000000112233;
  QuicDataWriter writer(3, buffer24, GetParam().endianness);
  writer.WriteBytesToUInt64(3, in_memory24);
  quiche::test::CompareCharArraysWithHexError(
      "uint24", buffer24, 3,
      GetParam().endianness == quiche::NETWORK_BYTE_ORDER ? big_endian24
                                                          : little_endian24,
      3);

  uint64_t read_number24;
  QuicDataReader reader(buffer24, 3, GetParam().endianness);
  reader.ReadBytesToUInt64(3, &read_number24);
  EXPECT_EQ(in_memory24, read_number24);
}

TEST_P(QuicDataWriterTest, Write32BitUnsignedIntegers) {
  char little_endian32[] = {0x44, 0x33, 0x22, 0x11};
  char big_endian32[] = {0x11, 0x22, 0x33, 0x44};
  char buffer32[4];
  {
    uint32_t in_memory32 = 0x11223344;
    QuicDataWriter writer(4, buffer32, GetParam().endianness);
    writer.WriteUInt32(in_memory32);
    quiche::test::CompareCharArraysWithHexError(
        "uint32_t", buffer32, 4,
        GetParam().endianness == quiche::NETWORK_BYTE_ORDER ? big_endian32
                                                            : little_endian32,
        4);

    uint32_t read_number32;
    QuicDataReader reader(buffer32, 4, GetParam().endianness);
    reader.ReadUInt32(&read_number32);
    EXPECT_EQ(in_memory32, read_number32);
  }

  {
    uint64_t in_memory32 = 0x11223344;
    QuicDataWriter writer(4, buffer32, GetParam().endianness);
    writer.WriteBytesToUInt64(4, in_memory32);
    quiche::test::CompareCharArraysWithHexError(
        "uint32_t", buffer32, 4,
        GetParam().endianness == quiche::NETWORK_BYTE_ORDER ? big_endian32
                                                            : little_endian32,
        4);

    uint64_t read_number32;
    QuicDataReader reader(buffer32, 4, GetParam().endianness);
    reader.ReadBytesToUInt64(4, &read_number32);
    EXPECT_EQ(in_memory32, read_number32);
  }
}

TEST_P(QuicDataWriterTest, Write40BitUnsignedIntegers) {
  uint64_t in_memory40 = 0x0000001122334455;
  char little_endian40[] = {0x55, 0x44, 0x33, 0x22, 0x11};
  char big_endian40[] = {0x11, 0x22, 0x33, 0x44, 0x55};
  char buffer40[5];
  QuicDataWriter writer(5, buffer40, GetParam().endianness);
  writer.WriteBytesToUInt64(5, in_memory40);
  quiche::test::CompareCharArraysWithHexError(
      "uint40", buffer40, 5,
      GetParam().endianness == quiche::NETWORK_BYTE_ORDER ? big_endian40
                                                          : little_endian40,
      5);

  uint64_t read_number40;
  QuicDataReader reader(buffer40, 5, GetParam().endianness);
  reader.ReadBytesToUInt64(5, &read_number40);
  EXPECT_EQ(in_memory40, read_number40);
}

TEST_P(QuicDataWriterTest, Write48BitUnsignedIntegers) {
  uint64_t in_memory48 = 0x0000112233445566;
  char little_endian48[] = {0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
  char big_endian48[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  char buffer48[6];
  QuicDataWriter writer(6, buffer48, GetParam().endianness);
  writer.WriteBytesToUInt64(6, in_memory48);
  quiche::test::CompareCharArraysWithHexError(
      "uint48", buffer48, 6,
      GetParam().endianness == quiche::NETWORK_BYTE_ORDER ? big_endian48
                                                          : little_endian48,
      6);

  uint64_t read_number48;
  QuicDataReader reader(buffer48, 6, GetParam().endianness);
  reader.ReadBytesToUInt64(6., &read_number48);
  EXPECT_EQ(in_memory48, read_number48);
}

TEST_P(QuicDataWriterTest, Write56BitUnsignedIntegers) {
  uint64_t in_memory56 = 0x0011223344556677;
  char little_endian56[] = {0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
  char big_endian56[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
  char buffer56[7];
  QuicDataWriter writer(7, buffer56, GetParam().endianness);
  writer.WriteBytesToUInt64(7, in_memory56);
  quiche::test::CompareCharArraysWithHexError(
      "uint56", buffer56, 7,
      GetParam().endianness == quiche::NETWORK_BYTE_ORDER ? big_endian56
                                                          : little_endian56,
      7);

  uint64_t read_number56;
  QuicDataReader reader(buffer56, 7, GetParam().endianness);
  reader.ReadBytesToUInt64(7, &read_number56);
  EXPECT_EQ(in_memory56, read_number56);
}

TEST_P(QuicDataWriterTest, Write64BitUnsignedIntegers) {
  uint64_t in_memory64 = 0x1122334455667788;
  unsigned char little_endian64[] = {0x88, 0x77, 0x66, 0x55,
                                     0x44, 0x33, 0x22, 0x11};
  unsigned char big_endian64[] = {0x11, 0x22, 0x33, 0x44,
                                  0x55, 0x66, 0x77, 0x88};
  char buffer64[8];
  QuicDataWriter writer(8, buffer64, GetParam().endianness);
  writer.WriteBytesToUInt64(8, in_memory64);
  quiche::test::CompareCharArraysWithHexError(
      "uint64_t", buffer64, 8,
      GetParam().endianness == quiche::NETWORK_BYTE_ORDER
          ? AsChars(big_endian64)
          : AsChars(little_endian64),
      8);

  uint64_t read_number64;
  QuicDataReader reader(buffer64, 8, GetParam().endianness);
  reader.ReadBytesToUInt64(8, &read_number64);
  EXPECT_EQ(in_memory64, read_number64);

  QuicDataWriter writer2(8, buffer64, GetParam().endianness);
  writer2.WriteUInt64(in_memory64);
  quiche::test::CompareCharArraysWithHexError(
      "uint64_t", buffer64, 8,
      GetParam().endianness == quiche::NETWORK_BYTE_ORDER
          ? AsChars(big_endian64)
          : AsChars(little_endian64),
      8);
  read_number64 = 0u;
  QuicDataReader reader2(buffer64, 8, GetParam().endianness);
  reader2.ReadUInt64(&read_number64);
  EXPECT_EQ(in_memory64, read_number64);
}

TEST_P(QuicDataWriterTest, WriteIntegers) {
  char buf[43];
  uint8_t i8 = 0x01;
  uint16_t i16 = 0x0123;
  uint32_t i32 = 0x01234567;
  uint64_t i64 = 0x0123456789ABCDEF;
  QuicDataWriter writer(46, buf, GetParam().endianness);
  for (size_t i = 0; i < 10; ++i) {
    switch (i) {
      case 0u:
        EXPECT_TRUE(writer.WriteBytesToUInt64(i, i64));
        break;
      case 1u:
        EXPECT_TRUE(writer.WriteUInt8(i8));
        EXPECT_TRUE(writer.WriteBytesToUInt64(i, i64));
        break;
      case 2u:
        EXPECT_TRUE(writer.WriteUInt16(i16));
        EXPECT_TRUE(writer.WriteBytesToUInt64(i, i64));
        break;
      case 3u:
        EXPECT_TRUE(writer.WriteBytesToUInt64(i, i64));
        break;
      case 4u:
        EXPECT_TRUE(writer.WriteUInt32(i32));
        EXPECT_TRUE(writer.WriteBytesToUInt64(i, i64));
        break;
      case 5u:
      case 6u:
      case 7u:
      case 8u:
        EXPECT_TRUE(writer.WriteBytesToUInt64(i, i64));
        break;
      default:
        EXPECT_FALSE(writer.WriteBytesToUInt64(i, i64));
    }
  }

  QuicDataReader reader(buf, 46, GetParam().endianness);
  for (size_t i = 0; i < 10; ++i) {
    uint8_t read8;
    uint16_t read16;
    uint32_t read32;
    uint64_t read64;
    switch (i) {
      case 0u:
        EXPECT_TRUE(reader.ReadBytesToUInt64(i, &read64));
        EXPECT_EQ(0u, read64);
        break;
      case 1u:
        EXPECT_TRUE(reader.ReadUInt8(&read8));
        EXPECT_TRUE(reader.ReadBytesToUInt64(i, &read64));
        EXPECT_EQ(i8, read8);
        EXPECT_EQ(0xEFu, read64);
        break;
      case 2u:
        EXPECT_TRUE(reader.ReadUInt16(&read16));
        EXPECT_TRUE(reader.ReadBytesToUInt64(i, &read64));
        EXPECT_EQ(i16, read16);
        EXPECT_EQ(0xCDEFu, read64);
        break;
      case 3u:
        EXPECT_TRUE(reader.ReadBytesToUInt64(i, &read64));
        EXPECT_EQ(0xABCDEFu, read64);
        break;
      case 4u:
        EXPECT_TRUE(reader.ReadUInt32(&read32));
        EXPECT_TRUE(reader.ReadBytesToUInt64(i, &read64));
        EXPECT_EQ(i32, read32);
        EXPECT_EQ(0x89ABCDEFu, read64);
        break;
      case 5u:
        EXPECT_TRUE(reader.ReadBytesToUInt64(i, &read64));
        EXPECT_EQ(0x6789ABCDEFu, read64);
        break;
      case 6u:
        EXPECT_TRUE(reader.ReadBytesToUInt64(i, &read64));
        EXPECT_EQ(0x456789ABCDEFu, read64);
        break;
      case 7u:
        EXPECT_TRUE(reader.ReadBytesToUInt64(i, &read64));
        EXPECT_EQ(0x23456789ABCDEFu, read64);
        break;
      case 8u:
        EXPECT_TRUE(reader.ReadBytesToUInt64(i, &read64));
        EXPECT_EQ(0x0123456789ABCDEFu, read64);
        break;
      default:
        EXPECT_FALSE(reader.ReadBytesToUInt64(i, &read64));
    }
  }
}

TEST_P(QuicDataWriterTest, WriteBytes) {
  char bytes[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
  char buf[ABSL_ARRAYSIZE(bytes)];
  QuicDataWriter writer(ABSL_ARRAYSIZE(buf), buf, GetParam().endianness);
  EXPECT_TRUE(writer.WriteBytes(bytes, ABSL_ARRAYSIZE(bytes)));
  for (unsigned int i = 0; i < ABSL_ARRAYSIZE(bytes); ++i) {
    EXPECT_EQ(bytes[i], buf[i]);
  }
}

// Following tests all try to fill the buffer with multiple values,
// go one value more than the buffer can accommodate, then read
// the successfully encoded values, and try to read the unsuccessfully
// encoded value. The following is the number of values to encode.
const int kMultiVarCount = 1000;

// Test encoding/decoding stream-id values.
void EncodeDecodeStreamId(uint64_t value_in) {
  char buffer[1 * kMultiVarCount];
  memset(buffer, 0, sizeof(buffer));

  // Encode the given Stream ID.
  QuicDataWriter writer(sizeof(buffer), static_cast<char*>(buffer),
                        quiche::Endianness::NETWORK_BYTE_ORDER);
  EXPECT_TRUE(writer.WriteVarInt62(value_in));

  QuicDataReader reader(buffer, sizeof(buffer),
                        quiche::Endianness::NETWORK_BYTE_ORDER);
  QuicStreamId received_stream_id;
  uint64_t temp;
  EXPECT_TRUE(reader.ReadVarInt62(&temp));
  received_stream_id = static_cast<QuicStreamId>(temp);
  EXPECT_EQ(value_in, received_stream_id);
}

// Test writing & reading stream-ids of various value.
TEST_P(QuicDataWriterTest, StreamId1) {
  // Check a 1-byte QuicStreamId, should work
  EncodeDecodeStreamId(UINT64_C(0x15));

  // Check a 2-byte QuicStream ID. It should work.
  EncodeDecodeStreamId(UINT64_C(0x1567));

  // Check a QuicStreamId that requires 4 bytes of encoding
  // This should work.
  EncodeDecodeStreamId(UINT64_C(0x34567890));

  // Check a QuicStreamId that requires 8 bytes of encoding
  // but whose value is in the acceptable range.
  // This should work.
  EncodeDecodeStreamId(UINT64_C(0xf4567890));
}

TEST_P(QuicDataWriterTest, WriteRandomBytes) {
  char buffer[20];
  char expected[20];
  for (size_t i = 0; i < 20; ++i) {
    expected[i] = 'r';
  }
  MockRandom random;
  QuicDataWriter writer(20, buffer, GetParam().endianness);
  EXPECT_FALSE(writer.WriteRandomBytes(&random, 30));

  EXPECT_TRUE(writer.WriteRandomBytes(&random, 20));
  quiche::test::CompareCharArraysWithHexError("random", buffer, 20, expected,
                                              20);
}

TEST_P(QuicDataWriterTest, WriteInsecureRandomBytes) {
  char buffer[20];
  char expected[20];
  for (size_t i = 0; i < 20; ++i) {
    expected[i] = 'r';
  }
  MockRandom random;
  QuicDataWriter writer(20, buffer, GetParam().endianness);
  EXPECT_FALSE(writer.WriteInsecureRandomBytes(&random, 30));

  EXPECT_TRUE(writer.WriteInsecureRandomBytes(&random, 20));
  quiche::test::CompareCharArraysWithHexError("random", buffer, 20, expected,
                                              20);
}

TEST_P(QuicDataWriterTest, PeekVarInt62Length) {
  // In range [0, 63], variable length should be 1 byte.
  char buffer[20];
  QuicDataWriter writer(20, buffer, quiche::NETWORK_BYTE_ORDER);
  EXPECT_TRUE(writer.WriteVarInt62(50));
  QuicDataReader reader(buffer, 20, quiche::NETWORK_BYTE_ORDER);
  EXPECT_EQ(1, reader.PeekVarInt62Length());
  // In range (63-16383], variable length should be 2 byte2.
  char buffer2[20];
  QuicDataWriter writer2(20, buffer2, quiche::NETWORK_BYTE_ORDER);
  EXPECT_TRUE(writer2.WriteVarInt62(100));
  QuicDataReader reader2(buffer2, 20, quiche::NETWORK_BYTE_ORDER);
  EXPECT_EQ(2, reader2.PeekVarInt62Length());
  // In range (16383, 1073741823], variable length should be 4 bytes.
  char buffer3[20];
  QuicDataWriter writer3(20, buffer3, quiche::NETWORK_BYTE_ORDER);
  EXPECT_TRUE(writer3.WriteVarInt62(20000));
  QuicDataReader reader3(buffer3, 20, quiche::NETWORK_BYTE_ORDER);
  EXPECT_EQ(4, reader3.PeekVarInt62Length());
  // In range (1073741823, 4611686018427387903], variable length should be 8
  // bytes.
  char buffer4[20];
  QuicDataWriter writer4(20, buffer4, quiche::NETWORK_BYTE_ORDER);
  EXPECT_TRUE(writer4.WriteVarInt62(2000000000));
  QuicDataReader reader4(buffer4, 20, quiche::NETWORK_BYTE_ORDER);
  EXPECT_EQ(8, reader4.PeekVarInt62Length());
}

TEST_P(QuicDataWriterTest, ValidStreamCount) {
  char buffer[1024];
  memset(buffer, 0, sizeof(buffer));
  QuicDataWriter writer(sizeof(buffer), static_cast<char*>(buffer),
                        quiche::Endianness::NETWORK_BYTE_ORDER);
  QuicDataReader reader(buffer, sizeof(buffer));
  const QuicStreamCount write_stream_count = 0xffeeddcc;
  EXPECT_TRUE(writer.WriteVarInt62(write_stream_count));
  QuicStreamCount read_stream_count;
  uint64_t temp;
  EXPECT_TRUE(reader.ReadVarInt62(&temp));
  read_stream_count = static_cast<QuicStreamId>(temp);
  EXPECT_EQ(write_stream_count, read_stream_count);
}

TEST_P(QuicDataWriterTest, Seek) {
  char buffer[3] = {};
  QuicDataWriter writer(ABSL_ARRAYSIZE(buffer), buffer, GetParam().endianness);
  EXPECT_TRUE(writer.WriteUInt8(42));
  EXPECT_TRUE(writer.Seek(1));
  EXPECT_TRUE(writer.WriteUInt8(3));

  char expected[] = {42, 0, 3};
  for (size_t i = 0; i < ABSL_ARRAYSIZE(expected); ++i) {
    EXPECT_EQ(buffer[i], expected[i]);
  }
}

TEST_P(QuicDataWriterTest, SeekTooFarFails) {
  char buffer[20];

  // Check that one can seek to the end of the writer, but not past.
  {
    QuicDataWriter writer(ABSL_ARRAYSIZE(buffer), buffer,
                          GetParam().endianness);
    EXPECT_TRUE(writer.Seek(20));
    EXPECT_FALSE(writer.Seek(1));
  }

  // Seeking several bytes past the end fails.
  {
    QuicDataWriter writer(ABSL_ARRAYSIZE(buffer), buffer,
                          GetParam().endianness);
    EXPECT_FALSE(writer.Seek(100));
  }

  // Seeking so far that arithmetic overflow could occur also fails.
  {
    QuicDataWriter writer(ABSL_ARRAYSIZE(buffer), buffer,
                          GetParam().endianness);
    EXPECT_TRUE(writer.Seek(10));
    EXPECT_FALSE(writer.Seek(std::numeric_limits<size_t>::max()));
  }
}

TEST_P(QuicDataWriterTest, PayloadReads) {
  char buffer[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  char expected_first_read[4] = {1, 2, 3, 4};
  char expected_remaining[12] = {5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  QuicDataReader reader(buffer, sizeof(buffer));
  char first_read_buffer[4] = {};
  EXPECT_TRUE(reader.ReadBytes(first_read_buffer, sizeof(first_read_buffer)));
  quiche::test::CompareCharArraysWithHexError(
      "first read", first_read_buffer, sizeof(first_read_buffer),
      expected_first_read, sizeof(expected_first_read));
  absl::string_view peeked_remaining_payload = reader.PeekRemainingPayload();
  quiche::test::CompareCharArraysWithHexError(
      "peeked_remaining_payload", peeked_remaining_payload.data(),
      peeked_remaining_payload.length(), expected_remaining,
      sizeof(expected_remaining));
  absl::string_view full_payload = reader.FullPayload();
  quiche::test::CompareCharArraysWithHexError(
      "full_payload", full_payload.data(), full_payload.length(), buffer,
      sizeof(buffer));
  absl::string_view read_remaining_payload = reader.ReadRemainingPayload();
  quiche::test::CompareCharArraysWithHexError(
      "read_remaining_payload", read_remaining_payload.data(),
      read_remaining_payload.length(), expected_remaining,
      sizeof(expected_remaining));
  EXPECT_TRUE(reader.IsDoneReading());
  absl::string_view full_payload2 = reader.FullPayload();
  quiche::test::CompareCharArraysWithHexError(
      "full_payload2", full_payload2.data(), full_payload2.length(), buffer,
      sizeof(buffer));
}

TEST_P(QuicDataWriterTest, StringPieceVarInt62) {
  char inner_buffer[16] = {1, 2,  3,  4,  5,  6,  7,  8,
                           9, 10, 11, 12, 13, 14, 15, 16};
  absl::string_view inner_payload_write(inner_buffer, sizeof(inner_buffer));
  char buffer[sizeof(inner_buffer) + sizeof(uint8_t)] = {};
  QuicDataWriter writer(sizeof(buffer), buffer);
  EXPECT_TRUE(writer.WriteStringPieceVarInt62(inner_payload_write));
  EXPECT_EQ(0u, writer.remaining());
  QuicDataReader reader(buffer, sizeof(buffer));
  absl::string_view inner_payload_read;
  EXPECT_TRUE(reader.ReadStringPieceVarInt62(&inner_payload_read));
  quiche::test::CompareCharArraysWithHexError(
      "inner_payload", inner_payload_write.data(), inner_payload_write.length(),
      inner_payload_read.data(), inner_payload_read.length());
}

}  // namespace
}  // namespace test
}  // namespace quic
```
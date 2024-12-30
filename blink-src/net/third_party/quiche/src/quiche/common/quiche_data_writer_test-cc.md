Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Identify the Core Purpose:** The filename `quiche_data_writer_test.cc` immediately suggests this file contains unit tests for a class named `QuicheDataWriter`. The presence of `#include "quiche/common/quiche_data_writer.h"` confirms this. The tests are likely verifying the functionality of `QuicheDataWriter`.

2. **Understand the Test Structure:**  Look for standard C++ testing patterns.
    * `#include "quiche/common/platform/api/quiche_test.h"` hints at a custom testing framework, but the core principles remain the same.
    * The use of `TEST_P` and `INSTANTIATE_TEST_SUITE_P` indicates parameterized tests. This suggests testing the `QuicheDataWriter` with different configurations.
    * The `TestParams` struct and `GetTestParams` function reveal the parameterization is based on `quiche::Endianness` (network byte order and host byte order).
    * Individual `TEST_P` blocks represent specific test cases.

3. **Analyze Individual Test Cases:** Go through each `TEST_P` function and determine what it's testing. Look for:
    * **What's being written:** `WriteUInt16`, `WriteBytesToUInt64`, `WriteBytes`, `WriteVarInt62`, etc.
    * **What's being checked:** Comparisons against expected byte arrays (`CompareCharArraysWithHexError`), equality checks (`EXPECT_EQ`), boolean checks (`EXPECT_TRUE`, `EXPECT_FALSE`).
    * **How the data is being read back:**  The use of `QuicheDataReader` and its corresponding `Read` methods.

4. **Summarize the Functionality:** Based on the test cases, create a high-level summary of `QuicheDataWriter`'s capabilities:
    * Writing various integer types (8, 16, 24, 32, 40, 48, 56, 64 bits) in both network and host byte order.
    * Writing raw bytes.
    * Writing variable-length integers (VarInts) according to the IETF standard.
    * Seeking within the buffer.

5. **Consider JavaScript Relevance:** Think about how data serialization and deserialization occur in JavaScript, particularly in network contexts.
    * `ArrayBuffer` and `DataView` are the key APIs for handling binary data.
    * Byte order matters when interacting with network protocols or file formats.
    * Variable-length integers are used in some protocols to optimize data size.
    * Provide concrete examples using `DataView` to demonstrate how JavaScript would perform similar operations.

6. **Identify Logical Reasoning and Assumptions:** Look for tests that involve more than just writing and reading fixed values. The VarInt tests are a good example.
    * **Assumption:** The VarInt encoding follows the IETF standard.
    * **Reasoning:** The tests verify the correct encoding length based on the input value and that the decoding recovers the original value.
    * **Hypothetical Input/Output:** Provide examples for different VarInt lengths to illustrate the encoding process.

7. **Spot Potential Usage Errors:** Consider how a developer might misuse the `QuicheDataWriter`.
    * **Buffer Overflow:**  Trying to write more data than the buffer can hold. The tests with `kMultiVarCount` demonstrate this.
    * **Incorrect Endianness:**  Writing data with one endianness and reading with another. While the tests cover both, a user might make a mistake.
    * **Seeking Errors:**  Seeking beyond the buffer boundaries. The `SeekTooFarFails` test specifically addresses this.

8. **Trace User Operations (Debugging Clues):** Imagine a scenario where a developer encounters an issue related to `QuicheDataWriter`. How might they arrive at this code?
    * **Network Protocol Implementation:** The developer might be implementing a network protocol that uses a binary format, and `QuicheDataWriter` is used for constructing the messages.
    * **Data Serialization:** The developer might be serializing data for storage or transmission.
    * **Debugging Process:** Describe the steps a developer would take to investigate a problem, potentially leading them to examine the `QuicheDataWriter` code and its tests. This involves using debuggers, logging, and examining network traffic.

9. **Review and Refine:** Go back through the analysis and ensure clarity, accuracy, and completeness. Are the examples clear? Is the reasoning sound? Have all aspects of the prompt been addressed?  For example, initially, I might have focused too much on the individual integer types and not enough on the overarching purpose and the VarInt logic. Reviewing helps to balance the different parts of the analysis.
这个文件 `net/third_party/quiche/src/quiche/common/quiche_data_writer_test.cc` 是 Chromium 网络栈中 QUIC 协议库的一部分，它专门用于测试 `QuicheDataWriter` 类的功能。`QuicheDataWriter` 的作用是将各种数据类型（如整数、字节序列等）按照指定的字节序写入到缓冲区中。

**该文件的主要功能可以概括为：**

1. **单元测试 `QuicheDataWriter` 类:**  该文件包含了大量的测试用例，用于验证 `QuicheDataWriter` 类的各种方法是否按照预期工作。
2. **测试不同大小的无符号整数写入:** 测试了写入 16 位、24 位、32 位、40 位、48 位、56 位和 64 位的无符号整数，并验证了在网络字节序（大端序）和主机字节序下的正确性。
3. **测试字节序列写入:** 验证了将一段字节数组写入缓冲区的操作是否正确。
4. **测试变长整数 (VarInt) 的写入和读取:**  测试了 `QuicheDataWriter` 中用于写入 QUIC 协议中使用的变长整数 (VarInt) 的功能，包括不同长度的 VarInt 的编码和解码，以及边界情况的测试。
5. **测试 `Seek` 功能:**  验证了在缓冲区中移动写入位置 (`Seek` 方法) 的功能是否正常。
6. **测试与 `QuicheDataReader` 的互操作性:** 虽然主要测试 `QuicheDataWriter`，但也通过 `QuicheDataReader` 来验证写入的数据是否可以被正确读取，从而间接测试了写入的正确性。
7. **覆盖边界情况和错误处理:** 测试用例覆盖了各种边界情况，例如写入超过缓冲区大小的数据，以及 `Seek` 到非法位置等。

**它与 JavaScript 的功能关系：**

虽然这是一个 C++ 文件，但 `QuicheDataWriter` 的功能与 JavaScript 中处理二进制数据的场景有相似之处。在 JavaScript 中，可以使用 `ArrayBuffer` 和 `DataView` 来进行类似的二进制数据写入和读取操作。

**举例说明：**

假设我们需要在 JavaScript 中将一个 32 位的无符号整数以大端序写入到一个 `ArrayBuffer` 中，并随后读取出来：

```javascript
// JavaScript 写入示例（类似于 QuicheDataWriter 的功能）
const buffer = new ArrayBuffer(4);
const dataView = new DataView(buffer);

const valueToWrite = 0x11223344;

// 以大端序写入 32 位无符号整数
dataView.setUint32(0, valueToWrite, false); // false 表示大端序

// 验证写入的内容（类似于测试中的 CompareCharArraysWithHexError）
const expectedBuffer = new Uint8Array([0x11, 0x22, 0x33, 0x44]);
const actualBuffer = new Uint8Array(buffer);
// 这里需要一些比较数组的方法来验证 actualBuffer 和 expectedBuffer 是否一致

// JavaScript 读取示例（类似于 QuicheDataReader 的功能）
const readValue = dataView.getUint32(0, false); // false 表示大端序

console.log(readValue === valueToWrite); // 输出 true
```

在这个 JavaScript 示例中：

* `ArrayBuffer` 类似于 `QuicheDataWriter` 使用的缓冲区。
* `DataView` 提供了写入和读取不同类型数据的方法，类似于 `QuicheDataWriter` 的 `WriteUInt32` 等方法。
* `setUint32(offset, value, littleEndian)` 的 `littleEndian` 参数对应于 `QuicheDataWriter` 的字节序设置。`false` 代表大端序 (网络字节序)。
* `getUint32(offset, littleEndian)` 用于读取数据。

**逻辑推理，假设输入与输出：**

以测试 `Write16BitUnsignedIntegers` 为例：

**假设输入：**

* `in_memory16 = 0x1122` (要写入的 16 位无符号整数)
* `GetParam().endianness = quiche::NETWORK_BYTE_ORDER` (网络字节序，即大端序)
* `buffer16` 是一个长度为 2 的字符数组。

**逻辑推理：**

`QuicheDataWriter` 的 `WriteUInt16` 方法会将 `0x1122` 按照大端序写入到 `buffer16` 中。大端序意味着高位字节在前，低位字节在后。

**预期输出：**

* `buffer16` 的内容将变为 `{0x11, 0x22}`。
* 随后的 `QuicheDataReader` 从 `buffer16` 中读取数据时，会得到与原始值 `0x1122` 相同的结果。

**如果 `GetParam().endianness` 是 `quiche::HOST_BYTE_ORDER`（假设主机是小端序）：**

**预期输出：**

* `buffer16` 的内容将变为 `{0x22, 0x11}`。

**涉及用户或编程常见的使用错误：**

1. **缓冲区溢出:** 用户在创建 `QuicheDataWriter` 时指定的缓冲区大小不足以容纳要写入的数据。
   * **示例：**
     ```c++
     char buffer[2];
     QuicheDataWriter writer(2, buffer, quiche::NETWORK_BYTE_ORDER);
     writer.WriteUInt32(0x11223344); // 尝试写入 4 字节数据到 2 字节缓冲区，会导致缓冲区溢出
     ```
2. **字节序错误:** 用户在写入和读取数据时使用了不一致的字节序。
   * **示例：**
     ```c++
     char buffer[2];
     uint16_t value = 0x1122;
     QuicheDataWriter writer(2, buffer, quiche::NETWORK_BYTE_ORDER);
     writer.WriteUInt16(value); // 以大端序写入

     uint16_t read_value;
     QuicheDataReader reader(buffer, 2, quiche::HOST_BYTE_ORDER); // 尝试以小端序读取
     reader.ReadUInt16(&read_value);
     // read_value 的值将不会是 0x1122 (如果主机是小端序)
     ```
3. **`Seek` 操作越界:** 用户使用 `Seek` 方法将写入位置移动到缓冲区之外。
   * **示例：**
     ```c++
     char buffer[10];
     QuicheDataWriter writer(10, buffer, quiche::NETWORK_BYTE_ORDER);
     writer.Seek(15); // 尝试将写入位置移动到缓冲区之外，这应该会导致错误
     ```
4. **尝试写入超过剩余空间的数据:**  在已经写入部分数据后，尝试写入的数据量超过了缓冲区剩余的空间。
   * **示例：**
     ```c++
     char buffer[5];
     QuicheDataWriter writer(5, buffer, quiche::NETWORK_BYTE_ORDER);
     writer.WriteUInt16(0x1234); // 写入 2 字节
     writer.WriteBytes("abcde", 5); // 尝试写入 5 字节，但只剩下 3 字节空间
     ```

**说明用户操作是如何一步步的到达这里，作为调试线索：**

当网络协议栈在处理网络数据包时，可能需要将各种数据编码成特定的二进制格式。`QuicheDataWriter` 就是用于完成这个任务的工具。以下是一个可能导致用户（或开发者）查看 `quiche_data_writer_test.cc` 的调试场景：

1. **网络连接问题或数据解析错误:** 用户在使用基于 QUIC 协议的应用（例如 Chrome 浏览器访问某些使用了 QUIC 的网站）时，可能会遇到连接失败、数据传输错误或页面加载异常等问题。
2. **开发者介入调试:**  当用户报告这些问题后，负责网络协议栈开发的工程师会开始调试。
3. **定位到 QUIC 协议层:** 开发者可能会通过查看网络日志、抓包分析等手段，初步判断问题可能出在 QUIC 协议的实现上。
4. **怀疑数据编码或解码环节出错:**  如果怀疑是数据包的编码或解码过程中出现了错误，开发者可能会深入研究 QUIC 协议栈中负责数据处理的部分。
5. **查看 `QuicheDataWriter` 的使用:** 开发者可能会发现代码中使用了 `QuicheDataWriter` 来构建 QUIC 数据包的某些部分（例如，写入帧类型、连接 ID、数据长度等）。
6. **检查 `QuicheDataWriter` 的行为:** 为了验证 `QuicheDataWriter` 是否按照预期工作，开发者可能会：
   * **阅读 `QuicheDataWriter` 的源代码:**  了解其内部实现逻辑。
   * **查看 `quiche_data_writer_test.cc`:**  查看已有的单元测试用例，了解如何正确使用 `QuicheDataWriter`，以及它应该如何处理各种输入和边界情况。这些测试用例可以作为参考，帮助开发者理解 `QuicheDataWriter` 的功能和预期行为。
   * **编写新的测试用例:** 如果现有的测试用例没有覆盖到开发者怀疑出错的场景，他们可能会编写新的测试用例来重现问题或验证修复方案。
   * **在实际代码中添加日志或断点:**  在调用 `QuicheDataWriter` 的地方添加日志输出或设置断点，观察写入的数据是否符合预期。

通过以上步骤，开发者可以利用 `quiche_data_writer_test.cc` 中的测试用例作为调试线索，理解 `QuicheDataWriter` 的工作方式，并帮助定位和解决网络协议栈中的数据编码相关问题。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/common/quiche_data_writer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/common/quiche_data_writer.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_data_reader.h"
#include "quiche/common/quiche_endian.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

namespace quiche {
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

class QuicheDataWriterTest : public QuicheTestWithParam<TestParams> {};

INSTANTIATE_TEST_SUITE_P(QuicheDataWriterTests, QuicheDataWriterTest,
                         ::testing::ValuesIn(GetTestParams()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicheDataWriterTest, Write16BitUnsignedIntegers) {
  char little_endian16[] = {0x22, 0x11};
  char big_endian16[] = {0x11, 0x22};
  char buffer16[2];
  {
    uint16_t in_memory16 = 0x1122;
    QuicheDataWriter writer(2, buffer16, GetParam().endianness);
    writer.WriteUInt16(in_memory16);
    test::CompareCharArraysWithHexError(
        "uint16_t", buffer16, 2,
        GetParam().endianness == quiche::NETWORK_BYTE_ORDER ? big_endian16
                                                            : little_endian16,
        2);

    uint16_t read_number16;
    QuicheDataReader reader(buffer16, 2, GetParam().endianness);
    reader.ReadUInt16(&read_number16);
    EXPECT_EQ(in_memory16, read_number16);
  }

  {
    uint64_t in_memory16 = 0x0000000000001122;
    QuicheDataWriter writer(2, buffer16, GetParam().endianness);
    writer.WriteBytesToUInt64(2, in_memory16);
    test::CompareCharArraysWithHexError(
        "uint16_t", buffer16, 2,
        GetParam().endianness == quiche::NETWORK_BYTE_ORDER ? big_endian16
                                                            : little_endian16,
        2);

    uint64_t read_number16;
    QuicheDataReader reader(buffer16, 2, GetParam().endianness);
    reader.ReadBytesToUInt64(2, &read_number16);
    EXPECT_EQ(in_memory16, read_number16);
  }
}

TEST_P(QuicheDataWriterTest, Write24BitUnsignedIntegers) {
  char little_endian24[] = {0x33, 0x22, 0x11};
  char big_endian24[] = {0x11, 0x22, 0x33};
  char buffer24[3];
  uint64_t in_memory24 = 0x0000000000112233;
  QuicheDataWriter writer(3, buffer24, GetParam().endianness);
  writer.WriteBytesToUInt64(3, in_memory24);
  test::CompareCharArraysWithHexError(
      "uint24", buffer24, 3,
      GetParam().endianness == quiche::NETWORK_BYTE_ORDER ? big_endian24
                                                          : little_endian24,
      3);

  uint64_t read_number24;
  QuicheDataReader reader(buffer24, 3, GetParam().endianness);
  reader.ReadBytesToUInt64(3, &read_number24);
  EXPECT_EQ(in_memory24, read_number24);
}

TEST_P(QuicheDataWriterTest, Write32BitUnsignedIntegers) {
  char little_endian32[] = {0x44, 0x33, 0x22, 0x11};
  char big_endian32[] = {0x11, 0x22, 0x33, 0x44};
  char buffer32[4];
  {
    uint32_t in_memory32 = 0x11223344;
    QuicheDataWriter writer(4, buffer32, GetParam().endianness);
    writer.WriteUInt32(in_memory32);
    test::CompareCharArraysWithHexError(
        "uint32_t", buffer32, 4,
        GetParam().endianness == quiche::NETWORK_BYTE_ORDER ? big_endian32
                                                            : little_endian32,
        4);

    uint32_t read_number32;
    QuicheDataReader reader(buffer32, 4, GetParam().endianness);
    reader.ReadUInt32(&read_number32);
    EXPECT_EQ(in_memory32, read_number32);
  }

  {
    uint64_t in_memory32 = 0x11223344;
    QuicheDataWriter writer(4, buffer32, GetParam().endianness);
    writer.WriteBytesToUInt64(4, in_memory32);
    test::CompareCharArraysWithHexError(
        "uint32_t", buffer32, 4,
        GetParam().endianness == quiche::NETWORK_BYTE_ORDER ? big_endian32
                                                            : little_endian32,
        4);

    uint64_t read_number32;
    QuicheDataReader reader(buffer32, 4, GetParam().endianness);
    reader.ReadBytesToUInt64(4, &read_number32);
    EXPECT_EQ(in_memory32, read_number32);
  }
}

TEST_P(QuicheDataWriterTest, Write40BitUnsignedIntegers) {
  uint64_t in_memory40 = 0x0000001122334455;
  char little_endian40[] = {0x55, 0x44, 0x33, 0x22, 0x11};
  char big_endian40[] = {0x11, 0x22, 0x33, 0x44, 0x55};
  char buffer40[5];
  QuicheDataWriter writer(5, buffer40, GetParam().endianness);
  writer.WriteBytesToUInt64(5, in_memory40);
  test::CompareCharArraysWithHexError(
      "uint40", buffer40, 5,
      GetParam().endianness == quiche::NETWORK_BYTE_ORDER ? big_endian40
                                                          : little_endian40,
      5);

  uint64_t read_number40;
  QuicheDataReader reader(buffer40, 5, GetParam().endianness);
  reader.ReadBytesToUInt64(5, &read_number40);
  EXPECT_EQ(in_memory40, read_number40);
}

TEST_P(QuicheDataWriterTest, Write48BitUnsignedIntegers) {
  uint64_t in_memory48 = 0x0000112233445566;
  char little_endian48[] = {0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
  char big_endian48[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  char buffer48[6];
  QuicheDataWriter writer(6, buffer48, GetParam().endianness);
  writer.WriteBytesToUInt64(6, in_memory48);
  test::CompareCharArraysWithHexError(
      "uint48", buffer48, 6,
      GetParam().endianness == quiche::NETWORK_BYTE_ORDER ? big_endian48
                                                          : little_endian48,
      6);

  uint64_t read_number48;
  QuicheDataReader reader(buffer48, 6, GetParam().endianness);
  reader.ReadBytesToUInt64(6., &read_number48);
  EXPECT_EQ(in_memory48, read_number48);
}

TEST_P(QuicheDataWriterTest, Write56BitUnsignedIntegers) {
  uint64_t in_memory56 = 0x0011223344556677;
  char little_endian56[] = {0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
  char big_endian56[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
  char buffer56[7];
  QuicheDataWriter writer(7, buffer56, GetParam().endianness);
  writer.WriteBytesToUInt64(7, in_memory56);
  test::CompareCharArraysWithHexError(
      "uint56", buffer56, 7,
      GetParam().endianness == quiche::NETWORK_BYTE_ORDER ? big_endian56
                                                          : little_endian56,
      7);

  uint64_t read_number56;
  QuicheDataReader reader(buffer56, 7, GetParam().endianness);
  reader.ReadBytesToUInt64(7, &read_number56);
  EXPECT_EQ(in_memory56, read_number56);
}

TEST_P(QuicheDataWriterTest, Write64BitUnsignedIntegers) {
  uint64_t in_memory64 = 0x1122334455667788;
  unsigned char little_endian64[] = {0x88, 0x77, 0x66, 0x55,
                                     0x44, 0x33, 0x22, 0x11};
  unsigned char big_endian64[] = {0x11, 0x22, 0x33, 0x44,
                                  0x55, 0x66, 0x77, 0x88};
  char buffer64[8];
  QuicheDataWriter writer(8, buffer64, GetParam().endianness);
  writer.WriteBytesToUInt64(8, in_memory64);
  test::CompareCharArraysWithHexError(
      "uint64_t", buffer64, 8,
      GetParam().endianness == quiche::NETWORK_BYTE_ORDER
          ? AsChars(big_endian64)
          : AsChars(little_endian64),
      8);

  uint64_t read_number64;
  QuicheDataReader reader(buffer64, 8, GetParam().endianness);
  reader.ReadBytesToUInt64(8, &read_number64);
  EXPECT_EQ(in_memory64, read_number64);

  QuicheDataWriter writer2(8, buffer64, GetParam().endianness);
  writer2.WriteUInt64(in_memory64);
  test::CompareCharArraysWithHexError(
      "uint64_t", buffer64, 8,
      GetParam().endianness == quiche::NETWORK_BYTE_ORDER
          ? AsChars(big_endian64)
          : AsChars(little_endian64),
      8);
  read_number64 = 0u;
  QuicheDataReader reader2(buffer64, 8, GetParam().endianness);
  reader2.ReadUInt64(&read_number64);
  EXPECT_EQ(in_memory64, read_number64);
}

TEST_P(QuicheDataWriterTest, WriteIntegers) {
  char buf[43];
  uint8_t i8 = 0x01;
  uint16_t i16 = 0x0123;
  uint32_t i32 = 0x01234567;
  uint64_t i64 = 0x0123456789ABCDEF;
  QuicheDataWriter writer(46, buf, GetParam().endianness);
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

  QuicheDataReader reader(buf, 46, GetParam().endianness);
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

TEST_P(QuicheDataWriterTest, WriteBytes) {
  char bytes[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
  char buf[ABSL_ARRAYSIZE(bytes)];
  QuicheDataWriter writer(ABSL_ARRAYSIZE(buf), buf, GetParam().endianness);
  EXPECT_TRUE(writer.WriteBytes(bytes, ABSL_ARRAYSIZE(bytes)));
  for (unsigned int i = 0; i < ABSL_ARRAYSIZE(bytes); ++i) {
    EXPECT_EQ(bytes[i], buf[i]);
  }
}

const int kVarIntBufferLength = 1024;

// Encodes and then decodes a specified value, checks that the
// value that was encoded is the same as the decoded value, the length
// is correct, and that after decoding, all data in the buffer has
// been consumed..
// Returns true if everything works, false if not.
bool EncodeDecodeValue(uint64_t value_in, char* buffer, size_t size_of_buffer) {
  // Init the buffer to all 0, just for cleanliness. Makes for better
  // output if, in debugging, we need to dump out the buffer.
  memset(buffer, 0, size_of_buffer);
  // make a writer. Note that for IETF encoding
  // we do not care about endianness... It's always big-endian,
  // but the c'tor expects to be told what endianness is in force...
  QuicheDataWriter writer(size_of_buffer, buffer,
                          quiche::Endianness::NETWORK_BYTE_ORDER);

  // Try to write the value.
  if (writer.WriteVarInt62(value_in) != true) {
    return false;
  }
  // Look at the value we encoded. Determine how much should have been
  // used based on the value, and then check the state of the writer
  // to see that it matches.
  size_t expected_length = 0;
  if (value_in <= 0x3f) {
    expected_length = 1;
  } else if (value_in <= 0x3fff) {
    expected_length = 2;
  } else if (value_in <= 0x3fffffff) {
    expected_length = 4;
  } else {
    expected_length = 8;
  }
  if (writer.length() != expected_length) {
    return false;
  }

  // set up a reader, just the length we've used, no more, no less.
  QuicheDataReader reader(buffer, expected_length,
                          quiche::Endianness::NETWORK_BYTE_ORDER);
  uint64_t value_out;

  if (reader.ReadVarInt62(&value_out) == false) {
    return false;
  }
  if (value_in != value_out) {
    return false;
  }
  // We only write one value so there had better be nothing left to read
  return reader.IsDoneReading();
}

// Test that 8-byte-encoded Variable Length Integers are properly laid
// out in the buffer.
TEST_P(QuicheDataWriterTest, VarInt8Layout) {
  char buffer[1024];

  // Check that the layout of bytes in the buffer is correct. Bytes
  // are always encoded big endian...
  memset(buffer, 0, sizeof(buffer));
  QuicheDataWriter writer(sizeof(buffer), static_cast<char*>(buffer),
                          quiche::Endianness::NETWORK_BYTE_ORDER);
  EXPECT_TRUE(writer.WriteVarInt62(UINT64_C(0x3142f3e4d5c6b7a8)));
  EXPECT_EQ(static_cast<unsigned char>(*(writer.data() + 0)),
            (0x31 + 0xc0));  // 0xc0 for encoding
  EXPECT_EQ(static_cast<unsigned char>(*(writer.data() + 1)), 0x42);
  EXPECT_EQ(static_cast<unsigned char>(*(writer.data() + 2)), 0xf3);
  EXPECT_EQ(static_cast<unsigned char>(*(writer.data() + 3)), 0xe4);
  EXPECT_EQ(static_cast<unsigned char>(*(writer.data() + 4)), 0xd5);
  EXPECT_EQ(static_cast<unsigned char>(*(writer.data() + 5)), 0xc6);
  EXPECT_EQ(static_cast<unsigned char>(*(writer.data() + 6)), 0xb7);
  EXPECT_EQ(static_cast<unsigned char>(*(writer.data() + 7)), 0xa8);
}

// Test that 4-byte-encoded Variable Length Integers are properly laid
// out in the buffer.
TEST_P(QuicheDataWriterTest, VarInt4Layout) {
  char buffer[1024];

  // Check that the layout of bytes in the buffer is correct. Bytes
  // are always encoded big endian...
  memset(buffer, 0, sizeof(buffer));
  QuicheDataWriter writer(sizeof(buffer), static_cast<char*>(buffer),
                          quiche::Endianness::NETWORK_BYTE_ORDER);
  EXPECT_TRUE(writer.WriteVarInt62(0x3243f4e5));
  EXPECT_EQ(static_cast<unsigned char>(*(writer.data() + 0)),
            (0x32 + 0x80));  // 0x80 for encoding
  EXPECT_EQ(static_cast<unsigned char>(*(writer.data() + 1)), 0x43);
  EXPECT_EQ(static_cast<unsigned char>(*(writer.data() + 2)), 0xf4);
  EXPECT_EQ(static_cast<unsigned char>(*(writer.data() + 3)), 0xe5);
}

// Test that 2-byte-encoded Variable Length Integers are properly laid
// out in the buffer.
TEST_P(QuicheDataWriterTest, VarInt2Layout) {
  char buffer[1024];

  // Check that the layout of bytes in the buffer is correct. Bytes
  // are always encoded big endian...
  memset(buffer, 0, sizeof(buffer));
  QuicheDataWriter writer(sizeof(buffer), static_cast<char*>(buffer),
                          quiche::Endianness::NETWORK_BYTE_ORDER);
  EXPECT_TRUE(writer.WriteVarInt62(0x3647));
  EXPECT_EQ(static_cast<unsigned char>(*(writer.data() + 0)),
            (0x36 + 0x40));  // 0x40 for encoding
  EXPECT_EQ(static_cast<unsigned char>(*(writer.data() + 1)), 0x47);
}

// Test that 1-byte-encoded Variable Length Integers are properly laid
// out in the buffer.
TEST_P(QuicheDataWriterTest, VarInt1Layout) {
  char buffer[1024];

  // Check that the layout of bytes in the buffer
  // is correct. Bytes are always encoded big endian...
  memset(buffer, 0, sizeof(buffer));
  QuicheDataWriter writer(sizeof(buffer), static_cast<char*>(buffer),
                          quiche::Endianness::NETWORK_BYTE_ORDER);
  EXPECT_TRUE(writer.WriteVarInt62(0x3f));
  EXPECT_EQ(static_cast<unsigned char>(*(writer.data() + 0)), 0x3f);
}

// Test certain, targeted, values that are expected to succeed:
// 0, 1,
// 0x3e, 0x3f, 0x40, 0x41 (around the 1-2 byte transitions)
// 0x3ffe, 0x3fff, 0x4000, 0x4001 (the 2-4 byte transition)
// 0x3ffffffe, 0x3fffffff, 0x40000000, 0x40000001 (the 4-8 byte
//                          transition)
// 0x3ffffffffffffffe, 0x3fffffffffffffff,  (the highest valid values)
// 0xfe, 0xff, 0x100, 0x101,
// 0xfffe, 0xffff, 0x10000, 0x10001,
// 0xfffffe, 0xffffff, 0x1000000, 0x1000001,
// 0xfffffffe, 0xffffffff, 0x100000000, 0x100000001,
// 0xfffffffffe, 0xffffffffff, 0x10000000000, 0x10000000001,
// 0xfffffffffffe, 0xffffffffffff, 0x1000000000000, 0x1000000000001,
// 0xfffffffffffffe, 0xffffffffffffff, 0x100000000000000, 0x100000000000001,
TEST_P(QuicheDataWriterTest, VarIntGoodTargetedValues) {
  char buffer[kVarIntBufferLength];
  uint64_t passing_values[] = {
      0,
      1,
      0x3e,
      0x3f,
      0x40,
      0x41,
      0x3ffe,
      0x3fff,
      0x4000,
      0x4001,
      0x3ffffffe,
      0x3fffffff,
      0x40000000,
      0x40000001,
      0x3ffffffffffffffe,
      0x3fffffffffffffff,
      0xfe,
      0xff,
      0x100,
      0x101,
      0xfffe,
      0xffff,
      0x10000,
      0x10001,
      0xfffffe,
      0xffffff,
      0x1000000,
      0x1000001,
      0xfffffffe,
      0xffffffff,
      0x100000000,
      0x100000001,
      0xfffffffffe,
      0xffffffffff,
      0x10000000000,
      0x10000000001,
      0xfffffffffffe,
      0xffffffffffff,
      0x1000000000000,
      0x1000000000001,
      0xfffffffffffffe,
      0xffffffffffffff,
      0x100000000000000,
      0x100000000000001,
  };
  for (uint64_t test_val : passing_values) {
    EXPECT_TRUE(
        EncodeDecodeValue(test_val, static_cast<char*>(buffer), sizeof(buffer)))
        << " encode/decode of " << test_val << " failed";
  }
}
//
// Test certain, targeted, values where failure is expected (the
// values are invalid w.r.t. IETF VarInt encoding):
// 0x4000000000000000, 0x4000000000000001,  ( Just above max allowed value)
// 0xfffffffffffffffe, 0xffffffffffffffff,  (should fail)
TEST_P(QuicheDataWriterTest, VarIntBadTargetedValues) {
  char buffer[kVarIntBufferLength];
  uint64_t failing_values[] = {
      0x4000000000000000,
      0x4000000000000001,
      0xfffffffffffffffe,
      0xffffffffffffffff,
  };
  for (uint64_t test_val : failing_values) {
    EXPECT_FALSE(
        EncodeDecodeValue(test_val, static_cast<char*>(buffer), sizeof(buffer)))
        << " encode/decode of " << test_val << " succeeded, but was an "
        << "invalid value";
  }
}
// Test writing varints with a forced length.
TEST_P(QuicheDataWriterTest, WriteVarInt62WithForcedLength) {
  char buffer[90];
  memset(buffer, 0, sizeof(buffer));
  QuicheDataWriter writer(sizeof(buffer), static_cast<char*>(buffer));

  writer.WriteVarInt62WithForcedLength(1, VARIABLE_LENGTH_INTEGER_LENGTH_1);
  writer.WriteVarInt62WithForcedLength(1, VARIABLE_LENGTH_INTEGER_LENGTH_2);
  writer.WriteVarInt62WithForcedLength(1, VARIABLE_LENGTH_INTEGER_LENGTH_4);
  writer.WriteVarInt62WithForcedLength(1, VARIABLE_LENGTH_INTEGER_LENGTH_8);

  writer.WriteVarInt62WithForcedLength(63, VARIABLE_LENGTH_INTEGER_LENGTH_1);
  writer.WriteVarInt62WithForcedLength(63, VARIABLE_LENGTH_INTEGER_LENGTH_2);
  writer.WriteVarInt62WithForcedLength(63, VARIABLE_LENGTH_INTEGER_LENGTH_4);
  writer.WriteVarInt62WithForcedLength(63, VARIABLE_LENGTH_INTEGER_LENGTH_8);

  writer.WriteVarInt62WithForcedLength(64, VARIABLE_LENGTH_INTEGER_LENGTH_2);
  writer.WriteVarInt62WithForcedLength(64, VARIABLE_LENGTH_INTEGER_LENGTH_4);
  writer.WriteVarInt62WithForcedLength(64, VARIABLE_LENGTH_INTEGER_LENGTH_8);

  writer.WriteVarInt62WithForcedLength(16383, VARIABLE_LENGTH_INTEGER_LENGTH_2);
  writer.WriteVarInt62WithForcedLength(16383, VARIABLE_LENGTH_INTEGER_LENGTH_4);
  writer.WriteVarInt62WithForcedLength(16383, VARIABLE_LENGTH_INTEGER_LENGTH_8);

  writer.WriteVarInt62WithForcedLength(16384, VARIABLE_LENGTH_INTEGER_LENGTH_4);
  writer.WriteVarInt62WithForcedLength(16384, VARIABLE_LENGTH_INTEGER_LENGTH_8);

  writer.WriteVarInt62WithForcedLength(1073741823,
                                       VARIABLE_LENGTH_INTEGER_LENGTH_4);
  writer.WriteVarInt62WithForcedLength(1073741823,
                                       VARIABLE_LENGTH_INTEGER_LENGTH_8);

  writer.WriteVarInt62WithForcedLength(1073741824,
                                       VARIABLE_LENGTH_INTEGER_LENGTH_8);

  QuicheDataReader reader(buffer, sizeof(buffer));

  uint64_t test_val = 0;
  for (int i = 0; i < 4; ++i) {
    EXPECT_TRUE(reader.ReadVarInt62(&test_val));
    EXPECT_EQ(test_val, 1u);
  }
  for (int i = 0; i < 4; ++i) {
    EXPECT_TRUE(reader.ReadVarInt62(&test_val));
    EXPECT_EQ(test_val, 63u);
  }

  for (int i = 0; i < 3; ++i) {
    EXPECT_TRUE(reader.ReadVarInt62(&test_val));
    EXPECT_EQ(test_val, 64u);
  }
  for (int i = 0; i < 3; ++i) {
    EXPECT_TRUE(reader.ReadVarInt62(&test_val));
    EXPECT_EQ(test_val, 16383u);
  }

  for (int i = 0; i < 2; ++i) {
    EXPECT_TRUE(reader.ReadVarInt62(&test_val));
    EXPECT_EQ(test_val, 16384u);
  }
  for (int i = 0; i < 2; ++i) {
    EXPECT_TRUE(reader.ReadVarInt62(&test_val));
    EXPECT_EQ(test_val, 1073741823u);
  }

  EXPECT_TRUE(reader.ReadVarInt62(&test_val));
  EXPECT_EQ(test_val, 1073741824u);

  // We are at the end of the buffer so this should fail.
  EXPECT_FALSE(reader.ReadVarInt62(&test_val));
}

// Following tests all try to fill the buffer with multiple values,
// go one value more than the buffer can accommodate, then read
// the successfully encoded values, and try to read the unsuccessfully
// encoded value. The following is the number of values to encode.
const int kMultiVarCount = 1000;

// Test writing & reading multiple 8-byte-encoded varints
TEST_P(QuicheDataWriterTest, MultiVarInt8) {
  uint64_t test_val;
  char buffer[8 * kMultiVarCount];
  memset(buffer, 0, sizeof(buffer));
  QuicheDataWriter writer(sizeof(buffer), static_cast<char*>(buffer),
                          quiche::Endianness::NETWORK_BYTE_ORDER);
  // Put N values into the buffer. Adding i to the value ensures that
  // each value is different so we can detect if we overwrite values,
  // or read the same value over and over.
  for (int i = 0; i < kMultiVarCount; i++) {
    EXPECT_TRUE(writer.WriteVarInt62(UINT64_C(0x3142f3e4d5c6b7a8) + i));
  }
  EXPECT_EQ(writer.length(), 8u * kMultiVarCount);

  // N+1st should fail, the buffer is full.
  EXPECT_FALSE(writer.WriteVarInt62(UINT64_C(0x3142f3e4d5c6b7a8)));

  // Now we should be able to read out the N values that were
  // successfully encoded.
  QuicheDataReader reader(buffer, sizeof(buffer),
                          quiche::Endianness::NETWORK_BYTE_ORDER);
  for (int i = 0; i < kMultiVarCount; i++) {
    EXPECT_TRUE(reader.ReadVarInt62(&test_val));
    EXPECT_EQ(test_val, (UINT64_C(0x3142f3e4d5c6b7a8) + i));
  }
  // And the N+1st should fail.
  EXPECT_FALSE(reader.ReadVarInt62(&test_val));
}

// Test writing & reading multiple 4-byte-encoded varints
TEST_P(QuicheDataWriterTest, MultiVarInt4) {
  uint64_t test_val;
  char buffer[4 * kMultiVarCount];
  memset(buffer, 0, sizeof(buffer));
  QuicheDataWriter writer(sizeof(buffer), static_cast<char*>(buffer),
                          quiche::Endianness::NETWORK_BYTE_ORDER);
  // Put N values into the buffer. Adding i to the value ensures that
  // each value is different so we can detect if we overwrite values,
  // or read the same value over and over.
  for (int i = 0; i < kMultiVarCount; i++) {
    EXPECT_TRUE(writer.WriteVarInt62(UINT64_C(0x3142f3e4) + i));
  }
  EXPECT_EQ(writer.length(), 4u * kMultiVarCount);

  // N+1st should fail, the buffer is full.
  EXPECT_FALSE(writer.WriteVarInt62(UINT64_C(0x3142f3e4)));

  // Now we should be able to read out the N values that were
  // successfully encoded.
  QuicheDataReader reader(buffer, sizeof(buffer),
                          quiche::Endianness::NETWORK_BYTE_ORDER);
  for (int i = 0; i < kMultiVarCount; i++) {
    EXPECT_TRUE(reader.ReadVarInt62(&test_val));
    EXPECT_EQ(test_val, (UINT64_C(0x3142f3e4) + i));
  }
  // And the N+1st should fail.
  EXPECT_FALSE(reader.ReadVarInt62(&test_val));
}

// Test writing & reading multiple 2-byte-encoded varints
TEST_P(QuicheDataWriterTest, MultiVarInt2) {
  uint64_t test_val;
  char buffer[2 * kMultiVarCount];
  memset(buffer, 0, sizeof(buffer));
  QuicheDataWriter writer(sizeof(buffer), static_cast<char*>(buffer),
                          quiche::Endianness::NETWORK_BYTE_ORDER);
  // Put N values into the buffer. Adding i to the value ensures that
  // each value is different so we can detect if we overwrite values,
  // or read the same value over and over.
  for (int i = 0; i < kMultiVarCount; i++) {
    EXPECT_TRUE(writer.WriteVarInt62(UINT64_C(0x3142) + i));
  }
  EXPECT_EQ(writer.length(), 2u * kMultiVarCount);

  // N+1st should fail, the buffer is full.
  EXPECT_FALSE(writer.WriteVarInt62(UINT64_C(0x3142)));

  // Now we should be able to read out the N values that were
  // successfully encoded.
  QuicheDataReader reader(buffer, sizeof(buffer),
                          quiche::Endianness::NETWORK_BYTE_ORDER);
  for (int i = 0; i < kMultiVarCount; i++) {
    EXPECT_TRUE(reader.ReadVarInt62(&test_val));
    EXPECT_EQ(test_val, (UINT64_C(0x3142) + i));
  }
  // And the N+1st should fail.
  EXPECT_FALSE(reader.ReadVarInt62(&test_val));
}

// Test writing & reading multiple 1-byte-encoded varints
TEST_P(QuicheDataWriterTest, MultiVarInt1) {
  uint64_t test_val;
  char buffer[1 * kMultiVarCount];
  memset(buffer, 0, sizeof(buffer));
  QuicheDataWriter writer(sizeof(buffer), static_cast<char*>(buffer),
                          quiche::Endianness::NETWORK_BYTE_ORDER);
  // Put N values into the buffer. Adding i to the value ensures that
  // each value is different so we can detect if we overwrite values,
  // or read the same value over and over. &0xf ensures we do not
  // overflow the max value for single-byte encoding.
  for (int i = 0; i < kMultiVarCount; i++) {
    EXPECT_TRUE(writer.WriteVarInt62(UINT64_C(0x30) + (i & 0xf)));
  }
  EXPECT_EQ(writer.length(), 1u * kMultiVarCount);

  // N+1st should fail, the buffer is full.
  EXPECT_FALSE(writer.WriteVarInt62(UINT64_C(0x31)));

  // Now we should be able to read out the N values that were
  // successfully encoded.
  QuicheDataReader reader(buffer, sizeof(buffer),
                          quiche::Endianness::NETWORK_BYTE_ORDER);
  for (int i = 0; i < kMultiVarCount; i++) {
    EXPECT_TRUE(reader.ReadVarInt62(&test_val));
    EXPECT_EQ(test_val, (UINT64_C(0x30) + (i & 0xf)));
  }
  // And the N+1st should fail.
  EXPECT_FALSE(reader.ReadVarInt62(&test_val));
}

TEST_P(QuicheDataWriterTest, Seek) {
  char buffer[3] = {};
  QuicheDataWriter writer(ABSL_ARRAYSIZE(buffer), buffer,
                          GetParam().endianness);
  EXPECT_TRUE(writer.WriteUInt8(42));
  EXPECT_TRUE(writer.Seek(1));
  EXPECT_TRUE(writer.WriteUInt8(3));

  char expected[] = {42, 0, 3};
  for (size_t i = 0; i < ABSL_ARRAYSIZE(expected); ++i) {
    EXPECT_EQ(buffer[i], expected[i]);
  }
}

TEST_P(QuicheDataWriterTest, SeekTooFarFails) {
  char buffer[20];

  // Check that one can seek to the end of the writer, but not past.
  {
    QuicheDataWriter writer(ABSL_ARRAYSIZE(buffer), buffer,
                            GetParam().endianness);
    EXPECT_TRUE(writer.Seek(20));
    EXPECT_FALSE(writer.Seek(1));
  }

  // Seeking several bytes past the end fails.
  {
    QuicheDataWriter writer(ABSL_ARRAYSIZE(buffer), buffer,
                            GetParam().endianness);
    EXPECT_FALSE(writer.Seek(100));
  }

  // Seeking so far that arithmetic overflow could occur also fails.
  {
    QuicheDataWriter writer(ABSL_ARRAYSIZE(buffer), buffer,
                            GetParam().endianness);
    EXPECT_TRUE(writer.Seek(10));
    EXPECT_FALSE(writer.Seek(std::numeric_limits<size_t>::max()));
  }
}

TEST_P(QuicheDataWriterTest, PayloadReads) {
  char buffer[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  char expected_first_read[4] = {1, 2, 3, 4};
  char expected_remaining[12] = {5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  QuicheDataReader reader(buffer, sizeof(buffer));
  absl::string_view previously_read_payload1 = reader.PreviouslyReadPayload();
  EXPECT_TRUE(previously_read_payload1.empty());
  char first_read_buffer[4] = {};
  EXPECT_TRUE(reader.ReadBytes(first_read_buffer, sizeof(first_read_buffer)));
  test::CompareCharArraysWithHexError(
      "first read", first_read_buffer, sizeof(first_read_buffer),
      expected_first_read, sizeof(expected_first_read));
  absl::string_view peeked_remaining_payload = reader.PeekRemainingPayload();
  test::CompareCharArraysWithHexError(
      "peeked_remaining_payload", peeked_remaining_payload.data(),
      peeked_remaining_payload.length(), expected_remaining,
      sizeof(expected_remaining));
  absl::string_view full_payload = reader.FullPayload();
  test::CompareCharArraysWithHexError("full_payload", full_payload.data(),
                                      full_payload.length(), buffer,
                                      sizeof(buffer));
  absl::string_view previously_read_payload2 = reader.PreviouslyReadPayload();
  test::CompareCharArraysWithHexError(
      "previously_read_payload2", previously_read_payload2.data(),
      previously_read_payload2.length(), first_read_buffer,
      sizeof(first_read_buffer));
  absl::string_view read_remaining_payload = reader.ReadRemainingPayload();
  test::CompareCharArraysWithHexError(
      "read_remaining_payload", read_remaining_payload.data(),
      read_remaining_payload.length(), expected_remaining,
      sizeof(expected_remaining));
  EXPECT_TRUE(reader.IsDoneReading());
  absl::string_view full_payload2 = reader.FullPayload();
  test::CompareCharArraysWithHexError("full_payload2", full_payload2.data(),
                                      full_payload2.length(), buffer,
                                      sizeof(buffer));
  absl::string_view previously_read_payload3 = reader.PreviouslyReadPayload();
  test::CompareCharArraysWithHexError(
      "previously_read_payload3", previously_read_payload3.data(),
      previously_read_payload3.length(), buffer, sizeof(buffer));
}

}  // namespace
}  // namespace test
}  // namespace quiche

"""

```
Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name `hpack_output_stream_test.cc` immediately suggests it's a test file for something called `HpackOutputStream`. The `test.cc` convention is common in C++ testing frameworks.

2. **Locate the Class Under Test:**  The `#include "quiche/http2/hpack/hpack_output_stream.h"` confirms that we're testing the `HpackOutputStream` class.

3. **Understand the Context (Filename):** The path `net/third_party/quiche/src/quiche/http2/hpack/` gives context. It's part of the Chromium networking stack, specifically within the QUIC implementation (`quiche`), dealing with HTTP/2 (`http2`) header compression (`hpack`).

4. **Analyze the Tests:**  Go through each `TEST` block:

   * **`AppendBits`:**  The name suggests it tests the functionality of appending individual bits. The code manipulates bits and bytes, using bitwise operators. The `expected_str` and the final `EXPECT_EQ` clearly define the expected behavior: appending bits in most significant bit order, handling byte boundaries.

   * **`EncodeUint32`:** This looks like a utility function used within the tests, not a test itself. It takes a prefix length `N` and an integer `I`, and seems to encode `I` with that prefix. This hints at variable-length integer encoding, which is common in network protocols.

   * **`OneByteIntegersEightBitPrefix` through `SixByteIntegersEightBitPrefix`:**  These test encoding of various integers using an 8-bit prefix. The `EXPECT_EQ` calls with specific hex string literals define the expected encodings for different input integers. The naming indicates how many bytes the encoded output *should* be.

   * **`OneByteIntegersOneToSevenBitPrefixes` through `SixByteIntegersOneToSevenBitPrefixes`:** Similar to the previous set, but testing with prefixes of 1 to 7 bits. This reinforces the idea of variable-length encoding based on the prefix.

   * **`AppendUint32PreservesUpperBits`:** This test checks if appending a `uint32_t` after setting some initial bits correctly preserves those initial bits.

   * **`AppendBytes`:** A straightforward test for appending a sequence of bytes (strings).

   * **`BoundedTakeString`:** Tests taking a substring of the output, with a boundary. This suggests a way to retrieve parts of the encoded data without taking the whole thing.

   * **`MutableString`:** Tests the ability to directly access and modify the underlying string buffer.

5. **Summarize the Functionality:** Based on the test names and their actions, the `HpackOutputStream` class is responsible for:

   * Appending individual bits.
   * Encoding unsigned 32-bit integers with variable-length prefixes (from 1 to 8 bits).
   * Appending raw byte strings.
   * Providing ways to retrieve the encoded data, either entirely or in bounded chunks.
   * Allowing direct manipulation of the underlying buffer.

6. **Identify Relationships with JavaScript (if any):**  Hpack is related to HTTP/2 header compression. While the *implementation* is in C++, the *concept* directly impacts how HTTP/2 headers are transmitted. JavaScript running in a browser interacting with an HTTP/2 server will be affected by this compression. The browser doesn't *directly* use this C++ code, but the outcome (compressed headers) is something the JavaScript environment deals with.

7. **Provide Examples for JavaScript:** Illustrate how header compression affects JavaScript: reduced data transfer, faster page load times, and the browser handling decompression transparently.

8. **Infer Logic and Provide Input/Output Examples:** For the bit and integer encoding tests, the `EXPECT_EQ` calls *are* the input/output examples. Extract some of these to clearly demonstrate the encoding logic.

9. **Consider User/Programming Errors:** Think about how someone might misuse this class:
   * Appending bits in the wrong order (though the tests are designed to prevent this logic error in the implementation).
   * Incorrect prefix lengths in encoding functions.
   * Off-by-one errors in bounded string retrieval.

10. **Describe the User Journey (Debugging Context):** Imagine a scenario where a developer might encounter this code during debugging. Trace the steps:
    * A user reports a slow HTTP/2 connection.
    * The developer investigates header compression.
    * They might look at network logs or use debugging tools.
    * To understand how the compression works, they might delve into the Chromium source code, eventually landing in the HPACK implementation and these tests.

11. **Structure the Response:** Organize the findings logically: file functionality, JavaScript relationship, logic examples, potential errors, and debugging context. Use clear headings and bullet points for readability.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on the low-level bit manipulation. Realize the higher-level purpose is HTTP/2 header compression.
* Consider if there are any security implications. While not explicitly tested here, incorrect encoding could potentially lead to vulnerabilities. (Decide whether to include this based on the prompt's scope).
* Double-check the bitwise operations and hex values to ensure accuracy in the input/output examples.
* Ensure the JavaScript examples are clear and directly related to the core functionality.

By following these steps, breaking down the code into smaller units, and constantly relating it back to the broader context, a comprehensive analysis of the test file can be achieved.
这个 C++ 文件 `hpack_output_stream_test.cc` 是 Chromium 网络栈中 QUIC 协议 HTTP/2 的 HPACK (Header Compression for HTTP/2) 实现的测试文件。它专门测试 `HpackOutputStream` 类的功能。

以下是该文件的功能列表：

1. **测试位追加 (AppendBits):** 验证 `AppendBits` 方法是否能正确地将指定的位序列添加到输出流中，包括跨越字节边界的情况。
2. **测试无符号整数编码 (AppendUint32):**  测试 `AppendUint32` 方法在不同前缀长度 (`N`) 下编码无符号 32 位整数的功能。HPACK 使用变长整数编码，前缀位用于指示后续字节是否属于该整数。测试覆盖了 1 到 8 位的前缀长度以及不同字节数的整数编码。
3. **测试字节追加 (AppendBytes):** 验证 `AppendBytes` 方法是否能正确地将字节数组（字符串）添加到输出流中。
4. **测试限定长度字符串提取 (BoundedTakeString):** 测试 `BoundedTakeString` 方法，该方法允许从输出流中提取指定长度的字符串，而不会消耗掉整个流。
5. **测试可变字符串访问 (MutableString):**  测试 `MutableString` 方法，该方法允许直接访问和修改输出流内部的字符串缓冲区。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所测试的功能直接影响着 JavaScript 在浏览器中的网络请求行为。HPACK 是一种用于压缩 HTTP/2 头部的方法，可以显著减少头部大小，从而提高页面加载速度和降低带宽消耗。

当 JavaScript 发起一个 HTTP/2 请求时，浏览器会使用 HPACK 来压缩请求头。`HpackOutputStream` 负责将这些头部信息编码成 HPACK 格式的字节流，然后再通过网络发送到服务器。服务器接收到数据后，会使用 HPACK 的解码器将头部还原。

**举例说明:**

假设 JavaScript 代码发起一个带有自定义头部 `X-Custom-Header: my-value` 的 HTTP/2 请求。

1. **编码:** Chromium 的网络栈会使用 `HpackOutputStream` 将这个头部进行编码。编码过程可能涉及：
   - 将头部名称 `X-Custom-Header` 和值 `my-value` 按照 HPACK 规则进行表示。
   - 如果可能，利用 HPACK 的静态或动态表进行索引表示，以减少数据量。
   - 如果没有索引，则将头部名称和值以字面量的形式编码，并可能使用 Huffman 编码进一步压缩。
   - `AppendUint32` 会被用来编码表示名称或值的长度，以及可能的索引值。
   - `AppendBytes` 会被用来添加实际的头部名称和值（如果以字面量形式编码）。

2. **传输:** 编码后的字节流被发送到服务器。

3. **解码:** 服务器接收到字节流后，使用 HPACK 解码器将其还原为原始的头部 `X-Custom-Header: my-value`。

4. **JavaScript 获取:**  服务器处理请求后，将响应返回给浏览器。浏览器解码响应头，JavaScript 代码可以通过 `fetch` API 或 `XMLHttpRequest` 对象的 `headers` 属性访问到原始的 `X-Custom-Header: my-value`。

**逻辑推理与假设输入/输出:**

**测试 `AppendBits`:**

* **假设输入:**
    * 连续调用 `AppendBits`，例如 `AppendBits(0b1, 1)`, `AppendBits(0b0, 1)`, `AppendBits(0b11, 2)`
* **预期输出:**
    * 输出流的字节序列应该正确反映位序列的组合。例如，上述输入可能产生字节 `0b10110000` (假设后续没有更多添加)。

**测试 `AppendUint32` (以 8 位前缀为例):**

* **假设输入:** `EncodeUint32(8, 300)`
* **预期输出:**  `\xff\x25` (十六进制)。
    * `300` 的十六进制表示是 `0x12c`。
    * 由于前缀是 8 位，且 `300` 大于 127，所以第一个字节设置为 `0xff` 表示后续还有字节。
    * 后续字节编码实际的值，`300 - 128 = 172`，十六进制是 `0xac`。但是编码方式是 7 位一组，所以是 `0x25` (172 的二进制是 `10101100`, 去掉最高位是 `0101100`). （*更正：编码方式是 7 位一组，并设置最高位为 1 表示后续还有字节，为 0 表示结束。所以 300 编码为 `\xff\x80\x24`，第一个字节 `\xff`，后续字节 `10000000` 表示继续，`00100100` 是 300 - 128 的结果*）
    * *进一步更正：HPack 整数编码方式是，如果整数小于 2^N - 1，则直接编码在前 N 位中。否则，将前 N 位设置为全 1，并将剩余的值以 7 位一组编码，每个字节最高位为 1 表示后续还有字节，最后一个字节最高位为 0。所以 300 的编码是： 前缀 8 位，最大值 254。 300 > 254，所以第一个字节是 255 (`\xff`)。剩余值是 `300 - 254 = 46`。46 的二进制是 `00101110`，所以编码为 `\xff\x2e`*

* **假设输入:** `EncodeUint32(8, 10)`
* **预期输出:** `\x0a` (十六进制)。因为 10 小于 127，可以直接用一个字节表示。

**涉及用户或编程常见的使用错误:**

1. **错误的位追加顺序:**  如果开发者错误地假设 `AppendBits` 以最低有效位开始追加，可能会导致编码错误。测试用例确保了以最高有效位开始。
2. **不正确的整数编码前缀:**  如果使用 `AppendUint32` 时指定了错误的 `N` 值，会导致编码不符合 HPACK 规范，接收方可能无法正确解码。例如，本应使用 8 位前缀的地方使用了 7 位。
3. **`BoundedTakeString` 越界:**  如果调用的长度超过了输出流的实际长度，可能会导致未定义的行为或错误。虽然这个测试用例本身可能不会直接暴露这种错误（因为它在测试既定的输出），但在实际使用中需要注意。
4. **直接修改 `MutableString` 可能导致状态不一致:**  虽然提供了 `MutableString` 接口，但如果直接修改返回的字符串而没有正确维护 `HpackOutputStream` 的内部状态，可能会导致后续操作出现问题。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户报告 HTTP/2 网站加载缓慢:**  用户可能注意到某个使用 HTTP/2 的网站加载速度异常慢。

2. **开发者开始调查网络性能:** 开发者使用浏览器开发者工具 (例如 Chrome 的 "Network" 标签) 查看网络请求，发现头部大小异常大，或者怀疑头部压缩有问题。

3. **开发者检查 HTTP/2 连接和头部:** 开发者可能会查看请求和响应的头部信息，确认是否使用了 HTTP/2，以及头部是否被压缩 (例如，通过查看 `content-encoding` 等头部)。

4. **开发者怀疑 HPACK 实现问题:** 如果怀疑是头部压缩的问题，开发者可能会开始查看 Chromium 的网络栈源代码，特别是关于 HTTP/2 和 HPACK 的部分。

5. **开发者定位到 HPACK 输出流:**  为了理解头部是如何被编码的，开发者可能会查阅 `HpackOutputStream` 类的代码，并找到相关的测试文件 `hpack_output_stream_test.cc`，以了解该类的功能和预期行为。

6. **阅读测试用例:** 开发者会仔细阅读测试用例，例如 `AppendBits` 和 `AppendUint32` 的测试，来理解位和整数是如何被编码的，以及可能存在的边界情况和潜在错误。

通过阅读这些测试用例，开发者可以更深入地了解 HPACK 编码的细节，并有助于诊断和解决与 HTTP/2 头部压缩相关的性能问题。这些测试用例也为开发者提供了关于如何正确使用 `HpackOutputStream` 类的示例。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/hpack/hpack_output_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/hpack/hpack_output_stream.h"

#include <cstdint>
#include <string>

#include "quiche/common/platform/api/quiche_test.h"

namespace spdy {

namespace {

// Make sure that AppendBits() appends bits starting from the most
// significant bit, and that it can handle crossing a byte boundary.
TEST(HpackOutputStreamTest, AppendBits) {
  HpackOutputStream output_stream;
  std::string expected_str;

  output_stream.AppendBits(0x1, 1);
  expected_str.append(1, 0x00);
  expected_str.back() |= (0x1 << 7);

  output_stream.AppendBits(0x0, 1);

  output_stream.AppendBits(0x3, 2);
  *expected_str.rbegin() |= (0x3 << 4);

  output_stream.AppendBits(0x0, 2);

  // Byte-crossing append.
  output_stream.AppendBits(0x7, 3);
  *expected_str.rbegin() |= (0x7 >> 1);
  expected_str.append(1, 0x00);
  expected_str.back() |= (0x7 << 7);

  output_stream.AppendBits(0x0, 7);

  std::string str = output_stream.TakeString();
  EXPECT_EQ(expected_str, str);
}

// Utility function to return I as a string encoded with an N-bit
// prefix.
std::string EncodeUint32(uint8_t N, uint32_t I) {
  HpackOutputStream output_stream;
  if (N < 8) {
    output_stream.AppendBits(0x00, 8 - N);
  }
  output_stream.AppendUint32(I);
  std::string str = output_stream.TakeString();
  return str;
}

// The {Number}ByteIntegersEightBitPrefix tests below test that
// certain integers are encoded correctly with an 8-bit prefix in
// exactly {Number} bytes.

TEST(HpackOutputStreamTest, OneByteIntegersEightBitPrefix) {
  // Minimum.
  EXPECT_EQ(std::string("\x00", 1), EncodeUint32(8, 0x00));
  EXPECT_EQ("\x7f", EncodeUint32(8, 0x7f));
  // Maximum.
  EXPECT_EQ("\xfe", EncodeUint32(8, 0xfe));
}

TEST(HpackOutputStreamTest, TwoByteIntegersEightBitPrefix) {
  // Minimum.
  EXPECT_EQ(std::string("\xff\x00", 2), EncodeUint32(8, 0xff));
  EXPECT_EQ("\xff\x01", EncodeUint32(8, 0x0100));
  // Maximum.
  EXPECT_EQ("\xff\x7f", EncodeUint32(8, 0x017e));
}

TEST(HpackOutputStreamTest, ThreeByteIntegersEightBitPrefix) {
  // Minimum.
  EXPECT_EQ("\xff\x80\x01", EncodeUint32(8, 0x017f));
  EXPECT_EQ("\xff\x80\x1e", EncodeUint32(8, 0x0fff));
  // Maximum.
  EXPECT_EQ("\xff\xff\x7f", EncodeUint32(8, 0x40fe));
}

TEST(HpackOutputStreamTest, FourByteIntegersEightBitPrefix) {
  // Minimum.
  EXPECT_EQ("\xff\x80\x80\x01", EncodeUint32(8, 0x40ff));
  EXPECT_EQ("\xff\x80\xfe\x03", EncodeUint32(8, 0xffff));
  // Maximum.
  EXPECT_EQ("\xff\xff\xff\x7f", EncodeUint32(8, 0x002000fe));
}

TEST(HpackOutputStreamTest, FiveByteIntegersEightBitPrefix) {
  // Minimum.
  EXPECT_EQ("\xff\x80\x80\x80\x01", EncodeUint32(8, 0x002000ff));
  EXPECT_EQ("\xff\x80\xfe\xff\x07", EncodeUint32(8, 0x00ffffff));
  // Maximum.
  EXPECT_EQ("\xff\xff\xff\xff\x7f", EncodeUint32(8, 0x100000fe));
}

TEST(HpackOutputStreamTest, SixByteIntegersEightBitPrefix) {
  // Minimum.
  EXPECT_EQ("\xff\x80\x80\x80\x80\x01", EncodeUint32(8, 0x100000ff));
  // Maximum.
  EXPECT_EQ("\xff\x80\xfe\xff\xff\x0f", EncodeUint32(8, 0xffffffff));
}

// The {Number}ByteIntegersOneToSevenBitPrefix tests below test that
// certain integers are encoded correctly with an N-bit prefix in
// exactly {Number} bytes for N in {1, 2, ..., 7}.

TEST(HpackOutputStreamTest, OneByteIntegersOneToSevenBitPrefixes) {
  // Minimums.
  EXPECT_EQ(std::string("\x00", 1), EncodeUint32(7, 0x00));
  EXPECT_EQ(std::string("\x00", 1), EncodeUint32(6, 0x00));
  EXPECT_EQ(std::string("\x00", 1), EncodeUint32(5, 0x00));
  EXPECT_EQ(std::string("\x00", 1), EncodeUint32(4, 0x00));
  EXPECT_EQ(std::string("\x00", 1), EncodeUint32(3, 0x00));
  EXPECT_EQ(std::string("\x00", 1), EncodeUint32(2, 0x00));
  EXPECT_EQ(std::string("\x00", 1), EncodeUint32(1, 0x00));

  // Maximums.
  EXPECT_EQ("\x7e", EncodeUint32(7, 0x7e));
  EXPECT_EQ("\x3e", EncodeUint32(6, 0x3e));
  EXPECT_EQ("\x1e", EncodeUint32(5, 0x1e));
  EXPECT_EQ("\x0e", EncodeUint32(4, 0x0e));
  EXPECT_EQ("\x06", EncodeUint32(3, 0x06));
  EXPECT_EQ("\x02", EncodeUint32(2, 0x02));
  EXPECT_EQ(std::string("\x00", 1), EncodeUint32(1, 0x00));
}

TEST(HpackOutputStreamTest, TwoByteIntegersOneToSevenBitPrefixes) {
  // Minimums.
  EXPECT_EQ(std::string("\x7f\x00", 2), EncodeUint32(7, 0x7f));
  EXPECT_EQ(std::string("\x3f\x00", 2), EncodeUint32(6, 0x3f));
  EXPECT_EQ(std::string("\x1f\x00", 2), EncodeUint32(5, 0x1f));
  EXPECT_EQ(std::string("\x0f\x00", 2), EncodeUint32(4, 0x0f));
  EXPECT_EQ(std::string("\x07\x00", 2), EncodeUint32(3, 0x07));
  EXPECT_EQ(std::string("\x03\x00", 2), EncodeUint32(2, 0x03));
  EXPECT_EQ(std::string("\x01\x00", 2), EncodeUint32(1, 0x01));

  // Maximums.
  EXPECT_EQ("\x7f\x7f", EncodeUint32(7, 0xfe));
  EXPECT_EQ("\x3f\x7f", EncodeUint32(6, 0xbe));
  EXPECT_EQ("\x1f\x7f", EncodeUint32(5, 0x9e));
  EXPECT_EQ("\x0f\x7f", EncodeUint32(4, 0x8e));
  EXPECT_EQ("\x07\x7f", EncodeUint32(3, 0x86));
  EXPECT_EQ("\x03\x7f", EncodeUint32(2, 0x82));
  EXPECT_EQ("\x01\x7f", EncodeUint32(1, 0x80));
}

TEST(HpackOutputStreamTest, ThreeByteIntegersOneToSevenBitPrefixes) {
  // Minimums.
  EXPECT_EQ("\x7f\x80\x01", EncodeUint32(7, 0xff));
  EXPECT_EQ("\x3f\x80\x01", EncodeUint32(6, 0xbf));
  EXPECT_EQ("\x1f\x80\x01", EncodeUint32(5, 0x9f));
  EXPECT_EQ("\x0f\x80\x01", EncodeUint32(4, 0x8f));
  EXPECT_EQ("\x07\x80\x01", EncodeUint32(3, 0x87));
  EXPECT_EQ("\x03\x80\x01", EncodeUint32(2, 0x83));
  EXPECT_EQ("\x01\x80\x01", EncodeUint32(1, 0x81));

  // Maximums.
  EXPECT_EQ("\x7f\xff\x7f", EncodeUint32(7, 0x407e));
  EXPECT_EQ("\x3f\xff\x7f", EncodeUint32(6, 0x403e));
  EXPECT_EQ("\x1f\xff\x7f", EncodeUint32(5, 0x401e));
  EXPECT_EQ("\x0f\xff\x7f", EncodeUint32(4, 0x400e));
  EXPECT_EQ("\x07\xff\x7f", EncodeUint32(3, 0x4006));
  EXPECT_EQ("\x03\xff\x7f", EncodeUint32(2, 0x4002));
  EXPECT_EQ("\x01\xff\x7f", EncodeUint32(1, 0x4000));
}

TEST(HpackOutputStreamTest, FourByteIntegersOneToSevenBitPrefixes) {
  // Minimums.
  EXPECT_EQ("\x7f\x80\x80\x01", EncodeUint32(7, 0x407f));
  EXPECT_EQ("\x3f\x80\x80\x01", EncodeUint32(6, 0x403f));
  EXPECT_EQ("\x1f\x80\x80\x01", EncodeUint32(5, 0x401f));
  EXPECT_EQ("\x0f\x80\x80\x01", EncodeUint32(4, 0x400f));
  EXPECT_EQ("\x07\x80\x80\x01", EncodeUint32(3, 0x4007));
  EXPECT_EQ("\x03\x80\x80\x01", EncodeUint32(2, 0x4003));
  EXPECT_EQ("\x01\x80\x80\x01", EncodeUint32(1, 0x4001));

  // Maximums.
  EXPECT_EQ("\x7f\xff\xff\x7f", EncodeUint32(7, 0x20007e));
  EXPECT_EQ("\x3f\xff\xff\x7f", EncodeUint32(6, 0x20003e));
  EXPECT_EQ("\x1f\xff\xff\x7f", EncodeUint32(5, 0x20001e));
  EXPECT_EQ("\x0f\xff\xff\x7f", EncodeUint32(4, 0x20000e));
  EXPECT_EQ("\x07\xff\xff\x7f", EncodeUint32(3, 0x200006));
  EXPECT_EQ("\x03\xff\xff\x7f", EncodeUint32(2, 0x200002));
  EXPECT_EQ("\x01\xff\xff\x7f", EncodeUint32(1, 0x200000));
}

TEST(HpackOutputStreamTest, FiveByteIntegersOneToSevenBitPrefixes) {
  // Minimums.
  EXPECT_EQ("\x7f\x80\x80\x80\x01", EncodeUint32(7, 0x20007f));
  EXPECT_EQ("\x3f\x80\x80\x80\x01", EncodeUint32(6, 0x20003f));
  EXPECT_EQ("\x1f\x80\x80\x80\x01", EncodeUint32(5, 0x20001f));
  EXPECT_EQ("\x0f\x80\x80\x80\x01", EncodeUint32(4, 0x20000f));
  EXPECT_EQ("\x07\x80\x80\x80\x01", EncodeUint32(3, 0x200007));
  EXPECT_EQ("\x03\x80\x80\x80\x01", EncodeUint32(2, 0x200003));
  EXPECT_EQ("\x01\x80\x80\x80\x01", EncodeUint32(1, 0x200001));

  // Maximums.
  EXPECT_EQ("\x7f\xff\xff\xff\x7f", EncodeUint32(7, 0x1000007e));
  EXPECT_EQ("\x3f\xff\xff\xff\x7f", EncodeUint32(6, 0x1000003e));
  EXPECT_EQ("\x1f\xff\xff\xff\x7f", EncodeUint32(5, 0x1000001e));
  EXPECT_EQ("\x0f\xff\xff\xff\x7f", EncodeUint32(4, 0x1000000e));
  EXPECT_EQ("\x07\xff\xff\xff\x7f", EncodeUint32(3, 0x10000006));
  EXPECT_EQ("\x03\xff\xff\xff\x7f", EncodeUint32(2, 0x10000002));
  EXPECT_EQ("\x01\xff\xff\xff\x7f", EncodeUint32(1, 0x10000000));
}

TEST(HpackOutputStreamTest, SixByteIntegersOneToSevenBitPrefixes) {
  // Minimums.
  EXPECT_EQ("\x7f\x80\x80\x80\x80\x01", EncodeUint32(7, 0x1000007f));
  EXPECT_EQ("\x3f\x80\x80\x80\x80\x01", EncodeUint32(6, 0x1000003f));
  EXPECT_EQ("\x1f\x80\x80\x80\x80\x01", EncodeUint32(5, 0x1000001f));
  EXPECT_EQ("\x0f\x80\x80\x80\x80\x01", EncodeUint32(4, 0x1000000f));
  EXPECT_EQ("\x07\x80\x80\x80\x80\x01", EncodeUint32(3, 0x10000007));
  EXPECT_EQ("\x03\x80\x80\x80\x80\x01", EncodeUint32(2, 0x10000003));
  EXPECT_EQ("\x01\x80\x80\x80\x80\x01", EncodeUint32(1, 0x10000001));

  // Maximums.
  EXPECT_EQ("\x7f\x80\xff\xff\xff\x0f", EncodeUint32(7, 0xffffffff));
  EXPECT_EQ("\x3f\xc0\xff\xff\xff\x0f", EncodeUint32(6, 0xffffffff));
  EXPECT_EQ("\x1f\xe0\xff\xff\xff\x0f", EncodeUint32(5, 0xffffffff));
  EXPECT_EQ("\x0f\xf0\xff\xff\xff\x0f", EncodeUint32(4, 0xffffffff));
  EXPECT_EQ("\x07\xf8\xff\xff\xff\x0f", EncodeUint32(3, 0xffffffff));
  EXPECT_EQ("\x03\xfc\xff\xff\xff\x0f", EncodeUint32(2, 0xffffffff));
  EXPECT_EQ("\x01\xfe\xff\xff\xff\x0f", EncodeUint32(1, 0xffffffff));
}

// Test that encoding an integer with an N-bit prefix preserves the
// upper (8-N) bits of the first byte.
TEST(HpackOutputStreamTest, AppendUint32PreservesUpperBits) {
  HpackOutputStream output_stream;
  output_stream.AppendBits(0x7f, 7);
  output_stream.AppendUint32(0x01);
  std::string str = output_stream.TakeString();
  EXPECT_EQ(std::string("\xff\x00", 2), str);
}

TEST(HpackOutputStreamTest, AppendBytes) {
  HpackOutputStream output_stream;

  output_stream.AppendBytes("buffer1");
  output_stream.AppendBytes("buffer2");

  std::string str = output_stream.TakeString();
  EXPECT_EQ("buffer1buffer2", str);
}

TEST(HpackOutputStreamTest, BoundedTakeString) {
  HpackOutputStream output_stream;

  output_stream.AppendBytes("buffer12");
  output_stream.AppendBytes("buffer456");

  std::string str = output_stream.BoundedTakeString(9);
  EXPECT_EQ("buffer12b", str);

  output_stream.AppendBits(0x7f, 7);
  output_stream.AppendUint32(0x11);
  str = output_stream.BoundedTakeString(9);
  EXPECT_EQ("uffer456\xff", str);

  str = output_stream.BoundedTakeString(9);
  EXPECT_EQ("\x10", str);
}

TEST(HpackOutputStreamTest, MutableString) {
  HpackOutputStream output_stream;

  output_stream.AppendBytes("1");
  output_stream.MutableString()->append("2");

  output_stream.AppendBytes("foo");
  output_stream.MutableString()->append("bar");

  std::string str = output_stream.TakeString();
  EXPECT_EQ("12foobar", str);
}

}  // namespace

}  // namespace spdy
```
Response:
The user wants a summary of the C++ source code file `v8/third_party/inspector_protocol/crdtp/cbor_test.cc`.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The file name `cbor_test.cc` strongly suggests this file contains unit tests for CBOR (Concise Binary Object Representation) functionality. The path `v8/third_party/inspector_protocol/crdtp/` further suggests this CBOR implementation is used within the Chrome DevTools Protocol (CRDP) in the V8 JavaScript engine.

2. **Scan the includes:** The included headers provide clues about the file's capabilities:
    * `"cbor.h"`:  The core CBOR implementation being tested.
    * Standard library headers (`<array>`, `<clocale>`, etc.): Basic utilities.
    * `"json.h"` and `"parser_handler.h"`: Interaction with JSON, likely for converting between CBOR and JSON.
    * `"span.h"`:  Using `span` for efficient data handling.
    * `"status.h"` and `"status_test_support.h"`:  Error handling and testing framework integration.
    * `"test_platform.h"`: V8's testing infrastructure.

3. **Analyze the test structure:** The code uses the `TEST()` macro, which is a clear indication of Google Test usage. The test names (`IsCBORMessage`, `CheckCBORMessage`, `EncodeDecodeInt32Test`, etc.) reveal the specific features being tested.

4. **Group the tests by functionality:** Observe the organization of the tests and group them logically. For example:
    * Tests related to identifying CBOR content.
    * Tests focused on encoding and decoding individual CBOR data types (integers, strings, binary data, floating-point numbers).
    * Tests for encoding and decoding complete CBOR messages, including nested structures.
    * Tests for converting between JSON and CBOR.

5. **Identify key classes and functions:** Look for important classes and functions being tested, like `IsCBORMessage`, `CheckCBORMessage`, `EncodeInt32`, `EncodeString16`, `CBORTokenizer`, `NewCBOREncoder`, etc. Note their roles (e.g., `CBORTokenizer` for parsing, `NewCBOREncoder` for encoding from a stream).

6. **Consider the "Torque" aspect:** The prompt mentions `.tq` files. Since this file is `.cc`, it's not a Torque source file. State this clearly.

7. **Relate to JavaScript (if applicable):**  The file deals with CBOR, which is often used for efficient data serialization. Mention that while this *specific* file is C++, the underlying CBOR functionality is likely used when V8 needs to serialize data for communication, potentially including communication with the DevTools frontend (which uses JavaScript). Provide a simple JavaScript example of data serialization (though not directly using CBOR in JS, as it's an internal V8 detail).

8. **Address logic and error handling:**  The tests implicitly demonstrate logic by verifying encoding and decoding. The `Status` class and the `EXPECT_THAT(status, StatusIs(...))` assertions highlight the testing of error conditions. Provide an example of a common programming error that CBOR might help avoid (manual parsing/serialization).

9. **Summarize the functionality concisely:** Combine the observations into a high-level summary that addresses the prompt's request.

10. **Review and refine:** Ensure the summary is accurate, well-organized, and addresses all points in the prompt. Check for clarity and conciseness. For instance, initially, I might have just listed the test names. However, grouping them by functionality provides a much better understanding. Similarly, explaining *why* CBOR might be relevant to JavaScript (serialization) is more informative than simply stating it's related. Adding the point about common programming errors enhances the practical understanding.
这是V8 JavaScript引擎中用于测试CBOR（Concise Binary Object Representation）编码和解码功能的C++源代码文件。CBOR是一种二进制数据序列化格式，旨在提供比JSON更小的消息大小。

**主要功能归纳:**

1. **CBOR 消息的检测和校验:**
   - `IsCBORMessage`:  判断给定的字节序列是否看起来像一个CBOR消息（基于起始的特定字节）。
   - `CheckCBORMessage`:  执行更严格的校验，检查CBOR消息的信封（envelope）结构是否有效，例如起始字节、长度信息等。

2. **CBOR 数据的编码和解码:**
   - **编码特定类型的数据:**  提供了一系列函数用于将C++中的基本数据类型（如整数、字符串、二进制数据、浮点数）编码成CBOR格式。例如：
     - `EncodeInt32`: 编码32位整数。
     - `EncodeString16`: 编码UTF-16字符串。
     - `EncodeString8`: 编码UTF-8字符串。
     - `EncodeBinary`: 编码二进制数据。
     - `EncodeDouble`: 编码双精度浮点数。
   - **使用 `CBORTokenizer` 进行解码:**  提供了一个 `CBORTokenizer` 类，用于从CBOR字节流中解析出各个数据项，并获取其类型和值。
   - **信封（Envelope）的编码和解码:**  CBOR消息通常包含一个信封结构，用于包裹实际的数据。测试了信封的编码和解码，以及如何访问信封的内容。

3. **JSON 和 CBOR 之间的转换:**
   - 使用 `NewCBOREncoder` 将 JSON 数据编码成 CBOR。
   - 使用 `json::NewJSONEncoder` 和 `ParseCBOR` 将 CBOR 数据解码成 JSON。

**关于问题中的其他点:**

* **`.tq` 结尾:**  `v8/third_party/inspector_protocol/crdtp/cbor_test.cc` 以 `.cc` 结尾，所以它是一个 C++ 源代码文件，而不是 V8 Torque 源代码。

* **与 JavaScript 的功能关系:** 虽然这个文件是 C++ 代码，但它测试的 CBOR 功能在 V8 内部可能与 JavaScript 有关系。CBOR 可以作为一种高效的数据序列化方式，用于在 V8 的不同组件之间传递数据，或者在与外部系统（例如 Chrome DevTools 前端）通信时使用。

   **JavaScript 示例 (概念性):**  虽然 JavaScript 本身不直接操作这个 C++ 文件中的代码，但 V8 可能会在内部使用 CBOR 来序列化某些数据，例如用于调试或性能分析的信息。  你可以想象一个场景，当你在 Chrome DevTools 中检查一个 JavaScript 对象的属性时，V8 可能会将该对象的信息序列化为 CBOR 并发送到前端。前端的 JavaScript 代码会接收并反序列化这些 CBOR 数据。

   ```javascript
   // 这是一个概念性的例子，并不直接展示如何使用这个 C++ 文件
   // 假设 V8 内部使用了 CBOR 来序列化数据

   // V8 内部可能将一个 JavaScript 对象序列化为 CBOR
   const myObject = {
       name: "example",
       value: 123
   };

   // (V8 内部的 C++ 代码会将 myObject 序列化为 CBOR 字节流)
   // ...

   // Chrome DevTools 前端的 JavaScript 代码接收到 CBOR 数据
   const cborData = new Uint8Array([...]); // 假设这是接收到的 CBOR 字节流

   // (Chrome DevTools 前端可能会使用一个 CBOR 解析库来反序列化数据)
   // 假设存在一个名为 cbor 的库
   const decodedObject = cbor.decode(cborData);

   console.log(decodedObject.name); // 输出 "example"
   console.log(decodedObject.value); // 输出 123
   ```

* **代码逻辑推理 (假设输入与输出):**

   **假设输入:** 一个包含整数 123 的 C++ `std::vector<uint8_t>`。
   **预期输出:** 当使用 `CBORTokenizer` 解析这个字节序列时，会得到一个 `CBORTokenTag::INT32` 类型的 token，并且 `GetInt32()` 方法会返回 123。

   ```c++
   #include "cbor.h"
   #include <vector>
   #include <iostream>

   int main() {
       std::vector<uint8_t> encoded;
       v8_crdtp::cbor::EncodeInt32(123, &encoded);

       v8_crdtp::cbor::CBORTokenizer tokenizer(v8_crdtp::SpanFrom(encoded));
       if (tokenizer.TokenTag() == v8_crdtp::cbor::CBORTokenTag::INT32) {
           std::cout << "Decoded integer: " << tokenizer.GetInt32() << std::endl;
       } else {
           std::cout << "Decoding failed." << std::endl;
       }
       return 0;
   }
   // 预期输出: Decoded integer: 123
   ```

* **用户常见的编程错误:**  在处理二进制数据序列化时，一个常见的错误是 **字节序（Endianness）** 的处理不当。不同的系统可能使用大端序或小端序来存储多字节数据（如整数）。如果发送方和接收方使用的字节序不同，反序列化时就会出错。

   **CBOR 如何帮助避免错误 (或者需要注意的点):** CBOR 规范定义了其字节顺序（通常是大端序），因此使用 CBOR 可以减少因字节序不一致导致的错误。然而，在将 CBOR 数据映射到特定编程语言的数据结构时，仍然需要注意语言内部的字节序处理。例如，在 `EncodeDecodeString16Test` 中，可以看到 `String16WireRepToHost` 函数用于处理 UTF-16 字符串在网络传输时的小端序表示。

总结来说，`v8/third_party/inspector_protocol/crdtp/cbor_test.cc` 是 V8 中用于测试 CBOR 编码和解码功能的 C++ 单元测试文件，它涵盖了 CBOR 消息的检测、各种数据类型的编码和解码，以及 JSON 与 CBOR 之间的转换。虽然它是 C++ 代码，但它测试的功能可能在 V8 内部用于 JavaScript 相关的数据序列化场景。

### 提示词
```
这是目录为v8/third_party/inspector_protocol/crdtp/cbor_test.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/third_party/inspector_protocol/crdtp/cbor_test.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cbor.h"

#include <array>
#include <clocale>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include "json.h"
#include "parser_handler.h"
#include "span.h"
#include "status.h"
#include "status_test_support.h"
#include "test_platform.h"

using testing::ElementsAreArray;
using testing::Eq;

namespace v8_crdtp {
namespace cbor {
// =============================================================================
// Detecting CBOR content
// =============================================================================

TEST(IsCBORMessage, SomeSmokeTests) {
  std::vector<uint8_t> empty;
  EXPECT_FALSE(IsCBORMessage(SpanFrom(empty)));
  std::vector<uint8_t> hello = {'H', 'e', 'l', 'o', ' ', 't',
                                'h', 'e', 'r', 'e', '!'};
  EXPECT_FALSE(IsCBORMessage(SpanFrom(hello)));
  std::vector<uint8_t> example = {0xd8, 0x5a, 0, 0, 0, 0};
  EXPECT_TRUE(IsCBORMessage(SpanFrom(example)));
  std::vector<uint8_t> one = {0xd8, 0x5a, 0, 0, 0, 1, 1};
  EXPECT_TRUE(IsCBORMessage(SpanFrom(one)));
}

TEST(CheckCBORMessage, SmallestValidExample) {
  // The smallest example that we consider valid for this lightweight check is
  // an empty dictionary inside of an envelope.
  std::vector<uint8_t> empty_dict = {
      0xd8, 0x5a, 0, 0, 0, 2, EncodeIndefiniteLengthMapStart(), EncodeStop()};
  Status status = CheckCBORMessage(SpanFrom(empty_dict));
  EXPECT_THAT(status, StatusIsOk());
}

TEST(CheckCBORMessage, ValidCBORButNotValidMessage) {
  // The CBOR parser supports parsing values that aren't messages. E.g., this is
  // the encoded unsigned int 7 (CBOR really encodes it as a single byte with
  // value 7).
  std::vector<uint8_t> not_a_message = {7};

  // Show that the parser (happily) decodes it into JSON
  std::string json;
  Status status;
  std::unique_ptr<ParserHandler> json_writer =
      json::NewJSONEncoder(&json, &status);
  ParseCBOR(SpanFrom(not_a_message), json_writer.get());
  EXPECT_THAT(status, StatusIsOk());
  EXPECT_EQ("7", json);

  // ... but it's not a message.
  EXPECT_THAT(CheckCBORMessage(SpanFrom(not_a_message)),
              StatusIs(Error::CBOR_INVALID_START_BYTE, 0));
}

TEST(CheckCBORMessage, EmptyMessage) {
  std::vector<uint8_t> empty;
  Status status = CheckCBORMessage(SpanFrom(empty));
  EXPECT_THAT(status, StatusIs(Error::CBOR_UNEXPECTED_EOF_IN_ENVELOPE, 0));
}

TEST(CheckCBORMessage, InvalidStartByte) {
  // Here we test that some actual json, which usually starts with {, is not
  // considered CBOR. CBOR messages must start with 0xd8, 0x5a, the envelope
  // start bytes.
  Status status = CheckCBORMessage(SpanFrom("{\"msg\": \"Hello, world.\"}"));
  EXPECT_THAT(status, StatusIs(Error::CBOR_INVALID_START_BYTE, 0));
}

TEST(CheckCBORMessage, InvalidEnvelopes) {
  std::vector<uint8_t> bytes = {0xd8, 0x5a};
  EXPECT_THAT(CheckCBORMessage(SpanFrom(bytes)),
              StatusIs(Error::CBOR_UNEXPECTED_EOF_IN_ENVELOPE, 2));
  bytes = {0xd8, 0x5a, 0};
  EXPECT_THAT(CheckCBORMessage(SpanFrom(bytes)),
              StatusIs(Error::CBOR_UNEXPECTED_EOF_IN_ENVELOPE, 3));
  bytes = {0xd8, 0x5a, 0, 0};
  EXPECT_THAT(CheckCBORMessage(SpanFrom(bytes)),
              StatusIs(Error::CBOR_UNEXPECTED_EOF_IN_ENVELOPE, 4));
  bytes = {0xd8, 0x5a, 0, 0, 0};
  EXPECT_THAT(CheckCBORMessage(SpanFrom(bytes)),
              StatusIs(Error::CBOR_UNEXPECTED_EOF_IN_ENVELOPE, 5));
  bytes = {0xd8, 0x5a, 0, 0, 0, 0};
  EXPECT_THAT(CheckCBORMessage(SpanFrom(bytes)),
              StatusIs(Error::CBOR_MAP_OR_ARRAY_EXPECTED_IN_ENVELOPE, 6));
}

TEST(CheckCBORMessage, MapStartExpected) {
  std::vector<uint8_t> bytes = {0xd8, 0x5a, 0, 0, 0, 1};
  EXPECT_THAT(CheckCBORMessage(SpanFrom(bytes)),
              StatusIs(Error::CBOR_ENVELOPE_CONTENTS_LENGTH_MISMATCH, 6));
}

// =============================================================================
// Encoding individual CBOR items
// cbor::CBORTokenizer - for parsing individual CBOR items
// =============================================================================

//
// EncodeInt32 / CBORTokenTag::INT32
//
TEST(EncodeDecodeInt32Test, Roundtrips23) {
  // This roundtrips the int32_t value 23 through the pair of EncodeInt32 /
  // CBORTokenizer; this is interesting since 23 is encoded as a single byte.
  std::vector<uint8_t> encoded;
  EncodeInt32(23, &encoded);
  // first three bits: major type = 0; remaining five bits: additional info =
  // value 23.
  EXPECT_THAT(encoded, ElementsAreArray(std::array<uint8_t, 1>{{23}}));

  // Reverse direction: decode with CBORTokenizer.
  CBORTokenizer tokenizer(SpanFrom(encoded));
  EXPECT_EQ(CBORTokenTag::INT32, tokenizer.TokenTag());
  EXPECT_EQ(23, tokenizer.GetInt32());
  tokenizer.Next();
  EXPECT_EQ(CBORTokenTag::DONE, tokenizer.TokenTag());
}

TEST(EncodeDecodeInt32Test, RoundtripsUint8) {
  // This roundtrips the int32_t value 42 through the pair of EncodeInt32 /
  // CBORTokenizer. This is different from Roundtrip23 because 42 is encoded
  // in an extra byte after the initial one.
  std::vector<uint8_t> encoded;
  EncodeInt32(42, &encoded);
  // first three bits: major type = 0;
  // remaining five bits: additional info = 24, indicating payload is uint8.
  EXPECT_THAT(encoded, ElementsAreArray(std::array<uint8_t, 2>{{24, 42}}));

  // Reverse direction: decode with CBORTokenizer.
  CBORTokenizer tokenizer(SpanFrom(encoded));
  EXPECT_EQ(CBORTokenTag::INT32, tokenizer.TokenTag());
  EXPECT_EQ(42, tokenizer.GetInt32());
  tokenizer.Next();
  EXPECT_EQ(CBORTokenTag::DONE, tokenizer.TokenTag());
}

TEST(EncodeDecodeInt32Test, RoundtripsUint16) {
  // 500 is encoded as a uint16 after the initial byte.
  std::vector<uint8_t> encoded;
  EncodeInt32(500, &encoded);
  // 1 for initial byte, 2 for uint16.
  EXPECT_EQ(3u, encoded.size());
  // first three bits: major type = 0;
  // remaining five bits: additional info = 25, indicating payload is uint16.
  EXPECT_EQ(25, encoded[0]);
  EXPECT_EQ(0x01, encoded[1]);
  EXPECT_EQ(0xf4, encoded[2]);

  // Reverse direction: decode with CBORTokenizer.
  CBORTokenizer tokenizer(SpanFrom(encoded));
  EXPECT_EQ(CBORTokenTag::INT32, tokenizer.TokenTag());
  EXPECT_EQ(500, tokenizer.GetInt32());
  tokenizer.Next();
  EXPECT_EQ(CBORTokenTag::DONE, tokenizer.TokenTag());
}

TEST(EncodeDecodeInt32Test, RoundtripsInt32Max) {
  // std::numeric_limits<int32_t> is encoded as a uint32 after the initial byte.
  std::vector<uint8_t> encoded;
  EncodeInt32(std::numeric_limits<int32_t>::max(), &encoded);
  // 1 for initial byte, 4 for the uint32.
  // first three bits: major type = 0;
  // remaining five bits: additional info = 26, indicating payload is uint32.
  EXPECT_THAT(
      encoded,
      ElementsAreArray(std::array<uint8_t, 5>{{26, 0x7f, 0xff, 0xff, 0xff}}));

  // Reverse direction: decode with CBORTokenizer.
  CBORTokenizer tokenizer(SpanFrom(encoded));
  EXPECT_EQ(CBORTokenTag::INT32, tokenizer.TokenTag());
  EXPECT_EQ(std::numeric_limits<int32_t>::max(), tokenizer.GetInt32());
  tokenizer.Next();
  EXPECT_EQ(CBORTokenTag::DONE, tokenizer.TokenTag());
}

TEST(EncodeDecodeInt32Test, RoundtripsInt32Min) {
  // std::numeric_limits<int32_t> is encoded as a uint32 (4 unsigned bytes)
  // after the initial byte, which effectively carries the sign by
  // designating the token as NEGATIVE.
  std::vector<uint8_t> encoded;
  EncodeInt32(std::numeric_limits<int32_t>::min(), &encoded);
  // 1 for initial byte, 4 for the uint32.
  // first three bits: major type = 1;
  // remaining five bits: additional info = 26, indicating payload is uint32.
  EXPECT_THAT(encoded, ElementsAreArray(std::array<uint8_t, 5>{
                           {1 << 5 | 26, 0x7f, 0xff, 0xff, 0xff}}));

  // Reverse direction: decode with CBORTokenizer.
  CBORTokenizer tokenizer(SpanFrom(encoded));
  EXPECT_EQ(CBORTokenTag::INT32, tokenizer.TokenTag());
  EXPECT_EQ(std::numeric_limits<int32_t>::min(), tokenizer.GetInt32());
  // It's nice to see how the min int32 value reads in hex:
  // That is, -1 minus the unsigned payload (0x7fffffff, see above).
  int32_t expected = -1 - 0x7fffffff;
  EXPECT_EQ(expected, tokenizer.GetInt32());
  tokenizer.Next();
  EXPECT_EQ(CBORTokenTag::DONE, tokenizer.TokenTag());
}

TEST(EncodeDecodeInt32Test, CantRoundtripUint32) {
  // 0xdeadbeef is a value which does not fit below
  // std::numerical_limits<int32_t>::max(), so we can't encode
  // it with EncodeInt32. However, CBOR does support this, so we
  // encode it here manually with the internal routine, just to observe
  // that it's considered an invalid int32 by CBORTokenizer.
  std::vector<uint8_t> encoded;
  internals::WriteTokenStart(MajorType::UNSIGNED, 0xdeadbeef, &encoded);
  // 1 for initial byte, 4 for the uint32.
  // first three bits: major type = 0;
  // remaining five bits: additional info = 26, indicating payload is uint32.
  EXPECT_THAT(
      encoded,
      ElementsAreArray(std::array<uint8_t, 5>{{26, 0xde, 0xad, 0xbe, 0xef}}));

  // Now try to decode; we treat this as an invalid INT32.
  CBORTokenizer tokenizer(SpanFrom(encoded));
  // 0xdeadbeef is > std::numerical_limits<int32_t>::max().
  EXPECT_EQ(CBORTokenTag::ERROR_VALUE, tokenizer.TokenTag());
  EXPECT_THAT(tokenizer.Status(), StatusIs(Error::CBOR_INVALID_INT32, 0u));
}

TEST(EncodeDecodeInt32Test, DecodeErrorCases) {
  struct TestCase {
    std::vector<uint8_t> data;
    std::string msg;
  };
  std::vector<TestCase> tests{{
      TestCase{
          {24},
          "additional info = 24 would require 1 byte of payload (but it's 0)"},
      TestCase{{27, 0xaa, 0xbb, 0xcc},
               "additional info = 27 would require 8 bytes of payload (but "
               "it's 3)"},
      TestCase{{29}, "additional info = 29 isn't recognized"},
      TestCase{{1 << 5 | 27, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
               "Max UINT64 payload is outside the allowed range"},
      TestCase{{1 << 5 | 26, 0xff, 0xff, 0xff, 0xff},
               "Max UINT32 payload is outside the allowed range"},
      TestCase{{1 << 5 | 26, 0x80, 0x00, 0x00, 0x00},
               "UINT32 payload w/ high bit set is outside the allowed range"},
  }};
  for (const TestCase& test : tests) {
    SCOPED_TRACE(test.msg);
    CBORTokenizer tokenizer(SpanFrom(test.data));
    EXPECT_EQ(CBORTokenTag::ERROR_VALUE, tokenizer.TokenTag());
    EXPECT_THAT(tokenizer.Status(), StatusIs(Error::CBOR_INVALID_INT32, 0u));
  }
}

TEST(EncodeDecodeInt32Test, RoundtripsMinus24) {
  // This roundtrips the int32_t value -24 through the pair of EncodeInt32 /
  // CBORTokenizer; this is interesting since -24 is encoded as
  // a single byte as NEGATIVE, and it tests the specific encoding
  // (note how for unsigned the single byte covers values up to 23).
  // Additional examples are covered in RoundtripsAdditionalExamples.
  std::vector<uint8_t> encoded;
  EncodeInt32(-24, &encoded);
  // first three bits: major type = 1; remaining five bits: additional info =
  // value 23.
  EXPECT_THAT(encoded, ElementsAreArray(std::array<uint8_t, 1>{{1 << 5 | 23}}));

  // Reverse direction: decode with CBORTokenizer.
  CBORTokenizer tokenizer(SpanFrom(encoded));
  EXPECT_EQ(CBORTokenTag::INT32, tokenizer.TokenTag());
  EXPECT_EQ(-24, tokenizer.GetInt32());
  tokenizer.Next();
  EXPECT_EQ(CBORTokenTag::DONE, tokenizer.TokenTag());
}

TEST(EncodeDecodeInt32Test, RoundtripsAdditionalNegativeExamples) {
  std::vector<int32_t> examples = {-1,
                                   -10,
                                   -24,
                                   -25,
                                   -300,
                                   -30000,
                                   -300 * 1000,
                                   -1000 * 1000,
                                   -1000 * 1000 * 1000,
                                   std::numeric_limits<int32_t>::min()};
  for (int32_t example : examples) {
    SCOPED_TRACE(std::string("example ") + std::to_string(example));
    std::vector<uint8_t> encoded;
    EncodeInt32(example, &encoded);
    CBORTokenizer tokenizer(SpanFrom(encoded));
    EXPECT_EQ(CBORTokenTag::INT32, tokenizer.TokenTag());
    EXPECT_EQ(example, tokenizer.GetInt32());
    tokenizer.Next();
    EXPECT_EQ(CBORTokenTag::DONE, tokenizer.TokenTag());
  }
}

//
// EncodeString16 / CBORTokenTag::STRING16
//
TEST(EncodeDecodeString16Test, RoundtripsEmpty) {
  // This roundtrips the empty utf16 string through the pair of EncodeString16 /
  // CBORTokenizer.
  std::vector<uint8_t> encoded;
  EncodeString16(span<uint16_t>(), &encoded);
  EXPECT_EQ(1u, encoded.size());
  // first three bits: major type = 2; remaining five bits: additional info =
  // size 0.
  EXPECT_EQ(2 << 5, encoded[0]);

  // Reverse direction: decode with CBORTokenizer.
  CBORTokenizer tokenizer(SpanFrom(encoded));
  EXPECT_EQ(CBORTokenTag::STRING16, tokenizer.TokenTag());
  span<uint8_t> decoded_string16_wirerep = tokenizer.GetString16WireRep();
  EXPECT_TRUE(decoded_string16_wirerep.empty());
  tokenizer.Next();
  EXPECT_EQ(CBORTokenTag::DONE, tokenizer.TokenTag());
}

// On the wire, we STRING16 is encoded as little endian (least
// significant byte first). The host may or may not be little endian,
// so this routine follows the advice in
// https://commandcenter.blogspot.com/2012/04/byte-order-fallacy.html.
std::vector<uint16_t> String16WireRepToHost(span<uint8_t> in) {
  // must be even number of bytes.
  CHECK_EQ(in.size() & 1, 0u);
  std::vector<uint16_t> host_out;
  for (size_t ii = 0; ii < in.size(); ii += 2)
    host_out.push_back(in[ii + 1] << 8 | in[ii]);
  return host_out;
}

TEST(EncodeDecodeString16Test, RoundtripsHelloWorld) {
  // This roundtrips the hello world message which is given here in utf16
  // characters. 0xd83c, 0xdf0e: UTF16 encoding for the "Earth Globe Americas"
  // character, 🌎.
  std::array<uint16_t, 10> msg{
      {'H', 'e', 'l', 'l', 'o', ',', ' ', 0xd83c, 0xdf0e, '.'}};
  std::vector<uint8_t> encoded;
  EncodeString16(span<uint16_t>(msg.data(), msg.size()), &encoded);
  // This will be encoded as BYTE_STRING of length 20, so the 20 is encoded in
  // the additional info part of the initial byte. Payload is two bytes for each
  // UTF16 character.
  uint8_t initial_byte = /*major type=*/2 << 5 | /*additional info=*/20;
  std::array<uint8_t, 21> encoded_expected = {
      {initial_byte, 'H', 0,   'e', 0,    'l',  0,    'l',  0,   'o', 0,
       ',',          0,   ' ', 0,   0x3c, 0xd8, 0x0e, 0xdf, '.', 0}};
  EXPECT_THAT(encoded, ElementsAreArray(encoded_expected));

  // Now decode to complete the roundtrip.
  CBORTokenizer tokenizer(SpanFrom(encoded));
  EXPECT_EQ(CBORTokenTag::STRING16, tokenizer.TokenTag());
  std::vector<uint16_t> decoded =
      String16WireRepToHost(tokenizer.GetString16WireRep());
  EXPECT_THAT(decoded, ElementsAreArray(msg));
  tokenizer.Next();
  EXPECT_EQ(CBORTokenTag::DONE, tokenizer.TokenTag());

  // For bonus points, we look at the decoded message in UTF8 as well so we can
  // easily see it on the terminal screen.
  std::string utf8_decoded = UTF16ToUTF8(SpanFrom(decoded));
  EXPECT_EQ("Hello, 🌎.", utf8_decoded);
}

TEST(EncodeDecodeString16Test, Roundtrips500) {
  // We roundtrip a message that has 250 16 bit values. Each of these are just
  // set to their index. 250 is interesting because the cbor spec uses a
  // BYTE_STRING of length 500 for one of their examples of how to encode the
  // start of it (section 2.1) so it's easy for us to look at the first three
  // bytes closely.
  std::vector<uint16_t> two_fifty;
  for (uint16_t ii = 0; ii < 250; ++ii)
    two_fifty.push_back(ii);
  std::vector<uint8_t> encoded;
  EncodeString16(span<uint16_t>(two_fifty.data(), two_fifty.size()), &encoded);
  EXPECT_EQ(3u + 250u * 2, encoded.size());
  // Now check the first three bytes:
  // Major type: 2 (BYTE_STRING)
  // Additional information: 25, indicating size is represented by 2 bytes.
  // Bytes 1 and 2 encode 500 (0x01f4).
  EXPECT_EQ(2 << 5 | 25, encoded[0]);
  EXPECT_EQ(0x01, encoded[1]);
  EXPECT_EQ(0xf4, encoded[2]);

  // Now decode to complete the roundtrip.
  CBORTokenizer tokenizer(SpanFrom(encoded));
  EXPECT_EQ(CBORTokenTag::STRING16, tokenizer.TokenTag());
  std::vector<uint16_t> decoded =
      String16WireRepToHost(tokenizer.GetString16WireRep());
  EXPECT_THAT(decoded, ElementsAreArray(two_fifty));
  tokenizer.Next();
  EXPECT_EQ(CBORTokenTag::DONE, tokenizer.TokenTag());
}

TEST(EncodeDecodeString16Test, ErrorCases) {
  struct TestCase {
    std::vector<uint8_t> data;
    std::string msg;
  };
  std::vector<TestCase> tests{
      {TestCase{{2 << 5 | 1, 'a'},
                "length must be divisible by 2 (but it's 1)"},
       TestCase{{2 << 5 | 29}, "additional info = 29 isn't recognized"},
       TestCase{{2 << 5 | 9, 1, 2, 3, 4, 5, 6, 7, 8},
                "length (9) points just past the end of the test case"},
       TestCase{{2 << 5 | 27, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 'a', 'b', 'c'},
                "large length pointing past the end of the test case"}}};
  for (const TestCase& test : tests) {
    SCOPED_TRACE(test.msg);
    CBORTokenizer tokenizer(SpanFrom(test.data));
    EXPECT_EQ(CBORTokenTag::ERROR_VALUE, tokenizer.TokenTag());
    EXPECT_THAT(tokenizer.Status(), StatusIs(Error::CBOR_INVALID_STRING16, 0u));
  }
}

//
// EncodeString8 / CBORTokenTag::STRING8
//
TEST(EncodeDecodeString8Test, RoundtripsHelloWorld) {
  // This roundtrips the hello world message which is given here in utf8
  // characters. 🌎 is a four byte utf8 character.
  std::string utf8_msg = "Hello, 🌎.";
  std::vector<uint8_t> msg(utf8_msg.begin(), utf8_msg.end());
  std::vector<uint8_t> encoded;
  EncodeString8(SpanFrom(utf8_msg), &encoded);
  // This will be encoded as STRING of length 12, so the 12 is encoded in
  // the additional info part of the initial byte. Payload is one byte per
  // utf8 byte.
  uint8_t initial_byte = /*major type=*/3 << 5 | /*additional info=*/12;
  std::array<uint8_t, 13> encoded_expected = {{initial_byte, 'H', 'e', 'l', 'l',
                                               'o', ',', ' ', 0xF0, 0x9f, 0x8c,
                                               0x8e, '.'}};
  EXPECT_THAT(encoded, ElementsAreArray(encoded_expected));

  // Now decode to complete the roundtrip.
  CBORTokenizer tokenizer(SpanFrom(encoded));
  EXPECT_EQ(CBORTokenTag::STRING8, tokenizer.TokenTag());
  std::vector<uint8_t> decoded(tokenizer.GetString8().begin(),
                               tokenizer.GetString8().end());
  EXPECT_THAT(decoded, ElementsAreArray(msg));
  tokenizer.Next();
  EXPECT_EQ(CBORTokenTag::DONE, tokenizer.TokenTag());
}

TEST(EncodeDecodeString8Test, ErrorCases) {
  struct TestCase {
    std::vector<uint8_t> data;
    std::string msg;
  };
  std::vector<TestCase> tests{
      {TestCase{{3 << 5 | 29}, "additional info = 29 isn't recognized"},
       TestCase{{3 << 5 | 9, 1, 2, 3, 4, 5, 6, 7, 8},
                "length (9) points just past the end of the test case"},
       TestCase{{3 << 5 | 27, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 'a', 'b', 'c'},
                "large length pointing past the end of the test case"}}};
  for (const TestCase& test : tests) {
    SCOPED_TRACE(test.msg);
    CBORTokenizer tokenizer(SpanFrom(test.data));
    EXPECT_EQ(CBORTokenTag::ERROR_VALUE, tokenizer.TokenTag());
    EXPECT_THAT(tokenizer.Status(), StatusIs(Error::CBOR_INVALID_STRING8, 0u));
  }
}

TEST(EncodeFromLatin1Test, ConvertsToUTF8IfNeeded) {
  std::vector<std::pair<std::string, std::string>> examples = {
      {"Hello, world.", "Hello, world."},
      {"Above: \xDC"
       "ber",
       "Above: Über"},
      {"\xA5 500 are about \xA3 3.50; a y with umlaut is \xFF",
       "¥ 500 are about £ 3.50; a y with umlaut is ÿ"}};

  for (const auto& example : examples) {
    const std::string& latin1 = example.first;
    const std::string& expected_utf8 = example.second;
    std::vector<uint8_t> encoded;
    EncodeFromLatin1(SpanFrom(latin1), &encoded);
    CBORTokenizer tokenizer(SpanFrom(encoded));
    EXPECT_EQ(CBORTokenTag::STRING8, tokenizer.TokenTag());
    std::vector<uint8_t> decoded(tokenizer.GetString8().begin(),
                                 tokenizer.GetString8().end());
    std::string decoded_str(decoded.begin(), decoded.end());
    EXPECT_THAT(decoded_str, testing::Eq(expected_utf8));
  }
}

TEST(EncodeFromUTF16Test, ConvertsToUTF8IfEasy) {
  std::vector<uint16_t> ascii = {'e', 'a', 's', 'y'};
  std::vector<uint8_t> encoded;
  EncodeFromUTF16(span<uint16_t>(ascii.data(), ascii.size()), &encoded);

  CBORTokenizer tokenizer(SpanFrom(encoded));
  EXPECT_EQ(CBORTokenTag::STRING8, tokenizer.TokenTag());
  std::vector<uint8_t> decoded(tokenizer.GetString8().begin(),
                               tokenizer.GetString8().end());
  std::string decoded_str(decoded.begin(), decoded.end());
  EXPECT_THAT(decoded_str, testing::Eq("easy"));
}

TEST(EncodeFromUTF16Test, EncodesAsString16IfNeeded) {
  // Since this message contains non-ASCII characters, the routine is
  // forced to encode as UTF16. We see this below by checking that the
  // token tag is STRING16.
  std::vector<uint16_t> msg = {'H', 'e', 'l',    'l',    'o',
                               ',', ' ', 0xd83c, 0xdf0e, '.'};
  std::vector<uint8_t> encoded;
  EncodeFromUTF16(span<uint16_t>(msg.data(), msg.size()), &encoded);

  CBORTokenizer tokenizer(SpanFrom(encoded));
  EXPECT_EQ(CBORTokenTag::STRING16, tokenizer.TokenTag());
  std::vector<uint16_t> decoded =
      String16WireRepToHost(tokenizer.GetString16WireRep());
  std::string utf8_decoded = UTF16ToUTF8(SpanFrom(decoded));
  EXPECT_EQ("Hello, 🌎.", utf8_decoded);
}

//
// EncodeBinary / CBORTokenTag::BINARY
//
TEST(EncodeDecodeBinaryTest, RoundtripsHelloWorld) {
  std::vector<uint8_t> binary = {'H', 'e', 'l', 'l', 'o', ',', ' ',
                                 'w', 'o', 'r', 'l', 'd', '.'};
  std::vector<uint8_t> encoded;
  EncodeBinary(span<uint8_t>(binary.data(), binary.size()), &encoded);
  // So, on the wire we see that the binary blob travels unmodified.
  EXPECT_THAT(
      encoded,
      ElementsAreArray(std::array<uint8_t, 15>{
          {(6 << 5 | 22),  // tag 22 indicating base64 interpretation in JSON
           (2 << 5 | 13),  // BYTE_STRING (type 2) of length 13
           'H', 'e', 'l', 'l', 'o', ',', ' ', 'w', 'o', 'r', 'l', 'd', '.'}}));
  std::vector<uint8_t> decoded;
  CBORTokenizer tokenizer(SpanFrom(encoded));
  EXPECT_EQ(CBORTokenTag::BINARY, tokenizer.TokenTag());
  EXPECT_THAT(tokenizer.Status(), StatusIsOk());
  decoded = std::vector<uint8_t>(tokenizer.GetBinary().begin(),
                                 tokenizer.GetBinary().end());
  EXPECT_THAT(decoded, ElementsAreArray(binary));
  tokenizer.Next();
  EXPECT_EQ(CBORTokenTag::DONE, tokenizer.TokenTag());
}

TEST(EncodeDecodeBinaryTest, ErrorCases) {
  struct TestCase {
    std::vector<uint8_t> data;
    std::string msg;
  };
  std::vector<TestCase> tests{{TestCase{
      {6 << 5 | 22,  // tag 22 indicating base64 interpretation in JSON
       2 << 5 | 27,  // BYTE_STRING (type 2), followed by 8 bytes length
       0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
      "large length pointing past the end of the test case"}}};
  for (const TestCase& test : tests) {
    SCOPED_TRACE(test.msg);
    CBORTokenizer tokenizer(SpanFrom(test.data));
    EXPECT_EQ(CBORTokenTag::ERROR_VALUE, tokenizer.TokenTag());
    EXPECT_THAT(tokenizer.Status(), StatusIs(Error::CBOR_INVALID_BINARY, 0u));
  }
}

//
// EncodeDouble / CBORTokenTag::DOUBLE
//
TEST(EncodeDecodeDoubleTest, RoundtripsWikipediaExample) {
  // https://en.wikipedia.org/wiki/Double-precision_floating-point_format
  // provides the example of a hex representation 3FD5 5555 5555 5555, which
  // approximates 1/3.

  const double kOriginalValue = 1.0 / 3;
  std::vector<uint8_t> encoded;
  EncodeDouble(kOriginalValue, &encoded);
  // first three bits: major type = 7; remaining five bits: additional info =
  // value 27. This is followed by 8 bytes of payload (which match Wikipedia).
  EXPECT_THAT(
      encoded,
      ElementsAreArray(std::array<uint8_t, 9>{
          {7 << 5 | 27, 0x3f, 0xd5, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}}));

  // Reverse direction: decode and compare with original value.
  CBORTokenizer tokenizer(SpanFrom(encoded));
  EXPECT_EQ(CBORTokenTag::DOUBLE, tokenizer.TokenTag());
  EXPECT_THAT(tokenizer.GetDouble(), testing::DoubleEq(kOriginalValue));
  tokenizer.Next();
  EXPECT_EQ(CBORTokenTag::DONE, tokenizer.TokenTag());
}

TEST(EncodeDecodeDoubleTest, RoundtripsAdditionalExamples) {
  std::vector<double> examples = {0.0,
                                  1.0,
                                  -1.0,
                                  3.1415,
                                  std::numeric_limits<double>::min(),
                                  std::numeric_limits<double>::max(),
                                  std::numeric_limits<double>::infinity(),
                                  std::numeric_limits<double>::quiet_NaN()};
  for (double example : examples) {
    SCOPED_TRACE(std::string("example ") + std::to_string(example));
    std::vector<uint8_t> encoded;
    EncodeDouble(example, &encoded);
    CBORTokenizer tokenizer(SpanFrom(encoded));
    EXPECT_EQ(CBORTokenTag::DOUBLE, tokenizer.TokenTag());
    if (std::isnan(example))
      EXPECT_TRUE(std::isnan(tokenizer.GetDouble()));
    else
      EXPECT_THAT(tokenizer.GetDouble(), testing::DoubleEq(example));
    tokenizer.Next();
    EXPECT_EQ(CBORTokenTag::DONE, tokenizer.TokenTag());
  }
}

TEST(EncodeDecodeEnvelopesTest, MessageWithNestingAndEnvelopeContentsAccess) {
  // This encodes and decodes the following message, which has some nesting
  // and therefore envelopes.
  //  { "inner": { "foo" : "bar" } }
  // The decoding is done with the Tokenizer,
  // and we test both ::GetEnvelopeContents and GetEnvelope here.
  std::vector<uint8_t> message;
  EnvelopeEncoder envelope;
  envelope.EncodeStart(&message);
  size_t pos_after_header = message.size();
  message.push_back(EncodeIndefiniteLengthMapStart());
  EncodeString8(SpanFrom("inner"), &message);
  size_t pos_inside_inner = message.size();
  EnvelopeEncoder inner_envelope;
  inner_envelope.EncodeStart(&message);
  size_t pos_inside_inner_contents = message.size();
  message.push_back(EncodeIndefiniteLengthMapStart());
  EncodeString8(SpanFrom("foo"), &message);
  EncodeString8(SpanFrom("bar"), &message);
  message.push_back(EncodeStop());
  size_t pos_after_inner = message.size();
  inner_envelope.EncodeStop(&message);
  message.push_back(EncodeStop());
  envelope.EncodeStop(&message);

  CBORTokenizer tokenizer(SpanFrom(message));
  ASSERT_EQ(CBORTokenTag::ENVELOPE, tokenizer.TokenTag());
  EXPECT_EQ(message.size(), tokenizer.GetEnvelope().size());
  EXPECT_EQ(message.data(), tokenizer.GetEnvelope().data());
  EXPECT_EQ(message.data() + pos_after_header,
            tokenizer.GetEnvelopeContents().data());
  EXPECT_EQ(message.size() - pos_after_header,
            tokenizer.GetEnvelopeContents().size());
  tokenizer.EnterEnvelope();
  ASSERT_EQ(CBORTokenTag::MAP_START, tokenizer.TokenTag());
  tokenizer.Next();
  ASSERT_EQ(CBORTokenTag::STRING8, tokenizer.TokenTag());
  EXPECT_EQ("inner", std::string(tokenizer.GetString8().begin(),
                                 tokenizer.GetString8().end()));
  tokenizer.Next();
  ASSERT_EQ(CBORTokenTag::ENVELOPE, tokenizer.TokenTag());
  EXPECT_EQ(message.data() + pos_inside_inner, tokenizer.GetEnvelope().data());
  EXPECT_EQ(pos_after_inner - pos_inside_inner, tokenizer.GetEnvelope().size());
  EXPECT_EQ(message.data() + pos_inside_inner_contents,
            tokenizer.GetEnvelopeContents().data());
  EXPECT_EQ(pos_after_inner - pos_inside_inner_contents,
            tokenizer.GetEnvelopeContents().size());
  tokenizer.EnterEnvelope();
  ASSERT_EQ(CBORTokenTag::MAP_START, tokenizer.TokenTag());
  tokenizer.Next();
  ASSERT_EQ(CBORTokenTag::STRING8, tokenizer.TokenTag());
  EXPECT_EQ("foo", std::string(tokenizer.GetString8().begin(),
                               tokenizer.GetString8().end()));
  tokenizer.Next();
  ASSERT_EQ(CBORTokenTag::STRING8, tokenizer.TokenTag());
  EXPECT_EQ("bar", std::string(tokenizer.GetString8().begin(),
                               tokenizer.GetString8().end()));
  tokenizer.Next();
  ASSERT_EQ(CBORTokenTag::STOP, tokenizer.TokenTag());
  tokenizer.Next();
  ASSERT_EQ(CBORTokenTag::STOP, tokenizer.TokenTag());
  tokenizer.Next();
  ASSERT_EQ(CBORTokenTag::DONE, tokenizer.TokenTag());
}

// =============================================================================
// cbor::NewCBOREncoder - for encoding from a streaming parser
// =============================================================================

TEST(JSONToCBOREncoderTest, SevenBitStrings) {
  // When a string can be represented as 7 bit ASCII, the encoder will use the
  // STRING (major Type 3) type, so the actual characters end up as bytes on the
  // wire.
  std::vector<uint8_t> encoded;
  Status status;
  std::unique_ptr<ParserHandler> encoder = NewCBOREncoder(&encoded, &status);
  std::vector<uint16_t> utf16 = {'f', 'o', 'o'};
  encoder->HandleString16(span<uint16_t>(utf16.data(), utf16.size()));
  EXPECT_THAT(status, StatusIsOk());
  // Here we assert that indeed, seven bit strings are represented as
  // bytes on the wire, "foo" is just "foo".
  EXPECT_THAT(encoded,
              ElementsAreArray(std::array<uint8_t, 4>{
                  {/*major type 3*/ 3 << 5 | /*length*/ 3, 'f', 'o', 'o'}}));
}

TEST(JsonCborRoundtrip, EncodingDecoding) {
  // Hits all the cases except binary and error in ParserHandler, first
  // parsing a JSON message into CBOR, then parsing it back from CBOR into JSON.
  std::string json =
      "{"
      "\"string\":\"Hello, \\ud83c\\udf0e.\","
      "\"double\":3.1415,"
      "\"int\":1,"
      "\"negative int\":-1,"
      "\"bool\":true,"
      "\"null\":null,"
      "\"array\":[1,2,3]"
      "}";
  std::vector<uint8_t> encoded;
  Status status;
  std::unique_ptr<ParserHandler> encoder = NewCBOREncoder(&encoded, &status);
  span<uint8_t> ascii_in = SpanFrom(json);
  json::ParseJSON(ascii_in, encoder.get());
  std::vector<uint8_t> expected = {
      0xd8, 0x18,         // envelope
      0x5a,               // byte string with 32 bit length
      0,    0,    0, 95,  // length is 95 bytes
  };
  expected.push_back(0xbf);  // indef length map start
  EncodeString8(SpanFrom("string"), &expected);
  // This is followed by the encoded string for "Hello, 🌎."
  // So, it's the same bytes that we tested above in
  // EncodeDecodeString16Test.RoundtripsHelloWorld.
  expected.push_back(/*major type=*/2 << 5 | /*additional info=*/20);
  for (uint8_t ch : std::array<uint8_t, 20>{
           {'H', 0, 'e', 0, 'l',  0,    'l',  0,    'o', 0,
            ',', 0, ' ', 0, 0x3c, 0xd8, 0x0e, 0xdf, '.', 0}})
    expected.push_back(ch);
  EncodeString8(SpanFrom("double"), &expected);
  EncodeDouble(3.1415, &expected);
  EncodeString8(SpanFrom("int"), &expected);
  EncodeInt32(1, &expected);
  EncodeString8(SpanFrom("negative int"), &expected);
  EncodeInt32(-1, &expected);
  EncodeString8(SpanFrom("bool"), &expected);
  expected.push_back(7 << 5 | 21);  // RFC 7049 Section 2.3, Table 2: true
  EncodeString8(SpanFrom("null"), &expected);
  expected.push_back(7 << 5 | 22);  // RFC 7049 Section 2.3, Table 2: null
  EncodeString8(SpanFrom("array"), &expected);
  expected.push_back(0xd8);  // envelope (tag first byte)
  expected.push_back(0x18);  // envelope (tag second byte)
  expected.push_back(0x5a);  // byte string with 32 bit length
  // the length is 5 bytes (that's up to end indef length array below).
  for (uint8_t ch : std::array<uint8_t, 4>{{0, 0, 0, 5}})
    expected.push_back(ch);
  expected.push_back(0x9f);  // RFC 7049 Section 2.2.1, indef length array start
  expected.push_back(1);     // Three UNSIGNED values (easy since Major Type 0)
  expected.push_back(2);
  expected.push_back(3);
  expected.push_back(0xff);  // End indef length array
  expected.push_back(0xff);  // End indef length map
  EXPECT_TRUE(status.ok());
  EXPECT_THAT(encoded, ElementsAreArray(expected));

  // And now we roundtrip, decoding the message we just encoded.
  std::string decoded;
  std::unique_ptr<ParserHandler> json_encoder =
      json::NewJSONEncoder(&decoded, &status);
  ParseCBOR(span<uint8_t>(encoded.data(), encoded.size()), json_encoder.get());
  EXPECT_THAT(status, StatusIsOk());
  EXPECT_EQ(json, decoded);
}

TEST(JsonCborRoundtrip, MoreRoundtripExamples) {
  std::vector<std::string> e
```
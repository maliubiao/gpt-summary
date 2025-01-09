Response:
Let's break down the thought process to analyze the provided C++ code snippet.

1. **Understand the Goal:** The core request is to analyze the functionality of the `cbor.cc` file within the V8 project and relate it to JavaScript and common programming errors. The prompt also mentions `.tq` files (Torque) but immediately clarifies this file is `.cc`, so that's a quick check.

2. **Initial Scan for Keywords and Structure:**  Quickly scan the code for prominent keywords and structural elements:
    * `#include`:  This tells us about dependencies (`cbor.h`, standard library headers).
    * `namespace v8_crdtp::cbor`:  Indicates the code belongs to a specific V8 component, likely related to Chrome DevTools Protocol (CRDP). CBOR suggests binary serialization.
    * `constexpr`:  Lots of constants defined, often related to CBOR format specifics (major types, additional info).
    * `Encode...` functions:  These clearly deal with serializing data *into* CBOR.
    * `Read...` functions:  These handle deserializing data *from* CBOR.
    * `Envelope...`:  Suggests a mechanism for wrapping CBOR messages.
    * `CBORTokenizer`:  A class for breaking down CBOR byte streams into tokens.
    * `Parse...`: Functions for interpreting CBOR data structures (maps, arrays, values).
    * `ParserHandler`: An interface likely used for a streaming parsing approach.
    * `Status`, `StatusOr`: Error handling and result types.

3. **Identify Core Functionality Areas:** Based on the initial scan, group the code into logical areas:
    * **CBOR Encoding:**  Functions starting with `Encode...` (e.g., `EncodeInt32`, `EncodeString8`, `EncodeDouble`).
    * **CBOR Decoding/Tokenization:**  The `CBORTokenizer` class and related `Read...` functions.
    * **CBOR Parsing:**  The `Parse...` functions (e.g., `ParseMap`, `ParseArray`, `ParseValue`) and the `ParserHandler` interface.
    * **Envelope Handling:**  The `EnvelopeEncoder` and `EnvelopeHeader` classes.
    * **Utility Functions:**  Helper functions like `WriteBytesMostSignificantByteFirst` and `ReadBytesMostSignificantByteFirst`.
    * **Constants:**  Definitions related to the CBOR format.

4. **Deep Dive into Key Classes/Functions:**  Examine the core components in more detail:
    * **`internals::ReadTokenStart` and `internals::WriteTokenStart`:** These are fundamental for reading and writing the initial byte and length/value information in CBOR. Understanding the logic involving `kMajorTypeMask`, `kAdditionalInformationMask`, and the different `kAdditionalInformation...` constants is crucial.
    * **`EnvelopeEncoder` and `EnvelopeHeader`:**  Analyze how they wrap CBOR messages, including the size prefix.
    * **`CBORTokenizer`:** How it iterates through the byte stream and identifies different CBOR tokens. Pay attention to the `ReadNextToken` method and how it sets the `token_tag_`.
    * **`ParseMap`, `ParseArray`, `ParseValue`:**  These implement the recursive descent parsing logic for CBOR structures.

5. **Connect to JavaScript (if applicable):**  Consider how CBOR relates to JavaScript concepts. CBOR is often used for efficient binary serialization, which is relevant for:
    * **Data transfer:**  Sending data between a server and a JavaScript client (e.g., in a web application).
    * **Internal representation:** While V8 primarily uses its internal object model, CBOR might be used for certain serialization tasks or inter-process communication.
    * **The prompt specifically mentions a connection *if* one exists.** In this case, the connection is through the Chrome DevTools Protocol, where CBOR is used for message encoding. This is a key link to JavaScript debugging and profiling. Provide a simple JavaScript example illustrating the *concept* of serialization and deserialization, even if directly using this C++ code isn't possible in JavaScript. A JSON example is a good starting point since CBOR is a binary alternative to JSON.

6. **Identify Potential Programming Errors:** Think about common mistakes when dealing with binary data and serialization:
    * **Incorrect size calculations:**  Mistakes in calculating the length of strings, arrays, or the envelope.
    * **Endianness issues:**  While the code explicitly handles big-endian, misunderstanding byte order can lead to errors.
    * **Buffer overflows:**  Reading or writing beyond the bounds of a buffer.
    * **Incorrect type handling:**  Trying to decode a value as the wrong CBOR type.
    * **Not handling all CBOR types:** The code might not support all possible CBOR features. The prompt mentions "enough to roundtrip JSON messages," suggesting a focus on common use cases.

7. **Construct Hypothetical Input and Output (for logic reasoning):** Choose a simple CBOR example (e.g., encoding a small integer or a short string) and manually trace the encoding process. This helps verify the understanding of the `Encode...` functions. Similarly, for decoding, provide a small CBOR byte sequence and trace how the `CBORTokenizer` would process it.

8. **Summarize the Functionality:**  Based on the analysis, create a concise summary of the file's purpose, highlighting its key responsibilities (encoding, decoding, tokenization, envelope handling).

9. **Review and Refine:**  Read through the analysis to ensure accuracy, clarity, and completeness. Check if all parts of the prompt have been addressed. Ensure the JavaScript example and the common error examples are clear and relevant. For example, initially, I might just say "handles serialization," but refining it to "efficient binary serialization format (CBOR)" is more precise. Similarly, mentioning the connection to the Chrome DevTools Protocol adds valuable context.
好的，让我们来分析一下 `v8/third_party/inspector_protocol/crdtp/cbor.cc` 这个 C++ 源代码文件的功能。

**文件功能归纳:**

总的来说，`v8/third_party/inspector_protocol/crdtp/cbor.cc` 文件的主要功能是 **实现 CBOR (Concise Binary Object Representation) 格式的编码和解码，用于 Chrome DevTools Protocol (CRDP) 的消息传递。**  它提供了在 V8 中处理 CBOR 数据的能力，以便与前端开发者工具进行高效的通信。

更具体地说，它的功能包括：

1. **CBOR 编码:**
   - 将各种数据类型（例如，整数、字符串、布尔值、null、浮点数、数组、映射）编码成 CBOR 二进制格式。
   - 提供了对确定长度和不定长度的 CBOR 结构的支持。
   - 实现了 CBOR Envelope 机制，用于包装子消息，并包含消息长度信息。
   - 提供了将二进制数据编码为 Base64 字符串的功能（通过特定的 Tag）。

2. **CBOR 解码 (Tokenization 和 Parsing):**
   - 提供了一个 `CBORTokenizer` 类，用于将 CBOR 字节流分解为一个个的 Token（例如，整数、字符串的起始和结束、数组和映射的起始和结束等）。
   - 提供了 `ParseCBOR` 函数和相关的 `ParseMap`、`ParseArray`、`ParseValue` 函数，用于将 CBOR Token 流解析成更高层次的数据结构。
   - 使用 `ParserHandler` 接口来处理解析过程中遇到的各种 CBOR 数据类型和结构。

3. **CBOR Envelope 处理:**
   - 提供了 `EnvelopeEncoder` 类用于创建 CBOR Envelope。
   - 提供了 `EnvelopeHeader` 类用于解析 CBOR Envelope 的头部信息（例如，内容长度）。
   - 能够检测和校验 CBOR 消息是否以正确的 Envelope 格式开始。

4. **错误处理:**
   - 定义了一组 CBOR 相关的错误类型 (`Error` 枚举）。
   - 在编码和解码过程中进行错误检查，并通过 `Status` 和 `StatusOr` 类型来报告错误。

**关于文件名的判断:**

根据您的描述，如果 `v8/third_party/inspector_protocol/crdtp/cbor.cc` 以 `.tq` 结尾，那么它才会被认为是 V8 Torque 源代码。 由于它以 `.cc` 结尾，因此它是一个标准的 C++ 源代码文件。

**与 JavaScript 的关系:**

`v8/third_party/inspector_protocol/crdtp/cbor.cc` 与 JavaScript 的功能有密切关系，因为它被用于 Chrome DevTools Protocol (CRDP)。CRDP 是 Chrome 浏览器和基于 Chromium 的浏览器与开发者工具（通常是用 JavaScript 编写的前端）进行通信的协议。

在 CRDP 中，消息通常以 JSON 或 CBOR 格式进行编码。 CBOR 作为一种更紧凑的二进制格式，可以提高数据传输的效率，尤其是在传输大量数据时。

**JavaScript 举例说明:**

虽然这个 C++ 文件本身不能直接在 JavaScript 中运行，但它编码和解码的 CBOR 数据会被 JavaScript 代码处理。

例如，在开发者工具的前端（JavaScript 代码）中，可能会接收到从后端（使用此 C++ 代码编码）发送过来的 CBOR 数据，并将其解码为 JavaScript 对象：

```javascript
// 假设 receivedCborData 是从后端接收到的 CBOR 字节数组 (Uint8Array)
// 这里需要一个 JavaScript CBOR 解码库，例如 cbor-js 或 js-cbor

// 使用 cbor-js 库进行解码
cbor.decode(receivedCborData).then(decodedObject => {
  console.log("解码后的 JavaScript 对象:", decodedObject);
  // 可以进一步处理 decodedObject
});
```

同样，在某些情况下，JavaScript 代码可能需要将数据编码为 CBOR 格式发送到后端：

```javascript
// 假设 dataToSend 是要发送的 JavaScript 对象
// 同样需要一个 JavaScript CBOR 编码库

// 使用 cbor-js 库进行编码
cbor.encode(dataToSend).then(encodedCborData => {
  // 将 encodedCborData (Uint8Array) 发送到后端
  console.log("编码后的 CBOR 数据:", encodedCborData);
  // ... 发送数据的代码 ...
});
```

在这个过程中，后端的 C++ 代码（包括 `cbor.cc`）负责 CBOR 数据的实际编码和解码操作。

**代码逻辑推理示例 (假设输入与输出):**

假设我们要编码一个包含一个键值对的简单映射 (Map)，键是字符串 "name"，值是字符串 "Alice"。

**假设输入 (C++ 端):**

```c++
std::vector<uint8_t> encoded_data;
cbor::NewCBOREncoder encoder(&encoded_data, &status);
encoder->HandleMapBegin();
encoder->HandleString8(v8_crdtp::cbor::SpanFrom("name"));
encoder->HandleString8(v8_crdtp::cbor::SpanFrom("Alice"));
encoder->HandleMapEnd();
```

**可能的输出 (encoded_data 的内容，十六进制表示):**

```
bf  ; 不定长 Map 开始
64 6e 61 6d 65  ; 字符串 "name" (长度 4, 值为 name)
65 41 6c 69 63 65  ; 字符串 "Alice" (长度 5, 值为 Alice)
ff  ; 不定长 Map 结束
```

**解释:**

- `bf`:  代表不定长 Map 的开始 (Major type 5, additional info 31).
- `64`: 代表长度为 4 的 UTF-8 字符串 (Major type 3, additional info 4).
- `6e 61 6d 65`:  "name" 的 UTF-8 编码。
- `65`: 代表长度为 5 的 UTF-8 字符串 (Major type 3, additional info 5).
- `41 6c 69 63 65`: "Alice" 的 UTF-8 编码。
- `ff`: 代表不定长结构的结束 (Major type 7, additional info 31).

**用户常见的编程错误示例:**

1. **大小端 (Endianness) 混淆:**  CBOR 规范定义了网络字节序（大端），但如果开发者在处理多字节数据时错误地使用了本地字节序，会导致解码错误。虽然此代码中显式使用了 `WriteBytesMostSignificantByteFirst` 和 `ReadBytesMostSignificantByteFirst` 来处理字节序，但用户在集成或扩展时可能犯错。

   ```c++
   // 错误示例：假设要编码一个 32 位整数
   uint32_t value = 0x12345678;
   std::vector<uint8_t> encoded;
   // 错误地直接写入，没有考虑字节序
   encoded.push_back(value & 0xFF);
   encoded.push_back((value >> 8) & 0xFF);
   encoded.push_back((value >> 16) & 0xFF);
   encoded.push_back((value >> 24) & 0xFF);

   // 正确的做法是使用 WriteBytesMostSignificantByteFirst
   cbor::internals::WriteBytesMostSignificantByteFirst(value, &encoded);
   ```

2. **不正确的长度计算:** 在编码字符串、二进制数据、数组或映射时，如果提供的长度信息不正确，会导致解码失败或数据损坏。

   ```c++
   // 错误示例：编码字符串时长度计算错误
   std::string text = "hello";
   std::vector<uint8_t> encoded;
   cbor::internals::WriteTokenStart(cbor::MajorType::STRING, text.length() - 1, &encoded); // 长度错误
   encoded.insert(encoded.end(), text.begin(), text.end());
   ```

3. **CBOR 类型不匹配:**  尝试将 CBOR 数据解码为错误的类型。例如，将编码为整数的 CBOR 数据尝试解析为字符串。

   ```c++
   // 假设 cbor_data 包含一个编码后的整数
   cbor::CBORTokenizer tokenizer(cbor_data);
   if (tokenizer.TokenTag() == cbor::CBORTokenTag::STRING8) { // 错误的类型判断
       auto str = tokenizer.GetString8(); // 尝试获取字符串，但实际是整数
       // ...
   }
   ```

4. **忘记处理不定长结构的结束符:**  如果编码或解码不定长数组或映射时，忘记写入或检查结束符 (`kStopByte`)，会导致解析错误。

   ```c++
   // 错误示例：编码不定长数组时忘记添加结束符
   std::vector<uint8_t> encoded;
   encoded.push_back(cbor::EncodeIndefiniteLengthArrayStart());
   // ... 添加数组元素 ...
   // 忘记添加 cbor::EncodeStop();
   ```

**总结:**

`v8/third_party/inspector_protocol/crdtp/cbor.cc` 是 V8 中用于处理 CBOR 格式的关键组件，它使得 V8 能够高效地编码和解码用于 Chrome DevTools Protocol 的消息。它与 JavaScript 有着重要的联系，因为开发者工具的前端通常使用 JavaScript 来处理通过 CRDP 接收到的 CBOR 数据。 理解 CBOR 的规范和正确使用这个库对于避免常见的编程错误至关重要。

Prompt: 
```
这是目录为v8/third_party/inspector_protocol/crdtp/cbor.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/third_party/inspector_protocol/crdtp/cbor.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cbor.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <limits>
#include <stack>

namespace v8_crdtp {
namespace cbor {
namespace {
// Indicates the number of bits the "initial byte" needs to be shifted to the
// right after applying |kMajorTypeMask| to produce the major type in the
// lowermost bits.
static constexpr uint8_t kMajorTypeBitShift = 5u;
// Mask selecting the low-order 5 bits of the "initial byte", which is where
// the additional information is encoded.
static constexpr uint8_t kAdditionalInformationMask = 0x1f;
// Mask selecting the high-order 3 bits of the "initial byte", which indicates
// the major type of the encoded value.
static constexpr uint8_t kMajorTypeMask = 0xe0;
// Indicates the integer is in the following byte.
static constexpr uint8_t kAdditionalInformation1Byte = 24u;
// Indicates the integer is in the next 2 bytes.
static constexpr uint8_t kAdditionalInformation2Bytes = 25u;
// Indicates the integer is in the next 4 bytes.
static constexpr uint8_t kAdditionalInformation4Bytes = 26u;
// Indicates the integer is in the next 8 bytes.
static constexpr uint8_t kAdditionalInformation8Bytes = 27u;

// Encodes the initial byte, consisting of the |type| in the first 3 bits
// followed by 5 bits of |additional_info|.
constexpr uint8_t EncodeInitialByte(MajorType type, uint8_t additional_info) {
  return (static_cast<uint8_t>(type) << kMajorTypeBitShift) |
         (additional_info & kAdditionalInformationMask);
}

// TAG 24 indicates that what follows is a byte string which is
// encoded in CBOR format. We use this as a wrapper for
// maps and arrays, allowing us to skip them, because the
// byte string carries its size (byte length).
// https://tools.ietf.org/html/rfc7049#section-2.4.4.1
static constexpr uint8_t kInitialByteForEnvelope =
    EncodeInitialByte(MajorType::TAG, kAdditionalInformation1Byte);

// The standalone byte for "envelope" tag, to follow kInitialByteForEnvelope
// in the correct implementation, as it is above in-tag value max (which is
// also, confusingly, 24). See EnvelopeHeader::Parse() for more.
static constexpr uint8_t kCBOREnvelopeTag = 24;

// The initial byte for a byte string with at most 2^32 bytes
// of payload. This is used for envelope encoding, even if
// the byte string is shorter.
static constexpr uint8_t kInitialByteFor32BitLengthByteString =
    EncodeInitialByte(MajorType::BYTE_STRING, 26);

// See RFC 7049 Section 2.2.1, indefinite length arrays / maps have additional
// info = 31.
static constexpr uint8_t kInitialByteIndefiniteLengthArray =
    EncodeInitialByte(MajorType::ARRAY, 31);
static constexpr uint8_t kInitialByteIndefiniteLengthMap =
    EncodeInitialByte(MajorType::MAP, 31);
// See RFC 7049 Section 2.3, Table 1; this is used for finishing indefinite
// length maps / arrays.
static constexpr uint8_t kStopByte =
    EncodeInitialByte(MajorType::SIMPLE_VALUE, 31);

// See RFC 7049 Section 2.3, Table 2.
static constexpr uint8_t kEncodedTrue =
    EncodeInitialByte(MajorType::SIMPLE_VALUE, 21);
static constexpr uint8_t kEncodedFalse =
    EncodeInitialByte(MajorType::SIMPLE_VALUE, 20);
static constexpr uint8_t kEncodedNull =
    EncodeInitialByte(MajorType::SIMPLE_VALUE, 22);
static constexpr uint8_t kInitialByteForDouble =
    EncodeInitialByte(MajorType::SIMPLE_VALUE, 27);

// See RFC 7049 Table 3 and Section 2.4.4.2. This is used as a prefix for
// arbitrary binary data encoded as BYTE_STRING.
static constexpr uint8_t kExpectedConversionToBase64Tag =
    EncodeInitialByte(MajorType::TAG, 22);

// Writes the bytes for |v| to |out|, starting with the most significant byte.
// See also: https://commandcenter.blogspot.com/2012/04/byte-order-fallacy.html
template <typename T>
void WriteBytesMostSignificantByteFirst(T v, std::vector<uint8_t>* out) {
  for (int shift_bytes = sizeof(T) - 1; shift_bytes >= 0; --shift_bytes)
    out->push_back(0xff & (v >> (shift_bytes * 8)));
}

// Extracts sizeof(T) bytes from |in| to extract a value of type T
// (e.g. uint64_t, uint32_t, ...), most significant byte first.
// See also: https://commandcenter.blogspot.com/2012/04/byte-order-fallacy.html
template <typename T>
T ReadBytesMostSignificantByteFirst(span<uint8_t> in) {
  assert(in.size() >= sizeof(T));
  T result = 0;
  for (size_t shift_bytes = 0; shift_bytes < sizeof(T); ++shift_bytes)
    result |= T(in[sizeof(T) - 1 - shift_bytes]) << (shift_bytes * 8);
  return result;
}
}  // namespace

namespace internals {
// Reads the start of a token with definitive size from |bytes|.
// |type| is the major type as specified in RFC 7049 Section 2.1.
// |value| is the payload (e.g. for MajorType::UNSIGNED) or is the size
// (e.g. for BYTE_STRING).
// If successful, returns the number of bytes read. Otherwise returns 0.
size_t ReadTokenStart(span<uint8_t> bytes, MajorType* type, uint64_t* value) {
  if (bytes.empty())
    return 0;
  uint8_t initial_byte = bytes[0];
  *type = MajorType((initial_byte & kMajorTypeMask) >> kMajorTypeBitShift);

  uint8_t additional_information = initial_byte & kAdditionalInformationMask;
  if (additional_information < 24) {
    // Values 0-23 are encoded directly into the additional info of the
    // initial byte.
    *value = additional_information;
    return 1;
  }
  if (additional_information == kAdditionalInformation1Byte) {
    // Values 24-255 are encoded with one initial byte, followed by the value.
    if (bytes.size() < 2)
      return 0;
    *value = ReadBytesMostSignificantByteFirst<uint8_t>(bytes.subspan(1));
    return 2;
  }
  if (additional_information == kAdditionalInformation2Bytes) {
    // Values 256-65535: 1 initial byte + 2 bytes payload.
    if (bytes.size() < 1 + sizeof(uint16_t))
      return 0;
    *value = ReadBytesMostSignificantByteFirst<uint16_t>(bytes.subspan(1));
    return 3;
  }
  if (additional_information == kAdditionalInformation4Bytes) {
    // 32 bit uint: 1 initial byte + 4 bytes payload.
    if (bytes.size() < 1 + sizeof(uint32_t))
      return 0;
    *value = ReadBytesMostSignificantByteFirst<uint32_t>(bytes.subspan(1));
    return 5;
  }
  if (additional_information == kAdditionalInformation8Bytes) {
    // 64 bit uint: 1 initial byte + 8 bytes payload.
    if (bytes.size() < 1 + sizeof(uint64_t))
      return 0;
    *value = ReadBytesMostSignificantByteFirst<uint64_t>(bytes.subspan(1));
    return 9;
  }
  return 0;
}

// Writes the start of a token with |type|. The |value| may indicate the size,
// or it may be the payload if the value is an unsigned integer.
void WriteTokenStart(MajorType type,
                     uint64_t value,
                     std::vector<uint8_t>* encoded) {
  if (value < 24) {
    // Values 0-23 are encoded directly into the additional info of the
    // initial byte.
    encoded->push_back(EncodeInitialByte(type, /*additional_info=*/value));
    return;
  }
  if (value <= std::numeric_limits<uint8_t>::max()) {
    // Values 24-255 are encoded with one initial byte, followed by the value.
    encoded->push_back(EncodeInitialByte(type, kAdditionalInformation1Byte));
    encoded->push_back(value);
    return;
  }
  if (value <= std::numeric_limits<uint16_t>::max()) {
    // Values 256-65535: 1 initial byte + 2 bytes payload.
    encoded->push_back(EncodeInitialByte(type, kAdditionalInformation2Bytes));
    WriteBytesMostSignificantByteFirst<uint16_t>(value, encoded);
    return;
  }
  if (value <= std::numeric_limits<uint32_t>::max()) {
    // 32 bit uint: 1 initial byte + 4 bytes payload.
    encoded->push_back(EncodeInitialByte(type, kAdditionalInformation4Bytes));
    WriteBytesMostSignificantByteFirst<uint32_t>(static_cast<uint32_t>(value),
                                                 encoded);
    return;
  }
  // 64 bit uint: 1 initial byte + 8 bytes payload.
  encoded->push_back(EncodeInitialByte(type, kAdditionalInformation8Bytes));
  WriteBytesMostSignificantByteFirst<uint64_t>(value, encoded);
}
}  // namespace internals

// =============================================================================
// Detecting CBOR content
// =============================================================================

bool IsCBORMessage(span<uint8_t> msg) {
  return msg.size() >= 4 && msg[0] == kInitialByteForEnvelope &&
         (msg[1] == kInitialByteFor32BitLengthByteString ||
          (msg[1] == kCBOREnvelopeTag &&
           msg[2] == kInitialByteFor32BitLengthByteString));
}

Status CheckCBORMessage(span<uint8_t> msg) {
  if (msg.empty())
    return Status(Error::CBOR_UNEXPECTED_EOF_IN_ENVELOPE, 0);
  if (msg[0] != kInitialByteForEnvelope)
    return Status(Error::CBOR_INVALID_START_BYTE, 0);
  StatusOr<EnvelopeHeader> status_or_header = EnvelopeHeader::Parse(msg);
  if (!status_or_header.ok())
    return status_or_header.status();
  const size_t pos = (*status_or_header).header_size();
  assert(pos < msg.size());  // EnvelopeParser would not allow empty envelope.
  if (msg[pos] != EncodeIndefiniteLengthMapStart())
    return Status(Error::CBOR_MAP_START_EXPECTED, pos);
  return Status();
}

// =============================================================================
// Encoding invidiual CBOR items
// =============================================================================

uint8_t EncodeTrue() {
  return kEncodedTrue;
}

uint8_t EncodeFalse() {
  return kEncodedFalse;
}

uint8_t EncodeNull() {
  return kEncodedNull;
}

uint8_t EncodeIndefiniteLengthArrayStart() {
  return kInitialByteIndefiniteLengthArray;
}

uint8_t EncodeIndefiniteLengthMapStart() {
  return kInitialByteIndefiniteLengthMap;
}

uint8_t EncodeStop() {
  return kStopByte;
}

void EncodeInt32(int32_t value, std::vector<uint8_t>* out) {
  if (value >= 0) {
    internals::WriteTokenStart(MajorType::UNSIGNED, value, out);
  } else {
    uint64_t representation = static_cast<uint64_t>(-(value + 1));
    internals::WriteTokenStart(MajorType::NEGATIVE, representation, out);
  }
}

void EncodeString16(span<uint16_t> in, std::vector<uint8_t>* out) {
  uint64_t byte_length = static_cast<uint64_t>(in.size_bytes());
  internals::WriteTokenStart(MajorType::BYTE_STRING, byte_length, out);
  // When emitting UTF16 characters, we always write the least significant byte
  // first; this is because it's the native representation for X86.
  // TODO(johannes): Implement a more efficient thing here later, e.g.
  // casting *iff* the machine has this byte order.
  // The wire format for UTF16 chars will probably remain the same
  // (least significant byte first) since this way we can have
  // golden files, unittests, etc. that port easily and universally.
  // See also:
  // https://commandcenter.blogspot.com/2012/04/byte-order-fallacy.html
  for (const uint16_t two_bytes : in) {
    out->push_back(two_bytes);
    out->push_back(two_bytes >> 8);
  }
}

void EncodeString8(span<uint8_t> in, std::vector<uint8_t>* out) {
  internals::WriteTokenStart(MajorType::STRING,
                             static_cast<uint64_t>(in.size_bytes()), out);
  out->insert(out->end(), in.begin(), in.end());
}

void EncodeFromLatin1(span<uint8_t> latin1, std::vector<uint8_t>* out) {
  for (size_t ii = 0; ii < latin1.size(); ++ii) {
    if (latin1[ii] <= 127)
      continue;
    // If there's at least one non-ASCII char, convert to UTF8.
    std::vector<uint8_t> utf8(latin1.begin(), latin1.begin() + ii);
    for (; ii < latin1.size(); ++ii) {
      if (latin1[ii] <= 127) {
        utf8.push_back(latin1[ii]);
      } else {
        // 0xC0 means it's a UTF8 sequence with 2 bytes.
        utf8.push_back((latin1[ii] >> 6) | 0xc0);
        utf8.push_back((latin1[ii] | 0x80) & 0xbf);
      }
    }
    EncodeString8(SpanFrom(utf8), out);
    return;
  }
  EncodeString8(latin1, out);
}

void EncodeFromUTF16(span<uint16_t> utf16, std::vector<uint8_t>* out) {
  // If there's at least one non-ASCII char, encode as STRING16 (UTF16).
  for (uint16_t ch : utf16) {
    if (ch <= 127)
      continue;
    EncodeString16(utf16, out);
    return;
  }
  // It's all US-ASCII, strip out every second byte and encode as UTF8.
  internals::WriteTokenStart(MajorType::STRING,
                             static_cast<uint64_t>(utf16.size()), out);
  out->insert(out->end(), utf16.begin(), utf16.end());
}

void EncodeBinary(span<uint8_t> in, std::vector<uint8_t>* out) {
  out->push_back(kExpectedConversionToBase64Tag);
  uint64_t byte_length = static_cast<uint64_t>(in.size_bytes());
  internals::WriteTokenStart(MajorType::BYTE_STRING, byte_length, out);
  out->insert(out->end(), in.begin(), in.end());
}

// A double is encoded with a specific initial byte
// (kInitialByteForDouble) plus the 64 bits of payload for its value.
constexpr size_t kEncodedDoubleSize = 1 + sizeof(uint64_t);

void EncodeDouble(double value, std::vector<uint8_t>* out) {
  // The additional_info=27 indicates 64 bits for the double follow.
  // See RFC 7049 Section 2.3, Table 1.
  out->push_back(kInitialByteForDouble);
  union {
    double from_double;
    uint64_t to_uint64;
  } reinterpret;
  reinterpret.from_double = value;
  WriteBytesMostSignificantByteFirst<uint64_t>(reinterpret.to_uint64, out);
}

// =============================================================================
// cbor::EnvelopeEncoder - for wrapping submessages
// =============================================================================

void EnvelopeEncoder::EncodeStart(std::vector<uint8_t>* out) {
  assert(byte_size_pos_ == 0);
  out->push_back(kInitialByteForEnvelope);
  out->push_back(kCBOREnvelopeTag);
  out->push_back(kInitialByteFor32BitLengthByteString);
  byte_size_pos_ = out->size();
  out->resize(out->size() + sizeof(uint32_t));
}

bool EnvelopeEncoder::EncodeStop(std::vector<uint8_t>* out) {
  assert(byte_size_pos_ != 0);
  // The byte size is the size of the payload, that is, all the
  // bytes that were written past the byte size position itself.
  uint64_t byte_size = out->size() - (byte_size_pos_ + sizeof(uint32_t));
  // We store exactly 4 bytes, so at most INT32MAX, with most significant
  // byte first.
  if (byte_size > std::numeric_limits<uint32_t>::max())
    return false;
  for (int shift_bytes = sizeof(uint32_t) - 1; shift_bytes >= 0;
       --shift_bytes) {
    (*out)[byte_size_pos_++] = 0xff & (byte_size >> (shift_bytes * 8));
  }
  return true;
}

// static
StatusOr<EnvelopeHeader> EnvelopeHeader::Parse(span<uint8_t> in) {
  auto header_or_status = ParseFromFragment(in);
  if (!header_or_status.ok())
    return header_or_status;
  if ((*header_or_status).outer_size() > in.size()) {
    return StatusOr<EnvelopeHeader>(
        Status(Error::CBOR_ENVELOPE_CONTENTS_LENGTH_MISMATCH, in.size()));
  }
  return header_or_status;
}

// static
StatusOr<EnvelopeHeader> EnvelopeHeader::ParseFromFragment(span<uint8_t> in) {
  // Our copy of StatusOr<> requires explicit constructor.
  using Ret = StatusOr<EnvelopeHeader>;
  constexpr size_t kMinEnvelopeSize = 2 + /* for envelope tag */
                                      1 + /* for byte string */
                                      1;  /* for contents, a map or an array */
  if (in.size() < kMinEnvelopeSize)
    return Ret(Status(Error::CBOR_UNEXPECTED_EOF_IN_ENVELOPE, in.size()));
  assert(in[0] == kInitialByteForEnvelope);  // Caller should assure that.
  size_t offset = 1;
  // TODO(caseq): require this! We're currently accepting both a legacy,
  // non spec-compliant envelope tag (that this implementation still currently
  // produces), as well as a well-formed two-byte tag that a correct
  // implementation should emit.
  if (in[offset] == kCBOREnvelopeTag)
    ++offset;
  MajorType type;
  uint64_t size;
  size_t string_header_size =
      internals::ReadTokenStart(in.subspan(offset), &type, &size);
  if (!string_header_size)
    return Ret(Status(Error::CBOR_UNEXPECTED_EOF_IN_ENVELOPE, in.size()));
  if (type != MajorType::BYTE_STRING)
    return Ret(Status(Error::CBOR_INVALID_ENVELOPE, offset));
  // Do not allow empty envelopes -- at least an empty map/array should fit.
  if (!size) {
    return Ret(Status(Error::CBOR_MAP_OR_ARRAY_EXPECTED_IN_ENVELOPE,
                      offset + string_header_size));
  }
  if (size > std::numeric_limits<uint32_t>::max())
    return Ret(Status(Error::CBOR_INVALID_ENVELOPE, offset));
  offset += string_header_size;
  return Ret(EnvelopeHeader(offset, static_cast<size_t>(size)));
}

// =============================================================================
// cbor::NewCBOREncoder - for encoding from a streaming parser
// =============================================================================

namespace {
class CBOREncoder : public ParserHandler {
 public:
  CBOREncoder(std::vector<uint8_t>* out, Status* status)
      : out_(out), status_(status) {
    *status_ = Status();
  }

  void HandleMapBegin() override {
    if (!status_->ok())
      return;
    envelopes_.emplace_back();
    envelopes_.back().EncodeStart(out_);
    out_->push_back(kInitialByteIndefiniteLengthMap);
  }

  void HandleMapEnd() override {
    if (!status_->ok())
      return;
    out_->push_back(kStopByte);
    assert(!envelopes_.empty());
    if (!envelopes_.back().EncodeStop(out_)) {
      HandleError(
          Status(Error::CBOR_ENVELOPE_SIZE_LIMIT_EXCEEDED, out_->size()));
      return;
    }
    envelopes_.pop_back();
  }

  void HandleArrayBegin() override {
    if (!status_->ok())
      return;
    envelopes_.emplace_back();
    envelopes_.back().EncodeStart(out_);
    out_->push_back(kInitialByteIndefiniteLengthArray);
  }

  void HandleArrayEnd() override {
    if (!status_->ok())
      return;
    out_->push_back(kStopByte);
    assert(!envelopes_.empty());
    if (!envelopes_.back().EncodeStop(out_)) {
      HandleError(
          Status(Error::CBOR_ENVELOPE_SIZE_LIMIT_EXCEEDED, out_->size()));
      return;
    }
    envelopes_.pop_back();
  }

  void HandleString8(span<uint8_t> chars) override {
    if (!status_->ok())
      return;
    EncodeString8(chars, out_);
  }

  void HandleString16(span<uint16_t> chars) override {
    if (!status_->ok())
      return;
    EncodeFromUTF16(chars, out_);
  }

  void HandleBinary(span<uint8_t> bytes) override {
    if (!status_->ok())
      return;
    EncodeBinary(bytes, out_);
  }

  void HandleDouble(double value) override {
    if (!status_->ok())
      return;
    EncodeDouble(value, out_);
  }

  void HandleInt32(int32_t value) override {
    if (!status_->ok())
      return;
    EncodeInt32(value, out_);
  }

  void HandleBool(bool value) override {
    if (!status_->ok())
      return;
    // See RFC 7049 Section 2.3, Table 2.
    out_->push_back(value ? kEncodedTrue : kEncodedFalse);
  }

  void HandleNull() override {
    if (!status_->ok())
      return;
    // See RFC 7049 Section 2.3, Table 2.
    out_->push_back(kEncodedNull);
  }

  void HandleError(Status error) override {
    if (!status_->ok())
      return;
    *status_ = error;
    out_->clear();
  }

 private:
  std::vector<uint8_t>* out_;
  std::vector<EnvelopeEncoder> envelopes_;
  Status* status_;
};
}  // namespace

std::unique_ptr<ParserHandler> NewCBOREncoder(std::vector<uint8_t>* out,
                                              Status* status) {
  return std::unique_ptr<ParserHandler>(new CBOREncoder(out, status));
}

// =============================================================================
// cbor::CBORTokenizer - for parsing individual CBOR items
// =============================================================================

CBORTokenizer::CBORTokenizer(span<uint8_t> bytes)
    : bytes_(bytes), status_(Error::OK, 0) {
  ReadNextToken();
}

CBORTokenizer::~CBORTokenizer() {}

CBORTokenTag CBORTokenizer::TokenTag() const {
  return token_tag_;
}

void CBORTokenizer::Next() {
  if (token_tag_ == CBORTokenTag::ERROR_VALUE ||
      token_tag_ == CBORTokenTag::DONE)
    return;
  ReadNextToken();
}

void CBORTokenizer::EnterEnvelope() {
  token_byte_length_ = GetEnvelopeHeader().header_size();
  ReadNextToken();
}

Status CBORTokenizer::Status() const {
  return status_;
}

// The following accessor functions ::GetInt32, ::GetDouble,
// ::GetString8, ::GetString16WireRep, ::GetBinary, ::GetEnvelopeContents
// assume that a particular token was recognized in ::ReadNextToken.
// That's where all the error checking is done. By design,
// the accessors (assuming the token was recognized) never produce
// an error.

int32_t CBORTokenizer::GetInt32() const {
  assert(token_tag_ == CBORTokenTag::INT32);
  // The range checks happen in ::ReadNextToken().
  return static_cast<int32_t>(
      token_start_type_ == MajorType::UNSIGNED
          ? token_start_internal_value_
          : -static_cast<int64_t>(token_start_internal_value_) - 1);
}

double CBORTokenizer::GetDouble() const {
  assert(token_tag_ == CBORTokenTag::DOUBLE);
  union {
    uint64_t from_uint64;
    double to_double;
  } reinterpret;
  reinterpret.from_uint64 = ReadBytesMostSignificantByteFirst<uint64_t>(
      bytes_.subspan(status_.pos + 1));
  return reinterpret.to_double;
}

span<uint8_t> CBORTokenizer::GetString8() const {
  assert(token_tag_ == CBORTokenTag::STRING8);
  auto length = static_cast<size_t>(token_start_internal_value_);
  return bytes_.subspan(status_.pos + (token_byte_length_ - length), length);
}

span<uint8_t> CBORTokenizer::GetString16WireRep() const {
  assert(token_tag_ == CBORTokenTag::STRING16);
  auto length = static_cast<size_t>(token_start_internal_value_);
  return bytes_.subspan(status_.pos + (token_byte_length_ - length), length);
}

span<uint8_t> CBORTokenizer::GetBinary() const {
  assert(token_tag_ == CBORTokenTag::BINARY);
  auto length = static_cast<size_t>(token_start_internal_value_);
  return bytes_.subspan(status_.pos + (token_byte_length_ - length), length);
}

span<uint8_t> CBORTokenizer::GetEnvelope() const {
  return bytes_.subspan(status_.pos, GetEnvelopeHeader().outer_size());
}

span<uint8_t> CBORTokenizer::GetEnvelopeContents() const {
  const EnvelopeHeader& header = GetEnvelopeHeader();
  return bytes_.subspan(status_.pos + header.header_size(),
                        header.content_size());
}

const EnvelopeHeader& CBORTokenizer::GetEnvelopeHeader() const {
  assert(token_tag_ == CBORTokenTag::ENVELOPE);
  return envelope_header_;
}

// All error checking happens in ::ReadNextToken, so that the accessors
// can avoid having to carry an error return value.
//
// With respect to checking the encoded lengths of strings, arrays, etc:
// On the wire, CBOR uses 1,2,4, and 8 byte unsigned integers, so
// we initially read them as uint64_t, usually into token_start_internal_value_.
//
// However, since these containers have a representation on the machine,
// we need to do corresponding size computations on the input byte array,
// output span (e.g. the payload for a string), etc., and size_t is
// machine specific (in practice either 32 bit or 64 bit).
//
// Further, we must avoid overflowing size_t. Therefore, we use this
// kMaxValidLength constant to:
// - Reject values that are larger than the architecture specific
//   max size_t (differs between 32 bit and 64 bit arch).
// - Reserve at least one bit so that we can check against overflows
//   when adding lengths (array / string length / etc.); we do this by
//   ensuring that the inputs to an addition are <= kMaxValidLength,
//   and then checking whether the sum went past it.
//
// See also
// https://chromium.googlesource.com/chromium/src/+/main/docs/security/integer-semantics.md
static const uint64_t kMaxValidLength =
    std::min<uint64_t>(std::numeric_limits<uint64_t>::max() >> 2,
                       std::numeric_limits<size_t>::max());

void CBORTokenizer::ReadNextToken() {
  status_.pos += token_byte_length_;
  status_.error = Error::OK;
  envelope_header_ = EnvelopeHeader();
  if (status_.pos >= bytes_.size()) {
    token_tag_ = CBORTokenTag::DONE;
    return;
  }
  const size_t remaining_bytes = bytes_.size() - status_.pos;
  switch (bytes_[status_.pos]) {
    case kStopByte:
      SetToken(CBORTokenTag::STOP, 1);
      return;
    case kInitialByteIndefiniteLengthMap:
      SetToken(CBORTokenTag::MAP_START, 1);
      return;
    case kInitialByteIndefiniteLengthArray:
      SetToken(CBORTokenTag::ARRAY_START, 1);
      return;
    case kEncodedTrue:
      SetToken(CBORTokenTag::TRUE_VALUE, 1);
      return;
    case kEncodedFalse:
      SetToken(CBORTokenTag::FALSE_VALUE, 1);
      return;
    case kEncodedNull:
      SetToken(CBORTokenTag::NULL_VALUE, 1);
      return;
    case kExpectedConversionToBase64Tag: {  // BINARY
      const size_t bytes_read = internals::ReadTokenStart(
          bytes_.subspan(status_.pos + 1), &token_start_type_,
          &token_start_internal_value_);
      if (!bytes_read || token_start_type_ != MajorType::BYTE_STRING ||
          token_start_internal_value_ > kMaxValidLength) {
        SetError(Error::CBOR_INVALID_BINARY);
        return;
      }
      const uint64_t token_byte_length = token_start_internal_value_ +
                                         /* tag before token start: */ 1 +
                                         /* token start: */ bytes_read;
      if (token_byte_length > remaining_bytes) {
        SetError(Error::CBOR_INVALID_BINARY);
        return;
      }
      SetToken(CBORTokenTag::BINARY, static_cast<size_t>(token_byte_length));
      return;
    }
    case kInitialByteForDouble: {  // DOUBLE
      if (kEncodedDoubleSize > remaining_bytes) {
        SetError(Error::CBOR_INVALID_DOUBLE);
        return;
      }
      SetToken(CBORTokenTag::DOUBLE, kEncodedDoubleSize);
      return;
    }
    case kInitialByteForEnvelope: {  // ENVELOPE
      StatusOr<EnvelopeHeader> status_or_header =
          EnvelopeHeader::Parse(bytes_.subspan(status_.pos));
      if (!status_or_header.ok()) {
        status_.pos += status_or_header.status().pos;
        SetError(status_or_header.status().error);
        return;
      }
      assert((*status_or_header).outer_size() <= remaining_bytes);
      envelope_header_ = *status_or_header;
      SetToken(CBORTokenTag::ENVELOPE, envelope_header_.outer_size());
      return;
    }
    default: {
      const size_t bytes_read = internals::ReadTokenStart(
          bytes_.subspan(status_.pos), &token_start_type_,
          &token_start_internal_value_);
      switch (token_start_type_) {
        case MajorType::UNSIGNED:  // INT32.
          // INT32 is a signed int32 (int32 makes sense for the
          // inspector protocol, it's not a CBOR limitation), so we check
          // against the signed max, so that the allowable values are
          // 0, 1, 2, ... 2^31 - 1.
          if (!bytes_read ||
              static_cast<uint64_t>(std::numeric_limits<int32_t>::max()) <
                  static_cast<uint64_t>(token_start_internal_value_)) {
            SetError(Error::CBOR_INVALID_INT32);
            return;
          }
          SetToken(CBORTokenTag::INT32, bytes_read);
          return;
        case MajorType::NEGATIVE: {  // INT32.
          // INT32 is a signed int32 (int32 makes sense for the
          // inspector protocol, it's not a CBOR limitation); in CBOR, the
          // negative values for INT32 are represented as NEGATIVE, that is, -1
          // INT32 is represented as 1 << 5 | 0 (major type 1, additional info
          // value 0).
          // The represented allowed values range is -1 to -2^31.
          // They are mapped into the encoded range of 0 to 2^31-1.
          // We check the payload in token_start_internal_value_ against
          // that range (2^31-1 is also known as
          // std::numeric_limits<int32_t>::max()).
          if (!bytes_read ||
              static_cast<uint64_t>(token_start_internal_value_) >
                  static_cast<uint64_t>(std::numeric_limits<int32_t>::max())) {
            SetError(Error::CBOR_INVALID_INT32);
            return;
          }
          SetToken(CBORTokenTag::INT32, bytes_read);
          return;
        }
        case MajorType::STRING: {  // STRING8.
          if (!bytes_read || token_start_internal_value_ > kMaxValidLength) {
            SetError(Error::CBOR_INVALID_STRING8);
            return;
          }
          uint64_t token_byte_length = token_start_internal_value_ + bytes_read;
          if (token_byte_length > remaining_bytes) {
            SetError(Error::CBOR_INVALID_STRING8);
            return;
          }
          SetToken(CBORTokenTag::STRING8,
                   static_cast<size_t>(token_byte_length));
          return;
        }
        case MajorType::BYTE_STRING: {  // STRING16.
          // Length must be divisible by 2 since UTF16 is 2 bytes per
          // character, hence the &1 check.
          if (!bytes_read || token_start_internal_value_ > kMaxValidLength ||
              token_start_internal_value_ & 1) {
            SetError(Error::CBOR_INVALID_STRING16);
            return;
          }
          uint64_t token_byte_length = token_start_internal_value_ + bytes_read;
          if (token_byte_length > remaining_bytes) {
            SetError(Error::CBOR_INVALID_STRING16);
            return;
          }
          SetToken(CBORTokenTag::STRING16,
                   static_cast<size_t>(token_byte_length));
          return;
        }
        case MajorType::ARRAY:
        case MajorType::MAP:
        case MajorType::TAG:
        case MajorType::SIMPLE_VALUE:
          SetError(Error::CBOR_UNSUPPORTED_VALUE);
          return;
      }
    }
  }
}

void CBORTokenizer::SetToken(CBORTokenTag token_tag, size_t token_byte_length) {
  token_tag_ = token_tag;
  token_byte_length_ = token_byte_length;
}

void CBORTokenizer::SetError(Error error) {
  token_tag_ = CBORTokenTag::ERROR_VALUE;
  status_.error = error;
}

// =============================================================================
// cbor::ParseCBOR - for receiving streaming parser events for CBOR messages
// =============================================================================

namespace {
// When parsing CBOR, we limit recursion depth for objects and arrays
// to this constant.
static constexpr int kStackLimit = 300;

// Below are three parsing routines for CBOR, which cover enough
// to roundtrip JSON messages.
bool ParseMap(int32_t stack_depth,
              CBORTokenizer* tokenizer,
              ParserHandler* out);
bool ParseArray(int32_t stack_depth,
                CBORTokenizer* tokenizer,
                ParserHandler* out);
bool ParseValue(int32_t stack_depth,
                CBORTokenizer* tokenizer,
                ParserHandler* out);

void ParseUTF16String(CBORTokenizer* tokenizer, ParserHandler* out) {
  std::vector<uint16_t> value;
  span<uint8_t> rep = tokenizer->GetString16WireRep();
  for (size_t ii = 0; ii < rep.size(); ii += 2)
    value.push_back((rep[ii + 1] << 8) | rep[ii]);
  out->HandleString16(span<uint16_t>(value.data(), value.size()));
  tokenizer->Next();
}

bool ParseUTF8String(CBORTokenizer* tokenizer, ParserHandler* out) {
  assert(tokenizer->TokenTag() == CBORTokenTag::STRING8);
  out->HandleString8(tokenizer->GetString8());
  tokenizer->Next();
  return true;
}

bool ParseEnvelope(int32_t stack_depth,
                   CBORTokenizer* tokenizer,
                   ParserHandler* out) {
  assert(tokenizer->TokenTag() == CBORTokenTag::ENVELOPE);
  // Before we enter the envelope, we save the position that we
  // expect to see after we're done parsing the envelope contents.
  // This way we can compare and produce an error if the contents
  // didn't fit exactly into the envelope length.
  size_t pos_past_envelope =
      tokenizer->Status().pos + tokenizer->GetEnvelopeHeader().outer_size();
  tokenizer->EnterEnvelope();
  switch (tokenizer->TokenTag()) {
    case CBORTokenTag::ERROR_VALUE:
      out->HandleError(tokenizer->Status());
      return false;
    case CBORTokenTag::MAP_START:
      if (!ParseMap(stack_depth + 1, tokenizer, out))
        return false;
      break;  // Continue to check pos_past_envelope below.
    case CBORTokenTag::ARRAY_START:
      if (!ParseArray(stack_depth + 1, tokenizer, out))
        return false;
      break;  // Continue to check pos_past_envelope below.
    default:
      out->HandleError(Status{Error::CBOR_MAP_OR_ARRAY_EXPECTED_IN_ENVELOPE,
                              tokenizer->Status().pos});
      return false;
  }
  // The contents of the envelope parsed OK, now check that we're at
  // the expected position.
  if (pos_past_envelope != tokenizer->Status().pos) {
    out->HandleError(Status{Error::CBOR_ENVELOPE_CONTENTS_LENGTH_MISMATCH,
                            tokenizer->Status().pos});
    re
"""


```
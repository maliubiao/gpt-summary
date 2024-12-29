Response:
My thought process for analyzing the `normalize_algorithm.cc` file and answering the prompt went something like this:

1. **Understand the Goal:** The primary goal of this file is to take a potentially ambiguous or incomplete algorithm specification (often coming from JavaScript's Web Crypto API) and normalize it into a canonical, internal representation that the lower-level crypto implementation can understand. This involves parsing dictionaries and strings to identify algorithms, parameters, and handle potential errors.

2. **Identify Key Structures and Functions:** I scanned the code for the main building blocks. The `kAlgorithmNameMappings` array immediately stood out as a central lookup table for algorithm names and their internal IDs. The `LookupAlgorithmIdByName` function uses this table to translate string names to IDs. The `ErrorContext` class suggests a mechanism for tracking parsing errors. The numerous `Parse...Params` functions clearly handle the parsing of different algorithm-specific parameter dictionaries. The main `NormalizeAlgorithm` function ties these pieces together.

3. **Infer High-Level Functionality:** Based on the identified structures and functions, I concluded that the file's core function is *algorithm normalization*. This involves:
    * **Name Lookup:**  Taking a string representing an algorithm name and converting it to an internal ID.
    * **Parameter Parsing:**  Taking a dictionary of parameters and extracting the relevant values, ensuring they are valid according to the Web Crypto API specification.
    * **Error Handling:**  Providing detailed error messages when parsing fails.

4. **Relate to JavaScript, HTML, and CSS:**  I considered where this code fits within the browser's architecture and how it interacts with web developers. The Web Crypto API is exposed to JavaScript, so this file is a crucial part of the implementation of that API. While not directly related to HTML or CSS's core functionality, the Web Crypto API (and thus this file) enables secure communication and cryptographic operations within web pages, which are composed of HTML and styled by CSS.

5. **Develop Examples:**  To illustrate the connections, I constructed concrete examples of how a web developer might use the Web Crypto API in JavaScript and how the `normalize_algorithm.cc` code would come into play. This involved imagining different algorithm scenarios (hashing, encryption, key generation) and showing how parameters are passed.

6. **Consider Input and Output:** I focused on the primary function, `NormalizeAlgorithm`. I reasoned about what kind of input it receives (a `V8AlgorithmIdentifier` representing the algorithm name and optional parameters) and what kind of output it produces (a `WebCryptoAlgorithm` structure containing the normalized algorithm ID and parameters). I then created hypothetical examples of successful and failing normalizations.

7. **Think About Common Errors:** I considered common mistakes developers might make when using the Web Crypto API. This included providing incorrect parameter types, missing required parameters, or using unsupported algorithm names. I then linked these errors back to the role of `normalize_algorithm.cc` in detecting and reporting these issues.

8. **Trace User Actions:**  To understand how a user's actions could lead to this code being executed, I visualized the sequence of events: a user interacting with a web page, JavaScript code calling a Web Crypto API function, and then the browser's engine processing that call and eventually invoking the normalization logic in this file.

9. **Structure the Answer:** I organized my thoughts into clear sections based on the prompt's requirements: functionality, relationship to web technologies, input/output examples, common errors, and user action tracing. I used bullet points and code snippets to improve readability and clarity.

10. **Summarize Functionality (Part 1):** Finally, I reviewed all the information gathered and provided a concise summary of the file's main purpose for the "Part 1" aspect of the prompt. This involved focusing on the name-to-ID mapping and parameter parsing aspects.

Throughout this process, I constantly referred back to the provided code snippet to ensure my interpretations were accurate and supported by the source. I also made sure to address all the specific points raised in the prompt.
这是 `blink/renderer/modules/crypto/normalize_algorithm.cc` 文件的第一部分，其主要功能是**规范化 (normalize)** Web Crypto API 中提供的算法标识符 (algorithm identifier)。这意味着它接收一个可能包含算法名称（字符串）或更详细的算法字典的对象，并将其转换为一个内部的、标准化的 `WebCryptoAlgorithm` 结构体，方便 Blink 引擎的底层加密模块使用。

**具体功能归纳:**

1. **算法名称到 ID 的映射:**
   - 维护一个静态查找表 `kAlgorithmNameMappings`，将 Web Crypto API 中使用的算法名称字符串（例如 "AES-CBC", "SHA-256"）映射到内部的枚举类型 `WebCryptoAlgorithmId`。
   - 提供 `LookupAlgorithmIdByName` 函数，根据给定的算法名称字符串，在该查找表中查找对应的 `WebCryptoAlgorithmId`。这个查找是大小写不敏感的。
   - 包含了对 `RuntimeEnabledFeatures::WebCryptoCurve25519Enabled()` 的检查，意味着某些算法（如 Ed25519 和 X25519）可能需要特定的运行时特性启用才能被识别。

2. **算法参数的解析和验证:**
   - 提供了一系列 `Parse...Params` 函数，用于解析不同算法对应的参数字典。例如：
     - `ParseAesCbcParams` 用于解析 AES-CBC 算法的参数，例如 `iv` (初始化向量)。
     - `ParseHmacKeyGenParams` 用于解析 HMAC 密钥生成算法的参数，例如 `hash` (使用的哈希算法) 和可选的 `length` (密钥长度)。
     - `ParseRsaHashedKeyGenParams` 用于解析 RSA 密钥生成算法的参数，例如 `modulusLength` (模数长度) 和 `publicExponent` (公钥指数)。
   - 这些解析函数会检查参数字典中是否存在必需的属性，属性的类型是否正确，以及属性值是否在允许的范围内。如果发现错误，会设置相应的异常状态 (ExceptionState)。

3. **错误处理:**
   - 使用 `ErrorContext` 类来维护一个错误发生时的上下文堆栈，帮助定位错误原因。当解析算法参数时发生错误，会记录相关的上下文信息，生成更详细的错误消息。
   - 提供了 `SetTypeError` 和 `SetNotSupportedError` 辅助函数，用于抛出相应的 JavaScript 异常。

4. **数据类型的转换和处理:**
   - 提供了 `GetOptionalBufferSource`, `GetBufferSource`, `GetUint8Array`, `GetBigInteger`, `GetInteger` 等辅助函数，用于从 JavaScript 传递过来的 `Dictionary` 对象中安全地提取各种类型的数据，例如 `ArrayBuffer`, `ArrayBufferView`, 无符号整数等。

**与 JavaScript, HTML, CSS 的关系及举例:**

该文件直接参与了 Web Crypto API 的实现，因此与 JavaScript 密切相关。当 JavaScript 代码调用 Web Crypto API 中的函数，例如 `crypto.subtle.encrypt()` 或 `crypto.subtle.generateKey()` 时，浏览器引擎会调用 Blink 层的相应代码，而 `normalize_algorithm.cc` 中的函数就是这些代码的关键组成部分。

**JavaScript 示例:**

```javascript
// 使用 AES-CBC 算法加密数据
crypto.subtle.encrypt(
  {
    name: "AES-CBC",
    iv: new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
  },
  key, // 之前生成的或导入的密钥
  data // 要加密的数据 (ArrayBuffer 或 ArrayBufferView)
).then(function(encrypted){
  // ...
}).catch(function(err){
  console.error(err); // 如果算法名称或参数不正确，可能会在这里捕获到错误
});

// 生成 HMAC 密钥
crypto.subtle.generateKey(
  {
    name: "HMAC",
    hash: { name: "SHA-256" },
    length: 256
  },
  true, // 是否可以提取密钥
  ["sign", "verify"] // 密钥用途
).then(function(key){
  // ...
}).catch(function(err){
  console.error(err); // 同样，错误的算法或参数会导致错误
});
```

在上面的 JavaScript 示例中，当调用 `crypto.subtle.encrypt` 或 `crypto.subtle.generateKey` 时，传递给这些函数的第一个参数是一个包含算法名称和参数的对象。`normalize_algorithm.cc` 文件的职责就是接收这个 JavaScript 对象，并将其中的算法名称（例如 "AES-CBC", "HMAC"）和参数（例如 `iv`, `hash`, `length`）提取出来，验证其有效性，并将其转换为 Blink 引擎内部可以理解的格式。

**与 HTML 和 CSS 的关系:**

虽然 `normalize_algorithm.cc` 本身不直接处理 HTML 或 CSS，但它是 Web Crypto API 实现的关键部分。Web Crypto API 允许在 Web 页面中执行加密操作，这使得 Web 应用程序能够实现安全通信、数据完整性验证等功能。这些安全功能最终会影响到 Web 应用程序的用户体验和安全性，而这些应用程序的呈现和样式则由 HTML 和 CSS 控制。

**逻辑推理、假设输入与输出:**

**假设输入 (JavaScript 传递的算法对象):**

```javascript
{
  name: "aes-cbc", // 注意：大小写不敏感
  iv: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
}
```

**预期输出 (成功规范化后的 `WebCryptoAlgorithm` 结构体):**

```c++
WebCryptoAlgorithm {
  id: kWebCryptoAlgorithmIdAesCbc,
  params: std::make_unique<WebCryptoAesCbcParams>(WebVector<uint8_t>{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
}
```

**假设输入 (错误的算法参数):**

```javascript
{
  name: "AES-CBC",
  iv: "not an array" // 错误的数据类型
}
```

**预期输出 (抛出 JavaScript 异常):**

```
TypeError: iv: Not a BufferSource
```

**用户或编程常见的使用错误:**

1. **拼写错误的算法名称:** 例如将 "AES-CBC" 拼写成 "AES_CBC" 或 "aes-cbs"。
2. **参数名称错误:**  例如在 AES-CBC 中将 `iv` 写成 `initialVector`。
3. **参数类型错误:** 例如上面例子中 `iv` 应该是 `ArrayBuffer` 或 `ArrayBufferView`，却传递了字符串。
4. **缺少必需的参数:** 例如在 AES-CBC 中没有提供 `iv`。
5. **参数值超出范围:** 例如，某些算法对密钥长度有特定的要求。
6. **使用了不支持的算法:**  浏览器可能不支持某些较新的或实验性的算法。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中访问一个包含 JavaScript 代码的网页。**
2. **网页中的 JavaScript 代码调用了 Web Crypto API 的函数，例如 `crypto.subtle.encrypt()`。**
3. **浏览器引擎接收到 JavaScript 的调用，并将算法名称和参数传递给 Blink 渲染引擎。**
4. **Blink 渲染引擎的 Web Crypto API 实现会调用 `normalize_algorithm.cc` 中的 `NormalizeAlgorithm` 函数。**
5. **`NormalizeAlgorithm` 函数会首先使用 `LookupAlgorithmIdByName` 查找算法名称对应的 ID。**
6. **然后，根据算法 ID，调用相应的 `Parse...Params` 函数来解析和验证参数。**
7. **如果在解析过程中发现错误，例如参数类型不匹配，`Parse...Params` 函数会调用 `SetTypeError` 等函数抛出 JavaScript 异常。**
8. **这个异常会返回到 JavaScript 代码中，可能会被 `catch` 语句捕获并处理。**

**总结 (第一部分的功能):**

总而言之，`blink/renderer/modules/crypto/normalize_algorithm.cc` 文件的第一部分主要负责将 Web Crypto API 中用户提供的算法标识符（名称字符串或包含名称和参数的字典对象）转换成 Blink 引擎内部使用的标准化的 `WebCryptoAlgorithm` 结构体。这包括将算法名称映射到内部 ID，并解析和验证算法所需的参数，同时处理可能出现的各种错误情况。它是 Web Crypto API 在 Blink 引擎中的关键入口点之一，确保了用户提供的算法信息能够被正确理解和使用。

Prompt: 
```
这是目录为blink/renderer/modules/crypto/normalize_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/crypto/normalize_algorithm.h"

#include <algorithm>
#include <memory>
#include <string>

#include "third_party/blink/public/platform/web_crypto_algorithm_params.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/renderer/bindings/core/v8/dictionary.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_object_string.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_crypto_key.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_piece.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/crypto/crypto_key.h"
#include "third_party/blink/renderer/modules/crypto/crypto_utilities.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

struct AlgorithmNameMapping {
  // Must be an upper case ASCII string.
  const char* const algorithm_name;
  // Must be strlen(algorithmName).
  unsigned char algorithm_name_length;
  WebCryptoAlgorithmId algorithm_id;

#if DCHECK_IS_ON()
  bool operator<(const AlgorithmNameMapping&) const;
#endif
};

// Must be sorted by length, and then by reverse string.
// Also all names must be upper case ASCII.
const AlgorithmNameMapping kAlgorithmNameMappings[] = {
    {"HMAC", 4, kWebCryptoAlgorithmIdHmac},
    {"HKDF", 4, kWebCryptoAlgorithmIdHkdf},
    {"ECDH", 4, kWebCryptoAlgorithmIdEcdh},
    {"SHA-1", 5, kWebCryptoAlgorithmIdSha1},
    {"ECDSA", 5, kWebCryptoAlgorithmIdEcdsa},
    {"PBKDF2", 6, kWebCryptoAlgorithmIdPbkdf2},
    {"X25519", 6, kWebCryptoAlgorithmIdX25519},
    {"AES-KW", 6, kWebCryptoAlgorithmIdAesKw},
    {"SHA-512", 7, kWebCryptoAlgorithmIdSha512},
    {"SHA-384", 7, kWebCryptoAlgorithmIdSha384},
    {"SHA-256", 7, kWebCryptoAlgorithmIdSha256},
    {"ED25519", 7, kWebCryptoAlgorithmIdEd25519},
    {"AES-CBC", 7, kWebCryptoAlgorithmIdAesCbc},
    {"AES-GCM", 7, kWebCryptoAlgorithmIdAesGcm},
    {"AES-CTR", 7, kWebCryptoAlgorithmIdAesCtr},
    {"RSA-PSS", 7, kWebCryptoAlgorithmIdRsaPss},
    {"RSA-OAEP", 8, kWebCryptoAlgorithmIdRsaOaep},
    {"RSASSA-PKCS1-V1_5", 17, kWebCryptoAlgorithmIdRsaSsaPkcs1v1_5},
};

// Reminder to update the table mapping names to IDs whenever adding a new
// algorithm ID.
static_assert(kWebCryptoAlgorithmIdLast + 1 ==
                  std::size(kAlgorithmNameMappings),
              "algorithmNameMappings needs to be updated");

#if DCHECK_IS_ON()

// Essentially std::is_sorted() (however that function is new to C++11).
template <typename Iterator>
bool IsSorted(Iterator begin, Iterator end) {
  if (begin == end)
    return true;

  Iterator prev = begin;
  Iterator cur = begin + 1;

  while (cur != end) {
    if (*cur < *prev)
      return false;
    cur++;
    prev++;
  }

  return true;
}

bool AlgorithmNameMapping::operator<(const AlgorithmNameMapping& o) const {
  if (algorithm_name_length < o.algorithm_name_length)
    return true;
  if (algorithm_name_length > o.algorithm_name_length)
    return false;

  for (size_t i = 0; i < algorithm_name_length; ++i) {
    size_t reverse_index = algorithm_name_length - i - 1;
    char c1 = algorithm_name[reverse_index];
    char c2 = o.algorithm_name[reverse_index];

    if (c1 < c2)
      return true;
    if (c1 > c2)
      return false;
  }

  return false;
}

bool VerifyAlgorithmNameMappings(const AlgorithmNameMapping* begin,
                                 const AlgorithmNameMapping* end) {
  for (const AlgorithmNameMapping* it = begin; it != end; ++it) {
    if (it->algorithm_name_length != strlen(it->algorithm_name))
      return false;
    String str(base::span(it->algorithm_name, it->algorithm_name_length));
    if (!str.ContainsOnlyASCIIOrEmpty())
      return false;
    if (str.UpperASCII() != str)
      return false;
  }

  return IsSorted(begin, end);
}
#endif

template <typename CharType>
bool AlgorithmNameComparator(const AlgorithmNameMapping& a, StringImpl* b) {
  if (a.algorithm_name_length < b->length())
    return true;
  if (a.algorithm_name_length > b->length())
    return false;

  // Because the algorithm names contain many common prefixes, it is better
  // to compare starting at the end of the string.
  for (size_t i = 0; i < a.algorithm_name_length; ++i) {
    size_t reverse_index = a.algorithm_name_length - i - 1;
    CharType c1 = a.algorithm_name[reverse_index];
    CharType c2 = b->GetCharacters<CharType>()[reverse_index];
    if (!IsASCII(c2))
      return false;
    c2 = ToASCIIUpper(c2);

    if (c1 < c2)
      return true;
    if (c1 > c2)
      return false;
  }

  return false;
}

bool LookupAlgorithmIdByName(const String& algorithm_name,
                             WebCryptoAlgorithmId& id) {
  const AlgorithmNameMapping* begin = kAlgorithmNameMappings;
  const AlgorithmNameMapping* end =
      kAlgorithmNameMappings + std::size(kAlgorithmNameMappings);

#if DCHECK_IS_ON()
  DCHECK(VerifyAlgorithmNameMappings(begin, end));
#endif

  const AlgorithmNameMapping* it;
  if (algorithm_name.Impl()->Is8Bit())
    it = std::lower_bound(begin, end, algorithm_name.Impl(),
                          &AlgorithmNameComparator<LChar>);
  else
    it = std::lower_bound(begin, end, algorithm_name.Impl(),
                          &AlgorithmNameComparator<UChar>);

  if (it == end)
    return false;

  if (it->algorithm_name_length != algorithm_name.length() ||
      !DeprecatedEqualIgnoringCase(algorithm_name, it->algorithm_name))
    return false;

  id = it->algorithm_id;

  if (id == kWebCryptoAlgorithmIdEd25519 || id == kWebCryptoAlgorithmIdX25519) {
    return RuntimeEnabledFeatures::WebCryptoCurve25519Enabled();
  }

  return true;
}

void SetTypeError(const String& message, ExceptionState& exception_state) {
  exception_state.ThrowTypeError(message);
}

void SetNotSupportedError(const String& message,
                          ExceptionState& exception_state) {
  exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                    message);
}

// ErrorContext holds a stack of string literals which describe what was
// happening at the time the error occurred. This is helpful because
// parsing of the algorithm dictionary can be recursive and it is difficult to
// tell what went wrong from a failure alone.
class ErrorContext {
  STACK_ALLOCATED();

 public:
  void Add(const char* message) { messages_.push_back(message); }

  void RemoveLast() { messages_.pop_back(); }

  // Join all of the string literals into a single String.
  String ToString() const {
    if (messages_.empty())
      return String();

    StringBuilder result;
    const base::span<const LChar> separator =
        base::byte_span_from_cstring(": ");

    wtf_size_t length = (messages_.size() - 1) * separator.size();
    for (wtf_size_t i = 0; i < messages_.size(); ++i)
      length += strlen(messages_[i]);
    result.ReserveCapacity(length);

    for (wtf_size_t i = 0; i < messages_.size(); ++i) {
      if (i)
        result.Append(separator);
      result.Append(StringView(messages_[i]));
    }

    return result.ToString();
  }

  String ToString(const char* message) const {
    ErrorContext stack(*this);
    stack.Add(message);
    return stack.ToString();
  }

  String ToString(const char* message1, const char* message2) const {
    ErrorContext stack(*this);
    stack.Add(message1);
    stack.Add(message2);
    return stack.ToString();
  }

 private:
  // This inline size is large enough to avoid having to grow the Vector in
  // the majority of cases (up to 1 nested algorithm identifier).
  Vector<const char*, 10> messages_;
};

// Defined by the WebCrypto spec as:
//
//     typedef (ArrayBuffer or ArrayBufferView) BufferSource;
//
bool GetOptionalBufferSource(const Dictionary& raw,
                             const char* property_name,
                             bool& has_property,
                             WebVector<uint8_t>& bytes,
                             const ErrorContext& context,
                             ExceptionState& exception_state) {
  has_property = false;
  v8::Local<v8::Value> v8_value;
  if (!raw.Get(property_name, v8_value))
    return true;
  has_property = true;

  if (v8_value->IsArrayBufferView()) {
    DOMArrayBufferView* array_buffer_view =
        NativeValueTraits<NotShared<DOMArrayBufferView>>::NativeValue(
            raw.GetIsolate(), v8_value, exception_state)
            .Get();
    if (exception_state.HadException())
      return false;
    bytes = CopyBytes(array_buffer_view);
    return true;
  }

  if (v8_value->IsArrayBuffer()) {
    DOMArrayBuffer* array_buffer =
        NativeValueTraits<DOMArrayBuffer>::NativeValue(
            raw.GetIsolate(), v8_value, exception_state);
    if (exception_state.HadException())
      return false;
    bytes = CopyBytes(array_buffer);
    return true;
  }

  if (has_property) {
    SetTypeError(context.ToString(property_name, "Not a BufferSource"),
                 exception_state);
    return false;
  }
  return true;
}

bool GetBufferSource(const Dictionary& raw,
                     const char* property_name,
                     WebVector<uint8_t>& bytes,
                     const ErrorContext& context,
                     ExceptionState& exception_state) {
  bool has_property;
  bool ok = GetOptionalBufferSource(raw, property_name, has_property, bytes,
                                    context, exception_state);
  if (!has_property) {
    SetTypeError(context.ToString(property_name, "Missing required property"),
                 exception_state);
    return false;
  }
  return ok;
}

bool GetUint8Array(const Dictionary& raw,
                   const char* property_name,
                   WebVector<uint8_t>& bytes,
                   const ErrorContext& context,
                   ExceptionState& exception_state) {
  v8::Local<v8::Value> v8_value;
  if (!raw.Get(property_name, v8_value) || !v8_value->IsUint8Array()) {
    SetTypeError(context.ToString(property_name, "Missing or not a Uint8Array"),
                 exception_state);
    return false;
  }

  MaybeShared<DOMUint8Array> array =
      NativeValueTraits<MaybeShared<DOMUint8Array>>::NativeValue(
          raw.GetIsolate(), v8_value, exception_state);
  if (exception_state.HadException()) {
    return false;
  }
  bytes = CopyBytes(array.Get());
  return true;
}

// Defined by the WebCrypto spec as:
//
//     typedef Uint8Array BigInteger;
bool GetBigInteger(const Dictionary& raw,
                   const char* property_name,
                   WebVector<uint8_t>& bytes,
                   const ErrorContext& context,
                   ExceptionState& exception_state) {
  if (!GetUint8Array(raw, property_name, bytes, context, exception_state))
    return false;

  if (bytes.empty()) {
    // Empty BigIntegers represent 0 according to the spec
    bytes = WebVector<uint8_t>(static_cast<size_t>(1u));
    DCHECK_EQ(0u, bytes[0]);
  }

  return true;
}

// Gets an integer according to WebIDL's [EnforceRange].
bool GetOptionalInteger(const Dictionary& raw,
                        const char* property_name,
                        bool& has_property,
                        double& value,
                        double min_value,
                        double max_value,
                        const ErrorContext& context,
                        ExceptionState& exception_state) {
  v8::Local<v8::Value> v8_value;
  if (!raw.Get(property_name, v8_value)) {
    has_property = false;
    return true;
  }

  has_property = true;
  double number;
  bool ok = v8_value->NumberValue(raw.V8Context()).To(&number);

  if (!ok || std::isnan(number)) {
    SetTypeError(context.ToString(property_name, "Is not a number"),
                 exception_state);
    return false;
  }

  number = trunc(number);

  if (std::isinf(number) || number < min_value || number > max_value) {
    SetTypeError(context.ToString(property_name, "Outside of numeric range"),
                 exception_state);
    return false;
  }

  value = number;
  return true;
}

bool GetInteger(const Dictionary& raw,
                const char* property_name,
                double& value,
                double min_value,
                double max_value,
                const ErrorContext& context,
                ExceptionState& exception_state) {
  bool has_property;
  if (!GetOptionalInteger(raw, property_name, has_property, value, min_value,
                          max_value, context, exception_state))
    return false;

  if (!has_property) {
    SetTypeError(context.ToString(property_name, "Missing required property"),
                 exception_state);
    return false;
  }

  return true;
}

bool GetUint32(const Dictionary& raw,
               const char* property_name,
               uint32_t& value,
               const ErrorContext& context,
               ExceptionState& exception_state) {
  double number;
  if (!GetInteger(raw, property_name, number, 0, 0xFFFFFFFF, context,
                  exception_state))
    return false;
  value = number;
  return true;
}

bool GetUint16(const Dictionary& raw,
               const char* property_name,
               uint16_t& value,
               const ErrorContext& context,
               ExceptionState& exception_state) {
  double number;
  if (!GetInteger(raw, property_name, number, 0, 0xFFFF, context,
                  exception_state))
    return false;
  value = number;
  return true;
}

bool GetUint8(const Dictionary& raw,
              const char* property_name,
              uint8_t& value,
              const ErrorContext& context,
              ExceptionState& exception_state) {
  double number;
  if (!GetInteger(raw, property_name, number, 0, 0xFF, context,
                  exception_state))
    return false;
  value = number;
  return true;
}

bool GetOptionalUint32(const Dictionary& raw,
                       const char* property_name,
                       bool& has_value,
                       uint32_t& value,
                       const ErrorContext& context,
                       ExceptionState& exception_state) {
  double number;
  if (!GetOptionalInteger(raw, property_name, has_value, number, 0, 0xFFFFFFFF,
                          context, exception_state))
    return false;
  if (has_value)
    value = number;
  return true;
}

bool GetOptionalUint8(const Dictionary& raw,
                      const char* property_name,
                      bool& has_value,
                      uint8_t& value,
                      const ErrorContext& context,
                      ExceptionState& exception_state) {
  double number;
  if (!GetOptionalInteger(raw, property_name, has_value, number, 0, 0xFF,
                          context, exception_state))
    return false;
  if (has_value)
    value = number;
  return true;
}

V8AlgorithmIdentifier* GetAlgorithmIdentifier(v8::Isolate* isolate,
                                              const Dictionary& raw,
                                              const char* property_name,
                                              const ErrorContext& context,
                                              ExceptionState& exception_state) {
  // FIXME: This is not correct: http://crbug.com/438060
  //   (1) It may retrieve the property twice from the dictionary, whereas it
  //       should be reading the v8 value once to avoid issues with getters.
  //   (2) The value is stringified (whereas the spec says it should be an
  //       instance of DOMString).
  Dictionary dictionary;
  if (raw.Get(property_name, dictionary) && dictionary.IsObject()) {
    return MakeGarbageCollected<V8AlgorithmIdentifier>(
        ScriptValue(isolate, dictionary.V8Value()));
  }

  std::optional<String> algorithm_name =
      raw.Get<IDLString>(property_name, exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }

  if (!algorithm_name.has_value()) {
    SetTypeError(context.ToString(property_name,
                                  "Missing or not an AlgorithmIdentifier"),
                 exception_state);
    return nullptr;
  }

  return MakeGarbageCollected<V8AlgorithmIdentifier>(*algorithm_name);
}

// Defined by the WebCrypto spec as:
//
//    dictionary AesCbcParams : Algorithm {
//      required BufferSource iv;
//    };
bool ParseAesCbcParams(const Dictionary& raw,
                       std::unique_ptr<WebCryptoAlgorithmParams>& params,
                       const ErrorContext& context,
                       ExceptionState& exception_state) {
  WebVector<uint8_t> iv;
  if (!GetBufferSource(raw, "iv", iv, context, exception_state))
    return false;

  params = std::make_unique<WebCryptoAesCbcParams>(std::move(iv));
  return true;
}

// Defined by the WebCrypto spec as:
//
//    dictionary AesKeyGenParams : Algorithm {
//      [EnforceRange] required unsigned short length;
//    };
bool ParseAesKeyGenParams(const Dictionary& raw,
                          std::unique_ptr<WebCryptoAlgorithmParams>& params,
                          const ErrorContext& context,
                          ExceptionState& exception_state) {
  uint16_t length;
  if (!GetUint16(raw, "length", length, context, exception_state))
    return false;

  params = std::make_unique<WebCryptoAesKeyGenParams>(length);
  return true;
}

bool ParseAlgorithmIdentifier(v8::Isolate*,
                              const V8AlgorithmIdentifier&,
                              WebCryptoOperation,
                              WebCryptoAlgorithm&,
                              ErrorContext,
                              ExceptionState&);

bool ParseHash(v8::Isolate* isolate,
               const Dictionary& raw,
               WebCryptoAlgorithm& hash,
               ErrorContext context,
               ExceptionState& exception_state) {
  V8AlgorithmIdentifier* raw_hash =
      GetAlgorithmIdentifier(isolate, raw, "hash", context, exception_state);
  if (!raw_hash) {
    DCHECK(exception_state.HadException());
    return false;
  }

  context.Add("hash");
  return ParseAlgorithmIdentifier(isolate, *raw_hash, kWebCryptoOperationDigest,
                                  hash, context, exception_state);
}

// Defined by the WebCrypto spec as:
//
//    dictionary HmacImportParams : Algorithm {
//      required HashAlgorithmIdentifier hash;
//      [EnforceRange] unsigned long length;
//    };
bool ParseHmacImportParams(v8::Isolate* isolate,
                           const Dictionary& raw,
                           std::unique_ptr<WebCryptoAlgorithmParams>& params,
                           const ErrorContext& context,
                           ExceptionState& exception_state) {
  WebCryptoAlgorithm hash;
  if (!ParseHash(isolate, raw, hash, context, exception_state))
    return false;

  bool has_length;
  uint32_t length = 0;
  if (!GetOptionalUint32(raw, "length", has_length, length, context,
                         exception_state))
    return false;

  params =
      std::make_unique<WebCryptoHmacImportParams>(hash, has_length, length);
  return true;
}

// Defined by the WebCrypto spec as:
//
//    dictionary HmacKeyGenParams : Algorithm {
//      required HashAlgorithmIdentifier hash;
//      [EnforceRange] unsigned long length;
//    };
bool ParseHmacKeyGenParams(v8::Isolate* isolate,
                           const Dictionary& raw,
                           std::unique_ptr<WebCryptoAlgorithmParams>& params,
                           const ErrorContext& context,
                           ExceptionState& exception_state) {
  WebCryptoAlgorithm hash;
  if (!ParseHash(isolate, raw, hash, context, exception_state))
    return false;

  bool has_length;
  uint32_t length = 0;
  if (!GetOptionalUint32(raw, "length", has_length, length, context,
                         exception_state))
    return false;

  params =
      std::make_unique<WebCryptoHmacKeyGenParams>(hash, has_length, length);
  return true;
}

// Defined by the WebCrypto spec as:
//
//    dictionary RsaHashedImportParams : Algorithm {
//      required HashAlgorithmIdentifier hash;
//    };
bool ParseRsaHashedImportParams(
    v8::Isolate* isolate,
    const Dictionary& raw,
    std::unique_ptr<WebCryptoAlgorithmParams>& params,
    const ErrorContext& context,
    ExceptionState& exception_state) {
  WebCryptoAlgorithm hash;
  if (!ParseHash(isolate, raw, hash, context, exception_state))
    return false;

  params = std::make_unique<WebCryptoRsaHashedImportParams>(hash);
  return true;
}

// Defined by the WebCrypto spec as:
//
//    dictionary RsaKeyGenParams : Algorithm {
//      [EnforceRange] required unsigned long modulusLength;
//      required BigInteger publicExponent;
//    };
//
//    dictionary RsaHashedKeyGenParams : RsaKeyGenParams {
//      required HashAlgorithmIdentifier hash;
//    };
bool ParseRsaHashedKeyGenParams(
    v8::Isolate* isolate,
    const Dictionary& raw,
    std::unique_ptr<WebCryptoAlgorithmParams>& params,
    const ErrorContext& context,
    ExceptionState& exception_state) {
  uint32_t modulus_length;
  if (!GetUint32(raw, "modulusLength", modulus_length, context,
                 exception_state))
    return false;

  WebVector<uint8_t> public_exponent;
  if (!GetBigInteger(raw, "publicExponent", public_exponent, context,
                     exception_state))
    return false;

  WebCryptoAlgorithm hash;
  if (!ParseHash(isolate, raw, hash, context, exception_state))
    return false;

  params = std::make_unique<WebCryptoRsaHashedKeyGenParams>(
      hash, modulus_length, std::move(public_exponent));
  return true;
}

// Defined by the WebCrypto spec as:
//
//    dictionary AesCtrParams : Algorithm {
//      required BufferSource counter;
//      [EnforceRange] required octet length;
//    };
bool ParseAesCtrParams(const Dictionary& raw,
                       std::unique_ptr<WebCryptoAlgorithmParams>& params,
                       const ErrorContext& context,
                       ExceptionState& exception_state) {
  WebVector<uint8_t> counter;
  if (!GetBufferSource(raw, "counter", counter, context, exception_state))
    return false;

  uint8_t length;
  if (!GetUint8(raw, "length", length, context, exception_state))
    return false;

  params = std::make_unique<WebCryptoAesCtrParams>(length, std::move(counter));
  return true;
}

// Defined by the WebCrypto spec as:
//
//     dictionary AesGcmParams : Algorithm {
//       required BufferSource iv;
//       BufferSource additionalData;
//       [EnforceRange] octet tagLength;
//     }
bool ParseAesGcmParams(const Dictionary& raw,
                       std::unique_ptr<WebCryptoAlgorithmParams>& params,
                       const ErrorContext& context,
                       ExceptionState& exception_state) {
  WebVector<uint8_t> iv;
  if (!GetBufferSource(raw, "iv", iv, context, exception_state))
    return false;

  bool has_additional_data;
  WebVector<uint8_t> additional_data;
  if (!GetOptionalBufferSource(raw, "additionalData", has_additional_data,
                               additional_data, context, exception_state))
    return false;

  uint8_t tag_length = 0;
  bool has_tag_length;
  if (!GetOptionalUint8(raw, "tagLength", has_tag_length, tag_length, context,
                        exception_state))
    return false;

  params = std::make_unique<WebCryptoAesGcmParams>(
      std::move(iv), has_additional_data, std::move(additional_data),
      has_tag_length, tag_length);
  return true;
}

// Defined by the WebCrypto spec as:
//
//     dictionary RsaOaepParams : Algorithm {
//       BufferSource label;
//     };
bool ParseRsaOaepParams(const Dictionary& raw,
                        std::unique_ptr<WebCryptoAlgorithmParams>& params,
                        const ErrorContext& context,
                        ExceptionState& exception_state) {
  bool has_label;
  WebVector<uint8_t> label;
  if (!GetOptionalBufferSource(raw, "label", has_label, label, context,
                               exception_state))
    return false;

  params =
      std::make_unique<WebCryptoRsaOaepParams>(has_label, std::move(label));
  return true;
}

// Defined by the WebCrypto spec as:
//
//     dictionary RsaPssParams : Algorithm {
//       [EnforceRange] required unsigned long saltLength;
//     };
bool ParseRsaPssParams(const Dictionary& raw,
                       std::unique_ptr<WebCryptoAlgorithmParams>& params,
                       const ErrorContext& context,
                       ExceptionState& exception_state) {
  uint32_t salt_length_bytes;
  if (!GetUint32(raw, "saltLength", salt_length_bytes, context,
                 exception_state))
    return false;

  params = std::make_unique<WebCryptoRsaPssParams>(salt_length_bytes);
  return true;
}

// Defined by the WebCrypto spec as:
//
//     dictionary EcdsaParams : Algorithm {
//       required HashAlgorithmIdentifier hash;
//     };
bool ParseEcdsaParams(v8::Isolate* isolate,
                      const Dictionary& raw,
                      std::unique_ptr<WebCryptoAlgorithmParams>& params,
                      const ErrorContext& context,
                      ExceptionState& exception_state) {
  WebCryptoAlgorithm hash;
  if (!ParseHash(isolate, raw, hash, context, exception_state))
    return false;

  params = std::make_unique<WebCryptoEcdsaParams>(hash);
  return true;
}

struct CurveNameMapping {
  const char* const name;
  WebCryptoNamedCurve value;
};

const CurveNameMapping kCurveNameMappings[] = {
    {"P-256", kWebCryptoNamedCurveP256},
    {"P-384", kWebCryptoNamedCurveP384},
    {"P-521", kWebCryptoNamedCurveP521}};

// Reminder to update curveNameMappings when adding a new curve.
static_assert(kWebCryptoNamedCurveLast + 1 == std::size(kCurveNameMappings),
              "curveNameMappings needs to be updated");

bool ParseNamedCurve(const Dictionary& raw,
                     WebCryptoNamedCurve& named_curve,
                     ErrorContext context,
                     ExceptionState& exception_state) {
  std::optional<String> named_curve_string =
      raw.Get<IDLString>("namedCurve", exception_state);
  if (exception_state.HadException()) {
    return false;
  }

  if (!named_curve_string.has_value()) {
    SetTypeError(context.ToString("namedCurve", "Missing or not a string"),
                 exception_state);
    return false;
  }

  for (const auto& curve_name_mapping : kCurveNameMappings) {
    if (curve_name_mapping.name == *named_curve_string) {
      named_curve = curve_name_mapping.value;
      return true;
    }
  }

  SetNotSupportedError(context.ToString("Unrecognized namedCurve"),
                       exception_state);
  return false;
}

// Defined by the WebCrypto spec as:
//
//     dictionary EcKeyGenParams : Algorithm {
//       required NamedCurve namedCurve;
//     };
bool ParseEcKeyGenParams(const Dictionary& raw,
                         std::unique_ptr<WebCryptoAlgorithmParams>& params,
                         const ErrorContext& context,
                         ExceptionState& exception_state) {
  WebCryptoNamedCurve named_curve;
  if (!ParseNamedCurve(raw, named_curve, context, exception_state))
    return false;

  params = std::make_unique<WebCryptoEcKeyGenParams>(named_curve);
  return true;
}

// Defined by the WebCrypto spec as:
//
//     dictionary EcKeyImportParams : Algorithm {
//       required NamedCurve namedCurve;
//     };
bool ParseEcKeyImportParams(const Dictionary& raw,
                            std::unique_ptr<WebCryptoAlgorithmParams>& params,
                            const ErrorContext& context,
                            ExceptionState& exception_state) {
  WebCryptoNamedCurve named_curve;
  if (!ParseNamedCurve(raw, named_curve, context, exception_state))
    return false;

  params = std::make_unique<WebCryptoEcKeyImportParams>(named_curve);
  return true;
}

bool GetPeerPublicKey(const Dictionary& raw,
                      const ErrorContext& context,
                      WebCryptoKey* peer_public_key,
                      ExceptionState& exception_state) {
  v8::Local<v8::Value> v8_value;
  if (!raw.Get("public", v8_value)) {
    SetTypeError(context.ToString("public", "Missing required property"),
                 exception_state);
    return false;
  }

  CryptoKey* crypto_key = V8CryptoKey::ToWrappable(raw.GetIsolate(), v8_value);
  if (!crypto_key) {
    SetTypeError(context.ToString("public", "Must be a CryptoKey"),
                 exception_state);
    return false;
  }

  *peer_public_key = crypto_key->Key();
  return true;
}

// Defined by the WebCrypto spec as:
//
//     dictionary EcdhKeyDeriveParams : Algorithm {
//       required CryptoKey public;
//     };
bool ParseEcdhKeyDeriveParams(const Dictionary& raw,
                              std::unique_ptr<WebCryptoAlgorithmParams>& params,
                              const ErrorContext& context,
                              ExceptionState& exception_state) {
  WebCryptoKey peer_public_key;
  if (!GetPeerPublicKey(raw, context, &peer_public_key, exception_state))
    return false;

  DCHECK(!peer_public_key.IsNull());
  params = std::make_unique<WebCryptoEcdhKeyDeriveParams>(peer_public_key);
  return true;
}

// Defined by the WebCrypto spec as:
//
//     dictionary Pbkdf2Params : Algorithm {
//       required BufferSource salt;
//       [EnforceRange] required unsigned long iterations;
//       required HashAlgorithmIdentifier hash;
//     };
bool ParsePbkdf2Params(v8::Isolate* isolate,
                       const Dictionary& raw,
                       std::unique_ptr<WebCryptoAlgorithmParams>& params,
                       const ErrorContext& context,
                       ExceptionState& exception_state) {
  WebVector<uint8_t> salt;
  if (!GetBufferSource(raw, "salt", salt, context, exception_state))
    return false;

  uint32_t iterations;
  if (!GetUint32(raw, "iterations", iterations, context, exception_state))
    return false;

  WebCryptoAlgorithm hash;
  if (!ParseHash(isolate, raw, hash, context, exception_state))
    return false;
  params = std::make_unique<WebCryptoPbkdf2Params>(hash, std::move(salt),
                                                   iterations);
  return true;
}

// Defined by the WebCrypto spec as:
//
//    dictionary AesDerivedKeyParams : Algorithm {
//      [EnforceRange] required unsigned short length;
//    };
bool ParseAesDerivedKeyParams(const Dictionary& raw,
                              std::unique_ptr<WebCryptoAlgorithmParams>& params,
                              const ErrorContext& context,
                              ExceptionState& exception_state) {
  uint16_t length;
  if (!GetUint16(raw, "length", length, context, exception_state))
    return false;

  params = std::make_unique<WebCry
"""


```
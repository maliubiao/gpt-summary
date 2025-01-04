Response:
Let's break down the thought process for analyzing the `base64.cc` file.

1. **Understand the Core Functionality:** The filename `base64.cc` immediately suggests its primary purpose: handling Base64 encoding and decoding. The `#include "third_party/blink/renderer/platform/wtf/text/base64.h"` confirms this, indicating the presence of a corresponding header file defining the interface.

2. **Examine the Copyright and License:** The header comments provide context about the file's history, authors, and licensing (LGPL). This isn't directly related to functionality but provides important legal information.

3. **Identify Key Dependencies:** The `#include` statements reveal the file's dependencies:
    * `<limits.h>`: Standard C library for integer limits (likely for `MODP_B64_MAX_INPUT_LEN`).
    * `third_party/blink/renderer/platform/wtf/text/string_buffer.h`:  Indicates use of Blink's string buffer for efficient string manipulation.
    * `third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h`:  Suggests handling UTF-8 encoded strings, likely for optimized processing of Base64 input.
    * `third_party/modp_b64/modp_b64.h`:  Crucially, this reveals the use of an external library (`modp_b64`) for the core Base64 encoding/decoding logic. This is a *very* important observation. It means this file is primarily a *wrapper* around the `modp_b64` library, providing Blink-specific integration.

4. **Analyze Namespaces and Helper Functions:** The code is within the `WTF` namespace, and further organized with an anonymous namespace. The anonymous namespace often contains internal helper functions. The `IsAsciiWhitespace` function stands out as a utility for identifying whitespace characters. The `GetModpPolicy` function maps Blink's `Base64DecodePolicy` enum to the `modp_b64` policy enum. The `Base64DecodeRaw` function is clearly the low-level decoding function directly using `modp_b64_decode`.

5. **Focus on Publicly Exposed Functions:**  The functions outside the anonymous namespace are the public interface:
    * `Base64Encode`: Takes a `base::span<const uint8_t>` (a memory region) and returns a `String`. There's also an overload that writes to a provided `Vector<char>`. This is standard Base64 encoding.
    * `Base64Decode`: Takes a `StringView` (efficient string representation), a `Vector<char>` for output, and a `Base64DecodePolicy`. This handles Base64 decoding, with options for handling whitespace and padding.
    * `Base64UnpaddedURLDecode`: Specifically handles URL-safe Base64 decoding, checking for standard Base64 characters and using `NormalizeToBase64`.
    * `Base64URLEncode`: Encodes to URL-safe Base64 by replacing `+` and `/`.
    * `NormalizeToBase64`: Converts URL-safe Base64 back to standard Base64.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Now, think about where Base64 is used in web development:
    * **Data URIs:**  Immediately comes to mind. Images, fonts, and other resources can be embedded directly in HTML/CSS using Base64 encoding.
    * **`atob()` and `btoa()` in JavaScript:** These functions are the standard JavaScript APIs for Base64 encoding/decoding. Blink's implementation would need to align with these.
    * **`Authorization` headers:**  HTTP authentication often uses Base64 encoding for credentials.
    * **WebSockets:** Base64 can be used for encoding binary data within WebSocket messages.
    * **CSS `url()` function with data URIs:**  A specific case of data URIs.

7. **Construct Examples and Scenarios:** For each connection to web technologies, create illustrative examples:
    * *Data URI:*  Show an `<img src="data:image/png;base64,...">` example.
    * *JavaScript:*  Demonstrate `btoa()` and `atob()`.
    * *CSS:* Show a `background-image: url("data:image/png;base64,...");` example.

8. **Consider Logic and Assumptions:**
    * **Encoding:**  Input is binary data, output is a Base64 string.
    * **Decoding:** Input is a Base64 string, output is binary data.
    * **Whitespace Handling:** The `kForgiving` policy explicitly mentions whitespace removal.
    * **Padding:** The `kNoPaddingValidation` policy allows decoding without strict padding.
    * **URL-Safe Encoding:**  The character replacements are crucial for URL compatibility.

9. **Identify Potential Usage Errors:**  Think about common mistakes developers might make:
    * Incorrectly formatted Base64 strings (missing padding, invalid characters).
    * Trying to decode non-Base64 data.
    * Not understanding the different decoding policies (especially regarding whitespace and padding).
    * Confusing standard Base64 with URL-safe Base64.

10. **Structure the Answer:** Organize the findings into clear sections: functionality, relationship to web technologies, logical reasoning (with input/output examples), and common usage errors. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the low-level details of the `modp_b64` library. Realizing that this file is a *wrapper* shifts the focus to *how* Blink uses this library and exposes Base64 functionality to its higher levels.
* I might have missed some connections to web technologies initially and needed to brainstorm further. Thinking about common web development tasks involving data encoding is key.
* I need to ensure my examples are clear and easy to understand, illustrating the points effectively.
* Double-checking the code comments and function names helps confirm my understanding of the intended behavior. For example, the comments about forgiving Base64 decoding are important.

By following these steps, combining code analysis with knowledge of web technologies and potential pitfalls, a comprehensive and accurate explanation of the `base64.cc` file can be constructed.
这个文件 `blink/renderer/platform/wtf/text/base64.cc` 是 Chromium Blink 渲染引擎中负责 **Base64 编码和解码** 功能的源代码文件。它提供了一组函数，用于将二进制数据编码为 Base64 字符串，以及将 Base64 字符串解码回原始的二进制数据。

以下是它的主要功能：

1. **Base64 编码 (Encoding):**
   - `Base64Encode(base::span<const uint8_t> data)`:  接收一个字节数组 (`base::span<const uint8_t>`) 作为输入，并返回其对应的 Base64 编码的 `String` 对象。
   - `Base64Encode(base::span<const uint8_t> data, Vector<char>& out)`:  与上述函数类似，但将编码结果写入到提供的 `Vector<char>` 容器中。

2. **Base64 解码 (Decoding):**
   - `Base64Decode(const StringView& in, Vector<char>& out, Base64DecodePolicy policy)`:  接收一个 Base64 编码的字符串 (`StringView`)，一个用于存储解码结果的 `Vector<char>`，以及一个 `Base64DecodePolicy` 枚举值。`Base64DecodePolicy` 允许指定解码的策略，例如是否容忍空白字符或者是否需要校验填充字符。
   - `Base64UnpaddedURLDecode(const String& in, Vector<char>& out)`:  专门用于解码 URL 安全的 Base64 编码，这种编码中没有填充字符 (`=`)，并且将 `+` 替换为 `-`，`/` 替换为 `_`。此函数在解码前会检查输入字符串是否包含标准的 Base64 字符 `+`, `/`, `=`。

3. **URL 安全的 Base64 编码和规范化:**
   - `Base64URLEncode(base::span<const uint8_t> data)`:  将二进制数据编码为 URL 安全的 Base64 字符串，将标准 Base64 编码中的 `+` 替换为 `-`，`/` 替换为 `_`。
   - `NormalizeToBase64(const String& encoding)`:  将 URL 安全的 Base64 字符串转换回标准的 Base64 字符串，将 `-` 替换为 `+`，`_` 替换为 `/`。

**与 JavaScript, HTML, CSS 的功能关系和举例说明:**

Base64 编码在 Web 开发中被广泛使用，与 JavaScript, HTML, CSS 的功能都有密切关系：

**1. JavaScript:**

- **`atob()` 和 `btoa()` 函数:** JavaScript 提供了全局函数 `atob()` 用于解码 Base64 字符串，`btoa()` 用于编码字符串为 Base64。Blink 的 `base64.cc` 文件中的功能为这些 JavaScript API 提供了底层的实现支持。
  - **假设输入与输出 (JavaScript 编码):**
    - **输入 (JavaScript):** `btoa("Hello")`
    - **输出 (Blink `Base64Encode` 可能的中间过程):** 将 "Hello" 的 UTF-8 编码（例如：`[72, 101, 108, 108, 111]`）传递给 `Base64Encode` 函数。
    - **最终输出 (JavaScript):** "SGVsbG8="
  - **假设输入与输出 (JavaScript 解码):**
    - **输入 (JavaScript):** `atob("SGVsbG8=") `
    - **输出 (Blink `Base64Decode` 可能的中间过程):** 将 "SGVsbG8=" 传递给 `Base64Decode` 函数。
    - **最终输出 (JavaScript):** "Hello"

**2. HTML:**

- **Data URI Scheme:**  HTML 中可以使用 data URI 来嵌入资源（例如图片、字体）的内容。Data URI 使用 Base64 编码来表示资源的数据。
  - **举例说明:**
    ```html
    <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==" alt="Red dot" />
    ```
    在这个例子中，`iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==` 就是一个 Base64 编码的 PNG 图片。Blink 需要使用其 Base64 解码功能来解析这个 data URI 并渲染图片。
  - **假设输入与输出 (HTML Data URI 解码):**
    - **输入 (HTML 解析器):** 遇到 `src` 属性中的 data URI 字符串，提取 Base64 编码部分。
    - **输出 (Blink `Base64Decode`):** 将 Base64 字符串传递给 `Base64Decode` 函数，得到原始的 PNG 图片二进制数据。

**3. CSS:**

- **`url()` 函数和 Data URI:**  CSS 中也可以使用 `url()` 函数结合 data URI 来嵌入资源，例如背景图片或字体。
  - **举例说明:**
    ```css
    .my-element {
      background-image: url("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJjdXJyZW50Q29sb3IiIGNsYXNzPSJiaSBiaS1hcnJvd3ktbG9vcCI+CiAgPHBhdGggZD0iTTEuMzM3IDYuMjQ3YTYuNTg2IDYuNTg2IDAgMTAuODIxIDguNzU3bDEuODQzLTEuODQzYTQuNTg2IDQuNTg2IDAgMTAuNjQtNi4wODVsLjczNi43MzZhLjUwMS41MDEgMCAwMS0uNjUuNjQxbC0uOTQ3LS45NDdhLjUwMS41MDEgMCAwMS0uMDUyLS43ODlsLjU2LS41NmEyLjU4NiAyLjU4NiAwIDAwMy40ODYgMy40ODVsLjczNi43MzYtLjgzMy44MzNhLjUwMS41MDEgMCAwMS0uMzA0LjE1MmgtMy41YTEuNzUgMS43NSAwIDAxLTEuNzUtMS43NVY1aDEuNzVhLjUxLjUxIDAgMDEwLjUxLjUxdi41aC0xLjdhLjUxLjUxIDAgMDEwLS41MS0uNTF2LS41eiIvPgogIDxwYXRoIGQ9Ik0yMC42NjMgMTcuNzUzdWE2LjU4NiA2LjU4NiAwIDAwLTkuNzY1LTkuNzY1bDEuODQzIDEuODQzYTQuNTg2IDQuNTg2IDAgMDA2LjA3OCA2LjA3OGwuNzM3LS43MzZhLjUwMS41MDEgMCAwMS42NS0uNjQxbC45NDYuOTQ3YS41MDEuNTAxIDAgMDEuMDUyLjc4OWwtLjU2LjU2YS0yLjU4Ni0yLjU4NiAwIDAwLTMuNDg2LTMuNDg1bC0uNzM3LS43MzcuODM0LS44MzZhLjUwMS41MDEgMCAwMS4zMDQtLjE1MmEzLjUwMiAzLjUwMiAwIDAxMy41IDMuNXYxYTEuNzUgMS43NSAwIDAxLTEuNzUgMS43NWgtMS43NXYuNWExLjUxLjUxIDAgMDEwLjUxLjUxdi41aDEuNzVhLjUxLjUxIDAgMDEwLS41MS0uNTF2LS41eiIvPgogIDxwYXRoIGQ9Ik0xMi41IDEwLjV2Myg4LjVzLTUuNDc4IDAgLTYuNSAxLjVjLTEuMTA1IDEuMzM3LTEuNSAzLjAzMi0xLjUgNS41YzAgMS41OTQuNSAxLjYgMS41IDIuNWgxbTcuNS03LjVhLjUwMS41MDEgMCAwMS41LjV2NWEuNTAxLjUwMSAwIDAxLS41LjVoLTNhLjUwMS41MDEgMCAwMS0uNS0uNVY4LjVhLjUwMS41MDEgMCAwMS41LS41aDMiLz4KPC9zdmc+
    ```
    这里的 `PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJjdXJyZW50Q29sb3IiIGNsYXNzPSJiaSBiaS1hcnJvd3ktbG9vcCI+CiAgPHBhdGggZD0iTTEuMzM3IDYuMjQ3YTYuNTg2IDYuNTg2IDAgMTAuODIxIDguNzU3bDEuODQzLTEuODQzYTQuNTg2IDQuNTg2IDAgMTAuNjQtNi4wODVsLjczNi43MzZhLjUwMS41MDEgMCAwMS0uNjUuNjQxbC0uOTQ3LS45NDdhLjUwMS41MDEgMCAwMS0uMDUyLS43ODlsLjU2LS41NmEyLjU4NiAyLjU4NiAwIDAwMy40ODYgMy40ODVsLjczNi43MzYtLjgzMy44MzNhLjUwMS41MDEgMCAwMS0uMzA0LjE1MmgtMy41YTEuNzUgMS43NSAwIDAxLTEuNzUtMS43NVY1aDEuNzVhLjUxLjUxIDAgMDEwLjUxLjUxdi41aC0xLjdhLjUxLjUxIDAgMDEwLS41MS0uNTF2LS41eiIvPgogIDxwYXRoIGQ9Ik0yMC42NjMgMTcuNzUzdWE2LjU4NiA2LjU4NiAwIDAwLTkuNzY1LTkuNzY1bDEuODQzIDEuODQzYTQuNTg2IDQuNTg2IDAgMDA2LjA3OCA2LjA3OGwuNzM3LS43MzZhLjUwMS41MDEgMCAwMS42NS0uNjQxbC45NDYuOTQ3YS41MDEuNTAxIDAgMDEuMDUyLjc4OWwtLjU2LjU2YS0yLjU4Ni0yLjU4NiAwIDAwLTMuNDg2LTMuNDg1bC0uNzM3LS43MzcuODM0LS44MzZhLjUwMS41MDEgMCAwMS4zMDQtLjE1MmEzLjUwMiAzLjUwMiAwIDAxMy41IDMuNXYxYTEuNzUgMS43NSAwIDAxLTEuNzUgMS43NWgtMS43NXYuNWExLjUxLjUxIDAgMDEwLjUxLjUxdi41aDEuNzVhLjUxLjUxIDAgMDEwLS41MS0uNTF2LS41eiIvPgogIDxwYXRoIGQ9Ik0xMi41IDEwLjV2Myg4LjVzLTUuNDc4IDAgLTYuNSAxLjVjLTEuMTA1IDEuMzM3LTEuNSAzLjAzMi0xLjUgNS41YzAgMS41OTQuNSAxLjYgMS41IDIuNWgxbTcuNS03LjVhLjUwMS41MDEgMCAwMS41LjV2NWEuNTAxLjUwMSAwIDAxLS41LjVoLTNhLjUwMS41MDEgMCAwMS0uNS0uNVY4LjVhLjUwMS41MDEgMCAwMS41LS41aDMiLz4KPC9zdmc+`  是 SVG 图片的 Base64 编码。Blink 同样需要解码才能显示。
  - **假设输入与输出 (CSS Data URI 解码):** 流程与 HTML Data URI 解码类似。

**逻辑推理的假设输入与输出:**

- **假设输入 (Base64 编码):**
  - 输入数据 (字节数组): `[0x4d, 0x61, 0x6e]` (对应 ASCII 字符串 "Man")
  - 调用 `Base64Encode` 函数
  - **输出 (Base64 字符串):** "TWFu"

- **假设输入 (Base64 解码，无特殊策略):**
  - 输入字符串: "TWFu"
  - 调用 `Base64Decode` 函数
  - **输出 (字节数组):** `[0x4d, 0x61, 0x6e]`

- **假设输入 (Base64 解码，`kForgiving` 策略，带空格):**
  - 输入字符串: "  T W Fu  "
  - 调用 `Base64Decode` 函数，`policy` 设置为 `Base64DecodePolicy::kForgiving`
  - **输出 (字节数组):** `[0x4d, 0x61, 0x6e]` (因为 `kForgiving` 策略会移除空白字符)

- **假设输入 (URL 安全 Base64 编码):**
  - 输入数据 (字节数组):  假设编码结果为 URL 安全的 "YS1i" (对应标准 Base64 的 "YS+i")
  - 调用 `Base64URLEncode` 函数
  - **输出 (URL 安全 Base64 字符串):** "YS1i"

- **假设输入 (URL 安全 Base64 解码):**
  - 输入字符串: "YS1i"
  - 调用 `Base64UnpaddedURLDecode` 函数
  - **输出 (字节数组):**  解码得到原始数据

**涉及用户或者编程常见的使用错误举例说明:**

1. **尝试解码非 Base64 字符串:**
   - **错误示例:**  将一个普通的字符串（例如 "This is not base64"）传递给 `Base64Decode` 函数。
   - **结果:** 解码会失败，`Base64Decode` 函数会返回 `false`。
   - **用户错误:**  没有正确判断或验证输入字符串是否为合法的 Base64 编码。

2. **解码时策略不当:**
   - **错误示例 (需要 `kForgiving` 但未使用):** 尝试解码一个包含空格的 Base64 字符串，但 `policy` 没有设置为 `Base64DecodePolicy::kForgiving`。
   - **结果:** 解码会失败，因为默认策略可能不允许空白字符。
   - **用户错误:**  对 Base64 字符串的格式理解不足，或者没有根据实际情况选择合适的解码策略。

3. **混淆标准 Base64 和 URL 安全 Base64:**
   - **错误示例 (URL 安全编码用标准解码):**  尝试使用 `Base64Decode` 解码一个 URL 安全的 Base64 字符串（例如 "YS1i"）。
   - **结果:** 解码可能会失败，或者得到错误的结果，因为 `+` 和 `/` 被替换了。
   - **用户错误:**  不了解 URL 安全 Base64 的特点，没有使用 `Base64UnpaddedURLDecode` 或先进行规范化。

4. **编码或解码二进制数据时类型不匹配:**
   - **错误示例:**  在 JavaScript 中使用 `btoa()` 编码包含非 ASCII 字符的字符串，然后尝试在 Blink 中使用默认的 Base64 解码。
   - **结果:**  可能会导致编码或解码错误，因为 `btoa()` 针对的是 Latin-1 编码的字符串。
   - **用户错误:**  对字符编码和 Base64 的原理理解不足，没有正确处理不同编码格式的数据。

5. **忘记处理解码失败的情况:**
   - **错误示例:**  直接使用 `Base64Decode` 的结果，而没有检查其返回值是否为 `true`。
   - **结果:**  如果解码失败，可能会使用到未初始化的或错误的数据。
   - **用户错误:**  没有进行充分的错误处理。

总而言之，`blink/renderer/platform/wtf/text/base64.cc` 文件是 Blink 引擎中核心的 Base64 处理模块，为 Web 平台上的各种需要 Base64 编码和解码的场景提供了基础支持。理解其功能和使用方式对于进行 Web 开发，尤其是涉及到数据传输、资源嵌入等方面至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/wtf/text/base64.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
   Copyright (C) 2000-2001 Dawit Alemayehu <adawit@kde.org>
   Copyright (C) 2006 Alexey Proskuryakov <ap@webkit.org>
   Copyright (C) 2007, 2008 Apple Inc. All rights reserved.
   Copyright (C) 2010 Patrick Gansterer <paroga@paroga.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License (LGPL)
   version 2 as published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
   USA.

   This code is based on the java implementation in HTTPClient
   package by Ronald Tschalaer Copyright (C) 1996-1999.
*/

#include "third_party/blink/renderer/platform/wtf/text/base64.h"

#include <limits.h>

#include "third_party/blink/renderer/platform/wtf/text/string_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/modp_b64/modp_b64.h"

namespace WTF {

namespace {

// https://infra.spec.whatwg.org/#ascii-whitespace
// Matches the definition of IsHTMLSpace in html_parser_idioms.h.
template <typename CharType>
bool IsAsciiWhitespace(CharType character) {
  return character <= ' ' &&
         (character == ' ' || character == '\n' || character == '\t' ||
          character == '\r' || character == '\f');
}

ModpDecodePolicy GetModpPolicy(Base64DecodePolicy policy) {
  switch (policy) {
    case Base64DecodePolicy::kForgiving:
      return ModpDecodePolicy::kForgiving;
    case Base64DecodePolicy::kNoPaddingValidation:
      return ModpDecodePolicy::kNoPaddingValidation;
  }
}

// Invokes modp_b64 without stripping whitespace.
bool Base64DecodeRaw(const StringView& in,
                     Vector<char>& out,
                     Base64DecodePolicy policy) {
  // Using StringUTF8Adaptor means we avoid allocations if the string is 8-bit
  // ascii, which is likely given that base64 is required to be ascii.
  StringUTF8Adaptor adaptor(in);
  out.resize(modp_b64_decode_len(adaptor.size()));
  size_t output_size = modp_b64_decode(out.data(), adaptor.data(), adaptor.size(),
                                       GetModpPolicy(policy));
  if (output_size == MODP_B64_ERROR)
    return false;

  out.resize(output_size);
  return true;
}

}  // namespace

String Base64Encode(base::span<const uint8_t> data) {
  size_t encode_len = modp_b64_encode_data_len(data.size());
  CHECK_LE(data.size(), MODP_B64_MAX_INPUT_LEN);
  StringBuffer<LChar> result(encode_len);
  if (encode_len == 0)
    return String();
  const size_t output_size = modp_b64_encode_data(
      reinterpret_cast<char*>(result.Characters()),
      reinterpret_cast<const char*>(data.data()), data.size());
  DCHECK_EQ(output_size, encode_len);
  return result.Release();
}

void Base64Encode(base::span<const uint8_t> data, Vector<char>& out) {
  size_t encode_len = modp_b64_encode_data_len(data.size());
  CHECK_LE(data.size(), MODP_B64_MAX_INPUT_LEN);
  if (encode_len == 0) {
    out.clear();
    return;
  }
  out.resize(encode_len);
  const size_t output_size = modp_b64_encode_data(
      out.data(), reinterpret_cast<const char*>(data.data()), data.size());
  DCHECK_EQ(output_size, encode_len);
}

bool Base64Decode(const StringView& in,
                  Vector<char>& out,
                  Base64DecodePolicy policy) {
  switch (policy) {
    case Base64DecodePolicy::kForgiving: {
      // https://infra.spec.whatwg.org/#forgiving-base64-decode
      // Step 1 is to remove all whitespace. However, checking for whitespace
      // slows down the "happy" path. Since any whitespace will fail normal
      // decoding from modp_b64_decode, just try again if we detect a failure.
      // This shouldn't be much slower for whitespace inputs.
      //
      // TODO(csharrison): Most callers use String inputs so ToString() should
      // be fast. Still, we should add a RemoveCharacters method to StringView
      // to avoid a double allocation for non-String-backed StringViews.
      return Base64DecodeRaw(in, out, policy) ||
             Base64DecodeRaw(in.ToString().RemoveCharacters(&IsAsciiWhitespace),
                             out, policy);
    }
    case Base64DecodePolicy::kNoPaddingValidation: {
      return Base64DecodeRaw(in, out, policy);
    }
  }
}

bool Base64UnpaddedURLDecode(const String& in, Vector<char>& out) {
  if (in.Contains('+') || in.Contains('/') || in.Contains('='))
    return false;

  return Base64Decode(NormalizeToBase64(in), out);
}

String Base64URLEncode(base::span<const uint8_t> data) {
  return Base64Encode(data).Replace('+', '-').Replace('/', '_');
}

String NormalizeToBase64(const String& encoding) {
  return String(encoding).Replace('-', '+').Replace('_', '/');
}

}  // namespace WTF

"""

```
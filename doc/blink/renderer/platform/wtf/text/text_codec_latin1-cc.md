Response:
Let's break down the thought process for analyzing this code and answering the prompt.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `text_codec_latin1.cc` within the Chromium Blink engine, particularly its relation to web technologies (JavaScript, HTML, CSS), and identify potential usage errors.

**2. Initial Code Scan and Keyword Recognition:**

My first step is to quickly scan the code for recognizable keywords and patterns. I see:

* **Copyright and Licensing:**  Standard boilerplate, noting the origin.
* **Includes:**  `text_codec_latin1.h`, `<unicode/utf16.h>`, `string_buffer.h`, `text_codec_ascii_fast_path.h`, `wtf_string.h`. These indicate the file deals with text encoding and might interact with Unicode and ASCII. The "wtf" namespace suggests it's part of the Web Template Framework in Blink.
* **`kTable`:** A large constant array of `UChar`. This strongly suggests a lookup table for character mapping.
* **`RegisterEncodingNames` and `RegisterCodecs`:** These functions clearly indicate this code is responsible for registering the Latin-1 encoding with the browser's encoding system.
* **`Decode`:**  A function that takes `uint8_t` (bytes) as input and returns a `String`. This is a clear decoding function.
* **`Encode`:** Functions that take `UChar` or `LChar` (Unicode characters) and return `std::string` (bytes). This is the encoding counterpart.
* **`windows-1252`, `ISO-8859-1`, `US-ASCII`:** These are standard encoding names. The code seems to treat them (for decoding purposes) as synonymous with `windows-1252`.
* **"Fast path for ASCII":**  Optimization is mentioned, specifically for ASCII characters.
* **"UnencodableHandling":** This suggests the code deals with characters that cannot be directly represented in Latin-1.
* **"surrogate pair":**  A concept related to Unicode encoding beyond the Basic Multilingual Plane (BMP).

**3. Deeper Dive into Key Functions:**

Now I examine the core functions in more detail:

* **`kTable` Analysis:** The comments next to the array initialization are crucial. They show the mapping of byte values (0x00-0xFF) to Unicode code points. This is the heart of the Latin-1 (and its Windows-1252 variant) encoding. I notice the slight differences in the 0x80-0x9F range compared to the pure ISO-8859-1.

* **`Decode` Function Logic:**
    * Checks for empty input.
    * Attempts a fast path for ASCII characters. It leverages machine word operations for efficiency if the input is aligned.
    * If a non-ASCII character is encountered, it uses `kTable` for lookup.
    * It handles the case where a Latin-1 byte maps to a Unicode character outside the basic Latin range (requiring a `UChar` instead of `LChar`). This is important for the subtle differences between ISO-8859-1 and Windows-1252.

* **`Encode` Function Logic:**
    * The `EncodeCommon` template handles both `UChar` and `LChar` input.
    * It tries a fast path where all characters are within the ASCII range.
    * If not all ASCII, it calls `EncodeComplexWindowsLatin1`.
    * `EncodeComplexWindowsLatin1` iterates through characters and attempts to find a matching Latin-1 byte in `kTable`. It handles unencodable characters based on the `UnencodableHandling` parameter (e.g., replacing with '?'). It explicitly addresses surrogate pairs.

* **`Register...` Functions:** These are straightforward. They register the Latin-1 encoding and its aliases with the browser's text encoding system.

**4. Connecting to Web Technologies:**

Now I start linking the code's functionality to JavaScript, HTML, and CSS:

* **HTML:** The `<meta charset="iso-8859-1">` or `<meta charset="latin1">` tags directly tell the browser to use this codec for interpreting the HTML document's character encoding. This is a fundamental connection. I consider what happens if the declared encoding doesn't match the actual encoding (potential for garbled text).

* **JavaScript:**  JavaScript strings are generally UTF-16. When JavaScript interacts with external data (like fetching a file or submitting a form) that's encoded in Latin-1, the browser uses this codec to convert between the two encodings. I think about `TextDecoder` and `TextEncoder` APIs in JavaScript.

* **CSS:**  While CSS itself is generally UTF-8, if a CSS file is served with a Latin-1 encoding, this codec would be used to interpret it. This is less common but possible. I think about `@charset` rule in CSS.

**5. Identifying Potential Errors:**

I look for common mistakes developers might make:

* **Incorrect `charset` declaration:**  Declaring a different charset than the actual encoding leads to incorrect rendering.
* **Assuming Latin-1 is always ASCII:**  Forgetting that Latin-1 extends beyond ASCII can lead to issues when dealing with extended characters.
* **Misunderstanding the differences between ISO-8859-1 and Windows-1252:**  While the code treats them the same for *decoding*, subtle differences exist in the 0x80-0x9F range, which could lead to unexpected character renderings if the user assumes strict ISO-8859-1.
* **Not handling unencodable characters:**  When *encoding* to Latin-1, developers need to be aware that some Unicode characters don't have direct Latin-1 equivalents and handle them appropriately.

**6. Structuring the Answer:**

Finally, I organize my findings into a clear and structured answer, covering the requested points:

* **Functionality:**  Clearly state the core purpose (encoding and decoding Latin-1).
* **Relationship to Web Technologies:** Provide concrete examples for HTML, JavaScript, and CSS, explaining *how* the codec is involved.
* **Logic Reasoning (with assumptions):**  Create simple "input/output" scenarios to illustrate the decoding and encoding processes, including the fast path and the handling of extended characters.
* **User/Programming Errors:**  List common mistakes with illustrative examples.

**Self-Correction/Refinement During the Process:**

* Initially, I might focus too much on the low-level details of the code. I need to step back and think about the higher-level purpose and its impact on web technologies.
* I need to be precise about terminology (e.g., distinguishing between ISO-8859-1 and Windows-1252).
* I should ensure the examples are easy to understand and directly relate to the code's functionality.
* I need to make sure I've addressed all parts of the prompt.

By following this thought process, I can systematically analyze the code and generate a comprehensive and accurate answer to the prompt.
好的，让我们来分析一下 `blink/renderer/platform/wtf/text/text_codec_latin1.cc` 这个文件的功能。

**核心功能:**

这个文件实现了 Blink 渲染引擎中用于处理 Latin-1 字符编码的编解码器 (`TextCodecLatin1`)。它的主要功能是将 Latin-1 编码的字节流转换为 UTF-16 编码的字符串 (解码)，以及将 UTF-16 编码的字符串转换为 Latin-1 编码的字节流 (编码)。

**具体功能点:**

1. **解码 (Decoding):**
   - `Decode(base::span<const uint8_t> bytes, FlushBehavior, bool, bool&)` 函数负责将 Latin-1 编码的字节序列解码为 UTF-16 字符串。
   - 它内部使用了查找表 `kTable`，该表将每个 Latin-1 字符（0x00 - 0xFF）映射到对应的 Unicode 代码点。
   - 它针对 ASCII 字符（0x00 - 0x7F）进行了优化，存在一个快速处理路径，因为 ASCII 字符在 Latin-1 和 UTF-16 中的表示是相同的（代码点值相同）。
   - 它能处理标准的 Latin-1 字符集以及 Windows-1252 扩展的字符集（在 0x80-0x9F 范围内有所不同）。

2. **编码 (Encoding):**
   - `Encode(base::span<const UChar> characters, UnencodableHandling handling)` 和 `Encode(base::span<const LChar> characters, UnencodableHandling handling)` 函数负责将 UTF-16 字符串编码为 Latin-1 字节序列。
   - 它会尝试将每个 UTF-16 字符转换为对应的 Latin-1 字节。
   - `UnencodableHandling` 参数决定了如何处理无法在 Latin-1 中表示的字符。常见的处理方式是替换为特定的字符（例如 `?`）或者抛出错误。
   - 它也针对全 ASCII 字符串做了优化，如果所有字符都在 ASCII 范围内，则可以直接进行转换。

3. **编码名称注册:**
   - `RegisterEncodingNames(EncodingNameRegistrar registrar)` 函数用于注册与 Latin-1 相关的各种编码名称别名，例如 "windows-1252", "ISO-8859-1", "latin1", "US-ASCII" 等。这使得 Blink 能够识别并处理这些不同的编码名称。

4. **编解码器注册:**
   - `RegisterCodecs(TextCodecRegistrar registrar)` 函数用于注册 `TextCodecLatin1` 类作为处理特定编码的解码器。它将 "windows-1252", "ISO-8859-1", "US-ASCII" 这些编码名称与 `NewStreamingTextDecoderWindowsLatin1` 函数关联起来，以便在需要解码这些编码的内容时创建 `TextCodecLatin1` 的实例。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`TextCodecLatin1` 在 Web 浏览器中扮演着至关重要的角色，因为它负责处理网页内容的字符编码。

**1. HTML:**

- **功能关系:** 当浏览器加载一个 HTML 页面时，它需要知道这个页面的字符编码是什么，才能正确地解析和显示文本内容。HTML 文档通常会在 `<meta>` 标签中指定字符编码，例如 `<meta charset="iso-8859-1">` 或 `<meta charset="latin1">`。
- **举例说明:**
  ```html
  <!DOCTYPE html>
  <html lang="en">
  <head>
      <meta charset="iso-8859-1">
      <title>Latin-1 Example</title>
  </head>
  <body>
      <p>This page contains Latin-1 characters like éàç.</p>
  </body>
  </html>
  ```
  当浏览器加载这个 HTML 文件时，它会读取 `<meta charset="iso-8859-1">`，然后使用 `TextCodecLatin1` 来解码 HTML 文件中的字节流，将其转换为浏览器可以理解的 Unicode 字符串，从而正确显示 "éàç" 这些 Latin-1 特有的字符。

**2. JavaScript:**

- **功能关系:** JavaScript 字符串在内部使用 UTF-16 编码。当 JavaScript 代码需要处理来自服务器或者用户输入的 Latin-1 编码的文本数据时，浏览器会使用 `TextCodecLatin1` 进行解码。反之，当 JavaScript 需要将字符串数据发送到服务器，并指定使用 Latin-1 编码时，浏览器会使用 `TextCodecLatin1` 进行编码。
- **举例说明:**
  ```javascript
  // 假设从服务器获取的响应是 Latin-1 编码的
  fetch('data.txt')
    .then(response => response.arrayBuffer())
    .then(buffer => {
      const decoder = new TextDecoder('iso-8859-1');
      const text = decoder.decode(buffer);
      console.log(text); // 控制台会正确显示 Latin-1 字符
    });

  // 将 JavaScript 字符串编码为 Latin-1 发送给服务器
  const encoder = new TextEncoder('iso-8859-1');
  const encoded = encoder.encode('你好，这是 Latin-1'); // 注意： Latin-1 无法表示中文
  // ... 将 encoded 数据发送到服务器
  ```
  在 `TextDecoder` 和 `TextEncoder` API 的幕后，如果指定了 'iso-8859-1' 或 'latin1' 编码，Blink 引擎就会使用 `TextCodecLatin1` 来执行实际的编解码操作。

**3. CSS:**

- **功能关系:** CSS 文件本身也是文本文件，也有字符编码的概念。虽然通常推荐使用 UTF-8，但理论上 CSS 文件也可以使用 Latin-1 编码。浏览器在加载 CSS 文件时，会根据 HTTP 头部中的 `Content-Type` 字段或者 CSS 文件开头的 `@charset` 声明来确定字符编码，并使用相应的解码器进行处理。
- **举例说明:**
  假设一个 CSS 文件 `style.css` 使用 Latin-1 编码，并且包含如下内容：
  ```css
  /* @charset "iso-8859-1"; */ /* 可选的字符集声明 */
  body::before {
    content: "© 2023"; /* 版权符号是 Latin-1 字符 */
  }
  ```
  如果浏览器判断该 CSS 文件使用 Latin-1 编码，`TextCodecLatin1` 会被用来解码文件中的字节，确保版权符号 "©" 能正确显示在页面上。

**逻辑推理的假设输入与输出:**

**解码示例:**

假设输入是 Latin-1 编码的字节序列 `[0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0xE9]` (对应 "Hello é")。

- **假设输入:** `base::span<const uint8_t> bytes = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0xE9}`
- **输出:** `String result = "Hello é"` (UTF-16 编码的字符串，其中 'é' 的 Unicode 代码点是 U+00E9)

**编码示例:**

假设输入是 UTF-16 字符串 `"你好"`，并尝试用 Latin-1 编码。由于 "你" 和 "好" 无法在 Latin-1 中表示，处理方式取决于 `UnencodableHandling` 参数。

- **假设输入:** `base::span<const UChar> characters = {'你', '好'}`， `UnencodableHandling handling = kReplace` (替换不可编码字符)
- **输出:** `std::string result = "?? "` (Latin-1 编码的字节序列，假设 '?' 的 Latin-1 编码是 0x3F)

- **假设输入:** `base::span<const UChar> characters = {'H', 'i'}`， `UnencodableHandling handling = kReplace`
- **输出:** `std::string result = "Hi"` (Latin-1 编码的字节序列 `[0x48, 0x69]`)

**涉及用户或者编程常见的使用错误:**

1. **字符编码声明与实际编码不一致:**
   - **错误:** HTML 文件声明 `<meta charset="utf-8">`，但实际文件保存为 Latin-1 编码。
   - **结果:** 浏览器会使用 UTF-8 解码 Latin-1 的字节，导致页面上出现乱码。
   - **例如:**  Latin-1 的 "é" (0xE9) 在 UTF-8 中会被解释为无效的字节序列或错误的字符。

2. **JavaScript 中使用错误的编码器/解码器:**
   - **错误:**  尝试用 `TextDecoder('utf-8')` 解码一个 Latin-1 编码的字节流。
   - **结果:**  解码后的字符串会包含错误的字符。

3. **假设 Latin-1 可以表示所有字符:**
   - **错误:**  尝试将包含中文、日文等非 Latin-1 字符的字符串编码为 Latin-1。
   - **结果:**  根据 `UnencodableHandling` 的设置，可能会丢失信息（被替换为 '?' 等）或者抛出错误。

4. **服务端返回错误的 `Content-Type` 头部:**
   - **错误:**  服务器返回 Latin-1 编码的 HTML 文件，但 `Content-Type` 头部设置为 `text/html; charset=utf-8`。
   - **结果:**  浏览器会按照 UTF-8 解码，导致乱码。

5. **混淆 ISO-8859-1 和 Windows-1252:**
   - 虽然 `TextCodecLatin1` 通常将它们视为相同进行解码，但在某些情况下，特别是在处理 0x80-0x9F 范围内的字符时，细微的差异可能会导致误解，尤其是在编码时。例如，某些在 Windows-1252 中有定义的字符在严格的 ISO-8859-1 中是控制字符。

总而言之，`blink/renderer/platform/wtf/text/text_codec_latin1.cc` 是 Blink 引擎处理 Latin-1 字符编码的关键组件，它确保了浏览器能够正确地解释和呈现使用这种编码的网页内容，并与 JavaScript 等其他 Web 技术进行无缝集成。理解其功能有助于开发者避免字符编码相关的错误，创建更健壮的 Web 应用。

Prompt: 
```
这是目录为blink/renderer/platform/wtf/text/text_codec_latin1.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2004, 2006, 2008 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/wtf/text/text_codec_latin1.h"

#include <unicode/utf16.h>
#include <memory>

#include "third_party/blink/renderer/platform/wtf/text/string_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/text_codec_ascii_fast_path.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace WTF {

static const UChar kTable[256] = {
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,  // 00-07
    0x0008, 0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F,  // 08-0F
    0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017,  // 10-17
    0x0018, 0x0019, 0x001A, 0x001B, 0x001C, 0x001D, 0x001E, 0x001F,  // 18-1F
    0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,  // 20-27
    0x0028, 0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x002F,  // 28-2F
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,  // 30-37
    0x0038, 0x0039, 0x003A, 0x003B, 0x003C, 0x003D, 0x003E, 0x003F,  // 38-3F
    0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,  // 40-47
    0x0048, 0x0049, 0x004A, 0x004B, 0x004C, 0x004D, 0x004E, 0x004F,  // 48-4F
    0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,  // 50-57
    0x0058, 0x0059, 0x005A, 0x005B, 0x005C, 0x005D, 0x005E, 0x005F,  // 58-5F
    0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,  // 60-67
    0x0068, 0x0069, 0x006A, 0x006B, 0x006C, 0x006D, 0x006E, 0x006F,  // 68-6F
    0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,  // 70-77
    0x0078, 0x0079, 0x007A, 0x007B, 0x007C, 0x007D, 0x007E, 0x007F,  // 78-7F
    0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,  // 80-87
    0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,  // 88-8F
    0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,  // 90-97
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,  // 98-9F
    0x00A0, 0x00A1, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7,  // A0-A7
    0x00A8, 0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF,  // A8-AF
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7,  // B0-B7
    0x00B8, 0x00B9, 0x00BA, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00BF,  // B8-BF
    0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C5, 0x00C6, 0x00C7,  // C0-C7
    0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF,  // C8-CF
    0x00D0, 0x00D1, 0x00D2, 0x00D3, 0x00D4, 0x00D5, 0x00D6, 0x00D7,  // D0-D7
    0x00D8, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x00DD, 0x00DE, 0x00DF,  // D8-DF
    0x00E0, 0x00E1, 0x00E2, 0x00E3, 0x00E4, 0x00E5, 0x00E6, 0x00E7,  // E0-E7
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF,  // E8-EF
    0x00F0, 0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x00F7,  // F0-F7
    0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x00FD, 0x00FE, 0x00FF   // F8-FF
};

void TextCodecLatin1::RegisterEncodingNames(EncodingNameRegistrar registrar) {
  // Taken from the alias table at https://encoding.spec.whatwg.org/
  registrar("windows-1252", "windows-1252");
  registrar("ANSI_X3.4-1968", "windows-1252");
  registrar("ASCII", "windows-1252");
  registrar("cp1252", "windows-1252");
  registrar("cp819", "windows-1252");
  registrar("csISOLatin1", "windows-1252");
  registrar("IBM819", "windows-1252");
  registrar("ISO-8859-1", "windows-1252");
  registrar("iso-ir-100", "windows-1252");
  registrar("iso8859-1", "windows-1252");
  registrar("iso88591", "windows-1252");
  registrar("iso_8859-1", "windows-1252");
  registrar("iso_8859-1:1987", "windows-1252");
  registrar("l1", "windows-1252");
  registrar("latin1", "windows-1252");
  registrar("US-ASCII", "windows-1252");
  registrar("x-cp1252", "windows-1252");
}

static std::unique_ptr<TextCodec> NewStreamingTextDecoderWindowsLatin1(
    const TextEncoding&,
    const void*) {
  return std::make_unique<TextCodecLatin1>();
}

void TextCodecLatin1::RegisterCodecs(TextCodecRegistrar registrar) {
  registrar("windows-1252", NewStreamingTextDecoderWindowsLatin1, nullptr);

  // ASCII and Latin-1 both decode as Windows Latin-1 although they retain
  // unique identities.
  registrar("ISO-8859-1", NewStreamingTextDecoderWindowsLatin1, nullptr);
  registrar("US-ASCII", NewStreamingTextDecoderWindowsLatin1, nullptr);
}

String TextCodecLatin1::Decode(base::span<const uint8_t> bytes,
                               FlushBehavior,
                               bool,
                               bool&) {
  if (bytes.empty()) {
    return g_empty_string;
  }
  base::span<LChar> characters;
  String result = String::CreateUninitialized(
      base::checked_cast<wtf_size_t>(bytes.size()), characters);

  const uint8_t* source = bytes.data();
  const uint8_t* end = source + bytes.size();
  const uint8_t* aligned_end = AlignToMachineWord(end);
  LChar* destination = characters.data();

  while (source < end) {
    if (IsASCII(*source)) {
      // Fast path for ASCII. Most Latin-1 text will be ASCII.
      if (IsAlignedToMachineWord(source)) {
        while (source < aligned_end) {
          MachineWord chunk = *reinterpret_cast_ptr<const MachineWord*>(source);

          if (!IsAllASCII<LChar>(chunk))
            goto useLookupTable;

          CopyASCIIMachineWord(destination, source);
          source += sizeof(MachineWord);
          destination += sizeof(MachineWord);
        }

        if (source == end)
          break;
      }
      *destination = *source;
    } else {
    useLookupTable:
      if (kTable[*source] > 0xff)
        goto upConvertTo16Bit;

      *destination = static_cast<LChar>(kTable[*source]);
    }

    ++source;
    ++destination;
  }

  return result;

upConvertTo16Bit:
  base::span<UChar> characters16;
  String result16 = String::CreateUninitialized(
      base::checked_cast<wtf_size_t>(bytes.size()), characters16);

  UChar* destination16 = characters16.data();

  // Zero extend and copy already processed 8 bit data
  LChar* ptr8 = characters.data();
  LChar* end_ptr8 = destination;

  while (ptr8 < end_ptr8)
    *destination16++ = *ptr8++;

  // Handle the character that triggered the 16 bit path
  *destination16 = kTable[*source];
  ++source;
  ++destination16;

  while (source < end) {
    if (IsASCII(*source)) {
      // Fast path for ASCII. Most Latin-1 text will be ASCII.
      if (IsAlignedToMachineWord(source)) {
        while (source < aligned_end) {
          MachineWord chunk = *reinterpret_cast_ptr<const MachineWord*>(source);

          if (!IsAllASCII<LChar>(chunk))
            goto useLookupTable16;

          CopyASCIIMachineWord(destination16, source);
          source += sizeof(MachineWord);
          destination16 += sizeof(MachineWord);
        }

        if (source == end)
          break;
      }
      *destination16 = *source;
    } else {
    useLookupTable16:
      *destination16 = kTable[*source];
    }

    ++source;
    ++destination16;
  }

  return result16;
}

template <typename CharType>
static std::string EncodeComplexWindowsLatin1(
    base::span<const CharType> char_data,
    UnencodableHandling handling) {
  DCHECK_NE(handling, kNoUnencodables);
  const auto* characters = char_data.data();
  const wtf_size_t length = base::checked_cast<wtf_size_t>(char_data.size());
  wtf_size_t target_length = length;
  std::string result;
  result.reserve(target_length);

  for (wtf_size_t i = 0; i < length;) {
    UChar32 c;
    // If CharType is LChar the U16_NEXT call reads a byte and increments;
    // since the convention is that LChar is already latin1 this is safe.
    U16_NEXT(characters, i, length, c);
    // If input was a surrogate pair (non-BMP character) then we overestimated
    // the length.
    if (c > 0xffff)
      --target_length;
    unsigned char b = static_cast<unsigned char>(c);
    // Do an efficient check to detect characters other than 00-7F and A0-FF.
    if (b != c || (c & 0xE0) == 0x80) {
      // Look for a way to encode this with Windows Latin-1.
      for (b = 0x80; b < 0xA0; ++b) {
        if (kTable[b] == c)
          goto gotByte;
      }
      // No way to encode this character with Windows Latin-1.
      std::string replacement =
          TextCodec::GetUnencodableReplacement(c, handling);
      DCHECK_GT(replacement.length(), 0UL);
      // Only one char was initially reserved per input character, so grow if
      // necessary.
      target_length += replacement.length() - 1;
      if (target_length > result.size()) {
        result.reserve(target_length);
      }
      result.append(replacement);
      continue;
    }
  gotByte:
    result.push_back(b);
  }

  return result;
}

template <typename CharType>
std::string TextCodecLatin1::EncodeCommon(base::span<const CharType> characters,
                                          UnencodableHandling handling) {
  std::string string(characters.size(), '\0');

  // Convert the string a fast way and simultaneously do an efficient check to
  // see if it's all ASCII.
  UChar ored = 0;
  for (size_t i = 0; i < characters.size(); ++i) {
    UChar c = characters[i];
    string[i] = static_cast<char>(c);
    ored |= c;
  }

  if (!(ored & 0xFF80))
    return string;

  // If it wasn't all ASCII, call the function that handles more-complex cases.
  return EncodeComplexWindowsLatin1(characters, handling);
}

std::string TextCodecLatin1::Encode(base::span<const UChar> characters,
                                    UnencodableHandling handling) {
  return EncodeCommon(characters, handling);
}

std::string TextCodecLatin1::Encode(base::span<const LChar> characters,
                                    UnencodableHandling handling) {
  return EncodeCommon(characters, handling);
}

}  // namespace WTF

"""

```
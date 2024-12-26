Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request asks for the functionality of the `character_emoji.cc` file in the Chromium Blink engine, its relation to web technologies, logic analysis with examples, and potential usage errors.

2. **Initial Code Scan and High-Level Overview:**  The first thing that jumps out is the inclusion of `<unicode/uvernum.h>` and the conditional compilation based on `USING_SYSTEM_ICU` and `U_ICU_VERSION_MAJOR_NUM`. This strongly suggests the file deals with Unicode, specifically emoji, and handles different versions of the ICU library. The namespace `blink` confirms it's part of the Blink rendering engine.

3. **Identify Key Functions:**  The code defines several functions: `IsEmoji`, `IsEmojiTextDefault`, `IsEmojiEmojiDefault`, `IsEmojiModifierBase`, and `IsRegionalIndicator`. These function names clearly indicate the file's purpose: determining if a given Unicode code point has specific emoji properties.

4. **Analyze Conditional Compilation Logic:** The `#if` block is crucial. It handles cases where the system's ICU library is used or the ICU version is older than 62. In these cases, the emoji properties are determined using pre-compiled `UnicodeSet` patterns (represented by the `kEmojiTextPattern`, `kEmojiEmojiPattern`, and `kEmojiModifierBasePattern` string literals). Otherwise, it uses the newer ICU API ( `u_hasBinaryProperty`). This highlights a key function of the file: providing consistent emoji detection across different environments.

5. **Examine the `UnicodeSet` Patterns (Older ICU):** These large string literals are regular expression-like patterns defining ranges of Unicode code points. The comments within this section are helpful, explaining their origin (emoji-data.txt) and how they are generated. It's important to note that the code *includes* these patterns, implying that in older environments, the emoji detection is hardcoded within this file.

6. **Examine the `u_hasBinaryProperty` calls (Newer ICU):** This is the more modern and efficient approach. It relies on the ICU library's built-in knowledge of Unicode properties. The constants like `UCHAR_EMOJI`, `UCHAR_EMOJI_PRESENTATION`, and `UCHAR_EMOJI_MODIFIER_BASE` are standard ICU property identifiers.

7. **Understand the Individual Functions:**
    * `IsEmoji`:  Checks if a character is considered an emoji (either text-style or emoji-style).
    * `IsEmojiTextDefault`: Checks for emojis intended to be displayed as text by default (e.g., a black square).
    * `IsEmojiEmojiDefault`: Checks for emojis intended to be displayed as colorful images by default (e.g., a smiley face).
    * `IsEmojiModifierBase`: Checks for characters that can be combined with skin tone modifiers.
    * `IsRegionalIndicator`: Checks if a character is a regional indicator symbol (used for flags).

8. **Relate to Web Technologies (JavaScript, HTML, CSS):** This is where we connect the C++ code to the user-facing web.
    * **JavaScript:** JavaScript uses Unicode for strings. This C++ code helps Blink (the rendering engine) correctly *interpret* those Unicode characters as emojis when rendering a webpage. We can give examples of JavaScript strings containing emojis.
    * **HTML:** HTML displays text content. This C++ code ensures that when HTML contains emoji characters, they are rendered correctly by the browser. Examples would be embedding emojis directly in HTML.
    * **CSS:** CSS can influence how text is rendered (font, color, etc.). While this C++ code doesn't directly interact with CSS *rules*, it influences how the *characters* that CSS styles are interpreted. For example, CSS might specify a font that supports emoji rendering.

9. **Logic Analysis and Examples:** For each function, we can create hypothetical inputs (Unicode code points) and predict the output (true/false). This demonstrates understanding of how the functions work. It's useful to choose examples that highlight the different categories of emojis.

10. **Identify Potential Usage Errors:** This section requires thinking about how developers might misuse or misunderstand the functionality.
    * **Assuming consistent behavior across all browsers/ICU versions:** The conditional compilation makes it clear that behavior *can* vary.
    * **Incorrectly assuming a character is an emoji based on visual appearance:**  Some characters might look like emojis but aren't officially categorized as such.
    * **Not handling skin tone modifiers correctly:**  Developers need to be aware of combining characters for proper emoji rendering.

11. **Structure the Answer:**  Organize the information logically, starting with the main functionality, then relating it to web technologies, providing examples, and finally discussing potential errors. Use clear headings and bullet points for readability.

12. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Are there any ambiguities?  Are the examples clear?  Is the reasoning sound?  For example, initially, I might focus too much on the technical details of the `UnicodeSet` patterns. During review, I'd realize the importance of explaining *why* this code exists and its impact on web developers.

This detailed process, moving from high-level understanding to specific code analysis and then connecting it back to the broader context of web development, allows for a comprehensive and accurate answer to the prompt.
好的，让我们详细分析一下 `blink/renderer/platform/text/character_emoji.cc` 这个文件的功能。

**文件功能概要**

`character_emoji.cc` 文件的主要功能是**判断一个 Unicode 字符是否属于 Emoji 字符或具有特定的 Emoji 属性**。它为 Blink 渲染引擎提供了一种机制来识别和处理 Emoji 表情符号。

更具体地说，它实现了以下功能：

* **`IsEmoji(UChar32 ch)`**:  判断给定的 Unicode 代码点 `ch` 是否是一个 Emoji 字符（包括文本形式和图形形式的 Emoji）。
* **`IsEmojiTextDefault(UChar32 ch)`**: 判断给定的 Unicode 代码点 `ch` 是否是一个默认以文本形式显示的 Emoji 字符。例如，一些基本的 Emoji 符号如数字符号 (#) 或星号 (*)。
* **`IsEmojiEmojiDefault(UChar32 ch)`**: 判断给定的 Unicode 代码点 `ch` 是否是一个默认以图形（彩色）形式显示的 Emoji 字符。例如，笑脸 😊 或爱心 ❤️。
* **`IsEmojiModifierBase(UChar32 ch)`**: 判断给定的 Unicode 代码点 `ch` 是否是一个 Emoji 修饰符基础字符。这些字符可以与后续的修饰符（如肤色修饰符）组合使用，形成新的 Emoji。例如，人的表情符号 🧑‍🦰 可以通过组合基础字符 🧑 和肤色修饰符 🦰 得到。
* **`IsRegionalIndicator(UChar32 ch)`**: 判断给定的 Unicode 代码点 `ch` 是否是一个区域指示符。区域指示符通常成对使用，表示国家或地区的旗帜。

**与 JavaScript, HTML, CSS 的关系**

这个 C++ 文件在 Blink 引擎的底层工作，它直接影响着浏览器如何解析和渲染网页上的文本内容，包括 Emoji 表情符号。虽然 JavaScript, HTML, 和 CSS 本身不直接调用这个文件中的函数，但它们的功能息息相关：

* **HTML:**  HTML 用于构建网页的结构和内容。当 HTML 文本中包含 Emoji 字符时，Blink 引擎会使用 `character_emoji.cc` 中的函数来识别这些字符是 Emoji，并进行相应的渲染处理。
    * **举例说明：**
        * **假设输入 HTML:**  `<h1>Hello 😊 world!</h1>`
        * Blink 引擎在解析这段 HTML 时，会遇到 Unicode 代码点 `U+1F60A` (😊)。
        * `Character::IsEmoji(0x1F60A)` 会返回 `true`。
        * Blink 引擎会知道这是一个 Emoji 字符，并可能使用特定的字体或渲染方式来显示它。

* **JavaScript:** JavaScript 可以操作网页的内容和样式。JavaScript 字符串可以包含 Emoji 字符。当 JavaScript 将包含 Emoji 的字符串添加到 HTML 中时，Blink 引擎同样会使用这个文件来识别和渲染 Emoji。
    * **举例说明：**
        * **假设 JavaScript 代码:** `document.getElementById('myDiv').textContent = 'This is 👍';`
        * JavaScript 将字符串 "This is 👍" 设置为 div 的文本内容。
        * Blink 引擎在渲染这个 div 的文本时，会遇到 Unicode 代码点 `U+1F44D` (👍)。
        * `Character::IsEmoji(0x1F44D)` 会返回 `true`。
        * 浏览器会正确显示 "👍" 这个 Emoji。

* **CSS:** CSS 用于控制网页的样式。虽然 CSS 本身不直接处理 Emoji 的识别，但它可以影响 Emoji 的显示方式，例如通过字体设置。如果选择的字体不支持 Emoji，或者使用了特定的 CSS 样式导致 Emoji 显示异常，`character_emoji.cc` 的功能仍然是识别这些字符为 Emoji。
    * **举例说明：**
        * **假设 HTML:** `<p>🚩</p>`
        * **假设 CSS:** `p { font-family: 'Arial'; }`
        * 虽然 CSS 指定了 Arial 字体，但如果 Arial 字体没有包含 🚩 这个 Emoji 的字形，浏览器可能会回退到其他支持 Emoji 的字体来显示。 `Character::IsEmoji(0x1F6A9)` (🚩) 仍然会返回 `true`，告诉引擎这是一个 Emoji。

**逻辑推理与假设输入输出**

让我们针对几个函数进行逻辑推理和假设输入输出：

**1. `IsEmoji(UChar32 ch)`**

* **假设输入:** `ch = 0x0041` (大写字母 'A')
* **逻辑推理:** 大写字母 'A' 不是 Emoji 字符。
* **预期输出:** `false`

* **假设输入:** `ch = 0x1F600` (Emoji 笑脸 😀)
* **逻辑推理:**  😀 是一个 Emoji 字符。
* **预期输出:** `true`

* **假设输入:** `ch = 0x0023` (数字符号 '#')
* **逻辑推理:** '#' 在某些上下文中可以作为 Emoji 字符显示（例如，后跟变体选择符 U+FE0F）。 在这个函数中，根据代码，它会被认为是 Emoji。
* **预期输出:** `true`

**2. `IsEmojiTextDefault(UChar32 ch)`**

* **假设输入:** `ch = 0x002A` (星号 '*')
* **逻辑推理:** 星号 '*' 通常以文本形式显示。
* **预期输出:** `true` (在当前代码中，它被包含在 `kEmojiTextPattern` 中)

* **假设输入:** `ch = 0x1F60D` (Emoji 带心形的笑脸 😍)
* **逻辑推理:** 😍 通常以彩色图形形式显示。
* **预期输出:** `false`

**3. `IsEmojiEmojiDefault(UChar32 ch)`**

* **假设输入:** `ch = 0x1F499` (蓝色心形 💙)
* **逻辑推理:** 💙 通常以彩色图形形式显示。
* **预期输出:** `true`

* **假设输入:** `ch = 0x0039` (数字 '9')
* **逻辑推理:** 数字 '9' 通常以文本形式显示。
* **预期输出:** `false`

**4. `IsEmojiModifierBase(UChar32 ch)`**

* **假设输入:** `ch = 0x1F468` (男人 👨)
* **逻辑推理:**  男人 👨 可以与肤色修饰符组合。
* **预期输出:** `true`

* **假设输入:** `ch = 0x1F4BB` (笔记本电脑 💻)
* **逻辑推理:** 笔记本电脑 💻 不能与肤色修饰符组合。
* **预期输出:** `false`

**5. `IsRegionalIndicator(UChar32 ch)`**

* **假设输入:** `ch = 0x1F1E8` (区域指示符符号 'C')
* **逻辑推理:**  这是表示国家代码的区域指示符。
* **预期输出:** `true`

* **假设输入:** `ch = 0x0042` (大写字母 'B')
* **逻辑推理:** 大写字母 'B' 不是区域指示符。
* **预期输出:** `false`

**用户或编程常见的使用错误**

* **假设所有浏览器对 Emoji 的支持完全一致：**  虽然 Unicode 标准定义了 Emoji 字符，但不同浏览器和操作系统对 Emoji 的渲染可能会有细微差别，尤其是在旧版本或非主流平台上。开发者不能假设所有 Emoji 在所有环境下都以完全相同的方式显示。

* **错误地假设可以通过简单的字符代码判断 Emoji 的呈现方式：** 有些 Emoji 字符既可以以文本形式显示，也可以以图形形式显示，这取决于上下文或是否有变体选择符。例如，`U+2615` (☕) 可以是黑白的文本符号，也可以是彩色的咖啡杯 Emoji。 开发者需要理解这种灵活性。

* **忽略 Emoji 修饰符的影响：**  开发者可能会忘记处理 Emoji 修饰符，导致 Emoji 显示不完整或不正确。例如，一个表示人的 Emoji 可能需要与肤色修饰符组合才能正确显示特定肤色。

    * **举例说明：**  开发者可能只存储了 `U+1F468` (👨)，而没有考虑用户选择的肤色，导致在需要显示特定肤色男性 Emoji 的地方显示不正确。

* **在不支持 Emoji 的环境中使用 Emoji：**  如果网页需要在不支持 Emoji 的旧浏览器或终端中显示，直接使用 Emoji 字符可能会导致显示为乱码或方框。开发者需要考虑提供回退方案或使用 Emoji 图片。

* **混淆 `IsEmojiTextDefault` 和 `IsEmojiEmojiDefault` 的含义：** 开发者可能会错误地认为 `IsEmojiTextDefault` 表示“这个 Emoji 只能以文本形式显示”，而 `IsEmojiEmojiDefault` 表示“这个 Emoji 只能以图形形式显示”。 实际上，这些函数只是判断默认的显示方式，有些 Emoji 在某些情况下也可以强制以另一种方式显示（例如通过变体选择符）。

**总结**

`blink/renderer/platform/text/character_emoji.cc` 是 Blink 引擎中一个关键的底层文件，负责识别和分类 Unicode Emoji 字符。它对于在浏览器中正确渲染包含 Emoji 的文本至关重要，并直接影响用户在网页上看到的 Emoji 显示效果。理解其功能有助于开发者更好地处理网页中的 Emoji 内容，并避免一些常见的显示错误。

Prompt: 
```
这是目录为blink/renderer/platform/text/character_emoji.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/text/character.h"

#include <unicode/uvernum.h>

namespace blink {

// ICU 61 or earlier does not have up to date v11 Emoji properties, so we're
// temporarily uing our own functions again. Compare crbug.com/628333 Other than
// that: versions before 56 do not have an API for Emoji properties, but
// Chrome's copy of ICU 56 does.
#if defined(USING_SYSTEM_ICU) || (U_ICU_VERSION_MAJOR_NUM <= 61)
// The following UnicodeSet patterns were compiled from
// https://unicode.org/Public/emoji//11.0/emoji-data.txt

// The following patterns can be generated from the respective sections of the
// emoji_data.txt file by using the following Elisp function in Emacs.
// Known issues:
// 1) Does not insert the double [[ and ]] at the beginning and end of the
// pattern.
// 2) Does not insert \U0000 at the very last codepoint of a pattern.
//
// (defun convertemojidata ()
//   "Convert a section of the emoji_data.txt file to an ICU trie definition."
//   (interactive)
//   (goto-char 0)
//   (while (re-search-forward " *;.*$" nil t)
//     (replace-match "" nil nil))
//   (goto-char 0)
//   (while (re-search-forward "\\.\\." nil t)
//     (replace-match "-" nil nil))
//   (goto-char 0)
//   ; Pad 4 digit characters, step 1
//   (while (re-search-forward
//           "\\([^0-9A-F]*\\)\\([0-9A-F]\\{4\\}\\)\\([^0-9A-F]\\)"
//           nil t)
//     (replace-match "\\1\\\\U0000\\2\\3" nil nil))
//   (goto-char 0)
//   ; Fix up 5 digit characters padding, step 2
//   (while (re-search-forward "1\\\\U0000" nil t)
//     (replace-match "\\\\U0001" nil nil))
//   (goto-char 0)
//   (while (re-search-forward "^\\(.*\\)$" nil t)
//     (replace-match "[\\1]" nil nil))
//   (goto-char 0)
//   (replace-string "\n" " ")
//   (set-fill-column 72)
//   (goto-char 0)
//   (fill-paragraph)
//   (replace-string " " "")
//   (goto-char 0)
//   (while (re-search-forward "^\\(.*\\)$" nil t)
//     (replace-match "    R\"(\\1)\"" nil nil))
//   (goto-char 8)
//   (insert "[")
//   (goto-char (- (point-max) 3))
//   (insert "]")
//   )

static const char kEmojiTextPattern[] =
    R"([[\U00000023][\U0000002A][\U00000030-\U00000039][\U000000A9])"
    R"([\U000000AE][\U0000203C][\U00002049][\U00002122][\U00002139])"
    R"([\U00002194-\U00002199][\U000021A9-\U000021AA][\U0000231A-\U0000231B])"
    R"([\U00002328][\U000023CF][\U000023E9-\U000023F3])"
    R"([\U000023F8-\U000023FA][\U000024C2][\U000025AA-\U000025AB])"
    R"([\U000025B6][\U000025C0][\U000025FB-\U000025FE])"
    R"([\U00002600-\U00002604][\U0000260E][\U00002611])"
    R"([\U00002614-\U00002615][\U00002618][\U0000261D][\U00002620])"
    R"([\U00002622-\U00002623][\U00002626][\U0000262A])"
    R"([\U0000262E-\U0000262F][\U00002638-\U0000263A][\U00002640])"
    R"([\U00002642][\U00002648-\U00002653][\U0000265F-\U00002660])"
    R"([\U00002663][\U00002665-\U00002666][\U00002668][\U0000267B])"
    R"([\U0000267E-\U0000267F][\U00002692-\U00002697][\U00002699])"
    R"([\U0000269B-\U0000269C][\U000026A0-\U000026A1][\U000026AA-\U000026AB])"
    R"([\U000026B0-\U000026B1][\U000026BD-\U000026BE][\U000026C4-\U000026C5])"
    R"([\U000026C8][\U000026CE][\U000026CF][\U000026D1])"
    R"([\U000026D3-\U000026D4][\U000026E9-\U000026EA][\U000026F0-\U000026F5])"
    R"([\U000026F7-\U000026FA][\U000026FD][\U00002702][\U00002705])"
    R"([\U00002708-\U00002709][\U0000270A-\U0000270B][\U0000270C-\U0000270D])"
    R"([\U0000270F][\U00002712][\U00002714][\U00002716][\U0000271D])"
    R"([\U00002721][\U00002728][\U00002733-\U00002734][\U00002744])"
    R"([\U00002747][\U0000274C][\U0000274E][\U00002753-\U00002755])"
    R"([\U00002757][\U00002763-\U00002764][\U00002795-\U00002797])"
    R"([\U000027A1][\U000027B0][\U000027BF][\U00002934-\U00002935])"
    R"([\U00002B05-\U00002B07][\U00002B1B-\U00002B1C][\U00002B50])"
    R"([\U00002B55][\U00003030][\U0000303D][\U00003297][\U00003299])"
    R"([\U0001F004][\U0001F0CF][\U0001F170-\U0001F171][\U0001F17E])"
    R"([\U0001F17F][\U0001F18E][\U0001F191-\U0001F19A])"
    R"([\U0001F1E6-\U0001F1FF][\U0001F201-\U0001F202][\U0001F21A])"
    R"([\U0001F22F][\U0001F232-\U0001F23A][\U0001F250-\U0001F251])"
    R"([\U0001F300-\U0001F320][\U0001F321][\U0001F324-\U0001F32C])"
    R"([\U0001F32D-\U0001F32F][\U0001F330-\U0001F335][\U0001F336])"
    R"([\U0001F337-\U0001F37C][\U0001F37D][\U0001F37E-\U0001F37F])"
    R"([\U0001F380-\U0001F393][\U0001F396-\U0001F397][\U0001F399-\U0001F39B])"
    R"([\U0001F39E-\U0001F39F][\U0001F3A0-\U0001F3C4][\U0001F3C5])"
    R"([\U0001F3C6-\U0001F3CA][\U0001F3CB-\U0001F3CE][\U0001F3CF-\U0001F3D3])"
    R"([\U0001F3D4-\U0001F3DF][\U0001F3E0-\U0001F3F0][\U0001F3F3-\U0001F3F5])"
    R"([\U0001F3F7][\U0001F3F8-\U0001F3FF][\U0001F400-\U0001F43E])"
    R"([\U0001F43F][\U0001F440][\U0001F441][\U0001F442-\U0001F4F7])"
    R"([\U0001F4F8][\U0001F4F9-\U0001F4FC][\U0001F4FD][\U0001F4FF])"
    R"([\U0001F500-\U0001F53D][\U0001F549-\U0001F54A][\U0001F54B-\U0001F54E])"
    R"([\U0001F550-\U0001F567][\U0001F56F-\U0001F570][\U0001F573-\U0001F579])"
    R"([\U0001F57A][\U0001F587][\U0001F58A-\U0001F58D][\U0001F590])"
    R"([\U0001F595-\U0001F596][\U0001F5A4][\U0001F5A5][\U0001F5A8])"
    R"([\U0001F5B1-\U0001F5B2][\U0001F5BC][\U0001F5C2-\U0001F5C4])"
    R"([\U0001F5D1-\U0001F5D3][\U0001F5DC-\U0001F5DE][\U0001F5E1])"
    R"([\U0001F5E3][\U0001F5E8][\U0001F5EF][\U0001F5F3][\U0001F5FA])"
    R"([\U0001F5FB-\U0001F5FF][\U0001F600][\U0001F601-\U0001F610])"
    R"([\U0001F611][\U0001F612-\U0001F614][\U0001F615][\U0001F616])"
    R"([\U0001F617][\U0001F618][\U0001F619][\U0001F61A][\U0001F61B])"
    R"([\U0001F61C-\U0001F61E][\U0001F61F][\U0001F620-\U0001F625])"
    R"([\U0001F626-\U0001F627][\U0001F628-\U0001F62B][\U0001F62C])"
    R"([\U0001F62D][\U0001F62E-\U0001F62F][\U0001F630-\U0001F633])"
    R"([\U0001F634][\U0001F635-\U0001F640][\U0001F641-\U0001F642])"
    R"([\U0001F643-\U0001F644][\U0001F645-\U0001F64F][\U0001F680-\U0001F6C5])"
    R"([\U0001F6CB-\U0001F6CF][\U0001F6D0][\U0001F6D1-\U0001F6D2])"
    R"([\U0001F6E0-\U0001F6E5][\U0001F6E9][\U0001F6EB-\U0001F6EC])"
    R"([\U0001F6F0][\U0001F6F3][\U0001F6F4-\U0001F6F6])"
    R"([\U0001F6F7-\U0001F6F8][\U0001F6F9][\U0001F910-\U0001F918])"
    R"([\U0001F919-\U0001F91E][\U0001F91F][\U0001F920-\U0001F927])"
    R"([\U0001F928-\U0001F92F][\U0001F930][\U0001F931-\U0001F932])"
    R"([\U0001F933-\U0001F93A][\U0001F93C-\U0001F93E][\U0001F940-\U0001F945])"
    R"([\U0001F947-\U0001F94B][\U0001F94C][\U0001F94D-\U0001F94F])"
    R"([\U0001F950-\U0001F95E][\U0001F95F-\U0001F96B][\U0001F96C-\U0001F970])"
    R"([\U0001F973-\U0001F976][\U0001F97A][\U0001F97C-\U0001F97F])"
    R"([\U0001F980-\U0001F984][\U0001F985-\U0001F991][\U0001F992-\U0001F997])"
    R"([\U0001F998-\U0001F9A2][\U0001F9B0-\U0001F9B9][\U0001F9C0])"
    R"([\U0001F9C1-\U0001F9C2][\U0001F9D0-\U0001F9E6][\U0001F9E7-\U0001F9FF]])";

static const char kEmojiEmojiPattern[] =
    R"([[\U0000231A-\U0000231B][\U000023E9-\U000023EC][\U000023F0])"
    R"([\U000023F3][\U000025FD-\U000025FE][\U00002614-\U00002615])"
    R"([\U00002648-\U00002653][\U0000267F][\U00002693][\U000026A1])"
    R"([\U000026AA-\U000026AB][\U000026BD-\U000026BE][\U000026C4-\U000026C5])"
    R"([\U000026CE][\U000026D4][\U000026EA][\U000026F2-\U000026F3])"
    R"([\U000026F5][\U000026FA][\U000026FD][\U00002705])"
    R"([\U0000270A-\U0000270B][\U00002728][\U0000274C][\U0000274E])"
    R"([\U00002753-\U00002755][\U00002757][\U00002795-\U00002797])"
    R"([\U000027B0][\U000027BF][\U00002B1B-\U00002B1C][\U00002B50])"
    R"([\U00002B55][\U0001F004][\U0001F0CF][\U0001F18E])"
    R"([\U0001F191-\U0001F19A][\U0001F1E6-\U0001F1FF][\U0001F201])"
    R"([\U0001F21A][\U0001F22F][\U0001F232-\U0001F236])"
    R"([\U0001F238-\U0001F23A][\U0001F250-\U0001F251][\U0001F300-\U0001F320])"
    R"([\U0001F32D-\U0001F32F][\U0001F330-\U0001F335][\U0001F337-\U0001F37C])"
    R"([\U0001F37E-\U0001F37F][\U0001F380-\U0001F393][\U0001F3A0-\U0001F3C4])"
    R"([\U0001F3C5][\U0001F3C6-\U0001F3CA][\U0001F3CF-\U0001F3D3])"
    R"([\U0001F3E0-\U0001F3F0][\U0001F3F4][\U0001F3F8-\U0001F3FF])"
    R"([\U0001F400-\U0001F43E][\U0001F440][\U0001F442-\U0001F4F7])"
    R"([\U0001F4F8][\U0001F4F9-\U0001F4FC][\U0001F4FF])"
    R"([\U0001F500-\U0001F53D][\U0001F54B-\U0001F54E][\U0001F550-\U0001F567])"
    R"([\U0001F57A][\U0001F595-\U0001F596][\U0001F5A4])"
    R"([\U0001F5FB-\U0001F5FF][\U0001F600][\U0001F601-\U0001F610])"
    R"([\U0001F611][\U0001F612-\U0001F614][\U0001F615][\U0001F616])"
    R"([\U0001F617][\U0001F618][\U0001F619][\U0001F61A][\U0001F61B])"
    R"([\U0001F61C-\U0001F61E][\U0001F61F][\U0001F620-\U0001F625])"
    R"([\U0001F626-\U0001F627][\U0001F628-\U0001F62B][\U0001F62C])"
    R"([\U0001F62D][\U0001F62E-\U0001F62F][\U0001F630-\U0001F633])"
    R"([\U0001F634][\U0001F635-\U0001F640][\U0001F641-\U0001F642])"
    R"([\U0001F643-\U0001F644][\U0001F645-\U0001F64F][\U0001F680-\U0001F6C5])"
    R"([\U0001F6CC][\U0001F6D0][\U0001F6D1-\U0001F6D2])"
    R"([\U0001F6EB-\U0001F6EC][\U0001F6F4-\U0001F6F6][\U0001F6F7-\U0001F6F8])"
    R"([\U0001F6F9][\U0001F910-\U0001F918][\U0001F919-\U0001F91E])"
    R"([\U0001F91F][\U0001F920-\U0001F927][\U0001F928-\U0001F92F])"
    R"([\U0001F930][\U0001F931-\U0001F932][\U0001F933-\U0001F93A])"
    R"([\U0001F93C-\U0001F93E][\U0001F940-\U0001F945][\U0001F947-\U0001F94B])"
    R"([\U0001F94C][\U0001F94D-\U0001F94F][\U0001F950-\U0001F95E])"
    R"([\U0001F95F-\U0001F96B][\U0001F96C-\U0001F970][\U0001F973-\U0001F976])"
    R"([\U0001F97A][\U0001F97C-\U0001F97F][\U0001F980-\U0001F984])"
    R"([\U0001F985-\U0001F991][\U0001F992-\U0001F997][\U0001F998-\U0001F9A2])"
    R"([\U0001F9B0-\U0001F9B9][\U0001F9C0][\U0001F9C1-\U0001F9C2])"
    R"([\U0001F9D0-\U0001F9E6][\U0001F9E7-\U0001F9FF]])";

static const char kEmojiModifierBasePattern[] =
    R"([[\U0000261D][\U000026F9][\U0000270A-\U0000270B])"
    R"([\U0000270C-\U0000270D][\U0001F385][\U0001F3C2-\U0001F3C4])"
    R"([\U0001F3C7][\U0001F3CA][\U0001F3CB-\U0001F3CC])"
    R"([\U0001F442-\U0001F443][\U0001F446-\U0001F450][\U0001F466-\U0001F469])"
    R"([\U0001F46E][\U0001F470-\U0001F478][\U0001F47C])"
    R"([\U0001F481-\U0001F483][\U0001F485-\U0001F487][\U0001F4AA])"
    R"([\U0001F574-\U0001F575][\U0001F57A][\U0001F590])"
    R"([\U0001F595-\U0001F596][\U0001F645-\U0001F647][\U0001F64B-\U0001F64F])"
    R"([\U0001F6A3][\U0001F6B4-\U0001F6B6][\U0001F6C0][\U0001F6CC])"
    R"([\U0001F918][\U0001F919-\U0001F91C][\U0001F91E][\U0001F91F])"
    R"([\U0001F926][\U0001F930][\U0001F931-\U0001F932])"
    R"([\U0001F933-\U0001F939][\U0001F93D-\U0001F93E][\U0001F9B5-\U0001F9B6])"
    R"([\U0001F9B8-\U0001F9B9][\U0001F9D1-\U0001F9DD]])";

bool Character::IsEmoji(UChar32 ch) {
  return Character::IsEmojiTextDefault(ch) ||
         Character::IsEmojiEmojiDefault(ch);
}

bool Character::IsEmojiTextDefault(UChar32 ch) {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(icu::UnicodeSet, emojiTextSet, ());
  ApplyPatternAndFreezeIfEmpty(&emojiTextSet, kEmojiTextPattern);
  return emojiTextSet.contains(ch) && !IsEmojiEmojiDefault(ch);
}

bool Character::IsEmojiEmojiDefault(UChar32 ch) {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(icu::UnicodeSet, emojiEmojiSet, ());
  ApplyPatternAndFreezeIfEmpty(&emojiEmojiSet, kEmojiEmojiPattern);
  return emojiEmojiSet.contains(ch);
}

bool Character::IsEmojiModifierBase(UChar32 ch) {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(icu::UnicodeSet, emojieModifierBaseSet, ());
  ApplyPatternAndFreezeIfEmpty(&emojieModifierBaseSet,
                               kEmojiModifierBasePattern);
  return emojieModifierBaseSet.contains(ch);
}
#else
bool Character::IsEmoji(UChar32 ch) {
  return u_hasBinaryProperty(ch, UCHAR_EMOJI);
}
bool Character::IsEmojiTextDefault(UChar32 ch) {
  return u_hasBinaryProperty(ch, UCHAR_EMOJI) &&
         !u_hasBinaryProperty(ch, UCHAR_EMOJI_PRESENTATION);
}

bool Character::IsEmojiEmojiDefault(UChar32 ch) {
  return u_hasBinaryProperty(ch, UCHAR_EMOJI_PRESENTATION);
}

bool Character::IsEmojiModifierBase(UChar32 ch) {
  return u_hasBinaryProperty(ch, UCHAR_EMOJI_MODIFIER_BASE);
}
#endif  // defined(USING_SYSTEM_ICU) && (U_ICU_VERSION_MAJOR_NUM <= 61)

bool Character::IsRegionalIndicator(UChar32 ch) {
  return (ch >= 0x1F1E6 && ch <= 0x1F1FF);
}

}  // namespace blink

"""

```
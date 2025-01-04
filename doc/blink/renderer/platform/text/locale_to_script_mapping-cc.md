Response:
Let's break down the thought process for analyzing the `locale_to_script_mapping.cc` file.

1. **Understand the Goal:** The filename and the copyright notice immediately suggest this file deals with mapping locales or languages to scripts. The mention of "font selection" in `LocaleToScriptCodeForFontSelection` reinforces this. The overall goal seems to be helping the browser choose the appropriate font based on the language of the content.

2. **Identify Key Data Structures:** Scan the code for the primary data structures. The `SubtagScript` struct and the `kScriptNameCodeList` and `kLocaleScriptList` arrays are the core of the mapping logic. Notice they are `static constexpr`, implying they are compile-time constants and the mappings are fixed.

3. **Analyze Core Functions:** Focus on the public functions: `ScriptNameToCode` and `LocaleToScriptCodeForFontSelection`, and the internal helper `ScriptCodeForHanFromRegion` and `ScriptCodeForHanFromSubtags`.

    * **`ScriptNameToCode`:**  This function takes a script name (like "arab") and returns a `UScriptCode` (like `USCRIPT_ARABIC`). The comment highlights a key point: some script families are treated as a single script for font selection (e.g., "hira" and "kana" map to `USCRIPT_KATAKANA_OR_HIRAGANA`). This suggests a pragmatic approach focused on font rendering rather than strict linguistic distinction.

    * **`LocaleToScriptCodeForFontSelection`:** This is the most complex function. It takes a locale string (like "en-US", "zh-Hans", "ja") and attempts to map it to a `UScriptCode`. The logic involves:
        * **Normalization:** Replacing underscores with hyphens to handle different locale formats.
        * **Direct Lookup:** Iterating through `kLocaleScriptList` for exact matches.
        * **Subtag Parsing:** If no direct match is found, it iteratively removes subtags from the locale string (e.g., going from "zh-Hans-CN" to "zh-Hans" to "zh").
        * **Script Subtag Extraction:** If a 4-letter script subtag is found, it calls `ScriptNameToCode`.
        * **Defaulting:** If no mapping is found, it returns `USCRIPT_COMMON`.

    * **`ScriptCodeForHanFromRegion`:**  This function maps region codes (like "JP", "KR") to specific Han-related script codes. This indicates special handling for Chinese, Japanese, and Korean, where region can influence the desired Han variant.

    * **`ScriptCodeForHanFromSubtags`:** This function parses a locale string for script or region subtags to determine the appropriate Han script. It's used when the language itself is ambiguous (like just "zh").

4. **Consider the Relationship to Web Technologies (JavaScript, HTML, CSS):**

    * **HTML:**  Think about the `lang` attribute. This is the primary way to specify the language of content. The browser uses this information to make decisions about font rendering, among other things.

    * **CSS:** The `@font-face` rule allows specifying fonts for particular Unicode ranges or language settings. The script code determined by these functions directly influences which `@font-face` rule might be applied.

    * **JavaScript:** While JavaScript doesn't directly call these functions, it can manipulate the DOM and the `lang` attribute. It can also access internationalization APIs, which indirectly rely on similar locale information.

5. **Identify Potential Issues and Edge Cases:**

    * **Ambiguous Locales:**  Consider locales where the script isn't immediately obvious (e.g., "sr" could be Cyrillic or Latin depending on the region). The code primarily uses the language subtag for the initial mapping.
    * **Missing Mappings:**  What happens if a locale or script isn't in the lists? The code defaults to `USCRIPT_COMMON` or `USCRIPT_INVALID_CODE`, which might not be ideal for all situations. This suggests the data in these lists needs to be maintained and updated.
    * **Han Variant Selection:** The special handling for Han variants raises questions about the accuracy and completeness of the region-based mapping.

6. **Formulate Examples:**  Create concrete examples to illustrate the function's behavior. Think about different locale inputs and the expected script code outputs.

7. **Structure the Answer:** Organize the findings into clear sections: Functionality, Relationship to Web Technologies, Logic and Examples, Usage Errors. Use clear and concise language.

8. **Refine and Review:** Read through the answer to ensure accuracy, clarity, and completeness. Check for any logical inconsistencies or areas that could be explained better. For instance, initially, I might have missed the nuance of treating script *families* as single entities in `ScriptNameToCode`. A review would help catch such details.

This systematic approach of understanding the goal, dissecting the code, connecting it to broader concepts, and providing concrete examples is crucial for effectively analyzing source code and explaining its functionality.
这个文件 `blink/renderer/platform/text/locale_to_script_mapping.cc` 的主要功能是 **将语言区域设置（locale）映射到对应的 Unicode 脚本（script）**。 这在浏览器引擎 Blink 中对于选择合适的字体来渲染文本至关重要。

更具体地说，它提供了两个主要的公共函数：

1. **`ScriptNameToCode(const String& script_name)`:**
   - **功能:**  接受一个 ISO 15924 脚本名称 (例如 "Latn", "Cyrl", "Arab") 作为输入，并返回对应的 `UScriptCode` 枚举值。 `UScriptCode` 是 ICU (International Components for Unicode) 库中表示 Unicode 脚本的类型。
   - **特殊处理:**  该函数会进行一些特殊处理，将某些相关的脚本族映射到同一个 `UScriptCode`，以便在字体选择时将它们视为一个整体。 例如， "hira" (平假名) 和 "kana" (片假名) 都被映射到 `USCRIPT_KATAKANA_OR_HIRAGANA`。 这是因为 Blink 希望使用相同的字体设置来渲染所有日文脚本。
   - **假设输入与输出:**
     - 输入: "arab"  输出: `USCRIPT_ARABIC`
     - 输入: "hira"  输出: `USCRIPT_KATAKANA_OR_HIRAGANA`
     - 输入: "latn"  输出: `USCRIPT_LATIN`
     - 输入: "nonexistentscript" 输出: `USCRIPT_INVALID_CODE`

2. **`LocaleToScriptCodeForFontSelection(const String& locale)`:**
   - **功能:** 接受一个语言区域设置字符串 (例如 "en-US", "zh-CN", "ja") 作为输入，并返回该区域设置主要使用的脚本的 `UScriptCode`。这个函数主要用于字体选择。
   - **处理逻辑:**
     - 它首先将 locale 字符串中的下划线 `_` 替换为连字符 `-`，使其符合 BCP 47 标准。
     - 然后，它在一个预定义的映射表 `kLocaleScriptList` 中查找与给定 locale 完全匹配的项。如果找到，则返回对应的脚本代码。
     - 如果没有找到完全匹配的项，它会逐步移除 locale 字符串的尾部子标签（例如，从 "zh-Hans-CN" 变为 "zh-Hans" 再到 "zh"），并重复查找。
     - 在移除子标签的过程中，如果遇到长度为 4 的子标签，它会尝试将其解析为脚本名称，并使用 `ScriptNameToCode` 函数获取其对应的脚本代码。
     - 针对中文，如果 locale 中包含区域信息（例如 "zh-CN", "zh-TW"），它会根据区域信息来推断应该使用的 Han 脚本变体 (简体或繁体)。
     - 如果最终没有找到匹配的脚本，则返回 `USCRIPT_COMMON`。
   - **假设输入与输出:**
     - 输入: "en-US" 输出: `USCRIPT_LATIN`
     - 输入: "zh-CN" 输出: `USCRIPT_SIMPLIFIED_HAN`
     - 输入: "ja" 输出: `USCRIPT_KATAKANA_OR_HIRAGANA`
     - 输入: "ar-EG" 输出: `USCRIPT_ARABIC`
     - 输入: "ko-KR" 输出: `USCRIPT_HANGUL`
     - 输入: "fr-CA" 输出: `USCRIPT_LATIN`
     - 输入: "ru" 输出: `USCRIPT_CYRILLIC`
     - 输入: "unknown-locale" 输出: `USCRIPT_COMMON`

**与 JavaScript, HTML, CSS 的关系：**

这个文件中的功能与 Web 前端技术息息相关，因为它直接影响着浏览器如何渲染网页上的文本。

* **HTML:**
    - HTML 的 `lang` 属性用于声明元素的语言。例如，`<p lang="zh-CN">你好</p>` 表明这段文字是中文（中国大陆）。
    - Blink 引擎会读取 HTML 元素的 `lang` 属性值，并将其传递给 `LocaleToScriptCodeForFontSelection` 函数，以确定应该使用哪种脚本的字体来渲染这段文字。
    - **示例:** 如果 HTML 中有 `<p lang="ja">こんにちは</p>`, `LocaleToScriptCodeForFontSelection("ja")` 会返回 `USCRIPT_KATAKANA_OR_HIRAGANA`，浏览器会选择适合日文假名的字体进行渲染。

* **CSS:**
    - CSS 可以使用 `@font-face` 规则来定义自定义字体，并且可以通过 `unicode-range` 属性来指定字体适用的 Unicode 字符范围，或者通过 `lang` 描述符来指定字体适用的语言。
    - 当浏览器需要渲染特定语言的文本时，它会查找匹配的 `@font-face` 规则。 `LocaleToScriptCodeForFontSelection` 的输出有助于浏览器判断哪个 `@font-face` 规则更适合当前语言的文本。
    - **示例:**  一个网站可能定义了两个字体：
        ```css
        @font-face {
          font-family: 'MyFont';
          src: url('latin.woff2') format('woff2');
          unicode-range: U+0000-00FF, U+0100-017F, U+0180-024F; /* Basic Latin, Latin-1 Supplement, Latin Extended-A */
        }

        @font-face {
          font-family: 'MyFont';
          src: url('cyrillic.woff2') format('woff2');
          unicode-range: U+0400-04FF, U+0500-052F, U+2DE0-2DFF, U+A640-A69F; /* Cyrillic */
        }

        p[lang="ru"] {
          font-family: 'MyFont';
        }
        ```
        当浏览器渲染 `<p lang="ru">Привет</p>` 时，`LocaleToScriptCodeForFontSelection("ru")` 会返回 `USCRIPT_CYRILLIC`，浏览器会选择 `cyrillic.woff2` 中定义的字体来渲染俄语文本。

* **JavaScript:**
    - JavaScript 可以获取或设置 HTML 元素的 `lang` 属性，从而间接地影响字体选择。
    - JavaScript 的国际化 API (`Intl`) 可以根据用户的 locale 信息进行本地化处理，虽然 JavaScript 本身不直接调用 `LocaleToScriptCodeForFontSelection`，但这些 API 的底层实现可能依赖于类似的 locale 到脚本的映射逻辑。
    - **示例:**  一个 JavaScript 脚本可以动态地改变元素的 `lang` 属性：
      ```javascript
      const paragraph = document.getElementById('myParagraph');
      paragraph.lang = 'zh-TW'; // 将语言设置为繁体中文
      ```
      这将触发浏览器重新评估该段落的语言，并可能使用不同的字体进行渲染，而 `LocaleToScriptCodeForFontSelection("zh-TW")` 会返回 `USCRIPT_TRADITIONAL_HAN`。

**逻辑推理的假设输入与输出:**

上面在描述每个函数的功能时已经给出了假设输入和输出的例子。

**涉及用户或者编程常见的使用错误:**

1. **用户错误：**
   - **不正确的 `lang` 属性值:** 用户或开发者可能会在 HTML 中使用不正确的或不存在的 locale 代码。 例如，使用 "eng" 而不是 "en" 代表英语。 这会导致 `LocaleToScriptCodeForFontSelection` 无法找到正确的脚本映射，从而可能使用默认字体或者错误的字体进行渲染。
     - **示例:** `<p lang="eng">Hello</p>`  在这种情况下，`LocaleToScriptCodeForFontSelection("eng")` 可能无法找到匹配项，最终返回 `USCRIPT_COMMON`，使用的字体可能不是最合适的英文字体。
   - **`lang` 属性继承问题忽视:**  开发者可能没有意识到 `lang` 属性是可以继承的。如果在父元素上设置了错误的 `lang` 属性，其子元素也会继承该属性，除非子元素显式地设置了自己的 `lang` 属性。 这可能导致意外的字体渲染。

2. **编程错误：**
   - **Locale 字符串格式不一致:**  虽然 `LocaleToScriptCodeForFontSelection` 做了 `_` 到 `-` 的转换，但如果程序中处理 locale 字符串的方式不一致，可能会导致查找失败。
   - **假设所有语言都有唯一的脚本:** 开发者可能会错误地假设每种语言都只有一个对应的脚本。例如，塞尔维亚语 (sr) 可以使用西里尔字母 (sr-Cyrl) 或拉丁字母 (sr-Latn)。 仅仅使用 "sr" 作为输入可能会导致歧义。 `LocaleToScriptCodeForFontSelection` 通常会基于一些默认规则来处理这种情况，但这可能不是用户期望的。
   - **过度依赖默认字体:** 开发者可能没有充分测试不同语言环境下的字体渲染效果，过度依赖浏览器的默认字体，导致某些语言的显示效果不佳。 正确的做法是使用 CSS 的 `@font-face` 规则为不同的语言和脚本提供合适的字体。

总而言之， `locale_to_script_mapping.cc` 文件在 Blink 引擎中扮演着关键的角色，它通过将语言区域设置映射到相应的 Unicode 脚本，为浏览器选择合适的字体渲染不同语言的文本提供了基础，直接影响着用户在网页上看到的文本显示效果。 开发者理解其功能和使用场景，可以避免一些常见的国际化和本地化问题。

Prompt: 
```
这是目录为blink/renderer/platform/text/locale_to_script_mapping.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/text/locale_to_script_mapping.h"

#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"

namespace blink {

struct SubtagScript {
  const char* subtag;
  UScriptCode script;
};

UScriptCode ScriptNameToCode(const String& script_name) {
  // This generally maps an ISO 15924 script code to its UScriptCode, but
  // certain families of script codes are treated as a single script for
  // assigning a per-script font in Settings. For example, "hira" is mapped to
  // USCRIPT_KATAKANA_OR_HIRAGANA instead of USCRIPT_HIRAGANA, since we want all
  // Japanese scripts to be rendered using the same font setting.
  static constexpr SubtagScript kScriptNameCodeList[] = {
      {"zyyy", USCRIPT_COMMON},
      {"qaai", USCRIPT_INHERITED},
      {"arab", USCRIPT_ARABIC},
      {"armn", USCRIPT_ARMENIAN},
      {"beng", USCRIPT_BENGALI},
      {"bopo", USCRIPT_BOPOMOFO},
      {"cher", USCRIPT_CHEROKEE},
      {"copt", USCRIPT_COPTIC},
      {"cyrl", USCRIPT_CYRILLIC},
      {"dsrt", USCRIPT_DESERET},
      {"deva", USCRIPT_DEVANAGARI},
      {"ethi", USCRIPT_ETHIOPIC},
      {"geor", USCRIPT_GEORGIAN},
      {"goth", USCRIPT_GOTHIC},
      {"grek", USCRIPT_GREEK},
      {"gujr", USCRIPT_GUJARATI},
      {"guru", USCRIPT_GURMUKHI},
      {"hani", USCRIPT_HAN},
      {"hang", USCRIPT_HANGUL},
      {"hebr", USCRIPT_HEBREW},
      {"hira", USCRIPT_KATAKANA_OR_HIRAGANA},
      {"knda", USCRIPT_KANNADA},
      {"kana", USCRIPT_KATAKANA_OR_HIRAGANA},
      {"khmr", USCRIPT_KHMER},
      {"laoo", USCRIPT_LAO},
      {"latn", USCRIPT_LATIN},
      {"mlym", USCRIPT_MALAYALAM},
      {"mong", USCRIPT_MONGOLIAN},
      {"mymr", USCRIPT_MYANMAR},
      {"ogam", USCRIPT_OGHAM},
      {"ital", USCRIPT_OLD_ITALIC},
      {"orya", USCRIPT_ORIYA},
      {"runr", USCRIPT_RUNIC},
      {"sinh", USCRIPT_SINHALA},
      {"syrc", USCRIPT_SYRIAC},
      {"taml", USCRIPT_TAMIL},
      {"telu", USCRIPT_TELUGU},
      {"thaa", USCRIPT_THAANA},
      {"thai", USCRIPT_THAI},
      {"tibt", USCRIPT_TIBETAN},
      {"cans", USCRIPT_CANADIAN_ABORIGINAL},
      {"yiii", USCRIPT_YI},
      {"tglg", USCRIPT_TAGALOG},
      {"hano", USCRIPT_HANUNOO},
      {"buhd", USCRIPT_BUHID},
      {"tagb", USCRIPT_TAGBANWA},
      {"brai", USCRIPT_BRAILLE},
      {"cprt", USCRIPT_CYPRIOT},
      {"limb", USCRIPT_LIMBU},
      {"linb", USCRIPT_LINEAR_B},
      {"osma", USCRIPT_OSMANYA},
      {"shaw", USCRIPT_SHAVIAN},
      {"tale", USCRIPT_TAI_LE},
      {"ugar", USCRIPT_UGARITIC},
      {"hrkt", USCRIPT_KATAKANA_OR_HIRAGANA},
      {"bugi", USCRIPT_BUGINESE},
      {"glag", USCRIPT_GLAGOLITIC},
      {"khar", USCRIPT_KHAROSHTHI},
      {"sylo", USCRIPT_SYLOTI_NAGRI},
      {"talu", USCRIPT_NEW_TAI_LUE},
      {"tfng", USCRIPT_TIFINAGH},
      {"xpeo", USCRIPT_OLD_PERSIAN},
      {"bali", USCRIPT_BALINESE},
      {"batk", USCRIPT_BATAK},
      {"blis", USCRIPT_BLISSYMBOLS},
      {"brah", USCRIPT_BRAHMI},
      {"cham", USCRIPT_CHAM},
      {"cirt", USCRIPT_CIRTH},
      {"cyrs", USCRIPT_OLD_CHURCH_SLAVONIC_CYRILLIC},
      {"egyd", USCRIPT_DEMOTIC_EGYPTIAN},
      {"egyh", USCRIPT_HIERATIC_EGYPTIAN},
      {"egyp", USCRIPT_EGYPTIAN_HIEROGLYPHS},
      {"geok", USCRIPT_KHUTSURI},
      {"hans", USCRIPT_SIMPLIFIED_HAN},
      {"hant", USCRIPT_TRADITIONAL_HAN},
      {"hmng", USCRIPT_PAHAWH_HMONG},
      {"hung", USCRIPT_OLD_HUNGARIAN},
      {"inds", USCRIPT_HARAPPAN_INDUS},
      {"java", USCRIPT_JAVANESE},
      {"kali", USCRIPT_KAYAH_LI},
      {"latf", USCRIPT_LATIN_FRAKTUR},
      {"latg", USCRIPT_LATIN_GAELIC},
      {"lepc", USCRIPT_LEPCHA},
      {"lina", USCRIPT_LINEAR_A},
      {"mand", USCRIPT_MANDAEAN},
      {"maya", USCRIPT_MAYAN_HIEROGLYPHS},
      {"mero", USCRIPT_MEROITIC},
      {"nkoo", USCRIPT_NKO},
      {"orkh", USCRIPT_ORKHON},
      {"perm", USCRIPT_OLD_PERMIC},
      {"phag", USCRIPT_PHAGS_PA},
      {"phnx", USCRIPT_PHOENICIAN},
      {"plrd", USCRIPT_PHONETIC_POLLARD},
      {"roro", USCRIPT_RONGORONGO},
      {"sara", USCRIPT_SARATI},
      {"syre", USCRIPT_ESTRANGELO_SYRIAC},
      {"syrj", USCRIPT_WESTERN_SYRIAC},
      {"syrn", USCRIPT_EASTERN_SYRIAC},
      {"teng", USCRIPT_TENGWAR},
      {"vaii", USCRIPT_VAI},
      {"visp", USCRIPT_VISIBLE_SPEECH},
      {"xsux", USCRIPT_CUNEIFORM},
      {"jpan", USCRIPT_KATAKANA_OR_HIRAGANA},
      {"kore", USCRIPT_HANGUL},
      {"zxxx", USCRIPT_UNWRITTEN_LANGUAGES},
      {"zzzz", USCRIPT_UNKNOWN}};
  for (const auto& kv : kScriptNameCodeList) {
    if (EqualIgnoringASCIICase(script_name, kv.subtag))
      return kv.script;
  }
  return USCRIPT_INVALID_CODE;
}

UScriptCode LocaleToScriptCodeForFontSelection(const String& locale) {
  static constexpr SubtagScript kLocaleScriptList[] = {
      {"aa", USCRIPT_LATIN},
      {"ab", USCRIPT_CYRILLIC},
      {"ady", USCRIPT_CYRILLIC},
      {"aeb", USCRIPT_ARABIC},
      {"af", USCRIPT_LATIN},
      {"ak", USCRIPT_LATIN},
      {"am", USCRIPT_ETHIOPIC},
      {"ar", USCRIPT_ARABIC},
      {"arq", USCRIPT_ARABIC},
      {"ary", USCRIPT_ARABIC},
      {"arz", USCRIPT_ARABIC},
      {"as", USCRIPT_BENGALI},
      {"ast", USCRIPT_LATIN},
      {"av", USCRIPT_CYRILLIC},
      {"ay", USCRIPT_LATIN},
      {"az", USCRIPT_LATIN},
      {"azb", USCRIPT_ARABIC},
      {"ba", USCRIPT_CYRILLIC},
      {"bal", USCRIPT_ARABIC},
      {"be", USCRIPT_CYRILLIC},
      {"bej", USCRIPT_ARABIC},
      {"bg", USCRIPT_CYRILLIC},
      {"bi", USCRIPT_LATIN},
      {"bn", USCRIPT_BENGALI},
      {"bo", USCRIPT_TIBETAN},
      {"bqi", USCRIPT_ARABIC},
      {"brh", USCRIPT_ARABIC},
      {"bs", USCRIPT_LATIN},
      {"ca", USCRIPT_LATIN},
      {"ce", USCRIPT_CYRILLIC},
      {"ceb", USCRIPT_LATIN},
      {"ch", USCRIPT_LATIN},
      {"chk", USCRIPT_LATIN},
      {"cja", USCRIPT_ARABIC},
      {"cjm", USCRIPT_ARABIC},
      {"ckb", USCRIPT_ARABIC},
      {"cs", USCRIPT_LATIN},
      {"cy", USCRIPT_LATIN},
      {"da", USCRIPT_LATIN},
      {"dcc", USCRIPT_ARABIC},
      {"de", USCRIPT_LATIN},
      {"doi", USCRIPT_ARABIC},
      {"dv", USCRIPT_THAANA},
      {"dyo", USCRIPT_ARABIC},
      {"dz", USCRIPT_TIBETAN},
      {"ee", USCRIPT_LATIN},
      {"efi", USCRIPT_LATIN},
      {"el", USCRIPT_GREEK},
      {"en", USCRIPT_LATIN},
      {"es", USCRIPT_LATIN},
      {"et", USCRIPT_LATIN},
      {"eu", USCRIPT_LATIN},
      {"fa", USCRIPT_ARABIC},
      {"fi", USCRIPT_LATIN},
      {"fil", USCRIPT_LATIN},
      {"fj", USCRIPT_LATIN},
      {"fo", USCRIPT_LATIN},
      {"fr", USCRIPT_LATIN},
      {"fur", USCRIPT_LATIN},
      {"fy", USCRIPT_LATIN},
      {"ga", USCRIPT_LATIN},
      {"gaa", USCRIPT_LATIN},
      {"gba", USCRIPT_ARABIC},
      {"gbz", USCRIPT_ARABIC},
      {"gd", USCRIPT_LATIN},
      {"gil", USCRIPT_LATIN},
      {"gl", USCRIPT_LATIN},
      {"gjk", USCRIPT_ARABIC},
      {"gju", USCRIPT_ARABIC},
      {"glk", USCRIPT_ARABIC},
      {"gn", USCRIPT_LATIN},
      {"gsw", USCRIPT_LATIN},
      {"gu", USCRIPT_GUJARATI},
      {"ha", USCRIPT_LATIN},
      {"haw", USCRIPT_LATIN},
      {"haz", USCRIPT_ARABIC},
      {"he", USCRIPT_HEBREW},
      {"hi", USCRIPT_DEVANAGARI},
      {"hil", USCRIPT_LATIN},
      {"hnd", USCRIPT_ARABIC},
      {"hno", USCRIPT_ARABIC},
      {"ho", USCRIPT_LATIN},
      {"hr", USCRIPT_LATIN},
      {"ht", USCRIPT_LATIN},
      {"hu", USCRIPT_LATIN},
      {"hy", USCRIPT_ARMENIAN},
      {"id", USCRIPT_LATIN},
      {"ig", USCRIPT_LATIN},
      {"ii", USCRIPT_YI},
      {"ilo", USCRIPT_LATIN},
      {"inh", USCRIPT_CYRILLIC},
      {"is", USCRIPT_LATIN},
      {"it", USCRIPT_LATIN},
      {"iu", USCRIPT_CANADIAN_ABORIGINAL},
      {"ja", USCRIPT_KATAKANA_OR_HIRAGANA},
      {"jv", USCRIPT_LATIN},
      {"ka", USCRIPT_GEORGIAN},
      {"kaj", USCRIPT_LATIN},
      {"kam", USCRIPT_LATIN},
      {"kbd", USCRIPT_CYRILLIC},
      {"kha", USCRIPT_LATIN},
      {"khw", USCRIPT_ARABIC},
      {"kk", USCRIPT_CYRILLIC},
      {"kl", USCRIPT_LATIN},
      {"km", USCRIPT_KHMER},
      {"kn", USCRIPT_KANNADA},
      {"ko", USCRIPT_HANGUL},
      {"kok", USCRIPT_DEVANAGARI},
      {"kos", USCRIPT_LATIN},
      {"kpe", USCRIPT_LATIN},
      {"krc", USCRIPT_CYRILLIC},
      {"ks", USCRIPT_ARABIC},
      {"ku", USCRIPT_ARABIC},
      {"kum", USCRIPT_CYRILLIC},
      {"kvx", USCRIPT_ARABIC},
      {"kxp", USCRIPT_ARABIC},
      {"ky", USCRIPT_CYRILLIC},
      {"la", USCRIPT_LATIN},
      {"lah", USCRIPT_ARABIC},
      {"lb", USCRIPT_LATIN},
      {"lez", USCRIPT_CYRILLIC},
      {"lki", USCRIPT_ARABIC},
      {"ln", USCRIPT_LATIN},
      {"lo", USCRIPT_LAO},
      {"lrc", USCRIPT_ARABIC},
      {"lt", USCRIPT_LATIN},
      {"luz", USCRIPT_ARABIC},
      {"lv", USCRIPT_LATIN},
      {"mai", USCRIPT_DEVANAGARI},
      {"mdf", USCRIPT_CYRILLIC},
      {"mfa", USCRIPT_ARABIC},
      {"mg", USCRIPT_LATIN},
      {"mh", USCRIPT_LATIN},
      {"mi", USCRIPT_LATIN},
      {"mk", USCRIPT_CYRILLIC},
      {"ml", USCRIPT_MALAYALAM},
      {"mn", USCRIPT_CYRILLIC},
      {"mr", USCRIPT_DEVANAGARI},
      {"ms", USCRIPT_LATIN},
      {"mt", USCRIPT_LATIN},
      {"mvy", USCRIPT_ARABIC},
      {"my", USCRIPT_MYANMAR},
      {"myv", USCRIPT_CYRILLIC},
      {"mzn", USCRIPT_ARABIC},
      {"na", USCRIPT_LATIN},
      {"nb", USCRIPT_LATIN},
      {"ne", USCRIPT_DEVANAGARI},
      {"niu", USCRIPT_LATIN},
      {"nl", USCRIPT_LATIN},
      {"nn", USCRIPT_LATIN},
      {"nr", USCRIPT_LATIN},
      {"nso", USCRIPT_LATIN},
      {"ny", USCRIPT_LATIN},
      {"oc", USCRIPT_LATIN},
      {"om", USCRIPT_LATIN},
      {"or", USCRIPT_ORIYA},
      {"os", USCRIPT_CYRILLIC},
      {"pa", USCRIPT_GURMUKHI},
      {"pag", USCRIPT_LATIN},
      {"pap", USCRIPT_LATIN},
      {"pau", USCRIPT_LATIN},
      {"pl", USCRIPT_LATIN},
      {"pon", USCRIPT_LATIN},
      {"prd", USCRIPT_ARABIC},
      {"prs", USCRIPT_ARABIC},
      {"ps", USCRIPT_ARABIC},
      {"pt", USCRIPT_LATIN},
      {"qu", USCRIPT_LATIN},
      {"rm", USCRIPT_LATIN},
      {"rmt", USCRIPT_ARABIC},
      {"rn", USCRIPT_LATIN},
      {"ro", USCRIPT_LATIN},
      {"ru", USCRIPT_CYRILLIC},
      {"rw", USCRIPT_LATIN},
      {"sa", USCRIPT_DEVANAGARI},
      {"sah", USCRIPT_CYRILLIC},
      {"sat", USCRIPT_LATIN},
      {"sd", USCRIPT_ARABIC},
      {"sdh", USCRIPT_ARABIC},
      {"se", USCRIPT_LATIN},
      {"sg", USCRIPT_LATIN},
      {"shi", USCRIPT_ARABIC},
      {"si", USCRIPT_SINHALA},
      {"sid", USCRIPT_LATIN},
      {"sk", USCRIPT_LATIN},
      {"skr", USCRIPT_ARABIC},
      {"sl", USCRIPT_LATIN},
      {"sm", USCRIPT_LATIN},
      {"so", USCRIPT_LATIN},
      {"sq", USCRIPT_LATIN},
      {"sr", USCRIPT_CYRILLIC},
      {"ss", USCRIPT_LATIN},
      {"st", USCRIPT_LATIN},
      {"su", USCRIPT_LATIN},
      {"sus", USCRIPT_ARABIC},
      {"sv", USCRIPT_LATIN},
      {"sw", USCRIPT_LATIN},
      {"swb", USCRIPT_ARABIC},
      {"syr", USCRIPT_ARABIC},
      {"ta", USCRIPT_TAMIL},
      {"te", USCRIPT_TELUGU},
      {"tet", USCRIPT_LATIN},
      {"tg", USCRIPT_CYRILLIC},
      {"th", USCRIPT_THAI},
      {"ti", USCRIPT_ETHIOPIC},
      {"tig", USCRIPT_ETHIOPIC},
      {"tk", USCRIPT_LATIN},
      {"tkl", USCRIPT_LATIN},
      {"tl", USCRIPT_LATIN},
      {"tn", USCRIPT_LATIN},
      {"to", USCRIPT_LATIN},
      {"tpi", USCRIPT_LATIN},
      {"tr", USCRIPT_LATIN},
      {"trv", USCRIPT_LATIN},
      {"ts", USCRIPT_LATIN},
      {"tt", USCRIPT_CYRILLIC},
      {"ttt", USCRIPT_ARABIC},
      {"tvl", USCRIPT_LATIN},
      {"tw", USCRIPT_LATIN},
      {"ty", USCRIPT_LATIN},
      {"tyv", USCRIPT_CYRILLIC},
      {"udm", USCRIPT_CYRILLIC},
      {"ug", USCRIPT_ARABIC},
      {"uk", USCRIPT_CYRILLIC},
      {"und", USCRIPT_LATIN},
      {"ur", USCRIPT_ARABIC},
      {"uz", USCRIPT_CYRILLIC},
      {"ve", USCRIPT_LATIN},
      {"vi", USCRIPT_LATIN},
      {"wal", USCRIPT_ETHIOPIC},
      {"war", USCRIPT_LATIN},
      {"wo", USCRIPT_LATIN},
      {"xh", USCRIPT_LATIN},
      {"yap", USCRIPT_LATIN},
      {"yo", USCRIPT_LATIN},
      {"za", USCRIPT_LATIN},
      {"zdj", USCRIPT_ARABIC},
      {"zh", USCRIPT_SIMPLIFIED_HAN},
      {"zu", USCRIPT_LATIN},
      // Encompassed languages within the Chinese macrolanguage.
      // http://www-01.sil.org/iso639-3/documentation.asp?id=zho
      // http://lists.w3.org/Archives/Public/public-i18n-cjk/2016JulSep/0022.html
      {"cdo", USCRIPT_SIMPLIFIED_HAN},
      {"cjy", USCRIPT_SIMPLIFIED_HAN},
      {"cmn", USCRIPT_SIMPLIFIED_HAN},
      {"cpx", USCRIPT_SIMPLIFIED_HAN},
      {"czh", USCRIPT_SIMPLIFIED_HAN},
      {"czo", USCRIPT_SIMPLIFIED_HAN},
      {"gan", USCRIPT_SIMPLIFIED_HAN},
      {"hsn", USCRIPT_SIMPLIFIED_HAN},
      {"mnp", USCRIPT_SIMPLIFIED_HAN},
      {"wuu", USCRIPT_SIMPLIFIED_HAN},
      {"hak", USCRIPT_TRADITIONAL_HAN},
      {"lzh", USCRIPT_TRADITIONAL_HAN},
      {"nan", USCRIPT_TRADITIONAL_HAN},
      {"yue", USCRIPT_TRADITIONAL_HAN},
      {"zh-cdo", USCRIPT_SIMPLIFIED_HAN},
      {"zh-cjy", USCRIPT_SIMPLIFIED_HAN},
      {"zh-cmn", USCRIPT_SIMPLIFIED_HAN},
      {"zh-cpx", USCRIPT_SIMPLIFIED_HAN},
      {"zh-czh", USCRIPT_SIMPLIFIED_HAN},
      {"zh-czo", USCRIPT_SIMPLIFIED_HAN},
      {"zh-gan", USCRIPT_SIMPLIFIED_HAN},
      {"zh-hsn", USCRIPT_SIMPLIFIED_HAN},
      {"zh-mnp", USCRIPT_SIMPLIFIED_HAN},
      {"zh-wuu", USCRIPT_SIMPLIFIED_HAN},
      {"zh-hak", USCRIPT_TRADITIONAL_HAN},
      {"zh-lzh", USCRIPT_TRADITIONAL_HAN},
      {"zh-nan", USCRIPT_TRADITIONAL_HAN},
      {"zh-yue", USCRIPT_TRADITIONAL_HAN},
      // Chinese with regions. Logically, regions should be handled
      // separately, but this works for the current purposes.
      {"zh-hk", USCRIPT_TRADITIONAL_HAN},
      {"zh-mo", USCRIPT_TRADITIONAL_HAN},
      {"zh-tw", USCRIPT_TRADITIONAL_HAN},
  };

  // BCP 47 uses '-' as the delimiter but ICU uses '_'.
  // https://tools.ietf.org/html/bcp47
  String canonical_locale = locale;
  canonical_locale.Replace('_', '-');

  while (!canonical_locale.empty()) {
    for (const auto& kv : kLocaleScriptList) {
      if (EqualIgnoringASCIICase(canonical_locale, kv.subtag))
        return kv.script;
    }

    wtf_size_t pos = canonical_locale.ReverseFind('-');
    if (pos == kNotFound)
      break;
    // script = 4ALPHA
    if (canonical_locale.length() - (pos + 1) == 4) {
      UScriptCode code = ScriptNameToCode(canonical_locale.Substring(pos + 1));
      if (code != USCRIPT_INVALID_CODE && code != USCRIPT_UNKNOWN)
        return code;
    }
    canonical_locale = canonical_locale.Substring(0, pos);
  }
  return USCRIPT_COMMON;
}

static UScriptCode ScriptCodeForHanFromRegion(const String& region) {
  static constexpr SubtagScript kRegionScriptList[] = {
      {"hk", USCRIPT_TRADITIONAL_HAN}, {"jp", USCRIPT_KATAKANA_OR_HIRAGANA},
      {"kr", USCRIPT_HANGUL},          {"mo", USCRIPT_TRADITIONAL_HAN},
      {"tw", USCRIPT_TRADITIONAL_HAN},
  };
  for (const auto& kv : kRegionScriptList) {
    if (EqualIgnoringASCIICase(region, kv.subtag))
      return kv.script;
  }
  return USCRIPT_COMMON;
}

UScriptCode ScriptCodeForHanFromSubtags(const String& locale, char delimiter) {
  // Some sites emit lang="en-JP" when English is set as the preferred
  // language. Use script/region subtags of the content locale to pick the
  // fallback font for unified Han ideographs.
  for (wtf_size_t end = locale.find(delimiter); end != kNotFound;) {
    wtf_size_t begin = end + 1;
    end = locale.find(delimiter, begin);
    wtf_size_t len = (end == kNotFound ? locale.length() : end) - begin;
    UScriptCode script;
    switch (len) {
      case 2:  // region = 2ALPHA / 3DIGIT
        script = ScriptCodeForHanFromRegion(locale.Substring(begin, len));
        if (script != USCRIPT_COMMON)
          return script;
        break;
      case 4:  // script = 4ALPHA
        script = ScriptNameToCode(locale.Substring(begin, len));
        if (IsUnambiguousHanScript(script))
          return script;
    }
  }

  return USCRIPT_COMMON;
}

}  // namespace blink

"""

```
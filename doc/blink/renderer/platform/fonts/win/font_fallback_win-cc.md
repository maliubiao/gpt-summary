Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Skim and Goal Identification:**

The first step is a quick read-through to get the gist of the code. Keywords like "font," "fallback," "win," "script," "unicode," and "SkFontMgr" immediately stand out. The filename `font_fallback_win.cc` strongly suggests the primary function is to determine appropriate fallback fonts on Windows.

**2. Deeper Dive into Core Functionality:**

Next, I'd start examining the code more closely, focusing on key structures and functions:

* **`IsFontPresent`:** This function clearly checks if a given font name exists and is considered "present" by the system (with some extra logic for a runtime flag). This is fundamental to the fallback mechanism.

* **`FirstAvailableFont`:**  This function iterates through a list of candidate font names and returns the first one that `IsFontPresent` finds. This is the core of the prioritized fallback.

* **`FontMapping` and `ScriptToFontFamilies`:** These structs define how font families are associated with scripts. `FontMapping` holds the currently selected font and a list of candidates. `ScriptToFontFamilies` links a Unicode script code with a list of preferred font families.

* **`ScriptToFontMap`:** This class manages the mapping between script codes and `FontMapping` objects. The `Set` method populates this map.

* **`InitializeScriptFontMap`:** This function is crucial. It hardcodes a large table of script codes and their prioritized font lists. This is the knowledge base for font fallback. The comments mentioning MSDN documentation confirm this is based on Windows font recommendations.

* **`FindMonospaceFontForScript`:**  A specific function for finding monospace fonts based on script.

* **`GetScriptBasedOnUnicodeBlock` and `GetScript`:**  These functions handle the tricky part of determining the script of a given Unicode character. `GetScript` uses ICU, and `GetScriptBasedOnUnicodeBlock` provides a fallback if the script can't be determined directly.

* **`AvailableColorEmojiFont`, `AvailableMonoEmojiFont`, `FirstAvailableMathFont`:**  Specialized functions for finding appropriate fonts for emojis and math symbols.

* **`GetColorEmojiFont`, `GetMonoEmojiFont`, `GetMathFont`:** These functions use `DEFINE_THREAD_SAFE_STATIC_LOCAL` to cache the results of the availability checks, optimizing performance.

* **`GetFontBasedOnUnicodeBlock`:** Another fallback mechanism based on the Unicode block of a character, used for symbols and other specific character ranges.

* **`GetFontFamilyForScript`:** The main function for retrieving a font family for a given script and generic family (like monospace). It uses the `ScriptToFontMap`.

* **`GetFallbackFamily`:** The central function! It takes a character, generic family, locale, fallback priority, and font manager, and returns the most appropriate fallback font family. It handles emoji, falls back to script-specific fonts, and then has broader fallbacks.

**3. Identifying Relationships with Web Technologies (JavaScript, HTML, CSS):**

At this point, I would consider how this low-level code relates to the higher-level web technologies:

* **CSS `font-family`:** The most obvious connection. When a web developer specifies a `font-family`, and the browser doesn't find an exact match, this code (or something similar) is used to find suitable alternatives.

* **HTML `lang` attribute:** The code explicitly mentions using the `lang` attribute (and locale) to influence font selection for Han characters.

* **JavaScript (less direct):** JavaScript doesn't directly call this C++ code, but it can manipulate the DOM and CSS, thus indirectly influencing when this fallback logic is invoked. For example, dynamically adding text in a specific language.

**4. Constructing Examples and Scenarios:**

To solidify understanding, I'd create concrete examples:

* **CSS Fallback:** Imagine `font-family: 'Klingon', 'Arial', sans-serif;`. If "Klingon" isn't found, this code helps the browser decide if "Arial" is suitable, or what sans-serif font to use if "Arial" is missing or doesn't cover the necessary characters.

* **`lang` Attribute:**  If an HTML element has `<p lang="zh-CN">你好</p>`, this code uses the "zh-CN" to prioritize Simplified Chinese fonts when rendering "你好."

* **Emoji Handling:**  Demonstrating how the code differentiates between color and monochrome emoji presentation.

**5. Identifying Potential Errors and Assumptions:**

Finally, I would think about potential pitfalls:

* **User Missing Fonts:** The most common error. The code handles this by providing fallbacks, but the user experience might suffer if essential fonts are missing.

* **Incorrect `lang` Attribute:** If the `lang` attribute is wrong, the browser might choose an inappropriate font.

* **Platform Differences:** This specific code is for Windows. Font fallback works differently on other operating systems.

* **Complexity of Internationalization:**  Font fallback is a complex problem, and the hardcoded tables might not cover every possible scenario or user preference.

**Self-Correction/Refinement During the Process:**

* Initially, I might just focus on the script-to-font mapping. Then, realizing the importance of emoji and math symbol handling would lead me to examine those dedicated functions.

* Seeing the `DEFINE_THREAD_SAFE_STATIC_LOCAL` would prompt me to consider thread safety and performance optimizations.

*  The comments about potential improvements ("FIXME") are valuable clues about areas that could be further developed.

By following this structured approach – skimming, detailed reading, identifying connections, creating examples, and considering edge cases – I can arrive at a comprehensive understanding of the code and generate a detailed explanation like the example you provided.
这个C++源代码文件 `font_fallback_win.cc` 属于 Chromium Blink 渲染引擎，负责**在 Windows 平台上进行字体回退（Font Fallback）**。  简单来说，当浏览器需要渲染某个字符，但当前指定的字体中没有该字符的字形时，这个文件中的代码会尝试找到一个合适的后备字体来显示该字符。

下面列举其主要功能，并说明与 JavaScript, HTML, CSS 的关系，提供逻辑推理和用户/编程常见错误示例：

**功能列表:**

1. **维护 Unicode 脚本到首选字体家族的映射:**  代码中定义了一个名为 `ScriptToFontMap` 的类，它维护了一个 Unicode 脚本（例如，拉丁文、中文、阿拉伯文等）到一组**按优先级排序**的字体家族名称的映射。例如，对于阿拉伯文，优先尝试 "Tahoma"，如果不存在则尝试 "Segoe UI"。

2. **查找给定脚本的最合适的字体:** `GetFontFamilyForScript` 函数接收一个 Unicode 脚本和一个通用字体类型（例如，serif, sans-serif, monospace），并根据内部的映射关系，返回该脚本下最合适的可用字体家族的 `AtomicString`。

3. **根据 Unicode 字符查找回退字体:** `GetFallbackFamily` 函数是核心功能。它接收一个 Unicode 字符，通用字体类型，内容语言环境，回退优先级，字体管理器，并输出该字符所属的脚本。它会执行以下操作：
    * **优先处理 Emoji:** 如果字符是 Emoji，会尝试找到 Emoji 字体（彩色或单色）。
    * **基于 Unicode 块查找字体:**  对于某些特定的 Unicode 块（例如，数学符号，箭头），会尝试使用特定的符号字体。
    * **基于字符脚本查找字体:** 调用 `GetScript` 函数判断字符的 Unicode 脚本，然后调用 `GetFontFamilyForScript` 获取该脚本的推荐字体。
    * **处理全角 ASCII 字符:**  特殊处理全角 ASCII 字符，通常会将其视为汉字，使用汉字字体。
    * **处理非 BMP 字符:** 对于超出基本多文种平面（BMP）的字符，提供了一些硬编码的后备字体，例如 "code2001" 或中文字体扩展。
    * **提供最终回退字体:** 如果以上都找不到合适的字体，会使用一个最后的兜底字体，例如 "lucida sans unicode"。

4. **检测字体是否存在:** `IsFontPresent` 函数用于检查指定的字体是否存在于系统中。

5. **查找第一个可用的字体:** `FirstAvailableFont` 函数接收一个字体家族名称列表，并返回系统中第一个可用的字体名称。

6. **处理 Emoji 和数学符号:**  有专门的逻辑来查找和使用合适的 Emoji 字体（`Segoe UI Emoji`, `Segoe UI Symbol`）和数学符号字体 (`Cambria Math`, `Segoe UI Symbol`).

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件是浏览器渲染引擎的一部分，它的功能直接影响着网页在用户界面上的呈现。

* **CSS `font-family` 属性:**  当网页的 CSS 样式中指定了 `font-family` 属性时，例如：
  ```css
  body {
    font-family: "Helvetica Neue", Arial, sans-serif;
  }
  ```
  浏览器会按照顺序尝试使用这些字体。如果用户的系统中没有 "Helvetica Neue"，则会尝试 "Arial"。如果 "Arial" 也不存在，或者 "Arial" 中没有包含要渲染的字符，那么 `font_fallback_win.cc` 中的代码就会介入，根据字符的脚本和内部的映射关系，找到一个合适的 `sans-serif` 后备字体来显示文字。

* **HTML `lang` 属性:** HTML 的 `lang` 属性用于指定元素的语言，例如：
  ```html
  <p lang="zh">你好</p>
  <p lang="ar">مرحبا</p>
  ```
  `font_fallback_win.cc` 中的代码会考虑 `lang` 属性，为不同语言的文字选择合适的字体。例如，对于 `lang="zh"` 的中文内容，会优先选择中文字体。

* **JavaScript (间接关系):** JavaScript 可以动态地修改 HTML 结构和 CSS 样式，从而间接地影响字体回退的发生。例如，JavaScript 可以动态地添加包含特定 Unicode 字符的文本，或者修改元素的 `lang` 属性，从而触发不同的字体回退逻辑。

**逻辑推理示例（假设输入与输出）：**

**假设输入:**

* 需要渲染的字符: `U+4E00` (中文 "一")
* CSS `font-family`: "MyCustomFont", "Arial", "sans-serif"
* 用户系统中没有 "MyCustomFont"
* 用户系统中安装了 "Arial" 并且 "Arial" 包含 "一" 的字形

**输出:**

* 浏览器会使用 "Arial" 字体渲染 "一"。  `font_fallback_win.cc` 不会介入，因为在 `font-family` 列表中找到了合适的字体。

**假设输入:**

* 需要渲染的字符: `U+4E00` (中文 "一")
* CSS `font-family`: "MyCustomFont", "DoesNotExist", "sans-serif"
* 用户系统中没有 "MyCustomFont" 和 "DoesNotExist"

**输出:**

* `GetFallbackFamily` 函数会被调用。
* `GetScript(U+4E00)` 会返回 `USCRIPT_HAN` (汉字脚本)。
* `GetFontFamilyForScript(USCRIPT_HAN, FontDescription::kGenericFamilySans)` 会根据内部映射找到一个合适的 sans-serif 中文字体，例如 "Microsoft YaHei" 或 "simsun"。
* 浏览器会使用找到的中文 sans-serif 字体渲染 "一"。

**用户或编程常见的使用错误示例：**

1. **用户缺少必要的字体:**  最常见的问题是用户系统中没有安装网页指定的字体，也没有安装支持特定语言或字符的后备字体。例如，如果网页指定了某个特殊的日文字体，但用户没有安装，且默认的后备字体不包含日文字形，就会出现乱码或显示为方块。

2. **CSS 中字体回退列表顺序不合理:** 开发者应该将最希望使用的字体放在 `font-family` 列表的最前面，并提供合适的通用字体族（如 `serif`, `sans-serif`, `monospace`) 作为最后的保障。如果顺序不合理，可能会导致浏览器使用了不理想的后备字体。

   **错误示例:**
   ```css
   body {
     font-family: sans-serif, "MyPreferredFont"; /* 应该反过来 */
   }
   ```
   在这种情况下，即使 "MyPreferredFont" 存在，浏览器也会优先尝试使用系统默认的 `sans-serif` 字体。

3. **`lang` 属性使用不当:**  如果网页内容是某种语言，但 `lang` 属性设置错误或缺失，可能导致浏览器选择了不合适的字体。例如，中文内容但 `lang` 属性设置为 `en`，可能会导致浏览器使用英文字体进行渲染。

4. **假设所有用户都有相同的字体:**  开发者不应该假设所有用户的系统中都安装了特定的非通用字体。应该始终提供合理的字体回退方案，以确保网页在各种环境下都能正确显示。

5. **过度依赖 JavaScript 进行字体处理:** 虽然 JavaScript 可以进行一些字体相关的操作，但字体回退的核心逻辑通常由浏览器引擎处理。过度依赖 JavaScript 可能会导致性能问题或兼容性问题。

总而言之，`font_fallback_win.cc` 是 Chromium 在 Windows 平台上实现字体回退的关键组件，它根据 Unicode 脚本和字符属性，以及用户系统安装的字体情况，为网页内容选择合适的字体进行渲染，确保用户能够看到正确的文字显示。理解其工作原理有助于开发者更好地设计网页的字体方案，提高用户体验。

### 提示词
```
这是目录为blink/renderer/platform/fonts/win/font_fallback_win.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (c) 2006, 2007, 2008, 2009, 2010, 2012 Google Inc. All rights
 * reserved.
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

#include "third_party/blink/renderer/platform/fonts/win/font_fallback_win.h"

#include <unicode/uchar.h>

#include <limits>

#include "base/check_op.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_fallback_priority.h"
#include "third_party/blink/renderer/platform/text/icu_error.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/skia/include/core/SkFontMgr.h"
#include "third_party/skia/include/core/SkTypeface.h"

namespace blink {

namespace {

inline bool IsFontPresent(const char* font_name_utf8,
                          const SkFontMgr& font_manager) {
  sk_sp<SkTypeface> tf(
      font_manager.matchFamilyStyle(font_name_utf8, SkFontStyle()));
  if (!tf)
    return false;

  if (RuntimeEnabledFeatures::FontPresentWinEnabled()) {
    return true;
  }

  const String font_name = String::FromUTF8(font_name_utf8);
  SkTypeface::LocalizedStrings* actual_families =
      tf->createFamilyNameIterator();
  bool matches_requested_family = false;
  SkTypeface::LocalizedString actual_family;
  while (actual_families->next(&actual_family)) {
    if (DeprecatedEqualIgnoringCase(
            font_name, String::FromUTF8(actual_family.fString.c_str()))) {
      matches_requested_family = true;
      break;
    }
  }
  actual_families->unref();

  return matches_requested_family;
}

const char* FirstAvailableFont(
    base::span<const char* const> candidate_family_names,
    const SkFontMgr& font_manager) {
  for (const char* family : candidate_family_names) {
    if (IsFontPresent(family, font_manager)) {
      return family;
    }
  }
  return nullptr;
}

struct FontMapping {
  const char* FirstAvailableFont(const SkFontMgr& font_manager) {
    if (!candidate_family_names.empty()) {
      family_name =
          blink::FirstAvailableFont(candidate_family_names, font_manager);
      candidate_family_names = {};
    }
    return family_name;
  }

  const char* family_name;
  base::span<const char* const> candidate_family_names;
};

struct ScriptToFontFamilies {
  UScriptCode script;
  base::span<const char* const> families;
};

// A simple mapping from UScriptCode to family name. This is a sparse array,
// which works well since the range of UScriptCode values is small.
class ScriptToFontMap {
 public:
  static constexpr UScriptCode kSize = USCRIPT_CODE_LIMIT;

  FontMapping& operator[](UScriptCode script) { return mappings_[script]; }

  void Set(base::span<const ScriptToFontFamilies> families) {
    for (const auto& family : families) {
      mappings_[family.script].candidate_family_names = family.families;
    }
  }

 private:
  FontMapping mappings_[kSize];
};

const AtomicString& FindMonospaceFontForScript(UScriptCode script) {
  if (script == USCRIPT_ARABIC || script == USCRIPT_HEBREW) {
    DEFINE_THREAD_SAFE_STATIC_LOCAL(AtomicString, kCourierNew, ("courier new"));
    return kCourierNew;
  }
  return g_null_atom;
}

void InitializeScriptFontMap(ScriptToFontMap& script_font_map) {
  // For the following scripts, multiple fonts may be listed. They are tried
  // in order. The first slot is preferred but the font may not be available,
  // if so the remaining slots are tried in order.
  // In general the order is the Windows 10 font follow by the 8.1, 8.0 and
  // finally the font for Windows 7.
  // For scripts where an optional or region specific font may be available
  // that should be listed before the generic one.
  // Based on the "Script and Font Support in Windows" MSDN documentation [1]
  // with overrides and additional fallbacks as needed.
  // 1: https://msdn.microsoft.com/en-us/goglobal/bb688099.aspx
  static const char* const kArabicFonts[] = {"Tahoma", "Segoe UI"};
  static const char* const kArmenianFonts[] = {"Segoe UI", "Sylfaen"};
  static const char* const kBengaliFonts[] = {"Nirmala UI", "Vrinda"};
  static const char* const kBrahmiFonts[] = {"Segoe UI Historic"};
  static const char* const kBrailleFonts[] = {"Segoe UI Symbol"};
  static const char* const kBugineseFonts[] = {"Leelawadee UI"};
  static const char* const kCanadianAaboriginalFonts[] = {"Gadugi", "Euphemia"};
  static const char* const kCarianFonts[] = {"Segoe UI Historic"};
  static const char* const kCherokeeFonts[] = {"Gadugi", "Plantagenet"};
  static const char* const kCopticFonts[] = {"Segoe UI Symbol"};
  static const char* const kCuneiformFonts[] = {"Segoe UI Historic"};
  static const char* const kCypriotFonts[] = {"Segoe UI Historic"};
  static const char* const kCyrillicFonts[] = {"Times New Roman"};
  static const char* const kDeseretFonts[] = {"Segoe UI Symbol"};
  static const char* const kDevanagariFonts[] = {"Nirmala UI", "Mangal"};
  static const char* const kEgyptianHieroglyphsFonts[] = {"Segoe UI Historic"};
  static const char* const kEthiopicFonts[] = {"Nyala",
                                               "Abyssinica SIL",
                                               "Ethiopia Jiret",
                                               "Visual Geez Unicode",
                                               "GF Zemen Unicode",
                                               "Ebrima"};
  static const char* const kGeorgianFonts[] = {"Sylfaen", "Segoe UI"};
  static const char* const kGlagoliticFonts[] = {"Segoe UI Historic",
                                                 "Segoe UI Symbol"};
  static const char* const kGothicFonts[] = {"Segoe UI Historic",
                                             "Segoe UI Symbol"};
  static const char* const kGreekFonts[] = {"Times New Roman"};
  static const char* const kGujaratiFonts[] = {"Nirmala UI", "Shruti"};
  static const char* const kGurmukhiFonts[] = {"Nirmala UI", "Raavi"};
  static const char* const kHangulFonts[] = {"Noto Sans KR", "Noto Sans CJK KR",
                                             "Malgun Gothic", "Gulim"};
  static const char* const kHangulFontsNoNoto[] = {"Malgun Gothic", "Gulim"};
  static const char* const kHebrewFonts[] = {"David", "Segoe UI"};
  static const char* const kImperialAramaicFonts[] = {"Segoe UI Historic"};
  static const char* const kInscriptionalPahlaviFonts[] = {"Segoe UI Historic"};
  static const char* const kInscriptionalParthianFonts[] = {
      "Segoe UI Historic"};
  static const char* const kJavaneseFonts[] = {"Javanese Text"};
  static const char* const kKannadaFonts[] = {"Tunga", "Nirmala UI"};
  static const char* const kKatakanaOrHiraganaFonts[] = {
      "Noto Sans JP", "Noto Sans CJK JP", "Meiryo",
      "Yu Gothic",    "MS PGothic",       "Microsoft YaHei"};
  static const char* const kKatakanaOrHiraganaFontsNoNoto[] = {
      "Meiryo", "Yu Gothic", "MS PGothic", "Microsoft YaHei"};
  static const char* const kKharoshthiFonts[] = {"Segoe UI Historic"};
  // Try Khmer OS before Vista fonts as it goes along better with Latin
  // and looks better/larger for the same size.
  static const char* const kKhmerFonts[] = {
      "Leelawadee UI", "Khmer UI", "Khmer OS", "MoolBoran", "DaunPenh"};
  static const char* const kLaoFonts[] = {"Leelawadee UI", "Lao UI",
                                          "DokChampa",     "Saysettha OT",
                                          "Phetsarath OT", "Code2000"};
  static const char* const kLatinFonts[] = {"Times New Roman"};
  static const char* const kLisuFonts[] = {"Segoe UI"};
  static const char* const kLycianFonts[] = {"Segoe UI Historic"};
  static const char* const kLydianFonts[] = {"Segoe UI Historic"};
  static const char* const kMalayalamFonts[] = {"Nirmala UI", "Kartika"};
  static const char* const kMeroiticCursiveFonts[] = {"Segoe UI Historic",
                                                      "Segoe UI Symbol"};
  static const char* const kMongolianFonts[] = {"Mongolian Baiti"};
  static const char* const kMyanmarFonts[] = {
      "Myanmar Text", "Padauk", "Parabaik", "Myanmar3", "Code2000"};
  static const char* const kNewTaiLueFonts[] = {"Microsoft New Tai Lue"};
  static const char* const kNkoFonts[] = {"Ebrima"};
  static const char* const kOghamFonts[] = {"Segoe UI Historic",
                                            "Segoe UI Symbol"};
  static const char* const kOlChikiFonts[] = {"Nirmala UI"};
  static const char* const kOldItalicFonts[] = {"Segoe UI Historic",
                                                "Segoe UI Symbol"};
  static const char* const kOldPersianFonts[] = {"Segoe UI Historic"};
  static const char* const kOldSouthArabianFonts[] = {"Segoe UI Historic"};
  static const char* const kOriyaFonts[] = {"Kalinga", "ori1Uni", "Lohit Oriya",
                                            "Nirmala UI"};
  static const char* const kOrkhonFonts[] = {"Segoe UI Historic",
                                             "Segoe UI Symbol"};
  static const char* const kOsmanyaFonts[] = {"Ebrima"};
  static const char* const kPhagsPaFonts[] = {"Microsoft PhagsPa"};
  static const char* const kRunicFonts[] = {"Segoe UI Historic",
                                            "Segoe UI Symbol"};
  static const char* const kShavianFonts[] = {"Segoe UI Historic"};
  static const char* const kSimplifiedHanFonts[] = {
      "Noto Sans SC", "Noto Sans CJK SC", "Microsoft YaHei", "simsun"};
  static const char* const kSimplifiedHanFontsNoNoto[] = {"Microsoft YaHei",
                                                          "simsun"};
  static const char* const kSinhalaFonts[] = {"Iskoola Pota", "AksharUnicode",
                                              "Nirmala UI"};
  static const char* const kSoraSompengFonts[] = {"Nirmala UI"};
  static const char* const kSymbolsFonts[] = {"Segoe UI Symbol"};
  static const char* const kSyriacFonts[] = {"Estrangelo Edessa",
                                             "Estrangelo Nisibin", "Code2000"};
  static const char* const kTaiLeFonts[] = {"Microsoft Tai Le"};
  static const char* const kTamilFonts[] = {"Nirmala UI", "Latha"};
  static const char* const kTeluguFonts[] = {"Nirmala UI", "Gautami"};
  static const char* const kThaanaFonts[] = {"MV Boli"};
  static const char* const kThaiFonts[] = {"Tahoma", "Leelawadee UI",
                                           "Leelawadee"};
  static const char* const kTibetanFonts[] = {"Microsoft Himalaya", "Jomolhari",
                                              "Tibetan Machine Uni"};
  static const char* const kTifinaghFonts[] = {"Ebrima"};
  static const char* const kTraditionalHanFonts[] = {
      "Noto Sans TC", "Noto Sans CJK TC", "Microsoft JhengHei", "pmingli"};
  static const char* const kTraditionalHanFontsNoNoto[] = {"Microsoft JhengHei",
                                                           "pmingli"};
  static const char* const kVaiFonts[] = {"Ebrima"};
  static const char* const kYiFonts[] = {"Microsoft Yi Baiti", "Nuosu SIL",
                                         "Code2000"};

  static const ScriptToFontFamilies kScriptToFontFamilies[] = {
      {USCRIPT_ARABIC, kArabicFonts},
      {USCRIPT_ARMENIAN, kArmenianFonts},
      {USCRIPT_BENGALI, kBengaliFonts},
      {USCRIPT_BRAHMI, kBrahmiFonts},
      {USCRIPT_BRAILLE, kBrailleFonts},
      {USCRIPT_BUGINESE, kBugineseFonts},
      {USCRIPT_CANADIAN_ABORIGINAL, kCanadianAaboriginalFonts},
      {USCRIPT_CARIAN, kCarianFonts},
      {USCRIPT_CHEROKEE, kCherokeeFonts},
      {USCRIPT_COPTIC, kCopticFonts},
      {USCRIPT_CUNEIFORM, kCuneiformFonts},
      {USCRIPT_CYPRIOT, kCypriotFonts},
      {USCRIPT_CYRILLIC, kCyrillicFonts},
      {USCRIPT_DESERET, kDeseretFonts},
      {USCRIPT_DEVANAGARI, kDevanagariFonts},
      {USCRIPT_EGYPTIAN_HIEROGLYPHS, kEgyptianHieroglyphsFonts},
      {USCRIPT_ETHIOPIC, kEthiopicFonts},
      {USCRIPT_GEORGIAN, kGeorgianFonts},
      {USCRIPT_GLAGOLITIC, kGlagoliticFonts},
      {USCRIPT_GOTHIC, kGothicFonts},
      {USCRIPT_GREEK, kGreekFonts},
      {USCRIPT_GUJARATI, kGujaratiFonts},
      {USCRIPT_GURMUKHI, kGurmukhiFonts},
      {USCRIPT_HANGUL, kHangulFonts},
      {USCRIPT_HEBREW, kHebrewFonts},
      {USCRIPT_HIRAGANA, kKatakanaOrHiraganaFonts},
      {USCRIPT_IMPERIAL_ARAMAIC, kImperialAramaicFonts},
      {USCRIPT_INSCRIPTIONAL_PAHLAVI, kInscriptionalPahlaviFonts},
      {USCRIPT_INSCRIPTIONAL_PARTHIAN, kInscriptionalParthianFonts},
      {USCRIPT_JAVANESE, kJavaneseFonts},
      {USCRIPT_KANNADA, kKannadaFonts},
      {USCRIPT_KATAKANA, kKatakanaOrHiraganaFonts},
      {USCRIPT_KATAKANA_OR_HIRAGANA, kKatakanaOrHiraganaFonts},
      {USCRIPT_KHAROSHTHI, kKharoshthiFonts},
      {USCRIPT_KHMER, kKhmerFonts},
      {USCRIPT_LAO, kLaoFonts},
      {USCRIPT_LATIN, kLatinFonts},
      {USCRIPT_LISU, kLisuFonts},
      {USCRIPT_LYCIAN, kLycianFonts},
      {USCRIPT_LYDIAN, kLydianFonts},
      {USCRIPT_MALAYALAM, kMalayalamFonts},
      {USCRIPT_MEROITIC_CURSIVE, kMeroiticCursiveFonts},
      {USCRIPT_MONGOLIAN, kMongolianFonts},
      {USCRIPT_MYANMAR, kMyanmarFonts},
      {USCRIPT_NEW_TAI_LUE, kNewTaiLueFonts},
      {USCRIPT_NKO, kNkoFonts},
      {USCRIPT_OGHAM, kOghamFonts},
      {USCRIPT_OL_CHIKI, kOlChikiFonts},
      {USCRIPT_OLD_ITALIC, kOldItalicFonts},
      {USCRIPT_OLD_PERSIAN, kOldPersianFonts},
      {USCRIPT_OLD_SOUTH_ARABIAN, kOldSouthArabianFonts},
      {USCRIPT_ORIYA, kOriyaFonts},
      {USCRIPT_ORKHON, kOrkhonFonts},
      {USCRIPT_OSMANYA, kOsmanyaFonts},
      {USCRIPT_PHAGS_PA, kPhagsPaFonts},
      {USCRIPT_RUNIC, kRunicFonts},
      {USCRIPT_SHAVIAN, kShavianFonts},
      {USCRIPT_SIMPLIFIED_HAN, kSimplifiedHanFonts},
      {USCRIPT_SINHALA, kSinhalaFonts},
      {USCRIPT_SORA_SOMPENG, kSoraSompengFonts},
      {USCRIPT_SYMBOLS, kSymbolsFonts},
      {USCRIPT_SYRIAC, kSyriacFonts},
      {USCRIPT_TAI_LE, kTaiLeFonts},
      {USCRIPT_TAMIL, kTamilFonts},
      {USCRIPT_TELUGU, kTeluguFonts},
      {USCRIPT_THAANA, kThaanaFonts},
      {USCRIPT_THAI, kThaiFonts},
      {USCRIPT_TIBETAN, kTibetanFonts},
      {USCRIPT_TIFINAGH, kTifinaghFonts},
      {USCRIPT_TRADITIONAL_HAN, kTraditionalHanFonts},
      {USCRIPT_VAI, kVaiFonts},
      {USCRIPT_YI, kYiFonts}};
  script_font_map.Set(kScriptToFontFamilies);

  if (!RuntimeEnabledFeatures::FontSystemFallbackNotoCjkEnabled())
      [[unlikely]] {
    const ScriptToFontFamilies no_noto[] = {
        {USCRIPT_HANGUL, kHangulFontsNoNoto},
        {USCRIPT_HIRAGANA, kKatakanaOrHiraganaFontsNoNoto},
        {USCRIPT_KATAKANA, kKatakanaOrHiraganaFontsNoNoto},
        {USCRIPT_KATAKANA_OR_HIRAGANA, kKatakanaOrHiraganaFontsNoNoto},
        {USCRIPT_SIMPLIFIED_HAN, kSimplifiedHanFontsNoNoto},
        {USCRIPT_TRADITIONAL_HAN, kTraditionalHanFontsNoNoto},
    };
    script_font_map.Set(no_noto);
  }

  // Initialize the locale-dependent mapping from system locale.
  UScriptCode han_script = LayoutLocale::GetSystem().GetScriptForHan();
  DCHECK_NE(han_script, USCRIPT_HAN);
  const FontMapping& han_mapping = script_font_map[han_script];
  if (!han_mapping.candidate_family_names.empty()) {
    script_font_map[USCRIPT_HAN].candidate_family_names =
        han_mapping.candidate_family_names;
  }
}

// There are a lot of characters in USCRIPT_COMMON that can be covered
// by fonts for scripts closely related to them. See
// http://unicode.org/cldr/utility/list-unicodeset.jsp?a=[:Script=Common:]
// FIXME: make this more efficient with a wider coverage
UScriptCode GetScriptBasedOnUnicodeBlock(int ucs4) {
  UBlockCode block = ublock_getCode(ucs4);
  switch (block) {
    case UBLOCK_CJK_SYMBOLS_AND_PUNCTUATION:
      return USCRIPT_HAN;
    case UBLOCK_HIRAGANA:
    case UBLOCK_KATAKANA:
      return USCRIPT_KATAKANA_OR_HIRAGANA;
    case UBLOCK_ARABIC:
      return USCRIPT_ARABIC;
    case UBLOCK_THAI:
      return USCRIPT_THAI;
    case UBLOCK_GREEK:
      return USCRIPT_GREEK;
    case UBLOCK_DEVANAGARI:
      // For Danda and Double Danda (U+0964, U+0965), use a Devanagari
      // font for now although they're used by other scripts as well.
      // Without a context, we can't do any better.
      return USCRIPT_DEVANAGARI;
    case UBLOCK_ARMENIAN:
      return USCRIPT_ARMENIAN;
    case UBLOCK_GEORGIAN:
      return USCRIPT_GEORGIAN;
    case UBLOCK_KANNADA:
      return USCRIPT_KANNADA;
    case UBLOCK_GOTHIC:
      return USCRIPT_GOTHIC;
    default:
      return USCRIPT_COMMON;
  }
}

UScriptCode GetScript(int ucs4) {
  ICUError err;
  UScriptCode script = uscript_getScript(ucs4, &err);
  // If script is invalid, common or inherited or there's an error,
  // infer a script based on the unicode block of a character.
  if (script <= USCRIPT_INHERITED || U_FAILURE(err))
    script = GetScriptBasedOnUnicodeBlock(ucs4);
  return script;
}

const char* AvailableColorEmojiFont(const SkFontMgr& font_manager) {
  static const char* const kEmojiFonts[] = {"Segoe UI Emoji",
                                            "Segoe UI Symbol"};
  static const char* emoji_font = nullptr;
  // `std::once()` may cause hangs. crbug.com/349456407
  static bool initialized = false;
  if (!initialized) {
    emoji_font = FirstAvailableFont(kEmojiFonts, font_manager);
    initialized = true;
  }
  return emoji_font;
}

const char* AvailableMonoEmojiFont(const SkFontMgr& font_manager) {
  static const char* const kEmojiFonts[] = {"Segoe UI Symbol",
                                            "Segoe UI Emoji"};
  static const char* emoji_font = nullptr;
  // `std::once()` may cause hangs. crbug.com/349456407
  static bool initialized = false;
  if (!initialized) {
    emoji_font = FirstAvailableFont(kEmojiFonts, font_manager);
    initialized = true;
  }
  return emoji_font;
}

const char* FirstAvailableMathFont(const SkFontMgr& font_manager) {
  static const char* const kMathFonts[] = {"Cambria Math", "Segoe UI Symbol",
                                           "Code2000"};
  static const char* math_font = nullptr;
  // `std::once()` may cause hangs. crbug.com/349456407
  static bool initialized = false;
  if (!initialized) {
    math_font = FirstAvailableFont(kMathFonts, font_manager);
    initialized = true;
  }
  return math_font;
}

const AtomicString& GetColorEmojiFont(const SkFontMgr& font_manager) {
  // Calling `AvailableColorEmojiFont()` from `DEFINE_THREAD_SAFE_STATIC_LOCAL`
  // may cause hangs. crbug.com/349456407
  DEFINE_THREAD_SAFE_STATIC_LOCAL(AtomicString, emoji_font, (g_empty_atom));
  if (emoji_font.empty() && !emoji_font.IsNull()) {
    emoji_font = AtomicString(AvailableColorEmojiFont(font_manager));
    CHECK(!emoji_font.empty() || emoji_font.IsNull());
  }
  return emoji_font;
}

const AtomicString& GetMonoEmojiFont(const SkFontMgr& font_manager) {
  // Calling `AvailableMonoEmojiFont()` from `DEFINE_THREAD_SAFE_STATIC_LOCAL`
  // may cause hangs. crbug.com/349456407
  DEFINE_THREAD_SAFE_STATIC_LOCAL(AtomicString, emoji_font, (g_empty_atom));
  if (emoji_font.empty() && !emoji_font.IsNull()) {
    emoji_font = AtomicString(AvailableMonoEmojiFont(font_manager));
    CHECK(!emoji_font.empty() || emoji_font.IsNull());
  }
  return emoji_font;
}

const AtomicString& GetMathFont(const SkFontMgr& font_manager) {
  // Calling `AvailableMonoEmojiFont()` from `DEFINE_THREAD_SAFE_STATIC_LOCAL`
  // may cause hangs. crbug.com/349456407
  DEFINE_THREAD_SAFE_STATIC_LOCAL(AtomicString, math_font, (g_empty_atom));
  if (math_font.empty() && !math_font.IsNull()) {
    math_font = AtomicString(FirstAvailableMathFont(font_manager));
    CHECK(!math_font.empty() || math_font.IsNull());
  }
  return math_font;
}

const AtomicString& GetFontBasedOnUnicodeBlock(UBlockCode block_code,
                                               const SkFontMgr& font_manager) {
  switch (block_code) {
    case UBLOCK_EMOTICONS:
    case UBLOCK_ENCLOSED_ALPHANUMERIC_SUPPLEMENT:
      // We call this function only when FallbackPriority is not kEmojiEmoji or
      // kEmojiEmojiWithVS, so we need a text presentation of emoji.
      return GetMonoEmojiFont(font_manager);
    case UBLOCK_PLAYING_CARDS:
    case UBLOCK_MISCELLANEOUS_SYMBOLS:
    case UBLOCK_MISCELLANEOUS_SYMBOLS_AND_ARROWS:
    case UBLOCK_MISCELLANEOUS_SYMBOLS_AND_PICTOGRAPHS:
    case UBLOCK_TRANSPORT_AND_MAP_SYMBOLS:
    case UBLOCK_ALCHEMICAL_SYMBOLS:
    case UBLOCK_DINGBATS:
    case UBLOCK_GOTHIC: {
      DEFINE_THREAD_SAFE_STATIC_LOCAL(AtomicString, kSymbolFont,
                                      ("Segoe UI Symbol"));
      return kSymbolFont;
    }
    case UBLOCK_ARROWS:
    case UBLOCK_MATHEMATICAL_OPERATORS:
    case UBLOCK_MISCELLANEOUS_TECHNICAL:
    case UBLOCK_GEOMETRIC_SHAPES:
    case UBLOCK_MISCELLANEOUS_MATHEMATICAL_SYMBOLS_A:
    case UBLOCK_SUPPLEMENTAL_ARROWS_A:
    case UBLOCK_SUPPLEMENTAL_ARROWS_B:
    case UBLOCK_MISCELLANEOUS_MATHEMATICAL_SYMBOLS_B:
    case UBLOCK_SUPPLEMENTAL_MATHEMATICAL_OPERATORS:
    case UBLOCK_MATHEMATICAL_ALPHANUMERIC_SYMBOLS:
    case UBLOCK_ARABIC_MATHEMATICAL_ALPHABETIC_SYMBOLS:
    case UBLOCK_GEOMETRIC_SHAPES_EXTENDED:
      return GetMathFont(font_manager);
    default:
      return g_null_atom;
  }
}

}  // namespace

// FIXME: this is font fallback code version 0.1
//  - Cover all the scripts
//  - Get the default font for each script/generic family from the
//    preference instead of hardcoding in the source.
//    (at least, read values from the registry for IE font settings).
//  - Support generic families (from FontDescription)
//  - If the default font for a script is not available,
//    try some more fonts known to support it. Finally, we can
//    use EnumFontFamilies or similar APIs to come up with a list of
//    fonts supporting the script and cache the result.
//  - Consider using UnicodeSet (or UnicodeMap) converted from
//    GLYPHSET (BMP) or directly read from truetype cmap tables to
//    keep track of which character is supported by which font
//  - Update script_font_cache in response to WM_FONTCHANGE

const AtomicString& GetFontFamilyForScript(
    UScriptCode script,
    FontDescription::GenericFamilyType generic,
    const SkFontMgr& font_manager) {
  if (script < 0 || script >= ScriptToFontMap::kSize) [[unlikely]] {
    return g_null_atom;
  }

  if (generic == FontDescription::kMonospaceFamily) {
    if (const AtomicString& family = FindMonospaceFontForScript(script)) {
      return family;
    }
  }

  // Try the `AtomicString` cache first. `AtomicString` must be per thread, and
  // thus it can't be added to `ScriptToFontMap`.
  struct AtomicFamilies {
    std::optional<AtomicString> families[ScriptToFontMap::kSize];
  };
  DEFINE_THREAD_SAFE_STATIC_LOCAL(AtomicFamilies, families, ());
  std::optional<AtomicString>& family = families.families[script];
  if (family) {
    return *family;
  }

  static ScriptToFontMap script_font_map;
  static std::once_flag once_flag;
  std::call_once(once_flag, [] { InitializeScriptFontMap(script_font_map); });
  family.emplace(script_font_map[script].FirstAvailableFont(font_manager));
  return *family;
}

// FIXME:
//  - Handle 'Inherited', 'Common' and 'Unknown'
//    (see http://www.unicode.org/reports/tr24/#Usage_Model )
//    For 'Inherited' and 'Common', perhaps we need to
//    accept another parameter indicating the previous family
//    and just return it.
//  - All the characters (or characters up to the point a single
//    font can cover) need to be taken into account
const AtomicString& GetFallbackFamily(
    UChar32 character,
    FontDescription::GenericFamilyType generic,
    const LayoutLocale* content_locale,
    FontFallbackPriority fallback_priority,
    const SkFontMgr& font_manager,
    UScriptCode& script_out) {
  DCHECK(character);
  if (IsEmojiPresentationEmoji(fallback_priority)) [[unlikely]] {
    if (const AtomicString& family = GetColorEmojiFont(font_manager)) {
      script_out = USCRIPT_INVALID_CODE;
      return family;
    }
  } else if (IsTextPresentationEmoji(fallback_priority)) [[unlikely]] {
    if (const AtomicString& family = GetMonoEmojiFont(font_manager)) {
      script_out = USCRIPT_INVALID_CODE;
      return family;
    }
  } else {
    const UBlockCode block = ublock_getCode(character);
    if (const AtomicString& family =
            GetFontBasedOnUnicodeBlock(block, font_manager)) {
      script_out = USCRIPT_INVALID_CODE;
      return family;
    }
  }

  UScriptCode script = GetScript(character);

  // For the full-width ASCII characters (U+FF00 - U+FF5E), use the font for
  // Han (determined in a locale-dependent way above). Full-width ASCII
  // characters are rather widely used in Japanese and Chinese documents and
  // they're fully covered by Chinese, Japanese and Korean fonts.
  if (0xFF00 < character && character < 0xFF5F)
    script = USCRIPT_HAN;

  if (script == USCRIPT_COMMON)
    script = GetScriptBasedOnUnicodeBlock(character);

  // For unified-Han scripts, try the lang attribute, system, or
  // accept-languages.
  if (script == USCRIPT_HAN) {
    if (const LayoutLocale* locale_for_han =
            LayoutLocale::LocaleForHan(content_locale))
      script = locale_for_han->GetScriptForHan();
    // If still unknown, USCRIPT_HAN uses UI locale.
    // See initializeScriptFontMap().
  }

  script_out = script;

  // TODO(kojii): Limiting `GetFontFamilyForScript()` only to BMP may need
  // review to match the modern environment. This was done in 2010 for
  // https://bugs.webkit.org/show_bug.cgi?id=35605.
  if (character <= 0xFFFF) {
    if (const AtomicString& family =
            GetFontFamilyForScript(script, generic, font_manager)) {
      return family;
    }
  }

  // Another lame work-around to cover non-BMP characters.
  // If the font family for script is not found or the character is
  // not in BMP (> U+FFFF), we resort to the hard-coded list of
  // fallback fonts for now.
  int plane = character >> 16;
  switch (plane) {
    case 1: {
      DEFINE_THREAD_SAFE_STATIC_LOCAL(AtomicString, kPlane1, ("code2001"));
      return kPlane1;
    }
    case 2:
      // Use a Traditional Chinese ExtB font if in Traditional Chinese locale.
      // Otherwise, use a Simplified Chinese ExtB font. Windows Japanese
      // fonts do support a small subset of ExtB (that are included in JIS X
      // 0213), but its coverage is rather sparse.
      // Eventually, this should be controlled by lang/xml:lang.
      if (icu::Locale::getDefault() == icu::Locale::getTraditionalChinese()) {
        DEFINE_THREAD_SAFE_STATIC_LOCAL(AtomicString, kPlane2zht,
                                        ("pmingliu-extb"));
        return kPlane2zht;
      }
      DEFINE_THREAD_SAFE_STATIC_LOCAL(AtomicString, kPlane2zhs,
                                      ("simsun-extb"));
      return kPlane2zhs;
  }

  DEFINE_THREAD_SAFE_STATIC_LOCAL(AtomicString, kLastResort,
                                  ("lucida sans unicode"));
  return kLastResort;
}

}  // namespace blink
```
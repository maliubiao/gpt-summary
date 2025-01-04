Response:
Let's break down the thought process for analyzing this `layout_locale.cc` file.

1. **Understand the Purpose:** The filename `layout_locale.cc` strongly suggests this file is about handling locale-specific settings related to text layout within the Blink rendering engine. Keywords like "locale," "text," and "layout" are hints.

2. **Identify Key Components:**  Quickly scan the code for important data structures and functions. Look for:
    * Includes:  These point to external libraries and other Blink components the file depends on (e.g., `hb.h` for HarfBuzz, `unicode/locid.h` for ICU locales, `platform/language.h`, `platform/text/hyphenation.h`).
    * Namespaces:  The `blink` namespace is expected. The anonymous namespace at the top often contains helper functions.
    * Structures/Classes:  `PerThreadData`, `DelimiterConfig`, `LayoutLocale`, `QuotesData`. `LayoutLocale` is clearly central.
    * Global/Static Variables:  The `GetPerThreadData()` function using `DEFINE_THREAD_SAFE_STATIC_LOCAL` indicates thread-local storage, suggesting locale data might be cached per thread.
    * Key Functions: `Get()`, `GetDefault()`, `GetSystem()`, `LocaleForHan()`, `GetHyphenation()`, `GetQuotesData()`, `LocaleWithBreakKeyword()`, `AcceptLanguagesChanged()`.

3. **Analyze `LayoutLocale` Class:** This is the core of the file. Focus on its members and methods:
    * **Members:** `string_`, `harfbuzz_language_`, `script_`, `script_for_han_`, `hyphenation_`, `quotes_data_`, `case_map_locale_`. These store locale-specific information.
    * **Constructors:**  The constructor takes an `AtomicString` (likely a locale identifier) and initializes HarfBuzz language and script code.
    * **`Get()` (static):** This is a factory method, suggesting the `LayoutLocale` objects are likely managed and potentially cached.
    * **`GetDefault()` and `GetSystem()` (static):** These provide access to default and system locales.
    * **`LocaleForSkFontMgr()`:** This suggests interaction with the Skia graphics library for font selection.
    * **`GetScriptForHan()` and `LocaleForHan()`:** These deal specifically with Han scripts (Chinese, Japanese, Korean).
    * **`GetHyphenation()`:**  Handles hyphenation rules.
    * **`GetQuotesData()`:** Fetches quotation mark data.
    * **`LocaleWithBreakKeyword()`:**  Modifies the locale string for line-breaking behavior.

4. **Trace Data Flow and Logic:**
    * **Caching:** The `PerThreadData` and the `locale_map` clearly indicate caching of `LayoutLocale` objects to avoid redundant creation.
    * **Locale Resolution:**  Observe how the default and system locales are determined. Notice the handling of `accept-languages`.
    * **Han Script Handling:**  Pay attention to the logic in `GetScriptForHan()` and `LocaleForHan()`. It tries to disambiguate Han scripts based on locale information and user preferences.
    * **ICU Interaction:**  The code extensively uses ICU (International Components for Unicode) for locale data, hyphenation, and quotation marks.
    * **HarfBuzz Integration:**  `ToHarfbuzLanguage()` converts Blink's locale representation to a HarfBuzz language tag, indicating its use for shaping text.
    * **Skia Integration:**  `ToSkFontMgrLocale()` and `LocaleForSkFontMgr()` show how the locale is used for font selection in Skia.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):** Think about how locale settings influence web page rendering:
    * **`lang` attribute (HTML):** This directly relates to the locale used for rendering text.
    * **`Accept-Language` header (HTTP):** This influences the default locale used by the browser.
    * **CSS Font Selection:** Locale plays a role in font fallback and OpenType feature selection.
    * **JavaScript `Intl` API:**  This API provides JavaScript access to locale-sensitive operations like formatting dates, numbers, and collation. While this file doesn't directly *implement* the `Intl` API, it provides the underlying locale information that the `Intl` API uses.

6. **Infer Functionality and Relationships:** Based on the code and the connections to web technologies, deduce the main functionalities:
    * Provides `LayoutLocale` objects representing specific locales.
    * Caches these objects for performance.
    * Determines default and system locales.
    * Handles Han script disambiguation.
    * Fetches hyphenation rules and quotation mark data.
    * Integrates with HarfBuzz for text shaping and Skia for font selection.
    * Allows modification of the locale string for line-breaking behavior.
    * Responds to changes in the `Accept-Language` header.

7. **Construct Examples and Scenarios:** Create concrete examples to illustrate the functionality and potential issues:
    * **HTML `lang` attribute:** Show how different `lang` values affect hyphenation and quotation marks.
    * **`Accept-Language`:** Demonstrate how the browser's language settings influence the chosen locale.
    * **Han script ambiguity:** Explain how the logic helps choose the correct Han script.
    * **User errors:** Think about common mistakes developers might make regarding locale handling.

8. **Refine and Organize:**  Structure the findings logically, starting with a general overview and then diving into specific details and examples. Use clear and concise language. Ensure the explanations connect the code to web development concepts.

By following this systematic approach, one can effectively analyze and understand the purpose and functionality of a complex source code file like `layout_locale.cc`. The key is to combine code reading with knowledge of the relevant domain (web technologies, internationalization).
好的，让我们来详细分析一下 `blink/renderer/platform/text/layout_locale.cc` 这个 Blink 引擎的源代码文件。

**主要功能:**

`layout_locale.cc` 文件的核心功能是管理和提供与特定语言环境（locale）相关的布局信息。这包括：

1. **存储和管理 `LayoutLocale` 对象:**  该文件负责创建、缓存和提供 `LayoutLocale` 类的实例。`LayoutLocale` 对象封装了特定语言环境的信息，例如：
    * 语言代码（如 "en", "zh-CN"）
    * HarfBuzz 语言标签（用于字体排印）
    * Unicode 脚本代码（如拉丁文、中文）
    * 特定于汉字（中文、日文、韩文）的脚本代码
    * 连字符规则（用于断词）
    * 引号数据（不同语言的引号样式）
    * 用于大小写映射的 ICU Locale 对象

2. **获取不同类型的 Locale:** 它提供了获取以下几种 Locale 的方法：
    * **特定 Locale:**  根据传入的字符串（如 "en-US"）获取对应的 `LayoutLocale` 对象。
    * **默认 Locale:** 获取系统默认的语言环境。
    * **系统 Locale:** 获取操作系统报告的语言环境，这可能比默认 Locale 包含更详细的信息。
    * **汉字 Locale:**  根据内容或用户偏好，获取适合处理汉字的 Locale。

3. **提供与布局相关的数据:** `LayoutLocale` 对象可以提供与文本布局直接相关的数据：
    * **HarfBuzz 语言标签:**  用于 HarfBuzz 库进行高级字体排印，处理复杂的脚本和连字。
    * **连字符对象 (`Hyphenation`)**: 用于在文本换行时进行断词。
    * **引号数据 (`QuotesData`)**:  包含特定语言环境的开始和结束引号，以及备用引号。

4. **处理汉字脚本的歧义:** 对于中文、日文、韩文等使用汉字的语言，可能存在简体和繁体的区分。该文件尝试根据 Locale 信息或用户设置来确定合适的汉字脚本。

5. **与 Skia 集成:**  它提供了将 Blink 的 Locale 转换为 Skia 字体管理器所理解的 Locale 字符串的方法，用于选择合适的字体。

6. **处理行尾换行规则:**  允许根据严格程度修改 Locale 字符串，以影响行尾换行的行为。

7. **响应用户语言偏好的变化:** 监听用户 `Accept-Language` 头的变化，并更新相关的 Locale 信息，尤其是用于汉字的 Locale。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`layout_locale.cc` 虽然是 C++ 代码，但它提供的功能直接影响到浏览器如何渲染网页上的文本，因此与 JavaScript, HTML, CSS 有着密切的关系。

* **HTML `lang` 属性:**
    * **功能关系:** HTML 的 `lang` 属性用于指定元素的语言。浏览器会根据 `lang` 属性的值来选择合适的 `LayoutLocale` 对象。
    * **举例:**
        ```html
        <p lang="en-US">This is English text.</p>
        <p lang="zh-CN">这是中文文本。</p>
        ```
        当浏览器渲染这两个段落时，会分别使用 "en-US" 和 "zh-CN" 对应的 `LayoutLocale` 对象，从而应用不同的连字符规则、引号样式等。

* **HTTP `Accept-Language` 头:**
    * **功能关系:** 浏览器发送的 `Accept-Language` 头告诉服务器用户期望的语言偏好。Blink 会读取这个头部信息，并将其用于确定默认的 `LayoutLocale` 和用于处理汉字的 `LayoutLocale`。
    * **假设输入与输出:**
        * **假设输入 (Accept-Language):** `zh-CN,en-US;q=0.9,en;q=0.8`
        * **逻辑推理:**  Blink 会解析这个头部，优先选择简体中文（zh-CN），如果不可用则选择美式英语（en-US），然后是通用英语（en）。
        * **潜在输出 (GetDefault()):**  如果 `zh-CN` 存在对应的 `LayoutLocale`，则 `GetDefault()` 可能返回它。 `LocaleForHan()` 也可能优先考虑 `zh-CN` 对应的 Locale。

* **CSS 字体选择:**
    * **功能关系:** 虽然 CSS 直接指定字体，但语言环境会影响到某些高级字体特性，比如 OpenType 特性。此外，当指定的字体不支持某些字符时，浏览器会根据语言环境进行字体回退。`LayoutLocale::LocaleForSkFontMgr()` 提供的 Skia Locale 字符串就用于这个过程。
    * **举例:**  一个字体可能包含针对不同中文变体的字形（例如，针对简体和繁体）。浏览器会根据元素的 `lang` 属性（并因此根据 `LayoutLocale`）来选择合适的字形。

* **JavaScript `Intl` API:**
    * **功能关系:** JavaScript 的 `Intl` API 允许开发者执行本地化敏感的操作，例如格式化日期、数字和进行排序。`layout_locale.cc` 提供的 `LayoutLocale` 对象是 `Intl` API 的基础，`Intl` API 内部会使用这些信息。
    * **举例:**
        ```javascript
        const dateFormatter = new Intl.DateTimeFormat('zh-CN');
        const formattedDate = dateFormatter.format(new Date());
        ```
        这里的 `'zh-CN'` 字符串会影响 `Intl.DateTimeFormat` 的行为，而 Blink 内部会使用与 `'zh-CN'` 对应的 `LayoutLocale` 对象来获取日期格式化规则。

**逻辑推理的假设输入与输出:**

* **假设输入 (Get(AtomicString("zh-TW"))):**  请求获取繁体中文的 `LayoutLocale` 对象。
* **逻辑推理:**
    1. `Get()` 方法会先检查缓存中是否已存在 "zh-TW" 的 `LayoutLocale`。
    2. 如果不存在，则创建一个新的 `LayoutLocale` 对象。
    3. 在创建过程中，`ToHarfbuzLanguage("zh-TW")` 会被调用，生成 HarfBuzz 语言标签。
    4. `LocaleToScriptCodeForFontSelection("zh-TW")` 会被调用，根据 Locale 信息判断脚本（可能是 `USCRIPT_TRADITIONAL_HAN`）。
* **潜在输出:** 返回一个指向新创建的 `LayoutLocale` 对象的指针，该对象包含了 "zh-TW" 相关的布局信息，包括 HarfBuzz 语言标签和脚本代码。

* **假设输入 (LocaleForHan(LayoutLocale::Get(AtomicString("ja")))):** 尝试获取日语 Locale 的汉字专用 Locale。
* **逻辑推理:**
    1. `LocaleForHan()` 检查传入的 Locale（日语）是否已经明确指定了汉字脚本（通过 `HasScriptForHan()`）。
    2. 如果没有，则会尝试从用户 `Accept-Language` 设置中找到一个可以明确区分汉字脚本的 Locale (例如 "zh-Hans" 或 "zh-Hant")。
    3. 如果 `Accept-Language` 中没有合适的，则回退到默认 Locale 或系统 Locale，再次尝试。
* **潜在输出:** 如果用户的 `Accept-Language` 中包含 "zh-Hans"，并且存在对应的 `LayoutLocale`，则可能返回指向 "zh-Hans" `LayoutLocale` 对象的指针。如果找不到明确的，可能会返回默认的汉字 Locale 或者系统 Locale 的汉字版本。

**涉及用户或编程常见的使用错误及举例说明:**

1. **Locale 字符串拼写错误:**
    * **错误:**  在 HTML 的 `lang` 属性或 JavaScript 的 `Intl` API 中使用了错误的 Locale 字符串，例如 `"en_US"` 而不是 `"en-US"`。
    * **后果:**  浏览器可能无法正确识别语言环境，导致使用了错误的连字符规则、引号样式或字体回退。
    * **`layout_locale.cc` 的反应:** `LayoutLocale::Get()` 会尝试查找或创建对应的 Locale 对象，如果字符串格式不正确，可能无法找到最佳匹配，或者会创建并非预期的 Locale。

2. **忽略 `lang` 属性的重要性:**
    * **错误:**  开发者没有为页面或特定元素设置合适的 `lang` 属性。
    * **后果:**  浏览器无法确定文本的语言，可能会使用默认的或系统 Locale 进行渲染，导致在多语言页面上出现布局错误。
    * **`layout_locale.cc` 的反应:** 如果没有 `lang` 属性，浏览器会依赖默认或系统 Locale，这可能不是内容实际的语言，导致 `GetHyphenation()` 或 `GetQuotesData()` 返回不适用于当前文本的规则。

3. **混淆 Locale 和字符编码:**
    * **错误:**  误认为设置了 Locale 就解决了所有字符显示问题。
    * **后果:**  Locale 主要影响语言相关的布局规则，而字符编码决定了如何解释字节流。即使设置了正确的 Locale，如果字符编码不匹配，仍然会出现乱码。
    * **`layout_locale.cc` 的反应:**  `LayoutLocale` 主要关注布局信息，并不直接处理字符编码。字符编码问题需要在更底层的文本处理环节解决。

4. **过度依赖默认 Locale:**
    * **错误:**  开发者假设所有用户都使用相同的语言环境，没有考虑国际化需求。
    * **后果:**  对于非默认语言的用户，网站的显示效果可能不佳，例如断词不正确、引号样式不符合习惯等。
    * **`layout_locale.cc` 的反应:**  虽然提供了 `GetDefault()` 和 `GetSystem()`，但最佳实践是根据内容的实际语言设置 `lang` 属性，而不是完全依赖默认值。

5. **在 JavaScript 中使用硬编码的语言特定逻辑:**
    * **错误:**  在 JavaScript 代码中直接判断语言，例如 `if (navigator.language.startsWith('zh')) { ... }`。
    * **后果:**  这种做法不够灵活，且可能与浏览器内部的 Locale 管理不一致。应该尽可能使用 `Intl` API 来处理本地化敏感的操作。
    * **`layout_locale.cc` 的反应:**  `layout_locale.cc` 为 `Intl` API 提供了基础数据，应该利用 `Intl` API 而不是尝试在 JavaScript 中重新实现 Locale 相关的逻辑。

总而言之，`layout_locale.cc` 是 Blink 引擎中负责处理语言环境和布局相关信息的关键组件。它通过管理 `LayoutLocale` 对象，为文本渲染提供了必要的本地化支持，并与 HTML、CSS 和 JavaScript 的国际化 API 协同工作，确保网页能够正确地显示各种语言的文本。理解其功能有助于开发者更好地进行网页的国际化和本地化工作。

Prompt: 
```
这是目录为blink/renderer/platform/text/layout_locale.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/text/layout_locale.h"

#include <hb.h>
#include <unicode/locid.h>
#include <unicode/ulocdata.h>

#include <array>

#include "base/compiler_specific.h"
#include "base/memory/raw_ptr.h"
#include "base/notreached.h"
#include "third_party/blink/renderer/platform/language.h"
#include "third_party/blink/renderer/platform/text/hyphenation.h"
#include "third_party/blink/renderer/platform/text/icu_error.h"
#include "third_party/blink/renderer/platform/text/locale_to_script_mapping.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/case_folding_hash.h"
#include "third_party/blink/renderer/platform/wtf/thread_specific.h"

namespace blink {

namespace {

struct PerThreadData {
  HashMap<AtomicString,
          scoped_refptr<LayoutLocale>,
          CaseFoldingHashTraits<AtomicString>>
      locale_map;
  raw_ptr<const LayoutLocale> default_locale = nullptr;
  raw_ptr<const LayoutLocale> system_locale = nullptr;
  raw_ptr<const LayoutLocale> default_locale_for_han = nullptr;
  bool default_locale_for_han_computed = false;
  String current_accept_languages;
};

PerThreadData& GetPerThreadData() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(ThreadSpecific<PerThreadData>, data, ());
  return *data;
}

struct DelimiterConfig {
  ULocaleDataDelimiterType type;
  raw_ptr<UChar> result;
};
// Use  ICU ulocdata to find quote delimiters for an ICU locale
// https://unicode-org.github.io/icu-docs/apidoc/dev/icu4c/ulocdata_8h.html#a0bf1fdd1a86918871ae2c84b5ce8421f
scoped_refptr<QuotesData> GetQuotesDataForLanguage(const char* locale) {
  UErrorCode status = U_ZERO_ERROR;
  // Expect returned buffer size is 1 to match QuotesData type
  constexpr int ucharDelimMaxLength = 1;

  ULocaleData* uld = ulocdata_open(locale, &status);
  if (U_FAILURE(status)) {
    ulocdata_close(uld);
    return nullptr;
  }
  std::array<UChar, ucharDelimMaxLength> open1, close1, open2, close2;

  int32_t delimResultLength;
  struct DelimiterConfig delimiters[] = {
      {ULOCDATA_QUOTATION_START, open1.data()},
      {ULOCDATA_QUOTATION_END, close1.data()},
      {ULOCDATA_ALT_QUOTATION_START, open2.data()},
      {ULOCDATA_ALT_QUOTATION_END, close2.data()},
  };
  for (DelimiterConfig delim : delimiters) {
    delimResultLength = ulocdata_getDelimiter(uld, delim.type, delim.result,
                                              ucharDelimMaxLength, &status);
    if (U_FAILURE(status) || delimResultLength != 1) {
      ulocdata_close(uld);
      return nullptr;
    }
  }
  ulocdata_close(uld);

  return QuotesData::Create(open1[0], close1[0], open2[0], close2[0]);
}

// Returns the Unicode Line Break Style Identifier (key "lb") value.
// https://www.unicode.org/reports/tr35/#UnicodeLineBreakStyleIdentifier
inline const char* LbValueFromStrictness(LineBreakStrictness strictness) {
  switch (strictness) {
    case LineBreakStrictness::kDefault:
      return nullptr;  // nullptr removes any existing values.
    case LineBreakStrictness::kNormal:
      return "normal";
    case LineBreakStrictness::kStrict:
      return "strict";
    case LineBreakStrictness::kLoose:
      return "loose";
  }
  NOTREACHED();
}

}  // namespace

static hb_language_t ToHarfbuzLanguage(const AtomicString& locale) {
  std::string locale_as_latin1 = locale.Latin1();
  return hb_language_from_string(locale_as_latin1.data(),
                                 static_cast<int>(locale_as_latin1.length()));
}

// SkFontMgr uses two/three-letter language code with an optional ISO 15924
// four-letter script code, in POSIX style (with '-' as the separator,) such as
// "zh-Hant" and "zh-Hans". See `fonts.xml`.
static const char* ToSkFontMgrLocale(UScriptCode script) {
  switch (script) {
    case USCRIPT_KATAKANA_OR_HIRAGANA:
      return "ja";
    case USCRIPT_HANGUL:
      return "ko";
    case USCRIPT_SIMPLIFIED_HAN:
      return "zh-Hans";
    case USCRIPT_TRADITIONAL_HAN:
      return "zh-Hant";
    default:
      return nullptr;
  }
}

const char* LayoutLocale::LocaleForSkFontMgr() const {
  if (!string_for_sk_font_mgr_.empty())
    return string_for_sk_font_mgr_.c_str();

  if (const char* sk_font_mgr_locale = ToSkFontMgrLocale(script_)) {
    string_for_sk_font_mgr_ = sk_font_mgr_locale;
    DCHECK(!string_for_sk_font_mgr_.empty());
    return string_for_sk_font_mgr_.c_str();
  }

  const icu::Locale locale(Ascii().c_str());
  const char* language = locale.getLanguage();
  string_for_sk_font_mgr_ = language && *language ? language : "und";
  const char* script = locale.getScript();
  if (script && *script)
    string_for_sk_font_mgr_ = string_for_sk_font_mgr_ + "-" + script;
  DCHECK(!string_for_sk_font_mgr_.empty());
  return string_for_sk_font_mgr_.c_str();
}

void LayoutLocale::ComputeScriptForHan() const {
  if (IsUnambiguousHanScript(script_)) {
    script_for_han_ = script_;
    has_script_for_han_ = true;
    return;
  }

  script_for_han_ = ScriptCodeForHanFromSubtags(string_);
  if (script_for_han_ == USCRIPT_COMMON)
    script_for_han_ = USCRIPT_SIMPLIFIED_HAN;
  else
    has_script_for_han_ = true;
  DCHECK(IsUnambiguousHanScript(script_for_han_));
}

UScriptCode LayoutLocale::GetScriptForHan() const {
  if (script_for_han_ == USCRIPT_COMMON)
    ComputeScriptForHan();
  return script_for_han_;
}

bool LayoutLocale::HasScriptForHan() const {
  if (script_for_han_ == USCRIPT_COMMON)
    ComputeScriptForHan();
  return has_script_for_han_;
}

// static
const LayoutLocale* LayoutLocale::LocaleForHan(
    const LayoutLocale* content_locale) {
  if (content_locale && content_locale->HasScriptForHan())
    return content_locale;

  PerThreadData& data = GetPerThreadData();
  if (!data.default_locale_for_han_computed) [[unlikely]] {
    // Use the first acceptLanguages that can disambiguate.
    Vector<String> languages;
    data.current_accept_languages.Split(',', languages);
    for (String token : languages) {
      token = token.StripWhiteSpace();
      const LayoutLocale* locale = LayoutLocale::Get(AtomicString(token));
      if (locale->HasScriptForHan()) {
        data.default_locale_for_han = locale;
        break;
      }
    }
    if (!data.default_locale_for_han) {
      const LayoutLocale& default_locale = GetDefault();
      if (default_locale.HasScriptForHan())
        data.default_locale_for_han = &default_locale;
    }
    if (!data.default_locale_for_han) {
      const LayoutLocale& system_locale = GetSystem();
      if (system_locale.HasScriptForHan())
        data.default_locale_for_han = &system_locale;
    }
    data.default_locale_for_han_computed = true;
  }
  return data.default_locale_for_han;
}

const char* LayoutLocale::LocaleForHanForSkFontMgr() const {
  const char* locale = ToSkFontMgrLocale(GetScriptForHan());
  DCHECK(locale);
  return locale;
}

void LayoutLocale::ComputeCaseMapLocale() const {
  DCHECK(!case_map_computed_);
  case_map_computed_ = true;
  locale_for_case_map_ = CaseMap::Locale(LocaleString());
}

LayoutLocale::LayoutLocale(const AtomicString& locale)
    : string_(locale),
      harfbuzz_language_(ToHarfbuzLanguage(locale)),
      script_(LocaleToScriptCodeForFontSelection(locale)),
      script_for_han_(USCRIPT_COMMON),
      has_script_for_han_(false),
      hyphenation_computed_(false),
      quotes_data_computed_(false),
      case_map_computed_(false) {}

// static
const LayoutLocale* LayoutLocale::Get(const AtomicString& locale) {
  if (locale.IsNull())
    return nullptr;

  auto result = GetPerThreadData().locale_map.insert(locale, nullptr);
  if (result.is_new_entry)
    result.stored_value->value = base::AdoptRef(new LayoutLocale(locale));
  return result.stored_value->value.get();
}

// static
const LayoutLocale& LayoutLocale::GetDefault() {
  PerThreadData& data = GetPerThreadData();
  if (!data.default_locale) [[unlikely]] {
    AtomicString language = DefaultLanguage();
    data.default_locale =
        LayoutLocale::Get(!language.empty() ? language : AtomicString("en"));
  }
  return *data.default_locale;
}

// static
const LayoutLocale& LayoutLocale::GetSystem() {
  PerThreadData& data = GetPerThreadData();
  if (!data.system_locale) [[unlikely]] {
    // Platforms such as Windows can give more information than the default
    // locale, such as "en-JP" for English speakers in Japan.
    String name = icu::Locale::getDefault().getName();
    data.system_locale =
        LayoutLocale::Get(AtomicString(name.Replace('_', '-')));
  }
  return *data.system_locale;
}

scoped_refptr<LayoutLocale> LayoutLocale::CreateForTesting(
    const AtomicString& locale) {
  return base::AdoptRef(new LayoutLocale(locale));
}

Hyphenation* LayoutLocale::GetHyphenation() const {
  if (hyphenation_computed_)
    return hyphenation_.get();

  hyphenation_computed_ = true;
  hyphenation_ = Hyphenation::PlatformGetHyphenation(LocaleString());
  return hyphenation_.get();
}

void LayoutLocale::SetHyphenationForTesting(
    const AtomicString& locale_string,
    scoped_refptr<Hyphenation> hyphenation) {
  const LayoutLocale& locale = ValueOrDefault(Get(locale_string));
  locale.hyphenation_computed_ = true;
  locale.hyphenation_ = std::move(hyphenation);
}

scoped_refptr<QuotesData> LayoutLocale::GetQuotesData() const {
  if (quotes_data_computed_)
    return quotes_data_;
  quotes_data_computed_ = true;

  // BCP 47 uses '-' as the delimiter but ICU uses '_'.
  // https://tools.ietf.org/html/bcp47
  String normalized_lang = LocaleString();
  normalized_lang.Replace('-', '_');

  UErrorCode status = U_ZERO_ERROR;
  // Use uloc_openAvailableByType() to find all CLDR recognized locales
  // https://unicode-org.github.io/icu-docs/apidoc/dev/icu4c/uloc_8h.html#aa0332857185774f3e0520a0823c14d16
  UEnumeration* ulocales =
      uloc_openAvailableByType(ULOC_AVAILABLE_DEFAULT, &status);
  if (U_FAILURE(status)) {
    uenum_close(ulocales);
    return nullptr;
  }

  // Try to find exact match
  while (const char* loc = uenum_next(ulocales, nullptr, &status)) {
    if (U_FAILURE(status)) {
      uenum_close(ulocales);
      return nullptr;
    }
    if (EqualIgnoringASCIICase(loc, normalized_lang)) {
      quotes_data_ = GetQuotesDataForLanguage(loc);
      uenum_close(ulocales);
      return quotes_data_;
    }
  }
  uenum_close(ulocales);

  // No exact match, try to find without subtags.
  wtf_size_t hyphen_offset = normalized_lang.ReverseFind('_');
  if (hyphen_offset == kNotFound)
    return nullptr;
  normalized_lang = normalized_lang.Substring(0, hyphen_offset);
  ulocales = uloc_openAvailableByType(ULOC_AVAILABLE_DEFAULT, &status);
  if (U_FAILURE(status)) {
    uenum_close(ulocales);
    return nullptr;
  }
  while (const char* loc = uenum_next(ulocales, nullptr, &status)) {
    if (U_FAILURE(status)) {
      uenum_close(ulocales);
      return nullptr;
    }
    if (EqualIgnoringASCIICase(loc, normalized_lang)) {
      quotes_data_ = GetQuotesDataForLanguage(loc);
      uenum_close(ulocales);
      return quotes_data_;
    }
  }
  uenum_close(ulocales);
  return nullptr;
}

AtomicString LayoutLocale::LocaleWithBreakKeyword(
    LineBreakStrictness strictness,
    bool use_phrase) const {
  if (string_.empty())
    return string_;

  // uloc_setKeywordValue_58 has a problem to handle "@" in the original
  // string. crbug.com/697859
  if (string_.Contains('@'))
    return string_;

  constexpr wtf_size_t kMaxLbValueLen = 6;
  constexpr wtf_size_t kMaxKeywordsLen =
      /* strlen("@lb=") */ 4 + kMaxLbValueLen + /* strlen("@lw=phrase") */ 10;
  class ULocaleKeywordBuilder {
   public:
    explicit ULocaleKeywordBuilder(const std::string& utf8_locale)
        : length_(base::saturated_cast<wtf_size_t>(utf8_locale.length())),
          buffer_(length_ + kMaxKeywordsLen + 1, 0) {
      // The `buffer_` is initialized to 0 above.
      base::span(buffer_).copy_prefix_from(
          base::span(utf8_locale).first(length_));
    }
    explicit ULocaleKeywordBuilder(const String& locale)
        : ULocaleKeywordBuilder(locale.Utf8()) {}

    AtomicString ToAtomicString() const {
      return AtomicString::FromUTF8(base::as_byte_span(buffer_).first(length_));
    }

    bool SetStrictness(LineBreakStrictness strictness) {
      const char* const lb_value = LbValueFromStrictness(strictness);
      DCHECK(!lb_value || strlen(lb_value) <= kMaxLbValueLen);
      return SetKeywordValue("lb", lb_value);
    }

    bool SetKeywordValue(const char* keyword_name, const char* value) {
      ICUError status;
      int32_t length_needed = uloc_setKeywordValue(
          keyword_name, value, buffer_.data(), buffer_.size(), &status);
      if (U_SUCCESS(status)) {
        DCHECK_GE(length_needed, 0);
        length_ = length_needed;
        DCHECK_LT(length_, buffer_.size());
        return true;
      }
      DCHECK_NE(status, U_BUFFER_OVERFLOW_ERROR);
      return false;
    }

   private:
    wtf_size_t length_;
    Vector<char> buffer_;
  } builder(string_);

  if (builder.SetStrictness(strictness) &&
      (!use_phrase || builder.SetKeywordValue("lw", "phrase"))) {
    return builder.ToAtomicString();
  }
  NOTREACHED();
}

// static
void LayoutLocale::AcceptLanguagesChanged(const String& accept_languages) {
  PerThreadData& data = GetPerThreadData();
  if (data.current_accept_languages == accept_languages)
    return;

  data.current_accept_languages = accept_languages;
  data.default_locale_for_han = nullptr;
  data.default_locale_for_han_computed = false;
}

// static
void LayoutLocale::ClearForTesting() {
  GetPerThreadData() = PerThreadData();
}

}  // namespace blink

"""

```
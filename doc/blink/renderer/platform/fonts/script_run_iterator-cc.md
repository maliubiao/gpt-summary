Response:
Let's break down the thought process for analyzing the `script_run_iterator.cc` file. The goal is to extract its functionality and its relationship with web technologies.

1. **Understanding the Core Purpose:** The filename `script_run_iterator.cc` strongly suggests an iterator that deals with "script runs."  This hints at the idea of grouping text segments that share a common script. The initial comments about Copyright and BSD license are standard boilerplate and can be noted but aren't functionally relevant. The `#ifdef UNSAFE_BUFFERS_BUILD` section can also be noted as a conditional compilation flag, probably for debugging or specific build configurations, but not core functionality.

2. **Include Directives: Clues to Dependencies:** The included headers provide valuable context:
    * `<algorithm>`: Standard algorithms, likely used for set operations or searching.
    * `"base/containers/contains.h"`:  Indicates set membership checks.
    * `"base/logging.h"`:  Logging for debugging or error reporting.
    * `"base/notreached.h"`:  Indicates unreachable code paths, likely for assertions.
    * `"base/ranges/algorithm.h"`: Modern C++ range-based algorithms.
    * `"third_party/blink/renderer/platform/text/icu_error.h"`:  Interaction with the International Components for Unicode (ICU) library, crucial for handling different scripts.
    * `"third_party/blink/renderer/platform/wtf/text/character_names.h"`:  Likely contains constants or utilities related to character names (though not heavily used in *this* file).
    * `"third_party/blink/renderer/platform/wtf/threading.h"`:  Hints at thread safety considerations, potentially related to static initialization.

3. **Namespace and Initial Definitions:** The code is within the `blink` namespace, further confirming its role within the Blink rendering engine. The anonymous namespace contains helper functions. The function names like `GetScriptForOpenType`, `IsHanScript`, `GetHanScriptExtensions`, and `FixScriptsByEastAsianWidth` strongly suggest the file deals with script identification and normalization, particularly focusing on handling Han scripts and East Asian width properties.

4. **`ScriptData` and `ICUScriptData`:**  The declaration of `ScriptData` as an abstract base class and `ICUScriptData` as a concrete implementation using ICU provides the core mechanism for getting script information for characters. The `GetScripts` function in `ICUScriptData` is a key entry point for this. The `GetPairedBracket` and `GetPairedBracketType` functions indicate handling of bracket matching, which is relevant for bidirectional text and potentially for understanding text structure. The singleton pattern for `ICUScriptData::Instance()` is a common optimization.

5. **`ScriptRunIterator` Class: The Heart of the Logic:**  This is the main class. Key members like `text_`, `length_`, `current_set_`, `next_set_`, `ahead_set_`, `brackets_`, and `brackets_fixup_depth_` reveal the iterator's state and how it manages script information. The constructor initializes the iterator.

6. **`Consume` Method: Driving the Iteration:**  This method is likely the core of the iteration process. It fetches characters, handles paired brackets (`OpenBracket`, `CloseBracket`), and crucially, `MergeSets` to determine if the script is changing. The `ResolveCurrentScript` method finalizes the script for the current run. `FixupStack` suggests a mechanism to correct the script assignments for opening brackets after the corresponding closing bracket's script is determined.

7. **`OpenBracket` and `CloseBracket`:** These methods manage a stack of open brackets. The logic in `CloseBracket` tries to find the matching opening bracket and potentially influence the script assignment. The handling of Han scripts in `CloseBracket` is interesting, suggesting an optimization or special case.

8. **`MergeSets`:**  This is the core logic for deciding when a script run ends. It compares the script sets of the current and next characters and determines if they are compatible. The handling of `USCRIPT_COMMON` and `USCRIPT_INHERITED` is important for default script assignments.

9. **`FixupStack`:** This method connects the bracket matching logic back to the script runs. It ensures that opening brackets get the script of the run they belong to, which is often determined by the content *inside* the brackets.

10. **`Fetch`:** This method advances the iterator through the text, retrieving the next character and its associated scripts. It handles surrogate pairs (characters outside the basic multilingual plane). The logic around `USCRIPT_INHERITED` is crucial for handling characters that inherit their script from surrounding text.

11. **`ResolveCurrentScript`:** This method determines the final script for a run, taking into account the `common_preferred_` script.

12. **Relating to Web Technologies (JavaScript, HTML, CSS):**  This requires connecting the low-level script identification to higher-level concepts.
    * **JavaScript:**  JavaScript string manipulation is affected by how scripts are handled. For example, the concept of "grapheme clusters" (user-perceived characters) relies on correct script segmentation.
    * **HTML:** The `lang` attribute in HTML elements influences script detection. The iterator needs to be aware of these language hints.
    * **CSS:** CSS font selection depends heavily on script information. The `unicode-range` descriptor allows specifying which characters a font supports. The iterator's output directly impacts which fonts are chosen to render text. Font features (like ligatures or contextual alternates) are often script-specific.

13. **Logical Reasoning and Examples:** This involves creating concrete scenarios to illustrate the iterator's behavior. Choosing examples with different script combinations, brackets, and edge cases is key. The Han script examples are particularly important due to their complexity.

14. **Common Usage Errors:** This focuses on how developers might misuse or misunderstand the iterator's purpose or limitations. Incorrectly assuming single scripts per character or not handling bracket matching properly are potential pitfalls.

By following this structured approach, starting from the high-level purpose and progressively digging into the details, we can systematically understand the functionality of the `script_run_iterator.cc` file and its significance within the Blink rendering engine.
这是一个关于 Chromium Blink 引擎中处理文本脚本的源代码文件，名为 `script_run_iterator.cc`。它的主要功能是**将一段文本分割成具有相同脚本的“运行”（runs）**。这对于文本渲染至关重要，因为不同的脚本通常需要不同的字体和排版规则。

让我们详细列举一下它的功能，并说明它与 JavaScript、HTML 和 CSS 的关系：

**主要功能:**

1. **脚本识别和分组:**  `ScriptRunIterator` 遍历文本，并使用 ICU (International Components for Unicode) 库来识别每个字符的脚本 (Script Code)。然后，它将连续具有相同脚本的字符分组到一个 "run" 中。

2. **处理 Unicode 脚本扩展:**  有些字符属于多个脚本，`ScriptRunIterator` 考虑了 Unicode 脚本扩展，以更准确地确定字符的脚本归属。

3. **处理 OpenType 脚本标签:**  该文件考虑到 OpenType 脚本标签，例如将 Hiragana 和 Katakana 都映射到 'kana'，以帮助减少脚本运行之间的分割。

4. **处理东亚宽度（East Asian Width）属性:** 对于某些东亚标点符号，其脚本扩展可能不包含所有相关的汉字脚本。`FixScriptsByEastAsianWidth` 函数根据字符的东亚宽度属性来修正脚本列表，确保连续的 CJK 标点符号能够被正确地分组。

5. **处理成对的括号:**  代码能够识别并处理成对的括号。当遇到一个开括号时，它会将其信息压入栈中。当遇到一个闭括号时，它会在栈中查找匹配的开括号，并尝试将闭括号的脚本与开括号的脚本对齐，以避免不必要的脚本分割。这对于正确渲染包含括号的文本非常重要。

6. **维护脚本优先级:** 当一个字符可能属于多个脚本时，`ScriptRunIterator` 会维护一个优先级顺序，以确定该字符最终所属的脚本。

7. **迭代器接口:**  `ScriptRunIterator` 提供了一个 `Consume` 方法，允许调用者迭代文本的脚本运行。该方法返回当前运行的结束位置和该运行的脚本。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **`lang` 属性:** HTML 的 `lang` 属性可以指示元素的语言，这会影响 `ScriptRunIterator` 的行为。例如，如果一个 `<span>` 标签的 `lang` 属性设置为 "ja" (日语)，那么该 span 内的字符更有可能被识别为日语脚本。
    * **假设输入:**  HTML 代码片段 `<p><span lang="ja">こんにちは</span> world!</p>`
    * **逻辑推理:** `ScriptRunIterator` 在处理 "こんにちは" 时，会因为 `lang="ja"` 的提示，更倾向于将其识别为日语（Hiragana）。
    * **输出:** 可能会生成两个脚本运行：一个是日语运行包含 "こんにちは"，另一个是拉丁语运行包含 " world!"。

* **CSS:**
    * **`unicode-range` 属性:** CSS 的 `@font-face` 规则中的 `unicode-range` 属性允许指定字体支持的 Unicode 字符范围。`ScriptRunIterator` 的结果会直接影响浏览器选择哪个字体来渲染文本。如果一个脚本运行的脚本是日语，浏览器会尝试选择一个包含日语字符的字体。
    * **字体回退:** 如果一个字体不包含某个脚本的字符，浏览器会回退到其他字体。`ScriptRunIterator` 确保了文本按照脚本正确分割，以便浏览器能够为每个脚本运行选择合适的字体。
    * **假设输入:** CSS 规则 `@font-face { font-family: 'JapaneseFont'; src: url('...'); unicode-range: U+3040-U+309F, U+30A0-U+30FF; }` 定义了一个名为 "JapaneseFont" 的字体，它支持平假名和片假名。
    * **逻辑推理:** 当 `ScriptRunIterator` 将一段日语文本（包含平假名和片假名）识别为一个日语脚本运行时，浏览器会尝试使用 "JapaneseFont" 来渲染这段文本。

* **JavaScript:**
    * **文本处理和分析:** JavaScript 可以获取 DOM 树中的文本内容。虽然 JavaScript 本身不直接调用 `ScriptRunIterator`，但 Blink 引擎内部使用它来处理和渲染这些文本。JavaScript 可以通过 DOM API 获取文本，然后可能需要根据脚本进行进一步的处理或分析。
    * **国际化 (i18n) 和本地化 (l10n):** JavaScript 框架和库可以使用 Blink 的渲染结果来更好地支持国际化和本地化，例如根据脚本调整 UI 元素的布局或文本显示方式。
    * **假设输入:** JavaScript 代码 `const text = document.querySelector('p').textContent;` 获取一个段落的文本内容。
    * **逻辑推理:**  Blink 引擎在渲染这个段落时，会使用 `ScriptRunIterator` 将文本分割成不同的脚本运行。JavaScript 获取的 `text` 字符串已经经过了 Blink 的脚本处理阶段。

**逻辑推理举例:**

假设输入一段包含不同脚本的文本："Hello こんにちは World!"

1. **处理 "Hello":**
   - 字符 'H', 'e', 'l', 'l', 'o' 被识别为拉丁语脚本。
   - `ScriptRunIterator` 将它们分组到一个拉丁语脚本运行。

2. **处理 "こんにちは":**
   - 字符 'こ', 'ん', 'に', 'ち', 'は' 被识别为日语（平假名）脚本。
   - `ScriptRunIterator` 将它们分组到一个日语脚本运行。

3. **处理 " World!":**
   - 字符 ' ', 'W', 'o', 'r', 'l', 'd', '!' 被识别为拉丁语脚本（空格和感叹号通常也属于通用或拉丁语）。
   - `ScriptRunIterator` 将它们分组到一个拉丁语脚本运行。

**输出:**  `ScriptRunIterator` 会生成三个脚本运行：
   -  运行 1: "Hello", 脚本: 拉丁语
   -  运行 2: "こんにちは", 脚本: 日语 (平假名)
   -  运行 3: " World!", 脚本: 拉丁语

**用户或编程常见的使用错误 (与此文件直接相关的错误较少，更多是与理解渲染过程相关):**

* **假设所有字符都属于单一脚本:**  开发者可能会错误地假设每个字符只属于一个脚本，而忽略了 Unicode 脚本扩展或某些字符可能在不同上下文中属于不同的脚本。`ScriptRunIterator` 的存在正是为了处理这种复杂性。

* **忽略 `lang` 属性的重要性:**  开发者可能没有正确使用 HTML 的 `lang` 属性，导致浏览器无法准确判断文本的语言和脚本，从而影响渲染结果。

* **字体配置不当:**  即使 `ScriptRunIterator` 正确识别了脚本，如果 CSS 中没有提供支持该脚本的字体，或者 `unicode-range` 配置不正确，仍然会导致显示问题（例如显示为方框）。

* **对双向文本 (Bidi) 的理解不足:** 虽然这个文件主要关注脚本，但脚本信息也与双向文本算法相关。开发者可能对浏览器如何处理从右到左 (RTL) 的脚本（如阿拉伯语、希伯来语）与其他脚本混合的情况理解不足，导致布局错误。

总而言之，`script_run_iterator.cc` 是 Blink 引擎中一个关键的底层组件，它负责将文本分解成逻辑上的脚本单元，为后续的字体选择、排版和渲染奠定基础。它处理了 Unicode 规范中关于脚本的复杂性，确保了 Web 内容能够以正确的方式呈现在用户面前，支持各种不同的语言和书写系统。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/script_run_iterator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/fonts/script_run_iterator.h"

#include <algorithm>

#include "base/containers/contains.h"
#include "base/logging.h"
#include "base/notreached.h"
#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/platform/text/icu_error.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/threading.h"

namespace blink {

namespace {

// UScriptCode and OpenType script are not 1:1; specifically, both Hiragana and
// Katakana map to 'kana' in OpenType. They will be mapped correctly in
// HarfBuzz, but normalizing earlier helps to reduce splitting runs between
// these scripts.
// https://docs.microsoft.com/en-us/typography/opentype/spec/scripttags
inline UScriptCode GetScriptForOpenType(UChar32 ch, UErrorCode* status) {
  UScriptCode script = uscript_getScript(ch, status);
  if (U_FAILURE(*status)) [[unlikely]] {
    return script;
  }
  if (script == USCRIPT_KATAKANA || script == USCRIPT_KATAKANA_OR_HIRAGANA)
      [[unlikely]] {
    return USCRIPT_HIRAGANA;
  }
  return script;
}

inline bool IsHanScript(UScriptCode script) {
  return script == USCRIPT_HAN || script == USCRIPT_HIRAGANA ||
         script == USCRIPT_BOPOMOFO;
}

inline UScriptCode FirstHanScript(
    const ScriptRunIterator::UScriptCodeList& list) {
  const auto result = base::ranges::find_if(list, IsHanScript);
  if (result != list.end())
    return *result;
  return USCRIPT_INVALID_CODE;
}

ScriptRunIterator::UScriptCodeList GetHanScriptExtensions() {
  ICUError status;
  ScriptRunIterator::UScriptCodeList list;
  list.resize(ScriptRunIterator::kMaxScriptCount - 1);
  // Get the list from one of the CJK punctuation in the CJK Symbols and
  // Punctuation block.
  int count = uscript_getScriptExtensions(kLeftCornerBracket, &list[0],
                                          list.size(), &status);
  if (U_SUCCESS(status)) {
    DCHECK_GT(count, 0);
    list.resize(count);
    return list;
  }
  NOTREACHED();
}

// This function updates the script list to the Han ideographic-based scripts if
// the East Asian Width property[1] indicates it is an East Asian character.
//
// Most East Asian punctuation characters have East Asian scripts in the script
// extensions. However, not all of them are so. For example, when they are
// halfwidth/fullwidth forms, they must have the same properties as their
// canonical equivalent[2] code points that are not East Asian. Such code points
// can split runs in the middle of consecutive CJK punctuation characters when
// they are preceded by non-CJK characters, and prevent applying font features
// to consecutive CJK punctuation characters.
//
// TODO(crbug.com/1273998): This function is not needed if Unicode changes the
// script extension for these code points.
//
// [1]: https://www.unicode.org/reports/tr11/
// [2]: https://unicode.org/reports/tr15/#Canon_Compat_Equivalence
void FixScriptsByEastAsianWidth(UChar32 ch,
                                ScriptRunIterator::UScriptCodeList* set) {
  // Replace the list only if it is the `COMMON` script. If `COMMON`, there
  // should be only one entry.
  DCHECK(!set->empty());
  if (set->size() > 1 || set->front() != USCRIPT_COMMON) {
    DCHECK(!set->Contains(USCRIPT_COMMON));
    return;
  }

  // It's an East Asian character when the EAW property is W, F, or H.
  // https://www.unicode.org/reports/tr11/#Set_Relations
  const auto eaw = static_cast<UEastAsianWidth>(
      u_getIntPropertyValue(ch, UCHAR_EAST_ASIAN_WIDTH));
  if (eaw == U_EA_WIDE || eaw == U_EA_FULLWIDTH || eaw == U_EA_HALFWIDTH) {
    // Replace the list with the list of Han ideographic scripts, as seen for
    // U+300C in https://www.unicode.org/Public/UNIDATA/ScriptExtensions.txt.
    DEFINE_STATIC_LOCAL(ScriptRunIterator::UScriptCodeList, han_scripts,
                        (GetHanScriptExtensions()));
    if (han_scripts.empty()) [[unlikely]] {
      // When |GetHanScriptExtensions| returns an empty list, replacing with it
      // will crash later, which makes the analysis complicated.
      NOTREACHED();
    }
    set->Shrink(0);
    set->AppendVector(han_scripts);
  }
}

}  // namespace

typedef ScriptData::PairedBracketType PairedBracketType;

ScriptData::~ScriptData() = default;

void ICUScriptData::GetScripts(UChar32 ch, UScriptCodeList& dst) const {
  ICUError status;
  // Leave room to insert primary script. It's not strictly necessary but
  // it ensures that the result won't ever be greater than kMaxScriptCount,
  // which some client someday might expect.
  dst.resize(kMaxScriptCount - 1);
  // Note, ICU convention is to return the number of available items
  // regardless of the capacity passed to the call. So count can be greater
  // than dst->size(), if a later version of the unicode data has more
  // than kMaxScriptCount items.

  // |uscript_getScriptExtensions| do not need to be collated to
  // USCRIPT_HIRAGANA because when ScriptExtensions contains Kana, it contains
  // Hira as well, and Hira is always before Kana.
  int count = uscript_getScriptExtensions(ch, &dst[0], dst.size(), &status);
  if (status == U_BUFFER_OVERFLOW_ERROR) {
    // Allow this, we'll just use what we have.
    DLOG(ERROR) << "Exceeded maximum script count of " << kMaxScriptCount
                << " for 0x" << std::hex << ch;
    count = dst.size();
    status = U_ZERO_ERROR;
  }
  UScriptCode primary_script = GetScriptForOpenType(ch, &status);

  if (U_FAILURE(status)) {
    DLOG(ERROR) << "Could not get icu script data: " << status << " for 0x"
                << std::hex << ch;
    dst.clear();
    return;
  }

  dst.resize(count);

  if (primary_script == dst.at(0)) {
    // Only one script (might be common or inherited -- these are never in
    // the extensions unless they're the only script), or extensions are in
    // priority order already.
    return;
  }

  if (primary_script != USCRIPT_INHERITED && primary_script != USCRIPT_COMMON &&
      primary_script != USCRIPT_INVALID_CODE) {
    // Not common or primary, with extensions that are not in order. We know
    // the primary, so we insert it at the front and swap the previous front
    // to somewhere else in the list.
    auto it = std::find(dst.begin() + 1, dst.end(), primary_script);
    if (it == dst.end()) {
      dst.push_back(primary_script);
      std::swap(dst.front(), dst.back());
    } else {
      std::swap(*dst.begin(), *it);
    }
    return;
  }

  if (primary_script == USCRIPT_COMMON) {
    if (count == 1) {
      // Common with a preferred script. Keep common at head.
      dst.push_front(primary_script);
      return;
    }

    // Ignore common. Find the preferred script of the multiple scripts that
    // remain, and ensure it is at the head. Just keep swapping them in,
    // there aren't likely to be many.
    for (wtf_size_t i = 1; i < dst.size(); ++i) {
      if (dst.at(0) == USCRIPT_LATIN || dst.at(i) < dst.at(0)) {
        std::swap(dst.at(0), dst.at(i));
      }
    }
    return;
  }

  // The primary is inherited, and there are other scripts. Put inherited at
  // the front, the true primary next, and then the others in random order.
  // TODO: Take into account the language of a document if available.
  // Otherwise, use Unicode block as a tie breaker. Comparing
  // ScriptCodes as integers is not meaningful because 'old' scripts are
  // just sorted in alphabetic order.
  dst.push_back(dst.at(0));
  dst.at(0) = primary_script;
  for (wtf_size_t i = 2; i < dst.size(); ++i) {
    if (dst.at(1) == USCRIPT_LATIN || dst.at(i) < dst.at(1)) {
      std::swap(dst.at(1), dst.at(i));
    }
  }
}

UChar32 ICUScriptData::GetPairedBracket(UChar32 ch) const {
  return u_getBidiPairedBracket(ch);
}

PairedBracketType ICUScriptData::GetPairedBracketType(UChar32 ch) const {
  return static_cast<PairedBracketType>(
      u_getIntPropertyValue(ch, UCHAR_BIDI_PAIRED_BRACKET_TYPE));
}

const ICUScriptData* ICUScriptData::Instance() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(const ICUScriptData, icu_script_data_instance,
                                  ());
  return &icu_script_data_instance;
}

ScriptRunIterator::ScriptRunIterator(base::span<const UChar> text,
                                     const ScriptData* data)
    : text_(text.data()),
      length_(base::checked_cast<wtf_size_t>(text.size())),
      brackets_fixup_depth_(0),
      next_set_(std::make_unique<UScriptCodeList>()),
      ahead_set_(std::make_unique<UScriptCodeList>()),
      // The initial value of ahead_character_ is not used.
      ahead_character_(0),
      ahead_pos_(0),
      common_preferred_(USCRIPT_COMMON),
      script_data_(data) {
  DCHECK(text.data());
  DCHECK(data);

  if (ahead_pos_ < length_) {
    current_set_.clear();
    // Priming the current_set_ with USCRIPT_COMMON here so that the first
    // resolution between current_set_ and next_set_ in MergeSets() leads to
    // choosing the script of the first consumed character.
    current_set_.push_back(USCRIPT_COMMON);
    U16_NEXT(text_, ahead_pos_, length_, ahead_character_);
    script_data_->GetScripts(ahead_character_, *ahead_set_);
  }
}

ScriptRunIterator::ScriptRunIterator(base::span<const UChar> text)
    : ScriptRunIterator(text, ICUScriptData::Instance()) {}

bool ScriptRunIterator::Consume(unsigned* limit, UScriptCode* script) {
  if (current_set_.empty()) {
    return false;
  }

  wtf_size_t pos;
  UChar32 ch;
  while (Fetch(&pos, &ch)) {
    PairedBracketType paired_type = script_data_->GetPairedBracketType(ch);
    switch (paired_type) {
      case PairedBracketType::kBracketTypeOpen:
        OpenBracket(ch);
        break;
      case PairedBracketType::kBracketTypeClose:
        CloseBracket(ch);
        break;
      default:
        break;
    }
    if (!MergeSets()) {
      *limit = pos;
      *script = ResolveCurrentScript();
      // If the current character is an open bracket, do not assign the resolved
      // script to it yet because it will belong to the next run.
      const bool exclude_last =
          paired_type == PairedBracketType::kBracketTypeOpen;
      FixupStack(*script, exclude_last);
      current_set_ = *next_set_;
      return true;
    }
  }

  *limit = length_;
  *script = ResolveCurrentScript();
  current_set_.clear();
  return true;
}

void ScriptRunIterator::OpenBracket(UChar32 ch) {
  if (brackets_.size() == kMaxBrackets) {
    brackets_.pop_front();
    if (brackets_fixup_depth_ == kMaxBrackets) {
      --brackets_fixup_depth_;
    }
  }
  FixScriptsByEastAsianWidth(ch, next_set_.get());
  brackets_.push_back(BracketRec({ch, USCRIPT_COMMON}));
  ++brackets_fixup_depth_;
}

void ScriptRunIterator::CloseBracket(UChar32 ch) {
  if (!brackets_.empty()) {
    UChar32 target = script_data_->GetPairedBracket(ch);
    for (auto it = brackets_.rbegin(); it != brackets_.rend(); ++it) {
      if (it->ch == target) {
        // Have a match, use open paren's resolved script.
        UScriptCode script = it->script;
        // Han languages are multi-scripts, and there are font features that
        // apply to consecutive punctuation characters.
        // When encountering a closing bracket do not insist on the closing
        // bracket getting assigned the same script as the opening bracket if
        // current_set_ provides an option to resolve to any other possible Han
        // script as well, which avoids breaking the run.
        if (IsHanScript(script)) {
          const UScriptCode current_han_script = FirstHanScript(current_set_);
          if (current_han_script != USCRIPT_INVALID_CODE)
            script = current_han_script;
        }
        if (script != USCRIPT_COMMON) {
          next_set_->clear();
          next_set_->push_back(script);
        }

        // And pop stack to this point.
        int num_popped =
            static_cast<int>(std::distance(brackets_.rbegin(), it));
        // TODO: No resize operation in WTF::Deque?
        for (int i = 0; i < num_popped; ++i)
          brackets_.pop_back();
        brackets_fixup_depth_ = static_cast<wtf_size_t>(
            std::max(0, static_cast<int>(brackets_fixup_depth_) - num_popped));
        return;
      }
    }
  }
  // leave stack alone, no match
}

// Keep items in current_set_ that are in next_set_.
//
// If the sets are disjoint, return false and leave current_set_ unchanged. Else
// return true and make current set the intersection. Make sure to maintain
// current priority script as priority if it remains, else retain next priority
// script if it remains.
//
// Also maintain a common preferred script.  If current and next are both
// common, and there is no common preferred script and next has a preferred
// script, set the common preferred script to that of next.
bool ScriptRunIterator::MergeSets() {
  if (next_set_->empty() || current_set_.empty()) {
    return false;
  }

  auto current_set_it = current_set_.begin();
  auto current_end = current_set_.end();
  // Most of the time, this is the only one.
  // Advance the current iterator, we won't need to check it again later.
  UScriptCode priority_script = *current_set_it++;

  // If next is common or inherited, the only thing that might change
  // is the common preferred script.
  if (next_set_->at(0) <= USCRIPT_INHERITED) {
    if (next_set_->size() == 2 && priority_script <= USCRIPT_INHERITED &&
        common_preferred_ == USCRIPT_COMMON) {
      common_preferred_ = next_set_->at(1);
    }
    return true;
  }

  // If current is common or inherited, use the next script set.
  if (priority_script <= USCRIPT_INHERITED) {
    current_set_ = *next_set_;
    return true;
  }

  // Neither is common or inherited. If current is a singleton,
  // just see if it exists in the next set. This is the common case.
  bool have_priority = base::Contains(*next_set_, priority_script);
  if (current_set_it == current_end) {
    return have_priority;
  }

  // Establish the priority script, if we have one.
  // First try current priority script.
  auto next_it = next_set_->begin();
  auto next_end = next_set_->end();
  if (!have_priority) {
    // So try next priority script.
    // Skip the first current script, we already know it's not there.
    // Advance the next iterator, later we won't need to check it again.
    priority_script = *next_it++;
    have_priority =
        std::find(current_set_it, current_end, priority_script) != current_end;
  }

  // Note that we can never write more scripts into the current vector than
  // it already contains, so currentWriteIt won't ever exceed the size/capacity.
  auto current_write_it = current_set_.begin();
  if (have_priority) {
    // keep the priority script.
    *current_write_it++ = priority_script;
  }

  if (next_it != next_end) {
    // Iterate over the remaining current scripts, and keep them if
    // they occur in the remaining next scripts.
    while (current_set_it != current_end) {
      UScriptCode sc = *current_set_it++;
      if (std::find(next_it, next_end, sc) != next_end) {
        *current_write_it++ = sc;
      }
    }
  }

  // Only change current if the run continues.
  int written =
      static_cast<int>(std::distance(current_set_.begin(), current_write_it));
  if (written > 0) {
    current_set_.resize(written);
    return true;
  }
  return false;
}

// When we hit the end of the run, and resolve the script, we now know the
// resolved script of any open bracket that was pushed on the stack since
// the start of the run. Fixup depth records how many of these there
// were. We've maintained this count during pushes, and taken care to
// adjust it if the stack got overfull and open brackets were pushed off
// the bottom. This sets the script of the fixup_depth topmost entries of the
// stack to the resolved script.
void ScriptRunIterator::FixupStack(UScriptCode resolved_script,
                                   bool exclude_last) {
  wtf_size_t count = brackets_fixup_depth_;
  if (count <= 0)
    return;
  if (count > brackets_.size()) {
    // Should never happen unless someone breaks the code.
    DLOG(ERROR) << "Brackets fixup depth exceeds size of bracket vector.";
    count = brackets_.size();
  }
  auto it = brackets_.rbegin();
  // Do not assign the script to the last one if |exclude_last|.
  if (exclude_last) {
    ++it;
    --count;
    brackets_fixup_depth_ = 1;
  } else {
    brackets_fixup_depth_ = 0;
  }
  for (; count; ++it, --count)
    it->script = resolved_script;
}

bool ScriptRunIterator::Fetch(wtf_size_t* pos, UChar32* ch) {
  if (ahead_pos_ > length_) {
    return false;
  }
  *pos = ahead_pos_ - (ahead_character_ >= 0x10000 ? 2 : 1);
  *ch = ahead_character_;

  std::swap(next_set_, ahead_set_);
  if (ahead_pos_ == length_) {
    // No more data to fetch, but last character still needs to be processed.
    // Advance ahead_pos_ so that next time we will know this has been done.
    ahead_pos_++;
    return true;
  }

  U16_NEXT(text_, ahead_pos_, length_, ahead_character_);
  script_data_->GetScripts(ahead_character_, *ahead_set_);
  if (ahead_set_->empty()) {
    // No scripts for this character. This has already been logged, so
    // we just terminate processing this text.
    return false;
  }
  if ((*ahead_set_)[0] == USCRIPT_INHERITED && ahead_set_->size() > 1) {
    if ((*next_set_)[0] == USCRIPT_COMMON) {
      // Overwrite the next set with the non-inherited portion of the set.
      *next_set_ = *ahead_set_;
      next_set_->EraseAt(0);
      // Discard the remaining values, we'll inherit.
      ahead_set_->resize(1);
    } else {
      // Else, this applies to anything.
      ahead_set_->resize(1);
    }
  }
  return true;
}

UScriptCode ScriptRunIterator::ResolveCurrentScript() const {
  UScriptCode result = current_set_.at(0);
  return result == USCRIPT_COMMON ? common_preferred_ : result;
}

}  // namespace blink

"""

```
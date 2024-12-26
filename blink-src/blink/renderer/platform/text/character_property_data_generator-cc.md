Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

1. **Understand the Goal:** The core request is to understand what this C++ file *does* within the Blink rendering engine. Specifically, the prompt asks about its functions, relationships to web technologies (HTML, CSS, JavaScript), logic, and potential errors.

2. **Initial Scan - High-Level Purpose:** The filename `character_property_data_generator.cc` immediately suggests it's a *generator*. It's not code that runs during webpage rendering. It generates *data*. The `character_property_data.h` include confirms this – it's creating data about character properties.

3. **Key Components Identification:**  I'll look for the main actors and their roles:

    * **ICU Library:** The includes like `<unicode/brkiter.h>`, `<unicode/ucptrie.h>`, etc., clearly indicate heavy reliance on the International Components for Unicode (ICU) library. This library is a cornerstone for handling text and internationalization.
    * **`CharacterProperty`:** This is a central data structure, likely a bitfield or enum, holding information about individual characters.
    * **`CharacterPropertyValues` Class:** This class seems responsible for *calculating* or *determining* the `CharacterProperty` for each Unicode code point.
    * **`UMutableCPTrie` and `UCPTrie`:** These ICU data structures represent tries (prefix trees) optimized for storing character properties efficiently. The "Mutable" and immutable distinction is important for the generation process.
    * **`LineBreakData` Class:** This class focuses specifically on generating data related to line breaking rules.
    * **`GenerateCharacterPropertyData` function:**  This function orchestrates the creation of the character property trie.
    * **`LineBreakData::Generate` function:** This function generates the line break table.
    * **`main` function:** This function is the entry point, indicating this is a standalone executable. It initializes ICU and calls the generator functions.

4. **Dissecting `GenerateCharacterPropertyData`:** This is the core of the character property generation:

    * **Instantiation of `CharacterPropertyValues`:** This populates the `values_` array with the initial character properties.
    * **Iterating and Setting Properties:** The `#define SET` macro and the `SetForRanges`, `SetForValues`, and `SetForUnicodeSet` functions show how different character properties are assigned based on predefined ranges, individual values, and Unicode sets.
    * **Trie Construction:** The code creates a mutable trie, iterates through the `values_` array, and efficiently stores contiguous ranges of characters with the same properties in the trie. This is a key optimization.
    * **Serialization:**  The mutable trie is converted to an immutable one and then serialized into a byte array. This byte array is what will be included in the Blink engine.
    * **Output:** The `GenerateUTrieSerialized` function formats the serialized data as a C++ header file (`.h`) for inclusion in the Blink codebase.

5. **Dissecting `LineBreakData::Generate`:**

    * **ICU BreakIterator:**  It uses ICU's `BreakIterator` to determine line break opportunities based on the default locale.
    * **ASCII-Specific Rules:**  It then adds specific rules for ASCII characters, potentially overriding the ICU defaults to match browser compatibility requirements. This highlights the practical, browser-specific aspects of rendering.
    * **Table Generation:** The `Print` function formats the line break data as a 2D array in a C++ header file.

6. **Connecting to Web Technologies:**  Now, consider how this *generated data* is used:

    * **HTML Rendering:**  The line break data is directly used when rendering HTML text to determine where lines can be wrapped. The character properties (specifically the Han kerning information) influence how CJK text is laid out.
    * **CSS `word-break` and `overflow-wrap`:** These CSS properties indirectly rely on the line break data. The browser uses the line breaking rules to decide where to break words based on the specified CSS behavior.
    * **JavaScript String Manipulation:** JavaScript string manipulation doesn't directly use this generated data *during script execution*. However, the *rendering* of those manipulated strings in the browser will use this data.
    * **Custom Elements:** The `kIsPotentialCustomElementNameChar` property relates to the definition of valid custom element names in HTML.

7. **Logical Inferences and Examples:**

    * **Character Property Logic:**  The code explicitly sets properties for certain character ranges and individual characters. I need to pick some examples to illustrate this, like the Han kerning characters and the Unicode sets used for them.
    * **Line Break Logic:** The ASCII rules are interesting and showcase browser compatibility considerations. Providing examples of how these rules affect line breaking (e.g., breaking *before* an opening parenthesis but not *after*) is useful.

8. **Identifying Potential Errors:**

    * **ICU Initialization:**  If the ICU data file isn't found, or if `udata_setCommonData` fails, that's a critical error. The code handles the "built-in data" case, but a mismatch or corruption could cause problems.
    * **Unicode Set Parsing Errors:** If the Unicode set patterns are invalid, ICU will throw an error. The `CHECK_EQ(error, U_ZERO_ERROR)` lines are crucial for detecting this.
    * **Data Inconsistencies:**  If the manual ASCII line break rules conflict with ICU's default rules, this could lead to rendering inconsistencies.

9. **Structuring the Answer:** Organize the information logically, starting with the main function, then the data generation processes, and finally, the connections to web technologies and potential errors. Use clear headings and examples.

10. **Refinement and Clarity:** Review the answer for clarity and accuracy. Ensure the examples are easy to understand and the explanations are concise. Double-check the technical terms and their meanings within the Blink context. For instance, be precise about the distinction between data *generation* and data *usage* during rendering.
这个文件 `blink/renderer/platform/text/character_property_data_generator.cc` 的主要功能是**生成用于描述 Unicode 字符属性的静态数据**，这些数据被 Blink 渲染引擎在处理文本时使用。

更具体地说，它生成了两个关键的数据结构：

1. **字符属性查找表 (Character Property Data):**  这是一个经过优化的数据结构（使用 ICU 的 `UCPTrie`），用于快速查找给定 Unicode 码点的各种属性。这些属性存储在 `CharacterProperty` 枚举中。
2. **快速行分隔配对表 (Fast Line Break Pair Table):**  这是一个小的查找表，用于加速常见 ASCII 字符之间的行分隔判断。

**与 JavaScript, HTML, CSS 的关系：**

虽然这个文件本身是用 C++ 编写的，并且是一个生成数据的工具，但它生成的**数据**对于正确渲染 HTML、CSS 和处理 JavaScript 中的文本至关重要。

* **HTML:**
    * **文本渲染:** 当浏览器渲染 HTML 文本时，需要知道每个字符的属性，例如是否是 CJK 表意文字，是否是潜在的自定义元素名称字符等。这些信息影响文本的排版、换行、断词等。
    * **自定义元素名称:**  `kIsPotentialCustomElementNameChar` 属性用于验证 HTML 自定义元素的名称是否合法。

* **CSS:**
    * **`word-break` 和 `overflow-wrap` 属性:** 这些 CSS 属性控制文本在容器中溢出时的换行行为。浏览器需要字符属性数据来确定单词的边界以及允许换行的位置。例如，CJK 字符通常可以在字符之间换行，而拉丁字符通常需要在空格或连字符处换行。`LineBreakData` 生成的表直接影响这些属性的实现。
    * **`text-spacing` 属性:**  `HanKerningCharType` 用于实现 CSS 的 `text-spacing` 属性，该属性允许调整 CJK 字符之间的间距。例如，在标点符号周围增加或减少间距。

* **JavaScript:**
    * **字符串处理:** JavaScript 中的字符串操作涉及到对字符的分析和处理。虽然 JavaScript 引擎本身不直接使用这个文件生成的数据，但当 JavaScript 操作的字符串最终被渲染到页面上时，Blink 渲染引擎会使用这些数据来正确显示文本。
    * **正则表达式:** 一些正则表达式的元字符和字符类（例如 `\w`, `\s`）的匹配规则也可能受到字符属性数据的影响。

**逻辑推理 (假设输入与输出):**

这个程序的主要逻辑是遍历所有可能的 Unicode 码点 (0 到 0x10FFFF) 并为每个码点确定其 `CharacterProperty`。

**假设输入 (部分):**

* **ICU 数据文件:** 程序依赖 ICU (International Components for Unicode) 库来获取字符属性的初始信息。它会尝试加载 `icudtl.dat` 文件。
* **字符属性的定义:**  `CharacterPropertyValues::Initialize()` 函数中定义了各种字符属性的规则，例如哪些字符范围是 CJK 表意文字，哪些字符是双向控制字符等。这些规则硬编码在 C++ 代码中，并使用 ICU 的 Unicode Sets 进行更复杂的匹配。

**假设输出 (部分):**

* **`kSerializedCharacterData` 数组:**  这是一个 `uint8_t` 数组，包含了经过序列化的 `UCPTrie` 数据。这个 trie 允许根据 Unicode 码点快速查找对应的 `CharacterProperty` 值。例如，如果输入码点是汉字 "你" (U+4F60)，则通过查找这个 trie 可以得到其 `kIsCJKIdeographOrSymbol` 属性为真。
* **`kFastLineBreakTable` 数组:**  这是一个二维布尔数组，表示两个 ASCII 字符之间是否应该发生断行。例如，`kFastLineBreakTable['a' - '!', ' ' - '!']` 的值可能为真，表示在字母 'a' 后面可以换行。

**用户或编程常见的使用错误 (与此文件相关的):**

由于这是一个数据生成工具，用户或程序员直接使用此文件源码的机会不多。但是，如果开发者修改了此文件中的规则，可能会导致以下错误：

1. **错误的字符属性:** 如果 `CharacterPropertyValues::Initialize()` 中的规则被错误修改，可能导致某些字符的属性被错误标记。例如，将某个非 CJK 字符错误标记为 CJK 字符，可能会影响文本的排版和断行。
    * **举例:**  假设错误地将拉丁字母 'A' 添加到 `kIsCJKIdeographOrSymbolRanges` 中。这会导致浏览器在渲染包含 'A' 的文本时，可能将其视为 CJK 字符进行处理，例如允许在 'A' 后面断行，这在英文文本中是不希望发生的。

2. **ICU 数据加载失败:** 如果程序无法找到或加载正确的 ICU 数据文件，会导致程序运行失败，无法生成数据。
    * **举例:**  如果运行此生成器的环境缺少 `icudtl.dat` 文件，程序会报错并退出。

3. **生成的 `UCPTrie` 数据损坏:** 如果生成 `UCPTrie` 的过程出现错误，导致序列化的数据不正确，那么 Blink 渲染引擎在加载和使用这些数据时可能会崩溃或产生不可预测的行为。

4. **`LineBreakData` 表格错误:**  如果 `FillAscii()` 或 `FillFromIcu()` 中的逻辑错误，可能导致错误的行分隔判断，影响网页的排版。
    * **举例:**  假设错误地设置了 `SetPairValue('a', 'b', true)`，意味着在字母 'a' 和 'b' 之间允许换行。这会导致像 "alphabet" 这样的词被错误地断开。

总而言之，`character_property_data_generator.cc` 是 Blink 引擎构建过程中的一个关键环节，它生成的数据是正确渲染各种语言文本的基础。对这个文件的修改需要非常谨慎，因为它直接影响到网页的视觉呈现和文本处理的正确性。

Prompt: 
```
这是目录为blink/renderer/platform/text/character_property_data_generator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/text/character_property_data.h"

#include <stdio.h>
#include <unicode/brkiter.h>
#include <unicode/locid.h>
#include <unicode/ucptrie.h>
#include <unicode/udata.h>
#include <unicode/ulocdata.h>
#include <unicode/umutablecptrie.h>
#include <unicode/uniset.h>
#include <unicode/unistr.h>

#include <cassert>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <vector>

#include "base/check_op.h"
#include "base/containers/heap_array.h"
#include "base/containers/span.h"
#include "third_party/blink/renderer/platform/text/character_property.h"
#include "third_party/blink/renderer/platform/text/han_kerning_char_type.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"

namespace blink {
namespace {

#define CHECK_U_ERROR(error, name) \
  CHECK(U_SUCCESS(error)) << name << ": (" << error << ")" << u_errorName(error)

// Check ICU functions that need the data resources are working.
// https://unicode-org.github.io/icu/userguide/icu/design.html#icu4c-initialization-and-termination
void CheckIcuDataResources() {
  UErrorCode error = U_ZERO_ERROR;
  UVersionInfo version;
  ulocdata_getCLDRVersion(version, &error);
  CHECK_U_ERROR(error, "ulocdata_getCLDRVersion");
}

//
// Load the ICU data file and set it to the ICU.
//
void InitializeIcu(const char* exec_path) {
  // ICU can't load the data file by itself because ICU tries to load the
  // versioned data file (e.g., "icudt73l.dat"), while the Chromium build system
  // creates the unversioned data file (e.g., "icudtl.dat").
  std::filesystem::path path{exec_path};
  path = path.parent_path() / "icudt" U_ICUDATA_TYPE_LETTER ".dat";

  std::ifstream data_ifstream(path, std::ios_base::binary);
  if (!data_ifstream.is_open()) {
    // When the build config is `!use_icu_data_file`, the ICU data is built into
    // the binary.
    CheckIcuDataResources();
    return;
  }
  static std::vector<uint8_t> icu_data;
  CHECK(icu_data.empty());
  std::copy(std::istreambuf_iterator<char>(data_ifstream),
            std::istreambuf_iterator<char>(), std::back_inserter(icu_data));
  UErrorCode error = U_ZERO_ERROR;
  udata_setCommonData(icu_data.data(), &error);
  CHECK_U_ERROR(error, "udata_setCommonData");

  CheckIcuDataResources();
}

class CharacterPropertyValues {
 public:
  constexpr static UChar32 kMaxCodepoint = 0x10FFFF;
  constexpr static UChar32 kSize = kMaxCodepoint + 1;

  CharacterPropertyValues() : values_(new CharacterProperty[kSize]) {
    Initialize();
  }

  CharacterProperty operator[](UChar32 index) const { return values_[index]; }

 private:
  void Initialize() {
    memset(values_.get(), 0, sizeof(CharacterProperty) * kSize);

#define SET(name)                                     \
  SetForRanges(name##Ranges, std::size(name##Ranges), \
               CharacterProperty::name);              \
  SetForValues(name##Array, std::size(name##Array), CharacterProperty::name);

    SET(kIsCJKIdeographOrSymbol);
    SET(kIsPotentialCustomElementNameChar);
    SET(kIsBidiControl);
#undef SET
    SetForRanges(kIsHangulRanges, std::size(kIsHangulRanges),
                 CharacterProperty::kIsHangul);
    SetHanKerning();
  }

  void SetHanKerning() {
    // https://drafts.csswg.org/css-text-4/#text-spacing-classes
    Set(kLeftSingleQuotationMarkCharacter, HanKerningCharType::kOpenQuote);
    Set(kLeftDoubleQuotationMarkCharacter, HanKerningCharType::kOpenQuote);
    Set(kRightSingleQuotationMarkCharacter, HanKerningCharType::kCloseQuote);
    Set(kRightDoubleQuotationMarkCharacter, HanKerningCharType::kCloseQuote);
    Set(kIdeographicSpaceCharacter, HanKerningCharType::kMiddle);
    Set(kIdeographicCommaCharacter, HanKerningCharType::kDot);
    Set(kIdeographicFullStopCharacter, HanKerningCharType::kDot);
    Set(kFullwidthComma, HanKerningCharType::kDot);
    Set(kFullwidthFullStop, HanKerningCharType::kDot);
    Set(kFullwidthColon, HanKerningCharType::kColon);
    Set(kFullwidthSemicolon, HanKerningCharType::kSemicolon);
    Set(kMiddleDotCharacter, HanKerningCharType::kMiddle);
    Set(kHyphenationPointCharacter, HanKerningCharType::kMiddle);
    Set(kKatakanaMiddleDot, HanKerningCharType::kMiddle);
    SetForUnicodeSet("[[:blk=CJK_Symbols:][:ea=F:] & [:gc=Ps:]]",
                     HanKerningCharType::kOpen);
    SetForUnicodeSet("[[:blk=CJK_Symbols:][:ea=F:] & [:gc=Pe:]]",
                     HanKerningCharType::kClose);
    SetForUnicodeSet("[[:gc=Ps:] - [:blk=CJK_Symbols:] - [:ea=F:]]",
                     HanKerningCharType::kOpenNarrow);
    SetForUnicodeSet("[[:gc=Pe:] - [:blk=CJK_Symbols:] - [:ea=F:]]",
                     HanKerningCharType::kCloseNarrow);
  }

  static CharacterProperty ToCharacterProperty(HanKerningCharType value) {
    CHECK_EQ((static_cast<unsigned>(value) &
              ~static_cast<unsigned>(CharacterProperty::kHanKerningMask)),
             0u);
    return static_cast<CharacterProperty>(
        static_cast<unsigned>(value)
        << static_cast<unsigned>(CharacterProperty::kHanKerningShift));
  }

  void SetForUnicodeSet(const char* pattern, HanKerningCharType type) {
    SetForUnicodeSet(pattern, ToCharacterProperty(type),
                     CharacterProperty::kHanKerningShiftedMask);
  }

  // For `patterns`, see:
  // https://unicode-org.github.io/icu/userguide/strings/unicodeset.html#unicodeset-patterns
  void SetForUnicodeSet(const char* pattern,
                        CharacterProperty value,
                        CharacterProperty mask) {
    UErrorCode error = U_ZERO_ERROR;
    icu::UnicodeSet set(icu::UnicodeString(pattern), error);
    CHECK_EQ(error, U_ZERO_ERROR);
    const int32_t range_count = set.getRangeCount();
    for (int32_t i = 0; i < range_count; ++i) {
      const UChar32 end = set.getRangeEnd(i);
      for (UChar32 ch = set.getRangeStart(i); ch <= end; ++ch) {
        CHECK_EQ(static_cast<unsigned>(values_[ch] & mask), 0u);
        values_[ch] |= value;
      }
    }
  }

  void SetForRanges(const UChar32* ranges,
                    size_t length,
                    CharacterProperty value) {
    CHECK_EQ(length % 2, 0u);
    const UChar32* end = ranges + length;
    for (; ranges != end; ranges += 2) {
      CHECK_LE(ranges[0], ranges[1]);
      CHECK_LE(ranges[1], kMaxCodepoint);
      for (UChar32 c = ranges[0]; c <= ranges[1]; c++) {
        values_[c] |= value;
      }
    }
  }

  void SetForValues(const UChar32* begin,
                    size_t length,
                    CharacterProperty value) {
    const UChar32* end = begin + length;
    for (; begin != end; begin++) {
      CHECK_LE(*begin, kMaxCodepoint);
      values_[*begin] |= value;
    }
  }

  void Set(UChar32 ch, HanKerningCharType type) {
    const CharacterProperty value = ToCharacterProperty(type);
    CHECK_EQ(static_cast<unsigned>(values_[ch] &
                                   CharacterProperty::kHanKerningShiftedMask),
             0u);
    values_[ch] |= value;
  }

  std::unique_ptr<CharacterProperty[]> values_;
};

static void GenerateUTrieSerialized(FILE* fp,
                                    size_t size,
                                    base::span<uint8_t> array) {
  fprintf(fp,
          "#include <cstdint>\n\n"
          "namespace blink {\n\n"
          "extern const int32_t kSerializedCharacterDataSize = %zu;\n"
          // The utrie2_openFromSerialized function requires character data to
          // be aligned to 4 bytes.
          "alignas(4) extern const uint8_t kSerializedCharacterData[] = {",
          size);
  for (size_t i = 0; i < size;) {
    fprintf(fp, "\n   ");
    for (size_t col = 0; col < 16 && i < size; ++col, ++i) {
      fprintf(fp, " 0x%02X,", array[i]);
    }
  }
  fprintf(fp,
          "\n};\n\n"
          "} // namespace blink\n");
}

static void GenerateCharacterPropertyData(FILE* fp) {
  // Create a value array of all possible code points.
  CharacterPropertyValues values;

  // Create a trie from the value array.
  UErrorCode error = U_ZERO_ERROR;
  std::unique_ptr<UMutableCPTrie, decltype(&umutablecptrie_close)> trie(
      umutablecptrie_open(0, 0, &error), umutablecptrie_close);
  assert(error == U_ZERO_ERROR);
  UChar32 start = 0;
  CharacterProperty value = values[0];
  for (UChar32 c = 1;; c++) {
    if (c < CharacterPropertyValues::kSize && values[c] == value) {
      continue;
    }
    if (static_cast<uint32_t>(value)) {
      umutablecptrie_setRange(trie.get(), start, c - 1,
                              static_cast<uint32_t>(value), &error);
      assert(error == U_ZERO_ERROR);
    }
    if (c >= CharacterPropertyValues::kSize) {
      break;
    }
    start = c;
    value = values[start];
  }

  // Convert to immutable UCPTrie in order to be able to serialize.
  std::unique_ptr<UCPTrie, decltype(&ucptrie_close)> immutable_trie(
      umutablecptrie_buildImmutable(trie.get(), UCPTrieType::UCPTRIE_TYPE_FAST,
                                    UCPTrieValueWidth::UCPTRIE_VALUE_BITS_16,
                                    &error),
      ucptrie_close);

  assert(error == U_ZERO_ERROR);

  int32_t serialized_size =
      ucptrie_toBinary(immutable_trie.get(), nullptr, 0, &error);
  CHECK_GE(serialized_size, 0);
  error = U_ZERO_ERROR;

  auto serialized =
      base::HeapArray<uint8_t>::Uninit(static_cast<size_t>(serialized_size));
  // Ensure 32-bit alignment, as ICU requires that to the ucptrie_toBinary call.
  CHECK(!(reinterpret_cast<intptr_t>(serialized.data()) % 4));

  serialized_size = ucptrie_toBinary(immutable_trie.get(), serialized.data(),
                                     serialized.size(), &error);
  CHECK_GE(serialized_size, 0);
  assert(error == U_ZERO_ERROR);

  GenerateUTrieSerialized(fp, static_cast<size_t>(serialized_size), serialized);
}

//
// Generate a line break pair table in `break_iterator_data_inline_header.h`.
//
// See [UAX14](https://unicode.org/reports/tr14/).
//
class LineBreakData {
 public:
  LineBreakData() = default;

  static void Generate(FILE* fp) {
    LineBreakData data;
    data.FillFromIcu();
    data.FillAscii();
    data.Print(fp);
  }

 private:
  // Fill the pair table from the ICU BreakIterator.
  void FillFromIcu() {
    UErrorCode status = U_ZERO_ERROR;
    const icu::Locale locale("en");
    icu::BreakIterator* break_iterator =
        icu::BreakIterator::createLineInstance(locale, status);
    CHECK_U_ERROR(status, "createLineInstance");

    for (UChar ch = kMinChar; ch <= kMaxChar; ++ch) {
      const icu::UnicodeString ch_str(ch);
      for (UChar ch_next = kMinChar; ch_next <= kMaxChar; ++ch_next) {
        const icu::UnicodeString ch_next_str(ch_next);
        const icu::UnicodeString str = ch_str + ch_next_str;
        break_iterator->setText(str);
        SetPairValue(ch, ch_next, break_iterator->isBoundary(1));
      }
    }
  }

  // Line breaking table for printable ASCII characters. Line breaking
  // opportunities in this table are as below:
  // - before opening punctuations such as '(', '<', '[', '{' after certain
  //   characters (compatible with Firefox 3.6);
  // - after '-' and '?' (backward-compatible, and compatible with Internet
  //   Explorer).
  // Please refer to <https://bugs.webkit.org/show_bug.cgi?id=37698> for line
  // breaking matrixes of different browsers and the ICU standard.
  void FillAscii() {
#define ALL_CHAR '!', 0x7F
    SetPairValue(ALL_CHAR, ALL_CHAR, false);
    SetPairValue(ALL_CHAR, '(', '(', true);
    SetPairValue(ALL_CHAR, '<', '<', true);
    SetPairValue(ALL_CHAR, '[', '[', true);
    SetPairValue(ALL_CHAR, '{', '{', true);
    SetPairValue('-', '-', ALL_CHAR, true);
    SetPairValue('?', '?', ALL_CHAR, true);
    SetPairValue('-', '-', '$', '$', false);
    SetPairValue(ALL_CHAR, '!', '!', false);
    SetPairValue('?', '?', '"', '"', false);
    SetPairValue('?', '?', '\'', '\'', false);
    SetPairValue(ALL_CHAR, ')', ')', false);
    SetPairValue(ALL_CHAR, ',', ',', false);
    SetPairValue(ALL_CHAR, '.', '.', false);
    SetPairValue(ALL_CHAR, '/', '/', false);
    // Note: Between '-' and '[0-9]' is hard-coded in `ShouldBreakFast()`.
    SetPairValue('-', '-', '0', '9', false);
    SetPairValue(ALL_CHAR, ':', ':', false);
    SetPairValue(ALL_CHAR, ';', ';', false);
    SetPairValue(ALL_CHAR, '?', '?', false);
    SetPairValue(ALL_CHAR, ']', ']', false);
    SetPairValue(ALL_CHAR, '}', '}', false);
    SetPairValue('$', '$', ALL_CHAR, false);
    SetPairValue('\'', '\'', ALL_CHAR, false);
    SetPairValue('(', '(', ALL_CHAR, false);
    SetPairValue('/', '/', ALL_CHAR, false);
    SetPairValue('0', '9', ALL_CHAR, false);
    SetPairValue('<', '<', ALL_CHAR, false);
    SetPairValue('@', '@', ALL_CHAR, false);
    SetPairValue('A', 'Z', ALL_CHAR, false);
    SetPairValue('[', '[', ALL_CHAR, false);
    SetPairValue('^', '`', ALL_CHAR, false);
    SetPairValue('a', 'z', ALL_CHAR, false);
    SetPairValue('{', '{', ALL_CHAR, false);
    SetPairValue(0x7F, 0x7F, ALL_CHAR, false);
#undef ALL_CHAR
  }

  // Print the C++ source code.
  void Print(FILE* fp) {
    // Print file headers.
    fprintf(fp,
            "#include <cstdint>\n"
            "#include "
            "\"third_party/blink/renderer/platform/wtf/text/wtf_uchar.h\"\n"
            "\nnamespace {\n\n");

    fprintf(fp, "constexpr UChar kFastLineBreakMinChar = 0x%02X;\n", kMinChar);
    fprintf(fp, "constexpr UChar kFastLineBreakMaxChar = 0x%02X;\n", kMaxChar);

    // Define macros.
    fprintf(fp,
            "\n#define B(a, b, c, d, e, f, g, h)"
            " ((a) | ((b) << 1) | ((c) << 2) | ((d) << 3) |"
            " ((e) << 4) | ((f) << 5) | ((g) << 6) | ((h) << 7))\n\n");

    fprintf(fp, "const uint8_t kFastLineBreakTable[%d][%d] = {\n", kNumChars,
            kNumCharsRoundUp8 / 8);

    // Print the column comment.
    fprintf(fp, "           /*");
    for (UChar ch = kMinChar; ch <= kMaxChar; ++ch) {
      if (ch != kMinChar && (ch - kMinChar) % 8 == 0) {
        fprintf(fp, "   ");
      }
      fprintf(fp, ch < 0x7F ? " %c" : "%02X", ch);
    }
    fprintf(fp, " */\n");

    // Print the data array.
    for (int y = 0; y < kNumChars; ++y) {
      const UChar ch = y + kMinChar;
      fprintf(fp, "/* %02X %c */ {B(", ch, ch < 0x7F ? ch : ' ');
      const char* prefix = "";
      for (int x = 0; x < kNumCharsRoundUp8; ++x) {
        fprintf(fp, "%s%d", prefix, pair_[y][x]);
        prefix = (x % 8 == 7) ? "),B(" : ",";
      }
      fprintf(fp, ")},\n");
    }
    fprintf(fp,
            "};\n\n"
            "#undef B\n\n"
            "template <typename T>\n"
            "inline uint8_t GetFastLineBreak(T ch1, T ch2) {\n"
            "  const T i2 = ch2 - kFastLineBreakMinChar;\n"
            "  return kFastLineBreakTable[ch1 - kFastLineBreakMinChar]"
            "[i2 / 8] & (1 << (i2 %% 8));\n"
            "}\n\n"
            "}  // namespace\n");
  }

  void SetPairValue(UChar ch1_min,
                    UChar ch1_max,
                    UChar ch2_min,
                    UChar ch2_max,
                    bool value) {
    for (UChar ch1 = ch1_min; ch1 <= ch1_max; ++ch1) {
      for (UChar ch2 = ch2_min; ch2 <= ch2_max; ++ch2) {
        SetPairValue(ch1, ch2, value);
      }
    }
  }

  // Set the breakability between `ch1` and `ch2`.
  void SetPairValue(UChar ch1, UChar ch2, bool value) {
    CHECK_GE(ch1, kMinChar);
    CHECK_LE(ch1, kMaxChar);
    CHECK_GE(ch2, kMinChar);
    CHECK_LE(ch2, kMaxChar);
    pair_[ch1 - kMinChar][ch2 - kMinChar] = value;
  }

  constexpr static UChar kMinChar = '!';
  constexpr static UChar kMaxChar = 0xFF;
  constexpr static int kNumChars = kMaxChar - kMinChar + 1;
  constexpr static int kNumCharsRoundUp8 = (kNumChars + 7) / 8 * 8;
  bool pair_[kNumChars][kNumCharsRoundUp8]{};
};

void InvokeGenerator(int index,
                     int argc,
                     char** argv,
                     void (*generator)(FILE*)) {
  if (index >= argc) {
    return;
  }
  const char* path = argv[index];
  if (!*path) {
    return;
  }

  if (strcmp(path, "-") == 0) {
    (*generator)(stdout);
    return;
  }

  FILE* fp = fopen(path, "wb");
  (*generator)(fp);
  fclose(fp);
}

}  // namespace
}  // namespace blink

int main(int argc, char** argv) {
  blink::InitializeIcu(argv[0]);
  blink::InvokeGenerator(1, argc, argv, blink::GenerateCharacterPropertyData);
  blink::InvokeGenerator(2, argc, argv, blink::LineBreakData::Generate);

  return 0;
}

"""

```
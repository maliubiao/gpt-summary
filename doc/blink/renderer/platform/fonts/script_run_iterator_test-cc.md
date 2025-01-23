Response:
The user wants to understand the functionality of the `script_run_iterator_test.cc` file in the Chromium Blink engine. I need to analyze the code and explain its purpose, its relation to web technologies, provide examples with input and output, and illustrate common usage errors.

**Plan:**

1. **Identify the core functionality:** The file contains unit tests for the `ScriptRunIterator` class.
2. **Explain `ScriptRunIterator`'s role:**  It iterates through a string and identifies contiguous runs of text with the same script.
3. **Relate to web technologies:**  Script identification is crucial for rendering text correctly in different languages and scripts (JavaScript, HTML, CSS).
4. **Provide examples:** Demonstrate how the tests verify the correct identification of script runs for various scenarios (mixed scripts, parentheses, special characters).
5. **Illustrate logical reasoning:** Show how the tests use mock data and assertions to verify the iterator's behavior.
6. **Identify potential usage errors:**  Common mistakes might involve incorrect handling of script boundaries or assumptions about script identification.
这个文件 `script_run_iterator_test.cc` 是 Chromium Blink 引擎中用于测试 `ScriptRunIterator` 类的单元测试文件。`ScriptRunIterator` 的主要功能是**将一段文本分割成不同的“runs”，每个 run 中的字符都属于同一个 Unicode script（脚本）**。

**功能详解:**

1. **测试 `ScriptRunIterator` 的基本功能:**  这个文件包含了一系列的测试用例，用于验证 `ScriptRunIterator` 能否正确地识别文本中不同 script 的边界。
2. **模拟不同的文本场景:**  测试用例覆盖了各种文本组合，包括：
    *   只包含一种 script 的文本（例如，纯 Latin 字母，纯汉字）。
    *   包含多种 script 的文本，例如 Latin 字母和汉字混合。
    *   包含标点符号、空格等 common script 的字符。
    *   包含括号等需要特殊处理的字符。
    *   包含 emoji 等特殊字符。
    *   包含具有多个可能 script 的字符，并测试其如何根据上下文选择 script。
3. **使用 Mock 数据进行测试:**  为了更精细地控制字符的 script 属性，文件中定义了一个 `MockScriptData` 类。这个类允许自定义字符的 script 属性，以便测试 `ScriptRunIterator` 在各种假设情况下的行为。
4. **验证输出结果:**  每个测试用例都会定义期望的 script runs 及其边界，然后使用 `ScriptRunIterator` 处理输入文本，并断言实际生成的 runs 与期望的 runs 一致。

**与 JavaScript, HTML, CSS 的关系:**

`ScriptRunIterator` 的功能直接关系到网页内容的正确显示，这与 JavaScript, HTML, CSS 都有密切联系：

*   **HTML:** HTML 定义了网页的结构和内容。当 HTML 包含多种语言或 script 的文本时，浏览器需要正确识别这些 script，以便应用正确的字体和排版规则。`ScriptRunIterator` 的功能是浏览器渲染引擎处理 HTML 内容的基础步骤之一。
*   **CSS:** CSS 用于控制网页的样式，包括字体、颜色、排版等。不同的 script 可能需要不同的字体支持才能正确显示。例如，汉字需要包含汉字字形的字体，而 Latin 字母需要包含 Latin 字形的字体。`ScriptRunIterator` 识别出的 script runs 可以帮助浏览器选择合适的字体应用到不同的文本片段。
*   **JavaScript:** JavaScript 可以动态地生成或修改网页内容。如果 JavaScript 生成了包含多种 script 的文本，浏览器同样需要使用类似 `ScriptRunIterator` 的机制来正确处理这些文本。此外，JavaScript 也可能需要获取文本的 script 信息进行一些文本处理操作。

**举例说明:**

假设有以下 HTML 代码：

```html
<div>Hello 世界！</div>
```

1. **HTML 解析:** 浏览器解析这段 HTML，得到一个包含 "Hello 世界！" 字符串的文本节点。
2. **Script 识别:**  渲染引擎会使用类似 `ScriptRunIterator` 的机制来分析这个字符串。
3. **预期输入:**  字符串 "Hello 世界！"。
4. **可能的处理过程 (内部逻辑):**
    *   "H", "e", "l", "l", "o" 被识别为 Latin script。
    *   空格 " " 被识别为 Common script。
    *   "世", "界" 被识别为 Han script。
    *   "！" 被识别为 Common script。
5. **预期输出 (Script Runs):**
    *   Run 1: "Hello", Script: USCRIPT_LATIN
    *   Run 2: " ", Script: USCRIPT_COMMON
    *   Run 3: "世界", Script: USCRIPT_HAN
    *   Run 4: "！", Script: USCRIPT_COMMON
6. **CSS 应用:**  基于识别出的 script runs，浏览器会应用相应的 CSS 样式，例如为 Latin 字符选择 Latin 字体，为汉字选择中文字体。

**逻辑推理的假设输入与输出:**

**假设输入 1:**  包含混合 script 和括号的字符串 "你好(world)！"

*   **预期输出:**
    *   Run 1: "你好", Script: USCRIPT_HAN
    *   Run 2: "(", Script: USCRIPT_COMMON (或者根据 surrounding script，可能归为 HAN 或 LATIN)
    *   Run 3: "world", Script: USCRIPT_LATIN
    *   Run 4: ")", Script: USCRIPT_COMMON (或者根据 surrounding script，可能归为 HAN 或 LATIN)
    *   Run 5: "！", Script: USCRIPT_COMMON

**假设输入 2:**  使用 Mock 数据，假设字符 `<lh>` 的 script 同时包含 Latin 和 Han。

*   **预期输出 (取决于具体的 Mock 数据配置和上下文):**  如果 `<lh>` 前面是 Han 字符，后面是 Latin 字符，`ScriptRunIterator` 可能会将 `<lh>` 归为 Han script，以保持 run 的连续性。这取决于 `ScriptRunIterator` 的具体实现和优先级策略。

**涉及用户或编程常见的使用错误:**

虽然用户或直接编写网页代码的程序员通常不会直接使用 `ScriptRunIterator` 这个类，但理解其背后的逻辑有助于避免一些与多语言文本处理相关的错误：

1. **错误地假设字符的 script:**  开发者可能会错误地假设某个字符只属于一个 script，而忽略了 Unicode 中一些字符可能属于多个 script 的情况。`ScriptRunIterator` 的测试用例中就包含了对这种情况的处理。
2. **忽略标点符号和空格的处理:**  标点符号和空格通常属于 Common script，它们在 script run 的分割中起到连接或分隔的作用。错误地处理这些字符可能导致排版问题。例如，不理解空格可能属于前一个或后一个 script run。
3. **对括号等成对符号的处理不当:**  括号等成对符号的 script 通常会根据其内部的文本或周围的文本来确定。错误地处理这些符号可能导致 script run 的分割不符合预期。例如，将括号错误地分割成单独的 run。
4. **混淆 Unicode script 和语言:**  一个 script 可以用于多种语言，而一种语言也可能使用多种 script。例如，日语可能使用 Hiragana, Katakana, Kanji (属于 Han script) 等多种 script。理解 script 和语言的区别对于正确处理多语言文本至关重要。

例如，一个常见的错误可能是简单地按照字符的 Unicode 编码范围来判断其 script，而忽略了 Unicode 的 Script\_Extensions 属性以及 `ScriptRunIterator` 中考虑的上下文因素。

总而言之，`script_run_iterator_test.cc` 文件通过各种测试用例，确保 `ScriptRunIterator` 能够准确地将文本分割成具有相同 script 的 runs，这对于浏览器正确渲染多语言网页内容至关重要。理解其功能和测试用例有助于理解浏览器处理文本的底层机制。

### 提示词
```
这是目录为blink/renderer/platform/fonts/script_run_iterator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/fonts/script_run_iterator.h"

#include <utility>

#include "base/logging.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/threading.h"

namespace blink {

struct ScriptTestRun {
  const char* const text;
  UScriptCode code;
};

struct ScriptExpectedRun {
  unsigned limit;
  UScriptCode code;

  ScriptExpectedRun(unsigned the_limit, UScriptCode the_code)
      : limit(the_limit), code(the_code) {}

  bool operator==(const ScriptExpectedRun& other) const {
    return limit == other.limit && code == other.code;
  }
};

std::ostream& operator<<(std::ostream& output, const ScriptExpectedRun& run) {
  return output << String::Format("%d:%d (%s)", run.limit, run.code,
                                  uscript_getName(run.code));
}

class MockScriptData : public ScriptData {
 public:
  ~MockScriptData() override = default;

  static const MockScriptData* Instance() {
    DEFINE_THREAD_SAFE_STATIC_LOCAL(const MockScriptData, mock_script_data, ());
    return &mock_script_data;
  }

  void GetScripts(UChar32 ch, UScriptCodeList& dst) const override {
    DCHECK_GE(ch, kMockCharMin);
    DCHECK_LT(ch, kMockCharLimit);

    int code = ch - kMockCharMin;
    dst.clear();
    switch (code & kCodeSpecialMask) {
      case kCodeSpecialCommon:
        dst.push_back(USCRIPT_COMMON);
        break;
      case kCodeSpecialInherited:
        dst.push_back(USCRIPT_INHERITED);
        break;
      default:
        break;
    }
    int list_bits = kTable[code & kCodeListIndexMask];
    if (dst.empty() && list_bits == 0) {
      dst.push_back(USCRIPT_UNKNOWN);
      return;
    }
    while (list_bits) {
      switch (list_bits & kListMask) {
        case 0:
          break;
        case kLatin:
          dst.push_back(USCRIPT_LATIN);
          break;
        case kHan:
          dst.push_back(USCRIPT_HAN);
          break;
        case kGreek:
          dst.push_back(USCRIPT_GREEK);
          break;
      }
      list_bits >>= kListShift;
    }
  }

  UChar32 GetPairedBracket(UChar32 ch) const override {
    switch (GetPairedBracketType(ch)) {
      case PairedBracketType::kBracketTypeClose:
        return ch - kBracketDelta;
      case PairedBracketType::kBracketTypeOpen:
        return ch + kBracketDelta;
      default:
        return ch;
    }
  }

  PairedBracketType GetPairedBracketType(UChar32 ch) const override {
    DCHECK_GE(ch, kMockCharMin);
    DCHECK_LT(ch, kMockCharLimit);
    int code = ch - kMockCharMin;
    if ((code & kCodeBracketBit) == 0) {
      return PairedBracketType::kBracketTypeNone;
    }
    if (code & kCodeBracketCloseBit) {
      return PairedBracketType::kBracketTypeClose;
    }
    return PairedBracketType::kBracketTypeOpen;
  }

  static int TableLookup(int value) {
    for (int i = 0; i < 16; ++i) {
      if (kTable[i] == value) {
        return i;
      }
    }
    DLOG(ERROR) << "Table does not contain value 0x" << std::hex << value;
    return 0;
  }

  static String ToTestString(const std::string& input) {
    StringBuilder result;
    result.Ensure16Bit();
    bool in_set = false;
    int seen = 0;
    int code = 0;
    int list = 0;
    int current_shift = 0;
    for (char c : input) {
      if (in_set) {
        switch (c) {
          case '(':
            DCHECK_EQ(seen, 0);
            seen |= kSawBracket;
            code |= kCodeBracketBit;
            break;
          case '[':
            DCHECK_EQ(seen, 0);
            seen |= kSawBracket;
            code |= kCodeBracketBit | kCodeSquareBracketBit;
            break;
          case ')':
            DCHECK_EQ(seen, 0);
            seen |= kSawBracket;
            code |= kCodeBracketBit | kCodeBracketCloseBit;
            break;
          case ']':
            DCHECK_EQ(seen, 0);
            seen |= kSawBracket;
            code |=
                kCodeBracketBit | kCodeSquareBracketBit | kCodeBracketCloseBit;
            break;
          case 'i':
            DCHECK_EQ(seen, 0);  // brackets can't be inherited
            seen |= kSawSpecial;
            code |= kCodeSpecialInherited;
            break;
          case 'c':
            DCHECK_EQ((seen & ~kSawBracket), 0);
            seen |= kSawSpecial;
            code |= kCodeSpecialCommon;
            break;
          case 'l':
            DCHECK_EQ((seen & kSawLatin), 0);
            DCHECK_LT(current_shift, 3);
            seen |= kSawLatin;
            list |= kLatin << (2 * current_shift++);
            break;
          case 'h':
            DCHECK_EQ((seen & kSawHan), 0);
            DCHECK_LT(current_shift, 3);
            seen |= kSawHan;
            list |= kHan << (2 * current_shift++);
            break;
          case 'g':
            DCHECK_EQ((seen & kSawGreek), 0);
            DCHECK_LT(current_shift, 3);
            seen |= kSawGreek;
            list |= kGreek << (2 * current_shift++);
            break;
          case '>':
            DCHECK_NE(seen, 0);
            code |= TableLookup(list);
            result.Append(static_cast<UChar>(kMockCharMin + code));
            in_set = false;
            break;
          default:
            DLOG(ERROR) << "Illegal mock string set char: '" << c << "'";
            break;
        }
        continue;
      }
      // not in set
      switch (c) {
        case '<':
          seen = 0;
          code = 0;
          list = 0;
          current_shift = 0;
          in_set = true;
          break;
        case '(':
          code = kCodeBracketBit | kCodeSpecialCommon;
          break;
        case '[':
          code = kCodeBracketBit | kCodeSquareBracketBit | kCodeSpecialCommon;
          break;
        case ')':
          code = kCodeBracketBit | kCodeBracketCloseBit | kCodeSpecialCommon;
          break;
        case ']':
          code = kCodeBracketBit | kCodeSquareBracketBit |
                 kCodeBracketCloseBit | kCodeSpecialCommon;
          break;
        case 'i':
          code = kCodeSpecialInherited;
          break;
        case 'c':
          code = kCodeSpecialCommon;
          break;
        case 'l':
          code = kLatin;
          break;
        case 'h':
          code = kHan;
          break;
        case 'g':
          code = kGreek;
          break;
        case '?':
          code = 0;  // unknown
          break;
        default:
          DLOG(ERROR) << "Illegal mock string set char: '" << c << "'";
      }
      if (!in_set) {
        result.Append(static_cast<UChar>(kMockCharMin + code));
      }
    }
    return result.ToString();
  }

  // We determine properties based on the offset from kMockCharMin:
  // bits 0-3 represent the list of l, h, c scripts (index into table)
  // bit 4-5 means: 0 plain, 1 common, 2 inherited, 3 illegal
  // bit 6 clear means non-bracket, open means bracket
  // bit 7 clear means open bracket, set means close bracket
  // bit 8 clear means paren, set means bracket
  // if it's a bracket, the matching bracket is 64 code points away
  static const UChar32 kMockCharMin = 0xe000;
  static const UChar32 kMockCharLimit = kMockCharMin + 0x200;
  static const int kLatin = 1;
  static const int kHan = 2;
  static const int kGreek = 3;
  static const int kCodeListIndexMask = 0xf;
  static const int kCodeSpecialMask = 0x30;
  static const int kCodeSpecialCommon = 0x10;
  static const int kCodeSpecialInherited = 0x20;
  static const int kCodeBracketCloseBit = 0x40;
  static const int kCodeBracketBit = 0x80;
  static const int kCodeSquareBracketBit = 0x100;
  static const int kListShift = 2;
  static const int kListMask = 0x3;
  static const int kBracketDelta = kCodeBracketCloseBit;
  static const int kTable[16];

  static const int kSawBracket = 0x1;
  static const int kSawSpecial = 0x2;
  static const int kSawLatin = 0x4;
  static const int kSawHan = 0x8;
  static const int kSawGreek = 0x10;
};

static const int kLatin2 = MockScriptData::kLatin << 2;
static const int kHan2 = MockScriptData::kHan << 2;
static const int kGreek2 = MockScriptData::kGreek << 2;
static const int kLatin3 = MockScriptData::kLatin << 4;
static const int kHan3 = MockScriptData::kHan << 4;
static const int kGreek3 = MockScriptData::kGreek << 4;
const int MockScriptData::kTable[] = {
    0,
    kLatin,
    kHan,
    kGreek,
    kLatin2 + kHan,
    kLatin2 + kGreek,
    kHan2 + kLatin,
    kHan2 + kGreek,
    kGreek2 + kLatin,
    kGreek2 + kHan,
    kLatin3 + kHan2 + kGreek,
    kLatin3 + kGreek2 + kHan,
    kHan3 + kLatin2 + kGreek,
    kHan3 + kGreek2 + kLatin,
    kGreek3 + kLatin2 + kHan,
    kGreek3 + kHan2 + kLatin,
};

class ScriptRunIteratorTest : public testing::Test {
 protected:
  void CheckRuns(const Vector<ScriptTestRun>& runs) {
    StringBuilder text;
    text.Ensure16Bit();
    Vector<ScriptExpectedRun> expect;
    for (auto& run : runs) {
      text.Append(String::FromUTF8(run.text));
      expect.push_back(ScriptExpectedRun(text.length(), run.code));
    }
    ScriptRunIterator script_run_iterator(text.Span16());
    VerifyRuns(&script_run_iterator, expect);
  }

  // FIXME crbug.com/527329 - CheckMockRuns should be replaced by finding
  // suitable equivalent real codepoint sequences instead.
  void CheckMockRuns(const Vector<ScriptTestRun>& runs) {
    StringBuilder text;
    text.Ensure16Bit();
    Vector<ScriptExpectedRun> expect;
    for (const ScriptTestRun& run : runs) {
      text.Append(MockScriptData::ToTestString(run.text));
      expect.push_back(ScriptExpectedRun(text.length(), run.code));
    }

    ScriptRunIterator script_run_iterator(text.Span16(),
                                          MockScriptData::Instance());
    VerifyRuns(&script_run_iterator, expect);
  }

  void VerifyRuns(ScriptRunIterator* script_run_iterator,
                  const Vector<ScriptExpectedRun>& expect) {
    Vector<ScriptExpectedRun> actual;
    unsigned limit;
    UScriptCode code;
    while (script_run_iterator->Consume(&limit, &code))
      actual.emplace_back(limit, code);
    EXPECT_THAT(actual, testing::ContainerEq(expect));
  }
};

TEST_F(ScriptRunIteratorTest, Empty) {
  String empty(g_empty_string16_bit);
  ScriptRunIterator script_run_iterator(empty.Span16());
  unsigned limit = 0;
  UScriptCode code = USCRIPT_INVALID_CODE;
  DCHECK(!script_run_iterator.Consume(&limit, &code));
  ASSERT_EQ(limit, 0u);
  ASSERT_EQ(code, USCRIPT_INVALID_CODE);
}

// Some of our compilers cannot initialize a vector from an array yet.
#define DECLARE_SCRIPT_RUNSVECTOR(...)                   \
  static const ScriptTestRun kRunsArray[] = __VA_ARGS__; \
  Vector<ScriptTestRun> runs;                            \
  runs.Append(kRunsArray, sizeof(kRunsArray) / sizeof(*kRunsArray));

#define CHECK_SCRIPT_RUNS(...)            \
  DECLARE_SCRIPT_RUNSVECTOR(__VA_ARGS__); \
  CheckRuns(runs);

#define CHECK_MOCK_SCRIPT_RUNS(...)       \
  DECLARE_SCRIPT_RUNSVECTOR(__VA_ARGS__); \
  CheckMockRuns(runs);

TEST_F(ScriptRunIteratorTest, Whitespace) {
  CHECK_SCRIPT_RUNS({{" \t ", USCRIPT_COMMON}});
}

TEST_F(ScriptRunIteratorTest, Common) {
  CHECK_SCRIPT_RUNS({{" ... !?", USCRIPT_COMMON}});
}

TEST_F(ScriptRunIteratorTest, CombiningCircle) {
  CHECK_SCRIPT_RUNS({{"◌́◌̀◌̈◌̂◌̄◌̊", USCRIPT_COMMON}});
}

TEST_F(ScriptRunIteratorTest, Latin) {
  CHECK_SCRIPT_RUNS({{"latin", USCRIPT_LATIN}});
}

TEST_F(ScriptRunIteratorTest, Chinese) {
  CHECK_SCRIPT_RUNS({{"萬國碼", USCRIPT_HAN}});
}

struct JapaneseMixedScript {
  const char* string;
  // The expected primary_script when the string alone was evaluated.
  UScriptCode script;
} japanese_mixed_scripts[] = {{"あ", USCRIPT_HIRAGANA},
                              // Katakana should be normalized to Hiragana
                              {"ア", USCRIPT_HIRAGANA},
                              // Script_Extensions=Hira Kana
                              {"\u30FC", USCRIPT_HIRAGANA},
                              // Script_Extensions=Hani Hira Kana
                              {"\u303C", USCRIPT_HAN},
                              // Script_Extensions=Bopo Hang Hani Hira Kana
                              {"\u3003", USCRIPT_BOPOMOFO},
                              // Script_Extensions=Bopo Hang Hani Hira Kana Yiii
                              {"\u3001", USCRIPT_BOPOMOFO}};

class JapaneseMixedScriptTest
    : public ScriptRunIteratorTest,
      public testing::WithParamInterface<JapaneseMixedScript> {};

INSTANTIATE_TEST_SUITE_P(ScriptRunIteratorTest,
                         JapaneseMixedScriptTest,
                         testing::ValuesIn(japanese_mixed_scripts));

TEST_P(JapaneseMixedScriptTest, Data) {
  const auto& data = GetParam();
  std::string string(data.string);

  CheckRuns({{string.data(), data.script}});

  // If the string follows Hiragana or Katakana, or is followed by Hiragnaa or
  // Katakana, it should be normalized as Hiragana.
  std::string hiragana("か");
  std::string katakana("カ");
  CheckRuns({{(hiragana + string).data(), USCRIPT_HIRAGANA}});
  CheckRuns({{(string + hiragana).data(), USCRIPT_HIRAGANA}});

  CheckRuns({{(katakana + string).data(), USCRIPT_HIRAGANA}});
  CheckRuns({{(string + katakana).data(), USCRIPT_HIRAGANA}});

  CheckRuns({{(hiragana + string + katakana).data(), USCRIPT_HIRAGANA}});
  CheckRuns({{(katakana + string + hiragana).data(), USCRIPT_HIRAGANA}});
}

// Close bracket without matching open is ignored
TEST_F(ScriptRunIteratorTest, UnbalancedParens1) {
  CHECK_SCRIPT_RUNS(
      {{"(萬", USCRIPT_HAN}, {"a]", USCRIPT_LATIN}, {")", USCRIPT_HAN}});
}

// Open bracket without matching close is popped when inside
// matching close brackets, so doesn't match later close.
TEST_F(ScriptRunIteratorTest, UnbalancedParens2) {
  CHECK_SCRIPT_RUNS(
      {{"(萬", USCRIPT_HAN}, {"a[", USCRIPT_LATIN}, {")]", USCRIPT_HAN}});
}

// space goes with leading script
TEST_F(ScriptRunIteratorTest, LatinHan) {
  CHECK_SCRIPT_RUNS({{"Unicode ", USCRIPT_LATIN}, {"萬國碼", USCRIPT_HAN}});
}

// space goes with leading script
TEST_F(ScriptRunIteratorTest, HanLatin) {
  CHECK_SCRIPT_RUNS({{"萬國碼 ", USCRIPT_HAN}, {"Unicode", USCRIPT_LATIN}});
}

TEST_F(ScriptRunIteratorTest, ParenEmptyParen) {
  CHECK_SCRIPT_RUNS({{"()", USCRIPT_COMMON}});
}

TEST_F(ScriptRunIteratorTest, ParenChineseParen) {
  CHECK_SCRIPT_RUNS({{"(萬國碼)", USCRIPT_HAN}});
}

TEST_F(ScriptRunIteratorTest, ParenLatinParen) {
  CHECK_SCRIPT_RUNS({{"(Unicode)", USCRIPT_LATIN}});
}

// open paren gets leading script
TEST_F(ScriptRunIteratorTest, LatinParenChineseParen) {
  CHECK_SCRIPT_RUNS({{"Unicode (", USCRIPT_LATIN},
                     {"萬國碼", USCRIPT_HAN},
                     {")", USCRIPT_LATIN}});
}

// open paren gets first trailing script if no leading script
TEST_F(ScriptRunIteratorTest, ParenChineseParenLatin) {
  CHECK_SCRIPT_RUNS({{"(萬國碼) ", USCRIPT_HAN}, {"Unicode", USCRIPT_LATIN}});
}

// leading common and open paren get first trailing script.
// TODO(dougfelt): we don't do quote matching, but probably should figure out
// something better then doing nothing.
TEST_F(ScriptRunIteratorTest, QuoteParenChineseParenLatinQuote) {
  CHECK_SCRIPT_RUNS(
      {{"\"(萬國碼) ", USCRIPT_HAN}, {"Unicode\"", USCRIPT_LATIN}});
}

TEST_F(ScriptRunIteratorTest, CJKConsecutiveParens1) {
  CHECK_SCRIPT_RUNS({{"「あ", USCRIPT_HIRAGANA},
                     // The consecutive punctuation should not be split.
                     {"国。」", USCRIPT_HAN}});
}

TEST_F(ScriptRunIteratorTest, CJKConsecutiveParens2) {
  CHECK_SCRIPT_RUNS({{"あ「あ", USCRIPT_HIRAGANA},
                     // The consecutive punctuation should not be split.
                     {"国（国）」", USCRIPT_HAN}});
}

TEST_F(ScriptRunIteratorTest, CJKConsecutiveParens3) {
  CHECK_SCRIPT_RUNS({{"国「国", USCRIPT_HAN},
                     {"ア（", USCRIPT_HIRAGANA},
                     {"A", USCRIPT_LATIN},
                     // The consecutive punctuation should not be split.
                     {"）」", USCRIPT_HIRAGANA}});
}

TEST_F(ScriptRunIteratorTest, CJKConsecutiveParens4) {
  CHECK_SCRIPT_RUNS({{"A", USCRIPT_LATIN},
                     // CJK puncutuation after non-CJK resolves to Bopomofo,
                     // because it's the first script extension in the Unicode
                     // data. It's not correct but ok because GPOS/GSUB in CJK
                     // fonts usually include the same features for all CJK
                     // scripts including Bopomofo, even when they are not
                     // intended for Traditional Chinese.
                     {"「", USCRIPT_BOPOMOFO},
                     {"A", USCRIPT_LATIN},
                     {"あ（", USCRIPT_HIRAGANA},
                     // The consecutive punctuation should not be split.
                     {"国）」", USCRIPT_HAN}});
}

TEST_F(ScriptRunIteratorTest, CJKConsecutiveParens5) {
  CHECK_SCRIPT_RUNS({{"「あ", USCRIPT_HIRAGANA},
                     {"国", USCRIPT_HAN},
                     {"A", USCRIPT_LATIN},
                     {"」", USCRIPT_HIRAGANA}});
}

TEST_F(ScriptRunIteratorTest, CJKConsecutiveParens6) {
  CHECK_SCRIPT_RUNS({{"A", USCRIPT_LATIN},
                     {"「", USCRIPT_BOPOMOFO},  // See CJKConsecutiveParens4
                     {"A", USCRIPT_LATIN},
                     {"あ（", USCRIPT_HIRAGANA},
                     {"国）", USCRIPT_HAN},
                     {"A", USCRIPT_LATIN},
                     {"」", USCRIPT_BOPOMOFO}});
}

TEST_F(ScriptRunIteratorTest, CJKConsecutiveParens7) {
  CHECK_SCRIPT_RUNS({
      {"「あ", USCRIPT_HIRAGANA},
      {"国1」", USCRIPT_HAN},
  });
}

TEST_F(ScriptRunIteratorTest, CJKConsecutiveParens8) {
  CHECK_SCRIPT_RUNS({
      {"A", USCRIPT_LATIN},
      {"「", USCRIPT_BOPOMOFO},  // See CJKConsecutiveParens4
      {"A", USCRIPT_LATIN},
      {"あ（", USCRIPT_HIRAGANA},
      {"国）1」", USCRIPT_HAN},
  });
}

TEST_F(ScriptRunIteratorTest, CJKConsecutiveParens9) {
  CHECK_SCRIPT_RUNS({{"「あ", USCRIPT_HIRAGANA},
                     {"国", USCRIPT_HAN},
                     {"A1", USCRIPT_LATIN},
                     {"」", USCRIPT_HIRAGANA}});
}

TEST_F(ScriptRunIteratorTest, CJKConsecutiveParens10) {
  CHECK_SCRIPT_RUNS({{"A", USCRIPT_LATIN},
                     {"「", USCRIPT_BOPOMOFO},  // See CJKConsecutiveParens4
                     {"A", USCRIPT_LATIN},
                     {"あ（", USCRIPT_HIRAGANA},
                     {"国）", USCRIPT_HAN},
                     {"A1", USCRIPT_LATIN},
                     {"」", USCRIPT_BOPOMOFO}});
}

TEST_F(ScriptRunIteratorTest, CJKConsecutiveParensLatin1) {
  CHECK_SCRIPT_RUNS({{"「", USCRIPT_BOPOMOFO},  // See CJKConsecutiveParens4
                     {"A", USCRIPT_LATIN},
                     {"「", USCRIPT_BOPOMOFO},
                     {"A", USCRIPT_LATIN},
                     {"」」", USCRIPT_BOPOMOFO}});
}

TEST_F(ScriptRunIteratorTest, CJKConsecutiveParensLatin2) {
  CHECK_SCRIPT_RUNS({{"「", USCRIPT_BOPOMOFO},  // See CJKConsecutiveParens4
                     {"A", USCRIPT_LATIN},
                     {"（", USCRIPT_BOPOMOFO},
                     {"A", USCRIPT_LATIN},
                     {"）」", USCRIPT_BOPOMOFO}});
}

TEST_F(ScriptRunIteratorTest, CJKConsecutiveParensLatin3) {
  CHECK_SCRIPT_RUNS({{"「", USCRIPT_BOPOMOFO},  // See CJKConsecutiveParens4
                     {"A", USCRIPT_LATIN},
                     {"（国）」", USCRIPT_HAN}});
}

// Emojies are resolved to the leading script.
TEST_F(ScriptRunIteratorTest, EmojiCommon) {
  CHECK_SCRIPT_RUNS({{"百家姓🌱🌲🌳🌴", USCRIPT_HAN}});
}

// Unmatched close brace gets leading context
TEST_F(ScriptRunIteratorTest, UnmatchedClose) {
  CHECK_SCRIPT_RUNS({{"Unicode (", USCRIPT_LATIN},
                     {"萬國碼] ", USCRIPT_HAN},
                     {") Unicode\"", USCRIPT_LATIN}});
}

// Match up to 32 bracket pairs
TEST_F(ScriptRunIteratorTest, Match32Brackets) {
  CHECK_SCRIPT_RUNS({{"[萬國碼 ", USCRIPT_HAN},
                     {"Unicode (((((((((((((((((((((((((((((((!"
                      ")))))))))))))))))))))))))))))))",
                      USCRIPT_LATIN},
                     {"]", USCRIPT_HAN}});
}

// Matches 32 most recent bracket pairs. More than that, and we revert to
// surrounding script.
TEST_F(ScriptRunIteratorTest, Match32MostRecentBrackets) {
  CHECK_SCRIPT_RUNS({{"((([萬國碼 ", USCRIPT_HAN},
                     {"Unicode (((((((((((((((((((((((((((((((", USCRIPT_LATIN},
                     {"萬國碼!", USCRIPT_HAN},
                     {")))))))))))))))))))))))))))))))", USCRIPT_LATIN},
                     {"]", USCRIPT_HAN},
                     {"But )))", USCRIPT_LATIN}});
}

// A char with multiple scripts that match both leading and trailing context
// gets the leading context.
TEST_F(ScriptRunIteratorTest, ExtensionsPreferLeadingContext) {
  CHECK_MOCK_SCRIPT_RUNS({{"h<lh>", USCRIPT_HAN}, {"l", USCRIPT_LATIN}});
}

// A char with multiple scripts that only match trailing context gets the
// trailing context.
TEST_F(ScriptRunIteratorTest, ExtensionsMatchTrailingContext) {
  CHECK_MOCK_SCRIPT_RUNS({{"h", USCRIPT_HAN}, {"<gl>l", USCRIPT_LATIN}});
}

// Retain first established priority script.  <lhg><gh> produce the script <gh>
// with g as priority, because of the two priority scripts l and g, only g
// remains.  Then <gh><hgl> retains g as priority, because of the two priority
// scripts g and h that remain, g was encountered first.
TEST_F(ScriptRunIteratorTest, ExtensionsRetainFirstPriorityScript) {
  CHECK_MOCK_SCRIPT_RUNS({{"<lhg><gh><hgl>", USCRIPT_GREEK}});
}

// Parens can have scripts that break script runs.
TEST_F(ScriptRunIteratorTest, ExtensionsParens) {
  CHECK_MOCK_SCRIPT_RUNS({{"<gl><(lg>", USCRIPT_GREEK},
                          {"h<[hl>", USCRIPT_HAN},
                          {"l", USCRIPT_LATIN},
                          {"<]hl>", USCRIPT_HAN},
                          {"<)lg>", USCRIPT_GREEK}});
}

// The close paren might be encountered before we've established the open
// paren's script, but when this is the case the current set is still valid, so
// this doesn't affect it nor break the run.
TEST_F(ScriptRunIteratorTest, ExtensionsParens2) {
  CHECK_MOCK_SCRIPT_RUNS({{"<(lhg><gh><)lhg>", USCRIPT_GREEK}});
}

// A common script with a single extension should be treated as common, but
// with the extended script as a default.  If we encounter anything other than
// common, that takes priority.  If we encounter other common scripts with a
// single extension, the current priority remains.
TEST_F(ScriptRunIteratorTest, CommonWithPriority) {
  CHECK_MOCK_SCRIPT_RUNS({{"<ch>", USCRIPT_HAN}});
}

TEST_F(ScriptRunIteratorTest, CommonWithPriority2) {
  CHECK_MOCK_SCRIPT_RUNS({{"<ch><lh>", USCRIPT_LATIN}});
}

TEST_F(ScriptRunIteratorTest, CommonWithPriority3) {
  CHECK_MOCK_SCRIPT_RUNS({{"<ch><cl><cg>", USCRIPT_HAN}});
}

// UDatta (\xE0\xA5\x91) is inherited with LATIN, DEVANAGARI, BENGALI and
// other Indic scripts. Since it has LATIN, and the
// dotted circle U+25CC (\xE2\x97\x8C) is COMMON and has adopted the
// preceding LATIN, it gets the LATIN. This is standard.
TEST_F(ScriptRunIteratorTest, LatinDottedCircleUdatta) {
  CHECK_SCRIPT_RUNS({{"Latin \xE2\x97\x8C\xE0\xA5\x91", USCRIPT_LATIN}});
}

// In this situation, UDatta U+0951 (\xE0\xA5\x91) doesn't share a script
// with the value inherited by the dotted circle U+25CC (\xE2\x97\x8C).
// It captures the preceding dotted circle and breaks it from the run it would
// normally have been in. U+0951 is used in multiple scripts (DEVA, BENG, LATN,
// etc) and has multiple values for Script_Extension property. At the moment,
// getScripts() treats the script with the lowest script code as 'true' primary,
// and BENG comes before DEVA in the script enum so that we get BENGALI.
// Taking into account a Unicode block and returning DEVANAGARI would be
// slightly better.
TEST_F(ScriptRunIteratorTest, HanDottedCircleUdatta) {
  CHECK_SCRIPT_RUNS({{"萬國碼 ", USCRIPT_HAN},
                     {"\xE2\x97\x8C\xE0\xA5\x91", USCRIPT_BENGALI}});
}

// Tatweel is \xD9\x80 Lm, Fathatan is \xD9\x8B Mn. The script of tatweel is
// common, that of Fathatan is inherited.  The script extensions for Fathatan
// are Arabic and Syriac. The Syriac script is 34 in ICU, Arabic is 2. So the
// preferred script for Fathatan is Arabic, according to Behdad's
// heuristic. This is exactly analogous to the Udatta tests above, except
// Tatweel is Lm. But we don't take properties into account, only scripts.
TEST_F(ScriptRunIteratorTest, LatinTatweelFathatan) {
  CHECK_SCRIPT_RUNS(
      {{"Latin ", USCRIPT_LATIN}, {"\xD9\x80\xD9\x8B", USCRIPT_ARABIC}});
}

// Another case where if the mark accepts a script that was inherited by the
// preceding common-script character, they both continue in that script.
// SYRIAC LETTER NUN \xDC\xA2
// ARABIC TATWEEL \xD9\x80
// ARABIC FATHATAN \xD9\x82
TEST_F(ScriptRunIteratorTest, SyriacTatweelFathatan) {
  CHECK_SCRIPT_RUNS({{"\xDC\xA2\xD9\x80\xD9\x8B", USCRIPT_SYRIAC}});
}

// The Udatta (\xE0\xA5\x91) is inherited, so will share runs with anything that
// is not common.
TEST_F(ScriptRunIteratorTest, HanUdatta) {
  CHECK_SCRIPT_RUNS({{"萬國碼\xE0\xA5\x91", USCRIPT_HAN}});
}

// The Udatta U+0951 (\xE0\xA5\x91) is inherited, and will capture the space
// and turn it into Bengali because SCRIPT_BENAGLI is 4 and SCRIPT_DEVANAGARI
// is 10. See TODO comment for |getScripts| and HanDottedCircleUdatta.
TEST_F(ScriptRunIteratorTest, HanSpaceUdatta) {
  CHECK_SCRIPT_RUNS(
      {{"萬國碼", USCRIPT_HAN}, {" \xE0\xA5\x91", USCRIPT_BENGALI}});
}

// Corresponds to one test in RunSegmenter, where orientation of the
// space character is sidesways in vertical.
TEST_F(ScriptRunIteratorTest, Hangul) {
  CHECK_SCRIPT_RUNS({{"키스의 고유조건은", USCRIPT_HANGUL}});
}

// Corresponds to one test in RunSegmenter, which tests that the punctuation
// characters mixed in are actually sideways in vertical. The ScriptIterator
// should report one run, but the RunSegmenter should report three, with the
// middle one rotated sideways.
TEST_F(ScriptRunIteratorTest, HiraganaMixedPunctuation) {
  CHECK_SCRIPT_RUNS({{"いろはに.…¡ほへと", USCRIPT_HIRAGANA}});
}

// Make sure Mock code works too.
TEST_F(ScriptRunIteratorTest, MockHanInheritedGL) {
  CHECK_MOCK_SCRIPT_RUNS({{"h<igl>", USCRIPT_HAN}});
}

TEST_F(ScriptRunIteratorTest, MockHanCommonInheritedGL) {
  CHECK_MOCK_SCRIPT_RUNS({{"h", USCRIPT_HAN}, {"c<igl>", USCRIPT_GREEK}});
}

// Leading inherited just act like common, except there's no preferred script.
TEST_F(ScriptRunIteratorTest, MockLeadingInherited) {
  CHECK_MOCK_SCRIPT_RUNS({{"<igl>", USCRIPT_COMMON}});
}

// Leading inherited just act like common, except there's no preferred script.
TEST_F(ScriptRunIteratorTest, MockLeadingInherited2) {
  CHECK_MOCK_SCRIPT_RUNS({{"<igl><ih>", USCRIPT_COMMON}});
}

TEST_F(ScriptRunIteratorTest, LeadingInheritedHan) {
  // DEVANAGARI STRESS SIGN UDATTA \xE0\xA5\x91
  CHECK_SCRIPT_RUNS({{"\xE0\xA5\x91萬國碼", USCRIPT_HAN}});
}

TEST_F(ScriptRunIteratorTest, LeadingInheritedHan2) {
  // DEVANAGARI STRESS SIGN UDATTA \xE0\xA5\x91
  // ARABIC FATHATAN \xD9\x8B
  CHECK_SCRIPT_RUNS({{"\xE0\xA5\x91\xD9\x8B萬國碼", USCRIPT_HAN}});
}

TEST_F(ScriptRunIteratorTest, OddLatinString) {
  CHECK_SCRIPT_RUNS({{"ç̈", USCRIPT_LATIN}});
}

TEST_F(ScriptRunIteratorTest, CommonMalayalam) {
  CHECK_SCRIPT_RUNS({{"100-ാം", USCRIPT_MALAYALAM}});
}

std::pair<int, UChar32> MaximumScriptExtensions() {
  int max_extensions = 0;
  UChar32 max_extensionscp = 0;
  for (UChar32 cp = 0; cp < 0x11000; ++cp) {
    UErrorCode status = U_ZERO_ERROR;
    int count = uscript_getScriptExtensions(cp, nullptr, 0, &status);
    if (count > max_extensions) {
      max_extensions = count;
      max_extensionscp = cp;
    }
  }
  return std::make_pair(max_extensions, max_extensionscp);
}

TEST_F(ScriptRunIteratorTest, MaxUnicodeScriptExtensions) {
  int max_extensions = 0;
  UChar32 max_extensionscp = 0;
  std::tie(max_extensions, max_extensionscp) = MaximumScriptExtensions();
  // If this test fails (as a result of an ICU update, most likely), it means
  // we need to change kMaxUnicodeScriptExtensions.
  EXPECT_EQ(max_extensions, ScriptRunIterator::kMaxUnicodeScriptExtensions);
}

class ScriptRunIteratorICUDataTest : public testing::Test {
 public:
  ScriptRunIteratorICUDataTest() {
    std::tie(max_extensions_, max_extensions_codepoint_) =
        MaximumScriptExtensions();
  }

 protected:
  UChar32 GetACharWithMaxExtensions(int* num_extensions) {
    if (num_extensions) {
      *num_extensions = max_extensions_;
    }
    return max_extensions_codepoint_;
  }

 private:
  int max_extensions_;
  UChar32 max_extensions_codepoint_;
};

// Validate that ICU never returns more than our maximum expected number of
// script extensions.
TEST_F(ScriptRunIteratorICUDataTest, ValidateICUMaxScriptExtensions) {
  int max_extensions;
  UChar32 cp = GetACharWithMaxExtensions(&max_extensions);
  ASSERT_LE(max_extensions, ScriptData::kMaxScriptCount)
      << "char " << std::hex << cp << std::dec;
}

// Check that ICUScriptData returns all of a character's scripts.
// This only checks one likely character, but doesn't check all cases.
TEST_F(ScriptRunIteratorICUDataTest, ICUDataGetScriptsReturnsAllExtensions) {
  int max_extensions;
  UChar32 cp = GetACharWithMaxExtensions(&max_extensions);
  ScriptData::UScriptCodeList extensions;
  ICUScriptData::Instance()->GetScripts(cp, extensions);

  // It's possible that GetScripts adds the primary script to the list of
  // extensions, resulting in one more script than the raw extension count.
  ASSERT_GE(static_cast<int>(extensions.size()), max_extensions)
      << "char " << std::hex << cp << std::dec;
}

TEST_F(ScriptRunIteratorICUDataTest, CommonHaveNoMoreThanOneExtension) {
  ScriptData::UScriptCodeList extensions;
  for (UChar32 cp = 0; cp < 0x110000; ++cp) {
    ICUScriptData::Instance()->GetScripts(cp, extensions);
    UScriptCode primary = extensions.at(0);
    if (primary == USCRIPT_COMMON) {
      ASSERT_LE(extensions.size(), 2ul) << "cp: " << std::hex << cp << std::dec;
    }
  }
}

// ZWJ is \u200D Cf (Format, other) and its script is inherited.  I'm going to
// ignore this for now, as I think it shouldn't matter which run it ends up
// in. HarfBuzz needs to be able to use it as context and shape each
// neighboring character appropriately no matter what run it got assigned to.

}  // namespace blink
```
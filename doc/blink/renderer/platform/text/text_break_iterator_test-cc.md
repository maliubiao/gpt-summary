Response:
Let's break down the thought process for analyzing the `text_break_iterator_test.cc` file.

1. **Understand the Purpose of a Test File:**  The core purpose of a `_test.cc` file is to verify the functionality of the code it's testing. In this case, it's testing `text_break_iterator.h` and related code.

2. **Identify the Core Class Under Test:** The filename `text_break_iterator_test.cc` and the inclusion of `text_break_iterator.h` immediately tell us that the central component being tested is `TextBreakIterator`. The presence of `LazyLineBreakIterator` in many tests also indicates its importance.

3. **Analyze the Test Structure (using Google Test):**
   - **Includes:** Note the included headers (`testing/gmock/gmock.h`, `testing/gtest/include/gtest/gtest.h`, `wtf/text/wtf_string.h`). These are standard Google Test and WTF (Web Template Framework, a Chromium library) includes, indicating a test suite using these frameworks.
   - **Test Fixture (`TextBreakIteratorTest`):** The `class TextBreakIteratorTest : public testing::Test` defines a test fixture. This is a common pattern in Google Test to set up common resources or helper functions for multiple tests. We should look at the members and methods of this class.
   - **Individual Tests (`TEST_F`, `TEST_P`):**  `TEST_F` indicates a test case within the `TextBreakIteratorTest` fixture. `TEST_P` indicates a parameterized test, where the same test logic is run with different input values.
   - **Assertions (`EXPECT_EQ`, `EXPECT_THAT`):** These are Google Test's assertion macros. They are crucial for verifying the expected behavior of the code. Pay attention to what they are comparing.

4. **Examine the Test Fixture (`TextBreakIteratorTest`):**
   - **`SetTestString`, `SetTestString16`:** These methods are clearly for setting up the input string for the tests. The `16` version suggests handling of UTF-16 encoding.
   - **`MatchLineBreaks`:** This is a key method. It takes expected break positions and calls `TestIsBreakable` and `TestNextBreakOpportunity`. The `LineBreakType` and `BreakSpaceType` arguments indicate different breaking strategies being tested.
   - **`TestIsBreakable`, `TestNextBreakOpportunity`:** These methods directly test the core functionalities of the `TextBreakIterator`. They iterate through the string and assert that the actual break positions match the expected ones.
   - **`TestLengthOfGraphemeCluster`, `GraphemesClusterList`:** These methods suggest testing the handling of grapheme clusters, which are important for correct text segmentation in Unicode.
   - **`test_string_`, `locale_`:** These are member variables used by the test methods. `locale_` indicates that the break iterator's behavior is locale-sensitive.

5. **Analyze Individual Test Cases:** Read through the names and the code of each `TEST_F` and `TEST_P` function. Try to understand what specific scenario or edge case each test is covering. Look for:
   - **Different Input Strings:** Pay attention to the variety of strings used (empty, single characters, multiple words, punctuation, Chinese characters, emojis, soft hyphens, etc.).
   - **Different `LineBreakType` values:**  The parameterized test `BreakTypeTest` explicitly tests different line breaking strategies.
   - **Specific Function Calls:** Notice which methods of the `TextBreakIterator` are being called in each test (`IsBreakable`, `NextBreakOpportunity`, `SetBreakType`, `SetBreakSpace`, etc.).
   - **Expected Outputs:** The `expected_break_positions` in `MatchLineBreaks` are the crucial expected outputs. Try to reason why those positions are expected based on the input string and the breaking rules being tested.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Think about where text breaking is relevant in web rendering:
   - **Line Wrapping in HTML:**  When text doesn't fit within an element's width, the browser needs to decide where to break lines. This is a core function of the `TextBreakIterator`.
   - **JavaScript String Manipulation:** While JavaScript has its own string methods, the underlying browser engine (like Blink) uses components like `TextBreakIterator` for tasks like word counting, segmentation, and potentially even for implementing some JavaScript string functions.
   - **CSS `word-break`, `overflow-wrap` properties:** These CSS properties directly influence how the browser performs line breaking. The `TextBreakIterator` is a key component in implementing these properties.

7. **Identify Logic and Assumptions:**
   - **Assumptions about Breaking Rules:** The tests implicitly assume certain rules for line breaking based on the `LineBreakType` and the characters in the string.
   - **Locale Sensitivity:**  The tests involving Japanese characters and the `locale_` member highlight that line breaking is language-specific.

8. **Consider Potential User/Programming Errors:**
   - **Incorrectly Specifying Break Positions:** A programmer might have a misunderstanding of the line breaking rules and provide incorrect expected break positions in their tests (though this is an error in the *test* itself, not the tested code).
   - **Not Considering Locale:** Forgetting that line breaking rules vary by language can lead to unexpected behavior.
   - **Misunderstanding `BreakType` Options:**  Not fully understanding the differences between `kNormal`, `kBreakAll`, `kKeepAll`, etc., could lead to incorrect usage or expectations.

By following these steps, you can systematically analyze the test file and derive a comprehensive understanding of its purpose, functionality, and connections to web technologies, along with potential pitfalls. The process involves reading the code carefully, understanding the testing framework, and connecting the code's functionality to the broader context of web development.
这个 `text_break_iterator_test.cc` 文件是 Chromium Blink 引擎中用于测试 `TextBreakIterator` 及其相关功能的单元测试文件。它的主要功能是验证文本断行（line breaking）逻辑的正确性。

以下是它功能的详细列表，以及它与 JavaScript、HTML 和 CSS 功能的关系，逻辑推理示例，以及可能的用户或编程常见错误：

**文件主要功能:**

1. **测试 `TextBreakIterator` 类的核心功能:**
   - **查找换行符的位置:** 测试 `IsBreakable()` 和 `NextBreakOpportunity()` 方法，验证它们能否在给定的文本中正确识别出可以断行的位置。
   - **支持不同的断行类型:** 测试 `LineBreakType` 枚举（`kNormal`, `kBreakAll`, `kBreakCharacter`, `kKeepAll`, `kPhrase`）下，断行行为是否符合预期。
   - **处理不同的空格类型:** 测试 `BreakSpaceType` 枚举（`kAfterSpaceRun`）对断行行为的影响。
   - **处理不同语言和区域设置 (Locale):**  虽然此文件中测试的区域设置比较有限，但它确实展示了断行行为可以受 `LayoutLocale` 的影响。
   - **处理字形簇 (Grapheme Clusters):** 测试了如何正确识别和处理 Unicode 字形簇，这对于正确断行包含组合字符或 emoji 的文本至关重要。
   - **处理软连字符 (Soft Hyphen):**  测试了软连字符在断行时的行为，以及禁用软连字符时的行为。
   - **测试池化的 BreakIterator:** 验证了 `AcquireLineBreakIterator` 和 `PooledBreakIterator` 的行为，确保对象池化机制的正确性。

2. **提供测试辅助方法:**
   - `SetTestString()` 和 `SetTestString16()`:  用于设置测试用的字符串，支持 UTF-8 和 UTF-16 编码。
   - `MatchLineBreaks()`:  一个方便的方法，用于同时测试 `IsBreakable()` 和 `NextBreakOpportunity()`，并比较预期断点位置。
   - `TestIsBreakable()` 和 `TestNextBreakOpportunity()`:  分别测试 `IsBreakable()` 和 `NextBreakOpportunity()` 方法，并通过 Google Test 的断言进行验证。
   - `TestLengthOfGraphemeCluster()` 和 `GraphemesClusterList()`:  用于测试字形簇的长度和列表。

**与 JavaScript, HTML, CSS 的关系:**

`TextBreakIterator` 在 Blink 引擎中扮演着关键角色，它直接影响浏览器如何渲染和显示文本，因此与 JavaScript、HTML 和 CSS 功能息息相关：

* **HTML:**
    * **文本换行:** 当 HTML 内容中的文本超出其容器宽度时，浏览器需要决定在哪里断行。`TextBreakIterator` 提供的逻辑直接用于实现 HTML 文本的自动换行。例如，在 `<div>` 或 `<p>` 标签中显示的文本，其换行行为就依赖于此类。
    * **`wbr` 标签:** `<wbr>` (Word Break Opportunity) 标签提示浏览器可以在此处断行。`TextBreakIterator` 的逻辑需要考虑到这些提示。
* **CSS:**
    * **`word-break` 属性:** 这个 CSS 属性控制如何进行单词内的断行。不同的 `word-break` 值（例如 `normal`, `break-all`, `keep-all`) 对应着 `TextBreakIterator` 中不同的 `LineBreakType`。例如，`word-break: break-all` 可能会对应到 `LineBreakType::kBreakAll`。
    * **`overflow-wrap` (或 `word-wrap`) 属性:** 这个属性控制浏览器是否可以在正常的单词边界内断行以防止溢出。其行为也与 `TextBreakIterator` 的逻辑相关。
    * **文本渲染:**  更广泛地说，`TextBreakIterator` 是文本渲染流水线的一部分，确保文本在屏幕上正确显示。
* **JavaScript:**
    * **文本操作:** 虽然 JavaScript 自身提供了字符串操作方法，但底层浏览器引擎在处理文本布局和渲染时会使用 `TextBreakIterator`。例如，JavaScript 代码可能会计算文本的宽度或高度，这涉及到文本的断行。
    * **`Intl.Segmenter` API:**  新的 JavaScript `Intl.Segmenter` API 允许开发者以感知区域设置的方式分割文本成字形、单词或句子。虽然 `Intl.Segmenter` 是一个更高级别的 API，但底层的实现可能会利用类似 `TextBreakIterator` 的机制。

**逻辑推理示例 (假设输入与输出):**

假设我们有以下测试用例：

```c++
TEST_F(TextBreakIteratorTest, SimpleEnglish) {
  SetTestString("hello world");
  // 预期在 " " 之后可以断行
  MatchLineBreaks({6});
}
```

**假设输入:** 字符串 "hello world"
**预期输出:** `MatchLineBreaks` 函数会调用 `IsBreakable(6)` 返回 `true`，并且 `NextBreakOpportunity(0)` 会返回 `6`。

**推理:** 在英文文本中，通常在空格处进行断行。`TextBreakIterator` (在默认的 `LineBreakType::kNormal` 下) 应该能够识别出索引为 5 的空格字符后面的位置 (索引 6) 是一个合法的断行点。

**用户或编程常见的使用错误举例:**

1. **假设所有语言的断行规则都相同:**
   - **错误示例:**  开发者可能认为英文的断行规则适用于中文或日文，导致在不应该断行的地方断开了文本。
   - **`TextBreakIterator` 的作用:**  它考虑了不同语言的断行规则，例如中文通常在每个字符后都可以断行（在 `LineBreakType::kNormal` 下），而英文通常在单词之间断行。
   - **测试用例体现:**  例如，`TEST_F(TextBreakIteratorTest, Chinese)` 测试了中文文本的断行行为，预期在每个字符后都可以断行。

2. **错误地使用 `word-break: break-all`:**
   - **错误示例:**  开发者可能为了防止文本溢出而全局地使用 `word-break: break-all`，导致英文单词被强行断开，影响可读性。
   - **`TextBreakIterator` 的作用:**  测试用例如 `TEST_F(TextBreakIteratorTest, LatinPunctuation)` 展示了在 `LineBreakType::kBreakAll` 下，即使在单词内部也会断行。
   - **如何避免:**  应该根据具体需求谨慎使用 `break-all`，并考虑使用更合适的属性如 `overflow-wrap: break-word`。

3. **忽略软连字符的作用:**
   - **错误示例:**  开发者可能没有意识到软连字符 (`\u00AD`) 的存在，导致在包含软连字符的文本中，断行行为与预期不符。
   - **`TextBreakIterator` 的作用:**  `TEST_F(TextBreakIteratorTest, SoftHyphen)` 测试了软连字符在断行时的作用。
   - **如何利用:**  可以使用软连字符来提示浏览器在特定位置进行断行，提高文本的排版效果。

4. **没有考虑 Emoji 和复杂字符:**
   - **错误示例:**  早期的文本处理可能没有正确处理包含 Emoji 或组合字符的文本，导致断行发生在这些字符的中间，破坏了字符的完整性。
   - **`TextBreakIterator` 的作用:**  `TEST_F(TextBreakIteratorTest, KeepEmojiZWJFamilyIsolate)` 和相关的 Emoji 测试用例验证了 `TextBreakIterator` 可以正确处理这些复杂字符，将它们作为一个完整的字形簇进行处理，避免在中间断行。

总而言之，`text_break_iterator_test.cc` 通过大量的单元测试，确保了 Blink 引擎在处理文本断行时的正确性和鲁棒性，这对于构建高质量的网络浏览器至关重要，并且直接影响着用户在浏览网页时的文本呈现效果。

### 提示词
```
这是目录为blink/renderer/platform/text/text_break_iterator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/text/text_break_iterator.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class TextBreakIteratorTest : public testing::Test {
 protected:
  void SetTestString(const char* test_string) {
    test_string_ = String::FromUTF8(test_string);
  }

  void SetTestString16(Vector<UChar> input) { test_string_ = String(input); }

  // The expected break positions must be specified UTF-16 character boundaries.
  void MatchLineBreaks(
      const Vector<int> expected_break_positions,
      LineBreakType line_break_type = LineBreakType::kNormal,
      BreakSpaceType break_space = BreakSpaceType::kAfterSpaceRun) {
    if (test_string_.Is8Bit()) {
      test_string_ = String::Make16BitFrom8BitSource(test_string_.Span8());
    }
    LazyLineBreakIterator lazy_break_iterator(test_string_, locale_.get());
    lazy_break_iterator.SetBreakType(line_break_type);
    lazy_break_iterator.SetBreakSpace(break_space);
    TestIsBreakable(expected_break_positions, lazy_break_iterator);
    TestNextBreakOpportunity(expected_break_positions, lazy_break_iterator);
  }

  // Test IsBreakable() by iterating all positions. BreakingContext uses this
  // interface.
  void TestIsBreakable(const Vector<int> expected_break_positions,
                       const LazyLineBreakIterator& break_iterator) {
    Vector<int> break_positions;
    for (unsigned i = 0; i <= test_string_.length(); i++) {
      if (break_iterator.IsBreakable(i)) {
        break_positions.push_back(i);
      }
    }
    EXPECT_THAT(break_positions,
                testing::ElementsAreArray(expected_break_positions))
        << test_string_ << " " << break_iterator.BreakType() << " "
        << break_iterator.BreakSpace();
  }

  // Test NextBreakOpportunity() by iterating break opportunities.
  // ShapingLineBreaker uses this interface.
  void TestNextBreakOpportunity(const Vector<int> expected_break_positions,
                                const LazyLineBreakIterator& break_iterator) {
    Vector<int> break_positions;
    for (unsigned i = 0; i <= test_string_.length(); i++) {
      i = break_iterator.NextBreakOpportunity(i);
      break_positions.push_back(i);
    }
    EXPECT_THAT(break_positions,
                testing::ElementsAreArray(expected_break_positions))
        << test_string_ << " " << break_iterator.BreakType() << " "
        << break_iterator.BreakSpace();
  }

  unsigned TestLengthOfGraphemeCluster() {
    return LengthOfGraphemeCluster(test_string_);
  }

  Vector<unsigned> GraphemesClusterList(String input,
                                        unsigned start,
                                        unsigned length) {
    Vector<unsigned> result;
    ::blink::GraphemesClusterList(StringView(input, start, length), &result);
    return result;
  }

 protected:
  String test_string_;
  scoped_refptr<LayoutLocale> locale_;
};

TEST_F(TextBreakIteratorTest, PooledBreakIterator) {
  const AtomicString locale{"en"};
  const String str{"a"};
  PooledBreakIterator it1 = AcquireLineBreakIterator(str, locale);

  // Get another and release. It should be a different instance than `it1`.
  TextBreakIterator* ptr2;
  {
    PooledBreakIterator it2 = AcquireLineBreakIterator(str, locale);
    EXPECT_NE(it2.get(), it1.get());
    ptr2 = it2.get();
  }

  // Because `it2` is released, `it3` should be the same instance as `it2`.
  PooledBreakIterator it3 = AcquireLineBreakIterator(str, locale);
  EXPECT_EQ(it3.get(), ptr2);
}

static const LineBreakType all_break_types[] = {
    LineBreakType::kNormal, LineBreakType::kBreakAll,
    LineBreakType::kBreakCharacter, LineBreakType::kKeepAll,
    LineBreakType::kPhrase};

class BreakTypeTest : public TextBreakIteratorTest,
                      public testing::WithParamInterface<LineBreakType> {};

INSTANTIATE_TEST_SUITE_P(TextBreakIteratorTest,
                         BreakTypeTest,
                         testing::ValuesIn(all_break_types));

TEST_P(BreakTypeTest, EmptyString) {
  LazyLineBreakIterator iterator(g_empty_string);
  iterator.SetBreakType(GetParam());
  EXPECT_TRUE(iterator.IsBreakable(0));
}

TEST_P(BreakTypeTest, EmptyNullString) {
  LazyLineBreakIterator iterator(String{});
  iterator.SetBreakType(GetParam());
  EXPECT_TRUE(iterator.IsBreakable(0));
}

TEST_F(TextBreakIteratorTest, Strictness) {
  scoped_refptr<LayoutLocale> locale =
      LayoutLocale::CreateForTesting(AtomicString("ja"));
  LazyLineBreakIterator iterator(String(u"あーあ"), locale.get());
  EXPECT_EQ(iterator.NextBreakOpportunity(0), 1u);
  EXPECT_EQ(iterator.LocaleWithKeyword(), "ja");

  iterator.SetStrictness(LineBreakStrictness::kStrict);
  EXPECT_EQ(iterator.NextBreakOpportunity(0), 2u);
  EXPECT_EQ(iterator.LocaleWithKeyword(), "ja@lb=strict");

  iterator.SetLocale(nullptr);
  EXPECT_EQ(iterator.NextBreakOpportunity(0), 1u);
  EXPECT_EQ(iterator.LocaleWithKeyword(), "");
}

TEST_F(TextBreakIteratorTest, Basic) {
  SetTestString("a b  c");
  MatchLineBreaks({2, 5, 6});
}

TEST_F(TextBreakIteratorTest, Newline) {
  SetTestString("a\nb\n\nc\n d");
  MatchLineBreaks({2, 5, 8, 9});
}

TEST_F(TextBreakIteratorTest, Tab) {
  SetTestString("a\tb\t\tc");
  MatchLineBreaks({2, 5, 6}, LineBreakType::kNormal);
}

TEST_F(TextBreakIteratorTest, LatinPunctuation) {
  SetTestString("(ab) cd.");
  MatchLineBreaks({5, 8}, LineBreakType::kNormal);
  MatchLineBreaks({2, 5, 6, 8}, LineBreakType::kBreakAll);
  MatchLineBreaks({1, 2, 3, 4, 5, 6, 7, 8}, LineBreakType::kBreakCharacter);
  MatchLineBreaks({5, 8}, LineBreakType::kKeepAll);
}

TEST_F(TextBreakIteratorTest, Chinese) {
  SetTestString("標準萬國碼");
  MatchLineBreaks({1, 2, 3, 4, 5}, LineBreakType::kNormal);
  MatchLineBreaks({1, 2, 3, 4, 5}, LineBreakType::kBreakAll);
  MatchLineBreaks({1, 2, 3, 4, 5}, LineBreakType::kBreakCharacter);
  MatchLineBreaks({5}, LineBreakType::kKeepAll);
}

TEST_F(TextBreakIteratorTest, ChineseMixed) {
  SetTestString("標（準）萬ab國.碼");
  MatchLineBreaks({1, 4, 5, 7, 9, 10}, LineBreakType::kNormal);
  MatchLineBreaks({1, 4, 5, 6, 7, 9, 10}, LineBreakType::kBreakAll);
  MatchLineBreaks({1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
                  LineBreakType::kBreakCharacter);
  MatchLineBreaks({1, 4, 9, 10}, LineBreakType::kKeepAll);
}

TEST_F(TextBreakIteratorTest, ChineseSpaces) {
  SetTestString("標  萬  a  國");
  MatchLineBreaks({3, 6, 9, 10}, LineBreakType::kNormal);
  MatchLineBreaks({3, 6, 9, 10}, LineBreakType::kBreakAll);
  MatchLineBreaks({1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
                  LineBreakType::kBreakCharacter);
  MatchLineBreaks({3, 6, 9, 10}, LineBreakType::kKeepAll);
}

TEST_F(TextBreakIteratorTest, KeepEmojiZWJFamilyIsolate) {
  SetTestString("\U0001F468\u200D\U0001F469\u200D\U0001F467\u200D\U0001F466");
  MatchLineBreaks({11}, LineBreakType::kNormal);
  MatchLineBreaks({11}, LineBreakType::kBreakAll);
  MatchLineBreaks({11}, LineBreakType::kBreakCharacter);
  MatchLineBreaks({11}, LineBreakType::kKeepAll);
}

TEST_F(TextBreakIteratorTest, KeepEmojiModifierSequenceIsolate) {
  SetTestString("\u261D\U0001F3FB");
  MatchLineBreaks({3}, LineBreakType::kNormal);
  MatchLineBreaks({3}, LineBreakType::kBreakAll);
  MatchLineBreaks({3}, LineBreakType::kBreakCharacter);
  MatchLineBreaks({3}, LineBreakType::kKeepAll);
}

TEST_F(TextBreakIteratorTest, KeepEmojiZWJSequence) {
  SetTestString(
      "abc \U0001F469\u200D\U0001F469\u200D\U0001F467\u200D\U0001F467 def");
  MatchLineBreaks({4, 16, 19}, LineBreakType::kNormal);
  MatchLineBreaks({1, 2, 4, 16, 17, 18, 19}, LineBreakType::kBreakAll);
  MatchLineBreaks({1, 2, 3, 4, 15, 16, 17, 18, 19},
                  LineBreakType::kBreakCharacter);
  MatchLineBreaks({4, 16, 19}, LineBreakType::kKeepAll);
}

TEST_F(TextBreakIteratorTest, KeepEmojiModifierSequence) {
  SetTestString("abc \u261D\U0001F3FB def");
  MatchLineBreaks({4, 8, 11}, LineBreakType::kNormal);
  MatchLineBreaks({1, 2, 4, 8, 9, 10, 11}, LineBreakType::kBreakAll);
  MatchLineBreaks({1, 2, 3, 4, 7, 8, 9, 10, 11},
                  LineBreakType::kBreakCharacter);
  MatchLineBreaks({4, 8, 11}, LineBreakType::kKeepAll);
}

TEST_P(BreakTypeTest, NextBreakOpportunityAtEnd) {
  const LineBreakType break_type = GetParam();
  LazyLineBreakIterator break_iterator(String("1"));
  break_iterator.SetBreakType(break_type);
  EXPECT_EQ(1u, break_iterator.NextBreakOpportunity(1));
}

TEST_F(TextBreakIteratorTest, Phrase) {
  locale_ = LayoutLocale::CreateForTesting(AtomicString("ja"));
  test_string_ = u"今日はよい天気です。";
  MatchLineBreaks({3, 5, 10}, LineBreakType::kPhrase);
  test_string_ = u"あなたに寄り添う最先端のテクノロジー。";
  MatchLineBreaks({4, 8, 12, 19}, LineBreakType::kPhrase);
}

TEST_F(TextBreakIteratorTest, LengthOfGraphemeCluster) {
  SetTestString("");
  EXPECT_EQ(0u, TestLengthOfGraphemeCluster());

  SetTestString16({});
  EXPECT_EQ(0u, TestLengthOfGraphemeCluster());

  SetTestString("a");
  EXPECT_EQ(1u, TestLengthOfGraphemeCluster());
  SetTestString("\n");
  EXPECT_EQ(1u, TestLengthOfGraphemeCluster());
  SetTestString("\r");
  EXPECT_EQ(1u, TestLengthOfGraphemeCluster());
  SetTestString16({'a'});
  EXPECT_EQ(1u, TestLengthOfGraphemeCluster());
  SetTestString16({'\n'});
  EXPECT_EQ(1u, TestLengthOfGraphemeCluster());
  SetTestString16({'\r'});
  EXPECT_EQ(1u, TestLengthOfGraphemeCluster());

  SetTestString("abc");
  EXPECT_EQ(1u, TestLengthOfGraphemeCluster());

  SetTestString16({'a', 'b', 'c'});
  EXPECT_EQ(1u, TestLengthOfGraphemeCluster());

  SetTestString("\r\n");
  EXPECT_EQ(2u, TestLengthOfGraphemeCluster());

  SetTestString16({'\r', '\n'});
  EXPECT_EQ(2u, TestLengthOfGraphemeCluster());

  SetTestString("\n\r");
  EXPECT_EQ(1u, TestLengthOfGraphemeCluster());

  SetTestString16({'\n', '\r'});
  EXPECT_EQ(1u, TestLengthOfGraphemeCluster());

  SetTestString("\r\n\r");
  EXPECT_EQ(2u, TestLengthOfGraphemeCluster());

  SetTestString16({'\r', '\n', '\r'});
  EXPECT_EQ(2u, TestLengthOfGraphemeCluster());

  SetTestString16({'g', 0x308});
  EXPECT_EQ(2u, TestLengthOfGraphemeCluster());
  SetTestString16({0x1100, 0x1161, 0x11A8});
  EXPECT_EQ(3u, TestLengthOfGraphemeCluster());
  SetTestString16({0x0BA8, 0x0BBF});
  EXPECT_EQ(2u, TestLengthOfGraphemeCluster());

  SetTestString16({0x308, 'g'});
  EXPECT_EQ(1u, TestLengthOfGraphemeCluster());

  SetTestString("\r\nbc");
  EXPECT_EQ(2u, TestLengthOfGraphemeCluster());

  SetTestString16({'g', 0x308, 'b', 'c'});
  EXPECT_EQ(2u, TestLengthOfGraphemeCluster());
}

TEST_F(TextBreakIteratorTest, GraphemesClusterListTest) {
  EXPECT_EQ(GraphemesClusterList(u"hello", 0, 5),
            Vector<unsigned>({0, 1, 2, 3, 4}));
  EXPECT_EQ(GraphemesClusterList(u"hello", 2, 2), Vector<unsigned>({0, 1}));
  EXPECT_EQ(GraphemesClusterList(u"voila\u0300!", 0, 7),
            Vector<unsigned>({0, 1, 2, 3, 4, 4, 5}));
  EXPECT_EQ(GraphemesClusterList(u"di\u0303\u031c\u0337!", 0, 6),
            Vector<unsigned>({0, 1, 1, 1, 1, 2}));
  EXPECT_EQ(GraphemesClusterList(u"🇨🇦", 0, 4), Vector<unsigned>({0, 0, 0, 0}));

  EXPECT_EQ(GraphemesClusterList(u"🏳️‍🌈", 0, 6),
            Vector<unsigned>({0, 0, 0, 0, 0, 0}));
  // NO ZWJ on this sequence.
  EXPECT_EQ(GraphemesClusterList(u"🏳🌈", 0, 4),
            Vector<unsigned>({0, 0, 1, 1}));

  // ARABIC LETTER MEEM + ARABIC FATHA
  EXPECT_EQ(GraphemesClusterList(u"\u0645\u064E", 0, 2),
            Vector<unsigned>({0, 0}));
}

TEST_F(TextBreakIteratorTest, SoftHyphen) {
  SetTestString("xy\u00ADxy\u00ADxy xy\u00ADxy");
  LazyLineBreakIterator break_iterator(test_string_);
  break_iterator.SetBreakSpace(BreakSpaceType::kAfterSpaceRun);
  TestNextBreakOpportunity({3, 6, 9, 12, 14}, break_iterator);
  break_iterator.EnableSoftHyphen(false);
  TestNextBreakOpportunity({9, 14}, break_iterator);
}

TEST_F(TextBreakIteratorTest, HyphenMinusBeforeHighLatin) {
  SetTestString("Lorem-úpsum");
  MatchLineBreaks({6, 11});
  SetTestString("Lorem-èpsum");
  MatchLineBreaks({6, 11});
}

}  // namespace blink
```
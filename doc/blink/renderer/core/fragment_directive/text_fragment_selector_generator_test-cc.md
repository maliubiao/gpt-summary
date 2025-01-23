Response:
The user wants me to analyze a C++ source code file from the Chromium project related to text fragment selectors.

Here's a breakdown of the thought process to address the request:

1. **Identify the Core Functionality:** The file name `text_fragment_selector_generator_test.cc` immediately suggests it's a test file. The presence of `#include "third_party/blink/renderer/core/fragment_directive/text_fragment_selector_generator.h"` indicates it's testing the `TextFragmentSelectorGenerator` class. The code uses `gtest`, confirming it's a unit test. Therefore, the primary function is to **test the generation of text fragment selectors**.

2. **Understand Text Fragment Selectors:**  Recall or research what text fragment selectors are. They're a way to link directly to specific text on a webpage using a URL fragment. The format is typically `#:~:text=[prefix-,]textStart[,textEnd][,-suffix]`. This understanding is crucial for interpreting the test cases.

3. **Examine the Test Cases:** The test file contains numerous test functions (e.g., `EmptySelection`, `ExactTextSelector`). Analyze each test case to understand what scenario it's verifying:
    * **Basic Cases:**  Testing simple exact matches, empty selections, and cases where the selection spans multiple nodes.
    * **Contextual Cases:** Testing the addition of `prefix-` and `-suffix` when a simple exact match isn't unique. Pay attention to cases with the same prefix, same suffix, or both.
    * **Range Selectors:** Testing scenarios where the selection is long and spans across elements, leading to the use of `textStart,textEnd`.
    * **Edge Cases:**  Cases with long words, nested elements, extra spaces.

4. **Identify Interactions with Web Technologies:** Text fragment selectors are directly tied to how URLs work in web browsers. Consider how JavaScript, HTML, and CSS might interact (or not) with this functionality:
    * **HTML:** The structure of the HTML content is fundamental to how the selector is generated. The tests explicitly load HTML and target specific elements and text nodes.
    * **JavaScript:** While this specific C++ code doesn't directly execute JavaScript, the *result* of the selector generation is intended to be used in URLs, which JavaScript in a browser could then interpret and use (e.g., `window.location.hash`).
    * **CSS:** CSS primarily deals with styling. It's unlikely to directly influence the *generation* of the text fragment selector. However, the rendered layout (which CSS affects) could indirectly influence how the selection is made by the user.

5. **Infer Logic and Examples:** Based on the test case names and the `VerifySelector` and `VerifySelectorFails` functions, deduce the input and expected output for different scenarios.
    * **Input:** A starting and ending `Position` within the rendered HTML.
    * **Output:** A string representing the generated text fragment selector or an empty string if generation fails.

6. **Identify Potential User/Programming Errors:** Think about how users might incorrectly try to use or generate these selectors, or how developers might make mistakes in the underlying code:
    * **User Errors:** Manually constructing incorrect selectors, selecting whitespace or empty content, selecting too much content where the logic might have limitations.
    * **Programming Errors (in the generator):** Not handling edge cases, incorrect logic for determining prefix/suffix, failing to handle special characters, exceeding length limits.

7. **Summarize the Functionality:**  Condense the findings into a concise description of the file's purpose.

8. **Structure the Answer:** Organize the information logically, addressing each part of the user's request (functionality, relationships with web technologies, logic/examples, common errors, summary). Use clear language and provide specific examples from the code where applicable.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this file is about *handling* text fragment selectors.
* **Correction:** The file name and the included header clearly indicate it's about *generating* them. The `GenerateSelector` function confirms this.
* **Initial thought:** How does CSS relate?
* **Refinement:**  CSS likely has an indirect impact on what text is visible and selectable, but the *generation logic* itself probably doesn't directly interact with CSS in this code. The focus is on the DOM structure and text content.
* **Ensuring clarity:**  Use code snippets and the expected output to illustrate the logic. Explain the purpose of the helper functions like `VerifySelector` and `VerifySelectorFails`.

By following this thought process, the detailed and accurate answer provided earlier can be constructed.
这是名为 `text_fragment_selector_generator_test.cc` 的 Chromium Blink 引擎源代码文件，其主要功能是**测试 `TextFragmentSelectorGenerator` 类的功能**。

`TextFragmentSelectorGenerator` 类的作用是**根据用户在网页上选择的文本范围，生成相应的文本片段选择器 (Text Fragment Selector)**。文本片段选择器是一种 URL 片段，用于直接链接到网页上的特定文本内容。

以下是对其功能的详细解释，并结合 JavaScript, HTML, CSS 进行说明：

**1. 功能概览:**

* **生成文本片段选择器:**  `TextFragmentSelectorGenerator` 类接收用户选择的文本起始和结束位置作为输入，并尝试生成一个文本片段选择器字符串。
* **测试不同选择场景:**  该测试文件包含了各种测试用例，涵盖了不同的文本选择场景，例如：
    * 空选择
    * 精确文本选择（exact text）
    * 包含嵌套 HTML 元素的文本选择
    * 包含多个空格的文本选择
    * 需要上下文（context）才能唯一标识的选择
    * 跨越多个节点的选择（range selection）
    * 非常长的文本选择
* **验证选择器的正确性:**  每个测试用例都会断言生成的选择器是否与预期的一致。
* **记录指标 (Metrics):**  测试会检查成功和失败的选择器生成，并记录到 UKM (User Keyed Metrics) 和直方图 (Histograms) 中，用于性能和错误分析。

**2. 与 JavaScript, HTML, CSS 的关系及举例:**

* **HTML:** `TextFragmentSelectorGenerator` 的核心是处理 HTML 文档的结构和内容。它需要遍历 DOM 树来确定选择的文本范围，并提取必要的上下文信息。
    * **例子:** 测试用例中会加载不同的 HTML 片段，例如：
      ```html
      <!DOCTYPE html>
      <div>Test page</div>
      <p id='first'>First paragraph text that is longer than 20 chars</p>
      <p id='second'>Second paragraph text</p>
      ```
      测试会针对这些 HTML 结构中的文本进行选择，并验证生成的选择器是否正确。

* **JavaScript:**  虽然这个 C++ 文件本身不包含 JavaScript 代码，但 `TextFragmentSelectorGenerator` 生成的文本片段选择器最终会被 JavaScript 使用。当用户点击包含文本片段选择器的链接时，浏览器会使用 JavaScript 解析该选择器，并在页面上滚动到并高亮显示相应的文本。
    * **例子:**  如果 `TextFragmentSelectorGenerator` 为选择了 "paragraph text that is" 这段文本生成了选择器 "paragraph%20text%20that%20is"，那么一个包含该选择器的链接可能是：
      ```html
      <a href="https://example.com/test.html#:~:text=paragraph%2520text%2520that%2520is">跳转到特定文本</a>
      ```
      当用户点击这个链接时，浏览器（通过 JavaScript 处理）会尝试在 `https://example.com/test.html` 页面上找到并高亮显示 "paragraph text that is" 这段文本。

* **CSS:** CSS 主要负责网页的样式。它本身不直接参与文本片段选择器的生成过程。然而，CSS 可能会影响文本的布局和渲染，从而间接地影响用户选择的文本范围。
    * **例子:**  如果使用 CSS 将文本隐藏 (`display: none;`) 或使其不可见 (`visibility: hidden;`)，那么 `TextFragmentSelectorGenerator` 可能无法选择到这些文本。

**3. 逻辑推理与假设输入输出:**

假设用户在以下 HTML 中选择了 "unique snippet" 这段文本：

```html
<!DOCTYPE html>
<div>Test page</div>
<p id='first'>First paragraph prefix to unique snippet of text.</p>
<p id='second'>Second paragraph</p>
```

* **假设输入:**
    * `selected_start`: 指向 "unique" 中 'u' 的位置 (相对于 `#first` 元素的第一个子节点)
    * `selected_end`: 指向 "snippet" 中 't' 之后的位置 (相对于 `#first` 元素的第一个子节点)

* **逻辑推理:** 由于 "unique snippet" 可能在其他地方也出现，为了确保唯一性，`TextFragmentSelectorGenerator` 会尝试添加上下文。它会向前查找前缀，向后查找后缀，直到能够唯一标识这段文本。在这个例子中，前缀 "paragraph prefix to " 和后缀 " of text." 可以帮助区分。

* **假设输出:**
    ```
    "paragraph%20prefix%20to-,unique%20snippet,-of%20text."
    ```

**4. 用户或编程常见的使用错误:**

* **用户错误:**
    * **选择空白或不可见的文本:** 用户可能会尝试选择只包含空格或者被 CSS 隐藏的文本，这可能导致 `TextFragmentSelectorGenerator` 无法生成有效的选择器或者生成不符合预期的选择器。
    * **手动构造错误的文本片段选择器:** 用户可能会尝试手动编辑 URL 中的文本片段选择器，如果格式不正确，浏览器可能无法正确解析和定位。 例如，缺少 `#:~:text=` 前缀，或者使用了错误的 URL 编码。

* **编程错误 (在 `TextFragmentSelectorGenerator` 的实现中):**
    * **未正确处理特殊字符:**  如果 `TextFragmentSelectorGenerator` 没有正确地对文本中的特殊字符进行 URL 编码，生成的选择器可能无法正常工作。
    * **上下文提取逻辑错误:**  在需要添加上下文的情况下，如果前缀或后缀的提取逻辑存在错误，可能导致生成的选择器无法唯一标识目标文本，或者包含了不必要的上下文。
    * **性能问题:** 对于非常大的文档，如果文本遍历和比较的算法效率不高，生成选择器的过程可能会很慢。

**5. 功能归纳 (针对第 1 部分):**

`text_fragment_selector_generator_test.cc` 文件作为 Blink 引擎的一部分，主要功能是**测试 `TextFragmentSelectorGenerator` 类的文本片段选择器生成功能**。它通过模拟各种用户文本选择场景，并断言生成的选择器字符串是否符合预期，来确保 `TextFragmentSelectorGenerator` 的正确性和可靠性。 这个文件是单元测试，专注于验证生成器的核心逻辑，并使用指标来监控其行为。

### 提示词
```
这是目录为blink/renderer/core/fragment_directive/text_fragment_selector_generator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fragment_directive/text_fragment_selector_generator.h"

#include <gtest/gtest.h>

#include "base/run_loop.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "components/shared_highlighting/core/common/shared_highlighting_features.h"
#include "components/shared_highlighting/core/common/shared_highlighting_metrics.h"
#include "components/ukm/test_ukm_recorder.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "third_party/blink/public/mojom/link_to_text/link_to_text.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_handler.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/scoped_fake_ukm_recorder.h"

using LinkGenerationError = shared_highlighting::LinkGenerationError;

namespace blink {

namespace {
const char kSuccessUkmMetric[] = "Success";
const char kErrorUkmMetric[] = "Error";
}  // namespace

class TextFragmentSelectorGeneratorTest : public SimTest {
 public:
  void SetUp() override {
    SimTest::SetUp();
    WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  }

  void VerifySelector(Position selected_start,
                      Position selected_end,
                      String expected_selector) {
    String generated_selector = GenerateSelector(selected_start, selected_end);
    EXPECT_EQ(expected_selector, generated_selector);

    // Should not have logged errors in a success case.
    histogram_tester_.ExpectTotalCount("SharedHighlights.LinkGenerated.Error",
                                       0);
    histogram_tester_.ExpectTotalCount(
        "SharedHighlights.LinkGenerated.Error.Requested", 0);

    histogram_tester_.ExpectTotalCount("SharedHighlights.LinkGenerated",
                                       generate_call_count_);
    auto entries = ukm_recorder()->GetEntriesByName(
        ukm::builders::SharedHighlights_LinkGenerated::kEntryName);
    ASSERT_EQ(1u, entries.size());
    const ukm::mojom::UkmEntry* entry = entries[0];
    EXPECT_EQ(GetDocument().UkmSourceID(), entry->source_id);
    ukm_recorder()->ExpectEntryMetric(entry, kSuccessUkmMetric, true);
    EXPECT_FALSE(ukm_recorder()->GetEntryMetric(entry, kErrorUkmMetric));
  }

  void VerifySelectorFails(Position selected_start,
                           Position selected_end,
                           LinkGenerationError error) {
    String generated_selector = GenerateSelector(selected_start, selected_end);
    EXPECT_EQ("", generated_selector);

    histogram_tester_.ExpectTotalCount("SharedHighlights.LinkGenerated",
                                       generate_call_count_);
    histogram_tester_.ExpectBucketCount("SharedHighlights.LinkGenerated.Error",
                                        error, 1);
    auto entries = ukm_recorder()->GetEntriesByName(
        ukm::builders::SharedHighlights_LinkGenerated::kEntryName);
    ASSERT_EQ(1u, entries.size());
    const ukm::mojom::UkmEntry* entry = entries[0];
    EXPECT_EQ(GetDocument().UkmSourceID(), entry->source_id);
    ukm_recorder()->ExpectEntryMetric(entry, kSuccessUkmMetric, false);
    ukm_recorder()->ExpectEntryMetric(entry, kErrorUkmMetric,
                                      static_cast<int64_t>(error));
  }

  String GenerateSelector(Position selected_start, Position selected_end) {
    generate_call_count_++;

    bool callback_called = false;
    String selector;
    auto lambda = [](bool& callback_called, String& selector,
                     const TextFragmentSelector& generated_selector,
                     shared_highlighting::LinkGenerationError error) {
      selector = generated_selector.ToString();
      callback_called = true;
    };
    auto callback =
        WTF::BindOnce(lambda, std::ref(callback_called), std::ref(selector));
    CreateGenerator()->Generate(*MakeGarbageCollected<RangeInFlatTree>(
                                    ToPositionInFlatTree(selected_start),
                                    ToPositionInFlatTree(selected_end)),
                                std::move(callback));
    base::RunLoop().RunUntilIdle();

    EXPECT_TRUE(callback_called);
    return selector;
  }

  TextFragmentSelectorGenerator* CreateGenerator() {
    return MakeGarbageCollected<TextFragmentSelectorGenerator>(
        GetDocument().GetFrame());
  }

 protected:
  ukm::TestUkmRecorder* ukm_recorder() {
    return scoped_ukm_recorder_.recorder();
  }

  base::HistogramTester histogram_tester_;
  ScopedFakeUkmRecorder scoped_ukm_recorder_;
  int generate_call_count_ = 0;

  struct ScopedExactTextMaxCharsOverride {
    explicit ScopedExactTextMaxCharsOverride(int value) {
      TextFragmentSelectorGenerator::OverrideExactTextMaxCharsForTesting(value);
    }

    ~ScopedExactTextMaxCharsOverride() {
      TextFragmentSelectorGenerator::OverrideExactTextMaxCharsForTesting(-1);
    }
  };
};

// Basic exact selector case.
TEST_F(TextFragmentSelectorGeneratorTest, EmptySelection) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First paragraph</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 5);
  const auto& selected_end = Position(first_paragraph, 6);
  ASSERT_EQ(" ", PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelectorFails(selected_start, selected_end,
                      LinkGenerationError::kEmptySelection);
}

// Basic exact selector case.
TEST_F(TextFragmentSelectorGeneratorTest, ExactTextSelector) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph text that is longer than 20 chars</p>
    <p id='second'>Second paragraph text</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 0);
  const auto& selected_end = Position(first_paragraph, 28);
  ASSERT_EQ("First paragraph text that is",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "First%20paragraph%20text%20that%20is");
}

// A single long word will return an exact selection, even if it would normally
// exceed the max chars for exact threshold.
TEST_F(TextFragmentSelectorGeneratorTest, ExactTextSelector_Long) {
  ScopedExactTextMaxCharsOverride force_range_generation(10);
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>first_texts_and_last</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 0);
  const auto& selected_end = Position(first_paragraph, 20);
  ASSERT_EQ("first_texts_and_last",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end, "first_texts_and_last");
}

// Exact selector test where selection contains nested <i> node.
TEST_F(TextFragmentSelectorGeneratorTest, ExactTextWithNestedTextNodes) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph text that is <i>longer than 20</i> chars</p>
    <p id='second'>Second paragraph text</p>
  )HTML");
  Node* first_paragraph = GetDocument().getElementById(AtomicString("first"));
  const auto& selected_start = Position(first_paragraph->firstChild(), 0);
  const auto& selected_end =
      Position(first_paragraph->firstChild()->nextSibling()->firstChild(), 6);
  ASSERT_EQ("First paragraph text that is longer",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "First%20paragraph%20text%20that%20is%20longer");
}

// Exact selector test where selection contains multiple spaces.
TEST_F(TextFragmentSelectorGeneratorTest, ExactTextWithExtraSpace) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph text that is longer than 20 chars</p>
    <p id='second'>Second paragraph
      text</p>
  )HTML");
  Node* second_paragraph =
      GetDocument().getElementById(AtomicString("second"))->firstChild();
  const auto& selected_start = Position(second_paragraph, 0);
  const auto& selected_end = Position(second_paragraph, 27);
  ASSERT_EQ("Second paragraph text",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end, "Second%20paragraph%20text");
}

// Exact selector where selection is too short, in which case context is
// required.
TEST_F(TextFragmentSelectorGeneratorTest,
       ExactTextSelector_TooShortNeedsContext) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph prefix to unique snippet of text.</p>
    <p id='second'>Second paragraph</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 26);
  const auto& selected_end = Position(first_paragraph, 40);
  ASSERT_EQ("unique snippet",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "paragraph%20prefix%20to-,unique%20snippet,-of%20text.");
}

// Exact selector with context test. Case when only one word for prefix and
// suffix is enough to disambiguate the selection.
TEST_F(TextFragmentSelectorGeneratorTest,
       ExactTextSelector_WithOneWordContext) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph text that is longer than 20 chars</p>
    <p id='second'>Second paragraph text that is short</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 6);
  const auto& selected_end = Position(first_paragraph, 28);
  ASSERT_EQ("paragraph text that is",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "First-,paragraph%20text%20that%20is,-longer%20than%2020");
}

// Exact selector with context test. Case when multiple words for prefix and
// suffix is necessary to disambiguate the selection.
TEST_F(TextFragmentSelectorGeneratorTest,
       ExactTextSelector_MultipleWordContext) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First prefix to not unique snippet of text followed by suffix</p>
    <p id='second'>Second prefix to not unique snippet of text followed by suffix</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 16);
  const auto& selected_end = Position(first_paragraph, 42);
  ASSERT_EQ("not unique snippet of text",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "First%20prefix%20to-,not%20unique%20snippet%20of%"
                 "20text,-followed%20by%20suffix");
}

// Exact selector with context test. Case when multiple words for prefix and
// suffix is necessary to disambiguate the selection and prefix and suffix
// contain extra space.
TEST_F(TextFragmentSelectorGeneratorTest,
       ExactTextSelector_MultipleWordContext_ExtraSpace) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First prefix      to not unique snippet of text followed       by suffix</p>
    <p id='second'>Second prefix to not unique snippet of text followed by suffix</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 21);
  const auto& selected_end = Position(first_paragraph, 47);
  ASSERT_EQ("not unique snippet of text",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "First%20prefix%20to-,not%20unique%20snippet%20of%"
                 "20text,-followed%20by%20suffix");
}

// Exact selector with context test. Case when available prefix for all the
// occurrences of selected text is the same. In this case suffix should be
// extended until unique selector is found.
TEST_F(TextFragmentSelectorGeneratorTest, ExactTextSelector_SamePrefix) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>Prefix to not unique snippet of text followed by different suffix</p>
    <p id='second'>Prefix to not unique snippet of text followed by suffix</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 10);
  const auto& selected_end = Position(first_paragraph, 36);
  ASSERT_EQ("not unique snippet of text",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "Prefix%20to-,not%20unique%20snippet%20of%20text,-"
                 "followed%20by%20different");
}

// Exact selector with context test. Case when available suffix for all the
// occurrences of selected text is the same. In this case prefix should be
// extended until unique selector is found.
TEST_F(TextFragmentSelectorGeneratorTest, ExactTextSelector_SameSuffix) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph prefix to not unique snippet of text followed by suffix</p>
    <p id='second'>Second paragraph prefix to not unique snippet of text followed by suffix</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 26);
  const auto& selected_end = Position(first_paragraph, 52);
  ASSERT_EQ("not unique snippet of text",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "First%20paragraph%20prefix%20to-,not%20unique%"
                 "20snippet%20of%20text,-followed%20by%20suffix");
}

// Exact selector with context test. Case when available prefix and suffix for
// all the occurrences of selected text are the same. In this case generation
// should be unsuccessful.
TEST_F(TextFragmentSelectorGeneratorTest, ExactTextSelector_SamePrefixSuffix) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>Same paragraph prefix to not unique snippet of text followed by suffix</p>
    <p id='second'>Same paragraph prefix to not unique snippet of text followed by suffix</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 25);
  const auto& selected_end = Position(first_paragraph, 51);
  ASSERT_EQ("not unique snippet of text",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelectorFails(selected_start, selected_end,
                      LinkGenerationError::kContextExhausted);
}

// Exact selector with context test. Case when available prefix and suffix for
// all the occurrences of selected text are the same for the first 10 words. In
// this case generation should be unsuccessful.
TEST_F(TextFragmentSelectorGeneratorTest,
       ExactTextSelector_SimilarLongPreffixSuffix) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph prefix one two three four five six seven
     eight nine ten to not unique snippet of text followed by suffix</p>
    <p id='second'>Second paragraph prefix one two three four five six seven
     eight nine ten to not unique snippet of text followed by suffix</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 80);
  const auto& selected_end = Position(first_paragraph, 106);
  ASSERT_EQ("not unique snippet of text",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelectorFails(selected_start, selected_end,
                      LinkGenerationError::kContextLimitReached);
}

// Exact selector with context test. Case when no prefix is available.
TEST_F(TextFragmentSelectorGeneratorTest, ExactTextSelector_NoPrefix) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>Not unique snippet of text followed by first suffix</p>
    <p id='second'>Not unique snippet of text followed by second suffix</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 0);
  const auto& selected_end = Position(first_paragraph, 26);
  ASSERT_EQ("Not unique snippet of text",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "Not%20unique%20snippet%20of%20text,-followed%20by%20first");
}

// Exact selector with context test. Case when no suffix is available.
TEST_F(TextFragmentSelectorGeneratorTest, ExactTextSelector_NoSuffix) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First prefix to not unique snippet of text</p>
    <p id='second'>Second prefix to not unique snippet of text</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("second"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 17);
  const auto& selected_end = Position(first_paragraph, 43);
  ASSERT_EQ("not unique snippet of text",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "Second%20prefix%20to-,not%20unique%20snippet%20of%"
                 "20text");
}

// Exact selector with context test. Case when available prefix is the
// preceding block.
TEST_F(TextFragmentSelectorGeneratorTest, ExactTextSelector_PrevNodePrefix) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph with not unique snippet</p>
    <p id='second'>not unique snippet of text</p>
  )HTML");
  Node* second_paragraph =
      GetDocument().getElementById(AtomicString("second"))->firstChild();
  const auto& selected_start = Position(second_paragraph, 0);
  const auto& selected_end = Position(second_paragraph, 18);
  ASSERT_EQ("not unique snippet",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "not%20unique%20snippet-,not%20unique%20snippet,-of%20text");
}

// Exact selector with context test. Case when available prefix is the
// preceding block, which is a text node.
TEST_F(TextFragmentSelectorGeneratorTest,
       ExactTextSelector_PrevTextNodePrefix) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph with not unique snippet</p>
    text
    <p id='second'>not unique snippet of text</p>
  )HTML");
  Node* second_paragraph =
      GetDocument().getElementById(AtomicString("second"))->firstChild();
  const auto& selected_start = Position(second_paragraph, 0);
  const auto& selected_end = Position(second_paragraph, 18);
  ASSERT_EQ("not unique snippet",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "text-,not%20unique%20snippet,-of%20text");
}

// Exact selector with context test. Case when available suffix is the next
// block.
TEST_F(TextFragmentSelectorGeneratorTest, ExactTextSelector_NextNodeSuffix) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph with not unique snippet</p>
    <p id='second'>not unique snippet of text</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 21);
  const auto& selected_end = Position(first_paragraph, 39);
  ASSERT_EQ("not unique snippet",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "First%20paragraph%20with-,not%20unique%20snippet,-not%"
                 "20unique%20snippet");
}

// Exact selector with context test. Case when available suffix is the next
// block, which is a text node.
TEST_F(TextFragmentSelectorGeneratorTest,
       ExactTextSelector_NexttextNodeSuffix) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph with not unique snippet</p>
    text
    <p id='second'>not unique snippet of text</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 21);
  const auto& selected_end = Position(first_paragraph, 39);
  ASSERT_EQ("not unique snippet",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "First%20paragraph%20with-,not%20unique%20snippet,-text");
}

TEST_F(TextFragmentSelectorGeneratorTest, RangeSelector) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph text that is longer than 20 chars</p>
    <p id='second'>Second paragraph text</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  Node* second_paragraph =
      GetDocument().getElementById(AtomicString("second"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 0);
  const auto& selected_end = Position(second_paragraph, 6);
  ASSERT_EQ("First paragraph text that is longer than 20 chars\n\nSecond",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "First%20paragraph%20text,Second");
}

// It should be more than 300 characters selected from the same node so that
// ranges are used.
TEST_F(TextFragmentSelectorGeneratorTest, RangeSelector_SameNode) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph text text text text text text text
    text text text text text text text text text text text text text
    text text text text text text text text text text text text text
    text text text text text text text text text text text text text
    text text text text text text text text text and last text</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 0);
  const auto& selected_end = Position(first_paragraph, 320);
  ASSERT_EQ(
      "First paragraph text text text text text text text \
text text text text text text text text text text text text text \
text text text text text text text text text text text text text \
text text text text text text text text text text text text text \
text text text text text text text text text and last text",
      PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "First%20paragraph%20text,and%20last%20text");
}

// It should be more than 300 characters selected from the same node so that
// ranges are used.
TEST_F(TextFragmentSelectorGeneratorTest,
       RangeSelector_SameNode_MultipleSelections) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph text text text text text text text
    text text text text text text text text text text text text text
    text text text text text text text text text text text text text
    text text text text text text text text text text text text text
    text text text text text text text text text text and last text</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 0);
  const auto& selected_end = Position(first_paragraph, 325);
  ASSERT_EQ(
      "First paragraph text text text text text text text \
text text text text text text text text text text text text text \
text text text text text text text text text text text text text \
text text text text text text text text text text text text text \
text text text text text text text text text text and last text",
      PlainText(EphemeralRange(selected_start, selected_end)));
  ASSERT_EQ(309u,
            PlainText(EphemeralRange(selected_start, selected_end)).length());

  VerifySelector(selected_start, selected_end,
                 "First%20paragraph%20text,and%20last%20text");

  scoped_ukm_recorder_.ResetRecorder();

  const auto& second_selected_start = Position(first_paragraph, 6);
  const auto& second_selected_end = Position(first_paragraph, 325);
  ASSERT_EQ(
      "paragraph text text text text text text text \
text text text text text text text text text text text text text \
text text text text text text text text text text text text text \
text text text text text text text text text text text text text \
text text text text text text text text text text and last text",
      PlainText(EphemeralRange(second_selected_start, second_selected_end)));
  ASSERT_EQ(303u, PlainText(EphemeralRange(second_selected_start,
                                           second_selected_end))
                      .length());

  VerifySelector(second_selected_start, second_selected_end,
                 "paragraph%20text%20text,and%20last%20text");
}

// When using all the selected text for the range is not enough for unique
// match, context should be added.
TEST_F(TextFragmentSelectorGeneratorTest, RangeSelector_RangeNotUnique) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph</p><p id='text1'>text</p>
    <p id='second'>Second paragraph</p><p id='text2'>text</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  Node* first_text =
      GetDocument().getElementById(AtomicString("text1"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 6);
  const auto& selected_end = Position(first_text, 4);
  ASSERT_EQ("paragraph\n\ntext",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end,
                 "First-,paragraph,text,-Second%20paragraph");
}

// When selecting multiple short non block nodes, ensure range is produced
// correctly.
TEST_F(TextFragmentSelectorGeneratorTest,
       RangeSelector_RangeMultipleNonBlockNodes) {
  // This ensures that a range selector is created instead of an exact text
  // selector.
  ScopedExactTextMaxCharsOverride force_range_generation(4);
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <span id='foo'>foo</span> <span id='bar'>bar</span>
  )HTML");
  Node* foo = GetDocument().getElementById(AtomicString("foo"))->firstChild();
  Node* bar = GetDocument().getElementById(AtomicString("bar"))->firstChild();
  const auto& selected_start = Position(foo, 0);
  const auto& selected_end = Position(bar, 3);
  ASSERT_EQ("foo bar", PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end, "foo,bar");
}

// When using all the selected text for the range is not enough for unique
// match, context should be added, but only prefxi and no suffix is available.
TEST_F(TextFragmentSelectorGeneratorTest,
       RangeSelector_RangeNotUnique_NoSuffix) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph</p><p id='text1'>text</p>
    <p id='second'>Second paragraph</p><p id='text2'>text</p>
  )HTML");
  Node* second_paragraph =
      GetDocument().getElementById(AtomicString("second"))->firstChild();
  Node* second_text =
      GetDocument().getElementById(AtomicString("text2"))->firstChild();
  const auto& selected_start = Position(second_paragraph, 7);
  const auto& selected_end = Position(second_text, 4);
  ASSERT_EQ("paragraph\n\ntext",
            PlainText(EphemeralRange(selected_start, selected_end)));

  VerifySelector(selected_start, selected_end, "Second-,paragraph,text");
}

// Check the case with long word for range end.
TEST_F(TextFragmentSelectorGeneratorTest, RangeSelector_LongWord) {
  ScopedExactTextMaxCharsOverride force_range_generation(4);
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First second third fourth fifth sixth text_text_text_text_text_text_text_text_text_text_text_text_text_
```
Response:
Let's break down the thought process for analyzing this C++ unittest file.

**1. Initial Scan and Overall Purpose:**

The first thing I do is scan the imports and the namespace. I see `blink`, `content_extraction`, and `inner_text_builder`. The file name is `inner_text_builder_unittest.cc`, strongly suggesting this file contains unit tests for a class or set of functions related to building the "inner text" of HTML elements. The imports confirm this, including things like `Document`, `Text`, `HTMLDivElement`, etc.

**2. Analyzing Individual Tests (Top-Down Approach):**

I go through each `TEST` block, one by one, and try to understand what it's testing:

* **`Basic`:** This test loads a simple HTML string with an `iframe`. It checks if the `InnerTextBuilder` correctly identifies text nodes, the `iframe` as a separate frame, and extracts the content around it.

* **`MultiFrames`:** This test involves multiple nested `iframes` and checks if the `InnerTextBuilder` can traverse and extract text content across these frames. It also uses mocked URL loading, indicating it's testing scenarios where frames have different content loaded.

* **`DifferentOrigin`:** This test focuses on how the `InnerTextBuilder` handles `iframes` with a different origin. It expects that the content of cross-origin iframes *is not* included.

* **`InnerTextPassagesChunksSingleTextBlock` through `InnerTextPassagesExcludesSvgElements`:**  These tests use a different builder, `InnerTextPassagesBuilder`. The name and the parameters (`max_words_per_aggregate_passage`, etc.) strongly suggest this builder is designed to chunk or segment the inner text into passages based on certain criteria. I note the variety of scenarios covered: handling whitespace, empty elements, nested blocks, text nodes split by other elements, excluding certain tags (`title`, `style`, `script`, comments), greedy aggregation of siblings, handling section breaks (like `h2`), trimming extra passages, skipping short passages, and excluding SVG content.

**3. Identifying Key Functionality and Relationships:**

Based on the tests, I can infer the core functionality of `InnerTextBuilder` and `InnerTextPassagesBuilder`:

* **`InnerTextBuilder`:**
    * Extracts the textual content of an HTML element.
    * Handles `iframes` by representing them as separate frame segments.
    * Respects same-origin policy when processing `iframes`.
    * Identifies and segments different types of content (text, node locations, frames).

* **`InnerTextPassagesBuilder`:**
    * Builds upon `InnerTextBuilder` to further segment the text content into "passages".
    * Takes parameters to control the size and number of these passages.
    * Handles whitespace normalization.
    * Can greedily aggregate text from sibling nodes (with certain restrictions).
    * Excludes content from certain HTML elements that are typically not considered part of the main textual content.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Now I think about how this relates to the core web technologies:

* **HTML:** The tests directly manipulate HTML structures (elements, text nodes, iframes). The builders are clearly designed to process HTML content. The examples in the tests serve as good illustrations.

* **CSS:** While CSS isn't directly tested for *content extraction*, the test that excludes `<style>` tags shows an awareness of CSS's role. CSS dictates presentation, not core content. This exclusion makes sense for extracting the "inner text".

* **JavaScript:** The connection isn't as direct in these *unit tests*. However, I know that in a browser, JavaScript often interacts with the DOM (Document Object Model), which is what these builders operate on. JavaScript could trigger changes that necessitate re-extraction of inner text. I also consider that JavaScript might *use* the output of these builders for various purposes (e.g., indexing, search, accessibility).

**5. Logical Reasoning and Examples:**

For the passage chunking, I consider the logic behind the parameters. For instance:

* **Assumption:**  `max_words_per_aggregate_passage` limits how much text from adjacent elements is combined.
* **Example:** If the limit is 5 and two adjacent `<p>` tags have "This is a short paragraph" and "And this is another", they might be combined. But if the first paragraph were longer, they wouldn't be.

I also think about the "greedy aggregation" and how section breaks prevent it. This suggests a logic where certain structural elements indicate a thematic break.

**6. Identifying Potential User/Programming Errors:**

I consider how someone might misuse or misunderstand this functionality:

* **Forgetting Same-Origin:** A common mistake is expecting the content of cross-origin iframes to be included, which these builders intentionally avoid for security reasons.
* **Misconfiguring Chunking Parameters:**  Setting `max_words_per_aggregate_passage` too low could lead to excessive fragmentation. Setting `min_words_per_passage` too high might result in important content being skipped.
* **Assuming All Text is Included:** Users might not realize that elements like `<style>` or `<script>` are excluded by default.

**7. Tracing User Operations (Debugging Clues):**

I think about how a user action could lead to this code being executed:

* **Page Load:** When a webpage loads, the browser needs to understand its content. This could involve extracting inner text for indexing, accessibility features, or other internal processes.
* **JavaScript Interaction:**  JavaScript might trigger a request to get the inner text of a specific element. For example, a script might want to analyze the text content for sentiment analysis or keyword extraction.
* **Browser Features:** Features like "Reader Mode" or "Copy Text" likely rely on logic similar to these builders to extract the relevant textual content.

**8. Iteration and Refinement:**

After the initial pass, I reread the code and my analysis to ensure accuracy and completeness. I look for any nuances or edge cases I might have missed. For example, the comment about `NodeLocation` in the `Basic` test is something I'd make sure to include in the explanation.

This structured approach allows me to systematically analyze the code, understand its purpose, connect it to broader web technologies, and identify potential use cases and pitfalls.
这个文件 `inner_text_builder_unittest.cc` 是 Chromium Blink 引擎中 `content_extraction` 模块的一部分，专门用于测试 `InnerTextBuilder` 和 `InnerTextPassagesBuilder` 类的功能。

**主要功能：**

1. **测试 `InnerTextBuilder`:**
   - 验证 `InnerTextBuilder` 类能够正确地提取 HTML 元素的内部文本内容，包括处理嵌套的 `iframe` 元素。
   - 确认在处理 `iframe` 时，能将子 frame 的内容作为单独的 `InnerTextFrame` 结构返回。
   - 测试跨域 `iframe` 的处理，确认其内容不会被包含在父 frame 的文本中。

2. **测试 `InnerTextPassagesBuilder`:**
   - 验证 `InnerTextPassagesBuilder` 类能够根据给定的参数（例如最大单词数、是否贪婪地聚合兄弟节点、最大段落数、最小单词数）将 HTML 内容分割成多个文本段落 (passages)。
   - 测试对各种 HTML 结构和文本内容的分割效果，包括处理空格、换行符、HTML 实体编码、Unicode 字符等。
   - 确认 `InnerTextPassagesBuilder` 能正确地排除某些标签（如 `<style>`, `<script>`, `title>`, 注释等）的内容。
   - 测试贪婪聚合兄弟节点的功能，即在不超过最大单词数限制的情况下，将相邻的文本节点合并到一个段落中。
   - 验证对段落数量和最小单词数的限制是否生效。
   - 测试是否正确排除了 SVG 元素的内容。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:** `InnerTextBuilder` 和 `InnerTextPassagesBuilder` 的核心功能是解析和提取 HTML 内容。测试用例中大量使用了 HTML 字符串作为输入，例如：
    ```c++
    frame_test_helpers::LoadHTMLString(
        helper.LocalMainFrame(),
        "<body>container<iframe id='x'>iframe</iframe>after</body>",
        url_test_helpers::ToKURL("http://foobar.com"));
    ```
    这个 HTML 字符串包含了文本内容 (`container`, `after`) 和一个 `iframe` 元素。测试验证了 `InnerTextBuilder` 能正确识别并处理这些元素。

* **JavaScript:**  虽然这个单元测试文件本身是用 C++ 编写的，但 `InnerTextBuilder` 和 `InnerTextPassagesBuilder` 的功能最终会被 JavaScript 使用。例如，JavaScript 可以调用浏览器提供的 API 来获取元素的内部文本，而这些 API 的底层实现就可能用到类似 `InnerTextBuilder` 的逻辑。
    * **举例:** 假设有一个 JavaScript 函数想要提取网页中所有段落的文本内容并进行分析。浏览器内核会使用类似 `InnerTextBuilder` 的机制来高效地提取这些文本。

* **CSS:**  `InnerTextPassagesBuilder` 的测试用例中包含了对 `<style>` 标签的排除，这表明该功能考虑了 CSS 的存在，并决定不将样式标签内的内容视为正文内容。
    * **举例:** 考虑以下 HTML：
      ```html
      <p>This is some text.</p>
      <style> p { color: red; } </style>
      <p>More text.</p>
      ```
      `InnerTextPassagesBuilder` 在提取文本时，会包含 "This is some text." 和 "More text."，但会排除 `<style>` 标签内的 " p { color: red; } "。这保证了提取的文本是页面的实际内容，而不是样式信息。

**逻辑推理、假设输入与输出：**

**测试用例： `InnerTextBuilderTest.Basic`**

* **假设输入 HTML:** `"<body>container<iframe id='x'>iframe</iframe>after</body>"`
* **逻辑推理:** `InnerTextBuilder` 应该遍历 DOM 树，识别文本节点和 `iframe` 元素。文本节点的内容直接提取，`iframe` 元素会被标记为一个单独的 frame。
* **预期输出:** 一个包含四个片段的 `InnerTextFrame` 对象：
    - 第一个片段是文本 "container"。
    - 第二个片段是 `iframe` 节点的 location 信息。
    - 第三个片段是一个 `InnerTextFrame` 对象，代表子 `iframe` 的内容（在这个测试中子 `iframe` 没有加载内容，所以它的 `segments` 可能是空的或包含默认信息）。
    - 第四个片段是文本 "after"。

**测试用例： `InnerTextBuilderTest.InnerTextPassagesChunksSingleTextBlock`**

* **假设输入 HTML:** `<p>Here is a paragraph.</p>`， `max_words_per_aggregate_passage = 10`, `greedily_aggregate_sibling_nodes = false`, `max_passages = 0`, `min_words_per_passage = 0`。
* **逻辑推理:** 因为只有一个文本块，且最大单词数足够大，所以整个段落应该被作为一个单独的 passage 返回。
* **预期输出:**  一个包含一个文本片段的 `InnerTextFrame` 对象，该片段的文本内容是 "Here is a paragraph."。

**用户或编程常见的使用错误及举例说明：**

1. **错误地期望包含跨域 `iframe` 的内容：**
   - **情景:** 用户使用 JavaScript 获取一个包含跨域 `iframe` 的元素的内部文本，并期望能获取到 `iframe` 内部的文本。
   - **代码示例 (JavaScript):**
     ```javascript
     const element = document.getElementById('main-container');
     const innerText = element.innerText; // 或者 element.textContent
     console.log(innerText);
     ```
   - **问题:** 由于安全限制，浏览器不会默认允许跨域访问 `iframe` 的内容。`InnerTextBuilder` 的测试也验证了这一点。用户可能会因此得不到他们期望的完整文本。

2. **误解 `InnerTextPassagesBuilder` 的分段逻辑：**
   - **情景:** 开发者期望 `InnerTextPassagesBuilder` 严格按照 HTML 标签进行分段，而忽略了 `max_words_per_aggregate_passage` 和 `greedily_aggregate_sibling_nodes` 参数的影响。
   - **代码理解错误 (假设存在这样的 JS API):**
     ```javascript
     // 假设有这样的 API，实际不存在
     const passages = getInnerTextPassages(element, { maxWords: 5 });
     ```
   - **问题:** 如果 `greedily_aggregate_sibling_nodes` 为 true，即使两个段落是不同的 `<p>` 标签，但如果它们的总字数不超过 `maxWords`，也可能被合并成一个 passage。开发者如果没有理解这一点，可能会得到与预期不同的分段结果。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户访问网页:** 用户在浏览器中打开一个网页。
2. **浏览器解析 HTML:** Blink 引擎开始解析网页的 HTML 结构，构建 DOM 树。
3. **触发内容提取:** 某些浏览器功能或扩展可能会触发内容提取操作。这可能包括：
   - **辅助功能服务:** 屏幕阅读器等工具需要提取页面的文本内容。
   - **浏览器内置功能:**  "阅读模式" 或 "复制为纯文本" 等功能。
   - **扩展程序:**  一些浏览器扩展程序会分析页面内容，例如用于信息提取、翻译等。
4. **调用 `InnerTextBuilder` 或 `InnerTextPassagesBuilder`:**  当需要提取元素的内部文本时，Blink 引擎可能会调用 `InnerTextBuilder` 来获取包含 frame 信息的结构化文本，或者调用 `InnerTextPassagesBuilder` 来获取分段后的文本。
5. **单元测试作为调试线索:** 如果在上述过程中发现提取的文本内容不正确，例如：
   - 跨域 `iframe` 的内容被意外包含。
   - 文本分段不符合预期。
   - 某些应该排除的标签内容被包含进来。
   那么，开发人员可能会查看 `inner_text_builder_unittest.cc` 中的相关测试用例，来理解 `InnerTextBuilder` 和 `InnerTextPassagesBuilder` 的预期行为。这些测试用例覆盖了各种场景，可以帮助开发人员定位问题，例如：
   - 检查是否有针对跨域 `iframe` 的处理逻辑错误。
   - 验证分段参数的设置是否正确传递和生效。
   - 确认排除标签的逻辑是否按预期工作。

总而言之，`inner_text_builder_unittest.cc` 是保证 Blink 引擎正确提取网页文本内容的关键组成部分，它通过大量的单元测试覆盖了各种边界情况和使用场景，确保了内容提取功能的稳定性和准确性，而这对于很多依赖于网页内容分析的功能至关重要。

### 提示词
```
这是目录为blink/renderer/modules/content_extraction/inner_text_builder_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/content_extraction/inner_text_builder.h"

#include "base/test/metrics/histogram_tester.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/forms/form_controller.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/parser/html_construction_site.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {
namespace {

TEST(InnerTextBuilderTest, Basic) {
  test::TaskEnvironment task_environment;
  frame_test_helpers::WebViewHelper helper;
  helper.Initialize();
  // ScopedNullExecutionContext execution_context;
  ASSERT_TRUE(helper.LocalMainFrame());
  frame_test_helpers::LoadHTMLString(
      helper.LocalMainFrame(),
      "<body>container<iframe id='x'>iframe</iframe>after</body>",
      url_test_helpers::ToKURL("http://foobar.com"));
  auto iframe = helper.LocalMainFrame()->GetDocument().GetElementById("x");
  ASSERT_FALSE(iframe.IsNull());
  mojom::blink::InnerTextParams params;
  params.node_id = iframe.GetDomNodeId();
  auto frame =
      InnerTextBuilder::Build(*helper.LocalMainFrame()->GetFrame(), params);
  ASSERT_TRUE(frame);
  ASSERT_EQ(4u, frame->segments.size());
  ASSERT_TRUE(frame->segments[0]->is_text());
  EXPECT_EQ("container", frame->segments[0]->get_text());
  ASSERT_TRUE(frame->segments[1]->is_node_location());
  ASSERT_TRUE(frame->segments[2]->is_frame());
  const mojom::blink::InnerTextFramePtr& child_frame =
      frame->segments[2]->get_frame();
  HTMLIFrameElement* html_iframe =
      DynamicTo<HTMLIFrameElement>(iframe.Unwrap<Node>());
  EXPECT_EQ(html_iframe->contentDocument()->GetFrame()->GetLocalFrameToken(),
            child_frame->token);
  EXPECT_TRUE(frame->segments[3]->is_text());
  EXPECT_EQ("after", frame->segments[3]->get_text());
}

TEST(InnerTextBuilderTest, MultiFrames) {
  test::TaskEnvironment task_environment;
  frame_test_helpers::WebViewHelper helper;
  std::string base_url("http://internal.test/");
  url_test_helpers::RegisterMockedURLLoadFromBase(WebString::FromUTF8(base_url),
                                                  test::CoreTestDataPath(),
                                                  "inner_text_test1.html");
  url_test_helpers::RegisterMockedURLLoadFromBase(WebString::FromUTF8(base_url),
                                                  test::CoreTestDataPath(),
                                                  "subframe-a.html");
  url_test_helpers::RegisterMockedURLLoadFromBase(WebString::FromUTF8(base_url),
                                                  test::CoreTestDataPath(),
                                                  "subframe-b.html");
  url_test_helpers::RegisterMockedURLLoadFromBase(WebString::FromUTF8(base_url),
                                                  test::CoreTestDataPath(),
                                                  "subframe-d.html");
  helper.InitializeAndLoad(base_url + "inner_text_test1.html");

  auto web_iframe_d =
      helper.LocalMainFrame()->GetDocument().GetElementById("d");
  ASSERT_FALSE(web_iframe_d.IsNull());
  HTMLIFrameElement* iframe_d =
      DynamicTo<HTMLIFrameElement>(web_iframe_d.Unwrap<Node>());
  ASSERT_TRUE(iframe_d);
  mojom::blink::InnerTextParams params;
  params.node_id = iframe_d->contentDocument()
                       ->getElementById(AtomicString("bold"))
                       ->GetDomNodeId();

  auto frame =
      InnerTextBuilder::Build(*helper.LocalMainFrame()->GetFrame(), params);
  ASSERT_TRUE(frame);

  ASSERT_EQ(7u, frame->segments.size());
  ASSERT_TRUE(frame->segments[0]->is_text());
  EXPECT_EQ("A", frame->segments[0]->get_text());
  ASSERT_TRUE(frame->segments[1]->is_frame());
  // NOTE: the nesting in this function is intended to indicate a child frame.
  // It is purely for readability.
  {
    const mojom::blink::InnerTextFramePtr& frame_1 =
        frame->segments[1]->get_frame();
    ASSERT_EQ(1u, frame_1->segments.size());
    ASSERT_TRUE(frame_1->segments[0]->is_text());
    EXPECT_EQ("a", frame_1->segments[0]->get_text());
  }
  ASSERT_TRUE(frame->segments[2]->is_text());
  EXPECT_EQ("B C", frame->segments[2]->get_text());
  ASSERT_TRUE(frame->segments[3]->is_frame());
  {
    const mojom::blink::InnerTextFramePtr& frame_2 =
        frame->segments[3]->get_frame();
    ASSERT_EQ(2u, frame_2->segments.size());
    EXPECT_EQ("b ", frame_2->segments[0]->get_text());
    ASSERT_TRUE(frame_2->segments[1]->is_frame());
    {
      const mojom::blink::InnerTextFramePtr& frame_2_1 =
          frame_2->segments[1]->get_frame();
      ASSERT_EQ(1u, frame_2_1->segments.size());
      ASSERT_TRUE(frame_2_1->segments[0]->is_text());
      EXPECT_EQ("a", frame_2_1->segments[0]->get_text());
    }
  }
  ASSERT_TRUE(frame->segments[4]->is_text());
  EXPECT_EQ("D E", frame->segments[4]->get_text());
  ASSERT_TRUE(frame->segments[5]->is_frame());
  {
    const mojom::blink::InnerTextFramePtr& frame_3 =
        frame->segments[5]->get_frame();
    ASSERT_EQ(3u, frame_3->segments.size());
    ASSERT_TRUE(frame_3->segments[0]->is_text());
    EXPECT_EQ("e", frame_3->segments[0]->get_text());
    EXPECT_TRUE(frame_3->segments[1]->is_node_location());
    ASSERT_TRUE(frame_3->segments[2]->is_text());
    EXPECT_EQ("hello", frame_3->segments[2]->get_text());
  }
  ASSERT_TRUE(frame->segments[6]->is_text());
  EXPECT_EQ("F", frame->segments[6]->get_text());
}

TEST(InnerTextBuilderTest, DifferentOrigin) {
  test::TaskEnvironment task_environment;
  frame_test_helpers::WebViewHelper helper;
  std::string base_url("http://internal.test/");
  url_test_helpers::RegisterMockedURLLoadFromBase(WebString::FromUTF8(base_url),
                                                  test::CoreTestDataPath(),
                                                  "inner_text_test2.html");
  url_test_helpers::RegisterMockedURLLoadFromBase(
      WebString::FromUTF8("http://different-host.com/"),
      test::CoreTestDataPath(), "subframe-a.html");
  helper.InitializeAndLoad(base_url + "inner_text_test2.html");

  auto frame =
      InnerTextBuilder::Build(*helper.LocalMainFrame()->GetFrame(), {});

  // The child frame should not be included as it's not same-origin.
  ASSERT_TRUE(frame);
  ASSERT_EQ(1u, frame->segments.size());
  ASSERT_TRUE(frame->segments[0]->is_text());
  EXPECT_EQ("XY", frame->segments[0]->get_text());
}

////////////////////////////////////////////////////////////////////////////////

void ExpectChunkerResult(int max_words_per_aggregate_passage,
                         bool greedily_aggregate_sibling_nodes,
                         int max_passages,
                         int min_words_per_passage,
                         const std::string& html,
                         const std::vector<String>& expected_passages) {
  test::TaskEnvironment task_environment;
  frame_test_helpers::WebViewHelper helper;
  helper.Initialize();
  ASSERT_TRUE(helper.LocalMainFrame());
  frame_test_helpers::LoadHTMLString(
      helper.LocalMainFrame(), html,
      url_test_helpers::ToKURL("http://foobar.com"));
  ASSERT_TRUE(helper.LocalMainFrame());

  mojom::blink::InnerTextParams params;
  params.max_words_per_aggregate_passage = max_words_per_aggregate_passage;
  params.greedily_aggregate_sibling_nodes = greedily_aggregate_sibling_nodes;
  params.max_passages = max_passages;
  params.min_words_per_passage = min_words_per_passage;

  mojom::blink::InnerTextFramePtr frame = InnerTextPassagesBuilder::Build(
      *helper.LocalMainFrame()->GetFrame(), params);
  ASSERT_TRUE(frame);
  std::vector<String> result_passages;
  for (auto& segment : frame->segments) {
    ASSERT_TRUE(segment->is_text());
    result_passages.push_back(segment->get_text());
  }

  EXPECT_EQ(result_passages, expected_passages);
}

TEST(InnerTextBuilderTest, InnerTextPassagesChunksSingleTextBlock) {
  std::string html = "<p>Here is a paragraph.</p>";
  ExpectChunkerResult(10, false, 0, 0, html,
                      {
                          "Here is a paragraph.",
                      });
}

TEST(InnerTextBuilderTest, InnerTextPassagesHandlesEscapeCodes) {
  std::string html = "<p>Here&#39;s a paragraph.</p>";
  ExpectChunkerResult(10, false, 0, 0, html,
                      {
                          "Here's a paragraph.",
                      });
}

TEST(InnerTextBuilderTest, InnerTextPassagesHandlesUnicodeCharacters) {
  std::string html =
      "<p>Here is a "
      "\u2119\u212b\u213e\u212b\u210A\u213e\u212b\u2119\u210F.</p>";
  ExpectChunkerResult(10, false, 0, 0, html,
                      {
                          u"Here is a ℙÅℾÅℊℾÅℙℏ.",
                      });
}

TEST(InnerTextBuilderTest, InnerTextPassagesHandlesByteString) {
  std::string html =
      "<p>Here is a "
      "\xe2\x84\x99\xe2\x84\xab\xe2\x84\xbe\xe2\x84\xab\xe2\x84\x8a\xe2\x84\xbe"
      "\xe2\x84\xab\xe2\x84\x99\xe2\x84\x8f.</p>";
  ExpectChunkerResult(10, false, 0, 0, html,
                      {
                          u"Here is a ℙÅℾÅℊℾÅℙℏ.",
                      });
}

TEST(InnerTextBuilderTest, InnerTextPassagesStripsWhitespaceAroundNodeText) {
  std::string html = R"(
      <div>
        <p>     )"
                     "\t"
                     R"(Here is a paragraph.)"
                     "\n"
                     R"(And another.)"
                     "\n"
                     R"(

        </p>
        <p>)"
                     "\t\n"
                     R"(

        </p>
        <p>And more.
        </p>
      </div>
      )";
  ExpectChunkerResult(
      8, false, 0, 0, html,
      {
          // Note, the newline is included in whitespace simplification.
          "Here is a paragraph. And another. And more.",
      });

  // Additional testing of whitespace handling on edges. Here the word count
  // will exceed the limit and create two separate passages.
  EXPECT_EQ(String(" And more.").SimplifyWhiteSpace(), "And more.");
  EXPECT_EQ(String("And more. ").SimplifyWhiteSpace(), "And more.");
  EXPECT_EQ(String(" And  more. ").SimplifyWhiteSpace(), "And more.");
  ExpectChunkerResult(7, false, 0, 0, html,
                      {
                          "Here is a paragraph. And another.",
                          "And more.",
                      });
}

TEST(InnerTextBuilderTest, InnerTextPassagesHandlesEmptyDomElements) {
  std::string html = "<div><p></p></div>";
  ExpectChunkerResult(10, false, 0, 0, html, {});
}

TEST(InnerTextBuilderTest, InnerTextPassagesChunksMultipleHtmlBlocks) {
  std::string html = R"(
      <div>
        <div>First level one.
          <div>Second level one.
            <div>
              <p>Third level one.</p><p>Third level two.</p>
              <span>Third level three.</span>
            </div>
          </div>
        </div>
        <div>First level two.
        </div>
      </div>
  )";
  ExpectChunkerResult(
      10, false, 0, 0, html,
      {
          "First level one.",
          "Second level one.",
          "Third level one. Third level two. Third level three.",
          "First level two.",
      });
}

TEST(InnerTextBuilderTest,
     InnerTextPassagesIncludesNodesOverMaxAggregateChunkSize) {
  std::string html = R"(
      <div>
        <div>First level one.
          <div>Second level one.
            <div>
              <p>Third level one.</p><p>Third level two.</p>
              <span>Third level three but now it's over the max aggregate chunk size alone.</span>
            </div>
          </div>
        </div>
        <div>First level two.
        </div>
      </div>
  )";
  ExpectChunkerResult(10, false, 0, 0, html,
                      {
                          "First level one.",
                          "Second level one.",
                          "Third level one.",
                          "Third level two.",
                          "Third level three but now it's over the max "
                          "aggregate chunk size alone.",
                          "First level two.",
                      });
}

TEST(InnerTextBuilderTest, InnerTextPassagesJoinsSplitTextNodesWithinPTag) {
  std::string html = R"(
      <p>Paragraph one with
          <a>link</a>
          and more.
      </p>
  )";
  ExpectChunkerResult(10, false, 0, 0, html,
                      {
                          "Paragraph one with link and more.",
                      });
}

TEST(InnerTextBuilderTest,
     InnerTextPassagesDoesNotJoinSplitTextNodesWithinPTagWhenOverMax) {
  std::string html = R"(
      <p>Paragraph one with
          <a>link</a>
          and more.
      </p>
  )";
  ExpectChunkerResult(1, false, 0, 0, html,
                      {
                          "Paragraph one with",
                          "link",
                          "and more.",
                      });
}

TEST(InnerTextBuilderTest, InnerTextPassagesExcludesTextFromSomeHtmlTags) {
  std::string html = R"(
      <!DOCTYPE html>
      <html>
        <head>
          <title>Title</title>
          <style>.my-tag{display:none}</style>
        <head>
        <body>
          <script type="application/json">{"@context":"https://schema.org"}</script>
          <p><!-- A comment -->Paragraph</p>
        </body>
      </html>
  )";
  ExpectChunkerResult(10, false, 0, 0, html,
                      {
                          "Title Paragraph",
                      });
}

TEST(InnerTextBuilderTest, InnerTextPassagesGreedilyAggregatesSiblingNodes) {
  std::string html = R"(
      <div>
        <div>First level one.
          <div>Second level one.
            <div>
              <p>Third level one.</p>
              <p>Third level two.</p>
              <p>Third level three.
                <span>Fourth level one.</span>
              </p>
              <span>Third level four that's over the max aggregate chunk size alone.</span>
              <p>Third level five.</p>
              <p>Third level six.</p>
            </div>
          </div>
        </div>
        <div>First level two.
          <div>
            <p>Second level two that should be output alone.
            <p>Second level three.
          </div>
        </div>
      </div>
  )";
  ExpectChunkerResult(
      10, true, 0, 0, html,
      {
          "First level one.",
          "Second level one.",
          "Third level one. Third level two.",
          "Third level three. Fourth level one.",
          "Third level four that's over the max aggregate chunk size alone.",
          "Third level five. Third level six.",
          "First level two.",
          "Second level two that should be output alone.",
          "Second level three.",
      });
}

TEST(InnerTextBuilderTest,
     InnerTextPassagesDoesNotGreedilyAggregateAcrossSectionBreaks) {
  // The first div should all be combined into a single passage since under
  // max words. The second div is over max words so should be split, and
  // because of the <h2> tag, "Header two" should not be greedily combined with
  // "Paragraph three" and instead combines with "Paragraph four". The third
  // div is the same as the second except the header is changed to a paragraph,
  // allowing it ("Paragraph six") to be combined with "Paragraph five".
  std::string html = R"(
      <div>
        <p>Paragraph one with
          <a>link</a>
          and more.
        </p>
        <h2>Header one</h2>
        <p>Paragraph two.
      </div>
      <div>
        <p>Paragraph three with
          <a>link</a>
          and more.
        </p>
        <h2>Header two</h2>
        <p>Paragraph four that puts entire div over length.</p>
      </div>
      <div>
        <p>Paragraph five with
          <a>link</a>
          and more.
        </p>
        <p>Paragraph six.</p>
        <p>Paragraph seven that puts entire div over length.</p>
      </div>
  )";
  ExpectChunkerResult(
      10, true, 0, 0, html,
      {
          "Paragraph one with link and more. Header one Paragraph two.",
          "Paragraph three with link and more.",
          "Header two Paragraph four that puts entire div over length.",
          "Paragraph five with link and more. Paragraph six.",
          "Paragraph seven that puts entire div over length.",
      });
}

TEST(InnerTextBuilderTest, InnerTextPassagesTrimsExtraPassages) {
  std::string html = R"(
      <p>paragraph 1</p>
      <p>paragraph 2</p>
      <p>paragraph 3</p>
  )";
  ExpectChunkerResult(3, false, 2, 0, html,
                      {
                          "paragraph 1",
                          "paragraph 2",
                      });
}

TEST(InnerTextBuilderTest, InnerTextPassagesSkipsPassagesTooShort) {
  std::string html = R"(
      <p>an arbitrarily long paragraph</p>
      <p>short paragraph</p>
      <p>another long paragraph</p>
  )";
  ExpectChunkerResult(3, false, 0, 3, html,
                      {
                          "an arbitrarily long paragraph",
                          "another long paragraph",
                      });
}

TEST(InnerTextBuilderTest, InnerTextPassagesDropsShortPassagesAtMaxPassage) {
  std::string html = R"(
      <p>foo bar baz</p>
      <p>foo</p>
      <p>bar</p>
      <p>foo bar baz</p>
  )";
  ExpectChunkerResult(3, false, 2, 3, html,
                      {
                          "foo bar baz",
                          "foo bar baz",
                      });
}

TEST(InnerTextBuilderTest, InnerTextPassagesExcludesSvgElements) {
  std::string html = R"(
      <body>
      <p>foo bar baz</p>
      <svg>
        <defs>defs text is excluded</defs>
        <style>style text is excluded</style>
        <script>script text is excluded</script>
        text within svg
      </svg>
      <p>foo bar baz</p>
      </body>
  )";
  ExpectChunkerResult(10, false, 10, 0, html,
                      {
                          "foo bar baz text within svg foo bar baz",
                      });
}

}  // namespace
}  // namespace blink
```
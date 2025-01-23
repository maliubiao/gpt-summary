Response:
The user wants to understand the functionality of the `styled_markup_serializer_test.cc` file in the Chromium Blink engine. I need to analyze the code and explain its purpose, its relation to web technologies, provide examples, and discuss potential user errors.

**Plan:**

1. **Identify the core functionality:** The file contains unit tests for `StyledMarkupSerializer`.
2. **Explain the purpose of `StyledMarkupSerializer`:** It's responsible for serializing DOM subtrees into HTML markup, preserving styling information.
3. **Relate to web technologies:**
    *   **HTML:**  The serializer generates HTML.
    *   **CSS:** The serializer handles inline styles.
    *   **JavaScript:** While the test itself is in C++, the serializer is used when manipulating the DOM in JavaScript (e.g., `innerHTML`, copy/paste).
4. **Provide examples:**  Use the existing test cases as examples of input and expected output.
5. **Discuss user errors:** Focus on scenarios where the serialization might not produce the expected output, like issues with shadow DOM or invisible elements.
6. **Explain the debugging perspective:** Describe how a developer might end up in this code during debugging.
这个文件 `styled_markup_serializer_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `StyledMarkupSerializer` 类的功能。`StyledMarkupSerializer` 的主要功能是将 DOM 树或其一部分序列化为带有样式的 HTML 标记字符串。

**功能列举:**

1. **测试 `StyledMarkupSerializer` 的基本序列化功能:** 验证在不同 DOM 结构下，`StyledMarkupSerializer` 能否正确地将 DOM 节点（包括文本节点、元素节点等）转换为 HTML 字符串。
2. **测试样式信息的保留:**  验证序列化过程中是否正确地保留了元素的内联样式 (inline styles)。
3. **测试不同类型的 DOM 结构:** 覆盖了各种常见的 HTML 结构，例如：
    *   纯文本内容
    *   块级元素 (`<div>`)
    *   表单控件 (`<input>`, `<select>`, `<textarea>`)
    *   标题元素 (`<h4>`)
    *   内联元素 (`<b>`, `<i>`)
    *   混合嵌套元素
    *   带有 Shadow DOM 的元素
    *   带有 `display: none` 和 `display: contents` 样式的元素
4. **测试不同的序列化策略:**  文件中使用了 `EditingStrategy` 和 `EditingInFlatTreeStrategy` 两种策略，后者涉及到 Shadow DOM 的扁平树结构。这表明测试覆盖了在处理 Shadow DOM 时，序列化行为的不同。
5. **测试序列化范围:** `SerializePart` 函数测试了只序列化 DOM 树的一部分的功能。
6. **测试用于交互的注解 (Annotation for Interchange):** `ShouldAnnotateOptions` 函数相关的测试可能验证了在进行复制粘贴等操作时，序列化器是否添加了特定的注解信息。

**与 JavaScript, HTML, CSS 的关系:**

*   **HTML:** `StyledMarkupSerializer` 的核心功能就是生成 HTML 字符串。测试用例中大量的 `EXPECT_EQ` 断言比较了实际序列化结果和期望的 HTML 字符串。例如，`TEST_F(StyledMarkupSerializerTest, TextOnly)` 测试用例验证了纯文本内容被包裹在带有默认内联样式的 `<span>` 标签中：

    ```c++
    TEST_F(StyledMarkupSerializerTest, TextOnly) {
      const char* body_content = "Hello world!";
      SetBodyContent(body_content);
      const char* expected_result =
          "<span style=\"display: inline !important; float: none;\">Hello "
          "world!</span>";
      EXPECT_EQ(expected_result, Serialize<EditingStrategy>());
      EXPECT_EQ(expected_result, Serialize<EditingInFlatTreeStrategy>());
    }
    ```
    这里，输入的 HTML 内容是 "Hello world!"，经过序列化后，期望的输出是带有默认样式的 `<span>` 标签包裹的字符串。

*   **CSS:**  `StyledMarkupSerializer` 关注元素的内联样式。例如，`TEST_F(StyledMarkupSerializerTest, StyleDisplayNone)` 测试用例验证了当元素具有 `display: none` 样式时，该元素不会被序列化：

    ```c++
    TEST_F(StyledMarkupSerializerTest, StyleDisplayNone) {
      const char* body_content = "<b>00<i style='display:none'>11</i>22</b>";
      SetBodyContent(body_content);
      const char* expected_result = "<b>0022</b>";
      EXPECT_EQ(expected_result, Serialize<EditingStrategy>());
      EXPECT_EQ(expected_result, Serialize<EditingInFlatTreeStrategy>());
    }
    ```
    这里，`<i>11</i>` 元素由于 `style='display:none'` 而被忽略，最终序列化结果只包含 `<b>0022</b>`。

*   **JavaScript:** 虽然这个测试文件本身是用 C++ 编写的，但 `StyledMarkupSerializer` 的功能在 JavaScript 中有着重要的应用。当 JavaScript 代码需要获取或设置元素的 HTML 内容时，例如使用 `element.innerHTML` 属性，或者在进行复制粘贴操作时，Blink 引擎内部会使用类似的序列化机制。例如，当你用 JavaScript 读取一个带有内联样式的元素的 `innerHTML` 时，你看到的字符串就是经过类似 `StyledMarkupSerializer` 处理后的结果。

**逻辑推理的假设输入与输出:**

*   **假设输入:**  一个包含内联样式的 `<div>` 元素： `<div style="color: blue; font-size: 16px;">This is blue text.</div>`
*   **预期输出:**  序列化后的 HTML 字符串应该保留这些内联样式： `<div style="color: blue; font-size: 16px;">This is blue text.</div>` （在简单情况下，可能会有属性顺序或引号的细微差异，但核心样式信息会被保留）。

*   **假设输入 (带有 Shadow DOM):**
    ```html
    <my-element id="host">Some text</my-element>
    <script>
      const shadowRoot = document.getElementById('host').attachShadow({mode: 'open'});
      shadowRoot.innerHTML = '<span><slot></slot></span>';
    </script>
    ```
*   **预期输出 (使用 `EditingInFlatTreeStrategy`):**  序列化结果会包含 Shadow DOM 的结构： `<my-element id="host"><span><slot>Some text</slot></span></my-element>`

**用户或编程常见的使用错误举例:**

1. **错误地假设 `textarea` 的内容会被序列化:**  从 `TEST_F(StyledMarkupSerializerTest, FormControlTextArea)` 可以看出，`textarea` 元素的内容在序列化时是不会出现的。如果开发者期望获取 `textarea` 的完整内容，他们应该使用 `textarea.value` 属性，而不是依赖于元素的 HTML 序列化。

    ```c++
    TEST_F(StyledMarkupSerializerTest, FormControlTextArea) {
      const char* body_content = "<textarea>foo bar</textarea>";
      SetBodyContent(body_content);
      const char* expected_result = "<textarea></textarea>";
      EXPECT_EQ(expected_result, Serialize<EditingStrategy>())
          << "contents of TEXTAREA element should not be appeared.";
      EXPECT_EQ(expected_result, Serialize<EditingInFlatTreeStrategy>());
    }
    ```
    **用户操作场景:** 用户在一个 `<textarea>` 中输入了一些文本，然后尝试复制包含这个 `<textarea>` 的一部分内容。如果复制逻辑依赖于 HTML 序列化，那么 `textarea` 中的文本内容将不会被包含在复制的 HTML 中。

2. **忽略 `display: none` 元素不会被序列化:**  开发者可能会错误地认为所有 DOM 元素都会被序列化，而忽略了 `display: none` 样式的元素会被排除在外。

    **用户操作场景:**  一个网页中包含一些隐藏的元素（`display: none`）。用户尝试使用“复制元素”之类的开发者工具功能，并期望复制包括这些隐藏元素在内的完整结构。但由于序列化器的行为，隐藏元素可能不会出现在复制的结果中。

3. **对 Shadow DOM 的序列化行为不理解:**  在处理 Shadow DOM 时，不同的序列化策略会产生不同的结果。`EditingStrategy` 倾向于只序列化分布式的节点，而 `EditingInFlatTreeStrategy` 则会包含 Shadow DOM 的结构。开发者如果混淆了这两种策略的行为，可能会得到意料之外的序列化结果。

    **用户操作场景:**  一个使用了 Web Components 和 Shadow DOM 的网页。用户尝试复制一个包含 Shadow DOM 的组件，并期望粘贴到另一个地方时能保留其内部结构。如果复制逻辑使用的是不包含 Shadow DOM 的序列化策略，那么粘贴的结果可能只是组件的外部标签，而丢失了内部的 Shadow DOM 结构。

**用户操作是如何一步步到达这里的，作为调试线索:**

假设开发者在开发 Chromium 浏览器或基于 Chromium 的应用时，遇到了与复制粘贴功能相关的问题，特别是涉及到带有样式的文本或包含 Shadow DOM 的内容：

1. **用户报告或开发者发现复制粘贴行为异常:** 例如，复制带有特定样式的文本后，粘贴到目标位置时样式丢失或不正确。或者，复制一个包含 Shadow DOM 的自定义元素后，粘贴到另一个地方时结构不完整。
2. **开始调试:** 开发者可能会首先检查与剪贴板交互相关的代码，以及处理复制和粘贴事件的代码。
3. **定位到 DOM 序列化部分:**  在复制操作中，需要将选中的 DOM 结构转换为某种格式（通常是 HTML）放入剪贴板。开发者可能会追踪代码，发现涉及到将 DOM 节点序列化为字符串的过程。
4. **进入 `StyledMarkupSerializer` 的相关代码:**  由于问题涉及到样式信息的保留，开发者很可能会关注负责处理样式信息的序列化器，即 `StyledMarkupSerializer`。
5. **查看测试用例 (`styled_markup_serializer_test.cc`):**  为了理解 `StyledMarkupSerializer` 的具体行为，开发者会查看它的单元测试。这些测试用例覆盖了各种场景，可以帮助开发者了解在不同情况下，DOM 结构是如何被序列化的，以及样式信息是否被正确保留。通过分析测试用例，开发者可以更好地理解序列化器的预期行为，并对比实际的序列化结果，从而找到问题所在。例如，如果发现粘贴后 `textarea` 的内容丢失，开发者可能会查看 `FormControlTextArea` 测试用例，确认这是预期的行为。如果 Shadow DOM 的结构丢失，开发者可能会关注包含 `EditingInFlatTreeStrategy` 的测试用例。

总而言之，`styled_markup_serializer_test.cc` 文件是理解和验证 Blink 引擎中 DOM 序列化功能的重要资源，特别是涉及到样式信息和 Shadow DOM 的处理。通过分析这些测试用例，开发者可以更好地理解序列化器的行为，并排查与之相关的问题。

### 提示词
```
这是目录为blink/renderer/core/editing/serializers/styled_markup_serializer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/serializers/styled_markup_serializer.h"

#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"

namespace blink {

// Returns the first mismatching index in |input1| and |input2|.
static size_t Mismatch(const std::string& input1, const std::string& input2) {
  size_t index = 0;
  for (auto char1 : input1) {
    if (index == input2.size() || char1 != input2[index])
      return index;
    ++index;
  }
  return input1.size();
}

// This is smoke test of |StyledMarkupSerializer|. Full testing will be done
// in web tests.
class StyledMarkupSerializerTest : public EditingTestBase {
 protected:
  CreateMarkupOptions ShouldAnnotateOptions() const {
    return CreateMarkupOptions::Builder()
        .SetShouldAnnotateForInterchange(true)
        .Build();
  }

  template <typename Strategy>
  std::string Serialize(
      const CreateMarkupOptions& options = CreateMarkupOptions());

  template <typename Strategy>
  std::string SerializePart(
      const PositionTemplate<Strategy>& start,
      const PositionTemplate<Strategy>& end,
      const CreateMarkupOptions& options = CreateMarkupOptions());
};

template <typename Strategy>
std::string StyledMarkupSerializerTest::Serialize(
    const CreateMarkupOptions& options) {
  PositionTemplate<Strategy> start =
      PositionTemplate<Strategy>::FirstPositionInNode(*GetDocument().body());
  PositionTemplate<Strategy> end =
      PositionTemplate<Strategy>::LastPositionInNode(*GetDocument().body());
  return CreateMarkup(start, end, options).Utf8();
}

template <typename Strategy>
std::string StyledMarkupSerializerTest::SerializePart(
    const PositionTemplate<Strategy>& start,
    const PositionTemplate<Strategy>& end,
    const CreateMarkupOptions& options) {
  return CreateMarkup(start, end, options).Utf8();
}

TEST_F(StyledMarkupSerializerTest, TextOnly) {
  const char* body_content = "Hello world!";
  SetBodyContent(body_content);
  const char* expected_result =
      "<span style=\"display: inline !important; float: none;\">Hello "
      "world!</span>";
  EXPECT_EQ(expected_result, Serialize<EditingStrategy>());
  EXPECT_EQ(expected_result, Serialize<EditingInFlatTreeStrategy>());
}

TEST_F(StyledMarkupSerializerTest, BlockFormatting) {
  const char* body_content = "<div>Hello world!</div>";
  SetBodyContent(body_content);
  EXPECT_EQ(body_content, Serialize<EditingStrategy>());
  EXPECT_EQ(body_content, Serialize<EditingInFlatTreeStrategy>());
}

TEST_F(StyledMarkupSerializerTest, FormControlInput) {
  const char* body_content = "<input value='foo'>";
  SetBodyContent(body_content);
  const char* expected_result = "<input value=\"foo\">";
  EXPECT_EQ(expected_result, Serialize<EditingStrategy>());
  EXPECT_EQ(expected_result, Serialize<EditingInFlatTreeStrategy>());
}

TEST_F(StyledMarkupSerializerTest, FormControlInputRange) {
  const char* body_content = "<input type=range>";
  SetBodyContent(body_content);
  const char* expected_result = "<input type=\"range\">";
  EXPECT_EQ(expected_result, Serialize<EditingStrategy>());
  EXPECT_EQ(expected_result, Serialize<EditingInFlatTreeStrategy>());
}

TEST_F(StyledMarkupSerializerTest, FormControlSelect) {
  const char* body_content =
      "<select><option value=\"1\">one</option><option "
      "value=\"2\">two</option></select>";
  SetBodyContent(body_content);
  EXPECT_EQ(body_content, Serialize<EditingStrategy>());
  EXPECT_EQ(body_content, Serialize<EditingInFlatTreeStrategy>());
}

TEST_F(StyledMarkupSerializerTest, FormControlTextArea) {
  const char* body_content = "<textarea>foo bar</textarea>";
  SetBodyContent(body_content);
  const char* expected_result = "<textarea></textarea>";
  EXPECT_EQ(expected_result, Serialize<EditingStrategy>())
      << "contents of TEXTAREA element should not be appeared.";
  EXPECT_EQ(expected_result, Serialize<EditingInFlatTreeStrategy>());
}

TEST_F(StyledMarkupSerializerTest, HeadingFormatting) {
  const char* body_content = "<h4>Hello world!</h4>";
  SetBodyContent(body_content);
  EXPECT_EQ(body_content, Serialize<EditingStrategy>());
  EXPECT_EQ(body_content, Serialize<EditingInFlatTreeStrategy>());
}

TEST_F(StyledMarkupSerializerTest, InlineFormatting) {
  const char* body_content = "<b>Hello world!</b>";
  SetBodyContent(body_content);
  EXPECT_EQ(body_content, Serialize<EditingStrategy>());
  EXPECT_EQ(body_content, Serialize<EditingInFlatTreeStrategy>());
}

TEST_F(StyledMarkupSerializerTest, Mixed) {
  const char* body_content = "<i>foo<b>bar</b>baz</i>";
  SetBodyContent(body_content);
  EXPECT_EQ(body_content, Serialize<EditingStrategy>());
  EXPECT_EQ(body_content, Serialize<EditingInFlatTreeStrategy>());
}

TEST_F(StyledMarkupSerializerTest, ShadowTreeDistributeOrder) {
  const char* body_content =
      "<p id=\"host\">00<b slot='#one' id=\"one\">11</b><b slot='#two' "
      "id=\"two\">22</b>33</p>";
  const char* shadow_content =
      "<a><slot name='#two'></slot><slot name='#one'></slot></a>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");
  EXPECT_EQ(
      "<p id=\"host\"><b slot=\"#one\" id=\"one\">11</b><b slot=\"#two\" "
      "id=\"two\">22</b></p>",
      Serialize<EditingStrategy>())
      << "00 and 33 aren't appeared since they aren't distributed.";
  EXPECT_EQ(
      "<p id=\"host\"><a><slot name=\"#two\"><b slot=\"#two\" "
      "id=\"two\">22</b></slot><slot name=\"#one\"><b slot=\"#one\" "
      "id=\"one\">11</b></slot></a></p>",
      Serialize<EditingInFlatTreeStrategy>())
      << "00 and 33 aren't appeared since they aren't distributed.";
}

TEST_F(StyledMarkupSerializerTest, ShadowTreeInput) {
  const char* body_content =
      "<p id=\"host\">00<b slot='#one' id=\"one\">11</b><b slot='#two' "
      "id=\"two\"><input value=\"22\"></b>33</p>";
  const char* shadow_content =
      "<a><slot name='#two'></slot><slot name='#one'></slot></a>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");
  EXPECT_EQ(
      "<p id=\"host\"><b slot=\"#one\" id=\"one\">11</b><b slot=\"#two\" "
      "id=\"two\"><input value=\"22\"></b></p>",
      Serialize<EditingStrategy>())
      << "00 and 33 aren't appeared since they aren't distributed.";
  EXPECT_EQ(
      "<p id=\"host\"><a><slot name=\"#two\"><b slot=\"#two\" "
      "id=\"two\"><input value=\"22\"></b></slot><slot name=\"#one\"><b "
      "slot=\"#one\" id=\"one\">11</b></slot></a></p>",
      Serialize<EditingInFlatTreeStrategy>())
      << "00 and 33 aren't appeared since they aren't distributed.";
}

TEST_F(StyledMarkupSerializerTest, ShadowTreeNested) {
  const char* body_content =
      "<p id='host'>00<b slot='#one' id='one'>11</b><b slot='#two' "
      "id='two'>22</b>33</p>";
  const char* shadow_content1 =
      "<a><slot name='#two'></slot><span id=host2></span><slot "
      "name='#one'></slot></a>";
  const char* shadow_content2 = "NESTED";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root1 = SetShadowContent(shadow_content1, "host");
  CreateShadowRootForElementWithIDAndSetInnerHTML(*shadow_root1, "host2",
                                                  shadow_content2);

  EXPECT_EQ(
      "<p id=\"host\"><b slot=\"#one\" id=\"one\">11</b><b slot=\"#two\" "
      "id=\"two\">22</b></p>",
      Serialize<EditingStrategy>())
      << "00 and 33 aren't appeared since they aren't distributed.";
  EXPECT_EQ(
      "<p id=\"host\"><a><slot name=\"#two\"><b slot=\"#two\" "
      "id=\"two\">22</b></slot><span id=\"host2\">NESTED</span><slot "
      "name=\"#one\"><b slot=\"#one\" id=\"one\">11</b></slot></a></p>",
      Serialize<EditingInFlatTreeStrategy>())
      << "00 and 33 aren't appeared since they aren't distributed.";
}

TEST_F(StyledMarkupSerializerTest, ShadowTreeInterchangedNewline) {
  const char* body_content = "<span id=host><b slot='#one' id=one>1</b></span>";
  const char* shadow_content = "<slot name='#one'></slot><div><br></div>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");

  std::string result_from_dom_tree =
      Serialize<EditingStrategy>(ShouldAnnotateOptions());
  std::string result_from_flat_tree =
      Serialize<EditingInFlatTreeStrategy>(ShouldAnnotateOptions());
  size_t mismatched_index =
      Mismatch(result_from_dom_tree, result_from_flat_tree);

  // Note: We check difference between DOM tree result and flat tree
  // result, because results contain "style" attribute and this test
  // doesn't care about actual value of "style" attribute.
  EXPECT_EQ("b slot=\"#one\" id=\"one\">1</b></span>",
            result_from_dom_tree.substr(mismatched_index));
  EXPECT_EQ(
      "slot name=\"#one\"><b slot=\"#one\" "
      "id=\"one\">1</b></slot><div><br></div></span><br "
      "class=\"Apple-interchange-newline\">",
      result_from_flat_tree.substr(mismatched_index));
}

TEST_F(StyledMarkupSerializerTest, StyleDisplayNone) {
  const char* body_content = "<b>00<i style='display:none'>11</i>22</b>";
  SetBodyContent(body_content);
  const char* expected_result = "<b>0022</b>";
  EXPECT_EQ(expected_result, Serialize<EditingStrategy>());
  EXPECT_EQ(expected_result, Serialize<EditingInFlatTreeStrategy>());
}

TEST_F(StyledMarkupSerializerTest, StyleDisplayNoneAndNewLines) {
  const char* body_content = "<div style='display:none'>11</div>\n\n";
  SetBodyContent(body_content);
  EXPECT_EQ("", Serialize<EditingStrategy>());
  EXPECT_EQ("", Serialize<EditingInFlatTreeStrategy>());
}

TEST_F(StyledMarkupSerializerTest, ShadowTreeStyle) {
  const char* body_content =
      "<p id='host' style='color: red'><span style='font-weight: bold;'><span "
      "id='one'>11</span></span></p>\n";
  SetBodyContent(body_content);
  Element* one = GetDocument().getElementById(AtomicString("one"));
  auto* text = To<Text>(one->firstChild());
  Position start_dom(text, 0);
  Position end_dom(text, 2);
  const std::string& serialized_dom = SerializePart<EditingStrategy>(
      start_dom, end_dom, ShouldAnnotateOptions());

  body_content =
      "<p id='host' style='color: red'>00<span slot='#one' "
      "id='one'>11</span>22</p>\n";
  const char* shadow_content =
      "<span style='font-weight: bold'><slot name='#one'></slot></span>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");
  one = GetDocument().getElementById(AtomicString("one"));
  text = To<Text>(one->firstChild());
  PositionInFlatTree start_ict(text, 0);
  PositionInFlatTree end_ict(text, 2);
  const std::string& serialized_ict = SerializePart<EditingInFlatTreeStrategy>(
      start_ict, end_ict, ShouldAnnotateOptions());

  EXPECT_EQ(serialized_dom, serialized_ict);
}

// TODO(crbug.com/1157146): This test breaks without Shadow DOM v0.
TEST_F(StyledMarkupSerializerTest, DISABLED_AcrossShadow) {
  const char* body_content =
      "<p id='host1'>[<span id='one'>11</span>]</p><p id='host2'>[<span "
      "id='two'>22</span>]</p>";
  SetBodyContent(body_content);
  Element* one = GetDocument().getElementById(AtomicString("one"));
  Element* two = GetDocument().getElementById(AtomicString("two"));
  Position start_dom(To<Text>(one->firstChild()), 0);
  Position end_dom(To<Text>(two->firstChild()), 2);
  const std::string& serialized_dom = SerializePart<EditingStrategy>(
      start_dom, end_dom, ShouldAnnotateOptions());

  body_content =
      "<p id='host1'><span slot='#one' id='one'>11</span></p><p "
      "id='host2'><span "
      "slot='#two' id='two'>22</span></p>";
  const char* shadow_content1 = "[<slot name='#one'></slot>]";
  const char* shadow_content2 = "[<slot name='#two'></slot>]";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content1, "host1");
  SetShadowContent(shadow_content2, "host2");
  one = GetDocument().getElementById(AtomicString("one"));
  two = GetDocument().getElementById(AtomicString("two"));
  PositionInFlatTree start_ict(To<Text>(one->firstChild()), 0);
  PositionInFlatTree end_ict(To<Text>(two->firstChild()), 2);
  const std::string& serialized_ict = SerializePart<EditingInFlatTreeStrategy>(
      start_ict, end_ict, ShouldAnnotateOptions());

  // TODO(crbug.com/1157146): serialized_ict contains the <slot> elements, while
  // serialized_dom does not.
  EXPECT_EQ(serialized_dom, serialized_ict);
}

TEST_F(StyledMarkupSerializerTest, AcrossInvisibleElements) {
  const char* body_content =
      "<span id='span1' style='display: none'>11</span><span id='span2' "
      "style='display: none'>22</span>";
  SetBodyContent(body_content);
  Element* span1 = GetDocument().getElementById(AtomicString("span1"));
  Element* span2 = GetDocument().getElementById(AtomicString("span2"));
  Position start_dom = Position::FirstPositionInNode(*span1);
  Position end_dom = Position::LastPositionInNode(*span2);
  EXPECT_EQ("", SerializePart<EditingStrategy>(start_dom, end_dom));
  PositionInFlatTree start_ict =
      PositionInFlatTree::FirstPositionInNode(*span1);
  PositionInFlatTree end_ict = PositionInFlatTree::LastPositionInNode(*span2);
  EXPECT_EQ("", SerializePart<EditingInFlatTreeStrategy>(start_ict, end_ict));
}

TEST_F(StyledMarkupSerializerTest, DisplayContentsStyle) {
  const char* body_content = "1<span style='display: contents'>2</span>3";
  const char* expected_result =
      "<span style=\"display: inline !important; float: none;\">1</span><span "
      "style=\"display: contents;\">2</span><span style=\"display: inline "
      "!important; float: none;\">3</span>";
  SetBodyContent(body_content);
  EXPECT_EQ(expected_result, Serialize<EditingStrategy>());
  EXPECT_EQ(expected_result, Serialize<EditingInFlatTreeStrategy>());
}

}  // namespace blink
```
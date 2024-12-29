Response:
The user is asking for an analysis of a C++ source code file related to CSS Container Queries in the Chromium Blink engine. They want to know its functionality, its relationship to web technologies (HTML, CSS, JavaScript), examples of logic, potential user/programmer errors, debugging steps, and a summary of its functions.

Here's a breakdown of how to address each point:

1. **Functionality:**  The file name and the included headers strongly suggest that this file contains unit tests for the `ContainerQuery` class. It will likely test parsing, evaluation, and interaction with the style system.

2. **Relationship to HTML, CSS, and JavaScript:**
    * **CSS:** Container Queries are a CSS feature, so the file directly tests how CSS `@container` rules are parsed and how they affect the styling of HTML elements based on the size of their container.
    * **HTML:** The tests will involve creating HTML structures with elements that have container properties and are affected by container queries.
    * **JavaScript:** While this specific file is C++, the functionality it tests is triggered by changes in the browser, often initiated by JavaScript manipulating the DOM or CSS. JavaScript can also query computed styles, revealing the effects of container queries.

3. **Logic and Examples:**  The test functions (`TEST_F`) will demonstrate the logic. I can infer examples by looking at the test names and the code within them (e.g., `PreludeParsing` likely tests the syntax of the `@container` rule's preamble). I can provide hypothetical inputs (CSS rules, HTML structures) and expected outputs (parsed representation, computed styles).

4. **User/Programmer Errors:**  These would involve incorrect CSS syntax in `@container` rules, misunderstanding how container queries cascade and override other styles, or expecting container queries to behave like media queries in terms of viewport size.

5. **Debugging Steps:**  Reaching this code likely involves investigating issues with container queries not working as expected. Developers might use the browser's DevTools to inspect styles, look at the parsed CSS, and step through the rendering pipeline (which eventually would involve code like this).

6. **Summary:**  The file primarily tests the implementation of CSS container queries in the Blink rendering engine.

**Mental Sandbox:**

* I see various parsing functions (`ParseAtContainer`, `ParseContainerQuery`). These will be key to testing syntax.
* The `ContainerQueryEvaluation` test clearly demonstrates the core functionality.
* There are tests related to animations and transitions, indicating that container queries interact with these features.
* The inclusion of `page_test_base.h` confirms this is a unit test file within the Blink testing infrastructure.

**Confidence Score:** 5/5 - I'm quite confident in my understanding of the file's purpose.

Now, I will proceed with generating the response based on this analysis.
```cpp
    .getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  ASSERT_TRUE(container);

  EXPECT_NE("unset", ComputedValueString(target, "animation-name"));

  // Simulate a style and layout pass.
  {
    PostStyleUpdateScope post_style_update_scope(GetDocument());

    // Animation is initially set.
    EXPECT_EQ("anim", ComputedValueString(target, "animation-name"));
    EXPECT_EQ(0u, GetAnimationsCount(target));

    // Animation is unset in the final round.
    GetDocument().GetStyleEngine().UpdateStyleAndLayoutTreeForContainer(
        *container, LogicalSize(130, -1), kLogicalAxesInline);
    UpdateAllLifecyclePhasesForTest();
    EXPECT_EQ("none", ComputedValueString(target, "animation-name"));
    EXPECT_EQ(0u, GetAnimationsCount(target));

    EXPECT_FALSE(post_style_update_scope.Apply());
  }

  // Animation count should be updated after PostStyleUpdateScope::Apply.
  EXPECT_EQ(0u, GetAnimationsCount(target));
}

}  // namespace blink
```

这是目录为 `blink/renderer/core/css/container_query_test.cc` 的 Chromium Blink 引擎源代码文件，下面列举一下它的功能：

**主要功能:**

* **测试 CSS 容器查询 (Container Queries) 功能的实现:**  这个文件包含了大量的单元测试用例，用于验证 Blink 引擎中 `ContainerQuery` 类的行为是否符合 CSS 容器查询规范。它测试了容器查询的各个方面，包括解析、求值、与动画和过渡的交互等。

**具体功能点:**

* **解析测试:**
    * 测试 `@container` 规则语法的正确解析，包括有效的和无效的语法。
    * 测试容器查询条件中各种特征（如 `width`, `height`, `aspect-ratio`, `orientation` 等）的解析。
    * 测试容器名称的解析。
    * 测试逻辑运算符 (`and`, `or`, `not`) 在容器查询条件中的使用。
* **特征标志 (Feature Flags) 测试:**
    * 检查解析后的容器查询是否正确地标记了其中使用的 CSS 特性。
* **容器选择器 (Container Selector) 测试:**
    * 测试根据容器查询条件推断出的隐式容器选择器类型。
    * 测试 `scroll-state()` 函数的解析和容器选择器类型的确定。
* **规则解析测试:**
    * 测试包含容器查询的完整 CSS 规则的解析，包括规则块中的样式声明。
* **规则复制测试:**
    * 验证 `StyleRuleContainer` 对象的正确复制，包括其包含的规则和 `ContainerQuery` 对象。
* **容器查询求值测试:**
    * 测试容器查询条件在不同容器尺寸下的求值结果，以及如何影响元素的样式。
* **布局缩放 (Layout Zoom) 测试:**
    * 验证容器查询在布局缩放情况下的行为，特别是涉及到像素单位的查询。
* **字体相对单位测试:**
    * 测试容器查询中字体相对单位 (如 `em`, `ex`, `ch`) 的正确计算。
* **容器单元 (Container Units) 回退测试:**
    * 测试当容器尺寸无法确定时，容器单元 (如 `cqw`, `cqi`) 如何回退到视口单位。
* **动画和过渡测试:**
    * 测试容器查询如何与 CSS 过渡 (Transitions) 协同工作，包括在不同阶段添加、修改和移除过渡属性的情况。
    * 测试容器查询如何与 CSS 动画 (Animations) 协同工作，包括重新定义和取消动画的情况。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个 C++ 文件本身不直接包含 JavaScript、HTML 或 CSS 代码，但它测试的功能是基于这些 Web 技术的。

* **CSS:**  `container_query_test.cc` 的核心是测试 CSS 的容器查询特性。它解析和评估 CSS 的 `@container` 规则，并验证其对元素样式的影响。
    * **举例:** 文件中的 `TEST_F(ContainerQueryTest, PreludeParsing)` 测试了各种 `@container` 规则语法的解析，例如 `@container (min-width: 300px) {}`。
* **HTML:**  测试用例中会创建虚拟的 HTML 结构，用于测试容器查询在实际元素上的效果。
    * **举例:** `TEST_F(ContainerQueryTest, ContainerQueryEvaluation)` 中创建了包含 `#container` 和 `#div` 的 HTML 结构，用于测试容器尺寸变化时 `#div` 的 `z-index` 属性是否正确更新。
* **JavaScript:** 虽然此文件是 C++，但容器查询的功能最终会影响到 JavaScript 可以获取的元素样式。JavaScript 可以通过 `getComputedStyle()` 方法获取受容器查询影响的元素的最终样式。
    * **举例:**  假设在 JavaScript 中有以下代码：
      ```javascript
      const div = document.getElementById('div');
      const computedStyle = getComputedStyle(div);
      console.log(computedStyle.zIndex);
      ```
      `container_query_test.cc` 中 `ContainerQueryEvaluation` 的测试就是为了确保在容器尺寸变化时，JavaScript 获取到的 `zIndex` 值是正确的。

**逻辑推理及假设输入与输出:**

* **假设输入 (CSS 规则):** `@container (min-width: 500px) { div { color: red; } }`
* **假设输入 (HTML 结构):**
  ```html
  <div id="container" style="width: 400px;">
    <div>This is a div</div>
  </div>
  ```
* **逻辑推理:** `container_query_test.cc` 中的测试会验证，当容器 `#container` 的宽度小于 500px 时，`div` 元素的颜色不会变成红色。
* **假设输出 (Computed Style):** `div` 元素的 `color` 属性为默认值 (通常是黑色)。

* **假设输入 (CSS 规则):** `@container (min-width: 500px) { div { color: red; } }`
* **假设输入 (HTML 结构):**
  ```html
  <div id="container" style="width: 600px;">
    <div>This is a div</div>
  </div>
  ```
* **逻辑推理:** `container_query_test.cc` 中的测试会验证，当容器 `#container` 的宽度大于等于 500px 时，`div` 元素的颜色会变成红色。
* **假设输出 (Computed Style):** `div` 元素的 `color` 属性为 `red`。

**用户或编程常见的使用错误及举例说明:**

* **错误使用 `@container` 语法:**  用户可能会写出不符合 CSS 容器查询规范的语法。
    * **举例:** `@container min-width: 300px { ... }` (缺少括号)。`container_query_test.cc` 中的 `PreludeParsing` 测试会覆盖这类错误，确保 Blink 引擎能正确识别并处理这些无效语法，通常会忽略或报错。
* **误解容器查询的适用范围:**  用户可能认为容器查询会基于视口大小生效，但实际上它是基于最近的 **包含上下文 (containing context)** 的尺寸。
    * **举例:**  用户可能期望一个 `@container (min-width: 500px)` 规则在视口宽度大于 500px 时生效，但如果该元素没有设置 `container-type` 或其祖先没有形成容器上下文，则该规则可能不会生效。虽然 `container_query_test.cc` 不直接测试用户行为，但它通过测试 `ContainerQueryEvaluation` 确保在正确设置容器上下文的情况下，查询能够按预期工作。
* **在容器查询中使用不支持的 CSS 特性:**  早期的容器查询规范可能只支持有限的特性。
    * **举例:** 用户可能尝试使用 `@container (color) { ... }`，但 `color` 并不是尺寸容器查询的有效特性。`ValidFeatures` 测试用例会检查哪些特性是允许的，哪些是不允许的。

**用户操作是如何一步步的到达这里，作为调试线索:**

当开发者在浏览器中遇到了容器查询不生效或行为异常的问题时，他们可能会进行以下调试步骤，最终可能会涉及到查看 Blink 引擎的源代码：

1. **检查 CSS 语法:**  首先会检查 `@container` 规则的语法是否正确，包括拼写错误、缺少括号等。
2. **检查 `container-type` 属性:**  确认容器元素是否设置了 `container-type` 属性 (例如 `size`, `inline-size`)，以及该属性的值是否正确。
3. **检查容器元素的尺寸:**  使用浏览器的开发者工具 (DevTools) 检查容器元素的实际尺寸，确认是否满足容器查询的条件。
4. **检查样式层叠:**  查看受影响元素的 computed style，确认是否有其他 CSS 规则覆盖了容器查询的样式。
5. **简化测试用例:**  尝试创建一个最小化的 HTML/CSS 代码示例，只包含必要的元素和样式，以便更容易隔离问题。
6. **搜索浏览器 Bug 报告:**  如果怀疑是浏览器引擎的问题，可能会搜索 Chromium 的 bug 跟踪器，看看是否有相关的已知问题。
7. **阅读规范和文档:**  重新阅读 CSS 容器查询的规范和相关文档，确保对容器查询的工作原理有正确的理解。
8. **查看浏览器引擎源代码 (如 `container_query_test.cc`):**  如果以上步骤都无法解决问题，并且开发者有 C++ 基础，可能会尝试查看 Blink 引擎的源代码，特别是与容器查询相关的测试文件，例如 `container_query_test.cc`。通过阅读测试用例，可以更深入地了解容器查询的内部实现和预期行为，从而帮助定位问题。例如，查看 `ContainerQueryEvaluation` 测试可以理解 Blink 如何评估容器查询条件并更新样式。查看 `TransitionAppearingInFinalPass` 可以了解容器查询与过渡的复杂交互。

**归纳一下它的功能 (第 1 部分):**

`blink/renderer/core/css/container_query_test.cc` 的主要功能是作为 Chromium Blink 引擎中 CSS 容器查询功能的核心 **单元测试套件**。它通过大量的测试用例，细致地验证了容器查询的各个方面，包括语法解析、特征识别、条件评估以及与动画和过渡的集成。这些测试确保了 Blink 引擎对 CSS 容器查询的实现符合规范，并能按预期工作。 这部分代码涵盖了容器查询的基础解析和一些核心的功能验证。

Prompt: 
```
这是目录为blink/renderer/core/css/container_query_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/container_query.h"

#include <optional>

#include "third_party/blink/renderer/core/animation/document_animations.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/css/css_container_rule.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/post_style_update_scope.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/text/writing_mode.h"

namespace blink {

class ContainerQueryTest : public PageTestBase {
 public:
  bool HasUnknown(StyleRuleContainer* rule) {
    return rule && rule->GetContainerQuery().Query().HasUnknown();
  }

  enum class UnknownHandling {
    // No special handling of "unknown" values.
    kAllow,
    // Treats "unknown" values as parse errors.
    kError
  };

  StyleRuleContainer* ParseAtContainer(
      String rule_string,
      UnknownHandling unknown_handling = UnknownHandling::kError) {
    auto* rule = DynamicTo<StyleRuleContainer>(
        css_test_helpers::ParseRule(GetDocument(), rule_string));
    if ((unknown_handling == UnknownHandling::kError) && HasUnknown(rule)) {
      return nullptr;
    }
    return rule;
  }

  ContainerQuery* ParseContainerQuery(
      String query,
      UnknownHandling unknown_handling = UnknownHandling::kError) {
    String rule = "@container " + query + " {}";
    StyleRuleContainer* container = ParseAtContainer(rule, unknown_handling);
    if (!container) {
      return nullptr;
    }
    return &container->GetContainerQuery();
  }

  std::optional<MediaQueryExpNode::FeatureFlags> FeatureFlagsFrom(
      String query_string) {
    ContainerQuery* query =
        ParseContainerQuery(query_string, UnknownHandling::kAllow);
    if (!query) {
      return std::nullopt;
    }
    return GetInnerQuery(*query).CollectFeatureFlags();
  }

  ContainerSelector ContainerSelectorFrom(String query_string) {
    ContainerQuery* query =
        ParseContainerQuery(query_string, UnknownHandling::kAllow);
    if (!query) {
      return ContainerSelector();
    }
    return ContainerSelector(g_null_atom, GetInnerQuery(*query));
  }

  String SerializeCondition(StyleRuleContainer* container) {
    if (!container) {
      return "";
    }
    return container->GetContainerQuery().ToString();
  }

  const MediaQueryExpNode& GetInnerQuery(ContainerQuery& container_query) {
    return container_query.Query();
  }

  const CSSValue* ComputedValue(Element* element, String property_name) {
    CSSPropertyRef ref(property_name, GetDocument());
    DCHECK(ref.IsValid());
    return ref.GetProperty().CSSValueFromComputedStyle(
        element->ComputedStyleRef(),
        /* layout_object */ nullptr,
        /* allow_visited_style */ false, CSSValuePhase::kComputedValue);
  }

  String ComputedValueString(Element* element, String property_name) {
    if (const CSSValue* value = ComputedValue(element, property_name)) {
      return value->CssText();
    }
    return g_null_atom;
  }

  // Get animations count for a specific element without force-updating
  // style and layout-tree.
  size_t GetAnimationsCount(Element* element) {
    if (auto* element_animations = element->GetElementAnimations()) {
      return element_animations->Animations().size();
    }
    return 0;
  }

  size_t GetOldStylesCount(String html) {
    // Creating a PostStyleUpdateScope prevents old styles from being cleared
    // until this function completes.
    PostStyleUpdateScope post_style_update_scope(GetDocument());
    SetBodyInnerHTML(html);
    DCHECK(PostStyleUpdateScope::CurrentAnimationData());
    size_t old_styles_count =
        PostStyleUpdateScope::CurrentAnimationData()->old_styles_.size();
    // We don't care about the effects of this Apply call, except that it
    // silences a DCHECK in ~PostStyleUpdateScope.
    post_style_update_scope.Apply();
    return old_styles_count;
  }
};

TEST_F(ContainerQueryTest, PreludeParsing) {
  // Valid:
  EXPECT_EQ(
      "(min-width: 300px)",
      SerializeCondition(ParseAtContainer("@container (min-width: 300px) {}")));
  EXPECT_EQ(
      "(max-width: 500px)",
      SerializeCondition(ParseAtContainer("@container (max-width: 500px) {}")));
  EXPECT_EQ("(not (max-width: 500px))",
            SerializeCondition(
                ParseAtContainer("@container (not (max-width: 500px)) {}")));
  EXPECT_EQ(
      "((max-width: 500px) and (max-height: 500px))",
      SerializeCondition(ParseAtContainer("@container ((max-width: 500px) "
                                          "and (max-height: 500px)) {}")));
  EXPECT_EQ(
      "((max-width: 500px) or (max-height: 500px))",
      SerializeCondition(ParseAtContainer("@container ((max-width: 500px) "
                                          "or (max-height: 500px)) {}")));
  EXPECT_EQ(
      "(width < 300px)",
      SerializeCondition(ParseAtContainer("@container (width < 300px) {}")));

  EXPECT_EQ("somename not (width)", SerializeCondition(ParseAtContainer(
                                        "@container somename not (width) {}")));

  EXPECT_EQ("(width) and (height)", SerializeCondition(ParseAtContainer(
                                        "@container (width) and (height) {}")));

  EXPECT_EQ("(width) or (height)", SerializeCondition(ParseAtContainer(
                                       "@container (width) or (height) {}")));

  EXPECT_EQ("test_name (width) or (height)",
            SerializeCondition(ParseAtContainer(
                "@container test_name (width) or (height) {}")));

  EXPECT_EQ("test_name ((max-width: 500px) or (max-height: 500px))",
            SerializeCondition(
                ParseAtContainer("@container test_name ((max-width: 500px) "
                                 "or (max-height: 500px)) {}")));

  // Invalid:
  EXPECT_FALSE(ParseAtContainer("@container test_name {}"));
  EXPECT_FALSE(ParseAtContainer("@container 100px {}"));
  EXPECT_FALSE(ParseAtContainer("@container calc(1) {}"));
  EXPECT_FALSE(ParseAtContainer("@container {}"));
  EXPECT_FALSE(ParseAtContainer("@container (min-width: 300px) nonsense {}"));
  EXPECT_FALSE(ParseAtContainer("@container size(width) {}"));
}

TEST_F(ContainerQueryTest, ValidFeatures) {
  // https://drafts.csswg.org/css-contain-3/#size-container
  EXPECT_TRUE(ParseAtContainer("@container (width) {}"));
  EXPECT_TRUE(ParseAtContainer("@container (min-width: 0px) {}"));
  EXPECT_TRUE(ParseAtContainer("@container (max-width: 0px) {}"));
  EXPECT_TRUE(ParseAtContainer("@container (height) {}"));
  EXPECT_TRUE(ParseAtContainer("@container (min-height: 0px) {}"));
  EXPECT_TRUE(ParseAtContainer("@container (max-height: 0px) {}"));
  EXPECT_TRUE(ParseAtContainer("@container (aspect-ratio) {}"));
  EXPECT_TRUE(ParseAtContainer("@container (min-aspect-ratio: 1/2) {}"));
  EXPECT_TRUE(ParseAtContainer("@container (max-aspect-ratio: 1/2) {}"));
  EXPECT_TRUE(ParseAtContainer("@container (orientation: portrait) {}"));
  EXPECT_TRUE(
      ParseAtContainer("@container test_name (orientation: portrait) {}"));

  EXPECT_FALSE(ParseAtContainer("@container (color) {}"));
  EXPECT_FALSE(ParseAtContainer("@container test_name (color) {}"));
  EXPECT_FALSE(ParseAtContainer("@container (color-index) {}"));
  EXPECT_FALSE(ParseAtContainer("@container (color-index >= 1) {}"));
  EXPECT_FALSE(ParseAtContainer("@container (grid) {}"));
  EXPECT_FALSE(ParseAtContainer("@container (resolution: 150dpi) {}"));
  EXPECT_FALSE(ParseAtContainer("@container (resolution: calc(6x / 3)) {}"));
  EXPECT_FALSE(ParseAtContainer("@container size(width) {}"));
  EXPECT_FALSE(ParseAtContainer("@container test_name size(width) {}"));
}

TEST_F(ContainerQueryTest, FeatureFlags) {
  EXPECT_EQ(MediaQueryExpNode::kFeatureUnknown,
            FeatureFlagsFrom("(width: 100gil)"));
  EXPECT_EQ(MediaQueryExpNode::kFeatureWidth,
            FeatureFlagsFrom("(width: 100px)"));
  EXPECT_EQ(MediaQueryExpNode::kFeatureWidth,
            FeatureFlagsFrom("test_name (width: 100px)"));
  EXPECT_EQ(MediaQueryExpNode::kFeatureHeight,
            FeatureFlagsFrom("(height < 100px)"));
  EXPECT_EQ(MediaQueryExpNode::kFeatureInlineSize,
            FeatureFlagsFrom("(100px >= inline-size)"));
  EXPECT_EQ(MediaQueryExpNode::kFeatureBlockSize,
            FeatureFlagsFrom("(100px = block-size)"));
  EXPECT_EQ(static_cast<MediaQueryExpNode::FeatureFlags>(
                MediaQueryExpNode::kFeatureWidth |
                MediaQueryExpNode::kFeatureBlockSize),
            FeatureFlagsFrom("((width) and (100px = block-size))"));
  EXPECT_EQ(static_cast<MediaQueryExpNode::FeatureFlags>(
                MediaQueryExpNode::kFeatureUnknown |
                MediaQueryExpNode::kFeatureBlockSize),
            FeatureFlagsFrom("((unknown) and (100px = block-size))"));
  EXPECT_EQ(
      static_cast<MediaQueryExpNode::FeatureFlags>(
          MediaQueryExpNode::kFeatureWidth | MediaQueryExpNode::kFeatureHeight |
          MediaQueryExpNode::kFeatureInlineSize),
      FeatureFlagsFrom("((width) or (height) or (inline-size))"));
  EXPECT_EQ(MediaQueryExpNode::kFeatureWidth,
            FeatureFlagsFrom("((width: 100px))"));
  EXPECT_EQ(MediaQueryExpNode::kFeatureWidth,
            FeatureFlagsFrom("(not (width: 100px))"));
}

TEST_F(ContainerQueryTest, ImplicitContainerSelector) {
  ContainerSelector width = ContainerSelectorFrom("(width: 100px)");
  EXPECT_EQ(kContainerTypeInlineSize, width.Type(WritingMode::kHorizontalTb));
  EXPECT_EQ(kContainerTypeBlockSize, width.Type(WritingMode::kVerticalRl));

  ContainerSelector height = ContainerSelectorFrom("(height: 100px)");
  EXPECT_EQ(kContainerTypeBlockSize, height.Type(WritingMode::kHorizontalTb));
  EXPECT_EQ(kContainerTypeInlineSize, height.Type(WritingMode::kVerticalRl));

  ContainerSelector inline_size = ContainerSelectorFrom("(inline-size: 100px)");
  EXPECT_EQ(kContainerTypeInlineSize,
            inline_size.Type(WritingMode::kHorizontalTb));
  EXPECT_EQ(kContainerTypeInlineSize,
            inline_size.Type(WritingMode::kVerticalRl));

  ContainerSelector block_size = ContainerSelectorFrom("(block-size: 100px)");
  EXPECT_EQ(kContainerTypeBlockSize,
            block_size.Type(WritingMode::kHorizontalTb));
  EXPECT_EQ(kContainerTypeBlockSize, block_size.Type(WritingMode::kVerticalRl));

  ContainerSelector width_height =
      ContainerSelectorFrom("((width: 100px) or (height: 100px))");
  EXPECT_EQ((kContainerTypeInlineSize | kContainerTypeBlockSize),
            width_height.Type(WritingMode::kHorizontalTb));
  EXPECT_EQ((kContainerTypeInlineSize | kContainerTypeBlockSize),
            width_height.Type(WritingMode::kVerticalRl));

  ContainerSelector inline_block_size =
      ContainerSelectorFrom("((inline-size: 100px) or (block-size: 100px))");
  EXPECT_EQ((kContainerTypeInlineSize | kContainerTypeBlockSize),
            inline_block_size.Type(WritingMode::kHorizontalTb));
  EXPECT_EQ((kContainerTypeInlineSize | kContainerTypeBlockSize),
            inline_block_size.Type(WritingMode::kVerticalRl));

  ContainerSelector aspect_ratio = ContainerSelectorFrom("(aspect-ratio: 1/2)");
  EXPECT_EQ((kContainerTypeInlineSize | kContainerTypeBlockSize),
            aspect_ratio.Type(WritingMode::kHorizontalTb));
  EXPECT_EQ((kContainerTypeInlineSize | kContainerTypeBlockSize),
            aspect_ratio.Type(WritingMode::kVerticalRl));

  ContainerSelector orientation =
      ContainerSelectorFrom("(orientation: portrait)");
  EXPECT_EQ((kContainerTypeInlineSize | kContainerTypeBlockSize),
            orientation.Type(WritingMode::kHorizontalTb));
  EXPECT_EQ((kContainerTypeInlineSize | kContainerTypeBlockSize),
            orientation.Type(WritingMode::kVerticalRl));
}

TEST_F(ContainerQueryTest, ScrollStateContainerSelector) {
  ContainerSelector stuck_right =
      ContainerSelectorFrom("scroll-state(stuck: right)");
  EXPECT_EQ(kContainerTypeScrollState,
            stuck_right.Type(WritingMode::kHorizontalTb));

  ContainerSelector stuck_and_style =
      ContainerSelectorFrom("scroll-state(stuck: right) and style(--foo: bar)");
  EXPECT_EQ(kContainerTypeScrollState,
            stuck_and_style.Type(WritingMode::kHorizontalTb));

  ContainerSelector stuck_and_inline_size = ContainerSelectorFrom(
      "scroll-state(stuck: block-end) or (inline-size > 10px)");
  EXPECT_EQ((kContainerTypeScrollState | kContainerTypeInlineSize),
            stuck_and_inline_size.Type(WritingMode::kHorizontalTb));

  ContainerSelector stuck_and_block_size =
      ContainerSelectorFrom("scroll-state(stuck: block-end) and (height)");
  EXPECT_EQ((kContainerTypeScrollState | kContainerTypeBlockSize),
            stuck_and_block_size.Type(WritingMode::kHorizontalTb));
}

TEST_F(ContainerQueryTest, RuleParsing) {
  StyleRuleContainer* container = ParseAtContainer(R"CSS(
    @container test_name (min-width: 100px) {
      div { width: 100px; }
      span { height: 100px; }
    }
  )CSS");
  ASSERT_TRUE(container);
  ASSERT_EQ("test_name", container->GetContainerQuery().Selector().Name());

  CSSStyleSheet* sheet = css_test_helpers::CreateStyleSheet(GetDocument());
  auto* rule = DynamicTo<CSSContainerRule>(
      container->CreateCSSOMWrapper(/*position_hint=*/0, sheet));
  ASSERT_TRUE(rule);
  ASSERT_EQ(2u, rule->length());

  auto* div_rule = rule->Item(0);
  ASSERT_TRUE(div_rule);
  EXPECT_EQ("div { width: 100px; }", div_rule->cssText());

  auto* span_rule = rule->Item(1);
  ASSERT_TRUE(span_rule);
  EXPECT_EQ("span { height: 100px; }", span_rule->cssText());
}

TEST_F(ContainerQueryTest, RuleCopy) {
  StyleRuleContainer* container = ParseAtContainer(R"CSS(
    @container (min-width: 100px) {
      div { width: 100px; }
    }
  )CSS");
  ASSERT_TRUE(container);

  // Copy via StyleRuleBase to test switch dispatch.
  auto* copy_base = static_cast<StyleRuleBase*>(container)->Copy();
  auto* copy = DynamicTo<StyleRuleContainer>(copy_base);
  ASSERT_TRUE(copy);

  // The StyleRuleContainer object should be copied.
  EXPECT_NE(container, copy);

  // The rules should be copied.
  auto& rules = container->ChildRules();
  auto& rules_copy = copy->ChildRules();
  ASSERT_EQ(1u, rules.size());
  ASSERT_EQ(1u, rules_copy.size());
  EXPECT_NE(rules[0], rules_copy[0]);

  // The ContainerQuery should be copied.
  EXPECT_NE(&container->GetContainerQuery(), &copy->GetContainerQuery());

  // The inner MediaQueryExpNode is immutable, and does not need to be copied.
  EXPECT_EQ(&GetInnerQuery(container->GetContainerQuery()),
            &GetInnerQuery(copy->GetContainerQuery()));
}

TEST_F(ContainerQueryTest, ContainerQueryEvaluation) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #container {
        container-type: size;
        width: 500px;
        height: 500px;
      }
      #container.adjust {
        width: 600px;
      }

      div { z-index:1; }
      /* Should apply: */
      @container (min-width: 500px) {
        div { z-index:2; }
      }
      /* Should initially not apply: */
      @container (min-width: 600px) {
        div { z-index:3; }
      }
    </style>
    <div id=container>
      <div id=div></div>
    </div>
  )HTML");
  Element* div = GetDocument().getElementById(AtomicString("div"));
  ASSERT_TRUE(div);
  EXPECT_EQ(2, div->ComputedStyleRef().ZIndex());

  // Check that dependent elements are responsive to changes:
  Element* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_TRUE(container);
  container->setAttribute(html_names::kClassAttr, AtomicString("adjust"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(3, div->ComputedStyleRef().ZIndex());

  container->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(2, div->ComputedStyleRef().ZIndex());
}

TEST_F(ContainerQueryTest, QueryZoom) {
  GetFrame().SetLayoutZoomFactor(2.0f);

  SetBodyInnerHTML(R"HTML(
    <style>
      #container1 {
        width: 100px;
        height: 200px;
        container-type: size;
      }
      #container2 {
        width: 200px;
        height: 400px;
        container-type: size;
      }
      @container (width: 100px) {
        div { --w100:1; }
      }
      @container (width: 200px) {
        div { --w200:1; }
      }
      @container (height: 200px) {
        div { --h200:1; }
      }
      @container (height: 400px) {
        div { --h400:1; }
      }
    </style>
    <div id=container1>
      <div id=target1></div>
    </div>
    <div id=container2>
      <div id=target2></div>
    </div>
  )HTML");

  Element* target1 = GetDocument().getElementById(AtomicString("target1"));
  Element* target2 = GetDocument().getElementById(AtomicString("target2"));
  ASSERT_TRUE(target1);
  ASSERT_TRUE(target2);

  EXPECT_TRUE(
      target1->ComputedStyleRef().GetVariableData(AtomicString("--w100")));
  EXPECT_TRUE(
      target1->ComputedStyleRef().GetVariableData(AtomicString("--h200")));
  EXPECT_FALSE(
      target1->ComputedStyleRef().GetVariableData(AtomicString("--w200")));
  EXPECT_FALSE(
      target1->ComputedStyleRef().GetVariableData(AtomicString("--h400")));

  EXPECT_FALSE(
      target2->ComputedStyleRef().GetVariableData(AtomicString("--w100")));
  EXPECT_FALSE(
      target2->ComputedStyleRef().GetVariableData(AtomicString("--h200")));
  EXPECT_TRUE(
      target2->ComputedStyleRef().GetVariableData(AtomicString("--w200")));
  EXPECT_TRUE(
      target2->ComputedStyleRef().GetVariableData(AtomicString("--h400")));
}

TEST_F(ContainerQueryTest, QueryFontRelativeWithZoom) {
  GetFrame().SetLayoutZoomFactor(2.0f);

  SetBodyInnerHTML(R"HTML(
    <style>
      #font-root {
        font-size: 50px;
      }
      #em-container {
        width: 10em;
        container-type: inline-size;
      }
      #ex-container {
        width: 10ex;
        container-type: inline-size;
      }
      #ch-container {
        width: 10ch;
        container-type: inline-size;
      }
      @container (width: 10em) {
        #em-target { --em:1; }
      }
      @container (width: 10ex) {
        #ex-target { --ex:1; }
      }
      @container (width: 10ch) {
        #ch-target { --ch:1; }
      }
    </style>
    <div id="font-root">
      <div id="em-container">
        <div id="em-target"></div>
      </div>
      <div id="ex-container">
        <div id="ex-target"></div>
      </div>
      <div id="ch-container">
        <div id="ch-target"></div>
      </div>
    </div>
  )HTML");

  Element* em_target = GetDocument().getElementById(AtomicString("em-target"));
  Element* ex_target = GetDocument().getElementById(AtomicString("ex-target"));
  Element* ch_target = GetDocument().getElementById(AtomicString("ch-target"));
  ASSERT_TRUE(em_target);
  ASSERT_TRUE(ex_target);
  ASSERT_TRUE(ch_target);

  EXPECT_TRUE(
      em_target->ComputedStyleRef().GetVariableData(AtomicString("--em")));
  EXPECT_TRUE(
      ex_target->ComputedStyleRef().GetVariableData(AtomicString("--ex")));
  EXPECT_TRUE(
      ch_target->ComputedStyleRef().GetVariableData(AtomicString("--ch")));
}

TEST_F(ContainerQueryTest, ContainerUnitsViewportFallback) {
  using css_test_helpers::RegisterProperty;

  RegisterProperty(GetDocument(), "--cqw", "<length>", "0px", false);
  RegisterProperty(GetDocument(), "--cqi", "<length>", "0px", false);
  RegisterProperty(GetDocument(), "--cqh", "<length>", "0px", false);
  RegisterProperty(GetDocument(), "--cqb", "<length>", "0px", false);
  RegisterProperty(GetDocument(), "--cqmin", "<length>", "0px", false);
  RegisterProperty(GetDocument(), "--cqmax", "<length>", "0px", false);
  RegisterProperty(GetDocument(), "--fallback-h", "<length>", "0px", false);
  RegisterProperty(GetDocument(), "--fallback-min-cqi-vh", "<length>", "0px",
                   false);
  RegisterProperty(GetDocument(), "--fallback-max-cqi-vh", "<length>", "0px",
                   false);

  SetBodyInnerHTML(R"HTML(
    <style>
      #inline, #size {
        width: 100px;
        height: 100px;
      }
      #inline {
        container-type: inline-size;
      }
      #size {
        container-type: size;
      }
      #inline_target, #size_target {
        --cqw: 10cqw;
        --cqi: 10cqi;
        --cqh: 10cqh;
        --cqb: 10cqb;
        --cqmin: 10cqmin;
        --cqmax: 10cqmax;
        --fallback-h: 10vh;
        --fallback-min-cqi-vh: min(10cqi, 10vh);
        --fallback-max-cqi-vh: max(10cqi, 10vh);
      }
    </style>
    <div id=inline>
      <div id="inline_target"></div>
    </div>
    <div id=size>
      <div id="size_target"></div>
    </div>
  )HTML");

  Element* inline_target =
      GetDocument().getElementById(AtomicString("inline_target"));
  ASSERT_TRUE(inline_target);
  EXPECT_EQ(ComputedValueString(inline_target, "--cqw"), "10px");
  EXPECT_EQ(ComputedValueString(inline_target, "--cqi"), "10px");
  EXPECT_EQ(ComputedValueString(inline_target, "--cqh"),
            ComputedValueString(inline_target, "--fallback-h"));
  EXPECT_EQ(ComputedValueString(inline_target, "--cqb"),
            ComputedValueString(inline_target, "--fallback-h"));
  EXPECT_EQ(ComputedValueString(inline_target, "--cqmin"),
            ComputedValueString(inline_target, "--fallback-min-cqi-vh"));
  EXPECT_EQ(ComputedValueString(inline_target, "--cqmax"),
            ComputedValueString(inline_target, "--fallback-max-cqi-vh"));

  Element* size_target =
      GetDocument().getElementById(AtomicString("size_target"));
  ASSERT_TRUE(size_target);
  EXPECT_EQ(ComputedValueString(size_target, "--cqw"), "10px");
  EXPECT_EQ(ComputedValueString(size_target, "--cqi"), "10px");
  EXPECT_EQ(ComputedValueString(size_target, "--cqh"), "10px");
  EXPECT_EQ(ComputedValueString(size_target, "--cqb"), "10px");
  EXPECT_EQ(ComputedValueString(size_target, "--cqmin"), "10px");
  EXPECT_EQ(ComputedValueString(size_target, "--cqmax"), "10px");
}

TEST_F(ContainerQueryTest, OldStyleForTransitions) {
  Element* target = nullptr;

  SetBodyInnerHTML(R"HTML(
    <style>
      #container {
        container-type: inline-size;
        width: 20px;
      }
      #target {
        height: 10px;
        transition: height steps(2, start) 100s;
      }
      @container (width: 120px) {
        #target { height: 20px; }
      }
      @container (width: 130px) {
        #target { height: 30px; }
      }
      @container (width: 140px) {
        #target { height: 40px; }
      }
    </style>
    <div id=container>
      <div id=target>
      </div>
    </div>
  )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  ASSERT_TRUE(container);

  EXPECT_EQ("10px", ComputedValueString(target, "height"));
  EXPECT_EQ(0u, GetAnimationsCount(target));

  // Simulate a style and layout pass with multiple rounds of style recalc.
  {
    PostStyleUpdateScope post_style_update_scope(GetDocument());

    // Should transition between [10px, 20px]. (Intermediate round).
    GetDocument().GetStyleEngine().UpdateStyleAndLayoutTreeForContainer(
        *container, LogicalSize(120, -1), kLogicalAxesInline);
    EXPECT_EQ("15px", ComputedValueString(target, "height"));
    EXPECT_EQ(0u, GetAnimationsCount(target));

    // Should transition between [10px, 30px]. (Intermediate round).
    GetDocument().GetStyleEngine().UpdateStyleAndLayoutTreeForContainer(
        *container, LogicalSize(130, -1), kLogicalAxesInline);
    EXPECT_EQ("20px", ComputedValueString(target, "height"));
    EXPECT_EQ(0u, GetAnimationsCount(target));

    // Should transition between [10px, 40px]. (Final round).
    container->SetInlineStyleProperty(CSSPropertyID::kWidth, "140px");
    UpdateAllLifecyclePhasesForTest();
    EXPECT_EQ("25px", ComputedValueString(target, "height"));
    EXPECT_EQ(0u, GetAnimationsCount(target));

    EXPECT_FALSE(post_style_update_scope.Apply());
  }

  // Animation count should be updated after PostStyleUpdateScope::Apply.
  EXPECT_EQ(1u, GetAnimationsCount(target));

  // Verify that the newly-updated Animation produces the correct value.
  target->SetNeedsAnimationStyleRecalc();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ("25px", ComputedValueString(target, "height"));
}

TEST_F(ContainerQueryTest, TransitionAppearingInFinalPass) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #container {
        container-type: inline-size;
        width: 20px;
      }
      #target {
        height: 10px;
      }
      @container (width: 120px) {
        #target { height: 20px; }
      }
      @container (width: 130px) {
        #target { height: 30px; }
      }
      @container (width: 140px) {
        #target {
          height: 40px;
          transition: height steps(2, start) 100s;
        }
      }
    </style>
    <div id=container>
      <div id=target>
      </div>
    </div>
  )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  ASSERT_TRUE(container);

  EXPECT_EQ("10px", ComputedValueString(target, "height"));
  EXPECT_EQ(0u, GetAnimationsCount(target));

  // Simulate a style and layout pass with multiple rounds of style recalc.
  {
    PostStyleUpdateScope post_style_update_scope(GetDocument());

    // No transition property present. (Intermediate round).
    GetDocument().GetStyleEngine().UpdateStyleAndLayoutTreeForContainer(
        *container, LogicalSize(120, -1), kLogicalAxesInline);
    EXPECT_EQ("20px", ComputedValueString(target, "height"));
    EXPECT_EQ(0u, GetAnimationsCount(target));

    // Still no transition property present. (Intermediate round).
    GetDocument().GetStyleEngine().UpdateStyleAndLayoutTreeForContainer(
        *container, LogicalSize(130, -1), kLogicalAxesInline);
    EXPECT_EQ("30px", ComputedValueString(target, "height"));
    EXPECT_EQ(0u, GetAnimationsCount(target));

    // Now the transition property appears for the first time. (Final round).
    container->SetInlineStyleProperty(CSSPropertyID::kWidth, "140px");
    UpdateAllLifecyclePhasesForTest();
    EXPECT_EQ("25px", ComputedValueString(target, "height"));
    EXPECT_EQ(0u, GetAnimationsCount(target));

    EXPECT_FALSE(post_style_update_scope.Apply());
  }

  // Animation count should be updated after PostStyleUpdateScope::Apply.
  EXPECT_EQ(1u, GetAnimationsCount(target));

  // Verify that the newly-updated Animation produces the correct value.
  target->SetNeedsAnimationStyleRecalc();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ("25px", ComputedValueString(target, "height"));
}

TEST_F(ContainerQueryTest, TransitionTemporarilyAppearing) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #container {
        container-type: inline-size;
        width: 20px;
      }
      #target {
        height: 10px;
      }
      @container (width: 120px) {
        #target { height: 20px; }
      }
      @container (width: 130px) {
        #target {
          height: 90px;
          transition: height steps(2, start) 100s;
        }
      }
      @container (width: 140px) {
        #target { height: 40px; }
      }
    </style>
    <div id=container>
      <div id=target>
      </div>
    </div>
  )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  ASSERT_TRUE(container);

  EXPECT_EQ("10px", ComputedValueString(target, "height"));
  EXPECT_EQ(0u, GetAnimationsCount(target));

  // Simulate a style and layout pass with multiple rounds of style recalc.
  {
    PostStyleUpdateScope post_style_update_scope(GetDocument());

    // No transition property present yet. (Intermediate round).
    GetDocument().GetStyleEngine().UpdateStyleAndLayoutTreeForContainer(
        *container, LogicalSize(120, -1), kLogicalAxesInline);
    EXPECT_EQ("20px", ComputedValueString(target, "height"));
    EXPECT_EQ(0u, GetAnimationsCount(target));

    // Transition between [10px, 90px]. (Intermediate round).
    GetDocument().GetStyleEngine().UpdateStyleAndLayoutTreeForContainer(
        *container, LogicalSize(130, -1), kLogicalAxesInline);
    EXPECT_EQ("50px", ComputedValueString(target, "height"));
    EXPECT_EQ(0u, GetAnimationsCount(target));

    // The transition property disappeared again. (Final round).
    container->SetInlineStyleProperty(CSSPropertyID::kWidth, "140px");
    UpdateAllLifecyclePhasesForTest();
    EXPECT_EQ("40px", ComputedValueString(target, "height"));
    EXPECT_EQ(0u, GetAnimationsCount(target));

    EXPECT_FALSE(post_style_update_scope.Apply());
  }

  // Animation count should be updated after PostStyleUpdateScope::Apply.
  // We ultimately ended up with no transition, hence we should have no
  // Animations on the element.
  EXPECT_EQ(0u, GetAnimationsCount(target));
}

TEST_F(ContainerQueryTest, RedefiningAnimations) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @keyframes anim {
        from { height: 0px; }
        to { height: 100px; }
      }
      #container {
        container-type: inline-size;
        width: 10px;
      }
      @container (width: 120px) {
        #target {
          animation: anim 10s -2s linear paused;
        }
      }
      @container (width: 130px) {
        #target {
          animation: anim 10s -3s linear paused;
        }
      }
      @container (width: 140px) {
        #target {
          animation: anim 10s -4s linear paused;
        }
      }
    </style>
    <div id=container>
      <div id=target>
      </div>
    </div>
  )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  ASSERT_TRUE(container);

  EXPECT_EQ("auto", ComputedValueString(target, "height"));

  // Simulate a style and layout pass with multiple rounds of style recalc.
  {
    PostStyleUpdateScope post_style_update_scope(GetDocument());

    // Animation at 20%. (Intermediate round).
    GetDocument().GetStyleEngine().UpdateStyleAndLayoutTreeForContainer(
        *container, LogicalSize(120, -1), kLogicalAxesInline);
    EXPECT_EQ("20px", ComputedValueString(target, "height"));
    EXPECT_EQ(0u, GetAnimationsCount(target));

    // Animation at 30%. (Intermediate round).
    GetDocument().GetStyleEngine().UpdateStyleAndLayoutTreeForContainer(
        *container, LogicalSize(130, -1), kLogicalAxesInline);
    EXPECT_EQ("30px", ComputedValueString(target, "height"));
    EXPECT_EQ(0u, GetAnimationsCount(target));

    // Animation at 40%. (Final round).
    container->SetInlineStyleProperty(CSSPropertyID::kWidth, "140px");
    UpdateAllLifecyclePhasesForTest();
    EXPECT_EQ("40px", ComputedValueString(target, "height"));
    EXPECT_EQ(0u, GetAnimationsCount(target));

    EXPECT_FALSE(post_style_update_scope.Apply());
  }

  // Animation count should be updated after PostStyleUpdateScope::Apply.
  EXPECT_EQ(1u, GetAnimationsCount(target));

  // Verify that the newly-updated Animation produces the correct value.
  target->SetNeedsAnimationStyleRecalc();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ("40px", ComputedValueString(target, "height"));
}

TEST_F(ContainerQueryTest, UnsetAnimation) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @keyframes anim {
        from { height: 0px; }
        to { height: 100px; }
      }
      #container {
        container-type: inline-size;
        width: 10px;
      }
      #target {
        animation: anim 10s -2s linear paused;
      }
      @container (width: 130px) {
        #target {
          animation: unset;
        }
      }
    </style>
    <div id=container>
      <div id=target>
      </div>
    </div>
  )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  Element* target = GetDocument()
"""


```
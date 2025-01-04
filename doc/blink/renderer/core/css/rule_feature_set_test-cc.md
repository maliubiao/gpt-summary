Response:
The user wants me to analyze the provided C++ source code file `rule_feature_set_test.cc`.
This is the first part of a four-part request, so I should focus on providing a general overview of the file's purpose.

Here's a breakdown of the thought process to achieve the desired output:

1. **Identify the core purpose:** The filename `rule_feature_set_test.cc` strongly suggests this file contains unit tests for the `RuleFeatureSet` class. The `#include` directives confirm this, showing includes for testing frameworks (`gtest`) and related Blink classes (`RuleFeatureSet`).

2. **Relate to web technologies:** Consider how `RuleFeatureSet` interacts with web technologies. CSS rules are fundamental to styling web pages. Therefore, `RuleFeatureSet` likely plays a role in how Blink processes and applies CSS. Keywords like "selector," "property," and "invalidation" in the code snippets reinforce this connection.

3. **Explain the connection to specific technologies (JavaScript, HTML, CSS):**
    * **CSS:** This is the most direct connection. The tests manipulate CSS selectors and properties, demonstrating how `RuleFeatureSet` analyzes CSS rules.
    * **HTML:** CSS rules target HTML elements. The tests set up a simple HTML structure (`document_`, `body()`) to simulate the context in which CSS rules operate.
    * **JavaScript:** While this specific test file doesn't directly execute JavaScript, CSS and JavaScript often interact. JavaScript can dynamically modify CSS classes or styles, which would then be processed by components like `RuleFeatureSet`.

4. **Illustrate with examples:**  Provide concrete examples of how the code might relate to web development scenarios. This makes the explanation more tangible. For instance, show how a CSS rule like `.my-class { color: red; }` would be analyzed.

5. **Consider logical reasoning (input/output):**  Although this is a *test* file, try to deduce the logical flow being tested. The `CollectFeatures` methods are key. They take CSS selectors as input and presumably determine some features relevant to those selectors. The `InvalidationLists` and the `CollectInvalidationSetsFor...` methods suggest the output is information about how changes to the DOM might invalidate cached styles. Provide a simplified example of this.

6. **Identify potential user errors:** Think about common mistakes developers make when working with CSS that could be related to the functionality being tested. Incorrect CSS syntax or overly complex selectors are good examples.

7. **Trace user actions:** Describe how a developer might end up looking at this test file. Debugging CSS issues or contributing to Blink's rendering engine are plausible scenarios.

8. **Summarize the functionality:**  Provide a concise summary of the file's purpose based on the analysis.

9. **Address the "part 1 of 4" instruction:** Explicitly state that this is a summary of the first part and that further details will likely emerge in subsequent parts.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus solely on the technical aspects of the C++ code.
* **Correction:**  Shift the focus to explaining the *purpose* of the code in the context of web development. Emphasize the relationship to CSS, HTML, and JavaScript.
* **Initial thought:**  Simply list the classes and methods used.
* **Correction:** Explain *what* those classes and methods do and *why* they are important. Use analogies and simpler terms where possible.
* **Initial thought:** Provide very low-level details of the C++ implementation.
* **Correction:**  Keep the explanation at a higher level, focusing on the *functionality* being tested rather than the specific implementation details. The user is likely interested in the *what* and *why*, not necessarily the *how* at this stage.
好的，让我们来分析一下 `blink/renderer/core/css/rule_feature_set_test.cc` 这个文件的功能。

**文件功能归纳：**

`rule_feature_set_test.cc` 是 Chromium Blink 引擎中用于测试 `RuleFeatureSet` 类功能的单元测试文件。它的主要目的是验证 `RuleFeatureSet` 类是否能够正确地从 CSS 规则（特别是其中的选择器）中提取出用于优化样式计算的关键特征，并生成相应的失效集合（Invalidation Sets）。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个文件与 CSS 的关系最为直接，因为它处理的是 CSS 规则的解析和分析。同时，由于 CSS 作用于 HTML 元素，并且可以通过 JavaScript 动态修改，所以它也间接地与 HTML 和 JavaScript 有关。

* **CSS:**
    * **功能关系：** `RuleFeatureSet` 的核心任务是分析 CSS 选择器，例如类选择器 (`.class`)、ID 选择器 (`#id`)、标签选择器 (`div`)、属性选择器 (`[attr]`)、伪类选择器 (`:hover`) 等，以及各种组合选择器（例如后代选择器、子选择器、相邻兄弟选择器、通用兄弟选择器）。
    * **举例说明：** 文件中的测试用例会创建各种 CSS 选择器字符串，例如 `".p"`, `".o + .p"`, `":-webkit-any(.q, .r) ~ .s .t"`，然后调用 `CollectFeatures` 方法来提取这些选择器的特征。这些特征会被用来判断哪些 DOM 元素需要因为 CSS 规则的变化而重新计算样式。

* **HTML:**
    * **功能关系：** CSS 规则最终会应用到 HTML 元素上。`RuleFeatureSet` 分析出的特征会影响到当 HTML 结构或元素的属性发生变化时，哪些 CSS 规则需要重新匹配。
    * **举例说明：** 文件中的 `SetUp` 方法会创建一个简单的 HTML 文档结构 `<b><i></i></b>`。在测试中，会模拟 HTML 元素上的类名、ID 或属性的变化，并通过 `CollectInvalidationSetsForClass`、`CollectInvalidationSetsForId` 等方法来验证 `RuleFeatureSet` 是否正确地识别出哪些 CSS 规则会受到影响。

* **JavaScript:**
    * **功能关系：** JavaScript 可以动态地修改 HTML 元素的类名、ID、属性或样式。当这些修改发生时，Blink 引擎需要判断哪些 CSS 规则需要重新应用。`RuleFeatureSet` 提供的特征信息能够帮助优化这个过程。
    * **举例说明：** 假设 JavaScript 代码使用了 `element.classList.add('new-class')` 来给一个元素添加了一个新的类名。`RuleFeatureSet` 预先提取的关于类选择器的信息会帮助 Blink 快速判断哪些包含 `.new-class` 选择器的 CSS 规则需要重新考虑是否匹配该元素。

**逻辑推理 (假设输入与输出):**

`CollectFeatures` 方法是核心。它接收一个 CSS 选择器字符串作为输入，输出一个 `SelectorPreMatch` 枚举值，表明该选择器是否可能匹配元素。更重要的是，它还会将选择器中包含的特征信息存储到 `rule_feature_set_` 成员变量中。

**假设输入：** CSS 选择器字符串 `".my-class > div"`
**输出：**
* `SelectorPreMatch::kMayMatch` (因为该选择器有可能匹配某些 HTML 结构)
* `rule_feature_set_` 内部会记录包含类选择器 `.my-class` 和标签选择器 `div` 的信息，以及它们之间的子元素关系。

**假设输入：** CSS 选择器字符串 `"#my-id"`
**输出：**
* `SelectorPreMatch::kMayMatch`
* `rule_feature_set_` 内部会记录包含 ID 选择器 `#my-id` 的信息。

**涉及用户或者编程常见的使用错误（作为调试线索）：**

这个测试文件本身是用于确保 Blink 引擎内部逻辑的正确性，用户或编程错误通常发生在编写 CSS 或 JavaScript 代码时。但是，通过分析这个测试文件，可以帮助理解某些 CSS 特性可能带来的性能影响或行为。

* **复杂的 CSS 选择器：**  如果用户编写了非常复杂的 CSS 选择器（例如嵌套 बहुत अधिक 的伪类和属性选择器），`RuleFeatureSet` 可能会提取出大量的特征信息，这可能会增加样式计算的开销。测试用例中包含各种复杂的选择器组合，可以帮助开发者理解哪些类型的选择器会触发哪些类型的失效。
* **过度使用 `*` 通配符或属性选择器：**  虽然 `RuleFeatureSet` 可以处理这些选择器，但过度使用它们可能会导致更频繁和更广泛的样式失效。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为一个普通的 Web 开发者，你可能不会直接接触到这个 C++ 测试文件。但是，当你遇到与 CSS 样式失效或性能相关的问题时，Blink 引擎的开发者可能会使用这些测试用例作为调试线索。

1. **用户反馈样式问题：** 用户报告某个网页的样式在特定情况下没有正确应用，或者性能很慢。
2. **开发者复现问题：** Blink 引擎的开发者尝试在本地复现用户报告的问题。
3. **怀疑是 CSS 规则失效问题：** 开发者可能会怀疑是由于某些 CSS 规则的失效机制没有正确工作导致样式没有及时更新。
4. **查看相关代码：** 开发者可能会查看 `RuleFeatureSet` 相关的代码，包括这个测试文件，以理解其内部逻辑和已有的测试覆盖情况。
5. **运行测试用例：** 开发者可以运行这个测试文件中的特定用例，或者编写新的测试用例来验证他们对问题的假设。
6. **修改代码并验证：** 如果发现测试用例失败，开发者会修改 `RuleFeatureSet` 或相关的代码，并重新运行测试以确保修复了问题。

**第1部分功能归纳:**

总而言之，`rule_feature_set_test.cc` (第 1 部分) 的主要功能是：

* **测试 `RuleFeatureSet` 类的基本功能：** 验证它是否能够正确地从简单的 CSS 选择器中提取特征。
* **验证基本失效集合的生成：** 确认对于简单的选择器，能够生成正确的自失效（self-invalidation）集合。
* **覆盖基本的选择器类型：**  测试了类选择器、相邻兄弟选择器以及简单的后代选择器。

接下来的部分很可能会扩展测试的覆盖范围，包括更复杂的选择器、伪类、伪元素以及与其他 Blink 引擎组件的交互。

Prompt: 
```
这是目录为blink/renderer/core/css/rule_feature_set_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/rule_feature_set.h"

#include "base/test/scoped_feature_list.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_selector_list.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/invalidation/invalidation_set.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/rule_set.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

using testing::AssertionFailure;
using testing::AssertionResult;
using testing::AssertionSuccess;

namespace blink {

class RuleFeatureSetTest : public testing::Test {
 public:
  RuleFeatureSetTest() = default;

  void SetUp() override {
    document_ =
        HTMLDocument::CreateForTest(execution_context_.GetExecutionContext());
    auto* html = MakeGarbageCollected<HTMLHtmlElement>(*document_);
    html->AppendChild(MakeGarbageCollected<HTMLBodyElement>(*document_));
    document_->AppendChild(html);

    document_->body()->setInnerHTML("<b><i></i></b>");
  }

  SelectorPreMatch CollectFeatures(
      const String& selector_text,
      CSSNestingType nesting_type = CSSNestingType::kNone,
      StyleRule* parent_rule_for_nesting = nullptr) {
    return CollectFeaturesTo(selector_text, rule_feature_set_, nesting_type,
                             parent_rule_for_nesting);
  }

  SelectorPreMatch CollectFeatures(StyleRule* style_rule,
                                   const StyleScope* style_scope) {
    return CollectFeaturesTo(style_rule, style_scope, rule_feature_set_);
  }

  static SelectorPreMatch CollectFeaturesTo(
      base::span<CSSSelector> selector_vector,
      const StyleScope* style_scope,
      RuleFeatureSet& set) {
    if (selector_vector.empty()) {
      return SelectorPreMatch::kNeverMatches;
    }

    auto* style_rule = StyleRule::Create(
        selector_vector,
        MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode));
    return CollectFeaturesTo(style_rule, style_scope, set);
  }

  static SelectorPreMatch CollectFeaturesTo(StyleRule* style_rule,
                                            const StyleScope* style_scope,
                                            RuleFeatureSet& set) {
    SelectorPreMatch result = SelectorPreMatch::kNeverMatches;
    for (const CSSSelector* s = style_rule->FirstSelector(); s;
         s = CSSSelectorList::Next(*s)) {
      if (set.CollectFeaturesFromSelector(*s, style_scope) ==
          SelectorPreMatch::kMayMatch) {
        result = SelectorPreMatch::kMayMatch;
      }
    }
    return result;
  }

  static SelectorPreMatch CollectFeaturesTo(
      const String& selector_text,
      RuleFeatureSet& set,
      CSSNestingType nesting_type,
      StyleRule* parent_rule_for_nesting) {
    HeapVector<CSSSelector> arena;
    base::span<CSSSelector> selector_vector = CSSParser::ParseSelector(
        StrictCSSParserContext(SecureContextMode::kInsecureContext),
        nesting_type, parent_rule_for_nesting, false /* is_within_scope */,
        nullptr, selector_text, arena);
    return CollectFeaturesTo(selector_vector, nullptr /* style_scope */, set);
  }

  void ClearFeatures() { rule_feature_set_.Clear(); }

  void CollectInvalidationSetsForClass(InvalidationLists& invalidation_lists,
                                       const char* class_name) const {
    Element* element = Traversal<HTMLElement>::FirstChild(
        *Traversal<HTMLElement>::FirstChild(*document_->body()));
    rule_feature_set_.GetRuleInvalidationData().CollectInvalidationSetsForClass(
        invalidation_lists, *element, AtomicString(class_name));
  }

  void CollectInvalidationSetsForId(InvalidationLists& invalidation_lists,
                                    const char* id) const {
    Element* element = Traversal<HTMLElement>::FirstChild(
        *Traversal<HTMLElement>::FirstChild(*document_->body()));
    rule_feature_set_.GetRuleInvalidationData().CollectInvalidationSetsForId(
        invalidation_lists, *element, AtomicString(id));
  }

  void CollectInvalidationSetsForAttribute(
      InvalidationLists& invalidation_lists,
      const QualifiedName& attribute_name) const {
    Element* element = Traversal<HTMLElement>::FirstChild(
        *Traversal<HTMLElement>::FirstChild(*document_->body()));
    rule_feature_set_.GetRuleInvalidationData()
        .CollectInvalidationSetsForAttribute(invalidation_lists, *element,
                                             attribute_name);
  }

  void CollectInvalidationSetsForPseudoClass(
      InvalidationLists& invalidation_lists,
      CSSSelector::PseudoType pseudo) const {
    Element* element = Traversal<HTMLElement>::FirstChild(
        *Traversal<HTMLElement>::FirstChild(*document_->body()));
    rule_feature_set_.GetRuleInvalidationData()
        .CollectInvalidationSetsForPseudoClass(invalidation_lists, *element,
                                               pseudo);
  }

  void CollectPartInvalidationSet(InvalidationLists& invalidation_lists) const {
    rule_feature_set_.GetRuleInvalidationData().CollectPartInvalidationSet(
        invalidation_lists);
  }

  void CollectUniversalSiblingInvalidationSet(
      InvalidationLists& invalidation_lists) {
    rule_feature_set_.GetRuleInvalidationData()
        .CollectUniversalSiblingInvalidationSet(invalidation_lists, 1);
  }

  void CollectNthInvalidationSet(InvalidationLists& invalidation_lists) {
    rule_feature_set_.GetRuleInvalidationData().CollectNthInvalidationSet(
        invalidation_lists);
  }

  bool NeedsHasInvalidationForClass(const char* class_name) {
    return rule_feature_set_.GetRuleInvalidationData()
        .NeedsHasInvalidationForClass(AtomicString(class_name));
  }

  void MergeInto(RuleFeatureSet& rule_feature_set) {
    rule_feature_set.Merge(rule_feature_set_);
  }

  using BackingType = InvalidationSet::BackingType;

  template <BackingType type>
  HashSet<AtomicString> ToHashSet(
      typename InvalidationSet::Backing<type>::Range range) {
    HashSet<AtomicString> hash_set;
    for (auto str : range) {
      hash_set.insert(str);
    }
    return hash_set;
  }

  HashSet<AtomicString> ClassSet(const InvalidationSet& invalidation_set) {
    return ToHashSet<BackingType::kClasses>(invalidation_set.Classes());
  }

  HashSet<AtomicString> IdSet(const InvalidationSet& invalidation_set) {
    return ToHashSet<BackingType::kIds>(invalidation_set.Ids());
  }

  HashSet<AtomicString> TagNameSet(const InvalidationSet& invalidation_set) {
    return ToHashSet<BackingType::kTagNames>(invalidation_set.TagNames());
  }

  HashSet<AtomicString> AttributeSet(const InvalidationSet& invalidation_set) {
    return ToHashSet<BackingType::kAttributes>(invalidation_set.Attributes());
  }

  AssertionResult HasNoInvalidation(InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 0) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 0";
    }
    return AssertionSuccess();
  }

  AssertionResult HasSelfInvalidation(
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    if (!invalidation_sets[0]->InvalidatesSelf()) {
      return AssertionFailure() << "should invalidate self";
    }
    return AssertionSuccess();
  }

  AssertionResult HasNoSelfInvalidation(
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    if (invalidation_sets[0]->InvalidatesSelf()) {
      return AssertionFailure() << "should not invalidate self";
    }
    return AssertionSuccess();
  }

  AssertionResult HasSelfInvalidationSet(
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    if (!invalidation_sets[0]->IsSelfInvalidationSet()) {
      return AssertionFailure() << "should be the self-invalidation set";
    }
    return AssertionSuccess();
  }

  AssertionResult HasNotSelfInvalidationSet(
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    if (invalidation_sets[0]->IsSelfInvalidationSet()) {
      return AssertionFailure() << "should not be the self-invalidation set";
    }
    return AssertionSuccess();
  }

  AssertionResult HasWholeSubtreeInvalidation(
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    if (!invalidation_sets[0]->WholeSubtreeInvalid()) {
      return AssertionFailure() << "should invalidate whole subtree";
    }
    return AssertionSuccess();
  }

  AssertionResult HasClassInvalidation(
      const char* class_name,
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    HashSet<AtomicString> classes = ClassSet(*invalidation_sets[0]);
    if (classes.size() != 1u) {
      return AssertionFailure() << classes.size() << " should be 1";
    }
    if (!classes.Contains(AtomicString(class_name))) {
      return AssertionFailure() << "should invalidate class " << class_name;
    }
    return AssertionSuccess();
  }

  AssertionResult HasClassInvalidation(
      const char* first_class_name,
      const char* second_class_name,
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    HashSet<AtomicString> classes = ClassSet(*invalidation_sets[0]);
    if (classes.size() != 2u) {
      return AssertionFailure() << classes.size() << " should be 2";
    }
    if (!classes.Contains(AtomicString(first_class_name))) {
      return AssertionFailure()
             << "should invalidate class " << first_class_name;
    }
    if (!classes.Contains(AtomicString(second_class_name))) {
      return AssertionFailure()
             << "should invalidate class " << second_class_name;
    }
    return AssertionSuccess();
  }

  AssertionResult HasClassInvalidation(
      const AtomicString& first_class_name,
      const AtomicString& second_class_name,
      const AtomicString& third_class_name,
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    HashSet<AtomicString> classes = ClassSet(*invalidation_sets[0]);
    if (classes.size() != 3u) {
      return AssertionFailure() << classes.size() << " should be 3";
    }
    if (!classes.Contains(first_class_name)) {
      return AssertionFailure()
             << "should invalidate class " << first_class_name;
    }
    if (!classes.Contains(second_class_name)) {
      return AssertionFailure()
             << "should invalidate class " << second_class_name;
    }
    if (!classes.Contains(third_class_name)) {
      return AssertionFailure()
             << "should invalidate class " << third_class_name;
    }
    return AssertionSuccess();
  }

  AssertionResult HasSiblingClassInvalidation(
      unsigned max_direct_adjacent_selectors,
      const char* sibling_name,
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    const auto& sibling_invalidation_set =
        To<SiblingInvalidationSet>(*invalidation_sets[0]);
    HashSet<AtomicString> classes = ClassSet(sibling_invalidation_set);
    if (classes.size() != 1u) {
      return AssertionFailure() << classes.size() << " should be 1";
    }
    if (!classes.Contains(AtomicString(sibling_name))) {
      return AssertionFailure()
             << "should invalidate sibling id " << sibling_name;
    }
    if (sibling_invalidation_set.MaxDirectAdjacentSelectors() !=
        max_direct_adjacent_selectors) {
      return AssertionFailure()
             << sibling_invalidation_set.MaxDirectAdjacentSelectors()
             << " should be " << max_direct_adjacent_selectors;
    }
    return AssertionSuccess();
  }

  AssertionResult HasSiblingIdInvalidation(
      unsigned max_direct_adjacent_selectors,
      const char* sibling_name,
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    const auto& sibling_invalidation_set =
        To<SiblingInvalidationSet>(*invalidation_sets[0]);
    HashSet<AtomicString> ids = IdSet(*invalidation_sets[0]);
    if (ids.size() != 1u) {
      return AssertionFailure() << ids.size() << " should be 1";
    }
    if (!ids.Contains(AtomicString(sibling_name))) {
      return AssertionFailure()
             << "should invalidate sibling id " << sibling_name;
    }
    if (sibling_invalidation_set.MaxDirectAdjacentSelectors() !=
        max_direct_adjacent_selectors) {
      return AssertionFailure()
             << sibling_invalidation_set.MaxDirectAdjacentSelectors()
             << " should be " << max_direct_adjacent_selectors;
    }
    return AssertionSuccess();
  }

  AssertionResult HasSiblingDescendantInvalidation(
      unsigned max_direct_adjacent_selectors,
      const char* sibling_name,
      const char* descendant_name,
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    const auto& sibling_invalidation_set =
        To<SiblingInvalidationSet>(*invalidation_sets[0]);
    HashSet<AtomicString> classes = ClassSet(sibling_invalidation_set);
    if (classes.size() != 1u) {
      return AssertionFailure() << classes.size() << " should be 1";
    }
    if (!classes.Contains(AtomicString(sibling_name))) {
      return AssertionFailure()
             << "classes.Contains(sibling_name) should be true";
    }
    if (sibling_invalidation_set.MaxDirectAdjacentSelectors() !=
        max_direct_adjacent_selectors) {
      return AssertionFailure()
             << sibling_invalidation_set.MaxDirectAdjacentSelectors()
             << " should be " << max_direct_adjacent_selectors;
    }

    HashSet<AtomicString> descendant_classes =
        ClassSet(*sibling_invalidation_set.SiblingDescendants());
    if (descendant_classes.size() != 1u) {
      return AssertionFailure() << descendant_classes.size() << " should be 1";
    }
    if (!descendant_classes.Contains(AtomicString(descendant_name))) {
      return AssertionFailure()
             << "should invalidate descendant class " << descendant_name;
    }
    return AssertionSuccess();
  }

  AssertionResult HasSiblingDescendantInvalidation(
      unsigned max_direct_adjacent_selectors,
      const char* descendant_name,
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    const auto& sibling_invalidation_set =
        To<SiblingInvalidationSet>(*invalidation_sets[0]);
    if (!sibling_invalidation_set.WholeSubtreeInvalid()) {
      return AssertionFailure() << "should sibling-invalidate whole subtree";
    }
    if (sibling_invalidation_set.MaxDirectAdjacentSelectors() !=
        max_direct_adjacent_selectors) {
      return AssertionFailure()
             << sibling_invalidation_set.MaxDirectAdjacentSelectors()
             << " should be " << max_direct_adjacent_selectors;
    }
    if (!sibling_invalidation_set.SiblingDescendants()) {
      return AssertionFailure() << "sibling set should have descendants";
    }
    HashSet<AtomicString> descendant_classes =
        ClassSet(*sibling_invalidation_set.SiblingDescendants());
    if (descendant_classes.size() != 1u) {
      return AssertionFailure() << descendant_classes.size() << " should be 1";
    }
    if (!descendant_classes.Contains(AtomicString(descendant_name))) {
      return AssertionFailure()
             << "should descendant invalidate " << descendant_name;
    }
    return AssertionSuccess();
  }

  AssertionResult
  HasSiblingAndSiblingDescendantInvalidationForLogicalCombinationsInHas(
      const char* sibling_name,
      const char* sibling_name_for_sibling_descendant,
      const char* descendant_name,
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    const auto& sibling_invalidation_set =
        To<SiblingInvalidationSet>(*invalidation_sets[0]);
    HashSet<AtomicString> classes = ClassSet(sibling_invalidation_set);
    if (classes.size() != 2u) {
      return AssertionFailure() << classes.size() << " should be 2";
    }
    if (!classes.Contains(AtomicString(sibling_name))) {
      return AssertionFailure() << "should sibling invalidate " << sibling_name;
    }
    if (!classes.Contains(AtomicString(sibling_name_for_sibling_descendant))) {
      return AssertionFailure() << "should sibling invalidate "
                                << sibling_name_for_sibling_descendant;
    }
    if (sibling_invalidation_set.MaxDirectAdjacentSelectors() !=
        SiblingInvalidationSet::kDirectAdjacentMax) {
      return AssertionFailure()
             << sibling_invalidation_set.MaxDirectAdjacentSelectors()
             << " should be " << SiblingInvalidationSet::kDirectAdjacentMax;
    }

    HashSet<AtomicString> descendant_classes =
        ClassSet(*sibling_invalidation_set.SiblingDescendants());
    if (descendant_classes.size() != 1u) {
      return AssertionFailure() << descendant_classes.size() << " should be 1";
    }
    if (!descendant_classes.Contains(AtomicString(descendant_name))) {
      return AssertionFailure()
             << "should descendant invalidate " << descendant_name;
    }
    return AssertionSuccess();
  }

  AssertionResult HasSiblingNoDescendantInvalidation(
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    const auto& sibling_invalidation_set =
        To<SiblingInvalidationSet>(*invalidation_sets[0]);
    if (sibling_invalidation_set.SiblingDescendants()) {
      return AssertionFailure() << "should have no descendants";
    }
    return AssertionSuccess();
  }

  AssertionResult HasSiblingWholeSubtreeInvalidation(
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    const auto& sibling_invalidation_set =
        To<SiblingInvalidationSet>(*invalidation_sets[0]);
    if (!sibling_invalidation_set.SiblingDescendants()) {
      return AssertionFailure() << "should have a descendant set";
    };
    if (!sibling_invalidation_set.SiblingDescendants()->WholeSubtreeInvalid()) {
      return AssertionFailure()
             << "sibling descendants should invalidate whole subtree";
    }
    return AssertionSuccess();
  }

  AssertionResult HasIdInvalidation(const char* id,
                                    InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    HashSet<AtomicString> ids = IdSet(*invalidation_sets[0]);
    if (ids.size() != 1u) {
      return AssertionFailure() << ids.size() << " should be 1";
    }
    if (!ids.Contains(AtomicString(id))) {
      return AssertionFailure() << "should invalidate id " << id;
    }
    return AssertionSuccess();
  }

  AssertionResult HasIdInvalidation(const char* first_id,
                                    const char* second_id,
                                    InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    HashSet<AtomicString> ids = IdSet(*invalidation_sets[0]);
    if (ids.size() != 2u) {
      return AssertionFailure() << ids.size() << " should be 2";
    }
    if (!ids.Contains(AtomicString(first_id))) {
      return AssertionFailure() << "should invalidate id " << first_id;
    }
    if (!ids.Contains(AtomicString(second_id))) {
      return AssertionFailure() << "should invalidate id " << second_id;
    }
    return AssertionSuccess();
  }

  AssertionResult HasTagNameInvalidation(
      const char* tag_name,
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    HashSet<AtomicString> tag_names = TagNameSet(*invalidation_sets[0]);
    if (tag_names.size() != 1u) {
      return AssertionFailure() << tag_names.size() << " should be 1";
    }
    if (!tag_names.Contains(AtomicString(tag_name))) {
      return AssertionFailure() << "should invalidate tag " << tag_name;
    }
    return AssertionSuccess();
  }

  AssertionResult HasTagNameInvalidation(
      const char* first_tag_name,
      const char* second_tag_name,
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    HashSet<AtomicString> tag_names = TagNameSet(*invalidation_sets[0]);
    if (tag_names.size() != 2u) {
      return AssertionFailure() << tag_names.size() << " should be 2";
    }
    if (!tag_names.Contains(AtomicString(first_tag_name))) {
      return AssertionFailure() << "should invalidate tag " << first_tag_name;
    }
    if (!tag_names.Contains(AtomicString(second_tag_name))) {
      return AssertionFailure() << "should invalidate tag " << second_tag_name;
    }
    return AssertionSuccess();
  }

  AssertionResult HasAttributeInvalidation(
      const char* attribute,
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    HashSet<AtomicString> attributes = AttributeSet(*invalidation_sets[0]);
    if (attributes.size() != 1u) {
      return AssertionFailure() << attributes.size() << " should be 1";
    }
    if (!attributes.Contains(AtomicString(attribute))) {
      return AssertionFailure() << "should invalidate attribute " << attribute;
    }
    return AssertionSuccess();
  }

  AssertionResult HasPartsInvalidation(
      InvalidationSetVector& invalidation_sets) {
    if (invalidation_sets.size() != 1u) {
      return AssertionFailure() << "has " << invalidation_sets.size()
                                << " invalidation set(s), should have 1";
    }
    if (!invalidation_sets[0]->InvalidatesParts()) {
      return AssertionFailure() << "should invalidate parts";
    }
    return AssertionSuccess();
  }

  enum class RefCount { kOne, kMany };

  template <typename MapType, typename KeyType>
  AssertionResult HasRefCountForInvalidationSet(const MapType& map,
                                                const KeyType& key,
                                                RefCount ref_count) {
    auto it = map.find(key);
    if (map.end() == it) {
      return AssertionFailure() << "Could not find " << key;
    }

    if (ref_count == RefCount::kOne) {
      if (!it->value->HasOneRef()) {
        return AssertionFailure() << "should have a single ref";
      }

      // For SiblingInvalidationSets, we also require that the inner
      // InvalidationSets either don't exist, or have a refcount of 1.
      if (it->value->IsSiblingInvalidationSet()) {
        const auto& sibling_invalidation_set =
            To<SiblingInvalidationSet>(*it->value);
        bool sibling_descendants_has_one_ref =
            !sibling_invalidation_set.SiblingDescendants() ||
            sibling_invalidation_set.SiblingDescendants()->HasOneRef();
        bool descendants_has_one_ref =
            !sibling_invalidation_set.Descendants() ||
            sibling_invalidation_set.Descendants()->HasOneRef();
        if (!sibling_descendants_has_one_ref) {
          return AssertionFailure()
                 << "sibling descendants should have a single ref";
        }
        if (!descendants_has_one_ref) {
          return AssertionFailure() << "descendants should have a single ref";
        }
      }
    } else {
      if (it->value->HasOneRef()) {
        return AssertionFailure() << "should be shared";
      }
    }
    return AssertionSuccess();
  }

  AssertionResult HasRefCountForClassInvalidationSet(
      const RuleFeatureSet& rule_feature_set,
      const char* class_name,
      RefCount ref_count) {
    return HasRefCountForInvalidationSet(
        rule_feature_set.GetRuleInvalidationData().class_invalidation_sets,
        AtomicString(class_name), ref_count);
  }

  AssertionResult HasRefCountForAttributeInvalidationSet(
      const RuleFeatureSet& rule_feature_set,
      const char* attribute,
      RefCount ref_count) {
    return HasRefCountForInvalidationSet(
        rule_feature_set.GetRuleInvalidationData().attribute_invalidation_sets,
        AtomicString(attribute), ref_count);
  }

  AssertionResult HasRefCountForIdInvalidationSet(
      const RuleFeatureSet& rule_feature_set,
      const char* id,
      RefCount ref_count) {
    return HasRefCountForInvalidationSet(
        rule_feature_set.GetRuleInvalidationData().id_invalidation_sets,
        AtomicString(id), ref_count);
  }

  AssertionResult HasRefCountForPseudoInvalidationSet(
      const RuleFeatureSet& rule_feature_set,
      CSSSelector::PseudoType key,
      RefCount ref_count) {
    return HasRefCountForInvalidationSet(
        rule_feature_set.GetRuleInvalidationData().pseudo_invalidation_sets,
        key, ref_count);
  }

 protected:
  test::TaskEnvironment task_environment_;
  ScopedNullExecutionContext execution_context_;

 private:
  RuleFeatureSet rule_feature_set_;
  Persistent<Document> document_;
};

TEST_F(RuleFeatureSetTest, interleavedDescendantSibling1) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(".p"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "p");
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, interleavedDescendantSibling2) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(".o + .p"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "o");
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasSiblingClassInvalidation(1, "p", invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, interleavedDescendantSibling3) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(".m + .n .o + .p"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "n");
  EXPECT_TRUE(HasNoSelfInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasClassInvalidation("p", invalidation_lists.descendants));
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, interleavedDescendantSibling4) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(".m + .n .o + .p"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "m");
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasSiblingDescendantInvalidation(1, "n", "p",
                                               invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, interleavedDescendantSibling5) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".l ~ .m + .n .o + .p"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "l");
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasSiblingDescendantInvalidation(
      SiblingInvalidationSet::kDirectAdjacentMax, "n", "p",
      invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, interleavedDescendantSibling6) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".k > .l ~ .m + .n .o + .p"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "k");
  EXPECT_TRUE(HasClassInvalidation("p", invalidation_lists.descendants));
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, anySibling) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(":-webkit-any(.q, .r) ~ .s .t"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "q");
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasSiblingDescendantInvalidation(
      SiblingInvalidationSet::kDirectAdjacentMax, "s", "t",
      invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, any) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(":-webkit-any(.w, .x)"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "w");
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, repeatedAny) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(":-webkit-any(.v, .w):-webkit-any(.x, .y, .z)"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "v");
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "x");
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, anyIdDescendant) {
  EXPECT_EQ(Select
"""


```
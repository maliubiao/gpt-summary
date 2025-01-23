Response:
My thinking process to answer the request about `counter_style_map_test.cc` follows these steps:

1. **Understand the Goal:** The request asks for an explanation of the file's functionality, its relationship to web technologies, logic examples, common errors, and debugging context.

2. **Identify the Core Function:** The filename `counter_style_map_test.cc` and the included header `counter_style_map.h` immediately suggest this file is testing the `CounterStyleMap` class. The presence of `PageTestBase` confirms it's an integration test within the Blink rendering engine.

3. **Analyze the Test Structure:** I observe the standard Google Test structure:
    * A test fixture class `CounterStyleMapTest` inheriting from `PageTestBase`. This indicates it tests interactions within a simulated web page environment.
    * Helper methods like `AttachShadowTo` and `GetCounterStyle` abstract common setup tasks.
    * Multiple `TEST_F` macros, each representing a specific test case for different aspects of `CounterStyleMap`.

4. **Deconstruct Individual Tests:**  I go through each `TEST_F` and interpret its purpose based on the test name and the code within:
    * **`ExtendsUAStyle`**: Tests that an author-defined `@counter-style` can extend a built-in (User-Agent) counter style like `disc`.
    * **`ExtendsAuthorStyle`**: Tests extending another author-defined `@counter-style`.
    * **`ExtendsParentScopeStyle`**: Checks if a counter style in a shadow DOM can extend a style in the main document. This is important for CSS encapsulation.
    * **`ExtendsCyclic`**:  Tests how the system handles cyclic `extends` declarations (it should resolve to `decimal`).
    * **`ExtendsNonexistentStyle`**: Tests the behavior when extending a non-existent style (also resolves to `decimal`).
    * **`FallbackToUAStyle`**: Tests using the `fallback` property to fall back to a UA style.
    * **`FallbackToAuthorStyle`**: Tests falling back to another author-defined style.
    * **`FallbackOnExtends`**: Verifies that the fallback applies even when using `extends`.
    * **`FallbackCyclic`**: Checks handling of cyclic `fallback` (allowed, but broken during text generation).
    * **`FallbackToNonexistentStyle`**: Tests falling back to a non-existent style (resolves to `decimal`).
    * **`UpdateReferencesInChildScope`**: Tests how changes in the parent scope's counter styles affect styles in child (shadow) scopes. This is crucial for ensuring dynamic updates.
    * **`SpeakAsKeywords`**: Tests the `speak-as` descriptor with keyword values (like `auto`, `bullets`, etc.) for accessibility.
    * **`SpeakAsReference`**: Tests `speak-as` referencing other counter styles (both author and UA).
    * **`SpeakAsReferenceLoop`**: Tests the handling of cyclic `speak-as` references (should default to `auto`).

5. **Relate to Web Technologies:** Based on the tested features, I connect them to:
    * **CSS:** The `@counter-style` at-rule, `system`, `extends`, `fallback`, `symbols`, and `speak-as` properties are all CSS features.
    * **HTML:** The tests use HTML structure (elements, shadow DOM) to set up the scenarios.
    * **JavaScript (indirectly):** While not explicitly tested, these CSS features are often used in conjunction with JavaScript for dynamic styling and behavior. The tests manipulate the DOM, which is a core concept in JavaScript.

6. **Construct Logic Examples:** For each test, I create a simplified scenario with input (HTML/CSS) and expected output (the result of the `EXPECT_EQ` assertions). This illustrates the specific functionality being tested.

7. **Identify Potential Errors:** I consider common mistakes developers might make when working with `@counter-style`:
    * Incorrect syntax in `@counter-style` rules.
    * Cyclic `extends` or `fallback` declarations.
    * Referencing non-existent counter styles.
    * Forgetting how scoping works with shadow DOM.
    * Misunderstanding the `speak-as` property and its impact on accessibility.

8. **Explain Debugging Context:**  I describe how a developer might end up examining this test file:
    * Investigating bugs related to list numbering or custom counters.
    * Understanding how `@counter-style` is implemented in Blink.
    * Contributing to the Blink rendering engine.
    * Writing new tests for `@counter-style` features.

9. **Structure the Answer:** I organize the information logically, starting with a general overview and then diving into specifics for each test case. I use clear headings and formatting to make the answer easy to read.

10. **Refine and Review:**  I reread the answer to ensure accuracy, clarity, and completeness, addressing all aspects of the original request. For instance, I made sure to explicitly mention the relationship to CSS properties and how shadow DOM affects counter style resolution.
这个文件 `blink/renderer/core/css/counter_style_map_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `CounterStyleMap` 类的功能。`CounterStyleMap` 负责管理和解析 CSS 中 `@counter-style` 规则定义的自定义计数器样式。

**功能列举:**

该文件的主要功能是验证 `CounterStyleMap` 类的以下能力：

1. **解析 `@counter-style` 规则:** 测试能否正确解析 CSS 中的 `@counter-style` 规则，提取出定义的计数器样式名称、系统（`system`）、扩展（`extends`）、回退（`fallback`）、符号（`symbols`）等属性。
2. **处理 `extends` 关键字:**
   - **继承内置样式:** 验证自定义样式能否正确继承浏览器内置的计数器样式 (User-Agent Stylesheet, UA Style)，例如 `disc`。
   - **继承自定义样式:** 验证自定义样式能否继承其他已定义的自定义样式。
   - **跨作用域继承:** 测试在 Shadow DOM 中定义的样式能否继承父作用域（例如主文档）中定义的样式。
   - **处理循环继承:** 验证当出现循环 `extends` 时，系统如何处理（通常会回退到 `decimal` 样式）。
   - **处理继承不存在的样式:** 验证当继承一个不存在的样式时，系统如何处理（通常会回退到 `decimal` 样式）。
3. **处理 `fallback` 关键字:**
   - **回退到内置样式:** 验证自定义样式能否正确回退到浏览器内置的计数器样式。
   - **回退到自定义样式:** 验证自定义样式能否回退到其他已定义的自定义样式。
   - **`extends` 时的回退:** 测试当样式通过 `extends` 继承，但自身也定义了 `fallback` 时，`fallback` 是否生效。
   - **允许循环回退:** 验证是否允许循环 `fallback` 定义（虽然允许，但在生成计数器文本时会打破循环）。
   - **回退到不存在的样式:** 验证当回退到一个不存在的样式时，系统如何处理（通常会回退到 `decimal` 样式）。
4. **更新子作用域的引用:** 当父作用域中的 `@counter-style` 规则发生变化时，测试子作用域（例如 Shadow DOM）中引用该样式的样式对象是否能正确更新。
5. **处理 `speak-as` 描述符 (Accessibility):**
   - **处理关键字:** 验证能否正确解析 `speak-as` 描述符的关键字值，例如 `auto`、`bullets`、`numbers`、`words`。
   - **处理引用:** 验证 `speak-as` 能否引用其他自定义样式或内置样式。
   - **处理循环引用:** 验证当 `speak-as` 出现循环引用时，系统如何处理（通常会回退到 `auto`）。

**与 Javascript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关系到 **CSS** 的 `@counter-style` 规则。 `@counter-style` 允许开发者自定义列表项的标记样式，超越了传统的数字或符号列表。

**CSS 举例:**

```css
/* 定义一个名为 'lower-roman-custom' 的计数器样式 */
@counter-style lower-roman-custom {
  system: lower-roman; /* 使用小写罗马数字系统 */
  symbols: i ii iii iv v vi vii viii ix; /* 可以自定义符号 */
  suffix: '.'; /* 后缀 */
}

/* 定义一个继承自 'lower-roman-custom' 的计数器样式 */
@counter-style fancy-roman {
  system: extends lower-roman-custom;
  prefix: '第'; /* 前缀 */
  suffix: '章';
}

/* 定义一个带有回退的计数器样式 */
@counter-style my-emoji {
  system: cyclic;
  symbols: 🌟, ✨, 💫;
  fallback: decimal; /* 如果遇到不支持 cyclic 系统的浏览器，回退到 decimal */
}
```

**HTML 举例:**

```html
<ol style="list-style-type: lower-roman-custom;">
  <li>Item 1</li>
  <li>Item 2</li>
</ol>

<ol style="list-style-type: fancy-roman;">
  <li>Introduction</li>
  <li>Main Body</li>
</ol>

<ol style="list-style-type: my-emoji;">
  <li>Task A</li>
  <li>Task B</li>
  <li>Task C</li>
  <li>Task D</li>
</ol>
```

**Javascript 关系 (间接):**

虽然这个测试文件不直接涉及 JavaScript 代码，但 JavaScript 可以通过 DOM API 操作元素的样式，从而间接地影响 `@counter-style` 的应用。例如，JavaScript 可以动态地修改元素的 `list-style-type` 属性来使用不同的自定义计数器样式。

```javascript
const list = document.querySelector('ol');
list.style.listStyleType = 'fancy-roman';
```

**逻辑推理、假设输入与输出:**

**示例 1: 测试 `extends` 功能**

**假设输入 (CSS):**

```css
@counter-style base-style {
  symbols: 'A' 'B' 'C';
}

@counter-style extended-style {
  system: extends base-style;
  suffix: ')';
}
```

**预期输出 (测试结果):**

测试会验证 `extended-style` 计数器样式是否正确地继承了 `base-style` 的 `symbols` 属性，并且拥有了自己的 `suffix` 属性。当使用 `extended-style` 时，列表项的标记应该是 "A)", "B)", "C)" 等。

**示例 2: 测试循环 `extends` 功能**

**假设输入 (CSS):**

```css
@counter-style style-a {
  system: extends style-b;
}

@counter-style style-b {
  system: extends style-a;
}
```

**预期输出 (测试结果):**

测试会验证 `style-a` 和 `style-b` 的 `extends` 是否被解析，但由于是循环引用，最终会回退到默认的 `decimal` 样式。

**用户或编程常见的使用错误及举例说明:**

1. **语法错误:** 在 `@counter-style` 规则中使用了错误的语法，例如拼写错误、缺少分号等。
   ```css
   /* 错误示例 */
   @counter-style my-style {
     system: lower-roman  /* 缺少分号 */
     symbols: '*' '+' '-';
   }
   ```
2. **循环 `extends` 或 `fallback`:**  无意中创建了循环依赖，导致解析错误或行为不符合预期。
   ```css
   /* 错误示例 */
   @counter-style style-x { system: extends style-y; }
   @counter-style style-y { system: extends style-z; }
   @counter-style style-z { system: extends style-x; }
   ```
3. **引用不存在的计数器样式:** 在 `extends` 或 `fallback` 中引用了一个没有定义的计数器样式名称。
   ```css
   /* 错误示例 */
   @counter-style my-style {
     system: extends non-existent-style; /* 'non-existent-style' 未定义 */
   }
   ```
4. **在 Shadow DOM 中作用域问题:**  期望 Shadow DOM 中的样式能继承主文档中的样式，但由于 CSS 作用域的限制，可能需要额外的处理（如测试用例中所示）。
5. **误解 `speak-as` 的作用:**  不理解 `speak-as` 属性对辅助技术 (例如屏幕阅读器) 的影响，可能导致内容的可访问性问题。

**用户操作如何一步步到达这里 (调试线索):**

假设开发者在开发网页时遇到了与自定义列表样式相关的问题，例如：

1. **列表样式没有按预期显示:** 用户定义的 `@counter-style` 没有生效，或者回退到了默认样式。
2. **继承或回退行为不符合预期:**  自定义样式没有正确地继承或回退到指定的样式。
3. **Shadow DOM 中的样式问题:**  在使用了 Shadow DOM 的组件中，自定义列表样式的行为不一致。
4. **可访问性问题:**  使用自定义计数器样式后，屏幕阅读器无法正确朗读列表项。

为了调试这些问题，开发者可能会：

1. **检查浏览器的开发者工具:** 查看 "Elements" 面板中的 "Computed" 样式，确认 `@counter-style` 是否被正确解析和应用。查看 "Sources" 面板，查看 CSS 文件的加载情况。
2. **查阅 CSS 规范和浏览器文档:**  理解 `@counter-style` 的语法和行为。
3. **搜索相关的 bug 报告和技术文章:**  了解已知的问题和最佳实践。
4. **尝试简化问题:** 创建最小化的测试用例，逐步排除代码中的干扰因素。
5. **如果怀疑是浏览器引擎的 bug，或者想了解其内部实现:**  可能会查看 Chromium 的源代码，包括 `counter_style_map_test.cc` 这样的测试文件，来理解 `@counter-style` 的实现原理和测试覆盖范围。阅读这些测试用例可以帮助理解各种场景下 `CounterStyleMap` 的行为。

总之，`blink/renderer/core/css/counter_style_map_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎正确地实现了 CSS 的 `@counter-style` 功能，这对于实现丰富的自定义列表样式至关重要。理解这个文件的内容可以帮助开发者更好地理解和使用 `@counter-style`，也能帮助他们在遇到相关问题时进行有效的调试。

### 提示词
```
这是目录为blink/renderer/core/css/counter_style_map_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/counter_style_map.h"

#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

class CounterStyleMapTest : public PageTestBase {
 public:
  ShadowRoot& AttachShadowTo(const char* host_id) {
    Element* host = GetElementById(host_id);
    return host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  }

  const CounterStyle& GetCounterStyle(const TreeScope& scope,
                                      const char* name) {
    return *CounterStyleMap::GetAuthorCounterStyleMap(scope)
                ->counter_styles_.at(AtomicString(name));
  }
};

TEST_F(CounterStyleMapTest, ExtendsUAStyle) {
  SetHtmlInnerHTML(R"HTML(
    <style> @counter-style foo { system: extends disc; } </style>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  const CounterStyle& foo = GetCounterStyle(GetDocument(), "foo");
  EXPECT_EQ("disc", foo.GetExtendedStyle().GetName());
}

TEST_F(CounterStyleMapTest, ExtendsAuthorStyle) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      @counter-style foo { symbols: 'X'; }
      @counter-style bar { system: extends foo; }
    </style>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  const CounterStyle& bar = GetCounterStyle(GetDocument(), "bar");
  EXPECT_EQ("foo", bar.GetExtendedStyle().GetName());
}

TEST_F(CounterStyleMapTest, ExtendsParentScopeStyle) {
  SetHtmlInnerHTML(R"HTML(
    <style> @counter-style foo { symbols: 'X'; } </style>
    <div id=host></div>
  )HTML");
  ShadowRoot& shadow = AttachShadowTo("host");
  shadow.setInnerHTML(
      "<style>@counter-style bar { system: extends foo; }</style>");
  UpdateAllLifecyclePhasesForTest();

  const CounterStyle& bar = GetCounterStyle(shadow, "bar");
  EXPECT_EQ("foo", bar.GetExtendedStyle().GetName());
}

TEST_F(CounterStyleMapTest, ExtendsCyclic) {
  // Cyclic extends resolve to 'decimal'.
  SetHtmlInnerHTML(R"HTML(
    <style>
      @counter-style foo { system: extends bar; }
      @counter-style bar { system: extends baz; }
      @counter-style baz { system: extends bar; }
    </style>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  const CounterStyle& foo = GetCounterStyle(GetDocument(), "foo");
  EXPECT_EQ("bar", foo.GetExtendedStyle().GetName());

  const CounterStyle& bar = GetCounterStyle(GetDocument(), "bar");
  EXPECT_EQ("decimal", bar.GetExtendedStyle().GetName());

  const CounterStyle& baz = GetCounterStyle(GetDocument(), "baz");
  EXPECT_EQ("decimal", baz.GetExtendedStyle().GetName());
}

TEST_F(CounterStyleMapTest, ExtendsNonexistentStyle) {
  // Extending non-existent style resolves to 'decimal'.
  SetHtmlInnerHTML(R"HTML(
    <style>
      @counter-style foo { system: extends bar; }
      @counter-style bar { system: extends baz; }
    </style>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  const CounterStyle& foo = GetCounterStyle(GetDocument(), "foo");
  EXPECT_EQ("bar", foo.GetExtendedStyle().GetName());

  const CounterStyle& bar = GetCounterStyle(GetDocument(), "bar");
  EXPECT_EQ("decimal", bar.GetExtendedStyle().GetName());
}

TEST_F(CounterStyleMapTest, FallbackToUAStyle) {
  SetHtmlInnerHTML(R"HTML(
    <style> @counter-style foo { symbols: 'X'; fallback: disc; } </style>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  const CounterStyle& foo = GetCounterStyle(GetDocument(), "foo");
  EXPECT_EQ("disc", foo.GetFallbackStyle().GetName());
}

TEST_F(CounterStyleMapTest, FallbackToAuthorStyle) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      @counter-style foo { symbols: 'X'; }
      @counter-style bar { symbols: 'Y'; fallback: foo; }
    </style>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  const CounterStyle& bar = GetCounterStyle(GetDocument(), "bar");
  EXPECT_EQ("foo", bar.GetFallbackStyle().GetName());
}

TEST_F(CounterStyleMapTest, FallbackOnExtends) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      @counter-style foo { symbols: 'X'; fallback: disc; }
      @counter-style bar { system: extends foo; }
    </style>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  const CounterStyle& bar = GetCounterStyle(GetDocument(), "bar");
  EXPECT_EQ("disc", bar.GetFallbackStyle().GetName());
}

TEST_F(CounterStyleMapTest, FallbackCyclic) {
  // Cyclic fallbacks are allowed. We break cycles when generating counter text.
  SetHtmlInnerHTML(R"HTML(
    <style>
      @counter-style foo { symbols: 'X'; fallback: bar; }
      @counter-style bar { symbols: 'X'; fallback: foo; }
    </style>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  const CounterStyle& foo = GetCounterStyle(GetDocument(), "foo");
  EXPECT_EQ("bar", foo.GetFallbackStyle().GetName());

  const CounterStyle& bar = GetCounterStyle(GetDocument(), "bar");
  EXPECT_EQ("foo", bar.GetFallbackStyle().GetName());
}

TEST_F(CounterStyleMapTest, FallbackToNonexistentStyle) {
  // Fallback to non-existent style resolves to 'decimal'.
  SetHtmlInnerHTML(R"HTML(
    <style>
      @counter-style foo { symbols: 'X'; fallback: bar; }
      @counter-style bar { symbols: 'X'; fallback: baz; }
    </style>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  const CounterStyle& foo = GetCounterStyle(GetDocument(), "foo");
  EXPECT_EQ("bar", foo.GetFallbackStyle().GetName());

  const CounterStyle& bar = GetCounterStyle(GetDocument(), "bar");
  EXPECT_EQ("decimal", bar.GetFallbackStyle().GetName());
}

TEST_F(CounterStyleMapTest, UpdateReferencesInChildScope) {
  SetHtmlInnerHTML(R"HTML(
    <style> @counter-style foo { symbols: 'X'; } </style>
    <div id=host></div>
  )HTML");
  ShadowRoot& shadow = AttachShadowTo("host");
  shadow.setInnerHTML(
      "<style>@counter-style bar { system: extends foo; }</style>");
  UpdateAllLifecyclePhasesForTest();

  const CounterStyle& foo = GetCounterStyle(GetDocument(), "foo");
  const CounterStyle& bar = GetCounterStyle(shadow, "bar");
  EXPECT_EQ(&foo, &bar.GetExtendedStyle());

  GetDocument().QuerySelector(AtomicString("style"))->remove();
  UpdateAllLifecyclePhasesForTest();

  // After counter style rule changes in the parent scope, the original
  // CounterStyle for 'bar' in child scopes will be dirtied, and will be
  // replaced by a new CounterStyle object.
  EXPECT_TRUE(foo.IsDirty());
  EXPECT_TRUE(bar.IsDirty());

  const CounterStyle& new_bar = GetCounterStyle(shadow, "bar");
  EXPECT_NE(&bar, &new_bar);
  EXPECT_EQ("decimal", new_bar.GetExtendedStyle().GetName());
}

TEST_F(CounterStyleMapTest, SpeakAsKeywords) {
  ScopedCSSAtRuleCounterStyleSpeakAsDescriptorForTest enabled(true);

  SetHtmlInnerHTML(R"HTML(
    <style>
      @counter-style implicit-auto { symbols: 'X'; }
      @counter-style explicit-auto { speak-as: auto; symbols: 'X'; }
      @counter-style bullets { speak-as: bullets; symbols: 'X'; }
      @counter-style numbers { speak-as: numbers; symbols: 'X'; }
      @counter-style words { speak-as: words; symbols: 'X'; }
    </style>
  )HTML");

  const CounterStyle& implicit_auto =
      GetCounterStyle(GetDocument(), "implicit-auto");
  EXPECT_EQ(CounterStyleSpeakAs::kAuto, implicit_auto.GetSpeakAs());

  const CounterStyle& explicit_auto =
      GetCounterStyle(GetDocument(), "explicit-auto");
  EXPECT_EQ(CounterStyleSpeakAs::kAuto, explicit_auto.GetSpeakAs());

  const CounterStyle& bullets = GetCounterStyle(GetDocument(), "bullets");
  EXPECT_EQ(CounterStyleSpeakAs::kBullets, bullets.GetSpeakAs());

  const CounterStyle& numbers = GetCounterStyle(GetDocument(), "numbers");
  EXPECT_EQ(CounterStyleSpeakAs::kNumbers, numbers.GetSpeakAs());

  const CounterStyle& words = GetCounterStyle(GetDocument(), "words");
  EXPECT_EQ(CounterStyleSpeakAs::kWords, words.GetSpeakAs());
}

TEST_F(CounterStyleMapTest, SpeakAsReference) {
  ScopedCSSAtRuleCounterStyleSpeakAsDescriptorForTest enabled(true);

  SetHtmlInnerHTML(R"HTML(
    <style>
      @counter-style base { symbols: 'X'; }
      @counter-style valid-author-ref { speak-as: base; symbols: 'X'; }
      @counter-style valid-ua-ref { speak-as: disc; symbols: 'X'; }
      @counter-style invalid { speak-as: unknown; symbols: 'X'; }
    </style>
  )HTML");

  const CounterStyle& valid_author_ref =
      GetCounterStyle(GetDocument(), "valid-author-ref");
  EXPECT_EQ(CounterStyleSpeakAs::kReference, valid_author_ref.GetSpeakAs());
  EXPECT_EQ("base", valid_author_ref.GetSpeakAsStyle().GetName());

  const CounterStyle& valid_ua_ref =
      GetCounterStyle(GetDocument(), "valid-ua-ref");
  EXPECT_EQ(CounterStyleSpeakAs::kReference, valid_ua_ref.GetSpeakAs());
  EXPECT_EQ("disc", valid_ua_ref.GetSpeakAsStyle().GetName());

  // Invalid 'speak-as' reference will be treated as 'speak-as: auto'.
  const CounterStyle& invalid = GetCounterStyle(GetDocument(), "invalid");
  EXPECT_EQ(CounterStyleSpeakAs::kAuto, invalid.GetSpeakAs());
}

TEST_F(CounterStyleMapTest, SpeakAsReferenceLoop) {
  ScopedCSSAtRuleCounterStyleSpeakAsDescriptorForTest enabled(true);

  SetHtmlInnerHTML(R"HTML(
    <style>
      @counter-style a { speak-as: b; symbols: 'X'; }
      @counter-style b { speak-as: a; symbols: 'X'; }
      @counter-style c { speak-as: b; symbols: 'X'; }
    </style>
  )HTML");

  const CounterStyle& a = GetCounterStyle(GetDocument(), "a");
  const CounterStyle& b = GetCounterStyle(GetDocument(), "b");
  const CounterStyle& c = GetCounterStyle(GetDocument(), "c");

  // Counter styles on a 'speak-as' loop will be treated as 'speak-as: auto'.
  EXPECT_EQ(CounterStyleSpeakAs::kAuto, a.GetSpeakAs());
  EXPECT_EQ(CounterStyleSpeakAs::kAuto, b.GetSpeakAs());

  // c is not on the loop, so its reference remains valid.
  EXPECT_EQ(CounterStyleSpeakAs::kReference, c.GetSpeakAs());
  EXPECT_EQ(&b, &c.GetSpeakAsStyle());
}

}  // namespace blink
```
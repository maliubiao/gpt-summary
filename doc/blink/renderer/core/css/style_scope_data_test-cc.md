Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Understand the Goal:** The primary goal is to analyze the given Chromium Blink engine test file (`style_scope_data_test.cc`) and explain its functionality, its relation to web technologies (JavaScript, HTML, CSS), provide examples, and touch on potential usage errors and debugging.

2. **Identify the Core Subject:** The filename and the initial `#include` directives immediately point to `StyleScopeData`. This is the central piece of functionality being tested. The presence of `@scope` rules in the test cases reinforces this. The goal of this code is to verify how `StyleScopeData` behaves.

3. **Analyze the Test Structure:**  The code follows a standard Google Test format. Key elements include:
    * `class StyleScopeDataTest : public PageTestBase`: This sets up the testing environment. `PageTestBase` implies this is testing rendering-related functionality within a simulated web page.
    * Helper functions like `QuerySelector`, `GetStyleScopeData`, `GetTriggeredScopes`, `MakeStyle`, `AppendChild`, and `RemoveChild`: These are utility functions to manipulate the DOM and access `StyleScopeData`. This suggests the tests involve dynamically creating and modifying HTML structures.
    * `TEST_F(StyleScopeDataTest, ...)`:  These are individual test cases, each focusing on a specific aspect of `StyleScopeData`'s behavior.

4. **Examine Individual Test Cases:**  This is where the core understanding comes from. Go through each test case and try to understand what scenario it's setting up and what it's asserting. Look for patterns and variations:
    * **`NoScopes`:**  Verifies the absence of style scopes when no `@scope` rules are present.
    * **`NotImplicitScope`:** Checks that `@scope (selector)` (explicit scoping) doesn't trigger implicit scopes on the parent.
    * **`Trivial`:** The simplest case – an unscoped `@scope` rule.
    * **`ExtraLeadingStyleRule`, `ExtraTrailingStyleRule`:**  Confirms that surrounding non-`@scope` rules don't interfere.
    * **`TwoInOne`, `TwoInOneNested`:** Tests multiple `@scope` rules within the same `<style>` tag.
    * **`NestedNonImplicitOuter`:**  A more complex nesting scenario with an explicit outer scope.
    * **`DistinctContent`, `SharedContent`:** Examines how `StyleScopeData` handles identical and different `@scope` content in separate `<style>` tags. This hints at potential optimization strategies within Blink.
    * **`Tree`:**  Tests the behavior across a more complex DOM tree structure.
    * **Mutation tests (`TrivialInsertRemove`, `DoubleInsertRemove`, `MutateSheet`):** Focus on dynamic updates to the DOM (adding/removing `<style>` tags, modifying their content).
    * **Shadow DOM tests (`ShadowHost`, `ShadowHostDoubleScope`, `AdoptedStylesheet`):**  Specifically targets how `@scope` interacts with Shadow DOM.

5. **Identify Connections to Web Technologies:**  As you examine the test cases, connect them back to core web concepts:
    * **HTML:** The tests manipulate the DOM using string literals (`R"HTML(...)`) and functions like `AppendChild`. The `<style>` tag is central. The Shadow DOM `<template>` and `shadowrootmode` are also used.
    * **CSS:** The `@scope` at-rule is the core feature being tested. The tests verify how styles within `@scope` apply (or don't apply) to different elements.
    * **JavaScript (Indirectly):** While the test file is C++, it simulates browser behavior. JavaScript is the language that would typically manipulate the DOM and create these scenarios in a real web page. The test uses `UpdateAllLifecyclePhasesForTest()`, which simulates the browser's rendering pipeline, something JavaScript interactions would trigger.

6. **Infer Logic and Assumptions:**  Think about *why* the tests are structured the way they are. What assumptions are being made about how `StyleScopeData` *should* work? For example, the tests assume that an unscoped `@scope` will apply to the element containing the `<style>` tag. The mutation tests assume that dynamic DOM changes will trigger updates to the style scoping.

7. **Consider Potential Errors:** Based on the functionality being tested, what could go wrong from a user's or developer's perspective?  For instance, misunderstanding the specificity of `@scope` rules, incorrect DOM manipulation leading to unexpected scoping, or forgetting to update lifecycle phases in a testing environment.

8. **Trace User Actions (Debugging Context):** Imagine a user encountering a style scoping issue. How might they have arrived at a state where the tests are relevant?  This helps in understanding the practical implications of the code.

9. **Structure the Explanation:** Organize your findings logically. Start with a high-level summary of the file's purpose, then delve into specifics, providing examples for each key concept. Address the relationships with web technologies explicitly. Use clear headings and bullet points for readability.

10. **Refine and Review:** Read through your explanation. Is it clear? Accurate? Are there any ambiguities?  Could anything be explained more simply? For example, initially, I might not have emphasized the "implicit" nature of the tested scopes, but the test names like `NotImplicitScope` highlight this distinction, so I'd make sure to include it. Similarly, emphasizing the testing nature of the code is crucial – it's not the *implementation* of style scoping, but the *verification* of its behavior.

By following this structured approach, one can effectively analyze a complex code file and extract the necessary information to understand its purpose, relationships, and implications.
这个文件 `style_scope_data_test.cc` 是 Chromium Blink 引擎中的一个 C++ 单元测试文件，其主要功能是**测试 `StyleScopeData` 类的行为和功能**。

`StyleScopeData` 类在 Blink 渲染引擎中负责存储和管理与特定 DOM 节点关联的样式作用域信息，特别是与 CSS 的 `@scope` at-rule 相关的隐式作用域。

下面详细列举其功能以及与 JavaScript, HTML, CSS 的关系：

**1. 主要功能：测试 `StyleScopeData` 对象的创建、关联和更新**

* **测试在没有 `@scope` 规则时的行为:** 验证当页面或元素内部没有定义 `@scope` 规则时，`StyleScopeData` 的状态。
* **测试简单的 `@scope` 规则:** 验证当一个元素内部包含一个无限定符的 `@scope` 规则时，`StyleScopeData` 能正确地记录并关联这个作用域。
* **测试带有前导或尾随非 `@scope` 规则的情况:** 验证 `StyleScopeData` 能否正确识别和处理 `style` 标签中 `@scope` 规则前后的其他 CSS 规则。
* **测试多个 `@scope` 规则:** 验证在一个 `style` 标签内定义多个 `@scope` 规则时，`StyleScopeData` 能否正确记录和管理这些作用域。
* **测试嵌套的 `@scope` 规则:** 验证 `StyleScopeData` 能否处理和记录嵌套的 `@scope` 规则。
* **测试具有不同内容的 `@scope` 规则:** 验证当不同的元素内部定义了内容不同的 `@scope` 规则时，`StyleScopeData` 会创建不同的作用域对象。
* **测试具有相同内容的 `@scope` 规则:** 验证当不同的元素内部定义了内容相同的 `@scope` 规则时，`StyleScopeData` 是否会复用相同的底层 `StyleSheetContents` 对象以节省内存。
* **测试在 DOM 树中的行为:** 验证在复杂的 DOM 树结构中，`@scope` 规则如何影响不同元素的 `StyleScopeData`。
* **测试动态 DOM 操作 (Mutation):**
    * **插入和删除包含 `@scope` 规则的 `style` 元素:** 验证在动态插入或删除 `style` 标签时，`StyleScopeData` 是否能正确更新。
    * **修改 `style` 元素的内容:** 验证当 `style` 标签的内容被修改，从包含 `@scope` 规则变为不包含，或反之，`StyleScopeData` 是否能正确更新。
* **测试 Shadow DOM:**
    * **Shadow Host 中包含 `@scope` 规则:** 验证在 Shadow DOM 的 host 元素内部的 `<template shadowrootmode="open">` 中定义的 `@scope` 规则如何影响 host 元素的 `StyleScopeData`。
    * **Shadow Host 同时包含 Shadow Root 和 Light DOM 中的 `@scope` 规则:** 验证这两种情况下的 `StyleScopeData` 管理。
    * **使用 Adopted Stylesheets:** 验证通过 `adoptedStyleSheets` API 添加的包含 `@scope` 规则的样式表如何影响 Shadow Host 的 `StyleScopeData`。

**2. 与 JavaScript, HTML, CSS 的关系及举例说明：**

* **CSS:**  `StyleScopeData` 的核心目标就是处理 CSS 的 `@scope` at-rule。这个 at-rule 允许开发者将样式规则的作用范围限定在特定的 DOM 子树中。
    * **举例:**  在测试用例 `Trivial` 中，HTML 代码包含一个无限定符的 `@scope` 规则：
      ```html
      <div id=b>
        <style>
          @scope {
            * { color: green; }
          }
        </style>
      </div>
      ```
      这个测试验证了元素 `#b` 的 `StyleScopeData` 中会记录到一个隐式作用域。
* **HTML:**  `StyleScopeData` 与 HTML 元素紧密关联。它存储在 `Element` 对象中，用于跟踪该元素相关的样式作用域信息。测试用例通过操作 HTML 结构（例如，添加、删除 `style` 元素，创建 Shadow DOM）来验证 `StyleScopeData` 的行为。
    * **举例:** 在测试用例 `TrivialInsertRemove` 中，通过 JavaScript (在测试环境中模拟) 将包含 `@scope` 规则的 `<style>` 元素添加到 `#b`，然后移除。这测试了 `StyleScopeData` 在 DOM 结构变化时的更新。
* **JavaScript:** 虽然这个测试文件是 C++ 代码，但它模拟了浏览器中 JavaScript 操作可能触发的场景。例如，通过 `setInnerHTML` 设置 HTML 内容，这与 JavaScript 操作 DOM 的效果类似。此外，测试用例 `AdoptedStylesheet` 直接模拟了 JavaScript 的 `adoptedStyleSheets` API 的使用。
    * **举例:** 在测试用例 `AdoptedStylesheet` 中，模拟了使用 JavaScript 创建 `CSSStyleSheet` 对象，并通过 `replaceSync` 方法添加 `@scope` 规则，然后将其添加到 Shadow Root 的 `adoptedStyleSheets` 中。这测试了 `StyleScopeData` 对通过 JavaScript API 添加的样式表的处理。

**3. 逻辑推理、假设输入与输出：**

大多数测试用例都基于以下逻辑推理：

* **假设输入:** 一个特定的 HTML 结构，可能包含带有 `@scope` 规则的 `<style>` 元素，以及对 DOM 的操作（添加、删除元素，修改样式表）。
* **预期输出:**  特定元素的 `StyleScopeData` 对象中记录的隐式作用域的数量和状态。

**示例（基于 `Trivial` 测试用例）:**

* **假设输入:**
  ```html
  <div id=a></div>
  <div id=b>
    <style>
      @scope {
        * { color: green; }
      }
    </style>
  </div>
  ```
* **预期输出:**
  * `GetTriggeredScopes("#a").size()` 应该为 `0u` (元素 `#a` 没有关联的隐式作用域)。
  * `GetTriggeredScopes("#b").size()` 应该为 `1u` (元素 `#b` 关联一个隐式作用域)。

**4. 用户或编程常见的使用错误及举例说明：**

虽然 `style_scope_data_test.cc` 主要关注引擎内部的正确性，但可以推断一些用户或编程中与 `@scope` 相关的常见错误：

* **误解 `@scope` 的作用范围:** 开发者可能错误地认为 `@scope` 会影响其父元素或兄弟元素，而实际上无限定符的 `@scope` 只会影响包含它的元素的子树。
    * **举例:** 用户可能期望在以下情况下，`#a` 的文本颜色会变成绿色，但实际上不会，因为 `@scope` 只影响 `#b` 的子树：
      ```html
      <div id=a>Text</div>
      <div id=b>
        <style>
          @scope {
            #a { color: green; }
          }
        </style>
      </div>
      ```
* **在不支持 `@scope` 的浏览器中使用:** 早期版本的浏览器可能不支持 `@scope`，导致样式规则无法生效。
* **动态添加/删除样式表后未正确触发样式更新:**  在某些复杂情况下，开发者可能需要确保在动态修改样式表后，浏览器的样式重新计算流程被正确触发，否则 `StyleScopeData` 可能不会及时更新。
* **与 Shadow DOM 的交互理解不足:**  开发者可能对 `@scope` 在 Shadow DOM 中的作用范围和影响理解不足，导致样式应用出现意外情况。

**5. 用户操作如何一步步到达这里作为调试线索：**

作为一个底层的测试文件，普通用户操作不会直接触发到这里。这个文件主要是 Blink 引擎的开发者在开发和调试样式系统时使用的。以下是一些可能导致开发者需要查看或调试 `StyleScopeData` 的场景：

1. **开发者添加了新的 CSS `@scope` 相关功能:**  在实现新的 `@scope` 语法或特性后，开发者会编写类似的单元测试来验证其正确性。
2. **发现了与 `@scope` 相关的 Bug:** 如果用户报告了某些情况下 `@scope` 规则没有按预期工作，Blink 开发者可能会通过复现 Bug 并进行调试，逐步深入到 `StyleScopeData` 相关的代码。
3. **性能分析和优化:** 为了提高样式计算的性能，开发者可能会分析 `StyleScopeData` 的数据结构和算法，并进行优化。
4. **代码重构:** 在对样式系统的代码进行重构时，为了确保重构没有引入新的错误，开发者会运行这些单元测试。

**调试线索（开发者角度）：**

* **复现 Bug 的最小化 HTML 页面:**  开发者首先需要创建一个最小化的 HTML 页面，能够稳定地复现用户报告的 `@scope` 相关问题。
* **使用 Chromium 的调试工具:**  开发者可以使用 Chromium 提供的开发者工具，例如 "Elements" 面板查看元素的样式，以及 "Sources" 面板查看样式表的源代码。
* **设置断点:**  在 `style_scope_data_test.cc` 或相关的 `StyleScopeData` 实现代码中设置断点，以便在测试运行时检查变量的值和程序执行流程。
* **查看 Style Inspector 的输出:**  Chromium 的 Style Inspector 可能会提供关于样式计算和作用域的信息，帮助开发者理解 `@scope` 的影响。
* **运行相关的单元测试:**  开发者会运行 `style_scope_data_test.cc` 中的测试用例，看是否能复现问题或发现回归。如果现有的测试无法覆盖到 Bug，开发者可能需要添加新的测试用例。
* **分析日志输出:**  Blink 引擎在调试模式下可能会输出与样式计算和作用域相关的日志信息，可以帮助开发者定位问题。

总而言之，`style_scope_data_test.cc` 是一个关键的测试文件，用于确保 Chromium Blink 引擎中与 CSS `@scope` 规则相关的 `StyleScopeData` 类能够正确地管理和维护样式作用域信息，从而保证网页样式的正确渲染。

### 提示词
```
这是目录为blink/renderer/core/css/style_scope_data_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/css/style_scope_data.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_css_style_sheet_init.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/style_scope.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"

namespace blink {

class StyleScopeDataTest : public PageTestBase {
 public:
  Element& QuerySelector(String selector) {
    Element* element = GetDocument().QuerySelector(AtomicString(selector));
    DCHECK(element);
    return *element;
  }

  StyleScopeData* GetStyleScopeData(String selector) {
    return QuerySelector(selector).GetStyleScopeData();
  }

  using TriggeredScopes = HeapVector<Member<const StyleScope>, 1>;

  TriggeredScopes GetTriggeredScopes(String selector) {
    if (StyleScopeData* style_scope_data = GetStyleScopeData(selector)) {
      return style_scope_data->triggered_implicit_scopes_;
    }
    return TriggeredScopes();
  }

  const StyleScope* GetSingleTriggeredScope(String selector) {
    const TriggeredScopes& scopes = GetTriggeredScopes(selector);
    return (scopes.size() == 1u) ? scopes.front().Get() : nullptr;
  }

  Element* MakeStyle(String style) {
    auto* style_element = MakeGarbageCollected<HTMLStyleElement>(GetDocument());
    style_element->setTextContent(style);
    return style_element;
  }

  void AppendChild(String selector, Element* child) {
    QuerySelector(selector).AppendChild(child);
  }

  void RemoveChild(String selector, Element* child) {
    QuerySelector(selector).RemoveChild(child);
  }
};

TEST_F(StyleScopeDataTest, NoScopes) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=a></div>
    <div id=b></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(0u, GetTriggeredScopes("#b").size());
}

TEST_F(StyleScopeDataTest, NotImplicitScope) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=a></div>
    <div id=b>
      <style>
        @scope (div) {
          * { color: green; }
        }
      </style>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(0u, GetTriggeredScopes("#b").size());
}

TEST_F(StyleScopeDataTest, Trivial) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=a></div>
    <div id=b>
      <style>
        @scope {
          * { color: green; }
        }
      </style>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(1u, GetTriggeredScopes("#b").size());
}

TEST_F(StyleScopeDataTest, ExtraLeadingStyleRule) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=a></div>
    <div id=b>
      <style>
        div { color: blue; }
        @scope {
          * { color: green; }
        }
      </style>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(1u, GetTriggeredScopes("#b").size());
}

TEST_F(StyleScopeDataTest, ExtraTrailingStyleRule) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=a></div>
    <div id=b>
      <style>
        @scope {
          * { color: green; }
        }
        div { color: blue; }
      </style>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(1u, GetTriggeredScopes("#b").size());
}

TEST_F(StyleScopeDataTest, TwoInOne) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=a></div>
    <div id=b>
      <style>
        @scope {
          * { color: green; }
        }
        @scope {
          * { color: blue; }
        }
      </style>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(2u, GetTriggeredScopes("#b").size());
}

TEST_F(StyleScopeDataTest, TwoInOneNested) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=a></div>
    <div id=b>
      <style>
        @scope {
          * { color: green; }

          @scope {
            * { color: blue; }
          }
        }
      </style>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(2u, GetTriggeredScopes("#b").size());
}

TEST_F(StyleScopeDataTest, NestedNonImplicitOuter) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=a></div>
    <div id=b>
      <style>
        @scope (div) {
          * { color: green; }

          @scope {
            * { color: blue; }
          }
        }
      </style>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(1u, GetTriggeredScopes("#b").size());
}

TEST_F(StyleScopeDataTest, DistinctContent) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=a>
      <style>
        @scope {
          * { color: green; }
        }
      </style>
    </div>
    <div id=b>
      <style>
        @scope {
          * { --different: true; }
        }
      </style>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  const StyleScope* a = GetSingleTriggeredScope("#a");
  const StyleScope* b = GetSingleTriggeredScope("#b");
  ASSERT_TRUE(a);
  ASSERT_TRUE(b);
  EXPECT_NE(a, b);
}

TEST_F(StyleScopeDataTest, SharedContent) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=a>
      <style>
        @scope {
          * { color: green; }
        }
      </style>
    </div>
    <div id=b>
      <style>
        @scope {
          * { color: green; }
        }
      </style>
    </div>
    <div id=c>
      <style>
        @scope {
          * { --different: true; }
        }
      </style>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  const StyleScope* a = GetSingleTriggeredScope("#a");
  const StyleScope* b = GetSingleTriggeredScope("#b");
  const StyleScope* c = GetSingleTriggeredScope("#c");
  ASSERT_TRUE(a);
  ASSERT_TRUE(b);
  ASSERT_TRUE(c);
  // The StyleScope instances for #a and b are the same, because the two
  // stylesheets are identical, and therefore share the same StyleSheetContents.
  EXPECT_EQ(a, b);
  // The style for #c is not identical however.
  EXPECT_NE(a, c);
}

TEST_F(StyleScopeDataTest, Tree) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=a1></div>
    <div id=a2>
      <div id=b1></div>
      <div id=b2>
        <div id=c1></div>
        <style>
          @scope {
            * { color: green; }
          }
        </style>
        <div id=c2></div>
        <div id=c3></div>
      </div>
      <div id=b3></div>
    </div>
    <div id=a3></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(0u, GetTriggeredScopes("#a1").size());
  EXPECT_EQ(0u, GetTriggeredScopes("#a2").size());
  EXPECT_EQ(0u, GetTriggeredScopes("#a3").size());

  EXPECT_EQ(0u, GetTriggeredScopes("#b1").size());
  EXPECT_EQ(1u, GetTriggeredScopes("#b2").size());
  EXPECT_EQ(0u, GetTriggeredScopes("#b3").size());

  EXPECT_EQ(0u, GetTriggeredScopes("#c1").size());
  EXPECT_EQ(0u, GetTriggeredScopes("#c2").size());
  EXPECT_EQ(0u, GetTriggeredScopes("#c3").size());
}

// Mutations

TEST_F(StyleScopeDataTest, TrivialInsertRemove) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=a></div>
    <div id=b></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(0u, GetTriggeredScopes("#b").size());

  Element* style = MakeStyle(R"CSS(
    @scope {
      * { color: green; }
    }
  )CSS");

  AppendChild("#b", style);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(1u, GetTriggeredScopes("#b").size());

  RemoveChild("#b", style);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(0u, GetTriggeredScopes("#b").size());
}

TEST_F(StyleScopeDataTest, DoubleInsertRemove) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=a></div>
    <div id=b></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(0u, GetTriggeredScopes("#b").size());

  Element* style1 = MakeStyle(R"CSS(
    @scope {
      * { color: green; }
    }
  )CSS");

  Element* style2 = MakeStyle(R"CSS(
    @scope {
      * { color: blue; }
    }
  )CSS");

  AppendChild("#a", style1);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(0u, GetTriggeredScopes("#b").size());

  AppendChild("#b", style2);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(1u, GetTriggeredScopes("#b").size());

  // Move style2 to #a.
  RemoveChild("#b", style2);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(0u, GetTriggeredScopes("#b").size());
  AppendChild("#a", style2);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(2u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(0u, GetTriggeredScopes("#b").size());
}

TEST_F(StyleScopeDataTest, MutateSheet) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=a></div>
    <div id=b>
      <style id=s></style>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(0u, GetTriggeredScopes("#b").size());

  Element& s = QuerySelector("#s");

  s.setTextContent("@scope { * { color: green; } }");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(1u, GetTriggeredScopes("#b").size());

  s.setTextContent("div { color: red; }");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(0u, GetTriggeredScopes("#b").size());
}

TEST_F(StyleScopeDataTest, ShadowHost) {
  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <div id=a></div>
    <div id=host>
      <template shadowrootmode=open>
        <style>
          @scope {
            * { color: green; }
          }
        </style>
      </template>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(1u, GetTriggeredScopes("#host").size());
}

TEST_F(StyleScopeDataTest, ShadowHostDoubleScope) {
  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <div id=a></div>
    <div id=host>
      <template shadowrootmode=open>
        <style>
          @scope {
            * { color: green; }
          }
        </style>
      </template>
      <style>
          @scope {
            * { color: blue; }
          }
      </style>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(2u, GetTriggeredScopes("#host").size());
}

TEST_F(StyleScopeDataTest, AdoptedStylesheet) {
  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <div id=a></div>
    <div id=host>
      <template shadowrootmode=open>
      </template>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(0u, GetTriggeredScopes("#host").size());

  DummyExceptionStateForTesting exception_state;
  auto* init = CSSStyleSheetInit::Create();
  auto* sheet = CSSStyleSheet::Create(GetDocument(), init, exception_state);
  sheet->replaceSync("@scope { * { color: blue; } }", exception_state);

  Element* host = GetDocument().getElementById(AtomicString("host"));
  ASSERT_TRUE(host);
  ASSERT_TRUE(host->GetShadowRoot());

  HeapVector<Member<CSSStyleSheet>> stylesheets;
  stylesheets.push_back(sheet);
  host->GetShadowRoot()->SetAdoptedStyleSheetsForTesting(stylesheets);

  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(1u, GetTriggeredScopes("#host").size());

  // Add a second adopted stylesheet.
  auto* sheet2 = CSSStyleSheet::Create(GetDocument(), init, exception_state);
  sheet2->replaceSync("@scope { * { color: red; } }", exception_state);
  stylesheets.push_back(sheet2);
  host->GetShadowRoot()->SetAdoptedStyleSheetsForTesting(stylesheets);

  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(2u, GetTriggeredScopes("#host").size());

  // Insert a non-adopted stylesheet.
  host->AppendChild(MakeStyle("@scope { * { color: yellow; } }"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, GetTriggeredScopes("#a").size());
  EXPECT_EQ(3u, GetTriggeredScopes("#host").size());
}

}  // namespace blink
```
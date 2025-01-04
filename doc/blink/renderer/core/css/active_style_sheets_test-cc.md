Response:
Let's break down the thought process for analyzing the `active_style_sheets_test.cc` file.

1. **Identify the Core Purpose:** The file name `active_style_sheets_test.cc` immediately suggests it's a test file related to `ActiveStyleSheets`. The `#include "third_party/blink/renderer/core/css/active_style_sheets.h"` confirms this. The `.cc` extension signifies it's a C++ source file.

2. **Recognize the Testing Framework:** The inclusion of `#include "testing/gtest/include/gtest/gtest.h"` indicates that the file uses the Google Test framework for writing unit tests. This means we should look for `TEST_F` macros.

3. **Understand the Setup:** The file defines a test fixture class `ActiveStyleSheetsTest` that inherits from `PageTestBase`. This is a common pattern in Blink tests, providing a basic page environment for running tests. The `protected` section suggests helper functions like `CreateSheet` will be used within the tests.

4. **Analyze Helper Functions:** The `CreateSheet` function is crucial. It creates a `CSSStyleSheet` object. Key aspects to note are:
    * It creates `StyleSheetContents`.
    * It uses `CSSParserContext` for parsing, indicating it deals with CSS syntax.
    * `ParseString` suggests it takes CSS text as input.
    * `EnsureRuleSet` is called, meaning it's preparing the stylesheet for use.

5. **Identify the Main Testing Subject:** The tests primarily focus on the `CompareActiveStyleSheets` function. This function takes two `ActiveStyleSheetVector` objects (representing old and new states) and a `HeapHashSet<Member<RuleSet>>` for tracking changes. The return value appears to be an enum indicating the type of change.

6. **Categorize the Tests:**  Go through each `TEST_F` block and understand what it's testing:
    * **`CompareActiveStyleSheets_NoChange`:** Checks the case where the old and new stylesheet lists are identical.
    * **`CompareActiveStyleSheets_AppendedToEmpty` and `_AppendedToNonEmpty`:**  Test adding new stylesheets.
    * **`CompareActiveStyleSheets_Mutated`:** Tests when a stylesheet's content (RuleSet) changes.
    * **`CompareActiveStyleSheets_Inserted` and `_Removed`:** Test adding and removing stylesheets from the middle of the list.
    * **`CompareActiveStyleSheets_RemovedAll`:** Tests removing all stylesheets.
    * **`CompareActiveStyleSheets_InsertedAndRemoved`:** Tests a combination of insertion and removal.
    * **Tests involving `NullRuleSet`:** These are edge cases where a stylesheet might be present but not have a valid RuleSet.
    * **`CompareActiveStyleSheets_ReorderedImportSheets`:** Tests the behavior when the order of imported stylesheets changes.
    * **`CompareActiveStyleSheets_DisableAndAppend`:** Tests disabling a stylesheet and adding another.
    * **`CompareActiveStyleSheets_AddRemoveNonMatchingMQ`:** Tests stylesheets with media queries that don't match.

7. **Identify the Relationship to Web Technologies:**
    * **CSS:**  The core of the testing is about CSS stylesheets, parsing, and rule sets. The `CreateSheet` function explicitly parses CSS text.
    * **HTML:** While not directly manipulating HTML elements in *most* of the `CompareActiveStyleSheets` tests, the setup uses `PageTestBase`, which implies a basic HTML document context. The `ApplyRulesetsTest` *does* manipulate HTML to create shadow DOM.
    * **JavaScript:** The tests don't directly execute JavaScript. However, the functionality being tested (managing active stylesheets) is crucial for how JavaScript interacts with the DOM and styles (e.g., modifying `document.styleSheets`).

8. **Infer Logical Reasoning and Assumptions:** For each test case, consider the *expected* behavior. For example, if a stylesheet is added, the `CompareActiveStyleSheets` function should detect this and indicate `kActiveSheetsAppended` or `kActiveSheetsChanged`. The tests make assumptions about how stylesheet changes are detected and tracked.

9. **Consider User/Programming Errors:** Think about how a developer might misuse the stylesheet APIs or encounter unexpected behavior. For example:
    * Modifying a stylesheet object directly without triggering a re-evaluation.
    * Not understanding how changes to imported stylesheets are handled.
    * Incorrectly comparing stylesheet lists.

10. **Trace User Actions (Debugging Context):**  Imagine a scenario where a web page isn't styling correctly. How might a developer end up investigating the `ActiveStyleSheets`? This involves thinking about:
    * Inspecting the `document.styleSheets` in the browser's developer tools.
    * Observing the order and content of stylesheets.
    * Using JavaScript to manipulate stylesheets and observing the effects.
    * Looking for performance issues related to stylesheet recalculation.

11. **Structure the Analysis:**  Organize the findings into logical categories (functionality, relationships to web technologies, reasoning, errors, debugging). Use clear and concise language. Provide specific examples from the code.

12. **Refine and Review:** Read through the analysis to ensure accuracy and completeness. Check for any misunderstandings or missed points.

By following these steps, you can systematically analyze the provided C++ code and extract the relevant information about its functionality, its connection to web technologies, and its implications for developers and users.
这个文件 `active_style_sheets_test.cc` 是 Chromium Blink 引擎中负责测试 `ActiveStyleSheets` 类的功能的单元测试文件。`ActiveStyleSheets` 类在 Blink 引擎中扮演着管理和比较当前文档或 Shadow DOM 树上生效的样式表的重要角色。

**文件功能概览:**

该文件主要通过编写一系列的单元测试用例来验证 `ActiveStyleSheets` 类的以下核心功能：

1. **比较新旧生效样式表集合 (CompareActiveStyleSheets):**
   - 判断两个生效样式表集合之间的差异。
   - 检测样式表的添加、删除、修改以及顺序变化。
   - 区分不同的变化类型，例如 `kNoActiveSheetsChanged` (无变化), `kActiveSheetsAppended` (新增样式表), `kActiveSheetsChanged` (样式表发生变化，包括内容修改、插入、删除等)。

2. **应用规则集变化 (ApplyRuleSetChanges):**
   - 模拟在文档或 Shadow DOM 上应用样式规则变化的过程。
   - 验证不同类型的规则（例如通用选择器、`@font-face` 规则）添加到不同作用域时是否会触发预期的样式失效和重计算。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`ActiveStyleSheets` 类及其测试直接关系到 CSS 的应用和管理，并且间接地与 JavaScript 和 HTML 交互：

* **CSS:**
    * **核心功能:** `ActiveStyleSheets` 负责管理哪些 CSS 规则在当前上下文中生效。测试用例中大量使用 `CreateSheet` 函数创建 `CSSStyleSheet` 对象，并通过 `ParseString` 方法解析 CSS 文本。
    * **举例:**  测试用例 `CompareActiveStyleSheets_Mutated` 模拟了修改已存在的样式表内容的情况。假设 CSS 文件 `style.css` 最初包含 `body { background-color: white; }`，然后通过 JavaScript 修改为 `body { background-color: black; }`。`ActiveStyleSheets` 的比较功能会检测到这个变化。

* **HTML:**
    * **作用域:** `ActiveStyleSheets` 的管理范围包括主文档和 Shadow DOM。测试用例 `ApplyRulesetsTest` 中有针对文档和 Shadow DOM 的测试，例如 `AddUniversalRuleToDocument` 和 `AddUniversalRuleToShadowTree`。
    * **举例:**  当 HTML 中通过 `<link>` 标签引入外部 CSS 文件，或者使用 `<style>` 标签内嵌 CSS 时，Blink 引擎会解析这些 CSS 并将其添加到文档的生效样式表集合中。`ActiveStyleSheets` 负责跟踪这些样式表。

* **JavaScript:**
    * **DOM 操作:** JavaScript 可以通过 DOM API (例如 `document.styleSheets`, `element.shadowRoot.styleSheets`) 访问和修改文档或 Shadow DOM 的样式表。
    * **事件触发:** 当 JavaScript 修改样式表时，例如通过 `sheet.insertRule()` 添加规则，或者修改 `sheet.disabled` 属性，会导致生效样式表集合发生变化，进而触发 Blink 引擎的样式重计算流程。`ActiveStyleSheets` 的比较功能会在这些操作后被调用，以确定哪些规则集需要重新应用。
    * **举例:**  JavaScript 代码可能如下：
      ```javascript
      const styleSheet = document.styleSheets[0];
      styleSheet.insertRule('p { color: blue; }', styleSheet.cssRules.length);
      ```
      这个操作会改变生效的样式表集合，`ActiveStyleSheets` 的比较功能会识别到新添加的规则。

**逻辑推理及假设输入与输出:**

以 `CompareActiveStyleSheets_AppendedToEmpty` 测试用例为例：

* **假设输入:**
    * `old_sheets`: 一个空的 `ActiveStyleSheetVector`。
    * `new_sheets`: 一个包含两个新创建的 `CSSStyleSheet` 对象的 `ActiveStyleSheetVector`。

* **逻辑推理:**  由于旧的集合是空的，而新的集合包含两个样式表，因此可以推断出新的样式表被添加进来了。

* **预期输出:**
    * `CompareActiveStyleSheets` 函数返回 `kActiveSheetsAppended`。
    * `changed_rule_sets` 集合包含这两个新样式表的 `RuleSet` 指针。

**用户或编程常见的使用错误及举例说明:**

1. **手动修改 `RuleSet` 对象:** 开发者可能会尝试直接修改 `CSSStyleSheet` 对象内部的 `RuleSet`，而不通过 Blink 提供的 API 更新样式表。这会导致 `ActiveStyleSheets` 的比较功能无法正确检测到变化，从而可能导致样式更新不及时或不正确。
   ```cpp
   // 错误的做法
   CSSStyleSheet* sheet = ...;
   sheet->Contents()->GetMutableRuleSet()->AddRule(...); // 直接修改 RuleSet

   // 正确的做法应该通过修改 CSSStyleSheet 的内容来触发更新
   sheet->SetText("body { color: red; }");
   ```

2. **不理解 Shadow DOM 的样式隔离:** 开发者可能认为修改主文档的样式表会影响到 Shadow DOM 内的元素，反之亦然。`ActiveStyleSheets` 区分主文档和 Shadow DOM 的生效样式表，确保样式隔离。
   ```html
   <div id="host"></div>
   <script>
     const host = document.getElementById('host');
     const shadowRoot = host.attachShadow({ mode: 'open' });
     shadowRoot.innerHTML = '<style>p { color: green; }</style><p>In Shadow DOM</p>';

     const style = document.createElement('style');
     style.textContent = 'p { color: blue; }';
     document.head.appendChild(style); // 这不会影响 Shadow DOM 内的 <p>
   </script>
   ```

**用户操作如何一步步到达这里 (调试线索):**

假设用户在网页上看到元素的样式不正确，开发者进行调试的步骤可能如下：

1. **检查元素样式:** 使用浏览器开发者工具的 "Elements" 面板，查看目标元素的 "Computed" (计算后) 样式，确定最终生效的 CSS 属性值。
2. **查看样式来源:** 在 "Computed" 样式中，可以查看每个属性值来自哪个样式规则和样式表。这有助于定位问题可能存在的 CSS 文件或 `<style>` 标签。
3. **检查 `document.styleSheets`:** 在开发者工具的 Console 中输入 `document.styleSheets`，可以查看当前文档的所有样式表对象。检查样式表的数量、顺序、以及是否被禁用。对于 Shadow DOM，可以使用 `element.shadowRoot.styleSheets`。
4. **检查样式表内容:** 可以访问 `styleSheet.cssRules` 查看每个样式表的 CSS 规则。
5. **动态修改样式:** 使用 JavaScript 动态修改样式表，观察页面变化，例如：
   ```javascript
   document.styleSheets[0].disabled = true; // 禁用第一个样式表
   document.styleSheets[0].insertRule('body { background-color: yellow; }', 0); // 插入新规则
   ```
6. **Blink 内部调试 (涉及 `active_style_sheets_test.cc`):** 如果开发者需要深入了解 Blink 引擎如何管理样式表，可能会：
   - **断点调试:** 在 Blink 源代码中，例如 `core/css/active_style_sheets.cc` 和相关的调用栈上设置断点，观察 `CompareActiveStyleSheets` 函数的调用时机和参数。
   - **阅读测试用例:** 阅读像 `active_style_sheets_test.cc` 这样的测试文件，了解 `ActiveStyleSheets` 类的各种使用场景和预期行为，从而帮助理解引擎内部的逻辑。
   - **日志输出:** 在 Blink 源代码中添加日志输出，记录生效样式表的变化和比较结果，以便追踪问题。

总而言之，`active_style_sheets_test.cc` 是 Blink 引擎中一个关键的测试文件，它确保了样式表管理的核心逻辑的正确性，这对于网页的正确渲染至关重要。理解这个文件的功能有助于开发者更好地理解 Blink 引擎如何处理 CSS，并为调试样式问题提供更深入的线索。

Prompt: 
```
这是目录为blink/renderer/core/css/active_style_sheets_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/active_style_sheets.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_shadow_root_init.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/media_query_evaluator.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/media_query_parser.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/css/style_sheet_list.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

class ActiveStyleSheetsTest : public PageTestBase {
 protected:
  CSSStyleSheet* CreateSheet(const String& css_text = String()) {
    auto* contents = MakeGarbageCollected<StyleSheetContents>(
        MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode, SecureContextMode::kInsecureContext));
    contents->ParseString(css_text);
    contents->EnsureRuleSet(MediaQueryEvaluator(GetDocument().GetFrame()));
    return MakeGarbageCollected<CSSStyleSheet>(contents);
  }
};

class ApplyRulesetsTest : public ActiveStyleSheetsTest {};

TEST_F(ActiveStyleSheetsTest, CompareActiveStyleSheets_NoChange) {
  ActiveStyleSheetVector old_sheets;
  ActiveStyleSheetVector new_sheets;
  HeapHashSet<Member<RuleSet>> changed_rule_sets;

  EXPECT_EQ(
      kNoActiveSheetsChanged,
      CompareActiveStyleSheets(old_sheets, new_sheets, {}, changed_rule_sets));
  EXPECT_EQ(0u, changed_rule_sets.size());

  CSSStyleSheet* sheet1 = CreateSheet();
  CSSStyleSheet* sheet2 = CreateSheet();

  old_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  old_sheets.push_back(
      std::make_pair(sheet2, &sheet2->Contents()->GetRuleSet()));

  new_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  new_sheets.push_back(
      std::make_pair(sheet2, &sheet2->Contents()->GetRuleSet()));

  EXPECT_EQ(
      kNoActiveSheetsChanged,
      CompareActiveStyleSheets(old_sheets, new_sheets, {}, changed_rule_sets));
  EXPECT_EQ(0u, changed_rule_sets.size());
}

TEST_F(ActiveStyleSheetsTest, CompareActiveStyleSheets_AppendedToEmpty) {
  ActiveStyleSheetVector old_sheets;
  ActiveStyleSheetVector new_sheets;
  HeapHashSet<Member<RuleSet>> changed_rule_sets;

  CSSStyleSheet* sheet1 = CreateSheet();
  CSSStyleSheet* sheet2 = CreateSheet();

  new_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  new_sheets.push_back(
      std::make_pair(sheet2, &sheet2->Contents()->GetRuleSet()));

  EXPECT_EQ(
      kActiveSheetsAppended,
      CompareActiveStyleSheets(old_sheets, new_sheets, {}, changed_rule_sets));
  EXPECT_EQ(2u, changed_rule_sets.size());
}

TEST_F(ActiveStyleSheetsTest, CompareActiveStyleSheets_AppendedToNonEmpty) {
  ActiveStyleSheetVector old_sheets;
  ActiveStyleSheetVector new_sheets;
  HeapHashSet<Member<RuleSet>> changed_rule_sets;

  CSSStyleSheet* sheet1 = CreateSheet();
  CSSStyleSheet* sheet2 = CreateSheet();

  old_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  new_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  new_sheets.push_back(
      std::make_pair(sheet2, &sheet2->Contents()->GetRuleSet()));

  EXPECT_EQ(
      kActiveSheetsAppended,
      CompareActiveStyleSheets(old_sheets, new_sheets, {}, changed_rule_sets));
  EXPECT_EQ(1u, changed_rule_sets.size());
}

TEST_F(ActiveStyleSheetsTest, CompareActiveStyleSheets_Mutated) {
  ActiveStyleSheetVector old_sheets;
  ActiveStyleSheetVector new_sheets;
  HeapHashSet<Member<RuleSet>> changed_rule_sets;

  CSSStyleSheet* sheet1 = CreateSheet();
  CSSStyleSheet* sheet2 = CreateSheet();
  CSSStyleSheet* sheet3 = CreateSheet();

  old_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  old_sheets.push_back(
      std::make_pair(sheet2, &sheet2->Contents()->GetRuleSet()));
  old_sheets.push_back(
      std::make_pair(sheet3, &sheet3->Contents()->GetRuleSet()));

  sheet2->Contents()->ClearRuleSet();
  sheet2->Contents()->EnsureRuleSet(
      MediaQueryEvaluator(GetDocument().GetFrame()));

  EXPECT_NE(old_sheets[1].second, &sheet2->Contents()->GetRuleSet());

  new_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  new_sheets.push_back(
      std::make_pair(sheet2, &sheet2->Contents()->GetRuleSet()));
  new_sheets.push_back(
      std::make_pair(sheet3, &sheet3->Contents()->GetRuleSet()));

  EXPECT_EQ(
      kActiveSheetsChanged,
      CompareActiveStyleSheets(old_sheets, new_sheets, {}, changed_rule_sets));
  EXPECT_EQ(2u, changed_rule_sets.size());
  EXPECT_TRUE(changed_rule_sets.Contains(&sheet2->Contents()->GetRuleSet()));
  EXPECT_TRUE(changed_rule_sets.Contains(old_sheets[1].second));
}

TEST_F(ActiveStyleSheetsTest, CompareActiveStyleSheets_Inserted) {
  ActiveStyleSheetVector old_sheets;
  ActiveStyleSheetVector new_sheets;
  HeapHashSet<Member<RuleSet>> changed_rule_sets;

  CSSStyleSheet* sheet1 = CreateSheet();
  CSSStyleSheet* sheet2 = CreateSheet();
  CSSStyleSheet* sheet3 = CreateSheet();

  old_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  old_sheets.push_back(
      std::make_pair(sheet3, &sheet3->Contents()->GetRuleSet()));

  new_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  new_sheets.push_back(
      std::make_pair(sheet2, &sheet2->Contents()->GetRuleSet()));
  new_sheets.push_back(
      std::make_pair(sheet3, &sheet3->Contents()->GetRuleSet()));

  EXPECT_EQ(
      kActiveSheetsChanged,
      CompareActiveStyleSheets(old_sheets, new_sheets, {}, changed_rule_sets));
  EXPECT_EQ(1u, changed_rule_sets.size());
  EXPECT_TRUE(changed_rule_sets.Contains(&sheet2->Contents()->GetRuleSet()));
}

TEST_F(ActiveStyleSheetsTest, CompareActiveStyleSheets_Removed) {
  ActiveStyleSheetVector old_sheets;
  ActiveStyleSheetVector new_sheets;
  HeapHashSet<Member<RuleSet>> changed_rule_sets;

  CSSStyleSheet* sheet1 = CreateSheet();
  CSSStyleSheet* sheet2 = CreateSheet();
  CSSStyleSheet* sheet3 = CreateSheet();

  old_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  old_sheets.push_back(
      std::make_pair(sheet2, &sheet2->Contents()->GetRuleSet()));
  old_sheets.push_back(
      std::make_pair(sheet3, &sheet3->Contents()->GetRuleSet()));

  new_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  new_sheets.push_back(
      std::make_pair(sheet3, &sheet3->Contents()->GetRuleSet()));

  EXPECT_EQ(
      kActiveSheetsChanged,
      CompareActiveStyleSheets(old_sheets, new_sheets, {}, changed_rule_sets));
  EXPECT_EQ(1u, changed_rule_sets.size());
  EXPECT_TRUE(changed_rule_sets.Contains(&sheet2->Contents()->GetRuleSet()));
}

TEST_F(ActiveStyleSheetsTest, CompareActiveStyleSheets_RemovedAll) {
  ActiveStyleSheetVector old_sheets;
  ActiveStyleSheetVector new_sheets;
  HeapHashSet<Member<RuleSet>> changed_rule_sets;

  CSSStyleSheet* sheet1 = CreateSheet();
  CSSStyleSheet* sheet2 = CreateSheet();
  CSSStyleSheet* sheet3 = CreateSheet();

  old_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  old_sheets.push_back(
      std::make_pair(sheet2, &sheet2->Contents()->GetRuleSet()));
  old_sheets.push_back(
      std::make_pair(sheet3, &sheet3->Contents()->GetRuleSet()));

  EXPECT_EQ(
      kActiveSheetsChanged,
      CompareActiveStyleSheets(old_sheets, new_sheets, {}, changed_rule_sets));
  EXPECT_EQ(3u, changed_rule_sets.size());
}

TEST_F(ActiveStyleSheetsTest, CompareActiveStyleSheets_InsertedAndRemoved) {
  ActiveStyleSheetVector old_sheets;
  ActiveStyleSheetVector new_sheets;
  HeapHashSet<Member<RuleSet>> changed_rule_sets;

  CSSStyleSheet* sheet1 = CreateSheet();
  CSSStyleSheet* sheet2 = CreateSheet();
  CSSStyleSheet* sheet3 = CreateSheet();

  old_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  old_sheets.push_back(
      std::make_pair(sheet2, &sheet2->Contents()->GetRuleSet()));

  new_sheets.push_back(
      std::make_pair(sheet2, &sheet2->Contents()->GetRuleSet()));
  new_sheets.push_back(
      std::make_pair(sheet3, &sheet3->Contents()->GetRuleSet()));

  EXPECT_EQ(
      kActiveSheetsChanged,
      CompareActiveStyleSheets(old_sheets, new_sheets, {}, changed_rule_sets));
  EXPECT_EQ(2u, changed_rule_sets.size());
  EXPECT_TRUE(changed_rule_sets.Contains(&sheet1->Contents()->GetRuleSet()));
  EXPECT_TRUE(changed_rule_sets.Contains(&sheet3->Contents()->GetRuleSet()));
}

TEST_F(ActiveStyleSheetsTest, CompareActiveStyleSheets_AddNullRuleSet) {
  ActiveStyleSheetVector old_sheets;
  ActiveStyleSheetVector new_sheets;
  HeapHashSet<Member<RuleSet>> changed_rule_sets;

  CSSStyleSheet* sheet1 = CreateSheet();
  CSSStyleSheet* sheet2 = CreateSheet();

  old_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));

  new_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  new_sheets.push_back(std::make_pair(sheet2, nullptr));

  EXPECT_EQ(
      kNoActiveSheetsChanged,
      CompareActiveStyleSheets(old_sheets, new_sheets, {}, changed_rule_sets));
  EXPECT_EQ(0u, changed_rule_sets.size());
}

TEST_F(ActiveStyleSheetsTest, CompareActiveStyleSheets_RemoveNullRuleSet) {
  ActiveStyleSheetVector old_sheets;
  ActiveStyleSheetVector new_sheets;
  HeapHashSet<Member<RuleSet>> changed_rule_sets;

  CSSStyleSheet* sheet1 = CreateSheet();
  CSSStyleSheet* sheet2 = CreateSheet();

  old_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  old_sheets.push_back(std::make_pair(sheet2, nullptr));

  new_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));

  EXPECT_EQ(
      kNoActiveSheetsChanged,
      CompareActiveStyleSheets(old_sheets, new_sheets, {}, changed_rule_sets));
  EXPECT_EQ(0u, changed_rule_sets.size());
}

TEST_F(ActiveStyleSheetsTest, CompareActiveStyleSheets_AddRemoveNullRuleSet) {
  ActiveStyleSheetVector old_sheets;
  ActiveStyleSheetVector new_sheets;
  HeapHashSet<Member<RuleSet>> changed_rule_sets;

  CSSStyleSheet* sheet1 = CreateSheet();
  CSSStyleSheet* sheet2 = CreateSheet();
  CSSStyleSheet* sheet3 = CreateSheet();

  old_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  old_sheets.push_back(std::make_pair(sheet2, nullptr));

  new_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  new_sheets.push_back(std::make_pair(sheet3, nullptr));

  EXPECT_EQ(
      kNoActiveSheetsChanged,
      CompareActiveStyleSheets(old_sheets, new_sheets, {}, changed_rule_sets));
  EXPECT_EQ(0u, changed_rule_sets.size());
}

TEST_F(ActiveStyleSheetsTest,
       CompareActiveStyleSheets_RemoveNullRuleSetAndAppend) {
  ActiveStyleSheetVector old_sheets;
  ActiveStyleSheetVector new_sheets;
  HeapHashSet<Member<RuleSet>> changed_rule_sets;

  CSSStyleSheet* sheet1 = CreateSheet();
  CSSStyleSheet* sheet2 = CreateSheet();
  CSSStyleSheet* sheet3 = CreateSheet();

  old_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  old_sheets.push_back(std::make_pair(sheet2, nullptr));

  new_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  new_sheets.push_back(
      std::make_pair(sheet3, &sheet3->Contents()->GetRuleSet()));

  EXPECT_EQ(
      kActiveSheetsChanged,
      CompareActiveStyleSheets(old_sheets, new_sheets, {}, changed_rule_sets));
  EXPECT_EQ(1u, changed_rule_sets.size());
  EXPECT_TRUE(changed_rule_sets.Contains(&sheet3->Contents()->GetRuleSet()));
}

TEST_F(ActiveStyleSheetsTest, CompareActiveStyleSheets_ReorderedImportSheets) {
  ActiveStyleSheetVector old_sheets;
  ActiveStyleSheetVector new_sheets;
  HeapHashSet<Member<RuleSet>> changed_rule_sets;

  CSSStyleSheet* sheet1 = CreateSheet();
  CSSStyleSheet* sheet2 = CreateSheet();

  // It is possible to have CSSStyleSheet pointers re-orderered for html imports
  // because their documents, and hence their stylesheets are persisted on
  // remove / insert. This test is here to show that the active sheet comparison
  // is not able to see that anything changed.
  //
  // Imports are handled by forcing re-append and recalc of the document scope
  // when html imports are removed.
  old_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  old_sheets.push_back(
      std::make_pair(sheet2, &sheet2->Contents()->GetRuleSet()));

  new_sheets.push_back(
      std::make_pair(sheet2, &sheet2->Contents()->GetRuleSet()));
  new_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));

  EXPECT_EQ(
      kNoActiveSheetsChanged,
      CompareActiveStyleSheets(old_sheets, new_sheets, {}, changed_rule_sets));
  EXPECT_EQ(0u, changed_rule_sets.size());
}

TEST_F(ActiveStyleSheetsTest, CompareActiveStyleSheets_DisableAndAppend) {
  ActiveStyleSheetVector old_sheets;
  ActiveStyleSheetVector new_sheets;
  HeapHashSet<Member<RuleSet>> changed_rule_sets;

  CSSStyleSheet* sheet1 = CreateSheet();
  CSSStyleSheet* sheet2 = CreateSheet();

  old_sheets.push_back(
      std::make_pair(sheet1, &sheet1->Contents()->GetRuleSet()));
  new_sheets.push_back(std::make_pair(sheet1, nullptr));
  new_sheets.push_back(
      std::make_pair(sheet2, &sheet2->Contents()->GetRuleSet()));

  EXPECT_EQ(
      kActiveSheetsChanged,
      CompareActiveStyleSheets(old_sheets, new_sheets, {}, changed_rule_sets));
  EXPECT_EQ(2u, changed_rule_sets.size());
}

TEST_F(ActiveStyleSheetsTest, CompareActiveStyleSheets_AddRemoveNonMatchingMQ) {
  ActiveStyleSheetVector old_sheets;
  ActiveStyleSheetVector new_sheets;
  HeapHashSet<Member<RuleSet>> changed_rule_sets;

  EXPECT_EQ(
      kNoActiveSheetsChanged,
      CompareActiveStyleSheets(old_sheets, new_sheets, {}, changed_rule_sets));
  EXPECT_EQ(0u, changed_rule_sets.size());

  CSSStyleSheet* sheet1 = CreateSheet();
  MediaQuerySet* mq =
      MediaQueryParser::ParseMediaQuerySet("(min-width: 9000px)", nullptr);
  sheet1->SetMediaQueries(mq);
  sheet1->MatchesMediaQueries(MediaQueryEvaluator(GetDocument().GetFrame()));

  new_sheets.push_back(std::make_pair(sheet1, nullptr));

  EXPECT_EQ(
      kActiveSheetsAppended,
      CompareActiveStyleSheets(old_sheets, new_sheets, {}, changed_rule_sets));
  EXPECT_EQ(0u, changed_rule_sets.size());

  EXPECT_EQ(
      kActiveSheetsChanged,
      CompareActiveStyleSheets(new_sheets, old_sheets, {}, changed_rule_sets));
  EXPECT_EQ(0u, changed_rule_sets.size());
}

TEST_F(ApplyRulesetsTest, AddUniversalRuleToDocument) {
  UpdateAllLifecyclePhasesForTest();

  CSSStyleSheet* sheet = CreateSheet("body * { color:red }");

  ActiveStyleSheetVector new_style_sheets;
  new_style_sheets.push_back(
      std::make_pair(sheet, &sheet->Contents()->GetRuleSet()));

  GetStyleEngine().ApplyRuleSetChanges(GetDocument(), ActiveStyleSheetVector(),
                                       new_style_sheets, {});

  EXPECT_FALSE(GetStyleEngine().NeedsStyleInvalidation());
  EXPECT_FALSE(GetStyleEngine().NeedsStyleRecalc());
}

TEST_F(ApplyRulesetsTest, AddUniversalRuleToShadowTree) {
  GetDocument().body()->setInnerHTML("<div id=host></div>");
  Element* host = GetElementById("host");
  ASSERT_TRUE(host);

  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  UpdateAllLifecyclePhasesForTest();

  CSSStyleSheet* sheet = CreateSheet("body * { color:red }");

  ActiveStyleSheetVector new_style_sheets;
  new_style_sheets.push_back(
      std::make_pair(sheet, &sheet->Contents()->GetRuleSet()));

  GetStyleEngine().ApplyRuleSetChanges(shadow_root, ActiveStyleSheetVector(),
                                       new_style_sheets, {});

  EXPECT_FALSE(GetStyleEngine().NeedsStyleInvalidation());
  EXPECT_FALSE(GetStyleEngine().NeedsStyleRecalc());
}

TEST_F(ApplyRulesetsTest, AddFontFaceRuleToDocument) {
  UpdateAllLifecyclePhasesForTest();

  CSSStyleSheet* sheet =
      CreateSheet("@font-face { font-family: ahum; src: url(ahum.ttf) }");

  ActiveStyleSheetVector new_style_sheets;
  new_style_sheets.push_back(
      std::make_pair(sheet, &sheet->Contents()->GetRuleSet()));

  GetStyleEngine().ApplyRuleSetChanges(GetDocument(), ActiveStyleSheetVector(),
                                       new_style_sheets, {});

  EXPECT_EQ(kNoStyleChange,
            GetDocument().documentElement()->GetStyleChangeType());
}

TEST_F(ApplyRulesetsTest, AddFontFaceRuleToShadowTree) {
  GetDocument().body()->setInnerHTML("<div id=host></div>");
  Element* host = GetElementById("host");
  ASSERT_TRUE(host);

  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  UpdateAllLifecyclePhasesForTest();

  CSSStyleSheet* sheet =
      CreateSheet("@font-face { font-family: ahum; src: url(ahum.ttf) }");

  ActiveStyleSheetVector new_style_sheets;
  new_style_sheets.push_back(
      std::make_pair(sheet, &sheet->Contents()->GetRuleSet()));

  GetStyleEngine().ApplyRuleSetChanges(shadow_root, ActiveStyleSheetVector(),
                                       new_style_sheets, {});

  EXPECT_FALSE(GetDocument().NeedsStyleRecalc());
  EXPECT_FALSE(GetDocument().ChildNeedsStyleRecalc());
  EXPECT_FALSE(GetDocument().NeedsStyleInvalidation());
  EXPECT_FALSE(GetDocument().ChildNeedsStyleInvalidation());
}

TEST_F(ApplyRulesetsTest, RemoveSheetFromShadowTree) {
  GetDocument().body()->setInnerHTML("<div id=host></div>");
  Element* host = GetElementById("host");
  ASSERT_TRUE(host);

  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<style>::slotted(#dummy){color:pink}</style>");
  UpdateAllLifecyclePhasesForTest();

  ASSERT_EQ(1u, shadow_root.StyleSheets().length());

  StyleSheet* sheet = shadow_root.StyleSheets().item(0);
  ASSERT_TRUE(sheet);
  ASSERT_TRUE(sheet->IsCSSStyleSheet());

  auto* css_sheet = To<CSSStyleSheet>(sheet);
  ActiveStyleSheetVector old_style_sheets;
  old_style_sheets.push_back(
      std::make_pair(css_sheet, &css_sheet->Contents()->GetRuleSet()));
  GetStyleEngine().ApplyRuleSetChanges(shadow_root, old_style_sheets,
                                       ActiveStyleSheetVector(), {});
}

}  // namespace blink

"""

```
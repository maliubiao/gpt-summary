Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The primary goal is to analyze the given C++ test file (`invalidation_set_test.cc`) and explain its purpose, relationship to web technologies, logic, and potential errors.

2. **Identify the Core Component:** The file name itself, `invalidation_set_test.cc`, immediately points to the core component being tested: `InvalidationSet`. Looking at the `#include` directives confirms this, especially `#include "third_party/blink/renderer/core/css/invalidation/invalidation_set.h"`. This tells us the code is about managing sets of things that cause CSS invalidation.

3. **Analyze the Test Structure:** The file uses the Google Test framework (`testing/gtest/include/gtest/gtest.h`). The presence of `TEST(TestGroupName, TestName)` macros is the key indicator of individual test cases.

4. **Categorize the Tests:**  A quick scan reveals patterns in the test names:
    * `Backing_*`:  These tests seem to focus on a sub-component called `Backing`. The template usage `Backing<BackingType::kClasses>` suggests `Backing` is a templated class dealing with different types of invalidation triggers (like classes, IDs, tag names, attributes).
    * `*_InvalidatesElement`: These tests specifically check how the `InvalidationSet` interacts with DOM elements and whether it correctly identifies invalidation triggers.
    * `SubtreeInvalid_*`: These tests deal with a specific "whole subtree invalid" state.
    * `SelfInvalidationSet_*`: This test focuses on a particular type of `InvalidationSet`.

5. **Deep Dive into `Backing` Tests:**
    * **`Backing_Create`**:  Checks the initial state of a `Backing` object.
    * **`Backing_Add`**: Tests adding single and multiple items, and how it might upgrade its internal storage (from a single string to a hash set).
    * **`Backing_AddSame`**:  Checks the optimization for adding the same item multiple times.
    * **`Backing_Independence`**:  Crucially, this test verifies that different `Backing` instances (for classes, IDs, etc.) are independent. Adding to one doesn't affect others. This is a key design aspect.
    * **`Backing_ClearContains`**:  Tests the `Clear` method and whether `Contains` behaves correctly after clearing.
    * **`Backing_BackingIsEmpty` / `Backing_IsEmpty`**:  Checks different ways to determine if a `Backing` is empty.
    * **`Backing_Iterator`**: Verifies that you can iterate over the items in a `Backing`.
    * **`Backing_GetString` / `Backing_GetHashSet`**:  Examines the internal representation of the `Backing` – how it stores one or multiple items.

6. **Analyze `*_InvalidatesElement` Tests:** These tests simulate a DOM environment (using `DummyPageHolder`) and check if adding specific classes or attributes to an `InvalidationSet` correctly identifies an element as needing invalidation. This directly links the C++ code to HTML and CSS concepts.

7. **Understand `SubtreeInvalid` Tests:** These tests focus on an optimization: if the *entire* subtree is invalid, there's no need to track individual classes, IDs, etc. The tests verify that setting `SetWholeSubtreeInvalid()` clears any existing specific invalidation rules.

8. **Examine `SelfInvalidationSet` Test:**  This test confirms the existence and behavior of a special `InvalidationSet` that invalidates the element itself, rather than its descendants.

9. **Relate to Web Technologies:**
    * **CSS:** The entire purpose is to manage CSS invalidation. The tests directly manipulate class names and attributes, which are fundamental to CSS selectors.
    * **HTML:** The tests use `HTMLElement` and manipulate its `innerHTML`, showing how changes in HTML structure can trigger invalidation.
    * **JavaScript:** While this test file is C++, the concepts of CSS invalidation are directly relevant to JavaScript when manipulating the DOM. JavaScript code that changes classes, IDs, or attributes can trigger the invalidation logic tested here.

10. **Infer Logic and Assumptions:** The tests implicitly assume that:
    * Changes to an element's class list, ID, tag name, or attributes can require re-styling.
    * There are optimizations to avoid unnecessary re-styling.
    * The `InvalidationSet` is a mechanism to efficiently track what has changed and needs to be re-evaluated.

11. **Consider User/Programming Errors:**  While this is a *test* file, it highlights potential errors in the *implementation* of `InvalidationSet`. For example, a bug in the `Combine` method could lead to incorrect invalidation. From a user's perspective (a web developer), understanding how CSS invalidation works can help them write more performant code. For example, excessively adding and removing classes using JavaScript can lead to frequent invalidation and performance issues.

12. **Debug Clues:** The tests themselves serve as excellent debugging clues. If a particular type of invalidation isn't working correctly, you can look at the relevant test case to understand the expected behavior and pinpoint where the implementation might be going wrong. The setup of the DOM in the `*_InvalidatesElement` tests shows a common scenario that might be encountered during debugging.

13. **Structure the Explanation:** Organize the findings logically, starting with the high-level purpose and then diving into the details of each test category. Provide clear explanations and examples, especially when relating the code to web technologies. Use bullet points and clear headings to improve readability.

By following these steps, one can systematically analyze the given C++ test file and provide a comprehensive explanation of its functionality and its relationship to web development concepts.
这个文件 `invalidation_set_test.cc` 是 Chromium Blink 引擎中用于测试 `InvalidationSet` 类的单元测试文件。`InvalidationSet` 类位于 `blink/renderer/core/css/invalidation/invalidation_set.h`，它主要负责**追踪由于 DOM 结构或属性变化而需要重新计算样式的元素集合**。

让我们详细分解它的功能以及与其他 Web 技术的关系：

**1. 功能概述:**

* **测试 `InvalidationSet` 类的核心功能:** 这个文件中的测试用例旨在验证 `InvalidationSet` 类的各种方法是否按预期工作。这包括：
    * **添加和检查不同类型的选择器:** 例如，类名、ID、标签名、属性。
    * **管理内部存储:**  `InvalidationSet` 内部使用不同的数据结构（例如，单个字符串或哈希集合）来存储选择器，测试验证了这些内部机制的正确性。
    * **判断元素是否需要重新计算样式:** 测试了 `InvalidationSet` 如何判断一个给定的元素是否匹配其包含的选择器，从而确定该元素是否需要重新样式化。
    * **合并 `InvalidationSet` 对象:**  测试了如何将多个 `InvalidationSet` 合并为一个，这在复杂的样式计算场景中非常有用。
    * **处理“整个子树失效”的情况:**  当整个子树都需要重新计算样式时，`InvalidationSet` 可以标记这种情况，而不需要存储大量的单个选择器。
    * **处理自身失效的情况:**  存在一种特殊的 `InvalidationSet`，它表示元素自身需要失效。

* **确保 CSS 样式失效逻辑的正确性:**  `InvalidationSet` 是 CSS 样式失效机制的关键部分。这些测试保证了当 DOM 发生变化时，系统能够正确识别哪些元素受到了影响，从而触发高效的样式重新计算。

**2. 与 JavaScript, HTML, CSS 的关系及举例:**

`InvalidationSet` 的核心功能与 CSS 样式规则的匹配以及 HTML 元素的结构和属性息息相关。JavaScript 通常用于动态修改 HTML 结构和元素属性，这些修改可能会触发 CSS 样式的重新计算，而 `InvalidationSet` 就参与了这个过程。

* **CSS 选择器:** `InvalidationSet` 存储和匹配各种 CSS 选择器。
    * **例子 (CSS):**
        ```css
        .my-class { color: red; }
        #my-id { font-weight: bold; }
        div { background-color: blue; }
        [data-attribute="value"] { font-size: 16px; }
        ```
    * **例子 (C++ 测试):** 测试用例中会添加类似 "my-class"、"my-id"、"div"、"data-attribute" 这样的字符串到 `InvalidationSet` 中。

* **HTML 元素和属性:** `InvalidationSet` 需要判断 HTML 元素是否匹配其存储的选择器。
    * **例子 (HTML):**
        ```html
        <div id="my-id" class="my-class another-class" data-attribute="value">Content</div>
        ```
    * **例子 (C++ 测试):**  测试用例会创建 `HTMLElement` 对象，并设置其 ID、类名、属性等，然后使用 `InvalidationSet::InvalidatesElement()` 方法来判断是否需要失效。例如，`ClassInvalidatesElement` 和 `AttributeInvalidatesElement` 这两个测试用例就直接演示了这一点。

* **JavaScript DOM 操作:**  JavaScript 可以通过 DOM API 修改 HTML 结构和属性，这些修改会触发浏览器的样式失效机制，最终会涉及到 `InvalidationSet`。
    * **例子 (JavaScript):**
        ```javascript
        const element = document.getElementById('my-id');
        element.classList.add('new-class'); // 添加类名，可能触发样式重新计算
        element.setAttribute('another-attribute', 'another-value'); // 修改属性，可能触发样式重新计算
        ```
    * **关系说明:** 当 JavaScript 执行类似的操作时，Blink 引擎会更新 DOM 树，并使用 `InvalidationSet` 来跟踪哪些元素因这些变化而需要重新计算样式。

**3. 逻辑推理、假设输入与输出:**

让我们以 `ClassInvalidatesElement` 测试用例为例进行逻辑推理：

* **假设输入:**
    * 一个 HTML 元素 `<div id=test class='a b'>` 被添加到 DOM 中。
    * 创建了一个空的 `DescendantInvalidationSet` 对象。
    * 向该 `InvalidationSet` 对象添加了类名 "a"。
    * 向该 `InvalidationSet` 对象添加了类名 "c"。

* **逻辑推理:**
    1. 初始状态，`InvalidationSet` 为空，所以 `InvalidatesElement` 应该返回 `false`。
    2. 添加类名 "a" 后，`InvalidationSet` 包含了类选择器 "a"。由于 HTML 元素 `div` 的 `class` 属性包含 "a"，所以 `InvalidatesElement` 应该返回 `true`。
    3. 添加类名 "c" 后，`InvalidationSet` 包含了类选择器 "a" 和 "c"。由于 HTML 元素 `div` 的 `class` 属性仍然包含 "a"，所以 `InvalidatesElement` 应该继续返回 `true`。
    4. 创建一个新的空的 `InvalidationSet`，添加类名 "c"，由于 HTML 元素 `div` 的 `class` 属性不包含 "c"，所以 `InvalidatesElement` 应该返回 `false`。
    5. 创建一个新的空的 `InvalidationSet`，添加类名 "d"，由于 HTML 元素 `div` 的 `class` 属性不包含 "d"，所以 `InvalidatesElement` 应该返回 `false`。

* **预期输出:**  测试用例中的 `EXPECT_FALSE` 和 `EXPECT_TRUE` 断言应该全部通过，验证了上述逻辑推理的正确性。

**4. 用户或编程常见的使用错误举例:**

虽然用户或前端开发者通常不会直接操作 `InvalidationSet`，但理解其背后的原理可以帮助避免一些性能问题。

* **过度使用 JavaScript 修改类名或属性:**  如果 JavaScript 代码频繁地添加、删除类名或修改属性，可能会导致浏览器频繁地进行样式重新计算，从而影响性能。`InvalidationSet` 的存在就是为了更高效地管理这些重新计算，但过度的操作仍然会带来负担。
    * **例子 (错误用法):**  在一个动画循环中，每次都修改元素的 `class` 属性，即使样式变化不大。
    * **调试线索:**  开发者工具中的 Performance 面板可能会显示大量的 "Recalculate Style" 事件。

* **CSS 选择器过于宽泛:**  如果 CSS 选择器匹配了大量的元素，当其中一个元素发生变化时，可能会导致大量的元素被标记为需要重新计算样式，即使它们实际上没有受到影响。
    * **例子 (CSS):**  使用 `*` 选择器或者非常通用的标签选择器，例如 `div`。
    * **调试线索:**  虽然 `InvalidationSet` 可以优化这种情况，但过于宽泛的选择器仍然可能导致不必要的计算。

* **误解 CSS 继承和层叠:**  不理解 CSS 的继承和层叠规则可能导致不必要的 DOM 操作，从而触发不必要的样式失效。

**5. 用户操作如何一步步到达这里 (调试线索):**

开发者通常不会直接 "到达" `invalidation_set_test.cc` 这个文件，除非他们是 Blink 引擎的开发者或者在进行 Chromium 的开发和调试。但是，从用户操作的角度来看，可以追溯到导致样式失效的根源：

1. **用户与网页交互:** 用户在网页上进行操作，例如：
    * 点击按钮。
    * 滚动页面。
    * 鼠标悬停在元素上。
    * 输入文本。
2. **JavaScript 代码响应用户操作:**  这些用户操作通常会触发 JavaScript 代码的执行。
3. **JavaScript 修改 DOM:** JavaScript 代码可能会修改 DOM 结构或元素属性：
    * 使用 `element.classList.add()` 或 `element.classList.remove()` 添加或删除类名。
    * 使用 `element.setAttribute()` 修改属性。
    * 使用 `element.style.property = value` 修改内联样式。
    * 添加或删除 DOM 节点。
4. **Blink 引擎接收到 DOM 变化通知:**  当 DOM 发生变化时，Blink 引擎会收到通知。
5. **样式失效 (Invalidation) 过程:**
    * Blink 引擎会使用某种机制（例如，mutation observer）来检测 DOM 的变化。
    * **`InvalidationSet` 被创建或更新:**  根据 DOM 的变化类型，会创建或更新 `InvalidationSet` 对象，将受影响的元素和相关的选择器添加到其中。
    * 确定需要重新计算样式的元素。
6. **样式重新计算 (Style Recalculation):**  Blink 引擎会根据 `InvalidationSet` 中的信息，重新计算受影响元素的样式。
7. **布局 (Layout) 和绘制 (Paint):**  样式重新计算完成后，如果影响了元素的布局或外观，则会进行布局和绘制阶段。
8. **用户看到页面更新:**  最终，用户会在浏览器中看到页面更新后的效果。

**调试线索:**

* **开发者工具 Performance 面板:** 可以记录页面性能，查看 "Recalculate Style" 事件，了解样式重新计算的频率和耗时。
* **开发者工具 Elements 面板:** 可以查看元素的 Computed 样式，了解最终应用的样式。
* **Blink 开发者调试:**  Blink 开发者可以使用断点、日志等工具跟踪 `InvalidationSet` 的创建、更新和使用过程，例如在 `InvalidationSet::AddClass()`、`InvalidationSet::InvalidatesElement()` 等方法中设置断点。

总而言之，`invalidation_set_test.cc` 是 Blink 引擎中一个重要的测试文件，它确保了 CSS 样式失效机制的核心组件 `InvalidationSet` 的正确性，这对于保证网页的渲染性能至关重要。理解其功能和与其他 Web 技术的联系，可以帮助开发者更好地理解浏览器的工作原理，并编写出更高效的前端代码。

### 提示词
```
这是目录为blink/renderer/core/css/invalidation/invalidation_set_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/invalidation/invalidation_set.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {
namespace {

using BackingType = InvalidationSet::BackingType;
using BackingFlags = InvalidationSet::BackingFlags;
template <BackingType type>
using Backing = InvalidationSet::Backing<type>;

template <BackingType type>
bool HasAny(const Backing<type>& backing,
            const BackingFlags& flags,
            std::initializer_list<const char*> args) {
  for (const char* str : args) {
    if (backing.Contains(flags, AtomicString(str))) {
      return true;
    }
  }
  return false;
}

template <BackingType type>
bool HasAll(const Backing<type>& backing,
            const BackingFlags& flags,
            std::initializer_list<const char*> args) {
  for (const char* str : args) {
    if (!backing.Contains(flags, AtomicString(str))) {
      return false;
    }
  }
  return true;
}

TEST(InvalidationSetTest, Backing_Create) {
  BackingFlags flags;
  Backing<BackingType::kClasses> backing;

  ASSERT_FALSE(backing.IsHashSet(flags));
}

TEST(InvalidationSetTest, Backing_Add) {
  BackingFlags flags;
  Backing<BackingType::kClasses> backing;

  ASSERT_FALSE(backing.IsHashSet(flags));
  backing.Add(flags, AtomicString("test1"));
  ASSERT_FALSE(backing.IsHashSet(flags));
  backing.Add(flags, AtomicString("test2"));
  ASSERT_TRUE(backing.IsHashSet(flags));
  backing.Clear(flags);
}

TEST(InvalidationSetTest, Backing_AddSame) {
  BackingFlags flags;
  Backing<BackingType::kClasses> backing;

  ASSERT_FALSE(backing.IsHashSet(flags));
  backing.Add(flags, AtomicString("test1"));
  ASSERT_FALSE(backing.IsHashSet(flags));
  backing.Add(flags, AtomicString("test1"));
  // No need to upgrade to HashSet if we're adding the item we already have.
  ASSERT_FALSE(backing.IsHashSet(flags));
  backing.Clear(flags);
}

TEST(InvalidationSetTest, Backing_Independence) {
  BackingFlags flags;

  Backing<BackingType::kClasses> classes;
  Backing<BackingType::kIds> ids;
  Backing<BackingType::kTagNames> tag_names;
  Backing<BackingType::kAttributes> attributes;

  classes.Add(flags, AtomicString("test1"));
  ids.Add(flags, AtomicString("test2"));
  tag_names.Add(flags, AtomicString("test3"));
  attributes.Add(flags, AtomicString("test4"));

  // Adding to set does not affect other backings:
  ASSERT_TRUE(classes.Contains(flags, AtomicString("test1")));
  ASSERT_FALSE(HasAny(classes, flags, {"test2", "test3", "test4"}));

  ASSERT_TRUE(ids.Contains(flags, AtomicString("test2")));
  ASSERT_FALSE(HasAny(ids, flags, {"test1", "test3", "test4"}));

  ASSERT_TRUE(tag_names.Contains(flags, AtomicString("test3")));
  ASSERT_FALSE(HasAny(tag_names, flags, {"test1", "test2", "test4"}));

  ASSERT_TRUE(attributes.Contains(flags, AtomicString("test4")));
  ASSERT_FALSE(HasAny(attributes, flags, {"test1", "test2", "test3"}));

  // Adding additional items to one set does not affect others:
  classes.Add(flags, AtomicString("test5"));
  tag_names.Add(flags, AtomicString("test6"));

  ASSERT_TRUE(HasAll(classes, flags, {"test1", "test5"}));
  ASSERT_FALSE(HasAny(classes, flags, {"test2", "test3", "test4", "test6"}));

  ASSERT_TRUE(ids.Contains(flags, AtomicString("test2")));
  ASSERT_FALSE(
      HasAny(ids, flags, {"test1", "test3", "test4", "test5", "test6"}));

  ASSERT_TRUE(HasAll(tag_names, flags, {"test3", "test6"}));
  ASSERT_FALSE(HasAny(tag_names, flags, {"test1", "test2", "test4", "test5"}));

  ASSERT_TRUE(attributes.Contains(flags, AtomicString("test4")));
  ASSERT_FALSE(HasAny(attributes, flags, {"test1", "test2", "test3"}));

  // Clearing one set does not clear others:

  classes.Clear(flags);
  ids.Clear(flags);
  attributes.Clear(flags);

  auto all_test_strings = {"test1", "test2", "test3",
                           "test4", "test5", "test6"};

  ASSERT_FALSE(HasAny(classes, flags, all_test_strings));
  ASSERT_FALSE(HasAny(ids, flags, all_test_strings));
  ASSERT_FALSE(HasAny(attributes, flags, all_test_strings));

  ASSERT_FALSE(classes.IsHashSet(flags));
  ASSERT_FALSE(ids.IsHashSet(flags));
  ASSERT_FALSE(attributes.IsHashSet(flags));

  ASSERT_TRUE(tag_names.IsHashSet(flags));
  ASSERT_TRUE(HasAll(tag_names, flags, {"test3", "test6"}));
  ASSERT_FALSE(HasAny(tag_names, flags, {"test1", "test2", "test4", "test5"}));
  tag_names.Clear(flags);
}

TEST(InvalidationSetTest, Backing_ClearContains) {
  BackingFlags flags;
  Backing<BackingType::kClasses> backing;

  AtomicString test1("test1");
  AtomicString test2("test2");

  // Clearing an empty set:
  ASSERT_FALSE(backing.Contains(flags, test1));
  ASSERT_FALSE(backing.IsHashSet(flags));
  backing.Clear(flags);
  ASSERT_FALSE(backing.IsHashSet(flags));

  // Add one element to the set, and clear it:
  backing.Add(flags, test1);
  ASSERT_FALSE(backing.IsHashSet(flags));
  ASSERT_TRUE(backing.Contains(flags, test1));
  backing.Clear(flags);
  ASSERT_FALSE(backing.Contains(flags, test1));
  ASSERT_FALSE(backing.IsHashSet(flags));

  // Add two elements to the set, and clear them:
  backing.Add(flags, test1);
  ASSERT_FALSE(backing.IsHashSet(flags));
  ASSERT_TRUE(backing.Contains(flags, test1));
  ASSERT_FALSE(backing.Contains(flags, test2));
  backing.Add(flags, test2);
  ASSERT_TRUE(backing.IsHashSet(flags));
  ASSERT_TRUE(backing.Contains(flags, test1));
  ASSERT_TRUE(backing.Contains(flags, test2));
  backing.Clear(flags);
  ASSERT_FALSE(backing.Contains(flags, test1));
  ASSERT_FALSE(backing.Contains(flags, test2));
  ASSERT_FALSE(backing.IsHashSet(flags));
}

TEST(InvalidationSetTest, Backing_BackingIsEmpty) {
  BackingFlags flags;
  Backing<BackingType::kClasses> backing;

  ASSERT_TRUE(backing.IsEmpty(flags));
  backing.Add(flags, AtomicString("test1"));
  ASSERT_FALSE(backing.IsEmpty(flags));
  backing.Add(flags, AtomicString("test2"));
  backing.Clear(flags);
  ASSERT_TRUE(backing.IsEmpty(flags));
}

TEST(InvalidationSetTest, Backing_IsEmpty) {
  BackingFlags flags;
  Backing<BackingType::kClasses> backing;

  ASSERT_TRUE(backing.IsEmpty(flags));

  backing.Add(flags, AtomicString("test1"));
  ASSERT_FALSE(backing.IsEmpty(flags));

  backing.Clear(flags);
  ASSERT_TRUE(backing.IsEmpty(flags));
}

TEST(InvalidationSetTest, Backing_Iterator) {
  AtomicString test1("test1");
  AtomicString test2("test2");
  AtomicString test3("test3");
  // Iterate over empty set.
  {
    BackingFlags flags;
    Backing<BackingType::kClasses> backing;

    Vector<AtomicString> strings;
    for (const AtomicString& str : backing.Items(flags)) {
      strings.push_back(str);
    }
    ASSERT_EQ(0u, strings.size());
  }

  // Iterate over set with one item.
  {
    BackingFlags flags;
    Backing<BackingType::kClasses> backing;

    backing.Add(flags, test1);
    Vector<AtomicString> strings;
    for (const AtomicString& str : backing.Items(flags)) {
      strings.push_back(str);
    }
    ASSERT_EQ(1u, strings.size());
    ASSERT_TRUE(strings.Contains(test1));
    backing.Clear(flags);
  }

  // Iterate over set with multiple items.
  {
    BackingFlags flags;
    Backing<BackingType::kClasses> backing;

    backing.Add(flags, test1);
    backing.Add(flags, test2);
    backing.Add(flags, test3);
    Vector<AtomicString> strings;
    for (const AtomicString& str : backing.Items(flags)) {
      strings.push_back(str);
    }
    ASSERT_EQ(3u, strings.size());
    ASSERT_TRUE(strings.Contains(test1));
    ASSERT_TRUE(strings.Contains(test2));
    ASSERT_TRUE(strings.Contains(test3));
    backing.Clear(flags);
  }
}

TEST(InvalidationSetTest, Backing_GetString) {
  BackingFlags flags;
  Backing<BackingType::kClasses> backing;
  ASSERT_NE(nullptr, backing.GetString(flags));
  EXPECT_TRUE(backing.GetString(flags)->IsNull());
  backing.Add(flags, AtomicString("a"));
  EXPECT_EQ("a", *backing.GetString(flags));
  backing.Add(flags, AtomicString("b"));
  EXPECT_EQ(nullptr, backing.GetString(flags));
  backing.Clear(flags);
}

TEST(InvalidationSetTest, Backing_GetHashSet) {
  BackingFlags flags;
  Backing<BackingType::kClasses> backing;
  EXPECT_FALSE(backing.GetHashSet(flags));
  backing.Add(flags, AtomicString("a"));
  EXPECT_FALSE(backing.GetHashSet(flags));
  backing.Add(flags, AtomicString("b"));
  EXPECT_TRUE(backing.GetHashSet(flags));
  backing.Clear(flags);
}

TEST(InvalidationSetTest, ClassInvalidatesElement) {
  test::TaskEnvironment task_environment;
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  auto& document = dummy_page_holder->GetDocument();
  document.body()->setInnerHTML("<div id=test class='a b'>");
  document.View()->UpdateAllLifecyclePhasesForTest();
  Element* element = document.getElementById(AtomicString("test"));
  ASSERT_TRUE(element);

  scoped_refptr<InvalidationSet> set = DescendantInvalidationSet::Create();
  EXPECT_FALSE(set->InvalidatesElement(*element));
  // Adding one string sets the string_impl_ of the classes_ Backing.
  set->AddClass(AtomicString("a"));
  EXPECT_TRUE(set->InvalidatesElement(*element));
  // Adding another upgrades to a HashSet.
  set->AddClass(AtomicString("c"));
  EXPECT_TRUE(set->InvalidatesElement(*element));

  // These sets should not cause invalidation.
  set = DescendantInvalidationSet::Create();
  set->AddClass(AtomicString("c"));
  EXPECT_FALSE(set->InvalidatesElement(*element));
  set->AddClass(AtomicString("d"));
  EXPECT_FALSE(set->InvalidatesElement(*element));
}

TEST(InvalidationSetTest, AttributeInvalidatesElement) {
  test::TaskEnvironment task_environment;
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  auto& document = dummy_page_holder->GetDocument();
  document.body()->setInnerHTML("<div id=test a b>");
  document.View()->UpdateAllLifecyclePhasesForTest();
  Element* element = document.getElementById(AtomicString("test"));
  ASSERT_TRUE(element);

  scoped_refptr<InvalidationSet> set = DescendantInvalidationSet::Create();
  EXPECT_FALSE(set->InvalidatesElement(*element));
  // Adding one string sets the string_impl_ of the classes_ Backing.
  set->AddAttribute(AtomicString("a"));
  EXPECT_TRUE(set->InvalidatesElement(*element));
  // Adding another upgrades to a HashSet.
  set->AddAttribute(AtomicString("c"));
  EXPECT_TRUE(set->InvalidatesElement(*element));

  // These sets should not cause invalidation.
  set = DescendantInvalidationSet::Create();
  set->AddAttribute(AtomicString("c"));
  EXPECT_FALSE(set->InvalidatesElement(*element));
  set->AddAttribute(AtomicString("d"));
  EXPECT_FALSE(set->InvalidatesElement(*element));
}

// Once we setWholeSubtreeInvalid, we should not keep the HashSets.
TEST(InvalidationSetTest, SubtreeInvalid_AddBefore) {
  scoped_refptr<InvalidationSet> set = DescendantInvalidationSet::Create();
  set->AddClass(AtomicString("a"));
  set->SetWholeSubtreeInvalid();

  ASSERT_TRUE(set->IsEmpty());
}

// Don't (re)create HashSets if we've already setWholeSubtreeInvalid.
TEST(InvalidationSetTest, SubtreeInvalid_AddAfter) {
  scoped_refptr<InvalidationSet> set = DescendantInvalidationSet::Create();
  set->SetWholeSubtreeInvalid();
  set->AddTagName(AtomicString("a"));

  ASSERT_TRUE(set->IsEmpty());
}

// No need to keep the HashSets when combining with a wholeSubtreeInvalid set.
TEST(InvalidationSetTest, SubtreeInvalid_Combine_1) {
  scoped_refptr<DescendantInvalidationSet> set1 =
      DescendantInvalidationSet::Create();
  scoped_refptr<DescendantInvalidationSet> set2 =
      DescendantInvalidationSet::Create();

  set1->AddId(AtomicString("a"));
  set2->SetWholeSubtreeInvalid();

  set1->Combine(*set2);

  ASSERT_TRUE(set1->WholeSubtreeInvalid());
  ASSERT_TRUE(set1->IsEmpty());
}

// No need to add HashSets from combining set when we already have
// wholeSubtreeInvalid.
TEST(InvalidationSetTest, SubtreeInvalid_Combine_2) {
  scoped_refptr<DescendantInvalidationSet> set1 =
      DescendantInvalidationSet::Create();
  scoped_refptr<DescendantInvalidationSet> set2 =
      DescendantInvalidationSet::Create();

  set1->SetWholeSubtreeInvalid();
  set2->AddAttribute(AtomicString("a"));

  set1->Combine(*set2);

  ASSERT_TRUE(set1->WholeSubtreeInvalid());
  ASSERT_TRUE(set1->IsEmpty());
}

TEST(InvalidationSetTest, SubtreeInvalid_AddCustomPseudoBefore) {
  scoped_refptr<InvalidationSet> set = DescendantInvalidationSet::Create();
  set->SetCustomPseudoInvalid();
  ASSERT_FALSE(set->IsEmpty());

  set->SetWholeSubtreeInvalid();
  ASSERT_TRUE(set->IsEmpty());
}

TEST(InvalidationSetTest, SelfInvalidationSet_Combine) {
  InvalidationSet* self_set = InvalidationSet::SelfInvalidationSet();

  EXPECT_TRUE(self_set->IsSelfInvalidationSet());
  self_set->Combine(*self_set);
  EXPECT_TRUE(self_set->IsSelfInvalidationSet());

  scoped_refptr<InvalidationSet> set = DescendantInvalidationSet::Create();
  EXPECT_FALSE(set->InvalidatesSelf());
  set->Combine(*self_set);
  EXPECT_TRUE(set->InvalidatesSelf());
}

}  // namespace
}  // namespace blink
```
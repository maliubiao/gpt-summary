Response:
Let's break down the thought process for analyzing the `cascade_priority_test.cc` file.

1. **Understand the Goal:** The primary goal is to understand the *functionality* of this specific C++ test file within the Chromium Blink rendering engine. This means figuring out what aspects of the CSS cascade it's testing.

2. **Identify the Core Class Under Test:** The file name itself, `cascade_priority_test.cc`, strongly suggests that the `CascadePriority` class is the main subject of these tests. A quick scan of the includes confirms this.

3. **Analyze the Test Structure:** The file uses Google Test (`gtest`). This means we'll see `TEST()` macros defining individual test cases. These test cases are grouped by the first argument to `TEST()`, which acts as a test suite name. In this file, the suite name is consistently `CascadePriorityTest`.

4. **Examine Individual Test Cases:** The key to understanding the file's functionality is to go through each test case and determine what it's verifying. Here's a breakdown of the thought process for some key tests:

   * **`EncodeOriginImportance`:**  This test directly manipulates the bits used to represent the origin and importance of a style rule. It's checking the correctness of the `EncodeOriginImportance` function. This is a low-level implementation detail, but important for ensuring the priority logic works correctly.

   * **`OriginOperators`:** This test verifies the comparison operators (`>`, `<`, `>=`, `<=`, `==`, `!=`) for `CascadePriority` objects based on their `CascadeOrigin`. It confirms the expected order of precedence for different origins (e.g., `kTransition` > `kAnimation` > `kAuthor`).

   * **`OriginImportance`:** This expands on `OriginOperators` by including the `important` flag in the comparisons. It tests the interaction between origin and importance.

   * **`IsImportant`:**  A straightforward test to confirm that the `IsImportant()` method of `CascadePriority` correctly reflects whether the `important` flag is set.

   * **`GetOrigin` and `HasOrigin`:** These tests verify the accessor methods for retrieving and checking the presence of a `CascadeOrigin`.

   * **`EncodeTreeOrder`:** Similar to `EncodeOriginImportance`, this tests the bit manipulation used to encode the tree order and its relationship with importance.

   * **`TreeOrder` and `TreeOrderImportant`:** These tests focus on how the `tree_order` affects priority, both for regular and `!important` rules. The `tree_order` reflects the order of elements in the DOM.

   * **`Position` and `PositionAndTreeOrder`:** These tests examine the role of the `position` (likely the order of rules within a stylesheet or inline style) in determining priority, and how it interacts with `tree_order`.

   * **`LayerOrder` and related tests:**  These focus on CSS cascade layers (`@layer`). They verify how the `layer_order` influences priority.

   * **`InlineStyle`:** This is a crucial test case, specifically dealing with the priority of inline styles (`style="..."`). It checks how inline styles compare to other types of styles.

   * **`TryStyle` and `TryTacticsStyle`:** These seem to relate to experimental or specific types of styling mechanisms. The comments within the tests provide clues about their intended behavior (e.g., generating separate layers).

   * **`ForLayerComparison`:** This tests a specific method used for comparing priorities *within* the same cascade layer. It highlights that some factors are ignored when comparing within a layer.

5. **Identify Relationships to Web Technologies:**  As each test case is understood, consider how it relates to HTML, CSS, and JavaScript:

   * **HTML:** The `tree_order` directly relates to the structure of the HTML DOM tree. Inline styles are a feature of HTML elements.
   * **CSS:**  The entire concept of cascade priority is fundamental to CSS. The different origins (`kUserAgent`, `kUser`, `kAuthor`), `!important` rules, and cascade layers are all core CSS features.
   * **JavaScript:**  While this test file is C++, JavaScript can dynamically modify CSS styles, including inline styles. The priority rules tested here apply regardless of how the styles are applied.

6. **Look for Logic and Examples:**  The test cases themselves often serve as examples of the logic being tested. The `EXPECT_GE`, `EXPECT_LT`, and `EXPECT_EQ` assertions directly show the expected priority relationships. The `Options` struct and the helper functions like `AuthorPriority` make the test setup clear.

7. **Consider Potential User Errors:** Think about how developers or users might encounter situations where these priority rules matter and might make mistakes. Common errors involve misunderstandings about the order of precedence of different style origins or the impact of `!important`.

8. **Imagine the Debugging Scenario:** Consider how a developer might end up looking at this code. It's likely because they are investigating a CSS priority issue. They might be trying to understand *why* a particular style is being applied instead of another. The test cases in this file provide a clear and structured way to understand the different factors that influence cascade priority.

9. **Structure the Explanation:** Organize the findings into logical sections, starting with the main purpose, then drilling down into specific functionalities, relationships to web technologies, and potential user errors. Use clear and concise language, and provide concrete examples where possible. The use of bullet points and code snippets helps with readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This just tests the `CascadePriority` class."
* **Refinement:** "It tests specific *aspects* of `CascadePriority`, like how it handles different origins, importance, tree order, layers, and inline styles."

* **Initial thought:** "The bit manipulation tests are just implementation details."
* **Refinement:** "While low-level, they are crucial for ensuring the overall priority logic is correct. They test the encoding and decoding of priority information."

* **Initial thought:** "How does this relate to user actions?"
* **Refinement:** "User actions in a browser can trigger style recalculations. This code ensures those recalculations correctly apply CSS priority rules based on the HTML structure and CSS rules."

By following this iterative process of examining the code, considering its context, and thinking about its implications, a comprehensive understanding of the file's functionality can be achieved.
这个文件 `blink/renderer/core/css/resolver/cascade_priority_test.cc` 是 Chromium Blink 引擎中用于测试 `CascadePriority` 类的单元测试文件。 `CascadePriority` 类负责表示和比较 CSS 规则在层叠过程中的优先级。

以下是该文件的详细功能说明：

**功能:**

1. **测试 `CascadePriority` 类的各种构造和比较行为:**  该文件包含了多个 `TEST` 宏定义的测试用例，用于验证 `CascadePriority` 类的不同构造方式和其比较运算符（例如 `>`，`<`，`>=`，`<=`，`==`，`!=`）的正确性。

2. **测试 CSS 层叠优先级规则的实现:**  通过设置不同的 `CascadePriority` 对象，并使用比较运算符进行比较，该文件测试了 Blink 引擎中 CSS 层叠优先级规则的实现是否符合预期。 这些规则包括：
    * **来源 (Origin):**  例如 User-Agent 样式、用户样式、作者样式、动画样式、过渡样式等。
    * **重要性 (!important):**  测试 `!important` 声明对优先级的影响。
    * **DOM 树顺序 (Tree Order):**  测试样式声明在 DOM 树中的出现顺序对优先级的影响。
    * **内联样式 (Inline Style):**  测试 HTML 元素的 `style` 属性定义的内联样式与其他样式来源的优先级关系。
    * **CSS Layers (@layer):** 测试 CSS 层叠层的功能及其对优先级的影响。
    * **尝试样式 (Try Style) 和尝试策略样式 (Try Tactics Style):**  测试特定类型的样式在层叠中的优先级行为（这可能是 Blink 引擎内部的特殊概念）。
    * **位置 (Position):**  测试样式规则在样式表或内联样式中的声明顺序对优先级的影响。

3. **测试 `CascadePriority` 类的辅助方法:**  该文件还测试了 `CascadePriority` 类的一些辅助方法，例如：
    * `EncodeOriginImportance`: 测试将来源和重要性编码为整数的方法。
    * `IsImportant`: 测试判断样式是否为 `!important` 的方法。
    * `GetOrigin`: 测试获取样式来源的方法。
    * `HasOrigin`: 测试样式是否具有特定来源的方法。
    * `EncodeTreeOrder`: 测试编码 DOM 树顺序的方法。
    * `EncodeLayerOrder`: 测试编码层叠层顺序的方法。
    * `ForLayerComparison`: 测试用于层叠层内部比较优先级的方法。
    * `GetPosition`: 测试获取样式位置的方法。
    * `GetGeneration`: 测试获取样式生成信息的方法。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

该文件直接关联到 CSS 的核心概念——层叠优先级。CSS 的层叠决定了当多个样式规则应用于同一个 HTML 元素时，哪个规则的属性值最终生效。

* **CSS:** 该文件测试的核心就是 CSS 的层叠优先级规则。例如，测试用例会验证 `!important` 的作者样式比非 `!important` 的用户代理样式具有更高的优先级。
    * **举例:**  在 CSS 中，如果作者样式定义了 `color: blue;`，而用户代理样式定义了 `color: black;`，那么元素最终的颜色将是蓝色，因为作者样式的优先级更高。 该文件中的 `TEST(CascadePriorityTest, OriginOperators)` 和 `TEST(CascadePriorityTest, OriginImportance)` 等测试用例就覆盖了这类场景。

* **HTML:** HTML 结构通过 DOM 树顺序影响 CSS 的层叠。后出现的样式规则（在 DOM 树中）通常具有更高的优先级（在来源和重要性相同的情况下）。内联样式是直接写在 HTML 元素上的，其优先级高于大多数其他作者样式。
    * **举例:**  考虑以下 HTML 片段：
      ```html
      <div id="container" style="color: green;">
        <p style="color: red;">This is a paragraph.</p>
      </div>
      ```
      段落 `<p>` 的颜色最终会是红色，因为其内联样式的优先级高于容器 `<div>` 的内联样式。 `TEST(CascadePriorityTest, InlineStyle)` 就测试了内联样式的优先级。

* **JavaScript:** JavaScript 可以动态地修改 HTML 元素的样式，包括添加、删除或修改内联样式。理解 CSS 的层叠优先级对于编写能够正确控制元素样式的 JavaScript 代码至关重要。虽然这个测试文件本身不是 JavaScript 代码，但它验证了 Blink 引擎中处理 CSS 优先级的 C++ 代码的正确性，这直接影响到 JavaScript 操作样式后的最终渲染结果。
    * **举例:**  如果 JavaScript 代码设置了 `element.style.color = 'orange';`，那么这个内联样式会根据 CSS 层叠规则与其他样式竞争优先级。该文件确保了 Blink 引擎能够正确处理这种动态添加的内联样式的优先级。

**逻辑推理和假设输入与输出:**

许多测试用例都基于逻辑推理来验证优先级关系。以下是一个例子：

**假设输入:** 两个 `CascadePriority` 对象：
* `priority1`:  作者来源，非 `!important`，DOM 树顺序为 1。
* `priority2`:  作者来源，非 `!important`，DOM 树顺序为 0。

**测试用例代码 (简化):**
```c++
TEST(CascadePriorityTest, TreeOrder) {
  CascadePriority priority1 = AuthorPriority(1, 0);
  CascadePriority priority2 = AuthorPriority(0, 0);
  EXPECT_GE(priority1, priority2); // 断言 priority1 的优先级大于或等于 priority2
}
```

**逻辑推理:**  在来源和重要性相同的情况下，DOM 树顺序越大的样式规则优先级越高。

**预期输出:** `EXPECT_GE(priority1, priority2)` 断言成功，因为 `priority1` 的 DOM 树顺序 (1) 大于 `priority2` 的 DOM 树顺序 (0)。

**用户或编程常见的使用错误举例说明:**

* **误解 `!important` 的作用:**  开发者可能会过度使用 `!important`，导致样式难以覆盖和维护。例如，在作者样式中使用了 `!important`，却期望用户样式能够覆盖它，这是不可能的，除非用户样式也使用了 `!important` 并且有更高的优先级（例如，通过特定的浏览器设置）。
    * **测试文件如何帮助调试:**  `TEST(CascadePriorityTest, IsImportant)` 和包含 `important` 标志的比较测试用例可以帮助开发者理解 `!important` 对优先级的影响。

* **忘记考虑来源优先级:**  开发者可能只关注选择器的 specificity，而忽略了不同来源的优先级顺序。例如，期望作者样式能够覆盖用户代理的默认样式，但用户代理的某些样式（尤其是 `!important` 的）具有更高的优先级。
    * **测试文件如何帮助调试:** `TEST(CascadePriorityTest, OriginOperators)` 和 `TEST(CascadePriorityTest, OriginImportance)` 明确地测试了不同来源之间的优先级关系。

* **对内联样式的优先级理解不足:**  开发者可能不清楚内联样式的优先级高于大多数其他作者样式。
    * **测试文件如何帮助调试:** `TEST(CascadePriorityTest, InlineStyle)` 专门测试了内联样式与其他样式的优先级比较。

* **不了解 CSS Layers 的工作方式:**  CSS Layers 引入了新的优先级维度。开发者可能不清楚未分层的样式与分层样式的优先级关系，或者不同层之间的优先级关系。
    * **测试文件如何帮助调试:**  包含 `layer_order` 的测试用例，例如 `TEST(CascadePriorityTest, LayerOrder)` 和 `TEST(CascadePriorityTest, ForLayerComparison)`，验证了 CSS Layers 相关的优先级逻辑。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户遇到页面样式问题:** 用户浏览网页时，发现某个元素的样式不符合预期。例如，某个文本的颜色应该是红色，但实际显示为蓝色。

2. **开发者检查元素:** 开发者使用浏览器开发者工具（通常通过右键点击元素并选择 "检查" 或 "检查元素"）来查看该元素的样式。

3. **开发者查看 "Computed" 或 "Styles" 面板:** 在开发者工具中，"Computed" 面板会显示最终应用于元素的所有样式属性及其值，以及生效的样式来源。"Styles" 面板会列出所有匹配该元素的选择器及其样式规则。

4. **开发者发现优先级冲突:**  开发者在 "Styles" 或 "Computed" 面板中可能会看到多个样式规则都试图设置同一个属性（例如 `color`），但只有一个生效。这表明存在优先级冲突。

5. **开发者需要理解优先级规则:** 为了解决这个冲突，开发者需要理解 CSS 的层叠优先级规则，包括来源、重要性、选择器 specificity、DOM 树顺序等因素。

6. **如果开发者怀疑 Blink 引擎的优先级计算有问题:**  在极少数情况下，开发者可能会怀疑浏览器引擎本身在计算优先级时存在错误。这通常发生在一些非常复杂或边缘的 CSS 场景中。

7. **开发者可能会查看 Blink 引擎的源代码:**  为了深入理解 Blink 引擎是如何处理 CSS 优先级的，或者为了验证他们对优先级规则的理解是否正确，开发者可能会查找相关的源代码文件，例如 `blink/renderer/core/css/resolver/cascade_priority.cc` 和 `blink/renderer/core/css/resolver/cascade_priority_test.cc`。

8. **查看测试用例作为调试线索:** `cascade_priority_test.cc` 文件中的测试用例可以作为开发者理解 Blink 引擎中 CSS 优先级实现的宝贵线索。通过阅读这些测试用例，开发者可以了解各种优先级场景下的预期行为，从而帮助他们诊断和解决他们遇到的样式问题。例如，如果开发者不确定内联样式和 `!important` 的作者样式哪个优先级更高，他们可以在 `cascade_priority_test.cc` 中找到相关的测试用例来验证。

总而言之，`cascade_priority_test.cc` 是一个关键的测试文件，它确保了 Blink 引擎能够正确地实现 CSS 的层叠优先级规则，这对于网页样式的正确渲染至关重要。开发者可以通过阅读这个文件中的测试用例来深入理解 CSS 的优先级机制，并辅助他们进行样式调试。

Prompt: 
```
这是目录为blink/renderer/core/css/resolver/cascade_priority_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/resolver/cascade_priority.h"
#include <gtest/gtest.h>

namespace blink {

namespace {

struct Options {
  CascadeOrigin origin = CascadeOrigin::kAuthor;
  bool important = false;
  uint16_t tree_order = 0;
  bool is_inline_style = false;
  bool is_try_style = false;
  bool is_try_tactics_style = false;
  uint16_t layer_order = 0;
  uint32_t position = 0;
};

CascadePriority Priority(Options o) {
  return CascadePriority(o.origin, o.important, o.tree_order, o.is_inline_style,
                         o.is_try_style, o.is_try_tactics_style, o.layer_order,
                         o.position);
}

CascadePriority AuthorPriority(uint16_t tree_order, uint32_t position) {
  return Priority({.origin = CascadeOrigin::kAuthor,
                   .tree_order = tree_order,
                   .position = position});
}

CascadePriority ImportantAuthorPriority(uint16_t tree_order,
                                        uint32_t position) {
  return Priority({.origin = CascadeOrigin::kAuthor,
                   .important = true,
                   .tree_order = tree_order,
                   .position = position});
}

}  // namespace

TEST(CascadePriorityTest, EncodeOriginImportance) {
  using Origin = CascadeOrigin;
  EXPECT_EQ(0b00001ull, EncodeOriginImportance(Origin::kUserAgent, false));
  EXPECT_EQ(0b00010ull, EncodeOriginImportance(Origin::kUser, false));
  EXPECT_EQ(0b00100ull, EncodeOriginImportance(Origin::kAuthor, false));
  EXPECT_EQ(0b00101ull, EncodeOriginImportance(Origin::kAnimation, false));
  EXPECT_EQ(0b01011ull, EncodeOriginImportance(Origin::kAuthor, true));
  EXPECT_EQ(0b01101ull, EncodeOriginImportance(Origin::kUser, true));
  EXPECT_EQ(0b01110ull, EncodeOriginImportance(Origin::kUserAgent, true));
  EXPECT_EQ(0b10000ull, EncodeOriginImportance(Origin::kTransition, false));
}

TEST(CascadePriorityTest, OriginOperators) {
  std::vector<CascadePriority> priorities = {
      Priority({.origin = CascadeOrigin::kTransition}),
      Priority({.origin = CascadeOrigin::kAnimation}),
      Priority({.origin = CascadeOrigin::kAuthor}),
      Priority({.origin = CascadeOrigin::kUser}),
      Priority({.origin = CascadeOrigin::kUserAgent}),
      Priority({.origin = CascadeOrigin::kNone})};

  for (size_t i = 0; i < priorities.size(); ++i) {
    for (size_t j = i; j < priorities.size(); ++j) {
      EXPECT_GE(priorities[i], priorities[j]);
      EXPECT_FALSE(priorities[i] < priorities[j]);
    }
  }

  for (size_t i = 0; i < priorities.size(); ++i) {
    for (size_t j = i + 1; j < priorities.size(); ++j) {
      EXPECT_LT(priorities[j], priorities[i]);
      EXPECT_FALSE(priorities[j] >= priorities[i]);
    }
  }

  for (CascadePriority priority : priorities) {
    EXPECT_EQ(priority, priority);
  }

  for (size_t i = 0; i < priorities.size(); ++i) {
    for (size_t j = 0; j < priorities.size(); ++j) {
      if (i == j) {
        continue;
      }
      EXPECT_NE(priorities[i], priorities[j]);
    }
  }
}

TEST(CascadePriorityTest, OriginImportance) {
  std::vector<CascadePriority> priorities = {
      Priority({.origin = CascadeOrigin::kTransition, .important = false}),
      Priority({.origin = CascadeOrigin::kUserAgent, .important = true}),
      Priority({.origin = CascadeOrigin::kUser, .important = true}),
      Priority({.origin = CascadeOrigin::kAuthor, .important = true}),
      Priority({.origin = CascadeOrigin::kAnimation, .important = false}),
      Priority({.origin = CascadeOrigin::kAuthor, .important = false}),
      Priority({.origin = CascadeOrigin::kUser, .important = false}),
      Priority({.origin = CascadeOrigin::kUserAgent, .important = false}),
      Priority({.origin = CascadeOrigin::kNone, .important = false})};

  for (size_t i = 0; i < priorities.size(); ++i) {
    for (size_t j = i; j < priorities.size(); ++j) {
      EXPECT_GE(priorities[i], priorities[j]);
    }
  }
}

TEST(CascadePriorityTest, IsImportant) {
  using Origin = CascadeOrigin;

  EXPECT_FALSE(Priority({.origin = Origin::kUserAgent}).IsImportant());
  EXPECT_FALSE(Priority({.origin = Origin::kUser}).IsImportant());
  EXPECT_FALSE(Priority({.origin = Origin::kAuthor}).IsImportant());
  EXPECT_FALSE(Priority({.origin = Origin::kAnimation}).IsImportant());
  EXPECT_FALSE(Priority({.origin = Origin::kTransition}).IsImportant());
  EXPECT_FALSE(Priority({.origin = Origin::kAuthor,
                         .important = false,
                         .tree_order = 1024,
                         .layer_order = 2048,
                         .position = 4096})
                   .IsImportant());

  EXPECT_TRUE(Priority({.origin = Origin::kUserAgent, .important = true})
                  .IsImportant());
  EXPECT_TRUE(
      Priority({.origin = Origin::kUser, .important = true}).IsImportant());
  EXPECT_TRUE(
      Priority({.origin = Origin::kAuthor, .important = true}).IsImportant());
  EXPECT_TRUE(Priority({.origin = Origin::kAnimation, .important = true})
                  .IsImportant());
  EXPECT_TRUE(Priority({.origin = Origin::kTransition, .important = true})
                  .IsImportant());
  EXPECT_TRUE(Priority({.origin = Origin::kAuthor,
                        .important = true,
                        .tree_order = 1024,
                        .layer_order = 2048,
                        .position = 4096})
                  .IsImportant());
}

static std::vector<CascadeOrigin> all_origins = {
    CascadeOrigin::kUserAgent, CascadeOrigin::kUser, CascadeOrigin::kAuthor,
    CascadeOrigin::kTransition, CascadeOrigin::kAnimation};

TEST(CascadePriorityTest, GetOrigin) {
  for (CascadeOrigin origin : all_origins) {
    EXPECT_EQ(Priority({.origin = origin, .important = false}).GetOrigin(),
              origin);
  }

  for (CascadeOrigin origin : all_origins) {
    if (origin == CascadeOrigin::kAnimation) {
      continue;
    }
    if (origin == CascadeOrigin::kTransition) {
      continue;
    }
    EXPECT_EQ(Priority({.origin = origin, .important = true}).GetOrigin(),
              origin);
  }
}

TEST(CascadePriorityTest, HasOrigin) {
  for (CascadeOrigin origin : all_origins) {
    if (origin != CascadeOrigin::kNone) {
      EXPECT_TRUE(CascadePriority(origin).HasOrigin());
    } else {
      EXPECT_FALSE(CascadePriority(origin).HasOrigin());
    }
  }
  EXPECT_FALSE(CascadePriority().HasOrigin());
}

TEST(CascadePriorityTest, EncodeTreeOrder) {
  EXPECT_EQ(0ull, EncodeTreeOrder(0, false));
  EXPECT_EQ(1ull, EncodeTreeOrder(1, false));
  EXPECT_EQ(2ull, EncodeTreeOrder(2, false));
  EXPECT_EQ(100ull, EncodeTreeOrder(100, false));
  EXPECT_EQ(0xFFFFull, EncodeTreeOrder(0xFFFF, false));

  EXPECT_EQ(0ull ^ 0xFFFF, EncodeTreeOrder(0, true));
  EXPECT_EQ(1ull ^ 0xFFFF, EncodeTreeOrder(1, true));
  EXPECT_EQ(2ull ^ 0xFFFF, EncodeTreeOrder(2, true));
  EXPECT_EQ(100ull ^ 0xFFFF, EncodeTreeOrder(100, true));
  EXPECT_EQ(0xFFFFull ^ 0xFFFF, EncodeTreeOrder(0xFFFF, true));
}

TEST(CascadePriorityTest, TreeOrder) {
  using Priority = CascadePriority;
  CascadeOrigin origin = CascadeOrigin::kAuthor;
  EXPECT_GE(Priority(origin, false, 1), Priority(origin, false, 0));
  EXPECT_GE(Priority(origin, false, 7), Priority(origin, false, 6));
  EXPECT_GE(Priority(origin, false, 42), Priority(origin, false, 42));
  EXPECT_FALSE(Priority(origin, false, 1) >= Priority(origin, false, 8));
}

TEST(CascadePriorityTest, TreeOrderImportant) {
  using Priority = CascadePriority;
  CascadeOrigin origin = CascadeOrigin::kAuthor;
  EXPECT_GE(Priority(origin, true, 0), Priority(origin, true, 1));
  EXPECT_GE(Priority(origin, true, 6), Priority(origin, true, 7));
  EXPECT_GE(Priority(origin, true, 42), Priority(origin, true, 42));
  EXPECT_FALSE(Priority(origin, true, 8) >= Priority(origin, true, 1));
}

TEST(CascadePriorityTest, TreeOrderDifferentOrigin) {
  using Priority = CascadePriority;
  // Tree order does not matter if the origin is different.
  CascadeOrigin author = CascadeOrigin::kAuthor;
  CascadeOrigin transition = CascadeOrigin::kTransition;
  EXPECT_GE(Priority(transition, 1), Priority(author, 42));
  EXPECT_GE(Priority(transition, 1), Priority(author, 1));
}

TEST(CascadePriorityTest, Position) {
  // AuthorPriority(tree_order, position)
  EXPECT_GE(AuthorPriority(0, 0), AuthorPriority(0, 0));
  EXPECT_GE(AuthorPriority(0, 1), AuthorPriority(0, 1));
  EXPECT_GE(AuthorPriority(0, 1), AuthorPriority(0, 0));
  EXPECT_GE(AuthorPriority(0, 2), AuthorPriority(0, 1));
  EXPECT_GE(AuthorPriority(0, 0xFFFFFFFF), AuthorPriority(0, 0xFFFFFFFE));
  EXPECT_FALSE(AuthorPriority(0, 2) >= AuthorPriority(0, 3));
}

TEST(CascadePriorityTest, PositionAndTreeOrder) {
  // AuthorPriority(tree_order, position)
  EXPECT_GE(AuthorPriority(1, 0), AuthorPriority(0, 0));
  EXPECT_GE(AuthorPriority(1, 1), AuthorPriority(0, 1));
  EXPECT_GE(AuthorPriority(1, 1), AuthorPriority(0, 3));
  EXPECT_GE(AuthorPriority(1, 2), AuthorPriority(0, 0xFFFFFFFF));
}

TEST(CascadePriorityTest, PositionAndOrigin) {
  // [Important]AuthorPriority(tree_order, position)
  EXPECT_GE(ImportantAuthorPriority(0, 0), AuthorPriority(0, 0));
  EXPECT_GE(ImportantAuthorPriority(0, 1), AuthorPriority(0, 1));
  EXPECT_GE(ImportantAuthorPriority(0, 1), AuthorPriority(0, 3));
  EXPECT_GE(ImportantAuthorPriority(0, 2), AuthorPriority(0, 0xFFFFFFFF));
}

TEST(CascadePriorityTest, Generation) {
  CascadePriority ua(CascadeOrigin::kUserAgent);
  CascadePriority author(CascadeOrigin::kAuthor);

  EXPECT_EQ(author, author);
  EXPECT_GE(CascadePriority(author, 1), author);
  EXPECT_GE(CascadePriority(author, 2), CascadePriority(author, 1));
  EXPECT_EQ(CascadePriority(author, 2), CascadePriority(author, 2));

  EXPECT_LT(ua, author);
  EXPECT_LT(CascadePriority(ua, 1), author);
  EXPECT_LT(CascadePriority(ua, 2), CascadePriority(author, 1));
  EXPECT_LT(CascadePriority(ua, 2), CascadePriority(author, 2));
  EXPECT_LT(CascadePriority(ua, 2), CascadePriority(author, 3));
}

TEST(CascadePriorityTest, GenerationOverwrite) {
  CascadePriority ua(CascadeOrigin::kUserAgent);

  for (int8_t g = 0; g < 16; ++g) {
    ua = CascadePriority(ua, g);
    EXPECT_EQ(g, ua.GetGeneration());
  }

  for (int8_t g = 15; g >= 0; --g) {
    ua = CascadePriority(ua, g);
    EXPECT_EQ(g, ua.GetGeneration());
  }
}

TEST(CascadePriorityTest, PositionEncoding) {
  // Test 0b0, 0b1, 0b11, 0b111, etc.
  uint32_t pos = 0;
  do {
    // AuthorPriority(tree_order, position)
    ASSERT_EQ(pos, AuthorPriority(0, pos).GetPosition());
    pos = (pos << 1) | 1;
  } while (pos != ~static_cast<uint32_t>(0));

  // Test 0b1, 0b10, 0b100, etc
  pos = 1;
  do {
    // AuthorPriority(tree_order, position)
    ASSERT_EQ(pos, AuthorPriority(0, pos).GetPosition());
    pos <<= 1;
  } while (pos != ~static_cast<uint32_t>(1) << 31);
}

TEST(CascadePriorityTest, EncodeLayerOrder) {
  EXPECT_EQ(0ull, EncodeLayerOrder(0, false));
  EXPECT_EQ(1ull, EncodeLayerOrder(1, false));
  EXPECT_EQ(2ull, EncodeLayerOrder(2, false));
  EXPECT_EQ(100ull, EncodeLayerOrder(100, false));
  EXPECT_EQ(0xFFFFull, EncodeLayerOrder(0xFFFF, false));

  EXPECT_EQ(0ull ^ 0xFFFF, EncodeLayerOrder(0, true));
  EXPECT_EQ(1ull ^ 0xFFFF, EncodeLayerOrder(1, true));
  EXPECT_EQ(2ull ^ 0xFFFF, EncodeLayerOrder(2, true));
  EXPECT_EQ(100ull ^ 0xFFFF, EncodeLayerOrder(100, true));
  EXPECT_EQ(0xFFFFull ^ 0xFFFF, EncodeLayerOrder(0xFFFF, true));
}

TEST(CascadePriorityTest, LayerOrder) {
  EXPECT_GE(Priority({.layer_order = 1}), Priority({.layer_order = 0}));
  EXPECT_GE(Priority({.layer_order = 7}), Priority({.layer_order = 6}));
  EXPECT_GE(Priority({.layer_order = 42}), Priority({.layer_order = 42}));
  EXPECT_FALSE(Priority({.layer_order = 1}) >= Priority({.layer_order = 8}));
}

TEST(CascadePriorityTest, LayerOrderImportant) {
  EXPECT_GE(Priority({.important = true, .layer_order = 0}),
            Priority({.important = true, .layer_order = 1}));
  EXPECT_GE(Priority({.important = true, .layer_order = 6}),
            Priority({.important = true, .layer_order = 7}));
  EXPECT_GE(Priority({.important = true, .layer_order = 4}),
            Priority({.important = true, .layer_order = 4}));
  EXPECT_FALSE(Priority({.important = true, .layer_order = 8}) >=
               Priority({.important = true, .layer_order = 1}));
}

TEST(CascadePriorityTest, LayerOrderDifferentOrigin) {
  // Layer order does not matter if the origin is different.
  CascadeOrigin transition = CascadeOrigin::kTransition;
  EXPECT_GE(Priority({.origin = transition, .layer_order = 1}),
            Priority({.layer_order = 42}));
  EXPECT_GE(Priority({.origin = transition, .layer_order = 1}),
            Priority({.layer_order = 1}));
}

TEST(CascadePriorityTest, InlineStyle) {
  CascadeOrigin user = CascadeOrigin::kUser;

  // Non-important inline style priorities
  EXPECT_GE(Priority({.is_inline_style = true}), Priority({.position = 1}));
  EXPECT_GE(Priority({.is_inline_style = true}), Priority({.layer_order = 1}));
  EXPECT_GE(Priority({.tree_order = 1, .is_inline_style = true}),
            Priority({.is_inline_style = false}));
  EXPECT_LT(Priority({.tree_order = 1, .is_inline_style = true}),
            Priority({.tree_order = 2}));
  EXPECT_GE(Priority({.is_inline_style = true}), Priority({.origin = user}));
  EXPECT_LT(Priority({.is_inline_style = true}), Priority({.important = true}));

  // Important inline style priorities
  EXPECT_GE(Priority({.important = true, .is_inline_style = true}),
            Priority({.important = true, .position = 1}));
  EXPECT_GE(Priority({.important = true, .is_inline_style = true}),
            Priority({.important = true, .layer_order = 1}));
  EXPECT_LT(
      Priority({.important = true, .tree_order = 1, .is_inline_style = true}),
      Priority({.important = true}));
  EXPECT_GE(
      Priority({.important = true, .tree_order = 1, .is_inline_style = true}),
      Priority({.important = true, .tree_order = 2}));
  EXPECT_LT(Priority({.important = true, .is_inline_style = true}),
            Priority({.origin = user, .important = true}));
  EXPECT_GE(Priority({.important = true, .is_inline_style = true}),
            Priority({.is_inline_style = false}));
}

TEST(CascadePriorityTest, TryStyle) {
  EXPECT_GE(Priority({.is_try_style = true}), Priority({}));
  EXPECT_GE(Priority({.is_try_style = true}),
            Priority({.is_inline_style = true}));
  EXPECT_GE(Priority({.is_try_style = true}),
            Priority({.layer_order = static_cast<uint16_t>(
                          EncodeLayerOrder(1u, /* important */ false))}));
  EXPECT_GE(Priority({.is_try_style = true}), Priority({.position = 1000}));

  EXPECT_LT(Priority({.is_try_style = true}), Priority({.important = true}));
  EXPECT_LT(Priority({.is_try_style = true}),
            Priority({.origin = CascadeOrigin::kAnimation}));
  EXPECT_LT(Priority({.is_try_style = true}),
            Priority({.origin = CascadeOrigin::kTransition}));

  // Try styles generate a separate layer.
  EXPECT_NE(Priority({.is_try_style = true}).ForLayerComparison(),
            Priority({}).ForLayerComparison());
}

TEST(CascadePriorityTest, TryTacticsStyle) {
  // Should be stronger than try-style.
  EXPECT_GE(Priority({.is_try_tactics_style = true}),
            Priority({.is_try_style = true}));

  // Should be stronger than inline styles.
  EXPECT_GE(Priority({.is_try_tactics_style = true}),
            Priority({.is_inline_style = true}));

  // Should be stronger than author cascade layers.
  EXPECT_GE(Priority({.is_try_tactics_style = true}),
            Priority({.layer_order = 1000}));

  // Should be weaker than important in the same origin
  EXPECT_LT(Priority({.is_try_tactics_style = true}),
            Priority({.important = true}));

  // Should be weaker than a stronger origin.
  EXPECT_LT(Priority({.is_try_tactics_style = true}),
            Priority({.origin = CascadeOrigin::kTransition}));

  // Try-tactics styles generate a separate layer.
  EXPECT_NE(Priority({.is_try_tactics_style = true}).ForLayerComparison(),
            Priority({}).ForLayerComparison());
  // Also a separate layer vs. the try styles.
  EXPECT_NE(Priority({.is_try_tactics_style = true}).ForLayerComparison(),
            Priority({.is_try_style = true}).ForLayerComparison());
}

TEST(CascadePriorityTest, ForLayerComparison) {
  CascadeOrigin user = CascadeOrigin::kUser;

  EXPECT_EQ(Priority({.layer_order = 1, .position = 2}).ForLayerComparison(),
            Priority({.layer_order = 1, .position = 8}).ForLayerComparison());
  EXPECT_EQ(
      Priority(
          {.important = true, .tree_order = 1, .layer_order = 1, .position = 4})
          .ForLayerComparison(),
      Priority(
          {.important = true, .tree_order = 1, .layer_order = 1, .position = 8})
          .ForLayerComparison());
  EXPECT_EQ(Priority({.important = true,
                      .tree_order = 1,
                      .layer_order = 1,
                      .position = 16})
                .ForLayerComparison(),
            Priority({.tree_order = 1, .layer_order = 1, .position = 32})
                .ForLayerComparison());
  EXPECT_EQ(Priority({.important = true,
                      .tree_order = 1,
                      .is_inline_style = true,
                      .position = 16})
                .ForLayerComparison(),
            Priority({.tree_order = 1, .is_inline_style = true, .position = 32})
                .ForLayerComparison());

  EXPECT_LT(Priority({.origin = user, .position = 1}).ForLayerComparison(),
            Priority({.origin = user, .layer_order = 1}).ForLayerComparison());
  EXPECT_LT(
      Priority({.origin = user, .position = 1}).ForLayerComparison(),
      Priority({.origin = user, .is_inline_style = true}).ForLayerComparison());
  EXPECT_LT(Priority({.origin = user, .position = 1}).ForLayerComparison(),
            Priority({.origin = user, .tree_order = 1}).ForLayerComparison());
  EXPECT_LT(Priority({.origin = user, .position = 1}).ForLayerComparison(),
            Priority({}).ForLayerComparison());
  EXPECT_LT(Priority({.origin = user, .important = true, .position = 1})
                .ForLayerComparison(),
            Priority({.origin = user, .layer_order = 1}).ForLayerComparison());
  EXPECT_LT(
      Priority({.origin = user, .important = true, .position = 1})
          .ForLayerComparison(),
      Priority({.origin = user, .is_inline_style = true}).ForLayerComparison());
  EXPECT_LT(Priority({.origin = user, .important = true, .position = 1})
                .ForLayerComparison(),
            Priority({.origin = user, .tree_order = 1}).ForLayerComparison());
  EXPECT_LT(Priority({.origin = user, .important = true, .position = 1})
                .ForLayerComparison(),
            Priority({}).ForLayerComparison());
  EXPECT_LT(Priority({.origin = user, .position = 1}).ForLayerComparison(),
            Priority({.origin = user, .important = true, .layer_order = 1})
                .ForLayerComparison());
  EXPECT_LT(
      Priority({.origin = user, .position = 1}).ForLayerComparison(),
      Priority({.origin = user, .important = true, .is_inline_style = true})
          .ForLayerComparison());
  EXPECT_LT(Priority({.origin = user, .position = 1}).ForLayerComparison(),
            Priority({.origin = user, .important = true, .tree_order = 1})
                .ForLayerComparison());
  EXPECT_LT(Priority({.origin = user, .position = 1}).ForLayerComparison(),
            Priority({.important = true}).ForLayerComparison());
  EXPECT_LT(Priority({.origin = user, .important = true, .position = 1})
                .ForLayerComparison(),
            Priority({.origin = user, .important = true, .layer_order = 1})
                .ForLayerComparison());
  EXPECT_LT(
      Priority({.origin = user, .important = true, .position = 1})
          .ForLayerComparison(),
      Priority({.origin = user, .important = true, .is_inline_style = true})
          .ForLayerComparison());
  EXPECT_LT(Priority({.origin = user, .important = true, .position = 1})
                .ForLayerComparison(),
            Priority({.origin = user, .important = true, .tree_order = 1})
                .ForLayerComparison());
  EXPECT_LT(Priority({.origin = user, .important = true, .position = 1})
                .ForLayerComparison(),
            Priority({.important = true}).ForLayerComparison());
}

}  // namespace blink

"""

```
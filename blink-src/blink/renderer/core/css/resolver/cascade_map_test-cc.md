Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The core task is to analyze a C++ test file (`cascade_map_test.cc`) within the Chromium Blink engine. The specific questions are about its functionality, its relation to web technologies (HTML, CSS, JavaScript), logical reasoning (input/output), potential user/programming errors, and how a user might trigger this code (debugging).

2. **Identify the Target Class:** The file name `cascade_map_test.cc` strongly suggests it's testing a class named `CascadeMap`. This is the primary focus of our analysis. A quick scan of the code confirms this.

3. **Analyze the Test Structure (gtest):**  The presence of `#include <gtest/gtest.h>` immediately tells us this uses Google Test. This means we should look for `TEST()` macros, which define individual test cases. We'll also see `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `ASSERT_TRUE`, etc., which are gtest assertion macros. Understanding these helps decipher what each test is checking.

4. **Deconstruct Individual Tests:**  Go through each `TEST()` function and understand its purpose:

    * **`Empty`:** Checks that a newly created `CascadeMap` is indeed empty, with no properties present.
    * **`AddCustom`:** Focuses on adding custom CSS properties (those starting with `--`). It verifies adding, overwriting, and the persistence of different priorities.
    * **`AddNative`:** Similar to `AddCustom`, but for standard CSS properties (like `color`, `display`).
    * **`FindAndMutateCustom` and `FindAndMutateNative`:** These tests explore the `Find()` method and demonstrate the ability to retrieve a `CascadePriority` object by reference and modify it.
    * **`AtCustom` and `AtNative`:**  Examine the `At()` method, which returns a `CascadePriority` by value (not a pointer), showing its behavior when a property is present or absent.
    * **`HighPriorityBits` and `AllHighPriorityBits`:** These are more complex. They deal with a bitmask (`HighPriorityBits()`) used to efficiently track the presence of high-priority CSS properties. The tests check that the bitmask is updated correctly when adding high-priority properties. The `AllHighPriorityBits` test iterates through *all* high-priority properties.
    * **`LastHighPrio`:** A specific test related to the last defined high-priority CSS property.
    * **`Reset`:** Verifies the `Reset()` method, which clears all entries from the `CascadeMap`.
    * **`ResetHighPrio`:** Checks that `Reset()` also clears the `HighPriorityBits` mask.
    * **`FindOrigin`:**  This is a crucial test that delves into the *cascade* aspect. It adds properties with different origins (User Agent, User, Author) and verifies that `Find()` (with and without specifying an origin) returns the `CascadePriority` according to CSS cascading rules.

5. **Identify Key Concepts:** As we analyze the tests, key concepts emerge:

    * **`CascadeMap`:**  The central data structure being tested. It stores CSS property names and their associated `CascadePriority`.
    * **`CascadePriority`:**  Represents the priority of a CSS rule, based on origin (User Agent, User, Author), importance (`!important`), and other factors.
    * **CSS Property Names:**  Both standard (e.g., `color`) and custom (`--x`).
    * **CSS Cascading:** The fundamental mechanism by which browsers determine which CSS rule applies to an element when multiple rules target the same property.
    * **Origins:** The source of a CSS rule (browser defaults, user stylesheets, website stylesheets).

6. **Relate to Web Technologies:** Now we connect the dots to HTML, CSS, and JavaScript:

    * **CSS:**  The most direct connection. `CascadeMap` is clearly involved in CSS rule resolution. Examples are straightforward (setting `color`, `display`, custom properties).
    * **HTML:**  HTML provides the structure to which CSS rules are applied. The examples involving styling elements demonstrate this.
    * **JavaScript:**  JavaScript can dynamically modify styles, including inline styles and custom properties. This is a key point for demonstrating how user actions can lead to the execution of this code.

7. **Infer Functionality:** Based on the tests, we can deduce the core functionality of `CascadeMap`:

    * Store CSS property priorities.
    * Handle both standard and custom properties.
    * Allow adding, finding, and potentially modifying priorities.
    * Support efficient tracking of high-priority properties.
    * Allow resetting the map.
    * Support querying priorities up to a specific origin in the cascade.

8. **Develop Examples (Input/Output, Errors):**  Create concrete examples to illustrate the concepts:

    * **Input/Output:**  Choose a simple test case (like adding and finding a property) and show the state of the `CascadeMap` before and after the operation.
    * **User/Programming Errors:** Think about common mistakes related to CSS and how `CascadeMap` might be involved (e.g., expecting a style to apply when a higher-priority rule exists).

9. **Trace User Actions (Debugging):**  Consider how a user's actions in a web browser can eventually lead to this code being executed. Start with high-level actions and work down:

    * User opens a web page.
    * The browser parses HTML and CSS.
    * The style engine needs to resolve the final styles for each element.
    * This involves the CSS cascade, and `CascadeMap` likely plays a role in storing and comparing rule priorities.
    * JavaScript interactions that modify styles are also relevant.

10. **Structure the Answer:**  Organize the findings logically, following the prompts in the original request:

    * Functionality.
    * Relationship to JavaScript, HTML, CSS (with examples).
    * Logical reasoning (input/output).
    * User/programming errors.
    * User actions leading to the code.

11. **Refine and Elaborate:**  Review the answer for clarity, accuracy, and completeness. Add more detail where needed, ensuring the explanations are easy to understand, even for someone not deeply familiar with the Blink rendering engine. For instance, explaining the concept of CSS cascading is crucial for understanding the `FindOrigin` test.

By following these steps, we can systematically analyze the C++ test file and generate a comprehensive answer that addresses all the questions effectively. The key is to combine code analysis with knowledge of web technologies and browser internals.
这个C++文件 `cascade_map_test.cc` 是 Chromium Blink 渲染引擎中用于测试 `CascadeMap` 类功能的单元测试文件。 `CascadeMap` 类位于 `blink/renderer/core/css/resolver/cascade_map.h`，它主要负责**存储和管理 CSS 属性的层叠优先级信息**。

**功能总结:**

`cascade_map_test.cc` 中的测试用例主要验证了 `CascadeMap` 类的以下功能：

1. **添加 CSS 属性及其优先级:**
   - 可以添加标准的 CSS 属性 (例如 `color`, `display`) 和自定义属性 (例如 `--x`, `--y`)，并关联相应的 `CascadePriority` 对象。
   - `CascadePriority` 对象包含了 CSS 属性的来源 (User-Agent, User, Author)、重要性 (`!important`) 等信息，用于确定层叠顺序。

2. **查找 CSS 属性的最高优先级:**
   - `Find()` 方法能够根据 CSS 属性名查找当前存储的最高优先级信息。
   - 可以选择性地指定查找的优先级来源范围，例如只查找用户代理样式或用户样式。

3. **获取 CSS 属性的当前优先级:**
   - `At()` 方法返回指定 CSS 属性的当前优先级信息，如果属性不存在则返回默认的 `CascadePriority`。

4. **修改已存储的优先级信息:**
   - 可以通过 `Find()` 方法获取到指向 `CascadePriority` 对象的指针，并修改其值。

5. **管理高优先级属性:**
   - 维护一个位掩码 (`HighPriorityBits()`) 来记录当前 `CascadeMap` 中存在的高优先级 CSS 属性。这可以用于优化性能，快速判断是否存在需要特殊处理的高优先级属性。

6. **重置 `CascadeMap`:**
   - `Reset()` 方法可以清空 `CascadeMap` 中存储的所有 CSS 属性及其优先级信息。

**与 Javascript, HTML, CSS 的关系及举例说明:**

`CascadeMap` 类是 CSS 样式计算的核心组成部分，直接参与了 CSS 规则层叠的解析和处理。

* **CSS:**
    - 当浏览器解析 CSS 样式表（包括内联样式、外部样式表、用户样式表等）时，会将 CSS 属性及其对应的优先级信息存储到 `CascadeMap` 中。
    - 例如，以下 CSS 规则会被解析，其优先级信息会添加到 `CascadeMap` 中：
      ```css
      /* 作者样式表 */
      .my-element {
        color: blue; /* 作者普通优先级 */
      }

      /* 用户样式表 */
      .my-element {
        color: green !important; /* 用户重要优先级 */
      }

      /* 用户代理样式表（浏览器默认样式）*/
      body {
        display: block; /* 用户代理普通优先级 */
      }

      /* 内联样式 */
      <div style="font-size: 16px;"></div>
      ```
    - 在 `cascade_map_test.cc` 中，`AuthorPriority`, `UserPriority`, `UaPriority` 等辅助函数模拟了不同来源的 CSS 规则优先级。

* **HTML:**
    - HTML 元素是 CSS 规则应用的目标。浏览器根据 HTML 结构和 CSS 选择器，将匹配的 CSS 规则应用到相应的 HTML 元素上。
    - `CascadeMap` 负责管理这些规则的优先级，最终决定哪个规则的属性值会生效。

* **Javascript:**
    - Javascript 可以动态地修改元素的样式，包括内联样式和样式表的规则。
    - 当 Javascript 修改样式时，可能会影响 `CascadeMap` 中存储的优先级信息。例如，使用 `element.style.color = 'red'` 会设置内联样式，其优先级高于大多数作者样式。
    - 示例：
      ```javascript
      const element = document.querySelector('.my-element');
      element.style.backgroundColor = 'yellow'; // 设置内联样式，会影响 CascadeMap
      ```
    - Javascript 还可以通过操作 CSSOM (CSS Object Model) 来修改样式表规则，这些修改最终也会反映到 `CascadeMap` 中。

**逻辑推理 (假设输入与输出):**

假设有以下 CSS 规则作用于同一个元素，并按照其优先级顺序添加到 `CascadeMap`:

**输入:**

1. **用户代理样式:** `color: black;` (UaPriority(1))
2. **用户样式:** `color: gray;` (UserPriority(10))
3. **作者样式:** `color: blue;` (AuthorPriority(20))

**测试代码片段 (模拟 `FindOrigin` 测试):**

```c++
TEST(CascadeMapTest, FindOriginExample) {
  CascadeMap map;
  CSSPropertyName color(CSSPropertyID::kColor);

  map.Add(color.Id(), UaPriority(1));
  map.Add(color.Id(), UserPriority(10));
  map.Add(color.Id(), AuthorPriority(20));

  // 查找最终生效的优先级
  ASSERT_TRUE(map.Find(color));
  EXPECT_EQ(AuthorPriority(20), *map.Find(color));

  // 查找直到用户样式的最高优先级
  ASSERT_TRUE(map.Find(color, CascadeOrigin::kUser));
  EXPECT_EQ(UserPriority(10), *map.Find(color, CascadeOrigin::kUser));

  // 查找直到用户代理样式的最高优先级
  ASSERT_TRUE(map.Find(color, CascadeOrigin::kUserAgent));
  EXPECT_EQ(UaPriority(1), *map.Find(color, CascadeOrigin::kUserAgent));
}
```

**输出:**

* `map.Find(color)` 会返回指向 `AuthorPriority(20)` 的指针，因为作者样式优先级最高。
* `map.Find(color, CascadeOrigin::kUser)` 会返回指向 `UserPriority(10)` 的指针，因为我们指定了只考虑用户样式及其之前的优先级。
* `map.Find(color, CascadeOrigin::kUserAgent)` 会返回指向 `UaPriority(1)` 的指针，因为我们指定了只考虑用户代理样式的优先级。

**用户或编程常见的使用错误:**

虽然 `CascadeMap` 是浏览器引擎内部的实现，普通用户不会直接与之交互，但编程错误可能会导致 `CascadeMap` 的状态不正确，从而导致样式计算错误。

1. **优先级比较错误:** 在实现 CSS 属性值比较逻辑时，如果对 `CascadePriority` 的比较规则理解不正确，可能会导致选择了错误的属性值。例如，错误地认为用户代理样式比作者样式优先级高。

2. **添加优先级顺序错误:** 如果在处理样式表时，没有按照正确的层叠顺序添加优先级信息到 `CascadeMap` 中，可能会导致最终的样式计算结果不符合预期。

3. **忽略重要性 (`!important`):**  没有正确处理 `!important` 声明会导致优先级计算错误，因为 `!important` 声明会提升规则的优先级。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为一个普通的 Web 开发者或用户，我们不会直接调用 `CascadeMap` 的代码。但是，我们的操作会触发浏览器的渲染引擎执行相关代码，其中就包括 `CascadeMap` 的使用。以下是一个可能的流程：

1. **用户在浏览器中打开一个网页 (输入 URL 或点击链接)。**
2. **浏览器下载 HTML、CSS 和 Javascript 等资源。**
3. **浏览器解析 HTML，构建 DOM 树。**
4. **浏览器解析 CSS，构建 CSSOM 树。**
5. **浏览器将 CSSOM 树与 DOM 树结合，构建 Render 树 (或 Layout 树)。** 在这个阶段，浏览器需要确定每个 DOM 节点的最终样式。
6. **对于 Render 树中的每个元素，浏览器会执行样式计算 (Style Calculation)。**
7. **在样式计算过程中，浏览器会查找与该元素匹配的所有 CSS 规则。** 这些规则可能来自不同的来源（用户代理、用户、作者、内联样式）。
8. **浏览器根据 CSS 层叠规则，计算每个 CSS 属性的最终值。** 这其中就涉及到 `CascadeMap` 的使用。
   - 浏览器会创建一个 `CascadeMap` 对象，用于存储与当前元素相关的 CSS 属性及其优先级信息。
   - 来自不同来源的 CSS 规则的优先级信息会被添加到 `CascadeMap` 中。
   - 浏览器使用 `CascadeMap` 的 `Find()` 方法来查找每个属性的最高优先级值。
9. **最终计算出的样式信息会被用于渲染页面的布局和绘制。**

**作为调试线索:**

如果开发者在调试 CSS 样式问题时，发现某个元素的样式没有按照预期生效，可能的原因是 CSS 层叠规则导致了优先级冲突。为了排查问题，开发者可以使用浏览器的开发者工具：

1. **打开开发者工具 (通常按 F12)。**
2. **选择 "Elements" 或 "Inspect" 面板。**
3. **选中需要调试的 HTML 元素。**
4. **查看 "Styles" 或 "Computed" 面板。**
   - "Styles" 面板会列出应用到该元素的所有 CSS 规则，并显示它们的来源和优先级。浏览器内部可能使用了类似于 `CascadeMap` 的机制来确定这些规则的优先级。
   - "Computed" 面板会显示该元素最终生效的 CSS 属性值。

通过查看这些信息，开发者可以分析哪些 CSS 规则覆盖了其他规则，从而定位样式问题的根源。虽然开发者不会直接调试 `cascade_map_test.cc` 的代码，但理解 `CascadeMap` 的功能有助于理解浏览器处理 CSS 层叠的机制，从而更好地进行 CSS 调试。

Prompt: 
```
这是目录为blink/renderer/core/css/resolver/cascade_map_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/resolver/cascade_map.h"
#include <gtest/gtest.h>
#include "third_party/blink/renderer/core/css/css_property_name.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/css/resolver/cascade_priority.h"

namespace blink {

namespace {
CascadePriority UaPriority(wtf_size_t position) {
  return CascadePriority(CascadeOrigin::kUserAgent,
                         /* important */ false,
                         /* tree_order */ 0,
                         /* is_inline_style */ false,
                         /* is_try_style */ false,
                         /* is_try_tactics_style */ false,
                         /* layer_order */ 0, position);
}
CascadePriority UserPriority(wtf_size_t position) {
  return CascadePriority(CascadeOrigin::kUser,
                         /* important */ false,
                         /* tree_order */ 0,
                         /* is_inline_style */ false,
                         /* is_try_style */ false,
                         /* is_try_tactics_style */ false,
                         /* layer_order */ 0, position);
}
CascadePriority AuthorPriority(wtf_size_t position) {
  return CascadePriority(CascadeOrigin::kAuthor,
                         /* important */ false,
                         /* tree_order */ 0,
                         /* is_inline_style */ false,
                         /* is_try_style */ false,
                         /* is_try_tactics_style */ false,
                         /* layer_order */ 0, position);
}

bool AddTo(CascadeMap& map,
           const CSSPropertyName& name,
           CascadePriority priority) {
  CascadePriority before = map.At(name);
  if (name.IsCustomProperty()) {
    map.Add(name.ToAtomicString(), priority);
  } else {
    map.Add(name.Id(), priority);
  }
  CascadePriority after = map.At(name);
  return before != after;
}

}  // namespace

TEST(CascadeMapTest, Empty) {
  CascadeMap map;
  EXPECT_FALSE(map.Find(CSSPropertyName(AtomicString("--x"))));
  EXPECT_FALSE(map.Find(CSSPropertyName(AtomicString("--y"))));
  EXPECT_FALSE(map.Find(CSSPropertyName(CSSPropertyID::kColor)));
  EXPECT_FALSE(map.Find(CSSPropertyName(CSSPropertyID::kDisplay)));
}

TEST(CascadeMapTest, AddCustom) {
  CascadeMap map;
  CascadePriority user(CascadeOrigin::kUser);
  CascadePriority author(CascadeOrigin::kAuthor);
  CSSPropertyName x(AtomicString("--x"));
  CSSPropertyName y(AtomicString("--y"));

  EXPECT_TRUE(AddTo(map, x, user));
  EXPECT_TRUE(AddTo(map, x, author));
  EXPECT_FALSE(AddTo(map, x, author));
  ASSERT_TRUE(map.Find(x));
  EXPECT_EQ(author, *map.Find(x));

  EXPECT_FALSE(map.Find(y));
  EXPECT_TRUE(AddTo(map, y, user));

  // --x should be unchanged.
  ASSERT_TRUE(map.Find(x));
  EXPECT_EQ(author, *map.Find(x));

  // --y should exist too.
  ASSERT_TRUE(map.Find(y));
  EXPECT_EQ(user, *map.Find(y));
}

TEST(CascadeMapTest, AddNative) {
  CascadeMap map;
  CascadePriority user(CascadeOrigin::kUser);
  CascadePriority author(CascadeOrigin::kAuthor);
  CSSPropertyName color(CSSPropertyID::kColor);
  CSSPropertyName display(CSSPropertyID::kDisplay);

  EXPECT_TRUE(AddTo(map, color, user));
  EXPECT_TRUE(AddTo(map, color, author));
  EXPECT_FALSE(AddTo(map, color, author));
  ASSERT_TRUE(map.Find(color));
  EXPECT_EQ(author, *map.Find(color));

  EXPECT_FALSE(map.Find(display));
  EXPECT_TRUE(AddTo(map, display, user));

  // color should be unchanged.
  ASSERT_TRUE(map.Find(color));
  EXPECT_EQ(author, *map.Find(color));

  // display should exist too.
  ASSERT_TRUE(map.Find(display));
  EXPECT_EQ(user, *map.Find(display));
}

TEST(CascadeMapTest, FindAndMutateCustom) {
  CascadeMap map;
  CascadePriority user(CascadeOrigin::kUser);
  CascadePriority author(CascadeOrigin::kAuthor);
  CSSPropertyName x(AtomicString("--x"));

  EXPECT_TRUE(AddTo(map, x, user));

  CascadePriority* p = map.Find(x);
  ASSERT_TRUE(p);
  EXPECT_EQ(user, *p);

  *p = author;

  EXPECT_FALSE(AddTo(map, x, author));
  ASSERT_TRUE(map.Find(x));
  EXPECT_EQ(author, *map.Find(x));
}

TEST(CascadeMapTest, FindAndMutateNative) {
  CascadeMap map;
  CascadePriority user(CascadeOrigin::kUser);
  CascadePriority author(CascadeOrigin::kAuthor);
  CSSPropertyName color(CSSPropertyID::kColor);

  EXPECT_TRUE(AddTo(map, color, user));

  CascadePriority* p = map.Find(color);
  ASSERT_TRUE(p);
  EXPECT_EQ(user, *p);

  *p = author;

  EXPECT_FALSE(AddTo(map, color, author));
  ASSERT_TRUE(map.Find(color));
  EXPECT_EQ(author, *map.Find(color));
}

TEST(CascadeMapTest, AtCustom) {
  CascadeMap map;
  CascadePriority user(CascadeOrigin::kUser);
  CascadePriority author(CascadeOrigin::kAuthor);
  CSSPropertyName x(AtomicString("--x"));

  EXPECT_EQ(CascadePriority(), map.At(x));

  EXPECT_TRUE(AddTo(map, x, user));
  EXPECT_EQ(user, map.At(x));

  EXPECT_TRUE(AddTo(map, x, author));
  EXPECT_EQ(author, map.At(x));
}

TEST(CascadeMapTest, AtNative) {
  CascadeMap map;
  CascadePriority user(CascadeOrigin::kUser);
  CascadePriority author(CascadeOrigin::kAuthor);
  CSSPropertyName color(CSSPropertyID::kColor);

  EXPECT_EQ(CascadePriority(), map.At(color));

  EXPECT_TRUE(AddTo(map, color, user));
  EXPECT_EQ(user, map.At(color));

  EXPECT_TRUE(AddTo(map, color, author));
  EXPECT_EQ(author, map.At(color));
}

TEST(CascadeMapTest, HighPriorityBits) {
  CascadeMap map;

  EXPECT_FALSE(map.HighPriorityBits());

  map.Add(CSSPropertyID::kFontSize, CascadePriority(CascadeOrigin::kAuthor));
  EXPECT_EQ(map.HighPriorityBits(),
            1ull << static_cast<uint64_t>(CSSPropertyID::kFontSize));

  map.Add(CSSPropertyID::kColor, CascadePriority(CascadeOrigin::kAuthor));
  map.Add(CSSPropertyID::kFontSize, CascadePriority(CascadeOrigin::kAuthor));
  EXPECT_EQ(map.HighPriorityBits(),
            (1ull << static_cast<uint64_t>(CSSPropertyID::kFontSize)) |
                (1ull << static_cast<uint64_t>(CSSPropertyID::kColor)));
}

TEST(CascadeMapTest, AllHighPriorityBits) {
  CascadeMap map;

  EXPECT_FALSE(map.HighPriorityBits());

  uint64_t expected = 0;
  for (CSSPropertyID id : CSSPropertyIDList()) {
    if (IsHighPriority(id)) {
      if (CSSProperty::Get(id).IsSurrogate()) {
        continue;
      }
      map.Add(id, CascadePriority(CascadeOrigin::kAuthor));
      expected |= (1ull << static_cast<uint64_t>(id));
    }
  }

  EXPECT_EQ(expected, map.HighPriorityBits());
}

TEST(CascadeMapTest, LastHighPrio) {
  CascadeMap map;

  EXPECT_FALSE(map.HighPriorityBits());

  CSSPropertyID last = kLastHighPriorityCSSProperty;

  map.Add(last, CascadePriority(CascadeOrigin::kAuthor));
  EXPECT_EQ(map.HighPriorityBits(), 1ull << static_cast<uint64_t>(last));
}

TEST(CascadeMapTest, Reset) {
  CascadeMap map;

  CascadePriority author(CascadeOrigin::kAuthor);

  CSSPropertyName color(CSSPropertyID::kColor);
  CSSPropertyName x(AtomicString("--x"));

  EXPECT_FALSE(map.Find(color));
  EXPECT_FALSE(map.Find(x));

  map.Add(color.Id(), author);
  map.Add(x.ToAtomicString(), author);

  EXPECT_EQ(author, map.At(color));
  EXPECT_EQ(author, map.At(x));

  map.Reset();

  EXPECT_FALSE(map.Find(color));
  EXPECT_FALSE(map.Find(x));
}

TEST(CascadeMapTest, ResetHighPrio) {
  CascadeMap map;
  EXPECT_FALSE(map.HighPriorityBits());
  map.Add(CSSPropertyID::kFontSize, CascadePriority(CascadeOrigin::kAuthor));
  EXPECT_TRUE(map.HighPriorityBits());
  map.Reset();
  EXPECT_FALSE(map.HighPriorityBits());
}

TEST(CascadeMapTest, FindOrigin) {
  CascadeMap map;

  CSSPropertyName color(CSSPropertyID::kColor);
  CSSPropertyName display(CSSPropertyID::kDisplay);
  CSSPropertyName top(CSSPropertyID::kTop);
  CSSPropertyName left(CSSPropertyID::kLeft);
  CSSPropertyName right(CSSPropertyID::kRight);
  CSSPropertyName bottom(CSSPropertyID::kBottom);

  map.Add(color.Id(), UaPriority(1));
  map.Add(display.Id(), UaPriority(2));
  map.Add(top.Id(), UaPriority(3));
  map.Add(left.Id(), UaPriority(4));
  map.Add(right.Id(), UaPriority(5));

  map.Add(display.Id(), UserPriority(10));
  map.Add(right.Id(), UserPriority(11));

  map.Add(color.Id(), AuthorPriority(20));
  map.Add(display.Id(), AuthorPriority(21));
  map.Add(top.Id(), AuthorPriority(22));
  map.Add(bottom.Id(), AuthorPriority(23));

  // Final result of the cascade:
  EXPECT_EQ(AuthorPriority(20), *map.Find(color));
  EXPECT_EQ(AuthorPriority(21), *map.Find(display));
  EXPECT_EQ(AuthorPriority(22), *map.Find(top));
  EXPECT_EQ(UaPriority(4), *map.Find(left));
  EXPECT_EQ(UserPriority(11), *map.Find(right));
  EXPECT_EQ(AuthorPriority(23), *map.Find(bottom));

  // Final result up to and including kUser:
  EXPECT_EQ(UaPriority(1), *map.Find(color, CascadeOrigin::kUser));
  EXPECT_EQ(UserPriority(10), *map.Find(display, CascadeOrigin::kUser));
  EXPECT_EQ(UaPriority(3), *map.Find(top, CascadeOrigin::kUser));
  EXPECT_EQ(UaPriority(4), *map.Find(left, CascadeOrigin::kUser));
  EXPECT_EQ(UserPriority(11), *map.Find(right, CascadeOrigin::kUser));
  EXPECT_FALSE(map.Find(bottom, CascadeOrigin::kUser));

  // Final result up to and including kUserAgent:
  EXPECT_EQ(UaPriority(1), *map.Find(color, CascadeOrigin::kUserAgent));
  EXPECT_EQ(UaPriority(2), *map.Find(display, CascadeOrigin::kUserAgent));
  EXPECT_EQ(UaPriority(3), *map.Find(top, CascadeOrigin::kUserAgent));
  EXPECT_EQ(UaPriority(4), *map.Find(left, CascadeOrigin::kUserAgent));
  EXPECT_EQ(UaPriority(5), *map.Find(right, CascadeOrigin::kUserAgent));
  EXPECT_FALSE(map.Find(bottom, CascadeOrigin::kUserAgent));
}

}  // namespace blink

"""

```
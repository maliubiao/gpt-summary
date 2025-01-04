Response:
Let's break down the thought process for analyzing this C++ test file for Blink's rendering engine.

**1. Understanding the Goal:**

The primary goal is to understand the *purpose* of this specific test file (`anchor_evaluator_impl_test.cc`). This means figuring out what part of the Blink rendering engine it's testing and how it does that.

**2. Initial Scan for Keywords and Structure:**

A quick scan reveals some key terms and structural elements:

* `#include ...`:  Indicates dependencies. Crucially, it includes `anchor_evaluator_impl.h`, suggesting this file tests the `AnchorEvaluatorImpl` class. It also includes testing frameworks like `gmock` and Blink's own testing helpers.
* `namespace blink { namespace { ... } }`:  Shows this code belongs to the Blink rendering engine and uses an anonymous namespace for internal organization.
* `class AnchorEvaluatorImplTest : public RenderingTest`:  The core of the file. This is a test fixture, inheriting from `RenderingTest` which likely sets up a test environment for rendering.
* `TEST_F(AnchorEvaluatorImplTest, ...)`:  Standard Google Test framework syntax for defining individual test cases within the fixture. The second argument to `TEST_F` is the name of the test case.
* HTML strings (using `R"HTML(...)HTML"`):  These are used to set up the DOM structure for the tests.
* CSS styles within the HTML strings:  These define the visual properties of the elements.
* Calls to methods like `SetBodyInnerHTML`, `GetElementById`, `AnchorQuery`, `UpdateAllLifecyclePhasesForTest`, `classList().Add`, `scrollTo`. These suggest interactions with the DOM, layout, and rendering lifecycle.
* Assertions using `EXPECT_FALSE`, `ASSERT_NE`, `EXPECT_THAT`, `testing::ElementsAre`, `testing::UnorderedElementsAre`. These are used to verify the expected behavior of the code under test.

**3. Identifying the Core Functionality Under Test:**

The presence of `AnchorEvaluatorImplTest` and the inclusion of `anchor_evaluator_impl.h` are the strongest indicators. The class likely tests how the `AnchorEvaluatorImpl` works. The name "anchor evaluator" suggests it's related to how the browser determines the position or properties of "anchors" on a webpage.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

The use of HTML and CSS within the tests strongly suggests that the "anchors" being tested are related to CSS features. The CSS properties like `anchor-name` appearing in the `<style>` blocks confirm this. The tests manipulate CSS classes (using `classList().Add`) and check how changes to these styles affect the anchor evaluation.

**5. Dissecting the Test Cases:**

Now, examine each `TEST_F` case individually:

* **`AnchorNameAdd`:** Tests adding an `anchor-name` via a CSS class change.
* **`AnchorNameChange`:** Tests changing an existing `anchor-name` via a CSS class change.
* **`AnchorNameRemove`:** Tests removing an `anchor-name` via a CSS class change (setting it to `none`).
* **`BlockFlow`:** Tests `anchor-name` on block-level elements, including how changes in element dimensions affect the anchor's position.
* **`Inline`:** Tests `anchor-name` on inline elements, including considerations for culled (hidden) inline elements and atomic inline elements (images, inline-blocks).
* **`OutOfFlow`:** Tests `anchor-name` on absolutely positioned elements and how their anchors are associated with their containing blocks.
* **`Relative`:** Tests `anchor-name` on relatively positioned elements and how the relative offset is reflected in the anchor's position.
* **`Transform`:** Tests that CSS `transform` properties *do not* affect the reported anchor position.
* **`Scroll`:** Tests that scroll position of a container *does not* affect the reported anchor position within it.
* **`FragmentedContainingBlock`:** Tests `anchor-name` within a multi-column layout, where an element's layout can be split across multiple fragments (columns).

**6. Identifying Assumptions and Logic:**

The tests make assumptions about how Blink's rendering engine should behave. For example, the `Transform` test assumes that `transform` affects visual rendering but not the underlying layout coordinates used for anchor evaluation. The `Scroll` test assumes that scrolling only affects the viewport and not the intrinsic position of elements.

**7. Considering User/Programming Errors:**

While not explicitly testing error conditions, the test cases implicitly reveal potential errors:

* **Incorrect `anchor-name` syntax:**  The tests assume valid CSS syntax. An invalid `anchor-name` might lead to it being ignored.
* **Forgetting to update layout:**  The tests often call `UpdateAllLifecyclePhasesForTest()`. Failing to do this after modifying styles or the DOM could lead to stale anchor information.
* **Misunderstanding the scope of `anchor-name`:** The `OutOfFlow` test shows that anchors are associated with containing blocks, which might be surprising if one expects them to be isolated to the element itself.

**8. Formulating the Summary:**

Based on the above analysis, the summary can be constructed, highlighting the main purpose of the file, its relation to web technologies, illustrating with examples from the test cases, and discussing assumptions and potential errors. The key is to synthesize the information extracted from the code into a coherent and informative explanation.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This might be about HTML anchor tags (`<a>`)."  *Correction:*  The presence of `anchor-name` CSS property quickly shifts focus to CSS-based anchoring.
* **Vague understanding of `PhysicalAnchorQuery`:**  *Refinement:*  Observing how it's populated and used in assertions clarifies its role in storing anchor name-rectangle pairs.
* **Overlooking the significance of `UpdateAllLifecyclePhasesForTest()`:** *Correction:* Recognizing that layout and rendering updates are crucial for the tests to reflect the changes being made.

By following these steps of scanning, identifying key components, connecting to relevant concepts, and detailed examination of the test cases, a comprehensive understanding of the test file's purpose and functionality can be achieved.
这个文件 `anchor_evaluator_impl_test.cc` 是 Chromium Blink 引擎中用于测试 `AnchorEvaluatorImpl` 类的单元测试文件。 `AnchorEvaluatorImpl`  负责收集和管理页面中定义了 `anchor-name` CSS 属性的元素的物理布局信息（例如位置和尺寸），以便其他 CSS 功能（如 `position-anchor` 和 `inset-anchor`）可以使用这些信息来定位元素。

以下是该文件的功能分解和与 Web 技术的关系：

**功能:**

1. **测试 `anchor-name` 属性的添加、修改和移除:**  验证当元素的 `anchor-name` 属性被添加、修改或移除时，`AnchorEvaluatorImpl` 是否正确地更新了它维护的锚点信息。

2. **测试不同布局模式下的锚点信息收集:** 涵盖了块级元素、行内元素、浮动元素、绝对定位元素、相对定位元素以及使用了 CSS `transform` 和 `overflow` 属性的元素，确保在各种布局场景下都能正确收集锚点信息。

3. **测试锚点信息在包含块中的传播:** 验证了即使锚点元素是绝对定位的，其锚点信息也会被传播到其包含块，以便在包含块的上下文中可以使用。

4. **测试滚动和 CSS 变换对锚点信息的影响:** 确认滚动位置不会影响记录的锚点矩形，并且 CSS `transform` 变换也不会改变锚点的原始布局矩形（这很关键，因为 `position-anchor` 等特性依赖于未变换的布局位置）。

5. **测试分片容器中的锚点信息:** 涉及到多列布局，验证了在元素被分片到多个列中的情况下，`AnchorEvaluatorImpl` 如何处理和报告锚点信息。

**与 JavaScript, HTML, CSS 的关系:**

* **CSS:** 这个测试文件直接测试了与 CSS 属性 `anchor-name` 相关的核心功能。`anchor-name` 允许开发者为 HTML 元素指定一个名字，使其可以作为其他元素的定位锚点。
    * **举例:**  在 `AnchorNameAdd` 测试中，通过添加 CSS 类来设置 `#div1` 的 `anchor-name: --div1a;`。 这展示了 CSS 如何定义锚点。

* **HTML:** 测试文件使用 HTML 结构来创建需要测试的布局场景。例如，创建包含不同类型元素的 `<div>` 容器。
    * **举例:**  在所有测试中，都使用了 `SetBodyInnerHTML(R"HTML(...)HTML")` 来设置 HTML 内容，这决定了页面元素的结构和初始状态。

* **JavaScript (间接关系):**  虽然此测试文件本身是用 C++ 编写的，用于测试 Blink 引擎的内部逻辑，但它所测试的 CSS 功能最终会被 JavaScript API (例如，通过 `Element.style` 属性或 `getComputedStyle`) 影响。JavaScript 可以动态地修改元素的 `anchor-name` 属性，而 `AnchorEvaluatorImpl` 负责跟踪这些变化。
    * **概念性举例:**  虽然测试中没有直接的 JavaScript 代码，但可以设想 JavaScript 代码 `document.getElementById('div1').style.anchorName = '--new-anchor';` 会触发 `AnchorEvaluatorImpl` 更新其存储的关于 `#div1` 的锚点信息。

**逻辑推理和假设输入输出:**

以 `AnchorNameAdd` 测试为例：

**假设输入:**

* HTML 结构:
  ```html
  <div id="container">
    <div id="div1"></div>
  </div>
  ```
* 初始状态下，`#div1` 没有 `anchor-name` 属性。
* 通过 JavaScript (模拟 CSS 规则应用) 向 `#container` 添加 `after` 类，该类定义了针对 `#div1` 的 CSS 规则：
  ```css
  .after #div1 {
    anchor-name: --div1a;
  }
  ```

**输出:**

* 在添加 `after` 类并更新布局后，通过 `AnchorQuery(*container)` 获取到的锚点查询结果应该包含一个名为 `--div1a` 的锚点，并且其 `PhysicalRect` 应该对应于 `#div1` 在页面上的物理布局矩形 (例如，左上角坐标 (0, 0)，宽度 50px，高度 20px)。

**涉及用户或编程常见的使用错误:**

1. **拼写错误或大小写不匹配的 `anchor-name`:**  用户可能会在 `anchor-name` 属性中输入错误的名称，导致 `position-anchor` 或 `inset-anchor` 无法找到对应的锚点。
    * **举例:**  CSS 中定义了 `anchor-name: --myAnchor;`，但在 `position-anchor` 中使用了 `--myanchor` (大小写不同)。这将导致锚定失效。

2. **忘记更新布局:** 在某些情况下，如果页面的布局发生变化（例如，通过 JavaScript 修改了元素的尺寸或位置），但没有触发 Blink 引擎的布局更新流程，那么 `AnchorEvaluatorImpl` 可能会持有过时的锚点信息。虽然这个测试文件主要测试引擎内部逻辑，但它确保了当布局更新时，锚点信息也会随之更新。

3. **在不支持 `anchor-name` 的浏览器中使用:**  `anchor-name` 是一个相对较新的 CSS 功能。如果在不支持该功能的浏览器中使用，将不会产生任何效果。

4. **循环引用:**  虽然这个测试文件没有直接测试循环引用，但可以想象，如果元素 A 将元素 B 作为锚点，而元素 B 又将元素 A 作为锚点，可能会导致一些复杂的布局和计算问题。Blink 引擎需要能够处理或避免这类情况。

总而言之，`anchor_evaluator_impl_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎正确地实现了 CSS 锚点功能，这对于实现更灵活和强大的 CSS 定位机制至关重要。

Prompt: 
```
这是目录为blink/renderer/core/layout/anchor_evaluator_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/anchor_evaluator_impl.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {
namespace {

class AnchorEvaluatorImplTest : public RenderingTest {
 public:
  AnchorEvaluatorImplTest() = default;

  const PhysicalAnchorQuery* AnchorQuery(const Element& element) const {
    const LayoutBlockFlow* container =
        To<LayoutBlockFlow>(element.GetLayoutObject());
    if (!container->PhysicalFragmentCount())
      return nullptr;
    const PhysicalBoxFragment* fragment = container->GetPhysicalFragment(0);
    DCHECK(fragment);
    return fragment->AnchorQuery();
  }

  const PhysicalAnchorQuery* AnchorQueryByElementId(const char* id) const {
    if (const Element* element = GetElementById(id))
      return AnchorQuery(*element);
    return nullptr;
  }
};

struct AnchorTestData {
  static Vector<AnchorTestData> ToList(
      const PhysicalAnchorQuery& anchor_query) {
    Vector<AnchorTestData> items;
    for (auto entry : anchor_query) {
      if (auto** name = absl::get_if<const ScopedCSSName*>(&entry.key)) {
        items.push_back(AnchorTestData{(*name)->GetName(), entry.value->rect});
      }
    }
    std::sort(items.begin(), items.end(),
              [](const AnchorTestData& a, const AnchorTestData& b) {
                return CodeUnitCompare(a.name, b.name) < 0;
              });
    return items;
  }
  bool operator==(const AnchorTestData& other) const {
    return name == other.name && rect == other.rect;
  }

  AtomicString name;
  PhysicalRect rect;
};

std::ostream& operator<<(std::ostream& os, const AnchorTestData& value) {
  return os << value.name << ": " << value.rect;
}

TEST_F(AnchorEvaluatorImplTest, AnchorNameAdd) {
  SetBodyInnerHTML(R"HTML(
    <style>
    html, body {
      margin: 0;
      width: 800px;
    }
    #div1 {
      width: 50px;
      height: 20px;
    }
    .after #div1 {
      anchor-name: --div1a;
    }
    </style>
    <div id="container">
      <div id="div1"></div>
    </div>
  )HTML");
  Element* container = GetElementById("container");
  const PhysicalAnchorQuery* anchor_query = AnchorQuery(*container);
  EXPECT_FALSE(anchor_query);

  // Add the "after" class and test anchors are updated accordingly.
  container->classList().Add(AtomicString("after"));
  UpdateAllLifecyclePhasesForTest();
  anchor_query = AnchorQuery(*container);
  ASSERT_NE(anchor_query, nullptr);
  EXPECT_THAT(AnchorTestData::ToList(*anchor_query),
              testing::ElementsAre(AnchorTestData{AtomicString("--div1a"),
                                                  PhysicalRect(0, 0, 50, 20)}));
}

TEST_F(AnchorEvaluatorImplTest, AnchorNameChange) {
  SetBodyInnerHTML(R"HTML(
    <style>
    html, body {
      margin: 0;
      width: 800px;
    }
    #div1 {
      anchor-name: --div1;
      width: 50px;
      height: 20px;
    }
    .after #div1 {
      anchor-name: --div1a;
    }
    </style>
    <div id="container">
      <div id="div1"></div>
    </div>
  )HTML");
  Element* container = GetElementById("container");
  const PhysicalAnchorQuery* anchor_query = AnchorQuery(*container);
  ASSERT_NE(anchor_query, nullptr);
  EXPECT_THAT(AnchorTestData::ToList(*anchor_query),
              testing::ElementsAre(AnchorTestData{AtomicString("--div1"),
                                                  PhysicalRect(0, 0, 50, 20)}));

  // Add the "after" class and test anchors are updated accordingly.
  container->classList().Add(AtomicString("after"));
  UpdateAllLifecyclePhasesForTest();
  anchor_query = AnchorQuery(*container);
  ASSERT_NE(anchor_query, nullptr);
  EXPECT_THAT(AnchorTestData::ToList(*anchor_query),
              testing::ElementsAre(AnchorTestData{AtomicString("--div1a"),
                                                  PhysicalRect(0, 0, 50, 20)}));
}

TEST_F(AnchorEvaluatorImplTest, AnchorNameRemove) {
  SetBodyInnerHTML(R"HTML(
    <style>
    html, body {
      margin: 0;
      width: 800px;
    }
    #div1 {
      anchor-name: --div1;
      width: 50px;
      height: 20px;
    }
    .after #div1 {
      anchor-name: none;
    }
    </style>
    <div id="container">
      <div id="div1"></div>
    </div>
  )HTML");
  Element* container = GetElementById("container");
  const PhysicalAnchorQuery* anchor_query = AnchorQuery(*container);
  ASSERT_NE(anchor_query, nullptr);
  EXPECT_THAT(AnchorTestData::ToList(*anchor_query),
              testing::ElementsAre(AnchorTestData{AtomicString("--div1"),
                                                  PhysicalRect(0, 0, 50, 20)}));

  // Add the "after" class and test anchors are updated accordingly.
  container->classList().Add(AtomicString("after"));
  UpdateAllLifecyclePhasesForTest();
  anchor_query = AnchorQuery(*container);
  EXPECT_FALSE(anchor_query);
}

TEST_F(AnchorEvaluatorImplTest, BlockFlow) {
  SetBodyInnerHTML(R"HTML(
    <style>
    html, body {
      margin: 0;
      width: 800px;
    }
    #div1 {
      height: 20px;
    }
    .after #div1 {
      height: 40px;
    }
    </style>
    <div id="container">
      <div id="div1" style="anchor-name: --div1; width: 400px"></div>
      <div style="anchor-name: --div2"></div>
      <div>
        <div style="height: 30px"></div> <!-- spacer -->
        <div style="anchor-name: --div3"></div>
      </div>
    </div>
  )HTML");
  Element* container = GetElementById("container");
  const PhysicalAnchorQuery* anchor_query = AnchorQuery(*container);
  ASSERT_NE(anchor_query, nullptr);
  EXPECT_THAT(
      AnchorTestData::ToList(*anchor_query),
      testing::UnorderedElementsAre(
          AnchorTestData{AtomicString("--div1"), PhysicalRect(0, 0, 400, 20)},
          AnchorTestData{AtomicString("--div2"), PhysicalRect(0, 20, 800, 0)},
          AnchorTestData{AtomicString("--div3"), PhysicalRect(0, 50, 800, 0)}));

  // Add the "after" class and test anchors are updated accordingly.
  container->classList().Add(AtomicString("after"));
  UpdateAllLifecyclePhasesForTest();
  anchor_query = AnchorQuery(*container);
  ASSERT_NE(anchor_query, nullptr);
  EXPECT_THAT(
      AnchorTestData::ToList(*anchor_query),
      testing::UnorderedElementsAre(
          AnchorTestData{AtomicString("--div1"), PhysicalRect(0, 0, 400, 40)},
          AnchorTestData{AtomicString("--div2"), PhysicalRect(0, 40, 800, 0)},
          AnchorTestData{AtomicString("--div3"), PhysicalRect(0, 70, 800, 0)}));
}

TEST_F(AnchorEvaluatorImplTest, Inline) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
    html, body {
      margin: 0;
      width: 800px;
      font-family: Ahem;
      font-size: 10px;
      line-height: 1;
    }
    img {
      width: 10px;
      height: 8px;
    }
    .after .add {
      anchor-name: --add;
    }
    </style>
    <div id="container">
      0
      <!-- culled and non-culled inline boxes. -->
      <span style="anchor-name: --culled">23</span>
      <span style="anchor-name: --non-culled; background: yellow">56</span>

      <!-- Adding `anchor-name` dynamically should uncull. -->
      <span class="add">89</span>

      <!-- Atomic inlines: replaced elements and inline blocks. -->
      <img style="anchor-name: --img" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=">
      <span style="anchor-name: --inline-block; display: inline-block">X</span>
    </div>
  )HTML");
  Element* container = GetElementById("container");
  const PhysicalAnchorQuery* anchor_query = AnchorQuery(*container);
  ASSERT_NE(anchor_query, nullptr);
  EXPECT_THAT(
      AnchorTestData::ToList(*anchor_query),
      testing::UnorderedElementsAre(
          AnchorTestData{AtomicString("--culled"), PhysicalRect(20, 0, 20, 10)},
          AnchorTestData{AtomicString("--img"), PhysicalRect(110, 0, 10, 8)},
          AnchorTestData{AtomicString("--inline-block"),
                         PhysicalRect(130, 0, 10, 10)},
          AnchorTestData{AtomicString("--non-culled"),
                         PhysicalRect(50, 0, 20, 10)}));

  // Add the "after" class and test anchors are updated accordingly.
  container->classList().Add(AtomicString("after"));
  UpdateAllLifecyclePhasesForTest();
  anchor_query = AnchorQuery(*container);
  ASSERT_NE(anchor_query, nullptr);
  EXPECT_THAT(
      AnchorTestData::ToList(*anchor_query),
      testing::UnorderedElementsAre(
          AnchorTestData{AtomicString("--add"), PhysicalRect(80, 0, 20, 10)},
          AnchorTestData{AtomicString("--culled"), PhysicalRect(20, 0, 20, 10)},
          AnchorTestData{AtomicString("--img"), PhysicalRect(110, 0, 10, 8)},
          AnchorTestData{AtomicString("--inline-block"),
                         PhysicalRect(130, 0, 10, 10)},
          AnchorTestData{AtomicString("--non-culled"),
                         PhysicalRect(50, 0, 20, 10)}));
}

TEST_F(AnchorEvaluatorImplTest, OutOfFlow) {
  SetBodyInnerHTML(R"HTML(
    <style>
    html, body {
      margin: 0;
      width: 800px;
    }
    </style>
    <div id="container" style="position: relative">
      <div id="middle">
        <div style="anchor-name: --abs1; position: absolute; left: 100px; top: 50px; width: 400px; height: 20px"></div>
      </div>
    </div>
  )HTML");
  const PhysicalAnchorQuery* anchor_query = AnchorQueryByElementId("container");
  ASSERT_NE(anchor_query, nullptr);
  EXPECT_THAT(AnchorTestData::ToList(*anchor_query),
              testing::ElementsAre(AnchorTestData{
                  AtomicString("--abs1"), PhysicalRect(100, 50, 400, 20)}));

  // Anchor names of out-of-flow positioned objects are propagated to their
  // containing blocks.
  EXPECT_EQ(AnchorQueryByElementId("middle"), nullptr);
}

// Relative-positioning should shift the rectangles.
TEST_F(AnchorEvaluatorImplTest, Relative) {
  SetBodyInnerHTML(R"HTML(
    <style>
    html, body {
      margin: 0;
      width: 800px;
    }
    </style>
    <div id="container">
      <div style="anchor-name: --relpos; position: relative; left: 20px; top: 10px"></div>
    </div>
  )HTML");
  const PhysicalAnchorQuery* anchor_query = AnchorQueryByElementId("container");
  ASSERT_NE(anchor_query, nullptr);
  EXPECT_THAT(AnchorTestData::ToList(*anchor_query),
              testing::ElementsAre(AnchorTestData{
                  AtomicString("--relpos"), PhysicalRect(20, 10, 800, 0)}));
}

// CSS Transform should not shift the rectangles.
TEST_F(AnchorEvaluatorImplTest, Transform) {
  SetBodyInnerHTML(R"HTML(
    <style>
    html, body {
      margin: 0;
      width: 800px;
    }
    </style>
    <div id="container">
      <div style="anchor-name: --transform; transform: translate(100px, 100px)"></div>
    </div>
  )HTML");
  const PhysicalAnchorQuery* anchor_query = AnchorQueryByElementId("container");
  ASSERT_NE(anchor_query, nullptr);
  EXPECT_THAT(AnchorTestData::ToList(*anchor_query),
              testing::ElementsAre(AnchorTestData{AtomicString("--transform"),
                                                  PhysicalRect(0, 0, 800, 0)}));
}

// Scroll positions should not shift the rectangles.
TEST_F(AnchorEvaluatorImplTest, Scroll) {
  SetBodyInnerHTML(R"HTML(
    <style>
    html, body {
      margin: 0;
      width: 800px;
    }
    </style>
    <div id="container" style="overflow: scroll; width: 200px; height: 200px">
      <div style="anchor-name: --inner; width: 400px; height: 500px"></div>
    </div>
  )HTML");
  Element* container = GetElementById("container");
  ASSERT_NE(container, nullptr);
  container->scrollTo(30, 20);
  UpdateAllLifecyclePhasesForTest();

  const PhysicalAnchorQuery* anchor_query = AnchorQuery(*container);
  ASSERT_NE(anchor_query, nullptr);
  EXPECT_THAT(AnchorTestData::ToList(*anchor_query),
              testing::ElementsAre(AnchorTestData{
                  AtomicString("--inner"), PhysicalRect(0, 0, 400, 500)}));
}

TEST_F(AnchorEvaluatorImplTest, FragmentedContainingBlock) {
  SetBodyInnerHTML(R"HTML(
    <style>
    html, body {
      margin: 0;
      width: 800px;
    }
    #cb {
      position: relative;
    }
    #columns {
      column-count: 3;
      column-fill: auto;
      column-gap: 10px;
      column-width: 100px;
      width: 320px;
      height: 100px;
    }
    </style>
    <div id="container">
      <div style="height: 10px"></div>
      <div id="columns">
        <div style="height: 10px"></div>
        <div id="cb">
          <div style="height: 140px"></div>
          <!-- This anchor box starts at the middle of the 2nd column. -->
          <div style="anchor-name: --a1; width: 100px; height: 100px"></div>
        </div>
      </div>
    </div>
  )HTML");
  auto* cb = To<LayoutBox>(GetLayoutObjectByElementId("cb"));
  ASSERT_EQ(cb->PhysicalFragmentCount(), 3u);
  const PhysicalBoxFragment* cb_fragment1 = cb->GetPhysicalFragment(1);
  const PhysicalAnchorQuery* cb_anchor_query1 = cb_fragment1->AnchorQuery();
  ASSERT_NE(cb_anchor_query1, nullptr);
  EXPECT_THAT(AnchorTestData::ToList(*cb_anchor_query1),
              testing::ElementsAre(AnchorTestData{
                  AtomicString("--a1"), PhysicalRect(0, 50, 100, 50)}));
  const PhysicalBoxFragment* cb_fragment2 = cb->GetPhysicalFragment(2);
  const PhysicalAnchorQuery* cb_anchor_query2 = cb_fragment2->AnchorQuery();
  ASSERT_NE(cb_anchor_query2, nullptr);
  EXPECT_THAT(AnchorTestData::ToList(*cb_anchor_query2),
              testing::ElementsAre(AnchorTestData{
                  AtomicString("--a1"), PhysicalRect(0, 0, 100, 50)}));

  const PhysicalAnchorQuery* columns_anchor_query =
      AnchorQueryByElementId("columns");
  ASSERT_NE(columns_anchor_query, nullptr);
  EXPECT_THAT(AnchorTestData::ToList(*columns_anchor_query),
              testing::ElementsAre(AnchorTestData{
                  AtomicString("--a1"), PhysicalRect(110, 0, 210, 100)}));

  const PhysicalAnchorQuery* container_anchor_query =
      AnchorQueryByElementId("container");
  ASSERT_NE(container_anchor_query, nullptr);
  EXPECT_THAT(AnchorTestData::ToList(*container_anchor_query),
              testing::ElementsAre(AnchorTestData{
                  AtomicString("--a1"), PhysicalRect(110, 10, 210, 100)}));
}

}  // namespace
}  // namespace blink

"""

```
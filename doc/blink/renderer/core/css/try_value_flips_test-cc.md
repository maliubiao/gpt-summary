Response:
Let's break down the thought process to analyze the C++ test file.

**1. Understanding the Goal:**

The first step is to recognize that this is a *test file*. The filename `try_value_flips_test.cc` strongly suggests it's testing the functionality of something related to "value flips". The presence of `#include` directives further confirms this, especially the inclusion of `try_value_flips.h`.

**2. High-Level Structure Analysis:**

Quickly scan the code to identify key components:

* **Includes:** What other parts of the Blink engine are being used? This gives context. `CSSFlipRevertValue`, `CSSPropertyValueSet`, `css_test_helpers`, `TryTacticTransform`, `PageTestBase`, `WritingDirectionMode` are important hints.
* **Namespaces:**  The code is within the `blink` namespace.
* **Helper Functions/Structures:**  Look for reusable blocks of code. `Tactics`, `ExpectedFlips`, `ExpectedFlipsSet`, `DeclarationStrings`, `ExpectedFlipsVector`, `ActualFlipsVector`, `ParseDeclaration`. These are clearly setup and assertion helpers.
* **Test Fixtures:**  `TryValueFlipsTest`, `FlipValueTest`, `NoFlipValueTest` derived from `PageTestBase` indicate different sets of tests.
* **`TEST_F` and `TEST_P` macros:**  These are the actual test cases. `TEST_F` for simple tests, `TEST_P` for parameterized tests.
* **Data Structures for Testing:** `flip_value_test_data`, `no_flip_value_test_data`. These arrays contain test inputs, expected outputs, and configurations.

**3. Deciphering Core Functionality (`TryValueFlips`):**

Based on the test names and helper functions, the core functionality being tested seems to involve:

* **CSS Property Flipping:**  The tests manipulate CSS properties like `inset-block-start`, `margin-inline-end`, `align-self`, `block-size`, etc. The `ExpectedFlips` structure and the logic within `ExpectedFlipsSet` clearly define these expected flips.
* **Try Tactics:** The `TryTactic` enum (and `TryTacticList`) is central. Test cases are named after different tactic combinations (e.g., `FlipBlock`, `FlipInline`, `FlipStart`). This suggests the system tries different strategies to flip values.
* **Writing Modes and Text Direction:** The inclusion of `WritingDirectionMode` and tests that explicitly set it (like the last few in `flip_value_test_data`) indicate that text direction (LTR/RTL) and writing mode (horizontal/vertical) influence the flipping logic.
* **`anchor()` and `anchor-size()` CSS functions:**  Specific tests focus on how these relatively new CSS functions are flipped.
* **`calc()`, `min()`:** Tests involve expressions, indicating the flipping logic needs to handle more complex value types.

**4. Detailed Examination of Test Cases:**

Go through the individual test cases. For example, in `TEST_F(TryValueFlipsTest, FlipBlock)`, the expectation is that `inset-block-start` flips to `inset-block-end`, `margin-block-start` flips to `margin-block-end`, and so on. This confirms the "FlipBlock" tactic targets block-level properties. Similarly, `FlipInline` targets inline-level properties. `FlipStart` appears to involve a more comprehensive transformation.

**5. Parameterized Tests (`FlipValueTest`, `NoFlipValueTest`):**

Recognize that `TEST_P` uses external data arrays. Examine `flip_value_test_data` and `no_flip_value_test_data`. Each entry in these arrays represents a specific test scenario with:

* `input`: A CSS declaration string.
* `expected`: The expected flipped CSS declaration string.
* `tactic`: The `TryTacticList` being applied.
* `writing_direction`:  Optional writing direction.

The `TEST_P` macro executes the test function (`All`) for each entry in the data array.

**6. Identifying Potential User Errors and Debugging Clues:**

Based on the functionality and the test cases:

* **Incorrect Tactic Combinations:** Users might apply tactics that don't produce the desired flipping behavior. The tests implicitly demonstrate this by showcasing various tactic combinations.
* **Misunderstanding Writing Modes:**  Users might not realize that writing mode and text direction affect flipping. The tests with explicit `writing_direction` highlight this.
* **Unexpected Flipping of Complex Values:** Users might have complex CSS values (like those involving `calc()`, `min()`, or custom functions) and might not anticipate how they are flipped. The tests involving these functions serve as examples.

**7. Connecting to JavaScript, HTML, and CSS:**

Think about how the tested functionality interacts with web technologies:

* **CSS:** The core of the functionality is about manipulating CSS properties and values.
* **HTML:** CSS is applied to HTML elements. The effects of these flips would be visible in how elements are laid out and styled.
* **JavaScript:** JavaScript could be used to dynamically change CSS properties, potentially triggering or observing these flipping mechanisms. For example, JavaScript could change the `direction` or `writing-mode` style of an element.

**8. Inferring User Steps for Debugging:**

Consider how a developer might end up needing to look at this test file:

* They might observe unexpected layout behavior when working with logical properties in different writing modes.
* They might be implementing a new CSS feature that interacts with logical properties and need to understand how flipping works.
* They might be debugging a bug related to incorrect flipping of CSS values.

**Self-Correction/Refinement During Analysis:**

Initially, one might focus too much on the specific properties being flipped. However, realizing the importance of `TryTactic` and the parameterized tests leads to a deeper understanding of the *strategies* for flipping, not just the individual property mappings. Also, the inclusion of `anchor()` and `anchor-size()` functions points to the system's ability to handle newer CSS features. The tests with `calc()` and `min()` correct the initial assumption that only simple values are considered.
这个C++源代码文件 `try_value_flips_test.cc` 是 Chromium Blink 渲染引擎的一部分，其主要功能是 **测试 `TryValueFlips` 类及其相关的 CSS 属性值翻转逻辑**。

更具体地说，这个文件测试了在不同的 "尝试策略（Try Tactics）" 下，哪些 CSS 属性值会被翻转，以及翻转成什么值。这种翻转通常是为了支持**国际化（i18n）**，特别是处理**从左到右（LTR）**和**从右到左（RTL）**的文本方向，以及不同的**书写模式（writing modes）**。

以下是该文件的更详细功能分解以及与 JavaScript、HTML 和 CSS 的关系：

**文件功能:**

1. **定义测试用例:** 该文件使用 Google Test 框架定义了多个测试用例（以 `TEST_F` 和 `TEST_P` 开头）。每个测试用例都针对 `TryValueFlips` 类的特定行为进行验证。
2. **测试不同的尝试策略 (Try Tactics):**  `TryValueFlips` 类似乎接受一个 `TryTacticList` 作为输入，这个列表定义了应用于 CSS 值的翻转策略。测试用例涵盖了不同的策略组合，例如：
   - `TryTactic::kNone`: 不进行翻转。
   - `TryTactic::kFlipBlock`: 翻转块级相关的属性。
   - `TryTactic::kFlipInline`: 翻转行内相关的属性。
   - `TryTactic::kFlipStart`: 翻转起始和结束相关的属性。
3. **验证属性翻转映射:** 测试用例定义了预期的属性翻转结果。例如，当应用 `TryTactic::kFlipBlock` 时，`inset-block-start` 应该翻转为 `inset-block-end`，`margin-block-start` 应该翻转为 `margin-block-end`。
4. **处理逻辑属性和物理属性:**  该文件测试了逻辑属性（如 `inset-block-start`, `margin-inline-end`）和物理属性（如 `left`, `right`, `top`, `bottom`）之间的翻转。
5. **测试 CSS 函数的翻转:**  文件中包含对 CSS 函数 `anchor()` 和 `anchor-size()` 的翻转测试，以及包含 `calc()` 和 `min()` 等表达式的测试。这表明 `TryValueFlips` 能够处理更复杂的 CSS 值。
6. **考虑书写模式和文本方向:**  某些测试用例显式地设置了 `WritingDirectionMode`，包括水平和垂直书写模式以及 LTR 和 RTL 文本方向，以验证翻转逻辑在不同国际化场景下的正确性。
7. **使用辅助函数进行测试:**  该文件定义了一些辅助函数，如 `ExpectedFlipsSet`, `DeclarationStrings`, `ExpectedFlipsVector`, `ActualFlipsVector` 和 `ParseDeclaration`，以简化测试用例的编写和断言。

**与 JavaScript, HTML, CSS 的关系:**

`try_value_flips_test.cc` 间接地与 JavaScript、HTML 和 CSS 相关，因为它测试了 Blink 引擎中处理 CSS 属性值翻转的核心逻辑。

* **CSS:** 这是最直接相关的。`TryValueFlips` 的目的是正确地翻转 CSS 属性值，以适应不同的布局方向和书写模式。例如，在 RTL 布局中，`margin-left` 可能会被翻转为 `margin-right`。
   - **例子:**  如果 CSS 样式表中有 `margin-inline-start: 10px;`，在 RTL 环境下，`TryValueFlips` 的逻辑会将其翻转为 `margin-inline-end: 10px;`。
* **HTML:** HTML 结构决定了元素的布局方式，而 CSS 样式应用于这些元素。`TryValueFlips` 的正确性确保了在不同的书写模式下，HTML 元素能够按照预期的方式进行布局。
   - **例子:**  一个包含文本的 `<div>` 元素，其文本方向由 HTML 的 `dir` 属性或 CSS 的 `direction` 属性控制。`TryValueFlips` 确保了与文本方向相关的 CSS 属性能够正确地应用于该 `<div>`。
* **JavaScript:** JavaScript 可以动态地修改 CSS 样式。Blink 引擎在应用这些修改时，可能会涉及到 `TryValueFlips` 的逻辑。例如，如果 JavaScript 代码修改了一个元素的 `margin-inline-start` 属性，引擎需要根据当前的布局方向正确地处理这个值。
   - **例子:**  JavaScript 代码可以使用 `element.style.marginLeft = '10px'` 来设置元素的左边距。在 RTL 环境下，虽然代码设置的是 `marginLeft`，但浏览器内部可能会根据 `TryValueFlips` 的逻辑，将其理解为设置了逻辑上的起始边距。

**逻辑推理 (假设输入与输出):**

假设输入是一个包含 CSS 属性和值的 `CSSPropertyValueSet`，以及一个 `TryTacticList`。

**假设输入:**

```
CSSPropertyValueSet {
  inset-block-start: 5px;
  margin-inline-start: 10px;
  align-self: start;
}
```

**情景 1: TryTactic::kFlipBlock**

**预期输出:**

```
CSSPropertyValueSet {
  inset-block-start: 翻转后的值 (可能是 inset-block-end);
  margin-inline-start: 10px; // 不受 kFlipBlock 影响
  align-self: start;         // 不受 kFlipBlock 影响
}
```

**情景 2: TryTactic::kFlipInline**

**预期输出:**

```
CSSPropertyValueSet {
  inset-block-start: 5px;     // 不受 kFlipInline 影响
  margin-inline-start: 翻转后的值 (可能是 margin-inline-end);
  align-self: start;         // 不受 kFlipInline 影响
}
```

**情景 3: TryTactic::kFlipStart (假设会翻转 align-items 的 start/end 值)**

**预期输出:**

```
CSSPropertyValueSet {
  inset-block-start: 翻转后的值 (可能是 inset-inline-start);
  margin-inline-start: 翻转后的值 (可能是 margin-block-start);
  align-self: end;           // start 翻转为 end
}
```

**用户或编程常见的使用错误:**

1. **错误地假设物理属性会自动翻转:** 用户可能会认为设置 `left: 10px;` 在 RTL 环境下会自动变为设置右边距，但实际上可能需要使用逻辑属性 `inset-inline-start` 才能实现跨方向的兼容性。`TryValueFlips` 的测试确保了逻辑属性的正确翻转。
   - **例子:** 用户在编写 CSS 时，直接使用 `left` 和 `right` 属性，而没有考虑国际化，导致在 RTL 语言环境下布局错乱。
2. **不理解不同的翻转策略:** 开发者可能不清楚 `TryTactic::kFlipBlock`, `TryTactic::kFlipInline`, `TryTactic::kFlipStart` 等策略的具体作用范围，导致在应用翻转时出现意外的结果。
   - **例子:**  开发者可能只想翻转行内相关的属性，但错误地使用了 `TryTactic::kFlipBlock`，导致块级相关的属性也被翻转。
3. **在 JavaScript 中直接操作物理属性:**  JavaScript 代码如果直接修改 `element.style.marginLeft`，可能会绕过 Blink 引擎的翻转逻辑，导致在不同语言环境下行为不一致。应该尽量使用逻辑属性或考虑当前的布局方向。
   - **例子:**  JavaScript 代码使用 `element.style.left = '10px'` 来定位元素，在 RTL 环境下，可能需要使用 `element.style.right = '10px'` 才能达到相同的视觉效果。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个网页:** 浏览器开始解析 HTML、CSS 和 JavaScript。
2. **浏览器渲染引擎 (Blink) 解析 CSS:**  Blink 引擎会解析网页的 CSS 样式表，包括逻辑属性和物理属性。
3. **布局计算:** Blink 引擎会根据 CSS 样式和 HTML 结构进行布局计算，确定页面上各个元素的位置和大小。
4. **遇到需要翻转的属性:** 在布局计算过程中，如果遇到需要根据书写模式或文本方向进行翻转的 CSS 属性值，Blink 引擎会调用相关的逻辑，这其中可能就涉及到了 `TryValueFlips` 类。
5. **应用尝试策略:**  Blink 引擎会根据当前的上下文（例如，是否处于 RTL 模式）选择合适的尝试策略。
6. **调用 `TryValueFlips::FlipSet` 或 `TryValueFlips::FlipValue`:** 相关的函数会被调用，传入 CSS 属性和当前的尝试策略。
7. **根据策略进行翻转:** `TryValueFlips` 类根据传入的策略，查找预定义的翻转映射，并返回翻转后的属性值。
8. **应用翻转后的值进行布局:** 最终，翻转后的 CSS 属性值会被用于元素的最终布局和渲染。

**调试线索:**

如果开发者在调试与布局或国际化相关的问题，可能会查看这个文件作为线索：

* **布局错乱:** 当网页在不同的语言环境下出现布局错乱时，可能是因为 CSS 属性的翻转逻辑出现问题。开发者可能会查看 `TryValueFlips` 的测试用例，了解哪些属性在哪些策略下会发生翻转。
* **RTL/LTR 问题:**  当处理 RTL 和 LTR 语言切换时，如果元素的定位或边距出现异常，开发者可能会研究 `TryValueFlips` 如何处理与方向相关的属性。
* **新的 CSS 特性:** 如果使用了新的 CSS 逻辑属性或函数（如 `anchor()`），并且行为不符合预期，开发者可能会查看 `TryValueFlips` 中是否包含了对这些新特性的处理。
* **理解 Blink 内部机制:**  想要深入了解 Blink 引擎如何处理 CSS 属性翻转的开发者，会阅读这个测试文件来理解其背后的逻辑和覆盖的场景。

总而言之，`try_value_flips_test.cc` 是 Blink 引擎中一个非常重要的测试文件，它确保了 CSS 属性值翻转逻辑的正确性，这对于支持国际化和多语言网页至关重要。

Prompt: 
```
这是目录为blink/renderer/core/css/try_value_flips_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/try_value_flips.h"

#include "third_party/blink/renderer/core/css/css_flip_revert_value.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/try_tactic_transform.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/text/writing_direction_mode.h"

namespace blink {

constexpr TryTacticList Tactics(TryTactic t0,
                                TryTactic t1 = TryTactic::kNone,
                                TryTactic t2 = TryTactic::kNone) {
  return TryTacticList{t0, t1, t2};
}

class TryValueFlipsTest : public PageTestBase {
 public:
  struct ExpectedFlips {
    CSSPropertyID inset_block_start = CSSPropertyID::kInsetBlockStart;
    CSSPropertyID inset_block_end = CSSPropertyID::kInsetBlockEnd;
    CSSPropertyID inset_inline_start = CSSPropertyID::kInsetInlineStart;
    CSSPropertyID inset_inline_end = CSSPropertyID::kInsetInlineEnd;
    CSSPropertyID margin_block_start = CSSPropertyID::kMarginBlockStart;
    CSSPropertyID margin_block_end = CSSPropertyID::kMarginBlockEnd;
    CSSPropertyID margin_inline_start = CSSPropertyID::kMarginInlineStart;
    CSSPropertyID margin_inline_end = CSSPropertyID::kMarginInlineEnd;
    CSSPropertyID align_self = CSSPropertyID::kAlignSelf;
    CSSPropertyID justify_self = CSSPropertyID::kJustifySelf;
    CSSPropertyID block_size = CSSPropertyID::kBlockSize;
    CSSPropertyID inline_size = CSSPropertyID::kInlineSize;
    CSSPropertyID min_block_size = CSSPropertyID::kMinBlockSize;
    CSSPropertyID min_inline_size = CSSPropertyID::kMinInlineSize;
    CSSPropertyID max_block_size = CSSPropertyID::kMaxBlockSize;
    CSSPropertyID max_inline_size = CSSPropertyID::kMaxInlineSize;
  };

  // Creates a CSSPropertyValueSet that contains CSSFlipRevertValue
  // for each declarations in `flips` that actually represents a flip
  // (i.e. doesn't just flip to itself).
  const CSSPropertyValueSet* ExpectedFlipsSet(ExpectedFlips flips) {
    auto* set =
        MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode);

    auto add = [set](CSSPropertyID from, CSSPropertyID to) {
      set->SetProperty(from,
                       *MakeGarbageCollected<cssvalue::CSSFlipRevertValue>(
                           to, TryTacticTransform()));
    };

    auto add_if_flipped = [&add](CSSPropertyID from, CSSPropertyID to) {
      if (from != to) {
        add(from, to);
      }
    };

    add_if_flipped(CSSPropertyID::kInsetBlockStart, flips.inset_block_start);
    add_if_flipped(CSSPropertyID::kInsetBlockEnd, flips.inset_block_end);
    add_if_flipped(CSSPropertyID::kInsetInlineStart, flips.inset_inline_start);
    add_if_flipped(CSSPropertyID::kInsetInlineEnd, flips.inset_inline_end);
    add_if_flipped(CSSPropertyID::kMarginBlockStart, flips.margin_block_start);
    add_if_flipped(CSSPropertyID::kMarginBlockEnd, flips.margin_block_end);
    add_if_flipped(CSSPropertyID::kMarginInlineStart,
                   flips.margin_inline_start);
    add_if_flipped(CSSPropertyID::kMarginInlineEnd, flips.margin_inline_end);
    add(CSSPropertyID::kAlignSelf, flips.align_self);
    add(CSSPropertyID::kJustifySelf, flips.justify_self);
    add(CSSPropertyID::kPositionArea, CSSPropertyID::kPositionArea);
    add_if_flipped(CSSPropertyID::kBlockSize, flips.block_size);
    add_if_flipped(CSSPropertyID::kInlineSize, flips.inline_size);
    add_if_flipped(CSSPropertyID::kMinBlockSize, flips.min_block_size);
    add_if_flipped(CSSPropertyID::kMinInlineSize, flips.min_inline_size);
    add_if_flipped(CSSPropertyID::kMaxBlockSize, flips.max_block_size);
    add_if_flipped(CSSPropertyID::kMaxInlineSize, flips.max_inline_size);

    return set;
  }

  // Serializes the declarations of `set` into a vector. AsText is not used,
  // because it shorthandifies the declarations, which is not helpful
  // for debugging failing tests.
  Vector<String> DeclarationStrings(const CSSPropertyValueSet* set) {
    Vector<String> result;
    for (unsigned i = 0; i < set->PropertyCount(); ++i) {
      CSSPropertyValueSet::PropertyReference ref = set->PropertyAt(i);
      result.push_back(ref.Name().ToAtomicString() + ":" +
                       ref.Value().CssText());
    }
    return result;
  }

  Vector<String> ExpectedFlipsVector(ExpectedFlips flips) {
    return DeclarationStrings(ExpectedFlipsSet(flips));
  }

  Vector<String> ActualFlipsVector(const TryTacticList& tactic_list) {
    TryValueFlips flips;
    return DeclarationStrings(flips.FlipSet(tactic_list));
  }
};

TEST_F(TryValueFlipsTest, None) {
  TryValueFlips flips;
  EXPECT_FALSE(flips.FlipSet(Tactics(TryTactic::kNone)));
}

// Flips without kFlipStart:

TEST_F(TryValueFlipsTest, FlipBlock) {
  EXPECT_EQ(ExpectedFlipsVector(ExpectedFlips{
                .inset_block_start = CSSPropertyID::kInsetBlockEnd,
                .inset_block_end = CSSPropertyID::kInsetBlockStart,
                .margin_block_start = CSSPropertyID::kMarginBlockEnd,
                .margin_block_end = CSSPropertyID::kMarginBlockStart,
            }),
            ActualFlipsVector(Tactics(TryTactic::kFlipBlock)));
}

TEST_F(TryValueFlipsTest, FlipInline) {
  EXPECT_EQ(ExpectedFlipsVector(ExpectedFlips{
                .inset_inline_start = CSSPropertyID::kInsetInlineEnd,
                .inset_inline_end = CSSPropertyID::kInsetInlineStart,
                .margin_inline_start = CSSPropertyID::kMarginInlineEnd,
                .margin_inline_end = CSSPropertyID::kMarginInlineStart,
            }),
            ActualFlipsVector(Tactics(TryTactic::kFlipInline)));
}

TEST_F(TryValueFlipsTest, FlipBlockInline) {
  EXPECT_EQ(ExpectedFlipsVector(ExpectedFlips{
                .inset_block_start = CSSPropertyID::kInsetBlockEnd,
                .inset_block_end = CSSPropertyID::kInsetBlockStart,
                .inset_inline_start = CSSPropertyID::kInsetInlineEnd,
                .inset_inline_end = CSSPropertyID::kInsetInlineStart,
                .margin_block_start = CSSPropertyID::kMarginBlockEnd,
                .margin_block_end = CSSPropertyID::kMarginBlockStart,
                .margin_inline_start = CSSPropertyID::kMarginInlineEnd,
                .margin_inline_end = CSSPropertyID::kMarginInlineStart,
            }),
            ActualFlipsVector(
                Tactics(TryTactic::kFlipBlock, TryTactic::kFlipInline)));
}

TEST_F(TryValueFlipsTest, FlipInlineBlock) {
  EXPECT_EQ(
      ActualFlipsVector(Tactics(TryTactic::kFlipBlock, TryTactic::kFlipInline)),
      ActualFlipsVector(
          Tactics(TryTactic::kFlipInline, TryTactic::kFlipBlock)));
}

// Flips with kFlipStart:

TEST_F(TryValueFlipsTest, FlipStart) {
  EXPECT_EQ(
      ExpectedFlipsVector(ExpectedFlips{
          .inset_block_start = CSSPropertyID::kInsetInlineStart,
          .inset_block_end = CSSPropertyID::kInsetInlineEnd,
          .inset_inline_start = CSSPropertyID::kInsetBlockStart,
          .inset_inline_end = CSSPropertyID::kInsetBlockEnd,
          .margin_block_start = CSSPropertyID::kMarginInlineStart,
          .margin_block_end = CSSPropertyID::kMarginInlineEnd,
          .margin_inline_start = CSSPropertyID::kMarginBlockStart,
          .margin_inline_end = CSSPropertyID::kMarginBlockEnd,
          // Flipped alignment:
          .align_self = CSSPropertyID::kJustifySelf,
          .justify_self = CSSPropertyID::kAlignSelf,
          // Flipped sizing:
          .block_size = CSSPropertyID::kInlineSize,
          .inline_size = CSSPropertyID::kBlockSize,
          .min_block_size = CSSPropertyID::kMinInlineSize,
          .min_inline_size = CSSPropertyID::kMinBlockSize,
          .max_block_size = CSSPropertyID::kMaxInlineSize,
          .max_inline_size = CSSPropertyID::kMaxBlockSize,
      }),
      ActualFlipsVector(Tactics(TryTactic::kFlipBlock, TryTactic::kFlipStart,
                                TryTactic::kFlipInline)));
}

TEST_F(TryValueFlipsTest, FlipBlockStartInline) {
  EXPECT_EQ(
      ActualFlipsVector(Tactics(TryTactic::kFlipStart)),
      ActualFlipsVector(Tactics(TryTactic::kFlipBlock, TryTactic::kFlipStart,
                                TryTactic::kFlipInline)));
}

TEST_F(TryValueFlipsTest, FlipInlineStartBlock) {
  EXPECT_EQ(
      ActualFlipsVector(Tactics(TryTactic::kFlipStart)),
      ActualFlipsVector(Tactics(TryTactic::kFlipInline, TryTactic::kFlipStart,
                                TryTactic::kFlipBlock)));
}

TEST_F(TryValueFlipsTest, FlipStartBlock) {
  EXPECT_EQ(
      ExpectedFlipsVector(ExpectedFlips{
          .inset_block_start = CSSPropertyID::kInsetInlineEnd,
          .inset_block_end = CSSPropertyID::kInsetInlineStart,
          .inset_inline_start = CSSPropertyID::kInsetBlockStart,
          .inset_inline_end = CSSPropertyID::kInsetBlockEnd,
          .margin_block_start = CSSPropertyID::kMarginInlineEnd,
          .margin_block_end = CSSPropertyID::kMarginInlineStart,
          .margin_inline_start = CSSPropertyID::kMarginBlockStart,
          .margin_inline_end = CSSPropertyID::kMarginBlockEnd,
          // Flipped alignment:
          .align_self = CSSPropertyID::kJustifySelf,
          .justify_self = CSSPropertyID::kAlignSelf,
          // Flipped sizing:
          .block_size = CSSPropertyID::kInlineSize,
          .inline_size = CSSPropertyID::kBlockSize,
          .min_block_size = CSSPropertyID::kMinInlineSize,
          .min_inline_size = CSSPropertyID::kMinBlockSize,
          .max_block_size = CSSPropertyID::kMaxInlineSize,
          .max_inline_size = CSSPropertyID::kMaxBlockSize,
      }),
      ActualFlipsVector(Tactics(TryTactic::kFlipStart, TryTactic::kFlipBlock)));
}

TEST_F(TryValueFlipsTest, FlipInlineStart) {
  EXPECT_EQ(
      ActualFlipsVector(Tactics(TryTactic::kFlipStart, TryTactic::kFlipBlock)),
      ActualFlipsVector(
          Tactics(TryTactic::kFlipInline, TryTactic::kFlipStart)));
}

TEST_F(TryValueFlipsTest, FlipStartInline) {
  EXPECT_EQ(ExpectedFlipsVector(ExpectedFlips{
                .inset_block_start = CSSPropertyID::kInsetInlineStart,
                .inset_block_end = CSSPropertyID::kInsetInlineEnd,
                .inset_inline_start = CSSPropertyID::kInsetBlockEnd,
                .inset_inline_end = CSSPropertyID::kInsetBlockStart,
                .margin_block_start = CSSPropertyID::kMarginInlineStart,
                .margin_block_end = CSSPropertyID::kMarginInlineEnd,
                .margin_inline_start = CSSPropertyID::kMarginBlockEnd,
                .margin_inline_end = CSSPropertyID::kMarginBlockStart,
                // Flipped alignment:
                .align_self = CSSPropertyID::kJustifySelf,
                .justify_self = CSSPropertyID::kAlignSelf,
                // Flipped sizing:
                .block_size = CSSPropertyID::kInlineSize,
                .inline_size = CSSPropertyID::kBlockSize,
                .min_block_size = CSSPropertyID::kMinInlineSize,
                .min_inline_size = CSSPropertyID::kMinBlockSize,
                .max_block_size = CSSPropertyID::kMaxInlineSize,
                .max_inline_size = CSSPropertyID::kMaxBlockSize,
            }),
            ActualFlipsVector(
                Tactics(TryTactic::kFlipStart, TryTactic::kFlipInline)));
}

TEST_F(TryValueFlipsTest, FlipBlockStart) {
  EXPECT_EQ(
      ActualFlipsVector(Tactics(TryTactic::kFlipStart, TryTactic::kFlipInline)),
      ActualFlipsVector(Tactics(TryTactic::kFlipBlock, TryTactic::kFlipStart)));
}

TEST_F(TryValueFlipsTest, FlipStartBlockInline) {
  EXPECT_EQ(
      ExpectedFlipsVector(ExpectedFlips{
          .inset_block_start = CSSPropertyID::kInsetInlineEnd,
          .inset_block_end = CSSPropertyID::kInsetInlineStart,
          .inset_inline_start = CSSPropertyID::kInsetBlockEnd,
          .inset_inline_end = CSSPropertyID::kInsetBlockStart,
          .margin_block_start = CSSPropertyID::kMarginInlineEnd,
          .margin_block_end = CSSPropertyID::kMarginInlineStart,
          .margin_inline_start = CSSPropertyID::kMarginBlockEnd,
          .margin_inline_end = CSSPropertyID::kMarginBlockStart,
          // Flipped alignment:
          .align_self = CSSPropertyID::kJustifySelf,
          .justify_self = CSSPropertyID::kAlignSelf,
          // Flipped sizing:
          .block_size = CSSPropertyID::kInlineSize,
          .inline_size = CSSPropertyID::kBlockSize,
          .min_block_size = CSSPropertyID::kMinInlineSize,
          .min_inline_size = CSSPropertyID::kMinBlockSize,
          .max_block_size = CSSPropertyID::kMaxInlineSize,
          .max_inline_size = CSSPropertyID::kMaxBlockSize,
      }),
      ActualFlipsVector(Tactics(TryTactic::kFlipStart, TryTactic::kFlipBlock,
                                TryTactic::kFlipInline)));
}

TEST_F(TryValueFlipsTest, FlipStartInlineBlock) {
  EXPECT_EQ(
      ActualFlipsVector(Tactics(TryTactic::kFlipStart, TryTactic::kFlipBlock,
                                TryTactic::kFlipInline)),
      ActualFlipsVector(Tactics(TryTactic::kFlipStart, TryTactic::kFlipInline,
                                TryTactic::kFlipBlock)));
}

TEST_F(TryValueFlipsTest, FlipInlineBlockStart) {
  EXPECT_EQ(
      ActualFlipsVector(Tactics(TryTactic::kFlipStart, TryTactic::kFlipBlock,
                                TryTactic::kFlipInline)),
      ActualFlipsVector(Tactics(TryTactic::kFlipInline, TryTactic::kFlipBlock,
                                TryTactic::kFlipStart)));
}

TEST_F(TryValueFlipsTest, FlipBlockInlineStart) {
  EXPECT_EQ(
      ActualFlipsVector(Tactics(TryTactic::kFlipStart, TryTactic::kFlipBlock,
                                TryTactic::kFlipInline)),
      ActualFlipsVector(Tactics(TryTactic::kFlipBlock, TryTactic::kFlipInline,
                                TryTactic::kFlipStart)));
}

namespace {

struct Declaration {
  STACK_ALLOCATED();

 public:
  CSSPropertyID property_id;
  const CSSValue* value;
};

Declaration ParseDeclaration(String string) {
  const CSSPropertyValueSet* set =
      css_test_helpers::ParseDeclarationBlock(string);
  CHECK(set);
  CHECK_EQ(1u, set->PropertyCount());
  CSSPropertyValueSet::PropertyReference ref = set->PropertyAt(0);
  return Declaration{.property_id = ref.Name().Id(), .value = &ref.Value()};
}

}  // namespace

struct FlipValueTestData {
  const char* input;
  const char* expected;
  TryTacticList tactic;
  WritingDirectionMode writing_direction =
      WritingDirectionMode(WritingMode::kHorizontalTb, TextDirection::kLtr);
};

FlipValueTestData flip_value_test_data[] = {
    // clang-format off

    // Possible transforms (from try_tactic_transforms.h):
    //
    // block                  (1)
    // inline                 (2)
    // block inline           (3)
    // start                  (4)
    // block start            (5)
    // inline start           (6)
    // block inline start     (7)

    // Physical anchor():

    // (1)
    {
      .input = "left:anchor(right)",
      .expected = "left:anchor(right)",
      .tactic = Tactics(TryTactic::kFlipBlock)
    },
    {
      .input = "right:anchor(left)",
      .expected = "right:anchor(left)",
      .tactic = Tactics(TryTactic::kFlipBlock)
    },
    {
      .input = "top:anchor(bottom)",
      .expected = "bottom:anchor(top)",
      .tactic = Tactics(TryTactic::kFlipBlock)
    },
    {
      .input = "bottom:anchor(top)",
      .expected = "top:anchor(bottom)",
      .tactic = Tactics(TryTactic::kFlipBlock)
    },

    // (2)
    {
      .input = "left:anchor(right)",
      .expected = "right:anchor(left)",
      .tactic = Tactics(TryTactic::kFlipInline)
    },
    {
      .input = "right:anchor(left)",
      .expected = "left:anchor(right)",
      .tactic = Tactics(TryTactic::kFlipInline)
    },
    {
      .input = "top:anchor(bottom)",
      .expected = "top:anchor(bottom)",
      .tactic = Tactics(TryTactic::kFlipInline)
    },
    {
      .input = "bottom:anchor(top)",
      .expected = "bottom:anchor(top)",
      .tactic = Tactics(TryTactic::kFlipInline)
    },

    // (3)
    {
      .input = "left:anchor(right)",
      .expected = "right:anchor(left)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipInline)
    },
    {
      .input = "right:anchor(left)",
      .expected = "left:anchor(right)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipInline)
    },
    {
      .input = "top:anchor(bottom)",
      .expected = "bottom:anchor(top)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipInline)
    },
    {
      .input = "bottom:anchor(top)",
      .expected = "top:anchor(bottom)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipInline)
    },

    // (4)
    {
      .input = "left:anchor(right)",
      .expected = "top:anchor(bottom)",
      .tactic = Tactics(TryTactic::kFlipStart)
    },
    {
      .input = "right:anchor(left)",
      .expected = "bottom:anchor(top)",
      .tactic = Tactics(TryTactic::kFlipStart)
    },
    {
      .input = "top:anchor(bottom)",
      .expected = "left:anchor(right)",
      .tactic = Tactics(TryTactic::kFlipStart)
    },
    {
      .input = "bottom:anchor(top)",
      .expected = "right:anchor(left)",
      .tactic = Tactics(TryTactic::kFlipStart)
    },

    // (5)
    {
      .input = "left:anchor(right)",
      .expected = "top:anchor(bottom)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipStart)
    },
    {
      .input = "right:anchor(left)",
      .expected = "bottom:anchor(top)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipStart)
    },
    {
      .input = "top:anchor(bottom)",
      .expected = "right:anchor(left)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipStart)
    },
    {
      .input = "bottom:anchor(top)",
      .expected = "left:anchor(right)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipStart)
    },

    // (6)
    {
      .input = "left:anchor(right)",
      .expected = "bottom:anchor(top)",
      .tactic = Tactics(TryTactic::kFlipInline, TryTactic::kFlipStart)
    },
    {
      .input = "right:anchor(left)",
      .expected = "top:anchor(bottom)",
      .tactic = Tactics(TryTactic::kFlipInline, TryTactic::kFlipStart)
    },
    {
      .input = "top:anchor(bottom)",
      .expected = "left:anchor(right)",
      .tactic = Tactics(TryTactic::kFlipInline, TryTactic::kFlipStart)
    },
    {
      .input = "bottom:anchor(top)",
      .expected = "right:anchor(left)",
      .tactic = Tactics(TryTactic::kFlipInline, TryTactic::kFlipStart)
    },

    // (7)
    {
      .input = "left:anchor(right)",
      .expected = "bottom:anchor(top)",
      .tactic = Tactics(TryTactic::kFlipBlock,
                        TryTactic::kFlipInline,
                        TryTactic::kFlipStart)
    },
    {
      .input = "right:anchor(left)",
      .expected = "top:anchor(bottom)",
      .tactic = Tactics(TryTactic::kFlipBlock,
                        TryTactic::kFlipInline,
                        TryTactic::kFlipStart)
    },
    {
      .input = "top:anchor(bottom)",
      .expected = "right:anchor(left)",
      .tactic = Tactics(TryTactic::kFlipBlock,
                        TryTactic::kFlipInline,
                        TryTactic::kFlipStart)
    },
    {
      .input = "bottom:anchor(top)",
      .expected = "left:anchor(right)",
      .tactic = Tactics(TryTactic::kFlipBlock,
                        TryTactic::kFlipInline,
                        TryTactic::kFlipStart)
    },

    // Logical anchor():

    // (1)
    {
      .input = "left:anchor(end)",
      .expected = "left:anchor(end)",
      .tactic = Tactics(TryTactic::kFlipBlock)
    },
    {
      .input = "right:anchor(start)",
      .expected = "right:anchor(start)",
      .tactic = Tactics(TryTactic::kFlipBlock)
    },
    {
      .input = "top:anchor(end)",
      .expected = "bottom:anchor(start)",
      .tactic = Tactics(TryTactic::kFlipBlock)
    },
    {
      .input = "bottom:anchor(start)",
      .expected = "top:anchor(end)",
      .tactic = Tactics(TryTactic::kFlipBlock)
    },

    // (2)
    {
      .input = "left:anchor(end)",
      .expected = "right:anchor(start)",
      .tactic = Tactics(TryTactic::kFlipInline)
    },
    {
      .input = "right:anchor(start)",
      .expected = "left:anchor(end)",
      .tactic = Tactics(TryTactic::kFlipInline)
    },
    {
      .input = "top:anchor(end)",
      .expected = "top:anchor(end)",
      .tactic = Tactics(TryTactic::kFlipInline)
    },
    {
      .input = "bottom:anchor(start)",
      .expected = "bottom:anchor(start)",
      .tactic = Tactics(TryTactic::kFlipInline)
    },

    // (3)
    {
      .input = "left:anchor(end)",
      .expected = "right:anchor(start)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipInline)
    },
    {
      .input = "right:anchor(start)",
      .expected = "left:anchor(end)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipInline)
    },
    {
      .input = "top:anchor(end)",
      .expected = "bottom:anchor(start)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipInline)
    },
    {
      .input = "bottom:anchor(start)",
      .expected = "top:anchor(end)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipInline)
    },

    // (4)
    {
      .input = "left:anchor(end)",
      .expected = "top:anchor(end)",
      .tactic = Tactics(TryTactic::kFlipStart)
    },
    {
      .input = "right:anchor(start)",
      .expected = "bottom:anchor(start)",
      .tactic = Tactics(TryTactic::kFlipStart)
    },
    {
      .input = "top:anchor(end)",
      .expected = "left:anchor(end)",
      .tactic = Tactics(TryTactic::kFlipStart)
    },
    {
      .input = "bottom:anchor(start)",
      .expected = "right:anchor(start)",
      .tactic = Tactics(TryTactic::kFlipStart)
    },

    // (5)
    {
      .input = "left:anchor(end)",
      .expected = "top:anchor(end)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipStart)
    },
    {
      .input = "right:anchor(start)",
      .expected = "bottom:anchor(start)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipStart)
    },
    {
      .input = "top:anchor(end)",
      .expected = "right:anchor(start)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipStart)
    },
    {
      .input = "bottom:anchor(start)",
      .expected = "left:anchor(end)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipStart)
    },

    // (6)
    {
      .input = "left:anchor(end)",
      .expected = "bottom:anchor(start)",
      .tactic = Tactics(TryTactic::kFlipInline, TryTactic::kFlipStart)
    },
    {
      .input = "right:anchor(start)",
      .expected = "top:anchor(end)",
      .tactic = Tactics(TryTactic::kFlipInline, TryTactic::kFlipStart)
    },
    {
      .input = "top:anchor(end)",
      .expected = "left:anchor(end)",
      .tactic = Tactics(TryTactic::kFlipInline, TryTactic::kFlipStart)
    },
    {
      .input = "bottom:anchor(start)",
      .expected = "right:anchor(start)",
      .tactic = Tactics(TryTactic::kFlipInline, TryTactic::kFlipStart)
    },

    // (7)
    {
      .input = "left:anchor(end)",
      .expected = "bottom:anchor(start)",
      .tactic = Tactics(TryTactic::kFlipBlock,
                        TryTactic::kFlipInline,
                        TryTactic::kFlipStart)
    },
    {
      .input = "right:anchor(start)",
      .expected = "top:anchor(end)",
      .tactic = Tactics(TryTactic::kFlipBlock,
                        TryTactic::kFlipInline,
                        TryTactic::kFlipStart)
    },
    {
      .input = "top:anchor(end)",
      .expected = "right:anchor(start)",
      .tactic = Tactics(TryTactic::kFlipBlock,
                        TryTactic::kFlipInline,
                        TryTactic::kFlipStart)
    },
    {
      .input = "bottom:anchor(start)",
      .expected = "left:anchor(end)",
      .tactic = Tactics(TryTactic::kFlipBlock,
                        TryTactic::kFlipInline,
                        TryTactic::kFlipStart)
    },

    // Physical anchor-size()

    // (1)
    {
      .input = "width:anchor-size(width)",
      .expected = "width:anchor-size(width)",
      .tactic = Tactics(TryTactic::kFlipBlock)
    },

    // (2)
    {
      .input = "width:anchor-size(width)",
      .expected = "width:anchor-size(width)",
      .tactic = Tactics(TryTactic::kFlipInline)
    },

    // (3)
    {
      .input = "width:anchor-size(width)",
      .expected = "width:anchor-size(width)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipInline)
    },

    // (4)
    {
      .input = "width:anchor-size(width)",
      .expected = "height:anchor-size(height)",
      .tactic = Tactics(TryTactic::kFlipStart)
    },

    // (5)
    {
      .input = "width:anchor-size(width)",
      .expected = "height:anchor-size(height)",
      .tactic = Tactics(TryTactic::kFlipStart)
    },

    // (6)
    {
      .input = "width:anchor-size(width)",
      .expected = "height:anchor-size(height)",
      .tactic = Tactics(TryTactic::kFlipStart)
    },

    // (7)
    {
      .input = "width:anchor-size(width)",
      .expected = "height:anchor-size(height)",
      .tactic = Tactics(TryTactic::kFlipStart)
    },

    // Logical anchor-size():

    // (1)
    {
      .input = "width:anchor-size(inline)",
      .expected = "width:anchor-size(inline)",
      .tactic = Tactics(TryTactic::kFlipBlock)
    },

    // (2)
    {
      .input = "width:anchor-size(inline)",
      .expected = "width:anchor-size(inline)",
      .tactic = Tactics(TryTactic::kFlipInline)
    },

    // (3)
    {
      .input = "width:anchor-size(inline)",
      .expected = "width:anchor-size(inline)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipInline)
    },

    // (4)
    {
      .input = "width:anchor-size(inline)",
      .expected = "height:anchor-size(block)",
      .tactic = Tactics(TryTactic::kFlipStart)
    },

    // (5)
    {
      .input = "width:anchor-size(inline)",
      .expected = "height:anchor-size(block)",
      .tactic = Tactics(TryTactic::kFlipStart)
    },

    // (6)
    {
      .input = "width:anchor-size(inline)",
      .expected = "height:anchor-size(block)",
      .tactic = Tactics(TryTactic::kFlipStart)
    },

    // (7)
    {
      .input = "width:anchor-size(inline)",
      .expected = "height:anchor-size(block)",
      .tactic = Tactics(TryTactic::kFlipStart)
    },

    // calc() expressions, etc:

    {
      .input = "left:calc(anchor(left) + 10px)",
      .expected = "right:calc(anchor(right) + 10px)",
      .tactic = Tactics(TryTactic::kFlipInline)
    },
    {
      .input = "left:calc(min(anchor(left), anchor(right), 50px) + 10px)",
      .expected = "right:calc(min(anchor(right), anchor(left), 50px) + 10px)",
      .tactic = Tactics(TryTactic::kFlipInline)
    },
    {
      .input = "left:calc(anchor(left, anchor(right)) + 10px)",
      .expected = "right:calc(anchor(right, anchor(left)) + 10px)",
      .tactic = Tactics(TryTactic::kFlipInline)
    },

    // Writing modes:

    {
      .input = "left:anchor(left)",
      .expected = "right:anchor(right)",
      .tactic = Tactics(TryTactic::kFlipInline),
      .writing_direction = WritingDirectionMode(
        WritingMode::kHorizontalTb, TextDirection::kRtl)
    },
    {
      .input = "right:anchor(right)",
      .expected = "left:anchor(left)",
      .tactic = Tactics(TryTactic::kFlipInline),
      .writing_direction = WritingDirectionMode(
        WritingMode::kHorizontalTb, TextDirection::kRtl)
    },
    {
      .input = "left:anchor(left)",
      .expected = "right:anchor(right)",
      .tactic = Tactics(TryTactic::kFlipBlock),
      .writing_direction = WritingDirectionMode(
        WritingMode::kVerticalLr, TextDirection::kLtr)
    },
    {
      .input = "left:anchor(left)",
      .expected = "top:anchor(top)",
      .tactic = Tactics(TryTactic::kFlipBlock, TryTactic::kFlipStart),
      .writing_direction = WritingDirectionMode(
        WritingMode::kVerticalRl, TextDirection::kLtr)
    },

    // clang-format on
};

class FlipValueTest : public PageTestBase,
                      public testing::WithParamInterface<FlipValueTestData> {};

INSTANTIATE_TEST_SUITE_P(TryValueFlipsTest,
                         FlipValueTest,
                         testing::ValuesIn(flip_value_test_data));

TEST_P(FlipValueTest, All) {
  FlipValueTestData param = GetParam();
  Declaration input = ParseDeclaration(String(param.input));
  Declaration expected = ParseDeclaration(String(param.expected));
  TryTacticTransform transform = TryTacticTransform(param.tactic);
  const CSSValue* actual_value = TryValueFlips::FlipValue(
      input.property_id, input.value, transform, param.writing_direction);
  ASSERT_TRUE(actual_value);
  EXPECT_EQ(expected.value->CssText(), actual_value->CssText());
}

struct NoFlipValueTestData {
  const char* input;
  TryTacticList tactic;
  WritingDirectionMode writing_direction =
      WritingDirectionMode(WritingMode::kHorizontalTb, TextDirection::kLtr);
};

// These cases should cause TryValueFlips::FlipValue to return
// the incoming CSSValue instance.
NoFlipValueTestData no_flip_value_test_data[] = {
    // clang-format off

    {
      .input = "left:10px",
      .tactic = Tactics(TryTactic::kNone)
    },
    {
      .input = "left:calc(10px + 20px)",
      .tactic = Tactics(TryTactic::kNone)
    },
    {
      .input = "left:min(10px, 20px)",
      .tactic = Tactics(TryTactic::kNone)
    },
    {
      .input = "left:anchor(left)",
      .tactic = Tactics(TryTactic::kFlipBlock)
    },
    {
      .input = "left:anchor(start)",
      .tactic = Tactics(TryTactic::kFlipBlock)
    },
    {
      .input = "top:anchor(start)",
      .tactic = Tactics(TryTactic::kFlipInline)
    },
    {
      .input = "left:anchor(self-start)",
      .tactic = Tactics(TryTactic::kFlipBlock)
    },
    {
      .input = "top:anchor(self-start)",
      .tactic = Tactics(TryTactic::kFlipInline)
    },
    {
      .input = "left:calc(anchor(left) + 10px)",
      .tactic = Tactics(TryTactic::kFlipBlock)
    },
    {
      .input = "left:calc(anchor(left) + 10px)",
      .tactic = Tactics(TryTactic::kFlipBlock)
    },
    {
      .input = "left:calc(anchor(start) + 10px)",
      .tactic = Tactics(TryTactic::kFlipStart)
    },
    {
      .input = "width:anchor-size(width)",
      .tactic = Tactics(TryTactic::kNone)
    },
    {
      .input = "width:anchor-size(width)",
      .tactic = Tactics(TryTactic::kFlipBlock)
    },
    {
      .input = "width:calc(anchor-size(width) + anchor-size(height))",
      .tactic = Tactics(TryTactic::kFlipInline)
    },

    // clang-format on
};

class NoFlipValueTest
    : public PageTestBase,
      public testing::WithParamInterface<NoFlipValueTestData> {};

INSTANTIATE_TEST_SUITE_P(TryValueFlipsTest,
                         NoFlipValueTest,
                         testing::ValuesIn(no_flip_value_test_data));

TEST_P(NoFlipValueTest, All) {
  NoFlipValueTestData param = GetParam();
  Declaration input = ParseDeclaration(String(param.input));
  TryTacticTransform transform = TryTacticTransform(param.tactic);
  const CSSValue* actual_value = TryValueFlips::FlipValue(
      input.property_id, input.value, transform, param.writing_direction);
  ASSERT_TRUE(actual_value);
  SCOPED_TRACE(testing::Message() << "Actual: " << actual_value->CssText());
  SCOPED_TRACE(testing::Message() << "Expected: " << input.value->CssText());
  EXPECT_EQ(input.value, actual_value);
}

}  // namespace blink

"""

```
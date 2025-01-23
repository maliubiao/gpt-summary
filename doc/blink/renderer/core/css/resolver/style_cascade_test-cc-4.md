Response:
The user is asking for a summary of the functionality of the `style_cascade_test.cc` file, which is part of the Chromium Blink rendering engine. This is the final part of a multi-part request, so I need to synthesize the information from the previous parts (even though I don't have direct access to them) and focus on the functionalities demonstrated in this specific snippet.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The filename `style_cascade_test.cc` immediately suggests that this file contains tests for the CSS style cascading mechanism within Blink. The content of the file confirms this.

2. **Analyze the test structure:** The file uses the Google Test framework (`TEST_F`). Each `TEST_F` function represents a specific test case for a particular aspect of the style cascading logic.

3. **Categorize the test cases:**  By reading through the test names and the code within each test, I can group them by the specific CSS features or cascading behaviors they are testing. The following categories emerge from this snippet:
    * `revert` keyword behavior (specifically with different origins).
    * `FlipRevertSet` (handling logical property mappings when reverting).
    * Inline style precedence.
    * `try-style` and `try-tactics-style` properties.
    * `revert-to` and `revert-layer` with anchor positions.
    * Variables within anchor positions.
    * Edge cases with anchor positions (like invalid flips).
    * `-internal-appearance-auto-base-select` function (used for styling form elements).
    * CSS cycle detection (specifically with `lh` units and custom properties).
    * CSS `@function` functionality.

4. **Explain each category with examples:** For each category, I'll pick a representative test case and explain what it's doing. I should connect these explanations to standard CSS concepts where applicable.

5. **Address the prompt's specific requests:**
    * **Functionality:**  Provide a clear list of the tested functionalities.
    * **Relationship to JavaScript, HTML, CSS:** Explain how the tested features relate to these web technologies. For example, CSS properties are applied to HTML elements and can be manipulated by JavaScript.
    * **Logic and examples:** While the tests themselves are the logic, I can rephrase some of the tests as "if input X, then output Y" scenarios.
    * **User/programming errors:** Think about how users or developers might misuse these features. For instance, misunderstanding the order of precedence with `!important` or creating circular dependencies with custom properties.
    * **User journey:** Explain how a user's actions might lead to this code being executed (e.g., a user interacting with a webpage triggers style recalculations).
    * **Summary:** Since this is the final part, summarize the overall purpose of the file and its contribution to the Blink rendering engine.

6. **Review and refine:**  Ensure the explanations are clear, concise, and accurate. Check for any jargon that might need clarification. Make sure all parts of the prompt have been addressed.

**Self-Correction/Refinement during the process:**

* Initially, I might have just listed the test names. However, the prompt asks for *functionality*, so I need to go deeper and explain *what* each test is testing.
* I considered simply saying "tests CSS features," but the prompt asks for *specific* features, so I need to be more granular.
* I realized that while I don't have access to previous parts, I can infer from this section that the file tests the *cascading* aspect of CSS, not just individual property parsing or computation. The keywords like "revert," "origin," and "layer" are strong indicators.
* I made sure to tie the explanations back to user actions and common web development scenarios to make the information more accessible.

By following these steps, I can generate a comprehensive and helpful answer that addresses all aspects of the user's request.
好的，根据你提供的 `blink/renderer/core/css/resolver/style_cascade_test.cc` 文件代码片段，我们可以归纳一下它在本部分中的功能：

**本部分的功能归纳：**

这部分 `style_cascade_test.cc` 文件主要集中在测试 Blink 引擎中 **CSS 样式层叠解析器 (Style Cascade Resolver)** 的以下功能：

1. **`revert` 关键字的行为:**  测试 `revert` 关键字在不同层叠来源 (origin) 下的表现，验证 `revert` 能否正确回退到用户代理样式或更低优先级的样式。
2. **`FlipRevertSet` 功能:**  重点测试了 `FlipRevertSet` 的逻辑，这是一个用于在样式层叠中处理具有对称关系的属性（如 `left` 和 `right`）在 `revert` 时的行为。测试用例覆盖了：
    * **交换 (Swap):**  `revert` 一个属性会回退到其对称属性的值。
    * **链式 (Chain):**  多个 `FlipRevertSet` 串联的效果。
    * **非对称 (Asymmetric):**  只对一个方向进行 `FlipRevert`，另一个方向不受影响。
    * **不同来源 (Different Origins):** `FlipRevertSet` 在不同层叠来源下的表现。
    * **覆盖 (Overwritten):**  `FlipRevertSet` 的效果被更高优先级的样式覆盖。
3. **内联样式 (Inline Style) 的层叠优先级:**  测试内联样式是否能成功参与层叠并胜出，以及内联样式是否因为 `!important` 规则而失去层叠优势。
4. **`try-style` 和 `try-tactics-style` 属性:**  测试这两个实验性属性的功能，它们允许尝试应用一些样式，但这些样式可以被后续更高优先级的样式覆盖。
5. **`revert-to-anchor` 和 `revert-layer-to-anchor` 功能:**  测试使用 `anchor()` 函数作为 `revert` 或 `revert-layer` 的目标，验证能否正确回退到锚点定义的值。同时测试了锚点定义中包含变量的情况。
6. **`appearance: -internal-appearance-auto-base-select(...)` 函数:**  测试这个内部函数，它用于为 `<select>` 元素等特定控件生成默认样式。测试用例涵盖了：
    * 使用简写属性设置。
    * 在该函数中使用 `revert` 关键字。
    * 在该函数中使用 `env()` 函数。
    * 该函数出现循环引用的情况。
7. **CSS 循环依赖检测:**  测试在自定义属性中使用 `lh` 单位时可能产生的循环依赖，以及使用 `var()` 函数引用这些循环依赖属性时的行为。
8. **CSS `@function` 功能:**  测试 CSS 自定义函数的功能，包括：
    * 简单的函数调用。
    * 带有参数的函数调用。
    * 调用其他函数的函数。
    * 函数返回值类型强制转换。
    * 函数中隐式的 `calc()` 运算。
    * 检测样式是否受到 CSS 函数的影响。
    * 在简写属性中使用不存在的 CSS 函数的情况。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:**  所有测试直接关系到 CSS 的特性和规则，例如 `revert` 关键字、内联样式、`!important` 规则、自定义属性、CSS 函数等。
    * **举例:** `TEST_F(StyleCascadeTest, RevertValue)` 测试了 CSS 的 `revert` 关键字，它允许样式回退到继承值或用户代理样式。
* **HTML:** 测试中会创建简单的 HTML 结构（例如 `<select>` 元素）来应用和测试 CSS 样式。
    * **举例:** `TEST_F(StyleCascadeTest, AppearanceAutoBaseSelectValueShorthand)` 创建了一个 `<select>` 元素来测试特定 `appearance` 值的应用。
* **JavaScript:**  虽然这个测试文件本身是用 C++ 编写的，用于测试 Blink 引擎的核心功能，但这些被测试的 CSS 特性最终会被 JavaScript 通过 DOM API (例如 `element.style`) 进行操作或影响。
    * **假设输入:**  JavaScript 代码设置了元素的内联样式 `element.style.top = '20px'`;  CSS 规则中也设置了 `top: 10px;`.
    * **预期输出:**  根据内联样式优先级更高的规则，解析器应该解析出 `top` 的值为 `20px`。相关的测试用例如 `TEST_F(StyleCascadeTest, InlineStyleWonCascade)` 和 `TEST_F(StyleCascadeTest, InlineStyleLostCascade)` 验证了这种行为。

**逻辑推理的假设输入与输出:**

* **假设输入 (针对 `FlipRevertValue_Swap`):**
    * CSS 规则 1: `left: 1px; right: 2px;`
    * CSS 规则 2: `revert: left;` (应用于 `right` 属性)
    * CSS 规则 3: `revert: right;` (应用于 `left` 属性)
* **预期输出:** `left` 的计算值为 `2px`，`right` 的计算值为 `1px`，因为 `revert` 导致它们互相交换了值。

* **假设输入 (针对 `CSSFunctionWithArgument`):**
    * CSS `@function --foo(--a: length): length { @return calc(arg(--a) * 2); }`
    * CSS 规则: `left: --foo(10px);`
* **预期输出:** `left` 的计算值为 `20px`。

**用户或编程常见的使用错误举例说明:**

* **误解 `revert` 的行为:** 用户可能认为 `revert` 会将样式重置为初始值，但实际上它会回退到上一个层叠层级的值。
    * **举例:**  用户在作者样式中设置了 `color: red;`，然后在后续样式中设置 `color: revert;`，期望颜色变为默认值，但实际上会回退到用户代理样式中可能设置的颜色。
* **`FlipRevertSet` 的错误配置:**  开发者可能错误地配置 `FlipRevertSet`，导致非预期的样式回退行为。
    * **举例:**  只对 `left` 设置了 `FlipRevertSet("left", "right")`，而没有对 `right` 进行反向设置，可能导致只在一个方向上发生回退。
* **CSS 循环依赖:**  在自定义属性中使用循环引用会导致解析错误。
    * **举例:**  `--x: var(--y); --y: var(--x);` 会导致无限循环。`TEST_F(StyleCascadeTest, LhUnitCycle)` 和 `TEST_F(StyleCascadeTest, SubstitutingLhCycles)`  演示了类似的循环依赖场景。
* **CSS 函数的参数类型错误:**  调用 CSS 函数时提供的参数类型与函数定义不符。
    * **举例:**  一个函数定义为接受 `length` 类型的参数，但调用时传入了 `color` 类型的值。

**用户操作是如何一步步的到达这里，作为调试线索:**

当用户在浏览器中访问一个网页时，Blink 引擎会执行以下步骤，其中涉及到样式层叠解析器的运行：

1. **加载 HTML 和 CSS:** 浏览器下载并解析 HTML 结构和相关的 CSS 文件（包括外部样式表、`<style>` 标签内的样式和内联样式）。
2. **构建 DOM 树和 CSSOM 树:**  浏览器将 HTML 解析成 DOM 树，将 CSS 解析成 CSSOM 树。
3. **应用用户代理样式:** 浏览器应用默认的用户代理样式。
4. **计算匹配的 CSS 规则:** 对于 DOM 树中的每个元素，样式系统会查找所有与之匹配的 CSS 规则（包括选择器匹配和媒体查询等）。
5. **构建样式层叠:**  将匹配的规则按照来源（用户代理、用户、作者）、优先级、`!important` 标记等排序，形成样式层叠。
6. **解析层叠值:**  **`style_cascade_test.cc` 测试的就是这一步的关键逻辑。** 样式层叠解析器会遍历层叠，根据 CSS 规范，确定每个 CSS 属性的最终计算值。这包括处理 `revert`、`FlipRevertSet`、内联样式、`try-style`、`anchor()` 函数、CSS 函数等复杂的层叠规则。
7. **样式计算和布局:**  计算出的样式值会被用于布局和渲染网页。

**调试线索:** 如果在样式解析过程中出现问题，例如元素的样式没有按预期应用，开发者可以使用浏览器的开发者工具进行调试：

* **检查元素的计算样式:** 查看元素最终的计算样式，了解哪些 CSS 规则生效，哪些被覆盖。
* **查看样式层叠:**  开发者工具通常会显示样式规则的层叠顺序和来源，帮助理解优先级关系。
* **断点调试 Blink 渲染引擎代码:**  对于 Blink 引擎的开发者，可以在 `blink/renderer/core/css/resolver/style_cascade.cc` 或相关的代码中设置断点，逐步跟踪样式解析的过程，理解 `revert`、`FlipRevertSet`、CSS 函数等是如何被处理的。`style_cascade_test.cc` 中的测试用例可以作为调试特定问题的参考。

总结来说，这部分 `style_cascade_test.cc` 文件专注于测试 Blink 引擎中复杂且重要的 CSS 样式层叠解析逻辑，确保浏览器能够正确地解释和应用各种 CSS 特性和规则，从而正确渲染网页。

### 提示词
```
这是目录为blink/renderer/core/css/resolver/style_cascade_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
hor);

  cascade.AnalyzeIfNeeded();

  CSSValue* revert_value = cssvalue::CSSRevertValue::Create();

  TestCascadeResolver resolver;

  CascadeOrigin origin = CascadeOrigin::kAuthor;
  const CSSValue* resolved_value =
      cascade.Resolve(GetCSSPropertyWidth(), *revert_value, origin);
  ASSERT_TRUE(resolved_value);
  EXPECT_EQ(CascadeOrigin::kUser, origin);
  EXPECT_EQ("2px", resolved_value->CssText());

  origin = CascadeOrigin::kAuthor;
  resolved_value =
      cascade.Resolve(GetCSSPropertyHeight(), *revert_value, origin);
  ASSERT_TRUE(resolved_value);
  EXPECT_EQ(CascadeOrigin::kUserAgent, origin);
  EXPECT_EQ("1px", resolved_value->CssText());

  origin = CascadeOrigin::kAuthor;
  resolved_value =
      cascade.Resolve(GetCSSPropertyDisplay(), *revert_value, origin);
  ASSERT_TRUE(resolved_value);
  EXPECT_EQ(CascadeOrigin::kUserAgent, origin);
  EXPECT_EQ("block", resolved_value->CssText());

  origin = CascadeOrigin::kAuthor;
  resolved_value =
      cascade.Resolve(GetCSSPropertyMarginLeft(), *revert_value, origin);
  ASSERT_TRUE(resolved_value);
  EXPECT_EQ(CascadeOrigin::kNone, origin);
  EXPECT_EQ("unset", resolved_value->CssText());
}

TEST_F(StyleCascadeTest, FlipRevertValue_Swap) {
  TestCascade cascade(GetDocument());

  cascade.Add("left:1px", {.layer_order = 1});
  cascade.Add("right:2px", {.layer_order = 1});
  cascade.Add("top:3px", {.layer_order = 1});
  cascade.Add("bottom:4px", {.layer_order = 1});

  // Revert left to right, and vice-versa.
  cascade.Add(FlipRevertSet("left", "right"), {.layer_order = 2});
  cascade.Add(FlipRevertSet("right", "left"), {.layer_order = 2});
  cascade.Add(FlipRevertSet("top", "bottom"), {.layer_order = 2});
  cascade.Add(FlipRevertSet("bottom", "top"), {.layer_order = 2});

  cascade.Apply();

  EXPECT_EQ("2px", cascade.ComputedValue("left"));
  EXPECT_EQ("1px", cascade.ComputedValue("right"));
  EXPECT_EQ("4px", cascade.ComputedValue("top"));
  EXPECT_EQ("3px", cascade.ComputedValue("bottom"));
}

TEST_F(StyleCascadeTest, FlipRevertValue_Chain) {
  TestCascade cascade(GetDocument());

  cascade.Add("left:1px", {.layer_order = 1});
  cascade.Add("right:2px", {.layer_order = 1});
  cascade.Add("top:3px", {.layer_order = 1});
  cascade.Add("bottom:4px", {.layer_order = 1});

  cascade.Add(FlipRevertSet("right", "left"), {.layer_order = 2});

  cascade.Add(FlipRevertSet("top", "right"), {.layer_order = 3});

  cascade.Add(FlipRevertSet("bottom", "top"), {.layer_order = 4});

  cascade.Apply();

  EXPECT_EQ("1px", cascade.ComputedValue("left"));
  EXPECT_EQ("1px", cascade.ComputedValue("right"));
  EXPECT_EQ("1px", cascade.ComputedValue("top"));
  EXPECT_EQ("1px", cascade.ComputedValue("bottom"));
}

TEST_F(StyleCascadeTest, FlipRevertValue_Asymmetric) {
  TestCascade cascade(GetDocument());

  cascade.Add("left:1px", {.layer_order = 1});
  cascade.Add("right:2px", {.layer_order = 1});
  cascade.Add("top:3px", {.layer_order = 1});
  cascade.Add("bottom:4px", {.layer_order = 1});

  // Revert left to right, but not vice-versa.
  cascade.Add(FlipRevertSet("left", "right"), {.layer_order = 2});
  cascade.Add(FlipRevertSet("top", "bottom"), {.layer_order = 2});

  cascade.Apply();

  EXPECT_EQ("2px", cascade.ComputedValue("left"));
  EXPECT_EQ("2px", cascade.ComputedValue("right"));
  EXPECT_EQ("4px", cascade.ComputedValue("top"));
  EXPECT_EQ("4px", cascade.ComputedValue("bottom"));
}

TEST_F(StyleCascadeTest, FlipRevertValue_DifferentOrigins) {
  TestCascade cascade(GetDocument());

  cascade.Add("left:10px", {.origin = CascadeOrigin::kUser});

  // CascadeOrigin::kAuthor
  cascade.Add("right:2px", {.layer_order = 1});
  cascade.Add("top:3px", {.layer_order = 1});
  cascade.Add("bottom:4px", {.layer_order = 1});

  cascade.Add(FlipRevertSet("right", "left"), {.layer_order = 2});
  cascade.Add(FlipRevertSet("bottom", "top"), {.layer_order = 2});

  cascade.Apply();

  EXPECT_EQ("10px", cascade.ComputedValue("left"));
  EXPECT_EQ("10px", cascade.ComputedValue("right"));
  EXPECT_EQ("3px", cascade.ComputedValue("top"));
  EXPECT_EQ("3px", cascade.ComputedValue("bottom"));
}

TEST_F(StyleCascadeTest, FlipRevertValue_Overwritten) {
  TestCascade cascade(GetDocument());

  cascade.Add("left:1px", {.layer_order = 1});
  cascade.Add("right:2px", {.layer_order = 1});
  cascade.Add("top:3px", {.layer_order = 1});
  cascade.Add("bottom:4px", {.layer_order = 1});

  cascade.Add(FlipRevertSet("left", "right"), {.layer_order = 2});
  cascade.Add(FlipRevertSet("right", "left"), {.layer_order = 2});
  cascade.Add(FlipRevertSet("top", "bottom"), {.layer_order = 2});
  cascade.Add(FlipRevertSet("bottom", "top"), {.layer_order = 2});

  // Overwrite the CSSFlipRevertValues for left/top.
  cascade.Add("left:10px", {.layer_order = 3});
  cascade.Add("top:30px", {.layer_order = 3});

  cascade.Apply();

  EXPECT_EQ("10px", cascade.ComputedValue("left"));
  EXPECT_EQ("1px", cascade.ComputedValue("right"));
  EXPECT_EQ("30px", cascade.ComputedValue("top"));
  EXPECT_EQ("3px", cascade.ComputedValue("bottom"));
}

TEST_F(StyleCascadeTest, InlineStyleWonCascade) {
  TestCascade cascade(GetDocument());
  cascade.Add("top:1px", CascadeOrigin::kUserAgent);
  cascade.Add("top:2px",
              {.origin = CascadeOrigin::kAuthor, .is_inline_style = true});
  cascade.Apply();
  EXPECT_FALSE(cascade.InlineStyleLostCascade());
}

TEST_F(StyleCascadeTest, InlineStyleLostCascade) {
  TestCascade cascade(GetDocument());
  cascade.Add("top:1px !important", {.origin = CascadeOrigin::kUserAgent});
  cascade.Add("top:2px",
              {.origin = CascadeOrigin::kAuthor, .is_inline_style = true});
  cascade.Apply();
  EXPECT_TRUE(cascade.InlineStyleLostCascade());
}

TEST_F(StyleCascadeTest, TryStyle) {
  TestCascade cascade(GetDocument());
  cascade.Add("position:absolute");
  cascade.Add("top:1px");
  cascade.Add("top:2px", {.is_inline_style = true});
  cascade.Add("top:3px", {.is_try_style = true});
  cascade.Apply();
  EXPECT_EQ("3px", cascade.ComputedValue("top"));
}

TEST_F(StyleCascadeTest, TryTacticsStyle) {
  TestCascade cascade(GetDocument());
  cascade.Add("position:absolute");
  cascade.Add("top:1px");
  cascade.Add("top:2px", {.is_try_style = true});
  cascade.Add("top:3px", {.is_try_tactics_style = true});
  cascade.Apply();
  EXPECT_EQ("3px", cascade.ComputedValue("top"));
}

TEST_F(StyleCascadeTest, TryTacticsStyleRevertLayer) {
  TestCascade cascade(GetDocument());
  cascade.Add("position:absolute");
  cascade.Add("top:1px");
  cascade.Add("top:2px", {.is_try_style = true});
  cascade.Add("top:revert-layer", {.is_try_tactics_style = true});
  cascade.Apply();
  EXPECT_EQ("2px", cascade.ComputedValue("top"));
}

TEST_F(StyleCascadeTest, TryTacticsStyleRevertTo) {
  TestCascade cascade(GetDocument());
  cascade.Add("position:absolute");
  cascade.Add("top:1px");
  cascade.Add("top:2px", {.is_try_style = true});
  cascade.Add("bottom:3px", {.is_try_style = true});
  cascade.Add(FlipRevertSet("bottom", "top"), {.is_try_tactics_style = true});
  cascade.Add(FlipRevertSet("top", "bottom"), {.is_try_tactics_style = true});
  cascade.Apply();
  EXPECT_EQ("3px", cascade.ComputedValue("top"));
  EXPECT_EQ("2px", cascade.ComputedValue("bottom"));
}

TEST_F(StyleCascadeTest, RevertToAnchor) {
  TestCascade cascade(GetDocument());
  cascade.Add("top:anchor(top, 10px)", {.origin = CascadeOrigin::kUser});
  cascade.Add("top:revert");
  cascade.Apply();
  EXPECT_EQ("10px", cascade.ComputedValue("top"));
}

TEST_F(StyleCascadeTest, RevertToAnchorInvalid) {
  TestCascade cascade(GetDocument());
  cascade.Add("top:anchor(top)", {.origin = CascadeOrigin::kUser});
  cascade.Add("top:revert");
  cascade.Apply();
  EXPECT_EQ("auto", cascade.ComputedValue("top"));
}

TEST_F(StyleCascadeTest, RevertLayerToAnchor) {
  TestCascade cascade(GetDocument());
  cascade.Add("top:anchor(top, 10px)", {.layer_order = 1});
  cascade.Add("top:revert-layer", {.layer_order = 2});
  cascade.Apply();
  EXPECT_EQ("10px", cascade.ComputedValue("top"));
}

TEST_F(StyleCascadeTest, RevertLayerToAnchorInvalid) {
  TestCascade cascade(GetDocument());
  cascade.Add("top:anchor(top)", {.layer_order = 1});
  cascade.Add("top:revert-layer", {.layer_order = 2});
  cascade.Apply();
  EXPECT_EQ("auto", cascade.ComputedValue("top"));
}

TEST_F(StyleCascadeTest, VarInAnchor) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x:top");
  cascade.Add("top:anchor(var(--x), 10px)");
  cascade.Apply();
  EXPECT_EQ("10px", cascade.ComputedValue("top"));
}

TEST_F(StyleCascadeTest, VarInAnchorInvalid) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x:top");
  cascade.Add("top:anchor(var(--x))");
  cascade.Apply();
  EXPECT_EQ("auto", cascade.ComputedValue("top"));
}

TEST_F(StyleCascadeTest, RevertToVarAnchor) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x:top", {.origin = CascadeOrigin::kUser});
  cascade.Add("top:anchor(var(--x), 10px)", {.origin = CascadeOrigin::kUser});
  cascade.Add("top:revert");
  cascade.Apply();
  EXPECT_EQ("10px", cascade.ComputedValue("top"));
}

TEST_F(StyleCascadeTest, RevertToVarAnchorInvalid) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x:top", {.origin = CascadeOrigin::kUser});
  cascade.Add("top:anchor(var(--x))", {.origin = CascadeOrigin::kUser});
  cascade.Add("top:revert");
  cascade.Apply();
  EXPECT_EQ("auto", cascade.ComputedValue("top"));
}

namespace {

// An AnchorEvaluator that responds to Mode::kTop only. This can be used to
// test what happens when a flip converts a top (valid) into a bottom
// (invalid).
class TopAnchorEvaluator : public AnchorEvaluator {
  STACK_ALLOCATED();

 public:
  std::optional<LayoutUnit> Evaluate(
      const AnchorQuery&,
      const ScopedCSSName* position_anchor,
      const std::optional<PositionAreaOffsets>&) override {
    if (GetMode() == Mode::kTop) {
      return LayoutUnit(1);
    }
    return std::nullopt;
  }
  std::optional<PositionAreaOffsets> ComputePositionAreaOffsetsForLayout(
      const ScopedCSSName*,
      PositionArea) override {
    return PositionAreaOffsets();
  }
  std::optional<PhysicalOffset> ComputeAnchorCenterOffsets(
      const ComputedStyleBuilder&) override {
    return std::nullopt;
  }
};

}  // namespace

TEST_F(StyleCascadeTest, FlipToAnchorInvalid) {
  TopAnchorEvaluator evaluator;
  StyleRecalcContext style_recalc_context;
  style_recalc_context.anchor_evaluator = &evaluator;

  TestCascade cascade(GetDocument(), /* element */ GetDocument().body(),
                      &style_recalc_context);
  cascade.Add("position:absolute");
  cascade.Add("top:anchor(top)");
  cascade.Add(FlipRevertSet("bottom", "top"), {.is_try_tactics_style = true});
  cascade.Add(FlipRevertSet("top", "bottom"), {.is_try_tactics_style = true});
  cascade.Apply();
  // Do not crash:
  EXPECT_EQ("auto", cascade.ComputedValue("top"));
  EXPECT_EQ("auto", cascade.ComputedValue("bottom"));
}

TEST_F(StyleCascadeTest, AppearanceAutoBaseSelectValueShorthand) {
  SetBodyInnerHTML("<select id=select></select>");
  Element* select = GetDocument().getElementById(AtomicString("select"));
  ASSERT_TRUE(select);

  const CSSPropertyValueSet* set = css_test_helpers::ParseDeclarationBlock(
      R"CSS(
      border:-internal-appearance-auto-base-select(1px solid green, 1px solid red);
    )CSS",
      kUASheetMode);

  TestCascade cascade(GetDocument(), select);
  cascade.Add(set);
  cascade.Apply();
  EXPECT_EQ("1px", cascade.ComputedValue("border-left-width"));
  EXPECT_EQ("solid", cascade.ComputedValue("border-left-style"));
  EXPECT_EQ("rgb(0, 128, 0)", cascade.ComputedValue("border-left-color"));
}

TEST_F(StyleCascadeTest, RevertInAppearanceAutoBaseSelectValue) {
  SetBodyInnerHTML("<select id=select></select>");
  Element* select = GetDocument().getElementById(AtomicString("select"));
  ASSERT_TRUE(select);

  const CSSPropertyValueSet* set = css_test_helpers::ParseDeclarationBlock(
      R"CSS(
      left:-internal-appearance-auto-base-select(revert, 2px);
    )CSS",
      kUASheetMode);

  TestCascade cascade(GetDocument(), select);
  cascade.Add("left:300px", {.origin = CascadeOrigin::kUser});
  cascade.Add(set);
  cascade.Apply();
  EXPECT_EQ("300px", cascade.ComputedValue("left"));
}

TEST_F(StyleCascadeTest, EnvInAppearanceAutoBaseSelectValue) {
  SetBodyInnerHTML("<select id=select></select>");
  Element* select = GetDocument().getElementById(AtomicString("select"));
  ASSERT_TRUE(select);

  // UA styles don't use var(), but they could conceivably use env().
  const CSSPropertyValueSet* set = css_test_helpers::ParseDeclarationBlock(
      R"CSS(
      border-left-style: solid;
      border-left-width: -internal-appearance-auto-base-select(env(unknown, 7px), 42px);
    )CSS",
      kUASheetMode);

  TestCascade cascade(GetDocument(), select);
  cascade.Add(set);
  cascade.Apply();
  EXPECT_EQ("7px", cascade.ComputedValue("border-left-width"));
}

TEST_F(StyleCascadeTest, AppearanceAutoBaseSelectCycle) {
  SetBodyInnerHTML("<select id=select></select>");
  Element* select = GetDocument().getElementById(AtomicString("select"));
  ASSERT_TRUE(select);

  const CSSPropertyValueSet* set = css_test_helpers::ParseDeclarationBlock(
      R"CSS(
      appearance:-internal-appearance-auto-base-select(auto, auto);
    )CSS",
      kUASheetMode);

  TestCascade cascade(GetDocument(), select);
  cascade.Add(set);
  cascade.Apply();
  EXPECT_EQ("none", cascade.ComputedValue("appearance"));
}

TEST_F(StyleCascadeTest, LhUnitCycle) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("line-height", "var(--x)");
  cascade.Add("--x", "10lh");
  cascade.Apply();

  EXPECT_EQ("0px", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, SubstitutingLhCycles) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("line-height", "var(--x)");
  cascade.Add("--x", "10lh");
  cascade.Add("--y", "var(--x)");
  cascade.Add("--z", "var(--x,1px)");
  cascade.Apply();

  EXPECT_EQ("0px", cascade.ComputedValue("--y"));
  EXPECT_EQ("0px", cascade.ComputedValue("--z"));
}

TEST_F(StyleCascadeTest, CSSFunctionTrivial) {
  AppendSheet(R"HTML(
     @function --foo(): color {
       @return red;
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("background-color", "--foo()");
  cascade.Apply();

  EXPECT_EQ("rgb(255, 0, 0)", cascade.ComputedValue("background-color"));
}

TEST_F(StyleCascadeTest, CSSFunctionWithArgument) {
  AppendSheet(R"HTML(
     @function --foo(--a: length): length {
       @return calc(arg(--a) * 2);
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("left", "--foo(10.00px)");
  cascade.Apply();

  EXPECT_EQ("20px", cascade.ComputedValue("left"));
}

TEST_F(StyleCascadeTest, CSSFunctionWithTwoArguments) {
  AppendSheet(R"HTML(
     @function --foo(--a: integer, --b: integer): integer {
       @return calc(arg(--a) * arg(--b));
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("z-index", "--foo(4, 6)");
  cascade.Apply();

  EXPECT_EQ("24", cascade.ComputedValue("z-index"));
}

TEST_F(StyleCascadeTest, CSSFunctionCallingOtherFunction) {
  AppendSheet(R"HTML(
     @function --foo(--a: length): length {
       @return calc(arg(--a) * 2);
     }
     @function --bar(--b: length): length {
       @return calc(--foo(arg(--b)) * 3);
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("left", "--bar(10.00px)");
  cascade.Apply();

  EXPECT_EQ("60px", cascade.ComputedValue("left"));
}

TEST_F(StyleCascadeTest, CSSFunctionReturnTypeCoercion) {
  AppendSheet(R"HTML(
     @function --returning-any(): any {
       @return var(--v);
     }
     @function --returning-length(): length {
       @return var(--v);
     }
     @function --returning-color(): color {
       @return var(--v);
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("--v", "10.00px");
  cascade.Add("--any", "--returning-any()");
  cascade.Add("--length", "--returning-length()");
  cascade.Add("--color", "--returning-color()");
  cascade.Apply();

  EXPECT_EQ("10.00px", cascade.ComputedValue("--any"));
  EXPECT_EQ("10px", cascade.ComputedValue("--length"));
  EXPECT_EQ(nullptr, cascade.ComputedValue("--color"));
}

TEST_F(StyleCascadeTest, CSSFunctionImplicitCalc) {
  AppendSheet(R"HTML(
     @function --foo(--x: number): number {
       @return arg(--x) * 2;
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("--result", "--foo(4 + 5)");
  cascade.Apply();

  EXPECT_EQ("18", cascade.ComputedValue("--result"));
}

TEST_F(StyleCascadeTest, AffectedByCSSFunction) {
  AppendSheet(R"HTML(
     @function --red(): color {
       @return red;
     }
    )HTML");

  {
    TestCascade cascade(GetDocument());
    cascade.Add("color", "--red()");
    cascade.Apply();
    EXPECT_EQ("rgb(255, 0, 0)", cascade.ComputedValue("color"));
    EXPECT_TRUE(cascade.TakeStyle()->AffectedByCSSFunction());
  }
  {
    TestCascade cascade(GetDocument());
    cascade.Add("color", "red");
    cascade.Apply();
    EXPECT_EQ("rgb(255, 0, 0)", cascade.ComputedValue("color"));
    EXPECT_FALSE(cascade.TakeStyle()->AffectedByCSSFunction());
  }
}

TEST_F(StyleCascadeTest, CSSFunctionDoesNotExistInShorthand) {
  for (bool enabled : {false, true}) {
    ScopedCSSFunctionsForTest scoped_feature(enabled);
    TestCascade cascade(GetDocument());

    cascade.Add("background", "--nonexistent()");
    cascade.Apply();

    EXPECT_EQ("rgba(0, 0, 0, 0)", cascade.ComputedValue("background-color"));
  }
}

}  // namespace blink
```
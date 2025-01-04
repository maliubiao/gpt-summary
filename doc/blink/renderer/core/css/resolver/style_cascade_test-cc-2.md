Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The primary goal is to analyze the provided C++ code snippet from `style_cascade_test.cc` and explain its functionality, especially its relationship to web technologies (HTML, CSS, JavaScript), provide examples, discuss potential user/programming errors, and relate it to a debugging scenario. Finally, I need to summarize the functionality of this specific section.

2. **High-Level Analysis of the Code:** I first scan the code for keywords and patterns. I see `TEST_F`, `EXPECT_EQ`, `cascade.Add`, `cascade.Apply`, `ComputedValue`. These clearly indicate this is a unit testing file. The tests are focused on `StyleCascade`, which strongly suggests it's testing how CSS styles are applied and resolved in the browser engine.

3. **Identify Key Concepts:** The tests revolve around these CSS concepts:
    * **Custom Properties (CSS Variables):** `--x`, `--y`, `var(--x)`.
    * **`initial`, `inherit`, `unset`:** Keywords for resetting or inheriting property values.
    * **Animation:** `@keyframes`, `animation-name`, `animation-duration`, `animation-delay`, `AnimationTaintedSet`.
    * **Transitions:** `transition`.
    * **`env()` function:**  Accessing environment variables.
    * **Cascade Order/Specificity:**  How different style origins (author, user-agent, animation, transition) interact.
    * **Logical Properties:** `margin-inline-start`.
    * **Shorthand Properties:** `margin`.
    * **Visited Links:** `:visited`.
    * **`zoom` property.**
    * **`writing-mode` and `-webkit-writing-mode`.**
    * **`ruby-position` and `-webkit-ruby-position`.**
    * **`text-orientation` and `-webkit-text-orientation`.**
    * **`-webkit-border-image` and its longhand properties.**
    * **`-webkit-perspective-origin` and `perspective-origin`.**

4. **Analyze Individual Test Cases:** I go through each `TEST_F` function, understanding its specific purpose:

    * **`RegisteredCustomProperty*`:** Tests how custom properties behave with `initial`, `inherit`, and `unset`.
    * **`SubstituteAnimationTainted*`:**  Focuses on how values changed by animations are handled, especially when used in other properties. "Tainted" likely means the value is currently being animated.
    * **`Env*`:** Tests the `env()` function, including fallbacks and nested variables.
    * **`*ApplyFilter`:** Checks if applying a filter (e.g., only inherited properties) works correctly during animations and transitions.
    * **`PendingKeyframeAnimation*`:** Verifies that keyframe animations are correctly registered and applied.
    * **`TransitionCausesInterpolationValue`:**  Tests if a transition starts when a property value changes.
    * **`TransitionDetectedForChangedFontSize`:**  Checks if changes in related properties (like `font-size` affecting `em` units) trigger transitions.
    * **`AnimatingVarReferences`:**  Confirms that CSS variables can be animated.
    * **`Animate*Property`:** Tests animating standard and logical CSS properties.
    * **`AuthorImportantWinOverAnimations`:**  Verifies the CSS cascade order when `!important` is involved.
    * **`TransitionsWinOverAuthorImportant`:** Checks the priority of transitions over `!important` styles.
    * **`EmRespondsToAnimatedFontSize`:**  Ensures that relative units like `em` update correctly during font-size animations.
    * **`AnimateStandardShorthand`:** Tests animating shorthand properties.
    * **`AnimatedVisited*`:**  Focuses on how animations interact with the `:visited` pseudo-class.
    * **`AnimatePendingSubstitutionValue`:**  Similar to `AnimatingVarReferences`.
    * **`Zoom*`:** Tests the behavior and cascade order of the `zoom` property.
    * **`WritingMode*`, `RubyPosition*`, `TextOrientation*`:** Test the cascade order and priority of prefixed and unprefixed versions of these properties.
    * **`WebkitBorderImage*`:**  Examines the interaction between the `-webkit-border-image` shorthand and its longhand properties.
    * **`WebkitPerspectiveOrigin*`:** Tests the cascade of `-webkit-perspective-origin-x`, `-webkit-perspective-origin-y`, and `perspective-origin`.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**

    * **CSS:** The entire file is about CSS style resolution. I point out how the tests directly relate to CSS features like variables, inheritance, animation, transitions, and specific properties.
    * **HTML:** The styles are applied to HTML elements (implicitly in the test setup). I mention how CSS styles the visual presentation of HTML.
    * **JavaScript:** While the tests are in C++, I explain how JavaScript can dynamically manipulate CSS styles, and how these tests ensure that the style changes are resolved correctly.

6. **Provide Examples:** For each major concept, I construct simple, illustrative HTML/CSS examples to make the functionality clearer. This helps connect the C++ test code to practical web development.

7. **Consider Logic and Assumptions:** The tests make assumptions about the input CSS and verify the expected output (computed styles). I outline these assumptions and the expected outcomes.

8. **Think About User/Programming Errors:** I consider common mistakes developers might make when using the tested CSS features (e.g., incorrect variable names, misunderstanding cascade order, forgetting vendor prefixes).

9. **Construct a Debugging Scenario:** I create a step-by-step scenario where a developer might encounter issues related to the code being tested. This demonstrates the practical relevance of these unit tests.

10. **Summarize the Functionality:** Finally, I synthesize the information gathered into a concise summary of the code's purpose. Since this is part 3 of 5, I focus on the specific features covered in this section (mainly animations, transitions, environment variables, and some prefixed properties).

11. **Refine and Organize:** I review my answer for clarity, accuracy, and organization. I ensure that the examples are easy to understand and that the connections to web technologies are clear. I break down the explanation into logical sections to improve readability.
这是对 Chromium Blink 引擎源代码文件 `blink/renderer/core/css/resolver/style_cascade_test.cc` 的第三部分的功能归纳，基于提供的代码片段，我们可以总结出以下功能：

**核心功能：测试 CSS 样式层叠（Cascade）的解析和计算逻辑，尤其关注以下方面:**

* **CSS 自定义属性 (CSS Variables) 的解析和计算:**
    * 测试自定义属性的声明、赋值和使用 (`var()` 函数)。
    * 测试自定义属性与 `initial`、`inherit` 和 `unset` 关键字的交互。
    * 测试自定义属性的层叠规则，包括来自父元素的继承。
* **动画 (Animations) 对样式层叠的影响:**
    * 测试由动画修改的属性值如何参与样式层叠。
    * 测试动画修改的自定义属性如何影响其他属性。
    * 特别关注 `AnimationTaintedSet` 的使用，这可能表示动画正在修改属性值。
    * 测试动画在不同属性（包括标准属性和自定义属性）中的应用。
    * 测试动画延迟对计算值的影响。
    * 测试动画关键帧对自定义属性的影响。
    * 测试动画值作为其他属性的引用的情况。
    * 测试动画与 `!important` 声明的优先级关系。
    * 测试动画对 `:visited` 伪类的影响。
    * 测试动画对简写属性的影响。
* **过渡 (Transitions) 对样式层叠的影响:**
    * 测试过渡效果如何参与样式层叠。
    * 测试过渡如何与自定义属性配合工作。
    * 测试字体大小变化如何触发过渡。
    * 测试过渡与 `!important` 声明的优先级关系。
* **`env()` 函数 (Environment Variables) 的解析和计算:**
    * 测试 `env()` 函数的基本用法，包括访问已定义和未定义的环境变量。
    * 测试 `env()` 函数的备用值 (fallback) 功能。
    * 测试 `env()` 函数中嵌套 `var()` 函数的情况。
* **样式层叠的过滤 (Cascade Filtering):**
    * 测试在应用样式层叠时，可以根据特定条件（例如是否为继承属性）进行过滤。这主要体现在 `AnimationApplyFilter` 和 `TransitionApplyFilter` 这两个测试用例中。
* **特定 CSS 属性的层叠顺序和优先级:**
    * 测试 `zoom` 属性在不同来源和 `!important` 声明下的层叠顺序。
    * 测试 `writing-mode` 及其 `-webkit-` 前缀版本的层叠顺序和优先级。
    * 测试 `ruby-position` 及其 `-webkit-` 前缀版本的层叠顺序。
    * 测试 `text-orientation` 及其 `-webkit-` 前缀版本的层叠顺序和优先级。
    * 测试 `-webkit-border-image` 简写属性及其长属性的层叠顺序。
    * 测试 `-webkit-perspective-origin` 及其长属性 `perspective-origin` 的层叠顺序。

**与 Javascript, HTML, CSS 的关系及举例说明:**

* **CSS:**  该文件是直接测试 CSS 样式解析的核心逻辑。所有的测试用例都在验证 CSS 的各种特性，例如自定义属性、动画、过渡、`env()` 函数以及特定属性的层叠规则。
    * **举例:**  `TEST_F(StyleCascadeTest, RegisteredCustomProperty)` 测试了 CSS 自定义属性的声明和使用，例如在 CSS 中可以写成 `--x: 10px;`，然后在其他地方使用 `var(--x)`。
    * **举例:** `TEST_F(StyleCascadeTest, AnimateStandardProperty)` 测试了 CSS 动画，例如在 CSS 中可以定义 `@keyframes test { from { width: 10px; } to { width: 20px; } }`，然后在元素上应用 `animation: test 10s linear -5s;`。
    * **举例:** `TEST_F(StyleCascadeTest, TransitionCausesInterpolationValue)` 测试了 CSS 过渡，例如在 CSS 中可以写成 `transition: --x 1s;`，当 `--x` 的值改变时会产生过渡效果。
    * **举例:** `TEST_F(StyleCascadeTest, EnvMissingFallback)` 测试了 CSS 的 `env()` 函数，例如在 CSS 中可以写成 `background-color: env(MISSING_ENV_VAR, blue);`，如果 `MISSING_ENV_VAR` 未定义，则使用 `blue` 作为备用值。

* **HTML:**  虽然代码中没有直接操作 HTML 元素，但这些测试的目的是确保浏览器引擎能够正确地解析和应用作用于 HTML 元素的 CSS 样式。`GetDocument()` 实际上获取的是一个模拟的文档环境，用于测试样式解析。
    * **举例:**  虽然测试代码没有直接创建 HTML，但可以想象这些测试是为了确保当 HTML 元素应用了包含自定义属性、动画或过渡的 CSS 样式时，浏览器能够正确地计算出最终的样式值。

* **Javascript:**  JavaScript 可以通过 DOM API 修改元素的样式，包括自定义属性、动画和过渡。这些测试保证了当 JavaScript 修改样式时，样式层叠的计算逻辑仍然是正确的。
    * **举例:**  虽然测试代码不是 JavaScript，但可以想象这些测试是为了确保当 JavaScript 使用 `element.style.setProperty('--x', '20px')` 或 `element.style.animation = '...'` 来修改样式时，浏览器引擎能够按照 CSS 规范正确地处理这些修改。

**逻辑推理、假设输入与输出:**

以 `TEST_F(StyleCascadeTest, RegisteredExplicitInitial)` 为例：

* **假设输入:**
    * 注册了一个自定义属性 `--x`，其初始值为 `0px`。
    * 向一个元素的样式层叠中添加了以下声明：
        * `--x: 10px;`
        * `--x: initial;`
        * `--y: var(--x);`
* **逻辑推理:**
    1. 第一个 `--x: 10px;` 会将 `--x` 的值设置为 `10px`。
    2. 第二个 `--x: initial;` 会将 `--x` 的值重置为其注册时的初始值，即 `0px`。
    3. `--y: var(--x);` 会将 `--y` 的值设置为当前 `--x` 的值。
* **预期输出:**
    * `cascade.ComputedValue("--x")` 应该返回 `"0px"`。
    * `cascade.ComputedValue("--y")` 应该返回 `"0px"`。

以 `TEST_F(StyleCascadeTest, AnimateStandardProperty)` 为例：

* **假设输入:**
    * 定义了一个名为 `test` 的关键帧动画，该动画改变 `width` 属性的值从 `10px` 到 `20px`。
    * 向一个元素的样式层叠中添加了应用该动画的声明：
        * `animation-name: test;`
        * `animation-duration: 10s;`
        * `animation-timing-function: linear;`
        * `animation-delay: -5s;`
* **逻辑推理:**
    1. 动画将在 10 秒内线性地改变 `width` 的值。
    2. `animation-delay: -5s;` 表示动画已经进行了一半的时间。
    3. 因此，在当前时间点，`width` 的值应该是 `10px` 和 `20px` 的中间值。
* **预期输出:**
    * `cascade.ComputedValue("width")` 应该返回 `"15px"`。
    * `cascade.GetOrigin("width")` 应该返回 `CascadeOrigin::kAnimation`，表示该值来源于动画。

**用户或编程常见的使用错误:**

* **自定义属性名称拼写错误:**  例如，在 CSS 中定义了 `--main-color: blue;`，但在其他地方使用了 `var(--mian-color)`，会导致无法获取到正确的值。测试用例如 `TEST_F(StyleCascadeTest, EnvMissingNestedVarFallback)` 间接测试了这种场景，当引用的变量不存在时，会使用回退值。
* **对 `initial`, `inherit`, `unset` 的理解错误:**  不清楚这三个关键字在不同上下文中的作用，可能导致样式未按预期重置或继承。测试用例如 `TEST_F(StyleCascadeTest, RegisteredExplicitInitial)`、`TEST_F(StyleCascadeTest, RegisteredExplicitInherit)` 和 `TEST_F(StyleCascadeTest, RegisteredExplicitUnset)` 验证了这些关键字的行为。
* **动画和过渡属性的冲突或覆盖:**  不清楚动画和过渡的优先级规则，可能导致预期的动画或过渡效果没有生效。测试用例如 `TEST_F(StyleCascadeTest, AuthorImportantWinOverAnimations)` 和 `TEST_F(StyleCascadeTest, TransitionsWinOverAuthorImportant)` 验证了这些优先级规则。
* **`env()` 函数使用错误:**  忘记提供备用值，或者错误地假设环境变量一定存在。测试用例如 `TEST_F(StyleCascadeTest, EnvMissingNestedVar)` 和 `TEST_F(StyleCascadeTest, EnvMissingFallback)` 演示了 `env()` 函数在缺少环境变量时的行为。
* **浏览器前缀的使用不当:**  混淆带前缀的属性和无前缀的属性，或者没有考虑不同浏览器的兼容性问题。测试用例如 `TEST_F(StyleCascadeTest, WritingModeCascadeOrder)` 和 `TEST_F(StyleCascadeTest, RubyPositionSurrogateCanCascadeAsOriginal)` 强调了处理浏览器前缀时的层叠规则。

**用户操作如何一步步的到达这里，作为调试线索:**

假设用户在网页上遇到了一个与 CSS 动画相关的样式问题，例如一个元素的宽度在动画过程中没有按照预期变化。作为开发者，在调试时可能会采取以下步骤，最终可能指向 `style_cascade_test.cc`：

1. **检查 CSS 样式表:**  查看应用到该元素的 CSS 规则，确认是否存在定义动画的 `animation-*` 属性，以及 `width` 属性的初始值和动画中的目标值。
2. **使用开发者工具检查计算后的样式:**  在浏览器开发者工具的 "Elements" 面板中，查看该元素 "Computed" 标签下的 `width` 属性值，以及它来自哪个 CSS 规则。这可以帮助确定是否有其他规则覆盖了动画效果。
3. **检查动画是否正在运行:**  在开发者工具的 "Animations" 面板中，查看是否有与该元素相关的动画正在运行，以及动画的状态（是否暂停、已进行的时间等）。
4. **逐步禁用 CSS 规则:**  在开发者工具中，逐个禁用可能影响该元素的 CSS 规则，以确定是否有其他规则干扰了动画效果。
5. **修改 CSS 属性进行测试:**  在开发者工具中，直接修改元素的 `width` 属性或相关的动画属性，观察变化，以排除简单的 CSS 语法错误或值错误。
6. **如果问题复杂，怀疑是浏览器引擎的样式计算问题:**  如果以上步骤都无法解决问题，开发者可能会怀疑是浏览器引擎在处理样式层叠或动画计算时出现了错误。这时，开发者可能会查阅浏览器引擎的源代码，或者搜索相关的 bug 报告。
7. **搜索或调试 Blink 引擎源代码:**  如果开发者有 Blink 引擎的源代码，并且怀疑是样式层叠的问题，可能会搜索与 "style cascade" 或 "animation" 相关的代码文件，`style_cascade_test.cc` 就是一个关键的测试文件，可以帮助理解样式层叠的实现逻辑和可能存在的问题。
8. **查看相关的单元测试:**  开发者可能会查看 `style_cascade_test.cc` 中与动画相关的测试用例，例如 `TEST_F(StyleCascadeTest, AnimateStandardProperty)`，来理解 Blink 引擎是如何测试动画效果的，以及是否存在类似的已知问题。

**总结其功能:**

总而言之，提供的代码片段主要测试了 Blink 引擎中 CSS 样式层叠解析器在处理 **自定义属性**、**动画**、**过渡** 和 **`env()` 函数** 以及一些特定 CSS 属性（如 `zoom`、`writing-mode` 等）时的行为和优先级规则。这些测试确保了浏览器能够按照 CSS 规范正确地计算出元素的最终样式，并处理各种复杂的样式组合和交互情况。这是对 CSS 引擎核心功能的细致验证，保证了网页样式的正确渲染。

Prompt: 
```
这是目录为blink/renderer/core/css/resolver/style_cascade_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
de.Add("--y", " var(--x) ");
  cascade.Apply();
  EXPECT_EQ("foo", cascade.ComputedValue("--x"));
  EXPECT_EQ("foo", cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, RegisteredExplicitInitial) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--x", "10px");
  cascade.Apply();
  EXPECT_EQ("10px", cascade.ComputedValue("--x"));

  cascade.Reset();
  cascade.Add("--x", "initial");
  cascade.Add("--y", "var(--x)");
  cascade.Apply();
  EXPECT_EQ("0px", cascade.ComputedValue("--x"));
  EXPECT_EQ("0px", cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, RegisteredExplicitInherit) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  TestCascade parent(GetDocument());
  parent.Add("--x", "15px");
  parent.Apply();
  EXPECT_EQ("15px", parent.ComputedValue("--x"));

  TestCascade cascade(GetDocument(), parent.TakeStyle());
  cascade.Apply();
  EXPECT_EQ("0px", cascade.ComputedValue("--x"));  // Note: inherit==false

  cascade.Reset();
  cascade.Add("--x", "inherit");
  cascade.Add("--y", "var(--x)");
  cascade.Apply();
  EXPECT_EQ("15px", cascade.ComputedValue("--x"));
  EXPECT_EQ("15px", cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, RegisteredExplicitUnset) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);
  RegisterProperty(GetDocument(), "--y", "<length>", "0px", true);

  TestCascade parent(GetDocument());
  parent.Add("--x", "15px");
  parent.Add("--y", "15px");
  parent.Apply();
  EXPECT_EQ("15px", parent.ComputedValue("--x"));
  EXPECT_EQ("15px", parent.ComputedValue("--y"));

  TestCascade cascade(GetDocument(), parent.TakeStyle());
  cascade.Add("--x", "2px");
  cascade.Add("--y", "2px");
  cascade.Apply();
  EXPECT_EQ("2px", cascade.ComputedValue("--x"));
  EXPECT_EQ("2px", cascade.ComputedValue("--y"));

  cascade.Reset();
  cascade.Add("--x", "unset");
  cascade.Add("--y", "unset");
  cascade.Add("--z", "var(--x) var(--y)");
  cascade.Apply();
  EXPECT_EQ("0px", cascade.ComputedValue("--x"));
  EXPECT_EQ("15px", cascade.ComputedValue("--y"));
  EXPECT_EQ("0px 15px", cascade.ComputedValue("--z"));
}

TEST_F(StyleCascadeTest, SubstituteAnimationTaintedInCustomProperty) {
  TestCascade cascade(GetDocument());
  cascade.Add(AnimationTaintedSet("--x", "15px"));
  cascade.Add("--y", "var(--x)");
  cascade.Apply();
  EXPECT_EQ("15px", cascade.ComputedValue("--x"));
  EXPECT_EQ("15px", cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, SubstituteAnimationTaintedInStandardProperty) {
  TestCascade cascade(GetDocument());
  cascade.Add(AnimationTaintedSet("--x", "15px"));
  cascade.Add("width", "var(--x)");
  cascade.Apply();
  EXPECT_EQ("15px", cascade.ComputedValue("--x"));
  EXPECT_EQ("15px", cascade.ComputedValue("width"));
}

TEST_F(StyleCascadeTest, SubstituteAnimationTaintedInAnimationDelay) {
  TestCascade cascade(GetDocument());
  cascade.Add(AnimationTaintedSet("--x", "1s"));
  cascade.Add("animation-delay", "var(--x)");
  cascade.Apply();
  EXPECT_EQ("1s", cascade.ComputedValue("--x"));
  EXPECT_EQ("0s", cascade.ComputedValue("animation-delay"));
}

TEST_F(StyleCascadeTest, SubstituteAnimationTaintedInAnimationProperty) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x", "20s");
  cascade.Add("animation-duration", "var(--x)");
  cascade.Apply();

  EXPECT_EQ("20s", cascade.ComputedValue("--x"));
  EXPECT_EQ("20s", cascade.ComputedValue("animation-duration"));

  cascade.Reset();
  cascade.Add(AnimationTaintedSet("--y", "20s"));
  cascade.Add("animation-duration", "var(--y)");
  cascade.Apply();

  EXPECT_EQ("20s", cascade.ComputedValue("--y"));
  EXPECT_EQ("0s", cascade.ComputedValue("animation-duration"));
}

TEST_F(StyleCascadeTest, IndirectlyAnimationTainted) {
  TestCascade cascade(GetDocument());
  cascade.Add(AnimationTaintedSet("--x", "20s"));
  cascade.Add("--y", "var(--x)");
  cascade.Add("animation-duration", "var(--y)");
  cascade.Apply();

  EXPECT_EQ("20s", cascade.ComputedValue("--x"));
  EXPECT_EQ("20s", cascade.ComputedValue("--y"));
  EXPECT_EQ("0s", cascade.ComputedValue("animation-duration"));
}

TEST_F(StyleCascadeTest, AnimationTaintedFallback) {
  TestCascade cascade(GetDocument());
  cascade.Add(AnimationTaintedSet("--x", "20s"));
  cascade.Add("animation-duration", "var(--x,1s)");
  cascade.Apply();

  EXPECT_EQ("20s", cascade.ComputedValue("--x"));
  EXPECT_EQ("1s", cascade.ComputedValue("animation-duration"));
}

TEST_F(StyleCascadeTest, EnvMissingNestedVar) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x", "rgb(0, 0, 0)");
  cascade.Add("background-color", "env(missing, var(--x))");
  cascade.Apply();

  EXPECT_EQ("rgb(0, 0, 0)", cascade.ComputedValue("--x"));
  EXPECT_EQ("rgb(0, 0, 0)", cascade.ComputedValue("background-color"));
}

TEST_F(StyleCascadeTest, EnvMissingNestedVarFallback) {
  TestCascade cascade(GetDocument());
  cascade.Add("background-color", "env(missing, var(--missing, blue))");
  cascade.Apply();

  EXPECT_EQ("rgb(0, 0, 255)", cascade.ComputedValue("background-color"));
}

TEST_F(StyleCascadeTest, EnvMissingFallback) {
  TestCascade cascade(GetDocument());
  cascade.Add("background-color", "env(missing, blue)");
  cascade.Apply();

  EXPECT_EQ("rgb(0, 0, 255)", cascade.ComputedValue("background-color"));
}

TEST_F(StyleCascadeTest, ValidEnv) {
  AutoEnv env(*this, "test", "red");

  TestCascade cascade(GetDocument());
  cascade.Add("background-color", "env(test, blue)");
  cascade.Apply();

  EXPECT_EQ("rgb(255, 0, 0)", cascade.ComputedValue("background-color"));
}

TEST_F(StyleCascadeTest, ValidEnvFallback) {
  AutoEnv env(*this, "test", "red");

  TestCascade cascade(GetDocument());
  cascade.Add("background-color", "env(test, blue)");
  cascade.Apply();

  EXPECT_EQ("rgb(255, 0, 0)", cascade.ComputedValue("background-color"));
}

TEST_F(StyleCascadeTest, ValidEnvInUnusedFallback) {
  AutoEnv env(*this, "test", "red");

  TestCascade cascade(GetDocument());
  cascade.Add("--x", "rgb(0, 0, 0)");
  cascade.Add("background-color", "var(--x, env(test))");
  cascade.Apply();

  EXPECT_EQ("rgb(0, 0, 0)", cascade.ComputedValue("--x"));
  EXPECT_EQ("rgb(0, 0, 0)", cascade.ComputedValue("background-color"));
}

TEST_F(StyleCascadeTest, ValidEnvInUsedFallback) {
  AutoEnv env(*this, "test", "red");

  TestCascade cascade(GetDocument());
  cascade.Add("background-color", "var(--missing, env(test))");
  cascade.Apply();

  EXPECT_EQ("rgb(255, 0, 0)", cascade.ComputedValue("background-color"));
}

TEST_F(StyleCascadeTest, AnimationApplyFilter) {
  AppendSheet(R"HTML(
     @keyframes test {
        from { color: white; background-color: white; }
        to { color: gray; background-color: gray; }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("animation: test linear 10s -5s");
  cascade.Add("color:green");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply(CascadeFilter(CSSProperty::kInherited, true));

  EXPECT_EQ("rgb(0, 128, 0)", cascade.ComputedValue("color"));
  EXPECT_EQ("rgb(192, 192, 192)", cascade.ComputedValue("background-color"));
}

TEST_F(StyleCascadeTest, TransitionApplyFilter) {
  UpdateAllLifecyclePhasesForTest();

  TestCascade cascade1(GetDocument());
  cascade1.Add("background-color: white");
  cascade1.Add("color: white");
  cascade1.Add("transition: all steps(2, start) 100s");
  cascade1.Apply();

  // Set the old style on the element, so that the transition
  // update detects it.
  GetDocument().body()->SetComputedStyle(cascade1.TakeStyle());

  // Now simulate a new style, with new color values.
  TestCascade cascade2(GetDocument());
  cascade2.Add("background-color: gray");
  cascade2.Add("color: gray");
  cascade2.Add("transition: all steps(2, start) 100s");
  cascade2.Apply();

  cascade2.AddInterpolations();
  cascade2.Apply(CascadeFilter(CSSProperty::kInherited, true));

  EXPECT_EQ("rgb(128, 128, 128)", cascade2.ComputedValue("color"));
  EXPECT_EQ("rgb(192, 192, 192)", cascade2.ComputedValue("background-color"));
}

TEST_F(StyleCascadeTest, PendingKeyframeAnimation) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  AppendSheet(R"HTML(
     @keyframes test {
        from { --x: 10px; }
        to { --x: 20px; }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("animation-name", "test");
  cascade.Add("animation-duration", "1s");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();

  EXPECT_EQ(CascadeOrigin::kAnimation, cascade.GetPriority("--x").GetOrigin());
}

TEST_F(StyleCascadeTest, PendingKeyframeAnimationApply) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  AppendSheet(R"HTML(
     @keyframes test {
        from { --x: 10px; }
        to { --x: 20px; }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("animation-name", "test");
  cascade.Add("animation-duration", "10s");
  cascade.Add("animation-timing-function", "linear");
  cascade.Add("animation-delay", "-5s");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();

  EXPECT_EQ(CascadeOrigin::kAnimation, cascade.GetPriority("--x").GetOrigin());
  EXPECT_EQ("15px", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, TransitionCausesInterpolationValue) {
  UpdateAllLifecyclePhasesForTest();

  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  // First, simulate an "old style".
  TestCascade cascade1(GetDocument());
  cascade1.Add("--x", "10px");
  cascade1.Add("transition", "--x 1s");
  cascade1.Apply();

  // Set the old style on the element, so that the animation
  // update detects it.
  GetDocument().body()->SetComputedStyle(cascade1.TakeStyle());

  // Now simulate a new style, with a new value for --x.
  TestCascade cascade2(GetDocument());
  cascade2.Add("--x", "20px");
  cascade2.Add("transition", "--x 1s");
  cascade2.Apply();

  cascade2.AddInterpolations();
  cascade2.Apply();

  EXPECT_EQ(CascadeOrigin::kTransition,
            cascade2.GetPriority("--x").GetOrigin());
}

TEST_F(StyleCascadeTest, TransitionDetectedForChangedFontSize) {
  UpdateAllLifecyclePhasesForTest();

  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  TestCascade cascade1(GetDocument());
  cascade1.Add("font-size", "10px");
  cascade1.Add("--x", "10em");
  cascade1.Add("width", "10em");
  cascade1.Add("height", "10px");
  cascade1.Add("transition", "--x 1s, width 1s");
  cascade1.Apply();

  GetDocument().body()->SetComputedStyle(cascade1.TakeStyle());

  TestCascade cascade2(GetDocument());
  cascade2.Add("font-size", "20px");
  cascade2.Add("--x", "10em");
  cascade2.Add("width", "10em");
  cascade2.Add("height", "10px");
  cascade2.Add("transition", "--x 1s, width 1s");
  cascade2.Apply();

  cascade2.AddInterpolations();
  cascade2.Apply();

  EXPECT_EQ(CascadeOrigin::kTransition, cascade2.GetOrigin("--x"));
  EXPECT_EQ(CascadeOrigin::kTransition, cascade2.GetOrigin("width"));
  EXPECT_EQ("10px", cascade2.ComputedValue("height"));
}

TEST_F(StyleCascadeTest, AnimatingVarReferences) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  AppendSheet(R"HTML(
     @keyframes test {
        from { --x: var(--from); }
        to { --x: var(--to); }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("animation-name", "test");
  cascade.Add("animation-duration", "10s");
  cascade.Add("animation-timing-function", "linear");
  cascade.Add("animation-delay", "-5s");
  cascade.Add("--from", "10px");
  cascade.Add("--to", "20px");
  cascade.Add("--y", "var(--x)");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();

  EXPECT_EQ("15px", cascade.ComputedValue("--x"));
  EXPECT_EQ("15px", cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, AnimateStandardProperty) {
  AppendSheet(R"HTML(
     @keyframes test {
        from { width: 10px; }
        to { width: 20px; }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("animation-name", "test");
  cascade.Add("animation-duration", "10s");
  cascade.Add("animation-timing-function", "linear");
  cascade.Add("animation-delay", "-5s");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();

  EXPECT_EQ(CascadeOrigin::kAnimation, cascade.GetOrigin("width"));
  EXPECT_EQ("15px", cascade.ComputedValue("width"));
}

TEST_F(StyleCascadeTest, AnimateLogicalProperty) {
  // We don't support smooth interpolation of css-logical properties yet,
  // so this test uses a paused animation at t=0.
  // TODO(crbug.com/865579): Support animations of css-logical properties

  AppendSheet(R"HTML(
     @keyframes test {
        from { margin-inline-start: 10px; }
        to { margin-inline-start: 20px; }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("margin-left:1000px");
  cascade.Add("animation:test 1s linear paused");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();

  EXPECT_EQ(CascadeOrigin::kAnimation, cascade.GetOrigin("margin-left"));
  EXPECT_EQ("10px", cascade.ComputedValue("margin-left"));
}

TEST_F(StyleCascadeTest, AnimateLogicalPropertyWithLookup) {
  // We don't support smooth interpolation of css-logical properties yet,
  // so this test uses a paused animation at t=0.
  // TODO(crbug.com/865579): Support animations of css-logical properties

  AppendSheet(R"HTML(
     @keyframes test {
        from { margin-inline-start: 10px; }
        to { margin-inline-start: 20px; }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("margin-left:1000px");
  cascade.Add("animation:test 1s linear paused");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.ApplySingle(GetCSSPropertyMarginLeft());

  EXPECT_EQ(CascadeOrigin::kAnimation, cascade.GetOrigin("margin-left"));
  EXPECT_EQ("10px", cascade.ComputedValue("margin-left"));
}

TEST_F(StyleCascadeTest, AuthorImportantWinOverAnimations) {
  AppendSheet(R"HTML(
     @keyframes test {
        from { width: 10px; height: 10px; }
        to { width: 20px; height: 20px; }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("animation-name", "test");
  cascade.Add("animation-duration", "10s");
  cascade.Add("animation-timing-function", "linear");
  cascade.Add("animation-delay", "-5s");
  cascade.Add("width:40px");
  cascade.Add("height:40px !important");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();

  EXPECT_EQ(CascadeOrigin::kAnimation, cascade.GetOrigin("width"));
  EXPECT_EQ(CascadeOrigin::kAuthor, cascade.GetOrigin("height"));

  EXPECT_EQ("15px", cascade.ComputedValue("width"));
  EXPECT_EQ("40px", cascade.ComputedValue("height"));
}

TEST_F(StyleCascadeTest, TransitionsWinOverAuthorImportant) {
  UpdateAllLifecyclePhasesForTest();

  // First, simulate an "old style".
  TestCascade cascade1(GetDocument());
  cascade1.Add("width:10px !important");
  cascade1.Add("height:10px !important");
  cascade1.Add("transition:all 1s");
  cascade1.Apply();

  // Set the old style on the element, so that the animation
  // update detects it.
  GetDocument().body()->SetComputedStyle(cascade1.TakeStyle());

  // Now simulate a new style, with a new value for width/height.
  TestCascade cascade2(GetDocument());
  cascade2.Add("width:20px !important");
  cascade2.Add("height:20px !important");
  cascade2.Add("transition:all 1s");
  cascade2.Apply();

  cascade2.AddInterpolations();
  cascade2.Apply();

  EXPECT_EQ(CascadeOrigin::kTransition,
            cascade2.GetPriority("width").GetOrigin());
  EXPECT_EQ(CascadeOrigin::kTransition,
            cascade2.GetPriority("height").GetOrigin());
}

TEST_F(StyleCascadeTest, EmRespondsToAnimatedFontSize) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  AppendSheet(R"HTML(
     @keyframes test {
        from { font-size: 10px; }
        to { font-size: 20px; }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("animation-name", "test");
  cascade.Add("animation-duration", "10s");
  cascade.Add("animation-timing-function", "linear");
  cascade.Add("animation-delay", "-5s");
  cascade.Add("--x", "2em");
  cascade.Add("width", "10em");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();

  EXPECT_EQ("30px", cascade.ComputedValue("--x"));
  EXPECT_EQ("150px", cascade.ComputedValue("width"));
}

TEST_F(StyleCascadeTest, AnimateStandardPropertyWithVar) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  AppendSheet(R"HTML(
     @keyframes test {
        from { width: var(--from); }
        to { width: var(--to); }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("animation-name", "test");
  cascade.Add("animation-duration", "10s");
  cascade.Add("animation-timing-function", "linear");
  cascade.Add("animation-delay", "-5s");
  cascade.Add("--from", "10px");
  cascade.Add("--to", "20px");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();

  EXPECT_EQ("15px", cascade.ComputedValue("width"));
}

TEST_F(StyleCascadeTest, AnimateStandardShorthand) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  AppendSheet(R"HTML(
     @keyframes test {
        from { margin: 10px; }
        to { margin: 20px; }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("animation-name", "test");
  cascade.Add("animation-duration", "10s");
  cascade.Add("animation-timing-function", "linear");
  cascade.Add("animation-delay", "-5s");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();

  EXPECT_EQ(CascadeOrigin::kAnimation, cascade.GetOrigin("margin-top"));
  EXPECT_EQ(CascadeOrigin::kAnimation, cascade.GetOrigin("margin-right"));
  EXPECT_EQ(CascadeOrigin::kAnimation, cascade.GetOrigin("margin-bottom"));
  EXPECT_EQ(CascadeOrigin::kAnimation, cascade.GetOrigin("margin-left"));

  EXPECT_EQ("15px", cascade.ComputedValue("margin-top"));
  EXPECT_EQ("15px", cascade.ComputedValue("margin-right"));
  EXPECT_EQ("15px", cascade.ComputedValue("margin-bottom"));
  EXPECT_EQ("15px", cascade.ComputedValue("margin-left"));
}

TEST_F(StyleCascadeTest, AnimatedVisitedImportantOverride) {
  AppendSheet(R"HTML(
     @keyframes test {
        from { background-color: rgb(100, 100, 100); }
        to { background-color: rgb(200, 200, 200); }
     }
    )HTML");

  TestCascade cascade(GetDocument());
  cascade.State().StyleBuilder().SetInsideLink(EInsideLink::kInsideVisitedLink);

  cascade.Add(ParseDeclarationBlock("background-color:red !important"),
              {.link_match_type = CSSSelector::kMatchVisited});
  cascade.Add("animation-name:test");
  cascade.Add("animation-duration:10s");
  cascade.Add("animation-timing-function:linear");
  cascade.Add("animation-delay:-5s");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();
  EXPECT_EQ("rgb(150, 150, 150)", cascade.ComputedValue("background-color"));

  const auto* style = cascade.TakeStyle();

  ComputedStyleBuilder builder(*style);
  builder.SetInsideLink(EInsideLink::kInsideVisitedLink);
  style = builder.TakeStyle();
  EXPECT_EQ(Color(255, 0, 0),
            style->VisitedDependentColor(GetCSSPropertyBackgroundColor()));

  builder = ComputedStyleBuilder(*style);
  builder.SetInsideLink(EInsideLink::kNotInsideLink);
  style = builder.TakeStyle();
  EXPECT_EQ(Color(150, 150, 150),
            style->VisitedDependentColor(GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleCascadeTest, AnimatedVisitedHighPrio) {
  AppendSheet(R"HTML(
     @keyframes test {
        from { color: rgb(100, 100, 100); }
        to { color: rgb(200, 200, 200); }
     }
    )HTML");

  TestCascade cascade(GetDocument());
  cascade.Add("color:red");
  cascade.Add("animation:test 10s -5s linear");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();
  EXPECT_EQ("rgb(150, 150, 150)", cascade.ComputedValue("color"));

  const auto* style = cascade.TakeStyle();

  ComputedStyleBuilder builder(*style);
  builder.SetInsideLink(EInsideLink::kInsideVisitedLink);
  style = builder.TakeStyle();
  EXPECT_EQ(Color(150, 150, 150),
            style->VisitedDependentColor(GetCSSPropertyColor()));

  builder = ComputedStyleBuilder(*style);
  builder.SetInsideLink(EInsideLink::kNotInsideLink);
  style = builder.TakeStyle();
  EXPECT_EQ(Color(150, 150, 150),
            style->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleCascadeTest, AnimatePendingSubstitutionValue) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  AppendSheet(R"HTML(
     @keyframes test {
        from { margin: var(--from); }
        to { margin: var(--to); }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("animation-name", "test");
  cascade.Add("animation-duration", "10s");
  cascade.Add("animation-timing-function", "linear");
  cascade.Add("animation-delay", "-5s");
  cascade.Add("--from", "10px");
  cascade.Add("--to", "20px");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();

  EXPECT_EQ(CascadeOrigin::kAnimation, cascade.GetOrigin("margin-top"));
  EXPECT_EQ(CascadeOrigin::kAnimation, cascade.GetOrigin("margin-right"));
  EXPECT_EQ(CascadeOrigin::kAnimation, cascade.GetOrigin("margin-bottom"));
  EXPECT_EQ(CascadeOrigin::kAnimation, cascade.GetOrigin("margin-left"));

  EXPECT_EQ("15px", cascade.ComputedValue("margin-top"));
  EXPECT_EQ("15px", cascade.ComputedValue("margin-right"));
  EXPECT_EQ("15px", cascade.ComputedValue("margin-bottom"));
  EXPECT_EQ("15px", cascade.ComputedValue("margin-left"));
}

TEST_F(StyleCascadeTest, ZoomCascadeOrder) {
  TestCascade cascade(GetDocument());
  cascade.Add("zoom:200%", CascadeOrigin::kUserAgent);
  cascade.Add("zoom:normal", CascadeOrigin::kUserAgent);
  cascade.Apply();

  EXPECT_EQ(1.0f, cascade.TakeStyle()->EffectiveZoom());
}

TEST_F(StyleCascadeTest, ZoomVsAll) {
  TestCascade cascade(GetDocument());
  cascade.Add("zoom:200%", CascadeOrigin::kUserAgent);
  cascade.Add("all:initial");
  cascade.Apply();

  EXPECT_EQ(1.0f, cascade.TakeStyle()->EffectiveZoom());
}

TEST_F(StyleCascadeTest, ZoomReversedCascadeOrder) {
  TestCascade cascade(GetDocument());
  cascade.Add("zoom:normal", CascadeOrigin::kUserAgent);
  cascade.Add("zoom:200%", CascadeOrigin::kUserAgent);
  cascade.Apply();

  EXPECT_EQ(2.0f, cascade.TakeStyle()->EffectiveZoom());
}

TEST_F(StyleCascadeTest, ZoomImportant) {
  TestCascade cascade(GetDocument());
  cascade.Add("zoom:200% !important", CascadeOrigin::kUserAgent);
  cascade.Add("zoom:normal", CascadeOrigin::kAuthor);
  cascade.Apply();

  EXPECT_EQ(2.0f, cascade.TakeStyle()->EffectiveZoom());
}

TEST_F(StyleCascadeTest, ZoomExplicitDefault) {
  ScopedStandardizedBrowserZoomForTest scoped_feature(true);

  TestCascade cascade(GetDocument());
  cascade.Add("zoom:200%");
  cascade.Apply();

  // Since the zoom changed, there should be an explicit entry
  // in the cascade map with CascadeOrigin::kNone.
  CascadePriority* priority =
      cascade.FindPriority(CSSPropertyName(CSSPropertyID::kLineHeight));
  ASSERT_TRUE(priority);
  EXPECT_EQ(CascadeOrigin::kNone, priority->GetOrigin());
}

TEST_F(StyleCascadeTest, ZoomNoExplicitDefault) {
  ScopedStandardizedBrowserZoomForTest scoped_feature(true);

  TestCascade cascade(GetDocument());
  cascade.Apply();

  // Since the zoom did not change, there should not be an entry in the map.
  CascadePriority* priority =
      cascade.FindPriority(CSSPropertyName(CSSPropertyID::kLineHeight));
  EXPECT_FALSE(priority);
}

TEST_F(StyleCascadeTest, WritingModeCascadeOrder) {
  TestCascade cascade(GetDocument());
  cascade.Add("writing-mode", "vertical-lr");
  cascade.Add("-webkit-writing-mode", "vertical-rl");
  cascade.Apply();

  EXPECT_EQ("vertical-rl", cascade.ComputedValue("writing-mode"));
  EXPECT_EQ("vertical-rl", cascade.ComputedValue("-webkit-writing-mode"));
}

TEST_F(StyleCascadeTest, WritingModeReversedCascadeOrder) {
  TestCascade cascade(GetDocument());
  cascade.Add("-webkit-writing-mode", "vertical-rl");
  cascade.Add("writing-mode", "vertical-lr");
  cascade.Apply();

  EXPECT_EQ("vertical-lr", cascade.ComputedValue("writing-mode"));
  EXPECT_EQ("vertical-lr", cascade.ComputedValue("-webkit-writing-mode"));
}

TEST_F(StyleCascadeTest, WritingModePriority) {
  TestCascade cascade(GetDocument());
  cascade.Add("writing-mode:vertical-lr !important", Origin::kAuthor);
  cascade.Add("-webkit-writing-mode:vertical-rl", Origin::kAuthor);
  cascade.Apply();

  EXPECT_EQ("vertical-lr", cascade.ComputedValue("writing-mode"));
  EXPECT_EQ("vertical-lr", cascade.ComputedValue("-webkit-writing-mode"));
}

TEST_F(StyleCascadeTest, RubyPositionCascadeOrder) {
  TestCascade cascade(GetDocument());
  cascade.Add("ruby-position", "over");
  cascade.Add("-webkit-ruby-position", "after");
  cascade.Apply();

  EXPECT_EQ("under", cascade.ComputedValue("ruby-position"));
  EXPECT_EQ("after", cascade.ComputedValue("-webkit-ruby-position"));
}

TEST_F(StyleCascadeTest, RubyPositionReverseCascadeOrder) {
  TestCascade cascade(GetDocument());
  cascade.Add("-webkit-ruby-position", "after");
  cascade.Add("ruby-position", "over");
  cascade.Apply();

  EXPECT_EQ("over", cascade.ComputedValue("ruby-position"));
  EXPECT_EQ("before", cascade.ComputedValue("-webkit-ruby-position"));
}

TEST_F(StyleCascadeTest, RubyPositionSurrogateCanCascadeAsOriginal) {
  // Note: -webkit-ruby-position is defined as the surrogate, and ruby-position
  // is the original.
  ASSERT_FALSE(GetCSSPropertyRubyPosition().IsSurrogate());
  ASSERT_TRUE(GetCSSPropertyWebkitRubyPosition().IsSurrogate());

  const struct {
    CSSValueID specified;
    const char* webkit_expected;
    const char* unprefixed_expected;
  } tests[] = {
      {CSSValueID::kBefore, "before", "over"},
      {CSSValueID::kAfter, "after", "under"},
      {CSSValueID::kOver, "before", "over"},
      {CSSValueID::kUnder, "after", "under"},
  };

  for (const auto& test : tests) {
    TestCascade cascade(GetDocument());
    auto* set =
        MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode);
    set->SetProperty(CSSPropertyID::kWebkitRubyPosition,
                     *CSSIdentifierValue::Create(test.specified));
    cascade.Add(set);
    cascade.Apply();
    EXPECT_EQ(test.unprefixed_expected, cascade.ComputedValue("ruby-position"));
    EXPECT_EQ(test.webkit_expected,
              cascade.ComputedValue("-webkit-ruby-position"));
  }
}

TEST_F(StyleCascadeTest, TextOrientationPriority) {
  TestCascade cascade(GetDocument());
  cascade.Add("text-orientation:upright !important");
  cascade.Add("-webkit-text-orientation:sideways");
  cascade.Apply();

  EXPECT_EQ("upright", cascade.ComputedValue("text-orientation"));
  EXPECT_EQ("upright", cascade.ComputedValue("-webkit-text-orientation"));
}

TEST_F(StyleCascadeTest, TextOrientationRevert) {
  TestCascade cascade(GetDocument());
  cascade.Add("text-orientation:upright", CascadeOrigin::kUserAgent);
  cascade.Add("-webkit-text-orientation:mixed");
  cascade.Add("-webkit-text-orientation:revert");
  cascade.Apply();

  EXPECT_EQ("upright", cascade.ComputedValue("text-orientation"));
  EXPECT_EQ("upright", cascade.ComputedValue("-webkit-text-orientation"));
}

TEST_F(StyleCascadeTest, TextOrientationLegacyKeyword) {
  TestCascade cascade(GetDocument());
  cascade.Add("-webkit-text-orientation:vertical-right");
  cascade.Apply();

  EXPECT_EQ("mixed", cascade.ComputedValue("text-orientation"));
  EXPECT_EQ("vertical-right",
            cascade.ComputedValue("-webkit-text-orientation"));
}

TEST_F(StyleCascadeTest, WebkitBorderImageCascadeOrder) {
  String gradient1("linear-gradient(rgb(0, 0, 0), rgb(0, 128, 0))");
  String gradient2("linear-gradient(rgb(0, 0, 0), rgb(0, 200, 0))");

  TestCascade cascade(GetDocument());
  cascade.Add("-webkit-border-image", gradient1 + " round 40 / 10px / 20px",
              Origin::kAuthor);
  cascade.Add("border-image-source", gradient2, Origin::kAuthor);
  cascade.Add("border-image-slice", "20", Origin::kAuthor);
  cascade.Add("border-image-width", "6px", Origin::kAuthor);
  cascade.Add("border-image-outset", "4px", Origin::kAuthor);
  cascade.Add("border-image-repeat", "space", Origin::kAuthor);
  cascade.Apply();

  EXPECT_EQ(gradient2, cascade.ComputedValue("border-image-source"));
  EXPECT_EQ("20", cascade.ComputedValue("border-image-slice"));
  EXPECT_EQ("6px", cascade.ComputedValue("border-image-width"));
  EXPECT_EQ("4px", cascade.ComputedValue("border-image-outset"));
  EXPECT_EQ("space", cascade.ComputedValue("border-image-repeat"));
}

TEST_F(StyleCascadeTest, WebkitBorderImageReverseCascadeOrder) {
  String gradient1("linear-gradient(rgb(0, 0, 0), rgb(0, 128, 0))");
  String gradient2("linear-gradient(rgb(0, 0, 0), rgb(0, 200, 0))");

  TestCascade cascade(GetDocument());
  cascade.Add("border-image-source", gradient2, Origin::kAuthor);
  cascade.Add("border-image-slice", "20", Origin::kAuthor);
  cascade.Add("border-image-width", "6px", Origin::kAuthor);
  cascade.Add("border-image-outset", "4px", Origin::kAuthor);
  cascade.Add("border-image-repeat", "space", Origin::kAuthor);
  cascade.Add("-webkit-border-image", gradient1 + " round 40 / 10px / 20px",
              Origin::kAuthor);
  cascade.Apply();

  EXPECT_EQ(gradient1, cascade.ComputedValue("border-image-source"));
  EXPECT_EQ("40 fill", cascade.ComputedValue("border-image-slice"));
  EXPECT_EQ("10px", cascade.ComputedValue("border-image-width"));
  EXPECT_EQ("20px", cascade.ComputedValue("border-image-outset"));
  EXPECT_EQ("round", cascade.ComputedValue("border-image-repeat"));
}

TEST_F(StyleCascadeTest, WebkitBorderImageMixedOrder) {
  String gradient1("linear-gradient(rgb(0, 0, 0), rgb(0, 128, 0))");
  String gradient2("linear-gradient(rgb(0, 0, 0), rgb(0, 200, 0))");

  TestCascade cascade(GetDocument());
  cascade.Add("border-image-source", gradient2, Origin::kAuthor);
  cascade.Add("border-image-width", "6px", Origin::kAuthor);
  cascade.Add("-webkit-border-image", gradient1 + " round 40 / 10px / 20px",
              Origin::kAuthor);
  cascade.Add("border-image-slice", "20", Origin::kAuthor);
  cascade.Add("border-image-outset", "4px", Origin::kAuthor);
  cascade.Add("border-image-repeat", "space", Origin::kAuthor);
  cascade.Apply();

  EXPECT_EQ(gradient1, cascade.ComputedValue("border-image-source"));
  EXPECT_EQ("20", cascade.ComputedValue("border-image-slice"));
  EXPECT_EQ("10px", cascade.ComputedValue("border-image-width"));
  EXPECT_EQ("4px", cascade.ComputedValue("border-image-outset"));
  EXPECT_EQ("space", cascade.ComputedValue("border-image-repeat"));
}

TEST_F(StyleCascadeTest, WebkitPerspectiveOriginCascadeOrder) {
  TestCascade cascade(GetDocument());
  cascade.Add("-webkit-perspective-origin-x:10px");
  cascade.Add("-webkit-perspective-origin-y:20px");
  cascade.Add("perspective-origin:30px 40px");
  cascade.Apply();

  EXPECT_EQ("30px 40px", cascade.ComputedValue("perspective-origin"));

  // The -webkit-perspective-origin-x/y properties are not "computable".
  EXPECT_EQ(nullptr, cascade.ComputedValue("-webkit-perspective-origin-x"));
  EXPECT_EQ(nullptr, cascade.ComputedValue("-webkit-perspective-origin-y"));
}

TEST_F(StyleCascadeTest, WebkitPerspectiveOriginReverseCascadeOrder) {
  TestCascade cascade(GetDocument());
  cascade.Add("perspective-origin:30px 40px");
  cascade.Add("-webkit-perspective-origin-x:10px");
  cascade.Add("-webkit-perspective-origin-y:20px");
  cascade.Apply();

  EXPECT_EQ("10px 20px", cascade.ComputedValue("perspective-origin"));

  // The -webkit-perspective-origin-x/y properties are not "computable".
  EXPECT_EQ(nullptr, cascade.ComputedValue("-webkit-perspective-origin-x"));
  EXPECT_EQ(nullptr, cascade.ComputedValue("-webkit-perspective-origin-y"));
}

TEST_F(StyleCascadeTest, WebkitPerspectiveOriginMixedCascadeOrder) {
  TestCascade cascade(GetDocument());
  cascade.Add("-webkit-perspective-origin-x:10px");
  cascade.Add("perspective-origin:30px 40px");
  cascade.Add("-webkit-perspective-origin-y:20px");
  cascade.Apply();

  EXPECT_EQ("30px 20px", cascade.ComputedValue("perspective-origin"));

  // The -webkit-perspective-origin-x/y properties are not "computable".
  EXPECT_EQ(nullptr, cascade.ComputedValue("-webkit-perspective-origin-x"));
  EXPECT_EQ(nullptr, cascade.ComputedValue("-webkit-perspective-origin-y"));
}

TEST_F(StyleCascadeTest, WebkitPerspectiveOriginRevert) {
  TestCascade cascade(GetDocument());
  cascade.Add("-webkit-perspective-origin-x:10px");
  cascade.Add("perspective-origin:30px 40px");
  cascade.Add("-webkit-perspective-origin-y:20px");
  cascade.Apply();

  EXPECT_EQ("30px 20px", cascade.ComputedValue("perspective-origin"));

  // The -webkit-perspective-origin-x/y properties are 
"""


```
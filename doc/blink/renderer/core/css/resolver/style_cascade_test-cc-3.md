Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from a Chromium Blink engine file. Specifically, they want to understand:

1. **Core Functionality:** What does this code do?
2. **Relationship to Web Technologies:** How does it relate to JavaScript, HTML, and CSS?
3. **Logic and Examples:** Provide input/output examples for logical operations.
4. **Common Errors:**  Illustrate typical user or programming mistakes related to this code.
5. **Debugging Context:**  How does a user end up interacting with this part of the engine?
6. **Overall Summary:** A concise summary of the file's purpose.

Let's break down the code and address each of these points.

**Code Analysis:**

The code is a series of C++ unit tests using the `TEST_F` macro, which suggests a testing framework like Google Test. Each test function focuses on a specific aspect of CSS style cascading. The `StyleCascadeTest` fixture provides a `TestCascade` helper class, which seems to simulate the process of applying CSS rules and resolving style values.

The tests cover various scenarios, including:

* **Order of application:** How different CSS properties interact based on their order in the stylesheet.
* **Shorthand and longhand properties:** How shorthand properties (like `transform-origin`) interact with their corresponding longhand properties (`-webkit-transform-origin-x`, etc.).
* **`!important` rules:**  Though not explicitly shown in this snippet, the presence of `AnalyzeMatchResult` test suggests it's handled elsewhere in the full file.
* **Vendor prefixes:**  Testing how prefixed properties (like `-webkit-`) are handled.
* **Logical properties:**  How logical properties (`margin-inline-start`) resolve to physical properties (`margin-left`).
* **Initial and non-initial values:** How properties behave with default and overridden values.
* **`text-size-adjust`:**  Testing the behavior of text autosizing.
* **Dependencies:** Whether a style calculation depends on cascade-affecting properties.
* **Custom properties (CSS variables):**  How custom properties are defined, referenced, and resolved using `var()`.
* **Visited links:** How styles for visited links are applied.
* **Filtering:** Applying style cascading with specific property filters.
* **Author styles:**  Checking if author-defined styles are present for specific properties.
* **`revert` keyword:**  Testing the behavior of the `revert` keyword in CSS.
* **`all: unset`:** How the `all` shorthand property interacts with other properties.
* **Animations:** How animated values are considered during cascading.
* **`env()` function:** How environment variables are handled in CSS.
* **`initial` keyword:** How the `initial` keyword works, particularly with `color`.
* **Maximum variable size:** Testing limitations on the size of custom property values.
* **Unicode escapes in custom properties:**  Ensuring Unicode characters in custom properties are handled correctly.
* **`GetCascadedValues()`:**  Testing the ability to retrieve the cascaded values of CSS properties.
* **Static resolution:**  A helper function to resolve CSS values in a static context.

**Connecting to Web Technologies:**

* **CSS:** This code is fundamentally about CSS style cascading. It tests how different CSS rules from various origins (user-agent, user, author) with different levels of specificity and importance are applied to determine the final computed style of an element. The examples within the tests directly use CSS property names and values.
* **HTML:** While the code itself doesn't directly manipulate HTML, the `GetDocument()` calls suggest that the tests are operating within the context of a parsed HTML document. The styles being resolved would eventually be applied to HTML elements.
* **JavaScript:**  JavaScript can interact with the computed styles of elements. For instance, JavaScript can use `getComputedStyle()` to retrieve the final style values calculated by the cascade mechanism tested here. Changes made by JavaScript to an element's style also need to be integrated into the cascade.

**Logical Reasoning and Examples:**

Let's take the `WebkitTransformOriginCascadeOrder` test as an example:

* **Input:**  CSS declarations added to the cascade in the following order:
    ```css
    -webkit-transform-origin-x: 10px;
    -webkit-transform-origin-y: 20px;
    -webkit-transform-origin-z: 30px;
    transform-origin: 40px 50px 60px;
    ```
* **Process:** The `Apply()` method simulates the cascading process. Since `transform-origin` is a standard property and has higher precedence than the individual `-webkit-` prefixed longhands when applied later, it should override them.
* **Output:**
    * `cascade.ComputedValue("transform-origin")` will return `"40px 50px 60px"`.
    * `cascade.ComputedValue("-webkit-transform-origin-x")`, `cascade.ComputedValue("-webkit-transform-origin-y")`, and `cascade.ComputedValue("-webkit-transform-origin-z")` will return `nullptr` because these are not considered "computable" after the standard shorthand is applied.

**User and Programming Errors:**

* **Incorrect Vendor Prefix Usage:** A common mistake is to rely solely on vendor-prefixed properties without including the standard property. This can lead to inconsistent behavior across different browsers. For example, only using `-webkit-transform-origin` will not work in Firefox. The tests highlight the interaction between prefixed and standard properties, encouraging developers to use both for wider compatibility.
* **Specificity Issues:**  Users might unintentionally write CSS rules that are overridden by more specific rules, or by rules declared later in the stylesheet. Understanding the cascade order and specificity rules is crucial to avoid these issues. The tests implicitly cover specificity by testing different declaration orders.
* **Misunderstanding `!important`:** Overusing `!important` can make stylesheets difficult to manage and debug. While this snippet doesn't explicitly demonstrate `!important` errors, the presence of tests analyzing match results hints at the importance of this concept within the cascading logic.
* **Forgetting to Define Custom Properties:** Using `var(--my-variable)` without defining `--my-variable` will result in the fallback value (if provided) or the initial/inherited value. The tests with `MarkHasVariableReferenceLonghandMissingVar` and `MarkHasVariableReferenceShorthandMissingVar` touch upon this.
* **Exceeding Custom Property Value Limits:**  The `MaxVariableBytes` test shows that there are limits to the size of custom property values. Users might encounter issues if they try to store very large strings in custom properties.

**User Operation and Debugging:**

A user's interaction that leads to this code being executed typically involves the browser rendering a web page. Here's a step-by-step scenario:

1. **User loads a web page:** The user types a URL into the browser or clicks a link.
2. **Browser requests resources:** The browser requests the HTML, CSS, and JavaScript files from the server.
3. **HTML parsing:** The HTML is parsed to create the Document Object Model (DOM) tree.
4. **CSS parsing:** The CSS files are parsed, and the browser builds internal representations of the style rules.
5. **Style calculation:**  This is where the `style_cascade_test.cc` code comes into play (indirectly). The browser's style engine needs to determine the final styles for each element in the DOM. This involves:
    * **Matching CSS rules:** Identifying which CSS rules apply to a specific element based on selectors.
    * **Cascading:** Applying the matching rules according to the cascade order (origin, specificity, order of appearance). The `TestCascade` class in the test file simulates this process.
    * **Inheritance:**  Propagating certain style values from parent to child elements.
    * **Computing values:**  Resolving relative units (like `em`, `%`) and applying default values.
6. **Rendering:**  The browser uses the computed styles to layout and paint the web page on the screen.

**Debugging Connection:**

If a web developer is debugging a CSS styling issue, they might:

* **Inspect the element:** Use the browser's developer tools to examine the computed styles of an element.
* **Check the applied CSS rules:**  The developer tools show which CSS rules are affecting the element and their order of precedence.
* **Look for `!important` rules:** Identify any `!important` declarations that might be overriding other styles.
* **Trace the cascade:**  Understand how different CSS rules from different sources (author stylesheets, user stylesheets, browser defaults) are interacting.

The code in `style_cascade_test.cc` is part of the foundational logic that makes this debugging process possible. It ensures that the browser's style engine is correctly implementing the CSS cascading rules. If a bug were present in this core logic, developers would see unexpected or inconsistent styling behavior in their web pages.

**Summary of Functionality:**

The `style_cascade_test.cc` file contains unit tests for the Blink rendering engine's CSS style cascading mechanism. These tests verify the correctness of how CSS rules are applied, ordered, and resolved to determine the final computed styles of elements. It ensures that the browser correctly implements the CSS specification regarding inheritance, specificity, origin, and the interaction of different CSS features like vendor prefixes, logical properties, custom properties, and animations. Essentially, it's a critical component for ensuring consistent and predictable rendering of web pages based on CSS.

这是 `blink/renderer/core/css/resolver/style_cascade_test.cc` 文件的第 4 部分，该文件是 Chromium Blink 引擎的源代码，专门用于测试 CSS 样式层叠的解析器。

**它的主要功能是：**

1. **验证 CSS 样式层叠的解析逻辑：** 该文件包含大量的单元测试，用于验证 Blink 引擎在解析和应用 CSS 样式规则时的正确性。它模拟了各种不同的 CSS 声明组合和优先级情况，以确保最终计算出的样式值是符合 CSS 规范的。

2. **测试不同 CSS 特性的层叠行为：**  这些测试涵盖了各种 CSS 特性，例如：
    * **传统属性与 `-webkit-` 前缀属性的交互：** 例如 `perspective-origin` 和 `-webkit-perspective-origin-x/y`，`transform-origin` 和 `-webkit-transform-origin-x/y/z`，以及 `box-decoration-break` 和 `-webkit-box-decoration-break`。测试确保在存在标准属性和带前缀的属性时，引擎能够按照正确的优先级进行选择。
    * **逻辑属性与物理属性的映射：** 例如 `margin-inline-start` 和 `margin-left`，测试在不同的 `direction` 和 `writing-mode` 下，逻辑属性如何正确映射到物理属性。
    * **`text-size-adjust` 属性的影响：** 测试 `text-size-adjust` 如何影响 `font-size` 和 `line-height` 的计算。
    * **CSS 自定义属性（CSS 变量）：**  测试自定义属性的定义、引用（使用 `var()` 函数）和层叠行为，包括引用已定义的变量和未定义的变量。
    * **伪类 `:visited` 的样式应用：** 测试在链接被访问后，`:visited` 伪类定义的样式如何被应用。
    * **使用 `all: unset` 重置样式：** 测试 `all: unset` 如何重置所有 CSS 属性的样式。
    * **CSS 动画的影响：** 测试 CSS 动画在样式层叠中的作用，以及如何通过插值计算动画过程中的样式值。
    * **`env()` 函数的使用：** 测试 `env()` 函数在 CSS 中的使用，用于获取环境变量。
    * **`initial`，`inherit`，`unset`，`revert` 等 CSS 全局关键字：** 测试这些关键字在样式层叠中的行为。

3. **检查依赖于层叠影响属性的计算：**  测试某些属性的计算是否依赖于其他可能影响层叠的属性（例如 `inline-size` 会影响 `width` 的计算）。

4. **标记变量引用和环境引用：**  测试代码会检查样式中是否包含对 CSS 变量 (`var()`) 或环境变量 (`env()`) 的引用。

5. **使用过滤器应用层叠：**  测试可以根据特定的属性类型（例如继承属性或带有 `-webkit-` 前缀的属性）来过滤应用层叠。

6. **判断是否包含作者样式：**  测试用于判断是否应用了来自作者样式表的背景或边框相关属性。

7. **分析匹配结果：**  测试能够分析哪些样式规则最终被应用，以及它们的来源（用户代理、用户、作者）。

8. **获取层叠后的属性值：**  测试 `GetCascadedValues()` 方法，该方法可以获取元素上最终层叠后的各个 CSS 属性的值。

9. **静态解析 CSS 值：** 测试 `StaticResolve()` 方法，该方法可以在没有完整样式层叠的情况下，静态地解析 CSS 值，例如解析包含 `var()` 函数的属性值。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **CSS:**  该文件直接测试 CSS 的解析和应用逻辑。例如，`TEST_F(StyleCascadeTest, WebkitPerspectiveOriginCascadeOrder)` 测试了当同时存在 `-webkit-perspective-origin-x/y` 和 `perspective-origin` 属性时，哪个属性会生效，这直接关系到 CSS 属性的优先级和层叠规则。
    ```css
    /* 假设的 HTML 结构 */
    <div style="-webkit-perspective-origin-x: 10px; -webkit-perspective-origin-y: 20px; perspective-origin: 30px 40px;"></div>
    ```
    测试会验证最终 `perspective-origin` 的计算值是否为 `30px 40px`。

* **HTML:**  虽然该文件不直接操作 HTML，但测试的上下文是基于 HTML 文档的。`GetDocument()` 方法获取的是一个模拟的 HTML 文档对象，测试中的样式规则将会应用到这个文档中的元素上（尽管在测试中通常是隐式的）。

* **JavaScript:** JavaScript 可以通过 `getComputedStyle()` 方法获取元素最终的计算样式。该文件测试的样式层叠逻辑正是 `getComputedStyle()` 返回值的基石。例如，如果 JavaScript 代码想要获取上面例子中 `div` 元素的 `perspective-origin` 值，它依赖于这里测试的层叠逻辑的正确性。
    ```javascript
    // 假设的 JavaScript 代码
    const div = document.querySelector('div');
    const perspectiveOrigin = getComputedStyle(div).perspectiveOrigin;
    console.log(perspectiveOrigin); // 预期输出 "30px 40px"
    ```

**逻辑推理的假设输入与输出举例说明：**

以 `TEST_F(StyleCascadeTest, WebkitTransformOriginReverseCascadeOrder)` 为例：

* **假设输入（CSS 声明的顺序）：**
    ```css
    transform-origin: 40px 50px 60px;
    -webkit-transform-origin-x: 10px;
    -webkit-transform-origin-y: 20px;
    -webkit-transform-origin-z: 30px;
    ```
* **逻辑推理：**  由于 `-webkit-transform-origin-x/y/z` 是更具体的属性，并且在 `transform-origin` 之后声明，它们会覆盖 `transform-origin` 中对应的分量。
* **预期输出：**
    * `cascade.ComputedValue("transform-origin")` 将返回 `"10px 20px 30px"`。
    * `cascade.ComputedValue("-webkit-transform-origin-x")`，`cascade.ComputedValue("-webkit-transform-origin-y")`，和 `cascade.ComputedValue("-webkit-transform-origin-z")` 将返回 `nullptr`，因为这些属性在层叠后不再是 "可计算的"（computable），它们的值被合并到了 `transform-origin` 中。

**用户或编程常见的使用错误举例说明：**

* **错误地认为 `-webkit-` 前缀属性总是优先：**  开发者可能错误地认为带有 `-webkit-` 前缀的属性总是比标准属性优先级高。例如，在上面的 `WebkitTransformOriginReverseCascadeOrder` 例子中，如果开发者不理解层叠顺序，可能会错误地认为 `transform-origin` 的值会是最终结果。
* **忘记包含标准属性：**  开发者可能只使用了 `-webkit-` 前缀的属性，而没有包含标准的属性，导致在非 WebKit 内核的浏览器上样式失效。例如，只写 `-webkit-transform-origin: 10px 20px;` 在 Firefox 上不会生效。
* **过度使用 `!important`：**  虽然在这个代码片段中没有直接体现，但样式层叠测试也会验证 `!important` 的作用。开发者过度使用 `!important` 会导致样式难以维护和调试，因为会打乱正常的层叠顺序。
* **自定义属性命名错误或作用域问题：**  开发者可能在 `var()` 函数中错误地引用了不存在的自定义属性，或者自定义属性的作用域不正确，导致样式无法生效。测试用例 `TEST_F(StyleCascadeTest, MarkHasVariableReferenceLonghandMissingVar)` 和 `TEST_F(StyleCascadeTest, MarkHasVariableReferenceShorthandMissingVar)` 就覆盖了这种情况。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中访问一个网页。**
2. **浏览器开始解析 HTML 和 CSS。**
3. **在 CSS 解析阶段，浏览器会构建内部的样式规则表示。**
4. **当浏览器需要计算某个 HTML 元素的最终样式时，就会触发样式层叠的解析过程。**  `blink/renderer/core/css/resolver/style_cascade.cc` 中的代码（该测试文件与之相关）会被执行，根据匹配到的 CSS 规则、选择器优先级、来源等因素，计算出最终的样式值。
5. **如果开发者在调试 CSS 样式问题，他们可能会使用浏览器的开发者工具来检查元素的“计算样式”。**  这些计算样式的结果正是由这里测试的样式层叠逻辑决定的。
6. **如果计算样式与预期不符，开发者可能需要检查 CSS 规则的声明顺序、选择器优先级、是否使用了 `!important` 等，以理解样式层叠的过程。** 该测试文件中的用例可以帮助开发者理解各种层叠场景下的行为。

**作为第 4 部分，共 5 部分，它的功能归纳：**

这部分测试主要集中在以下几个方面，是对样式层叠解析器功能的更细致和深入的验证：

* **传统属性与 `-webkit-` 前缀属性的优先级和覆盖规则。**
* **逻辑属性到物理属性的映射在不同书写模式和方向下的正确性。**
* **`text-size-adjust` 对字体和行高的影响。**
* **CSS 变量的定义、引用和在复杂层叠场景下的行为，包括未定义变量的处理。**
* **`:visited` 伪类样式的应用。**
* **使用过滤器来应用特定的样式规则。**
* **判断是否存在由作者定义的背景和边框样式。**
* **分析最终生效的样式规则及其来源。**

总而言之，这部分测试旨在确保 Blink 引擎能够准确、可靠地实现 CSS 样式层叠的各种细节规则，从而保证网页在不同浏览器和场景下呈现一致的视觉效果。

Prompt: 
```
这是目录为blink/renderer/core/css/resolver/style_cascade_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能

"""
not "computable".
  EXPECT_EQ(nullptr, cascade.ComputedValue("-webkit-perspective-origin-x"));
  EXPECT_EQ(nullptr, cascade.ComputedValue("-webkit-perspective-origin-y"));
}

TEST_F(StyleCascadeTest, WebkitTransformOriginCascadeOrder) {
  TestCascade cascade(GetDocument());
  cascade.Add("-webkit-transform-origin-x:10px");
  cascade.Add("-webkit-transform-origin-y:20px");
  cascade.Add("-webkit-transform-origin-z:30px");
  cascade.Add("transform-origin:40px 50px 60px");
  cascade.Apply();

  EXPECT_EQ("40px 50px 60px", cascade.ComputedValue("transform-origin"));

  // The -webkit-transform-origin-x/y/z properties are not "computable".
  EXPECT_EQ(nullptr, cascade.ComputedValue("-webkit-transform-origin-x"));
  EXPECT_EQ(nullptr, cascade.ComputedValue("-webkit-transform-origin-y"));
  EXPECT_EQ(nullptr, cascade.ComputedValue("-webkit-transform-origin-z"));
}

TEST_F(StyleCascadeTest, WebkitTransformOriginReverseCascadeOrder) {
  TestCascade cascade(GetDocument());
  cascade.Add("transform-origin:40px 50px 60px");
  cascade.Add("-webkit-transform-origin-x:10px");
  cascade.Add("-webkit-transform-origin-y:20px");
  cascade.Add("-webkit-transform-origin-z:30px");
  cascade.Apply();

  EXPECT_EQ("10px 20px 30px", cascade.ComputedValue("transform-origin"));

  // The -webkit-transform-origin-x/y/z properties are not "computable".
  EXPECT_EQ(nullptr, cascade.ComputedValue("-webkit-transform-origin-x"));
  EXPECT_EQ(nullptr, cascade.ComputedValue("-webkit-transform-origin-y"));
  EXPECT_EQ(nullptr, cascade.ComputedValue("-webkit-transform-origin-z"));
}

TEST_F(StyleCascadeTest, WebkitTransformOriginMixedCascadeOrder) {
  TestCascade cascade(GetDocument());
  cascade.Add("-webkit-transform-origin-x:10px");
  cascade.Add("transform-origin:40px 50px 60px");
  cascade.Add("-webkit-transform-origin-y:20px");
  cascade.Add("-webkit-transform-origin-z:30px");
  cascade.Apply();

  EXPECT_EQ("40px 20px 30px", cascade.ComputedValue("transform-origin"));

  // The -webkit-transform-origin-x/y/z properties are not "computable".
  EXPECT_EQ(nullptr, cascade.ComputedValue("-webkit-transform-origin-x"));
  EXPECT_EQ(nullptr, cascade.ComputedValue("-webkit-transform-origin-y"));
  EXPECT_EQ(nullptr, cascade.ComputedValue("-webkit-transform-origin-z"));
}

TEST_F(StyleCascadeTest, VerticalAlignBaselineSource) {
  TestCascade cascade(GetDocument());
  cascade.Add("vertical-align", "top");
  cascade.Add("baseline-source", "first");
  cascade.Apply();

  EXPECT_EQ("top", cascade.ComputedValue("vertical-align"));
  EXPECT_EQ("first", cascade.ComputedValue("baseline-source"));
}

TEST_F(StyleCascadeTest, VerticalAlignBaselineSourceReversed) {
  TestCascade cascade(GetDocument());
  cascade.Add("baseline-source", "first");
  cascade.Add("vertical-align", "top");
  cascade.Apply();

  EXPECT_EQ("top", cascade.ComputedValue("vertical-align"));
  EXPECT_EQ("auto", cascade.ComputedValue("baseline-source"));
}

TEST_F(StyleCascadeTest, WebkitBoxDecorationBreakOverlap) {
  ScopedBoxDecorationBreakForTest scoped_feature(true);

  TestCascade cascade(GetDocument());
  cascade.Add("-webkit-box-decoration-break", "slice");
  cascade.Add("box-decoration-break", "clone");
  cascade.Apply();

  EXPECT_EQ("clone", cascade.ComputedValue("box-decoration-break"));
  EXPECT_EQ("clone", cascade.ComputedValue("-webkit-box-decoration-break"));
}

TEST_F(StyleCascadeTest, WebkitBoxDecorationBreakOverlapReverse) {
  ScopedBoxDecorationBreakForTest scoped_feature(true);

  TestCascade cascade(GetDocument());
  cascade.Add("box-decoration-break", "slice");
  cascade.Add("-webkit-box-decoration-break", "clone");
  cascade.Apply();

  EXPECT_EQ("clone", cascade.ComputedValue("box-decoration-break"));
  EXPECT_EQ("clone", cascade.ComputedValue("-webkit-box-decoration-break"));
}

TEST_F(StyleCascadeTest, InitialDirection) {
  TestCascade cascade(GetDocument());
  cascade.Add("margin-inline-start:10px");
  cascade.Add("margin-inline-end:20px");
  cascade.Apply();

  EXPECT_EQ("10px", cascade.ComputedValue("margin-left"));
  EXPECT_EQ("20px", cascade.ComputedValue("margin-right"));
}

TEST_F(StyleCascadeTest, NonInitialDirection) {
  TestCascade cascade(GetDocument());
  cascade.Add("margin-inline-start:10px");
  cascade.Add("margin-inline-end:20px");
  cascade.Add("direction:rtl");
  cascade.Apply();

  EXPECT_EQ("20px", cascade.ComputedValue("margin-left"));
  EXPECT_EQ("10px", cascade.ComputedValue("margin-right"));
}

TEST_F(StyleCascadeTest, InitialWritingMode) {
  TestCascade cascade(GetDocument());
  cascade.Add("inline-size:10px");
  cascade.Add("block-size:20px");
  cascade.Apply();

  EXPECT_EQ("10px", cascade.ComputedValue("width"));
  EXPECT_EQ("20px", cascade.ComputedValue("height"));
}

TEST_F(StyleCascadeTest, NonInitialWritingMode) {
  TestCascade cascade(GetDocument());
  cascade.Add("inline-size:10px");
  cascade.Add("block-size:20px");
  cascade.Add("writing-mode:vertical-lr");
  cascade.Apply();

  EXPECT_EQ("20px", cascade.ComputedValue("width"));
  EXPECT_EQ("10px", cascade.ComputedValue("height"));
}

TEST_F(StyleCascadeTest, InitialTextSizeAdjust) {
  GetDocument().GetSettings()->SetTextAutosizingEnabled(true);
  ScopedTextSizeAdjustImprovementsForTest scoped_feature(true);

  TestCascade cascade(GetDocument());
  cascade.Add("font-size:10px");
  cascade.Add("line-height:20px");
  cascade.Apply();

  EXPECT_EQ("10px", cascade.ComputedValue("font-size"));
  EXPECT_EQ("20px", cascade.ComputedValue("line-height"));
}

TEST_F(StyleCascadeTest, NonInitialTextSizeAdjust) {
  GetDocument().GetSettings()->SetTextAutosizingEnabled(true);
  ScopedTextSizeAdjustImprovementsForTest scoped_feature(true);

  TestCascade cascade(GetDocument());
  cascade.Add("font-size:10px");
  cascade.Add("line-height:20px");
  cascade.Add("text-size-adjust:200%");
  cascade.Apply();

  EXPECT_EQ("20px", cascade.ComputedValue("font-size"));
  EXPECT_EQ("40px", cascade.ComputedValue("line-height"));
}

TEST_F(StyleCascadeTest, DoesNotDependOnCascadeAffectingProperty) {
  TestCascade cascade(GetDocument());
  cascade.Add("width:10px");
  cascade.Add("height:20px");
  cascade.Apply();

  EXPECT_FALSE(cascade.DependsOnCascadeAffectingProperty());
  EXPECT_EQ("10px", cascade.ComputedValue("width"));
  EXPECT_EQ("20px", cascade.ComputedValue("height"));
}

TEST_F(StyleCascadeTest, DependsOnCascadeAffectingProperty) {
  TestCascade cascade(GetDocument());
  cascade.Add("inline-size:10px");
  cascade.Add("height:20px");
  cascade.Apply();

  EXPECT_TRUE(cascade.DependsOnCascadeAffectingProperty());
  EXPECT_EQ("10px", cascade.ComputedValue("width"));
  EXPECT_EQ("20px", cascade.ComputedValue("height"));
}

TEST_F(StyleCascadeTest, ResetDependsOnCascadeAffectingPropertyFlag) {
  TestCascade cascade(GetDocument());
  cascade.Add("inline-size:10px");
  cascade.Add("height:20px");
  cascade.Apply();

  EXPECT_TRUE(cascade.DependsOnCascadeAffectingProperty());
  cascade.Reset();
  EXPECT_FALSE(cascade.DependsOnCascadeAffectingProperty());
}

TEST_F(StyleCascadeTest, MarkReferenced) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);
  RegisterProperty(GetDocument(), "--y", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("width", "var(--x)");
  cascade.Apply();

  const auto& registry = GetDocument().EnsurePropertyRegistry();

  EXPECT_TRUE(registry.WasReferenced(AtomicString("--x")));
  EXPECT_FALSE(registry.WasReferenced(AtomicString("--y")));
}

TEST_F(StyleCascadeTest, MarkHasVariableReferenceLonghand) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x", "1px");
  cascade.Add("width", "var(--x)");
  cascade.Apply();
  const auto* style = cascade.TakeStyle();
  EXPECT_TRUE(style->HasVariableReference());
}

TEST_F(StyleCascadeTest, MarkHasVariableReferenceShorthand) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x", "1px");
  cascade.Add("margin", "var(--x)");
  cascade.Apply();
  const auto* style = cascade.TakeStyle();
  EXPECT_TRUE(style->HasVariableReference());
}

TEST_F(StyleCascadeTest, MarkHasVariableReferenceLonghandMissingVar) {
  TestCascade cascade(GetDocument());
  cascade.Add("width", "var(--x)");
  cascade.Apply();
  const auto* style = cascade.TakeStyle();
  EXPECT_TRUE(style->HasVariableReference());
}

TEST_F(StyleCascadeTest, MarkHasVariableReferenceShorthandMissingVar) {
  TestCascade cascade(GetDocument());
  cascade.Add("margin", "var(--x)");
  cascade.Apply();
  const auto* style = cascade.TakeStyle();
  EXPECT_TRUE(style->HasVariableReference());
}

TEST_F(StyleCascadeTest, NoMarkHasVariableReferenceWithoutVar) {
  TestCascade cascade(GetDocument());
  cascade.Add("width", "1px");
  cascade.Apply();
  const auto* style = cascade.TakeStyle();
  EXPECT_FALSE(style->HasVariableReference());
}

TEST_F(StyleCascadeTest, InternalVisitedColorLonghand) {
  TestCascade cascade(GetDocument());
  cascade.Add("color:green");
  cascade.Add("color:red", {.origin = CascadeOrigin::kAuthor,
                            .link_match_type = CSSSelector::kMatchVisited});

  cascade.State().StyleBuilder().SetInsideLink(EInsideLink::kInsideVisitedLink);
  cascade.Apply();

  EXPECT_EQ("rgb(0, 128, 0)", cascade.ComputedValue("color"));

  Color red(255, 0, 0);
  const css_longhand::Color& color = GetCSSPropertyColor();
  EXPECT_EQ(red, cascade.TakeStyle()->VisitedDependentColor(color));
}

TEST_F(StyleCascadeTest, VarInInternalVisitedColorShorthand) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x:red");
  cascade.Add("outline:medium solid var(--x)",
              {.link_match_type = CSSSelector::kMatchVisited});
  cascade.Add("outline-color:green",
              {.link_match_type = CSSSelector::kMatchLink});

  cascade.State().StyleBuilder().SetInsideLink(EInsideLink::kInsideVisitedLink);
  cascade.Apply();

  EXPECT_EQ("rgb(0, 128, 0)", cascade.ComputedValue("outline-color"));

  Color red(255, 0, 0);
  const css_longhand::OutlineColor& outline_color =
      GetCSSPropertyOutlineColor();
  EXPECT_EQ(red, cascade.TakeStyle()->VisitedDependentColor(outline_color));
}

TEST_F(StyleCascadeTest, ApplyWithFilter) {
  TestCascade cascade(GetDocument());
  cascade.Add("color", "blue", Origin::kAuthor);
  cascade.Add("background-color", "green", Origin::kAuthor);
  cascade.Add("display", "inline", Origin::kAuthor);
  cascade.Apply();

  cascade.Reset();
  cascade.Add("color", "green", Origin::kAuthor);
  cascade.Add("background-color", "red", Origin::kAuthor);
  cascade.Add("display", "block", Origin::kAuthor);
  cascade.Apply(CascadeFilter(CSSProperty::kInherited, false));
  EXPECT_EQ("rgb(0, 128, 0)", cascade.ComputedValue("color"));
  EXPECT_EQ("rgb(0, 128, 0)", cascade.ComputedValue("background-color"));
  EXPECT_EQ("inline", cascade.ComputedValue("display"));
}

TEST_F(StyleCascadeTest, FilterWebkitBorderImage) {
  TestCascade cascade(GetDocument());
  cascade.Add("border-image:linear-gradient(green, red) 1 / 2 / 3 round",
              Origin::kAuthor);
  cascade.Add(
      "-webkit-border-image:linear-gradient(green, red) 4 / 5 / 6 round",
      Origin::kAuthor);
  cascade.Apply(CascadeFilter(CSSProperty::kLegacyOverlapping, true));
  EXPECT_EQ("linear-gradient(rgb(0, 128, 0), rgb(255, 0, 0)) 1 / 2 / 3 round",
            cascade.ComputedValue("-webkit-border-image"));
}

TEST_F(StyleCascadeTest, FilterPerspectiveOrigin) {
  TestCascade cascade(GetDocument());
  cascade.Add("-webkit-perspective-origin-x:10px");
  cascade.Add("-webkit-perspective-origin-y:20px");
  cascade.Add("perspective-origin:30px 40px");
  cascade.Apply(CascadeFilter(CSSProperty::kLegacyOverlapping, false));
  EXPECT_EQ("10px 20px", cascade.ComputedValue("perspective-origin"));
}

TEST_F(StyleCascadeTest, FilterTransformOrigin) {
  TestCascade cascade(GetDocument());
  cascade.Add("-webkit-transform-origin-x:10px");
  cascade.Add("-webkit-transform-origin-y:20px");
  cascade.Add("-webkit-transform-origin-z:30px");
  cascade.Add("transform-origin:40px 50px 60px");
  cascade.Apply(CascadeFilter(CSSProperty::kLegacyOverlapping, false));
  EXPECT_EQ("10px 20px 30px", cascade.ComputedValue("transform-origin"));
}

TEST_F(StyleCascadeTest, HasAuthorBackground) {
  Vector<String> properties = {"background-attachment", "background-clip",
                               "background-image",      "background-origin",
                               "background-position-x", "background-position-y",
                               "background-size"};

  for (String property : properties) {
    TestCascade cascade(GetDocument());
    cascade.Add("-webkit-appearance", "button", Origin::kUserAgent);
    cascade.Add(property, "unset", Origin::kAuthor);
    cascade.Apply();
    EXPECT_TRUE(cascade.TakeStyle()->HasAuthorBackground());
  }
}

TEST_F(StyleCascadeTest, HasAuthorBorder) {
  Vector<String> properties = {
      "border-top-color",          "border-right-color",
      "border-bottom-color",       "border-left-color",
      "border-top-style",          "border-right-style",
      "border-bottom-style",       "border-left-style",
      "border-top-width",          "border-right-width",
      "border-bottom-width",       "border-left-width",
      "border-top-left-radius",    "border-top-right-radius",
      "border-bottom-left-radius", "border-bottom-right-radius",
      "border-image-source",       "border-image-slice",
      "border-image-width",        "border-image-outset",
      "border-image-repeat"};

  for (String property : properties) {
    TestCascade cascade(GetDocument());
    cascade.Add("-webkit-appearance", "button", Origin::kUserAgent);
    cascade.Add(property, "unset", Origin::kAuthor);
    cascade.Apply();
    EXPECT_TRUE(cascade.TakeStyle()->HasAuthorBorder());
  }
}

TEST_F(StyleCascadeTest, HasAuthorBorderLogical) {
  TestCascade cascade(GetDocument());
  cascade.Add("-webkit-appearance", "button", Origin::kUserAgent);
  cascade.Add("border-block-start-color", "red", Origin::kUserAgent);
  cascade.Add("border-block-start-color", "green", Origin::kAuthor);
  cascade.Apply();
  const auto* style = cascade.TakeStyle();
  EXPECT_TRUE(style->HasAuthorBorder());
}

TEST_F(StyleCascadeTest, NoAuthorBackgroundOrBorder) {
  TestCascade cascade(GetDocument());
  cascade.Add("-webkit-appearance", "button", Origin::kUserAgent);
  cascade.Add("background-color", "red", Origin::kUserAgent);
  cascade.Add("border-left-color", "green", Origin::kUserAgent);
  cascade.Add("background-clip", "padding-box", Origin::kUser);
  cascade.Add("border-right-color", "green", Origin::kUser);
  cascade.Apply();
  const auto* style = cascade.TakeStyle();
  EXPECT_FALSE(style->HasAuthorBackground());
  EXPECT_FALSE(style->HasAuthorBorder());
}

TEST_F(StyleCascadeTest, AuthorBackgroundRevert) {
  TestCascade cascade(GetDocument());
  cascade.Add("-webkit-appearance", "button", Origin::kUserAgent);
  cascade.Add("background-color", "red", Origin::kUserAgent);
  cascade.Add("background-color", "revert", Origin::kAuthor);
  cascade.Apply();
  const auto* style = cascade.TakeStyle();
  EXPECT_FALSE(style->HasAuthorBackground());
}

TEST_F(StyleCascadeTest, AuthorBorderRevert) {
  TestCascade cascade(GetDocument());
  cascade.Add("-webkit-appearance", "button", Origin::kUserAgent);
  cascade.Add("border-top-color", "red", Origin::kUserAgent);
  cascade.Add("border-top-color", "revert", Origin::kAuthor);
  cascade.Apply();
  const auto* style = cascade.TakeStyle();
  EXPECT_FALSE(style->HasAuthorBorder());
}

TEST_F(StyleCascadeTest, AuthorBorderRevertLogical) {
  TestCascade cascade(GetDocument());
  cascade.Add("-webkit-appearance", "button", Origin::kUserAgent);
  cascade.Add("border-block-start-color", "red", Origin::kUserAgent);
  cascade.Add("border-block-start-color", "revert", Origin::kAuthor);
  cascade.Apply();
  const auto* style = cascade.TakeStyle();
  EXPECT_FALSE(style->HasAuthorBorder());
}

TEST_F(StyleCascadeTest, AnalyzeMatchResult) {
  auto ua = CascadeOrigin::kUserAgent;
  auto author = CascadeOrigin::kAuthor;

  TestCascade cascade(GetDocument());
  cascade.Add("display:none;left:5px", ua);
  cascade.Add("font-size:1px !important", ua);
  cascade.Add("display:block;color:red", author);
  cascade.Add("font-size:3px", author);
  cascade.Apply();

  EXPECT_EQ(cascade.GetPriority("display").GetOrigin(), author);
  EXPECT_EQ(cascade.GetPriority("left").GetOrigin(), ua);
  EXPECT_EQ(cascade.GetPriority("color").GetOrigin(), author);
  EXPECT_EQ(cascade.GetPriority("font-size").GetOrigin(), ua);
}

TEST_F(StyleCascadeTest, AnalyzeMatchResultAll) {
  auto ua = CascadeOrigin::kUserAgent;
  auto author = CascadeOrigin::kAuthor;

  TestCascade cascade(GetDocument());
  cascade.Add("display:block", ua);
  cascade.Add("font-size:1px !important", ua);
  cascade.Add("all:unset", author);
  cascade.Apply();

  EXPECT_EQ(cascade.GetPriority("display").GetOrigin(), author);
  EXPECT_EQ(cascade.GetPriority("font-size").GetOrigin(), ua);

  // Random sample from another property affected by 'all'.
  EXPECT_EQ(cascade.GetPriority("color").GetOrigin(), author);
  EXPECT_EQ(cascade.GetPriority("color"), cascade.GetPriority("display"));
}

TEST_F(StyleCascadeTest, AnalyzeFlagsClean) {
  AppendSheet(R"HTML(
     @keyframes test {
        from { top: 0px; }
        to { top: 10px; }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("bottom:10px");
  cascade.Add("animation:test linear 1000s -500s");
  cascade.Apply();
  EXPECT_FALSE(cascade.NeedsMatchResultAnalyze());
  EXPECT_FALSE(cascade.NeedsInterpolationsAnalyze());

  cascade.AddInterpolations();
  cascade.Apply();
  EXPECT_FALSE(cascade.NeedsMatchResultAnalyze());
  EXPECT_FALSE(cascade.NeedsInterpolationsAnalyze());
}

TEST_F(StyleCascadeTest, ApplyMatchResultFilter) {
  TestCascade cascade(GetDocument());
  cascade.Add("display:block");
  cascade.Add("color:green");
  cascade.Add("font-size:3px");
  cascade.Apply();

  cascade.Reset();
  cascade.Add("display:inline");
  cascade.Add("color:red");
  cascade.Apply(CascadeFilter(CSSProperty::kInherited, true));

  EXPECT_EQ("inline", cascade.ComputedValue("display"));
  EXPECT_EQ("rgb(0, 128, 0)", cascade.ComputedValue("color"));
  EXPECT_EQ("3px", cascade.ComputedValue("font-size"));
}

TEST_F(StyleCascadeTest, ApplyMatchResultAllFilter) {
  TestCascade cascade(GetDocument());
  cascade.Add("color:green");
  cascade.Add("display:block");
  cascade.Apply();

  cascade.Reset();
  cascade.Add("all:unset");
  cascade.Apply(CascadeFilter(CSSProperty::kInherited, true));

  EXPECT_EQ("rgb(0, 128, 0)", cascade.ComputedValue("color"));
  EXPECT_EQ("inline", cascade.ComputedValue("display"));
}

TEST_F(StyleCascadeTest, MarkHasReferenceLonghand) {
  TestCascade cascade(GetDocument());

  cascade.Add("--x:red");
  cascade.Add("background-color:var(--x)");
  cascade.Apply();

  EXPECT_TRUE(cascade.State().StyleBuilder().HasVariableReference());
}

TEST_F(StyleCascadeTest, MarkHasReferenceShorthand) {
  TestCascade cascade(GetDocument());

  cascade.Add("--x:red");
  cascade.Add("background:var(--x)");
  cascade.Apply();

  EXPECT_TRUE(cascade.State().StyleBuilder().HasVariableReference());
}

TEST_F(StyleCascadeTest, HasNoEnv) {
  TestCascade cascade(GetDocument());
  cascade.Add("margin:1px");
  cascade.Add("width:1px");
  cascade.Add("--x:1px");
  cascade.Apply();

  EXPECT_FALSE(cascade.State().StyleBuilder().HasEnv());
}

TEST_F(StyleCascadeTest, MarkHasEnvLonghand) {
  TestCascade cascade(GetDocument());
  cascade.Add("width:env(unknown)");
  cascade.Apply();
  EXPECT_TRUE(cascade.State().StyleBuilder().HasEnv());
}

TEST_F(StyleCascadeTest, MarkHasEnvShorthand) {
  TestCascade cascade(GetDocument());
  cascade.Add("padding:env(unknown)");
  cascade.Apply();
  EXPECT_TRUE(cascade.State().StyleBuilder().HasEnv());
}

TEST_F(StyleCascadeTest, MarkHasEnvCustomProperty) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x:env(unknown)");
  cascade.Apply();
  EXPECT_TRUE(cascade.State().StyleBuilder().HasEnv());
}

TEST_F(StyleCascadeTest, Reset) {
  TestCascade cascade(GetDocument());

  EXPECT_EQ(CascadePriority(), cascade.GetPriority("color"));
  EXPECT_EQ(CascadePriority(), cascade.GetPriority("--x"));

  cascade.Add("color:red");
  cascade.Add("--x:red");
  cascade.Apply();  // generation=1
  cascade.Apply();  // generation=2

  EXPECT_EQ(2u, cascade.GetPriority("color").GetGeneration());
  EXPECT_EQ(2u, cascade.GetPriority("--x").GetGeneration());

  cascade.Reset();

  EXPECT_EQ(CascadePriority(), cascade.GetPriority("color"));
  EXPECT_EQ(CascadePriority(), cascade.GetPriority("--x"));
}

TEST_F(StyleCascadeTest, GetImportantSetEmpty) {
  TestCascade cascade(GetDocument());
  cascade.Add("color:red");
  cascade.Add("width:1px");
  cascade.Add("--x:green");
  EXPECT_FALSE(cascade.GetImportantSet());
}

TEST_F(StyleCascadeTest, GetImportantSetSingle) {
  TestCascade cascade(GetDocument());
  cascade.Add("width:1px !important");
  ASSERT_TRUE(cascade.GetImportantSet());
  EXPECT_EQ(CSSBitset({CSSPropertyID::kWidth}), *cascade.GetImportantSet());
}

TEST_F(StyleCascadeTest, GetImportantSetMany) {
  TestCascade cascade(GetDocument());
  cascade.Add("width:1px !important");
  cascade.Add("height:1px !important");
  cascade.Add("top:1px !important");
  ASSERT_TRUE(cascade.GetImportantSet());
  EXPECT_EQ(CSSBitset({CSSPropertyID::kWidth, CSSPropertyID::kHeight,
                       CSSPropertyID::kTop}),
            *cascade.GetImportantSet());
}

TEST_F(StyleCascadeTest, RootColorNotModifiedByEmptyCascade) {
  TestCascade cascade(GetDocument(), GetDocument().documentElement());
  cascade.Add("color:red");
  cascade.Apply();

  cascade.Reset();
  cascade.Add("display:block");
  cascade.Apply();  // Should not affect 'color'.

  const auto* style = cascade.TakeStyle();

  ComputedStyleBuilder builder(*style);
  builder.SetInsideLink(EInsideLink::kInsideVisitedLink);
  style = builder.TakeStyle();
  EXPECT_EQ(Color(255, 0, 0),
            style->VisitedDependentColor(GetCSSPropertyColor()));

  builder = ComputedStyleBuilder(*style);
  builder.SetInsideLink(EInsideLink::kNotInsideLink);
  style = builder.TakeStyle();
  EXPECT_EQ(Color(255, 0, 0),
            style->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleCascadeTest, InitialColor) {
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);

  TestCascade cascade(GetDocument(), GetDocument().documentElement());
  cascade.Add("color-scheme:dark");

  // CSSInitialColorValue is not reachable via a string, hence we must
  // create the CSSPropertyValueSet that contains it manually.
  auto* set =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode);
  set->SetProperty(CSSPropertyID::kColor, *CSSInitialColorValue::Create());
  cascade.Add(set);

  cascade.Apply();

  const auto* style = cascade.TakeStyle();

  ComputedStyleBuilder builder(*style);
  builder.SetInsideLink(EInsideLink::kInsideVisitedLink);
  style = builder.TakeStyle();
  EXPECT_EQ(Color::kWhite, style->VisitedDependentColor(GetCSSPropertyColor()));

  builder = ComputedStyleBuilder(*style);
  builder.SetInsideLink(EInsideLink::kNotInsideLink);
  style = builder.TakeStyle();
  EXPECT_EQ(Color::kWhite, style->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleCascadeTest, MaxVariableBytes) {
  StringBuilder builder;
  for (size_t i = 0; i < CSSVariableData::kMaxVariableBytes; ++i) {
    builder.Append(':');  // <colon-token>
  }

  String at_limit = builder.ToString();
  String above_limit = builder.ToString() + ":";

  TestCascade cascade(GetDocument());
  cascade.Add("--at-limit", at_limit);
  cascade.Add("--above-limit", above_limit);
  cascade.Add("--at-limit-reference", "var(--at-limit)");
  cascade.Add("--above-limit-reference", "var(--above-limit)");
  cascade.Add("--at-limit-reference-fallback",
              "var(--unknown,var(--at-limit))");
  cascade.Add("--above-limit-reference-fallback",
              "var(--unknown,var(--above-limit))");
  cascade.Apply();

  EXPECT_EQ(at_limit, cascade.ComputedValue("--at-limit"));
  EXPECT_EQ(g_null_atom, cascade.ComputedValue("--above-limit"));
  EXPECT_EQ(at_limit, cascade.ComputedValue("--at-limit-reference"));
  EXPECT_EQ(g_null_atom, cascade.ComputedValue("--above-limit-reference"));
  EXPECT_EQ(at_limit, cascade.ComputedValue("--at-limit-reference-fallback"));
  EXPECT_EQ(g_null_atom,
            cascade.ComputedValue("--above-limit-reference-fallback"));
}

TEST_F(StyleCascadeTest, UnicodeEscapeInCustomProperty) {
  TestCascade cascade(GetDocument());
  cascade.Add("--a", "\"\\65e5\\672c\"");
  cascade.Add("content", "var(--a)");
  cascade.Apply();

  EXPECT_EQ(String::FromUTF8("\"日本\""), cascade.ComputedValue("content"));
}

TEST_F(StyleCascadeTest, GetCascadedValues) {
  TestCascade cascade(GetDocument());
  cascade.Add("top:1px", CascadeOrigin::kUserAgent);
  cascade.Add("right:2px", CascadeOrigin::kUserAgent);
  cascade.Add("bottom:3px", CascadeOrigin::kUserAgent);
  cascade.Add("left:4px !important", CascadeOrigin::kUserAgent);
  cascade.Add("width:5px", CascadeOrigin::kUserAgent);

  cascade.Add("top:10px", CascadeOrigin::kUser);
  cascade.Add("right:20px", CascadeOrigin::kUser);
  cascade.Add("bottom:30px !important", CascadeOrigin::kUser);
  cascade.Add("left:40px", CascadeOrigin::kUser);
  cascade.Add("height:60px", CascadeOrigin::kUser);
  cascade.Add("height:61px", CascadeOrigin::kUser);
  cascade.Add("--x:70px", CascadeOrigin::kUser);
  cascade.Add("--y:80px !important", CascadeOrigin::kUser);

  cascade.Add("top:100px", CascadeOrigin::kAuthor);
  cascade.Add("right:201px !important", CascadeOrigin::kAuthor);
  cascade.Add("right:200px", CascadeOrigin::kAuthor);
  cascade.Add("bottom:300px", CascadeOrigin::kAuthor);
  cascade.Add("left:400px", CascadeOrigin::kAuthor);
  cascade.Add("--x:700px", CascadeOrigin::kAuthor);
  cascade.Add("--y:800px", CascadeOrigin::kAuthor);

  cascade.Apply();

  auto map = cascade.GetCascadedValues();
  EXPECT_EQ(8u, map.size());

  EXPECT_EQ("100px", CssTextAt(map, "top"));
  EXPECT_EQ("201px", CssTextAt(map, "right"));
  EXPECT_EQ("30px", CssTextAt(map, "bottom"));
  EXPECT_EQ("4px", CssTextAt(map, "left"));
  EXPECT_EQ("5px", CssTextAt(map, "width"));
  EXPECT_EQ("61px", CssTextAt(map, "height"));
  EXPECT_EQ("700px", CssTextAt(map, "--x"));
  EXPECT_EQ("80px", CssTextAt(map, "--y"));
}

TEST_F(StyleCascadeTest, GetCascadedValuesCssWide) {
  TestCascade cascade(GetDocument());
  cascade.Add("top:initial");
  cascade.Add("right:inherit");
  cascade.Add("bottom:unset");
  cascade.Add("left:revert");
  cascade.Apply();

  auto map = cascade.GetCascadedValues();
  EXPECT_EQ(4u, map.size());

  EXPECT_EQ("initial", CssTextAt(map, "top"));
  EXPECT_EQ("inherit", CssTextAt(map, "right"));
  EXPECT_EQ("unset", CssTextAt(map, "bottom"));
  EXPECT_EQ("revert", CssTextAt(map, "left"));
}

TEST_F(StyleCascadeTest, GetCascadedValuesLogical) {
  TestCascade cascade(GetDocument());
  cascade.Add("margin-inline-start:1px");
  cascade.Add("margin-inline-end:2px");
  cascade.Apply();

  auto map = cascade.GetCascadedValues();
  EXPECT_EQ(2u, map.size());

  EXPECT_EQ("1px", CssTextAt(map, "margin-left"));
  EXPECT_EQ("2px", CssTextAt(map, "margin-right"));
}

TEST_F(StyleCascadeTest, GetCascadedValuesInterpolated) {
  AppendSheet(R"HTML(
     @keyframes test {
        from { --x: 100px; width: 100px; }
        to { --x: 200px; width: 200px; }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("animation-name: test");
  cascade.Add("animation-timing-function: linear");
  cascade.Add("animation-duration: 10s");
  cascade.Add("animation-delay: -5s");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();

  // Verify that effect values from the animation did apply:
  EXPECT_EQ("200px", cascade.ComputedValue("--x"));
  EXPECT_EQ("150px", cascade.ComputedValue("width"));

  // However, we don't currently support returning interpolated vales from
  // GetCascadedValues:
  auto map = cascade.GetCascadedValues();
  EXPECT_EQ(4u, map.size());

  EXPECT_EQ("test", CssTextAt(map, "animation-name"));
  EXPECT_EQ("linear", CssTextAt(map, "animation-timing-function"));
  EXPECT_EQ("10s", CssTextAt(map, "animation-duration"));
  EXPECT_EQ("-5s", CssTextAt(map, "animation-delay"));
}

TEST_F(StyleCascadeTest, GetCascadedValuesWithExplicitDefaults) {
  ScopedStandardizedBrowserZoomForTest scoped_feature(true);

  TestCascade cascade(GetDocument());
  cascade.Add("top:100px");
  cascade.Add("zoom:200%");  // Causes explicit defaults.
  cascade.Apply();

  // Any explicit defaults (StyleCascade::AddExplicitDefaults) should not
  // be visible via GetCascadedValues.

  auto map = cascade.GetCascadedValues();
  EXPECT_EQ(2u, map.size());

  EXPECT_EQ("100px", CssTextAt(map, "top"));
  EXPECT_EQ("200%", CssTextAt(map, "zoom"));
}

TEST_F(StyleCascadeTest, StaticResolveNoVar) {
  // We don't need this object, but it's an easy way of setting
  // up a StyleResolverState.
  TestCascade cascade(GetDocument());

  EXPECT_EQ("thing", CssText(TestCascade::StaticResolve(cascade.State(), "--x",
                                                        "thing")));
  EXPECT_EQ("red", CssText(TestCascade::StaticResolve(cascade.State(), "color",
                                                      "red")));
  EXPECT_EQ("10px", CssText(TestCascade::StaticResolve(cascade.State(), "width",
                                                       "10px")));
  EXPECT_EQ("10em", CssText(TestCascade::StaticResolve(cascade.State(), "width",
                                                       "10em")));
  EXPECT_EQ("calc(1% + 1em)", CssText(TestCascade::StaticResolve(
                                  cascade.State(), "width", "calc(1% + 1em)")));
}

TEST_F(StyleCascadeTest, StaticResolveVar) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x:foo");
  cascade.Apply();

  EXPECT_EQ("foo", CssText(TestCascade::StaticResolve(cascade.State(), "--y",
                                                      "var(--x)")));
  EXPECT_EQ("foo bar", CssText(TestCascade::StaticResolve(
                           cascade.State(), "--y", "var(--x) bar")));
  EXPECT_EQ("bar", CssText(TestCascade::StaticResolve(cascade.State(), "--y",
                                                      "var(--unknown,bar)")));
  EXPECT_EQ("unset", CssText(TestCascade::StaticResolve(cascade.State(), "--y",
                                                        "var(--unknown)")));
}

TEST_F(StyleCascadeTest, StaticResolveRegisteredVar) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);
  RegisterProperty(GetDocument(), "--y", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--x:100px");
  cascade.Apply();

  EXPECT_EQ("100px", CssText(TestCascade::StaticResolve(cascade.State(), "--y",
                                                        "var(--x)")));
  EXPECT_EQ("100px", CssText(TestCascade::StaticResolve(cascade.State(), "--z",
                                                        "var(--x)")));

  EXPECT_EQ("50px", CssText(TestCascade::StaticResolve(
                        cascade.State(), "--y", "var(--unknown, 50px)")));
  EXPECT_EQ("50px", CssText(TestCascade::StaticResolve(
                        cascade.State(), "--z", "var(--unknown, 50px)")));

  EXPECT_EQ("unset", CssText(TestCascade::StaticResolve(cascade.State(), "--y",
                                                        "var(--unknown)")));
  EXPECT_EQ("unset", CssText(TestCascade::StaticResolve(cascade.State(), "--z",
                                                        "var(--unknown)")));

  // StyleCacade::Resolve does not actually compute values, just eliminate
  // var() references.
  EXPECT_EQ("calc(5em + 100px)",
            CssText(TestCascade::StaticResolve(cascade.State(), "--y",
                                               "calc(5em + var(--x))")));
  EXPECT_EQ("calc(5em + 100px)",
            CssText(TestCascade::StaticResolve(cascade.State(), "--z",
                                               "calc(5em + var(--x))")));
}

TEST_F(StyleCascadeTest, RevertOrigin) {
  TestCascade cascade(GetDocument());

  cascade.Add("width", "1px", CascadeOrigin::kUserAgent);
  cascade.Add("height", "1px", CascadeOrigin::kUserAgent);
  cascade.Add("display", "block", CascadeOrigin::kUserAgent);
  cascade.Add("width", "2px", CascadeOrigin::kUser);
  cascade.Add("height", "revert", CascadeOrigin::kUser);
  cascade.Add("width", "revert", CascadeOrigin::kAuthor);
  cascade.Add("height", "revert", CascadeOrigin::kAuthor);
  cascade.Add("display", "revert", CascadeOrigin::kAuthor);
  cascade.Add("margin-left", "revert", CascadeOrigin::kAut
"""


```
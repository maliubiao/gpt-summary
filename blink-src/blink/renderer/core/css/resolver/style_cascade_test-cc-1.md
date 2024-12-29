Response:
The user wants me to analyze a C++ source code file for the Chromium Blink engine.
The file is `style_cascade_test.cc` located in `blink/renderer/core/css/resolver/`.
This suggests the file contains unit tests for the style cascading mechanism in Blink.

My analysis should cover:
1. **Functionality:** What does the code do?
2. **Relationship to Web Technologies:** How does it relate to JavaScript, HTML, and CSS?
3. **Logic and Examples:**  Provide examples of inputs and outputs if logical reasoning is involved.
4. **Common Errors:**  Illustrate potential user or programming errors.
5. **Debugging Context:** Explain how a user's actions can lead to this code being executed, as debugging clues.
6. **Summary:**  Provide a concise summary of the file's functionality based on the provided part of the code.

Based on the content of the provided code snippet, it appears to be a set of unit tests for the CSS custom properties (`--*`) and their interaction with various CSS concepts like:

*   **Cycles:** Testing how the system handles circular dependencies in custom property definitions.
*   **`var()` function:** Verifying the behavior of the `var()` function, including its fallback mechanism.
*   **Units:**  Checking the resolution of `em` and `rem` units in custom property values.
*   **CSS-wide keywords:**  Testing `initial`, `inherit`, `unset`, and `revert`.
*   **Cascade origins:**  Simulating different sources of style declarations (user-agent, user, author).
*   **`revert` keyword:**  Examining how `revert` interacts with different cascade origins and property types.
*   **Animations and Transitions:** Investigating the behavior of custom properties within animations and transitions.
*   **Registered properties:** Testing interactions with properties registered using `CSS.registerProperty`.

Let's break down each test case and infer its purpose.
```cpp
de.Apply();
  EXPECT_EQ("foo", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, SubstituteRegisteredCustomSyntaxInitial) {
  RegisterProperty(GetDocument(), "--x", "<color>", "lime", false);

  TestCascade cascade(GetDocument());
  cascade.Apply();
  EXPECT_EQ("rgb(0, 255, 0)", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, SubstituteRegisteredCustomSyntax) {
  RegisterProperty(GetDocument(), "--x", "<color>", "lime", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--x", "red");
  cascade.Add("--y", "var(--x)");
  cascade.Apply();
  EXPECT_EQ("rgb(255, 0, 0)", cascade.ComputedValue("--x"));
  EXPECT_EQ("rgb(255, 0, 0)", cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, SubstituteRegisteredCustomSyntaxInvalid) {
  RegisterProperty(GetDocument(), "--x", "<color>", "lime", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--y", " var(--x) ");
  cascade.Apply();
  EXPECT_EQ("rgb(0, 255, 0)", cascade.ComputedValue("--x"));
  EXPECT_EQ("rgb(0, 255, 0)", cascade.ComputedValue("--y"));

  cascade.Reset();
  cascade.Add("--x", "invalid");
  cascade.Add("--y", "var(--x)");
  cascade.Apply();
  EXPECT_FALSE(cascade.ComputedValue("--x"));
  EXPECT_FALSE(cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, SubstituteRegisteredCustomSyntaxVarFallback) {
  RegisterProperty(GetDocument(), "--x", "<color>", "lime", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--y", "var(--z, var(--x))");
  cascade.Apply();
  EXPECT_EQ("rgb(0, 255, 0)", cascade.ComputedValue("--x"));
  EXPECT_EQ("rgb(0, 255, 0)", cascade.ComputedValue("--y"));

  cascade.Reset();
  cascade.Add("--z", "red");
  cascade.Add("--y", "var(--z, var(--x))");
  cascade.Apply();
  EXPECT_EQ("rgb(0, 255, 0)", cascade.ComputedValue("--x"));
  EXPECT_EQ("rgb(255, 0, 0)", cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, SubstituteRegisteredCustomSyntaxNestedVarFallback) {
  RegisterProperty(GetDocument(), "--x", "<color>", "lime", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--y", "var(--z, var(--w, var(--x)))");
  cascade.Apply();
  EXPECT_EQ("rgb(0, 255, 0)", cascade.ComputedValue("--x"));
  EXPECT_EQ("rgb(0, 255, 0)", cascade.ComputedValue("--y"));

  cascade.Reset();
  cascade.Add("--w", "red");
  cascade.Add("--y", "var(--z, var(--w, var(--x)))");
  cascade.Apply();
  EXPECT_EQ("rgb(0, 255, 0)", cascade.ComputedValue("--x"));
  EXPECT_EQ("rgb(255, 0, 0)", cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, SubstituteRegisteredCustomSyntaxNestedVarFallbackInvalid) {
  RegisterProperty(GetDocument(), "--x", "<color>", "lime", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--y", "var(--z, var(--w, var(--x)))");
  cascade.Apply();
  EXPECT_EQ("rgb(0, 255, 0)", cascade.ComputedValue("--x"));
  EXPECT_EQ("rgb(0, 255, 0)", cascade.ComputedValue("--y"));

  cascade.Reset();
  cascade.Add("--w", "invalid");
  cascade.Add("--y", "var(--z, var(--w, var(--x)))");
  cascade.Apply();
  EXPECT_EQ("rgb(0, 255, 0)", cascade.ComputedValue("--x"));
  EXPECT_EQ("rgb(0, 255, 0)", cascade.ComputedValue("--y"));

  cascade.Reset();
  cascade.Add("--z", "invalid");
  cascade.Add("--w", "invalid");
  cascade.Add("--y", "var(--z, var(--w, var(--x)))");
  cascade.Apply();
  EXPECT_EQ("rgb(0, 255, 0)", cascade.ComputedValue("--x"));
  EXPECT_EQ("rgb(0, 255, 0)", cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, SubstituteRegisteredCustomSyntaxNestedVarFallbackAllInvalid) {
  RegisterProperty(GetDocument(), "--x", "<color>", "lime", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--y", "var(--z, var(--w, var(--x)))");
  cascade.Apply();
  EXPECT_EQ("rgb(0, 255, 0)", cascade.ComputedValue("--x"));
  EXPECT_EQ("rgb(0, 255, 0)", cascade.ComputedValue("--y"));

  cascade.Reset();
  cascade.Add("--z", "invalid");
  cascade.Add("--w", "invalid");
  cascade.Add("--x", "invalid");
  cascade.Add("--y", "var(--z, var(--w, var(--x)))");
  cascade.Apply();
  EXPECT_FALSE(cascade.ComputedValue("--x"));
  EXPECT_FALSE(cascade.ComputedValue("--y"));
}
```

### 功能归纳

这段代码是 Chromium Blink 引擎中 `style_cascade_test.cc` 文件的第二部分，它主要包含了一系列的单元测试，用于验证 **CSS 自定义属性（也称为 CSS 变量）** 在样式层叠解析过程中的各种行为和特性。

具体来说，这部分测试集中于以下功能点：

1. **循环依赖检测:** 测试了在自定义属性定义中出现循环依赖时，样式解析器是否能够正确地检测并避免无限循环。这包括基本的循环 (`--a: var(--b); --b: var(--a);`)、自循环 (`--a: var(--a);`)、以及通过 `var()` 函数的 fallback 机制引入的循环。
2. **`var()` 函数的行为:** 验证了 `var()` 函数在不同场景下的工作方式，包括：
    *   正常取值。
    *   使用 fallback 值。
    *   fallback 值为另一个 `var()` 函数。
    *   fallback 值中包含循环依赖。
3. **与已注册属性的交互:** 测试了自定义属性与通过 `CSS.registerProperty()` 注册的属性之间的相互作用，例如，当循环依赖涉及到已注册的属性时，是否会使用已注册的初始值。
4. **单位解析 (`em` 和 `rem`):**  测试了在自定义属性中使用 `em` 和 `rem` 单位时，其值的计算是否正确，以及是否存在与字体大小相关的循环依赖问题。
5. **CSS 关键字 (`initial`, `inherit`, `unset`, `revert`):**  验证了这些关键字在自定义属性中的行为，包括如何重置属性值以及如何继承父元素的属性值。
6. **`revert` 关键字与层叠上下文:** 详细测试了 `revert` 关键字在不同层叠来源（用户代理、用户、作者）下的行为，以及如何回退到更低优先级的样式声明，包括对标准属性和自定义属性的处理。
7. **动画和过渡中的自定义属性:**  测试了在 CSS 动画 (`@keyframes`) 和过渡 (`transition`) 中使用 `revert` 关键字的效果。
8. **已注册属性的默认值和语法:**  验证了通过 `CSS.registerProperty()` 注册的属性的默认值和自定义语法约束是否能够正确地影响自定义属性的值解析和替换。

### 与 JavaScript, HTML, CSS 的关系举例说明

*   **CSS:** 这部分代码直接测试了 CSS 的核心特性——自定义属性及其相关的 `var()` 函数和各种 CSS 关键字。例如：
    *   **示例 (循环依赖):** HTML 中定义了如下 CSS：
        ```html
        <style>
          :root {
            --a: var(--b);
            --b: var(--a);
          }
          div {
            color: var(--a, red); /* 使用 fallback 值 */
          }
        </style>
        ```
        `style_cascade_test.cc` 中的 `BasicCycle` 测试就是为了验证在这种情况下，`div` 的 `color` 会使用 fallback 值 `red`，而不是因为无限循环而导致错误。
    *   **示例 (`revert` 关键字):** HTML 中定义了如下 CSS：
        ```html
        <style>
          div {
            color: blue; /* 作者样式 */
          }
          div {
            color: revert; /* 作者样式尝试回退 */
          }
        </style>
        ```
        `RevertStandardProperty` 测试会模拟这种情况，验证 `div` 的颜色是否会回退到用户代理或用户的默认颜色。
*   **JavaScript:** JavaScript 可以通过 CSSOM (CSS Object Model) 与 CSS 交互，包括读取和设置自定义属性的值。`CSS.registerProperty()` 是一个 JavaScript API，用于注册自定义属性，允许指定其语法、是否继承以及初始值。
    *   **示例 (注册属性):**  JavaScript 代码可能如下：
        ```javascript
        CSS.registerProperty({
          name: '--my-color',
          syntax: '<color>',
          inherits: false,
          initialValue: 'green',
        });
        ```
        `RegisteredCycle` 测试会模拟在 CSS 中使用这个注册过的属性，并检查在循环依赖的情况下，是否会使用注册的初始值 (`0px` 在测试用例中)。
*   **HTML:** HTML 提供了结构，而 CSS 负责样式。自定义属性通常在 CSS 中定义，然后在 CSS 规则中或通过 JavaScript 引用来应用样式。测试用例通过模拟 HTML 文档和元素来验证样式解析的行为。

### 逻辑推理的假设输入与输出

以下是一些测试用例的逻辑推理：

*   **假设输入 (BasicCycle):**
    *   CSS 规则：`--a: var(--b); --b: var(--a);`
    *   查询属性：`--a`, `--b`
    *   预期输出：`ComputedValue("--a")` 为 `false`，`ComputedValue("--b")` 为 `false` (表示存在循环依赖，无法解析)。
*   **假设输入 (FallbackTriggeredByCycle):**
    *   CSS 规则：`--a: var(--b); --b: var(--a); --c: var(--a,foo);`
    *   查询属性：`--a`, `--b`, `--c`
    *   预期输出：`ComputedValue("--a")` 为 `false`，`ComputedValue("--b")` 为 `false`，`ComputedValue("--c")` 为 `"foo"` (因为 `--a` 无法解析，所以 `--c` 使用了 fallback 值)。
*   **假设输入 (EmUnit):**
    *   CSS 规则：`font-size: 10px; width: 10em;`
    *   查询属性：`width`
    *   预期输出：`ComputedValue("width")` 为 `"100px"` (因为 `10em` 相对于 `font-size` 的 `10px` 计算)。

### 用户或编程常见的使用错误举例说明

*   **循环依赖导致样式失效:** 用户在 CSS 中定义了循环依赖的自定义属性，例如：
    ```css
    :root {
      --size-a: var(--size-b);
      --size-b: calc(var(--size-a) + 10px);
    }
    div {
      width: var(--size-a);
    }
    ```
    这种错误会导致 `div` 的 `width` 无法被正确计算，可能会使用默认值或继承值，而不是用户期望的值。测试用例如 `BasicCycle`、`SelfCycle` 等就是为了防止这种错误导致意外行为。
*   **`var()` 函数的拼写错误或引用不存在的变量:** 用户可能在 CSS 中错误地使用了 `var()` 函数，例如 `width: va(--my-width);` 或引用了一个未定义的变量 `width: var(--undefined-variable);`。 虽然这部分测试侧重于逻辑，但确保 `var()` 的正确解析是至关重要的。
*   **`revert` 关键字使用不当:** 用户可能不理解 `revert` 的层叠行为，错误地期望它可以回退到某个特定的值，而实际上回退到了更早的层叠层级。例如，期望 `revert` 能回退到 `initial` 值，但实际上可能回退到用户代理样式。

### 用户操作如何一步步到达这里 (调试线索)

1. **用户编写 HTML, CSS, 或 JavaScript 代码:** 用户创建了一个包含 CSS 自定义属性的网页。
2. **浏览器加载网页并解析 CSS:** 当浏览器加载这个网页时，Blink 引擎的 CSS 解析器会解析 CSS 规则，包括自定义属性和 `var()` 函数。
3. **样式层叠解析:**  `blink/renderer/core/css/resolver/style_cascade.cc` 中的代码负责解决样式层叠，确定最终应用于每个元素的样式值。当遇到自定义属性时，解析器需要查找其定义并进行替换。
4. **遇到 `var()` 函数:** 如果 CSS 中使用了 `var()` 函数，样式解析器会尝试找到对应自定义属性的值。
5. **检测到循环依赖或需要处理 `revert` 等关键字:** 如果自定义属性的定义存在循环依赖，或者遇到了 `revert`、`initial` 等关键字，`style_cascade_test.cc` 中测试的逻辑就会被触发。例如，如果用户定义的 CSS 中存在循环依赖，解析器会执行类似 `BasicCycle` 测试中模拟的步骤来检测和处理这种情况.
6. **调试/开发:** 当开发者在开发 Blink 引擎的样式解析相关功能时，会运行这些单元测试来验证代码的正确性。如果用户报告了与自定义属性或 `revert` 关键字相关的 bug，开发者可能会编写新的测试用例添加到 `style_cascade_test.cc` 中来重现和修复该 bug。

### 功能归纳

总而言之，`blink/renderer/core/css/resolver/style_cascade_test.cc` 的这部分代码主要用于测试 Blink 引擎在解析和处理 CSS 自定义属性时的各种边界情况和复杂场景，特别是关于循环依赖、`var()` 函数的行为、CSS 关键字以及 `revert` 关键字在不同层叠上下文中的作用。这些测试确保了样式解析的正确性和健壮性，防止了因不正确的自定义属性使用而导致的意外行为。

Prompt: 
```
这是目录为blink/renderer/core/css/resolver/style_cascade_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能

"""
.CycleEnd());
    EXPECT_FALSE(resolver.InCycle());
  }
  EXPECT_FALSE(resolver.InCycle());
}

TEST_F(StyleCascadeTest, BasicCycle) {
  TestCascade cascade(GetDocument());
  cascade.Add("--a", "foo");
  cascade.Add("--b", "bar");
  cascade.Apply();

  EXPECT_EQ("foo", cascade.ComputedValue("--a"));
  EXPECT_EQ("bar", cascade.ComputedValue("--b"));

  cascade.Reset();
  cascade.Add("--a", "var(--b)");
  cascade.Add("--b", "var(--a)");
  cascade.Apply();

  EXPECT_FALSE(cascade.ComputedValue("--a"));
  EXPECT_FALSE(cascade.ComputedValue("--b"));
}

TEST_F(StyleCascadeTest, SelfCycle) {
  TestCascade cascade(GetDocument());
  cascade.Add("--a", "foo");
  cascade.Apply();

  EXPECT_EQ("foo", cascade.ComputedValue("--a"));

  cascade.Reset();
  cascade.Add("--a", "var(--a)");
  cascade.Apply();

  EXPECT_FALSE(cascade.ComputedValue("--a"));
}

TEST_F(StyleCascadeTest, SelfCycleInFallback) {
  TestCascade cascade(GetDocument());
  cascade.Add("--a", "var(--x, var(--a))");
  cascade.Apply();

  EXPECT_FALSE(cascade.ComputedValue("--a"));
}

TEST_F(StyleCascadeTest, SelfCycleInUnusedFallback) {
  TestCascade cascade(GetDocument());
  cascade.Add("--a", "var(--b, var(--a))");
  cascade.Add("--b", "10px");
  cascade.Apply();

  EXPECT_FALSE(cascade.ComputedValue("--a"));
  EXPECT_EQ("10px", cascade.ComputedValue("--b"));
}

TEST_F(StyleCascadeTest, LongCycle) {
  TestCascade cascade(GetDocument());
  cascade.Add("--a", "var(--b)");
  cascade.Add("--b", "var(--c)");
  cascade.Add("--c", "var(--d)");
  cascade.Add("--d", "var(--e)");
  cascade.Add("--e", "var(--a)");
  cascade.Apply();

  EXPECT_FALSE(cascade.ComputedValue("--a"));
  EXPECT_FALSE(cascade.ComputedValue("--b"));
  EXPECT_FALSE(cascade.ComputedValue("--c"));
  EXPECT_FALSE(cascade.ComputedValue("--d"));
  EXPECT_FALSE(cascade.ComputedValue("--e"));
}

TEST_F(StyleCascadeTest, PartialCycle) {
  TestCascade cascade(GetDocument());
  cascade.Add("--a", "var(--b)");
  cascade.Add("--b", "var(--a)");
  cascade.Add("--c", "bar var(--d) var(--a)");
  cascade.Add("--d", "foo");
  cascade.Apply();

  EXPECT_FALSE(cascade.ComputedValue("--a"));
  EXPECT_FALSE(cascade.ComputedValue("--b"));
  EXPECT_FALSE(cascade.ComputedValue("--c"));
  EXPECT_EQ("foo", cascade.ComputedValue("--d"));
}

TEST_F(StyleCascadeTest, VarCycleViaFallback) {
  TestCascade cascade(GetDocument());
  cascade.Add("--a", "var(--b)");
  cascade.Add("--b", "var(--x, var(--a))");
  cascade.Add("--c", "var(--a)");
  cascade.Apply();

  EXPECT_FALSE(cascade.ComputedValue("--a"));
  EXPECT_FALSE(cascade.ComputedValue("--b"));
  EXPECT_FALSE(cascade.ComputedValue("--c"));
}

TEST_F(StyleCascadeTest, FallbackTriggeredByCycle) {
  TestCascade cascade(GetDocument());
  cascade.Add("--a", "var(--b)");
  cascade.Add("--b", "var(--a)");
  cascade.Add("--c", "var(--a,foo)");
  cascade.Apply();

  EXPECT_FALSE(cascade.ComputedValue("--a"));
  EXPECT_FALSE(cascade.ComputedValue("--b"));
  EXPECT_EQ("foo", cascade.ComputedValue("--c"));
}

TEST_F(StyleCascadeTest, RegisteredCycle) {
  RegisterProperty(GetDocument(), "--a", "<length>", "0px", false);
  RegisterProperty(GetDocument(), "--b", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--a", "var(--b)");
  cascade.Add("--b", "var(--a)");
  cascade.Apply();

  EXPECT_EQ("0px", cascade.ComputedValue("--a"));
  EXPECT_EQ("0px", cascade.ComputedValue("--b"));
}

TEST_F(StyleCascadeTest, UniversalSyntaxCycle) {
  RegisterProperty(GetDocument(), "--a", "*", "foo", false);
  RegisterProperty(GetDocument(), "--b", "*", "bar", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--a", "var(--b)");
  cascade.Add("--b", "var(--a)");
  cascade.Apply();

  EXPECT_FALSE(cascade.ComputedValue("--a"));
  EXPECT_FALSE(cascade.ComputedValue("--b"));
}

TEST_F(StyleCascadeTest, PartiallyRegisteredCycle) {
  RegisterProperty(GetDocument(), "--a", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--a", "var(--b)");
  cascade.Add("--b", "var(--a)");
  cascade.Apply();

  EXPECT_EQ("0px", cascade.ComputedValue("--a"));
  EXPECT_FALSE(cascade.ComputedValue("--b"));
}

TEST_F(StyleCascadeTest, ReferencedRegisteredCycle) {
  RegisterProperty(GetDocument(), "--a", "<length>", "0px", false);
  RegisterProperty(GetDocument(), "--b", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  // Cycle:
  cascade.Add("--a", "var(--b)");
  cascade.Add("--b", "var(--a)");
  // References to cycle:
  cascade.Add("--c", "var(--a,1px)");
  cascade.Add("--d", "var(--b,2px)");
  cascade.Apply();

  EXPECT_EQ("0px", cascade.ComputedValue("--a"));
  EXPECT_EQ("0px", cascade.ComputedValue("--b"));
  EXPECT_EQ("0px", cascade.ComputedValue("--c"));
  EXPECT_EQ("0px", cascade.ComputedValue("--d"));
}

TEST_F(StyleCascadeTest, CycleStillInvalidWithFallback) {
  TestCascade cascade(GetDocument());
  // Cycle:
  cascade.Add("--a", "var(--b,red)");
  cascade.Add("--b", "var(--a,red)");
  // References to cycle:
  cascade.Add("--c", "var(--a,green)");
  cascade.Add("--d", "var(--b,green)");
  cascade.Apply();

  EXPECT_FALSE(cascade.ComputedValue("--a"));
  EXPECT_FALSE(cascade.ComputedValue("--b"));
  EXPECT_EQ("green", cascade.ComputedValue("--c"));
  EXPECT_EQ("green", cascade.ComputedValue("--d"));
}

TEST_F(StyleCascadeTest, CycleInFallbackStillInvalid) {
  TestCascade cascade(GetDocument());
  // Cycle:
  cascade.Add("--a", "var(--b,red)");
  cascade.Add("--b", "var(--x,var(--a))");
  // References to cycle:
  cascade.Add("--c", "var(--a,green)");
  cascade.Add("--d", "var(--b,green)");
  cascade.Apply();

  EXPECT_FALSE(cascade.ComputedValue("--a"));
  EXPECT_FALSE(cascade.ComputedValue("--b"));
  EXPECT_EQ("green", cascade.ComputedValue("--c"));
  EXPECT_EQ("green", cascade.ComputedValue("--d"));
}

TEST_F(StyleCascadeTest, CycleMultiple) {
  TestCascade cascade(GetDocument());
  // Cycle:
  cascade.Add("--a", "var(--c, red)");
  cascade.Add("--b", "var(--c, red)");
  cascade.Add("--c", "var(--a, blue) var(--b, blue)");
  // References to cycle:
  cascade.Add("--d", "var(--a,green)");
  cascade.Add("--e", "var(--b,green)");
  cascade.Add("--f", "var(--c,green)");
  cascade.Apply();

  EXPECT_FALSE(cascade.ComputedValue("--a"));
  EXPECT_FALSE(cascade.ComputedValue("--b"));
  EXPECT_FALSE(cascade.ComputedValue("--c"));
  EXPECT_EQ("green", cascade.ComputedValue("--d"));
  EXPECT_EQ("green", cascade.ComputedValue("--e"));
  EXPECT_EQ("green", cascade.ComputedValue("--f"));
}

TEST_F(StyleCascadeTest, CycleMultipleFallback) {
  TestCascade cascade(GetDocument());
  // Cycle:
  cascade.Add("--a", "var(--b, red)");
  cascade.Add("--b", "var(--a, var(--c, red))");
  cascade.Add("--c", "var(--b, red)");
  // References to cycle:
  cascade.Add("--d", "var(--a,green)");
  cascade.Add("--e", "var(--b,green)");
  cascade.Add("--f", "var(--c,green)");
  cascade.Apply();

  EXPECT_FALSE(cascade.ComputedValue("--a"));
  EXPECT_FALSE(cascade.ComputedValue("--b"));
  EXPECT_FALSE(cascade.ComputedValue("--c"));
  EXPECT_EQ("green", cascade.ComputedValue("--d"));
  EXPECT_EQ("green", cascade.ComputedValue("--e"));
  EXPECT_EQ("green", cascade.ComputedValue("--f"));
}

TEST_F(StyleCascadeTest, CycleMultipleUnusedFallback) {
  TestCascade cascade(GetDocument());
  cascade.Add("--a", "red");
  // Cycle:
  cascade.Add("--b", "var(--c, red)");
  cascade.Add("--c", "var(--a, var(--b, red) var(--d, red))");
  cascade.Add("--d", "var(--c, red)");
  // References to cycle:
  cascade.Add("--e", "var(--b,green)");
  cascade.Add("--f", "var(--c,green)");
  cascade.Add("--g", "var(--d,green)");
  cascade.Apply();

  EXPECT_FALSE(cascade.ComputedValue("--b"));
  EXPECT_FALSE(cascade.ComputedValue("--c"));
  EXPECT_FALSE(cascade.ComputedValue("--d"));
  EXPECT_EQ("green", cascade.ComputedValue("--e"));
  EXPECT_EQ("green", cascade.ComputedValue("--f"));
  EXPECT_EQ("green", cascade.ComputedValue("--g"));
}

TEST_F(StyleCascadeTest, CycleReferencedFromStandardProperty) {
  TestCascade cascade(GetDocument());
  cascade.Add("--a", "var(--b)");
  cascade.Add("--b", "var(--a)");
  cascade.Add("color:var(--a,green)");
  cascade.Apply();

  EXPECT_FALSE(cascade.ComputedValue("--a"));
  EXPECT_FALSE(cascade.ComputedValue("--b"));
  EXPECT_EQ("rgb(0, 128, 0)", cascade.ComputedValue("color"));
}

TEST_F(StyleCascadeTest, CycleReferencedFromShorthand) {
  TestCascade cascade(GetDocument());
  cascade.Add("--a", "var(--b)");
  cascade.Add("--b", "var(--a)");
  cascade.Add("background", "var(--a,green)");
  cascade.Apply();

  EXPECT_FALSE(cascade.ComputedValue("--a"));
  EXPECT_FALSE(cascade.ComputedValue("--b"));
  EXPECT_EQ("rgb(0, 128, 0)", cascade.ComputedValue("background-color"));
}

TEST_F(StyleCascadeTest, EmUnit) {
  TestCascade cascade(GetDocument());
  cascade.Add("font-size", "10px");
  cascade.Add("width", "10em");
  cascade.Apply();

  EXPECT_EQ("100px", cascade.ComputedValue("width"));
}

TEST_F(StyleCascadeTest, EmUnitCustomProperty) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("font-size", "10px");
  cascade.Add("--x", "10em");
  cascade.Apply();

  EXPECT_EQ("100px", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, EmUnitNonCycle) {
  TestCascade parent(GetDocument());
  parent.Add("font-size", "10px");
  parent.Apply();

  TestCascade cascade(GetDocument(), parent.TakeStyle());
  cascade.Add("font-size", "var(--x)");
  cascade.Add("--x", "10em");
  cascade.Apply();

  // Note: Only registered properties can have cycles with font-size.
  EXPECT_EQ("100px", cascade.ComputedValue("font-size"));
}

TEST_F(StyleCascadeTest, EmUnitCycle) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("font-size", "var(--x)");
  cascade.Add("--x", "10em");
  cascade.Apply();

  EXPECT_EQ("0px", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, SubstitutingEmCycles) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("font-size", "var(--x)");
  cascade.Add("--x", "10em");
  cascade.Add("--y", "var(--x)");
  cascade.Add("--z", "var(--x,1px)");
  cascade.Apply();

  EXPECT_EQ("0px", cascade.ComputedValue("--y"));
  EXPECT_EQ("0px", cascade.ComputedValue("--z"));
}

TEST_F(StyleCascadeTest, RemUnit) {
  SetRootFont("10px");
  UpdateAllLifecyclePhasesForTest();

  TestCascade cascade(GetDocument());
  cascade.Add("width", "10rem");
  cascade.Apply();

  EXPECT_EQ("100px", cascade.ComputedValue("width"));
}

TEST_F(StyleCascadeTest, RemUnitCustomProperty) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  SetRootFont("10px");
  UpdateAllLifecyclePhasesForTest();

  TestCascade cascade(GetDocument());
  cascade.Add("--x", "10rem");
  cascade.Apply();

  EXPECT_EQ("100px", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, RemUnitInFontSize) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  SetRootFont("10px");
  UpdateAllLifecyclePhasesForTest();

  TestCascade cascade(GetDocument());
  cascade.Add("font-size", "1rem");
  cascade.Add("--x", "10rem");
  cascade.Apply();

  EXPECT_EQ("100px", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, RemUnitInRootFontSizeCycle) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  TestCascade cascade(GetDocument(), DocumentElement());
  cascade.Add("font-size", "var(--x)");
  cascade.Add("--x", "1rem");
  cascade.Apply();

  EXPECT_EQ("0px", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, RemUnitInRootFontSizeNonCycle) {
  TestCascade cascade(GetDocument(), DocumentElement());
  cascade.Add("font-size", "initial");
  cascade.Apply();

  String expected = cascade.ComputedValue("font-size");

  cascade.Reset();
  cascade.Add("font-size", "var(--x)");
  cascade.Add("--x", "1rem");
  cascade.Apply();

  // Note: Only registered properties can have cycles with font-size.
  EXPECT_EQ("1rem", cascade.ComputedValue("--x"));
  EXPECT_EQ(expected, cascade.ComputedValue("font-size"));
}

TEST_F(StyleCascadeTest, Initial) {
  TestCascade parent(GetDocument());
  parent.Add("--x", "foo");
  parent.Apply();

  TestCascade cascade(GetDocument(), parent.TakeStyle());
  cascade.Add("--y", "foo");
  cascade.Apply();

  EXPECT_EQ("foo", cascade.ComputedValue("--x"));
  EXPECT_EQ("foo", cascade.ComputedValue("--y"));

  cascade.Reset();
  cascade.Add("--x", "initial");
  cascade.Add("--y", "initial");
  cascade.Apply();

  EXPECT_FALSE(cascade.ComputedValue("--x"));
  EXPECT_FALSE(cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, Inherit) {
  TestCascade parent(GetDocument());
  parent.Add("--x", "foo");
  parent.Apply();

  TestCascade cascade(GetDocument(), parent.TakeStyle());

  EXPECT_EQ("foo", cascade.ComputedValue("--x"));

  cascade.Add("--x", "bar");
  cascade.Apply();
  EXPECT_EQ("bar", cascade.ComputedValue("--x"));

  cascade.Reset();
  cascade.Add("--x", "inherit");
  cascade.Apply();
  EXPECT_EQ("foo", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, Unset) {
  TestCascade parent(GetDocument());
  parent.Add("--x", "foo");
  parent.Apply();

  TestCascade cascade(GetDocument(), parent.TakeStyle());
  EXPECT_EQ("foo", cascade.ComputedValue("--x"));

  cascade.Add("--x", "bar");
  cascade.Apply();
  EXPECT_EQ("bar", cascade.ComputedValue("--x"));

  cascade.Reset();
  cascade.Add("--x", "unset");
  cascade.Apply();
  EXPECT_EQ("foo", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, RevertUA) {
  TestCascade cascade(GetDocument());
  cascade.Add("display:block", CascadeOrigin::kUserAgent);
  cascade.Add("display:revert", CascadeOrigin::kUserAgent);

  cascade.Add("display:block", CascadeOrigin::kUser);
  cascade.Add("display:revert", CascadeOrigin::kUser);

  cascade.Add("display:block", CascadeOrigin::kAuthor);
  cascade.Add("display:revert", CascadeOrigin::kAuthor);

  cascade.Apply();

  EXPECT_EQ("inline", cascade.ComputedValue("display"));
}

TEST_F(StyleCascadeTest, RevertStandardProperty) {
  TestCascade cascade(GetDocument());
  cascade.Add("left:10px", CascadeOrigin::kUserAgent);
  cascade.Add("right:10px", CascadeOrigin::kUserAgent);

  cascade.Add("right:20px", CascadeOrigin::kUser);
  cascade.Add("right:revert", CascadeOrigin::kUser);
  cascade.Add("top:20px", CascadeOrigin::kUser);
  cascade.Add("bottom:20px", CascadeOrigin::kUser);

  cascade.Add("bottom:30px", CascadeOrigin::kAuthor);
  cascade.Add("bottom:revert", CascadeOrigin::kAuthor);
  cascade.Add("left:30px", CascadeOrigin::kAuthor);
  cascade.Add("left:revert", CascadeOrigin::kAuthor);
  cascade.Add("right:revert", CascadeOrigin::kAuthor);
  cascade.Apply();

  EXPECT_EQ("20px", cascade.ComputedValue("top"));
  EXPECT_EQ("10px", cascade.ComputedValue("right"));
  EXPECT_EQ("20px", cascade.ComputedValue("bottom"));
  EXPECT_EQ("10px", cascade.ComputedValue("left"));
}

TEST_F(StyleCascadeTest, RevertCustomProperty) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x:10px", CascadeOrigin::kUser);

  cascade.Add("--y:fail", CascadeOrigin::kAuthor);

  cascade.Add("--x:revert", CascadeOrigin::kAuthor);
  cascade.Add("--y:revert", CascadeOrigin::kAuthor);

  cascade.Apply();

  EXPECT_EQ("10px", cascade.ComputedValue("--x"));
  EXPECT_FALSE(cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, RevertChain) {
  TestCascade cascade(GetDocument());
  cascade.Add("width:10px", CascadeOrigin::kUserAgent);

  cascade.Add("width:revert", CascadeOrigin::kUser);
  cascade.Add("--x:revert", CascadeOrigin::kUser);

  cascade.Add("width:revert", CascadeOrigin::kAuthor);
  cascade.Add("--x:revert", CascadeOrigin::kAuthor);
  cascade.Apply();

  EXPECT_EQ("10px", cascade.ComputedValue("width"));
  EXPECT_FALSE(cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, RevertFromAuthorToUA) {
  TestCascade cascade(GetDocument());
  cascade.Add("width:10px", CascadeOrigin::kUserAgent);
  cascade.Add("height:10px", CascadeOrigin::kUserAgent);

  cascade.Add("width:20px", CascadeOrigin::kAuthor);
  cascade.Add("height:20px", CascadeOrigin::kAuthor);
  cascade.Add("width:revert", CascadeOrigin::kAuthor);
  cascade.Add("height:revert", CascadeOrigin::kAuthor);
  cascade.Apply();

  EXPECT_EQ("10px", cascade.ComputedValue("width"));
  EXPECT_EQ("10px", cascade.ComputedValue("height"));
}

TEST_F(StyleCascadeTest, RevertInitialFallback) {
  TestCascade cascade(GetDocument());
  cascade.Add("width:20px", CascadeOrigin::kAuthor);
  cascade.Add("width:revert", CascadeOrigin::kAuthor);
  cascade.Apply();

  EXPECT_EQ("auto", cascade.ComputedValue("width"));
}

TEST_F(StyleCascadeTest, RevertInheritedFallback) {
  TestCascade parent(GetDocument());
  parent.Add("color", "red");
  parent.Apply();

  TestCascade cascade(GetDocument(), parent.TakeStyle());
  EXPECT_EQ("rgb(255, 0, 0)", cascade.ComputedValue("color"));

  cascade.Add("color:black", CascadeOrigin::kAuthor);
  cascade.Add("color:revert", CascadeOrigin::kAuthor);
  cascade.Apply();
  EXPECT_EQ("rgb(255, 0, 0)", cascade.ComputedValue("color"));
}

TEST_F(StyleCascadeTest, RevertRegistered) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--x:20px", CascadeOrigin::kUser);
  cascade.Add("--x:100px", CascadeOrigin::kAuthor);
  cascade.Add("--x:revert", CascadeOrigin::kAuthor);
  cascade.Apply();

  EXPECT_EQ("20px", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, RevertRegisteredInitialFallback) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--x:20px", CascadeOrigin::kAuthor);
  cascade.Add("--x:revert", CascadeOrigin::kAuthor);
  cascade.Apply();

  EXPECT_EQ("0px", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, RevertRegisteredInheritedFallback) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", true);

  TestCascade parent(GetDocument());
  parent.Add("--x", "1px");
  parent.Apply();

  TestCascade cascade(GetDocument(), parent.TakeStyle());
  EXPECT_EQ("1px", cascade.ComputedValue("--x"));

  cascade.Add("--x:100px", CascadeOrigin::kAuthor);
  cascade.Add("--x:revert", CascadeOrigin::kAuthor);
  cascade.Apply();
  EXPECT_EQ("1px", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, RevertUASurrogate) {
  TestCascade cascade(GetDocument());

  // User-agent:

  // Only logical:
  cascade.Add("inline-size:10px", CascadeOrigin::kUserAgent);
  cascade.Add("min-inline-size:11px", CascadeOrigin::kUserAgent);
  // Only physical:
  cascade.Add("height:12px", CascadeOrigin::kUserAgent);
  cascade.Add("min-height:13px", CascadeOrigin::kUserAgent);
  // Physical first:
  cascade.Add("margin-left:14px", CascadeOrigin::kUserAgent);
  cascade.Add("padding-left:15px", CascadeOrigin::kUserAgent);
  cascade.Add("margin-inline-start:16px", CascadeOrigin::kUserAgent);
  cascade.Add("padding-inline-start:17px", CascadeOrigin::kUserAgent);
  // Logical first:
  cascade.Add("margin-inline-end:18px", CascadeOrigin::kUserAgent);
  cascade.Add("padding-inline-end:19px", CascadeOrigin::kUserAgent);
  cascade.Add("margin-right:20px", CascadeOrigin::kUserAgent);
  cascade.Add("padding-right:21px", CascadeOrigin::kUserAgent);

  // Author:

  cascade.Add("width:100px", CascadeOrigin::kAuthor);
  cascade.Add("height:101px", CascadeOrigin::kAuthor);
  cascade.Add("margin:102px", CascadeOrigin::kAuthor);
  cascade.Add("padding:103px", CascadeOrigin::kAuthor);
  cascade.Add("min-width:104px", CascadeOrigin::kAuthor);
  cascade.Add("min-height:105px", CascadeOrigin::kAuthor);
  // Revert via physical:
  cascade.Add("width:revert", CascadeOrigin::kAuthor);
  cascade.Add("height:revert", CascadeOrigin::kAuthor);
  cascade.Add("margin-left:revert", CascadeOrigin::kAuthor);
  cascade.Add("margin-right:revert", CascadeOrigin::kAuthor);
  // Revert via logical:
  cascade.Add("min-inline-size:revert", CascadeOrigin::kAuthor);
  cascade.Add("min-block-size:revert", CascadeOrigin::kAuthor);
  cascade.Add("padding-inline-start:revert", CascadeOrigin::kAuthor);
  cascade.Add("padding-inline-end:revert", CascadeOrigin::kAuthor);

  cascade.Apply();

  EXPECT_EQ("10px", cascade.ComputedValue("width"));
  EXPECT_EQ("12px", cascade.ComputedValue("height"));
  EXPECT_EQ("11px", cascade.ComputedValue("min-width"));
  EXPECT_EQ("13px", cascade.ComputedValue("min-height"));
  EXPECT_EQ("102px", cascade.ComputedValue("margin-top"));
  EXPECT_EQ("20px", cascade.ComputedValue("margin-right"));
  EXPECT_EQ("102px", cascade.ComputedValue("margin-bottom"));
  EXPECT_EQ("16px", cascade.ComputedValue("margin-left"));
  EXPECT_EQ("103px", cascade.ComputedValue("padding-top"));
  EXPECT_EQ("21px", cascade.ComputedValue("padding-right"));
  EXPECT_EQ("103px", cascade.ComputedValue("padding-bottom"));
  EXPECT_EQ("17px", cascade.ComputedValue("padding-left"));

  EXPECT_EQ("10px", cascade.ComputedValue("inline-size"));
  EXPECT_EQ("12px", cascade.ComputedValue("block-size"));
  EXPECT_EQ("11px", cascade.ComputedValue("min-inline-size"));
  EXPECT_EQ("13px", cascade.ComputedValue("min-block-size"));
  EXPECT_EQ("102px", cascade.ComputedValue("margin-block-start"));
  EXPECT_EQ("20px", cascade.ComputedValue("margin-inline-end"));
  EXPECT_EQ("102px", cascade.ComputedValue("margin-block-end"));
  EXPECT_EQ("16px", cascade.ComputedValue("margin-inline-start"));
  EXPECT_EQ("103px", cascade.ComputedValue("padding-block-start"));
  EXPECT_EQ("21px", cascade.ComputedValue("padding-inline-end"));
  EXPECT_EQ("103px", cascade.ComputedValue("padding-block-end"));
  EXPECT_EQ("17px", cascade.ComputedValue("padding-inline-start"));
}

TEST_F(StyleCascadeTest, RevertWithImportantPhysical) {
  TestCascade cascade(GetDocument());
  cascade.Add("inline-size:10px", CascadeOrigin::kUserAgent);
  cascade.Add("block-size:11px", CascadeOrigin::kUserAgent);

  cascade.Add("width:100px", CascadeOrigin::kAuthor);
  cascade.Add("height:101px", CascadeOrigin::kAuthor);
  cascade.Add("width:revert !important", CascadeOrigin::kAuthor);
  cascade.Add("inline-size:101px", CascadeOrigin::kAuthor);
  cascade.Add("block-size:102px", CascadeOrigin::kAuthor);
  cascade.Add("height:revert !important", CascadeOrigin::kAuthor);
  cascade.Apply();

  EXPECT_EQ("10px", cascade.ComputedValue("width"));
  EXPECT_EQ("11px", cascade.ComputedValue("height"));
  EXPECT_EQ("10px", cascade.ComputedValue("inline-size"));
  EXPECT_EQ("11px", cascade.ComputedValue("block-size"));
}

TEST_F(StyleCascadeTest, RevertWithImportantLogical) {
  TestCascade cascade(GetDocument());
  cascade.Add("inline-size:10px", CascadeOrigin::kUserAgent);
  cascade.Add("block-size:11px", CascadeOrigin::kUserAgent);

  cascade.Add("inline-size:revert !important", CascadeOrigin::kAuthor);
  cascade.Add("width:100px", CascadeOrigin::kAuthor);
  cascade.Add("height:101px", CascadeOrigin::kAuthor);
  cascade.Add("block-size:revert !important", CascadeOrigin::kAuthor);
  cascade.Apply();

  EXPECT_EQ("10px", cascade.ComputedValue("width"));
  EXPECT_EQ("11px", cascade.ComputedValue("height"));
  EXPECT_EQ("10px", cascade.ComputedValue("inline-size"));
  EXPECT_EQ("11px", cascade.ComputedValue("block-size"));
}

TEST_F(StyleCascadeTest, RevertSurrogateChain) {
  TestCascade cascade(GetDocument());

  cascade.Add("inline-size:revert", CascadeOrigin::kUserAgent);
  cascade.Add("block-size:10px", CascadeOrigin::kUserAgent);
  cascade.Add("min-inline-size:11px", CascadeOrigin::kUserAgent);
  cascade.Add("min-block-size:12px", CascadeOrigin::kUserAgent);
  cascade.Add("margin-inline:13px", CascadeOrigin::kUserAgent);
  cascade.Add("margin-block:14px", CascadeOrigin::kUserAgent);
  cascade.Add("margin-top:revert", CascadeOrigin::kUserAgent);
  cascade.Add("margin-left:15px", CascadeOrigin::kUserAgent);
  cascade.Add("margin-bottom:16px", CascadeOrigin::kUserAgent);
  cascade.Add("margin-block-end:17px", CascadeOrigin::kUserAgent);

  cascade.Add("inline-size:101px", CascadeOrigin::kUser);
  cascade.Add("block-size:102px", CascadeOrigin::kUser);
  cascade.Add("width:revert", CascadeOrigin::kUser);
  cascade.Add("height:revert", CascadeOrigin::kUser);
  cascade.Add("min-inline-size:103px", CascadeOrigin::kUser);
  cascade.Add("min-block-size:104px", CascadeOrigin::kUser);
  cascade.Add("margin:105px", CascadeOrigin::kUser);
  cascade.Add("margin-block-start:revert", CascadeOrigin::kUser);
  cascade.Add("margin-inline-start:106px", CascadeOrigin::kUser);
  cascade.Add("margin-block-end:revert", CascadeOrigin::kUser);
  cascade.Add("margin-right:107px", CascadeOrigin::kUser);

  cascade.Add("inline-size:revert", CascadeOrigin::kAuthor);
  cascade.Add("block-size:revert", CascadeOrigin::kAuthor);
  cascade.Add("min-inline-size:revert", CascadeOrigin::kAuthor);
  cascade.Add("min-block-size:1001px", CascadeOrigin::kAuthor);
  cascade.Add("margin:1002px", CascadeOrigin::kAuthor);
  cascade.Add("margin-top:revert", CascadeOrigin::kAuthor);
  cascade.Add("margin-left:1003px", CascadeOrigin::kAuthor);
  cascade.Add("margin-bottom:1004px", CascadeOrigin::kAuthor);
  cascade.Add("margin-right:1005px", CascadeOrigin::kAuthor);
  cascade.Apply();

  EXPECT_EQ("auto", cascade.ComputedValue("width"));
  EXPECT_EQ("10px", cascade.ComputedValue("height"));
  EXPECT_EQ("103px", cascade.ComputedValue("min-width"));
  EXPECT_EQ("1001px", cascade.ComputedValue("min-height"));
  EXPECT_EQ("0px", cascade.ComputedValue("margin-top"));
  EXPECT_EQ("1005px", cascade.ComputedValue("margin-right"));
  EXPECT_EQ("1004px", cascade.ComputedValue("margin-bottom"));
  EXPECT_EQ("1003px", cascade.ComputedValue("margin-left"));
}

TEST_F(StyleCascadeTest, RevertInKeyframe) {
  AppendSheet(R"HTML(
     @keyframes test {
        from { margin-left: 0px; }
        to { margin-left: revert; }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("margin-left:100px", CascadeOrigin::kUserAgent);
  cascade.Add("animation:test linear 1000s -500s");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();

  EXPECT_EQ("50px", cascade.ComputedValue("margin-left"));
}

TEST_F(StyleCascadeTest, RevertToCustomPropertyInKeyframe) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  AppendSheet(R"HTML(
     @keyframes test {
        from { --x: 0px; }
        to { --x: revert; }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("--x:100px", CascadeOrigin::kUser);
  cascade.Add("--x:1000px", CascadeOrigin::kAuthor);
  cascade.Add("animation:test linear 1000s -500s");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();

  EXPECT_EQ("50px", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, RevertToCustomPropertyInKeyframeUnset) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);
  RegisterProperty(GetDocument(), "--y", "<length>", "1000px", true);

  AppendSheet(R"HTML(
     @keyframes test {
        from { --x: 100px; --y: 100px; }
        to { --x: revert; --y: revert; }
     }
    )HTML");

  TestCascade parent(GetDocument());
  parent.Add("--y: 0px");
  parent.Apply();
  EXPECT_EQ("0px", parent.ComputedValue("--y"));

  TestCascade cascade(GetDocument(), parent.TakeStyle());
  cascade.Add("--x:10000px", CascadeOrigin::kAuthor);
  cascade.Add("--y:10000px", CascadeOrigin::kAuthor);
  cascade.Add("animation:test linear 1000s -500s");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();

  EXPECT_EQ("50px", cascade.ComputedValue("--x"));
  EXPECT_EQ("50px", cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, RevertToCustomPropertyInKeyframeEmptyInherit) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", true);

  AppendSheet(R"HTML(
     @keyframes test {
        from { --x: 100px; }
        to { --x: revert; }
     }
    )HTML");

  TestCascade cascade(GetDocument());
  cascade.Add("--x:10000px", CascadeOrigin::kAuthor);
  cascade.Add("animation:test linear 1000s -500s");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();

  EXPECT_EQ("50px", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, RevertInKeyframeResponsive) {
  AppendSheet(R"HTML(
     @keyframes test {
        from { margin-left: 0px; }
        to { margin-left: revert; }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("--x:100px", CascadeOrigin::kUser);
  cascade.Add("margin-left:var(--x)", CascadeOrigin::kUser);
  cascade.Add("animation:test linear 1000s -500s");
  cascade.Apply();
  cascade.AddInterpolations();
  cascade.Apply();

  EXPECT_EQ("50px", cascade.ComputedValue("margin-left"));

  cascade.Reset();
  cascade.Add("--x:100px", CascadeOrigin::kUser);
  cascade.Add("margin-left:var(--x)", CascadeOrigin::kUser);
  cascade.Add("animation:test linear 1000s -500s");
  cascade.Add("--x:80px", CascadeOrigin::kAuthor);
  cascade.Apply();
  cascade.AddInterpolations();
  cascade.Apply();

  EXPECT_EQ("40px", cascade.ComputedValue("margin-left"));
}

TEST_F(StyleCascadeTest, RevertToCycleInKeyframe) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  AppendSheet(R"HTML(
     @keyframes test {
        from { --x: 100px; }
        to { --x: revert; }
     }
    )HTML");

  TestCascade cascade(GetDocument());

  cascade.Add("--x:var(--y)", CascadeOrigin::kUser);
  cascade.Add("--y:var(--x)", CascadeOrigin::kUser);
  cascade.Add("--x:200px", CascadeOrigin::kAuthor);
  cascade.Add("animation:test linear 1000s -500s");
  cascade.Apply();

  cascade.AddInterpolations();
  cascade.Apply();

  EXPECT_EQ("0px", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, RevertCausesTransition) {
  UpdateAllLifecyclePhasesForTest();

  TestCascade cascade1(GetDocument());
  cascade1.Add("width:200px", CascadeOrigin::kUser);
  cascade1.Add("width:100px", CascadeOrigin::kAuthor);
  cascade1.Add("transition: width 1000s steps(2, end)", CascadeOrigin::kAuthor);
  cascade1.Apply();

  GetDocument().body()->SetComputedStyle(cascade1.TakeStyle());

  // Now simulate a new style, with new color values.
  TestCascade cascade2(GetDocument());
  cascade2.Add("width:200px", CascadeOrigin::kUser);
  cascade2.Add("width:100px", CascadeOrigin::kAuthor);
  cascade2.Add("width:revert", CascadeOrigin::kAuthor);
  cascade2.Add("transition: width 1000s steps(2, start)",
               CascadeOrigin::kAuthor);
  cascade2.Apply();

  cascade2.AddInterpolations();
  cascade2.Apply();

  EXPECT_EQ("150px", cascade2.ComputedValue("width"));
}

TEST_F(StyleCascadeTest, CSSWideKeywordsInFallbacks) {
  {
    TestCascade cascade(GetDocument());
    cascade.Add("display:var(--u,initial)");
    cascade.Add("margin:var(--u,initial)");
    cascade.Apply();
  }
  {
    TestCascade cascade(GetDocument());
    cascade.Add("display:var(--u,inherit)");
    cascade.Add("margin:var(--u,inherit)");
    cascade.Apply();
  }
  {
    TestCascade cascade(GetDocument());
    cascade.Add("display:var(--u,unset)");
    cascade.Add("margin:var(--u,unset)");
    cascade.Apply();
  }
  {
    TestCascade cascade(GetDocument());
    cascade.Add("display:var(--u,revert)");
    cascade.Add("margin:var(--u,revert)");
    cascade.Apply();
  }

  // TODO(crbug.com/1105782): Specs and WPT are currently in conflict
  // regarding the correct behavior here. For now this test just verifies
  // that we don't crash.
}

TEST_F(StyleCascadeTest, RegisteredInitial) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Apply();
  EXPECT_EQ("0px", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, SubstituteRegisteredImplicitInitialValue) {
  RegisterProperty(GetDocument(), "--x", "<length>", "13px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--y", " var(--x) ");
  cascade.Apply();
  EXPECT_EQ("13px", cascade.ComputedValue("--x"));
  EXPECT_EQ("13px", cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, SubstituteRegisteredUniversal) {
  RegisterProperty(GetDocument(), "--x", "*", "foo", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--x", "bar");
  cascade.Add("--y", "var(--x)");
  cascade.Apply();
  EXPECT_EQ("bar", cascade.ComputedValue("--x"));
  EXPECT_EQ("bar", cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, SubstituteRegisteredUniversalInvalid) {
  RegisterProperty(GetDocument(), "--x", "*", std::nullopt, false);

  TestCascade cascade(GetDocument());
  cascade.Add("--y", " var(--x) ");
  cascade.Apply();
  EXPECT_FALSE(cascade.ComputedValue("--x"));
  EXPECT_FALSE(cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, SubstituteRegisteredUniversalInitial) {
  RegisterProperty(GetDocument(), "--x", "*", "foo", false);

  TestCascade cascade(GetDocument());
  casca
"""


```
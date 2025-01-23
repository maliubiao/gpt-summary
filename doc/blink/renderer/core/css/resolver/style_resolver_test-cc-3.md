Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of a larger file `style_resolver_test.cc` in the Chromium Blink engine. The request asks for:

1. **General functionality:** What does this code do?
2. **Relevance to web technologies:** How does it relate to JavaScript, HTML, and CSS?
3. **Logical reasoning:** Can I infer input and output behavior?
4. **Common errors:** What mistakes might users or programmers make?
5. **User steps to reach this code:** How does a user's interaction lead to this part of the code?
6. **Overall function (for this part):** A concise summary of the functionality within this specific snippet.

**Analysis of the Code Snippet:**

The code consists primarily of a series of C++ test functions (`TEST_F`) within a test fixture (`StyleResolverTest`). These tests are designed to verify the behavior of the style resolution process in Blink, particularly focusing on:

* **Legacy CSS property handling:** Tests related to `-webkit-` prefixed properties and their interaction with standard properties (e.g., `transform-origin`, `border-image`, `border-image-width`). The tests check if a use counter is incremented when the legacy property is used in a way that overrides or differs from the standard property.
* **`@position-try` rule and `position-try-fallbacks` property:** Tests how these features, which allow for specifying fallback positioning styles, are resolved and cascaded. This includes testing with logical properties, relative length units, pseudo-elements, CSS-wide keywords, and dynamic property changes.
* **`try-set` feature:** Tests how temporary style declarations (`try_set`) affect style resolution, particularly in the context of absolute positioning and the `revert` and `revert-layer` keywords.
* **`try-tactics-set` feature:** Tests the application of transformations to property values during the try-set process (e.g., flipping `left` and `right`).
* **Interaction between animations and style changes:** Tests a scenario where a style change on an element with an animated pseudo-element should trigger a full style recalc, not just an animation style recalc.
* **Container Query Units Context:** Tests that the style resolver correctly captures the container's dimensions when resolving container query units.
* **Scoped Anchor Names and Position Anchors:** Tests the resolution of `anchor-name` and `position-anchor` properties, including how scoping works within shadow DOM.
* **`anchor()` and `anchor-size()` functions:** Tests whether the style resolver correctly identifies the presence of these functions in CSS property values.
* **`CanAffectAnimations()` method:** Tests the `CanAffectAnimations()` method, particularly in the context of container queries.
* **`@starting-style` rule:** Tests that the style resolver considers styles defined within `@starting-style` rules, even when the element is initially hidden.

**Planning the Response:**

I will structure the response by addressing each point in the user's request.

1. **Functionality:** Describe the code as a set of unit tests for the style resolver, specifically testing legacy property handling, `@position-try`, `try-set`, `try-tactics-set`, animation interactions, container queries, anchor positioning, and `@starting-style`.
2. **Web technologies:** Explain how each tested feature relates to CSS. For example, the legacy property tests relate to browser compatibility, `@position-try` and `try-set` are newer CSS features for advanced layout, and anchor positioning is a recent addition.
3. **Logical reasoning:** For a few key test cases (e.g., legacy property overriding, basic `@position-try` usage), provide simple examples of the HTML/CSS and the expected computed style.
4. **Common errors:**  Point out common CSS authoring mistakes that these tests aim to prevent or detect, such as incorrect usage of legacy properties, typos in property names, or misunderstanding the cascading order.
5. **User steps:** Explain how a user writing CSS that utilizes these features (or makes mistakes with them) will cause the browser's style engine to engage the style resolver, potentially triggering these tests during development.
6. **Overall function:** Summarize the code as testing the correctness and robustness of the style resolver's logic, ensuring it handles various CSS features and edge cases as expected.
这是 `blink/renderer/core/css/resolver/style_resolver_test.cc` 文件的第 4 部分，主要关注的是 **CSS 属性解析器** 的测试，特别是针对一些较新的或者有特殊行为的 CSS 功能进行验证。

以下是根据代码片段进行的功能归纳和说明：

**主要功能归纳：**

这部分测试主要验证了 `StyleResolver` 在处理以下 CSS 特性时的正确性：

* **与遗留 `-webkit-` 前缀属性的交互:**  测试当同时存在标准属性和带有 `-webkit-` 前缀的旧版本属性时，`StyleResolver` 的行为，特别是关于 `transform-origin` 和 `border-image` 的处理。它会检查在什么情况下会记录 `WebFeature` 的使用情况，以帮助 Chromium 团队跟踪这些遗留特性的使用情况。
* **`@position-try` 规则和 `position-try-fallbacks` 属性:** 测试了 CSS 定位尝试回退机制。验证了当主定位属性无法应用时，`StyleResolver` 如何按照 `position-try-fallbacks` 中定义的顺序尝试应用 `@position-try` 规则中的样式。这包括对逻辑属性、相对长度单位、伪元素和 CSS 关键字的支持。
* **`try-set` 特性:** 测试了一种临时的样式应用机制，允许在不修改原始样式的情况下，尝试应用一组新的样式声明。这主要用于测试布局或渲染的替代方案，并涉及到 `revert` 和 `revert-layer` 关键字的行为。
* **`try-tactics-set` 特性:** 测试了在 `try-set` 的基础上，可以定义一些策略来转换或修改尝试应用的属性值，例如可以定义一个策略来“翻转” `left` 和 `right` 的值。
* **动画和样式更改的交互:** 测试了当伪元素有动画效果时，其关联的原始元素样式发生变化时，`StyleResolver` 是否能正确处理并触发必要的样式重算。
* **容器查询单元上下文:** 验证了在处理容器查询相关的单位（例如 `cqw`, `cqh`）时，`StyleResolver` 能否正确获取容器的尺寸信息。
* **作用域内的锚点名称和位置锚点:** 测试了 `anchor-name` 和 `position-anchor` 属性在 Shadow DOM 中的作用域规则，确保 `StyleResolver` 能正确解析和关联锚点元素。
* **`anchor()` 和 `anchor-size()` 函数:**  测试了 `StyleResolver` 是否能识别 CSS 属性值中是否使用了 `anchor()` 和 `anchor-size()` 函数。
* **`CanAffectAnimations()` 方法:** 测试了 `StyleResolver` 的 `CanAffectAnimations()` 方法，该方法用于判断一个元素的样式是否会影响动画效果，特别是在容器查询的上下文中。
* **`@starting-style` 规则:** 测试了 `@starting-style` 规则，该规则定义了元素在特定状态（例如，从 `display: none` 变为可见）时的起始样式。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **CSS:**  这部分测试直接针对 CSS 的解析和应用。
    * **遗留属性:**  浏览器会解析类似 `-webkit-transform-origin` 这样的 CSS 属性。测试确保当标准属性 `transform-origin` 也存在时，浏览器能按预期处理，并统计遗留属性的使用。
    * **`@position-try` 和 `position-try-fallbacks`:** 这些是新的 CSS 功能，允许开发者定义更灵活的定位策略。例如，开发者可以使用：
      ```css
      @position-try --fallback1 { top: 100px; left: 50px; }
      #element {
        position: absolute;
        position-try-fallbacks: --fallback1;
        /* 如果默认定位导致元素超出屏幕等问题，浏览器会尝试应用 --fallback1 的样式 */
      }
      ```
    * **`try-set`:**  这是一个 Blink 内部的测试机制，但在某些实验性的 Web API 中可能存在类似的概念。从开发者角度，他们编写 CSS，而 `try-set` 可以在内部模拟不同的样式状态。
    * **容器查询:**  测试验证了 `StyleResolver` 能否正确处理容器查询单元，这与 CSS 容器查询特性直接相关。例如：
      ```css
      #container {
        container-type: size;
      }
      #element {
        width: 50cqw; /* 元素的宽度是容器宽度的 50% */
      }
      ```
    * **锚点定位:**  `anchor-name` 和 `position-anchor` 属性以及 `anchor()` 函数是 CSS 锚点定位规范的一部分，允许一个元素相对于另一个“锚点”元素进行定位。
      ```css
      #anchor {
        anchor-name: --my-anchor;
      }
      #positioned {
        position: absolute;
        top: anchor(--my-anchor bottom); /* positioned 元素的顶部与锚点元素的底部对齐 */
        left: anchor(--my-anchor right); /* positioned 元素的左边与锚点元素的右边对齐 */
      }
      ```
    * **`@starting-style`:** 这是一个 CSS 功能，用于定义元素在从某些状态（如隐藏）变为可见时的初始样式，从而实现平滑的过渡效果。

* **HTML:** HTML 提供了结构，CSS 样式会应用到 HTML 元素上。测试代码中的 `SetBodyInnerHTML` 方法用于设置测试所需的 HTML 结构。例如，在测试 `@position-try` 时，会创建一个带有特定 ID 的 `div` 元素作为目标。

* **JavaScript:** 虽然这个测试文件是 C++ 的，但它测试的 CSS 功能通常会与 JavaScript 交互。例如，JavaScript 可以动态修改元素的 CSS 类名或样式属性，这会触发 `StyleResolver` 的工作。在测试中，并没有直接的 JavaScript 代码，而是通过 C++ 代码模拟了样式变化。

**逻辑推理、假设输入与输出：**

**例子 1: 遗留属性 `transform-origin`**

* **假设输入 HTML/CSS:**
  ```html
  <style>
    div {
      transform-origin: 1px 2px 3px;
      -webkit-transform-origin-x: 4px;
    }
  </style>
  <div>target</div>
  ```
* **预期输出 (测试结果):**  `IsUseCounted(WebFeature::kCSSLegacyTransformOrigin)` 返回 `true`，因为 `-webkit-transform-origin-x` 的值与标准属性 `transform-origin` 的 x 分量不同，所以会记录遗留特性的使用。

**例子 2: `@position-try` 和 `position-try-fallbacks`**

* **假设输入 HTML/CSS:**
  ```html
  <style>
    @position-try --f1 { left: 100px; }
    #target {
      position: absolute;
      position-try-fallbacks: --f1;
    }
  </style>
  <div id="target"></div>
  ```
* **预期输出 (测试结果):** 在没有其他定位属性冲突的情况下，`target` 元素的计算样式中 `left` 属性的值会是 `100px`。

**涉及用户或者编程常见的使用错误及举例说明：**

* **遗留属性使用不当:** 开发者可能错误地认为 `-webkit-` 前缀的属性优先级更高，或者混淆了它们与标准属性的行为差异。例如，只写了 `-webkit-transform-origin-x` 而没有完整的 `transform-origin`。
* **`@position-try` 和 `position-try-fallbacks` 的逻辑错误:**  开发者可能错误地设置回退顺序，或者在 `@position-try` 规则中定义了不适用的属性，导致回退机制无法按预期工作。
* **`try-set` 的误用:**  虽然 `try-set` 主要用于内部测试，但如果开发者在实验性 API 中遇到类似概念，可能会错误地理解其作用域和生命周期。
* **容器查询单元上下文错误:** 开发者可能在非容器元素的子元素中使用容器查询单元，导致这些单元无法解析或解析结果不符合预期。
* **锚点定位错误:**  可能会出现循环依赖的锚点关系，或者锚点元素在布局过程中不可用，导致定位失败。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 HTML, CSS 和可能的 JavaScript 代码。** 比如，用户使用了 `position: absolute` 和 `position-try-fallbacks` 来尝试实现一种复杂的布局。
2. **浏览器加载并解析这些代码。**  当浏览器解析到 CSS 规则时，`StyleResolver` 会被调用来确定元素的最终样式。
3. **`StyleResolver` 在解析 `position-try-fallbacks` 时，会查找对应的 `@position-try` 规则。**
4. **如果布局出现问题，或者开发者在调试工具中检查元素的计算样式，他们可能会发现样式没有按预期应用。**
5. **Blink 开发者在开发或调试 `StyleResolver` 的相关功能时，会运行这些单元测试。** 如果测试失败，则表明 `StyleResolver` 在处理特定 CSS 场景时存在 bug。
6. **例如，如果用户发现使用了 `-webkit-border-image` 后，某些边框样式没有正确显示，Blink 开发者可能会检查 `LegacyOverlapBorderImage_*` 相关的测试，看是否有测试覆盖了这种情况，或者需要添加新的测试来复现和修复 bug。**

**总结一下它的功能:**

这部分 `style_resolver_test.cc` 的功能是 **系统地测试 Blink 引擎中 `StyleResolver` 组件在处理一系列复杂和新兴 CSS 特性时的正确性和健壮性**。它通过编写各种具有特定 CSS 场景的 HTML 代码，并断言 `StyleResolver` 的输出（例如，计算样式、WebFeature 的使用计数）是否符合预期，来确保 Blink 能够正确地解释和应用这些 CSS 规则。 这对于保证浏览器的兼容性、稳定性和对新 Web 标准的支持至关重要。

### 提示词
```
这是目录为blink/renderer/core/css/resolver/style_resolver_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
3px;
          -webkit-transform-origin-x: 1px;
          -webkit-transform-origin-y: 2px;
          -webkit-transform-origin-z: 3px;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSLegacyTransformOrigin))
      << "Not counted when values are the same";
}

TEST_F(StyleResolverTest, LegacyOverlapTransformOrigin_Last) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          transform-origin: 1px 2px 3px;
          -webkit-transform-origin-x: 4px;
          -webkit-transform-origin-y: 5px;
          -webkit-transform-origin-z: 6px;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSLegacyTransformOrigin))
      << "Counted when -webkit-transform-origin-* is last with different "
         "values";
}

TEST_F(StyleResolverTest, LegacyOverlapBorderImage_Single) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          border-image: url("#a") 1 fill / 2 / 3 round;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSLegacyBorderImage))
      << "Not counted when only border-image is used";
}

TEST_F(StyleResolverTest, LegacyOverlapBorderImage_Order) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          -webkit-border-image: url("#b") 2 fill / 3 / 4 round;
          border-image: url("#a") 1 fill / 2 / 3 round;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSLegacyBorderImage))
      << "Not counted when border-image is last";
}

TEST_F(StyleResolverTest, LegacyOverlapBorderImage_Values) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          border-image: url("#a") 1 fill / 2 / 3 round;
          -webkit-border-image: url("#a") 1 fill / 2 / 3 round;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSLegacyBorderImage))
      << "Not counted when values are the same";
}

TEST_F(StyleResolverTest, LegacyOverlapBorderImage_Last_Source) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          border-image: url("#a") 1 fill / 2 / 3 round;
          -webkit-border-image: url("#b") 1 fill / 2 / 3 round;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSLegacyBorderImage))
      << "Counted when border-image-source differs";
}

TEST_F(StyleResolverTest, LegacyOverlapBorderImage_Last_Slice) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          border-image: url("#a") 1 fill / 2 / 3 round;
          -webkit-border-image: url("#a") 2 fill / 2 / 3 round;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSLegacyBorderImage))
      << "Counted when border-image-slice differs";
}

TEST_F(StyleResolverTest, LegacyOverlapBorderImage_Last_SliceFill) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          border-image: url("#a") 1 / 2 / 3 round;
          -webkit-border-image: url("#a") 1 fill / 2 / 3 round;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSLegacyBorderImage))
      << "Counted when the fill keyword of border-image-slice differs";
}

TEST_F(StyleResolverTest, LegacyOverlapBorderImage_SliceFillImplicit) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          border-image: url("#a") 1 / 2 / 3 round;
          -webkit-border-image: url("#a") 1 / 2 / 3 round;
        }
      </style>
      <div>target</div>
    )HTML");
  // Note that -webkit-border-image implicitly adds "fill", but
  // border-image does not.
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSLegacyBorderImage))
      << "Counted when fill-less values are the same";
}

TEST_F(StyleResolverTest, LegacyOverlapBorderImage_Last_Width) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          border-image: url("#a") 1 fill / 2 / 3 round;
          -webkit-border-image: url("#a") 1 fill / 5 / 3 round;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSLegacyBorderImage))
      << "Counted when border-image-slice differs";
}

TEST_F(StyleResolverTest, LegacyOverlapBorderImage_Last_Outset) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          border-image: url("#a") 1 fill / 2 / 3 round;
          -webkit-border-image: url("#a") 1 fill / 2 / 5 round;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSLegacyBorderImage))
      << "Counted when border-image-outset differs";
}

TEST_F(StyleResolverTest, LegacyOverlapBorderImage_Last_Repeat) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          border-image: url("#a") 1 fill / 2 / 3 round;
          -webkit-border-image: url("#a") 1 fill / 2 / 3 space;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSLegacyBorderImage))
      << "Counted when border-image-repeat differs";
}

TEST_F(StyleResolverTest, LegacyOverlapBorderImageWidth_Single) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div {
        border: 1px solid black;
      }
    </style>
    <div>target</div>
  )HTML");
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSLegacyBorderImageWidth))
      << "Not counted when only border is used";
}

TEST_F(StyleResolverTest, LegacyOverlapBorderImageWidth_Order) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div {
        -webkit-border-image: url("#b") 2 fill / 3px / 4 round;
        border: 1px solid black;
      }
    </style>
    <div>target</div>
  )HTML");
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSLegacyBorderImageWidth))
      << "Not counted when border is last";
}

TEST_F(StyleResolverTest, LegacyOverlapBorderImageWidth_Values) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div {
        border: 1px solid black;
        -webkit-border-image: url("#b") 2 fill / 1px / 4 round;
      }
    </style>
    <div>target</div>
  )HTML");
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSLegacyBorderImageWidth))
      << "Not counted when values are the same";
}

TEST_F(StyleResolverTest, LegacyOverlapBorderImageWidth_Last_Border) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          border: 1px solid black;
          -webkit-border-image: url("#a") 1 fill / 2px / 3 round;
        }
      </style>
      <div>target</div>
    )HTML");
  // Since -webkit-border-image also sets border-width, we would normally
  // expect TRUE here. However, StyleCascade always applies
  // -webkit-border-image *first*, and does not do anything to prevent
  // border-width properties from also being applied. Hence border-width
  // always wins.
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSLegacyBorderImageWidth))
      << "Not even counted when -webkit-border-image is last";
}

TEST_F(StyleResolverTest, LegacyOverlapBorderImageWidth_Last_Style) {
  // Note that border-style is relevant here because the used border-width
  // is 0px if we don'y have any border-style. See e.g.
  // ComputedStyle::BorderLeftWidth.
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          border-style: solid;
          -webkit-border-image: url("#b") 1 fill / 2px / 3 round;
        }
      </style>
      <div>target</div>
    )HTML");
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSLegacyBorderImageWidth))
      << "Counted when -webkit-border-image is last and there's no "
         "border-width";
}

TEST_F(StyleResolverTest, PositionTryStylesBasic_Cascade) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @position-try --f1 { left: 100px; }
      @position-try --f2 { top: 100px; }
      @position-try --f3 { inset: 50px; }
      #target {
        position: absolute;
        position-try-fallbacks: --f1, --f2, --f3;
      }
    </style>
    <div id="target"></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  Element* target = GetElementById("target");
  const ComputedStyle* base_style = target->GetComputedStyle();
  ASSERT_TRUE(base_style);
  EXPECT_EQ(Length::Auto(), GetTop(*base_style));
  EXPECT_EQ(Length::Auto(), GetLeft(*base_style));

  UpdateStyleForOutOfFlow(*target, AtomicString("--f1"));
  const ComputedStyle* try1 = target->GetComputedStyle();
  ASSERT_TRUE(try1);
  EXPECT_EQ(Length::Auto(), GetTop(*try1));
  EXPECT_EQ(Length::Fixed(100), GetLeft(*try1));

  UpdateStyleForOutOfFlow(*target, AtomicString("--f2"));
  const ComputedStyle* try2 = target->GetComputedStyle();
  ASSERT_TRUE(try2);
  EXPECT_EQ(Length::Fixed(100), GetTop(*try2));
  EXPECT_EQ(Length::Auto(), GetLeft(*try2));

  // Shorthand should also work
  UpdateStyleForOutOfFlow(*target, AtomicString("--f3"));
  const ComputedStyle* try3 = target->GetComputedStyle();
  ASSERT_TRUE(try3);
  EXPECT_EQ(Length::Fixed(50), GetTop(*try3));
  EXPECT_EQ(Length::Fixed(50), GetLeft(*try3));
  EXPECT_EQ(Length::Fixed(50), GetBottom(*try3));
  EXPECT_EQ(Length::Fixed(50), GetRight(*try3));
}

TEST_F(StyleResolverTest, PositionTryStylesResolveLogicalProperties_Cascade) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @position-try --f1 { inset-inline-start: 100px; }
      @position-try --f2 { inset-block: 100px 90px; }
      #target {
        position: absolute;
        writing-mode: vertical-rl;
        direction: rtl;
        inset: 50px;
        position-try-fallbacks: --f1, --f2;
      }
    </style>
    <div id="target"></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  Element* target = GetElementById("target");
  const ComputedStyle* base_style = target->GetComputedStyle();
  ASSERT_TRUE(base_style);
  EXPECT_EQ(Length::Fixed(50), GetTop(*base_style));
  EXPECT_EQ(Length::Fixed(50), GetLeft(*base_style));
  EXPECT_EQ(Length::Fixed(50), GetBottom(*base_style));
  EXPECT_EQ(Length::Fixed(50), GetRight(*base_style));

  // 'inset-inline-start' should resolve to 'bottom'
  UpdateStyleForOutOfFlow(*target, AtomicString("--f1"));
  const ComputedStyle* try1 = target->GetComputedStyle();
  ASSERT_TRUE(try1);
  EXPECT_EQ(Length::Fixed(50), GetTop(*try1));
  EXPECT_EQ(Length::Fixed(50), GetLeft(*try1));
  EXPECT_EQ(Length::Fixed(100), GetBottom(*try1));
  EXPECT_EQ(Length::Fixed(50), GetRight(*try1));

  // 'inset-block' with two parameters should set 'right' and then 'left'
  UpdateStyleForOutOfFlow(*target, AtomicString("--f2"));
  const ComputedStyle* try2 = target->GetComputedStyle();
  ASSERT_TRUE(try2);
  EXPECT_EQ(Length::Fixed(50), GetTop(*try2));
  EXPECT_EQ(Length::Fixed(90), GetLeft(*try2));
  EXPECT_EQ(Length::Fixed(50), GetBottom(*try2));
  EXPECT_EQ(Length::Fixed(100), GetRight(*try2));
}

TEST_F(StyleResolverTest, PositionTryStylesResolveRelativeLengthUnits_Cascade) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @position-try --f1 { top: 2em; }
      #target {
        position: absolute;
        font-size: 20px;
        position-try-fallbacks: --f1;
      }
    </style>
    <div id="target"></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  Element* target = GetElementById("target");
  const ComputedStyle* base_style = target->GetComputedStyle();
  ASSERT_TRUE(base_style);
  EXPECT_EQ(Length::Auto(), GetTop(*base_style));

  // '2em' should resolve to '40px'
  UpdateStyleForOutOfFlow(*target, AtomicString("--f1"));
  const ComputedStyle* try1 = target->GetComputedStyle();
  ASSERT_TRUE(try1);
  EXPECT_EQ(Length::Fixed(40), GetTop(*try1));
}

TEST_F(StyleResolverTest, PositionTryStylesInBeforePseudoElement_Cascade) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @position-try --f1 { top: 50px; }
      #target::before {
        display: block;
        content: 'before';
        position: absolute;
        position-try-fallbacks: --f1;
      }
    </style>
    <div id="target"></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  Element* target = GetElementById("target");
  Element* before = target->GetPseudoElement(kPseudoIdBefore);
  ASSERT_TRUE(before);

  const ComputedStyle* base_style = before->GetComputedStyle();
  ASSERT_TRUE(base_style);
  EXPECT_EQ(Length::Auto(), GetTop(*base_style));

  // 'position-try-fallbacks' applies to ::before pseudo-element.
  UpdateStyleForOutOfFlow(*before, AtomicString("--f1"));
  const ComputedStyle* try1 = before->GetComputedStyle();
  ASSERT_TRUE(try1);
  EXPECT_EQ(Length::Fixed(50), GetTop(*try1));
}

TEST_F(StyleResolverTest, PositionTryStylesCSSWideKeywords_Cascade) {
  SetBodyInnerHTML(R"HTML(
    <style>
      /* 'revert' and 'revert-layer' are already rejected by parser */
      @position-try --f1 { top: initial }
      @position-try --f2 { left: inherit }
      @position-try --f3 { right: unset }
      #target {
        position: absolute;
        inset: 50px;
        position-try-fallbacks: --f1, --f2, --f3;
      }
      #container {
        position: absolute;
        inset: 100px;
      }
    </style>
    <div id="container">
      <div id="target"></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  Element* target = GetElementById("target");
  const ComputedStyle* base_style = target->GetComputedStyle();
  ASSERT_TRUE(base_style);
  EXPECT_EQ(Length::Fixed(50), GetTop(*base_style));
  EXPECT_EQ(Length::Fixed(50), GetLeft(*base_style));
  EXPECT_EQ(Length::Fixed(50), GetBottom(*base_style));
  EXPECT_EQ(Length::Fixed(50), GetRight(*base_style));

  UpdateStyleForOutOfFlow(*target, AtomicString("--f1"));
  const ComputedStyle* try1 = target->GetComputedStyle();
  ASSERT_TRUE(try1);
  EXPECT_EQ(Length::Auto(), GetTop(*try1));
  EXPECT_EQ(Length::Fixed(50), GetLeft(*try1));
  EXPECT_EQ(Length::Fixed(50), GetBottom(*try1));
  EXPECT_EQ(Length::Fixed(50), GetRight(*try1));

  UpdateStyleForOutOfFlow(*target, AtomicString("--f2"));
  const ComputedStyle* try2 = target->GetComputedStyle();
  ASSERT_TRUE(try2);
  EXPECT_EQ(Length::Fixed(50), GetTop(*try2));
  EXPECT_EQ(Length::Fixed(100), GetLeft(*try2));
  EXPECT_EQ(Length::Fixed(50), GetBottom(*try2));
  EXPECT_EQ(Length::Fixed(50), GetRight(*try2));

  UpdateStyleForOutOfFlow(*target, AtomicString("--f3"));
  const ComputedStyle* try3 = target->GetComputedStyle();
  ASSERT_TRUE(try3);
  EXPECT_EQ(Length::Fixed(50), GetTop(*try3));
  EXPECT_EQ(Length::Fixed(50), GetLeft(*try3));
  EXPECT_EQ(Length::Fixed(50), GetBottom(*try3));
  EXPECT_EQ(Length::Auto(), GetRight(*try3));
}

TEST_F(StyleResolverTest, PositionTryPropertyValueChange_Cascade) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @position-try --foo { top: 100px }
      @position-try --bar { left: 100px }
      #target {
        position: absolute;
        position-try-fallbacks: --foo;
      }
    </style>
    <div id="target"></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  Element* target = GetElementById("target");

  {
    const ComputedStyle* base_style = target->GetComputedStyle();
    ASSERT_TRUE(base_style);
    EXPECT_EQ(Length::Auto(), GetTop(*base_style));
    EXPECT_EQ(Length::Auto(), GetLeft(*base_style));

    UpdateStyleForOutOfFlow(*target, AtomicString("--foo"));
    const ComputedStyle* fallback = target->GetComputedStyle();
    ASSERT_TRUE(fallback);
    EXPECT_EQ(Length::Fixed(100), GetTop(*fallback));
    EXPECT_EQ(Length::Auto(), GetLeft(*fallback));
  }

  target->SetInlineStyleProperty(CSSPropertyID::kPositionTryFallbacks, "--bar");
  UpdateAllLifecyclePhasesForTest();

  {
    const ComputedStyle* base_style = target->GetComputedStyle();
    ASSERT_TRUE(base_style);
    EXPECT_EQ(Length::Auto(), GetTop(*base_style));
    EXPECT_EQ(Length::Auto(), GetLeft(*base_style));

    UpdateStyleForOutOfFlow(*target, AtomicString("--bar"));
    const ComputedStyle* fallback = target->GetComputedStyle();
    ASSERT_TRUE(fallback);
    ASSERT_TRUE(fallback);
    EXPECT_EQ(Length::Auto(), GetTop(*fallback));
    EXPECT_EQ(Length::Fixed(100), GetLeft(*fallback));
  }
}

TEST_F(StyleResolverTest, PositionTry_PaintInvalidation) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @position-try --f1 { left: 2222222px; }
      @position-try --f2 { left: 3333333px; }
      @position-try --f3 { top: 100px; left: 0; }
      #target {
        position: absolute;
        left: 1111111px;
        position-try-fallbacks: --f1, --f2, --f3;
      }
    </style>
    <div id="target"></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  Element* target = GetElementById("target");
  const ComputedStyle* style = target->GetComputedStyle();
  ASSERT_TRUE(style);
  EXPECT_EQ(Length::Fixed(100), GetTop(*style));
  EXPECT_EQ(Length::Fixed(0), GetLeft(*style));

  EXPECT_FALSE(target->GetLayoutObject()->NeedsLayout());

  // Invalidate paint (but not layout).
  target->SetInlineStyleProperty(CSSPropertyID::kBackgroundColor, "green");
  target->GetDocument().UpdateStyleAndLayoutTreeForThisDocument();

  EXPECT_FALSE(target->GetLayoutObject()->NeedsLayout());
  EXPECT_TRUE(target->GetLayoutObject()->ShouldCheckForPaintInvalidation());
}

TEST_F(StyleResolverTest, TrySet_Basic) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div {
        position: absolute;
        left: 10px;
      }
    </style>
    <div id=div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetElementById("div");
  ASSERT_TRUE(div);
  EXPECT_EQ("10px", ComputedValue("left", div->ComputedStyleRef()));
  EXPECT_EQ("auto", ComputedValue("right", div->ComputedStyleRef()));

  // Resolving a style with some try set stored on Element,
  // should cause that set to be added to the cascade.

  const CSSPropertyValueSet* try_set =
      css_test_helpers::ParseDeclarationBlock(R"CSS(
      left: 20px;
      right: 30px;
  )CSS");
  ASSERT_TRUE(try_set);

  const ComputedStyle* try_style = StyleForId(
      "div",
      StyleRecalcContext{.try_set = try_set, .is_interleaved_oof = true});
  ASSERT_TRUE(try_style);
  EXPECT_EQ("20px", ComputedValue("left", *try_style));
  EXPECT_EQ("30px", ComputedValue("right", *try_style));
}

TEST_F(StyleResolverTest, TrySet_RevertLayer) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div {
        position: absolute;
        left: 10px;
      }
    </style>
    <div id=div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetElementById("div");
  ASSERT_TRUE(div);

  // Declarations from the try set should appear in a separate layer.

  const CSSPropertyValueSet* try_set =
      css_test_helpers::ParseDeclarationBlock(R"CSS(
      left: revert-layer;
      right: 30px;
  )CSS");
  ASSERT_TRUE(try_set);

  const ComputedStyle* try_style = StyleForId(
      "div",
      StyleRecalcContext{.try_set = try_set, .is_interleaved_oof = true});
  ASSERT_TRUE(try_style);
  EXPECT_EQ("10px", ComputedValue("left", *try_style));
  EXPECT_EQ("30px", ComputedValue("right", *try_style));
}

TEST_F(StyleResolverTest, TrySet_Revert) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div {
        position: absolute;
        left: 10px;
      }
    </style>
    <div id=div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetElementById("div");
  ASSERT_TRUE(div);

  // Declarations from the try set should appear in the author origin.

  const CSSPropertyValueSet* try_set =
      css_test_helpers::ParseDeclarationBlock(R"CSS(
      left: revert;
      right: 30px;
  )CSS");
  ASSERT_TRUE(try_set);

  const ComputedStyle* try_style = StyleForId(
      "div",
      StyleRecalcContext{.try_set = try_set, .is_interleaved_oof = true});
  ASSERT_TRUE(try_style);
  EXPECT_EQ("auto", ComputedValue("left", *try_style));
  EXPECT_EQ("30px", ComputedValue("right", *try_style));
}

TEST_F(StyleResolverTest, TrySet_NonAbsPos) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div {
        position: static;
        left: 10px;
      }
    </style>
    <div id=div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetElementById("div");
  ASSERT_TRUE(div);

  // Declarations from the try set should only apply when absolutely positioned.
  // If not absolutely positioned, they should behave as 'revert-layer'.

  const CSSPropertyValueSet* try_set =
      css_test_helpers::ParseDeclarationBlock(R"CSS(
      left: 20px;
      right: 30px;
  )CSS");
  ASSERT_TRUE(try_set);

  const ComputedStyle* try_style = StyleForId(
      "div",
      StyleRecalcContext{.try_set = try_set, .is_interleaved_oof = true});
  ASSERT_TRUE(try_style);
  EXPECT_EQ("10px", ComputedValue("left", *try_style));
  EXPECT_EQ("auto", ComputedValue("right", *try_style));
}

TEST_F(StyleResolverTest, TrySet_NonAbsPosDynamic) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div {
        position: absolute;
        left: 10px;
      }
    </style>
    <div id=div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetElementById("div");
  ASSERT_TRUE(div);
  EXPECT_EQ("10px", ComputedValue("left", div->ComputedStyleRef()));
  EXPECT_EQ("auto", ComputedValue("right", div->ComputedStyleRef()));

  // Declarations from the try set should only apply when absolutely positioned,
  // including the cases where 'position' changes in the same style resolve.

  const CSSPropertyValueSet* try_set =
      css_test_helpers::ParseDeclarationBlock(R"CSS(
      left: 20px;
      right: 30px;
  )CSS");
  ASSERT_TRUE(try_set);

  div->SetInlineStyleProperty(CSSPropertyID::kPosition, "static");
  const ComputedStyle* try_style = StyleForId(
      "div",
      StyleRecalcContext{.try_set = try_set, .is_interleaved_oof = true});
  ASSERT_TRUE(try_style);
  EXPECT_EQ("10px", ComputedValue("left", *try_style));
  EXPECT_EQ("auto", ComputedValue("right", *try_style));
}

TEST_F(StyleResolverTest, TryTacticsSet_Flip) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div {
        position: absolute;
        left: 10px;
        right: 20px;
      }
    </style>
    <div id=div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetElementById("div");
  ASSERT_TRUE(div);
  EXPECT_EQ("10px", ComputedValue("left", div->ComputedStyleRef()));
  EXPECT_EQ("20px", ComputedValue("right", div->ComputedStyleRef()));

  const CSSPropertyValueSet* try_set =
      css_test_helpers::ParseDeclarationBlock(R"CSS(
      left: 100px;
      right: 200px;
  )CSS");
  ASSERT_TRUE(try_set);

  // Add a try-tactics set which flips left and right.
  auto* try_tactics_set =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode);
  try_tactics_set->SetProperty(
      CSSPropertyID::kLeft, *MakeGarbageCollected<cssvalue::CSSFlipRevertValue>(
                                CSSPropertyID::kRight, TryTacticTransform()));
  try_tactics_set->SetProperty(
      CSSPropertyID::kRight,
      *MakeGarbageCollected<cssvalue::CSSFlipRevertValue>(
          CSSPropertyID::kLeft, TryTacticTransform()));
  ASSERT_TRUE(try_tactics_set);

  const ComputedStyle* try_style =
      StyleForId("div", StyleRecalcContext{.try_set = try_set,
                                           .try_tactics_set = try_tactics_set,
                                           .is_interleaved_oof = true});
  ASSERT_TRUE(try_style);
  EXPECT_EQ("200px", ComputedValue("left", *try_style));
  EXPECT_EQ("100px", ComputedValue("right", *try_style));
}

TEST_F(StyleResolverTest,
       PseudoElementWithAnimationAndOriginatingElementStyleChange) {
  SetBodyInnerHTML(R"HTML(
      <style>
        div {
          width:100px;
          height:100px;
          background:red;
        }
        div:before {
          content:"blahblahblah";
          background:blue;
          transition:all 1s;
        }
        .content:before {
          content:"blahblah";
        }
        .color:before {
          background:red;
        }
      </style>
      <div class="content color" id="target"></div>
    )HTML");

  UpdateAllLifecyclePhasesForTest();

  auto* element = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(element);
  auto* before = element->GetPseudoElement(kPseudoIdBefore);
  ASSERT_TRUE(before);

  // Remove the color class to start an animation.
  NonThrowableExceptionState exception_state;
  element->classList().remove({"color"}, exception_state);
  UpdateAllLifecyclePhasesForTest();
  ASSERT_TRUE(before->GetElementAnimations());

  // Trigger a style invalidation for the transition animation and remove the
  // class from the originating element. The latter should reset the animation
  // bit.
  before->SetNeedsAnimationStyleRecalc();
  EXPECT_TRUE(before->GetElementAnimations()->IsAnimationStyleChange());
  element->classList().remove({"content"}, exception_state);
  EXPECT_TRUE(element->NeedsStyleRecalc());

  // Element::RecalcOwnStyle should detect that the style change on the
  // "target" ancestor node requires re-computing the base style for the
  // pseudo element and skip the optimization for animation style change.
  UpdateAllLifecyclePhasesForTest();
}

TEST_F(StyleResolverTestCQ, ContainerUnitContext) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #container, #div { container-type:size; }
      #container {
        width: 200px;
        height: 200px;
      }
      #div {
        width: 100px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="div"></div>
    </div>
  )HTML");

  Element* div = GetDocument().getElementById(AtomicString("div"));
  ASSERT_TRUE(div);

  // Don't provide a StyleRecalcContext here.
  StyleResolverState state(GetDocument(), *div);

  // To make UpdateLengthConversionData happen.
  state.SetStyle(div->ComputedStyleRef());

  EXPECT_DOUBLE_EQ(200.0, state.CssToLengthConversionData().ContainerWidth());
  EXPECT_DOUBLE_EQ(200.0, state.CssToLengthConversionData().ContainerHeight());
}

TEST_F(StyleResolverTest, ScopedAnchorName) {
  GetDocument().documentElement()->setHTMLUnsafe(R"HTML(
    <div id="outer-anchor" style="anchor-name: --outer"></div>
    <style>#host::part(anchor) { anchor-name: --part; }</style>
    <div id="host">
      <template shadowrootmode=open>
        <style>:host { anchor-name: --host; }</style>
        <div id="part" part="anchor"></div>
        <div id="inner-anchor" style="anchor-name: --inner"></div>
      </template>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  Element* outer_anchor = GetElementById("outer-anchor");
  Element* host = GetElementById("host");
  ShadowRoot* shadow = host->GetShadowRoot();
  Element* part = shadow->getElementById(AtomicString("part"));
  Element* inner_anchor = shadow->getElementById(AtomicString("inner-anchor"));

  EXPECT_EQ(*MakeGarbageCollected<ScopedCSSName>(AtomicString("--outer"),
                                                 &GetDocument()),
            *outer_anchor->ComputedStyleRef().AnchorName()->GetNames()[0]);
  EXPECT_EQ(
      *MakeGarbageCollected<ScopedCSSName>(AtomicString("--host"), shadow),
      *host->ComputedStyleRef().AnchorName()->GetNames()[0]);
  EXPECT_EQ(*MakeGarbageCollected<ScopedCSSName>(AtomicString("--part"),
                                                 &GetDocument()),
            *part->ComputedStyleRef().AnchorName()->GetNames()[0]);
  EXPECT_EQ(
      *MakeGarbageCollected<ScopedCSSName>(AtomicString("--inner"), shadow),
      *inner_anchor->ComputedStyleRef().AnchorName()->GetNames()[0]);
}

TEST_F(StyleResolverTest, ScopedPositionAnchor) {
  GetDocument().documentElement()->setHTMLUnsafe(R"HTML(
    <div id="outer-anchor" style="position-anchor: --outer"></div>
    <style>#host::part(anchor) { position-anchor: --part; }</style>
    <div id="host">
      <template shadowrootmode=open>
        <style>:host { position-anchor: --host; }</style>
        <div id="part" part="anchor"></div>
        <div id="inner-anchor" style="position-anchor: --inner"></div>
      </template>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  Element* outer_anchor = GetElementById("outer-anchor");
  Element* host = GetElementById("host");
  ShadowRoot* shadow = host->GetShadowRoot();
  Element* part = shadow->getElementById(AtomicString("part"));
  Element* inner_anchor = shadow->getElementById(AtomicString("inner-anchor"));

  EXPECT_EQ(*MakeGarbageCollected<ScopedCSSName>(AtomicString("--outer"),
                                                 &GetDocument()),
            *outer_anchor->ComputedStyleRef().PositionAnchor());
  EXPECT_EQ(
      *MakeGarbageCollected<ScopedCSSName>(AtomicString("--host"), shadow),
      *host->ComputedStyleRef().PositionAnchor());
  EXPECT_EQ(*MakeGarbageCollected<ScopedCSSName>(AtomicString("--part"),
                                                 &GetDocument()),
            *part->ComputedStyleRef().PositionAnchor());
  EXPECT_EQ(
      *MakeGarbageCollected<ScopedCSSName>(AtomicString("--inner"), shadow),
      *inner_anchor->ComputedStyleRef().PositionAnchor());
}

TEST_F(StyleResolverTest, NoAnchorFunction) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      div {
        left: 10px;
      }
    </style>
    <div id=div></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  auto* div = GetDocument().getElementById(AtomicString("div"));
  ASSERT_TRUE(div);
  EXPECT_FALSE(div->ComputedStyleRef().HasAnchorFunctions());
}

TEST_F(StyleResolverTest, HasAnchorFunction) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      div {
        left: anchor(--a left);
      }
    </style>
    <div id=div></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  auto* div = GetDocument().getElementById(AtomicString("div"));
  ASSERT_TRUE(div);
  EXPECT_TRUE(div->ComputedStyleRef().HasAnchorFunctions());
}

TEST_F(StyleResolverTest, HasAnchorFunctionImplicit) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      div {
        left: anchor(left);
      }
    </style>
    <div id=div></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  auto* div = GetDocument().getElementById(AtomicString("div"));
  ASSERT_TRUE(div);
  EXPECT_TRUE(div->ComputedStyleRef().HasAnchorFunctions());
}

TEST_F(StyleResolverTest, HasAnchorSizeFunction) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      div {
        width: anchor-size(--a width);
      }
    </style>
    <div id=div></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  auto* div = GetDocument().getElementById(AtomicString("div"));
  ASSERT_TRUE(div);
  EXPECT_TRUE(div->ComputedStyleRef().HasAnchorFunctions());
}

TEST_F(StyleResolverTest, HasAnchorSizeFunctionImplicit) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      div {
        width: anchor-size(width);
      }
    </style>
    <div id=div></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  auto* div = GetDocument().getElementById(AtomicString("div"));
  ASSERT_TRUE(div);
  EXPECT_TRUE(div->ComputedStyleRef().HasAnchorFunctions());
}

TEST_F(StyleResolverTestCQ, CanAffectAnimationsMPC) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #a { transition: color 1s; }
      @container (width > 100000px) {
        #b { animation-name: anim; }
      }
    </style>
    <div id=a></div>
    <div id=b></div>
    <div id=c></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  auto* a = GetDocument().getElementById(AtomicString("a"));
  auto* b = GetDocument().getElementById(AtomicString("b"));
  auto* c = GetDocument().getElementById(AtomicString("c"));

  ASSERT_TRUE(a);
  ASSERT_TRUE(b);
  ASSERT_TRUE(c);

  EXPECT_TRUE(a->ComputedStyleRef().CanAffectAnimations());
  EXPECT_FALSE(b->ComputedStyleRef().CanAffectAnimations());
  EXPECT_FALSE(c->ComputedStyleRef().CanAffectAnimations());
}

TEST_F(StyleResolverTest, CssRulesForElementIncludeStartingStyle) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @starting-style {
        #target {
          color: red;
        }
      }
    </style>
    <div id="wrapper" hidden>
      <span id="target"></span>
    </div>
  )HTML");

  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(target->GetComputedStyle(), nullptr);
  EXPECT_NE(GetStyleEngine().GetStyleResolver().CssRulesForElement(target),
            nullptr);

  GetElementById("wrapper")->removeAttribute(html_names::kHiddenAttr);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_NE(target->GetComputedStyle(), nullptr);
  EXPECT_NE(GetStyleEngine().GetStyleResolver().CssRulesForElement(target),
            nullptr);
}

TEST_F(StyleResolverTest, PseudoCSSRulesForElementIncludeStartingStyle) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @starting-style {
        #target::before {
          color: red;
        }
      }
      #target::before {
        content: "X";
        color: green;
      }
    </style>
    <div id="wrapper" hidden>
      <span id="target"></span>
    </div>
  )HTML");

  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(target->GetComputedStyle(), nullptr);
  EXPECT_EQ(target->Ge
```
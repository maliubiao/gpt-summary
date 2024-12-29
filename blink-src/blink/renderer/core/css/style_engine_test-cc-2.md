Response:
The user wants a summary of the functionality of the provided C++ code snippet from a Chromium Blink engine file.

The file seems to contain a series of C++ unit tests for the `StyleEngine` component in Blink. These tests verify how the style engine reacts to changes in various environmental factors, mainly related to CSS media queries and user preferences.

Here's a breakdown of the key areas covered in the tests:

1. **Media Queries:**  The tests check if changes to media features (like `prefers-color-scheme`, `prefers-contrast`, `prefers-reduced-motion`, `prefers-reduced-transparency`, `prefers-reduced-data`, `forced-colors`, `navigation-controls`, `inverted-colors`) correctly trigger style recalculations and apply the corresponding CSS rules. This involves setting and clearing overrides for these media features.

2. **User Preferences:**  The tests also cover how user preferences (like preferred color scheme, contrast) influence styling, particularly in conjunction with the `@media` rules.

3. **`forced-color-adjust`:** The tests demonstrate how the `forced-color-adjust` CSS property interacts with the forced colors media feature.

4. **Metrics and Use Counters:** Several tests verify if specific features (like dark mode, preferred color scheme) are correctly tracked using Chromium's use counters.

5. **Edge Cases and Potential Issues:**  There are tests focusing on potential crashes during style recalculation, especially in scenarios involving shadow DOM and elements with `display: contents`.

6. **CSS Selectors:** One test verifies the handling of CSS selectors targeting pseudo-elements.

To provide a good summary, I need to:
-  Identify the core functionalities being tested.
-  Explain the connection to HTML, CSS, and JavaScript (if any).
-  Give examples of assumed inputs and expected outputs for specific test cases.
-  Highlight potential user errors or common programming mistakes that these tests aim to prevent.
-  Describe the user actions leading to these tests being relevant (debugging scenarios).
```
功能归纳：

这段代码是 `blink/renderer/core/css/style_engine_test.cc` 文件的一部分，主要功能是**测试 Blink 渲染引擎中 `StyleEngine` 组件对于 CSS 媒体查询变化和用户偏好设置的响应**。 具体来说，它测试了以下几个方面：

1. **媒体查询变化引起的样式更新:**  测试当各种媒体查询（例如 `prefers-contrast`, `prefers-reduced-motion`, `prefers-reduced-transparency`, `prefers-reduced-data`, `forced-colors`, `prefers-color-scheme`, `navigation-controls`, `inverted-colors`）的状态发生变化时，`StyleEngine` 是否能正确地重新计算样式并应用匹配的 CSS 规则。

2. **媒体查询的覆盖 (Override):** 测试通过 JavaScript API (例如 `GetDocument().GetPage()->SetMediaFeatureOverride()` 和 `GetDocument().GetPage()->SetPreferenceOverride()`) 临时覆盖媒体查询特性值时，`StyleEngine` 的行为是否符合预期。这包括设置有效值、无效值和空值的情况，验证覆盖是否能正确生效和重置。

3. **用户偏好设置的影响:** 测试用户在操作系统或浏览器中设置的偏好（例如对比度、减少动画、颜色主题）如何通过媒体查询影响页面的样式。

4. **`forced-color-adjust` 属性:** 测试 `forced-color-adjust: none;` 属性如何阻止用户强制颜色模式对元素样式的影响。

5. **UseCounter 指标的记录:** 测试特定 CSS 特性和用户偏好设置的使用情况是否被正确记录到 Blink 的 `UseCounter` 机制中，用于统计分析。例如，测试 `prefers-color-scheme: dark`、强制暗黑模式等功能是否被成功计数。

6. **避免崩溃的健壮性测试:**  测试在特定的 DOM 操作场景下（例如 shadow DOM 的操作，`display: contents` 的使用），`StyleEngine` 是否能稳定运行，避免出现崩溃。

**与 Javascript, HTML, CSS 的关系举例说明：**

* **HTML:** 代码中大量使用 `R"HTML(...)HTML"` 来创建 HTML 片段，这些片段定义了测试所需的 DOM 结构和内联 CSS 样式。例如，定义一个带有特定 ID 的 `div` 元素，或者包含带有媒体查询的 `<style>` 标签。
    ```c++
    GetDocument().body()->setInnerHTML(R"HTML(
      <style>
        body { color: red }
        @media (prefers-color-scheme: dark) {
          body { color: green }
        }
      </style>
      <body></body>
    )HTML");
    ```
* **CSS:** 测试的核心是验证 CSS 样式的应用。代码通过断言 (`EXPECT_EQ`) 检查元素的计算样式 (`GetDocument().body()->GetComputedStyle()`) 是否与预期相符。 媒体查询是 CSS 的重要组成部分，用于根据不同的设备或用户环境应用不同的样式。
    ```c++
    EXPECT_EQ(Color::FromRGB(0, 128, 0),
              GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                  GetCSSPropertyColor()));
    ```
* **JavaScript:**  测试通过 Blink 提供的 C++ API 模拟 JavaScript 代码的行为，例如修改 DOM 结构 (`setInnerHTML`)、设置媒体查询覆盖 (`SetMediaFeatureOverride`, `SetPreferenceOverride`) 以及修改文档设置 (`GetSettings()->SetPrefersReducedMotion(true)`)。这些操作在实际的 Web 开发中通常是通过 JavaScript 来完成的。

**逻辑推理的假设输入与输出举例：**

**假设输入:**

```html
<style>
  body { color: red }
  @media (prefers-color-scheme: dark) {
    body { color: green }
  }
</style>
<body></body>
```

**场景:** 用户操作系统或浏览器偏好设置为浅色模式。

**预期输出:** `GetDocument().body()->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor())` 返回红色 (RGB: 255, 0, 0)。因为媒体查询 `(prefers-color-scheme: dark)` 不匹配当前环境。

**场景:** 用户操作系统或浏览器偏好设置为深色模式。

**预期输出:** `GetDocument().body()->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor())` 返回绿色 (RGB: 0, 128, 0)。因为媒体查询 `(prefers-color-scheme: dark)` 匹配当前环境。

**场景:**  通过 JavaScript 设置媒体查询覆盖：`GetDocument().GetPage()->SetMediaFeatureOverride(media_feature_names::kPrefersColorSchemeMediaFeature, "dark");`

**预期输出:** 即使用户偏好是浅色模式，`GetDocument().body()->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor())` 也会返回绿色 (RGB: 0, 128, 0)，因为媒体查询被强制覆盖为 `dark`。

**涉及用户或编程常见的使用错误举例说明：**

* **CSS 语法错误:** 虽然测试代码本身不会直接模拟 CSS 语法错误，但 `StyleEngine` 的功能就是解析和应用 CSS。如果用户编写了错误的 CSS 媒体查询，例如拼写错误 `prefers-color-schme`，`StyleEngine` 可能无法正确识别并应用该规则，导致样式不符合预期。测试用例中，会验证即使提供了 "invalid" 的媒体查询覆盖值，也会被正确处理并重置。
* **JavaScript API 使用错误:** 开发者可能错误地使用了媒体查询覆盖的 API，例如传递了错误的媒体特性名称或者无效的值。测试用例通过验证设置无效值和空值的行为，确保 `StyleEngine` 能处理这些情况，避免程序崩溃或其他不可预测的行为。例如，尝试设置 `GetDocument().GetPage()->SetPreferenceOverride(media_feature_names::kPrefersContrastMediaFeature, "invalid");` 会导致覆盖被重置。
* **对媒体查询的理解偏差:** 开发者可能不清楚不同媒体查询之间的优先级和相互作用，导致样式冲突。`StyleEngine` 的测试帮助验证这些逻辑是否正确实现。例如，测试 `forced-colors` 和 `prefers-color-scheme` 组合使用时的行为。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户访问网页:** 用户通过浏览器访问一个包含 CSS 样式和媒体查询的网页。
2. **浏览器解析 HTML 和 CSS:** 浏览器内核 (Blink) 的 HTML 解析器和 CSS 解析器会解析网页的 HTML 结构和 CSS 样式规则。
3. **`StyleEngine` 计算样式:** `StyleEngine` 负责根据解析后的 CSS 规则、HTML 结构以及当前的环境（例如屏幕尺寸、用户偏好、操作系统设置）计算出每个元素的最终样式。
4. **媒体查询评估:** `StyleEngine` 会评估 CSS 中定义的媒体查询，判断哪些规则应该被应用。
5. **用户更改系统设置或浏览器偏好:**  用户可能会在操作系统或浏览器设置中更改一些影响媒体查询的偏好，例如切换到深色模式、启用高对比度模式、减少动画等。
6. **浏览器通知 `StyleEngine`:** 当这些偏好发生变化时，浏览器会将这些变化通知给 `StyleEngine`。
7. **`StyleEngine` 重新计算样式:** `StyleEngine` 接收到通知后，会重新评估相关的媒体查询，并根据新的环境重新计算元素的样式。
8. **测试用例模拟上述过程:** `style_engine_test.cc` 中的测试用例正是模拟了上述用户操作和浏览器内部的处理流程。通过 C++ 代码模拟修改用户偏好和媒体查询状态，然后断言元素的计算样式是否符合预期。

**第3部分功能归纳:**

这部分代码主要集中在**测试 `StyleEngine` 对各种媒体查询的响应和覆盖机制**。它涵盖了 `prefers-contrast`，`prefers-reduced-motion`， `prefers-reduced-transparency`， `prefers-reduced-data`， `forced-colors`，以及 `prefers-color-scheme` 这些媒体查询特性的变化和通过 API 进行覆盖时的行为。此外，还测试了与 `forced-color-adjust` 属性的交互以及相关的 `UseCounter` 指标记录。 简而言之，这部分重点验证了 `StyleEngine` 如何根据用户偏好和媒体查询动态调整页面样式，并确保覆盖机制的正确性。

Prompt: 
```
这是目录为blink/renderer/core/css/style_engine_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共8部分，请归纳一下它的功能

"""
lor()));

  color_scheme_helper.SetPreferredContrast(
      mojom::blink::PreferredContrast::kCustom);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 255, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MediaQueriesChangePrefersContrastOverride) {
  ScopedForcedColorsForTest forced_scoped_feature(true);

  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredContrast(
      mojom::blink::PreferredContrast::kNoPreference);

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { color: red; forced-color-adjust: none; }
      @media (prefers-contrast: more) {
        body { color: blue }
      }
      @media (prefers-contrast: less) {
        body { color: orange }
      }
      @media (prefers-contrast: custom) {
        body { color: yellow }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetMediaFeatureOverride(
      media_feature_names::kPrefersContrastMediaFeature, "more");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 0, 255),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetMediaFeatureOverride(
      media_feature_names::kPrefersContrastMediaFeature, "no-preference");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetMediaFeatureOverride(
      media_feature_names::kPrefersContrastMediaFeature, "less");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 165, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetMediaFeatureOverride(
      media_feature_names::kPrefersContrastMediaFeature, "custom");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 255, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->ClearMediaFeatureOverrides();

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersContrastMediaFeature, "more");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 0, 255),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersContrastMediaFeature, "no-preference");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersContrastMediaFeature, "less");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 165, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->ClearPreferenceOverrides();

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersContrastMediaFeature, "less");

  UpdateAllLifecyclePhases();

  // Invalid value resets override
  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersContrastMediaFeature, "invalid");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersContrastMediaFeature, "less");

  UpdateAllLifecyclePhases();

  // Empty value resets override
  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersContrastMediaFeature, "");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MediaQueriesChangePrefersReducedMotion) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { color: red }
      @media (prefers-reduced-motion: reduce) {
        body { color: green }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetSettings()->SetPrefersReducedMotion(true);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MediaQueriesChangePrefersReducedTransparency) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { color: red }
      @media (prefers-reduced-transparency: reduce) {
        body { color: green }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetSettings()->SetPrefersReducedTransparency(true);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MediaQueriesChangePrefersReducedDataOn) {
  GetNetworkStateNotifier().SetSaveDataEnabled(true);

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { color: red }
      @media (prefers-reduced-data: reduce) {
        body { color: green }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();

  EXPECT_TRUE(GetNetworkStateNotifier().SaveDataEnabled());
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MediaQueriesChangePrefersReducedDataOff) {
  GetNetworkStateNotifier().SetSaveDataEnabled(false);

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { color: red }
      @media (prefers-reduced-data: reduce) {
        body { color: green }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();

  EXPECT_FALSE(GetNetworkStateNotifier().SaveDataEnabled());
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MediaQueriesChangeForcedColors) {
  ScopedForcedColorsForTest scoped_feature(true);
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body {
        forced-color-adjust: none;
      }
      @media (forced-colors: none) {
        body { color: red }
      }
      @media (forced-colors: active) {
        body { color: green }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetInForcedColors(GetDocument(),
                                        /*in_forced_colors=*/true);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MediaQueriesChangeForcedColorsAndPreferredColorScheme) {
  ScopedForcedColorsForTest scoped_feature(true);
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body {
        forced-color-adjust: none;
      }
      @media (forced-colors: none) and (prefers-color-scheme: light) {
        body { color: red }
      }
      @media (forced-colors: none) and (prefers-color-scheme: dark) {
        body { color: green }
      }
      @media (forced-colors: active) and (prefers-color-scheme: dark) {
        body { color: orange }
      }
      @media (forced-colors: active) and (prefers-color-scheme: light) {
        body { color: blue }
      }
    </style>
    <body></body>
  )HTML");

  // InForcedColors = false, PreferredColorScheme = kLight
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetInForcedColors(GetDocument(),
                                        /*in_forced_colors=*/false);
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kLight);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  // ForcedColors = kNone, PreferredColorScheme = kDark
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  // InForcedColors = true, PreferredColorScheme = kDark
  color_scheme_helper.SetInForcedColors(GetDocument(),
                                        /*in_forced_colors=*/true);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 165, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  // InForcedColors = true, PreferredColorScheme = kLight
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kLight);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 0, 255),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MediaQueriesForcedColorsOverride) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body {
        forced-color-adjust: none;
      }
      @media (forced-colors: none) {
        body { color: red }
      }
      @media (forced-colors: active) {
        body { color: green }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  ColorSchemeHelper color_scheme_helper(GetDocument());
  GetDocument().GetPage()->SetMediaFeatureOverride(
      media_feature_names::kForcedColorsMediaFeature, "active");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetMediaFeatureOverride(
      media_feature_names::kForcedColorsMediaFeature, "none");
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->ClearMediaFeatureOverrides();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MediaQueriesColorSchemeOverride) {
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kLight);
  EXPECT_EQ(mojom::blink::PreferredColorScheme::kLight,
            GetDocument().GetSettings()->GetPreferredColorScheme());

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { color: red }
      @media (prefers-color-scheme: dark) {
        body { color: green }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetMediaFeatureOverride(
      media_feature_names::kPrefersColorSchemeMediaFeature, "dark");
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->ClearMediaFeatureOverrides();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersColorSchemeMediaFeature, "dark");
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->ClearPreferenceOverrides();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersColorSchemeMediaFeature, "dark");
  UpdateAllLifecyclePhases();

  // Invalid value resets override
  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersColorSchemeMediaFeature, "invalid");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersColorSchemeMediaFeature, "dark");

  UpdateAllLifecyclePhases();

  // Empty value resets override
  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersColorSchemeMediaFeature, "");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MediaQueriesReducedTransparencyOverride) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { color: red }
      @media (prefers-reduced-transparency: reduce) {
        body { color: green }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetMediaFeatureOverride(
      media_feature_names::kPrefersReducedTransparencyMediaFeature, "reduce");
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->ClearMediaFeatureOverrides();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedTransparencyMediaFeature, "reduce");
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->ClearPreferenceOverrides();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetMediaFeatureOverride(
      media_feature_names::kPrefersReducedTransparencyMediaFeature, "reduce");

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedTransparencyMediaFeature,
      "no-preference");
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->ClearMediaFeatureOverrides();
  GetDocument().GetPage()->ClearPreferenceOverrides();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedTransparencyMediaFeature, "reduce");
  UpdateAllLifecyclePhases();

  // Invalid value resets override
  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedTransparencyMediaFeature, "invalid");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedTransparencyMediaFeature, "reduce");

  UpdateAllLifecyclePhases();

  // Empty value resets override
  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedTransparencyMediaFeature, "");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MediaQueriesReducedDataOverride) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { color: red }
      @media (prefers-reduced-data: reduce) {
        body { color: green }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetMediaFeatureOverride(
      media_feature_names::kPrefersReducedDataMediaFeature, "reduce");
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->ClearMediaFeatureOverrides();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedDataMediaFeature, "reduce");
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->ClearPreferenceOverrides();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetMediaFeatureOverride(
      media_feature_names::kPrefersReducedDataMediaFeature, "reduce");

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedDataMediaFeature, "no-preference");
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->ClearMediaFeatureOverrides();
  GetDocument().GetPage()->ClearPreferenceOverrides();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedDataMediaFeature, "reduce");
  UpdateAllLifecyclePhases();

  // Invalid value resets override
  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedDataMediaFeature, "invalid");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedDataMediaFeature, "reduce");

  UpdateAllLifecyclePhases();

  // Empty value resets override
  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedDataMediaFeature, "");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, PreferredColorSchemeMetric) {
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kLight);
  EXPECT_FALSE(IsUseCounted(WebFeature::kPreferredColorSchemeDark));
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  EXPECT_TRUE(IsUseCounted(WebFeature::kPreferredColorSchemeDark));
}

// The preferred color scheme setting used to differ from the preferred color
// scheme when forced dark mode was enabled. Test that it is no longer the case.
TEST_F(StyleEngineTest, PreferredColorSchemeSettingMetric) {
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kLight);
  GetDocument().GetSettings()->SetForceDarkModeEnabled(false);
  EXPECT_FALSE(IsUseCounted(WebFeature::kPreferredColorSchemeDark));
  EXPECT_FALSE(IsUseCounted(WebFeature::kPreferredColorSchemeDarkSetting));

  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  // Clear the UseCounters before they are updated by the
  // |SetForceDarkModeEnabled| call, below.
  ClearUseCounter(WebFeature::kPreferredColorSchemeDark);
  ClearUseCounter(WebFeature::kPreferredColorSchemeDarkSetting);
  GetDocument().GetSettings()->SetForceDarkModeEnabled(true);

  EXPECT_TRUE(IsUseCounted(WebFeature::kPreferredColorSchemeDark));
  EXPECT_TRUE(IsUseCounted(WebFeature::kPreferredColorSchemeDarkSetting));
}

TEST_F(StyleEngineTest, ForcedDarkModeMetric) {
  GetDocument().GetSettings()->SetForceDarkModeEnabled(false);
  EXPECT_FALSE(IsUseCounted(WebFeature::kForcedDarkMode));
  GetDocument().GetSettings()->SetForceDarkModeEnabled(true);
  EXPECT_TRUE(IsUseCounted(WebFeature::kForcedDarkMode));
}

TEST_F(StyleEngineTest, ColorSchemeDarkSupportedOnRootMetricFromMetaDark) {
  EXPECT_FALSE(IsUseCounted(WebFeature::kColorSchemeDarkSupportedOnRoot));
  GetDocument().body()->setInnerHTML(R"HTML(
    <meta name="color-scheme" content="dark">
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(IsUseCounted(WebFeature::kColorSchemeDarkSupportedOnRoot));
}

TEST_F(StyleEngineTest, ColorSchemeDarkSupportedOnRootMetricFromMetaLightDark) {
  EXPECT_FALSE(IsUseCounted(WebFeature::kColorSchemeDarkSupportedOnRoot));
  GetDocument().body()->setInnerHTML(R"HTML(
    <meta name="color-scheme" content="light dark">
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(IsUseCounted(WebFeature::kColorSchemeDarkSupportedOnRoot));
}

TEST_F(StyleEngineTest, ColorSchemeDarkSupportedOnRootMetricFromCSSDark) {
  EXPECT_FALSE(IsUseCounted(WebFeature::kColorSchemeDarkSupportedOnRoot));
  GetDocument().body()->setInnerHTML(R"HTML(
    <style> :root { color-scheme: dark; } </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(IsUseCounted(WebFeature::kColorSchemeDarkSupportedOnRoot));
}

TEST_F(StyleEngineTest, ColorSchemeDarkSupportedOnRootMetricFromCSSLightDark) {
  EXPECT_FALSE(IsUseCounted(WebFeature::kColorSchemeDarkSupportedOnRoot));
  GetDocument().body()->setInnerHTML(R"HTML(
    <style> :root { color-scheme: light dark; } </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(IsUseCounted(WebFeature::kColorSchemeDarkSupportedOnRoot));
}

TEST_F(StyleEngineTest, ColorSchemeDarkSupportedOnRootMetricFromChildCSSDark) {
  EXPECT_FALSE(IsUseCounted(WebFeature::kColorSchemeDarkSupportedOnRoot));
  GetDocument().body()->setInnerHTML(R"HTML(
    <style> div { color-scheme: dark; } </style>
    <div></div>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(IsUseCounted(WebFeature::kColorSchemeDarkSupportedOnRoot));
}

TEST_F(StyleEngineTest, ColorSchemeDarkSupportedOnRootMetricFromLight) {
  EXPECT_FALSE(IsUseCounted(WebFeature::kColorSchemeDarkSupportedOnRoot));
  GetDocument().body()->setInnerHTML(R"HTML(
    <meta name="color-scheme" content="light">
    <style> :root { color-scheme: light; } </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(IsUseCounted(WebFeature::kColorSchemeDarkSupportedOnRoot));
}

TEST_F(StyleEngineTest, MediaQueriesReducedMotionOverride) {
  EXPECT_FALSE(GetDocument().GetSettings()->GetPrefersReducedMotion());

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { color: red }
      @media (prefers-reduced-motion: reduce) {
        body { color: green }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetMediaFeatureOverride(
      media_feature_names::kPrefersReducedMotionMediaFeature, "reduce");
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->ClearMediaFeatureOverrides();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedMotionMediaFeature, "reduce");
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->ClearPreferenceOverrides();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
  GetDocument().GetPage()->ClearPreferenceOverrides();

  GetDocument().GetPage()->SetMediaFeatureOverride(
      media_feature_names::kPrefersReducedMotionMediaFeature, "reduce");

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedMotionMediaFeature, "no-preference");
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->ClearMediaFeatureOverrides();
  GetDocument().GetPage()->ClearPreferenceOverrides();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedMotionMediaFeature, "reduce");
  UpdateAllLifecyclePhases();

  // Invalid value resets override
  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedMotionMediaFeature, "invalid");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedMotionMediaFeature, "reduce");

  UpdateAllLifecyclePhases();

  // Empty value resets override
  GetDocument().GetPage()->SetPreferenceOverride(
      media_feature_names::kPrefersReducedMotionMediaFeature, "");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MediaQueriesChangeNavigationControls) {
  ScopedMediaQueryNavigationControlsForTest scoped_feature(true);
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @media (navigation-controls: none) {
        body { color: red }
      }
      @media (navigation-controls: back-button) {
        body { color: green }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetSettings()->SetNavigationControls(
      NavigationControls::kBackButton);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MediaQueriesChangeInvertedColors) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { color: red }
      @media (inverted-colors: inverted) {
        body { color: green }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetSettings()->SetInvertedColors(true);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, ShadowRootStyleRecalcCrash) {
  GetDocument().body()->setInnerHTML("<div id=host></div>");
  auto* host =
      To<HTMLElement>(GetDocument().getElementById(AtomicString("host")));
  ASSERT_TRUE(host);

  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);

  shadow_root.setInnerHTML(R"HTML(
    <span id=span></span>
    <style>
      :nth-child(odd) { color: green }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();

  // This should not cause DCHECK errors on style recalc flags.
  shadow_root.getElementById(AtomicString("span"))->remove();
  host->SetInlineStyleProperty(CSSPropertyID::kDisplay, "inline");
  UpdateAllLifecyclePhases();
}

TEST_F(StyleEngineTest, GetComputedStyleOutsideFlatTreeCrash) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body, div { display: contents }
      div::before { display: contents; content: "" }
    </style>
    <div id=host>
      <!-- no slots here -->
    </host>
    <div id=non-slotted></div>
  )HTML");

  GetDocument()
      .getElementById(AtomicString("host"))
      ->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  UpdateAllLifecyclePhases();
  GetDocument().body()->EnsureComputedStyle();
  GetDocument()
      .getElementById(AtomicString("non-slotted"))
      ->SetInlineStyleProperty(CSSPropertyID::kColor, "blue");
  UpdateAllLifecyclePhases();
}

TEST_F(StyleEngineTest, RejectSelectorForPseudoElement) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      div::before { content: "" }
      .not-in-filter div::before { color: red }
    </style>
    <div class='not-in-filter'></div>
  )HTML");
  UpdateAllLifecyclePhases();

  StyleEngine& engine = GetStyleEngine();
  // Even if the Stats() were already enabled, the following resets it to 0.
  engine.SetStatsEnabled(true);

  StyleResolverStats* stats = engine.Stats();
  ASSERT_TRUE(stats);
  EXPECT_EQ(0u, stats->rules_fast_rejected);

  Element* div = GetDocument(
"""


```
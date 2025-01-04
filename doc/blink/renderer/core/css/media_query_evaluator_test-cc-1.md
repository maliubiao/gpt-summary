Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is part of the Chromium Blink engine and is a test file for the `MediaQueryEvaluator` class.

Here's a breakdown of the code's function:

1. **Testing Media Query Evaluation**: The core purpose is to verify that the `MediaQueryEvaluator` correctly evaluates CSS media queries.
2. **Testing Different Media Features**: The code tests the evaluation of various media features, including:
    - `dynamic-range` and `video-dynamic-range` with different HDR support levels.
    - `inverted-colors` for different color inversion settings.
    - `scripting` for different JavaScript enablement states.
    - Range-based media features like `width`, `aspect-ratio` with `<`, `>`, `<=`, `>=`, and `=` operators.
    - Logical combinations of media queries using `and`, `or`, and `not`.
    - CSS Media Queries Level 4 features.
    - Handling of unknown media features.
3. **Testing Dependencies**: The code tests how the evaluator handles dependencies on viewport and device characteristics.
4. **Testing Identifiability**:  The latter part of the code focuses on testing the identifiability of media features for privacy analysis. It checks if specific media feature evaluations are recorded for potential privacy implications.

**Plan:**

1. Summarize the main function of the code.
2. Highlight the connection to CSS media queries.
3. Explain the test structure and how different media features are tested.
4. Briefly mention the identifiability testing aspect.
这是目录为blink/renderer/core/css/media_query_evaluator_test.cc的chromium blink引擎源代码文件的第2部分， 主要的功能是**继续测试 `MediaQueryEvaluator` 类在不同媒体特性和条件下的正确评估能力**。它延续了第1部分中建立的测试框架，并针对更多特定的媒体特性和场景进行验证。

以下是第2部分代码功能的归纳：

1. **测试动态范围 (Dynamic Range) 和视频动态范围 (Video Dynamic Range) 媒体特性：**
   - 这部分测试了 `dynamic-range` 和 `video-dynamic-range` 媒体查询在不同显示器是否支持高动态范围 (HDR) 的情况下的评估结果。
   - 它模拟了设备支持不同类型的 HDR 颜色空间（例如 Extended sRGB, Linear sRGB, HDR10, HLG），并验证了媒体查询评估器在这些情况下是否返回正确的布尔值。
   - 同时，它也测试了禁用 `video-dynamic-range` 特性时的评估结果，确保在功能被禁用时，相关的媒体查询不会生效。

2. **测试反色 (Inverted Colors) 媒体特性：**
   - 这部分测试了 `inverted-colors` 媒体查询在开启和关闭反色模式下的评估结果。
   - 它模拟了 `inverted_colors` 属性为 `true` (反色) 和 `false` (不反色) 的情况，并验证了评估器是否能正确识别。

3. **测试脚本 (Scripting) 媒体特性：**
   - 这部分测试了 `scripting` 媒体查询在不同的脚本状态下的评估结果。
   - 它模拟了脚本被禁用 (`kNone`)、仅初始加载时启用 (`kInitialOnly`) 和完全启用 (`kEnabled`) 这三种状态，并验证了评估器是否能正确判断。

4. **测试范围值 (Ranged Values) 媒体特性：**
   - 这部分着重测试了带有比较运算符（`<`, `>`, `<=`, `>=`, `=`）的媒体查询的评估。
   - 它针对 `width` 和 `aspect-ratio` 媒体特性，使用了不同的数值和比较运算符组合，验证了评估器在处理范围值时的逻辑是否正确。
   - **举例说明：**
     - **假设输入 CSS：**(width < 600px)
     - **假设 `data.viewport_width` 为 500px**
     - **预期输出：** `eval` 函数返回 `true`，因为 500px 小于 600px。
     - **假设输入 CSS：**(width > 500px)
     - **假设 `data.viewport_width` 为 500px**
     - **预期输出：** `eval` 函数返回 `false`，因为 500px 不大于 500px。

5. **测试表达式节点 (ExpNode) 的组合逻辑：**
   - 这部分测试了如何使用 `MediaQueryFeatureExpNode`、`MediaQueryNestedExpNode`、`MediaQueryNotExpNode`、`MediaQueryAndExpNode` 和 `MediaQueryOrExpNode` 来组合更复杂的媒体查询，并验证评估器对这些组合的评估结果。
   - **举例说明：**
     - **假设输入 CSS：**(width < 600px) and (width < 800px)
     - **假设 `data.viewport_width` 为 500px**
     - **预期输出：** `media_query_evaluator->Eval(*MakeGarbageCollected<MediaQueryAndExpNode>(width_lt_600, width_lt_800))` 返回 `KleeneValue::kTrue`，因为 500px 同时小于 600px 和 800px。
     - **假设输入 CSS：**(width < 600px) and (width < 400px)
     - **假设 `data.viewport_width` 为 500px**
     - **预期输出：** `media_query_evaluator->Eval(*MakeGarbageCollected<MediaQueryAndExpNode>(width_lt_600, width_lt_400))` 返回 `KleeneValue::kFalse`，因为 500px 不小于 400px。

**与 Javascript, HTML, CSS 的关系：**

- **CSS:**  `MediaQueryEvaluator` 的核心功能就是解析和评估 CSS 中的媒体查询。这些测试直接验证了引擎处理 CSS 媒体查询的正确性。
- **HTML:**  媒体查询的结果会影响 HTML 元素的样式应用。例如，如果一个媒体查询匹配当前视口大小，那么对应的 CSS 规则会被应用到 HTML 元素上。
- **Javascript:** Javascript 可以通过 `window.matchMedia()` 方法来检查媒体查询的状态。`MediaQueryEvaluator` 的正确性直接影响 `window.matchMedia()` 返回的结果。

**用户或编程常见的使用错误：**

- **范围值比较错误：** 用户可能在 CSS 中错误地使用范围比较运算符，例如 `(400px > width < 600px)`，这种写法在逻辑上是不清晰的，应该拆分成两个独立的条件。
- **逻辑运算符优先级错误：** 用户可能没有正确理解 `and` 和 `or` 的优先级，导致媒体查询的评估结果与预期不符。例如，`screen and (color) or print` 和 `screen and (color or print)` 的含义不同。
- **媒体特性名称拼写错误：**  CSS 中媒体特性的名称有特定的拼写规则，拼写错误会导致媒体查询无法被正确识别和评估。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写或加载包含 CSS 媒体查询的 HTML 页面。**
2. **浏览器解析 HTML 和 CSS，包括媒体查询。**
3. **当浏览器需要确定是否应用某个 CSS 规则时，会调用 `MediaQueryEvaluator` 来评估相关的媒体查询。**
4. **`MediaQueryEvaluator` 会获取当前的设备和视口信息（例如屏幕宽度、高度、设备像素比等）。**
5. **`MediaQueryEvaluator` 根据媒体查询的条件和当前的信息进行评估，返回 `true` 或 `false`。**
6. **如果评估结果为 `true`，则应用相关的 CSS 规则。**

作为调试线索，如果开发者发现媒体查询没有按预期工作，他们可能会：

- **检查 CSS 语法是否正确。**
- **使用浏览器的开发者工具查看当前设备的媒体特性值。**
- **在 Blink 引擎的源代码中，可能会断点到 `MediaQueryEvaluator::Eval` 方法，查看评估过程中的参数和中间结果，从而定位问题。**

总而言之，这部分测试代码集中验证了 `MediaQueryEvaluator` 在处理各种常见的和更特定的媒体特性时的核心评估逻辑，确保了浏览器能够正确地根据设备和环境特征来应用 CSS 样式。

Prompt: 
```
这是目录为blink/renderer/core/css/media_query_evaluator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
, media_query_evaluator);
    TestMQEvaluator(g_video_dynamic_range_standard_cases,
                    media_query_evaluator);

    // Test again with the feature disabled
    ScopedCSSVideoDynamicRangeMediaQueriesForTest const disable_video_feature{
        false};
    TestMQEvaluator(g_video_dynamic_range_feature_disabled_cases,
                    media_query_evaluator);
  }

  // Test with color spaces supporting high dynamic range
  {
    data.device_supports_hdr =
        gfx::DisplayColorSpaces(gfx::ColorSpace::CreateExtendedSRGB())
            .SupportsHDR();
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_dynamic_range_high_cases, media_query_evaluator);
    TestMQEvaluator(g_video_dynamic_range_high_cases, media_query_evaluator);

    // Test again with the feature disabled
    ScopedCSSVideoDynamicRangeMediaQueriesForTest const disable_video_feature{
        false};
    TestMQEvaluator(g_video_dynamic_range_feature_disabled_cases,
                    media_query_evaluator);
  }
  {
    data.device_supports_hdr =
        gfx::DisplayColorSpaces(gfx::ColorSpace::CreateSRGBLinear())
            .SupportsHDR();
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_dynamic_range_high_cases, media_query_evaluator);
    TestMQEvaluator(g_video_dynamic_range_high_cases, media_query_evaluator);

    // Test again with the feature disabled
    ScopedCSSVideoDynamicRangeMediaQueriesForTest const disable_video_feature{
        false};
    TestMQEvaluator(g_video_dynamic_range_feature_disabled_cases,
                    media_query_evaluator);
  }
  {
    data.device_supports_hdr =
        gfx::DisplayColorSpaces(gfx::ColorSpace::CreateHDR10()).SupportsHDR();
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_dynamic_range_high_cases, media_query_evaluator);
    TestMQEvaluator(g_video_dynamic_range_high_cases, media_query_evaluator);

    // Test again with the feature disabled
    ScopedCSSVideoDynamicRangeMediaQueriesForTest const disable_video_feature{
        false};
    TestMQEvaluator(g_video_dynamic_range_feature_disabled_cases,
                    media_query_evaluator);
  }
  {
    data.device_supports_hdr =
        gfx::DisplayColorSpaces(gfx::ColorSpace::CreateHLG()).SupportsHDR();
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_dynamic_range_high_cases, media_query_evaluator);
    TestMQEvaluator(g_video_dynamic_range_high_cases, media_query_evaluator);

    // Test again with the feature disabled
    ScopedCSSVideoDynamicRangeMediaQueriesForTest const disable_video_feature{
        false};
    TestMQEvaluator(g_video_dynamic_range_feature_disabled_cases,
                    media_query_evaluator);
  }
}

TEST(MediaQueryEvaluatorTest, CachedInvertedColors) {
  MediaValuesCached::MediaValuesCachedData data;

  // inverted-colors - none
  {
    data.inverted_colors = false;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_invertedcolors_none_cases, media_query_evaluator);
  }

  // inverted-colors - inverted
  {
    data.inverted_colors = true;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_invertedcolors_inverted_cases, media_query_evaluator);
  }
}

TEST(MediaQueryEvaluatorTest, CachedScripting) {
  MediaValuesCached::MediaValuesCachedData data;

  // scripting - none
  {
    data.scripting = Scripting::kNone;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_scripting_none_cases, media_query_evaluator);
  }

  // scripting - initial-only
  {
    data.scripting = Scripting::kInitialOnly;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_scripting_initial_only_cases, media_query_evaluator);
  }

  // scripting - enabled
  {
    data.scripting = Scripting::kEnabled;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_scripting_enabled_cases, media_query_evaluator);
  }
}

TEST(MediaQueryEvaluatorTest, RangedValues) {
  MediaValuesCached::MediaValuesCachedData data;
  data.viewport_width = 500;
  data.viewport_height = 250;

  auto* media_values = MakeGarbageCollected<MediaValuesCached>(data);
  MediaQueryEvaluator* media_query_evaluator =
      MakeGarbageCollected<MediaQueryEvaluator>(media_values);

  auto eval = [&media_query_evaluator](MediaQueryExp exp) {
    const auto* feature = MakeGarbageCollected<MediaQueryFeatureExpNode>(exp);
    return media_query_evaluator->Eval(*feature) == KleeneValue::kTrue;
  };

  // (width < 600px)
  EXPECT_TRUE(eval(MediaQueryExp::Create(
      AtomicString("width"), MediaQueryExpBounds(MediaQueryExpComparison(
                                 PxValue(600), MediaQueryOperator::kLt)))));

  // (width < 501px)
  EXPECT_TRUE(eval(MediaQueryExp::Create(
      AtomicString("width"), MediaQueryExpBounds(MediaQueryExpComparison(
                                 PxValue(501), MediaQueryOperator::kLt)))));

  // (width < 500px)
  EXPECT_FALSE(eval(MediaQueryExp::Create(
      AtomicString("width"), MediaQueryExpBounds(MediaQueryExpComparison(
                                 PxValue(500), MediaQueryOperator::kLt)))));

  // (width > 500px)
  EXPECT_FALSE(eval(MediaQueryExp::Create(
      AtomicString("width"), MediaQueryExpBounds(MediaQueryExpComparison(
                                 PxValue(500), MediaQueryOperator::kGt)))));

  // (width < 501px)
  EXPECT_TRUE(eval(MediaQueryExp::Create(
      AtomicString("width"), MediaQueryExpBounds(MediaQueryExpComparison(
                                 PxValue(501), MediaQueryOperator::kLt)))));

  // (width <= 500px)
  EXPECT_TRUE(eval(MediaQueryExp::Create(
      AtomicString("width"), MediaQueryExpBounds(MediaQueryExpComparison(
                                 PxValue(500), MediaQueryOperator::kLe)))));

  // (400px < width)
  EXPECT_TRUE(eval(MediaQueryExp::Create(
      AtomicString("width"),
      MediaQueryExpBounds(
          MediaQueryExpComparison(PxValue(400), MediaQueryOperator::kLt),
          MediaQueryExpComparison()))));

  // (600px < width)
  EXPECT_FALSE(eval(MediaQueryExp::Create(
      AtomicString("width"),
      MediaQueryExpBounds(
          MediaQueryExpComparison(PxValue(600), MediaQueryOperator::kLt),
          MediaQueryExpComparison()))));

  // (400px > width)
  EXPECT_FALSE(eval(MediaQueryExp::Create(
      AtomicString("width"),
      MediaQueryExpBounds(
          MediaQueryExpComparison(PxValue(400), MediaQueryOperator::kGt),
          MediaQueryExpComparison()))));

  // (600px > width)
  EXPECT_TRUE(eval(MediaQueryExp::Create(
      AtomicString("width"),
      MediaQueryExpBounds(
          MediaQueryExpComparison(PxValue(600), MediaQueryOperator::kGt),
          MediaQueryExpComparison()))));

  // (400px <= width)
  EXPECT_TRUE(eval(MediaQueryExp::Create(
      AtomicString("width"),
      MediaQueryExpBounds(
          MediaQueryExpComparison(PxValue(400), MediaQueryOperator::kLe),
          MediaQueryExpComparison()))));

  // (600px <= width)
  EXPECT_FALSE(eval(MediaQueryExp::Create(
      AtomicString("width"),
      MediaQueryExpBounds(
          MediaQueryExpComparison(PxValue(600), MediaQueryOperator::kLe),
          MediaQueryExpComparison()))));

  // (400px >= width)
  EXPECT_FALSE(eval(MediaQueryExp::Create(
      AtomicString("width"),
      MediaQueryExpBounds(
          MediaQueryExpComparison(PxValue(400), MediaQueryOperator::kGe),
          MediaQueryExpComparison()))));

  // (600px >= width)
  EXPECT_TRUE(eval(MediaQueryExp::Create(
      AtomicString("width"),
      MediaQueryExpBounds(
          MediaQueryExpComparison(PxValue(600), MediaQueryOperator::kGe),
          MediaQueryExpComparison()))));

  // (width = 500px)
  EXPECT_TRUE(eval(MediaQueryExp::Create(
      AtomicString("width"), MediaQueryExpBounds(MediaQueryExpComparison(
                                 PxValue(500), MediaQueryOperator::kEq)))));

  // (width = 400px)
  EXPECT_FALSE(eval(MediaQueryExp::Create(
      AtomicString("width"), MediaQueryExpBounds(MediaQueryExpComparison(
                                 PxValue(400), MediaQueryOperator::kEq)))));

  // (500px = width)
  EXPECT_TRUE(eval(MediaQueryExp::Create(
      AtomicString("width"),
      MediaQueryExpBounds(
          MediaQueryExpComparison(PxValue(500), MediaQueryOperator::kEq),
          MediaQueryExpComparison()))));

  // (400px = width)
  EXPECT_FALSE(eval(MediaQueryExp::Create(
      AtomicString("width"),
      MediaQueryExpBounds(
          MediaQueryExpComparison(PxValue(400), MediaQueryOperator::kEq),
          MediaQueryExpComparison()))));

  // (400px < width < 600px)
  EXPECT_TRUE(eval(MediaQueryExp::Create(
      AtomicString("width"),
      MediaQueryExpBounds(
          MediaQueryExpComparison(PxValue(400), MediaQueryOperator::kLt),
          MediaQueryExpComparison(PxValue(600), MediaQueryOperator::kLt)))));

  // (550px < width < 600px)
  EXPECT_FALSE(eval(MediaQueryExp::Create(
      AtomicString("width"),
      MediaQueryExpBounds(
          MediaQueryExpComparison(PxValue(550), MediaQueryOperator::kLt),
          MediaQueryExpComparison(PxValue(600), MediaQueryOperator::kLt)))));

  // (400px < width < 450px)
  EXPECT_FALSE(eval(MediaQueryExp::Create(
      AtomicString("width"),
      MediaQueryExpBounds(
          MediaQueryExpComparison(PxValue(400), MediaQueryOperator::kLt),
          MediaQueryExpComparison(PxValue(450), MediaQueryOperator::kLt)))));

  // (aspect-ratio = 2/1)
  EXPECT_TRUE(eval(
      MediaQueryExp::Create(AtomicString("aspect-ratio"),
                            MediaQueryExpBounds(MediaQueryExpComparison(
                                RatioValue(2, 1), MediaQueryOperator::kEq)))));

  // (aspect-ratio = 3/1)
  EXPECT_FALSE(eval(
      MediaQueryExp::Create(AtomicString("aspect-ratio"),
                            MediaQueryExpBounds(MediaQueryExpComparison(
                                RatioValue(3, 1), MediaQueryOperator::kEq)))));

  // (aspect-ratio < 1/1)
  EXPECT_FALSE(eval(
      MediaQueryExp::Create(AtomicString("aspect-ratio"),
                            MediaQueryExpBounds(MediaQueryExpComparison(
                                RatioValue(1, 1), MediaQueryOperator::kLt)))));

  // (aspect-ratio < 3/1)
  EXPECT_TRUE(eval(
      MediaQueryExp::Create(AtomicString("aspect-ratio"),
                            MediaQueryExpBounds(MediaQueryExpComparison(
                                RatioValue(3, 1), MediaQueryOperator::kLt)))));

  // (aspect-ratio > 1/1)
  EXPECT_TRUE(eval(
      MediaQueryExp::Create(AtomicString("aspect-ratio"),
                            MediaQueryExpBounds(MediaQueryExpComparison(
                                RatioValue(1, 1), MediaQueryOperator::kGt)))));

  // (aspect-ratio > 3/1)
  EXPECT_FALSE(eval(
      MediaQueryExp::Create(AtomicString("aspect-ratio"),
                            MediaQueryExpBounds(MediaQueryExpComparison(
                                RatioValue(3, 1), MediaQueryOperator::kGt)))));
}

TEST(MediaQueryEvaluatorTest, ExpNode) {
  MediaValuesCached::MediaValuesCachedData data;
  data.viewport_width = 500;

  auto* media_values = MakeGarbageCollected<MediaValuesCached>(data);
  MediaQueryEvaluator* media_query_evaluator =
      MakeGarbageCollected<MediaQueryEvaluator>(media_values);

  auto* width_lt_400 =
      MakeGarbageCollected<MediaQueryFeatureExpNode>(MediaQueryExp::Create(
          AtomicString("width"), MediaQueryExpBounds(MediaQueryExpComparison(
                                     PxValue(400), MediaQueryOperator::kLt))));
  auto* width_lt_600 =
      MakeGarbageCollected<MediaQueryFeatureExpNode>(MediaQueryExp::Create(
          AtomicString("width"), MediaQueryExpBounds(MediaQueryExpComparison(
                                     PxValue(600), MediaQueryOperator::kLt))));
  auto* width_lt_800 =
      MakeGarbageCollected<MediaQueryFeatureExpNode>(MediaQueryExp::Create(
          AtomicString("width"), MediaQueryExpBounds(MediaQueryExpComparison(
                                     PxValue(800), MediaQueryOperator::kLt))));

  EXPECT_EQ(KleeneValue::kTrue, media_query_evaluator->Eval(*width_lt_600));
  EXPECT_EQ(KleeneValue::kFalse, media_query_evaluator->Eval(*width_lt_400));

  EXPECT_EQ(KleeneValue::kTrue,
            media_query_evaluator->Eval(
                *MakeGarbageCollected<MediaQueryNestedExpNode>(width_lt_600)));
  EXPECT_EQ(KleeneValue::kFalse,
            media_query_evaluator->Eval(
                *MakeGarbageCollected<MediaQueryNestedExpNode>(width_lt_400)));

  EXPECT_EQ(KleeneValue::kFalse,
            media_query_evaluator->Eval(
                *MakeGarbageCollected<MediaQueryNotExpNode>(width_lt_600)));
  EXPECT_EQ(KleeneValue::kTrue,
            media_query_evaluator->Eval(
                *MakeGarbageCollected<MediaQueryNotExpNode>(width_lt_400)));

  EXPECT_EQ(KleeneValue::kTrue, media_query_evaluator->Eval(
                                    *MakeGarbageCollected<MediaQueryAndExpNode>(
                                        width_lt_600, width_lt_800)));
  EXPECT_EQ(
      KleeneValue::kFalse,
      media_query_evaluator->Eval(*MakeGarbageCollected<MediaQueryAndExpNode>(
          width_lt_600, width_lt_400)));

  EXPECT_EQ(KleeneValue::kTrue, media_query_evaluator->Eval(
                                    *MakeGarbageCollected<MediaQueryOrExpNode>(
                                        width_lt_600, width_lt_400)));
  EXPECT_EQ(
      KleeneValue::kFalse,
      media_query_evaluator->Eval(*MakeGarbageCollected<MediaQueryOrExpNode>(
          width_lt_400,
          MakeGarbageCollected<MediaQueryNotExpNode>(width_lt_800))));
}

TEST(MediaQueryEvaluatorTest, DependentResults) {
  MediaValuesCached::MediaValuesCachedData data;
  data.viewport_width = 300;
  data.device_width = 400;

  auto* media_values = MakeGarbageCollected<MediaValuesCached>(data);
  MediaQueryEvaluator* media_query_evaluator =
      MakeGarbageCollected<MediaQueryEvaluator>(media_values);

  // Viewport-dependent:
  auto* width_lt_400 =
      MakeGarbageCollected<MediaQueryFeatureExpNode>(MediaQueryExp::Create(
          AtomicString("width"), MediaQueryExpBounds(MediaQueryExpComparison(
                                     PxValue(400), MediaQueryOperator::kLt))));

  // Device-dependent:
  auto* device_width_lt_600 = MakeGarbageCollected<MediaQueryFeatureExpNode>(
      MediaQueryExp::Create(AtomicString("device-width"),
                            MediaQueryExpBounds(MediaQueryExpComparison(
                                PxValue(600), MediaQueryOperator::kLt))));

  // Neither viewport- nor device-dependent:
  auto* color =
      MakeGarbageCollected<MediaQueryFeatureExpNode>(MediaQueryExp::Create(
          AtomicString("color"),
          MediaQueryExpBounds(MediaQueryExpComparison(MediaQueryExpValue()))));

  // "(color)" should not be dependent on anything.
  {
    MediaQueryResultFlags result_flags;

    media_query_evaluator->Eval(*color, &result_flags);

    EXPECT_FALSE(result_flags.is_viewport_dependent);
    EXPECT_FALSE(result_flags.is_device_dependent);
  }

  // "(width < 400px)" should be viewport-dependent.
  {
    MediaQueryResultFlags result_flags;

    media_query_evaluator->Eval(*width_lt_400, &result_flags);

    EXPECT_TRUE(result_flags.is_viewport_dependent);
    EXPECT_FALSE(result_flags.is_device_dependent);
  }

  // "(device-width < 600px)" should be device-dependent.
  {
    MediaQueryResultFlags result_flags;

    media_query_evaluator->Eval(*device_width_lt_600, &result_flags);

    EXPECT_TRUE(result_flags.is_device_dependent);
    EXPECT_FALSE(result_flags.is_viewport_dependent);
  }

  // "((device-width < 600px))" should be device-dependent.
  {
    MediaQueryResultFlags result_flags;

    media_query_evaluator->Eval(
        *MakeGarbageCollected<MediaQueryNestedExpNode>(device_width_lt_600),
        &result_flags);

    EXPECT_FALSE(result_flags.is_viewport_dependent);
    EXPECT_TRUE(result_flags.is_device_dependent);
  }

  // "not (device-width < 600px)" should be device-dependent.
  {
    MediaQueryResultFlags result_flags;

    media_query_evaluator->Eval(
        *MakeGarbageCollected<MediaQueryNotExpNode>(device_width_lt_600),
        &result_flags);

    EXPECT_FALSE(result_flags.is_viewport_dependent);
    EXPECT_TRUE(result_flags.is_device_dependent);
  }

  // "(width < 400px) and (device-width < 600px)" should be both viewport- and
  // device-dependent.
  {
    MediaQueryResultFlags result_flags;

    media_query_evaluator->Eval(*MakeGarbageCollected<MediaQueryAndExpNode>(
                                    width_lt_400, device_width_lt_600),
                                &result_flags);

    EXPECT_TRUE(result_flags.is_viewport_dependent);
    EXPECT_TRUE(result_flags.is_device_dependent);
  }

  // "not (width < 400px) and (device-width < 600px)" should be
  // viewport-dependent only.
  //
  // Note that the evaluation short-circuits on the first condition, making the
  // the second condition irrelevant.
  {
    MediaQueryResultFlags result_flags;

    media_query_evaluator->Eval(
        *MakeGarbageCollected<MediaQueryAndExpNode>(
            MakeGarbageCollected<MediaQueryNotExpNode>(width_lt_400),
            device_width_lt_600),
        &result_flags);

    EXPECT_TRUE(result_flags.is_viewport_dependent);
    EXPECT_FALSE(result_flags.is_device_dependent);
  }

  // "(width < 400px) or (device-width < 600px)" should be viewport-dependent
  // only.
  //
  // Note that the evaluation short-circuits on the first condition, making the
  // the second condition irrelevant.
  {
    MediaQueryResultFlags result_flags;

    media_query_evaluator->Eval(*MakeGarbageCollected<MediaQueryOrExpNode>(
                                    width_lt_400, device_width_lt_600),
                                &result_flags);

    EXPECT_TRUE(result_flags.is_viewport_dependent);
    EXPECT_FALSE(result_flags.is_device_dependent);
  }

  // "not (width < 400px) or (device-width < 600px)" should be both viewport-
  //  and device-dependent.
  {
    MediaQueryResultFlags result_flags;

    media_query_evaluator->Eval(
        *MakeGarbageCollected<MediaQueryOrExpNode>(
            MakeGarbageCollected<MediaQueryNotExpNode>(width_lt_400),
            device_width_lt_600),
        &result_flags);

    EXPECT_TRUE(result_flags.is_viewport_dependent);
    EXPECT_TRUE(result_flags.is_device_dependent);
  }
}

TEST(MediaQueryEvaluatorTest, CSSMediaQueries4) {
  MediaValuesCached::MediaValuesCachedData data;
  data.viewport_width = 500;
  data.viewport_height = 500;
  auto* media_values = MakeGarbageCollected<MediaValuesCached>(data);
  MediaQueryEvaluator* media_query_evaluator =
      MakeGarbageCollected<MediaQueryEvaluator>(media_values);

  MediaQueryEvaluatorTestCase test_cases[] = {
      {"(width: 1px) or (width: 2px)", false},
      {"(width: 1px) or (width: 2px) or (width: 3px)", false},
      {"(width: 500px) or (width: 2px) or (width: 3px)", true},
      {"(width: 1px) or (width: 500px) or (width: 3px)", true},
      {"(width: 1px) or (width: 2px) or (width: 500px)", true},
      {"((width: 1px))", false},
      {"((width: 500px))", true},
      {"(((width: 500px)))", true},
      {"((width: 1px) or (width: 2px)) or (width: 3px)", false},
      {"(width: 1px) or ((width: 2px) or (width: 500px))", true},
      {"(width = 500px)", true},
      {"(width >= 500px)", true},
      {"(width <= 500px)", true},
      {"(width < 500px)", false},
      {"(500px = width)", true},
      {"(500px >= width)", true},
      {"(500px <= width)", true},
      {"(499px < width)", true},
      {"(499px > width)", false},
      {"(499px < width < 501px)", true},
      {"(499px < width <= 500px)", true},
      {"(499px < width < 500px)", false},
      {"(500px < width < 501px)", false},
      {"(501px > width > 499px)", true},
      {"(500px >= width > 499px)", true},
      {"(501px > width >= 500px)", true},
      {"(502px > width >= 501px)", false},
      {"not (499px > width)", true},
      {"(not (499px > width))", true},
      {"(width >= 500px) and (not (499px > width))", true},
      {"(width >= 500px) and ((499px > width) or (not (width = 500px)))",
       false},
  };

  TestMQEvaluator(test_cases, media_query_evaluator);
}

TEST(MediaQueryEvaluatorTest, GeneralEnclosed) {
  MediaValuesCached::MediaValuesCachedData data;
  data.viewport_width = 500;
  data.viewport_height = 500;

  auto* media_values = MakeGarbageCollected<MediaValuesCached>(data);
  MediaQueryEvaluator* media_query_evaluator =
      MakeGarbageCollected<MediaQueryEvaluator>(media_values);

  MediaQueryEvaluatorTestCase tests[] = {
      {"(unknown)", false},
      {"((unknown: 1px))", false},
      {"not (unknown: 1px)", false},
      {"(width) or (unknown: 1px)", true},
      {"(unknown: 1px) or (width)", true},
      {"(width: 42px) or (unknown: 1px)", false},
      {"(unknown: 1px) or (width: 42px)", false},
      {"not ((width: 42px) or (unknown: 1px))", false},
      {"not ((unknown: 1px) or (width: 42px))", false},
      {"not ((width) or (unknown: 1px))", false},
      {"not ((unknown: 1px) or (width))", false},
      {"(width) and (unknown: 1px)", false},
      {"(unknown: 1px) and (width)", false},
      {"(width: 42px) and (unknown: 1px)", false},
      {"(unknown: 1px) and (width: 42px)", false},
      {"not ((width: 42px) and (unknown: 1px))", true},
      {"not ((unknown: 1px) and (width: 42px))", true},
      {"not ((width) and (unknown: 1px))", false},
      {"not ((unknown: 1px) and (width))", false},
  };

  for (const MediaQueryEvaluatorTestCase& test : tests) {
    SCOPED_TRACE(String(test.input));
    String input(test.input);
    MediaQuerySet* query_set =
        MediaQueryParser::ParseMediaQuerySet(input, nullptr);
    ASSERT_TRUE(query_set);
    EXPECT_EQ(test.output, media_query_evaluator->Eval(*query_set));
  }
}

class MediaQueryEvaluatorIdentifiabilityTest : public PageTestBase {
 public:
  MediaQueryEvaluatorIdentifiabilityTest()
      : counts_{.response_for_is_active = true,
                .response_for_is_anything_blocked = false,
                .response_for_is_allowed = true} {
    IdentifiabilityStudySettings::SetGlobalProvider(
        std::make_unique<CountingSettingsProvider>(&counts_));
  }
  ~MediaQueryEvaluatorIdentifiabilityTest() override {
    IdentifiabilityStudySettings::ResetStateForTesting();
  }

  test::ScopedIdentifiabilityTestSampleCollector* collector() {
    return &collector_;
  }

 protected:
  CallCounts counts_;
  test::ScopedIdentifiabilityTestSampleCollector collector_;
  void UpdateAllLifecyclePhases() {
    GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  }
};

TEST_F(MediaQueryEvaluatorIdentifiabilityTest,
       MediaFeatureIdentifiableSurfacePrefersReducedMotion) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @media (prefers-reduced-motion: reduce) {
        div { color: green }
      }
    </style>
    <div id="green"></div>
    <span></span>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().WasMediaFeatureEvaluated(static_cast<int>(
      IdentifiableSurface::MediaFeatureName::kPrefersReducedMotion)));
  EXPECT_EQ(collector()->entries().size(), 1u);

  auto& entry = collector()->entries().front();
  EXPECT_EQ(entry.metrics.size(), 1u);
  EXPECT_EQ(
      entry.metrics.begin()->surface,
      IdentifiableSurface::FromTypeAndToken(
          IdentifiableSurface::Type::kMediaFeature,
          IdentifiableToken(
              IdentifiableSurface::MediaFeatureName::kPrefersReducedMotion)));
  EXPECT_EQ(entry.metrics.begin()->value, IdentifiableToken(false));
}

TEST_F(MediaQueryEvaluatorIdentifiabilityTest,
       MediaFeatureIdentifiableSurfacePrefersReducedTransparency) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @media (prefers-reduced-transparency: reduce) {
        div { color: green }
      }
    </style>
    <div id="green"></div>
    <span></span>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().WasMediaFeatureEvaluated(static_cast<int>(
      IdentifiableSurface::MediaFeatureName::kPrefersReducedTransparency)));
  EXPECT_EQ(collector()->entries().size(), 1u);

  auto& entry = collector()->entries().front();
  EXPECT_EQ(entry.metrics.size(), 1u);
  EXPECT_EQ(entry.metrics.begin()->surface,
            IdentifiableSurface::FromTypeAndToken(
                IdentifiableSurface::Type::kMediaFeature,
                IdentifiableToken(IdentifiableSurface::MediaFeatureName::
                                      kPrefersReducedTransparency)));
  EXPECT_EQ(entry.metrics.begin()->value, IdentifiableToken(false));
}

TEST_F(MediaQueryEvaluatorIdentifiabilityTest,
       MediaFeatureIdentifiableSurfaceOrientation) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @media (orientation: landscape) {
        div { color: green }
      }
    </style>
    <div id="green"></div>
    <span></span>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().WasMediaFeatureEvaluated(
      static_cast<int>(IdentifiableSurface::MediaFeatureName::kOrientation)));
  ASSERT_EQ(collector()->entries().size(), 1u);

  auto& entry = collector()->entries().front();
  EXPECT_EQ(entry.metrics.size(), 1u);
  EXPECT_EQ(entry.metrics.begin()->surface,
            IdentifiableSurface::FromTypeAndToken(
                IdentifiableSurface::Type::kMediaFeature,
                IdentifiableToken(
                    IdentifiableSurface::MediaFeatureName::kOrientation)));
  EXPECT_EQ(entry.metrics.begin()->value,
            IdentifiableToken(CSSValueID::kLandscape));
}

TEST_F(MediaQueryEvaluatorIdentifiabilityTest,
       MediaFeatureIdentifiableSurfaceCollectOnce) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @media (orientation: landscape) {
        div { color: green }
      }
    </style>
    <div id="green"></div>
    <span></span>
  )HTML");

  // Recompute layout twice but expect only one sample.
  UpdateAllLifecyclePhases();
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().WasMediaFeatureEvaluated(
      static_cast<int>(IdentifiableSurface::MediaFeatureName::kOrientation)));
  EXPECT_EQ(collector()->entries().size(), 1u);

  auto& entry = collector()->entries().front();
  EXPECT_EQ(entry.metrics.size(), 1u);
  EXPECT_EQ(entry.metrics.begin()->surface,
            IdentifiableSurface::FromTypeAndToken(
                IdentifiableSurface::Type::kMediaFeature,
                IdentifiableToken(
                    IdentifiableSurface::MediaFeatureName::kOrientation)));
  EXPECT_EQ(entry.metrics.begin()->value,
            IdentifiableToken(CSSValueID::kLandscape));
}

TEST_F(MediaQueryEvaluatorIdentifiabilityTest,
       MediaFeatureIdentifiableSurfaceDisplayMode) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @media all and (display-mode: browser) {
        div { color: green }
      }
    </style>
    <div id="green"></div>
    <span></span>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().WasMediaFeatureEvaluated(
      static_cast<int>(IdentifiableSurface::MediaFeatureName::kDisplayMode)));
  EXPECT_EQ(collector()->entries().size(), 1u);

  auto& entry = collector()->entries().front();
  EXPECT_EQ(entry.metrics.size(), 1u);
  EXPECT_EQ(entry.metrics.begin()->surface,
            IdentifiableSurface::FromTypeAndToken(
                IdentifiableSurface::Type::kMediaFeature,
                IdentifiableToken(
                    IdentifiableSurface::MediaFeatureName::kDisplayMode)));
  EXPECT_EQ(entry.metrics.begin()->value,
            IdentifiableToken(blink::mojom::DisplayMode::kBrowser));
}

TEST_F(MediaQueryEvaluatorIdentifiabilityTest,
       MediaFeatureIdentifiableSurfaceDisplayState) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @media all and (display-state: normal) {
        div { color: green }
      }
    </style>
    <div id="green"></div>
    <span></span>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().WasMediaFeatureEvaluated(
      static_cast<int>(IdentifiableSurface::MediaFeatureName::kDisplayState)));
  EXPECT_EQ(collector()->entries().size(), 1u);

  auto& entry = collector()->entries().front();
  EXPECT_EQ(entry.metrics.size(), 1u);
  EXPECT_EQ(entry.metrics.begin()->surface,
            IdentifiableSurface::FromTypeAndToken(
                IdentifiableSurface::Type::kMediaFeature,
                IdentifiableToken(
                    IdentifiableSurface::MediaFeatureName::kDisplayState)));
  EXPECT_EQ(entry.metrics.begin()->value,
            IdentifiableToken(ui::mojom::blink::WindowShowState::kDefault));
}

TEST_F(MediaQueryEvaluatorIdentifiabilityTest,
       MediaFeatureIdentifiableSurfaceResizable) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @media all and (resizable: true) {
        div { color: green }
      }
    </style>
    <div id="green"></div>
    <span></span>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().WasMediaFeatureEvaluated(
      static_cast<int>(IdentifiableSurface::MediaFeatureName::kResizable)));
  EXPECT_EQ(collector()->entries().size(), 1u);

  auto& entry = collector()->entries().front();
  EXPECT_EQ(entry.metrics.size(), 1u);
  EXPECT_EQ(entry.metrics.begin()->surface,
            IdentifiableSurface::FromTypeAndToken(
                IdentifiableSurface::Type::kMediaFeature,
                IdentifiableToken(
                    IdentifiableSurface::MediaFeatureName::kResizable)));
  EXPECT_EQ(entry.metrics.begin()->value, IdentifiableToken(true));
}

TEST_F(MediaQueryEvaluatorIdentifiabilityTest,
       MediaFeatureIdentifiableSurfaceForcedColorsHover) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @media all and (forced-colors: active) {
        div { color: green }
      }
    </style>
    <style>
      @media all and (hover: hover) {
        div { color: red }
      }
    </style>
    <div id="green"></div>
    <span></span>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().WasMediaFeatureEvaluated(
      static_cast<int>(IdentifiableSurface::MediaFeatureName::kForcedColors)));
  EXPECT_TRUE(GetDocument().WasMediaFeatureEvaluated(
      static_cast<int>(IdentifiableSurface::MediaFeatureName::kHover)));
  EXPECT_EQ(collector()->entries().size(), 2u);

  auto& entry_forced_colors = collector()->entries().front();
  EXPECT_EQ(entry_forced_colors.metrics.size(), 1u);
  EXPECT_EQ(entry_forced_colors.metrics.begin()->surface,
            IdentifiableSurface::FromTypeAndToken(
                IdentifiableSurface::Type::kMediaFeature,
                IdentifiableToken(
                    IdentifiableSurface::MediaFeatureName::kForcedColors)));
  EXPECT_EQ(entry_forced_colors.metrics.begin()->value,
            IdentifiableToken(ForcedColors::kNone));

  auto& entry_hover = collector()->entries().back();
  EXPECT_EQ(entry_hover.metrics.size(), 1u);
  EXPECT_EQ(
      entry_hover.metrics.begin()->surface,
      IdentifiableSurface::FromTypeAndToken(
          IdentifiableSurface::Type::kMediaFeature,
          IdentifiableToken(IdentifiableSurface::MediaFeatureName::kHover)));
  EXPECT_EQ(entry_hover.metrics.begin()->value,
            IdentifiableToken(mojom::blink::HoverType::kHoverNone));
}

TEST_F(MediaQueryEvaluatorIdentifiabilityTest,
       MediaFeatureIdentifiableSurfaceAspectRatioNormalized) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @media all
"""


```
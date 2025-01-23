Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is part of the Chromium Blink engine. The file is `media_query_evaluator.cc`. The request specifically asks to:
1. **List the functionalities** of the code.
2. **Explain its relation to JavaScript, HTML, and CSS**, providing examples.
3. **Illustrate logical reasoning** with input and output examples.
4. **Point out common user/programming errors**.
5. **Describe user actions leading to this code**, serving as a debugging clue.
6. **Summarize the functionality of this specific code block (part 2 of 3)**.

**Plan:**

1. **High-level overview:** Identify the core purpose of the code - evaluating media features in CSS media queries.
2. **Function-level analysis:** Examine each function to understand the specific media feature it evaluates (e.g., `MinWidthMediaFeatureEval`, `HoverMediaFeatureEval`).
3. **CSS relationship:** Connect the function names to corresponding CSS media features (e.g., `min-width`, `hover`).
4. **JavaScript relationship:** Explain how JavaScript can trigger media query re-evaluation (e.g., resizing the window).
5. **HTML relationship:**  Explain where media queries are defined in HTML (e.g., `<link>` tags, `<style>` blocks).
6. **Logical reasoning:**  Choose a few representative functions and demonstrate how they evaluate based on input `MediaQueryExpValue` and `MediaValues`.
7. **Common errors:**  Think about typical mistakes when writing media queries that this code would handle or where errors might occur.
8. **User actions:** Trace back the user interactions that would cause the browser to evaluate media queries.
9. **Focus on Part 2:**  Specifically summarize the functionalities present in the provided snippet.

**Mental Sandbox:**

* **Example CSS:** `@media (min-width: 768px) { ... }` - how would this code evaluate `min-width`?
* **Example JavaScript:** `window.innerWidth` change triggers re-evaluation.
* **Potential errors:** Incorrect syntax in media queries, using prefixed properties.
* **User action:** Resizing the browser window.

**Constraint Checklist & Confidence:**

1. List functionalities: Yes.
2. Relation to JS, HTML, CSS: Yes.
3. Examples for JS, HTML, CSS: Yes.
4. Logical reasoning with input/output: Yes.
5. User/programming errors: Yes.
6. User actions as debug clue: Yes.
7. Summarize part 2: Yes.

Confidence: 5/5

**Strategizing complete. Proceeding with response generation.**

这是 `blink/renderer/core/css/media_query_evaluator.cc` 文件第二部分的分析，主要关注的是其中定义的各种媒体特性评估函数。

**功能归纳：**

这部分代码的主要功能是定义了一系列静态函数，用于**评估各种 CSS 媒体特性的真假**。每个函数都对应一个特定的媒体特性（如 `min-width`, `max-height`, `hover`, `pointer` 等），并接收以下参数：

* `const MediaQueryExpValue& value`:  表示媒体特性表达式中给定的值（例如，`768px` 对于 `min-width: 768px`）。
* `MediaQueryOperator op`:  表示比较运算符（例如，`>=` 对于 `min-width`）。
* `const MediaValues& media_values`:  一个包含了当前环境媒体特性的值的对象（例如，当前屏幕的宽度、高度、设备像素比等）。

这些函数通过比较 `value` 和 `media_values` 中对应的实际值，并根据 `op` 运算符判断媒体特性是否匹配。  例如，`MinWidthMediaFeatureEval` 函数会比较 `value` 中的宽度值和 `media_values` 中设备的实际宽度，如果实际宽度大于等于给定的值，则返回 `true`。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这些函数直接关联到 **CSS 媒体查询**的功能。CSS 媒体查询允许开发者根据设备的特性（如屏幕尺寸、分辨率、输入方式等）应用不同的样式。

* **CSS:** 这部分代码实现了 CSS 规范中定义的各种媒体特性的评估逻辑。例如，CSS 中可以写 `@media (min-width: 768px) { ... }`，当浏览器解析到这个媒体查询时，会调用 `MinWidthMediaFeatureEval` 函数来判断当前视口的宽度是否大于等于 768px。
* **HTML:** HTML 文件中可以通过 `<link>` 标签引入带有媒体查询的 CSS 文件，或者在 `<style>` 标签内直接编写带有媒体查询的 CSS 规则。浏览器加载 HTML 并解析 CSS 时，会使用这里的代码来评估媒体查询。
  ```html
  <link rel="stylesheet" href="styles.css" media="(max-width: 600px)">
  <style>
  @media (orientation: portrait) {
    body {
      background-color: lightblue;
    }
  }
  </style>
  ```
* **JavaScript:** JavaScript 可以通过 `window.matchMedia()` 方法来程序化地检查媒体查询的状态。`matchMedia()` 方法内部会调用 Blink 引擎的相关代码，最终也会用到这里的评估函数。此外，JavaScript 的某些操作（例如，调整窗口大小）可能会导致媒体查询的重新评估，从而间接触发这些函数的执行.
  ```javascript
  if (window.matchMedia('(prefers-reduced-motion)').matches) {
    console.log('用户启用了减少动画偏好');
  }
  ```

**逻辑推理的假设输入与输出：**

假设我们有以下 CSS 媒体查询：

```css
@media (min-width: 800px) and (hover: hover) {
  /* 样式 */
}
```

* **假设输入给 `MinWidthMediaFeatureEval` 函数：**
    * `value`: 表示 `800px` 的 `MediaQueryExpValue` 对象。
    * `op`:  `MediaQueryOperator::kGe` (大于等于)。
    * `media_values`:  一个 `MediaValues` 对象，其 `Width()` 方法返回当前视口的宽度，假设为 `1024px`。
* **输出：** `true`，因为 `1024px >= 800px`。

* **假设输入给 `HoverMediaFeatureEval` 函数：**
    * `value`: 空的 `MediaQueryExpValue` 对象（表示没有指定 `none` 值）。
    * `op`:  `MediaQueryOperator::kNone`。
    * `media_values`: 一个 `MediaValues` 对象，其 `PrimaryHoverType()` 方法返回 `HoverType::kHoverHoverType` (设备支持悬停)。
* **输出：** `true`，因为 `hover` 媒体特性在没有指定 `none` 值时，只要设备支持悬停就为真。

**用户或编程常见的使用错误举例：**

1. **拼写错误或使用了不存在的媒体特性名称：** 例如，写成 `@media (minwidth: 768px)` 或 `@media (display-mode: fullscreen)` (正确的应该是 `display-mode: fullscreen`)。这会导致该媒体查询规则永远不会生效，因为评估函数找不到对应的媒体特性。
2. **单位错误：** 例如，写成 `@media (min-width: 800)`，缺少单位 `px`。这会导致解析错误，媒体查询可能无法正确评估。
3. **逻辑运算符使用错误：** 例如，错误地使用了 `or` 而不是 `and` 或 `,` 来组合媒体特性。
4. **对布尔类型的媒体特性错误地赋值：** 某些媒体特性是布尔类型，例如 `color-gamut`，直接判断其是否存在即可，如果错误地写成 `@media (color-gamut: true)` 或 `@media (color-gamut: false)` 则会导致评估错误。正确的使用方式是 `@media (color-gamut)` 或 `@media not (color-gamut)`.
5. **使用了带有浏览器前缀的媒体特性：** 尽管代码中存在对带前缀的媒体特性的处理（例如 `WebFeature::kPrefixedMinDevicePixelRatioMediaFeature`），但最佳实践是避免使用浏览器前缀，因为这些前缀最终会被移除，并使用标准的无前缀版本。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在 HTML 或 CSS 文件中编写了包含媒体查询的样式规则。**
2. **用户使用浏览器访问包含这些样式规则的网页。**
3. **浏览器开始解析 HTML 和 CSS。**
4. **当解析到媒体查询时，Blink 引擎会创建相应的媒体查询表达式树。**
5. **当浏览器需要应用样式时（例如，页面加载完成、窗口大小改变、设备方向改变等），会触发媒体查询的评估。**
6. **`MediaQueryEvaluator` 类会被调用，其中的 `EvalFeature` 方法会根据媒体特性类型调用相应的评估函数（例如，`MinWidthMediaFeatureEval`, `HoverMediaFeatureEval` 等）。**
7. **这些评估函数会获取当前的媒体环境值（从 `MediaValues` 对象中），并与媒体查询中指定的值进行比较。**
8. **评估结果会决定是否应用该媒体查询对应的样式规则。**

作为调试线索，如果开发者发现某个媒体查询没有按预期生效，可以怀疑是否是这里的评估逻辑出现了问题，例如：

* `MediaValues` 对象中的值是否正确？
* 评估函数中的比较逻辑是否符合预期？
* 媒体查询表达式是否被正确解析？

可以通过断点调试或者查看相关日志来追踪媒体查询的评估过程，定位问题所在。

**总结：**

总而言之，这部分代码是 Chromium Blink 引擎中负责**具体执行 CSS 媒体特性评估逻辑**的关键组成部分。它定义了一系列针对不同媒体特性的评估函数，这些函数接收媒体查询中指定的值和当前设备的实际媒体特性值，并返回该媒体特性是否匹配的结果。这直接影响了 CSS 媒体查询的功能，使得网页能够根据不同的设备环境应用不同的样式。

### 提示词
```
这是目录为blink/renderer/core/css/media_query_evaluator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ectRatioMediaFeatureEval(
    const MediaQueryExpValue& value,
    MediaQueryOperator,
    const MediaValues& media_values) {
  return DeviceAspectRatioMediaFeatureEval(value, MediaQueryOperator::kLe,
                                           media_values);
}

static bool MinDevicePixelRatioMediaFeatureEval(
    const MediaQueryExpValue& value,
    MediaQueryOperator,
    const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kPrefixedMinDevicePixelRatioMediaFeature);

  return DevicePixelRatioMediaFeatureEval(value, MediaQueryOperator::kGe,
                                          media_values);
}

static bool MaxDevicePixelRatioMediaFeatureEval(
    const MediaQueryExpValue& value,
    MediaQueryOperator,
    const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kPrefixedMaxDevicePixelRatioMediaFeature);

  return DevicePixelRatioMediaFeatureEval(value, MediaQueryOperator::kLe,
                                          media_values);
}

static bool MinHeightMediaFeatureEval(const MediaQueryExpValue& value,
                                      MediaQueryOperator,
                                      const MediaValues& media_values) {
  return HeightMediaFeatureEval(value, MediaQueryOperator::kGe, media_values);
}

static bool MaxHeightMediaFeatureEval(const MediaQueryExpValue& value,
                                      MediaQueryOperator,
                                      const MediaValues& media_values) {
  return HeightMediaFeatureEval(value, MediaQueryOperator::kLe, media_values);
}

static bool MinWidthMediaFeatureEval(const MediaQueryExpValue& value,
                                     MediaQueryOperator,
                                     const MediaValues& media_values) {
  return WidthMediaFeatureEval(value, MediaQueryOperator::kGe, media_values);
}

static bool MaxWidthMediaFeatureEval(const MediaQueryExpValue& value,
                                     MediaQueryOperator,
                                     const MediaValues& media_values) {
  return WidthMediaFeatureEval(value, MediaQueryOperator::kLe, media_values);
}

static bool MinBlockSizeMediaFeatureEval(const MediaQueryExpValue& value,
                                         MediaQueryOperator,
                                         const MediaValues& media_values) {
  return BlockSizeMediaFeatureEval(value, MediaQueryOperator::kGe,
                                   media_values);
}

static bool MaxBlockSizeMediaFeatureEval(const MediaQueryExpValue& value,
                                         MediaQueryOperator,
                                         const MediaValues& media_values) {
  return BlockSizeMediaFeatureEval(value, MediaQueryOperator::kLe,
                                   media_values);
}

static bool MinInlineSizeMediaFeatureEval(const MediaQueryExpValue& value,
                                          MediaQueryOperator,
                                          const MediaValues& media_values) {
  return InlineSizeMediaFeatureEval(value, MediaQueryOperator::kGe,
                                    media_values);
}

static bool MaxInlineSizeMediaFeatureEval(const MediaQueryExpValue& value,
                                          MediaQueryOperator,
                                          const MediaValues& media_values) {
  return InlineSizeMediaFeatureEval(value, MediaQueryOperator::kLe,
                                    media_values);
}

static bool MinDeviceHeightMediaFeatureEval(const MediaQueryExpValue& value,
                                            MediaQueryOperator,
                                            const MediaValues& media_values) {
  return DeviceHeightMediaFeatureEval(value, MediaQueryOperator::kGe,
                                      media_values);
}

static bool MaxDeviceHeightMediaFeatureEval(const MediaQueryExpValue& value,
                                            MediaQueryOperator,
                                            const MediaValues& media_values) {
  return DeviceHeightMediaFeatureEval(value, MediaQueryOperator::kLe,
                                      media_values);
}

static bool MinDeviceWidthMediaFeatureEval(const MediaQueryExpValue& value,
                                           MediaQueryOperator,
                                           const MediaValues& media_values) {
  return DeviceWidthMediaFeatureEval(value, MediaQueryOperator::kGe,
                                     media_values);
}

static bool MaxDeviceWidthMediaFeatureEval(const MediaQueryExpValue& value,
                                           MediaQueryOperator,
                                           const MediaValues& media_values) {
  return DeviceWidthMediaFeatureEval(value, MediaQueryOperator::kLe,
                                     media_values);
}

static bool MinResolutionMediaFeatureEval(const MediaQueryExpValue& value,
                                          MediaQueryOperator,
                                          const MediaValues& media_values) {
  return ResolutionMediaFeatureEval(value, MediaQueryOperator::kGe,
                                    media_values);
}

static bool MaxResolutionMediaFeatureEval(const MediaQueryExpValue& value,
                                          MediaQueryOperator,
                                          const MediaValues& media_values) {
  return ResolutionMediaFeatureEval(value, MediaQueryOperator::kLe,
                                    media_values);
}

static bool Transform3dMediaFeatureEval(const MediaQueryExpValue& value,
                                        MediaQueryOperator op,
                                        const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kPrefixedTransform3dMediaFeature);

  bool return_value_if_no_parameter;
  int have3d_rendering;

  bool three_d_enabled = media_values.ThreeDEnabled();
  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kTransform3d,
      three_d_enabled);

  return_value_if_no_parameter = three_d_enabled;
  have3d_rendering = three_d_enabled ? 1 : 0;

  if (value.IsValid()) {
    float number;
    return NumberValue(value, number, media_values) &&
           CompareValue(have3d_rendering, static_cast<int>(number), op);
  }
  return return_value_if_no_parameter;
}

static bool HoverMediaFeatureEval(const MediaQueryExpValue& value,
                                  MediaQueryOperator,
                                  const MediaValues& media_values) {
  HoverType hover = media_values.PrimaryHoverType();
  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kHover, hover);

  if (!value.IsValid()) {
    return hover != HoverType::kHoverNone;
  }

  if (!value.IsId()) {
    return false;
  }

  return (hover == HoverType::kHoverNone && value.Id() == CSSValueID::kNone) ||
         (hover == HoverType::kHoverHoverType &&
          value.Id() == CSSValueID::kHover);
}

static bool AnyHoverMediaFeatureEval(const MediaQueryExpValue& value,
                                     MediaQueryOperator,
                                     const MediaValues& media_values) {
  int available_hover_types = media_values.AvailableHoverTypes();
  MaybeRecordMediaFeatureValue(media_values,
                               IdentifiableSurface::MediaFeatureName::kAnyHover,
                               available_hover_types);

  if (!value.IsValid()) {
    return available_hover_types & ~static_cast<int>(HoverType::kHoverNone);
  }

  if (!value.IsId()) {
    return false;
  }

  switch (value.Id()) {
    case CSSValueID::kNone:
      return available_hover_types & static_cast<int>(HoverType::kHoverNone);
    case CSSValueID::kHover:
      return available_hover_types &
             static_cast<int>(HoverType::kHoverHoverType);
    default:
      NOTREACHED();
  }
}

static bool OriginTrialTestMediaFeatureEval(const MediaQueryExpValue& value,
                                            MediaQueryOperator,
                                            const MediaValues& media_values) {
  // The test feature only supports a 'no-value' parsing. So if we've gotten
  // to this point it will always match.
  DCHECK(!value.IsValid());
  return true;
}

static bool PointerMediaFeatureEval(const MediaQueryExpValue& value,
                                    MediaQueryOperator,
                                    const MediaValues& media_values) {
  PointerType pointer = media_values.PrimaryPointerType();
  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kPointer, pointer);

  if (!value.IsValid()) {
    return pointer != PointerType::kPointerNone;
  }

  if (!value.IsId()) {
    return false;
  }

  return (pointer == PointerType::kPointerNone &&
          value.Id() == CSSValueID::kNone) ||
         (pointer == PointerType::kPointerCoarseType &&
          value.Id() == CSSValueID::kCoarse) ||
         (pointer == PointerType::kPointerFineType &&
          value.Id() == CSSValueID::kFine);
}

static bool PrefersReducedMotionMediaFeatureEval(
    const MediaQueryExpValue& value,
    MediaQueryOperator,
    const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kPrefersReducedMotionMediaFeature);

  MaybeRecordMediaFeatureValue(
      media_values,
      IdentifiableSurface::MediaFeatureName::kPrefersReducedMotion,
      media_values.PrefersReducedMotion());

  // If the value is not valid, this was passed without an argument. In that
  // case, it implicitly resolves to 'reduce'.
  if (!value.IsValid()) {
    return media_values.PrefersReducedMotion();
  }

  if (!value.IsId()) {
    return false;
  }

  return (value.Id() == CSSValueID::kNoPreference) ^
         media_values.PrefersReducedMotion();
}

static bool PrefersReducedDataMediaFeatureEval(
    const MediaQueryExpValue& value,
    MediaQueryOperator,
    const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kPrefersReducedDataMediaFeature);
  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kPrefersReducedData,
      media_values.PrefersReducedData());

  if (!value.IsValid()) {
    return media_values.PrefersReducedData();
  }

  if (!value.IsId()) {
    return false;
  }

  return (value.Id() == CSSValueID::kNoPreference) ^
         media_values.PrefersReducedData();
}

static bool PrefersReducedTransparencyMediaFeatureEval(
    const MediaQueryExpValue& value,
    MediaQueryOperator,
    const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kPrefersReducedTransparencyMediaFeature);
  MaybeRecordMediaFeatureValue(
      media_values,
      IdentifiableSurface::MediaFeatureName::kPrefersReducedTransparency,
      media_values.PrefersReducedTransparency());

  if (!value.IsValid()) {
    return media_values.PrefersReducedTransparency();
  }

  if (!value.IsId()) {
    return false;
  }

  return (value.Id() == CSSValueID::kNoPreference) ^
         media_values.PrefersReducedTransparency();
}

static bool AnyPointerMediaFeatureEval(const MediaQueryExpValue& value,
                                       MediaQueryOperator,
                                       const MediaValues& media_values) {
  int available_pointers = media_values.AvailablePointerTypes();
  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kAnyPointer,
      available_pointers);

  if (!value.IsValid()) {
    return available_pointers & ~static_cast<int>(PointerType::kPointerNone);
  }

  if (!value.IsId()) {
    return false;
  }

  switch (value.Id()) {
    case CSSValueID::kCoarse:
      return available_pointers &
             static_cast<int>(PointerType::kPointerCoarseType);
    case CSSValueID::kFine:
      return available_pointers &
             static_cast<int>(PointerType::kPointerFineType);
    case CSSValueID::kNone:
      return available_pointers & static_cast<int>(PointerType::kPointerNone);
    default:
      NOTREACHED();
  }
}

static bool ScanMediaFeatureEval(const MediaQueryExpValue& value,
                                 MediaQueryOperator,
                                 const MediaValues& media_values) {
  MaybeRecordMediaFeatureValue(media_values,
                               IdentifiableSurface::MediaFeatureName::kScan,
                               media_values.MediaType().Utf8());

  // Scan only applies to 'tv' media.
  if (!EqualIgnoringASCIICase(media_values.MediaType(),
                              media_type_names::kTv)) {
    return false;
  }

  if (!value.IsValid()) {
    return true;
  }

  if (!value.IsId()) {
    return false;
  }

  // If a platform interface supplies progressive/interlace info for TVs in the
  // future, it needs to be handled here. For now, assume a modern TV with
  // progressive display.
  return (value.Id() == CSSValueID::kProgressive);
}

static bool ColorGamutMediaFeatureEval(const MediaQueryExpValue& value,
                                       MediaQueryOperator,
                                       const MediaValues& media_values) {
  // isValid() is false if there is no parameter. Without parameter we should
  // return true to indicate that colorGamutMediaFeature is enabled in the
  // browser.
  if (!value.IsValid()) {
    return true;
  }

  if (!value.IsId()) {
    return false;
  }

  DCHECK(value.Id() == CSSValueID::kSRGB || value.Id() == CSSValueID::kP3 ||
         value.Id() == CSSValueID::kRec2020);

  ColorSpaceGamut gamut = media_values.ColorGamut();
  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kColorGamut, gamut);

  switch (gamut) {
    case ColorSpaceGamut::kUnknown:
    case ColorSpaceGamut::kLessThanNTSC:
    case ColorSpaceGamut::NTSC:
    case ColorSpaceGamut::SRGB:
      return value.Id() == CSSValueID::kSRGB;
    case ColorSpaceGamut::kAlmostP3:
    case ColorSpaceGamut::P3:
    case ColorSpaceGamut::kAdobeRGB:
    case ColorSpaceGamut::kWide:
      return value.Id() == CSSValueID::kSRGB || value.Id() == CSSValueID::kP3;
    case ColorSpaceGamut::BT2020:
    case ColorSpaceGamut::kProPhoto:
    case ColorSpaceGamut::kUltraWide:
      return value.Id() == CSSValueID::kSRGB || value.Id() == CSSValueID::kP3 ||
             value.Id() == CSSValueID::kRec2020;
    case ColorSpaceGamut::kEnd:
      NOTREACHED();
  }

  NOTREACHED();
}

static bool PrefersColorSchemeMediaFeatureEval(
    const MediaQueryExpValue& value,
    MediaQueryOperator,
    const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kPrefersColorSchemeMediaFeature);

  auto preferred_scheme = media_values.GetPreferredColorScheme();
  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kPrefersColorScheme,
      preferred_scheme);

  if (!value.IsValid()) {
    return true;
  }

  if (!value.IsId()) {
    return false;
  }

  return (preferred_scheme == mojom::blink::PreferredColorScheme::kDark &&
          value.Id() == CSSValueID::kDark) ||
         (preferred_scheme == mojom::blink::PreferredColorScheme::kLight &&
          value.Id() == CSSValueID::kLight);
}

static bool PrefersContrastMediaFeatureEval(const MediaQueryExpValue& value,
                                            MediaQueryOperator,
                                            const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kPrefersContrastMediaFeature);

  auto preferred_contrast = media_values.GetPreferredContrast();
  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kPrefersContrast,
      preferred_contrast);

  if (!value.IsValid()) {
    return preferred_contrast != mojom::blink::PreferredContrast::kNoPreference;
  }

  if (!value.IsId()) {
    return false;
  }

  switch (value.Id()) {
    case CSSValueID::kMore:
      return preferred_contrast == mojom::blink::PreferredContrast::kMore;
    case CSSValueID::kLess:
      return preferred_contrast == mojom::blink::PreferredContrast::kLess;
    case CSSValueID::kNoPreference:
      return preferred_contrast ==
             mojom::blink::PreferredContrast::kNoPreference;
    case CSSValueID::kCustom:
      return preferred_contrast == mojom::blink::PreferredContrast::kCustom;
    default:
      NOTREACHED();
  }
}

static bool ForcedColorsMediaFeatureEval(const MediaQueryExpValue& value,
                                         MediaQueryOperator,
                                         const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kForcedColorsMediaFeature);

  ForcedColors forced_colors = media_values.GetForcedColors();
  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kForcedColors,
      forced_colors);

  if (!value.IsValid()) {
    return forced_colors != ForcedColors::kNone;
  }

  if (!value.IsId()) {
    return false;
  }

  // Check the forced colors against value.Id().
  return (forced_colors == ForcedColors::kNone &&
          value.Id() == CSSValueID::kNone) ||
         (forced_colors != ForcedColors::kNone &&
          value.Id() == CSSValueID::kActive);
}

static bool NavigationControlsMediaFeatureEval(
    const MediaQueryExpValue& value,
    MediaQueryOperator,
    const MediaValues& media_values) {
  NavigationControls navigation_controls = media_values.GetNavigationControls();
  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kNavigationControls,
      navigation_controls);

  if (!value.IsValid()) {
    return navigation_controls != NavigationControls::kNone;
  }

  if (!value.IsId()) {
    return false;
  }

  // Check the navigation controls against value.Id().
  return (navigation_controls == NavigationControls::kNone &&
          value.Id() == CSSValueID::kNone) ||
         (navigation_controls == NavigationControls::kBackButton &&
          value.Id() == CSSValueID::kBackButton);
}

static bool HorizontalViewportSegmentsMediaFeatureEval(
    const MediaQueryExpValue& value,
    MediaQueryOperator op,
    const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kViewportSegmentsMediaFeature);
  UseCounter::Count(media_values.GetDocument(), WebFeature::kFoldableAPIs);
  int horizontal_viewport_segments =
      media_values.GetHorizontalViewportSegments();

  MaybeRecordMediaFeatureValue(
      media_values,
      IdentifiableSurface::MediaFeatureName::kHorizontalViewportSegments,
      horizontal_viewport_segments);

  if (!value.IsValid()) {
    return true;
  }

  float number;
  return NumberValue(value, number, media_values) &&
         CompareValue(horizontal_viewport_segments, static_cast<int>(number),
                      op);
}

static bool VerticalViewportSegmentsMediaFeatureEval(
    const MediaQueryExpValue& value,
    MediaQueryOperator op,
    const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kViewportSegmentsMediaFeature);
  UseCounter::Count(media_values.GetDocument(), WebFeature::kFoldableAPIs);
  int vertical_viewport_segments = media_values.GetVerticalViewportSegments();

  MaybeRecordMediaFeatureValue(
      media_values,
      IdentifiableSurface::MediaFeatureName::kVerticalViewportSegments,
      vertical_viewport_segments);

  if (!value.IsValid()) {
    return true;
  }

  float number;
  return NumberValue(value, number, media_values) &&
         CompareValue(vertical_viewport_segments, static_cast<int>(number), op);
}

static bool OverflowInlineMediaFeatureEval(const MediaQueryExpValue& value,
                                           MediaQueryOperator,
                                           const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kOverflowMediaQuery);

  bool can_scroll = !EqualIgnoringASCIICase(media_values.MediaType(),
                                            media_type_names::kPrint);
  // No value = boolean context:
  // https://w3c.github.io/csswg-drafts/mediaqueries/#mq-boolean-context
  if (!value.IsValid()) {
    return can_scroll;
  }
  DCHECK(value.IsId());
  switch (value.Id()) {
    case CSSValueID::kNone:
      return !can_scroll;
    case CSSValueID::kScroll:
      return can_scroll;
    default:
      NOTREACHED();
  }
}

static bool OverflowBlockMediaFeatureEval(const MediaQueryExpValue& value,
                                          MediaQueryOperator,
                                          const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kOverflowMediaQuery);

  bool can_scroll = !EqualIgnoringASCIICase(media_values.MediaType(),
                                            media_type_names::kPrint);
  // No value = boolean context:
  // https://w3c.github.io/csswg-drafts/mediaqueries/#mq-boolean-context
  if (!value.IsValid()) {
    return true;
  }
  DCHECK(value.IsId());
  switch (value.Id()) {
    case CSSValueID::kNone:
      return false;
    case CSSValueID::kScroll:
      return can_scroll;
    case CSSValueID::kPaged:
      return !can_scroll;
    default:
      NOTREACHED();
  }
}

static bool DevicePostureMediaFeatureEval(const MediaQueryExpValue& value,
                                          MediaQueryOperator,
                                          const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kDevicePostureMediaFeature);
  UseCounter::Count(media_values.GetDocument(), WebFeature::kFoldableAPIs);
  // isValid() is false if there is no parameter. Without parameter we should
  // return true to indicate that device posture is enabled in the
  // browser.
  if (!value.IsValid()) {
    return true;
  }

  DCHECK(value.IsId());

  DevicePostureType device_posture = media_values.GetDevicePosture();
  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kDevicePosture,
      device_posture);

  switch (value.Id()) {
    case CSSValueID::kContinuous:
      return device_posture == DevicePostureType::kContinuous;
    case CSSValueID::kFolded:
      return device_posture == DevicePostureType::kFolded;
    default:
      NOTREACHED();
  }
}

static bool UpdateMediaFeatureEval(const MediaQueryExpValue& value,
                                   MediaQueryOperator,
                                   const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(), WebFeature::kUpdateMediaQuery);

  bool can_update = !EqualIgnoringASCIICase(media_values.MediaType(),
                                            media_type_names::kPrint);
  // No value = boolean context:
  // https://w3c.github.io/csswg-drafts/mediaqueries/#mq-boolean-context
  if (!value.IsValid()) {
    return can_update;
  }
  const auto& device_update_ability_type =
      media_values.OutputDeviceUpdateAbilityType();
  DCHECK(value.IsId());
  switch (value.Id()) {
    case CSSValueID::kNone:
      return !can_update;
    case CSSValueID::kSlow:
      return can_update &&
             device_update_ability_type ==
                 mojom::blink::OutputDeviceUpdateAbilityType::kSlowType;
    case CSSValueID::kFast:
      return can_update &&
             device_update_ability_type ==
                 mojom::blink::OutputDeviceUpdateAbilityType::kFastType;
    default:
      NOTREACHED();
  }
}

static bool StuckMediaFeatureEval(const MediaQueryExpValue& value,
                                  MediaQueryOperator op,
                                  const MediaValues& media_values) {
  if (!value.IsValid()) {
    return media_values.Stuck();
  }

  switch (value.Id()) {
    case CSSValueID::kNone:
      return media_values.StuckHorizontal() == ContainerStuckPhysical::kNo &&
             media_values.StuckVertical() == ContainerStuckPhysical::kNo;
    case CSSValueID::kTop:
      return media_values.StuckVertical() == ContainerStuckPhysical::kTop;
    case CSSValueID::kLeft:
      return media_values.StuckHorizontal() == ContainerStuckPhysical::kLeft;
    case CSSValueID::kBottom:
      return media_values.StuckVertical() == ContainerStuckPhysical::kBottom;
    case CSSValueID::kRight:
      return media_values.StuckHorizontal() == ContainerStuckPhysical::kRight;
    case CSSValueID::kBlockStart:
      return media_values.StuckBlock() == ContainerStuckLogical::kStart;
    case CSSValueID::kBlockEnd:
      return media_values.StuckBlock() == ContainerStuckLogical::kEnd;
    case CSSValueID::kInlineStart:
      return media_values.StuckInline() == ContainerStuckLogical::kStart;
    case CSSValueID::kInlineEnd:
      return media_values.StuckInline() == ContainerStuckLogical::kEnd;
    default:
      NOTREACHED();
  }
}

static bool SnappedMediaFeatureEval(const MediaQueryExpValue& value,
                                    MediaQueryOperator op,
                                    const MediaValues& media_values) {
  if (!value.IsValid()) {
    return media_values.Snapped();
  }
  switch (value.Id()) {
    case CSSValueID::kNone:
      return !media_values.Snapped();
    case CSSValueID::kX:
      return media_values.SnappedX();
    case CSSValueID::kY:
      return media_values.SnappedY();
    case CSSValueID::kBlock:
      return media_values.SnappedBlock();
    case CSSValueID::kInline:
      return media_values.SnappedInline();
    default:
      NOTREACHED();
  }
}

static bool OverflowingMediaFeatureEval(const MediaQueryExpValue& value,
                                        MediaQueryOperator op,
                                        const MediaValues& media_values) {
  if (!value.IsValid()) {
    return media_values.Overflowing();
  }
  switch (value.Id()) {
    case CSSValueID::kNone:
      return !media_values.Overflowing();
    case CSSValueID::kTop:
      return media_values.OverflowingVertical() &
             static_cast<ContainerOverflowingFlags>(
                 ContainerOverflowing::kStart);
    case CSSValueID::kLeft:
      return media_values.OverflowingHorizontal() &
             static_cast<ContainerOverflowingFlags>(
                 ContainerOverflowing::kStart);
    case CSSValueID::kBottom:
      return media_values.OverflowingVertical() &
             static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kEnd);
    case CSSValueID::kRight:
      return media_values.OverflowingHorizontal() &
             static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kEnd);
    case CSSValueID::kBlockStart:
      return media_values.OverflowingBlock() &
             static_cast<ContainerOverflowingFlags>(
                 ContainerOverflowing::kStart);
      ;
    case CSSValueID::kBlockEnd:
      return media_values.OverflowingBlock() &
             static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kEnd);
    case CSSValueID::kInlineStart:
      return media_values.OverflowingInline() &
             static_cast<ContainerOverflowingFlags>(
                 ContainerOverflowing::kStart);
    case CSSValueID::kInlineEnd:
      return media_values.OverflowingInline() &
             static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kEnd);
    default:
      NOTREACHED();
  }
}

static bool InvertedColorsMediaFeatureEval(const MediaQueryExpValue& value,
                                           MediaQueryOperator,
                                           const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kInvertedColorsMediaFeature);
  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kInvertedColors,
      media_values.InvertedColors());

  if (!value.IsValid()) {
    return media_values.InvertedColors();
  }

  if (!value.IsId()) {
    return false;
  }

  return (value.Id() == CSSValueID::kNone) != media_values.InvertedColors();
}

static bool ScriptingMediaFeatureEval(const MediaQueryExpValue& value,
                                      MediaQueryOperator,
                                      const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kScriptingMediaFeature);
  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kScripting,
      media_values.GetScripting());

  if (!value.IsValid()) {
    return media_values.GetScripting() == Scripting::kEnabled;
  }

  if (!value.IsId()) {
    return false;
  }

  switch (value.Id()) {
    case CSSValueID::kNone:
      return media_values.GetScripting() == Scripting::kNone;
    case CSSValueID::kInitialOnly:
      return media_values.GetScripting() == Scripting::kInitialOnly;
    case CSSValueID::kEnabled:
      return media_values.GetScripting() == Scripting::kEnabled;
    default:
      NOTREACHED();
  }
}

static MediaQueryOperator ReverseOperator(MediaQueryOperator op) {
  switch (op) {
    case MediaQueryOperator::kNone:
    case MediaQueryOperator::kEq:
      return op;
    case MediaQueryOperator::kLt:
      return MediaQueryOperator::kGt;
    case MediaQueryOperator::kLe:
      return MediaQueryOperator::kGe;
    case MediaQueryOperator::kGt:
      return MediaQueryOperator::kLt;
    case MediaQueryOperator::kGe:
      return MediaQueryOperator::kLe;
  }

  NOTREACHED();
}

void MediaQueryEvaluator::Init() {
  // Create the table.
  g_function_map = new FunctionMap;
#define ADD_TO_FUNCTIONMAP(constantPrefix, methodPrefix)   \
  g_function_map->Set(constantPrefix##MediaFeature.Impl(), \
                      methodPrefix##MediaFeatureEval);
  CSS_MEDIAQUERY_NAMES_FOR_EACH_MEDIAFEATURE(ADD_TO_FUNCTIONMAP);
#undef ADD_TO_FUNCTIONMAP
}

KleeneValue MediaQueryEvaluator::EvalFeature(
    const MediaQueryFeatureExpNode& feature,
    MediaQueryResultFlags* result_flags) const {
  if (!media_values_ || !media_values_->HasValues()) {
    // media_values_ should only be nullptr when parsing UA stylesheets. The
    // only media queries we support in UA stylesheets are media type queries.
    // If HasValues() return false, it means the document frame is nullptr.
    NOTREACHED();
  }

  if (!media_values_->Width().has_value() && feature.IsWidthDependent()) {
    return KleeneValue::kUnknown;
  }
  if (!media_values_->Height().has_value() && feature.IsHeightDependent()) {
    return KleeneValue::kUnknown;
  }
  if (!media_values_->InlineSize().has_value() &&
      feature.IsInlineSizeDependent()) {
    return KleeneValue::kUnknown;
  }
  if (!media_values_->BlockSize().has_value() &&
      feature.IsBlockSizeDependent()) {
    return KleeneValue::kUnknown;
  }

  if (CSSVariableParser::IsValidVariableName(feature.Name())) {
    return EvalStyleFeature(feature, result_flags);
  }

  DCHECK(g_function_map);

  // Call the media feature evaluation function. Assume no prefix and let
  // trampoline functions override the prefix if prefix is used.
  EvalFunc func = g_function_map->at(feature.Name().Impl());

  if (!func) {
    return KleeneValue::kFalse;
  }

  const auto& bounds = feature.Bounds();

  bool result = true;

  if (!bounds.IsRange() || bounds.right.IsValid()) {
    DCHECK((bounds.right.op == MediaQueryOperator::kNone) || bounds.IsRange());
    result &= func(bounds.right.value, bounds.right.op, *media_values_);
  }

  if (bounds.left.IsValid()) {
    DCHECK(bounds.IsRange());
    auto op = ReverseOperator(bounds.left.op);
    result &= func(bounds.left.value, op, *media_values_);
  }

  if (result_flags) {
    result_flags->is_viewport_dependent =
        result_flags->is_viewport_dependent || feature.IsViewportDependent();
    result_flags->is_device_dependent =
        result_flags->is_device_dependent || feature.IsDeviceDependent();
    result_flags->unit_flags |= feature.GetUnitFlags();
  }

  return result ? KleeneValue::kTrue : KleeneValue::kFalse;
}

KleeneValue MediaQueryEvaluator::EvalStyleFeature(
    const MediaQueryFeatureExpNode& feature,
    MediaQueryResultFlags* result_flags) const {
  if (!media_values_ || !media_values_->HasValues()) {
    NOTREACHED()
        << "media_values has to be initialized for style() container queries";
  }

  const MediaQueryExpBounds& bounds = feature.Bounds();

  // Style features do not support the range syntax.
  DCHECK(!bounds.IsRange());
  DCHECK(bounds.right.op == MediaQ
```
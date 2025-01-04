Response:
The user wants to understand the functionality of the `css_parsing_utils.cc` file in the Chromium Blink engine. This is part 4 of a 9-part series, so I need to summarize the functionality covered in this specific part.

My plan is to:
1. **Identify the main functions** present in this code snippet.
2. **Describe the purpose** of each function.
3. **Relate the functions to CSS parsing**, and provide examples where relevant to JavaScript, HTML, and CSS.
4. **Look for examples of logical reasoning** within the functions and illustrate them with input/output scenarios.
5. **Identify potential user/programmer errors** related to these functions and provide examples.
6. **Infer the user actions** that might lead to this code being executed.
7. **Summarize the overall functionality** of this specific part of the file.
这是 `blink/renderer/core/css/properties/css_parsing_utils.cc` 文件的第 4 部分，主要包含了用于解析 CSS 图像和渐变相关功能的工具函数。根据提供的代码片段，其功能可以归纳如下：

**主要功能:**

1. **解析径向渐变 (`ConsumeRadialGradient`, `ConsumeDeprecatedRadialGradient`):**
    *   负责解析 `radial-gradient()` 和 `-webkit-radial-gradient()` 函数。
    *   处理渐变的中心位置、形状 (circle, ellipse)、大小关键字 (closest-side, closest-corner, farthest-side, farthest-corner, contain, cover) 以及具体的尺寸长度或百分比。
    *   支持新的颜色空间规范。
    *   区分标准和旧式的径向渐变语法。
    *   处理 `repeating-radial-gradient()`。

2. **解析线性渐变 (`ConsumeLinearGradient`, `ConsumeDeprecatedWebkitGradient`):**
    *   负责解析 `linear-gradient()` 和 `-webkit-linear-gradient()` 函数。
    *   处理渐变的方向，可以使用角度或者 `to <side-or-corner>` 的语法。
    *   支持新的颜色空间规范。
    *   区分标准和旧式的线性渐变语法。
    *   处理 `repeating-linear-gradient()`。
    *   旧式的 `-webkit-gradient()` 函数也在这个部分处理。

3. **解析锥形渐变 (`ConsumeConicGradient`):**
    *   负责解析 `conic-gradient()` 函数。
    *   处理渐变的起始角度 (`from <angle>`) 和中心位置 (`at <position>`)。
    *   支持新的颜色空间规范。
    *   处理 `repeating-conic-gradient()`。

4. **解析 `image` 类型相关的值 (`ConsumeImageOrNone`, `ConsumeImage`, `ConsumeImageSet`):**
    *   `ConsumeImageOrNone`: 解析 `none` 关键字或者调用 `ConsumeImage` 解析其他图像类型。
    *   `ConsumeImage`:  是解析各种图像类型的主要入口，包括 URL 引用 (`url(...)`), 字符串形式的 URL, `image-set()`, 以及各种渐变函数。
    *   `ConsumeImageSet`: 解析 `image-set()` 函数，用于根据设备分辨率选择合适的图像。它会解析 `type` 属性和分辨率。

5. **解析 `cross-fade()` 函数 (`ConsumeCrossFade`, `ConsumeDeprecatedWebkitCrossFade`):**
    *   负责解析 `cross-fade()` 函数，用于在两个图像或颜色之间进行平滑过渡。
    *   区分标准和旧式的 `-webkit-cross-fade()` 语法。
    *   可以接受多个图像和可选的百分比值。

6. **解析 `paint()` 函数 (`ConsumePaint`):**
    *   负责解析 `paint()` 函数，允许使用注册的 Paint Worklet 来绘制图像。
    *   解析传递给 Paint Worklet 的参数。
    *   仅在安全上下文 (Secure Context) 中有效。

7. **解析形状盒子 (`ConsumeShapeBox`), 可视盒子 (`ConsumeVisualBox`), 坐标盒子 (`ConsumeCoordBox`), 几何盒子 (`ConsumeGeometryBox`):**
    *   这些函数用于解析与 CSS 盒子模型相关的关键字，例如 `content-box`, `padding-box`, `border-box`, `margin-box`, `fill-box`, `stroke-box`, `view-box`。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **CSS:** 这些函数直接服务于 CSS 属性值的解析，例如 `background-image`, `mask-image`, `border-image-source` 等。
    *   **例子:**  当 CSS 中出现 `background-image: linear-gradient(to right, red, blue);` 时，`ConsumeLinearGradient` 函数会被调用来解析这个值。
    *   **例子:**  当 CSS 中出现 `background-image: url("image.png");` 时，`ConsumeImage` 函数会被调用来解析 URL。
    *   **例子:**  当 CSS 中出现 `mask-image: paint(my-painter);` 时，`ConsumePaint` 函数会被调用来解析。

*   **HTML:** HTML 元素通过 `style` 属性或外部 CSS 文件应用样式，这些样式中可能包含需要这些函数解析的 CSS 值。
    *   **例子:**  `<div style="background-image: radial-gradient(circle at 50% 50%, yellow, green);"></div>`。
    *   **例子:**  `<img srcset="image-1x.png 1x, image-2x.png 2x" >`  （`image-set()` 的概念类似 `srcset`，但用于 CSS）。

*   **JavaScript:** JavaScript 可以通过 DOM API 修改元素的样式，这些修改后的样式值也需要经过类似的解析过程。
    *   **例子:** `element.style.backgroundImage = 'conic-gradient(from 90deg, purple, teal)';`。
    *   **例子:** 使用 CSSOM API 获取和修改样式规则时，也会涉及到 CSS 值的解析。

**逻辑推理的假设输入与输出:**

*   **假设输入 (ConsumeRadialGradient):**  CSS 字符串 `radial-gradient(circle, red 0%, blue 100%)`
    *   **输出:**  一个表示径向渐变的 `CSSRadialGradientValue` 对象，包含形状为 circle，颜色停止点为红色 0% 和蓝色 100%。

*   **假设输入 (ConsumeImageSet):** CSS 字符串 `-webkit-image-set(url("low.png") 1x, url("high.png") 2x)`
    *   **输出:** 一个 `CSSImageSetValue` 对象，包含两个 `CSSImageSetOptionValue` 对象，分别对应低分辨率和高分辨率的图像 URL 和分辨率值。

*   **假设输入 (ConsumeCrossFade):** CSS 字符串 `cross-fade(50%, url("image1.png"), url("image2.png"))`
    *   **输出:** 一个 `CSSCrossfadeValue` 对象，包含图像 `image1.png` 和 `image2.png`，以及它们之间的过渡比例 50%。

**用户或编程常见的使用错误及举例说明:**

*   **渐变语法错误:**
    *   **错误:** `background-image: linear-gradient(red blue);`  (缺少方向或角度)
    *   **结果:** 解析失败，该 CSS 属性值无效。
*   **`image-set()` 用法错误:**
    *   **错误:** `background-image: image-set(url("image.png"));` (缺少分辨率描述)
    *   **结果:** 解析失败，`image-set()` 需要指定分辨率。
*   **`cross-fade()` 参数错误:**
    *   **错误:** `background-image: cross-fade(url("image.png"));` (缺少第二个图像或颜色)
    *   **结果:** 解析失败，`cross-fade()` 至少需要两个图像或颜色。
*   **`paint()` 在非安全上下文中使用:**
    *   **错误:** 在非 HTTPS 页面中使用 `mask-image: paint(my-painter);`
    *   **结果:**  `ConsumePaint` 会返回 `nullptr`，导致该属性值无效。
*   **拼写错误或使用了不存在的关键字:**
    *   **错误:** `background-image: radial-gradient(cirlce, red, blue);` (circle 拼写错误)
    *   **结果:** 解析失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 HTML/CSS 代码:** 用户在 HTML 文件中通过 `<style>` 标签或者外部 CSS 文件编写包含 `linear-gradient`, `radial-gradient`, `image-set`, `cross-fade`, `paint` 等 CSS 函数的样式规则。
2. **浏览器加载和解析 HTML/CSS:** 当浏览器加载包含这些 CSS 代码的页面时，Blink 引擎的 CSS 解析器开始工作。
3. **遇到需要解析的图像或渐变值:** 当解析器遇到像 `background-image: linear-gradient(...)` 这样的属性值时，会识别出 `linear-gradient` 函数。
4. **调用相应的解析函数:**  解析器会根据函数名将控制权交给 `css_parsing_utils.cc` 文件中对应的解析函数，例如 `ConsumeLinearGradient`。
5. **词法分析和语法分析:** `ConsumeLinearGradient` 函数会进一步调用其他辅助函数 (例如 `ConsumeAngle`, `ConsumeIdent`, `ConsumeCommaIncludingWhitespace`, `ConsumeGradientColorStops`) 对 CSS 字符串进行词法分析 (分解成 token) 和语法分析 (按照 CSS 语法规则进行解析)。
6. **创建 CSSValue 对象:** 如果解析成功，这些函数会创建相应的 `CSSValue` 子类对象（例如 `CSSLinearGradientValue`），用于表示解析后的 CSS 值。
7. **应用样式:**  解析后的 `CSSValue` 对象会被用于后续的样式计算、布局和渲染阶段。

**调试线索:**

*   如果在开发者工具的 "Elements" 面板中，某个元素的样式中使用了渐变或 `image-set` 等，但显示不正确或被标记为无效，那么很可能是在此文件的解析过程中出现了问题。
*   可以使用 Chromium 的调试工具，例如断点调试，在 `css_parsing_utils.cc` 的相关函数中设置断点，查看解析过程中的 token 流和变量值，以定位解析错误的原因。
*   检查控制台是否有 CSS 解析错误相关的警告或错误信息。

**归纳一下它的功能:**

这部分 `css_parsing_utils.cc` 的主要功能是**解析 CSS 中与图像和渐变相关的复杂属性值**，包括各种类型的渐变 (`linear-gradient`, `radial-gradient`, `conic-gradient`)、`image-set()` 函数、`cross-fade()` 函数以及 `paint()` 函数。它负责将这些 CSS 字符串转换为 Blink 引擎可以理解和使用的 `CSSValue` 对象，是 CSS 样式解析的关键组成部分。

Prompt: 
```
这是目录为blink/renderer/core/css/properties/css_parsing_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共9部分，请归纳一下它的功能

"""
SSGradientRepeat repeating) {
  CSSValue* center_x = nullptr;
  CSSValue* center_y = nullptr;
  ConsumeOneOrTwoValuedPosition(stream, context, UnitlessQuirk::kForbid,
                                center_x, center_y);
  if ((center_x || center_y) && !ConsumeCommaIncludingWhitespace(stream)) {
    return nullptr;
  }

  const CSSIdentifierValue* shape =
      ConsumeIdent<CSSValueID::kCircle, CSSValueID::kEllipse>(stream);
  const CSSIdentifierValue* size_keyword =
      ConsumeIdent<CSSValueID::kClosestSide, CSSValueID::kClosestCorner,
                   CSSValueID::kFarthestSide, CSSValueID::kFarthestCorner,
                   CSSValueID::kContain, CSSValueID::kCover>(stream);
  if (!shape) {
    shape = ConsumeIdent<CSSValueID::kCircle, CSSValueID::kEllipse>(stream);
  }

  // Or, two lengths or percentages
  const CSSPrimitiveValue* horizontal_size = nullptr;
  const CSSPrimitiveValue* vertical_size = nullptr;
  if (!shape && !size_keyword) {
    horizontal_size = ConsumeLengthOrPercent(
        stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
    if (horizontal_size) {
      vertical_size = ConsumeLengthOrPercent(
          stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
      if (!vertical_size) {
        return nullptr;
      }
      ConsumeCommaIncludingWhitespace(stream);
    }
  } else {
    ConsumeCommaIncludingWhitespace(stream);
  }

  cssvalue::CSSGradientValue* result =
      MakeGarbageCollected<cssvalue::CSSRadialGradientValue>(
          center_x, center_y, shape, size_keyword, horizontal_size,
          vertical_size, repeating, cssvalue::kCSSPrefixedRadialGradient);
  return ConsumeGradientColorStops(stream, context, result,
                                   ConsumeGradientLengthOrPercent)
             ? result
             : nullptr;
}

static CSSValue* ConsumeRadialGradient(CSSParserTokenStream& stream,
                                       const CSSParserContext& context,
                                       cssvalue::CSSGradientRepeat repeating) {
  const CSSIdentifierValue* shape = nullptr;
  const CSSIdentifierValue* size_keyword = nullptr;
  const CSSPrimitiveValue* horizontal_size = nullptr;
  const CSSPrimitiveValue* vertical_size = nullptr;

  // First part of grammar, the size/shape/color space clause:
  // [ in <color-space>? &&
  // [[ circle || <length> ] |
  // [ ellipse || [ <length> | <percentage> ]{2} ] |
  // [ [ circle | ellipse] || <size-keyword> ]] ]

  Color::ColorSpace color_space;
  Color::HueInterpolationMethod hue_interpolation_method =
      Color::HueInterpolationMethod::kShorter;
  bool has_color_space = ConsumeColorInterpolationSpace(
      stream, color_space, hue_interpolation_method);

  for (int i = 0; i < 3; ++i) {
    if (stream.Peek().GetType() == kIdentToken) {
      CSSValueID id = stream.Peek().Id();
      if (id == CSSValueID::kCircle || id == CSSValueID::kEllipse) {
        if (shape) {
          return nullptr;
        }
        shape = ConsumeIdent(stream);
      } else if (id == CSSValueID::kClosestSide ||
                 id == CSSValueID::kClosestCorner ||
                 id == CSSValueID::kFarthestSide ||
                 id == CSSValueID::kFarthestCorner) {
        if (size_keyword) {
          return nullptr;
        }
        size_keyword = ConsumeIdent(stream);
      } else {
        break;
      }
    } else {
      CSSPrimitiveValue* center = ConsumeLengthOrPercent(
          stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
      if (!center) {
        break;
      }
      if (horizontal_size) {
        return nullptr;
      }
      horizontal_size = center;
      center = ConsumeLengthOrPercent(
          stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
      if (center) {
        vertical_size = center;
        ++i;
      }
    }
  }

  // You can specify size as a keyword or a length/percentage, not both.
  if (size_keyword && horizontal_size) {
    return nullptr;
  }
  // Circles must have 0 or 1 lengths.
  if (shape && shape->GetValueID() == CSSValueID::kCircle && vertical_size) {
    return nullptr;
  }
  // Ellipses must have 0 or 2 length/percentages.
  if (shape && shape->GetValueID() == CSSValueID::kEllipse && horizontal_size &&
      !vertical_size) {
    return nullptr;
  }
  // If there's only one size, it must be a length.
  if (!vertical_size && horizontal_size && horizontal_size->IsPercentage()) {
    return nullptr;
  }
  if ((horizontal_size && !horizontal_size->IsResolvableBeforeLayout()) ||
      (vertical_size && !vertical_size->IsResolvableBeforeLayout())) {
    return nullptr;
  }

  CSSValue* center_x = nullptr;
  CSSValue* center_y = nullptr;
  if (stream.Peek().Id() == CSSValueID::kAt) {
    stream.ConsumeIncludingWhitespace();
    ConsumePosition(stream, context, UnitlessQuirk::kForbid,
                    std::optional<WebFeature>(), center_x, center_y);
    if (!(center_x && center_y)) {
      return nullptr;
    }
    // Right now, CSS radial gradients have the same start and end centers.
  }

  if (!has_color_space) {
    has_color_space = ConsumeColorInterpolationSpace(stream, color_space,
                                                     hue_interpolation_method);
  }

  if ((shape || size_keyword || horizontal_size || center_x || center_y ||
       has_color_space) &&
      !ConsumeCommaIncludingWhitespace(stream)) {
    return nullptr;
  }

  cssvalue::CSSGradientValue* result =
      MakeGarbageCollected<cssvalue::CSSRadialGradientValue>(
          center_x, center_y, shape, size_keyword, horizontal_size,
          vertical_size, repeating, cssvalue::kCSSRadialGradient);

  if (has_color_space) {
    result->SetColorInterpolationSpace(color_space, hue_interpolation_method);
    context.Count(WebFeature::kCSSColorGradientColorSpace);
  }

  return ConsumeGradientColorStops(stream, context, result,
                                   ConsumeGradientLengthOrPercent)
             ? result
             : nullptr;
}

static CSSValue* ConsumeLinearGradient(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    cssvalue::CSSGradientRepeat repeating,
    cssvalue::CSSGradientType gradient_type) {
  // First part of grammar, the size/shape/color space clause:
  // [ in <color-space>? || [ <angle> | to <side-or-corner> ]?]
  bool expect_comma = true;
  Color::ColorSpace color_space;
  Color::HueInterpolationMethod hue_interpolation_method =
      Color::HueInterpolationMethod::kShorter;
  bool has_color_space = ConsumeColorInterpolationSpace(
      stream, color_space, hue_interpolation_method);

  const CSSPrimitiveValue* angle =
      ConsumeAngle(stream, context, WebFeature::kUnitlessZeroAngleGradient);
  const CSSIdentifierValue* end_x = nullptr;
  const CSSIdentifierValue* end_y = nullptr;
  if (!angle) {
    // <side-or-corner> parsing
    if (gradient_type == cssvalue::kCSSPrefixedLinearGradient ||
        ConsumeIdent<CSSValueID::kTo>(stream)) {
      end_x = ConsumeIdent<CSSValueID::kLeft, CSSValueID::kRight>(stream);
      end_y = ConsumeIdent<CSSValueID::kBottom, CSSValueID::kTop>(stream);
      if (!end_x && !end_y) {
        if (gradient_type == cssvalue::kCSSLinearGradient) {
          return nullptr;
        }
        end_y = CSSIdentifierValue::Create(CSSValueID::kTop);
        expect_comma = false;
      } else if (!end_x) {
        end_x = ConsumeIdent<CSSValueID::kLeft, CSSValueID::kRight>(stream);
      }
    } else {
      // No <angle> or <side-to-corner>
      expect_comma = false;
    }
  }
  // It's possible that the <color-space> comes after the [ <angle> |
  // <side-or-corner> ]
  if (!has_color_space) {
    has_color_space = ConsumeColorInterpolationSpace(stream, color_space,
                                                     hue_interpolation_method);
  }

  if (has_color_space) {
    expect_comma = true;
  }

  if (expect_comma && !ConsumeCommaIncludingWhitespace(stream)) {
    return nullptr;
  }

  cssvalue::CSSGradientValue* result =
      MakeGarbageCollected<cssvalue::CSSLinearGradientValue>(
          end_x, end_y, nullptr, nullptr, angle, repeating, gradient_type);

  if (has_color_space) {
    result->SetColorInterpolationSpace(color_space, hue_interpolation_method);
    context.Count(WebFeature::kCSSColorGradientColorSpace);
  }

  return ConsumeGradientColorStops(stream, context, result,
                                   ConsumeGradientLengthOrPercent)
             ? result
             : nullptr;
}

static CSSValue* ConsumeConicGradient(CSSParserTokenStream& stream,
                                      const CSSParserContext& context,
                                      cssvalue::CSSGradientRepeat repeating) {
  Color::ColorSpace color_space;
  Color::HueInterpolationMethod hue_interpolation_method =
      Color::HueInterpolationMethod::kShorter;
  bool has_color_space = ConsumeColorInterpolationSpace(
      stream, color_space, hue_interpolation_method);

  const CSSPrimitiveValue* from_angle = nullptr;
  if (ConsumeIdent<CSSValueID::kFrom>(stream)) {
    if (!(from_angle = ConsumeAngle(stream, context,
                                    WebFeature::kUnitlessZeroAngleGradient))) {
      return nullptr;
    }
  }

  CSSValue* center_x = nullptr;
  CSSValue* center_y = nullptr;
  if (ConsumeIdent<CSSValueID::kAt>(stream)) {
    if (!ConsumePosition(stream, context, UnitlessQuirk::kForbid,
                         std::optional<WebFeature>(), center_x, center_y)) {
      return nullptr;
    }
  }

  if (!has_color_space) {
    has_color_space = ConsumeColorInterpolationSpace(stream, color_space,
                                                     hue_interpolation_method);
  }

  // Comma separator required when fromAngle, position or color_space is
  // present.
  if ((from_angle || center_x || center_y || has_color_space) &&
      !ConsumeCommaIncludingWhitespace(stream)) {
    return nullptr;
  }

  auto* result = MakeGarbageCollected<cssvalue::CSSConicGradientValue>(
      center_x, center_y, from_angle, repeating);

  if (has_color_space) {
    result->SetColorInterpolationSpace(color_space, hue_interpolation_method);
    context.Count(WebFeature::kCSSColorGradientColorSpace);
  }

  return ConsumeGradientColorStops(stream, context, result,
                                   ConsumeGradientAngleOrPercent)
             ? result
             : nullptr;
}

CSSValue* ConsumeImageOrNone(CSSParserTokenStream& stream,
                             const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return ConsumeIdent(stream);
  }
  return ConsumeImage(stream, context);
}

CSSValue* ConsumeAxis(CSSParserTokenStream& stream,
                      const CSSParserContext& context) {
  CSSValueID axis_id = stream.Peek().Id();
  if (axis_id == CSSValueID::kX || axis_id == CSSValueID::kY ||
      axis_id == CSSValueID::kZ) {
    ConsumeIdent(stream);
    return MakeGarbageCollected<cssvalue::CSSAxisValue>(axis_id);
  }

  CSSValue* x_dimension =
      ConsumeNumber(stream, context, CSSPrimitiveValue::ValueRange::kAll);
  CSSValue* y_dimension =
      ConsumeNumber(stream, context, CSSPrimitiveValue::ValueRange::kAll);
  CSSValue* z_dimension =
      ConsumeNumber(stream, context, CSSPrimitiveValue::ValueRange::kAll);
  if (!x_dimension || !y_dimension || !z_dimension) {
    return nullptr;
  }
  return MakeGarbageCollected<cssvalue::CSSAxisValue>(
      To<CSSPrimitiveValue>(x_dimension), To<CSSPrimitiveValue>(y_dimension),
      To<CSSPrimitiveValue>(z_dimension));
}

CSSValue* ConsumeIntrinsicSizeLonghand(CSSParserTokenStream& stream,
                                       const CSSParserContext& context) {
  if (css_parsing_utils::IdentMatches<CSSValueID::kNone>(stream.Peek().Id())) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (css_parsing_utils::IdentMatches<CSSValueID::kAuto>(stream.Peek().Id())) {
    list->Append(*css_parsing_utils::ConsumeIdent(stream));
  }
  if (css_parsing_utils::IdentMatches<CSSValueID::kNone>(stream.Peek().Id())) {
    list->Append(*css_parsing_utils::ConsumeIdent(stream));
  } else {
    CSSValue* length = css_parsing_utils::ConsumeLength(
        stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
    if (!length) {
      return nullptr;
    }
    list->Append(*length);
  }
  return list;
}

static CSSValue* ConsumeDeprecatedWebkitCrossFade(
    CSSParserTokenStream& stream,
    const CSSParserContext& context) {
  CSSValue* from_image_value = ConsumeImageOrNone(stream, context);
  if (!from_image_value || !ConsumeCommaIncludingWhitespace(stream)) {
    return nullptr;
  }
  CSSValue* to_image_value = ConsumeImageOrNone(stream, context);
  if (!to_image_value || !ConsumeCommaIncludingWhitespace(stream)) {
    return nullptr;
  }

  CSSPrimitiveValue* percentage = nullptr;
  if (CSSPrimitiveValue* percent_value = ConsumePercent(
          stream, context, CSSPrimitiveValue::ValueRange::kAll)) {
    percentage = CSSNumericLiteralValue::Create(
        ClampTo<double>(percent_value->GetDoubleValue() / 100.0, 0, 1),
        CSSPrimitiveValue::UnitType::kNumber);
  } else if (CSSPrimitiveValue* number_value = ConsumeNumber(
                 stream, context, CSSPrimitiveValue::ValueRange::kAll)) {
    percentage = CSSNumericLiteralValue::Create(
        ClampTo<double>(number_value->GetDoubleValue(), 0, 1),
        CSSPrimitiveValue::UnitType::kNumber);
  }

  if (!percentage) {
    return nullptr;
  }
  return MakeGarbageCollected<cssvalue::CSSCrossfadeValue>(
      /*is_legacy_variant=*/true,
      HeapVector<std::pair<Member<CSSValue>, Member<CSSPrimitiveValue>>>{
          {from_image_value, nullptr}, {to_image_value, percentage}});
}

// https://drafts.csswg.org/css-images-4/#cross-fade-function
static CSSValue* ConsumeCrossFade(CSSParserTokenStream& stream,
                                  const CSSParserContext& context) {
  // Parse an arbitrary comma-separated image|color values,
  // where each image may have a percentage before or after it.
  HeapVector<std::pair<Member<CSSValue>, Member<CSSPrimitiveValue>>>
      image_and_percentages;
  CSSValue* image = nullptr;
  CSSPrimitiveValue* percentage = nullptr;
  for (;;) {
    if (CSSPrimitiveValue* percent_value = ConsumePercent(
            stream, context, CSSPrimitiveValue::ValueRange::kAll)) {
      if (percentage) {
        return nullptr;
      }
      if (percent_value->IsNumericLiteralValue()) {
        double val = percent_value->GetDoubleValue();
        if (!(val >= 0.0 &&
              val <= 100.0)) {  // Includes checks for NaN and infinities.
          return nullptr;
        }
      }
      percentage = percent_value;
      continue;
    } else if (CSSValue* image_value = ConsumeImage(stream, context)) {
      if (image) {
        return nullptr;
      }
      image = image_value;
    } else if (CSSValue* color_value = ConsumeColor(stream, context)) {
      if (image) {
        return nullptr;
      }

      // Wrap the color in a constant gradient, so that we can treat it as a
      // gradient in nearly all the remaining code.
      image =
          MakeGarbageCollected<cssvalue::CSSConstantGradientValue>(color_value);
    } else {
      if (!image) {
        return nullptr;
      }
      image_and_percentages.emplace_back(image, percentage);
      image = nullptr;
      percentage = nullptr;
      if (!ConsumeCommaIncludingWhitespace(stream)) {
        break;
      }
    }
  }
  if (image_and_percentages.empty()) {
    return nullptr;
  }

  return MakeGarbageCollected<cssvalue::CSSCrossfadeValue>(
      /*is_legacy_variant=*/false, image_and_percentages);
}

static CSSValue* ConsumePaint(CSSParserTokenStream& stream,
                              const CSSParserContext& context) {
  CSSCustomIdentValue* name = ConsumeCustomIdent(stream, context);
  if (!name) {
    return nullptr;
  }

  if (stream.AtEnd()) {
    return MakeGarbageCollected<CSSPaintValue>(name);
  }

  if (!RuntimeEnabledFeatures::CSSPaintAPIArgumentsEnabled()) {
    // Arguments not enabled, but exists. Invalid.
    return nullptr;
  }

  // Begin parse paint arguments.
  if (!ConsumeCommaIncludingWhitespace(stream)) {
    return nullptr;
  }

  // Consume arguments.
  // TODO(renjieliu): We may want to optimize the implementation by resolve
  // variables early if paint function is registered.
  Vector<CSSParserToken> argument_tokens;
  HeapVector<Member<CSSVariableData>> variable_data;
  bool first_argument = true;
  while (!stream.AtEnd()) {
    stream.ConsumeWhitespace();
    if (!first_argument) {
      if (stream.Peek().GetType() != kCommaToken) {
        return nullptr;
      }
      ConsumeCommaIncludingWhitespace(stream);
      if (stream.AtEnd()) {
        return nullptr;
      }
    }
    bool important_ignored;
    CSSVariableData* argument = CSSVariableParser::ConsumeUnparsedDeclaration(
        stream, /*allow_important_annotation=*/false,
        /*is_animation_tainted=*/false,
        /*must_contain_variable_reference=*/false,
        /*restricted_value=*/false, /*comma_ends_declaration=*/true,
        important_ignored, context);
    if (!argument) {
      return nullptr;
    }
    if (argument->NeedsVariableResolution()) {
      // If we see an un-substituted var() or similar, it is a sign that
      // we are in parsing (as opposed to resolving, where it would be
      // substituted). We need to return an error so that the value as a whole
      // becomes an unparsed value; we will be called back during resolving
      // with all substitutions done.
      //
      // This is something most properties do implicitly, since var() would
      // be a parse error. But since we accept pretty much any token sequence
      // as arguments to paint(), we need to make this check explicitly here.
      return nullptr;
    }
    variable_data.push_back(argument);
    first_argument = false;
  }

  return MakeGarbageCollected<CSSPaintValue>(name, std::move(variable_data));
}

static CSSValue* ConsumeGeneratedImage(CSSParserTokenStream& stream,
                                       const CSSParserContext& context) {
  CSSValueID id = stream.Peek().FunctionId();
  if (!IsGeneratedImage(id)) {
    return nullptr;
  }

  CSSValue* result = nullptr;
  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();
    if (id == CSSValueID::kRadialGradient) {
      result = ConsumeRadialGradient(stream, context, cssvalue::kNonRepeating);
    } else if (id == CSSValueID::kRepeatingRadialGradient) {
      result = ConsumeRadialGradient(stream, context, cssvalue::kRepeating);
    } else if (id == CSSValueID::kWebkitLinearGradient) {
      context.Count(WebFeature::kDeprecatedWebKitLinearGradient);
      result = ConsumeLinearGradient(stream, context, cssvalue::kNonRepeating,
                                     cssvalue::kCSSPrefixedLinearGradient);
    } else if (id == CSSValueID::kWebkitRepeatingLinearGradient) {
      context.Count(WebFeature::kDeprecatedWebKitRepeatingLinearGradient);
      result = ConsumeLinearGradient(stream, context, cssvalue::kRepeating,
                                     cssvalue::kCSSPrefixedLinearGradient);
    } else if (id == CSSValueID::kRepeatingLinearGradient) {
      result = ConsumeLinearGradient(stream, context, cssvalue::kRepeating,
                                     cssvalue::kCSSLinearGradient);
    } else if (id == CSSValueID::kLinearGradient) {
      result = ConsumeLinearGradient(stream, context, cssvalue::kNonRepeating,
                                     cssvalue::kCSSLinearGradient);
    } else if (id == CSSValueID::kWebkitGradient) {
      context.Count(WebFeature::kDeprecatedWebKitGradient);
      result = ConsumeDeprecatedGradient(stream, context);
    } else if (id == CSSValueID::kWebkitRadialGradient) {
      context.Count(WebFeature::kDeprecatedWebKitRadialGradient);
      result = ConsumeDeprecatedRadialGradient(stream, context,
                                               cssvalue::kNonRepeating);
    } else if (id == CSSValueID::kWebkitRepeatingRadialGradient) {
      context.Count(WebFeature::kDeprecatedWebKitRepeatingRadialGradient);
      result = ConsumeDeprecatedRadialGradient(stream, context,
                                               cssvalue::kRepeating);
    } else if (id == CSSValueID::kConicGradient) {
      result = ConsumeConicGradient(stream, context, cssvalue::kNonRepeating);
    } else if (id == CSSValueID::kRepeatingConicGradient) {
      result = ConsumeConicGradient(stream, context, cssvalue::kRepeating);
    } else if (id == CSSValueID::kWebkitCrossFade) {
      result = ConsumeDeprecatedWebkitCrossFade(stream, context);
    } else if (RuntimeEnabledFeatures::CSSCrossFadeEnabled() &&
               id == CSSValueID::kCrossFade) {
      result = ConsumeCrossFade(stream, context);
    } else if (id == CSSValueID::kPaint) {
      result =
          context.IsSecureContext() ? ConsumePaint(stream, context) : nullptr;
    }
    if (!result || !stream.AtEnd()) {
      return nullptr;
    }
    guard.Release();
  }
  stream.ConsumeWhitespace();

  WebFeature feature;
  if (id == CSSValueID::kWebkitCrossFade) {
    feature = WebFeature::kWebkitCrossFade;
  } else if (id == CSSValueID::kPaint) {
    feature = WebFeature::kCSSPaintFunction;
  } else {
    feature = WebFeature::kCSSGradient;
  }
  context.Count(feature);

  return result;
}

static CSSImageValue* CreateCSSImageValueWithReferrer(
    const StringView& uri,
    const CSSParserContext& context) {
  auto* image_value =
      MakeGarbageCollected<CSSImageValue>(CollectUrlData(uri, context));
  if (context.Mode() == kUASheetMode) {
    image_value->SetInitiator(fetch_initiator_type_names::kUacss);
  }
  return image_value;
}

static CSSImageSetTypeValue* ConsumeImageSetType(CSSParserTokenStream& stream) {
  if (stream.Peek().FunctionId() != CSSValueID::kType) {
    return nullptr;
  }

  String type;
  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();

    type = ConsumeStringAsString(stream);
    if (type.IsNull() || !stream.AtEnd()) {
      return nullptr;
    }

    guard.Release();
  }
  stream.ConsumeWhitespace();
  return MakeGarbageCollected<CSSImageSetTypeValue>(type);
}

static CSSImageSetOptionValue* ConsumeImageSetOption(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    ConsumeGeneratedImagePolicy generated_image_policy) {
  const CSSValue* image = ConsumeImage(stream, context, generated_image_policy,
                                       ConsumeStringUrlImagePolicy::kAllow,
                                       ConsumeImageSetImagePolicy::kForbid);
  if (!image) {
    return nullptr;
  }

  // Type could appear before or after resolution
  CSSImageSetTypeValue* type = ConsumeImageSetType(stream);
  CSSPrimitiveValue* resolution = ConsumeResolution(stream, context);
  if (!type) {
    type = ConsumeImageSetType(stream);
  }

  return MakeGarbageCollected<CSSImageSetOptionValue>(image, resolution, type);
}

static CSSValue* ConsumeImageSet(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    ConsumeGeneratedImagePolicy generated_image_policy =
        ConsumeGeneratedImagePolicy::kAllow) {
  auto* image_set = MakeGarbageCollected<CSSImageSetValue>();
  CSSValueID function_id = stream.Peek().FunctionId();
  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();

    do {
      auto* image_set_option =
          ConsumeImageSetOption(stream, context, generated_image_policy);
      if (!image_set_option) {
        return nullptr;
      }

      image_set->Append(*image_set_option);
    } while (ConsumeCommaIncludingWhitespace(stream));

    if (!stream.AtEnd()) {
      return nullptr;
    }

    switch (function_id) {
      case CSSValueID::kWebkitImageSet:
        context.Count(WebFeature::kWebkitImageSet);
        break;

      case CSSValueID::kImageSet:
        context.Count(WebFeature::kImageSet);
        break;

      default:
        NOTREACHED();
    }

    guard.Release();
  }
  stream.ConsumeWhitespace();

  return image_set;
}

CSSValue* ConsumeImage(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const ConsumeGeneratedImagePolicy generated_image_policy,
    const ConsumeStringUrlImagePolicy string_url_image_policy,
    const ConsumeImageSetImagePolicy image_set_image_policy) {
  CSSParserToken uri = ConsumeUrlAsToken(stream, context);
  if (uri.GetType() != kEOFToken) {
    return CreateCSSImageValueWithReferrer(uri.Value(), context);
  }
  if (string_url_image_policy == ConsumeStringUrlImagePolicy::kAllow) {
    wtf_size_t value_start_offset = stream.LookAheadOffset();
    String uri_string = ConsumeStringAsString(stream);
    if (!uri_string.IsNull()) {
      wtf_size_t value_end_offset = stream.LookAheadOffset();
      if (IsAttrTainted(stream, value_start_offset, value_end_offset)) {
        // https://drafts.csswg.org/css-values-5/#attr-security
        // “Additionally, attr() is not allowed to be used in any <url> value,
        // whether directly or indirectly. Doing so makes the property it’s used
        // in invalid.”
        return nullptr;
      }
      if (IsFetchRestricted(uri_string, context)) {
        uri_string = "";
      }
      return CreateCSSImageValueWithReferrer(uri_string, context);
    }
  }
  if (stream.Peek().GetType() == kFunctionToken) {
    CSSValueID id = stream.Peek().FunctionId();
    if (image_set_image_policy == ConsumeImageSetImagePolicy::kAllow &&
        IsImageSet(id)) {
      return ConsumeImageSet(stream, context, generated_image_policy);
    }
    if (generated_image_policy == ConsumeGeneratedImagePolicy::kAllow &&
        IsGeneratedImage(id)) {
      return ConsumeGeneratedImage(stream, context);
    }
    if (IsUASheetBehavior(context.Mode())) {
      return ConsumeLightDark(
          static_cast<CSSValue* (*)(CSSParserTokenStream&,
                                    const CSSParserContext&)>(
              ConsumeImageOrNone),
          stream, context);
    }
  }
  return nullptr;
}

// https://drafts.csswg.org/css-shapes-1/#typedef-shape-box
CSSIdentifierValue* ConsumeShapeBox(CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kContentBox, CSSValueID::kPaddingBox,
                      CSSValueID::kBorderBox, CSSValueID::kMarginBox>(stream);
}

// https://drafts.csswg.org/css-box-4/#typedef-visual-box
CSSIdentifierValue* ConsumeVisualBox(CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kContentBox, CSSValueID::kPaddingBox,
                      CSSValueID::kBorderBox>(stream);
}

// https://drafts.csswg.org/css-box-4/#typedef-coord-box
CSSIdentifierValue* ConsumeCoordBox(CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kContentBox, CSSValueID::kPaddingBox,
                      CSSValueID::kBorderBox, CSSValueID::kFillBox,
                      CSSValueID::kStrokeBox, CSSValueID::kViewBox>(stream);
}

// https://drafts.fxtf.org/css-masking/#typedef-geometry-box
CSSIdentifierValue* ConsumeGeometryBox(CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kBorderBox, CSSValueID::kPaddingBox,
                      CSSValueID::kContentBox, CSSValueID::kMarginBox,
                      CSSValueID::kFillBox, CSSValueID::kStrokeBox,
                      CSSValueID::kViewBox>(stream);
}

void AddProperty(CSSPropertyID resolved_property,
                 CSSPropertyID current_shorthand,
                 const CSSValue& value,
                 bool important,
                 IsImplicitProperty implicit,
                 HeapVector<CSSPropertyValue, 64>& properties) {
  DCHECK(!IsPropertyAlias(resolved_property));
  DCHECK(implicit == IsImplicitProperty::kNotImplicit ||
         implicit == IsImplicitProperty::kImplicit);

  int shorthand_index = 0;
  bool set_from_shorthand = false;

  if (IsValidCSSPropertyID(current_shorthand)) {
    Vector<StylePropertyShorthand, 4> shorthands;
    getMatchingShorthandsForLonghand(resolved_property, &shorthands);
    set_from_shorthand = true;
    if (shorthands.size() > 1) {
      shorthand_index =
          indexOfShorthandForLonghand(current_shorthand, shorthands);
    }
  }

  properties.push_back(CSSPropertyValue(
      CSSPropertyName(resolved_property), value, important, set_from_shorthand,
      shorthand_index, implicit == IsImplicitProperty::kImplicit));
}

CSSValue* ConsumeTransformValue(CSSParserTokenStream& stream,
                                const CSSParserContext& context) {
  bool use_legacy_parsing = false;
  return ConsumeTransformValue(stream, context, use_legacy_parsing);
}

CSSValue* ConsumeTransformList(CSSParserTokenStream& stream,
                               const CSSParserContext& context) {
  return ConsumeTransformList(stream, context, CSSParserLocalContext());
}

CSSValue* ConsumeFilterFunctionList(CSSParserTokenStream& stream,
                                    const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return ConsumeIdent(stream);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  do {
    CSSParserSavePoint savepoint(stream);
    CSSValue* filter_value = ConsumeUrl(stream, context);
    if (!filter_value) {
      filter_value = ConsumeFilterFunction(stream, context);
      if (!filter_value) {
        break;
      }
    }
    savepoint.Release();
    list->Append(*filter_value);
  } while (!stream.AtEnd());
  if (list->length() == 0) {
    return nullptr;
  }
  return list;
}

void CountKeywordOnlyPropertyUsage(CSSPropertyID property,
                                   const CSSParserContext& context,
                                   CSSValueID value_id) {
  if (!context.IsUseCounterRecordingEnabled()) {
    return;
  }
  switch (property) {
    case CSSPropertyID::kAppearance:
    case CSSPropertyID::kAliasWebkitAppearance: {
      // TODO(crbug.com/1426629): Remove warning after shipping.
      if (RuntimeEnabledFeatures::
              NonStandardAppearanceValueSliderVerticalEnabled() &&
          value_id == CSSValueID::kSliderVertical) {
        if (const auto* document = context.GetDocument()) {
          document->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
              mojom::blink::ConsoleMessageSource::kDeprecation,
              mojom::blink::ConsoleMessageLevel::kWarning,
              "The keyword 'slider-vertical' specified to an 'appearance' "
              "property is not standardized. It will be removed in the future. "
              "Use <input type=range style=\"writing-mode: vertical-lr; "
              "direction: rtl\"> instead."));
          Deprecation::CountDeprecation(
              document->GetExecutionContext(),
              WebFeature::kCSSValueAppearanceSliderVertical);
        }
        // We make double-sure the feature kCSSValueAppearanceSliderVertical is
        // counted here. It should also be counted below.
        context.Count(WebFeature::kCSSValueAppearanceSliderVertical);
      }
      WebFeature feature;
      if (value_id == CSSValueID::kNone) {
        feature = WebFeature::kCSSValueAppearanceNone;
      } else {
        feature = WebFeature::kCSSValueAppearanceNotNone;
        if (value_id == CSSValueID::kButton) {
          feature = WebFeature::kCSSValueAppearanceButton;
        } else if (value_id == CSSValueID::kCheckbox) {
          feature = WebFeature::kCSSValueAppearanceCheckbox;
        } else if (value_id == CSSValueID::kMenulist) {
          feature = WebFeature::kCSSValueAppearanceMenulist;
        } else if (value_id == CSSValueID::kMenulistButton) {
          feature = WebFeature::kCSSValueAppearanceMenulistButton;
        } else if (value_id == CSSValueID::kMeter) {
          feature = WebFeature::kCSSValueAppearanceMeter;
        } else if (value_id == CSSValueID::kListbox) {
          feature = WebFeature::kCSSValueAppearanceListbox;
        } else if (value_id == CSSValueID::kProgressBar) {
          feature = WebFeature::kCSSValueAppearanceProgressBar;
        } else if (value_id == CSSValueID::kRadio) {
          feature = WebFeature::kCSSValueAppearanceRadio;
        } else if (value_id == CSSValueID::kSearchfield) {
          feature = WebFeature::kCSSValueAppearanceSearchField;
        } else if (value_id == CSSValueID::kSliderVertical) {
          feature = WebFeature::kCSSValueAppearanceSliderVertical;
        } else if (value_id == CSSValueID::kTextarea) {
          feature = WebFeature::kCSSValueAppearanceTextarea;
        } else if (value_id == CSSValueID::kTextfield) {
          feature = WebFeature::kCSSValueAppearanceTextField;
     
"""


```
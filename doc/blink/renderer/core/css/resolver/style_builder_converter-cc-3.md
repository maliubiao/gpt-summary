Response:
My thinking process to answer the request about `style_builder_converter.cc` goes through these stages:

1. **Understand the Goal:** The primary goal is to explain the functionality of this specific Chromium Blink source file. The request also asks to relate it to web technologies (HTML, CSS, JavaScript), provide examples, discuss potential errors, outline a debugging path, and summarize the functionality.

2. **Analyze the File Path:**  The path `blink/renderer/core/css/resolver/style_builder_converter.cc` provides significant clues.
    * `blink/renderer`: This clearly indicates it's part of the rendering engine of Chromium.
    * `core/css`: This points to functionality related to CSS processing.
    * `resolver`: This suggests the file is involved in resolving or determining the final styles applied to elements.
    * `style_builder_converter.cc`: The "converter" part strongly implies that the file is responsible for converting CSS values into internal representations used by the rendering engine. The "style_builder" part hints at the context of style construction.

3. **Examine the Code Snippet (Focusing on Key Functions):** I carefully read the provided code, looking for the most important functions and their roles. I identified functions like:
    * `ResolveColorValue`:  This is central to handling CSS color values, including advanced color features like `color-mix` and relative color syntax. The logic for handling `light-dark()` is also present.
    * `ConvertStyleColor`:  This function seems to be the primary entry point for converting CSS color values in the style building process. It uses `ResolveColorValue`.
    * `ConvertStyleAutoColor`:  Handles the `auto` keyword for colors.
    * `ConvertSVGPaint`: Deals with how SVG fills and strokes are interpreted, including `context-fill` and `context-stroke`.
    * `ConvertTextBoxEdge`, `ConvertTextDecorationThickness`, etc.: A series of `Convert` functions for various CSS properties. This confirms the file's role as a converter.
    * `ConvertTransformOperations`, `ConvertTransformOrigin`, `ConvertTranslate`, `ConvertRotate`, `ConvertScale`: Functions dedicated to handling CSS transforms.
    * `ConvertRegisteredPropertyInitialValue`, `ConvertRegisteredPropertyValue`, `ConvertRegisteredPropertyVariableData`: Logic for handling CSS registered properties (custom properties).
    * `ConvertAspectRatio`:  Deals with the `aspect-ratio` CSS property.
    * `ConvertScrollbarColor`, `ConvertScrollbarGutter`: Functions related to styling scrollbars.

4. **Infer Functionality Based on Code Analysis:** Based on the identified functions, I can deduce the core functionality of the file:
    * **CSS Value Conversion:**  The primary function is to take CSS values (strings parsed from stylesheets) and convert them into internal C++ representations (e.g., `StyleColor`, `Length`, `TransformOperations`) that the rendering engine can use.
    * **Handling Specific CSS Features:**  It has specific logic for different CSS features, like colors (including advanced features), SVG paint, text decorations, transforms, registered properties, aspect ratio, and scrollbars.
    * **Contextual Conversion:** The functions often take a `StyleResolverState` as input, indicating that the conversion process is context-aware and depends on the current styling environment.
    * **Resolution of Complex Values:**  For values like colors and transforms, there's a resolution process involving helper functions to handle different syntax and keywords.

5. **Relate to Web Technologies:**  Now, I connect the inferred functionality to HTML, CSS, and JavaScript:
    * **CSS:** This is the most direct relationship. The file is fundamentally about processing CSS values. I provide examples of how different CSS properties (like `color`, `transform`, `aspect-ratio`) would be handled by the functions in this file.
    * **HTML:** The converted styles are ultimately applied to HTML elements. The file bridges the gap between the CSS syntax and the visual representation of HTML. I explain how the styling process starts with HTML elements having associated CSS rules.
    * **JavaScript:** JavaScript can manipulate CSS styles, and these manipulations would eventually go through a similar conversion process. I mention the `style` property and `getComputedStyle`.

6. **Develop Hypothetical Inputs and Outputs:**  For a few key functions (like `ResolveColorValue` and `ConvertTransformOperations`), I create simple examples of input CSS values and the expected output (internal representation). This illustrates the conversion process concretely.

7. **Consider User/Programming Errors:** I think about common mistakes developers might make when using CSS that could lead to issues within this conversion process. Examples include invalid color syntax, incorrect transform functions, and issues with registered property values.

8. **Construct a Debugging Scenario:** I outline a step-by-step user interaction that could lead to the execution of code within `style_builder_converter.cc`. This helps illustrate how a user action triggers the styling pipeline.

9. **Summarize the Functionality (Part 4 of 5):** Based on the analysis, I write a concise summary of the file's purpose, focusing on its role as a CSS value converter within the Blink rendering engine. I emphasize its contribution to the overall styling process.

10. **Review and Refine:**  I review the entire answer to ensure clarity, accuracy, and completeness. I check for any inconsistencies or areas that could be explained better. I make sure the explanation aligns with the provided code snippet and the broader context of a web browser's rendering engine. I also ensure the answer addresses all parts of the prompt.
好的，这是对 `blink/renderer/core/css/resolver/style_builder_converter.cc` 文件功能的归纳，基于您提供的代码片段（第四部分）：

**核心功能归纳 (基于提供的代码片段)：**

`style_builder_converter.cc` 的核心功能是 **将 CSS 属性值转换为 Blink 渲染引擎内部使用的特定数据结构**。  这是样式解析和构建过程中的关键步骤，发生在 CSS 解析之后，但在最终样式应用到渲染对象之前。

**具体功能点 (基于提供的代码片段)：**

1. **颜色值转换 (`ConvertStyleColor`, `ResolveColorValue`):**
   - **功能:** 将各种 CSS 颜色表示（如关键字、十六进制、`rgb()`、`hsl()`、`color()` 函数，以及更高级的 `color-mix()` 和相对颜色语法）转换为 `StyleColor` 对象。
   - **与 CSS 的关系:**  直接处理 CSS 颜色相关的属性，如 `color`, `background-color`, `border-color` 等。
   - **逻辑推理 (假设输入与输出):**
     - **输入:** CSS 字符串 `"red"`
     - **输出:** `StyleColor` 对象，内部表示为红色。
     - **输入:** CSS 字符串 `"rgb(255, 0, 0)"`
     - **输出:** `StyleColor` 对象，内部表示为红色。
     - **输入:** CSS 字符串 `"color-mix(in lch, blue 40%, red)"`
     - **输出:** `StyleColor` 对象，内部可能存储一个未解析的 `UnresolvedColorMix` 对象，直到计算时再解析。
   - **用户常见错误:**
     - 拼写错误的颜色关键字（例如，`re` 而不是 `red`）。
     - `rgb()` 或 `hsl()` 函数中参数超出范围（例如，`rgb(300, 0, 0)`）。
     - `color-mix()` 或相对颜色语法使用不正确的参数或颜色空间。

2. **自动颜色值转换 (`ConvertStyleAutoColor`):**
   - **功能:** 处理 `auto` 关键字在颜色属性中的使用，通常会使用默认或继承的颜色。
   - **与 CSS 的关系:** 对应 CSS 颜色属性中 `auto` 关键字的含义。

3. **SVG 绘制属性转换 (`ConvertSVGPaint`):**
   - **功能:** 将 SVG 相关的绘制属性值（如 `fill`, `stroke`）转换为 `SVGPaint` 对象，支持颜色、`none` 关键字、`url()` 引用、以及 `context-fill` 和 `context-stroke` 关键字。
   - **与 CSS 的关系:** 处理 SVG 元素样式中与绘制相关的属性。
   - **逻辑推理 (假设输入与输出):**
     - **输入:** CSS 字符串 `"blue"` (用于 SVG 的 `fill`)
     - **输出:** `SVGPaint` 对象，`type` 为 `kColor`，`color` 为蓝色。
     - **输入:** CSS 字符串 `"url(#myGradient)"` (用于 SVG 的 `fill`)
     - **输出:** `SVGPaint` 对象，`type` 为 `kUri`，`resource` 指向名为 "myGradient" 的资源。
   - **用户常见错误:**
     - `url()` 引用的 SVG 资源不存在。
     - 在不支持 `context-fill` 或 `context-stroke` 的上下文中使用了这些关键字。

4. **文本框边缘 (`ConvertTextBoxEdge`) 和文本装饰 (`ConvertTextDecorationThickness`) 转换:**
   - **功能:** 将 `text-box-edge` 和 `text-decoration-thickness` 属性的值转换为相应的内部表示。
   - **与 CSS 的关系:**  处理文本相关的 CSS 属性。

5. **文本强调位置 (`ConvertTextTextEmphasisPosition`) 转换:**
   - **功能:** 解析 `text-emphasis-position` 属性的值，包括 `over`, `under`, `left`, `right` 等关键字的组合。
   - **与 CSS 的关系:** 处理文本强调的位置。

6. **文本描边宽度 (`ConvertTextStrokeWidth`) 转换:**
   - **功能:** 将 `text-stroke-width` 属性的值转换为浮点数，可以处理关键字。
   - **与 CSS 的关系:** 处理文本描边的宽度。

7. **文本大小调整 (`ConvertTextSizeAdjust`) 转换:**
   - **功能:** 将 `text-size-adjust` 属性的值转换为 `TextSizeAdjust` 对象，处理 `none` 和 `auto` 关键字，以及百分比值。
   - **与 CSS 的关系:** 控制文本大小的自动调整。

8. **文本下划线位置和偏移 (`ConvertTextUnderlinePosition`, `ConvertTextUnderlineOffset`):**
   - **功能:** 解析 `text-underline-position` 和 `text-underline-offset` 属性的值。
   - **与 CSS 的关系:** 控制文本下划线的外观。

9. **变换 (`ConvertTransformOperations`, `ConvertTransformOrigin`, `ConvertTranslate`, `ConvertRotate`, `ConvertScale`):**
   - **功能:** 将 `transform` 和 `transform-origin` 属性的值转换为内部的变换操作序列 (`TransformOperations`) 和变换原点 (`TransformOrigin`) 对象。支持各种变换函数，如 `translate()`, `rotate()`, `scale()` 等。
   - **与 CSS 的关系:** 处理 CSS 变换效果。
   - **逻辑推理 (假设输入与输出):**
     - **输入:** CSS 字符串 `"translate(10px, 20px) rotate(45deg)"`
     - **输出:** `TransformOperations` 对象，包含一个平移操作和一个旋转操作。
   - **用户常见错误:**
     - 变换函数中参数错误或缺失。
     - `transform-origin` 的值不合法。

10. **滚动捕捉 (`ConvertSnapType`, `ConvertSnapAlign`):**
    - **功能:** 将 `scroll-snap-type` 和 `scroll-snap-align` 属性的值转换为 `cc::ScrollSnapType` 和 `cc::ScrollSnapAlign` 对象，用于实现滚动捕捉效果。
    - **与 CSS 的关系:** 处理滚动捕捉相关的 CSS 属性。

11. **图像方向 (`ConvertImageOrientation`):**
    - **功能:** 将 `image-orientation` 属性的值转换为 `RespectImageOrientationEnum` 枚举值，决定是否尊重图像的 EXIF 方向信息。
    - **与 CSS 的关系:** 控制图像的显示方向。

12. **路径 (`ConvertPathOrNone`, `ConvertOffsetPath`):**
    - **功能:** 将 `clip-path` 和 `offset-path` 等属性的值转换为 `StylePath` 或 `OffsetPathOperation` 对象，用于定义元素的裁剪区域或运动路径。
    - **与 CSS 的关系:** 处理路径相关的 CSS 属性。

13. **对象视口 (`ConvertObjectViewBox`):**
    - **功能:** 将 `object-view-box` 属性的值转换为 `BasicShape` 对象，用于定义嵌入内容的可视区域。
    - **与 CSS 的关系:** 处理 `object-view-box` 属性。

14. **已注册属性 (`ConvertRegisteredPropertyInitialValue`, `ConvertRegisteredPropertyValue`, `ConvertRegisteredPropertyVariableData`):**
    - **功能:** 处理 CSS 已注册的自定义属性。将初始值和使用时的值转换为内部表示，并处理动画情况下的数据。
    - **与 CSS 的关系:** 对应 CSS Houdini 的 Properties and Values API。
    - **逻辑推理 (假设输入与输出):**
      - **输入:** 已注册属性的初始值 `"10px"`
      - **输出:** `CSSPrimitiveValue` 对象，表示 10 像素。
    - **用户常见错误:**
      - 注册属性时类型定义与实际赋值不符。
      - 在不支持注册属性的浏览器中使用。

15. **宽高比 (`ConvertAspectRatio`):**
    - **功能:** 将 `aspect-ratio` 属性的值转换为 `StyleAspectRatio` 对象，处理 `auto` 关键字和比例值。
    - **与 CSS 的关系:** 处理元素的宽高比。

16. **内部对齐 (`ConvertInternalAlignContentBlock`, `ConvertInternalEmptyLineHeight`):**
    - **功能:**  处理一些内部使用的对齐相关的属性，可能与 Flexbox 或 Grid 布局有关。

17. **分页 (`ConvertPage`):**
    - **功能:** 将 `page` 属性的值转换为 `AtomicString`，用于命名分页符。
    - **与 CSS 的关系:**  处理分页媒体相关的 CSS 属性。

18. **Ruby 位置 (`ConvertRubyPosition`):**
    - **功能:** 将 `ruby-position` 属性的值转换为 `RubyPosition` 枚举值，控制 Ruby 注音的位置。
    - **与 CSS 的关系:**  处理 Ruby 相关的 CSS 属性。

19. **滚动条颜色 (`ConvertScrollbarColor`) 和槽 (`ConvertScrollbarGutter`):**
    - **功能:** 将 `scrollbar-color` 和 `scrollbar-gutter` 属性的值转换为 `StyleScrollbarColor` 对象和 `ScrollbarGutter` 枚举值，用于自定义滚动条的样式。
    - **与 CSS 的关系:** 处理滚动条样式相关的 CSS 属性。

20. **容器名称 (`ConvertContainerName`):**
    - **功能:** 将 `container-name` 属性的值转换为 `ScopedCSSNameList` 对象，用于指定容器查询的容器名称。
    - **与 CSS 的关系:** 处理容器查询相关的 CSS 属性。

21. **固有尺寸 (`ConvertIntrinsicDimension`):**
    - **功能:**  将表示固有尺寸的 CSS 值（如 `min-content`, `max-content`, `fit-content()` 等）转换为 `StyleIntrinsicLength` 对象。
    - **与 CSS 的关系:**  处理与元素内容相关的尺寸计算。

**用户操作如何到达这里 (调试线索):**

1. **加载 HTML 页面:** 用户在浏览器中打开一个包含 CSS 样式的 HTML 页面。
2. **CSS 解析:** Blink 的 CSS 解析器会解析 HTML 中 `<style>` 标签或外部 CSS 文件中的样式规则。
3. **样式计算:** 当需要确定一个 HTML 元素的最终样式时，Blink 的样式解析器会遍历匹配该元素的所有 CSS 规则。
4. **属性值转换:**  对于每个 CSS 属性值，`style_builder_converter.cc` 中的相应 `Convert...` 函数会被调用，将 CSSValue 对象转换为 Blink 内部使用的类型。
5. **样式构建:** 转换后的属性值被用于构建元素的 `ComputedStyle` 对象，该对象包含了元素最终的样式信息。
6. **渲染:** `ComputedStyle` 对象被渲染引擎用于布局和绘制元素。

**调试线索:**

- 如果在调试器中设置断点到 `style_builder_converter.cc` 的某个 `Convert...` 函数中，你可以观察到哪个 CSS 属性正在被处理，以及传入的 CSSValue 对象的内容。
- 可以检查 `StyleResolverState` 对象，了解当前的样式解析上下文。
- 如果样式没有按预期生效，可能是由于某个 `Convert...` 函数的转换逻辑出现了问题，或者 CSS 值本身存在错误。

**总结:**

`style_builder_converter.cc` 是 Blink 渲染引擎中一个至关重要的组件，负责将 CSS 属性值从文本表示转换为内部数据结构，这是样式系统工作的核心部分。它涵盖了各种各样的 CSS 属性，从基本的颜色和长度单位到更复杂的变换、动画和自定义属性。理解这个文件的功能有助于理解 Blink 如何处理和应用 CSS 样式。

### 提示词
```
这是目录为blink/renderer/core/css/resolver/style_builder_converter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
wise we need to store an unresolved value on StyleColor.
    if (style_color1.IsAbsoluteColor() && style_color2.IsAbsoluteColor()) {
      return StyleColor(unresolved_color_mix->Resolve(Color()));
    } else {
      return StyleColor(unresolved_color_mix);
    }
  }

  if (auto* relative_color_value =
          DynamicTo<cssvalue::CSSRelativeColorValue>(value)) {
    const StyleColor origin_color =
        ResolveColorValueImpl(relative_color_value->OriginColor(), context);
    const StyleColor::UnresolvedRelativeColor* unresolved_relative_color =
        MakeGarbageCollected<StyleColor::UnresolvedRelativeColor>(
            origin_color, relative_color_value->ColorInterpolationSpace(),
            relative_color_value->Channel0(), relative_color_value->Channel1(),
            relative_color_value->Channel2(), relative_color_value->Alpha());
    // https://drafts.csswg.org/css-color-5/#resolving-rcs
    // If the origin color is resolvable at computed-value time, the relative
    // color function should be resolved at computed-value time as well.
    // Otherwise we need to store an unresolved value on StyleColor.
    if (origin_color.IsAbsoluteColor()) {
      return StyleColor(unresolved_relative_color->Resolve(Color()));
    } else {
      return StyleColor(unresolved_relative_color);
    }
  }

  auto& light_dark_pair = To<CSSLightDarkValuePair>(value);
  const CSSValue& color_value = ResolveLightDarkPair(light_dark_pair, context);
  return ResolveColorValueImpl(color_value, context);
}

const CSSValue& ResolveLightDarkPair(
    const CSSLightDarkValuePair& light_dark_pair,
    const ResolveColorValueContext& context) {
  return context.used_color_scheme == mojom::blink::ColorScheme::kLight
             ? light_dark_pair.First()
             : light_dark_pair.Second();
}

bool ShouldConvertLegacyColorSpaceToSRGB(const CSSValue& value) {
  return value.IsRelativeColorValue() || value.IsColorMixValue();
}

}  // anonymous namespace

StyleColor ResolveColorValue(const CSSValue& value,
                             const ResolveColorValueContext& context) {
  // The rules for converting at the top level should apply transitively through
  // light-dark().
  if (auto* light_dark_pair = DynamicTo<CSSLightDarkValuePair>(value)) {
    const CSSValue& light_dark_result =
        ResolveLightDarkPair(*light_dark_pair, context);
    return ResolveColorValue(light_dark_result, context);
  }

  StyleColor result = ResolveColorValueImpl(value, context);
  if (ShouldConvertLegacyColorSpaceToSRGB(value) && result.IsAbsoluteColor()) {
    Color color = result.GetColor();
    if (Color::IsLegacyColorSpace(color.GetColorSpace())) {
      // Missing components can be carried forward when converting rgb(...) to
      // color(srgb, ...) since the two color spaces have analogous components.
      // For other legacy spaces, conversion to color(srgb, ...) requires
      // resolving missing components.
      const bool resolve_missing_components =
          (color.GetColorSpace() != Color::ColorSpace::kSRGBLegacy);
      color.ConvertToColorSpace(Color::ColorSpace::kSRGB,
                                resolve_missing_components);
      result = StyleColor(color);
    }
  }
  return result;
}

StyleColor StyleBuilderConverter::ConvertStyleColor(StyleResolverState& state,
                                                    const CSSValue& value,
                                                    bool for_visited_link) {
  mojom::blink::ColorScheme color_scheme =
      state.StyleBuilder().UsedColorScheme();
  auto& document = state.GetDocument();
  const ResolveColorValueContext context{
      .length_resolver = state.CssToLengthConversionData(),
      .text_link_colors = document.GetTextLinkColors(),
      .used_color_scheme = color_scheme,
      .color_provider = document.GetColorProviderForPainting(color_scheme),
      .is_in_web_app_scope = document.IsInWebAppScope(),
      .for_visited_link = for_visited_link};
  return ResolveColorValue(value, context);
}

StyleAutoColor StyleBuilderConverter::ConvertStyleAutoColor(
    StyleResolverState& state,
    const CSSValue& value,
    bool for_visited_link) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    if (identifier_value->GetValueID() == CSSValueID::kAuto) {
      return StyleAutoColor::AutoColor();
    }
  }
  return StyleAutoColor(ConvertStyleColor(state, value, for_visited_link));
}

SVGPaint StyleBuilderConverter::ConvertSVGPaint(StyleResolverState& state,
                                                const CSSValue& value,
                                                bool for_visited_link,
                                                CSSPropertyID property_id) {
  const CSSValue* local_value = &value;
  SVGPaint paint;
  if (const auto* list = DynamicTo<CSSValueList>(value)) {
    DCHECK_EQ(list->length(), 2u);
    paint.resource = ConvertElementReference(state, list->Item(0), property_id);
    local_value = &list->Item(1);
  }

  if (local_value->IsURIValue()) {
    paint.type = SVGPaintType::kUri;
    paint.resource = ConvertElementReference(state, *local_value, property_id);
  } else {
    auto* local_identifier_value = DynamicTo<CSSIdentifierValue>(local_value);
    if (local_identifier_value) {
      switch (local_identifier_value->GetValueID()) {
        case CSSValueID::kNone:
          paint.type =
              !paint.resource ? SVGPaintType::kNone : SVGPaintType::kUriNone;
          break;
        case CSSValueID::kContextFill:
          // context-fill cannot be use as a uri fallback
          DCHECK(!paint.resource);
          if (RuntimeEnabledFeatures::SvgContextPaintEnabled()) {
            paint.type = SVGPaintType::kContextFill;
            state.GetDocument().CountUse(WebFeature::kSvgContextFillOrStroke);
          } else {
            local_identifier_value = nullptr;
          }
          break;
        case CSSValueID::kContextStroke:
          // context-stroke cannot be use as a uri fallback
          DCHECK(!paint.resource);
          if (RuntimeEnabledFeatures::SvgContextPaintEnabled()) {
            paint.type = SVGPaintType::kContextStroke;
            state.GetDocument().CountUse(WebFeature::kSvgContextFillOrStroke);
          } else {
            local_identifier_value = nullptr;
          }
          break;
        default:
          // For all other keywords, try to parse as a color.
          local_identifier_value = nullptr;
          break;
      }
    }
    if (!local_identifier_value) {
      // TODO(fs): Pass along |for_visited_link|.
      paint.color = ConvertStyleColor(state, *local_value);
      paint.type =
          !paint.resource ? SVGPaintType::kColor : SVGPaintType::kUriColor;
    }
  }
  return paint;
}

// static
TextBoxEdge StyleBuilderConverter::ConvertTextBoxEdge(
    StyleResolverState& status,
    const CSSValue& value) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    return TextBoxEdge(identifier_value->ConvertTo<TextBoxEdge::Type>());
  }

  const auto* const list = DynamicTo<CSSValueList>(&value);
  DCHECK_EQ(list->length(), 2u);
  const CSSIdentifierValue& over = To<CSSIdentifierValue>(list->Item(0));
  const CSSIdentifierValue& under = To<CSSIdentifierValue>(list->Item(1));
  return TextBoxEdge(over.ConvertTo<TextBoxEdge::Type>(),
                     under.ConvertTo<TextBoxEdge::Type>());
}

TextDecorationThickness StyleBuilderConverter::ConvertTextDecorationThickness(
    StyleResolverState& state,
    const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value &&
      identifier_value->GetValueID() == CSSValueID::kFromFont) {
    return TextDecorationThickness(identifier_value->GetValueID());
  }

  return TextDecorationThickness(ConvertLengthOrAuto(state, value));
}

TextEmphasisPosition StyleBuilderConverter::ConvertTextTextEmphasisPosition(
    StyleResolverState& state,
    const CSSValue& value) {
  const auto& list = To<CSSValueList>(value);
  CSSValueID first = To<CSSIdentifierValue>(list.Item(0)).GetValueID();
  if (list.length() < 2) {
    if (first == CSSValueID::kOver) {
      return TextEmphasisPosition::kOverRight;
    }
    if (first == CSSValueID::kUnder) {
      return TextEmphasisPosition::kUnderRight;
    }
    return TextEmphasisPosition::kOverRight;
  }
  CSSValueID second = To<CSSIdentifierValue>(list.Item(1)).GetValueID();
  if (first == CSSValueID::kOver && second == CSSValueID::kRight) {
    return TextEmphasisPosition::kOverRight;
  }
  if (first == CSSValueID::kOver && second == CSSValueID::kLeft) {
    return TextEmphasisPosition::kOverLeft;
  }
  if (first == CSSValueID::kUnder && second == CSSValueID::kRight) {
    return TextEmphasisPosition::kUnderRight;
  }
  if (first == CSSValueID::kUnder && second == CSSValueID::kLeft) {
    return TextEmphasisPosition::kUnderLeft;
  }
  return TextEmphasisPosition::kOverRight;
}

float StyleBuilderConverter::ConvertTextStrokeWidth(StyleResolverState& state,
                                                    const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value && IsValidCSSValueID(identifier_value->GetValueID())) {
    float multiplier = ConvertLineWidth<float>(state, value);
    return CSSNumericLiteralValue::Create(multiplier / 48,
                                          CSSPrimitiveValue::UnitType::kEms)
        ->ComputeLength<float>(state.CssToLengthConversionData());
  }
  return To<CSSPrimitiveValue>(value).ComputeLength<float>(
      state.CssToLengthConversionData());
}

TextSizeAdjust StyleBuilderConverter::ConvertTextSizeAdjust(
    StyleResolverState& state,
    const CSSValue& value) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    if (identifier_value->GetValueID() == CSSValueID::kNone) {
      return TextSizeAdjust::AdjustNone();
    }
    if (identifier_value->GetValueID() == CSSValueID::kAuto) {
      return TextSizeAdjust::AdjustAuto();
    }
  }
  const CSSPrimitiveValue& primitive_value = To<CSSPrimitiveValue>(value);
  DCHECK(primitive_value.IsPercentage());
  return TextSizeAdjust(primitive_value.GetFloatValue() / 100.0f);
}

TextUnderlinePosition StyleBuilderConverter::ConvertTextUnderlinePosition(
    StyleResolverState& state,
    const CSSValue& value) {
  TextUnderlinePosition flags = TextUnderlinePosition::kAuto;

  auto process = [&flags](const CSSValue& identifier) {
    flags |=
        To<CSSIdentifierValue>(identifier).ConvertTo<TextUnderlinePosition>();
  };

  if (auto* value_list = DynamicTo<CSSValueList>(value)) {
    for (auto& entry : *value_list) {
      process(*entry);
    }
  } else {
    process(value);
  }
  return flags;
}

Length StyleBuilderConverter::ConvertTextUnderlineOffset(
    StyleResolverState& state,
    const CSSValue& value) {
  return ConvertLengthOrAuto(state, value);
}

TransformOperations StyleBuilderConverter::ConvertTransformOperations(
    StyleResolverState& state,
    const CSSValue& value) {
  return TransformBuilder::CreateTransformOperations(
      value, state.CssToLengthConversionData());
}

TransformOrigin StyleBuilderConverter::ConvertTransformOrigin(
    StyleResolverState& state,
    const CSSValue& value) {
  const auto& list = To<CSSValueList>(value);
  DCHECK_GE(list.length(), 2u);
  DCHECK(list.Item(0).IsPrimitiveValue() || list.Item(0).IsIdentifierValue());
  DCHECK(list.Item(1).IsPrimitiveValue() || list.Item(1).IsIdentifierValue());
  float z = 0;
  if (list.length() == 3) {
    DCHECK(list.Item(2).IsPrimitiveValue());
    z = StyleBuilderConverter::ConvertComputedLength<float>(state,
                                                            list.Item(2));
  }

  return TransformOrigin(
      ConvertPositionLength<CSSValueID::kLeft, CSSValueID::kRight>(
          state, list.Item(0)),
      ConvertPositionLength<CSSValueID::kTop, CSSValueID::kBottom>(
          state, list.Item(1)),
      z);
}

cc::ScrollSnapType StyleBuilderConverter::ConvertSnapType(
    StyleResolverState&,
    const CSSValue& value) {
  cc::ScrollSnapType snapType =
      ComputedStyleInitialValues::InitialScrollSnapType();
  if (const auto* pair = DynamicTo<CSSValuePair>(value)) {
    snapType.is_none = false;
    snapType.axis =
        To<CSSIdentifierValue>(pair->First()).ConvertTo<cc::SnapAxis>();
    snapType.strictness =
        To<CSSIdentifierValue>(pair->Second()).ConvertTo<cc::SnapStrictness>();
    return snapType;
  }

  if (To<CSSIdentifierValue>(value).GetValueID() == CSSValueID::kNone) {
    snapType.is_none = true;
    return snapType;
  }

  snapType.is_none = false;
  snapType.axis = To<CSSIdentifierValue>(value).ConvertTo<cc::SnapAxis>();
  return snapType;
}

cc::ScrollSnapAlign StyleBuilderConverter::ConvertSnapAlign(
    StyleResolverState&,
    const CSSValue& value) {
  cc::ScrollSnapAlign snapAlign =
      ComputedStyleInitialValues::InitialScrollSnapAlign();
  if (const auto* pair = DynamicTo<CSSValuePair>(value)) {
    snapAlign.alignment_block =
        To<CSSIdentifierValue>(pair->First()).ConvertTo<cc::SnapAlignment>();
    snapAlign.alignment_inline =
        To<CSSIdentifierValue>(pair->Second()).ConvertTo<cc::SnapAlignment>();
  } else {
    snapAlign.alignment_block =
        To<CSSIdentifierValue>(value).ConvertTo<cc::SnapAlignment>();
    snapAlign.alignment_inline = snapAlign.alignment_block;
  }
  return snapAlign;
}

TranslateTransformOperation* StyleBuilderConverter::ConvertTranslate(
    StyleResolverState& state,
    const CSSValue& value) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return nullptr;
  }
  const auto& list = To<CSSValueList>(value);
  DCHECK_LE(list.length(), 3u);
  Length tx = ConvertLength(state, list.Item(0));
  Length ty = Length::Fixed(0);
  double tz = 0;
  if (list.length() >= 2) {
    ty = ConvertLength(state, list.Item(1));
  }
  if (list.length() == 3) {
    tz = To<CSSPrimitiveValue>(list.Item(2))
             .ComputeLength<double>(state.CssToLengthConversionData());
  }

  return MakeGarbageCollected<TranslateTransformOperation>(
      tx, ty, tz, TransformOperation::kTranslate3D);
}

Rotation StyleBuilderConverter::ConvertRotation(
    const CSSLengthResolver& length_resolver,
    const CSSValue& value) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return Rotation(gfx::Vector3dF(0, 0, 1), 0);
  }

  const auto& list = To<CSSValueList>(value);
  DCHECK(list.length() == 1 || list.length() == 2);
  double x = 0;
  double y = 0;
  double z = 1;
  if (list.length() == 2) {
    // axis angle
    const cssvalue::CSSAxisValue& axis =
        To<cssvalue::CSSAxisValue>(list.Item(0));
    std::tie(x, y, z) = axis.ComputeAxis(length_resolver);
  }
  const CSSPrimitiveValue& angle =
      To<CSSPrimitiveValue>(list.Item(list.length() - 1));
  return Rotation(gfx::Vector3dF(x, y, z),
                  angle.ComputeDegrees(length_resolver));
}

RotateTransformOperation* StyleBuilderConverter::ConvertRotate(
    StyleResolverState& state,
    const CSSValue& value) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return nullptr;
  }

  return MakeGarbageCollected<RotateTransformOperation>(
      ConvertRotation(state.CssToLengthConversionData(), value),
      TransformOperation::kRotate3D);
}

ScaleTransformOperation* StyleBuilderConverter::ConvertScale(
    StyleResolverState& state,
    const CSSValue& value) {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return nullptr;
  }

  const auto& list = To<CSSValueList>(value);
  DCHECK_LE(list.length(), 3u);
  double sx = To<CSSPrimitiveValue>(list.Item(0))
                  .ComputeNumber(state.CssToLengthConversionData());
  double sy = sx;
  double sz = 1;
  if (list.length() >= 2) {
    sy = To<CSSPrimitiveValue>(list.Item(1))
             .ComputeNumber(state.CssToLengthConversionData());
  }
  if (list.length() == 3) {
    sz = To<CSSPrimitiveValue>(list.Item(2))
             .ComputeNumber(state.CssToLengthConversionData());
  }

  return MakeGarbageCollected<ScaleTransformOperation>(
      sx, sy, sz, TransformOperation::kScale3D);
}

RespectImageOrientationEnum StyleBuilderConverter::ConvertImageOrientation(
    StyleResolverState& state,
    const CSSValue& value) {
  // The default is kFromImage, so branch on the only other valid value, kNone.
  return To<CSSIdentifierValue>(value).GetValueID() == CSSValueID::kNone
             ? kDoNotRespectImageOrientation
             : kRespectImageOrientation;
}

scoped_refptr<StylePath> StyleBuilderConverter::ConvertPathOrNone(
    StyleResolverState& state,
    const CSSValue& value) {
  if (auto* path_value = DynamicTo<cssvalue::CSSPathValue>(value)) {
    return path_value->GetStylePath();
  }
  DCHECK_EQ(To<CSSIdentifierValue>(value).GetValueID(), CSSValueID::kNone);
  return nullptr;
}

namespace {

OffsetPathOperation* ConvertOffsetPathValueToOperation(
    StyleResolverState& state,
    const CSSValue& value,
    CoordBox coord_box) {
  if (value.IsRayValue() || value.IsBasicShapeValue()) {
    return MakeGarbageCollected<ShapeOffsetPathOperation>(
        BasicShapeForValue(state, value), coord_box);
  }
  if (auto* path_value = DynamicTo<cssvalue::CSSPathValue>(value)) {
    return MakeGarbageCollected<ShapeOffsetPathOperation>(
        path_value->GetStylePath(), coord_box);
  }
  const auto& url_value = To<cssvalue::CSSURIValue>(value);
  SVGResource* resource =
      state.GetElementStyleResources().GetSVGResourceFromValue(
          CSSPropertyID::kOffsetPath, url_value);
  return MakeGarbageCollected<ReferenceOffsetPathOperation>(
      url_value.ValueForSerialization(), resource, coord_box);
}

}  // namespace

OffsetPathOperation* StyleBuilderConverter::ConvertOffsetPath(
    StyleResolverState& state,
    const CSSValue& value) {
  if (value.IsIdentifierValue()) {
    DCHECK(To<CSSIdentifierValue>(value).GetValueID() == CSSValueID::kNone);
    // none: The element does not have an offset transform.
    return nullptr;
  }
  const auto& list = To<CSSValueList>(value);
  if (const auto* identifier = DynamicTo<CSSIdentifierValue>(list.First())) {
    // If <offset-path> is omitted, it defaults to inset(0 round X),
    // where X is the value of border-radius on the element that
    // establishes the containing block for this element.
    return MakeGarbageCollected<CoordBoxOffsetPathOperation>(
        identifier->ConvertTo<CoordBox>());
  }
  // If <coord-box> is omitted, it defaults to border-box.
  CoordBox coord_box =
      list.length() == 2
          ? To<CSSIdentifierValue>(list.Last()).ConvertTo<CoordBox>()
          : CoordBox::kBorderBox;
  return ConvertOffsetPathValueToOperation(state, list.First(), coord_box);
}

scoped_refptr<BasicShape> StyleBuilderConverter::ConvertObjectViewBox(
    StyleResolverState& state,
    const CSSValue& value) {
  if (!value.IsBasicShapeInsetValue() && !value.IsBasicShapeRectValue() &&
      !value.IsBasicShapeXYWHValue()) {
    return nullptr;
  }
  return BasicShapeForValue(state, value);
}

static const CSSValue& ComputeColorValue(
    const CSSLengthResolver& length_resolver,
    const CSSValue& color_value,
    const Document& document,
    mojom::blink::ColorScheme color_scheme) {
  const ResolveColorValueContext context{
      .length_resolver = length_resolver,
      .text_link_colors = document.GetTextLinkColors(),
      .used_color_scheme = color_scheme,
      .color_provider = document.GetColorProviderForPainting(color_scheme),
      .is_in_web_app_scope = document.IsInWebAppScope(),
      .for_visited_link = false};
  const StyleColor style_color = ResolveColorValue(color_value, context);
  return *style_color.ToCSSValue();
}

static const CSSValue& ComputeRegisteredPropertyValue(
    const Document& document,
    const StyleResolverState* state,
    const CSSToLengthConversionData& css_to_length_conversion_data,
    const CSSValue& value,
    const CSSParserContext* context) {
  // TODO(timloh): Images values can also contain lengths.
  if (const auto* function_value = DynamicTo<CSSFunctionValue>(value)) {
    CSSFunctionValue* new_function =
        MakeGarbageCollected<CSSFunctionValue>(function_value->FunctionType());
    for (const CSSValue* inner_value : To<CSSValueList>(value)) {
      new_function->Append(ComputeRegisteredPropertyValue(
          document, state, css_to_length_conversion_data, *inner_value,
          context));
    }
    return *new_function;
  }

  if (const auto* old_list = DynamicTo<CSSValueList>(value)) {
    CSSValueList* new_list = CSSValueList::CreateWithSeparatorFrom(*old_list);
    for (const CSSValue* inner_value : *old_list) {
      new_list->Append(ComputeRegisteredPropertyValue(
          document, state, css_to_length_conversion_data, *inner_value,
          context));
    }
    return *new_list;
  }

  if (const auto* primitive_value = DynamicTo<CSSPrimitiveValue>(value)) {
    // For simple (non-calculated) px or percentage values, we do not need to
    // convert, as the value already has the proper computed form.
    if (!primitive_value->IsCalculated() &&
        (primitive_value->IsPx() || primitive_value->IsPercentage())) {
      return value;
    }

    if (primitive_value->IsLength() || primitive_value->IsPercentage() ||
        !primitive_value->IsResolvableBeforeLayout()) {
      // Instead of the actual zoom, use 1 to avoid potential rounding errors
      Length length = primitive_value->ConvertToLength(
          css_to_length_conversion_data.Unzoomed());
      return *CSSPrimitiveValue::CreateFromLength(length, 1);
    }

    // Clamp/round calc() values according to the permitted range.
    //
    // https://drafts.csswg.org/css-values-4/#calc-type-checking
    if (primitive_value->IsNumber() && primitive_value->IsCalculated()) {
      const CSSMathFunctionValue& math_value =
          To<CSSMathFunctionValue>(*primitive_value);
      // Note that GetDoubleValue automatically clamps according to the
      // permitted range.
      return *CSSNumericLiteralValue::Create(
          math_value.ComputeNumber(css_to_length_conversion_data),
          CSSPrimitiveValue::UnitType::kNumber);
    }

    if (primitive_value->IsAngle()) {
      return *CSSNumericLiteralValue::Create(
          primitive_value->ComputeDegrees(css_to_length_conversion_data),
          CSSPrimitiveValue::UnitType::kDegrees);
    }

    if (primitive_value->IsTime()) {
      return *CSSNumericLiteralValue::Create(
          primitive_value->ComputeSeconds(css_to_length_conversion_data),
          CSSPrimitiveValue::UnitType::kSeconds);
    }

    if (primitive_value->IsResolution()) {
      return *CSSNumericLiteralValue::Create(
          primitive_value->ComputeDotsPerPixel(css_to_length_conversion_data),
          CSSPrimitiveValue::UnitType::kDotsPerPixel);
    }
  }

  mojom::blink::ColorScheme color_scheme =
      state ? state->StyleBuilder().UsedColorScheme()
            : mojom::blink::ColorScheme::kLight;

  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    CSSValueID value_id = identifier_value->GetValueID();
    if (value_id == CSSValueID::kCurrentcolor) {
      return value;
    }
    if (StyleColor::IsColorKeyword(value_id)) {
      return ComputeColorValue(css_to_length_conversion_data, *identifier_value,
                               document, color_scheme);
    }
  }

  if (const auto* uri_value = DynamicTo<cssvalue::CSSURIValue>(value)) {
    const KURL& base_url = context ? context->BaseURL() : KURL();
    const WTF::TextEncoding& charset =
        context ? context->Charset() : WTF::TextEncoding();
    return *uri_value->ComputedCSSValue(base_url, charset);
  }

  if (const auto* light_dark_pair = DynamicTo<CSSLightDarkValuePair>(value)) {
    const CSSValue& selected_value =
        color_scheme == mojom::blink::ColorScheme::kLight
            ? light_dark_pair->First()
            : light_dark_pair->Second();
    return ComputeRegisteredPropertyValue(document, state,
                                          css_to_length_conversion_data,
                                          selected_value, context);
  }

  if (auto* color_mix_value = DynamicTo<cssvalue::CSSColorMixValue>(value)) {
    return ComputeColorValue(css_to_length_conversion_data, *color_mix_value,
                             document, color_scheme);
  }

  if (auto* relative_color_value =
          DynamicTo<cssvalue::CSSRelativeColorValue>(value)) {
    return ComputeColorValue(css_to_length_conversion_data,
                             *relative_color_value, document, color_scheme);
  }

  return value;
}

const CSSValue& StyleBuilderConverter::ConvertRegisteredPropertyInitialValue(
    Document& document,
    const CSSValue& value) {
  CSSToLengthConversionData::FontSizes font_sizes;
  CSSToLengthConversionData::LineHeightSize line_height_size;
  CSSToLengthConversionData::ViewportSize viewport_size(
      document.GetLayoutView());
  CSSToLengthConversionData::ContainerSizes container_sizes;
  CSSToLengthConversionData::AnchorData anchor_data;
  CSSToLengthConversionData::Flags ignored_flags = 0;
  CSSToLengthConversionData conversion_data(
      WritingMode::kHorizontalTb, font_sizes, line_height_size, viewport_size,
      container_sizes, anchor_data,
      /* zoom */ 1.0f, ignored_flags, /*element=*/nullptr);

  const CSSParserContext* parser_context =
      document.ElementSheet().Contents()->ParserContext();
  return ComputeRegisteredPropertyValue(document, nullptr /* state */,
                                        conversion_data, value, parser_context);
}

const CSSValue& StyleBuilderConverter::ConvertRegisteredPropertyValue(
    const StyleResolverState& state,
    const CSSValue& value,
    const CSSParserContext* parser_context) {
  return ComputeRegisteredPropertyValue(state.GetDocument(), &state,
                                        state.CssToLengthConversionData(),
                                        value, parser_context);
}

// Registered properties need to substitute as absolute values. This means
// that 'em' units (for instance) are converted to 'px ' and calc()-expressions
// are resolved. This function creates new tokens equivalent to the computed
// value of the registered property.
//
// This is necessary to make things like font-relative units in inherited
// (and registered) custom properties work correctly.
//
// https://drafts.css-houdini.org/css-properties-values-api-1/#substitution
CSSVariableData* StyleBuilderConverter::ConvertRegisteredPropertyVariableData(
    const CSSValue& value,
    bool is_animation_tainted) {
  // TODO(andruud): Produce tokens directly from CSSValue.
  return CSSVariableData::Create(value.CssText(), is_animation_tainted,
                                 /* needs_variable_resolution */ false);
}

namespace {
gfx::SizeF GetRatioFromList(const CSSLengthResolver& length_resolver,
                            const CSSValueList& list) {
  auto* ratio = DynamicTo<cssvalue::CSSRatioValue>(list.Item(0));
  if (!ratio) {
    DCHECK_EQ(list.length(), 2u);
    ratio = DynamicTo<cssvalue::CSSRatioValue>(list.Item(1));
  }
  DCHECK(ratio);
  return gfx::SizeF(ratio->First().ComputeNumber(length_resolver),
                    ratio->Second().ComputeNumber(length_resolver));
}

bool ListHasAuto(const CSSValueList& list) {
  // If there's only one entry, it needs to be a ratio.
  // (A single auto is handled separately)
  if (list.length() == 1u) {
    return false;
  }
  auto* auto_value = DynamicTo<CSSIdentifierValue>(list.Item(0));
  if (!auto_value) {
    auto_value = DynamicTo<CSSIdentifierValue>(list.Item(1));
  }
  DCHECK(auto_value) << "If we have two items, one of them must be auto";
  DCHECK_EQ(auto_value->GetValueID(), CSSValueID::kAuto);
  return true;
}
}  // namespace

StyleAspectRatio StyleBuilderConverter::ConvertAspectRatio(
    const StyleResolverState& state,
    const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value && identifier_value->GetValueID() == CSSValueID::kAuto) {
    return StyleAspectRatio(EAspectRatioType::kAuto, gfx::SizeF());
  }

  // (auto, (1, 2)) or ((1, 2), auto) or ((1, 2))
  const CSSValueList& list = To<CSSValueList>(value);
  DCHECK_GE(list.length(), 1u);
  DCHECK_LE(list.length(), 2u);

  bool has_auto = ListHasAuto(list);
  EAspectRatioType type =
      has_auto ? EAspectRatioType::kAutoAndRatio : EAspectRatioType::kRatio;
  gfx::SizeF ratio = GetRatioFromList(state.CssToLengthConversionData(), list);
  return StyleAspectRatio(type, ratio);
}

bool StyleBuilderConverter::ConvertInternalAlignContentBlock(
    StyleResolverState&,
    const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  return identifier_value &&
         identifier_value->GetValueID() == CSSValueID::kCenter;
}

bool StyleBuilderConverter::ConvertInternalEmptyLineHeight(
    StyleResolverState&,
    const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  return identifier_value &&
         identifier_value->GetValueID() == CSSValueID::kFabricated;
}

AtomicString StyleBuilderConverter::ConvertPage(StyleResolverState& state,
                                                const CSSValue& value) {
  if (auto* custom_ident_value = DynamicTo<CSSCustomIdentValue>(value)) {
    return AtomicString(custom_ident_value->Value());
  }
  DCHECK(DynamicTo<CSSIdentifierValue>(value));
  DCHECK_EQ(DynamicTo<CSSIdentifierValue>(value)->GetValueID(),
            CSSValueID::kAuto);
  return AtomicString();
}

RubyPosition StyleBuilderConverter::ConvertRubyPosition(
    StyleResolverState& state,
    const CSSValue& value) {
  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    CSSValueID value_id = identifier_value->GetValueID();
    if (value_id == CSSValueID::kBefore) {
      return RubyPosition::kOver;
    }
    if (value_id == CSSValueID::kAfter) {
      return RubyPosition::kUnder;
    }
    return identifier_value->ConvertTo<blink::RubyPosition>();
  }
  NOTREACHED();
}

StyleScrollbarColor* StyleBuilderConverter::ConvertScrollbarColor(
    StyleResolverState& state,
    const CSSValue& value) {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value && identifier_value->GetValueID() == CSSValueID::kAuto) {
    return nullptr;
  }

  const CSSValueList& list = To<CSSValueList>(value);
  DCHECK_GE(list.length(), 1u);
  DCHECK_LE(list.length(), 2u);
  const StyleColor thumb_color = ConvertStyleColor(state, list.First());
  const StyleColor track_color = ConvertStyleColor(state, list.Last());

  return MakeGarbageCollected<StyleScrollbarColor>(thumb_color, track_color);
}

ScrollbarGutter StyleBuilderConverter::ConvertScrollbarGutter(
    StyleResolverState& state,
    const CSSValue& value) {
  ScrollbarGutter flags = kScrollbarGutterAuto;

  auto process = [&flags](const CSSValue& identifier) {
    flags |= To<CSSIdentifierValue>(identifier).ConvertTo<ScrollbarGutter>();
  };

  if (auto* value_list = DynamicTo<CSSValueList>(value)) {
    for (auto& entry : *value_list) {
      process(*entry);
    }
  } else {
    process(value);
  }
  return flags;
}

ScopedCSSNameList* StyleBuilderConverter::ConvertContainerName(
    StyleResolverState& state,
    const CSSValue& value) {
  DCHECK(value.IsScopedValue());
  if (IsA<CSSIdentifierValue>(value)) {
    DCHECK_EQ(To<CSSIdentifierValue>(value).GetValueID(), CSSValueID::kNone);
    return nullptr;
  }
  DCHECK(value.IsBaseValueList());
  HeapVector<Member<const ScopedCSSName>> names;
  for (const Member<const CSSValue>& item : To<CSSValueList>(value)) {
    names.push_back(ConvertNoneOrCustomIdent(state, *item));
  }
  return MakeGarbageCollected<ScopedCSSNameList>(std::move(names));
}

StyleIntrinsicLength StyleBuilderConverter::ConvertIntrinsicDimension(
    const StyleResolverState& state,
    const CSSValue& value) {
  // The valid grammar for this value is the following:
  // none | <length> | auto && <length> | auto && none.

  // Handle "none", which is the only case where we get an identifier.
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value) {
    DCHECK(identifier_value->GetValueID() == CSSValueID::kNone);
    return StyleIntrinsicLength(/*has_auto=*/false, std::nullopt);
  }

  // Handle "<length> | auto && <length> | auto && none, whic
```
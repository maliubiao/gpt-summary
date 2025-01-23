Response:
Let's break down the thought process for analyzing the C++ code and generating the explanation.

**1. Initial Understanding - The Big Picture:**

The first step is to read the file's header comments and the `#include` directives. This immediately tells us:

* **Purpose:** The file is part of the Blink rendering engine, specifically dealing with CSS. It's responsible for "resolving" or processing CSS filter operations.
* **Key Concepts:**  The code mentions `FilterOperation`, `CSSValue`, `CSSFunctionValue`, `CSSPrimitiveValue`, and `StyleResolverState`. These are all fundamental CSS concepts within Blink.
* **Dependencies:**  It depends on other Blink components related to CSS parsing, style resolution, and platform utilities.

**2. Function-by-Function Analysis:**

Next, I'd go through each function defined in the file, understanding its specific role:

* **`FilterOperationForType(CSSValueID type)`:** This function is clearly a mapping. Given a CSS keyword (like `grayscale`, `blur`), it returns an internal representation (`FilterOperation::OperationType`). This is a crucial step in translating CSS syntax into an internal structure Blink can work with.

* **`CountFilterUse(FilterOperation::OperationType operation_type, const Document& document)`:** This function is about tracking usage. Based on the filter operation type, it increments a counter associated with a specific web feature. This is for collecting statistics about which CSS features are being used on the web. The `NOTREACHED()` for certain filter types indicates those aren't directly handled here (perhaps they have their own specialized resolvers).

* **`ResolveNumericArgumentForFunction(const CSSFunctionValue& filter, const CSSLengthResolver& length_resolver)`:**  This function focuses on extracting and processing numeric arguments from filter functions (like the percentage in `grayscale(50%)` or the angle in `hue-rotate(90deg)`). It handles percentages, numbers, and angles, and importantly, *clamps* values to valid ranges where necessary. The `CSSLengthResolver` suggests it's dealing with units and resolving them to pixel values.

* **`CreateFilterOperations(StyleResolverState& state, const CSSValue& in_value, CSSPropertyID property_id)`:** This is a core function. It takes a CSS value (presumably the `filter` property value) and converts it into a list of `FilterOperation` objects. It iterates through the list of filter functions, handles `url()` for referencing SVG filters, and calls the helper functions to process the arguments of each filter function. The `StyleResolverState` is vital as it provides context for resolving styles.

* **`CreateOffscreenFilterOperations(const CSSValue& in_value, const Font& font)`:** This function is similar to the previous one, but it's specifically for off-screen rendering contexts (like `<canvas>`). It sets up a default length resolver since there's no associated DOM element. The comment about `TODO(layout-dev)` indicates potential future improvements. It also explicitly skips the `CountFilterUse` call, probably because off-screen rendering might not be tracked the same way.

**3. Identifying Relationships with Web Technologies:**

With an understanding of the functions, I can start connecting them to JavaScript, HTML, and CSS:

* **CSS:** The entire file revolves around CSS. It directly deals with parsing CSS filter functions and their arguments. Examples of CSS `filter` property values are essential here.

* **HTML:** The `filter` property is applied to HTML elements. The code operates *after* the CSS has been parsed and is being applied to elements in the HTML document. The example of a `<div>` with a `filter` style demonstrates this.

* **JavaScript:** JavaScript can manipulate the `filter` property via the `style` attribute or the CSSOM (CSS Object Model). This is where the "user operation" aspect comes in. An example of JavaScript setting the `filter` is important.

**4. Logical Reasoning and Examples:**

For each function, I consider how it processes input and what the output would be. This involves:

* **Assumptions:**  Making assumptions about the input data format (e.g., the structure of `CSSFunctionValue`).
* **Tracing Flow:** Mentally stepping through the code with example inputs.
* **Illustrative Examples:**  Creating simple CSS snippets and tracing how they would be processed by the relevant functions. This helps solidify understanding.

**5. User and Programming Errors:**

I think about common mistakes developers might make when using CSS filters:

* **Invalid Values:**  Providing values outside the allowed range (e.g., `grayscale(1.5)`).
* **Incorrect Units:**  Using the wrong units for lengths or angles.
* **Typos:**  Misspelling filter function names.
* **Browser Compatibility:**  While not directly a *programming* error in the code itself, it's a common user issue.

**6. Debugging Clues - The User Journey:**

To understand how a user's action leads to this code being executed, I trace the typical web page rendering process:

1. **HTML Parsing:** The browser parses the HTML.
2. **CSS Parsing:** The browser parses the CSS, including the `filter` property.
3. **Style Resolution:** This is where `filter_operation_resolver.cc` comes in. The browser needs to determine the final styles for each element, including the effects of filters. This involves matching CSS rules to HTML elements.
4. **Layout:**  The browser calculates the positions and sizes of elements.
5. **Painting:** The browser draws the elements, applying the resolved styles, including the filters calculated by this code.

**Self-Correction/Refinement during the Thought Process:**

* **Initial Over-Simplification:** I might initially think a function does something simpler than it actually does. Reading the code carefully and looking at the data structures involved helps refine the understanding. For example, initially, I might not fully grasp the role of `StyleResolverState`.
* **Missing Edge Cases:** I might forget to consider edge cases or less common filter functions. The `NOTREACHED()` statements highlight places where the current code doesn't handle certain filter types directly.
* **Clarity of Explanation:**  I continually evaluate whether the explanation is clear and easy to understand. Using concrete examples is crucial for this. I might rephrase sections to make them more accessible.
* **Double-Checking Assumptions:**  I make sure my assumptions about the input and output of functions are consistent with the code.

By following these steps, systematically analyzing the code, and connecting it to the broader web development context, I can generate a comprehensive and accurate explanation like the example you provided.
好的，让我们来分析一下 `blink/renderer/core/css/resolver/filter_operation_resolver.cc` 文件的功能。

**文件功能总览**

`filter_operation_resolver.cc` 文件的主要功能是解析和处理 CSS `filter` 属性中定义的各种滤镜操作。它负责将 CSS 语法描述的滤镜效果转换为 Blink 渲染引擎内部可以理解和执行的数据结构 (`FilterOperations`)。

**具体功能分解**

1. **将 CSS 滤镜函数映射到内部操作类型:**
   - `FilterOperationForType(CSSValueID type)` 函数负责将 CSS 滤镜函数的 `CSSValueID` (例如 `CSSValueID::kGrayscale`) 映射到 `FilterOperation::OperationType` 枚举值 (例如 `FilterOperation::OperationType::kGrayscale`)。这是将 CSS 语法转换为内部表示的第一步。

2. **记录滤镜的使用情况:**
   - `CountFilterUse(FilterOperation::OperationType operation_type, const Document& document)` 函数用于统计各种 CSS 滤镜功能的使用频率。这对于了解 Web 平台的特性使用情况非常重要。它会根据使用的滤镜类型，调用 `document.CountUse()` 来记录。

3. **解析滤镜函数的数值参数:**
   - `ResolveNumericArgumentForFunction(const CSSFunctionValue& filter, const CSSLengthResolver& length_resolver)` 函数用于解析滤镜函数中的数值参数。例如，对于 `grayscale(50%)`，它会解析出 `0.5`。
   - 它会根据不同的滤镜函数类型进行不同的处理，例如处理百分比、角度等单位。
   - 对于某些需要限制取值范围的滤镜 (例如 `grayscale`, `sepia`, `opacity`)，它还会确保解析出的数值在 0 到 1 之间。

4. **创建 `FilterOperations` 对象:**
   - `CreateFilterOperations(StyleResolverState& state, const CSSValue& in_value, CSSPropertyID property_id)` 函数是核心功能，它接收 CSS `filter` 属性的值 (`CSSValue`)，并将其转换为一个 `FilterOperations` 对象。
   - 它会遍历 `filter` 属性值中的每一个滤镜函数或 `url()` 引用。
   - 对于每个滤镜函数，它会调用 `FilterOperationForType` 获取操作类型，并调用 `ResolveNumericArgumentForFunction` 解析参数。
   - 根据不同的滤镜类型，它会创建不同的 `FilterOperation` 子类实例，例如 `BasicColorMatrixFilterOperation` (用于 `grayscale`, `sepia`, `saturate`, `hue-rotate`)，`BasicComponentTransferFilterOperation` (用于 `invert`, `brightness`, `contrast`, `opacity`)，`BlurFilterOperation`，`DropShadowFilterOperation` 等。
   - 如果遇到 `url()` 函数，它会创建 `ReferenceFilterOperation` 来引用 SVG 滤镜。
   - `StyleResolverState` 提供了样式解析的上下文信息，例如长度单位的解析等。

5. **为离屏画布创建 `FilterOperations`:**
   - `CreateOffscreenFilterOperations(const CSSValue& in_value, const Font& font)` 函数与 `CreateFilterOperations` 类似，但它是专门为离屏画布 (OffscreenCanvas) 创建 `FilterOperations` 的。
   - 由于离屏画布没有关联的 DOM 元素，它使用了一组默认的字体大小来解析长度单位。
   - 注意，它跳过了 `CountFilterUse`，因为离屏画布的使用情况可能不需要像普通 DOM 元素那样被统计。

**与 Javascript, HTML, CSS 的关系及举例说明**

这个文件直接参与了 CSS `filter` 属性的处理，因此与 CSS 的关系最为密切。它也间接地与 HTML 和 JavaScript 有关：

* **CSS:**
   - **功能关系:**  `filter_operation_resolver.cc` 负责解析 CSS `filter` 属性的值。
   - **举例说明:** 当 CSS 中有如下代码时：
     ```css
     .element {
       filter: grayscale(50%) blur(5px);
     }
     ```
     `filter_operation_resolver.cc` 会解析 `grayscale(50%)` 和 `blur(5px)` 这两个滤镜函数，并创建相应的 `FilterOperation` 对象。

* **HTML:**
   - **功能关系:** `filter` 属性应用于 HTML 元素，从而影响元素的渲染效果。
   - **举例说明:** 上述 CSS 规则应用于一个 `<div>` 元素时：
     ```html
     <div class="element">This is some text.</div>
     ```
     Blink 引擎会使用 `filter_operation_resolver.cc` 解析出的 `FilterOperations` 来渲染这个 `div`，使其呈现灰度和模糊效果。

* **JavaScript:**
   - **功能关系:** JavaScript 可以动态地修改元素的 `filter` 属性，从而触发 `filter_operation_resolver.cc` 的执行。
   - **举例说明:** JavaScript 代码如下：
     ```javascript
     const element = document.querySelector('.element');
     element.style.filter = 'hue-rotate(90deg)';
     ```
     当这段 JavaScript 代码执行时，Blink 引擎会再次调用 `filter_operation_resolver.cc` 来解析新的 `filter` 属性值 `hue-rotate(90deg)`。

**逻辑推理的假设输入与输出**

**假设输入 (对于 `ResolveNumericArgumentForFunction`):**

```c++
CSSFunctionValue grayscale_func;
grayscale_func.SetFunctionType(CSSValueID::kGrayscale);
CSSPrimitiveValue* percentage_value = CSSPrimitiveValue::Create(50, CSSUnitType::kPercentageUnit);
grayscale_func.Append(percentage_value);

CSSLengthResolver length_resolver; // 假设 length_resolver 已初始化
```

**输出:**

```
ResolveNumericArgumentForFunction(grayscale_func, length_resolver)  // 返回 0.5
```

**假设输入 (对于 `CreateFilterOperations`):**

```c++
StyleResolverState state; // 假设 state 已初始化
CSSValueList filter_list;

// 添加 grayscale(0.5)
CSSFunctionValue* grayscale_func = CSSFunctionValue::Create(CSSValueID::kGrayscale);
CSSPrimitiveValue* grayscale_value = CSSPrimitiveValue::Create(0.5, CSSUnitType::kNumber);
grayscale_func->Append(grayscale_value);
filter_list.Append(grayscale_func);

// 添加 blur(3px)
CSSFunctionValue* blur_func = CSSFunctionValue::Create(CSSValueID::kBlur);
CSSPrimitiveValue* blur_value = CSSPrimitiveValue::Create(3, CSSUnitType::kPixel);
blur_func->Append(blur_value);
filter_list.Append(blur_func);
```

**输出:**

`CreateFilterOperations(state, filter_list, CSSPropertyID::kFilter)` 将返回一个 `FilterOperations` 对象，其中包含两个 `FilterOperation`：
1. 一个 `BasicColorMatrixFilterOperation`，其 `operation_type` 为 `kGrayscale`，参数为 `0.5`。
2. 一个 `BlurFilterOperation`，其 `std_deviation` 为长度 `3px`。

**用户或编程常见的使用错误**

1. **提供无效的滤镜值:**
   - **例子:** `filter: grayscale(150%);` // 百分比超过 100%
   - **说明:** 虽然代码中会对一些值进行 clamp，但提供超出合理范围的值仍然可能导致非预期的渲染结果或者在解析阶段被拒绝。

2. **拼写错误的滤镜函数名:**
   - **例子:** `filter: grascale(50%);`
   - **说明:** 这种错误会导致 CSS 解析失败，滤镜效果不会生效。

3. **使用了浏览器不支持的滤镜函数:**
   - **例子:**  使用了实验性的或非标准的滤镜函数。
   - **说明:**  `filter_operation_resolver.cc` 只会处理 Blink 引擎支持的滤镜类型。

4. **在 `url()` 中引用了不存在的 SVG 滤镜:**
   - **例子:** `filter: url(#nonexistent-filter);`
   - **说明:**  这会导致 `ReferenceFilterOperation` 无法找到对应的 SVG 资源，滤镜效果不会应用。

**用户操作是如何一步步的到达这里 (调试线索)**

假设用户在网页上看到一个元素的滤镜效果不正确，想要调试问题：

1. **用户在浏览器中加载包含 CSS `filter` 属性的网页。**
2. **浏览器解析 HTML 和 CSS。** 当解析到包含 `filter` 属性的 CSS 规则时，Blink 引擎会创建相应的 CSS 样式对象。
3. **样式计算 (Style Calculation/Resolution)。**  当需要计算元素的最终样式时，`StyleResolver` (以及相关的 `filter_operation_resolver.cc`) 会被调用来解析 `filter` 属性的值。
   - `StyleResolverState` 会被创建，包含当前元素的上下文信息。
   - `CSSValue` (代表 `filter` 属性的值) 会被传递给 `CreateFilterOperations`。
   - `CreateFilterOperations` 内部会调用其他函数 (如 `FilterOperationForType`, `ResolveNumericArgumentForFunction`) 来逐个解析滤镜函数。
4. **创建 `FilterOperations` 对象。**  解析的结果会被存储在 `FilterOperations` 对象中。
5. **渲染 (Rendering)。**  在渲染阶段，Blink 引擎会使用 `FilterOperations` 对象中存储的滤镜信息来应用图形效果。

**作为调试线索，可以关注以下几点：**

* **检查 CSS 源代码:** 确认 `filter` 属性的语法是否正确，滤镜函数名和参数是否拼写正确，单位是否正确。
* **使用开发者工具:**
    * 查看元素的 "Styles" 面板，确认 `filter` 属性的值是否被正确解析。
    * 检查 "Computed" 面板，查看最终计算出的 `filter` 值。
    * 使用 "Performance" 面板或 "Timeline" 面板，观察样式计算和渲染过程，看是否有异常。
* **断点调试 (如果可以访问 Blink 源代码):**
    * 在 `filter_operation_resolver.cc` 的关键函数 (例如 `CreateFilterOperations`, `ResolveNumericArgumentForFunction`) 设置断点，查看 CSS 值的解析过程和创建的 `FilterOperation` 对象。
    * 检查 `StyleResolverState` 中的上下文信息是否正确。
    * 确认 `CountFilterUse` 是否被正确调用，以了解哪些滤镜功能正在使用。

总而言之，`filter_operation_resolver.cc` 是 Blink 渲染引擎中处理 CSS 滤镜效果的关键组件，它负责将 CSS 语法转换为引擎内部可以使用的表示形式，并参与到网页的渲染过程中。

### 提示词
```
这是目录为blink/renderer/core/css/resolver/filter_operation_resolver.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 2004-2005 Allan Sandfeld Jensen (kde@carewolf.com)
 * Copyright (C) 2006, 2007 Nicholas Shanks (webkit@nickshanks.com)
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013 Apple Inc.
 * All rights reserved.
 * Copyright (C) 2007 Alexey Proskuryakov <ap@webkit.org>
 * Copyright (C) 2007, 2008 Eric Seidel <eric@webkit.org>
 * Copyright (C) 2008, 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 * Copyright (c) 2011, Code Aurora Forum. All rights reserved.
 * Copyright (C) Research In Motion Limited 2011. All rights reserved.
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/css/resolver/filter_operation_resolver.h"

#include "third_party/blink/renderer/core/css/css_function_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value_mappings.h"
#include "third_party/blink/renderer/core/css/css_uri_value.h"
#include "third_party/blink/renderer/core/css/resolver/style_builder_converter.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"

namespace blink {

static const float kOffScreenCanvasEmFontSize = 16.0;
static const float kOffScreenCanvasRemFontSize = 16.0;

FilterOperation::OperationType FilterOperationResolver::FilterOperationForType(
    CSSValueID type) {
  switch (type) {
    case CSSValueID::kGrayscale:
      return FilterOperation::OperationType::kGrayscale;
    case CSSValueID::kSepia:
      return FilterOperation::OperationType::kSepia;
    case CSSValueID::kSaturate:
      return FilterOperation::OperationType::kSaturate;
    case CSSValueID::kHueRotate:
      return FilterOperation::OperationType::kHueRotate;
    case CSSValueID::kInvert:
      return FilterOperation::OperationType::kInvert;
    case CSSValueID::kOpacity:
      return FilterOperation::OperationType::kOpacity;
    case CSSValueID::kBrightness:
      return FilterOperation::OperationType::kBrightness;
    case CSSValueID::kContrast:
      return FilterOperation::OperationType::kContrast;
    case CSSValueID::kBlur:
      return FilterOperation::OperationType::kBlur;
    case CSSValueID::kDropShadow:
      return FilterOperation::OperationType::kDropShadow;
    default:
      NOTREACHED();
  }
}

static void CountFilterUse(FilterOperation::OperationType operation_type,
                           const Document& document) {
  std::optional<WebFeature> feature;
  switch (operation_type) {
    case FilterOperation::OperationType::kBoxReflect:
    case FilterOperation::OperationType::kConvolveMatrix:
    case FilterOperation::OperationType::kComponentTransfer:
    case FilterOperation::OperationType::kTurbulence:
      NOTREACHED();
    case FilterOperation::OperationType::kReference:
      feature = WebFeature::kCSSFilterReference;
      break;
    case FilterOperation::OperationType::kGrayscale:
      feature = WebFeature::kCSSFilterGrayscale;
      break;
    case FilterOperation::OperationType::kSepia:
      feature = WebFeature::kCSSFilterSepia;
      break;
    case FilterOperation::OperationType::kSaturate:
      feature = WebFeature::kCSSFilterSaturate;
      break;
    case FilterOperation::OperationType::kHueRotate:
      feature = WebFeature::kCSSFilterHueRotate;
      break;
    case FilterOperation::OperationType::kLuminanceToAlpha:
      feature = WebFeature::kCSSFilterLuminanceToAlpha;
      break;
    case FilterOperation::OperationType::kColorMatrix:
      feature = WebFeature::kCSSFilterColorMatrix;
      break;
    case FilterOperation::OperationType::kInvert:
      feature = WebFeature::kCSSFilterInvert;
      break;
    case FilterOperation::OperationType::kOpacity:
      feature = WebFeature::kCSSFilterOpacity;
      break;
    case FilterOperation::OperationType::kBrightness:
      feature = WebFeature::kCSSFilterBrightness;
      break;
    case FilterOperation::OperationType::kContrast:
      feature = WebFeature::kCSSFilterContrast;
      break;
    case FilterOperation::OperationType::kBlur:
      feature = WebFeature::kCSSFilterBlur;
      break;
    case FilterOperation::OperationType::kDropShadow:
      feature = WebFeature::kCSSFilterDropShadow;
      break;
  };
  DCHECK(feature.has_value());
  document.CountUse(*feature);
}

double FilterOperationResolver::ResolveNumericArgumentForFunction(
    const CSSFunctionValue& filter,
    const CSSLengthResolver& length_resolver) {
  switch (filter.FunctionType()) {
    case CSSValueID::kGrayscale:
    case CSSValueID::kSepia:
    case CSSValueID::kSaturate:
    case CSSValueID::kInvert:
    case CSSValueID::kBrightness:
    case CSSValueID::kContrast:
    case CSSValueID::kOpacity: {
      if (filter.length() == 1) {
        const CSSPrimitiveValue& value = To<CSSPrimitiveValue>(filter.Item(0));
        double computed_value;
        if (value.IsPercentage()) {
          computed_value = value.ComputePercentage(length_resolver) / 100;
        } else {
          computed_value = value.ComputeNumber(length_resolver);
        }
        if (filter.FunctionType() != CSSValueID::kBrightness &&
            filter.FunctionType() != CSSValueID::kSaturate &&
            filter.FunctionType() != CSSValueID::kContrast) {
          // Most values will be clamped at parse time, but the ones within
          // calc() will not, so we need to clamp them again here.
          return std::clamp(computed_value, 0.0, 1.0);
        } else {
          return computed_value;
        }
      }
      return 1;
    }
    case CSSValueID::kHueRotate: {
      double angle = 0;
      if (filter.length() == 1) {
        const CSSPrimitiveValue& value = To<CSSPrimitiveValue>(filter.Item(0));
        angle = value.ComputeDegrees(length_resolver);
      }
      return angle;
    }
    default:
      return 0;
  }
}

FilterOperations FilterOperationResolver::CreateFilterOperations(
    StyleResolverState& state,
    const CSSValue& in_value,
    CSSPropertyID property_id) {
  FilterOperations operations;

  if (auto* in_identifier_value = DynamicTo<CSSIdentifierValue>(in_value)) {
    DCHECK_EQ(in_identifier_value->GetValueID(), CSSValueID::kNone);
    return operations;
  }

  const CSSToLengthConversionData& conversion_data =
      state.CssToLengthConversionData();

  for (auto& curr_value : To<CSSValueList>(in_value)) {
    if (const auto* url_value =
            DynamicTo<cssvalue::CSSURIValue>(curr_value.Get())) {
      CountFilterUse(FilterOperation::OperationType::kReference,
                     state.GetDocument());

      SVGResource* resource =
          state.GetElementStyleResources().GetSVGResourceFromValue(property_id,
                                                                   *url_value);
      operations.Operations().push_back(
          MakeGarbageCollected<ReferenceFilterOperation>(
              url_value->ValueForSerialization(), resource));
      continue;
    }

    const auto* filter_value = To<CSSFunctionValue>(curr_value.Get());
    FilterOperation::OperationType operation_type =
        FilterOperationForType(filter_value->FunctionType());
    CountFilterUse(operation_type, state.GetDocument());
    DCHECK_LE(filter_value->length(), 1u);
    switch (filter_value->FunctionType()) {
      case CSSValueID::kGrayscale:
      case CSSValueID::kSepia:
      case CSSValueID::kSaturate:
      case CSSValueID::kHueRotate: {
        operations.Operations().push_back(
            MakeGarbageCollected<BasicColorMatrixFilterOperation>(
                ResolveNumericArgumentForFunction(*filter_value,
                                                  conversion_data),
                operation_type));
        break;
      }
      case CSSValueID::kInvert:
      case CSSValueID::kBrightness:
      case CSSValueID::kContrast:
      case CSSValueID::kOpacity: {
        operations.Operations().push_back(
            MakeGarbageCollected<BasicComponentTransferFilterOperation>(
                ResolveNumericArgumentForFunction(*filter_value,
                                                  conversion_data),
                operation_type));
        break;
      }
      case CSSValueID::kBlur: {
        Length std_deviation = Length::Fixed(0);
        if (filter_value->length() >= 1) {
          const CSSPrimitiveValue* first_value =
              DynamicTo<CSSPrimitiveValue>(filter_value->Item(0));
          std_deviation = first_value->ConvertToLength(conversion_data);
        }
        operations.Operations().push_back(
            MakeGarbageCollected<BlurFilterOperation>(std_deviation));
        break;
      }
      case CSSValueID::kDropShadow: {
        ShadowData shadow = StyleBuilderConverter::ConvertShadow(
            conversion_data, &state, filter_value->Item(0));
        operations.Operations().push_back(
            MakeGarbageCollected<DropShadowFilterOperation>(shadow));
        break;
      }
      default:
        NOTREACHED();
    }
  }

  return operations;
}

FilterOperations FilterOperationResolver::CreateOffscreenFilterOperations(
    const CSSValue& in_value,
    const Font& font) {
  FilterOperations operations;

  if (auto* in_identifier_value = DynamicTo<CSSIdentifierValue>(in_value)) {
    DCHECK_EQ(in_identifier_value->GetValueID(), CSSValueID::kNone);
    return operations;
  }

  // TODO(layout-dev): Should document zoom factor apply for offscreen canvas?
  float zoom = 1.0f;
  CSSToLengthConversionData::FontSizes font_sizes(
      kOffScreenCanvasEmFontSize, kOffScreenCanvasRemFontSize, &font, zoom);
  CSSToLengthConversionData::LineHeightSize line_height_size;
  CSSToLengthConversionData::ViewportSize viewport_size(0, 0);
  CSSToLengthConversionData::ContainerSizes container_sizes;
  CSSToLengthConversionData::AnchorData anchor_data;
  CSSToLengthConversionData::Flags ignored_flags = 0;
  CSSToLengthConversionData conversion_data(
      WritingMode::kHorizontalTb, font_sizes, line_height_size, viewport_size,
      container_sizes, anchor_data, 1 /* zoom */, ignored_flags,
      /*element=*/nullptr);

  for (auto& curr_value : To<CSSValueList>(in_value)) {
    if (curr_value->IsURIValue()) {
      continue;
    }

    const auto* filter_value = To<CSSFunctionValue>(curr_value.Get());
    FilterOperation::OperationType operation_type =
        FilterOperationForType(filter_value->FunctionType());
    // TODO(fserb): Take an ExecutionContext argument to this function,
    // so we can have workers using UseCounter as well.
    // countFilterUse(operationType, state.document());
    DCHECK_LE(filter_value->length(), 1u);
    switch (filter_value->FunctionType()) {
      case CSSValueID::kGrayscale:
      case CSSValueID::kSepia:
      case CSSValueID::kSaturate:
      case CSSValueID::kHueRotate: {
        operations.Operations().push_back(
            MakeGarbageCollected<BasicColorMatrixFilterOperation>(
                ResolveNumericArgumentForFunction(*filter_value,
                                                  conversion_data),
                operation_type));
        break;
      }
      case CSSValueID::kInvert:
      case CSSValueID::kBrightness:
      case CSSValueID::kContrast:
      case CSSValueID::kOpacity: {
        operations.Operations().push_back(
            MakeGarbageCollected<BasicComponentTransferFilterOperation>(
                ResolveNumericArgumentForFunction(*filter_value,
                                                  conversion_data),
                operation_type));
        break;
      }
      case CSSValueID::kBlur: {
        Length std_deviation = Length::Fixed(0);
        if (filter_value->length() >= 1) {
          const CSSPrimitiveValue* first_value =
              DynamicTo<CSSPrimitiveValue>(filter_value->Item(0));
          std_deviation = first_value->ConvertToLength(conversion_data);
        }
        operations.Operations().push_back(
            MakeGarbageCollected<BlurFilterOperation>(std_deviation));
        break;
      }
      case CSSValueID::kDropShadow: {
        ShadowData shadow = StyleBuilderConverter::ConvertShadow(
            conversion_data, nullptr, filter_value->Item(0));
        operations.Operations().push_back(
            MakeGarbageCollected<DropShadowFilterOperation>(shadow));
        break;
      }
      default:
        NOTREACHED();
    }
  }
  return operations;
}

}  // namespace blink
```
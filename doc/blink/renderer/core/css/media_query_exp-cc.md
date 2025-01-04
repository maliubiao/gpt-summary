Response:
The user wants to understand the functionality of the `media_query_exp.cc` file in the Chromium Blink rendering engine. I need to analyze the code and provide a comprehensive summary covering its purpose, relationship with web technologies, logical deductions, potential user errors, and debugging hints. Since this is part 1 of 2, I should focus on summarizing the core functionalities implemented within this specific code snippet.

**Plan:**

1. **Identify Core Functionality:**  The code seems to primarily handle parsing and representation of individual media query expressions.
2. **Analyze Key Structures:** Focus on `MediaQueryExp`, `MediaQueryExpValue`, and the various `MediaQueryExpNode` subclasses.
3. **Determine Relationships:** Identify connections to CSS, HTML, and JavaScript.
4. **Illustrate with Examples:** Create hypothetical inputs and outputs to demonstrate parsing logic.
5. **Consider User Errors:** Think about common mistakes users might make when writing media queries.
6. **Provide Debugging Clues:**  Explain how a user's actions might lead to this code being executed.
7. **Summarize Part 1:**  Offer a concise overview of the functionalities covered in this code segment.
```
这是目录为blink/renderer/core/css/media_query_exp.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

根据提供的代码，`blink/renderer/core/css/media_query_exp.cc` 文件的主要功能是：

1. **表示和操作 CSS 媒体查询表达式 (Media Query Expressions)：**  这个文件定义了用于表示和操作媒体查询表达式的 C++ 类和方法。这些表达式是 CSS 媒体查询的核心组成部分，用于描述特定的设备或环境特征。

2. **解析媒体查询表达式的值 (Parsing Media Query Expression Values):**  代码包含了用于解析媒体查询表达式中值的逻辑，例如数值、长度、分辨率、关键字等。`MediaQueryExpValue::Consume` 函数负责从 CSS 语法流中提取并验证这些值。

3. **验证媒体特性 (Media Feature) 及其值的有效性:**  代码中定义了一些静态内联函数（如 `FeatureWithValidIdent`, `FeatureWithValidLength`, `FeatureWithValidDensity` 等），用于检查特定的媒体特性是否接受特定类型或取值范围的值。例如，它会检查 `orientation` 媒体特性是否使用了 `portrait` 或 `landscape` 关键字。

4. **区分媒体特性的依赖性 (Dependency of Media Features):** 代码中包含一些方法（如 `IsViewportDependent`, `IsDeviceDependent`, `IsWidthDependent` 等）用于判断一个媒体特性是否依赖于视口、设备、宽度、高度等。这对于浏览器在不同场景下高效地评估媒体查询至关重要。

5. **序列化媒体查询表达式 (Serializing Media Query Expressions):**  `MediaQueryExp::Serialize` 函数可以将一个媒体查询表达式转换回 CSS 文本表示形式。

6. **管理媒体查询表达式的抽象语法树 (Abstract Syntax Tree - AST):**  代码中定义了 `MediaQueryExpNode` 及其子类（如 `MediaQueryFeatureExpNode`, `MediaQueryNotExpNode`, `MediaQueryAndExpNode` 等），用于构建媒体查询表达式的抽象语法树。这个 AST 用于表示复杂的媒体查询逻辑（例如，使用 `and`，`or`，`not` 组合多个表达式）。

7. **收集媒体查询表达式的单元信息 (Collecting Unit Information):** `MediaQueryExp::GetUnitFlags` 和 `MediaQueryExpValue::GetUnitFlags` 用于收集媒体查询表达式中使用的单位信息，例如是否使用了视口单位、字体相关单位等。

**与 JavaScript, HTML, CSS 的关系举例说明:**

*   **CSS:**  这是直接相关的。媒体查询表达式是 CSS 语法的一部分，用于根据设备或环境特性应用不同的样式规则。例如，在 CSS 文件中可以这样使用：

    ```css
    @media (max-width: 768px) {
      /* 屏幕宽度小于等于 768px 时的样式 */
      body {
        font-size: 14px;
      }
    }
    ```
    `max-width: 768px` 就是一个媒体查询表达式，`media_query_exp.cc` 中的代码负责解析和处理这部分。

*   **HTML:** HTML 文件通过 `<link>` 标签引入 CSS 文件，或者在 `<style>` 标签内嵌入 CSS 代码。当浏览器解析 HTML 并遇到包含媒体查询的 CSS 时，会调用 Blink 引擎的 CSS 解析和匹配模块，其中就包含 `media_query_exp.cc` 中的代码。

*   **JavaScript:**  JavaScript 可以通过 `window.matchMedia()` 方法来动态地检查当前环境是否满足某个媒体查询。例如：

    ```javascript
    if (window.matchMedia('(orientation: portrait)').matches) {
      console.log('当前设备处于竖屏模式');
    }
    ```
    当 JavaScript 调用 `matchMedia()` 时，Blink 引擎会解析提供的媒体查询字符串，这同样会涉及到 `media_query_exp.cc` 中的代码。

**逻辑推理的假设输入与输出:**

假设输入一个媒体查询表达式字符串 `"(min-width: 500px)"`，并且浏览器正在解析这段 CSS。

*   **假设输入:** CSS 语法流中的一段 token，表示 `"min-width"`, `":"`, `"500px"`。
*   **`MediaQueryExpValue::Consume` 的输出:**  会创建一个 `MediaQueryExpValue` 对象，其中包含了媒体特性名 `min-width` 和一个表示长度值 `500px` 的 `CSSPrimitiveValue` 对象。
*   **`MediaQueryExp::Create` 的输出:** 会创建一个 `MediaQueryExp` 对象，其中包含了媒体特性名 `min-width` 和一个 `MediaQueryExpBounds` 对象，表示下限边界为 `500px`。
*   **`MediaQueryFeatureExpNode::CollectFeatureFlags` 的输出:**  会返回一个表示宽度依赖的标志，因为 `min-width` 是一个与宽度相关的媒体特性。

**用户或编程常见的使用错误举例说明:**

1. **媒体特性名称拼写错误:** 用户在 CSS 中写了错误的媒体特性名称，例如 `min-widht` 而不是 `min-width`。  `media_query_exp.cc` 中的解析逻辑会识别出这是一个无效的媒体特性，导致样式规则无法正确应用。

2. **媒体特性值类型错误:** 用户为某个媒体特性提供了错误类型的值，例如为 `orientation` 提供了长度值 `100px`。 `FeatureWithValidIdent` 函数会检查到 `100px` 不是 `orientation` 特性允许的值 (`portrait` 或 `landscape`)。

3. **无效的比较运算符:**  虽然代码中定义了比较运算符，但在实际的 CSS 媒体查询语法中，通常不需要显式指定 `=`，而是通过 `:` 来赋值。  在某些情况下，范围查询会使用 `<`、`>` 等，但使用不当会导致解析错误。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户编写 HTML 和 CSS 代码:** 用户创建一个包含带有媒体查询的 CSS 规则的 HTML 文件或 CSS 文件。
2. **浏览器加载页面或 CSS 文件:** 当用户打开该 HTML 文件或浏览器加载外部 CSS 文件时，Blink 引擎开始解析这些资源。
3. **CSS 解析器遇到 `@media` 规则:**  CSS 解析器在解析 CSS 时遇到了 `@media` 规则。
4. **媒体查询解析启动:**  Blink 引擎的媒体查询解析器被调用，开始解析 `@media` 规则后面的媒体查询字符串。
5. **解析到媒体查询表达式:**  解析器将媒体查询字符串分解成一个个的表达式，例如 `(max-width: 768px)`。
6. **`media_query_exp.cc` 中的代码被执行:**  为了表示和处理这些表达式，`media_query_exp.cc` 文件中的类和函数（如 `MediaQueryExp::Create`, `MediaQueryExpValue::Consume` 等）会被调用，用于创建相应的 C++ 对象并验证其有效性。

**归纳一下它的功能 (Part 1):**

这个代码文件的主要功能是 **定义和实现了用于表示、解析、验证和操作 CSS 媒体查询表达式的底层数据结构和逻辑**。它负责将 CSS 媒体查询表达式的文本表示转换为 Blink 引擎内部可以理解和处理的对象，并提供了一些工具函数来检查媒体特性的有效性以及其依赖关系。这部分代码是 Blink 引擎处理 CSS 媒体查询的核心组成部分。

Prompt: 
```
这是目录为blink/renderer/core/css/media_query_exp.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * CSS Media Query
 *
 * Copyright (C) 2006 Kimmo Kinnunen <kimmo.t.kinnunen@nokia.com>.
 * Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies).
 * Copyright (C) 2013 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/css/media_query_exp.h"

#include "third_party/blink/renderer/core/css/css_math_expression_node.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_unparsed_declaration_value.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_impl.h"
#include "third_party/blink/renderer/core/css/parser/css_variable_parser.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/decimal.h"
#include "third_party/blink/renderer/platform/wtf/text/string_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

using media_feature_names::kMaxDeviceAspectRatioMediaFeature;
using media_feature_names::kMaxDevicePixelRatioMediaFeature;
using media_feature_names::kMinDeviceAspectRatioMediaFeature;

static inline bool FeatureWithValidIdent(const String& media_feature,
                                         CSSValueID ident,
                                         const CSSParserContext& context) {
  if (media_feature == media_feature_names::kDisplayModeMediaFeature) {
    return ident == CSSValueID::kFullscreen ||
           ident == CSSValueID::kBorderless ||
           ident == CSSValueID::kStandalone ||
           ident == CSSValueID::kMinimalUi ||
           ident == CSSValueID::kWindowControlsOverlay ||
           ident == CSSValueID::kBrowser || ident == CSSValueID::kTabbed ||
           ident == CSSValueID::kPictureInPicture;
  }

  if (RuntimeEnabledFeatures::DesktopPWAsAdditionalWindowingControlsEnabled() &&
      media_feature == media_feature_names::kDisplayStateMediaFeature) {
    return ident == CSSValueID::kFullscreen || ident == CSSValueID::kNormal ||
           ident == CSSValueID::kMinimized || ident == CSSValueID::kMaximized;
  }

  if (RuntimeEnabledFeatures::DesktopPWAsAdditionalWindowingControlsEnabled() &&
      media_feature == media_feature_names::kResizableMediaFeature) {
    return ident == CSSValueID::kTrue || ident == CSSValueID::kFalse;
  }

  if (media_feature == media_feature_names::kOrientationMediaFeature) {
    return ident == CSSValueID::kPortrait || ident == CSSValueID::kLandscape;
  }

  if (media_feature == media_feature_names::kPointerMediaFeature ||
      media_feature == media_feature_names::kAnyPointerMediaFeature) {
    return ident == CSSValueID::kNone || ident == CSSValueID::kCoarse ||
           ident == CSSValueID::kFine;
  }

  if (media_feature == media_feature_names::kHoverMediaFeature ||
      media_feature == media_feature_names::kAnyHoverMediaFeature) {
    return ident == CSSValueID::kNone || ident == CSSValueID::kHover;
  }

  if (media_feature == media_feature_names::kScanMediaFeature) {
    return ident == CSSValueID::kInterlace || ident == CSSValueID::kProgressive;
  }

  if (media_feature == media_feature_names::kColorGamutMediaFeature) {
    return ident == CSSValueID::kSRGB || ident == CSSValueID::kP3 ||
           ident == CSSValueID::kRec2020;
  }

  if (RuntimeEnabledFeatures::InvertedColorsEnabled() &&
      media_feature == media_feature_names::kInvertedColorsMediaFeature) {
    return ident == CSSValueID::kInverted || ident == CSSValueID::kNone;
  }

  if (media_feature == media_feature_names::kPrefersColorSchemeMediaFeature) {
    return ident == CSSValueID::kDark || ident == CSSValueID::kLight;
  }

  if (media_feature == media_feature_names::kPrefersContrastMediaFeature) {
    return ident == CSSValueID::kNoPreference || ident == CSSValueID::kMore ||
           ident == CSSValueID::kLess || ident == CSSValueID::kCustom;
  }

  if (media_feature == media_feature_names::kPrefersReducedMotionMediaFeature) {
    return ident == CSSValueID::kNoPreference || ident == CSSValueID::kReduce;
  }

  if (media_feature == media_feature_names::kDynamicRangeMediaFeature) {
    return ident == CSSValueID::kStandard || ident == CSSValueID::kHigh;
  }

  if (RuntimeEnabledFeatures::CSSVideoDynamicRangeMediaQueriesEnabled()) {
    if (media_feature == media_feature_names::kVideoDynamicRangeMediaFeature) {
      return ident == CSSValueID::kStandard || ident == CSSValueID::kHigh;
    }
  }

  if (RuntimeEnabledFeatures::PrefersReducedDataEnabled() &&
      media_feature == media_feature_names::kPrefersReducedDataMediaFeature) {
    return ident == CSSValueID::kNoPreference || ident == CSSValueID::kReduce;
  }

  if (media_feature ==
      media_feature_names::kPrefersReducedTransparencyMediaFeature) {
    return ident == CSSValueID::kNoPreference || ident == CSSValueID::kReduce;
  }

  if (RuntimeEnabledFeatures::ForcedColorsEnabled()) {
    if (media_feature == media_feature_names::kForcedColorsMediaFeature) {
      return ident == CSSValueID::kNone || ident == CSSValueID::kActive;
    }
  }

  if (RuntimeEnabledFeatures::MediaQueryNavigationControlsEnabled()) {
    if (media_feature == media_feature_names::kNavigationControlsMediaFeature) {
      return ident == CSSValueID::kNone || ident == CSSValueID::kBackButton;
    }
  }

  if (RuntimeEnabledFeatures::DevicePostureEnabled(
          context.GetExecutionContext())) {
    if (media_feature == media_feature_names::kDevicePostureMediaFeature) {
      return ident == CSSValueID::kContinuous || ident == CSSValueID::kFolded;
    }
  }

  if (media_feature == media_feature_names::kOverflowInlineMediaFeature) {
    return ident == CSSValueID::kNone || ident == CSSValueID::kScroll;
  }

  if (media_feature == media_feature_names::kOverflowBlockMediaFeature) {
    return ident == CSSValueID::kNone || ident == CSSValueID::kScroll ||
           ident == CSSValueID::kPaged;
  }

  if (media_feature == media_feature_names::kUpdateMediaFeature) {
    return ident == CSSValueID::kNone || ident == CSSValueID::kFast ||
           ident == CSSValueID::kSlow;
  }

  if (RuntimeEnabledFeatures::CSSStickyContainerQueriesEnabled()) {
    if (media_feature == media_feature_names::kStuckMediaFeature) {
      switch (ident) {
        case CSSValueID::kNone:
        case CSSValueID::kTop:
        case CSSValueID::kLeft:
        case CSSValueID::kBottom:
        case CSSValueID::kRight:
        case CSSValueID::kBlockStart:
        case CSSValueID::kBlockEnd:
        case CSSValueID::kInlineStart:
        case CSSValueID::kInlineEnd:
          return true;
        default:
          return false;
      }
    }
  }

  if (media_feature == media_feature_names::kScriptingMediaFeature) {
    return ident == CSSValueID::kEnabled || ident == CSSValueID::kInitialOnly ||
           ident == CSSValueID::kNone;
  }

  if (RuntimeEnabledFeatures::CSSSnapContainerQueriesEnabled()) {
    if (media_feature == media_feature_names::kSnappedMediaFeature) {
      switch (ident) {
        case CSSValueID::kNone:
        case CSSValueID::kBlock:
        case CSSValueID::kInline:
        case CSSValueID::kX:
        case CSSValueID::kY:
          return true;
        default:
          return false;
      }
    }
  }

  if (RuntimeEnabledFeatures::CSSOverflowContainerQueriesEnabled()) {
    if (media_feature == media_feature_names::kOverflowingMediaFeature) {
      switch (ident) {
        case CSSValueID::kNone:
        case CSSValueID::kTop:
        case CSSValueID::kLeft:
        case CSSValueID::kBottom:
        case CSSValueID::kRight:
        case CSSValueID::kBlockStart:
        case CSSValueID::kBlockEnd:
        case CSSValueID::kInlineStart:
        case CSSValueID::kInlineEnd:
          return true;
        default:
          return false;
      }
    }
  }

  return false;
}

static inline bool FeatureWithValidLength(const String& media_feature,
                                          const CSSPrimitiveValue* value) {
  if (!(value->IsLength() ||
        (value->IsNumber() &&
         value->IsZero() == CSSPrimitiveValue::BoolStatus::kTrue))) {
    return false;
  }

  return media_feature == media_feature_names::kHeightMediaFeature ||
         media_feature == media_feature_names::kMaxHeightMediaFeature ||
         media_feature == media_feature_names::kMinHeightMediaFeature ||
         media_feature == media_feature_names::kWidthMediaFeature ||
         media_feature == media_feature_names::kMaxWidthMediaFeature ||
         media_feature == media_feature_names::kMinWidthMediaFeature ||
         media_feature == media_feature_names::kBlockSizeMediaFeature ||
         media_feature == media_feature_names::kMaxBlockSizeMediaFeature ||
         media_feature == media_feature_names::kMinBlockSizeMediaFeature ||
         media_feature == media_feature_names::kInlineSizeMediaFeature ||
         media_feature == media_feature_names::kMaxInlineSizeMediaFeature ||
         media_feature == media_feature_names::kMinInlineSizeMediaFeature ||
         media_feature == media_feature_names::kDeviceHeightMediaFeature ||
         media_feature == media_feature_names::kMaxDeviceHeightMediaFeature ||
         media_feature == media_feature_names::kMinDeviceHeightMediaFeature ||
         media_feature == media_feature_names::kDeviceWidthMediaFeature ||
         media_feature == media_feature_names::kMinDeviceWidthMediaFeature ||
         media_feature == media_feature_names::kMaxDeviceWidthMediaFeature;
}

static inline bool FeatureWithValidDensity(const String& media_feature,
                                           const CSSPrimitiveValue* value) {
  // NOTE: The allowed range of <resolution> values always excludes negative
  // values, in addition to any explicit ranges that might be specified.
  // https://drafts.csswg.org/css-values/#resolution
  if (!value->IsResolution() ||
      value->IsNegative() == CSSPrimitiveValue::BoolStatus::kTrue) {
    return false;
  }

  return media_feature == media_feature_names::kResolutionMediaFeature ||
         media_feature == media_feature_names::kMinResolutionMediaFeature ||
         media_feature == media_feature_names::kMaxResolutionMediaFeature;
}

static inline bool FeatureExpectingInteger(const String& media_feature,
                                           const CSSParserContext& context) {
  if (media_feature == media_feature_names::kColorMediaFeature ||
      media_feature == media_feature_names::kMaxColorMediaFeature ||
      media_feature == media_feature_names::kMinColorMediaFeature ||
      media_feature == media_feature_names::kColorIndexMediaFeature ||
      media_feature == media_feature_names::kMaxColorIndexMediaFeature ||
      media_feature == media_feature_names::kMinColorIndexMediaFeature ||
      media_feature == media_feature_names::kMonochromeMediaFeature ||
      media_feature == media_feature_names::kMaxMonochromeMediaFeature ||
      media_feature == media_feature_names::kMinMonochromeMediaFeature) {
    return true;
  }

  if (RuntimeEnabledFeatures::ViewportSegmentsEnabled(
          context.GetExecutionContext())) {
    if (media_feature ==
            media_feature_names::kHorizontalViewportSegmentsMediaFeature ||
        media_feature ==
            media_feature_names::kVerticalViewportSegmentsMediaFeature) {
      return true;
    }
  }

  return false;
}

static inline bool FeatureWithInteger(const String& media_feature,
                                      const CSSPrimitiveValue* value,
                                      const CSSParserContext& context) {
  if (!value->IsInteger()) {
    return false;
  }
  return FeatureExpectingInteger(media_feature, context);
}

static inline bool FeatureWithNumber(const String& media_feature,
                                     const CSSPrimitiveValue* value) {
  if (!value->IsNumber()) {
    return false;
  }

  return media_feature == media_feature_names::kTransform3dMediaFeature ||
         media_feature == media_feature_names::kDevicePixelRatioMediaFeature ||
         media_feature == kMaxDevicePixelRatioMediaFeature ||
         media_feature == media_feature_names::kMinDevicePixelRatioMediaFeature;
}

static inline bool FeatureWithZeroOrOne(const String& media_feature,
                                        const CSSPrimitiveValue* value) {
  if (!value->IsInteger() ||
      (value->IsOne() == CSSPrimitiveValue::BoolStatus::kFalse &&
       value->IsZero() == CSSPrimitiveValue::BoolStatus::kFalse)) {
    return false;
  }

  return media_feature == media_feature_names::kGridMediaFeature;
}

static inline bool FeatureWithAspectRatio(const String& media_feature) {
  return media_feature == media_feature_names::kAspectRatioMediaFeature ||
         media_feature == media_feature_names::kDeviceAspectRatioMediaFeature ||
         media_feature == media_feature_names::kMinAspectRatioMediaFeature ||
         media_feature == media_feature_names::kMaxAspectRatioMediaFeature ||
         media_feature == kMinDeviceAspectRatioMediaFeature ||
         media_feature == kMaxDeviceAspectRatioMediaFeature;
}

bool MediaQueryExp::IsViewportDependent() const {
  return media_feature_ == media_feature_names::kWidthMediaFeature ||
         media_feature_ == media_feature_names::kHeightMediaFeature ||
         media_feature_ == media_feature_names::kMinWidthMediaFeature ||
         media_feature_ == media_feature_names::kMinHeightMediaFeature ||
         media_feature_ == media_feature_names::kMaxWidthMediaFeature ||
         media_feature_ == media_feature_names::kMaxHeightMediaFeature ||
         media_feature_ == media_feature_names::kOrientationMediaFeature ||
         media_feature_ == media_feature_names::kAspectRatioMediaFeature ||
         media_feature_ == media_feature_names::kMinAspectRatioMediaFeature ||
         media_feature_ == media_feature_names::kDevicePixelRatioMediaFeature ||
         media_feature_ == media_feature_names::kResolutionMediaFeature ||
         media_feature_ == media_feature_names::kMaxAspectRatioMediaFeature ||
         media_feature_ == kMaxDevicePixelRatioMediaFeature ||
         media_feature_ ==
             media_feature_names::kMinDevicePixelRatioMediaFeature;
}

bool MediaQueryExp::IsDeviceDependent() const {
  return media_feature_ ==
             media_feature_names::kDeviceAspectRatioMediaFeature ||
         media_feature_ == media_feature_names::kDeviceWidthMediaFeature ||
         media_feature_ == media_feature_names::kDeviceHeightMediaFeature ||
         media_feature_ == kMinDeviceAspectRatioMediaFeature ||
         media_feature_ == media_feature_names::kMinDeviceWidthMediaFeature ||
         media_feature_ == media_feature_names::kMinDeviceHeightMediaFeature ||
         media_feature_ == kMaxDeviceAspectRatioMediaFeature ||
         media_feature_ == media_feature_names::kMaxDeviceWidthMediaFeature ||
         media_feature_ == media_feature_names::kMaxDeviceHeightMediaFeature ||
         media_feature_ == media_feature_names::kDynamicRangeMediaFeature ||
         media_feature_ == media_feature_names::kVideoDynamicRangeMediaFeature;
}

bool MediaQueryExp::IsWidthDependent() const {
  return media_feature_ == media_feature_names::kWidthMediaFeature ||
         media_feature_ == media_feature_names::kMinWidthMediaFeature ||
         media_feature_ == media_feature_names::kMaxWidthMediaFeature ||
         media_feature_ == media_feature_names::kAspectRatioMediaFeature ||
         media_feature_ == media_feature_names::kMinAspectRatioMediaFeature ||
         media_feature_ == media_feature_names::kMaxAspectRatioMediaFeature ||
         media_feature_ == media_feature_names::kOrientationMediaFeature;
}

bool MediaQueryExp::IsHeightDependent() const {
  return media_feature_ == media_feature_names::kHeightMediaFeature ||
         media_feature_ == media_feature_names::kMinHeightMediaFeature ||
         media_feature_ == media_feature_names::kMaxHeightMediaFeature ||
         media_feature_ == media_feature_names::kAspectRatioMediaFeature ||
         media_feature_ == media_feature_names::kMinAspectRatioMediaFeature ||
         media_feature_ == media_feature_names::kMaxAspectRatioMediaFeature ||
         media_feature_ == media_feature_names::kOrientationMediaFeature;
}

bool MediaQueryExp::IsInlineSizeDependent() const {
  return media_feature_ == media_feature_names::kInlineSizeMediaFeature ||
         media_feature_ == media_feature_names::kMinInlineSizeMediaFeature ||
         media_feature_ == media_feature_names::kMaxInlineSizeMediaFeature;
}

bool MediaQueryExp::IsBlockSizeDependent() const {
  return media_feature_ == media_feature_names::kBlockSizeMediaFeature ||
         media_feature_ == media_feature_names::kMinBlockSizeMediaFeature ||
         media_feature_ == media_feature_names::kMaxBlockSizeMediaFeature;
}

MediaQueryExp::MediaQueryExp(const MediaQueryExp& other)
    : media_feature_(other.MediaFeature()), bounds_(other.bounds_) {}

MediaQueryExp::MediaQueryExp(const String& media_feature,
                             const MediaQueryExpValue& value)
    : MediaQueryExp(media_feature,
                    MediaQueryExpBounds(MediaQueryExpComparison(value))) {}

MediaQueryExp::MediaQueryExp(const String& media_feature,
                             const MediaQueryExpBounds& bounds)
    : media_feature_(media_feature), bounds_(bounds) {}

MediaQueryExp MediaQueryExp::Create(const AtomicString& media_feature,
                                    CSSParserTokenStream& stream,
                                    const CSSParserContext& context) {
  if (auto value =
          MediaQueryExpValue::Consume(media_feature, stream, context)) {
    return MediaQueryExp(media_feature, *value);
  }
  return Invalid();
}

std::optional<MediaQueryExpValue> MediaQueryExpValue::Consume(
    const String& media_feature,
    CSSParserTokenStream& stream,
    const CSSParserContext& context) {
  CSSParserContext::ParserModeOverridingScope scope(context, kHTMLStandardMode);

  if (CSSVariableParser::IsValidVariableName(media_feature)) {
    // Parse style queries for container queries, e.g. “style(--foo: bar)”.
    // (These look like a declaration, but are really a test as part of
    // a media query expression.) !important, if present, is stripped
    // and ignored.
    if (const CSSValue* value =
            CSSVariableParser::ParseDeclarationIncludingCSSWide(stream, false,
                                                                context)) {
      while (!stream.AtEnd()) {
        stream.Consume();
      }
      return MediaQueryExpValue(*value);
    }
    return std::nullopt;
  }

  DCHECK_EQ(media_feature, media_feature.LowerASCII())
      << "Under the assumption that custom properties in style() container "
         "queries are currently the only case sensitive features";

  CSSPrimitiveValue* value = css_parsing_utils::ConsumeInteger(
      stream, context, -std::numeric_limits<double>::max() /* minimum_value */);
  if (!value && !FeatureExpectingInteger(media_feature, context)) {
    value = css_parsing_utils::ConsumeNumber(
        stream, context, CSSPrimitiveValue::ValueRange::kAll);
  }
  if (!value) {
    value = css_parsing_utils::ConsumeLength(
        stream, context, CSSPrimitiveValue::ValueRange::kAll);
  }
  if (!value) {
    value = css_parsing_utils::ConsumeResolution(stream, context);
  }

  if (!value) {
    if (CSSIdentifierValue* ident = css_parsing_utils::ConsumeIdent(stream)) {
      CSSValueID ident_id = ident->GetValueID();
      if (!FeatureWithValidIdent(media_feature, ident_id, context)) {
        return std::nullopt;
      }
      return MediaQueryExpValue(ident_id);
    }
    return std::nullopt;
  }

  // Now we have |value| as a number, length or resolution
  // Create value for media query expression that must have 1 or more values.
  if (FeatureWithAspectRatio(media_feature)) {
    if (value->IsNegative() == CSSPrimitiveValue::BoolStatus::kTrue) {
      return std::nullopt;
    }
    if (!css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
      return MediaQueryExpValue(*value,
                                *CSSNumericLiteralValue::Create(
                                    1, CSSPrimitiveValue::UnitType::kNumber));
    }
    CSSPrimitiveValue* denominator = css_parsing_utils::ConsumeNumber(
        stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
    if (!denominator) {
      return std::nullopt;
    }
    if (value->IsZero() == CSSPrimitiveValue::BoolStatus::kTrue &&
        denominator->IsZero() == CSSPrimitiveValue::BoolStatus::kTrue) {
      return MediaQueryExpValue(*CSSNumericLiteralValue::Create(
                                    1, CSSPrimitiveValue::UnitType::kNumber),
                                *CSSNumericLiteralValue::Create(
                                    0, CSSPrimitiveValue::UnitType::kNumber));
    }
    return MediaQueryExpValue(*value, *denominator);
  }

  if (FeatureWithInteger(media_feature, value, context) ||
      FeatureWithNumber(media_feature, value) ||
      FeatureWithZeroOrOne(media_feature, value) ||
      FeatureWithValidLength(media_feature, value) ||
      FeatureWithValidDensity(media_feature, value)) {
    return MediaQueryExpValue(*value);
  }

  return std::nullopt;
}

namespace {

const char* MediaQueryOperatorToString(MediaQueryOperator op) {
  switch (op) {
    case MediaQueryOperator::kNone:
      return "";
    case MediaQueryOperator::kEq:
      return "=";
    case MediaQueryOperator::kLt:
      return "<";
    case MediaQueryOperator::kLe:
      return "<=";
    case MediaQueryOperator::kGt:
      return ">";
    case MediaQueryOperator::kGe:
      return ">=";
  }

  NOTREACHED();
}

}  // namespace

MediaQueryExp MediaQueryExp::Create(const AtomicString& media_feature,
                                    const MediaQueryExpBounds& bounds) {
  return MediaQueryExp(media_feature, bounds);
}

MediaQueryExp::~MediaQueryExp() = default;

void MediaQueryExp::Trace(Visitor* visitor) const {
  visitor->Trace(bounds_);
}

bool MediaQueryExp::operator==(const MediaQueryExp& other) const {
  return (other.media_feature_ == media_feature_) && (bounds_ == other.bounds_);
}

String MediaQueryExp::Serialize() const {
  StringBuilder result;
  // <mf-boolean> e.g. (color)
  // <mf-plain>  e.g. (width: 100px)
  if (!bounds_.IsRange()) {
    result.Append(media_feature_);
    if (bounds_.right.IsValid()) {
      result.Append(": ");
      result.Append(bounds_.right.value.CssText());
    }
  } else {
    if (bounds_.left.IsValid()) {
      result.Append(bounds_.left.value.CssText());
      result.Append(" ");
      result.Append(MediaQueryOperatorToString(bounds_.left.op));
      result.Append(" ");
    }
    result.Append(media_feature_);
    if (bounds_.right.IsValid()) {
      result.Append(" ");
      result.Append(MediaQueryOperatorToString(bounds_.right.op));
      result.Append(" ");
      result.Append(bounds_.right.value.CssText());
    }
  }

  return result.ReleaseString();
}

unsigned MediaQueryExp::GetUnitFlags() const {
  unsigned unit_flags = 0;
  if (Bounds().left.IsValid()) {
    unit_flags |= Bounds().left.value.GetUnitFlags();
  }
  if (Bounds().right.IsValid()) {
    unit_flags |= Bounds().right.value.GetUnitFlags();
  }
  return unit_flags;
}

String MediaQueryExpValue::CssText() const {
  StringBuilder output;
  switch (type_) {
    case Type::kInvalid:
      break;
    case Type::kValue:
      output.Append(GetCSSValue().CssText());
      break;
    case Type::kRatio:
      output.Append(Numerator().CssText());
      output.Append(" / ");
      output.Append(Denominator().CssText());
      break;
    case Type::kId:
      output.Append(GetCSSValueNameAs<StringView>(Id()));
      break;
  }

  return output.ReleaseString();
}

unsigned MediaQueryExpValue::GetUnitFlags() const {
  CSSPrimitiveValue::LengthTypeFlags length_type_flags;

  if (IsValue()) {
    if (auto* primitive = DynamicTo<CSSPrimitiveValue>(GetCSSValue())) {
      primitive->AccumulateLengthUnitTypes(length_type_flags);
    }
  }

  unsigned unit_flags = 0;

  if (length_type_flags.test(CSSPrimitiveValue::kUnitTypeFontSize) ||
      length_type_flags.test(CSSPrimitiveValue::kUnitTypeFontXSize) ||
      length_type_flags.test(CSSPrimitiveValue::kUnitTypeZeroCharacterWidth) ||
      length_type_flags.test(CSSPrimitiveValue::kUnitTypeFontCapitalHeight) ||
      length_type_flags.test(
          CSSPrimitiveValue::kUnitTypeIdeographicFullWidth) ||
      length_type_flags.test(CSSPrimitiveValue::kUnitTypeLineHeight)) {
    unit_flags |= UnitFlags::kFontRelative;
  }

  if (length_type_flags.test(CSSPrimitiveValue::kUnitTypeRootFontSize) ||
      length_type_flags.test(CSSPrimitiveValue::kUnitTypeRootFontXSize) ||
      length_type_flags.test(
          CSSPrimitiveValue::kUnitTypeRootFontCapitalHeight) ||
      length_type_flags.test(
          CSSPrimitiveValue::kUnitTypeRootFontZeroCharacterWidth) ||
      length_type_flags.test(
          CSSPrimitiveValue::kUnitTypeRootFontIdeographicFullWidth) ||
      length_type_flags.test(CSSPrimitiveValue::kUnitTypeRootLineHeight)) {
    unit_flags |= UnitFlags::kRootFontRelative;
  }

  if (CSSPrimitiveValue::HasDynamicViewportUnits(length_type_flags)) {
    unit_flags |= UnitFlags::kDynamicViewport;
  }

  if (CSSPrimitiveValue::HasStaticViewportUnits(length_type_flags)) {
    unit_flags |= UnitFlags::kStaticViewport;
  }

  if (length_type_flags.test(CSSPrimitiveValue::kUnitTypeContainerWidth) ||
      length_type_flags.test(CSSPrimitiveValue::kUnitTypeContainerHeight) ||
      length_type_flags.test(CSSPrimitiveValue::kUnitTypeContainerInlineSize) ||
      length_type_flags.test(CSSPrimitiveValue::kUnitTypeContainerBlockSize) ||
      length_type_flags.test(CSSPrimitiveValue::kUnitTypeContainerMin) ||
      length_type_flags.test(CSSPrimitiveValue::kUnitTypeContainerMax)) {
    unit_flags |= UnitFlags::kContainer;
  }

  return unit_flags;
}

String MediaQueryExpNode::Serialize() const {
  StringBuilder builder;
  SerializeTo(builder);
  return builder.ReleaseString();
}

const MediaQueryExpNode* MediaQueryExpNode::Not(
    const MediaQueryExpNode* operand) {
  if (!operand) {
    return nullptr;
  }
  return MakeGarbageCollected<MediaQueryNotExpNode>(operand);
}

const MediaQueryExpNode* MediaQueryExpNode::Nested(
    const MediaQueryExpNode* operand) {
  if (!operand) {
    return nullptr;
  }
  return MakeGarbageCollected<MediaQueryNestedExpNode>(operand);
}

const MediaQueryExpNode* MediaQueryExpNode::Function(
    const MediaQueryExpNode* operand,
    const AtomicString& name) {
  if (!operand) {
    return nullptr;
  }
  return MakeGarbageCollected<MediaQueryFunctionExpNode>(operand, name);
}

const MediaQueryExpNode* MediaQueryExpNode::And(
    const MediaQueryExpNode* left,
    const MediaQueryExpNode* right) {
  if (!left || !right) {
    return nullptr;
  }
  return MakeGarbageCollected<MediaQueryAndExpNode>(left, right);
}

const MediaQueryExpNode* MediaQueryExpNode::Or(const MediaQueryExpNode* left,
                                               const MediaQueryExpNode* right) {
  if (!left || !right) {
    return nullptr;
  }
  return MakeGarbageCollected<MediaQueryOrExpNode>(left, right);
}

bool MediaQueryFeatureExpNode::IsViewportDependent() const {
  return exp_.IsViewportDependent();
}

bool MediaQueryFeatureExpNode::IsDeviceDependent() const {
  return exp_.IsDeviceDependent();
}

unsigned MediaQueryFeatureExpNode::GetUnitFlags() const {
  return exp_.GetUnitFlags();
}

bool MediaQueryFeatureExpNode::IsWidthDependent() const {
  return exp_.IsWidthDependent();
}

bool MediaQueryFeatureExpNode::IsHeightDependent() const {
  return exp_.IsHeightDependent();
}

bool MediaQueryFeatureExpNode::IsInlineSizeDependent() const {
  return exp_.IsInlineSizeDependent();
}

bool MediaQueryFeatureExpNode::IsBlockSizeDependent() const {
  return exp_.IsBlockSizeDependent();
}

void MediaQueryFeatureExpNode::SerializeTo(StringBuilder& builder) const {
  builder.Append(exp_.Serialize());
}

void MediaQueryFeatureExpNode::CollectExpressions(
    HeapVector<MediaQueryExp>& result) const {
  result.push_back(exp_);
}

MediaQueryExpNode::FeatureFlags MediaQueryFeatureExpNode::CollectFeatureFlags()
    const {
  if (exp_.MediaFeature() == media_feature_names::kStuckMediaFeature) {
    return kFeatureSticky;
  } else if (exp_.MediaFeature() == media_feature_names::kSnappedMediaFeature) {
    return kFeatureSnap;
  } else if (exp_.MediaFeature() ==
             media_feature_names::kOverflowingMediaFeature) {
    return kFeatureOverflow;
  } else if (exp_.IsInlineSizeDependent()) {
    return kFeatureInlineSize;
  } else if (exp_.IsBlockSizeDependent()) {
    return kFeatureBlockSize;
  } else {
    FeatureFlags flags = 0;
    if (exp_.IsWidthDependent()) {
      flags |= kFeatureWidth;
    }
    if (exp_.IsHeightDependent()) {
      flags |= kFeatureHeight;
    }
    return flags;
  }
}

void MediaQueryFeatureExpNode::Trace(Visitor* visitor) const {
  visitor->Trace(exp_);
  MediaQueryExpNode::Trace(visitor);
}

void MediaQueryUnaryExpNode::Trace(Visitor* visitor) const {
  visitor->Trace(operand_);
  MediaQueryExpNode::Trace(visitor);
}

void MediaQueryUnaryExpNode::CollectExpressions(
    HeapVector<MediaQueryExp>& result) const {
  operand_->CollectExpressions(result);
}

MediaQueryExpNode::FeatureFlags MediaQueryUnaryExpNode::CollectFeatureFlags()
    const {
  return operand_->CollectFeatureFlags();
}

void MediaQueryNestedExpNode::SerializeTo(StringBuilder& builder) const {
  builder.Append("(");
  Operand().SerializeTo(builder);
  builder.Append(")");
}

void MediaQueryFunctionExpNode::SerializeTo(StringBuilder& builder) const {
  builder.Append(name_);
  builder.Append("(");
  Operand().SerializeTo(builder);
  builder.Append(")");
}

MediaQueryExpNode::FeatureFlags MediaQueryFunctionExpNode::CollectFeatureFlags()
    const {
  FeatureFlags flags = MediaQueryUnaryExpNode::CollectFeatureFlags();
  if (name_ == AtomicString("style")) {
    flags |= kFeatureStyle;
  }
  return flags;
}

void MediaQueryNotExpNode::SerializeTo(StringBuilder& builder) const {
  builder.Append("not ");
  Operand().SerializeTo(builder);
}

void MediaQueryCompoundExpNode::Trace(Visitor* visitor) const {
  visitor->Trace(left_);
  visitor->Trace(right_);
  MediaQueryExpNode::Trace(visitor);
}

void MediaQueryCompoundExpNode::CollectExpressions(
    HeapVector<MediaQueryExp>& result) const {
  left_->CollectExpressions(result);
  right_->CollectExpressions(result);
}

MediaQueryExpNode::FeatureFlags MediaQueryCompoundExpNode::CollectFeatureFlags()
    const {
  return left_->CollectFeatureFlags() | right_->CollectFeatureFlags();
}

void MediaQueryAndExpNode::SerializeTo(StringBuilder& builder) const {
  Left().SerializeTo(builder);
  builder.Append(" and ");
  Right().SerializeTo(builder);
}

void MediaQueryOrExpNode::SerializeTo(StringBuilder& builder) const {
  Left().SerializeTo(builder);
  builder.Append(" or ");
  Right().SerializeTo(builder);
}

void MediaQueryUnknownExpNode::SerializeTo(StringBuilder& builder) const {
  builder.Append(string_);
}

v
"""


```
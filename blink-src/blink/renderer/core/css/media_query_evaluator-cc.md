Response:
The user wants to understand the functionality of the `media_query_evaluator.cc` file in the Chromium Blink engine. I need to:

1. **Identify the core purpose:** Based on the file name and included headers, it's clear this file is responsible for evaluating CSS media queries.
2. **Explain the relationship with web technologies:** Detail how media queries impact CSS, HTML, and JavaScript.
3. **Provide examples:** Illustrate the connection with concrete examples for each technology.
4. **Address logical reasoning:** Show how inputs (media query conditions) lead to outputs (true/false evaluation).
5. **Highlight potential user/programmer errors:** Explain common mistakes when working with media queries.
6. **Describe the user journey:** Outline how a user interaction can trigger the code in this file.
7. **Summarize the overall function:** Concisely state the primary role of the file.

**Breakdown of the file content:**

* **Copyright and License:** Standard legal information.
* **Includes:** A comprehensive list of headers, hinting at the functionalities it relies on. Key includes are related to CSS (media queries, values, properties), frame information, and platform functionalities.
* **Namespaces:** The code is within the `blink` namespace.
* **Helper functions:** `MaybeRecordMediaFeatureValue`, `KleeneOr`, `KleeneAnd` seem to handle internal logic, possibly related to tracking or boolean operations.
* **`MediaQueryEvaluator` class:** This is the main class, responsible for the evaluation logic.
* **Evaluation methods:** `Eval` functions handle different parts of a media query (whole query, expressions, individual features).
* **Comparison functions:** `CompareValue`, `CompareDoubleValue`, `CompareAspectRatioValue` are used for evaluating conditions against values.
* **Media feature evaluation functions:**  A set of functions like `ColorMediaFeatureEval`, `OrientationMediaFeatureEval`, etc., handle the evaluation of specific media features.
* **Function map:**  `g_function_map` likely stores the mapping between media feature names and their evaluation functions.

**Plan:**

1. State the primary function: Evaluating CSS media queries.
2. Explain the relationship with CSS: How it determines which styles apply based on device characteristics. Give a CSS example.
3. Explain the relationship with HTML: How media queries can be linked in HTML. Give an HTML example.
4. Explain the relationship with JavaScript: How JavaScript can interact with media queries. Give a JS example.
5. Provide a logical reasoning example: Input a simple media query and show the expected output.
6. List common errors: Incorrect syntax, misunderstanding operators, etc.
7. Describe the user journey: User interaction -> style calculation -> media query evaluation.
8. Summarize the core function.
这是 `blink/renderer/core/css/media_query_evaluator.cc` 文件的第一部分，主要负责 **评估 CSS 媒体查询表达式的真假**。

更具体地说，它的功能可以归纳为：

1. **媒体类型匹配:** 确定当前环境的媒体类型（如 "screen", "print"）是否与媒体查询中指定的媒体类型匹配。
2. **表达式求值:**  解析并评估媒体查询表达式的逻辑，例如 `(min-width: 800px)` 或 `(orientation: landscape)`。这涉及到：
    * **操作符处理:** 处理 `and`, `or`, `not` 等逻辑操作符。
    * **媒体特性评估:**  针对各种媒体特性（如 `width`, `height`, `color`, `orientation` 等）获取当前环境的值，并将其与媒体查询中指定的值进行比较。
    * **比较运算:** 支持大于、小于、等于等比较运算符。
3. **布尔结果返回:**  最终返回一个布尔值（或 Kleene 值，包含 `true`, `false`, `unknown` 三种状态）表示媒体查询表达式是否为真。
4. **性能优化:**  在评估过程中可能存在短路优化，例如在 `and` 运算中，如果左侧表达式为假，则不再评估右侧表达式。
5. **隐私记录:**  可能记录某些媒体特性的评估结果用于隐私分析（通过 `IdentifiabilityMetricBuilder`）。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:**  这是该文件最直接关联的部分。媒体查询在 CSS 中用于根据不同的设备或环境应用不同的样式规则。
    * **举例:**
    ```css
    /* 当屏幕宽度大于 800px 时应用以下样式 */
    @media (min-width: 800px) {
      body {
        font-size: 16px;
      }
    }

    /* 当屏幕方向为横向时应用以下样式 */
    @media (orientation: landscape) {
      .sidebar {
        float: left;
      }
    }
    ```
    `media_query_evaluator.cc` 的核心职责就是判断浏览器当前的状态是否满足 `(min-width: 800px)` 或 `(orientation: landscape)` 这些条件，从而决定是否应用对应的 CSS 规则。

* **HTML:** 媒体查询可以通过 `<link>` 标签的 `media` 属性或 `<style>` 标签定义在 HTML 中。
    * **举例:**
    ```html
    <link rel="stylesheet" href="style.css" media="screen and (min-width: 768px)">
    <style media="print">
      /* 打印时的样式 */
      body {
        font-size: 12pt;
      }
    </style>
    ```
    当浏览器解析到这些 HTML 元素时，`media_query_evaluator.cc` 会评估 `media` 属性中的媒体查询，以确定是否加载或应用对应的样式表。

* **JavaScript:** JavaScript 可以通过 `window.matchMedia()` 方法来检查媒体查询的匹配状态，并监听媒体查询状态的变化。
    * **举例:**
    ```javascript
    if (window.matchMedia('(max-width: 767px)').matches) {
      console.log('当前屏幕宽度小于 768px');
      // 执行移动端特定的 JavaScript 代码
    }

    const mediaQueryList = window.matchMedia('(orientation: portrait)');
    mediaQueryList.addEventListener('change', (event) => {
      if (event.matches) {
        console.log('屏幕方向变为竖向');
      } else {
        console.log('屏幕方向变为横向');
      }
    });
    ```
    `window.matchMedia()` 内部会调用 Blink 引擎的相关接口，最终也会使用到 `media_query_evaluator.cc` 来判断媒体查询是否匹配。

**逻辑推理（假设输入与输出）:**

**假设输入:**

1. **CSS 规则:** `@media (min-width: 600px) and (orientation: portrait) { ... }`
2. **当前环境:**
    * 屏幕宽度: 700px
    * 屏幕方向: 竖向 (portrait)

**输出:** `true`

**推理过程:**

* `MediaTypeMatch()` 会判断当前媒体类型（假设是 "screen"）是否与规则中的媒体类型匹配（未指定，默认为 "all"，因此匹配）。
* `Eval()` 会解析表达式 `(min-width: 600px) and (orientation: portrait)`。
* `EvalAnd()` 会先评估左侧 `(min-width: 600px)`。
    * `WidthMediaFeatureEval()` 获取当前屏幕宽度 700px。
    * `CompareLengthAndCompare()` 比较 700px 是否大于等于 600px，结果为 `true`。
* 然后评估右侧 `(orientation: portrait)`。
    * `OrientationMediaFeatureEval()` 获取当前屏幕方向为 "portrait"。
    * 比较 "portrait" 是否等于 "portrait"，结果为 `true`。
* 由于 `and` 操作符两边都为 `true`，最终 `EvalAnd()` 返回 `true`。

**假设输入:**

1. **CSS 规则:** `@media (max-width: 500px) { ... }`
2. **当前环境:**
    * 屏幕宽度: 650px

**输出:** `false`

**推理过程:**

* `MediaTypeMatch()` 判断媒体类型匹配。
* `Eval()` 解析表达式 `(max-width: 500px)`。
* `WidthMediaFeatureEval()` 获取当前屏幕宽度 650px。
* `CompareLengthAndCompare()` 比较 650px 是否小于等于 500px，结果为 `false`。
* `Eval()` 返回 `false`。

**用户或编程常见的使用错误举例:**

1. **媒体查询语法错误:**  拼写错误、缺少括号、使用错误的单位等。
    * **举例:** `@media (min width: 100px)`  (缺少连字符)
    * **结果:** 媒体查询可能无法被正确解析和评估，导致样式不生效。

2. **逻辑运算符使用不当:**  错误地组合 `and` 和 `or`，导致意料之外的结果。
    * **举例:** `@media (min-width: 800px), (orientation: landscape)` (本意可能是同时满足两个条件，但这里是或的关系)
    * **结果:**  只要满足其中一个条件，样式就会生效，可能与预期不符。

3. **对媒体特性理解偏差:**  对某些媒体特性的行为或取值范围理解错误。
    * **举例:** 假设认为 `(orientation: portrait)` 只在手机竖屏时生效，但实际上平板竖屏也会匹配。
    * **结果:**  样式可能在不期望的设备或状态下生效。

4. **忽略了媒体类型:**  在需要特定媒体类型的样式规则中，忘记指定媒体类型。
    * **举例:**  只想在打印时生效的样式写成了 `@media (color) { ... }` (没有指定 `print` 媒体类型)
    * **结果:**  样式可能会在其他支持彩色的设备上生效。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个网页:**  浏览器开始解析 HTML、CSS。
2. **浏览器解析到包含媒体查询的 CSS 规则:** 例如在 `<style>` 标签或外部 CSS 文件中。
3. **样式计算过程启动:**  浏览器需要确定哪些 CSS 规则应该应用到页面的元素上。
4. **遇到媒体查询:**  `media_query_evaluator.cc` 中的代码被调用，以评估该媒体查询在当前环境下的真假。
5. **获取当前环境信息:**  `MediaQueryEvaluator` 会从 `MediaValues` 对象中获取当前设备的屏幕宽度、高度、方向、颜色能力等信息。这些信息可能来自操作系统、浏览器窗口大小等。
6. **执行评估逻辑:**  根据媒体查询的表达式和当前环境信息，进行逻辑判断和比较运算。
7. **返回评估结果:**  `true` 或 `false`，指示媒体查询是否匹配。
8. **样式应用:**  如果媒体查询评估结果为 `true`，则对应的 CSS 规则会被应用到页面元素上，影响页面的最终渲染效果。

**调试线索:**

如果样式没有按照预期生效，可以考虑以下调试线索：

* **检查 CSS 语法:**  使用浏览器的开发者工具查看是否有 CSS 语法错误。
* **检查媒体查询表达式:**  确认媒体查询的逻辑是否符合预期。
* **查看当前媒体特性值:**  在开发者工具中，有些浏览器可以显示当前设备的媒体特性值，可以与媒体查询中的值进行对比。
* **使用 `window.matchMedia()` 进行 JavaScript 测试:**  可以在控制台中运行 `window.matchMedia('your-media-query').matches` 来快速测试媒体查询的匹配状态。
* **断点调试:**  如果需要深入了解评估过程，可以在 `media_query_evaluator.cc` 中设置断点，查看代码的执行流程和变量的值。

**总结一下它的功能:**

`blink/renderer/core/css/media_query_evaluator.cc` 的主要功能是 **判断 CSS 媒体查询在当前浏览器环境下的匹配状态**，从而决定是否应用相应的 CSS 样式规则。它是浏览器渲染引擎中处理响应式设计的核心组件之一。

Prompt: 
```
这是目录为blink/renderer/core/css/media_query_evaluator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * CSS Media Query Evaluator
 *
 * Copyright (C) 2006 Kimmo Kinnunen <kimmo.t.kinnunen@nokia.com>.
 * Copyright (C) 2013 Apple Inc. All rights reserved.
 * Copyright (C) 2013 Intel Corporation. All rights reserved.
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

#include "third_party/blink/renderer/core/css/media_query_evaluator.h"

#include "third_party/blink/public/common/css/forced_colors.h"
#include "third_party/blink/public/common/css/navigation_controls.h"
#include "third_party/blink/public/common/css/scripting.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_surface.h"
#include "third_party/blink/public/mojom/device_posture/device_posture_provider.mojom-blink.h"
#include "third_party/blink/public/mojom/manifest/display_mode.mojom-shared.h"
#include "third_party/blink/public/mojom/webpreferences/web_preferences.mojom-blink.h"
#include "third_party/blink/renderer/core/css/css_container_values.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_resolution_units.h"
#include "third_party/blink/renderer/core/css/css_to_length_conversion_data.h"
#include "third_party/blink/renderer/core/css/css_unparsed_declaration_value.h"
#include "third_party/blink/renderer/core/css/media_feature_names.h"
#include "third_party/blink/renderer/core/css/media_features.h"
#include "third_party/blink/renderer/core/css/media_list.h"
#include "third_party/blink/renderer/core/css/media_query.h"
#include "third_party/blink/renderer/core/css/media_values.h"
#include "third_party/blink/renderer/core/css/media_values_dynamic.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/parser/css_variable_parser.h"
#include "third_party/blink/renderer/core/css/properties/longhands/custom_property.h"
#include "third_party/blink/renderer/core/css/resolver/media_query_result.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/media_type_names.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/graphics/color_space_gamut.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "ui/base/mojom/window_show_state.mojom-blink.h"
#include "ui/gfx/geometry/rect_f.h"

namespace blink {

namespace {

template <class T>
void MaybeRecordMediaFeatureValue(
    const MediaValues& media_values,
    const IdentifiableSurface::MediaFeatureName feature_name,
    T value) {
  Document* document = nullptr;
  if ((document = media_values.GetDocument()) &&
      (IdentifiabilityStudySettings::Get()->ShouldSampleType(
          IdentifiableSurface::Type::kMediaFeature)) &&
      !document->WasMediaFeatureEvaluated(static_cast<int>(feature_name))) {
    IdentifiableSurface surface = IdentifiableSurface::FromTypeAndToken(
        IdentifiableSurface::Type::kMediaFeature,
        IdentifiableToken(feature_name));

    IdentifiabilityMetricBuilder(document->UkmSourceID())
        .Add(surface, IdentifiableToken(value))
        .Record(document->UkmRecorder());
    document->SetMediaFeatureEvaluated(static_cast<int>(feature_name));
  }
}

KleeneValue KleeneOr(KleeneValue a, KleeneValue b) {
  switch (a) {
    case KleeneValue::kTrue:
      return KleeneValue::kTrue;
    case KleeneValue::kFalse:
      return b;
    case KleeneValue::kUnknown:
      return (b == KleeneValue::kTrue) ? KleeneValue::kTrue
                                       : KleeneValue::kUnknown;
  }
}

KleeneValue KleeneAnd(KleeneValue a, KleeneValue b) {
  switch (a) {
    case KleeneValue::kTrue:
      return b;
    case KleeneValue::kFalse:
      return KleeneValue::kFalse;
    case KleeneValue::kUnknown:
      return (b == KleeneValue::kFalse) ? KleeneValue::kFalse
                                        : KleeneValue::kUnknown;
  }
}

}  // namespace

using mojom::blink::DevicePostureType;
using mojom::blink::HoverType;
using mojom::blink::PointerType;

using EvalFunc = bool (*)(const MediaQueryExpValue&,
                          MediaQueryOperator,
                          const MediaValues&);
using FunctionMap = HashMap<StringImpl*, EvalFunc>;
static FunctionMap* g_function_map;

MediaQueryEvaluator::MediaQueryEvaluator(const char* accepted_media_type)
    : media_type_(accepted_media_type) {}

MediaQueryEvaluator::MediaQueryEvaluator(LocalFrame* frame)
    : media_values_(MediaValues::CreateDynamicIfFrameExists(frame)) {}

MediaQueryEvaluator::MediaQueryEvaluator(const MediaValues* container_values)
    : media_values_(container_values) {}

MediaQueryEvaluator::~MediaQueryEvaluator() = default;

void MediaQueryEvaluator::Trace(Visitor* visitor) const {
  visitor->Trace(media_values_);
}

const String MediaQueryEvaluator::MediaType() const {
  // If a static mediaType was given by the constructor, we use it here.
  if (!media_type_.empty()) {
    return media_type_;
  }
  // Otherwise, we get one from mediaValues (which may be dynamic or cached).
  if (media_values_) {
    return media_values_->MediaType();
  }
  return g_null_atom;
}

bool MediaQueryEvaluator::MediaTypeMatch(
    const String& media_type_to_match) const {
  return media_type_to_match.empty() ||
         EqualIgnoringASCIICase(media_type_to_match, media_type_names::kAll) ||
         EqualIgnoringASCIICase(media_type_to_match, MediaType());
}

static bool ApplyRestrictor(MediaQuery::RestrictorType r, KleeneValue value) {
  if (value == KleeneValue::kUnknown) {
    return false;
  }
  if (r == MediaQuery::RestrictorType::kNot) {
    return value == KleeneValue::kFalse;
  }
  return value == KleeneValue::kTrue;
}

bool MediaQueryEvaluator::Eval(const MediaQuery& query) const {
  return Eval(query, nullptr /* result_flags */);
}

bool MediaQueryEvaluator::Eval(const MediaQuery& query,
                               MediaQueryResultFlags* result_flags) const {
  if (!MediaTypeMatch(query.MediaType())) {
    return ApplyRestrictor(query.Restrictor(), KleeneValue::kFalse);
  }
  if (!query.ExpNode()) {
    return ApplyRestrictor(query.Restrictor(), KleeneValue::kTrue);
  }
  return ApplyRestrictor(query.Restrictor(),
                         Eval(*query.ExpNode(), result_flags));
}

bool MediaQueryEvaluator::Eval(const MediaQuerySet& query_set) const {
  return Eval(query_set, nullptr /* result_flags */);
}

bool MediaQueryEvaluator::Eval(const MediaQuerySet& query_set,
                               MediaQueryResultFlags* result_flags) const {
  const HeapVector<Member<const MediaQuery>>& queries = query_set.QueryVector();
  if (!queries.size()) {
    return true;  // Empty query list evaluates to true.
  }

  // Iterate over queries, stop if any of them eval to true (OR semantics).
  bool result = false;
  for (wtf_size_t i = 0; i < queries.size() && !result; ++i) {
    result = Eval(*queries[i], result_flags);
  }

  return result;
}

KleeneValue MediaQueryEvaluator::Eval(const MediaQueryExpNode& node) const {
  return Eval(node, nullptr /* result_flags */);
}

KleeneValue MediaQueryEvaluator::Eval(
    const MediaQueryExpNode& node,
    MediaQueryResultFlags* result_flags) const {
  if (auto* n = DynamicTo<MediaQueryNestedExpNode>(node)) {
    return Eval(n->Operand(), result_flags);
  }
  if (auto* n = DynamicTo<MediaQueryFunctionExpNode>(node)) {
    return Eval(n->Operand(), result_flags);
  }
  if (auto* n = DynamicTo<MediaQueryNotExpNode>(node)) {
    return EvalNot(n->Operand(), result_flags);
  }
  if (auto* n = DynamicTo<MediaQueryAndExpNode>(node)) {
    return EvalAnd(n->Left(), n->Right(), result_flags);
  }
  if (auto* n = DynamicTo<MediaQueryOrExpNode>(node)) {
    return EvalOr(n->Left(), n->Right(), result_flags);
  }
  if (IsA<MediaQueryUnknownExpNode>(node)) {
    return KleeneValue::kUnknown;
  }
  return EvalFeature(To<MediaQueryFeatureExpNode>(node), result_flags);
}

KleeneValue MediaQueryEvaluator::EvalNot(
    const MediaQueryExpNode& operand_node,
    MediaQueryResultFlags* result_flags) const {
  switch (Eval(operand_node, result_flags)) {
    case KleeneValue::kTrue:
      return KleeneValue::kFalse;
    case KleeneValue::kFalse:
      return KleeneValue::kTrue;
    case KleeneValue::kUnknown:
      return KleeneValue::kUnknown;
  }
}

KleeneValue MediaQueryEvaluator::EvalAnd(
    const MediaQueryExpNode& left_node,
    const MediaQueryExpNode& right_node,
    MediaQueryResultFlags* result_flags) const {
  KleeneValue left = Eval(left_node, result_flags);
  // Short-circuiting before calling Eval on |right_node| prevents
  // unnecessary entries in |results|.
  if (left == KleeneValue::kFalse) {
    return left;
  }
  return KleeneAnd(left, Eval(right_node, result_flags));
}

KleeneValue MediaQueryEvaluator::EvalOr(
    const MediaQueryExpNode& left_node,
    const MediaQueryExpNode& right_node,
    MediaQueryResultFlags* result_flags) const {
  KleeneValue left = Eval(left_node, result_flags);
  // Short-circuiting before calling Eval on |right_node| prevents
  // unnecessary entries in |results|.
  if (left == KleeneValue::kTrue) {
    return left;
  }
  return KleeneOr(left, Eval(right_node, result_flags));
}

bool MediaQueryEvaluator::DidResultsChange(
    const HeapVector<MediaQuerySetResult>& result_flags) const {
  for (const auto& result : result_flags) {
    if (result.Result() != Eval(result.MediaQueries())) {
      return true;
    }
  }
  return false;
}

// As per
// https://w3c.github.io/csswg-drafts/mediaqueries/#false-in-the-negative-range
static bool HandleNegativeMediaFeatureValue(MediaQueryOperator op) {
  switch (op) {
    case MediaQueryOperator::kLe:
    case MediaQueryOperator::kLt:
    case MediaQueryOperator::kEq:
    case MediaQueryOperator::kNone:
      return false;
    case MediaQueryOperator::kGt:
    case MediaQueryOperator::kGe:
      return true;
  }
}

template <typename T>
bool CompareValue(T actual_value, T query_value, MediaQueryOperator op) {
  if (query_value < T(0)) {
    return HandleNegativeMediaFeatureValue(op);
  }
  switch (op) {
    case MediaQueryOperator::kGe:
      return actual_value >= query_value;
    case MediaQueryOperator::kLe:
      return actual_value <= query_value;
    case MediaQueryOperator::kEq:
    case MediaQueryOperator::kNone:
      return actual_value == query_value;
    case MediaQueryOperator::kLt:
      return actual_value < query_value;
    case MediaQueryOperator::kGt:
      return actual_value > query_value;
  }
  return false;
}

bool CompareDoubleValue(double actual_value,
                        double query_value,
                        MediaQueryOperator op) {
  if (query_value < 0) {
    return HandleNegativeMediaFeatureValue(op);
  }
  const double precision = LayoutUnit::Epsilon();
  switch (op) {
    case MediaQueryOperator::kGe:
      return actual_value >= (query_value - precision);
    case MediaQueryOperator::kLe:
      return actual_value <= (query_value + precision);
    case MediaQueryOperator::kEq:
    case MediaQueryOperator::kNone:
      return std::abs(actual_value - query_value) <= precision;
    case MediaQueryOperator::kLt:
      return actual_value < query_value;
    case MediaQueryOperator::kGt:
      return actual_value > query_value;
  }
  return false;
}

static bool CompareAspectRatioValue(const MediaQueryExpValue& value,
                                    int width,
                                    int height,
                                    MediaQueryOperator op,
                                    const MediaValues& media_values) {
  if (value.IsRatio()) {
    return CompareDoubleValue(
        static_cast<double>(width) * value.Denominator(media_values),
        static_cast<double>(height) * value.Numerator(media_values), op);
  }
  return false;
}

static bool NumberValue(const MediaQueryExpValue& value,
                        float& result,
                        const MediaValues& media_values) {
  if (value.IsNumber()) {
    result = ClampTo<float>(value.Value(media_values));
    return true;
  }
  return false;
}

static bool ColorMediaFeatureEval(const MediaQueryExpValue& value,
                                  MediaQueryOperator op,
                                  const MediaValues& media_values) {
  float number;
  int bits_per_component = media_values.ColorBitsPerComponent();
  MaybeRecordMediaFeatureValue(media_values,
                               IdentifiableSurface::MediaFeatureName::kColor,
                               bits_per_component);
  if (value.IsValid()) {
    return NumberValue(value, number, media_values) &&
           CompareValue(bits_per_component, static_cast<int>(number), op);
  }

  return bits_per_component != 0;
}

static bool ColorIndexMediaFeatureEval(const MediaQueryExpValue& value,
                                       MediaQueryOperator op,
                                       const MediaValues& media_values) {
  // FIXME: We currently assume that we do not support indexed displays, as it
  // is unknown how to retrieve the information if the display mode is indexed.
  // This matches Firefox.
  if (!value.IsValid()) {
    return false;
  }

  // Acording to spec, if the device does not use a color lookup table, the
  // value is zero.
  float number;
  return NumberValue(value, number, media_values) &&
         CompareValue(0, static_cast<int>(number), op);
}

static bool MonochromeMediaFeatureEval(const MediaQueryExpValue& value,
                                       MediaQueryOperator op,
                                       const MediaValues& media_values) {
  float number;
  int bits_per_component = media_values.MonochromeBitsPerComponent();
  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kMonochrome,
      bits_per_component);
  if (value.IsValid()) {
    return NumberValue(value, number, media_values) &&
           CompareValue(bits_per_component, static_cast<int>(number), op);
  }
  return bits_per_component != 0;
}

static bool DisplayModeMediaFeatureEval(const MediaQueryExpValue& value,
                                        MediaQueryOperator,
                                        const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kDisplayModeMediaQuery);

  // isValid() is false if there is no parameter. Without parameter we should
  // return true to indicate that displayModeMediaFeature is enabled in the
  // browser.
  if (!value.IsValid()) {
    return true;
  }

  if (!value.IsId()) {
    return false;
  }

  blink::mojom::DisplayMode mode = media_values.DisplayMode();

  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kDisplayMode, mode);

  switch (value.Id()) {
    case CSSValueID::kFullscreen:
      return mode == blink::mojom::DisplayMode::kFullscreen;
    case CSSValueID::kStandalone:
      return mode == blink::mojom::DisplayMode::kStandalone;
    case CSSValueID::kMinimalUi:
      return mode == blink::mojom::DisplayMode::kMinimalUi;
    case CSSValueID::kBrowser:
      return mode == blink::mojom::DisplayMode::kBrowser;
    case CSSValueID::kWindowControlsOverlay:
      return mode == blink::mojom::DisplayMode::kWindowControlsOverlay;
    case CSSValueID::kBorderless:
      return mode == blink::mojom::DisplayMode::kBorderless;
    case CSSValueID::kTabbed:
      return mode == blink::mojom::DisplayMode::kTabbed;
    case CSSValueID::kPictureInPicture:
      return mode == blink::mojom::DisplayMode::kPictureInPicture;
    default:
      NOTREACHED();
  }
}

// WindowShowState is mapped into a CSS media query value `display-state`.
static bool DisplayStateMediaFeatureEval(const MediaQueryExpValue& value,
                                         MediaQueryOperator,
                                         const MediaValues& media_values) {
  // No value = boolean context:
  // https://w3c.github.io/csswg-drafts/mediaqueries/#mq-boolean-context
  if (!value.IsValid()) {
    return true;
  }

  if (!value.IsId()) {
    return false;
  }

  ui::mojom::blink::WindowShowState state = media_values.WindowShowState();
  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kDisplayState,
      state);

  switch (value.Id()) {
    case CSSValueID::kFullscreen:
      return state == ui::mojom::blink::WindowShowState::kFullscreen;
    case CSSValueID::kMaximized:
      return state == ui::mojom::blink::WindowShowState::kMaximized;
    case CSSValueID::kMinimized:
      return state == ui::mojom::blink::WindowShowState::kMinimized;
    case CSSValueID::kNormal:
      return state == ui::mojom::blink::WindowShowState::kDefault ||
             state == ui::mojom::blink::WindowShowState::kInactive ||
             state == ui::mojom::blink::WindowShowState::kNormal;
    default:
      NOTREACHED();
  }
}

static bool ResizableMediaFeatureEval(const MediaQueryExpValue& value,
                                      MediaQueryOperator,
                                      const MediaValues& media_values) {
  // No value = boolean context:
  // https://w3c.github.io/csswg-drafts/mediaqueries/#mq-boolean-context
  if (!value.IsValid()) {
    return true;
  }

  if (!value.IsId()) {
    return false;
  }

  bool resizable = media_values.Resizable();
  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kResizable,
      resizable);

  return (resizable && value.Id() == CSSValueID::kTrue) ||
         (!resizable && value.Id() == CSSValueID::kFalse);
}

static bool OrientationMediaFeatureEval(const MediaQueryExpValue& value,
                                        MediaQueryOperator,
                                        const MediaValues& media_values) {
  int width = *media_values.Width();
  int height = *media_values.Height();

  if (value.IsId()) {
    if (width > height) {  // Square viewport is portrait.
      MaybeRecordMediaFeatureValue(
          media_values, IdentifiableSurface::MediaFeatureName::kOrientation,
          CSSValueID::kLandscape);
      return CSSValueID::kLandscape == value.Id();
    }

    MaybeRecordMediaFeatureValue(
        media_values, IdentifiableSurface::MediaFeatureName::kOrientation,
        CSSValueID::kPortrait);
    return CSSValueID::kPortrait == value.Id();
  }

  // Expression (orientation) evaluates to true if width and height >= 0.
  return height >= 0 && width >= 0;
}

static bool AspectRatioMediaFeatureEval(const MediaQueryExpValue& value,
                                        MediaQueryOperator op,
                                        const MediaValues& media_values) {
  double aspect_ratio =
      std::max(*media_values.Width(), *media_values.Height()) /
      std::min(*media_values.Width(), *media_values.Height());
  MaybeRecordMediaFeatureValue(
      media_values,
      IdentifiableSurface::MediaFeatureName::kAspectRatioNormalized,
      aspect_ratio);
  if (value.IsValid()) {
    return CompareAspectRatioValue(value, *media_values.Width(),
                                   *media_values.Height(), op, media_values);
  }

  // ({,min-,max-}aspect-ratio)
  // assume if we have a device, its aspect ratio is non-zero.
  return true;
}

static bool DeviceAspectRatioMediaFeatureEval(const MediaQueryExpValue& value,
                                              MediaQueryOperator op,
                                              const MediaValues& media_values) {
  if (value.IsValid()) {
    return CompareAspectRatioValue(value, media_values.DeviceWidth(),
                                   media_values.DeviceHeight(), op,
                                   media_values);
  }

  // ({,min-,max-}device-aspect-ratio)
  // assume if we have a device, its aspect ratio is non-zero.
  return true;
}

static bool DynamicRangeMediaFeatureEval(const MediaQueryExpValue& value,
                                         MediaQueryOperator op,
                                         const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kDynamicRangeMediaQuery);

  if (!value.IsId()) {
    return false;
  }

  switch (value.Id()) {
    case CSSValueID::kStandard:
      MaybeRecordMediaFeatureValue(
          media_values, IdentifiableSurface::MediaFeatureName::kDynamicRange,
          CSSValueID::kStandard);
      return true;

    case CSSValueID::kHigh:
      MaybeRecordMediaFeatureValue(
          media_values, IdentifiableSurface::MediaFeatureName::kDynamicRange,
          media_values.DeviceSupportsHDR());
      return media_values.DeviceSupportsHDR();

    default:
      NOTREACHED();
  }
}

static bool VideoDynamicRangeMediaFeatureEval(const MediaQueryExpValue& value,
                                              MediaQueryOperator op,
                                              const MediaValues& media_values) {
  // For now, Chrome makes no distinction between video-dynamic-range and
  // dynamic-range
  return DynamicRangeMediaFeatureEval(value, op, media_values);
}

static bool EvalResolution(const MediaQueryExpValue& value,
                           MediaQueryOperator op,
                           const MediaValues& media_values) {
  // According to MQ4, only 'screen', 'print' and 'speech' may match.
  // FIXME: What should speech match?
  // https://www.w3.org/Style/CSS/Tracker/issues/348
  float actual_resolution = 0;

  // This checks the actual media type applied to the document, and we know
  // this method only got called if this media type matches the one defined
  // in the query. Thus, if if the document's media type is "print", the
  // media type of the query will either be "print" or "all".
  if (EqualIgnoringASCIICase(media_values.MediaType(),
                             media_type_names::kScreen)) {
    actual_resolution = ClampTo<float>(media_values.DevicePixelRatio());
  } else if (EqualIgnoringASCIICase(media_values.MediaType(),
                                    media_type_names::kPrint)) {
    // The resolution of images while printing should not depend on the DPI
    // of the screen. Until we support proper ways of querying this info
    // we use 300px which is considered minimum for current printers.
    actual_resolution = 300 / kCssPixelsPerInch;
  }

  MaybeRecordMediaFeatureValue(
      media_values, IdentifiableSurface::MediaFeatureName::kResolution,
      actual_resolution);

  if (!value.IsValid()) {
    return !!actual_resolution;
  }

  if (value.IsNumber()) {
    return CompareValue(actual_resolution,
                        ClampTo<float>(value.Value(media_values)), op);
  }

  if (!value.IsResolution()) {
    return false;
  }

  double dppx_factor = CSSPrimitiveValue::ConversionToCanonicalUnitsScaleFactor(
      CSSPrimitiveValue::UnitType::kDotsPerPixel);
  float value_in_dppx = ClampTo<float>(value.Value(media_values) / dppx_factor);
  if (value.IsDotsPerCentimeter()) {
    // To match DPCM to DPPX values, we limit to 2 decimal points.
    // The https://drafts.csswg.org/css-values/#absolute-lengths recommends
    // "that the pixel unit refer to the whole number of device pixels that best
    // approximates the reference pixel". With that in mind, allowing 2 decimal
    // point precision seems appropriate.
    return CompareValue(floorf(0.5 + 100 * actual_resolution) / 100,
                        floorf(0.5 + 100 * value_in_dppx) / 100, op);
  }

  return CompareValue(actual_resolution, value_in_dppx, op);
}

static bool DevicePixelRatioMediaFeatureEval(const MediaQueryExpValue& value,
                                             MediaQueryOperator op,
                                             const MediaValues& media_values) {
  UseCounter::Count(media_values.GetDocument(),
                    WebFeature::kPrefixedDevicePixelRatioMediaFeature);

  return (!value.IsValid() || value.IsNumber()) &&
         EvalResolution(value, op, media_values);
}

static bool ResolutionMediaFeatureEval(const MediaQueryExpValue& value,
                                       MediaQueryOperator op,
                                       const MediaValues& media_values) {
  return (!value.IsValid() || value.IsResolution()) &&
         EvalResolution(value, op, media_values);
}

static bool GridMediaFeatureEval(const MediaQueryExpValue& value,
                                 MediaQueryOperator op,
                                 const MediaValues& media_values) {
  // if output device is bitmap, grid: 0 == true
  // assume we have bitmap device
  float number;
  if (value.IsValid() && NumberValue(value, number, media_values)) {
    return CompareValue(static_cast<int>(number), 0, op);
  }
  return false;
}

static bool ComputeLength(const MediaQueryExpValue& value,
                          const MediaValues& media_values,
                          double& result) {
  if (value.IsNumber()) {
    result = ClampTo<int>(value.Value(media_values));
    return !media_values.StrictMode() || !result;
  }

  if (value.IsValue()) {
    result = value.Value(media_values);
    return true;
  }

  return false;
}

static bool ComputeLengthAndCompare(const MediaQueryExpValue& value,
                                    MediaQueryOperator op,
                                    const MediaValues& media_values,
                                    double compare_to_value) {
  double length;
  return ComputeLength(value, media_values, length) &&
         CompareDoubleValue(compare_to_value, length, op);
}

static bool DeviceHeightMediaFeatureEval(const MediaQueryExpValue& value,
                                         MediaQueryOperator op,
                                         const MediaValues& media_values) {
  if (value.IsValid()) {
    return ComputeLengthAndCompare(value, op, media_values,
                                   media_values.DeviceHeight());
  }

  // ({,min-,max-}device-height)
  // assume if we have a device, assume non-zero
  return true;
}

static bool DeviceWidthMediaFeatureEval(const MediaQueryExpValue& value,
                                        MediaQueryOperator op,
                                        const MediaValues& media_values) {
  if (value.IsValid()) {
    return ComputeLengthAndCompare(value, op, media_values,
                                   media_values.DeviceWidth());
  }

  // ({,min-,max-}device-width)
  // assume if we have a device, assume non-zero
  return true;
}

static bool HeightMediaFeatureEval(const MediaQueryExpValue& value,
                                   MediaQueryOperator op,
                                   const MediaValues& media_values) {
  double height = *media_values.Height();
  if (value.IsValid()) {
    return ComputeLengthAndCompare(value, op, media_values, height);
  }

  return height;
}

static bool WidthMediaFeatureEval(const MediaQueryExpValue& value,
                                  MediaQueryOperator op,
                                  const MediaValues& media_values) {
  double width = *media_values.Width();
  if (value.IsValid()) {
    return ComputeLengthAndCompare(value, op, media_values, width);
  }

  return width;
}

static bool InlineSizeMediaFeatureEval(const MediaQueryExpValue& value,
                                       MediaQueryOperator op,
                                       const MediaValues& media_values) {
  double size = *media_values.InlineSize();
  if (value.IsValid()) {
    return ComputeLengthAndCompare(value, op, media_values, size);
  }

  return size;
}

static bool BlockSizeMediaFeatureEval(const MediaQueryExpValue& value,
                                      MediaQueryOperator op,
                                      const MediaValues& media_values) {
  double size = *media_values.BlockSize();
  if (value.IsValid()) {
    return ComputeLengthAndCompare(value, op, media_values, size);
  }

  return size;
}

// Rest of the functions are trampolines which set the prefix according to the
// media feature expression used.

static bool MinColorMediaFeatureEval(const MediaQueryExpValue& value,
                                     MediaQueryOperator,
                                     const MediaValues& media_values) {
  return ColorMediaFeatureEval(value, MediaQueryOperator::kGe, media_values);
}

static bool MaxColorMediaFeatureEval(const MediaQueryExpValue& value,
                                     MediaQueryOperator,
                                     const MediaValues& media_values) {
  return ColorMediaFeatureEval(value, MediaQueryOperator::kLe, media_values);
}

static bool MinColorIndexMediaFeatureEval(const MediaQueryExpValue& value,
                                          MediaQueryOperator,
                                          const MediaValues& media_values) {
  return ColorIndexMediaFeatureEval(value, MediaQueryOperator::kGe,
                                    media_values);
}

static bool MaxColorIndexMediaFeatureEval(const MediaQueryExpValue& value,
                                          MediaQueryOperator,
                                          const MediaValues& media_values) {
  return ColorIndexMediaFeatureEval(value, MediaQueryOperator::kLe,
                                    media_values);
}

static bool MinMonochromeMediaFeatureEval(const MediaQueryExpValue& value,
                                          MediaQueryOperator,
                                          const MediaValues& media_values) {
  return MonochromeMediaFeatureEval(value, MediaQueryOperator::kGe,
                                    media_values);
}

static bool MaxMonochromeMediaFeatureEval(const MediaQueryExpValue& value,
                                          MediaQueryOperator,
                                          const MediaValues& media_values) {
  return MonochromeMediaFeatureEval(value, MediaQueryOperator::kLe,
                                    media_values);
}

static bool MinAspectRatioMediaFeatureEval(const MediaQueryExpValue& value,
                                           MediaQueryOperator,
                                           const MediaValues& media_values) {
  return AspectRatioMediaFeatureEval(value, MediaQueryOperator::kGe,
                                     media_values);
}

static bool MaxAspectRatioMediaFeatureEval(const MediaQueryExpValue& value,
                                           MediaQueryOperator,
                                           const MediaValues& media_values) {
  return AspectRatioMediaFeatureEval(value, MediaQueryOperator::kLe,
                                     media_values);
}

static bool MinDeviceAspectRatioMediaFeatureEval(
    const MediaQueryExpValue& value,
    MediaQueryOperator,
    const MediaValues& media_values) {
  return DeviceAspectRatioMediaFeatureEval(value, MediaQueryOperator::kGe,
                                           media_values);
}

static bool MaxDeviceAsp
"""


```
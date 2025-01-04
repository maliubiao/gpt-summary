Response:
The user wants a summary of the functionality of the `HTMLPermissionElement.cc` file in the Chromium Blink engine.

I need to analyze the provided code snippet to understand its purpose and how it interacts with other web technologies like JavaScript, HTML, and CSS.

Here's a breakdown of the thought process:

1. **Identify the core class:** The file is named `html_permission_element.cc`, indicating the primary class is `HTMLPermissionElement`.

2. **Analyze includes:** The included headers provide hints about the class's dependencies and functionalities. Keywords like "permission," "html," "css," "javascript" (via bindings), "dom," and "intersection observer" are significant.

3. **Examine the constructor:** The constructor shows that the `HTMLPermissionElement` is associated with a document, uses an `IntersectionObserver`, and has a user-agent shadow root. The `UseCounter::Count` suggests it's a new feature being tracked.

4. **Inspect methods related to permissions:**  Methods like `initialPermissionStatus`, `permissionStatus`, `OnPermissionStatusInitialized`, `MaybeRegisterPageEmbeddedPermissionControl`, and interactions with `PermissionService` suggest the class is responsible for managing and displaying the status of browser permissions.

5. **Look for DOM interactions:** Methods like `InsertedInto`, `RemovedFrom`, `AttachLayoutTree`, `DetachLayoutTree`, and `AttributeChanged` indicate the class interacts with the DOM lifecycle and responds to attribute changes.

6. **Investigate styling aspects:** The `AdjustStyle` method is crucial. It reveals how the element's style is being manipulated to enforce accessibility and usability guidelines. It mentions things like font weight, letter spacing, margins, and checks for sufficient contrast.

7. **Examine the `IntersectionObserver`:**  The presence of an `IntersectionObserver` and the `OnIntersectionChanged` method suggests the element's behavior is influenced by its visibility and intersection with the viewport. This ties into the "disable clicking" logic.

8. **Identify potential user/programming errors:**  The code includes checks for invalid `type` attributes, permissions being used in incorrect contexts (like fenced frames without proper CSP), and style violations.

9. **Infer JavaScript interaction:** The inclusion of `v8_permission_state.h` suggests the permission status is exposed to JavaScript.

10. **Infer HTML interaction:** The class inherits from `HTMLElement`, meaning it's a custom HTML element. The `kPermissionTag` in the constructor confirms this. The `type` attribute is a key HTML attribute being parsed.

11. **Infer CSS interaction:** The `AdjustStyle` method directly manipulates CSS properties. The contrast checks and forced style adjustments are important CSS-related functionalities.

12. **Synthesize a summary:** Combine the observations from the above steps to create a concise description of the class's functionality.

13. **Address specific instructions:**  Specifically address the relationships with JavaScript, HTML, and CSS, provide examples, mention logical reasoning (like disabling clicking based on intersection), and point out potential user errors.

14. **Organize the information:** Structure the answer logically with clear headings and bullet points for readability.
好的，根据你提供的 blink 引擎源代码文件 `html_permission_element.cc` 的内容，这是第一部分，我来归纳一下它的功能：

**核心功能：实现 `<permission>` HTML 元素**

这个文件定义了 `HTMLPermissionElement` 类，它是 Chromium 中用于实现新的 `<permission>` HTML 元素的关键组件。  这个元素旨在为开发者提供一种声明式的方式来表达对特定浏览器权限的需求，并根据权限状态提供相应的用户界面。

**具体功能点归纳：**

1. **权限请求和状态管理:**
   -  解析 `<permission>` 元素的 `type` 属性，识别所需的浏览器权限 (例如：地理位置、摄像头、麦克风)。
   -  支持单个权限和组合权限（例如：摄像头和麦克风）。
   -  使用 `PermissionService` 与浏览器权限系统交互，请求权限状态。
   -  监听权限状态的变化，并通过 `PermissionObserver` 接口接收通知。
   -  维护权限状态的内部映射 (`permission_status_map_`)。
   -  提供 `initialPermissionStatus()` 和 `permissionStatus()` 方法，以 JavaScript 可访问的方式暴露初始和当前的权限状态。

2. **用户界面呈现和交互:**
   -  创建并管理一个用户代理 shadow root，并在其中包含用于显示权限相关文本的 `<span>` 元素 (`permission_text_span_`)。
   -  根据当前的权限状态，动态更新 `permission_text_span_` 中显示的文本信息 (例如："请求访问摄像头"，"摄像头已允许")，支持多语言本地化。
   -  默认情况下，该元素是可聚焦的，类似于按钮。
   -  通过 `AdjustStyle()` 方法，强制执行一些样式约束，以确保可访问性和可用性，例如：最小字重、限制字间距和词间距、确保足够的颜色对比度等。

3. **IntersectionObserver 集成:**
   -  使用 `IntersectionObserver` 监控元素与视口的交叉情况，并根据可见性状态调整元素的行为。
   -  当元素刚添加到布局树或最近变为完全可见时，会暂时禁用元素的点击交互。
   -  如果元素不可见（超出视口、被裁剪或被遮挡），也会禁用点击交互，防止用户在不了解情况时触发权限请求。

4. **生命周期管理:**
   -  在元素插入 DOM 树时 (`InsertedInto`)，可能会注册 `EmbeddedPermissionControl` 以进行更细粒度的权限控制。
   -  在元素添加到布局树时 (`AttachLayoutTree`)，会启动一个定时器，暂时禁用点击。
   -  在元素从布局树移除时 (`DetachLayoutTree`)，会取消生命周期通知的注册。
   -  在元素从 DOM 树移除时 (`RemovedFrom`)，会清理相关的权限监听器和状态。

5. **错误处理和日志记录:**
   -  如果 `<permission>` 元素的 `type` 属性无效或不支持，会在控制台输出错误信息。
   -  对在受限环境（如 fenced frames 或缺少必要的 CSP 指令的跨域 iframe）中使用权限元素进行检查并输出错误。

6. **CSS 样式调整:**
   -  通过 `AdjustStyle()` 方法，对元素的样式进行调整，例如：
     -  限制外边距的最小值。
     -  强制最小字重，并将非法的字体样式重置为 normal。
     -  限制字间距和词间距的范围。
     -  确保 `display` 属性为 `inline-block`。
     -  进行颜色对比度检查，如果对比度不足，可能会被标记为 invalid。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:**
    - `<permission type="camera microphone"></permission>`：  在 HTML 中声明一个 `<permission>` 元素，请求摄像头和麦克风的权限。`type` 属性定义了请求的权限类型。
* **JavaScript:**
    - `const permissionElem = document.querySelector('permission');`
    - `console.log(permissionElem.permissionStatus());`：JavaScript 可以通过 DOM API 获取到 `<permission>` 元素，并访问其 `permissionStatus()` 属性来获取当前的权限状态。
* **CSS:**
    - 虽然 `HTMLPermissionElement` 会强制一些基本的样式，开发者仍然可以使用 CSS 来进一步定制元素的外观。例如，可以设置元素的背景色、字体颜色等。
    - 然而，该元素会拒绝一些可能影响其核心功能的样式属性，例如通过 `GetCascadeFilter()` 限制某些属性的级联。
    - 例如，代码中会检查颜色和背景色的对比度，这直接关联到 CSS 的 `color` 和 `background-color` 属性。

**逻辑推理的假设输入与输出:**

假设输入：一个 `<permission type="geolocation">` 元素被添加到页面中。

输出：
1. `HTMLPermissionElement` 会解析 `type` 属性，确定需要地理位置权限。
2. 它会向浏览器权限系统请求地理位置权限的状态。
3. 初始状态可能是 "prompt" (需要用户授权)。
4. `permission_text_span_` 可能会显示 "请求访问您的位置信息"。
5. 如果用户在浏览器中授权了地理位置权限，权限状态会更新为 "granted"，并且 `permission_text_span_` 的文本会更新为 "位置信息已允许"。

**涉及用户或编程常见的使用错误举例说明:**

1. **错误的 `type` 属性:**
   - 用户可能会设置一个不存在或拼写错误的 `type` 属性，例如 `<permission type="wificonnection">`。
   - 结果：`HTMLPermissionElement` 会识别出无效的权限类型，并在控制台输出错误信息，该元素可能不会正常工作。

2. **在不支持的环境中使用:**
   - 开发者可能会在 fenced frame 中使用需要权限的 `<permission>` 元素，但没有正确配置 Permissions Policy。
   - 结果：`HTMLPermissionElement` 会检测到这种情况，并在控制台输出错误，权限请求可能会被阻止。

3. **样式导致不可读:**
   - 开发者可能会使用 CSS 样式使得权限元素的文本与背景色对比度过低，导致用户难以阅读。
   - 结果：`HTMLPermissionElement` 会检测到对比度不足，可能会被标记为 invalid，并且可能禁用交互以防止用户在无法理解提示的情况下操作。

**总结 (针对第 1 部分):**

`HTMLPermissionElement.cc` 文件的核心功能是定义和实现了 `<permission>` 这个新的 HTML 元素。它负责处理权限请求、管理权限状态、呈现与权限相关的用户界面，并集成 `IntersectionObserver` 来根据元素的可见性调整行为。  该实现还关注元素的样式和可访问性，并进行错误处理和日志记录，以帮助开发者正确使用该元素。

Prompt: 
```
这是目录为blink/renderer/core/html/html_permission_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/html_permission_element.h"

#include <optional>

#include "base/functional/bind.h"
#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_functions.h"
#include "third_party/blink/public/common/input/web_pointer_properties.h"
#include "third_party/blink/public/mojom/permissions/permission.mojom-blink.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/public/strings/grit/permission_element_strings.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_permission_state.h"
#include "third_party/blink/renderer/core/css/css_selector.h"
#include "third_party/blink/renderer/core/css/font_size_functions.h"
#include "third_party/blink/renderer/core/css/properties/css_property_instances.h"
#include "third_party/blink/renderer/core/css/properties/longhand.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/space_split_string.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_ukm_aggregator.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_permission_element_strings_map.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_entry.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/computed_style_base_constants.h"
#include "third_party/blink/renderer/platform/fonts/font_description.h"
#include "third_party/blink/renderer/platform/fonts/font_selection_types.h"
#include "third_party/blink/renderer/platform/geometry/calculation_expression_node.h"
#include "third_party/blink/renderer/platform/geometry/calculation_value.h"
#include "third_party/blink/renderer/platform/geometry/length.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "ui/gfx/color_utils.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

using mojom::blink::EmbeddedPermissionControlResult;
using mojom::blink::EmbeddedPermissionRequestDescriptor;
using mojom::blink::PermissionDescriptor;
using mojom::blink::PermissionDescriptorPtr;
using mojom::blink::PermissionName;
using mojom::blink::PermissionObserver;
using mojom::blink::PermissionService;
using MojoPermissionStatus = mojom::blink::PermissionStatus;
// A data structure that maps Permission element MessageIds to locale specific
// MessageIds.
// Key of the outer map: locale.
// Key of the inner map: The base MessageId (in english).
// Value of the outer map: The corresponding MessageId in the given locale.
using GeneratedMessagesMap = HashMap<String, HashMap<int, int>>;

namespace {

const base::TimeDelta kDefaultDisableTimeout = base::Milliseconds(500);
constexpr FontSelectionValue kMinimumFontWeight = FontSelectionValue(200);
constexpr float kMaximumWordSpacingToFontSizeRatio = 0.5;
constexpr float kMinimumAllowedContrast = 3.;
constexpr float kMaximumLetterSpacingToFontSizeRatio = 0.2;
constexpr float kMinimumLetterSpacingToFontSizeRatio = -0.05;
constexpr int kMaxLengthToFontSizeRatio = 3;
constexpr int kMinLengthToFontSizeRatio = 1;
constexpr int kMaxVerticalPaddingToFontSizeRatio = 1;
constexpr int kMaxHorizontalPaddingToFontSizeRatio = 5;
// Needed to avoid IntersectionObserver false-positives caused by other elements
// being too close.
constexpr int kMinMargin = 4;
constexpr float kIntersectionThreshold = 1.0f;

PermissionDescriptorPtr CreatePermissionDescriptor(PermissionName name) {
  auto descriptor = PermissionDescriptor::New();
  descriptor->name = name;
  return descriptor;
}

// To support group permissions, the `type` attribute of permission element
// would contain a list of permissions (type is a space-separated string, for
// example <permission type=”camera microphone”>).
// This helper converts the type string to a list of `PermissionDescriptor`. If
// any of the splitted strings is invalid or not supported, return an empty
// list.
Vector<PermissionDescriptorPtr> ParsePermissionDescriptorsFromString(
    const AtomicString& type) {
  SpaceSplitString permissions(type);
  Vector<PermissionDescriptorPtr> permission_descriptors;

  // TODO(crbug.com/1462930): For MVP, we only support:
  // - Single permission: geolocation, camera, microphone.
  // - Group of 2 permissions: camera and microphone (order does not matter).
  // - Repeats are *not* allowed: "camera camera" is invalid.
  for (unsigned i = 0; i < permissions.size(); i++) {
    if (permissions[i] == "geolocation") {
      permission_descriptors.push_back(
          CreatePermissionDescriptor(PermissionName::GEOLOCATION));
    } else if (permissions[i] == "camera") {
      permission_descriptors.push_back(
          CreatePermissionDescriptor(PermissionName::VIDEO_CAPTURE));
    } else if (permissions[i] == "microphone") {
      permission_descriptors.push_back(
          CreatePermissionDescriptor(PermissionName::AUDIO_CAPTURE));
    } else {
      return Vector<PermissionDescriptorPtr>();
    }
  }

  if (permission_descriptors.size() <= 1) {
    return permission_descriptors;
  }

  if (permission_descriptors.size() >= 3) {
    return Vector<PermissionDescriptorPtr>();
  }

  if ((permission_descriptors[0]->name == PermissionName::VIDEO_CAPTURE &&
       permission_descriptors[1]->name == PermissionName::AUDIO_CAPTURE) ||
      (permission_descriptors[0]->name == PermissionName::AUDIO_CAPTURE &&
       permission_descriptors[1]->name == PermissionName::VIDEO_CAPTURE)) {
    return permission_descriptors;
  }

  return Vector<PermissionDescriptorPtr>();
}

int GetTranslatedMessageID(int message_id,
                           const AtomicString& language_string) {
  DCHECK(language_string.IsLowerASCII());
  DEFINE_STATIC_LOCAL(GeneratedMessagesMap, generated_message_ids, ());
  if (language_string.empty()) {
    return message_id;
  }

  if (generated_message_ids.empty()) {
    FillInPermissionElementTranslationsMap(generated_message_ids);
  }

  const auto language_map_itr = generated_message_ids.find(language_string);
  if (language_map_itr != generated_message_ids.end()) {
    const auto& language_map = language_map_itr->value;
    const auto translated_message_itr = language_map.find(message_id);
    if (translated_message_itr != language_map.end()) {
      return translated_message_itr->value;
    }
  }

  Vector<String> parts;
  language_string.GetString().Split('-', parts);

  if (parts.size() == 0) {
    return message_id;
  }
  // This is to support locales with unknown combination of languages and
  // countries. If the combination of language and country is not known,
  // the code will fallback to strings just from the language part of the
  // locale.
  // Eg: en-au is a unknown combination, in this case we will fall back to
  // en strings.
  if (generated_message_ids.Contains(parts[0])) {
    const auto& language_map = generated_message_ids.find(parts[0])->value;
    if (language_map.Contains(message_id)) {
      return language_map.find(message_id)->value;
    }
  }
  return message_id;
}

// Helper to get permission text resource ID for the given map which has only
// one element.
int GetUntranslatedMessageIDSinglePermission(PermissionName name,
                                             bool granted,
                                             bool is_precise_location) {
  if (name == PermissionName::VIDEO_CAPTURE) {
    return granted ? IDS_PERMISSION_REQUEST_CAMERA_ALLOWED
                   : IDS_PERMISSION_REQUEST_CAMERA;
  }

  if (name == PermissionName::AUDIO_CAPTURE) {
    return granted ? IDS_PERMISSION_REQUEST_MICROPHONE_ALLOWED
                   : IDS_PERMISSION_REQUEST_MICROPHONE;
  }

  if (name == PermissionName::GEOLOCATION) {
    if (is_precise_location) {
      // This element uses precise location.
      return granted ? IDS_PERMISSION_REQUEST_PRECISE_GEOLOCATION_ALLOWED
                     : IDS_PERMISSION_REQUEST_PRECISE_GEOLOCATION;
    }
    return granted ? IDS_PERMISSION_REQUEST_GEOLOCATION_ALLOWED
                   : IDS_PERMISSION_REQUEST_GEOLOCATION;
  }

  return 0;
}

// Helper to get permission text resource ID for the given map which has
// multiple elements. Currently we only support "camera microphone" grouped
// permissions.
int GetUntranslatedMessageIDMultiplePermissions(bool granted) {
  return granted ? IDS_PERMISSION_REQUEST_CAMERA_MICROPHONE_ALLOWED
                 : IDS_PERMISSION_REQUEST_CAMERA_MICROPHONE;
}

// Helper to get `PermissionsPolicyFeature` from permission name
mojom::blink::PermissionsPolicyFeature PermissionNameToPermissionsPolicyFeature(
    PermissionName permission_name) {
  switch (permission_name) {
    case PermissionName::AUDIO_CAPTURE:
      return mojom::blink::PermissionsPolicyFeature::kMicrophone;
    case PermissionName::VIDEO_CAPTURE:
      return mojom::blink::PermissionsPolicyFeature::kCamera;
    case PermissionName::GEOLOCATION:
      return mojom::blink::PermissionsPolicyFeature::kGeolocation;
    default:
      NOTREACHED() << "Not supported permission " << permission_name;
  }
}

// Helper to translate permission names into strings, primarily used for logging
// console messages.
String PermissionNameToString(PermissionName permission_name) {
  switch (permission_name) {
    case PermissionName::GEOLOCATION:
      return "geolocation";
    case PermissionName::AUDIO_CAPTURE:
      return "audio_capture";
    case PermissionName::VIDEO_CAPTURE:
      return "video_capture";
    default:
      NOTREACHED() << "Not supported permission " << permission_name;
  }
}

// Helper to translated permission statuses to strings.
V8PermissionState::Enum PermissionStatusToV8Enum(MojoPermissionStatus status) {
  switch (status) {
    case MojoPermissionStatus::GRANTED:
      return V8PermissionState::Enum::kGranted;
    case MojoPermissionStatus::ASK:
      return V8PermissionState::Enum::kPrompt;
    case MojoPermissionStatus::DENIED:
      return V8PermissionState::Enum::kDenied;
  }
  NOTREACHED();
}

float ContrastBetweenColorAndBackgroundColor(const ComputedStyle* style) {
  return color_utils::GetContrastRatio(
      style->VisitedDependentColor(GetCSSPropertyColor()).toSkColor4f(),
      style->VisitedDependentColor(GetCSSPropertyBackgroundColor())
          .toSkColor4f());
}

// Returns the minimum contrast between the background color and all four border
// colors.
float ContrastBetweenColorAndBorderColor(const ComputedStyle* style) {
  auto background_color =
      style->VisitedDependentColor(GetCSSPropertyBackgroundColor())
          .toSkColor4f();
  SkColor4f border_colors[] = {
      style->VisitedDependentColor(GetCSSPropertyBorderBottomColor())
          .toSkColor4f(),
      style->VisitedDependentColor(GetCSSPropertyBorderTopColor())
          .toSkColor4f(),
      style->VisitedDependentColor(GetCSSPropertyBorderLeftColor())
          .toSkColor4f(),
      style->VisitedDependentColor(GetCSSPropertyBorderRightColor())
          .toSkColor4f()};

  float min_contrast = SK_FloatInfinity;
  float contrast;
  for (const auto& border_color : border_colors) {
    contrast = color_utils::GetContrastRatio(border_color, background_color);
    if (min_contrast > contrast) {
      min_contrast = contrast;
    }
  }

  return min_contrast;
}

// Returns true if the 'color' or 'background-color' properties have the
// alphas set to anything else except fully opaque.
bool AreColorsNonOpaque(const ComputedStyle* style) {
  return style->VisitedDependentColor(GetCSSPropertyColor()).Alpha() != 1. ||
         style->VisitedDependentColor(GetCSSPropertyBackgroundColor())
                 .Alpha() != 1;
}

// Returns true if any border color has an alpha that is not fully opaque.
bool AreBorderColorsNonOpaque(const ComputedStyle* style) {
  return style->VisitedDependentColor(GetCSSPropertyBorderBottomColor())
                 .Alpha() != 1. ||
         style->VisitedDependentColor(GetCSSPropertyBorderTopColor()).Alpha() !=
             1. ||
         style->VisitedDependentColor(GetCSSPropertyBorderLeftColor())
                 .Alpha() != 1. ||
         style->VisitedDependentColor(GetCSSPropertyBorderRightColor())
                 .Alpha() != 1.;
}

bool IsBorderSufficientlyDistinctFromBackgroundColor(
    const ComputedStyle* style) {
  if (!style || !style->HasBorder()) {
    return false;
  }

  if (style->BorderBottomWidth() == 0 || style->BorderTopWidth() == 0 ||
      style->BorderLeftWidth() == 0 || style->BorderRightWidth() == 0) {
    return false;
  }

  if (AreBorderColorsNonOpaque(style)) {
    return false;
  }

  if (ContrastBetweenColorAndBorderColor(style) < kMinimumAllowedContrast) {
    return false;
  }

  return true;
}

// Build an expression that is equivalent to `size * |factor|)`. To be used
// inside a `calc-size` expression.
scoped_refptr<const CalculationExpressionNode> BuildFitContentExpr(
    float factor) {
  auto constant_expr =
      base::MakeRefCounted<CalculationExpressionNumberNode>(factor);
  auto size_expr = base::MakeRefCounted<CalculationExpressionSizingKeywordNode>(
      CalculationExpressionSizingKeywordNode::Keyword::kSize);
  return CalculationExpressionOperationNode::CreateSimplified(
      CalculationExpressionOperationNode::Children({constant_expr, size_expr}),
      CalculationOperator::kMultiply);
}

// Builds an expression that takes a |length| and bounds it lower, higher, or on
// both sides with the provided expressions.
scoped_refptr<const CalculationExpressionNode> BuildLengthBoundExpr(
    const Length& length,
    std::optional<scoped_refptr<const CalculationExpressionNode>>
        lower_bound_expr,
    std::optional<scoped_refptr<const CalculationExpressionNode>>
        upper_bound_expr) {
  if (lower_bound_expr.has_value() && upper_bound_expr.has_value()) {
    return CalculationExpressionOperationNode::CreateSimplified(
        CalculationExpressionOperationNode::Children(
            {lower_bound_expr.value(),
             length.AsCalculationValue()->GetOrCreateExpression(),
             upper_bound_expr.value()}),
        CalculationOperator::kClamp);
  }

  if (lower_bound_expr.has_value()) {
    return CalculationExpressionOperationNode::CreateSimplified(
        CalculationExpressionOperationNode::Children(
            {lower_bound_expr.value(),
             length.AsCalculationValue()->GetOrCreateExpression()}),
        CalculationOperator::kMax);
  }

  if (upper_bound_expr.has_value()) {
    return CalculationExpressionOperationNode::CreateSimplified(
        CalculationExpressionOperationNode::Children(
            {upper_bound_expr.value(),
             length.AsCalculationValue()->GetOrCreateExpression()}),
        CalculationOperator::kMin);
  }

  NOTREACHED();
}

}  // namespace

HTMLPermissionElement::HTMLPermissionElement(Document& document)
    : HTMLElement(html_names::kPermissionTag, document),
      ScrollSnapshotClient(GetDocument().GetFrame()),
      permission_service_(document.GetExecutionContext()),
      permission_observer_receivers_(this, document.GetExecutionContext()),
      embedded_permission_control_receiver_(this,
                                            document.GetExecutionContext()),
      disable_reason_expire_timer_(
          this,
          &HTMLPermissionElement::DisableReasonExpireTimerFired) {
  DCHECK(RuntimeEnabledFeatures::PermissionElementEnabled(
      document.GetExecutionContext()));
  SetHasCustomStyleCallbacks();
  intersection_observer_ = IntersectionObserver::Create(
      GetDocument(),
      WTF::BindRepeating(&HTMLPermissionElement::OnIntersectionChanged,
                         WrapWeakPersistent(this)),
      LocalFrameUkmAggregator::kPermissionElementIntersectionObserver,
      IntersectionObserver::Params{
          .thresholds = {kIntersectionThreshold},
          .semantics = IntersectionObserver::kFractionOfTarget,
          .behavior = IntersectionObserver::kDeliverDuringPostLifecycleSteps,
          .delay = base::Milliseconds(100),
          .track_visibility = true,
          .expose_occluder_id = true,
      });

  intersection_observer_->observe(this);
  EnsureUserAgentShadowRoot();
  UseCounter::Count(document, WebFeature::kHTMLPermissionElement);
}

HTMLPermissionElement::~HTMLPermissionElement() = default;

const AtomicString& HTMLPermissionElement::GetType() const {
  return type_.IsNull() ? g_empty_atom : type_;
}

String HTMLPermissionElement::invalidReason() const {
  return clicking_enabled_state_.invalid_reason;
}

bool HTMLPermissionElement::isValid() const {
  return clicking_enabled_state_.is_valid;
}

V8PermissionState HTMLPermissionElement::initialPermissionStatus() const {
  return V8PermissionState(
      PermissionStatusToV8Enum(initial_aggregated_permission_status_.value_or(
          MojoPermissionStatus::ASK)));
}

V8PermissionState HTMLPermissionElement::permissionStatus() const {
  return V8PermissionState(PermissionStatusToV8Enum(
      aggregated_permission_status_.value_or(MojoPermissionStatus::ASK)));
}

void HTMLPermissionElement::Trace(Visitor* visitor) const {
  visitor->Trace(permission_service_);
  visitor->Trace(permission_observer_receivers_);
  visitor->Trace(embedded_permission_control_receiver_);
  visitor->Trace(permission_text_span_);
  visitor->Trace(intersection_observer_);
  visitor->Trace(disable_reason_expire_timer_);
  HTMLElement::Trace(visitor);
}

void HTMLPermissionElement::OnPermissionStatusInitialized(
    PermissionStatusMap initilized_map) {
  permission_status_map_ = std::move(initilized_map);
  UpdatePermissionStatusAndAppearance();
}

Node::InsertionNotificationRequest HTMLPermissionElement::InsertedInto(
    ContainerNode& insertion_point) {
  HTMLElement::InsertedInto(insertion_point);
  MaybeRegisterPageEmbeddedPermissionControl();
  return kInsertionDone;
}

void HTMLPermissionElement::AttachLayoutTree(AttachContext& context) {
  Element::AttachLayoutTree(context);
  DisableClickingTemporarily(DisableReason::kRecentlyAttachedToLayoutTree,
                             kDefaultDisableTimeout);
  CHECK(GetDocument().View());
  GetDocument().View()->RegisterForLifecycleNotifications(this);
}

void HTMLPermissionElement::DetachLayoutTree(bool performing_reattach) {
  Element::DetachLayoutTree(performing_reattach);
  if (auto* view = GetDocument().View()) {
    view->UnregisterFromLifecycleNotifications(this);
  }
}

void HTMLPermissionElement::RemovedFrom(ContainerNode& insertion_point) {
  HTMLElement::RemovedFrom(insertion_point);
  // We also need to remove all permission observer receivers from the set, to
  // effectively stop listening the permission status change events.
  permission_observer_receivers_.Clear();
  permission_status_map_.clear();
  aggregated_permission_status_ = std::nullopt;
  pseudo_state_ = {/*has_invalid_style*/ false, /*is_occluded*/ false};
  if (disable_reason_expire_timer_.IsActive()) {
    disable_reason_expire_timer_.Stop();
  }
  intersection_rect_ = std::nullopt;
  if (embedded_permission_control_receiver_.is_bound()) {
    embedded_permission_control_receiver_.reset();
  }

  if (LocalDOMWindow* window = GetDocument().domWindow()) {
    CachedPermissionStatus::From(window)->UnregisterClient(
        this, permission_descriptors_);
  }
}

void HTMLPermissionElement::Focus(const FocusParams& params) {
  // This will only apply to `focus` and `blur` JS API. Other focus types (like
  // accessibility focusing and manual user focus), will still be permitted as
  // usual.
  if (params.type == mojom::blink::FocusType::kScript) {
    return;
  }

  HTMLElement::Focus(params);
}

FocusableState HTMLPermissionElement::SupportsFocus(UpdateBehavior) const {
  // The permission element is only focusable if it has a valid type.
  return permission_descriptors_.empty() ? FocusableState::kNotFocusable
                                         : FocusableState::kFocusable;
}

int HTMLPermissionElement::DefaultTabIndex() const {
  // The permission element behaves similarly to a button and therefore is
  // focusable via keyboard by default.
  return 0;
}

CascadeFilter HTMLPermissionElement::GetCascadeFilter() const {
  // Reject all properties for which 'kValidForPermissionElement' is false.
  return CascadeFilter(CSSProperty::kValidForPermissionElement, false);
}

bool HTMLPermissionElement::CanGeneratePseudoElement(PseudoId id) const {
  switch (id) {
    case PseudoId::kPseudoIdAfter:
    case PseudoId::kPseudoIdBefore:
    case PseudoId::kPseudoIdCheck:
    case PseudoId::kPseudoIdSelectArrow:
      return false;
    default:
      return Element::CanGeneratePseudoElement(id);
  }
}

bool HTMLPermissionElement::HasInvalidStyle() const {
  return IsClickingDisabledIndefinitely(DisableReason::kInvalidStyle);
}

bool HTMLPermissionElement::IsOccluded() const {
  return !GetRecentlyAttachedTimeoutRemaining() &&
         IsClickingDisabledIndefinitely(
             DisableReason::kIntersectionVisibilityOccludedOrDistorted);
}

// static
Vector<PermissionDescriptorPtr>
HTMLPermissionElement::ParsePermissionDescriptorsForTesting(
    const AtomicString& type) {
  return ParsePermissionDescriptorsFromString(type);
}

// static
String HTMLPermissionElement::DisableReasonToString(DisableReason reason) {
  switch (reason) {
    case DisableReason::kRecentlyAttachedToLayoutTree:
      return "being recently attached to layout tree";
    case DisableReason::kIntersectionRecentlyFullyVisible:
      return "being recently fully visible";
    case DisableReason::kIntersectionWithViewportChanged:
      return "intersection with viewport changed";
    case DisableReason::kIntersectionVisibilityOutOfViewPortOrClipped:
      return "intersection out of viewport or clipped";
    case DisableReason::kIntersectionVisibilityOccludedOrDistorted:
      return "intersection occluded or distorted";
    case DisableReason::kInvalidStyle:
      return "invalid style";
    case DisableReason::kUnknown:
      NOTREACHED();
  }
}

// static
HTMLPermissionElement::UserInteractionDeniedReason
HTMLPermissionElement::DisableReasonToUserInteractionDeniedReason(
    DisableReason reason) {
  switch (reason) {
    case DisableReason::kRecentlyAttachedToLayoutTree:
      return UserInteractionDeniedReason::kRecentlyAttachedToLayoutTree;
    case DisableReason::kIntersectionRecentlyFullyVisible:
      return UserInteractionDeniedReason::kIntersectionRecentlyFullyVisible;
    case DisableReason::kIntersectionWithViewportChanged:
      return UserInteractionDeniedReason::kIntersectionWithViewportChanged;
    case DisableReason::kIntersectionVisibilityOutOfViewPortOrClipped:
      return UserInteractionDeniedReason::
          kIntersectionVisibilityOutOfViewPortOrClipped;
    case DisableReason::kIntersectionVisibilityOccludedOrDistorted:
      return UserInteractionDeniedReason::
          kIntersectionVisibilityOccludedOrDistorted;
    case DisableReason::kInvalidStyle:
      return UserInteractionDeniedReason::kInvalidStyle;
    case DisableReason::kUnknown:
      NOTREACHED();
  }
}

// static
AtomicString HTMLPermissionElement::DisableReasonToInvalidReasonString(
    DisableReason reason) {
  switch (reason) {
    case DisableReason::kRecentlyAttachedToLayoutTree:
      return AtomicString("recently_attached");
    case DisableReason::kIntersectionRecentlyFullyVisible:
      return AtomicString("intersection_visible");
    case DisableReason::kIntersectionWithViewportChanged:
      return AtomicString("intersection_changed");
    case DisableReason::kIntersectionVisibilityOutOfViewPortOrClipped:
      return AtomicString("intersection_out_of_viewport_or_clipped");
    case DisableReason::kIntersectionVisibilityOccludedOrDistorted:
      return AtomicString("intersection_occluded_or_distorted");
    case DisableReason::kInvalidStyle:
      return AtomicString("style_invalid");
    case DisableReason::kUnknown:
      NOTREACHED();
  }
}

PermissionService* HTMLPermissionElement::GetPermissionService() {
  if (!permission_service_.is_bound()) {
    GetExecutionContext()->GetBrowserInterfaceBroker().GetInterface(
        permission_service_.BindNewPipeAndPassReceiver(GetTaskRunner()));
    permission_service_.set_disconnect_handler(WTF::BindOnce(
        &HTMLPermissionElement::OnPermissionServiceConnectionFailed,
        WrapWeakPersistent(this)));
  }

  return permission_service_.get();
}

void HTMLPermissionElement::OnPermissionServiceConnectionFailed() {
  permission_service_.reset();
}

bool HTMLPermissionElement::MaybeRegisterPageEmbeddedPermissionControl() {
  if (embedded_permission_control_receiver_.is_bound()) {
    return true;
  }

  if (permission_descriptors_.empty()) {
    return false;
  }

  LocalFrame* frame = GetDocument().GetFrame();
  if (!frame) {
    return false;
  }

  if (frame->IsInFencedFrameTree()) {
    AddConsoleError(
        String::Format("The permission '%s' is not allowed in fenced frame",
                       GetType().Utf8().c_str()));
    return false;
  }

  if (frame->IsCrossOriginToOutermostMainFrame() &&
      !GetExecutionContext()
           ->GetContentSecurityPolicy()
           ->HasEnforceFrameAncestorsDirectives()) {
    AddConsoleError(
        String::Format("The permission '%s' is not allowed without the CSP "
                       "'frame-ancestors' directive present.",
                       GetType().Utf8().c_str()));
    return false;
  }

  for (const PermissionDescriptorPtr& descriptor : permission_descriptors_) {
    if (!GetExecutionContext()->IsFeatureEnabled(
            PermissionNameToPermissionsPolicyFeature(descriptor->name))) {
      AddConsoleError(String::Format(
          "The permission '%s' is not allowed in the current context due to "
          "PermissionsPolicy",
          PermissionNameToString(descriptor->name).Utf8().c_str()));
      return false;
    }
  }

  CachedPermissionStatus::From(GetDocument().domWindow())
      ->RegisterClient(this, permission_descriptors_);
  mojo::PendingRemote<EmbeddedPermissionControlClient> client;
  embedded_permission_control_receiver_.Bind(
      client.InitWithNewPipeAndPassReceiver(), GetTaskRunner());
  GetPermissionService()->RegisterPageEmbeddedPermissionControl(
      mojo::Clone(permission_descriptors_), std::move(client));
  return true;
}

void HTMLPermissionElement::AttributeChanged(
    const AttributeModificationParams& params) {
  if (params.name == html_names::kTypeAttr) {
    // `type` should only take effect once, when is added to the permission
    // element. Removing, or modifying the attribute has no effect.
    if (!type_.IsNull()) {
      return;
    }

    type_ = params.new_value;

    CHECK(permission_descriptors_.empty());
    permission_descriptors_ = ParsePermissionDescriptorsFromString(GetType());
    if (permission_descriptors_.empty()) {
      AddConsoleError("The permission type '" + GetType().GetString() +
                      "' is not supported by the "
                      "permission element.");
      return;
    }

    CHECK_LE(permission_descriptors_.size(), 2U)
        << "Unexpected permissions size " << permission_descriptors_.size();
  }

  MaybeRegisterPageEmbeddedPermissionControl();

  if (params.name == html_names::kPreciselocationAttr) {
    // This attribute can only be set once, and can not be modified afterwards.
    if (is_precise_location_) {
      return;
    }

    is_precise_location_ = true;
    UpdateText();
  }

  if (params.name == html_names::kLangAttr) {
    UpdateText();
  }

  HTMLElement::AttributeChanged(params);
}

void HTMLPermissionElement::DidAddUserAgentShadowRoot(ShadowRoot& root) {
  permission_text_span_ = MakeGarbageCollected<HTMLSpanElement>(GetDocument());
  permission_text_span_->SetShadowPseudoId(
      shadow_element_names::kPseudoInternalPermissionTextSpan);
  root.AppendChild(permission_text_span_);
}

void HTMLPermissionElement::AdjustStyle(ComputedStyleBuilder& builder) {
  Element::AdjustStyle(builder);

  builder.SetOutlineOffset(builder.OutlineOffset().ClampNegativeToZero());

  auto device_pixel_ratio =
      GetDocument().GetFrame()->LocalFrameRoot().DevicePixelRatio();

  builder.SetMarginLeft(AdjustedBoundedLength(
      builder.MarginLeft(), /*lower_bound=*/kMinMargin * device_pixel_ratio,
      /*upper_bound=*/std::nullopt,
      /*should_multiply_by_content_size=*/false));
  builder.SetMarginRight(AdjustedBoundedLength(
      builder.MarginRight(), /*lower_bound=*/kMinMargin * device_pixel_ratio,
      /*upper_bound=*/std::nullopt,
      /*should_multiply_by_content_size=*/false));
  builder.SetMarginTop(AdjustedBoundedLength(
      builder.MarginTop(), /*lower_bound=*/kMinMargin * device_pixel_ratio,
      /*upper_bound=*/std::nullopt,
      /*should_multiply_by_content_size=*/false));
  builder.SetMarginBottom(AdjustedBoundedLength(
      builder.MarginBottom(), /*lower_bound=*/kMinMargin * device_pixel_ratio,
      /*upper_bound=*/std::nullopt,
      /*should_multiply_by_content_size=*/false));

  // Check and modify (if needed) properties related to the font.
  std::optional<FontDescription> new_font_description;

  // Font weight has to be at least kMinimumFontWeight.
  if (builder.GetFontDescription().Weight() <= kMinimumFontWeight) {
    if (!new_font_description) {
      new_font_description = builder.GetFontDescription();
    }
    new_font_description->SetWeight(kMinimumFontWeight);
  }

  // Any other values other than 'italic' and 'normal' are reset to 'normal'.
  if (builder.GetFontDescription().Style() != kItalicSlopeValue &&
      builder.GetFontDescription().Style() != kNormalSlopeValue) {
    if (!new_font_description) {
      new_font_description = builder.GetFontDescription();
    }
    new_font_description->SetStyle(kNormalSlopeValue);
  }

  if (new_font_description) {
    builder.SetFontDescription(*new_font_description);
  }

  if (builder.GetFontDescription().WordSpacing() >
      kMaximumWordSpacingToFontSizeRatio * builder.FontSize()) {
    builder.SetWordSpacing(builder.FontSize() *
                           kMaximumWordSpacingToFontSizeRatio);
  } else if (builder.GetFontDescription().WordSpacing() < 0) {
    builder.SetWordSpacing(0);
  }

  if (builder.GetDisplayStyle().Display() != EDisplay::kNone &&
      builder.GetDisplayStyle().Display() != EDisplay::kInlineBlock) {
    builder.SetDisplay(EDisplay::kInlineBlock);
  }

  if (builder.GetFontDescription().LetterSpacing() >
      kMaximumLetterSpacingToFontSizeRatio * builder.FontSize()) {
    builder.SetLetterSpacing(builder.FontSize() *
                             kMaximumLetterSpacingToFontSizeRatio);
  } else if (builder.GetFontDescription().LetterSpacing() <
             kMinimumLetterSpacingToFontSizeRatio * builder.FontSize()) {
    builder.SetLetterSpacing(builder.FontSize() *
                             kMinimumLetterSpacingToFontSizeRatio);
  }

  builder.SetMinHeight(AdjustedBoundedLength(
      builder.MinHeigh
"""


```
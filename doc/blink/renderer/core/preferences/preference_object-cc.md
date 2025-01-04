Response:
The user wants to understand the functionality of the `preference_object.cc` file in the Chromium Blink rendering engine. I need to break down its purpose and explain its interactions with web technologies like JavaScript, HTML, and CSS. I also need to provide examples, logical reasoning with inputs/outputs, common usage errors, and a step-by-step explanation of how a user's actions can lead to this code being executed.

Here's a plan:

1. **Identify the core functionality:** The file deals with accessing and potentially overriding user preferences related to accessibility and appearance (color scheme, contrast, reduced motion, reduced transparency, reduced data).

2. **Explain the interaction with web technologies:**
    - **JavaScript:**  The file provides a JavaScript API (likely through a web API) to read and potentially set overrides for these preferences.
    - **HTML:**  While not directly involved in rendering HTML, these preferences affect how the browser renders the page.
    - **CSS:**  These preferences directly map to CSS media queries (`prefers-color-scheme`, `prefers-contrast`, etc.).

3. **Provide examples:** Show how JavaScript might interact with this object to get the current preference or request an override. Demonstrate how these preferences affect CSS.

4. **Illustrate logical reasoning:** For the `override` and `value` functions, show examples of what happens when different preference names are requested.

5. **Highlight potential user errors:** Focus on incorrect usage of the JavaScript API, like providing invalid preference values.

6. **Describe user interaction leading to execution:** Trace the path from user actions (OS settings, browser settings, JavaScript calls) to the code in this file.

7. **Structure the response:**  Organize the information into clear sections as requested by the user.
这是 `blink/renderer/core/preferences/preference_object.cc` 文件的功能说明：

**核心功能:**

`PreferenceObject` 类的主要功能是**提供一个 JavaScript 可访问的接口，用于查询和潜在地覆盖用户的媒体偏好设置**，例如首选的颜色方案（浅色/深色）、对比度、是否启用减少动画、减少透明度和减少数据使用。

**它与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  `PreferenceObject` 暴露给 JavaScript，允许网页通过 JavaScript 代码读取用户的这些偏好设置。这使得网页能够根据用户的偏好进行动态调整。
* **CSS:**  这些偏好设置与 CSS 媒体查询（Media Queries）直接相关。例如，`prefers-color-scheme` 媒体查询允许 CSS 根据用户的首选颜色方案应用不同的样式。`PreferenceObject` 的存在使得 JavaScript 可以读取这些媒体查询背后的用户偏好。
* **HTML:** HTML 本身不直接与 `PreferenceObject` 交互，但 JavaScript 可以使用 `PreferenceObject` 获取的偏好信息来动态修改 HTML 结构或其应用的 CSS 类，从而影响最终的 HTML 呈现。

**功能详细说明：**

1. **`PreferenceObject` 的创建和初始化:**
   - 构造函数 `PreferenceObject(ExecutionContext* executionContext, AtomicString name)` 接收一个执行上下文 (通常是 `LocalDOMWindow`) 和一个表示偏好设置名称的字符串 (`name_`)。
   - 它获取与执行上下文关联的 `MediaValues` 对象，该对象存储了当前的媒体偏好设置。
   - 它将 `MediaValues` 对象中的偏好值（例如 `preferred_color_scheme_`）缓存到 `PreferenceObject` 实例中。

2. **`override(ScriptState* script_state)`:**
   - 此方法允许 JavaScript 查询当前是否对某个偏好设置进行了覆盖。
   - **输入:** 一个 `ScriptState` 对象，用于获取当前的执行上下文。
   - **输出:** 一个 `std::optional<AtomicString>`，如果该偏好设置被覆盖，则包含覆盖后的字符串值（例如 "light", "dark", "reduce"），否则返回 `std::nullopt`。
   - **逻辑推理:**
     - **假设输入:** `name_` 是 "color-scheme"，并且用户在浏览器或操作系统层面设置了首选深色模式，但当前页面通过 JavaScript API 覆盖为了浅色模式。
     - **输出:**  此方法会返回 `std::make_optional(AtomicString("light"))`。
   - 它检查 `PreferenceOverrides` 对象，该对象存储了通过 JavaScript API 设置的覆盖。

3. **`value(ScriptState* script_state)`:**
   - 此方法返回当前偏好设置的实际值。
   - **输入:** 一个 `ScriptState` 对象。
   - **输出:** 一个 `AtomicString`，表示当前偏好设置的值（例如 "light", "dark", "reduce", "no-preference"）。
   - **逻辑推理:**
     - **假设输入:** `name_` 是 "reduced-motion"，并且用户在操作系统或浏览器中启用了减少动画。
     - **输出:** 此方法会返回 `AtomicString("reduce")`。
   - 它首先检查是否有覆盖，如果有则返回覆盖后的值，否则返回从 `MediaValues` 获取的原始值。

4. **`clearOverride(ScriptState* script_state)`:**
   - 此方法允许 JavaScript 清除之前设置的偏好设置覆盖。
   - **输入:** 一个 `ScriptState` 对象。
   - **输出:** 无。
   - **逻辑推理:**
     - **假设当前状态:**  `name_` 是 "contrast"，并且通过 JavaScript 覆盖为了 "more"。
     - **操作:** 调用 `clearOverride`。
     - **结果:**  覆盖被清除，该偏好设置将恢复为用户操作系统或浏览器的默认设置。
   - 清除覆盖后，如果偏好设置的值发生了变化，它会触发一个 "change" 事件。

5. **`requestOverride(ScriptState* script_state, std::optional<AtomicString> value)`:**
   - 此方法允许 JavaScript 请求覆盖某个偏好设置。
   - **输入:** 一个 `ScriptState` 对象和一个可选的 `AtomicString` 值，表示要覆盖成的值。如果 `value` 为空，则相当于调用 `clearOverride`。
   - **输出:** 一个 `ScriptPromise<IDLUndefined>`，表示异步操作的结果。
   - **逻辑推理:**
     - **假设输入:** `name_` 是 "reduced-transparency"，并且 `value` 是 `std::make_optional(AtomicString("reduce"))`。
     - **输出:**  页面会尝试将 "prefers-reduced-transparency" 媒体查询覆盖为 "reduce"。Promise 会在操作完成后 resolve。
   - 它会验证提供的值是否为有效值，并将覆盖设置到 `PreferenceOverrides` 对象中。
   - 如果成功设置了覆盖，并且覆盖后的值与之前的值不同，或者之前没有覆盖但新的覆盖值与当前值相同，它会触发一个 "change" 事件。

6. **`validValues()`:**
   - 此方法返回一个冻结数组，包含该偏好设置的有效值。
   - **输入:** 无。
   - **输出:** 一个 `FrozenArray<IDLString>`，包含有效值字符串（例如对于 "color-scheme" 是 ["light", "dark"]）。

7. **`PreferenceMaybeChanged()`:**
   - 此方法在底层的媒体偏好设置发生变化时被调用。
   - 它检查当前缓存的偏好值是否与最新的 `MediaValues` 中的值不同。
   - 如果不同，则更新缓存的偏好值并触发一个 "change" 事件，通知 JavaScript 该偏好设置已更改。

**用户或编程常见的使用错误：**

1. **尝试覆盖无效的值:**  例如，尝试将 "color-scheme" 覆盖为 "gray"。`requestOverride` 方法会拒绝该请求并返回一个带有 `TypeMismatchError` 的 rejected promise。
   - **假设输入:** `preferenceObject.requestOverride("gray")`，当 `preferenceObject` 的 `name_` 是 "color-scheme"。
   - **输出:**  JavaScript 会收到一个 rejected promise，错误信息类似 "gray is not a valid value."。

2. **在不支持 Web Preferences API 的浏览器中使用:** 虽然代码本身在 Blink 引擎中，但如果用户使用的浏览器版本过低，可能无法访问相关的 JavaScript API。

3. **混淆 `override()` 和 `value()`:**  开发者可能会错误地认为 `override()` 返回的是当前生效的值，而实际上它只返回是否有覆盖以及覆盖的值。应该使用 `value()` 获取当前生效的值。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户修改操作系统或浏览器的偏好设置:**
   - 用户在操作系统设置中更改了外观模式为深色。
   - 浏览器会监听到操作系统的这些更改。
   - Blink 引擎会更新其内部的 `MediaValues` 对象，反映这些更改。
   - 当 JavaScript 代码访问 `PreferenceObject` 的 `value()` 方法时，它会返回更新后的值。

2. **网页通过 JavaScript 请求覆盖偏好设置:**
   - 网页的 JavaScript 代码调用 `preferenceObject.requestOverride("dark")` 来覆盖首选颜色方案为深色。
   - 这个调用会最终触发 `PreferenceObject::requestOverride` 方法。
   - `requestOverride` 会更新 `PreferenceOverrides` 对象，并可能触发 "change" 事件。
   - 相关的 CSS 媒体查询也会因此重新评估，页面样式可能会发生变化。

3. **网页监听 "change" 事件:**
   - 网页的 JavaScript 代码可能添加了 `preferenceObject.addEventListener('change', ...)` 来监听偏好设置的变化。
   - 当用户修改了偏好设置（无论是通过操作系统/浏览器还是通过 JavaScript 覆盖），`PreferenceObject::PreferenceMaybeChanged` 或 `PreferenceObject::clearOverride`/`requestOverride` 可能会触发 "change" 事件。
   - 网页的事件监听器会接收到该事件，并可以执行相应的逻辑。

**作为调试线索：**

如果你正在调试与这些偏好设置相关的行为，可以按照以下步骤：

1. **检查浏览器的开发者工具:** 查看 "Application" 或 "Rendering" 面板，可能会有关于媒体偏好设置的信息。
2. **在 JavaScript 中打印 `PreferenceObject` 的值:**  使用 `console.log(preferenceObject.value())` 来查看当前生效的偏好值。
3. **断点调试 `preference_object.cc`:** 如果你有 Chromium 的源代码和构建环境，可以在 `PreferenceObject` 的相关方法上设置断点，例如 `override`, `value`, `requestOverride`, `clearOverride`, `PreferenceMaybeChanged`，以跟踪代码的执行流程，查看偏好值是如何获取和修改的。
4. **检查 `PreferenceOverrides` 对象:**  了解当前是否有任何覆盖被设置。
5. **查看 CSS 媒体查询是否生效:**  检查应用到页面的 CSS 规则，确认媒体查询是否与当前的偏好设置匹配。

总而言之，`preference_object.cc` 是 Blink 引擎中一个关键的组件，它桥接了用户的媒体偏好设置和网页的 JavaScript 及 CSS 代码，使得网页能够更好地适应用户的个人喜好和辅助功能需求。

Prompt: 
```
这是目录为blink/renderer/core/preferences/preference_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/preferences/preference_object.h"

#include "third_party/blink/renderer/bindings/core/v8/frozen_array.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/core/css/media_values.h"
#include "third_party/blink/renderer/core/css/media_values_cached.h"
#include "third_party/blink/renderer/core/css/media_values_dynamic.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/preferences/preference_names.h"
#include "third_party/blink/renderer/core/preferences/preference_overrides.h"
#include "third_party/blink/renderer/core/preferences/preference_values.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

AtomicString ColorSchemeToString(
    mojom::blink::PreferredColorScheme colorScheme) {
  switch (colorScheme) {
    case mojom::PreferredColorScheme::kLight:
      return preference_values::kLight;
    case mojom::PreferredColorScheme::kDark:
      return preference_values::kDark;
    default:
      NOTREACHED();
  }
}

AtomicString ContrastToString(mojom::blink::PreferredContrast contrast) {
  switch (contrast) {
    case mojom::PreferredContrast::kMore:
      return preference_values::kMore;
    case mojom::PreferredContrast::kLess:
      return preference_values::kLess;
    case mojom::PreferredContrast::kCustom:
      return preference_values::kCustom;
    case mojom::PreferredContrast::kNoPreference:
      return preference_values::kNoPreference;
    default:
      NOTREACHED();
  }
}

PreferenceObject::PreferenceObject(ExecutionContext* executionContext,
                                   AtomicString name)
    : ExecutionContextLifecycleObserver(executionContext), name_(name) {
  LocalFrame* frame = nullptr;
  if (executionContext && !executionContext->IsContextDestroyed()) {
    frame = DynamicTo<LocalDOMWindow>(executionContext)->GetFrame();
  }
  media_values_ = MediaValues::CreateDynamicIfFrameExists(frame);
  preferred_color_scheme_ = media_values_->GetPreferredColorScheme();
  preferred_contrast_ = media_values_->GetPreferredContrast();
  prefers_reduced_data_ = media_values_->PrefersReducedData();
  prefers_reduced_motion_ = media_values_->PrefersReducedMotion();
  prefers_reduced_transparency_ = media_values_->PrefersReducedTransparency();
}

PreferenceObject::~PreferenceObject() = default;

std::optional<AtomicString> PreferenceObject::override(
    ScriptState* script_state) {
  CHECK(RuntimeEnabledFeatures::WebPreferencesEnabled());
  if (!script_state || !script_state->ContextIsValid()) {
    return std::nullopt;
  }
  auto* execution_context = ExecutionContext::From(script_state);
  if (!execution_context || execution_context->IsContextDestroyed()) {
    return std::nullopt;
  }
  auto* window = DynamicTo<LocalDOMWindow>(execution_context);
  if (!window) {
    return std::nullopt;
  }

  const PreferenceOverrides* overrides =
      window->GetFrame()->GetPage()->GetPreferenceOverrides();

  if (!overrides) {
    return std::nullopt;
  }

  if (name_ == preference_names::kColorScheme) {
    std::optional<mojom::blink::PreferredColorScheme> color_scheme =
        overrides->GetPreferredColorScheme();
    if (!color_scheme.has_value()) {
      return std::nullopt;
    }

    return std::make_optional(ColorSchemeToString(color_scheme.value()));
  } else if (name_ == preference_names::kContrast) {
    std::optional<mojom::blink::PreferredContrast> contrast =
        overrides->GetPreferredContrast();
    if (!contrast.has_value()) {
      return std::nullopt;
    }

    return std::make_optional(ContrastToString(contrast.value()));
  } else if (name_ == preference_names::kReducedMotion) {
    std::optional<bool> reduced_motion = overrides->GetPrefersReducedMotion();
    if (!reduced_motion.has_value()) {
      return std::nullopt;
    }

    return std::make_optional(reduced_motion.value()
                                  ? preference_values::kReduce
                                  : preference_values::kNoPreference);
  } else if (name_ == preference_names::kReducedTransparency) {
    std::optional<bool> reduced_transparency =
        overrides->GetPrefersReducedTransparency();
    if (!reduced_transparency.has_value()) {
      return std::nullopt;
    }

    return std::make_optional(reduced_transparency.value()
                                  ? preference_values::kReduce
                                  : preference_values::kNoPreference);
  } else if (name_ == preference_names::kReducedData) {
    std::optional<bool> reduced_data = overrides->GetPrefersReducedData();
    if (!reduced_data.has_value()) {
      return std::nullopt;
    }

    return std::make_optional(reduced_data ? preference_values::kReduce
                                           : preference_values::kNoPreference);
  } else {
    NOTREACHED();
  }
}

AtomicString PreferenceObject::value(ScriptState* script_state) {
  CHECK(RuntimeEnabledFeatures::WebPreferencesEnabled());
  if (!script_state || !script_state->ContextIsValid()) {
    return g_empty_atom;
  }
  auto* execution_context = ExecutionContext::From(script_state);
  if (!execution_context || execution_context->IsContextDestroyed()) {
    return g_empty_atom;
  }
  auto* window = DynamicTo<LocalDOMWindow>(execution_context);
  if (!window) {
    return g_empty_atom;
  }

  if (name_ == preference_names::kColorScheme) {
    return ColorSchemeToString(preferred_color_scheme_);
  } else if (name_ == preference_names::kContrast) {
    return ContrastToString(preferred_contrast_);
  } else if (name_ == preference_names::kReducedMotion) {
    return prefers_reduced_motion_ ? preference_values::kReduce
                                   : preference_values::kNoPreference;
  } else if (name_ == preference_names::kReducedTransparency) {
    return prefers_reduced_transparency_ ? preference_values::kReduce
                                         : preference_values::kNoPreference;
  } else if (name_ == preference_names::kReducedData) {
    return prefers_reduced_data_ ? preference_values::kReduce
                                 : preference_values::kNoPreference;
  } else {
    NOTREACHED();
  }
}

void PreferenceObject::clearOverride(ScriptState* script_state) {
  CHECK(RuntimeEnabledFeatures::WebPreferencesEnabled());
  if (!script_state || !script_state->ContextIsValid()) {
    return;
  }
  auto* execution_context = ExecutionContext::From(script_state);
  if (!execution_context || execution_context->IsContextDestroyed()) {
    return;
  }
  auto* window = DynamicTo<LocalDOMWindow>(execution_context);
  if (!window) {
    return;
  }

  const PreferenceOverrides* overrides =
      window->GetFrame()->GetPage()->GetPreferenceOverrides();

  if (!overrides) {
    return;
  }

  bool value_unchanged;
  if (name_ == preference_names::kColorScheme) {
    std::optional<mojom::blink::PreferredColorScheme> color_scheme =
        overrides->GetPreferredColorScheme();
    if (!color_scheme.has_value()) {
      return;
    }

    window->GetFrame()->GetPage()->SetPreferenceOverride(
        media_feature_names::kPrefersColorSchemeMediaFeature, String());
    value_unchanged =
        (color_scheme.value() == media_values_->GetPreferredColorScheme());
  } else if (name_ == preference_names::kContrast) {
    std::optional<mojom::blink::PreferredContrast> contrast =
        overrides->GetPreferredContrast();
    if (!contrast.has_value()) {
      return;
    }

    window->GetFrame()->GetPage()->SetPreferenceOverride(
        media_feature_names::kPrefersContrastMediaFeature, String());
    value_unchanged =
        (contrast.value() == media_values_->GetPreferredContrast());
  } else if (name_ == preference_names::kReducedMotion) {
    std::optional<bool> reduced_motion = overrides->GetPrefersReducedMotion();
    if (!reduced_motion.has_value()) {
      return;
    }

    window->GetFrame()->GetPage()->SetPreferenceOverride(
        media_feature_names::kPrefersReducedMotionMediaFeature, String());
    value_unchanged =
        (reduced_motion.value() == media_values_->PrefersReducedMotion());
  } else if (name_ == preference_names::kReducedTransparency) {
    std::optional<bool> reduced_transparency =
        overrides->GetPrefersReducedTransparency();
    if (!reduced_transparency.has_value()) {
      return;
    }

    window->GetFrame()->GetPage()->SetPreferenceOverride(
        media_feature_names::kPrefersReducedTransparencyMediaFeature, String());
    value_unchanged = (reduced_transparency.value() ==
                       media_values_->PrefersReducedTransparency());
  } else if (name_ == preference_names::kReducedData) {
    std::optional<bool> reduced_data = overrides->GetPrefersReducedData();
    if (!reduced_data.has_value()) {
      return;
    }

    window->GetFrame()->GetPage()->SetPreferenceOverride(
        media_feature_names::kPrefersReducedDataMediaFeature, String());
    value_unchanged =
        (reduced_data.value() == media_values_->PrefersReducedData());
  } else {
    NOTREACHED();
  }
  if (value_unchanged) {
    DispatchEvent(*Event::Create(event_type_names::kChange));
  }
}

ScriptPromise<IDLUndefined> PreferenceObject::requestOverride(
    ScriptState* script_state,
    std::optional<AtomicString> value) {
  CHECK(RuntimeEnabledFeatures::WebPreferencesEnabled());
  if (!script_state || !script_state->ContextIsValid()) {
    return EmptyPromise();
  }
  auto* execution_context = ExecutionContext::From(script_state);
  if (!execution_context || execution_context->IsContextDestroyed()) {
    return EmptyPromise();
  }
  auto* window = DynamicTo<LocalDOMWindow>(execution_context);
  if (!window) {
    return EmptyPromise();
  }

  if (!value.has_value() || value.value().empty()) {
    clearOverride(script_state);
    return ToResolvedUndefinedPromise(script_state);
  }

  AtomicString feature_name;
  AtomicString new_value;
  bool has_existing_override = false;
  bool value_same_as_existing_override = false;

  AtomicString existing_value;

  if (validValues().AsVector().Contains(value.value())) {
    new_value = value.value();
  }

  const PreferenceOverrides* overrides =
      window->GetFrame()->GetPage()->GetPreferenceOverrides();
  if (name_ == preference_names::kColorScheme) {
    feature_name = media_feature_names::kPrefersColorSchemeMediaFeature;

    if (overrides) {
      auto override = overrides->GetPreferredColorScheme();
      if (override.has_value()) {
        has_existing_override = true;
        if (new_value == ColorSchemeToString(override.value()).GetString()) {
          value_same_as_existing_override = true;
        }
      }
    }
    existing_value = ColorSchemeToString(preferred_color_scheme_);
  } else if (name_ == preference_names::kContrast) {
    feature_name = media_feature_names::kPrefersContrastMediaFeature;

    if (overrides) {
      auto override = overrides->GetPreferredContrast();
      if (override.has_value()) {
        has_existing_override = true;
        if (new_value == ContrastToString(override.value()).GetString()) {
          value_same_as_existing_override = true;
        }
      }
    }
    existing_value = ContrastToString(preferred_contrast_);
  } else if (name_ == preference_names::kReducedMotion) {
    feature_name = media_feature_names::kPrefersReducedMotionMediaFeature;

    if (overrides) {
      auto override = overrides->GetPrefersReducedMotion();
      if (override.has_value()) {
        has_existing_override = true;
        if ((new_value == preference_values::kReduce && override.value()) ||
            (new_value == preference_values::kNoPreference &&
             !override.value())) {
          value_same_as_existing_override = true;
        }
      }
    }
    existing_value = prefers_reduced_motion_ ? preference_values::kReduce
                                             : preference_values::kNoPreference;
  } else if (name_ == preference_names::kReducedTransparency) {
    feature_name = media_feature_names::kPrefersReducedTransparencyMediaFeature;

    if (overrides) {
      auto override = overrides->GetPrefersReducedTransparency();
      if (override.has_value()) {
        has_existing_override = true;
        if ((new_value == preference_values::kReduce && override.value()) ||
            (new_value == preference_values::kNoPreference &&
             !override.value())) {
          value_same_as_existing_override = true;
        }
      }
    }
    existing_value = prefers_reduced_transparency_
                         ? preference_values::kReduce
                         : preference_values::kNoPreference;
  } else if (name_ == preference_names::kReducedData) {
    feature_name = media_feature_names::kPrefersReducedDataMediaFeature;

    if (overrides) {
      auto override = overrides->GetPrefersReducedData();
      if (override.has_value()) {
        has_existing_override = true;
        if ((new_value == preference_values::kReduce && override.value()) ||
            (new_value == preference_values::kNoPreference &&
             !override.value())) {
          value_same_as_existing_override = true;
        }
      }
    }
    existing_value = prefers_reduced_data_ ? preference_values::kReduce
                                           : preference_values::kNoPreference;
  } else {
    NOTREACHED();
  }

  if (new_value.empty()) {
    return ScriptPromise<IDLUndefined>::RejectWithDOMException(
        script_state, MakeGarbageCollected<DOMException>(
                          DOMExceptionCode::kTypeMismatchError,
                          value.value() + " is not a valid value."));
  }

  if (!value_same_as_existing_override) {
    window->GetFrame()->GetPage()->SetPreferenceOverride(feature_name,
                                                         new_value.GetString());
  }

  if (!has_existing_override && new_value == existing_value) {
    DispatchEvent(*Event::Create(event_type_names::kChange));
  }

  return ToResolvedUndefinedPromise(script_state);
}

const FrozenArray<IDLString>& PreferenceObject::validValues() {
  CHECK(RuntimeEnabledFeatures::WebPreferencesEnabled());
  if (valid_values_) [[likely]] {
    return *valid_values_.Get();
  }

  FrozenArray<IDLString>::VectorType valid_values;
  if (name_ == preference_names::kColorScheme) {
    valid_values.push_back(preference_values::kLight);
    valid_values.push_back(preference_values::kDark);
  } else if (name_ == preference_names::kContrast) {
    valid_values.push_back(preference_values::kMore);
    valid_values.push_back(preference_values::kLess);
    valid_values.push_back(preference_values::kNoPreference);
  } else if (name_ == preference_names::kReducedMotion) {
    valid_values.push_back(preference_values::kReduce);
    valid_values.push_back(preference_values::kNoPreference);
  } else if (name_ == preference_names::kReducedTransparency) {
    valid_values.push_back(preference_values::kReduce);
    valid_values.push_back(preference_values::kNoPreference);
  } else if (name_ == preference_names::kReducedData) {
    valid_values.push_back(preference_values::kReduce);
    valid_values.push_back(preference_values::kNoPreference);
  } else {
    NOTREACHED();
  }
  valid_values_ =
      MakeGarbageCollected<FrozenArray<IDLString>>(std::move(valid_values));
  return *valid_values_.Get();
}

void PreferenceObject::PreferenceMaybeChanged() {
  CHECK(RuntimeEnabledFeatures::WebPreferencesEnabled());
  if (!GetExecutionContext() || GetExecutionContext()->IsContextDestroyed()) {
    return;
  }
  auto* window = DynamicTo<LocalDOMWindow>(GetExecutionContext());
  if (!window) {
    return;
  }

  if (name_ == preference_names::kColorScheme) {
    if (preferred_color_scheme_ == media_values_->GetPreferredColorScheme()) {
      return;
    }
  } else if (name_ == preference_names::kContrast) {
    if (preferred_contrast_ == media_values_->GetPreferredContrast()) {
      return;
    }
  } else if (name_ == preference_names::kReducedMotion) {
    if (prefers_reduced_motion_ == media_values_->PrefersReducedMotion()) {
      return;
    }
  } else if (name_ == preference_names::kReducedTransparency) {
    if (prefers_reduced_transparency_ ==
        media_values_->PrefersReducedTransparency()) {
      return;
    }
  } else if (name_ == preference_names::kReducedData) {
    if (prefers_reduced_data_ == media_values_->PrefersReducedData()) {
      return;
    }
  } else {
    NOTREACHED();
  }
  preferred_color_scheme_ = media_values_->GetPreferredColorScheme();
  preferred_contrast_ = media_values_->GetPreferredContrast();
  prefers_reduced_data_ = media_values_->PrefersReducedData();
  prefers_reduced_motion_ = media_values_->PrefersReducedMotion();
  prefers_reduced_transparency_ = media_values_->PrefersReducedTransparency();
  DispatchEvent(*Event::Create(event_type_names::kChange));
}

void PreferenceObject::Trace(Visitor* visitor) const {
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
  visitor->Trace(valid_values_);
  visitor->Trace(media_values_);
}

const AtomicString& PreferenceObject::InterfaceName() const {
  return event_target_names::kPreferenceObject;
}

void PreferenceObject::ContextDestroyed() {
  RemoveAllEventListeners();
}

ExecutionContext* PreferenceObject::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

}  // namespace blink

"""

```
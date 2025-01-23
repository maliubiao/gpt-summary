Response:
Let's break down the thought process for analyzing the `origin_trial_context.cc` file.

1. **Understand the Core Purpose:** The file name and the `#include` directives immediately give a strong hint:  `origin_trials`. This points to a system for experimenting with new web platform features in a controlled manner. The `context` part suggests managing the state and validation of these trials within a specific execution environment.

2. **Identify Key Data Structures:** Scan the class definition (`OriginTrialContext`) and its members. Notable ones include:
    * `trial_token_validator_`:  Clearly related to verifying the authenticity and validity of trial tokens.
    * `trial_results_`:  Likely stores the outcomes of processing different trial tokens.
    * `enabled_features_`: Keeps track of which origin trial features are active.
    * `navigation_activated_features_`:  Specifically for features activated during navigation.
    * `feature_expiry_times_`: Stores the expiration dates of enabled features.
    * `feature_to_tokens_`: Maps enabled features back to the tokens that activated them.

3. **Analyze Key Methods:**  Focus on the public or important-looking methods. Group them by their likely function:
    * **Token Handling:** `AddToken`, `AddTokens`, `ParseHeaderValue`, `ExtractTokenOrQuotedString`, `EnableTrialFromToken`. These are central to processing and validating the trial tokens themselves.
    * **Feature Activation:** `ActivateWorkerInheritedFeatures`, `ActivateNavigationFeaturesFromInitiator`, `InitializePendingFeatures`, `InstallFeatures`, `InstallSettingFeature`, `AddFeature`, `EnableTrialFromName`. These methods deal with enabling the actual experimental features based on valid tokens.
    * **Feature Querying:** `IsFeatureEnabled`, `GetFeatureExpiry`, `IsNavigationFeatureActivated`, `GetTokens`, `GetInheritedTrialFeatures`, `GetEnabledNavigationFeatures`. These allow checking the current status of origin trials.
    * **Context and Origin:** `GetSecurityOrigin`, `IsSecureContext`, `GetCurrentOriginInfo`. These manage the security context in which the trials operate.
    * **Force Enabling:** `AddForceEnabledTrials`, `CanEnableTrialFromName`. These handle cases where trials are explicitly enabled, bypassing token validation.
    * **Browser Communication:** `SendTokenToBrowser`. This suggests interaction with the browser process.

4. **Trace the Flow of a Token:** Imagine a website providing an origin trial token. How does it get processed?
    * A header or `<meta>` tag contains the token.
    * `ParseHeaderValue` extracts the token string.
    * `AddTokens` (or `AddToken`) is called.
    * `EnableTrialFromToken` validates the token using `TrialTokenValidator`. This involves checking the signature, expiration, origin, and feature name.
    * If valid, the corresponding feature is added to `enabled_features_`.
    * `InitializePendingFeatures` and `InstallFeatures` then apply the feature, potentially affecting JavaScript APIs or browser behavior.

5. **Consider Relationships with Web Technologies (JavaScript, HTML, CSS):**  Think about how origin trials *manifest* on the web page:
    * **HTML:** The `<meta>` tag is the primary mechanism for delivering tokens.
    * **JavaScript:**  Origin trials often expose new JavaScript APIs or modify existing ones. The code needs to connect the enabling of a feature to the availability of these APIs.
    * **CSS:**  Some origin trials might introduce new CSS properties or behaviors. The code might influence how the rendering engine interprets CSS.

6. **Look for Logic and Conditional Behavior:**  Identify `if` statements and other control flow that governs how trials are enabled. Pay attention to checks for feature flags (`base::FeatureList::IsEnabled`), secure contexts, and OS-specific behavior.

7. **Consider Potential Errors:** Think about what could go wrong:
    * Invalid or expired tokens.
    * Tokens for the wrong origin.
    * Enabling trials that conflict with existing features or browser settings.
    * Misusing the origin trial system by developers.

8. **Formulate Examples:**  Based on the above analysis, create concrete examples demonstrating the interactions with JavaScript, HTML, and CSS. Think about specific APIs that might be gated by origin trials.

9. **Address Logical Reasoning and Assumptions:** For scenarios involving conditional behavior (e.g., `CanEnableTrialFromName`), construct hypothetical inputs (trial names, feature flag states) and predict the outputs (whether the trial can be enabled).

10. **Review and Refine:**  Read through the generated description, ensuring it's accurate, well-organized, and addresses all aspects of the prompt. Check for clarity and completeness. For instance, initially, I might have missed the nuance of `navigation_activated_features_`, but a closer look at its usage and the associated methods would clarify its purpose. Similarly, the interaction with the browser process via `SendTokenToBrowser` might require a second pass to fully understand.

This iterative process of examining the code, understanding its purpose, tracing execution flow, and considering interactions with other web technologies helps to build a comprehensive understanding of the `origin_trial_context.cc` file.
这个文件 `blink/renderer/core/origin_trials/origin_trial_context.cc` 在 Chromium Blink 引擎中扮演着核心角色，它负责管理和处理 **Origin Trials**（也称为 Feature Trials）。Origin Trials 是一种机制，允许开发者在真实的用户环境中测试实验性的 Web 平台功能。

以下是该文件的主要功能：

**1. Origin Trial 令牌（Token）的管理和验证:**

* **解析 HTTP 头部:**  `ParseHeaderValue` 函数负责解析 `Origin-Trial` HTTP 头部，提取其中包含的 Origin Trial 令牌。
* **提取令牌:** `ExtractTokenOrQuotedString` 函数用于从 HTTP 头部值中提取带引号或不带引号的令牌字符串。
* **添加令牌:** `AddTokensFromHeader` 和 `AddTokens` 函数将从 HTTP 头部或 JavaScript 中获取的令牌添加到当前的执行上下文中。
* **验证令牌:**  `EnableTrialFromToken` 函数使用 `TrialTokenValidator` 来验证令牌的有效性，包括签名、过期时间、来源等。
* **缓存令牌状态:** `CacheToken` 函数存储每个令牌的验证结果和相关的试验名称，以便后续查询。

**2. Origin Trial 功能的激活和管理:**

* **存储已启用的功能:** `enabled_features_` 成员变量存储当前上下文中已启用的 Origin Trial 功能。
* **存储跨导航激活的功能:** `navigation_activated_features_` 成员变量存储在导航过程中激活的 Origin Trial 功能。
* **激活继承的功能:** `ActivateWorkerInheritedFeatures` 函数用于在 Worker 或 Worklet 中激活从主线程继承的 Origin Trial 功能。
* **激活导航功能:** `ActivateNavigationFeaturesFromInitiator` 函数用于激活在导航过程中由发起者传递的 Origin Trial 功能。
* **安装功能:** `InitializePendingFeatures` 和 `InstallFeatures` 函数负责在 JavaScript 环境中安装已启用的 Origin Trial 功能，例如，注册新的 JavaScript API 或修改现有 API 的行为。
* **安装设置功能:** `InstallSettingFeature` 函数处理需要通过 `Settings` 对象启用的特定 Origin Trial 功能。
* **强制启用试验:** `AddForceEnabledTrials` 函数允许通过命令行或配置强制启用指定的 Origin Trial。
* **检查功能是否已启用:** `IsFeatureEnabled` 函数检查指定的 Origin Trial 功能是否已在当前上下文中启用。
* **获取功能过期时间:** `GetFeatureExpiry` 函数返回指定 Origin Trial 功能的过期时间。
* **判断导航功能是否激活:** `IsNavigationFeatureActivated` 函数判断指定的 Origin Trial 功能是否在导航过程中被激活。

**3. 与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML `<meta>` 标签:**  网站可以通过在 HTML 文档的 `<head>` 中添加 `<meta>` 标签来提供 Origin Trial 令牌。例如：
  ```html
  <meta http-equiv="Origin-Trial" content="TOKEN_STRING_HERE">
  ```
  `OriginTrialContext` 会解析这个头部信息，提取 `TOKEN_STRING_HERE` 并进行验证。如果验证通过，与该令牌关联的实验性功能可能会被激活，从而影响页面中 JavaScript 或 CSS 的行为。

* **JavaScript API:**  Origin Trials 的目标是测试新的 Web 平台功能，这些功能通常会通过新的 JavaScript API 暴露给开发者。`InstallPropertiesPerFeature` (代码中未直接展示，但逻辑存在于 `InstallFeatures`) 等函数会在 JavaScript 环境中注册这些新的 API。例如，如果某个 Origin Trial 旨在测试一个新的 `navigator.mediaDevices` 的方法，那么当该 Origin Trial 被成功激活后，这个新的方法才能在 JavaScript 中使用。

  **假设输入与输出 (JavaScript):**
  * **假设输入:** 网站提供了一个有效的 Origin Trial 令牌，用于启用一个名为 `NewAwesomeAPI` 的实验性 API，该 API 在 `window` 对象上添加了一个新的方法 `window.newAwesomeFunction()`.
  * **输出:** 在 Origin Trial 被成功激活后，JavaScript 代码可以调用 `window.newAwesomeFunction()` 而不会报错。如果 Origin Trial 未激活或令牌无效，调用该方法将会导致 `TypeError`。

* **CSS 功能:**  Origin Trials 也可能涉及新的 CSS 功能。虽然该文件主要关注 JavaScript 相关的逻辑，但 Origin Trials 的激活也会影响 Blink 的渲染引擎对 CSS 的解释。例如，一个新的 CSS 属性可能只有在对应的 Origin Trial 激活后才能生效。

  **假设输入与输出 (CSS):**
  * **假设输入:** 网站提供了一个有效的 Origin Trial 令牌，用于启用一个名为 `cssCustomHighlightAPI` 的实验性 CSS 功能。
  * **输出:** 在 Origin Trial 被成功激活后，开发者可以在 CSS 中使用相关的伪元素或属性（例如 `::highlight(search-result)`)，并且浏览器会按照实验性的规范进行渲染。如果 Origin Trial 未激活，浏览器可能会忽略这些新的 CSS 规则。

**4. 逻辑推理 (假设输入与输出):**

* **假设输入 (HTTP 头部):** 服务器发送以下 HTTP 响应头：
  ```
  Origin-Trial: validToken1, invalidToken2,   validToken3
  ```
* **输出:**
    * `ParseHeaderValue` 会提取出三个字符串: `"validToken1"`, `"invalidToken2"`, `"validToken3"`。
    * `AddTokensFromHeader` 会将这三个字符串传递给 `AddTokens`。
    * `EnableTrialFromToken` 会分别验证这三个令牌。假设 `validToken1` 和 `validToken3` 是有效的，而 `invalidToken2` 是无效的（例如，签名错误或已过期）。
    * 只有与 `validToken1` 和 `validToken3` 关联的 Origin Trial 功能才会被激活。`invalidToken2` 会被忽略，并且可能在 `trial_results_` 中记录其失败状态。

**5. 用户或编程常见的使用错误:**

* **令牌错误或过期:**  开发者可能会使用错误的令牌字符串，或者使用了已经过期的令牌。这会导致 `EnableTrialFromToken` 返回失败状态，并且相关的实验性功能不会被激活。
* **来源不匹配:** Origin Trial 令牌通常与特定的来源（Origin）绑定。如果在与令牌绑定的来源不同的页面上使用该令牌，验证将会失败。
* **功能依赖错误:** 某些 Origin Trial 功能可能依赖于其他功能或浏览器设置。如果这些依赖项不满足，即使令牌有效，功能也可能无法完全生效。
* **在不支持的浏览器中使用:**  Origin Trials 是针对特定 Chromium 版本的功能。如果在不支持 Origin Trials 或不支持特定 Trial 的浏览器中使用，令牌会被忽略。
* **开发者混淆测试环境和生产环境:**  开发者可能会在生产环境中使用用于测试的 Origin Trial 令牌，这可能会导致意外的行为，因为实验性功能可能不稳定或存在已知问题。
* **忘记移除 Origin Trial 令牌:** 在 Origin Trial 结束后，开发者需要从网站的 HTML 或 HTTP 头部中移除相关的 `<meta>` 标签或 HTTP 头部，否则可能会继续启用不再需要的功能。

总而言之，`origin_trial_context.cc` 是 Blink 引擎中负责管理 Origin Trials 的关键组件，它处理令牌的解析、验证和实验性功能的激活，从而允许开发者在受控的环境中测试新的 Web 平台特性。它与 HTML（通过 `<meta>` 标签）、JavaScript（通过暴露新的 API）以及 CSS（通过激活新的 CSS 功能）都有着密切的联系。

### 提示词
```
这是目录为blink/renderer/core/origin_trials/origin_trial_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"

#include <ostream>
#include <vector>

#include "base/feature_list.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "components/attribution_reporting/features.h"
#include "services/network/public/cpp/features.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/features_generated.h"
#include "third_party/blink/public/common/origin_trials/origin_trials.h"
#include "third_party/blink/public/common/origin_trials/trial_token.h"
#include "third_party/blink/public/common/origin_trials/trial_token_result.h"
#include "third_party/blink/public/common/origin_trials/trial_token_validator.h"
#include "third_party/blink/public/mojom/origin_trials/origin_trial_feature.mojom-shared.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/window_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/workers/worklet_global_scope.h"
#include "third_party/blink/renderer/platform/bindings/origin_trial_features.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/runtime_feature_state/runtime_feature_state_override_context.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

constexpr char kDefaultTrialName[] = "UNKNOWN";

bool IsWhitespace(UChar chr) {
  return (chr == ' ') || (chr == '\t');
}

bool SkipWhiteSpace(const String& str, unsigned& pos) {
  unsigned len = str.length();
  while (pos < len && IsWhitespace(str[pos]))
    ++pos;
  return pos < len;
}

// Extracts a quoted or unquoted token from an HTTP header. If the token was a
// quoted string, this also removes the quotes and unescapes any escaped
// characters. Also skips all whitespace before and after the token.
String ExtractTokenOrQuotedString(const String& header_value, unsigned& pos) {
  unsigned len = header_value.length();
  String result;
  if (!SkipWhiteSpace(header_value, pos))
    return String();

  if (header_value[pos] == '\'' || header_value[pos] == '"') {
    StringBuilder out;
    // Quoted string, append characters until matching quote is found,
    // unescaping as we go.
    UChar quote = header_value[pos++];
    while (pos < len && header_value[pos] != quote) {
      if (header_value[pos] == '\\')
        pos++;
      if (pos < len)
        out.Append(header_value[pos++]);
    }
    if (pos < len)
      pos++;
    result = out.ToString();
  } else {
    // Unquoted token. Consume all characters until whitespace or comma.
    int start_pos = pos;
    while (pos < len && !IsWhitespace(header_value[pos]) &&
           header_value[pos] != ',')
      pos++;
    result = header_value.Substring(start_pos, pos - start_pos);
  }
  SkipWhiteSpace(header_value, pos);
  return result;
}

// Returns whether the given feature can be activated across navigations. Only
// features reviewed and approved by security reviewers can be activated across
// navigations.
bool IsCrossNavigationFeature(mojom::blink::OriginTrialFeature feature) {
  return origin_trials::FeatureEnabledForNavigation(feature);
}

std::ostream& operator<<(std::ostream& stream, OriginTrialTokenStatus status) {
// Included for debug builds only for reduced binary size.
#ifndef NDEBUG
  switch (status) {
    case OriginTrialTokenStatus::kSuccess:
      return stream << "kSuccess";
    case OriginTrialTokenStatus::kNotSupported:
      return stream << "kNotSupported";
    case OriginTrialTokenStatus::kInsecure:
      return stream << "kInsecure";
    case OriginTrialTokenStatus::kExpired:
      return stream << "kExpired";
    case OriginTrialTokenStatus::kWrongOrigin:
      return stream << "kWrongOrigin";
    case OriginTrialTokenStatus::kInvalidSignature:
      return stream << "kInvalidSignature";
    case OriginTrialTokenStatus::kMalformed:
      return stream << "kMalformed";
    case OriginTrialTokenStatus::kWrongVersion:
      return stream << "kWrongVersion";
    case OriginTrialTokenStatus::kFeatureDisabled:
      return stream << "kFeatureDisabled";
    case OriginTrialTokenStatus::kTokenDisabled:
      return stream << "kTokenDisabled";
    case OriginTrialTokenStatus::kFeatureDisabledForUser:
      return stream << "kFeatureDisabledForUser";
    case OriginTrialTokenStatus::kUnknownTrial:
      return stream << "kUnknownTrial";
  }
  NOTREACHED();
#else
  return stream << (static_cast<int>(status));
#endif  // ifndef NDEBUG
}

// Merges `OriginTrialStatus` from different tokens for the same trial.
// Some combinations of status should never occur, such as
// s1 == kOSNotSupported && s2 == kEnabled.
OriginTrialStatus MergeOriginTrialStatus(OriginTrialStatus s1,
                                         OriginTrialStatus s2) {
  using Status = OriginTrialStatus;
  if (s1 == Status::kEnabled || s2 == Status::kEnabled) {
    return Status::kEnabled;
  }

  // kOSNotSupported status comes from OS support checks that are generated
  // at compile time.
  if (s1 == Status::kOSNotSupported || s2 == Status::kOSNotSupported) {
    return Status::kOSNotSupported;
  }

  // kTrialNotAllowed status comes from `CanEnableTrialFromName` check.
  if (s1 == Status::kTrialNotAllowed || s2 == Status::kTrialNotAllowed) {
    return Status::kTrialNotAllowed;
  }

  return Status::kValidTokenNotProvided;
}

}  // namespace

// TODO(crbug.com/607555): Mark `TrialToken` as copyable.
OriginTrialTokenResult::OriginTrialTokenResult(
    const String& raw_token,
    OriginTrialTokenStatus status,
    const std::optional<TrialToken>& parsed_token)
    : raw_token(raw_token), status(status), parsed_token(parsed_token) {}

OriginTrialContext::OriginTrialContext(ExecutionContext* context)
    : trial_token_validator_(std::make_unique<TrialTokenValidator>()),
      context_(context) {}

void OriginTrialContext::SetTrialTokenValidatorForTesting(
    std::unique_ptr<TrialTokenValidator> validator) {
  trial_token_validator_ = std::move(validator);
}

// static
std::unique_ptr<Vector<String>> OriginTrialContext::ParseHeaderValue(
    const String& header_value) {
  std::unique_ptr<Vector<String>> tokens(new Vector<String>);
  unsigned pos = 0;
  unsigned len = header_value.length();
  while (pos < len) {
    String token = ExtractTokenOrQuotedString(header_value, pos);
    if (!token.empty())
      tokens->push_back(token);
    // Make sure tokens are comma-separated.
    if (pos < len && header_value[pos++] != ',')
      return nullptr;
  }
  return tokens;
}

// static
void OriginTrialContext::AddTokensFromHeader(ExecutionContext* context,
                                             const String& header_value) {
  if (header_value.empty())
    return;
  std::unique_ptr<Vector<String>> tokens(ParseHeaderValue(header_value));
  if (!tokens)
    return;
  AddTokens(context, tokens.get());
}

// static
void OriginTrialContext::AddTokens(ExecutionContext* context,
                                   const Vector<String>* tokens) {
  if (!tokens || tokens->empty())
    return;
  DCHECK(context && context->GetOriginTrialContext());
  context->GetOriginTrialContext()->AddTokens(*tokens);
}

// static
void OriginTrialContext::ActivateWorkerInheritedFeatures(
    ExecutionContext* context,
    const Vector<mojom::blink::OriginTrialFeature>* features) {
  if (!features || features->empty())
    return;
  DCHECK(context && context->GetOriginTrialContext());
  DCHECK(context->IsDedicatedWorkerGlobalScope() ||
         context->IsWorkletGlobalScope());
  context->GetOriginTrialContext()->ActivateWorkerInheritedFeatures(*features);
}

// static
void OriginTrialContext::ActivateNavigationFeaturesFromInitiator(
    ExecutionContext* context,
    const Vector<mojom::blink::OriginTrialFeature>* features) {
  if (!features || features->empty())
    return;
  DCHECK(context && context->GetOriginTrialContext());
  context->GetOriginTrialContext()->ActivateNavigationFeaturesFromInitiator(
      *features);
}

// static
std::unique_ptr<Vector<String>> OriginTrialContext::GetTokens(
    ExecutionContext* execution_context) {
  DCHECK(execution_context);
  const OriginTrialContext* context =
      execution_context->GetOriginTrialContext();
  if (!context || context->trial_results_.empty())
    return nullptr;

  auto tokens = std::make_unique<Vector<String>>();
  for (const auto& entry : context->trial_results_) {
    const OriginTrialResult& trial_result = entry.value;
    for (const OriginTrialTokenResult& token_result :
         trial_result.token_results) {
      tokens->push_back(token_result.raw_token);
    }
  }
  return tokens;
}

// static
std::unique_ptr<Vector<mojom::blink::OriginTrialFeature>>
OriginTrialContext::GetInheritedTrialFeatures(
    ExecutionContext* execution_context) {
  DCHECK(execution_context);
  const OriginTrialContext* context =
      execution_context->GetOriginTrialContext();
  return context ? context->GetInheritedTrialFeatures() : nullptr;
}

// static
std::unique_ptr<Vector<mojom::blink::OriginTrialFeature>>
OriginTrialContext::GetEnabledNavigationFeatures(
    ExecutionContext* execution_context) {
  DCHECK(execution_context);
  const OriginTrialContext* context =
      execution_context->GetOriginTrialContext();
  return context ? context->GetEnabledNavigationFeatures() : nullptr;
}

std::unique_ptr<Vector<mojom::blink::OriginTrialFeature>>
OriginTrialContext::GetInheritedTrialFeatures() const {
  if (enabled_features_.empty()) {
    return nullptr;
  }
  std::unique_ptr<Vector<mojom::blink::OriginTrialFeature>> result =
      std::make_unique<Vector<mojom::blink::OriginTrialFeature>>();
  // TODO(crbug.com/1083407): Handle features from
  // |navigation_activated_features_| and |feature_expiry_times_| expiry.
  for (const mojom::blink::OriginTrialFeature& feature : enabled_features_) {
    result->push_back(feature);
  }
  return result;
}

std::unique_ptr<Vector<mojom::blink::OriginTrialFeature>>
OriginTrialContext::GetEnabledNavigationFeatures() const {
  if (enabled_features_.empty())
    return nullptr;
  std::unique_ptr<Vector<mojom::blink::OriginTrialFeature>> result =
      std::make_unique<Vector<mojom::blink::OriginTrialFeature>>();
  for (const mojom::blink::OriginTrialFeature& feature : enabled_features_) {
    if (IsCrossNavigationFeature(feature)) {
      result->push_back(feature);
    }
  }
  return result->empty() ? nullptr : std::move(result);
}

void OriginTrialContext::AddToken(const String& token) {
  AddTokenInternal(token, GetCurrentOriginInfo(), nullptr);
}

void OriginTrialContext::AddTokenFromExternalScript(
    const String& token,
    const Vector<scoped_refptr<SecurityOrigin>>& external_origins) {
  Vector<OriginInfo> script_origins;
  for (const scoped_refptr<SecurityOrigin>& origin : external_origins) {
    OriginInfo origin_info = {.origin = origin,
                              .is_secure = origin->IsPotentiallyTrustworthy()};
    DVLOG(1) << "AddTokenFromExternalScript: " << origin->ToString()
             << ", secure = " << origin_info.is_secure;
    script_origins.push_back(origin_info);
  }
  AddTokenInternal(token, GetCurrentOriginInfo(), &script_origins);
}

void OriginTrialContext::AddTokenInternal(
    const String& token,
    const OriginInfo origin,
    const Vector<OriginInfo>* script_origins) {
  if (token.empty())
    return;

  bool enabled = EnableTrialFromToken(token, origin, script_origins);
  if (enabled) {
    // Only install pending features if the provided token is valid.
    // Otherwise, there was no change to the list of enabled features.
    InitializePendingFeatures();
  }
}

void OriginTrialContext::AddTokens(const Vector<String>& tokens) {
  if (tokens.empty())
    return;
  bool found_valid = false;
  OriginInfo origin_info = GetCurrentOriginInfo();
  for (const String& token : tokens) {
    if (!token.empty()) {
      if (EnableTrialFromToken(token, origin_info))
        found_valid = true;
    }
  }
  if (found_valid) {
    // Only install pending features if at least one of the provided tokens are
    // valid. Otherwise, there was no change to the list of enabled features.
    InitializePendingFeatures();
  }
}

void OriginTrialContext::ActivateWorkerInheritedFeatures(
    const Vector<mojom::blink::OriginTrialFeature>& features) {
  for (const mojom::blink::OriginTrialFeature& feature : features) {
    enabled_features_.insert(feature);
  }
  InitializePendingFeatures();
}

void OriginTrialContext::ActivateNavigationFeaturesFromInitiator(
    const Vector<mojom::blink::OriginTrialFeature>& features) {
  for (const mojom::blink::OriginTrialFeature& feature : features) {
    if (IsCrossNavigationFeature(feature)) {
      navigation_activated_features_.insert(feature);
    }
  }
  InitializePendingFeatures();
}

void OriginTrialContext::InitializePendingFeatures() {
  if (!enabled_features_.size() && !navigation_activated_features_.size())
    return;
  auto* window = DynamicTo<LocalDOMWindow>(context_.Get());
  // Normally, LocalDOMWindow::document() doesn't need to be null-checked.
  // However, this is a rare function that can get called between when the
  // LocalDOMWindow is constructed and the Document is installed. We are not
  // ready for script in that case, so bail out.
  if (!window || !window->document())
    return;
  ScriptState* script_state = ToScriptStateForMainWorld(window->GetFrame());
  if (!script_state)
    return;
  if (!script_state->ContextIsValid())
    return;
  ScriptState::Scope scope(script_state);

  bool added_binding_feature =
      InstallFeatures(enabled_features_, *window->document(), script_state);
  added_binding_feature |= InstallFeatures(navigation_activated_features_,
                                           *window->document(), script_state);

  if (added_binding_feature) {
    // Also allow V8 to install conditional features now.
    script_state->GetIsolate()->InstallConditionalFeatures(
        script_state->GetContext());
  }
}

bool OriginTrialContext::InstallFeatures(
    const HashSet<mojom::blink::OriginTrialFeature>& features,
    Document& document,
    ScriptState* script_state) {
  bool added_binding_features = false;
  for (mojom::blink::OriginTrialFeature enabled_feature : features) {
    // TODO(https://crbug.com/40243430): add support for workers/non-frames that
    // are enabling origin trials to send their information to the browser too.
    if (context_->IsWindow() && feature_to_tokens_.Contains(enabled_feature)) {
      // Note that, as we support third-party origin trials, the tokens must be
      // sent anytime there is an update. We cannot depend on sending once as
      // not all tokens activate the feature for the same scope.
      context_->GetRuntimeFeatureStateOverrideContext()
          ->ApplyOriginTrialOverride(
              enabled_feature, feature_to_tokens_.find(enabled_feature)->value);
    }

    if (installed_features_.Contains(enabled_feature))
      continue;

    installed_features_.insert(enabled_feature);

    if (InstallSettingFeature(document, enabled_feature))
      continue;

    InstallPropertiesPerFeature(script_state, enabled_feature);
    added_binding_features = true;
  }

  return added_binding_features;
}

bool OriginTrialContext::InstallSettingFeature(
    Document& document,
    mojom::blink::OriginTrialFeature enabled_feature) {
  switch (enabled_feature) {
    case mojom::blink::OriginTrialFeature::kAutoDarkMode:
      if (document.GetSettings())
        document.GetSettings()->SetForceDarkModeEnabled(true);
      return true;
    default:
      return false;
  }
}

void OriginTrialContext::AddFeature(mojom::blink::OriginTrialFeature feature) {
  enabled_features_.insert(feature);
  InitializePendingFeatures();
}

bool OriginTrialContext::IsFeatureEnabled(
    mojom::blink::OriginTrialFeature feature) const {
  return enabled_features_.Contains(feature) ||
         navigation_activated_features_.Contains(feature);
}

base::Time OriginTrialContext::GetFeatureExpiry(
    mojom::blink::OriginTrialFeature feature) {
  if (!IsFeatureEnabled(feature))
    return base::Time();

  auto it = feature_expiry_times_.find(feature);
  if (it == feature_expiry_times_.end())
    return base::Time();

  return it->value;
}

bool OriginTrialContext::IsNavigationFeatureActivated(
    mojom::blink::OriginTrialFeature feature) const {
  return navigation_activated_features_.Contains(feature);
}

void OriginTrialContext::AddForceEnabledTrials(
    const Vector<String>& trial_names) {
  bool is_valid = false;
  for (const auto& trial_name : trial_names) {
    DCHECK(origin_trials::IsTrialValid(trial_name.Utf8()));
    is_valid |=
        EnableTrialFromName(trial_name, /*expiry_time=*/base::Time::Max())
            .status == OriginTrialStatus::kEnabled;
  }

  if (is_valid) {
    // Only install pending features if at least one trial is valid. Otherwise
    // there was no change to the list of enabled features.
    InitializePendingFeatures();
  }
}

bool OriginTrialContext::CanEnableTrialFromName(const StringView& trial_name) {
  if (trial_name == "FledgeBiddingAndAuctionServer") {
    return base::FeatureList::IsEnabled(features::kInterestGroupStorage) &&
           base::FeatureList::IsEnabled(
               features::kFledgeBiddingAndAuctionServer);
  }

  if (trial_name == "FencedFrames")
    return base::FeatureList::IsEnabled(features::kFencedFrames);

  if (trial_name == "AdInterestGroupAPI")
    return base::FeatureList::IsEnabled(features::kInterestGroupStorage);

  if (trial_name == "TrustTokens")
    return base::FeatureList::IsEnabled(network::features::kFledgePst);

  if (trial_name == "SpeculationRulesPrefetchFuture") {
    return base::FeatureList::IsEnabled(
        features::kSpeculationRulesPrefetchFuture);
  }

  if (trial_name == "BackForwardCacheSendNotRestoredReasons") {
    return base::FeatureList::IsEnabled(
        features::kBackForwardCacheSendNotRestoredReasons);
  }

  if (trial_name == "CompressionDictionaryTransport") {
    return base::FeatureList::IsEnabled(
        network::features::kCompressionDictionaryTransportBackend);
  }

  if (trial_name == "SoftNavigationHeuristics") {
    return base::FeatureList::IsEnabled(features::kSoftNavigationDetection);
  }

  if (trial_name == "FoldableAPIs") {
    return base::FeatureList::IsEnabled(features::kViewportSegments);
  }

  if (trial_name == "PermissionElement") {
    return base::FeatureList::IsEnabled(blink::features::kPermissionElement);
  }

  // TODO(crbug.com/362675965): remove after origin trial.
  if (trial_name == "AISummarizationAPI") {
    return base::FeatureList::IsEnabled(features::kEnableAISummarizationAPI);
  }

  if (trial_name == "LanguageDetectionAPI") {
    return base::FeatureList::IsEnabled(features::kLanguageDetectionAPI);
  }

  if (trial_name == "AIPromptAPIForExtension") {
    return base::FeatureList::IsEnabled(
        features::kEnableAIPromptAPIForExtension);
  }

  if (trial_name == "TranslationAPI") {
#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_MAC) || BUILDFLAG(IS_LINUX)
    return base::FeatureList::IsEnabled(features::kEnableTranslationAPI);
#else
    return false;
#endif
  }

  return true;
}

OriginTrialFeaturesEnabled OriginTrialContext::EnableTrialFromName(
    const String& trial_name,
    base::Time expiry_time) {
  if (!CanEnableTrialFromName(trial_name)) {
    DVLOG(1) << "EnableTrialFromName: cannot enable trial " << trial_name;
    return {OriginTrialStatus::kTrialNotAllowed,
            Vector<mojom::blink::OriginTrialFeature>()};
  }

  bool did_enable_feature = false;
  Vector<mojom::blink::OriginTrialFeature> origin_trial_features;
  for (mojom::blink::OriginTrialFeature feature :
       origin_trials::FeaturesForTrial(trial_name.Utf8())) {
    if (!origin_trials::FeatureEnabledForOS(feature)) {
      DVLOG(1) << "EnableTrialFromName: feature " << static_cast<int>(feature)
               << " is disabled on current OS.";
      continue;
    }

    did_enable_feature = true;
    enabled_features_.insert(feature);
    origin_trial_features.push_back(feature);

    // Use the latest expiry time for the feature.
    if (GetFeatureExpiry(feature) < expiry_time)
      feature_expiry_times_.Set(feature, expiry_time);

    // Also enable any features implied by this feature.
    for (mojom::blink::OriginTrialFeature implied_feature :
         origin_trials::GetImpliedFeatures(feature)) {
      enabled_features_.insert(implied_feature);
      origin_trial_features.push_back(implied_feature);

      // Use the latest expiry time for the implied feature.
      if (GetFeatureExpiry(implied_feature) < expiry_time)
        feature_expiry_times_.Set(implied_feature, expiry_time);
    }
  }
  OriginTrialStatus status = did_enable_feature
                                 ? OriginTrialStatus::kEnabled
                                 : OriginTrialStatus::kOSNotSupported;
  return {status, std::move(origin_trial_features)};
}

bool OriginTrialContext::EnableTrialFromToken(const String& token,
                                              const OriginInfo origin_info) {
  return EnableTrialFromToken(token, origin_info, nullptr);
}

bool OriginTrialContext::EnableTrialFromToken(
    const String& token,
    const OriginInfo origin_info,
    const Vector<OriginInfo>* script_origins) {
  DCHECK(!token.empty());
  OriginTrialStatus trial_status = OriginTrialStatus::kValidTokenNotProvided;
  StringUTF8Adaptor token_string(token);
  // TODO(https://crbug.com/1153336): Remove explicit validator.
  // Since |blink::SecurityOrigin::IsPotentiallyTrustworthy| is the source of
  // security information in this context, use that explicitly, instead of
  // relying on the default in |TrialTokenValidator|
  Vector<TrialTokenValidator::OriginInfo> script_url_origins;
  if (script_origins) {
    for (const OriginInfo& script_origin_info : *script_origins) {
      script_url_origins.emplace_back(script_origin_info.origin->ToUrlOrigin(),
                                      script_origin_info.is_secure);
    }
  }

  TrialTokenResult token_result =
      trial_token_validator_->ValidateTokenAndTrialWithOriginInfo(
          token_string.AsStringView(),
          TrialTokenValidator::OriginInfo(origin_info.origin->ToUrlOrigin(),
                                          origin_info.is_secure),
          script_url_origins, base::Time::Now());
  DVLOG(1) << "EnableTrialFromToken: token_result = " << token_result.Status()
           << ", token = " << token;

  if (token_result.Status() == OriginTrialTokenStatus::kSuccess) {
    String trial_name =
        String::FromUTF8(token_result.ParsedToken()->feature_name());
    OriginTrialFeaturesEnabled result = EnableTrialFromName(
        trial_name, token_result.ParsedToken()->expiry_time());
    trial_status = result.status;
    // Go through the features and map them to the token that enabled them.
    for (mojom::blink::OriginTrialFeature const& feature : result.features) {
      auto feature_iter = feature_to_tokens_.find(feature);
      // A feature may have 0 to many tokens associated with it.
      if (feature_iter == feature_to_tokens_.end()) {
        auto token_vector = Vector<String>();
        token_vector.push_back(token);
        feature_to_tokens_.insert(feature, token_vector);
      } else {
        auto mapped_tokens = feature_to_tokens_.at(feature);
        mapped_tokens.push_back(token);
        feature_to_tokens_.Set(feature, mapped_tokens);
      }
    }

    // The browser will make its own decision on whether to enable any features
    // based on this token, so now that it's been confirmed that it is valid,
    // we should send it even if it didn't enable any features in Blink.
    SendTokenToBrowser(origin_info, *token_result.ParsedToken(), token,
                       script_origins);
  }

  CacheToken(token, token_result, trial_status);
  return trial_status == OriginTrialStatus::kEnabled;
}

void OriginTrialContext::CacheToken(const String& raw_token,
                                    const TrialTokenResult& token_result,
                                    OriginTrialStatus trial_status) {
  String trial_name =
      token_result.ParsedToken() &&
              token_result.Status() != OriginTrialTokenStatus::kUnknownTrial
          ? String::FromUTF8(token_result.ParsedToken()->feature_name())
          : kDefaultTrialName;

  // Does nothing if key already exists.
  auto& trial_result =
      trial_results_
          .insert(trial_name,
                  OriginTrialResult{
                      trial_name,
                      OriginTrialStatus::kValidTokenNotProvided,
                      /* token_results */ {},
                  })
          .stored_value->value;

  trial_result.status =
      MergeOriginTrialStatus(trial_result.status, trial_status);
  trial_result.token_results.push_back(OriginTrialTokenResult{
      raw_token, token_result.Status(),
      token_result.ParsedToken()
          ? std::make_optional(*token_result.ParsedToken())
          : std::nullopt});
}

void OriginTrialContext::Trace(Visitor* visitor) const {
  visitor->Trace(context_);
}

const SecurityOrigin* OriginTrialContext::GetSecurityOrigin() {
  const SecurityOrigin* origin;
  CHECK(context_);
  // Determines the origin to be validated against tokens:
  //  - For the purpose of origin trials, we consider worklets as running in the
  //    same context as the originating document. Thus, the special logic here
  //    to use the origin from the document context.
  if (auto* scope = DynamicTo<WorkletGlobalScope>(context_.Get()))
    origin = scope->DocumentSecurityOrigin();
  else
    origin = context_->GetSecurityOrigin();
  return origin;
}

bool OriginTrialContext::IsSecureContext() {
  bool is_secure = false;
  CHECK(context_);
  // Determines if this is a secure context:
  //  - For worklets, they are currently spec'd to not be secure, given their
  //    scope has unique origin:
  //    https://drafts.css-houdini.org/worklets/#script-settings-for-worklets
  //  - For the purpose of origin trials, we consider worklets as running in the
  //    same context as the originating document. Thus, the special logic here
  //    to check the secure status of the document context.
  if (auto* scope = DynamicTo<WorkletGlobalScope>(context_.Get())) {
    is_secure = scope->DocumentSecureContext();
  } else {
    is_secure = context_->IsSecureContext();
  }
  return is_secure;
}

OriginTrialContext::OriginInfo OriginTrialContext::GetCurrentOriginInfo() {
  return {.origin = GetSecurityOrigin(), .is_secure = IsSecureContext()};
}

void OriginTrialContext::SendTokenToBrowser(
    const OriginInfo& origin_info,
    const TrialToken& parsed_token,
    const String& raw_token,
    const Vector<OriginInfo>* script_origin_info) {
  // Passing activated origin trial tokens is only supported for windows.
  if (!context_->IsWindow()) {
    return;
  }

  if (!origin_trials::IsTrialPersistentToNextResponse(
          parsed_token.feature_name())) {
    return;
  }

  Vector<scoped_refptr<const blink::SecurityOrigin>> script_origins;
  if (script_origin_info) {
    for (const OriginInfo& script_origin : *script_origin_info) {
      script_origins.push_back(script_origin.origin);
    }
  }
  context_->GetRuntimeFeatureStateOverrideContext()->EnablePersistentTrial(
      raw_token, std::move(script_origins));
}

}  // namespace blink
```
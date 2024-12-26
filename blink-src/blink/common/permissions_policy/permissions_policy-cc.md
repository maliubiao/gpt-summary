Response: Let's break down the thought process to analyze the `permissions_policy.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this file within the Chromium Blink engine and its relation to web technologies (JavaScript, HTML, CSS).

2. **Initial Scan and Key Terms:** Quickly read through the code, paying attention to keywords and structure. Notice terms like `PermissionsPolicy`, `Allowlist`, `Origin`, `Feature`, `ParsedPermissionsPolicy`, `Inherited`, `Enabled`, `Disabled`, `ReportingEndpoints`. These suggest the file is about controlling access to certain browser features based on origin.

3. **Identify Core Classes and Structures:** The `PermissionsPolicy` class seems central. The nested `Allowlist` class is also important. The `ParsedPermissionsPolicy` likely represents the parsed form of policy declarations. `mojom::PermissionsPolicyFeature` is an enum representing different features controlled by the policy.

4. **Analyze `Allowlist`:** Focus on the `Allowlist` class first as it seems fundamental to how permissions are managed.
    * **Purpose:**  It represents a set of origins (or special keywords like "self", "*", "opaque-src") that are allowed a certain permission.
    * **Key Methods:**  `Add`, `AddSelf`, `AddAll`, `AddOpaqueSrc`, `Contains`. These methods indicate how to build and check the allowlist.
    * **Relationship to Web Tech:**  The concept of origins directly relates to how web pages are identified and isolated. This is fundamental to the web's security model and thus impacts JavaScript (making API calls to different origins), HTML (embedding content from other origins), and potentially CSS (though less direct).

5. **Analyze `PermissionsPolicy`:** Now dive into the main `PermissionsPolicy` class.
    * **Purpose:** Represents the overall permissions policy for a specific origin.
    * **Key Methods:**
        * **Creation:** `CreateFromParentPolicy`, `CopyStateFrom`, `CreateFromParsedPolicy`, `CreateFlexibleForFencedFrame`, `CreateFixedForFencedFrame`. These methods show different ways a policy can be created, indicating different contexts where policies are applied (inheritance, fenced frames, etc.).
        * **Checking Permissions:** `IsFeatureEnabled`, `IsFeatureEnabledForOrigin`, `IsFeatureEnabledForSubresourceRequest`, `GetFeatureValueForOrigin`. These are crucial for determining if a specific feature is allowed for a given origin.
        * **Retrieving Allowlists:** `GetAllowlistForDevTools`, `GetAllowlistForFeature`, `GetAllowlistForFeatureIfExists`. These methods provide access to the allowlist associated with a feature.
        * **Handling Inheritance:** The `InheritedValueForFeature` function is clearly about how permissions are passed down from parent frames/documents.
    * **Data Members:** `origin_`, `allowlists_`, `inherited_policies_`, `feature_list_`. These hold the core state of a permissions policy.
    * **Relationship to Web Tech:** This class directly dictates whether certain web features (defined by `mojom::PermissionsPolicyFeature`) are available to JavaScript code running on a specific origin, impacting HTML features that rely on these permissions, and even affecting CSS behavior in some cases (though less frequently).

6. **Identify Key Functionalities (Summarize):** Based on the method analysis, list the main functions of the file:
    * Creating and managing permissions policies.
    * Defining allowlists of origins for specific features.
    * Checking if a feature is enabled for a given origin.
    * Handling policy inheritance.
    * Integrating with parsing of policy declarations.
    * Providing information for developer tools.

7. **Relate to JavaScript, HTML, CSS (Provide Examples):** Now, connect the functionality to specific web technologies. Think of concrete scenarios:
    * **JavaScript:**  `navigator.geolocation.getCurrentPosition()` is blocked if the `geolocation` permission is not granted by the policy.
    * **HTML:** An `<iframe>` with `allow="camera"` will only get access to the camera if the parent's policy allows it. The `Permissions-Policy` header itself is part of HTML delivery.
    * **CSS:** While less common, features like the `Web Authentication API` (though primarily JS) could be gated by permissions policy. Consider how CSS might trigger resource loads that are subject to permissions (though the example is less direct).

8. **Identify Logical Reasoning and Create Examples:** Look for functions that make decisions based on input. `IsFeatureEnabledForOriginImpl` and `InheritedValueForFeature` are good candidates.
    * **Hypothesize Input:**  A specific feature (e.g., `microphone`), an origin (e.g., `https://example.com`), and the policy state.
    * **Trace Execution:**  Mentally walk through the code to see how the result (enabled/disabled) is determined.
    * **Construct Examples:**  Create simple scenarios demonstrating the logic.

9. **Identify Potential User/Programming Errors:** Consider common mistakes developers might make when dealing with permissions policies.
    * **Misconfigured Headers:**  Incorrect syntax or missing directives.
    * **Incorrect Origin Matching:**  Not understanding how wildcards or "self" work.
    * **Forgetting Inheritance:**  Assuming a child frame has a permission just because the parent does.
    * **Not Testing Policy:**  Failing to verify the policy is working as expected.

10. **Review and Refine:** Read through the analysis to ensure clarity, accuracy, and completeness. Check for any missing aspects or areas that need better explanation. Ensure the examples are clear and illustrative. (Self-correction: Initially, I might have focused too much on the individual methods and not enough on the overall purpose and how the pieces fit together. Reviewing helps to bring that higher-level understanding into focus).
这个文件 `blink/common/permissions_policy/permissions_policy.cc` 是 Chromium Blink 引擎中实现 **Permissions Policy（权限策略）** 的核心部分。Permissions Policy 是一种 Web 平台机制，允许网站控制在它们自己的网站上以及嵌入的第三方内容中可以使用哪些浏览器功能。这增强了安全性并允许更细粒度的控制。

以下是该文件的主要功能：

1. **定义和管理权限策略：**  `PermissionsPolicy` 类及其相关的结构体（如 `Allowlist`）负责表示和操作权限策略。它存储了哪些特性（例如，地理位置、摄像头、麦克风等）被允许以及允许哪些来源使用这些特性。

2. **解析和应用策略声明：**  该文件包含用于处理和解释从 HTTP 头部（`Permissions-Policy`）或 HTML 属性（如 `<iframe>` 标签的 `allow` 属性）中解析出的权限策略声明的逻辑。

3. **执行策略检查：**  `PermissionsPolicy` 类提供了方法来检查在给定上下文中（例如，特定的源）是否允许使用某个特性。这涉及到检查与该特性关联的允许列表（`Allowlist`）。

4. **处理策略继承：**  Permissions Policy 具有继承机制，子框架可以继承父框架的策略，但也可能受到额外的限制。该文件包含了处理这种继承关系的逻辑。

5. **与浏览器功能集成：**  该代码与 Blink 引擎的其他部分集成，以便在尝试使用受权限策略控制的功能时执行策略检查。例如，当 JavaScript 代码尝试访问麦克风时，会查询当前的权限策略以确定是否允许该操作。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

Permissions Policy 通过 HTTP 头部和 HTML 属性进行声明，并影响 JavaScript 代码的行为。它与 CSS 的关系相对间接，主要体现在某些可能触发需要权限的功能的 CSS 特性上（尽管这种情况较少）。

**JavaScript:**

* **功能控制:** Permissions Policy 可以限制 JavaScript API 的使用。例如，如果一个页面的 Permissions Policy 中不允许使用地理位置 API，那么尝试调用 `navigator.geolocation.getCurrentPosition()` 将会被阻止，或者返回错误。
   * **假设输入:**  一个页面设置了 `Permissions-Policy: geolocation=()` 头部，表示不允许任何来源使用地理位置 API。
   * **输出:**  页面上的 JavaScript 代码调用 `navigator.geolocation.getCurrentPosition()` 将会失败，并可能抛出一个错误或调用错误回调函数。

* **第三方内容限制:**  Permissions Policy 可以控制嵌入的 `<iframe>` 中的 JavaScript 代码可以使用的功能。
   * **假设输入:**  父页面设置了 `Permissions-Policy: microphone=self`，而 `<iframe>` 标签没有 `allow` 属性或者 `allow` 属性没有包含 `microphone`。
   * **输出:**  `<iframe>` 中的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ audio: true })` 将会被阻止。

**HTML:**

* **策略声明:** Permissions Policy 主要通过 HTTP 的 `Permissions-Policy` 头部进行声明。
   * **举例:**  服务器发送响应头 `Permissions-Policy: camera=(self "https://example.com")`，表示当前域和 `https://example.com` 可以使用摄像头。

* **`<iframe>` 的 `allow` 属性:**  `<iframe>` 标签的 `allow` 属性允许父页面为嵌入的子框架放宽一些权限限制。
   * **举例:**  `<iframe src="https://thirdparty.com" allow="microphone"></iframe>`  允许 `https://thirdparty.com` 页面使用麦克风，即使父页面的 Permissions Policy 中可能没有显式允许所有来源使用麦克风。

**CSS:**

* **间接影响:**  虽然 Permissions Policy 不直接限制 CSS 的语法或属性，但它可以影响某些 CSS 功能所依赖的底层机制。例如，如果 Permissions Policy 阻止了某个 API 的使用，那么可能导致依赖该 API 的 CSS 功能无法正常工作（这种情况相对较少见）。
   * **假设输入:**  一个网站的 Permissions Policy 阻止了 Web Authentication API 的使用。页面上的 CSS 可能会触发与 Web Authentication 相关的操作（虽然这通常是 JavaScript 的责任）。
   * **输出:**  由于底层 API 被阻止，CSS 触发的相关功能可能无法正常执行。

**逻辑推理的假设输入与输出:**

考虑 `PermissionsPolicy::IsFeatureEnabledForOrigin` 方法，它用于判断特定来源是否允许使用某个特性。

* **假设输入 1:**
    * `feature`: `mojom::PermissionsPolicyFeature::kGeolocation` (地理位置)
    * `origin`: `https://example.com`
    * 当前页面的 Permissions Policy 包含 `geolocation=(self "https://example.com")`。
* **输出 1:** `true` (因为 `https://example.com` 在允许列表中)。

* **假设输入 2:**
    * `feature`: `mojom::PermissionsPolicyFeature::kCamera` (摄像头)
    * `origin`: `https://malicious.com`
    * 当前页面的 Permissions Policy 包含 `camera=(self)`。
* **输出 2:** `false` (因为 `https://malicious.com` 不在允许列表中)。

* **假设输入 3 (继承情况):**
    * 父框架的 Permissions Policy 设置为 `microphone=self`.
    * 子框架的来源是与父框架相同的来源。
    * 检查子框架是否允许使用麦克风。
* **输出 3:** `true` (因为子框架继承了父框架的策略，并且来源相同)。

**用户或编程常见的使用错误举例说明:**

1. **拼写错误或特性名称错误:**
   * **错误举例:**  在 HTTP 头部中写成 `Permisions-Policy: camera=()` 而不是 `Permissions-Policy: camera=()`。或者使用了不存在的特性名称。
   * **后果:**  浏览器无法正确解析策略，导致策略失效或行为不符合预期。

2. **对 `self` 关键字的误解:**
   * **错误举例:**  认为 `Permissions-Policy: camera=(self)` 允许所有同源的子域使用摄像头。
   * **后果:**  只有完全相同的源（协议、域名、端口都相同）才能使用摄像头，子域需要显式列出。

3. **在 `<iframe>` 中忘记使用 `allow` 属性:**
   * **错误举例:**  父页面设置了 `Permissions-Policy: microphone=*`，但嵌入的第三方 `<iframe>` 中的代码仍然无法访问麦克风。
   * **后果:**  即使父页面允许所有来源使用麦克风，`<iframe>` 仍然需要通过 `allow` 属性显式地被授予权限。

4. **过于宽松的策略:**
   * **错误举例:**  设置 `Permissions-Policy: * *` 允许所有特性被所有来源使用。
   * **后果:**  降低了网站的安全性，因为恶意第三方内容可能滥用这些权限。

5. **过于严格的策略导致功能失效:**
   * **错误举例:**  不小心设置了 `Permissions-Policy: geolocation=()`，导致网站自身的地图功能无法使用。
   * **后果:**  网站的预期功能受到影响，用户体验下降。

6. **混淆 HTTP 头部和 `<iframe>` 的 `allow` 属性:**
   * **错误举例:**  认为在 HTTP 头部中设置了某个特性为允许后，所有的 `<iframe>` 都会自动获得该权限。
   * **后果:**  `<iframe>` 的权限需要单独通过 `allow` 属性进行控制，HTTP 头部的策略是父页面的默认策略。

理解 `blink/common/permissions_policy/permissions_policy.cc` 的功能对于 Web 开发者来说至关重要，因为它直接关系到如何在 Web 应用中安全地使用各种强大的浏览器特性，并控制第三方内容的权限，从而提升用户的安全性和隐私。

Prompt: 
```
这是目录为blink/common/permissions_policy/permissions_policy.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/permissions_policy/permissions_policy.h"

#include "base/containers/contains.h"
#include "base/memory/ptr_util.h"
#include "base/no_destructor.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/mojom/web_sandbox_flags.mojom-shared.h"
#include "third_party/blink/public/common/client_hints/client_hints.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/frame/fenced_frame_permissions_policies.h"
#include "third_party/blink/public/common/permissions_policy/permissions_policy_features.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom.h"

namespace blink {

PermissionsPolicy::Allowlist::Allowlist() = default;

PermissionsPolicy::Allowlist::Allowlist(const Allowlist& rhs) = default;

PermissionsPolicy::Allowlist::~Allowlist() = default;

PermissionsPolicy::Allowlist PermissionsPolicy::Allowlist::FromDeclaration(
    const ParsedPermissionsPolicyDeclaration& parsed_declaration) {
  auto result = PermissionsPolicy::Allowlist();
  if (parsed_declaration.self_if_matches) {
    result.AddSelf(parsed_declaration.self_if_matches);
  }
  if (parsed_declaration.matches_all_origins)
    result.AddAll();
  if (parsed_declaration.matches_opaque_src)
    result.AddOpaqueSrc();
  for (const auto& value : parsed_declaration.allowed_origins)
    result.Add(value);

  return result;
}

void PermissionsPolicy::Allowlist::Add(
    const blink::OriginWithPossibleWildcards& origin) {
  allowed_origins_.push_back(origin);
}

void PermissionsPolicy::Allowlist::AddSelf(std::optional<url::Origin> self) {
  self_if_matches_ = std::move(self);
}

void PermissionsPolicy::Allowlist::AddAll() {
  matches_all_origins_ = true;
}

void PermissionsPolicy::Allowlist::AddOpaqueSrc() {
  matches_opaque_src_ = true;
}

bool PermissionsPolicy::Allowlist::Contains(const url::Origin& origin) const {
  if (origin == self_if_matches_) {
    return true;
  }
  for (const auto& allowed_origin : allowed_origins_) {
    if (allowed_origin.DoesMatchOrigin(origin))
      return true;
  }
  if (origin.opaque())
    return matches_opaque_src_;
  return matches_all_origins_;
}

const std::optional<url::Origin>& PermissionsPolicy::Allowlist::SelfIfMatches()
    const {
  return self_if_matches_;
}

bool PermissionsPolicy::Allowlist::MatchesAll() const {
  return matches_all_origins_;
}

void PermissionsPolicy::Allowlist::RemoveMatchesAll() {
  matches_all_origins_ = false;
}

bool PermissionsPolicy::Allowlist::MatchesOpaqueSrc() const {
  return matches_opaque_src_;
}

// static
std::unique_ptr<PermissionsPolicy> PermissionsPolicy::CreateFromParentPolicy(
    const PermissionsPolicy* parent_policy,
    const ParsedPermissionsPolicy& header_policy,
    const ParsedPermissionsPolicy& container_policy,
    const url::Origin& origin) {
  return CreateFromParentPolicy(parent_policy, header_policy, container_policy,
                                origin,
                                GetPermissionsPolicyFeatureList(origin));
}

// static
std::unique_ptr<PermissionsPolicy> PermissionsPolicy::CopyStateFrom(
    const PermissionsPolicy* source) {
  if (!source)
    return nullptr;

  std::unique_ptr<PermissionsPolicy> new_policy = base::WrapUnique(
      new PermissionsPolicy(source->origin_, {source->allowlists_, {}},
                            source->inherited_policies_,
                            GetPermissionsPolicyFeatureList(source->origin_)));

  return new_policy;
}

// static
std::unique_ptr<PermissionsPolicy> PermissionsPolicy::CreateFromParsedPolicy(
    const ParsedPermissionsPolicy& parsed_policy,
    const std::optional<ParsedPermissionsPolicy>& base_policy,
    const url::Origin& origin) {
  return CreateFromParsedPolicy(parsed_policy, base_policy, origin,
                                GetPermissionsPolicyFeatureList(origin));
}

// static
std::unique_ptr<PermissionsPolicy> PermissionsPolicy::CreateFromParsedPolicy(
    const ParsedPermissionsPolicy& parsed_policy,
    const std::optional<ParsedPermissionsPolicy>&
        parsed_policy_for_isolated_app,
    const url::Origin& origin,
    const PermissionsPolicyFeatureList& features) {
  PermissionsPolicyFeatureState inherited_policies;
  AllowlistsAndReportingEndpoints allow_lists_and_reporting_endpoints =
      parsed_policy_for_isolated_app
          ? CombinePolicies(parsed_policy_for_isolated_app.value(),
                            parsed_policy)
          : CreateAllowlistsAndReportingEndpoints(parsed_policy);
  for (const auto& feature : features) {
    inherited_policies[feature.first] =
        base::Contains(allow_lists_and_reporting_endpoints.allowlists_,
                       feature.first) &&
        allow_lists_and_reporting_endpoints.allowlists_[feature.first].Contains(
            origin);
  }

  std::unique_ptr<PermissionsPolicy> new_policy = base::WrapUnique(
      new PermissionsPolicy(origin, allow_lists_and_reporting_endpoints,
                            inherited_policies, features));

  return new_policy;
}

bool PermissionsPolicy::IsFeatureEnabledByInheritedPolicy(
    mojom::PermissionsPolicyFeature feature) const {
  DCHECK(base::Contains(inherited_policies_, feature));
  return inherited_policies_.at(feature);
}

bool PermissionsPolicy::IsFeatureEnabled(
    mojom::PermissionsPolicyFeature feature) const {
  return IsFeatureEnabledForOrigin(feature, origin_);
}

bool PermissionsPolicy::IsFeatureEnabledForOrigin(
    mojom::PermissionsPolicyFeature feature,
    const url::Origin& origin) const {
  return IsFeatureEnabledForOriginImpl(feature, origin, /*opt_in_features=*/{});
}

bool PermissionsPolicy::IsFeatureEnabledForSubresourceRequest(
    mojom::PermissionsPolicyFeature feature,
    const url::Origin& origin,
    const network::ResourceRequest& request) const {
  // Derive the opt-in features from the request attributes.
  std::set<mojom::PermissionsPolicyFeature> opt_in_features;
  if (request.browsing_topics) {
    DCHECK(base::FeatureList::IsEnabled(blink::features::kBrowsingTopics));

    opt_in_features.insert(mojom::PermissionsPolicyFeature::kBrowsingTopics);
    opt_in_features.insert(
        mojom::PermissionsPolicyFeature::kBrowsingTopicsBackwardCompatible);
  }

  // Note that currently permissions for `sharedStorageWritable` are checked
  // using `IsFeatureEnabledForSubresourceRequestAssumingOptIn()`, since a
  // `network::ResourceRequest` is not available at the call site and
  // `blink::ResourceRequest` should not be used in blink public APIs.
  if (request.shared_storage_writable_eligible) {
    DCHECK(base::FeatureList::IsEnabled(blink::features::kSharedStorageAPI));
    opt_in_features.insert(mojom::PermissionsPolicyFeature::kSharedStorage);
  }

  if (request.ad_auction_headers) {
    DCHECK(
        base::FeatureList::IsEnabled(blink::features::kInterestGroupStorage));

    opt_in_features.insert(mojom::PermissionsPolicyFeature::kRunAdAuction);
  }

  return IsFeatureEnabledForOriginImpl(feature, origin, opt_in_features);
}

// Implements Permissions Policy 9.8: Get feature value for origin.
// Version https://www.w3.org/TR/2023/WD-permissions-policy-1-20231218/
bool PermissionsPolicy::GetFeatureValueForOrigin(
    mojom::PermissionsPolicyFeature feature,
    const url::Origin& origin) const {
  DCHECK(base::Contains(*feature_list_, feature));

  // 9.8.2 If policy’s inherited policy for feature is "Disabled", return
  // "Disabled".
  if (!IsFeatureEnabledByInheritedPolicy(feature)) {
    return false;
  }

  // 9.8.3 If feature is present in policy’s declared policy:
  //   1 If the allowlist for feature in policy’s declared policy matches
  //     origin, then return "Enabled".
  //   2 Otherwise return "Disabled".
  auto allowlist = allowlists_.find(feature);
  if (allowlist != allowlists_.end()) {
    return allowlist->second.Contains(origin);
  }

  // 9.8.4 Return "Enabled".
  return true;
}

const PermissionsPolicy::Allowlist PermissionsPolicy::GetAllowlistForDevTools(
    mojom::PermissionsPolicyFeature feature) const {
  // Return an empty allowlist when disabled through inheritance.
  if (!IsFeatureEnabledByInheritedPolicy(feature))
    return PermissionsPolicy::Allowlist();

  // Return defined policy if exists; otherwise return default policy.
  const auto& maybe_allow_list = GetAllowlistForFeatureIfExists(feature);
  if (maybe_allow_list.has_value())
    return maybe_allow_list.value();

  // Note: |allowlists_| purely comes from HTTP header. If a feature is not
  // declared in HTTP header, all origins are implicitly allowed unless the
  // default is `EnableForNone`.
  PermissionsPolicy::Allowlist default_allowlist;
  const PermissionsPolicyFeatureDefault default_policy =
      feature_list_->at(feature);
  switch (default_policy) {
    case PermissionsPolicyFeatureDefault::EnableForAll:
    case PermissionsPolicyFeatureDefault::EnableForSelf:
      default_allowlist.AddAll();
      break;
    case PermissionsPolicyFeatureDefault::EnableForNone:
      break;
  }

  return default_allowlist;
}

// TODO(crbug.com/937131): Use |PermissionsPolicy::GetAllowlistForDevTools|
// to replace this method. This method uses legacy |default_allowlist|
// calculation method.
const PermissionsPolicy::Allowlist PermissionsPolicy::GetAllowlistForFeature(
    mojom::PermissionsPolicyFeature feature) const {
  DCHECK(base::Contains(*feature_list_, feature));
  // Return an empty allowlist when disabled through inheritance.
  if (!IsFeatureEnabledByInheritedPolicy(feature))
    return PermissionsPolicy::Allowlist();

  // Return defined policy if exists; otherwise return default policy.
  const auto& maybe_allow_list = GetAllowlistForFeatureIfExists(feature);
  if (maybe_allow_list.has_value())
    return maybe_allow_list.value();

  const PermissionsPolicyFeatureDefault default_policy =
      feature_list_->at(feature);
  PermissionsPolicy::Allowlist default_allowlist;

  switch (default_policy) {
    case PermissionsPolicyFeatureDefault::EnableForAll:
      default_allowlist.AddAll();
      break;
    case PermissionsPolicyFeatureDefault::EnableForSelf: {
      std::optional<blink::OriginWithPossibleWildcards>
          origin_with_possible_wildcards =
              blink::OriginWithPossibleWildcards::FromOrigin(origin_);
      if (origin_with_possible_wildcards.has_value()) {
        default_allowlist.Add(*origin_with_possible_wildcards);
      }
    } break;
    case PermissionsPolicyFeatureDefault::EnableForNone:
      break;
  }

  return default_allowlist;
}

std::optional<const PermissionsPolicy::Allowlist>
PermissionsPolicy::GetAllowlistForFeatureIfExists(
    mojom::PermissionsPolicyFeature feature) const {
  // Return an empty allowlist when disabled through inheritance.
  if (!IsFeatureEnabledByInheritedPolicy(feature))
    return std::nullopt;

  // Only return allowlist if actually in `allowlists_`.
  auto allowlist = allowlists_.find(feature);
  if (allowlist != allowlists_.end())
    return allowlist->second;
  return std::nullopt;
}

std::optional<std::string> PermissionsPolicy::GetEndpointForFeature(
    mojom::PermissionsPolicyFeature feature) const {
  auto endpoint = reporting_endpoints_.find(feature);
  if (endpoint != reporting_endpoints_.end()) {
    return endpoint->second;
  }
  return std::nullopt;
}

// static
PermissionsPolicy::AllowlistsAndReportingEndpoints
PermissionsPolicy::CreateAllowlistsAndReportingEndpoints(
    const ParsedPermissionsPolicy& parsed_header) {
  AllowlistsAndReportingEndpoints allow_lists_and_reporting_endpoints;
  for (const ParsedPermissionsPolicyDeclaration& parsed_declaration :
       parsed_header) {
    mojom::PermissionsPolicyFeature feature = parsed_declaration.feature;
    DCHECK(feature != mojom::PermissionsPolicyFeature::kNotFound);
    allow_lists_and_reporting_endpoints.allowlists_.emplace(
        feature, Allowlist::FromDeclaration(parsed_declaration));
    if (parsed_declaration.reporting_endpoint.has_value()) {
      allow_lists_and_reporting_endpoints.reporting_endpoints_.insert(
          {feature, parsed_declaration.reporting_endpoint.value()});
    }
  }
  return allow_lists_and_reporting_endpoints;
}

// static
PermissionsPolicy::AllowlistsAndReportingEndpoints
PermissionsPolicy::CombinePolicies(
    const ParsedPermissionsPolicy& base_policy,
    const ParsedPermissionsPolicy& second_policy) {
  PermissionsPolicy::AllowlistsAndReportingEndpoints
      allow_lists_and_reporting_endpoints =
          CreateAllowlistsAndReportingEndpoints(base_policy);
  for (const ParsedPermissionsPolicyDeclaration& parsed_declaration :
       second_policy) {
    mojom::PermissionsPolicyFeature feature = parsed_declaration.feature;
    DCHECK(feature != mojom::PermissionsPolicyFeature::kNotFound);
    const auto& second_allowlist =
        PermissionsPolicy::Allowlist::FromDeclaration(parsed_declaration);
    auto& base_allowlist =
        allow_lists_and_reporting_endpoints.allowlists_.at(feature);

    // If the header does not specify further restrictions we do not need to
    // modify the policy.
    if (second_allowlist.MatchesAll()) {
      continue;
    }

    const auto& second_allowed_origins = second_allowlist.AllowedOrigins();
    // If the manifest allows all origins access to this feature, use the more
    // restrictive header policy.
    if (base_allowlist.MatchesAll()) {
      // TODO(https://crbug.com/40847608): Refactor to use Allowlist::clone()
      // after clone() is implemented.
      base_allowlist.SetAllowedOrigins(second_allowed_origins);
      base_allowlist.RemoveMatchesAll();
      base_allowlist.AddSelf(second_allowlist.SelfIfMatches());
      continue;
    }

    // Otherwise, we use the intersection of origins in the manifest and the
    // header.
    auto manifest_allowed_origins = base_allowlist.AllowedOrigins();
    std::vector<blink::OriginWithPossibleWildcards> final_allowed_origins;
    // TODO(https://crbug.com/339404063): consider rewriting this to not be
    // O(N^2).
    for (const auto& origin : manifest_allowed_origins) {
      if (base::Contains(second_allowed_origins, origin)) {
        final_allowed_origins.push_back(origin);
      }
    }
    base_allowlist.SetAllowedOrigins(final_allowed_origins);
  }
  return allow_lists_and_reporting_endpoints;
}

std::unique_ptr<PermissionsPolicy> PermissionsPolicy::WithClientHints(
    const ParsedPermissionsPolicy& parsed_header) const {
  std::map<mojom::PermissionsPolicyFeature, Allowlist> allowlists = allowlists_;
  for (const ParsedPermissionsPolicyDeclaration& parsed_declaration :
       parsed_header) {
    mojom::PermissionsPolicyFeature feature = parsed_declaration.feature;
    DCHECK(GetPolicyFeatureToClientHintMap().contains(feature));
    allowlists[feature] = Allowlist::FromDeclaration(parsed_declaration);
  }

  return base::WrapUnique(new PermissionsPolicy(
      origin_, {allowlists, reporting_endpoints_}, inherited_policies_,
      GetPermissionsPolicyFeatureList(origin_)));
}

const mojom::PermissionsPolicyFeature
    PermissionsPolicy::defined_opt_in_features_[] = {
        mojom::PermissionsPolicyFeature::kBrowsingTopics,
        mojom::PermissionsPolicyFeature::kBrowsingTopicsBackwardCompatible,
        mojom::PermissionsPolicyFeature::kSharedStorage,
        mojom::PermissionsPolicyFeature::kRunAdAuction};

PermissionsPolicy::PermissionsPolicy(
    url::Origin origin,
    AllowlistsAndReportingEndpoints allow_lists_and_reporting_endpoints,
    PermissionsPolicyFeatureState inherited_policies,
    const PermissionsPolicyFeatureList& feature_list)
    : origin_(std::move(origin)),
      allowlists_(std::move(allow_lists_and_reporting_endpoints.allowlists_)),
      reporting_endpoints_(
          std::move(allow_lists_and_reporting_endpoints.reporting_endpoints_)),
      inherited_policies_(std::move(inherited_policies)),
      feature_list_(feature_list) {}

PermissionsPolicy::~PermissionsPolicy() = default;

// static
std::unique_ptr<PermissionsPolicy>
PermissionsPolicy::CreateFlexibleForFencedFrame(
    const PermissionsPolicy* parent_policy,
    const ParsedPermissionsPolicy& header_policy,
    const ParsedPermissionsPolicy& container_policy,
    const url::Origin& subframe_origin) {
  return CreateFlexibleForFencedFrame(
      parent_policy, header_policy, container_policy, subframe_origin,
      GetPermissionsPolicyFeatureList(subframe_origin));
}

// static
std::unique_ptr<PermissionsPolicy>
PermissionsPolicy::CreateFlexibleForFencedFrame(
    const PermissionsPolicy* parent_policy,
    const ParsedPermissionsPolicy& header_policy,
    const ParsedPermissionsPolicy& container_policy,
    const url::Origin& subframe_origin,
    const PermissionsPolicyFeatureList& features) {
  PermissionsPolicyFeatureState inherited_policies;
  for (const auto& feature : features) {
    if (base::Contains(kFencedFrameAllowedFeatures, feature.first)) {
      inherited_policies[feature.first] = InheritedValueForFeature(
          subframe_origin, parent_policy, feature, container_policy);
    } else {
      inherited_policies[feature.first] = false;
    }
  }
  return base::WrapUnique(new PermissionsPolicy(
      subframe_origin, CreateAllowlistsAndReportingEndpoints(header_policy),
      inherited_policies, features));
}

// static
std::unique_ptr<PermissionsPolicy> PermissionsPolicy::CreateFixedForFencedFrame(
    const url::Origin& origin,
    const ParsedPermissionsPolicy& header_policy,
    base::span<const blink::mojom::PermissionsPolicyFeature>
        effective_enabled_permissions) {
  return CreateFixedForFencedFrame(origin, header_policy,
                                   GetPermissionsPolicyFeatureList(origin),
                                   effective_enabled_permissions);
}

// static
std::unique_ptr<PermissionsPolicy> PermissionsPolicy::CreateFixedForFencedFrame(
    const url::Origin& origin,
    const ParsedPermissionsPolicy& header_policy,
    const PermissionsPolicyFeatureList& features,
    base::span<const blink::mojom::PermissionsPolicyFeature>
        effective_enabled_permissions) {
  PermissionsPolicyFeatureState inherited_policies;
  for (const auto& feature : features) {
    inherited_policies[feature.first] = false;
  }
  for (const blink::mojom::PermissionsPolicyFeature feature :
       effective_enabled_permissions) {
    inherited_policies[feature] = true;
  }

  return base::WrapUnique(new PermissionsPolicy(
      origin, CreateAllowlistsAndReportingEndpoints(header_policy),
      inherited_policies, features));
}

// static
std::unique_ptr<PermissionsPolicy> PermissionsPolicy::CreateFromParentPolicy(
    const PermissionsPolicy* parent_policy,
    const ParsedPermissionsPolicy& header_policy,
    const ParsedPermissionsPolicy& container_policy,
    const url::Origin& origin,
    const PermissionsPolicyFeatureList& features) {
  PermissionsPolicyFeatureState inherited_policies;
  for (const auto& feature : features) {
    inherited_policies[feature.first] = InheritedValueForFeature(
        origin, parent_policy, feature, container_policy);
  }
  return base::WrapUnique(new PermissionsPolicy(
      origin, CreateAllowlistsAndReportingEndpoints(header_policy),
      inherited_policies, features));
}

// Implements Permissions Policy 9.9: Is feature enabled in document for origin?
// Version https://www.w3.org/TR/2023/WD-permissions-policy-1-20230717/
bool PermissionsPolicy::IsFeatureEnabledForOriginImpl(
    mojom::PermissionsPolicyFeature feature,
    const url::Origin& origin,
    const std::set<mojom::PermissionsPolicyFeature>& opt_in_features) const {
  DCHECK(base::Contains(*feature_list_, feature));

  // 9.9.2: If policy’s inherited policy for feature is Disabled, return
  // "Disabled".
  if (!IsFeatureEnabledByInheritedPolicy(feature)) {
    return false;
  }

  // 9.9.3: If feature is present in policy’s declared policy:
  //    1. If the allowlist for feature in policy’s declared policy matches
  //       origin, then return "Enabled".
  //    2. Otherwise return "Disabled".
  auto allowlist = allowlists_.find(feature);
  if (allowlist != allowlists_.end()) {
    return allowlist->second.Contains(origin);
  }

  // Proposed algorithm change in
  // https://github.com/w3c/webappsec-permissions-policy/pull/499: if
  // optInFeatures contains feature, then return "Enabled".
  if (base::Contains(opt_in_features, feature)) {
    return true;
  }

  const PermissionsPolicyFeatureDefault default_policy =
      feature_list_->at(feature);

  switch (default_policy) {
    case PermissionsPolicyFeatureDefault::EnableForAll:
      // 9.9.4: If feature’s default allowlist is *, return "Enabled".
      return true;
    case PermissionsPolicyFeatureDefault::EnableForSelf:
      // 9.9.5: If feature’s default allowlist is 'self', and origin is same
      // origin with document’s origin, return "Enabled".
      if (origin_.IsSameOriginWith(origin)) {
        return true;
      }
      break;
    case PermissionsPolicyFeatureDefault::EnableForNone:
      break;
  }
  // 9.9.6: Return "Disabled".
  return false;
}

bool PermissionsPolicy::IsFeatureEnabledForSubresourceRequestAssumingOptIn(
    mojom::PermissionsPolicyFeature feature,
    const url::Origin& origin) const {
  CHECK(base::Contains(defined_opt_in_features_, feature));

  // Make an opt-in features set containing exactly `feature`, as we're not
  // given access to the full request to derive any other opt-in features.
  std::set<mojom::PermissionsPolicyFeature> opt_in_features({feature});

  return IsFeatureEnabledForOriginImpl(feature, origin, opt_in_features);
}

// Implements Permissions Policy 9.7: Define an inherited policy for
// feature in container at origin.
// Version https://www.w3.org/TR/2023/WD-permissions-policy-1-20230717/
// static
bool PermissionsPolicy::InheritedValueForFeature(
    const url::Origin& origin,
    const PermissionsPolicy* parent_policy,
    std::pair<mojom::PermissionsPolicyFeature, PermissionsPolicyFeatureDefault>
        feature,
    const ParsedPermissionsPolicy& container_policy) {
  // 9.7 1: If container is null, return "Enabled".
  if (!parent_policy) {
    return true;
  }

  // 9.7 2: If the result of executing Get feature value for origin on feature,
  // container’s node document, and container’s node document’s origin is
  // "Disabled", return "Disabled".
  if (!parent_policy->GetFeatureValueForOrigin(feature.first,
                                               parent_policy->origin_)) {
    return false;
  }

  // 9.7 3: If feature was inherited and (if declared) the allowlist for the
  // feature does not match origin, then return "Disabled".
  if (!parent_policy->GetFeatureValueForOrigin(feature.first, origin)) {
    return false;
  }

  for (const auto& decl : container_policy) {
    if (decl.feature == feature.first) {
      // 9.7 5.1: If the allowlist for feature in container policy matches
      // origin, return "Enabled".
      // 9.7 5.2: Otherwise return "Disabled".
      return Allowlist::FromDeclaration(decl).Contains(origin);
    }
  }
  switch (feature.second) {
    case PermissionsPolicyFeatureDefault::EnableForAll:
      // 9.7 6: If feature’s default allowlist is *, return "Enabled".
      return true;
    case PermissionsPolicyFeatureDefault::EnableForSelf:
      // 9.7 7: If feature’s default allowlist is 'self', and origin is same
      // origin with container’s node document’s origin, return "Enabled". 9.7
      if (origin.IsSameOriginWith(parent_policy->origin_)) {
        return true;
      }
      break;
    case PermissionsPolicyFeatureDefault::EnableForNone:
      break;
  }
  // 9.7 8: Otherwise return "Disabled".
  return false;
}

const PermissionsPolicyFeatureList& PermissionsPolicy::GetFeatureList() const {
  return *feature_list_;
}

}  // namespace blink

"""

```
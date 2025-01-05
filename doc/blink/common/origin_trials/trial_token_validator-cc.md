Response: Let's break down the thought process for analyzing the `trial_token_validator.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this C++ file within the Chromium Blink engine, specifically how it validates Origin Trial tokens. We need to identify its relationships with JavaScript, HTML, and CSS, understand its internal logic, and pinpoint potential usage errors.

2. **Initial Scan and Keywords:**  Quickly read through the code, looking for key terms and patterns:
    * `OriginTrial`, `TrialToken`, `Validate`, `Policy`, `Feature`, `Expiry`, `Secure`, `ThirdParty`. These words immediately suggest the core functionality.
    *  `#include` statements indicate dependencies. Notice `net/http/http_response_headers.h` and `net/url_request/url_request.h`, suggesting interaction with network requests and responses.
    *  Namespaces like `blink` and `mojom::OriginTrialFeature` point to the Blink engine and its interface definition language.
    *  Function names like `ValidateTokenAndTrial`, `ValidateToken`, `IsTokenValid`, `IsTokenExpired`, `ResponseBearsValidTokenForFeature` are strong indicators of core functions.

3. **Identify Core Functionality (High-Level):**  Based on the keywords and function names, it's clear that this file is responsible for validating Origin Trial tokens. This involves:
    * Parsing tokens.
    * Checking token signatures against public keys.
    * Verifying the token's validity for a given origin and time.
    * Checking for token expiry.
    * Determining if the associated feature is enabled.
    * Handling third-party tokens.
    * Interacting with an `OriginTrialPolicy` to get configuration.

4. **Map Functions to Functionality (Mid-Level):** Go through each significant function and understand its purpose:
    * `PolicyGetter()`:  A way to access the global `OriginTrialPolicy`. This is crucial for configuration.
    * `IsDeprecationTrialPossible()`: Checks if deprecation trials are allowed.
    * `IsTokenValid()`: The fundamental function for checking if a token is valid for a given origin. It distinguishes between first-party and third-party tokens.
    * `IsTokenExpired()`: Determines if a token has expired, considering potential grace periods for manual completion trials.
    * `ValidateTokenEnabled()`: Checks if a token is enabled, considering expiry, disabled features, and user-specific disablings.
    * `ValidateTokenAndTrial()`:  A higher-level function that validates a token and checks if the corresponding trial is valid. It handles both first-party and third-party scenarios.
    * `ValidateToken()`:  Focuses specifically on validating the token's signature and basic validity.
    * `RevalidateTokenAndTrial()`: Re-checks if a trial is enabled given its name, expiry, and signature.
    * `FeaturesEnabledByTrial()`:  Determines the features enabled by a given trial, including implied features.
    * `RequestEnablesFeature()` and `ResponseBearsValidTokenForFeature()`: Check if a network request or response carries a valid token for a specific feature.
    * `GetValidTokensFromHeaders()` and `GetValidTokens()`: Extract valid tokens from HTTP headers or a pre-existing map.
    * `IsTrialPossibleOnOrigin()`:  Determines if Origin Trials are generally possible for a given origin.

5. **Analyze Relationships with Web Technologies:**  Consider how Origin Trials interact with JavaScript, HTML, and CSS:
    * **JavaScript:** JavaScript uses APIs to detect if a feature is enabled by an Origin Trial. The validator ensures the tokens provided are valid.
    * **HTML:**  `<meta>` tags (though not explicitly mentioned in *this* file) are the primary way to provide Origin Trial tokens in HTML. This validator processes those tokens.
    * **CSS:** CSS features can be gated by Origin Trials. The validator ensures the tokens that enable those features are valid.

6. **Identify Logic and Assumptions:**  Focus on the conditional statements and loops to understand the decision-making process:
    * The distinction between first-party and third-party tokens and their validation logic.
    * The handling of expiry dates and grace periods.
    * The checks for disabled features (globally and for specific users).
    * The requirement for secure origins (with exceptions for deprecation trials).

7. **Consider Potential Errors:** Think about how developers might misuse Origin Trials and how this validator might catch those errors:
    * Providing an incorrect token string.
    * Using a token for the wrong origin.
    * Using an expired token.
    * Trying to use a token for a disabled feature.
    * Forgetting to include the token in the HTTP header or meta tag.
    * Misunderstanding the secure origin requirement.

8. **Structure the Answer:** Organize the findings into logical categories: Functionality, Relationships, Logic (with examples), and Usage Errors. Use clear and concise language.

9. **Refine and Add Detail:** Review the initial analysis and add more specific examples and explanations where needed. For instance, for the "Logic" section, provide concrete examples of input and output based on the function's purpose. For "Usage Errors," explain *why* these are errors in the context of Origin Trials.

10. **Self-Correction/Review:**  Read through the entire explanation to ensure accuracy and completeness. Are there any ambiguities?  Have all the key aspects of the file been covered?  For example, initially, I might have missed the detail about the expiry grace period, but a closer look at `IsTokenExpired()` would reveal that. Similarly, paying attention to the third-party origin validation logic requires careful reading of the loops and conditional checks in `IsTokenValid()` and `ValidateTokenAndTrialWithOriginInfo()`.
This C++ source file, `trial_token_validator.cc`, located within the `blink/common/origin_trials` directory of the Chromium Blink engine, is responsible for **validating Origin Trial tokens**.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Parsing and Basic Validation:**
   - It takes a string representing an Origin Trial token as input.
   - It uses `TrialToken::From()` to attempt to parse this string into a structured `TrialToken` object. This involves verifying the token's signature against known public keys.

2. **Origin Matching:**
   - It checks if the token is valid for a specific origin (the website or frame where the token is being used).
   - For third-party tokens, it validates against a list of allowed third-party origins.

3. **Expiry Date Validation:**
   - It verifies if the token's expiry date has passed the current time.
   - It handles a grace period for manual completion trials, where a token is considered valid for a short time after its nominal expiry.

4. **Feature and Token Enablement Checks:**
   - It consults an `OriginTrialPolicy` (obtained through a getter function) to determine if the specific feature associated with the token is currently enabled.
   - It also checks if the specific token signature has been disabled.
   - For subset trials, it checks if the feature is enabled for the current user.

5. **Secure Origin Enforcement:**
   - It ensures that Origin Trials are generally only active on secure origins (HTTPS).
   - It makes an exception for deprecation trials, which can sometimes be enabled on insecure origins for testing purposes.

6. **Integration with Network Requests:**
   - It provides functions to check if a network request's response headers contain a valid Origin Trial token for a specific feature.
   - It can extract all valid tokens from response headers for a given origin.

**Relationships with JavaScript, HTML, and CSS:**

Origin Trials are a mechanism to allow developers to experiment with experimental web platform features in a controlled manner. This file is crucial for enforcing the rules of these experiments. Here's how it relates:

* **JavaScript:**
    - **Detection:** JavaScript code can check if an Origin Trial is active for a particular feature using APIs like `navigator.originTrial.isFeatureEnabled()`. This validator is the underlying mechanism that determines if the trial is indeed enabled.
    - **Enabling Features:** When a browser encounters a valid Origin Trial token (e.g., in an HTTP header or `<meta>` tag), this validator determines if it unlocks the corresponding JavaScript API or behavior.

    * **Example:** A website wants to experiment with the "Web Serial API" before it's fully standardized. They obtain an Origin Trial token for this feature and include it in their HTTP response header. When the browser loads the page, `TrialTokenValidator` verifies the token. If valid, JavaScript code on that page can then successfully use the `navigator.serial` API.

* **HTML:**
    - **Token Delivery:** Origin Trial tokens can be delivered through `<meta>` tags in the HTML `<head>`.
    - **Processing:** When the HTML parser encounters an `Origin-Trial` meta tag, the browser extracts the token and uses this validator to determine its validity and enable the associated features.

    * **Example:**
      ```html
      <!DOCTYPE html>
      <html>
      <head>
        <meta http-equiv="origin-trial" content="YOUR_TRIAL_TOKEN_HERE">
        <title>Origin Trial Example</title>
      </head>
      <body>
        <script>
          if ('someExperimentalFeature' in window) {
            // Code that uses the experimental feature
          }
        </script>
      </body>
      </html>
      ```
      The `TrialTokenValidator` will process the token from the meta tag and, if valid, make `someExperimentalFeature` available in the JavaScript context.

* **CSS:**
    - **Feature Gating:** Some experimental CSS features are also gated by Origin Trials.
    - **Enabling CSS:** A valid Origin Trial token can enable the browser to understand and apply experimental CSS properties or selectors.

    * **Example:** Imagine an experimental CSS property called `::part()`. A valid Origin Trial token for this feature, validated by `TrialTokenValidator`, would allow the browser to correctly parse and apply styles using `::part()`. Without the valid token, the browser would likely ignore or treat the property as invalid.

**Logic and Assumptions (Hypothetical Examples):**

Let's consider the `ValidateTokenAndTrial` function:

**Assumption:** The `OriginTrialPolicy` is configured to enable a trial named "SuperFeature" and has the correct public key to verify tokens for this trial.

**Hypothetical Input 1:**

* `token`: A valid token string generated for the "SuperFeature" trial and the current origin "https://example.com".
* `origin`: The `url::Origin` object representing "https://example.com".
* `current_time`: The current time is before the token's expiry.

**Hypothetical Output 1:**

The function would return a `TrialTokenResult` with:
* `Status()`: `OriginTrialTokenStatus::kSuccess`
* `ParsedToken()`: A pointer to a `TrialToken` object representing the parsed token, with `feature_name()` equal to "SuperFeature".

**Hypothetical Input 2:**

* `token`: A valid token string for "SuperFeature", but intended for "https://different-origin.com".
* `origin`: The `url::Origin` object representing "https://example.com".
* `current_time`:  Irrelevant in this case as the origin mismatch will be detected first.

**Hypothetical Output 2:**

The function would return a `TrialTokenResult` with:
* `Status()`: `OriginTrialTokenStatus::kWrongOrigin`

**Hypothetical Input 3:**

* `token`: A valid token string for "SuperFeature" and the current origin, but the token's expiry date is in the past.
* `origin`: The `url::Origin` object representing "https://example.com".
* `current_time`: A time after the token's expiry.

**Hypothetical Output 3:**

The function would return a `TrialTokenResult` with:
* `Status()`: `OriginTrialTokenStatus::kExpired`

**User and Programming Common Usage Errors:**

1. **Incorrect Token String:** Providing a token string that is malformed, truncated, or has been tampered with. This will likely result in `OriginTrialTokenStatus::kInvalidSignature` or other parsing errors.

   * **Example:** A developer copies and pastes a token and accidentally misses a character.

2. **Token for the Wrong Origin:** Using a token that was generated for a different domain or subdomain. The validator will return `OriginTrialTokenStatus::kWrongOrigin`.

   * **Example:** A developer generates a token for `example.com` but tries to use it on `sub.example.com` without understanding subdomain matching rules.

3. **Expired Token:** Trying to use a token after its expiry date. The validator will return `OriginTrialTokenStatus::kExpired`.

   * **Example:** A developer forgets to update the Origin Trial token after its expiration period.

4. **Feature Not Enabled in Policy:**  The `OriginTrialPolicy` might not have the specific trial enabled, even if a valid token is present. The validator will return `OriginTrialTokenStatus::kUnknownTrial` or if the token parses correctly but the feature is disabled, `OriginTrialTokenStatus::kFeatureDisabled`.

   * **Example:** A developer uses a token for a feature that is still under development and not yet enabled in the browser's configuration.

5. **Using a Third-Party Token on a First-Party Origin (or vice-versa):**  Misunderstanding the scope of first-party and third-party tokens.

   * **Example:** Trying to use a token intended for inclusion in a top-level document's header within an iframe from a different origin.

6. **Insecure Context (for non-deprecation trials):** Attempting to use an Origin Trial (that isn't a deprecation trial explicitly allowed on insecure contexts) on an `http://` page. The validator will return `OriginTrialTokenStatus::kInsecure`.

   * **Example:** A developer tests an experimental feature on their local `http://localhost` without realizing the secure context requirement for regular Origin Trials.

7. **Token Disabled by Policy:**  The specific token signature might have been revoked or disabled through the `OriginTrialPolicy`. The validator will return `OriginTrialTokenStatus::kTokenDisabled`.

   * **Example:** A token is found to have been compromised or is being misused, so the browser vendor disables it.

8. **Misunderstanding Grace Periods:** For manual completion trials, developers might incorrectly assume the token is immediately invalid after the nominal expiry time, not realizing the short grace period.

In summary, `trial_token_validator.cc` is a critical component for the security and controlled rollout of experimental web features in Chromium. It ensures that only authorized origins can access these features within the defined timeframes and under the configured policies.

Prompt: 
```
这是目录为blink/common/origin_trials/trial_token_validator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/origin_trials/trial_token_validator.h"

#include <memory>
#include <string_view>

#include "base/check.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/no_destructor.h"
#include "base/time/time.h"
#include "net/http/http_response_headers.h"
#include "net/url_request/url_request.h"
#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "third_party/blink/public/common/origin_trials/origin_trial_policy.h"
#include "third_party/blink/public/common/origin_trials/origin_trials.h"
#include "third_party/blink/public/common/origin_trials/trial_token.h"
#include "third_party/blink/public/common/origin_trials/trial_token_result.h"
#include "third_party/blink/public/mojom/origin_trials/origin_trial_feature.mojom-shared.h"

namespace blink {
namespace {

static base::RepeatingCallback<OriginTrialPolicy*()>& PolicyGetter() {
  static base::NoDestructor<base::RepeatingCallback<OriginTrialPolicy*()>>
      policy(
          base::BindRepeating([]() -> OriginTrialPolicy* { return nullptr; }));
  return *policy;
}

bool IsDeprecationTrialPossible() {
  OriginTrialPolicy* policy = PolicyGetter().Run();
  return policy && policy->IsOriginTrialsSupported();
}

// Validates the provided trial_token. If provided, the third_party_origins is
// only used for validating third-party tokens.
OriginTrialTokenStatus IsTokenValid(
    const TrialToken& trial_token,
    const url::Origin& origin,
    base::span<const url::Origin> third_party_origins,
    base::Time current_time) {
  OriginTrialTokenStatus status;
  if (trial_token.is_third_party()) {
    if (!third_party_origins.empty()) {
      for (const auto& third_party_origin : third_party_origins) {
        status = trial_token.IsValid(third_party_origin, current_time);
        if (status == OriginTrialTokenStatus::kSuccess)
          break;
      }
    } else {
      status = OriginTrialTokenStatus::kWrongOrigin;
    }
  } else {
    status = trial_token.IsValid(origin, current_time);
  }
  return status;
}

// Determine if the the |token_expiry_time| should be considered as expired
// at |current_time| given the |trial_name|.
// Manual completion trials add an expiry grace period, which has to be taken
// into account to answer this question.
bool IsTokenExpired(std::string_view trial_name,
                    const base::Time token_expiry_time,
                    const base::Time current_time) {
  // Check token expiry.
  bool token_expired = token_expiry_time <= current_time;
  if (token_expired) {
    if (origin_trials::IsTrialValid(trial_name)) {
      // Manual completion trials have an expiry grace period. For these trials
      // the token expiry time is valid if:
      // token_expiry_time + kExpiryGracePeriod > current_time
      for (mojom::OriginTrialFeature feature :
           origin_trials::FeaturesForTrial(trial_name)) {
        if (origin_trials::FeatureHasExpiryGracePeriod(feature)) {
          if (token_expiry_time + kExpiryGracePeriod > current_time) {
            token_expired = false;  // consider the token non-expired
            break;
          }
        }
      }
    }
  }
  return token_expired;
}

// Validate that the passed token has not yet expired and that the trial or
// token has not been disabled.
OriginTrialTokenStatus ValidateTokenEnabled(
    const OriginTrialPolicy& policy,
    std::string_view trial_name,
    const base::Time token_expiry_time,
    const TrialToken::UsageRestriction usage_restriction,
    std::string_view token_signature,
    const base::Time current_time) {
  if (IsTokenExpired(trial_name, token_expiry_time, current_time))
    return OriginTrialTokenStatus::kExpired;

  if (policy.IsFeatureDisabled(trial_name))
    return OriginTrialTokenStatus::kFeatureDisabled;

  if (policy.IsTokenDisabled(token_signature))
    return OriginTrialTokenStatus::kTokenDisabled;

  if (usage_restriction == TrialToken::UsageRestriction::kSubset &&
      policy.IsFeatureDisabledForUser(trial_name)) {
    return OriginTrialTokenStatus::kFeatureDisabledForUser;
  }

  // All checks passed, return success
  return OriginTrialTokenStatus::kSuccess;
}

}  // namespace

TrialTokenValidator::OriginInfo::OriginInfo(const url::Origin& wrapped_origin)
    : origin(wrapped_origin) {
  is_secure = network::IsOriginPotentiallyTrustworthy(origin);
}

TrialTokenValidator::OriginInfo::OriginInfo(const url::Origin& wrapped_origin,
                                            bool origin_is_secure)
    : origin(wrapped_origin), is_secure(origin_is_secure) {}

TrialTokenValidator::TrialTokenValidator() = default;

TrialTokenValidator::~TrialTokenValidator() = default;

void TrialTokenValidator::SetOriginTrialPolicyGetter(
    base::RepeatingCallback<OriginTrialPolicy*()> policy_getter) {
  PolicyGetter() = policy_getter;
}

void TrialTokenValidator::ResetOriginTrialPolicyGetter() {
  SetOriginTrialPolicyGetter(
      base::BindRepeating([]() -> OriginTrialPolicy* { return nullptr; }));
}

TrialTokenResult TrialTokenValidator::ValidateTokenAndTrial(
    std::string_view token,
    const url::Origin& origin,
    base::Time current_time) const {
  return ValidateTokenAndTrialWithOriginInfo(
      token, OriginInfo(origin), base::span<const OriginInfo>{}, current_time);
}

TrialTokenResult TrialTokenValidator::ValidateTokenAndTrial(
    std::string_view token,
    const url::Origin& origin,
    base::span<const url::Origin> third_party_origins,
    base::Time current_time) const {
  std::vector<OriginInfo> third_party_origin_info;
  for (const url::Origin& third_party_origin : third_party_origins) {
    third_party_origin_info.emplace_back(third_party_origin);
  }
  return ValidateTokenAndTrialWithOriginInfo(
      token, OriginInfo(origin), third_party_origin_info, current_time);
}

TrialTokenResult TrialTokenValidator::ValidateTokenAndTrialWithOriginInfo(
    std::string_view token,
    const OriginInfo& origin,
    base::span<const OriginInfo> third_party_origin_info,
    base::Time current_time) const {
  std::vector<url::Origin> third_party_origins;
  for (const OriginInfo& info : third_party_origin_info) {
    third_party_origins.push_back(info.origin);
  }
  TrialTokenResult token_result =
      ValidateToken(token, origin.origin, third_party_origins, current_time);

  if (token_result.Status() != OriginTrialTokenStatus::kSuccess)
    return token_result;

  const TrialToken& parsed_token = *token_result.ParsedToken();

  if (!origin_trials::IsTrialValid(parsed_token.feature_name())) {
    token_result.SetStatus(OriginTrialTokenStatus::kUnknownTrial);
    return token_result;
  }

  if (parsed_token.is_third_party() &&
      !origin_trials::IsTrialEnabledForThirdPartyOrigins(
          parsed_token.feature_name())) {
    DVLOG(1) << "ValidateTokenAndTrial: feature disabled for third party trial";
    token_result.SetStatus(OriginTrialTokenStatus::kFeatureDisabled);
    return token_result;
  }

  // Origin trials are only enabled for secure origins. The only exception
  // is for deprecation trials. For those, the secure origin check can be
  // skipped.
  if (origin_trials::IsTrialEnabledForInsecureContext(
          parsed_token.feature_name())) {
    return token_result;
  }

  bool is_secure = origin.is_secure;
  if (parsed_token.is_third_party()) {
    // For third-party tokens, both the current origin and the script origin
    // must be secure. Due to subdomain matching, the token origin might not
    // be an exact match for one of the provided script origins, and the result
    // doesn't indicate which specific origin was matched. This means it's not
    // a direct lookup to find the appropriate script origin. To avoid re-doing
    // all the origin comparisons, there are shortcuts that depend on how many
    // script origins were provided. There must be at least one, or the third
    // party token would not be validated successfully.
    DCHECK(!third_party_origin_info.empty());
    if (third_party_origin_info.size() == 1) {
      // Only one script origin, it must be the origin used for validation.
      is_secure &= third_party_origin_info[0].is_secure;
    } else {
      // Match the origin in the token to one of the multiple script origins, if
      // necessary. If all the provided origins are secure, then it doesn't
      // matter which one matched. Only insecure origins need to be matched.
      bool is_script_origin_secure = true;
      for (const OriginInfo& script_origin_info : third_party_origin_info) {
        if (script_origin_info.is_secure) {
          continue;
        }
        // Re-use the IsValid() check, as it contains the subdomain matching
        // logic. The token validation takes the first valid match, so can
        // assume that success means it was the origin used.
        if (parsed_token.IsValid(script_origin_info.origin, current_time) ==
            OriginTrialTokenStatus::kSuccess) {
          is_script_origin_secure = false;
          break;
        }
      }
      is_secure &= is_script_origin_secure;
    }
  }

  if (!is_secure) {
    DVLOG(1) << "ValidateTokenAndTrial: not secure";
    token_result.SetStatus(OriginTrialTokenStatus::kInsecure);
  }

  return token_result;
}

TrialTokenResult TrialTokenValidator::ValidateToken(
    std::string_view token,
    const url::Origin& origin,
    base::Time current_time) const {
  return ValidateToken(token, origin, base::span<const url::Origin>{},
                       current_time);
}

TrialTokenResult TrialTokenValidator::ValidateToken(
    std::string_view token,
    const url::Origin& origin,
    base::span<const url::Origin> third_party_origins,
    base::Time current_time) const {
  OriginTrialPolicy* policy = PolicyGetter().Run();

  if (!policy || !policy->IsOriginTrialsSupported())
    return TrialTokenResult(OriginTrialTokenStatus::kNotSupported);

  std::vector<OriginTrialPublicKey> public_keys = policy->GetPublicKeys();
  if (public_keys.size() == 0)
    return TrialTokenResult(OriginTrialTokenStatus::kNotSupported);

  OriginTrialTokenStatus status;
  std::unique_ptr<TrialToken> trial_token;
  for (OriginTrialPublicKey& key : public_keys) {
    trial_token = TrialToken::From(token, key, &status);
    if (status == OriginTrialTokenStatus::kSuccess)
      break;
  }

  // Not attaching trial_token to result when token is unable to parse.
  if (status != OriginTrialTokenStatus::kSuccess)
    return TrialTokenResult(status);

  status =
      IsTokenValid(*trial_token, origin, third_party_origins, current_time);

  if (status == OriginTrialTokenStatus::kSuccess ||
      status == OriginTrialTokenStatus::kExpired) {
    // Since manual completion trials have a grace period, we need to check
    // expired tokens in addition to valid tokens.
    status = ValidateTokenEnabled(*policy, trial_token->feature_name(),
                                  trial_token->expiry_time(),
                                  trial_token->usage_restriction(),
                                  trial_token->signature(), current_time);
  }
  return TrialTokenResult(status, std::move(trial_token));
}

bool TrialTokenValidator::RevalidateTokenAndTrial(
    std::string_view trial_name,
    const base::Time token_expiry_time,
    const TrialToken::UsageRestriction usage_restriction,
    std::string_view token_signature,
    const base::Time current_time) const {
  OriginTrialPolicy* policy = PolicyGetter().Run();

  if (!policy || !policy->IsOriginTrialsSupported())
    return false;

  if (!origin_trials::IsTrialValid(trial_name))
    return false;

  OriginTrialTokenStatus status =
      ValidateTokenEnabled(*policy, trial_name, token_expiry_time,
                           usage_restriction, token_signature, current_time);
  return status == OriginTrialTokenStatus::kSuccess;
}

std::vector<mojom::OriginTrialFeature>
TrialTokenValidator::FeaturesEnabledByTrial(std::string_view trial_name) {
  std::vector<mojom::OriginTrialFeature> enabled_features;
  base::span<const mojom::OriginTrialFeature> features =
      origin_trials::FeaturesForTrial(trial_name);
  for (const mojom::OriginTrialFeature feature : features) {
    if (origin_trials::FeatureEnabledForOS(feature)) {
      enabled_features.push_back(feature);
      // Also add implied features
      for (const mojom::OriginTrialFeature implied_feature :
           origin_trials::GetImpliedFeatures(feature)) {
        enabled_features.push_back(implied_feature);
      }
    }
  }
  return enabled_features;
}

bool TrialTokenValidator::TrialEnablesFeaturesForOS(
    std::string_view trial_name) {
  return !FeaturesEnabledByTrial(trial_name).empty();
}

bool TrialTokenValidator::RequestEnablesFeature(const net::URLRequest* request,
                                                std::string_view feature_name,
                                                base::Time current_time) const {
  // TODO(mek): Possibly cache the features that are availble for request in
  // UserData associated with the request.
  return RequestEnablesFeature(request->url(), request->response_headers(),
                               feature_name, current_time);
}

bool TrialTokenValidator::RequestEnablesFeature(
    const GURL& request_url,
    const net::HttpResponseHeaders* response_headers,
    std::string_view feature_name,
    base::Time current_time) const {
  return IsTrialPossibleOnOrigin(request_url) &&
         ResponseBearsValidTokenForFeature(request_url, *response_headers,
                                           feature_name, current_time);
}

bool TrialTokenValidator::RequestEnablesDeprecatedFeature(
    const GURL& request_url,
    const net::HttpResponseHeaders* response_headers,
    std::string_view feature_name,
    base::Time current_time) const {
  return IsDeprecationTrialPossible() &&
         ResponseBearsValidTokenForFeature(request_url, *response_headers,
                                           feature_name, current_time);
}

bool TrialTokenValidator::ResponseBearsValidTokenForFeature(
    const GURL& request_url,
    const net::HttpResponseHeaders& response_headers,
    std::string_view feature_name,
    base::Time current_time) const {
  url::Origin origin = url::Origin::Create(request_url);
  size_t iter = 0;
  std::string token;
  while (response_headers.EnumerateHeader(&iter, "Origin-Trial", &token)) {
    TrialTokenResult result =
        ValidateTokenAndTrial(token, origin, current_time);
    // TODO(mek): Log the validation errors to histograms?
    if (result.Status() == OriginTrialTokenStatus::kSuccess)
      if (result.ParsedToken()->feature_name() == feature_name)
        return true;
  }
  return false;
}

std::unique_ptr<TrialTokenValidator::FeatureToTokensMap>
TrialTokenValidator::GetValidTokensFromHeaders(
    const url::Origin& origin,
    const net::HttpResponseHeaders* headers,
    base::Time current_time) const {
  std::unique_ptr<FeatureToTokensMap> tokens(
      std::make_unique<FeatureToTokensMap>());
  if (!IsTrialPossibleOnOrigin(origin.GetURL()))
    return tokens;

  size_t iter = 0;
  std::string token;
  while (headers->EnumerateHeader(&iter, "Origin-Trial", &token)) {
    TrialTokenResult result = ValidateToken(token, origin, current_time);
    if (result.Status() == OriginTrialTokenStatus::kSuccess) {
      (*tokens)[result.ParsedToken()->feature_name()].push_back(token);
    }
  }
  return tokens;
}

std::unique_ptr<TrialTokenValidator::FeatureToTokensMap>
TrialTokenValidator::GetValidTokens(const url::Origin& origin,
                                    const FeatureToTokensMap& tokens,
                                    base::Time current_time) const {
  std::unique_ptr<FeatureToTokensMap> out_tokens(
      std::make_unique<FeatureToTokensMap>());
  if (!IsTrialPossibleOnOrigin(origin.GetURL()))
    return out_tokens;

  for (const auto& feature : tokens) {
    for (const std::string& token : feature.second) {
      TrialTokenResult result = ValidateToken(token, origin, current_time);
      if (result.Status() == OriginTrialTokenStatus::kSuccess) {
        DCHECK_EQ(result.ParsedToken()->feature_name(), feature.first);
        (*out_tokens)[feature.first].push_back(token);
      }
    }
  }
  return out_tokens;
}

// static
bool TrialTokenValidator::IsTrialPossibleOnOrigin(const GURL& url) {
  OriginTrialPolicy* policy = PolicyGetter().Run();
  return policy && policy->IsOriginTrialsSupported() &&
         policy->IsOriginSecure(url);
}

}  // namespace blink

"""

```
Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Understanding: The Big Picture**

The filename `origin_trial_context_test.cc` immediately tells us this is a *test file*. The `origin_trials` part suggests it's testing functionality related to enabling experimental browser features through origin trials. The `Context` part implies it's likely testing a central class or component responsible for managing these trials within a specific execution context (like a web page).

**2. Examining the Includes: Key Dependencies**

The included headers provide crucial information about the file's purpose:

*   `origin_trial_context.h`: This is the header file for the class being tested. We know immediately there's an `OriginTrialContext` class.
*   `testing/gtest/include/gtest/gtest.h`:  Confirms this is a Google Test based unit test. We'll see `TEST_F` macros later.
*   `third_party/blink/public/common/features.h`, `origin_trials/*.h`:  These point to the core Blink origin trial infrastructure, defining features, tokens, and validation logic.
*   `third_party/blink/public/mojom/origin_trials/*.mojom-shared.h`: Indicates interaction with the Chromium Mojo system, suggesting communication across process boundaries (though this test might be isolated).
*   `third_party/blink/renderer/core/…`: These include headers from the Blink rendering engine, such as DOM elements (`HTMLHeadElement`, `HTMLMetaElement`), frames (`LocalFrame`, `LocalDOMWindow`), and security (`SecurityOrigin`). This tells us the tests are simulating scenarios within a web page.
*   `third_party/blink/renderer/platform/…`:  Includes platform-level utilities like `TaskEnvironment` for managing asynchronous tasks.

**3. Identifying Core Functionality: The Tests Themselves**

The `TEST_F` macros define individual test cases. Reading the names of these tests reveals the specific functionalities being verified:

*   `ValidatorGetsCorrectInfo`, `ValidatorGetsCorrectSecurityInfoForInsecureOrigins`, `ValidatorGetsCorrectSecurityInfoThirdParty`: Focuses on verifying that the `OriginTrialContext` correctly passes information to the `TrialTokenValidator`. This is crucial for security and correctness.
*   `EnabledNonExistingTrial`, `EnabledSecureRegisteredOrigin`, `ThirdPartyTrialWithThirdPartyTokenEnabled`: Checks the basic enabling/disabling logic based on token validity and origin type.
*   `InvalidTokenResponseFromPlatform`, `FeatureNotEnableOnInsecureOrigin`, `FeatureNotEnableOnInsecureThirdPartyOrigin`:  Tests negative cases where features *should not* be enabled.
*   `ParseHeaderValue`, `ParseHeaderValue_NotCommaSeparated`:  Focuses on the parsing of the `Origin-Trial` HTTP header.
*   `PermissionsPolicy`:  Tests the integration with the Permissions Policy feature, showing how origin trials can enable policy directives.
*   `GetEnabledNavigationFeatures`, `ActivateNavigationFeature`: Deals with navigation-scoped origin trials.
*   `GetTokenExpiryTimeIgnoresIrrelevantTokens`, `LastExpiryForFeatureIsUsed`, `ImpliedFeatureExpiryTimesAreUpdated`:  Verifies how expiry times are handled for different scenarios.
*   `SettingFeatureUpdatesDocumentSettings`:  Checks if enabling an origin trial can affect browser settings.
*   `AddedFeaturesAreMappedToTokens`:  Tests the internal mapping of features to the tokens that enabled them.
*   The `OriginTrialContextDevtoolsTest` suite: Focuses on providing information for developer tools about the status of origin trials.

**4. Looking for Relationships with Web Technologies (JavaScript, HTML, CSS)**

Based on the included headers and test names, we can infer the relationships:

*   **HTML:** The inclusion of `HTMLHeadElement` and `HTMLMetaElement` suggests that origin trial tokens can be provided via `<meta>` tags in the HTML `<head>`. The tests don't directly *manipulate* these elements, but the context is set up as if they exist.
*   **JavaScript:** While not explicitly included in the headers, the concept of "enabling features" strongly implies that these features would be accessible and usable by JavaScript code. Origin trials are a mechanism to allow developers to experiment with new JavaScript APIs or modify existing ones.
*   **CSS:**  It's less direct, but some origin trials *could* enable new CSS features or modify existing ones. The test file doesn't have explicit CSS interactions, but the general principle of enabling browser features applies.

**5. Analyzing the Mocking Strategy**

The use of `MockTokenValidator` is a key aspect. This tells us:

*   The tests are designed to be isolated and fast. They don't rely on the actual complex logic of token validation.
*   The focus is on testing the `OriginTrialContext`'s interaction with the validator – ensuring it calls the validator with the correct arguments and reacts appropriately to the validator's responses.

**6. Inferring Logical Reasoning and Examples**

By looking at the test names and the setup within each test, we can infer the underlying logic:

*   **Input:** A web page loaded at a specific origin, potentially containing `<meta>` tags with origin trial tokens or having tokens added via JavaScript (though not directly tested here).
*   **Processing:** The `OriginTrialContext` parses and validates these tokens using the `TrialTokenValidator`.
*   **Output:** The ability to determine if a specific origin trial feature is enabled (`IsFeatureEnabled`), the expiry time of the feature (`GetFeatureExpiry`), and information for developer tools (`GetOriginTrialResultsForDevtools`).

**7. Identifying Potential User/Programming Errors**

By looking at the negative test cases and the overall flow:

*   **Incorrect Token:** Providing an invalid, expired, or malformed token will prevent the feature from being enabled.
*   **Insecure Origin:** Features requiring secure contexts won't be enabled on `http://` pages.
*   **Third-Party Restrictions:**  Tokens intended for first-party origins won't work for third-party scripts, and vice-versa.
*   **Typos in Trial Names:** Incorrectly specifying the trial name will result in the token not being recognized.
*   **Forgetting to Enable the Feature Flag:** Even with a valid token, if the underlying feature flag in Chromium is disabled, the origin trial won't be effective (as demonstrated in the `DependentFeatureNotEnabled` test).

**Self-Correction/Refinement during the Process:**

*   Initially, I might have assumed more direct interaction with HTML. However, looking at the test setup, it's more about *simulating* the presence of tokens rather than actively manipulating the DOM.
*   The `mojom` includes initially suggested cross-process communication. However, the mocking strategy and the use of `NullExecutionContext` suggest that these tests are likely running within a single process for simplicity. The `mojom` interfaces are still used to define the structure of the data being exchanged.

By following this kind of detailed examination of the code structure, includes, test names, and mocking strategies, we can build a comprehensive understanding of the functionality being tested and its relationship to web technologies and potential errors.
这个文件 `origin_trial_context_test.cc` 是 Chromium Blink 引擎中 `blink/renderer/core/origin_trials/origin_trial_context.h` 对应类的单元测试文件。它主要的功能是测试 `OriginTrialContext` 类的各种方法和功能是否按预期工作。

以下是该文件测试的功能的详细列表，并解释了它与 JavaScript、HTML、CSS 的关系，逻辑推理，以及可能的用户/编程错误：

**文件主要功能:**

1. **Token 的添加和验证:**
    *   测试 `OriginTrialContext` 是否能正确接收并处理 Origin Trial 的 token (通过 HTTP 头或 `<meta>` 标签)。
    *   使用 `MockTokenValidator` 模拟 token 验证过程，验证 `OriginTrialContext` 是否向 validator 传递了正确的信息（token 字符串、当前页面的 Origin、是否是安全上下文等）。
    *   测试不同验证结果（成功、失败、过期、无效签名等）对功能是否启用的影响。

2. **功能是否启用 (IsFeatureEnabled):**
    *   测试在提供有效 token 的情况下，对应的 Origin Trial 功能是否被正确启用。
    *   测试在没有提供有效 token 或 token 无效的情况下，功能是否保持禁用状态。
    *   测试针对安全上下文 (HTTPS) 和非安全上下文 (HTTP) 的 token 处理是否符合预期。
    *   测试针对第一方和第三方 Origin 的 token 处理是否正确。

3. **HTTP Header 解析:**
    *   测试 `OriginTrialContext::ParseHeaderValue` 方法是否能正确解析 `Origin-Trial` HTTP 响应头中的 token 字符串，处理空格、引号、逗号等分隔符。

4. **与 Permissions Policy 的集成:**
    *   测试 Origin Trial 如何与 Permissions Policy 集成。通过启用 Origin Trial，可以使得相应的 Permissions Policy 功能生效。

5. **导航相关的 Origin Trial 功能:**
    *   测试针对导航的 Origin Trial 功能的处理，例如 `GetEnabledNavigationFeatures` 返回启用的导航功能列表，以及 `ActivateNavigationFeature` 如何激活导航功能。

6. **Token 过期时间:**
    *   测试 `GetFeatureExpiry` 方法是否能正确获取已启用功能的过期时间。
    *   测试当收到多个 token 时，如何确定最终的过期时间。

7. **Document Settings 的更新:**
    *   测试启用某些 Origin Trial 功能是否会影响到 `DocumentSettings` 中的配置项。

8. **DevTools 的支持:**
    *   测试 `GetOriginTrialResultsForDevtools` 方法，该方法用于向开发者工具提供 Origin Trial 的状态信息，包括 token 的验证状态、功能是否启用等。

**与 JavaScript, HTML, CSS 的关系:**

*   **HTML:**
    *   **`<meta>` 标签:** Origin Trial 的 token 可以通过 `<meta http-equiv="Origin-Trial" content="...">` 标签添加到 HTML 文档的 `<head>` 部分。该测试模拟了浏览器解析 HTML 并提取 token 的过程。
        *   **举例:**  测试会模拟页面加载，并假定 `<meta>` 标签中包含了有效的 token，然后验证对应的功能是否被启用。
    *   该测试会创建 `HTMLHeadElement` 和 `HTMLMetaElement` 的实例来模拟 HTML 结构，虽然它本身不直接操作 HTML 解析器。

*   **JavaScript:**
    *   **API 的启用:** Origin Trial 的目的是让开发者能够试用实验性的 JavaScript API 或浏览器功能。如果 Origin Trial 成功启用，JavaScript 代码就可以使用这些新的 API。
        *   **举例:**  虽然测试本身不包含 JavaScript 代码，但测试的核心目标是验证某个 Origin Trial 是否成功启用，而这个启用的结果会直接影响到 JavaScript 代码的行为。例如，如果某个 Origin Trial 启用了新的 `navigator.mediaDevices` 方法，那么测试会确保在 token 有效的情况下，这个方法在 JavaScript 中是可用的（虽然测试本身不运行 JavaScript 代码）。
    *   **HTTP Header 的影响:** JavaScript 可以通过 `fetch` 或 `XMLHttpRequest` 发起请求，服务器可以在响应头中设置 `Origin-Trial`，从而影响当前页面的 Origin Trial 状态。测试模拟了浏览器接收并处理这些 HTTP 头信息的过程。

*   **CSS:**
    *   **CSS 功能的启用:**  Origin Trial 也可以用于测试新的 CSS 功能。
        *   **举例:**  如果某个 Origin Trial 旨在测试新的 CSS 属性，那么测试会验证在提供有效 token 的情况下，这个 CSS 属性是否会被浏览器识别和应用（虽然测试本身不直接渲染 CSS）。

**逻辑推理 (假设输入与输出):**

*   **假设输入:**
    *   当前页面的 URL 是 `https://www.example.com`。
    *   HTML 中包含 `<meta http-equiv="Origin-Trial" content="valid_token_for_frobulate">`。
    *   `valid_token_for_frobulate` 是一个针对 "Frobulate" 功能且对 `https://www.example.com` 有效的 token。
*   **逻辑推理:** `OriginTrialContext` 会解析 `<meta>` 标签，将 token 传递给 `MockTokenValidator` 进行验证。`MockTokenValidator` 被配置为在收到该 token 时返回成功状态。
*   **输出:** `IsFeatureEnabled(mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI)` 将返回 `true`，表示 "Frobulate" 功能已启用。

*   **假设输入:**
    *   当前页面的 URL 是 `http://www.example.com` (注意是非安全上下文)。
    *   HTML 中包含针对 "Frobulate" 功能的有效 token (假设 token 没有限制安全上下文)。
*   **逻辑推理:** `OriginTrialContext` 会解析 token，但由于当前页面是非安全上下文，并且 "Frobulate" 功能可能要求安全上下文，验证器可能会返回 `kInsecure` 状态。
*   **输出:** `IsFeatureEnabled(mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI)` 将返回 `false`。

**用户或者编程常见的使用错误:**

*   **Token 错误:**
    *   **拼写错误:** 用户在 `<meta>` 标签或 HTTP 头中输入了错误的 token 字符串。
        *   **举例:** `<meta http-equiv="Origin-Trial" content="invlid_tolen">`
    *   **Token 过期:** 使用了过期的 token。
        *   **举例:**  测试中模拟了 token 过期的情况，验证功能不会被启用。
    *   **Token 与 Origin 不匹配:**  Token 是为其他 Origin 生成的，不适用于当前页面。
        *   **举例:**  测试中会设置不同的 Origin 并验证 token 是否生效。
    *   **Token 签名无效:** Token 被篡改或签名验证失败。
        *   **举例:** 测试中模拟了无效签名的情况。

*   **配置错误:**
    *   **未启用 Feature Flag:**  即使提供了有效的 Origin Trial token，如果 Chromium 的 Feature Flag 本身没有启用，该功能仍然不会生效。
        *   **举例:** `DependentFeatureNotEnabled` 测试验证了这种情况。
    *   **错误的 `<meta>` 标签属性:**  使用了错误的 `http-equiv` 属性值，例如 `<meta name="Origin-Trial" ...>`。

*   **开发调试错误:**
    *   **混淆测试环境:**  在本地测试时，可能会与之前设置的 Origin Trial 状态冲突。
    *   **不理解 DevTools 的输出:**  开发者可能不理解 DevTools 中显示的 Origin Trial 状态信息，导致误判。

总而言之，`origin_trial_context_test.cc` 是一个非常重要的测试文件，它确保了 Origin Trial 机制的核心组件 `OriginTrialContext` 的正确性，这对于 Chromium 能够安全可靠地进行实验性功能部署至关重要。它通过模拟各种场景，包括不同的 token 状态、Origin 类型、HTTP 头信息等，来验证 `OriginTrialContext` 的行为是否符合预期。

### 提示词
```
这是目录为blink/renderer/core/origin_trials/origin_trial_context_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include <memory>
#include <string_view>
#include <vector>

#include "base/containers/span.h"
#include "base/ranges/algorithm.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/origin_trials/origin_trials.h"
#include "third_party/blink/public/common/origin_trials/trial_token.h"
#include "third_party/blink/public/common/origin_trials/trial_token_result.h"
#include "third_party/blink/public/common/origin_trials/trial_token_validator.h"
#include "third_party/blink/public/mojom/origin_trials/origin_trial_feature.mojom-shared.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_meta_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/permissions_policy/permissions_policy_parser.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {
namespace {

const char kUnknownTrialName[] = "UnknownTrial";
const char kFrobulateTrialName[] = "Frobulate";
const char kFrobulateThirdPartyTrialName[] = "FrobulateThirdParty";
const char kFrobulateNavigationTrialName[] = "FrobulateNavigation";
const char kFrobulateDeprecationTrialName[] = "FrobulateDeprecation";
const char kFrobulateBrowserReadWriteTrialName[] = "FrobulateBrowserReadWrite";
const char kFrobulateEnabledOrigin[] = "https://www.example.com";
const char kFrobulateEnabledOriginInsecure[] = "http://www.example.com";
const char kUnrelatedSecureOrigin[] = "https://other.example.com";

// The tokens expire in 2033.
const base::Time kBaseTokenExpiryTime = base::Time::FromTimeT(2000000000);

// Trial token placeholder for mocked calls to validator
const char kTokenPlaceholder[] = "The token contents are not used";

// Since all of trial token validation is tested elsewhere,
// this mock lets us test the context in isolation and assert
// that correct parameters are passed to the validator
// without having to generate a large number of valid tokens
class MockTokenValidator : public TrialTokenValidator {
 public:
  struct MockResponse {
    OriginTrialTokenStatus status = OriginTrialTokenStatus::kNotSupported;
    std::string feature;
    url::Origin origin;
    base::Time expiry = kBaseTokenExpiryTime;
  };

  struct ValidationParams {
    const std::string token;
    const OriginInfo origin;
    Vector<OriginInfo> third_party_origin_info;
    const base::Time current_time;
    ValidationParams(std::string_view token_param,
                     const OriginInfo& origin_info,
                     base::span<const OriginInfo> scripts,
                     base::Time time)
        : token(token_param), origin(origin_info), current_time(time) {
      third_party_origin_info.AppendRange(scripts.begin(), scripts.end());
    }
  };

  MockTokenValidator() = default;
  MockTokenValidator(const MockTokenValidator&) = delete;
  MockTokenValidator& operator=(const MockTokenValidator&) = delete;
  ~MockTokenValidator() override = default;

  TrialTokenResult ValidateTokenAndTrialWithOriginInfo(
      std::string_view token,
      const OriginInfo& origin,
      base::span<const OriginInfo> third_party_origin_info,
      base::Time current_time) const override {
    validation_params_.emplace_back(token, origin, third_party_origin_info,
                                    current_time);
    if (response_.status == OriginTrialTokenStatus::kMalformed) {
      return TrialTokenResult(response_.status);
    } else {
      return TrialTokenResult(
          response_.status,
          TrialToken::CreateTrialTokenForTesting(
              origin.origin, false, response_.feature, response_.expiry, false,
              TrialToken::UsageRestriction::kNone, ""));
    }
  }

  void SetResponse(MockResponse response) { response_ = response; }

  Vector<ValidationParams> GetValidationParams() const {
    return validation_params_;
  }

 private:
  MockResponse response_;
  mutable Vector<ValidationParams> validation_params_;
};

}  // namespace

class OriginTrialContextTest : public testing::Test {
 protected:
  OriginTrialContextTest()
      : token_validator_(new MockTokenValidator()),
        execution_context_(MakeGarbageCollected<NullExecutionContext>()) {
    execution_context_->GetOriginTrialContext()
        ->SetTrialTokenValidatorForTesting(
            std::unique_ptr<MockTokenValidator>(token_validator_));
  }
  ~OriginTrialContextTest() override {
    execution_context_->NotifyContextDestroyed();
    // token_validator_ is deleted by the unique_ptr handed to the
    // OriginTrialContext
  }

  void UpdateSecurityOrigin(const String& origin) {
    KURL page_url(origin);
    scoped_refptr<SecurityOrigin> page_origin =
        SecurityOrigin::Create(page_url);
    execution_context_->GetSecurityContext().SetSecurityOrigin(page_origin);
  }

  void AddTokenWithResponse(MockTokenValidator::MockResponse response) {
    token_validator_->SetResponse(std::move(response));
    execution_context_->GetOriginTrialContext()->AddToken(kTokenPlaceholder);
  }

  void AddTokenWithResponse(const std::string& trial_name,
                            OriginTrialTokenStatus validation_status) {
    AddTokenWithResponse({.status = validation_status, .feature = trial_name});
  }

  void AddTokenForThirdPartyOriginsWithResponse(
      const std::string& trial_name,
      OriginTrialTokenStatus validation_status,
      const Vector<String>& script_origins) {
    token_validator_->SetResponse(
        {.status = validation_status, .feature = trial_name});
    Vector<scoped_refptr<SecurityOrigin>> external_origins;
    for (const auto& script_origin : script_origins) {
      KURL script_url(script_origin);
      external_origins.emplace_back(SecurityOrigin::Create(script_url));
    };
    execution_context_->GetOriginTrialContext()->AddTokenFromExternalScript(
        kTokenPlaceholder, external_origins);
  }

  bool IsFeatureEnabled(mojom::blink::OriginTrialFeature feature) {
    return execution_context_->GetOriginTrialContext()->IsFeatureEnabled(
        feature);
  }

  base::Time GetFeatureExpiry(mojom::blink::OriginTrialFeature feature) {
    return execution_context_->GetOriginTrialContext()->GetFeatureExpiry(
        feature);
  }

  std::unique_ptr<Vector<mojom::blink::OriginTrialFeature>>
  GetEnabledNavigationFeatures() {
    return execution_context_->GetOriginTrialContext()
        ->GetEnabledNavigationFeatures();
  }

  HashMap<mojom::blink::OriginTrialFeature, Vector<String>>
  GetFeatureToTokens() {
    return execution_context_->GetOriginTrialContext()
        ->GetFeatureToTokensForTesting();
  }

  bool ActivateNavigationFeature(mojom::blink::OriginTrialFeature feature) {
    execution_context_->GetOriginTrialContext()
        ->ActivateNavigationFeaturesFromInitiator({feature});
    return execution_context_->GetOriginTrialContext()
        ->IsNavigationFeatureActivated(feature);
  }

 protected:
  test::TaskEnvironment task_environment_;
  MockTokenValidator* token_validator_;
  Persistent<NullExecutionContext> execution_context_;
};

// Test that we're passing correct information to the validator
TEST_F(OriginTrialContextTest, ValidatorGetsCorrectInfo) {
  UpdateSecurityOrigin(kFrobulateEnabledOrigin);

  AddTokenWithResponse(kFrobulateTrialName, OriginTrialTokenStatus::kSuccess);

  Vector<MockTokenValidator::ValidationParams> validation_params =
      token_validator_->GetValidationParams();
  ASSERT_EQ(1ul, validation_params.size());
  EXPECT_EQ(url::Origin::Create(GURL(kFrobulateEnabledOrigin)),
            validation_params[0].origin.origin);
  EXPECT_TRUE(validation_params[0].origin.is_secure);
  EXPECT_TRUE(validation_params[0].third_party_origin_info.empty());

  // Check that the "expected" token is passed to the validator
  EXPECT_EQ(kTokenPlaceholder, validation_params[0].token);

  // Check that the passed current_time to the validator was within a reasonable
  // bound (+-5 minutes) of the current time, since the context is passing
  // base::Time::Now() when it calls the function.
  ASSERT_LT(base::Time::Now() - validation_params[0].current_time,
            base::Minutes(5));
  ASSERT_LT(validation_params[0].current_time - base::Time::Now(),
            base::Minutes(5));
}

// Test that we're passing correct security information to the validator
TEST_F(OriginTrialContextTest,
       ValidatorGetsCorrectSecurityInfoForInsecureOrigins) {
  UpdateSecurityOrigin(kFrobulateEnabledOriginInsecure);

  AddTokenWithResponse(kFrobulateTrialName, OriginTrialTokenStatus::kInsecure);

  Vector<MockTokenValidator::ValidationParams> validation_params =
      token_validator_->GetValidationParams();
  ASSERT_EQ(1ul, validation_params.size());
  EXPECT_EQ(url::Origin::Create(GURL(kFrobulateEnabledOriginInsecure)),
            validation_params[0].origin.origin);
  EXPECT_FALSE(validation_params[0].origin.is_secure);
  EXPECT_TRUE(validation_params[0].third_party_origin_info.empty());
}

// Test that we're passing correct security information to the validator
TEST_F(OriginTrialContextTest, ValidatorGetsCorrectSecurityInfoThirdParty) {
  UpdateSecurityOrigin(kFrobulateEnabledOrigin);

  AddTokenForThirdPartyOriginsWithResponse(
      kFrobulateThirdPartyTrialName, OriginTrialTokenStatus::kInsecure,
      {kUnrelatedSecureOrigin, kFrobulateEnabledOriginInsecure});

  Vector<MockTokenValidator::ValidationParams> validation_params =
      token_validator_->GetValidationParams();
  ASSERT_EQ(1ul, validation_params.size());
  EXPECT_EQ(url::Origin::Create(GURL(kFrobulateEnabledOrigin)),
            validation_params[0].origin.origin);
  EXPECT_TRUE(validation_params[0].origin.is_secure);

  EXPECT_EQ(2ul, validation_params[0].third_party_origin_info.size());
  auto unrelated_info = base::ranges::find_if(
      validation_params[0].third_party_origin_info,
      [](const TrialTokenValidator::OriginInfo& item) {
        return item.origin.IsSameOriginWith(GURL(kUnrelatedSecureOrigin));
      });
  ASSERT_NE(validation_params[0].third_party_origin_info.end(), unrelated_info);
  EXPECT_TRUE(unrelated_info->is_secure);

  auto insecure_origin_info =
      base::ranges::find_if(validation_params[0].third_party_origin_info,
                            [](const TrialTokenValidator::OriginInfo& item) {
                              return item.origin.IsSameOriginWith(
                                  GURL(kFrobulateEnabledOriginInsecure));
                            });
  ASSERT_NE(validation_params[0].third_party_origin_info.end(),
            insecure_origin_info);
  EXPECT_FALSE(insecure_origin_info->is_secure);
}

// Test that unrelated features are not enabled
TEST_F(OriginTrialContextTest, EnabledNonExistingTrial) {
  UpdateSecurityOrigin(kFrobulateEnabledOrigin);

  AddTokenWithResponse(kFrobulateTrialName, OriginTrialTokenStatus::kSuccess);

  bool is_non_existing_feature_enabled =
      IsFeatureEnabled(mojom::blink::OriginTrialFeature::kNonExisting);
  EXPECT_FALSE(is_non_existing_feature_enabled);
}

// The feature should be enabled if a valid token for the origin is provided
TEST_F(OriginTrialContextTest, EnabledSecureRegisteredOrigin) {
  UpdateSecurityOrigin(kFrobulateEnabledOrigin);

  AddTokenWithResponse(kFrobulateTrialName, OriginTrialTokenStatus::kSuccess);
  bool is_origin_enabled = IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI);
  EXPECT_TRUE(is_origin_enabled);

  // kOriginTrialsSampleAPI is not a navigation feature, so shouldn't be
  // included in GetEnabledNavigationFeatures().
  EXPECT_EQ(nullptr, GetEnabledNavigationFeatures());
}

// The feature should be enabled when all of:
// 1) token is valid for third party origin
// 2) token is enabled for secure, third party origin
// 3) trial allows third party origins
TEST_F(OriginTrialContextTest, ThirdPartyTrialWithThirdPartyTokenEnabled) {
  UpdateSecurityOrigin(kFrobulateEnabledOrigin);
  AddTokenForThirdPartyOriginsWithResponse(kFrobulateThirdPartyTrialName,
                                           OriginTrialTokenStatus::kSuccess,
                                           {kFrobulateEnabledOrigin});
  bool is_origin_enabled = IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPIThirdParty);
  EXPECT_TRUE(is_origin_enabled);
}

// If the browser says it's invalid for any reason, that's enough to reject.
TEST_F(OriginTrialContextTest, InvalidTokenResponseFromPlatform) {
  UpdateSecurityOrigin(kFrobulateEnabledOrigin);
  AddTokenWithResponse(kFrobulateTrialName,
                       OriginTrialTokenStatus::kInvalidSignature);

  bool is_origin_enabled = IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI);
  EXPECT_FALSE(is_origin_enabled);
}

// Features should not be enabled on insecure origins
TEST_F(OriginTrialContextTest, FeatureNotEnableOnInsecureOrigin) {
  UpdateSecurityOrigin(kFrobulateEnabledOriginInsecure);
  AddTokenWithResponse(kFrobulateTrialName, OriginTrialTokenStatus::kInsecure);
  EXPECT_FALSE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));
}

// Features should not be enabled on insecure third-party origins
TEST_F(OriginTrialContextTest, FeatureNotEnableOnInsecureThirdPartyOrigin) {
  UpdateSecurityOrigin(kFrobulateEnabledOrigin);
  AddTokenForThirdPartyOriginsWithResponse(kFrobulateThirdPartyTrialName,
                                           OriginTrialTokenStatus::kInsecure,
                                           {kFrobulateEnabledOriginInsecure});
  EXPECT_FALSE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPIThirdParty));
}

TEST_F(OriginTrialContextTest, ParseHeaderValue) {
  std::unique_ptr<Vector<String>> tokens;
  ASSERT_TRUE(tokens = OriginTrialContext::ParseHeaderValue(" foo\t "));
  ASSERT_EQ(1u, tokens->size());
  EXPECT_EQ("foo", (*tokens)[0]);

  ASSERT_TRUE(tokens = OriginTrialContext::ParseHeaderValue(" \" bar \" "));
  ASSERT_EQ(1u, tokens->size());
  EXPECT_EQ(" bar ", (*tokens)[0]);

  ASSERT_TRUE(tokens = OriginTrialContext::ParseHeaderValue(" foo, bar"));
  ASSERT_EQ(2u, tokens->size());
  EXPECT_EQ("foo", (*tokens)[0]);
  EXPECT_EQ("bar", (*tokens)[1]);

  ASSERT_TRUE(tokens =
                  OriginTrialContext::ParseHeaderValue(",foo, ,bar,,'  ', ''"));
  ASSERT_EQ(3u, tokens->size());
  EXPECT_EQ("foo", (*tokens)[0]);
  EXPECT_EQ("bar", (*tokens)[1]);
  EXPECT_EQ("  ", (*tokens)[2]);

  ASSERT_TRUE(tokens =
                  OriginTrialContext::ParseHeaderValue("  \"abc\"  , 'def',g"));
  ASSERT_EQ(3u, tokens->size());
  EXPECT_EQ("abc", (*tokens)[0]);
  EXPECT_EQ("def", (*tokens)[1]);
  EXPECT_EQ("g", (*tokens)[2]);

  ASSERT_TRUE(tokens = OriginTrialContext::ParseHeaderValue(
                  " \"a\\b\\\"c'd\", 'e\\f\\'g' "));
  ASSERT_EQ(2u, tokens->size());
  EXPECT_EQ("ab\"c'd", (*tokens)[0]);
  EXPECT_EQ("ef'g", (*tokens)[1]);

  ASSERT_TRUE(tokens =
                  OriginTrialContext::ParseHeaderValue("\"ab,c\" , 'd,e'"));
  ASSERT_EQ(2u, tokens->size());
  EXPECT_EQ("ab,c", (*tokens)[0]);
  EXPECT_EQ("d,e", (*tokens)[1]);

  ASSERT_TRUE(tokens = OriginTrialContext::ParseHeaderValue("  "));
  EXPECT_EQ(0u, tokens->size());

  ASSERT_TRUE(tokens = OriginTrialContext::ParseHeaderValue(""));
  EXPECT_EQ(0u, tokens->size());

  ASSERT_TRUE(tokens = OriginTrialContext::ParseHeaderValue(" ,, \"\" "));
  EXPECT_EQ(0u, tokens->size());
}

TEST_F(OriginTrialContextTest, ParseHeaderValue_NotCommaSeparated) {
  EXPECT_FALSE(OriginTrialContext::ParseHeaderValue("foo bar"));
  EXPECT_FALSE(OriginTrialContext::ParseHeaderValue("\"foo\" 'bar'"));
  EXPECT_FALSE(OriginTrialContext::ParseHeaderValue("foo 'bar'"));
  EXPECT_FALSE(OriginTrialContext::ParseHeaderValue("\"foo\" bar"));
}

TEST_F(OriginTrialContextTest, PermissionsPolicy) {
  // Create a page holder window/document with an OriginTrialContext.
  auto page_holder = std::make_unique<DummyPageHolder>();
  LocalDOMWindow* window = page_holder->GetFrame().DomWindow();
  OriginTrialContext* context = window->GetOriginTrialContext();

  // Enable the sample origin trial API ("Frobulate").
  context->AddFeature(mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI);
  EXPECT_TRUE(context->IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));

  // Make a mock feature name map with "frobulate".
  FeatureNameMap feature_map;
  feature_map.Set("frobulate",
                  mojom::blink::PermissionsPolicyFeature::kFrobulate);

  // Attempt to parse the "frobulate" permissions policy. This will only work if
  // the permissions policy is successfully enabled via the origin trial.
  scoped_refptr<const SecurityOrigin> security_origin =
      SecurityOrigin::CreateFromString(kFrobulateEnabledOrigin);

  PolicyParserMessageBuffer logger;
  ParsedPermissionsPolicy result;
  result = PermissionsPolicyParser::ParsePermissionsPolicyForTest(
      "frobulate=*", security_origin, nullptr, logger, feature_map, window);
  EXPECT_TRUE(logger.GetMessages().empty());
  ASSERT_EQ(1u, result.size());
  EXPECT_EQ(mojom::blink::PermissionsPolicyFeature::kFrobulate,
            result[0].feature);
}

TEST_F(OriginTrialContextTest, GetEnabledNavigationFeatures) {
  UpdateSecurityOrigin(kFrobulateEnabledOrigin);
  AddTokenWithResponse(kFrobulateNavigationTrialName,
                       OriginTrialTokenStatus::kSuccess);
  EXPECT_TRUE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPINavigation));

  auto enabled_navigation_features = GetEnabledNavigationFeatures();
  ASSERT_NE(nullptr, enabled_navigation_features.get());
  EXPECT_EQ(
      WTF::Vector<mojom::blink::OriginTrialFeature>(
          {mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPINavigation}),
      *enabled_navigation_features.get());
}

TEST_F(OriginTrialContextTest, ActivateNavigationFeature) {
  EXPECT_TRUE(ActivateNavigationFeature(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPINavigation));
  EXPECT_FALSE(ActivateNavigationFeature(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));
}

TEST_F(OriginTrialContextTest, GetTokenExpiryTimeIgnoresIrrelevantTokens) {
  UpdateSecurityOrigin(kFrobulateEnabledOrigin);

  // A non-success response shouldn't affect Frobulate's expiry time.
  AddTokenWithResponse(kUnknownTrialName, OriginTrialTokenStatus::kMalformed);
  EXPECT_FALSE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));
  EXPECT_EQ(base::Time(),
            GetFeatureExpiry(
                mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));

  // A different trial shouldn't affect Frobulate's expiry time.
  AddTokenWithResponse(kFrobulateDeprecationTrialName,
                       OriginTrialTokenStatus::kSuccess);
  EXPECT_TRUE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPIDeprecation));
  EXPECT_EQ(base::Time(),
            GetFeatureExpiry(
                mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));

  // A valid trial should update the expiry time.
  AddTokenWithResponse(kFrobulateTrialName, OriginTrialTokenStatus::kSuccess);
  EXPECT_TRUE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));
  EXPECT_EQ(kBaseTokenExpiryTime,
            GetFeatureExpiry(
                mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));
}

TEST_F(OriginTrialContextTest, LastExpiryForFeatureIsUsed) {
  UpdateSecurityOrigin(kFrobulateEnabledOrigin);

  base::Time plusone = kBaseTokenExpiryTime + base::Seconds(1);
  base::Time plustwo = plusone + base::Seconds(1);
  base::Time plusthree = plustwo + base::Seconds(1);

  AddTokenWithResponse({
      .status = OriginTrialTokenStatus::kSuccess,
      .feature = kFrobulateTrialName,
      .expiry = plusone,
  });
  EXPECT_TRUE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));
  EXPECT_EQ(plusone,
            GetFeatureExpiry(
                mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));

  AddTokenWithResponse({
      .status = OriginTrialTokenStatus::kSuccess,
      .feature = kFrobulateTrialName,
      .expiry = plusthree,
  });
  EXPECT_TRUE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));
  EXPECT_EQ(plusthree,
            GetFeatureExpiry(
                mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));

  AddTokenWithResponse({
      .status = OriginTrialTokenStatus::kSuccess,
      .feature = kFrobulateTrialName,
      .expiry = plustwo,
  });
  EXPECT_TRUE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));
  EXPECT_EQ(plusthree,
            GetFeatureExpiry(
                mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));
}

TEST_F(OriginTrialContextTest, ImpliedFeatureExpiryTimesAreUpdated) {
  UpdateSecurityOrigin(kFrobulateEnabledOrigin);

  base::Time plusone = kBaseTokenExpiryTime + base::Seconds(1);
  AddTokenWithResponse({
      .status = OriginTrialTokenStatus::kSuccess,
      .feature = kFrobulateTrialName,
      .expiry = plusone,
  });
  EXPECT_TRUE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));
  EXPECT_EQ(
      plusone,
      GetFeatureExpiry(
          mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPIImplied));
}

TEST_F(OriginTrialContextTest, SettingFeatureUpdatesDocumentSettings) {
  // Create a page holder window/document with an OriginTrialContext.
  auto page_holder = std::make_unique<DummyPageHolder>();
  LocalDOMWindow* window = page_holder->GetFrame().DomWindow();
  OriginTrialContext* context = window->GetOriginTrialContext();

  // Force-disabled the AutoDarkMode feature in the page holder's settings.
  ASSERT_TRUE(page_holder->GetDocument().GetSettings());
  page_holder->GetDocument().GetSettings()->SetForceDarkModeEnabled(false);

  // Enable a settings-based origin trial API ("AutoDarkMode").
  context->AddFeature(mojom::blink::OriginTrialFeature::kAutoDarkMode);
  EXPECT_TRUE(context->IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kAutoDarkMode));

  // Expect the AutoDarkMode setting to have been enabled.
  EXPECT_TRUE(
      page_holder->GetDocument().GetSettings()->GetForceDarkModeEnabled());

  // TODO(crbug.com/1260410): Switch this test away from using the AutoDarkMode
  // feature towards an OriginTrialsSampleAPI* feature.
}

// This test ensures that the feature and token data are correctly mapped. The
// assertions mirror the code that is used to send origin trial overrides to the
// browser process via RuntimeFeatureStateOverrideContext's IPC.
TEST_F(OriginTrialContextTest, AddedFeaturesAreMappedToTokens) {
  // Add a new feature via token.
  UpdateSecurityOrigin(kFrobulateEnabledOrigin);
  AddTokenWithResponse(kFrobulateBrowserReadWriteTrialName,
                       OriginTrialTokenStatus::kSuccess);
  // Ensure that FrobulateBrowserReadWrite is enabled.
  EXPECT_TRUE(IsFeatureEnabled(mojom::blink::OriginTrialFeature::
                                   kOriginTrialsSampleAPIBrowserReadWrite));
  EXPECT_TRUE(GetFeatureToTokens().Contains(
      mojom::blink::OriginTrialFeature::
          kOriginTrialsSampleAPIBrowserReadWrite));
  // Ensure that the corresponding token is stored.
  Vector<String> expected_tokens({kTokenPlaceholder});
  EXPECT_EQ(GetFeatureToTokens().at(mojom::blink::OriginTrialFeature::
                                        kOriginTrialsSampleAPIBrowserReadWrite),
            expected_tokens);
}

class OriginTrialContextDevtoolsTest : public OriginTrialContextTest {
 public:
  OriginTrialContextDevtoolsTest() = default;

  const HashMap<String, OriginTrialResult> GetOriginTrialResultsForDevtools()
      const {
    return execution_context_->GetOriginTrialContext()
        ->GetOriginTrialResultsForDevtools();
  }

  struct ExpectedOriginTrialTokenResult {
    OriginTrialTokenStatus status;
    bool token_parsable;
  };

  void ExpectTrialResultContains(
      const HashMap<String, OriginTrialResult>& trial_results,
      const String& trial_name,
      OriginTrialStatus trial_status,
      const Vector<ExpectedOriginTrialTokenResult>& expected_token_results)
      const {
    auto trial_result = trial_results.find(trial_name);
    ASSERT_TRUE(trial_result != trial_results.end());
    EXPECT_EQ(trial_result->value.trial_name, trial_name);
    EXPECT_EQ(trial_result->value.status, trial_status);
    EXPECT_EQ(trial_result->value.token_results.size(),
              expected_token_results.size());

    for (wtf_size_t i = 0; i < expected_token_results.size(); i++) {
      const auto& expected_token_result = expected_token_results[i];
      const auto& actual_token_result = trial_result->value.token_results[i];

      // Note: `OriginTrialTokenResult::raw_token` is not checked
      // as the mocking class uses `kTokenPlaceholder` as raw token string.
      // Further content of `OriginTrialTokenResult::raw_token` is
      // also not checked, as it is generated by the mocking class.
      EXPECT_EQ(actual_token_result.status, expected_token_result.status);
      EXPECT_EQ(actual_token_result.parsed_token.has_value(),
                expected_token_result.token_parsable);
      EXPECT_NE(actual_token_result.raw_token, g_empty_string);
    }
  }
};

TEST_F(OriginTrialContextDevtoolsTest, DependentFeatureNotEnabled) {
  UpdateSecurityOrigin(kFrobulateEnabledOrigin);

  base::test::ScopedFeatureList feature_list_;
  feature_list_.InitAndDisableFeature(
      blink::features::kSpeculationRulesPrefetchFuture);

  AddTokenWithResponse("SpeculationRulesPrefetchFuture",
                       OriginTrialTokenStatus::kSuccess);

  EXPECT_FALSE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kSpeculationRulesPrefetchFuture));
  HashMap<String, OriginTrialResult> origin_trial_results =
      GetOriginTrialResultsForDevtools();
  EXPECT_EQ(origin_trial_results.size(), 1u);
  ExpectTrialResultContains(
      origin_trial_results, "SpeculationRulesPrefetchFuture",
      OriginTrialStatus::kTrialNotAllowed,
      {{OriginTrialTokenStatus::kSuccess, /* token_parsable */ true}});
}

TEST_F(OriginTrialContextDevtoolsTest, TrialNameNotRecognized) {
  UpdateSecurityOrigin(kFrobulateEnabledOrigin);

  AddTokenWithResponse(kUnknownTrialName,
                       OriginTrialTokenStatus::kUnknownTrial);

  EXPECT_FALSE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));

  HashMap<String, OriginTrialResult> origin_trial_results =
      GetOriginTrialResultsForDevtools();

  EXPECT_EQ(origin_trial_results.size(), 1u);
  ExpectTrialResultContains(
      origin_trial_results,
      /* trial_name */ "UNKNOWN", OriginTrialStatus::kValidTokenNotProvided,
      {{OriginTrialTokenStatus::kUnknownTrial, /* token_parsable */ true}});
}

TEST_F(OriginTrialContextDevtoolsTest, NoValidToken) {
  UpdateSecurityOrigin(kFrobulateEnabledOrigin);

  AddTokenWithResponse(kFrobulateTrialName, OriginTrialTokenStatus::kExpired);

  EXPECT_FALSE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));

  HashMap<String, OriginTrialResult> origin_trial_results =
      GetOriginTrialResultsForDevtools();

  // Receiving invalid token should set feature status to
  // kValidTokenNotProvided.
  EXPECT_EQ(origin_trial_results.size(), 1u);
  ExpectTrialResultContains(
      origin_trial_results,
      /* trial_name */ kFrobulateTrialName,
      OriginTrialStatus::kValidTokenNotProvided,
      {{OriginTrialTokenStatus::kExpired, /* token_parsable */ true}});

  // Add a non-expired token
  AddTokenWithResponse(kFrobulateTrialName, OriginTrialTokenStatus::kSuccess);

  // Receiving valid token should change feature status to kEnabled.
  EXPECT_TRUE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));
  origin_trial_results = GetOriginTrialResultsForDevtools();
  EXPECT_EQ(origin_trial_results.size(), 1u);
  ExpectTrialResultContains(
      origin_trial_results,
      /* trial_name */ kFrobulateTrialName, OriginTrialStatus::kEnabled,
      {
          {OriginTrialTokenStatus::kExpired, /* token_parsable */ true},
          {OriginTrialTokenStatus::kSuccess, /* token_parsable */ true},
      });
}

TEST_F(OriginTrialContextDevtoolsTest, Enabled) {
  UpdateSecurityOrigin(kFrobulateEnabledOrigin);

  AddTokenWithResponse(kFrobulateTrialName, OriginTrialTokenStatus::kSuccess);

  // Receiving valid token when feature is enabled should set feature status
  // to kEnabled.
  EXPECT_TRUE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));
  HashMap<String, OriginTrialResult> origin_trial_results =
      GetOriginTrialResultsForDevtools();
  EXPECT_EQ(origin_trial_results.size(), 1u);
  ExpectTrialResultContains(
      origin_trial_results,
      /* trial_name */ kFrobulateTrialName, OriginTrialStatus::kEnabled,
      {{OriginTrialTokenStatus::kSuccess, /* token_parsable */ true}});

  AddTokenWithResponse(kFrobulateTrialName, OriginTrialTokenStatus::kExpired);

  // Receiving invalid token when a valid token already exists should
  // not change feature status.
  EXPECT_TRUE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));
  origin_trial_results = GetOriginTrialResultsForDevtools();
  EXPECT_EQ(origin_trial_results.size(), 1u);
  ExpectTrialResultContains(
      origin_trial_results,
      /* trial_name */ kFrobulateTrialName, OriginTrialStatus::kEnabled,
      {
          {OriginTrialTokenStatus::kSuccess, /* token_parsable */ true},
          {OriginTrialTokenStatus::kExpired, /* token_parsable */ true},
      });
}

TEST_F(OriginTrialContextDevtoolsTest, UnparsableToken) {
  UpdateSecurityOrigin(kFrobulateEnabledOrigin);

  AddTokenWithResponse(kFrobulateTrialName, OriginTrialTokenStatus::kMalformed);

  EXPECT_FALSE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));
  HashMap<String, OriginTrialResult> origin_trial_results =
      GetOriginTrialResultsForDevtools();
  EXPECT_EQ(origin_trial_results.size(), 1u);
  ExpectTrialResultContains(
      origin_trial_results,
      /* trial_name */ "UNKNOWN", OriginTrialStatus::kValidTokenNotProvided,
      {{OriginTrialTokenStatus::kMalformed, /* token_parsable */ false}});
}

TEST_F(OriginTrialContextDevtoolsTest, InsecureOrigin) {
  UpdateSecurityOrigin(kFrobulateEnabledOriginInsecure);
  AddTokenWithResponse(kFrobulateTrialName, OriginTrialTokenStatus::kInsecure);

  EXPECT_FALSE(IsFeatureEnabled(
      mojom::blink::OriginTrialFeature::kOriginTrialsSampleAPI));

  HashMap<String, OriginTrialResult> origin_trial_results =
      GetOriginTrialResultsForDevtools();

  EXPECT_EQ(origin_trial_results.size(), 1u);
  ExpectTrialResultContains(
      origin_trial_results,
      /* trial_name */ kFrobulateTrialName,
      OriginTrialStatus::kValidTokenNotProvided,
      {{OriginTrialTokenStatus::kInsecure, /* token_parsable */ true}});
}

}  // namespace blink
```
Response:
The user wants to understand the functionality of the `trial_token_validator_unittest.cc` file in the Chromium Blink engine. This is a C++ unit test file.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Function:** The filename strongly suggests this file tests the `TrialTokenValidator`. Unit tests verify specific functionalities of a given component.

2. **Analyze the Test Structure:** The code is organized into `TEST_F` and `TEST_P` blocks, indicating the use of Google Test framework. `TEST_F` uses a fixed test fixture (`TrialTokenValidatorTest`), while `TEST_P` uses parameterized tests (`TrialTokenValidatorEquivalenceTest`). This means some tests cover different input scenarios within a single logical test.

3. **Examine Individual Tests (High-Level):** Go through each test case and identify its purpose based on its name and the assertions (`EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`). Look for patterns in the input data and the expected outcomes.

4. **Relate to Origin Trials:** The presence of "Origin-Trial" headers and tokens (like `kSampleToken`, `kExpiredToken`) directly links the tests to the Origin Trials feature. This feature allows developers to experiment with new web platform features.

5. **Identify Key Functionalities Tested:** Based on the test names and assertions, group the tests by the functionalities they are verifying. This leads to categories like:
    * Basic token validation (success, expiry, wrong origin).
    * Handling of disabled tokens and trials.
    * Expiry grace period behavior.
    * Subdomain matching.
    * Third-party token validation.
    * Interaction with HTTP headers.
    * Differences between `ValidateToken` and `ValidateTokenAndTrial`.
    * Handling of insecure origins and tokens.
    * Revalidation of tokens.
    * Specific origin trial exceptions (like `WebViewXRequestedWithDeprecation`).

6. **Determine Relationships with Web Technologies (JavaScript, HTML, CSS):** Origin Trials are about enabling experimental features in web browsers. These features are often exposed through JavaScript APIs, affect how HTML is parsed or rendered, or introduce new CSS properties. Therefore, the tests implicitly relate to these technologies, even if they don't directly manipulate JavaScript, HTML, or CSS strings within the test file.

7. **Construct Examples for Web Technologies:** For each relevant functionality, devise a simple scenario illustrating how it connects to JavaScript, HTML, or CSS. For example:
    * **JavaScript:** Using `navigator.userAgentData.getHighEntropyValues()` (a real-world Origin Trial feature) to demonstrate how a successful token enables an API.
    * **HTML:**  Showing how a token might enable a new HTML tag or attribute.
    * **CSS:**  Illustrating a new CSS property being enabled by a token.

8. **Develop Logical Reasoning Examples (Input/Output):**  For specific tests, provide hypothetical inputs (token, origin, time) and the expected `OriginTrialTokenStatus`. This clarifies the logic being tested.

9. **Identify Potential User/Programming Errors:** Think about common mistakes developers might make when using Origin Trials, such as:
    * Incorrect token format.
    * Using tokens on the wrong origin.
    * Expired tokens.
    * Incorrectly assuming a feature is enabled.

10. **Summarize the Functionality:** Concisely describe the overall purpose of the test file.

11. **Review and Refine:** Ensure the answer is clear, accurate, and well-organized. Check for any inconsistencies or missing information. Make sure the examples are easy to understand. For instance, initially, I might just say "tests third-party token validation," but refining it to explain *how* different scenarios are tested (secure vs. insecure, primary vs. third-party origin) adds more value. Similarly, initially the web technology examples might be too abstract, and need to be grounded with concrete API examples.
这是对 `blink/common/origin_trials/trial_token_validator_unittest.cc` 文件中第二部分代码的功能归纳。

**归纳一下 `trial_token_validator_unittest.cc` 的功能 (基于提供的第二部分代码):**

这部分代码主要针对 `TrialTokenValidator` 类的各种验证场景进行更深入、更细致的单元测试，特别是关注以下几个方面：

1. **验证请求头中的 Origin Trial Token:**
   - 测试 `RequestEnablesFeature` 和 `RequestEnablesDeprecatedFeature` 方法，模拟服务器响应头中包含 `Origin-Trial` 字段的情况，验证 token 是否能成功启用对应功能。
   - 测试了单个 header 和多个 header 的情况，以及单个 header 中包含多个 token 值的情况。
   - 验证了未知 Feature 的 Token 在请求头中的处理。

2. **`ValidateToken` 和 `ValidateTokenAndTrial` 方法的差异性测试:**
   - 强调了 `ValidateToken` 仅进行 token 结构的验证，而 `ValidateTokenAndTrial` 会进一步结合当前 Origin 是否符合 Trial 的要求进行验证。
   - 测试了未知 Feature 的 Token，`ValidateToken` 可能成功解析，但 `ValidateTokenAndTrial` 会返回 `kUnknownTrial`。
   - 测试了针对非 Third-Party Feature 使用 Third-Party Token 的情况，`ValidateToken` 可以解析，但 `ValidateTokenAndTrial` 会返回 `kFeatureDisabled`。
   - 测试了 Insecure Token 在 `ValidateToken` 和 `ValidateTokenAndTrial` 中的不同结果，`ValidateToken` 可能会成功解析，但 `ValidateTokenAndTrial` 会返回 `kInsecure`。

3. **针对 Third-Party Token 的更细致测试:**
   - 详细测试了 Third-Party Token 在不同 Origin 组合下的验证情况，包括 Primary Origin 和 Third-Party Origin 的 Secure/Insecure 组合。
   - 测试了 `ValidateTokenAndTrialWithOriginInfo` 方法，允许更细粒度地控制 Origin 的安全信息，模拟不同场景下的安全性判断。

4. **`RevalidateTokenAndTrial` 方法的测试:**
   - 测试了重新验证已存在 token 的信息，例如检查 token 是否过期、对应的 Trial 是否被禁用、token 本身是否被禁用。
   - 特别测试了用户层面禁用 Trial 的情况，只有当 token 的 UsageRestriction 为 `kSubset` 时才会被禁用。

5. **针对特定 Origin Trial 的特殊处理:**
   - 专门测试了 `WebViewXRequestedWithDeprecation` Origin Trial，该 Trial 对 Third-Party Token 忽略 Origin 检查的特殊行为。

**与 Javascript, HTML, CSS 的关系举例:**

尽管这个单元测试文件是用 C++ 编写的，它测试的功能直接影响到 Web 开发人员如何使用 Javascript, HTML, 和 CSS 中的实验性特性。

* **Javascript:**  如果一个 Origin Trial Token 验证成功，那么浏览器可能会暴露出一个新的 Javascript API 给页面使用。
    ```javascript
    // 假设 "NewFeature" 是一个需要 Origin Trial 的新功能
    if ('newFeature' in navigator) {
      navigator.newFeature().doSomething();
    } else {
      console.log("NewFeature is not available, ensure the Origin Trial Token is valid.");
    }
    ```
* **HTML:** Origin Trial 可能允许使用新的 HTML 标签或属性。
    ```html
    <!-- 只有在 Origin Trial Token 有效的情况下，浏览器才会正确解析并渲染 <new-element> -->
    <new-element>This is a new experimental element.</new-element>
    ```
* **CSS:**  Origin Trial 可能启用新的 CSS 属性。
    ```css
    /* 只有在 Origin Trial Token 有效的情况下，才能使用这个新的 CSS 属性 */
    .element {
      new-css-property: value;
    }
    ```

**逻辑推理的假设输入与输出举例:**

* **假设输入:**
    * `kSampleToken`: 一个针对 `kAppropriateFeatureName` 的有效 token。
    * `appropriate_origin_`:  `https://valid.example.com:443`
    * `Now()`: 当前时间在 token 的有效期内。
* **预期输出:**
    * `Validate(kSampleToken, appropriate_origin_, Now()).Status()` 应该返回 `blink::OriginTrialTokenStatus::kSuccess`。

* **假设输入:**
    * `kExpiredToken`: 一个已过期的 token。
    * `appropriate_origin_`: `https://valid.example.com:443`
    * `Now()`: 当前时间在 token 的过期时间之后。
* **预期输出:**
    * `Validate(kExpiredToken, appropriate_origin_, Now()).Status()` 应该返回 `blink::OriginTrialTokenStatus::kExpired`。

**涉及用户或者编程常见的使用错误举例:**

* **用户错误:** 开发者在本地开发环境 (通常是 `http://localhost`) 尝试使用需要 HTTPS Origin Trial 的功能。由于 Origin 不匹配，token 验证会失败。
* **编程错误:** 开发者在服务器响应头中错误地设置了 `Origin-Trial` 字段的格式，例如拼写错误或者包含额外的空格，导致 token 无法被正确解析。
* **编程错误:** 开发者混淆了 First-Party Token 和 Third-Party Token 的使用场景，将只适用于主 Origin 的 token 用在了嵌入的 iframe 中，导致验证失败。
* **编程错误:** 开发者没有考虑到 Expiry Grace Period，认为 token 在过期时间后立即失效，而实际上有一个短暂的宽限期。

总之，这部分代码通过大量的单元测试用例，全面验证了 `TrialTokenValidator` 在各种场景下对 Origin Trial Token 的验证逻辑，确保了 Origin Trials 功能的正确性和可靠性。 这些测试覆盖了 token 的基本有效性、与 Origin 的匹配、过期处理、禁用状态以及 Third-Party Token 的特殊情况等。

### 提示词
```
这是目录为blink/common/origin_trials/trial_token_validator_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
arty_origins, Now())
                .Status());
}

TEST_P(TrialTokenValidatorEquivalenceTest, ValidatorRespectsDisabledTokens) {
  TrialTokenResult result = Validate(kSampleToken, appropriate_origin_, Now());
  // Disable an irrelevant token; token should still validate
  DisableToken(expired_token_signature_);
  EXPECT_EQ(blink::OriginTrialTokenStatus::kSuccess, result.Status());
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  // Disable the token; it should no longer be valid
  DisableToken(valid_token_signature_);
  EXPECT_EQ(blink::OriginTrialTokenStatus::kTokenDisabled,
            Validate(kSampleToken, appropriate_origin_, Now()).Status());
}

TEST_P(TrialTokenValidatorEquivalenceTest, ValidateValidExpiryGraceToken) {
  // This token is valid one day before the end of the expiry grace period,
  // even though it is past the token's expiry time.
  auto current_time =
      kSampleTokenExpiryTime + kExpiryGracePeriod - base::Days(1);
  TrialTokenResult result =
      Validate(kExpiryGracePeriodToken, appropriate_origin_, current_time);
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_P(TrialTokenValidatorEquivalenceTest, ValidateExpiredExpiryGraceToken) {
  // This token is expired at the end of the expiry grace period.
  auto current_time = kSampleTokenExpiryTime + kExpiryGracePeriod;
  TrialTokenResult result =
      Validate(kExpiryGracePeriodToken, appropriate_origin_, current_time);
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kExpired);
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_P(TrialTokenValidatorEquivalenceTest,
       ValidateValidExpiryGraceThirdPartyToken) {
  url::Origin third_party_origins[] = {appropriate_origin_};
  // This token is valid one day before the end of the expiry grace period,
  // even though it is past the token's expiry time.
  auto current_time =
      kSampleTokenExpiryTime + kExpiryGracePeriod - base::Days(1);
  TrialTokenResult result =
      Validate(kExpiryGracePeriodThirdPartyToken, appropriate_origin_,
               third_party_origins, current_time);
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_TRUE(result.ParsedToken()->is_third_party());
}

TEST_P(TrialTokenValidatorEquivalenceTest,
       ValidateExpiredExpiryGraceThirdPartyToken) {
  url::Origin third_party_origins[] = {appropriate_origin_};
  // This token is expired at the end of the expiry grace period.
  auto current_time = kSampleTokenExpiryTime + kExpiryGracePeriod;
  TrialTokenResult result =
      Validate(kExpiryGracePeriodThirdPartyToken, appropriate_origin_,
               third_party_origins, current_time);
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kExpired);
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_TRUE(result.ParsedToken()->is_third_party());
}

TEST_P(TrialTokenValidatorEquivalenceTest, ValidateSubdomainToken) {
  TrialTokenResult result =
      Validate(kSubdomainToken, appropriate_origin_, {}, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_TRUE(result.ParsedToken()->match_subdomains());
}

TEST_P(TrialTokenValidatorEquivalenceTest,
       ValidateSubdomainTokenUnrelatedOrigin) {
  // A subdomain token should not match against an unrelated origin
  TrialTokenResult result =
      Validate(kSubdomainToken, unrelated_origin_, {}, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kWrongOrigin);
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_TRUE(result.ParsedToken()->match_subdomains());
}

TEST_P(TrialTokenValidatorEquivalenceTest, ValidateThirdPartySubdomainToken) {
  // Subdomain third-party tokens should validate even if the primary origin
  // is unrelated and there are other, insecure, origins as well
  url::Origin script_origins[] = {insecure_origin_, appropriate_origin_};
  TrialTokenResult result = Validate(kThirdPartySubdomainToken,
                                     unrelated_origin_, script_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_TRUE(result.ParsedToken()->match_subdomains());
}

TEST_P(TrialTokenValidatorEquivalenceTest,
       ValidateThirdPartySubdomainTokenInsecureOrigin) {
  // Subdomain third-party tokens should not validate against insecure origins
  url::Origin script_origins[] = {insecure_origin_};
  TrialTokenResult result = Validate(kThirdPartySubdomainToken,
                                     unrelated_origin_, script_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kWrongOrigin);
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_TRUE(result.ParsedToken()->match_subdomains());
}

// Tests of RequestEnablesFeature methods

TEST_F(TrialTokenValidatorTest, ValidateRequestInsecure) {
  response_headers_->AddHeader("Origin-Trial", kInsecureOriginToken);
  EXPECT_FALSE(validator_.RequestEnablesFeature(
      GURL(kInsecureOrigin), response_headers_.get(), kAppropriateFeatureName,
      Now()));
}

TEST_F(TrialTokenValidatorTest, ValidateRequestForDeprecationInsecure) {
  response_headers_->AddHeader("Origin-Trial", kDeprecationInsecureToken);
  EXPECT_TRUE(validator_.RequestEnablesDeprecatedFeature(
      GURL(kInsecureOrigin), response_headers_.get(),
      kAppropriateDeprecationFeatureName, Now()));
}

TEST_F(TrialTokenValidatorTest, ValidateRequestValidToken) {
  response_headers_->AddHeader("Origin-Trial", kSampleToken);
  EXPECT_TRUE(validator_.RequestEnablesFeature(GURL(kAppropriateOrigin),
                                               response_headers_.get(),
                                               kAppropriateFeatureName, Now()));
}

TEST_F(TrialTokenValidatorTest, ValidateRequestForDeprecationValidToken) {
  response_headers_->AddHeader("Origin-Trial", kSampleToken);
  EXPECT_TRUE(validator_.RequestEnablesDeprecatedFeature(
      GURL(kAppropriateOrigin), response_headers_.get(),
      kAppropriateFeatureName, Now()));
}

TEST_F(TrialTokenValidatorTest, ValidateRequestNoTokens) {
  EXPECT_FALSE(validator_.RequestEnablesFeature(
      GURL(kAppropriateOrigin), response_headers_.get(),
      kAppropriateFeatureName, Now()));
}

TEST_F(TrialTokenValidatorTest, ValidateRequestForDeprecationNoTokens) {
  EXPECT_FALSE(validator_.RequestEnablesDeprecatedFeature(
      GURL(kAppropriateOrigin), response_headers_.get(),
      kAppropriateFeatureName, Now()));
}

TEST_F(TrialTokenValidatorTest, ValidateRequestMultipleHeaders) {
  response_headers_->AddHeader("Origin-Trial", kSampleToken);
  response_headers_->AddHeader("Origin-Trial", kExpiredToken);
  EXPECT_TRUE(validator_.RequestEnablesFeature(GURL(kAppropriateOrigin),
                                               response_headers_.get(),
                                               kAppropriateFeatureName, Now()));
  EXPECT_FALSE(validator_.RequestEnablesFeature(
      GURL(kAppropriateOrigin), response_headers_.get(),
      kInappropriateFeatureName, Now()));
  EXPECT_FALSE(validator_.RequestEnablesFeature(
      GURL(kInappropriateOrigin), response_headers_.get(),
      kAppropriateFeatureName, Now()));
}

TEST_F(TrialTokenValidatorTest, ValidateRequestMultipleHeaderValues) {
  response_headers_->AddHeader(
      "Origin-Trial", std::string(kExpiredToken) + ", " + kSampleToken);
  EXPECT_TRUE(validator_.RequestEnablesFeature(GURL(kAppropriateOrigin),
                                               response_headers_.get(),
                                               kAppropriateFeatureName, Now()));
  EXPECT_FALSE(validator_.RequestEnablesFeature(
      GURL(kAppropriateOrigin), response_headers_.get(),
      kInappropriateFeatureName, Now()));
  EXPECT_FALSE(validator_.RequestEnablesFeature(
      GURL(kInappropriateOrigin), response_headers_.get(),
      kAppropriateFeatureName, Now()));
}

TEST_F(TrialTokenValidatorTest, ValidateRequestUnknownFeatureToken) {
  response_headers_->AddHeader("Origin-Trial", kUnknownFeatureToken);
  EXPECT_FALSE(validator_.RequestEnablesFeature(
      GURL(kAppropriateOrigin), response_headers_.get(),
      kInappropriateFeatureName, Now()));
}

// Tests where ValidateToken and ValidateTokenAndTrial are expected
// to yield different results.
// These tests should test both |ValidateToken|, |ValidateTokenAndTrial|,
// and |ValidateTokenAndTrialWithOriginInfo| to ensure all entry points
// give the expected results

TEST_F(TrialTokenValidatorTest, ValidateUnknownFeatureToken) {
  // An unknown feature token can be valid, but the trial validation won't be
  TrialTokenResult result = validator_.ValidateToken(
      kUnknownFeatureToken, appropriate_origin_, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kInappropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrial(kUnknownFeatureToken,
                                            appropriate_origin_, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kUnknownTrial);
  EXPECT_EQ(kInappropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kUnknownFeatureToken, WithInfo(appropriate_origin_), {}, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kUnknownTrial);
  EXPECT_EQ(kInappropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_F(TrialTokenValidatorTest, ValidateUnknownFeatureThirdPartyToken) {
  // An unknown feature token can be valid, but the trial validation won't be
  url::Origin third_party_origins[] = {appropriate_origin_};
  TrialTokenResult result =
      validator_.ValidateToken(kUnknownFeatureThirdPartyToken,
                               appropriate_origin_, third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kInappropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_EQ(true, result.ParsedToken()->is_third_party());

  result = validator_.ValidateTokenAndTrial(kUnknownFeatureThirdPartyToken,
                                            appropriate_origin_,
                                            third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kUnknownTrial);
  EXPECT_EQ(kInappropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_EQ(true, result.ParsedToken()->is_third_party());

  result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kUnknownFeatureThirdPartyToken, WithInfo(appropriate_origin_),
      WithInfo(third_party_origins), Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kUnknownTrial);
  EXPECT_EQ(kInappropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_EQ(true, result.ParsedToken()->is_third_party());
}

TEST_F(TrialTokenValidatorTest, ValidateInsecureToken) {
  // An insecure token validates against an insecure origin, but only if the
  // trial allows it
  TrialTokenResult result =
      validator_.ValidateToken(kInsecureOriginToken, insecure_origin_, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrial(kInsecureOriginToken,
                                            insecure_origin_, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  // Ensure the result is the same if we provide our own security information
  result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kInsecureOriginToken, WithInfo(insecure_origin_), {}, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_F(TrialTokenValidatorTest,
       ValidateThirdPartyTokenForNonThirdPartyFeature) {
  // A third-party token should validate against an appropriate third-party
  // origin, but not if the trial doesn't allow for third-party tokens.
  url::Origin third_party_origins[] = {appropriate_origin_};
  TrialTokenResult result =
      validator_.ValidateToken(kThirdPartyTokenForNonThirdPartyTrial,
                               appropriate_origin_, third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_EQ(true, result.ParsedToken()->is_third_party());

  result = validator_.ValidateTokenAndTrial(
      kThirdPartyTokenForNonThirdPartyTrial, appropriate_origin_,
      third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kFeatureDisabled);
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_EQ(true, result.ParsedToken()->is_third_party());

  result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kThirdPartyTokenForNonThirdPartyTrial, WithInfo(appropriate_origin_),
      WithInfo(third_party_origins), Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kFeatureDisabled);
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_EQ(true, result.ParsedToken()->is_third_party());
}

TEST_F(TrialTokenValidatorTest, ValidateInsecureThirdPartyToken) {
  // An insecure third-party token is valid against insecure origins,
  // but only if the trial allows insecure tokens.
  url::Origin third_party_origins[] = {insecure_origin_};
  TrialTokenResult result =
      validator_.ValidateToken(kThirdPartyInsecureToken, appropriate_origin_,
                               third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrial(kThirdPartyInsecureToken,
                                            appropriate_origin_,
                                            third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kThirdPartyInsecureToken, WithInfo(appropriate_origin_),
      WithInfo(third_party_origins), Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_F(TrialTokenValidatorTest, ValidateInsecureThirdPartyTokenInsecureOrigin) {
  // A third-party token should validate against an insecure primary origin
  // and a secure third-party origin, but only if the trial allows
  // for insecure origins in general
  url::Origin third_party_origins[] = {inappropriate_origin_,
                                       appropriate_origin_};
  TrialTokenResult result = validator_.ValidateToken(
      kThirdPartyToken, insecure_origin_, third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrial(kThirdPartyToken, insecure_origin_,
                                            third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kThirdPartyToken, WithInfo(insecure_origin_),
      WithInfo(third_party_origins), Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_F(TrialTokenValidatorTest,
       ValidateInsecureThirdPartyTokenMultipleOrigins) {
  // An insecure third-party token is valid against insecure origins,
  // but only if the trial allows insecure tokens. And other, unrelated but
  // secure third-party origins should not change this-.
  url::Origin third_party_origins[] = {insecure_origin_, inappropriate_origin_};
  TrialTokenResult result =
      validator_.ValidateToken(kThirdPartyInsecureToken, appropriate_origin_,
                               third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrial(kThirdPartyInsecureToken,
                                            appropriate_origin_,
                                            third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kThirdPartyInsecureToken, WithInfo(appropriate_origin_),
      WithInfo(third_party_origins), Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_F(TrialTokenValidatorTest, ValidateThirdPartyTokenInsecureOrigin) {
  // An insecure third-party subdomain token is valid against an insecure
  // third-party subdomain, but not if the trial doesn't allow insecure origins.
  url::Origin third_party_origins[] = {unrelated_origin_, insecure_origin_};
  TrialTokenResult result =
      validator_.ValidateToken(kThirdPartyInsecureSubdomainToken,
                               appropriate_origin_, third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kSuccess);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrial(kThirdPartyInsecureSubdomainToken,
                                            appropriate_origin_,
                                            third_party_origins, Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());

  result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kThirdPartyInsecureSubdomainToken, WithInfo(appropriate_origin_),
      WithInfo(third_party_origins), Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

// Tests that only check the behaviour of
// |ValidateTokenAndTrialWithOriginInfo| - these are the ones
// that rely on changes in passing in specific OriginInfo

TEST_F(TrialTokenValidatorTest, ValidateInsecureOriginInfo) {
  TrialTokenValidator::OriginInfo insecure_origin_info(appropriate_origin_,
                                                       false);
  TrialTokenResult result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kSampleToken, insecure_origin_info, {}, Now());
  EXPECT_EQ(blink::OriginTrialTokenStatus::kInsecure, result.Status());
  EXPECT_EQ(kAppropriateFeatureName, result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
  EXPECT_EQ(false, result.ParsedToken()->is_third_party());
}

TEST_F(TrialTokenValidatorTest, ValidateInsecureOriginThirdPartyOriginInfo) {
  // Third-party tokens should not be secure if the primary origin is insecure
  TrialTokenValidator::OriginInfo insecure_origin_info(appropriate_origin_,
                                                       false);
  url::Origin third_party_origins[] = {appropriate_origin_};
  TrialTokenResult result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kThirdPartyToken, insecure_origin_info, WithInfo(third_party_origins),
      Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_F(TrialTokenValidatorTest,
       ValidateInsecureThirdPartyOriginThirdPartyOriginInfo) {
  // Third-party tokens should not be secure if the third-party origin is
  // insecure
  TrialTokenValidator::OriginInfo insecure_origin_info(appropriate_origin_,
                                                       false);
  TrialTokenValidator::OriginInfo insecure_third_parties[] = {
      insecure_origin_info};
  TrialTokenResult result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kThirdPartyToken, WithInfo(appropriate_origin_), insecure_third_parties,
      Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

TEST_F(TrialTokenValidatorTest,
       ValidateMultipleInsecureThirdPartyOriginThirdPartyOriginInfo) {
  // Third-party tokens should not be secure if the third-party origin is
  // insecure, even if there are other, secure, third-party origins
  TrialTokenValidator::OriginInfo insecure_origin_info(appropriate_origin_,
                                                       false);

  TrialTokenValidator::OriginInfo third_party_origins[] = {
      WithInfo(inappropriate_origin_),  // Secure, but not appropriate
      insecure_origin_info};
  TrialTokenResult result = validator_.ValidateTokenAndTrialWithOriginInfo(
      kThirdPartyToken, WithInfo(appropriate_origin_), third_party_origins,
      Now());
  EXPECT_EQ(result.Status(), blink::OriginTrialTokenStatus::kInsecure);
  EXPECT_EQ(kAppropriateThirdPartyFeatureName,
            result.ParsedToken()->feature_name());
  EXPECT_EQ(kSampleTokenExpiryTime, result.ParsedToken()->expiry_time());
}

//
// Tests of |RevalidateTokenAndTrial|
//
TEST_F(TrialTokenValidatorTest, RevalidateTokenInformation) {
  EXPECT_TRUE(validator_.RevalidateTokenAndTrial(
      kAppropriateFeatureName, kSampleTokenExpiryTime,
      blink::TrialToken::UsageRestriction::kNone, valid_token_signature_,
      Now()));
}

TEST_F(TrialTokenValidatorTest, RevalidateExpiredToken) {
  // Check basic expiration. The expiry must be > the current time
  base::Time expiry = Now();

  EXPECT_FALSE(validator_.RevalidateTokenAndTrial(
      kAppropriateFeatureName, expiry,
      blink::TrialToken::UsageRestriction::kNone, valid_token_signature_,
      Now()));

  // Check grace period expiration
  EXPECT_TRUE(validator_.RevalidateTokenAndTrial(
      kAppropriateGracePeriodFeatureName, expiry,
      blink::TrialToken::UsageRestriction::kNone, valid_token_signature_,
      Now()));

  // Check the boundary of the grace period.
  expiry = Now() - kExpiryGracePeriod;
  EXPECT_FALSE(validator_.RevalidateTokenAndTrial(
      kAppropriateGracePeriodFeatureName, expiry,
      blink::TrialToken::UsageRestriction::kNone, valid_token_signature_,
      Now()));
}

TEST_F(TrialTokenValidatorTest, RevalidateDisabledTrial) {
  policy_.DisableFeature(kAppropriateFeatureName);
  EXPECT_FALSE(validator_.RevalidateTokenAndTrial(
      kAppropriateFeatureName, kSampleTokenExpiryTime,
      blink::TrialToken::UsageRestriction::kNone, valid_token_signature_,
      Now()));
}

TEST_F(TrialTokenValidatorTest, RevalidateDisabledToken) {
  policy_.DisableToken(valid_token_signature_);
  EXPECT_FALSE(validator_.RevalidateTokenAndTrial(
      kAppropriateFeatureName, kSampleTokenExpiryTime,
      blink::TrialToken::UsageRestriction::kNone, valid_token_signature_,
      Now()));
}

TEST_F(TrialTokenValidatorTest, RevalidateDisabledTrialForUser) {
  policy_.DisableFeatureForUser(kAppropriateThirdPartyFeatureName);
  // Per-user disabled trials should only be disabled if the token is marked as
  // kSubset
  EXPECT_TRUE(validator_.RevalidateTokenAndTrial(
      kAppropriateThirdPartyFeatureName, kSampleTokenExpiryTime,
      blink::TrialToken::UsageRestriction::kNone, valid_token_signature_,
      Now()));

  EXPECT_FALSE(validator_.RevalidateTokenAndTrial(
      kAppropriateThirdPartyFeatureName, kSampleTokenExpiryTime,
      blink::TrialToken::UsageRestriction::kSubset, valid_token_signature_,
      Now()));
}

TEST_F(TrialTokenValidatorTest, XRWTrialAllowedForAll3POrigins) {
  // Specific test for WebViewXRequestedWithDeprecation origin trial, which
  // omits origin checks for third-party tokens.
  // Can be removed when the origin trial is removed from
  // |runtime_enabled_features.json5|.

  // Generated with
  // tools/origin_trials/generate_token.py thirdparty.com
  // WebViewXRequestedWithDeprecation --expire-timestamp=2000000000
  const char kXRW1PToken[] =
      "Ay6L+HCN2v3sAGUg/"
      "UUqhAD5OR2rE+FzVlQpAVBbSUrzDvx3Uz76a84EpeLiOyMpy6NGNH5z4KrC+"
      "CEnhCGLOgIAAABteyJvcmlnaW4iOiAiaHR0cHM6Ly90aGlyZHBhcnR5LmNvbTo0NDMiLCAiZ"
      "mVhdHVyZSI6ICJXZWJWaWV3WFJlcXVlc3RlZFdpdGhEZXByZWNhdGlvbiIsICJleHBpcnkiO"
      "iAyMDAwMDAwMDAwfQ==";

  // Generated with
  // tools/origin_trials/generate_token.py thirdparty.com
  // WebViewXRequestedWithDeprecation --expire-timestamp=2000000000
  // --is-third-party
  const char kXRW3PToken[] =
      "AwINH5I2lshWrnPvEqz1KRya3QU2Zx5djBDcr7Q5CnnccjUgNtWaAecPL26JnZlvye3WgAz6"
      "/MZDIRfewUNHOg4AAACDeyJvcmlnaW4iOiAiaHR0cHM6Ly90aGlyZHBhcnR5LmNvbTo0NDMi"
      "LCAiZmVhdHVyZSI6ICJXZWJWaWV3WFJlcXVlc3RlZFdpdGhEZXByZWNhdGlvbiIsICJleHBp"
      "cnkiOiAyMDAwMDAwMDAwLCAiaXNUaGlyZFBhcnR5IjogdHJ1ZX0=";

  // Note that the tokens are for thirdparty.com, which is different from both
  // `appropriate_origin_` (valid.example.com) and `inappropriate_origin_`
  // (invalid.example.com)
  url::Origin scriptOrigins[] = {appropriate_origin_};

  // First party tokens should match the origin, so we expect a non-success
  // result.
  TrialTokenResult firstPartyResult = validator_.ValidateTokenAndTrial(
      kXRW1PToken, inappropriate_origin_, scriptOrigins, Now());
  EXPECT_EQ(blink::OriginTrialTokenStatus::kWrongOrigin,
            firstPartyResult.Status());

  // For this trial only, we have disabled the origin check on third-party
  // tokens. See |trial_token.cc|.
  TrialTokenResult thirdPartyResult = validator_.ValidateTokenAndTrial(
      kXRW3PToken, inappropriate_origin_, scriptOrigins, Now());
  EXPECT_EQ(blink::OriginTrialTokenStatus::kSuccess, thirdPartyResult.Status());
}

}  // namespace blink::trial_token_validator_unittest
```
Response:
The user wants me to summarize the functionality of the provided C++ code snippet. This code snippet is part of a larger test file for the Content Security Policy (CSP) implementation in the Chromium Blink engine.

My plan is to:
1. Identify the main purpose of the code: testing CSP functionalities.
2. Analyze the individual test cases and their objectives.
3. Group similar test cases to provide a concise summary.
4. Identify the relationships with Javascript, HTML, and CSS.
5. Look for examples of logical reasoning and user/programming errors.
这个代码片段主要测试了Content Security Policy (CSP) 的以下功能：

**1. 基于 Scheme 的 CSP 绕过控制:**

*   **功能:** 测试了 `SchemeRegistry::RegisterURLSchemeAsBypassingContentSecurityPolicy` 方法，该方法允许将特定 URL scheme 注册为可以绕过 CSP 策略。
*   **与 JavaScript, HTML, CSS 的关系:** 当网站需要加载来自特定 scheme (例如 `filesystem:` 或 `blob:`) 的资源时，CSP 可能会阻止这些请求。通过将这些 scheme 注册为可绕过 CSP，可以允许加载这些资源，这可能涉及到加载 JavaScript 文件、HTML 内容或者 CSS 样式。
*   **逻辑推理:**
    *   **假设输入:**  CSP 策略设置为只允许来自 `https://example.com` 的资源。一个 `filesystem:` 或 `blob:` URL 指向 `https://example.com`，另一个指向 `https://not-example.com`。
    *   **预期输出:** 在注册 "https" 为可绕过 CSP 之前，这两个 URL 都会被阻止。注册之后，这两个 URL 都被允许。
*   **用户/编程常见的使用错误:** 错误地将过于宽泛的 scheme (例如 "http") 注册为可绕过 CSP，可能会引入安全风险，因为这会允许加载来自任何 HTTP 源的资源，即使 CSP 策略原本禁止这样做。

**2. 特权 Scheme 下的 CSP 绕过禁用:**

*   **功能:** 测试了即使某个 scheme 被注册为可绕过 CSP，但如果当前文档的 scheme 是特权的（例如 "https"），则 CSP 绕过规则将被忽略。
*   **与 JavaScript, HTML, CSS 的关系:**  这影响了在 HTTPS 页面中加载 HTTP 资源的能力，即使 "http" 被设置为可以绕过 CSP。这对于确保 HTTPS 页面的安全性至关重要。
*   **逻辑推理:**
    *   **假设输入:** CSP 策略设置为只允许来自 `http://example.com` 的脚本。 "http" 被注册为可绕过 CSP。当前页面的 URL 使用 "https" scheme (被标记为 privileged)。
    *   **预期输出:** 来自 `http://not-example.com` 的脚本仍然会被阻止，即使 "http" 理论上应该可以绕过 CSP。
*   **用户/编程常见的使用错误:**  开发者可能会误以为注册了 scheme 就可以在任何情况下绕过 CSP，而忽略了特权 scheme 的限制，导致资源加载失败。

**3. `trusted-types` 指令测试:**

*   **功能:**  测试了 `trusted-types` CSP 指令的不同语法和行为，包括允许的 policy 名称、通配符、重复名称以及报告模式和强制模式的区别。
*   **与 JavaScript, HTML, CSS 的关系:** `trusted-types` 旨在防止 DOM XSS 攻击，它要求某些 API (如设置 `innerHTML`) 的参数必须是 Trusted Types 对象，从而限制了不安全的数据注入。这些测试验证了 CSP 如何控制哪些 Trusted Type policy 是允许的。
*   **逻辑推理:**
    *   **假设输入:** 不同的 `trusted-types` 指令字符串，以及尝试创建和使用不同名称的 Trusted Type policy。
    *   **预期输出:** 根据 `trusted-types` 指令，某些 policy 名称会被允许，某些会被阻止。对于允许重复的指令，重复创建 policy 不会被阻止。报告模式下，即使违反策略也不会阻止操作，但会生成报告。强制模式下，违反策略的操作会被阻止。
*   **用户/编程常见的使用错误:**
    *   在强制模式下使用了未在 `trusted-types` 指令中声明的 policy 名称。
    *   在不允许重复的情况下，尝试创建同名的 Trusted Type policy。
    *   混淆了报告模式和强制模式的区别。

**4. `require-trusted-types-for` 指令测试:**

*   **功能:** 测试了 `require-trusted-types-for` CSP 指令，该指令可以强制页面上的所有脚本都必须使用 Trusted Types。
*   **与 JavaScript, HTML, CSS 的关系:**  该指令直接影响 JavaScript 代码的执行，要求开发者使用 Trusted Types 来操作 DOM，从而增强安全性。
*   **逻辑推理:**
    *   **假设输入:**  `require-trusted-types-for 'script'` 指令被设置。
    *   **预期输出:**  `csp->IsRequireTrustedTypes()` 返回 true，表示强制使用 Trusted Types。
*   **用户/编程常见的使用错误:**  在启用了 `require-trusted-types-for` 的情况下，编写了没有使用 Trusted Types 的 JavaScript 代码，导致运行时错误。

**总结本代码片段的功能:**

这个代码片段主要集中测试了 CSP 中关于 **scheme 绕过机制**以及 **Trusted Types 功能**的实现细节和各种边界情况。它验证了如何通过注册 scheme 来允许特定类型的请求，以及特权 scheme 如何影响这种绕过。 此外，它详细测试了 `trusted-types` 和 `require-trusted-types-for` 指令的解析、生效逻辑和不同配置下的行为，确保 CSP 能够正确地控制 Trusted Types 的使用，从而提高 Web 应用的安全性。

### 提示词
```
这是目录为blink/renderer/core/frame/csp/content_security_policy_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
cure_url);  // https://example.com
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "default-src https://example.com", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));

  const KURL example_url("filesystem:https://example.com/file.txt");
  EXPECT_FALSE(csp->AllowRequest(mojom::blink::RequestContextType::OBJECT,
                                 network::mojom::RequestDestination::kEmpty,
                                 example_url, String(), IntegrityMetadataSet(),
                                 kParserInserted, example_url,
                                 ResourceRequest::RedirectStatus::kNoRedirect,
                                 ReportingDisposition::kSuppressReporting));

  const KURL not_example_url("filesystem:https://not-example.com/file.txt");
  EXPECT_FALSE(csp->AllowRequest(
      mojom::blink::RequestContextType::OBJECT,
      network::mojom::RequestDestination::kEmpty, not_example_url, String(),
      IntegrityMetadataSet(), kParserInserted, not_example_url,
      ResourceRequest::RedirectStatus::kNoRedirect,
      ReportingDisposition::kSuppressReporting));

  // Register "https" as bypassing CSP, which should now bypass it entirely
  SchemeRegistry::RegisterURLSchemeAsBypassingContentSecurityPolicy("https");

  EXPECT_TRUE(csp->AllowRequest(mojom::blink::RequestContextType::OBJECT,
                                network::mojom::RequestDestination::kEmpty,
                                example_url, String(), IntegrityMetadataSet(),
                                kParserInserted, example_url,
                                ResourceRequest::RedirectStatus::kNoRedirect,
                                ReportingDisposition::kSuppressReporting));

  EXPECT_TRUE(csp->AllowRequest(
      mojom::blink::RequestContextType::OBJECT,
      network::mojom::RequestDestination::kEmpty, not_example_url, String(),
      IntegrityMetadataSet(), kParserInserted, not_example_url,
      ResourceRequest::RedirectStatus::kNoRedirect,
      ReportingDisposition::kSuppressReporting));

  SchemeRegistry::RemoveURLSchemeRegisteredAsBypassingContentSecurityPolicy(
      "https");
}

TEST_F(ContentSecurityPolicyTest, BlobAllowedWhenBypassingCSP) {
  const KURL base;
  CreateExecutionContext();
  execution_context->GetSecurityContext().SetSecurityOrigin(
      secure_origin);                     // https://example.com
  execution_context->SetURL(secure_url);  // https://example.com
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "default-src https://example.com", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));

  const KURL example_url("blob:https://example.com/");
  EXPECT_FALSE(csp->AllowRequest(mojom::blink::RequestContextType::OBJECT,
                                 network::mojom::RequestDestination::kEmpty,
                                 example_url, String(), IntegrityMetadataSet(),
                                 kParserInserted, example_url,
                                 ResourceRequest::RedirectStatus::kNoRedirect,
                                 ReportingDisposition::kSuppressReporting));

  const KURL not_example_url("blob:https://not-example.com/");
  EXPECT_FALSE(csp->AllowRequest(
      mojom::blink::RequestContextType::OBJECT,
      network::mojom::RequestDestination::kEmpty, not_example_url, String(),
      IntegrityMetadataSet(), kParserInserted, not_example_url,
      ResourceRequest::RedirectStatus::kNoRedirect,
      ReportingDisposition::kSuppressReporting));

  // Register "https" as bypassing CSP, which should now bypass it entirely
  SchemeRegistry::RegisterURLSchemeAsBypassingContentSecurityPolicy("https");

  EXPECT_TRUE(csp->AllowRequest(mojom::blink::RequestContextType::OBJECT,
                                network::mojom::RequestDestination::kEmpty,
                                example_url, String(), IntegrityMetadataSet(),
                                kParserInserted, example_url,
                                ResourceRequest::RedirectStatus::kNoRedirect,
                                ReportingDisposition::kSuppressReporting));

  EXPECT_TRUE(csp->AllowRequest(
      mojom::blink::RequestContextType::OBJECT,
      network::mojom::RequestDestination::kEmpty, not_example_url, String(),
      IntegrityMetadataSet(), kParserInserted, not_example_url,
      ResourceRequest::RedirectStatus::kNoRedirect,
      ReportingDisposition::kSuppressReporting));

  SchemeRegistry::RemoveURLSchemeRegisteredAsBypassingContentSecurityPolicy(
      "https");
}

TEST_F(ContentSecurityPolicyTest, CSPBypassDisabledWhenSchemeIsPrivileged) {
  const KURL base;
  CreateExecutionContext();
  execution_context->GetSecurityContext().SetSecurityOrigin(secure_origin);
  execution_context->SetURL(BlankURL());
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "script-src http://example.com", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));

  const KURL allowed_url("http://example.com/script.js");
  const KURL http_url("http://not-example.com/script.js");
  const KURL blob_url(base, "blob:http://not-example.com/uuid");
  const KURL filesystem_url(base, "filesystem:http://not-example.com/file.js");

  // The {Requests,Blob,Filesystem}AllowedWhenBypassingCSP tests have already
  // ensured that RegisterURLSchemeAsBypassingContentSecurityPolicy works as
  // expected.
  //
  // "http" is registered as bypassing CSP, but the context's scheme ("https")
  // is marked as a privileged scheme, so the bypass rule should be ignored.
  SchemeRegistry::RegisterURLSchemeAsBypassingContentSecurityPolicy("http");
  SchemeRegistry::RegisterURLSchemeAsNotAllowingJavascriptURLs("https");

  EXPECT_TRUE(csp->AllowScriptFromSource(
      allowed_url, String(), IntegrityMetadataSet(), kNotParserInserted,
      allowed_url, ResourceRequest::RedirectStatus::kNoRedirect,
      ReportingDisposition::kSuppressReporting));
  EXPECT_FALSE(csp->AllowScriptFromSource(
      http_url, String(), IntegrityMetadataSet(), kNotParserInserted, http_url,
      ResourceRequest::RedirectStatus::kNoRedirect,
      ReportingDisposition::kSuppressReporting));
  EXPECT_FALSE(csp->AllowScriptFromSource(
      blob_url, String(), IntegrityMetadataSet(), kNotParserInserted, blob_url,
      ResourceRequest::RedirectStatus::kNoRedirect,
      ReportingDisposition::kSuppressReporting));
  EXPECT_FALSE(csp->AllowScriptFromSource(
      filesystem_url, String(), IntegrityMetadataSet(), kNotParserInserted,
      filesystem_url, ResourceRequest::RedirectStatus::kNoRedirect,
      ReportingDisposition::kSuppressReporting));

  SchemeRegistry::RemoveURLSchemeRegisteredAsBypassingContentSecurityPolicy(
      "http");
  SchemeRegistry::RemoveURLSchemeAsNotAllowingJavascriptURLs("https");
}

TEST_F(ContentSecurityPolicyTest, TrustedTypesNoDirective) {
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));

  ContentSecurityPolicy::AllowTrustedTypePolicyDetails violation_details;
  EXPECT_TRUE(
      csp->AllowTrustedTypePolicy("somepolicy", false, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);
  EXPECT_TRUE(
      csp->AllowTrustedTypePolicy("somepolicy", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);
}

TEST_F(ContentSecurityPolicyTest, TrustedTypesSimpleDirective) {
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "trusted-types one two three", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));
}

TEST_F(ContentSecurityPolicyTest, TrustedTypesWhitespace) {
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "trusted-types one\ntwo\rthree", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));

  ContentSecurityPolicy::AllowTrustedTypePolicyDetails violation_details;
  EXPECT_TRUE(csp->AllowTrustedTypePolicy("one", false, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);
  EXPECT_TRUE(csp->AllowTrustedTypePolicy("two", false, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);
  EXPECT_TRUE(csp->AllowTrustedTypePolicy("three", false, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);

  EXPECT_FALSE(csp->AllowTrustedTypePolicy("four", false, violation_details));
  EXPECT_EQ(
      violation_details,
      ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kDisallowedName);
  EXPECT_FALSE(csp->AllowTrustedTypePolicy("one", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::
                kDisallowedDuplicateName);
  EXPECT_FALSE(csp->AllowTrustedTypePolicy("four", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::
                kDisallowedDuplicateName);
}

TEST_F(ContentSecurityPolicyTest, TrustedTypesEmpty) {
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "trusted-types", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));

  ContentSecurityPolicy::AllowTrustedTypePolicyDetails violation_details;
  EXPECT_FALSE(
      csp->AllowTrustedTypePolicy("somepolicy", false, violation_details));
  EXPECT_EQ(
      violation_details,
      ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kDisallowedName);
  EXPECT_FALSE(
      csp->AllowTrustedTypePolicy("somepolicy", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::
                kDisallowedDuplicateName);
}

TEST_F(ContentSecurityPolicyTest, TrustedTypesStar) {
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "trusted-types *", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));

  ContentSecurityPolicy::AllowTrustedTypePolicyDetails violation_details;
  EXPECT_TRUE(
      csp->AllowTrustedTypePolicy("somepolicy", false, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);
  EXPECT_FALSE(
      csp->AllowTrustedTypePolicy("somepolicy", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::
                kDisallowedDuplicateName);
}

TEST_F(ContentSecurityPolicyTest, TrustedTypesStarMix) {
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "trusted-types abc * def", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));

  ContentSecurityPolicy::AllowTrustedTypePolicyDetails violation_details;
  EXPECT_TRUE(csp->AllowTrustedTypePolicy("abc", false, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);
  EXPECT_TRUE(csp->AllowTrustedTypePolicy("def", false, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);
  EXPECT_TRUE(csp->AllowTrustedTypePolicy("ghi", false, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);

  EXPECT_FALSE(csp->AllowTrustedTypePolicy("abc", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::
                kDisallowedDuplicateName);
  EXPECT_FALSE(csp->AllowTrustedTypePolicy("def", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::
                kDisallowedDuplicateName);
  EXPECT_FALSE(csp->AllowTrustedTypePolicy("ghi", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::
                kDisallowedDuplicateName);
}

TEST_F(ContentSecurityPolicyTest, TrustedTypeDupe) {
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "trusted-types somepolicy 'allow-duplicates'",
      ContentSecurityPolicyType::kEnforce, ContentSecurityPolicySource::kHTTP,
      *secure_origin));

  ContentSecurityPolicy::AllowTrustedTypePolicyDetails violation_details;
  EXPECT_TRUE(
      csp->AllowTrustedTypePolicy("somepolicy", false, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);
  EXPECT_TRUE(
      csp->AllowTrustedTypePolicy("somepolicy", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);
}

TEST_F(ContentSecurityPolicyTest, TrustedTypeDupeStar) {
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "trusted-types * 'allow-duplicates'", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));

  ContentSecurityPolicy::AllowTrustedTypePolicyDetails violation_details;
  EXPECT_TRUE(
      csp->AllowTrustedTypePolicy("somepolicy", false, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);
  EXPECT_TRUE(
      csp->AllowTrustedTypePolicy("somepolicy", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);
}

TEST_F(ContentSecurityPolicyTest, TrustedTypesReserved) {
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "trusted-types one \"two\" 'three'", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));

  ContentSecurityPolicy::AllowTrustedTypePolicyDetails violation_details;
  EXPECT_TRUE(csp->AllowTrustedTypePolicy("one", false, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);
  EXPECT_FALSE(csp->AllowTrustedTypePolicy("one", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::
                kDisallowedDuplicateName);

  // Quoted strings are considered 'reserved':
  EXPECT_FALSE(csp->AllowTrustedTypePolicy("two", false, violation_details));
  EXPECT_EQ(
      violation_details,
      ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kDisallowedName);
  EXPECT_FALSE(
      csp->AllowTrustedTypePolicy("\"two\"", false, violation_details));
  EXPECT_EQ(
      violation_details,
      ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kDisallowedName);
  EXPECT_FALSE(csp->AllowTrustedTypePolicy("three", false, violation_details));
  EXPECT_EQ(
      violation_details,
      ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kDisallowedName);
  EXPECT_FALSE(
      csp->AllowTrustedTypePolicy("'three'", false, violation_details));
  EXPECT_EQ(
      violation_details,
      ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kDisallowedName);
  EXPECT_FALSE(csp->AllowTrustedTypePolicy("two", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::
                kDisallowedDuplicateName);
  EXPECT_FALSE(csp->AllowTrustedTypePolicy("\"two\"", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::
                kDisallowedDuplicateName);
  EXPECT_FALSE(csp->AllowTrustedTypePolicy("three", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::
                kDisallowedDuplicateName);
  EXPECT_FALSE(csp->AllowTrustedTypePolicy("'three'", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::
                kDisallowedDuplicateName);
}

TEST_F(ContentSecurityPolicyTest, TrustedTypesReportingStar) {
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "trusted-types *", ContentSecurityPolicyType::kReport,
      ContentSecurityPolicySource::kHTTP, *secure_origin));

  ContentSecurityPolicy::AllowTrustedTypePolicyDetails violation_details;
  EXPECT_TRUE(
      csp->AllowTrustedTypePolicy("somepolicy", false, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);
  EXPECT_TRUE(
      csp->AllowTrustedTypePolicy("somepolicy", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::
                kDisallowedDuplicateName);
}

TEST_F(ContentSecurityPolicyTest, TrustedTypeReportingSimple) {
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "trusted-types a b c", ContentSecurityPolicyType::kReport,
      ContentSecurityPolicySource::kHTTP, *secure_origin));

  ContentSecurityPolicy::AllowTrustedTypePolicyDetails violation_details;
  EXPECT_TRUE(csp->AllowTrustedTypePolicy("a", false, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);
  EXPECT_TRUE(csp->AllowTrustedTypePolicy("a", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::
                kDisallowedDuplicateName);
}

TEST_F(ContentSecurityPolicyTest, TrustedTypeEnforce) {
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "trusted-types one\ntwo\rthree", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));
  EXPECT_FALSE(csp->IsRequireTrustedTypes());
  EXPECT_TRUE(csp->AllowTrustedTypeAssignmentFailure("blabla"));
}

TEST_F(ContentSecurityPolicyTest, TrustedTypeReport) {
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "trusted-types one\ntwo\rthree", ContentSecurityPolicyType::kReport,
      ContentSecurityPolicySource::kHTTP, *secure_origin));
  EXPECT_FALSE(csp->IsRequireTrustedTypes());
  EXPECT_TRUE(csp->AllowTrustedTypeAssignmentFailure("blabla"));
}

TEST_F(ContentSecurityPolicyTest, TrustedTypeReportAndEnforce) {
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "trusted-types one", ContentSecurityPolicyType::kReport,
      ContentSecurityPolicySource::kHTTP, *secure_origin));
  csp->AddPolicies(ParseContentSecurityPolicies(
      "trusted-types two", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));
  EXPECT_FALSE(csp->IsRequireTrustedTypes());
  EXPECT_TRUE(csp->AllowTrustedTypeAssignmentFailure("blabla"));
}

TEST_F(ContentSecurityPolicyTest, TrustedTypeReportAndNonTTEnforce) {
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "trusted-types one", ContentSecurityPolicyType::kReport,
      ContentSecurityPolicySource::kHTTP, *secure_origin));
  csp->AddPolicies(ParseContentSecurityPolicies(
      "script-src none", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));
  EXPECT_FALSE(csp->IsRequireTrustedTypes());
  EXPECT_TRUE(csp->AllowTrustedTypeAssignmentFailure("blabla"));
}

TEST_F(ContentSecurityPolicyTest, RequireTrustedTypeForEnforce) {
  execution_context->SetRequireTrustedTypesForTesting();
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "require-trusted-types-for ''", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));
  EXPECT_FALSE(csp->IsRequireTrustedTypes());

  csp->AddPolicies(ParseContentSecurityPolicies(
      "require-trusted-types-for 'script'", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));
  EXPECT_TRUE(csp->IsRequireTrustedTypes());
}

TEST_F(ContentSecurityPolicyTest, RequireTrustedTypeForReport) {
  execution_context->SetRequireTrustedTypesForTesting();
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "require-trusted-types-for 'script'", ContentSecurityPolicyType::kReport,
      ContentSecurityPolicySource::kHTTP, *secure_origin));
  EXPECT_TRUE(csp->IsRequireTrustedTypes());
}

TEST_F(ContentSecurityPolicyTest, DefaultPolicy) {
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "trusted-types *", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));

  ContentSecurityPolicy::AllowTrustedTypePolicyDetails violation_details;
  EXPECT_TRUE(csp->AllowTrustedTypePolicy("default", false, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);
  EXPECT_FALSE(csp->AllowTrustedTypePolicy("default", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::
                kDisallowedDuplicateName);
}

TEST_F(ContentSecurityPolicyTest, DirectiveNameCaseInsensitive) {
  KURL example_url("http://example.com");
  KURL not_example_url("http://not-example.com");

  // Directive name is case insensitive.
  csp = MakeGarbageCollected<ContentSecurityPolicy>();
  csp->AddPolicies(ParseContentSecurityPolicies(
      "sCrIpt-sRc http://example.com", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());

  EXPECT_TRUE(csp->AllowScriptFromSource(
      example_url, String(), IntegrityMetadataSet(), kParserInserted,
      example_url, ResourceRequest::RedirectStatus::kNoRedirect));
  EXPECT_FALSE(csp->AllowScriptFromSource(
      not_example_url, String(), IntegrityMetadataSet(), kParserInserted,
      not_example_url, ResourceRequest::RedirectStatus::kNoRedirect));

  // Duplicate directive that is in a different case pattern is
  // correctly treated as a duplicate directive and ignored.
  csp = MakeGarbageCollected<ContentSecurityPolicy>();
  csp->AddPolicies(ParseContentSecurityPolicies(
      "SCRipt-SRC http://example.com; script-src http://not-example.com;",
      ContentSecurityPolicyType::kEnforce, ContentSecurityPolicySource::kHTTP,
      *secure_origin));
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());

  EXPECT_TRUE(csp->AllowScriptFromSource(
      example_url, String(), IntegrityMetadataSet(), kParserInserted,
      example_url, ResourceRequest::RedirectStatus::kNoRedirect));
  EXPECT_FALSE(csp->AllowScriptFromSource(
      not_example_url, String(), IntegrityMetadataSet(), kParserInserted,
      not_example_url, ResourceRequest::RedirectStatus::kNoRedirect));
}

// Tests that using an empty CSP works and doesn't impose any policy
// restrictions.
TEST_F(ContentSecurityPolicyTest, EmptyCSPIsNoOp) {
  csp = MakeGarbageCollected<ContentSecurityPolicy>();
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());

  const KURL example_url("http://example.com");
  auto* document = Document::CreateForTest(*execution_context);
  String source;
  String context_url;
  String nonce;
  OrdinalNumber ordinal_number = OrdinalNumber::First();
  auto* element =
      MakeGarbageCollected<HTMLScriptElement>(*document, CreateElementFlags());

  EXPECT_TRUE(csp->AllowInline(ContentSecurityPolicy::InlineType::kNavigation,
                               element, source, String() /* nonce */,
                               context_url, ordinal_number));
  EXPECT_TRUE(csp->AllowInline(
      ContentSecurityPolicy::InlineType::kScriptAttribute, element, source,
      String() /* nonce */, context_url, ordinal_number));
  EXPECT_TRUE(csp->AllowEval(ReportingDisposition::kReport,
                             ContentSecurityPolicy::kWillNotThrowException,
                             g_empty_string));
  EXPECT_TRUE(csp->AllowWasmCodeGeneration(
      ReportingDisposition::kReport,
      ContentSecurityPolicy::kWillNotThrowException, g_empty_string));

  CSPDirectiveName types_to_test[] = {
      CSPDirectiveName::BaseURI,       CSPDirectiveName::ConnectSrc,
      CSPDirectiveName::FontSrc,       CSPDirectiveName::FormAction,
      CSPDirectiveName::FrameSrc,      CSPDirectiveName::ImgSrc,
      CSPDirectiveName::ManifestSrc,   CSPDirectiveName::MediaSrc,
      CSPDirectiveName::ObjectSrc,     CSPDirectiveName::ScriptSrcElem,
      CSPDirectiveName::StyleSrcElem,  CSPDirectiveName::WorkerSrc,
      CSPDirectiveName::FencedFrameSrc};
  for (auto type : types_to_test) {
    EXPECT_TRUE(
        csp->AllowFromSource(type, example_url, example_url,
                             ResourceRequest::RedirectStatus::kNoRedirect));
  }

  EXPECT_TRUE(csp->AllowObjectFromSource(example_url));
  EXPECT_TRUE(csp->AllowImageFromSource(
      example_url, example_url, ResourceRequest::RedirectStatus::kNoRedirect));
  EXPECT_TRUE(csp->AllowMediaFromSource(example_url));
  EXPECT_TRUE(csp->AllowConnectToSource(
      example_url, example_url, ResourceRequest::RedirectStatus::kNoRedirect));
  EXPECT_TRUE(csp->AllowFormAction(example_url));
  EXPECT_TRUE(csp->AllowBaseURI(example_url));
  EXPECT_TRUE(csp->AllowWorkerContextFromSource(example_url));
  EXPECT_TRUE(csp->AllowScriptFromSource(
      example_url, nonce, IntegrityMetadataSet(), kParserInserted, example_url,
      ResourceRequest::RedirectStatus::kNoRedirect));

  ContentSecurityPolicy::AllowTrustedTypePolicyDetails violation_details;

  EXPECT_TRUE(
      csp->AllowTrustedTypePolicy("somepolicy", true, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);
  EXPECT_TRUE(
      csp->AllowTrustedTypePolicy("somepolicy", false, violation_details));
  EXPECT_EQ(violation_details,
            ContentSecurityPolicy::AllowTrustedTypePolicyDetails::kAllowed);
  EXPECT_TRUE(csp->AllowInline(ContentSecurityPolicy::InlineType::kScript,
                               element, source, nonce, context_url,
                               ordinal_number));
  EXPECT_TRUE(csp->AllowInline(ContentSecurityPolicy::InlineType::kStyle,
                               element, source, nonce, context_url,
                               ordinal_number));
  EXPECT_TRUE(csp->AllowRequest(mojom::blink::RequestContextType::SCRIPT,
                                network::mojom::RequestDestination::kScript,
                                example_url, nonce, IntegrityMetadataSet(),
                                kParserInserted, example_url,
                                ResourceRequest::RedirectStatus::kNoRedirect));
  EXPECT_FALSE(csp->IsActive());
  EXPECT_FALSE(csp->IsActiveForConnections());
  EXPECT_TRUE(csp->FallbackUrlForPlugin().IsEmpty());
  EXPECT_EQ(mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone,
            csp->GetInsecureRequestPolicy());
  EXPECT_FALSE(csp->HasHeaderDeliveredPolicy());
  EXPECT_FALSE(csp->SupportsWasmEval());
  EXPECT_EQ(network::mojom::blink::WebSandboxFlags::kNone,
            csp->GetSandboxMask());
  EXPECT_FALSE(csp->HasPolicyFromSource(ContentSecurityPolicySource::kHTTP));
}

TEST_F(ContentSecurityPolicyTest, WasmUnsafeEvalCSPEnable) {
  csp = MakeGarbageCollected<ContentSecurityPolicy>();
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());

  csp->AddPolicies(ParseContentSecurityPolicies(
      "script-src 'wasm-unsafe-eval'", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));

  EXPECT_TRUE(csp->AllowWasmCodeGeneration(
      ReportingDisposition::kReport,
      ContentSecurityPolicy::kWillNotThrowException, g_empty_string));
}

TEST_F(ContentSecurityPolicyTest, OpaqueOriginBeforeBind) {
  const KURL url("https://example.test");

  // Security Origin of execution context might change when sandbox flags
  // are applied. This shouldn't change the application of the 'self'
  // determination.
  secure_origin = secure_origin->DeriveNewOpaqueOrigin();
  CreateExecutionContext();
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "default-src 'self';", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kMeta, *secure_origin));
  EXPECT_TRUE(csp->AllowRequest(mojom::blink::RequestContextType::SUBRESOURCE,
                                network::mojom::RequestDestination::kEmpty, url,
                                String(), IntegrityMetadataSet(),
                                kParserInserted, url,
                                ResourceRequest::RedirectStatus::kNoRedirect,
                                ReportingDisposition::kSuppressReporting));
}

TEST_F(ContentSecurityPolicyTest, SelfForDataMatchesNothing) {
  const KURL url("https://example.test");
  auto reference_origin = SecurityOrigin::Create(url);
  const KURL data_url("data:text/html,hello");
  secure_origin = SecurityOrigin::CreateWithReferenceOrigin(
      data_url, reference_origin.get());

  CreateExecutionContext();
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "default-src 'self';", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kMeta, *secure_origin));
  EXPECT_TRUE(csp->AllowRequest(mojom::blink::RequestContextType::SUBRESOURCE,
                                network::mojom::RequestDestination::kEmpty, url,
                                String(), IntegrityMetadataSet(),
                                kParserInserted, url,
                                ResourceRequest::RedirectStatus::kNoRedirect,
                                ReportingDisposition::kSuppressReporting));
  EXPECT_FALSE(csp->AllowRequest(mojom::blink::RequestContextType::SUBRESOURCE,
                                 network::mojom::RequestDestination::kEmpty,
                                 data_url, String(), IntegrityMetadataSet(),
                                 kParserInserted, url,
                                 ResourceRequest::RedirectStatus::kNoRedirect,
                                 ReportingDisposition::kSuppressReporting));
}

TEST_F(ContentSecurityPolicyTest, IsStrictPolicyEnforced) {
  // No policy, no strictness.
  csp = MakeGarbageCollected<ContentSecurityPolicy>();
  EXPECT_FALSE(csp->IsStrictPolicyEnforced());

  // Strict policy, strictness.
  const char* strict_policy =
      "object-src 'none'; "
      "script-src 'nonce-abc' 'unsafe-inline' 'unsafe-eval' 'strict-dynamic' "
      "           https: http:;"
      "base-uri 'none';";
  csp->AddPolicies(ParseContentSecurityPolicies(
      strict_policy, ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));
  EXPECT_TRUE(csp->IsStrictPolicyEnforced());

  // Report-only strict policy, no strictness.
  csp = MakeGarbageCollected<ContentSecurityPolicy>();
  csp->AddPolicies(ParseContentSecurityPolicies(
      strict_policy, ContentSecurity
```
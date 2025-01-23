Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's Blink engine. This code is part of the `permissions_policy_test.cc` file and seems to focus on testing the parsing of Permissions Policy and Feature Policy headers.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename and the test suite names like `PermissionsPolicyParserParsingTest` clearly indicate that the primary function is testing the parsing logic for Permissions Policy and Feature Policy headers.

2. **Analyze the test cases:** The code includes several test cases within the `kCases` array. Each test case defines:
    * `test_name`: A descriptive name for the test.
    * `feature_policy_string`: A string representing a Feature Policy header.
    * `permissions_policy_string`: A string representing a Permissions Policy header.
    * `self_origin`: The origin of the current document.
    * `src_origin`: The origin of the resource being loaded.
    * `expected_parse_result`: The expected outcome after parsing the policy strings.

3. **Connect to web technologies (JavaScript, HTML, CSS):**  Permissions Policy and Feature Policy are mechanisms to control the use of browser features. This directly relates to JavaScript APIs (e.g., `navigator.geolocation`), HTML elements (e.g., `<iframe allow="fullscreen">`), and can be delivered via HTTP headers.

4. **Provide illustrative examples:** For each connection to web technologies, provide concrete examples of how these policies affect them. This makes the explanation more understandable.

5. **Explain the logic of the tests:** Describe how the test cases verify the parsing logic by comparing the actual parsed output with the `expected_parse_result`. Highlight how different scenarios (valid, invalid, conflicting policies, reporting endpoints) are tested.

6. **Address potential user errors:**  Consider common mistakes developers might make when using these policies, such as incorrect syntax or understanding the precedence rules between Feature Policy and Permissions Policy.

7. **Trace user actions to the code:** Explain how a developer might encounter this code during debugging, such as investigating why a certain browser feature is not working as expected or while working on implementing or modifying policy parsing logic in Blink.

8. **Summarize the functionality of the provided part:**  Focus on the specific aspects covered in the given code snippet, such as testing parsing of reporting endpoints, handling duplicated declarations, and interactions between Feature Policy and Permissions Policy headers.

9. **Structure the answer:** Organize the information logically with clear headings and bullet points for readability.

10. **Refine and review:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any ambiguities or missing information. For instance, initially, I might not have explicitly mentioned the role of `PolicyParserMessageBuffer` for capturing parsing errors/warnings, but reviewing the code highlights its importance. Similarly, initially, the connection between the test cases and the underlying parsing functions might not have been explicit enough, so I added clarification. The emphasis on the *last* declaration winning in Permissions Policy and the *first* in Feature Policy is a crucial detail to highlight.

By following these steps, the goal is to produce a comprehensive and easy-to-understand explanation of the provided code snippet and its role in the larger context of Chromium's Blink engine.
这是第2部分，延续了对 `blink/renderer/core/permissions_policy/permissions_policy_test.cc` 文件的功能描述。基于你提供的代码片段，我们可以继续归纳其功能：

**归纳 `permissions_policy_test.cc` (第2部分) 的功能：**

这部分代码主要集中在以下几个方面，继续验证 Permissions Policy 和 Feature Policy 的解析逻辑以及它们之间的交互：

1. **测试 Reporting Endpoints 的解析：**
   - 测试了 `report-to` 指令在 Permissions Policy 中的解析，包括：
     - 允许列表内外都指定 reporting endpoint。
     - 为不同的 feature 指定不同的 reporting endpoint。
     - reporting endpoint 的值不合法（例如布尔值、数字）。
   - 这部分测试确保了 Permissions Policy 可以正确解析和处理 reporting endpoint 的配置，以便在策略违规时发送报告。

2. **测试重复 Feature 声明的处理：**
   - 区分了 Feature Policy 和 Permissions Policy 在处理重复 feature 声明时的不同行为：
     - **Feature Policy:**  采用**第一个**声明的值。
     - **Permissions Policy:** 采用**最后一个**声明的值。
   - 这些测试确保了 Blink 引擎正确遵循了这两种策略在处理重复声明上的规范。

3. **测试 Feature Policy 和 Permissions Policy 并存时的冲突处理：**
   - 当同一个 feature 在两个 header 中都有声明时，Permissions Policy 的值会覆盖 Feature Policy 的值。
   - 测试了非冲突的 feature 会被合并。

4. **测试重复声明导致警告信息：**
   - 当同一个 feature 同时存在于 Feature Policy 和 Permissions Policy 中时，会产生一条警告信息，提示开发者。
   - 测试了警告信息的生成以及内容是否正确。

5. **测试使用不同的 Logger 记录不同 Policy 的消息：**
   - 可以使用不同的 `PolicyParserMessageBuffer` 实例来记录 Feature Policy 和 Permissions Policy 的解析消息。
   - 这有助于区分和管理不同策略的解析日志。

6. **测试 Attribute 中逗号分隔符的处理：**
   - 测试了在 HTML 标签的 `allow` 属性中使用逗号分隔符时，解析器的行为以及是否会产生错误信息。

7. **测试合法的和非法的 Header Policy 字符串：**
   - 使用预定义的合法和非法 Header Policy 字符串进行测试，验证解析器能否正确识别和处理。

8. **测试过长的 Policy 字符串：**
   - 测试了当 Policy 字符串过长时，解析器是否会报错。

9. **测试 Header 中 Policy 使用的 Histogram 统计：**
   - 使用 `base::HistogramTester` 来验证 Feature Policy header 中每个 feature 的使用次数是否被正确统计。
   - 即使同一个 feature 被声明多次，也只会被统计一次。

10. **测试逗号和分号分隔符的 Use Counter：**
    - 测试了使用逗号和分号分隔多个 feature 声明时，是否会触发相应的 Use Counter。这用于统计开发者在实践中如何使用这些分隔符。

11. **测试 Policy 对象的修改方法：**
    - 提供了一系列测试用例，用于验证对解析后的 Policy 对象进行修改的方法，例如：
        - `IsFeatureDeclared`: 检查某个 feature 是否已声明。
        - `RemoveFeatureIfPresent`: 移除指定的 feature（如果存在）。
        - `DisallowFeatureIfNotPresent`: 如果 feature 不存在，则添加一个禁止该 feature 的声明。
        - `AllowFeatureEverywhereIfNotPresent`: 如果 feature 不存在，则添加一个允许所有源使用该 feature 的声明。
        - `DisallowFeature`: 无条件禁止指定的 feature。
        - `AllowFeatureEverywhere`: 无条件允许所有源使用指定的 feature。
    - 这些测试确保了 Policy 对象提供的修改方法能够正确操作 Policy 数据。

12. **测试 Feature Policy 的可见性（与隔离上下文相关）：**
    - 测试了在不同的隔离上下文（Isolated Context）下，Feature Policy 的行为是否符合预期。例如，某些 feature (如 `controlled-frame`, `direct-sockets`) 可能只在隔离上下文中可用。

**与 JavaScript, HTML, CSS 的关系举例说明 (延续第1部分的例子):**

* **JavaScript:**  当 Permissions Policy 禁止某个 feature (例如 `geolocation`) 时，JavaScript 代码调用相关的 API (例如 `navigator.geolocation.getCurrentPosition()`) 将会失败，并可能抛出异常或返回错误。

* **HTML:**  如果 Permissions Policy 禁止 `fullscreen` feature，那么即使 HTML 元素上设置了 `allowfullscreen` 属性，并且 JavaScript 代码尝试调用 `element.requestFullscreen()`，全屏操作仍然会被阻止。

* **CSS:**  某些 CSS 功能可能也受到 Permissions Policy 的控制，例如与设备硬件交互的功能（尽管目前 CSS 与 Permissions Policy 的关联不如 JavaScript 紧密）。 例如，理论上未来可能会有控制硬件加速或特定渲染特性的策略。

**逻辑推理的假设输入与输出 (延续第1部分的例子):**

* **假设输入:**  一个带有以下 Permissions Policy header 的 HTTP 响应: `camera='self' "https://example.com"; microphone=*`
* **输出:**
    - 解析结果中会包含两个 feature 的声明：`camera` 和 `microphone`。
    - `camera` feature 仅允许当前源 (`'self'`) 和 `https://example.com` 使用。
    - `microphone` feature 允许所有源 (`*`) 使用。

**涉及用户或编程常见的使用错误 (延续第1部分的例子):**

* **错误地认为 Feature Policy 和 Permissions Policy 的重复声明处理方式相同。**  开发者可能会错误地认为后声明会覆盖前声明，而 Feature Policy 实际上是采用第一个声明。
* **忘记在 Permissions Policy 中使用分号分隔多个 feature 声明。** 例如，写成 `camera='self' microphone='self'` 而不是 `camera='self'; microphone='self'`。

**用户操作是如何一步步的到达这里，作为调试线索 (延续第1部分的例子):**

一个开发者在调试一个网页时，发现某些浏览器功能（例如摄像头访问）无法正常工作。他可能会采取以下步骤：

1. **检查浏览器控制台:** 查看是否有与 Permissions Policy 相关的报错信息。
2. **检查 HTTP 响应头:**  查看 `Permissions-Policy` 或 `Feature-Policy` header 的设置。
3. **如果策略设置有问题:**  开发者可能会修改服务器端的策略配置，然后重新加载页面进行测试。
4. **如果怀疑是 Blink 引擎解析策略的问题:**  开发者可能会查看 `blink/renderer/core/permissions_policy/permissions_policy_test.cc` 这样的测试文件，了解 Blink 引擎是如何解析和处理各种策略配置的，以便更好地理解问题所在，或者甚至贡献代码来修复潜在的 Bug。

总而言之，`permissions_policy_test.cc` 的这部分代码继续深入测试了 Permissions Policy 和 Feature Policy 的解析和处理逻辑，特别是关注了 reporting endpoints、重复声明的处理、两种策略之间的交互以及对解析后 Policy 对象的修改操作。这些测试对于确保 Chromium Blink 引擎能够正确、安全地执行 Web 平台的策略机制至关重要。

### 提示词
```
这是目录为blink/renderer/core/permissions_policy/permissions_policy_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
{
            /* test_name */ "ReportingEndpointsInsideAndOutsideList",
            /* feature_policy_string */ NOT_APPLICABLE,
            /* permissions_policy_string */
            "fullscreen=(\"" ORIGIN_C
            "\";report-to=endpoint1);report-to=endpoint2",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kFullscreen,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {{ORIGIN_C, /*has_subdomain_wildcard=*/false}},
                    /* reporting_endpoint */ "endpoint2",
                },
            },
        },
        // DifferentReportingEndpoints
        {
            /* test_name */ "DifferentReportingEndpoints",
            /* feature_policy_string */ NOT_APPLICABLE,
            /* permissions_policy_string */
            "fullscreen=\"" ORIGIN_B "\";report-to=endpoint1,"
            "geolocation=\"" ORIGIN_C "\";report-to=endpoint2",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kFullscreen,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {{ORIGIN_B, /*has_subdomain_wildcard=*/false}},
                    "endpoint1",
                },
                {
                    mojom::blink::PermissionsPolicyFeature::kGeolocation,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {{ORIGIN_C, /*has_subdomain_wildcard=*/false}},
                    "endpoint2",
                },
            },
        },
        {
            /* test_name */ "InvalidReportingEndpointsBool",
            /* feature_policy_string */ NOT_APPLICABLE,
            /* permissions_policy_string */
            "fullscreen=*;report-to",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kFullscreen,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ true,
                    /* matches_opaque_src */ true,
                    {},
                    /* reporting_endpoint */ std::nullopt,
                },
            },
        },
        {
            /* test_name */ "InvalidReportingEndpointsNumber",
            /* feature_policy_string */ NOT_APPLICABLE,
            /* permissions_policy_string */
            "fullscreen=*;report-to=7",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kFullscreen,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ true,
                    /* matches_opaque_src */ true,
                    {},
                    /* reporting_endpoint */ std::nullopt,
                },
            },
        },
};

INSTANTIATE_TEST_SUITE_P(
    All,
    PermissionsPolicyParserParsingTest,
    ::testing::ValuesIn(PermissionsPolicyParserParsingTest::kCases),
    [](const testing::TestParamInfo<PermissionsPolicyParserTestCase>&
           param_info) { return param_info.param.test_name; });

TEST_P(PermissionsPolicyParserParsingTest, FeaturePolicyParsedCorrectly) {
  PolicyParserMessageBuffer logger;
  const PermissionsPolicyParserTestCase& test_case = GetParam();
  if (test_case.feature_policy_string == NOT_APPLICABLE)
    return;

  ASSERT_NE(test_case.self_origin, nullptr);
  CheckParsedPolicy(
      ParseFeaturePolicy(test_case.feature_policy_string, test_case.self_origin,
                         test_case.src_origin, logger, test_feature_name_map),
      test_case.expected_parse_result);
}

TEST_P(PermissionsPolicyParserParsingTest, PermissionsPolicyParsedCorrectly) {
  PolicyParserMessageBuffer logger;
  const PermissionsPolicyParserTestCase& test_case = GetParam();
  if (test_case.permissions_policy_string == NOT_APPLICABLE)
    return;

  ASSERT_NE(test_case.self_origin, nullptr);
  CheckParsedPolicy(
      ParsePermissionsPolicy(test_case.permissions_policy_string,
                             test_case.self_origin, test_case.src_origin,
                             logger, test_feature_name_map),
      test_case.expected_parse_result);
}

TEST_F(PermissionsPolicyParserParsingTest,
       FeaturePolicyDuplicatedFeatureDeclaration) {
  PolicyParserMessageBuffer logger;

  // For Feature-Policy header, if there are multiple declaration for same
  // feature, the allowlist value from *FIRST* declaration will be taken.
  CheckParsedPolicy(
      PermissionsPolicyParser::ParseHeader(
          "geolocation 'none', geolocation 'self'", "", origin_a_.get(), logger,
          logger, nullptr /* context */),
      {
          {
              // allowlist value 'none' is expected.
              mojom::blink::PermissionsPolicyFeature::kGeolocation,
              /* self_if_matches */ std::nullopt,
              /* matches_all_origins */ false,
              /* matches_opaque_src */ false,
              {},
          },
      });

  EXPECT_TRUE(logger.GetMessages().empty());
}

TEST_F(PermissionsPolicyParserParsingTest,
       PermissionsPolicyDuplicatedFeatureDeclaration) {
  PolicyParserMessageBuffer logger;

  // For Permissions-Policy header, if there are multiple declaration for same
  // feature, the allowlist value from *LAST* declaration will be taken.
  CheckParsedPolicy(
      PermissionsPolicyParser::ParseHeader(
          "", "geolocation=(), geolocation=self", origin_a_.get(), logger,
          logger, nullptr /* context */),
      {
          {
              // allowlist value 'self' is expected.
              mojom::blink::PermissionsPolicyFeature::kGeolocation,
              /* self_if_matches */ ORIGIN_A,
              /* matches_all_origins */ false,
              /* matches_opaque_src */ false,
              {},
          },
      });

  EXPECT_TRUE(logger.GetMessages().empty());
}

TEST_F(PermissionsPolicyParserParsingTest,
       FeaturePolicyHeaderPermissionsPolicyHeaderCoExistConflictEntry) {
  PolicyParserMessageBuffer logger;

  // When there is conflict take the value from permission policy,
  // non-conflicting entries will be merged.
  CheckParsedPolicy(
      PermissionsPolicyParser::ParseHeader(
          "geolocation 'none', fullscreen 'self'",
          "geolocation=self, payment=*", origin_a_.get(), logger, logger,
          nullptr /* context */),
      {
          {
              // With geolocation appearing in both headers,
              // the value should be taken from permissions policy
              // header, which is 'self' here.
              mojom::blink::PermissionsPolicyFeature::kGeolocation,
              /* self_if_matches */ ORIGIN_A,
              /* matches_all_origins */ false,
              /* matches_opaque_src */ false,
              {},
          },
          {
              mojom::blink::PermissionsPolicyFeature::kPayment,
              /* self_if_matches */ std::nullopt,
              /* matches_all_origins */ true,
              /* matches_opaque_src */ true,
              {},
          },
          {
              mojom::blink::PermissionsPolicyFeature::kFullscreen,
              /* self_if_matches */ ORIGIN_A,
              /* matches_all_origins */ false,
              /* matches_opaque_src */ false,
              {},
          },
      });
}

TEST_F(PermissionsPolicyParserParsingTest,
       OverlapDeclarationSingleWarningMessage) {
  PolicyParserMessageBuffer feature_policy_logger("");
  PolicyParserMessageBuffer permissions_policy_logger("");

  CheckParsedPolicy(
      PermissionsPolicyParser::ParseHeader(
          "geolocation 'self', fullscreen 'self'" /* feature_policy_header */
          ,
          "geolocation=*, fullscreen=*" /* permissions_policy_header */
          ,
          origin_a_.get(), feature_policy_logger, permissions_policy_logger,
          nullptr /* context */
          ),
      {
          {
              mojom::blink::PermissionsPolicyFeature::kGeolocation,
              /* self_if_matches */ std::nullopt,
              /* matches_all_origins */ true,
              /* matches_opaque_src */ true,
              {},
          },
          {
              mojom::blink::PermissionsPolicyFeature::kFullscreen,
              /* self_if_matches */ std::nullopt,
              /* matches_all_origins */ true,
              /* matches_opaque_src */ true,
              {},
          },
      });

  CheckConsoleMessage(feature_policy_logger.GetMessages(),
                      {
                          "Some features are specified in both Feature-Policy "
                          "and Permissions-Policy header: geolocation, "
                          "fullscreen. Values defined in "
                          "Permissions-Policy header will be used.",
                      });
  CheckConsoleMessage(permissions_policy_logger.GetMessages(), {});
}

TEST_F(PermissionsPolicyParserParsingTest,
       FeaturePolicyHeaderPermissionsPolicyHeaderCoExistSeparateLogger) {
  PolicyParserMessageBuffer feature_policy_logger("Feature Policy: ");
  PolicyParserMessageBuffer permissions_policy_logger("Permissions Policy: ");

  // 'geolocation' in permissions policy has a invalid allowlist item, which
  // results in an empty allowlist, which is equivalent to "()" in permissions
  // policy syntax.
  CheckParsedPolicy(
      PermissionsPolicyParser::ParseHeader(
          "worse-feature 'none', geolocation 'self'" /* feature_policy_header */
          ,
          "bad-feature=*, geolocation=\"data:///bad-origin\"" /* permissions_policy_header
                                                               */
          ,
          origin_a_.get(), feature_policy_logger, permissions_policy_logger,
          nullptr /* context */
          ),
      {
          {
              mojom::blink::PermissionsPolicyFeature::kGeolocation,
              /* self_if_matches */ std::nullopt,
              /* matches_all_origins */ false,
              /* matches_opaque_src */ false,
              {},
          },
      });

  CheckConsoleMessage(
      feature_policy_logger.GetMessages(),
      {
          "Feature Policy: Unrecognized feature: 'worse-feature'.",
          "Feature Policy: Some features are specified in both Feature-Policy "
          "and Permissions-Policy header: geolocation. Values defined in "
          "Permissions-Policy header will be used.",
      });
  CheckConsoleMessage(
      permissions_policy_logger.GetMessages(),
      {
          "Permissions Policy: Unrecognized feature: 'bad-feature'.",
          "Permissions Policy: Unrecognized origin: 'data:///bad-origin'.",
      });
}

TEST_F(PermissionsPolicyParserParsingTest, CommaSeparatorInAttribute) {
  PolicyParserMessageBuffer logger;

  CheckParsedPolicy(
      PermissionsPolicyParser::ParseAttribute(
          "geolocation 'none', fullscreen 'self'",
          /* self_origin */ origin_a_.get(),
          /* src_origin */ origin_a_.get(), logger, /* context */ nullptr),
      {
          {
              mojom::blink::PermissionsPolicyFeature::kGeolocation,
              /* self_if_matches */ ORIGIN_A,
              /* matches_all_origins */ false,
              /* matches_opaque_src */ false,
              {},
          },
      });

  EXPECT_EQ(logger.GetMessages().size(), 2u)
      << "Parser should report parsing error.";

  EXPECT_EQ(logger.GetMessages().front().content.Ascii(),
            "Unrecognized origin: ''none','.")
      << "\"'none',\" should be treated as an invalid allowlist item ";

  EXPECT_EQ(logger.GetMessages().back().content.Ascii(),
            "Unrecognized origin: 'fullscreen'.")
      << "\"fullscreen\" should be treated as an invalid allowlist item";
}

TEST_F(PermissionsPolicyParserTest, ParseValidHeaderPolicy) {
  for (const char* policy_string : kValidHeaderPolicies) {
    PolicyParserMessageBuffer logger;
    PermissionsPolicyParser::ParseFeaturePolicyForTest(
        policy_string, origin_a_.get(), nullptr, logger, test_feature_name_map);
    EXPECT_EQ(0UL, logger.GetMessages().size())
        << "Should parse " << policy_string;
  }
}

TEST_F(PermissionsPolicyParserTest, ParseInvalidHeaderPolicy) {
  for (const char* policy_string : kInvalidHeaderPolicies) {
    PolicyParserMessageBuffer logger;
    PermissionsPolicyParser::ParseFeaturePolicyForTest(
        policy_string, origin_a_.get(), nullptr, logger, test_feature_name_map);
    EXPECT_LT(0UL, logger.GetMessages().size())
        << "Should fail to parse " << policy_string;
  }
}

TEST_F(PermissionsPolicyParserTest, ParseTooLongPolicy) {
  PolicyParserMessageBuffer logger;
  auto policy_string = "geolocation http://" + std::string(1 << 17, 'a');
  PermissionsPolicyParser::ParseFeaturePolicyForTest(
      policy_string.c_str(), origin_a_.get(), origin_b_.get(), logger,
      test_feature_name_map);
  EXPECT_EQ(1UL, logger.GetMessages().size())
      << "Should fail to parse feature policy string with size "
      << policy_string.size();
  PermissionsPolicyParser::ParsePermissionsPolicyForTest(
      policy_string.c_str(), origin_a_.get(), origin_b_.get(), logger,
      test_feature_name_map);
  EXPECT_EQ(2UL, logger.GetMessages().size())
      << "Should fail to parse permissions policy string with size "
      << policy_string.size();
}

// Test histogram counting the use of permissions policies in header.
TEST_F(PermissionsPolicyParserTest, HeaderHistogram) {
  const char* histogram_name = "Blink.UseCounter.FeaturePolicy.Header";
  base::HistogramTester tester;
  PolicyParserMessageBuffer logger;

  PermissionsPolicyParser::ParseFeaturePolicyForTest(
      "payment; fullscreen", origin_a_.get(), nullptr, logger,
      test_feature_name_map);
  tester.ExpectTotalCount(histogram_name, 2);
  tester.ExpectBucketCount(
      histogram_name,
      static_cast<int>(blink::mojom::blink::PermissionsPolicyFeature::kPayment),
      1);
  tester.ExpectBucketCount(
      histogram_name,
      static_cast<int>(
          blink::mojom::blink::PermissionsPolicyFeature::kFullscreen),
      1);
}

// Test counting the use of each permissions policy only once per header.
TEST_F(PermissionsPolicyParserTest, HistogramMultiple) {
  const char* histogram_name = "Blink.UseCounter.FeaturePolicy.Header";
  base::HistogramTester tester;
  PolicyParserMessageBuffer logger;

  // If the same feature is listed multiple times, it should only be counted
  // once.
  PermissionsPolicyParser::ParseFeaturePolicyForTest(
      "geolocation 'self'; payment; geolocation *", origin_a_.get(), nullptr,
      logger, test_feature_name_map);
  PermissionsPolicyParser::ParseFeaturePolicyForTest(
      "fullscreen 'self', fullscreen *", origin_a_.get(), nullptr, logger,
      test_feature_name_map);
  tester.ExpectTotalCount(histogram_name, 3);
  tester.ExpectBucketCount(
      histogram_name,
      static_cast<int>(
          blink::mojom::blink::PermissionsPolicyFeature::kGeolocation),
      1);
  tester.ExpectBucketCount(
      histogram_name,
      static_cast<int>(
          blink::mojom::blink::PermissionsPolicyFeature::kFullscreen),
      1);
}

// Tests the use counter for comma separator in declarations.
TEST_F(PermissionsPolicyParserTest, CommaSeparatedUseCounter) {
  PolicyParserMessageBuffer logger;

  // Declarations without a semicolon should not trigger the use counter.
  {
    auto dummy = std::make_unique<DummyPageHolder>();
    ParseFeaturePolicyHeader("payment", origin_a_.get(), logger,
                             dummy->GetFrame().DomWindow());
    EXPECT_FALSE(dummy->GetDocument().IsUseCounted(
        WebFeature::kFeaturePolicyCommaSeparatedDeclarations));
  }

  // Validate that declarations which should trigger the use counter do.
  {
    auto dummy = std::make_unique<DummyPageHolder>();
    ParseFeaturePolicyHeader("payment, fullscreen", origin_a_.get(), logger,
                             dummy->GetFrame().DomWindow());
    EXPECT_TRUE(dummy->GetDocument().IsUseCounted(
        WebFeature::kFeaturePolicyCommaSeparatedDeclarations))
        << "'payment, fullscreen' should trigger the comma separated use "
           "counter.";
  }
}

// Tests the use counter for semicolon separator in declarations.
TEST_F(PermissionsPolicyParserTest, SemicolonSeparatedUseCounter) {
  PolicyParserMessageBuffer logger;

  // Declarations without a semicolon should not trigger the use counter.
  {
    auto dummy = std::make_unique<DummyPageHolder>();
    ParseFeaturePolicyHeader("payment", origin_a_.get(), logger,
                             dummy->GetFrame().DomWindow());
    EXPECT_FALSE(dummy->GetDocument().IsUseCounted(
        WebFeature::kFeaturePolicySemicolonSeparatedDeclarations));
  }

  // Validate that declarations which should trigger the use counter do.
  {
    auto dummy = std::make_unique<DummyPageHolder>();
    ParseFeaturePolicyHeader("payment; fullscreen", origin_a_.get(), logger,
                             dummy->GetFrame().DomWindow());
    EXPECT_TRUE(dummy->GetDocument().IsUseCounted(
        WebFeature::kFeaturePolicySemicolonSeparatedDeclarations))
        << "'payment; fullscreen' should trigger the semicolon separated use "
           "counter.";
  }
}

// Test policy mutation methods
class FeaturePolicyMutationTest : public testing::Test {
 protected:
  FeaturePolicyMutationTest() = default;

  ~FeaturePolicyMutationTest() override = default;

  url::Origin url_origin_a_ = url::Origin::Create(GURL(ORIGIN_A));
  url::Origin url_origin_b_ = url::Origin::Create(GURL(ORIGIN_B));
  url::Origin url_origin_c_ = url::Origin::Create(GURL(ORIGIN_C));

  // Returns true if the policy contains a declaration for the feature which
  // allows it in all origins.
  bool IsFeatureAllowedEverywhere(
      mojom::blink::PermissionsPolicyFeature feature,
      const ParsedPermissionsPolicy& policy) {
    const auto& result = base::ranges::find(
        policy, feature, &ParsedPermissionsPolicyDeclaration::feature);
    if (result == policy.end())
      return false;

    return result->feature == feature && result->matches_all_origins &&
           result->matches_opaque_src && result->allowed_origins.empty();
  }

  // Returns true if the policy contains a declaration for the feature which
  // disallows it in all origins.
  bool IsFeatureDisallowedEverywhere(
      mojom::blink::PermissionsPolicyFeature feature,
      const ParsedPermissionsPolicy& policy) {
    const auto& result = base::ranges::find(
        policy, feature, &ParsedPermissionsPolicyDeclaration::feature);
    if (result == policy.end())
      return false;

    return result->feature == feature && !result->matches_all_origins &&
           !result->matches_opaque_src && result->allowed_origins.empty();
  }

  ParsedPermissionsPolicy test_policy = {
      {mojom::blink::PermissionsPolicyFeature::kFullscreen,
       /*allowed_origins=*/
       {*blink::OriginWithPossibleWildcards::FromOrigin(url_origin_a_),
        *blink::OriginWithPossibleWildcards::FromOrigin(url_origin_b_)},
       /*self_if_matches=*/std::nullopt,
       /*matches_all_origins=*/false,
       /*matches_opaque_src=*/false},
      {mojom::blink::PermissionsPolicyFeature::kGeolocation,
       /*=allowed_origins*/
       {*blink::OriginWithPossibleWildcards::FromOrigin(url_origin_a_)},
       /*self_if_matches=*/std::nullopt,
       /*matches_all_origins=*/false,
       /*matches_opaque_src=*/false}};

  ParsedPermissionsPolicy empty_policy = {};
  test::TaskEnvironment task_environment_;
};

TEST_F(FeaturePolicyMutationTest, TestIsFeatureDeclared) {
  EXPECT_TRUE(IsFeatureDeclared(
      mojom::blink::PermissionsPolicyFeature::kFullscreen, test_policy));
  EXPECT_TRUE(IsFeatureDeclared(
      mojom::blink::PermissionsPolicyFeature::kGeolocation, test_policy));
  EXPECT_FALSE(IsFeatureDeclared(mojom::blink::PermissionsPolicyFeature::kUsb,
                                 test_policy));
  EXPECT_FALSE(IsFeatureDeclared(
      mojom::blink::PermissionsPolicyFeature::kNotFound, test_policy));
}

TEST_F(FeaturePolicyMutationTest, TestIsFeatureDeclaredWithEmptyPolicy) {
  EXPECT_FALSE(IsFeatureDeclared(
      mojom::blink::PermissionsPolicyFeature::kFullscreen, empty_policy));
  EXPECT_FALSE(IsFeatureDeclared(
      mojom::blink::PermissionsPolicyFeature::kNotFound, empty_policy));
}

TEST_F(FeaturePolicyMutationTest, TestRemoveAbsentFeature) {
  ASSERT_EQ(2UL, test_policy.size());
  EXPECT_FALSE(IsFeatureDeclared(
      mojom::blink::PermissionsPolicyFeature::kPayment, test_policy));
  EXPECT_FALSE(RemoveFeatureIfPresent(
      mojom::blink::PermissionsPolicyFeature::kPayment, test_policy));
  ASSERT_EQ(2UL, test_policy.size());
  EXPECT_FALSE(IsFeatureDeclared(
      mojom::blink::PermissionsPolicyFeature::kPayment, test_policy));
}

TEST_F(FeaturePolicyMutationTest, TestRemoveFromEmptyPolicy) {
  ASSERT_EQ(0UL, empty_policy.size());
  EXPECT_FALSE(RemoveFeatureIfPresent(
      mojom::blink::PermissionsPolicyFeature::kPayment, test_policy));
  ASSERT_EQ(0UL, empty_policy.size());
}

TEST_F(FeaturePolicyMutationTest, TestRemoveFeatureIfPresent) {
  ASSERT_EQ(2UL, test_policy.size());
  EXPECT_TRUE(IsFeatureDeclared(
      mojom::blink::PermissionsPolicyFeature::kFullscreen, test_policy));
  EXPECT_TRUE(RemoveFeatureIfPresent(
      mojom::blink::PermissionsPolicyFeature::kFullscreen, test_policy));
  EXPECT_EQ(1UL, test_policy.size());
  EXPECT_FALSE(IsFeatureDeclared(
      mojom::blink::PermissionsPolicyFeature::kFullscreen, test_policy));

  // Attempt to remove the feature again
  EXPECT_FALSE(RemoveFeatureIfPresent(
      mojom::blink::PermissionsPolicyFeature::kFullscreen, test_policy));
  EXPECT_EQ(1UL, test_policy.size());
  EXPECT_FALSE(IsFeatureDeclared(
      mojom::blink::PermissionsPolicyFeature::kFullscreen, test_policy));
}

TEST_F(FeaturePolicyMutationTest, TestRemoveFeatureIfPresentOnSecondFeature) {
  ASSERT_EQ(2UL, test_policy.size());
  EXPECT_TRUE(IsFeatureDeclared(
      mojom::blink::PermissionsPolicyFeature::kGeolocation, test_policy));
  EXPECT_TRUE(RemoveFeatureIfPresent(
      mojom::blink::PermissionsPolicyFeature::kGeolocation, test_policy));
  ASSERT_EQ(1UL, test_policy.size());
  EXPECT_FALSE(IsFeatureDeclared(
      mojom::blink::PermissionsPolicyFeature::kGeolocation, test_policy));

  // Attempt to remove the feature again
  EXPECT_FALSE(RemoveFeatureIfPresent(
      mojom::blink::PermissionsPolicyFeature::kGeolocation, test_policy));
  EXPECT_EQ(1UL, test_policy.size());
  EXPECT_FALSE(IsFeatureDeclared(
      mojom::blink::PermissionsPolicyFeature::kGeolocation, test_policy));
}

TEST_F(FeaturePolicyMutationTest, TestRemoveAllFeatures) {
  ASSERT_EQ(2UL, test_policy.size());
  EXPECT_TRUE(RemoveFeatureIfPresent(
      mojom::blink::PermissionsPolicyFeature::kFullscreen, test_policy));
  EXPECT_TRUE(RemoveFeatureIfPresent(
      mojom::blink::PermissionsPolicyFeature::kGeolocation, test_policy));
  EXPECT_EQ(0UL, test_policy.size());
  EXPECT_FALSE(IsFeatureDeclared(
      mojom::blink::PermissionsPolicyFeature::kFullscreen, test_policy));
  EXPECT_FALSE(IsFeatureDeclared(
      mojom::blink::PermissionsPolicyFeature::kGeolocation, test_policy));
}

TEST_F(FeaturePolicyMutationTest, TestDisallowIfNotPresent) {
  ParsedPermissionsPolicy copy = test_policy;
  // Try to disallow a feature which already exists
  EXPECT_FALSE(DisallowFeatureIfNotPresent(
      mojom::blink::PermissionsPolicyFeature::kFullscreen, copy));
  ASSERT_EQ(copy, test_policy);

  // Disallow a new feature
  EXPECT_TRUE(DisallowFeatureIfNotPresent(
      mojom::blink::PermissionsPolicyFeature::kPayment, copy));
  EXPECT_EQ(3UL, copy.size());
  // Verify that the feature is, in fact, now disallowed everywhere
  EXPECT_TRUE(IsFeatureDisallowedEverywhere(
      mojom::blink::PermissionsPolicyFeature::kPayment, copy));
}

TEST_F(FeaturePolicyMutationTest, TestAllowEverywhereIfNotPresent) {
  ParsedPermissionsPolicy copy = test_policy;
  // Try to allow a feature which already exists
  EXPECT_FALSE(AllowFeatureEverywhereIfNotPresent(
      mojom::blink::PermissionsPolicyFeature::kFullscreen, copy));
  ASSERT_EQ(copy, test_policy);

  // Allow a new feature
  EXPECT_TRUE(AllowFeatureEverywhereIfNotPresent(
      mojom::blink::PermissionsPolicyFeature::kPayment, copy));
  EXPECT_EQ(3UL, copy.size());
  // Verify that the feature is, in fact, allowed everywhere
  EXPECT_TRUE(IsFeatureAllowedEverywhere(
      mojom::blink::PermissionsPolicyFeature::kPayment, copy));
}

TEST_F(FeaturePolicyMutationTest, TestDisallowUnconditionally) {
  // Try to disallow a feature which already exists
  DisallowFeature(mojom::blink::PermissionsPolicyFeature::kFullscreen,
                  test_policy);
  // Should not have changed the number of declarations
  EXPECT_EQ(2UL, test_policy.size());
  // Verify that the feature is, in fact, now disallowed everywhere
  EXPECT_TRUE(IsFeatureDisallowedEverywhere(
      mojom::blink::PermissionsPolicyFeature::kFullscreen, test_policy));
}

TEST_F(FeaturePolicyMutationTest, TestDisallowNewFeatureUnconditionally) {
  // Try to disallow a feature which does not yet exist
  DisallowFeature(mojom::blink::PermissionsPolicyFeature::kPayment,
                  test_policy);
  // Should have added a new declaration
  EXPECT_EQ(3UL, test_policy.size());
  // Verify that the feature is, in fact, now disallowed everywhere
  EXPECT_TRUE(IsFeatureDisallowedEverywhere(
      mojom::blink::PermissionsPolicyFeature::kPayment, test_policy));
}

TEST_F(FeaturePolicyMutationTest, TestAllowUnconditionally) {
  // Try to allow a feature which already exists
  AllowFeatureEverywhere(mojom::blink::PermissionsPolicyFeature::kFullscreen,
                         test_policy);
  // Should not have changed the number of declarations
  EXPECT_EQ(2UL, test_policy.size());
  // Verify that the feature is, in fact, now allowed everywhere
  EXPECT_TRUE(IsFeatureAllowedEverywhere(
      mojom::blink::PermissionsPolicyFeature::kFullscreen, test_policy));
}

TEST_F(FeaturePolicyMutationTest, TestAllowNewFeatureUnconditionally) {
  // Try to allow a feature which does not yet exist
  AllowFeatureEverywhere(mojom::blink::PermissionsPolicyFeature::kPayment,
                         test_policy);
  // Should have added a new declaration
  EXPECT_EQ(3UL, test_policy.size());
  // Verify that the feature is, in fact, now allowed everywhere
  EXPECT_TRUE(IsFeatureAllowedEverywhere(
      mojom::blink::PermissionsPolicyFeature::kPayment, test_policy));
}

class FeaturePolicyVisibilityTest
    : public testing::Test,
      public testing::WithParamInterface</*is_isolated=*/bool> {
 public:
  FeaturePolicyVisibilityTest() : is_isolated_(GetParam()) {}

  bool GetIsIsolated() { return is_isolated_; }

 private:
  test::TaskEnvironment task_environment_;
  bool is_isolated_{false};
};

INSTANTIATE_TEST_SUITE_P(All, FeaturePolicyVisibilityTest, testing::Bool());

TEST_P(FeaturePolicyVisibilityTest, VerifyIsolated) {
  EXPECT_TRUE(RuntimeEnabledFeatures::ControlledFrameEnabled());
  EXPECT_TRUE(RuntimeEnabledFeatures::DirectSocketsEnabled());

  auto dummy_page_holder = std::make_unique<DummyPageHolder>();
  ExecutionContext* execution_context =
      dummy_page_holder->GetFrame().DomWindow();

  Agent::ResetIsIsolatedContextForTest();
  Agent::SetIsIsolatedContext(GetIsIsolated());
  bool is_isolated_context = execution_context->IsIsolatedContext();
  EXPECT_EQ(is_isolated_context, GetIsIsolated());

  const String kControlledFrameFeature = "controlled-frame";
  EXPECT_EQ(GetDefaultFeatureNameMap(is_isolated_context)
                .Contains(kControlledFrameFeature),
            GetIsIsolated());

  const String kDirectSocketsFeature = "direct-sockets";
  EXPECT_EQ(GetDefaultFeatureNameMap(is_isolated_context)
                .Contains(kDirectSocketsFeature),
            GetIsIsolated());
}

}  // namespace blink
```
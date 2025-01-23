Response:
The user wants a summary of the provided C++ code, specifically the `permissions_policy_test.cc` file within the Chromium Blink engine.

Here's a breakdown of the thinking process to generate the answer:

1. **Identify the core functionality:** The filename `permissions_policy_test.cc` strongly suggests this file contains tests for the Permissions Policy feature in Blink.

2. **Scan the includes:** The included headers provide valuable clues:
    * `testing/gtest/include/gtest/gtest.h`: Indicates this is a unit test file using the Google Test framework.
    * `third_party/blink/public/common/features.h`: Suggests interaction with Blink's feature system.
    * `third_party/blink/public/common/permissions_policy/origin_with_possible_wildcards.h` and `third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h`:  Point directly to the Permissions Policy data structures and interface definitions.
    * `third_party/blink/renderer/core/...`: Includes from the `renderer/core` directory reveal that this test interacts with the core rendering engine components related to Permissions Policy. Key headers are:
        * `execution_context/agent.h`
        * `frame/local_dom_window.h`
        * `frame/local_frame.h`
        * `frame/settings.h`
        * `loader/empty_clients.h`
        * `permissions_policy/permissions_policy_parser.h`
        * `permissions_policy/policy_helper.h`
    * `third_party/blink/renderer/core/testing/page_test_base.h`:  Implies the tests might involve creating and manipulating test pages.
    * `url/gurl.h` and `url/origin.h`: Indicate the use of URL and origin concepts, which are central to Permissions Policy.

3. **Analyze the defined constants and classes:**
    * `ORIGIN_A`, `ORIGIN_B`, `ORIGIN_C`, `OPAQUE_ORIGIN`: These define test origins, suggesting the tests will involve different origin scenarios.
    * `kValidHeaderPolicies`, `kInvalidHeaderPolicies`: These arrays contain strings representing valid and invalid Permissions Policy headers, clearly indicating testing of header parsing.
    * `PermissionsPolicyParserTest`:  This class, inheriting from `::testing::Test`, sets up the test fixture. It initializes test origins and provides a helper function `ParseFeaturePolicyHeader` to parse policy strings.
    * `OriginWithPossibleWildcardsForTest`, `ParsedPolicyDeclarationForTest`, `ParsedPolicyForTest`: These structs define the expected structure of parsed Permissions Policy data for test assertions.
    * `PermissionsPolicyParserTestCase`:  This struct encapsulates all the information for a single parsing test case (input strings, expected output).
    * `PermissionsPolicyParserParsingTest`: This class, using `::testing::WithParamInterface`, implements parameterized tests for parsing. It includes helper functions `ParseFeaturePolicy`, `ParsePermissionsPolicy`, `CheckParsedPolicy`, and `CheckConsoleMessage` for parsing and assertion.

4. **Identify the test categories:** The code includes tests for:
    * Parsing valid and invalid Permissions Policy header strings.
    * Parsing Permissions Policy strings from various sources (headers, potentially iframe attributes - although not explicitly shown in this snippet, the context suggests it).
    * Handling different types of directives (e.g., `geolocation`, `fullscreen`).
    * Testing different values for directives ('self', '*', specific origins).
    * Testing the handling of subdomains and wildcards.
    * Testing with opaque origins.
    * Testing reporting endpoints.
    * Checking for correct parsing and error handling.

5. **Determine the relationship with web technologies:** Permissions Policy directly controls the access of web APIs (like geolocation, fullscreen, payment) by web pages. Therefore, these tests are fundamentally linked to:
    * **JavaScript:**  JavaScript code running in a browser context will be affected by the Permissions Policy. If a policy disallows a feature, JavaScript attempts to use that feature will fail.
    * **HTML:** The Permissions Policy can be set via HTTP headers or the `allow` attribute on `<iframe>` elements. The tests likely simulate the parsing of policies from these sources.
    * **CSS:** While CSS itself doesn't directly interact with Permissions Policy, the policy might affect the behavior of certain CSS features indirectly (e.g., a fullscreen API being blocked could impact a CSS-based fullscreen implementation).

6. **Infer logical reasoning and test scenarios:** The tests involve:
    * **Input:** A Permissions Policy string (header or attribute).
    * **Parsing Logic:** The `PermissionsPolicyParser` class processes the input string.
    * **Output:** A structured representation of the parsed policy (`ParsedPermissionsPolicy`).
    * **Assertions:** The tests compare the actual parsed output with the expected output.

7. **Identify potential user/programming errors:**  The tests implicitly highlight common errors:
    * **Incorrect syntax in the policy string:**  The `kInvalidHeaderPolicies` array demonstrates this.
    * **Using invalid feature names.**
    * **Incorrectly specifying origins.**
    * **Misunderstanding the meaning of keywords like 'self' and '*'.**

8. **Trace user actions leading to the code:**  While this specific test file isn't directly triggered by user actions, it *tests* the code that *is* triggered by user actions. A user's browsing actions that lead to the loading of a web page with a Permissions Policy will eventually invoke the parsing logic tested here. The steps would be:
    1. User navigates to a URL.
    2. The server sends an HTTP response with a `Permissions-Policy` header (or equivalent).
    3. The browser's rendering engine (Blink) receives the response.
    4. The `PermissionsPolicyParser` (tested by this file) parses the header.
    5. The parsed policy is then used to control feature access for the page.

9. **Summarize the functionality for Part 1:** Based on the above analysis, the first part of the file focuses on setting up the test environment and defining the structure for parsing tests. It includes:
    * Defining test origins and policy strings.
    * Setting up the test fixture (`PermissionsPolicyParserTest`).
    * Defining data structures to represent parsed policy information and test cases.
    * Implementing the base class for parsing tests (`PermissionsPolicyParserParsingTest`) with helper functions for parsing and checking results.

By following these steps, we can systematically analyze the code and generate a comprehensive explanation of its functionality.
这是名为 `permissions_policy_test.cc` 的 C++ 源代码文件，属于 Chromium Blink 引擎。它的主要功能是 **测试 Blink 引擎中权限策略 (Permissions Policy) 的解析和处理逻辑**。

具体来说，这个文件的第一部分主要涵盖了以下功能：

1. **定义测试用例的基础结构和数据:**
    * **定义了用于测试的常量字符串:**  例如 `ORIGIN_A`, `ORIGIN_B`, `ORIGIN_C` 代表不同的源 (origin)，`OPAQUE_ORIGIN` 代表不透明源。这些常量用于构建各种测试场景。
    * **定义了有效的和无效的权限策略头字符串数组:** `kValidHeaderPolicies` 和 `kInvalidHeaderPolicies` 包含了用于测试策略解析器正确处理不同格式策略字符串的能力。
    * **定义了测试用的数据结构:**
        * `OriginWithPossibleWildcardsForTest`:  用于表示可能包含子域名通配符的源。
        * `ParsedPolicyDeclarationForTest`:  用于表示解析后的单个权限策略声明，包括特性名称、是否允许自身源、是否匹配所有源、是否匹配不透明源、允许的源列表以及报告端点。
        * `ParsedPolicyForTest`:  一个包含多个 `ParsedPolicyDeclarationForTest` 的向量，代表一个完整的解析后的权限策略。
        * `PermissionsPolicyParserTestCase`:  用于组织单个测试用例的输入（策略字符串、自身源、来源源）和预期输出。
    * **定义了测试用的 FeatureNameMap:** `test_feature_name_map` 将特性名称字符串 (例如 "fullscreen", "geolocation") 映射到枚举类型 `mojom::blink::PermissionsPolicyFeature`。

2. **构建测试基础设施:**
    * **`PermissionsPolicyParserTest` 类:**  作为所有权限策略解析测试的基类，提供了测试所需的公共资源，例如预定义的源对象 (`origin_a_`, `origin_b_`, `origin_c_`) 和一个用于解析策略头字符串的辅助函数 `ParseFeaturePolicyHeader`。
    * **`PermissionsPolicyParserParsingTest` 类:**  继承自 `PermissionsPolicyParserTest`，并使用了 Google Test 的参数化测试特性 (`::testing::WithParamInterface`)，允许使用 `kCases` 数组中定义的多个测试用例进行测试。它包含了用于解析不同格式策略字符串 (Feature Policy 和 Permissions Policy) 的函数 `ParseFeaturePolicy` 和 `ParsePermissionsPolicy`，以及用于比较实际解析结果和预期结果的函数 `CheckParsedPolicy` 和 `CheckConsoleMessage`。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件直接测试的是 Permissions Policy 的解析逻辑，而 Permissions Policy 本身是 Web 平台的一项安全特性，用于控制 Web 页面对特定浏览器特性的访问。它与 JavaScript, HTML, CSS 的关系如下：

* **JavaScript:** Permissions Policy 限制了 JavaScript 代码可以调用的 Web API。例如，如果一个页面的 Permissions Policy 禁止了 `geolocation` 特性，那么页面中的 JavaScript 代码调用 `navigator.geolocation` 相关 API 将会失败。
    * **举例:** 假设一个页面的 Permissions Policy 设置为 `geolocation 'none'`, 那么页面上的 JavaScript 代码 `navigator.geolocation.getCurrentPosition(...)` 将会抛出一个错误。

* **HTML:**  Permissions Policy 可以通过 HTTP 头部 (`Permissions-Policy`) 或者 `<iframe>` 标签的 `allow` 属性来设置。这个测试文件会模拟解析这些策略来源。
    * **举例:**
        * **HTTP 头部:** 服务器返回的 HTTP 响应头中包含 `Permissions-Policy: geolocation 'self'`，这个测试文件会测试解析器能否正确解析这个头部。
        * **`<iframe>` 标签:**  HTML 中嵌入一个 `<iframe>`，其 `allow` 属性设置为 `geolocation 'src'`: `<iframe src="..." allow="geolocation 'src'"></iframe>`。虽然这个代码片段侧重于头部解析，但相关的解析逻辑也会被测试覆盖。

* **CSS:**  Permissions Policy 本身不直接影响 CSS 的功能，但它控制的特性可能会间接影响 CSS 的某些行为。例如，如果 Permissions Policy 禁止了全屏 API，那么依赖于 JavaScript 调用全屏 API 的 CSS 全屏效果可能无法正常工作。

**逻辑推理 (假设输入与输出):**

* **假设输入 (用于 `ParseFeaturePolicyHeader`):**
    * `feature_policy_header`: `"geolocation 'self'; fullscreen *"`
    * `origin`:  `https://example.com/`
    * `logger`: 一个用于记录解析错误的 `PolicyParserMessageBuffer` 对象。
* **预期输出:**  一个 `ParsedPermissionsPolicy` 对象，包含两个 `ParsedPolicyDeclarationForTest`：
    * 第一个声明：`feature` 为 `kGeolocation`，`self_if_matches` 为 `https://example.com/`，其他字段根据策略设置。
    * 第二个声明：`feature` 为 `kFullscreen`，`matches_all_origins` 为 `true`，其他字段根据策略设置。

**用户或编程常见的使用错误举例:**

* **错误的策略语法:**  例如在策略头中使用未定义的特性名称，或者使用了错误的关键词。`kInvalidHeaderPolicies` 中列举了一些这样的错误。
    * **举例:**  用户可能会错误地写成 `"badfeaturename 'self'"`，解析器应该能够识别并报告这个错误。
* **混淆 'self' 和 '*' 的含义:**  开发者可能不清楚 `'self'` 只允许同源访问，而 `'*'` 允许所有来源访问。
* **在不应该使用的地方使用通配符:**  例如在主机名中使用 `*`，但没有按照规定的格式。
* **忘记在不同的策略指令之间使用分号 `;` 分隔。**

**用户操作如何一步步到达这里 (调试线索):**

虽然用户不会直接“到达”这个测试文件，但用户的操作会触发浏览器执行与权限策略相关的代码，而这个测试文件就是用来验证这些代码是否正确运行的。步骤如下：

1. **用户在浏览器地址栏输入一个 URL 并访问一个网页。**
2. **服务器响应请求，返回包含 HTML 内容以及 HTTP 头部的信息。**
3. **浏览器接收到响应头，其中可能包含 `Permissions-Policy` 头部。**
4. **Blink 引擎的渲染进程会解析这个 `Permissions-Policy` 头部。**  `PermissionsPolicyParser::ParseHeader` 函数 (在 `permissions_policy_parser.cc` 中定义，被此测试文件测试) 会被调用来执行解析。
5. **如果页面中包含 `<iframe>` 标签，浏览器还会解析 `<iframe>` 标签的 `allow` 属性。** 相关的解析逻辑也会被测试覆盖。
6. **解析后的权限策略会被存储起来，并在后续的页面生命周期中用于控制 JavaScript 代码对受限特性的访问。** 例如，当 JavaScript 代码尝试调用 `navigator.geolocation.getCurrentPosition()` 时，浏览器会检查当前页面的权限策略是否允许 `geolocation` 特性。

**归纳一下它的功能 (第1部分):**

这个 `permissions_policy_test.cc` 文件的第一部分主要功能是 **为 Blink 引擎的权限策略解析器建立一套全面的测试框架**。它定义了测试数据结构、测试用例的组织方式，以及用于解析和验证策略字符串的基础工具。这部分代码的核心目标是确保权限策略的解析逻辑能够正确处理各种有效的和无效的策略语法，为后续更具体的权限策略行为测试奠定基础。

### 提示词
```
这是目录为blink/renderer/core/permissions_policy/permissions_policy_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <map>
#include <string>

#include "base/ranges/algorithm.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/permissions_policy/origin_with_possible_wildcards.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/permissions_policy/permissions_policy_parser.h"
#include "third_party/blink/renderer/core/permissions_policy/policy_helper.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "url/gurl.h"
#include "url/origin.h"

// Origin strings used for tests
#define ORIGIN_A "https://example.com/"
#define ORIGIN_A_SUBDOMAIN_WILDCARD "https://*.example.com/"
#define ORIGIN_A_SUBDOMAIN_ESCAPED "https://%2A.example.com/"
#define ORIGIN_B "https://example.net/"
#define ORIGIN_C "https://example.org/"
#define OPAQUE_ORIGIN ""

// identifier used for feature/permissions policy parsing test.
// when there is a testcase for one syntax but not the other.
#define NOT_APPLICABLE nullptr

class GURL;

namespace blink {

namespace {

const char* const kValidHeaderPolicies[] = {
    "",      // An empty policy.
    " ",     // An empty policy.
    ";;",    // Empty policies.
    ",,",    // Empty policies.
    " ; ;",  // Empty policies.
    " , ,",  // Empty policies.
    ",;,",   // Empty policies.
    "geolocation 'none'",
    "geolocation 'self'",
    "geolocation",
    "geolocation; fullscreen; payment",
    "geolocation *",
    "geolocation " ORIGIN_A "",
    "geolocation " ORIGIN_B "",
    "geolocation  " ORIGIN_A " " ORIGIN_B "",
    "geolocation 'none' " ORIGIN_A " " ORIGIN_B "",
    "geolocation " ORIGIN_A " 'none' " ORIGIN_B "",
    "geolocation 'none' 'none' 'none'",
    "geolocation " ORIGIN_A " *",
    "fullscreen  " ORIGIN_A "; payment 'self'",
    "fullscreen " ORIGIN_A "; payment *, geolocation 'self'"};

const char* const kInvalidHeaderPolicies[] = {
    "badfeaturename",
    "badfeaturename 'self'",
    "1.0",
    "geolocation 'src'",  // Only valid for iframe allow attribute.
    "geolocation data:///badorigin",
    "geolocation https://bad;origin",
    "geolocation https:/bad,origin",
    "geolocation https://example.com, https://a.com",
    "geolocation *, payment data:///badorigin",
    "geolocation ws://xn--fd\xbcwsw3taaaaaBaa333aBBBBBBJBBJBBBt",
};
}  // namespace

class PermissionsPolicyParserTest : public ::testing::Test {
 protected:
  PermissionsPolicyParserTest() = default;

  ~PermissionsPolicyParserTest() override = default;

  scoped_refptr<const SecurityOrigin> origin_a_ =
      SecurityOrigin::CreateFromString(ORIGIN_A);
  scoped_refptr<const SecurityOrigin> origin_b_ =
      SecurityOrigin::CreateFromString(ORIGIN_B);
  scoped_refptr<const SecurityOrigin> origin_c_ =
      SecurityOrigin::CreateFromString(ORIGIN_C);

  url::Origin expected_url_origin_a_ = url::Origin::Create(GURL(ORIGIN_A));
  url::Origin expected_url_origin_b_ = url::Origin::Create(GURL(ORIGIN_B));
  url::Origin expected_url_origin_c_ = url::Origin::Create(GURL(ORIGIN_C));

  const FeatureNameMap test_feature_name_map = {
      {"fullscreen",
       blink::mojom::blink::PermissionsPolicyFeature::kFullscreen},
      {"payment", blink::mojom::blink::PermissionsPolicyFeature::kPayment},
      {"geolocation",
       blink::mojom::blink::PermissionsPolicyFeature::kGeolocation}};

  ParsedPermissionsPolicy ParseFeaturePolicyHeader(
      const String& feature_policy_header,
      scoped_refptr<const SecurityOrigin> origin,
      PolicyParserMessageBuffer& logger,
      ExecutionContext* context = nullptr) {
    return PermissionsPolicyParser::ParseHeader(
        feature_policy_header, g_empty_string, origin, logger, logger, context);
  }
  test::TaskEnvironment task_environment_;
};

struct OriginWithPossibleWildcardsForTest {
  const char* origin;
  bool has_subdomain_wildcard;
};

struct ParsedPolicyDeclarationForTest {
  mojom::blink::PermissionsPolicyFeature feature;
  std::optional<const char*> self_if_matches;
  bool matches_all_origins;
  bool matches_opaque_src;
  std::vector<OriginWithPossibleWildcardsForTest> allowed_origins;
  std::optional<std::string> reporting_endpoint;
};

using ParsedPolicyForTest = std::vector<ParsedPolicyDeclarationForTest>;

struct PermissionsPolicyParserTestCase {
  const char* test_name;

  // Test inputs.
  const char* feature_policy_string;
  const char* permissions_policy_string;
  const char* self_origin;
  const char* src_origin;

  // Test expectation.
  ParsedPolicyForTest expected_parse_result;
};

class PermissionsPolicyParserParsingTest
    : public PermissionsPolicyParserTest,
      public ::testing::WithParamInterface<PermissionsPolicyParserTestCase> {
 private:
  scoped_refptr<const SecurityOrigin> GetSrcOrigin(const char* origin_str) {
    scoped_refptr<const SecurityOrigin> src_origin;
    if (String(origin_str) == OPAQUE_ORIGIN) {
      src_origin = SecurityOrigin::CreateUniqueOpaque();
    } else {
      src_origin =
          origin_str ? SecurityOrigin::CreateFromString(origin_str) : nullptr;
    }
    return src_origin;
  }

 protected:
  ParsedPermissionsPolicy ParseFeaturePolicy(
      const char* policy_string,
      const char* self_origin_string,
      const char* src_origin_string,
      PolicyParserMessageBuffer& logger,
      const FeatureNameMap& feature_names,
      ExecutionContext* context = nullptr) {
    return PermissionsPolicyParser::ParseFeaturePolicyForTest(
        policy_string, SecurityOrigin::CreateFromString(self_origin_string),
        GetSrcOrigin(src_origin_string), logger, feature_names, context);
  }

  ParsedPermissionsPolicy ParsePermissionsPolicy(
      const char* policy_string,
      const char* self_origin_string,
      const char* src_origin_string,
      PolicyParserMessageBuffer& logger,
      const FeatureNameMap& feature_names,
      ExecutionContext* context = nullptr) {
    return PermissionsPolicyParser::ParsePermissionsPolicyForTest(
        policy_string, SecurityOrigin::CreateFromString(self_origin_string),
        GetSrcOrigin(src_origin_string), logger, feature_names, context);
  }

  void CheckParsedPolicy(const ParsedPermissionsPolicy& actual,
                         const ParsedPolicyForTest& expected) {
    ASSERT_EQ(actual.size(), expected.size());
    for (size_t i = 0; i < actual.size(); ++i) {
      const auto& actual_declaration = actual[i];
      const auto& expected_declaration = expected[i];

      EXPECT_EQ(actual_declaration.feature, expected_declaration.feature);
      if (expected_declaration.self_if_matches) {
        EXPECT_TRUE(actual_declaration.self_if_matches->IsSameOriginWith(
            url::Origin::Create(GURL(*expected_declaration.self_if_matches))));
      } else {
        EXPECT_FALSE(actual_declaration.self_if_matches);
      }
      EXPECT_EQ(actual_declaration.matches_all_origins,
                expected_declaration.matches_all_origins);
      EXPECT_EQ(actual_declaration.matches_opaque_src,
                expected_declaration.matches_opaque_src);
      EXPECT_EQ(actual_declaration.reporting_endpoint,
                expected_declaration.reporting_endpoint);

      ASSERT_EQ(actual_declaration.allowed_origins.size(),
                expected_declaration.allowed_origins.size());
      for (size_t j = 0; j < actual_declaration.allowed_origins.size(); ++j) {
        const url::Origin origin = url::Origin::Create(
            GURL(expected_declaration.allowed_origins[j].origin));
        EXPECT_EQ(
            actual_declaration.allowed_origins[j].CSPSourceForTest().scheme,
            origin.scheme());
        EXPECT_EQ(actual_declaration.allowed_origins[j].CSPSourceForTest().host,
                  origin.host());
        if (actual_declaration.allowed_origins[j].CSPSourceForTest().port !=
            url::PORT_UNSPECIFIED) {
          EXPECT_EQ(
              actual_declaration.allowed_origins[j].CSPSourceForTest().port,
              origin.port());
        }
        EXPECT_EQ(
            actual_declaration.allowed_origins[j]
                .CSPSourceForTest()
                .is_host_wildcard,
            expected_declaration.allowed_origins[j].has_subdomain_wildcard);
      }
    }
  }

  void CheckConsoleMessage(
      const Vector<PolicyParserMessageBuffer::Message>& actual,
      const std::vector<String> expected) {
    ASSERT_EQ(actual.size(), expected.size());
    for (wtf_size_t i = 0; i < actual.size(); ++i) {
      EXPECT_EQ(actual[i].content, expected[i]);
    }
  }

 public:
  static const PermissionsPolicyParserTestCase kCases[];
};

const PermissionsPolicyParserTestCase
    PermissionsPolicyParserParsingTest::kCases[] = {
        {
            /* test_name */ "EmptyPolicy",
            /* feature_policy_string */ "",
            /* permissions_policy_string */ "",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */ {},
        },
        {
            /* test_name */ "SimplePolicyWithSelf",
            /* feature_policy_string */ "geolocation 'self'",
            /* permissions_policy_string */ "geolocation=self",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kGeolocation,
                    /* self_if_matches */ ORIGIN_A,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {},
                },
            },
        },
        {
            /* test_name */ "SimplePolicyWithSelfExplicitListSyntax",
            /* feature_policy_string */ NOT_APPLICABLE,
            /* permissions_policy_string */ "geolocation=(self)",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kGeolocation,
                    /* self_if_matches */ ORIGIN_A,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {},
                },
            },
        },
        {
            /* test_name */ "SimplePolicyWithStar",
            /* feature_policy_string */ "geolocation *",
            /* permissions_policy_string */ "geolocation=*",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kGeolocation,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ true,
                    /* matches_opaque_src */ true,
                    {},
                },
            },
        },
        {
            /* test_name */ "ComplicatedPolicy",
            /* feature_policy_string */
            "geolocation *; "
            "fullscreen " ORIGIN_B " " ORIGIN_C "; "
            "payment 'self'",
            /* permissions_policy_string */
            "geolocation=*, "
            "fullscreen=(\"" ORIGIN_B "\" \"" ORIGIN_C "\"),"
            "payment=self",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
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
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {{ORIGIN_B, /*has_subdomain_wildcard=*/false},
                     {ORIGIN_C, /*has_subdomain_wildcard=*/false}},
                },
                {
                    mojom::blink::PermissionsPolicyFeature::kPayment,
                    /* self_if_matches */ ORIGIN_A,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {},
                },
            },
        },
        {
            /* test_name */ "MultiplePoliciesIncludingBadFeatureName",
            /* feature_policy_string */
            "geolocation * " ORIGIN_B "; "
            "fullscreen " ORIGIN_B " bad_feature_name " ORIGIN_C ";"
            "payment 'self' badorigin",
            /* permissions_policy_string */
            "geolocation=(* \"" ORIGIN_B "\"),"
            "fullscreen=(\"" ORIGIN_B "\" bad_feature_name \"" ORIGIN_C "\"),"
            "payment=(self \"badorigin\")",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
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
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {{ORIGIN_B, /*has_subdomain_wildcard=*/false},
                     {ORIGIN_C, /*has_subdomain_wildcard=*/false}},
                },
                {
                    mojom::blink::PermissionsPolicyFeature::kPayment,
                    /* self_if_matches */ ORIGIN_A,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {},
                },
            },
        },
        {
            /* test_name */ "HeaderPoliciesWithNoOptionalOriginLists",
            /* feature_policy_string */ "geolocation;fullscreen;payment",
            // Note: In structured header, if no value is associated with a key
            // in dictionary, default value would be boolean true, which is
            // not allowed as allowlist value in permission policy syntax.
            /* permissions_policy_string */
            "geolocation=self,fullscreen=self,payment=self",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ nullptr,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kGeolocation,
                    /* self_if_matches */ ORIGIN_A,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {},
                },
                {
                    mojom::blink::PermissionsPolicyFeature::kFullscreen,
                    /* self_if_matches */ ORIGIN_A,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {},
                },
                {
                    mojom::blink::PermissionsPolicyFeature::kPayment,
                    /* self_if_matches */ ORIGIN_A,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {},
                },
            },
        },
        {
            /* test_name */ "EmptyPolicyOpaqueSrcOrigin",
            /* feature_policy_string */ "",
            /* permissions_policy_string */ "",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ OPAQUE_ORIGIN,
            /* expected_parse_result */ {},
        },
        {
            /* test_name */ "SimplePolicyOpaqueSrcOrigin",
            /* feature_policy_string */ "geolocation",
            /* permissions_policy_string */ NOT_APPLICABLE,
            /* self_origin */ ORIGIN_A,
            /* src_origin */ OPAQUE_ORIGIN,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kGeolocation,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ true,
                    {},
                },
            },
        },
        {
            /* test_name */ "SimplePolicyWithSrcOpaqueSrcOrigin",
            /* feature_policy_string */ "geolocation 'src'",
            /* permissions_policy_string */ NOT_APPLICABLE,
            /* self_origin */ ORIGIN_A,
            /* src_origin */ OPAQUE_ORIGIN,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kGeolocation,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ true,
                    {},
                },
            },
        },
        {
            /* test_name */ "SimplePolicyWithStarOpaqueSrcOrigin",
            /* feature_policy_string */ "geolocation *",
            /* permissions_policy_string */ "geolocation=*",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ OPAQUE_ORIGIN,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kGeolocation,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ true,
                    /* matches_opaque_src */ true,
                    {},
                },
            },
        },
        {
            /* test_name */ "PolicyWithExplicitOriginsOpaqueSrcOrigin",
            /* feature_policy_string */ "geolocation " ORIGIN_B " " ORIGIN_C,
            /* permissions_policy_string */
            "geolocation=(\"" ORIGIN_B "\" \"" ORIGIN_C "\")",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ OPAQUE_ORIGIN,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kGeolocation,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {{ORIGIN_B, /*has_subdomain_wildcard=*/false},
                     {ORIGIN_C, /*has_subdomain_wildcard=*/false}},
                },
            },
        },
        {
            /* test_name */ "PolicyWithMultipleOriginsIncludingSrc"
                            "OpaqueSrcOrigin",
            /* feature_policy_string */ "geolocation " ORIGIN_B " 'src'",
            /* permissions_policy_string */ NOT_APPLICABLE,
            /* self_origin */ ORIGIN_A,
            /* src_origin */ OPAQUE_ORIGIN,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kGeolocation,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ true,
                    {{ORIGIN_B, /*has_subdomain_wildcard=*/false}},
                },
            },
        },
        {
            /* test_name */ "PolicyWithInvalidDataTypeInt",
            /* feature_policy_string */ NOT_APPLICABLE,
            // int value should be rejected as allowlist items.
            /* permissions_policy_string */ "geolocation=9",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ nullptr,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kGeolocation,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {},
                },
            },
        },
        {
            /* test_name */ "PolicyWithInvalidDataTypeFloat",
            /* feature_policy_string */ NOT_APPLICABLE,
            // decimal value should be rejected as allowlist items.
            /* permissions_policy_string */ "geolocation=1.1",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ nullptr,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kGeolocation,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {},
                },
            },
        },
        {
            /* test_name */ "PolicyWithInvalidDataTypeBoolean",
            /* feature_policy_string */ NOT_APPLICABLE,
            // boolean value should be rejected as allowlist items.
            /* permissions_policy_string */ "geolocation=?0",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ nullptr,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kGeolocation,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {},
                },
            },
        },
        {
            /* test_name */ "PolicyWithEmptyOriginString",
            /* feature_policy_string */ NOT_APPLICABLE,
            /* permissions_policy_string */ "geolocation=\"\"",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ nullptr,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kGeolocation,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {},
                },
            },
        },
        {
            /* test_name */ "ProperWildcardIncludedForFeaturePolicy",
            /* feature_policy_string */
            "fullscreen " ORIGIN_A_SUBDOMAIN_WILDCARD,
            /* permissions_policy_string */ NOT_APPLICABLE,
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kFullscreen,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {},
                },
            },
        },
        {
            /* test_name */ "ProperWildcardIncludedForPermissionsPolicy",
            /* feature_policy_string */ NOT_APPLICABLE,
            /* permissions_policy_string */
            "fullscreen=(\"" ORIGIN_A_SUBDOMAIN_WILDCARD "\")",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kFullscreen,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {{ORIGIN_A,
                      /*has_subdomain_wildcard=*/true}},
                },
            },
        },
        {
            /* test_name */ "ImproperWildcardsIncluded",
            /* feature_policy_string */
            "fullscreen *://example.com https://foo.*.example.com "
            "https://*.*.example.com",
            /* permissions_policy_string */
            "fullscreen=(\"*://example.com\" \"https://foo.*.example.com\" "
            "\"https://*.*.example.com\")",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kFullscreen,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {},
                },
            },
        },
        {
            /* test_name */ "AttributeWithLineBreaks",
            /* feature_policy_string */
            "geolocation;\n"
            "fullscreen",
            /* permissions_policy_string */ NOT_APPLICABLE,
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kGeolocation,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {{ORIGIN_B, /*has_subdomain_wildcard=*/false}},
                },
                {
                    mojom::blink::PermissionsPolicyFeature::kFullscreen,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {{ORIGIN_B, /*has_subdomain_wildcard=*/false}},
                },
            },
        },
        {
            /* test_name */ "AttributeWithCRLF",
            /* feature_policy_string */
            "geolocation;\r\n"
            "fullscreen",
            /* permissions_policy_string */ NOT_APPLICABLE,
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kGeolocation,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {{ORIGIN_B, /*has_subdomain_wildcard=*/false}},
                },
                {
                    mojom::blink::PermissionsPolicyFeature::kFullscreen,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {{ORIGIN_B, /*has_subdomain_wildcard=*/false}},
                },
            },
        },
        {
            /* test_name */ "AlternativeWhitespceBetweenTokens",
            /* feature_policy_string */
            "\r\n\r\ngeolocation\t 'self'\f\f" ORIGIN_B "\t",
            /* permissions_policy_string */ NOT_APPLICABLE,
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kGeolocation,
                    /* self_if_matches */ ORIGIN_A,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {{ORIGIN_B, /*has_subdomain_wildcard=*/false}},
                },
            },
        },
        {
            /* test_name */ "ReportingEndpointWithStar",
            /* feature_policy_string */ NOT_APPLICABLE,
            /* permissions_policy_string */
            "fullscreen=*;report-to=endpoint",
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
                    "endpoint",
                },
            },
        },
        {
            /* test_name */ "ReportingEndpointWithList",
            /* feature_policy_string */ NOT_APPLICABLE,
            /* permissions_policy_string */
            "fullscreen=(\"" ORIGIN_B "\" \"" ORIGIN_C "\");report-to=endpoint",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kFullscreen,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {{ORIGIN_B, /*has_subdomain_wildcard=*/false},
                     {ORIGIN_C, /*has_subdomain_wildcard=*/false}},
                    "endpoint",
                },
            },
        },
        {
            /* test_name */ "ReportingEndpointWithNone",
            /* feature_policy_string */ NOT_APPLICABLE,
            /* permissions_policy_string */
            "fullscreen=();report-to=endpoint",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kFullscreen,
                    /* self_if_matches */ std::nullopt,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {},
                    "endpoint",
                },
            },
        },
        {
            /* test_name */ "ReportingEndpointWithSelf",
            /* feature_policy_string */ NOT_APPLICABLE,
            /* permissions_policy_string */
            "fullscreen=self;report-to=endpoint",
            /* self_origin */ ORIGIN_A,
            /* src_origin */ ORIGIN_B,
            /* expected_parse_result */
            {
                {
                    mojom::blink::PermissionsPolicyFeature::kFullscreen,
                    /* self_if_matches */ ORIGIN_A,
                    /* matches_all_origins */ false,
                    /* matches_opaque_src */ false,
                    {},
                    "endpoint",
                },
            },
        },
        {
            /* test_name */ "ReportingEndpointWithSingleOrigin",
            /* feature_policy_string */ NOT_APPLICABLE,
            /* permissions_policy_string */
            "fullscreen=\"" ORIGIN_C "\";report-to=endpoint",
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
                    "endpoint",
                },
            },
        },
        {
            /* test_name */ "InvalidReportingEndpointInList",
            /* feature_policy_string */ NOT_APPLICABLE,
            // Note: The reporting endpoint parameter needs to apply to the
            // entire value for the dictionary entry. In this example, it is
            // placed on a single inner list item, and should therefore be
            // ignored.
            /* permissions_policy_string */
            "fullscreen=(\"" ORIGIN_C "\";report-to=endpoint)",
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
                    /* reporting_endpoint */ std::nullopt,
                },
            },
        },
```
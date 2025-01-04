Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name `script_web_bundle_rule_test.cc` immediately tells us this is a test file. The `ScriptWebBundleRule` part suggests it's testing a class or functionality related to web bundles, specifically for scripts.

2. **Scan for Key Classes and Functions:**  Look for the main class being tested. Here, it's `ScriptWebBundleRule`. Then, identify the key functions being tested. A quick scan reveals `ParseJson`. This is the function under scrutiny.

3. **Understand the Testing Framework:** The `#include "testing/gmock/include/gmock.h"` and `#include "testing/gtest/include/gtest/gtest.h"` lines indicate the use of Google Test and Google Mock frameworks for writing tests. This tells us to expect test cases defined using `TEST()` macros and assertions using `ASSERT_TRUE`, `EXPECT_EQ`, `EXPECT_THAT`, etc.

4. **Analyze Individual Test Cases:** Go through each `TEST()` block. For each test:
    * **Name:** Understand the intent from the test name (e.g., `Empty`, `Basic`, `SourceOnly`, `CredentialsDefaultIsSameOrigin`, `MissingSource`, etc.).
    * **Setup:** Look at the input data being used for `ParseJson`. This is often a JSON string. Identify the `base_url`.
    * **Execution:**  See how `ParseJson` is called with the input.
    * **Assertions:** Analyze the `ASSERT_TRUE` and `EXPECT_*` statements. These are the checks verifying the correctness of the `ParseJson` function's behavior. Pay attention to:
        * **Success Cases:**  Tests where `ParseJson` is expected to succeed and return a `ScriptWebBundleRule`. What properties of the resulting rule are being checked (e.g., `source_url`, `scope_urls`, `resource_urls`, `credentials_mode`)?
        * **Error Cases:** Tests where `ParseJson` is expected to fail and return a `ScriptWebBundleError`. What type of error is expected (`kSyntaxError`, `kTypeError`) and what is the expected error message?
    * **Special Cases:** Note tests that examine default behavior (e.g., `CredentialsDefaultIsSameOrigin`), invalid input handling (e.g., `CredentialsInvalidValueIsSameOrigin`, `TopLevelIsNotAnObject`, `MissingSource`), and handling of relative URLs (`ResourcesShouldBeResolvedOnBundleURL`, `ScopesShouldBeResolvedOnBundleURL`).

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Think about how `ScriptWebBundleRule` and web bundles relate to these technologies.
    * **JavaScript:** The name itself suggests a connection. Web bundles can contain JavaScript files. The "scopes" likely define where the bundled JavaScript is allowed to execute.
    * **HTML:** Web bundles can contain HTML files. The resources section could include HTML files.
    * **CSS:** The test cases explicitly use `.css` files in the `resources` array, indicating that web bundles can include CSS. The `scopes` might also influence the application of CSS.

6. **Infer Functionality and Purpose:** Based on the test cases, deduce the following about `ScriptWebBundleRule::ParseJson`:
    * It parses a JSON string representing a web bundle rule.
    * It extracts information like the bundle's source URL, scopes, resources, and credentials mode.
    * It handles relative URLs for scopes and resources by resolving them against the bundle's URL.
    * It validates the JSON structure and types.
    * It handles invalid input gracefully, returning specific error types and messages.
    * It uses a `ConsoleLogger` for warnings about unknown keys.

7. **Consider User/Programming Errors:**  Think about how developers might misuse this functionality based on the error cases tested:
    * Providing invalid JSON.
    * Missing the `source` field.
    * Using incorrect data types for fields.
    * Providing unparsable URLs.
    * Using incorrect values for `credentials`.

8. **Hypothesize User Operations and Debugging:**  Imagine how a user might encounter issues related to web bundles and how this test file could be helpful in debugging:
    * A developer creates a web bundle and defines rules for it in a JSON file.
    * If the rules are malformed, the browser's web bundle loading mechanism will likely fail.
    * These tests simulate those error scenarios, helping developers understand what went wrong with their rule definition.
    * The error messages in the tests are similar to what a browser might report, providing clues.

9. **Structure the Explanation:** Organize the findings into clear sections: Functionality, Relationship to Web Technologies, Logical Reasoning, Common Errors, and Debugging Clues. Use examples from the code to illustrate each point.

10. **Refine and Review:** Read through the explanation, ensuring clarity, accuracy, and completeness. Check for any missing connections or misunderstandings. For instance, initially, I might focus too much on the syntax. Then, I'd realize that the *meaning* of "scopes" and "resources" within the context of web loading is also important.
这个 C++ 文件 `script_web_bundle_rule_test.cc` 是 Chromium Blink 引擎的一部分，专门用于测试 `ScriptWebBundleRule` 类的功能。`ScriptWebBundleRule` 的作用是解析和表示 Web Bundle 的规则，这些规则定义了如何加载和处理 Web Bundle 中的资源。

**功能总结:**

这个测试文件的主要功能是验证 `ScriptWebBundleRule::ParseJson` 方法的正确性。该方法负责将一个 JSON 字符串解析成 `ScriptWebBundleRule` 对象。测试涵盖了各种场景，包括：

* **成功解析合法的 JSON 规则:** 验证能够正确解析包含 `source`, `scopes`, `resources`, `credentials` 等字段的 JSON 字符串。
* **处理不同的 `credentials` 模式:** 测试 `same-origin`, `include`, `omit` 等不同的 `credentials` 取值是否被正确解析。
* **处理空 JSON 或格式错误的 JSON:** 验证对于无效的 JSON 输入，能够正确返回错误信息。
* **处理缺少必要字段的 JSON:** 测试缺少 `source` 字段的情况。
* **处理字段类型错误的 JSON:** 测试 `source`, `scopes`, `resources` 等字段类型不正确的情况。
* **处理无效的 URL:** 验证对于无法解析为 URL 的 `source` 字段，能够正确返回错误信息。
* **处理相对 URL:** 测试 `scopes` 和 `resources` 中的相对 URL 是否能正确基于 `source` URL 进行解析。
* **忽略未知的顶级键:** 验证解析器是否会忽略 JSON 中未知的顶级键，并发出警告信息。

**与 JavaScript, HTML, CSS 的关系:**

`ScriptWebBundleRule` 与 JavaScript, HTML, CSS 有着密切的关系，因为它定义了如何加载包含这些资源的 Web Bundle。

* **JavaScript:**
    * **`scopes` 字段:**  `scopes` 字段定义了 Web Bundle 中脚本的作用域。例如，`"scopes": ["js"]` 可能意味着这个 Web Bundle 中的 JavaScript 资源只在这个路径或其子路径下有效。
    * **资源加载:** `ScriptWebBundleRule` 决定了如何加载包含 JavaScript 代码的 `.wbn` 文件。
    * **假设输入与输出:** 如果 JSON 规则是 `{"source": "my-bundle.wbn", "scopes": ["/scripts/"]}`, 并且 `my-bundle.wbn` 包含一个名为 `app.js` 的 JavaScript 文件，那么这个规则意味着 `app.js` (或其他在 bundle 中的 JavaScript 资源) 可以在 `/scripts/` 或 `/scripts/subdir/` 等路径下的 HTML 页面中被加载和执行。

* **HTML:**
    * **资源加载:** Web Bundle 可以包含 HTML 文件。`ScriptWebBundleRule` 决定了如何加载这些 HTML 文件。
    * **`resources` 字段:**  `resources` 字段可以列出 Web Bundle 中包含的 HTML 文件，例如 `{"source": "my-bundle.wbn", "resources": ["index.html"]}`。
    * **假设输入与输出:** 如果 JSON 规则是 `{"source": "content.wbn", "resources": ["page1.html", "page2.html"]}`,  那么这个规则指示浏览器可以从 `content.wbn` 中加载 `page1.html` 和 `page2.html`。

* **CSS:**
    * **资源加载:** Web Bundle 同样可以包含 CSS 文件。
    * **`resources` 字段:**  `resources` 字段可以列出 Web Bundle 中包含的 CSS 文件，例如 `{"source": "style.wbn", "resources": ["global.css", "component.css"]}`。
    * **假设输入与输出:** 如果 JSON 规则是 `{"source": "theme.wbn", "resources": ["dark.css"]}`, 并且在某个 HTML 页面中引用了 `theme.wbn/dark.css`，那么 `ScriptWebBundleRule` 确保浏览器知道从哪里加载这个 CSS 文件。

**逻辑推理的假设输入与输出:**

* **假设输入 (JSON 规则):**
  ```json
  {
    "source": "my-app.wbn",
    "scopes": ["/app/"],
    "resources": ["main.js", "style.css"]
  }
  ```
* **假设 `base_url`:** `https://example.com/`
* **逻辑推理:** `ParseJson` 方法会解析这个 JSON，创建一个 `ScriptWebBundleRule` 对象。
* **假设输出 (解析后的 `ScriptWebBundleRule` 对象属性):**
    * `source_url()`: `https://example.com/my-app.wbn`
    * `scope_urls()`: 包含一个元素的集合 `{"https://example.com/app/"}`
    * `resource_urls()`: 包含两个元素的集合 `{"https://example.com/main.js", "https://example.com/style.css"}`

* **假设输入 (JSON 规则，包含相对路径):**
  ```json
  {
    "source": "bundles/my-library.wbn",
    "scopes": ["utils/"],
    "resources": ["helpers.js"]
  }
  ```
* **假设 `base_url`:** `https://example.com/`
* **逻辑推理:** `ParseJson` 方法会解析这个 JSON，并基于 `source` 的路径解析相对路径。
* **假设输出 (解析后的 `ScriptWebBundleRule` 对象属性):**
    * `source_url()`: `https://example.com/bundles/my-library.wbn`
    * `scope_urls()`: 包含一个元素的集合 `{"https://example.com/bundles/utils/"}`
    * `resource_urls()`: 包含一个元素的集合 `{"https://example.com/bundles/helpers.js"}`

**用户或编程常见的使用错误:**

* **JSON 格式错误:** 用户可能会在 JSON 规则中引入语法错误，例如缺少逗号、引号不匹配等。
    * **示例:** `{"source": "my.wbn" "scopes": ["/"]}` (缺少逗号)
    * **错误信息 (测试用例 `Empty` 模拟):**  `Failed to parse web bundle rule: invalid JSON.`
* **缺少 `source` 字段:**  `source` 字段是必需的，用户可能会忘记添加。
    * **示例:** `{"scopes": ["/"]}`
    * **错误信息 (测试用例 `MissingSource` 模拟):** `Failed to parse web bundle rule: "source" top-level key must be a string.`
* **`source` 字段类型错误:** `source` 字段必须是字符串，用户可能会错误地使用其他类型。
    * **示例:** `{"source": 123}`
    * **错误信息 (测试用例 `WrongSourceType` 模拟):** `Failed to parse web bundle rule: "source" top-level key must be a string.`
* **无效的 URL 在 `source` 中:** 用户提供的 `source` 值可能不是一个有效的 URL。
    * **示例:** `{"source": "invalid-url"}`
    * **错误信息 (测试用例 `BadSourceURL` 模拟):** `Failed to parse web bundle rule: "source" is not parsable as a URL.`
* **`scopes` 或 `resources` 类型错误:** 这两个字段应该是数组。
    * **示例 (`scopes` 类型错误):** `{"source": "my.wbn", "scopes": "/app/"}`
    * **错误信息 (测试用例 `InvalidScopesType` 模拟):** `Failed to parse web bundle rule: "scopes" must be an array.`
    * **示例 (`resources` 类型错误):** `{"source": "my.wbn", "resources": {"file": "data"}}`
    * **错误信息 (测试用例 `InvalidResourcesType` 模拟):** `Failed to parse web bundle rule: "resources" must be an array.`
* **`credentials` 取值错误:**  `credentials` 只能是 `"same-origin"`, `"include"`, 或 `"omit"`。
    * **示例:** `{"source": "my.wbn", "credentials": "anonymous"}`
    * **行为 (测试用例 `CredentialsInvalidValueIsSameOrigin` 模拟):** 会回退到默认值 `same-origin`。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发者创建 Web Bundle 规则文件:** 开发者会创建一个 JSON 文件来描述如何加载和处理他们的 Web Bundle。这个文件可能被命名为 `web_bundle_rules.json` 或类似的名字。
2. **浏览器尝试加载 Web Bundle:** 当用户访问一个使用了 Web Bundle 的网页时，浏览器会尝试加载相关的 Web Bundle 文件。
3. **浏览器解析 Web Bundle 规则:** 浏览器会读取并解析开发者提供的 Web Bundle 规则文件。这个过程会调用到 `ScriptWebBundleRule::ParseJson` 方法。
4. **如果解析失败:**
    * **开发者可能在控制台中看到错误信息:**  如果 `ParseJson` 返回错误，浏览器通常会在开发者工具的控制台中显示相关的错误信息，例如 "Failed to parse web bundle rule: invalid JSON."。
    * **网络请求可能失败:**  由于无法正确解析规则，浏览器可能无法正确加载 Web Bundle 中的资源，导致网络请求失败。
    * **页面功能异常:**  如果 Web Bundle 中包含关键的 JavaScript, HTML 或 CSS 资源，解析失败会导致页面功能出现异常或样式错乱。
5. **开发者使用调试工具:**
    * **查看网络面板:** 开发者可以使用浏览器开发者工具的网络面板来查看 Web Bundle 文件的加载状态以及可能的错误信息。
    * **查看控制台:** 控制台会显示解析 Web Bundle 规则时产生的错误或警告信息。
    * **检查 Web Bundle 规则文件:** 开发者需要仔细检查他们的 `web_bundle_rules.json` 文件，确保 JSON 格式正确，所有字段的类型和取值都符合规范。这个 `script_web_bundle_rule_test.cc` 文件中定义的测试用例模拟了各种解析失败的场景，可以帮助开发者理解可能出现的错误以及如何修复它们。

总而言之，`script_web_bundle_rule_test.cc` 文件是确保 Chromium 浏览器能够正确解析和理解 Web Bundle 规则的关键组成部分。它通过大量的测试用例覆盖了各种可能的输入情况，帮助开发者避免常见的错误，并确保 Web Bundle 功能的稳定性和可靠性。

Prompt: 
```
这是目录为blink/renderer/core/loader/web_bundle/script_web_bundle_rule_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/loader/web_bundle/script_web_bundle_rule.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

namespace {

class MockConsoleLogger final : public GarbageCollected<MockConsoleLogger>,
                                public ConsoleLogger {
 public:
  const String& Message() const { return message_; }

 private:
  void AddConsoleMessageImpl(
      mojom::ConsoleMessageSource,
      mojom::ConsoleMessageLevel,
      const String& message,
      bool discard_duplicates,
      std::optional<mojom::ConsoleMessageCategory>) override {
    message_ = message;
  }
  void AddConsoleMessageImpl(ConsoleMessage*, bool) override { NOTREACHED(); }
  String message_;
};

}  // namespace

TEST(ScriptWebBundleRuleTest, Empty) {
  auto result =
      ScriptWebBundleRule::ParseJson("", KURL("https://example.com/"), nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleError>(result));
  auto& error = absl::get<ScriptWebBundleError>(result);
  EXPECT_EQ(error.GetType(), ScriptWebBundleError::Type::kSyntaxError);
  EXPECT_EQ(error.GetMessage(),
            "Failed to parse web bundle rule: invalid JSON.");
}

TEST(ScriptWebBundleRuleTest, Basic) {
  const KURL base_url("https://example.com/");
  auto result = ScriptWebBundleRule::ParseJson(
      R"({
        "source": "foo.wbn",
        "scopes": ["js"],
        "resources": ["dir/a.css", "dir/b.css"]
      })",
      base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleRule>(result));
  auto& rule = absl::get<ScriptWebBundleRule>(result);
  EXPECT_EQ(rule.source_url(), "https://example.com/foo.wbn");
  EXPECT_THAT(rule.scope_urls(),
              testing::UnorderedElementsAre("https://example.com/js"));
  EXPECT_THAT(rule.resource_urls(),
              testing::UnorderedElementsAre("https://example.com/dir/a.css",
                                            "https://example.com/dir/b.css"));
}

TEST(ScriptWebBundleRuleTest, SourceOnly) {
  const KURL base_url("https://example.com/");
  auto result = ScriptWebBundleRule::ParseJson(
      R"({
        "source": "foo.wbn"
      })",
      base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleRule>(result));
  auto& rule = absl::get<ScriptWebBundleRule>(result);
  EXPECT_EQ(rule.source_url(), "https://example.com/foo.wbn");
  EXPECT_TRUE(rule.scope_urls().empty());
  EXPECT_TRUE(rule.resource_urls().empty());
}

TEST(ScriptWebBundleRuleTest, ResourcesShouldBeResolvedOnBundleURL) {
  const KURL base_url("https://example.com/");
  auto result = ScriptWebBundleRule::ParseJson(
      R"({
        "source": "hello/foo.wbn",
        "resources": ["dir/a.css"]
      })",
      base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleRule>(result));
  auto& rule = absl::get<ScriptWebBundleRule>(result);
  EXPECT_EQ(rule.source_url(), "https://example.com/hello/foo.wbn");
  EXPECT_THAT(rule.resource_urls(), testing::UnorderedElementsAre(
                                        "https://example.com/hello/dir/a.css"));
}

TEST(ScriptWebBundleRuleTest, ScopesShouldBeResolvedOnBundleURL) {
  const KURL base_url("https://example.com/");
  auto result = ScriptWebBundleRule::ParseJson(
      R"({
        "source": "hello/foo.wbn",
        "scopes": ["js"]
      })",
      base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleRule>(result));
  auto& rule = absl::get<ScriptWebBundleRule>(result);
  EXPECT_EQ(rule.source_url(), "https://example.com/hello/foo.wbn");
  EXPECT_THAT(rule.scope_urls(),
              testing::UnorderedElementsAre("https://example.com/hello/js"));
}

TEST(ScriptWebBundleRuleTest, CredentialsDefaultIsSameOrigin) {
  const KURL base_url("https://example.com/");
  auto result = ScriptWebBundleRule::ParseJson(
      R"({
        "source": "foo.wbn"
      })",
      base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleRule>(result));
  auto& rule = absl::get<ScriptWebBundleRule>(result);
  EXPECT_EQ(rule.source_url(), "https://example.com/foo.wbn");
  EXPECT_EQ(rule.credentials_mode(),
            network::mojom::CredentialsMode::kSameOrigin);
}

TEST(ScriptWebBundleRuleTest, CredentialsSameOrigin) {
  const KURL base_url("https://example.com/");
  auto result = ScriptWebBundleRule::ParseJson(
      R"({
        "source": "foo.wbn",
        "credentials": "same-origin"
      })",
      base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleRule>(result));
  auto& rule = absl::get<ScriptWebBundleRule>(result);
  EXPECT_EQ(rule.source_url(), "https://example.com/foo.wbn");
  EXPECT_EQ(rule.credentials_mode(),
            network::mojom::CredentialsMode::kSameOrigin);
}

TEST(ScriptWebBundleRuleTest, CredentialsInclude) {
  const KURL base_url("https://example.com/");
  auto result = ScriptWebBundleRule::ParseJson(
      R"({
        "source": "foo.wbn",
        "credentials": "include"
      })",
      base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleRule>(result));
  auto& rule = absl::get<ScriptWebBundleRule>(result);
  EXPECT_EQ(rule.source_url(), "https://example.com/foo.wbn");
  EXPECT_EQ(rule.credentials_mode(), network::mojom::CredentialsMode::kInclude);
}

TEST(ScriptWebBundleRuleTest, CredentialsOmit) {
  const KURL base_url("https://example.com/");
  auto result = ScriptWebBundleRule::ParseJson(
      R"({
        "source": "foo.wbn",
        "credentials": "omit"
      })",
      base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleRule>(result));
  auto& rule = absl::get<ScriptWebBundleRule>(result);
  EXPECT_EQ(rule.source_url(), "https://example.com/foo.wbn");
  EXPECT_EQ(rule.credentials_mode(), network::mojom::CredentialsMode::kOmit);
}

TEST(ScriptWebBundleRuleTest, CredentialsInvalidValueIsSameOrigin) {
  const KURL base_url("https://example.com/");
  auto result = ScriptWebBundleRule::ParseJson(
      R"({
        "source": "foo.wbn",
        "credentials": "invalid-value"
      })",
      base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleRule>(result));
  auto& rule = absl::get<ScriptWebBundleRule>(result);
  EXPECT_EQ(rule.source_url(), "https://example.com/foo.wbn");
  EXPECT_EQ(rule.credentials_mode(),
            network::mojom::CredentialsMode::kSameOrigin);
}

TEST(ScriptWebBundleRuleTest, CredentialsExtraSpeceIsNotAllowed) {
  const KURL base_url("https://example.com/");
  auto result = ScriptWebBundleRule::ParseJson(
      R"({
        "source": "foo.wbn",
        "credentials": " include"
      })",
      base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleRule>(result));
  auto& rule = absl::get<ScriptWebBundleRule>(result);
  EXPECT_EQ(rule.source_url(), "https://example.com/foo.wbn");
  EXPECT_EQ(rule.credentials_mode(),
            network::mojom::CredentialsMode::kSameOrigin);
}

TEST(ScriptWebBundleRuleTest, CredentialsIsCaseSensitive) {
  const KURL base_url("https://example.com/");
  auto result = ScriptWebBundleRule::ParseJson(
      R"({
        "source": "foo.wbn",
        "credentials": "INCLUDE"
      })",
      base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleRule>(result));
  auto& rule = absl::get<ScriptWebBundleRule>(result);
  EXPECT_EQ(rule.source_url(), "https://example.com/foo.wbn");
  EXPECT_EQ(rule.credentials_mode(),
            network::mojom::CredentialsMode::kSameOrigin);
}

TEST(ScriptWebBundleRuleTest, TopLevelIsNotAnObject) {
  const KURL base_url("https://example.com/");
  auto result = ScriptWebBundleRule::ParseJson("[]", base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleError>(result));
  auto& error = absl::get<ScriptWebBundleError>(result);
  EXPECT_EQ(error.GetType(), ScriptWebBundleError::Type::kTypeError);
  EXPECT_EQ(error.GetMessage(),
            "Failed to parse web bundle rule: not an object.");
}

TEST(ScriptWebBundleRuleTest, MissingSource) {
  const KURL base_url("https://example.com/");
  auto result = ScriptWebBundleRule::ParseJson("{}", base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleError>(result));
  auto& error = absl::get<ScriptWebBundleError>(result);
  EXPECT_EQ(error.GetType(), ScriptWebBundleError::Type::kTypeError);
  EXPECT_EQ(error.GetMessage(),
            "Failed to parse web bundle rule: \"source\" "
            "top-level key must be a string.");
}

TEST(ScriptWebBundleRuleTest, WrongSourceType) {
  const KURL base_url("https://example.com/");
  auto result =
      ScriptWebBundleRule::ParseJson(R"({"source": 123})", base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleError>(result));
  auto& error = absl::get<ScriptWebBundleError>(result);
  EXPECT_EQ(error.GetType(), ScriptWebBundleError::Type::kTypeError);
  EXPECT_EQ(error.GetMessage(),
            "Failed to parse web bundle rule: \"source\" "
            "top-level key must be a string.");
}

TEST(ScriptWebBundleRuleTest, BadSourceURL) {
  const KURL base_url("https://example.com/");
  auto result = ScriptWebBundleRule::ParseJson(R"({"source": "http://"})",
                                               base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleError>(result));
  auto& error = absl::get<ScriptWebBundleError>(result);
  EXPECT_EQ(error.GetType(), ScriptWebBundleError::Type::kTypeError);
  EXPECT_EQ(error.GetMessage(),
            "Failed to parse web bundle rule: \"source\" "
            "is not parsable as a URL.");
}

TEST(ScriptWebBundleRuleTest, NoScopesNorResources) {
  const KURL base_url("https://example.com/");
  auto result = ScriptWebBundleRule::ParseJson(R"({"source": "http://"})",
                                               base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleError>(result));
  auto& error = absl::get<ScriptWebBundleError>(result);
  EXPECT_EQ(error.GetType(), ScriptWebBundleError::Type::kTypeError);
  EXPECT_EQ(error.GetMessage(),
            "Failed to parse web bundle rule: \"source\" "
            "is not parsable as a URL.");
}

TEST(ScriptWebBundleRuleTest, InvalidScopesType) {
  const KURL base_url("https://example.com/");
  auto result = ScriptWebBundleRule::ParseJson(
      R"({
        "source": "foo.wbn",
        "scopes": "js"
      })",
      base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleError>(result));
  auto& error = absl::get<ScriptWebBundleError>(result);
  EXPECT_EQ(error.GetType(), ScriptWebBundleError::Type::kTypeError);
  EXPECT_EQ(error.GetMessage(),
            "Failed to parse web bundle rule: \"scopes\" must be an array.");
}

TEST(ScriptWebBundleRuleTest, InvalidResourcesType) {
  const KURL base_url("https://example.com/");
  auto result = ScriptWebBundleRule::ParseJson(
      R"({
        "source": "foo.wbn",
        "resources":  { "a": "hello" }
      })",
      base_url, nullptr);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleError>(result));
  auto& error = absl::get<ScriptWebBundleError>(result);
  EXPECT_EQ(error.GetType(), ScriptWebBundleError::Type::kTypeError);
  EXPECT_EQ(error.GetMessage(),
            "Failed to parse web bundle rule: \"resources\" must be an array.");
}

TEST(ScriptWebBundleRuleTest, UnknownKey) {
  const KURL base_url("https://example.com/");
  MockConsoleLogger* logger = MakeGarbageCollected<MockConsoleLogger>();
  auto result = ScriptWebBundleRule::ParseJson(
      R"({
        "source": "foo.wbn",
        "unknown": []
      })",
      base_url, logger);
  ASSERT_TRUE(absl::holds_alternative<ScriptWebBundleRule>(result));
  auto& rule = absl::get<ScriptWebBundleRule>(result);
  EXPECT_EQ(rule.source_url(), "https://example.com/foo.wbn");
  EXPECT_TRUE(rule.scope_urls().empty());
  EXPECT_TRUE(rule.resource_urls().empty());
  EXPECT_EQ(logger->Message(),
            "Invalid top-level key \"unknown\" in WebBundle rule.");
}

}  // namespace blink

"""

```
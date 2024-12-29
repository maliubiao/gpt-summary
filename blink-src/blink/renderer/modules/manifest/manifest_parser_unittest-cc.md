Response:
The user wants a summary of the functionality of the `manifest_parser_unittest.cc` file in the Chromium Blink engine. I need to analyze the provided code snippet to understand its purpose and how it relates to web technologies like JavaScript, HTML, and CSS.

**Plan:**

1. Identify the core functionality of the file.
2. Determine if and how it interacts with JavaScript, HTML, and CSS.
3. Look for examples of logical reasoning within the tests (input/output).
4. Identify common user or programming errors that the tests might be checking for.
5. Infer the user actions that might lead to this code being executed (debugging context).
6. Summarize the identified functionality for this first part of the file.
这是 Chromium Blink 引擎中 `blink/renderer/modules/manifest/manifest_parser_unittest.cc` 文件的第一部分，主要功能是**测试 Manifest 文件的解析器 (`ManifestParser`) 的功能**。

更具体地说，这部分代码包含了一系列的单元测试，用于验证 `ManifestParser`  在解析不同格式和内容的 Manifest 文件时是否能够正确地提取和处理其中的数据，以及是否能够正确地报告错误。

**与 JavaScript, HTML, CSS 的关系：**

Manifest 文件是一个 JSON 格式的文件，用于描述 Web 应用的元数据，例如名称、图标、启动 URL 等。这些信息被浏览器用来将 Web 应用添加到用户的设备桌面或启动器，提供类似于原生应用的体验。因此，`manifest_parser_unittest.cc` 间接地与 JavaScript, HTML, 和 CSS 有关：

*   **HTML:**  HTML 文件通过 `<link rel="manifest" href="manifest.json">` 标签来引用 Manifest 文件。测试会模拟浏览器加载包含这个 link 标签的 HTML 页面，并尝试解析 `href` 指向的 Manifest 文件。
*   **JavaScript:** JavaScript 代码可以通过 `navigator.serviceWorker.register('service-worker.js')` 等 API 来注册 Service Worker。Service Worker 的注册通常与 Manifest 文件关联，浏览器需要解析 Manifest 文件来获取应用的元数据。
*   **CSS:** 虽然 Manifest 文件本身不是 CSS，但 Manifest 中定义的 `theme_color` 和 `background_color` 等属性会影响浏览器渲染 Web 应用时的视觉样式。测试会验证这些属性是否能被正确解析。

**举例说明:**

假设一个简单的 `manifest.json` 文件如下：

```json
{
  "name": "我的应用",
  "short_name": "应用",
  "start_url": "/index.html",
  "display": "standalone"
}
```

*   **假设输入 (JSON 数据):** `"{\"name\": \"我的应用\", \"short_name\": \"应用\", \"start_url\": \"/index.html\", \"display\": \"standalone\"}"`
*   **预期输出 (解析后的 Manifest 对象):** 一个 `mojom::blink::ManifestPtr` 对象，其 `name` 属性值为 "我的应用"，`short_name` 属性值为 "应用"，`start_url` 属性值为 "http://foo.com/index.html" (假设 `document_url` 为 "http://foo.com/index.html")，`display` 属性值为 `blink::mojom::DisplayMode::kStandalone`。

**用户或编程常见的使用错误举例说明：**

*   **Manifest 文件格式错误:** 用户可能在编写 `manifest.json` 时使用了错误的 JSON 语法，例如缺少引号、逗号等。测试用例 `TEST_F(ManifestParserTest, EmptyStringNull)` 模拟了这种情况，当传入一个空字符串时，解析器会报告语法错误。
*   **Manifest 属性类型错误:** 用户可能在 Manifest 文件中为某个属性设置了错误的数据类型，例如将 `name` 属性的值设置为数字而不是字符串。测试用例 `TEST_F(ManifestParserTest, MultipleErrorsReporting)` 中就包含了这样的例子，例如 `"name": 42`。
*   **使用了不支持的 Manifest 属性:** 用户可能参考了过时的文档或者其他平台的规范，在 Manifest 文件中使用了浏览器不支持的属性。测试用例 `TEST_F(ManifestParserTest, UnrecognizedFieldsIgnored)` 验证了解析器会忽略这些未知的字段。
*   **`start_url` 跨域:** 用户可能错误地将 `start_url` 设置为与当前页面不同域名的 URL。测试用例 `TEST_F(ManifestParserTest, StartURLParseRules)` 中有针对这种情况的测试，验证了解析器会忽略跨域的 `start_url`。

**用户操作如何一步步的到达这里 (调试线索):**

1. **开发者创建或修改了 Web 应用的 Manifest 文件 (`manifest.json`)。**
2. **用户通过浏览器访问了包含 `<link rel="manifest" href="manifest.json">` 标签的 HTML 页面。**
3. **浏览器开始下载并解析 `manifest.json` 文件。**
4. **`ManifestParser` 类被调用来执行解析操作。**
5. **如果 Manifest 文件的内容导致解析出现问题，开发者可能会设置断点在 `manifest_parser_unittest.cc` 中的相关测试用例中，例如解析特定属性的测试用例，来调试解析过程。**
6. **开发者可以逐步执行代码，查看 `ManifestParser` 如何处理不同的输入，以及如何产生错误信息。**

**归纳一下这部分的功能:**

这部分 `manifest_parser_unittest.cc` 文件的主要功能是**通过一系列单元测试来验证 `ManifestParser` 类解析 Web 应用 Manifest 文件的正确性、健壮性和错误处理能力**。它涵盖了各种合法的和非法的 Manifest 文件内容，包括不同数据类型、格式错误、不支持的属性等，确保 Manifest 文件能被浏览器正确解析，从而为用户提供预期的 Web 应用体验。

Prompt: 
```
这是目录为blink/renderer/modules/manifest/manifest_parser_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共8部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/manifest/manifest_parser.h"

#include <stdint.h>

#include <memory>
#include <optional>

#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/permissions_policy/permissions_policy.h"
#include "third_party/blink/public/common/safe_url_pattern.h"
#include "third_party/blink/public/mojom/manifest/manifest.mojom-blink.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_uchar.h"
#include "third_party/liburlpattern/pattern.h"

namespace blink {

namespace {
bool IsManifestEmpty(const mojom::blink::ManifestPtr& manifest) {
  return manifest == mojom::blink::Manifest::New();
}
}  // namespace

class ManifestParserTest : public testing::Test {
 public:
  ManifestParserTest(const ManifestParserTest&) = delete;
  ManifestParserTest& operator=(const ManifestParserTest&) = delete;

 protected:
  ManifestParserTest() {}
  ~ManifestParserTest() override {}

  mojom::blink::ManifestPtr& ParseManifestWithURLs(const String& data,
                                                   const KURL& manifest_url,
                                                   const KURL& document_url) {
    ManifestParser parser(data, manifest_url, document_url,
                          /*execution_context=*/nullptr);
    parser.Parse();
    Vector<mojom::blink::ManifestErrorPtr> errors;
    parser.TakeErrors(&errors);

    errors_.clear();
    for (auto& error : errors)
      errors_.push_back(std::move(error->message));
    manifest_ = parser.TakeManifest();
    EXPECT_TRUE(manifest_);
    return manifest_;
  }

  mojom::blink::ManifestPtr& ParseManifest(const String& data) {
    return ParseManifestWithURLs(data, DefaultManifestUrl(),
                                 DefaultDocumentUrl());
  }

  const Vector<String>& errors() const { return errors_; }

  unsigned int GetErrorCount() const { return errors_.size(); }

  static KURL DefaultDocumentUrl() { return KURL("http://foo.com/index.html"); }
  static KURL DefaultManifestUrl() {
    return KURL("http://foo.com/manifest.json");
  }

  bool HasDefaultValuesWithUrls(
      const mojom::blink::ManifestPtr& manifest,
      const KURL& document_url = DefaultDocumentUrl(),
      const KURL& manifest_url = DefaultManifestUrl()) {
    mojom::blink::ManifestPtr expected_manifest = mojom::blink::Manifest::New();
    // A true "default" manifest would have an empty manifest URL. However in
    // these tests we don't want to check for that, rather this method is used
    // to check that a manifest has all its fields set to "default" values, but
    // also have the expected manifest url.
    expected_manifest->manifest_url = manifest_url;
    expected_manifest->start_url = document_url;
    expected_manifest->id = document_url;
    expected_manifest->id.RemoveFragmentIdentifier();
    expected_manifest->scope = KURL(document_url.BaseAsString().ToString());
    return manifest == expected_manifest;
  }

  void VerifySafeUrlPatternSizes(const SafeUrlPattern& pattern,
                                 size_t protocol_size,
                                 size_t username_size,
                                 size_t password_size,
                                 size_t hostname_size,
                                 size_t port_size,
                                 size_t pathname_size,
                                 size_t search_size,
                                 size_t hash_size) {
    EXPECT_EQ(pattern.protocol.size(), protocol_size);
    EXPECT_EQ(pattern.username.size(), username_size);
    EXPECT_EQ(pattern.password.size(), password_size);
    EXPECT_EQ(pattern.hostname.size(), hostname_size);
    EXPECT_EQ(pattern.port.size(), port_size);
    EXPECT_EQ(pattern.pathname.size(), pathname_size);
    EXPECT_EQ(pattern.search.size(), search_size);
    EXPECT_EQ(pattern.hash.size(), hash_size);
  }

 private:
  test::TaskEnvironment task_environment_;
  mojom::blink::ManifestPtr manifest_;
  Vector<String> errors_;
};

TEST_F(ManifestParserTest, CrashTest) {
  // Passing temporary variables should not crash.
  const String json = R"({"start_url": "/"})";
  KURL url("http://example.com");
  ManifestParser parser(json, url, url, /*execution_context=*/nullptr);

  bool has_comments = parser.Parse();
  EXPECT_FALSE(has_comments);
  Vector<mojom::blink::ManifestErrorPtr> errors;
  parser.TakeErrors(&errors);
  auto manifest = parser.TakeManifest();

  // .Parse() should have been call without crashing and succeeded.
  EXPECT_EQ(0u, errors.size());
  EXPECT_FALSE(IsManifestEmpty(manifest));
}

TEST_F(ManifestParserTest, HasComments) {
  const String json = R"({
        // comment
        "start_url": "/"
      })";
  KURL url("http://example.com");
  ManifestParser parser(json, url, url, /*execution_context=*/nullptr);

  bool has_comments = parser.Parse();
  EXPECT_TRUE(has_comments);
}

TEST_F(ManifestParserTest, EmptyStringNull) {
  auto& manifest = ParseManifest("");

  // This Manifest is not a valid JSON object, it's a parsing error.
  EXPECT_EQ(1u, GetErrorCount());
  EXPECT_EQ("Line: 1, column: 1, Syntax error.", errors()[0]);

  // A parsing error is equivalent to an empty manifest.
  EXPECT_TRUE(IsManifestEmpty(manifest));
  EXPECT_FALSE(HasDefaultValuesWithUrls(manifest));
}

TEST_F(ManifestParserTest, ValidNoContentParses) {
  base::HistogramTester histogram_tester;
  auto& manifest = ParseManifestWithURLs("{}", KURL(), DefaultDocumentUrl());

  // Empty Manifest is not a parsing error.
  EXPECT_EQ(0u, GetErrorCount());

  // Check that the fields are null or set to their default values.
  EXPECT_FALSE(IsManifestEmpty(manifest));
  EXPECT_TRUE(HasDefaultValuesWithUrls(manifest, DefaultDocumentUrl(), KURL()));
  EXPECT_EQ(manifest->dir, mojom::blink::Manifest::TextDirection::kAuto);
  EXPECT_TRUE(manifest->name.IsNull());
  EXPECT_TRUE(manifest->short_name.IsNull());
  EXPECT_EQ(manifest->start_url, DefaultDocumentUrl());
  EXPECT_EQ(manifest->display, blink::mojom::DisplayMode::kUndefined);
  EXPECT_EQ(manifest->orientation,
            device::mojom::ScreenOrientationLockType::DEFAULT);
  EXPECT_FALSE(manifest->has_theme_color);
  EXPECT_FALSE(manifest->has_background_color);
  EXPECT_TRUE(manifest->gcm_sender_id.IsNull());
  EXPECT_EQ(DefaultDocumentUrl().BaseAsString(), manifest->scope.GetString());
  EXPECT_TRUE(manifest->shortcuts.empty());

  // Check that the metrics don't record anything
  EXPECT_THAT(histogram_tester.GetAllSamples("Manifest.HasProperty.name"),
              testing::IsEmpty());
  EXPECT_THAT(histogram_tester.GetAllSamples("Manifest.HasProperty.start_url"),
              testing::IsEmpty());
  EXPECT_THAT(histogram_tester.GetAllSamples("Manifest.HasProperty.short_name"),
              testing::IsEmpty());

  EXPECT_THAT(
      histogram_tester.GetAllSamples("Manifest.HasProperty.description"),
      testing::IsEmpty());
  EXPECT_THAT(histogram_tester.GetAllSamples("Manifest.HasProperty.start_url"),
              testing::IsEmpty());
  EXPECT_THAT(histogram_tester.GetAllSamples("Manifest.HasProperty.display"),
              testing::IsEmpty());
  EXPECT_THAT(
      histogram_tester.GetAllSamples("Manifest.HasProperty.orientation"),
      testing::IsEmpty());
  EXPECT_THAT(histogram_tester.GetAllSamples("Manifest.HasProperty.icons"),
              testing::IsEmpty());
  EXPECT_THAT(
      histogram_tester.GetAllSamples("Manifest.HasProperty.screenshots"),
      testing::IsEmpty());
  EXPECT_THAT(
      histogram_tester.GetAllSamples("Manifest.HasProperty.share_target"),
      testing::IsEmpty());

  EXPECT_THAT(
      histogram_tester.GetAllSamples("Manifest.HasProperty.protocol_handlers"),
      testing::IsEmpty());
  EXPECT_THAT(
      histogram_tester.GetAllSamples("Manifest.HasProperty.gcm_sender_id"),
      testing::IsEmpty());
}

TEST_F(ManifestParserTest, UnrecognizedFieldsIgnored) {
  auto& manifest = ParseManifest(
      R"({
        "unrecognizable_manifest_field": ["foo"],
        "name": "bar"
      })");

  // Unrecognized Manifest fields are not a parsing error.
  EXPECT_EQ(0u, GetErrorCount());

  // Check that subsequent fields parsed.
  EXPECT_FALSE(IsManifestEmpty(manifest));
  EXPECT_FALSE(HasDefaultValuesWithUrls(manifest));
  EXPECT_EQ(manifest->name, "bar");
  EXPECT_EQ(DefaultDocumentUrl().BaseAsString(), manifest->scope.GetString());
}

TEST_F(ManifestParserTest, MultipleErrorsReporting) {
  auto& manifest = ParseManifest(
      R"({ "dir": "foo", "name": 42, "short_name": 4,
      "id": 12, "orientation": {}, "display": "foo",
      "start_url": null, "icons": {}, "theme_color": 42,
      "background_color": 42, "shortcuts": {} })");
  EXPECT_FALSE(IsManifestEmpty(manifest));
  EXPECT_TRUE(HasDefaultValuesWithUrls(manifest));

  EXPECT_THAT(errors(),
              testing::UnorderedElementsAre(
                  "unknown 'dir' value ignored.",
                  "property 'name' ignored, type string expected.",
                  "property 'short_name' ignored, type string expected.",
                  "property 'start_url' ignored, type string expected.",
                  "property 'id' ignored, type string expected.",
                  "unknown 'display' value ignored.",
                  "property 'orientation' ignored, type string expected.",
                  "property 'icons' ignored, type array expected.",
                  "property 'theme_color' ignored, type string expected.",
                  "property 'background_color' ignored, type string expected.",
                  "property 'shortcuts' ignored, type array expected."));
}

TEST_F(ManifestParserTest, DirParseRules) {
  using TextDirection = mojom::blink::Manifest::TextDirection;

  // Smoke test.
  {
    auto& manifest = ParseManifest(R"({ "dir": "ltr" })");
    EXPECT_EQ(manifest->dir, TextDirection::kLTR);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_FALSE(HasDefaultValuesWithUrls(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Trim whitespaces.
  {
    auto& manifest = ParseManifest(R"({ "dir": "  rtl  " })");
    EXPECT_EQ(manifest->dir, TextDirection::kRTL);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Don't parse if dir isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "dir": {} })");
    EXPECT_EQ(manifest->dir, TextDirection::kAuto);
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'dir' ignored, type string expected.", errors()[0]);
  }

  // Don't parse if dir isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "dir": 42 })");
    EXPECT_EQ(manifest->dir, TextDirection::kAuto);
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'dir' ignored, type string expected.", errors()[0]);
  }

  // Accept 'auto'.
  {
    auto& manifest = ParseManifest(R"({ "dir": "auto" })");
    EXPECT_EQ(manifest->dir, TextDirection::kAuto);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept 'ltr'.
  {
    auto& manifest = ParseManifest(R"({ "dir": "ltr" })");
    EXPECT_EQ(manifest->dir, TextDirection::kLTR);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept 'rtl'.
  {
    auto& manifest = ParseManifest(R"({ "dir": "rtl" })");
    EXPECT_EQ(manifest->dir, TextDirection::kRTL);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Parse fails if string isn't known.
  {
    auto& manifest = ParseManifest(R"({ "dir": "foo" })");
    EXPECT_EQ(manifest->dir, TextDirection::kAuto);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("unknown 'dir' value ignored.", errors()[0]);
  }
}

TEST_F(ManifestParserTest, NameParseRules) {
  // Smoke test.
  {
    auto& manifest = ParseManifest(R"({ "name": "foo" })");
    EXPECT_EQ(manifest->name, "foo");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_FALSE(HasDefaultValuesWithUrls(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Trim whitespaces.
  {
    auto& manifest = ParseManifest(R"({ "name": "  foo  " })");
    EXPECT_EQ(manifest->name, "foo");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Don't parse if name isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "name": {} })");
    EXPECT_TRUE(manifest->name.IsNull());
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'name' ignored, type string expected.", errors()[0]);
  }

  // Don't parse if name isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "name": 42 })");
    EXPECT_TRUE(manifest->name.IsNull());
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'name' ignored, type string expected.", errors()[0]);
  }

  // Test stripping out of \t \r and \n.
  {
    auto& manifest = ParseManifest("{ \"name\": \"abc\\t\\r\\ndef\" }");
    EXPECT_EQ(manifest->name, "abcdef");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }
}

TEST_F(ManifestParserTest, DescriptionParseRules) {
  // Smoke test.
  {
    auto& manifest =
        ParseManifest(R"({ "description": "foo is the new black" })");
    EXPECT_EQ(manifest->description, "foo is the new black");
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Trim whitespaces.
  {
    auto& manifest = ParseManifest(R"({ "description": "  foo  " })");
    EXPECT_EQ(manifest->description, "foo");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Don't parse if description isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "description": {} })");
    EXPECT_TRUE(manifest->description.IsNull());
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'description' ignored, type string expected.",
              errors()[0]);
  }

  // Don't parse if description isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "description": 42 })");
    EXPECT_TRUE(manifest->description.IsNull());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'description' ignored, type string expected.",
              errors()[0]);
  }
}

TEST_F(ManifestParserTest, ShortNameParseRules) {
  // Smoke test.
  {
    auto& manifest = ParseManifest(R"({ "short_name": "foo" })");
    ASSERT_EQ(manifest->short_name, "foo");
    ASSERT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Trim whitespaces.
  {
    auto& manifest = ParseManifest(R"({ "short_name": "  foo  " })");
    ASSERT_EQ(manifest->short_name, "foo");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Don't parse if name isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "short_name": {} })");
    ASSERT_TRUE(manifest->short_name.IsNull());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'short_name' ignored, type string expected.",
              errors()[0]);
  }

  // Don't parse if name isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "short_name": 42 })");
    ASSERT_TRUE(manifest->short_name.IsNull());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'short_name' ignored, type string expected.",
              errors()[0]);
  }

  // Test stripping out of \t \r and \n.
  {
    auto& manifest = ParseManifest("{ \"short_name\": \"abc\\t\\r\\ndef\" }");
    ASSERT_EQ(manifest->short_name, "abcdef");
    ASSERT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }
}

TEST_F(ManifestParserTest, IdParseRules) {
  // Empty manifest.
  {
    auto& manifest = ParseManifest("{ }");
    ASSERT_TRUE(manifest);
    EXPECT_THAT(errors(), testing::IsEmpty());
    EXPECT_EQ(manifest->id, DefaultDocumentUrl());
    EXPECT_FALSE(manifest->has_custom_id);
  }
  // Does not contain id field.
  {
    auto& manifest = ParseManifest(R"({"start_url": "/start?query=a" })");
    EXPECT_THAT(errors(), testing::IsEmpty());
    EXPECT_EQ("http://foo.com/start?query=a", manifest->id);
    EXPECT_FALSE(manifest->has_custom_id);
  }
  // Invalid type.
  {
    auto& manifest =
        ParseManifest("{\"start_url\": \"/start?query=a\", \"id\": 1}");
    EXPECT_THAT(errors(), testing::ElementsAre(
                              "property 'id' ignored, type string expected."));
    EXPECT_EQ("http://foo.com/start?query=a", manifest->id);
    EXPECT_FALSE(manifest->has_custom_id);
  }
  // Empty string.
  {
    auto& manifest =
        ParseManifest(R"({ "start_url": "/start?query=a", "id": "" })");
    EXPECT_THAT(errors(), testing::IsEmpty());
    EXPECT_EQ("http://foo.com/start?query=a", manifest->id);
    EXPECT_FALSE(manifest->has_custom_id);
  }
  // Full url.
  {
    auto& manifest = ParseManifest(
        "{ \"start_url\": \"/start?query=a\", \"id\": \"http://foo.com/foo\" "
        "}");
    EXPECT_THAT(errors(), testing::IsEmpty());
    EXPECT_EQ("http://foo.com/foo", manifest->id);
    EXPECT_TRUE(manifest->has_custom_id);
  }
  // Full url with different origin.
  {
    auto& manifest = ParseManifest(
        "{ \"start_url\": \"/start?query=a\", \"id\": "
        "\"http://another.com/foo\" }");
    EXPECT_THAT(
        errors(),
        testing::ElementsAre(
            "property 'id' ignored, should be same origin as document."));
    EXPECT_EQ("http://foo.com/start?query=a", manifest->id);
    EXPECT_FALSE(manifest->has_custom_id);
  }
  // Relative path
  {
    auto& manifest =
        ParseManifest("{ \"start_url\": \"/start?query=a\", \"id\": \".\" }");
    EXPECT_THAT(errors(), testing::IsEmpty());
    EXPECT_EQ("http://foo.com/", manifest->id);
    EXPECT_TRUE(manifest->has_custom_id);
  }
  // Absolute path
  {
    auto& manifest =
        ParseManifest("{ \"start_url\": \"/start?query=a\", \"id\": \"/\" }");
    EXPECT_THAT(errors(), testing::IsEmpty());
    EXPECT_EQ("http://foo.com/", manifest->id);
    EXPECT_TRUE(manifest->has_custom_id);
  }
  // url with fragment
  {
    auto& manifest = ParseManifest(
        "{ \"start_url\": \"/start?query=a\", \"id\": \"/#abc\" }");
    EXPECT_THAT(errors(), testing::IsEmpty());
    EXPECT_EQ("http://foo.com/", manifest->id);
    EXPECT_TRUE(manifest->has_custom_id);
  }
  // Smoke test.
  {
    auto& manifest =
        ParseManifest(R"({ "start_url": "/start?query=a", "id": "foo" })");
    EXPECT_THAT(errors(), testing::IsEmpty());
    EXPECT_EQ("http://foo.com/foo", manifest->id);
    EXPECT_TRUE(manifest->has_custom_id);
  }
  // Invalid UTF-8 character.
  {
    UChar invalid_utf8_chars[] = {0xD801, 0x0000};
    String manifest_str =
        String("{ \"start_url\": \"/start?query=a\", \"id\": \"") +
        String(invalid_utf8_chars) + String("\" }");

    auto& manifest = ParseManifest(manifest_str);
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_THAT(
        errors()[0].Utf8(),
        testing::EndsWith("Unsupported encoding. JSON and all string literals "
                          "must contain valid Unicode characters."));
    ASSERT_TRUE(manifest);
    EXPECT_FALSE(manifest->has_custom_id);
  }
}

TEST_F(ManifestParserTest, StartURLParseRules) {
  // Smoke test.
  {
    base::HistogramTester histogram_tester;
    auto& manifest = ParseManifest(R"({ "start_url": "land.html" })");
    ASSERT_EQ(manifest->start_url, KURL(DefaultDocumentUrl(), "land.html"));
    ASSERT_FALSE(IsManifestEmpty(manifest));
    EXPECT_THAT(errors(), testing::IsEmpty());
    EXPECT_TRUE(manifest->has_valid_specified_start_url);
    EXPECT_FALSE(HasDefaultValuesWithUrls(manifest));
    EXPECT_THAT(
        histogram_tester.GetAllSamples("Manifest.HasProperty.start_url"),
        base::BucketsAre(base::Bucket(1, 1)));
  }

  // Whitespaces.
  {
    auto& manifest = ParseManifest(R"({ "start_url": "  land.html  " })");
    ASSERT_EQ(manifest->start_url, KURL(DefaultDocumentUrl(), "land.html"));
    EXPECT_THAT(errors(), testing::IsEmpty());
    EXPECT_TRUE(manifest->has_valid_specified_start_url);
  }

  // Don't parse if property isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "start_url": {} })");
    EXPECT_EQ(manifest->start_url, DefaultDocumentUrl());
    EXPECT_EQ(DefaultDocumentUrl(), manifest->id);
    EXPECT_THAT(errors(),
                testing::ElementsAre(
                    "property 'start_url' ignored, type string expected."));
    EXPECT_FALSE(manifest->has_valid_specified_start_url);
    EXPECT_TRUE(HasDefaultValuesWithUrls(manifest));
  }

  // Don't parse if property isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "start_url": 42 })");
    EXPECT_EQ(manifest->start_url, DefaultDocumentUrl());
    EXPECT_THAT(errors(),
                testing::ElementsAre(
                    "property 'start_url' ignored, type string expected."));
    EXPECT_FALSE(manifest->has_valid_specified_start_url);
  }

  // Don't parse if property isn't a valid URL.
  {
    auto& manifest =
        ParseManifest(R"({ "start_url": "http://www.google.ca:a" })");
    EXPECT_EQ(manifest->start_url, DefaultDocumentUrl());
    EXPECT_THAT(errors(), testing::ElementsAre(
                              "property 'start_url' ignored, URL is invalid."));
    EXPECT_FALSE(manifest->has_valid_specified_start_url);
  }

  // Absolute start_url, same origin with document.
  {
    auto& manifest =
        ParseManifestWithURLs(R"({ "start_url": "http://foo.com/land.html" })",
                              KURL("http://foo.com/manifest.json"),
                              KURL("http://foo.com/index.html"));
    EXPECT_EQ(manifest->start_url.GetString(), "http://foo.com/land.html");
    EXPECT_THAT(errors(), testing::IsEmpty());
    EXPECT_TRUE(manifest->has_valid_specified_start_url);
  }

  // Absolute start_url, cross origin with document.
  {
    auto& manifest =
        ParseManifestWithURLs(R"({ "start_url": "http://bar.com/land.html" })",
                              KURL("http://foo.com/manifest.json"),
                              KURL("http://foo.com/index.html"));
    EXPECT_EQ(manifest->start_url, DefaultDocumentUrl());
    EXPECT_THAT(errors(),
                testing::ElementsAre("property 'start_url' ignored, should "
                                     "be same origin as document."));
    EXPECT_FALSE(manifest->has_valid_specified_start_url);
  }

  // Resolving has to happen based on the manifest_url.
  {
    auto& manifest =
        ParseManifestWithURLs(R"({ "start_url": "land.html" })",
                              KURL("http://foo.com/landing/manifest.json"),
                              KURL("http://foo.com/index.html"));
    EXPECT_EQ(manifest->start_url.GetString(),
              "http://foo.com/landing/land.html");
    EXPECT_THAT(errors(), testing::IsEmpty());
    EXPECT_TRUE(manifest->has_valid_specified_start_url);
  }
}

TEST_F(ManifestParserTest, ScopeParseRules) {
  // Smoke test.
  {
    auto& manifest = ParseManifest(
        R"({ "scope": "land", "start_url": "land/landing.html" })");
    ASSERT_EQ(manifest->scope, KURL(DefaultDocumentUrl(), "land"));
    ASSERT_FALSE(IsManifestEmpty(manifest));
    EXPECT_THAT(errors(), testing::IsEmpty());
  }

  // Whitespaces.
  {
    auto& manifest = ParseManifest(
        R"({ "scope": "  land  ", "start_url": "land/landing.html" })");
    ASSERT_EQ(manifest->scope, KURL(DefaultDocumentUrl(), "land"));
    EXPECT_THAT(errors(), testing::IsEmpty());
  }

  // Return the default value if the property isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "scope": {} })");
    ASSERT_EQ(manifest->scope.GetString(), DefaultDocumentUrl().BaseAsString());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'scope' ignored, type string expected.", errors()[0]);
  }

  // Return the default value if property isn't a string.
  {
    auto& manifest = ParseManifest(
        R"({ "scope": 42,
        "start_url": "http://foo.com/land/landing.html" })");
    ASSERT_EQ(manifest->scope, KURL(DefaultDocumentUrl(), "land/"));
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("property 'scope' ignored, type string expected.", errors()[0]);
  }

  // Absolute scope, start URL is in scope.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "scope": "http://foo.com/land",
        "start_url": "http://foo.com/land/landing.html" })",
        KURL("http://foo.com/manifest.json"),
        KURL("http://foo.com/index.html"));
    ASSERT_EQ(manifest->scope.GetString(), "http://foo.com/land");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Absolute scope, start URL is not in scope.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "scope": "http://foo.com/land",
        "start_url": "http://foo.com/index.html" })",
        KURL("http://foo.com/manifest.json"),
        KURL("http://foo.com/index.html"));
    ASSERT_EQ(manifest->scope.GetString(), DefaultDocumentUrl().BaseAsString());
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'scope' ignored. Start url should be within scope "
        "of scope URL.",
        errors()[0]);
  }

  // Absolute scope, start URL has different origin than scope URL.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "scope": "http://foo.com/land",
        "start_url": "http://bar.com/land/landing.html" })",
        KURL("http://foo.com/manifest.json"),
        KURL("http://foo.com/index.html"));
    ASSERT_EQ(manifest->scope.GetString(), DefaultDocumentUrl().BaseAsString());
    ASSERT_EQ(2u, GetErrorCount());
    EXPECT_EQ(
        "property 'start_url' ignored, should be same origin as document.",
        errors()[0]);
    EXPECT_EQ(
        "property 'scope' ignored. Start url should be within scope "
        "of scope URL.",
        errors()[1]);
  }

  // scope and start URL have diferent origin than document URL.
  {
    KURL document_url("http://bar.com/index.html");
    auto& manifest = ParseManifestWithURLs(
        R"({ "scope": "http://foo.com/land",
        "start_url": "http://foo.com/land/landing.html" })",
        KURL("http://foo.com/manifest.json"), document_url);
    ASSERT_EQ(manifest->scope.GetString(), document_url.BaseAsString());
    ASSERT_EQ(2u, GetErrorCount());
    EXPECT_EQ(
        "property 'start_url' ignored, should be same origin as document.",
        errors()[0]);
    EXPECT_EQ(
        "property 'scope' ignored. Start url should be within scope "
        "of scope URL.",
        errors()[1]);
  }

  // No start URL. Document URL is in a subdirectory of scope.
  {
    auto& manifest =
        ParseManifestWithURLs(R"({ "scope": "http://foo.com/land" })",
                              KURL("http://foo.com/manifest.json"),
                              KURL("http://foo.com/land/site/index.html"));
    ASSERT_EQ(manifest->scope.GetString(), "http://foo.com/land");
    ASSERT_EQ(0u, GetErrorCount());
  }

  // No start URL. Document is out of scope.
  {
    KURL document_url("http://foo.com/index.html");
    auto& manifest =
        ParseManifestWithURLs(R"({ "scope": "http://foo.com/land" })",
                              KURL("http://foo.com/manifest.json"),
                              KURL("http://foo.com/index.html"));
    ASSERT_EQ(manifest->scope.GetString(), document_url.BaseAsString());
    ASSERT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'scope' ignored. Start url should be within scope "
        "of scope URL.",
        errors()[0]);
  }

  // Resolving has to happen based on the manifest_url.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "scope": "treasure" })", KURL("http://foo.com/map/manifest.json"),
        KURL("http://foo.com/map/treasure/island/index.html"));
    ASSERT_EQ(manifest->scope.GetString(), "http://foo.com/map/treasure");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Scope is parent directory.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "scope": ".." })", KURL("http://foo.com/map/manifest.json"),
        KURL("http://foo.com/index.html"));
    ASSERT_EQ(manifest->scope.GetString(), "http://foo.com/");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Scope tries to go up past domain.
  {
    auto& manifest = ParseManifestWithURLs(
        R"({ "scope": "../.." })", KURL("http://foo.com/map/manifest.json"),
        KURL("http://foo.com/index.html"));
    ASSERT_EQ(manifest->scope.GetString(), "http://foo.com/");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Scope removes query args.
  {
    auto& manifest = ParseManifest(
        R"({ "start_url": "app/index.html",
             "scope": "/?test=abc" })");
    ASSERT_EQ(manifest->scope.GetString(), "http://foo.com/");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Scope removes fragments.
  {
    auto& manifest = ParseManifest(
        R"({ "start_url": "app/index.html",
             "scope": "/#abc" })");
    ASSERT_EQ(manifest->scope.GetString(), "http://foo.com/");
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Scope defaults to start_url with the filename, query, and fragment removed.
  {
    auto& manifest =
        ParseManifest(R"({ "start_url": "land/landing.html?query=test#abc" })");
    ASSERT_EQ(manifest->scope, KURL(DefaultDocumentUrl(), "land/"));
    EXPECT_EQ(0u, GetErrorCount());
  }

  {
    auto& manifest =
        ParseManifest(R"({ "start_url": "land/land/landing.html" })");
    ASSERT_EQ(manifest->scope, KURL(DefaultDocumentUrl(), "land/land/"));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Scope defaults to document_url if start_url is not present.
  {
    auto& manifest = ParseManifest("{}");
    ASSERT_EQ(manifest->scope, KURL(DefaultDocumentUrl(), "."));
    EXPECT_EQ(0u, GetErrorCount());
  }
}

TEST_F(ManifestParserTest, DisplayParseRules) {
  // Smoke test.
  {
    auto& manifest = ParseManifest(R"({ "display": "browser" })");
    EXPECT_EQ(manifest->display, blink::mojom::DisplayMode::kBrowser);
    EXPECT_FALSE(IsManifestEmpty(manifest));
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Trim whitespaces.
  {
    auto& manifest = ParseManifest(R"({ "display": "  browser  " })");
    EXPECT_EQ(manifest->display, blink::mojom::DisplayMode::kBrowser);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Don't parse if name isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "display": {} })");
    EXPECT_EQ(manifest->display, blink::mojom::DisplayMode::kUndefined);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'display' ignored,"
        " type string expected.",
        errors()[0]);
  }

  // Don't parse if name isn't a string.
  {
    auto& manifest = ParseManifest(R"({ "display": 42 })");
    EXPECT_EQ(manifest->display, blink::mojom::DisplayMode::kUndefined);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ(
        "property 'display' ignored,"
        " type string expected.",
        errors()[0]);
  }

  // Parse fails if string isn't known.
  {
    auto& manifest = ParseManifest(R"({ "display": "browser_something" })");
    EXPECT_EQ(manifest->display, blink::mojom::DisplayMode::kUndefined);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("unknown 'display' value ignored.", errors()[0]);
  }

  // Accept 'fullscreen'.
  {
    auto& manifest = ParseManifest(R"({ "display": "fullscreen" })");
    EXPECT_EQ(manifest->display, blink::mojom::DisplayMode::kFullscreen);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept 'standalone'.
  {
    auto& manifest = ParseManifest(R"({ "display": "standalone" })");
    EXPECT_EQ(manifest->display, blink::mojom::DisplayMode::kStandalone);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept 'minimal-ui'.
  {
    auto& manifest = ParseManifest(R"({ "display": "minimal-ui" })");
    EXPECT_EQ(manifest->display, blink::mojom::DisplayMode::kMinimalUi);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Accept 'browser'.
  {
    auto& manifest = ParseManifest(R"({ "display": "browser" })");
    EXPECT_EQ(manifest->display, blink::mojom::DisplayMode::kBrowser);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Case insensitive.
  {
    auto& manifest = ParseManifest(R"({ "display": "BROWSER" })");
    EXPECT_EQ(manifest->display, blink::mojom::DisplayMode::kBrowser);
    EXPECT_EQ(0u, GetErrorCount());
  }

  // Do not accept 'window-controls-overlay' as a display mode.
  {
    auto& manifest =
        ParseManifest(R"({ "display": "window-controls-overlay" })");
    EXPECT_EQ(manifest->display, blink::mojom::DisplayMode::kUndefined);
    EXPECT_EQ(1u, GetErrorCount());
    EXPECT_EQ("inapplicable 'display' value ignored.", errors()[0]);
  }

  // Parsing fails for 'borderless' when Borderless flag is disabled.
  {
    base::test::ScopedFeatureList fe
"""


```
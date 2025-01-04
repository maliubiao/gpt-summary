Response:
The user wants to understand the functionality of the provided C++ code snippet, which is a test file for the HTML preload scanner in the Chromium Blink engine.

Here's a breakdown of the thought process to answer the request:

1. **Identify the Core Purpose:** The file name `html_preload_scanner_test.cc` immediately suggests this is a testing file for the `HTMLPreloadScanner`.

2. **Understand the Testing Framework:** The code uses `TEST_F`, `TEST_P`, `INSTANTIATE_TEST_SUITE_P`, and `::testing::*` which are part of the Google Test framework. This indicates the file contains unit tests.

3. **Analyze Test Case Structures:**  Notice the use of structures like `PreloadScannerTestCase`, `LazyLoadImageTestCase`, `TokenStreamMatcherTestCase`, and `SharedStorageWritableTestCase`. These structures define the input and expected output for different test scenarios.

4. **Examine Individual Tests:**  Go through each `TEST_F` and `TEST_P` to understand what specific functionality they are testing. Look for patterns in the input HTML and the expected preloaded resources.

5. **Connect to HTML, CSS, and JavaScript Concepts:**  Relate the tested scenarios to web development concepts. For example:
    * `<link rel="preload">`: Directly related to HTML preloading.
    * `<script src="...">`:  JavaScript loading.
    * `<link rel="stylesheet">`: CSS loading.
    * `<img>`: Image loading and the `loading` attribute for lazy loading.
    * `<meta http-equiv='Content-Security-Policy'>`:  Impacts preloading behavior.
    * `@import url(...)`: CSS import statements.
    * `<template>`: HTML template elements and their impact on preloading.
    * `<base href="...">`: Base URL influence on resource loading.
    * `sharedstoragewritable`: A specific attribute related to the Shared Storage API.

6. **Identify Logic and Assumptions:**  Pay attention to tests that involve conditional logic, such as the `MetaCspNoPreloadsAfterTest` which depends on a boolean parameter. The assumptions are generally that the `HTMLPreloadScanner` should correctly identify preloads based on the HTML structure.

7. **Recognize Potential User/Programming Errors:** Consider how a developer might misuse or misunderstand the features being tested. For example,  incorrectly placing preloads after a CSP meta tag or using a JavaScript URL in the `<base>` tag.

8. **Synthesize and Summarize:** Based on the analysis of individual tests, create a summary of the file's overall purpose and the specific functionalities it covers.

9. **Provide Concrete Examples:** For each category (HTML, CSS, JavaScript), give specific code examples from the test file and explain how they relate to the functionality.

10. **Formulate Hypotheses and Outcomes:** For tests involving logic, construct hypothetical inputs and predict the expected output based on the test's purpose.

11. **Illustrate Common Errors:**  Provide examples of how developers could make mistakes related to the tested features.

12. **Address the "Part 3" Requirement:**  Since this is the final part of a series, provide a concise summary of the overall functionality covered in this specific file, building upon the understanding gained from the previous parts (though those weren't provided here, the concept of incremental understanding remains).
这是 `blink/renderer/core/html/parser/html_preload_scanner_test.cc` 文件的第三部分，延续了之前的功能，主要用于测试 Blink 渲染引擎中 `HTMLPreloadScanner` 的功能。 `HTMLPreloadScanner` 的主要任务是在 HTML 解析过程中，提前扫描文档内容，识别出可以预加载的资源（如脚本、样式表、图片等），从而优化页面加载速度。

**本部分主要的功能归纳如下:**

* **测试在动态插入的 CSP meta 标签后的预加载行为:** 验证在通过 JavaScript 动态插入 Content Security Policy (CSP) meta 标签后，之前的预加载声明是否会被正确处理或忽略，以符合 CSP 的安全策略。
* **测试图片的懒加载属性 (`loading`) 对预加载的影响:**  验证当 `<img>` 标签设置 `loading='lazy'` 时，预加载扫描器是否会跳过该图片的预加载，从而优化初始加载性能。
* **测试 CSS `@import` 规则中包含分号的 URL 的解析:** 确保预加载扫描器能够正确解析 CSS 中 `@import` 规则中带有分号的 URL，避免因 URL 解析错误而导致资源无法预加载。
* **测试 `<template>` 元素对预加载的影响:** 验证预加载扫描器是否会忽略 `<template>` 标签内部的资源，因为 `<template>` 内部的内容在模板实例化之前不会被渲染。
* **测试 `<base>` 标签的 `href` 属性为 `javascript:` 的情况:** 验证当 `<base>` 标签的 `href` 属性设置为 `javascript:` 时，预加载扫描器是否能正确处理后续资源的 URL 解析，避免出现安全问题。
* **测试 CSS `@import` 规则前的其他 CSS 规则:**  验证预加载扫描器在遇到 `@charset` 或 `@layer` 等 CSS 规则后，仍然能正确解析和预加载后续的 `@import` 规则。
* **测试 CSS 分层 `@import` 规则 (`@import ... layer`) 的预加载:**  验证预加载扫描器是否能够正确识别和预加载 CSS 的分层导入。
* **测试 TokenStreamMatcher 功能:**  验证可以使用 `TokenStreamMatcher` 来定位特定的 HTML 元素，并基于这些元素来触发或验证预加载行为。这通常用于更精细的预加载控制或测试。
* **测试 Shared Storage API 的 `sharedstoragewritable` 属性:** 验证带有 `sharedstoragewritable` 属性的 `<img>` 标签在安全上下文下是否会被识别为可写入 Shared Storage 的资源。
* **测试 LCP (Largest Contentful Paint) 相关的懒加载图片预加载:** 引入了特性标志 `kLCPPLazyLoadImagePreload` 来测试不同策略下对 LCP 元素中的懒加载图片进行预加载的行为。这包括原生懒加载 (`loading='lazy'`) 和自定义懒加载 (例如使用 `data-src` 属性)。
* **测试禁用预加载扫描的情况:** 验证当显式禁用预加载扫描时，扫描器是否真的不会触发任何资源的预加载。

**与 JavaScript, HTML, CSS 的功能关系以及举例说明:**

* **HTML:**
    * **`<link rel="preload">`:**  测试文件直接使用了 `<link rel="preload" ...>` 标签来声明需要预加载的资源。例如：
        ```html
        "<link rel=preload href=bla as=SCRIPT>"
        ```
        这部分测试验证了扫描器能否正确识别并处理这些预加载声明。
    * **`<script src="...">`:**  测试了 JavaScript 脚本的预加载。例如：
        ```html
        "<script src='test.js'></script>"
        ```
    * **`<link rel="stylesheet" href="...">`:** 测试了 CSS 样式表的预加载。例如：
        ```html
        "<link rel='stylesheet' href='sheet.css' type='text/css'>"
        ```
    * **`<img>` 标签和 `loading` 属性:** 测试了 `loading='lazy'` 属性对图片预加载的影响。例如：
        ```html
        "<img src='foo.jpg' loading='lazy'>"
        ```
    * **`<meta http-equiv='Content-Security-Policy'>`:** 测试了 CSP 对预加载的影响。例如：
        ```html
        "<meta http-equiv='Content-Security-Policy'>"
        ```
    * **`<template>`:** 测试了模板元素内部资源的预加载行为。例如：
        ```html
        "<template><img src='bla.gif'></template>"
        ```
    * **`<base href="...">`:** 测试了 `<base>` 标签对资源 URL 解析的影响。例如：
        ```html
        "<base href='http://example.test/'><link rel=preload href=bla as=SCRIPT>"
        ```
    * **`sharedstoragewritable` 属性:** 测试了该属性对图片资源是否允许写入 Shared Storage 的影响。例如：
        ```html
        "<img src='/image' sharedstoragewritable>"
        ```

* **CSS:**
    * **`@import url(...)`:** 测试了 CSS `@import` 规则的预加载，包括带有分号的 URL 和分层导入的情况。例如：
        ```css
        @import url("https://example2.test/css?foo=a;b&bar=d");
        @import url("https://example2.test/lib.css") layer;
        ```
    * **`@charset` 和 `@layer`:** 测试了这些规则对后续 `@import` 规则预加载的影响。

* **JavaScript:** 虽然这个测试文件主要是测试 HTML 解析和预加载，但它间接地与 JavaScript 有关，例如：
    * **动态插入 CSP meta 标签:**  模拟了 JavaScript 操作 DOM 来改变页面行为的情况。
    * **`<script src="...">` 标签:**  直接测试了 JavaScript 文件的预加载。
    * **`<base href='javascript:'>`:** 涉及到 JavaScript URL 的解析和潜在的安全风险。

**逻辑推理的假设输入与输出:**

* **假设输入 (针对 `MetaCspNoPreloadsAfterTest`):**
    * **情况 1:**  HTML 包含一个预加载声明，然后通过 JavaScript 动态插入一个 CSP meta 标签。
    * **情况 2:**  HTML 包含一个预加载声明，然后通过 JavaScript 动态插入一个 CSP meta 标签，之后又有其他的 HTML 内容。
* **预期输出 (针对 `MetaCspNoPreloadsAfterTest`):**
    * 如果 CSP 策略阻止预加载，则在 CSP 标签插入后，之前的预加载声明应该被忽略，不会触发资源的预加载。反之，如果 CSP 允许预加载，则应该触发。测试用例通过 `ExpectPreloads()` 来控制预期结果。

* **假设输入 (针对 `LazyLoadImage`):**
    * HTML 包含一个 `<img>` 标签，其 `loading` 属性设置为 `lazy`。
* **预期输出 (针对 `LazyLoadImage`):**
    * 预加载扫描器应该识别出该图片是懒加载的，因此不会立即触发预加载。

**用户或编程常见的使用错误举例说明:**

* **在 CSP 限制下尝试预加载资源:** 用户可能在设置了严格 CSP 的页面中使用了 `<link rel="preload">`，但 CSP 策略阻止了该资源的加载。测试用例 `MetaCspNoPreloadsAfterTest` 模拟了这种情况。
* **错误地假设 `<template>` 内部的资源会被立即预加载:** 开发者可能在 `<template>` 标签内部声明了需要预加载的资源，但由于 `<template>` 的特性，这些资源不会在模板实例化之前被预加载。测试用例 `TemplateInteractions` 验证了这一点。
* **在 CSS 中使用不合法的 `@import` 语法:**  虽然测试用例关注的是 URL 中包含分号的情况，但用户可能在 `@import` 语句中犯其他语法错误，导致预加载失败。
* **错误地使用 `javascript:` 作为 `<base>` 标签的 `href`:** 开发者可能会错误地将 `<base href>` 设置为 `javascript:`，这可能导致后续的 URL 解析出现问题，甚至引发安全漏洞。测试用例 `JavascriptBaseUrl` 检查了扫描器对此类情况的处理。
* **忘记考虑懒加载对预加载的影响:** 开发者可能在使用了懒加载的图片上添加了预加载提示，但预加载扫描器应该能够识别出懒加载属性并避免重复加载。

**总结本部分功能:**

这部分测试主要关注 `HTMLPreloadScanner` 在处理特定 HTML 结构和属性时的行为，特别是涉及到 CSP、懒加载、`<template>` 元素、`<base>` 标签以及 CSS `@import` 规则的场景。目标是确保预加载扫描器能够准确地识别可预加载的资源，并遵循相关的标准和安全策略，从而优化页面加载性能并避免潜在的问题。此外，还测试了在特定条件下禁用预加载扫描的能力，以及与 Shared Storage API 的集成。最后，引入了对 LCP 元素中懒加载图片进行预加载的测试，以进一步提升关键渲染路径的性能。

Prompt: 
```
这是目录为blink/renderer/core/html/parser/html_preload_scanner_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
g=>"},
  };

  for (const auto& test_case : test_cases)
    Test(test_case);
}

class MetaCspNoPreloadsAfterTest : public HTMLPreloadScannerTest,
                                   public ::testing::WithParamInterface<bool> {
 public:
  MetaCspNoPreloadsAfterTest() : scopedAllow(GetParam()) {}

  bool ExpectPreloads() const { return GetParam(); }

 private:
  blink::RuntimeEnabledFeaturesTestHelpers::ScopedAllowPreloadingWithCSPMetaTag
      scopedAllow;
};

INSTANTIATE_TEST_SUITE_P(MetaCspNoPreloadsAfterTests,
                         MetaCspNoPreloadsAfterTest,
                         testing::Bool());

// Regression test for http://crbug.com/898795 where preloads after a
// dynamically inserted meta csp tag are dispatched on subsequent calls to the
// HTMLPreloadScanner, after they had been parsed.
TEST_P(MetaCspNoPreloadsAfterTest, NoPreloadsAfter) {
  PreloadScannerTestCase test_cases[] = {
      {"http://example.test",
       "<meta http-equiv='Content-Security-Policy'><link rel=preload href=bla "
       "as=SCRIPT>",
       ExpectPreloads() ? "bla" : nullptr, "http://example.test/",
       ResourceType::kScript, 0},
      // The buffered text referring to the preload above should be
      // cleared, so make sure it is not preloaded on subsequent calls to
      // Scan.
      {"http://example.test", "", nullptr, "http://example.test/",
       ResourceType::kScript, 0},
  };

  for (const auto& test_case : test_cases) {
    Test(test_case);
  }
}

TEST_F(HTMLPreloadScannerTest, LazyLoadImage) {
  RunSetUp(kViewportEnabled);
  LazyLoadImageTestCase test_cases[] = {
      {"<img src='foo.jpg' loading='auto'>", true},
      {"<img src='foo.jpg' loading='lazy'>", false},
      {"<img src='foo.jpg' loading='eager'>", true},
  };
  for (const auto& test_case : test_cases)
    Test(test_case);
}

// https://crbug.com/1087854
TEST_F(HTMLPreloadScannerTest, CSSImportWithSemicolonInUrl) {
  PreloadScannerTestCase test_cases[] = {
      {"https://example.test",
       "<style>@import "
       "url(\"https://example2.test/css?foo=a;b&bar=d\");</style>",
       "https://example2.test/css?foo=a;b&bar=d", "https://example.test/",
       ResourceType::kCSSStyleSheet, 0},
      {"https://example.test",
       "<style>@import "
       "url('https://example2.test/css?foo=a;b&bar=d');</style>",
       "https://example2.test/css?foo=a;b&bar=d", "https://example.test/",
       ResourceType::kCSSStyleSheet, 0},
      {"https://example.test",
       "<style>@import "
       "url(https://example2.test/css?foo=a;b&bar=d);</style>",
       "https://example2.test/css?foo=a;b&bar=d", "https://example.test/",
       ResourceType::kCSSStyleSheet, 0},
      {"https://example.test",
       "<style>@import \"https://example2.test/css?foo=a;b&bar=d\";</style>",
       "https://example2.test/css?foo=a;b&bar=d", "https://example.test/",
       ResourceType::kCSSStyleSheet, 0},
      {"https://example.test",
       "<style>@import 'https://example2.test/css?foo=a;b&bar=d';</style>",
       "https://example2.test/css?foo=a;b&bar=d", "https://example.test/",
       ResourceType::kCSSStyleSheet, 0},
  };

  for (const auto& test : test_cases)
    Test(test);
}

// https://crbug.com/1181291
TEST_F(HTMLPreloadScannerTest, TemplateInteractions) {
  PreloadScannerTestCase test_cases[] = {
      {"http://example.test", "<template><img src='bla.gif'></template>",
       nullptr, "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test",
       "<template><template><img src='bla.gif'></template></template>", nullptr,
       "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test",
       "<template><template></template><img src='bla.gif'></template>", nullptr,
       "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test",
       "<template><template></template><script "
       "src='test.js'></script></template>",
       nullptr, "http://example.test/", ResourceType::kScript, 0},
      {"http://example.test",
       "<template><template></template><link rel=preload as=fetch "
       "href=bla></template>",
       nullptr, "http://example.test/", ResourceType::kRaw, 0},
      {"http://example.test",
       "<template><template></template><link rel='stylesheet' href='sheet.css' "
       "type='text/css'></template>",
       nullptr, "http://example.test/", ResourceType::kCSSStyleSheet, 0},
  };
  for (const auto& test : test_cases)
    Test(test);
}

// Regression test for https://crbug.com/1181291
TEST_F(HTMLPreloadScannerTest, JavascriptBaseUrl) {
  PreloadScannerTestCase test_cases[] = {
      {"",
       "<base href='javascript:'><base href='javascript:notallowed'><base "
       "href='http://example.test/'><link rel=preload href=bla as=SCRIPT>",
       "bla", "http://example.test/", ResourceType::kScript, 0},
  };

  for (const auto& test_case : test_cases)
    Test(test_case);
}

TEST_F(HTMLPreloadScannerTest, OtherRulesBeforeImport) {
  PreloadScannerTestCase test_cases[] = {
      {"https://example.test",
       R"HTML(
       <style>
         @charset "utf-8";
         @import url("https://example2.test/lib.css");
       </style>
       )HTML",
       "https://example2.test/lib.css", "https://example.test/",
       ResourceType::kCSSStyleSheet, 0},
      {"https://example.test",
       R"HTML(
       <style>
         @layer foo, bar;
         @import url("https://example2.test/lib.css");
       </style>
       )HTML",
       "https://example2.test/lib.css", "https://example.test/",
       ResourceType::kCSSStyleSheet, 0},
      {"https://example.test",
       R"HTML(
       <style>
         @charset "utf-8";
         @layer foo, bar;
         @import url("https://example2.test/lib.css");
       </style>
       )HTML",
       "https://example2.test/lib.css", "https://example.test/",
       ResourceType::kCSSStyleSheet, 0},
  };

  for (const auto& test : test_cases)
    Test(test);
}

TEST_F(HTMLPreloadScannerTest, PreloadLayeredImport) {
  PreloadScannerTestCase test_cases[] = {
      {"https://example.test",
       R"HTML(
       <style>
         @import url("https://example2.test/lib.css") layer
       </style>
       )HTML",
       "https://example2.test/lib.css", "https://example.test/",
       ResourceType::kCSSStyleSheet, 0},
      {"https://example.test",
       R"HTML(
        <style>
          @import url("https://example2.test/lib.css") layer;
        </style>
        )HTML",
       "https://example2.test/lib.css", "https://example.test/",
       ResourceType::kCSSStyleSheet, 0},
      {"https://example.test",
       R"HTML(
        <style>
          @import url("https://example2.test/lib.css") layer(foo)
        </style>
        )HTML",
       "https://example2.test/lib.css", "https://example.test/",
       ResourceType::kCSSStyleSheet, 0},
      {"https://example.test",
       R"HTML(
        <style>
          @import url("https://example2.test/lib.css") layer(foo);
        </style>
        )HTML",
       "https://example2.test/lib.css", "https://example.test/",
       ResourceType::kCSSStyleSheet, 0},
      {"https://example.test",
       R"HTML(
       <style>
         @layer foo, bar;
         @import url("https://example2.test/lib.css") layer
       </style>
       )HTML",
       "https://example2.test/lib.css", "https://example.test/",
       ResourceType::kCSSStyleSheet, 0},
      {"https://example.test",
       R"HTML(
       <style>
         @layer foo, bar;
         @import url("https://example2.test/lib.css") layer;
       </style>
       )HTML",
       "https://example2.test/lib.css", "https://example.test/",
       ResourceType::kCSSStyleSheet, 0},
      {"https://example.test",
       R"HTML(
       <style>
         @layer foo, bar;
         @import url("https://example2.test/lib.css") layer(foo)
       </style>
       )HTML",
       "https://example2.test/lib.css", "https://example.test/",
       ResourceType::kCSSStyleSheet, 0},
      {"https://example.test",
       R"HTML(
       <style>
         @layer foo, bar;
         @import url("https://example2.test/lib.css") layer(foo);
       </style>
       )HTML",
       "https://example2.test/lib.css", "https://example.test/",
       ResourceType::kCSSStyleSheet, 0},
      {"https://example.test",
       R"HTML(
        <style>
          @import url("https://example2.test/lib.css") layer foo;
        </style>
        )HTML",
       nullptr},
      {"https://example.test",
       R"HTML(
        <style>
          @import url("https://example2.test/lib.css") layer(foo) bar;
        </style>
        )HTML",
       nullptr},
      {"https://example.test",
       R"HTML(
        <style>
          @import url("https://example2.test/lib.css") layer();
        </style>
        )HTML",
       nullptr},
  };

  for (const auto& test : test_cases)
    Test(test);
}

TEST_F(HTMLPreloadScannerTest, TokenStreamMatcher) {
  ElementLocator locator;
  auto* c = locator.add_components()->mutable_id();
  c->set_id_attr("target");

  TokenStreamMatcherTestCase test_case = {locator,
                                          R"HTML(
    <div>
      <img src="not-interesting.jpg">
      <img src="super-interesting.jpg" id="target">
      <img src="not-interesting2.jpg">
    </div>
    )HTML",
                                          "super-interesting.jpg", true};
  Test(test_case);
}

TEST_F(HTMLPreloadScannerTest, testSharedStorageWritable) {
  WebRuntimeFeaturesBase::EnableSharedStorageAPI(true);
  WebRuntimeFeaturesBase::EnableSharedStorageAPIM118(true);
  static constexpr bool kSecureDocumentUrl = true;
  static constexpr bool kInsecureDocumentUrl = false;

  static constexpr char kSecureBaseURL[] = "https://example.test";
  static constexpr char kInsecureBaseURL[] = "http://example.test";

  SharedStorageWritableTestCase test_cases[] = {
      // Insecure context
      {kInsecureDocumentUrl, kSecureBaseURL,
       "<img src='/image' sharedstoragewritable>",
       /*expected_shared_storage_writable_opted_in=*/false},
      // No sharedstoragewritable attribute
      {kSecureDocumentUrl, kSecureBaseURL, "<img src='/image'>",
       /*expected_shared_storage_writable_opted_in=*/false},
      // Irrelevant element type
      {kSecureDocumentUrl, kSecureBaseURL,
       "<video poster='/image' sharedstoragewritable>",
       /*expected_shared_storage_writable_opted_in=*/false},
      // Secure context, sharedstoragewritable attribute
      // Base (initial) URL does not affect SharedStorageWritable eligibility
      {kSecureDocumentUrl, kInsecureBaseURL,
       "<img src='/image' sharedstoragewritable>",
       /*expected_shared_storage_writable_opted_in=*/true},
      // Secure context, sharedstoragewritable attribute
      {kSecureDocumentUrl, kSecureBaseURL,
       "<img src='/image' sharedstoragewritable>",
       /*expected_shared_storage_writable_opted_in=*/true},
  };

  for (const auto& test_case : test_cases) {
    RunSetUp(kViewportDisabled, kPreloadEnabled,
             network::mojom::ReferrerPolicy::kDefault,
             /*use_secure_document_url=*/test_case.use_secure_document_url);
    Test(test_case);
  }
}

enum class LcppPreloadLazyLoadImageType {
  kNativeLazyLoad,
  kCustomLazyLoad,
  kAll,
};

class HTMLPreloadScannerLCPPLazyLoadImageTest
    : public HTMLPreloadScannerTest,
      public testing::WithParamInterface<LcppPreloadLazyLoadImageType> {
 public:
  HTMLPreloadScannerLCPPLazyLoadImageTest() {
    switch (GetParam()) {
      case LcppPreloadLazyLoadImageType::kNativeLazyLoad:
        scoped_feature_list_.InitAndEnableFeatureWithParameters(
            blink::features::kLCPPLazyLoadImagePreload,
            {{blink::features::kLCPCriticalPathPredictorPreloadLazyLoadImageType
                  .name,
              "native_lazy_loading"}});
        break;
      case LcppPreloadLazyLoadImageType::kCustomLazyLoad:
        scoped_feature_list_.InitAndEnableFeatureWithParameters(
            blink::features::kLCPPLazyLoadImagePreload,
            {{blink::features::kLCPCriticalPathPredictorPreloadLazyLoadImageType
                  .name,
              "custom_lazy_loading"}});
        break;
      case LcppPreloadLazyLoadImageType::kAll:
        scoped_feature_list_.InitAndEnableFeatureWithParameters(
            blink::features::kLCPPLazyLoadImagePreload,
            {{blink::features::kLCPCriticalPathPredictorPreloadLazyLoadImageType
                  .name,
              "all"}});
        break;
    }
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

INSTANTIATE_TEST_SUITE_P(
    All,
    HTMLPreloadScannerLCPPLazyLoadImageTest,
    ::testing::Values(LcppPreloadLazyLoadImageType::kNativeLazyLoad,
                      LcppPreloadLazyLoadImageType::kCustomLazyLoad,
                      LcppPreloadLazyLoadImageType::kAll));

TEST_P(HTMLPreloadScannerLCPPLazyLoadImageTest,
       TokenStreamMatcherWithLoadingLazy) {
  ElementLocator locator;
  auto* c = locator.add_components()->mutable_id();
  c->set_id_attr("target");

  switch (GetParam()) {
    case LcppPreloadLazyLoadImageType::kNativeLazyLoad:
      CachedDocumentParameters::SetLcppPreloadLazyLoadImageTypeForTesting(
          features::LcppPreloadLazyLoadImageType::kNativeLazyLoading);
      Test(TokenStreamMatcherTestCase{locator, R"HTML(
        <div>
          <img src="not-interesting.jpg">
          <img src="super-interesting.jpg" id="target" loading="lazy">
          <img src="not-interesting2.jpg">
        </div>
        )HTML",
                                      "super-interesting.jpg", true});
      break;
    case LcppPreloadLazyLoadImageType::kCustomLazyLoad:
      CachedDocumentParameters::SetLcppPreloadLazyLoadImageTypeForTesting(
          features::LcppPreloadLazyLoadImageType::kCustomLazyLoading);
      Test(TokenStreamMatcherTestCase{locator, R"HTML(
        <div>
          <img src="not-interesting.jpg">
          <img data-src="super-interesting.jpg" id="target">
          <img src="not-interesting2.jpg">
        </div>
        )HTML",
                                      "super-interesting.jpg", true});
      break;
    case LcppPreloadLazyLoadImageType::kAll:
      CachedDocumentParameters::SetLcppPreloadLazyLoadImageTypeForTesting(
          features::LcppPreloadLazyLoadImageType::kAll);
      Test(TokenStreamMatcherTestCase{locator, R"HTML(
        <div>
          <img src="not-interesting.jpg">
          <img src="super-interesting.jpg" id="target" loading="lazy">
          <img src="not-interesting2.jpg">
        </div>
        )HTML",
                                      "super-interesting.jpg", true});
      Test(TokenStreamMatcherTestCase{locator, R"HTML(
        <div>
          <img src="not-interesting.jpg">
          <img data-src="super-interesting.jpg" id="target">
          <img src="not-interesting2.jpg">
        </div>
        )HTML",
                                      "super-interesting.jpg", true});
      break;
  }

  CachedDocumentParameters::SetLcppPreloadLazyLoadImageTypeForTesting(
      std::nullopt);
}

TEST_P(HTMLPreloadScannerLCPPLazyLoadImageTest,
       TokenStreamMatcherWithLoadingLazyAutoSizes) {
  ElementLocator locator;
  auto* c = locator.add_components()->mutable_id();
  c->set_id_attr("target");

  switch (GetParam()) {
    case LcppPreloadLazyLoadImageType::kNativeLazyLoad:
    case LcppPreloadLazyLoadImageType::kCustomLazyLoad:
    case LcppPreloadLazyLoadImageType::kAll:
      Test(TokenStreamMatcherTestCase{locator, R"HTML(
        <div>
          <img src="not-interesting.jpg">
          <img src="super-interesting.jpg" id="target" loading="lazy" sizes="auto">
          <img src="not-interesting2.jpg">
        </div>
        )HTML",
                                      nullptr, false});
      break;
  }
}

TEST_F(HTMLPreloadScannerTest, PreloadScanDisabled_NoPreloads) {
  PreloadScannerTestCase test_cases[] = {
      {"http://example.test", "<img src='bla.gif'>", /* preloaded_url=*/nullptr,
       "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test", "<script src='test.js'></script>",
       /* preloaded_url=*/nullptr, "http://example.test/",
       ResourceType::kScript, 0}};

  for (const auto& test_case : test_cases) {
    RunSetUp(kViewportDisabled, kPreloadEnabled,
             network::mojom::ReferrerPolicy::kDefault, true, {},
             /* disable_preload_scanning=*/true);
    Test(test_case);
  }
}

}  // namespace blink

"""


```
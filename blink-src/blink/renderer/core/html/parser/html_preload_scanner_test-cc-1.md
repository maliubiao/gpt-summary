Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of a test file for the HTML preload scanner in the Chromium Blink engine.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Functionality:** The filename `html_preload_scanner_test.cc` strongly suggests that this code is testing the `HTMLPreloadScanner`. The code contains numerous `TEST_F` calls within a `HTMLPreloadScannerTest` class, further confirming this. The tests involve feeding HTML snippets to the scanner and verifying its behavior.

2. **Analyze the Test Cases:**  The code defines several sets of test cases using arrays of structs (e.g., `PreloadScannerTestCase`, `RenderBlockingTestCase`). Each struct represents a specific scenario with an HTML input and expected outcomes. This indicates that the file's primary function is to systematically test different aspects of the preload scanner's functionality.

3. **Identify Key Features Being Tested:** By examining the names of the test functions and the structure of the test cases, I can identify the specific features being tested:
    * `testMetaAcceptCH`: Tests how the scanner handles the `accept-ch` meta tag for client hints.
    * `testMetaAcceptCHInsecureDocument`: Specifically tests the behavior of `accept-ch` in insecure contexts.
    * `testRenderBlocking`: Checks how the scanner identifies render-blocking resources.
    * `testPreconnect`: Tests the scanner's ability to identify preconnect hints.
    * `testDisables`:  Likely tests scenarios where preloading is disabled.
    * `testPicture`: Tests how the scanner handles `<picture>` elements and their sources.
    * `testContext`:  Potentially tests the context in which resources are found.
    * `testReferrerPolicy`: Tests how the scanner handles `referrerpolicy` attributes and meta tags.
    * `testCors`: Tests how the scanner determines CORS settings for resources.
    * `testCSP`: Tests how Content Security Policy affects the scanner.
    * `testNonce`: Tests how the scanner handles `nonce` attributes for scripts and stylesheets.
    * `testAttributionSrc`: Tests the `attributionsrc` attribute for attribution reporting.
    * `testReferrerPolicyOnDocument`: Tests document-level referrer policies.
    * `testLinkRelPreload`: Tests the `<link rel="preload">` functionality.
    * `testNoDataUrls`: Ensures the scanner doesn't try to preload data URLs.
    * `testScriptTypeAndLanguage`: Tests how the scanner handles `type` and `language` attributes for scripts.
    * `testUppercaseAsValues`: Tests if the scanner correctly parses uppercase values for attributes like `as` in `<link rel="preload">`.
    * `ReferrerHeader`:  Tests how referrer headers are handled.
    * `Integrity`: Tests the `integrity` attribute for subresource integrity.

4. **Relate to Web Technologies:** The tested features directly relate to core web technologies:
    * **HTML:** The scanner parses HTML, identifies elements and attributes.
    * **JavaScript:** The tests cover `<script>` tags, module scripts, and their attributes.
    * **CSS:** The tests include `<link rel="stylesheet">` and how the scanner handles them.
    * **HTTP:** Concepts like CORS, referrer policy, and client hints are tested, reflecting HTTP behavior.

5. **Consider Logic and Examples:**  For each test category, I can infer the logic and potential examples:
    * **Client Hints:**  The scanner needs to parse the `accept-ch` meta tag and identify which client hints are requested. The output would be the specific hints that should be sent for subsequent requests.
    * **Render Blocking:** The scanner needs to determine if a resource will block page rendering. Inputs are different types of `<script>` and `<link>` tags, and the output is whether they are blocking, non-blocking, or potentially blocking.
    * **Preconnect:** The scanner looks for `<link rel="preconnect">` to initiate early connections. The output is the URL to preconnect to.
    * **`<picture>` element:** The scanner needs to choose the correct image source based on `srcset`, `sizes`, `media`, and `type` attributes. The output is the selected image URL.
    * **Referrer Policy:** The scanner needs to respect `referrerpolicy` attributes and meta tags. The output is the referrer policy that should be applied to the request.
    * **CORS:** The scanner determines the CORS mode based on the `crossorigin` attribute. The output is the CORS mode and credentials mode.
    * **CSP and Nonce:** The scanner checks for CSP meta tags and `nonce` attributes. The output is whether CSP is active and the nonce value.
    * **`<link rel="preload">`:** The scanner identifies resources to preload based on the `as` attribute. The output is the URL and resource type to preload.
    * **Subresource Integrity:** The scanner parses the `integrity` attribute. The output is the number of valid integrity metadata found.

6. **Identify Potential User Errors:**  Common mistakes developers might make when using these features are:
    * Incorrect `accept-ch` syntax.
    * Incorrect `referrerpolicy` values.
    * Mixing up `crossorigin` values.
    * Providing invalid `integrity` metadata.
    * Using incorrect `as` values in `<link rel="preload">`.
    * Incorrectly specifying script `type` or `language`.

7. **Structure the Summary:** Organize the findings into clear sections addressing the user's request: functionality, relationship to web technologies, logic and examples, and common user errors.

8. **Focus on Part 2:**  Since the prompt specifies this is part 2 of 3, and part 1 likely described the general purpose, the summary for part 2 should focus on the *specific* tests within this code snippet. The final summarization should tie together the individual test categories.

By following these steps, I can generate a comprehensive and accurate summary of the provided code snippet, addressing all aspects of the user's request.
这是`blink/renderer/core/html/parser/html_preload_scanner_test.cc`文件的第二部分，它延续了对HTML预加载扫描器功能的测试。 从这部分代码来看，主要的功能是测试`HTMLPreloadScanner`在解析HTML时，对以下特性的处理和识别能力：

**归纳一下这部分代码的功能：**

这部分代码主要测试了`HTMLPreloadScanner`对以下HTML特性的解析和预加载行为的正确性：

* **Meta Accept-CH 标签 (Client Hints):** 测试了扫描器如何解析 `<meta http-equiv='accept-ch'>` 标签，并提取其中指定的客户端提示（Client Hints），例如 `dpr` (设备像素比), `width` (资源宽度), `viewport-width` (视口宽度)。  它还测试了旧版本和新版本 (带有 `sec-ch-` 前缀) 的客户端提示的处理。  同时，还测试了在非安全上下文 (HTTP) 下，客户端提示是否会被正确忽略。
* **Render Blocking 行为:** 测试了扫描器如何判断资源是否会阻塞页面渲染，例如不同类型的 `<script>` 标签 (同步、异步、defer、module) 和 `<link rel="stylesheet">` 标签。
* **Preconnect:** 测试了扫描器如何识别 `<link rel="preconnect">` 标签，并提取需要预连接的 URL 和 `crossorigin` 属性。
* **预加载禁用场景:** 测试了在预加载功能被禁用的情况下，扫描器是否不会发起预加载请求。
* **`<picture>` 元素:** 测试了扫描器如何解析 `<picture>` 元素及其子元素 `<source>` 和 `<img>`，并根据 `srcset`, `sizes`, `media`, `type` 等属性选择合适的资源进行预加载。
* **上下文 (Context):** 测试了扫描器在不同 HTML 结构中识别资源的正确性，例如在 `<picture>` 元素内的 `<img>` 和独立的 `<img>` 标签。
* **Referrer Policy:** 测试了扫描器如何处理 `referrerpolicy` 属性和 `<meta name="referrer">` 标签，并确定预加载请求的 Referrer Policy。
* **CORS (跨域资源共享):** 测试了扫描器如何根据 `<script>` 标签的 `crossorigin` 属性来确定 CORS 请求模式 (No CORS, CORS) 和凭据模式 (Same-origin, Include)。
* **CSP (内容安全策略):** 测试了扫描器是否能识别 `<meta http-equiv="Content-Security-Policy">` 标签，但这部分测试更像是验证 CSP 存在与否，而不是具体的策略解析。
* **Nonce (一次性密码):** 测试了扫描器如何提取 `<script>` 和 `<link rel="stylesheet">` 标签的 `nonce` 属性。
* **Attribution Source (`attributionsrc`):** 测试了扫描器如何识别带有 `attributionsrc` 属性的 `<img>` 和 `<script>` 标签，这与归因报告 (Attribution Reporting) 功能相关。
* **文档级别的 Referrer Policy:** 测试了通过 HTTP 头部设置的文档级别 Referrer Policy 对预加载请求的影响，以及 `<meta name="referrer">` 标签的覆盖行为。
* **`<link rel="preload">`:**  测试了扫描器如何解析 `<link rel="preload">` 标签，并根据 `href`, `as`, `type`, `media` 等属性来确定需要预加载的资源类型和 URL。
* **Data URLs:** 测试了扫描器是否会忽略 data URLs，不进行预加载。
* **`<script>` 标签的 `type` 和 `language` 属性:** 测试了扫描器对 `<script>` 标签的 `type` 和 `language` 属性的处理，以确定是否需要预加载。
* **`<link rel="preload">` 标签 `as` 属性值的大小写:** 测试了扫描器是否能正确处理 `as` 属性值的大小写形式。
* **Referrer 头部:**  测试了在设置了特定的文档 Referrer Policy 后，预加载请求的 Referrer 头部是否符合预期。
* **完整性 (Integrity):** 测试了扫描器如何解析 `<script>` 标签的 `integrity` 属性，用于进行子资源完整性 (SRI) 校验。

**与 JavaScript, HTML, CSS 的功能关系举例说明:**

* **HTML:**  测试的核心是解析各种 HTML 标签和属性，例如 `<link>`, `<script>`, `<img>`, `<meta>`, `<picture>`, `<source>`. 例如，测试 `<img src='bla.gif'>` 就是测试扫描器能否识别 `<img>` 标签的 `src` 属性并提取 URL 进行预加载。
* **JavaScript:**  测试了 `<script>` 标签的不同类型 (`type='module'`, 没有 `type` 或 `type='text/javascript'`)，以及 `async`, `defer`, `nonce`, `integrity`, `crossorigin`, `attributionsrc` 等属性，这些属性直接影响 JavaScript 资源的加载和执行。例如，测试 `<script type='module' src='test.js'></script>` 就是测试扫描器能否识别模块脚本并进行预加载。
* **CSS:** 测试了 `<link rel='stylesheet'>` 标签，以及 `media`, `nonce` 等属性。例如，测试 `<link rel=preload href=bla as=style>` 就是测试扫描器能否识别需要预加载的 CSS 样式表。  `@import` 规则也间接与 CSS 相关。

**逻辑推理的假设输入与输出:**

**假设输入:**

```html
<meta http-equiv='accept-ch' content='dpr, width'>
<img srcset='small.jpg 320w, large.jpg 640w' sizes='(max-width: 600px) 100vw, 50vw'>
<script src="app.js"></script>
```

**输出 (预期的预加载行为):**

* 扫描器会解析 `<meta>` 标签，识别出需要发送 `dpr` 和 `width` 客户端提示。
* 扫描器会解析 `<img>` 标签，根据视口大小和 `sizes` 属性，选择 `small.jpg` 或 `large.jpg` 进行预加载，并可能携带 `width` 客户端提示。
* 扫描器会解析 `<script>` 标签，预加载 `app.js`。

**涉及用户或编程常见的使用错误举例说明:**

* **拼写错误或不合法的 `accept-ch` 值:** 用户可能将 `dpr` 拼写成 `drp`，导致客户端提示无法生效。例如：`<meta http-equiv='accept-ch' content='drp'>`。
* **错误的 `referrerpolicy` 值:** 用户可能使用了不被支持的 `referrerpolicy` 值，例如：`<img referrerpolicy='invalid-policy' src='image.jpg'>`，导致浏览器使用默认策略。
* **`<link rel="preload">` 的 `as` 属性值错误:** 用户可能将 `as="script"` 写成 `as="javascript"`，导致浏览器无法正确识别资源类型，预加载可能失败。
* **CORS 配置错误:**  当从不同的域加载资源时，如果服务器没有设置正确的 CORS 头部，即使使用了 `<script crossorigin>`，资源加载也可能失败。

总而言之，这部分代码是针对 `HTMLPreloadScanner` 的细致的功能测试，覆盖了多种 HTML 特性和属性，确保浏览器能够正确地识别和预加载资源，从而提升页面加载性能。

Prompt: 
```
这是目录为blink/renderer/core/html/parser/html_preload_scanner_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
dSend(
      network::mojom::WebClientHintsType::kDpr_DEPRECATED);
  dpr.SetShouldSend(network::mojom::WebClientHintsType::kDpr);
  all.SetShouldSend(network::mojom::WebClientHintsType::kDpr_DEPRECATED);
  all.SetShouldSend(network::mojom::WebClientHintsType::kDpr);
  resource_width_DEPRECATED.SetShouldSend(
      network::mojom::WebClientHintsType::kResourceWidth_DEPRECATED);
  resource_width.SetShouldSend(
      network::mojom::WebClientHintsType::kResourceWidth);
  all.SetShouldSend(
      network::mojom::WebClientHintsType::kResourceWidth_DEPRECATED);
  all.SetShouldSend(network::mojom::WebClientHintsType::kResourceWidth);
  viewport_width_DEPRECATED.SetShouldSend(
      network::mojom::WebClientHintsType::kViewportWidth_DEPRECATED);
  viewport_width.SetShouldSend(
      network::mojom::WebClientHintsType::kViewportWidth);
  all.SetShouldSend(
      network::mojom::WebClientHintsType::kViewportWidth_DEPRECATED);
  all.SetShouldSend(network::mojom::WebClientHintsType::kViewportWidth);
  PreloadScannerTestCase test_cases[] = {
      {"http://example.test",
       "<meta http-equiv='accept-ch' content='bla'><img srcset='bla.gif 320w, "
       "blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test",
       "<meta http-equiv='accept-ch' content='dprw'><img srcset='bla.gif 320w, "
       "blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test",
       "<meta http-equiv='accept-ch'><img srcset='bla.gif 320w, blabla.gif "
       "640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test",
       "<meta http-equiv='accept-ch' content='dpr  '><img srcset='bla.gif "
       "320w, blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 0,
       dpr_DEPRECATED},
      {"http://example.test",
       "<meta http-equiv='accept-ch' content='sec-ch-dpr  '><img "
       "srcset='bla.gif 320w, blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 0, dpr},
      {"http://example.test",
       "<meta http-equiv='accept-ch' content='bla,dpr  '><img srcset='bla.gif "
       "320w, blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 0,
       dpr_DEPRECATED},
      {"http://example.test",
       "<meta http-equiv='accept-ch' content='bla,sec-ch-dpr  '><img "
       "srcset='bla.gif 320w, blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 0, dpr},
      {"http://example.test",
       "<meta http-equiv='accept-ch' content='  width  '><img sizes='100vw' "
       "srcset='bla.gif 320w, blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 500,
       resource_width_DEPRECATED},
      {"http://example.test",
       "<meta http-equiv='accept-ch' content='  sec-ch-width  '><img "
       "sizes='100vw' srcset='bla.gif 320w, blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 500,
       resource_width},
      {"http://example.test",
       "<meta http-equiv='accept-ch' content='  width  , wutever'><img "
       "sizes='300px' srcset='bla.gif 320w, blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 300,
       resource_width_DEPRECATED},
      {"http://example.test",
       "<meta http-equiv='accept-ch' content='  sec-ch-width  , wutever'><img "
       "sizes='300px' srcset='bla.gif 320w, blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 300,
       resource_width},
      {"http://example.test",
       "<meta http-equiv='accept-ch' content='  viewport-width  '><img "
       "srcset='bla.gif 320w, blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 0,
       viewport_width_DEPRECATED},
      {"http://example.test",
       "<meta http-equiv='accept-ch' content='  sec-ch-viewport-width  '><img "
       "srcset='bla.gif 320w, blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 0,
       viewport_width},
      {"http://example.test",
       "<meta http-equiv='accept-ch' content='  viewport-width  , "
       "wutever'><img srcset='bla.gif 320w, blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 0,
       viewport_width_DEPRECATED},
      {"http://example.test",
       "<meta http-equiv='accept-ch' content='  sec-ch-viewport-width  , "
       "wutever'><img srcset='bla.gif 320w, blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 0,
       viewport_width},
      {"http://example.test",
       "<meta http-equiv='accept-ch' content='  viewport-width  ,width, "
       "wutever, dpr , sec-ch-dpr,sec-ch-viewport-width,   sec-ch-width '><img "
       "sizes='90vw' srcset='bla.gif 320w, blabla.gif 640w'>",
       "blabla.gif", "http://example.test/", ResourceType::kImage, 450, all},
  };

  for (const auto& test_case : test_cases) {
    RunSetUp(kViewportDisabled, kPreloadEnabled,
             network::mojom::ReferrerPolicy::kDefault,
             true /* use_secure_document_url */);
    Test(test_case);
  }
}

TEST_F(HTMLPreloadScannerTest, testMetaAcceptCHInsecureDocument) {
  ClientHintsPreferences all;
  all.SetShouldSend(network::mojom::WebClientHintsType::kDpr_DEPRECATED);
  all.SetShouldSend(network::mojom::WebClientHintsType::kDpr);
  all.SetShouldSend(
      network::mojom::WebClientHintsType::kResourceWidth_DEPRECATED);
  all.SetShouldSend(network::mojom::WebClientHintsType::kResourceWidth);
  all.SetShouldSend(
      network::mojom::WebClientHintsType::kViewportWidth_DEPRECATED);
  all.SetShouldSend(network::mojom::WebClientHintsType::kViewportWidth);

  const PreloadScannerTestCase expect_no_client_hint = {
      "http://example.test",
      "<meta http-equiv='accept-ch' content='  viewport-width  ,width, "
      "wutever, dpr  '><img sizes='90vw' srcset='bla.gif 320w, blabla.gif "
      "640w'>",
      "blabla.gif",
      "http://example.test/",
      ResourceType::kImage,
      450};

  const PreloadScannerTestCase expect_client_hint = {
      "http://example.test",
      "<meta http-equiv='accept-ch' content='  viewport-width  ,width, "
      "wutever, dpr,   sec-ch-viewport-width  ,sec-ch-width, wutever2, "
      "sec-ch-dpr  '><img sizes='90vw' srcset='bla.gif 320w, blabla.gif 640w'>",
      "blabla.gif",
      "http://example.test/",
      ResourceType::kImage,
      450,
      all};

  // For an insecure document, client hint should not be attached.
  RunSetUp(kViewportDisabled, kPreloadEnabled,
           network::mojom::ReferrerPolicy::kDefault,
           false /* use_secure_document_url */);
  Test(expect_no_client_hint);

  // For a secure document, client hint should be attached.
  RunSetUp(kViewportDisabled, kPreloadEnabled,
           network::mojom::ReferrerPolicy::kDefault,
           true /* use_secure_document_url */);
  Test(expect_client_hint);
}

TEST_F(HTMLPreloadScannerTest, testRenderBlocking) {
  RenderBlockingTestCase test_cases[] = {
      {"http://example.test", "<link rel=preload href='bla.gif' as=image>",
       RenderBlockingBehavior::kNonBlocking},
      {"http://example.test",
       "<script type='module' src='test.js' defer></script>",
       RenderBlockingBehavior::kNonBlocking},
      {"http://example.test",
       "<script type='module' src='test.js' async></script>",
       RenderBlockingBehavior::kPotentiallyBlocking},
      {"http://example.test",
       "<script type='module' src='test.js' defer blocking='render'></script>",
       RenderBlockingBehavior::kBlocking},
      {"http://example.test", "<script src='test.js'></script>",
       RenderBlockingBehavior::kBlocking},
      {"http://example.test", "<body><script src='test.js'></script></body>",
       RenderBlockingBehavior::kInBodyParserBlocking},
      {"http://example.test", "<script src='test.js' disabled></script>",
       RenderBlockingBehavior::kBlocking},
      {"http://example.test", "<link rel=stylesheet href=http://example2.test>",
       RenderBlockingBehavior::kBlocking},
      {"http://example.test",
       "<body><link rel=stylesheet href=http://example2.test></body>",
       RenderBlockingBehavior::kInBodyParserBlocking},
      {"http://example.test",
       "<link rel=stylesheet href=http://example2.test disabled>",
       RenderBlockingBehavior::kNonBlocking},
  };

  for (const auto& test_case : test_cases) {
    Test(test_case);
  }
}

TEST_F(HTMLPreloadScannerTest, testPreconnect) {
  HTMLPreconnectTestCase test_cases[] = {
      {"http://example.test", "<link rel=preconnect href=http://example2.test>",
       "http://example2.test", kCrossOriginAttributeNotSet},
      {"http://example.test",
       "<link rel=preconnect href=http://example2.test crossorigin=anonymous>",
       "http://example2.test", kCrossOriginAttributeAnonymous},
      {"http://example.test",
       "<link rel=preconnect href=http://example2.test "
       "crossorigin='use-credentials'>",
       "http://example2.test", kCrossOriginAttributeUseCredentials},
      {"http://example.test",
       "<link rel=preconnected href=http://example2.test "
       "crossorigin='use-credentials'>",
       nullptr, kCrossOriginAttributeNotSet},
      {"http://example.test",
       "<link rel=preconnect href=ws://example2.test "
       "crossorigin='use-credentials'>",
       nullptr, kCrossOriginAttributeNotSet},
  };

  for (const auto& test_case : test_cases)
    Test(test_case);
}

TEST_F(HTMLPreloadScannerTest, testDisables) {
  RunSetUp(kViewportEnabled, kPreloadDisabled);

  PreloadScannerTestCase test_cases[] = {
      {"http://example.test", "<img src='bla.gif'>"},
  };

  for (const auto& test_case : test_cases)
    Test(test_case);
}

TEST_F(HTMLPreloadScannerTest, testPicture) {
  PreloadScannerTestCase test_cases[] = {
      {"http://example.test",
       "<picture><source srcset='srcset_bla.gif'><img src='bla.gif'></picture>",
       "srcset_bla.gif", "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test",
       "<picture><source srcset='srcset_bla.gif' type=''><img "
       "src='bla.gif'></picture>",
       "srcset_bla.gif", "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test",
       "<picture><source sizes='50vw' srcset='srcset_bla.gif'><img "
       "src='bla.gif'></picture>",
       "srcset_bla.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<picture><source sizes='50vw' srcset='srcset_bla.gif'><img "
       "sizes='50vw' src='bla.gif'></picture>",
       "srcset_bla.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<picture><source srcset='srcset_bla.gif' sizes='50vw'><img "
       "sizes='50vw' src='bla.gif'></picture>",
       "srcset_bla.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<picture><source srcset='srcset_bla.gif'><img sizes='50vw' "
       "src='bla.gif'></picture>",
       "srcset_bla.gif", "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test",
       "<picture><source media='(max-width: 900px)' "
       "srcset='srcset_bla.gif'><img sizes='50vw' srcset='bla.gif "
       "500w'></picture>",
       "srcset_bla.gif", "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test",
       "<picture><source media='(max-width: 400px)' "
       "srcset='srcset_bla.gif'><img sizes='50vw' srcset='bla.gif "
       "500w'></picture>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<picture><source type='image/webp' srcset='srcset_bla.gif'><img "
       "sizes='50vw' srcset='bla.gif 500w'></picture>",
       "srcset_bla.gif", "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test",
       "<picture><source type='image/jp2' srcset='srcset_bla.gif'><img "
       "sizes='50vw' srcset='bla.gif 500w'></picture>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<picture><source media='(max-width: 900px)' type='image/jp2' "
       "srcset='srcset_bla.gif'><img sizes='50vw' srcset='bla.gif "
       "500w'></picture>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<picture><source type='image/webp' media='(max-width: 400px)' "
       "srcset='srcset_bla.gif'><img sizes='50vw' srcset='bla.gif "
       "500w'></picture>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<picture><source type='image/jp2' media='(max-width: 900px)' "
       "srcset='srcset_bla.gif'><img sizes='50vw' srcset='bla.gif "
       "500w'></picture>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 250},
      {"http://example.test",
       "<picture><source media='(max-width: 400px)' type='image/webp' "
       "srcset='srcset_bla.gif'><img sizes='50vw' srcset='bla.gif "
       "500w'></picture>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 250},
  };

  for (const auto& test_case : test_cases)
    Test(test_case);
}

TEST_F(HTMLPreloadScannerTest, testContext) {
  ContextTestCase test_cases[] = {
      {"http://example.test",
       "<picture><source srcset='srcset_bla.gif'><img src='bla.gif'></picture>",
       "srcset_bla.gif", true},
      {"http://example.test", "<img src='bla.gif'>", "bla.gif", false},
      {"http://example.test", "<img srcset='bla.gif'>", "bla.gif", true},
  };

  for (const auto& test_case : test_cases)
    Test(test_case);
}

TEST_F(HTMLPreloadScannerTest, testReferrerPolicy) {
  ReferrerPolicyTestCase test_cases[] = {
      {"http://example.test", "<img src='bla.gif'/>", "bla.gif",
       "http://example.test/", ResourceType::kImage, 0,
       network::mojom::ReferrerPolicy::kDefault},
      {"http://example.test", "<img referrerpolicy='origin' src='bla.gif'/>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 0,
       network::mojom::ReferrerPolicy::kOrigin, nullptr},
      {"http://example.test",
       "<meta name='referrer' content='not-a-valid-policy'><img "
       "src='bla.gif'/>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 0,
       network::mojom::ReferrerPolicy::kDefault, nullptr},
      {"http://example.test",
       "<img referrerpolicy='origin' referrerpolicy='origin-when-cross-origin' "
       "src='bla.gif'/>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 0,
       network::mojom::ReferrerPolicy::kOrigin, nullptr},
      {"http://example.test",
       "<img referrerpolicy='not-a-valid-policy' src='bla.gif'/>", "bla.gif",
       "http://example.test/", ResourceType::kImage, 0,
       network::mojom::ReferrerPolicy::kDefault, nullptr},
      {"http://example.test",
       "<link rel=preload as=image referrerpolicy='origin-when-cross-origin' "
       "href='bla.gif'/>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 0,
       network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin, nullptr},
      {"http://example.test",
       "<link rel=preload as=image referrerpolicy='same-origin' "
       "href='bla.gif'/>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 0,
       network::mojom::ReferrerPolicy::kSameOrigin, nullptr},
      {"http://example.test",
       "<link rel=preload as=image referrerpolicy='strict-origin' "
       "href='bla.gif'/>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 0,
       network::mojom::ReferrerPolicy::kStrictOrigin, nullptr},
      {"http://example.test",
       "<link rel=preload as=image "
       "referrerpolicy='strict-origin-when-cross-origin' "
       "href='bla.gif'/>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 0,
       network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin, nullptr},
      {"http://example.test",
       "<link rel='stylesheet' href='sheet.css' type='text/css'>", "sheet.css",
       "http://example.test/", ResourceType::kCSSStyleSheet, 0,
       network::mojom::ReferrerPolicy::kDefault, nullptr},
      {"http://example.test",
       "<link rel=preload as=image referrerpolicy='origin' "
       "referrerpolicy='origin-when-cross-origin' href='bla.gif'/>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 0,
       network::mojom::ReferrerPolicy::kOrigin, nullptr},
      {"http://example.test",
       "<meta name='referrer' content='no-referrer'><img "
       "referrerpolicy='origin' src='bla.gif'/>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 0,
       network::mojom::ReferrerPolicy::kOrigin, nullptr},
      // The scanner's state is not reset between test cases, so all subsequent
      // test cases have a document referrer policy of no-referrer.
      {"http://example.test",
       "<link rel=preload as=image referrerpolicy='not-a-valid-policy' "
       "href='bla.gif'/>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 0,
       network::mojom::ReferrerPolicy::kNever, nullptr},
      {"http://example.test",
       "<img referrerpolicy='not-a-valid-policy' src='bla.gif'/>", "bla.gif",
       "http://example.test/", ResourceType::kImage, 0,
       network::mojom::ReferrerPolicy::kNever, nullptr},
      {"http://example.test", "<img src='bla.gif'/>", "bla.gif",
       "http://example.test/", ResourceType::kImage, 0,
       network::mojom::ReferrerPolicy::kNever, nullptr}};

  for (const auto& test_case : test_cases)
    Test(test_case);
}

TEST_F(HTMLPreloadScannerTest, testCors) {
  CorsTestCase test_cases[] = {
      {"http://example.test", "<script src='/script'></script>",
       network::mojom::RequestMode::kNoCors,
       network::mojom::CredentialsMode::kInclude},
      {"http://example.test", "<script crossorigin src='/script'></script>",
       network::mojom::RequestMode::kCors,
       network::mojom::CredentialsMode::kSameOrigin},
      {"http://example.test",
       "<script crossorigin=use-credentials src='/script'></script>",
       network::mojom::RequestMode::kCors,
       network::mojom::CredentialsMode::kInclude},
      {"http://example.test", "<script type='module' src='/script'></script>",
       network::mojom::RequestMode::kCors,
       network::mojom::CredentialsMode::kSameOrigin},
      {"http://example.test",
       "<script type='module' crossorigin='anonymous' src='/script'></script>",
       network::mojom::RequestMode::kCors,
       network::mojom::CredentialsMode::kSameOrigin},
      {"http://example.test",
       "<script type='module' crossorigin='use-credentials' "
       "src='/script'></script>",
       network::mojom::RequestMode::kCors,
       network::mojom::CredentialsMode::kInclude},
  };

  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(test_case.input_html);
    Test(test_case);
  }
}

TEST_F(HTMLPreloadScannerTest, testCSP) {
  CSPTestCase test_cases[] = {
      {"http://example.test",
       "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src "
       "https:\">",
       true},
      {"http://example.test",
       "<meta name=\"viewport\" content=\"width=device-width\">", false},
      {"http://example.test", "<img src=\"example.gif\">", false}};

  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(test_case.input_html);
    Test(test_case);
  }
}

TEST_F(HTMLPreloadScannerTest, testNonce) {
  NonceTestCase test_cases[] = {
      {"http://example.test", "<script src='/script'></script>", ""},
      {"http://example.test", "<script src='/script' nonce=''></script>", ""},
      {"http://example.test", "<script src='/script' nonce='abc'></script>",
       "abc"},
      {"http://example.test", "<link rel='stylesheet' href='/style'>", ""},
      {"http://example.test", "<link rel='stylesheet' href='/style' nonce=''>",
       ""},
      {"http://example.test",
       "<link rel='stylesheet' href='/style' nonce='abc'>", "abc"},

      // <img> doesn't support nonces:
      {"http://example.test", "<img src='/image'>", ""},
      {"http://example.test", "<img src='/image' nonce=''>", ""},
      {"http://example.test", "<img src='/image' nonce='abc'>", ""},
  };

  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(test_case.input_html);
    Test(test_case);
  }
}

TEST_F(HTMLPreloadScannerTest, testAttributionSrc) {
  static constexpr bool kSecureDocumentUrl = true;
  static constexpr bool kInsecureDocumentUrl = false;

  static constexpr char kSecureBaseURL[] = "https://example.test";
  static constexpr char kInsecureBaseURL[] = "http://example.test";

  url_test_helpers::RegisterMockedURLLoad(
      url_test_helpers::ToKURL("https://example.test/script"), "");
  url_test_helpers::RegisterMockedURLLoad(
      url_test_helpers::ToKURL("http://example.test/script"), "");

  GetDocument().GetSettings()->SetScriptEnabled(true);

  AttributionSrcTestCase test_cases[] = {
      // Insecure context
      {kInsecureDocumentUrl, kSecureBaseURL,
       "<img src='/image' attributionsrc>",
       network::mojom::AttributionReportingEligibility::kUnset},
      {kInsecureDocumentUrl, kSecureBaseURL,
       "<script src='/script' attributionsrc></script>",
       network::mojom::AttributionReportingEligibility::kUnset},
      // No attributionsrc attribute
      {kSecureDocumentUrl, kSecureBaseURL, "<img src='/image'>",
       network::mojom::AttributionReportingEligibility::kUnset},
      {kSecureDocumentUrl, kSecureBaseURL, "<script src='/script'></script>",
       network::mojom::AttributionReportingEligibility::kUnset},
      // Irrelevant element type
      {kSecureDocumentUrl, kSecureBaseURL,
       "<video poster='/image' attributionsrc>",
       network::mojom::AttributionReportingEligibility::kUnset},
      // Not potentially trustworthy reporting origin
      {kSecureDocumentUrl, kInsecureBaseURL,
       "<img src='/image' attributionsrc>",
       network::mojom::AttributionReportingEligibility::kUnset},
      {kSecureDocumentUrl, kInsecureBaseURL,
       "<script src='/script' attributionsrc></script>",
       network::mojom::AttributionReportingEligibility::kUnset},
      // Secure context, potentially trustworthy reporting origin,
      // attributionsrc attribute
      {kSecureDocumentUrl, kSecureBaseURL, "<img src='/image' attributionsrc>",
       network::mojom::AttributionReportingEligibility::kEventSourceOrTrigger},
      {kSecureDocumentUrl, kSecureBaseURL,
       "<script src='/script' attributionsrc></script>",
       network::mojom::AttributionReportingEligibility::kEventSourceOrTrigger},
      {kSecureDocumentUrl, kSecureBaseURL, "<img src='/image' attributionsrc>",
       network::mojom::AttributionReportingEligibility::kEventSourceOrTrigger,
       network::mojom::AttributionSupport::kWebAndOs},
  };

  for (const auto& test_case : test_cases) {
    RunSetUp(kViewportDisabled, kPreloadEnabled,
             network::mojom::ReferrerPolicy::kDefault,
             /*use_secure_document_url=*/test_case.use_secure_document_url);
    Test(test_case);
  }
}

// Tests that a document-level referrer policy (e.g. one set by HTTP header) is
// applied for preload requests.
TEST_F(HTMLPreloadScannerTest, testReferrerPolicyOnDocument) {
  RunSetUp(kViewportEnabled, kPreloadEnabled,
           network::mojom::ReferrerPolicy::kOrigin);
  ReferrerPolicyTestCase test_cases[] = {
      {"http://example.test", "<img src='blah.gif'/>", "blah.gif",
       "http://example.test/", ResourceType::kImage, 0,
       network::mojom::ReferrerPolicy::kOrigin, nullptr},
      {"http://example.test", "<style>@import url('blah.css');</style>",
       "blah.css", "http://example.test/", ResourceType::kCSSStyleSheet, 0,
       network::mojom::ReferrerPolicy::kOrigin, nullptr},
      // Tests that a meta-delivered referrer policy with an unrecognized policy
      // value does not override the document's referrer policy.
      {"http://example.test",
       "<meta name='referrer' content='not-a-valid-policy'><img "
       "src='bla.gif'/>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 0,
       network::mojom::ReferrerPolicy::kOrigin, nullptr},
      // Tests that a meta-delivered referrer policy with a valid policy value
      // does override the document's referrer policy.
      {"http://example.test",
       "<meta name='referrer' content='unsafe-url'><img src='bla.gif'/>",
       "bla.gif", "http://example.test/", ResourceType::kImage, 0,
       network::mojom::ReferrerPolicy::kAlways, nullptr},
  };

  for (const auto& test_case : test_cases)
    Test(test_case);
}

TEST_F(HTMLPreloadScannerTest, testLinkRelPreload) {
  PreloadScannerTestCase test_cases[] = {
      {"http://example.test", "<link rel=preload as=fetch href=bla>", "bla",
       "http://example.test/", ResourceType::kRaw, 0},
      {"http://example.test", "<link rel=preload href=bla as=script>", "bla",
       "http://example.test/", ResourceType::kScript, 0},
      {"http://example.test",
       "<link rel=preload href=bla as=script type='script/foo'>", "bla",
       "http://example.test/", ResourceType::kScript, 0},
      {"http://example.test", "<link rel=preload href=bla as=style>", "bla",
       "http://example.test/", ResourceType::kCSSStyleSheet, 0},
      {"http://example.test",
       "<link rel=preload href=bla as=style type='text/css'>", "bla",
       "http://example.test/", ResourceType::kCSSStyleSheet, 0},
      {"http://example.test",
       "<link rel=preload href=bla as=style type='text/bla'>", nullptr,
       "http://example.test/", ResourceType::kCSSStyleSheet, 0},
      {"http://example.test", "<link rel=preload href=bla as=image>", "bla",
       "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test",
       "<link rel=preload href=bla as=image type='image/webp'>", "bla",
       "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test",
       "<link rel=preload href=bla as=image type='image/bla'>", nullptr,
       "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test", "<link rel=preload href=bla as=font>", "bla",
       "http://example.test/", ResourceType::kFont, 0},
      {"http://example.test",
       "<link rel=preload href=bla as=font type='font/woff2'>", "bla",
       "http://example.test/", ResourceType::kFont, 0},
      {"http://example.test",
       "<link rel=preload href=bla as=font type='font/bla'>", nullptr,
       "http://example.test/", ResourceType::kFont, 0},
      // Until the preload cache is defined in terms of range requests and media
      // fetches we can't reliably preload audio/video content and expect it to
      // be served from the cache correctly. Until
      // https://github.com/w3c/preload/issues/97 is resolved and implemented we
      // need to disable these preloads.
      {"http://example.test", "<link rel=preload href=bla as=video>", nullptr,
       "http://example.test/", ResourceType::kVideo, 0},
      {"http://example.test", "<link rel=preload href=bla as=track>", "bla",
       "http://example.test/", ResourceType::kTextTrack, 0},
      {"http://example.test",
       "<link rel=preload href=bla as=image media=\"(max-width: 800px)\">",
       "bla", "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test",
       "<link rel=preload href=bla as=image media=\"(max-width: 400px)\">",
       nullptr, "http://example.test/", ResourceType::kImage, 0},
      {"http://example.test", "<link rel=preload href=bla>", nullptr,
       "http://example.test/", ResourceType::kRaw, 0},
  };

  for (const auto& test_case : test_cases)
    Test(test_case);
}

TEST_F(HTMLPreloadScannerTest, testNoDataUrls) {
  PreloadScannerTestCase test_cases[] = {
      {"http://example.test",
       "<link rel=preload href='data:text/html,<p>data</data>'>", nullptr,
       "http://example.test/", ResourceType::kRaw, 0},
      {"http://example.test", "<img src='data:text/html,<p>data</data>'>",
       nullptr, "http://example.test/", ResourceType::kImage, 0},
      {"data:text/html,<a>anchor</a>", "<img src='#anchor'>", nullptr,
       "http://example.test/", ResourceType::kImage, 0},
  };

  for (const auto& test_case : test_cases)
    Test(test_case);
}

// The preload scanner should follow the same policy that the ScriptLoader does
// with regard to the type and language attribute.
TEST_F(HTMLPreloadScannerTest, testScriptTypeAndLanguage) {
  PreloadScannerTestCase test_cases[] = {
      // Allow empty src and language attributes.
      {"http://example.test", "<script src='test.js'></script>", "test.js",
       "http://example.test/", ResourceType::kScript, 0},
      {"http://example.test",
       "<script type='' language='' src='test.js'></script>", "test.js",
       "http://example.test/", ResourceType::kScript, 0},
      // Allow standard language and type attributes.
      {"http://example.test",
       "<script type='text/javascript' src='test.js'></script>", "test.js",
       "http://example.test/", ResourceType::kScript, 0},
      {"http://example.test",
       "<script type='text/javascript' language='javascript' "
       "src='test.js'></script>",
       "test.js", "http://example.test/", ResourceType::kScript, 0},
      // Allow legacy languages in the "language" attribute with an empty
      // type.
      {"http://example.test",
       "<script language='javascript1.1' src='test.js'></script>", "test.js",
       "http://example.test/", ResourceType::kScript, 0},
      // Do not allow legacy languages in the "type" attribute.
      {"http://example.test",
       "<script type='javascript' src='test.js'></script>", nullptr,
       "http://example.test/", ResourceType::kScript, 0},
      {"http://example.test",
       "<script type='javascript1.7' src='test.js'></script>", nullptr,
       "http://example.test/", ResourceType::kScript, 0},
      // Do not allow invalid types in the "type" attribute.
      {"http://example.test", "<script type='invalid' src='test.js'></script>",
       nullptr, "http://example.test/", ResourceType::kScript, 0},
      {"http://example.test", "<script type='asdf' src='test.js'></script>",
       nullptr, "http://example.test/", ResourceType::kScript, 0},
      // Do not allow invalid languages.
      {"http://example.test",
       "<script language='french' src='test.js'></script>", nullptr,
       "http://example.test/", ResourceType::kScript, 0},
      {"http://example.test",
       "<script language='python' src='test.js'></script>", nullptr,
       "http://example.test/", ResourceType::kScript, 0},
  };

  for (const auto& test_case : test_cases)
    Test(test_case);
}

// Regression test for crbug.com/664744.
TEST_F(HTMLPreloadScannerTest, testUppercaseAsValues) {
  PreloadScannerTestCase test_cases[] = {
      {"http://example.test", "<link rel=preload href=bla as=SCRIPT>", "bla",
       "http://example.test/", ResourceType::kScript, 0},
      {"http://example.test", "<link rel=preload href=bla as=fOnT>", "bla",
       "http://example.test/", ResourceType::kFont, 0},
  };

  for (const auto& test_case : test_cases)
    Test(test_case);
}

TEST_F(HTMLPreloadScannerTest, ReferrerHeader) {
  RunSetUp(kViewportEnabled, kPreloadEnabled,
           network::mojom::ReferrerPolicy::kAlways);

  KURL preload_url("http://example.test/sheet.css");
  // TODO(crbug.com/751425): We should use the mock functionality
  // via |PageTestBase::dummy_page_holder_|.
  url_test_helpers::RegisterMockedURLLoadWithCustomResponse(
      preload_url, "", WrappedResourceResponse(ResourceResponse()));

  ReferrerPolicyTestCase test_case = {
      "http://example.test",
      "<link rel='stylesheet' href='sheet.css' type='text/css'>",
      "sheet.css",
      "http://example.test/",
      ResourceType::kCSSStyleSheet,
      0,
      network::mojom::ReferrerPolicy::kAlways,
      "http://whatever.test/"};
  Test(test_case);
}

TEST_F(HTMLPreloadScannerTest, Integrity) {
  IntegrityTestCase test_cases[] = {
      {0, "<script src=bla.js>"},
      {1,
       "<script src=bla.js "
       "integrity=sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng=>"},
      {0, "<script src=bla.js integrity=sha257-XXX>"},
      {2,
       "<script src=bla.js "
       "integrity=sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng= "
       "sha256-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxng=>"},
      {1,
       "<script src=bla.js "
       "integrity=sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng= "
       "integrity=sha257-XXXX>"},
      {0,
       "<script src=bla.js integrity=sha257-XXX "
       "integrity=sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tn
"""


```
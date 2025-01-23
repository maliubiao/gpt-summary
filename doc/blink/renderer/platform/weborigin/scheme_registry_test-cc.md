Response:
Let's break down the thought process for analyzing the `scheme_registry_test.cc` file.

1. **Identify the Core Purpose:** The filename `scheme_registry_test.cc` immediately suggests its purpose: testing the functionality of a `SchemeRegistry` class. The presence of `testing/gtest/include/gtest/gtest.h` confirms this.

2. **Understand the Tested Class:**  The `#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"` line tells us exactly which class is being tested. The path `weborigin` suggests this class deals with the concept of web origins and URL schemes.

3. **Analyze the Test Structure:** The code uses Google Test (`TEST_F`). Each `TEST_F` defines a specific test case. The `SchemeRegistryTest` class provides a common setup (and teardown, although in this case it's mostly for `DCHECK`).

4. **Examine Individual Test Cases:**  Go through each `TEST_F` and try to understand what aspect of `SchemeRegistry` it's verifying. Look for the `EXPECT_TRUE` and `EXPECT_FALSE` calls, as these are the assertions that define the expected behavior.

    * **`NoCSPBypass`:** Tests the default state where a newly introduced scheme does *not* bypass Content Security Policy (CSP).
    * **`FullCSPBypass`:** Tests registering a scheme to *fully* bypass CSP. It checks both the general bypass and the bypass for a specific policy area (image).
    * **`PartialCSPBypass`:** Tests registering a scheme to bypass CSP for *specific* policy areas (image in this case) but not others (style).
    * **`BypassSecureContextCheck`:** Tests registering a scheme to bypass the requirement of a secure context (HTTPS).
    * **`WebUIScheme`:** Tests registering, unregistering, and checking if a scheme is considered a "WebUI" scheme (often used for internal browser pages).
    * **`ExtensionScheme`:** Tests similar registration, unregistration, and checking for "extension" schemes.
    * **`CodeCacheWithHashing`:** Tests the registration, unregistration, and checking of schemes that support code caching with hashing (an optimization).

5. **Connect to Web Concepts (JavaScript, HTML, CSS):**  Now, consider how the tested functionalities relate to core web technologies.

    * **CSP:**  Directly related to web security. If a scheme bypasses CSP, it means content loaded from that scheme is treated differently by the browser's security mechanisms. Think about `<script src="...">`, `<link rel="stylesheet" href="...">`, `<img>`. If a custom scheme bypasses CSP, it could potentially execute scripts or load resources that would normally be blocked.
    * **Secure Context:**  Relates to features like service workers, geolocation, etc., which are restricted to secure origins (HTTPS). Allowing a non-secure scheme to bypass this check can have security implications.
    * **WebUI/Extension Schemes:** These are internal browser concepts, but they influence how these types of URLs are handled (e.g., restrictions on what APIs they can access).
    * **Code Caching:** While less directly visible, it's an optimization that affects how quickly JavaScript and other resources load.

6. **Infer Logic and Input/Output:** For each test case, think about the underlying logic being tested. What is the *input* to the `SchemeRegistry` (registering a scheme), and what is the *output* (the result of the `ShouldBypass...` or `Is...Scheme` checks)?  This helps clarify the purpose of each test.

7. **Identify Potential User/Programming Errors:** Think about how a developer might misuse or misunderstand the `SchemeRegistry` and its implications.

    * Incorrectly assuming a scheme bypasses CSP when it doesn't.
    * Not understanding the security implications of bypassing secure context checks.
    * Confusing different types of scheme registrations (WebUI, extension, CSP bypass).
    * Forgetting to unregister schemes in testing or other scenarios, leading to unexpected behavior.

8. **Review and Refine:**  Read through the analysis and make sure it's clear, concise, and accurate. Ensure the examples are relevant and illustrative. For example, instead of just saying "CSP is about security," give concrete examples of HTML tags affected by it.

**Self-Correction Example during the Process:**

Initially, I might just say "CSP bypass means security is ignored."  But that's too simplistic. I need to refine it to be more accurate: "Bypassing CSP means the usual restrictions on loading resources and executing scripts from that origin are lifted. This can be useful for trusted internal resources but dangerous if misused."  This adds nuance and context. Similarly, just saying "WebUI is internal" is less helpful than explaining that it affects how these pages are treated by the browser.
这个文件 `blink/renderer/platform/weborigin/scheme_registry_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `SchemeRegistry` 类的功能。 `SchemeRegistry` 类负责管理和查询 URL 协议（scheme）的各种属性和行为，例如是否应该绕过内容安全策略 (CSP)，是否是 WebUI 方案，是否是扩展程序方案等。

**主要功能：**

1. **测试注册和查询 URL 协议的 CSP 绕过属性:**
   - 测试可以注册一个自定义协议，并设置其是否应该绕过 CSP。
   - 测试可以针对不同的策略区域（例如 `kPolicyAreaImage`）设置不同的 CSP 绕过属性。
   - 验证 `SchemeRegistry::SchemeShouldBypassContentSecurityPolicy()` 方法是否能正确返回协议的 CSP 绕过状态。

2. **测试注册和查询 URL 协议的 "绕过安全上下文检查" 属性:**
   - 测试可以注册一个自定义协议，使其可以绕过安全上下文检查（通常 HTTPS 页面才被认为是安全上下文）。
   - 验证 `SchemeRegistry::SchemeShouldBypassSecureContextCheck()` 方法是否能正确返回协议是否绕过安全上下文检查的状态。

3. **测试注册和查询 URL 协议是否是 WebUI 方案:**
   - 测试可以注册和移除一个协议作为 WebUI 方案。
   - 验证 `SchemeRegistry::IsWebUIScheme()` 方法是否能正确判断一个协议是否是 WebUI 方案。

4. **测试注册和查询 URL 协议是否是扩展程序方案:**
   - 测试可以注册和移除一个协议作为扩展程序方案。
   - 验证 `CommonSchemeRegistry::IsExtensionScheme()` 方法是否能正确判断一个协议是否是扩展程序方案。

5. **测试注册和查询 URL 协议是否支持带哈希的 Code Cache:**
   - 测试可以注册和移除一个协议，使其支持或不支持带哈希的 Code Cache。
   - 验证 `SchemeRegistry::SchemeSupportsCodeCacheWithHashing()` 方法是否能正确判断一个协议是否支持带哈希的 Code Cache。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`SchemeRegistry` 的功能直接影响着浏览器如何处理不同协议的资源，从而间接影响 JavaScript, HTML, CSS 的行为。

1. **内容安全策略 (CSP):**
   - **关系:** CSP 是一种安全机制，用于限制网页可以加载和执行的资源来源。`SchemeRegistry` 决定了某些协议是否可以绕过 CSP 的限制。
   - **举例:**
     - 假设注册了一个名为 `test-scheme` 的协议并设置为绕过 CSP。在 HTML 中，即使 CSP 策略非常严格，以下代码也可能被允许执行或加载：
       ```html
       <script src="test-scheme://some-script.js"></script>
       <img src="test-scheme://some-image.png">
       <link rel="stylesheet" href="test-scheme://some-styles.css">
       ```
     - 如果 `test-scheme` 没有被设置为绕过 CSP，那么 CSP 可能会阻止这些资源的加载，导致 JavaScript 无法执行，图片无法显示，CSS 样式无法应用。

2. **安全上下文:**
   - **关系:** 某些强大的 Web API（如 Service Workers, Geolocation）只能在安全上下文（通常是 HTTPS 页面）中运行。`SchemeRegistry` 可以允许某些非 HTTPS 协议绕过这个限制。
   - **举例:**
     - 假设注册了一个名为 `random-scheme` 的协议并设置为绕过安全上下文检查。即使一个页面是通过 `random-scheme://some-page` 加载的，它也可能能够使用 Service Workers API：
       ```javascript
       navigator.serviceWorker.register('sw.js');
       ```
     - 如果 `random-scheme` 没有被设置为绕过安全上下文检查，那么尝试在这样的页面中使用 Service Workers API 将会失败。

3. **WebUI 方案:**
   - **关系:** WebUI 方案通常用于浏览器内部的页面，例如设置页面、历史记录页面等。浏览器可能会对 WebUI 方案的页面有特殊的处理。
   - **举例:** 以 `chrome://settings` 为例，`chrome://` 就是一个 WebUI 方案。浏览器知道这是一个内部页面，可能会赋予它一些特殊的权限或限制。虽然 JavaScript, HTML, CSS 在这些页面中仍然使用，但其行为可能受到 WebUI 特性的影响。例如，某些安全限制可能被放宽，或者可以访问一些特殊的 Chrome 扩展 API。

4. **扩展程序方案:**
   - **关系:** 扩展程序通常使用特定的协议（如 `chrome-extension://`）来加载资源。`SchemeRegistry` 用于标识这些协议。
   - **举例:**  一个 Chrome 扩展程序的 manifest 文件中可能会声明一些 HTML 页面或 JavaScript 文件，这些文件通过 `chrome-extension://<extension-id>/...` 的 URL 引用。浏览器通过 `SchemeRegistry` 识别出 `chrome-extension://` 是扩展程序的协议，并据此处理这些资源的加载和权限。

5. **Code Cache with Hashing:**
   - **关系:**  这是一种优化技术，浏览器可以缓存 JavaScript 代码的编译结果，以提高页面加载速度。带哈希的 Code Cache 可以更精确地匹配缓存，即使 URL 中包含哈希值。
   - **举例:** 如果一个协议被注册为支持带哈希的 Code Cache，那么当加载具有相同主 URL 但哈希不同的 JavaScript 文件时，浏览器可能会更有效地利用缓存，或者能够为不同的哈希值存储不同的缓存。这可以提高 JavaScript 的加载和执行效率。

**逻辑推理和假设输入输出:**

以下是一些基于代码的逻辑推理和假设的输入输出示例：

**测试用例: `FullCSPBypass`**

* **假设输入:** 调用 `SchemeRegistry::RegisterURLSchemeAsBypassingContentSecurityPolicy("test-scheme")`。
* **预期输出:**
    * `SchemeRegistry::SchemeShouldBypassContentSecurityPolicy("test-scheme")` 返回 `true`。
    * `SchemeRegistry::SchemeShouldBypassContentSecurityPolicy("test-scheme", SchemeRegistry::kPolicyAreaImage)` 返回 `true`。
    * `SchemeRegistry::SchemeShouldBypassContentSecurityPolicy("test-scheme-2")` 返回 `false`。
    * `SchemeRegistry::SchemeShouldBypassContentSecurityPolicy("test-scheme-2", SchemeRegistry::kPolicyAreaImage)` 返回 `false`。

**测试用例: `PartialCSPBypass`**

* **假设输入:** 调用 `SchemeRegistry::RegisterURLSchemeAsBypassingContentSecurityPolicy("test-scheme", SchemeRegistry::kPolicyAreaImage)`。
* **预期输出:**
    * `SchemeRegistry::SchemeShouldBypassContentSecurityPolicy("test-scheme")` 返回 `false`。
    * `SchemeRegistry::SchemeShouldBypassContentSecurityPolicy("test-scheme", SchemeRegistry::kPolicyAreaImage)` 返回 `true`。
    * `SchemeRegistry::SchemeShouldBypassContentSecurityPolicy("test-scheme", SchemeRegistry::kPolicyAreaStyle)` 返回 `false`。
    * `SchemeRegistry::SchemeShouldBypassContentSecurityPolicy("test-scheme-2", SchemeRegistry::kPolicyAreaImage)` 返回 `false`。

**测试用例: `WebUIScheme`**

* **假设输入序列:**
    1. 调用 `SchemeRegistry::RegisterURLSchemeAsWebUI("test-scheme")`。
    2. 调用 `SchemeRegistry::RegisterURLSchemeAsWebUI("chrome")`。
    3. 调用 `SchemeRegistry::RemoveURLSchemeAsWebUI("test-scheme")`。
    4. 调用 `SchemeRegistry::RemoveURLSchemeAsWebUI("chrome")`。
* **预期输出序列:**
    1. `SchemeRegistry::IsWebUIScheme("test-scheme")` 返回 `true`， `SchemeRegistry::IsWebUIScheme("chrome")` 返回 `false`。
    2. `SchemeRegistry::IsWebUIScheme("test-scheme")` 返回 `true`， `SchemeRegistry::IsWebUIScheme("chrome")` 返回 `true`。
    3. `SchemeRegistry::IsWebUIScheme("test-scheme")` 返回 `false`， `SchemeRegistry::IsWebUIScheme("chrome")` 返回 `true`。
    4. `SchemeRegistry::IsWebUIScheme("test-scheme")` 返回 `false`， `SchemeRegistry::IsWebUIScheme("chrome")` 返回 `false`。

**用户或编程常见的使用错误举例说明:**

1. **错误地假设自定义协议会绕过 CSP:**
   - **场景:** 开发者创建了一个自定义协议 `my-app://` 并尝试在网页中加载资源，例如 `<img src="my-app://image.png">`，但没有在 `SchemeRegistry` 中显式注册该协议以绕过 CSP。
   - **结果:** 浏览器会按照 CSP 的默认规则处理该请求，可能会阻止资源的加载，导致图片无法显示。
   - **正确做法:** 如果希望自定义协议绕过 CSP，需要在 Blink 初始化时（或其他合适的时机）调用 `SchemeRegistry::RegisterURLSchemeAsBypassingContentSecurityPolicy("my-app")`。

2. **在不安全的环境中使用绕过安全上下文检查的协议:**
   - **场景:** 开发者为了方便本地开发，将 `file://` 协议注册为绕过安全上下文检查，然后在生产环境的 HTTP 页面中尝试使用 Service Workers 或其他需要安全上下文的 API。
   - **结果:** 虽然本地开发可能没问题，但在生产环境中，由于页面本身不是 HTTPS，绕过安全上下文检查的设置可能不会生效，或者会引入安全风险。
   - **正确做法:** 谨慎使用绕过安全上下文检查的功能，仅在确实需要且理解其安全含义的情况下使用，并避免在生产环境中使用。

3. **忘记移除测试中注册的协议属性:**
   - **场景:** 在一个集成测试中，为了测试某个功能，注册了一个协议绕过 CSP。但在测试结束后，忘记移除该注册。
   - **结果:** 后续的测试可能会受到这个注册的影响，导致测试结果不准确，甚至产生误报。
   - **正确做法:** 在测试的 `TearDown()` 方法中，或者在不需要该注册后，显式调用 `SchemeRegistry::RemoveURLSchemeRegisteredAsBypassingContentSecurityPolicy()` 等方法来清理注册。代码中的 `TearDown()` 方法就展示了这种做法。

4. **混淆不同类型的协议注册:**
   - **场景:** 开发者希望一个自定义协议既能绕过 CSP，又能被认为是 WebUI 方案，但错误地使用了注册方法，例如只注册了 CSP 绕过，而没有注册为 WebUI。
   - **结果:** 该协议可以绕过 CSP，但不会被浏览器视为 WebUI 方案，可能无法获得 WebUI 方案的特定处理或权限。
   - **正确做法:** 仔细阅读 `SchemeRegistry` 提供的各种注册方法，根据需要注册相应的属性。例如，需要同时调用 `RegisterURLSchemeAsBypassingContentSecurityPolicy()` 和 `RegisterURLSchemeAsWebUI()`。

总而言之，`scheme_registry_test.cc` 这个文件通过各种测试用例，确保了 `SchemeRegistry` 类能够正确地管理和查询 URL 协议的各种属性，这些属性直接影响着浏览器如何加载和处理不同来源的资源，并对 Web 安全和功能特性有着重要的作用。理解这个文件的作用有助于理解 Blink 引擎如何处理不同的 URL 协议及其相关的安全和功能特性。

### 提示词
```
这是目录为blink/renderer/platform/weborigin/scheme_registry_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/scheme_registry.h"
#include "third_party/blink/renderer/platform/wtf/threading.h"

namespace blink {
namespace {

const char kTestScheme[] = "test-scheme";
const char kTestScheme2[] = "test-scheme-2";

class SchemeRegistryTest : public testing::Test {
  void TearDown() override {
#if DCHECK_IS_ON()
    WTF::SetIsBeforeThreadCreatedForTest();  // Required for next operation:
#endif
    SchemeRegistry::RemoveURLSchemeRegisteredAsBypassingContentSecurityPolicy(
        kTestScheme);
  }
};

TEST_F(SchemeRegistryTest, NoCSPBypass) {
  EXPECT_FALSE(
      SchemeRegistry::SchemeShouldBypassContentSecurityPolicy(kTestScheme));
  EXPECT_FALSE(SchemeRegistry::SchemeShouldBypassContentSecurityPolicy(
      kTestScheme, SchemeRegistry::kPolicyAreaImage));
}

TEST_F(SchemeRegistryTest, FullCSPBypass) {
#if DCHECK_IS_ON()
  WTF::SetIsBeforeThreadCreatedForTest();  // Required for next operation:
#endif
  SchemeRegistry::RegisterURLSchemeAsBypassingContentSecurityPolicy(
      kTestScheme);
  EXPECT_TRUE(
      SchemeRegistry::SchemeShouldBypassContentSecurityPolicy(kTestScheme));
  EXPECT_TRUE(SchemeRegistry::SchemeShouldBypassContentSecurityPolicy(
      kTestScheme, SchemeRegistry::kPolicyAreaImage));
  EXPECT_FALSE(
      SchemeRegistry::SchemeShouldBypassContentSecurityPolicy(kTestScheme2));
  EXPECT_FALSE(SchemeRegistry::SchemeShouldBypassContentSecurityPolicy(
      kTestScheme2, SchemeRegistry::kPolicyAreaImage));
}

TEST_F(SchemeRegistryTest, PartialCSPBypass) {
#if DCHECK_IS_ON()
  WTF::SetIsBeforeThreadCreatedForTest();  // Required for next operation:
#endif
  SchemeRegistry::RegisterURLSchemeAsBypassingContentSecurityPolicy(
      kTestScheme, SchemeRegistry::kPolicyAreaImage);
  EXPECT_FALSE(
      SchemeRegistry::SchemeShouldBypassContentSecurityPolicy(kTestScheme));
  EXPECT_TRUE(SchemeRegistry::SchemeShouldBypassContentSecurityPolicy(
      kTestScheme, SchemeRegistry::kPolicyAreaImage));
  EXPECT_FALSE(SchemeRegistry::SchemeShouldBypassContentSecurityPolicy(
      kTestScheme, SchemeRegistry::kPolicyAreaStyle));
  EXPECT_FALSE(SchemeRegistry::SchemeShouldBypassContentSecurityPolicy(
      kTestScheme2, SchemeRegistry::kPolicyAreaImage));
}

TEST_F(SchemeRegistryTest, BypassSecureContextCheck) {
  const char* scheme1 = "http";
  const char* scheme2 = "https";
  const char* scheme3 = "random-scheme";

  EXPECT_FALSE(SchemeRegistry::SchemeShouldBypassSecureContextCheck(scheme1));
  EXPECT_FALSE(SchemeRegistry::SchemeShouldBypassSecureContextCheck(scheme2));
  EXPECT_FALSE(SchemeRegistry::SchemeShouldBypassSecureContextCheck(scheme3));

#if DCHECK_IS_ON()
  WTF::SetIsBeforeThreadCreatedForTest();  // Required for next operation:
#endif
  SchemeRegistry::RegisterURLSchemeBypassingSecureContextCheck("random-scheme");

  EXPECT_FALSE(SchemeRegistry::SchemeShouldBypassSecureContextCheck(scheme1));
  EXPECT_FALSE(SchemeRegistry::SchemeShouldBypassSecureContextCheck(scheme2));
  EXPECT_TRUE(SchemeRegistry::SchemeShouldBypassSecureContextCheck(scheme3));
}

TEST_F(SchemeRegistryTest, WebUIScheme) {
  const char* kChromeUIScheme = "chrome";
  EXPECT_FALSE(SchemeRegistry::IsWebUIScheme(kTestScheme));
  EXPECT_FALSE(SchemeRegistry::IsWebUIScheme(kChromeUIScheme));

#if DCHECK_IS_ON()
  WTF::SetIsBeforeThreadCreatedForTest();  // Required for next operation:
#endif
  SchemeRegistry::RegisterURLSchemeAsWebUI(kTestScheme);

  EXPECT_TRUE(SchemeRegistry::IsWebUIScheme(kTestScheme));
  EXPECT_FALSE(SchemeRegistry::IsWebUIScheme(kChromeUIScheme));

  SchemeRegistry::RegisterURLSchemeAsWebUI(kChromeUIScheme);

  EXPECT_TRUE(SchemeRegistry::IsWebUIScheme(kTestScheme));
  EXPECT_TRUE(SchemeRegistry::IsWebUIScheme(kChromeUIScheme));

  SchemeRegistry::RemoveURLSchemeAsWebUI(kTestScheme);

  EXPECT_FALSE(SchemeRegistry::IsWebUIScheme(kTestScheme));
  EXPECT_TRUE(SchemeRegistry::IsWebUIScheme(kChromeUIScheme));

  SchemeRegistry::RemoveURLSchemeAsWebUI(kChromeUIScheme);

  EXPECT_FALSE(SchemeRegistry::IsWebUIScheme(kTestScheme));
  EXPECT_FALSE(SchemeRegistry::IsWebUIScheme(kChromeUIScheme));
}

TEST_F(SchemeRegistryTest, ExtensionScheme) {
  const char* kExtensionScheme = "chrome-extension";
  EXPECT_FALSE(CommonSchemeRegistry::IsExtensionScheme(kTestScheme));
  EXPECT_FALSE(CommonSchemeRegistry::IsExtensionScheme(kExtensionScheme));

#if DCHECK_IS_ON()
  WTF::SetIsBeforeThreadCreatedForTest();  // Required for next operation:
#endif
  CommonSchemeRegistry::RegisterURLSchemeAsExtension(kExtensionScheme);

  EXPECT_FALSE(CommonSchemeRegistry::IsExtensionScheme(kTestScheme));
  EXPECT_TRUE(CommonSchemeRegistry::IsExtensionScheme(kExtensionScheme));

  CommonSchemeRegistry::RegisterURLSchemeAsExtension(kTestScheme);

  EXPECT_TRUE(CommonSchemeRegistry::IsExtensionScheme(kTestScheme));
  EXPECT_TRUE(CommonSchemeRegistry::IsExtensionScheme(kExtensionScheme));

  CommonSchemeRegistry::RemoveURLSchemeAsExtensionForTest(kExtensionScheme);

  EXPECT_TRUE(CommonSchemeRegistry::IsExtensionScheme(kTestScheme));
  EXPECT_FALSE(CommonSchemeRegistry::IsExtensionScheme(kExtensionScheme));

  CommonSchemeRegistry::RemoveURLSchemeAsExtensionForTest(kTestScheme);

  EXPECT_FALSE(CommonSchemeRegistry::IsExtensionScheme(kTestScheme));
  EXPECT_FALSE(CommonSchemeRegistry::IsExtensionScheme(kExtensionScheme));
}

TEST_F(SchemeRegistryTest, CodeCacheWithHashing) {
  const char* kChromeUIScheme = "chrome";
  EXPECT_FALSE(SchemeRegistry::SchemeSupportsCodeCacheWithHashing(kTestScheme));
  EXPECT_FALSE(
      SchemeRegistry::SchemeSupportsCodeCacheWithHashing(kChromeUIScheme));

  SchemeRegistry::RegisterURLSchemeAsCodeCacheWithHashing(kTestScheme);

  EXPECT_TRUE(SchemeRegistry::SchemeSupportsCodeCacheWithHashing(kTestScheme));
  EXPECT_FALSE(
      SchemeRegistry::SchemeSupportsCodeCacheWithHashing(kChromeUIScheme));

  SchemeRegistry::RegisterURLSchemeAsCodeCacheWithHashing(kChromeUIScheme);

  EXPECT_TRUE(SchemeRegistry::SchemeSupportsCodeCacheWithHashing(kTestScheme));
  EXPECT_TRUE(
      SchemeRegistry::SchemeSupportsCodeCacheWithHashing(kChromeUIScheme));

  SchemeRegistry::RemoveURLSchemeAsCodeCacheWithHashing(kTestScheme);

  EXPECT_FALSE(SchemeRegistry::SchemeSupportsCodeCacheWithHashing(kTestScheme));
  EXPECT_TRUE(
      SchemeRegistry::SchemeSupportsCodeCacheWithHashing(kChromeUIScheme));

  SchemeRegistry::RemoveURLSchemeAsCodeCacheWithHashing(kChromeUIScheme);

  EXPECT_FALSE(SchemeRegistry::SchemeSupportsCodeCacheWithHashing(kTestScheme));
  EXPECT_FALSE(
      SchemeRegistry::SchemeSupportsCodeCacheWithHashing(kChromeUIScheme));
}

}  // namespace
}  // namespace blink
```
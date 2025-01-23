Response:
My thinking process to analyze the C++ test file and generate the explanation went through these stages:

1. **Understand the Goal:** The request asks for the functionality of the test file `local_dom_window_test.cc`, its relation to web technologies (JavaScript, HTML, CSS), examples of logic inference, and common usage errors.

2. **Identify the Core Subject:** The filename itself, `local_dom_window_test.cc`, immediately tells me the file is testing the `LocalDOMWindow` class in the Blink rendering engine.

3. **Analyze Imports:**  The `#include` directives provide crucial context:
    * `"third_party/blink/renderer/core/frame/local_dom_window.h"`: Confirms the main class being tested.
    * `"testing/gmock/include/gmock/gmock.h"` and `"testing/gtest/include/gtest/gtest.h"`: Indicate the use of Google Test and Google Mock for unit testing.
    * Includes related to networking (`services/network`), bindings (`renderer/bindings`), core frame components (`renderer/core/frame`), inspector (`renderer/core/inspector`), testing utilities (`renderer/core/testing`, `renderer/platform/testing`), platform services (`renderer/platform`), and web origins (`renderer/platform/weborigin`). These reveal the various aspects of `LocalDOMWindow` being tested.

4. **Examine Test Fixture:** The `LocalDOMWindowTest` class inheriting from `PageTestBase` signals an environment for testing within a simulated page. The `NavigateWithSandbox` helper function suggests tests related to sandboxing and navigation.

5. **Deconstruct Individual Tests:** I then go through each `TEST_F` function:
    * **`AttachExecutionContext`:** Focuses on the connection between `LocalDOMWindow` and the scheduler/event loop. This is internal Blink infrastructure, less directly related to web technologies.
    * **`referrerPolicyParsing` and `referrerPolicyParsingWithCommas`:**  Clearly tests the parsing of the `referrerpolicy` attribute or HTTP header, directly related to HTML and how browsers handle referrer information. This involves logic based on the string values.
    * **`OutgoingReferrer` and `OutgoingReferrerWithUniqueOrigin`:** Test the computation of the outgoing referrer, influenced by the page's URL and sandbox flags – another web standard concept.
    * **`EnforceSandboxFlags`:** Tests how sandbox attributes on `<iframe>` or via HTTP headers affect the security origin of the `LocalDOMWindow`. This has direct implications for JavaScript execution and access to APIs.
    * **`UserAgent`:**  Verifies that `LocalDOMWindow` exposes the user agent string, a crucial piece of information for web servers and JavaScript.
    * **`CSPForWorld`:**  A more complex test involving Content Security Policy (CSP), which is directly relevant to HTML `<meta>` tags and HTTP headers, and impacts JavaScript execution. This test also introduces the concept of isolated worlds within the browser.
    * **`ConsoleMessageCategory`:**  Tests the ability to set and retrieve the category of console messages, used by developers for debugging JavaScript and other web technologies.
    * **`NavigationId`:** Tests the generation and uniqueness of navigation IDs, mostly an internal browser concept but can be related to browser history and navigation APIs.
    * **`StorageAccessApiStatus`:** Tests the state of the Storage Access API, a JavaScript API for requesting access to third-party cookies.
    * **`CanExecuteScriptsDuringDetach`:**  Focuses on a specific edge case during document detachment, important for browser stability and correct script execution behavior. This is less directly user-facing but critical for developers working on the rendering engine.

6. **Identify Relationships to Web Technologies:** For each test, I consider:
    * **JavaScript:** Does it test features that JavaScript can interact with (e.g., `referrerPolicy`, `StorageAccessApiStatus`, CSP, console messages)?
    * **HTML:** Does it relate to HTML elements or attributes (e.g., `<meta>` for referrer policy, `<iframe>` for sandboxing)?
    * **CSS:**  While this file doesn't directly test CSS functionality, I keep in mind that the behavior tested (like security origins) can indirectly impact how CSS is loaded and applied.

7. **Formulate Examples:** Based on the identified relationships, I create concrete examples of how the tested functionality manifests in web development. For instance, showing how a `<meta>` tag with `referrerpolicy` works or how sandbox attributes restrict JavaScript.

8. **Infer Logic and Provide Examples:**  For tests involving parsing or decision-making (like `referrerPolicyParsing` or `EnforceSandboxFlags`), I create hypothetical inputs and outputs to illustrate the logic being tested.

9. **Identify Potential User/Programming Errors:** I think about how developers might misuse the features being tested. For example, incorrectly setting the `referrerpolicy` or misunderstanding the impact of sandbox attributes.

10. **Structure the Output:**  Finally, I organize the information clearly, using headings and bullet points to address each part of the request. I start with a general overview and then go into more detail for each test, ensuring the explanations are easy to understand for someone with a web development background, even if they aren't familiar with the Blink internals. I use code snippets where appropriate to illustrate the concepts.

By following these steps, I can systematically analyze the C++ test file and provide a comprehensive explanation of its functionality and relevance to web technologies. The key is to connect the low-level C++ code to the high-level concepts that web developers work with daily.
这个C++源代码文件 `local_dom_window_test.cc` 是 Chromium Blink 引擎的一部分，专门用于测试 `LocalDOMWindow` 类的功能。 `LocalDOMWindow` 代表了浏览器窗口的 DOM（文档对象模型）接口在特定浏览上下文（LocalFrame）中的实现。

以下是该文件测试的主要功能，并解释了它们与 JavaScript, HTML, CSS 的关系，以及可能的逻辑推理和常见错误：

**主要功能：**

1. **ExecutionContext 的依附 (AttachExecutionContext):**
   - **功能:** 测试 `LocalDOMWindow` 与执行上下文（ExecutionContext）的关联和分离。执行上下文管理着 JavaScript 代码的执行环境。
   - **与 JavaScript 的关系:**  `LocalDOMWindow` 是 JavaScript 中 `window` 对象的底层实现。JavaScript 代码在 `LocalDOMWindow` 提供的上下文中运行。
   - **逻辑推理:** 假设一个 `LocalDOMWindow` 被创建并关联到一个调度器 (scheduler)。测试验证 `LocalDOMWindow` 的 Agent (负责执行 JavaScript) 是否正确地连接到该调度器的事件循环。当 `LocalDOMWindow` 被销毁时，测试验证这种连接是否被正确移除。
   - **假设输入与输出:**
     - **输入:** 创建一个 `LocalDOMWindow` 实例，并将其关联到一个 FrameScheduler。
     - **输出:** 断言 `window->GetAgent()->event_loop()->IsSchedulerAttachedForTest(scheduler)` 返回 `true`。
     - **输入:** 销毁该 `LocalDOMWindow` 实例。
     - **输出:** 断言 `window->GetAgent()->event_loop()->IsSchedulerAttachedForTest(scheduler)` 返回 `false`。

2. **Referrer Policy 解析 (referrerPolicyParsing, referrerPolicyParsingWithCommas):**
   - **功能:** 测试 `LocalDOMWindow` 解析和设置 referrer policy 的能力。Referrer policy 控制着在导航请求中发送哪些 referrer 信息。
   - **与 HTML 的关系:** Referrer policy 可以通过 HTML `<meta>` 标签的 `referrerpolicy` 属性或 HTTP 头 `Referrer-Policy` 来设置。
   - **与 JavaScript 的关系:** JavaScript 可以通过 `document.referrer` 属性访问 referrer 信息，而 referrer policy 会影响该属性的值。
   - **逻辑推理:**  测试用例定义了不同的 referrer policy 字符串，包括有效的、无效的，以及包含逗号分隔的多个策略。测试验证 `LocalDOMWindow` 能否正确解析这些字符串并设置相应的内部 referrer policy 枚举值。对于包含逗号的情况，测试还区分了通过 `<meta>` 标签设置和通过 HTTP 头设置的不同处理方式。
   - **假设输入与输出:**
     - **输入:**  设置不同的 referrer policy 字符串 (例如 "no-referrer-when-downgrade", "unsafe-url", "same-origin,strict-origin")。
     - **输出:**  断言 `window->GetReferrerPolicy()` 返回预期的 `network::mojom::ReferrerPolicy` 枚举值。

3. **传出的 Referrer (OutgoingReferrer, OutgoingReferrerWithUniqueOrigin):**
   - **功能:** 测试 `LocalDOMWindow` 获取当前文档传出的 referrer 的能力。
   - **与 HTML 的关系:**  当用户点击链接或通过 JavaScript 发起导航时，浏览器会发送 referrer。
   - **与 JavaScript 的关系:**  JavaScript 可以通过 `document.referrer` 观察传入的 referrer。`LocalDOMWindow` 的 `OutgoingReferrer()` 方法模拟了浏览器发送的 referrer。
   - **逻辑推理:**  导航到一个特定的 URL 后，测试验证 `OutgoingReferrer()` 返回的字符串是否符合预期 (通常是去掉片段标识符和查询参数的 URL)。对于具有唯一来源 (例如通过沙箱 iframe 创建) 的文档，传出的 referrer 应该是空字符串。
   - **假设输入与输出:**
     - **输入:**  导航到 URL "https://www.example.com/hoge#fuga?piyo"。
     - **输出:**  断言 `GetFrame().DomWindow()->OutgoingReferrer()` 返回 "https://www.example.com/hoge"。
     - **输入:**  在一个具有沙箱属性且没有脚本权限的 iframe 中导航到相同的 URL。
     - **输出:**  断言 `GetFrame().DomWindow()->OutgoingReferrer()` 返回空字符串。

4. **强制执行沙箱标志 (EnforceSandboxFlags):**
   - **功能:** 测试沙箱属性对 `LocalDOMWindow` 的影响，特别是对安全来源 (security origin) 的影响。
   - **与 HTML 的关系:**  通过 `<iframe>` 标签的 `sandbox` 属性可以设置沙箱标志，限制页面的能力。
   - **与 JavaScript 的关系:** 沙箱标志会限制 JavaScript 的执行能力，例如访问父窗口、使用某些 API 等。
   - **逻辑推理:**  测试使用不同的沙箱标志进行导航，并验证 `LocalDOMWindow` 的安全来源是否按预期变为不透明 (opaque origin)。对于某些特定的 scheme，即使在沙箱环境下也可能被认为是可信的。
   - **假设输入与输出:**
     - **输入:**  使用沙箱标志 `~WebSandboxFlags::kOrigin` 导航到 "http://example.test/"。
     - **输出:**  断言 `GetFrame().DomWindow()->GetSecurityOrigin()->IsOpaque()` 返回 `false`。
     - **输入:**  使用所有沙箱标志导航到 "http://example.test/"。
     - **输出:**  断言 `GetFrame().DomWindow()->GetSecurityOrigin()->IsOpaque()` 返回 `true`。

5. **用户代理 (UserAgent):**
   - **功能:** 测试 `LocalDOMWindow` 返回的用户代理字符串是否与 `FrameLoader` 返回的相同。
   - **与 JavaScript 的关系:**  JavaScript 可以通过 `navigator.userAgent` 属性访问用户代理字符串。
   - **逻辑推理:**  `LocalDOMWindow` 应该提供与浏览器内核使用的用户代理字符串一致的值。
   - **假设输入与输出:**
     - **输入:**  获取 `GetFrame().DomWindow()->UserAgent()` 和 `GetFrame().Loader().UserAgent()` 的值。
     - **输出:**  断言这两个值相等。

6. **针对特定 World 的 CSP (CSPForWorld):**
   - **功能:** 测试 `LocalDOMWindow` 在不同的 JavaScript world 中获取正确的 Content Security Policy (CSP) 的能力。
   - **与 HTML 的关系:** CSP 可以通过 HTTP 头 `Content-Security-Policy` 或 `<meta>` 标签设置。
   - **与 JavaScript 的关系:** CSP 限制了页面可以加载的资源、可以执行的脚本等，对 JavaScript 的安全执行至关重要。浏览器扩展等会使用隔离的 JavaScript world。
   - **逻辑推理:**  测试创建了多个 JavaScript world（主 world 和隔离的 world），并为它们设置不同的 CSP。测试验证在不同的 world 中调用 `GetContentSecurityPolicyForCurrentWorld()` 方法时，返回的是该 world 对应的 CSP。如果隔离的 world 没有设置 CSP，则应该返回主 world 的 CSP。
   - **假设输入与输出:**
     - **输入:**  为主 world 设置 CSP "connect-src https://google.com;"，为隔离 world 设置 CSP "script-src 'none';"。
     - **输出:**  在主 world 中调用 `GetContentSecurityPolicyForCurrentWorld()` 返回包含主 world CSP 的对象。
     - **输出:**  在未设置 CSP 的隔离 world 中调用 `GetContentSecurityPolicyForCurrentWorld()` 返回包含主 world CSP 的对象。
     - **输出:**  在设置了 CSP 的隔离 world 中调用 `GetContentSecurityPolicyForCurrentWorld()` 返回包含隔离 world CSP 的对象。

7. **Console 消息类别 (ConsoleMessageCategory):**
   - **功能:** 测试向 `LocalDOMWindow` 添加带有特定类别的 console 消息的功能。
   - **与 JavaScript 的关系:**  JavaScript 可以使用 `console.log`, `console.error` 等方法输出消息到浏览器的开发者工具控制台。这些消息可以有不同的类别 (例如 "cors", "javascript")。
   - **逻辑推理:**  测试创建了一个带有 "Cors" 类别的 console 消息，并将其添加到 `LocalDOMWindow`。然后验证该消息是否被正确存储，并且类别被保留。
   - **假设输入与输出:**
     - **输入:**  创建一个 `ConsoleMessage` 对象，并设置其类别为 `mojom::blink::ConsoleMessageCategory::Cors`。
     - **输出:**  将该消息添加到 `LocalDOMWindow` 后，在消息存储中找到该消息，并断言其类别为 `mojom::blink::ConsoleMessageCategory::Cors`。

8. **导航 ID (NavigationId):**
   - **功能:** 测试 `LocalDOMWindow` 生成新的唯一导航 ID 的能力。
   - **与 JavaScript 的关系:**  导航 ID 主要用于浏览器内部跟踪导航事件，可能与一些底层的导航 API 有关，但通常 JavaScript 不会直接访问它。
   - **逻辑推理:**  连续调用 `GenerateNewNavigationId()` 应该生成不同的字符串。
   - **假设输入与输出:**
     - **输入:**  连续调用 `GetFrame().DomWindow()->GetNavigationId()` 和 `GetFrame().DomWindow()->GenerateNewNavigationId()` 若干次。
     - **输出:**  断言生成的多个导航 ID 字符串彼此不相等。

9. **存储访问 API 状态 (StorageAccessApiStatus):**
   - **功能:** 测试设置和获取 `LocalDOMWindow` 的存储访问 API 状态的功能。
   - **与 JavaScript 的关系:** 存储访问 API 允许嵌入的第三方内容请求访问其第一方 cookie。JavaScript 代码会调用相关 API 来请求或获取状态。
   - **逻辑推理:**  先验证默认状态是 `kNone`，然后设置状态为 `kAccessViaAPI`，并验证状态被正确更新。
   - **假设输入与输出:**
     - **输入:**  获取初始的存储访问 API 状态。
     - **输出:**  断言状态为 `net::StorageAccessApiStatus::kNone`。
     - **输入:**  设置存储访问 API 状态为 `net::StorageAccessApiStatus::kAccessViaAPI`。
     - **输出:**  再次获取状态，并断言其为 `net::StorageAccessApiStatus::kAccessViaAPI`。

10. **在 Detach 期间能否执行脚本 (CanExecuteScriptsDuringDetach):**
    - **功能:** 测试在文档 detach 过程中，`LocalDOMWindow` 是否能正确判断是否可以执行脚本。
    - **与 JavaScript 的关系:**  这关系到在页面卸载或导航离开时，JavaScript 代码的执行时机和安全。
    - **逻辑推理:**  在文档开始 detach 但 `LocalDOMWindow` 尚未完全与 Frame 分离的特定状态下，即使 `LocalDOMWindow` 对象仍然存在，也应该禁止执行脚本以避免崩溃或其他问题。
    - **假设输入与输出:**
        - **输入:**  调用 `GetFrame().Loader().DetachDocument()` 开始文档 detach。
        - **输出:**  断言 `GetFrame().DomWindow()->CanExecuteScripts(kAboutToExecuteScript)` 返回 `false`。

**用户或编程常见的使用错误示例:**

* **Referrer Policy 设置错误:** 开发者可能错误地配置 `<meta>` 标签或 HTTP 头中的 `referrerpolicy` 值，导致浏览器发送的 referrer 信息不符合预期，可能泄露敏感信息或者导致某些功能失效。例如，误用 `unsafe-url` 可能在不应该发送完整 URL 的情况下发送了。
* **沙箱属性理解不足:** 开发者可能不完全理解 `sandbox` 属性的各种标志及其组合效果，导致嵌入的 `<iframe>` 拥有超出预期的权限，可能引入安全风险。例如，忘记添加 `allow-scripts` 可能会阻止 iframe 中的 JavaScript 运行。
* **CSP 配置错误:**  错误的 CSP 配置可能阻止页面加载必要的资源（例如 CSS、图片、脚本），导致页面功能异常或样式错乱。例如，错误地设置 `script-src 'none'` 会阻止所有外部和内联脚本的执行。
* **在错误的 JavaScript World 中访问对象:**  如果开发者在浏览器扩展中使用隔离的 JavaScript world，但尝试访问主 world 中的对象（反之亦然），可能会遇到错误或访问受限。
* **在文档 Detach 期间尝试执行脚本:**  虽然测试覆盖了这种情况，但如果开发者尝试在 `beforeunload` 或 `unload` 事件处理程序中执行长时间运行的或不安全的操作，可能会导致浏览器行为异常。

总而言之，`local_dom_window_test.cc` 文件通过各种单元测试，确保 `LocalDOMWindow` 类的核心功能按照预期工作，并且与 Web 标准（如 referrer policy, CSP, 沙箱）和 JavaScript API 的行为保持一致，从而保障 Chromium 浏览器的稳定性和安全性。

### 提示词
```
这是目录为blink/renderer/core/frame/local_dom_window_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (c) 2014, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/frame/local_dom_window.h"

#include "services/network/public/cpp/web_sandbox_flags.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/loader/referrer_utils.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink-forward.h"
#include "third_party/blink/renderer/bindings/core/v8/isolated_world_csp.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/console_message_storage.h"
#include "third_party/blink/renderer/core/testing/mock_policy_container_host.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/threading.h"

namespace blink {

using network::mojom::ContentSecurityPolicySource;
using network::mojom::ContentSecurityPolicyType;
using network::mojom::WebSandboxFlags;

class LocalDOMWindowTest : public PageTestBase {
 protected:
  void NavigateWithSandbox(
      const KURL& url,
      WebSandboxFlags sandbox_flags = WebSandboxFlags::kAll) {
    auto params = WebNavigationParams::CreateWithEmptyHTMLForTesting(url);
    MockPolicyContainerHost mock_policy_container_host;
    params->policy_container = std::make_unique<blink::WebPolicyContainer>(
        blink::WebPolicyContainerPolicies(),
        mock_policy_container_host.BindNewEndpointAndPassDedicatedRemote());
    params->policy_container->policies.sandbox_flags = sandbox_flags;
    GetFrame().Loader().CommitNavigation(std::move(params),
                                         /*extra_data=*/nullptr);
    test::RunPendingTasks();
    ASSERT_EQ(url.GetString(), GetDocument().Url().GetString());
  }
};

TEST_F(LocalDOMWindowTest, AttachExecutionContext) {
  auto* scheduler = GetFrame().GetFrameScheduler();
  auto* window = GetFrame().DomWindow();
  EXPECT_TRUE(
      window->GetAgent()->event_loop()->IsSchedulerAttachedForTest(scheduler));
  window->FrameDestroyed();
  EXPECT_FALSE(
      window->GetAgent()->event_loop()->IsSchedulerAttachedForTest(scheduler));
}

TEST_F(LocalDOMWindowTest, referrerPolicyParsing) {
  LocalDOMWindow* window = GetFrame().DomWindow();
  EXPECT_EQ(network::mojom::ReferrerPolicy::kDefault,
            window->GetReferrerPolicy());

  struct TestCase {
    const char* policy;
    network::mojom::ReferrerPolicy expected;
    bool uses_legacy_tokens;
  } tests[] = {
      {"", network::mojom::ReferrerPolicy::kDefault, false},
      // Test that invalid policy values are ignored.
      {"not-a-real-policy", network::mojom::ReferrerPolicy::kDefault, false},
      {"not-a-real-policy,also-not-a-real-policy",
       network::mojom::ReferrerPolicy::kDefault, false},
      {"not-a-real-policy,unsafe-url", network::mojom::ReferrerPolicy::kAlways,
       false},
      {"unsafe-url,not-a-real-policy", network::mojom::ReferrerPolicy::kAlways,
       false},
      // Test parsing each of the policy values.
      {"always", network::mojom::ReferrerPolicy::kAlways, true},
      {"default",
       ReferrerUtils::MojoReferrerPolicyResolveDefault(
           network::mojom::ReferrerPolicy::kDefault),
       true},
      {"never", network::mojom::ReferrerPolicy::kNever, true},
      {"no-referrer", network::mojom::ReferrerPolicy::kNever, false},
      {"no-referrer-when-downgrade",
       network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade, false},
      {"origin", network::mojom::ReferrerPolicy::kOrigin, false},
      {"origin-when-crossorigin",
       network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin, true},
      {"origin-when-cross-origin",
       network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin, false},
      {"same-origin", network::mojom::ReferrerPolicy::kSameOrigin, false},
      {"strict-origin", network::mojom::ReferrerPolicy::kStrictOrigin, false},
      {"strict-origin-when-cross-origin",
       network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin, false},
      {"unsafe-url", network::mojom::ReferrerPolicy::kAlways},
  };

  for (const auto test : tests) {
    window->SetReferrerPolicy(network::mojom::ReferrerPolicy::kDefault);
    if (test.uses_legacy_tokens) {
      // Legacy tokens are supported only for meta-specified policy.
      window->ParseAndSetReferrerPolicy(test.policy, kPolicySourceHttpHeader);
      EXPECT_EQ(network::mojom::ReferrerPolicy::kDefault,
                window->GetReferrerPolicy());
      window->ParseAndSetReferrerPolicy(test.policy, kPolicySourceMetaTag);
    } else {
      window->ParseAndSetReferrerPolicy(test.policy, kPolicySourceHttpHeader);
    }
    EXPECT_EQ(test.expected, window->GetReferrerPolicy()) << test.policy;
  }
}

TEST_F(LocalDOMWindowTest, referrerPolicyParsingWithCommas) {
  LocalDOMWindow* window = GetFrame().DomWindow();
  EXPECT_EQ(network::mojom::ReferrerPolicy::kDefault,
            window->GetReferrerPolicy());

  struct TestCase {
    const char* policy;
    network::mojom::ReferrerPolicy expected;
  } tests[] = {
      {"same-origin,strict-origin",
       network::mojom::ReferrerPolicy::kStrictOrigin},
      {"same-origin,not-a-real-policy,strict-origin",
       network::mojom::ReferrerPolicy::kStrictOrigin},
      {"strict-origin, same-origin, not-a-real-policy",
       network::mojom::ReferrerPolicy::kSameOrigin},
  };

  for (const auto test : tests) {
    window->SetReferrerPolicy(network::mojom::ReferrerPolicy::kDefault);
    // Policies containing commas are ignored when specified by a Meta element.
    window->ParseAndSetReferrerPolicy(test.policy, kPolicySourceMetaTag);
    EXPECT_EQ(network::mojom::ReferrerPolicy::kDefault,
              window->GetReferrerPolicy());

    // Header-specified policy permits commas and returns the last valid policy.
    window->ParseAndSetReferrerPolicy(test.policy, kPolicySourceHttpHeader);
    EXPECT_EQ(test.expected, window->GetReferrerPolicy()) << test.policy;
  }
}

TEST_F(LocalDOMWindowTest, OutgoingReferrer) {
  NavigateTo(KURL("https://www.example.com/hoge#fuga?piyo"));
  EXPECT_EQ("https://www.example.com/hoge",
            GetFrame().DomWindow()->OutgoingReferrer());
}

TEST_F(LocalDOMWindowTest, OutgoingReferrerWithUniqueOrigin) {
  NavigateWithSandbox(
      KURL("https://www.example.com/hoge#fuga?piyo"),
      ~WebSandboxFlags::kAutomaticFeatures & ~WebSandboxFlags::kScripts);
  EXPECT_TRUE(GetFrame().DomWindow()->GetSecurityOrigin()->IsOpaque());
  EXPECT_EQ(String(), GetFrame().DomWindow()->OutgoingReferrer());
}

TEST_F(LocalDOMWindowTest, EnforceSandboxFlags) {
  NavigateWithSandbox(KURL("http://example.test/"), ~WebSandboxFlags::kOrigin);
  EXPECT_FALSE(GetFrame().DomWindow()->GetSecurityOrigin()->IsOpaque());
  EXPECT_FALSE(
      GetFrame().DomWindow()->GetSecurityOrigin()->IsPotentiallyTrustworthy());

  NavigateWithSandbox(KURL("http://example.test/"));
  EXPECT_TRUE(GetFrame().DomWindow()->GetSecurityOrigin()->IsOpaque());
  EXPECT_FALSE(
      GetFrame().DomWindow()->GetSecurityOrigin()->IsPotentiallyTrustworthy());

  // A unique origin does not bypass secure context checks unless it
  // is also potentially trustworthy.
  {
    url::ScopedSchemeRegistryForTests scoped_registry;
    url::AddStandardScheme("very-special-scheme", url::SCHEME_WITH_HOST);
#if DCHECK_IS_ON()
    WTF::SetIsBeforeThreadCreatedForTest();  // Required for next operation:
#endif
    SchemeRegistry::RegisterURLSchemeBypassingSecureContextCheck(
        "very-special-scheme");
    NavigateWithSandbox(KURL("very-special-scheme://example.test"));
    EXPECT_TRUE(GetFrame().DomWindow()->GetSecurityOrigin()->IsOpaque());
    EXPECT_FALSE(GetFrame()
                     .DomWindow()
                     ->GetSecurityOrigin()
                     ->IsPotentiallyTrustworthy());
  }

  {
    url::ScopedSchemeRegistryForTests scoped_registry;
    url::AddStandardScheme("very-special-scheme", url::SCHEME_WITH_HOST);
    url::AddSecureScheme("very-special-scheme");
    NavigateWithSandbox(KURL("very-special-scheme://example.test"));
    EXPECT_TRUE(GetFrame().DomWindow()->GetSecurityOrigin()->IsOpaque());
    EXPECT_TRUE(GetFrame()
                    .DomWindow()
                    ->GetSecurityOrigin()
                    ->IsPotentiallyTrustworthy());

    NavigateWithSandbox(KURL("https://example.test"));
    EXPECT_TRUE(GetFrame().DomWindow()->GetSecurityOrigin()->IsOpaque());
    EXPECT_TRUE(GetFrame()
                    .DomWindow()
                    ->GetSecurityOrigin()
                    ->IsPotentiallyTrustworthy());
  }
}

TEST_F(LocalDOMWindowTest, UserAgent) {
  EXPECT_EQ(GetFrame().DomWindow()->UserAgent(),
            GetFrame().Loader().UserAgent());
}

// Tests ExecutionContext::GetContentSecurityPolicyForCurrentWorld().
TEST_F(PageTestBase, CSPForWorld) {
  using ::testing::ElementsAre;

  // Set a CSP for the main world.
  const char* kMainWorldCSP = "connect-src https://google.com;";
  GetFrame().DomWindow()->GetContentSecurityPolicy()->AddPolicies(
      ParseContentSecurityPolicies(
          kMainWorldCSP, ContentSecurityPolicyType::kEnforce,
          ContentSecurityPolicySource::kHTTP,
          *(GetFrame().DomWindow()->GetSecurityOrigin())));
  const Vector<
      network::mojom::blink::ContentSecurityPolicyPtr>& parsed_main_world_csp =
      GetFrame().DomWindow()->GetContentSecurityPolicy()->GetParsedPolicies();

  LocalFrame* frame = &GetFrame();
  ScriptState* main_world_script_state = ToScriptStateForMainWorld(frame);
  v8::Isolate* isolate = main_world_script_state->GetIsolate();

  constexpr int kIsolatedWorldWithoutCSPId = 1;
  DOMWrapperWorld* world_without_csp =
      DOMWrapperWorld::EnsureIsolatedWorld(isolate, kIsolatedWorldWithoutCSPId);
  ASSERT_TRUE(world_without_csp->IsIsolatedWorld());
  ScriptState* isolated_world_without_csp_script_state =
      ToScriptState(frame, *world_without_csp);

  const char* kIsolatedWorldCSP = "script-src 'none';";
  constexpr int kIsolatedWorldWithCSPId = 2;
  DOMWrapperWorld* world_with_csp =
      DOMWrapperWorld::EnsureIsolatedWorld(isolate, kIsolatedWorldWithCSPId);
  ASSERT_TRUE(world_with_csp->IsIsolatedWorld());
  ScriptState* isolated_world_with_csp_script_state =
      ToScriptState(frame, *world_with_csp);
  IsolatedWorldCSP::Get().SetContentSecurityPolicy(
      kIsolatedWorldWithCSPId, kIsolatedWorldCSP,
      SecurityOrigin::Create(KURL("chrome-extension://123")));

  // Returns the csp headers being used for the current world.
  auto get_csp = [this]()
      -> const Vector<network::mojom::blink::ContentSecurityPolicyPtr>& {
    auto* csp =
        GetFrame().DomWindow()->GetContentSecurityPolicyForCurrentWorld();
    return csp->GetParsedPolicies();
  };

  {
    SCOPED_TRACE("In main world.");
    ScriptState::Scope scope(main_world_script_state);
    EXPECT_EQ(get_csp(), parsed_main_world_csp);
  }

  {
    SCOPED_TRACE("In isolated world without csp.");
    ScriptState::Scope scope(isolated_world_without_csp_script_state);

    // If we are in an isolated world with no CSP defined, we use the main world
    // CSP.
    EXPECT_EQ(get_csp(), parsed_main_world_csp);
  }

  {
    SCOPED_TRACE("In isolated world with csp.");
    ScriptState::Scope scope(isolated_world_with_csp_script_state);
    // We use the isolated world's CSP if it specified one.
    EXPECT_EQ(get_csp()[0]->header->header_value, kIsolatedWorldCSP);
  }
}

TEST_F(LocalDOMWindowTest, ConsoleMessageCategory) {
  auto unknown_location = CaptureSourceLocation(String(), 0, 0);
  auto* console_message = MakeGarbageCollected<ConsoleMessage>(
      mojom::blink::ConsoleMessageSource::kJavaScript,
      mojom::blink::ConsoleMessageLevel::kError, "Kaboom!",
      std::move(unknown_location));
  console_message->SetCategory(mojom::blink::ConsoleMessageCategory::Cors);
  auto* window = GetFrame().DomWindow();
  window->AddConsoleMessageImpl(console_message, false);
  auto* message_storage = &GetFrame().GetPage()->GetConsoleMessageStorage();
  EXPECT_EQ(1u, message_storage->size());
  for (WTF::wtf_size_t i = 0; i < message_storage->size(); ++i) {
    EXPECT_EQ(mojom::blink::ConsoleMessageCategory::Cors,
              *message_storage->at(i)->Category());
  }
}
TEST_F(LocalDOMWindowTest, NavigationId) {
  String navigation_id1 = GetFrame().DomWindow()->GetNavigationId();
  GetFrame().DomWindow()->GenerateNewNavigationId();
  String navigation_id2 = GetFrame().DomWindow()->GetNavigationId();
  GetFrame().DomWindow()->GenerateNewNavigationId();
  String navigation_id3 = GetFrame().DomWindow()->GetNavigationId();
  EXPECT_NE(navigation_id1, navigation_id2);
  EXPECT_NE(navigation_id1, navigation_id3);
  EXPECT_NE(navigation_id2, navigation_id3);
}

TEST_F(LocalDOMWindowTest, StorageAccessApiStatus) {
  EXPECT_EQ(GetFrame().DomWindow()->GetStorageAccessApiStatus(),
            net::StorageAccessApiStatus::kNone);
  GetFrame().DomWindow()->SetStorageAccessApiStatus(
      net::StorageAccessApiStatus::kAccessViaAPI);
  EXPECT_EQ(GetFrame().DomWindow()->GetStorageAccessApiStatus(),
            net::StorageAccessApiStatus::kAccessViaAPI);
}

TEST_F(LocalDOMWindowTest, CanExecuteScriptsDuringDetach) {
  GetFrame().Loader().DetachDocument();
  EXPECT_NE(GetFrame().DomWindow(), nullptr);

  // When detach has started and FrameLoader::document_loader_ is nullptr, but
  // the window hasn't been detached from its frame yet, CanExecuteScripts()
  // should return false and not crash.
  // This case is reachable when the only thing blocking a main frame's load
  // event from firing is an iframe's load event, and that iframe is detached,
  // thus unblocking the load event. If the detaching window is accessed inside
  // a load event listener in that case, we may call CanExecuteScripts() in this
  // partially-detached state.
  // See crbug.com/350874762, crbug.com/41482536 and crbug.com/41484859.
  EXPECT_FALSE(
      GetFrame().DomWindow()->CanExecuteScripts(kAboutToExecuteScript));
}

}  // namespace blink
```
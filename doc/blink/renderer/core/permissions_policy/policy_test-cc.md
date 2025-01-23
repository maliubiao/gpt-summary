Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The filename `policy_test.cc` immediately suggests that this file contains tests related to "policy."  The specific namespace `permissions_policy` confirms that it's about permission policies within the Blink rendering engine.

2. **Examine Includes:** The `#include` directives provide crucial context:
    * `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h`:  This confirms it's a unit test file using Google Test and Google Mock frameworks.
    * `third_party/blink/renderer/core/frame/local_dom_window.h` and `local_frame.h`: Indicates interaction with the DOM and frame structure of a web page.
    * `third_party/blink/renderer/core/permissions_policy/dom_feature_policy.h`, `iframe_policy.h`, `permissions_policy_parser.h`: These are the core classes being tested. They deal with feature permissions at the DOM level, specifically for iframes, and the parsing of policy strings.
    * `third_party/blink/renderer/core/testing/dummy_page_holder.h`:  Suggests a mock or simplified page environment for testing.
    * `third_party/blink/renderer/platform/testing/task_environment.h`: Likely provides a simulated environment for asynchronous tasks.
    * `third_party/blink/renderer/platform/weborigin/security_origin.h`: Deals with the concept of web origins and security contexts.

3. **Analyze the Test Structure:**
    * **Namespaces:** The code is within the `blink` namespace and an anonymous namespace for internal constants. This is standard C++ practice.
    * **Constants:**  `kSelfOrigin`, `kOriginA`, etc., are defined. These are example URLs used in the tests to simulate different origins.
    * **Test Fixtures:** The `PolicyTest`, `DOMFeaturePolicyTest`, and `IFramePolicyTest` classes are test fixtures. `PolicyTest` sets up common infrastructure, and the others inherit from it, customizing the `policy_` member. This pattern helps avoid code duplication in test setup.
    * **`SetUp()` methods:** These methods initialize the test environment before each test case runs. Crucially, `PolicyTest::SetUp()` *parses a sample Permissions Policy header and attribute string*. This parsed policy becomes the baseline for the tests.
    * **`TEST_F()` macros:** These define individual test cases. Each test focuses on a specific aspect of the policy classes (e.g., `TestAllowsFeature`, `TestGetAllowList`).
    * **Assertions:** `EXPECT_TRUE`, `EXPECT_FALSE`, and `EXPECT_THAT` are used to assert the expected behavior of the code under test. `UnorderedElementsAre` is a matcher from Google Mock for comparing sets of strings without regard to order.

4. **Connect to Web Concepts:** Now, map the C++ code to web development concepts:
    * **Permissions Policy:** This is the central theme. It's a browser mechanism that allows websites to control which features (like camera, microphone, geolocation) can be used by the website itself and by embedded iframes.
    * **Features:**  The test cases use examples like "fullscreen," "payment," "midi," "camera," "geolocation," "sync-xhr," and "gyroscope." These represent actual browser features governed by Permissions Policy.
    * **Origins:** The `kSelfOrigin`, `kOriginA`, etc., simulate different websites or parts of a website. The Permissions Policy is origin-based.
    * **`allow` attribute (of `<iframe>`):** The `IFramePolicyTest` specifically tests how Permissions Policy interacts with the `allow` attribute of iframes. The `ParseAttribute` function simulates parsing the `allow` attribute string.
    * **Headers and Attributes:**  The `SetUp` method in `PolicyTest` shows parsing both a HTTP header (`Permissions-Policy`) and an iframe `allow` attribute.

5. **Analyze Test Logic and Examples:** Go through each test case and understand what it's verifying:
    * **`TestAllowsFeature`:** Checks if a given feature is allowed for a specific origin, based on the parsed policy.
    * **`TestGetAllowList`:** Checks the list of origins allowed for a particular feature.
    * **`TestAllowedFeatures`:** Checks the set of features allowed in a given context.
    * **`IFramePolicyTest` cases:**  Specifically test how the Permissions Policy of the parent document interacts with the `allow` attribute of an iframe, considering same-origin and cross-origin scenarios.

6. **Infer Relationships to JavaScript, HTML, and CSS:**
    * **JavaScript:** The Permissions Policy affects JavaScript APIs. If a feature is disallowed by the policy, JavaScript code attempting to use that feature's API will fail or behave differently.
    * **HTML:** The `allow` attribute of the `<iframe>` tag is directly related to the Permissions Policy. The tests for `IFramePolicyTest` directly examine this.
    * **CSS (Indirect):** While not directly tested here, CSS features like fullscreen can be controlled by Permissions Policy.

7. **Consider User Actions and Debugging:** Think about how a user might encounter these policies and how a developer might debug them:
    * **User Actions:**  A user navigating to a website or a website embedding an iframe triggers the evaluation of Permissions Policy.
    * **Debugging:** The test file itself serves as a good debugging resource. The test cases show how the policy should behave under different configurations. Developers can use browser developer tools to inspect the applied Permissions Policy.

8. **Synthesize and Organize:**  Finally, structure the analysis into clear sections covering the file's functionality, its relation to web technologies, logical inferences, common errors, and debugging hints. Use clear language and provide concrete examples.

By following this structured approach, even with limited prior knowledge of the specific Blink codebase, you can effectively understand the purpose and functionality of a test file like this. The key is to start with the basics (filename, includes), understand the testing framework, and then relate the code to the broader web development context.
The file `blink/renderer/core/permissions_policy/policy_test.cc` is a **unit test file** within the Chromium Blink rendering engine. Its primary function is to **test the implementation of the Permissions Policy feature**.

Here's a breakdown of its functionalities and relationships:

**1. Core Functionality: Testing Permissions Policy**

* **Verifies Policy Enforcement:** The tests in this file ensure that the Permissions Policy, which controls access to certain browser features, is correctly applied and enforced.
* **Tests Different Policy Directives:** It checks how various directives within the Permissions Policy header and iframe `allow` attribute affect feature access. Examples include:
    * `'self'`: Allowing the feature only for the origin of the document itself.
    * `*`: Allowing the feature for all origins.
    * `<origin>`: Allowing the feature for a specific origin.
    * `'none'`: Disallowing the feature entirely.
    * Wildcard origins (e.g., `https://*.example.com`).
* **Tests Different Contexts:** It tests policy enforcement in different scenarios, such as:
    * The main document's own policy (`DOMFeaturePolicyTest`).
    * The combined policy of a parent document and an iframe's `allow` attribute (`IFramePolicyTest`).
    * Same-origin and cross-origin iframe scenarios.
* **Tests Feature Availability:** It verifies which features are allowed or disallowed based on the applied policy.

**2. Relationship with JavaScript, HTML, and CSS**

Permissions Policy directly impacts the behavior of JavaScript APIs and can be declared in HTML. This test file indirectly relates to them by ensuring the underlying policy engine works correctly.

* **JavaScript:** When JavaScript code attempts to use a feature that is blocked by the Permissions Policy, the browser will typically prevent the action, potentially throwing an error or returning a rejected Promise. This test file doesn't directly execute JavaScript, but it verifies the policy that *governs* JavaScript feature access.
    * **Example:** If the Permissions Policy disallows the `camera` feature, JavaScript code like `navigator.mediaDevices.getUserMedia({ video: true })` would fail. The tests in `policy_test.cc` ensure that the policy engine correctly identifies whether the `camera` feature is allowed for a given origin.
* **HTML:** The Permissions Policy can be set via the `Permissions-Policy` HTTP header or the `allow` attribute on `<iframe>` elements. This file tests the parsing and application of both these mechanisms.
    * **Example:** The `SetUp` method in `PolicyTest` parses a sample `Permissions-Policy` header: `"fullscreen *; payment 'self'; midi 'none'; camera 'self' https://example.com https://example.net"`. This header string is directly related to how a website would declare its policy in an HTTP response. The `IFramePolicyTest` uses `PermissionsPolicyParser::ParseAttribute` to simulate parsing the `allow` attribute of an iframe.
* **CSS (Indirect):**  While not directly interacting with CSS properties, some CSS features might be gated by Permissions Policy (though less common than JavaScript APIs). For instance, access to certain hardware features that could be controlled by CSS might be subject to these policies.

**3. Logical Reasoning and Examples**

The tests perform logical reasoning based on the parsed policy.

**Assumption:** The `SetUp` method establishes a base Permissions Policy.

**Example 1 (DOMFeaturePolicyTest - `TestAllowsFeature`):**

* **Input (Feature, Origin):** "camera", "https://example.com"
* **Policy:** The parsed header includes `camera 'self' https://example.com https://example.net`.
* **Logic:** The policy explicitly allows "camera" for the current origin (`'self'`) and for `https://example.com`.
* **Output:** `GetPolicy()->allowsFeature(nullptr, "camera", kOriginA)` returns `true`.

**Example 2 (IFramePolicyTest - `TestCombinedPolicyOnOriginA`):**

* **Input (Parent Policy, Iframe `allow` attribute, Iframe Origin):**
    * Parent Policy (from `SetUp`):  Allows `camera` for `'self'`, `https://example.com`, and `https://example.net`.
    * Iframe `allow` attribute: `"geolocation 'src'; payment 'none'; midi; camera 'src'; gyroscope 'src'"`
    * Iframe Origin: `https://example.com`
* **Logic:**
    * The iframe's `allow` attribute grants permissions to the iframe's own origin (`'src'`).
    * The parent policy might further restrict these permissions.
    * The feature is allowed only if both the parent policy and the iframe's `allow` attribute permit it.
* **Output:** `allowed_features.Contains("camera")` returns `true` because both the parent policy allows it for `https://example.com` and the iframe's `allow` attribute also allows it for its own origin. `allowed_features.Contains("payment")` returns `false` because the iframe's `allow` attribute explicitly disallows it (`'none'`).

**4. User and Programming Errors**

This test file helps prevent common errors by ensuring the Permissions Policy implementation is robust. Here are some examples of user/programming errors that these tests might catch:

* **Incorrect Policy Syntax:** If the parser (tested elsewhere) fails to correctly interpret the policy string, these tests would likely fail, indicating a problem with the parsing logic.
* **Misunderstanding Policy Semantics:** Developers might misunderstand how different policy directives interact. The tests provide concrete examples of how the policy should behave, helping to clarify the intended semantics.
* **Forgetting to Set the Policy:** If the Permissions Policy is not correctly set on a document or iframe, features might be unexpectedly allowed or disallowed. The tests simulate different policy configurations to ensure the expected behavior.
* **Typos in Feature Names:**  If a developer makes a typo in a feature name in the policy, it won't have the intended effect. The tests use correct feature names to verify the core functionality.

**5. User Operations and Debugging Clues**

While a user doesn't directly interact with this C++ test file, their actions in a web browser can lead to the execution of the code being tested. Here's how a user's actions can lead to this code being relevant, serving as debugging clues:

1. **User Navigates to a Website:**
   - The browser fetches the website's resources, including the HTML and HTTP headers.
   - If the HTTP response contains a `Permissions-Policy` header, the browser's policy engine (which includes the code tested here) will parse and store this policy.

2. **Website Embeds an Iframe:**
   - The browser creates a new browsing context for the iframe.
   - If the `<iframe>` tag has an `allow` attribute, the browser's policy engine will parse and combine this with the parent document's policy.

3. **JavaScript Code Attempts to Access a Feature:**
   - When JavaScript code tries to use an API like `navigator.mediaDevices.getUserMedia()` (for camera/microphone) or `navigator.geolocation.getCurrentPosition()`, the browser's policy engine will check if the current document or iframe is allowed to use that feature based on the applied Permissions Policy.
   - **Debugging Clue:** If a user reports that a website feature is not working as expected (e.g., the camera permission is denied), a developer might investigate the `Permissions-Policy` header and the iframe `allow` attributes involved. They might even run similar tests locally (or within the browser's debugging tools) to understand how the policy is being applied.

4. **Developer Inspects the Policy:**
   - Modern browsers provide developer tools to inspect the applied Permissions Policy for a given frame. This allows developers to see the computed policy and understand why a feature might be blocked or allowed.

**In essence, `policy_test.cc` is a foundational piece of infrastructure that ensures the Permissions Policy feature in Chromium works as intended. While users don't directly interact with it, their browsing actions trigger the execution of the underlying code, and when things go wrong, the logic tested in this file becomes a critical part of the debugging process.**

### 提示词
```
这是目录为blink/renderer/core/permissions_policy/policy_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/permissions_policy/dom_feature_policy.h"
#include "third_party/blink/renderer/core/permissions_policy/iframe_policy.h"
#include "third_party/blink/renderer/core/permissions_policy/permissions_policy_parser.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

namespace blink {

namespace {
constexpr char kSelfOrigin[] = "https://selforigin.com";
constexpr char kOriginA[] = "https://example.com";
constexpr char kOriginASubdomain[] = "https://sub.example.com";
constexpr char kOriginB[] = "https://example.net";
constexpr char kOriginBSubdomain[] = "https://sub.example.net";
}  // namespace

using testing::UnorderedElementsAre;

class PolicyTest : public testing::Test {
 public:
  void SetUp() override {
    page_holder_ = std::make_unique<DummyPageHolder>();

    auto origin = SecurityOrigin::CreateFromString(kSelfOrigin);

    PolicyParserMessageBuffer dummy_logger("", true /* discard_message */);
    auto header = PermissionsPolicyParser::ParseHeader(
        "fullscreen *; payment 'self'; midi 'none'; camera 'self' "
        "https://example.com https://example.net",
        "gyroscope=(self \"https://*.example.com\" \"https://example.net\")",
        origin.get(), dummy_logger, dummy_logger);
    auto permissions_policy = PermissionsPolicy::CreateFromParentPolicy(
        nullptr, header, {}, origin->ToUrlOrigin());

    auto& security_context =
        page_holder_->GetFrame().DomWindow()->GetSecurityContext();
    security_context.SetSecurityOriginForTesting(origin);
    security_context.SetPermissionsPolicy(std::move(permissions_policy));
  }

  DOMFeaturePolicy* GetPolicy() const { return policy_; }

 protected:
  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> page_holder_;
  Persistent<DOMFeaturePolicy> policy_;
};

class DOMFeaturePolicyTest : public PolicyTest {
 public:
  void SetUp() override {
    PolicyTest::SetUp();
    policy_ = MakeGarbageCollected<DOMFeaturePolicy>(
        page_holder_->GetFrame().DomWindow());
  }
};

class IFramePolicyTest : public PolicyTest {
 public:
  void SetUp() override {
    PolicyTest::SetUp();
    policy_ = MakeGarbageCollected<IFramePolicy>(
        page_holder_->GetFrame().DomWindow(), ParsedPermissionsPolicy(),
        SecurityOrigin::CreateFromString(kSelfOrigin));
  }
};

TEST_F(DOMFeaturePolicyTest, TestAllowsFeature) {
  EXPECT_FALSE(GetPolicy()->allowsFeature(nullptr, "badfeature"));
  EXPECT_FALSE(GetPolicy()->allowsFeature(nullptr, "midi"));
  EXPECT_FALSE(GetPolicy()->allowsFeature(nullptr, "midi", kSelfOrigin));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "fullscreen"));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "fullscreen", kOriginA));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "payment"));
  EXPECT_FALSE(GetPolicy()->allowsFeature(nullptr, "payment", kOriginA));
  EXPECT_FALSE(GetPolicy()->allowsFeature(nullptr, "payment", kOriginB));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "camera"));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "camera", kOriginA));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "camera", kOriginB));
  EXPECT_FALSE(
      GetPolicy()->allowsFeature(nullptr, "camera", "https://badorigin.com"));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "geolocation", kSelfOrigin));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "sync-xhr"));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "sync-xhr", kOriginA));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "gyroscope"));
  EXPECT_FALSE(GetPolicy()->allowsFeature(nullptr, "gyroscope", kOriginA));
  EXPECT_TRUE(
      GetPolicy()->allowsFeature(nullptr, "gyroscope", kOriginASubdomain));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "gyroscope", kOriginB));
  EXPECT_FALSE(
      GetPolicy()->allowsFeature(nullptr, "gyroscope", kOriginBSubdomain));
}

TEST_F(DOMFeaturePolicyTest, TestGetAllowList) {
  EXPECT_THAT(GetPolicy()->getAllowlistForFeature(nullptr, "camera"),
              UnorderedElementsAre(kSelfOrigin, kOriginA, kOriginB));
  EXPECT_THAT(GetPolicy()->getAllowlistForFeature(nullptr, "payment"),
              UnorderedElementsAre(kSelfOrigin));
  EXPECT_THAT(GetPolicy()->getAllowlistForFeature(nullptr, "geolocation"),
              UnorderedElementsAre(kSelfOrigin));
  EXPECT_THAT(GetPolicy()->getAllowlistForFeature(nullptr, "fullscreen"),
              UnorderedElementsAre("*"));
  EXPECT_TRUE(
      GetPolicy()->getAllowlistForFeature(nullptr, "badfeature").empty());
  EXPECT_TRUE(GetPolicy()->getAllowlistForFeature(nullptr, "midi").empty());
  EXPECT_THAT(GetPolicy()->getAllowlistForFeature(nullptr, "sync-xhr"),
              UnorderedElementsAre("*"));
  EXPECT_THAT(
      GetPolicy()->getAllowlistForFeature(nullptr, "gyroscope"),
      UnorderedElementsAre(kSelfOrigin, kOriginB, "https://*.example.com"));
}

TEST_F(DOMFeaturePolicyTest, TestAllowedFeatures) {
  Vector<String> allowed_features = GetPolicy()->allowedFeatures(nullptr);
  EXPECT_TRUE(allowed_features.Contains("fullscreen"));
  EXPECT_TRUE(allowed_features.Contains("payment"));
  EXPECT_TRUE(allowed_features.Contains("camera"));
  EXPECT_TRUE(allowed_features.Contains("gyroscope"));
  // "geolocation" has default policy as allowed on self origin.
  EXPECT_TRUE(allowed_features.Contains("geolocation"));
  EXPECT_FALSE(allowed_features.Contains("badfeature"));
  EXPECT_FALSE(allowed_features.Contains("midi"));
  // "sync-xhr" is allowed on all origins
  EXPECT_TRUE(allowed_features.Contains("sync-xhr"));
}

TEST_F(IFramePolicyTest, TestAllowsFeature) {
  EXPECT_FALSE(GetPolicy()->allowsFeature(nullptr, "badfeature"));
  EXPECT_FALSE(GetPolicy()->allowsFeature(nullptr, "midi"));
  EXPECT_FALSE(GetPolicy()->allowsFeature(nullptr, "midi", kSelfOrigin));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "fullscreen"));
  EXPECT_FALSE(GetPolicy()->allowsFeature(nullptr, "fullscreen", kOriginA));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "fullscreen", kSelfOrigin));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "payment"));
  EXPECT_FALSE(GetPolicy()->allowsFeature(nullptr, "payment", kOriginA));
  EXPECT_FALSE(GetPolicy()->allowsFeature(nullptr, "payment", kOriginB));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "camera"));
  EXPECT_FALSE(GetPolicy()->allowsFeature(nullptr, "camera", kOriginA));
  EXPECT_FALSE(GetPolicy()->allowsFeature(nullptr, "camera", kOriginB));
  EXPECT_FALSE(
      GetPolicy()->allowsFeature(nullptr, "camera", "https://badorigin.com"));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "geolocation", kSelfOrigin));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "sync-xhr"));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "sync-xhr", kOriginA));
  EXPECT_TRUE(GetPolicy()->allowsFeature(nullptr, "gyroscope"));
  EXPECT_FALSE(GetPolicy()->allowsFeature(nullptr, "gyroscope", kOriginA));
  EXPECT_FALSE(
      GetPolicy()->allowsFeature(nullptr, "gyroscope", kOriginASubdomain));
  EXPECT_FALSE(GetPolicy()->allowsFeature(nullptr, "gyroscope", kOriginB));
  EXPECT_FALSE(
      GetPolicy()->allowsFeature(nullptr, "gyroscope", kOriginBSubdomain));
}

TEST_F(IFramePolicyTest, TestGetAllowList) {
  EXPECT_THAT(GetPolicy()->getAllowlistForFeature(nullptr, "camera"),
              UnorderedElementsAre(kSelfOrigin));
  EXPECT_THAT(GetPolicy()->getAllowlistForFeature(nullptr, "payment"),
              UnorderedElementsAre(kSelfOrigin));
  EXPECT_THAT(GetPolicy()->getAllowlistForFeature(nullptr, "geolocation"),
              UnorderedElementsAre(kSelfOrigin));
  EXPECT_THAT(GetPolicy()->getAllowlistForFeature(nullptr, "fullscreen"),
              UnorderedElementsAre(kSelfOrigin));
  EXPECT_TRUE(
      GetPolicy()->getAllowlistForFeature(nullptr, "badfeature").empty());
  EXPECT_TRUE(GetPolicy()->getAllowlistForFeature(nullptr, "midi").empty());
  EXPECT_THAT(GetPolicy()->getAllowlistForFeature(nullptr, "sync-xhr"),
              UnorderedElementsAre("*"));
  EXPECT_THAT(GetPolicy()->getAllowlistForFeature(nullptr, "gyroscope"),
              UnorderedElementsAre(kSelfOrigin));
}

TEST_F(IFramePolicyTest, TestSameOriginAllowedFeatures) {
  Vector<String> allowed_features = GetPolicy()->allowedFeatures(nullptr);
  // These features are allowed in a same origin context, and not restricted by
  // the parent document's policy.
  EXPECT_TRUE(allowed_features.Contains("fullscreen"));
  EXPECT_TRUE(allowed_features.Contains("payment"));
  EXPECT_TRUE(allowed_features.Contains("camera"));
  EXPECT_TRUE(allowed_features.Contains("geolocation"));
  EXPECT_TRUE(allowed_features.Contains("gyroscope"));
  // "midi" is restricted by the parent document's policy.
  EXPECT_FALSE(allowed_features.Contains("midi"));
  // "sync-xhr" is allowed on all origins.
  EXPECT_TRUE(allowed_features.Contains("sync-xhr"));
  // This feature does not exist, so should not be advertised as allowed.
  EXPECT_FALSE(allowed_features.Contains("badfeature"));
}

TEST_F(IFramePolicyTest, TestCrossOriginAllowedFeatures) {
  // Update the iframe's policy, given a new origin.
  GetPolicy()->UpdateContainerPolicy(
      ParsedPermissionsPolicy(), SecurityOrigin::CreateFromString(kOriginA));
  Vector<String> allowed_features = GetPolicy()->allowedFeatures(nullptr);
  // None of these features should be allowed in a cross-origin context.
  EXPECT_FALSE(allowed_features.Contains("fullscreen"));
  EXPECT_FALSE(allowed_features.Contains("payment"));
  EXPECT_FALSE(allowed_features.Contains("camera"));
  EXPECT_FALSE(allowed_features.Contains("geolocation"));
  EXPECT_FALSE(allowed_features.Contains("midi"));
  EXPECT_FALSE(allowed_features.Contains("gyroscope"));
  // "sync-xhr" is allowed on all origins.
  EXPECT_TRUE(allowed_features.Contains("sync-xhr"));
  // This feature does not exist, so should not be advertised as allowed.
  EXPECT_FALSE(allowed_features.Contains("badfeature"));
}

TEST_F(IFramePolicyTest, TestCombinedPolicyOnOriginA) {
  PolicyParserMessageBuffer dummy_logger("", true /* discard_message */);
  ParsedPermissionsPolicy container_policy =
      PermissionsPolicyParser::ParseAttribute(
          "geolocation 'src'; payment 'none'; midi; camera 'src'; gyroscope "
          "'src'",
          SecurityOrigin::CreateFromString(kSelfOrigin),
          SecurityOrigin::CreateFromString(kOriginA), dummy_logger);
  GetPolicy()->UpdateContainerPolicy(
      container_policy, SecurityOrigin::CreateFromString(kOriginA));
  Vector<String> allowed_features = GetPolicy()->allowedFeatures(nullptr);
  // These features are not explicitly allowed.
  EXPECT_FALSE(allowed_features.Contains("fullscreen"));
  EXPECT_FALSE(allowed_features.Contains("payment"));
  EXPECT_FALSE(allowed_features.Contains("gyroscope"));
  // These features are explicitly allowed.
  EXPECT_TRUE(allowed_features.Contains("geolocation"));
  EXPECT_TRUE(allowed_features.Contains("camera"));
  // "midi" is allowed by the attribute, but still blocked by the parent
  // document's policy.
  EXPECT_FALSE(allowed_features.Contains("midi"));
  // "sync-xhr" is still implicitly allowed on all origins.
  EXPECT_TRUE(allowed_features.Contains("sync-xhr"));
  // This feature does not exist, so should not be advertised as allowed.
  EXPECT_FALSE(allowed_features.Contains("badfeature"));
}

TEST_F(IFramePolicyTest, TestCombinedPolicyOnOriginASubdomain) {
  PolicyParserMessageBuffer dummy_logger("", true /* discard_message */);
  ParsedPermissionsPolicy container_policy =
      PermissionsPolicyParser::ParseAttribute(
          "geolocation 'src'; payment 'none'; midi; camera 'src'; gyroscope "
          "'src'",
          SecurityOrigin::CreateFromString(kSelfOrigin),
          SecurityOrigin::CreateFromString(kOriginASubdomain), dummy_logger);
  GetPolicy()->UpdateContainerPolicy(
      container_policy, SecurityOrigin::CreateFromString(kOriginASubdomain));
  Vector<String> allowed_features = GetPolicy()->allowedFeatures(nullptr);
  // These features are not explicitly allowed.
  EXPECT_FALSE(allowed_features.Contains("fullscreen"));
  EXPECT_FALSE(allowed_features.Contains("payment"));
  // These features are explicitly allowed.
  EXPECT_TRUE(allowed_features.Contains("geolocation"));
  // These are allowed by the attribute, but still blocked by the parent policy.
  EXPECT_FALSE(allowed_features.Contains("midi"));
  EXPECT_FALSE(allowed_features.Contains("camera"));
  // These features are allowed via wildcard matching.
  EXPECT_TRUE(allowed_features.Contains("gyroscope"));
  // "sync-xhr" is still implicitly allowed on all origins.
  EXPECT_TRUE(allowed_features.Contains("sync-xhr"));
  // This feature does not exist, so should not be advertised as allowed.
  EXPECT_FALSE(allowed_features.Contains("badfeature"));
}

TEST_F(IFramePolicyTest, TestCombinedPolicyOnOriginB) {
  PolicyParserMessageBuffer dummy_logger("", true /* discard_message */);
  ParsedPermissionsPolicy container_policy =
      PermissionsPolicyParser::ParseAttribute(
          "geolocation 'src'; payment 'none'; midi; camera 'src'; gyroscope "
          "'src'",
          SecurityOrigin::CreateFromString(kSelfOrigin),
          SecurityOrigin::CreateFromString(kOriginB), dummy_logger);
  GetPolicy()->UpdateContainerPolicy(
      container_policy, SecurityOrigin::CreateFromString(kOriginB));
  Vector<String> allowed_features = GetPolicy()->allowedFeatures(nullptr);
  // These features are not explicitly allowed.
  EXPECT_FALSE(allowed_features.Contains("fullscreen"));
  EXPECT_FALSE(allowed_features.Contains("payment"));
  // These features are explicitly allowed.
  EXPECT_TRUE(allowed_features.Contains("geolocation"));
  EXPECT_TRUE(allowed_features.Contains("camera"));
  EXPECT_TRUE(allowed_features.Contains("gyroscope"));
  // These are allowed by the attribute, but still blocked by the parent policy.
  EXPECT_FALSE(allowed_features.Contains("midi"));
  // "sync-xhr" is still implicitly allowed on all origins.
  EXPECT_TRUE(allowed_features.Contains("sync-xhr"));
  // This feature does not exist, so should not be advertised as allowed.
  EXPECT_FALSE(allowed_features.Contains("badfeature"));
}

TEST_F(IFramePolicyTest, TestCombinedPolicyOnOriginBSubdomain) {
  PolicyParserMessageBuffer dummy_logger("", true /* discard_message */);
  ParsedPermissionsPolicy container_policy =
      PermissionsPolicyParser::ParseAttribute(
          "geolocation 'src'; payment 'none'; midi; camera 'src'; gyroscope "
          "'src'",
          SecurityOrigin::CreateFromString(kSelfOrigin),
          SecurityOrigin::CreateFromString(kOriginBSubdomain), dummy_logger);
  GetPolicy()->UpdateContainerPolicy(
      container_policy, SecurityOrigin::CreateFromString(kOriginBSubdomain));
  Vector<String> allowed_features = GetPolicy()->allowedFeatures(nullptr);
  // These features are not explicitly allowed.
  EXPECT_FALSE(allowed_features.Contains("fullscreen"));
  EXPECT_FALSE(allowed_features.Contains("payment"));
  EXPECT_FALSE(allowed_features.Contains("gyroscope"));
  // These features are explicitly allowed.
  EXPECT_TRUE(allowed_features.Contains("geolocation"));
  // These are allowed by the attribute, but still blocked by the parent policy.
  EXPECT_FALSE(allowed_features.Contains("midi"));
  EXPECT_FALSE(allowed_features.Contains("camera"));
  // "sync-xhr" is still implicitly allowed on all origins.
  EXPECT_TRUE(allowed_features.Contains("sync-xhr"));
  // This feature does not exist, so should not be advertised as allowed.
  EXPECT_FALSE(allowed_features.Contains("badfeature"));
}

}  // namespace blink
```
Response:
Let's break down the thought process for analyzing the given C++ test file.

1. **Understand the Core Purpose:** The file name `html_iframe_element_test.cc` immediately tells us this is a test file specifically for the `HTMLIFrameElement` class within the Blink rendering engine. The `_test.cc` suffix is a common convention for unit tests.

2. **Identify Key Imports:**  Look at the `#include` statements. These reveal the dependencies and the functionalities being tested.
    * `<gtest/gtest.h>`:  Confirms this is using Google Test, a popular C++ testing framework.
    * `HTMLIFrameElement.h`:  The class under test.
    * `permissions_policy/...`: Indicates a focus on permissions policy aspects of iframes.
    * `WebRuntimeFeaturesBase.h`: Suggests testing features that can be enabled/disabled via runtime flags.
    * `Document.h`, `LocalDOMWindow.h`:  Shows interaction with the DOM structure and the window object.
    * `testing/...`, `sim/...`:  Indicates the use of Blink's testing utilities, likely for setting up a simulated environment.
    * `platform/...`:  Points to platform-level utilities, potentially related to security origins and task management.

3. **Examine the Test Fixture:** The `HTMLIFrameElementTest` class inheriting from `testing::Test` sets up the testing environment.
    * `GetOriginForPermissionsPolicy()`: A helper function to access a protected method, hinting at testing the logic for determining the origin for permissions policy.
    * `SetUp()`:  Initializes a dummy page, window, and an `HTMLIFrameElement`. This is the standard setup for each test case.
    * `TearDown()`: Cleans up resources after each test.
    * Member variables like `page_holder_`, `window_`, `frame_element_`: These are the core components the tests will interact with.

4. **Analyze Individual Test Cases (Focus on Functionality):** Go through each `TEST_F` function and determine what aspect of `HTMLIFrameElement` it's verifying.
    * `FramesUseCorrectOrigin`: Tests how the `src` attribute affects the iframe's origin in different scenarios (about:blank, data URLs, regular URLs).
    * `SandboxFramesUseCorrectOrigin`: Focuses on how the `sandbox` attribute influences the origin (making it opaque).
    * `SameOriginSandboxFramesUseCorrectOrigin`: Checks the `allow-same-origin` sandbox flag.
    * `SrcdocFramesUseCorrectOrigin`: Tests the origin of iframes using the `srcdoc` attribute.
    * `SandboxedSrcdocFramesUseCorrectOrigin`: Combines `sandbox` and `srcdoc`.
    * `RelativeURLsUseCorrectOrigin`: Examines how relative URLs in `src` are resolved.
    * `DefaultContainerPolicy`, `AllowAttributeContainerPolicy`: Test the default and attribute-driven construction of the container policy (permissions policy).
    * `ConstructEmptyContainerPolicy`, `ConstructContainerPolicy`, `ConstructContainerPolicyWithAllowFullscreen`, `ConstructContainerPolicyWithAllowPaymentRequest`, `ConstructContainerPolicyWithAllowAttributes`: These all focus on testing the `ConstructContainerPolicy` method with different attribute combinations (`allow`, `allowfullscreen`, `allowpaymentrequest`).

5. **Identify Relationships with Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The entire test suite revolves around the `<iframe>` element and its attributes (`src`, `sandbox`, `allow`, `allowfullscreen`, `allowpaymentrequest`, `srcdoc`, `policy`, `adauctionheaders`, `sharedstoragewritable`). These attributes directly control iframe behavior in HTML.
    * **JavaScript:** While this test file is C++, the functionalities being tested directly impact JavaScript's behavior within the iframe. For example, the origin and permissions policy determine what APIs and resources the JavaScript code inside the iframe can access. The sandbox attribute restricts JavaScript capabilities.
    * **CSS:** While not directly tested here, the iframe's origin and security context can influence CSS behavior, particularly when dealing with cross-origin iframes and potential style isolation.

6. **Look for Logical Reasoning (Assumptions and Outputs):** For each test, identify the setup (input attributes) and the expected outcome (origin, container policy).
    * **Example:**  If `src` is "http://example.net/" and no `sandbox` attribute is set, the expected output is a non-opaque origin that is different from the parent's. If `sandbox` *is* set, the output is an opaque origin.

7. **Consider User/Programming Errors:** Think about common mistakes developers might make when using iframes, and how these tests might catch such errors.
    * **Incorrect `allow` attribute syntax:** The tests for `AllowAttributeParsingError` specifically address this.
    * **Forgetting the `allow-same-origin` flag when needed:** The test for `SameOriginSandboxFramesUseCorrectOrigin` highlights its importance.
    * **Misunderstanding how `sandbox` affects origins.**
    * **Using features like `adauctionheaders` or `sharedstoragewritable` in insecure contexts.**  The dedicated tests for these attributes exemplify this.

8. **Pay Attention to `SimTest` Cases:**  These tests typically involve loading HTML content and observing the resulting behavior, including console messages. This helps verify error handling and warnings.

9. **Synthesize and Organize:** Finally, group the observations into logical categories (functionality, relation to web techs, logical reasoning, potential errors) to create a clear and comprehensive summary. Use examples from the code to illustrate your points.

Self-Correction/Refinement during the process:

* **Initial thought:**  "This just tests iframe creation."  **Correction:**  The tests go much deeper, specifically focusing on security aspects like origin and permissions policy.
* **Overlooking specific attribute tests:**  Realizing that tests like `Adauctionheaders_SecureContext_Allowed` target very specific iframe attributes and their context-dependent behavior.
* **Not explicitly linking to web technologies:** Initially focusing too much on the C++ code. Realizing the importance of connecting the tested functionalities to how iframes are used in HTML, and how this impacts JavaScript and (indirectly) CSS.
* **Insufficiently detailing logical reasoning:**  Simply stating the test purpose isn't enough. Specifying the *input* (attributes) and *expected output* (origin, policy) makes the reasoning clearer.
* **Missing examples of user errors:**  Actively thinking about what could go wrong from a web developer's perspective makes the analysis more practical.
This C++ source code file, `html_iframe_element_test.cc`, is a **unit test file** for the `HTMLIFrameElement` class within the Blink rendering engine (which is the rendering engine for Chromium). Its primary function is to **verify the correct behavior and functionality of the `HTMLIFrameElement` class**.

Here's a breakdown of its functionalities and connections to web technologies:

**Core Functionalities Being Tested:**

1. **Origin Determination for Permissions Policy:**
   - It tests how the `HTMLIFrameElement` determines its effective security origin, which is crucial for enforcing the Permissions Policy.
   - This includes scenarios with different `src` attributes (e.g., `about:blank`, data URLs, same-origin, cross-origin), the presence or absence of the `sandbox` attribute, and the use of the `srcdoc` attribute.

2. **Permissions Policy Enforcement (Container Policy):**
   - It examines how the `allow` attribute, `allowfullscreen` attribute, and `allowpaymentrequest` attribute contribute to building the "container policy" for the iframe. This policy dictates which features are allowed within the iframe.
   - It tests the `ConstructContainerPolicy` method of `HTMLIFrameElement`.

3. **Handling of Relative URLs:**
   - It verifies that relative URLs in the `src` attribute are correctly resolved against the parent document's origin.

4. **Error Handling and Console Messages:**
   - It includes tests (`PolicyAttributeParsingError`, `AllowAttributeParsingError`) to check how the code handles invalid values in the `policy` and `allow` attributes, ensuring appropriate console warnings are generated.

5. **Feature-Specific Attribute Handling:**
   - It has tests for specific attributes like `adauctionheaders` and `sharedstoragewritable`, checking their behavior in different security contexts (secure vs. insecure).

**Relationship with JavaScript, HTML, and CSS:**

* **HTML:** This test file directly relates to the `<iframe>` HTML element and its attributes. The tests manipulate these attributes (`src`, `sandbox`, `allow`, `allowfullscreen`, `allowpaymentrequest`, `srcdoc`, `policy`, `adauctionheaders`, `sharedstoragewritable`) to verify how `HTMLIFrameElement` interprets them and updates its internal state, particularly concerning security and permissions.

   **Example:**
   ```html
   <iframe src="http://example.net/" allow="fullscreen"></iframe>
   ```
   The test `AllowAttributeContainerPolicy` checks that when the `allow` attribute is set to "fullscreen", the `HTMLIFrameElement` correctly creates a container policy that allows the `fullscreen` feature for the specified origin ("http://example.net/").

* **JavaScript:** The security origin and permissions policy of an iframe directly impact the JavaScript code running inside it. The permissions policy controls which browser features and APIs the iframe's JavaScript can access (e.g., camera, microphone, fullscreen API).

   **Example:**
   If an iframe has `sandbox` attribute without `allow-same-origin`, its JavaScript will be treated as cross-origin and have restricted access to the parent document's resources. The tests verifying the origin in sandboxed iframes directly relate to this JavaScript behavior.

* **CSS:**  While not directly tested in this specific file, the security context and origin of an iframe can indirectly affect CSS behavior. For instance, cross-origin iframes have style isolation by default, preventing styles from leaking between the parent and iframe. The tests ensuring correct origin determination contribute to the foundation of this CSS isolation.

**Logical Reasoning (Hypothesized Input and Output):**

* **Assumption:**  Setting the `src` attribute to a cross-origin URL without the `sandbox` attribute should result in the iframe having a non-opaque origin different from the parent.
   * **Input:** `frame_element_->setAttribute(html_names::kSrcAttr, AtomicString("http://example.net/"));`
   * **Expected Output:** `EXPECT_FALSE(effective_origin->IsSameOriginWith(window_->GetSecurityOrigin()));` and `EXPECT_FALSE(effective_origin->IsOpaque());`

* **Assumption:** Setting the `sandbox` attribute without `allow-same-origin` should result in the iframe having an opaque origin.
   * **Input:** `frame_element_->setAttribute(html_names::kSandboxAttr, g_empty_atom);` and `frame_element_->setAttribute(html_names::kSrcAttr, AtomicString("http://example.com/"));`
   * **Expected Output:** `EXPECT_FALSE(effective_origin->IsSameOriginWith(window_->GetSecurityOrigin()));` and `EXPECT_TRUE(effective_origin->IsOpaque());`

* **Assumption:** The `allow` attribute correctly parses feature names and creates a corresponding container policy.
   * **Input:** `frame_element_->setAttribute(html_names::kAllowAttr, AtomicString("fullscreen"));`
   * **Expected Output:** The container policy should contain an entry for the `fullscreen` feature, restricted to the iframe's origin.

**User or Programming Common Usage Errors:**

1. **Misunderstanding the `sandbox` attribute:**
   - **Error:**  A developer might add the `sandbox` attribute expecting to simply isolate the iframe's JavaScript, but forget that by default, it also makes the origin opaque, potentially breaking same-origin communication if that's desired.
   - **Test Relevance:** The tests for sandboxed iframes (e.g., `SandboxFramesUseCorrectOrigin`) highlight this behavior and help ensure the code correctly implements the default sandboxing rules.

2. **Incorrect syntax in the `allow` attribute:**
   - **Error:**  A developer might mistype a feature name in the `allow` attribute (e.g., `allow="fulscren"` instead of `allow="fullscreen"`).
   - **Test Relevance:** The `AllowAttributeParsingError` test specifically checks for this scenario and verifies that a console warning is generated, helping developers identify such mistakes.

3. **Using security-sensitive features in insecure contexts:**
   - **Error:** A developer might try to use the `adauctionheaders` attribute on an iframe loaded over HTTP.
   - **Test Relevance:** The `Adauctionheaders_InsecureContext_NotAllowed` test catches this common error and confirms that the code prevents the feature from being enabled in insecure contexts, issuing a console warning.

4. **Forgetting the `allow-same-origin` flag when needed:**
   - **Error:**  A developer might sandbox an iframe but still need it to communicate with the parent document via same-origin policies. Forgetting the `allow-same-origin` flag will prevent this.
   - **Test Relevance:** The `SameOriginSandboxFramesUseCorrectOrigin` test verifies the correct behavior when this flag is used.

In summary, `html_iframe_element_test.cc` is a critical component of the Chromium project, ensuring the stability, security, and correct implementation of the `<iframe>` element and its associated attributes, especially in relation to security origins and the Permissions Policy. It helps prevent common developer errors and ensures that web developers can rely on the intended behavior of iframes.

### 提示词
```
这是目录为blink/renderer/core/html/html_iframe_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/html_iframe_element.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/permissions_policy/origin_with_possible_wildcards.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/platform/web_runtime_features.h"
#include "third_party/blink/public/platform/web_runtime_features_base.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/permissions_policy/permissions_policy_parser.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"

namespace blink {

class HTMLIFrameElementTest : public testing::Test {
 public:
  scoped_refptr<const SecurityOrigin> GetOriginForPermissionsPolicy(
      HTMLIFrameElement* element) {
    return element->GetOriginForPermissionsPolicy();
  }

  void SetUp() final {
    const KURL document_url("http://example.com");
    page_holder_ = std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
    window_ = page_holder_->GetFrame().DomWindow();
    window_->document()->SetURL(document_url);
    window_->GetSecurityContext().SetSecurityOriginForTesting(
        SecurityOrigin::Create(document_url));
    frame_element_ =
        MakeGarbageCollected<HTMLIFrameElement>(*window_->document());
  }

  void TearDown() final {
    frame_element_.Clear();
    window_.Clear();
    page_holder_.reset();
  }

 protected:
  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> page_holder_;
  Persistent<LocalDOMWindow> window_;
  Persistent<HTMLIFrameElement> frame_element_;
};

// Test that the correct origin is used when constructing the container policy,
// and that frames which should inherit their parent document's origin do so.
TEST_F(HTMLIFrameElementTest, FramesUseCorrectOrigin) {
  frame_element_->setAttribute(html_names::kSrcAttr,
                               AtomicString("about:blank"));
  scoped_refptr<const SecurityOrigin> effective_origin =
      GetOriginForPermissionsPolicy(frame_element_);
  EXPECT_TRUE(effective_origin->IsSameOriginWith(window_->GetSecurityOrigin()));

  frame_element_->setAttribute(
      html_names::kSrcAttr,
      AtomicString("data:text/html;base64,PHRpdGxlPkFCQzwvdGl0bGU+"));
  effective_origin = GetOriginForPermissionsPolicy(frame_element_);
  EXPECT_FALSE(
      effective_origin->IsSameOriginWith(window_->GetSecurityOrigin()));
  EXPECT_TRUE(effective_origin->IsOpaque());

  frame_element_->setAttribute(html_names::kSrcAttr,
                               AtomicString("http://example.net/"));
  effective_origin = GetOriginForPermissionsPolicy(frame_element_);
  EXPECT_FALSE(
      effective_origin->IsSameOriginWith(window_->GetSecurityOrigin()));
  EXPECT_FALSE(effective_origin->IsOpaque());
}

// Test that a unique origin is used when constructing the container policy in a
// sandboxed iframe.
TEST_F(HTMLIFrameElementTest, SandboxFramesUseCorrectOrigin) {
  frame_element_->setAttribute(html_names::kSandboxAttr, g_empty_atom);
  frame_element_->setAttribute(html_names::kSrcAttr,
                               AtomicString("http://example.com/"));
  scoped_refptr<const SecurityOrigin> effective_origin =
      GetOriginForPermissionsPolicy(frame_element_);
  EXPECT_FALSE(
      effective_origin->IsSameOriginWith(window_->GetSecurityOrigin()));
  EXPECT_TRUE(effective_origin->IsOpaque());

  frame_element_->setAttribute(html_names::kSrcAttr,
                               AtomicString("http://example.net/"));
  effective_origin = GetOriginForPermissionsPolicy(frame_element_);
  EXPECT_FALSE(
      effective_origin->IsSameOriginWith(window_->GetSecurityOrigin()));
  EXPECT_TRUE(effective_origin->IsOpaque());
}

// Test that a sandboxed iframe with the allow-same-origin sandbox flag uses the
// parent document's origin for the container policy.
TEST_F(HTMLIFrameElementTest, SameOriginSandboxFramesUseCorrectOrigin) {
  frame_element_->setAttribute(html_names::kSandboxAttr,
                               AtomicString("allow-same-origin"));
  frame_element_->setAttribute(html_names::kSrcAttr,
                               AtomicString("http://example.com/"));
  scoped_refptr<const SecurityOrigin> effective_origin =
      GetOriginForPermissionsPolicy(frame_element_);
  EXPECT_TRUE(effective_origin->IsSameOriginWith(window_->GetSecurityOrigin()));
  EXPECT_FALSE(effective_origin->IsOpaque());
}

// Test that the parent document's origin is used when constructing the
// container policy in a srcdoc iframe.
TEST_F(HTMLIFrameElementTest, SrcdocFramesUseCorrectOrigin) {
  frame_element_->setAttribute(html_names::kSrcdocAttr,
                               AtomicString("<title>title</title>"));
  scoped_refptr<const SecurityOrigin> effective_origin =
      GetOriginForPermissionsPolicy(frame_element_);
  EXPECT_TRUE(effective_origin->IsSameOriginWith(window_->GetSecurityOrigin()));
}

// Test that a unique origin is used when constructing the container policy in a
// sandboxed iframe with a srcdoc.
TEST_F(HTMLIFrameElementTest, SandboxedSrcdocFramesUseCorrectOrigin) {
  frame_element_->setAttribute(html_names::kSandboxAttr, g_empty_atom);
  frame_element_->setAttribute(html_names::kSrcdocAttr,
                               AtomicString("<title>title</title>"));
  scoped_refptr<const SecurityOrigin> effective_origin =
      GetOriginForPermissionsPolicy(frame_element_);
  EXPECT_FALSE(
      effective_origin->IsSameOriginWith(window_->GetSecurityOrigin()));
  EXPECT_TRUE(effective_origin->IsOpaque());
}

// Test that iframes with relative src urls correctly construct their origin
// relative to the parent document.
TEST_F(HTMLIFrameElementTest, RelativeURLsUseCorrectOrigin) {
  // Host-relative URLs should resolve to the same domain as the parent.
  frame_element_->setAttribute(html_names::kSrcAttr,
                               AtomicString("index2.html"));
  scoped_refptr<const SecurityOrigin> effective_origin =
      GetOriginForPermissionsPolicy(frame_element_);
  EXPECT_TRUE(effective_origin->IsSameOriginWith(window_->GetSecurityOrigin()));

  // Scheme-relative URLs should not resolve to the same domain as the parent.
  frame_element_->setAttribute(html_names::kSrcAttr,
                               AtomicString("//example.net/index2.html"));
  effective_origin = GetOriginForPermissionsPolicy(frame_element_);
  EXPECT_FALSE(
      effective_origin->IsSameOriginWith(window_->GetSecurityOrigin()));
}

// Test that various iframe attribute configurations result in the correct
// container policies.

// Test that the correct container policy is constructed on an iframe element.
TEST_F(HTMLIFrameElementTest, DefaultContainerPolicy) {
  frame_element_->setAttribute(html_names::kSrcAttr,
                               AtomicString("http://example.net/"));
  frame_element_->UpdateContainerPolicyForTests();

  const ParsedPermissionsPolicy& container_policy =
      frame_element_->GetFramePolicy().container_policy;
  EXPECT_EQ(0UL, container_policy.size());
}

// Test that the allow attribute results in a container policy which is
// restricted to the domain in the src attribute.
TEST_F(HTMLIFrameElementTest, AllowAttributeContainerPolicy) {
  frame_element_->setAttribute(html_names::kSrcAttr,
                               AtomicString("http://example.net/"));
  frame_element_->setAttribute(html_names::kAllowAttr,
                               AtomicString("fullscreen"));
  frame_element_->UpdateContainerPolicyForTests();

  const ParsedPermissionsPolicy& container_policy1 =
      frame_element_->GetFramePolicy().container_policy;

  EXPECT_EQ(1UL, container_policy1.size());
  EXPECT_EQ(mojom::blink::PermissionsPolicyFeature::kFullscreen,
            container_policy1[0].feature);
  EXPECT_FALSE(container_policy1[0].matches_all_origins);
  EXPECT_EQ(1UL, container_policy1[0].allowed_origins.size());
  EXPECT_EQ("http://example.net",
            container_policy1[0].allowed_origins.begin()->Serialize());

  frame_element_->setAttribute(html_names::kAllowAttr,
                               AtomicString("payment; fullscreen"));
  frame_element_->UpdateContainerPolicyForTests();

  const ParsedPermissionsPolicy& container_policy2 =
      frame_element_->GetFramePolicy().container_policy;
  EXPECT_EQ(2UL, container_policy2.size());
  EXPECT_TRUE(container_policy2[0].feature ==
                  mojom::blink::PermissionsPolicyFeature::kFullscreen ||
              container_policy2[1].feature ==
                  mojom::blink::PermissionsPolicyFeature::kFullscreen);
  EXPECT_TRUE(container_policy2[0].feature ==
                  mojom::blink::PermissionsPolicyFeature::kPayment ||
              container_policy2[1].feature ==
                  mojom::blink::PermissionsPolicyFeature::kPayment);
  EXPECT_EQ(1UL, container_policy2[0].allowed_origins.size());
  EXPECT_EQ("http://example.net",
            container_policy2[0].allowed_origins.begin()->Serialize());
  EXPECT_FALSE(container_policy2[1].matches_all_origins);
  EXPECT_EQ(1UL, container_policy2[1].allowed_origins.size());
  EXPECT_EQ("http://example.net",
            container_policy2[1].allowed_origins.begin()->Serialize());
}

// Test the ConstructContainerPolicy method when no attributes are set on the
// iframe element.
TEST_F(HTMLIFrameElementTest, ConstructEmptyContainerPolicy) {
  ParsedPermissionsPolicy container_policy =
      frame_element_->ConstructContainerPolicy();
  EXPECT_EQ(0UL, container_policy.size());
}

// Test the ConstructContainerPolicy method when the "allow" attribute is used
// to enable features in the frame.
TEST_F(HTMLIFrameElementTest, ConstructContainerPolicy) {
  frame_element_->setAttribute(html_names::kAllowAttr,
                               AtomicString("payment; usb"));
  ParsedPermissionsPolicy container_policy =
      frame_element_->ConstructContainerPolicy();
  EXPECT_EQ(2UL, container_policy.size());
  EXPECT_EQ(mojom::blink::PermissionsPolicyFeature::kPayment,
            container_policy[0].feature);
  EXPECT_FALSE(container_policy[0].matches_all_origins);
  EXPECT_EQ(1UL, container_policy[0].allowed_origins.size());
  EXPECT_TRUE(container_policy[0].allowed_origins.begin()->DoesMatchOrigin(
      GetOriginForPermissionsPolicy(frame_element_)->ToUrlOrigin()));
  EXPECT_EQ(mojom::blink::PermissionsPolicyFeature::kUsb,
            container_policy[1].feature);
  EXPECT_EQ(1UL, container_policy[1].allowed_origins.size());
  EXPECT_TRUE(container_policy[1].allowed_origins.begin()->DoesMatchOrigin(
      GetOriginForPermissionsPolicy(frame_element_)->ToUrlOrigin()));
}

// Test the ConstructContainerPolicy method when the "allowfullscreen" attribute
// is used to enable fullscreen in the frame.
TEST_F(HTMLIFrameElementTest, ConstructContainerPolicyWithAllowFullscreen) {
  frame_element_->SetBooleanAttribute(html_names::kAllowfullscreenAttr, true);

  ParsedPermissionsPolicy container_policy =
      frame_element_->ConstructContainerPolicy();
  EXPECT_EQ(1UL, container_policy.size());
  EXPECT_EQ(mojom::blink::PermissionsPolicyFeature::kFullscreen,
            container_policy[0].feature);
  EXPECT_TRUE(container_policy[0].matches_all_origins);
}

// Test the ConstructContainerPolicy method when the "allowpaymentrequest"
// attribute is used to enable the paymentrequest API in the frame.
TEST_F(HTMLIFrameElementTest, ConstructContainerPolicyWithAllowPaymentRequest) {
  frame_element_->setAttribute(html_names::kAllowAttr, AtomicString("usb"));
  frame_element_->SetBooleanAttribute(html_names::kAllowpaymentrequestAttr,
                                      true);

  ParsedPermissionsPolicy container_policy =
      frame_element_->ConstructContainerPolicy();
  EXPECT_EQ(2UL, container_policy.size());
  EXPECT_EQ(mojom::blink::PermissionsPolicyFeature::kUsb,
            container_policy[0].feature);
  EXPECT_FALSE(container_policy[0].matches_all_origins);
  EXPECT_EQ(1UL, container_policy[0].allowed_origins.size());
  EXPECT_TRUE(container_policy[0].allowed_origins.begin()->DoesMatchOrigin(
      GetOriginForPermissionsPolicy(frame_element_)->ToUrlOrigin()));
  EXPECT_EQ(mojom::blink::PermissionsPolicyFeature::kPayment,
            container_policy[1].feature);
}

// Test the ConstructContainerPolicy method when both "allowfullscreen" and
// "allowpaymentrequest" attributes are set on the iframe element, and the
// "allow" attribute is also used to override the paymentrequest feature. In the
// resulting container policy, the payment and usb features should be enabled
// only for the frame's origin, (since the allow attribute overrides
// allowpaymentrequest,) while fullscreen should be enabled for all origins.
TEST_F(HTMLIFrameElementTest, ConstructContainerPolicyWithAllowAttributes) {
  frame_element_->setAttribute(html_names::kAllowAttr,
                               AtomicString("payment; usb"));
  frame_element_->SetBooleanAttribute(html_names::kAllowfullscreenAttr, true);
  frame_element_->SetBooleanAttribute(html_names::kAllowpaymentrequestAttr,
                                      true);

  ParsedPermissionsPolicy container_policy =
      frame_element_->ConstructContainerPolicy();
  EXPECT_EQ(3UL, container_policy.size());
  EXPECT_EQ(mojom::blink::PermissionsPolicyFeature::kPayment,
            container_policy[0].feature);
  EXPECT_FALSE(container_policy[0].matches_all_origins);
  EXPECT_EQ(1UL, container_policy[0].allowed_origins.size());
  EXPECT_TRUE(container_policy[0].allowed_origins.begin()->DoesMatchOrigin(
      GetOriginForPermissionsPolicy(frame_element_)->ToUrlOrigin()));
  EXPECT_EQ(mojom::blink::PermissionsPolicyFeature::kUsb,
            container_policy[1].feature);
  EXPECT_EQ(1UL, container_policy[1].allowed_origins.size());
  EXPECT_TRUE(container_policy[1].allowed_origins.begin()->DoesMatchOrigin(
      GetOriginForPermissionsPolicy(frame_element_)->ToUrlOrigin()));
  EXPECT_EQ(mojom::blink::PermissionsPolicyFeature::kFullscreen,
            container_policy[2].feature);
}

using HTMLIFrameElementSimTest = SimTest;

TEST_F(HTMLIFrameElementSimTest, PolicyAttributeParsingError) {
  SimRequest main_resource("https://example.com", "text/html");
  LoadURL("https://example.com");
  main_resource.Complete(R"(
    <iframe policy="bad-feature-name"></iframe>
  )");

  // Note: Parsing of policy attribute string, i.e. call to
  // HTMLFrameOwnerElement::UpdateRequiredPolicy(), happens twice in above
  // situation:
  // - HTMLFrameOwnerElement::LoadOrRedirectSubframe()
  // - HTMLIFrameElement::ParseAttribute()
  EXPECT_EQ(ConsoleMessages().size(), 2u);
  for (const auto& message : ConsoleMessages()) {
    EXPECT_TRUE(
        message.StartsWith("Unrecognized document policy feature name"));
  }
}

TEST_F(HTMLIFrameElementSimTest, AllowAttributeParsingError) {
  SimRequest main_resource("https://example.com", "text/html");
  LoadURL("https://example.com");
  main_resource.Complete(R"(
    <iframe
      allow="bad-feature-name"
      allowfullscreen
      allowpayment
      sandbox=""></iframe>
  )");

  EXPECT_EQ(ConsoleMessages().size(), 1u)
      << "Allow attribute parsing should only generate console message once, "
         "even though there might be multiple call to "
         "PermissionsPolicyParser::ParseAttribute.";
  EXPECT_TRUE(ConsoleMessages().front().StartsWith("Unrecognized feature"))
      << "Expect permissions policy parser raising error for unrecognized "
         "feature but got: "
      << ConsoleMessages().front();
}

TEST_F(HTMLIFrameElementSimTest, Adauctionheaders_SecureContext_Allowed) {
  SimRequest main_resource("https://example.com", "text/html");
  LoadURL("https://example.com");
  main_resource.Complete(R"(
    <iframe adauctionheaders></iframe>
  )");

  EXPECT_TRUE(ConsoleMessages().empty());
}

TEST_F(HTMLIFrameElementSimTest, Adauctionheaders_InsecureContext_NotAllowed) {
  SimRequest main_resource("http://example.com", "text/html");
  LoadURL("http://example.com");
  main_resource.Complete(R"(
    <iframe adauctionheaders></iframe>
  )");

  EXPECT_EQ(ConsoleMessages().size(), 1u);
  EXPECT_TRUE(ConsoleMessages().front().StartsWith(
      "adAuctionHeaders: Protected Audience APIs "
      "are only available in secure contexts."))
      << "Unexpected error; got: " << ConsoleMessages().front();
}

TEST_F(HTMLIFrameElementSimTest, Sharedstoragewritable_SecureContext_Allowed) {
  WebRuntimeFeaturesBase::EnableSharedStorageAPI(true);
  WebRuntimeFeaturesBase::EnableSharedStorageAPIM118(true);
  SimRequest main_resource("https://example.com", "text/html");
  LoadURL("https://example.com");
  main_resource.Complete(R"(
    <iframe
      allow="shared-storage"
      sharedstoragewritable></iframe>
  )");

  EXPECT_TRUE(ConsoleMessages().empty());
}

TEST_F(HTMLIFrameElementSimTest,
       Sharedstoragewritable_InsecureContext_NotAllowed) {
  WebRuntimeFeaturesBase::EnableSharedStorageAPI(true);
  WebRuntimeFeaturesBase::EnableSharedStorageAPIM118(true);
  SimRequest main_resource("http://example.com", "text/html");
  LoadURL("http://example.com");
  main_resource.Complete(R"(
    <iframe
      allow="shared-storage"
      sharedstoragewritable></iframe>
  )");

  EXPECT_EQ(ConsoleMessages().size(), 1u);
  EXPECT_TRUE(ConsoleMessages().front().StartsWith(
      "sharedStorageWritable: sharedStorage operations are only available in "
      "secure contexts."))
      << "Expect error that Shared Storage operations are not allowed in "
         "insecure contexts but got: "
      << ConsoleMessages().front();
}

}  // namespace blink
```
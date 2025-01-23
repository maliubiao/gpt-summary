Response:
The user is asking for a summary of the functionality of the provided C++ code file, `html_permission_element_test.cc`, which is part of the Chromium Blink rendering engine.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Functionality:** The filename strongly suggests this file contains tests for the `HTMLPermissionElement`. This will be the central theme of the summary.

2. **Scan the Test Names:** Look for patterns and keywords in the `TEST_F` macro calls. Keywords like "GrantedSelectorDisplayNone", "MovePEPCToAnotherDocument", "IntersectionChanged", "ClickingDisablePseudoClass", "InvalidatePEPCAfterMove", "InvalidatePEPCAfterResize", etc., provide direct clues about the features being tested.

3. **Analyze Test Logic (High Level):**  Without diving deep into every line, understand the basic actions in the tests:
    * Creating a permission element.
    * Manipulating its properties (style, attributes).
    * Simulating user interactions (scrolling).
    * Checking expected behavior (clicking enabled/disabled, console messages, CSS pseudo-classes).
    * Using mock `permission_service()` to simulate permission status changes.
    * Using `IntersectionObserver` related methods to check visibility.

4. **Connect Tests to Web Technologies:**  Consider how the tested functionalities relate to HTML, CSS, and JavaScript:
    * **HTML:** The `<permission>` element itself, attributes, embedding in iframes.
    * **CSS:**  Styling the element, using pseudo-classes like `:granted`, `:occluded`, `:invalid-style`. The impact of CSS properties like `display`, `transform`, `opacity`, `clip-path`.
    * **JavaScript:**  While the tests are in C++, they simulate JavaScript actions or test features triggered by JavaScript (like `requestAnimationFrame`).

5. **Identify Logical Inferences and Assumptions:** Look for tests where the outcome depends on a sequence of actions or external factors. For example, the tests involving scrolling or moving elements rely on the assumption that the layout engine correctly updates the element's visibility and clickability.

6. **Spot Common Usage Errors:** Consider what mistakes a web developer might make when using the `<permission>` element. This is often related to incorrect styling, placement, or understanding of the element's lifecycle and interaction with the permission system.

7. **Structure the Summary:** Organize the findings into logical categories:
    * Overall purpose.
    * Specific features tested.
    * Relationship to web technologies (with examples).
    * Logical inferences and assumptions.
    * Common usage errors.

8. **Refine and Elaborate:**  Add detail to each category based on the analysis. For example, instead of just saying "tests CSS," provide specific CSS properties and pseudo-classes.

9. **Address the "Part 3" Instruction:** Explicitly state that this part of the test suite focuses on specific aspects of the `HTMLPermissionElement`.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus solely on the C++ testing aspects.
* **Correction:** Recognize the need to connect the C++ tests back to the web platform features they are validating.
* **Initial thought:**  List every test individually.
* **Correction:** Group tests by functionality to create a more concise and understandable summary.
* **Initial thought:**  Assume in-depth knowledge of Blink internals.
* **Correction:** Explain concepts in a way that is understandable to someone familiar with web development but not necessarily the Blink engine.

By following these steps, we can generate a comprehensive and informative summary of the `html_permission_element_test.cc` file.
Based on the provided code snippet, here's a breakdown of the functionalities tested in this part of `html_permission_element_test.cc`:

**Overall Functionality (Based on this Snippet):**

This section of the test file focuses on verifying the behavior of the `<permission>` HTML element in various scenarios, particularly concerning its **visibility, clickability, and interaction with CSS and the browser's permission system.**  It builds upon the foundational tests in earlier parts by exploring more complex interactions and edge cases.

**Specific Functionalities Tested and their Relation to Web Technologies:**

1. **Interaction with Content Security Policy (CSP):**
   - **Function:** Checks if a `<permission>` element embedded in an iframe correctly triggers a console error if the necessary `frame-ancestors` CSP directive is missing.
   - **Relation to HTML:**  Deals with embedding content using `<iframe>`.
   - **Relation to JavaScript:** The console error is a form of feedback to developers, often seen in the browser's developer tools.
   - **Example:**
     - **Assumption (Input):** An HTML page on `https://example.test` embeds an iframe from `https://example.com` containing a `<permission>` element. The parent page (`https://example.test`) lacks the `frame-ancestors 'self' example.com;` CSP directive.
     - **Output:** The browser's console for the iframe should display an error message indicating that the `<permission>` element requires the `frame-ancestors` directive.

2. **CSS `:granted` Pseudo-class:**
   - **Function:** Verifies that the `:granted` CSS pseudo-class correctly hides and shows the `<permission>` element based on the permission's status.
   - **Relation to HTML:**  Targets the `<permission>` element.
   - **Relation to CSS:** Tests the functionality of a specific CSS pseudo-class.
   - **Example:**
     - **Assumption (Input):** An HTML page includes the CSS rule `permission:granted { display: none; }`. A `<permission type="geolocation">` element exists on the page.
     - **Scenario 1 (Output):** When the geolocation permission is granted, the `<permission>` element should have `display: none` applied and effectively be hidden.
     - **Scenario 2 (Output):** When the geolocation permission is denied, the `:granted` rule no longer applies, and the `<permission>` element should revert to its default display (e.g., `inline-block`).

3. **Moving `<permission>` Element Between Documents (Iframe):**
   - **Function:**  Tests the behavior of a `<permission>` element when it's moved from the parent document to an iframe's document. This test is currently disabled (`DISABLED_`).
   - **Relation to HTML:** Involves manipulating the DOM structure and moving elements between documents.
   - **Relation to JavaScript (Implied):**  DOM manipulation is a core part of JavaScript functionality.
   - **Hypothetical Example (if enabled):**
     - **Assumption (Input):** A `<permission type="camera">` element is initially in the main document. JavaScript (or the browser's internal logic) moves this element into the document of a child iframe.
     - **Output:** The test would likely verify if the permission element remains functional and correctly interacts with the permission service in the new document context. It might also check if the click-to-activate delay and other behaviors are maintained.

4. **Interaction with Intersection Observer (Visibility and Clickability):**
   - **Function:**  Extensive tests focusing on how the visibility of the `<permission>` element, as determined by the Intersection Observer, affects its clickability. It checks scenarios where the element is:
     - Fully visible within the viewport.
     - Partially visible or clipped.
     - Completely outside the viewport.
     - Occluded by other elements.
     - Subject to CSS transformations (rotate, opacity, clip-path).
   - **Relation to HTML:**  The placement and structure of the `<permission>` element and surrounding elements are crucial.
   - **Relation to CSS:** CSS properties influence the layout and visibility of elements, directly impacting intersection.
   - **Relation to JavaScript (Implied):**  While the tests are in C++, the Intersection Observer API is exposed to JavaScript, and its behavior is being validated here.
   - **Examples:**
     - **Scrolling:** Scrolling the page to move the `<permission>` element in and out of the viewport should toggle its clickability after a short delay.
     - **Occlusion:** Placing a `<div>` element on top of the `<permission>` element should disable its clickability. Removing the `<div>` should re-enable it after a delay.
     - **CSS Transforms:** Applying `transform: rotate()` to a container of the `<permission>` element can occlude or distort it, affecting clickability.
     - **CSS Opacity:** Setting `opacity` on a container might occlude the `<permission>` element.
     - **CSS Clip-path:** Using `clip-path` on a container might make the `<permission>` element partially visible, affecting its clickability.

5. **CSS `:occluded` and `:invalid-style` Pseudo-classes:**
   - **Function:** Tests if the `:occluded` pseudo-class correctly applies when the `<permission>` element is visually obstructed by another element, and if `:invalid-style` applies when the styling of the element doesn't meet accessibility requirements (e.g., insufficient contrast).
   - **Relation to HTML:**  Targets the `<permission>` element and surrounding elements for occlusion tests. Styling is applied via the `style` attribute.
   - **Relation to CSS:** Validates the behavior of these specific CSS pseudo-classes.
   - **Example:**
     - **`:occluded`:** Placing a `<div>` with a solid background on top of the `<permission>` element should cause it to match the `:occluded` pseudo-class.
     - **`:invalid-style`:** Setting the text color and background color of the `<permission>` element to colors with insufficient contrast should cause it to match the `:invalid-style` pseudo-class.

6. **Layout Changes and Invalidation:**
   - **Function:**  Verifies that changes to the layout of the `<permission>` element or its containing elements (position, size, transforms) correctly trigger an invalidation, temporarily disabling the element's clickability until the layout settles.
   - **Relation to HTML:**  Manipulating element attributes (e.g., `style`).
   - **Relation to CSS:** CSS properties control layout.
   - **Relation to JavaScript (Implied):** Layout changes can be triggered by JavaScript manipulating the DOM or CSS.
   - **Examples:**
     - **Moving the element:** Changing the `top` or `left` style of the `<permission>` element should temporarily disable clicking.
     - **Resizing the element:** Changing the `width` or `height` style.
     - **Moving a container:** Changing the position of a parent element.
     - **Applying transforms to a container:** Using CSS `transform` on a parent.

7. **Layout Changes in `requestAnimationFrame`:**
   - **Function:** Tests a specific scenario where layout changes to the `<permission>` element are performed within a `requestAnimationFrame` callback. It ensures that while the element is temporarily unclickable due to the layout change, this doesn't incorrectly trigger an "intersection changed" lifecycle update.
   - **Relation to HTML:**  Targets the `<permission>` element's style.
   - **Relation to CSS:** CSS properties (width) are being modified.
   - **Relation to JavaScript:**  Uses the `requestAnimationFrame` API, which is a JavaScript feature.

**Common User or Programming Errors (Examples from the Tests):**

* **Forgetting `frame-ancestors` CSP directive:** Embedding a `<permission>` element in an iframe without the appropriate CSP can lead to unexpected behavior or errors.
* **Incorrectly assuming immediate clickability after layout changes:** The tests demonstrate that after layout modifications (moving, resizing, etc.), there's a short delay before the `<permission>` element becomes clickable again. Developers need to account for this.
* **Overlapping elements without understanding occlusion:**  Developers might accidentally place other elements on top of the `<permission>` element, making it unclickable. The `:occluded` pseudo-class provides a way to visually indicate this.
* **Insufficient color contrast:**  Styling the `<permission>` element with poor color contrast can make it inaccessible. The `:invalid-style` pseudo-class helps identify such issues.
* **Not understanding the impact of CSS transforms and clipping:** CSS properties like `transform` and `clip-path` on the `<permission>` element or its ancestors can affect its visibility and clickability in ways that might not be immediately obvious.

**Summary of this Part:**

This specific part of the `html_permission_element_test.cc` file thoroughly tests the `<permission>` element's behavior in scenarios involving:

* **Integration with iframes and Content Security Policy.**
* **Dynamic behavior based on permission status (using the `:granted` pseudo-class).**
* **Complex interactions with the Intersection Observer, ensuring clickability is correctly managed based on visibility and occlusion.**
* **The application of CSS pseudo-classes (`:occluded`, `:invalid-style`) for indicating visibility and accessibility issues.**
* **The impact of layout changes, even those triggered within `requestAnimationFrame`, on the element's clickability.**

Essentially, this section delves into the more nuanced aspects of how the `<permission>` element interacts with the rendering engine, CSS, and the browser's permission system to provide a robust and user-friendly experience.

### 提示词
```
这是目录为blink/renderer/core/html/html_permission_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
red_callback(
        base::BindOnce(&NotReachedForPEPCRegistered));
    base::RunLoop().RunUntilIdle();
    // Should console log a error message due to missing 'frame-ancestors' CSP
    auto& first_console_messages =
        static_cast<frame_test_helpers::TestWebFrameClient*>(
            first_child_frame->Client())
            ->ConsoleMessages();
    EXPECT_EQ(first_console_messages.size(), 2u);
    EXPECT_TRUE(first_console_messages.front().Contains(
        "is not allowed without the CSP 'frame-ancestors' directive present."));
    first_console_messages.clear();
    permission_service()->set_pepc_registered_callback(base::NullCallback());
  }
}

// Test that a permission element can be hidden (and shown again) by using the
// ":granted" pseudo-class selector.
TEST_F(HTMLPemissionElementSimTest, GrantedSelectorDisplayNone) {
  SimRequest main_resource("https://example.test", "text/html");
  LoadURL("https://example.test");
  main_resource.Complete(R"(
    <body>
    <style>
      permission:granted { display: none; }
    </style>
    </body>
  )");

  auto* permission_element =
      CreatePermissionElement(GetDocument(), "geolocation");
  // Calling one more time waiting for the cache observer.
  permission_service()->WaitForPermissionObserverAdded();
  permission_service()->WaitForPermissionObserverAdded();
  EXPECT_TRUE(permission_element->GetComputedStyle());
  EXPECT_EQ(
      EDisplay::kInlineBlock,
      permission_element->GetComputedStyle()->GetDisplayStyle().Display());

  // The permission becomes granted, hiding the permission element because of
  // the style.
  permission_service()->NotifyPermissionStatusChange(
      PermissionName::GEOLOCATION, MojoPermissionStatus::GRANTED);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  // An element with "display: none" does not have a computed style.
  EXPECT_FALSE(permission_element->GetComputedStyle());

  // The permission stops being granted, the permission element is no longer
  // hidden.
  permission_service()->NotifyPermissionStatusChange(
      PermissionName::GEOLOCATION, MojoPermissionStatus::DENIED);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  EXPECT_TRUE(permission_element->GetComputedStyle());
  EXPECT_EQ(
      EDisplay::kInlineBlock,
      permission_element->GetComputedStyle()->GetDisplayStyle().Display());
}

// TODO(crbug.com/375231573): We should verify this test again. It's likely when
// moving PEPC between documents, the execution context binding to permission
// service will be changed.
TEST_F(HTMLPemissionElementSimTest, DISABLED_MovePEPCToAnotherDocument) {
  SimRequest main_resource("https://example.test/", "text/html");
  SimRequest iframe_resource("https://example.test/foo.html", "text/html");
  LoadURL("https://example.test/");
  main_resource.Complete(R"HTML(
  <body>
      <iframe src='https://example.test/foo.html'
        allow="camera *">
      </iframe>
  </body>
  )HTML");
  iframe_resource.Finish();

  Compositor().BeginFrame();
  auto* permission_element =
      CreatePermissionElement(*MainFrame().GetFrame()->GetDocument(), "camera");
  EXPECT_FALSE(permission_element->IsClickingEnabled());
  DeferredChecker checker(permission_element);
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled*/ true);
  auto* child_frame = To<WebLocalFrameImpl>(MainFrame().FirstChild());
  auto& new_document = *child_frame->GetFrame()->GetDocument();
  new_document.body()->AppendChild(permission_element);
  permission_service()->WaitForClientDisconnected();
  EXPECT_FALSE(permission_element->IsClickingEnabled());
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled*/ true);
}

class HTMLPemissionElementIntersectionTest
    : public HTMLPemissionElementSimTest {
 public:
  static constexpr int kViewportWidth = 800;
  static constexpr int kViewportHeight = 600;

 protected:
  HTMLPemissionElementIntersectionTest() = default;

  void SetUp() override {
    HTMLPemissionElementSimTest::SetUp();
    IntersectionObserver::SetThrottleDelayEnabledForTesting(false);
    WebView().MainFrameWidget()->Resize(
        gfx::Size(kViewportWidth, kViewportHeight));
  }

  void TearDown() override {
    IntersectionObserver::SetThrottleDelayEnabledForTesting(true);
    HTMLPemissionElementSimTest::TearDown();
  }

  void WaitForIntersectionVisibilityChanged(
      HTMLPermissionElement* element,
      HTMLPermissionElement::IntersectionVisibility visibility) {
    // The intersection observer might only detect elements that enter/leave the
    // viewport after a cycle is complete.
    GetDocument().View()->UpdateAllLifecyclePhasesForTest();
    EXPECT_EQ(element->IntersectionVisibilityForTesting(), visibility);
  }

  void TestContainerStyleAffectsVisibility(
      CSSPropertyID property_name,
      const String& property_value,
      HTMLPermissionElement::IntersectionVisibility expect_visibility) {
    SimRequest main_resource("https://example.test/", "text/html");
    LoadURL("https://example.test/");
    main_resource.Complete(R"HTML(
    <div id='container' style='position: fixed; left: 100px; top: 100px; width: 100px; height: 100px;'>
      <permission id='camera' type='camera'>
    </div>
    )HTML");

    Compositor().BeginFrame();
    auto* permission_element = To<HTMLPermissionElement>(
        GetDocument().QuerySelector(AtomicString("permission")));
    auto* div =
        To<HTMLDivElement>(GetDocument().QuerySelector(AtomicString("div")));

    WaitForIntersectionVisibilityChanged(
        permission_element,
        HTMLPermissionElement::IntersectionVisibility::kFullyVisible);
    DeferredChecker checker(permission_element);
    checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                           /*expected_enabled*/ true);

    div->SetInlineStyleProperty(property_name, property_value);
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
    WaitForIntersectionVisibilityChanged(permission_element, expect_visibility);
    checker.CheckClickingEnabled(/*expected_enabled*/ false);
  }
};

TEST_F(HTMLPemissionElementIntersectionTest, IntersectionChanged) {
  SimRequest main_resource("https://example.test/", "text/html");
  LoadURL("https://example.test/");
  main_resource.Complete(R"HTML(
    <div id='heading' style='height: 100px;'></div>
    <permission id='camera' type='camera'>
    <div id='trailing' style='height: 700px;'></div>
  )HTML");

  Compositor().BeginFrame();
  auto* permission_element = To<HTMLPermissionElement>(
      GetDocument().QuerySelector(AtomicString("permission")));
  WaitForIntersectionVisibilityChanged(
      permission_element,
      HTMLPermissionElement::IntersectionVisibility::kFullyVisible);
  DeferredChecker checker(permission_element);
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled*/ true);
  GetDocument().View()->LayoutViewport()->ScrollBy(
      ScrollOffset(0, kViewportHeight), mojom::blink::ScrollType::kUser);
  WaitForIntersectionVisibilityChanged(
      permission_element,
      HTMLPermissionElement::IntersectionVisibility::kOutOfViewportOrClipped);
  EXPECT_FALSE(permission_element->IsClickingEnabled());
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled*/ false);
  GetDocument().View()->LayoutViewport()->ScrollBy(
      ScrollOffset(0, -kViewportHeight), mojom::blink::ScrollType::kUser);

  // The element is fully visible now but unclickable for a short delay.
  WaitForIntersectionVisibilityChanged(
      permission_element,
      HTMLPermissionElement::IntersectionVisibility::kFullyVisible);
  EXPECT_FALSE(permission_element->IsClickingEnabled());
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled*/ true);
  EXPECT_EQ(permission_element->IntersectionVisibilityForTesting(),
            HTMLPermissionElement::IntersectionVisibility::kFullyVisible);
  EXPECT_TRUE(permission_element->IsClickingEnabled());
}

TEST_F(HTMLPemissionElementIntersectionTest,
       IntersectionVisibleOverlapsRecentAttachedInterval) {
  SimRequest main_resource("https://example.test/", "text/html");
  LoadURL("https://example.test/");
  main_resource.Complete(R"HTML(
    <div id='heading' style='height: 700px;'></div>
    <permission id='camera' type='camera'>
  )HTML");

  Compositor().BeginFrame();
  auto* permission_element = To<HTMLPermissionElement>(
      GetDocument().QuerySelector(AtomicString("permission")));
  WaitForIntersectionVisibilityChanged(
      permission_element,
      HTMLPermissionElement::IntersectionVisibility::kOutOfViewportOrClipped);
  permission_element->DisableClickingTemporarily(
      HTMLPermissionElement::DisableReason::kRecentlyAttachedToLayoutTree,
      base::Milliseconds(600));
  DeferredChecker checker(permission_element);

  checker.CheckClickingEnabledAfterDelay(base::Milliseconds(300),
                                         /*expected_enabled*/ false);
  // The `kIntersectionRecentlyFullyVisible` cooldown time which is overlapping
  // `kRecentlyAttachedToLayoutTree` will not extend the cooldown time, just
  // change the disable reason.
  GetDocument().View()->LayoutViewport()->ScrollBy(
      ScrollOffset(0, kViewportHeight), mojom::blink::ScrollType::kUser);
  WaitForIntersectionVisibilityChanged(
      permission_element,
      HTMLPermissionElement::IntersectionVisibility::kFullyVisible);
  permission_element->EnableClicking(
      HTMLPermissionElement::DisableReason::kIntersectionWithViewportChanged);
  EXPECT_FALSE(permission_element->IsClickingEnabled());
  EXPECT_FALSE(permission_element->isValid());
  checker.CheckClickingEnabledAfterDelay(base::Milliseconds(300),
                                         /*expected_enabled*/ true);
  EXPECT_TRUE(permission_element->isValid());
}

TEST_F(HTMLPemissionElementIntersectionTest,
       IntersectionChangedDisableEnableDisable) {
  SimRequest main_resource("https://example.test/", "text/html");
  LoadURL("https://example.test/");
  main_resource.Complete(R"HTML(
    <div id='cover' style='position: fixed; left: 0px; top: 100px; width: 100px; height: 100px;'></div>
    <permission id='camera' type='camera'>
  )HTML");

  Compositor().BeginFrame();
  auto* permission_element = To<HTMLPermissionElement>(
      GetDocument().QuerySelector(AtomicString("permission")));
  auto* div =
      To<HTMLDivElement>(GetDocument().QuerySelector(AtomicString("div")));
  WaitForIntersectionVisibilityChanged(
      permission_element,
      HTMLPermissionElement::IntersectionVisibility::kFullyVisible);
  DeferredChecker checker(permission_element);
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled*/ true);

  // Placing the div over the element disables it.
  div->SetInlineStyleProperty(CSSPropertyID::kTop, "0px");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  WaitForIntersectionVisibilityChanged(
      permission_element,
      HTMLPermissionElement::IntersectionVisibility::kOccludedOrDistorted);

  // Moving the div again will re-enable the element after a delay. Deliberately
  // don't make any calls that result in calling
  // PermissionElement::IsClickingEnabled.
  div->SetInlineStyleProperty(CSSPropertyID::kTop, "100px");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();

  // Placing the div over the element disables it again.
  div->SetInlineStyleProperty(CSSPropertyID::kTop, "0px");
  WaitForIntersectionVisibilityChanged(
      permission_element,
      HTMLPermissionElement::IntersectionVisibility::kOccludedOrDistorted);
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled*/ false);
  auto& console_messages =
      static_cast<frame_test_helpers::TestWebFrameClient*>(MainFrame().Client())
          ->ConsoleMessages();
  EXPECT_EQ(console_messages.size(), 2u);
  EXPECT_EQ(
      console_messages.front(),
      String::Format("The permission element 'camera' cannot be activated due "
                     "to intersection occluded or distorted."));
  EXPECT_EQ(console_messages.back(),
            String::Format("The permission element is occluded by node %s",
                           div->ToString().Utf8().c_str()));
}

TEST_F(HTMLPemissionElementIntersectionTest, ClickingDisablePseudoClass) {
  SimRequest main_resource("https://example.test/", "text/html");
  LoadURL("https://example.test/");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <div id='cover'
      style='position: fixed; left: 0px; top: 100px; width: 100px; height: 100px;'>
    </div>
    <permission id='camera' type='camera'>
  )HTML");

  Compositor().BeginFrame();
  auto* permission_element = To<HTMLPermissionElement>(
      GetDocument().QuerySelector(AtomicString("permission")));
  auto* div =
      To<HTMLDivElement>(GetDocument().QuerySelector(AtomicString("div")));
  WaitForIntersectionVisibilityChanged(
      permission_element,
      HTMLPermissionElement::IntersectionVisibility::kFullyVisible);
  DeferredChecker checker(permission_element);
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled*/ true);
  EXPECT_FALSE(To<HTMLPermissionElement>(
                   GetDocument().QuerySelector(AtomicString("permission")))
                   ->matches(AtomicString(":occluded")));

  permission_element->setAttribute(
      html_names::kStyleAttr,
      AtomicString("color: red; background-color: white;"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled=*/true);
  EXPECT_FALSE(To<HTMLPermissionElement>(
                   GetDocument().QuerySelector(AtomicString("permission")))
                   ->matches(AtomicString(":invalid-style")));

  // Red on purple is not sufficient contrast.
  permission_element->setAttribute(
      html_names::kStyleAttr,
      AtomicString("color: red; background-color: purple;"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  checker.CheckClickingEnabled(/*enabled=*/false);
  EXPECT_TRUE(To<HTMLPermissionElement>(
                  GetDocument().QuerySelector(AtomicString("permission")))
                  ->matches(AtomicString(":invalid-style")));

  // Move the div to overlap the Permission Element
  div->SetInlineStyleProperty(CSSPropertyID::kTop, "0px");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  WaitForIntersectionVisibilityChanged(
      permission_element,
      HTMLPermissionElement::IntersectionVisibility::kOccludedOrDistorted);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(To<HTMLPermissionElement>(
                  GetDocument().QuerySelector(AtomicString("permission")))
                  ->matches(AtomicString(":occluded")));
  div->SetInlineStyleProperty(CSSPropertyID::kTop, "100px");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(To<HTMLPermissionElement>(
                   GetDocument().QuerySelector(AtomicString("permission")))
                   ->matches(AtomicString(":occluded")));

  permission_element->setAttribute(
      html_names::kStyleAttr,
      AtomicString("color: yellow; background-color: purple;"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  checker.CheckClickingEnabled(/*enabled=*/false);
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled=*/true);
  EXPECT_FALSE(To<HTMLPermissionElement>(
                   GetDocument().QuerySelector(AtomicString("permission")))
                   ->matches(AtomicString(":invalid-style")));
}

TEST_F(HTMLPemissionElementIntersectionTest, ContainerDivRotates) {
  TestContainerStyleAffectsVisibility(
      CSSPropertyID::kTransform, "rotate(0.1turn)",
      HTMLPermissionElement::IntersectionVisibility::kOccludedOrDistorted);
}

TEST_F(HTMLPemissionElementIntersectionTest, ContainerDivOpacity) {
  TestContainerStyleAffectsVisibility(
      CSSPropertyID::kOpacity, "0.9",
      HTMLPermissionElement::IntersectionVisibility::kOccludedOrDistorted);
}

TEST_F(HTMLPemissionElementIntersectionTest, ContainerDivClipPath) {
  // Set up a mask that covers a bit of the container.
  TestContainerStyleAffectsVisibility(
      CSSPropertyID::kClipPath, "circle(40%)",
      HTMLPermissionElement::IntersectionVisibility::kOutOfViewportOrClipped);
}

class HTMLPemissionElementLayoutChangeTest
    : public HTMLPemissionElementSimTest {
 public:
  static constexpr int kViewportWidth = 800;
  static constexpr int kViewportHeight = 600;

 protected:
  HTMLPemissionElementLayoutChangeTest() = default;

  void SetUp() override {
    HTMLPemissionElementSimTest::SetUp();
    IntersectionObserver::SetThrottleDelayEnabledForTesting(false);
    WebView().MainFrameWidget()->Resize(
        gfx::Size(kViewportWidth, kViewportHeight));
  }

  void TearDown() override {
    IntersectionObserver::SetThrottleDelayEnabledForTesting(true);
    HTMLPemissionElementSimTest::TearDown();
  }

  HTMLPermissionElement* CheckAndQueryPermissionElement(AtomicString element) {
    auto* permission_element =
        To<HTMLPermissionElement>(GetDocument().QuerySelector(element));
    GetDocument().View()->UpdateAllLifecyclePhasesForTest();
    EXPECT_EQ(permission_element->IntersectionVisibilityForTesting(),
              HTMLPermissionElement::IntersectionVisibility::kFullyVisible);
    DeferredChecker checker(permission_element);
    checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                           /*expected_enabled*/ true);
    return permission_element;
  }
};

TEST_F(HTMLPemissionElementLayoutChangeTest, InvalidatePEPCAfterMove) {
  SimRequest main_resource("https://example.test/", "text/html");
  LoadURL("https://example.test/");
  main_resource.Complete(R"HTML(
  <body>
    <permission
      style='position: relative; top: 1px; left: 1px;'
      id='camera'
      type='camera'>
  </body>
  )HTML");

  Compositor().BeginFrame();
  auto* permission_element =
      CheckAndQueryPermissionElement(AtomicString("permission"));
  permission_element->setAttribute(
      html_names::kStyleAttr,
      AtomicString("position: relative; top: 100px; left: 100px"));
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(permission_element->IsClickingEnabled());
  DeferredChecker checker(permission_element);
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled*/ true);
}

TEST_F(HTMLPemissionElementLayoutChangeTest, InvalidatePEPCAfterResize) {
  SimRequest main_resource("https://example.test/", "text/html");
  LoadURL("https://example.test/");
  main_resource.Complete(R"HTML(
  <body>
    <permission
      style=' height: 3em; width: 40px;' id='camera' type='camera'>
  </body>
  )HTML");

  Compositor().BeginFrame();
  auto* permission_element =
      CheckAndQueryPermissionElement(AtomicString("permission"));
  permission_element->setAttribute(html_names::kStyleAttr,
                                   AtomicString(" height: 1em; width: 30px;"));
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(permission_element->IsClickingEnabled());
  DeferredChecker checker(permission_element);
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled*/ true);
}

TEST_F(HTMLPemissionElementLayoutChangeTest, InvalidatePEPCAfterMoveContainer) {
  SimRequest main_resource("https://example.test/", "text/html");
  SimRequest iframe_resource("https://example.test/foo.html", "text/html");
  LoadURL("https://example.test/");
  main_resource.Complete(R"HTML(
  <body>
      <iframe src='https://example.test/foo.html'
        allow="camera *">
      </iframe>
  </body>
  )HTML");
  iframe_resource.Finish();

  Compositor().BeginFrame();
  auto* child_frame = To<WebLocalFrameImpl>(MainFrame().FirstChild());
  auto* permission_element = CreatePermissionElement(
      *child_frame->GetFrame()->GetDocument(), "camera");
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(permission_element->IsClickingEnabled());
  DeferredChecker checker(permission_element);
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled*/ true);
  auto* iframe = To<HTMLIFrameElement>(
      GetDocument().QuerySelector(AtomicString("iframe")));
  iframe->setAttribute(
      html_names::kStyleAttr,
      AtomicString("position: relative; top: 100px; left: 100px"));
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(permission_element->IsClickingEnabled());
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled*/ true);
}

TEST_F(HTMLPemissionElementLayoutChangeTest,
       InvalidatePEPCAfterTransformContainer) {
  SimRequest main_resource("https://example.test/", "text/html");
  LoadURL("https://example.test/");
  main_resource.Complete(R"HTML(
    <div id='container'>
      <permission id='camera' type='camera'>
    </div>
    )HTML");
  Compositor().BeginFrame();
  auto* permission_element =
      CheckAndQueryPermissionElement(AtomicString("permission"));
  auto* div =
      To<HTMLDivElement>(GetDocument().QuerySelector(AtomicString("div")));
  div->SetInlineStyleProperty(CSSPropertyID::kTransform, "translateX(10px)");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(permission_element->IsClickingEnabled());
  DeferredChecker checker(permission_element);
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled*/ true);
}

TEST_F(HTMLPemissionElementLayoutChangeTest,
       InvalidatePEPCLayoutInAnimationFrameCallback) {
  SimRequest main_resource("https://example.test/", "text/html");
  LoadURL("https://example.test/");
  main_resource.Complete(R"HTML(
  <body>
    <permission
      style=' height: 3em; width: 40px;' id='camera' type='camera'>
  </body>
  )HTML");

  Compositor().BeginFrame();
  auto* permission_element =
      CheckAndQueryPermissionElement(AtomicString("permission"));
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  // Run an animation frame callback which mutates the style of the element and
  // causes a synchronous style update. This should not result in an
  // "intersection changed" lifecycle state update, but still lock the element
  // temporarily.
  ClassicScript::CreateUnspecifiedScript(
      "window.requestAnimationFrame(function() {\n"
      "  var camera = document.getElementById('camera');\n"
      "  camera.style.width = '10px';\n"
      "  camera.getBoundingClientRect();\n"
      "  camera.style.width = '40px';\n"
      "\n"
      "});\n")
      ->RunScript(&Window());
  Compositor().BeginFrame();
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(permission_element->IsClickingEnabled());
  DeferredChecker checker(permission_element);
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled*/ true);
}

}  // namespace blink
```
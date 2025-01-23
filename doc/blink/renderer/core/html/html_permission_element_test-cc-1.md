Response:
The user wants a summary of the functionalities of the provided C++ code. This code is a unit test file (`html_permission_element_test.cc`) for the Blink rendering engine, specifically focusing on the `HTMLPermissionElement`.

Here's a breakdown of how to summarize the code:

1. **Identify the core subject:** The tests are for `HTMLPermissionElement`. This means the code is testing how this element behaves.

2. **Analyze the test names and structures:** The test names (e.g., `StatusesChangeGeolocationPermissionsElement`, `InitialAndUpdatedPermissionStatus`, `UnclickableBeforeRegistered`) give direct clues about the functionalities being tested. The `TEST_F` macro indicates these are integration tests using a test fixture (`HTMLPemissionElementTest` or its derived classes).

3. **Examine the code within each test:**  Look for patterns and what aspects of `HTMLPermissionElement` are being manipulated and checked. Key elements to look for are:
    * Creation of `HTMLPermissionElement` instances.
    * Setting attributes (like `type`).
    * Interaction with a `permission_service()`.
    * Assertions using `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`.
    * Checks for text content, permission status, and clickability.
    * Simulation of permission status changes.
    * Testing in different contexts (e.g., iframes, fenced frames).
    * Checks related to styling and accessibility (contrast, font size).
    * Dispatching and handling of validation events.

4. **Group related functionalities:**  Combine tests that address the same or similar aspects of the element's behavior. For example, tests related to permission status changes can be grouped.

5. **Identify connections to web technologies:** Determine how the tested functionalities relate to HTML, JavaScript, and CSS. The test names and the element's purpose (requesting permissions) strongly suggest these connections.

6. **Look for logical reasoning and assumptions:**  Some tests involve setting up specific conditions and then checking the expected outcomes. This involves logical reasoning within the test.

7. **Identify potential user/programming errors:** Consider scenarios where a developer might misuse the `HTMLPermissionElement` or make mistakes in its configuration.

8. **Consider the "Part 2" context:** The prompt explicitly mentions this is part 2 of 3. This suggests the functionalities in this section build upon or are distinct from those in parts 1 and 3 (though not provided here). Focus on summarizing *this specific part*.

**Pre-computation/Analysis (based on the code):**

* **Permission Status Changes:** Tests how the element's displayed text reflects changes in permission status (granted, denied, ask).
* **Initial and Updated Status:**  Tests how the element reflects the initial permission status and updates when the status changes. Also tests grouped permissions (e.g., camera and microphone).
* **Clickability:** Tests when the element becomes clickable, particularly after it's been registered with the permission service and after certain delays or style updates.
* **Permissions Policy:**  Tests how the element interacts with the Permissions Policy, which can prevent it from working in certain iframes.
* **Styling and Accessibility:** Tests how CSS properties like contrast and font size can affect the element's clickability (for accessibility reasons).
* **Validation Events:** Tests the dispatch and handling of events related to the validity of the permission element, triggered by factors like registration and changes in clickability.
* **Fenced Frames:** Tests that the element is not allowed in fenced frames.
* **CSP (Content Security Policy):** Tests how the `frame-ancestors` directive in CSP can block the element.

**Final Summary Structure:** Organize the identified functionalities into a clear and concise summary, addressing the user's specific requests (relationships to JS/HTML/CSS, logical reasoning, common errors).
这是对 Chromium Blink 引擎中 `blink/renderer/core/html/html_permission_element_test.cc` 文件的一部分代码的功能归纳。 基于这段代码，该部分主要关注于 `HTMLPermissionElement` 在以下方面的功能测试：

**主要功能归纳:**

1. **测试权限状态变化时 `HTMLPermissionElement` 的文本更新:**
   - 验证当摄像头和麦克风的权限状态发生变化时，`HTMLPermissionElement` 中显示的文本内容是否会正确更新。
   - 例如，当摄像头和麦克风都被授权时，显示的文本应该指示权限已被允许。

2. **测试 `HTMLPermissionElement` 的初始和更新后的权限状态:**
   - 验证 `HTMLPermissionElement` 能否正确获取和反映初始的权限状态（例如，询问、拒绝、允许）。
   - 验证当权限状态更新时，`HTMLPermissionElement` 能否正确反映新的状态，同时保持初始状态不变。
   - 同时测试了分组权限（例如，同时请求摄像头和麦克风权限）的初始和更新状态。分组权限的状态以最严格的权限状态为准。

3. **测试 `HTMLPermissionElement` 的点击启用时机:**
   - 验证 `HTMLPermissionElement` 在注册之前是不可点击的。
   - 模拟了在 `HTMLPermissionElement` 注册回调被延迟的情况下，元素在经过一定时间后才能被点击。

4. **模拟场景下 `HTMLPermissionElement` 的初始化和显示:**
   - 在模拟的文档加载场景下，测试当权限被授予时，`HTMLPermissionElement` 初始化后显示的文本是否正确。
   - 同时验证了元素在渲染后的尺寸是否符合预期（非零宽度和高度）。

5. **测试 `HTMLPermissionElement` 受权限策略 (Permissions Policy) 的影响:**
   - 验证在设置了权限策略的 iframe 中，如果策略禁止了某些权限，那么在这些 iframe 中创建的 `HTMLPermissionElement` 将无法正常工作，并且会在控制台输出错误信息。

6. **测试 `HTMLPermissionElement` 点击启用延迟功能:**
   - 验证可以禁用 `HTMLPermissionElement` 的点击功能，并在一段时间后重新启用。
   - 测试了即使针对当前未禁用点击功能的原因调用 `EnableClickingAfterDelay` 也不会产生影响。

7. **测试低对比度导致 `HTMLPermissionElement` 被禁用:**
   - 验证当 `HTMLPermissionElement` 的文本颜色和背景颜色对比度不足时，元素会被禁用，无法点击。
   - 验证当对比度恢复正常后，元素会在延迟后重新启用。
   - 同时测试了颜色透明度也会影响对比度判断。

8. **测试字体大小导致 `HTMLPermissionElement` 被禁用:**
   - 验证当 `HTMLPermissionElement` 的字体大小过小或过大时，元素可能会被禁用。
   - 测试了不同的字体大小单位和关键字对元素是否启用的影响。

**与 Javascript, HTML, CSS 的关系及举例说明:**

* **HTML:**  `HTMLPermissionElement` 本身就是一个 HTML 元素，通过 `<permission type="...">` 这样的标签添加到 HTML 结构中。测试代码中通过 `CreatePermissionElement("geolocation")` 创建元素并添加到文档的 body 中。
* **Javascript:** 测试代码中涉及到通过 Javascript 设置元素的属性，例如 `permission_element->setAttribute(html_names::kTypeAttr, AtomicString(permission))`。同时，测试还模拟了通过 `onvalidationstatuschange` 属性设置事件处理函数，并在元素状态变化时触发 Javascript 代码的执行 (`console.log('event dispatched')`)。
* **CSS:** 测试代码验证了 CSS 样式会影响 `HTMLPermissionElement` 的可用性。例如，通过设置 `style` 属性来改变元素的颜色、背景色和字体大小，并验证这些样式变化是否会导致元素被禁用。
    * **例子 (CSS):**  `permission_element->setAttribute(html_names::kStyleAttr, AtomicString("color: red; background-color: white;"));` 这行代码模拟了通过 CSS 设置元素的文本颜色为红色，背景色为白色。测试会验证在这种对比度下元素是否可点击。

**逻辑推理和假设输入输出:**

* **假设输入:**  摄像头权限状态为 `MojoPermissionStatus::DENIED`，麦克风权限状态为 `MojoPermissionStatus::GRANTED`。
* **逻辑推理:** 根据 `kTestData` 的定义，当摄像头权限被拒绝，麦克风权限被允许时，预期的文本内容应该是 `kCameraMicrophoneString`。
* **预期输出:** `EXPECT_EQ(kCameraMicrophoneString, permission_element->permission_text_span_for_testing()->innerText());` 这行代码验证了元素的文本内容是否与预期一致。

**用户或编程常见的使用错误举例:**

* **未等待元素注册完成就进行操作:**  开发者可能会在 `HTMLPermissionElement` 注册到权限服务之前就尝试与其交互，例如尝试点击它。测试用例 `UnclickableBeforeRegistered` 模拟了这种情况，并验证了在注册完成前元素是不可点击的。
* **错误地设置 CSS 样式导致元素不可用:** 开发者可能会设置对比度过低或字体大小不合适的 CSS 样式，导致 `HTMLPermissionElement` 因为可访问性问题而被禁用。测试用例 `BadContrastDisablesElement` 和 `FontSizeCanDisableElement` 验证了这种情况。
* **在被 Permissions Policy 阻止的上下文中使用元素:**  开发者可能在嵌入的 iframe 中使用了需要特定权限的 `HTMLPermissionElement`，但父页面设置的 Permissions Policy 阻止了该权限。测试用例 `BlockedByPermissionsPolicy` 验证了这种情况，并展示了浏览器会输出错误信息。

总而言之，这段代码主要测试了 `HTMLPermissionElement` 在权限状态变化时的 UI 更新、生命周期管理（注册、点击启用时机）、与权限策略的交互以及受 CSS 样式影响的行为。它确保了这个自定义元素能够按照预期的方式工作，并能正确地反映当前的权限状态和用户交互能力。

### 提示词
```
这是目录为blink/renderer/core/html/html_permission_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
t().body()->RemoveChild(permission_element);
  }
}

TEST_F(HTMLPemissionElementTest,
       StatusesChangeCameraMicrophonePermissionsElement) {
  const struct {
    MojoPermissionStatus camera_status;
    MojoPermissionStatus microphone_status;
    String expected_text;
  } kTestData[] = {
      {MojoPermissionStatus::DENIED, MojoPermissionStatus::DENIED,
       kCameraMicrophoneString},
      {MojoPermissionStatus::DENIED, MojoPermissionStatus::ASK,
       kCameraMicrophoneString},
      {MojoPermissionStatus::DENIED, MojoPermissionStatus::GRANTED,
       kCameraMicrophoneString},
      {MojoPermissionStatus::ASK, MojoPermissionStatus::ASK,
       kCameraMicrophoneString},
      {MojoPermissionStatus::ASK, MojoPermissionStatus::GRANTED,
       kCameraMicrophoneString},
      {MojoPermissionStatus::ASK, MojoPermissionStatus::DENIED,
       kCameraMicrophoneString},
      {MojoPermissionStatus::GRANTED, MojoPermissionStatus::ASK,
       kCameraMicrophoneString},
      {MojoPermissionStatus::GRANTED, MojoPermissionStatus::DENIED,
       kCameraMicrophoneString},
      {MojoPermissionStatus::GRANTED, MojoPermissionStatus::GRANTED,
       kCameraMicrophoneAllowedString},
  };
  for (const auto& data : kTestData) {
    auto* permission_element = CreatePermissionElement("camera microphone");
    // Calling one more time waiting for the cache observer.
    permission_service()->WaitForPermissionObserverAdded();
    permission_service()->WaitForPermissionObserverAdded();
    permission_service()->NotifyPermissionStatusChange(
        PermissionName::VIDEO_CAPTURE, data.camera_status);
    permission_service()->NotifyPermissionStatusChange(
        PermissionName::AUDIO_CAPTURE, data.microphone_status);
    EXPECT_EQ(
        data.expected_text,
        permission_element->permission_text_span_for_testing()->innerText());
  }
}

TEST_F(HTMLPemissionElementTest, InitialAndUpdatedPermissionStatus) {
  for (const auto initial_status :
       {MojoPermissionStatus::ASK, MojoPermissionStatus::DENIED,
        MojoPermissionStatus::GRANTED}) {
    CachedPermissionStatus::From(GetDocument().domWindow())
        ->SetPermissionStatusMap(
            {{blink::mojom::PermissionName::GEOLOCATION, initial_status}});
    V8PermissionState::Enum expected_initial_status =
        PermissionStatusV8Enum(initial_status);
    auto* permission_element = CreatePermissionElement("geolocation");
    permission_service()->set_initial_statuses({initial_status});
    // Calling one more time waiting for the cache observer.
    permission_service()->WaitForPermissionObserverAdded();
    permission_service()->WaitForPermissionObserverAdded();
    EXPECT_EQ(expected_initial_status,
              permission_element->initialPermissionStatus());
    EXPECT_EQ(expected_initial_status, permission_element->permissionStatus());

    for (const auto updated_status :
         {MojoPermissionStatus::ASK, MojoPermissionStatus::DENIED,
          MojoPermissionStatus::GRANTED}) {
      V8PermissionState::Enum expected_updated_status =
          PermissionStatusV8Enum(updated_status);
      permission_service()->NotifyPermissionStatusChange(
          PermissionName::GEOLOCATION, updated_status);
      // After an updated, the initial permission status remains the same and
      // just the permission status changes.
      EXPECT_EQ(expected_initial_status,
                permission_element->initialPermissionStatus());
      EXPECT_EQ(expected_updated_status,
                permission_element->permissionStatus());
    }
    GetDocument().body()->RemoveChild(permission_element);
  }
}

TEST_F(HTMLPemissionElementTest, InitialAndUpdatedPermissionStatusGrouped) {
  CachedPermissionStatus::From(GetDocument().domWindow())
      ->SetPermissionStatusMap({{blink::mojom::PermissionName::VIDEO_CAPTURE,
                                 MojoPermissionStatus::ASK},
                                {blink::mojom::PermissionName::AUDIO_CAPTURE,
                                 MojoPermissionStatus::ASK}});
  auto* permission_element = CreatePermissionElement("camera microphone");
  permission_service()->set_initial_statuses(
      {MojoPermissionStatus::ASK, MojoPermissionStatus::DENIED});

  // Before receiving any status, it's assumed it is "prompt" since we don't
  // have a better idea.
  EXPECT_EQ(PermissionStatusV8Enum(MojoPermissionStatus::ASK),
            permission_element->initialPermissionStatus());
  EXPECT_EQ(PermissionStatusV8Enum(MojoPermissionStatus::ASK),
            permission_element->permissionStatus());

  // Two permissoin observers should be added since it's a grouped permission
  // element.
  permission_service()->WaitForPermissionObserverAdded();
  permission_service()->WaitForPermissionObserverAdded();

  // Calling one more time waiting for the cache observer.
  permission_service()->WaitForPermissionObserverAdded();
  permission_service()->WaitForPermissionObserverAdded();

  // The status is the most restrictive of the two permissions. The initial
  // status never changes. camera: ASK, mic: DENIED
  EXPECT_EQ(PermissionStatusV8Enum(MojoPermissionStatus::ASK),
            permission_element->initialPermissionStatus());
  EXPECT_EQ(PermissionStatusV8Enum(MojoPermissionStatus::DENIED),
            permission_element->permissionStatus());

  // camera:ASK, mic: ASK
  permission_service()->NotifyPermissionStatusChange(
      PermissionName::AUDIO_CAPTURE, MojoPermissionStatus::ASK);
  EXPECT_EQ(PermissionStatusV8Enum(MojoPermissionStatus::ASK),
            permission_element->initialPermissionStatus());
  EXPECT_EQ(PermissionStatusV8Enum(MojoPermissionStatus::ASK),
            permission_element->permissionStatus());

  // camera:DENIED, mic: ASK
  permission_service()->NotifyPermissionStatusChange(
      PermissionName::VIDEO_CAPTURE, MojoPermissionStatus::DENIED);
  EXPECT_EQ(PermissionStatusV8Enum(MojoPermissionStatus::ASK),
            permission_element->initialPermissionStatus());
  EXPECT_EQ(PermissionStatusV8Enum(MojoPermissionStatus::DENIED),
            permission_element->permissionStatus());

  // camera:DENIED, mic: GRANTED
  permission_service()->NotifyPermissionStatusChange(
      PermissionName::AUDIO_CAPTURE, MojoPermissionStatus::GRANTED);
  EXPECT_EQ(PermissionStatusV8Enum(MojoPermissionStatus::ASK),
            permission_element->initialPermissionStatus());
  EXPECT_EQ(PermissionStatusV8Enum(MojoPermissionStatus::DENIED),
            permission_element->permissionStatus());

  // camera:GRANTED, mic: GRANTED
  permission_service()->NotifyPermissionStatusChange(
      PermissionName::VIDEO_CAPTURE, MojoPermissionStatus::GRANTED);
  EXPECT_EQ(PermissionStatusV8Enum(MojoPermissionStatus::ASK),
            permission_element->initialPermissionStatus());
  EXPECT_EQ(PermissionStatusV8Enum(MojoPermissionStatus::GRANTED),
            permission_element->permissionStatus());
}

class HTMLPemissionElementClickingEnabledTest
    : public HTMLPemissionElementTest {
 public:
  HTMLPemissionElementClickingEnabledTest()
      : HTMLPemissionElementTest(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}

  ~HTMLPemissionElementClickingEnabledTest() override = default;
};

TEST_F(HTMLPemissionElementClickingEnabledTest, UnclickableBeforeRegistered) {
  const struct {
    const char* type;
    String expected_text;
  } kTestData[] = {{"geolocation", kGeolocationString},
                   {"microphone", kMicrophoneString},
                   {"camera", kCameraString},
                   {"camera microphone", kCameraMicrophoneString}};
  for (const auto& data : kTestData) {
    auto* permission_element = CreatePermissionElement(data.type);
    permission_service()->set_should_defer_registered_callback(
        /*should_defer*/ true);
    // Check if the element is still unclickable even after the default timeout
    // of `kRecentlyAttachedToLayoutTree`.
    FastForwardBy(base::Milliseconds(600));
    EXPECT_FALSE(permission_element->IsClickingEnabled());
    std::move(permission_service()->TakePEPCRegisteredCallback()).Run();
    FastForwardUntilNoTasksRemain();
    EXPECT_TRUE(permission_element->IsClickingEnabled());
    permission_service()->set_should_defer_registered_callback(
        /*should_defer*/ false);
  }
}

class HTMLPemissionElementSimTest : public SimTest {
 public:
  HTMLPemissionElementSimTest() = default;

  ~HTMLPemissionElementSimTest() override = default;

  void SetUp() override {
    SimTest::SetUp();
    MainFrame().GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
        PermissionService::Name_,
        base::BindRepeating(&TestPermissionService::BindHandle,
                            base::Unretained(&permission_service_)));
  }

  void TearDown() override {
    MainFrame().GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
        PermissionService::Name_, {});
    SimTest::TearDown();
  }

  TestPermissionService* permission_service() { return &permission_service_; }

  HTMLPermissionElement* CreatePermissionElement(
      Document& document,
      const char* permission,
      std::optional<const char*> precise_location = std::nullopt) {
    HTMLPermissionElement* permission_element =
        MakeGarbageCollected<HTMLPermissionElement>(document);
    permission_element->setAttribute(html_names::kTypeAttr,
                                     AtomicString(permission));
    if (precise_location.has_value()) {
      permission_element->setAttribute(html_names::kPreciselocationAttr,
                                       AtomicString(precise_location.value()));
    }
    document.body()->AppendChild(permission_element);
    document.UpdateStyleAndLayout(DocumentUpdateReason::kTest);
    return permission_element;
  }

 private:
  TestPermissionService permission_service_;
  ScopedTestingPlatformSupport<LocalePlatformSupport> support;
  ScopedPermissionElementForTest scoped_feature_{true};
};

TEST_F(HTMLPemissionElementSimTest, InitializeGrantedText) {
  SimRequest resource("https://example.test", "text/html");
  LoadURL("https://example.test");
  resource.Complete(R"(
    <body>
    </body>
  )");
  CachedPermissionStatus::From(GetDocument().domWindow())
      ->SetPermissionStatusMap({{blink::mojom::PermissionName::VIDEO_CAPTURE,
                                 MojoPermissionStatus::GRANTED},
                                {blink::mojom::PermissionName::AUDIO_CAPTURE,
                                 MojoPermissionStatus::GRANTED},
                                {blink::mojom::PermissionName::GEOLOCATION,
                                 MojoPermissionStatus::GRANTED}});
  const struct {
    const char* type;
    String expected_text;
  } kTestData[] = {{"geolocation", kGeolocationAllowedString},
                   {"microphone", kMicrophoneAllowedString},
                   {"camera", kCameraAllowedString},
                   {"camera microphone", kCameraMicrophoneAllowedString}};

  for (const auto& data : kTestData) {
    auto* permission_element =
        MakeGarbageCollected<HTMLPermissionElement>(GetDocument());
    permission_element->setAttribute(html_names::kTypeAttr,
                                     AtomicString(data.type));
    permission_element->setAttribute(html_names::kStyleAttr,
                                     AtomicString("width: auto; height: auto"));
    GetDocument().body()->AppendChild(permission_element);
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
    EXPECT_EQ(
        data.expected_text,
        permission_element->permission_text_span_for_testing()->innerText());
    DOMRect* rect = permission_element->GetBoundingClientRect();
    EXPECT_NE(0, rect->width());
    EXPECT_NE(0, rect->height());
  }
}

TEST_F(HTMLPemissionElementSimTest, BlockedByPermissionsPolicy) {
  SimRequest main_resource("https://example.test", "text/html");
  LoadURL("https://example.test");
  SimRequest first_iframe_resource("https://example.test/foo1.html",
                                   "text/html");
  SimRequest last_iframe_resource("https://example.test/foo2.html",
                                  "text/html");
  main_resource.Complete(R"(
    <body>
      <iframe src='https://example.test/foo1.html'
        allow="camera 'none';microphone 'none';geolocation 'none'">
      </iframe>
      <iframe src='https://example.test/foo2.html'
        allow="camera *;microphone *;geolocation *">
      </iframe>
    </body>
  )");
  first_iframe_resource.Finish();
  last_iframe_resource.Finish();

  auto* first_child_frame = To<WebLocalFrameImpl>(MainFrame().FirstChild());
  auto* last_child_frame = To<WebLocalFrameImpl>(MainFrame().LastChild());
  for (const char* permission : {"camera", "microphone", "geolocation"}) {
    auto* permission_element = CreatePermissionElement(
        *last_child_frame->GetFrame()->GetDocument(), permission);
    RegistrationWaiter(permission_element).Wait();
    // PermissionsPolicy passed with no console log.
    auto& last_console_messages =
        static_cast<frame_test_helpers::TestWebFrameClient*>(
            last_child_frame->Client())
            ->ConsoleMessages();
    EXPECT_EQ(last_console_messages.size(), 0u);

    CreatePermissionElement(*first_child_frame->GetFrame()->GetDocument(),
                            permission);
    permission_service()->set_pepc_registered_callback(
        base::BindOnce(&NotReachedForPEPCRegistered));
    base::RunLoop().RunUntilIdle();
    // Should console log a error message due to PermissionsPolicy
    auto& first_console_messages =
        static_cast<frame_test_helpers::TestWebFrameClient*>(
            first_child_frame->Client())
            ->ConsoleMessages();
    EXPECT_EQ(first_console_messages.size(), 2u);
    EXPECT_TRUE(first_console_messages.front().Contains(
        "is not allowed in the current context due to PermissionsPolicy"));
    first_console_messages.clear();
    permission_service()->set_pepc_registered_callback(base::NullCallback());
  }
}

TEST_F(HTMLPemissionElementSimTest, EnableClickingAfterDelay) {
  auto* permission_element = CreatePermissionElement(GetDocument(), "camera");
  DeferredChecker checker(permission_element);
  permission_element->DisableClickingIndefinitely(
      HTMLPermissionElement::DisableReason::kInvalidStyle);
  checker.CheckClickingEnabled(/*enabled=*/false);

  // Calling |EnableClickingAfterDelay| for a reason that is currently disabling
  // clicking will result in clicking becoming enabled after the delay.
  permission_element->EnableClickingAfterDelay(
      HTMLPermissionElement::DisableReason::kInvalidStyle, kDefaultTimeout);
  checker.CheckClickingEnabled(/*enabled=*/false);
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled=*/true);

  // Calling |EnableClickingAfterDelay| for a reason that is currently *not*
  // disabling clicking does not do anything.
  permission_element->EnableClickingAfterDelay(
      HTMLPermissionElement::DisableReason::kInvalidStyle, kDefaultTimeout);
  checker.CheckClickingEnabled(/*enabled=*/true);
}

TEST_F(HTMLPemissionElementSimTest, BadContrastDisablesElement) {
  auto* permission_element = CreatePermissionElement(GetDocument(), "camera");
  DeferredChecker checker(permission_element);
  // Red on white is sufficient contrast.
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

  // Purple on yellow is sufficient contrast, the element will be re-enabled
  // after a delay.
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

  // Purple on yellow is sufficient contrast, however the alpha is not at 100%
  // so the element should become disabled. rgba(255, 255, 0, 0.99) is "yellow"
  // at 99% alpha.
  permission_element->setAttribute(
      html_names::kStyleAttr,
      AtomicString(
          "color: rgba(255, 255, 0, 0.99); background-color: purple;"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  checker.CheckClickingEnabled(/*enabled=*/false);
}

TEST_F(HTMLPemissionElementSimTest, FontSizeCanDisableElement) {
  GetDocument().GetSettings()->SetDefaultFontSize(12);
  auto* permission_element = CreatePermissionElement(GetDocument(), "camera");
  DeferredChecker checker(permission_element);

  // Normal font-size for baseline.
  permission_element->setAttribute(html_names::kStyleAttr,
                                   AtomicString("font-size: normal;"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  checker.CheckClickingEnabledAfterDelay(kDefaultTimeout,
                                         /*expected_enabled=*/true);

  struct {
    std::string fontSizeString;
    bool enabled;
  } kTests[] = {
      // px values.
      {"2px", false},
      {"100px", false},
      {"20px", true},
      // Keywords
      {"xlarge", true},
      // em based values
      {"1.5em", true},
      {"0.5em", false},
      {"6em", false},
      // Calculation values
      {"min(2px, 20px)", false},
      {"max(xsmall, large)", true},
  };

  std::string font_size_string;

  for (const auto& test : kTests) {
    SCOPED_TRACE(test.fontSizeString);
    font_size_string = "font-size: " + test.fontSizeString + ";";
    permission_element->setAttribute(html_names::kStyleAttr,
                                     AtomicString(font_size_string.c_str()));
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
    checker.CheckClickingEnabledAfterDelay(kDefaultTimeout, test.enabled);
    permission_element->EnableClicking(
        HTMLPermissionElement::DisableReason::kRecentlyAttachedToLayoutTree);
    permission_element->EnableClicking(HTMLPermissionElement::DisableReason::
                                           kIntersectionRecentlyFullyVisible);
    permission_element->EnableClicking(
        HTMLPermissionElement::DisableReason::kInvalidStyle);

    EXPECT_TRUE(permission_element->IsClickingEnabled());
  }
}

class HTMLPemissionElementDispatchValidationEventTest
    : public HTMLPemissionElementSimTest {
 public:
  HTMLPemissionElementDispatchValidationEventTest() = default;

  ~HTMLPemissionElementDispatchValidationEventTest() override = default;

  HTMLPermissionElement* CreateElementAndWaitForRegistration() {
    auto& document = GetDocument();
    HTMLPermissionElement* permission_element =
        MakeGarbageCollected<HTMLPermissionElement>(document);
    permission_element->setAttribute(html_names::kTypeAttr,
                                     AtomicString("camera"));
    permission_element->setAttribute(
        html_names::kOnvalidationstatuschangeAttr,
        AtomicString("console.log('event dispatched')"));
    document.body()->AppendChild(permission_element);
    document.UpdateStyleAndLayout(DocumentUpdateReason::kTest);
    DeferredChecker checker(permission_element, &MainFrame());
    checker.CheckConsoleMessage(/*expected_count*/ 1u, "event dispatched");
    EXPECT_FALSE(permission_element->isValid());
    EXPECT_EQ(permission_element->invalidReason(), "unsuccessful_registration");
    permission_service()->set_should_defer_registered_callback(
        /*should_defer*/ true);
    checker.CheckConsoleMessageAfterDelay(base::Milliseconds(600),
                                          /*expected_count*/ 1u,
                                          "event dispatched");
    EXPECT_FALSE(permission_element->isValid());
    EXPECT_EQ(permission_element->invalidReason(), "unsuccessful_registration");
    std::move(permission_service()->TakePEPCRegisteredCallback()).Run();
    RegistrationWaiter(permission_element).Wait();
    permission_service()->set_should_defer_registered_callback(
        /*should_defer*/ false);
    return permission_element;
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

// Test receiving event after registration
TEST_F(HTMLPemissionElementDispatchValidationEventTest, Registration) {
  auto* permission_element = CreateElementAndWaitForRegistration();
  DeferredChecker checker(permission_element, &MainFrame());
  checker.CheckConsoleMessage(
      /*expected_count*/ 2u, "event dispatched");
  EXPECT_TRUE(permission_element->isValid());
}

// Test receiving event after several times disabling (temporarily or
// indefinitely) + enabling a single reason and verify the `isValid` and
// `invalidReason` attrs.
TEST_F(HTMLPemissionElementDispatchValidationEventTest, DisableEnableClicking) {
  const struct {
    HTMLPermissionElement::DisableReason reason;
    String expected_invalid_reason;
  } kTestData[] = {
      {HTMLPermissionElement::DisableReason::kIntersectionRecentlyFullyVisible,
       String("intersection_visible")},
      {HTMLPermissionElement::DisableReason::kRecentlyAttachedToLayoutTree,
       String("recently_attached")},
      {HTMLPermissionElement::DisableReason::kInvalidStyle,
       String("style_invalid")}};
  for (const auto& data : kTestData) {
    auto* permission_element = CreateElementAndWaitForRegistration();
    DeferredChecker checker(permission_element, &MainFrame());
    checker.CheckConsoleMessage(
        /*expected_count*/ 2u);
    EXPECT_TRUE(permission_element->isValid());
    permission_element->DisableClickingIndefinitely(data.reason);
    base::RunLoop().RunUntilIdle();
    checker.CheckConsoleMessage(
        /*expected_count*/ 3u, "event dispatched");
    EXPECT_FALSE(permission_element->isValid());
    EXPECT_EQ(permission_element->invalidReason(),
              data.expected_invalid_reason);
    // Calling |DisableClickingTemporarily| for a reason that is currently
    // disabling clicking does not do anything.
    permission_element->DisableClickingTemporarily(data.reason,
                                                   base::Milliseconds(600));
    checker.CheckConsoleMessageAfterDelay(kSmallTimeout,
                                          /*expected_count*/ 3u,
                                          "event dispatched");
    EXPECT_FALSE(permission_element->isValid());
    EXPECT_EQ(permission_element->invalidReason(),
              data.expected_invalid_reason);
    // Calling |EnableClickingAfterDelay| for a reason that is currently
    // disabling clicking will result in a validation change event.
    permission_element->EnableClickingAfterDelay(data.reason, kSmallTimeout);
    EXPECT_FALSE(permission_element->isValid());
    EXPECT_EQ(permission_element->invalidReason(),
              data.expected_invalid_reason);
    checker.CheckConsoleMessageAfterDelay(kSmallTimeout,
                                          /*expected_count*/ 4u,
                                          "event dispatched");
    EXPECT_TRUE(permission_element->isValid());
    // Calling |EnableClickingAfterDelay| for a reason that is currently *not*
    // disabling clicking does not do anything.
    permission_element->EnableClickingAfterDelay(data.reason, kSmallTimeout);
    checker.CheckConsoleMessageAfterDelay(kSmallTimeout,
                                          /*expected_count*/ 4u);

    permission_element->DisableClickingTemporarily(data.reason, kSmallTimeout);
    base::RunLoop().RunUntilIdle();
    checker.CheckConsoleMessage(
        /*expected_count*/ 5u, "event dispatched");
    EXPECT_FALSE(permission_element->isValid());
    EXPECT_EQ(permission_element->invalidReason(),
              data.expected_invalid_reason);
    checker.CheckConsoleMessageAfterDelay(kSmallTimeout,
                                          /*expected_count*/ 6u,
                                          "event dispatched");
    EXPECT_TRUE(permission_element->isValid());

    GetDocument().body()->RemoveChild(permission_element);
    ConsoleMessages().clear();
  }
}

// Test restart the timer caused by `DisableClickingTemporarily` or
// `EnableClickingAfterDelay`. And verify that `invalidReason` changing could
// result in an event.
TEST_F(HTMLPemissionElementDispatchValidationEventTest,
       ChangeReasonRestartTimer) {
  auto* permission_element = CreateElementAndWaitForRegistration();
  DeferredChecker checker(permission_element, &MainFrame());
  checker.CheckConsoleMessage(
      /*expected_count*/ 2u, "event dispatched");
  EXPECT_TRUE(permission_element->isValid());
  permission_element->DisableClickingTemporarily(
      HTMLPermissionElement::DisableReason::kRecentlyAttachedToLayoutTree,
      kSmallTimeout);
  base::RunLoop().RunUntilIdle();
  checker.CheckConsoleMessage(
      /*expected_count*/ 3u, "event dispatched");
  EXPECT_FALSE(permission_element->isValid());
  EXPECT_EQ(permission_element->invalidReason(), "recently_attached");
  permission_element->DisableClickingTemporarily(
      HTMLPermissionElement::DisableReason::kInvalidStyle, kDefaultTimeout);
  // Reason change to the "longest alive" reason, in this case is
  // `kInvalidStyle`
  base::RunLoop().RunUntilIdle();
  checker.CheckConsoleMessage(/*expected_count*/ 4u, "event dispatched");
  EXPECT_FALSE(permission_element->isValid());
  EXPECT_EQ(permission_element->invalidReason(), "style_invalid");
  permission_element->DisableClickingTemporarily(
      HTMLPermissionElement::DisableReason::kRecentlyAttachedToLayoutTree,
      base::Milliseconds(100));
  EXPECT_FALSE(permission_element->isValid());
  EXPECT_EQ(permission_element->invalidReason(), "style_invalid");
  permission_element->EnableClickingAfterDelay(
      HTMLPermissionElement::DisableReason::kInvalidStyle, kSmallTimeout);
  checker.CheckConsoleMessageAfterDelay(kSmallTimeout,
                                        /*expected_count*/ 5u);
  EXPECT_FALSE(permission_element->isValid());
  EXPECT_EQ(permission_element->invalidReason(), "recently_attached");
  checker.CheckConsoleMessageAfterDelay(kSmallTimeout,
                                        /*expected_count*/ 6u,
                                        "event dispatched");
  EXPECT_TRUE(permission_element->isValid());
}

// Test receiving event after disabling (temporarily or indefinitely) + enabling
// multiple reasons and verify the `isValid` and `invalidReason` attrs.
TEST_F(HTMLPemissionElementDispatchValidationEventTest,
       DisableEnableClickingDifferentReasons) {
  auto* permission_element = CreateElementAndWaitForRegistration();
  DeferredChecker checker(permission_element, &MainFrame());
  checker.CheckConsoleMessage(
      /*expected_count*/ 2u, "event dispatched");
  EXPECT_TRUE(permission_element->isValid());
  permission_element->DisableClickingTemporarily(
      HTMLPermissionElement::DisableReason::kIntersectionRecentlyFullyVisible,
      kDefaultTimeout);
  base::RunLoop().RunUntilIdle();
  checker.CheckConsoleMessage(
      /*expected_count*/ 3u, "event dispatched");
  EXPECT_FALSE(permission_element->isValid());
  EXPECT_EQ(permission_element->invalidReason(), "intersection_visible");

  // Disable indefinitely will stop the timer.
  permission_element->DisableClickingIndefinitely(
      HTMLPermissionElement::DisableReason::kInvalidStyle);
  base::RunLoop().RunUntilIdle();
  // `invalidReason` change from temporary `intersection` to indefinitely
  // `style`
  checker.CheckConsoleMessage(
      /*expected_count*/ 4u, "event dispatched");
  EXPECT_FALSE(permission_element->isValid());
  EXPECT_EQ(permission_element->invalidReason(), "style_invalid");
  checker.CheckConsoleMessageAfterDelay(kDefaultTimeout,
                                        /*expected_count*/ 4u);
  permission_element->DisableClickingTemporarily(
      HTMLPermissionElement::DisableReason::kIntersectionRecentlyFullyVisible,
      kDefaultTimeout);
  EXPECT_FALSE(permission_element->isValid());
  EXPECT_EQ(permission_element->invalidReason(), "style_invalid");

  // Enable the indefinitely disabling reason, the timer will start with the
  // remaining temporary reason in the map.
  permission_element->EnableClicking(
      HTMLPermissionElement::DisableReason::kInvalidStyle);
  base::RunLoop().RunUntilIdle();
  // `invalidReason` change from `style` to temporary `intersection`
  checker.CheckConsoleMessage(
      /*expected_count*/ 5u, "event dispatched");
  EXPECT_FALSE(permission_element->isValid());
  EXPECT_EQ(permission_element->invalidReason(), "intersection_visible");
  checker.CheckConsoleMessageAfterDelay(kDefaultTimeout,
                                        /*expected_count*/ 6u,
                                        "event dispatched");
  EXPECT_TRUE(permission_element->isValid());
}

class HTMLPemissionElementFencedFrameTest : public HTMLPemissionElementSimTest {
 public:
  HTMLPemissionElementFencedFrameTest() {
    scoped_feature_list_.InitAndEnableFeatureWithParameters(
        blink::features::kFencedFrames, {{"implementation_type", "mparch"}});
  }

  ~HTMLPemissionElementFencedFrameTest() override = default;

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

TEST_F(HTMLPemissionElementFencedFrameTest, NotAllowedInFencedFrame) {
  InitializeFencedFrameRoot(
      blink::FencedFrame::DeprecatedFencedFrameMode::kDefault);
  SimRequest resource("https://example.test", "text/html");
  LoadURL("https://example.test");
  resource.Complete(R"(
    <body>
    </body>
  )");

  for (const char* permission : {"camera", "microphone", "geolocation"}) {
    auto* permission_element = CreatePermissionElement(
        *MainFrame().GetFrame()->GetDocument(), permission);
    // We need this call to establish binding to the remote permission service,
    // otherwise the next testing binder will fail.
    permission_element->GetPermissionService();
    permission_service()->set_pepc_registered_callback(
        base::BindOnce(&NotReachedForPEPCRegistered));
    base::RunLoop().RunUntilIdle();
  }
}

TEST_F(HTMLPemissionElementSimTest, BlockedByMissingFrameAncestorsCSP) {
  SimRequest::Params params;
  params.response_http_headers = {
      {"content-security-policy",
       "frame-ancestors 'self' https://example.test"}};
  SimRequest main_resource("https://example.test", "text/html");
  LoadURL("https://example.test");
  SimRequest first_iframe_resource("https://cross-example.test/foo1.html",
                                   "text/html");
  SimRequest last_iframe_resource("https://cross-example.test/foo2.html",
                                  "text/html", params);
  main_resource.Complete(R"(
    <body>
      <iframe src='https://cross-example.test/foo1.html'
        allow="camera *;microphone *;geolocation *">
      </iframe>
      <iframe src='https://cross-example.test/foo2.html'
        allow="camera *;microphone *;geolocation *">
      </iframe>
    </body>
  )");
  first_iframe_resource.Finish();
  last_iframe_resource.Finish();

  auto* first_child_frame = To<WebLocalFrameImpl>(MainFrame().FirstChild());
  auto* last_child_frame = To<WebLocalFrameImpl>(MainFrame().LastChild());
  for (const char* permission : {"camera", "microphone", "geolocation"}) {
    auto* permission_element = CreatePermissionElement(
        *last_child_frame->GetFrame()->GetDocument(), permission);
    RegistrationWaiter(permission_element).Wait();
    auto& last_console_messages =
        static_cast<frame_test_helpers::TestWebFrameClient*>(
            last_child_frame->Client())
            ->ConsoleMessages();
    EXPECT_EQ(last_console_messages.size(), 0u);

    CreatePermissionElement(*first_child_frame->GetFrame()->GetDocument(),
                            permission);
    permission_service()->set_pepc_registe
```
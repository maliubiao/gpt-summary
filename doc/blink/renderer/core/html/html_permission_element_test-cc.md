Response:
My thinking process to analyze the code and generate the summary involved several steps:

1. **Understand the Goal:** The request asks for a functional summary of a C++ test file for the Blink rendering engine, specifically focusing on `html_permission_element_test.cc`. It also requests highlighting connections to web technologies (HTML, CSS, JavaScript), logical inferences with examples, and common usage errors. The fact that this is "part 1 of 3" indicates a larger context and the need for a high-level overview in this initial part.

2. **Identify the Core Subject:** The file name `html_permission_element_test.cc` immediately tells me the code is testing the `HTMLPermissionElement`. This becomes the central focus of my analysis.

3. **Scan for Key Code Structures:** I quickly scanned the code for important elements:
    * **Includes:**  These reveal the dependencies and what the code interacts with. I noted includes for `HTMLPermissionElement`, testing frameworks (`gtest`), strings, CSS, DOM, and Mojo bindings.
    * **Namespaces:** The `blink` namespace confirms this is part of the Blink engine.
    * **Test Fixtures (`TEST_F`):** These define the test cases. The names of the test fixtures (e.g., `HTMLPemissionElementTestBase`, `HTMLPemissionElementTest`) give hints about the different aspects being tested.
    * **Helper Classes/Functions:** I saw `LocalePlatformSupport`, `PermissionStatusChangeWaiter`, `TestPermissionService`, `RegistrationWaiter`, and `DeferredChecker`. These are clearly designed to facilitate testing specific scenarios.
    * **Constants:**  `constexpr` values like `kGeolocationString`, `kCameraString`, etc., are used for assertions, indicating the tests involve checking displayed text.
    * **Mojo Bindings:**  The code uses Mojo interfaces for permission handling, such as `PermissionService` and `PermissionObserver`. This is a crucial aspect of the functionality being tested.

4. **Infer Functionality from Test Names and Code:**  I started mapping test names to the functionality they likely verify:
    * `SetTypeAttribute`: Testing if setting the `type` attribute works.
    * `SetPreciseLocationAttribute`: Checking the `preciselocation` attribute.
    * `ParsePermissionDescriptorsFromType`: Verifying how the `type` attribute is parsed into permission requests.
    * Tests involving `InitializeInnerText`, `TranslateInnerText`, and setting inner text after insertion/registration: These tests are clearly about the text displayed within the `<permission>` element.
    * `AfterDetachLayoutTreeCrashTest`:  A robustness test to prevent crashes in specific scenarios.
    * Tests involving status changes (`StatusChangeSinglePermissionElement`): These verify how the element reacts to changes in permission status.
    * Tests involving multiple permissions (`SetInnerTextAfterRegistrationCameraMicrophonePermissions`): Checking how the element handles combined permission requests.

5. **Identify Connections to Web Technologies:**  Based on the included headers and test scenarios, I connected the functionality to:
    * **HTML:** The `<permission>` element itself, its attributes (`type`, `preciselocation`, `lang`), and its insertion into the DOM.
    * **CSS:** The test `InitializeInnerText` mentions setting `style` attributes (`width: auto; height: auto`), indicating CSS influences the element's rendering and size.
    * **JavaScript:** Although not directly present in *this* file, the underlying `HTMLPermissionElement` class is used by JavaScript. The tests indirectly verify behavior that JavaScript would trigger or observe. I noted that JavaScript would be used to manipulate the element and observe its state.

6. **Formulate Logical Inferences with Examples:** I looked for patterns in the tests to create illustrative scenarios:
    * **Input:** Setting an attribute (e.g., `type="camera"`).
    * **Output:** The element's internal state being updated, leading to specific text being displayed or a permission request being made.
    * I used the provided string constants as examples of the displayed text.

7. **Consider Potential Usage Errors:** I thought about how developers might misuse the `<permission>` element:
    * Incorrect `type` attribute values.
    * Forgetting to handle permission status changes.
    * Expecting the element to work without proper browser support (though this is less of a *usage* error and more of an environment limitation).

8. **Structure the Summary:** I organized the information into clear sections:
    * **Core Functionality:** A concise overview of the file's purpose.
    * **Relationship to Web Technologies:** Explicitly linking the testing to HTML, CSS, and JavaScript with examples.
    * **Logical Inferences:** Providing "if-then" scenarios with inputs and expected outputs.
    * **Common Usage Errors:** Listing potential mistakes developers might make.
    * **Summary for Part 1:** A brief recap of the key functionalities covered in the provided code snippet.

9. **Refine and Iterate:** I reviewed my summary for clarity, accuracy, and completeness, ensuring it addressed all aspects of the prompt. I made sure the language was accessible and avoided overly technical jargon where possible. The "part 1 of 3" indication prompted me to keep the initial summary relatively high-level.

By following these steps, I could break down the C++ test code and generate a comprehensive summary that addresses the specific requirements of the prompt, including its connection to web technologies, logical inferences, and potential usage errors.
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/html_permission_element.h"

// ... (Includes as provided in the question)

namespace blink {

// ... (Namespace definitions and constants as provided)

// Helper class used to wait until receiving a permission status change event.
class PermissionStatusChangeWaiter : public PermissionObserver {
 public:
  explicit PermissionStatusChangeWaiter(
      mojo::PendingReceiver<PermissionObserver> receiver,
      base::OnceClosure callback)
      : receiver_(this, std::move(receiver)), callback_(std::move(callback)) {}

  // PermissionObserver override
  void OnPermissionStatusChange(MojoPermissionStatus status) override {
    if (callback_) {
      std::move(callback_).Run();
    }
  }

 private:
  mojo::Receiver<PermissionObserver> receiver_;
  base::OnceClosure callback_;
};

class TestPermissionService : public PermissionService {
 public:
  explicit TestPermissionService() = default;
  ~TestPermissionService() override = default;

  void BindHandle(mojo::ScopedMessagePipeHandle handle) {
    receivers_.Add(this,
                   mojo::PendingReceiver<PermissionService>(std::move(handle)));
  }

  // mojom::blink::PermissionService implementation
  void HasPermission(PermissionDescriptorPtr permission,
                     HasPermissionCallback) override {}
  void RegisterPageEmbeddedPermissionControl(
      Vector<PermissionDescriptorPtr> permissions,
      mojo::PendingRemote<mojom::blink::EmbeddedPermissionControlClient>
          pending_client) override {
    // ... (Implementation as provided)
  }

  void RegisterPageEmbeddedPermissionControlInternal(
      Vector<PermissionDescriptorPtr> permissions,
      mojo::PendingRemote<mojom::blink::EmbeddedPermissionControlClient>
          pending_client) {
    // ... (Implementation as provided)
  }

  void OnMojoDisconnect() {
    // ... (Implementation as provided)
  }

  void RequestPageEmbeddedPermission(
      EmbeddedPermissionRequestDescriptorPtr permissions,
      RequestPageEmbeddedPermissionCallback) override {}
  void RequestPermission(PermissionDescriptorPtr permission,
                         bool user_gesture,
                         RequestPermissionCallback) override {}
  void RequestPermissions(Vector<PermissionDescriptorPtr> permissions,
                          bool user_gesture,
                          RequestPermissionsCallback) override {}
  void RevokePermission(PermissionDescriptorPtr permission,
                        RevokePermissionCallback) override {}
  void AddPermissionObserver(
      PermissionDescriptorPtr permission,
      MojoPermissionStatus last_known_status,
      mojo::PendingRemote<PermissionObserver> observer) override {}
  void AddPageEmbeddedPermissionObserver(
      PermissionDescriptorPtr permission,
      MojoPermissionStatus last_known_status,
      mojo::PendingRemote<PermissionObserver> observer) override {
    // ... (Implementation as provided)
  }

  void NotifyEventListener(PermissionDescriptorPtr permission,
                           const String& event_type,
                           bool is_added) override {}

  void NotifyPermissionStatusChange(PermissionName name,
                                    MojoPermissionStatus status) {
    // ... (Implementation as provided)
  }

  void WaitForPermissionStatusChange(MojoPermissionStatus status) {
    // ... (Implementation as provided)
  }

  void WaitForPermissionObserverAdded() {
    // ... (Implementation as provided)
  }

  void WaitForClientDisconnected() {
    // ... (Implementation as provided)
  }

  void set_initial_statuses(const Vector<MojoPermissionStatus>& statuses) {
    // ... (Implementation as provided)
  }

  void set_pepc_registered_callback(base::OnceClosure callback) {
    // ... (Implementation as provided)
  }

  base::OnceClosure TakePEPCRegisteredCallback() {
    // ... (Implementation as provided)
  }

  void set_should_defer_registered_callback(bool should_defer) {
    // ... (Implementation as provided)
  }

 private:
  mojo::ReceiverSet<PermissionService> receivers_;
  Vector<std::pair<PermissionName, mojo::Remote<PermissionObserver>>>
      observers_;
  std::unique_ptr<base::RunLoop> run_loop_;
  Vector<MojoPermissionStatus> initial_statuses_;
  bool should_defer_registered_callback_ = false;
  base::OnceClosure pepc_registered_callback_;
  mojo::Remote<mojom::blink::EmbeddedPermissionControlClient> client_;
  std::unique_ptr<base::RunLoop> client_disconnect_run_loop_;
};

class RegistrationWaiter {
 public:
  explicit RegistrationWaiter(HTMLPermissionElement* element)
      : element_(element) {}

  RegistrationWaiter(const RegistrationWaiter&) = delete;
  RegistrationWaiter& operator=(const RegistrationWaiter&) = delete;

  void Wait() {
    PostDelayedTask();
    run_loop_.Run();
  }

  void PostDelayedTask() {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        WTF::BindOnce(&RegistrationWaiter::VerifyRegistration,
                      base::Unretained(this)),
        base::Milliseconds(500));
  }
  void VerifyRegistration() {
    if (element_ && !element_->IsRegisteredInBrowserProcess()) {
      PostDelayedTask();
    } else {
      run_loop_.Quit();
    }
  }

 private:
  WeakPersistent<HTMLPermissionElement> element_;
  base::RunLoop run_loop_;
};

class HTMLPemissionElementTest : public HTMLPemissionElementTestBase {
 protected:
  HTMLPemissionElementTest() = default;

  HTMLPemissionElementTest(base::test::TaskEnvironment::TimeSource time_source)
      : HTMLPemissionElementTestBase(time_source) {}

  void SetUp() override {
    HTMLPemissionElementTestBase::SetUp();
    GetFrame().GetBrowserInterfaceBroker().SetBinderForTesting(
        PermissionService::Name_,
        base::BindRepeating(&TestPermissionService::BindHandle,
                            base::Unretained(&permission_service_)));
  }

  void TearDown() override {
    GetFrame().GetBrowserInterfaceBroker().SetBinderForTesting(
        PermissionService::Name_, {});
    HTMLPemissionElementTestBase::TearDown();
  }

  TestPermissionService* permission_service() { return &permission_service_; }

  HTMLPermissionElement* CreatePermissionElement(
      const char* permission,
      bool precise_location = false) {
    HTMLPermissionElement* permission_element =
        MakeGarbageCollected<HTMLPermissionElement>(GetDocument());
    permission_element->setAttribute(html_names::kTypeAttr,
                                     AtomicString(permission));
    if (precise_location) {
      permission_element->setAttribute(html_names::kPreciselocationAttr,
                                       AtomicString(""));
    }
    GetDocument().body()->AppendChild(permission_element);
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
    return permission_element;
  }

 private:
  TestPermissionService permission_service_;
  ScopedTestingPlatformSupport<LocalePlatformSupport> support_;
};

// ... (DeferredChecker class as provided)

TEST_F(HTMLPemissionElementTest, InitializeInnerText) {
  // ... (Test implementation as provided)
}

TEST_F(HTMLPemissionElementTest, TranslateInnerText) {
  // ... (Test implementation as provided)
}

// Regression test for crbug.com/341875650, check that a detached layout tree
// permission element doesn't crash the renderer process.
TEST_F(HTMLPemissionElementTest, AfterDetachLayoutTreeCrashTest) {
  // ... (Test implementation as provided)
}

TEST_F(HTMLPemissionElementTest, SetTypeAfterInsertedInto) {
  // ... (Test implementation as provided)
}

TEST_F(HTMLPemissionElementTest, SetInnerTextAfterRegistrationSingleElement) {
  // ... (Test implementation as provided)
}

TEST_F(HTMLPemissionElementTest,
       SetInnerTextAfterRegistrationCameraMicrophonePermissions) {
  // ... (Test implementation as provided)
}

TEST_F(HTMLPemissionElementTest, StatusChangeSinglePermissionElement) {
  // ... (Test implementation as provided)
}
```

```
这是目录为blink/renderer/core/html/html_permission_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 功能归纳 (Part 1)

这个C++测试文件 `html_permission_element_test.cc` 的主要功能是**测试 Chromium Blink 引擎中 `<permission>` 元素 (`HTMLPermissionElement`) 的行为和功能**。 它通过编写各种单元测试用例，来验证该元素在不同场景下的正确性。

**具体功能点 (基于提供的代码片段):**

1. **属性设置和解析:**
   - 测试了 `<permission>` 元素的 `type` 属性的设置和获取，例如 `permission_element->setAttribute(html_names::kTypeAttr, AtomicString("camera"));`。
   - 测试了 `preciselocation` 属性的设置和解析，以及它如何影响内部状态 (`is_precise_location_`)。
   - 测试了 `type` 属性的值（例如 "camera", "geolocation", "camera microphone"）如何被解析成对应的权限描述符 (`PermissionDescriptorPtr`)。

2. **权限状态管理和交互:**
   - 使用 `TestPermissionService` 模拟了浏览器进程中的权限服务，用于控制和模拟权限状态的变化 (GRANTED, ASK, DENIED)。
   - 测试了 `<permission>` 元素如何注册到浏览器进程以监听权限状态的变化 (`RegisterPageEmbeddedPermissionControl`).
   - 测试了当权限状态改变时，元素内部的文本内容是否会相应更新，例如从 "Use location" 变为 "Location allowed"。
   - 使用 `PermissionStatusChangeWaiter` 来异步等待权限状态变化的通知。

3. **文本内容的初始化和翻译:**
   - 测试了 `<permission>` 元素在不同权限状态下，其内部显示的文本内容是否正确初始化，例如 "Use camera"。
   - 测试了 `lang` 属性对元素内部文本内容的影响，即本地化翻译是否生效，例如 `<permission type="geolocation" lang="pt">` 会显示葡萄牙语的文本。

4. **生命周期管理:**
   - 测试了 `<permission>` 元素在插入到 DOM 树前后设置 `type` 属性的行为。
   - 涉及了布局树的附加和分离，并测试了在分离后重新附加布局树的情况下，元素是否能正常工作，防止崩溃。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:**
    * **直接关系:**  该测试文件直接测试了 HTML `<permission>` 元素的行为，包括其属性 (`type`, `preciselocation`, `lang`) 的解析和作用。
    * **示例:** 测试用例中创建并操作 `<permission>` 元素，例如 `MakeGarbageCollected<HTMLPermissionElement>(GetDocument())` 和 `permission_element->setAttribute(...)`。
* **CSS:**
    * **间接关系:** 虽然这个代码片段没有直接涉及 CSS 的测试，但其中一个测试用例 `InitializeInnerText` 设置了 `style` 属性 (`width: auto; height: auto`)，这表明元素的渲染和布局受到 CSS 的影响。  `<permission>` 元素的最终呈现样式会受到 CSS 规则的影响。
    * **示例:**  `permission_element->setAttribute(html_names::kStyleAttr, AtomicString("width: auto; height: auto"));` 用于确保元素具有可计算的尺寸，以便后续检查其边界矩形。
* **JavaScript:**
    * **间接关系:**  `<permission>` 元素最终会暴露给 JavaScript 进行操作和交互。 JavaScript 可以通过 DOM API 来访问和修改 `<permission>` 元素的属性，并监听其状态变化（尽管在这个测试文件中，状态变化是由模拟的浏览器服务触发的）。
    * **示例:**  开发者可以使用 JavaScript 来动态创建 `<permission>` 元素，设置其 `type` 属性，或者根据其状态执行不同的操作。例如：
      ```javascript
      const permissionElement = document.createElement('permission');
      permissionElement.type = 'camera';
      document.body.appendChild(permissionElement);

      // 可能监听 permissionElement 的某些事件 (虽然标准 <permission> 元素没有标准事件，这里只是假设)
      ```

**逻辑推理示例：**

* **假设输入:**  创建一个 `<permission>` 元素，设置 `type` 属性为 "geolocation"。
* **输出:**  该元素内部会显示与地理位置权限相关的提示文本，例如 "Use location"。如果浏览器权限服务返回该权限已被授予，则文本可能会变为 "Location allowed"。

**常见的使用错误示例 (基于代码理解，可能不完全涵盖实际使用场景)：**

* **编程错误:**
    * **`type` 属性值拼写错误或使用不支持的值:** 例如，将 `type` 设置为 "camer" 而不是 "camera"，会导致权限解析失败，元素可能无法正常工作。测试用例 `ParsePermissionDescriptorsFromType` 中就包含了这种情况。
    * **忘记处理权限状态变化:**  开发者可能创建了 `<permission>` 元素，但没有监听或处理权限状态的改变，导致 UI 没有及时更新。
* **用户错误 (更多体现在实际应用中，测试代码侧重于开发者使用):**
    * **用户在浏览器中拒绝了权限请求:** 虽然测试代码模拟了权限状态，但在实际应用中，用户可能会拒绝权限，开发者需要处理这种情况。

**总结:**

这部分测试代码主要关注 `<permission>` 元素的基础功能，包括属性处理、权限状态的初始交互、以及文本内容的显示和翻译。它通过模拟浏览器权限服务来隔离测试 `<permission>` 元素自身的逻辑。后续的部分很可能会涉及更复杂的用户交互、事件处理以及与其他浏览器 API 的集成测试。

### 提示词
```
这是目录为blink/renderer/core/html/html_permission_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/html_permission_element.h"

#include <optional>

#include "base/compiler_specific.h"
#include "base/run_loop.h"
#include "base/test/run_until.h"
#include "base/test/scoped_feature_list.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/public/strings/grit/permission_element_generated_strings.h"
#include "third_party/blink/public/strings/grit/permission_element_strings.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_permission_state.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_init.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

using mojom::blink::EmbeddedPermissionControlResult;
using mojom::blink::EmbeddedPermissionRequestDescriptor;
using mojom::blink::EmbeddedPermissionRequestDescriptorPtr;
using mojom::blink::PermissionDescriptor;
using mojom::blink::PermissionDescriptorPtr;
using mojom::blink::PermissionName;
using mojom::blink::PermissionObserver;
using mojom::blink::PermissionService;
using MojoPermissionStatus = mojom::blink::PermissionStatus;

namespace {

constexpr char16_t kGeolocationStringPt[] = u"Usar localização";
constexpr char16_t kGeolocationAllowedStringPt[] =
    u"Acesso à localização permitido";
constexpr char16_t kGeolocationStringBr[] = u"Usar local";
constexpr char16_t kGeolocationAllowedStringBr[] =
    u"Acesso à localização permitido";
constexpr char16_t kGeolocationStringTa[] = u"இருப்பிடத்தைப் பயன்படுத்து";
constexpr char16_t kGeolocationAllowedStringTa[] = u"இருப்பிட அனுமதி வழங்கப்பட்டது";

constexpr char kCameraString[] = "Use camera";
constexpr char kCameraAllowedString[] = "Camera allowed";
constexpr char kMicrophoneString[] = "Use microphone";
constexpr char kMicrophoneAllowedString[] = "Microphone allowed";
constexpr char kGeolocationString[] = "Use location";
constexpr char kGeolocationAllowedString[] = "Location allowed";
constexpr char kCameraMicrophoneString[] = "Use microphone and camera";
constexpr char kCameraMicrophoneAllowedString[] =
    "Camera and microphone allowed";
constexpr char kPreciseGeolocationString[] = "Use precise location";
constexpr char kPreciseGeolocationAllowedString[] = "Precise location allowed";

constexpr base::TimeDelta kDefaultTimeout = base::Milliseconds(500);
constexpr base::TimeDelta kSmallTimeout = base::Milliseconds(50);

class LocalePlatformSupport : public TestingPlatformSupport {
 public:
  WebString QueryLocalizedString(int resource_id) override {
    switch (resource_id) {
      case IDS_PERMISSION_REQUEST_CAMERA:
        return kCameraString;
      case IDS_PERMISSION_REQUEST_MICROPHONE:
        return kMicrophoneString;
      case IDS_PERMISSION_REQUEST_GEOLOCATION:
        return kGeolocationString;
      case IDS_PERMISSION_REQUEST_CAMERA_ALLOWED:
        return kCameraAllowedString;
      case IDS_PERMISSION_REQUEST_GEOLOCATION_ALLOWED:
        return kGeolocationAllowedString;
      case IDS_PERMISSION_REQUEST_MICROPHONE_ALLOWED:
        return kMicrophoneAllowedString;
      case IDS_PERMISSION_REQUEST_CAMERA_MICROPHONE:
        return kCameraMicrophoneString;
      case IDS_PERMISSION_REQUEST_CAMERA_MICROPHONE_ALLOWED:
        return kCameraMicrophoneAllowedString;
      case IDS_PERMISSION_REQUEST_PRECISE_GEOLOCATION:
        return kPreciseGeolocationString;
      case IDS_PERMISSION_REQUEST_PRECISE_GEOLOCATION_ALLOWED:
        return kPreciseGeolocationAllowedString;
      case IDS_PERMISSION_REQUEST_GEOLOCATION_pt_PT:
        return WebString::FromUTF16(kGeolocationStringPt);
      case IDS_PERMISSION_REQUEST_GEOLOCATION_ALLOWED_pt_PT:
        return WebString::FromUTF16(kGeolocationAllowedStringPt);
      case IDS_PERMISSION_REQUEST_GEOLOCATION_pt_BR:
        return WebString::FromUTF16(kGeolocationStringBr);
      case IDS_PERMISSION_REQUEST_GEOLOCATION_ALLOWED_pt_BR:
        return WebString::FromUTF16(kGeolocationAllowedStringBr);
      case IDS_PERMISSION_REQUEST_GEOLOCATION_ta:
        return WebString::FromUTF16(kGeolocationStringTa);
      case IDS_PERMISSION_REQUEST_GEOLOCATION_ALLOWED_ta:
        return WebString::FromUTF16(kGeolocationAllowedStringTa);
      default:
        break;
    }
    return TestingPlatformSupport::QueryLocalizedString(resource_id);
  }
};

void NotReachedForPEPCRegistered() {
  EXPECT_TRUE(false)
      << "The RegisterPageEmbeddedPermissionControl was called despite the "
         "test expecting it not to.";
}

V8PermissionState::Enum PermissionStatusV8Enum(MojoPermissionStatus status) {
  switch (status) {
    case MojoPermissionStatus::GRANTED:
      return V8PermissionState::Enum::kGranted;
    case MojoPermissionStatus::ASK:
      return V8PermissionState::Enum::kPrompt;
    case MojoPermissionStatus::DENIED:
      return V8PermissionState::Enum::kDenied;
  }
}

}  // namespace

class HTMLPemissionElementTestBase : public PageTestBase {
 protected:
  HTMLPemissionElementTestBase() = default;

  HTMLPemissionElementTestBase(
      base::test::TaskEnvironment::TimeSource time_source)
      : PageTestBase(time_source) {}

  void SetUp() override {
    scoped_feature_list_.InitAndEnableFeature(
        blink::features::kPermissionElement);
    PageTestBase::SetUp();
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
  ScopedPermissionElementForTest scoped_feature_{true};
};

TEST_F(HTMLPemissionElementTestBase, SetTypeAttribute) {
  auto* permission_element =
      MakeGarbageCollected<HTMLPermissionElement>(GetDocument());
  permission_element->setAttribute(html_names::kTypeAttr,
                                   AtomicString("camera"));
  permission_element->setAttribute(html_names::kTypeAttr,
                                   AtomicString("geolocation"));

  EXPECT_EQ(AtomicString("camera"), permission_element->GetType());
}

TEST_F(HTMLPemissionElementTestBase, SetPreciseLocationAttribute) {
  auto* permission_element =
      MakeGarbageCollected<HTMLPermissionElement>(GetDocument());

  EXPECT_FALSE(permission_element->is_precise_location_);

  permission_element->setAttribute(html_names::kPreciselocationAttr,
                                   AtomicString(""));
  EXPECT_TRUE(permission_element->is_precise_location_);

  permission_element->removeAttribute(html_names::kPreciselocationAttr);
  EXPECT_TRUE(permission_element->is_precise_location_);
}

TEST_F(HTMLPemissionElementTestBase, ParsePermissionDescriptorsFromType) {
  struct TestData {
    const char* type;
    Vector<PermissionName> expected_permissions;
  } test_data[] = {
      {"camer", {}},
      {"camera", {PermissionName::VIDEO_CAPTURE}},
      {"microphone", {PermissionName::AUDIO_CAPTURE}},
      {"geolocation", {PermissionName::GEOLOCATION}},
      {"camera microphone",
       {PermissionName::VIDEO_CAPTURE, PermissionName::AUDIO_CAPTURE}},
      {" camera     microphone ",
       {PermissionName::VIDEO_CAPTURE, PermissionName::AUDIO_CAPTURE}},
      {"camera   invalid", {}},
      // For MVP, we only support group permissions of camera and microphone
      {"camera microphone geolocation", {}},
      {"camera geolocation", {}},
      {"camera camera", {PermissionName::VIDEO_CAPTURE}},
      {"microphone geolocation", {}},
  };

  for (const auto& data : test_data) {
    Vector<PermissionDescriptorPtr> expected_permission_descriptors;
    expected_permission_descriptors.reserve(data.expected_permissions.size());
    base::ranges::transform(data.expected_permissions,
                            std::back_inserter(expected_permission_descriptors),
                            [&](const auto& name) {
                              auto descriptor = PermissionDescriptor::New();
                              descriptor->name = name;
                              return descriptor;
                            });
    auto* permission_element =
        MakeGarbageCollected<HTMLPermissionElement>(GetDocument());
    permission_element->setAttribute(html_names::kTypeAttr,
                                     AtomicString(data.type));
    EXPECT_EQ(expected_permission_descriptors,
              permission_element->ParsePermissionDescriptorsForTesting(
                  permission_element->GetType()));
  }
}

// Helper class used to wait until receiving a permission status change event.
class PermissionStatusChangeWaiter : public PermissionObserver {
 public:
  explicit PermissionStatusChangeWaiter(
      mojo::PendingReceiver<PermissionObserver> receiver,
      base::OnceClosure callback)
      : receiver_(this, std::move(receiver)), callback_(std::move(callback)) {}

  // PermissionObserver override
  void OnPermissionStatusChange(MojoPermissionStatus status) override {
    if (callback_) {
      std::move(callback_).Run();
    }
  }

 private:
  mojo::Receiver<PermissionObserver> receiver_;
  base::OnceClosure callback_;
};

class TestPermissionService : public PermissionService {
 public:
  explicit TestPermissionService() = default;
  ~TestPermissionService() override = default;

  void BindHandle(mojo::ScopedMessagePipeHandle handle) {
    receivers_.Add(this,
                   mojo::PendingReceiver<PermissionService>(std::move(handle)));
  }

  // mojom::blink::PermissionService implementation
  void HasPermission(PermissionDescriptorPtr permission,
                     HasPermissionCallback) override {}
  void RegisterPageEmbeddedPermissionControl(
      Vector<PermissionDescriptorPtr> permissions,
      mojo::PendingRemote<mojom::blink::EmbeddedPermissionControlClient>
          pending_client) override {
    if (pepc_registered_callback_) {
      std::move(pepc_registered_callback_).Run();
      return;
    }

    if (should_defer_registered_callback_) {
      pepc_registered_callback_ = WTF::BindOnce(
          &TestPermissionService::RegisterPageEmbeddedPermissionControlInternal,
          base::Unretained(this), std::move(permissions),
          std::move(pending_client));
      return;
    }

    RegisterPageEmbeddedPermissionControlInternal(std::move(permissions),
                                                  std::move(pending_client));
  }

  void RegisterPageEmbeddedPermissionControlInternal(
      Vector<PermissionDescriptorPtr> permissions,
      mojo::PendingRemote<mojom::blink::EmbeddedPermissionControlClient>
          pending_client) {
    Vector<MojoPermissionStatus> statuses =
        initial_statuses_.empty()
            ? Vector<MojoPermissionStatus>(permissions.size(),
                                           MojoPermissionStatus::ASK)
            : initial_statuses_;
    client_ = mojo::Remote<mojom::blink::EmbeddedPermissionControlClient>(
        std::move(pending_client));
    client_.set_disconnect_handler(base::BindOnce(
        &TestPermissionService::OnMojoDisconnect, base::Unretained(this)));
    client_->OnEmbeddedPermissionControlRegistered(/*allowed=*/true,
                                                   std::move(statuses));
  }

  void OnMojoDisconnect() {
    if (client_disconnect_run_loop_) {
      client_disconnect_run_loop_->Quit();
    }
  }

  void RequestPageEmbeddedPermission(
      EmbeddedPermissionRequestDescriptorPtr permissions,
      RequestPageEmbeddedPermissionCallback) override {}
  void RequestPermission(PermissionDescriptorPtr permission,
                         bool user_gesture,
                         RequestPermissionCallback) override {}
  void RequestPermissions(Vector<PermissionDescriptorPtr> permissions,
                          bool user_gesture,
                          RequestPermissionsCallback) override {}
  void RevokePermission(PermissionDescriptorPtr permission,
                        RevokePermissionCallback) override {}
  void AddPermissionObserver(
      PermissionDescriptorPtr permission,
      MojoPermissionStatus last_known_status,
      mojo::PendingRemote<PermissionObserver> observer) override {}
  void AddPageEmbeddedPermissionObserver(
      PermissionDescriptorPtr permission,
      MojoPermissionStatus last_known_status,
      mojo::PendingRemote<PermissionObserver> observer) override {
    observers_.emplace_back(permission->name, mojo::Remote<PermissionObserver>(
                                                  std::move(observer)));
    if (run_loop_) {
      run_loop_->Quit();
    }
  }

  void NotifyEventListener(PermissionDescriptorPtr permission,
                           const String& event_type,
                           bool is_added) override {}

  void NotifyPermissionStatusChange(PermissionName name,
                                    MojoPermissionStatus status) {
    for (const auto& observer : observers_) {
      if (observer.first == name) {
        observer.second->OnPermissionStatusChange(status);
      }
    }
    WaitForPermissionStatusChange(status);
  }

  void WaitForPermissionStatusChange(MojoPermissionStatus status) {
    mojo::Remote<PermissionObserver> observer;
    base::RunLoop run_loop;
    auto waiter = std::make_unique<PermissionStatusChangeWaiter>(
        observer.BindNewPipeAndPassReceiver(), run_loop.QuitClosure());
    observer->OnPermissionStatusChange(status);
    run_loop.Run();
  }

  void WaitForPermissionObserverAdded() {
    run_loop_ = std::make_unique<base::RunLoop>();
    run_loop_->Run();
  }

  void WaitForClientDisconnected() {
    client_disconnect_run_loop_ = std::make_unique<base::RunLoop>();
    client_disconnect_run_loop_->Run();
  }

  void set_initial_statuses(const Vector<MojoPermissionStatus>& statuses) {
    initial_statuses_ = statuses;
  }

  void set_pepc_registered_callback(base::OnceClosure callback) {
    pepc_registered_callback_ = std::move(callback);
  }

  base::OnceClosure TakePEPCRegisteredCallback() {
    return std::move(pepc_registered_callback_);
  }

  void set_should_defer_registered_callback(bool should_defer) {
    should_defer_registered_callback_ = should_defer;
  }

 private:
  mojo::ReceiverSet<PermissionService> receivers_;
  Vector<std::pair<PermissionName, mojo::Remote<PermissionObserver>>>
      observers_;
  std::unique_ptr<base::RunLoop> run_loop_;
  Vector<MojoPermissionStatus> initial_statuses_;
  bool should_defer_registered_callback_ = false;
  base::OnceClosure pepc_registered_callback_;
  mojo::Remote<mojom::blink::EmbeddedPermissionControlClient> client_;
  std::unique_ptr<base::RunLoop> client_disconnect_run_loop_;
};

class RegistrationWaiter {
 public:
  explicit RegistrationWaiter(HTMLPermissionElement* element)
      : element_(element) {}

  RegistrationWaiter(const RegistrationWaiter&) = delete;
  RegistrationWaiter& operator=(const RegistrationWaiter&) = delete;

  void Wait() {
    PostDelayedTask();
    run_loop_.Run();
  }

  void PostDelayedTask() {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        WTF::BindOnce(&RegistrationWaiter::VerifyRegistration,
                      base::Unretained(this)),
        base::Milliseconds(500));
  }
  void VerifyRegistration() {
    if (element_ && !element_->IsRegisteredInBrowserProcess()) {
      PostDelayedTask();
    } else {
      run_loop_.Quit();
    }
  }

 private:
  WeakPersistent<HTMLPermissionElement> element_;
  base::RunLoop run_loop_;
};

class HTMLPemissionElementTest : public HTMLPemissionElementTestBase {
 protected:
  HTMLPemissionElementTest() = default;

  HTMLPemissionElementTest(base::test::TaskEnvironment::TimeSource time_source)
      : HTMLPemissionElementTestBase(time_source) {}

  void SetUp() override {
    HTMLPemissionElementTestBase::SetUp();
    GetFrame().GetBrowserInterfaceBroker().SetBinderForTesting(
        PermissionService::Name_,
        base::BindRepeating(&TestPermissionService::BindHandle,
                            base::Unretained(&permission_service_)));
  }

  void TearDown() override {
    GetFrame().GetBrowserInterfaceBroker().SetBinderForTesting(
        PermissionService::Name_, {});
    HTMLPemissionElementTestBase::TearDown();
  }

  TestPermissionService* permission_service() { return &permission_service_; }

  HTMLPermissionElement* CreatePermissionElement(
      const char* permission,
      bool precise_location = false) {
    HTMLPermissionElement* permission_element =
        MakeGarbageCollected<HTMLPermissionElement>(GetDocument());
    permission_element->setAttribute(html_names::kTypeAttr,
                                     AtomicString(permission));
    if (precise_location) {
      permission_element->setAttribute(html_names::kPreciselocationAttr,
                                       AtomicString(""));
    }
    GetDocument().body()->AppendChild(permission_element);
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
    return permission_element;
  }

 private:
  TestPermissionService permission_service_;
  ScopedTestingPlatformSupport<LocalePlatformSupport> support_;
};

// TODO(crbug.com/1315595): remove this class and use
// `SimTest(base::test::TaskEnvironment::TimeSource::MOCK_TIME)` once migration
// to blink_unittests_v2 completes. We then can simply use
// `time_environment()->FastForwardBy()`
class DeferredChecker {
 public:
  explicit DeferredChecker(HTMLPermissionElement* element,
                           WebLocalFrameImpl* main_frame = nullptr)
      : element_(element), main_frame_(main_frame) {}

  DeferredChecker(const DeferredChecker&) = delete;
  DeferredChecker& operator=(const DeferredChecker&) = delete;

  void CheckClickingEnabledAfterDelay(base::TimeDelta time,
                                      bool expected_enabled) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        WTF::BindOnce(&DeferredChecker::CheckClickingEnabled,
                      base::Unretained(this), expected_enabled),
        time);
    run_loop_ = std::make_unique<base::RunLoop>();
    run_loop_->Run();
  }

  void CheckClickingEnabled(bool enabled) {
    CHECK(element_);
    EXPECT_EQ(element_->IsClickingEnabled(), enabled);
    if (run_loop_) {
      run_loop_->Quit();
    }
  }

  void CheckConsoleMessageAfterDelay(
      base::TimeDelta time,
      unsigned int expected_count,
      std::optional<String> expected_text = std::nullopt) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        WTF::BindOnce(&DeferredChecker::CheckConsoleMessage,
                      base::Unretained(this), expected_count,
                      std::move(expected_text)),
        time);
    run_loop_ = std::make_unique<base::RunLoop>();
    run_loop_->Run();
  }

  void CheckConsoleMessage(unsigned int expected_count,
                           std::optional<String> expected_text = std::nullopt) {
    CHECK(main_frame_);
    auto& console_messages =
        static_cast<frame_test_helpers::TestWebFrameClient*>(
            main_frame_->Client())
            ->ConsoleMessages();
    EXPECT_EQ(console_messages.size(), expected_count);

    if (expected_text.has_value()) {
      EXPECT_TRUE(console_messages.back().Contains(expected_text.value()));
    }
    if (run_loop_) {
      run_loop_->Quit();
    }
  }

 private:
  Persistent<HTMLPermissionElement> element_ = nullptr;
  Persistent<WebLocalFrameImpl> main_frame_ = nullptr;
  std::unique_ptr<base::RunLoop> run_loop_;
};

TEST_F(HTMLPemissionElementTest, InitializeInnerText) {
  CachedPermissionStatus::From(GetDocument().domWindow())
      ->SetPermissionStatusMap({{blink::mojom::PermissionName::VIDEO_CAPTURE,
                                 MojoPermissionStatus::ASK},
                                {blink::mojom::PermissionName::AUDIO_CAPTURE,
                                 MojoPermissionStatus::ASK},
                                {blink::mojom::PermissionName::GEOLOCATION,
                                 MojoPermissionStatus::ASK}});
  const struct {
    const char* type;
    String expected_text;
    bool precise_location = false;
  } kTestData[] = {{"geolocation", kGeolocationString},
                   {"microphone", kMicrophoneString},
                   {"camera", kCameraString},
                   {"camera microphone", kCameraMicrophoneString},
                   {"geolocation", kPreciseGeolocationString, true},
                   {"geolocation", kGeolocationString, false}};
  for (const auto& data : kTestData) {
    auto* permission_element =
        MakeGarbageCollected<HTMLPermissionElement>(GetDocument());
    permission_element->setAttribute(html_names::kTypeAttr,
                                     AtomicString(data.type));
    if (data.precise_location) {
      permission_element->setAttribute(html_names::kPreciselocationAttr,
                                       AtomicString(""));
    }
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

TEST_F(HTMLPemissionElementTest, TranslateInnerText) {
  const struct {
    const char* lang_attr_value;
    String expected_text_ask;
    String expected_text_allowed;
  } kTestData[] = {
      // no language means the default string
      {"", kGeolocationString, kGeolocationAllowedString},
      // "pt" selects Portuguese
      {"pT", kGeolocationStringPt, kGeolocationAllowedStringPt},
      // "pt-br" selects brazilian Portuguese
      {"pt-BR", kGeolocationStringBr, kGeolocationAllowedStringBr},
      // "pt" and a country that has no defined separate translation falls back
      // to Portuguese
      {"Pt-cA", kGeolocationStringPt, kGeolocationAllowedStringPt},
      // "pt" and something that is not a country falls back to Portuguese
      {"PT-gIbbeRish", kGeolocationStringPt, kGeolocationAllowedStringPt},
      // unrecognized locale selects the default string
      {"gibBeRish", kGeolocationString, kGeolocationAllowedString},
      // try tamil to test non-english-alphabet-based language
      {"ta", kGeolocationStringTa, kGeolocationAllowedStringTa}};

  auto* permission_element = CreatePermissionElement("geolocation");
  // Calling one more time waiting for the cache observer.
  permission_service()->WaitForPermissionObserverAdded();
  permission_service()->WaitForPermissionObserverAdded();
  for (const auto& data : kTestData) {
    permission_element->setAttribute(html_names::kLangAttr,
                                     AtomicString(data.lang_attr_value));
    permission_service()->NotifyPermissionStatusChange(
        PermissionName::GEOLOCATION, MojoPermissionStatus::ASK);
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
    EXPECT_EQ(
        data.expected_text_ask,
        permission_element->permission_text_span_for_testing()->innerText());

    permission_service()->NotifyPermissionStatusChange(
        PermissionName::GEOLOCATION, MojoPermissionStatus::GRANTED);
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
    EXPECT_EQ(
        data.expected_text_allowed,
        permission_element->permission_text_span_for_testing()->innerText());
  }
}

// Regression test for crbug.com/341875650, check that a detached layout tree
// permission element doesn't crash the renderer process.
TEST_F(HTMLPemissionElementTest, AfterDetachLayoutTreeCrashTest) {
  auto* permission_element = CreatePermissionElement("camera");
  RegistrationWaiter(permission_element).Wait();
  permission_element->SetForceReattachLayoutTree();
  UpdateAllLifecyclePhasesForTest();
  RegistrationWaiter(permission_element).Wait();
  // We end up here if the renderer process did not crash.
}

TEST_F(HTMLPemissionElementTest, SetTypeAfterInsertedInto) {
  const struct {
    const char* type;
    MojoPermissionStatus status;
    String expected_text;
    bool precise_location = false;
  } kTestData[] = {
      {"geolocation", MojoPermissionStatus::ASK, kGeolocationString},
      {"microphone", MojoPermissionStatus::ASK, kMicrophoneString},
      {"camera", MojoPermissionStatus::ASK, kCameraString},
      {"geolocation", MojoPermissionStatus::DENIED, kGeolocationString},
      {"microphone", MojoPermissionStatus::DENIED, kMicrophoneString},
      {"camera", MojoPermissionStatus::DENIED, kCameraString},
      {"geolocation", MojoPermissionStatus::GRANTED, kGeolocationAllowedString},
      {"microphone", MojoPermissionStatus::GRANTED, kMicrophoneAllowedString},
      {"camera", MojoPermissionStatus::GRANTED, kCameraAllowedString},
      {"geolocation", MojoPermissionStatus::ASK, kPreciseGeolocationString,
       true},
      {"geolocation", MojoPermissionStatus::DENIED, kPreciseGeolocationString,
       true},
      {"geolocation", MojoPermissionStatus::GRANTED,
       kPreciseGeolocationAllowedString, true},

      // Only affects geolocation.
      {"camera", MojoPermissionStatus::GRANTED, kCameraAllowedString, true},
      {"microphone", MojoPermissionStatus::ASK, kMicrophoneString, true},
  };
  for (const auto& data : kTestData) {
    auto* permission_element =
        MakeGarbageCollected<HTMLPermissionElement>(GetDocument());
    permission_element->GetPermissionService();
    GetDocument().body()->AppendChild(permission_element);
    permission_service()->set_initial_statuses({data.status});
    permission_element->setAttribute(html_names::kTypeAttr,
                                     AtomicString(data.type));
    if (data.precise_location) {
      permission_element->setAttribute(html_names::kPreciselocationAttr,
                                       AtomicString(""));
    }
    RegistrationWaiter(permission_element).Wait();
    EXPECT_EQ(
        data.expected_text,
        permission_element->permission_text_span_for_testing()->innerText());
  }
}

TEST_F(HTMLPemissionElementTest, SetInnerTextAfterRegistrationSingleElement) {
  const struct {
    const char* type;
    MojoPermissionStatus status;
    String expected_text;
    bool precise_location = false;
  } kTestData[] = {
      {"geolocation", MojoPermissionStatus::ASK, kGeolocationString},
      {"microphone", MojoPermissionStatus::ASK, kMicrophoneString},
      {"camera", MojoPermissionStatus::ASK, kCameraString},
      {"geolocation", MojoPermissionStatus::DENIED, kGeolocationString},
      {"microphone", MojoPermissionStatus::DENIED, kMicrophoneString},
      {"camera", MojoPermissionStatus::DENIED, kCameraString},
      {"geolocation", MojoPermissionStatus::GRANTED, kGeolocationAllowedString},
      {"microphone", MojoPermissionStatus::GRANTED, kMicrophoneAllowedString},
      {"camera", MojoPermissionStatus::GRANTED, kCameraAllowedString},
      {"geolocation", MojoPermissionStatus::ASK, kPreciseGeolocationString,
       true},
      {"geolocation", MojoPermissionStatus::DENIED, kPreciseGeolocationString,
       true},
      {"geolocation", MojoPermissionStatus::GRANTED,
       kPreciseGeolocationAllowedString, true},

      // Only affects geolocation.
      {"camera", MojoPermissionStatus::GRANTED, kCameraAllowedString, true},
      {"microphone", MojoPermissionStatus::ASK, kMicrophoneString, true},
  };
  for (const auto& data : kTestData) {
    auto* permission_element =
        CreatePermissionElement(data.type, data.precise_location);
    permission_service()->set_initial_statuses({data.status});
    RegistrationWaiter(permission_element).Wait();
    EXPECT_EQ(
        data.expected_text,
        permission_element->permission_text_span_for_testing()->innerText());
  }
}

TEST_F(HTMLPemissionElementTest,
       SetInnerTextAfterRegistrationCameraMicrophonePermissions) {
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
    permission_service()->set_initial_statuses(
        {data.camera_status, data.microphone_status});
    RegistrationWaiter(permission_element).Wait();
    EXPECT_EQ(
        data.expected_text,
        permission_element->permission_text_span_for_testing()->innerText());
  }
}

TEST_F(HTMLPemissionElementTest, StatusChangeSinglePermissionElement) {
  const struct {
    const char* type;
    PermissionName name;
    MojoPermissionStatus status;
    String expected_text;
    bool precise_location = false;
  } kTestData[] = {
      {"geolocation", PermissionName::GEOLOCATION, MojoPermissionStatus::ASK,
       kGeolocationString},
      {"microphone", PermissionName::AUDIO_CAPTURE, MojoPermissionStatus::ASK,
       kMicrophoneString},
      {"camera", PermissionName::VIDEO_CAPTURE, MojoPermissionStatus::ASK,
       kCameraString},
      {"geolocation", PermissionName::GEOLOCATION, MojoPermissionStatus::DENIED,
       kGeolocationString},
      {"microphone", PermissionName::AUDIO_CAPTURE,
       MojoPermissionStatus::DENIED, kMicrophoneString},
      {"camera", PermissionName::VIDEO_CAPTURE, MojoPermissionStatus::DENIED,
       kCameraString},
      {"geolocation", PermissionName::GEOLOCATION,
       MojoPermissionStatus::GRANTED, kGeolocationAllowedString},
      {"microphone", PermissionName::AUDIO_CAPTURE,
       MojoPermissionStatus::GRANTED, kMicrophoneAllowedString},
      {"camera", PermissionName::VIDEO_CAPTURE, MojoPermissionStatus::GRANTED,
       kCameraAllowedString},
      {"geolocation", PermissionName::GEOLOCATION, MojoPermissionStatus::ASK,
       kPreciseGeolocationString, true},
      {"geolocation", PermissionName::GEOLOCATION, MojoPermissionStatus::DENIED,
       kPreciseGeolocationString, true},
      {"geolocation", PermissionName::GEOLOCATION,
       MojoPermissionStatus::GRANTED, kPreciseGeolocationAllowedString, true}};
  for (const auto& data : kTestData) {
    auto* permission_element =
        CreatePermissionElement(data.type, data.precise_location);
    // Calling one more time waiting for the cache observer.
    permission_service()->WaitForPermissionObserverAdded();
    permission_service()->WaitForPermissionObserverAdded();
    permission_service()->NotifyPermissionStatusChange(data.name, data.status);
    EXPECT_EQ(
        data.expected_text,
        permission_element->permission_text_span_for_testing()->innerText());
    GetDocumen
```
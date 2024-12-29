Response:
Let's break down the thought process for analyzing this C++ test file for Chromium's Blink engine.

**1. Initial Understanding of the Request:**

The core request is to understand the functionality of `picture_in_picture_controller_test.cc` and relate it to web technologies (JavaScript, HTML, CSS). It also asks for logical inferences, common errors, debugging hints, and a summary. The request explicitly states it's part 1 of 2, suggesting a broader context.

**2. Deconstructing the File's Structure (Skimming and Identifying Key Areas):**

My initial pass involves skimming the code to identify major sections and patterns. I look for:

* **Includes:** These tell me what other parts of the codebase this file interacts with. I see things related to:
    * `base`: Fundamental Chromium utilities.
    * `media/mojo/mojom`: Inter-process communication related to media.
    * `mojo`:  The core Mojo IPC framework.
    * `testing/gmock`, `testing/gtest`: C++ testing frameworks. This confirms it's a test file.
    * `third_party/blink/public/platform`: Public Blink interfaces.
    * `third_party/blink/renderer/bindings`:  Interaction with JavaScript through V8.
    * `third_party/blink/renderer/core`: Core Blink DOM and rendering logic.
    * `third_party/blink/renderer/modules/document_picture_in_picture`: The specific module being tested.
    * `third_party/blink/renderer/platform`: Platform-specific abstractions.
* **Namespaces:**  `blink` and an anonymous namespace. This helps organize the code.
* **Helper Functions/Classes:** I notice functions like `OpenDocumentPictureInPictureWindow` and classes like `MockPictureInPictureSession`, `MockPictureInPictureService`, `PictureInPictureControllerFrameClient`, etc. These are crucial for understanding the test setup. The "Mock" prefix strongly suggests these are used for isolating and controlling the behavior of dependencies.
* **Test Fixtures:** Classes like `PictureInPictureControllerTestWithWidget` and `PictureInPictureControllerTestWithChromeClient` inheriting from `RenderingTest`. This is a standard GTest pattern for setting up common test environments.
* **`TEST_F` Macros:**  These define the individual test cases. I scan the names to get a high-level idea of what's being tested (e.g., "EnterPictureInPictureFiresEvent", "ExitPictureInPictureFiresEvent", "DocumentPiPDoesNotAllowVizThrottling").

**3. Analyzing Key Components and Their Relationships:**

Now I delve deeper into the purpose of the identified components:

* **`OpenDocumentPictureInPictureWindow`:** This function appears to programmatically trigger the creation of a Document Picture-in-Picture window. I note the parameters (Document, URL, options) and the use of `DocumentPictureInPictureOptions`. This directly relates to the JavaScript API for Document PiP.
* **`MockPictureInPictureSession` and `MockPictureInPictureService`:** These are mock implementations of Mojo interfaces. They are used to simulate the browser's Picture-in-Picture service without actually going through the full system. The `MOCK_METHOD` macros indicate that the tests will assert on calls to these mocks (e.g., `StartSession`, `Stop`). This highlights the file's focus on testing the interaction with this service.
* **`PictureInPictureControllerFrameClient` and `PictureInPictureControllerPlayer`:** These seem to be custom implementations related to media playback, specifically for testing scenarios. The `OnRequestPictureInPicture` method in `PictureInPictureControllerPlayer` is a key point for triggering PiP for video elements.
* **Test Fixtures (`PictureInPictureControllerTestWithWidget`, `PictureInPictureControllerTestWithChromeClient`):** I recognize that `WithWidget` tests likely involve the rendering pipeline and `WithChromeClient` focuses on interactions with the browser's chrome.

**4. Relating to Web Technologies (JavaScript, HTML, CSS):**

Based on the code, I can start connecting the dots to web technologies:

* **JavaScript:** The inclusion of `ScriptPromise`, `ScriptPromiseResolver`, `DocumentPictureInPictureOptions`, and the `OpenDocumentPictureInPictureWindow` function strongly suggest testing the JavaScript API related to Document Picture-in-Picture. The test setup simulates the JavaScript calls that a web page would make.
* **HTML:** The use of `HTMLVideoElement` and the manipulation of its attributes (`src`, `poster`) directly link to HTML. The tests verify how the PiP controller interacts with video elements.
* **CSS:** The test with "EnterPictureInPictureProvideSourceBoundsSetToReplacedContentRect" explicitly manipulates CSS properties (`padding`, `width`, `height`, `transform`, `object-fit`) and verifies how the PiP window's source bounds are determined based on these styles, particularly with the `poster` image.

**5. Inferring Logic and Examples:**

I analyze the `TEST_F` names and the mock setups to infer the logic being tested. For example:

* "EnterPictureInPictureFiresEvent":  This implies that when PiP is entered, an event is dispatched to the video element. A likely input is a video element in a document, and the output is the dispatch of the 'enterpictureinpicture' event.
* "ExitPictureInPictureFiresEvent": Similar logic, but for the 'leavepictureinpicture' event.
* The tests involving `MockPictureInPictureService` and `MockPictureInPictureSession` demonstrate the interaction with the browser service. The tests set expectations on the arguments passed to `StartSession` (e.g., player ID, surface ID, size).

**6. Identifying Potential Errors and Debugging Hints:**

By understanding the test setup, I can identify potential user/programming errors:

* **Missing User Gesture:**  The code around `LocalFrame::NotifyUserActivation` in the Document PiP tests indicates that a user gesture is often required to open a PiP window. A common error is trying to open it programmatically without a recent user interaction.
* **Invalid State:** The "EnterPictureInPictureAfterResettingWMP" test explicitly checks for `DOMExceptionCode::kInvalidStateError`. This highlights that trying to enter PiP on a video element that has been reset is an invalid operation.
* **Security Context:** The `OpenDocumentPictureInPictureWindow` function has checks for `isSecureContext()`. This suggests that PiP might have security restrictions based on the page's origin (HTTPS).

For debugging, the steps outlined in the `OpenDocumentPictureInPictureWindow` function provide a trace: check for feature flags, document URL, security context, and user activation.

**7. Summarization (for Part 1):**

Finally, I synthesize the information gathered into a concise summary of the file's functionality, focusing on the key aspects identified above.

**Self-Correction/Refinement During the Process:**

* Initially, I might just see "Mojo" and not fully grasp its significance. But by looking at the mock classes and the `StartSession` calls, I realize that the file is heavily focused on testing the communication with the browser's PiP service.
* I might overlook the CSS aspect at first glance. However, the test case with "source bounds" and the explicit manipulation of style attributes in the code highlights the connection.
* I might need to re-read certain sections of the code or the GTest documentation to fully understand the test setup and assertions.

By following these steps iteratively, I can effectively analyze the provided C++ test file and generate a comprehensive explanation. The process involves a mix of code reading, pattern recognition, knowledge of web technologies and testing frameworks, and logical deduction.
这是文件 `blink/renderer/modules/document_picture_in_picture/picture_in_picture_controller_test.cc` 的第一部分，其主要功能是**测试 Blink 渲染引擎中 `PictureInPictureControllerImpl` 类的行为**，特别是针对**视频画中画 (Video Picture-in-Picture) 和文档画中画 (Document Picture-in-Picture)** 功能。

以下是对其功能的详细列举和与 Web 技术关系的说明：

**核心功能:**

1. **测试视频画中画 (Video Picture-in-Picture) 功能:**
   - **进入画中画:** 测试 `EnterPictureInPicture` 方法的正确性，包括：
     - 触发 `enterpictureinpicture` 事件。
     - 正确调用 Mojo 接口 (`PictureInPictureService`) 的 `StartSession` 方法，传递正确的参数，例如 `MediaPlayer` 的 ID、视频 Surface ID、视频尺寸等。
     - 测试在进入画中画后，帧节流 (Frame Throttling) 是否被正确禁用。
     - 验证在进入画中画后，`PictureInPictureControllerImpl` 是否正确记录了画中画元素。
     - 验证是否成功绑定了 Session 观察者 (Observer)。
     - 测试在某些情况下（例如视频时长为无限或使用 Media Source），画中画窗口是否不显示播放/暂停按钮。
     - 测试提供源边界 (Source Bounds) 时，是否正确设置为视频元素的边界或替换内容 (例如 poster 图片) 的边界。
     - 测试在 `HTMLVideoElement` 的 `persistentState` 属性为 `true` (模拟 Android 的自动画中画) 时，是否不允许进入画中画。
   - **退出画中画:** 测试 `ExitPictureInPicture` 方法的正确性，包括：
     - 触发 `leavepictureinpicture` 事件。
     - 正确调用 Mojo 接口 (`PictureInPictureSession`) 的 `Stop` 方法。
     - 测试在退出画中画后，帧节流是否被重新启用。
     - 验证在退出画中画后，`PictureInPictureControllerImpl` 是否清除了画中画元素和窗口的记录。
     - 验证是否成功解绑了 Session 观察者。
   - **模拟用户操作:** 测试通过 `MediaPlayerActionAtViewportPoint` 方法模拟用户点击视频上的画中画按钮。
   - **处理错误情况:** 测试在 WebMediaPlayer 被重置后尝试进入画中画时，是否会抛出 `InvalidStateError` 异常。

2. **测试文档画中画 (Document Picture-in-Picture) 功能:**
   - **打开文档画中画窗口:** 测试 `CreateDocumentPictureInPictureWindow` 方法的正确性，包括：
     - 验证成功创建了一个新的 `LocalDOMWindow` 作为画中画窗口。
     - 验证画中画窗口的 `document.baseURI` 与打开者的 URL 一致。
     - 验证画中画窗口的移动和调整大小操作是否与预期的行为一致（例如，需要用户手势才能调整大小）。
     - 测试使用 `file://` URL 打开文档画中画窗口的情况。
     - 验证可以通过 `DocumentPictureInPicture.window` 属性获取画中画窗口对象。
     - 测试文档画中画窗口是否禁用了 Viz 节流。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    - **事件:** 测试验证了 `enterpictureinpicture` 和 `leavepictureinpicture` 这两个 JavaScript 事件是否在正确的时机被触发。例如，当用户通过 JavaScript 调用 `video.requestPictureInPicture()` 或通过浏览器 UI 进入画中画时，会触发 `enterpictureinpicture` 事件。退出时则触发 `leavepictureinpicture`。
    - **Promise:** 测试中使用了 `ScriptPromise` 和 `ScriptPromiseResolver`，这与 JavaScript 中异步操作的 Promise 机制相关。例如，`video.requestPictureInPicture()` 返回一个 Promise，该 Promise 在进入或拒绝进入画中画时会 resolve 或 reject。
    - **API 调用:** 测试模拟了 JavaScript 调用 `documentPictureInPicture.requestWindow()` 来创建文档画中画窗口，并验证了传递的 `DocumentPictureInPictureOptions` 参数（例如 `width` 和 `height`）。
    - **DOM 操作:** 测试中通过 JavaScript 操作 DOM 元素，例如创建 `HTMLVideoElement` 并添加到文档中。

* **HTML:**
    - **`<video>` 元素:**  测试的核心围绕着 `HTMLVideoElement` 的画中画功能。测试会设置视频的 `src` 属性，模拟视频的加载和状态变化。
    - **`poster` 属性:** 测试验证了当视频设置了 `poster` 属性时，进入画中画时使用的源边界是 poster 图片的尺寸，而不是视频元素的实际尺寸。
    - **样式 (Style Attribute):** 测试中使用了 `style` 属性来设置视频元素和其父元素的样式，例如 `padding`, `width`, `height`, `transform`, `object-fit`，并验证了这些样式如何影响画中画的源边界计算。

* **CSS:**
    - 虽然测试文件本身是 C++ 代码，但它测试的逻辑直接关系到浏览器如何解析和应用 CSS 样式来确定视频元素在页面上的布局和渲染，从而影响画中画的源边界。例如，`object-fit: none` 会导致 poster 图片以原始尺寸显示，这会影响画中画的起始位置和大小。

**逻辑推理 (假设输入与输出):**

**场景 1: 测试进入视频画中画**

* **假设输入:**
    - 一个 `HTMLVideoElement` 对象 `video`，已加载视频元数据。
    - 用户或脚本触发进入画中画的操作 (例如，调用 `video.requestPictureInPicture()` 或点击浏览器提供的画中画按钮)。
* **预期输出:**
    - `video` 元素上触发 `enterpictureinpicture` 事件。
    - `PictureInPictureControllerImpl` 调用 `PictureInPictureService` 的 `StartSession` 方法，传递 `video` 对应的 `WebMediaPlayer` 的 ID、视频的 `SurfaceId`、视频的自然尺寸等信息。
    - `PictureInPictureControllerImpl` 内部记录下当前的画中画元素为 `video`。

**场景 2: 测试退出视频画中画**

* **假设输入:**
    - 当前处于画中画模式的 `HTMLVideoElement` 对象 `video`。
    - 用户或脚本触发退出画中画的操作 (例如，点击画中画窗口的关闭按钮或调用 `document.exitPictureInPicture()`)。
* **预期输出:**
    - `video` 元素上触发 `leavepictureinpicture` 事件。
    - `PictureInPictureControllerImpl` 调用 `PictureInPictureSession` 的 `Stop` 方法，通知浏览器服务关闭画中画会话。
    - `PictureInPictureControllerImpl` 内部清除对画中画元素的记录。

**用户或编程常见的使用错误举例说明:**

1. **尝试在没有用户手势的情况下打开文档画中画窗口:**
   - **错误代码 (JavaScript):**
     ```javascript
     // 假设这是在页面加载完成后立即执行的代码
     documentPictureInPicture.requestWindow();
     ```
   - **预期行为:**  浏览器通常会阻止此类操作，因为它可能被滥用。文档画中画的打开通常需要一个明确的用户操作 (例如，点击按钮)。
   - **调试线索:** 开发者控制台可能会显示类似 "需要用户手势" 的错误信息。测试代码中会调用 `LocalFrame::NotifyUserActivation` 来模拟用户手势，这说明了用户手势的重要性。

2. **在视频 `WebMediaPlayer` 被重置后尝试进入画中画:**
   - **错误代码 (JavaScript):**
     ```javascript
     const video = document.querySelector('video');
     video.src = 'new_video.mp4'; // 这可能会导致 WebMediaPlayer 的重置
     video.requestPictureInPicture(); // 尝试进入画中画
     ```
   - **预期行为:**  由于 `WebMediaPlayer` 的状态可能已失效，进入画中画的操作可能会失败，并抛出 `InvalidStateError` 异常。
   - **调试线索:** 测试代码 `EnterPictureInPictureAfterResettingWMP` 验证了这种情况，确保 `PictureInPictureControllerImpl` 能正确处理。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户访问包含 `<video>` 元素的网页。**
2. **用户与视频元素交互:**
   - **视频画中画:** 用户可能点击了浏览器提供的默认画中画按钮，或者网页开发者自定义的画中画按钮（该按钮会调用 `video.requestPictureInPicture()` JavaScript API）。
   - **文档画中画:** 用户可能点击了网页上的某个按钮，该按钮的 JavaScript 代码会调用 `documentPictureInPicture.requestWindow()` 来请求打开文档画中画窗口。
3. **浏览器接收到用户的画中画请求。**
4. **Blink 渲染引擎处理该请求:**
   - `HTMLVideoElement` 或相关的 DOM 元素接收到画中画请求。
   - `PictureInPictureControllerImpl` 负责协调画中画的启动。
   - `PictureInPictureControllerImpl` 会与浏览器进程中的 `PictureInPictureService` 进行通信 (通过 Mojo IPC)。
   - 对于视频画中画，会传递 `WebMediaPlayer` 的信息和视频的渲染信息。
   - 对于文档画中画，会创建一个新的 `LocalDOMWindow`。
5. **浏览器可能会创建新的画中画窗口。**
6. **如果出现问题，例如权限被拒绝或状态不正确，`PictureInPictureControllerImpl` 可能会拒绝画中画请求，并触发相应的错误事件或 Promise rejection。**

**调试线索:**

* **检查 JavaScript 控制台:** 查看是否有与画中画相关的错误或警告信息。
* **断点调试 JavaScript 代码:**  在 `video.requestPictureInPicture()` 或 `documentPictureInPicture.requestWindow()` 调用处设置断点，查看调用栈和变量值。
* **查看 Chrome 的 `chrome://media-internals` 页面:**  可以查看媒体相关的事件和状态，包括画中画会话的信息。
* **使用 Blink 的调试工具:**  如果需要深入了解 Blink 内部的运行机制，可以使用 Blink 提供的调试工具，例如日志输出和断点调试，来跟踪 `PictureInPictureControllerImpl` 的执行流程。测试代码本身也提供了很多测试用例，可以作为理解代码逻辑的参考。

**归纳一下它的功能 (第 1 部分):**

这部分测试文件主要集中在测试 `PictureInPictureControllerImpl` 类处理**视频画中画和文档画中画的创建和销毁过程**，以及**与浏览器进程中 `PictureInPictureService` 的交互**。它验证了关键的事件触发、Mojo 接口调用、状态管理和错误处理逻辑。同时也测试了文档画中画窗口的基本创建和管理功能，例如窗口属性和用户交互限制。

请提供第 2 部分的内容，以便进行更全面的分析。

Prompt: 
```
这是目录为blink/renderer/modules/document_picture_in_picture/picture_in_picture_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include "base/containers/contains.h"
#include "base/memory/raw_ptr.h"
#include "media/mojo/mojom/media_player.mojom-blink.h"
#include "mojo/public/cpp/bindings/pending_associated_remote.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/media/html_media_test_helper.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/layout/layout_image.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/wait_for_event.h"
#include "third_party/blink/renderer/modules/document_picture_in_picture/document_picture_in_picture.h"
#include "third_party/blink/renderer/modules/document_picture_in_picture/picture_in_picture_controller_impl.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_descriptor.h"
#include "third_party/blink/renderer/platform/testing/empty_web_media_player.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"

#if !BUILDFLAG(TARGET_OS_IS_ANDROID)
#include "third_party/blink/renderer/bindings/modules/v8/v8_document_picture_in_picture_options.h"
#endif  // !BUILDFLAG(TARGET_OS_IS_ANDROID)

using ::testing::_;

namespace blink {

namespace {
#if !BUILDFLAG(TARGET_OS_IS_ANDROID)
KURL GetOpenerURL() {
  return KURL("https://example.com/");
}

LocalDOMWindow* OpenDocumentPictureInPictureWindow(
    V8TestingScope& v8_scope,
    Document& document,
    KURL opener_url = GetOpenerURL()) {
  auto& controller = PictureInPictureControllerImpl::From(document);
  EXPECT_EQ(nullptr, controller.pictureInPictureWindow());

  // Enable the DocumentPictureInPictureAPI flag.
  ScopedDocumentPictureInPictureAPIForTest scoped_feature(true);

  // Make sure that the document URL is set, since it's required.
  document.SetURL(opener_url);

  // Get past the LocalDOMWindow::isSecureContext() check.
  document.domWindow()->GetSecurityContext().SetSecurityOriginForTesting(
      nullptr);
  document.domWindow()->GetSecurityContext().SetSecurityOrigin(
      SecurityOrigin::Create(opener_url));

  // Get past the BindingSecurity::ShouldAllowAccessTo() check.
  ScriptState* script_state = ToScriptStateForMainWorld(document.GetFrame());
  ScriptState::Scope entered_context_scope(script_state);

  // Create the DocumentPictureInPictureOptions.
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<DOMWindow>>(script_state);
  ExceptionState exception_state(script_state->GetIsolate(),
                                 v8::ExceptionContext::kOperation,
                                 "DocumentPictureInPicture", "requestWindow");

  v8::Local<v8::Object> v8_object = v8::Object::New(v8_scope.GetIsolate());
  v8_object
      ->Set(v8_scope.GetContext(), V8String(v8_scope.GetIsolate(), "width"),
            v8::Number::New(v8_scope.GetIsolate(), 640))
      .Check();
  v8_object
      ->Set(v8_scope.GetContext(), V8String(v8_scope.GetIsolate(), "height"),
            v8::Number::New(v8_scope.GetIsolate(), 320))
      .Check();
  DocumentPictureInPictureOptions* options =
      DocumentPictureInPictureOptions::Create(script_state->GetIsolate(),
                                              v8_object, exception_state);

  // Set a base URL for the opener window.
  document.SetBaseURLOverride(opener_url);
  EXPECT_EQ(opener_url.GetString(), document.BaseURL().GetString());

  controller.CreateDocumentPictureInPictureWindow(
      script_state, *document.domWindow(), options, resolver);

  return controller.documentPictureInPictureWindow();
}
#endif  // !BUILDFLAG(TARGET_OS_IS_ANDROID)

}  // namespace

viz::SurfaceId TestSurfaceId() {
  // Use a fake but valid viz::SurfaceId.
  return {viz::FrameSinkId(1, 1),
          viz::LocalSurfaceId(
              11, base::UnguessableToken::CreateForTesting(0x111111, 0))};
}

// The MockPictureInPictureSession implements a PictureInPicture session in the
// same process as the test and guarantees that the callbacks are called in
// order for the events to be fired.
class MockPictureInPictureSession
    : public mojom::blink::PictureInPictureSession {
 public:
  MockPictureInPictureSession(
      mojo::PendingReceiver<mojom::blink::PictureInPictureSession> receiver)
      : receiver_(this, std::move(receiver)) {
    ON_CALL(*this, Stop(_)).WillByDefault([](StopCallback callback) {
      std::move(callback).Run();
    });
  }
  ~MockPictureInPictureSession() override = default;

  MOCK_METHOD(void, Stop, (StopCallback));
  MOCK_METHOD(void,
              Update,
              (uint32_t,
               mojo::PendingAssociatedRemote<media::mojom::blink::MediaPlayer>,
               const viz::SurfaceId&,
               const gfx::Size&,
               bool));

 private:
  mojo::Receiver<mojom::blink::PictureInPictureSession> receiver_;
};

// The MockPictureInPictureService implements the PictureInPicture service in
// the same process as the test and guarantees that the callbacks are called in
// order for the events to be fired.
class MockPictureInPictureService
    : public mojom::blink::PictureInPictureService {
 public:
  MockPictureInPictureService() {
    // Setup default implementations.
    ON_CALL(*this, StartSession(_, _, _, _, _, _, _, _))
        .WillByDefault(testing::Invoke(
            this, &MockPictureInPictureService::StartSessionInternal));
  }

  MockPictureInPictureService(const MockPictureInPictureService&) = delete;
  MockPictureInPictureService& operator=(const MockPictureInPictureService&) =
      delete;

  ~MockPictureInPictureService() override = default;

  void Bind(mojo::ScopedMessagePipeHandle handle) {
    receiver_.Bind(mojo::PendingReceiver<mojom::blink::PictureInPictureService>(
        std::move(handle)));

    session_ = std::make_unique<MockPictureInPictureSession>(
        session_remote_.InitWithNewPipeAndPassReceiver());
  }

  MOCK_METHOD(
      void,
      StartSession,
      (uint32_t,
       mojo::PendingAssociatedRemote<media::mojom::blink::MediaPlayer>,
       const viz::SurfaceId&,
       const gfx::Size&,
       bool,
       mojo::PendingRemote<mojom::blink::PictureInPictureSessionObserver>,
       const gfx::Rect&,
       StartSessionCallback));

  MockPictureInPictureSession& Session() { return *session_.get(); }

  void StartSessionInternal(
      uint32_t,
      mojo::PendingAssociatedRemote<media::mojom::blink::MediaPlayer>,
      const viz::SurfaceId&,
      const gfx::Size&,
      bool,
      mojo::PendingRemote<mojom::blink::PictureInPictureSessionObserver>,
      const gfx::Rect& source_bounds,
      StartSessionCallback callback) {
    source_bounds_ = source_bounds;
    std::move(callback).Run(std::move(session_remote_), gfx::Size());
  }

  const gfx::Rect& source_bounds() const { return source_bounds_; }

 private:
  mojo::Receiver<mojom::blink::PictureInPictureService> receiver_{this};
  std::unique_ptr<MockPictureInPictureSession> session_;
  mojo::PendingRemote<mojom::blink::PictureInPictureSession> session_remote_;
  gfx::Rect source_bounds_;
};

class PictureInPictureControllerFrameClient
    : public test::MediaStubLocalFrameClient {
 public:
  static PictureInPictureControllerFrameClient* Create(
      std::unique_ptr<WebMediaPlayer> player) {
    return MakeGarbageCollected<PictureInPictureControllerFrameClient>(
        std::move(player));
  }

  explicit PictureInPictureControllerFrameClient(
      std::unique_ptr<WebMediaPlayer> player)
      : test::MediaStubLocalFrameClient(std::move(player)) {}

  PictureInPictureControllerFrameClient(
      const PictureInPictureControllerFrameClient&) = delete;
  PictureInPictureControllerFrameClient& operator=(
      const PictureInPictureControllerFrameClient&) = delete;
};

class PictureInPictureControllerPlayer final : public EmptyWebMediaPlayer {
 public:
  PictureInPictureControllerPlayer() = default;

  PictureInPictureControllerPlayer(const PictureInPictureControllerPlayer&) =
      delete;
  PictureInPictureControllerPlayer& operator=(
      const PictureInPictureControllerPlayer&) = delete;

  ~PictureInPictureControllerPlayer() override = default;

  double Duration() const override {
    if (infinity_duration_)
      return std::numeric_limits<double>::infinity();
    return EmptyWebMediaPlayer::Duration();
  }
  ReadyState GetReadyState() const override { return kReadyStateHaveMetadata; }
  bool HasVideo() const override { return true; }
  void OnRequestPictureInPicture() override { surface_id_ = TestSurfaceId(); }
  std::optional<viz::SurfaceId> GetSurfaceId() override { return surface_id_; }

  void set_infinity_duration(bool value) { infinity_duration_ = value; }

 private:
  bool infinity_duration_ = false;
  std::optional<viz::SurfaceId> surface_id_;
};

class PictureInPictureTestWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  explicit PictureInPictureTestWebFrameClient(
      std::unique_ptr<WebMediaPlayer> web_media_player)
      : web_media_player_(std::move(web_media_player)) {}

  std::unique_ptr<WebMediaPlayer> CreateMediaPlayer(
      const WebMediaPlayerSource&,
      WebMediaPlayerClient*,
      blink::MediaInspectorContext*,
      WebMediaPlayerEncryptedMediaClient*,
      WebContentDecryptionModule*,
      const WebString& sink_id,
      const cc::LayerTreeSettings* settings,
      scoped_refptr<base::TaskRunner> compositor_worker_task_runner) override {
    return std::move(web_media_player_);
  }

 private:
  std::unique_ptr<WebMediaPlayer> web_media_player_;
};

// PictureInPictureController tests that require a Widget.
// Video PiP tests typically do, while Document PiP tests typically do not.
// If you need to mock the ChromeClient, then this is not the right test harness
// for you. If you need to mock the client and have a Widget, then you'll
// probably need to modify `WebViewHelper`.
class PictureInPictureControllerTestWithWidget : public RenderingTest {
 public:
  void SetUp() override {
    client_ = std::make_unique<PictureInPictureTestWebFrameClient>(
        std::make_unique<PictureInPictureControllerPlayer>());

    helper_.Initialize(client_.get());

    GetFrame().GetBrowserInterfaceBroker().SetBinderForTesting(
        mojom::blink::PictureInPictureService::Name_,
        WTF::BindRepeating(&MockPictureInPictureService::Bind,
                           WTF::Unretained(&mock_service_)));

    video_ = MakeGarbageCollected<HTMLVideoElement>(GetDocument());
    GetDocument().body()->AppendChild(video_);
    Video()->SetReadyState(HTMLMediaElement::ReadyState::kHaveMetadata);
    layer_ = cc::Layer::Create();
    Video()->SetCcLayerForTesting(layer_.get());

    std::string test_name =
        testing::UnitTest::GetInstance()->current_test_info()->name();
    if (base::Contains(test_name, "MediaSource")) {
      MediaStreamComponentVector dummy_tracks;
      auto* descriptor = MakeGarbageCollected<MediaStreamDescriptor>(
          dummy_tracks, dummy_tracks);
      Video()->SetSrcObjectVariant(descriptor);
    } else {
      Video()->SetSrc(AtomicString("http://example.com/foo.mp4"));
    }

    test::RunPendingTasks();
  }

  void TearDown() override {
    GetFrame().GetBrowserInterfaceBroker().SetBinderForTesting(
        mojom::blink::PictureInPictureService::Name_, {});
    RenderingTest::TearDown();
  }

  HTMLVideoElement* Video() const { return video_.Get(); }
  MockPictureInPictureService& Service() { return mock_service_; }

  LocalFrame& GetFrame() const { return *helper_.LocalMainFrame()->GetFrame(); }

  Document& GetDocument() const { return *GetFrame().GetDocument(); }

  WebFrameWidgetImpl* GetWidget() const {
    return static_cast<WebFrameWidgetImpl*>(
        GetDocument().GetFrame()->GetWidgetForLocalRoot());
  }

  WebViewImpl* GetWebView() const { return helper_.GetWebView(); }

  void ResetMediaPlayerAndMediaSource() {
    Video()->ResetMediaPlayerAndMediaSource();
  }

 private:
  Persistent<HTMLVideoElement> video_;
  std::unique_ptr<frame_test_helpers::TestWebFrameClient> client_;
  testing::NiceMock<MockPictureInPictureService> mock_service_;
  scoped_refptr<cc::Layer> layer_;
  frame_test_helpers::WebViewHelper helper_;
};

TEST_F(PictureInPictureControllerTestWithWidget,
       EnterPictureInPictureFiresEvent) {
  EXPECT_EQ(nullptr, PictureInPictureControllerImpl::From(GetDocument())
                         .PictureInPictureElement());

  WebMediaPlayer* player = Video()->GetWebMediaPlayer();
  EXPECT_CALL(Service(),
              StartSession(player->GetDelegateId(), _, TestSurfaceId(),
                           player->NaturalSize(), true, _, _, _));

  PictureInPictureControllerImpl::From(GetDocument())
      .EnterPictureInPicture(Video(), /*promise=*/nullptr);

  MakeGarbageCollected<WaitForEvent>(Video(),
                                     event_type_names::kEnterpictureinpicture);

  EXPECT_NE(nullptr, PictureInPictureControllerImpl::From(GetDocument())
                         .PictureInPictureElement());
}

TEST_F(PictureInPictureControllerTestWithWidget,
       FrameThrottlingIsSetProperlyWithoutSetup) {
  // This test assumes that it throttling is allowed by default.
  ASSERT_TRUE(GetWidget()->GetMayThrottleIfUndrawnFramesForTesting());

  // Entering PictureInPicture should disallow throttling.
  PictureInPictureControllerImpl::From(GetDocument())
      .EnterPictureInPicture(Video(), /*promise=*/nullptr);
  MakeGarbageCollected<WaitForEvent>(Video(),
                                     event_type_names::kEnterpictureinpicture);
  EXPECT_FALSE(GetWidget()->GetMayThrottleIfUndrawnFramesForTesting());

  // Exiting PictureInPicture should re-enable it.
  PictureInPictureControllerImpl::From(GetDocument())
      .ExitPictureInPicture(Video(), nullptr /* resolver */);
  MakeGarbageCollected<WaitForEvent>(Video(),
                                     event_type_names::kLeavepictureinpicture);
  EXPECT_TRUE(GetWidget()->GetMayThrottleIfUndrawnFramesForTesting());
}

TEST_F(PictureInPictureControllerTestWithWidget,
       ExitPictureInPictureFiresEvent) {
  EXPECT_EQ(nullptr, PictureInPictureControllerImpl::From(GetDocument())
                         .PictureInPictureElement());

  WebMediaPlayer* player = Video()->GetWebMediaPlayer();
  EXPECT_CALL(Service(),
              StartSession(player->GetDelegateId(), _, TestSurfaceId(),
                           player->NaturalSize(), true, _, _, _));

  PictureInPictureControllerImpl::From(GetDocument())
      .EnterPictureInPicture(Video(), /*promise=*/nullptr);

  EXPECT_CALL(Service().Session(), Stop(_));

  MakeGarbageCollected<WaitForEvent>(Video(),
                                     event_type_names::kEnterpictureinpicture);

  EXPECT_NE(nullptr, PictureInPictureControllerImpl::From(GetDocument())
                         .PictureInPictureElement());
  EXPECT_NE(nullptr, PictureInPictureControllerImpl::From(GetDocument())
                         .pictureInPictureWindow());

  PictureInPictureControllerImpl::From(GetDocument())
      .ExitPictureInPicture(Video(), nullptr);

  MakeGarbageCollected<WaitForEvent>(Video(),
                                     event_type_names::kLeavepictureinpicture);

  // Make sure the state has been cleaned up.
  // https://crbug.com/1496926
  EXPECT_EQ(nullptr, PictureInPictureControllerImpl::From(GetDocument())
                         .PictureInPictureElement());
  EXPECT_EQ(nullptr, PictureInPictureControllerImpl::From(GetDocument())
                         .pictureInPictureWindow());
}

TEST_F(PictureInPictureControllerTestWithWidget, StartObserving) {
  EXPECT_FALSE(PictureInPictureControllerImpl::From(GetDocument())
                   .IsSessionObserverReceiverBoundForTesting());

  WebMediaPlayer* player = Video()->GetWebMediaPlayer();
  EXPECT_CALL(Service(),
              StartSession(player->GetDelegateId(), _, TestSurfaceId(),
                           player->NaturalSize(), true, _, _, _));

  PictureInPictureControllerImpl::From(GetDocument())
      .EnterPictureInPicture(Video(), /*promise=*/nullptr);

  MakeGarbageCollected<WaitForEvent>(Video(),
                                     event_type_names::kEnterpictureinpicture);

  EXPECT_TRUE(PictureInPictureControllerImpl::From(GetDocument())
                  .IsSessionObserverReceiverBoundForTesting());
}

TEST_F(PictureInPictureControllerTestWithWidget, StopObserving) {
  EXPECT_FALSE(PictureInPictureControllerImpl::From(GetDocument())
                   .IsSessionObserverReceiverBoundForTesting());

  WebMediaPlayer* player = Video()->GetWebMediaPlayer();
  EXPECT_CALL(Service(),
              StartSession(player->GetDelegateId(), _, TestSurfaceId(),
                           player->NaturalSize(), true, _, _, _));

  PictureInPictureControllerImpl::From(GetDocument())
      .EnterPictureInPicture(Video(), /*promise=*/nullptr);

  EXPECT_CALL(Service().Session(), Stop(_));

  MakeGarbageCollected<WaitForEvent>(Video(),
                                     event_type_names::kEnterpictureinpicture);

  PictureInPictureControllerImpl::From(GetDocument())
      .ExitPictureInPicture(Video(), nullptr);
  MakeGarbageCollected<WaitForEvent>(Video(),
                                     event_type_names::kLeavepictureinpicture);

  EXPECT_FALSE(PictureInPictureControllerImpl::From(GetDocument())
                   .IsSessionObserverReceiverBoundForTesting());
}

TEST_F(PictureInPictureControllerTestWithWidget,
       PlayPauseButton_InfiniteDuration) {
  EXPECT_EQ(nullptr, PictureInPictureControllerImpl::From(GetDocument())
                         .PictureInPictureElement());

  Video()->DurationChanged(std::numeric_limits<double>::infinity(), false);

  WebMediaPlayer* player = Video()->GetWebMediaPlayer();
  EXPECT_CALL(Service(),
              StartSession(player->GetDelegateId(), _, TestSurfaceId(),
                           player->NaturalSize(), false, _, _, _));

  PictureInPictureControllerImpl::From(GetDocument())
      .EnterPictureInPicture(Video(), /*promise=*/nullptr);

  MakeGarbageCollected<WaitForEvent>(Video(),
                                     event_type_names::kEnterpictureinpicture);
}

TEST_F(PictureInPictureControllerTestWithWidget, PlayPauseButton_MediaSource) {
  EXPECT_EQ(nullptr, PictureInPictureControllerImpl::From(GetDocument())
                         .PictureInPictureElement());

  // The test automatically setup the WebMediaPlayer with a MediaSource based on
  // the test name.

  WebMediaPlayer* player = Video()->GetWebMediaPlayer();
  EXPECT_CALL(Service(),
              StartSession(player->GetDelegateId(), _, TestSurfaceId(),
                           player->NaturalSize(), false, _, _, _));

  PictureInPictureControllerImpl::From(GetDocument())
      .EnterPictureInPicture(Video(), /*promise=*/nullptr);

  MakeGarbageCollected<WaitForEvent>(Video(),
                                     event_type_names::kEnterpictureinpicture);
}

TEST_F(PictureInPictureControllerTestWithWidget, PerformMediaPlayerAction) {
  frame_test_helpers::WebViewHelper helper;
  helper.Initialize();

  WebLocalFrameImpl* frame = helper.LocalMainFrame();
  Document* document = frame->GetFrame()->GetDocument();

  Persistent<HTMLVideoElement> video =
      MakeGarbageCollected<HTMLVideoElement>(*document);
  document->body()->AppendChild(video);

  gfx::Point bounds = video->BoundsInWidget().CenterPoint();

  // Performs the specified media player action on the media element at the
  // given location.
  frame->GetFrame()->MediaPlayerActionAtViewportPoint(
      bounds, blink::mojom::MediaPlayerActionType::kPictureInPicture, true);
}

TEST_F(PictureInPictureControllerTestWithWidget,
       EnterPictureInPictureAfterResettingWMP) {
  V8TestingScope scope;

  EXPECT_NE(nullptr, Video()->GetWebMediaPlayer());

  // Reset web media player.
  ResetMediaPlayerAndMediaSource();
  EXPECT_EQ(nullptr, Video()->GetWebMediaPlayer());

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PictureInPictureWindow>>(
          scope.GetScriptState());
  auto promise = resolver->Promise();
  PictureInPictureControllerImpl::From(GetDocument())
      .EnterPictureInPicture(Video(), resolver);

  // Verify rejected with DOMExceptionCode::kInvalidStateError.
  EXPECT_EQ(v8::Promise::kRejected, promise.V8Promise()->State());
  DOMException* dom_exception = V8DOMException::ToWrappable(
      scope.GetIsolate(), promise.V8Promise()->Result());
  ASSERT_NE(dom_exception, nullptr);
  EXPECT_EQ(static_cast<int>(DOMExceptionCode::kInvalidStateError),
            dom_exception->code());
}

TEST_F(PictureInPictureControllerTestWithWidget,
       EnterPictureInPictureProvideSourceBoundsSetToBoundsInWidget) {
  EXPECT_EQ(nullptr, PictureInPictureControllerImpl::From(GetDocument())
                         .PictureInPictureElement());

  WebMediaPlayer* player = Video()->GetWebMediaPlayer();
  EXPECT_CALL(Service(),
              StartSession(player->GetDelegateId(), _, TestSurfaceId(),
                           player->NaturalSize(), true, _, _, _));

  PictureInPictureControllerImpl::From(GetDocument())
      .EnterPictureInPicture(Video(), /*promise=*/nullptr);

  MakeGarbageCollected<WaitForEvent>(Video(),
                                     event_type_names::kEnterpictureinpicture);

  // We expect that the video element has some nontrivial rect, else this won't
  // really test anything.
  ASSERT_NE(Video()->BoundsInWidget(), gfx::Rect());
  EXPECT_EQ(Service().source_bounds(), Video()->BoundsInWidget());
}

TEST_F(PictureInPictureControllerTestWithWidget,
       EnterPictureInPictureProvideSourceBoundsSetToReplacedContentRect) {
  // Create one image with a size of 10x10px
  SkImageInfo raster_image_info =
      SkImageInfo::MakeN32Premul(10, 10, SkColorSpace::MakeSRGB());
  sk_sp<SkSurface> surface(SkSurfaces::Raster(raster_image_info));
  ImageResourceContent* image_content = ImageResourceContent::CreateLoaded(
      UnacceleratedStaticBitmapImage::Create(surface->makeImageSnapshot())
          .get());

  Element* div = GetDocument().CreateRawElement(html_names::kDivTag);
  div->setAttribute(html_names::kStyleAttr,
                    AtomicString("padding: 100px;"
                                 "width: 150px;"
                                 "height: 150px;"
                                 "padding: 100px;"
                                 "transform: scale(2)"));
  GetDocument().body()->AppendChild(div);
  div->AppendChild(Video());
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();

  // Set poster image to video
  auto* layout_image = To<LayoutImage>(Video()->GetLayoutObject());
  const char kPosterUrl[] = "http://example.com/foo.jpg";
  url_test_helpers::RegisterMockedErrorURLLoad(
      url_test_helpers::ToKURL(kPosterUrl));
  Video()->setAttribute(html_names::kPosterAttr, AtomicString(kPosterUrl));
  Video()->setAttribute(html_names::kStyleAttr, AtomicString("object-fit: none;"
                                                             "height: 150px;"
                                                             "width: 150px;"));
  layout_image->ImageResource()->SetImageResource(image_content);
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(nullptr, PictureInPictureControllerImpl::From(GetDocument())
                         .PictureInPictureElement());

  WebMediaPlayer* player = Video()->GetWebMediaPlayer();
  EXPECT_CALL(Service(),
              StartSession(player->GetDelegateId(), _, TestSurfaceId(),
                           player->NaturalSize(), true, _, _, _));

  PictureInPictureControllerImpl::From(GetDocument())
      .EnterPictureInPicture(Video(), /*promise=*/nullptr);

  MakeGarbageCollected<WaitForEvent>(Video(),
                                     event_type_names::kEnterpictureinpicture);

  // Source bounds are expected to match the poster image size, not the bounds
  // of the video element.
  EXPECT_EQ(Video()->BoundsInWidget(), gfx::Rect(33, 33, 300, 300));
  EXPECT_EQ(Service().source_bounds(), gfx::Rect(173, 173, 20, 20));
}

TEST_F(PictureInPictureControllerTestWithWidget, VideoIsNotAllowedIfAutoPip) {
  EXPECT_EQ(PictureInPictureControllerImpl::Status::kEnabled,
            PictureInPictureControllerImpl::From(GetDocument())
                .IsElementAllowed(*Video(), /*report_failure=*/false));

  // Simulate auto-pip mode.
  Video()->SetPersistentState(true);

  EXPECT_EQ(PictureInPictureControllerImpl::Status::kAutoPipAndroid,
            PictureInPictureControllerImpl::From(GetDocument())
                .IsElementAllowed(*Video(), /*report_failure=*/false));
}

#if !BUILDFLAG(TARGET_OS_IS_ANDROID)
TEST_F(PictureInPictureControllerTestWithWidget,
       DocumentPiPDoesNotAllowVizThrottling) {
  EXPECT_TRUE(GetWidget()->GetMayThrottleIfUndrawnFramesForTesting());

  V8TestingScope v8_scope;
  ScriptState* script_state =
      ToScriptStateForMainWorld(GetDocument().GetFrame());
  ScriptState::Scope entered_context_scope(script_state);
  LocalFrame::NotifyUserActivation(
      &GetFrame(), mojom::UserActivationNotificationType::kTest);
  OpenDocumentPictureInPictureWindow(v8_scope, GetDocument());

  EXPECT_FALSE(GetWidget()->GetMayThrottleIfUndrawnFramesForTesting());

  // TODO(1357125): Check that GetMayThrottle... returns true once the PiP
  // window is closed.
}

TEST_F(PictureInPictureControllerTestWithWidget,
       DocumentPiPDoesOpenWithFileUrl) {
  V8TestingScope v8_scope;
  ScriptState* script_state =
      ToScriptStateForMainWorld(GetDocument().GetFrame());
  ScriptState::Scope entered_context_scope(script_state);
  LocalFrame::NotifyUserActivation(
      &GetFrame(), mojom::UserActivationNotificationType::kTest);
  auto* pip = OpenDocumentPictureInPictureWindow(v8_scope, GetDocument(),
                                                 KURL("file://my/file.html"));
  EXPECT_TRUE(pip);
}

class PictureInPictureControllerChromeClient
    : public RenderingTestChromeClient {
 public:
  PictureInPictureControllerChromeClient() = default;

  void set_dummy_page_holder(DummyPageHolder* dummy_page_holder) {
    dummy_page_holder_ = dummy_page_holder;
  }

  // RenderingTestChromeClient:
  Page* CreateWindowDelegate(LocalFrame*,
                             const FrameLoadRequest&,
                             const AtomicString&,
                             const WebWindowFeatures&,
                             network::mojom::blink::WebSandboxFlags,
                             const SessionStorageNamespaceId&,
                             bool& consumed_user_gesture) override {
    CHECK(dummy_page_holder_);
    return &dummy_page_holder_->GetPage();
  }
  MOCK_METHOD(void, SetWindowRect, (const gfx::Rect&, LocalFrame&));

 private:
  raw_ptr<DummyPageHolder, DanglingUntriaged> dummy_page_holder_ = nullptr;
};

// Tests for Picture in Picture with a mockable chrome client.  This makes it
// easy to mock things like `SetWindowRect` on the client.  However, it skips
// the setup in `WebViewHelper` that provides a Widget.  `WebViewHelper` makes
// it hard to mock the client, since it provides a real `ChromeClient`.
class PictureInPictureControllerTestWithChromeClient : public RenderingTest {
 public:
  void SetUp() override {
    chrome_client_ =
        MakeGarbageCollected<PictureInPictureControllerChromeClient>();
    dummy_page_holder_ =
        std::make_unique<DummyPageHolder>(gfx::Size(), chrome_client_);
    chrome_client_->set_dummy_page_holder(dummy_page_holder_.get());
    RenderingTest::SetUp();
  }

  Document& GetDocument() const { return *GetFrame().GetDocument(); }

  // Used by RenderingTest.
  RenderingTestChromeClient& GetChromeClient() const override {
    return *chrome_client_;
  }

  // Convenience function to set expectations on the mock.
  PictureInPictureControllerChromeClient& GetPipChromeClient() const {
    return *chrome_client_;
  }

 private:
  Persistent<PictureInPictureControllerChromeClient> chrome_client_;
  // This is used by our chrome client to create the PiP window.  We keep
  // ownership of it here so that it outlives the GC'd objects.  The client
  // cannot own it because it also has a GC root to the client; everything would
  // leak if we did so.
  std::unique_ptr<DummyPageHolder> dummy_page_holder_;
};

TEST_F(PictureInPictureControllerTestWithChromeClient,
       CreateDocumentPictureInPictureWindow) {
  EXPECT_EQ(nullptr, PictureInPictureControllerImpl::From(GetDocument())
                         .pictureInPictureWindow());
  V8TestingScope v8_scope;
  LocalFrame::NotifyUserActivation(
      &GetFrame(), mojom::UserActivationNotificationType::kTest);
  auto* pictureInPictureWindow =
      OpenDocumentPictureInPictureWindow(v8_scope, GetDocument());
  ASSERT_NE(nullptr, pictureInPictureWindow);
  Document* document = pictureInPictureWindow->document();
  ASSERT_NE(nullptr, document);

  // The Picture in Picture window's base URL should match the opener.
  EXPECT_EQ(GetOpenerURL().GetString(), document->BaseURL().GetString());

  // Verify that move* doesn't call through to the chrome client.
  EXPECT_CALL(GetPipChromeClient(), SetWindowRect(_, _)).Times(0);
  document->domWindow()->moveTo(10, 10);
  document->domWindow()->moveBy(10, 10);
  testing::Mock::VerifyAndClearExpectations(&GetPipChromeClient());

  {
    // Verify that resizeTo consumes a user gesture, and so only one of the
    // following calls will succeed.
    EXPECT_CALL(GetPipChromeClient(), SetWindowRect(_, _));
    LocalFrame::NotifyUserActivation(
        document->GetFrame(), mojom::UserActivationNotificationType::kTest);
    ExceptionState exception_state(
        ToScriptStateForMainWorld(document->GetFrame())->GetIsolate(),
        v8::ExceptionContext::kOperation, "Window", "resizeTo");
    document->domWindow()->resizeTo(10, 10, exception_state);
    document->domWindow()->resizeTo(20, 20, exception_state);
    testing::Mock::VerifyAndClearExpectations(&GetPipChromeClient());
  }

  {
    // Verify that resizeBy consumes a user gesture, and so only one of the
    // following calls will succeed.
    EXPECT_CALL(GetPipChromeClient(), SetWindowRect(_, _));
    LocalFrame::NotifyUserActivation(
        document->GetFrame(), mojom::UserActivationNotificationType::kTest);
    ExceptionState exception_state(
        ToScriptStateForMainWorld(document->GetFrame())->GetIsolate(),
        v8::ExceptionContext::kOperation, "Window", "resizeBy");
    document->domWindow()->resizeBy(10, 10, exception_state);
    document->domWindow()->resizeBy(20, 20, exception_state);
    testing::Mock::VerifyAndClearExpectations(&GetPipChromeClient());
  }

  // Make sure that the `document` is not the same as the opener.
  EXPECT_NE(document, &GetDocument());

  // Make sure that the `window` attribute returns the window.
  {
    ScriptState* script_state =
        ToScriptStateForMainWorld(GetDocument().GetFrame());
    ScriptState::Scope entered_context_scope(script_state);
    EXPECT_EQ(pictureInPictureWindow,
              DocumentPictureInPicture::From(*GetDocument().domWindow())
                  ->window(script_state));
  }
}

TEST_F(PictureInPictureCon
"""


```
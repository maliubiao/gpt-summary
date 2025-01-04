Response:
Let's break down the thought process for analyzing the provided C++ unittest file.

**1. Initial Understanding: What is the Purpose of This File?**

The file name `render_frame_metadata_observer_impl_unittest.cc` immediately suggests that it's a unit test file. The `_unittest` suffix is a strong convention. The rest of the name, `render_frame_metadata_observer_impl`, points to the specific class being tested: `RenderFrameMetadataObserverImpl`.

**2. Core Class Identification:**

The `#include` directives confirm this. The first `#include` is for `render_frame_metadata_observer_impl.h`, the header file for the class under test.

**3. Unpacking the Includes: Dependencies and Context**

Next, look at the other `#include` statements. These tell us about the dependencies and the general area of Blink this code operates in:

* `"base/run_loop.h"` and `"base/test/task_environment.h"`: Indicate asynchronous operations and a test environment setup.
* `"build/build_config.h"`:  Suggests platform-specific code (like the Android-specific sections).
* `"cc/mojom/render_frame_metadata.mojom-blink.h"` and `"cc/trees/render_frame_metadata.h"`:  Key elements! `cc` often refers to the Chromium Compositor. `RenderFrameMetadata` is likely data about a rendered frame. The `.mojom` part indicates this is a Mojo interface definition (for inter-process communication).
* `"components/viz/common/quads/compositor_frame_metadata.h"`: `viz` is the Chromium Viz component, responsible for rendering. `CompositorFrameMetadata` is likely metadata about a frame as seen by the compositor.
* `"mojo/public/cpp/bindings/...`:  Confirms the use of Mojo for communication between components.
* `"testing/gmock/include/gmock/gmock.h"` and `"testing/gtest/include/gtest/gtest.h"`: Standard C++ testing frameworks (Google Mock and Google Test).
* `"third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"`:  Indicates testing of features that can be enabled or disabled at runtime.

**4. Identifying Key Interactions and Concepts:**

From the includes, we can infer the following interactions:

* **`RenderFrameMetadataObserverImpl`:** The class being tested. It likely observes and processes render frame metadata.
* **Mojo:**  Used for communication. This suggests that `RenderFrameMetadataObserverImpl` likely communicates with other components (possibly in different processes) using Mojo interfaces.
* **Compositor (cc and viz):** The code interacts with the compositor, receiving and potentially sending frame metadata.
* **`RenderFrameMetadata` and `CompositorFrameMetadata`:** These are the core data structures being exchanged.

**5. Examining the Test Structure:**

The file uses Google Test (`TEST_F`). We see:

* A `MockRenderFrameMetadataObserverClient`: This is a crucial pattern in unit testing. It's a mock implementation of the `cc::mojom::blink::RenderFrameMetadataObserverClient` interface. This allows the test to verify that `RenderFrameMetadataObserverImpl` calls the client correctly with the expected data. The `MOCK_METHOD` macros define the expected calls.
* A `RenderFrameMetadataObserverImplTest` fixture: This sets up the test environment, creating an instance of `RenderFrameMetadataObserverImpl` and the mock client.
* Multiple `TEST_F` functions: Each test function focuses on a specific aspect of `RenderFrameMetadataObserverImpl`'s functionality.

**6. Analyzing Individual Tests:  Focusing on Functionality**

Go through each test case and try to understand what it's verifying. Look at the `EXPECT_CALL` statements in the mock client. These are the key to understanding the expected behavior.

* **`ShouldSendFrameToken`:**  Checks if the frame token is correctly extracted from `CompositorFrameMetadata` and passed to the client along with `RenderFrameMetadata`.
* **`ShouldSendFrameTokenOnAndroid`:**  Tests the behavior on Android regarding frame token requests when the root scroll offset changes.
* **`SendRootScrollsForAccessibility`:**  Verifies how root scroll offset changes are handled, especially when accessibility is involved.
* **`DoNotSendRootScrollOffsetByDefault`:**  Ensures that root scroll offset notifications aren't sent unless explicitly requested.
* **`DoNotSendExtraRootScrollOffset`:** Checks that redundant root scroll offset notifications are avoided.
* **`SendRootScrollOffsetOnScrollEnd`:** Tests the behavior of sending root scroll offset when scrolling ends.
* **`SendRenderFrameMetadataOnUpdateFrequency`:** Verifies that metadata is sent when the update frequency for root scroll offsets changes.
* **`ForceSendMetadata`:** Checks the "force send" mechanism for metadata updates.

**7. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Now, relate the observed functionality to the web technologies:

* **Frame Rendering:**  The core purpose of this code is to track and communicate metadata related to the rendering of web page frames. This directly impacts how efficiently and smoothly web pages are displayed.
* **Scrolling:** Several tests focus on scroll offsets. This is a fundamental interaction in web browsing. JavaScript often interacts with scrolling (e.g., for infinite scrolling or parallax effects). CSS can also influence scrolling behavior.
* **Accessibility:** The "SendRootScrollsForAccessibility" test highlights the role of this code in providing information to assistive technologies, enabling users with disabilities to interact with web content.
* **Performance:** Optimizations like avoiding redundant notifications are crucial for maintaining a responsive user experience.
* **Mobile Optimization:** The `is_mobile_optimized` flag and the Android-specific tests indicate platform-specific considerations.

**8. Identifying Potential User/Programming Errors:**

Think about how developers might misuse or misunderstand this system:

* **Incorrectly assuming root scroll updates are always sent:** The "DoNotSendRootScrollOffsetByDefault" test shows this isn't the case.
* **Not understanding the implications of `force_send`:** Developers might overuse it, leading to unnecessary metadata updates.
* **Issues with synchronization:**  The tests implicitly handle asynchronous operations. Developers need to be aware of potential timing issues when dealing with frame metadata.

**9. Logical Reasoning (Assumptions and Outputs):**

For each test, consider:

* **Input:** The initial state, the data passed to `OnRenderFrameSubmission`, the configuration of the `observer_impl`.
* **Output:** The calls made to the mock client (`OnRenderFrameMetadataChanged`, `OnRootScrollOffsetChanged`), the values of the arguments.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just sends frame metadata."
* **Refinement:** "It *observes* and sends metadata, and it's more nuanced than just sending everything every time. There's logic around frame tokens, scroll offsets, and update frequencies."
* **Initial thought:** "The Android-specific code is isolated."
* **Refinement:** "While there are `#if BUILDFLAG(IS_ANDROID)`, the underlying mechanisms for metadata handling are likely shared across platforms, but Android has specific optimizations or requirements."

By following this step-by-step process, analyzing the code structure, dependencies, individual tests, and connecting it to relevant web technologies, we can arrive at a comprehensive understanding of the functionality of `render_frame_metadata_observer_impl_unittest.cc`.
这个文件 `render_frame_metadata_observer_impl_unittest.cc` 是 Chromium Blink 引擎中 `RenderFrameMetadataObserverImpl` 类的单元测试文件。它的主要功能是 **测试 `RenderFrameMetadataObserverImpl` 类在接收到渲染帧元数据时的行为是否符合预期。**

具体来说，它测试了以下几个方面：

**`RenderFrameMetadataObserverImpl` 的功能：**

1. **传递帧令牌 (Frame Token):**
   - 当收到 `CompositorFrameMetadata` 时，`RenderFrameMetadataObserverImpl` 应该能够正确地提取其中的帧令牌，并将其传递给客户端 (`MockRenderFrameMetadataObserverClient`)。
   - **与 JavaScript/HTML/CSS 的关系：**  帧令牌用于标识一个特定的渲染帧。当 JavaScript 或浏览器内部需要与特定帧关联信息时（例如，处理用户输入或动画），帧令牌就非常重要。例如，一个 JavaScript 回调可能需要知道它处理的是哪个帧的输入事件。

   **假设输入与输出：**
   - **假设输入:** `CompositorFrameMetadata` 包含 `frame_token = 1337`。
   - **预期输出:** `MockRenderFrameMetadataObserverClient` 的 `OnRenderFrameMetadataChanged` 方法被调用，且传入的 `frame_token` 参数为 `1337`。

2. **传递渲染帧元数据 (RenderFrameMetadata):**
   -  `RenderFrameMetadataObserverImpl` 应该能够将收到的 `cc::RenderFrameMetadata` 对象完整地传递给客户端。
   - **与 JavaScript/HTML/CSS 的关系：** `RenderFrameMetadata` 包含了关于渲染帧的重要信息，例如是否进行了移动端优化 (`is_mobile_optimized`)，根滚动偏移 (`root_scroll_offset`)，滚动视口大小 (`scrollable_viewport_size`) 等。这些信息可以被用来优化渲染过程或提供给 JavaScript 以实现特定的效果。例如，JavaScript 可以根据 `is_mobile_optimized` 来加载不同的资源或应用不同的逻辑。

   **假设输入与输出：**
   - **假设输入:** `cc::RenderFrameMetadata` 包含 `is_mobile_optimized = true`。
   - **预期输出:** `MockRenderFrameMetadataObserverClient` 的 `OnRenderFrameMetadataChanged` 方法被调用，且传入的 `metadata` 参数的 `is_mobile_optimized` 字段为 `true`。

3. **处理 Android 平台的特殊情况:**
   - 在 Android 平台上，当根滚动偏移发生变化时，默认情况下不需要请求新的帧令牌。测试验证了这种情况。
   - **与 JavaScript/HTML/CSS 的关系：**  在移动端，特别是 Android 上，滚动性能至关重要。避免不必要的帧令牌请求可以提高滚动的流畅性。JavaScript 可以读取当前的滚动位置，而 CSS 的 `overflow: scroll` 属性会影响滚动行为。

   **假设输入与输出：**
   - **假设输入:** 在 Android 平台，接收到根滚动偏移变化的 `cc::RenderFrameMetadata`。
   - **预期输出:** `CompositorFrameMetadata.send_frame_token_to_embedder` 为 `false`，表示不需要新的帧令牌。

4. **处理根滚动偏移更新 (Root Scroll Offset Updates):**
   - 测试了在不同配置下，`RenderFrameMetadataObserverImpl` 如何向客户端报告根滚动偏移的变化。
   - 默认情况下，不会主动发送根滚动偏移变化的通知，除非显式配置。
   - 可以配置为在每次帧提交时都发送，或者只在滚动结束时发送。
   - **与 JavaScript/HTML/CSS 的关系：** 根滚动偏移直接影响用户在页面上的可见区域。JavaScript 可以监听滚动事件并获取当前的滚动偏移，CSS 的固定定位 (`position: fixed`) 元素会根据滚动位置进行渲染。

   **假设输入与输出：**
   - **假设输入:** 收到根滚动偏移变化的 `cc::RenderFrameMetadata`，且已配置为在所有更新时发送。
   - **预期输出:** `MockRenderFrameMetadataObserverClient` 的 `OnRootScrollOffsetChanged` 方法被调用，并传入新的滚动偏移。

5. **强制发送元数据 (Force Send Metadata):**
   - 测试了 `RenderFrameMetadataObserverImpl` 是否能够响应强制发送元数据的请求，即使元数据本身没有变化。
   - **与 JavaScript/HTML/CSS 的关系：**  在某些情况下，即使渲染数据没有实际变化，也可能需要通知客户端。例如，某些状态的同步可能依赖于元数据的传递。

   **假设输入与输出：**
   - **假设输入:** 连续两次收到相同的 `cc::RenderFrameMetadata`，第二次请求强制发送。
   - **预期输出:** `MockRenderFrameMetadataObserverClient` 的 `OnRenderFrameMetadataChanged` 方法被调用两次。

**与 JavaScript, HTML, CSS 的功能关系举例：**

* **JavaScript 获取滚动位置:**  `RenderFrameMetadata` 中包含的 `root_scroll_offset` 信息最终会影响浏览器提供的 JavaScript API，例如 `window.scrollY` 或 `document.documentElement.scrollTop` 的值。`RenderFrameMetadataObserverImpl` 负责将底层的滚动信息传递到可以被 JavaScript 感知的层面。

* **CSS 固定定位:**  CSS 的 `position: fixed` 属性使得元素相对于视口固定。`RenderFrameMetadata` 中的视口大小 (`scrollable_viewport_size`) 信息对于正确渲染固定定位元素至关重要。

* **移动端优化:**  `RenderFrameMetadata` 中的 `is_mobile_optimized` 标志可能被 Blink 引擎用来选择不同的渲染路径或应用特定的优化策略，这些策略可能与移动设备的屏幕尺寸、像素密度等特性相关，最终影响 HTML 和 CSS 的渲染效果。JavaScript 也可以根据这个标志来执行不同的逻辑，例如加载更小尺寸的图片。

**逻辑推理的假设输入与输出：**

上面的每个测试用例都包含了假设输入和预期输出。总结一下常见的模式：

* **假设输入:** 通常是构造一个 `cc::RenderFrameMetadata` 和 `viz::CompositorFrameMetadata` 对象，并调用 `observer_impl().OnRenderFrameSubmission()` 方法。
* **预期输出:**  通常是通过 `EXPECT_CALL` 宏来断言 `MockRenderFrameMetadataObserverClient` 的特定方法是否被调用，以及调用时传入的参数值是否符合预期。

**涉及用户或者编程常见的使用错误：**

这个单元测试主要关注 `RenderFrameMetadataObserverImpl` 内部的逻辑，不太直接涉及用户的错误。但是，从编程角度来看，一些可能的使用错误包括：

1. **客户端（`MockRenderFrameMetadataObserverClient` 的实际实现者）没有正确处理 `OnRenderFrameMetadataChanged` 回调：**  如果客户端没有正确解析和使用接收到的 `RenderFrameMetadata`，可能会导致渲染或功能上的错误。例如，客户端可能忽略了 `is_mobile_optimized` 标志，导致在移动端加载了不合适的资源。

2. **在不需要的时候强制发送元数据：**  过度使用强制发送功能可能会导致不必要的性能开销，因为它会强制进行元数据的传递和处理，即使数据没有变化。

3. **在 Android 平台上错误地假设每次滚动都会触发新的帧令牌请求：**  这可能会导致一些不必要的同步或处理逻辑，因为 Android 平台对此进行了优化。

4. **配置根滚动偏移更新频率不当：**  如果配置为频繁更新，可能会增加不必要的通信开销。如果配置为不更新，则客户端可能无法及时获取到最新的滚动信息。

**总结:**

`render_frame_metadata_observer_impl_unittest.cc` 通过一系列单元测试，详细验证了 `RenderFrameMetadataObserverImpl` 类在处理渲染帧元数据时的各种场景和行为，确保了该类能够正确地传递帧令牌、渲染帧元数据以及处理平台特定的优化策略，这对于 Blink 引擎的正确渲染和性能至关重要。这些元数据最终会影响到 JavaScript、HTML 和 CSS 的行为和渲染结果。

Prompt: 
```
这是目录为blink/renderer/platform/widget/compositing/render_frame_metadata_observer_impl_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/widget/compositing/render_frame_metadata_observer_impl.h"

#include "base/run_loop.h"
#include "base/test/task_environment.h"
#include "build/build_config.h"
#include "cc/mojom/render_frame_metadata.mojom-blink.h"
#include "cc/trees/render_frame_metadata.h"
#include "components/viz/common/quads/compositor_frame_metadata.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {
namespace {

ACTION_P(InvokeClosure, closure) {
  closure.Run();
}

}  // namespace

class MockRenderFrameMetadataObserverClient
    : public cc::mojom::blink::RenderFrameMetadataObserverClient {
 public:
  MockRenderFrameMetadataObserverClient(
      mojo::PendingReceiver<cc::mojom::blink::RenderFrameMetadataObserverClient>
          client_receiver,
      mojo::PendingRemote<cc::mojom::blink::RenderFrameMetadataObserver>
          observer)
      : render_frame_metadata_observer_client_receiver_(
            this,
            std::move(client_receiver)),
        render_frame_metadata_observer_remote_(std::move(observer)) {}
  MockRenderFrameMetadataObserverClient(
      const MockRenderFrameMetadataObserverClient&) = delete;
  MockRenderFrameMetadataObserverClient& operator=(
      const MockRenderFrameMetadataObserverClient&) = delete;

  MOCK_METHOD2(OnRenderFrameMetadataChanged,
               void(uint32_t frame_token,
                    const cc::RenderFrameMetadata& metadata));
  MOCK_METHOD1(OnFrameSubmissionForTesting, void(uint32_t frame_token));
#if BUILDFLAG(IS_ANDROID)
  MOCK_METHOD1(OnRootScrollOffsetChanged, void(const gfx::PointF& offset));
#endif

 private:
  mojo::Receiver<cc::mojom::blink::RenderFrameMetadataObserverClient>
      render_frame_metadata_observer_client_receiver_;
  mojo::Remote<cc::mojom::blink::RenderFrameMetadataObserver>
      render_frame_metadata_observer_remote_;
};

class RenderFrameMetadataObserverImplTest : public testing::Test {
 public:
  RenderFrameMetadataObserverImplTest() = default;
  RenderFrameMetadataObserverImplTest(
      const RenderFrameMetadataObserverImplTest&) = delete;
  RenderFrameMetadataObserverImplTest& operator=(
      const RenderFrameMetadataObserverImplTest&) = delete;
  ~RenderFrameMetadataObserverImplTest() override = default;

  RenderFrameMetadataObserverImpl& observer_impl() { return *observer_impl_; }

  MockRenderFrameMetadataObserverClient& client() { return *client_; }

  // testing::Test:
  void SetUp() override {
    mojo::PendingRemote<cc::mojom::blink::RenderFrameMetadataObserver>
        observer_remote;
    mojo::PendingReceiver<cc::mojom::blink::RenderFrameMetadataObserver>
        receiver = observer_remote.InitWithNewPipeAndPassReceiver();
    mojo::PendingRemote<cc::mojom::blink::RenderFrameMetadataObserverClient>
        client_remote;

    client_ = std::make_unique<
        testing::NiceMock<MockRenderFrameMetadataObserverClient>>(
        client_remote.InitWithNewPipeAndPassReceiver(),
        std::move(observer_remote));
    observer_impl_ = std::make_unique<RenderFrameMetadataObserverImpl>(
        std::move(receiver), std::move(client_remote));
    observer_impl_->BindToCurrentSequence();
  }

  void TearDown() override {
    observer_impl_.reset();
    client_.reset();
    task_environment_.RunUntilIdle();
  }

 private:
  base::test::TaskEnvironment task_environment_;
  std::unique_ptr<testing::NiceMock<MockRenderFrameMetadataObserverClient>>
      client_;
  std::unique_ptr<RenderFrameMetadataObserverImpl> observer_impl_;
};

// This test verifies that the RenderFrameMetadataObserverImpl picks up
// the frame token from CompositorFrameMetadata and passes it along to the
// client. This test also verifies that the RenderFrameMetadata object is
// passed along to the client.
TEST_F(RenderFrameMetadataObserverImplTest, ShouldSendFrameToken) {
  viz::CompositorFrameMetadata compositor_frame_metadata;
  compositor_frame_metadata.send_frame_token_to_embedder = false;
  compositor_frame_metadata.frame_token = 1337;
  cc::RenderFrameMetadata render_frame_metadata;
  render_frame_metadata.is_mobile_optimized = true;
  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  // |is_mobile_optimized| should be synchronized with frame activation so
  // RenderFrameMetadataObserverImpl should ask for the frame token from
  // Viz.
  EXPECT_TRUE(compositor_frame_metadata.send_frame_token_to_embedder);
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(),
                OnRenderFrameMetadataChanged(1337, render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }
}

// This test verifies that a frame token is not requested from viz when
// the root scroll offset changes on Android.
#if BUILDFLAG(IS_ANDROID)
TEST_F(RenderFrameMetadataObserverImplTest, ShouldSendFrameTokenOnAndroid) {
  viz::CompositorFrameMetadata compositor_frame_metadata;
  compositor_frame_metadata.send_frame_token_to_embedder = false;
  compositor_frame_metadata.frame_token = 1337;
  cc::RenderFrameMetadata render_frame_metadata;
  render_frame_metadata.root_scroll_offset = gfx::PointF(0.f, 1.f);
  render_frame_metadata.root_layer_size = gfx::SizeF(100.f, 100.f);
  render_frame_metadata.scrollable_viewport_size = gfx::SizeF(100.f, 50.f);
  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  // The first RenderFrameMetadata will always get a corresponding frame token
  // from Viz because this is the first frame.
  EXPECT_TRUE(compositor_frame_metadata.send_frame_token_to_embedder);
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(),
                OnRenderFrameMetadataChanged(1337, render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }

  // Scroll back to the top.
  render_frame_metadata.root_scroll_offset = gfx::PointF(0.f, 0.f);

  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  // Android does not need a corresponding frame token.
  EXPECT_FALSE(compositor_frame_metadata.send_frame_token_to_embedder);
  {
    base::RunLoop run_loop;
    // The 0u frame token indicates that the client should not expect
    // a corresponding frame token from Viz.
    EXPECT_CALL(client(),
                OnRenderFrameMetadataChanged(0u, render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }
}

// This test verifies that a request to send root scroll changes for
// accessibility is respected.
TEST_F(RenderFrameMetadataObserverImplTest, SendRootScrollsForAccessibility) {
  const uint32_t expected_frame_token = 1337;
  viz::CompositorFrameMetadata compositor_frame_metadata;
  compositor_frame_metadata.send_frame_token_to_embedder = false;
  compositor_frame_metadata.frame_token = expected_frame_token;
  cc::RenderFrameMetadata render_frame_metadata;

  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  // The first RenderFrameMetadata will always get a corresponding frame token
  // from Viz because this is the first frame.
  EXPECT_TRUE(compositor_frame_metadata.send_frame_token_to_embedder);
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(), OnRenderFrameMetadataChanged(expected_frame_token,
                                                       render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }

  // Submit with a root scroll change and then a scroll offset at top change, we
  // should only get one notification, as the root scroll change will not
  // trigger one,
  render_frame_metadata.root_scroll_offset = gfx::PointF(0.0f, 100.0f);
  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  render_frame_metadata.is_scroll_offset_at_top =
      !render_frame_metadata.is_scroll_offset_at_top;
  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(), OnRenderFrameMetadataChanged(expected_frame_token,
                                                       render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }

  // Enable reporting for root scroll changes on every frame. This will generate
  // one notification.
  observer_impl().UpdateRootScrollOffsetUpdateFrequency(
      cc::mojom::RootScrollOffsetUpdateFrequency::kAllUpdates);
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(), OnRenderFrameMetadataChanged(expected_frame_token,
                                                       render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }

  // Now send a single root scroll change, we should get the notification.
  render_frame_metadata.root_scroll_offset = gfx::PointF(0.0f, 200.0f);
  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(), OnRootScrollOffsetChanged(
                              *(render_frame_metadata.root_scroll_offset)))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }

  // Send one more message to ensure that no spurious
  // OnRenderFrameMetadataChanged messages were generated.
  render_frame_metadata.is_scroll_offset_at_top =
      !render_frame_metadata.is_scroll_offset_at_top;
  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(), OnRenderFrameMetadataChanged(expected_frame_token,
                                                       render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }
}

// This test verifies that we don't get notifications for the root scroll
// offsets by default.
TEST_F(RenderFrameMetadataObserverImplTest,
       DoNotSendRootScrollOffsetByDefault) {
  const uint32_t expected_frame_token = 1337;
  viz::CompositorFrameMetadata compositor_frame_metadata;
  compositor_frame_metadata.send_frame_token_to_embedder = false;
  compositor_frame_metadata.frame_token = expected_frame_token;
  cc::RenderFrameMetadata render_frame_metadata;

  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(), OnRenderFrameMetadataChanged(expected_frame_token,
                                                       render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }

  // Submit with a root scroll change 3 times. We shouldn't get a notification.
  render_frame_metadata.root_scroll_offset = gfx::PointF(0.0f, 100.0f);
  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  render_frame_metadata.root_scroll_offset->set_y(200.0f);
  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  render_frame_metadata.root_scroll_offset->set_y(300.0f);
  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  EXPECT_CALL(client(), OnRenderFrameMetadataChanged(expected_frame_token,
                                                     render_frame_metadata))
      .Times(0);
}

// This test verifies that we don't get an extra `OnRootScrollOffsetChanged()`
// when we would already get an `OnRenderFrameMetadataChanged()` notification.
TEST_F(RenderFrameMetadataObserverImplTest, DoNotSendExtraRootScrollOffset) {
  const uint32_t expected_frame_token = 1337;
  viz::CompositorFrameMetadata compositor_frame_metadata;
  compositor_frame_metadata.send_frame_token_to_embedder = false;
  compositor_frame_metadata.frame_token = expected_frame_token;
  cc::RenderFrameMetadata render_frame_metadata;

  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(), OnRenderFrameMetadataChanged(expected_frame_token,
                                                       render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }

  // Enable reporting for root scroll changes on every frame. This will generate
  // one notification.
  observer_impl().UpdateRootScrollOffsetUpdateFrequency(
      cc::mojom::RootScrollOffsetUpdateFrequency::kAllUpdates);
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(), OnRenderFrameMetadataChanged(expected_frame_token,
                                                       render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }

  // Send a single root scroll change with `is_scroll_offset_at_top`, which
  // should already trigger an `OnRenderFrameMetadataChanged()` and shouldn't
  // send an `OnRootScrollOffsetChanged()`.
  render_frame_metadata.root_scroll_offset = gfx::PointF(0.0f, 200.0f);
  render_frame_metadata.is_scroll_offset_at_top =
      !render_frame_metadata.is_scroll_offset_at_top;
  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  EXPECT_CALL(client(), OnRootScrollOffsetChanged(
                            *(render_frame_metadata.root_scroll_offset)))
      .Times(0);
}

// This test verifies that we get an `OnRootScrollOffsetChanged()` when we call
// `DidEndScroll()`.
TEST_F(RenderFrameMetadataObserverImplTest, SendRootScrollOffsetOnScrollEnd) {
  ScopedCCTNewRFMPushBehaviorForTest feature(true);
  const uint32_t expected_frame_token = 1337;
  viz::CompositorFrameMetadata compositor_frame_metadata;
  compositor_frame_metadata.send_frame_token_to_embedder = false;
  compositor_frame_metadata.frame_token = expected_frame_token;
  cc::RenderFrameMetadata render_frame_metadata;

  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(), OnRenderFrameMetadataChanged(expected_frame_token,
                                                       render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }

  // Enable reporting for root scroll changes on scroll-end. This will generate
  // a notification.
  observer_impl().UpdateRootScrollOffsetUpdateFrequency(
      cc::mojom::RootScrollOffsetUpdateFrequency::kOnScrollEnd);
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(), OnRenderFrameMetadataChanged(expected_frame_token,
                                                       render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }

  // Submit with a root scroll change a couple times. This shouldn't generate a
  // notification.
  render_frame_metadata.root_scroll_offset = gfx::PointF(0.0f, 100.0f);
  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  render_frame_metadata.root_scroll_offset->set_y(200.0f);
  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  EXPECT_CALL(client(), OnRenderFrameMetadataChanged(expected_frame_token,
                                                     render_frame_metadata))
      .Times(0);
  EXPECT_CALL(client(), OnRootScrollOffsetChanged(
                            *(render_frame_metadata.root_scroll_offset)))
      .Times(0);

  // Now, simulate a ScrollEnd. This should send the latest root scroll offset.
  observer_impl().DidEndScroll();
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(), OnRootScrollOffsetChanged(
                              *(render_frame_metadata.root_scroll_offset)))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }
}

// This test verifies that we get an `OnRenderFrameMetadataChanged()` when we
// update the update frequency.
TEST_F(RenderFrameMetadataObserverImplTest,
       SendRenderFrameMetadataOnUpdateFrequency) {
  ScopedCCTNewRFMPushBehaviorForTest feature(true);
  const uint32_t expected_frame_token = 1337;
  viz::CompositorFrameMetadata compositor_frame_metadata;
  compositor_frame_metadata.send_frame_token_to_embedder = false;
  compositor_frame_metadata.frame_token = expected_frame_token;
  cc::RenderFrameMetadata render_frame_metadata;

  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(), OnRenderFrameMetadataChanged(expected_frame_token,
                                                       render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }

  // Update frequency to kNone. This should send a notification since the
  // frequency was empty before.
  observer_impl().UpdateRootScrollOffsetUpdateFrequency(
      cc::mojom::RootScrollOffsetUpdateFrequency::kNone);
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(), OnRenderFrameMetadataChanged(expected_frame_token,
                                                       render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }

  // Update frequency to on scroll-end. This should send a notification since
  // the frequency increased.
  observer_impl().UpdateRootScrollOffsetUpdateFrequency(
      cc::mojom::RootScrollOffsetUpdateFrequency::kOnScrollEnd);
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(), OnRenderFrameMetadataChanged(expected_frame_token,
                                                       render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }
}
#endif

// This test verifies that a request to force send metadata is respected.
TEST_F(RenderFrameMetadataObserverImplTest, ForceSendMetadata) {
  const uint32_t expected_frame_token = 1337;
  viz::CompositorFrameMetadata compositor_frame_metadata;
  compositor_frame_metadata.send_frame_token_to_embedder = false;
  compositor_frame_metadata.frame_token = expected_frame_token;
  cc::RenderFrameMetadata render_frame_metadata;
  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  // The first RenderFrameMetadata will always get a corresponding frame token
  // from Viz because this is the first frame.
  EXPECT_TRUE(compositor_frame_metadata.send_frame_token_to_embedder);
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(), OnRenderFrameMetadataChanged(expected_frame_token,
                                                       render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }

  // Submit twice with no changes, but once with |force_send|. We should get
  // exactly one call to OnRenderFrameMetadataChanged.
  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  observer_impl().OnRenderFrameSubmission(
      render_frame_metadata, &compositor_frame_metadata, true /* force_send */);
  // Force send does not trigger sending a frame token.
  EXPECT_FALSE(compositor_frame_metadata.send_frame_token_to_embedder);
  {
    base::RunLoop run_loop;
    // The 0u frame token indicates that the client should not expect
    // a corresponding frame token from Viz.
    EXPECT_CALL(client(),
                OnRenderFrameMetadataChanged(0u, render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }

  // Update the metadata and send one more message to ensure that no spurious
  // OnRenderFrameMetadataChanged messages were generated.
  render_frame_metadata.is_scroll_offset_at_top =
      !render_frame_metadata.is_scroll_offset_at_top;
  observer_impl().OnRenderFrameSubmission(render_frame_metadata,
                                          &compositor_frame_metadata,
                                          false /* force_send */);
  {
    base::RunLoop run_loop;
    EXPECT_CALL(client(), OnRenderFrameMetadataChanged(expected_frame_token,
                                                       render_frame_metadata))
        .WillOnce(InvokeClosure(run_loop.QuitClosure()));
    run_loop.Run();
  }
}

}  // namespace blink

"""

```
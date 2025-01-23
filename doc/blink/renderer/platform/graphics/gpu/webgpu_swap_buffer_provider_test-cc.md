Response:
Let's break down the thought process to analyze this C++ test file.

1. **Understand the Goal:** The first step is to recognize that this is a *test file*. The naming convention `*_test.cc` is a strong indicator. Test files exist to verify the functionality of other code. Specifically, this file is testing `webgpu_swap_buffer_provider.h`.

2. **Identify the Tested Class:** The filename `webgpu_swap_buffer_provider_test.cc` directly points to the class being tested: `WebGPUSwapBufferProvider`.

3. **Examine Imports and Namespaces:**  Look at the `#include` directives and the `namespace`. This reveals dependencies and the context of the code.
    * Includes like `<dawn/dawn_proc.h>`, `<dawn/wire/WireClient.h>`, `gpu/command_buffer/client/webgpu_interface_stub.h`, and the `third_party/blink` paths clearly indicate this code interacts with the WebGPU API and the Chromium/Blink rendering engine.
    * The `namespace blink` confirms its location within the Blink engine.

4. **Identify Key Mock Objects and Test Fixture:**  Test files often use mocking to isolate the unit under test.
    * `MockWebGPUInterface`: This is a crucial observation. It's a mock implementation of the WebGPU interface, meaning the tests control how WebGPU calls behave. This is essential for unit testing.
    * `FakeProviderClient`:  This likely mocks the client of the `WebGPUSwapBufferProvider`, allowing tests to observe interactions.
    * `WebGPUSwapBufferProviderForTests`:  A derived class, potentially to add testing-specific functionality or to make members accessible.
    * `WebGPUSwapBufferProviderTest`: The main test fixture using `testing::Test`. This sets up and tears down the testing environment.

5. **Analyze Individual Test Cases (TEST_F):** Go through each `TEST_F` function. Each one represents a specific scenario being tested. Try to understand the *purpose* of each test:
    * `VerifyDestructionCompleteAfterAllResourceReleased`:  Focuses on resource management and destruction order.
    * `VerifyResizingProperlyAffectsResources`: Checks if resizing triggers appropriate behavior.
    * `VerifyInsertAndWaitSyncTokenCorrectly`:  Tests synchronization mechanisms.
    * `ReuseSwapBuffers`: Checks if swap buffers are recycled correctly.
    * `ReuseSwapBufferResize`:  Tests the recycling behavior when resizing occurs.
    * `PrepareTransferableResourceTwiceAfterDestroy`: A regression test for a specific bug.
    * `VerifyMailboxDissociationOnNeuter`: Tests the `Neuter()` function.
    * `VerifyNoDoubleMailboxDissociation`: Ensures `Neuter()` doesn't cause issues when other dissociation mechanisms are in play.
    * `ReserveTextureDescriptorForReflection`: Verifies the parameters passed to the `ReserveTexture` call.
    * `VerifyZeroSizeRejects`: Checks handling of invalid sizes.
    * `GetLastWebGPUMailboxTextureReturnsEmptyWithoutSwapBuffer`: Tests an edge case of `GetLastWebGPUMailboxTexture()`.
    * `GetLastWebGPUMailboxTextureReturnsValidTextureWithSwapBuffer`: Tests the normal case of `GetLastWebGPUMailboxTexture()`.
    * `GetNewTexturePassesClientSpecifiedInternalUsagePlusRenderAttachment`:  Verifies how internal usage flags are combined.
    * `GetLastMailboxTexturePassesClientSpecifiedInternalUsage`:  Verifies internal usage flags in a different scenario.

6. **Look for Interactions with Web Technologies (JavaScript, HTML, CSS):** Consider how the tested class might be used in a web browser.
    * WebGPU is an API exposed to JavaScript. The `WebGPUSwapBufferProvider` likely plays a role in how WebGPU renders content to the screen.
    * While this specific test file doesn't *directly* manipulate HTML, CSS, or JavaScript, its functionality is crucial for the underlying implementation of WebGPU, which *is* used by those technologies. Think about how a WebGL or WebGPU canvas is rendered – swap buffers are part of that process.

7. **Identify Potential User/Programming Errors:**  Based on the test cases, infer potential errors. For example, the "PrepareTransferableResourceTwiceAfterDestroy" test suggests a potential issue if resources are accessed after being destroyed. Incorrectly managing the lifetime of the `WebGPUSwapBufferProvider` or its associated resources could lead to errors.

8. **Analyze Mock Behavior and Assertions:**  Pay attention to how the mock objects are set up using `EXPECT_CALL` and what assertions (`EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_NE`) are being made. This reveals the expected behavior of the code under test.

9. **Consider Logic and Assumptions:** For example, when a swap buffer is resized, it likely can't reuse the old buffer. This is the logic being tested in `ReuseSwapBufferResize`. Think about the underlying assumptions of the code.

10. **Structure the Answer:** Organize the findings into logical categories as requested: functionality, relationship to web technologies, logical reasoning (input/output), and common errors. Provide specific examples from the code to support the analysis.这个文件 `webgpu_swap_buffer_provider_test.cc` 是 Chromium Blink 引擎中用于测试 `WebGPUSwapBufferProvider` 类的单元测试文件。 `WebGPUSwapBufferProvider` 的主要职责是管理用于 WebGPU 渲染的交换缓冲区（swap buffers），这些缓冲区用于将渲染结果呈现到屏幕上。

以下是该文件的功能分解：

**1. 测试 `WebGPUSwapBufferProvider` 的核心功能:**

*   **交换缓冲区的创建和管理:**  测试 `WebGPUSwapBufferProvider` 如何创建、存储和回收交换缓冲区。这包括在需要时分配新的纹理，以及在不再使用时释放它们。
*   **与 GPU 进程的交互:** 通过模拟 `gpu::webgpu::WebGPUInterface`，测试 `WebGPUSwapBufferProvider` 如何与 GPU 进程进行通信，例如预留纹理 (`ReserveTexture`)，关联和取消关联邮箱 (`AssociateMailbox`, `DissociateMailbox`)，以及生成和等待同步令牌 (`GenSyncTokenCHROMIUM`, `WaitSyncTokenCHROMIUM`)。
*   **资源转移和同步:**  测试 `PrepareTransferableResource` 方法，该方法将交换缓冲区准备好以便转移到合成器（compositor），并生成用于同步的令牌。
*   **资源释放:** 测试在交换缓冲区不再使用时，`WebGPUSwapBufferProvider` 如何处理资源的释放和清理。
*   **调整缓冲区大小:** 测试当渲染目标的大小改变时，`WebGPUSwapBufferProvider` 如何处理缓冲区的调整。
*   **显式销毁:** 测试 `Neuter()` 方法，该方法用于显式地释放与 `WebGPUSwapBufferProvider` 关联的资源。

**2. 模拟 WebGPU 环境:**

*   **`MockWebGPUInterface`:**  这是一个模拟的 WebGPU 接口，用于隔离被测试的代码，并允许测试控制 WebGPU 相关调用的行为和返回值。通过 `MOCK_METHOD` 宏，可以定义模拟函数的行为，例如 `ReserveTexture`。
*   **`FakeProviderClient`:** 这是一个模拟的 `WebGPUSwapBufferProvider::Client`，用于观察 `WebGPUSwapBufferProvider` 的行为，例如纹理转移的通知。
*   **`WebGPUSwapBufferProviderForTests`:** 这是一个继承自 `WebGPUSwapBufferProvider` 的测试专用类，可能为了方便测试而暴露了一些内部状态或方法。
*   **Dawn Wire 集成:**  使用 Dawn Wire 协议进行进程间通信的模拟，这在 Chromium 中是 WebGPU 实现的一部分。

**3. 测试用例 (`TEST_F`)：**

*   每个 `TEST_F` 函数都针对 `WebGPUSwapBufferProvider` 的特定方面或场景进行测试。

**与 JavaScript, HTML, CSS 的功能关系及举例说明:**

`WebGPUSwapBufferProvider` 位于渲染引擎的底层，直接与 WebGPU API 的实现相关，而 WebGPU API 是 JavaScript 可以访问的。 因此，虽然这个 C++ 文件本身不包含 JavaScript、HTML 或 CSS 代码，但它的功能对于在网页上渲染 WebGPU 内容至关重要。

*   **JavaScript:**  当 JavaScript 代码使用 WebGPU API 进行渲染时，例如创建一个 Canvas 并获取其 WebGPU 上下文，然后执行渲染命令，`WebGPUSwapBufferProvider` 负责管理用于显示渲染结果的缓冲区。
    *   **例子:**  假设一个 JavaScript WebGPU 程序绘制了一个 3D 模型。当 `requestAnimationFrame` 被触发，并且渲染命令被提交到 GPU 时，`WebGPUSwapBufferProvider` 会提供一个可用于渲染的缓冲区。渲染完成后，该缓冲区会被提交以显示在 `<canvas>` 元素上。

*   **HTML:** HTML 的 `<canvas>` 元素是 WebGPU 内容的渲染目标。 `WebGPUSwapBufferProvider` 提供的缓冲区最终会与这个 `<canvas>` 元素关联，以便浏览器可以将渲染结果显示出来。
    *   **例子:**  HTML 中有一个 `<canvas id="gpuCanvas"></canvas>` 元素。 JavaScript 代码会获取这个 canvas 的 WebGPU 上下文。 `WebGPUSwapBufferProvider` 管理的交换缓冲区的内容会被渲染到这个 canvas 上。

*   **CSS:** CSS 可以影响 `<canvas>` 元素的大小和布局。当 canvas 的大小改变时，`WebGPUSwapBufferProvider` 需要能够处理缓冲区大小的调整，以确保渲染内容能够正确显示。
    *   **例子:**  CSS 样式设置了 `#gpuCanvas { width: 500px; height: 300px; }`。 当这个样式生效时，`WebGPUSwapBufferProvider` 需要创建或调整交换缓冲区的大小以匹配 500x300。 测试用例 `VerifyResizingProperlyAffectsResources` 正是测试了这种场景。

**逻辑推理的假设输入与输出 (基于测试用例):**

*   **假设输入 (以 `VerifyDestructionCompleteAfterAllResourceReleased` 为例):**
    1. 创建 `WebGPUSwapBufferProvider` 实例。
    2. 连续获取多个新的纹理（交换缓冲区）。
    3. 对每个纹理调用 `PrepareTransferableResource` 获取用于释放资源的回调函数。
    4. 先将 `WebGPUSwapBufferProvider` 实例置空。
    5. 依次执行每个纹理的释放回调。

*   **预期输出:** `WebGPUSwapBufferProvider` 实例的生命周期应该在所有相关的交换缓冲区资源被释放后才结束，即在最后一个释放回调被执行后。 测试中通过 `provider_alive_` 标志来验证这一点。

*   **假设输入 (以 `VerifyResizingProperlyAffectsResources` 为例):**
    1. 创建 `WebGPUSwapBufferProvider` 实例。
    2. 以一个尺寸 (例如 10x10) 获取新的纹理，并准备好资源。
    3. 释放该资源。
    4. 以另一个尺寸 (例如 20x20) 获取新的纹理，并准备好资源。
    5. 释放该资源。
    6. 再次以第一个尺寸 (10x10) 获取新的纹理，并准备好资源。

*   **预期输出:** 每次调用 `PrepareTransferableResource` 时，返回的 `viz::TransferableResource` 的 `size` 字段应该与获取纹理时指定的尺寸相匹配。

**涉及用户或编程常见的使用错误及举例说明:**

*   **资源泄漏:**  如果用户（在这里指的是 Blink 引擎的开发者或 WebGPU 的实现者）在交换缓冲区不再需要时没有正确地释放它们，可能会导致内存泄漏。 测试用例如 `VerifyDestructionCompleteAfterAllResourceReleased` 旨在确保资源能够被正确清理。

    *   **例子:**  一个错误的实现可能在交换缓冲区不再显示在屏幕上后，仍然持有对它的引用，导致 GPU 内存无法被回收。

*   **过早释放资源:**  如果在 GPU 完成对交换缓冲区的操作之前就释放了它，可能会导致渲染错误或崩溃。 测试用例如 `VerifyInsertAndWaitSyncTokenCorrectly` 确保了资源转移和释放的同步机制的正确性。

    *   **例子:**  JavaScript 代码提交了渲染命令并立即释放了相关的纹理对象，而 GPU 可能还在使用该纹理进行渲染。

*   **在资源销毁后访问:**  尝试在 `WebGPUSwapBufferProvider` 或其管理的资源被销毁后仍然访问它们会导致未定义的行为。 测试用例 `PrepareTransferableResourceTwiceAfterDestroy` 旨在防止这种错误。

    *   **例子:**  在 `WebGPUSwapBufferProvider` 被销毁后，仍然尝试调用其 `PrepareTransferableResource` 方法。

*   **不匹配的缓冲区大小:** 如果提供给 WebGPU 的缓冲区大小与渲染目标的大小不匹配，会导致渲染结果显示不正确。 测试用例 `VerifyResizingProperlyAffectsResources` 确保了缓冲区大小调整的正确性。

    *   **例子:**  CSS 将 canvas 的大小调整为 800x600，但 `WebGPUSwapBufferProvider` 仍然提供 500x300 的缓冲区，导致渲染内容被裁剪或拉伸。

总而言之，`webgpu_swap_buffer_provider_test.cc` 是一个关键的测试文件，用于确保 `WebGPUSwapBufferProvider` 类的正确性和稳定性，这对于在 Chromium 中正确实现和渲染 WebGPU 内容至关重要。 它通过模拟各种场景和交互，验证了资源管理、同步和与 GPU 进程通信等核心功能。

### 提示词
```
这是目录为blink/renderer/platform/graphics/gpu/webgpu_swap_buffer_provider_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/graphics/gpu/webgpu_swap_buffer_provider.h"

#include <dawn/dawn_proc.h>
#include <dawn/wire/WireClient.h>
#include <dawn/wire/WireServer.h>

#include "base/memory/raw_ptr.h"
#include "base/test/task_environment.h"
#include "gpu/command_buffer/client/webgpu_interface_stub.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_graphics_context_3d_provider.h"
#include "third_party/blink/renderer/platform/graphics/gpu/drawing_buffer_test_helpers.h"
#include "third_party/blink/renderer/platform/graphics/gpu/webgpu_cpp.h"
#include "third_party/blink/renderer/platform/graphics/gpu/webgpu_native_test_support.h"

using testing::_;
using testing::Invoke;
using testing::Return;

namespace blink {

namespace {

class MockWebGPUInterface : public gpu::webgpu::WebGPUInterfaceStub {
 public:
  MOCK_METHOD(gpu::webgpu::ReservedTexture,
              ReserveTexture,
              (WGPUDevice device, const WGPUTextureDescriptor* optionalDesc));

  // NOTE: Can switch to using mock if tracking state manually grows to be
  // unwieldy.
  void AssociateMailbox(GLuint,
                        GLuint,
                        GLuint,
                        GLuint,
                        uint64_t,
                        uint64_t internal_usage,
                        const WGPUTextureFormat*,
                        GLuint,
                        gpu::webgpu::MailboxFlags,
                        const gpu::Mailbox&) override {
    internal_usage_from_most_recent_associate_mailbox_call =
        static_cast<wgpu::TextureUsage>(internal_usage);
    num_associated_mailboxes++;
  }
  void DissociateMailbox(GLuint, GLuint) override {
    num_associated_mailboxes--;
  }
  void DissociateMailboxForPresent(GLuint, GLuint, GLuint, GLuint) override {
    num_associated_mailboxes--;
  }

  // It is hard to use GMock with SyncTokens represented as GLByte*, instead we
  // remember which were the last sync tokens generated or waited upon.
  void GenUnverifiedSyncTokenCHROMIUM(GLbyte* sync_token) override {
    most_recent_generated_token =
        gpu::SyncToken(gpu::CommandBufferNamespace::GPU_IO,
                       gpu::CommandBufferId(), ++token_id_);
    memcpy(sync_token, &most_recent_generated_token, sizeof(gpu::SyncToken));
  }
  void GenSyncTokenCHROMIUM(GLbyte* sync_token) override {
    most_recent_generated_token =
        gpu::SyncToken(gpu::CommandBufferNamespace::GPU_IO,
                       gpu::CommandBufferId(), ++token_id_);
    most_recent_generated_token.SetVerifyFlush();
    memcpy(sync_token, &most_recent_generated_token, sizeof(gpu::SyncToken));
  }

  void WaitSyncTokenCHROMIUM(const GLbyte* sync_token_data) override {
    memcpy(&most_recent_waited_token, sync_token_data, sizeof(gpu::SyncToken));
  }

  gpu::SyncToken most_recent_generated_token;
  gpu::SyncToken most_recent_waited_token;

  int num_associated_mailboxes = 0;
  wgpu::TextureUsage internal_usage_from_most_recent_associate_mailbox_call =
      wgpu::TextureUsage::None;

 private:
  uint64_t token_id_ = 42;
};

class FakeProviderClient : public WebGPUSwapBufferProvider::Client {
 public:
  void OnTextureTransferred() override {
    DCHECK(texture);
    texture = nullptr;
  }

  void SetNeedsCompositingUpdate() override {}

  scoped_refptr<WebGPUMailboxTexture> texture;
};

class WebGPUSwapBufferProviderForTests : public WebGPUSwapBufferProvider {
 public:
  WebGPUSwapBufferProviderForTests(
      bool* alive,
      FakeProviderClient* client,
      const wgpu::Device& device,
      scoped_refptr<DawnControlClientHolder> dawn_control_client,
      wgpu::TextureUsage usage,
      wgpu::TextureUsage internal_usage,
      wgpu::TextureFormat format,
      PredefinedColorSpace color_space,
      const gfx::HDRMetadata& hdr_metadata)
      : WebGPUSwapBufferProvider(client,
                                 dawn_control_client,
                                 device,
                                 usage,
                                 internal_usage,
                                 format,
                                 color_space,
                                 hdr_metadata),
        alive_(alive),
        client_(client) {
    texture_desc_ = {
        .usage = usage,
        .size = {0, 0, 1},
        .format = format,
    };
    texture_internal_usage_ = {{
        .internalUsage = internal_usage,
    }};
    texture_desc_.nextInChain = &texture_internal_usage_;
  }
  ~WebGPUSwapBufferProviderForTests() override { *alive_ = false; }

  scoped_refptr<WebGPUMailboxTexture> GetNewTexture(const gfx::Size& size) {
    // The alpha type is an optimization hint so just pass in opaque here.
    texture_desc_.size.width = size.width();
    texture_desc_.size.height = size.height();
    client_->texture = WebGPUSwapBufferProvider::GetNewTexture(
        texture_desc_, kOpaque_SkAlphaType);
    return client_->texture;
  }

 private:
  raw_ptr<bool> alive_;
  raw_ptr<FakeProviderClient> client_;
  wgpu::TextureDescriptor texture_desc_;
  wgpu::DawnTextureInternalUsageDescriptor texture_internal_usage_;
};

class WireSerializer : public dawn::wire::CommandSerializer {
 public:
  size_t GetMaximumAllocationSize() const override { return sizeof(buf_); }

  void SetHandler(dawn::wire::CommandHandler* handler) { handler_ = handler; }

  void* GetCmdSpace(size_t size) override {
    if (size > sizeof(buf_)) {
      return nullptr;
    }
    if (sizeof(buf_) - size < offset_) {
      if (!Flush()) {
        return nullptr;
      }
    }
    char* result = &buf_[offset_];
    offset_ += size;
    return result;
  }

  bool Flush() override {
    bool success = handler_->HandleCommands(buf_, offset_) != nullptr;
    offset_ = 0;
    return success;
  }

 private:
  size_t offset_ = 0;
  char buf_[1024 * 1024];
  raw_ptr<dawn::wire::CommandHandler> handler_;
};

}  // anonymous namespace

class WebGPUSwapBufferProviderTest : public testing::Test {
 protected:
  static constexpr wgpu::TextureFormat kFormat =
      wgpu::TextureFormat::RGBA8Unorm;
  static constexpr wgpu::TextureUsage kUsage =
      wgpu::TextureUsage::RenderAttachment;
  static constexpr wgpu::TextureUsage kInternalUsage =
      wgpu::TextureUsage::CopyDst;

  void SetUp() override {
    auto webgpu = std::make_unique<MockWebGPUInterface>();
    webgpu_ = webgpu.get();

    Platform::SetMainThreadTaskRunnerForTesting();

    auto provider = std::make_unique<WebGraphicsContext3DProviderForTests>(
        std::move(webgpu));
    sii_ = provider->SharedImageInterface();

    c2s_serializer_.SetHandler(&wire_server_);
    s2c_serializer_.SetHandler(&wire_client_);
#if !BUILDFLAG(USE_DAWN)
    // If not USE_DAWN, then Dawn wire is not linked into the Blink code.
    // Instead the proc table is used. Set the procs to the wire procs to
    // unittest this platform where Dawn is not enabled by default yet.
    dawnProcSetProcs(&dawn::wire::client::GetProcs());
#endif

    wgpu::InstanceDescriptor instance_desc = {};
    auto reservation = wire_client_.ReserveInstance(
        reinterpret_cast<WGPUInstanceDescriptor*>(&instance_desc));

    WGPUInstance native_instance = MakeNativeWGPUInstance();
    wire_server_.InjectInstance(native_instance, reservation.handle);
    GetDawnNativeProcs().instanceRelease(native_instance);

    instance_ = wgpu::Instance::Acquire(reservation.instance);

    wgpu::RequestAdapterOptions options = {
        .backendType = wgpu::BackendType::Null,
    };
    instance_.RequestAdapter(
        &options, wgpu::CallbackMode::AllowSpontaneous,
        [&](wgpu::RequestAdapterStatus status, wgpu::Adapter adapter,
            wgpu::StringView) { adapter_ = std::move(adapter); });
    ASSERT_TRUE(c2s_serializer_.Flush());
    ASSERT_TRUE(s2c_serializer_.Flush());
    ASSERT_NE(adapter_, nullptr);

    wgpu::DeviceDescriptor deviceDesc = {};
    adapter_.RequestDevice(
        &deviceDesc, wgpu::CallbackMode::AllowSpontaneous,
        [&](wgpu::RequestDeviceStatus, wgpu::Device device, wgpu::StringView) {
          device_ = std::move(device);
        });
    ASSERT_TRUE(c2s_serializer_.Flush());
    ASSERT_TRUE(s2c_serializer_.Flush());
    ASSERT_NE(device_, nullptr);

    dawn_control_client_ = base::MakeRefCounted<DawnControlClientHolder>(
        std::move(provider), scheduler::GetSingleThreadTaskRunnerForTesting());

    provider_ = base::MakeRefCounted<WebGPUSwapBufferProviderForTests>(
        &provider_alive_, &client_, device_.Get(), dawn_control_client_, kUsage,
        kInternalUsage, kFormat, PredefinedColorSpace::kSRGB,
        gfx::HDRMetadata());
  }

  void TearDown() override { Platform::UnsetMainThreadTaskRunnerForTesting(); }

  gpu::webgpu::ReservedTexture ReserveTextureImpl(
      WGPUDevice device,
      const WGPUTextureDescriptor* desc) {
    auto reserved = wire_client_.ReserveTexture(device, desc);
    gpu::webgpu::ReservedTexture result;
    result.texture = reserved.texture;
    result.id = reserved.handle.id;
    result.generation = reserved.handle.generation;
    result.deviceId = reserved.deviceHandle.id;
    result.deviceGeneration = reserved.deviceHandle.generation;
    return result;
  }

  base::test::TaskEnvironment task_environment_;

  WireSerializer c2s_serializer_;
  WireSerializer s2c_serializer_;
  dawn::wire::WireClient wire_client_{{.serializer = &c2s_serializer_}};
  dawn::wire::WireServer wire_server_{
      {.procs = &GetDawnNativeProcs(), .serializer = &s2c_serializer_}};
  wgpu::Instance instance_;
  wgpu::Adapter adapter_;
  wgpu::Device device_;

  scoped_refptr<DawnControlClientHolder> dawn_control_client_;
  raw_ptr<MockWebGPUInterface> webgpu_;
  raw_ptr<gpu::TestSharedImageInterface> sii_;
  FakeProviderClient client_;
  scoped_refptr<WebGPUSwapBufferProviderForTests> provider_;
  bool provider_alive_ = true;
};

TEST_F(WebGPUSwapBufferProviderTest,
       VerifyDestructionCompleteAfterAllResourceReleased) {
  const gfx::Size kSize(10, 10);

  viz::TransferableResource resource1;
  viz::ReleaseCallback release_callback1;

  viz::TransferableResource resource2;
  viz::ReleaseCallback release_callback2;

  viz::TransferableResource resource3;
  viz::ReleaseCallback release_callback3;

  // Produce resources.
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);
  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource1, &release_callback1));

  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);
  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource2, &release_callback2));

  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);
  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource3, &release_callback3));

  // Release resources one by one, the provider should only be freed when the
  // last one is called.
  provider_ = nullptr;
  std::move(release_callback1).Run(gpu::SyncToken(), false /* lostResource */);
  ASSERT_EQ(provider_alive_, true);

  std::move(release_callback2).Run(gpu::SyncToken(), false /* lostResource */);
  ASSERT_EQ(provider_alive_, true);

  std::move(release_callback3).Run(gpu::SyncToken(), false /* lostResource */);
  ASSERT_EQ(provider_alive_, false);
}

TEST_F(WebGPUSwapBufferProviderTest, VerifyResizingProperlyAffectsResources) {
  const gfx::Size kSize(10, 10);
  const gfx::Size kOtherSize(20, 20);

  viz::TransferableResource resource;
  viz::ReleaseCallback release_callback;

  // Produce one resource of size kSize.
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);
  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource, &release_callback));
  EXPECT_EQ(kSize, resource.size);
  std::move(release_callback).Run(gpu::SyncToken(), false /* lostResource */);

  // Produce one resource of size kOtherSize.
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kOtherSize);
  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource, &release_callback));
  EXPECT_EQ(kOtherSize, resource.size);
  std::move(release_callback).Run(gpu::SyncToken(), false /* lostResource */);

  // Produce one resource of size kSize again.
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);
  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource, &release_callback));
  EXPECT_EQ(kSize, resource.size);
  std::move(release_callback).Run(gpu::SyncToken(), false /* lostResource */);
}

TEST_F(WebGPUSwapBufferProviderTest, VerifyInsertAndWaitSyncTokenCorrectly) {
  const gfx::Size kSize(10, 10);

  viz::TransferableResource resource;
  viz::ReleaseCallback release_callback;

  // Produce the first resource, check that WebGPU will wait for the creation of
  // the shared image
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);
  EXPECT_EQ(sii_->MostRecentGeneratedToken(),
            webgpu_->most_recent_waited_token);

  // WebGPU should produce a token so that the next of user of the resource can
  // synchronize properly
  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource, &release_callback));
  EXPECT_EQ(webgpu_->most_recent_generated_token, resource.sync_token());

  // Check that the release token is used to synchronize the shared image
  // destruction
  gpu::SyncToken release_token;
  webgpu_->GenSyncTokenCHROMIUM(release_token.GetData());
  std::move(release_callback).Run(release_token, false /* lostResource */);

  // Release the unused swap buffers held by the provider.
  provider_ = nullptr;

  EXPECT_EQ(sii_->MostRecentDestroyToken(), release_token);
}

// Ensures swap buffers will be recycled.
// Creates two swap buffers, destroys them, then creates them again.
TEST_F(WebGPUSwapBufferProviderTest, ReuseSwapBuffers) {
  const gfx::Size kSize(10, 10);

  base::flat_set<gpu::Mailbox> shared_images = {};

  viz::TransferableResource resource;

  // Produce some swap buffers
  viz::ReleaseCallback release_callback_0;
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);

  EXPECT_TRUE(
      shared_images.insert(provider_->GetCurrentMailboxForTesting()).second);

  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource, &release_callback_0));

  viz::ReleaseCallback release_callback_1;
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);

  EXPECT_TRUE(
      shared_images.insert(provider_->GetCurrentMailboxForTesting()).second);

  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource, &release_callback_1));

  viz::ReleaseCallback release_callback_2;
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);

  EXPECT_TRUE(
      shared_images.insert(provider_->GetCurrentMailboxForTesting()).second);

  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource, &release_callback_2));

  // Destroy the swap buffers.
  std::move(release_callback_0).Run(gpu::SyncToken(), false /* lostResource */);
  std::move(release_callback_1).Run(gpu::SyncToken(), false /* lostResource */);
  std::move(release_callback_2).Run(gpu::SyncToken(), false /* lostResource */);

  // Produce two swap buffers
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);

  EXPECT_FALSE(
      shared_images.insert(provider_->GetCurrentMailboxForTesting()).second);

  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource, &release_callback_1));

  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);

  EXPECT_FALSE(
      shared_images.insert(provider_->GetCurrentMailboxForTesting()).second);

  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource, &release_callback_2));
}

// Ensures swap buffers will NOT be recycled if resized.
// Creates two swap buffers of a size, destroys them, then creates them again
// with a different size.
TEST_F(WebGPUSwapBufferProviderTest, ReuseSwapBufferResize) {
  base::flat_set<gpu::Mailbox> shared_images = {};

  viz::TransferableResource resource;

  // Create swap buffers
  const gfx::Size kSize(10, 10);

  viz::ReleaseCallback release_callback_1;
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);

  EXPECT_TRUE(
      shared_images.insert(provider_->GetCurrentMailboxForTesting()).second);

  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource, &release_callback_1));

  viz::ReleaseCallback release_callback_2;
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);

  EXPECT_TRUE(
      shared_images.insert(provider_->GetCurrentMailboxForTesting()).second);

  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource, &release_callback_2));

  // Destroy swap buffers
  std::move(release_callback_1).Run(gpu::SyncToken(), false /* lostResource */);
  std::move(release_callback_2).Run(gpu::SyncToken(), false /* lostResource */);

  // Create swap buffers again with different size.
  const gfx::Size kOtherSize(20, 20);

  viz::ReleaseCallback release_callback_3;
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kOtherSize);

  EXPECT_TRUE(
      shared_images.insert(provider_->GetCurrentMailboxForTesting()).second);

  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource, &release_callback_3));

  viz::ReleaseCallback release_callback_4;
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kOtherSize);

  EXPECT_TRUE(
      shared_images.insert(provider_->GetCurrentMailboxForTesting()).second);

  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource, &release_callback_4));
}

// Regression test for crbug.com/1236418 where calling
// PrepareTransferableResource twice after the context is destroyed would hit a
// DCHECK.
TEST_F(WebGPUSwapBufferProviderTest,
       PrepareTransferableResourceTwiceAfterDestroy) {
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(gfx::Size(10, 10));

  dawn_control_client_->Destroy();

  viz::TransferableResource resource;
  viz::ReleaseCallback release_callback_1;
  EXPECT_FALSE(
      provider_->PrepareTransferableResource(&resource, &release_callback_1));

  viz::ReleaseCallback release_callback_2;
  EXPECT_FALSE(
      provider_->PrepareTransferableResource(&resource, &release_callback_2));
}

// Test that checks mailbox is dissociated when Neuter() is called.
TEST_F(WebGPUSwapBufferProviderTest, VerifyMailboxDissociationOnNeuter) {
  const gfx::Size kSize(10, 10);

  viz::TransferableResource resource1;
  viz::ReleaseCallback release_callback1;

  viz::TransferableResource resource2;
  viz::ReleaseCallback release_callback2;

  // Produce and prepare transferable resource
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);
  EXPECT_EQ(webgpu_->num_associated_mailboxes, 1);

  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource1, &release_callback1));
  EXPECT_EQ(webgpu_->num_associated_mailboxes, 0);

  // Produce 2nd resource but this time neuters the provider. Mailbox must also
  // be dissociated.
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);
  EXPECT_EQ(webgpu_->num_associated_mailboxes, 1);

  provider_->Neuter();
  EXPECT_EQ(webgpu_->num_associated_mailboxes, 0);
}

// Test that checks mailbox is not dissociated twice when both
// PrepareTransferableResource() and Neuter() are called.
TEST_F(WebGPUSwapBufferProviderTest, VerifyNoDoubleMailboxDissociation) {
  const gfx::Size kSize(10, 10);

  viz::TransferableResource resource1;
  viz::ReleaseCallback release_callback1;

  // Produce and prepare transferable resource
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(
          Invoke([&](WGPUDevice device, const WGPUTextureDescriptor* desc) {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);
  EXPECT_EQ(webgpu_->num_associated_mailboxes, 1);

  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource1, &release_callback1));
  EXPECT_EQ(webgpu_->num_associated_mailboxes, 0);

  // Calling Neuter() won't dissociate mailbox again.
  provider_->Neuter();
  EXPECT_EQ(webgpu_->num_associated_mailboxes, 0);
}

TEST_F(WebGPUSwapBufferProviderTest, ReserveTextureDescriptorForReflection) {
  const gfx::Size kSize(10, 10);
  const gfx::Size kOtherSize(20, 20);

  viz::TransferableResource resource;
  viz::ReleaseCallback release_callback;

  // Produce one resource of size kSize and check that the descriptor passed to
  // ReserveTexture is correct..
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(Invoke(
          [&](WGPUDevice device, const WGPUTextureDescriptor* desc) -> auto {
            EXPECT_NE(desc, nullptr);
            EXPECT_EQ(desc->size.width, static_cast<uint32_t>(kSize.width()));
            EXPECT_EQ(desc->size.height, static_cast<uint32_t>(kSize.height()));
            EXPECT_EQ(desc->size.depthOrArrayLayers, 1u);
            EXPECT_EQ(desc->format, static_cast<WGPUTextureFormat>(kFormat));
            EXPECT_EQ(desc->usage, static_cast<WGPUTextureUsage>(kUsage));
            EXPECT_EQ(desc->dimension, WGPUTextureDimension_2D);
            EXPECT_EQ(desc->mipLevelCount, 1u);
            EXPECT_EQ(desc->sampleCount, 1u);
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);
  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource, &release_callback));
  EXPECT_EQ(kSize, resource.size);
  std::move(release_callback).Run(gpu::SyncToken(), false /* lostResource */);

  // Produce one resource of size kOtherSize. The descriptor passed to
  // ReserveTexture is updated accordingly.
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(Invoke([&](WGPUDevice device,
                           const WGPUTextureDescriptor* desc) -> auto {
        EXPECT_EQ(desc->size.width, static_cast<uint32_t>(kOtherSize.width()));
        EXPECT_EQ(desc->size.height,
                  static_cast<uint32_t>(kOtherSize.height()));
        return ReserveTextureImpl(device, desc);
      }));
  provider_->GetNewTexture(kOtherSize);
  EXPECT_TRUE(
      provider_->PrepareTransferableResource(&resource, &release_callback));
  EXPECT_EQ(kOtherSize, resource.size);
  std::move(release_callback).Run(gpu::SyncToken(), false /* lostResource */);
}

// Ensures that requests for zero size textures (width == 0 or height == 0) do
// not attempt to reserve a texture.
TEST_F(WebGPUSwapBufferProviderTest, VerifyZeroSizeRejects) {
  const gfx::Size kZeroSize(0, 0);
  const gfx::Size kZeroWidth(0, 10);
  const gfx::Size kZeroHeight(10, 0);

  // None of these calls should result in ReserveTexture being called
  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _)).Times(0);

  EXPECT_EQ(nullptr, provider_->GetNewTexture(kZeroSize));
  EXPECT_EQ(nullptr, provider_->GetNewTexture(kZeroWidth));
  EXPECT_EQ(nullptr, provider_->GetNewTexture(kZeroHeight));
}

// Verifies that GetLastWebGPUMailboxTexture() returns empty information if no
// swapbuffer has been created.
TEST_F(WebGPUSwapBufferProviderTest,
       GetLastWebGPUMailboxTextureReturnsEmptyWithoutSwapBuffer) {
  auto mailbox_texture = provider_->GetLastWebGPUMailboxTexture();
  EXPECT_EQ(mailbox_texture, nullptr);
}

// Verifies that GetLastWebGPUMailboxTexture() returns a correctly-configured
// texture if a swapbuffer has been created.
TEST_F(WebGPUSwapBufferProviderTest,
       GetLastWebGPUMailboxTextureReturnsValidTextureWithSwapBuffer) {
  const gfx::Size kSize(10, 20);

  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillRepeatedly(Invoke(
          [&](WGPUDevice device, const WGPUTextureDescriptor* desc) -> auto {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);

  auto mailbox_texture = provider_->GetLastWebGPUMailboxTexture();
  EXPECT_NE(mailbox_texture, nullptr);

  auto texture = mailbox_texture->GetTexture();
  EXPECT_EQ(texture.GetUsage(), kUsage);
  EXPECT_EQ(texture.GetFormat(), kFormat);
  EXPECT_EQ(texture.GetDepthOrArrayLayers(), 1u);
  EXPECT_EQ(texture.GetDimension(), wgpu::TextureDimension::e2D);
  EXPECT_EQ(texture.GetMipLevelCount(), 1u);
  EXPECT_EQ(texture.GetSampleCount(), 1u);
  EXPECT_EQ(texture.GetHeight(), static_cast<uint32_t>(kSize.height()));
  EXPECT_EQ(texture.GetWidth(), static_cast<uint32_t>(kSize.width()));
}

// Verifies that GetNewTexture() passes client-specified internal usages to
// AssociateMailbox() and additionally adds RenderAttachment as an internal
// usage when associating the mailbox to ensure that lazy clearing is supported.
TEST_F(WebGPUSwapBufferProviderTest,
       GetNewTexturePassesClientSpecifiedInternalUsagePlusRenderAttachment) {
  ASSERT_EQ(kInternalUsage & wgpu::TextureUsage::RenderAttachment, 0);

  const gfx::Size kSize(10, 20);

  EXPECT_EQ(webgpu_->internal_usage_from_most_recent_associate_mailbox_call,
            wgpu::TextureUsage::None);

  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillOnce(Invoke(
          [&](WGPUDevice device, const WGPUTextureDescriptor* desc) -> auto {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);

  EXPECT_EQ(webgpu_->internal_usage_from_most_recent_associate_mailbox_call,
            kInternalUsage | wgpu::TextureUsage::RenderAttachment);
}

// Verifies that GetLastMailboxTexture() passes client-specified internal usages
// to AssociateMailbox() and doesn't additionally add RenderAttachment (since
// it does not instruct the decoder to do lazy clearing on this texture).
TEST_F(WebGPUSwapBufferProviderTest,
       GetLastMailboxTexturePassesClientSpecifiedInternalUsage) {
  ASSERT_EQ(kInternalUsage & wgpu::TextureUsage::RenderAttachment, 0);

  const gfx::Size kSize(10, 20);

  EXPECT_EQ(webgpu_->internal_usage_from_most_recent_associate_mailbox_call,
            wgpu::TextureUsage::None);

  EXPECT_CALL(*webgpu_, ReserveTexture(device_.Get(), _))
      .WillRepeatedly(Invoke(
          [&](WGPUDevice device, const WGPUTextureDescriptor* desc) -> auto {
            return ReserveTextureImpl(device, desc);
          }));
  provider_->GetNewTexture(kSize);

  provider_->GetLastWebGPUMailboxTexture();
  EXPECT_EQ(webgpu_->internal_usage_from_most_recent_associate_mailbox_call,
            kInternalUsage);
}

}  // namespace blink
```
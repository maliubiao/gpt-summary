Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The filename `heap_mojo_receiver_set_test.cc` immediately suggests this file tests the functionality of `HeapMojoReceiverSet`. The `_test.cc` suffix is a common convention for test files.

2. **Understand the Tested Class:** The `#include "third_party/blink/renderer/platform/mojo/heap_mojo_receiver_set.h"` confirms that we're examining tests for the `HeapMojoReceiverSet` class. We should mentally (or physically, if needed) note what this class likely does. Based on the name, it probably manages a set of Mojo receivers and has some interaction with the Blink heap (garbage collection).

3. **Look for Test Fixtures:** The code uses Google Test (`TEST_F`). The classes inheriting from `::testing::Test` (and in this case, a custom base `TestSupportingGC`) are test fixtures. These group related tests and often provide setup/teardown logic. We see several fixtures like `HeapMojoReceiverSetGCWithContextObserverTest`, `HeapMojoReceiverSetGCWithoutContextObserverTest`, etc. The naming suggests different scenarios related to garbage collection and context observers.

4. **Analyze Individual Tests:**  Examine each `TEST_F` function. What specific aspect of `HeapMojoReceiverSet` is being tested?

    * **`RemovesReceiver`:** Tests adding and then removing a receiver using `Add` and `Remove`.
    * **`NoClearOnConservativeGC`:** Explores the interaction with garbage collection. The name suggests it's verifying that a conservative GC doesn't prematurely clear something.
    * **`ClearLeavesSetEmpty`:** Checks if `Clear()` empties the receiver set.
    * **`AddSeveralReceiverSet`:**  Tests adding multiple receivers and verifying the size and `HasReceiver`.
    * **`AddSeveralReceiverSetWithContext`:** Similar to the above, but with context associated with the receivers.
    * **`Clear` (in DisconnectHandler test):** Focuses on the disconnect handler being triggered when `Clear()` is called.
    * **`ClearWithReason`:** Tests the `ClearWithReason` functionality and verifies the disconnect reason and description.

5. **Identify Key Concepts:** As you analyze the tests, look for recurring concepts:

    * **`HeapMojoReceiverSet`:** The central class under test.
    * **Mojo:**  The presence of `mojo::PendingReceiver`, `mojo::Remote`, and `.mojom-blink.h` files indicates interaction with the Mojo binding framework.
    * **Garbage Collection (GC):**  Terms like `ConservativelyCollectGarbage`, `PreciselyCollectGarbage`, and the `TestSupportingGC` base class highlight the importance of GC in these tests.
    * **Context Observers:** The different test fixture names (WithContextObserver, WithoutContextObserver) suggest different ways the `HeapMojoReceiverSet` interacts with context.
    * **Disconnect Handlers:**  The tests with "DisconnectHandler" in their names deal with what happens when a Mojo connection is closed.

6. **Infer Functionality of `HeapMojoReceiverSet`:** Based on the tests, we can deduce the core responsibilities of `HeapMojoReceiverSet`:

    * Manages a collection of Mojo receivers.
    * Allows adding and removing receivers.
    * Provides a way to clear all receivers.
    * Handles disconnections (potentially with reasons).
    * Interacts with Blink's garbage collection mechanism, possibly ensuring that receivers and associated resources are properly managed during GC.
    * Optionally associates context with receivers.

7. **Consider Relevance to Web Technologies (JavaScript, HTML, CSS):**  This is where we connect the low-level C++ code to higher-level web development concepts.

    * **Mojo Bindings:** Mojo is used for inter-process communication within Chromium. In Blink, it's a key mechanism for communication between the renderer process (where JavaScript, HTML, and CSS are processed) and other browser processes (like the browser process or utility processes).
    * **Receivers:** A receiver in Mojo handles incoming messages for a particular interface. In the context of a web page, a receiver might be handling requests from JavaScript to access browser features.
    * **Garbage Collection:**  JavaScript has its own garbage collection. Blink's GC interacts with the JavaScript heap to manage the lifetime of C++ objects that are exposed to JavaScript or are part of the rendering engine.

8. **Formulate Examples:**  Think of concrete scenarios where this C++ code might be relevant:

    * **JavaScript API:** Imagine a JavaScript API that allows fetching data from a remote server. The underlying implementation might use Mojo to communicate with a network service in another process. The `HeapMojoReceiverSet` could be used to manage the Mojo receivers for these network requests.
    * **Custom Elements/Web Components:**  If a custom element needs to interact with browser features, it might use Mojo interfaces. The `HeapMojoReceiverSet` could manage the connections for these interactions.

9. **Identify Potential User/Programming Errors:** Think about how a developer might misuse `HeapMojoReceiverSet` or related Mojo concepts:

    * **Forgetting to `Clear()`:**  If a `HeapMojoReceiverSet` isn't cleared properly, it could lead to resource leaks or unexpected behavior when the associated objects are no longer needed.
    * **Incorrect Disconnect Handling:**  Not setting or handling disconnect handlers correctly can lead to situations where the application doesn't react appropriately to connection closures.
    * **Lifetime Issues:**  If the owner of the `HeapMojoReceiverSet` is destroyed prematurely, it could lead to dangling pointers or use-after-free errors (though the GC helps mitigate this).

10. **Structure the Output:** Organize the findings into clear categories like "Functionality," "Relationship to Web Technologies," "Logic and Assumptions," and "Common Errors."  Use examples to illustrate the points.

This systematic approach allows you to dissect the C++ test file and understand its purpose, its connection to broader web development concepts, and potential pitfalls.
这个 C++ 文件 `heap_mojo_receiver_set_test.cc` 是 Chromium Blink 渲染引擎中的一个测试文件，专门用于测试 `HeapMojoReceiverSet` 类的功能。 `HeapMojoReceiverSet` 用于管理一组 Mojo 接收器（receivers），这些接收器与特定的垃圾回收（GC）生命周期相关联。

**主要功能:**

1. **管理 Mojo 接收器集合:**  `HeapMojoReceiverSet` 维护着一组实现了特定 Mojo 接口的对象（在本例中是 `sample::blink::Service`）。它允许添加、删除和遍历这些接收器。

2. **与 Blink 的垃圾回收集成:**  该类被设计成与 Blink 的垃圾回收机制协同工作。这意味着当持有 `HeapMojoReceiverSet` 的对象被垃圾回收时，`HeapMojoReceiverSet` 也会被适当地清理，相关的 Mojo 连接也会被关闭。

3. **支持上下文关联:**  一些测试表明 `HeapMojoReceiverSet` 可以与上下文信息关联（例如，`HeapMojoReceiverSetStringContextGCWithContextObserverTest`），这允许在管理接收器时使用额外的标识符。

4. **处理连接断开:**  测试涵盖了当 Mojo 连接断开时的情况，包括使用断开处理程序（disconnect handlers）来执行清理或其他操作。还可以设置带有原因的断开处理程序。

5. **不同的包装模式:**  测试中使用了不同的 `HeapMojoWrapperMode`，例如 `kWithContextObserver` 和 `kForceWithoutContextObserver`。这表明 `HeapMojoReceiverSet` 可能有不同的实现策略，以适应不同的使用场景和性能需求。

**与 JavaScript, HTML, CSS 的关系:**

`HeapMojoReceiverSet` 本身是一个底层的 C++ 类，并不直接处理 JavaScript, HTML 或 CSS 的语法和解析。然而，它在 Blink 渲染引擎的架构中扮演着重要的角色，使得 JavaScript 代码能够通过 Mojo 与浏览器或其他进程进行通信。

* **JavaScript 与 Mojo 通信:**  当 JavaScript 代码需要调用浏览器提供的某些功能（例如，访问设备 API，进行网络请求等）时，通常会通过 Mojo 接口进行。`HeapMojoReceiverSet` 可以用来管理渲染进程中接收这些来自其他进程的请求的接收器。

    **举例说明:** 假设一个 JavaScript 代码需要使用浏览器的地理位置 API：

    ```javascript
    navigator.geolocation.getCurrentPosition(successCallback, errorCallback);
    ```

    在底层，Blink 渲染引擎可能会通过 Mojo 向浏览器进程发送一个请求。浏览器进程会找到相应的 Mojo 接收器来处理这个请求。`HeapMojoReceiverSet` 可以用来管理这个接收器，确保当相关的 JavaScript 对象被垃圾回收时，Mojo 连接也能被适当地清理。

* **Web Components 和 Custom Elements:** 如果 Web Components 或 Custom Elements 需要与浏览器提供的服务进行交互，它们也可能通过 Mojo 进行通信。 `HeapMojoReceiverSet` 可以用来管理这些组件所持有的 Mojo 连接。

    **举例说明:**  一个自定义元素可能需要使用浏览器的存储 API 来持久化数据。这个自定义元素内部的 C++ 代码可能会使用 `HeapMojoReceiverSet` 来管理与存储服务之间的 Mojo 连接。

* **渲染过程中的进程间通信:**  Blink 渲染引擎是多进程架构，不同的功能可能由不同的进程负责。例如，渲染进程负责 HTML, CSS 和 JavaScript 的执行，而 GPU 进程负责图形渲染。`HeapMojoReceiverSet` 可以用来管理渲染进程中接收来自其他进程消息的接收器，例如来自 GPU 进程的渲染结果。

**逻辑推理和假设输入输出:**

**假设输入:**

1. 创建一个 `HeapMojoReceiverSet` 实例。
2. 创建一个实现了 `sample::blink::Service` 接口的对象。
3. 获取该对象的 `mojo::PendingReceiver<sample::blink::Service>`。
4. 使用 `Add` 方法将接收器添加到 `HeapMojoReceiverSet`。
5. 调用 `HasReceiver` 方法检查接收器是否存在。
6. 调用 `Remove` 方法移除接收器。
7. 再次调用 `HasReceiver` 方法检查接收器是否已被移除。

**预期输出:**

* 在 `Add` 之后，`HasReceiver` 返回 `true`。
* 在 `Remove` 之后，`HasReceiver` 返回 `false`。

**假设输入 (涉及 GC):**

1. 创建一个持有 `HeapMojoReceiverSet` 的垃圾回收对象 `GCOwner`。
2. 向 `HeapMojoReceiverSet` 添加一个接收器。
3. 将 `GCOwner` 对象置为可回收状态（例如，解除所有强引用）。
4. 触发垃圾回收。

**预期输出:**

* 在垃圾回收之后，与该接收器关联的 Mojo 连接应该被关闭（如果设置了断开处理程序，则会被触发）。
* `HeapMojoReceiverSet` 中不再包含该接收器。

**用户或编程常见的使用错误:**

1. **忘记移除或清理接收器:**  如果 `HeapMojoReceiverSet` 中的接收器没有在不再需要时被移除或清理，可能会导致资源泄漏，因为相关的 Mojo 连接会一直保持打开状态。

    **举例说明:**  一个 JavaScript 对象创建了一个与浏览器服务的 Mojo 连接，但是当该 JavaScript 对象不再使用时，底层的 C++ 代码没有清理 `HeapMojoReceiverSet` 中的接收器。这会导致即使 JavaScript 层面认为连接已关闭，但底层的 Mojo 连接仍然存在。

2. **在对象被销毁后访问 `HeapMojoReceiverSet`:** 如果尝试在一个已经销毁了其关联的 `GCOwner` 对象的 `HeapMojoReceiverSet` 上执行操作，会导致崩溃或未定义行为。

    **举例说明:**  `GCOwner` 对象被垃圾回收，但是仍然有其他代码持有对 `GCOwner` 中 `receiver_set_` 的引用，并在之后尝试调用 `receiver_set_.Clear()`。

3. **不正确地处理断开连接:**  如果应用程序依赖于 Mojo 连接的持久性，而没有正确设置和处理断开连接的情况，可能会导致应用程序在连接意外断开时出现错误。

    **举例说明:**  一个 Web Component 通过 Mojo 与一个后台服务通信获取数据。如果网络出现问题导致连接断开，但该 Web Component 没有设置断开处理程序来重新连接或通知用户，那么该组件可能会停留在错误状态。

4. **在错误的线程上操作 `HeapMojoReceiverSet`:** Mojo 有线程模型的要求，通常需要在创建接收器的线程上操作它们。在错误的线程上添加、删除或操作 `HeapMojoReceiverSet` 中的接收器可能会导致错误。

总而言之，`heap_mojo_receiver_set_test.cc` 文件通过各种测试用例，确保 `HeapMojoReceiverSet` 能够正确地管理 Mojo 接收器，并与 Blink 的垃圾回收机制以及 Mojo 的连接生命周期管理良好地集成，这对于构建稳定可靠的 Chromium 渲染引擎至关重要，也间接地影响着 Web 开发者编写的 JavaScript, HTML 和 CSS 代码的功能和性能。

Prompt: 
```
这是目录为blink/renderer/platform/mojo/heap_mojo_receiver_set_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/mojo/heap_mojo_receiver_set.h"

#include <string>
#include <utility>

#include "base/memory/raw_ptr.h"
#include "base/test/null_task_runner.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/interfaces/bindings/tests/sample_service.mojom-blink.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/context_lifecycle_notifier.h"
#include "third_party/blink/renderer/platform/heap/heap_test_utilities.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/heap_observer_list.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_wrapper_mode.h"
#include "third_party/blink/renderer/platform/mojo/mojo_binding_context.h"
#include "third_party/blink/renderer/platform/testing/mock_context_lifecycle_notifier.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

template <HeapMojoWrapperMode Mode, typename ContextType>
class HeapMojoReceiverSetGCBaseTest;

template <HeapMojoWrapperMode Mode, typename ContextType>
class GCOwner final : public GarbageCollected<GCOwner<Mode, ContextType>>,
                      public sample::blink::Service {
 public:
  explicit GCOwner(MockContextLifecycleNotifier* context,
                   HeapMojoReceiverSetGCBaseTest<Mode, ContextType>* test)
      : receiver_set_(this, context), test_(test) {
    test_->set_is_owner_alive(true);
  }
  void Dispose() { test_->set_is_owner_alive(false); }
  void Trace(Visitor* visitor) const { visitor->Trace(receiver_set_); }

  HeapMojoReceiverSet<sample::blink::Service, GCOwner, Mode, ContextType>&
  receiver_set() {
    return receiver_set_;
  }

  void Frobinate(sample::blink::FooPtr foo,
                 Service::BazOptions baz,
                 mojo::PendingRemote<sample::blink::Port> port,
                 FrobinateCallback callback) override {}
  void GetPort(mojo::PendingReceiver<sample::blink::Port> receiver) override {}

 private:
  HeapMojoReceiverSet<sample::blink::Service, GCOwner, Mode, ContextType>
      receiver_set_;
  raw_ptr<HeapMojoReceiverSetGCBaseTest<Mode, ContextType>> test_;
};

template <HeapMojoWrapperMode Mode, typename ContextType>
class HeapMojoReceiverSetGCBaseTest : public TestSupportingGC {
 public:
  MockContextLifecycleNotifier* context() { return context_; }
  scoped_refptr<base::NullTaskRunner> task_runner() {
    return null_task_runner_;
  }
  GCOwner<Mode, ContextType>* owner() { return owner_; }
  void set_is_owner_alive(bool alive) { is_owner_alive_ = alive; }

  void ClearOwner() { owner_ = nullptr; }

 protected:
  void SetUp() override {
    context_ = MakeGarbageCollected<MockContextLifecycleNotifier>();
    owner_ = MakeGarbageCollected<GCOwner<Mode, ContextType>>(context(), this);
  }
  void TearDown() override {
    owner_ = nullptr;
    PreciselyCollectGarbage();
  }

  Persistent<MockContextLifecycleNotifier> context_;
  Persistent<GCOwner<Mode, ContextType>> owner_;
  bool is_owner_alive_ = false;
  scoped_refptr<base::NullTaskRunner> null_task_runner_ =
      base::MakeRefCounted<base::NullTaskRunner>();
};

template <HeapMojoWrapperMode Mode, typename ContextType>
class HeapMojoReceiverSetDisconnectHandlerBaseTest
    : public HeapMojoReceiverSetGCBaseTest<Mode, ContextType> {
 public:
  base::RunLoop& run_loop() { return run_loop_; }
  bool& disconnected() { return disconnected_; }

 protected:
  void SetUp() override {
    this->context_ = MakeGarbageCollected<MockContextLifecycleNotifier>();
    this->owner_ =
        MakeGarbageCollected<GCOwner<Mode, ContextType>>(this->context(), this);

    mojo::PendingRemote<sample::blink::Service> pending_remote;
    this->owner_->receiver_set().Add(
        pending_remote.InitWithNewPipeAndPassReceiver(), this->task_runner());
    remote_.Bind(std::move(pending_remote));
    remote_.set_disconnect_handler(WTF::BindOnce(
        [](HeapMojoReceiverSetDisconnectHandlerBaseTest* receiver_set_test) {
          receiver_set_test->run_loop().Quit();
          receiver_set_test->disconnected() = true;
        },
        WTF::Unretained(this)));
  }

  base::RunLoop run_loop_;
  mojo::Remote<sample::blink::Service> remote_;
  bool disconnected_ = false;
};

template <HeapMojoWrapperMode Mode, typename ContextType>
class HeapMojoReceiverSetDisconnectWithReasonHandlerBaseTest
    : public HeapMojoReceiverSetDisconnectHandlerBaseTest<Mode, ContextType> {
 public:
  std::optional<uint32_t>& disconnected_reason_code() {
    return disconnected_reason_code_;
  }
  std::optional<std::string>& disconnected_description() {
    return disconnected_description_;
  }

 protected:
  void SetUp() override {
    this->context_ = MakeGarbageCollected<MockContextLifecycleNotifier>();
    this->owner_ =
        MakeGarbageCollected<GCOwner<Mode, ContextType>>(this->context(), this);

    mojo::PendingRemote<sample::blink::Service> pending_remote;
    this->owner_->receiver_set().Add(
        pending_remote.InitWithNewPipeAndPassReceiver(), this->task_runner());
    this->remote_.Bind(std::move(pending_remote));
    this->remote_.set_disconnect_with_reason_handler(WTF::BindOnce(
        [](HeapMojoReceiverSetDisconnectWithReasonHandlerBaseTest*
               receiver_set_test,
           const uint32_t custom_reason, const std::string& description) {
          receiver_set_test->run_loop().Quit();
          receiver_set_test->disconnected_reason_code() = custom_reason;
          receiver_set_test->disconnected_description() = description;
        },
        WTF::Unretained(this)));
  }

  std::optional<uint32_t> disconnected_reason_code_;
  std::optional<std::string> disconnected_description_;
};

}  // namespace

class HeapMojoReceiverSetGCWithContextObserverTest
    : public HeapMojoReceiverSetGCBaseTest<
          HeapMojoWrapperMode::kWithContextObserver,
          void> {};
class HeapMojoReceiverSetStringContextGCWithContextObserverTest
    : public HeapMojoReceiverSetGCBaseTest<
          HeapMojoWrapperMode::kWithContextObserver,
          std::string> {};
class HeapMojoReceiverSetGCWithoutContextObserverTest
    : public HeapMojoReceiverSetGCBaseTest<
          HeapMojoWrapperMode::kForceWithoutContextObserver,
          void> {};
class HeapMojoReceiverSetDisconnectHandlerWithoutContextObserverTest
    : public HeapMojoReceiverSetDisconnectHandlerBaseTest<
          HeapMojoWrapperMode::kForceWithoutContextObserver,
          void> {};
class HeapMojoReceiverSetDisconnectWithReasonHandlerWithoutContextObserverTest
    : public HeapMojoReceiverSetDisconnectWithReasonHandlerBaseTest<
          HeapMojoWrapperMode::kForceWithoutContextObserver,
          void> {};

// GC the HeapMojoReceiverSet with context observer and verify that the receiver
// is no longer part of the set, and that the service was deleted.
TEST_F(HeapMojoReceiverSetGCWithContextObserverTest, RemovesReceiver) {
  auto& receiver_set = owner()->receiver_set();
  auto receiver = mojo::PendingReceiver<sample::blink::Service>(
      mojo::MessagePipe().handle0);

  mojo::ReceiverId rid = receiver_set.Add(std::move(receiver), task_runner());
  EXPECT_TRUE(receiver_set.HasReceiver(rid));

  receiver_set.Remove(rid);

  EXPECT_FALSE(receiver_set.HasReceiver(rid));
}

// Check that the wrapper does not outlive the owner when ConservativeGC finds
// the wrapper.
TEST_F(HeapMojoReceiverSetGCWithContextObserverTest, NoClearOnConservativeGC) {
  auto* wrapper = owner_->receiver_set().wrapper_.Get();

  auto receiver = mojo::PendingReceiver<sample::blink::Service>(
      mojo::MessagePipe().handle0);

  mojo::ReceiverId rid =
      owner()->receiver_set().Add(std::move(receiver), task_runner());
  EXPECT_TRUE(wrapper->receiver_set().HasReceiver(rid));

  ClearOwner();
  EXPECT_TRUE(is_owner_alive_);

  ConservativelyCollectGarbage();

  EXPECT_TRUE(wrapper->receiver_set().HasReceiver(rid));
  EXPECT_TRUE(is_owner_alive_);
}

// GC the HeapMojoReceiverSet without context observer and verify that the
// receiver is no longer part of the set, and that the service was deleted.
TEST_F(HeapMojoReceiverSetGCWithoutContextObserverTest, RemovesReceiver) {
  auto& receiver_set = owner()->receiver_set();
  auto receiver = mojo::PendingReceiver<sample::blink::Service>(
      mojo::MessagePipe().handle0);

  mojo::ReceiverId rid = receiver_set.Add(std::move(receiver), task_runner());
  EXPECT_TRUE(receiver_set.HasReceiver(rid));

  receiver_set.Remove(rid);

  EXPECT_FALSE(receiver_set.HasReceiver(rid));
}

// GC the HeapMojoReceiverSet with context observer and verify that the receiver
// is no longer part of the set, and that the service was deleted.
TEST_F(HeapMojoReceiverSetGCWithContextObserverTest, ClearLeavesSetEmpty) {
  auto& receiver_set = owner()->receiver_set();
  auto receiver = mojo::PendingReceiver<sample::blink::Service>(
      mojo::MessagePipe().handle0);

  mojo::ReceiverId rid = receiver_set.Add(std::move(receiver), task_runner());
  EXPECT_TRUE(receiver_set.HasReceiver(rid));

  receiver_set.Clear();

  EXPECT_FALSE(receiver_set.HasReceiver(rid));
}

// GC the HeapMojoReceiverSet without context observer and verify that the
// receiver is no longer part of the set, and that the service was deleted.
TEST_F(HeapMojoReceiverSetGCWithoutContextObserverTest, ClearLeavesSetEmpty) {
  auto& receiver_set = owner()->receiver_set();
  auto receiver = mojo::PendingReceiver<sample::blink::Service>(
      mojo::MessagePipe().handle0);

  mojo::ReceiverId rid = receiver_set.Add(std::move(receiver), task_runner());
  EXPECT_TRUE(receiver_set.HasReceiver(rid));

  receiver_set.Clear();

  EXPECT_FALSE(receiver_set.HasReceiver(rid));
}

// Add several receiver and confirm that receiver_set holds properly.
TEST_F(HeapMojoReceiverSetGCWithContextObserverTest, AddSeveralReceiverSet) {
  auto& receiver_set = owner()->receiver_set();

  EXPECT_TRUE(receiver_set.empty());
  EXPECT_EQ(receiver_set.size(), 0u);

  auto receiver_1 = mojo::PendingReceiver<sample::blink::Service>(
      mojo::MessagePipe().handle0);
  mojo::ReceiverId rid_1 =
      receiver_set.Add(std::move(receiver_1), task_runner());
  EXPECT_TRUE(receiver_set.HasReceiver(rid_1));
  EXPECT_FALSE(receiver_set.empty());
  EXPECT_EQ(receiver_set.size(), 1u);

  auto receiver_2 = mojo::PendingReceiver<sample::blink::Service>(
      mojo::MessagePipe().handle0);
  mojo::ReceiverId rid_2 =
      receiver_set.Add(std::move(receiver_2), task_runner());
  EXPECT_TRUE(receiver_set.HasReceiver(rid_1));
  EXPECT_TRUE(receiver_set.HasReceiver(rid_2));
  EXPECT_FALSE(receiver_set.empty());
  EXPECT_EQ(receiver_set.size(), 2u);

  receiver_set.Clear();

  EXPECT_FALSE(receiver_set.HasReceiver(rid_1));
  EXPECT_FALSE(receiver_set.HasReceiver(rid_2));
  EXPECT_TRUE(receiver_set.empty());
  EXPECT_EQ(receiver_set.size(), 0u);
}

// Add several receiver with context and confirm that receiver_set holds
// properly.
TEST_F(HeapMojoReceiverSetStringContextGCWithContextObserverTest,
       AddSeveralReceiverSetWithContext) {
  auto& receiver_set = owner()->receiver_set();

  EXPECT_TRUE(receiver_set.empty());
  EXPECT_EQ(receiver_set.size(), 0u);

  auto receiver_1 = mojo::PendingReceiver<sample::blink::Service>(
      mojo::MessagePipe().handle0);
  mojo::ReceiverId rid_1 = receiver_set.Add(
      std::move(receiver_1), std::string("context1"), task_runner());
  EXPECT_TRUE(receiver_set.HasReceiver(rid_1));
  EXPECT_FALSE(receiver_set.empty());
  EXPECT_EQ(receiver_set.size(), 1u);

  auto receiver_2 = mojo::PendingReceiver<sample::blink::Service>(
      mojo::MessagePipe().handle0);
  mojo::ReceiverId rid_2 = receiver_set.Add(
      std::move(receiver_2), std::string("context2"), task_runner());
  EXPECT_TRUE(receiver_set.HasReceiver(rid_1));
  EXPECT_TRUE(receiver_set.HasReceiver(rid_2));
  EXPECT_FALSE(receiver_set.empty());
  EXPECT_EQ(receiver_set.size(), 2u);

  receiver_set.Clear();

  EXPECT_FALSE(receiver_set.HasReceiver(rid_1));
  EXPECT_FALSE(receiver_set.HasReceiver(rid_2));
  EXPECT_TRUE(receiver_set.empty());
  EXPECT_EQ(receiver_set.size(), 0u);
}

// Clear the receiver set and check that the specified handler is fired.
TEST_F(HeapMojoReceiverSetDisconnectHandlerWithoutContextObserverTest, Clear) {
  ASSERT_FALSE(disconnected());

  owner()->receiver_set().Clear();
  run_loop().Run();

  EXPECT_TRUE(disconnected());
}

// Clear the receiver set with custom reason and check that the specified
// handler is fired.
TEST_F(HeapMojoReceiverSetDisconnectWithReasonHandlerWithoutContextObserverTest,
       ClearWithReason) {
  const std::string message = "test message";
  const uint32_t reason = 15;

  ASSERT_FALSE(disconnected_reason_code().has_value());
  ASSERT_FALSE(disconnected_description().has_value());

  owner()->receiver_set().ClearWithReason(reason, message);
  run_loop().Run();

  EXPECT_EQ(disconnected_reason_code(), reason);
  EXPECT_EQ(disconnected_description(), message);
}

}  // namespace blink

"""

```
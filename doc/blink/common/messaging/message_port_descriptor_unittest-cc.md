Response: Let's break down the thought process for analyzing this C++ unittest file.

**1. Initial Understanding: The Basics**

* **File Location:** `blink/common/messaging/message_port_descriptor_unittest.cc` immediately tells us this is a unit test file for a class named `MessagePortDescriptor` located in the `blink` (Chromium's rendering engine) and specifically the `common/messaging` directory. This suggests it deals with inter-process or inter-thread communication mechanisms within the rendering engine.
* **Unittest:** The `_unittest.cc` suffix is a strong indicator of a test file. We expect to see `TEST()` macros and assertions (`EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `EXPECT_DCHECK_DEATH`).
* **Includes:**  The `#include` directives point to key dependencies:
    * `message_port_descriptor.h`: The header file for the class being tested. This is crucial.
    * `base/test/gtest_util.h`: Utilities for Google Test, particularly `EXPECT_DCHECK_DEATH` for testing `DCHECK` assertions.
    * `testing/gmock/include/gmock/gmock.h`: Google Mock for creating mock objects. This suggests the class interacts with other components.
    * `testing/gtest/include/gtest/gtest.h`: The core Google Test framework.

**2. Identifying the Core Functionality Being Tested**

* **Test Case Names:** The `TEST()` macros provide high-level information about what's being tested:
    * `InstrumentationAndSerializationWorks`:  Indicates testing of logging/monitoring (`Instrumentation`) and how the `MessagePortDescriptor` is converted to/from a serializable format.
    * `InvalidUsageInstrumentationDelegate`: Focuses on testing how the `InstrumentationDelegate` is used and what happens with incorrect usage (specifically around `SetInstrumentationDelegate`). The `DeathTest` suffix further emphasizes this.
    * `InvalidUsageForSerialization`: Tests incorrect ways of serializing and deserializing the `MessagePortDescriptor`. The `DeathTest` suffix again highlights expected crashes due to `DCHECK`s.
    * `InvalidUsageForEntangling`: Tests invalid operations related to "entangling" a message port, likely connecting it to some underlying communication channel. The `DeathTest` suffix remains important.

**3. Deep Dive into `InstrumentationAndSerializationWorks`**

* **Mocking:** The `MockInstrumentationDelegate` and `LenientMockInstrumentationDelegate` are central. This tells us that the `MessagePortDescriptor` has a mechanism to notify external components about its lifecycle events. The `MOCK_METHOD` calls define the methods that are expected to be called.
* **Lifecycle Events:** The mocked methods (`NotifyMessagePortPairCreated`, `NotifyMessagePortAttached`, `NotifyMessagePortDetached`, `NotifyMessagePortDestroyed`) reveal the key lifecycle stages of a message port.
* **Serialization:** The test manipulates `MessagePortDescriptorPair` and uses `TakePort0()`, `TakePort1()`. This strongly suggests that message ports often come in pairs. The assertions about `IsValid()`, `IsEntangled()`, and `IsDefault()` track the state transitions of the ports. The interaction with `TakeHandleToEntangle` and `GiveDisentangledHandle` demonstrates how a port gets connected and disconnected from its underlying communication mechanism.
* **Sequence Numbers and IDs:** The test checks `created_data.token0`, `created_data.token1`, `created_data.seq0`, and `created_data.seq1`. This highlights the importance of unique identifiers and sequence numbers for tracking message ports.

**4. Analyzing the `DeathTest` Cases**

* **`InvalidUsageInstrumentationDelegate`:** The focus here is on the `SetInstrumentationDelegate` method and how it should *not* be called with `nullptr` after a delegate has been set, or with multiple different delegates. This indicates the delegate is likely a singleton or a globally managed resource.
* **`InvalidUsageForSerialization`:** The repeated calls to `TakeHandleForSerialization()`, `TakeIdForSerialization()`, `TakeSequenceNumberForSerialization()` followed by `EXPECT_DCHECK_DEATH` suggest that these actions are meant to be performed only once as part of a serialization process. The `InitializeFromSerializedValues` tests different combinations of valid and invalid serialized data, verifying error handling during deserialization.
* **`InvalidUsageForEntangling`:** The calls to `TakeHandleToEntangleWithEmbedder()` and then subsequent attempts to entangle or reset the port, coupled with `EXPECT_DCHECK_DEATH`, indicate that entangling is a one-time operation, and certain actions are invalid once a port is entangled.

**5. Connecting to Web Concepts (as requested by the prompt)**

* **JavaScript `MessageChannel`:**  The concept of message port pairs (`MessagePortDescriptorPair`) directly maps to the JavaScript `MessageChannel` API. A `MessageChannel` creates two entangled ports that can be used for communication between different scripts or contexts (e.g., iframes, web workers).
* **`postMessage()`:** The act of "entangling" a port likely corresponds to setting up the underlying communication channel used when `postMessage()` is called on a `MessagePort`. Serialization is necessary when transferring these ports across process boundaries.
* **Iframes and Web Workers:** The need for inter-context communication is fundamental to how web pages are structured and how background tasks are handled using web workers. `MessagePortDescriptor` is a low-level mechanism enabling this.

**6. Formulating the Answer**

Based on the above analysis, we can structure the answer to address the prompt's specific questions:

* **Functionality:** Summarize the core purpose of `MessagePortDescriptor` (representing message ports) and the testing focus (instrumentation, serialization, valid usage).
* **Relationship to JavaScript/HTML/CSS:** Explicitly connect `MessagePortDescriptor` to the `MessageChannel` API and its role in `postMessage()` for cross-context communication. Give examples like iframes and web workers. Mention that CSS is not directly related.
* **Logical Reasoning (Assumptions/Inputs/Outputs):**  For the "Instrumentation" part, describe a scenario (creating a port pair, attaching, detaching, destroying) and predict the sequence of calls to the mock delegate. For "Serialization," illustrate the process of taking the handle, ID, and sequence number, and the expected behavior with valid and invalid deserialization attempts. For "Entangling," show the attempt to entangle multiple times and the expected `DCHECK_DEATH`.
* **Common Usage Errors:**  Focus on the errors highlighted by the `DeathTest` cases: double-setting the instrumentation delegate, incorrect serialization/deserialization sequences, and invalid operations on entangled ports.

**Self-Correction/Refinement during the thought process:**

* Initially, I might just focus on the code structure. However, realizing the prompt asks for connections to web technologies forces a shift to consider the higher-level purpose.
* The "DeathTest" naming convention is a key hint about the nature of the tested errors.
*  It's important to connect the C++ class names and concepts to their corresponding JavaScript equivalents to make the explanation more accessible.
*  Providing concrete examples of when these errors might occur in a web development context makes the answer more practical.
这个 `blink/common/messaging/message_port_descriptor_unittest.cc` 文件是 Chromium Blink 引擎中 `MessagePortDescriptor` 类的单元测试文件。它的主要功能是 **验证 `MessagePortDescriptor` 类的正确性和可靠性**。

具体来说，这个测试文件涵盖了以下几个方面的功能：

**1. `MessagePortDescriptor` 的基本操作:**

* **创建和销毁:** 测试 `MessagePortDescriptor` 对象的创建 (包括通过 `MessagePortDescriptorPair`) 和销毁。
* **状态管理:**  验证 `IsValid()`, `IsEntangled()`, `IsDefault()` 等方法是否能正确反映 `MessagePortDescriptor` 的状态。例如，一个新创建的端口应该是有效的 (`IsValid()`) 且默认的 (`IsDefault()`)，但未纠缠 (`IsEntangled()`).
* **纠缠 (Entangling) 和解开 (Disentangling):** 测试将 `MessagePortDescriptor` 与底层消息管道关联 (`TakeHandleToEntangle`, `TakeHandleToEntangleWithEmbedder`) 和解除关联 (`GiveDisentangledHandle`) 的操作。

**2. Instrumentation (监控):**

* **测试监控回调:**  `MessagePortDescriptor` 提供了一个 `InstrumentationDelegate` 接口，用于在消息端口的生命周期中进行监控。这个测试文件使用了 `MockInstrumentationDelegate` 来模拟这个委托，并验证在端口创建、附加、分离和销毁时，是否会调用相应的委托方法，并且参数是否正确。

**3. 序列化和反序列化:**

* **测试序列化相关方法:**  验证用于序列化 `MessagePortDescriptor` 状态的方法，例如 `TakeHandleForSerialization()`, `TakeIdForSerialization()`, `TakeSequenceNumberForSerialization()`。
* **测试反序列化:** 验证通过 `InitializeFromSerializedValues()` 方法能否正确地从序列化的数据中恢复 `MessagePortDescriptor` 的状态。

**与 JavaScript, HTML, CSS 的关系 (间接):**

`MessagePortDescriptor` 是 Blink 引擎内部用于实现消息传递机制的关键组件。它与 JavaScript 中的 `MessageChannel` 和 `MessagePort` API 有着密切的关系。

* **JavaScript `MessageChannel`:**  当 JavaScript 代码创建一个 `MessageChannel` 对象时，Blink 引擎会在底层创建一对 `MessagePortDescriptor` 对象。这两个 `MessagePortDescriptor` 对象分别代表 `MessageChannel` 的 `port1` 和 `port2` 属性。
* **JavaScript `postMessage()`:**  当 JavaScript 代码在一个 `MessagePort` 上调用 `postMessage()` 方法发送消息时，Blink 引擎会使用与该 `MessagePort` 关联的 `MessagePortDescriptor` 来处理消息的路由和传递。
* **跨文档/跨上下文通信:** `MessagePortDescriptor` 是实现跨文档（例如 iframe 之间）或跨上下文（例如主线程和 Web Worker 之间）通信的关键。

**举例说明:**

假设一个网页中包含一个 iframe。以下是 `MessagePortDescriptor` 如何参与其中的一个例子：

1. **JavaScript 创建 `MessageChannel`:**  主页面或 iframe 中的 JavaScript 代码创建一个 `MessageChannel` 对象：
   ```javascript
   const channel = new MessageChannel();
   const port1 = channel.port1;
   const port2 = channel.port2;
   ```
2. **Blink 内部创建 `MessagePortDescriptor`:**  Blink 引擎会创建两个 `MessagePortDescriptor` 对象，分别对应 `port1` 和 `port2`。单元测试中的 `MessagePortDescriptorPair` 就是模拟了这个过程。
3. **传递端口:**  主页面可以将 `port2` 传递给 iframe：
   ```javascript
   iframeElement.contentWindow.postMessage(port2, '*', [port2]);
   ```
4. **Blink 内部处理传递:**  Blink 引擎会序列化与 `port2` 关联的 `MessagePortDescriptor`，并通过进程间通信（IPC）将其传递给 iframe 所在的渲染进程。
5. **iframe 接收端口:** iframe 的 JavaScript 代码接收到传递的 `port2`：
   ```javascript
   navigator.serviceWorker.addEventListener('message', event => {
     const receivedPort = event.ports[0];
     // ... 使用 receivedPort 进行通信
   });
   ```
6. **Blink 内部反序列化:** iframe 渲染进程中的 Blink 引擎会反序列化接收到的数据，重新创建 `MessagePortDescriptor` 对象。
7. **使用端口通信:**  主页面和 iframe 可以通过各自的端口使用 `postMessage()` 进行双向通信。Blink 引擎会使用底层的 `MessagePortDescriptor` 来路由和传递消息。

**逻辑推理与假设输入输出:**

**测试用例: `InstrumentationAndSerializationWorks`**

* **假设输入:**  调用 `MessagePortDescriptorPair()` 创建一对端口描述符。然后分别通过 `TakePort0()` 和 `TakePort1()` 获取两个独立的 `MessagePortDescriptor` 对象。接着模拟附加 (entangle) 和分离 (disentangle) 其中一个端口，最后销毁两个端口。
* **预期输出:**
    * 在创建端口对时，`MockInstrumentationDelegate` 的 `NotifyMessagePortPairCreated` 方法会被调用，并携带两个新创建的端口的 ID。
    * 当一个端口被附加时，`NotifyMessagePortAttached` 方法会被调用，并携带端口的 ID、序列号和执行上下文。
    * 当一个端口被分离时，`NotifyMessagePortDetached` 方法会被调用，并携带端口的 ID 和序列号.
    * 当端口被销毁时，`NotifyMessagePortDestroyed` 方法会被调用，并携带端口的 ID 和序列号。
    * 在整个过程中，`MessagePortDescriptor` 的 `IsValid()`, `IsEntangled()`, `IsDefault()` 等方法会返回符合预期的状态。

**测试用例: `InvalidUsageForSerialization`**

* **假设输入:**  尝试对一个默认状态的 `MessagePortDescriptor` 调用序列化相关的方法 (例如 `TakeHandleForSerialization()`).
* **预期输出:**  由于这是无效的操作，测试会使用 `EXPECT_DCHECK_DEATH` 来断言程序会因为 DCHECK 失败而终止。DCHECK 是 Chromium 中用于在开发阶段检测逻辑错误的宏。

**用户或编程常见的使用错误举例:**

* **多次调用序列化方法:** 程序员可能会错误地多次调用 `TakeHandleForSerialization()` 或其他序列化方法。`MessagePortDescriptor` 的设计要求这些方法只能被调用一次，多次调用会导致未定义的行为或崩溃。测试用例 `InvalidUsageForSerialization` 就覆盖了这种情况，并使用 `DCHECK` 来防止这种错误在发布版本中发生。
* **在端口纠缠后尝试序列化:**  一旦一个 `MessagePortDescriptor` 被纠缠（例如，通过 `TakeHandleToEntangle()` 获取了底层管道），它就不能再被序列化。尝试这样做会导致错误。测试用例 `InvalidUsageForEntangling` 验证了这一点。
* **错误地管理 `InstrumentationDelegate`:**  程序员可能会尝试多次设置 `InstrumentationDelegate`，或者在已经设置了委托的情况下再次设置为空。测试用例 `InvalidUsageInstrumentationDelegate` 检查了这些错误用法。

总而言之，`blink/common/messaging/message_port_descriptor_unittest.cc` 通过各种测试用例，确保 `MessagePortDescriptor` 类能够正确地管理消息端口的状态、进行监控，并支持可靠的序列化和反序列化，从而保证了 Blink 引擎中消息传递机制的稳定性和可靠性。这对于实现 Web 平台的跨文档和跨上下文通信至关重要。

### 提示词
```
这是目录为blink/common/messaging/message_port_descriptor_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/messaging/message_port_descriptor.h"

#include "base/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace blink {

namespace {

ExecutionContext* kDummyEc = reinterpret_cast<ExecutionContext*>(0xBAADF00D);

class LenientMockInstrumentationDelegate
    : public MessagePortDescriptor::InstrumentationDelegate {
 public:
  LenientMockInstrumentationDelegate() {
    MessagePortDescriptor::SetInstrumentationDelegate(this);
  }

  ~LenientMockInstrumentationDelegate() override {
    MessagePortDescriptor::SetInstrumentationDelegate(nullptr);
  }

  MOCK_METHOD2(NotifyMessagePortPairCreated,
               void(const base::UnguessableToken& port0_id,
                    const base::UnguessableToken& port1_id));

  MOCK_METHOD3(NotifyMessagePortAttached,
               void(const base::UnguessableToken& port_id,
                    uint64_t sequence_number,
                    ExecutionContext* execution_context));

  MOCK_METHOD2(NotifyMessagePortAttachedToEmbedder,
               void(const base::UnguessableToken& port_id,
                    uint64_t sequence_number));

  MOCK_METHOD2(NotifyMessagePortDetached,
               void(const base::UnguessableToken& port_id,
                    uint64_t sequence_number));

  MOCK_METHOD2(NotifyMessagePortDestroyed,
               void(const base::UnguessableToken& port_id,
                    uint64_t sequence_number));
};

using MockInstrumentationDelegate =
    testing::StrictMock<LenientMockInstrumentationDelegate>;

using testing::_;
using testing::Invoke;

}  // namespace

TEST(MessagePortDescriptorTest, InstrumentationAndSerializationWorks) {
  MockInstrumentationDelegate delegate;

  // A small struct for holding information gleaned about ports during their
  // creation event. Allows verifying that other events are appropriately
  // sequenced.
  struct {
    base::UnguessableToken token0;
    base::UnguessableToken token1;
    uint64_t seq0 = 1;
    uint64_t seq1 = 1;
  } created_data;

  // Create a message handle descriptor pair and expect a notification.
  EXPECT_CALL(delegate, NotifyMessagePortPairCreated(_, _))
      .WillOnce(Invoke([&created_data](const base::UnguessableToken& port0_id,
                                       const base::UnguessableToken& port1_id) {
        created_data.token0 = port0_id;
        created_data.token1 = port1_id;
      }));
  MessagePortDescriptorPair pair;

  MessagePortDescriptor port0;
  MessagePortDescriptor port1;
  EXPECT_FALSE(port0.IsValid());
  EXPECT_FALSE(port1.IsValid());
  EXPECT_FALSE(port0.IsEntangled());
  EXPECT_FALSE(port1.IsEntangled());
  EXPECT_TRUE(port0.IsDefault());
  EXPECT_TRUE(port1.IsDefault());
  port0 = pair.TakePort0();
  port1 = pair.TakePort1();
  EXPECT_TRUE(port0.IsValid());
  EXPECT_TRUE(port1.IsValid());
  EXPECT_FALSE(port0.IsEntangled());
  EXPECT_FALSE(port1.IsEntangled());
  EXPECT_FALSE(port0.IsDefault());
  EXPECT_FALSE(port1.IsDefault());

  // Expect that the data received at creation matches the actual ports.
  EXPECT_EQ(created_data.token0, port0.id());
  EXPECT_EQ(created_data.seq0, port0.sequence_number());
  EXPECT_EQ(created_data.token1, port1.id());
  EXPECT_EQ(created_data.seq1, port1.sequence_number());

  // Simulate that a handle is attached by taking the pipe handle.
  EXPECT_CALL(delegate,
              NotifyMessagePortAttached(created_data.token0,
                                        created_data.seq0++, kDummyEc));
  auto handle0 = port0.TakeHandleToEntangle(kDummyEc);
  EXPECT_TRUE(port0.IsValid());
  EXPECT_TRUE(port0.IsEntangled());
  EXPECT_FALSE(port0.IsDefault());

  // Simulate that the handle is detached by giving the pipe handle back.
  EXPECT_CALL(delegate, NotifyMessagePortDetached(created_data.token0,
                                                  created_data.seq0++));
  port0.GiveDisentangledHandle(std::move(handle0));
  EXPECT_TRUE(port0.IsValid());
  EXPECT_FALSE(port0.IsEntangled());
  EXPECT_FALSE(port0.IsDefault());

  // Tear down a handle explicitly.
  EXPECT_CALL(delegate, NotifyMessagePortDestroyed(created_data.token1,
                                                   created_data.seq1++));
  port1.Reset();

  // And leave the other handle to be torn down in the destructor.
  EXPECT_CALL(delegate, NotifyMessagePortDestroyed(created_data.token0,
                                                   created_data.seq0++));
}

TEST(MessagePortDescriptorTestDeathTest, InvalidUsageInstrumentationDelegate) {
  static MessagePortDescriptor::InstrumentationDelegate* kDummyDelegate1 =
      reinterpret_cast<MessagePortDescriptor::InstrumentationDelegate*>(
          0xBAADF00D);
  static MessagePortDescriptor::InstrumentationDelegate* kDummyDelegate2 =
      reinterpret_cast<MessagePortDescriptor::InstrumentationDelegate*>(
          0xDEADBEEF);
  EXPECT_DCHECK_DEATH(
      MessagePortDescriptor::SetInstrumentationDelegate(nullptr));
  MessagePortDescriptor::SetInstrumentationDelegate(kDummyDelegate1);
  // Setting the same or another delegate should explode.
  EXPECT_DCHECK_DEATH(
      MessagePortDescriptor::SetInstrumentationDelegate(kDummyDelegate1));
  EXPECT_DCHECK_DEATH(
      MessagePortDescriptor::SetInstrumentationDelegate(kDummyDelegate2));
  // Unset the dummy delegate we installed so we don't receive notifications in
  // the rest of the test.
  MessagePortDescriptor::SetInstrumentationDelegate(nullptr);
}

TEST(MessagePortDescriptorTestDeathTest, InvalidUsageForSerialization) {
  // Trying to take properties of a default port descriptor should explode.
  MessagePortDescriptor port0;
  EXPECT_DCHECK_DEATH(port0.TakeHandleForSerialization());
  EXPECT_DCHECK_DEATH(port0.TakeIdForSerialization());
  EXPECT_DCHECK_DEATH(port0.TakeSequenceNumberForSerialization());

  MessagePortDescriptorPair pair;
  port0 = pair.TakePort0();
  MessagePortDescriptor port1 = pair.TakePort1();

  {
    // Dismantle the port as if for serialization. Trying to take fields a
    // second time should explode. A partially serialized object should also
    // explode if
    auto handle = port0.TakeHandleForSerialization();
    EXPECT_DCHECK_DEATH(port0.TakeHandleForSerialization());
    EXPECT_DCHECK_DEATH(port0.Reset());
    auto id = port0.TakeIdForSerialization();
    EXPECT_DCHECK_DEATH(port0.TakeIdForSerialization());
    EXPECT_DCHECK_DEATH(port0.Reset());
    auto sequence_number = port0.TakeSequenceNumberForSerialization();
    EXPECT_DCHECK_DEATH(port0.TakeSequenceNumberForSerialization());

    // This time reset should *not* explode, as the object has been fully taken
    // for serialization.
    port0.Reset();

    // Reserializing with inconsistent state should explode.

    // First try with any 1 of the 3 fields being invalid.
    EXPECT_DCHECK_DEATH(port0.InitializeFromSerializedValues(
        mojo::ScopedMessagePipeHandle(), id, sequence_number));
    EXPECT_DCHECK_DEATH(port0.InitializeFromSerializedValues(
        std::move(handle), base::UnguessableToken::Null(), sequence_number));
    EXPECT_DCHECK_DEATH(
        port0.InitializeFromSerializedValues(std::move(handle), id, 0));

    // Next try with any 2 of the 3 fields being invalid.
    EXPECT_DCHECK_DEATH(port0.InitializeFromSerializedValues(
        std::move(handle), base::UnguessableToken::Null(), 0));
    EXPECT_DCHECK_DEATH(port0.InitializeFromSerializedValues(
        mojo::ScopedMessagePipeHandle(), id, 0));
    EXPECT_DCHECK_DEATH(port0.InitializeFromSerializedValues(
        mojo::ScopedMessagePipeHandle(), base::UnguessableToken::Null(),
        sequence_number));

    // Restoring the port with default state should work (all 3 fields invalid).
    port0.InitializeFromSerializedValues(mojo::ScopedMessagePipeHandle(),
                                         base::UnguessableToken::Null(), 0);
    EXPECT_TRUE(port0.IsDefault());

    // Restoring the port with full state should work (all 3 fields valid).
    port0.InitializeFromSerializedValues(std::move(handle), id,
                                         sequence_number);
  }
}

TEST(MessagePortDescriptorTestDeathTest, InvalidUsageForEntangling) {
  MessagePortDescriptorPair pair;
  MessagePortDescriptor port0 = pair.TakePort0();
  MessagePortDescriptor port1 = pair.TakePort1();

  // Entangle the port.
  auto handle0 = port0.TakeHandleToEntangleWithEmbedder();

  // Trying to entangle a second time should explode.
  EXPECT_DCHECK_DEATH(port0.TakeHandleToEntangleWithEmbedder());
  EXPECT_DCHECK_DEATH(port0.TakeHandleToEntangle(kDummyEc));

  // Destroying a port descriptor that has been entangled should explode. The
  // handle needs to be given back to the descriptor before its death, ensuring
  // descriptors remain fully accounted for over their entire lifecycle.
  EXPECT_DCHECK_DEATH(port0.Reset());

  // Trying to assign while the handle is entangled should explode, as it
  // amounts to destroying the existing descriptor.
  EXPECT_DCHECK_DEATH(port0 = MessagePortDescriptor());

  // Trying to reset an entangled port should explode.
  EXPECT_DCHECK_DEATH(port0.Reset());

  // Trying to serialize an entangled port should explode.
  EXPECT_DCHECK_DEATH(port0.TakeHandleForSerialization());
  EXPECT_DCHECK_DEATH(port0.TakeIdForSerialization());
  EXPECT_DCHECK_DEATH(port0.TakeSequenceNumberForSerialization());

  // Disentangle the port so it doesn't explode at teardown.
  port0.GiveDisentangledHandle(std::move(handle0));
}

}  // namespace blink
```
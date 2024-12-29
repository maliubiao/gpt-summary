Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Goal:**

The core request is to analyze a specific Chromium Blink test file (`datagram_duplex_stream_test.cc`) and explain its purpose, connections to web technologies, logic, potential errors, and debugging context.

**2. Initial Scan and Keyword Recognition:**

I first quickly scanned the file, looking for familiar keywords and patterns. This immediately revealed:

* **`// Copyright`:**  Indicates a Chromium source file.
* **`#include` directives:**  Shows dependencies, including:
    * `DatagramDuplexStream.h`:  The main class being tested.
    * `WebTransport.h`: The underlying WebTransport API.
    * `testing/gtest/include/gtest/gtest.h`:  Indicates this is a Google Test file.
    * `v8_binding_for_testing.h`:  Suggests interaction with V8 (JavaScript engine).
* **`namespace blink {`**: Confirms it's part of the Blink rendering engine.
* **`TEST(DatagramDuplexStreamTest, ...)`**:  Standard Google Test macro, revealing individual test cases.
* **Class names like `StubWebTransport`, `ScopedWebTransport`, `ScopedDatagramDuplexStream`**:  These look like test fixtures or helper classes.
* **Methods like `setIncomingMaxAge`, `setOutgoingMaxAge`, `setIncomingHighWaterMark`, `setOutgoingHighWaterMark`**: These are the methods of `DatagramDuplexStream` being tested.
* **Assertions like `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`**: Standard Google Test assertions for verifying behavior.

**3. Deciphering the Test Structure:**

I noticed the pattern of using "scoped" helper classes (`ScopedWebTransport`, `ScopedDatagramDuplexStream`). This is a common pattern in C++ testing to manage the setup and teardown of test dependencies.

* **`StubWebTransport`:**  This is a *mock* or *stub* implementation of the `network::mojom::blink::WebTransport` interface. It allows testing `DatagramDuplexStream` in isolation, without needing a full network stack. The `NOTREACHED()` in some methods indicates that these methods are not expected to be called during the tests.
* **`ScopedWebTransport`:** This class creates a `StubWebTransport` and a corresponding `WebTransport` object used by the class being tested. It seems to be handling the Mojo (inter-process communication) setup.
* **`ScopedDatagramDuplexStream`:** This class instantiates the `DatagramDuplexStream` being tested, along with the necessary `ScopedWebTransport`.

**4. Identifying the Tested Functionality:**

By looking at the `TEST` cases, I could clearly identify the features being tested:

* **Defaults:**  Checks the initial values of properties.
* **`SetIncomingMaxAge`:** Tests setting the maximum age for incoming datagrams.
* **`SetOutgoingMaxAge`:** Tests setting the maximum age for outgoing datagrams. Crucially, this also interacts with the `StubWebTransport` to verify that the correct Mojo call is made.
* **`SetIncomingHighWaterMark`:** Tests setting the high water mark for incoming datagrams.
* **`SetOutgoingHighWaterMark`:** Tests setting the high water mark for outgoing datagrams.
* **`InitialMaxDatagramSize`:** Checks the initial maximum datagram size.

**5. Connecting to Web Technologies:**

Based on the class name (`DatagramDuplexStream`) and the inclusion of `WebTransport.h`, it's clear this code relates to the **WebTransport API**. I then considered how WebTransport is used:

* **JavaScript API:**  Web developers interact with WebTransport through JavaScript. This means the C++ code is the underlying implementation of the JavaScript API.
* **Datagrams:** WebTransport supports sending and receiving unreliable datagrams. This test focuses on the `DatagramDuplexStream`, which manages these datagrams.
* **Max Age:** The `incomingMaxAge` and `outgoingMaxAge` settings relate to the expiration of datagrams, a feature of WebTransport to manage network traffic and resource usage.
* **High Water Mark:** These settings likely control buffering or flow control mechanisms for datagrams.

**6. Inferring Logic and Examples:**

For each test case, I analyzed the assertions to understand the expected behavior. For example:

* **`SetOutgoingMaxAge`:** Setting a positive value should trigger a call to the `StubWebTransport` to set the expiration duration. Setting `null`, `0`, or a negative value should reset it. The test checks both the local property and the interaction with the stub.

**7. Considering User Errors and Debugging:**

I thought about how a web developer might misuse the WebTransport API, leading to issues related to this C++ code:

* **Incorrectly setting max age:** Setting a very short max age might cause datagrams to expire prematurely.
* **Misunderstanding high water marks:** Setting these values incorrectly could lead to excessive buffering or dropped datagrams.

For debugging, I considered the steps a developer might take:

* **Using the JavaScript WebTransport API:**  The developer would be writing JavaScript code.
* **Observing network behavior:** They might use browser developer tools to inspect network traffic and see if datagrams are being sent and received as expected.
* **Encountering errors:** If something goes wrong, they might see errors in the JavaScript console. This C++ test file helps ensure the underlying implementation is correct, reducing the likelihood of such errors.

**8. Structuring the Answer:**

Finally, I organized the information into the requested categories: functionality, relationship to web technologies, logic/examples, common errors, and debugging. I tried to be clear and concise, providing specific examples where possible. I used the information gathered in the previous steps to populate each section.
这个文件 `datagram_duplex_stream_test.cc` 是 Chromium Blink 引擎中用于测试 `DatagramDuplexStream` 类的单元测试文件。 `DatagramDuplexStream` 类是 WebTransport API 的一部分，负责处理不可靠的、无序的数据报（datagram）的发送和接收。

**文件功能:**

这个文件的主要功能是：

1. **测试 `DatagramDuplexStream` 类的各种功能:**  它包含了多个独立的测试用例（使用 Google Test 框架），用于验证 `DatagramDuplexStream` 类的行为是否符合预期。
2. **模拟 WebTransport 的底层交互:**  它创建了一个简化的 `StubWebTransport` 类，用于模拟 `DatagramDuplexStream` 类所依赖的 `network::mojom::blink::WebTransport` 接口。这使得测试可以在不涉及完整网络堆栈的情况下进行。
3. **测试属性的设置和获取:**  测试用例覆盖了 `DatagramDuplexStream` 类的各种属性，例如 `incomingMaxAge`（接收数据报的最大生存时间）、`outgoingMaxAge`（发送数据报的最大生存时间）、`incomingHighWaterMark`（接收缓冲区的高水位线）、`outgoingHighWaterMark`（发送缓冲区的高水位线）以及 `maxDatagramSize`（最大数据报大小）。

**与 Javascript, HTML, CSS 的关系:**

`DatagramDuplexStream` 是 WebTransport API 的一部分，而 WebTransport 是一个允许在客户端和服务器之间进行双向、多路复用的通信协议。 它与 JavaScript 有着直接的关系，因为 web 开发者会使用 JavaScript API 来创建和操作 WebTransport 连接，包括发送和接收数据报。

* **JavaScript API:** Web 开发者可以使用 JavaScript 中的 `WebTransport` 接口来创建连接，并通过该连接获取 `send()` 方法来发送数据报，以及监听 `datagram` 事件来接收数据报。 `DatagramDuplexStream` 的 C++ 代码是这些 JavaScript API 的底层实现。

* **HTML:** HTML 提供了创建网页结构的基础，而 WebTransport API 可以被嵌入到 JavaScript 代码中，从而在 HTML 页面中使用。 例如，一个网页上的 JavaScript 可以创建一个 WebTransport 连接到服务器，并使用数据报进行实时通信，比如游戏中的位置更新或者传感器数据的传输。

* **CSS:** CSS 负责网页的样式和布局。虽然 CSS 本身不直接与 WebTransport 交互，但它影响着使用 WebTransport 的网页的用户界面。例如，CSS 可以用来渲染实时更新的数据（通过 WebTransport 数据报接收）。

**举例说明:**

假设一个 JavaScript 应用程序使用 WebTransport 发送和接收游戏角色的位置信息：

```javascript
// JavaScript 代码
const transport = new WebTransport("https://example.com/webtransport");

transport.ready.then(() => {
  const writer = transport.datagrams.writable.getWriter();

  // 发送角色位置信息
  function sendPosition(x, y) {
    const encoder = new TextEncoder();
    const data = encoder.encode(`position:${x},${y}`);
    writer.write(data);
  }

  transport.datagrams.readable.getReader().read().then(function processResult( { done, value } ) {
    if (done) {
      console.log("Datagram stream closed");
      return;
    }
    const decoder = new TextDecoder();
    const message = decoder.decode(value);
    console.log("Received datagram:", message);
    // 更新其他角色位置信息
    // ...
    return reader.read().then(processResult);
  });

  // ... 游戏中不断调用 sendPosition 更新位置
  setInterval(() => {
    const randomX = Math.floor(Math.random() * 100);
    const randomY = Math.floor(Math.random() * 100);
    sendPosition(randomX, randomY);
  }, 100);
});
```

在这个例子中，当 JavaScript 代码调用 `writer.write(data)` 发送数据报时，Blink 渲染引擎内部会调用到 `DatagramDuplexStream` 类的相关方法来处理数据报的发送。 `datagram_duplex_stream_test.cc` 中的测试用例会验证 `DatagramDuplexStream` 是否正确地处理了数据报的发送逻辑，例如是否正确地设置了数据报的最大生存时间 (通过 `outgoingMaxAge`)。

**逻辑推理和假设输入输出:**

**测试用例：`SetOutgoingMaxAge`**

* **假设输入:**
    * 创建一个 `DatagramDuplexStream` 实例。
    * 调用 `setOutgoingMaxAge(1.0)`，设置发送数据报的最大生存时间为 1 秒。
* **逻辑推理:**
    * `DatagramDuplexStream` 应该将内部的 `outgoingMaxAge_` 成员变量设置为 1.0。
    * `DatagramDuplexStream` 应该调用底层的 `WebTransport` 接口的 `SetOutgoingDatagramExpirationDuration` 方法，并将参数设置为 1 秒（或者与其最接近的 `base::TimeDelta` 值）。
* **预期输出:**
    * `duplex->outgoingMaxAge().value()` 应该返回 1.0。
    * `stub->OutgoingDatagramExpirationDurationValue().value()` 应该返回 `base::Milliseconds(1)`。

**测试用例：`SetIncomingHighWaterMark`**

* **假设输入:**
    * 创建一个 `DatagramDuplexStream` 实例。
    * 调用 `setIncomingHighWaterMark(10)`，设置接收缓冲区的高水位线为 10。
* **逻辑推理:**
    * `DatagramDuplexStream` 应该将内部的 `incomingHighWaterMark_` 成员变量设置为 10。
* **预期输出:**
    * `duplex->incomingHighWaterMark()` 应该返回 10。

**用户或编程常见的使用错误:**

1. **设置 `outgoingMaxAge` 为非正数:**  用户可能错误地将 `outgoingMaxAge` 设置为 0 或负数，期望立即丢弃数据报。然而，测试用例表明，在这种情况下，该值会被忽略或不生效。正确的做法是使用 `null` 来表示不设置最大生存时间。

   ```javascript
   // 错误示例
   transport.datagramMaxAge = 0; // 或者 -1
   ```

2. **混淆 `incomingMaxAge` 和 `outgoingMaxAge` 的作用:** 用户可能不理解这两个属性的区别，错误地设置了接收数据报的最大生存时间，而实际上他们想控制发送数据报的生存时间。

3. **不理解 High Water Mark 的含义:** 用户可能错误地设置了 `incomingHighWaterMark` 或 `outgoingHighWaterMark`，导致数据报被意外丢弃或缓冲区溢出。 High Water Mark 通常用于流控制，需要根据具体的应用场景进行合理设置。

**用户操作如何一步步到达这里 (作为调试线索):**

假设一个 web 开发者在使用 WebTransport 时遇到了数据报延迟或丢失的问题。他们可能会进行以下调试步骤，最终可能会涉及到查看 `datagram_duplex_stream_test.cc`：

1. **编写 JavaScript 代码使用 WebTransport API:** 开发者首先会编写 JavaScript 代码来创建 WebTransport 连接并发送/接收数据报。
2. **观察网络行为:** 开发者可能会使用浏览器开发者工具的网络面板来查看 WebTransport 连接的状态和数据报的传输情况。
3. **遇到问题 (例如数据报延迟):** 如果开发者发现数据报有明显的延迟，他们可能会怀疑是某些配置问题导致的。
4. **检查 WebTransport API 的使用:** 开发者会检查他们的 JavaScript 代码，确保正确使用了 WebTransport API，例如检查是否设置了 `datagramMaxAge`。
5. **查阅文档和规范:** 开发者可能会查阅 WebTransport 的相关文档和规范，了解各个属性的含义和作用。
6. **搜索相关错误和问题:** 开发者可能会在网上搜索与 WebTransport 数据报延迟相关的错误信息。
7. **怀疑浏览器实现问题:** 如果排除了自身代码的问题，开发者可能会开始怀疑是浏览器实现的 bug。
8. **查看 Chromium 源代码 (高级调试):**  为了深入了解问题，开发者可能会下载 Chromium 的源代码，并尝试找到与 WebTransport 数据报处理相关的代码。他们可能会搜索 `DatagramDuplexStream` 或相关的类名。
9. **查看 `datagram_duplex_stream_test.cc`:**  开发者可能会找到这个测试文件，并查看其中的测试用例，以了解 `DatagramDuplexStream` 的预期行为以及如何设置各种属性。例如，他们可能会查看 `SetOutgoingMaxAge` 测试用例，来理解 `outgoingMaxAge` 的工作原理以及如何与底层的 `WebTransport` 接口交互。
10. **进行本地构建和调试:**  更高级的开发者可能会尝试在本地构建 Chromium，并在调试模式下运行，以便更详细地跟踪数据报的发送和接收过程，甚至可以修改测试用例来复现和分析他们遇到的问题。

总而言之，`datagram_duplex_stream_test.cc` 是 Blink 引擎中保证 WebTransport 数据报功能正确性的重要组成部分。理解其功能和测试用例可以帮助开发者更好地理解 WebTransport API 的底层实现和预期行为，从而避免常见的使用错误并进行有效的调试。

Prompt: 
```
这是目录为blink/renderer/modules/webtransport/datagram_duplex_stream_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webtransport/datagram_duplex_stream.h"

#include <memory>
#include <utility>

#include "base/functional/callback.h"
#include "base/time/time.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "services/network/public/mojom/web_transport.mojom-blink.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/modules/webtransport/test_utils.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

constexpr int32_t kInitialOutgoingHighWaterMark = 1;

// Tiny implementation of network::mojom::blink::WebTransport with only the
// functionality needed for these tests.
class StubWebTransport final : public network::mojom::blink::WebTransport {
 public:
  explicit StubWebTransport(
      mojo::PendingReceiver<network::mojom::blink::WebTransport>
          pending_receiver)
      : receiver_(this, std::move(pending_receiver)) {}

  std::optional<base::TimeDelta> OutgoingDatagramExpirationDurationValue() {
    return outgoing_datagram_expiration_duration_value_;
  }

  // Implementation of WebTransport.
  void SendDatagram(base::span<const uint8_t> data,
                    base::OnceCallback<void(bool)>) override {
    NOTREACHED();
  }

  void CreateStream(
      mojo::ScopedDataPipeConsumerHandle output_consumer,
      mojo::ScopedDataPipeProducerHandle input_producer,
      base::OnceCallback<void(bool, uint32_t)> callback) override {
    NOTREACHED();
  }

  void AcceptBidirectionalStream(
      base::OnceCallback<void(uint32_t,
                              mojo::ScopedDataPipeConsumerHandle,
                              mojo::ScopedDataPipeProducerHandle)> callback)
      override {
    DCHECK(!ignored_accept_callback_);
    // This method is always called. We have to retain the callback to avoid an
    // error about early destruction, but never call it.
    ignored_accept_callback_ = std::move(callback);
  }

  void AcceptUnidirectionalStream(
      base::OnceCallback<void(uint32_t, mojo::ScopedDataPipeConsumerHandle)>
          callback) override {
    DCHECK(!ignored_unidirectional_stream_callback_);
    // This method is always called. We have to retain the callback to avoid an
    // error about early destruction, but never call it.
    ignored_unidirectional_stream_callback_ = std::move(callback);
  }

  void SendFin(uint32_t stream_id) override {}

  void AbortStream(uint32_t stream_id, uint8_t code) override {}

  void StopSending(uint32_t stream_id, uint8_t code) override {}

  void SetOutgoingDatagramExpirationDuration(base::TimeDelta value) override {
    outgoing_datagram_expiration_duration_value_ = value;
  }

  void GetStats(GetStatsCallback callback) override {
    std::move(callback).Run(nullptr);
  }

  void Close(network::mojom::blink::WebTransportCloseInfoPtr) override {}

 private:
  base::OnceCallback<void(uint32_t,
                          mojo::ScopedDataPipeConsumerHandle,
                          mojo::ScopedDataPipeProducerHandle)>
      ignored_accept_callback_;
  base::OnceCallback<void(uint32_t, mojo::ScopedDataPipeConsumerHandle)>
      ignored_unidirectional_stream_callback_;
  mojo::Receiver<network::mojom::blink::WebTransport> receiver_;
  std::optional<base::TimeDelta> outgoing_datagram_expiration_duration_value_;
};

// This class sets up a connected blink::WebTransport object using a
// StubWebTransport and provides access to both.
class ScopedWebTransport final {
  STACK_ALLOCATED();

 public:
  // This constructor runs the event loop.
  explicit ScopedWebTransport(const V8TestingScope& scope) {
    creator_.Init(scope.GetScriptState(),
                  WTF::BindRepeating(&ScopedWebTransport::CreateStub,
                                     weak_ptr_factory_.GetWeakPtr()));
  }

  WebTransport* GetWebTransport() const { return creator_.GetWebTransport(); }
  StubWebTransport* Stub() const { return stub_.get(); }

 private:
  void CreateStub(mojo::PendingRemote<network::mojom::blink::WebTransport>&
                      web_transport_to_pass) {
    stub_ = std::make_unique<StubWebTransport>(
        web_transport_to_pass.InitWithNewPipeAndPassReceiver());
  }

  TestWebTransportCreator creator_;
  std::unique_ptr<StubWebTransport> stub_;

  base::WeakPtrFactory<ScopedWebTransport> weak_ptr_factory_{this};
};

class ScopedDatagramDuplexStream final {
  STACK_ALLOCATED();

 public:
  ScopedDatagramDuplexStream()
      : scoped_web_transport_(v8_testing_scope_),
        duplex_(MakeGarbageCollected<DatagramDuplexStream>(
            scoped_web_transport_.GetWebTransport(),
            kInitialOutgoingHighWaterMark)) {}
  ScopedDatagramDuplexStream(const ScopedDatagramDuplexStream&) = delete;
  ScopedDatagramDuplexStream& operator=(const ScopedDatagramDuplexStream&) =
      delete;

  DatagramDuplexStream* Duplex() { return duplex_; }

  StubWebTransport* Stub() { return scoped_web_transport_.Stub(); }

 private:
  V8TestingScope v8_testing_scope_;
  ScopedWebTransport scoped_web_transport_;
  DatagramDuplexStream* const duplex_;
};

TEST(DatagramDuplexStreamTest, Defaults) {
  test::TaskEnvironment task_environment;
  ScopedDatagramDuplexStream scope;
  auto* duplex = scope.Duplex();
  EXPECT_FALSE(duplex->incomingMaxAge().has_value());
  EXPECT_FALSE(duplex->outgoingMaxAge().has_value());
  EXPECT_EQ(duplex->incomingHighWaterMark(), kDefaultIncomingHighWaterMark);
  EXPECT_EQ(duplex->outgoingHighWaterMark(), kInitialOutgoingHighWaterMark);
}

TEST(DatagramDuplexStreamTest, SetIncomingMaxAge) {
  test::TaskEnvironment task_environment;
  ScopedDatagramDuplexStream scope;
  auto* duplex = scope.Duplex();

  duplex->setIncomingMaxAge(1.0);
  ASSERT_TRUE(duplex->incomingMaxAge().has_value());
  EXPECT_EQ(duplex->incomingMaxAge().value(), 1.0);

  duplex->setIncomingMaxAge(std::nullopt);
  ASSERT_FALSE(duplex->incomingMaxAge().has_value());

  duplex->setIncomingMaxAge(0.0);
  ASSERT_FALSE(duplex->incomingMaxAge().has_value());

  duplex->setIncomingMaxAge(-1.0);
  ASSERT_FALSE(duplex->incomingMaxAge().has_value());
}

TEST(DatagramDuplexStreamTest, SetOutgoingMaxAge) {
  test::TaskEnvironment task_environment;
  ScopedDatagramDuplexStream scope;
  auto* duplex = scope.Duplex();
  auto* stub = scope.Stub();

  duplex->setOutgoingMaxAge(1.0);
  ASSERT_TRUE(duplex->outgoingMaxAge().has_value());
  EXPECT_EQ(duplex->outgoingMaxAge().value(), 1.0);
  test::RunPendingTasks();
  auto expiration_duration = stub->OutgoingDatagramExpirationDurationValue();
  ASSERT_TRUE(expiration_duration.has_value());
  EXPECT_EQ(expiration_duration.value(), base::Milliseconds(1.0));

  duplex->setOutgoingMaxAge(std::nullopt);
  ASSERT_FALSE(duplex->outgoingMaxAge().has_value());
  test::RunPendingTasks();
  expiration_duration = stub->OutgoingDatagramExpirationDurationValue();
  ASSERT_TRUE(expiration_duration.has_value());
  EXPECT_EQ(expiration_duration.value(), base::Milliseconds(0.0));

  duplex->setOutgoingMaxAge(0.5);
  ASSERT_TRUE(duplex->outgoingMaxAge().has_value());
  EXPECT_EQ(duplex->outgoingMaxAge().value(), 0.5);
  test::RunPendingTasks();
  expiration_duration = stub->OutgoingDatagramExpirationDurationValue();
  ASSERT_TRUE(expiration_duration.has_value());
  EXPECT_EQ(expiration_duration.value(), base::Milliseconds(0.5));

  duplex->setOutgoingMaxAge(0.0);
  ASSERT_TRUE(duplex->outgoingMaxAge().has_value());
  EXPECT_EQ(duplex->outgoingMaxAge().value(), 0.5);  // unchanged
  test::RunPendingTasks();
  expiration_duration = stub->OutgoingDatagramExpirationDurationValue();
  ASSERT_TRUE(expiration_duration.has_value());
  EXPECT_EQ(expiration_duration.value(),
            base::Milliseconds(0.5));  // Unchanged

  duplex->setOutgoingMaxAge(-1.0);
  ASSERT_TRUE(duplex->outgoingMaxAge().has_value());
  EXPECT_EQ(duplex->outgoingMaxAge().value(), 0.5);  // unchanged
  test::RunPendingTasks();
  expiration_duration = stub->OutgoingDatagramExpirationDurationValue();
  ASSERT_TRUE(expiration_duration.has_value());
  EXPECT_EQ(expiration_duration.value(),
            base::Milliseconds(0.5));  // Unchanged
}

TEST(DatagramDuplexStreamTest, SetIncomingHighWaterMark) {
  test::TaskEnvironment task_environment;
  ScopedDatagramDuplexStream scope;
  auto* duplex = scope.Duplex();

  duplex->setIncomingHighWaterMark(10);
  EXPECT_EQ(duplex->incomingHighWaterMark(), 10);

  duplex->setIncomingHighWaterMark(0);
  EXPECT_EQ(duplex->incomingHighWaterMark(), 0);

  duplex->setIncomingHighWaterMark(-1);
  EXPECT_EQ(duplex->incomingHighWaterMark(), 0);
}

TEST(DatagramDuplexStreamTest, SetOutgoingHighWaterMark) {
  test::TaskEnvironment task_environment;
  ScopedDatagramDuplexStream scope;
  auto* duplex = scope.Duplex();

  duplex->setOutgoingHighWaterMark(10);
  EXPECT_EQ(duplex->outgoingHighWaterMark(), 10);

  duplex->setOutgoingHighWaterMark(0);
  EXPECT_EQ(duplex->outgoingHighWaterMark(), 0);

  duplex->setOutgoingHighWaterMark(-1);
  EXPECT_EQ(duplex->outgoingHighWaterMark(), 0);
}

TEST(DatagramDuplexStreamTest, InitialMaxDatagramSize) {
  test::TaskEnvironment task_environment;
  ScopedDatagramDuplexStream scope;
  auto* duplex = scope.Duplex();

  EXPECT_EQ(duplex->maxDatagramSize(), 1024u);
}

}  // namespace

}  // namespace blink

"""

```
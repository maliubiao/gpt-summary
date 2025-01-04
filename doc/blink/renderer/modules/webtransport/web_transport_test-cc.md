Response:
The user is asking for a summary of the functionality of the C++ test file `web_transport_test.cc` within the Chromium Blink rendering engine. The file seems to be focused on testing the `WebTransport` API.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Purpose:** The filename `web_transport_test.cc` strongly suggests this file contains unit tests for the WebTransport API implementation in Blink.

2. **Analyze Includes:** The included headers provide clues about what's being tested:
    * `third_party/blink/renderer/modules/webtransport/web_transport.h`: This is the main WebTransport API being tested.
    * Headers related to `mojom::blink::WebTransport*`: Indicates interaction with the Mojo interface for WebTransport, likely communication with the network service.
    * `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h`:  Confirms this is a unit test file using Google Test and Google Mock.
    * Headers related to V8 bindings (`third_party/blink/renderer/bindings/core/v8/*`, `third_party/blink/renderer/bindings/modules/v8/*`): Suggests tests cover the JavaScript API aspects of WebTransport.
    * Headers related to Streams (`third_party/blink/renderer/core/streams/*`):  Indicates tests involving the integration of WebTransport with the Streams API (ReadableStream, WritableStream).
    * Headers for other WebTransport related classes (`bidirectional_stream.h`, `datagram_duplex_stream.h`, etc.): Shows testing of individual components within the WebTransport implementation.

3. **Examine Test Fixture:** The `WebTransportTest` class is the main test fixture. Key elements within it:
    * `WebTransportConnector`: A mock implementation to intercept and verify calls to establish WebTransport connections.
    * `MockWebTransport`:  A mock implementation of the `network::mojom::blink::WebTransport` interface to control the behavior of the underlying network connection.
    * Helper methods like `Create`, `ConnectSuccessfully`, `CreateAndConnectSuccessfully`, `CreateSendStreamSuccessfully`, `DoAcceptUnidirectionalStream`, `ReadReceiveStream`: These methods set up various WebTransport scenarios for testing.

4. **Review Individual Tests:**  The names of the tests (`FailWithNullURL`, `FailWithEmptyURL`, `FailWithHttpsURL`, `SuccessfulConnect`, `FailedConnect`, `SendDatagram`, `CloseDuringConnect`, `GarbageCollection`, etc.) reveal the specific functionalities being tested. They cover:
    * **Error Handling:** Testing invalid URL inputs, CSP violations.
    * **Connection Establishment:** Testing successful and failed connections, handling of server certificate fingerprints.
    * **Closing Connections:** Testing various close scenarios.
    * **Data Transfer:** Testing sending datagrams, creating and using unidirectional and bidirectional streams.
    * **Integration with Streams API:** Testing how WebTransport streams interact with JavaScript ReadableStream and WritableStream.
    * **Garbage Collection:** Ensuring proper memory management.

5. **Synthesize the Functionality:** Based on the analysis, the file's primary function is to rigorously test the Blink's implementation of the WebTransport API. This includes:
    * Testing API surface correctness.
    * Verifying correct interaction with the underlying network service (using mocks).
    * Ensuring proper integration with JavaScript and the Streams API.
    * Checking error handling and edge cases.
    * Validating memory management.

6. **Address Specific Questions:**
    * **Relationship with JavaScript/HTML/CSS:** WebTransport is primarily a JavaScript API. The tests heavily involve creating and manipulating `WebTransport` objects and related stream objects from within the testing framework (which simulates a JavaScript environment using V8). While not directly related to HTML or CSS rendering, WebTransport is used within web pages accessed via HTML.
    * **Logical Reasoning with Input/Output:**  The tests implicitly perform logical reasoning. For example, the `SuccessfulConnect` test assumes that if the Mojo handshake succeeds, the `ready` promise should be fulfilled. A more explicit example would be a test for stream creation where the input is a call to `createUnidirectionalStream` and the expected output is a `SendStream` object.
    * **Common Usage Errors:** The tests that check for exceptions (like `FailWithNullURL`) highlight potential programmer errors when using the WebTransport API. Another example is providing invalid certificate fingerprints.
    * **User Operation to Reach Here:** A developer working on the WebTransport implementation in Chromium would modify this file to add new tests or fix bugs. A failing test here indicates an issue with the underlying implementation triggered by JavaScript code using the WebTransport API in a web page.

7. **Formulate the Summary:** Combine the findings into a concise summary addressing the user's request for the first part.
This代码是 Chromium Blink 引擎中 `blink/renderer/modules/webtransport/web_transport_test.cc` 文件的第一部分，它的主要功能是 **对 WebTransport API 的 JavaScript 绑定进行单元测试**。

具体来说，这部分代码的功能可以归纳为以下几点：

1. **测试 WebTransport 对象的创建和初始化**:
   -  验证创建 `WebTransport` 对象时对 URL 参数的校验，例如：
      -  不允许 `null` 或空 URL。
      -  不允许使用非 `https` 协议。
      -  不允许 URL 中包含 fragment identifier (`#`).
   -  测试在创建 `WebTransport` 对象时，Content Security Policy (CSP) 的限制是否生效。

2. **测试 WebTransport 连接的建立**:
   -  模拟成功的 WebTransport 连接过程，验证 `ready` promise 是否正确 resolve。
   -  模拟失败的 WebTransport 连接过程，验证 `ready` 和 `closed` promise 是否正确 reject。
   -  测试在连接建立过程中关闭 WebTransport 连接的情况。
   -  测试连接建立时发送服务器证书指纹 (fingerprint) 的功能。

3. **测试 WebTransport 连接的关闭**:
   -  测试在连接建立后正常关闭 WebTransport 连接，并验证 `closed` promise 是否正确 resolve。
   -  测试使用 `WebTransportCloseInfo` 对象传递关闭代码和原因的功能。
   -  测试在没有提供 `WebTransportCloseInfo` 对象时关闭连接的功能。

4. **测试 WebTransport 对象的垃圾回收**:
   -  验证当 WebTransport 对象没有被引用时，会被垃圾回收。
   -  测试当底层的 Mojo 连接发生错误时，WebTransport 对象会被垃圾回收。

5. **测试通过 WebTransport 发送数据报 (datagram)**:
   -  验证可以通过 `WebTransport` 对象的 `datagrams().writable()` 获取 `WritableStream`，并向其写入数据来发送数据报。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件主要测试的是 **JavaScript API** 的行为，因为它直接操作 `WebTransport` 对象以及相关的 Promise 和 Stream 对象。

* **JavaScript:**
    -  测试代码模拟了 JavaScript 中创建 `WebTransport` 对象的方式：`WebTransport::Create(scope.GetScriptState(), url, options, ASSERT_NO_EXCEPTION);` 这反映了 JavaScript 中 `new WebTransport(url, options)` 的调用。
    -  测试代码使用了 `ScriptPromiseTester` 来验证 `ready` 和 `closed` promise 的状态变化，这与 JavaScript 中使用 `.then()` 或 `await` 来处理 Promise 的结果相对应。
    -  测试代码使用了 `V8WritableStream` 来操作可写流，这对应于 JavaScript 中 `WebTransportDatagramDuplexStream.writable` 返回的 `WritableStream` 对象。

    **举例说明:**  在 JavaScript 中，你可以这样创建一个 WebTransport 连接并监听其 `ready` 状态：
    ```javascript
    const wt = new WebTransport("https://example.com");
    wt.ready.then(() => {
      console.log("WebTransport connection is ready!");
    }).catch(error => {
      console.error("WebTransport connection failed:", error);
    });
    ```
    测试文件中的 `SuccessfulConnect` 和 `FailedConnect` 等测试用例就模拟了这种 JavaScript 代码的行为，并验证了 Blink 引擎中 `WebTransport` 对象的内部状态变化是否符合预期。

* **HTML:**  WebTransport API 是在 JavaScript 中使用的，HTML 提供了加载和执行 JavaScript 代码的载体。一个网页可以通过 `<script>` 标签引入包含 WebTransport 相关代码的 JavaScript 文件。

* **CSS:** CSS 与 WebTransport API 没有直接的功能关系。CSS 负责网页的样式和布局，而 WebTransport 负责底层的双向数据传输。

**逻辑推理、假设输入与输出：**

**假设输入:** 调用 `WebTransport::Create` 方法，并传入一个非 `https` 协议的 URL，例如 `"http://example.com/"`。

**逻辑推理:**  根据 WebTransport 的规范，连接必须使用 `https` 协议。因此，`WebTransport::Create` 应该抛出一个异常，指示 URL 格式错误。

**输出:**  测试用例 `TEST_F(WebTransportTest, FailWithHttpsURL)` 验证了这种情况，预期会抛出一个 `DOMExceptionCode::kSyntaxError` 类型的异常，并且错误消息是 "The URL's scheme must be 'https'. 'http' is not allowed."。

**用户或编程常见的使用错误：**

1. **提供无效的 URL:**
   -  例如，使用 `null`、空字符串、非 `https` 协议的 URL，或者包含 fragment identifier。测试用例 `FailWithNullURL`, `FailWithEmptyURL`, `FailWithHttpsURL`, `FailWithNoHost`, `FailWithURLFragment` 覆盖了这些错误。
   -  **用户操作步骤:** 在 JavaScript 代码中，将这些无效的 URL 传递给 `new WebTransport()` 构造函数。

2. **在 CSP 策略禁止的情况下尝试连接:**
   -  如果页面的 CSP 策略中 `connect-src` 指令没有允许连接到目标域名，那么 WebTransport 连接会失败。测试用例 `FailByCSP` 模拟了这种情况。
   -  **用户操作步骤:** 开发者在服务器端配置了限制性的 CSP 头，然后在前端 JavaScript 代码中尝试连接到被阻止的域名。

3. **提供无效的服务器证书指纹:**
   -  如果在 `WebTransportOptions` 中提供的服务器证书指纹格式不正确或信息缺失，连接可能不会成功建立。测试用例 `SendConnectWithInvalidFingerprint` 验证了这种情况。
   -  **用户操作步骤:**  开发者在 JavaScript 代码中创建 `WebTransport` 对象时，在 `serverCertificateHashes` 选项中提供了不正确的指纹信息。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户访问一个网页:** 用户在浏览器中输入 URL 或点击链接，访问一个包含 WebTransport 功能的网页。
2. **网页加载并执行 JavaScript 代码:**  浏览器加载 HTML、CSS 和 JavaScript 代码。
3. **JavaScript 代码尝试建立 WebTransport 连接:**  JavaScript 代码中使用了 `new WebTransport(url, options)` 来尝试与服务器建立连接。
4. **Blink 引擎处理 WebTransport 连接请求:**  Blink 引擎接收到 JavaScript 的连接请求，并开始处理。这涉及到调用 `WebTransport::Create` 等 C++ 代码。
5. **如果出现错误 (例如，无效的 URL):**  `WebTransport::Create` 方法会检测到错误，抛出一个异常，并在 JavaScript 中表现为一个 Promise 的 rejection。
6. **如果需要调试 Blink 引擎的 WebTransport 实现:**  开发者可能会查看 `web_transport_test.cc` 文件中的相关测试用例，来理解预期的行为，或者在实际代码中设置断点，跟踪代码执行流程，定位问题。例如，如果用户报告一个 "Failed to construct 'WebTransport': The URL 'ws://example.com' is invalid." 的错误，开发者可以查看 `FailWithHttpsURL` 测试用例，确认该错误是符合预期的。

**总结 - 该部分代码的功能：**

该部分 `web_transport_test.cc` 文件的主要功能是 **验证 Blink 引擎中 WebTransport API 的 JavaScript 绑定层的基本功能和错误处理**，包括对象的创建、连接的建立与关闭、以及基本的错误场景。它通过模拟 JavaScript 代码的调用方式，确保 WebTransport API 在各种情况下都能按照规范正确运行。

Prompt: 
```
这是目录为blink/renderer/modules/webtransport/web_transport_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webtransport/web_transport.h"

#include <array>
#include <memory>
#include <optional>
#include <utility>

#include "base/containers/span.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/test/mock_callback.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "services/network/public/mojom/web_transport.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/webtransport/web_transport_connector.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/iterable.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream_read_result.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_writable_stream.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_web_transport_bidirectional_stream.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_web_transport_close_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_web_transport_error.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_web_transport_hash.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_web_transport_options.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_byob_reader.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_reader.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_writer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/webtransport/bidirectional_stream.h"
#include "third_party/blink/renderer/modules/webtransport/datagram_duplex_stream.h"
#include "third_party/blink/renderer/modules/webtransport/receive_stream.h"
#include "third_party/blink/renderer/modules/webtransport/send_stream.h"
#include "third_party/blink/renderer/modules/webtransport/test_utils.h"
#include "third_party/blink/renderer/modules/webtransport/web_transport_error.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

using ::testing::_;
using ::testing::ElementsAre;
using ::testing::Invoke;
using ::testing::Mock;
using ::testing::StrictMock;
using ::testing::Truly;
using ::testing::Unused;

class WebTransportConnector final : public mojom::blink::WebTransportConnector {
 public:
  struct ConnectArgs {
    ConnectArgs(
        const KURL& url,
        Vector<network::mojom::blink::WebTransportCertificateFingerprintPtr>
            fingerprints,
        mojo::PendingRemote<network::mojom::blink::WebTransportHandshakeClient>
            handshake_client)
        : url(url),
          fingerprints(std::move(fingerprints)),
          handshake_client(std::move(handshake_client)) {}

    KURL url;
    Vector<network::mojom::blink::WebTransportCertificateFingerprintPtr>
        fingerprints;
    mojo::PendingRemote<network::mojom::blink::WebTransportHandshakeClient>
        handshake_client;
  };

  void Connect(
      const KURL& url,
      Vector<network::mojom::blink::WebTransportCertificateFingerprintPtr>
          fingerprints,
      mojo::PendingRemote<network::mojom::blink::WebTransportHandshakeClient>
          handshake_client) override {
    connect_args_.push_back(
        ConnectArgs(url, std::move(fingerprints), std::move(handshake_client)));
  }

  Vector<ConnectArgs> TakeConnectArgs() { return std::move(connect_args_); }

  void Bind(
      mojo::PendingReceiver<mojom::blink::WebTransportConnector> receiver) {
    receiver_set_.Add(this, std::move(receiver));
  }

 private:
  mojo::ReceiverSet<mojom::blink::WebTransportConnector> receiver_set_;
  Vector<ConnectArgs> connect_args_;
};

class MockWebTransport : public network::mojom::blink::WebTransport {
 public:
  explicit MockWebTransport(
      mojo::PendingReceiver<network::mojom::blink::WebTransport>
          pending_receiver)
      : receiver_(this, std::move(pending_receiver)) {}

  MOCK_METHOD2(SendDatagram,
               void(base::span<const uint8_t> data,
                    base::OnceCallback<void(bool)> callback));

  MOCK_METHOD3(CreateStream,
               void(mojo::ScopedDataPipeConsumerHandle readable,
                    mojo::ScopedDataPipeProducerHandle writable,
                    base::OnceCallback<void(bool, uint32_t)> callback));

  MOCK_METHOD1(
      AcceptBidirectionalStream,
      void(base::OnceCallback<void(uint32_t,
                                   mojo::ScopedDataPipeConsumerHandle,
                                   mojo::ScopedDataPipeProducerHandle)>));

  MOCK_METHOD1(AcceptUnidirectionalStream,
               void(base::OnceCallback<
                    void(uint32_t, mojo::ScopedDataPipeConsumerHandle)>));

  MOCK_METHOD1(SetOutgoingDatagramExpirationDuration, void(base::TimeDelta));
  MOCK_METHOD1(GetStats, void(GetStatsCallback));
  MOCK_METHOD0(Close, void());
  MOCK_METHOD2(Close, void(uint32_t, String));

  void Close(
      network::mojom::blink::WebTransportCloseInfoPtr close_info) override {
    if (!close_info) {
      Close();
      return;
    }
    Close(close_info->code, close_info->reason);
  }

  void SendFin(uint32_t stream_id) override {}
  void AbortStream(uint32_t stream_id, uint8_t code) override {}
  void StopSending(uint32_t stream_id, uint8_t code) override {}

 private:
  mojo::Receiver<network::mojom::blink::WebTransport> receiver_;
};

class WebTransportTest : public ::testing::Test {
 public:
  using AcceptUnidirectionalStreamCallback =
      base::OnceCallback<void(uint32_t, mojo::ScopedDataPipeConsumerHandle)>;
  using AcceptBidirectionalStreamCallback =
      base::OnceCallback<void(uint32_t,
                              mojo::ScopedDataPipeConsumerHandle,
                              mojo::ScopedDataPipeProducerHandle)>;

  void AddBinder(const V8TestingScope& scope) {
    interface_broker_ =
        &scope.GetExecutionContext()->GetBrowserInterfaceBroker();
    interface_broker_->SetBinderForTesting(
        mojom::blink::WebTransportConnector::Name_,
        WTF::BindRepeating(&WebTransportTest::BindConnector,
                  weak_ptr_factory_.GetWeakPtr()));
  }

  static WebTransportOptions* EmptyOptions() {
    return MakeGarbageCollected<WebTransportOptions>();
  }

  // Creates a WebTransport object with the given |url|.
  WebTransport* Create(const V8TestingScope& scope,
                       const String& url,
                       WebTransportOptions* options) {
    AddBinder(scope);
    return WebTransport::Create(scope.GetScriptState(), url, options,
                                ASSERT_NO_EXCEPTION);
  }

  // Connects a WebTransport object. Runs the event loop.
  void ConnectSuccessfully(
      WebTransport* web_transport,
      base::TimeDelta expected_outgoing_datagram_expiration_duration =
          base::TimeDelta()) {
    ConnectSuccessfullyWithoutRunningPendingTasks(
        web_transport, expected_outgoing_datagram_expiration_duration);
    test::RunPendingTasks();
  }

  void ConnectSuccessfullyWithoutRunningPendingTasks(
      WebTransport* web_transport,
      base::TimeDelta expected_outgoing_datagram_expiration_duration =
          base::TimeDelta()) {
    DCHECK(!mock_web_transport_) << "Only one connection supported, sorry";

    test::RunPendingTasks();

    auto args = connector_.TakeConnectArgs();
    if (args.size() != 1u) {
      ADD_FAILURE() << "args.size() should be 1, but is " << args.size();
      return;
    }

    mojo::Remote<network::mojom::blink::WebTransportHandshakeClient>
        handshake_client(std::move(args[0].handshake_client));

    mojo::PendingRemote<network::mojom::blink::WebTransport>
        web_transport_to_pass;
    mojo::PendingRemote<network::mojom::blink::WebTransportClient>
        client_remote;

    mock_web_transport_ = std::make_unique<StrictMock<MockWebTransport>>(
        web_transport_to_pass.InitWithNewPipeAndPassReceiver());

    // These are called on every connection, so expect them in every test.
    EXPECT_CALL(*mock_web_transport_, AcceptUnidirectionalStream(_))
        .WillRepeatedly([this](AcceptUnidirectionalStreamCallback callback) {
          pending_unidirectional_accept_callbacks_.push_back(
              std::move(callback));
        });

    EXPECT_CALL(*mock_web_transport_, AcceptBidirectionalStream(_))
        .WillRepeatedly([this](AcceptBidirectionalStreamCallback callback) {
          pending_bidirectional_accept_callbacks_.push_back(
              std::move(callback));
        });

    if (expected_outgoing_datagram_expiration_duration != base::TimeDelta()) {
      EXPECT_CALL(*mock_web_transport_,
                  SetOutgoingDatagramExpirationDuration(
                      expected_outgoing_datagram_expiration_duration));
    }

    handshake_client->OnConnectionEstablished(
        std::move(web_transport_to_pass),
        client_remote.InitWithNewPipeAndPassReceiver(),
        network::mojom::blink::HttpResponseHeaders::New(),
        network::mojom::blink::WebTransportStats::New());
    client_remote_.Bind(std::move(client_remote));
  }

  // Creates, connects and returns a WebTransport object with the given |url|.
  // Runs the event loop.
  WebTransport* CreateAndConnectSuccessfully(
      const V8TestingScope& scope,
      const String& url,
      WebTransportOptions* options = EmptyOptions()) {
    auto* web_transport = Create(scope, url, options);
    ConnectSuccessfully(web_transport);
    return web_transport;
  }

  SendStream* CreateSendStreamSuccessfully(const V8TestingScope& scope,
                                           WebTransport* web_transport) {
    EXPECT_CALL(*mock_web_transport_, CreateStream(_, _, _))
        .WillOnce([this](mojo::ScopedDataPipeConsumerHandle handle, Unused,
                         base::OnceCallback<void(bool, uint32_t)> callback) {
          send_stream_consumer_handle_ = std::move(handle);
          std::move(callback).Run(true, next_stream_id_++);
        });

    auto* script_state = scope.GetScriptState();
    auto send_stream_promise = web_transport->createUnidirectionalStream(
        script_state, ASSERT_NO_EXCEPTION);
    ScriptPromiseTester tester(script_state, send_stream_promise);

    tester.WaitUntilSettled();

    EXPECT_TRUE(tester.IsFulfilled());
    auto* writable = V8WritableStream::ToWrappable(scope.GetIsolate(),
                                                   tester.Value().V8Value());
    EXPECT_TRUE(writable);
    return static_cast<SendStream*>(writable);
  }

  mojo::ScopedDataPipeProducerHandle DoAcceptUnidirectionalStream() {
    mojo::ScopedDataPipeProducerHandle producer;
    mojo::ScopedDataPipeConsumerHandle consumer;

    // There's no good way to handle failure to create the pipe, so just
    // continue.
    CreateDataPipeForWebTransportTests(&producer, &consumer);

    std::move(pending_unidirectional_accept_callbacks_.front())
        .Run(next_stream_id_++, std::move(consumer));
    pending_unidirectional_accept_callbacks_.pop_front();

    return producer;
  }

  ReceiveStream* ReadReceiveStream(const V8TestingScope& scope,
                                   WebTransport* web_transport) {
    ReadableStream* streams = web_transport->incomingUnidirectionalStreams();

    v8::Local<v8::Value> v8value = ReadValueFromStream(scope, streams);

    ReadableStream* readable =
        V8ReadableStream::ToWrappable(scope.GetIsolate(), v8value);
    EXPECT_TRUE(readable);

    return static_cast<ReceiveStream*>(readable);
  }

  void BindConnector(mojo::ScopedMessagePipeHandle handle) {
    connector_.Bind(mojo::PendingReceiver<mojom::blink::WebTransportConnector>(
        std::move(handle)));
  }

  void TearDown() override {
    if (!interface_broker_)
      return;
    interface_broker_->SetBinderForTesting(
        mojom::blink::WebTransportConnector::Name_, {});
  }

  raw_ptr<const BrowserInterfaceBrokerProxy, DanglingUntriaged>
      interface_broker_ = nullptr;
  WTF::Deque<AcceptUnidirectionalStreamCallback>
      pending_unidirectional_accept_callbacks_;
  WTF::Deque<AcceptBidirectionalStreamCallback>
      pending_bidirectional_accept_callbacks_;
  test::TaskEnvironment task_environment_;
  WebTransportConnector connector_;
  std::unique_ptr<MockWebTransport> mock_web_transport_;
  mojo::Remote<network::mojom::blink::WebTransportClient> client_remote_;
  uint32_t next_stream_id_ = 0;
  mojo::ScopedDataPipeConsumerHandle send_stream_consumer_handle_;

  base::WeakPtrFactory<WebTransportTest> weak_ptr_factory_{this};
};

TEST_F(WebTransportTest, FailWithNullURL) {
  V8TestingScope scope;
  auto& exception_state = scope.GetExceptionState();
  WebTransport::Create(scope.GetScriptState(), String(), EmptyOptions(),
                       exception_state);
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(static_cast<int>(DOMExceptionCode::kSyntaxError),
            exception_state.Code());
}

TEST_F(WebTransportTest, FailWithEmptyURL) {
  V8TestingScope scope;
  auto& exception_state = scope.GetExceptionState();
  WebTransport::Create(scope.GetScriptState(), String(""), EmptyOptions(),
                       exception_state);
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(static_cast<int>(DOMExceptionCode::kSyntaxError),
            exception_state.Code());
  EXPECT_EQ("The URL '' is invalid.", exception_state.Message());
}

TEST_F(WebTransportTest, FailWithNoScheme) {
  V8TestingScope scope;
  auto& exception_state = scope.GetExceptionState();
  WebTransport::Create(scope.GetScriptState(), String("no-scheme"),
                       EmptyOptions(), exception_state);
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(static_cast<int>(DOMExceptionCode::kSyntaxError),
            exception_state.Code());
  EXPECT_EQ("The URL 'no-scheme' is invalid.", exception_state.Message());
}

TEST_F(WebTransportTest, FailWithHttpsURL) {
  V8TestingScope scope;
  auto& exception_state = scope.GetExceptionState();
  WebTransport::Create(scope.GetScriptState(), String("http://example.com/"),
                       EmptyOptions(), exception_state);
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(static_cast<int>(DOMExceptionCode::kSyntaxError),
            exception_state.Code());
  EXPECT_EQ("The URL's scheme must be 'https'. 'http' is not allowed.",
            exception_state.Message());
}

TEST_F(WebTransportTest, FailWithNoHost) {
  V8TestingScope scope;
  auto& exception_state = scope.GetExceptionState();
  WebTransport::Create(scope.GetScriptState(), String("https:///"),
                       EmptyOptions(), exception_state);
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(static_cast<int>(DOMExceptionCode::kSyntaxError),
            exception_state.Code());
  EXPECT_EQ("The URL 'https:///' is invalid.", exception_state.Message());
}

TEST_F(WebTransportTest, FailWithURLFragment) {
  V8TestingScope scope;
  auto& exception_state = scope.GetExceptionState();
  WebTransport::Create(scope.GetScriptState(),
                       String("https://example.com/#failing"), EmptyOptions(),
                       exception_state);
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(static_cast<int>(DOMExceptionCode::kSyntaxError),
            exception_state.Code());
  EXPECT_EQ(
      "The URL contains a fragment identifier ('#failing'). Fragment "
      "identifiers are not allowed in WebTransport URLs.",
      exception_state.Message());
}

TEST_F(WebTransportTest, FailByCSP) {
  V8TestingScope scope;
  scope.GetExecutionContext()
      ->GetContentSecurityPolicyForCurrentWorld()
      ->AddPolicies(ParseContentSecurityPolicies(
          "connect-src 'none'",
          network::mojom::ContentSecurityPolicyType::kEnforce,
          network::mojom::ContentSecurityPolicySource::kHTTP,
          *(scope.GetExecutionContext()->GetSecurityOrigin())));
  auto* web_transport = WebTransport::Create(
      scope.GetScriptState(), String("https://example.com/"), EmptyOptions(),
      ASSERT_NO_EXCEPTION);
  ScriptPromiseTester ready_tester(
      scope.GetScriptState(), web_transport->ready(scope.GetScriptState()));
  ScriptPromiseTester closed_tester(
      scope.GetScriptState(), web_transport->closed(scope.GetScriptState()));

  test::RunPendingTasks();

  EXPECT_FALSE(web_transport->HasPendingActivity());
  EXPECT_TRUE(ready_tester.IsRejected());
  EXPECT_TRUE(closed_tester.IsRejected());
}

TEST_F(WebTransportTest, PassCSP) {
  V8TestingScope scope;
  // This doesn't work without the https:// prefix, even thought it should
  // according to
  // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/connect-src.
  scope.GetExecutionContext()
      ->GetContentSecurityPolicyForCurrentWorld()
      ->AddPolicies(ParseContentSecurityPolicies(
          "connect-src https://example.com",
          network::mojom::ContentSecurityPolicyType::kEnforce,
          network::mojom::ContentSecurityPolicySource::kHTTP,
          *(scope.GetExecutionContext()->GetSecurityOrigin())));
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com/");
  ScriptPromiseTester ready_tester(
      scope.GetScriptState(), web_transport->ready(scope.GetScriptState()));

  EXPECT_TRUE(web_transport->HasPendingActivity());

  ready_tester.WaitUntilSettled();
  EXPECT_TRUE(ready_tester.IsFulfilled());
}

TEST_F(WebTransportTest, SendConnect) {
  V8TestingScope scope;
  AddBinder(scope);
  auto* web_transport = WebTransport::Create(
      scope.GetScriptState(), String("https://example.com/"), EmptyOptions(),
      ASSERT_NO_EXCEPTION);

  test::RunPendingTasks();

  auto args = connector_.TakeConnectArgs();
  ASSERT_EQ(1u, args.size());
  EXPECT_EQ(KURL("https://example.com/"), args[0].url);
  EXPECT_TRUE(args[0].fingerprints.empty());
  EXPECT_TRUE(web_transport->HasPendingActivity());
}

TEST_F(WebTransportTest, SuccessfulConnect) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");
  ScriptPromiseTester ready_tester(
      scope.GetScriptState(), web_transport->ready(scope.GetScriptState()));

  EXPECT_TRUE(web_transport->HasPendingActivity());

  ready_tester.WaitUntilSettled();
  EXPECT_TRUE(ready_tester.IsFulfilled());
}

TEST_F(WebTransportTest, FailedConnect) {
  V8TestingScope scope;
  AddBinder(scope);
  auto* web_transport = WebTransport::Create(
      scope.GetScriptState(), String("https://example.com/"), EmptyOptions(),
      ASSERT_NO_EXCEPTION);
  ScriptPromiseTester ready_tester(
      scope.GetScriptState(), web_transport->ready(scope.GetScriptState()));
  ScriptPromiseTester closed_tester(
      scope.GetScriptState(), web_transport->closed(scope.GetScriptState()));

  test::RunPendingTasks();

  auto args = connector_.TakeConnectArgs();
  ASSERT_EQ(1u, args.size());

  mojo::Remote<network::mojom::blink::WebTransportHandshakeClient>
      handshake_client(std::move(args[0].handshake_client));

  handshake_client->OnHandshakeFailed(nullptr);

  test::RunPendingTasks();
  EXPECT_FALSE(web_transport->HasPendingActivity());
  EXPECT_TRUE(ready_tester.IsRejected());
  EXPECT_TRUE(closed_tester.IsRejected());
}

TEST_F(WebTransportTest, SendConnectWithFingerprint) {
  V8TestingScope scope;
  AddBinder(scope);
  auto* hash = MakeGarbageCollected<WebTransportHash>();
  hash->setAlgorithm("sha-256");
  constexpr uint8_t kPattern[] = {
      0xED, 0x3D, 0xD7, 0xC3, 0x67, 0x10, 0x94, 0x68, 0xD1, 0xDC, 0xD1,
      0x26, 0x5C, 0xB2, 0x74, 0xD7, 0x1C, 0xA2, 0x63, 0x3E, 0x94, 0x94,
      0xC0, 0x84, 0x39, 0xD6, 0x64, 0xFA, 0x08, 0xB9, 0x77, 0x37,
  };
  DOMUint8Array* hashValue = DOMUint8Array::Create(kPattern);
  hash->setValue(MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferView>(
      NotShared<DOMUint8Array>(hashValue)));
  auto* options = MakeGarbageCollected<WebTransportOptions>();
  options->setServerCertificateHashes({hash});
  WebTransport::Create(scope.GetScriptState(), String("https://example.com/"),
                       options, ASSERT_NO_EXCEPTION);

  test::RunPendingTasks();

  auto args = connector_.TakeConnectArgs();
  ASSERT_EQ(1u, args.size());
  ASSERT_EQ(1u, args[0].fingerprints.size());
  EXPECT_EQ(args[0].fingerprints[0]->algorithm, "sha-256");
  EXPECT_EQ(args[0].fingerprints[0]->fingerprint,
            "ED:3D:D7:C3:67:10:94:68:D1:DC:D1:26:5C:B2:74:D7:1C:A2:63:3E:94:94:"
            "C0:84:39:D6:64:FA:08:B9:77:37");
}

TEST_F(WebTransportTest, SendConnectWithArrayBufferHash) {
  V8TestingScope scope;
  AddBinder(scope);
  auto* hash = MakeGarbageCollected<WebTransportHash>();
  hash->setAlgorithm("sha-256");
  constexpr uint8_t kPattern[] = {0x28, 0x24, 0xa8, 0xa2};
  DOMArrayBuffer* hashValue = DOMArrayBuffer::Create(kPattern);
  hash->setValue(
      MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferView>(hashValue));
  auto* options = MakeGarbageCollected<WebTransportOptions>();
  options->setServerCertificateHashes({hash});
  WebTransport::Create(scope.GetScriptState(), String("https://example.com/"),
                       options, ASSERT_NO_EXCEPTION);

  test::RunPendingTasks();

  auto args = connector_.TakeConnectArgs();
  ASSERT_EQ(1u, args.size());
  ASSERT_EQ(1u, args[0].fingerprints.size());
  EXPECT_EQ(args[0].fingerprints[0]->algorithm, "sha-256");
  EXPECT_EQ(args[0].fingerprints[0]->fingerprint, "28:24:A8:A2");
}

TEST_F(WebTransportTest, SendConnectWithOffsetArrayBufferViewHash) {
  V8TestingScope scope;
  AddBinder(scope);
  auto* hash = MakeGarbageCollected<WebTransportHash>();
  hash->setAlgorithm("sha-256");
  constexpr uint8_t kPattern[6] = {0x28, 0x24, 0xa8, 0xa2, 0x44, 0xee};
  DOMArrayBuffer* buffer = DOMArrayBuffer::Create(kPattern);
  DOMUint8Array* view = DOMUint8Array::Create(buffer, 2, 3);
  hash->setValue(MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferView>(
      NotShared<DOMUint8Array>(view)));
  auto* options = MakeGarbageCollected<WebTransportOptions>();
  options->setServerCertificateHashes({hash});
  WebTransport::Create(scope.GetScriptState(), String("https://example.com/"),
                       options, ASSERT_NO_EXCEPTION);

  test::RunPendingTasks();

  auto args = connector_.TakeConnectArgs();
  ASSERT_EQ(1u, args.size());
  ASSERT_EQ(1u, args[0].fingerprints.size());
  EXPECT_EQ(args[0].fingerprints[0]->algorithm, "sha-256");
  EXPECT_EQ(args[0].fingerprints[0]->fingerprint, "A8:A2:44");
}

// Regression test for https://crbug.com/1242185.
TEST_F(WebTransportTest, SendConnectWithInvalidFingerprint) {
  V8TestingScope scope;
  AddBinder(scope);
  auto* hash = MakeGarbageCollected<WebTransportHash>();
  // "algorithm" is unset.
  constexpr uint8_t kPattern[] = {
      0xED, 0x3D, 0xD7, 0xC3, 0x67, 0x10, 0x94, 0x68, 0xD1, 0xDC, 0xD1,
      0x26, 0x5C, 0xB2, 0x74, 0xD7, 0x1C, 0xA2, 0x63, 0x3E, 0x94, 0x94,
      0xC0, 0x84, 0x39, 0xD6, 0x64, 0xFA, 0x08, 0xB9, 0x77, 0x37,
  };
  DOMUint8Array* hashValue = DOMUint8Array::Create(kPattern);
  hash->setValue(MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferView>(
      NotShared<DOMUint8Array>(hashValue)));
  auto* options = MakeGarbageCollected<WebTransportOptions>();
  options->setServerCertificateHashes({hash});
  WebTransport::Create(scope.GetScriptState(), String("https://example.com/"),
                       options, ASSERT_NO_EXCEPTION);

  test::RunPendingTasks();

  auto args = connector_.TakeConnectArgs();
  ASSERT_EQ(1u, args.size());
  ASSERT_EQ(0u, args[0].fingerprints.size());
}

TEST_F(WebTransportTest, CloseDuringConnect) {
  V8TestingScope scope;
  AddBinder(scope);
  auto* web_transport = WebTransport::Create(
      scope.GetScriptState(), String("https://example.com/"), EmptyOptions(),
      ASSERT_NO_EXCEPTION);
  ScriptPromiseTester ready_tester(
      scope.GetScriptState(), web_transport->ready(scope.GetScriptState()));
  ScriptPromiseTester closed_tester(
      scope.GetScriptState(), web_transport->closed(scope.GetScriptState()));

  test::RunPendingTasks();

  auto args = connector_.TakeConnectArgs();
  ASSERT_EQ(1u, args.size());

  web_transport->close(nullptr);

  test::RunPendingTasks();

  EXPECT_FALSE(web_transport->HasPendingActivity());
  EXPECT_TRUE(ready_tester.IsRejected());
  EXPECT_TRUE(closed_tester.IsRejected());
}

TEST_F(WebTransportTest, CloseAfterConnection) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");
  EXPECT_CALL(*mock_web_transport_, Close(42, String("because")));

  ScriptPromiseTester ready_tester(
      scope.GetScriptState(), web_transport->ready(scope.GetScriptState()));
  ScriptPromiseTester closed_tester(
      scope.GetScriptState(), web_transport->closed(scope.GetScriptState()));

  WebTransportCloseInfo* close_info =
      MakeGarbageCollected<WebTransportCloseInfo>();
  close_info->setCloseCode(42);
  close_info->setReason("because");
  web_transport->close(close_info);

  test::RunPendingTasks();

  EXPECT_FALSE(web_transport->HasPendingActivity());
  EXPECT_TRUE(ready_tester.IsFulfilled());
  EXPECT_TRUE(closed_tester.IsFulfilled());

  // Calling close again does nothing.
  web_transport->close(nullptr);
}

TEST_F(WebTransportTest, CloseWithNull) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  EXPECT_CALL(*mock_web_transport_, Close());

  ScriptPromiseTester ready_tester(
      scope.GetScriptState(), web_transport->ready(scope.GetScriptState()));
  ScriptPromiseTester closed_tester(
      scope.GetScriptState(), web_transport->closed(scope.GetScriptState()));

  web_transport->close(nullptr);

  test::RunPendingTasks();

  EXPECT_FALSE(web_transport->HasPendingActivity());
  EXPECT_TRUE(ready_tester.IsFulfilled());
  EXPECT_TRUE(closed_tester.IsFulfilled());

  // TODO(yhirano): Make sure Close() is called.
}

TEST_F(WebTransportTest, CloseWithReasonOnly) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  EXPECT_CALL(*mock_web_transport_, Close(0, String("because")));

  ScriptPromiseTester ready_tester(
      scope.GetScriptState(), web_transport->ready(scope.GetScriptState()));
  ScriptPromiseTester closed_tester(
      scope.GetScriptState(), web_transport->closed(scope.GetScriptState()));

  WebTransportCloseInfo* close_info =
      MakeGarbageCollected<WebTransportCloseInfo>();
  close_info->setReason("because");
  web_transport->close(close_info);

  test::RunPendingTasks();
}

// A live connection will be kept alive even if there is no explicit reference.
// When the underlying connection is shut down, the connection will be swept.
TEST_F(WebTransportTest, GarbageCollection) {
  V8TestingScope scope;

  WeakPersistent<WebTransport> web_transport;

  auto* isolate = scope.GetIsolate();

  {
    // The streams created when creating a WebTransport create some v8 handles.
    // To ensure these are collected, we need to create a handle scope. This is
    // not a problem for garbage collection in normal operation.
    v8::HandleScope handle_scope(isolate);
    web_transport = CreateAndConnectSuccessfully(scope, "https://example.com");
    EXPECT_CALL(*mock_web_transport_, Close());
  }

  // Pretend the stack is empty. This will avoid accidentally treating any
  // copies of the |web_transport| pointer as references.
  ThreadState::Current()->CollectAllGarbageForTesting();

  EXPECT_TRUE(web_transport);

  {
    v8::HandleScope handle_scope(isolate);
    web_transport->close(nullptr);
  }

  test::RunPendingTasks();

  ThreadState::Current()->CollectAllGarbageForTesting();

  EXPECT_FALSE(web_transport);
}

TEST_F(WebTransportTest, GarbageCollectMojoConnectionError) {
  V8TestingScope scope;

  WeakPersistent<WebTransport> web_transport;

  {
    v8::HandleScope handle_scope(scope.GetIsolate());
    web_transport = CreateAndConnectSuccessfully(scope, "https://example.com");
  }

  ScriptPromiseTester closed_tester(
      scope.GetScriptState(), web_transport->closed(scope.GetScriptState()));

  // Closing the server-side of the pipe causes a mojo connection error.
  client_remote_.reset();

  test::RunPendingTasks();

  ThreadState::Current()->CollectAllGarbageForTesting();

  EXPECT_FALSE(web_transport);
  EXPECT_TRUE(closed_tester.IsRejected());
}

TEST_F(WebTransportTest, SendDatagram) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  EXPECT_CALL(*mock_web_transport_, SendDatagram(ElementsAre('A'), _))
      .WillOnce(Invoke([](base::span<const uint8_t>,
                          MockWebTransport::SendDatagramCallback callback) {
        std::move(callback).Run(true);
      }));

  auto* writable = web_transport->datagrams()->writable();
  auto* script_state = scope.GetScriptState();
  auto* writer = writable->getWriter(script_state, ASSERT_NO_EXCEPTION);
  auto* chunk = DOMUint8Array::Create(1);
  *chunk->Data() = 'A';
  auto result =
      writer->write(script_state, ScriptValue::From(script_state, chunk),
                    ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, result);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  EXPECT_TRUE(tester.Value().IsUndefined());
}

// TODO(yhirano): Move this to datagram_duplex_stream_test.cc.
TEST_F(WebTransportTest, BackpressureForOutgoingDatagrams) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  EXPECT_CALL(*mock_web_transport_, SendDatagram(_, _))
      .Times(4)
      .WillRepeatedly(
          Invoke([](base::span<const uint8_t>,
                    MockWebTransport::SendDatagramCallback callback) {
            std::move(callback).Run(true);
          }));

  web_transport->datagrams()->setOutgoingHighWaterMark(3);
  auto* writable = web_transport->datagrams()->writable();
  auto* script_state = scope.GetScriptState();
  auto* writer = writable->getWriter(script_state, ASSERT_NO_EXCEPTION);

  ScriptPromise<IDLUndefined> promise1;
  ScriptPromise<IDLUndefined> promise2;
  ScriptPromise<IDLUndefined> promise3;
  ScriptPromise<IDLUndefined> promise4;

  {
    auto* chunk = DOMUint8Array::Create(1);
    *chunk->Data() = 'A';
    promise1 =
        writer->write(script_state, ScriptValue::From(script_state, chunk),
                      ASSERT_NO_EXCEPTION);
  }
  {
    auto* chunk = DOMUint8Array::Create(1);
    *chunk->Data() = 'B';
    promise2 =
        writer->write(script_state, ScriptValue::From(script_state, chunk),
                      ASSERT_NO_EXCEPTION);
  }
  {
    auto* chunk = DOMUint8Array::Create(1);
    *chunk->Data() = 'C';
    promise3 =
        writer->write(script_state, ScriptValue::From(script_state, chunk),
                      ASSERT_NO_EXCEPTION);
  }
  {
    auto* chunk = DOMUint8Array::Create(1);
    *chunk->Data() = 'D';
    promise4 =
        writer->write(script_state, ScriptValue::From(script_state, chunk),
                      ASSER
"""


```
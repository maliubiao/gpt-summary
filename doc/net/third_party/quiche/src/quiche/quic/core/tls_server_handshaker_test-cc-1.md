Response:
The user wants a summary of the functionality of the provided C++ code, which is a test file for the TLS server handshaker in the Chromium QUIC stack.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Subject:** The file name `tls_server_handshaker_test.cc` clearly indicates that this code tests the `TlsServerHandshaker` class. This class is responsible for handling the TLS handshake on the server side in a QUIC connection.

2. **Recognize Testing Context:** The `.cc` extension and the presence of `TEST_P` macros strongly suggest that this is a unit test file using Google Test. The `TEST_P` indicates parameterized tests, meaning the tests are run with different configurations (likely different QUIC versions, as seen in the `GetParam()` calls).

3. **Scan for Key Functionalities (based on test names):**  Quickly read through the `TEST_P` functions to get an overview of what's being tested:
    * `Resumption` and `ZeroRttResumption`:  Testing session resumption and zero-RTT connection establishment.
    * `DecryptCallback`:  Focus on asynchronous ticket decryption.
    * `FailingProofSource`: Testing behavior when the proof source (certificate provider) fails.
    * `RequestClientCert`: Testing different modes of client certificate handling.
    * `SetInvalidServerTransportParamsByDelayedSslConfig` and `SetValidServerTransportParamsByDelayedSslConfig`: Testing how server transport parameters are set via a delayed SSL configuration.
    * `CloseConnectionBeforeSelectCert`: Testing connection closure during the handshake.
    * `FailUponCustomTranportParam` and `SuccessWithCustomTranportParam`: Testing handling of custom transport parameters.
    * `EnableKyber`: Testing support for the Kyber post-quantum key exchange algorithm.
    * `AlpsUseNewCodepoint`: Testing the Application Layer Protocol Settings (ALPS) extension with potentially new codepoints.

4. **Group Related Tests:** Notice that several tests relate to resumption, client certificates, and delayed SSL configuration. Grouping these helps in summarizing.

5. **Identify Setup and Helper Functions:** The code uses functions like `InitializeFakeClient`, `InitializeServer`, `CompleteCryptoHandshake`, `ExpectHandshakeSuccessful`, `SetupClientCert`, and `InitializeServerConfigWithFailingProofSource`. These are helper functions to set up the test environment and perform common actions, which is a common pattern in testing.

6. **Look for Assertions and Expectations:** The `ASSERT_TRUE`, `EXPECT_TRUE`, `EXPECT_FALSE`, and `EXPECT_EQ` macros are used to verify the expected behavior of the `TlsServerHandshaker`. These checks are crucial for understanding the purpose of each test.

7. **Consider the Parameterization (`GetParam()`):** The frequent use of `GetParam()` suggests that the tests are designed to run against different QUIC versions or configurations, including scenarios where resumption is disabled.

8. **Address Specific Questions from the Prompt:**
    * **JavaScript Relationship:**  Since this is a low-level networking component, it doesn't have a direct, immediate relationship with JavaScript. However, it's part of the browser's networking stack, which *enables* JavaScript to perform network requests.
    * **Logic and Assumptions:** For tests involving failures, the assumption is that the injected failure mechanism (e.g., `ticket_crypter_->set_fail_decrypt(true)`) correctly simulates the failure. The input is the sequence of handshake messages exchanged, and the output is the resulting state of the connection (success, failure, specific error codes).
    * **User/Programming Errors:**  The tests implicitly highlight potential programming errors in the `TlsServerHandshaker` implementation, such as incorrect handling of decryption failures, proof source errors, or invalid transport parameters. User errors aren't directly tested here but the code ensures the system handles certain scenarios gracefully (e.g., no client cert when requested).
    * **User Operations and Debugging:** The test scenarios provide debugging clues by simulating various handshake flows and failure conditions. A developer debugging handshake issues could look at these tests to understand how different scenarios are handled.

9. **Synthesize the Summary:** Combine the identified functionalities and address the specific questions in a concise and informative manner.

10. **Address Part 2 Specific Request:** The prompt explicitly asks for a summary *of this specific code snippet*. Therefore, focus on the tests *within this given block* and avoid repeating information from the first part unless it's directly relevant to understanding the current snippet. In this part, the emphasis is on:
    * Resumption with decryption failures (both synchronous and asynchronous).
    * Handshake failure due to a failing proof source.
    * Zero-RTT resumption and its rejection based on application state changes.
    * Client certificate requests (with and without a client certificate present).
    * Handling of server transport parameters via delayed SSL configuration.
    * Connection closure scenarios during handshake.
    * Handling of custom transport parameters (both successful and failing cases).
    * Testing for post-quantum cryptography (Kyber).
    * Testing for ALPS new codepoint support.
这是对 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/tls_server_handshaker_test.cc` 文件部分代码的分析和功能归纳。由于这是第二部分，我们将重点关注这部分代码所测试的具体功能，并结合之前分析的总体功能进行总结。

**这部分代码主要测试了 `TlsServerHandshaker` 的以下功能：**

1. **会话恢复 (Resumption) 的高级场景:**
   - **`ResumptionWithFailingDecryptCallback`:** 测试当恢复会话时，如果解密会话票据的回调函数失败，服务器能否正确处理并完成新的握手。
   - **`ResumptionWithFailingAsyncDecryptCallback`:**  与上一个测试类似，但针对异步解密回调失败的情况。这验证了异步操作失败时的处理逻辑。
   - **推断逻辑:** 假设第一次握手成功建立了会话，并保存了会话票据。第二次握手尝试恢复会话，但由于 `ticket_crypter_->set_fail_decrypt(true)`，解密会话票据失败。期望服务器仍然能完成握手，但不会是恢复会话。
   - **用户/编程错误:**  开发者可能会错误地配置会话票据的解密逻辑，导致解密失败。这部分测试确保了在这种情况下服务器不会崩溃，而是回退到完整的握手流程。

2. **处理证书提供失败的情况:**
   - **`HandshakeFailsWithFailingProofSource`:** 测试当服务器获取证书的 ProofSource 失败时，握手是否会正确失败。
   - **推断逻辑:** 假设 ProofSource 配置错误或不可用。期望服务器在握手过程中无法获取证书，从而导致握手失败，并且不会发送任何握手消息。
   - **用户/编程错误:**  服务器管理员可能配置了错误的证书路径或权限，导致 ProofSource 无法正常工作。

3. **零 RTT (0-RTT) 会话恢复的限制:**
   - **`ZeroRttRejectOnApplicationStateChange`:** 测试当服务器端的应用状态发生变化时，是否会拒绝 0-RTT 会话恢复。这是为了保证 0-RTT 的安全性，防止重放攻击。
   - **推断逻辑:** 假设第一次握手成功并记录了应用状态。第二次握手尝试 0-RTT 恢复，但服务器端设置了不同的应用状态。期望服务器拒绝 0-RTT 恢复。
   - **用户/编程错误:**  开发者可能在没有充分理解 0-RTT 安全性的前提下，尝试在应用状态变化后允许 0-RTT 恢复，这可能导致安全问题。

4. **客户端证书请求和处理:**
   - **`RequestClientCert`:** 测试服务器请求客户端证书时的正常流程。
   - **`SetInvalidServerTransportParamsByDelayedSslConfig` 和 `SetValidServerTransportParamsByDelayedSslConfig`:** 测试通过延迟的 SSL 配置 (QuicDelayedSSLConfig) 设置服务器传输参数，这包括设置无效和有效的参数，以验证配置的正确性。
   - **`RequestClientCertByDelayedSslConfig`:** 测试通过延迟的 SSL 配置请求客户端证书。
   - **`RequestClientCert_NoCert`:** 测试当服务器请求客户端证书，但客户端没有提供证书时的情况。
   - **`RequestAndRequireClientCert` 和 `RequestAndRequireClientCertByDelayedSslConfig`:** 测试服务器要求客户端证书时的正常流程。
   - **`RequestAndRequireClientCert_NoCert`:** 测试当服务器要求客户端证书，但客户端没有提供证书时，连接应该被关闭。
   - **推断逻辑:**  根据 `initial_client_cert_mode_` 的设置 (kRequest, kRequire) 来模拟服务器的行为。如果设置为 kRequire 且客户端未提供证书，期望连接被关闭。
   - **用户/编程错误:**  服务器管理员可能错误地配置了客户端证书的请求模式，或者客户端用户可能没有配置客户端证书。

5. **在证书选择前关闭连接:**
   - **`CloseConnectionBeforeSelectCert`:** 测试在服务器选择证书之前，连接被关闭的情况，验证资源清理和状态管理。
   - **推断逻辑:** 模拟在服务器调用 `SelectCertificate` 之前，由于其他原因 (例如收到了 `GOAWAY` 帧) 导致连接关闭。期望不会发生崩溃，并且相关的回调不会被执行。

6. **处理自定义传输参数:**
   - **`FailUponCustomTranportParam`:** 测试当客户端发送服务器不支持的自定义传输参数时，握手应该失败。
   - **`SuccessWithCustomTranportParam`:** 测试当客户端发送服务器支持的自定义传输参数时，握手应该成功。
   - **推断逻辑:**  通过 `client_session_->config()->custom_transport_parameters_to_send()` 设置客户端发送的自定义参数。服务器根据配置决定是否接受这些参数。
   - **用户/编程错误:**  开发者可能在客户端发送了服务器不理解的自定义传输参数，导致握手失败。

7. **启用 Kyber 密钥交换算法 (如果 BoringSSL 版本支持):**
   - **`EnableKyber`:** 测试当服务器和客户端都支持 Kyber 算法时，能否成功协商并使用 Kyber 进行密钥交换。
   - **推断逻辑:** 配置服务器和客户端支持 Kyber 算法，期望握手成功，并且协商的密钥交换组是 Kyber。

8. **ALPS 新代码点支持 (如果 BoringSSL 版本支持):**
   - **`AlpsUseNewCodepoint`:** 测试在不同客户端和服务器 ALPS 代码点支持配置下，握手是否能够成功完成，并验证 `UseAlpsNewCodepoint()` 方法的返回值。
   - **推断逻辑:**  通过设置 reloadable flag 和客户端配置来模拟不同的 ALPS 代码点支持情况，验证握手的兼容性。

**与 JavaScript 的关系：**

虽然此代码是 C++ 编写的底层网络协议实现，但它直接影响着 JavaScript 在浏览器中的网络行为。例如：

* **会话恢复和 0-RTT:**  这些功能可以显著提升网页加载速度，用户在 JavaScript 中发起网络请求时，如果可以复用之前的连接，将无需重新进行完整的 TLS 握手，从而更快地获取资源。
* **客户端证书:**  一些需要身份验证的网站可能会要求客户端提供证书，这部分 C++ 代码负责处理服务器端的证书请求和验证，最终决定 JavaScript 发起的请求是否被允许。
* **自定义传输参数:**  虽然不常见，但 QUIC 允许自定义传输参数，这可以用于扩展协议功能。JavaScript 通过浏览器 API 发起的请求，其底层的 QUIC 连接可能会包含这些自定义参数。
* **安全性和加密:** TLS 握手是保证网络连接安全的关键步骤，这部分代码的正确性直接影响到用户通过 JavaScript 访问网站时的安全。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入网址或点击链接，发起 HTTPS 请求。**
2. **浏览器发现需要建立 QUIC 连接 (如果服务器支持且浏览器配置允许)。**
3. **浏览器作为 QUIC 客户端，开始与服务器进行 QUIC 握手。**
4. **服务器端的 `TlsServerHandshaker` 负责处理来自客户端的握手消息。**
5. **如果涉及到会话恢复，`TlsServerHandshaker` 会尝试解密会话票据。**
6. **如果服务器配置了需要客户端证书，`TlsServerHandshaker` 会发送请求客户端证书的消息。**
7. **如果涉及到自定义传输参数，`TlsServerHandshaker` 会解析客户端发送的参数。**
8. **在调试过程中，开发者可能会在 `TlsServerHandshaker` 的相关代码中设置断点，以观察握手过程中的状态变化、消息内容以及错误处理逻辑。**
9. **例如，如果用户报告连接失败或安全错误，开发者可能会检查 `HandshakeFailsWithFailingProofSource` 类似的测试场景，以确定是否是服务器证书配置问题。**
10. **如果用户报告首次加载慢，但后续加载快，开发者可能会关注会话恢复相关的测试，例如 `ResumptionWithFailingDecryptCallback`，以排查会话恢复失败的原因。**

**功能归纳（针对第二部分代码）：**

这部分 `TlsServerHandshakerTest` 代码专注于测试 TLS 服务器握手器在更细致和异常情况下的行为。它涵盖了会话恢复过程中解密失败的处理、证书提供失败时的容错、对不安全的 0-RTT 恢复的拒绝、以及对客户端证书请求和不同配置的处理。此外，还测试了在握手过程中连接被提前关闭的情况，以及对自定义传输参数的处理能力。最后，针对较新版本的 BoringSSL，还包含了对 Kyber 密钥交换算法和 ALPS 新代码点支持的测试。 这些测试确保了 `TlsServerHandshaker` 的健壮性、安全性和对各种配置的支持。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/tls_server_handshaker_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""

      /*compute_signature_action=*/FakeProofSourceHandle::Action::
          DELEGATE_SYNC);
  InitializeFakeClient();

  AdvanceHandshakeWithFakeClient();

  // Ensure an async DecryptCallback is now pending.
  ASSERT_EQ(ticket_crypter_->NumPendingCallbacks(), 1u);

  {
    QuicConnection::ScopedPacketFlusher flusher(server_connection_);
    server_handshaker_->AdvanceHandshake();
  }

  // This will delete |server_handshaker_|.
  server_session_ = nullptr;

  ticket_crypter_->RunPendingCallback(0);  // Should not crash.
}

TEST_P(TlsServerHandshakerTest, ResumptionWithFailingDecryptCallback) {
  if (GetParam().disable_resumption) {
    return;
  }

  // Do the first handshake
  InitializeFakeClient();
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();

  ticket_crypter_->set_fail_decrypt(true);
  // Now do another handshake
  InitializeServer();
  InitializeFakeClient();
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_FALSE(client_stream()->IsResumption());
  EXPECT_FALSE(server_stream()->IsResumption());
  EXPECT_TRUE(server_stream()->ResumptionAttempted());
}

TEST_P(TlsServerHandshakerTest, ResumptionWithFailingAsyncDecryptCallback) {
  if (GetParam().disable_resumption) {
    return;
  }

  // Do the first handshake
  InitializeFakeClient();
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();

  ticket_crypter_->set_fail_decrypt(true);
  ticket_crypter_->SetRunCallbacksAsync(true);
  // Now do another handshake
  InitializeServer();
  InitializeFakeClient();

  AdvanceHandshakeWithFakeClient();
  // Test that the DecryptCallback will be run asynchronously, and then run it.
  ASSERT_EQ(ticket_crypter_->NumPendingCallbacks(), 1u);
  ticket_crypter_->RunPendingCallback(0);

  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_FALSE(client_stream()->IsResumption());
  EXPECT_FALSE(server_stream()->IsResumption());
  EXPECT_TRUE(server_stream()->ResumptionAttempted());
}

TEST_P(TlsServerHandshakerTest, HandshakeFailsWithFailingProofSource) {
  InitializeServerConfigWithFailingProofSource();
  InitializeServer();
  InitializeFakeClient();

  // Attempt handshake.
  AdvanceHandshakeWithFakeClient();
  // Check that the server didn't send any handshake messages, because it failed
  // to handshake.
  EXPECT_EQ(moved_messages_counts_.second, 0u);
}

TEST_P(TlsServerHandshakerTest, ZeroRttResumption) {
  std::vector<uint8_t> application_state = {0, 1, 2, 3};

  // Do the first handshake
  server_stream()->SetServerApplicationStateForResumption(
      std::make_unique<ApplicationState>(application_state));
  InitializeFakeClient();
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_FALSE(client_stream()->IsResumption());
  EXPECT_FALSE(server_stream()->IsZeroRtt());

  // Now do another handshake
  InitializeServer();
  server_stream()->SetServerApplicationStateForResumption(
      std::make_unique<ApplicationState>(application_state));
  InitializeFakeClient();
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_NE(client_stream()->IsResumption(), GetParam().disable_resumption);
  EXPECT_NE(server_stream()->IsZeroRtt(), GetParam().disable_resumption);
}

TEST_P(TlsServerHandshakerTest, ZeroRttRejectOnApplicationStateChange) {
  std::vector<uint8_t> original_application_state = {1, 2};
  std::vector<uint8_t> new_application_state = {3, 4};

  // Do the first handshake
  server_stream()->SetServerApplicationStateForResumption(
      std::make_unique<ApplicationState>(original_application_state));
  InitializeFakeClient();
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_FALSE(client_stream()->IsResumption());
  EXPECT_FALSE(server_stream()->IsZeroRtt());

  // Do another handshake, but change the application state
  InitializeServer();
  server_stream()->SetServerApplicationStateForResumption(
      std::make_unique<ApplicationState>(new_application_state));
  InitializeFakeClient();
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_NE(client_stream()->IsResumption(), GetParam().disable_resumption);
  EXPECT_FALSE(server_stream()->IsZeroRtt());
}

TEST_P(TlsServerHandshakerTest, RequestClientCert) {
  ASSERT_TRUE(SetupClientCert());
  InitializeFakeClient();

  initial_client_cert_mode_ = ClientCertMode::kRequest;
  InitializeServerWithFakeProofSourceHandle();
  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_SYNC,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::
          DELEGATE_SYNC);

  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_TRUE(server_handshaker_->received_client_cert());
}

TEST_P(TlsServerHandshakerTest,
       SetInvalidServerTransportParamsByDelayedSslConfig) {
  ASSERT_TRUE(SetupClientCert());
  InitializeFakeClient();

  QuicDelayedSSLConfig delayed_ssl_config;
  delayed_ssl_config.quic_transport_parameters = {1, 2, 3};
  InitializeServerWithFakeProofSourceHandle();
  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_ASYNC,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::DELEGATE_SYNC,
      delayed_ssl_config);

  AdvanceHandshakeWithFakeClient();
  ASSERT_TRUE(
      server_handshaker_->fake_proof_source_handle()->HasPendingOperation());
  server_handshaker_->fake_proof_source_handle()->CompletePendingOperation();

  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_FALSE(server_handshaker_->fake_proof_source_handle()
                   ->all_compute_signature_args()
                   .empty());
}

TEST_P(TlsServerHandshakerTest,
       SetValidServerTransportParamsByDelayedSslConfig) {
  ParsedQuicVersion version = GetParam().version;

  TransportParameters server_params;
  std::string error_details;
  server_params.perspective = quic::Perspective::IS_SERVER;
  server_params.legacy_version_information =
      TransportParameters::LegacyVersionInformation();
  server_params.legacy_version_information.value().supported_versions =
      quic::CreateQuicVersionLabelVector(
          quic::ParsedQuicVersionVector{version});
  server_params.legacy_version_information.value().version =
      quic::CreateQuicVersionLabel(version);
  server_params.version_information = TransportParameters::VersionInformation();
  server_params.version_information.value().chosen_version =
      quic::CreateQuicVersionLabel(version);
  server_params.version_information.value().other_versions =
      quic::CreateQuicVersionLabelVector(
          quic::ParsedQuicVersionVector{version});

  ASSERT_TRUE(server_params.AreValid(&error_details)) << error_details;

  std::vector<uint8_t> server_params_bytes;
  ASSERT_TRUE(
      SerializeTransportParameters(server_params, &server_params_bytes));

  ASSERT_TRUE(SetupClientCert());
  InitializeFakeClient();

  QuicDelayedSSLConfig delayed_ssl_config;
  delayed_ssl_config.quic_transport_parameters = server_params_bytes;
  InitializeServerWithFakeProofSourceHandle();
  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_ASYNC,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::DELEGATE_SYNC,
      delayed_ssl_config);

  AdvanceHandshakeWithFakeClient();
  ASSERT_TRUE(
      server_handshaker_->fake_proof_source_handle()->HasPendingOperation());
  server_handshaker_->fake_proof_source_handle()->CompletePendingOperation();

  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_FALSE(server_handshaker_->fake_proof_source_handle()
                   ->all_compute_signature_args()
                   .empty());
}

TEST_P(TlsServerHandshakerTest, RequestClientCertByDelayedSslConfig) {
  ASSERT_TRUE(SetupClientCert());
  InitializeFakeClient();

  QuicDelayedSSLConfig delayed_ssl_config;
  delayed_ssl_config.client_cert_mode = ClientCertMode::kRequest;
  InitializeServerWithFakeProofSourceHandle();
  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_ASYNC,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::DELEGATE_SYNC,
      delayed_ssl_config);

  AdvanceHandshakeWithFakeClient();
  ASSERT_TRUE(
      server_handshaker_->fake_proof_source_handle()->HasPendingOperation());
  server_handshaker_->fake_proof_source_handle()->CompletePendingOperation();

  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_TRUE(server_handshaker_->received_client_cert());
}

TEST_P(TlsServerHandshakerTest, RequestClientCert_NoCert) {
  initial_client_cert_mode_ = ClientCertMode::kRequest;
  InitializeServerWithFakeProofSourceHandle();
  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_SYNC,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::
          DELEGATE_SYNC);

  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_FALSE(server_handshaker_->received_client_cert());
}

TEST_P(TlsServerHandshakerTest, RequestAndRequireClientCert) {
  ASSERT_TRUE(SetupClientCert());
  InitializeFakeClient();

  initial_client_cert_mode_ = ClientCertMode::kRequire;
  InitializeServerWithFakeProofSourceHandle();
  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_SYNC,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::
          DELEGATE_SYNC);

  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_TRUE(server_handshaker_->received_client_cert());
}

TEST_P(TlsServerHandshakerTest, RequestAndRequireClientCertByDelayedSslConfig) {
  ASSERT_TRUE(SetupClientCert());
  InitializeFakeClient();

  QuicDelayedSSLConfig delayed_ssl_config;
  delayed_ssl_config.client_cert_mode = ClientCertMode::kRequire;
  InitializeServerWithFakeProofSourceHandle();
  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_ASYNC,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::DELEGATE_SYNC,
      delayed_ssl_config);

  AdvanceHandshakeWithFakeClient();
  ASSERT_TRUE(
      server_handshaker_->fake_proof_source_handle()->HasPendingOperation());
  server_handshaker_->fake_proof_source_handle()->CompletePendingOperation();

  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_TRUE(server_handshaker_->received_client_cert());
}

TEST_P(TlsServerHandshakerTest, RequestAndRequireClientCert_NoCert) {
  initial_client_cert_mode_ = ClientCertMode::kRequire;
  InitializeServerWithFakeProofSourceHandle();
  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_SYNC,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::
          DELEGATE_SYNC);

  EXPECT_CALL(*server_connection_,
              CloseConnection(QUIC_TLS_CERTIFICATE_REQUIRED, _, _, _));

  AdvanceHandshakeWithFakeClient();
  AdvanceHandshakeWithFakeClient();
  EXPECT_FALSE(server_handshaker_->received_client_cert());
}

TEST_P(TlsServerHandshakerTest, CloseConnectionBeforeSelectCert) {
  InitializeServerWithFakeProofSourceHandle();
  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::
          FAIL_SYNC_DO_NOT_CHECK_CLOSED,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::
          FAIL_SYNC_DO_NOT_CHECK_CLOSED);

  EXPECT_CALL(*server_handshaker_, OverrideQuicConfigDefaults(_))
      .WillOnce(testing::Invoke([](QuicConfig* config) {
        QuicConfigPeer::SetReceivedMaxUnidirectionalStreams(config,
                                                            /*max_streams=*/0);
      }));

  EXPECT_CALL(*server_connection_,
              CloseConnection(QUIC_ZERO_RTT_RESUMPTION_LIMIT_REDUCED, _, _))
      .WillOnce(testing::Invoke(
          [this](QuicErrorCode error, const std::string& details,
                 ConnectionCloseBehavior connection_close_behavior) {
            server_connection_->ReallyCloseConnection(
                error, details, connection_close_behavior);
            ASSERT_FALSE(server_connection_->connected());
          }));

  AdvanceHandshakeWithFakeClient();

  EXPECT_TRUE(server_handshaker_->fake_proof_source_handle()
                  ->all_select_cert_args()
                  .empty());
}

TEST_P(TlsServerHandshakerTest, FailUponCustomTranportParam) {
  client_session_->config()->custom_transport_parameters_to_send().emplace(
      TestTlsServerHandshaker::kFailHandshakeParam,
      "Fail handshake upon seeing this.");

  InitializeServerWithFakeProofSourceHandle();
  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_ASYNC,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::
          DELEGATE_SYNC);
  EXPECT_CALL(
      *server_connection_,
      CloseConnection(QUIC_HANDSHAKE_FAILED,
                      "Failed to process additional transport parameters", _));

  // Start handshake.
  AdvanceHandshakeWithFakeClient();
}

TEST_P(TlsServerHandshakerTest, SuccessWithCustomTranportParam) {
  client_session_->config()->custom_transport_parameters_to_send().emplace(
      TransportParameters::TransportParameterId{0xFFEADD},
      "Continue upon seeing this.");

  InitializeServerWithFakeProofSourceHandle();
  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_ASYNC,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::
          DELEGATE_SYNC);
  EXPECT_CALL(*server_connection_, CloseConnection(_, _, _)).Times(0);

  // Start handshake.
  AdvanceHandshakeWithFakeClient();
  ASSERT_TRUE(
      server_handshaker_->fake_proof_source_handle()->HasPendingOperation());
  server_handshaker_->fake_proof_source_handle()->CompletePendingOperation();

  CompleteCryptoHandshake();

  ExpectHandshakeSuccessful();
}

#if BORINGSSL_API_VERSION >= 22
TEST_P(TlsServerHandshakerTest, EnableKyber) {
  server_crypto_config_->set_preferred_groups(
      {SSL_GROUP_X25519_KYBER768_DRAFT00});
  client_crypto_config_->set_preferred_groups(
      {SSL_GROUP_X25519_KYBER768_DRAFT00, SSL_GROUP_X25519, SSL_GROUP_SECP256R1,
       SSL_GROUP_SECP384R1});

  InitializeServer();
  InitializeFakeClient();
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_EQ(PROTOCOL_TLS1_3, server_stream()->handshake_protocol());
  EXPECT_EQ(SSL_GROUP_X25519_KYBER768_DRAFT00,
            SSL_get_group_id(server_stream()->GetSsl()));
}
#endif  // BORINGSSL_API_VERSION

#if BORINGSSL_API_VERSION >= 27
TEST_P(TlsServerHandshakerTest, AlpsUseNewCodepoint) {
  const struct {
    bool client_use_alps_new_codepoint;
    bool server_allow_alps_new_codepoint;
  } tests[] = {
      // The intent of this test is to demonstrate different combinations of
      // ALPS codepoint settings works well for both client and server.
      {true, true},
      {false, true},
      {false, false},
      {true, true},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    SCOPED_TRACE(absl::StrCat("Test #", i));
    const auto& test = tests[i];
    client_crypto_config_->set_alps_use_new_codepoint(
        test.client_use_alps_new_codepoint);
    SetQuicReloadableFlag(quic_gfe_allow_alps_new_codepoint,
                          test.server_allow_alps_new_codepoint);

    ASSERT_TRUE(SetupClientCert());
    InitializeFakeClient();

    InitializeServerWithFakeProofSourceHandle();
    server_handshaker_->SetupProofSourceHandle(
        /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_SYNC,
        /*compute_signature_action=*/FakeProofSourceHandle::Action::
            DELEGATE_SYNC);

    // Start handshake.
    AdvanceHandshakeWithFakeClient();
    EXPECT_EQ(test.client_use_alps_new_codepoint,
              server_handshaker_->UseAlpsNewCodepoint());

    CompleteCryptoHandshake();
    ExpectHandshakeSuccessful();
    EXPECT_EQ(PROTOCOL_TLS1_3, server_stream()->handshake_protocol());
  }
}
#endif  // BORINGSSL_API_VERSION

}  // namespace
}  // namespace test
}  // namespace quic

"""


```
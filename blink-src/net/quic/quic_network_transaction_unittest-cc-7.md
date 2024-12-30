Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium networking test file. They're particularly interested in:

1. **General functionality:** What does this specific part of the test file do?
2. **Relation to JavaScript:**  Is there any connection to JavaScript functionality?
3. **Logical reasoning:** If there's conditional logic, what are the expected inputs and outputs?
4. **Common user/programming errors:**  What mistakes might lead to this code being executed?
5. **User journey:** How does a user's action lead to this code?
6. **Debugging context:** How does this help in debugging?
7. **Summary of the entire file (part 8 of 13):**  Based on this snippet, what's the overall purpose of the test file?

Let's break down the analysis of the code snippet:

* **`mock_quic_data.AddRead(...)` and `mock_quic_data.AddWrite(...)`:** These lines simulate network interactions using the QUIC protocol. They define the expected sequence of data being read from and written to a QUIC connection.
* **`ConstructServerResponseHeadersPacket(...)` and `ConstructServerDataPacket(...)`:** These functions likely create QUIC packets representing server responses.
* **`ConstructClientAckPacket(...)`:** This function likely creates a QUIC packet acknowledging received data.
* **`ERR_IO_PENDING` and `ERR_CONNECTION_CLOSED`:** These are network error codes.
* **`mock_quic_data.AddSocketDataToFactory(&socket_factory_)`:** This line sets up the simulated network data for use in the tests.
* **`CreateSession()`:** This function likely creates a test QUIC session.
* **`session_->quic_session_pool()->set_has_quic_ever_worked_on_current_network(false)`:** This simulates a scenario where QUIC has not previously worked on the current network.
* **`AddQuicAlternateProtocolMapping(...)`:** This likely configures the system to consider QUIC as an alternative protocol for the current connection.
* **`host_resolver_.set_synchronous_mode(false)`:** This forces asynchronous host resolution, delaying the connection process.
* **`HttpNetworkTransaction trans(...)` and `trans.Start(...)`:** This creates and starts a network transaction, which is the core of fetching a resource.
* **`TestCompletionCallback callback`:** This is a utility for waiting for the network transaction to complete.
* **`EXPECT_THAT(...)` and `IsError(...)`:** These are assertion macros from a testing framework, checking for expected outcomes.
* **`base::RunLoop().RunUntilIdle()`:** This runs the message loop, allowing asynchronous operations to complete.
* **`crypto_client_stream_factory_.last_stream()->NotifySessionOneRttKeyAvailable()`:** This simulates the completion of the QUIC handshake.
* **`ASSERT_FALSE(mock_quic_data.AllReadDataConsumed())` and `mock_quic_data.Resume()`:** These lines control the progression of the simulated network interaction.
* **`CheckWasQuicResponse(&trans)` and `CheckResponseData(&trans, ...)`:** These functions likely verify that the response was received via QUIC and that the data is correct.
* **`DelayTCPOnStartWithQuicSupportOnDifferentIP` test:** This tests a specific scenario where QUIC support was previously seen on a different IP address.
* **`NetErrorDetailsSetBeforeHandshake` test:** This checks if error details are correctly populated even if the QUIC handshake hasn't completed.
* **`FailedZeroRttBrokenAlternateProtocol` and related tests:** These tests check how the system handles failures when trying to use QUIC as an alternate protocol.
* **`ConnectionCloseDuringConnect` tests:** These simulate the QUIC connection closing during the connection establishment phase.
* **`SecureResourceOverSecureQuic` test:** This verifies that secure resources can be fetched over a secure QUIC connection.
* **`QuicUpload` and `QuicUploadWriteError` tests:** These cover scenarios involving uploading data over QUIC.
* **`RetryAfterAsyncNoBufferSpace` and related tests:** These check how the system handles network errors like `ERR_NO_BUFFER_SPACE` and retries connections.
* **`MaxRetriesAfterAsyncNoBufferSpace` tests:** These verify the retry limits for certain network errors.
* **`NoMigrationForMsgTooBig` test:** This checks that connection migration doesn't happen for specific errors like `ERR_MSG_TOO_BIG`.
* **`QuicForceHolBlocking` test:** This likely tests how QUIC handles head-of-line blocking.
* **`HostInAllowlist` test:** This checks if a host being in the QUIC allowlist affects connection behavior.

**Overall Functionality:** The provided code snippet contains several unit tests for the `QuicNetworkTransaction` class in Chromium. These tests cover various scenarios related to establishing and using QUIC connections, including:

* **Successful QUIC connections.**
* **QUIC connections when TCP is delayed.**
* **Handling QUIC handshake completion.**
* **Fallback to TCP when QUIC fails.**
* **Handling different QUIC connection error conditions.**
* **Uploading data over QUIC.**
* **Connection retries after errors.**
* **The impact of QUIC being an "alternate protocol."**

Now, let's construct the detailed answer based on these observations.
This code snippet is part of a unit test file (`quic_network_transaction_unittest.cc`) for the `QuicNetworkTransaction` class in Chromium's networking stack. Let's break down its functionalities based on the provided examples.

**General Functionalities Demonstrated in the Snippet:**

This section of the test file primarily focuses on testing how `QuicNetworkTransaction` behaves in various scenarios involving the establishment and use of QUIC connections. Key functionalities being tested include:

1. **Successful QUIC Connection and Data Transfer:**
   - The tests simulate successful QUIC handshakes and data transfer using mocked QUIC data (`mock_quic_data`).
   - They verify that when QUIC is available and works, the `HttpNetworkTransaction` successfully fetches the resource over QUIC.
   - This includes checking the response headers and data.

2. **Delayed TCP when QUIC is Possible:**
   - Tests like `DelayTCPOnStartNoConfirmation` and `DelayTCPOnStartWithQuicSupportOnDifferentIP` examine scenarios where the initiation of a TCP connection is delayed because the system anticipates a successful QUIC connection.
   - They verify that the TCP connection doesn't proceed immediately, giving the QUIC connection a chance to establish.

3. **Handling QUIC Handshake Confirmation:**
   - Some tests involve scenarios where QUIC requires confirmation (e.g., after observing QUIC support on a different IP).
   - They check that the TCP connection is further delayed until the QUIC handshake is explicitly confirmed.

4. **Error Handling in QUIC Connections:**
   - Tests like `NetErrorDetailsSetBeforeHandshake`, `FailedZeroRttBrokenAlternateProtocol`, and `BrokenAlternateProtocolOnConnectFailure` cover how `QuicNetworkTransaction` handles various errors during the QUIC connection attempt.
   - This includes scenarios where the QUIC connection fails before the handshake, due to socket errors, or during connection establishment.

5. **Fallback to TCP when QUIC Fails:**
   - Tests like `ConnectionCloseDuringConnect` and `ConnectionCloseDuringConnectProxy` demonstrate the fallback mechanism. If the QUIC connection fails during the connection phase, the transaction should retry the request over a standard HTTP/TCP connection.

6. **Secure Connections over QUIC:**
   - The `SecureResourceOverSecureQuic` test verifies that when requesting a secure resource (HTTPS), the connection can be established and data transferred successfully over QUIC.

7. **Handling QUIC Uploads (POST Requests):**
   - Tests like `QuicUpload` and `QuicUploadWriteError` focus on how `QuicNetworkTransaction` handles HTTP POST requests with data uploads over QUIC. This includes scenarios with errors during the upload process.

8. **Connection Retries and Error Scenarios:**
   - Tests like `RetryAfterAsyncNoBufferSpace`, `RetryAfterSynchronousNoBufferSpace`, `MaxRetriesAfterAsyncNoBufferSpace`, and `MaxRetriesAfterSynchronousNoBufferSpace` explore how the system retries QUIC connections after encountering errors like `ERR_NO_BUFFER_SPACE`. They also test the limits of these retries.

9. **Specific Error Handling (e.g., MSG_TOO_BIG):**
   - The `NoMigrationForMsgTooBig` test checks how `QuicNetworkTransaction` reacts to specific errors like `ERR_MSG_TOO_BIG` and whether it triggers connection migration (in this case, it shouldn't).

10. **Head-of-Line Blocking (HOL) in QUIC:**
    - The `QuicForceHolBlocking` test likely examines scenarios related to how QUIC handles HOL blocking, though the provided snippet doesn't show the explicit HOL blocking logic.

11. **QUIC Allowlist:**
    - The `HostInAllowlist` test checks if a host being in the QUIC allowlist influences the connection attempt.

**Relationship to JavaScript Functionality:**

While this C++ code directly deals with the network layer, it has an indirect but crucial relationship with JavaScript functionality in a web browser:

- **Network Requests Initiated by JavaScript:** When a JavaScript application running in a web page makes a network request (e.g., using `fetch` or `XMLHttpRequest`), the browser's networking stack (including the code being tested here) handles the underlying connection and data transfer.
- **QUIC Protocol for Performance:** QUIC is a transport protocol designed to improve web performance. If a website supports QUIC, and the browser is configured to use it, these tests ensure that the browser's QUIC implementation works correctly when JavaScript initiates network requests to that website.

**Example:**

Imagine a JavaScript application making an HTTPS request to `https://mail.example.org/`.

1. **JavaScript `fetch()` call:**
   ```javascript
   fetch('https://mail.example.org/data.json')
     .then(response => response.json())
     .then(data => console.log(data));
   ```

2. **Browser's Network Stack:** This `fetch()` call triggers the browser's network stack. The `QuicNetworkTransaction` class (being tested here) might be involved if:
   - The server supports QUIC.
   - The browser has a prior indication (e.g., through Alt-Svc headers) that QUIC is available for this domain.
   - Or, if the test scenarios are forcing QUIC (like the `origins_to_force_quic_on` setting).

3. **`QuicNetworkTransaction` in Action:** The tests you provided simulate different aspects of this process:
   - `SecureResourceOverSecureQuic`: Tests a successful QUIC connection for the JavaScript request.
   - `FailedZeroRttBrokenAlternateProtocol`: Tests what happens if the initial QUIC attempt fails, and the browser might fall back to TCP, impacting the speed of the JavaScript's request.
   - `QuicUpload`:  Tests how a JavaScript `fetch()` with a `POST` request and body data would be handled over QUIC.

**Logical Reasoning (with Assumptions and Examples):**

Let's take the `DelayTCPOnStartNoConfirmation` test as an example:

**Assumptions:**

- The server at `mail.example.org` supports QUIC.
- The browser has previously learned about this QUIC support (through Alt-Svc).
- The `HttpServerProperties` indicate that QUIC has worked on this network before.

**Hypothetical Input (from the test setup):**

- `mock_quic_data` is set up to simulate a successful QUIC handshake and response.
- `host_resolver_.set_synchronous_mode(false)`: Host resolution is asynchronous, which takes time.

**Logical Steps in the Test:**

1. The test starts an `HttpNetworkTransaction` for `https://mail.example.org/`.
2. Because QUIC is considered a viable alternative, the test expects the TCP connection attempt to be delayed (`EXPECT_THAT(trans.Start(...), IsError(ERR_IO_PENDING))`). The `ERR_IO_PENDING` indicates an asynchronous operation is in progress (the QUIC connection attempt).
3. The test then runs the message loop (`base::RunLoop().RunUntilIdle()`) to allow the asynchronous QUIC connection to proceed.
4. The test verifies that the response was indeed received via QUIC (`CheckWasQuicResponse(&trans)`).

**Expected Output:**

- The `HttpNetworkTransaction` completes successfully using QUIC.
- The TCP connection was never fully established because the QUIC connection succeeded first.

**User or Programming Common Usage Errors:**

1. **Incorrectly Configuring QUIC on the Server:** If a server advertises QUIC support (e.g., through Alt-Svc headers) but its QUIC implementation is faulty or misconfigured, users might experience connection failures. Tests like the "broken alternate protocol" scenarios cover these situations.
2. **Network Issues Blocking UDP:** QUIC uses UDP. If a user's network or firewall blocks UDP traffic, QUIC connections will fail. The tests simulate these failures and ensure the browser can fall back to TCP.
3. **Browser Configuration Errors:** If a user has manually disabled QUIC in their browser settings, these tests would still pass (as they are isolated unit tests), but in a real browser scenario, QUIC wouldn't be attempted.
4. **Programming Errors in JavaScript:** While not directly related to user errors, if a JavaScript developer makes a lot of rapid network requests, they might inadvertently trigger edge cases in the QUIC implementation that these tests are designed to catch.

**User Operation Steps to Reach Here (as Debugging Clues):**

1. **User Enters a URL in the Address Bar (e.g., `https://mail.example.org/`) or Clicks a Link:** This initiates a navigation request.
2. **Browser Checks for Cached Information:** The browser might check its HTTP cache and its knowledge of alternative services (like QUIC). If it knows `mail.example.org` supports QUIC, it might attempt a QUIC connection.
3. **DNS Resolution:** The browser resolves the IP address of `mail.example.org`.
4. **Connection Attempt:** The `HttpNetworkTransaction` is created. Based on the cached information and network conditions, it might attempt a QUIC connection in parallel with or instead of a TCP connection. This is where the logic tested in these snippets comes into play.
5. **QUIC Handshake (if attempted):** The browser and server negotiate the QUIC connection parameters.
6. **Data Transfer:** Once the connection is established, the browser sends the HTTP request and receives the response.
7. **Error Scenarios:** If at any point during the QUIC connection attempt there's an error (simulated by the `mock_quic_data` in the tests), the browser's error handling mechanisms (also tested here) will kick in, potentially falling back to TCP.

**As a Debugging Line:** If a user reports issues connecting to a website, especially intermittent ones, and the website is known to support QUIC, a developer might investigate these unit tests to understand how the browser handles different QUIC error scenarios. If a test is failing, it might indicate a bug in the QUIC implementation. Examining the specific error conditions simulated in the failing test can provide valuable clues about the root cause of the user's problem.

**归纳一下它的功能 (Summary of Functionality):**

As part 8 of 13, this section of `quic_network_transaction_unittest.cc` focuses on comprehensively testing the behavior of the `QuicNetworkTransaction` class in a variety of scenarios where QUIC is either the primary or an alternative transport protocol. It covers successful QUIC connections, delayed TCP connections when QUIC is anticipated, various QUIC error conditions and the fallback to TCP, handling secure connections over QUIC, managing data uploads, testing connection retry mechanisms after errors, and ensuring proper handling of specific error codes. Essentially, it validates the robustness and correctness of the `QuicNetworkTransaction` in managing network requests with QUIC as a potential transport.

Prompt: 
```
这是目录为net/quic/quic_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共13部分，请归纳一下它的功能

"""
ck_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // Pause.
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_number++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);
  // No HTTP data is mocked as TCP job never starts in this case.

  CreateSession();
  // QuicSessionPool by default requires confirmation on construction.
  session_->quic_session_pool()->set_has_quic_ever_worked_on_current_network(
      false);

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  // Stall host resolution so that QUIC job will not succeed synchronously.
  // Socket will not be configured immediately and QUIC support is not sorted
  // out, TCP job will still be delayed as server properties indicates QUIC
  // support on last IP address.
  host_resolver_.set_synchronous_mode(false);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  EXPECT_THAT(trans.Start(&request_, callback.callback(), net_log_with_source_),
              IsError(ERR_IO_PENDING));
  // Complete host resolution in next message loop so that QUIC job could
  // proceed.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();

  ASSERT_FALSE(mock_quic_data.AllReadDataConsumed());
  mock_quic_data.Resume();

  // Run the QUIC session to completion.
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  CheckWasQuicResponse(&trans);
  CheckResponseData(&trans, kQuicRespData);
}

TEST_P(QuicNetworkTransactionTest,
       DelayTCPOnStartWithQuicSupportOnDifferentIP) {
  // Tests that TCP job is delayed and QUIC job requires confirmation if QUIC
  // was recently supported on a different IP address on start.

  // Set QUIC support on the last IP address, which is different with the local
  // IP address. Require confirmation mode will remain when local IP address is
  // sorted out after we configure the UDP socket.
  http_server_properties_->SetLastLocalAddressWhenQuicWorked(
      IPAddress(1, 2, 3, 4));

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);
  // No HTTP data is mocked as TCP job will be delayed and never starts.

  CreateSession();
  session_->quic_session_pool()->set_has_quic_ever_worked_on_current_network(
      false);
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  // Stall host resolution so that QUIC job could not proceed and unblocks TCP.
  // Socket will not be configured immediately and QUIC support is not sorted
  // out, TCP job will still be delayed as server properties indicates QUIC
  // support on last IP address.
  host_resolver_.set_synchronous_mode(false);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  EXPECT_THAT(trans.Start(&request_, callback.callback(), net_log_with_source_),
              IsError(ERR_IO_PENDING));

  // Complete host resolution in next message loop so that QUIC job could
  // proceed.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake so that QUIC job could succeed.
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  CheckWasQuicResponse(&trans);
  CheckResponseData(&trans, kQuicRespData);
}

TEST_P(QuicNetworkTransactionTest, NetErrorDetailsSetBeforeHandshake) {
  // Test that NetErrorDetails is correctly populated, even if the
  // handshake has not yet been confirmed and no stream has been created.

  // QUIC job will pause. When resumed, it will fail.
  MockQuicData mock_quic_data(version_);
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // Main job will also fail.
  MockRead http_reads[] = {
      MockRead(ASYNC, ERR_SOCKET_NOT_CONNECTED),
  };

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  http_data.set_connect_data(MockConnect(ASYNC, ERR_SOCKET_NOT_CONNECTED));
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();
  // Require handshake confirmation to ensure that no QUIC streams are
  // created, and to ensure that the TCP job does not wait for the QUIC
  // job to fail before it starts.
  session_->quic_session_pool()->set_has_quic_ever_worked_on_current_network(
      false);

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::COLD_START);
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Allow the TCP job to fail.
  base::RunLoop().RunUntilIdle();
  // Now let the QUIC job fail.
  mock_quic_data.Resume();
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));
  ExpectQuicAlternateProtocolMapping();
  NetErrorDetails details;
  trans.PopulateNetErrorDetails(&details);
  EXPECT_EQ(quic::QUIC_PACKET_READ_ERROR, details.quic_connection_error);
}

TEST_P(QuicNetworkTransactionTest, FailedZeroRttBrokenAlternateProtocol) {
  // Alternate-protocol job
  MockRead quic_reads[] = {
      MockRead(ASYNC, ERR_SOCKET_NOT_CONNECTED),
  };
  StaticSocketDataProvider quic_data(quic_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&quic_data);

  // Second Alternate-protocol job which will race with the TCP job.
  StaticSocketDataProvider quic_data2(quic_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&quic_data2);

  // Final job that will proceed when the QUIC job fails.
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello from http"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  SendRequestAndExpectHttpResponse("hello from http");

  ExpectBrokenAlternateProtocolMapping();

  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());
}

TEST_P(QuicNetworkTransactionTest,
       FailedZeroRttBrokenAlternateProtocolWithNetworkIsolationKey) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  http_server_properties_ = std::make_unique<HttpServerProperties>();

  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const net::NetworkIsolationKey kNetworkIsolationKey1(kSite1, kSite1);
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const net::NetworkIsolationKey kNetworkIsolationKey2(kSite2, kSite2);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  // Alternate-protocol job
  MockRead quic_reads[] = {
      MockRead(ASYNC, ERR_SOCKET_NOT_CONNECTED),
  };
  StaticSocketDataProvider quic_data(quic_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&quic_data);

  // Second Alternate-protocol job which will race with the TCP job.
  StaticSocketDataProvider quic_data2(quic_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&quic_data2);

  // Final job that will proceed when the QUIC job fails.
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello from http"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT,
                                  kNetworkAnonymizationKey1);
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT,
                                  kNetworkAnonymizationKey2);

  request_.network_isolation_key = kNetworkIsolationKey1;
  request_.network_anonymization_key = kNetworkAnonymizationKey1;
  SendRequestAndExpectHttpResponse("hello from http");
  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());

  ExpectBrokenAlternateProtocolMapping(kNetworkAnonymizationKey1);
  ExpectQuicAlternateProtocolMapping(kNetworkAnonymizationKey2);

  // Subsequent requests using kNetworkIsolationKey1 should not use QUIC.
  AddHttpDataAndRunRequest();
  // Requests using other NetworkIsolationKeys can still use QUIC.
  request_.network_isolation_key = kNetworkIsolationKey2;
  request_.network_anonymization_key = kNetworkAnonymizationKey2;

  AddQuicDataAndRunRequest();

  // The last two requests should not have changed the alternative service
  // mappings.
  ExpectBrokenAlternateProtocolMapping(kNetworkAnonymizationKey1);
  ExpectQuicAlternateProtocolMapping(kNetworkAnonymizationKey2);
}

TEST_P(QuicNetworkTransactionTest, BrokenAlternateProtocolOnConnectFailure) {
  // Alternate-protocol job will fail before creating a QUIC session.
  StaticSocketDataProvider quic_data;
  quic_data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_CONNECTION_FAILED));
  socket_factory_.AddSocketDataProvider(&quic_data);

  // Main job which will succeed even though the alternate job fails.
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello from http"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::COLD_START);
  SendRequestAndExpectHttpResponse("hello from http");

  ExpectBrokenAlternateProtocolMapping();
}

TEST_P(QuicNetworkTransactionTest, ConnectionCloseDuringConnect) {
  FLAGS_quic_enable_chaos_protection = false;
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  MockQuicData mock_quic_data(version_);
  mock_quic_data.AddWrite(SYNCHRONOUS, client_maker_->MakeDummyCHLOPacket(1));
  mock_quic_data.AddRead(ASYNC, ConstructServerConnectionClosePacket(1));
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // When the QUIC connection fails, we will try the request again over HTTP.
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header_.data()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");

  CreateSession();
  // TODO(rch): Check if we need a 0RTT version of ConnectionCloseDuringConnect
  AddQuicAlternateProtocolMapping(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);
  SendRequestAndExpectHttpResponse(kHttpRespData);
}

TEST_P(QuicNetworkTransactionTest, ConnectionCloseDuringConnectProxy) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  MockQuicData mock_quic_data(version_);
  mock_quic_data.AddWrite(SYNCHRONOUS, client_maker_->MakeDummyCHLOPacket(1));
  mock_quic_data.AddRead(ASYNC, ConstructServerConnectionClosePacket(1));
  mock_quic_data.AddWrite(
      SYNCHRONOUS, ConstructClientRequestHeadersPacket(
                       1, GetNthClientInitiatedBidirectionalStreamId(0), true,
                       GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddWrite(SYNCHRONOUS, ConstructClientAckPacket(2, 1, 1));
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // When the QUIC connection fails, we will try the request again over HTTP.
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header_.data()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  const char kProxyHost[] = "myproxy.org";
  const auto kQuicProxyChain =
      ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
          ProxyServer::SCHEME_QUIC, kProxyHost, 443)});
  const auto kHttpsProxyChain = ProxyChain::FromSchemeHostAndPort(
      ProxyServer::SCHEME_HTTPS, kProxyHost, 443);
  proxy_resolution_service_ =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {kQuicProxyChain, kHttpsProxyChain}, TRAFFIC_ANNOTATION_FOR_TESTS);
  request_.url = GURL("http://mail.example.org/");

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(kProxyHost, "192.168.0.1", "");

  CreateSession();
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);
  SendRequestAndExpectHttpResponseFromProxy(
      kHttpRespData, kHttpsProxyChain.First().GetPort(), kHttpsProxyChain);
  EXPECT_THAT(session_->proxy_resolution_service()->proxy_retry_info(),
              ElementsAre(Key(kQuicProxyChain)));
}

TEST_P(QuicNetworkTransactionTest, SecureResourceOverSecureQuic) {
  client_maker_->set_hostname("www.example.org");
  EXPECT_FALSE(
      test_socket_performance_watcher_factory_.rtt_notification_received());
  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more read data.
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  request_.url = GURL("https://www.example.org:443");
  AddHangingNonAlternateProtocolSocketData();
  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::CONFIRM_HANDSHAKE);
  SendRequestAndExpectQuicResponse(kQuicRespData);
  EXPECT_TRUE(
      test_socket_performance_watcher_factory_.rtt_notification_received());
}

TEST_P(QuicNetworkTransactionTest, QuicUpload) {
  context_.params()->origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData mock_quic_data(version_);
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  mock_quic_data.AddWrite(SYNCHRONOUS, ERR_FAILED);
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  CreateSession();
  request_.method = "POST";
  ChunkedUploadDataStream upload_data(0);
  upload_data.AppendData(base::byte_span_from_cstring("1"), true);

  request_.upload_data_stream = &upload_data;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_NE(OK, callback.WaitForResult());
}

TEST_P(QuicNetworkTransactionTest, QuicUploadWriteError) {
  context_.params()->retry_without_alt_svc_on_quic_errors = false;
  ScopedMockNetworkChangeNotifier network_change_notifier;
  MockNetworkChangeNotifier* mock_ncn =
      network_change_notifier.mock_network_change_notifier();
  mock_ncn->ForceNetworkHandlesSupported();
  mock_ncn->SetConnectedNetworksList(
      {kDefaultNetworkForTests, kNewNetworkForTests});

  context_.params()->origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));
  context_.params()->migrate_sessions_on_network_change_v2 = true;

  MockQuicData socket_data(version_);
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  int packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));
  socket_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), false,
          GetRequestHeaders("POST", "https", "/")));
  socket_data.AddWrite(SYNCHRONOUS, ERR_FAILED);
  socket_data.AddSocketDataToFactory(&socket_factory_);

  MockQuicData socket_data2(version_);
  socket_data2.AddConnect(SYNCHRONOUS, ERR_ADDRESS_INVALID);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  CreateSession();
  request_.method = "POST";
  ChunkedUploadDataStream upload_data(0);

  request_.upload_data_stream = &upload_data;

  auto trans = std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY,
                                                        session_.get());
  TestCompletionCallback callback;
  int rv = trans->Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  base::RunLoop().RunUntilIdle();
  upload_data.AppendData(base::byte_span_from_cstring("1"), true);
  base::RunLoop().RunUntilIdle();

  EXPECT_NE(OK, callback.WaitForResult());
  trans.reset();
  session_.reset();
}

TEST_P(QuicNetworkTransactionTest, RetryAfterAsyncNoBufferSpace) {
  context_.params()->origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData socket_data(version_);
  int packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));
  socket_data.AddWrite(ASYNC, ERR_NO_BUFFER_SPACE);
  socket_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  socket_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  socket_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructClientAckPacket(packet_num++, 2, 1));
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read
  socket_data.AddWrite(
      SYNCHRONOUS,
      client_maker_->Packet(packet_num++)
          .AddAckFrame(/*first_received=*/1, /*largest_received=*/2,
                       /*smallest_received=*/1)
          .AddConnectionCloseFrame(quic::QUIC_CONNECTION_CANCELLED, "net error",
                                   0)
          .Build());

  socket_data.AddSocketDataToFactory(&socket_factory_);

  CreateSession();

  SendRequestAndExpectQuicResponse(kQuicRespData);
  session_.reset();
}

TEST_P(QuicNetworkTransactionTest, RetryAfterSynchronousNoBufferSpace) {
  context_.params()->origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData socket_data(version_);
  int packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));
  socket_data.AddWrite(SYNCHRONOUS, ERR_NO_BUFFER_SPACE);
  socket_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  socket_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  socket_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructClientAckPacket(packet_num++, 2, 1));
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read
  socket_data.AddWrite(
      SYNCHRONOUS,
      client_maker_->Packet(packet_num++)
          .AddAckFrame(/*first_received=*/1, /*largest_received=*/2,
                       /*smallest_received=*/1)
          .AddConnectionCloseFrame(quic::QUIC_CONNECTION_CANCELLED, "net error",
                                   0)
          .Build());

  socket_data.AddSocketDataToFactory(&socket_factory_);

  CreateSession();

  SendRequestAndExpectQuicResponse(kQuicRespData);
  session_.reset();
}

TEST_P(QuicNetworkTransactionTest, MaxRetriesAfterAsyncNoBufferSpace) {
  context_.params()->retry_without_alt_svc_on_quic_errors = false;
  context_.params()->origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData socket_data(version_);
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(1));
  for (int i = 0; i < 13; ++i) {  // 12 retries then one final failure.
    socket_data.AddWrite(ASYNC, ERR_NO_BUFFER_SPACE);
  }
  socket_data.AddSocketDataToFactory(&socket_factory_);

  CreateSession();
  // Use a TestTaskRunner to avoid waiting in real time for timeouts.
  QuicSessionPoolPeer::SetTaskRunner(session_->quic_session_pool(),
                                     quic_task_runner_.get());

  quic::QuicTime start = context_.clock()->Now();
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  while (!callback.have_result()) {
    base::RunLoop().RunUntilIdle();
    quic_task_runner_->RunUntilIdle();
  }
  ASSERT_TRUE(callback.have_result());
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  // Backoff should take between 4 - 5 seconds.
  EXPECT_TRUE(context_.clock()->Now() - start >
              quic::QuicTime::Delta::FromSeconds(4));
  EXPECT_TRUE(context_.clock()->Now() - start <
              quic::QuicTime::Delta::FromSeconds(5));
}

TEST_P(QuicNetworkTransactionTest, MaxRetriesAfterSynchronousNoBufferSpace) {
  context_.params()->retry_without_alt_svc_on_quic_errors = false;
  context_.params()->origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData socket_data(version_);
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(1));
  for (int i = 0; i < 13; ++i) {  // 12 retries then one final failure.
    socket_data.AddWrite(ASYNC, ERR_NO_BUFFER_SPACE);
  }
  socket_data.AddSocketDataToFactory(&socket_factory_);

  CreateSession();
  // Use a TestTaskRunner to avoid waiting in real time for timeouts.
  QuicSessionPoolPeer::SetTaskRunner(session_->quic_session_pool(),
                                     quic_task_runner_.get());

  quic::QuicTime start = context_.clock()->Now();
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  while (!callback.have_result()) {
    base::RunLoop().RunUntilIdle();
    quic_task_runner_->RunUntilIdle();
  }
  ASSERT_TRUE(callback.have_result());
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  // Backoff should take between 4 - 5 seconds.
  EXPECT_TRUE(context_.clock()->Now() - start >
              quic::QuicTime::Delta::FromSeconds(4));
  EXPECT_TRUE(context_.clock()->Now() - start <
              quic::QuicTime::Delta::FromSeconds(5));
}

TEST_P(QuicNetworkTransactionTest, NoMigrationForMsgTooBig) {
  context_.params()->retry_without_alt_svc_on_quic_errors = false;
  context_.params()->origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));
  const std::string error_details = base::StrCat(
      {"Write failed with error: ", base::NumberToString(ERR_MSG_TOO_BIG), " (",
       strerror(ERR_MSG_TOO_BIG), ")"});

  MockQuicData socket_data(version_);
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  int packet_num = 1;
  socket_data.AddWrite(SYNCHRONOUS,
                       ConstructInitialSettingsPacket(packet_num++));
  socket_data.AddWrite(SYNCHRONOUS, ERR_MSG_TOO_BIG);
  // Connection close packet will be sent for MSG_TOO_BIG.
  socket_data.AddWrite(
      SYNCHRONOUS,
      client_maker_->Packet(packet_num + 1)
          .AddConnectionCloseFrame(quic::QUIC_PACKET_WRITE_ERROR, error_details)
          .Build());
  socket_data.AddSocketDataToFactory(&socket_factory_);

  CreateSession();

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(callback.have_result());
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicNetworkTransactionTest, QuicForceHolBlocking) {
  context_.params()->origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData mock_quic_data(version_);

  int write_packet_index = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(write_packet_index++));

  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersAndDataFramesPacket(
          write_packet_index++, GetNthClientInitiatedBidirectionalStreamId(0),
          true, DEFAULT_PRIORITY, GetRequestHeaders("POST", "https", "/"),
          nullptr, {ConstructDataFrame("1")}));

  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));

  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));

  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(write_packet_index++, 2, 1));

  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  CreateSession();
  request_.method = "POST";
  ChunkedUploadDataStream upload_data(0);
  upload_data.AppendData(base::byte_span_from_cstring("1"), true);

  request_.upload_data_stream = &upload_data;

  SendRequestAndExpectQuicResponse(kQuicRespData);
}

TEST_P(QuicNetworkTransactionTest, HostInAllowlist) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  session_params_.quic_host_allowlist.insert("mail.example.org");

  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header_.data()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  SendRequestAndExpectHtt
"""


```
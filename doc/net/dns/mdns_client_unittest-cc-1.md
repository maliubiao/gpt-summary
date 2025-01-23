Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a unit test file for a mDNS client in Chromium.

Here's a breakdown of the thinking process to generate the summary:

1. **Identify the Core Purpose:** The filename `mdns_client_unittest.cc` immediately tells us this is a unit test file. The main goal is to test the functionality of the `MDnsClient` class.

2. **Scan for Key Classes and Methods:** Look for instantiations of `MDnsClient`, `MDnsTransaction`, `MDnsListener`, and interactions with mock objects. Pay attention to methods like `CreateTransaction`, `CreateListener`, `Start`, `SimulatePacketReceive`, and callbacks.

3. **Analyze Individual Tests:** Go through each `TEST_F` and understand what specific aspect of the `MDnsClient` is being tested. Note the setup (e.g., creating listeners or transactions), the actions (e.g., simulating packet reception), and the expected outcomes (using `EXPECT_CALL` and `EXPECT_TRUE`).

4. **Group Tests by Functionality:**  Categorize the tests into logical groups based on what they are testing. For example, tests related to transactions (timeout, multiple records, reentrant deletion), listeners (record updates, goodbye packets, reentrant deletion), and other functionalities like NSEC records and cache management.

5. **Look for Mock Objects and Expectations:** The use of `MockListenerDelegate` and `MockMDnsDatagramServerSocket` indicates that the tests are isolating the `MDnsClient` and simulating external interactions. The `EXPECT_CALL` statements define the expected behavior of these mock objects, which are crucial for understanding what the tests are validating.

6. **Identify Potential Interactions with JavaScript:**  Consider how mDNS might be used in a browser context. Browsers can use mDNS to discover local devices. This could involve JavaScript APIs for network discovery. While the *specific* code doesn't interact with JavaScript, it underpins functionality that *could* be exposed to JavaScript.

7. **Infer Input and Output for Logic:** For tests involving logic (like transaction timeouts or record processing), think about what inputs would lead to the expected outputs. For example, a transaction with a timeout will eventually result in a `RESULT_NO_RESULTS` callback if no matching response is received.

8. **Identify Potential User/Programming Errors:** Consider how a developer using the `MDnsClient` API might misuse it. For instance, failing to start a listener or transaction after creating it, or incorrect handling of callbacks.

9. **Consider the Debugging Perspective:** How would a developer end up looking at this code during debugging? They might be tracing why a device isn't being discovered, or why a particular mDNS operation isn't behaving as expected. The test names and setups can provide clues.

10. **Address Part 2 Request:** Since this is part 2, recall the summary from part 1. Part 1 likely covered basic initialization, sending queries, and receiving responses. Part 2 seems to focus on more advanced scenarios like timeouts, handling multiple records, reentrant calls, goodbye packets, NSEC records, and cache management.

11. **Synthesize the Summary:** Combine the information gathered into a concise summary that covers the key functionalities tested in the provided code snippet. Use clear and descriptive language.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on the individual test cases. I need to step back and see the bigger picture – the overall features being tested.
* I need to avoid getting bogged down in the specific details of the packet formats unless they are directly relevant to the functionality being described.
* I should ensure I am explicitly addressing all parts of the user's request (functionality, JavaScript relation, input/output, errors, debugging, and the "part 2" context).
*  Realize that the JavaScript interaction is *indirect*. The C++ code provides the underlying functionality. The example needs to reflect this indirect relationship.
这是对 Chromium 网络栈中 `net/dns/mdns_client_unittest.cc` 文件第二部分的功能归纳。结合第一部分，我们可以更全面地理解该单元测试文件的作用。

**综合第一部分和第二部分，`net/dns/mdns_client_unittest.cc` 的主要功能是：**

**核心功能测试:**

* **MDnsClient 的基本生命周期管理:**  测试 `MDnsClient` 的创建、启动监听 (通过 `StartListening`) 和停止。
* **发送和接收 mDNS 数据包:**  模拟发送 mDNS 查询包 (通过 `ExpectPacket`) 并模拟接收 mDNS 响应包 (通过 `SimulatePacketReceive`)，验证 `MDnsClient` 是否正确地发送和解析数据包。
* **DNS 记录的解析和存储:** 测试 `MDnsClient` 是否能正确解析收到的 DNS 记录 (例如 PTR, A 记录等)，并将其存储在内部缓存中。
* **MDnsTransaction 的管理:**
    * **创建和启动事务:** 测试 `CreateTransaction` 方法创建不同类型的 mDNS 事务 (例如查询网络、查询缓存、单次结果)。
    * **事务超时:** 验证事务在没有收到响应时是否会按预期超时并触发回调。
    * **接收多个记录:** 测试事务处理接收到的多个相关记录的能力。
    * **重入删除:** 测试在事务的回调函数中删除事务自身是否会导致问题。
    * **从缓存启动事务:** 测试直接从缓存中查找结果的事务。
* **MDnsListener 的管理:**
    * **创建和启动监听器:** 测试 `CreateListener` 方法创建监听特定 DNS 类型和域名的监听器。
    * **接收记录更新:** 验证监听器在接收到相关记录时是否会调用 `OnRecordUpdate` 回调，通知添加或更新了记录。
    * **接收再见包 (Goodbye Packet):** 测试监听器如何处理再见包，并更新其维护的记录。
    * **重入删除:** 测试在监听器的回调函数中删除监听器自身是否会导致问题。
* **NSEC 记录的处理:**
    * **监听器接收 NSEC 记录:** 测试监听器是否能接收和处理 NSEC 记录，表明某些记录类型不存在。
    * **事务处理 NSEC 记录:** 测试事务在查询网络和缓存时如何处理 NSEC 记录。
    * **NSEC 记录导致的冲突移除:** 验证接收到 NSEC 记录后，缓存中相应的记录是否会被移除。
* **主动刷新查询 (Active Refresh):** 测试监听器是否能定期发送查询来刷新缓存中的记录。
* **错误处理:** 测试 `StartListening` 失败的情况 (例如，底层的 Socket 创建失败)。
* **缓存管理:** 测试当缓存超过限制时是否会进行清理。
* **MDnsConnection 的测试:**
    * **连接的初始化:** 测试 `MDnsConnection` 的初始化过程。
    * **同步和异步接收数据包:** 测试 `MDnsConnection` 同步和异步接收 mDNS 数据包的能力。
    * **连接错误处理:** 测试 `MDnsConnection` 如何处理底层的 Socket 错误。
    * **发送数据包:** 测试 `MDnsConnection` 发送 mDNS 数据包的功能。
    * **发送队列管理:** 测试 `MDnsConnection` 如何处理发送队列，特别是在发送过程中遇到错误或延迟时。
* **MDnsSocket 的创建:**  验证 mDNS Socket 的创建是否正常。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但它是 Chromium 浏览器网络栈的一部分，负责处理底层的 mDNS 协议。JavaScript 可以通过浏览器提供的 API (例如 `navigator.mediaDevices.enumerateDevices()`，在某些场景下会使用 mDNS 来发现本地网络设备) 来间接使用 `MDnsClient` 的功能。

**举例说明:**

假设一个智能家居应用运行在用户的浏览器中，需要发现局域网内的智能灯泡。

1. **JavaScript 发起设备发现:** JavaScript 代码调用 `navigator.mediaDevices.enumerateDevices()` 或其他相关的浏览器 API。
2. **浏览器调用底层网络栈:**  浏览器内部会将这个设备发现的请求传递给底层的网络栈。
3. **`MDnsClient` 发送 mDNS 查询:** `MDnsClient` (或其相关组件) 会构建并发送一个 mDNS 查询包，查找特定服务类型的设备 (例如 `_hap._tcp.local` 用于 HomeKit 设备)。
4. **设备响应:**  局域网内的智能灯泡收到查询包后，会发送包含其信息的 mDNS 响应包。
5. **`MDnsClient` 接收和解析响应:** `MDnsClient` 接收到响应包，解析出灯泡的 IP 地址、主机名等信息。
6. **信息传递回 JavaScript:**  浏览器将发现的设备信息通过回调函数传递回 JavaScript 代码。

**假设输入与输出 (逻辑推理):**

* **假设输入 (针对 `TransactionTimeout` 测试):**
    * 创建一个查询 "_privet._tcp.local" 的 `MDnsTransaction`，设置为查询网络。
    * 不模拟接收任何针对该查询的响应包。
    * 运行足够长的时间，超过事务的默认超时时间 (例如 4 秒)。
* **预期输出:**
    * `MockableRecordCallback` 被调用一次，`MDnsTransaction::RESULT_NO_RESULTS` 作为结果参数。

* **假设输入 (针对 `TransactionMultipleRecords` 测试):**
    * 创建一个查询 "_privet._tcp.local" 的 `MDnsTransaction`，设置为查询网络。
    * 模拟接收两个针对该查询的不同的 PTR 记录响应包。
* **预期输出:**
    * `MockableRecordCallback` 被调用两次，每次的 `RecordParsed` 参数分别包含接收到的两个 PTR 记录的信息。
    * `MockableRecordCallback` 最终被调用一次，`MDnsTransaction::RESULT_DONE` 作为结果参数。

**用户或编程常见的使用错误 (举例说明):**

* **忘记启动 Listener 或 Transaction:** 用户创建了一个 `MDnsListener` 或 `MDnsTransaction` 对象，但忘记调用 `Start()` 方法，导致监听器不会接收数据，事务也不会发送查询。
    ```c++
    // 错误示例
    std::unique_ptr<MDnsListener> listener =
        test_client_->CreateListener(dns_protocol::kTypeA, "example.local", &delegate);
    // 忘记调用 listener->Start();
    ```
* **在回调函数中错误地删除对象:** 用户在一个 `MDnsTransaction` 或 `MDnsListener` 的回调函数中直接 `delete this` (如果回调函数是对象的方法)，可能导致程序崩溃或未定义的行为。Chromium 的 `base::BindRepeating` 和智能指针 `std::unique_ptr` 等机制旨在帮助避免这类错误，但理解其原理仍然重要。
* **未处理所有可能的回调结果:** 用户在实现 `MDnsTransaction` 的回调函数时，可能只处理了 `RESULT_RECORD` 的情况，而忽略了 `RESULT_NO_RESULTS`, `RESULT_NSEC` 或 `RESULT_DONE` 等其他可能的结果，导致程序逻辑不完整。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在使用 Chrome 浏览器时，发现局域网内的某个设备无法被正确发现。作为 Chromium 的开发者或熟悉网络栈的工程师，进行调试的步骤可能如下：

1. **重现问题:**  首先尝试重现用户报告的问题，例如，尝试在浏览器的设备发现页面中搜索特定的设备。
2. **检查网络活动:** 使用浏览器的开发者工具 (Network 面板) 或 Wireshark 等网络抓包工具，查看是否发送了 mDNS 查询，以及是否收到了响应。
3. **定位到 mDNS 代码:** 如果确认问题与 mDNS 相关，则需要深入到 Chromium 的网络栈代码中。可能会从调用设备发现 API 的 JavaScript 代码开始，逐步追踪到负责处理 mDNS 查询的代码，最终可能定位到 `net/dns` 目录下的相关文件。
4. **查看 `MDnsClient` 的日志或状态:**  如果启用了网络相关的调试日志，可以查看 `MDnsClient` 的内部状态，例如当前注册的监听器、活跃的事务、缓存的记录等。
5. **分析 `mdns_client_unittest.cc`:**  查阅 `mdns_client_unittest.cc` 文件可以帮助理解 `MDnsClient` 的预期行为和各种边界情况。例如，如果怀疑是超时问题，可以查看 `TransactionTimeout` 测试；如果怀疑是多记录处理问题，可以查看 `TransactionMultipleRecords` 测试。
6. **设置断点和单步调试:**  在 `MDnsClient` 的相关代码中设置断点，例如在 `SimulatePacketReceive` 或回调函数中，单步执行代码，观察变量的值和程序的执行流程，以找出问题所在。例如，可以检查接收到的数据包是否被正确解析，回调函数是否被正确调用，缓存是否被正确更新等。

总而言之，`net/dns/mdns_client_unittest.cc` 的第二部分，连同第一部分，全面地测试了 Chromium `MDnsClient` 及其相关组件的各种功能，确保其能够正确地实现 mDNS 协议，进行设备发现和服务发现。 它可以作为理解 `MDnsClient` 工作原理的重要参考，并在调试 mDNS 相关问题时提供关键的线索。

### 提示词
```
这是目录为net/dns/mdns_client_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
sizeof(kSamplePacketAdditionalOnly));

  EXPECT_TRUE(record_privet.IsRecordWith("_privet._tcp.local",
                                         "hello._privet._tcp.local"));
}

TEST_F(MDnsTest, TransactionTimeout) {
  ExpectPacket(kQueryPacketPrivet, sizeof(kQueryPacketPrivet));

  std::unique_ptr<MDnsTransaction> transaction_privet =
      test_client_->CreateTransaction(
          dns_protocol::kTypePTR, "_privet._tcp.local",
          MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE |
              MDnsTransaction::SINGLE_RESULT,
          base::BindRepeating(&MDnsTest::MockableRecordCallback,
                              base::Unretained(this)));

  ASSERT_TRUE(transaction_privet->Start());

  EXPECT_CALL(*this, MockableRecordCallback(MDnsTransaction::RESULT_NO_RESULTS,
                                            nullptr))
      .Times(Exactly(1))
      .WillOnce(InvokeWithoutArgs(this, &MDnsTest::Stop));

  RunFor(base::Seconds(4));
}

TEST_F(MDnsTest, TransactionMultipleRecords) {
  ExpectPacket(kQueryPacketPrivet, sizeof(kQueryPacketPrivet));

  std::unique_ptr<MDnsTransaction> transaction_privet =
      test_client_->CreateTransaction(
          dns_protocol::kTypePTR, "_privet._tcp.local",
          MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE,
          base::BindRepeating(&MDnsTest::MockableRecordCallback,
                              base::Unretained(this)));

  ASSERT_TRUE(transaction_privet->Start());

  PtrRecordCopyContainer record_privet;
  PtrRecordCopyContainer record_privet2;

  EXPECT_CALL(*this, MockableRecordCallback(MDnsTransaction::RESULT_RECORD, _))
      .Times(Exactly(2))
      .WillOnce(Invoke(&record_privet,
                       &PtrRecordCopyContainer::SaveWithDummyArg))
      .WillOnce(Invoke(&record_privet2,
                       &PtrRecordCopyContainer::SaveWithDummyArg));

  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));
  SimulatePacketReceive(kSamplePacket2, sizeof(kSamplePacket2));

  EXPECT_TRUE(record_privet.IsRecordWith("_privet._tcp.local",
                                         "hello._privet._tcp.local"));

  EXPECT_TRUE(record_privet2.IsRecordWith("_privet._tcp.local",
                                          "zzzzz._privet._tcp.local"));

  EXPECT_CALL(*this,
              MockableRecordCallback(MDnsTransaction::RESULT_DONE, nullptr))
      .WillOnce(InvokeWithoutArgs(this, &MDnsTest::Stop));

  RunFor(base::Seconds(4));
}

TEST_F(MDnsTest, TransactionReentrantDelete) {
  ExpectPacket(kQueryPacketPrivet, sizeof(kQueryPacketPrivet));

  transaction_ = test_client_->CreateTransaction(
      dns_protocol::kTypePTR, "_privet._tcp.local",
      MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE |
          MDnsTransaction::SINGLE_RESULT,
      base::BindRepeating(&MDnsTest::MockableRecordCallback,
                          base::Unretained(this)));

  ASSERT_TRUE(transaction_->Start());

  EXPECT_CALL(*this, MockableRecordCallback(MDnsTransaction::RESULT_NO_RESULTS,
                                            nullptr))
      .Times(Exactly(1))
      .WillOnce(DoAll(InvokeWithoutArgs(this, &MDnsTest::DeleteTransaction),
                      InvokeWithoutArgs(this, &MDnsTest::Stop)));

  RunFor(base::Seconds(4));

  EXPECT_EQ(nullptr, transaction_.get());
}

TEST_F(MDnsTest, TransactionReentrantDeleteFromCache) {
  StrictMock<MockListenerDelegate> delegate_irrelevant;
  std::unique_ptr<MDnsListener> listener_irrelevant =
      test_client_->CreateListener(dns_protocol::kTypeA,
                                   "codereview.chromium.local",
                                   &delegate_irrelevant);
  ASSERT_TRUE(listener_irrelevant->Start());

  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));

  transaction_ = test_client_->CreateTransaction(
      dns_protocol::kTypePTR, "_privet._tcp.local",
      MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE,
      base::BindRepeating(&MDnsTest::MockableRecordCallback,
                          base::Unretained(this)));

  EXPECT_CALL(*this, MockableRecordCallback(MDnsTransaction::RESULT_RECORD, _))
      .Times(Exactly(1))
      .WillOnce(InvokeWithoutArgs(this, &MDnsTest::DeleteTransaction));

  ASSERT_TRUE(transaction_->Start());

  EXPECT_EQ(nullptr, transaction_.get());
}

TEST_F(MDnsTest, TransactionReentrantCacheLookupStart) {
  ExpectPacket(kQueryPacketPrivet, sizeof(kQueryPacketPrivet));

  std::unique_ptr<MDnsTransaction> transaction1 =
      test_client_->CreateTransaction(
          dns_protocol::kTypePTR, "_privet._tcp.local",
          MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE |
              MDnsTransaction::SINGLE_RESULT,
          base::BindRepeating(&MDnsTest::MockableRecordCallback,
                              base::Unretained(this)));

  std::unique_ptr<MDnsTransaction> transaction2 =
      test_client_->CreateTransaction(
          dns_protocol::kTypePTR, "_printer._tcp.local",
          MDnsTransaction::QUERY_CACHE | MDnsTransaction::SINGLE_RESULT,
          base::BindRepeating(&MDnsTest::MockableRecordCallback2,
                              base::Unretained(this)));

  EXPECT_CALL(*this, MockableRecordCallback2(MDnsTransaction::RESULT_RECORD,
                                             _))
      .Times(Exactly(1));

  EXPECT_CALL(*this, MockableRecordCallback(MDnsTransaction::RESULT_RECORD,
                                            _))
      .Times(Exactly(1))
      .WillOnce(IgnoreResult(InvokeWithoutArgs(transaction2.get(),
                                               &MDnsTransaction::Start)));

  ASSERT_TRUE(transaction1->Start());

  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));
}

TEST_F(MDnsTest, GoodbyePacketNotification) {
  StrictMock<MockListenerDelegate> delegate_privet;

  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet);
  ASSERT_TRUE(listener_privet->Start());

  SimulatePacketReceive(kSamplePacketGoodbye, sizeof(kSamplePacketGoodbye));

  RunFor(base::Seconds(2));
}

TEST_F(MDnsTest, GoodbyePacketRemoval) {
  StrictMock<MockListenerDelegate> delegate_privet;

  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet);
  ASSERT_TRUE(listener_privet->Start());

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1));

  SimulatePacketReceive(kSamplePacket2, sizeof(kSamplePacket2));

  SimulatePacketReceive(kSamplePacketGoodbye, sizeof(kSamplePacketGoodbye));

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_REMOVED, _))
      .Times(Exactly(1));

  RunFor(base::Seconds(2));
}

// In order to reliably test reentrant listener deletes, we create two listeners
// and have each of them delete both, so we're guaranteed to try and deliver a
// callback to at least one deleted listener.

TEST_F(MDnsTest, ListenerReentrantDelete) {
  StrictMock<MockListenerDelegate> delegate_privet;

  listener1_ = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet);

  listener2_ = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet);

  ASSERT_TRUE(listener1_->Start());

  ASSERT_TRUE(listener2_->Start());

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1))
      .WillOnce(InvokeWithoutArgs(this, &MDnsTest::DeleteBothListeners));

  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));

  EXPECT_EQ(nullptr, listener1_.get());
  EXPECT_EQ(nullptr, listener2_.get());
}

ACTION_P(SaveIPAddress, ip_container) {
  ::testing::StaticAssertTypeEq<const RecordParsed*, arg1_type>();
  ::testing::StaticAssertTypeEq<IPAddress*, ip_container_type>();

  *ip_container = arg1->template rdata<ARecordRdata>()->address();
}

TEST_F(MDnsTest, DoubleRecordDisagreeing) {
  IPAddress address;
  StrictMock<MockListenerDelegate> delegate_privet;

  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypeA, "privet.local", &delegate_privet);

  ASSERT_TRUE(listener_privet->Start());

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(Exactly(1))
      .WillOnce(SaveIPAddress(&address));

  SimulatePacketReceive(kCorruptedPacketDoubleRecord,
                        sizeof(kCorruptedPacketDoubleRecord));

  EXPECT_EQ("2.3.4.5", address.ToString());
}

TEST_F(MDnsTest, NsecWithListener) {
  StrictMock<MockListenerDelegate> delegate_privet;
  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypeA, "_privet._tcp.local", &delegate_privet);

  // Test to make sure nsec callback is NOT called for PTR
  // (which is marked as existing).
  StrictMock<MockListenerDelegate> delegate_privet2;
  std::unique_ptr<MDnsListener> listener_privet2 = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet2);

  ASSERT_TRUE(listener_privet->Start());

  EXPECT_CALL(delegate_privet,
              OnNsecRecord("_privet._tcp.local", dns_protocol::kTypeA));

  SimulatePacketReceive(kSamplePacketNsec,
                        sizeof(kSamplePacketNsec));
}

TEST_F(MDnsTest, NsecWithTransactionFromNetwork) {
  std::unique_ptr<MDnsTransaction> transaction_privet =
      test_client_->CreateTransaction(
          dns_protocol::kTypeA, "_privet._tcp.local",
          MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE |
              MDnsTransaction::SINGLE_RESULT,
          base::BindRepeating(&MDnsTest::MockableRecordCallback,
                              base::Unretained(this)));

  EXPECT_CALL(socket_factory_, OnSendTo(_)).Times(2);

  ASSERT_TRUE(transaction_privet->Start());

  EXPECT_CALL(*this,
              MockableRecordCallback(MDnsTransaction::RESULT_NSEC, nullptr));

  SimulatePacketReceive(kSamplePacketNsec,
                        sizeof(kSamplePacketNsec));
}

TEST_F(MDnsTest, NsecWithTransactionFromCache) {
  // Force mDNS to listen.
  StrictMock<MockListenerDelegate> delegate_irrelevant;
  std::unique_ptr<MDnsListener> listener_irrelevant =
      test_client_->CreateListener(dns_protocol::kTypePTR, "_privet._tcp.local",
                                   &delegate_irrelevant);
  listener_irrelevant->Start();

  SimulatePacketReceive(kSamplePacketNsec,
                        sizeof(kSamplePacketNsec));

  EXPECT_CALL(*this,
              MockableRecordCallback(MDnsTransaction::RESULT_NSEC, nullptr));

  std::unique_ptr<MDnsTransaction> transaction_privet_a =
      test_client_->CreateTransaction(
          dns_protocol::kTypeA, "_privet._tcp.local",
          MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE |
              MDnsTransaction::SINGLE_RESULT,
          base::BindRepeating(&MDnsTest::MockableRecordCallback,
                              base::Unretained(this)));

  ASSERT_TRUE(transaction_privet_a->Start());

  // Test that a PTR transaction does NOT consider the same NSEC record to be a
  // valid answer to the query

  std::unique_ptr<MDnsTransaction> transaction_privet_ptr =
      test_client_->CreateTransaction(
          dns_protocol::kTypePTR, "_privet._tcp.local",
          MDnsTransaction::QUERY_NETWORK | MDnsTransaction::QUERY_CACHE |
              MDnsTransaction::SINGLE_RESULT,
          base::BindRepeating(&MDnsTest::MockableRecordCallback,
                              base::Unretained(this)));

  EXPECT_CALL(socket_factory_, OnSendTo(_)).Times(2);

  ASSERT_TRUE(transaction_privet_ptr->Start());
}

TEST_F(MDnsTest, NsecConflictRemoval) {
  StrictMock<MockListenerDelegate> delegate_privet;
  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypeA, "_privet._tcp.local", &delegate_privet);

  ASSERT_TRUE(listener_privet->Start());

  const RecordParsed* record1;
  const RecordParsed* record2;

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .WillOnce(SaveArg<1>(&record1));

  SimulatePacketReceive(kSamplePacketAPrivet,
                        sizeof(kSamplePacketAPrivet));

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_REMOVED, _))
      .WillOnce(SaveArg<1>(&record2));

  EXPECT_CALL(delegate_privet,
              OnNsecRecord("_privet._tcp.local", dns_protocol::kTypeA));

  SimulatePacketReceive(kSamplePacketNsec,
                        sizeof(kSamplePacketNsec));

  EXPECT_EQ(record1, record2);
}

// TODO(crbug.com/40807339): Flaky on fuchsia.
#if BUILDFLAG(IS_FUCHSIA)
#define MAYBE_RefreshQuery DISABLED_RefreshQuery
#else
#define MAYBE_RefreshQuery RefreshQuery
#endif
TEST_F(MDnsTest, MAYBE_RefreshQuery) {
  StrictMock<MockListenerDelegate> delegate_privet;
  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypeA, "_privet._tcp.local", &delegate_privet);

  listener_privet->SetActiveRefresh(true);
  ASSERT_TRUE(listener_privet->Start());

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _));

  SimulatePacketReceive(kSamplePacketAPrivet,
                        sizeof(kSamplePacketAPrivet));

  // Expecting 2 calls (one for ipv4 and one for ipv6) for each of the 2
  // scheduled refresh queries.
  EXPECT_CALL(socket_factory_, OnSendTo(
      MakeString(kQueryPacketPrivetA, sizeof(kQueryPacketPrivetA))))
      .Times(4);

  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_REMOVED, _));

  RunFor(base::Seconds(6));
}

// MDnsSocketFactory implementation that creates a single socket that will
// always fail on RecvFrom. Passing this to MdnsClient is expected to result in
// the client failing to start listening.
class FailingSocketFactory : public MDnsSocketFactory {
  void CreateSockets(
      std::vector<std::unique_ptr<DatagramServerSocket>>* sockets) override {
    auto socket =
        std::make_unique<MockMDnsDatagramServerSocket>(ADDRESS_FAMILY_IPV4);
    EXPECT_CALL(*socket, RecvFrom(_, _, _, _))
        .WillRepeatedly(Return(ERR_FAILED));
    sockets->push_back(std::move(socket));
  }
};

TEST_F(MDnsTest, StartListeningFailure) {
  test_client_ = std::make_unique<MDnsClientImpl>();
  FailingSocketFactory socket_factory;

  EXPECT_THAT(test_client_->StartListening(&socket_factory),
              test::IsError(ERR_FAILED));
}

// Test that the cache is cleared when it gets filled to unreasonable sizes.
TEST_F(MDnsTest, ClearOverfilledCache) {
  test_client_->core()->cache_for_testing()->set_entry_limit_for_testing(1);

  StrictMock<MockListenerDelegate> delegate_privet;
  StrictMock<MockListenerDelegate> delegate_printer;

  PtrRecordCopyContainer record_privet;
  PtrRecordCopyContainer record_printer;

  std::unique_ptr<MDnsListener> listener_privet = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_privet._tcp.local", &delegate_privet);
  std::unique_ptr<MDnsListener> listener_printer = test_client_->CreateListener(
      dns_protocol::kTypePTR, "_printer._tcp.local", &delegate_printer);

  ASSERT_TRUE(listener_privet->Start());
  ASSERT_TRUE(listener_printer->Start());

  bool privet_added = false;
  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(AtMost(1))
      .WillOnce(Assign(&privet_added, true));
  EXPECT_CALL(delegate_privet, OnRecordUpdate(MDnsListener::RECORD_REMOVED, _))
      .WillRepeatedly(Assign(&privet_added, false));

  bool printer_added = false;
  EXPECT_CALL(delegate_printer, OnRecordUpdate(MDnsListener::RECORD_ADDED, _))
      .Times(AtMost(1))
      .WillOnce(Assign(&printer_added, true));
  EXPECT_CALL(delegate_printer, OnRecordUpdate(MDnsListener::RECORD_REMOVED, _))
      .WillRepeatedly(Assign(&printer_added, false));

  // Fill past capacity and expect everything to eventually be removed.
  SimulatePacketReceive(kSamplePacket1, sizeof(kSamplePacket1));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(privet_added);
  EXPECT_FALSE(printer_added);
}

// Note: These tests assume that the ipv4 socket will always be created first.
// This is a simplifying assumption based on the way the code works now.
class SimpleMockSocketFactory : public MDnsSocketFactory {
 public:
  void CreateSockets(
      std::vector<std::unique_ptr<DatagramServerSocket>>* sockets) override {
    sockets->clear();
    sockets->swap(sockets_);
  }

  void PushSocket(std::unique_ptr<DatagramServerSocket> socket) {
    sockets_.push_back(std::move(socket));
  }

 private:
  std::vector<std::unique_ptr<DatagramServerSocket>> sockets_;
};

class MockMDnsConnectionDelegate : public MDnsConnection::Delegate {
 public:
  void HandlePacket(DnsResponse* response, int size) override {
    HandlePacketInternal(std::string(response->io_buffer()->data(), size));
  }

  MOCK_METHOD1(HandlePacketInternal, void(std::string packet));

  MOCK_METHOD1(OnConnectionError, void(int error));
};

class MDnsConnectionTest : public TestWithTaskEnvironment {
 public:
  MDnsConnectionTest() : connection_(&delegate_) {
  }

 protected:
  // Follow successful connection initialization.
  void SetUp() override {
    auto socket_ipv4 =
        std::make_unique<MockMDnsDatagramServerSocket>(ADDRESS_FAMILY_IPV4);
    auto socket_ipv6 =
        std::make_unique<MockMDnsDatagramServerSocket>(ADDRESS_FAMILY_IPV6);
    socket_ipv4_ptr_ = socket_ipv4.get();
    socket_ipv6_ptr_ = socket_ipv6.get();
    factory_.PushSocket(std::move(socket_ipv4));
    factory_.PushSocket(std::move(socket_ipv6));
    sample_packet_ = MakeString(kSamplePacket1, sizeof(kSamplePacket1));
    sample_buffer_ = base::MakeRefCounted<StringIOBuffer>(sample_packet_);
  }

  int InitConnection() { return connection_.Init(&factory_); }

  StrictMock<MockMDnsConnectionDelegate> delegate_;

  raw_ptr<MockMDnsDatagramServerSocket, DanglingUntriaged> socket_ipv4_ptr_;
  raw_ptr<MockMDnsDatagramServerSocket, DanglingUntriaged> socket_ipv6_ptr_;
  SimpleMockSocketFactory factory_;
  MDnsConnection connection_;
  TestCompletionCallback callback_;
  std::string sample_packet_;
  scoped_refptr<IOBuffer> sample_buffer_;
};

TEST_F(MDnsConnectionTest, ReceiveSynchronous) {
  socket_ipv6_ptr_->SetResponsePacket(sample_packet_);
  EXPECT_CALL(*socket_ipv4_ptr_, RecvFrom(_, _, _, _))
      .WillOnce(Return(ERR_IO_PENDING));
  EXPECT_CALL(*socket_ipv6_ptr_, RecvFrom(_, _, _, _))
      .WillOnce(Invoke(socket_ipv6_ptr_.get(),
                       &MockMDnsDatagramServerSocket::HandleRecvNow))
      .WillOnce(Return(ERR_IO_PENDING));

  EXPECT_CALL(delegate_, HandlePacketInternal(sample_packet_));
  EXPECT_THAT(InitConnection(), test::IsOk());
}

TEST_F(MDnsConnectionTest, ReceiveAsynchronous) {
  socket_ipv6_ptr_->SetResponsePacket(sample_packet_);

  EXPECT_CALL(*socket_ipv4_ptr_, RecvFrom(_, _, _, _))
      .WillOnce(Return(ERR_IO_PENDING));
  EXPECT_CALL(*socket_ipv6_ptr_, RecvFrom(_, _, _, _))
      .Times(2)
      .WillOnce(Invoke(socket_ipv6_ptr_.get(),
                       &MockMDnsDatagramServerSocket::HandleRecvLater))
      .WillOnce(Return(ERR_IO_PENDING));

  ASSERT_THAT(InitConnection(), test::IsOk());

  EXPECT_CALL(delegate_, HandlePacketInternal(sample_packet_));

  base::RunLoop().RunUntilIdle();
}

TEST_F(MDnsConnectionTest, Error) {
  CompletionOnceCallback callback;

  EXPECT_CALL(*socket_ipv4_ptr_, RecvFrom(_, _, _, _))
      .WillOnce(Return(ERR_IO_PENDING));
  EXPECT_CALL(*socket_ipv6_ptr_, RecvFrom(_, _, _, _))
      .WillOnce([&](auto, auto, auto, auto cb) {
        callback = std::move(cb);
        return ERR_IO_PENDING;
      });

  ASSERT_THAT(InitConnection(), test::IsOk());

  EXPECT_CALL(delegate_, OnConnectionError(ERR_SOCKET_NOT_CONNECTED));
  std::move(callback).Run(ERR_SOCKET_NOT_CONNECTED);
  base::RunLoop().RunUntilIdle();
}

class MDnsConnectionSendTest : public MDnsConnectionTest {
 protected:
  void SetUp() override {
    MDnsConnectionTest::SetUp();
    EXPECT_CALL(*socket_ipv4_ptr_, RecvFrom(_, _, _, _))
        .WillOnce(Return(ERR_IO_PENDING));
    EXPECT_CALL(*socket_ipv6_ptr_, RecvFrom(_, _, _, _))
        .WillOnce(Return(ERR_IO_PENDING));
    EXPECT_THAT(InitConnection(), test::IsOk());
  }
};

TEST_F(MDnsConnectionSendTest, Send) {
  EXPECT_CALL(*socket_ipv4_ptr_,
              SendToInternal(sample_packet_, "224.0.0.251:5353", _));
  EXPECT_CALL(*socket_ipv6_ptr_,
              SendToInternal(sample_packet_, "[ff02::fb]:5353", _));

  connection_.Send(sample_buffer_, sample_packet_.size());
}

TEST_F(MDnsConnectionSendTest, SendError) {
  EXPECT_CALL(*socket_ipv4_ptr_,
              SendToInternal(sample_packet_, "224.0.0.251:5353", _));
  EXPECT_CALL(*socket_ipv6_ptr_,
              SendToInternal(sample_packet_, "[ff02::fb]:5353", _))
      .WillOnce(Return(ERR_SOCKET_NOT_CONNECTED));

  connection_.Send(sample_buffer_, sample_packet_.size());
  EXPECT_CALL(delegate_, OnConnectionError(ERR_SOCKET_NOT_CONNECTED));
  base::RunLoop().RunUntilIdle();
}

TEST_F(MDnsConnectionSendTest, SendQueued) {
  // Send data immediately.
  EXPECT_CALL(*socket_ipv4_ptr_,
              SendToInternal(sample_packet_, "224.0.0.251:5353", _))
      .Times(2)
      .WillRepeatedly(Return(OK));

  CompletionOnceCallback callback;
  // Delay sending data. Only the first call should be made.
  EXPECT_CALL(*socket_ipv6_ptr_,
              SendToInternal(sample_packet_, "[ff02::fb]:5353", _))
      .WillOnce([&](auto, auto, auto cb) {
        callback = std::move(cb);
        return ERR_IO_PENDING;
      });

  connection_.Send(sample_buffer_, sample_packet_.size());
  connection_.Send(sample_buffer_, sample_packet_.size());

  // The second IPv6 packet is not sent yet.
  EXPECT_CALL(*socket_ipv4_ptr_,
              SendToInternal(sample_packet_, "224.0.0.251:5353", _))
      .Times(0);
  // Expect call for the second IPv6 packet.
  EXPECT_CALL(*socket_ipv6_ptr_,
              SendToInternal(sample_packet_, "[ff02::fb]:5353", _))
      .WillOnce(Return(OK));
  std::move(callback).Run(OK);
}

TEST(MDnsSocketTest, CreateSocket) {
  // Verifies that socket creation hasn't been broken.
  auto socket = CreateAndBindMDnsSocket(AddressFamily::ADDRESS_FAMILY_IPV4, 1,
                                        net::NetLog::Get());
  EXPECT_TRUE(socket);
  socket->Close();
}

}  // namespace net
```
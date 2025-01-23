Response:
The user is asking for the functionality of a C++ test file for a network state notifier in the Chromium Blink engine. They specifically want to know:

1. **General Functionality:** What does this test file do?
2. **Relevance to Web Technologies:** How does it relate to JavaScript, HTML, and CSS?
3. **Logic and Examples:**  Provide examples with assumed inputs and outputs for any logical deductions.
4. **Common Usage Errors:**  Point out potential mistakes users or programmers might make.
5. **Summary:** A concise overview of the file's purpose.

This is the *second part* of the analysis, implying the first part provided context or preliminary information.

Let's break down the code and address each point:

**1. General Functionality:**

This test file (`network_state_notifier_test.cc`) is part of the Chromium Blink engine's unit testing framework. Its purpose is to test the functionality of the `NetworkStateNotifier` class. This class is responsible for:

* **Tracking Network Connectivity:** Monitoring whether the device is online or offline.
* **Tracking Connection Type:** Identifying the type of network connection (e.g., Ethernet, Wi-Fi, cellular).
* **Tracking Network Performance Metrics:**  Storing information like round-trip time (RTT), downlink throughput, and effective connection type (ECT).
* **Handling "Save Data" Mode:**  Notifying about the status of data saver settings.
* **Notifying Observers:**  Informing other parts of the browser (observers) about changes in network state.
* **Implementing Overrides:** Allowing temporary or forced network state configurations for testing or specific use cases.

The tests in this file verify that the `NetworkStateNotifier` correctly updates and reports these various aspects of network state under different conditions.

**2. Relevance to Web Technologies (JavaScript, HTML, CSS):**

The `NetworkStateNotifier` doesn't directly manipulate HTML, CSS, or execute JavaScript code. However, the *information* it provides is crucial for how web pages behave.

* **JavaScript:** JavaScript can access network information through browser APIs like the Network Information API (`navigator.connection`). The `NetworkStateNotifier` is likely the underlying component that feeds data to this API. For example, JavaScript code might adapt the loading of images or videos based on the effective connection type (e.g., load lower-resolution images on a slow 2G connection).
* **HTML/CSS:**  While HTML and CSS don't directly interact with network state, their loading and rendering performance is heavily influenced by the network. The browser might make decisions about resource loading priority or use techniques like responsive images (using the `<picture>` element with `media` queries based on network speed – though this is less direct) based on information provided by the `NetworkStateNotifier`.

**Examples:**

* **JavaScript:**  Imagine a website uses the Network Information API. When the `NetworkStateNotifier` detects a change from Wi-Fi to a slow cellular connection, it will update the information available through `navigator.connection.effectiveType`. A JavaScript function might then react to this change by:
    ```javascript
    if (navigator.connection && navigator.connection.effectiveType === 'slow-2g') {
      // Load lower quality images
      document.querySelectorAll('img[data-high-res]').forEach(img => {
        img.src = img.dataset.lowRes;
      });
    }
    ```
* **HTML/CSS (Indirect):** A website might use a Content Delivery Network (CDN) that dynamically serves different versions of CSS based on network conditions. The browser, informed by `NetworkStateNotifier`, could request a lighter CSS file if the connection is slow.

**3. Logic and Examples (Hypothetical Inputs and Outputs):**

Let's consider the `SaveDataOverride` test case:

* **Hypothetical Input:**
    1. Initially, the network is online, and the connection type is Bluetooth with "Save Data" disabled (`SaveData::kOff`).
    2. The `notifier_.SetSaveDataEnabledOverride(true)` is called.
    3. Later, `SetConnection` is called with `SaveData::kOff`, but the override is still active.
    4. Finally, `notifier_.ClearOverride()` is called.

* **Logical Deduction:** The `NetworkStateNotifier` should prioritize the override setting. When the override is active, calls to `SetConnection` regarding the "Save Data" status should be temporarily ignored. Clearing the override should revert to the last set connection state.

* **Expected Output (Based on the test code):**
    1. Initial state: Observers are notified of `SaveData::kOff`.
    2. After `SetSaveDataEnabledOverride(true)`: Observers are notified of `SaveData::kOn`.
    3. After `SetConnection` with `SaveData::kOff` (while override is active): Observers are *not* notified of a change to `SaveData::kOff`. The override keeps it at `kOn`.
    4. After `ClearOverride()`: Observers are notified of `SaveData::kOff` because the last `SetConnection` call had this value.

**4. Common Usage Errors:**

* **Forgetting to Clear Overrides:**  If `SetNetworkConnectionInfoOverride` or `SetSaveDataEnabledOverride` is used, failing to call `ClearOverride` afterwards could lead to unexpected behavior in the browser, as the network state would be stuck in the overridden state. This is more of an internal Chromium development concern during testing or when implementing specific features.

* **Incorrectly Interpreting Notifications:**  Observers need to be aware that they might receive multiple notifications if multiple aspects of the network state change simultaneously. The `NoExtraNotifications` test checks that redundant notifications are avoided when the same network information is set repeatedly.

* **Race Conditions (Although not directly shown in *this* snippet):** In a multithreaded environment, if the network state changes rapidly and observers are not properly synchronized, they might receive outdated information. The test file uses `RunPendingTasks()` which helps in simulating a single-threaded environment for testing but real-world scenarios require careful synchronization.

**5. Summary of Functionality (Part 2):**

This second part of the test file continues to verify the `NetworkStateNotifier`'s behavior, specifically focusing on:

* **Overrides:** Testing how setting and clearing network connection info and "Save Data" overrides affects the reported network state and notifications. It ensures that while an override is active, regular connection updates are ignored, and that clearing the override restores the normal behavior.
* **Preventing Redundant Notifications:**  Verifying that observers are only notified when there is an actual change in the network state, not for redundant calls with the same information.
* **Initial State Notifications:** Ensuring that observers are not notified during the initial setup of the `NetworkStateNotifier` before any explicit state changes are made.
* **Online/Offline Notifications:** Testing the specific notifications for changes in the online/offline status.
* **Multiple Observers:**  Confirming that multiple observers correctly receive notifications about network state changes.
* **Effective Connection Type Generation:** Checking the logic that derives the effective connection type based on the round-trip time when an explicit effective connection type is not provided in the override.
* **Web Holdback Experiment:** Testing the functionality related to a potential "web holdback" experiment, which might artificially simulate a slower connection.
* **Observer Removal Safety:**  Addressing potential dangling pointer issues if observers are removed while notifications are being processed. This is crucial for memory safety.

In essence, this part of the test file thoroughly exercises the more advanced features of the `NetworkStateNotifier`, particularly its override mechanism and its ability to manage and notify multiple observers efficiently and safely.

这是 blink 引擎中 `NetworkStateNotifier` 类的测试文件的第二部分。延续第一部分，这部分主要关注以下功能：

**1. 测试网络连接信息覆盖 (Network Connection Info Override) 功能:**

* **功能描述:**  `NetworkStateNotifier` 允许设置临时的网络连接信息覆盖，用于模拟特定的网络环境，例如在测试环境下强制模拟某种连接类型或网络速度。
* **测试用例 `SetNetworkConnectionInfoOverride`:**
    * **假设输入:**
        1. 初始状态：在线，连接类型未知，其他网络指标也未知。
        2. 设置网络连接为以太网 (Ethernet)，并设定相关的网络指标 (RTT, Throughput)。
        3. 激活网络连接信息覆盖，设置为以太网，有效的连接类型为 3G，并设定 RTT 和带宽。
        4. 清除覆盖。
    * **逻辑推理:**  当覆盖被激活时，通过 `SetConnection` 设置的常规网络信息应该被临时忽略，而是使用覆盖的值。清除覆盖后，应该恢复到最后一次通过 `SetConnection` 设置的值。
    * **预期输出:**
        1. 初始状态：观察者收到初始的网络状态通知。
        2. 设置以太网后：观察者收到以太网的网络状态通知。
        3. 激活覆盖后：观察者收到覆盖设定的以太网，3G 连接类型的网络状态通知。
        4. 清除覆盖后：观察者收到之前通过 `SetConnection` 设置的未知连接类型的网络状态通知。
* **用户或编程常见使用错误:**
    * **忘记清除覆盖:**  如果在测试或某些特殊场景下激活了覆盖，忘记在之后清除，可能会导致程序在后续运行中一直使用被覆盖的网络信息，而不是真实的物理网络状态。

**2. 测试节省数据模式覆盖 (Save Data Override) 功能:**

* **功能描述:**  `NetworkStateNotifier` 允许设置临时的节省数据模式覆盖，用于模拟用户开启或关闭了节省数据模式的情况。
* **测试用例 `SaveDataOverride`:**
    * **假设输入:**
        1. 初始状态：在线，连接类型为蓝牙，节省数据模式关闭。
        2. 激活节省数据模式覆盖。
        3. 在覆盖激活的情况下，尝试通过 `SetConnection` 设置节省数据模式为关闭。
        4. 清除覆盖。
        5. 设置节省数据模式为开启。
    * **逻辑推理:**  当节省数据模式覆盖被激活时，通过 `SetConnection` 设置的节省数据模式状态应该被临时忽略。清除覆盖后，应该恢复到最后一次通过 `SetConnection` 设置的值。
    * **预期输出:**
        1. 初始状态：观察者收到节省数据模式关闭的通知。
        2. 激活覆盖后：观察者收到节省数据模式开启的通知。
        3. 尝试设置关闭 (覆盖激活)：观察者仍然收到节省数据模式开启的通知，因为覆盖生效。
        4. 清除覆盖后：观察者收到节省数据模式关闭的通知。
        5. 设置开启后：观察者收到节省数据模式开启的通知。
* **用户或编程常见使用错误:**
    * **与网络连接信息覆盖类似，忘记清除覆盖会导致程序行为不符合预期。**

**3. 测试避免不必要的通知 (No Extra Notifications):**

* **功能描述:**  验证 `NetworkStateNotifier` 在网络状态没有实际变化时，不会发送多余的通知给观察者。
* **测试用例 `NoExtraNotifications`:**
    * **假设输入:**
        1. 多次调用 `SetConnection` 设置相同的网络状态。
        2. 调用 `SetConnection` 设置不同的网络状态。
        3. 多次调用 `SetConnection` 设置相同的节省数据模式。
    * **逻辑推理:**  只有当网络连接类型、带宽、有效连接类型、RTT、吞吐量或节省数据模式发生实际变化时，观察者才应该收到通知。
    * **预期输出:**  观察者的回调函数只会在网络状态真正发生变化时被调用。回调次数应该与网络状态的实际变化次数一致。

**4. 测试初始化时不发送通知 (No Notification On Initialization):**

* **功能描述:**  验证 `NetworkStateNotifier` 在初始化时，即使设置了初始的网络状态，也不会立即通知观察者。观察者只会在状态 *改变* 时收到通知。
* **测试用例 `NoNotificationOnInitialization`:**
    * **假设输入:**
        1. 创建 `NetworkStateNotifier` 实例并添加观察者。
        2. 设置初始的网络连接类型和在线状态。
        3. 再次设置相同的网络状态。
        4. 设置不同的网络状态。
        5. 更改在线状态。
    * **逻辑推理:**  初始化设置不应触发通知，只有后续的网络状态变化才会触发。
    * **预期输出:**  观察者的回调函数只会在设置了不同的网络状态和更改了在线状态后被调用。

**5. 测试在线状态通知 (OnLineNotification):**

* **功能描述:**  专门测试 `NetworkStateNotifier` 在在线状态 (OnLine) 发生变化时正确通知观察者。
* **测试用例 `OnLineNotification`:**
    * **假设输入:**  设置在线状态为 true，然后设置为 false。
    * **逻辑推理:**  每次在线状态改变，观察者都应该收到通知。
    * **预期输出:**  观察者会收到两次通知，分别对应在线状态变为 true 和 false。

**6. 测试多个观察者 (Multiple Observers):**

* **功能描述:**  验证 `NetworkStateNotifier` 可以正确地向多个观察者发送网络状态变化的通知。
* **测试用例 `MultipleObservers`:**
    * **假设输入:**  创建两个观察者，一个只观察在线状态，另一个观察所有连接信息。然后更改在线状态和网络连接信息。
    * **逻辑推理:**  所有注册的观察者都应该收到相应的通知。只观察在线状态的观察者只会收到在线状态变化的通知，而观察所有连接信息的观察者会收到所有相关的通知。
    * **预期输出:**  两个观察者的回调函数都会被正确调用，次数和携带的信息与预期的网络状态变化一致。

**7. 测试根据 RTT 生成有效连接类型 (SetNetworkConnectionInfoOverrideGenerateECTs):**

* **功能描述:**  当通过 `SetNetworkConnectionInfoOverride` 设置网络连接信息时，如果没有显式指定有效的连接类型 (EffectiveConnectionType)，则 `NetworkStateNotifier` 应该能够根据提供的 RTT (Round-Trip Time) 值推断出合适的有效连接类型。
* **测试用例 `SetNetworkConnectionInfoOverrideGenerateECTs`:**
    * **假设输入:**  设置不同的 RTT 值。
    * **逻辑推理:**  不同的 RTT 值对应不同的有效连接类型（例如，较小的 RTT 对应 4G，较大的 RTT 对应 2G）。
    * **预期输出:**  观察者收到的通知中，有效的连接类型应该与提供的 RTT 值对应的类型一致。

**8. 测试网络质量 Web Holdback 功能 (SetNetInfoHoldback):**

* **功能描述:**  测试一个可能的 "Web Holdback" 实验功能，该功能可能用于在某些情况下人为地限制或调整网络质量信息。
* **测试用例 `SetNetInfoHoldback`:**
    * **假设输入:**  设置 Web Holdback 的有效连接类型。
    * **逻辑推理:**  设置 Web Holdback 后，`NetworkStateNotifier` 应该返回相应的被 "holdback" 的网络质量指标。
    * **预期输出:**  通过特定的 API 获取到的网络质量信息（如有效连接类型、RTT、吞吐量）应该反映 Web Holdback 设置的值。

**9. 测试移除观察者时的安全性 (RemoveObserverBeforeNotifying 和 RemoveObserverWhileNotifying):**

* **功能描述:**  测试在 `NetworkStateNotifier` 正在发送通知或准备发送通知时移除观察者是否会导致程序崩溃或出现其他错误（例如，悬空指针）。
* **测试用例 `RemoveObserverBeforeNotifying` 和 `RemoveObserverWhileNotifying`:**
    * **假设输入:**
        1. 添加一个观察者。
        2. 触发一个网络状态变化。
        3. 在通知发送 *之前* 或 *期间* 移除观察者。
    * **逻辑推理:**  `NetworkStateNotifier` 应该能够安全地处理观察者的移除，即使在通知过程中。
    * **预期输出:**  程序不会崩溃，也不会出现内存错误。

**总结:**

这部分测试文件主要关注 `NetworkStateNotifier` 类的以下功能：

* **覆盖机制:**  测试网络连接信息覆盖和节省数据模式覆盖的正确性，确保覆盖生效时优先使用覆盖值，清除覆盖后恢复正常。
* **通知机制的优化:**  验证避免发送不必要的重复通知，以及初始化时不发送通知的行为。
* **在线状态通知:**  专门测试在线状态变化的通知。
* **多观察者支持:**  验证可以正确地向多个观察者发送通知。
* **有效连接类型推断:**  测试根据 RTT 值自动推断有效连接类型的功能。
* **Web Holdback 实验功能:**  测试可能存在的 Web Holdback 功能。
* **观察者移除的安全性:**  确保在通知过程中移除观察者不会导致程序错误。

总的来说，这部分测试用例更深入地测试了 `NetworkStateNotifier` 类的核心功能和边界情况，确保其在各种场景下都能正确地管理和通知网络状态信息。这些功能对于浏览器优化资源加载、提升用户体验至关重要。

### 提示词
```
这是目录为blink/renderer/platform/network/network_state_notifier_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
pe3G, notifier_.EffectiveType());
  EXPECT_EQ(kEthernetHttpRtt, notifier_.HttpRtt());
  EXPECT_EQ(kEthernetThroughputMbps, notifier_.DownlinkThroughputMbps());
  VerifyInitialMetricsWithWebHoldbackState(
      kWebConnectionTypeOther, kEthernetThroughputMbps.value(),
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
      kEthernetThroughputMbps, SaveData::kOff);

  // When override is active, calls to SetConnection are temporary ignored.
  notifier_.SetOnLine(false);
  SetConnection(kWebConnectionTypeNone, kNoneMaxBandwidthMbps,
                WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
                kUnknownRtt, kUnknownThroughputMbps, SaveData::kOff);
  RunPendingTasks();
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeOther, kEthernetThroughputMbps.value(),
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt, kUnknownRtt,
      kEthernetThroughputMbps, SaveData::kOff));
  EXPECT_TRUE(notifier_.OnLine());
  EXPECT_EQ(kWebConnectionTypeOther, notifier_.ConnectionType());
  EXPECT_EQ(kEthernetThroughputMbps, notifier_.MaxBandwidth());
  EXPECT_EQ(WebEffectiveConnectionType::kType3G, notifier_.EffectiveType());
  EXPECT_EQ(kEthernetHttpRtt, notifier_.HttpRtt());
  EXPECT_EQ(kEthernetThroughputMbps, notifier_.DownlinkThroughputMbps());

  // Override the network connection info as well.
  notifier_.SetNetworkConnectionInfoOverride(
      true, kWebConnectionTypeEthernet, WebEffectiveConnectionType::kType3G,
      kEthernetHttpRtt.value().InMilliseconds(), kEthernetMaxBandwidthMbps);
  RunPendingTasks();
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt, kUnknownRtt,
      kEthernetMaxBandwidthMbps, SaveData::kOff));
  EXPECT_TRUE(notifier_.OnLine());
  EXPECT_EQ(kWebConnectionTypeEthernet, notifier_.ConnectionType());
  EXPECT_EQ(kEthernetMaxBandwidthMbps, notifier_.MaxBandwidth());
  EXPECT_EQ(WebEffectiveConnectionType::kType3G, notifier_.EffectiveType());
  EXPECT_EQ(kEthernetHttpRtt, notifier_.HttpRtt());
  EXPECT_EQ(kEthernetMaxBandwidthMbps, notifier_.DownlinkThroughputMbps());

  // Clearing the override should cause the network state to be changed and
  // notified to observers.
  notifier_.ClearOverride();
  RunPendingTasks();
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeNone, kNoneMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
  EXPECT_FALSE(notifier_.OnLine());
  EXPECT_EQ(kWebConnectionTypeNone, notifier_.ConnectionType());
  EXPECT_EQ(kNoneMaxBandwidthMbps, notifier_.MaxBandwidth());
  EXPECT_EQ(WebEffectiveConnectionType::kTypeUnknown,
            notifier_.EffectiveType());
  EXPECT_EQ(kUnknownRtt, notifier_.TransportRtt());
  EXPECT_EQ(kUnknownThroughputMbps, notifier_.DownlinkThroughputMbps());
}

TEST_F(NetworkStateNotifierTest, SaveDataOverride) {
  StateObserver observer;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle =
      notifier_.AddConnectionObserver(&observer, GetTaskRunner());

  notifier_.SetOnLine(true);
  // Set save-data attribute to false.
  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
                kUnknownRtt, kUnknownThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
  EXPECT_TRUE(notifier_.OnLine());
  EXPECT_EQ(kWebConnectionTypeBluetooth, notifier_.ConnectionType());
  EXPECT_EQ(kBluetoothMaxBandwidthMbps, notifier_.MaxBandwidth());
  EXPECT_FALSE(notifier_.SaveDataEnabled());

  // Set save-data attribute to true.
  notifier_.SetSaveDataEnabledOverride(true);
  RunPendingTasks();
  EXPECT_TRUE(VerifyObservations(observer, kWebConnectionTypeOther, -1,
                                 WebEffectiveConnectionType::kTypeUnknown,
                                 kUnknownRtt, kUnknownRtt,
                                 kUnknownThroughputMbps, SaveData::kOn));
  EXPECT_TRUE(notifier_.OnLine());
  EXPECT_EQ(kWebConnectionTypeOther, notifier_.ConnectionType());
  EXPECT_EQ(-1, notifier_.MaxBandwidth());
  EXPECT_TRUE(notifier_.SaveDataEnabled());

  // When override is active, calls to SetConnection are temporary ignored.
  // save_data is set to false in SetConnection() but would be temporarily
  // ignored.
  notifier_.SetOnLine(false);
  SetConnection(kWebConnectionTypeNone, -1,
                WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
                kUnknownRtt, kUnknownThroughputMbps, SaveData::kOff);
  RunPendingTasks();
  EXPECT_TRUE(VerifyObservations(observer, kWebConnectionTypeOther, -1,
                                 WebEffectiveConnectionType::kTypeUnknown,
                                 kUnknownRtt, kUnknownRtt,
                                 kUnknownThroughputMbps, SaveData::kOn));
  EXPECT_TRUE(notifier_.OnLine());
  EXPECT_EQ(kWebConnectionTypeOther, notifier_.ConnectionType());
  EXPECT_EQ(-1, notifier_.MaxBandwidth());
  EXPECT_TRUE(notifier_.SaveDataEnabled());

  // CLearing the override should cause the network state to be changed and
  // notified to observers.
  notifier_.ClearOverride();
  RunPendingTasks();
  EXPECT_TRUE(VerifyObservations(observer, kWebConnectionTypeNone, -1,
                                 WebEffectiveConnectionType::kTypeUnknown,
                                 kUnknownRtt, kUnknownRtt,
                                 kUnknownThroughputMbps, SaveData::kOff));
  EXPECT_FALSE(notifier_.OnLine());
  EXPECT_EQ(kWebConnectionTypeNone, notifier_.ConnectionType());
  EXPECT_EQ(-1, notifier_.MaxBandwidth());
  EXPECT_FALSE(notifier_.SaveDataEnabled());

  // Set save-data attribute to true.
  SetConnection(kWebConnectionTypeNone, -1,
                WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
                kUnknownRtt, kUnknownThroughputMbps, SaveData::kOn);
  RunPendingTasks();
  EXPECT_TRUE(VerifyObservations(observer, kWebConnectionTypeNone, -1,
                                 WebEffectiveConnectionType::kTypeUnknown,
                                 kUnknownRtt, kUnknownRtt,
                                 kUnknownThroughputMbps, SaveData::kOn));
  EXPECT_FALSE(notifier_.OnLine());
  EXPECT_EQ(kWebConnectionTypeNone, notifier_.ConnectionType());
  EXPECT_EQ(-1, notifier_.MaxBandwidth());
  EXPECT_TRUE(notifier_.SaveDataEnabled());
}

TEST_F(NetworkStateNotifierTest, NoExtraNotifications) {
  StateObserver observer;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle =
      notifier_.AddConnectionObserver(&observer, GetTaskRunner());

  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
                kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
      kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff));
  EXPECT_EQ(observer.CallbackCount(), 2);

  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
                kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff);
  EXPECT_EQ(observer.CallbackCount(), 2);

  SetConnection(kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
                WebEffectiveConnectionType::kType4G,
                kEthernetHttpRtt.value() * 2, kEthernetTransportRtt.value() * 2,
                kEthernetThroughputMbps.value() * 2, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
      WebEffectiveConnectionType::kType4G, kEthernetHttpRtt.value() * 2,
      kEthernetTransportRtt.value() * 2, kEthernetThroughputMbps.value() * 2,
      SaveData::kOff));
  EXPECT_EQ(observer.CallbackCount(), 4);

  SetConnection(kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
                WebEffectiveConnectionType::kType4G,
                kEthernetHttpRtt.value() * 2, kEthernetTransportRtt.value() * 2,
                kEthernetThroughputMbps.value() * 2, SaveData::kOff);
  EXPECT_EQ(observer.CallbackCount(), 4);

  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
                kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
      kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff));
  EXPECT_EQ(observer.CallbackCount(), 6);

  // Changing the Save-Data attribute should trigger one callback.
  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
                kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOn);
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
      kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOn));
  EXPECT_EQ(observer.CallbackCount(), 7);

  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
                kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOn);
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
      kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOn));
  EXPECT_EQ(observer.CallbackCount(), 7);
}

TEST_F(NetworkStateNotifierTest, NoNotificationOnInitialization) {
  NetworkStateNotifier notifier;
  StateObserver observer;

  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle1 =
      notifier.AddConnectionObserver(&observer, GetTaskRunner());
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle2 =
      notifier.AddOnLineObserver(&observer, GetTaskRunner());
  RunPendingTasks();
  EXPECT_EQ(observer.CallbackCount(), 0);

  notifier.SetWebConnection(kWebConnectionTypeBluetooth,
                            kBluetoothMaxBandwidthMbps);
  notifier.SetOnLine(true);
  RunPendingTasks();
  EXPECT_EQ(observer.CallbackCount(), 0);

  notifier.SetOnLine(true);
  notifier.SetWebConnection(kWebConnectionTypeBluetooth,
                            kBluetoothMaxBandwidthMbps);
  RunPendingTasks();
  EXPECT_EQ(observer.CallbackCount(), 0);

  notifier.SetWebConnection(kWebConnectionTypeEthernet,
                            kEthernetMaxBandwidthMbps);
  RunPendingTasks();
  EXPECT_EQ(observer.CallbackCount(), 1);
  EXPECT_EQ(observer.ObservedType(), kWebConnectionTypeEthernet);
  EXPECT_EQ(observer.ObservedMaxBandwidth(), kEthernetMaxBandwidthMbps);

  notifier.SetOnLine(false);
  RunPendingTasks();
  EXPECT_EQ(observer.CallbackCount(), 2);
  EXPECT_FALSE(observer.ObservedOnLineState());
}

TEST_F(NetworkStateNotifierTest, OnLineNotification) {
  StateObserver observer;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle =
      notifier_.AddOnLineObserver(&observer, GetTaskRunner());

  SetOnLine(true);
  RunPendingTasks();
  EXPECT_TRUE(observer.ObservedOnLineState());
  EXPECT_EQ(observer.CallbackCount(), 1);

  SetOnLine(false);
  RunPendingTasks();
  EXPECT_FALSE(observer.ObservedOnLineState());
  EXPECT_EQ(observer.CallbackCount(), 2);
}

TEST_F(NetworkStateNotifierTest, MultipleObservers) {
  StateObserver observer1;
  StateObserver observer2;

  // Observer1 observes online state, Observer2 observes both.
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle1 =
      notifier_.AddOnLineObserver(&observer1, GetTaskRunner());
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle2 =
      notifier_.AddConnectionObserver(&observer2, GetTaskRunner());
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle3 =
      notifier_.AddOnLineObserver(&observer2, GetTaskRunner());

  notifier_.SetOnLine(true);
  RunPendingTasks();
  EXPECT_TRUE(observer1.ObservedOnLineState());
  EXPECT_TRUE(observer2.ObservedOnLineState());
  EXPECT_EQ(observer1.CallbackCount(), 1);
  EXPECT_EQ(observer2.CallbackCount(), 1);

  notifier_.SetOnLine(false);
  RunPendingTasks();
  EXPECT_FALSE(observer1.ObservedOnLineState());
  EXPECT_FALSE(observer2.ObservedOnLineState());
  EXPECT_EQ(observer1.CallbackCount(), 2);
  EXPECT_EQ(observer2.CallbackCount(), 2);

  notifier_.SetOnLine(true);
  SetConnection(kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
                WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
                kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff);

  EXPECT_TRUE(observer1.ObservedOnLineState());
  EXPECT_TRUE(observer2.ObservedOnLineState());
  EXPECT_TRUE(VerifyObservations(
      observer2, kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
      kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff));
  EXPECT_EQ(observer1.CallbackCount(), 3);
  EXPECT_EQ(observer2.CallbackCount(), 5);
}

TEST_F(NetworkStateNotifierTest, SetNetworkConnectionInfoOverrideGenerateECTs) {
  StateObserver observer;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle =
      notifier_.AddConnectionObserver(&observer, GetTaskRunner());

  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
                kUnknownRtt, kNoneMaxBandwidthMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kNoneMaxBandwidthMbps, SaveData::kOff));

  const struct {
    std::optional<base::TimeDelta> rtt;
    WebEffectiveConnectionType expected_effective_connection_type;
  } tests[] = {
      {base::Milliseconds(100), WebEffectiveConnectionType::kType4G},
      {base::Milliseconds(600), WebEffectiveConnectionType::kType3G},
      {base::Milliseconds(1600), WebEffectiveConnectionType::kType2G},
      {base::Milliseconds(2800), WebEffectiveConnectionType::kTypeSlow2G},
  };

  for (const auto& test : tests) {
    // The effective connection type is set to Unknown.
    // SetNetworkConnectionInfoOverride() should compute the effective
    // connection type based on the provided RTT.
    notifier_.SetNetworkConnectionInfoOverride(
        true, kWebConnectionTypeEthernet, std::nullopt,
        test.rtt.value().InMilliseconds(), kNoneMaxBandwidthMbps);
    RunPendingTasks();
    EXPECT_TRUE(VerifyObservations(
        observer, kWebConnectionTypeEthernet, kNoneMaxBandwidthMbps,
        test.expected_effective_connection_type, test.rtt, kUnknownRtt,
        kNoneMaxBandwidthMbps, SaveData::kOff));
  }
}

// Verify that network state notifier APIs return the correct value when the
// network quality web holdback experiment is enabled.
TEST_F(NetworkStateNotifierTest, SetNetInfoHoldback) {
  VerifyInitialMetricsWithWebHoldbackState(
      kWebConnectionTypeUnknown, kNoneMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff);

  EXPECT_FALSE(notifier_.GetWebHoldbackEffectiveType().has_value());
  EXPECT_FALSE(notifier_.GetWebHoldbackHttpRtt().has_value());
  EXPECT_FALSE(notifier_.GetWebHoldbackDownlinkThroughputMbps().has_value());

  notifier_.SetNetworkQualityWebHoldback(WebEffectiveConnectionType::kType2G);
  VerifyInitialMetricsWithWebHoldbackState(
      kWebConnectionTypeUnknown, kNoneMaxBandwidthMbps,
      WebEffectiveConnectionType::kType2G, base::Milliseconds(1800), 0.075,
      SaveData::kOff);

  EXPECT_EQ(WebEffectiveConnectionType::kType2G,
            notifier_.GetWebHoldbackEffectiveType().value());
  EXPECT_EQ(base::Milliseconds(1800),
            notifier_.GetWebHoldbackHttpRtt().value());
  EXPECT_EQ(0.075, notifier_.GetWebHoldbackDownlinkThroughputMbps().value());
}

// Verify dangling pointer conditions: http://crbug.com/1278708
TEST_F(NetworkStateNotifierTest, RemoveObserverBeforeNotifying) {
  base::test::SingleThreadTaskEnvironment task_environment;
  scoped_refptr<FakeTaskRunner> task_runner =
      base::MakeRefCounted<FakeTaskRunner>();

  std::unique_ptr<StateObserver> observer = std::make_unique<StateObserver>();
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle =
      notifier_.AddOnLineObserver(observer.get(), task_runner);

  SetOnLine(true);
  handle.reset();
  observer.reset();
  task_runner->RunUntilIdle();
}

class OnlineStateObserver : public NetworkStateNotifier::NetworkStateObserver {
 public:
  void OnLineStateChange(bool on_line) override {
    count++;
    handle_.reset();
    task_runner_->RunUntilIdle();
  }
  raw_ptr<FakeTaskRunner> task_runner_;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle_;
  int count = 0;
};

TEST_F(NetworkStateNotifierTest, RemoveObserverWhileNotifying) {
  base::test::SingleThreadTaskEnvironment task_environment;
  scoped_refptr<FakeTaskRunner> task_runner =
      base::MakeRefCounted<FakeTaskRunner>();

  OnlineStateObserver observer;
  observer.task_runner_ = task_runner.get();
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle =
      notifier_.AddOnLineObserver(&observer, task_runner);
  observer.handle_ = std::move(handle);

  SetOnLine(true);
  SetOnLine(false);
  task_runner->RunUntilIdle();
  EXPECT_EQ(1, observer.count);
}

}  // namespace blink
```
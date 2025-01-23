Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Understanding the Goal:**

The request asks for an analysis of `network_change_notifier_delegate_android.cc`. The key aspects to identify are:

* **Functionality:** What does this code *do*?  What are its main responsibilities?
* **Relationship to JavaScript:**  Is there any direct interaction or influence on JavaScript execution within Chromium?
* **Logic and Assumptions:**  Are there specific input-output scenarios that can illustrate its behavior?
* **Common Errors:** What mistakes might developers or the system make when using this code?
* **Debugging:** How does a user's interaction lead to this code being executed?

**2. Initial Code Scan and Keyword Identification:**

A quick skim of the code reveals several important clues:

* **`NetworkChangeNotifierDelegateAndroid`:** This is the central class. The name suggests it's a delegate responsible for handling network change notifications on Android.
* **`JNIEnv*` and Java method calls (`Java_NetworkChangeNotifier_...`, `Java_NetworkActiveNotifier_...`):**  This strongly indicates interaction with the Android Java layer. This is the bridge between Chromium's C++ and the Android OS.
* **`NetworkChangeNotifier::ConnectionType`, `NetworkChangeNotifier::ConnectionCost`, `NetworkChangeNotifier::ConnectionSubtype`:** These enums point to the core data this class manages – information about the network connection.
* **`Observer` pattern:** The `RegisterObserver` and `UnregisterObserver` methods, along with the `observer_` member, suggest this class notifies other parts of Chromium about network changes.
* **`base::android::...`:**  Utilities for interacting with Android from C++.
* **`SetCurrent...` methods:**  Internal methods to update the cached network state.
* **`Notify...` methods:** Methods called from the Java side to inform the C++ side of network events.
* **`Fake...` methods:**  Methods for testing and simulating network events.

**3. Deconstructing Functionality:**

Now, let's systematically examine the purpose of different parts:

* **Initialization (`NetworkChangeNotifierDelegateAndroid::NetworkChangeNotifierDelegateAndroid()`):**  Establishes the connection to the Java side, retrieves the initial network state, and sets up the observer mechanism.
* **Destruction (`NetworkChangeNotifierDelegateAndroid::~NetworkChangeNotifierDelegateAndroid()`):** Cleans up resources and disconnects from the Java side.
* **Getter Methods (`GetCurrentConnectionType`, `GetCurrentConnectionCost`, etc.):** Provide access to the current network state. These are likely used by other Chromium components.
* **`Notify...` Methods:**  These are the core of the interaction with Android. They translate Java network events into C++ notifications and update the internal state. Each `Notify...` method corresponds to a specific network event (connect, disconnect, cost change, etc.).
* **`Fake...` Methods:**  Crucial for testing the network change handling logic in a controlled environment.
* **Observer Pattern Implementation:**  Allows other Chromium components to subscribe to network change events.
* **`JavaLongArrayToNetworkMap`:** A helper function to convert data from the Java side.
* **`ConvertConnectionType`, `ConvertConnectionCost`, `ConvertConnectionSubtype`:**  Mapping functions between Java and C++ enums.

**4. Identifying the JavaScript Connection:**

The key here is to recognize that this C++ code *doesn't directly execute JavaScript*. Instead, it *provides information* about the network to other parts of Chromium. Those other parts, which *could* include components that interact with the rendering engine (Blink), might then expose this information to JavaScript. The thought process is:  "Network information is important for web pages. How does a web page learn about the network state?  Through JavaScript APIs."  This leads to the examples of `navigator.onLine` and the Network Information API.

**5. Constructing Logic and Assumptions:**

For each `Notify...` method, think about:

* **Input:** What data is passed from the Java side?
* **Internal Processing:** How is the internal state updated?
* **Output/Side Effects:** What notifications are sent to observers?

Example: For `NotifyOfNetworkConnect`, the input is `net_id` and `connection_type`. Internally, the `network_map_` is updated. If it's a new connection, observers are notified via `OnNetworkConnected` and potentially `OnNetworkMadeDefault`.

**6. Thinking About Common Errors:**

Consider potential issues:

* **Mismatched Java and C++ states:** If the Java side reports one thing, and the C++ side doesn't update correctly, inconsistencies can occur.
* **Race conditions:** Network events can happen quickly. Proper locking is essential.
* **Incorrect assumptions about Android behavior:**  The code mentions dealing with duplicate notifications on older Android versions.
* **Forgetting to register/unregister observers:**  Leads to missed notifications or crashes.

**7. Tracing User Actions (Debugging Clues):**

The goal here is to connect user behavior to the execution of this C++ code. The path is not always direct.

* **High-level actions:**  Opening a website, downloading a file, watching a video.
* **Network changes:**  Connecting to Wi-Fi, disconnecting, switching to mobile data, airplane mode.
* **Operating System:** Android's network management system detects these changes.
* **Java Layer:** Android's connectivity services notify the Chromium Android Java code (`NetworkChangeNotifier.java`).
* **JNI Bridge:**  The Java code calls the native methods implemented in `network_change_notifier_delegate_android.cc`.
* **C++ Processing:** The C++ code updates its state and notifies observers.
* **Chromium Components:** Other parts of Chromium react to these notifications (e.g., the rendering engine might update the state of `navigator.onLine`).

**8. Refinement and Organization:**

After the initial analysis, organize the information logically under the requested headings. Use clear language and provide specific examples where possible. Review the code and the analysis to ensure accuracy and completeness. For instance, ensuring the explanation of the observer pattern is clear, and the connection to the Java layer is well-defined. Also, double-checking the assumed inputs and outputs for the logical reasoning sections.
好的，我们来详细分析一下 `net/android/network_change_notifier_delegate_android.cc` 这个文件。

**功能概述:**

`NetworkChangeNotifierDelegateAndroid` 类是 Chromium 网络栈中一个关键的组件，它负责监听和处理 Android 系统底层的网络状态变化，并将这些变化通知给 Chromium 的其他部分。  它的主要功能可以概括为：

1. **作为 Android 网络状态变化的监听器：** 它通过 JNI (Java Native Interface) 与 Android 的 Java 代码进行交互，特别是 `android.net.ConnectivityManager` 和相关的 API，来接收网络连接状态、网络类型、网络成本等信息的更新。

2. **将 Android 的网络信息转换为 Chromium 内部的表示：** Android 使用自己的方式来表示网络状态，这个类负责将这些信息转换为 Chromium 网络栈中定义的 `NetworkChangeNotifier::ConnectionType`、`NetworkChangeNotifier::ConnectionCost` 等枚举类型。

3. **维护当前的网络状态：** 它内部维护了当前的网络连接类型、连接成本、默认网络、以及所有活动网络的列表和类型等信息。

4. **通知 Chromium 的其他部分网络状态变化：**  它使用了观察者模式 (Observer pattern)，当网络状态发生变化时，它会通知已经注册的观察者 (`Observer` 接口的实现类)。这些观察者可以是 Chromium 的其他网络组件，例如资源加载器、WebSocket 等。

5. **提供查询当前网络状态的接口：**  Chromium 的其他部分可以通过调用 `NetworkChangeNotifierDelegateAndroid` 的方法来获取当前的网络连接类型、连接成本、默认网络等信息。

6. **提供测试和模拟网络状态变化的接口：**  为了方便测试，这个类提供了一些 `Fake...` 方法，允许在测试环境中模拟各种网络连接和断开的情况。

**与 JavaScript 的关系:**

`NetworkChangeNotifierDelegateAndroid` 本身并不直接执行 JavaScript 代码，但它提供的网络状态信息最终会影响到在 Chromium 内运行的网页和 JavaScript 代码的行为。以下是一些相关的例子：

* **`navigator.onLine` 属性:**  JavaScript 可以通过 `navigator.onLine` 属性来获取浏览器是否处于在线状态。`NetworkChangeNotifierDelegateAndroid` 探测到的网络连接变化会影响到这个属性的值。当网络断开时，`navigator.onLine` 会变为 `false`，反之则为 `true`。

   **举例说明:**
   * **假设输入 (Android):** 用户断开了 Wi-Fi 连接，并且没有移动数据连接。
   * **逻辑推理:**  `NetworkChangeNotifierDelegateAndroid` 会接收到 Android 系统的网络状态更新，判断当前没有可用的网络连接，并将此信息传递给 Chromium 的其他部分。
   * **输出 (JavaScript):**  在网页中运行的 JavaScript 代码查询 `navigator.onLine` 时，会得到 `false` 的结果。

* **Network Information API:**  这是一个更强大的 Web API，允许 JavaScript 获取更详细的网络连接信息，例如连接类型（wifi, cellular, ethernet 等）、数据节省模式等。`NetworkChangeNotifierDelegateAndroid` 获取的连接类型等信息会作为这个 API 的底层数据来源。

   **举例说明:**
   * **假设输入 (Android):** 用户连接到 4G 移动网络。
   * **逻辑推理:** `NetworkChangeNotifierDelegateAndroid` 会接收到连接类型为 4G 的通知，并更新其内部状态。
   * **输出 (JavaScript):**  网页中的 JavaScript 代码可以通过 Network Information API（例如 `navigator.connection.effectiveType`）获取到 "4g" 的连接类型信息。

* **资源加载和错误处理:** 当网络连接断开或不稳定时，JavaScript 发起的网络请求（例如 `fetch` 或 `XMLHttpRequest`) 可能会失败。`NetworkChangeNotifierDelegateAndroid` 提供的网络状态信息可以帮助 JavaScript 代码进行更智能的错误处理和重试机制。

   **举例说明:**
   * **假设输入 (Android):** 用户在网页加载过程中突然进入地铁，导致网络连接中断。
   * **逻辑推理:** `NetworkChangeNotifierDelegateAndroid` 检测到网络断开，并通知 Chromium 的网络组件。
   * **输出 (JavaScript):**  正在进行的网络请求会失败，`fetch` 或 `XMLHttpRequest` 会抛出错误，JavaScript 代码可以捕获这些错误并向用户提示网络连接问题。

**逻辑推理 (假设输入与输出):**

* **场景 1：网络从 Wi-Fi 切换到移动数据 (4G)**
    * **假设输入 (Android):**  Android 系统检测到 Wi-Fi 连接断开，并成功连接到 4G 移动网络。
    * **逻辑推理:**
        1. Android 系统会通过 `ConnectivityManager` 发出网络状态变化的广播。
        2. Chromium 的 Java 代码 (`NetworkChangeNotifier.java`) 接收到广播，并调用 JNI 方法通知 `NetworkChangeNotifierDelegateAndroid`。
        3. `NetworkChangeNotifierDelegateAndroid` 的 `NotifyConnectionTypeChanged` 方法被调用，更新内部的连接类型为 `CONNECTION_4G`，并更新默认网络 ID。
        4. 注册的观察者会收到 `OnConnectionTypeChanged` 和可能的 `OnNetworkMadeDefault` 通知。
    * **输出 (Chromium):**
        * `GetCurrentConnectionType()` 将返回 `CONNECTION_4G`。
        * `GetCurrentDefaultNetwork()` 将返回新的移动网络 ID。
        * JavaScript 中 `navigator.connection.effectiveType` 可能会更新为 "4g"。

* **场景 2：从飞行模式恢复**
    * **假设输入 (Android):** 用户关闭飞行模式，设备重新连接到 Wi-Fi 网络。
    * **逻辑推理:**
        1. Android 系统会检测到网络连接的建立。
        2. `NetworkChangeNotifierDelegateAndroid` 会通过 JNI 接收到多个通知，包括网络连接、连接类型、默认网络等。
        3. `NotifyOfNetworkConnect` 方法会被调用，将新的网络添加到 `network_map_` 中。
        4. `NotifyConnectionTypeChanged` 方法会被调用，更新连接类型和默认网络。
        5. 观察者会收到相应的 `OnNetworkConnected`, `OnConnectionTypeChanged`, `OnNetworkMadeDefault` 等通知。
    * **输出 (Chromium):**
        * `IsDefaultNetworkActive()` 将返回 `true`。
        * 之前无法加载的网页可能会开始加载。
        * JavaScript 中 `navigator.onLine` 会变为 `true`。

**用户或编程常见的使用错误:**

1. **忘记注册观察者:** 如果 Chromium 的某个组件需要监听网络状态变化，但忘记了调用 `RegisterObserver` 方法注册自己，那么它将不会收到任何网络状态更新通知。这可能导致该组件的功能异常。

   **举例说明:**  一个负责缓存网页资源的组件没有正确注册观察者，当网络断开时，它可能仍然尝试从网络加载资源，而不是使用缓存，导致性能问题。

2. **在不应该的时候调用 `SetOnline()` 或 `SetOffline()`:**  这两个方法主要用于测试目的。如果在生产代码中不当使用，可能会导致网络状态的误报，影响 Chromium 的行为。

   **举例说明:**  一个错误的模块调用了 `SetOffline()`，即使设备实际上有网络连接，也会导致网页无法加载。

3. **假设网络状态是静态的:**  开发者可能会错误地假设网络状态在一段时间内不会改变，从而没有正确处理网络状态变化的场景。

   **举例说明:**  一个视频播放器在开始播放时检查了一次网络连接，但没有监听后续的网络变化。如果用户在观看过程中网络断开，播放器可能无法正确处理，导致播放中断或卡顿。

4. **在 Java 层处理网络变化后忘记通知 Native 层:**  如果开发者修改了 Android 的 Java 代码，负责监听网络变化，但忘记通过 JNI 通知 C++ 的 `NetworkChangeNotifierDelegateAndroid`，那么 Chromium 的网络状态将与实际情况不符。

**用户操作是如何一步步到达这里 (作为调试线索):**

假设用户正在浏览网页，并且网络连接发生了变化：

1. **用户操作:** 用户可能执行以下操作导致网络状态变化：
   * **连接或断开 Wi-Fi:** 用户在设备的设置中打开或关闭 Wi-Fi。
   * **启用或禁用移动数据:** 用户在设备的设置中打开或关闭移动数据。
   * **进入或离开飞行模式:** 用户启用或禁用飞行模式。
   * **设备移动到不同网络环境:**  例如，从有 Wi-Fi 的家移动到只有移动数据的户外。
   * **网络信号不稳定或中断:** 运营商的网络问题导致连接中断。

2. **Android 系统事件:**  当上述用户操作或网络环境变化发生时，Android 系统底层的网络管理服务 (如 `ConnectivityService`) 会检测到这些变化。

3. **`ConnectivityManager`:**  `ConnectivityService` 会通过 `ConnectivityManager` 向应用程序发送广播 (如 `android.net.conn.CONNECTIVITY_CHANGE`)，告知网络状态的改变。

4. **Chromium Java 代码 (`NetworkChangeNotifier.java`):**  Chromium 的 Java 代码（特别是 `NetworkChangeNotifier.java`）会注册监听这些网络状态变化的广播。当接收到广播时，它会提取相关的网络信息（连接类型、是否连接、网络 ID 等）。

5. **JNI 调用:**  `NetworkChangeNotifier.java` 会通过 JNI (Java Native Interface) 调用 `net::NetworkChangeNotifierDelegateAndroid` 类中对应的 Native 方法，例如：
   * `NotifyConnectionTypeChanged` (当连接类型改变时)
   * `NotifyOfNetworkConnect` (当新的网络连接建立时)
   * `NotifyOfNetworkDisconnect` (当网络连接断开时)
   * `NotifyConnectionCostChanged` (当网络连接成本改变时)
   * ...等等。

6. **`NetworkChangeNotifierDelegateAndroid` 处理:**  `NetworkChangeNotifierDelegateAndroid` 接收到 JNI 调用后，会执行以下操作：
   * 更新其内部维护的网络状态信息。
   * 通知所有已注册的观察者 (`Observer` 接口的实现类)，告知网络状态发生了变化。

7. **Chromium 其他组件响应:**  接收到通知的观察者（通常是 Chromium 的其他网络组件，例如负责资源加载、WebSocket 连接、QUIC 连接的模块）会根据新的网络状态采取相应的行动，例如：
   * 重新评估路由选择。
   * 尝试重新连接 WebSocket 或 QUIC 连接。
   * 调整资源加载策略。
   * 更新 `navigator.onLine` 和 Network Information API 的值。

**作为调试线索：**  当出现与网络相关的 bug 时，可以按照这个步骤反向追踪：

* **观察到的现象:** 用户报告网页加载失败、视频卡顿、`navigator.onLine` 状态错误等。
* **JavaScript 错误:** 查看开发者工具的 Console 面板，是否有与网络请求相关的错误。
* **断点调试 Java 代码:**  在 `NetworkChangeNotifier.java` 中设置断点，查看是否收到了预期的 Android 网络状态广播，以及传递给 Native 层的参数是否正确。
* **断点调试 C++ 代码:** 在 `NetworkChangeNotifierDelegateAndroid.cc` 的 `Notify...` 方法中设置断点，查看是否接收到了 Java 层的通知，以及内部状态是否更新正确，是否正确通知了观察者。
* **查看网络日志:**  使用 `chrome://net-export/` 可以记录 Chromium 的网络事件，帮助分析网络请求的详细过程以及网络状态变化的时间点。

通过以上分析，可以更深入地理解 `net/android/network_change_notifier_delegate_android.cc` 文件的作用以及它在 Chromium 网络栈中的地位。

### 提示词
```
这是目录为net/android/network_change_notifier_delegate_android.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/android/network_change_notifier_delegate_android.h"

#include "base/android/build_info.h"
#include "base/android/jni_array.h"
#include "base/check.h"
#include "base/notreached.h"
#include "net/android/network_change_notifier_android.h"
#include "net/base/features.h"

// Must come after all headers that specialize FromJniType() / ToJniType().
#include "net/net_jni_headers/NetworkActiveNotifier_jni.h"
#include "net/net_jni_headers/NetworkChangeNotifier_jni.h"

using base::android::JavaParamRef;
using base::android::JavaRef;
using base::android::ScopedJavaLocalRef;

namespace net {

namespace {

// Converts a Java side connection type (integer) to
// the native side NetworkChangeNotifier::ConnectionType.
NetworkChangeNotifier::ConnectionType ConvertConnectionType(
    jint connection_type) {
  switch (connection_type) {
    case NetworkChangeNotifier::CONNECTION_UNKNOWN:
    case NetworkChangeNotifier::CONNECTION_ETHERNET:
    case NetworkChangeNotifier::CONNECTION_WIFI:
    case NetworkChangeNotifier::CONNECTION_2G:
    case NetworkChangeNotifier::CONNECTION_3G:
    case NetworkChangeNotifier::CONNECTION_4G:
    case NetworkChangeNotifier::CONNECTION_5G:
    case NetworkChangeNotifier::CONNECTION_NONE:
    case NetworkChangeNotifier::CONNECTION_BLUETOOTH:
      break;
    default:
      NOTREACHED() << "Unknown connection type received: " << connection_type;
  }
  return static_cast<NetworkChangeNotifier::ConnectionType>(connection_type);
}

// Converts a Java side connection cost (integer) to
// the native side NetworkChangeNotifier::ConnectionCost.
NetworkChangeNotifier::ConnectionCost ConvertConnectionCost(
    jint connection_cost) {
  switch (connection_cost) {
    case NetworkChangeNotifier::CONNECTION_COST_UNKNOWN:
    case NetworkChangeNotifier::CONNECTION_COST_UNMETERED:
    case NetworkChangeNotifier::CONNECTION_COST_METERED:
      break;
    default:
      NOTREACHED() << "Unknown connection cost received: " << connection_cost;
  }
  return static_cast<NetworkChangeNotifier::ConnectionCost>(connection_cost);
}

// Converts a Java side connection type (integer) to
// the native side NetworkChangeNotifier::ConnectionType.
NetworkChangeNotifier::ConnectionSubtype ConvertConnectionSubtype(
    jint subtype) {
  DCHECK(subtype >= 0 && subtype <= NetworkChangeNotifier::SUBTYPE_LAST);

  return static_cast<NetworkChangeNotifier::ConnectionSubtype>(subtype);
}

}  // namespace

// static
void NetworkChangeNotifierDelegateAndroid::JavaLongArrayToNetworkMap(
    JNIEnv* env,
    const JavaRef<jlongArray>& long_array,
    NetworkMap* network_map) {
  std::vector<int64_t> int64_list;
  base::android::JavaLongArrayToInt64Vector(env, long_array, &int64_list);
  network_map->clear();
  for (auto i = int64_list.begin(); i != int64_list.end(); ++i) {
    handles::NetworkHandle network_handle = *i;
    CHECK(++i != int64_list.end());
    (*network_map)[network_handle] = static_cast<ConnectionType>(*i);
  }
}

NetworkChangeNotifierDelegateAndroid::NetworkChangeNotifierDelegateAndroid()
    : java_network_change_notifier_(Java_NetworkChangeNotifier_init(
          base::android::AttachCurrentThread())),
      register_network_callback_failed_(
          Java_NetworkChangeNotifier_registerNetworkCallbackFailed(
              base::android::AttachCurrentThread(),
              java_network_change_notifier_)) {
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_NetworkChangeNotifier_addNativeObserver(
      env, java_network_change_notifier_, reinterpret_cast<intptr_t>(this));
  SetCurrentConnectionType(
      ConvertConnectionType(Java_NetworkChangeNotifier_getCurrentConnectionType(
          env, java_network_change_notifier_)));
  SetCurrentConnectionCost(
      ConvertConnectionCost(Java_NetworkChangeNotifier_getCurrentConnectionCost(
          env, java_network_change_notifier_)));
  auto connection_subtype = ConvertConnectionSubtype(
      Java_NetworkChangeNotifier_getCurrentConnectionSubtype(
          env, java_network_change_notifier_));
  SetCurrentConnectionSubtype(connection_subtype);
  SetCurrentMaxBandwidth(
      NetworkChangeNotifierAndroid::GetMaxBandwidthMbpsForConnectionSubtype(
          connection_subtype));
  SetCurrentDefaultNetwork(Java_NetworkChangeNotifier_getCurrentDefaultNetId(
      env, java_network_change_notifier_));
  NetworkMap network_map;
  ScopedJavaLocalRef<jlongArray> networks_and_types =
      Java_NetworkChangeNotifier_getCurrentNetworksAndTypes(
          env, java_network_change_notifier_);
  JavaLongArrayToNetworkMap(env, networks_and_types, &network_map);
  SetCurrentNetworksAndTypes(network_map);
  java_network_active_notifier_ = Java_NetworkActiveNotifier_build(
      base::android::AttachCurrentThread(), reinterpret_cast<intptr_t>(this));
}

NetworkChangeNotifierDelegateAndroid::~NetworkChangeNotifierDelegateAndroid() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_EQ(default_network_active_observers_, 0);
  {
    base::AutoLock auto_lock(observer_lock_);
    DCHECK(!observer_);
  }
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_NetworkChangeNotifier_removeNativeObserver(
      env, java_network_change_notifier_, reinterpret_cast<intptr_t>(this));
}

NetworkChangeNotifier::ConnectionType
NetworkChangeNotifierDelegateAndroid::GetCurrentConnectionType() const {
  base::AutoLock auto_lock(connection_lock_);
  return connection_type_;
}

NetworkChangeNotifier::ConnectionCost
NetworkChangeNotifierDelegateAndroid::GetCurrentConnectionCost() {
  base::AutoLock auto_lock(connection_lock_);
  return connection_cost_;
}

NetworkChangeNotifier::ConnectionSubtype
NetworkChangeNotifierDelegateAndroid::GetCurrentConnectionSubtype() const {
  if (base::FeatureList::IsEnabled(net::features::kStoreConnectionSubtype)) {
    base::AutoLock auto_lock(connection_lock_);
    return connection_subtype_;
  }
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return ConvertConnectionSubtype(
      Java_NetworkChangeNotifier_getCurrentConnectionSubtype(
          base::android::AttachCurrentThread(), java_network_change_notifier_));
}

void NetworkChangeNotifierDelegateAndroid::
    GetCurrentMaxBandwidthAndConnectionType(
        double* max_bandwidth_mbps,
        ConnectionType* connection_type) const {
  base::AutoLock auto_lock(connection_lock_);
  *connection_type = connection_type_;
  *max_bandwidth_mbps = connection_max_bandwidth_;
}

NetworkChangeNotifier::ConnectionType
NetworkChangeNotifierDelegateAndroid::GetNetworkConnectionType(
    handles::NetworkHandle network) const {
  base::AutoLock auto_lock(connection_lock_);
  auto network_entry = network_map_.find(network);
  if (network_entry == network_map_.end())
    return ConnectionType::CONNECTION_UNKNOWN;
  return network_entry->second;
}

handles::NetworkHandle
NetworkChangeNotifierDelegateAndroid::GetCurrentDefaultNetwork() const {
  base::AutoLock auto_lock(connection_lock_);
  return default_network_;
}

void NetworkChangeNotifierDelegateAndroid::GetCurrentlyConnectedNetworks(
    NetworkList* network_list) const {
  network_list->clear();
  base::AutoLock auto_lock(connection_lock_);
  for (auto i : network_map_)
    network_list->push_back(i.first);
}

bool NetworkChangeNotifierDelegateAndroid::IsDefaultNetworkActive() {
  JNIEnv* env = base::android::AttachCurrentThread();
  return Java_NetworkActiveNotifier_isDefaultNetworkActive(
      env, java_network_active_notifier_);
}

void NetworkChangeNotifierDelegateAndroid::NotifyConnectionCostChanged(
    JNIEnv* env,
    const JavaParamRef<jobject>& obj,
    jint new_connection_cost) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  const ConnectionCost actual_connection_cost =
      ConvertConnectionCost(new_connection_cost);
  SetCurrentConnectionCost(actual_connection_cost);
  base::AutoLock auto_lock(observer_lock_);
  if (observer_)
    observer_->OnConnectionCostChanged();
}

void NetworkChangeNotifierDelegateAndroid::NotifyConnectionTypeChanged(
    JNIEnv* env,
    const JavaParamRef<jobject>& obj,
    jint new_connection_type,
    jlong default_netid) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  const ConnectionType actual_connection_type = ConvertConnectionType(
      new_connection_type);
  SetCurrentConnectionType(actual_connection_type);
  handles::NetworkHandle default_network = default_netid;
  if (default_network != GetCurrentDefaultNetwork()) {
    SetCurrentDefaultNetwork(default_network);
    bool default_exists;
    {
      base::AutoLock auto_lock(connection_lock_);
      // |default_network| may be an invalid value (i.e. -1) in cases where
      // the device is disconnected or when run on Android versions prior to L,
      // in which case |default_exists| will correctly be false and no
      // OnNetworkMadeDefault notification will be sent.
      default_exists = network_map_.find(default_network) != network_map_.end();
    }
    // Android Lollipop had race conditions where CONNECTIVITY_ACTION intents
    // were sent out before the network was actually made the default.
    // Delay sending the OnNetworkMadeDefault notification until we are
    // actually notified that the network connected in NotifyOfNetworkConnect.
    if (default_exists) {
      base::AutoLock auto_lock(observer_lock_);
      if (observer_)
        observer_->OnNetworkMadeDefault(default_network);
    }
  }

  base::AutoLock auto_lock(observer_lock_);
  if (observer_)
    observer_->OnConnectionTypeChanged();
}

jint NetworkChangeNotifierDelegateAndroid::GetConnectionType(JNIEnv*,
                                                             jobject) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return GetCurrentConnectionType();
}

jint NetworkChangeNotifierDelegateAndroid::GetConnectionCost(JNIEnv*, jobject) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return GetCurrentConnectionCost();
}

void NetworkChangeNotifierDelegateAndroid::NotifyConnectionSubtypeChanged(
    JNIEnv* env,
    const JavaParamRef<jobject>& obj,
    jint subtype) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  double new_max_bandwidth =
      NetworkChangeNotifierAndroid::GetMaxBandwidthMbpsForConnectionSubtype(
          ConvertConnectionSubtype(subtype));
  SetCurrentConnectionSubtype(ConvertConnectionSubtype(subtype));
  SetCurrentMaxBandwidth(new_max_bandwidth);
  const ConnectionType connection_type = GetCurrentConnectionType();
  base::AutoLock auto_lock(observer_lock_);
  if (observer_) {
    observer_->OnMaxBandwidthChanged(new_max_bandwidth, connection_type);
  }
}

void NetworkChangeNotifierDelegateAndroid::NotifyOfNetworkConnect(
    JNIEnv* env,
    const JavaParamRef<jobject>& obj,
    jlong net_id,
    jint connection_type) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  handles::NetworkHandle network = net_id;
  bool already_exists;
  bool is_default_network;
  {
    base::AutoLock auto_lock(connection_lock_);
    already_exists = network_map_.find(network) != network_map_.end();
    network_map_[network] = static_cast<ConnectionType>(connection_type);
    is_default_network = (network == default_network_);
  }
  // Android Lollipop would send many duplicate notifications.
  // This was later fixed in Android Marshmallow.
  // Deduplicate them here by avoiding sending duplicate notifications.
  if (!already_exists) {
    base::AutoLock auto_lock(observer_lock_);
    if (observer_) {
      observer_->OnNetworkConnected(network);
      if (is_default_network)
        observer_->OnNetworkMadeDefault(network);
    }
  }
}

void NetworkChangeNotifierDelegateAndroid::NotifyOfNetworkSoonToDisconnect(
    JNIEnv* env,
    const JavaParamRef<jobject>& obj,
    jlong net_id) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  handles::NetworkHandle network = net_id;
  {
    base::AutoLock auto_lock(connection_lock_);
    if (network_map_.find(network) == network_map_.end())
      return;
  }
  base::AutoLock auto_lock(observer_lock_);
  if (observer_)
    observer_->OnNetworkSoonToDisconnect(network);
}

void NetworkChangeNotifierDelegateAndroid::NotifyOfNetworkDisconnect(
    JNIEnv* env,
    const JavaParamRef<jobject>& obj,
    jlong net_id) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  handles::NetworkHandle network = net_id;
  {
    base::AutoLock auto_lock(connection_lock_);
    if (network == default_network_)
      default_network_ = handles::kInvalidNetworkHandle;
    if (network_map_.erase(network) == 0)
      return;
  }
  base::AutoLock auto_lock(observer_lock_);
  if (observer_)
    observer_->OnNetworkDisconnected(network);
}

void NetworkChangeNotifierDelegateAndroid::NotifyPurgeActiveNetworkList(
    JNIEnv* env,
    const JavaParamRef<jobject>& obj,
    const JavaParamRef<jlongArray>& active_networks) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  NetworkList active_network_list;
  base::android::JavaLongArrayToInt64Vector(env, active_networks,
                                            &active_network_list);
  NetworkList disconnected_networks;
  {
    base::AutoLock auto_lock(connection_lock_);
    for (auto i : network_map_) {
      bool found = false;
      for (auto j : active_network_list) {
        if (j == i.first) {
          found = true;
          break;
        }
      }
      if (!found) {
        disconnected_networks.push_back(i.first);
      }
    }
  }
  for (auto disconnected_network : disconnected_networks)
    NotifyOfNetworkDisconnect(env, obj, disconnected_network);
}

void NetworkChangeNotifierDelegateAndroid::NotifyOfDefaultNetworkActive(
    JNIEnv* env) {
  base::AutoLock auto_lock(observer_lock_);
  if (observer_)
    observer_->OnDefaultNetworkActive();
}

void NetworkChangeNotifierDelegateAndroid::RegisterObserver(
    Observer* observer) {
  base::AutoLock auto_lock(observer_lock_);
  DCHECK(!observer_);
  observer_ = observer;
}

void NetworkChangeNotifierDelegateAndroid::UnregisterObserver(
    Observer* observer) {
  base::AutoLock auto_lock(observer_lock_);
  DCHECK_EQ(observer_, observer);
  observer_ = nullptr;
}

void NetworkChangeNotifierDelegateAndroid::DefaultNetworkActiveObserverAdded() {
  if (default_network_active_observers_.fetch_add(1) == 0)
    EnableDefaultNetworkActiveNotifications();
}

void NetworkChangeNotifierDelegateAndroid::
    DefaultNetworkActiveObserverRemoved() {
  if (default_network_active_observers_.fetch_sub(1) == 1)
    DisableDefaultNetworkActiveNotifications();
}

void NetworkChangeNotifierDelegateAndroid::
    EnableDefaultNetworkActiveNotifications() {
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_NetworkActiveNotifier_enableNotifications(env,
                                                 java_network_active_notifier_);
}

void NetworkChangeNotifierDelegateAndroid::
    DisableDefaultNetworkActiveNotifications() {
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_NetworkActiveNotifier_disableNotifications(
      env, java_network_active_notifier_);
}

void NetworkChangeNotifierDelegateAndroid::SetCurrentConnectionType(
    ConnectionType new_connection_type) {
  base::AutoLock auto_lock(connection_lock_);
  connection_type_ = new_connection_type;
}

void NetworkChangeNotifierDelegateAndroid::SetCurrentConnectionSubtype(
    ConnectionSubtype new_connection_subtype) {
  base::AutoLock auto_lock(connection_lock_);
  connection_subtype_ = new_connection_subtype;
}

void NetworkChangeNotifierDelegateAndroid::SetCurrentConnectionCost(
    ConnectionCost new_connection_cost) {
  base::AutoLock auto_lock(connection_lock_);
  connection_cost_ = new_connection_cost;
}

void NetworkChangeNotifierDelegateAndroid::SetCurrentMaxBandwidth(
    double max_bandwidth) {
  base::AutoLock auto_lock(connection_lock_);
  connection_max_bandwidth_ = max_bandwidth;
}

void NetworkChangeNotifierDelegateAndroid::SetCurrentDefaultNetwork(
    handles::NetworkHandle default_network) {
  base::AutoLock auto_lock(connection_lock_);
  default_network_ = default_network;
}

void NetworkChangeNotifierDelegateAndroid::SetCurrentNetworksAndTypes(
    NetworkMap network_map) {
  base::AutoLock auto_lock(connection_lock_);
  network_map_ = network_map;
}

void NetworkChangeNotifierDelegateAndroid::SetOnline() {
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_NetworkChangeNotifier_forceConnectivityState(env, true);
}

void NetworkChangeNotifierDelegateAndroid::SetOffline() {
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_NetworkChangeNotifier_forceConnectivityState(env, false);
}

void NetworkChangeNotifierDelegateAndroid::FakeNetworkConnected(
    handles::NetworkHandle network,
    ConnectionType type) {
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_NetworkChangeNotifier_fakeNetworkConnected(env, network, type);
}

void NetworkChangeNotifierDelegateAndroid::FakeNetworkSoonToBeDisconnected(
    handles::NetworkHandle network) {
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_NetworkChangeNotifier_fakeNetworkSoonToBeDisconnected(env, network);
}

void NetworkChangeNotifierDelegateAndroid::FakeNetworkDisconnected(
    handles::NetworkHandle network) {
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_NetworkChangeNotifier_fakeNetworkDisconnected(env, network);
}

void NetworkChangeNotifierDelegateAndroid::FakePurgeActiveNetworkList(
    NetworkChangeNotifier::NetworkList networks) {
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_NetworkChangeNotifier_fakePurgeActiveNetworkList(
      env, base::android::ToJavaLongArray(env, networks));
}

void NetworkChangeNotifierDelegateAndroid::FakeDefaultNetwork(
    handles::NetworkHandle network,
    ConnectionType type) {
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_NetworkChangeNotifier_fakeDefaultNetwork(env, network, type);
}

void NetworkChangeNotifierDelegateAndroid::FakeConnectionCostChanged(
    ConnectionCost cost) {
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_NetworkChangeNotifier_fakeConnectionCostChanged(env, cost);
}

void NetworkChangeNotifierDelegateAndroid::FakeConnectionSubtypeChanged(
    ConnectionSubtype subtype) {
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_NetworkChangeNotifier_fakeConnectionSubtypeChanged(env, subtype);
}

void NetworkChangeNotifierDelegateAndroid::FakeDefaultNetworkActive() {
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_NetworkActiveNotifier_fakeDefaultNetworkActive(
      env, java_network_active_notifier_);
}

void NetworkChangeNotifierDelegateAndroid::
    EnableNetworkChangeNotifierAutoDetectForTest() {
  JNIEnv* env = base::android::AttachCurrentThread();
  Java_NetworkChangeNotifier_setAutoDetectConnectivityState(env, true);
}

}  // namespace net
```
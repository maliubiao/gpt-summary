Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Request:** The core request is to explain the functionality of `network_change_notifier_android.cc`, its relation to JavaScript, how it works with specific inputs and outputs, common errors, and how a user might reach this code during debugging.

2. **Initial Code Scan and High-Level Understanding:**  First, I'd skim the code and comments to grasp the overall purpose. Key things that jump out are:
    * "Network Change Notifier":  This suggests the code is responsible for detecting and reporting network connectivity changes.
    * "Android":  It's specific to the Android platform.
    * "Threading considerations":  The extensive comments about threading are important. It highlights the interaction between native C++ and Java and the need for careful synchronization.
    * "Propagation of network change notifications": This explains the data flow: Android platform -> Java code -> Native C++ code -> Observers.
    * Includes like `<string>`, `<unordered_set>`, `"base/..."`, `"net/..."`: These give hints about the libraries and functionalities used. `base/android/build_info.h` suggests interaction with Android system information. `net/base/address_tracker_linux.h` hints at lower-level network monitoring (though it's conditionally used).

3. **Deconstructing the Code - Functionality:** Now, I'd go through the code section by section, focusing on the public methods and the important private ones.

    * **Constructor/Destructor:**  `NetworkChangeNotifierAndroid()` and `~NetworkChangeNotifierAndroid()` show initialization (registering as an observer) and cleanup (unregistering).
    * **`GetCurrentConnectionType()` and related `GetCurrent...` methods:** These are clearly for querying the current network state. The delegation to `delegate_` is crucial.
    * **`ForceNetworkHandlesSupportedForTesting()` and `AreNetworkHandlesCurrentlySupported()`:** This is related to network handles (NetIDs) and suggests different ways of identifying networks depending on Android versions.
    * **`GetCurrentConnectedNetworks()`:** Retrieves a list of currently active networks.
    * **`OnConnectionTypeChanged()`, `OnConnectionCostChanged()`, etc.:** These are *callbacks* triggered by the `delegate_` when network events occur. They then notify other observers.
    * **`BlockingThreadObjects`:** This inner class, used conditionally for older Android versions, manages `AddressTrackerLinux` for tunnel state changes. The threading comments mention it needs a specific type of message loop.
    * **`NetworkChangeCalculatorParamsAndroid()`:**  Defines parameters for delaying notifications, likely to avoid rapid, potentially noisy updates.

4. **Identifying Relationships and Data Flow:** The comments about "factory" and "delegate" are crucial. I'd infer the following:
    * `NetworkChangeNotifierFactoryAndroid` creates `NetworkChangeNotifierDelegateAndroid`.
    * `NetworkChangeNotifierAndroid` is the class being analyzed.
    * `NetworkChangeNotifierDelegateAndroid` acts as an intermediary, receiving notifications from Java and forwarding them to `NetworkChangeNotifierAndroid`.
    * The Java side (`NetworkChangeNotifier.java`) is the ultimate source of truth for network changes on Android.

5. **JavaScript Interaction:**  At this point, I'd think about how browser functionality relies on network information. Things like:
    * Fetch API:  JavaScript needs to know the network status to make requests.
    * WebSockets:  Requires a stable network connection.
    * Online/Offline events:  JavaScript can react to changes in connectivity.
    * Network Information API:  Provides details about the connection type, speed, etc., directly to web pages.

    The key connection is that the *data* this C++ code gathers is *used* by JavaScript through the Chromium rendering engine's APIs. The C++ code doesn't directly execute JavaScript, but it provides the foundation for JavaScript's network awareness.

6. **Logic and Input/Output:**  Consider the callback functions.

    * **Assumption:** The Android system detects a Wi-Fi connection.
    * **Input:** The Android system signals a change.
    * **Processing:** The Java `NetworkChangeNotifier` detects this, the `NetworkChangeNotifierDelegateAndroid` receives the notification (on the main thread), and calls `OnConnectionTypeChanged()` on the `NetworkChangeNotifierAndroid` instance.
    * **Output:**  `NetworkChangeNotifierAndroid::OnConnectionTypeChanged()` calls `NetworkChangeNotifier::NotifyObserversOfConnectionTypeChange()`, which informs other parts of Chromium (potentially including the rendering engine) about the change.

7. **Common Errors:** Think about what could go wrong:
    * **Permissions:** Android apps need permissions to access network state.
    * **Race conditions:**  The threading complexity introduces possibilities for race conditions, especially if the Java and C++ sides aren't synchronized correctly.
    * **Incorrect observer registration:** If observers don't register or unregister properly, they might miss notifications or cause crashes.

8. **User Actions and Debugging:** How does a user trigger this code?
    * **Connecting to Wi-Fi/Cellular:** A fundamental user action.
    * **Airplane mode:**  A deliberate action that changes network state.
    * **Network settings changes:**  Modifying Wi-Fi networks, etc.
    * **VPN usage:** Connecting to or disconnecting from a VPN.

    For debugging, looking at network events in `chrome://net-export/` or using Android Studio's network monitoring tools would be relevant. Breakpoints in the C++ code (in Android Studio while debugging Chrome on Android) would be a direct way to inspect the flow.

9. **Structuring the Answer:** Finally, organize the information logically, using clear headings and examples. The original request's structure (functionality, JavaScript relation, logic, errors, debugging) provides a good framework. Use bullet points and code snippets where appropriate to make it easy to read.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe JavaScript calls into this C++ code directly. **Correction:** Realize that the interaction is more indirect, through Chromium's internal APIs. JavaScript uses higher-level APIs that rely on this lower-level code.
* **Overlooking details:**  Initially, I might not fully grasp the purpose of `BlockingThreadObjects`. **Refinement:**  Re-read the comments and code related to it, noting its conditional use for older Android versions and its role in monitoring tunnel interfaces.
* **Being too general:**  Instead of just saying "handles network changes,"  be specific about *what kind* of changes (connection type, cost, IP address, specific network connections, default network).
* **Not giving concrete examples:**  Instead of just saying "JavaScript uses this," give specific API examples like `navigator.onLine` or the Network Information API.

By following this structured approach, combining code analysis with understanding the broader context of network management and browser functionality, I can generate a comprehensive and accurate explanation.
This C++ file, `network_change_notifier_android.cc`, is a crucial part of Chromium's network stack on Android. Its primary function is to **monitor network connectivity changes on the Android device and propagate these changes to other parts of the Chromium browser**. It acts as a bridge between the Android operating system's network status and Chromium's internal network handling mechanisms.

Here's a breakdown of its key functionalities:

**1. Network Change Detection:**

* It registers as an observer with a Java-side singleton class (`NetworkChangeNotifier.java` - outside the scope of this file, but mentioned in the comments). This Java class listens to Android system broadcasts and callbacks related to network state changes.
* When the Java side detects a change (e.g., Wi-Fi connected, cellular disconnected, network type changed), it notifies the native `NetworkChangeNotifierAndroid` instance through its `NetworkChangeNotifierDelegateAndroid`.

**2. Abstraction and Normalization:**

* It abstracts away the Android-specific details of network change notifications. Chromium's core network stack doesn't need to know the intricacies of Android's `ConnectivityManager` or network intents.
* It normalizes the network information into a platform-independent format understood by Chromium's `NetworkChangeNotifier` base class.

**3. Notification Propagation:**

* It inherits from `net::NetworkChangeNotifier`, making it a source of network change events within Chromium.
* When it receives a notification from the Java side, it processes the change and then uses the `NetworkChangeNotifier` base class to notify other interested components within Chromium about the network event. These components could include:
    * The rendering engine (Blink) to inform web pages about online/offline status.
    * The download manager to pause or resume downloads.
    * The networking layer for routing decisions.
    * Services that rely on network connectivity.

**4. Providing Current Network State Information:**

* It provides methods to query the current network state, such as:
    * `GetCurrentConnectionType()`: Returns the general type of connection (e.g., Wi-Fi, cellular, none).
    * `GetCurrentConnectionCost()`: Returns whether the connection is metered or not.
    * `GetCurrentConnectionSubtype()`: Provides more granular information about the connection (e.g., 4G, 3G).
    * `GetCurrentMaxBandwidthAndConnectionType()`:  Estimates the maximum bandwidth.
    * `GetCurrentConnectedNetworks()`:  Lists currently active network handles (NetIds).
    * `GetCurrentNetworkConnectionType(handles::NetworkHandle network)`: Gets the connection type for a specific network.
    * `GetCurrentDefaultNetwork()`:  Returns the handle of the currently default network.

**5. Handling Network Handles (NetIds):**

* It deals with Android's concept of "NetIds" (represented as `handles::NetworkHandle` in the code), which are unique identifiers for network interfaces.
* It provides methods to get network information based on these handles, particularly for Android versions Lollipop (API level 21) and above, where network handles are more comprehensively supported.

**Relationship with JavaScript Functionality:**

This C++ code has a **indirect but crucial relationship** with JavaScript functionality in the browser. Here's how:

* **`navigator.onLine` property and `online`/`offline` events:**  When the `NetworkChangeNotifierAndroid` detects a change in overall network connectivity (going online or offline), it ultimately triggers events that update the JavaScript `navigator.onLine` property and fire the `online` and `offline` events on the `window` object. Web pages can listen for these events to adjust their behavior based on network availability.

   **Example:**
   ```javascript
   window.addEventListener('online', function() {
     console.log('Browser is online');
     // Re-enable features that require network access.
   });

   window.addEventListener('offline', function() {
     console.log('Browser is offline');
     // Disable features that require network access, perhaps show a warning.
   });

   if (navigator.onLine) {
     console.log('Initial online status: Online');
   } else {
     console.log('Initial online status: Offline');
   }
   ```

* **Network Information API (`navigator.connection`):** This API provides more detailed information about the user's network connection, such as the connection type (`effectiveType`), downlink speed (`downlink`), and whether the connection is metered (`metering`). The data provided by this C++ code is used to populate the values of the `navigator.connection` object.

   **Example:**
   ```javascript
   if (navigator.connection) {
     console.log('Connection type:', navigator.connection.effectiveType);
     console.log('Downlink speed:', navigator.connection.downlink, 'Mb/s');
     console.log('Metered connection:', navigator.connection.metering);
   }
   ```

**Logical Reasoning with Assumptions (Hypothetical Input and Output):**

**Scenario:** The user disconnects their Android phone from a Wi-Fi network.

**Assumptions:**

* The phone was successfully connected to a Wi-Fi network.
* The Android operating system correctly detects the Wi-Fi disconnection.
* The Java-side `NetworkChangeNotifier` is registered and listening for network changes.

**Input:**

1. The Android system detects the Wi-Fi disconnect and broadcasts a corresponding intent or calls a relevant callback.
2. The Java `NetworkChangeNotifier` receives this signal.
3. The Java `NetworkChangeNotifier` calls the appropriate method on the `NetworkChangeNotifierDelegateAndroid` instance.

**Processing (within `network_change_notifier_android.cc`):**

1. The `NetworkChangeNotifierDelegateAndroid` (on the main thread) receives the notification.
2. It calls the relevant method on the registered `NetworkChangeNotifierAndroid` instance, likely `OnConnectionTypeChanged()` and potentially `OnNetworkDisconnected()` for the specific Wi-Fi network's handle.
3. `OnConnectionTypeChanged()` calls `BlockingThreadObjects::NotifyNetworkChangeNotifierObservers()`, which in turn calls `NetworkChangeNotifier::NotifyObserversOfConnectionTypeChange()`.
4. `OnNetworkDisconnected()` calls `NetworkChangeNotifier::NotifyObserversOfSpecificNetworkChange(NetworkChangeType::kDisconnected, network_handle_of_wifi)`.

**Output:**

1. Chromium's internal observers (e.g., the rendering engine) are notified of the connection type change (likely from "WIFI" to "CELLULAR" or "NONE").
2. Observers are notified about the disconnection of the specific Wi-Fi network (if network handles are supported).
3. JavaScript code running in web pages receives the `offline` event.
4. The `navigator.onLine` property becomes `false`.
5. The `navigator.connection` object might update its properties to reflect the new connection type (e.g., `effectiveType` changes to "4g" or "3g").

**User or Programming Common Usage Errors:**

1. **Missing Network Permissions on Android:** If the Chromium application (or the embedding app) doesn't have the necessary Android permissions to access network state (e.g., `ACCESS_NETWORK_STATE`), this code will not receive notifications. This is a common Android development error. The user will likely see incorrect network status within the browser.

   **Example:** The Android Manifest file is missing the `<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />` line.

2. **Incorrect Assumption about Threading:** The comments in the code heavily emphasize threading considerations. Developers working with this code (or related Java code) might make errors by calling methods from the wrong threads. For instance, trying to directly call methods on the Java `NetworkChangeNotifier` from a non-main thread could lead to crashes or unexpected behavior.

3. **Not Registering Observers Properly:** Components within Chromium need to register themselves as observers with the `NetworkChangeNotifier` to receive network change notifications. If a component forgets to register or unregisters prematurely, it will miss important network events.

4. **Misinterpreting Network Handles:** When dealing with network handles, developers need to be aware of the Android API level and the availability of network handle support. Assuming network handles are always available or using them incorrectly on older Android versions can lead to bugs.

**User Operations and Debugging Clues:**

A user might trigger this code through various everyday actions:

1. **Connecting to or disconnecting from Wi-Fi:** This is a primary trigger for network change notifications.
2. **Enabling or disabling mobile data:** Directly affects the network connection.
3. **Toggling airplane mode:** A drastic change that disconnects all networks.
4. **Connecting to or disconnecting from a VPN:** VPN connections create virtual network interfaces.
5. **Experiencing network interruptions:** Temporary loss of signal or connectivity issues.
6. **Roaming onto a different cellular network:**  Can trigger a change in connection type and cost.

**Debugging Steps to Reach This Code:**

If a developer suspects issues with network change detection on Android, they might follow these debugging steps:

1. **Enable NetLog:** In Chromium, navigating to `chrome://net-export/` allows capturing a detailed log of network events. This log will show when network change notifications are received and processed. Looking for entries related to `NetworkChangeNotifier` can be helpful.

2. **Android Studio Debugging:** If debugging the Android Chromium code directly:
   * Set breakpoints in `network_change_notifier_android.cc`, particularly in the `OnConnectionTypeChanged()`, `OnNetworkConnected()`, `OnNetworkDisconnected()`, and other `On...` methods.
   * Connect an Android device or emulator with the Chromium build to the debugger.
   * Perform network-related actions on the device (e.g., connect/disconnect from Wi-Fi).
   * Observe if the breakpoints are hit and inspect the values of variables like the connection type and network handle.

3. **Logging:** Add `DLOG` or `VLOG` statements within `network_change_notifier_android.cc` to print information about received notifications and the current network state. These logs can be viewed using `adb logcat` on the connected Android device.

4. **Inspecting Java-side Notifications:** Since this C++ code relies on the Java `NetworkChangeNotifier`, it might be necessary to also debug the Java side. Set breakpoints in `org.chromium.net.NetworkChangeNotifier.java` (or the relevant Java file) to see when and how the Java code detects network changes and sends notifications to the native side.

5. **Using Android's `ConnectivityManager` Tools:** Android provides tools like `dumpsys connectivity` that can be used to inspect the current network state and active network interfaces on the device. This can help verify if the Android system itself is reporting the network status correctly.

By understanding the flow of network change notifications from the Android system to this C++ code and then to the rest of Chromium, developers can effectively diagnose and fix issues related to network connectivity in the browser on Android.

Prompt: 
```
这是目录为net/android/network_change_notifier_android.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

////////////////////////////////////////////////////////////////////////////////
// Threading considerations:
//
// This class is designed to meet various threading guarantees starting from the
// ones imposed by NetworkChangeNotifier:
// - The notifier can be constructed on any thread.
// - GetCurrentConnectionType() can be called on any thread.
//
// The fact that this implementation of NetworkChangeNotifier is backed by a
// Java side singleton class (see NetworkChangeNotifier.java) adds another
// threading constraint:
// - The calls to the Java side (stateful) object must be performed from a
//   single thread. This object happens to be a singleton which is used on the
//   application side on the main thread. Therefore all the method calls from
//   the native NetworkChangeNotifierAndroid class to its Java counterpart are
//   performed on the main thread.
//
// This leads to a design involving the following native classes:
// 1) NetworkChangeNotifierFactoryAndroid ('factory')
// 2) NetworkChangeNotifierDelegateAndroid ('delegate')
// 3) NetworkChangeNotifierAndroid ('notifier')
//
// The factory constructs and owns the delegate. The factory is constructed and
// destroyed on the main thread which makes it construct and destroy the
// delegate on the main thread too. This guarantees that the calls to the Java
// side are performed on the main thread.
// Note that after the factory's construction, the factory's creation method can
// be called from any thread since the delegate's construction (performing the
// JNI calls) already happened on the main thread (when the factory was
// constructed).
//
////////////////////////////////////////////////////////////////////////////////
// Propagation of network change notifications:
//
// When the factory is requested to create a new instance of the notifier, the
// factory passes the delegate to the notifier (without transferring ownership).
// Note that there is a one-to-one mapping between the factory and the
// delegate as explained above. But the factory naturally creates multiple
// instances of the notifier. That means that there is a one-to-many mapping
// between delegate and notifier (i.e. a single delegate can be shared by
// multiple notifiers).
// At construction the notifier (which is also an observer) subscribes to
// notifications fired by the delegate. These notifications, received by the
// delegate (and forwarded to the notifier(s)), are sent by the Java side
// notifier (see NetworkChangeNotifier.java) and are initiated by the Android
// platform.
// Notifications from the Java side always arrive on the main thread. The
// delegate then forwards these notifications to the threads of each observer
// (network change notifier). The network change notifier then processes the
// state change, and notifies each of its observers on their threads.
//
// This can also be seen as:
// Android platform -> NetworkChangeNotifier (Java) ->
// NetworkChangeNotifierDelegateAndroid -> NetworkChangeNotifierAndroid.

#include "net/android/network_change_notifier_android.h"

#include <string>
#include <unordered_set>

#include "base/android/build_info.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/metrics/histogram_macros.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/task_traits.h"
#include "base/task/thread_pool.h"
#include "base/threading/thread.h"
#include "net/base/address_tracker_linux.h"

namespace net {

// Expose handles::kInvalidNetworkHandle out to Java as NetId.INVALID. The
// notion of a NetID is an Android framework one, see android.net.Network.netId.
// NetworkChangeNotifierAndroid implements handles::NetworkHandle to simply be
// the NetID.
// GENERATED_JAVA_ENUM_PACKAGE: org.chromium.net
enum NetId {
  // Cannot use |handles::kInvalidNetworkHandle| here as the Java generator
  // fails, instead enforce their equality with CHECK in
  // NetworkChangeNotifierAndroid().
  INVALID = -1
};

// Thread on which we can run DnsConfigService, which requires a TYPE_IO
// message loop to monitor /system/etc/hosts.
class NetworkChangeNotifierAndroid::BlockingThreadObjects {
 public:
  BlockingThreadObjects()
      : address_tracker_(
            base::DoNothing(),
            base::DoNothing(),
            // We're only interested in tunnel interface changes.
            base::BindRepeating(NotifyNetworkChangeNotifierObservers),
            std::unordered_set<std::string>()) {}
  BlockingThreadObjects(const BlockingThreadObjects&) = delete;
  BlockingThreadObjects& operator=(const BlockingThreadObjects&) = delete;

  void Init() {
    address_tracker_.Init();
  }

  static void NotifyNetworkChangeNotifierObservers() {
    NetworkChangeNotifier::NotifyObserversOfIPAddressChange();
    NetworkChangeNotifier::NotifyObserversOfConnectionTypeChange();
  }

 private:
  // Used to detect tunnel state changes.
  internal::AddressTrackerLinux address_tracker_;
};

NetworkChangeNotifierAndroid::~NetworkChangeNotifierAndroid() {
  ClearGlobalPointer();
  delegate_->UnregisterObserver(this);
}

NetworkChangeNotifier::ConnectionType
NetworkChangeNotifierAndroid::GetCurrentConnectionType() const {
  return delegate_->GetCurrentConnectionType();
}

NetworkChangeNotifier::ConnectionCost
NetworkChangeNotifierAndroid::GetCurrentConnectionCost() {
  return delegate_->GetCurrentConnectionCost();
}

NetworkChangeNotifier::ConnectionSubtype
NetworkChangeNotifierAndroid::GetCurrentConnectionSubtype() const {
  return delegate_->GetCurrentConnectionSubtype();
}

void NetworkChangeNotifierAndroid::GetCurrentMaxBandwidthAndConnectionType(
    double* max_bandwidth_mbps,
    ConnectionType* connection_type) const {
  delegate_->GetCurrentMaxBandwidthAndConnectionType(max_bandwidth_mbps,
                                                     connection_type);
}

void NetworkChangeNotifierAndroid::ForceNetworkHandlesSupportedForTesting() {
  force_network_handles_supported_for_testing_ = true;
}

bool NetworkChangeNotifierAndroid::AreNetworkHandlesCurrentlySupported() const {
  // Notifications for API using handles::NetworkHandles and querying using
  // handles::NetworkHandles only implemented for Android versions >= L.
  return force_network_handles_supported_for_testing_ ||
         (base::android::BuildInfo::GetInstance()->sdk_int() >=
              base::android::SDK_VERSION_LOLLIPOP &&
          !delegate_->RegisterNetworkCallbackFailed());
}

void NetworkChangeNotifierAndroid::GetCurrentConnectedNetworks(
    NetworkChangeNotifier::NetworkList* networks) const {
  delegate_->GetCurrentlyConnectedNetworks(networks);
}

NetworkChangeNotifier::ConnectionType
NetworkChangeNotifierAndroid::GetCurrentNetworkConnectionType(
    handles::NetworkHandle network) const {
  return delegate_->GetNetworkConnectionType(network);
}

handles::NetworkHandle NetworkChangeNotifierAndroid::GetCurrentDefaultNetwork()
    const {
  return delegate_->GetCurrentDefaultNetwork();
}

void NetworkChangeNotifierAndroid::OnConnectionTypeChanged() {
  BlockingThreadObjects::NotifyNetworkChangeNotifierObservers();
}

void NetworkChangeNotifierAndroid::OnConnectionCostChanged() {
  NetworkChangeNotifier::NotifyObserversOfConnectionCostChange();
}

void NetworkChangeNotifierAndroid::OnMaxBandwidthChanged(
    double max_bandwidth_mbps,
    ConnectionType type) {
  NetworkChangeNotifier::NotifyObserversOfMaxBandwidthChange(max_bandwidth_mbps,
                                                             type);
}

void NetworkChangeNotifierAndroid::OnNetworkConnected(
    handles::NetworkHandle network) {
  NetworkChangeNotifier::NotifyObserversOfSpecificNetworkChange(
      NetworkChangeType::kConnected, network);
}

void NetworkChangeNotifierAndroid::OnNetworkSoonToDisconnect(
    handles::NetworkHandle network) {
  NetworkChangeNotifier::NotifyObserversOfSpecificNetworkChange(
      NetworkChangeType::kSoonToDisconnect, network);
}

void NetworkChangeNotifierAndroid::OnNetworkDisconnected(
    handles::NetworkHandle network) {
  NetworkChangeNotifier::NotifyObserversOfSpecificNetworkChange(
      NetworkChangeType::kDisconnected, network);
}

void NetworkChangeNotifierAndroid::OnNetworkMadeDefault(
    handles::NetworkHandle network) {
  NetworkChangeNotifier::NotifyObserversOfSpecificNetworkChange(
      NetworkChangeType::kMadeDefault, network);
}

void NetworkChangeNotifierAndroid::OnDefaultNetworkActive() {
  NetworkChangeNotifier::NotifyObserversOfDefaultNetworkActive();
}

NetworkChangeNotifierAndroid::NetworkChangeNotifierAndroid(
    NetworkChangeNotifierDelegateAndroid* delegate)
    : NetworkChangeNotifier(NetworkChangeCalculatorParamsAndroid()),
      delegate_(delegate),
      blocking_thread_objects_(nullptr, base::OnTaskRunnerDeleter(nullptr)) {
  static_assert(NetId::INVALID == handles::kInvalidNetworkHandle,
                "handles::kInvalidNetworkHandle doesn't match NetId::INVALID");
  delegate_->RegisterObserver(this);
  // Since Android P, ConnectivityManager's signals include VPNs so we don't
  // need to use AddressTrackerLinux.
  if (base::android::BuildInfo::GetInstance()->sdk_int() <
      base::android::SDK_VERSION_P) {
    // |blocking_thread_objects_| will live on this runner.
    scoped_refptr<base::SequencedTaskRunner> blocking_thread_runner =
        base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()});
    blocking_thread_objects_ =
        std::unique_ptr<BlockingThreadObjects, base::OnTaskRunnerDeleter>(
            new BlockingThreadObjects(),
            // Ensure |blocking_thread_objects_| lives on
            // |blocking_thread_runner| to prevent races where
            // NetworkChangeNotifierAndroid outlives
            // TaskEnvironment. https://crbug.com/938126
            base::OnTaskRunnerDeleter(blocking_thread_runner));
    blocking_thread_runner->PostTask(
        FROM_HERE,
        base::BindOnce(&BlockingThreadObjects::Init,
                       // The Unretained pointer is safe here because it's
                       // posted before the deleter can post.
                       base::Unretained(blocking_thread_objects_.get())));
  }
}

// static
NetworkChangeNotifier::NetworkChangeCalculatorParams
NetworkChangeNotifierAndroid::NetworkChangeCalculatorParamsAndroid() {
  NetworkChangeCalculatorParams params;
  // IPAddressChanged is produced immediately prior to ConnectionTypeChanged
  // so delay IPAddressChanged so they get merged with the following
  // ConnectionTypeChanged signal.
  params.ip_address_offline_delay_ = base::Seconds(1);
  params.ip_address_online_delay_ = base::Seconds(1);
  params.connection_type_offline_delay_ = base::Seconds(0);
  params.connection_type_online_delay_ = base::Seconds(0);
  return params;
}

bool NetworkChangeNotifierAndroid::IsDefaultNetworkActiveInternal() {
  return delegate_->IsDefaultNetworkActive();
}

void NetworkChangeNotifierAndroid::DefaultNetworkActiveObserverAdded() {
  delegate_->DefaultNetworkActiveObserverAdded();
}

void NetworkChangeNotifierAndroid::DefaultNetworkActiveObserverRemoved() {
  delegate_->DefaultNetworkActiveObserverRemoved();
}

}  // namespace net

"""

```
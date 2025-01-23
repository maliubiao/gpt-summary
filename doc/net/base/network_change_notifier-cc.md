Response:
The user wants a summary of the functionalities of the `NetworkChangeNotifier` class in Chromium's networking stack, specifically focusing on how it relates to JavaScript, any logical inferences, common user errors, debugging steps, and a general conclusion.

Here's a breakdown of the thinking process:

1. **Identify the Core Functionality:** The primary purpose of `NetworkChangeNotifier` is to detect and notify about changes in network connectivity. This involves observing various underlying system events and then broadcasting these changes to interested parties within the Chromium process.

2. **Break Down Functionalities by Category:**  To provide a structured answer, it's useful to categorize the functionalities. Possible categories include:
    * **Observation:** How it detects network changes (IP address, connection type, DNS, etc.)
    * **Notification:** How it informs other parts of the system about these changes (observers).
    * **Information Retrieval:** How other parts of the system can query the current network status.
    * **Platform Abstraction:** How it provides a consistent interface across different operating systems.
    * **Testing and Mocking:** Facilities for testing network change scenarios.

3. **Analyze Interactions with JavaScript:** Consider how network changes impact web pages and JavaScript running within them. Key areas include:
    * **`navigator.onLine`:** This JavaScript API directly reflects network connectivity.
    * **Fetch API and XMLHttpRequest:** These APIs will fail or behave differently depending on the network status.
    * **WebSockets:**  Network changes can cause WebSocket connections to close or attempt reconnection.
    * **Offline Web Applications:**  Service Workers and the Cache API rely on understanding network availability.

4. **Identify Logical Inferences:**  Look for places where the code makes assumptions or deductions about network state. The `NetworkChangeCalculator` is a prime example – it delays notifications based on configured parameters. Consider the inputs (IP address change, connection type change) and the output (delayed notification of the overall network change).

5. **Consider User/Programming Errors:** Think about common mistakes developers might make when using this class or relying on its notifications. This includes:
    * **Forgetting to add/remove observers:** Leading to missed or stale notifications.
    * **Making assumptions about the timing of notifications:**  Notifications might be delayed or coalesced.
    * **Not handling offline states gracefully:**  Applications should anticipate and handle periods without network connectivity.

6. **Outline Debugging Steps:** How would a developer investigate issues related to network change notifications?
    * **Setting breakpoints:** To inspect the state of the `NetworkChangeNotifier`.
    * **Observing notifications:**  Logging when notifications are sent and received.
    * **Simulating network changes:** Using platform-specific tools or the mocking capabilities of `NetworkChangeNotifier`.

7. **Synthesize a Summary:** Condense the key functionalities into a concise overview.

8. **Structure the Response:**  Organize the information logically, using headings and bullet points for clarity. Address each part of the user's request explicitly.

**Self-Correction/Refinement during the thought process:**

* **Initial Thought:**  Focus solely on the code structure.
* **Correction:** Need to broaden the scope to include the *purpose* and *use cases* of the class, especially its interaction with higher-level components like JavaScript.

* **Initial Thought:** Directly map code blocks to functionalities.
* **Correction:**  Group related code sections under broader functional headings to make the explanation easier to understand.

* **Initial Thought:** Provide very technical, code-centric examples.
* **Correction:** Provide more user-centric examples of how network changes manifest in the browser and how JavaScript interacts with them. Think about the end-user experience.

* **Initial Thought:**  Focus only on successful scenarios.
* **Correction:**  Explicitly address potential errors and debugging strategies.

By following this process, the goal is to provide a comprehensive yet understandable explanation of the `NetworkChangeNotifier` class and its role in the Chromium networking stack.
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/network_change_notifier.h"

#include <limits>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>

#include "base/memory/ref_counted.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/no_destructor.h"
#include "base/observer_list.h"
#include "base/sequence_checker.h"
#include "base/strings/string_util.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread_checker.h"
#include "base/timer/timer.h"
#include "build/build_config.h"
#include "build/chromeos_buildflags.h"
#include "net/base/network_change_notifier_factory.h"
#include "net/base/network_interfaces.h"
#include "net/base/url_util.h"
#include "net/dns/dns_config.h"
#include "net/dns/dns_config_service.h"
#include "net/dns/system_dns_config_change_notifier.h"
#include "net/url_request/url_request.h"
#include "url/gurl.h"

#if BUILDFLAG(IS_WIN)
#include "net/base/network_change_notifier_win.h"
#elif BUILDFLAG(IS_LINUX)
#include "net/base/network_change_notifier_linux.h"
#elif BUILDFLAG(IS_APPLE)
#include "net/base/network_change_notifier_apple.h"
#elif BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_ANDROID)
#include "net/base/network_change_notifier_passive.h"
#elif BUILDFLAG(IS_FUCHSIA)
#include "net/base/network_change_notifier_fuchsia.h"
#endif

namespace net {

namespace {

// The process-wide singleton notifier.
NetworkChangeNotifier* g_network_change_notifier = nullptr;

// Class factory singleton.
NetworkChangeNotifierFactory* g_network_change_notifier_factory = nullptr;

// Lock to protect |g_network_change_notifier| during creation time. Since
// creation of the process-wide instance can happen on any thread, this lock is
// used to guarantee only one instance is created. Once the global instance is
// created, the owner is responsible for destroying it on the same thread. All
// the other calls to the NetworkChangeNotifier do not require this lock as
// the global instance is only destroyed when the process is getting killed.
base::Lock& NetworkChangeNotifierCreationLock() {
  static base::NoDestructor<base::Lock> instance;
  return *instance;
}

class MockNetworkChangeNotifier : public NetworkChangeNotifier {
 public:
  explicit MockNetworkChangeNotifier(
      std::unique_ptr<SystemDnsConfigChangeNotifier> dns_config_notifier)
      : NetworkChangeNotifier(
            NetworkChangeCalculatorParams(),
            dns_config_notifier.get(),
            // Omit adding observers from the constructor as that would prevent
            // construction when SingleThreadTaskRunner::CurrentDefaultHandle
            // isn't set.
            /* omit_observers_in_constructor_for_testing=*/true),
        dns_config_notifier_(std::move(dns_config_notifier)) {}

  ~MockNetworkChangeNotifier() override { StopSystemDnsConfigNotifier(); }

  ConnectionType GetCurrentConnectionType() const override {
    return CONNECTION_UNKNOWN;
  }

 private:
  std::unique_ptr<SystemDnsConfigChangeNotifier> dns_config_notifier_;
};

}  // namespace

// static
bool NetworkChangeNotifier::test_notifications_only_ = false;

NetworkChangeNotifier::NetworkChangeCalculatorParams::
    NetworkChangeCalculatorParams() = default;

// Calculates NetworkChange signal from IPAddress, ConnectionCost, and
// ConnectionType signals.
class NetworkChangeNotifier::NetworkChangeCalculator
    : public ConnectionTypeObserver,
      public ConnectionCostObserver,
      public IPAddressObserver {
 public:
  explicit NetworkChangeCalculator(const NetworkChangeCalculatorParams& params)
      : params_(params) {
    DCHECK(g_network_change_notifier);
    AddConnectionTypeObserver(this);
    AddConnectionCostObserver(this);
    AddIPAddressObserver(this);
  }

  NetworkChangeCalculator(const NetworkChangeCalculator&) = delete;
  NetworkChangeCalculator& operator=(const NetworkChangeCalculator&) = delete;

  ~NetworkChangeCalculator() override {
    DCHECK(thread_checker_.CalledOnValidThread());
    RemoveConnectionTypeObserver(this);
    RemoveConnectionCostObserver(this);
    RemoveIPAddressObserver(this);
  }

  // NetworkChangeNotifier::IPAddressObserver implementation.
  void OnIPAddressChanged() override {
    DCHECK(thread_checker_.CalledOnValidThread());
    pending_connection_type_ = GetConnectionType();
    base::TimeDelta delay = last_announced_connection_type_ == CONNECTION_NONE
        ? params_.ip_address_offline_delay_ : params_.ip_address_online_delay_;
    // Cancels any previous timer.
    timer_.Start(FROM_HERE, delay, this, &NetworkChangeCalculator::Notify);
  }

  // NetworkChangeNotifier::ConnectionTypeObserver implementation.
  void OnConnectionTypeChanged(ConnectionType type) override {
    DCHECK(thread_checker_.CalledOnValidThread());
    pending_connection_type_ = type;
    base::TimeDelta delay = last_announced_connection_type_ == CONNECTION_NONE
        ? params_.connection_type_offline_delay_
        : params_.connection_type_online_delay_;
    // Cancels any previous timer.
    timer_.Start(FROM_HERE, delay, this, &NetworkChangeCalculator::Notify);
  }

  // NetworkChangeNotifier::ConnectionCostObserver implementation.
  void OnConnectionCostChanged(ConnectionCost cost) override {
    base::UmaHistogramEnumeration("Net.NetworkChangeNotifier.NewConnectionCost",
                                  cost, CONNECTION_COST_LAST);
  }

 private:
  void Notify() {
    DCHECK(thread_checker_.CalledOnValidThread());
    // Don't bother signaling about dead connections.
    if (have_announced_ &&
        (last_announced_connection_type_ == CONNECTION_NONE) &&
        (pending_connection_type_ == CONNECTION_NONE)) {
      return;
    }

    UMA_HISTOGRAM_ENUMERATION("Net.NetworkChangeNotifier.NewConnectionType",
                              pending_connection_type_, CONNECTION_LAST + 1);

    have_announced_ = true;
    last_announced_connection_type_ = pending_connection_type_;
    // Immediately before sending out an online signal, send out an offline
    // signal to perform any destructive actions before constructive actions.
    if (pending_connection_type_ != CONNECTION_NONE)
      NetworkChangeNotifier::NotifyObserversOfNetworkChange(CONNECTION_NONE);
    NetworkChangeNotifier::NotifyObserversOfNetworkChange(
        pending_connection_type_);
  }

  const NetworkChangeCalculatorParams params_;

  // Indicates if NotifyObserversOfNetworkChange has been called yet.
  bool have_announced_ = false;
  // Last value passed to NotifyObserversOfNetworkChange.
  ConnectionType last_announced_connection_type_ = CONNECTION_NONE;
  // Value to pass to NotifyObserversOfNetworkChange when Notify is called.
  ConnectionType pending_connection_type_ = CONNECTION_NONE;
  // Used to delay notifications so duplicates can be combined.
  base::OneShotTimer timer_;

  base::ThreadChecker thread_checker_;
};

// Holds the collection of observer lists used by NetworkChangeNotifier.
class NetworkChangeNotifier::ObserverList {
 public:
  ObserverList()
      : ip_address_observer_list_(
            base::MakeRefCounted<base::ObserverListThreadSafe<
                NetworkChangeNotifier::IPAddressObserver>>(
                base::ObserverListPolicy::EXISTING_ONLY)),
        connection_type_observer_list_(
            base::MakeRefCounted<base::ObserverListThreadSafe<
                NetworkChangeNotifier::ConnectionTypeObserver>>(
                base::ObserverListPolicy::EXISTING_ONLY)),
        resolver_state_observer_list_(
            base::MakeRefCounted<base::ObserverListThreadSafe<
                NetworkChangeNotifier::DNSObserver>>(
                base::ObserverListPolicy::EXISTING_ONLY)),
        network_change_observer_list_(
            base::MakeRefCounted<base::ObserverListThreadSafe<
                NetworkChangeNotifier::NetworkChangeObserver>>(
                base::ObserverListPolicy::EXISTING_ONLY)),
        max_bandwidth_observer_list_(
            base::MakeRefCounted<base::ObserverListThreadSafe<
                NetworkChangeNotifier::MaxBandwidthObserver>>(
                base::ObserverListPolicy::EXISTING_ONLY)),
        network_observer_list_(
            base::MakeRefCounted<base::ObserverListThreadSafe<
                NetworkChangeNotifier::NetworkObserver>>(
                base::ObserverListPolicy::EXISTING_ONLY)),
        connection_cost_observer_list_(
            base::MakeRefCounted<base::ObserverListThreadSafe<
                NetworkChangeNotifier::ConnectionCostObserver>>(
                base::ObserverListPolicy::EXISTING_ONLY)),
        default_network_active_observer_list_(
            base::MakeRefCounted<
                base::ObserverListThreadSafe<DefaultNetworkActiveObserver>>(
                base::ObserverListPolicy::EXISTING_ONLY)) {}

  ObserverList(const ObserverList&) = delete;
  ObserverList& operator=(const ObserverList&) = delete;
  ~ObserverList() = default;

  const scoped_refptr<
      base::ObserverListThreadSafe<NetworkChangeNotifier::IPAddressObserver>>
      ip_address_observer_list_;
  const scoped_refptr<base::ObserverListThreadSafe<
      NetworkChangeNotifier::ConnectionTypeObserver>>
      connection_type_observer_list_;
  const scoped_refptr<
      base::ObserverListThreadSafe<NetworkChangeNotifier::DNSObserver>>
      resolver_state_observer_list_;
  const scoped_refptr<base::ObserverListThreadSafe<
      NetworkChangeNotifier::NetworkChangeObserver>>
      network_change_observer_list_;
  const scoped_refptr<
      base::ObserverListThreadSafe<NetworkChangeNotifier::MaxBandwidthObserver>>
      max_bandwidth_observer_list_;
  const scoped_refptr<
      base::ObserverListThreadSafe<NetworkChangeNotifier::NetworkObserver>>
      network_observer_list_;
  const scoped_refptr<base::ObserverListThreadSafe<
      NetworkChangeNotifier::ConnectionCostObserver>>
      connection_cost_observer_list_;
  const scoped_refptr<
      base::ObserverListThreadSafe<DefaultNetworkActiveObserver>>
      default_network_active_observer_list_;
};

class NetworkChangeNotifier::SystemDnsConfigObserver
    : public SystemDnsConfigChangeNotifier::Observer {
 public:
  virtual ~SystemDnsConfigObserver() = default;

  void OnSystemDnsConfigChanged(std::optional<DnsConfig> config) override {
    NotifyObserversOfDNSChange();
  }
};

void NetworkChangeNotifier::ClearGlobalPointer() {
  if (!cleared_global_pointer_) {
    cleared_global_pointer_ = true;
    DCHECK_EQ(this, g_network_change_notifier);
    g_network_change_notifier = nullptr;
  }
}

NetworkChangeNotifier::~NetworkChangeNotifier() {
  network_change_calculator_.reset();
  ClearGlobalPointer();
  StopSystemDnsConfigNotifier();
}

// static
NetworkChangeNotifierFactory* NetworkChangeNotifier::GetFactory() {
  return g_network_change_notifier_factory;
}

// static
void NetworkChangeNotifier::SetFactory(
    NetworkChangeNotifierFactory* factory) {
  CHECK(!g_network_change_notifier_factory);
  g_network_change_notifier_factory = factory;
}

// static
std::unique_ptr<NetworkChangeNotifier> NetworkChangeNotifier::CreateIfNeeded(
    NetworkChangeNotifier::ConnectionType initial_type,
    NetworkChangeNotifier::ConnectionSubtype initial_subtype) {
  {
    base::AutoLock auto_lock(NetworkChangeNotifierCreationLock());
    if (g_network_change_notifier)
      return nullptr;
  }

  if (g_network_change_notifier_factory) {
    return g_network_change_notifier_factory->CreateInstanceWithInitialTypes(
        initial_type, initial_subtype);
  }

#if BUILDFLAG(IS_WIN)
  std::unique_ptr<NetworkChangeNotifierWin> network_change_notifier =
      std::make_unique<NetworkChangeNotifierWin>();
  network_change_notifier->WatchForAddressChange();
  return network_change_notifier;
#elif BUILDFLAG(IS_ANDROID)
  // Fallback to use NetworkChangeNotifierPassive if
  // NetworkChangeNotifierFactory is not set. Currently used for tests and when
  // running network service in a separate process.
  return std::make_unique<NetworkChangeNotifierPassive>(initial_type,
                                                        initial_subtype);
#elif BUILDFLAG(IS_CHROMEOS)
  return std::make_unique<NetworkChangeNotifierPassive>(initial_type,
                                                        initial_subtype);
#elif BUILDFLAG(IS_LINUX)
  return std::make_unique<NetworkChangeNotifierLinux>(
      std::unordered_set<std::string>());
#elif BUILDFLAG(IS_APPLE)
  return std::make_unique<NetworkChangeNotifierApple>();
#elif BUILDFLAG(IS_FUCHSIA)
  return std::make_unique<NetworkChangeNotifierFuchsia>(
      /*require_wlan=*/false);
#else
  NOTIMPLEMENTED();
  return nullptr;
#endif
}

// static
NetworkChangeNotifier::ConnectionCost
NetworkChangeNotifier::GetConnectionCost() {
  return g_network_change_notifier
             ? g_network_change_notifier->GetCurrentConnectionCost()
             : CONNECTION_COST_UNKNOWN;
}

// static
NetworkChangeNotifier::ConnectionType
NetworkChangeNotifier::GetConnectionType() {
  return g_network_change_notifier ?
      g_network_change_notifier->GetCurrentConnectionType() :
      CONNECTION_UNKNOWN;
}

// static
NetworkChangeNotifier::ConnectionSubtype
NetworkChangeNotifier::GetConnectionSubtype() {
  return g_network_change_notifier
             ? g_network_change_notifier->GetCurrentConnectionSubtype()
             : SUBTYPE_UNKNOWN;
}

// static
void NetworkChangeNotifier::GetMaxBandwidthAndConnectionType(
    double* max_bandwidth_mbps,
    ConnectionType* connection_type) {
  if (!g_network_change_notifier) {
    *connection_type = CONNECTION_UNKNOWN;
    *max_bandwidth_mbps =
        GetMaxBandwidthMbpsForConnectionSubtype(SUBTYPE_UNKNOWN);
    return;
  }

  g_network_change_notifier->GetCurrentMaxBandwidthAndConnectionType(
      max_bandwidth_mbps, connection_type);
}

// static
double NetworkChangeNotifier::GetMaxBandwidthMbpsForConnectionSubtype(
    ConnectionSubtype subtype) {
  switch (subtype) {
    case SUBTYPE_GSM:
      return 0.01;
    case SUBTYPE_IDEN:
      return 0.064;
    case SUBTYPE_CDMA:
      return 0.115;
    case SUBTYPE_1XRTT:
      return 0.153;
    case SUBTYPE_GPRS:
      return 0.237;
    case SUBTYPE_EDGE:
      return 0.384;
    case SUBTYPE_UMTS:
      return 2.0;
    case SUBTYPE_EVDO_REV_0:
      return 2.46;
    case SUBTYPE_EVDO_REV_A:
      return 3.1;
    case SUBTYPE_HSPA:
      return 3.6;
    case SUBTYPE_EVDO_REV_B:
      return 14.7;
    case SUBTYPE_HSDPA:
      return 14.3;
    case SUBTYPE_HSUPA:
      return 14.4;
    case SUBTYPE_EHRPD:
      return 21.0;
    case SUBTYPE_HSPAP:
      return 42.0;
    case SUBTYPE_LTE:
      return 100.0;
    case SUBTYPE_LTE_ADVANCED:
      return 100.0;
    case SUBTYPE_BLUETOOTH_1_2:
      return 1.0;
    case SUBTYPE_BLUETOOTH_2_1:
      return 3.0;
    case SUBTYPE_BLUETOOTH_3_0:
      return 24.0;
    case SUBTYPE_BLUETOOTH_4_0:
      return 1.0;
    case SUBTYPE_ETHERNET:
      return 10.0;
    case SUBTYPE_FAST_ETHERNET:
      return 100.0;
    case SUBTYPE_GIGABIT_ETHERNET:
      return 1000.0;
    case SUBTYPE_10_GIGABIT_ETHERNET:
      return 10000.0;
    case SUBTYPE_WIFI_B:
      return 11.0;
    case SUBTYPE_WIFI_G:
      return 54.0;
    case SUBTYPE_WIFI_N:
      return 600.0;
    case SUBTYPE_WIFI_AC:
      return 1300.0;
    case SUBTYPE_WIFI_AD:
      return 7000.0;
    case SUBTYPE_UNKNOWN:
      return std::numeric_limits<double>::infinity();
    case SUBTYPE_NONE:
      return 0.0;
    case SUBTYPE_OTHER:
      return std::numeric_limits<double>::infinity();
  }
  NOTREACHED();
}

// static
bool NetworkChangeNotifier::AreNetworkHandlesSupported() {
  if (g_network_change_notifier) {
    return g_network_change_notifier->AreNetworkHandlesCurrentlySupported();
  }
  return false;
}

// static
void NetworkChangeNotifier::GetConnectedNetworks(NetworkList* network_list) {
  DCHECK(AreNetworkHandlesSupported());
  if (g_network_change_notifier) {
    g_network_change_notifier->GetCurrentConnectedNetworks(network_list);
  } else {
    network_list->clear();
  }
}

// static
NetworkChangeNotifier::ConnectionType
NetworkChangeNotifier::GetNetworkConnectionType(
    handles::NetworkHandle network) {
  DCHECK(AreNetworkHandlesSupported());
  return g_network_change_notifier
             ? g_network_change_notifier->GetCurrentNetworkConnectionType(
                   network)
             : CONNECTION_UNKNOWN;
}

// static
handles::NetworkHandle NetworkChangeNotifier::GetDefaultNetwork() {
  DCHECK(AreNetworkHandlesSupported());
  return g_network_change_notifier
             ? g_network_change_notifier->GetCurrentDefaultNetwork()
             : handles::kInvalidNetworkHandle;
}

// static
SystemDnsConfigChangeNotifier*
NetworkChangeNotifier::GetSystemDnsConfigNotifier() {
  if (g_network_change_notifier)
    return g_network_change_notifier->GetCurrentSystemDnsConfigNotifier();
  return nullptr;
}

// static
bool NetworkChangeNotifier::IsDefaultNetworkActive() {
  if (g_network_change_notifier)
    return g_network_change_notifier->IsDefaultNetworkActiveInternal();
  // Assume true as a "default" to avoid batching indefinitely.
  return true;
}

// static
base::cstring_view NetworkChangeNotifier::ConnectionTypeToString(
    ConnectionType type) {
  static constexpr auto kConnectionTypeNames =
      std::to_array<base::cstring_view>({
          "CONNECTION_UNKNOWN",
          "CONNECTION_ETHERNET",
          "CONNECTION_WIFI",
          "CONNECTION_2G",
          "CONNECTION_3G",
          "CONNECTION_4G",
          "CONNECTION_NONE",
          "CONNECTION_BLUETOOTH",
          "CONNECTION_5G",
      });
  static_assert(std::size(kConnectionTypeNames) ==
                    NetworkChangeNotifier::CONNECTION_LAST + 1,
                "ConnectionType name count should match");
  if (type < CONNECTION_UNKNOWN || type > CONNECTION_LAST) {
    NOTREACHED();
  }
  return kConnectionTypeNames[type];
}

#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
// static
AddressMapOwnerLinux* NetworkChangeNotifier::GetAddressMapOwner() {
  return g_network_change_notifier
             ? g_network_change_notifier->GetAddressMapOwnerInternal()
             : nullptr;
}
#endif  // BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)

#if BUILDFLAG(IS_FUCHSIA)
// static
const internal::NetworkInterfaceCache*
NetworkChangeNotifier::GetNetworkInterfaceCache() {
  return g_network_change_notifier
             ? g_network_change_notifier->GetNetworkInterfaceCacheInternal()
             : nullptr;
}
#endif  // BUILDFLAG(IS_FUCHSIA)

// static
bool NetworkChangeNotifier::IsOffline() {
  return GetConnectionType() == CONNECTION_NONE;
}

// static
bool NetworkChangeNotifier::IsConnectionCellular(ConnectionType type) {
  bool is_cellular = false;
  switch (type) {
    case CONNECTION_2G:
    case CONNECTION_3G:
    case CONNECTION_4G:
    case CONNECTION_5G:
      is_cellular =  true;
      break;
    case CONNECTION_UNKNOWN:
    case CONNECTION_ETHERNET:
    case CONNECTION_WIFI:
    case CONNECTION_NONE:
    case CONNECTION_BLUETOOTH:
      is_cellular = false;
      break;
  }
  return is_cellular;
}

// static
NetworkChangeNotifier::ConnectionType
NetworkChangeNotifier::ConnectionTypeFromInterfaces() {
  NetworkInterfaceList interfaces;
  if (!GetNetworkList(&interfaces, EXCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES))
    return CONNECTION_UNKNOWN;
  return ConnectionTypeFromInterfaceList(interfaces);
}

// static
NetworkChangeNotifier::ConnectionType
NetworkChangeNotifier::ConnectionTypeFromInterfaceList(
    const NetworkInterfaceList& interfaces) {
  bool first = true;
  ConnectionType result = CONNECTION_NONE;
  for (const auto& network_interface : interfaces) {
#if BUILDFLAG(IS_WIN)
    if (network_interface.friendly_name == "Teredo Tunneling Pseudo-Interface")
      continue;
#endif
#if BUILDFLAG(IS_APPLE)
    // Ignore link-local addresses as they aren't globally routable.
    // Mac assigns these to disconnected interfaces like tunnel interfaces
    // ("utun"), airdrop interfaces ("awdl"), and ethernet ports ("en").
    if (network_interface.address.IsLinkLocal())
      continue;
#endif

    // Remove VMware network interfaces as they're internal and should not be
    // used to determine the network connection type.
    if (base::ToLowerASCII(network_interface.friendly_name).find("vmnet") !=
        std::string::npos) {
      continue;
    }
    if (first) {
      first = false;
      result = network_interface.type;
    } else if (result != network_interface.type) {
      return CONNECTION_UNKNOWN;
    }
  }
  return result;
}

// static
std::unique_ptr<NetworkChangeNotifier>
NetworkChangeNotifier::CreateMockIfNeeded() {
  {
    base::AutoLock auto_lock(NetworkChangeNotifierCreationLock());
    if (g_network_change_notifier)
      return nullptr;
  }
  // Use an empty noop SystemDnsConfigChangeNotifier to disable actual system
  // DNS configuration notifications.
  return std::make_unique<MockNetworkChangeNotifier>(
      std::make_unique<SystemDnsConfigChangeNotifier>(
          nullptr /* task_runner */, nullptr /* dns_config_service */));
}

NetworkChangeNotifier::IPAddressObserver::IPAddressObserver() = default;
NetworkChangeNotifier::IPAddressObserver::~IPAddressObserver() = default;

NetworkChangeNotifier::ConnectionTypeObserver::ConnectionTypeObserver() =
    default;
NetworkChangeNotifier::ConnectionTypeObserver::~ConnectionTypeObserver() =
    default;

NetworkChangeNotifier::DNSObserver::DNSObserver() = default;
NetworkChangeNotifier::DNSObserver::~DNSObserver() = default;

NetworkChangeNotifier::NetworkChangeObserver::NetworkChangeObserver() = default;
NetworkChangeNotifier::NetworkChangeObserver::~NetworkChangeObserver() =
    default;

NetworkChangeNotifier::MaxBandwidthObserver::MaxBandwidthObserver() = default;
NetworkChangeNotifier::MaxBandwidthObserver::~MaxBandwidthObserver() = default;

NetworkChangeNotifier::NetworkObserver::NetworkObserver() = default;
NetworkChangeNotifier::NetworkObserver::~NetworkObserver() = default;

NetworkChangeNotifier::ConnectionCostObserver::ConnectionCostObserver() =
    default;
NetworkChangeNotifier::ConnectionCostObserver::~ConnectionCostObserver() =
    default;

NetworkChangeNotifier::DefaultNetworkActiveObserver::
    DefaultNetworkActiveObserver() = default;
NetworkChangeNotifier::DefaultNetworkActiveObserver::
    ~DefaultNetworkActiveObserver() = default;

void NetworkChangeNotifier::AddIPAddressObserver(IPAddressObserver* observer) {
  DCHECK(!observer->observer_list_);
  observer->observer_list_ = GetObserverList().ip_address_observer_list_;
  observer->observer_list_->AddObserver(observer);
}

void NetworkChangeNotifier::AddConnectionTypeObserver(
    ConnectionTypeObserver* observer) {
  DCHECK(!observer->observer_list_);
  observer->observer_list_ = GetObserverList().connection_type_observer_list_;
  observer->observer_list_->AddObserver(observer);
}

void NetworkChangeNotifier::AddDNSObserver(DNSObserver* observer) {
  DCHECK(!observer->observer_list_);
  observer->observer_list_ = GetObserverList().resolver_state_observer_list_;
  observer->observer_list_->AddObserver(observer);
}

void NetworkChangeNotifier::AddNetworkChangeObserver(
    NetworkChangeObserver* observer) {
  DCHECK(!observer->observer_list_);
  observer->observer_list_ = GetObserverList().network_change_observer_list_;
  observer->observer_list_->AddObserver(observer);
}

void NetworkChangeNotifier::AddMaxBandwidthObserver(
    MaxBandwidthObserver* observer) {
  DCHECK(!observer->observer_list_);
  observer->observer_list_ = GetObserverList().max_bandwidth_observer_list_;
  observer->observer_list_->AddObserver(observer);
}

void NetworkChangeNotifier::AddNetworkObserver(NetworkObserver* observer) {
  base::AutoLock auto_lock(NetworkChangeNotifierCreationLock());
  DCHECK(AreNetworkHandlesSupported());
  DCHECK(!observer->observer_list_);
  observer->observer_list_ = GetObserverList().network_observer_list_;
  observer->observer_list_->AddObserver(observer);
}

void NetworkChangeNotifier::AddConnectionCostObserver(
    ConnectionCostObserver* observer) {
  DCHECK(!observer->observer_list_);
  observer->observer_list_ = GetObserverList().connection_cost_observer_list_;
  observer->observer_list_->AddObserver(observer);
}

void NetworkChangeNotifier::AddDefaultNetworkActiveObserver(
    DefaultNetworkActiveObserver* observer) {
  DCHECK(!observer->observer_list_);
  observer->observer_list_ =
      GetObserverList().default_network_active_observer_list_;
  observer->observer_list_->AddObserver(observer);
  base::AutoLock auto_lock(NetworkChangeNotifierCreationLock());
  // Currently we lose DefaultNetworkActiveObserverAdded notifications for
  // observers added prior to NCN creation. This should be a non-issue as
  // currently only Cronet listens to this and its observers are always added
  // after NCN creation.
  if (g_network_change_notifier) {
    g_network_change_notifier->DefaultNetworkActiveObserverAdded();
  }
}

void NetworkChangeNotifier::RemoveIPAddressObserver(
    IPAddressObserver* observer) {
  if (observer->observer_list_) {
    observer->observer_list_->RemoveObserver(observer);
    observer->observer_list_.reset();
  }
}

void NetworkChangeNotifier::RemoveConnectionTypeObserver(
    ConnectionTypeObserver* observer) {
  if (observer->observer_list_) {
    observer->observer_list_->RemoveObserver(observer);
    observer->observer_list_.reset();
  }
}

void NetworkChangeNotifier::RemoveDNSObserver(DNSObserver* observer) {
  if (observer->observer_list_) {
    observer->observer_list_->RemoveObserver(observer);
    observer->observer_list_.reset();
  }
}

void NetworkChangeNotifier::RemoveNetworkChangeObserver(
    NetworkChangeObserver* observer) {
  if (observer->observer_list_) {
    observer->observer_list_->RemoveObserver(observer);
    observer->observer_list_.reset();
  }
}

void NetworkChangeNotifier::RemoveMaxBandwidthObserver(
    MaxBandwidthObserver* observer) {
  if (observer->observer_list_) {
    observer->observer_list_->RemoveObserver(observer);
    observer->observer_list_.reset();
  }
}

void NetworkChangeNotifier::RemoveNetworkObserver(NetworkObserver* observer) {
  if (observer->observer_list_) {
    observer->observer_list_->RemoveObserver(observer);
    observer->observer_list_.reset();
  }
}

void NetworkChangeNotifier::RemoveConnectionCostObserver(
    ConnectionCostObserver* observer) {
  if (observer->observer_list_) {
    observer->observer_list_->RemoveObserver(observer);
    observer->observer_list_.reset();
  }
}

void NetworkChangeNotifier::RemoveDefaultNetworkActiveObserver(
    DefaultNetworkActiveObserver* observer) {
  if (observer->observer_list_) {
    observer->observer_list_->RemoveObserver(observer);
    observer->observer_list_.reset();
    g_network_change_notifier->DefaultNetworkActiveObserverRemoved();
  }
}

void NetworkChangeNotifier::TriggerNonSystemDnsChange() {
  NetworkChangeNotifier::NotifyObserversOfDNSChange();
}

// static
void NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests() {
  if (g_network_change_notifier)
    g_network_change_notifier->NotifyObserversOfIPAddressChangeImpl();
}

// static
void NetworkChangeNotifier::NotifyObserversOfConnectionTypeChangeForTests(
    ConnectionType type) {
  if (g_network_change_notifier)
    g_network_change_notifier->NotifyObserversOfConnectionTypeChangeImpl(type);
}

// static
void NetworkChangeNotifier::NotifyObserversOfDNSChangeForTests() {
  if (g_network_change_notifier)
    g_network_change_notifier->NotifyObserversOfDNSChangeImpl
### 提示词
```
这是目录为net/base/network_change_notifier.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/network_change_notifier.h"

#include <limits>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>

#include "base/memory/ref_counted.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/no_destructor.h"
#include "base/observer_list.h"
#include "base/sequence_checker.h"
#include "base/strings/string_util.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread_checker.h"
#include "base/timer/timer.h"
#include "build/build_config.h"
#include "build/chromeos_buildflags.h"
#include "net/base/network_change_notifier_factory.h"
#include "net/base/network_interfaces.h"
#include "net/base/url_util.h"
#include "net/dns/dns_config.h"
#include "net/dns/dns_config_service.h"
#include "net/dns/system_dns_config_change_notifier.h"
#include "net/url_request/url_request.h"
#include "url/gurl.h"

#if BUILDFLAG(IS_WIN)
#include "net/base/network_change_notifier_win.h"
#elif BUILDFLAG(IS_LINUX)
#include "net/base/network_change_notifier_linux.h"
#elif BUILDFLAG(IS_APPLE)
#include "net/base/network_change_notifier_apple.h"
#elif BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_ANDROID)
#include "net/base/network_change_notifier_passive.h"
#elif BUILDFLAG(IS_FUCHSIA)
#include "net/base/network_change_notifier_fuchsia.h"
#endif

namespace net {

namespace {

// The process-wide singleton notifier.
NetworkChangeNotifier* g_network_change_notifier = nullptr;

// Class factory singleton.
NetworkChangeNotifierFactory* g_network_change_notifier_factory = nullptr;

// Lock to protect |g_network_change_notifier| during creation time. Since
// creation of the process-wide instance can happen on any thread, this lock is
// used to guarantee only one instance is created. Once the global instance is
// created, the owner is responsible for destroying it on the same thread. All
// the other calls to the NetworkChangeNotifier do not require this lock as
// the global instance is only destroyed when the process is getting killed.
base::Lock& NetworkChangeNotifierCreationLock() {
  static base::NoDestructor<base::Lock> instance;
  return *instance;
}

class MockNetworkChangeNotifier : public NetworkChangeNotifier {
 public:
  explicit MockNetworkChangeNotifier(
      std::unique_ptr<SystemDnsConfigChangeNotifier> dns_config_notifier)
      : NetworkChangeNotifier(
            NetworkChangeCalculatorParams(),
            dns_config_notifier.get(),
            // Omit adding observers from the constructor as that would prevent
            // construction when SingleThreadTaskRunner::CurrentDefaultHandle
            // isn't set.
            /* omit_observers_in_constructor_for_testing=*/true),
        dns_config_notifier_(std::move(dns_config_notifier)) {}

  ~MockNetworkChangeNotifier() override { StopSystemDnsConfigNotifier(); }

  ConnectionType GetCurrentConnectionType() const override {
    return CONNECTION_UNKNOWN;
  }

 private:
  std::unique_ptr<SystemDnsConfigChangeNotifier> dns_config_notifier_;
};

}  // namespace

// static
bool NetworkChangeNotifier::test_notifications_only_ = false;

NetworkChangeNotifier::NetworkChangeCalculatorParams::
    NetworkChangeCalculatorParams() = default;

// Calculates NetworkChange signal from IPAddress, ConnectionCost, and
// ConnectionType signals.
class NetworkChangeNotifier::NetworkChangeCalculator
    : public ConnectionTypeObserver,
      public ConnectionCostObserver,
      public IPAddressObserver {
 public:
  explicit NetworkChangeCalculator(const NetworkChangeCalculatorParams& params)
      : params_(params) {
    DCHECK(g_network_change_notifier);
    AddConnectionTypeObserver(this);
    AddConnectionCostObserver(this);
    AddIPAddressObserver(this);
  }

  NetworkChangeCalculator(const NetworkChangeCalculator&) = delete;
  NetworkChangeCalculator& operator=(const NetworkChangeCalculator&) = delete;

  ~NetworkChangeCalculator() override {
    DCHECK(thread_checker_.CalledOnValidThread());
    RemoveConnectionTypeObserver(this);
    RemoveConnectionCostObserver(this);
    RemoveIPAddressObserver(this);
  }

  // NetworkChangeNotifier::IPAddressObserver implementation.
  void OnIPAddressChanged() override {
    DCHECK(thread_checker_.CalledOnValidThread());
    pending_connection_type_ = GetConnectionType();
    base::TimeDelta delay = last_announced_connection_type_ == CONNECTION_NONE
        ? params_.ip_address_offline_delay_ : params_.ip_address_online_delay_;
    // Cancels any previous timer.
    timer_.Start(FROM_HERE, delay, this, &NetworkChangeCalculator::Notify);
  }

  // NetworkChangeNotifier::ConnectionTypeObserver implementation.
  void OnConnectionTypeChanged(ConnectionType type) override {
    DCHECK(thread_checker_.CalledOnValidThread());
    pending_connection_type_ = type;
    base::TimeDelta delay = last_announced_connection_type_ == CONNECTION_NONE
        ? params_.connection_type_offline_delay_
        : params_.connection_type_online_delay_;
    // Cancels any previous timer.
    timer_.Start(FROM_HERE, delay, this, &NetworkChangeCalculator::Notify);
  }

  // NetworkChangeNotifier::ConnectionCostObserver implementation.
  void OnConnectionCostChanged(ConnectionCost cost) override {
    base::UmaHistogramEnumeration("Net.NetworkChangeNotifier.NewConnectionCost",
                                  cost, CONNECTION_COST_LAST);
  }

 private:
  void Notify() {
    DCHECK(thread_checker_.CalledOnValidThread());
    // Don't bother signaling about dead connections.
    if (have_announced_ &&
        (last_announced_connection_type_ == CONNECTION_NONE) &&
        (pending_connection_type_ == CONNECTION_NONE)) {
      return;
    }

    UMA_HISTOGRAM_ENUMERATION("Net.NetworkChangeNotifier.NewConnectionType",
                              pending_connection_type_, CONNECTION_LAST + 1);

    have_announced_ = true;
    last_announced_connection_type_ = pending_connection_type_;
    // Immediately before sending out an online signal, send out an offline
    // signal to perform any destructive actions before constructive actions.
    if (pending_connection_type_ != CONNECTION_NONE)
      NetworkChangeNotifier::NotifyObserversOfNetworkChange(CONNECTION_NONE);
    NetworkChangeNotifier::NotifyObserversOfNetworkChange(
        pending_connection_type_);
  }

  const NetworkChangeCalculatorParams params_;

  // Indicates if NotifyObserversOfNetworkChange has been called yet.
  bool have_announced_ = false;
  // Last value passed to NotifyObserversOfNetworkChange.
  ConnectionType last_announced_connection_type_ = CONNECTION_NONE;
  // Value to pass to NotifyObserversOfNetworkChange when Notify is called.
  ConnectionType pending_connection_type_ = CONNECTION_NONE;
  // Used to delay notifications so duplicates can be combined.
  base::OneShotTimer timer_;

  base::ThreadChecker thread_checker_;
};

// Holds the collection of observer lists used by NetworkChangeNotifier.
class NetworkChangeNotifier::ObserverList {
 public:
  ObserverList()
      : ip_address_observer_list_(
            base::MakeRefCounted<base::ObserverListThreadSafe<
                NetworkChangeNotifier::IPAddressObserver>>(
                base::ObserverListPolicy::EXISTING_ONLY)),
        connection_type_observer_list_(
            base::MakeRefCounted<base::ObserverListThreadSafe<
                NetworkChangeNotifier::ConnectionTypeObserver>>(
                base::ObserverListPolicy::EXISTING_ONLY)),
        resolver_state_observer_list_(
            base::MakeRefCounted<base::ObserverListThreadSafe<
                NetworkChangeNotifier::DNSObserver>>(
                base::ObserverListPolicy::EXISTING_ONLY)),
        network_change_observer_list_(
            base::MakeRefCounted<base::ObserverListThreadSafe<
                NetworkChangeNotifier::NetworkChangeObserver>>(
                base::ObserverListPolicy::EXISTING_ONLY)),
        max_bandwidth_observer_list_(
            base::MakeRefCounted<base::ObserverListThreadSafe<
                NetworkChangeNotifier::MaxBandwidthObserver>>(
                base::ObserverListPolicy::EXISTING_ONLY)),
        network_observer_list_(
            base::MakeRefCounted<base::ObserverListThreadSafe<
                NetworkChangeNotifier::NetworkObserver>>(
                base::ObserverListPolicy::EXISTING_ONLY)),
        connection_cost_observer_list_(
            base::MakeRefCounted<base::ObserverListThreadSafe<
                NetworkChangeNotifier::ConnectionCostObserver>>(
                base::ObserverListPolicy::EXISTING_ONLY)),
        default_network_active_observer_list_(
            base::MakeRefCounted<
                base::ObserverListThreadSafe<DefaultNetworkActiveObserver>>(
                base::ObserverListPolicy::EXISTING_ONLY)) {}

  ObserverList(const ObserverList&) = delete;
  ObserverList& operator=(const ObserverList&) = delete;
  ~ObserverList() = default;

  const scoped_refptr<
      base::ObserverListThreadSafe<NetworkChangeNotifier::IPAddressObserver>>
      ip_address_observer_list_;
  const scoped_refptr<base::ObserverListThreadSafe<
      NetworkChangeNotifier::ConnectionTypeObserver>>
      connection_type_observer_list_;
  const scoped_refptr<
      base::ObserverListThreadSafe<NetworkChangeNotifier::DNSObserver>>
      resolver_state_observer_list_;
  const scoped_refptr<base::ObserverListThreadSafe<
      NetworkChangeNotifier::NetworkChangeObserver>>
      network_change_observer_list_;
  const scoped_refptr<
      base::ObserverListThreadSafe<NetworkChangeNotifier::MaxBandwidthObserver>>
      max_bandwidth_observer_list_;
  const scoped_refptr<
      base::ObserverListThreadSafe<NetworkChangeNotifier::NetworkObserver>>
      network_observer_list_;
  const scoped_refptr<base::ObserverListThreadSafe<
      NetworkChangeNotifier::ConnectionCostObserver>>
      connection_cost_observer_list_;
  const scoped_refptr<
      base::ObserverListThreadSafe<DefaultNetworkActiveObserver>>
      default_network_active_observer_list_;
};

class NetworkChangeNotifier::SystemDnsConfigObserver
    : public SystemDnsConfigChangeNotifier::Observer {
 public:
  virtual ~SystemDnsConfigObserver() = default;

  void OnSystemDnsConfigChanged(std::optional<DnsConfig> config) override {
    NotifyObserversOfDNSChange();
  }
};

void NetworkChangeNotifier::ClearGlobalPointer() {
  if (!cleared_global_pointer_) {
    cleared_global_pointer_ = true;
    DCHECK_EQ(this, g_network_change_notifier);
    g_network_change_notifier = nullptr;
  }
}

NetworkChangeNotifier::~NetworkChangeNotifier() {
  network_change_calculator_.reset();
  ClearGlobalPointer();
  StopSystemDnsConfigNotifier();
}

// static
NetworkChangeNotifierFactory* NetworkChangeNotifier::GetFactory() {
  return g_network_change_notifier_factory;
}

// static
void NetworkChangeNotifier::SetFactory(
    NetworkChangeNotifierFactory* factory) {
  CHECK(!g_network_change_notifier_factory);
  g_network_change_notifier_factory = factory;
}

// static
std::unique_ptr<NetworkChangeNotifier> NetworkChangeNotifier::CreateIfNeeded(
    NetworkChangeNotifier::ConnectionType initial_type,
    NetworkChangeNotifier::ConnectionSubtype initial_subtype) {
  {
    base::AutoLock auto_lock(NetworkChangeNotifierCreationLock());
    if (g_network_change_notifier)
      return nullptr;
  }

  if (g_network_change_notifier_factory) {
    return g_network_change_notifier_factory->CreateInstanceWithInitialTypes(
        initial_type, initial_subtype);
  }

#if BUILDFLAG(IS_WIN)
  std::unique_ptr<NetworkChangeNotifierWin> network_change_notifier =
      std::make_unique<NetworkChangeNotifierWin>();
  network_change_notifier->WatchForAddressChange();
  return network_change_notifier;
#elif BUILDFLAG(IS_ANDROID)
  // Fallback to use NetworkChangeNotifierPassive if
  // NetworkChangeNotifierFactory is not set. Currently used for tests and when
  // running network service in a separate process.
  return std::make_unique<NetworkChangeNotifierPassive>(initial_type,
                                                        initial_subtype);
#elif BUILDFLAG(IS_CHROMEOS)
  return std::make_unique<NetworkChangeNotifierPassive>(initial_type,
                                                        initial_subtype);
#elif BUILDFLAG(IS_LINUX)
  return std::make_unique<NetworkChangeNotifierLinux>(
      std::unordered_set<std::string>());
#elif BUILDFLAG(IS_APPLE)
  return std::make_unique<NetworkChangeNotifierApple>();
#elif BUILDFLAG(IS_FUCHSIA)
  return std::make_unique<NetworkChangeNotifierFuchsia>(
      /*require_wlan=*/false);
#else
  NOTIMPLEMENTED();
  return nullptr;
#endif
}

// static
NetworkChangeNotifier::ConnectionCost
NetworkChangeNotifier::GetConnectionCost() {
  return g_network_change_notifier
             ? g_network_change_notifier->GetCurrentConnectionCost()
             : CONNECTION_COST_UNKNOWN;
}

// static
NetworkChangeNotifier::ConnectionType
NetworkChangeNotifier::GetConnectionType() {
  return g_network_change_notifier ?
      g_network_change_notifier->GetCurrentConnectionType() :
      CONNECTION_UNKNOWN;
}

// static
NetworkChangeNotifier::ConnectionSubtype
NetworkChangeNotifier::GetConnectionSubtype() {
  return g_network_change_notifier
             ? g_network_change_notifier->GetCurrentConnectionSubtype()
             : SUBTYPE_UNKNOWN;
}

// static
void NetworkChangeNotifier::GetMaxBandwidthAndConnectionType(
    double* max_bandwidth_mbps,
    ConnectionType* connection_type) {
  if (!g_network_change_notifier) {
    *connection_type = CONNECTION_UNKNOWN;
    *max_bandwidth_mbps =
        GetMaxBandwidthMbpsForConnectionSubtype(SUBTYPE_UNKNOWN);
    return;
  }

  g_network_change_notifier->GetCurrentMaxBandwidthAndConnectionType(
      max_bandwidth_mbps, connection_type);
}

// static
double NetworkChangeNotifier::GetMaxBandwidthMbpsForConnectionSubtype(
    ConnectionSubtype subtype) {
  switch (subtype) {
    case SUBTYPE_GSM:
      return 0.01;
    case SUBTYPE_IDEN:
      return 0.064;
    case SUBTYPE_CDMA:
      return 0.115;
    case SUBTYPE_1XRTT:
      return 0.153;
    case SUBTYPE_GPRS:
      return 0.237;
    case SUBTYPE_EDGE:
      return 0.384;
    case SUBTYPE_UMTS:
      return 2.0;
    case SUBTYPE_EVDO_REV_0:
      return 2.46;
    case SUBTYPE_EVDO_REV_A:
      return 3.1;
    case SUBTYPE_HSPA:
      return 3.6;
    case SUBTYPE_EVDO_REV_B:
      return 14.7;
    case SUBTYPE_HSDPA:
      return 14.3;
    case SUBTYPE_HSUPA:
      return 14.4;
    case SUBTYPE_EHRPD:
      return 21.0;
    case SUBTYPE_HSPAP:
      return 42.0;
    case SUBTYPE_LTE:
      return 100.0;
    case SUBTYPE_LTE_ADVANCED:
      return 100.0;
    case SUBTYPE_BLUETOOTH_1_2:
      return 1.0;
    case SUBTYPE_BLUETOOTH_2_1:
      return 3.0;
    case SUBTYPE_BLUETOOTH_3_0:
      return 24.0;
    case SUBTYPE_BLUETOOTH_4_0:
      return 1.0;
    case SUBTYPE_ETHERNET:
      return 10.0;
    case SUBTYPE_FAST_ETHERNET:
      return 100.0;
    case SUBTYPE_GIGABIT_ETHERNET:
      return 1000.0;
    case SUBTYPE_10_GIGABIT_ETHERNET:
      return 10000.0;
    case SUBTYPE_WIFI_B:
      return 11.0;
    case SUBTYPE_WIFI_G:
      return 54.0;
    case SUBTYPE_WIFI_N:
      return 600.0;
    case SUBTYPE_WIFI_AC:
      return 1300.0;
    case SUBTYPE_WIFI_AD:
      return 7000.0;
    case SUBTYPE_UNKNOWN:
      return std::numeric_limits<double>::infinity();
    case SUBTYPE_NONE:
      return 0.0;
    case SUBTYPE_OTHER:
      return std::numeric_limits<double>::infinity();
  }
  NOTREACHED();
}

// static
bool NetworkChangeNotifier::AreNetworkHandlesSupported() {
  if (g_network_change_notifier) {
    return g_network_change_notifier->AreNetworkHandlesCurrentlySupported();
  }
  return false;
}

// static
void NetworkChangeNotifier::GetConnectedNetworks(NetworkList* network_list) {
  DCHECK(AreNetworkHandlesSupported());
  if (g_network_change_notifier) {
    g_network_change_notifier->GetCurrentConnectedNetworks(network_list);
  } else {
    network_list->clear();
  }
}

// static
NetworkChangeNotifier::ConnectionType
NetworkChangeNotifier::GetNetworkConnectionType(
    handles::NetworkHandle network) {
  DCHECK(AreNetworkHandlesSupported());
  return g_network_change_notifier
             ? g_network_change_notifier->GetCurrentNetworkConnectionType(
                   network)
             : CONNECTION_UNKNOWN;
}

// static
handles::NetworkHandle NetworkChangeNotifier::GetDefaultNetwork() {
  DCHECK(AreNetworkHandlesSupported());
  return g_network_change_notifier
             ? g_network_change_notifier->GetCurrentDefaultNetwork()
             : handles::kInvalidNetworkHandle;
}

// static
SystemDnsConfigChangeNotifier*
NetworkChangeNotifier::GetSystemDnsConfigNotifier() {
  if (g_network_change_notifier)
    return g_network_change_notifier->GetCurrentSystemDnsConfigNotifier();
  return nullptr;
}

// static
bool NetworkChangeNotifier::IsDefaultNetworkActive() {
  if (g_network_change_notifier)
    return g_network_change_notifier->IsDefaultNetworkActiveInternal();
  // Assume true as a "default" to avoid batching indefinitely.
  return true;
}

// static
base::cstring_view NetworkChangeNotifier::ConnectionTypeToString(
    ConnectionType type) {
  static constexpr auto kConnectionTypeNames =
      std::to_array<base::cstring_view>({
          "CONNECTION_UNKNOWN",
          "CONNECTION_ETHERNET",
          "CONNECTION_WIFI",
          "CONNECTION_2G",
          "CONNECTION_3G",
          "CONNECTION_4G",
          "CONNECTION_NONE",
          "CONNECTION_BLUETOOTH",
          "CONNECTION_5G",
      });
  static_assert(std::size(kConnectionTypeNames) ==
                    NetworkChangeNotifier::CONNECTION_LAST + 1,
                "ConnectionType name count should match");
  if (type < CONNECTION_UNKNOWN || type > CONNECTION_LAST) {
    NOTREACHED();
  }
  return kConnectionTypeNames[type];
}

#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
// static
AddressMapOwnerLinux* NetworkChangeNotifier::GetAddressMapOwner() {
  return g_network_change_notifier
             ? g_network_change_notifier->GetAddressMapOwnerInternal()
             : nullptr;
}
#endif  // BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)

#if BUILDFLAG(IS_FUCHSIA)
// static
const internal::NetworkInterfaceCache*
NetworkChangeNotifier::GetNetworkInterfaceCache() {
  return g_network_change_notifier
             ? g_network_change_notifier->GetNetworkInterfaceCacheInternal()
             : nullptr;
}
#endif  // BUILDFLAG(IS_FUCHSIA)

// static
bool NetworkChangeNotifier::IsOffline() {
  return GetConnectionType() == CONNECTION_NONE;
}

// static
bool NetworkChangeNotifier::IsConnectionCellular(ConnectionType type) {
  bool is_cellular = false;
  switch (type) {
    case CONNECTION_2G:
    case CONNECTION_3G:
    case CONNECTION_4G:
    case CONNECTION_5G:
      is_cellular =  true;
      break;
    case CONNECTION_UNKNOWN:
    case CONNECTION_ETHERNET:
    case CONNECTION_WIFI:
    case CONNECTION_NONE:
    case CONNECTION_BLUETOOTH:
      is_cellular = false;
      break;
  }
  return is_cellular;
}

// static
NetworkChangeNotifier::ConnectionType
NetworkChangeNotifier::ConnectionTypeFromInterfaces() {
  NetworkInterfaceList interfaces;
  if (!GetNetworkList(&interfaces, EXCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES))
    return CONNECTION_UNKNOWN;
  return ConnectionTypeFromInterfaceList(interfaces);
}

// static
NetworkChangeNotifier::ConnectionType
NetworkChangeNotifier::ConnectionTypeFromInterfaceList(
    const NetworkInterfaceList& interfaces) {
  bool first = true;
  ConnectionType result = CONNECTION_NONE;
  for (const auto& network_interface : interfaces) {
#if BUILDFLAG(IS_WIN)
    if (network_interface.friendly_name == "Teredo Tunneling Pseudo-Interface")
      continue;
#endif
#if BUILDFLAG(IS_APPLE)
    // Ignore link-local addresses as they aren't globally routable.
    // Mac assigns these to disconnected interfaces like tunnel interfaces
    // ("utun"), airdrop interfaces ("awdl"), and ethernet ports ("en").
    if (network_interface.address.IsLinkLocal())
      continue;
#endif

    // Remove VMware network interfaces as they're internal and should not be
    // used to determine the network connection type.
    if (base::ToLowerASCII(network_interface.friendly_name).find("vmnet") !=
        std::string::npos) {
      continue;
    }
    if (first) {
      first = false;
      result = network_interface.type;
    } else if (result != network_interface.type) {
      return CONNECTION_UNKNOWN;
    }
  }
  return result;
}

// static
std::unique_ptr<NetworkChangeNotifier>
NetworkChangeNotifier::CreateMockIfNeeded() {
  {
    base::AutoLock auto_lock(NetworkChangeNotifierCreationLock());
    if (g_network_change_notifier)
      return nullptr;
  }
  // Use an empty noop SystemDnsConfigChangeNotifier to disable actual system
  // DNS configuration notifications.
  return std::make_unique<MockNetworkChangeNotifier>(
      std::make_unique<SystemDnsConfigChangeNotifier>(
          nullptr /* task_runner */, nullptr /* dns_config_service */));
}

NetworkChangeNotifier::IPAddressObserver::IPAddressObserver() = default;
NetworkChangeNotifier::IPAddressObserver::~IPAddressObserver() = default;

NetworkChangeNotifier::ConnectionTypeObserver::ConnectionTypeObserver() =
    default;
NetworkChangeNotifier::ConnectionTypeObserver::~ConnectionTypeObserver() =
    default;

NetworkChangeNotifier::DNSObserver::DNSObserver() = default;
NetworkChangeNotifier::DNSObserver::~DNSObserver() = default;

NetworkChangeNotifier::NetworkChangeObserver::NetworkChangeObserver() = default;
NetworkChangeNotifier::NetworkChangeObserver::~NetworkChangeObserver() =
    default;

NetworkChangeNotifier::MaxBandwidthObserver::MaxBandwidthObserver() = default;
NetworkChangeNotifier::MaxBandwidthObserver::~MaxBandwidthObserver() = default;

NetworkChangeNotifier::NetworkObserver::NetworkObserver() = default;
NetworkChangeNotifier::NetworkObserver::~NetworkObserver() = default;

NetworkChangeNotifier::ConnectionCostObserver::ConnectionCostObserver() =
    default;
NetworkChangeNotifier::ConnectionCostObserver::~ConnectionCostObserver() =
    default;

NetworkChangeNotifier::DefaultNetworkActiveObserver::
    DefaultNetworkActiveObserver() = default;
NetworkChangeNotifier::DefaultNetworkActiveObserver::
    ~DefaultNetworkActiveObserver() = default;

void NetworkChangeNotifier::AddIPAddressObserver(IPAddressObserver* observer) {
  DCHECK(!observer->observer_list_);
  observer->observer_list_ = GetObserverList().ip_address_observer_list_;
  observer->observer_list_->AddObserver(observer);
}

void NetworkChangeNotifier::AddConnectionTypeObserver(
    ConnectionTypeObserver* observer) {
  DCHECK(!observer->observer_list_);
  observer->observer_list_ = GetObserverList().connection_type_observer_list_;
  observer->observer_list_->AddObserver(observer);
}

void NetworkChangeNotifier::AddDNSObserver(DNSObserver* observer) {
  DCHECK(!observer->observer_list_);
  observer->observer_list_ = GetObserverList().resolver_state_observer_list_;
  observer->observer_list_->AddObserver(observer);
}

void NetworkChangeNotifier::AddNetworkChangeObserver(
    NetworkChangeObserver* observer) {
  DCHECK(!observer->observer_list_);
  observer->observer_list_ = GetObserverList().network_change_observer_list_;
  observer->observer_list_->AddObserver(observer);
}

void NetworkChangeNotifier::AddMaxBandwidthObserver(
    MaxBandwidthObserver* observer) {
  DCHECK(!observer->observer_list_);
  observer->observer_list_ = GetObserverList().max_bandwidth_observer_list_;
  observer->observer_list_->AddObserver(observer);
}

void NetworkChangeNotifier::AddNetworkObserver(NetworkObserver* observer) {
  base::AutoLock auto_lock(NetworkChangeNotifierCreationLock());
  DCHECK(AreNetworkHandlesSupported());
  DCHECK(!observer->observer_list_);
  observer->observer_list_ = GetObserverList().network_observer_list_;
  observer->observer_list_->AddObserver(observer);
}

void NetworkChangeNotifier::AddConnectionCostObserver(
    ConnectionCostObserver* observer) {
  DCHECK(!observer->observer_list_);
  observer->observer_list_ = GetObserverList().connection_cost_observer_list_;
  observer->observer_list_->AddObserver(observer);
}

void NetworkChangeNotifier::AddDefaultNetworkActiveObserver(
    DefaultNetworkActiveObserver* observer) {
  DCHECK(!observer->observer_list_);
  observer->observer_list_ =
      GetObserverList().default_network_active_observer_list_;
  observer->observer_list_->AddObserver(observer);
  base::AutoLock auto_lock(NetworkChangeNotifierCreationLock());
  // Currently we lose DefaultNetworkActiveObserverAdded notifications for
  // observers added prior to NCN creation. This should be a non-issue as
  // currently only Cronet listens to this and its observers are always added
  // after NCN creation.
  if (g_network_change_notifier) {
    g_network_change_notifier->DefaultNetworkActiveObserverAdded();
  }
}

void NetworkChangeNotifier::RemoveIPAddressObserver(
    IPAddressObserver* observer) {
  if (observer->observer_list_) {
    observer->observer_list_->RemoveObserver(observer);
    observer->observer_list_.reset();
  }
}

void NetworkChangeNotifier::RemoveConnectionTypeObserver(
    ConnectionTypeObserver* observer) {
  if (observer->observer_list_) {
    observer->observer_list_->RemoveObserver(observer);
    observer->observer_list_.reset();
  }
}

void NetworkChangeNotifier::RemoveDNSObserver(DNSObserver* observer) {
  if (observer->observer_list_) {
    observer->observer_list_->RemoveObserver(observer);
    observer->observer_list_.reset();
  }
}

void NetworkChangeNotifier::RemoveNetworkChangeObserver(
    NetworkChangeObserver* observer) {
  if (observer->observer_list_) {
    observer->observer_list_->RemoveObserver(observer);
    observer->observer_list_.reset();
  }
}

void NetworkChangeNotifier::RemoveMaxBandwidthObserver(
    MaxBandwidthObserver* observer) {
  if (observer->observer_list_) {
    observer->observer_list_->RemoveObserver(observer);
    observer->observer_list_.reset();
  }
}

void NetworkChangeNotifier::RemoveNetworkObserver(NetworkObserver* observer) {
  if (observer->observer_list_) {
    observer->observer_list_->RemoveObserver(observer);
    observer->observer_list_.reset();
  }
}

void NetworkChangeNotifier::RemoveConnectionCostObserver(
    ConnectionCostObserver* observer) {
  if (observer->observer_list_) {
    observer->observer_list_->RemoveObserver(observer);
    observer->observer_list_.reset();
  }
}

void NetworkChangeNotifier::RemoveDefaultNetworkActiveObserver(
    DefaultNetworkActiveObserver* observer) {
  if (observer->observer_list_) {
    observer->observer_list_->RemoveObserver(observer);
    observer->observer_list_.reset();
    g_network_change_notifier->DefaultNetworkActiveObserverRemoved();
  }
}

void NetworkChangeNotifier::TriggerNonSystemDnsChange() {
  NetworkChangeNotifier::NotifyObserversOfDNSChange();
}

// static
void NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests() {
  if (g_network_change_notifier)
    g_network_change_notifier->NotifyObserversOfIPAddressChangeImpl();
}

// static
void NetworkChangeNotifier::NotifyObserversOfConnectionTypeChangeForTests(
    ConnectionType type) {
  if (g_network_change_notifier)
    g_network_change_notifier->NotifyObserversOfConnectionTypeChangeImpl(type);
}

// static
void NetworkChangeNotifier::NotifyObserversOfDNSChangeForTests() {
  if (g_network_change_notifier)
    g_network_change_notifier->NotifyObserversOfDNSChangeImpl();
}

// static
void NetworkChangeNotifier::NotifyObserversOfNetworkChangeForTests(
    ConnectionType type) {
  if (g_network_change_notifier)
    g_network_change_notifier->NotifyObserversOfNetworkChangeImpl(type);
}

// static
void NetworkChangeNotifier::NotifyObserversOfMaxBandwidthChangeForTests(
    double max_bandwidth_mbps,
    ConnectionType type) {
  if (g_network_change_notifier) {
    g_network_change_notifier->NotifyObserversOfMaxBandwidthChangeImpl(
        max_bandwidth_mbps, type);
  }
}

// static
void NetworkChangeNotifier::NotifyObserversOfConnectionCostChangeForTests(
    ConnectionCost cost) {
  if (g_network_change_notifier)
    g_network_change_notifier->NotifyObserversOfConnectionCostChangeImpl(cost);
}

// static
void NetworkChangeNotifier::NotifyObserversOfDefaultNetworkActiveForTests() {
  if (g_network_change_notifier)
    g_network_change_notifier->NotifyObserversOfDefaultNetworkActiveImpl();
}

// static
void NetworkChangeNotifier::SetTestNotificationsOnly(bool test_only) {
  DCHECK(!g_network_change_notifier);
  NetworkChangeNotifier::test_notifications_only_ = test_only;
}

NetworkChangeNotifier::NetworkChangeNotifier(
    const NetworkChangeCalculatorParams& params
    /*= NetworkChangeCalculatorParams()*/,
    SystemDnsConfigChangeNotifier* system_dns_config_notifier /*= nullptr */,
    bool omit_observers_in_constructor_for_testing /*= false */)
    : system_dns_config_notifier_(system_dns_config_notifier),
      system_dns_config_observer_(std::make_unique<SystemDnsConfigObserver>()) {
  {
    base::AutoLock auto_lock(NetworkChangeNotifierCreationLock());
    if (!system_dns_config_notifier_) {
      static base::NoDestructor<SystemDnsConfigChangeNotifier> singleton{};
      system_dns_config_notifier_ = singleton.get();
    }

    DCHECK(!g_network_change_notifier);
    g_network_change_notifier = this;

    system_dns_config_notifier_->AddObserver(system_dns_config_observer_.get());
  }
  if (!omit_observers_in_constructor_for_testing) {
    network_change_calculator_ =
        std::make_unique<NetworkChangeCalculator>(params);
  }
}

#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
AddressMapOwnerLinux* NetworkChangeNotifier::GetAddressMapOwnerInternal() {
  return nullptr;
}
#endif

#if BUILDFLAG(IS_FUCHSIA)
const internal::NetworkInterfaceCache*
NetworkChangeNotifier::GetNetworkInterfaceCacheInternal() const {
  return nullptr;
}
#endif

NetworkChangeNotifier::ConnectionCost
NetworkChangeNotifier::GetCurrentConnectionCost() {
  // This is the default non-platform specific implementation and assumes that
  // cellular connectivity is metered and non-cellular is not. The function can
  // be specialized on each platform specific notifier implementation.
  return IsConnectionCellular(GetCurrentConnectionType())
             ? CONNECTION_COST_METERED
             : CONNECTION_COST_UNMETERED;
}

NetworkChangeNotifier::ConnectionSubtype
NetworkChangeNotifier::GetCurrentConnectionSubtype() const {
  return SUBTYPE_UNKNOWN;
}

void NetworkChangeNotifier::GetCurrentMaxBandwidthAndConnectionType(
    double* max_bandwidth_mbps,
    ConnectionType* connection_type) const {
  // This default implementation conforms to the NetInfo V3 specification but
  // should be overridden to provide specific bandwidth data based on the
  // platform.
  *connection_type = GetCurrentConnectionType();
  *max_bandwidth_mbps =
      *connection_type == CONNECTION_NONE
          ? GetMaxBandwidthMbpsForConnectionSubtype(SUBTYPE_NONE)
          : GetMaxBandwidthMbpsForConnectionSubtype(SUBTYPE_UNKNOWN);
}

bool NetworkChangeNotifier::AreNetworkHandlesCurrentlySupported() const {
  return false;
}

void NetworkChangeNotifier::GetCurrentConnectedNetworks(
    NetworkList* network_list) const {
  network_list->clear();
}

NetworkChangeNotifier::ConnectionType
NetworkChangeNotifier::GetCurrentNetworkConnectionType(
    handles::NetworkHandle network) const {
  return CONNECTION_UNKNOWN;
}

handles::NetworkHandle NetworkChangeNotifier::GetCurrentDefaultNetwork() const {
  return handles::kInvalidNetworkHandle;
}

SystemDnsConfigChangeNotifier*
NetworkChangeNotifier::GetCurrentSystemDnsConfigNotifier() {
  DCHECK(system_dns_config_notifier_);
  return system_dns_config_notifier_;
}

bool NetworkChangeNotifier::IsDefaultNetworkActiveInternal() {
  return true;
}

// static
void NetworkChangeNotifier::NotifyObserversOfIPAddressChange() {
  if (g_network_change_notifier &&
      !NetworkChangeNotifier::test_notifications_only_) {
    g_network_change_notifier->NotifyObserversOfIPAddressChangeImpl();
  }
}

// static
void NetworkChangeNotifier::NotifyObserversOfConnectionTypeChange() {
  if (g_network_change_notifier &&
      !NetworkChangeNotifier::test_notifications_only_) {
    g_network_change_notifier->NotifyObserversOfConnectionTypeChangeImpl(
        GetConnectionType());
  }
}

// static
void NetworkChangeNotifier::NotifyObserversOfNetworkChange(
    ConnectionType type) {
  if (g_network_change_notifier &&
      !NetworkChangeNotifier::test_notifications_only_) {
    g_network_change_notifier->NotifyObs
```
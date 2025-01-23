Response: The user wants to understand the functionality of the `filtering_network_manager_test.cc` file in the Chromium Blink engine. I need to analyze the code and identify its purpose, its relation to web technologies (JavaScript, HTML, CSS), and potential usage errors.

**Plan:**

1. **Identify the core class being tested:** The filename and the `#include` directive clearly indicate that `FilteringNetworkManager` is the primary focus.
2. **Determine the testing methodology:** The code uses Google Test (`testing/gmock` and `testing/gtest`). This means it's a unit test suite.
3. **Analyze the test cases:** Go through each `TEST_F` function to understand what specific aspects of `FilteringNetworkManager` are being tested.
4. **Look for connections to web technologies:**  Consider how network management, especially in the context of WebRTC (implied by the presence of `third_party/webrtc`), might relate to JavaScript APIs or browser behavior related to HTML/CSS.
5. **Identify logical reasoning and assumptions:** Pay attention to the `TestEntry` struct and how the tests are structured around sequences of events and expected outcomes.
6. **Consider common usage errors:**  Think about how a developer might misuse the `FilteringNetworkManager` or related APIs, leading to unexpected behavior.
这个文件 `filtering_network_manager_test.cc` 是 Chromium Blink 引擎中的一个 **单元测试文件**，专门用于测试 `FilteringNetworkManager` 类的功能。

**主要功能:**

1. **测试 `FilteringNetworkManager` 的网络过滤和权限控制逻辑:**  `FilteringNetworkManager` 的主要职责是在 WebRTC P2P 连接中，根据麦克风和摄像头的权限状态，来决定是否向外暴露所有的网络接口信息。这个测试文件通过模拟不同的权限状态和网络状态变化，来验证 `FilteringNetworkManager` 是否按照预期工作。
2. **验证 `StartUpdating()` 和 `StopUpdating()` 方法的行为:** 测试当客户端调用 `StartUpdating()` 和 `StopUpdating()` 方法时，`FilteringNetworkManager` 是否正确地开始和停止监听网络变化，并根据权限状态触发 `SignalNetworksChanged` 信号。
3. **验证 `SignalNetworksChanged` 信号的触发条件和参数:**  测试在不同的权限状态和网络状态下，`FilteringNetworkManager` 何时会触发 `SignalNetworksChanged` 信号，以及信号携带的参数（`ENUMERATION_ALLOWED` 或 `ENUMERATION_BLOCKED`）。
4. **模拟麦克风和摄像头权限的授予和拒绝:** 测试文件中创建了一个 `MockMediaPermission` 类，用于模拟用户授予或拒绝麦克风和摄像头权限的操作，以便测试 `FilteringNetworkManager` 对这些权限变化的响应。
5. **模拟底层网络状态的变化:**  测试文件中创建了一个 `MockNetworkManager` 类，用于模拟底层网络接口的变化，例如添加或删除网络接口，以便测试 `FilteringNetworkManager` 如何处理这些变化。
6. **验证在不同权限状态下 `GetNetworks()` 和 `GetAnyAddressNetworks()` 返回的网络列表:** 测试在权限被允许和拒绝的情况下，`FilteringNetworkManager` 返回的网络列表是否符合预期，特别是关于 mDNS responder 的关联。

**与 JavaScript, HTML, CSS 的关系 (间接):**

`FilteringNetworkManager` 本身不直接操作 JavaScript, HTML 或 CSS。然而，它的功能直接影响到 WebRTC API 在 JavaScript 中的行为，从而间接地影响到基于 WebRTC 构建的 Web 应用的功能。

*   **JavaScript WebRTC API:** 当 JavaScript 代码使用 WebRTC API（例如 `RTCPeerConnection` 的 `getConfiguration()` 方法）获取网络接口信息时，`FilteringNetworkManager` 的行为会影响到返回的网络接口列表。如果麦克风和摄像头权限被拒绝，`FilteringNetworkManager` 可能会阻止某些网络接口的枚举，从而影响 JavaScript 代码看到的网络信息。
*   **HTML 和 CSS (通过 Web 应用的功能):**  基于 WebRTC 构建的 Web 应用，例如视频会议应用或文件共享应用，可能会依赖于获取完整的网络接口信息来实现某些功能。`FilteringNetworkManager` 的过滤行为可能会影响这些功能的正常运行。例如，如果权限被拒绝，某些网络连接方式可能不可用。

**逻辑推理 (假设输入与输出):**

假设用户在一个网页中请求使用 WebRTC 进行视频通话，并且：

*   **假设输入 1:** 麦克风和摄像头权限都被 **允许**。
    *   **输出 1:** `FilteringNetworkManager` 的 `enumeration_permission()` 将为 `ENUMERATION_ALLOWED`。当 JavaScript 代码调用 WebRTC API 获取网络接口时，将会看到 **所有** 可用的网络接口。
*   **假设输入 2:** 麦克风和摄像头权限都被 **拒绝**。
    *   **输出 2:** `FilteringNetworkManager` 的 `enumeration_permission()` 将为 `ENUMERATION_BLOCKED`。当 JavaScript 代码调用 WebRTC API 获取网络接口时，可能会 **看不到某些** 网络接口（例如本地局域网接口），这取决于具体的实现策略。
*   **假设输入 3:** 用户先 **拒绝** 了麦克风和摄像头权限，然后 **授予** 了麦克风权限。
    *   **输出 3:**  最初 `enumeration_permission()` 为 `ENUMERATION_BLOCKED`。在授予麦克风权限后，`FilteringNetworkManager` 会触发 `SignalNetworksChanged` 信号，并且 `enumeration_permission()` 将变为 `ENUMERATION_ALLOWED`。后续 JavaScript 代码获取网络接口时，将能看到更多的网络接口。

**用户或编程常见的使用错误 (与 `FilteringNetworkManager` 相关的间接错误):**

虽然开发者不直接使用 `FilteringNetworkManager`，但理解其行为对于正确使用 WebRTC API 很重要。以下是一些可能出现的错误：

1. **假设在没有媒体权限的情况下能够枚举所有网络接口:**  开发者可能会假设即使没有麦克风或摄像头权限，也能像以前一样获取到所有网络接口信息。然而，`FilteringNetworkManager` 的存在意味着这种假设不再成立。如果代码依赖于某些特定网络接口的存在，需要在权限被拒绝的情况下进行妥善处理。
    *   **例子:** 一个文件共享应用可能需要在局域网内广播自己的存在。如果麦克风/摄像头权限被拒绝，应用可能无法获取局域网接口信息，导致广播失败。
2. **没有处理 `enumeration_permission()` 状态的变化:**  开发者需要在 JavaScript 代码中监听 `RTCPeerConnection` 的相关事件，并根据权限状态的变化动态调整应用的行为。如果忽略了权限状态的变化，可能会导致用户体验不佳。
    *   **例子:**  一个视频会议应用在权限被拒绝后，应该向用户明确提示无法使用某些网络连接方式，而不是默默地连接失败。
3. **不理解 mDNS responder 的作用:**  在权限被拒绝的情况下，`FilteringNetworkManager` 可能会使用 mDNS responder 来模糊本地 IP 地址。开发者需要理解这种机制，避免在依赖于真实本地 IP 地址的场景中出现问题。

**总结:**

`filtering_network_manager_test.cc` 是一个关键的测试文件，用于确保 Chromium Blink 引擎中的网络过滤和权限控制逻辑正确工作。虽然开发者不直接接触 `FilteringNetworkManager`，但理解其功能和行为对于正确开发基于 WebRTC 的 Web 应用至关重要，特别是涉及到处理媒体权限和网络接口枚举的场景。

### 提示词
```
这是目录为blink/renderer/platform/p2p/filtering_network_manager_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/p2p/filtering_network_manager.h"

#include <stddef.h>

#include <memory>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/memory/raw_ptr_exclusion.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/notreached.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/test_simple_task_runner.h"
#include "media/base/media_permission.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/p2p/empty_network_manager.h"
#include "third_party/webrtc/rtc_base/ip_address.h"

using ::testing::SizeIs;

namespace {

enum EventType {
  kMicDenied,      // Receive mic permission denied.
  kMicGranted,     // Receive mic permission granted.
  kCameraDenied,   // Receive camera permission denied.
  kCameraGranted,  // Receive camera permission granted.
  kStartUpdating,  // Client calls StartUpdating() on FilteringNetworkManager.
  kStopUpdating,   // Client calls StopUpdating() on FilteringNetworkManager.
  kMockNetworksChangedWithNewNetwork,   // MockNetworkManager has signaled
                                        // networks changed event and the
                                        // underlying network is replaced by
                                        // a new one.
  kMockNetworksChangedWithSameNetwork,  // MockNetworkManager has signaled
                                        // networks changed event but the
                                        // underlying network stays the
                                        // same.
};

enum ResultType {
  kNoSignal,                  // Do not expect SignalNetworksChanged fired.
  kSignalEnumerationBlocked,  // Expect SignalNetworksChanged and
                              // ENUMERATION_BLOCKED.
  kSignalEnumerationAllowed,  // Expect SignalNetworksChanged and
                              // ENUMERATION_ALLOWED.
};

struct TestEntry {
  EventType event;
  ResultType expected_result;
};

class EmptyMdnsResponder : public webrtc::MdnsResponderInterface {
 public:
  void CreateNameForAddress(const rtc::IPAddress& addr,
                            NameCreatedCallback callback) override {
    NOTREACHED();
  }
  void RemoveNameForAddress(const rtc::IPAddress& addr,
                            NameRemovedCallback callback) override {
    NOTREACHED();
  }
};

class MockNetworkManager : public rtc::NetworkManagerBase {
 public:
  MockNetworkManager() : mdns_responder_(new EmptyMdnsResponder()) {}
  // Mimic the current behavior that once the first signal is sent, any future
  // StartUpdating() will trigger another one.
  void StartUpdating() override {
    if (sent_first_update_)
      SignalNetworksChanged();
  }
  void StopUpdating() override {}

  std::vector<const rtc::Network*> GetNetworks() const override {
    return {network_.get()};
  }

  void SendNetworksChanged() {
    sent_first_update_ = true;
    SignalNetworksChanged();
  }

  webrtc::MdnsResponderInterface* GetMdnsResponder() const override {
    return mdns_responder_.get();
  }

  void CopyAndSetNetwork(const rtc::Network& network) {
    network_ = std::make_unique<rtc::Network>(network);
    network_->AddIP(network_->GetBestIP());
  }

  base::WeakPtr<MockNetworkManager> AsWeakPtr() {
    return weak_factory_.GetWeakPtr();
  }

 private:
  bool sent_first_update_ = false;
  std::unique_ptr<rtc::Network> network_;
  std::unique_ptr<EmptyMdnsResponder> mdns_responder_;
  base::WeakPtrFactory<MockNetworkManager> weak_factory_{this};
};

class MockMediaPermission : public media::MediaPermission {
 public:
  MockMediaPermission() = default;
  ~MockMediaPermission() override = default;

  void RequestPermission(Type type,
                         PermissionStatusCB permission_status_cb) override {
    NOTIMPLEMENTED();
  }

  void HasPermission(Type type,
                     PermissionStatusCB permission_status_cb) override {
    if (type == MediaPermission::Type::kAudioCapture) {
      DCHECK(mic_callback_.is_null());
      mic_callback_ = std::move(permission_status_cb);
    } else {
      DCHECK(type == MediaPermission::Type::kVideoCapture);
      DCHECK(camera_callback_.is_null());
      camera_callback_ = std::move(permission_status_cb);
    }
  }

  bool IsEncryptedMediaEnabled() override { return true; }

#if BUILDFLAG(IS_WIN)
  void IsHardwareSecureDecryptionAllowed(
      IsHardwareSecureDecryptionAllowedCB cb) override {
    std::move(cb).Run(true);
  }
#endif  // BUILDFLAG(IS_WIN)

  void SetMicPermission(bool granted) {
    if (!mic_callback_)
      return;

    std::move(mic_callback_).Run(granted);
  }

  void SetCameraPermission(bool granted) {
    if (!camera_callback_)
      return;

    std::move(camera_callback_).Run(granted);
  }

 private:
  PermissionStatusCB mic_callback_;
  PermissionStatusCB camera_callback_;
};

}  // namespace

namespace blink {

class FilteringNetworkManagerTest : public testing::Test,
                                    public sigslot::has_slots<> {
 public:
  FilteringNetworkManagerTest()
      : media_permission_(new MockMediaPermission()),
        task_runner_(new base::TestSimpleTaskRunner()),
        task_runner_current_default_handle_(task_runner_) {
    networks_.emplace_back("test_eth0", "Test Network Adapter 1",
                           rtc::IPAddress(0x12345600U), 24,
                           rtc::ADAPTER_TYPE_ETHERNET),
        networks_.back().AddIP(rtc::IPAddress(0x12345678));
    networks_.emplace_back("test_eth1", "Test Network Adapter 2",
                           rtc::IPAddress(0x87654300U), 24,
                           rtc::ADAPTER_TYPE_ETHERNET),
        networks_.back().AddIP(rtc::IPAddress(0x87654321));
  }

  void SetupNetworkManager(bool multiple_routes_requested) {
    base_network_manager_ = std::make_unique<MockNetworkManager>();
    SetNewNetworkForBaseNetworkManager();
    if (multiple_routes_requested) {
      network_manager_.reset(new FilteringNetworkManager(
          base_network_manager_->AsWeakPtr(), media_permission_.get(),
          allow_mdns_obfuscation_));
      network_manager_->Initialize();
    } else {
      network_manager_.reset(new EmptyNetworkManager(
          base_network_manager_.get(), base_network_manager_->AsWeakPtr()));
    }
    network_manager_->SignalNetworksChanged.connect(
        this, &FilteringNetworkManagerTest::OnNetworksChanged);
  }

  void RunTests(TestEntry* tests, size_t size) {
    for (size_t i = 0; i < size; ++i) {
      EXPECT_EQ(tests[i].expected_result, ProcessEvent(tests[i].event))
          << " in step: " << i;
    }
  }

  void SetNewNetworkForBaseNetworkManager() {
    base_network_manager_->CopyAndSetNetwork(networks_[next_new_network_id_]);
    next_new_network_id_ = (next_new_network_id_ + 1) % networks_.size();
  }

  ResultType ProcessEvent(EventType event) {
    clear_callback_called();
    switch (event) {
      case kMicDenied:
      case kMicGranted:
        media_permission_->SetMicPermission(event == kMicGranted);
        break;
      case kCameraDenied:
      case kCameraGranted:
        media_permission_->SetCameraPermission(event == kCameraGranted);
        break;
      case kStartUpdating:
        network_manager_->StartUpdating();
        break;
      case kStopUpdating:
        network_manager_->StopUpdating();
        break;
      case kMockNetworksChangedWithNewNetwork:
        SetNewNetworkForBaseNetworkManager();
        base_network_manager_->SendNetworksChanged();
        break;
      case kMockNetworksChangedWithSameNetwork:
        base_network_manager_->SendNetworksChanged();
        break;
    }

    task_runner_->RunUntilIdle();

    if (!callback_called_)
      return kNoSignal;

    if (network_manager_->enumeration_permission() ==
        rtc::NetworkManager::ENUMERATION_BLOCKED) {
      EXPECT_EQ(0u, GetP2PNetworkList().size());
      return kSignalEnumerationBlocked;
    }
    EXPECT_EQ(1u, GetP2PNetworkList().size());
    return kSignalEnumerationAllowed;
  }

 protected:
  const std::vector<const rtc::Network*>& GetP2PNetworkList() {
    network_list_ = network_manager_->GetNetworks();
    return network_list_;
  }

  void OnNetworksChanged() { callback_called_ = true; }
  void clear_callback_called() { callback_called_ = false; }
  void set_allow_mdns_obfuscation(bool val) { allow_mdns_obfuscation_ = val; }

  bool callback_called_ = false;
  std::unique_ptr<rtc::NetworkManager> network_manager_;
  std::unique_ptr<MockNetworkManager> base_network_manager_;

  std::unique_ptr<MockMediaPermission> media_permission_;
  bool allow_mdns_obfuscation_ = true;

  std::vector<rtc::Network> networks_;
  int next_new_network_id_ = 0;

  // This field is not vector<raw_ptr<...>> due to interaction with third_party
  // api.
  RAW_PTR_EXCLUSION std::vector<const rtc::Network*> network_list_;
  scoped_refptr<base::TestSimpleTaskRunner> task_runner_;
  base::SingleThreadTaskRunner::CurrentDefaultHandle
      task_runner_current_default_handle_;
};

// Test that when multiple routes is not requested, SignalNetworksChanged is
// fired right after the StartUpdating().
TEST_F(FilteringNetworkManagerTest, MultipleRoutesNotRequested) {
  SetupNetworkManager(false);
  TestEntry tests[] = {
      // Underneath network manager signals, no callback as StartUpdating() is
      // not called.
      {kMockNetworksChangedWithSameNetwork, kNoSignal},
      // StartUpdating() is called, should receive callback as the multiple
      // routes is not requested.
      {kStartUpdating, kSignalEnumerationBlocked},
      // Further network signal should trigger callback, since the
      // EmptyNetworkManager always forwards the signal from the base network
      // manager if there is any outstanding StartUpdate();
      {kMockNetworksChangedWithSameNetwork, kSignalEnumerationBlocked},
      // StartUpdating() always triggers callback after we have sent the first
      // network update.
      {kStartUpdating, kSignalEnumerationBlocked},
      {kStopUpdating, kNoSignal},
      {kStopUpdating, kNoSignal},
      // No outstanding StartUpdating(), no more signal.
      {kMockNetworksChangedWithSameNetwork, kNoSignal},
  };

  RunTests(tests, std::size(tests));
}

// Test that multiple routes request is blocked and signaled right after
// StartUpdating() since mic/camera permissions are denied.
TEST_F(FilteringNetworkManagerTest, BlockMultipleRoutesByStartUpdating) {
  SetupNetworkManager(true);

  TestEntry tests[] = {
      {kMockNetworksChangedWithSameNetwork, kNoSignal},
      // Both mic and camera are denied.
      {kMicDenied, kNoSignal},
      {kCameraDenied, kNoSignal},
      // Once StartUpdating() is called, signal network changed event with
      // ENUMERATION_BLOCKED.
      {kStartUpdating, kSignalEnumerationBlocked},
      // Further network signal should not trigger callback, since the set of
      // networks does not change after merging.
      {kMockNetworksChangedWithSameNetwork, kNoSignal},
      // Signal when observing a change after merging while there is any
      // outstanding StartUpdate();
      {kMockNetworksChangedWithNewNetwork, kSignalEnumerationBlocked},
      {kStartUpdating, kSignalEnumerationBlocked},
      {kStopUpdating, kNoSignal},
      {kStopUpdating, kNoSignal},
  };

  RunTests(tests, std::size(tests));
}

// Test that multiple routes request is blocked and signaled right after
// last pending permission check is denied since StartUpdating() has been called
// previously.
TEST_F(FilteringNetworkManagerTest, BlockMultipleRoutesByPermissionsDenied) {
  SetupNetworkManager(true);

  TestEntry tests[] = {
      // StartUpdating() should not fire the event before we send the first
      // update.
      {kStartUpdating, kNoSignal},
      {kMockNetworksChangedWithSameNetwork, kNoSignal},
      {kMicDenied, kNoSignal},
      // The last permission check being denied should immediately trigger the
      // networks changed signal, since we already have an updated network list.
      {kCameraDenied, kSignalEnumerationBlocked},
      {kStartUpdating, kSignalEnumerationBlocked},
      {kStopUpdating, kNoSignal},
      {kStopUpdating, kNoSignal},
      // No outstanding StartUpdating(), no more signal.
      {kMockNetworksChangedWithNewNetwork, kNoSignal},
  };

  RunTests(tests, std::size(tests));
}

// Test that after permissions have been denied, a network change signal from
// the internal NetworkManager is still needed before signaling a network
// change outwards. This is because even if network enumeration is blocked,
// we still want to give time to obtain the default IP addresses.
TEST_F(FilteringNetworkManagerTest, BlockMultipleRoutesByNetworksChanged) {
  SetupNetworkManager(true);

  TestEntry tests[] = {
      {kStartUpdating, kNoSignal},
      {kMicDenied, kNoSignal},
      {kCameraDenied, kNoSignal},
      {kMockNetworksChangedWithSameNetwork, kSignalEnumerationBlocked},
      {kStartUpdating, kSignalEnumerationBlocked},
      {kStopUpdating, kNoSignal},
      {kStopUpdating, kNoSignal},
  };

  RunTests(tests, std::size(tests));
}

// Test that multiple routes request is granted and signaled right after
// a pending permission check is granted since StartUpdating() has been called
// previously.
TEST_F(FilteringNetworkManagerTest, AllowMultipleRoutesByPermissionsGranted) {
  SetupNetworkManager(true);

  TestEntry tests[] = {
      {kStartUpdating, kNoSignal},
      {kMicDenied, kNoSignal},
      {kMockNetworksChangedWithSameNetwork, kNoSignal},
      // Once one media type is granted, signal networks changed with
      // ENUMERATION_ALLOWED.
      {kCameraGranted, kSignalEnumerationAllowed},
      {kMockNetworksChangedWithSameNetwork, kNoSignal},
      {kStartUpdating, kSignalEnumerationAllowed},
      {kStopUpdating, kNoSignal},
      // If there is any outstanding StartUpdating(), new event from underneath
      // network manger should trigger SignalNetworksChanged.
      {kMockNetworksChangedWithNewNetwork, kSignalEnumerationAllowed},
      {kStopUpdating, kNoSignal},
      // No outstanding StartUpdating(), no more signal.
      {kMockNetworksChangedWithNewNetwork, kNoSignal},
  };

  RunTests(tests, std::size(tests));
}

// Test that multiple routes request is granted and signaled right after
// StartUpdating() since there is at least one media permission granted.
TEST_F(FilteringNetworkManagerTest, AllowMultipleRoutesByStartUpdating) {
  SetupNetworkManager(true);

  TestEntry tests[] = {
      {kMicDenied, kNoSignal},
      {kMockNetworksChangedWithSameNetwork, kNoSignal},
      {kCameraGranted, kNoSignal},
      // StartUpdating() should signal the event with the status of permissions
      // granted.
      {kStartUpdating, kSignalEnumerationAllowed},
      {kMockNetworksChangedWithSameNetwork, kNoSignal},
      {kStartUpdating, kSignalEnumerationAllowed},
      {kStopUpdating, kNoSignal},
      // Signal when observing a change after merging while there is any
      // outstanding StartUpdate();
      {kMockNetworksChangedWithNewNetwork, kSignalEnumerationAllowed},
      {kStopUpdating, kNoSignal},
      // No outstanding StartUpdating(), no more signal.
      {kMockNetworksChangedWithNewNetwork, kNoSignal},
  };

  RunTests(tests, std::size(tests));
}

// Test that multiple routes request is granted and signaled right after
// underneath NetworkManager's SignalNetworksChanged() as at least one
// permission is granted and StartUpdating() has been called.
TEST_F(FilteringNetworkManagerTest, AllowMultipleRoutesByNetworksChanged) {
  SetupNetworkManager(true);

  TestEntry tests[] = {
      {kStartUpdating, kNoSignal},
      {kCameraGranted, kNoSignal},
      // Underneath network manager's signal networks changed should trigger
      // SignalNetworksChanged with ENUMERATION_ALLOWED.
      {kMockNetworksChangedWithSameNetwork, kSignalEnumerationAllowed},
      {kMicDenied, kNoSignal},
      {kMockNetworksChangedWithNewNetwork, kSignalEnumerationAllowed},
      {kStartUpdating, kSignalEnumerationAllowed},
      {kStopUpdating, kNoSignal},
      {kMockNetworksChangedWithNewNetwork, kSignalEnumerationAllowed},
      {kStopUpdating, kNoSignal},
      {kMockNetworksChangedWithNewNetwork, kNoSignal},
  };

  RunTests(tests, std::size(tests));
}

// Test that the networks provided by the GetNetworks() and
// GetAnyAddressNetworks() are not associated with an mDNS responder if the
// enumeration permission is granted, even if the mDNS obfuscation of local IPs
// is allowed (which is by default).
TEST_F(FilteringNetworkManagerTest, NullMdnsResponderAfterPermissionGranted) {
  SetupNetworkManager(true);

  TestEntry setup_steps[] = {
      {kMockNetworksChangedWithSameNetwork, kNoSignal},
      // Both mic and camera are granted.
      {kMicGranted, kNoSignal},
      {kCameraGranted, kNoSignal},
      // Once StartUpdating() is called, signal network changed event with
      // ENUMERATION_ALLOWED.
      {kStartUpdating, kSignalEnumerationAllowed},
  };
  RunTests(setup_steps, std::size(setup_steps));

  std::vector<const rtc::Network*> networks = network_manager_->GetNetworks();
  EXPECT_THAT(networks, SizeIs(1u));
  for (const rtc::Network* network : networks) {
    EXPECT_EQ(nullptr, network->GetMdnsResponder());
  }

  networks = network_manager_->GetAnyAddressNetworks();
  EXPECT_THAT(networks, SizeIs(2u));
  for (const rtc::Network* network : networks) {
    EXPECT_EQ(nullptr, network->GetMdnsResponder());
  }
}

// Test the networks on the default routes given by GetAnyAddressNetworks() are
// associated with an mDNS responder if the enumeration is blocked and the mDNS
// obfuscation of local IPs is allowed (which is by default).
TEST_F(FilteringNetworkManagerTest,
       ProvideMdnsResponderForDefaultRouteAfterPermissionDenied) {
  SetupNetworkManager(true);
  // By default, the enumeration is blocked if we provide |media_permission_|;
  EXPECT_EQ(rtc::NetworkManager::ENUMERATION_BLOCKED,
            network_manager_->enumeration_permission());

  std::vector<const rtc::Network*> networks = network_manager_->GetNetworks();
  EXPECT_TRUE(networks.empty());

  networks = network_manager_->GetAnyAddressNetworks();
  EXPECT_THAT(networks, SizeIs(2u));
  EXPECT_NE(nullptr, network_manager_->GetMdnsResponder());
  for (const rtc::Network* network : networks) {
    EXPECT_EQ(network_manager_->GetMdnsResponder(),
              network->GetMdnsResponder());
  }
}

// This is a similar test to the previous one but tests that the networks
// provided by the GetNetworks() and GetAnyAddressNetworks() are not associated
// with an mDNS responder if the mDNS obfuscation of local IPs is not allowed.
TEST_F(FilteringNetworkManagerTest,
       NullMdnsResponderWhenMdnsObfuscationDisallowedAfterPermissionDenied) {
  set_allow_mdns_obfuscation(false);
  SetupNetworkManager(true);
  // By default, the enumeration is blocked if we provide |media_permission_|;
  EXPECT_EQ(rtc::NetworkManager::ENUMERATION_BLOCKED,
            network_manager_->enumeration_permission());

  std::vector<const rtc::Network*> networks = network_manager_->GetNetworks();
  EXPECT_TRUE(networks.empty());

  networks = network_manager_->GetAnyAddressNetworks();
  EXPECT_THAT(networks, SizeIs(2u));
  for (const rtc::Network* network : networks) {
    EXPECT_EQ(nullptr, network->GetMdnsResponder());
  }
}

}  // namespace blink
```
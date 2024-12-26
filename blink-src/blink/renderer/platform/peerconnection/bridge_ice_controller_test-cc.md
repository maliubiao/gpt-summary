Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Understand the Goal:** The request asks for the functionality of the C++ test file, its relation to web technologies, any logical inferences, and common usage errors. The core is understanding what this test file *tests*.

2. **Identify the Target Class:** The filename `bridge_ice_controller_test.cc` strongly suggests the test is for a class named `BridgeIceController`. A quick scan of the code confirms this.

3. **Infer the Purpose of the Target Class:** The path `blink/renderer/platform/peerconnection/` indicates this class is part of the Blink rendering engine, specifically within the PeerConnection (WebRTC) module. The name "BridgeIceController" implies it acts as an intermediary or adapter for managing ICE (Interactive Connectivity Establishment) within Blink. ICE is a crucial component of WebRTC for establishing direct peer-to-peer connections.

4. **Analyze Imports and Dependencies:** Examining the `#include` directives reveals the key dependencies:
    * `third_party/webrtc_overrides/p2p/base/bridge_ice_controller.h`: This is the header file for the class being tested.
    * `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h`:  These indicate the use of Google Mock and Google Test, standard C++ testing frameworks. This confirms the file is indeed a test file.
    * Files related to WebRTC: `ice_controller_interface.h`, `mock_ice_agent.h`, `mock_ice_controller.h`, etc. These suggest the `BridgeIceController` interacts with lower-level ICE components provided by the WebRTC library.
    * Blink-specific files: `fake_connection_test_base.h`, `webrtc_connection_matchers.h`. These provide utilities for setting up test environments and custom matchers for WebRTC connections within the Blink context.

5. **Examine Test Structure:** The file uses `TEST_F` and `TEST_P` macros, which are part of Google Test. `TEST_F` sets up a test fixture (in this case, `BridgeIceControllerTest` and its derived classes). `TEST_P` indicates parameterized tests. This tells us the tests are organized into logical units.

6. **Analyze Individual Tests:** Now, go through each `TEST_F` and `TEST_P` to understand what specific aspect of `BridgeIceController` is being tested. Look for:
    * **Mock Objects:**  The use of `MockIceAgent` and `MockIceController` indicates that the tests are isolating the `BridgeIceController` and simulating the behavior of its dependencies. This is a standard practice in unit testing.
    * **Expectations:** `EXPECT_CALL` is the core of Google Mock. It sets up expectations for how the mock objects should be called. Analyzing these expectations reveals the interactions being tested (e.g., `SetIceConfig`, `AddConnection`, `OnConnectionSwitched`, `ShouldSwitchConnection`).
    * **Assertions:**  `EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_NE`, and `EXPECT_THAT` are used to verify the behavior of the `BridgeIceController` based on the mock interactions.
    * **Specific Scenarios:**  Tests often focus on particular scenarios like handling immediate switch requests, sort and switch requests, pinging, and invalid proposals.
    * **Parameterization:** The `BridgeIceControllerProposalTest` uses parameterization to test different combinations of accepting or rejecting proposals.

7. **Relate to Web Technologies (JavaScript, HTML, CSS):**  This requires connecting the low-level C++ code to the higher-level web APIs. Think about how WebRTC is used in web browsers:
    * **JavaScript API:**  The `RTCPeerConnection` JavaScript API is the primary way developers interact with WebRTC. The `BridgeIceController` is part of the browser's internal implementation that supports this API. Actions like creating an `RTCPeerConnection`, adding ICE candidates, and setting remote descriptions will eventually involve the underlying ICE logic that `BridgeIceController` manages.
    * **HTML:** While HTML itself doesn't directly interact with ICE, the `<video>` and `<audio>` elements are used to display the media streams established through WebRTC connections.
    * **CSS:** CSS is used for styling the video and audio elements, but it has no direct functional relationship with the ICE controller.

8. **Logical Inferences and Assumptions:** Identify any implicit assumptions made in the tests or logical deductions about the class's behavior. For example, if a test expects `OnConnectionSwitched` to be called after `SetSelectedConnection`, it implies a causal relationship.

9. **Common Usage Errors:**  Consider how developers might misuse the WebRTC JavaScript API or how the underlying ICE process could fail. Examples include providing invalid ICE candidates or network connectivity issues. The tests related to "invalid proposals" in the C++ code hint at the kind of error handling needed when the interaction with the ICE layer isn't perfect.

10. **Structure the Output:** Organize the findings logically into the categories requested: functionality, relationship to web technologies, logical inferences, and common usage errors. Use clear and concise language, providing specific examples from the code where possible.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the file directly manipulates HTML elements. **Correction:**  Realized that the file is a *low-level* test for the ICE controller. The connection to HTML is indirect through the JavaScript API and media elements.
* **Initial thought:** Focus only on successful scenarios. **Correction:** Noticed the tests for "invalid proposals," highlighting the importance of error handling.
* **Initial thought:**  Simply list the tested methods. **Correction:**  Provided more context about *how* they are tested (using mocks, expectations, and assertions) and the underlying purpose of the methods in the ICE negotiation process.

By following this structured approach, and being willing to refine initial assumptions, it's possible to effectively analyze the C++ test file and provide a comprehensive answer.
这个文件 `bridge_ice_controller_test.cc` 是 Chromium Blink 引擎中 `BridgeIceController` 类的单元测试文件。 `BridgeIceController` 的作用是作为 Blink 渲染引擎和底层的 WebRTC ICE (Interactive Connectivity Establishment) 控制器之间的桥梁。它负责协调 ICE 代理的行为，并与 Blink 的其他组件进行交互。

以下是该文件测试的主要功能：

**1. 桥接和转发 ICE 控制器接口调用:**
    * 测试 `BridgeIceController` 能正确地将来自 Blink 的请求转发到底层的 `IceControllerInterface` 实现（通常是 `cricket::IceController`）。
    * 例如，测试 `SetIceConfig`, `GetUseCandidateAttribute`, `AddConnection`, `SetSelectedConnection`, `MarkConnectionPinged`, `FindNextPingableConnection`, `OnConnectionDestroyed` 等方法的调用和参数传递是否正确。

**2. 管理和通知观察者 (Observer):**
    * 测试 `BridgeIceController` 能正确地添加和移除观察者 (`IceControllerObserverInterface`)，并在 ICE 连接状态变化时通知这些观察者。
    * 例如，测试当有新的连接添加 (`OnConnectionAdded`)、连接状态更新 (`OnConnectionUpdated`)、连接切换 (`OnConnectionSwitched`) 或连接销毁 (`OnConnectionDestroyed`) 时，观察者是否被正确通知。

**3. 处理立即切换请求 (Immediate Switch Request):**
    * 测试 `BridgeIceController` 如何响应立即切换连接的请求。
    * 验证在接收到立即切换请求后，是否会调用底层的 `ShouldSwitchConnection` 判断是否可以切换，并根据结果发送 `SwitchProposal` 给观察者，最终调用 ICE 代理的 `SwitchSelectedConnection` 进行切换。
    * 测试了在切换后，是否会安排定时任务来重新检查最佳连接。

**4. 处理立即排序和切换请求 (Immediate Sort and Switch Request):**
    * 测试 `BridgeIceController` 如何响应立即进行连接排序并切换的请求。
    * 验证是否会调用底层的 `SortAndSwitchConnection`，并根据返回结果发送 `SwitchProposal` 给观察者。
    * 测试了在接收到 `SwitchProposal` 后，是否可以被接受或拒绝，并根据结果调用 ICE 代理的 `SwitchSelectedConnection` 进行切换。
    * 同时测试了是否会调用 `PruneConnections` 来清理不必要的连接，并发送 `PruneProposal`。

**5. 处理排序和切换请求 (Sort and Switch Request):**
    * 测试 `BridgeIceController` 如何处理异步的连接排序和切换请求。
    * 验证是否会在稍后的任务中调用底层的 `SortAndSwitchConnection`，并发送 `SwitchProposal`。

**6. 处理 Ping 提议 (Ping Proposal):**
    * 测试在排序和切换后，`BridgeIceController` 如何开始 ping 连接以探测网络质量。
    * 验证是否会调用底层的 `SelectConnectionToPing` 选择要 ping 的连接，并发送 `PingProposal` 给观察者。
    * 测试了 `PingProposal` 可以被接受或拒绝，并根据结果调用 ICE 代理的 `SendPingRequest`。
    * 测试了在一定时间间隔后，会重新检查并发送 ping 请求。

**7. 处理无效的提议 (Invalid Proposal):**
    * 测试当接收到无效的 `PingProposal`, `SwitchProposal`, 或 `PruneProposal` 时，`BridgeIceController` 的行为，例如拒绝接受非期望的提议或包含未知连接的提议。

**8. 处理显式的 Ping, Switch, Prune 请求:**
    * 测试通过 `IceInteractionInterface` 发起的显式 `PingIceConnection`, `SwitchToIceConnection`, `PruneIceConnections` 请求的处理。
    * 验证这些请求是否被正确地转发到底层的 ICE 代理，并处理无效的连接参数。

**与 JavaScript, HTML, CSS 的关系:**

`bridge_ice_controller_test.cc` 所在的代码是浏览器内核的一部分，直接与 JavaScript, HTML, CSS 没有直接的代码交互。但是，它所测试的 `BridgeIceController` 组件是 WebRTC 功能实现的关键部分，而 WebRTC 功能可以通过 JavaScript API (例如 `RTCPeerConnection`) 在网页中使用。

* **JavaScript:**
    * **举例说明:** 当 JavaScript 代码创建一个 `RTCPeerConnection` 对象并开始进行 ICE 连接协商时，Blink 引擎内部会创建并使用 `BridgeIceController` 来管理 ICE 代理。JavaScript 代码通过 `RTCPeerConnection` 的方法 (例如 `addIceCandidate`, `createOffer`, `createAnswer`) 与底层的 ICE 过程进行交互。`BridgeIceController` 负责协调这些操作。
    * **假设输入与输出:**
        * **假设输入 (JavaScript):**  JavaScript 代码调用 `peerConnection.addIceCandidate(candidate)`，其中 `candidate` 是一个从远端接收到的 ICE 候选者信息。
        * **逻辑推理:** Blink 引擎会解析这个 `candidate`，并将其传递给底层的 ICE 代理。`BridgeIceController` 可能会收到连接添加的通知，并调用其观察者的 `OnConnectionAdded` 方法。
    * **用户或编程常见的使用错误:**
        * **错误示例 (JavaScript):** 在 ICE 连接协商完成之前就尝试发送数据到 `RTCPeerConnection` 的数据通道。
        * **C++ 层面体现:**  `BridgeIceController` 可能会在连接状态不稳定时拒绝某些操作或触发重连机制。

* **HTML:**
    * **举例说明:** HTML 中的 `<video>` 和 `<audio>` 元素常用于显示通过 WebRTC 建立的媒体流。虽然 HTML 本身不直接参与 ICE 协商，但 WebRTC 的目的是在网页上实现实时的音视频通信。
    * **假设输入与输出:**
        * **假设输入 (HTML):**  网页包含一个 `<video>` 元素，用于显示远程视频流。
        * **逻辑推理:** 当 WebRTC 连接建立成功后，接收到的视频数据会被解码并渲染到这个 `<video>` 元素上。`BridgeIceController` 在幕后确保了连接的稳定和高效。

* **CSS:**
    * **关系较弱:** CSS 主要用于样式化 HTML 元素，与 `BridgeIceController` 的功能没有直接关系。但是，CSS 可以用于控制 `<video>` 和 `<audio>` 元素的显示效果。

**逻辑推理的假设输入与输出:**

* **场景：处理立即切换请求**
    * **假设输入:** `BridgeIceController` 接收到 `OnImmediateSwitchRequest`，指定要切换到的连接 `conn`，以及切换的原因 `reason` (例如 `IceSwitchReason::NOMINATION_ON_CONTROLLED_SIDE`)。
    * **逻辑推理:**
        1. `BridgeIceController` 调用底层 `IceController` 的 `ShouldSwitchConnection(reason, conn)`。
        2. **假设 `ShouldSwitchConnection` 返回一个包含新连接 `conn` 和重新检查事件的 `SwitchResult`。**
        3. `BridgeIceController` 通知观察者发送 `SwitchProposal`。
        4. 如果提议被接受（在这个测试中是模拟的），`BridgeIceController` 调用 ICE 代理的 `SwitchSelectedConnection(conn, reason)`。
        5. `BridgeIceController` 安排一个定时任务，在一定的延迟后重新检查连接。
    * **预期输出:** 底层 ICE 代理切换到指定的连接，观察者收到连接切换的通知，并且在延迟后会触发连接的重新评估。

* **场景：处理 Ping 提议**
    * **假设输入:** 在排序和切换之后，`BridgeIceController` 需要选择一个连接进行 ping 测试。底层 `IceController` 的 `SelectConnectionToPing` 方法返回一个需要 ping 的连接 `conn` 和一个重新检查延迟。
    * **逻辑推理:**
        1. `BridgeIceController` 创建一个 `PingProposal`，包含要 ping 的连接和重新检查延迟。
        2. `BridgeIceController` 通知观察者发送 `PingProposal`。
        3. **假设 `PingProposal` 被接受。**
        4. `BridgeIceController` 调用 ICE 代理的 `SendPingRequest(conn)`。
    * **预期输出:** ICE 代理向指定的连接发送 ping 请求。

**用户或编程常见的使用错误:**

* **错误示例 1 (用户):**  用户的网络环境不稳定，导致 ICE 连接建立失败或频繁断开。
    * **C++ 层面体现:**  `BridgeIceController` 可能会多次尝试连接，触发连接切换，或者最终报告连接错误。测试中模拟了连接切换和重新检查的场景。

* **错误示例 2 (程序员):**  在 JavaScript 代码中没有正确处理 ICE 候选者，例如忽略了某些候选者或者处理顺序错误。
    * **C++ 层面体现:**  这可能导致 `BridgeIceController` 无法找到有效的连接路径。测试中包含了处理未知连接的提议的场景，模拟了这种情况下的错误处理。

* **错误示例 3 (程序员):**  过早地尝试发送数据，在 ICE 连接建立完成之前。
    * **C++ 层面体现:**  `BridgeIceController` 会维护连接状态，并在连接未建立时阻止数据发送或给出相应的错误指示。

总而言之，`bridge_ice_controller_test.cc` 通过大量的单元测试，确保了 `BridgeIceController` 作为 Blink 和底层 WebRTC ICE 控制器之间的桥梁能够正确地工作，处理各种 ICE 协商和连接管理相关的逻辑，并且能够与 Blink 的其他组件（例如观察者）进行有效的通信。这对于保证 WebRTC 功能在 Chromium 浏览器中的稳定性和可靠性至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/peerconnection/bridge_ice_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/webrtc_overrides/p2p/base/bridge_ice_controller.h"

#include <memory>
#include <tuple>

#include "base/memory/raw_ptr.h"
#include "base/memory/raw_ptr_exclusion.h"
#include "base/memory/scoped_refptr.h"
#include "base/strings/strcat.h"
#include "base/test/gtest_util.h"
#include "base/time/time.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

#include "third_party/blink/renderer/platform/peerconnection/fake_connection_test_base.h"
#include "third_party/blink/renderer/platform/peerconnection/webrtc_connection_matchers.h"

#include "third_party/webrtc/p2p/base/ice_controller_interface.h"
#include "third_party/webrtc/p2p/base/ice_switch_reason.h"
#include "third_party/webrtc/p2p/base/mock_ice_agent.h"
#include "third_party/webrtc/p2p/base/mock_ice_controller.h"

#include "third_party/webrtc_overrides/p2p/base/fake_connection_factory.h"
#include "third_party/webrtc_overrides/p2p/base/ice_connection.h"
#include "third_party/webrtc_overrides/p2p/base/ice_interaction_interface.h"
#include "third_party/webrtc_overrides/p2p/base/ice_ping_proposal.h"
#include "third_party/webrtc_overrides/p2p/base/ice_prune_proposal.h"
#include "third_party/webrtc_overrides/p2p/base/ice_switch_proposal.h"

namespace cricket {
// This is an opaque type for the purposes of this test, so a forward
// declaration suffices
struct IceConfig;
}  // namespace cricket

namespace {

using ::blink::BridgeIceController;
using ::blink::FakeConnectionFactory;
using ::blink::IceConnection;
using ::blink::IceControllerObserverInterface;
using ::blink::IceInteractionInterface;
using ::blink::IcePingProposal;
using ::blink::IcePruneProposal;
using ::blink::IceSwitchProposal;

using ::cricket::Candidate;
using ::cricket::Connection;
using ::cricket::IceConfig;
using ::cricket::IceControllerFactoryArgs;
using ::cricket::IceControllerInterface;
using ::cricket::IceMode;
using ::cricket::IceRecheckEvent;
using ::cricket::IceSwitchReason;
using ::cricket::MockIceAgent;
using ::cricket::MockIceController;
using ::cricket::MockIceControllerFactory;
using ::cricket::NominationMode;

using ::testing::_;
using ::testing::Combine;
using ::testing::ElementsAreArray;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::NiceMock;
using ::testing::Ref;
using ::testing::Return;
using ::testing::Sequence;
using ::testing::StrictMock;
using ::testing::Test;
using ::testing::TestParamInfo;
using ::testing::Values;
using ::testing::WithArgs;
using ::testing::WithParamInterface;

using ::blink::ConnectionEq;
using ::blink::PingProposalEq;
using ::blink::PruneProposalEq;
using ::blink::SwitchProposalEq;

using ::base::test::SingleThreadTaskEnvironment;
using ::base::test::TaskEnvironment;

static const std::string kIp = "1.2.3.4";
static const std::string kIpTwo = "1.3.5.7";
static const std::string kIpThree = "1.4.7.10";
static const int kPort = 6745;

static const IceConfig kIceConfig;

static const std::vector<const Connection*> kEmptyConnsList{};
static const IceControllerInterface::SwitchResult kEmptySwitchResult{};

static constexpr base::TimeDelta kTick = base::Milliseconds(1);

class MockIceControllerObserver : public IceControllerObserverInterface {
 public:
  MockIceControllerObserver() = default;
  ~MockIceControllerObserver() override = default;

  MOCK_METHOD(void,
              OnObserverAttached,
              (scoped_refptr<IceInteractionInterface> agent),
              (override));
  MOCK_METHOD(void, OnObserverDetached, (), (override));
  MOCK_METHOD(void,
              OnConnectionAdded,
              (const IceConnection& connection),
              (override));
  MOCK_METHOD(void,
              OnConnectionUpdated,
              (const IceConnection& connection),
              (override));
  MOCK_METHOD(void,
              OnConnectionSwitched,
              (const IceConnection& connection),
              (override));
  MOCK_METHOD(void,
              OnConnectionDestroyed,
              (const IceConnection& connection),
              (override));
  MOCK_METHOD(void,
              OnPingProposal,
              (const IcePingProposal& ping_proposal),
              (override));
  MOCK_METHOD(void,
              OnSwitchProposal,
              (const IceSwitchProposal& switch_proposal),
              (override));
  MOCK_METHOD(void,
              OnPruneProposal,
              (const IcePruneProposal& prune_proposal),
              (override));
};

class BridgeIceControllerTest : public ::blink::FakeConnectionTestBase {};

enum class ProposalResponse {
  ACCEPT,
  REJECT,
};
using PingProposalResponse = ProposalResponse;
using SwitchProposalResponse = ProposalResponse;
using PruneProposalResponse = ProposalResponse;

class BridgeIceControllerProposalTest
    : public BridgeIceControllerTest,
      public WithParamInterface<std::tuple<PingProposalResponse,
                                           SwitchProposalResponse,
                                           PruneProposalResponse>> {
 protected:
  BridgeIceControllerProposalTest()
      : should_accept_ping_proposal(std::get<0>(GetParam()) ==
                                    ProposalResponse::ACCEPT),
        should_accept_switch_proposal(std::get<1>(GetParam()) ==
                                      ProposalResponse::ACCEPT),
        should_accept_prune_proposal(std::get<2>(GetParam()) ==
                                     ProposalResponse::ACCEPT) {}

  const bool should_accept_ping_proposal;
  const bool should_accept_switch_proposal;
  const bool should_accept_prune_proposal;
};

std::string ToTestSuffix(std::string type, ProposalResponse response) {
  return base::StrCat(
      {(response == ProposalResponse::ACCEPT ? "Accept" : "Reject"), "", type});
}

std::string MakeTestName(
    const TestParamInfo<BridgeIceControllerProposalTest::ParamType>& info) {
  return base::StrCat({ToTestSuffix("Ping", std::get<0>(info.param)), "_",
                       ToTestSuffix("Switch", std::get<1>(info.param)), "_",
                       ToTestSuffix("Prune", std::get<2>(info.param))});
}

INSTANTIATE_TEST_SUITE_P(All,
                         BridgeIceControllerProposalTest,
                         Combine(Values(PingProposalResponse::ACCEPT,
                                        PingProposalResponse::REJECT),
                                 Values(SwitchProposalResponse::ACCEPT,
                                        SwitchProposalResponse::REJECT),
                                 Values(PruneProposalResponse::ACCEPT,
                                        PruneProposalResponse::REJECT)),
                         MakeTestName);

TEST_F(BridgeIceControllerTest, ObserverAttached) {
  MockIceAgent agent;
  MockIceControllerObserver observer1;
  MockIceControllerObserver observer2;
  std::unique_ptr<MockIceController> will_move =
      std::make_unique<MockIceController>(IceControllerFactoryArgs{});

  scoped_refptr<IceInteractionInterface> interaction_agent = nullptr;
  EXPECT_CALL(observer1, OnObserverAttached).WillOnce(WithArgs<0>([&](auto ia) {
    interaction_agent = std::move(ia);
  }));
  BridgeIceController controller(env.GetMainThreadTaskRunner(), &observer1,
                                 &agent, std::move(will_move));
  EXPECT_NE(interaction_agent, nullptr);

  EXPECT_CALL(observer1, OnObserverDetached);
  EXPECT_CALL(observer2, OnObserverAttached(_));
  controller.AttachObserver(&observer2);

  EXPECT_CALL(observer2, OnObserverDetached);
  controller.AttachObserver(nullptr);
}

TEST_F(BridgeIceControllerTest, PassthroughIceControllerInterface) {
  MockIceAgent agent;
  MockIceControllerObserver observer1;
  MockIceControllerObserver observer2;
  std::unique_ptr<MockIceController> will_move =
      std::make_unique<MockIceController>(IceControllerFactoryArgs{});
  MockIceController* wrapped = will_move.get();

  EXPECT_CALL(observer1, OnObserverAttached(_));
  BridgeIceController controller(env.GetMainThreadTaskRunner(), &observer1,
                                 &agent, std::move(will_move));

  const Connection* conn = GetConnection(kIp, kPort);
  ASSERT_NE(conn, nullptr);
  const Connection* conn_two = GetConnection(kIpTwo, kPort);
  ASSERT_NE(conn_two, nullptr);
  const Connection* conn_three = GetConnection(kIpThree, kPort);
  ASSERT_NE(conn_three, nullptr);

  EXPECT_CALL(*wrapped, SetIceConfig(Ref(kIceConfig)));
  controller.SetIceConfig(kIceConfig);

  EXPECT_CALL(*wrapped, GetUseCandidateAttr(conn, NominationMode::AGGRESSIVE,
                                            IceMode::ICEMODE_LITE))
      .WillOnce(Return(true));
  EXPECT_TRUE(controller.GetUseCandidateAttribute(
      conn, NominationMode::AGGRESSIVE, IceMode::ICEMODE_LITE));

  EXPECT_CALL(*wrapped, AddConnection(conn));
  EXPECT_CALL(observer1, OnConnectionAdded(ConnectionEq(conn)));
  controller.OnConnectionAdded(conn);

  EXPECT_CALL(*wrapped, SetSelectedConnection(conn));
  EXPECT_CALL(observer1, OnConnectionSwitched(ConnectionEq(conn)));
  controller.OnConnectionSwitched(conn);

  EXPECT_CALL(*wrapped, MarkConnectionPinged(conn));
  controller.OnConnectionPinged(conn);

  EXPECT_CALL(*wrapped, FindNextPingableConnection()).WillOnce(Return(conn));
  EXPECT_EQ(controller.FindNextPingableConnection(), conn);

  EXPECT_CALL(*wrapped, OnConnectionDestroyed(conn));
  EXPECT_CALL(observer1, OnConnectionDestroyed(ConnectionEq(conn)));
  controller.OnConnectionDestroyed(conn);

  EXPECT_CALL(observer1, OnObserverDetached);
  EXPECT_CALL(observer2, OnObserverAttached(_));
  controller.AttachObserver(&observer2);

  EXPECT_CALL(*wrapped, AddConnection(conn_two));
  EXPECT_CALL(observer1, OnConnectionAdded).Times(0);
  EXPECT_CALL(observer2, OnConnectionAdded(ConnectionEq(conn_two)));
  controller.OnConnectionAdded(conn_two);

  EXPECT_CALL(*wrapped, SetSelectedConnection(conn_two));
  EXPECT_CALL(observer1, OnConnectionSwitched).Times(0);
  EXPECT_CALL(observer2, OnConnectionSwitched(ConnectionEq(conn_two)));
  controller.OnConnectionSwitched(conn_two);

  EXPECT_CALL(*wrapped, OnConnectionDestroyed(conn_two));
  EXPECT_CALL(observer1, OnConnectionDestroyed).Times(0);
  EXPECT_CALL(observer2, OnConnectionDestroyed(ConnectionEq(conn_two)));
  controller.OnConnectionDestroyed(conn_two);

  EXPECT_CALL(observer2, OnObserverDetached);
  controller.AttachObserver(nullptr);

  EXPECT_CALL(*wrapped, AddConnection(conn_three));
  EXPECT_CALL(observer1, OnConnectionAdded).Times(0);
  EXPECT_CALL(observer2, OnConnectionAdded).Times(0);
  controller.OnConnectionAdded(conn_three);

  EXPECT_CALL(*wrapped, SetSelectedConnection(conn_three));
  EXPECT_CALL(observer1, OnConnectionSwitched).Times(0);
  EXPECT_CALL(observer2, OnConnectionSwitched).Times(0);
  controller.OnConnectionSwitched(conn_three);

  EXPECT_CALL(*wrapped, OnConnectionDestroyed(conn_three));
  EXPECT_CALL(observer1, OnConnectionDestroyed).Times(0);
  EXPECT_CALL(observer2, OnConnectionDestroyed).Times(0);
  controller.OnConnectionDestroyed(conn_three);
}

TEST_F(BridgeIceControllerTest, HandlesImmediateSwitchRequest) {
  NiceMock<MockIceAgent> agent;
  MockIceControllerObserver observer;
  std::unique_ptr<MockIceController> will_move =
      std::make_unique<MockIceController>(IceControllerFactoryArgs{});
  MockIceController* wrapped = will_move.get();

  scoped_refptr<IceInteractionInterface> interaction_agent = nullptr;
  EXPECT_CALL(observer, OnObserverAttached(_))
      .WillOnce(
          WithArgs<0>([&](auto ia) { interaction_agent = std::move(ia); }));
  BridgeIceController controller(env.GetMainThreadTaskRunner(), &observer,
                                 &agent, std::move(will_move));

  const Connection* conn = GetConnection(kIp, kPort);
  ASSERT_NE(conn, nullptr);
  const Connection* conn_two = GetConnection(kIpTwo, kPort);
  ASSERT_NE(conn_two, nullptr);

  // Set default native ICE controller behaviour.
  const std::vector<const Connection*> connection_set{conn, conn_two};
  EXPECT_CALL(*wrapped, GetConnections())
      .WillRepeatedly(Return(connection_set));
  EXPECT_CALL(*wrapped, HasPingableConnection).WillRepeatedly(Return(false));

  const IceSwitchReason reason = IceSwitchReason::NOMINATION_ON_CONTROLLED_SIDE;
  const std::vector<const Connection*> conns_to_forget{conn_two};
  const int recheck_delay_ms = 10;
  const IceControllerInterface::SwitchResult switch_result{
      conn,
      IceRecheckEvent(IceSwitchReason::ICE_CONTROLLER_RECHECK,
                      recheck_delay_ms),
      conns_to_forget};

  // ICE controller should switch to given connection immediately.
  Sequence check_then_switch;
  EXPECT_CALL(*wrapped, ShouldSwitchConnection(reason, conn))
      .InSequence(check_then_switch)
      .WillOnce(Return(switch_result));
  EXPECT_CALL(observer, OnSwitchProposal(SwitchProposalEq(
                            reason, switch_result, /*reply_expected*/ false)))
      .InSequence(check_then_switch);
  EXPECT_CALL(agent, SwitchSelectedConnection(conn, reason))
      .InSequence(check_then_switch);
  EXPECT_CALL(agent, ForgetLearnedStateForConnections(
                         ElementsAreArray(conns_to_forget)));

  EXPECT_TRUE(controller.OnImmediateSwitchRequest(reason, conn));

  // No rechecks before recheck delay.
  env.FastForwardBy(base::Milliseconds(recheck_delay_ms - 1));

  // ICE controller should recheck for best connection after the recheck delay.
  Sequence recheck_sort;
  EXPECT_CALL(agent, UpdateConnectionStates()).InSequence(recheck_sort);
  EXPECT_CALL(*wrapped,
              SortAndSwitchConnection(IceSwitchReason::ICE_CONTROLLER_RECHECK))
      .InSequence(recheck_sort)
      .WillOnce(Return(kEmptySwitchResult));
  // Empty switch proposal could be eliminated, but reason may be interesting.
  EXPECT_CALL(observer, OnSwitchProposal(SwitchProposalEq(
                            IceSwitchReason::ICE_CONTROLLER_RECHECK,
                            kEmptySwitchResult, /*reply_expected*/ false)))
      .InSequence(recheck_sort);
  EXPECT_CALL(agent, ForgetLearnedStateForConnections(IsEmpty()))
      .InSequence(recheck_sort);
  // Recheck should check if anything needs pruning.
  EXPECT_CALL(*wrapped, PruneConnections())
      .InSequence(recheck_sort)
      .WillOnce(Return(kEmptyConnsList));
  // No need to propose pruning if nothing to do.
  EXPECT_CALL(observer, OnPruneProposal).Times(0);
  EXPECT_CALL(agent, PruneConnections(IsEmpty())).InSequence(recheck_sort);

  env.FastForwardBy(kTick);
}

TEST_P(BridgeIceControllerProposalTest, HandlesImmediateSortAndSwitchRequest) {
  NiceMock<MockIceAgent> agent;
  MockIceControllerObserver observer;
  std::unique_ptr<MockIceController> will_move =
      std::make_unique<MockIceController>(IceControllerFactoryArgs{});
  MockIceController* wrapped = will_move.get();

  scoped_refptr<IceInteractionInterface> interaction_agent = nullptr;
  EXPECT_CALL(observer, OnObserverAttached(_))
      .WillOnce(
          WithArgs<0>([&](auto ia) { interaction_agent = std::move(ia); }));
  BridgeIceController controller(env.GetMainThreadTaskRunner(), &observer,
                                 &agent, std::move(will_move));

  const Connection* conn = GetConnection(kIp, kPort);
  ASSERT_NE(conn, nullptr);
  const Connection* conn_two = GetConnection(kIpTwo, kPort);
  ASSERT_NE(conn_two, nullptr);
  const Connection* conn_three = GetConnection(kIpThree, kPort);
  ASSERT_NE(conn_three, nullptr);

  // Set default native ICE controller behaviour.
  const std::vector<const Connection*> connection_set{conn, conn_two,
                                                      conn_three};
  EXPECT_CALL(*wrapped, GetConnections())
      .WillRepeatedly(Return(connection_set));
  EXPECT_CALL(*wrapped, HasPingableConnection).WillRepeatedly(Return(false));

  const IceSwitchReason reason =
      IceSwitchReason::NEW_CONNECTION_FROM_LOCAL_CANDIDATE;
  const std::vector<const Connection*> conns_to_forget{conn_two};
  const std::vector<const Connection*> conns_to_prune{conn_three};
  const int recheck_delay_ms = 10;
  const IceControllerInterface::SwitchResult switch_result{
      conn,
      IceRecheckEvent(IceSwitchReason::ICE_CONTROLLER_RECHECK,
                      recheck_delay_ms),
      conns_to_forget};

  Sequence sort_and_switch;
  EXPECT_CALL(agent, UpdateConnectionStates()).InSequence(sort_and_switch);
  EXPECT_CALL(*wrapped, SortAndSwitchConnection(reason))
      .InSequence(sort_and_switch)
      .WillOnce(Return(switch_result));
  EXPECT_CALL(observer, OnSwitchProposal(_))
      .InSequence(sort_and_switch)
      .WillOnce(WithArgs<0>([&](auto switch_proposal) {
        EXPECT_THAT(switch_proposal, SwitchProposalEq(reason, switch_result,
                                                      /*reply_expected*/ true));
        if (should_accept_switch_proposal) {
          interaction_agent->AcceptSwitchProposal(switch_proposal);
        } else {
          interaction_agent->RejectSwitchProposal(switch_proposal);
        }
      }));
  // Only expect a switch to occur if switch proposal is accepted. Further state
  // update occurs regardless.
  if (should_accept_switch_proposal) {
    EXPECT_CALL(agent, SwitchSelectedConnection(conn, reason))
        .InSequence(sort_and_switch);
  }
  EXPECT_CALL(*wrapped, PruneConnections())
      .InSequence(sort_and_switch)
      .WillOnce(Return(conns_to_prune));
  EXPECT_CALL(observer, OnPruneProposal(_))
      .InSequence(sort_and_switch)
      .WillOnce(WithArgs<0>([&](auto prune_proposal) {
        EXPECT_THAT(prune_proposal,
                    PruneProposalEq(conns_to_prune, /*reply_expected*/ true));
        if (should_accept_prune_proposal) {
          interaction_agent->AcceptPruneProposal(prune_proposal);
        } else {
          interaction_agent->RejectPruneProposal(prune_proposal);
        }
      }));
  // Only expect a pruning to occur if prune proposal is accepted. Recheck
  // occurs regardless.
  if (should_accept_prune_proposal) {
    EXPECT_CALL(agent, PruneConnections(ElementsAreArray(conns_to_prune)))
        .InSequence(sort_and_switch);
  }

  controller.OnImmediateSortAndSwitchRequest(reason);

  // No rechecks before recheck delay.
  env.FastForwardBy(base::Milliseconds(recheck_delay_ms - 1));

  // ICE controller should recheck for best connection after the recheck
  // delay.
  Sequence recheck_sort;
  EXPECT_CALL(agent, UpdateConnectionStates()).InSequence(recheck_sort);
  EXPECT_CALL(*wrapped,
              SortAndSwitchConnection(IceSwitchReason::ICE_CONTROLLER_RECHECK))
      .InSequence(recheck_sort)
      .WillOnce(Return(IceControllerInterface::SwitchResult{}));
  // Empty switch proposal could be eliminated, but reason may be interesting.
  EXPECT_CALL(observer, OnSwitchProposal(SwitchProposalEq(
                            IceSwitchReason::ICE_CONTROLLER_RECHECK,
                            kEmptySwitchResult, /*reply_expected*/ false)))
      .InSequence(recheck_sort);
  EXPECT_CALL(*wrapped, PruneConnections())
      .InSequence(recheck_sort)
      .WillOnce(Return(kEmptyConnsList));
  // No need to propose pruning if nothing to do.
  EXPECT_CALL(observer, OnPruneProposal).Times(0);
  EXPECT_CALL(agent, PruneConnections(IsEmpty())).InSequence(recheck_sort);

  env.FastForwardBy(kTick);
}

TEST_P(BridgeIceControllerProposalTest, HandlesSortAndSwitchRequest) {
  NiceMock<MockIceAgent> agent;
  MockIceControllerObserver observer;
  std::unique_ptr<MockIceController> will_move =
      std::make_unique<MockIceController>(IceControllerFactoryArgs{});
  MockIceController* wrapped = will_move.get();

  scoped_refptr<IceInteractionInterface> interaction_agent = nullptr;
  EXPECT_CALL(observer, OnObserverAttached(_))
      .WillOnce(
          WithArgs<0>([&](auto ia) { interaction_agent = std::move(ia); }));
  BridgeIceController controller(env.GetMainThreadTaskRunner(), &observer,
                                 &agent, std::move(will_move));

  const Connection* conn = GetConnection(kIp, kPort);
  ASSERT_NE(conn, nullptr);
  const Connection* conn_two = GetConnection(kIpTwo, kPort);
  ASSERT_NE(conn_two, nullptr);

  // Set default native ICE controller behaviour.
  const std::vector<const Connection*> connection_set{conn, conn_two};
  EXPECT_CALL(*wrapped, GetConnections())
      .WillRepeatedly(Return(connection_set));
  EXPECT_CALL(*wrapped, HasPingableConnection).WillRepeatedly(Return(false));

  const IceSwitchReason reason = IceSwitchReason::NETWORK_PREFERENCE_CHANGE;

  // No action should occur immediately
  EXPECT_CALL(agent, UpdateConnectionStates()).Times(0);
  EXPECT_CALL(*wrapped, SortAndSwitchConnection(_)).Times(0);
  EXPECT_CALL(observer, OnSwitchProposal(_)).Times(0);
  EXPECT_CALL(agent, SwitchSelectedConnection(_, _)).Times(0);

  controller.OnSortAndSwitchRequest(reason);

  const std::vector<const Connection*> conns_to_forget{conn_two};
  const int recheck_delay_ms = 10;
  const IceControllerInterface::SwitchResult switch_result{
      conn,
      IceRecheckEvent(IceSwitchReason::ICE_CONTROLLER_RECHECK,
                      recheck_delay_ms),
      conns_to_forget};

  // Sort and switch should take place as the subsequent task.
  Sequence sort_and_switch;
  EXPECT_CALL(agent, UpdateConnectionStates()).InSequence(sort_and_switch);
  EXPECT_CALL(*wrapped, SortAndSwitchConnection(reason))
      .InSequence(sort_and_switch)
      .WillOnce(Return(switch_result));
  EXPECT_CALL(observer, OnSwitchProposal(_))
      .InSequence(sort_and_switch)
      .WillOnce(WithArgs<0>([&](auto switch_proposal) {
        EXPECT_THAT(switch_proposal, SwitchProposalEq(reason, switch_result,
                                                      /*reply_expected*/ true));
        if (should_accept_switch_proposal) {
          interaction_agent->AcceptSwitchProposal(switch_proposal);
        } else {
          interaction_agent->RejectSwitchProposal(switch_proposal);
        }
      }));
  // Only expect a switch to occur if switch proposal is accepted. Further state
  // update occurs regardless.
  if (should_accept_switch_proposal) {
    EXPECT_CALL(agent, SwitchSelectedConnection(conn, reason))
        .InSequence(sort_and_switch);
  }
  EXPECT_CALL(*wrapped, PruneConnections())
      .InSequence(sort_and_switch)
      .WillOnce(Return(kEmptyConnsList));
  // No need to propose pruning if nothing to do.
  EXPECT_CALL(observer, OnPruneProposal).Times(0);
  EXPECT_CALL(agent, PruneConnections(IsEmpty())).InSequence(sort_and_switch);

  // Pick up the first task.
  env.FastForwardBy(kTick);
}

TEST_P(BridgeIceControllerProposalTest, StartPingingAfterSortAndSwitch) {
  NiceMock<MockIceAgent> agent;
  MockIceControllerObserver observer;
  std::unique_ptr<MockIceController> will_move =
      std::make_unique<MockIceController>(IceControllerFactoryArgs{});
  MockIceController* wrapped = will_move.get();

  scoped_refptr<IceInteractionInterface> interaction_agent = nullptr;
  EXPECT_CALL(observer, OnObserverAttached(_))
      .WillOnce(
          WithArgs<0>([&](auto ia) { interaction_agent = std::move(ia); }));
  BridgeIceController controller(env.GetMainThreadTaskRunner(), &observer,
                                 &agent, std::move(will_move));

  const Connection* conn = GetConnection(kIp, kPort);
  ASSERT_NE(conn, nullptr);

  // Set default native ICE controller behaviour.
  const std::vector<const Connection*> connection_set{conn};
  EXPECT_CALL(*wrapped, GetConnections())
      .WillRepeatedly(Return(connection_set));

  // Pinging does not start automatically, unless triggered through a sort.
  EXPECT_CALL(*wrapped, HasPingableConnection()).Times(0);
  EXPECT_CALL(*wrapped, SelectConnectionToPing(_)).Times(0);
  EXPECT_CALL(observer, OnPingProposal(_)).Times(0);
  EXPECT_CALL(agent, OnStartedPinging()).Times(0);

  controller.OnSortAndSwitchRequest(IceSwitchReason::DATA_RECEIVED);

  // Pinging does not start if no pingable connection.
  EXPECT_CALL(*wrapped, SortAndSwitchConnection(IceSwitchReason::DATA_RECEIVED))
      .WillOnce(Return(kEmptySwitchResult));
  EXPECT_CALL(observer, OnSwitchProposal(SwitchProposalEq(
                            IceSwitchReason::DATA_RECEIVED, kEmptySwitchResult,
                            /*reply_expected*/ false)));
  EXPECT_CALL(*wrapped, PruneConnections()).WillOnce(Return(kEmptyConnsList));
  // No need to propose pruning if nothing to do.
  EXPECT_CALL(observer, OnPruneProposal).Times(0);
  EXPECT_CALL(agent, PruneConnections(IsEmpty()));
  EXPECT_CALL(*wrapped, HasPingableConnection()).WillOnce(Return(false));
  EXPECT_CALL(*wrapped, SelectConnectionToPing(_)).Times(0);
  EXPECT_CALL(observer, OnPingProposal(_)).Times(0);
  EXPECT_CALL(agent, OnStartedPinging()).Times(0);

  // Pick up the first task.
  env.FastForwardBy(kTick);

  const int recheck_delay_ms = 10;
  const IceControllerInterface::PingResult ping_result(conn, recheck_delay_ms);
  const IceControllerInterface::PingResult empty_ping_result(nullptr,
                                                             recheck_delay_ms);

  // Pinging starts when there is a pingable connection.
  Sequence start_pinging;
  EXPECT_CALL(*wrapped, SortAndSwitchConnection(IceSwitchReason::DATA_RECEIVED))
      .InSequence(start_pinging)
      .WillOnce(Return(kEmptySwitchResult));
  EXPECT_CALL(observer, OnSwitchProposal(SwitchProposalEq(
                            IceSwitchReason::DATA_RECEIVED, kEmptySwitchResult,
                            /*reply_expected*/ false)))
      .InSequence(start_pinging);
  EXPECT_CALL(*wrapped, PruneConnections())
      .InSequence(start_pinging)
      .WillOnce(Return(kEmptyConnsList));
  // No need to propose pruning if nothing to do.
  EXPECT_CALL(observer, OnPruneProposal).Times(0);
  EXPECT_CALL(agent, PruneConnections(IsEmpty())).InSequence(start_pinging);
  EXPECT_CALL(*wrapped, HasPingableConnection())
      .InSequence(start_pinging)
      .WillOnce(Return(true));
  EXPECT_CALL(agent, OnStartedPinging()).InSequence(start_pinging);
  EXPECT_CALL(agent, GetLastPingSentMs())
      .InSequence(start_pinging)
      .WillOnce(Return(123));
  EXPECT_CALL(*wrapped, SelectConnectionToPing(123))
      .InSequence(start_pinging)
      .WillOnce(Return(ping_result));
  EXPECT_CALL(observer, OnPingProposal(_))
      .InSequence(start_pinging)
      .WillOnce(WithArgs<0>([&](auto ping_proposal) {
        EXPECT_THAT(ping_proposal, PingProposalEq(ping_result,
                                                  /*reply_expected*/ true));
        if (should_accept_ping_proposal) {
          interaction_agent->AcceptPingProposal(ping_proposal);
        } else {
          interaction_agent->RejectPingProposal(ping_proposal);
        }
      }));
  // Only expect a ping to occur if ping proposal is accepted. Recheck occurs
  // regardless.
  if (should_accept_ping_proposal) {
    EXPECT_CALL(agent, SendPingRequest(conn)).InSequence(start_pinging);
  }

  controller.OnSortAndSwitchRequest(IceSwitchReason::DATA_RECEIVED);
  env.FastForwardBy(kTick);

  // ICE controller should recheck and ping after the recheck delay.
  // No ping should be sent if no connection selected to ping.
  EXPECT_CALL(agent, GetLastPingSentMs()).WillOnce(Return(456));
  EXPECT_CALL(*wrapped, SelectConnectionToPing(456))
      .WillOnce(Return(empty_ping_result));
  EXPECT_CALL(observer,
              OnPingProposal(PingProposalEq(empty_ping_result,
                                            /*reply_expected*/ false)));
  EXPECT_CALL(agent, SendPingRequest(conn)).Times(0);

  env.FastForwardBy(base::Milliseconds(recheck_delay_ms));
}

// Tests that verify correct handling of invalid proposals.
class BridgeIceControllerInvalidProposalTest : public BridgeIceControllerTest {
 protected:
  BridgeIceControllerInvalidProposalTest()
      : recheck_event(IceSwitchReason::ICE_CONTROLLER_RECHECK,
                      recheck_delay_ms) {
    std::unique_ptr<StrictMock<MockIceController>> will_move =
        std::make_unique<StrictMock<MockIceController>>(
            IceControllerFactoryArgs{});
    wrapped_controller = will_move.get();

    EXPECT_CALL(observer, OnObserverAttached(_))
        .WillOnce(
            WithArgs<0>([&](auto ia) { interaction_agent = std::move(ia); }));
    controller = std::make_unique<BridgeIceController>(
        env.GetMainThreadTaskRunner(), &observer, &agent, std::move(will_move));

    conn = GetConnection(kIp, kPort);
    EXPECT_NE(conn, nullptr);
    conn_two = GetConnection(kIpTwo, kPort);
    EXPECT_NE(conn_two, nullptr);

    // Exclude conn_two to be able to test for unknown connection in proposal.
    const std::vector<const Connection*> connection_set{conn};
    EXPECT_CALL(*wrapped_controller, GetConnections())
        .WillRepeatedly(Return(connection_set));

    // No expectations set on any mocks. Together with StrictMock, this ensures
    // that invalid proposal actions with side-effects will cause a test
    // failure.
  }

  void Recheck() { env.FastForwardBy(base::Milliseconds(recheck_delay_ms)); }

  const int recheck_delay_ms = 10;
  raw_ptr<const Connection> conn = nullptr;
  raw_ptr<const Connection> conn_two = nullptr;
  // This field is not vector<raw_ptr<...>> due to interaction with third_party
  // api.
  RAW_PTR_EXCLUSION const std::vector<const Connection*>
      empty_conns_to_forget{};
  const IceSwitchReason reason = IceSwitchReason::DATA_RECEIVED;
  const IceRecheckEvent recheck_event;

  scoped_refptr<IceInteractionInterface> interaction_agent;
  StrictMock<MockIceAgent> agent;
  StrictMock<MockIceControllerObserver> observer;
  std::unique_ptr<BridgeIceController> controller;
  raw_ptr<StrictMock<MockIceController>> wrapped_controller;
};

// Alias for verifying DCHECKs. This test suite should be used for death tests.
using BridgeIceControllerDeathTest = BridgeIceControllerInvalidProposalTest;
// Alias for verifying no side-effects, without hitting a DCHECK.
using BridgeIceControllerNoopTest = BridgeIceControllerInvalidProposalTest;

TEST_F(BridgeIceControllerDeathTest, AcceptUnsolicitedPingProposal) {
  const IceControllerInterface::PingResult ping_result(conn, recheck_delay_ms);
  const IcePingProposal proposal(ping_result, /*reply_expected=*/false);
  EXPECT_DCHECK_DEATH_WITH(interaction_agent->AcceptPingProposal(proposal),
                           "unsolicited");
}

TEST_F(BridgeIceControllerDeathTest, RejectUnsolicitedPingProposal) {
  const IceControllerInterface::PingResult ping_result(conn, recheck_delay_ms);
  const IcePingProposal proposal(ping_result, /*reply_expected=*/false);
  EXPECT_DCHECK_DEATH_WITH(interaction_agent->RejectPingProposal(proposal),
                           "unsolicited");
}

TEST_F(BridgeIceControllerDeathTest, AcceptEmptyPingProposal) {
  const IceControllerInterface::PingResult null_ping_result(nullptr,
                                                            recheck_delay_ms);
  const IcePingProposal proposal(null_ping_result, /*reply_expected=*/true);
  EXPECT_DCHECK_DEATH_WITH(interaction_agent->AcceptPingProposal(proposal),
                           "without a connection");
}

TEST_F(BridgeIceControllerNoopTest, AcceptUnknownPingProposal) {
  const IceControllerInterface::PingResult ping_result(conn_two,
                                                       recheck_delay_ms);
  const IcePingProposal proposal(ping_result, /*reply_expected=*/true);
  interaction_agent->AcceptPingProposal(proposal);
  Recheck();
}

TEST_F(BridgeIceControllerDeathTest, AcceptUnsolicitedSwitchProposal) {
  const IceControllerInterface::SwitchResult switch_result{
      conn.get(), recheck_event, empty_conns_to_forget};
  const IceSwitchProposal proposal(reason, switch_result,
                                   /*reply_expected=*/false);
  EXPECT_DCHECK_DEATH_WITH(interaction_agent->AcceptSwitchProposal(proposal),
                           "unsolicited");
}

TEST_F(BridgeIceControllerDeathTest, RejectUnsolicitedSwitchProposal) {
  const IceControllerInterface::SwitchResult switch_result{
      conn.get(), recheck_event, empty_conns_to_forget};
  const IceSwitchProposal proposal(reason, switch_result,
                                   /*reply_expected=*/false);
  EXPECT_DCHECK_DEATH_WITH(interaction_agent->RejectSwitchProposal(proposal),
                           "unsolicited");
}

TEST_F(BridgeIceControllerDeathTest, AcceptEmptySwitchProposal) {
  const IceControllerInterface::SwitchResult switch_result{
      std::nullopt, recheck_event, empty_conns_to_forget};
  const IceSwitchProposal proposal(reason, switch_result,
                                   /*reply_expected=*/true);
  EXPECT_DCHECK_DEATH_WITH(interaction_agent->AcceptSwitchProposal(proposal),
                           "without a connection");
}

TEST_F(BridgeIceControllerDeathTest, AcceptNullSwitchProposal) {
  const IceControllerInterface::SwitchResult switch_result{
      std::optional<const Connection*>(nullptr), recheck_event,
      empty_conns_to_forget};
  const IceSwitchProposal proposal(reason, switch_result,
                                   /*reply_expected=*/true);
  EXPECT_DCHECK_DEATH_WITH(interaction_agent->AcceptSwitchProposal(proposal),
                           "without a connection");
}

TEST_F(BridgeIceControllerNoopTest, AcceptUnknownSwitchProposal) {
  const IceControllerInterface::SwitchResult switch_result{
      conn_two.get(), recheck_event, empty_conns_to_forget};
  const IceSwitchProposal proposal(reason, switch_result,
                                   /*reply_expected=*/true);
  interaction_agent->AcceptSwitchProposal(proposal);
  Recheck();
}

TEST_F(BridgeIceControllerDeathTest, AcceptUnsolicitedPruneProposal) {
  std::vector<const Connection*> conns_to_prune{conn};
  const IcePruneProposal proposal(conns_to_prune, /*reply_expected=*/false);
  EXPECT_DCHECK_DEATH_WITH(interaction_agent->RejectPruneProposal(proposal),
                           "unsolicited");
}

TEST_F(BridgeIceControllerDeathTest, RejectUnsolicitedPruneProposal) {
  std::vector<const Connection*> conns_to_prune{conn};
  const IcePruneProposal proposal(conns_to_prune, /*reply_expected=*/false);
  EXPECT_DCHECK_DEATH_WITH(interaction_agent->RejectPruneProposal(proposal),
                           "unsolicited");
}

TEST_F(BridgeIceControllerInvalidProposalTest, AcceptUnknownPruneProposal) {
  std::vector<const Connection*> conns_to_prune{conn_two};
  const IcePruneProposal proposal(conns_to_prune, /*reply_expected=*/true);
  EXPECT_CALL(agent, UpdateState);
  EXPECT_CALL(*wrapped_controller, HasPingableConnection);
  interaction_agent->RejectPruneProposal(proposal);
}

TEST_F(BridgeIceControllerTest, HandlesPingRequest) {
  NiceMock<MockIceAgent> agent;
  MockIceControllerObserver observer;
  std::unique_ptr<MockIceController> will_move =
      std::make_unique<MockIceController>(IceControllerFactoryArgs{});
  MockIceController* wrapped = will_move.get();

  scoped_refptr<IceInteractionInterface> interaction_agent = nullptr;
  EXPECT_CALL(observer, OnObserverAttached(_))
      .WillOnce(
          WithArgs<0>([&](auto ia) { interaction_agent = std::move(ia); }));
  BridgeIceController controller(env.GetMainThreadTaskRunner(), &observer,
                                 &agent, std::move(will_move));

  const Connection* conn = GetConnection(kIp, kPort);
  ASSERT_NE(conn, nullptr);
  const Connection* conn_two = GetConnection(kIpTwo, kPort);
  ASSERT_NE(conn_two, nullptr);

  // Exclude conn_two to be able to test for unknown connection in request.
  const std::vector<const Connection*> connection_set{conn};
  EXPECT_CALL(*wrapped, GetConnections())
      .WillRepeatedly(Return(connection_set));

  EXPECT_CALL(agent, SendPingRequest(conn));
  EXPECT_EQ(interaction_agent->PingIceConnection(IceConnection(conn)).type(),
            webrtc::RTCErrorType::NONE);

  EXPECT_CALL(agent, SendPingRequest).Times(0);
  EXPECT_EQ(
      interaction_agent->PingIceConnection(IceConnection(conn_two)).type(),
      webrtc::RTCErrorType::INVALID_PARAMETER);
}

TEST_F(BridgeIceControllerTest, HandlesSwitchRequest) {
  NiceMock<MockIceAgent> agent;
  MockIceControllerObserver observer;
  std::unique_ptr<MockIceController> will_move =
      std::make_unique<MockIceController>(IceControllerFactoryArgs{});
  MockIceController* wrapped = will_move.get();

  scoped_refptr<IceInteractionInterface> interaction_agent = nullptr;
  EXPECT_CALL(observer, OnObserverAttached(_))
      .WillOnce(
          WithArgs<0>([&](auto ia) { interaction_agent = std::move(ia); }));
  BridgeIceController controller(env.GetMainThreadTaskRunner(), &observer,
                                 &agent, std::move(will_move));

  const Connection* conn = GetConnection(kIp, kPort);
  ASSERT_NE(conn, nullptr);
  const Connection* conn_two = GetConnection(kIpTwo, kPort);
  ASSERT_NE(conn_two, nullptr);

  // Exclude conn_two to be able to test for unknown connection in request.
  const std::vector<const Connection*> connection_set{conn};
  EXPECT_CALL(*wrapped, GetConnections())
      .WillRepeatedly(Return(connection_set));

  EXPECT_CALL(agent, SwitchSelectedConnection(
                         conn, IceSwitchReason::APPLICATION_REQUESTED));
  EXPECT_EQ(
      interaction_agent->SwitchToIceConnection(IceConnection(conn)).type(),
      webrtc::RTCErrorType::NONE);

  EXPECT_CALL(agent, SwitchSelectedConnection).Times(0);
  EXPECT_EQ(
      interaction_agent->SwitchToIceConnection(IceConnection(conn_two)).type(),
      webrtc::RTCErrorType::INVALID_PARAMETER);
}

TEST_F(BridgeIceControllerTest, HandlesPruneRequest) {
  NiceMock<MockIceAgent> agent;
  MockIceControllerObserver observer;
  std::unique_ptr<MockIceController> will_move =
      std::make_unique<MockIceController>(IceControllerFactoryArgs{});
  MockIceController* wrapped = will_move.get();

  scoped_refptr<IceInteractionInterface> interaction_agent = nullptr;
  EXPECT_CALL(observer, OnObserverAttached(_))
      .WillOnce(
          WithArgs<0>([&](auto ia) { interaction_agent = std::move(ia); }));
  BridgeIceController controller(env.GetMainThreadTaskRunner(), &observer,
                                 &agent, std::move(will_move));

  const Connection* conn = GetConnection(kIp, kPort);
  ASSERT_NE(conn, nullptr);
  const Connection* conn_two = GetConnection(kIpTwo, kPort);
  ASSERT_NE(conn_two, nullptr);
  const Connection* conn_three = GetConnection(kIpThree, kPort);
  ASSERT_NE(conn_three, nullptr);

  // Exclude conn_three to be able to test for unknown connection in request.
  const std::vector<const Connection*> connection_set{conn, conn_two};
  EXPECT_CALL(*wrapped, GetConnections())
      .WillRepeatedly(Return(connection_set));

  const std::vector<const Connection*> conns_to_prune{conn};
  const std::vector<IceConnection> valid_ice_conns_to_prune{
      IceConnection(conn)};
  const std::vector<const Connection*> partial_conns_to_prune{conn_two};
  const std::vector<IceConnection> mixed_ice_conns_to_prune{
      IceConnection(conn_two), IceConnection(conn_three)};
  const std::vector<IceConnection> invalid_ice_conns_to_prune{
      IceConnection(conn_three)};

  EXPECT_CALL(agent, PruneConnections(ElementsAreArray(conns_to_prune)));
  EXPECT_EQ(
      interaction_agent->PruneIceConnections(valid_ice_conns_to_prune).type(),
      webrtc::RTCErrorType::NONE);

  // Invalid/unknown connections are ignored in a prune request, but the request
  // itself doesn't fail.

  EXPECT_CALL(agent,
              PruneConnections(ElementsAreArray(partial_conns_to_prune)));
  EXPECT_EQ(
      interaction_agent->PruneIceConnections(mixed_ice_conns_to_prune).type(),
      webrtc::RTCErrorType::NONE);

  EXPECT_CALL(agent, PruneConnections).Times(0);
  EXPECT_EQ(
      interaction_agent->PruneIceConnections(invalid_ice_conns_to_prune).type(),
      webrtc::RTCErrorType::NONE);
}

}  // unnamed namespace

"""

```
Response:
Let's break down the thought process to analyze the provided C++ code and generate the response.

1. **Understand the Goal:** The primary goal is to analyze the `QuicSocketDataProvider` class in the provided Chromium networking code. This involves figuring out its purpose, how it works, its relationship to JavaScript (if any), potential issues, and how to reach this code during debugging.

2. **Initial Code Scan (High-Level):**  Quickly read through the code, paying attention to class names, methods, and key data structures. Keywords like `Expectation`, `READ`, `WRITE`, `PAUSE`, `packet`, and the usage of `gtest` hints at a testing or mocking utility.

3. **Identify Core Functionality:** Focus on the methods that define the class's behavior. Methods like `AddRead`, `AddWrite`, `OnRead`, `OnWrite`, `RunUntilPause`, `Resume`, `RunUntilAllConsumed`, and `Reset` are crucial. These suggest the class is used to simulate network socket behavior.

4. **Deconstruct the `Expectation` Class:** This inner class is central. It represents a predefined action (read, write, pause) with associated data (packet, return value). The `After` method hints at the ability to create dependencies between expectations.

5. **Analyze `QuicSocketDataProvider` Methods:**  Go through each significant method:
    * `AddRead/AddWrite/AddPause`:  These methods build up a sequence of expected socket operations. The naming and parameters make their purpose clear.
    * `OnRead/OnWrite`: These are the methods that interact with the simulated socket. They check against the expected sequence of operations. The return types (`MockRead`, `MockWriteResult`) and the use of `ERR_IO_PENDING` suggest asynchronous behavior.
    * `RunUntilPause/Resume/RunUntilAllConsumed`: These control the execution flow of the simulated socket operations, allowing for stepping and waiting.
    * `Reset`: This method seems to prepare the data provider for a new simulation run, setting up dependencies.
    * `MaybeConsumeExpectations`: This is a crucial internal method that drives the simulation forward by processing ready expectations. The use of `PostTask` hints at asynchronous execution.
    * `VerifyWriteData`:  This verifies the data written against the expected data.

6. **Identify Data Structures:**  Pay attention to the main data structures:
    * `expectations_`:  A `std::vector` storing the sequence of expected operations.
    * `dependencies_`: A `std::map` representing the dependencies between expectations.
    * `paused_at_`:  An `std::optional` indicating a pause point in the simulation.
    * `read_pending_/write_pending_`:  Booleans/optionals tracking the state of asynchronous read/write operations.

7. **Infer the Purpose:** Based on the methods and data structures, it becomes clear that `QuicSocketDataProvider` is a *mocking framework* or *test utility* for simulating QUIC socket behavior. It allows developers to define a sequence of expected read and write operations, including errors and pauses, to test QUIC implementations.

8. **JavaScript Relationship (Critical Thinking):**  The code is C++. JavaScript runs in a different context (the browser's rendering engine or Node.js). However, *QUIC is used in web browsers to fetch resources for web pages*. Therefore, while this C++ code isn't directly *in* JavaScript, its behavior *affects* how JavaScript interacts with the network. JavaScript code using `fetch()` or `XMLHttpRequest` might eventually trigger QUIC connections, and this class could be used in testing the underlying QUIC implementation that supports those JavaScript APIs. This requires connecting the low-level network stack with high-level JavaScript APIs.

9. **Logical Reasoning (Input/Output):** Consider a simple scenario:
    * **Input:**  A sequence of `AddRead` and `AddWrite` calls, followed by calls to `OnRead` and `OnWrite`.
    * **Output:** The `OnRead` and `OnWrite` methods will return `MockRead` and `MockWriteResult` objects containing the expected data or error codes defined in the `Expectation` objects. The simulation progresses step-by-step, potentially pausing at defined points.

10. **Common Usage Errors:** Think about how a developer might misuse this class:
    * Defining expectations in the wrong order.
    * Forgetting to define an expected write.
    * Not consuming all expectations in tests.
    * Incorrectly setting up dependencies.

11. **Debugging Scenario:**  Imagine a network issue in a Chromium browser. How could one end up in this code?  The thought process would involve:
    * A user initiates a network request (e.g., clicks a link, types a URL).
    * The browser determines to use QUIC.
    * The QUIC implementation interacts with the socket layer.
    * *If there's a test failing related to QUIC socket behavior*, a developer might be stepping through the `QuicSocketDataProvider` to see if the expected socket interactions are happening correctly. Breakpoints in `OnRead` or `OnWrite` would be logical starting points.

12. **Structure the Response:**  Organize the findings into clear sections: Functionality, JavaScript Relationship, Logical Reasoning, Common Errors, and Debugging. Use clear and concise language. Provide specific examples where possible. Use code snippets where appropriate.

13. **Refine and Review:** Read through the generated response, ensuring accuracy, completeness, and clarity. Check for any logical inconsistencies or missing information. Ensure the language is easy to understand. For example, initially, I might have just said "it's a testing class," but adding the context of QUIC and network stack testing makes it more informative. Similarly, elaborating on the JavaScript connection through network requests makes the link clearer.
好的，让我们来详细分析一下 `net/quic/quic_socket_data_provider.cc` 文件的功能。

**功能概览:**

`QuicSocketDataProvider` 是 Chromium 网络栈中用于**测试** QUIC（Quick UDP Internet Connections）协议实现的工具类。它的主要目的是模拟网络套接字的行为，允许测试代码预先定义一系列的读写操作和预期结果，从而在隔离的环境中验证 QUIC 协议栈的正确性。

更具体地说，`QuicSocketDataProvider` 允许你：

1. **预定义期望的套接字操作序列:** 你可以添加一系列的 "期望 (Expectation)"，每个期望定义了一个预期的读操作、写操作或暂停点。
2. **模拟套接字的读操作:**  通过 `AddRead` 方法，你可以指定在模拟的套接字上读取数据时，应该返回哪些预先定义好的 QUIC 数据包（`quic::QuicEncryptedPacket` 或 `quic::QuicReceivedPacket`），以及可选的 TOS 字节。你也可以使用 `AddReadError` 来模拟读取错误。
3. **模拟套接字的写操作:** 通过 `AddWrite` 方法，你可以指定在模拟的套接字上执行写操作时，测试代码会发送哪些 QUIC 数据包，并设置预期的返回值（通常是 `OK`）。你也可以使用 `AddWriteError` 来模拟写入错误。
4. **控制测试执行流程:** 通过 `AddPause` 方法，你可以在特定的期望点暂停测试执行，以便进行更细致的检查或模拟特定的时序。 `RunUntilPause` 和 `Resume` 方法用于控制暂停和恢复。`RunUntilAllConsumed` 会等待所有预定义的期望都被处理完成。
5. **验证实际的套接字交互:** 当被测试的 QUIC 代码执行读写操作时，`QuicSocketDataProvider` 会检查这些操作是否与预定义的期望相符。对于写操作，它会比较实际写入的数据与期望写入的数据。
6. **处理异步操作:** `OnRead` 和 `OnWrite` 方法用于模拟异步的套接字操作。它们会检查下一个期望，并返回相应的模拟结果（例如 `MockRead` 或 `MockWriteResult`）。
7. **支持依赖关系:** 通过 `Expectation::After` 方法，你可以指定一个期望必须在另一个期望完成后才能被处理，这允许你模拟更复杂的网络交互场景。

**与 JavaScript 的关系:**

虽然 `QuicSocketDataProvider` 本身是用 C++ 编写的，并且直接运行在 Chromium 的网络进程中，但它所测试的 QUIC 协议是支撑现代 Web 应用的重要技术。因此，它与 JavaScript 的功能有着间接但重要的联系。

**举例说明:**

假设一个 JavaScript 应用使用 `fetch()` API 发起一个 HTTP/3 请求（HTTP/3 基于 QUIC）。Chromium 的网络栈会尝试建立一个 QUIC 连接。为了测试这个连接建立和数据传输的过程，可以使用 `QuicSocketDataProvider` 来模拟底层的网络交互。

例如，你可能在测试代码中设置以下期望：

1. **模拟客户端发送初始连接请求:** 使用 `AddWrite` 添加一个包含客户端初始 QUIC 连接信息的 `QuicEncryptedPacket`。
2. **模拟服务器响应:** 使用 `AddRead` 添加一个包含服务器响应的 `QuicEncryptedPacket`，例如 `CONNECTION_ACCEPT` 帧。
3. **模拟客户端发送 HTTP/3 请求:** 使用 `AddWrite` 添加包含 HTTP 请求数据的 `QuicEncryptedPacket`。
4. **模拟服务器返回 HTTP 响应:** 使用 `AddRead` 添加包含 HTTP 响应数据的 `QuicEncryptedPacket`。

当实际的 JavaScript 代码通过 `fetch()` 发起请求时，Chromium 的 QUIC 实现会尝试进行网络交互。`QuicSocketDataProvider` 会拦截这些操作，并根据预定义的期望返回模拟的数据或错误。这样，即使没有真实的服务器，也可以测试 QUIC 连接建立、握手、数据传输等各个环节的正确性。

**逻辑推理 (假设输入与输出):**

**假设输入:**

```c++
QuicSocketDataProvider data_provider(quic::ParsedQuicVersion::Unsupported()); // 使用一个不支持的版本，方便测试错误

// 期望读取操作返回一个错误
data_provider.AddReadError("read_error", net::ERR_CONNECTION_REFUSED);

// 期望写入操作发送一个特定的数据包
std::unique_ptr<quic::QuicEncryptedPacket> write_packet = ...; // 构造一个 QUIC 数据包
data_provider.AddWrite("write_packet", std::move(write_packet), net::OK);
```

**预期输出:**

1. 当被测试的代码调用套接字的读取操作时，`QuicSocketDataProvider::OnRead()` 将会返回一个 `MockRead` 对象，其 `result` 值为 `net::ERR_CONNECTION_REFUSED`。
2. 当被测试的代码调用套接字的写入操作时，`QuicSocketDataProvider::OnWrite()` 将会比较实际写入的数据与 `write_packet` 的内容。如果匹配，则返回一个 `MockWriteResult` 对象，其 `result` 值为 `net::OK`。如果不匹配，测试会失败并输出错误信息。

**用户或编程常见的使用错误:**

1. **期望顺序错误:**  如果预定义的期望顺序与实际代码执行的套接字操作顺序不符，测试将会失败。例如，如果代码先执行写操作，但 `QuicSocketDataProvider` 的第一个期望是读操作，则会出错。

   ```c++
   QuicSocketDataProvider data_provider(...);
   data_provider.AddRead("read_first", ...); // 期望先读
   data_provider.AddWrite("write_second", ...); // 然后写

   // 如果被测试的代码实际先执行写操作，则会出错。
   ```

2. **忘记定义期望:** 如果被测试的代码执行了套接字操作，但在 `QuicSocketDataProvider` 中没有为该操作定义相应的期望，测试也会失败。

   ```c++
   QuicSocketDataProvider data_provider(...);
   // 假设被测试的代码会执行一个写操作，但是这里没有定义期望。
   // 当代码执行写操作时，QuicSocketDataProvider 会报错。
   ```

3. **数据包内容不匹配:** 对于写操作的期望，如果实际写入的数据与期望的数据包内容不一致，测试将会失败。

   ```c++
   QuicSocketDataProvider data_provider(...);
   std::unique_ptr<quic::QuicEncryptedPacket> expected_packet = ...;
   data_provider.AddWrite("write_data", std::move(expected_packet), net::OK);

   // 如果被测试的代码写入了不同的数据，VerifyWriteData 会检测到不匹配。
   ```

4. **未消费所有期望:** 在测试结束时，如果 `QuicSocketDataProvider` 中还有未被消费的期望，通常意味着测试逻辑有误或者模拟的场景不完整。`RunUntilAllConsumed()` 方法可以用来确保所有期望都被处理。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为一个开发人员，当遇到与 QUIC 协议相关的网络问题时，可能会需要调试到 `QuicSocketDataProvider`。以下是一些可能的步骤：

1. **发现 QUIC 连接问题:** 用户可能报告网页加载缓慢、连接中断等问题，这些问题可能与 QUIC 连接有关。
2. **尝试复现问题并开启网络日志:** 开发人员可能会尝试复现用户报告的问题，并开启 Chromium 的网络日志（可以使用 `--log-net-log` 命令行参数）。网络日志会记录详细的网络事件，包括 QUIC 连接的建立、数据传输等信息。
3. **分析网络日志:** 通过分析网络日志，开发人员可能会发现 QUIC 连接的某个阶段出现了异常，例如握手失败、数据包丢失等。
4. **编写或运行 QUIC 相关单元测试:** 为了更深入地诊断问题，开发人员可能会编写或运行针对 QUIC 协议栈的单元测试。这些测试通常会使用 `QuicSocketDataProvider` 来模拟各种网络场景。
5. **设置断点并单步调试:** 在运行单元测试时，开发人员可能会在 `QuicSocketDataProvider` 的关键方法（例如 `OnRead`、`OnWrite`、`ConsumeNextRead`、`ConsumeNextWrite`）中设置断点。
6. **检查期望和实际操作:** 当断点命中时，开发人员可以检查当前的期望列表，查看下一个预期的操作是什么，以及实际的套接字操作是什么。这有助于确定预定义的期望是否正确，以及被测试的代码是否按预期执行。
7. **分析依赖关系和暂停点:** 如果测试中使用了 `After` 来定义依赖关系或使用了 `AddPause` 设置了暂停点，开发人员可以检查这些设置是否正确地模拟了所需的场景。
8. **查看错误信息:** 如果测试失败，`QuicSocketDataProvider` 通常会提供详细的错误信息，例如期望的写数据与实际写数据的差异。这些错误信息可以帮助开发人员快速定位问题。

总而言之，`QuicSocketDataProvider` 是一个强大的测试工具，它允许 Chromium 的开发人员在没有真实网络的情况下，对 QUIC 协议的各个方面进行细致的测试和调试。通过预定义期望和模拟网络行为，它可以帮助发现和修复 QUIC 实现中的潜在问题，从而确保 Chromium 浏览器能够稳定可靠地使用 QUIC 协议进行网络通信。

### 提示词
```
这是目录为net/quic/quic_socket_data_provider.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_socket_data_provider.h"

#include <algorithm>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>

#include "base/functional/callback.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/sequenced_task_runner.h"
#include "net/base/hex_utils.h"
#include "net/socket/socket_test_util.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_packets.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net::test {

QuicSocketDataProvider::Expectation::Expectation(
    std::string name,
    Type type,
    int rv,
    std::unique_ptr<quic::QuicEncryptedPacket> packet)
    : name_(std::move(name)),
      type_(type),
      rv_(rv),
      packet_(std::move(packet)) {}

QuicSocketDataProvider::Expectation::Expectation(
    QuicSocketDataProvider::Expectation&&) = default;

QuicSocketDataProvider::Expectation::~Expectation() = default;

QuicSocketDataProvider::Expectation& QuicSocketDataProvider::Expectation::After(
    std::string name) {
  after_.insert(std::move(name));
  return *this;
}

std::string QuicSocketDataProvider::Expectation::TypeToString(
    QuicSocketDataProvider::Expectation::Type type) {
  switch (type) {
    case Expectation::Type::READ:
      return "READ";
    case Expectation::Type::WRITE:
      return "WRITE";
    case Expectation::Type::PAUSE:
      return "PAUSE";
  }
  NOTREACHED();
}

void QuicSocketDataProvider::Expectation::Consume() {
  CHECK(!consumed_);
  VLOG(1) << "Consuming " << TypeToString(type_) << " expectation " << name_;
  consumed_ = true;
}

QuicSocketDataProvider::QuicSocketDataProvider(quic::ParsedQuicVersion version)
    : printer_(version) {}

QuicSocketDataProvider::~QuicSocketDataProvider() = default;

QuicSocketDataProvider::Expectation& QuicSocketDataProvider::AddRead(
    std::string name,
    std::unique_ptr<quic::QuicEncryptedPacket> packet) {
  expectations_.push_back(Expectation(std::move(name), Expectation::Type::READ,
                                      OK, std::move(packet)));
  return expectations_.back();
}

QuicSocketDataProvider::Expectation& QuicSocketDataProvider::AddRead(
    std::string name,
    std::unique_ptr<quic::QuicReceivedPacket> packet) {
  uint8_t tos_byte = static_cast<uint8_t>(packet->ecn_codepoint());
  return AddRead(std::move(name),
                 static_cast<std::unique_ptr<quic::QuicEncryptedPacket>>(
                     std::move(packet)))
      .TosByte(tos_byte);
}

QuicSocketDataProvider::Expectation& QuicSocketDataProvider::AddReadError(
    std::string name,
    int rv) {
  CHECK_NE(rv, OK);
  CHECK_NE(rv, ERR_IO_PENDING);
  expectations_.push_back(
      Expectation(std::move(name), Expectation::Type::READ, rv, nullptr));
  return expectations_.back();
}

QuicSocketDataProvider::Expectation& QuicSocketDataProvider::AddWrite(
    std::string name,
    std::unique_ptr<quic::QuicEncryptedPacket> packet,
    int rv) {
  expectations_.push_back(Expectation(std::move(name), Expectation::Type::WRITE,
                                      rv, std::move(packet)));
  return expectations_.back();
}

QuicSocketDataProvider::Expectation& QuicSocketDataProvider::AddWriteError(
    std::string name,
    int rv) {
  CHECK_NE(rv, OK);
  CHECK_NE(rv, ERR_IO_PENDING);
  expectations_.push_back(
      Expectation(std::move(name), Expectation::Type::WRITE, rv, nullptr));
  return expectations_.back();
}

QuicSocketDataProvider::PausePoint QuicSocketDataProvider::AddPause(
    std::string name) {
  expectations_.push_back(
      Expectation(std::move(name), Expectation::Type::PAUSE, OK, nullptr));
  return expectations_.size() - 1;
}

bool QuicSocketDataProvider::AllDataConsumed() const {
  return std::all_of(
      expectations_.begin(), expectations_.end(),
      [](const Expectation& expectation) { return expectation.consumed(); });
}

void QuicSocketDataProvider::RunUntilPause(
    QuicSocketDataProvider::PausePoint pause_point) {
  if (!paused_at_.has_value()) {
    run_until_run_loop_ = std::make_unique<base::RunLoop>();
    run_until_run_loop_->Run();
    run_until_run_loop_.reset();
  }
  CHECK(paused_at_.has_value() && *paused_at_ == pause_point)
      << "Did not pause at '" << expectations_[pause_point].name() << "'.";
}

void QuicSocketDataProvider::Resume() {
  CHECK(paused_at_.has_value());
  VLOG(1) << "Resuming from pause point " << expectations_[*paused_at_].name();
  expectations_[*paused_at_].Consume();
  paused_at_ = std::nullopt;
  ExpectationConsumed();
}

void QuicSocketDataProvider::RunUntilAllConsumed() {
  if (!AllDataConsumed()) {
    run_until_run_loop_ = std::make_unique<base::RunLoop>();
    run_until_run_loop_->Run();
    run_until_run_loop_.reset();
  }

  // If that run timed out, then there will still be un-consumed data.
  if (!AllDataConsumed()) {
    std::vector<size_t> unconsumed;
    for (size_t i = 0; i < expectations_.size(); i++) {
      if (!expectations_[i].consumed()) {
        unconsumed.push_back(i);
      }
    }
    FAIL() << "All expectations were not consumed; remaining: "
           << ExpectationList(unconsumed);
  }
}

MockRead QuicSocketDataProvider::OnRead() {
  CHECK(!read_pending_);
  read_pending_ = true;
  std::optional<MockRead> next_read = ConsumeNextRead();
  if (!next_read.has_value()) {
    return MockRead(ASYNC, ERR_IO_PENDING);
  }

  read_pending_ = false;
  return *next_read;
}

MockWriteResult QuicSocketDataProvider::OnWrite(const std::string& data) {
  CHECK(!write_pending_.has_value());
  write_pending_ = data;
  std::optional<MockWriteResult> next_write = ConsumeNextWrite();
  if (!next_write.has_value()) {
    // If Write() was called when no corresponding expectation exists, that's an
    // error unless execution is currently paused, in which case it's just
    // pending. This rarely occurs because the only other type of expectation
    // that might be blocking a WRITE is a READ, and QUIC implementations
    // typically eagerly consume READs.
    if (paused_at_.has_value()) {
      return MockWriteResult(ASYNC, ERR_IO_PENDING);
    } else {
      ADD_FAILURE() << "Write call when none is expected:\n"
                    << printer_.PrintWrite(data);
      return MockWriteResult(SYNCHRONOUS, ERR_UNEXPECTED);
    }
  }

  write_pending_ = std::nullopt;
  return *next_write;
}

bool QuicSocketDataProvider::AllReadDataConsumed() const {
  return AllDataConsumed();
}

bool QuicSocketDataProvider::AllWriteDataConsumed() const {
  return AllDataConsumed();
}

void QuicSocketDataProvider::CancelPendingRead() {
  read_pending_ = false;
}

void QuicSocketDataProvider::Reset() {
  // Note that `Reset` is a parent-class method with a confusing name. It is
  // used to initialize the socket data provider before it is used.

  // Map names to index, and incidentally check for duplicate names.
  std::map<std::string, size_t> names;
  for (size_t i = 0; i < expectations_.size(); i++) {
    Expectation& expectation = expectations_[i];
    auto [_, inserted] = names.insert({expectation.name(), i});
    CHECK(inserted) << "Another expectation named " << expectation.name()
                    << " exists.";
  }

  // Calculate `dependencies_` mapping indices in `expectations_` to indices of
  // the expectations they depend on.
  dependencies_.clear();
  for (size_t i = 0; i < expectations_.size(); i++) {
    Expectation& expectation = expectations_[i];
    if (expectation.after().empty()) {
      // If no other dependencies are given, make the expectation depend on the
      // previous expectation.
      if (i > 0) {
        dependencies_[i].insert(i - 1);
      }
    } else {
      for (auto& after : expectation.after()) {
        const auto dep = names.find(after);
        CHECK(dep != names.end()) << "No expectation named " << after;
        dependencies_[i].insert(dep->second);
      }
    }
  }

  pending_maybe_consume_expectations_ = false;
  read_pending_ = false;
  write_pending_ = std::nullopt;
  MaybeConsumeExpectations();
}

std::optional<size_t> QuicSocketDataProvider::FindReadyExpectations(
    Expectation::Type type) {
  std::vector<size_t> matches;
  for (size_t i = 0; i < expectations_.size(); i++) {
    const Expectation& expectation = expectations_[i];
    if (expectation.consumed() || expectation.type() != type) {
      continue;
    }
    bool found_unconsumed = false;
    for (auto dep : dependencies_[i]) {
      if (!expectations_[dep].consumed_) {
        found_unconsumed = true;
        break;
      }
    }
    if (!found_unconsumed) {
      matches.push_back(i);
    }
  }

  if (matches.size() > 1) {
    std::string exp_type = Expectation::TypeToString(type);
    std::string names = ExpectationList(matches);
    CHECK(matches.size() <= 1)
        << "Multiple expectations of type " << exp_type
        << " are ready: " << names << ". Use .After() to disambiguate.";
  }

  return matches.empty() ? std::nullopt : std::make_optional(matches[0]);
}

std::optional<MockRead> QuicSocketDataProvider::ConsumeNextRead() {
  CHECK(read_pending_);
  std::optional<size_t> ready = FindReadyExpectations(Expectation::Type::READ);
  if (!ready.has_value()) {
    return std::nullopt;
  }

  // If there's exactly one matching expectation, return it.
  Expectation& ready_expectation = expectations_[*ready];
  MockRead read(ready_expectation.mode(), ready_expectation.rv());
  if (ready_expectation.packet()) {
    read.data = ready_expectation.packet()->data();
    read.data_len = ready_expectation.packet()->length();
  }
  read.tos = ready_expectation.tos_byte();
  ready_expectation.Consume();
  ExpectationConsumed();
  return read;
}

std::optional<MockWriteResult> QuicSocketDataProvider::ConsumeNextWrite() {
  CHECK(write_pending_.has_value());
  std::optional<size_t> ready = FindReadyExpectations(Expectation::Type::WRITE);
  if (!ready.has_value()) {
    return std::nullopt;
  }

  // If there's exactly one matching expectation, check if it matches the write
  // and return it.
  Expectation& ready_expectation = expectations_[*ready];
  if (ready_expectation.packet()) {
    if (!VerifyWriteData(ready_expectation)) {
      return MockWriteResult(SYNCHRONOUS, ERR_UNEXPECTED);
    }
  }
  MockWriteResult write(ready_expectation.mode(),
                        ready_expectation.packet()
                            ? ready_expectation.packet()->length()
                            : ready_expectation.rv());
  ready_expectation.Consume();
  ExpectationConsumed();
  return write;
}

void QuicSocketDataProvider::MaybeConsumeExpectations() {
  pending_maybe_consume_expectations_ = false;
  if (read_pending_) {
    std::optional<MockRead> next_read = ConsumeNextRead();
    if (next_read.has_value()) {
      read_pending_ = false;
      if (socket()) {
        socket()->OnReadComplete(*next_read);
      }
    }
  }

  if (write_pending_.has_value()) {
    std::optional<MockWriteResult> next_write = ConsumeNextWrite();
    if (next_write.has_value()) {
      write_pending_ = std::nullopt;
      if (socket()) {
        socket()->OnWriteComplete(next_write->result);
      }
    }
  }

  if (!paused_at_) {
    std::optional<size_t> ready =
        FindReadyExpectations(Expectation::Type::PAUSE);
    if (ready.has_value()) {
      VLOG(1) << "Pausing at " << expectations_[*ready].name();
      paused_at_ = *ready;
      if (run_until_run_loop_) {
        run_until_run_loop_->Quit();
      }
    }
  }

  if (run_until_run_loop_ && AllDataConsumed()) {
    run_until_run_loop_->Quit();
  }
}

void QuicSocketDataProvider::ExpectationConsumed() {
  if (pending_maybe_consume_expectations_) {
    return;
  }
  pending_maybe_consume_expectations_ = true;

  // Call `MaybeConsumeExpectations` in a task. That method may trigger
  // consumption of other expectations, and that consumption must happen _after_
  // the current call to `Read` or `Write` has finished.
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&QuicSocketDataProvider::MaybeConsumeExpectations,
                     weak_factory_.GetWeakPtr()));
}

bool QuicSocketDataProvider::VerifyWriteData(
    QuicSocketDataProvider::Expectation& expectation) {
  std::string expected_data(expectation.packet()->data(),
                            expectation.packet()->length());
  std::string& actual_data = *write_pending_;
  bool write_matches = actual_data == expected_data;
  EXPECT_TRUE(write_matches)
      << "Expectation '" << expectation.name()
      << "' not met. Actual formatted write data:\n"
      << printer_.PrintWrite(actual_data) << "But expectation '"
      << expectation.name() << "' expected formatted write data:\n"
      << printer_.PrintWrite(expected_data) << "Actual raw write data:\n"
      << HexDump(actual_data) << "Expected raw write data:\n"
      << HexDump(expected_data);
  return write_matches;
}

std::string QuicSocketDataProvider::ExpectationList(
    const std::vector<size_t>& indices) {
  std::ostringstream names;
  bool first = true;
  for (auto i : indices) {
    names << (first ? "" : ", ") << expectations_[i].name();
    first = false;
  }
  return names.str();
}

}  // namespace net::test
```
Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Subject:** The filename `session_store_impl_unittest.cc` and the included header `session_store_impl.h` immediately tell us this file is testing the `SessionStoreImpl` class. This class is part of the `net::device_bound_sessions` namespace, suggesting it deals with network sessions specifically tied to a device.

2. **Understand the Purpose of Unittests:** Unittests are designed to isolate and verify the behavior of individual units of code (in this case, the `SessionStoreImpl` class). They do this by setting up specific scenarios (inputs), calling methods of the class under test, and then asserting that the outputs and side effects match the expected behavior.

3. **Analyze the Includes:** The included headers provide clues about the dependencies and functionalities being tested:
    * Standard C++ libraries (`memory`, `vector`, etc.):  Basic data structures and memory management.
    * `base/files/...`:  File system operations, indicating the `SessionStoreImpl` likely interacts with persistent storage.
    * `base/test/...`:  Testing utilities provided by the Chromium base library.
    * `components/unexportable_keys/...`:  Interaction with a service for managing cryptographic keys that cannot be exported. This is a *key* aspect of the `SessionStoreImpl`'s functionality.
    * `crypto/...`: Cryptographic primitives.
    * `net/base/...`:  Networking base classes like `SchemefulSite` and `GURL`.
    * `net/device_bound_sessions/proto/storage.pb.h`: Protocol Buffer definitions for storing session data, confirming the persistence mechanism.
    * `net/dns/public/secure_dns_mode.h`:  Potentially related to how DNS settings interact with device-bound sessions (though not directly used in most tests).
    * `testing/gtest/...`: The Google Test framework for writing assertions.

4. **Examine Helper Functions:** The anonymous namespace contains several helper functions. These are crucial for understanding the test setup and common operations:
    * `GenerateNewKey`, `GetWrappedKey`:  Interact with the `UnexportableKeyService`, indicating the core functionality revolves around managing encrypted session keys.
    * `SessionMapsAreEqual`: A comparison function for session maps, essential for verifying test results.
    * `CreateSessionHelper`, `CreateSessionProto`:  Create `Session` objects and their corresponding protobuf representations.
    * `CreateAndSaveSessions`:  A utility to create and save multiple sessions for testing bulk operations.

5. **Study the Test Fixture (`SessionStoreImplTest`):**  This sets up the testing environment:
    * `TaskEnvironment`:  Provides a controlled environment for asynchronous operations.
    * `ScopedTempDir`: Creates a temporary directory for the database, ensuring tests don't interfere with real data.
    * `ScopedMockUnexportableKeyProvider`, `UnexportableKeyTaskManager`, `UnexportableKeyServiceImpl`:  Mock or real implementations of the unexportable key service, allowing tests to control key generation and retrieval.
    * `CreateStore`, `DeleteStore`, `MimicRestart`, `LoadSessions`, `CreateStoreAndLoadSessions`, `RestoreSessionBindingKey`: Methods for managing the lifecycle of the `SessionStoreImpl` and loading/reloading session data, simulating real-world scenarios.

6. **Analyze Individual Test Cases:** Each `TEST_F` function focuses on a specific aspect of `SessionStoreImpl`'s behavior:
    * **Error Handling:** `FailDBLoadFromInvalidPath` tests how the store handles invalid database paths.
    * **Initialization:** `InitializeStore` verifies basic store creation and loading.
    * **Dependency on Initialization:** `RequireDBInit` checks that saving/deleting sessions doesn't work before the database is properly initialized.
    * **Key Handling:** `RequireValidBindingKeyForSave` ensures sessions have valid unexportable keys before saving.
    * **Basic CRUD Operations:** `SaveNewSessions`, `UpdateExistingSession`, `DeleteSessions` test the core functionality of creating, updating, and deleting sessions.
    * **Handling Non-Existent Data:** `HandleNonexistingSite`, `HandleNonexistingSession` verify how the store deals with attempts to modify or retrieve non-existent sessions.
    * **Persistence:** `LoadSavedSessions` checks that sessions are correctly saved and loaded after a restart.
    * **Data Integrity and Pruning:** `PruneLoadedEntryWithInvalidSite`, `PruneLoadedEntryWithInvalidSession`, `PruneLoadedEntryWithSessionMissingWrappedKey` test the store's ability to handle and discard corrupted or invalid data during loading.

7. **Identify Relationships with JavaScript (if any):** This code is part of the Chromium network stack, which directly interacts with the browser's core functionality. While this specific C++ code doesn't directly execute JavaScript, it plays a crucial role in features that *are* exposed to JavaScript. The key connection is through web APIs that manage sessions and potentially device-bound credentials.

8. **Formulate Examples and Debugging Clues:** Based on the understanding of the code, provide concrete examples of how user actions might lead to this code being executed and common errors that developers might make.

9. **Review and Refine:**  Go through the analysis, ensuring clarity, accuracy, and completeness. Check for any missed details or areas that could be explained better. For instance, explicitly connecting the `UnexportableKeyService` to the need for secure, device-bound credentials.

This systematic approach, starting with the high-level purpose and gradually drilling down into the details of the code, allows for a comprehensive understanding of the functionality and its context within the larger Chromium project.
这个文件 `net/device_bound_sessions/session_store_impl_unittest.cc` 是 Chromium 网络栈中 `device_bound_sessions` 组件的单元测试文件。它主要用于测试 `SessionStoreImpl` 类的功能。`SessionStoreImpl` 负责在本地持久化存储设备绑定的会话信息。

**功能列举:**

1. **创建和删除数据库:** 测试 `SessionStoreImpl` 能否成功创建和删除用于存储会话数据的 SQLite 数据库文件。
2. **保存新的会话:** 测试 `SaveSession` 方法能否正确地将新的会话信息保存到数据库中。这包括会话的 ID、关联的站点、以及绑定的不可导出密钥的 ID (wrapped key)。
3. **更新现有会话:** 测试 `SaveSession` 方法能否正确地更新数据库中已存在的会话信息，例如更新会话的过期时间。
4. **加载已保存的会话:** 测试 `LoadSessions` 方法能否从数据库中正确加载之前保存的会话信息。
5. **删除会话:** 测试 `DeleteSession` 方法能否从数据库中删除指定的会话信息。
6. **处理不存在的站点或会话:** 测试当尝试删除或恢复不存在的站点或会话时，`SessionStoreImpl` 的行为是否正确。
7. **处理无效的数据库路径:** 测试当提供的数据库路径无效时，`SessionStoreImpl` 是否能正确处理并报告错误。
8. **依赖数据库初始化:** 测试在数据库未初始化的情况下，`SaveSession` 等操作是否会被忽略。
9. **要求有效的绑定密钥:** 测试在保存会话时，是否要求会话关联有效的不可导出密钥。
10. **在重启后加载会话:** 测试在模拟重启浏览器后，`SessionStoreImpl` 是否能成功加载之前保存的会话。
11. **清理加载的数据:** 测试在加载数据时，`SessionStoreImpl` 能否识别并清理无效的会话条目，例如关联了无效站点或者会话本身无效的条目。
12. **恢复会话绑定密钥:** 测试 `RestoreSessionBindingKey` 方法能否根据会话 ID 从数据库中恢复绑定的不可导出密钥 ID。

**与 JavaScript 的关系 (间接):**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所测试的功能与 Web API 有着间接的关系，这些 Web API 可能被 JavaScript 代码调用。

* **假设场景:** 考虑一个网站想要创建一个与用户设备绑定的会话，以便在用户下次访问时可以无需重新身份验证。这个网站可能会使用浏览器提供的 Web API (例如，未来可能出现的 Device Bound Sessions API 或相关扩展) 来请求创建这样的会话。
* **执行流程:**
    1. JavaScript 代码调用相应的 Web API。
    2. 浏览器内部的网络栈处理这个请求。
    3. `SessionStoreImpl` 类会被用来持久化这个设备绑定的会话信息，包括加密的密钥信息。
    4. 当用户下次访问该网站时，JavaScript 代码再次调用 Web API。
    5. 浏览器会使用 `SessionStoreImpl` 加载之前保存的会话信息。
    6. 浏览器可以使用加载的密钥信息进行身份验证，而无需用户再次输入用户名和密码。

**举例说明:**

假设未来有一个名为 `navigator.deviceBoundSession.create()` 的 JavaScript API 可以用来创建设备绑定的会话。

```javascript
// JavaScript 代码
navigator.deviceBoundSession.create({
  url: 'https://example.com',
  sessionId: 'uniqueSessionId123'
}).then(() => {
  console.log('Device-bound session created!');
});
```

当这个 JavaScript 代码执行时，浏览器底层的网络栈会与 `SessionStoreImpl` 进行交互，将这个会话的信息（包括一个与设备硬件绑定的密钥的引用）存储到本地数据库中。  `session_store_impl_unittest.cc` 中的测试就是为了确保 `SessionStoreImpl` 在这个过程中能够正确地执行保存操作。

**逻辑推理 (假设输入与输出):**

**测试用例:** `TEST_F(SessionStoreImplTest, SaveNewSessions)`

**假设输入:**

* `cfgs`: 一个包含多个会话配置的列表，每个配置包含 URL 和会话 ID。例如:
  ```c++
  SessionCfgList cfgs = {
      {"https://a.foo.test/index.html", "session0"},
      {"https://b.foo.test/index.html", "session1"},
  };
  ```
* `unexportable_key_service()`: 一个用于生成和管理不可导出密钥的服务实例。
* `store()`: 一个 `SessionStoreImpl` 实例。

**预期输出:**

* 调用 `CreateAndSaveSessions` 后，`store()` 的数据库中应该包含对应于 `cfgs` 中所有会话的条目。
* `store().GetAllSessions()` 返回的 `SessionStore::SessionsMap` 应该包含与 `cfgs` 中定义的会话信息相匹配的 `Session` 对象，并且每个会话对象都关联了一个通过 `unexportable_key_service()` 生成的不可导出密钥 ID。
* `SessionMapsAreEqual(expected_sessions, store_sessions)` 应该返回 `true`。

**用户或编程常见的使用错误:**

1. **在数据库未初始化前尝试保存或加载会话:**  开发者可能会在 `SessionStoreImpl` 初始化完成之前就尝试调用 `SaveSession` 或 `LoadSessions`。`TEST_F(SessionStoreImplTest, RequireDBInit)` 就是为了测试这种情况，并确保 `SessionStoreImpl` 能正确处理，避免崩溃或数据损坏。
2. **保存没有有效绑定密钥的会话:**  如果开发者在创建会话时没有为其分配一个有效的不可导出密钥 ID，那么尝试保存这个会话可能会失败或导致未预期的行为。`TEST_F(SessionStoreImplTest, RequireValidBindingKeyForSave)` 测试了这种情况。
3. **使用错误的数据库路径:**  如果提供给 `SessionStoreImpl` 的数据库路径是无效的或者没有权限写入，可能会导致数据库创建或加载失败。`TEST_F(SessionStoreImplTest, FailDBLoadFromInvalidPath)` 测试了这种情况。
4. **忘记处理异步操作:** `LoadSessions` 等操作是异步的，开发者需要正确处理完成回调，才能获取加载的会话数据。在测试代码中，`base::RunLoop` 被用来等待异步操作完成。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在浏览一个支持设备绑定会话的网站：

1. **用户访问网站:** 用户在 Chrome 浏览器中输入网站地址并访问。
2. **网站请求创建设备绑定会话:** 网站的 JavaScript 代码调用浏览器提供的相关 API (假设存在)，请求创建一个与用户设备绑定的会话。
3. **浏览器处理请求:** Chrome 浏览器的网络栈接收到这个请求。
4. **创建会话对象:**  网络栈内部会创建一个 `Session` 对象，并可能调用 `unexportable_keys` 组件生成一个与设备硬件绑定的不可导出密钥。
5. **保存会话信息:**  `SessionStoreImpl` 的 `SaveSession` 方法会被调用，将这个 `Session` 对象的信息（包括加密的密钥信息）保存到本地数据库中。 这时就会触发 `session_store_impl_unittest.cc` 中测试的保存逻辑。
6. **用户关闭浏览器或离开网站:** 用户可能关闭了浏览器标签页或完全关闭了 Chrome 浏览器。
7. **用户再次访问网站:** 用户再次打开 Chrome 浏览器并访问相同的网站。
8. **浏览器尝试恢复会话:**  浏览器在启动时或在访问网站时，可能会调用 `SessionStoreImpl` 的 `LoadSessions` 方法，尝试加载之前保存的设备绑定会话信息。 这时就会触发 `session_store_impl_unittest.cc` 中测试的加载逻辑。
9. **恢复密钥:**  `SessionStoreImpl` 可能会调用 `RestoreSessionBindingKey` 来尝试恢复与加载的会话关联的不可导出密钥。

**作为调试线索:**

* 如果用户遇到与设备绑定会话相关的问题 (例如，会话没有正确保存或恢复)，开发者可以检查 `SessionStoreImpl` 的日志，查看是否成功调用了 `SaveSession` 和 `LoadSessions` 方法。
* 可以检查数据库文件是否存在，以及其内容是否符合预期。
* 可以使用调试器单步执行 `SessionStoreImpl` 的代码，查看在保存和加载会话时发生的具体操作。
* `session_store_impl_unittest.cc` 中的测试用例可以帮助开发者验证 `SessionStoreImpl` 的基本功能是否正常，从而缩小问题范围。如果某个测试用例失败，就可能表明 `SessionStoreImpl` 的某个核心功能存在 bug。

总而言之，`session_store_impl_unittest.cc` 是确保 Chromium 网络栈中设备绑定会话持久化功能正确性的关键部分。它通过一系列单元测试，覆盖了 `SessionStoreImpl` 类的各种使用场景和边界情况，帮助开发者发现和修复潜在的 bug，从而保证用户在使用相关功能时的稳定性和可靠性。

### 提示词
```
这是目录为net/device_bound_sessions/session_store_impl_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/device_bound_sessions/session_store_impl.h"

#include <memory>

#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/strings/string_util_internal.h"
#include "base/test/bind.h"
#include "base/test/task_environment.h"
#include "base/test/test_future.h"
#include "base/types/expected.h"
#include "components/unexportable_keys/unexportable_key_service.h"
#include "components/unexportable_keys/unexportable_key_service_impl.h"
#include "components/unexportable_keys/unexportable_key_task_manager.h"
#include "crypto/scoped_mock_unexportable_key_provider.h"
#include "crypto/unexportable_key.h"
#include "net/base/schemeful_site.h"
#include "net/device_bound_sessions/proto/storage.pb.h"
#include "net/dns/public/secure_dns_mode.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net::device_bound_sessions {

namespace {

constexpr crypto::SignatureVerifier::SignatureAlgorithm
    kAcceptableAlgorithms[] = {crypto::SignatureVerifier::ECDSA_SHA256};
constexpr unexportable_keys::BackgroundTaskPriority kTaskPriority =
    unexportable_keys::BackgroundTaskPriority::kUserBlocking;

unexportable_keys::UnexportableKeyId GenerateNewKey(
    unexportable_keys::UnexportableKeyService& key_service) {
  base::test::TestFuture<
      unexportable_keys::ServiceErrorOr<unexportable_keys::UnexportableKeyId>>
      generate_future;
  key_service.GenerateSigningKeySlowlyAsync(
      kAcceptableAlgorithms, kTaskPriority, generate_future.GetCallback());
  unexportable_keys::ServiceErrorOr<unexportable_keys::UnexportableKeyId>
      key_id = generate_future.Get();
  CHECK(key_id.has_value());
  return *key_id;
}

std::vector<uint8_t> GetWrappedKey(
    unexportable_keys::UnexportableKeyService& key_service,
    const unexportable_keys::UnexportableKeyId& key_id) {
  unexportable_keys::ServiceErrorOr<std::vector<uint8_t>> wrapped_key =
      key_service.GetWrappedKey(key_id);
  CHECK(wrapped_key.has_value());
  return *wrapped_key;
}

bool SessionMapsAreEqual(const SessionStore::SessionsMap& lhs,
                         const SessionStore::SessionsMap& rhs) {
  return base::ranges::is_permutation(
      lhs, rhs, [&](const auto& pair1, const auto& pair2) {
        return pair1.first == pair2.first &&
               pair1.second->IsEqualForTesting(*pair2.second);
      });
}

std::unique_ptr<Session> CreateSessionHelper(
    unexportable_keys::UnexportableKeyService& key_service,
    const std::string& url_string,
    const std::string& session_id) {
  SessionParams::Scope scope;
  std::string cookie_attr = "Secure; Domain=" + GURL(url_string).host();
  std::vector<SessionParams::Credential> cookie_credentials(
      {SessionParams::Credential{"test_cookie", cookie_attr}});
  SessionParams params{session_id, url_string, std::move(scope),
                       std::move(cookie_credentials)};
  std::unique_ptr<Session> session =
      Session::CreateIfValid(params, GURL(url_string));
  session->set_unexportable_key_id(GenerateNewKey(key_service));
  return session;
}

proto::Session CreateSessionProto(
    unexportable_keys::UnexportableKeyService& key_service,
    const std::string& url_string,
    const std::string& session_id) {
  std::unique_ptr<Session> session =
      CreateSessionHelper(key_service, url_string, session_id);
  proto::Session sproto = session->ToProto();
  unexportable_keys::UnexportableKeyId key_id =
      session->unexportable_key_id().value();
  std::vector<uint8_t> wrapped_key = GetWrappedKey(key_service, key_id);
  sproto.set_wrapped_key(std::string(wrapped_key.begin(), wrapped_key.end()));
  return sproto;
}

struct SessionCfg {
  std::string url;
  std::string session_id;
};
using SessionCfgList = std::vector<SessionCfg>;
SessionStore::SessionsMap CreateAndSaveSessions(
    const SessionCfgList& cfgs,
    unexportable_keys::UnexportableKeyService& key_service,
    SessionStore& store) {
  SessionStore::SessionsMap session_map;
  for (auto& cfg : cfgs) {
    auto site = net::SchemefulSite(GURL(cfg.url));
    std::unique_ptr<Session> session =
        CreateSessionHelper(key_service, cfg.url, cfg.session_id);
    EXPECT_TRUE(session);
    store.SaveSession(site, *session);
    session_map.emplace(std::move(site), std::move(session));
  }

  return session_map;
}

}  // namespace

class SessionStoreImplTest : public testing::Test {
 public:
  SessionStoreImplTest()
      : unexportable_key_service_(unexportable_key_task_manager_) {
    EXPECT_TRUE(temp_dir_.CreateUniqueTempDir());
  }

  ~SessionStoreImplTest() override = default;

  void TearDown() override {
    if (store_) {
      DeleteStore();
    }
  }

  SessionStoreImpl& store() { return *store_; }

  unexportable_keys::UnexportableKeyService& unexportable_key_service() {
    return unexportable_key_service_;
  }

  base::FilePath GetDBPath() const {
    return temp_dir_.GetPath().Append(
        base::FilePath(FILE_PATH_LITERAL("db_file")));
  }

  void CreateStore(base::FilePath db_path) {
    store_ =
        std::make_unique<SessionStoreImpl>(db_path, unexportable_key_service_);
  }

  void DeleteStore() {
    base::RunLoop run_loop;
    store_->SetShutdownCallbackForTesting(run_loop.QuitClosure());
    store_ = nullptr;
    run_loop.Run();
  }

  void MimicRestart() {
    DeleteStore();
    CreateStore(GetDBPath());
  }

  SessionStore::SessionsMap LoadSessions() {
    base::RunLoop run_loop;
    SessionStore::SessionsMap loaded_sessions;
    store_->LoadSessions(base::BindLambdaForTesting(
        [&run_loop, &loaded_sessions](SessionStore::SessionsMap sessions) {
          loaded_sessions = std::move(sessions);
          run_loop.Quit();
        }));
    run_loop.Run();
    return loaded_sessions;
  }

  void CreateStoreAndLoadSessions() {
    CreateStore(GetDBPath());
    SessionStore::SessionsMap sessions = LoadSessions();
    EXPECT_TRUE(store().db_status() == SessionStoreImpl::DBStatus::kSuccess);
    EXPECT_EQ(sessions.size(), 0u);
  }

  void RestoreSessionBindingKey(const SchemefulSite& site, Session* session) {
    base::RunLoop run_loop;
    store_->RestoreSessionBindingKey(
        site, session->id(),
        base::BindLambdaForTesting(
            [&run_loop,
             &session](unexportable_keys::ServiceErrorOr<
                       unexportable_keys::UnexportableKeyId> key_id_or_error) {
              session->set_unexportable_key_id(key_id_or_error);
              run_loop.Quit();
            }));
    run_loop.Run();
  }

 private:
  base::test::TaskEnvironment task_environment_;
  base::ScopedTempDir temp_dir_;
  crypto::ScopedMockUnexportableKeyProvider scoped_key_provider_;
  unexportable_keys::UnexportableKeyTaskManager unexportable_key_task_manager_{
      crypto::UnexportableKeyProvider::Config()};
  unexportable_keys::UnexportableKeyServiceImpl unexportable_key_service_;
  std::unique_ptr<SessionStoreImpl> store_;
};

TEST_F(SessionStoreImplTest, FailDBLoadFromInvalidPath) {
  base::FilePath invalid_path(FILE_PATH_LITERAL("o://inaccessible-path"));
  CreateStore(invalid_path);
  LoadSessions();
  EXPECT_FALSE(store().db_status() == SessionStoreImpl::DBStatus::kSuccess);
}

TEST_F(SessionStoreImplTest, InitializeStore) {
  CreateStoreAndLoadSessions();
}

TEST_F(SessionStoreImplTest, RequireDBInit) {
  // Create a store but don't initialize DB with an initial load.
  CreateStore(GetDBPath());
  EXPECT_TRUE(store().db_status() != SessionStoreImpl::DBStatus::kSuccess);

  // Verify that save session call is ignored.
  std::unique_ptr<Session> session = CreateSessionHelper(
      unexportable_key_service(), "https://foo.test", "session1");
  auto site = net::SchemefulSite(GURL("https://foo.test"));
  store().SaveSession(site, *session);
  EXPECT_EQ(store().GetAllSessions().size(), 0u);

  // Verify that delete session call is ignored.
  store().DeleteSession(site, session->id());
  EXPECT_EQ(store().GetAllSessions().size(), 0u);

  // Verify that restore session binding key call fails.
  RestoreSessionBindingKey(site, session.get());
  EXPECT_TRUE(session->unexportable_key_id() ==
              base::unexpected(unexportable_keys::ServiceError::kKeyNotFound));
}

TEST_F(SessionStoreImplTest, RequireValidBindingKeyForSave) {
  CreateStoreAndLoadSessions();
  std::unique_ptr<Session> session = CreateSessionHelper(
      unexportable_key_service(), "https://foo.test", "session1");
  session->set_unexportable_key_id(unexportable_keys::UnexportableKeyId());
  store().SaveSession(net::SchemefulSite(GURL("https://foo.test")), *session);
  EXPECT_EQ(store().GetAllSessions().size(), 0u);
}

TEST_F(SessionStoreImplTest, SaveNewSessions) {
  CreateStoreAndLoadSessions();
  SessionCfgList cfgs = {
      {"https://a.foo.test/index.html", "session0"},  // schemeful site 1
      {"https://b.foo.test/index.html", "session1"},  // ""
      {"https://c.bar.test/index.html", "session2"},  // schemeful site 2
  };
  SessionStore::SessionsMap expected_sessions =
      CreateAndSaveSessions(cfgs, unexportable_key_service(), store());

  // Retrieve all sessions from the store.
  SessionStore::SessionsMap store_sessions = store().GetAllSessions();

  // Restore the binding keys in the store session objects.
  for (auto& [site, session] : store_sessions) {
    RestoreSessionBindingKey(site, session.get());
  }

  // Verify the session store contents.
  EXPECT_TRUE(SessionMapsAreEqual(expected_sessions, store_sessions));
}

TEST_F(SessionStoreImplTest, UpdateExistingSession) {
  CreateStoreAndLoadSessions();

  // Save a new session.
  std::unique_ptr<Session> session = CreateSessionHelper(
      unexportable_key_service(), "https://foo.test", "session1");
  auto site = net::SchemefulSite(GURL("https://foo.test"));
  store().SaveSession(site, *session);
  EXPECT_EQ(store().GetAllSessions().size(), 1u);

  // Modify the existing session and save it again to the store. The
  // save will fail if time advances past the expiry date, so use a 10
  // second margin of safety. This is arbitrary, as long as it's longer
  // than it takes to save a session.
  session->set_expiry_date(base::Time::Now() + base::Seconds(10));
  store().SaveSession(site, *session);

  // Retrieve the session from the store and check that its contents
  // match the updated data.
  SessionStore::SessionsMap store_sessions = store().GetAllSessions();
  EXPECT_EQ(store_sessions.size(), 1u);
  for (auto& [store_site, store_session] : store_sessions) {
    EXPECT_TRUE(store_site == site);
    EXPECT_TRUE(store_session->expiry_date() == session->expiry_date());
    RestoreSessionBindingKey(store_site, store_session.get());
    EXPECT_TRUE(store_session->IsEqualForTesting(*session));
  }
}

TEST_F(SessionStoreImplTest, HandleNonexistingSite) {
  CreateStoreAndLoadSessions();

  // Try to delete a session associated with a nonexisting site (in the store).
  auto site = net::SchemefulSite(GURL("https://foo.test"));
  store().DeleteSession(site, Session::Id("session"));
  EXPECT_EQ(store().GetAllSessions().size(), 0u);

  // Create a session but don't save it to the store.
  std::unique_ptr<Session> session = CreateSessionHelper(
      unexportable_key_service(), "https://foo.test", "session");
  // Try to restore that session's binding key. Note that the store doesn't have
  // an entry for the associated site.
  RestoreSessionBindingKey(site, session.get());
  EXPECT_EQ(store().GetAllSessions().size(), 0u);
  EXPECT_TRUE(session->unexportable_key_id() ==
              base::unexpected(unexportable_keys::ServiceError::kKeyNotFound));
}

TEST_F(SessionStoreImplTest, HandleNonexistingSession) {
  CreateStoreAndLoadSessions();

  // Save a session.
  std::unique_ptr<Session> session = CreateSessionHelper(
      unexportable_key_service(), "https://foo.test", "session1");
  auto site = net::SchemefulSite(GURL("https://foo.test"));
  store().SaveSession(site, *session);
  EXPECT_EQ(store().GetAllSessions().size(), 1u);

  // Create another but don't save it to the store.
  std::unique_ptr<Session> session2 = CreateSessionHelper(
      unexportable_key_service(), "https://foo.test", "session2");

  // Try to delete the unsaved session.
  store().DeleteSession(site, session2->id());
  EXPECT_EQ(store().GetAllSessions().size(), 1u);

  // Try to restore the unsaved session's binding key.
  RestoreSessionBindingKey(site, session2.get());
  EXPECT_EQ(store().GetAllSessions().size(), 1u);
  EXPECT_TRUE(session2->unexportable_key_id() ==
              base::unexpected(unexportable_keys::ServiceError::kKeyNotFound));
}

TEST_F(SessionStoreImplTest, DeleteSessions) {
  CreateStoreAndLoadSessions();

  // Create and save some sessions.
  SessionCfgList cfgs = {
      {"https://a.foo.test/index.html", "session0"},  // schemeful site 1
      {"https://b.foo.test/index.html", "session1"},  // ""
      {"https://c.bar.test/index.html", "session2"},  // schemeful site 2
  };
  SessionStore::SessionsMap expected_sessions =
      CreateAndSaveSessions(cfgs, unexportable_key_service(), store());

  auto site1 = net::SchemefulSite(GURL(cfgs[0].url));
  auto site2 = net::SchemefulSite(GURL(cfgs[2].url));

  // Retrieve all sessions from the store.
  SessionStore::SessionsMap store_sessions = store().GetAllSessions();
  EXPECT_EQ(store_sessions.size(), 3u);

  // Delete the valid sessions one by one and check store contents.
  store().DeleteSession(site2, Session::Id(cfgs[2].session_id));
  store_sessions = store().GetAllSessions();
  EXPECT_TRUE(store_sessions.find(site2) == store_sessions.end());

  store().DeleteSession(site1, Session::Id(cfgs[0].session_id));
  store_sessions = store().GetAllSessions();
  EXPECT_EQ(store_sessions.size(), 1u);
  EXPECT_EQ(store_sessions.begin()->first, site1);
  EXPECT_EQ(store_sessions.begin()->second->id(),
            Session::Id(cfgs[1].session_id));

  store().DeleteSession(site1, Session::Id(cfgs[1].session_id));
  store_sessions = store().GetAllSessions();
  EXPECT_EQ(store_sessions.size(), 0u);
}

TEST_F(SessionStoreImplTest, LoadSavedSessions) {
  CreateStoreAndLoadSessions();
  SessionCfgList cfgs = {
      {"https://a.foo.test/index.html", "session0"},
      {"https://b.foo.test/index.html", "session1"},
      {"https://c.bar.test/index.html", "session2"},
  };

  SessionStore::SessionsMap saved_sessions =
      CreateAndSaveSessions(cfgs, unexportable_key_service(), store());

  MimicRestart();

  SessionStore::SessionsMap loaded_sessions = LoadSessions();
  // Restore the binding keys in the store session objects.
  for (auto& [site, session] : loaded_sessions) {
    RestoreSessionBindingKey(site, session.get());
  }

  EXPECT_TRUE(SessionMapsAreEqual(saved_sessions, loaded_sessions));
}

TEST_F(SessionStoreImplTest, PruneLoadedEntryWithInvalidSite) {
  // Create an entry with an invalid site.
  proto::Session sproto = CreateSessionProto(unexportable_key_service(),
                                             "https://foo.test", "session_id");
  proto::SiteSessions site_proto;
  (*site_proto.mutable_sessions())["session_id"] = std::move(sproto);

  // Create an entry with a valid site.
  proto::Session sproto2 = CreateSessionProto(unexportable_key_service(),
                                              "https://bar.test", "session_id");
  proto::SiteSessions site2_proto;
  (*site2_proto.mutable_sessions())["session_id"] = std::move(sproto2);
  auto site2 = net::SchemefulSite(GURL("https://bar.test)"));

  // Create a table with these two entries.
  std::map<std::string, proto::SiteSessions> loaded_tbl;
  loaded_tbl["about:blank"] = std::move(site_proto);
  loaded_tbl[site2.Serialize()] = std::move(site2_proto);

  // Run the 2-entry table through the store's cleaning method.
  std::vector<std::string> keys_to_delete;
  SessionStore::SessionsMap sessions_map =
      SessionStoreImpl::CreateSessionsFromLoadedData(loaded_tbl,
                                                     keys_to_delete);

  // Verify:
  // - entry with valid site is present in the output sessions map.
  // - entry with invalid site is not present and is included in the
  //   keys_to_delete list.
  EXPECT_EQ(sessions_map.size(), 1u);
  EXPECT_EQ(sessions_map.count(site2), 1u);
  EXPECT_EQ(keys_to_delete.size(), 1u);
  EXPECT_EQ(keys_to_delete[0], "about:blank");
}

// Note: There are several reasons why a session may be invalid. We only
// use one of them here to test the pruning logic. The individual invalid
// reasons have been tested in SessionTest.FailCreateFromInvalidProto
// in file session_unittest.cc
TEST_F(SessionStoreImplTest, PruneLoadedEntryWithInvalidSession) {
  // Create an entry with 1 valid and 1 invalid session.
  proto::Session sproto1 = CreateSessionProto(
      unexportable_key_service(), "https://foo.example.test", "session_1");
  // Create an invalid session.
  proto::Session sproto2 = CreateSessionProto(
      unexportable_key_service(), "https://bar.example.test", "session_2");
  sproto2.set_refresh_url("invalid_url");

  // Create a site proto (proto table's value field) consisting of the above 2
  // sessions.
  proto::SiteSessions site_proto;
  (*site_proto.mutable_sessions())["session_1"] = std::move(sproto1);
  (*site_proto.mutable_sessions())["session_2"] = std::move(sproto2);

  // Create a table consisting of the above 2-session entry.
  std::map<std::string, proto::SiteSessions> loaded_tbl;
  auto site = net::SchemefulSite(GURL("https://foo.example.test"));
  loaded_tbl[site.Serialize()] = std::move(site_proto);

  // Run the DB table through the store's cleaning method.
  std::vector<std::string> keys_to_delete;
  SessionStore::SessionsMap sessions_map =
      SessionStoreImpl::CreateSessionsFromLoadedData(loaded_tbl,
                                                     keys_to_delete);

  // Verify that the entry is pruned even though only 1 out of the 2 sessions
  // was invalid.
  EXPECT_EQ(sessions_map.size(), 0u);
  EXPECT_EQ(keys_to_delete.size(), 1u);
  EXPECT_EQ(keys_to_delete[0], site.Serialize());
}

TEST_F(SessionStoreImplTest, PruneLoadedEntryWithSessionMissingWrappedKey) {
  // Create a Session proto with missing wrapped key field.
  proto::Session sproto = CreateSessionProto(
      unexportable_key_service(), "https://foo.example.test", "session_id");
  sproto.clear_wrapped_key();

  // Create a single entry table with the above session data.
  proto::SiteSessions site_proto;
  (*site_proto.mutable_sessions())["session_id"] = std::move(sproto);
  std::map<std::string, proto::SiteSessions> loaded_tbl;
  auto site = net::SchemefulSite(GURL("https://foo.example.test"));
  loaded_tbl[site.Serialize()] = std::move(site_proto);

  // Run the table through the store's cleaning method.
  std::vector<std::string> keys_to_delete;
  SessionStore::SessionsMap sessions_map =
      SessionStoreImpl::CreateSessionsFromLoadedData(loaded_tbl,
                                                     keys_to_delete);

  // Verify that the DB entry has been pruned in the output sessions map.
  EXPECT_EQ(sessions_map.size(), 0u);
  EXPECT_EQ(keys_to_delete.size(), 1u);
  EXPECT_EQ(keys_to_delete[0], site.Serialize());
}

}  // namespace net::device_bound_sessions
```
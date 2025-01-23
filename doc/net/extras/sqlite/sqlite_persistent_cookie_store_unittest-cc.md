Response:
The user wants a summary of the functionality of the C++ source code file `net/extras/sqlite/sqlite_persistent_cookie_store_unittest.cc`. I need to identify the core purpose of this file and extract the key functionalities being tested. Since it's a unittest file, its primary function is to test the `SQLitePersistentCookieStore` class.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core class under test:** The `#include "net/extras/sqlite/sqlite_persistent_cookie_store.h"` clearly indicates that the tests are for the `SQLitePersistentCookieStore` class.

2. **Infer the purpose of the tested class:** The name "SQLitePersistentCookieStore" suggests it's responsible for storing cookies persistently using an SQLite database.

3. **Recognize the file's nature:** The filename ends with `_unittest.cc`, signifying that it's a unit test file. Unit tests verify the functionality of a specific component in isolation.

4. **Scan the test functions:** Look at the names of the `TEST_F` functions. These names usually provide clues about the specific features being tested. Examples include:
    * `TestInvalidVersionRecovery`
    * `TestInvalidMetaTableRecovery`
    * `TestPersistance`
    * `TestSessionCookiesDeletedOnStartup`
    * `TestLoadCookiesForKey`
    * `TestFlush`
    * `TestLoadOldSessionCookies`
    * `TestDontLoadOldSessionCookies`
    * `FilterBadCookiesAndFixupDb`
    * `PersistIsPersistent`

5. **Group related tests:** Group the test functions into logical categories based on the functionality they are testing. For example:
    * **Database Integrity/Recovery:** `TestInvalidVersionRecovery`, `TestInvalidMetaTableRecovery`
    * **Basic Persistence:** `TestPersistance`
    * **Session Cookie Handling:** `TestSessionCookiesDeletedOnStartup`, `TestLoadOldSessionCookies`, `TestDontLoadOldSessionCookies`
    * **Prioritized Loading:** `TestLoadCookiesForKey`
    * **Forced Writes:** `TestFlush`
    * **Data Integrity:** `FilterBadCookiesAndFixupDb`
    * **Cookie Attributes:** `PersistIsPersistent` (though only partially included in the snippet)

6. **Formulate a concise summary:** Combine the identified functionalities into a brief overview.

7. **Address the specific prompt questions (even though it's only part 1):**
    * **Javascript relationship:** Although this is a C++ test file, understanding what it's testing reveals a connection to how web browsers handle cookies, which are accessible via Javascript. However, the *unittest itself* doesn't directly interact with Javascript.
    * **Logical Reasoning:** Look for specific test cases that involve setting up certain conditions and verifying the expected outcome. The recovery tests and the session cookie tests are good examples.
    * **User/Programming Errors:** Consider the scenarios tested. Incorrect database versions or corrupt meta tables represent potential errors. The session cookie tests highlight the importance of correctly configuring the cookie store.
    * **User Operation for Debugging:**  Think about the steps a user might take in a browser that would lead to the cookie store being used and potentially needing debugging.

By following these steps, I can generate a comprehensive yet concise summary of the provided code snippet's functionality, even within the context of being the first part of a larger request.
这个C++源代码文件 `sqlite_persistent_cookie_store_unittest.cc` 的主要功能是 **测试 `SQLitePersistentCookieStore` 类的各种功能**。`SQLitePersistentCookieStore` 负责将网络 Cookie 持久化存储到 SQLite 数据库中。

具体来说，从提供的代码片段中可以看出，这个单元测试文件涵盖了以下方面的功能测试：

1. **数据库的初始化和恢复能力:**
   - 测试当数据库版本号无效时 (`TestInvalidVersionRecovery`)，`SQLitePersistentCookieStore` 能否正确地恢复，创建一个新的空数据库。
   - 测试当元数据表损坏时 (`TestInvalidMetaTableRecovery`)，`SQLitePersistentCookieStore` 能否正确地恢复。

2. **Cookie 的持久化存储和读取:**
   - 测试 Cookie 能否正确地写入数据库并能在重启后重新加载 (`TestPersistance`)。
   - 测试 Cookie 能否在删除后正确地从数据库中移除 (`TestPersistance`)。

3. **会话 Cookie 的处理:**
   - 测试在不恢复旧会话 Cookie 的情况下，启动时是否会删除数据库中的会话 Cookie (`TestSessionCookiesDeletedOnStartup`)。
   - 测试在恢复旧会话 Cookie 的情况下，启动时是否会加载这些会话 Cookie (`TestLoadOldSessionCookies`)。
   - 测试在不恢复旧会话 Cookie 的情况下，数据库是否会删除旧的会话 Cookie (`TestDontLoadOldSessionCookies`)。

4. **特定域名的 Cookie 的优先加载:**
   - 测试能否优先加载特定域名的 Cookie，而不需要等待整个数据库加载完成 (`TestLoadCookiesForKey`)。

5. **在提交前的回调:**
   - 测试在 Cookie 数据提交到数据库之前是否可以设置回调函数 (`TestBeforeCommitCallback`)。

6. **强制将数据写入数据库:**
   - 测试调用 `Flush()` 方法是否能强制将内存中的 Cookie 数据写入到数据库文件中 (`TestFlush`)。

7. **过滤和修复损坏的 Cookie 数据:**
   - 测试当数据库中存在格式不正确的 Cookie 数据时，`SQLitePersistentCookieStore` 能否在加载时将其过滤掉，并修复数据库 (`FilterBadCookiesAndFixupDb`)。

8. **持久化 Cookie 的 `is_persistent` 属性:**
   - 测试能否正确地存储和加载 Cookie 的持久性属性 (`PersistIsPersistent`)。

**与 JavaScript 的功能关系：**

虽然这个 C++ 代码文件本身不包含 JavaScript 代码，但它测试的网络 Cookie 存储功能直接影响着 Web 浏览器的 JavaScript 代码对 Cookie 的访问和操作。

**举例说明：**

假设一个网页通过 JavaScript 使用 `document.cookie` 设置了一个名为 "mycookie" 的 Cookie：

```javascript
document.cookie = "mycookie=myvalue; domain=example.com; path=/; expires=Fri, 31 Dec 2024 23:59:59 GMT";
```

当浏览器关闭并重新打开时，如果 `SQLitePersistentCookieStore` 工作正常，这个 "mycookie" 应该被加载回来。如果测试用例 `TestPersistance` 通过，就意味着这种持久化功能是可靠的。

反之，如果用户在 JavaScript 中设置了一个会话 Cookie (没有 `expires` 属性)：

```javascript
document.cookie = "sessionid=12345; domain=example.com; path=/";
```

如果 `SQLitePersistentCookieStore` 的配置是不恢复旧会话 Cookie，那么在浏览器重启后，这个 `sessionid` Cookie 应该不会被加载回来，这对应着测试用例 `TestSessionCookiesDeletedOnStartup` 的行为。

**逻辑推理 (假设输入与输出):**

**假设输入 (针对 `TestInvalidVersionRecovery`):**

1. 一个已经存在的 SQLite Cookie 数据库文件，其元数据表中存储的版本号是一个过时的、不支持的版本 (例如 17)。

**输出:**

1. `SQLitePersistentCookieStore` 加载时检测到版本号无效。
2. `SQLitePersistentCookieStore` 将旧的数据库文件视为无效，并创建一个新的空的数据库。
3. 加载完成后，Cookie 列表为空。

**假设输入 (针对 `TestLoadCookiesForKey`):**

1. SQLite 数据库中存储了多个 Cookie，属于不同的域名，例如 "foo.bar"、"www.aaa.com"、"travel.aaa.com" 和 "www.bbb.com"。
2. 调用 `LoadCookiesForKey("aaa.com")`。

**输出:**

1. `SQLitePersistentCookieStore` 优先加载属于 "aaa.com" 及其子域名的 Cookie ("www.aaa.com" 和 "travel.aaa.com")。
2. 在回调函数中，只会返回属于 "aaa.com" 及其子域名的 Cookie。
3. 之后，当整个 Cookie 数据库加载完成后，才会加载其他域名的 Cookie。

**用户或编程常见的使用错误:**

1. **数据库文件损坏或权限问题:** 如果用户手动修改了 Cookie 数据库文件，或者文件权限不正确导致无法读写，`SQLitePersistentCookieStore` 可能无法正常工作，导致 Cookie 丢失或加载失败。测试用例中的数据库恢复测试 (`TestInvalidVersionRecovery`, `TestInvalidMetaTableRecovery`) 就是为了应对这类问题。
2. **配置错误导致会话 Cookie 处理不当:** 开发者可能错误地配置 `SQLitePersistentCookieStore` 是否恢复旧的会话 Cookie。如果期望保留会话 Cookie 但配置成不恢复，则会导致会话信息丢失。`TestLoadOldSessionCookies` 和 `TestDontLoadOldSessionCookies` 测试了这两种情况。
3. **并发访问数据库:** 虽然 `SQLitePersistentCookieStore` 内部处理了并发问题，但如果外部代码也尝试直接操作同一个数据库文件，可能会导致数据损坏。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中访问网站并设置了 Cookie。** 例如，用户登录一个网站，服务器通过 `Set-Cookie` 头部设置了一个持久化的认证 Cookie。
2. **浏览器进程需要将这些 Cookie 持久化存储。**  浏览器的网络栈使用了 `SQLitePersistentCookieStore` 来完成这个任务。当新的 Cookie 被添加或已有的 Cookie 被修改时，`SQLitePersistentCookieStore` 会将这些更改写入到 SQLite 数据库文件中。
3. **用户关闭浏览器。** 在浏览器关闭时，`SQLitePersistentCookieStore` 可能会进行最后的写入操作，确保所有 Cookie 都被保存。
4. **用户重新打开浏览器并访问之前访问过的网站。** 浏览器需要加载之前存储的 Cookie，以便发送给服务器，维持用户的登录状态或其他状态。
5. **浏览器再次使用 `SQLitePersistentCookieStore` 从 SQLite 数据库中读取 Cookie。** 如果在这个过程中出现问题，例如数据库文件损坏，或者代码逻辑错误导致 Cookie 没有被正确加载，开发者可能会需要查看 `sqlite_persistent_cookie_store_unittest.cc` 中的测试用例来理解可能出现的问题以及如何解决。例如，如果用户报告重启浏览器后 Cookie 丢失，开发者可能会查看 `TestSessionCookiesDeletedOnStartup` 或 `TestPersistance` 等测试用例来排查是否是会话 Cookie 处理逻辑或基本持久化功能出现了问题。

**功能归纳 (第 1 部分):**

总而言之，`net/extras/sqlite/sqlite_persistent_cookie_store_unittest.cc` 的第 1 部分主要测试了 `SQLitePersistentCookieStore` 的**基本数据库初始化和恢复能力，Cookie 的基本持久化存储和读取功能，以及在启动时对会话 Cookie 的处理逻辑**。 这些测试用例确保了 Cookie 能够可靠地存储在本地数据库中，并在浏览器重启后能够被正确地加载，这是浏览器网络栈中 Cookie 管理功能的核心组成部分。

### 提示词
```
这是目录为net/extras/sqlite/sqlite_persistent_cookie_store_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/extras/sqlite/sqlite_persistent_cookie_store.h"

#include <stdint.h>

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#include "base/containers/span.h"
#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/location.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/run_loop.h"
#include "base/sequence_checker.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/threading/thread_restrictions.h"
#include "base/time/time.h"
#include "crypto/aes_cbc.h"
#include "net/base/features.h"
#include "net/base/test_completion_callback.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/cookie_constants.h"
#include "net/cookies/cookie_inclusion_status.h"
#include "net/cookies/cookie_store_test_callbacks.h"
#include "net/extras/sqlite/cookie_crypto_delegate.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/test/test_with_task_environment.h"
#include "sql/database.h"
#include "sql/meta_table.h"
#include "sql/statement.h"
#include "sql/transaction.h"
#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/third_party/mozilla/url_parse.h"

namespace net {

namespace {

const base::FilePath::CharType kCookieFilename[] = FILE_PATH_LITERAL("Cookies");

class CookieCryptor : public CookieCryptoDelegate {
 public:
  CookieCryptor();

  // net::CookieCryptoDelegate implementation.
  void Init(base::OnceClosure callback) override;
  bool EncryptString(const std::string& plaintext,
                     std::string* ciphertext) override;
  bool DecryptString(const std::string& ciphertext,
                     std::string* plaintext) override;

  // Obtain a closure that can be called to trigger an initialize. If this
  // instance has already been destructed then the returned base::OnceClosure
  // does nothing. This allows tests to pass ownership to the CookieCryptor
  // while still retaining a weak reference to the Init function.
  base::OnceClosure GetInitClosure(base::OnceClosure callback);

 private:
  void InitComplete();
  bool init_ GUARDED_BY_CONTEXT(sequence_checker_) = false;
  bool initing_ GUARDED_BY_CONTEXT(sequence_checker_) = false;
  base::OnceClosureList callbacks_ GUARDED_BY_CONTEXT(sequence_checker_);
  SEQUENCE_CHECKER(sequence_checker_);

  base::WeakPtrFactory<CookieCryptor> weak_ptr_factory_{this};
};

constexpr std::array<uint8_t, 32> kFixedKey{
    'c', 'o', 'o', 'k', 'i', 'e', 'c', 'r', 'y', 'p', 't',
    'o', 'r', 'i', 's', 'a', 'u', 's', 'e', 'f', 'u', 'l',
    't', 'e', 's', 't', 'c', 'l', 'a', 's', 's', '!',
};
constexpr std::array<uint8_t, 16> kFixedIv{
    't', 'h', 'e', ' ', 'i', 'v', ':', ' ',
    '1', '6', ' ', 'b', 'y', 't', 'e', 's',
};

CookieCryptor::CookieCryptor() {
  DETACH_FROM_SEQUENCE(sequence_checker_);
}

base::OnceClosure CookieCryptor::GetInitClosure(base::OnceClosure callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return base::BindOnce(&CookieCryptor::Init, weak_ptr_factory_.GetWeakPtr(),
                        std::move(callback));
}

void CookieCryptor::Init(base::OnceClosure callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (init_) {
    std::move(callback).Run();
    return;
  }

  // Callbacks here are owned by test fixtures that outlive the CookieCryptor.
  callbacks_.AddUnsafe(std::move(callback));

  if (initing_) {
    return;
  }

  initing_ = true;
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&CookieCryptor::InitComplete,
                     weak_ptr_factory_.GetWeakPtr()),
      base::Milliseconds(100));
}

bool CookieCryptor::EncryptString(const std::string& plaintext,
                                  std::string* ciphertext) {
  // SQLite crypto uses OSCrypt Async Encryptor and the behavior for empty
  // plaintext is to return empty ciphertext. See
  // os_crypt_async::Encryptor::EncryptString. This matches this behavior,
  // without adding a dependency from net into components.
  if (plaintext.empty()) {
    ciphertext->clear();
    return true;
  }
  auto result = crypto::aes_cbc::Encrypt(kFixedKey, kFixedIv,
                                         base::as_byte_span(plaintext));
  ciphertext->assign(result.begin(), result.end());
  return true;
}

bool CookieCryptor::DecryptString(const std::string& ciphertext,
                                  std::string* plaintext) {
  // SQLite crypto uses OSCrypt Async Encryptor and the behavior for empty
  // ciphertext is to return empty plaintext. See
  // os_crypt_async::Encryptor::DecryptString. This matches this behavior,
  // without adding a dependency from net into components.
  if (ciphertext.empty()) {
    plaintext->clear();
    return true;
  }
  auto result = crypto::aes_cbc::Decrypt(kFixedKey, kFixedIv,
                                         base::as_byte_span(ciphertext));
  if (result.has_value()) {
    plaintext->assign(result->begin(), result->end());
    return true;
  }

  return false;
}

void CookieCryptor::InitComplete() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  init_ = true;
  callbacks_.Notify();
}

// Matches the CanonicalCookie's strictly_unique_key and last_access_date
// against a unique_ptr<CanonicalCookie>.
MATCHER_P2(MatchesCookieKeyAndLastAccessDate,
           StrictlyUniqueKey,
           last_access_date,
           "") {
  if (!arg) {
    return false;
  }
  const CanonicalCookie& list_cookie = *arg;

  return testing::ExplainMatchResult(StrictlyUniqueKey,
                                     list_cookie.StrictlyUniqueKey(),
                                     result_listener) &&
         testing::ExplainMatchResult(
             last_access_date, list_cookie.LastAccessDate(), result_listener);
}

// Matches every field of a CanonicalCookie against a
// unique_ptr<CanonicalCookie>.
MATCHER_P(MatchesEveryCookieField, cookie, "") {
  if (!arg) {
    return false;
  }
  const CanonicalCookie& list_cookie = *arg;
  return cookie.HasEquivalentDataMembers(list_cookie);
}

}  // namespace

typedef std::vector<std::unique_ptr<CanonicalCookie>> CanonicalCookieVector;

class SQLitePersistentCookieStoreTest : public TestWithTaskEnvironment {
 public:
  SQLitePersistentCookieStoreTest()
      : loaded_event_(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                      base::WaitableEvent::InitialState::NOT_SIGNALED),
        db_thread_event_(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                         base::WaitableEvent::InitialState::NOT_SIGNALED) {}

  void SignalLoadedEvent() { loaded_event_.Signal(); }

  void OnLoaded(base::OnceClosure closure, CanonicalCookieVector cookies) {
    cookies_.swap(cookies);
    std::move(closure).Run();
  }

  CanonicalCookieVector Load() {
    base::RunLoop run_loop;
    CanonicalCookieVector cookies;
    store_->Load(
        base::BindLambdaForTesting([&](CanonicalCookieVector obtained_cookies) {
          cookies.swap(obtained_cookies);
          run_loop.Quit();
        }),
        NetLogWithSource::Make(NetLogSourceType::NONE));
    run_loop.Run();
    return cookies;
  }

  void LoadAsyncAndSignalEvent() {
    store_->Load(
        base::BindOnce(
            &SQLitePersistentCookieStoreTest::OnLoaded, base::Unretained(this),
            base::BindOnce(&SQLitePersistentCookieStoreTest::SignalLoadedEvent,
                           base::Unretained(this))),
        NetLogWithSource::Make(NetLogSourceType::NONE));
  }

  void Flush() {
    base::RunLoop run_loop;
    store_->Flush(run_loop.QuitClosure());
    run_loop.Run();
  }

  void DestroyStore() {
    store_ = nullptr;
    // Make sure we wait until the destructor has run by running all
    // TaskEnvironment tasks.
    RunUntilIdle();
  }

  void Create(bool crypt_cookies,
              bool restore_old_session_cookies,
              bool use_current_thread,
              bool enable_exclusive_access) {
    store_ = base::MakeRefCounted<SQLitePersistentCookieStore>(
        temp_dir_.GetPath().Append(kCookieFilename),
        use_current_thread ? base::SingleThreadTaskRunner::GetCurrentDefault()
                           : client_task_runner_,
        background_task_runner_, restore_old_session_cookies,
        crypt_cookies ? std::make_unique<CookieCryptor>() : nullptr,
        enable_exclusive_access);
  }

  CanonicalCookieVector CreateAndLoad(bool crypt_cookies,
                                      bool restore_old_session_cookies) {
    Create(crypt_cookies, restore_old_session_cookies,
           /*use_current_thread=*/false, /*enable_exclusive_access=*/false);
    return Load();
  }

  void InitializeStore(bool crypt, bool restore_old_session_cookies) {
    EXPECT_EQ(0U, CreateAndLoad(crypt, restore_old_session_cookies).size());
  }

  void WaitOnDBEvent() {
    base::ScopedAllowBaseSyncPrimitivesForTesting allow_base_sync_primitives;
    db_thread_event_.Wait();
  }

  // Adds a persistent cookie to store_.
  void AddCookie(const std::string& name,
                 const std::string& value,
                 const std::string& domain,
                 const std::string& path,
                 const base::Time& creation) {
    store_->AddCookie(*CanonicalCookie::CreateUnsafeCookieForTesting(
        name, value, domain, path, creation, /*expiration=*/creation,
        /*last_access=*/base::Time(), /*last_update=*/base::Time(),
        /*secure=*/false,
        /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
        COOKIE_PRIORITY_DEFAULT));
  }

  void AddCookieWithExpiration(const std::string& name,
                               const std::string& value,
                               const std::string& domain,
                               const std::string& path,
                               const base::Time& creation,
                               const base::Time& expiration) {
    store_->AddCookie(*CanonicalCookie::CreateUnsafeCookieForTesting(
        name, value, domain, path, creation, expiration,
        /*last_access=*/base::Time(), /*last_update=*/base::Time(),
        /*secure=*/false,
        /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
        COOKIE_PRIORITY_DEFAULT));
  }

  std::string ReadRawDBContents() {
    std::string contents;
    if (!base::ReadFileToString(temp_dir_.GetPath().Append(kCookieFilename),
                                &contents))
      return std::string();
    return contents;
  }

  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }

  void TearDown() override {
    if (!expect_init_errors_) {
      EXPECT_THAT(histograms_.GetAllSamples("Cookie.ErrorInitializeDB"),
                  ::testing::IsEmpty());
    }
    DestroyStore();
  }

 protected:
  const scoped_refptr<base::SequencedTaskRunner> background_task_runner_ =
      base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()});
  const scoped_refptr<base::SequencedTaskRunner> client_task_runner_ =
      base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()});
  base::WaitableEvent loaded_event_;
  base::WaitableEvent db_thread_event_;
  CanonicalCookieVector cookies_;
  base::ScopedTempDir temp_dir_;
  scoped_refptr<SQLitePersistentCookieStore> store_;
  std::unique_ptr<CookieCryptor> cookie_crypto_delegate_;
  base::HistogramTester histograms_;
  bool expect_init_errors_ = false;
};

TEST_F(SQLitePersistentCookieStoreTest, TestInvalidVersionRecovery) {
  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/false);
  AddCookie("A", "B", "foo.bar", "/", base::Time::Now());
  DestroyStore();

  // Load up the store and verify that it has good data in it.
  CanonicalCookieVector cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/false);
  ASSERT_EQ(1U, cookies.size());
  ASSERT_STREQ("foo.bar", cookies[0]->Domain().c_str());
  ASSERT_STREQ("A", cookies[0]->Name().c_str());
  ASSERT_STREQ("B", cookies[0]->Value().c_str());
  DestroyStore();
  cookies.clear();

  // Now make the version too old to initialize from.
  {
    sql::Database db;
    ASSERT_TRUE(db.Open(temp_dir_.GetPath().Append(kCookieFilename)));
    sql::MetaTable meta_table;
    ASSERT_TRUE(meta_table.Init(&db, 1, 1));
    // Keep in sync with latest unsupported version from:
    // net/extras/sqlite/sqlite_persistent_cookie_store.cc
    ASSERT_TRUE(meta_table.SetVersionNumber(17));
  }

  // Upon loading, the database should be reset to a good, blank state.
  cookies = CreateAndLoad(/*crypt_cookies=*/false,
                          /*restore_old_session_cookies=*/false);
  ASSERT_EQ(0U, cookies.size());

  // Verify that, after, recovery, the database persists properly.
  AddCookie("X", "Y", "foo.bar", "/", base::Time::Now());
  DestroyStore();
  cookies = CreateAndLoad(/*crypt_cookies=*/false,
                          /*restore_old_session_cookies=*/false);
  ASSERT_EQ(1U, cookies.size());
  ASSERT_STREQ("foo.bar", cookies[0]->Domain().c_str());
  ASSERT_STREQ("X", cookies[0]->Name().c_str());
  ASSERT_STREQ("Y", cookies[0]->Value().c_str());
}

TEST_F(SQLitePersistentCookieStoreTest, TestInvalidMetaTableRecovery) {
  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/false);
  AddCookie("A", "B", "foo.bar", "/", base::Time::Now());
  DestroyStore();

  // Load up the store and verify that it has good data in it.
  CanonicalCookieVector cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/false);
  ASSERT_EQ(1U, cookies.size());
  ASSERT_STREQ("foo.bar", cookies[0]->Domain().c_str());
  ASSERT_STREQ("A", cookies[0]->Name().c_str());
  ASSERT_STREQ("B", cookies[0]->Value().c_str());
  DestroyStore();
  cookies.clear();

  // Now corrupt the meta table.
  {
    sql::Database db;
    ASSERT_TRUE(db.Open(temp_dir_.GetPath().Append(kCookieFilename)));
    sql::MetaTable meta_table;
    ASSERT_TRUE(meta_table.Init(&db, 1, 1));
    ASSERT_TRUE(db.Execute("DELETE FROM meta"));
  }

  // Upon loading, the database should be reset to a good, blank state.
  cookies = CreateAndLoad(/*crypt_cookies=*/false,
                          /*restore_old_session_cookies=*/false);
  ASSERT_EQ(0U, cookies.size());

  // Verify that, after, recovery, the database persists properly.
  AddCookie("X", "Y", "foo.bar", "/", base::Time::Now());
  DestroyStore();
  cookies = CreateAndLoad(/*crypt_cookies=*/false,
                          /*restore_old_session_cookies=*/false);
  ASSERT_EQ(1U, cookies.size());
  ASSERT_STREQ("foo.bar", cookies[0]->Domain().c_str());
  ASSERT_STREQ("X", cookies[0]->Name().c_str());
  ASSERT_STREQ("Y", cookies[0]->Value().c_str());
}

// Test if data is stored as expected in the SQLite database.
TEST_F(SQLitePersistentCookieStoreTest, TestPersistance) {
  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/false);
  AddCookie("A", "B", "foo.bar", "/", base::Time::Now());
  // Replace the store effectively destroying the current one and forcing it
  // to write its data to disk. Then we can see if after loading it again it
  // is still there.
  DestroyStore();
  // Reload and test for persistence
  CanonicalCookieVector cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/false);
  ASSERT_EQ(1U, cookies.size());
  ASSERT_STREQ("foo.bar", cookies[0]->Domain().c_str());
  ASSERT_STREQ("A", cookies[0]->Name().c_str());
  ASSERT_STREQ("B", cookies[0]->Value().c_str());

  // Now delete the cookie and check persistence again.
  store_->DeleteCookie(*cookies[0]);
  DestroyStore();
  cookies.clear();

  // Reload and check if the cookie has been removed.
  cookies = CreateAndLoad(/*crypt_cookies=*/false,
                          /*restore_old_session_cookies=*/false);
  ASSERT_EQ(0U, cookies.size());
}

TEST_F(SQLitePersistentCookieStoreTest, TestSessionCookiesDeletedOnStartup) {
  // Initialize the cookie store with 3 persistent cookies, 5 transient
  // cookies.
  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/false);

  // Add persistent cookies.
  base::Time t = base::Time::Now();
  AddCookie("A", "B", "a1.com", "/", t);
  t += base::Microseconds(10);
  AddCookie("A", "B", "a2.com", "/", t);
  t += base::Microseconds(10);
  AddCookie("A", "B", "a3.com", "/", t);

  // Add transient cookies.
  t += base::Microseconds(10);
  AddCookieWithExpiration("A", "B", "b1.com", "/", t, base::Time());
  t += base::Microseconds(10);
  AddCookieWithExpiration("A", "B", "b2.com", "/", t, base::Time());
  t += base::Microseconds(10);
  AddCookieWithExpiration("A", "B", "b3.com", "/", t, base::Time());
  t += base::Microseconds(10);
  AddCookieWithExpiration("A", "B", "b4.com", "/", t, base::Time());
  t += base::Microseconds(10);
  AddCookieWithExpiration("A", "B", "b5.com", "/", t, base::Time());
  DestroyStore();

  // Load the store a second time. Before the store finishes loading, add a
  // transient cookie and flush it to disk.
  store_ = base::MakeRefCounted<SQLitePersistentCookieStore>(
      temp_dir_.GetPath().Append(kCookieFilename), client_task_runner_,
      background_task_runner_, false, nullptr, false);

  // Posting a blocking task to db_thread_ makes sure that the DB thread waits
  // until both Load and Flush have been posted to its task queue.
  background_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&SQLitePersistentCookieStoreTest::WaitOnDBEvent,
                                base::Unretained(this)));
  LoadAsyncAndSignalEvent();
  t += base::Microseconds(10);
  AddCookieWithExpiration("A", "B", "c.com", "/", t, base::Time());
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  store_->Flush(
      base::BindOnce(&base::WaitableEvent::Signal, base::Unretained(&event)));

  // Now the DB-thread queue contains:
  // (active:)
  // 1. Wait (on db_event)
  // (pending:)
  // 2. "Init And Chain-Load First Domain"
  // 3. Add Cookie (c.com)
  // 4. Flush Cookie (c.com)
  db_thread_event_.Signal();
  event.Wait();
  loaded_event_.Wait();
  cookies_.clear();
  DestroyStore();

  // Load the store a third time, this time restoring session cookies. The
  // store should contain exactly 4 cookies: the 3 persistent, and "c.com",
  // which was added during the second cookie store load.
  store_ = base::MakeRefCounted<SQLitePersistentCookieStore>(
      temp_dir_.GetPath().Append(kCookieFilename), client_task_runner_,
      background_task_runner_, true, nullptr, false);
  LoadAsyncAndSignalEvent();
  loaded_event_.Wait();
  ASSERT_EQ(4u, cookies_.size());
}

// Test that priority load of cookies for a specific domain key could be
// completed before the entire store is loaded.
TEST_F(SQLitePersistentCookieStoreTest, TestLoadCookiesForKey) {
  InitializeStore(/*crypt=*/true, /*restore_old_session_cookies=*/false);
  base::Time t = base::Time::Now();
  AddCookie("A", "B", "foo.bar", "/", t);
  t += base::Microseconds(10);
  AddCookie("A", "B", "www.aaa.com", "/", t);
  t += base::Microseconds(10);
  AddCookie("A", "B", "travel.aaa.com", "/", t);
  t += base::Microseconds(10);
  AddCookie("A", "B", "www.bbb.com", "/", t);
  DestroyStore();

  auto cookie_crypto_delegate = std::make_unique<CookieCryptor>();
  base::RunLoop cookie_crypto_loop;
  auto init_closure =
      cookie_crypto_delegate->GetInitClosure(cookie_crypto_loop.QuitClosure());

  // base::test::TaskEnvironment runs |background_task_runner_| and
  // |client_task_runner_| on the same thread. Therefore, when a
  // |background_task_runner_| task is blocked, |client_task_runner_| tasks
  // can't run. To allow precise control of |background_task_runner_| without
  // preventing client tasks to run, use
  // base::SingleThreadTaskRunner::GetCurrentDefault() instead of
  // |client_task_runner_| for this test.
  store_ = base::MakeRefCounted<SQLitePersistentCookieStore>(
      temp_dir_.GetPath().Append(kCookieFilename),
      base::SingleThreadTaskRunner::GetCurrentDefault(),
      background_task_runner_,
      /*restore_old_session_cookies=*/false, std::move(cookie_crypto_delegate),
      /*enable_exclusive_access=*/false);

  // Posting a blocking task to db_thread_ makes sure that the DB thread waits
  // until both Load and LoadCookiesForKey have been posted to its task queue.
  background_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&SQLitePersistentCookieStoreTest::WaitOnDBEvent,
                                base::Unretained(this)));
  RecordingNetLogObserver net_log_observer;
  LoadAsyncAndSignalEvent();
  base::RunLoop run_loop;
  net_log_observer.SetObserverCaptureMode(NetLogCaptureMode::kDefault);
  store_->LoadCookiesForKey(
      "aaa.com",
      base::BindOnce(&SQLitePersistentCookieStoreTest::OnLoaded,
                     base::Unretained(this), run_loop.QuitClosure()));

  // Complete the initialization of the cookie crypto delegate. This ensures
  // that any background tasks from the Load or the LoadCookiesForKey are posted
  // to the background_task_runner_.
  std::move(init_closure).Run();
  cookie_crypto_loop.Run();

  // Post a final blocking task to the background_task_runner_ to ensure no
  // other cookie loads take place during the test.
  background_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&SQLitePersistentCookieStoreTest::WaitOnDBEvent,
                                base::Unretained(this)));

  // Now the DB-thread queue contains:
  // (active:)
  // 1. Wait (on db_event)
  // (pending:)
  // 2. "Init And Chain-Load First Domain"
  // 3. Priority Load (aaa.com)
  // 4. Wait (on db_event)
  db_thread_event_.Signal();

  // Wait until the OnKeyLoaded callback has run.
  run_loop.Run();
  EXPECT_FALSE(loaded_event_.IsSignaled());

  std::set<std::string> cookies_loaded;
  for (CanonicalCookieVector::const_iterator it = cookies_.begin();
       it != cookies_.end(); ++it) {
    cookies_loaded.insert((*it)->Domain().c_str());
  }
  cookies_.clear();
  ASSERT_GT(4U, cookies_loaded.size());
  ASSERT_EQ(true, cookies_loaded.find("www.aaa.com") != cookies_loaded.end());
  ASSERT_EQ(true,
            cookies_loaded.find("travel.aaa.com") != cookies_loaded.end());

  db_thread_event_.Signal();

  RunUntilIdle();
  EXPECT_TRUE(loaded_event_.IsSignaled());

  for (CanonicalCookieVector::const_iterator it = cookies_.begin();
       it != cookies_.end(); ++it) {
    cookies_loaded.insert((*it)->Domain().c_str());
  }
  ASSERT_EQ(4U, cookies_loaded.size());
  ASSERT_EQ(cookies_loaded.find("foo.bar") != cookies_loaded.end(), true);
  ASSERT_EQ(cookies_loaded.find("www.bbb.com") != cookies_loaded.end(), true);
  cookies_.clear();

  store_ = nullptr;
  auto entries = net_log_observer.GetEntries();
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::COOKIE_PERSISTENT_STORE_LOAD,
      NetLogEventPhase::BEGIN);
  pos = ExpectLogContainsSomewhere(
      entries, pos, NetLogEventType::COOKIE_PERSISTENT_STORE_LOAD,
      NetLogEventPhase::END);
  pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::COOKIE_PERSISTENT_STORE_LOAD,
      NetLogEventPhase::BEGIN);
  pos = ExpectLogContainsSomewhere(
      entries, pos, NetLogEventType::COOKIE_PERSISTENT_STORE_KEY_LOAD_STARTED,
      NetLogEventPhase::NONE);
  EXPECT_FALSE(GetOptionalStringValueFromParams(entries[pos], "key"));
  pos = ExpectLogContainsSomewhere(
      entries, pos, NetLogEventType::COOKIE_PERSISTENT_STORE_KEY_LOAD_COMPLETED,
      NetLogEventPhase::NONE);
  pos = ExpectLogContainsSomewhere(
      entries, pos, NetLogEventType::COOKIE_PERSISTENT_STORE_LOAD,
      NetLogEventPhase::END);
  ExpectLogContainsSomewhere(entries, pos,
                             NetLogEventType::COOKIE_PERSISTENT_STORE_CLOSED,
                             NetLogEventPhase::NONE);
}

TEST_F(SQLitePersistentCookieStoreTest, TestBeforeCommitCallback) {
  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/false);

  struct Counter {
    int count = 0;
    void increment() { count++; }
  };

  Counter counter;
  store_->SetBeforeCommitCallback(
      base::BindRepeating(&Counter::increment, base::Unretained(&counter)));

  // The implementation of SQLitePersistentCookieStore::Backend flushes changes
  // after 30s or 512 pending operations. Add 512 cookies to the store to test
  // that the callback gets called when SQLitePersistentCookieStore internally
  // flushes its store.
  for (int i = 0; i < 512; i++) {
    // Each cookie needs a unique timestamp for creation_utc (see DB schema).
    base::Time t = base::Time::Now() + base::Microseconds(i);
    AddCookie(base::StringPrintf("%d", i), "foo", "example.com", "/", t);
  }

  RunUntilIdle();
  EXPECT_GT(counter.count, 0);

  DestroyStore();
}

// Test that we can force the database to be written by calling Flush().
TEST_F(SQLitePersistentCookieStoreTest, TestFlush) {
  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/false);
  // File timestamps don't work well on all platforms, so we'll determine
  // whether the DB file has been modified by checking its size.
  base::FilePath path = temp_dir_.GetPath().Append(kCookieFilename);
  base::File::Info info;
  ASSERT_TRUE(base::GetFileInfo(path, &info));
  int64_t base_size = info.size;

  // Write some large cookies, so the DB will have to expand by several KB.
  for (char c = 'a'; c < 'z'; ++c) {
    // Each cookie needs a unique timestamp for creation_utc (see DB schema).
    base::Time t = base::Time::Now() + base::Microseconds(c);
    std::string name(1, c);
    std::string value(1000, c);
    AddCookie(name, value, "foo.bar", "/", t);
  }

  Flush();

  // We forced a write, so now the file will be bigger.
  ASSERT_TRUE(base::GetFileInfo(path, &info));
  ASSERT_GT(info.size, base_size);
}

// Test loading old session cookies from the disk.
TEST_F(SQLitePersistentCookieStoreTest, TestLoadOldSessionCookies) {
  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/true);

  // Add a session cookie.
  store_->AddCookie(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "C", "D", "sessioncookie.com", "/", /*creation=*/base::Time::Now(),
      /*expiration=*/base::Time(),
      /*last_access=*/base::Time(), /*last_update=*/base::Time(),
      /*secure=*/false, /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT));

  // Force the store to write its data to the disk.
  DestroyStore();

  // Create a store that loads session cookies and test that the session cookie
  // was loaded.
  CanonicalCookieVector cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/true);

  ASSERT_EQ(1U, cookies.size());
  ASSERT_STREQ("sessioncookie.com", cookies[0]->Domain().c_str());
  ASSERT_STREQ("C", cookies[0]->Name().c_str());
  ASSERT_STREQ("D", cookies[0]->Value().c_str());
  ASSERT_EQ(COOKIE_PRIORITY_DEFAULT, cookies[0]->Priority());
}

// Test refusing to load old session cookies from the disk.
TEST_F(SQLitePersistentCookieStoreTest, TestDontLoadOldSessionCookies) {
  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/true);

  // Add a session cookie.
  store_->AddCookie(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "C", "D", "sessioncookie.com", "/", /*creation=*/base::Time::Now(),
      /*expiration=*/base::Time(),
      /*last_access=*/base::Time(), /*last_update=*/base::Time(),
      /*secure=*/false, /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT));

  // Force the store to write its data to the disk.
  DestroyStore();

  // Create a store that doesn't load old session cookies and test that the
  // session cookie was not loaded.
  CanonicalCookieVector cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/false);
  ASSERT_EQ(0U, cookies.size());

  // The store should also delete the session cookie. Wait until that has been
  // done.
  DestroyStore();

  // Create a store that loads old session cookies and test that the session
  // cookie is gone.
  cookies = CreateAndLoad(/*crypt_cookies=*/false,
                          /*restore_old_session_cookies=*/true);
  ASSERT_EQ(0U, cookies.size());
}

// Confirm bad cookies on disk don't get looaded, and that we also remove them
// from the database.
TEST_F(SQLitePersistentCookieStoreTest, FilterBadCookiesAndFixupDb) {
  // Create an on-disk store.
  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/true);
  DestroyStore();

  // Add some cookies in by hand.
  base::FilePath store_name(temp_dir_.GetPath().Append(kCookieFilename));
  std::unique_ptr<sql::Database> db(std::make_unique<sql::Database>());
  ASSERT_TRUE(db->Open(store_name));
  sql::Statement stmt(db->GetUniqueStatement(
      "INSERT INTO cookies (creation_utc, host_key, top_frame_site_key, name, "
      "value, encrypted_value, path, expires_utc, is_secure, is_httponly, "
      "samesite, last_access_utc, has_expires, is_persistent, priority, "
      "source_scheme, source_port, last_update_utc, source_type, "
      "has_cross_site_ancestor) "
      "VALUES (?,?,?,?,?,'',?,0,0,0,0,0,1,1,0,?,?,?,0,0)"));
  ASSERT_TRUE(stmt.is_valid());

  struct CookieInfo {
    const char* domain;
    const char* name;
    const char* value;
    const char* path;
  } cookies_info[] = {// A couple non-canonical cookies.
                      {"google.izzle", "A=", "B", "/path"},
                      {"google.izzle", "C ", "D", "/path"},

                      // A canonical cookie for same eTLD+1. This one will get
                      // dropped out of precaution to avoid confusing the site,
                      // even though there is nothing wrong with it.
                      {"sub.google.izzle", "E", "F", "/path"},

                      // A canonical cookie for another eTLD+1
                      {"chromium.org", "G", "H", "/dir"}};

  int64_t creation_time = 1;
  base::Time last_update(base::Time::Now());
  for (auto& cookie_info : cookies_info) {
    stmt.Reset(true);

    stmt.BindInt64(0, creation_time++);
    stmt.BindString(1, cookie_info.domain);
    // TODO(crbug.com/40188414) Test some non-empty values when CanonicalCookie
    // supports partition key.
    stmt.BindString(2, net::kEmptyCookiePartitionKey);
    stmt.BindString(3, cookie_info.name);
    stmt.BindString(4, cookie_info.value);
    stmt.BindString(5, cookie_info.path);
    stmt.BindInt(6, static_cast<int>(CookieSourceScheme::kUnset));
    stmt.BindInt(7, SQLitePersistentCookieStore::kDefaultUnknownPort);
    stmt.BindTime(8, last_update);
    ASSERT_TRUE(stmt.Run());
  }
  stmt.Clear();
  db.reset();

  // Reopen the store and confirm that the only cookie loaded is the
  // canonical one on an unrelated domain.
  CanonicalCookieVector cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/false);
  ASSERT_EQ(1U, cookies.size());
  EXPECT_STREQ("chromium.org", cookies[0]->Domain().c_str());
  EXPECT_STREQ("G", cookies[0]->Name().c_str());
  EXPECT_STREQ("H", cookies[0]->Value().c_str());
  EXPECT_STREQ("/dir", cookies[0]->Path().c_str());
  EXPECT_EQ(last_update, cookies[0]->LastUpdateDate());
  DestroyStore();

  // Make sure that we only have one row left.
  db = std::make_unique<sql::Database>();
  ASSERT_TRUE(db->Open(store_name));
  sql::Statement verify_stmt(db->GetUniqueStatement("SELECT * FROM COOKIES"));
  ASSERT_TRUE(verify_stmt.is_valid());

  EXPECT_TRUE(verify_stmt.Step());
  EXPECT_TRUE(verify_stmt.Succeeded());
  // Confirm only one match.
  EXPECT_FALSE(verify_stmt.Step());
}

TEST_F(SQLitePersistentCookieStoreTest, PersistIsPersistent) {
  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/true);
  static const char kSessionName[] = "session";
  static const char kPersistentName[] = "persistent";

  // Add a session cookie.
  store_->AddCookie(*CanonicalCookie::CreateUnsafeCookieForTesting(
      kSessionName, "val", "sessioncookie.com", "/",
      /*creation=*/base::Time::Now(),
      /*e
```
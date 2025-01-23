Response:
The user wants a summary of the functionalities of the provided C++ code snippet. The code is part of Chromium's network stack and deals with persistent storage of cookies using SQLite.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The file name `sqlite_persistent_cookie_store.cc` immediately suggests its primary function: persistently storing cookies using SQLite.

2. **Analyze the class structure:**  The code defines a `SQLitePersistentCookieStore` and a nested `Backend` class. The `Backend` class appears to handle the actual database interaction. This separation suggests an architecture where the main class provides the API and the backend handles the implementation details on a separate thread.

3. **Examine the `Backend` class methods:** Focus on the public methods of `Backend` as they represent the external interface for interacting with the cookie store. Key methods include:
    * `Load`:  Responsible for loading cookies from the database.
    * `LoadCookiesForKey`: Loads cookies for a specific domain.
    * `AddCookie`: Adds a new cookie to the store.
    * `UpdateCookieAccessTime`: Updates the last access time of a cookie.
    * `DeleteCookie`: Deletes a cookie from the store.
    * `DeleteAllInList`: Deletes multiple cookies.
    * `GetQueueLengthForTesting`: A testing utility.

4. **Look for database interaction details:**  Note the usage of SQLite-related classes like `sql::Database`, `sql::Statement`, and `sql::Transaction`. Also, look for mentions of database schema creation and migration (`CreateDatabaseSchema`, `DoMigrateDatabaseSchema`).

5. **Identify threading and asynchronicity:**  The code uses `base::SequencedTaskRunner` for background tasks. This indicates that database operations are likely performed on a separate thread to avoid blocking the main thread. The presence of callbacks (`LoadedCallback`) further reinforces asynchronous operation.

6. **Look for security and encryption:** The inclusion of `CookieCryptoDelegate` suggests that the store supports encryption of cookie data.

7. **Consider the interaction with `CanonicalCookie`:** The code works extensively with `net::CanonicalCookie`, the standard representation of cookies in Chromium.

8. **Identify metrics and logging:**  The code uses `UMA_HISTOGRAM_ENUMERATION` for recording metrics related to cookie loading and saving, and `net::NetLog` for logging events.

9. **Relate to JavaScript (if applicable):**  While the C++ code itself doesn't directly execute JavaScript, it *manages* the cookies that JavaScript running in web pages interacts with. JavaScript uses the `document.cookie` API to read and write cookies, and this C++ code is responsible for persisting those cookies.

10. **Formulate the summary based on the above observations:**  Structure the summary logically, starting with the core purpose and then elaborating on the key functionalities, threading model, and other important aspects.

11. **Address the specific questions in the prompt:**
    * **Functionalities:** List the observed functions based on the method analysis.
    * **Relationship with JavaScript:** Explain how the cookie store supports JavaScript's cookie handling.
    * **Logical Reasoning (Hypothetical Input/Output):**  Provide a simple example of adding and retrieving a cookie, highlighting the asynchronous nature.
    * **User/Programming Errors:** Identify common mistakes like incorrect file paths or database corruption.
    * **User Operation to Reach the Code:** Describe the typical user actions that trigger cookie storage (visiting websites, setting cookies via JavaScript).
    * **Overall Function:**  Provide a concise summary of the component's role.

By following these steps, we can generate a comprehensive and accurate summary of the provided C++ code, addressing all the points raised in the user's request.
这是Chromium网络栈中负责持久化存储Cookie的C++源代码文件。它使用SQLite数据库来存储和检索Cookie信息，以便在浏览器重启后依然能够保留Cookie。

**主要功能归纳：**

1. **Cookie的持久化存储：** 该文件实现了将 `net::CanonicalCookie` 对象存储到SQLite数据库中。它定义了数据库的schema（表结构），包括Cookie的各种属性，如域名、路径、名称、值、过期时间、安全标志等。

2. **Cookie的加载：** 它能够从SQLite数据库中读取Cookie信息，并将这些信息重新构建为 `net::CanonicalCookie` 对象。这个过程发生在浏览器启动或者需要加载特定域名的Cookie时。

3. **Cookie的增删改查操作：**  该文件提供了添加、更新（例如更新访问时间）、删除Cookie的功能。这些操作会被批量处理，并定期或在需要时提交到数据库。

4. **支持加密：**  如果配置了 `CookieCryptoDelegate`，它可以对Cookie的值进行加密存储，提高安全性。

5. **异步操作：**  数据库的读写操作通常在后台线程中进行，以避免阻塞浏览器的主线程。这通过 `base::SequencedTaskRunner` 实现。

6. **数据库版本管理和迁移：**  代码中定义了数据库的版本号 (`kCurrentVersionNumber`)，并在数据库schema发生变化时提供迁移机制 (`DoMigrateDatabaseSchema`)，以保证代码能够处理不同版本的数据库。

7. **性能优化：**  使用批量操作和后台线程来提高Cookie存储和检索的效率。

**与JavaScript的功能的关系和举例说明：**

虽然这段C++代码本身不执行JavaScript，但它是浏览器处理Cookie的核心部分，直接支撑着JavaScript中通过 `document.cookie` API 对Cookie的操作。

**举例：**

1. **JavaScript设置Cookie:** 当网页中的JavaScript代码执行 `document.cookie = "mycookie=myvalue; path=/";` 时，浏览器网络栈会将这个Cookie信息传递到 `SQLitePersistentCookieStore`，最终该文件会将 "mycookie" 的 name 和 "myvalue" 的 value 存储到 SQLite 数据库中。

2. **JavaScript读取Cookie:** 当网页中的JavaScript代码执行 `document.cookie` 尝试读取 Cookie 时，浏览器会先从内存中的 Cookie 缓存中查找，如果找不到，可能会触发 `SQLitePersistentCookieStore` 从 SQLite 数据库中加载相关的 Cookie 信息，然后返回给 JavaScript。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* **操作:**  调用 `AddCookie` 方法，传入一个表示新的 Cookie 信息的 `net::CanonicalCookie` 对象，例如：
  ```c++
  net::CanonicalCookie cookie("example.com", "mycookie", "myvalue", "/", base::Time::Now() + base::Days(7), base::Time::Now(), base::Time(), false, false, net::CookieSameSite::NO_RESTRICTION, net::COOKIE_PRIORITY_MEDIUM, false, net::CookieSourceScheme::kSecure, net::CookieSourceType::kHTTP);
  backend_->AddCookie(cookie);
  ```

**输出:**

* 该 Cookie 的信息会被序列化并插入到 SQLite 数据库的 `cookies` 表中。
* 如果数据库操作成功，后续的 `Load` 操作应该能够读取到这个新添加的 Cookie。

**假设输入:**

* **操作:** 调用 `DeleteCookie` 方法，传入一个表示要删除的 Cookie 的 `net::CanonicalCookie` 对象，该 Cookie 已经在数据库中存在。

**输出:**

* 数据库中与该 Cookie 匹配的记录将被删除。
* 后续的 `Load` 操作将不再返回该 Cookie。

**用户或者编程常见的使用错误举例说明：**

1. **文件路径错误：**  如果在创建 `SQLitePersistentCookieStore` 时提供了错误的数据库文件路径，会导致数据库创建或加载失败，Cookie无法持久化。
   ```c++
   base::FilePath wrong_path("/non/existent/directory/Cookies");
   auto cookie_store = new SQLitePersistentCookieStore(
       wrong_path, ...); // 可能导致初始化失败
   ```
   **现象:** 浏览器无法保存或加载 Cookie，用户可能会遇到需要频繁登录的情况。

2. **数据库文件损坏：**  如果 `Cookies` 数据库文件被意外损坏（例如，文件系统错误、程序崩溃时写入不完整），会导致加载 Cookie 时出错。
   **现象:**  浏览器可能无法启动，或者启动后无法正确加载 Cookie，导致网站功能异常。

3. **权限问题：**  运行浏览器的用户没有对 Cookie 数据库文件所在目录的读写权限，也会导致 Cookie 无法持久化。
   **现象:**  与文件路径错误类似，浏览器无法保存或加载 Cookie。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户访问一个网站:**  用户在浏览器地址栏输入网址或点击链接访问一个网站（例如 `https://www.example.com`）。
2. **网站发送Set-Cookie头:**  服务器在 HTTP 响应头中包含 `Set-Cookie` 指令，指示浏览器设置一个或多个 Cookie。例如：`Set-Cookie: mycookie=myvalue; path=/; Secure; HttpOnly`。
3. **浏览器接收Set-Cookie头:**  Chromium 的网络栈接收到这个响应头。
4. **解析Set-Cookie头:**  网络栈中的 Cookie 管理模块会解析 `Set-Cookie` 头，创建一个 `net::CanonicalCookie` 对象。
5. **调用`AddCookie`:**  为了持久化这个 Cookie，网络栈会调用 `SQLitePersistentCookieStore` 的 `AddCookie` 方法，将该 `net::CanonicalCookie` 对象传递给后台的 `Backend` 处理。
6. **`Backend`操作数据库:** `Backend` 接收到 `AddCookie` 的请求，会将 Cookie 的信息插入到 SQLite 数据库中。

**反向调试线索：** 如果在 `net/extras/sqlite/sqlite_persistent_cookie_store.cc` 中设置断点，并观察到 `AddCookie` 方法被调用，可以追溯到是哪个网站设置了 Cookie，以及 Cookie 的具体属性。同样，在 `Load` 相关的方法中设置断点，可以了解浏览器在哪些场景下会加载 Cookie。

**功能归纳（第1部分）：**

该文件的主要功能是 **提供一个基于 SQLite 数据库的持久化 Cookie 存储机制**。它负责将 `net::CanonicalCookie` 对象安全可靠地保存到磁盘，并在需要时加载这些 Cookie，从而保证用户在关闭和重新打开浏览器后，网站仍然能够识别用户身份或保存用户的偏好设置。它还处理与 JavaScript Cookie API 的交互，以及数据库的版本管理和潜在的加密需求。

### 提示词
```
这是目录为net/extras/sqlite/sqlite_persistent_cookie_store.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/extras/sqlite/sqlite_persistent_cookie_store.h"

#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <tuple>
#include <unordered_set>

#include "base/feature_list.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/lock.h"
#include "base/task/sequenced_task_runner.h"
#include "base/thread_annotations.h"
#include "base/time/time.h"
#include "base/types/optional_ref.h"
#include "base/values.h"
#include "build/build_config.h"
#include "crypto/sha2.h"
#include "net/base/features.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/cookie_constants.h"
#include "net/cookies/cookie_util.h"
#include "net/extras/sqlite/cookie_crypto_delegate.h"
#include "net/extras/sqlite/sqlite_persistent_store_backend_base.h"
#include "net/log/net_log.h"
#include "net/log/net_log_values.h"
#include "sql/error_delegate_util.h"
#include "sql/meta_table.h"
#include "sql/statement.h"
#include "sql/transaction.h"
#include "url/gurl.h"
#include "url/third_party/mozilla/url_parse.h"

using base::Time;

namespace {

static constexpr int kHoursInOneWeek = 24 * 7;
static constexpr int kHoursInOneYear = 24 * 365;

base::Value::Dict CookieKeyedLoadNetLogParams(
    const std::string& key,
    net::NetLogCaptureMode capture_mode) {
  if (!net::NetLogCaptureIncludesSensitive(capture_mode))
    return base::Value::Dict();
  base::Value::Dict dict;
  dict.Set("key", key);
  return dict;
}

// Used to populate a histogram for problems when loading cookies.
//
// Please do not reorder or remove entries. New entries must be added to the
// end of the list, just before kMaxValue.
enum class CookieLoadProblem {
  // Entry decryption failed.
  kDecryptFailed = 0,
  // Deprecated 03/2021.
  // COOKIE_LOAD_PROBLEM_DECRYPT_TIMEOUT = 1,
  // Cookie canonical form check failed.
  kNotCanonical = 2,
  // Could not open or initialize database.
  kOpenDb = 3,
  // Attempt to delete broken (and related) rows failed.
  KRecoveryFailed = 4,
  // Attempt to delete cookies with matching top_frame_site_keys failed. Added
  // in https://crrev.com/3153340 (M96).
  kDeleteCookiePartitionFailed = 5,
  // Hash verification of encrypted value failed. Added in
  // https://crrev.com/5875192 (M131).
  kHashFailed = 6,
  // Cookie was encrypted but no crypto delegate was passed. Added in
  // https://crrev.com/5875192 (M131).
  kNoCrypto = 7,
  // Cookie had values in both the plaintext and encrypted fields of the
  // database. Added in https://crrev.com/5875190 (M131).
  kValuesExistInBothEncryptedAndPlaintext = 8,
  kMaxValue = kValuesExistInBothEncryptedAndPlaintext,
};

// Used to populate a histogram for problems when committing cookies.
//
// Please do not reorder or remove entries. New entries must be added to the
// end of the list, just before kMaxValue.
enum class CookieCommitProblem {
  // Entry encryption failed.
  kEncryptFailed = 0,
  // Adding cookie to DB failed.
  kAdd = 1,
  // Updating access time of cookie failed.
  kUpdateAccess = 2,
  // Deleting cookie failed.
  kDelete = 3,
  // Committing the transaction failed.
  kTransactionCommit = 4,
  kMaxValue = kTransactionCommit,
};

void RecordCookieLoadProblem(CookieLoadProblem event) {
  UMA_HISTOGRAM_ENUMERATION("Cookie.LoadProblem", event);
}

void RecordCookieCommitProblem(CookieCommitProblem event) {
  UMA_HISTOGRAM_ENUMERATION("Cookie.CommitProblem", event);
}

// Records metrics around the age in hours of a cookie loaded from the store via
// MakeCookiesFromSQLStatement for use by some browser context.
void HistogramCookieAge(const net::CanonicalCookie& cookie) {
  if (cookie.IsPersistent()) {
    // We are studying the age of script cookies in active use. This record is
    // split into two histograms to improve resolution.
    if (!cookie.LastUpdateDate().is_null() &&
        cookie.SourceType() == net::CookieSourceType::kScript) {
      const int script_cookie_age_since_last_update_in_hours =
          (Time::Now() - cookie.LastUpdateDate()).InHours();
      if (script_cookie_age_since_last_update_in_hours > kHoursInOneWeek) {
        UMA_HISTOGRAM_CUSTOM_COUNTS(
            "Cookie.ScriptAgeSinceLastUpdateInHoursGTOneWeek",
            script_cookie_age_since_last_update_in_hours, kHoursInOneWeek + 1,
            kHoursInOneYear, 100);
      } else {
        UMA_HISTOGRAM_CUSTOM_COUNTS(
            "Cookie.ScriptAgeSinceLastUpdateInHoursLTEOneWeek",
            script_cookie_age_since_last_update_in_hours, 1,
            kHoursInOneWeek + 1, 100);
      }
    }
  } else {
    // We are studying the age of session cookies in active use. The record is
    // split into two histograms to improve resolution.
    if (!cookie.CreationDate().is_null()) {
      const int session_cookie_age_in_hours =
          (Time::Now() - cookie.CreationDate()).InHours();
      if (session_cookie_age_in_hours > kHoursInOneWeek) {
        UMA_HISTOGRAM_CUSTOM_COUNTS("Cookie.SessionAgeInHoursGTOneWeek2",
                                    session_cookie_age_in_hours,
                                    kHoursInOneWeek + 1, kHoursInOneYear, 100);
      } else {
        UMA_HISTOGRAM_CUSTOM_COUNTS("Cookie.SessionAgeInHoursLTEOneWeek2",
                                    session_cookie_age_in_hours, 1,
                                    kHoursInOneWeek + 1, 100);
      }
    }
    // Similar to the above, except this metric tracks time since the cookie was
    // last updated and not just initial creation.
    if (!cookie.LastUpdateDate().is_null()) {
      const int session_cookie_age_since_last_update_in_hours =
          (Time::Now() - cookie.LastUpdateDate()).InHours();
      if (session_cookie_age_since_last_update_in_hours > kHoursInOneWeek) {
        UMA_HISTOGRAM_CUSTOM_COUNTS(
            "Cookie.SessionAgeSinceLastUpdateInHoursGTOneWeek",
            session_cookie_age_since_last_update_in_hours, kHoursInOneWeek + 1,
            kHoursInOneYear, 100);
      } else {
        UMA_HISTOGRAM_CUSTOM_COUNTS(
            "Cookie.SessionAgeSinceLastUpdateInHoursLTEOneWeek",
            session_cookie_age_since_last_update_in_hours, 1,
            kHoursInOneWeek + 1, 100);
      }
    }
  }
}

}  // namespace

namespace net {

base::TaskPriority GetCookieStoreBackgroundSequencePriority() {
  return base::TaskPriority::USER_BLOCKING;
}

namespace {

// Version number of the database.
//
// Version 24 - 2024/08/15 - https://crrev.com/c/5792044
// Version 23 - 2024/04/10 - https://crrev.com/c/5169630
// Version 22 - 2024/03/22 - https://crrev.com/c/5378176
// Version 21 - 2023/11/22 - https://crrev.com/c/5049032
// Version 20 - 2023/11/14 - https://crrev.com/c/5030577
// Version 19 - 2023/09/22 - https://crrev.com/c/4704672
// Version 18 - 2022/04/19 - https://crrev.com/c/3594203
//
// Versions older than two years should be removed and marked as unsupported.
// This was last done in February 2024. https://crrev.com/c/5300252
// Be sure to update SQLitePersistentCookieStoreTest.TestInvalidVersionRecovery
// to test the latest unsupported version number.
//
// Unsupported versions:
// Version 17 - 2022/01/25 - https://crrev.com/c/3416230
// Version 16 - 2021/09/10 - https://crrev.com/c/3152897
// Version 15 - 2021/07/01 - https://crrev.com/c/3001822
// Version 14 - 2021/02/23 - https://crrev.com/c/2036899
// Version 13 - 2020/10/28 - https://crrev.com/c/2505468
// Version 12 - 2019/11/20 - https://crrev.com/c/1898301
// Version 11 - 2019/04/17 - https://crrev.com/c/1570416
// Version 10 - 2018/02/13 - https://crrev.com/c/906675
// Version 9  - 2015/04/17 - https://codereview.chromium.org/1083623003
// Version 8  - 2015/02/23 - https://codereview.chromium.org/876973003
// Version 7  - 2013/12/16 - https://codereview.chromium.org/24734007
// Version 6  - 2013/04/23 - https://codereview.chromium.org/14208017
// Version 5  - 2011/12/05 - https://codereview.chromium.org/8533013
// Version 4  - 2009/09/01 - https://codereview.chromium.org/183021
//

// Version 24 adds a SHA256 hash of the domain value to front of the the
// encrypted_value.
//
// Version 23 adds the value for has_cross_site_ancestor and updates any
// preexisting cookies with a source_scheme value of kUnset and a is_secure of
// true to have a source_scheme value of kSecure.
//
// Version 22 adds one new field: "source_type". This reflects the source of
// the last set/update to the cookie (unknown, http, script, other). Existing
// cookies in the DB default to "unknown".
//
// Version 21 removes the is_same_party column.
//
// Version 20 changes the UNIQUE constraint to include the source_scheme and
// source_port and begins to insert, update, and delete cookies based on their
// source_scheme and source_port.
//
// Version 19 caps expires_utc to no more than 400 days in the future for all
// stored cookies with has_expires. This is in compliance with section 7.2 of
// draft-ietf-httpbis-rfc6265bis-12.
//
// Version 18 adds one new field: "last_update_utc" (if not 0 this represents
// the last time the cookie was updated). This is distinct from creation_utc
// which is carried forward when cookies are updated.
//
// Version 17 fixes crbug.com/1290841: Bug in V16 migration.
//
// Version 16 changes the unique constraint's order of columns to have
// top_frame_site_key be after host_key. This allows us to use the internal
// index created by the UNIQUE keyword without to load cookies by domain
// without us needing to supply a top_frame_site_key. This is necessary because
// CookieMonster tracks pending cookie loading tasks by host key only.
// Version 16 also removes the DEFAULT value from several columns.
//
// Version 15 adds one new field: "top_frame_site_key" (if not empty then the
// string is the scheme and site of the topmost-level frame the cookie was
// created in). This field is deserialized into the cookie's partition key.
// top_frame_site_key is *NOT* the site-for-cookies when the cookie was created.
// In migrating, top_frame_site_key defaults to empty string. This change also
// changes the uniqueness constraint on cookies to include the
// top_frame_site_key as well.
//
// Version 14 just reads all encrypted cookies and re-writes them out again to
// make sure the new encryption key is in use. This active migration only
// happens on Windows, on other OS, this migration is a no-op.
//
// Version 13 adds two new fields: "source_port" (the port number of the source
// origin, and "is_same_party" (boolean indicating whether the cookie had a
// SameParty attribute). In migrating, source_port defaults to -1
// (url::PORT_UNSPECIFIED) for old entries for which the source port is unknown,
// and is_same_party defaults to false.
//
// Version 12 adds a column for "source_scheme" to store whether the
// cookie was set from a URL with a cryptographic scheme.
//
// Version 11 renames the "firstpartyonly" column to "samesite", and changes any
// stored values of kCookieSameSiteNoRestriction into
// kCookieSameSiteUnspecified to reflect the fact that those cookies were set
// without a SameSite attribute specified. Support for a value of
// kCookieSameSiteExtended for "samesite" was added, however, that value is now
// deprecated and is mapped to CookieSameSite::UNSPECIFIED when loading from the
// database.
//
// Version 10 removes the uniqueness constraint on the creation time (which
// was not propagated up the stack and caused problems in
// http://crbug.com/800414 and others).  It replaces that constraint by a
// constraint on (name, domain, path), which is spec-compliant (see
// https://tools.ietf.org/html/rfc6265#section-5.3 step 11).  Those fields
// can then be used in place of the creation time for updating access
// time and deleting cookies.
// Version 10 also marks all booleans in the store with an "is_" prefix
// to indicated their booleanness, as SQLite has no such concept.
//
// Version 9 adds a partial index to track non-persistent cookies.
// Non-persistent cookies sometimes need to be deleted on startup. There are
// frequently few or no non-persistent cookies, so the partial index allows the
// deletion to be sped up or skipped, without having to page in the DB.
//
// Version 8 adds "first-party only" cookies.
//
// Version 7 adds encrypted values.  Old values will continue to be used but
// all new values written will be encrypted on selected operating systems.  New
// records read by old clients will simply get an empty cookie value while old
// records read by new clients will continue to operate with the unencrypted
// version.  New and old clients alike will always write/update records with
// what they support.
//
// Version 6 adds cookie priorities. This allows developers to influence the
// order in which cookies are evicted in order to meet domain cookie limits.
//
// Version 5 adds the columns has_expires and is_persistent, so that the
// database can store session cookies as well as persistent cookies. Databases
// of version 5 are incompatible with older versions of code. If a database of
// version 5 is read by older code, session cookies will be treated as normal
// cookies. Currently, these fields are written, but not read anymore.
//
// In version 4, we migrated the time epoch.  If you open the DB with an older
// version on Mac or Linux, the times will look wonky, but the file will likely
// be usable. On Windows version 3 and 4 are the same.
//
// Version 3 updated the database to include the last access time, so we can
// expire them in decreasing order of use when we've reached the maximum
// number of cookies.
const int kCurrentVersionNumber = 24;
const int kCompatibleVersionNumber = 24;

}  // namespace

// This class is designed to be shared between any client thread and the
// background task runner. It batches operations and commits them on a timer.
//
// SQLitePersistentCookieStore::Load is called to load all cookies.  It
// delegates to Backend::Load, which posts a Backend::LoadAndNotifyOnDBThread
// task to the background runner.  This task calls Backend::ChainLoadCookies(),
// which repeatedly posts itself to the BG runner to load each eTLD+1's cookies
// in separate tasks.  When this is complete, Backend::CompleteLoadOnIOThread is
// posted to the client runner, which notifies the caller of
// SQLitePersistentCookieStore::Load that the load is complete.
//
// If a priority load request is invoked via SQLitePersistentCookieStore::
// LoadCookiesForKey, it is delegated to Backend::LoadCookiesForKey, which posts
// Backend::LoadKeyAndNotifyOnDBThread to the BG runner. That routine loads just
// that single domain key (eTLD+1)'s cookies, and posts a Backend::
// CompleteLoadForKeyOnIOThread to the client runner to notify the caller of
// SQLitePersistentCookieStore::LoadCookiesForKey that that load is complete.
//
// Subsequent to loading, mutations may be queued by any thread using
// AddCookie, UpdateCookieAccessTime, and DeleteCookie. These are flushed to
// disk on the BG runner every 30 seconds, 512 operations, or call to Flush(),
// whichever occurs first.
class SQLitePersistentCookieStore::Backend
    : public SQLitePersistentStoreBackendBase {
 public:
  Backend(const base::FilePath& path,
          scoped_refptr<base::SequencedTaskRunner> client_task_runner,
          scoped_refptr<base::SequencedTaskRunner> background_task_runner,
          bool restore_old_session_cookies,
          std::unique_ptr<CookieCryptoDelegate> crypto_delegate,
          bool enable_exclusive_access)
      : SQLitePersistentStoreBackendBase(path,
                                         /* histogram_tag = */ "Cookie",
                                         kCurrentVersionNumber,
                                         kCompatibleVersionNumber,
                                         std::move(background_task_runner),
                                         std::move(client_task_runner),
                                         enable_exclusive_access),
        restore_old_session_cookies_(restore_old_session_cookies),
        crypto_(std::move(crypto_delegate)) {}

  Backend(const Backend&) = delete;
  Backend& operator=(const Backend&) = delete;

  // Creates or loads the SQLite database.
  void Load(LoadedCallback loaded_callback);

  // Loads cookies for the domain key (eTLD+1). If no key is supplied then this
  // behaves identically to `Load`.
  void LoadCookiesForKey(base::optional_ref<const std::string> key,
                         LoadedCallback loaded_callback);

  // Steps through all results of |statement|, makes a cookie from each, and
  // adds the cookie to |cookies|. Returns true if everything loaded
  // successfully.
  bool MakeCookiesFromSQLStatement(
      std::vector<std::unique_ptr<CanonicalCookie>>& cookies,
      sql::Statement& statement,
      std::unordered_set<std::string>& top_frame_site_keys_to_delete);

  // Batch a cookie addition.
  void AddCookie(const CanonicalCookie& cc);

  // Batch a cookie access time update.
  void UpdateCookieAccessTime(const CanonicalCookie& cc);

  // Batch a cookie deletion.
  void DeleteCookie(const CanonicalCookie& cc);

  size_t GetQueueLengthForTesting();

  // Post background delete of all cookies that match |cookies|.
  void DeleteAllInList(const std::list<CookieOrigin>& cookies);

 private:
  // You should call Close() before destructing this object.
  ~Backend() override {
    DCHECK_EQ(0u, num_pending_);
    DCHECK(pending_.empty());
  }

  // Database upgrade statements.
  std::optional<int> DoMigrateDatabaseSchema() override;

  class PendingOperation {
   public:
    enum OperationType {
      COOKIE_ADD,
      COOKIE_UPDATEACCESS,
      COOKIE_DELETE,
    };

    PendingOperation(OperationType op, const CanonicalCookie& cc)
        : op_(op), cc_(cc) {}

    OperationType op() const { return op_; }
    const CanonicalCookie& cc() const { return cc_; }

   private:
    OperationType op_;
    CanonicalCookie cc_;
  };

 private:
  // Creates or loads the SQLite database on background runner. Supply domain
  // key (eTLD+1) to only load for this domain.
  void LoadAndNotifyInBackground(base::optional_ref<const std::string> key,
                                 LoadedCallback loaded_callback);

  // Notifies the CookieMonster when loading completes for a specific domain key
  // or for all domain keys. Triggers the callback and passes it all cookies
  // that have been loaded from DB since last IO notification.
  void NotifyLoadCompleteInForeground(LoadedCallback loaded_callback,
                                      bool load_success);

  // Called from Load when crypto gets obtained.
  void CryptoHasInitFromLoad(base::optional_ref<const std::string> key,
                             LoadedCallback loaded_callback);

  // Initialize the Cookies table.
  bool CreateDatabaseSchema() override;

  // Initialize the data base.
  bool DoInitializeDatabase() override;

  // Loads cookies for the next domain key from the DB, then either reschedules
  // itself or schedules the provided callback to run on the client runner (if
  // all domains are loaded).
  void ChainLoadCookies(LoadedCallback loaded_callback);

  // Load all cookies for a set of domains/hosts. The error recovery code
  // assumes |key| includes all related domains within an eTLD + 1.
  bool LoadCookiesForDomains(const std::set<std::string>& key);

  void DeleteTopFrameSiteKeys(
      const std::unordered_set<std::string>& top_frame_site_keys);

  // Batch a cookie operation (add or delete)
  void BatchOperation(PendingOperation::OperationType op,
                      const CanonicalCookie& cc);
  // Commit our pending operations to the database.
  void DoCommit() override;

  void DeleteSessionCookiesOnStartup();

  void BackgroundDeleteAllInList(const std::list<CookieOrigin>& cookies);

  // Shared code between the different load strategies to be used after all
  // cookies have been loaded.
  void FinishedLoadingCookies(LoadedCallback loaded_callback, bool success);

  void RecordOpenDBProblem() override {
    RecordCookieLoadProblem(CookieLoadProblem::kOpenDb);
  }

  void RecordDBMigrationProblem() override {
    RecordCookieLoadProblem(CookieLoadProblem::kOpenDb);
  }

  typedef std::list<std::unique_ptr<PendingOperation>> PendingOperationsForKey;
  typedef std::map<CanonicalCookie::StrictlyUniqueCookieKey,
                   PendingOperationsForKey>
      PendingOperationsMap;
  PendingOperationsMap pending_ GUARDED_BY(lock_);
  PendingOperationsMap::size_type num_pending_ GUARDED_BY(lock_) = 0;
  // Guard |cookies_|, |pending_|, |num_pending_|.
  base::Lock lock_;

  // Temporary buffer for cookies loaded from DB. Accumulates cookies to reduce
  // the number of messages sent to the client runner. Sent back in response to
  // individual load requests for domain keys or when all loading completes.
  std::vector<std::unique_ptr<CanonicalCookie>> cookies_ GUARDED_BY(lock_);

  // Map of domain keys(eTLD+1) to domains/hosts that are to be loaded from DB.
  std::map<std::string, std::set<std::string>> keys_to_load_;

  // If false, we should filter out session cookies when reading the DB.
  bool restore_old_session_cookies_;

  // Crypto instance, or nullptr if encryption is disabled.
  std::unique_ptr<CookieCryptoDelegate> crypto_;
};

namespace {

// Possible values for the 'priority' column.
enum DBCookiePriority {
  kCookiePriorityLow = 0,
  kCookiePriorityMedium = 1,
  kCookiePriorityHigh = 2,
};

DBCookiePriority CookiePriorityToDBCookiePriority(CookiePriority value) {
  switch (value) {
    case COOKIE_PRIORITY_LOW:
      return kCookiePriorityLow;
    case COOKIE_PRIORITY_MEDIUM:
      return kCookiePriorityMedium;
    case COOKIE_PRIORITY_HIGH:
      return kCookiePriorityHigh;
  }

  NOTREACHED();
}

CookiePriority DBCookiePriorityToCookiePriority(DBCookiePriority value) {
  switch (value) {
    case kCookiePriorityLow:
      return COOKIE_PRIORITY_LOW;
    case kCookiePriorityMedium:
      return COOKIE_PRIORITY_MEDIUM;
    case kCookiePriorityHigh:
      return COOKIE_PRIORITY_HIGH;
  }

  NOTREACHED();
}

// Possible values for the 'samesite' column
enum DBCookieSameSite {
  kCookieSameSiteUnspecified = -1,
  kCookieSameSiteNoRestriction = 0,
  kCookieSameSiteLax = 1,
  kCookieSameSiteStrict = 2,
  // Deprecated, mapped to kCookieSameSiteUnspecified.
  kCookieSameSiteExtended = 3
};

DBCookieSameSite CookieSameSiteToDBCookieSameSite(CookieSameSite value) {
  switch (value) {
    case CookieSameSite::NO_RESTRICTION:
      return kCookieSameSiteNoRestriction;
    case CookieSameSite::LAX_MODE:
      return kCookieSameSiteLax;
    case CookieSameSite::STRICT_MODE:
      return kCookieSameSiteStrict;
    case CookieSameSite::UNSPECIFIED:
      return kCookieSameSiteUnspecified;
  }
}

CookieSameSite DBCookieSameSiteToCookieSameSite(DBCookieSameSite value) {
  CookieSameSite samesite = CookieSameSite::UNSPECIFIED;
  switch (value) {
    case kCookieSameSiteNoRestriction:
      samesite = CookieSameSite::NO_RESTRICTION;
      break;
    case kCookieSameSiteLax:
      samesite = CookieSameSite::LAX_MODE;
      break;
    case kCookieSameSiteStrict:
      samesite = CookieSameSite::STRICT_MODE;
      break;
    // SameSite=Extended is deprecated, so we map to UNSPECIFIED.
    case kCookieSameSiteExtended:
    case kCookieSameSiteUnspecified:
      samesite = CookieSameSite::UNSPECIFIED;
      break;
  }
  return samesite;
}

// Possible values for the `source` column
enum DBCookieSourceType {
  kDBCookieSourceTypeUnknown = 0,
  kDBCookieSourceTypeHTTP = 1,
  kDBCookieSourceTypeScript = 2,
  kDBCookieSourceTypeOther = 3,
};

DBCookieSourceType CookieSourceTypeToDBCookieSourceType(
    CookieSourceType value) {
  switch (value) {
    case CookieSourceType::kUnknown:
      return kDBCookieSourceTypeUnknown;
    case CookieSourceType::kHTTP:
      return kDBCookieSourceTypeHTTP;
    case CookieSourceType::kScript:
      return kDBCookieSourceTypeScript;
    case CookieSourceType::kOther:
      return kDBCookieSourceTypeOther;
  }
}

CookieSourceType DBCookieSourceTypeToCookieSourceType(
    DBCookieSourceType value) {
  switch (value) {
    case kDBCookieSourceTypeUnknown:
      return CookieSourceType::kUnknown;
    case kDBCookieSourceTypeHTTP:
      return CookieSourceType::kHTTP;
    case kDBCookieSourceTypeScript:
      return CookieSourceType::kScript;
    case kDBCookieSourceTypeOther:
      return CookieSourceType::kOther;
    default:
      return CookieSourceType::kUnknown;
  }
}

CookieSourceScheme DBToCookieSourceScheme(int value) {
  int enum_max_value = static_cast<int>(CookieSourceScheme::kMaxValue);

  if (value < 0 || value > enum_max_value) {
    DLOG(WARNING) << "DB read of cookie's source scheme is invalid. Resetting "
                     "value to unset.";
    value = static_cast<int>(
        CookieSourceScheme::kUnset);  // Reset value to a known, useful, state.
  }

  return static_cast<CookieSourceScheme>(value);
}

// Increments a specified TimeDelta by the duration between this object's
// constructor and destructor. Not thread safe. Multiple instances may be
// created with the same delta instance as long as their lifetimes are nested.
// The shortest lived instances have no impact.
class IncrementTimeDelta {
 public:
  explicit IncrementTimeDelta(base::TimeDelta* delta)
      : delta_(delta), original_value_(*delta), start_(base::Time::Now()) {}

  IncrementTimeDelta(const IncrementTimeDelta&) = delete;
  IncrementTimeDelta& operator=(const IncrementTimeDelta&) = delete;

  ~IncrementTimeDelta() {
    *delta_ = original_value_ + base::Time::Now() - start_;
  }

 private:
  raw_ptr<base::TimeDelta> delta_;
  base::TimeDelta original_value_;
  base::Time start_;
};

bool CreateV20Schema(sql::Database* db) {
  CHECK(!db->DoesTableExist("cookies"));

  static constexpr char kCreateTableQuery[] =
      "CREATE TABLE cookies("
      "creation_utc INTEGER NOT NULL,"
      "host_key TEXT NOT NULL,"
      "top_frame_site_key TEXT NOT NULL,"
      "name TEXT NOT NULL,"
      "value TEXT NOT NULL,"
      "encrypted_value BLOB NOT NULL,"
      "path TEXT NOT NULL,"
      "expires_utc INTEGER NOT NULL,"
      "is_secure INTEGER NOT NULL,"
      "is_httponly INTEGER NOT NULL,"
      "last_access_utc INTEGER NOT NULL,"
      "has_expires INTEGER NOT NULL,"
      "is_persistent INTEGER NOT NULL,"
      "priority INTEGER NOT NULL,"
      "samesite INTEGER NOT NULL,"
      "source_scheme INTEGER NOT NULL,"
      "source_port INTEGER NOT NULL,"
      "is_same_party INTEGER NOT NULL,"
      "last_update_utc INTEGER NOT NULL);";

  static constexpr char kCreateIndexQuery[] =
      "CREATE UNIQUE INDEX cookies_unique_index "
      "ON cookies(host_key, top_frame_site_key, name, path, source_scheme, "
      "source_port)";

  return db->Execute(kCreateTableQuery) && db->Execute(kCreateIndexQuery);
}

bool CreateV21Schema(sql::Database* db) {
  CHECK(!db->DoesTableExist("cookies"));

  static constexpr char kCreateTableQuery[] =
      "CREATE TABLE cookies("
      "creation_utc INTEGER NOT NULL,"
      "host_key TEXT NOT NULL,"
      "top_frame_site_key TEXT NOT NULL,"
      "name TEXT NOT NULL,"
      "value TEXT NOT NULL,"
      "encrypted_value BLOB NOT NULL,"
      "path TEXT NOT NULL,"
      "expires_utc INTEGER NOT NULL,"
      "is_secure INTEGER NOT NULL,"
      "is_httponly INTEGER NOT NULL,"
      "last_access_utc INTEGER NOT NULL,"
      "has_expires INTEGER NOT NULL,"
      "is_persistent INTEGER NOT NULL,"
      "priority INTEGER NOT NULL,"
      "samesite INTEGER NOT NULL,"
      "source_scheme INTEGER NOT NULL,"
      "source_port INTEGER NOT NULL,"
      "last_update_utc INTEGER NOT NULL);";

  static constexpr char kCreateIndexQuery[] =
      "CREATE UNIQUE INDEX cookies_unique_index "
      "ON cookies(host_key, top_frame_site_key, name, path, source_scheme, "
      "source_port)";

  return db->Execute(kCreateTableQuery) && db->Execute(kCreateIndexQuery);
}

bool CreateV22Schema(sql::Database* db) {
  CHECK(!db->DoesTableExist("cookies"));

  static constexpr char kCreateTableQuery[] =
      "CREATE TABLE cookies("
      "creation_utc INTEGER NOT NULL,"
      "host_key TEXT NOT NULL,"
      "top_frame_site_key TEXT NOT NULL,"
      "name TEXT NOT NULL,"
      "value TEXT NOT NULL,"
      "encrypted_value BLOB NOT NULL,"
      "path TEXT NOT NULL,"
      "expires_utc INTEGER NOT NULL,"
      "is_secure INTEGER NOT NULL,"
      "is_httponly INTEGER NOT NULL,"
      "last_access_utc INTEGER NOT NULL,"
      "has_expires INTEGER NOT NULL,"
      "is_persistent INTEGER NOT NULL,"
      "priority INTEGER NOT NULL,"
      "samesite INTEGER NOT NULL,"
      "source_scheme INTEGER NOT NULL,"
      "source_port INTEGER NOT NULL,"
      "last_update_utc INTEGER NOT NULL,"
      "source_type INTEGER NOT NULL);";

  static constexpr char kCreateIndexQuery[] =
      "CREATE UNIQUE INDEX cookies_unique_index "
      "ON cookies(host_key, top_frame_site_key, name, path, source_scheme, "
      "source_port)";

  return db->Execute(kCreateTableQuery) && db->Execute(kCreateIndexQuery);
}

bool CreateV23Schema(sql::Database* db) {
  CHECK(!db->DoesTableExist("cookies"));

  static constexpr char kCreateTableQuery[] =
      "CREATE TABLE cookies("
      "creation_utc INTEGER NOT NULL,"
      "host_key TEXT NOT NULL,"
      "top_frame_site_key TEXT NOT NULL,"
      "name TEXT NOT NULL,"
      "value TEXT NOT NULL,"
      "encrypted_value BLOB NOT NULL,"
      "path TEXT NOT NULL,"
      "expires_utc INTEGER NOT NULL,"
      "is_secure INTEGER NOT NULL,"
      "is_httponly INTEGER NOT NULL,"
      "last_access_utc INTEGER NOT NULL,"
      "has_expires INTEGER NOT NULL,"
      "is_persistent INTEGER NOT NULL,"
      "priority INTEGER NOT NULL,"
      "samesite INTEGER NOT NULL,"
      "source_scheme INTEGER NOT NULL,"
      "source_port INTEGER NOT NULL,"
      "last_update_utc INTEGER NOT NULL,"
      "source_type INTEGER NOT NULL,"
      "has_cross_site_ancestor INTEGER NOT NULL);";

  static constexpr char kCreateIndexQuery[] =
      "CREATE UNIQUE INDEX cookies_unique_index "
      "ON cookies(host_key, top_frame_site_key, has_cross_site_ancestor, "
      "name, path, source_scheme, source_port)";

  return db->Execute(kCreateTableQuery) && db->Execute(kCreateIndexQuery);
}

// v24 schema is identical to v23 schema.
bool CreateV24Schema(sql::Database* db) {
  return CreateV23Schema(db);
}

}  // namespace

void SQLitePersistentCookieStore::Backend::Load(
    LoadedCallback loaded_callback) {
  LoadCookiesForKey(std::nullopt, std::move(loaded_callback));
}

void SQLitePersistentCookieStore::Backend::LoadCookiesForKey(
    base::optional_ref<const std::string> key,
    LoadedCallback loaded_callback) {
  if (crypto_) {
    crypto_->Init(base::BindOnce(&Backend::CryptoHasInitFromLoad, this,
                                 key.CopyAsOptional(),
                                 std::move(loaded_callback)));
  } else {
    CryptoHasInitFromLoad(key, std::move(loaded_callback));
  }
}

void SQLitePersistentCookieStore::Backend::CryptoHasInitFromLoad(
    base::optional_ref<const std::string> key,
    LoadedCallback loaded_callback) {
  PostBackgroundTask(
      FROM_HERE,
      base::BindOnce(&Backend::LoadAndNotifyInBackground, this,
                     key.CopyAsOptional(), std::move(loaded_callback)));
}

void SQLitePersistentCookieStore::Backend::LoadAndNotifyInBackground(
    base::optional_ref<const std::string> key,
    LoadedCallback loaded_callback) {
  DCHECK(background_task_runner()->RunsTasksInCurrentSequence());
  bool success = false;

  if (InitializeDatabase()) {
    if (!key.has_value()) {
      ChainLoadCookies(std::move(loaded_callback));
      return;
    }

    auto it = keys_to_load_.find(*key);
    if (it != keys_to_load_.end()) {
      success = LoadCookiesForDomains(it->second);
      keys_to_load_.erase(it);
    } else {
      success = true;
    }
  }

  FinishedLoadingCookies(std::move(loaded_callback), success);
}

void SQLitePersistentCookieStore::Backend::NotifyLoadCompleteInForeground(
    LoadedCallback loaded_callback,
    bool load_success) {
  DCHECK(client_task_runner()->RunsTasksInCurrentSequence());

  std::vector<std::unique_ptr<CanonicalCookie>> cookies;
  {
    base::AutoLock locked(lock_);
    co
```
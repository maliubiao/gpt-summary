Response:
The user is asking for an analysis of the C++ source code file `net/proxy_resolution/proxy_config_service_linux_unittest.cc` from the Chromium project. They want to know:

1. **Functionality:** What does this file do?
2. **Relation to JavaScript:** Does it interact with JavaScript, and if so, how?
3. **Logical Reasoning (with examples):** If the code involves logical deductions, provide example inputs and outputs.
4. **Common Usage Errors:**  Are there common mistakes users or developers might make when interacting with this code?
5. **User Journey (Debugging):** How does a user's action lead to this code being executed during debugging?
6. **Summary:** A high-level summary of the file's purpose.

**Mental Process:**

1. **Identify the Core Purpose:** The file name strongly suggests it's a unit test file (`_unittest.cc`) for `ProxyConfigServiceLinux`. Unit tests verify the behavior of a specific code unit.

2. **Examine Includes:** The included headers provide clues:
    * `net/proxy_resolution/proxy_config_service_linux.h`:  The header for the class being tested.
    * `net/proxy_resolution/proxy_config.h`: Defines the `ProxyConfig` structure, likely the input/output of the service.
    * `net/proxy_resolution/proxy_config_service_common_unittest.h`: Likely contains common test utilities related to proxy configuration.
    * Standard testing libraries (`gtest/gtest.h`).
    * Base libraries (`base/...`) for threading, file manipulation, strings, etc.

3. **Analyze the Test Structure:**  Notice the use of `TEST_F` and the `ProxyConfigServiceLinuxTest` fixture. This indicates tests are structured around specific scenarios related to proxy configuration on Linux.

4. **Look for Test Cases:**  The code defines several test cases (e.g., `BasicGSettingsTest`, `BasicEnvTest`). Each test case seems to focus on testing how the `ProxyConfigServiceLinux` class behaves under different configurations.

5. **Focus on the Test Logic:**
    * **Mocking:** The presence of `MockEnvironment` and `MockSettingGetter` is a key indicator. These are used to isolate the `ProxyConfigServiceLinux` from external dependencies (like actual environment variables or system settings) during testing.
    * **Input Setup:** The test cases define input values for environment variables (`EnvVarValues`) and GSettings (`GSettingsValues`).
    * **Expected Output:**  Each test case specifies the expected `ProxyConfigService::ConfigAvailability` and the contents of the `ProxyConfig` (auto-detect, PAC URL, proxy rules).
    * **Assertion:** The tests use `EXPECT_EQ` and `EXPECT_TRUE` to compare the actual output of the `ProxyConfigServiceLinux` with the expected output.

6. **Consider JavaScript Interaction:** Based on the file's purpose (testing proxy configuration) and the included headers, there's no direct indication of JavaScript interaction within *this specific file*. Proxy configuration happens at a lower network level than where JavaScript typically operates in a browser. However, the *results* of this service would be used by the browser's network stack, which might eventually be triggered by JavaScript making a network request.

7. **Logical Reasoning Examples:**  The test cases themselves provide examples of logical reasoning. The code takes a set of environment variables or GSettings and deduces the appropriate proxy configuration.

8. **Common Usage Errors:**  Since this is a unit test file, the "users" are primarily developers. Common errors would involve incorrect mocking, wrong expected outputs, or failing to cover all possible configuration scenarios.

9. **User Journey (Debugging):**  A user experiencing proxy problems might trigger debugging that leads to investigating the `ProxyConfigServiceLinux`. This happens when the browser needs to determine how to route network requests.

10. **Synthesize the Summary:** Combine the observations into a concise description of the file's role.

By following these steps, we can arrive at a comprehensive understanding of the provided code snippet.
这是文件 `net/proxy_resolution/proxy_config_service_linux_unittest.cc` 的第一部分，它是一个 C++ 单元测试文件，用于测试 Chromium 网络栈中 `ProxyConfigServiceLinux` 类的功能。`ProxyConfigServiceLinux` 类的职责是在 Linux 平台上获取系统级别的代理配置信息。

**它的主要功能可以归纳为：**

1. **测试 `ProxyConfigServiceLinux` 类从不同来源获取代理配置的能力。** 这部分代码主要关注以下两种配置来源：
    * **环境变量：**  例如 `http_proxy`, `https_proxy`, `no_proxy` 等。
    * **GSettings (GNOME/GTK 设置)：**  这是 Linux 桌面环境中存储用户配置的一种机制。

2. **模拟环境和 GSettings 的状态。** 为了进行单元测试，代码使用了 `MockEnvironment` 类来模拟环境变量，以及 `MockSettingGetter` 类来模拟从 GSettings 获取配置的过程。 这样可以隔离被测试的代码，避免受到实际系统配置的影响。

3. **定义了多个测试用例，覆盖不同的代理配置场景。**  每个测试用例都设置了特定的环境变量或 GSettings 值，并断言 `ProxyConfigServiceLinux` 类能够正确解析这些配置，生成期望的 `ProxyConfig` 对象。

4. **验证解析结果的正确性。** 测试用例会检查解析出的代理配置是否包含了正确的自动检测设置、PAC 文件 URL 以及代理规则（例如，单个代理服务器、分协议代理、绕过列表等）。

**它与 JavaScript 的功能关系：**

这个 C++ 文件本身并不直接与 JavaScript 交互。它的作用是在 Chromium 浏览器内部的网络层提供代理配置信息。然而，**最终 JavaScript 发起的网络请求会受到这里配置的代理设置的影响。**

**举例说明：**

假设 JavaScript 代码尝试通过 `fetch()` API 发起一个 HTTP 请求：

```javascript
fetch('https://www.example.com');
```

在 Chromium 内部，网络栈会查询 `ProxyConfigServiceLinux` 获取当前的代理配置。 如果 `ProxyConfigServiceLinux` 根据 GSettings 的配置，返回了使用 `http://proxy.mycompany.com:8080` 作为 HTTP 和 HTTPS 代理的配置，那么 JavaScript 发起的 `fetch()` 请求实际上会先连接到 `proxy.mycompany.com:8080`，再由代理服务器转发到 `www.example.com`。

**逻辑推理的假设输入与输出：**

**假设输入 (基于 `BasicGSettingsTest` 中的一个测试用例):**

* **GSettings 值：**
    * `mode`: "manual"
    * `http_host`: "www.google.com"
    * `http_port`: 80
    * `use_proxy`: TRUE
    * `same_proxy`: TRUE
    * `ignore_hosts`: 空列表

**逻辑推理过程:**

`ProxyConfigServiceLinux` 会读取这些 GSettings 值，并根据预定义的规则进行解析：

1. `mode` 为 "manual"，表示使用手动配置的代理。
2. `use_proxy` 为 TRUE，表示启用代理。
3. `same_proxy` 为 TRUE，表示所有协议使用相同的代理服务器。
4. `http_host` 为 "www.google.com"，`http_port` 为 80，因此代理服务器地址为 `www.google.com:80`。
5. `ignore_hosts` 为空，表示没有需要绕过代理的主机。

**预期输出:**

* `availability`: `ProxyConfigService::CONFIG_VALID` (表示配置有效)
* `auto_detect`: `false`
* `pac_url`: 空 URL
* `proxy_rules`:  包含一个单条代理规则，使用 `www.google.com:80` 作为所有协议的代理，并且没有绕过规则。

**假设输入 (基于 `BasicEnvTest` 中的一个测试用例):**

* **环境变量：**
    * `all_proxy`: "www.google.com"
    * `no_proxy`: NULL (未设置)

**逻辑推理过程:**

`ProxyConfigServiceLinux` 会读取环境变量：

1. 存在 `all_proxy` 环境变量，其值为 "www.google.com"。
2. `all_proxy` 表示所有协议都使用该代理。端口默认为 80。
3. `no_proxy` 未设置，表示没有需要绕过代理的主机。

**预期输出:**

* `availability`: `ProxyConfigService::CONFIG_VALID`
* `auto_detect`: `false`
* `pac_url`: 空 URL
* `proxy_rules`: 包含一个单条代理规则，使用 `www.google.com:80` 作为所有协议的代理，并且没有绕过规则。

**涉及用户或编程常见的使用错误：**

1. **环境变量设置错误：** 用户可能错误地设置了环境变量，例如拼写错误、端口号错误或者使用了错误的格式。例如，将 `http_proxy` 设置为 `http//proxy.example.com` (缺少冒号)。

2. **GSettings 配置错误：** 用户通过 GNOME 设置界面修改代理配置时，可能会输入无效的 URL 或主机名。例如，在 PAC 文件 URL 中输入一个不完整的地址。

3. **`no_proxy` 配置不当：** 用户可能忘记将需要绕过代理的主机添加到 `no_proxy` 列表中，导致访问这些主机时出现问题。或者 `no_proxy` 的格式不正确，导致绕过规则失效。例如，使用 `,` 分隔而不是 `, `。

4. **开发者在测试中 Mock 环境不准确：**  在编写类似这样的单元测试时，开发者可能会在 `MockEnvironment` 或 `MockSettingGetter` 中模拟错误的配置值，导致测试结果不符合预期。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在使用 Chromium 浏览器时遇到网络连接问题，怀疑是代理配置错误：

1. **用户尝试访问一个网页，例如 `https://www.example.com`。**
2. **浏览器网络栈开始处理请求。**
3. **网络栈需要确定使用哪个代理服务器（如果存在）。**
4. **Chromium 会调用 `ProxyConfigServiceLinux` 的方法来获取当前的代理配置。**
5. **`ProxyConfigServiceLinux` 会读取环境变量和 GSettings 中的代理相关配置。**
6. **如果需要调试代理配置的解析逻辑，开发者可能会设置断点在这个文件的相关代码中，例如 `BasicGSettingsTest` 或 `BasicEnvTest` 中的配置读取和解析部分。**
7. **开发者可以逐步执行代码，查看读取到的环境变量和 GSettings 值，以及最终生成的 `ProxyConfig` 对象，从而找出配置错误的原因。**
8. **例如，开发者可能会发现 GSettings 中 `mode` 的值是 "manual"，但 `http_host` 却是空的，这会导致代理配置无效。**

**归纳一下它的功能 (第 1 部分):**

这部分代码定义了 `net/proxy_resolution/proxy_config_service_linux_unittest.cc` 文件中用于测试 `ProxyConfigServiceLinux` 类的基础结构和一些基本的测试用例。它主要关注测试 `ProxyConfigServiceLinux` 从环境变量和 GSettings 中读取和解析代理配置信息的能力，并验证解析结果的正确性。 这部分通过模拟环境和 GSettings 的状态，实现了对 `ProxyConfigServiceLinux` 类的隔离测试。

Prompt: 
```
这是目录为net/proxy_resolution/proxy_config_service_linux_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/proxy_resolution/proxy_config_service_linux.h"

#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "base/check.h"
#include "base/compiler_specific.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/format_macros.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/message_loop/message_pump_type.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "net/proxy_resolution/proxy_config.h"
#include "net/proxy_resolution/proxy_config_service_common_unittest.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

// TODO(eroman): Convert these to parameterized tests using TEST_P().

namespace net {
namespace {

// Set of values for all environment variables that we might
// query. NULL represents an unset variable.
struct EnvVarValues {
  // The strange capitalization is so that the field matches the
  // environment variable name exactly.
  const char* DESKTOP_SESSION;
  const char* HOME;
  const char* KDEHOME;
  const char* KDE_SESSION_VERSION;
  const char* XDG_CURRENT_DESKTOP;
  const char* auto_proxy;
  const char* all_proxy;
  const char* http_proxy;
  const char* https_proxy;
  const char* ftp_proxy;
  const char* SOCKS_SERVER;
  const char* SOCKS_VERSION;
  const char* no_proxy;
  const char* XDG_CONFIG_DIRS;
};

// Undo macro pollution from GDK includes (from message_loop.h).
#undef TRUE
#undef FALSE

// So as to distinguish between an unset boolean variable and
// one that is false.
enum BoolSettingValue { UNSET = 0, TRUE, FALSE };

// Set of values for all gsettings settings that we might query.
struct GSettingsValues {
  // strings
  const char* mode;
  const char* autoconfig_url;
  const char* http_host;
  const char* secure_host;
  const char* ftp_host;
  const char* socks_host;
  // integers
  int http_port;
  int secure_port;
  int ftp_port;
  int socks_port;
  // booleans
  BoolSettingValue use_proxy;
  BoolSettingValue same_proxy;
  BoolSettingValue use_auth;
  // string list
  std::vector<std::string> ignore_hosts;
};

// Mapping from a setting name to the location of the corresponding
// value (inside a EnvVarValues or GSettingsValues struct).
template <typename key_type, typename value_type>
struct SettingsTable {
  typedef std::map<key_type, value_type*> map_type;

  // Gets the value from its location
  value_type Get(key_type key) {
    auto it = settings.find(key);
    // In case there's a typo or the unittest becomes out of sync.
    CHECK(it != settings.end()) << "key " << key << " not found";
    value_type* value_ptr = it->second;
    return *value_ptr;
  }

  map_type settings;
};

class MockEnvironment : public base::Environment {
 public:
  MockEnvironment() {
#define ENTRY(x) table_[#x] = &values.x
    ENTRY(DESKTOP_SESSION);
    ENTRY(HOME);
    ENTRY(KDEHOME);
    ENTRY(KDE_SESSION_VERSION);
    ENTRY(XDG_CURRENT_DESKTOP);
    ENTRY(auto_proxy);
    ENTRY(all_proxy);
    ENTRY(http_proxy);
    ENTRY(https_proxy);
    ENTRY(ftp_proxy);
    ENTRY(no_proxy);
    ENTRY(SOCKS_SERVER);
    ENTRY(SOCKS_VERSION);
    ENTRY(XDG_CONFIG_DIRS);
#undef ENTRY
    Reset();
  }

  // Zeroes all environment values.
  void Reset() {
    EnvVarValues zero_values = {nullptr};
    values = zero_values;
  }

  // Begin base::Environment implementation.
  bool GetVar(std::string_view variable_name, std::string* result) override {
    auto it = table_.find(variable_name);
    if (it == table_.end() || !*it->second)
      return false;

    // Note that the variable may be defined but empty.
    *result = *(it->second);
    return true;
  }

  bool SetVar(std::string_view variable_name,
              const std::string& new_value) override {
    ADD_FAILURE();
    return false;
  }

  bool UnSetVar(std::string_view variable_name) override {
    ADD_FAILURE();
    return false;
  }
  // End base::Environment implementation.

  // Intentionally public, for convenience when setting up a test.
  EnvVarValues values;

 private:
  std::map<std::string_view, const char**> table_;
};

class MockSettingGetter : public ProxyConfigServiceLinux::SettingGetter {
 public:
  typedef ProxyConfigServiceLinux::SettingGetter SettingGetter;
  MockSettingGetter() {
#define ENTRY(key, field) \
  strings_table.settings[SettingGetter::key] = &values.field
    ENTRY(PROXY_MODE, mode);
    ENTRY(PROXY_AUTOCONF_URL, autoconfig_url);
    ENTRY(PROXY_HTTP_HOST, http_host);
    ENTRY(PROXY_HTTPS_HOST, secure_host);
    ENTRY(PROXY_FTP_HOST, ftp_host);
    ENTRY(PROXY_SOCKS_HOST, socks_host);
#undef ENTRY
#define ENTRY(key, field) \
  ints_table.settings[SettingGetter::key] = &values.field
    ENTRY(PROXY_HTTP_PORT, http_port);
    ENTRY(PROXY_HTTPS_PORT, secure_port);
    ENTRY(PROXY_FTP_PORT, ftp_port);
    ENTRY(PROXY_SOCKS_PORT, socks_port);
#undef ENTRY
#define ENTRY(key, field) \
  bools_table.settings[SettingGetter::key] = &values.field
    ENTRY(PROXY_USE_HTTP_PROXY, use_proxy);
    ENTRY(PROXY_USE_SAME_PROXY, same_proxy);
    ENTRY(PROXY_USE_AUTHENTICATION, use_auth);
#undef ENTRY
    string_lists_table.settings[SettingGetter::PROXY_IGNORE_HOSTS] =
        &values.ignore_hosts;
    Reset();
  }

  // Zeros all environment values.
  void Reset() {
    GSettingsValues zero_values = {nullptr};
    values = zero_values;
  }

  bool Init(const scoped_refptr<base::SingleThreadTaskRunner>& glib_task_runner)
      override {
    task_runner_ = glib_task_runner;
    return true;
  }

  void ShutDown() override {}

  bool SetUpNotifications(
      ProxyConfigServiceLinux::Delegate* delegate) override {
    return true;
  }

  const scoped_refptr<base::SequencedTaskRunner>& GetNotificationTaskRunner()
      override {
    return task_runner_;
  }

  bool GetString(StringSetting key, std::string* result) override {
    const char* value = strings_table.Get(key);
    if (value) {
      *result = value;
      return true;
    }
    return false;
  }

  bool GetBool(BoolSetting key, bool* result) override {
    BoolSettingValue value = bools_table.Get(key);
    switch (value) {
      case UNSET:
        return false;
      case TRUE:
        *result = true;
        break;
      case FALSE:
        *result = false;
    }
    return true;
  }

  bool GetInt(IntSetting key, int* result) override {
    // We don't bother to distinguish unset keys from 0 values.
    *result = ints_table.Get(key);
    return true;
  }

  bool GetStringList(StringListSetting key,
                     std::vector<std::string>* result) override {
    *result = string_lists_table.Get(key);
    // We don't bother to distinguish unset keys from empty lists.
    return !result->empty();
  }

  bool BypassListIsReversed() override { return false; }

  bool UseSuffixMatching() override { return false; }

  // Intentionally public, for convenience when setting up a test.
  GSettingsValues values;

 private:
  scoped_refptr<base::SequencedTaskRunner> task_runner_;
  SettingsTable<StringSetting, const char*> strings_table;
  SettingsTable<BoolSetting, BoolSettingValue> bools_table;
  SettingsTable<IntSetting, int> ints_table;
  SettingsTable<StringListSetting, std::vector<std::string>> string_lists_table;
};

// This helper class runs ProxyConfigServiceLinux::GetLatestProxyConfig() on
// the main TaskRunner and synchronously waits for the result.
// Some code duplicated from pac_file_fetcher_unittest.cc.
class SyncConfigGetter : public ProxyConfigService::Observer {
 public:
  explicit SyncConfigGetter(
      std::unique_ptr<ProxyConfigServiceLinux> config_service)
      : event_(base::WaitableEvent::ResetPolicy::AUTOMATIC,
               base::WaitableEvent::InitialState::NOT_SIGNALED),
        main_thread_("Main_Thread"),
        config_service_(std::move(config_service)),
        matches_pac_url_event_(
            base::WaitableEvent::ResetPolicy::AUTOMATIC,
            base::WaitableEvent::InitialState::NOT_SIGNALED) {
    // Start the main IO thread.
    base::Thread::Options options;
    options.message_pump_type = base::MessagePumpType::IO;
    main_thread_.StartWithOptions(std::move(options));

    // Make sure the thread started.
    main_thread_.task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(&SyncConfigGetter::Init, base::Unretained(this)));
    Wait();
  }

  ~SyncConfigGetter() override {
    // Clean up the main thread.
    main_thread_.task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(&SyncConfigGetter::CleanUp, base::Unretained(this)));
    Wait();
  }

  // Does gsettings setup and initial fetch of the proxy config,
  // all on the calling thread (meant to be the thread with the
  // default glib main loop, which is the glib thread).
  void SetupAndInitialFetch() {
    config_service_->SetupAndFetchInitialConfig(
        base::SingleThreadTaskRunner::GetCurrentDefault(),
        main_thread_.task_runner(), TRAFFIC_ANNOTATION_FOR_TESTS);
  }
  // Synchronously gets the proxy config.
  ProxyConfigService::ConfigAvailability SyncGetLatestProxyConfig(
      ProxyConfigWithAnnotation* config) {
    main_thread_.task_runner()->PostTask(
        FROM_HERE, base::BindOnce(&SyncConfigGetter::GetLatestConfigOnIOThread,
                                  base::Unretained(this)));
    Wait();
    *config = proxy_config_;
    return get_latest_config_result_;
  }

  // Instructs |matches_pac_url_event_| to be signalled once the configuration
  // changes to |pac_url|. The way to use this function is:
  //
  //   SetExpectedPacUrl(..);
  //   EXPECT_TRUE(base::WriteFile(...))
  //   WaitUntilPacUrlMatchesExpectation();
  //
  // The expectation must be set *before* any file-level mutation is done,
  // otherwise the change may be received before
  // WaitUntilPacUrlMatchesExpectation(), and subsequently be lost.
  void SetExpectedPacUrl(const std::string& pac_url) {
    base::AutoLock lock(lock_);
    expected_pac_url_ = GURL(pac_url);
  }

  // Blocks until the proxy config service has received a configuration
  // matching the value previously passed to SetExpectedPacUrl().
  void WaitUntilPacUrlMatchesExpectation() {
    matches_pac_url_event_.Wait();
    matches_pac_url_event_.Reset();
  }

 private:
  void OnProxyConfigChanged(
      const ProxyConfigWithAnnotation& config,
      ProxyConfigService::ConfigAvailability availability) override {
    // If the configuration changed to |expected_pac_url_| signal the event.
    base::AutoLock lock(lock_);
    if (config.value().has_pac_url() &&
        config.value().pac_url() == expected_pac_url_) {
      expected_pac_url_ = GURL();
      matches_pac_url_event_.Signal();
    }
  }

  // [Runs on |main_thread_|]
  void Init() {
    config_service_->AddObserver(this);
    event_.Signal();
  }

  // Calls GetLatestProxyConfig, running on |main_thread_| Signals |event_|
  // on completion.
  void GetLatestConfigOnIOThread() {
    get_latest_config_result_ =
        config_service_->GetLatestProxyConfig(&proxy_config_);
    event_.Signal();
  }

  // [Runs on |main_thread_|] Signals |event_| on cleanup completion.
  void CleanUp() {
    config_service_->RemoveObserver(this);
    config_service_.reset();
    base::RunLoop().RunUntilIdle();
    event_.Signal();
  }

  void Wait() {
    event_.Wait();
    event_.Reset();
  }

  base::WaitableEvent event_;
  base::Thread main_thread_;

  std::unique_ptr<ProxyConfigServiceLinux> config_service_;

  // The config obtained by |main_thread_| and read back by the main
  // thread.
  ProxyConfigWithAnnotation proxy_config_;

  // Return value from GetLatestProxyConfig().
  ProxyConfigService::ConfigAvailability get_latest_config_result_;

  // If valid, |expected_pac_url_| is the URL that is being waited for in
  // the proxy configuration. The URL should only be accessed while |lock_|
  // is held. Once a configuration arrives for |expected_pac_url_| then the
  // event |matches_pac_url_event_| will be signalled.
  base::Lock lock_;
  GURL expected_pac_url_;
  base::WaitableEvent matches_pac_url_event_;
};

// This test fixture is only really needed for the KDEConfigParser test case,
// but all the test cases with the same prefix ("ProxyConfigServiceLinuxTest")
// must use the same test fixture class (also "ProxyConfigServiceLinuxTest").
class ProxyConfigServiceLinuxTest : public PlatformTest,
                                    public WithTaskEnvironment {
 protected:
  void SetUp() override {
    PlatformTest::SetUp();
    // Set up a temporary KDE home directory.
    std::string prefix("ProxyConfigServiceLinuxTest_user_home");
    base::CreateNewTempDirectory(prefix, &user_home_);
    config_home_ = user_home_.Append(FILE_PATH_LITERAL(".config"));
    kde_home_ = user_home_.Append(FILE_PATH_LITERAL(".kde"));
    base::FilePath path = kde_home_.Append(FILE_PATH_LITERAL("share"));
    path = path.Append(FILE_PATH_LITERAL("config"));
    base::CreateDirectory(path);
    kioslaverc_ = path.Append(FILE_PATH_LITERAL("kioslaverc"));
    // Set up paths but do not create the directory for .kde4.
    kde4_home_ = user_home_.Append(FILE_PATH_LITERAL(".kde4"));
    path = kde4_home_.Append(FILE_PATH_LITERAL("share"));
    kde4_config_ = path.Append(FILE_PATH_LITERAL("config"));
    kioslaverc4_ = kde4_config_.Append(FILE_PATH_LITERAL("kioslaverc"));
    // Set up paths for KDE 5
    kioslaverc5_ = config_home_.Append(FILE_PATH_LITERAL("kioslaverc"));
    config_xdg_home_ = user_home_.Append(FILE_PATH_LITERAL("xdg"));
    config_kdedefaults_home_ =
        config_home_.Append(FILE_PATH_LITERAL("kdedefaults"));
    kioslaverc5_xdg_ = config_xdg_home_.Append(FILE_PATH_LITERAL("kioslaverc"));
    kioslaverc5_kdedefaults_ =
        config_kdedefaults_home_.Append(FILE_PATH_LITERAL("kioslaverc"));
  }

  void TearDown() override {
    // Delete the temporary KDE home directory.
    base::DeletePathRecursively(user_home_);
    PlatformTest::TearDown();
  }

  base::FilePath user_home_;
  base::FilePath config_home_;
  base::FilePath config_xdg_home_;
  base::FilePath config_kdedefaults_home_;
  // KDE3 paths.
  base::FilePath kde_home_;
  base::FilePath kioslaverc_;
  // KDE4 paths.
  base::FilePath kde4_home_;
  base::FilePath kde4_config_;
  base::FilePath kioslaverc4_;
  // KDE5 paths.
  base::FilePath kioslaverc5_;
  base::FilePath kioslaverc5_xdg_;
  base::FilePath kioslaverc5_kdedefaults_;
};

// Builds an identifier for each test in an array.
#define TEST_DESC(desc) base::StringPrintf("at line %d <%s>", __LINE__, desc)

TEST_F(ProxyConfigServiceLinuxTest, BasicGSettingsTest) {
  std::vector<std::string> empty_ignores;

  std::vector<std::string> google_ignores;
  google_ignores.push_back("*.google.com");

  // Inspired from proxy_config_service_win_unittest.cc.
  // Very neat, but harder to track down failures though.
  const struct {
    // Short description to identify the test
    std::string description;

    // Input.
    GSettingsValues values;

    // Expected outputs (availability and fields of ProxyConfig).
    ProxyConfigService::ConfigAvailability availability;
    bool auto_detect;
    GURL pac_url;
    ProxyRulesExpectation proxy_rules;
  } tests[] = {
      {
          TEST_DESC("No proxying"),
          {
              // Input.
              "none",               // mode
              "",                   // autoconfig_url
              "", "", "", "",       // hosts
              0, 0, 0, 0,           // ports
              FALSE, FALSE, FALSE,  // use, same, auth
              empty_ignores,        // ignore_hosts
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Auto detect"),
          {
              // Input.
              "auto",               // mode
              "",                   // autoconfig_url
              "", "", "", "",       // hosts
              0, 0, 0, 0,           // ports
              FALSE, FALSE, FALSE,  // use, same, auth
              empty_ignores,        // ignore_hosts
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          true,    // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Valid PAC URL"),
          {
              // Input.
              "auto",                  // mode
              "http://wpad/wpad.dat",  // autoconfig_url
              "", "", "", "",          // hosts
              0, 0, 0, 0,              // ports
              FALSE, FALSE, FALSE,     // use, same, auth
              empty_ignores,           // ignore_hosts
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                         // auto_detect
          GURL("http://wpad/wpad.dat"),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Invalid PAC URL"),
          {
              // Input.
              "auto",               // mode
              "wpad.dat",           // autoconfig_url
              "", "", "", "",       // hosts
              0, 0, 0, 0,           // ports
              FALSE, FALSE, FALSE,  // use, same, auth
              empty_ignores,        // ignore_hosts
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Single-host in proxy list"),
          {
              // Input.
              "manual",                      // mode
              "",                            // autoconfig_url
              "www.google.com", "", "", "",  // hosts
              80, 0, 0, 0,                   // ports
              TRUE, TRUE, FALSE,             // use, same, auth
              empty_ignores,                 // ignore_hosts
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                              // auto_detect
          GURL(),                                             // pac_url
          ProxyRulesExpectation::Single("www.google.com:80",  // single proxy
                                        ""),                  // bypass rules
      },

      {
          TEST_DESC("use_http_proxy is honored"),
          {
              // Input.
              "manual",                      // mode
              "",                            // autoconfig_url
              "www.google.com", "", "", "",  // hosts
              80, 0, 0, 0,                   // ports
              FALSE, TRUE, FALSE,            // use, same, auth
              empty_ignores,                 // ignore_hosts
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("use_http_proxy and use_same_proxy are optional"),
          {
              // Input.
              "manual",                      // mode
              "",                            // autoconfig_url
              "www.google.com", "", "", "",  // hosts
              80, 0, 0, 0,                   // ports
              UNSET, UNSET, FALSE,           // use, same, auth
              empty_ignores,                 // ignore_hosts
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "",                   // https
                                           "",                   // ftp
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC("Single-host, different port"),
          {
              // Input.
              "manual",                      // mode
              "",                            // autoconfig_url
              "www.google.com", "", "", "",  // hosts
              88, 0, 0, 0,                   // ports
              TRUE, TRUE, FALSE,             // use, same, auth
              empty_ignores,                 // ignore_hosts
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                              // auto_detect
          GURL(),                                             // pac_url
          ProxyRulesExpectation::Single("www.google.com:88",  // single proxy
                                        ""),                  // bypass rules
      },

      {
          TEST_DESC("Per-scheme proxy rules"),
          {
              // Input.
              "manual",            // mode
              "",                  // autoconfig_url
              "www.google.com",    // http_host
              "www.foo.com",       // secure_host
              "ftp.foo.com",       // ftp
              "",                  // socks
              88, 110, 121, 0,     // ports
              TRUE, FALSE, FALSE,  // use, same, auth
              empty_ignores,       // ignore_hosts
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:88",  // http
                                           "www.foo.com:110",    // https
                                           "ftp.foo.com:121",    // ftp
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC("socks"),
          {
              // Input.
              "manual",                 // mode
              "",                       // autoconfig_url
              "", "", "", "socks.com",  // hosts
              0, 0, 0, 99,              // ports
              TRUE, FALSE, FALSE,       // use, same, auth
              empty_ignores,            // ignore_hosts
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Single(
              "socks5://socks.com:99",  // single proxy
              "")                       // bypass rules
      },

      {
          TEST_DESC("Per-scheme proxy rules with fallback to SOCKS"),
          {
              // Input.
              "manual",            // mode
              "",                  // autoconfig_url
              "www.google.com",    // http_host
              "www.foo.com",       // secure_host
              "ftp.foo.com",       // ftp
              "foobar.net",        // socks
              88, 110, 121, 99,    // ports
              TRUE, FALSE, FALSE,  // use, same, auth
              empty_ignores,       // ignore_hosts
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::PerSchemeWithSocks(
              "www.google.com:88",       // http
              "www.foo.com:110",         // https
              "ftp.foo.com:121",         // ftp
              "socks5://foobar.net:99",  // socks
              ""),                       // bypass rules
      },

      {
          TEST_DESC(
              "Per-scheme proxy rules (just HTTP) with fallback to SOCKS"),
          {
              // Input.
              "manual",            // mode
              "",                  // autoconfig_url
              "www.google.com",    // http_host
              "",                  // secure_host
              "",                  // ftp
              "foobar.net",        // socks
              88, 0, 0, 99,        // ports
              TRUE, FALSE, FALSE,  // use, same, auth
              empty_ignores,       // ignore_hosts
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::PerSchemeWithSocks(
              "www.google.com:88",       // http
              "",                        // https
              "",                        // ftp
              "socks5://foobar.net:99",  // socks
              ""),                       // bypass rules
      },

      {
          TEST_DESC("Bypass *.google.com"),
          {
              // Input.
              "manual",                      // mode
              "",                            // autoconfig_url
              "www.google.com", "", "", "",  // hosts
              80, 0, 0, 0,                   // ports
              TRUE, TRUE, FALSE,             // use, same, auth
              google_ignores,                // ignore_hosts
          },

          ProxyConfigService::CONFIG_VALID,
          false,                                              // auto_detect
          GURL(),                                             // pac_url
          ProxyRulesExpectation::Single("www.google.com:80",  // single proxy
                                        "*.google.com"),      // bypass rules
      },
  };

  for (size_t i = 0; i < std::size(tests); ++i) {
    SCOPED_TRACE(base::StringPrintf("Test[%" PRIuS "] %s", i,
                                    tests[i].description.c_str()));
    auto env = std::make_unique<MockEnvironment>();
    auto setting_getter = std::make_unique<MockSettingGetter>();
    auto* setting_getter_ptr = setting_getter.get();
    SyncConfigGetter sync_config_getter(
        std::make_unique<ProxyConfigServiceLinux>(
            std::move(env), std::move(setting_getter),
            TRAFFIC_ANNOTATION_FOR_TESTS));
    ProxyConfigWithAnnotation config;
    setting_getter_ptr->values = tests[i].values;
    sync_config_getter.SetupAndInitialFetch();
    ProxyConfigService::ConfigAvailability availability =
        sync_config_getter.SyncGetLatestProxyConfig(&config);
    EXPECT_EQ(tests[i].availability, availability);

    if (availability == ProxyConfigService::CONFIG_VALID) {
      EXPECT_EQ(tests[i].auto_detect, config.value().auto_detect());
      EXPECT_EQ(tests[i].pac_url, config.value().pac_url());
      EXPECT_TRUE(tests[i].proxy_rules.Matches(config.value().proxy_rules()));
    }
  }
}

TEST_F(ProxyConfigServiceLinuxTest, BasicEnvTest) {
  // Inspired from proxy_config_service_win_unittest.cc.
  const struct {
    // Short description to identify the test
    std::string description;

    // Input.
    EnvVarValues values;

    // Expected outputs (availability and fields of ProxyConfig).
    ProxyConfigService::ConfigAvailability availability;
    bool auto_detect;
    GURL pac_url;
    ProxyRulesExpectation proxy_rules;
  } tests[] = {
      {
          TEST_DESC("No proxying"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              nullptr,                    // auto_proxy
              nullptr,                    // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              nullptr, nullptr,           // SOCKS
              "*",                        // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Auto detect"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              "",                         // auto_proxy
              nullptr,                    // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              nullptr, nullptr,           // SOCKS
              nullptr,                    // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          true,    // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Valid PAC URL"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              "http://wpad/wpad.dat",     // auto_proxy
              nullptr,                    // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              nullptr, nullptr,           // SOCKS
              nullptr,                    // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                         // auto_detect
          GURL("http://wpad/wpad.dat"),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Invalid PAC URL"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              "wpad.dat",                 // auto_proxy
              nullptr,                    // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              nullptr, nullptr,           // SOCKS
              nullptr,                    // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Single-host in proxy list"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              nullptr,                    // auto_proxy
              "www.google.com",           // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              nullptr, nullptr,           // SOCKS
              nullptr,                    // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                              // auto_detect
          GURL(),                                             // pac_url
          ProxyRulesExpectation::Single("www.google.com:80",  // single proxy
                                        ""),                  // bypass rules
      },

      {
          TEST_DESC("Single-host, different port"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,          
"""


```
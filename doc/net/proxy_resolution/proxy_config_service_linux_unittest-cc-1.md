Response:
Let's break down the thought process for analyzing this code snippet.

**1. Understanding the Goal:**

The request asks for an analysis of a specific part of a C++ unittest file related to proxy configuration in Chromium's networking stack. The key is to understand *what* this code is testing and *how* it's doing it.

**2. Initial Scan and Keywords:**

A quick scan reveals important keywords and patterns:

* `TEST_F`: This immediately tells us it's a Google Test framework test fixture.
* `ProxyConfigServiceLinuxTest`: This identifies the class being tested.
* `SyncConfigGetter`: This suggests a focus on synchronous retrieval of proxy configuration.
* `MockEnvironment`, `MockSettingGetter`: These indicate the use of mock objects to control the test environment.
* `ProxyConfigServiceLinux`: This is the class under test.
* `ProxyConfigWithAnnotation`:  This is likely a structure or class holding the proxy configuration data.
* `ConfigAvailability`, `auto_detect`, `pac_url`, `proxy_rules`: These are the specific aspects of the proxy configuration being validated.
* The large array of structs with `TEST_DESC`, `Input`, and `Expected result`: This is the core of the unit tests, defining various scenarios and their expected outcomes.
* Environment variables like `DESKTOP_SESSION`, `HOME`, `KDEHOME`, `all_proxy`, etc.: This highlights the dependency of proxy configuration on the system environment.

**3. Deconstructing the Test Cases:**

The bulk of the code is the array of test cases. The core pattern is:

* **Setup (Input):** Defining the state of the mocked environment (primarily environment variables).
* **Action:**  Instantiating `ProxyConfigServiceLinux`, triggering `SetupAndInitialFetch`, and then `SyncGetLatestProxyConfig`.
* **Assertion (Expected result):** Comparing the retrieved configuration (availability, auto-detect, PAC URL, proxy rules) against the predefined expected values.

**4. Identifying the Functionality Being Tested:**

By examining the different test cases, we can deduce the functionalities being verified:

* **Basic Proxy Types:**  Testing how different environment variables (`all_proxy`, per-protocol proxies, `SOCKS`) are interpreted.
* **Tolerating Schemes:** Checking if the code handles URLs with schemes in the proxy settings.
* **SOCKS Proxy Variations:** Testing different SOCKS protocols (SOCKS5, SOCKS4) and default port handling.
* **Bypass Rules:**  Verifying how `no_proxy` environment variable is parsed and applied.

**5. Relating to JavaScript (if applicable):**

The prompt specifically asks about connections to JavaScript. The crucial link here is the PAC (Proxy Auto-Config) file. PAC files are written in JavaScript. While this specific C++ code *parses* environment variables, the *result* of some configurations (like setting `auto_proxy`) might lead the system to *fetch and execute* a JavaScript PAC file. This is a key indirect relationship.

**6. Logical Reasoning and Assumptions:**

For each test case, there's a clear input and expected output. The logic is about correctly mapping environment variable settings to the internal proxy configuration representation. Assumptions are implicit in the test setup, such as the correct functioning of the mocking framework. A specific example of a hypothetical input and output is already present in the code itself (the test case definitions).

**7. Identifying Potential User Errors:**

By looking at the parsing logic (especially around `no_proxy`), we can infer common user errors:

* **Incorrect syntax in `no_proxy`:**  Missing commas, incorrect port specifications, typos.
* **Misunderstanding wildcard matching:** Not realizing that simple hostnames might be treated as wildcards in some configurations.
* **Conflicting proxy settings:**  Setting both `all_proxy` and specific protocol proxies, leading to unexpected behavior.

**8. Tracing User Actions (Debugging Clues):**

To understand how a user might reach this code, we need to consider the chain of events:

1. **User attempts to access a website.**
2. **The browser (Chromium) needs to determine the proxy settings.**
3. **On Linux, it checks environment variables.**
4. **`ProxyConfigServiceLinux` is responsible for reading and interpreting these variables.**
5. **If there are issues, developers might look at the output of this unittest to understand how the parsing is supposed to work.**

**9. Summarizing the Functionality (Part 2):**

The request specifies that this is part 2 of a 3-part analysis. Knowing that part 1 likely dealt with GSettings, and part 3 might cover KDE in more detail, part 2 seems focused on:

* **Testing environment variable-based proxy configuration.**
* **Covering various common scenarios for proxy settings.**
* **Validating the parsing logic of `ProxyConfigServiceLinux` when reading environment variables.**

**Self-Correction/Refinement During Analysis:**

* **Initial thought:**  The code is *only* about environment variables.
* **Correction:**  Realize the connection to JavaScript via PAC files and the potential influence of KDE settings (even though this specific snippet focuses on environment variables).
* **Initial thought:** The tests are purely functional.
* **Refinement:** Recognize the implicit performance considerations (not explicitly tested here, but parsing needs to be efficient) and the security implications of correctly handling proxy settings.

By following this systematic approach, we can thoroughly analyze the provided code snippet and address all aspects of the request.
这是 Chromium 网络栈源代码文件 `net/proxy_resolution/proxy_config_service_linux_unittest.cc` 的第二部分，延续了第一部分的测试用例，主要功能仍然是**测试 `ProxyConfigServiceLinux` 类在读取和解析 Linux 系统环境变量时，能否正确地识别和处理各种代理配置。**

具体来说，这部分测试用例关注的是通过**环境变量**来配置代理的情况。

**功能归纳（针对第二部分）：**

1. **测试通过 `all_proxy` 环境变量设置全局代理：** 验证能够正确解析 `all_proxy` 环境变量，并提取出代理服务器地址和端口。
2. **测试 `all_proxy` 环境变量中包含协议头的情况：**  验证即使 `all_proxy` 包含了 `http://` 前缀，也能正确解析出代理服务器地址和端口。
3. **测试通过分协议环境变量设置代理：** 验证能够正确解析 `http_proxy`, `https_proxy`, `ftp_proxy` 等环境变量，设置不同协议的代理服务器。
4. **测试通过 `socks` 环境变量设置 SOCKS 代理：** 验证能够正确解析 `socks` 环境变量，并识别出 SOCKS 代理的地址、端口和协议版本（默认或显式指定）。
5. **测试通过 `no_proxy` 环境变量设置绕过代理的规则：** 验证能够正确解析 `no_proxy` 环境变量，并将其转换为绕过代理的规则列表。

**与 Javascript 的关系：**

这部分代码本身并不直接涉及执行 Javascript。然而，它所测试的功能是**配置代理**，而代理配置的一个重要方面是 **PAC (Proxy Auto-Config) 文件**。PAC 文件是用 Javascript 编写的，浏览器会执行 PAC 文件中的代码来动态决定是否使用代理以及使用哪个代理。

这部分代码测试的是通过环境变量配置代理，如果环境变量中指定了 PAC 文件的 URL（通常是通过 `auto_proxy` 环境变量，但这部分代码没有直接测试 `auto_proxy`），那么浏览器最终会去获取并执行该 PAC 文件。

**举例说明：**

假设一个测试用例中，环境变量 `auto_proxy` 被设置为 `http://example.com/proxy.pac`。虽然这段 C++ 代码本身不执行 Javascript，但它会识别到需要使用 PAC 文件，并将 PAC 文件的 URL 传递给浏览器的其他组件。浏览器在发起网络请求时，会下载 `http://example.com/proxy.pac` 并执行其中的 Javascript 代码，根据 PAC 文件中的逻辑来决定如何代理该请求。

**逻辑推理，假设输入与输出：**

* **假设输入：** 环境变量 `all_proxy` 设置为 `"proxy.example.com:8080"`
* **预期输出：** `ProxyConfigService` 会解析出代理规则，指示所有协议的请求都通过 `proxy.example.com:8080` 这个代理服务器。

* **假设输入：** 环境变量 `http_proxy` 设置为 `"http-proxy.example.com:80"`, `https_proxy` 设置为 `"https-proxy.example.com:443"`
* **预期输出：** `ProxyConfigService` 会解析出针对 HTTP 请求使用 `http-proxy.example.com:80`，针对 HTTPS 请求使用 `https-proxy.example.com:443` 的代理规则。

* **假设输入：** 环境变量 `socks` 设置为 `"socks.example.com:1080"`
* **预期输出：** `ProxyConfigService` 会解析出使用 SOCKS5 协议，代理服务器为 `socks.example.com:1080` 的代理规则。

* **假设输入：** 环境变量 `no_proxy` 设置为 `".google.com,localhost"`
* **预期输出：** `ProxyConfigService` 会解析出绕过代理的规则，对所有以 `.google.com` 结尾的域名和 `localhost` 不使用代理。

**涉及用户或编程常见的使用错误：**

* **`all_proxy` 中包含错误的格式：** 例如，`all_proxy="proxy.example.com"` (缺少端口)，或者 `all_proxy="http:proxy.example.com:8080"` (协议头错误)。这将导致解析失败或得到意外的代理配置。
* **`no_proxy` 中使用错误的语法：** 例如，缺少逗号分隔，或者使用了不支持的通配符。这将导致部分域名无法正确绕过代理。
* **同时设置了 `all_proxy` 和分协议代理：**  这会导致优先级问题，用户可能不清楚最终会使用哪个代理。例如，同时设置 `all_proxy="global-proxy"` 和 `http_proxy="http-specific-proxy"`。
* **SOCKS 代理的协议版本指定错误：** 例如，`socks="socks.example.com:1080:4"`  (冒号分隔符错误)。
* **端口号超出范围：** 例如，`all_proxy="proxy.example.com:65536"`。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户配置系统级别的代理设置：**  在 Linux 系统中，用户可以通过多种方式设置代理，其中一种常见的方式是修改环境变量。例如，在终端中执行 `export all_proxy="proxy.example.com:8080"` 或修改 `~/.bashrc` 等配置文件。
2. **用户启动 Chromium 浏览器：** 当 Chromium 启动时，它会读取系统的环境变量，包括代理相关的环境变量。
3. **`ProxyConfigServiceLinux` 被实例化：**  Chromium 的网络栈会创建 `ProxyConfigServiceLinux` 的实例来负责从 Linux 系统中获取代理配置。
4. **`ProxyConfigServiceLinux` 读取环境变量：**  `ProxyConfigServiceLinux` 会读取诸如 `all_proxy`, `http_proxy`, `no_proxy` 等环境变量的值。
5. **`SyncGetLatestProxyConfig` 被调用：** 当 Chromium 需要获取最新的代理配置时，会调用 `ProxyConfigServiceLinux` 的 `SyncGetLatestProxyConfig` 方法。
6. **测试用例模拟环境变量和调用过程：**  `proxy_config_service_linux_unittest.cc` 中的测试用例通过 `MockEnvironment` 模拟了各种环境变量的设置，并调用 `SyncGetLatestProxyConfig` 来验证 `ProxyConfigServiceLinux` 是否能正确解析这些环境变量。

**作为调试线索：** 如果用户报告了 Chromium 的代理设置不符合预期，开发者可以：

* **检查用户的系统环境变量：** 确认用户设置的代理环境变量是否正确。
* **运行相关的单元测试：** 运行 `proxy_config_service_linux_unittest.cc` 中的测试用例，特别是模拟用户当前环境变量配置的测试用例，来验证 `ProxyConfigServiceLinux` 的行为是否符合预期。如果测试失败，则表明 `ProxyConfigServiceLinux` 在解析该种环境变量配置时存在 bug。
* **使用 Chromium 的内部工具：**  Chromium 提供了一些内部页面 (例如 `net-internals`) 可以查看当前的代理配置信息，这可以帮助开发者确认 Chromium 实际使用的代理配置是什么，并与预期进行对比。

总而言之，这部分测试用例的核心功能是验证 `ProxyConfigServiceLinux` 组件在处理基于 Linux 环境变量的代理配置时的正确性，确保 Chromium 能够按照用户的系统设置来处理网络请求。

Prompt: 
```
这是目录为net/proxy_resolution/proxy_config_service_linux_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
          // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              nullptr,                    // auto_proxy
              "www.google.com:99",        // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              nullptr, nullptr,           // SOCKS
              nullptr,                    // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                              // auto_detect
          GURL(),                                             // pac_url
          ProxyRulesExpectation::Single("www.google.com:99",  // single
                                        ""),                  // bypass rules
      },

      {
          TEST_DESC("Tolerate a scheme"),
          {
              // Input.
              nullptr,                     // DESKTOP_SESSION
              nullptr,                     // HOME
              nullptr,                     // KDEHOME
              nullptr,                     // KDE_SESSION_VERSION
              nullptr,                     // XDG_CURRENT_DESKTOP
              nullptr,                     // auto_proxy
              "http://www.google.com:99",  // all_proxy
              nullptr, nullptr, nullptr,   // per-proto proxies
              nullptr, nullptr,            // SOCKS
              nullptr,                     // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                              // auto_detect
          GURL(),                                             // pac_url
          ProxyRulesExpectation::Single("www.google.com:99",  // single proxy
                                        ""),                  // bypass rules
      },

      {
          TEST_DESC("Per-scheme proxy rules"),
          {
              // Input.
              nullptr,  // DESKTOP_SESSION
              nullptr,  // HOME
              nullptr,  // KDEHOME
              nullptr,  // KDE_SESSION_VERSION
              nullptr,  // XDG_CURRENT_DESKTOP
              nullptr,  // auto_proxy
              nullptr,  // all_proxy
              "www.google.com:80", "www.foo.com:110",
              "ftp.foo.com:121",  // per-proto
              nullptr, nullptr,   // SOCKS
              nullptr,            // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "www.foo.com:110",    // https
                                           "ftp.foo.com:121",    // ftp
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC("socks"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              nullptr,                    // auto_proxy
              "",                         // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              "socks.com:888", nullptr,   // SOCKS
              nullptr,                    // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Single(
              "socks5://socks.com:888",  // single proxy
              ""),                       // bypass rules
      },

      {
          TEST_DESC("socks4"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              nullptr,                    // auto_proxy
              "",                         // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              "socks.com:888", "4",       // SOCKS
              nullptr,                    // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Single(
              "socks4://socks.com:888",  // single proxy
              ""),                       // bypass rules
      },

      {
          TEST_DESC("socks default port"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              nullptr,                    // auto_proxy
              "",                         // all_proxy
              nullptr, nullptr, nullptr,  // per-proto proxies
              "socks.com", nullptr,       // SOCKS
              nullptr,                    // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Single(
              "socks5://socks.com:1080",  // single proxy
              ""),                        // bypass rules
      },

      {
          TEST_DESC("bypass"),
          {
              // Input.
              nullptr,                    // DESKTOP_SESSION
              nullptr,                    // HOME
              nullptr,                    // KDEHOME
              nullptr,                    // KDE_SESSION_VERSION
              nullptr,                    // XDG_CURRENT_DESKTOP
              nullptr,                    // auto_proxy
              "www.google.com",           // all_proxy
              nullptr, nullptr, nullptr,  // per-proto
              nullptr, nullptr,           // SOCKS
              ".google.com, foo.com:99, 1.2.3.4:22, 127.0.0.1/8",  // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Single(
              "www.google.com:80",
              "*.google.com,*foo.com:99,1.2.3.4:22,127.0.0.1/8"),
      },
  };

  for (size_t i = 0; i < std::size(tests); ++i) {
    SCOPED_TRACE(base::StringPrintf("Test[%" PRIuS "] %s", i,
                                    tests[i].description.c_str()));
    auto env = std::make_unique<MockEnvironment>();
    env->values = tests[i].values;
    auto setting_getter = std::make_unique<MockSettingGetter>();
    SyncConfigGetter sync_config_getter(
        std::make_unique<ProxyConfigServiceLinux>(
            std::move(env), std::move(setting_getter),
            TRAFFIC_ANNOTATION_FOR_TESTS));
    ProxyConfigWithAnnotation config;
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

TEST_F(ProxyConfigServiceLinuxTest, GSettingsNotification) {
  auto env = std::make_unique<MockEnvironment>();
  auto setting_getter = std::make_unique<MockSettingGetter>();
  auto* setting_getter_ptr = setting_getter.get();
  auto service = std::make_unique<ProxyConfigServiceLinux>(
      std::move(env), std::move(setting_getter), TRAFFIC_ANNOTATION_FOR_TESTS);
  auto* service_ptr = service.get();
  SyncConfigGetter sync_config_getter(std::move(service));
  ProxyConfigWithAnnotation config;

  // Start with no proxy.
  setting_getter_ptr->values.mode = "none";
  sync_config_getter.SetupAndInitialFetch();
  EXPECT_EQ(ProxyConfigService::CONFIG_VALID,
            sync_config_getter.SyncGetLatestProxyConfig(&config));
  EXPECT_FALSE(config.value().auto_detect());

  // Now set to auto-detect.
  setting_getter_ptr->values.mode = "auto";
  // Simulate setting change notification callback.
  service_ptr->OnCheckProxyConfigSettings();
  EXPECT_EQ(ProxyConfigService::CONFIG_VALID,
            sync_config_getter.SyncGetLatestProxyConfig(&config));
  EXPECT_TRUE(config.value().auto_detect());

  // Simulate two settings changes, where PROXY_MODE is missing. This will make
  // the settings be interpreted as DIRECT.
  //
  // Trigering the check a *second* time is a regression test for
  // https://crbug.com/848237, where a comparison is done between two nullopts.
  for (size_t i = 0; i < 2; ++i) {
    setting_getter_ptr->values.mode = nullptr;
    service_ptr->OnCheckProxyConfigSettings();
    EXPECT_EQ(ProxyConfigService::CONFIG_VALID,
              sync_config_getter.SyncGetLatestProxyConfig(&config));
    EXPECT_FALSE(config.value().auto_detect());
    EXPECT_TRUE(config.value().proxy_rules().empty());
  }
}

TEST_F(ProxyConfigServiceLinuxTest, KDEConfigParser) {
  // One of the tests below needs a worst-case long line prefix. We build it
  // programmatically so that it will always be the right size.
  std::string long_line;
  size_t limit = ProxyConfigServiceLinux::SettingGetter::BUFFER_SIZE - 1;
  for (size_t i = 0; i < limit; ++i)
    long_line += "-";

  // Inspired from proxy_config_service_win_unittest.cc.
  const struct {
    // Short description to identify the test
    std::string description;

    // Input.
    std::string kioslaverc;
    EnvVarValues env_values;

    // Expected outputs (availability and fields of ProxyConfig).
    ProxyConfigService::ConfigAvailability availability;
    bool auto_detect;
    GURL pac_url;
    ProxyRulesExpectation proxy_rules;
  } tests[] = {
      {
          TEST_DESC("No proxying"),

          // Input.
          "[Proxy Settings]\nProxyType=0\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },
      {
          TEST_DESC("Invalid proxy type (ProxyType=-3)"),

          // Input.
          "[Proxy Settings]\nProxyType=-3\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Invalid proxy type (ProxyType=AB-)"),

          // Input.
          "[Proxy Settings]\nProxyType=AB-\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Auto detect"),

          // Input.
          "[Proxy Settings]\nProxyType=3\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          true,    // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Valid PAC URL"),

          // Input.
          "[Proxy Settings]\nProxyType=2\n"
          "Proxy Config Script=http://wpad/wpad.dat\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                         // auto_detect
          GURL("http://wpad/wpad.dat"),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Valid PAC file without file://"),

          // Input.
          "[Proxy Settings]\nProxyType=2\n"
          "Proxy Config Script=/wpad/wpad.dat\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                          // auto_detect
          GURL("file:///wpad/wpad.dat"),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Per-scheme proxy rules"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "httpsProxy=www.foo.com\nftpProxy=ftp.foo.com\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "www.foo.com:80",     // https
                                           "ftp.foo.com:80",     // http
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC("Only HTTP proxy specified"),

          // Input.
          "[Proxy Settings]\nProxyType=1\n"
          "httpProxy=www.google.com\n",
          {},  // env_values

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
          TEST_DESC("Only HTTP proxy specified, different port"),

          // Input.
          "[Proxy Settings]\nProxyType=1\n"
          "httpProxy=www.google.com:88\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:88",  // http
                                           "",                   // https
                                           "",                   // ftp
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC(
              "Only HTTP proxy specified, different port, space-delimited"),

          // Input.
          "[Proxy Settings]\nProxyType=1\n"
          "httpProxy=www.google.com 88\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:88",  // http
                                           "",                   // https
                                           "",                   // ftp
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC("Bypass *.google.com"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "NoProxyFor=.google.com\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "",                   // https
                                           "",                   // ftp
                                           "*.google.com"),      // bypass rules
      },

      {
          TEST_DESC("Bypass *.google.com and *.kde.org"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "NoProxyFor=.google.com,.kde.org\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::PerScheme(
              "www.google.com:80",        // http
              "",                         // https
              "",                         // ftp
              "*.google.com,*.kde.org"),  // bypass rules
      },

      {
          TEST_DESC("Correctly parse bypass list with ReversedException=true"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "NoProxyFor=.google.com\nReversedException=true\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::PerSchemeWithBypassReversed(
              "www.google.com:80",  // http
              "",                   // https
              "",                   // ftp
              "*.google.com"),      // bypass rules
      },

      {
          TEST_DESC("Correctly parse bypass list with ReversedException=false"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "NoProxyFor=.google.com\nReversedException=false\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "",                   // https
                                           "",                   // ftp
                                           "*.google.com"),      // bypass rules
      },

      {
          TEST_DESC("Correctly parse bypass list with ReversedException=1"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "NoProxyFor=.google.com\nReversedException=1\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::PerSchemeWithBypassReversed(
              "www.google.com:80",  // http
              "",                   // https
              "",                   // ftp
              "*.google.com"),      // bypass rules
      },

      {
          TEST_DESC("Overflow: ReversedException=18446744073709551617"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "NoProxyFor=.google.com\nReversedException=18446744073709551617\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "",                   // https
                                           "",                   // ftp
                                           "*.google.com"),      // bypass rules
      },

      {
          TEST_DESC("Not a number: ReversedException=noitpecxE"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "NoProxyFor=.google.com\nReversedException=noitpecxE\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "",                   // https
                                           "",                   // ftp
                                           "*.google.com"),      // bypass rules
      },

      {
          TEST_DESC("socks"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nsocksProxy=socks.com 888\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Single(
              "socks5://socks.com:888",  // single proxy
              ""),                       // bypass rules
      },

      {
          TEST_DESC("socks4"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nsocksProxy=socks4://socks.com 888\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Single(
              "socks4://socks.com:888",  // single proxy
              ""),                       // bypass rules
      },

      {
          TEST_DESC("Treat all hostname patterns as wildcard patterns"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "NoProxyFor=google.com,kde.org,<local>\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::PerScheme(
              "www.google.com:80",              // http
              "",                               // https
              "",                               // ftp
              "*google.com,*kde.org,<local>"),  // bypass rules
      },

      {
          TEST_DESC("Allow trailing whitespace after boolean value"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "NoProxyFor=.google.com\nReversedException=true  \n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::PerSchemeWithBypassReversed(
              "www.google.com:80",  // http
              "",                   // https
              "",                   // ftp
              "*.google.com"),      // bypass rules
      },

      {
          TEST_DESC("Ignore settings outside [Proxy Settings]"),

          // Input.
          "httpsProxy=www.foo.com\n[Proxy Settings]\nProxyType=1\n"
          "httpProxy=www.google.com\n[Other Section]\nftpProxy=ftp.foo.com\n",
          {},  // env_values

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
          TEST_DESC("Handle CRLF line endings"),

          // Input.
          "[Proxy Settings]\r\nProxyType=1\r\nhttpProxy=www.google.com\r\n",
          {},  // env_values

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
          TEST_DESC("Handle blank lines and mixed line endings"),

          // Input.
          "[Proxy Settings]\r\n\nProxyType=1\n\r\nhttpProxy=www.google.com\n\n",
          {},  // env_values

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
          TEST_DESC("Handle localized settings"),

          // Input.
          "[Proxy Settings]\nProxyType[$e]=1\nhttpProxy[$e]=www.google.com\n",
          {},  // env_values

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
          TEST_DESC("Ignore malformed localized settings"),

          // Input.
          "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com\n"
          "httpsProxy$e]=www.foo.com\nftpProxy=ftp.foo.com\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "",                   // https
                                           "ftp.foo.com:80",     // ftp
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC("Handle strange whitespace"),

          // Input.
          "[Proxy Settings]\nProxyType [$e] =2\n"
          "  Proxy Config Script =  http:// foo\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                // auto_detect
          GURL("http:// foo"),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Ignore all of a line which is too long"),

          // Input.
          std::string("[Proxy Settings]\nProxyType=1\nftpProxy=ftp.foo.com\n") +
              long_line + "httpsProxy=www.foo.com\nhttpProxy=www.google.com\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,                                                 // auto_detect
          GURL(),                                                // pac_url
          ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                           "",                   // https
                                           "ftp.foo.com:80",     // ftp
                                           ""),                  // bypass rules
      },

      {
          TEST_DESC("Indirect Proxy - no env vars set"),

          // Input.
          "[Proxy Settings]\nProxyType=4\nhttpProxy=http_proxy\n"
          "httpsProxy=https_proxy\nftpProxy=ftp_proxy\nNoProxyFor=no_proxy\n",
          {},  // env_values

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::Empty(),
      },

      {
          TEST_DESC("Indirect Proxy - with env vars set"),

          // Input.
          "[Proxy Settings]\nProxyType=4\nhttpProxy=http_proxy\n"
          "httpsProxy=https_proxy\nftpProxy=ftp_proxy\nNoProxyFor=no_proxy\n"
          "socksProxy=SOCKS_SERVER\n",
          {
              // env_values
              nullptr,                          // DESKTOP_SESSION
              nullptr,                          // HOME
              nullptr,                          // KDEHOME
              nullptr,                          // KDE_SESSION_VERSION
              nullptr,                          // XDG_CURRENT_DESKTOP
              nullptr,                          // auto_proxy
              nullptr,                          // all_proxy
              "www.normal.com",                 // http_proxy
              "www.secure.com",                 // https_proxy
              "ftp.foo.com",                    // ftp_proxy
              "socks.comfy.com:1234", nullptr,  // SOCKS
              ".google.com, .kde.org",          // no_proxy
          },

          // Expected result.
          ProxyConfigService::CONFIG_VALID,
          false,   // auto_detect
          GURL(),  // pac_url
          ProxyRulesExpectation::PerSchemeWithSocks(
              "www.normal.com:80",              // http
              "www.secure.com:80",              // https
              "ftp.foo.com:80",                 // ftp
              "socks5://socks.comfy.com:1234",  // socks
              "*.google.com,*.kde.org"),        // bypass rules
      },
  };

  for (size_t i = 0; i < std::size(tests); ++i) {
    SCOPED_TRACE(base::StringPrintf("Test[%" PRIuS "] %s", i,
                                    tests[i].description.c_str()));
    auto env = std::make_unique<MockEnvironment>();
    env->values = tests[i].env_values;
    // Force the KDE getter to be used and tell it where the test is.
    env->values.DESKTOP_SESSION = "kde4";
    env->values.KDEHOME = kde_home_.value().c_str();
    SyncConfigGetter sync_config_getter(
        std::make_unique<ProxyConfigServiceLinux>(
            std::move(env), TRAFFIC_ANNOTATION_FOR_TESTS));
    ProxyConfigWithAnnotation config;
    // Overwrite the kioslaverc file.
    base::WriteFile(kioslaverc_, tests[i].kioslaverc);
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

TEST_F(ProxyConfigServiceLinuxTest, KDEHomePicker) {
  // Auto detect proxy settings.
  std::string slaverc3 = "[Proxy Settings]\nProxyType=3\n";
  // Valid PAC URL.
  std::string slaverc4 =
      "[Proxy Settings]\nProxyType=2\n"
      "Proxy Config Script=http://wpad/wpad.dat\n";
  GURL slaverc4_pac_url("http://wpad/wpad.dat");
  // Basic HTTP proxy setting.
  std::string slaverc5 =
      "[Proxy Settings]\nProxyType=1\nhttpProxy=www.google.com 80\n";
  ProxyRulesExpectation slaverc5_rules =
      ProxyRulesExpectation::PerScheme("www.google.com:80",  // http
                                       "",                   // https
                                       "",                   // ftp
                                       "");                  // bypass rules

  // Overwrite the .kde kioslaverc file.
  base::WriteFile(kioslaverc_, slaverc3);

  // If .kde4 exists it will mess up the first test. It should not, as
  // we created the directory for $HOME in the test setup.
  CHECK(!base::DirectoryExists(kde4_home_));

  {
    SCOPED_TRACE("KDE4, no .kde4 directory, verify fallback");
    auto env = std::make_unique<MockEnvironment>();
    env->values.DESKTOP_SESSION = "kde4";
    env->values.HOME = user_home_.value().c_str();
    SyncConfigGetter sync_config_getter(
        std::make_unique<ProxyConfigSe
"""


```
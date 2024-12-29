Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

1. **Understand the Goal:** The primary goal is to understand what the `cert_verify_tool.cc` file does within the Chromium network stack. The prompt also asks specifically about its relationship to JavaScript, logical reasoning (with inputs/outputs), potential usage errors, and how a user might reach this code during debugging.

2. **Initial Code Scan (Keywords and Structure):**
    * **Headers:** Look at the included headers. They provide immediate clues about the tool's functionality. `net/cert/...`, `net/url_request/...`, `base/...` are strong indicators of network operations, certificate handling, and general Chromium infrastructure. `iostream`, `string_view` suggest command-line tool usage.
    * **`main` function:**  This is the entry point. Its structure will reveal the overall flow of the program. Look for command-line argument parsing, initialization, core logic, and cleanup.
    * **Classes and Functions:**  Identify key classes like `CertVerifyImpl`, `CertVerifyImplUsingProc`, `CertVerifyImplUsingPathBuilder`. Note functions like `VerifyCert`, `CreateCertVerifyImplFromName`. These indicate different ways the tool can perform certificate verification.
    * **Command-line flags:**  The `kUsage` string is crucial. It explicitly lists the available command-line options, providing a detailed understanding of the tool's capabilities.

3. **Deconstruct the Functionality (Based on Code and `kUsage`):**

    * **Core Functionality:** The name "cert_verify_tool" and the presence of `CertVerifyProc`, `CertPathBuilder` strongly suggest its primary function is to verify X.509 certificates.
    * **Input:** The tool takes a target certificate (and optionally intermediate certificates) as input, either directly in a file or separated. The `--roots` flag allows specifying trusted root certificates.
    * **Verification Methods:** The existence of different `CertVerifyImpl` subclasses (`UsingProc`, `UsingPathBuilder`) signifies multiple ways to perform verification. The `impls` flag lets the user choose or prioritize these methods.
    * **Verification Parameters:** The `--hostname` flag is used for hostname validation. `--time` allows specifying a verification time, useful for testing validity periods. `--crlset` enables CRL checking.
    * **Trust Settings:** Flags like `--trust-last-cert`, `--root-trust`, and `--trust-leaf-cert` indicate the ability to customize trust settings for specific certificates.
    * **Output:** The tool prints the verification result (success/failure) to the console. The `--dump` flag allows saving the verified certificate chain.

4. **Address Specific Prompt Questions:**

    * **Functionality Listing:**  Summarize the findings from the deconstruction phase into a clear list of functionalities.
    * **Relationship to JavaScript:** This requires careful consideration. Does this *specific* C++ code interact directly with JavaScript?  The code deals with core network and certificate verification logic. This logic is *used by* the browser (which includes a JavaScript engine), but it's not directly calling or being called by JavaScript code. The connection is indirect. Provide examples of how JavaScript in a browser *relies on* this underlying verification (e.g., `fetch`, `XMLHttpRequest`, website security indicators). The key is to explain the architectural relationship.
    * **Logical Reasoning (Input/Output):**  Choose a simple, demonstrative scenario. Verifying a self-signed certificate is a good example because the outcome is predictable (failure without explicit trust). Clearly state the assumed input files and the expected console output.
    * **User/Programming Errors:** Think about common mistakes users might make when using this tool. Forgetting `--hostname`, providing incorrect file paths, using incompatible flags (like `--time` with `CertVerifyProc`), or misinterpreting the output are all good examples. Explain *why* these are errors and what the tool's response would be.
    * **User Path to Code (Debugging):** This requires understanding the broader browser architecture. When does certificate verification happen?  Browsing a secure website is the most obvious trigger. Trace the steps: user types URL, browser initiates connection, SSL/TLS handshake, certificate verification. Then, explain how a developer investigating a certificate issue might use this tool to isolate the problem. Mentioning command-line usage within a developer environment is relevant.

5. **Refine and Organize:**

    * **Clarity:** Use clear and concise language. Avoid jargon where possible, or explain it.
    * **Structure:**  Organize the answer logically, following the structure of the prompt. Use headings and bullet points for readability.
    * **Examples:**  Provide concrete examples to illustrate abstract concepts (e.g., trust strings, error scenarios).
    * **Accuracy:** Double-check your understanding of the code and the Chromium architecture.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this tool directly exposes some API to JavaScript. **Correction:**  Upon closer inspection, the code is a standalone command-line tool. The interaction with JavaScript is through the browser using the *results* of this verification, not direct function calls.
* **Initial thought:** Just list all the flags from `kUsage`. **Correction:** Group the functionalities logically for better understanding.
* **Initial thought:**  Focus only on successful scenarios for input/output. **Correction:** A failure scenario (like verifying a self-signed cert without trust) is more illustrative of the tool's behavior.
* **Initial thought:** Simply state the errors. **Correction:** Explain *why* they are errors and what the tool's feedback would be.

By following this systematic approach, combining code analysis with an understanding of the prompt's requirements, and refining the answers with examples and clear explanations, we can generate a comprehensive and accurate response.
`net/tools/cert_verify_tool/cert_verify_tool.cc` 是 Chromium 网络栈中的一个命令行工具，用于执行证书链的验证。它允许开发者和调试人员手动测试和检查证书验证过程，而无需通过完整的浏览器环境。

**功能列表:**

1. **加载证书链:**  可以从文件中读取目标证书以及可选的中间证书，构成待验证的证书链。
2. **指定信任根:** 可以指定额外的信任根证书文件，用于验证证书链的根是否受信任。可以选择忽略系统默认的信任根。
3. **选择验证实现:** 可以选择使用不同的证书验证实现，包括平台默认的验证器 (`platform`)，Chromium 内置的验证器 (`builtin`)，以及基于路径构建的验证器 (`pathbuilder`)。这允许比较不同验证器在相同输入下的行为。
4. **主机名验证:**  可以指定主机名，以便进行证书的主机名匹配验证。这对于测试服务器证书是否适用于特定的域名非常重要。
5. **时间控制:**  可以指定一个特定的时间点进行验证，而不是使用当前系统时间。这对于测试证书的有效期很有用。
6. **CRLSet 支持:** 可以加载 CRLSet (Certificate Revocation List Set) 文件，用于模拟浏览器在吊销检查中的行为。
7. **信任设置:** 可以为特定的证书（包括根证书和叶子证书）指定自定义的信任设置，例如将其标记为信任的锚点或叶子。
8. **输出调试信息:** 可以将验证后的证书链以 PEM 格式导出到文件中，方便进一步分析。
9. **多种输入格式:** 支持读取 DER 编码和 PEM 格式的证书文件。

**与 JavaScript 的关系:**

`cert_verify_tool.cc` 本身是一个 C++ 编写的命令行工具，**不直接与 JavaScript 代码交互**。然而，它的功能与 JavaScript 在浏览器中的行为密切相关。

在浏览器中，当 JavaScript 代码发起 HTTPS 请求时，浏览器会使用底层的网络栈（包括这个工具所测试的证书验证逻辑）来验证服务器提供的证书。如果证书验证失败，浏览器会阻止请求，并可能在开发者工具中显示错误信息。

**举例说明:**

假设一个网站使用了无效的 SSL 证书。

1. **用户操作 (浏览器):** 用户在浏览器地址栏输入该网站的 URL 并访问。
2. **浏览器行为:** 浏览器的网络栈会尝试与服务器建立 HTTPS 连接。在握手阶段，服务器会发送其证书链。
3. **底层证书验证:** 浏览器会使用其内置的证书验证逻辑（其行为可以被 `cert_verify_tool` 模拟）来验证服务器的证书链。
4. **验证失败:** 如果证书过期、主机名不匹配、或根证书不受信任，验证将失败。
5. **JavaScript 影响:**  如果验证失败，`fetch` API 或 `XMLHttpRequest` 等 JavaScript 网络请求会抛出错误，导致网页无法加载或部分功能受限。开发者可能会在浏览器的开发者工具的 Network 或 Console 面板中看到与证书相关的错误信息。

**使用 `cert_verify_tool` 进行调试:**

开发者可以使用 `cert_verify_tool` 来复现浏览器中的证书验证失败情况，并进行更详细的分析。例如：

```bash
# 假设 server.crt 包含了网站的证书，intermediate.crt 包含了中间证书
./cert_verify_tool server.crt --hostname=example.com

# 使用特定的信任根 ca.crt
./cert_verify_tool server.crt --hostname=example.com --roots=ca.crt

# 指定一个过去的时间进行验证
./cert_verify_tool server.crt --hostname=example.com --time="2022-01-01 00:00:00 GMT"
```

**逻辑推理与假设输入输出:**

假设我们有一个自签名证书 `self-signed.crt`。自签名证书通常不会被系统默认信任。

**假设输入:**

* `self-signed.crt`: 一个自签名证书文件。
* 命令: `./cert_verify_tool self-signed.crt --hostname=localhost`

**逻辑推理:**

由于 `self-signed.crt` 是自签名的，并且没有通过 `--roots` 指定为信任根，因此默认的证书验证过程（例如 `platform` 或 `builtin`）将会因为无法找到信任的根而失败。

**预期输出:**

```
Input chain:
 <指纹> <主题>

platform:
ERROR: net::ERR_CERT_AUTHORITY_INVALID

builtin:
ERROR: net::ERR_CERT_AUTHORITY_INVALID

pathbuilder:
ERROR: net::ERR_CERT_AUTHORITY_INVALID
```

输出会显示各个验证器都返回了 `net::ERR_CERT_AUTHORITY_INVALID` 错误，表明证书的颁发机构无效或不受信任。

**涉及用户或编程常见的使用错误:**

1. **忘记指定 `--hostname`:**  对于 `CertVerifyProc` 类型的验证器 (如 `platform` 和 `builtin`)，如果不指定 `--hostname`，工具会报错并跳过验证，因为主机名匹配是证书验证的关键步骤。
   ```bash
   ./cert_verify_tool server.crt
   ```
   输出可能包含类似 "ERROR: --hostname is required for CertVerifyProc (system), skipping" 的信息。

2. **指定了错误的文件路径:** 如果提供的证书文件路径不存在或无法读取，工具会报错。
   ```bash
   ./cert_verify_tool non_existent.crt --hostname=example.com
   ```
   输出可能会包含 "ERROR: Couldn't read certificate chain" 或类似的错误信息。

3. **使用 `--time` 参数与不支持的验证器:** `--time` 参数并非所有验证器都支持。例如，某些平台默认的验证器可能不支持自定义验证时间。使用 `--time` 与这些验证器可能会导致警告，并且实际验证会使用当前时间。
   ```bash
   ./cert_verify_tool server.crt --hostname=example.com --time="2022-01-01 00:00:00 GMT" --impls=platform
   ```
   输出可能会包含 "WARNING: --time is not supported by CertVerifyProc (system), will use current time."

4. **混淆信任设置:** 用户可能会错误地使用 `--trust-last-cert` 或 `--root-trust`，导致与预期不同的信任状态，从而得到误导性的验证结果。例如，错误地信任了一个恶意的中间证书。

**用户操作如何一步步到达这里 (作为调试线索):**

假设一个开发者在测试其网站的 HTTPS 配置时遇到问题，浏览器显示证书错误。以下是可能的调试步骤，最终可能使用到 `cert_verify_tool`:

1. **用户访问网站并看到证书错误:** 用户在浏览器中访问其网站，浏览器显示 "您的连接不是私密连接" 或类似的错误，表明证书验证失败。

2. **检查浏览器开发者工具:** 开发者打开浏览器的开发者工具，查看 "安全" 或 "网络" 面板，可能会看到具体的证书错误信息，例如 `NET::ERR_CERT_DATE_INVALID` (证书过期) 或 `NET::ERR_CERT_COMMON_NAME_INVALID` (主机名不匹配)。

3. **导出服务器证书链:** 开发者可能会使用浏览器或在线工具导出服务器提供的证书链，保存为 `server.crt` 和 `intermediate.crt` 等文件。

4. **使用 `openssl` 或类似工具进行初步检查:** 开发者可能会使用 `openssl` 命令查看证书的详细信息，例如有效期、主题、颁发者等。
   ```bash
   openssl x509 -in server.crt -text -noout
   ```

5. **使用 `cert_verify_tool` 进行更精细的验证:** 为了模拟浏览器的验证过程并使用不同的验证器进行对比，开发者会使用 `cert_verify_tool`。他们可能会尝试以下操作：
   * 验证完整链：`./cert_verify_tool server.crt intermediate.crt --hostname=example.com`
   * 排除中间证书的影响：`./cert_verify_tool server.crt --hostname=example.com` (只验证目标证书)
   * 指定信任根：如果怀疑是信任根的问题，可能会使用 `--roots` 参数指定信任根文件。
   * 模拟过期时间：使用 `--time` 参数检查证书在特定时间是否有效。
   * 比较不同验证器的结果：使用 `--impls` 参数选择不同的验证器，观察结果是否一致，以排除特定验证器实现的问题。

通过这些步骤，开发者可以使用 `cert_verify_tool` 作为一个强大的辅助工具，深入理解证书验证过程，并定位导致浏览器证书错误的根本原因。

Prompt: 
```
这是目录为net/tools/cert_verify_tool/cert_verify_tool.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <string_view>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/message_loop/message_pump_type.h"
#include "base/strings/string_split.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/cert/cert_net_fetcher.h"
#include "net/cert/cert_verify_proc.h"
#include "net/cert/cert_verify_proc_builtin.h"
#include "net/cert/crl_set.h"
#include "net/cert/do_nothing_ct_verifier.h"
#include "net/cert/internal/platform_trust_store.h"
#include "net/cert/internal/system_trust_store.h"
#include "net/cert/x509_util.h"
#include "net/cert_net/cert_net_fetcher_url_request.h"
#include "net/tools/cert_verify_tool/cert_verify_tool_util.h"
#include "net/tools/cert_verify_tool/verify_using_cert_verify_proc.h"
#include "net/tools/cert_verify_tool/verify_using_path_builder.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_context_getter.h"
#include "third_party/abseil-cpp/absl/cleanup/cleanup.h"
#include "third_party/boringssl/src/pki/trust_store.h"
#include "third_party/boringssl/src/pki/trust_store_collection.h"

#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
#include "net/proxy_resolution/proxy_config.h"
#include "net/proxy_resolution/proxy_config_service_fixed.h"
#endif

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
#include "net/cert/internal/trust_store_chrome.h"
#endif

namespace {

enum class RootStoreType {
  // No roots other than those explicitly passed in on the command line.
  kEmpty,
#if !BUILDFLAG(CHROME_ROOT_STORE_ONLY)
  // Use the system root store.
  kSystem,
#endif
  // Use the Chrome Root Store.
  kChrome
};

std::string GetUserAgent() {
  return "cert_verify_tool/0.1";
}

void SetUpOnNetworkThread(
    std::unique_ptr<net::URLRequestContext>* context,
    scoped_refptr<net::CertNetFetcherURLRequest>* cert_net_fetcher,
    base::WaitableEvent* initialization_complete_event) {
  net::URLRequestContextBuilder url_request_context_builder;
  url_request_context_builder.set_user_agent(GetUserAgent());
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
  // On Linux, use a fixed ProxyConfigService, since the default one
  // depends on glib.
  //
  // TODO(akalin): Remove this once http://crbug.com/146421 is fixed.
  url_request_context_builder.set_proxy_config_service(
      std::make_unique<net::ProxyConfigServiceFixed>(
          net::ProxyConfigWithAnnotation()));
#endif
  *context = url_request_context_builder.Build();

  // TODO(mattm): add command line flag to configure using
  // CertNetFetcher
  *cert_net_fetcher = base::MakeRefCounted<net::CertNetFetcherURLRequest>();
  (*cert_net_fetcher)->SetURLRequestContext(context->get());
  initialization_complete_event->Signal();
}

void ShutdownOnNetworkThread(
    std::unique_ptr<net::URLRequestContext>* context,
    scoped_refptr<net::CertNetFetcherURLRequest>* cert_net_fetcher) {
  (*cert_net_fetcher)->Shutdown();
  cert_net_fetcher->reset();
  context->reset();
}

// Base class to abstract running a particular implementation of certificate
// verification.
class CertVerifyImpl {
 public:
  virtual ~CertVerifyImpl() = default;

  virtual std::string GetName() const = 0;

  // Does certificate verification.
  //
  // Note that |hostname| may be empty to indicate that no name validation is
  // requested, and a null value of |verify_time| means to use the current time.
  virtual bool VerifyCert(const CertInput& target_der_cert,
                          const std::string& hostname,
                          const std::vector<CertInput>& intermediate_der_certs,
                          const std::vector<CertInputWithTrustSetting>&
                              der_certs_with_trust_settings,
                          base::Time verify_time,
                          net::CRLSet* crl_set,
                          const base::FilePath& dump_prefix_path) = 0;
};

// Runs certificate verification using a particular CertVerifyProc.
class CertVerifyImplUsingProc : public CertVerifyImpl {
 public:
  CertVerifyImplUsingProc(const std::string& name,
                          scoped_refptr<net::CertVerifyProc> proc)
      : name_(name), proc_(std::move(proc)) {}

  std::string GetName() const override { return name_; }

  bool VerifyCert(const CertInput& target_der_cert,
                  const std::string& hostname,
                  const std::vector<CertInput>& intermediate_der_certs,
                  const std::vector<CertInputWithTrustSetting>&
                      der_certs_with_trust_settings,
                  base::Time verify_time,
                  net::CRLSet* crl_set,
                  const base::FilePath& dump_prefix_path) override {
    if (!verify_time.is_null()) {
      std::cerr << "WARNING: --time is not supported by " << GetName()
                << ", will use current time.\n";
    }

    if (hostname.empty()) {
      std::cerr << "ERROR: --hostname is required for " << GetName()
                << ", skipping\n";
      return true;  // "skipping" is considered a successful return.
    }

    base::FilePath dump_path;
    if (!dump_prefix_path.empty()) {
      dump_path = dump_prefix_path.AddExtension(FILE_PATH_LITERAL(".pem"))
                      .InsertBeforeExtensionASCII("." + GetName());
    }

    return VerifyUsingCertVerifyProc(proc_.get(), target_der_cert, hostname,
                                     intermediate_der_certs,
                                     der_certs_with_trust_settings, dump_path);
  }

 private:
  const std::string name_;
  scoped_refptr<net::CertVerifyProc> proc_;
};

// Runs certificate verification using bssl::CertPathBuilder.
class CertVerifyImplUsingPathBuilder : public CertVerifyImpl {
 public:
  explicit CertVerifyImplUsingPathBuilder(
      scoped_refptr<net::CertNetFetcher> cert_net_fetcher,
      std::unique_ptr<net::SystemTrustStore> system_trust_store)
      : cert_net_fetcher_(std::move(cert_net_fetcher)),
        system_trust_store_(std::move(system_trust_store)) {}

  std::string GetName() const override { return "CertPathBuilder"; }

  bool VerifyCert(const CertInput& target_der_cert,
                  const std::string& hostname,
                  const std::vector<CertInput>& intermediate_der_certs,
                  const std::vector<CertInputWithTrustSetting>&
                      der_certs_with_trust_settings,
                  base::Time verify_time,
                  net::CRLSet* crl_set,
                  const base::FilePath& dump_prefix_path) override {
    if (!hostname.empty()) {
      std::cerr << "WARNING: --hostname is not verified with CertPathBuilder\n";
    }

    if (verify_time.is_null()) {
      verify_time = base::Time::Now();
    }

    return VerifyUsingPathBuilder(target_der_cert, intermediate_der_certs,
                                  der_certs_with_trust_settings, verify_time,
                                  dump_prefix_path, cert_net_fetcher_,
                                  system_trust_store_.get());
  }

 private:
  scoped_refptr<net::CertNetFetcher> cert_net_fetcher_;
  std::unique_ptr<net::SystemTrustStore> system_trust_store_;
};

class DummySystemTrustStore : public net::SystemTrustStore {
 public:
  bssl::TrustStore* GetTrustStore() override { return &trust_store_; }

  bool IsKnownRoot(const bssl::ParsedCertificate* trust_anchor) const override {
    return false;
  }

#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
  net::PlatformTrustStore* GetPlatformTrustStore() override { return nullptr; }

  bool IsLocallyTrustedRoot(
      const bssl::ParsedCertificate* trust_anchor) override {
    return false;
  }

  int64_t chrome_root_store_version() const override { return 0; }

  base::span<const net::ChromeRootCertConstraints> GetChromeRootConstraints(
      const bssl::ParsedCertificate* cert) const override {
    return {};
  }
#endif

 private:
  bssl::TrustStoreCollection trust_store_;
};

std::unique_ptr<net::SystemTrustStore> CreateSystemTrustStore(
    std::string_view impl_name,
    RootStoreType root_store_type) {
  switch (root_store_type) {
#if BUILDFLAG(IS_FUCHSIA)
    case RootStoreType::kSystem:
      std::cerr << impl_name
                << ": using system roots (--roots are in addition).\n";
      return net::CreateSslSystemTrustStore();
#endif
    case RootStoreType::kChrome:
#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
      std::cerr << impl_name
                << ": using Chrome Root Store (--roots are in addition).\n";
      return net::CreateSslSystemTrustStoreChromeRoot(
          std::make_unique<net::TrustStoreChrome>());
#else
      std::cerr << impl_name << ": not supported.\n";
      [[fallthrough]];
#endif

    case RootStoreType::kEmpty:
    default:
      std::cerr << impl_name << ": only using --roots specified.\n";
      return std::make_unique<DummySystemTrustStore>();
  }
}

// Creates an subclass of CertVerifyImpl based on its name, or returns nullptr.
std::unique_ptr<CertVerifyImpl> CreateCertVerifyImplFromName(
    std::string_view impl_name,
    scoped_refptr<net::CertNetFetcher> cert_net_fetcher,
    scoped_refptr<net::CRLSet> crl_set,
    RootStoreType root_store_type) {
#if !(BUILDFLAG(IS_FUCHSIA) || BUILDFLAG(CHROME_ROOT_STORE_ONLY))
  if (impl_name == "platform") {
    if (root_store_type != RootStoreType::kSystem) {
      std::cerr << "WARNING: platform verifier not supported with "
                   "--no-system-roots and --use-chrome-root-store, using "
                   "system roots (--roots are in addition).\n";
    }

    return std::make_unique<CertVerifyImplUsingProc>(
        "CertVerifyProc (system)",
        net::CertVerifyProc::CreateSystemVerifyProc(std::move(cert_net_fetcher),
                                                    std::move(crl_set)));
  }
#endif

  if (impl_name == "builtin") {
    return std::make_unique<CertVerifyImplUsingProc>(
        "CertVerifyProcBuiltin",
        net::CreateCertVerifyProcBuiltin(
            std::move(cert_net_fetcher), std::move(crl_set),
            // TODO(crbug.com/41392053): support CT.
            std::make_unique<net::DoNothingCTVerifier>(),
            base::MakeRefCounted<net::DefaultCTPolicyEnforcer>(),
            CreateSystemTrustStore(impl_name, root_store_type), {},
            std::nullopt));
  }

  if (impl_name == "pathbuilder") {
    return std::make_unique<CertVerifyImplUsingPathBuilder>(
        std::move(cert_net_fetcher),
        CreateSystemTrustStore(impl_name, root_store_type));
  }

  std::cerr << "WARNING: Unrecognized impl: " << impl_name << "\n";
  return nullptr;
}

void PrintCertHashAndSubject(CRYPTO_BUFFER* cert) {
  std::cout << " " << FingerPrintCryptoBuffer(cert) << " "
            << SubjectFromCryptoBuffer(cert) << "\n";
}

void PrintInputChain(const CertInput& target,
                     const std::vector<CertInput>& intermediates) {
  std::cout << "Input chain:\n";
  PrintCertHashAndSubject(
      net::x509_util::CreateCryptoBuffer(target.der_cert).get());
  for (const auto& intermediate : intermediates) {
    PrintCertHashAndSubject(
        net::x509_util::CreateCryptoBuffer(intermediate.der_cert).get());
  }
  std::cout << "\n";
}

void PrintAdditionalRoots(const std::vector<CertInputWithTrustSetting>&
                              der_certs_with_trust_settings) {
  std::cout << "Additional roots:\n";
  for (const auto& cert : der_certs_with_trust_settings) {
    std::cout << " " << cert.trust.ToDebugString() << ":\n ";
    PrintCertHashAndSubject(
        net::x509_util::CreateCryptoBuffer(cert.cert_input.der_cert).get());
  }
  std::cout << "\n";
}

const char kUsage[] =
    " [flags] <target/chain>\n"
    "\n"
    " <target/chain> is a file containing certificates [1]. Minimally it\n"
    " contains the target certificate. Optionally it may subsequently list\n"
    " additional certificates needed to build a chain (this is equivalent to\n"
    " specifying them through --intermediates)\n"
    "\n"
    "Flags:\n"
    "\n"
    " --hostname=<hostname>\n"
    "      The hostname required to match the end-entity certificate.\n"
    "      Required for the CertVerifyProc implementation.\n"
    "\n"
    " --roots=<certs path>\n"
    "      <certs path> is a file containing certificates [1] to interpret as\n"
    "      trust anchors (without any anchor constraints).\n"
    "\n"
    " --no-system-roots\n"
    "      Do not use system provided trust roots, only trust roots specified\n"
    "      by --roots or --trust-last-cert will be used. Only supported by\n"
    "      the builtin and pathbuilter impls.\n"
    "\n"
    " --use-chrome-root-store\n"
    "      Use the Chrome Root Store. Only supported by the builtin and \n"
    "      pathbuilder impls; if set will override the --no-system-roots \n"
    "      flag.\n"
    "\n"
    " --intermediates=<certs path>\n"
    "      <certs path> is a file containing certificates [1] for use when\n"
    "      path building is looking for intermediates.\n"
    "\n"
    " --impls=<ordered list of implementations>\n"
    "      Ordered list of the verifier implementations to run. If omitted,\n"
    "      will default to: \"platform,builtin,pathbuilder\".\n"
    "      Changing this can lead to different results in cases where the\n"
    "      platform verifier affects global caches (as in the case of NSS).\n"
    "\n"
    " --trust-last-cert\n"
    "      Removes the final intermediate from the chain and instead adds it\n"
    "      as a root. This is useful when providing a <target/chain>\n"
    "      parameter whose final certificate is a trust anchor.\n"
    "\n"
    " --root-trust=<trust string>\n"
    "      Roots trusted by --roots and --trust-last-cert will be trusted\n"
    "      with the specified trust [2].\n"
    "\n"
    " --trust-leaf-cert=[trust string]\n"
    "      The leaf cert will be considered trusted with the specified\n"
    "      trust [2]. If [trust string] is omitted, defaults to TRUSTED_LEAF.\n"
    "\n"
    " --time=<time>\n"
    "      Use <time> instead of the current system time. <time> is\n"
    "      interpreted in local time if a timezone is not specified.\n"
    "      Many common formats are supported, including:\n"
    "        1994-11-15 12:45:26 GMT\n"
    "        Tue, 15 Nov 1994 12:45:26 GMT\n"
    "        Nov 15 12:45:26 1994 GMT\n"
    "\n"
    " --crlset=<crlset path>\n"
    "      <crlset path> is a file containing a serialized CRLSet to use\n"
    "      during revocation checking. For example:\n"
    "        <chrome data dir>/CertificateRevocation/<number>/crl-set\n"
    "\n"
    " --dump=<file prefix>\n"
    "      Dumps the verified chain to PEM files starting with\n"
    "      <file prefix>.\n"
    "\n"
    "\n"
    "[1] A \"file containing certificates\" means a path to a file that can\n"
    "    either be:\n"
    "    * A binary file containing a single DER-encoded RFC 5280 Certificate\n"
    "    * A PEM file containing one or more CERTIFICATE blocks (DER-encoded\n"
    "      RFC 5280 Certificate)\n"
    "\n"
    "[2] A \"trust string\" consists of a trust type and zero or more options\n"
    "    separated by '+' characters. Note that these trust settings are only\n"
    "    honored by the builtin & pathbuilder impls.\n"
    "    Trust types: UNSPECIFIED, DISTRUSTED, TRUSTED_ANCHOR,\n"
    "                 TRUSTED_ANCHOR_OR_LEAF, TRUSTED_LEAF\n"
    "    Options: enforce_anchor_expiry, enforce_anchor_constraints,\n"
    "             require_anchor_basic_constraints, require_leaf_selfsigned\n"
    "    Ex: TRUSTED_ANCHOR+enforce_anchor_expiry+enforce_anchor_constraints\n";

void PrintUsage(const char* argv0) {
  std::cerr << "Usage: " << argv0 << kUsage;

  // TODO(mattm): allow <certs path> to be a directory containing DER/PEM files?
  // TODO(mattm): allow target to specify an HTTPS URL to check the cert of?
  // TODO(mattm): allow target to be a verify_certificate_chain_unittest .test
  // file?
  // TODO(mattm): allow specifying ocsp_response and sct_list inputs as well.
}

}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit_manager;
  if (!base::CommandLine::Init(argc, argv)) {
    std::cerr << "ERROR in CommandLine::Init\n";
    return 1;
  }
  base::ThreadPoolInstance::CreateAndStartWithDefaultParams("cert_verify_tool");
  absl::Cleanup cleanup = [] { base::ThreadPoolInstance::Get()->Shutdown(); };
  base::CommandLine& command_line = *base::CommandLine::ForCurrentProcess();
  logging::LoggingSettings settings;
  settings.logging_dest =
      logging::LOG_TO_SYSTEM_DEBUG_LOG | logging::LOG_TO_STDERR;
  logging::InitLogging(settings);

  base::CommandLine::StringVector args = command_line.GetArgs();
  if (args.size() != 1U || command_line.HasSwitch("help")) {
    PrintUsage(argv[0]);
    return 1;
  }

  std::string hostname = command_line.GetSwitchValueASCII("hostname");

  base::Time verify_time;
  std::string time_flag = command_line.GetSwitchValueASCII("time");
  if (!time_flag.empty()) {
    if (!base::Time::FromString(time_flag.c_str(), &verify_time)) {
      std::cerr << "Error parsing --time flag\n";
      return 1;
    }
  }

#if BUILDFLAG(CHROME_ROOT_STORE_ONLY)
  RootStoreType root_store_type = RootStoreType::kChrome;
#else
  RootStoreType root_store_type = RootStoreType::kSystem;
#endif

  if (command_line.HasSwitch("no-system-roots")) {
    root_store_type = RootStoreType::kEmpty;
  }
  if (command_line.HasSwitch("use-chrome-root-store")) {
    root_store_type = RootStoreType::kChrome;
  }

  base::FilePath roots_path = command_line.GetSwitchValuePath("roots");
  base::FilePath intermediates_path =
      command_line.GetSwitchValuePath("intermediates");
  base::FilePath target_path = base::FilePath(args[0]);

  base::FilePath crlset_path = command_line.GetSwitchValuePath("crlset");
  scoped_refptr<net::CRLSet> crl_set = net::CRLSet::BuiltinCRLSet();
  if (!crlset_path.empty()) {
    std::string crl_set_bytes;
    if (!ReadFromFile(crlset_path, &crl_set_bytes))
      return 1;
    if (!net::CRLSet::Parse(crl_set_bytes, &crl_set)) {
      std::cerr << "Error parsing CRLSet\n";
      return 1;
    }
  }

  base::FilePath dump_prefix_path = command_line.GetSwitchValuePath("dump");

  std::vector<CertInputWithTrustSetting> der_certs_with_trust_settings;
  std::vector<CertInput> root_der_certs;
  std::vector<CertInput> intermediate_der_certs;
  CertInput target_der_cert;

  if (!roots_path.empty())
    ReadCertificatesFromFile(roots_path, &root_der_certs);
  if (!intermediates_path.empty())
    ReadCertificatesFromFile(intermediates_path, &intermediate_der_certs);

  if (!ReadChainFromFile(target_path, &target_der_cert,
                         &intermediate_der_certs)) {
    std::cerr << "ERROR: Couldn't read certificate chain\n";
    return 1;
  }

  if (target_der_cert.der_cert.empty()) {
    std::cerr << "ERROR: no target cert\n";
    return 1;
  }

  // If --trust-last-cert was specified, move the final intermediate to the
  // roots list.
  if (command_line.HasSwitch("trust-last-cert")) {
    if (intermediate_der_certs.empty()) {
      std::cerr << "ERROR: no intermediate certificates\n";
      return 1;
    }

    root_der_certs.push_back(intermediate_der_certs.back());
    intermediate_der_certs.pop_back();
  }

  if (command_line.HasSwitch("trust-leaf-cert")) {
    bssl::CertificateTrust trust = bssl::CertificateTrust::ForTrustedLeaf();
    std::string trust_str = command_line.GetSwitchValueASCII("trust-leaf-cert");
    if (!trust_str.empty()) {
      std::optional<bssl::CertificateTrust> parsed_trust =
          bssl::CertificateTrust::FromDebugString(trust_str);
      if (!parsed_trust) {
        std::cerr << "ERROR: invalid leaf trust string " << trust_str << "\n";
        return 1;
      }
      trust = *parsed_trust;
    }
    der_certs_with_trust_settings.push_back({target_der_cert, trust});
  }

  // TODO(crbug.com/40888483): Maybe default to the trust setting that
  // would be used for locally added anchors on the current platform?
  bssl::CertificateTrust root_trust = bssl::CertificateTrust::ForTrustAnchor();

  if (command_line.HasSwitch("root-trust")) {
    std::string trust_str = command_line.GetSwitchValueASCII("root-trust");
    std::optional<bssl::CertificateTrust> parsed_trust =
        bssl::CertificateTrust::FromDebugString(trust_str);
    if (!parsed_trust) {
      std::cerr << "ERROR: invalid root trust string " << trust_str << "\n";
      return 1;
    }
    root_trust = *parsed_trust;
  }

  for (const auto& cert_input : root_der_certs) {
    der_certs_with_trust_settings.push_back({cert_input, root_trust});
  }

  PrintInputChain(target_der_cert, intermediate_der_certs);
  if (!der_certs_with_trust_settings.empty()) {
    PrintAdditionalRoots(der_certs_with_trust_settings);
  }

  // Create a network thread to be used for AIA fetches, and wait for a
  // CertNetFetcher to be constructed on that thread.
  base::Thread::Options options(base::MessagePumpType::IO, 0);
  base::Thread thread("network_thread");
  CHECK(thread.StartWithOptions(std::move(options)));
  // Owned by this thread, but initialized, used, and shutdown on the network
  // thread.
  std::unique_ptr<net::URLRequestContext> context;
  scoped_refptr<net::CertNetFetcherURLRequest> cert_net_fetcher;
  base::WaitableEvent initialization_complete_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  thread.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&SetUpOnNetworkThread, &context, &cert_net_fetcher,
                     &initialization_complete_event));
  initialization_complete_event.Wait();

  std::vector<std::unique_ptr<CertVerifyImpl>> impls;

  // Parse the ordered list of CertVerifyImpl passed via command line flags into
  // |impls|.
  std::string impls_str = command_line.GetSwitchValueASCII("impls");
  if (impls_str.empty()) {
    // Default value.
#if !(BUILDFLAG(IS_FUCHSIA) || BUILDFLAG(IS_LINUX) || \
      BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(CHROME_ROOT_STORE_ONLY))
    impls_str = "platform,";
#endif
    impls_str += "builtin,pathbuilder";
  }

  std::vector<std::string> impl_names = base::SplitString(
      impls_str, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  for (const std::string& impl_name : impl_names) {
    auto verify_impl = CreateCertVerifyImplFromName(impl_name, cert_net_fetcher,
                                                    crl_set, root_store_type);
    if (verify_impl)
      impls.push_back(std::move(verify_impl));
  }

  // Sequentially run the chain with each of the selected verifier
  // implementations.
  bool all_impls_success = true;

  for (size_t i = 0; i < impls.size(); ++i) {
    if (i != 0)
      std::cout << "\n";

    std::cout << impls[i]->GetName() << ":\n";
    if (!impls[i]->VerifyCert(target_der_cert, hostname, intermediate_der_certs,
                              der_certs_with_trust_settings, verify_time,
                              crl_set.get(), dump_prefix_path)) {
      all_impls_success = false;
    }
  }

  // Clean up on the network thread and stop it (which waits for the clean up
  // task to run).
  thread.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&ShutdownOnNetworkThread, &context, &cert_net_fetcher));
  thread.Stop();

  return all_impls_success ? 0 : 1;
}

"""

```
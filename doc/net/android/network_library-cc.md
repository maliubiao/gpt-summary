Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Understanding the Goal:**

The request asks for an analysis of the `network_library.cc` file within the Chromium networking stack. The key requirements are:

* **Functionality Summary:** What does this file do?
* **JavaScript Relationship:** Does it interact with JavaScript, and how?
* **Logical Inference:** Are there functions that perform reasoning based on inputs? Provide examples.
* **Common Errors:** What mistakes might developers or users make when interacting with this code?
* **Debugging Path:** How does user interaction lead to this code being executed?

**2. Initial Code Scan and Keyword Spotting:**

The first step is to quickly scan the code for important keywords and patterns. This helps to get a high-level understanding.

* **`#include` statements:** These indicate dependencies and areas of focus. Notice `jni.h`, `base/android`, `net/base`, `net/dns`. This immediately suggests interaction with Android's Java layer and core networking concepts.
* **Function names:** Look for descriptive function names. `GetUserAddedRoots`, `VerifyX509CertChain`, `IsCleartextPermitted`, `GetMimeTypeFromExtension`, `GetCurrentDnsServers`, `BindToNetwork`. These provide clues about the file's purpose.
* **JNI calls:**  The patterns `Java_AndroidNetworkLibrary_...` and `base::android::AttachCurrentThread()` are strong indicators of Java Native Interface calls.
* **`base::` namespace:**  Functions like `ConvertUTF8ToJavaString`, `ConvertJavaStringToUTF8`, `SplitString` suggest utility functions from the Chromium base library.
* **Networking terms:**  "DNS", "certificate", "socket", "network", "IPAddress", "IPEndPoint".
* **Conditional compilation/SDK version checks:** The `DCHECK_GE(base::android::BuildInfo::GetInstance()->sdk_int(), ...)` patterns suggest handling different Android versions.

**3. Grouping Functionality:**

Based on the keywords and function names, start grouping related functionalities:

* **Certificate Handling:** `GetUserAddedRoots`, `VerifyX509CertChain`, `AddTestRootCertificate`, `ClearTestRootCertificates`.
* **Network Policy/Permissions:** `IsCleartextPermitted`.
* **Network Information:** `HaveOnlyLoopbackAddresses`, `GetTelephonyNetworkOperator`, `GetIsRoaming`, `GetIsCaptivePortal`, `GetWifiSSID`, `GetWifiSignalLevel`.
* **MIME Type Handling:** `GetMimeTypeFromExtension`.
* **DNS Resolution:** `GetCurrentDnsServers`, `GetDnsServersForNetwork`.
* **Socket Binding:** `BindToNetwork`.
* **Low-Level Socket/Network Interaction:** `TagSocket`, `GetAddrInfoForNetwork`.
* **Testing Helpers:** `SetWifiEnabledForTesting`.

**4. Analyzing Each Function (Focus on the Request's Requirements):**

Now, delve into each function, keeping the request's specific points in mind:

* **Functionality:**  Describe what each function does. Use the function name and the JNI calls as primary indicators.
* **JavaScript Relationship:**  This is where understanding JNI is crucial. Realize that this C++ code acts as a bridge. While *this specific file* doesn't directly call JavaScript, its functions are likely called *by* Java code, which *can* be invoked by JavaScript through the WebView or other mechanisms. The key is to identify the bridge nature. Provide examples of what kind of data is being exchanged (strings, byte arrays).
* **Logical Inference:** Look for functions that make decisions or transform data based on input. `VerifyX509CertChain` is a prime example – it takes certificates and other info and returns a status. Think about the *inputs* and the likely *outputs*.
* **Common Errors:**  Consider the parameters each function takes and potential mistakes a developer might make. Incorrect certificate formats, invalid hostnames, or calling version-specific functions on older Android versions are good candidates. Think about *how* a user action might lead to these errors.
* **Debugging Path:** This requires understanding the architecture. Imagine a user browsing a website. Trace the likely path: User action -> JavaScript in WebView -> Java code in Android framework -> JNI call to this C++ code. Focus on actions that relate to the functionality of each function. For example, accessing an HTTPS site triggers certificate verification.

**5. Addressing Specific Request Points:**

* **Listing Functions:** Simply enumerate the public functions.
* **JavaScript Relationship:** Emphasize the JNI bridge nature and how data is marshalled. Provide concrete examples of data types being passed.
* **Logical Inference:**  Select a function that performs a decision or transformation (`VerifyX509CertChain` is ideal). Clearly state the assumed inputs and possible outputs.
* **Common Errors:**  Focus on practical mistakes related to the function's purpose.
* **User Operation to Code:** Describe a realistic user scenario that leads to the execution of functions within this file. Start from a high-level user action and narrow down.

**6. Structuring the Output:**

Organize the analysis logically. Start with a general overview of the file's purpose. Then, address each of the request's points systematically. Use clear headings and bullet points to improve readability. Provide concrete examples wherever possible.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file handles all networking in Android."  **Correction:**  It's *part* of the Chromium networking stack's Android integration. It bridges to the Android system.
* **Initial thought:** "JavaScript directly calls these functions." **Correction:** JavaScript calls into the WebView or Android framework, which then uses JNI to invoke this C++ code.
* **Realizing the importance of JNI:** The presence of JNI is a recurring theme and needs to be highlighted throughout the analysis.

By following these steps, systematically examining the code, and constantly relating back to the specific requirements of the request, a comprehensive and accurate analysis can be produced.
This C++ source file, `network_library.cc`, located within the `net/android` directory of the Chromium project's network stack, serves as a **bridge between Chromium's network code and the Android operating system's networking capabilities.**  It uses the Java Native Interface (JNI) to interact with Java code in the Android framework.

Here's a breakdown of its functions:

**Core Functionalities:**

* **Certificate Management:**
    * `GetUserAddedRoots()`: Retrieves the list of user-added root certificates from the Android system. This is used for trust decisions during secure connections.
    * `VerifyX509CertChain()`:  Verifies an X.509 certificate chain against the system's trusted roots (including user-added ones). This is crucial for HTTPS and other secure protocols. It delegates the actual verification to Android's Java-based certificate verification mechanisms.
    * `AddTestRootCertificate()`: Adds a test root certificate. This is primarily for testing purposes and allows developers to simulate scenarios with custom certificate authorities.
    * `ClearTestRootCertificates()`: Clears the list of added test root certificates.

* **Network Policy and Permissions:**
    * `IsCleartextPermitted()`: Checks if cleartext (unencrypted HTTP) traffic is permitted for a given host, based on Android's Network Security Configuration.

* **Network Information Retrieval:**
    * `HaveOnlyLoopbackAddresses()`: Determines if the device currently only has loopback addresses (meaning no external network connectivity).
    * `GetMimeTypeFromExtension()`:  Retrieves the MIME type associated with a given file extension, leveraging Android's `MimeTypeMap`.
    * `GetTelephonyNetworkOperator()`: Gets the name of the current mobile network operator.
    * `GetIsRoaming()`: Checks if the device is currently in a roaming state on the mobile network.
    * `GetIsCaptivePortal()`: Detects if the device is currently behind a captive portal (a network that requires authentication before granting internet access).
    * `GetWifiSSID()`: Retrieves the SSID (name) of the currently connected Wi-Fi network.
    * `GetWifiSignalLevel()`: Gets the current Wi-Fi signal level, divided into buckets.
    * `GetCurrentDnsServers()`: Retrieves the DNS server addresses, DoT status, and search suffixes for the current default network.
    * `GetDnsServersForNetwork()`: Retrieves the DNS server addresses, DoT status, and search suffixes for a specific network.

* **Socket Management and Binding:**
    * `TagSocket()`: Associates a socket with a specific user ID (UID) and tag. This is used for network traffic accounting and policy enforcement.
    * `BindToNetwork()`: Attempts to bind a socket to a specific network interface. This allows the application to force traffic through a particular network when multiple are available (requires Android Lollipop or later).
    * `GetAddrInfoForNetwork()`:  Performs DNS resolution for a specific network (requires Android Marshmallow or later). This is a network-aware version of `getaddrinfo`.

* **Testing and Debugging:**
    * `SetWifiEnabledForTesting()`:  Allows programmatic enabling or disabling of Wi-Fi (primarily for testing).
    * `ReportBadDefaultNetwork()`:  Signals to the Android system that the current default network is experiencing issues.

**Relationship with JavaScript:**

This C++ code **does not directly interact with JavaScript**. However, it plays a crucial role in enabling network functionality that JavaScript running within a Chromium-based browser (like Chrome or a WebView) relies upon.

Here's how the connection works:

1. **JavaScript makes a network request:** When JavaScript code in a web page or application needs to access a resource over the network (e.g., fetching an image, making an AJAX call), it uses web APIs like `fetch` or `XMLHttpRequest`.

2. **Browser processes the request:** The browser's rendering engine (Blink) processes this request. For network operations on Android, it often needs to interact with the underlying operating system's network stack.

3. **Java layer interaction:** Chromium's Java code (within the `org.chromium.net` package and related areas) acts as an intermediary. This Java code receives the network request details from the C++ core.

4. **JNI calls to `network_library.cc`:** The Java code then uses JNI to call functions within `network_library.cc`. For example:
    * If the request is for an HTTPS URL, `VerifyX509CertChain()` might be called to validate the server's certificate.
    * If the browser needs to know if it's on a Wi-Fi network, `GetWifiSSID()` could be invoked.
    * When establishing a socket connection, `BindToNetwork()` might be used to select a specific network interface.

5. **Interaction with Android System:** The functions in `network_library.cc` then make calls to Android's system APIs to perform the necessary network operations.

**Example of Indirect JavaScript Relationship:**

Imagine JavaScript code tries to load an HTTPS website:

```javascript
fetch('https://www.example.com');
```

Here's a simplified breakdown of how this might involve `network_library.cc`:

1. The JavaScript `fetch` call is initiated.
2. Chromium's rendering engine (Blink) handles this request.
3. The network stack in Chromium (written in C++) determines the need for a secure connection.
4. The C++ code interacts with the Java layer in Chromium on Android.
5. The Java code (e.g., in `CronetEngine.java` or related classes) calls the JNI method that corresponds to the C++ function `VerifyX509CertChain()` in `network_library.cc`. This call passes the server's certificate chain to the C++ code.
6. `VerifyX509CertChain()` uses JNI to call Android's certificate verification APIs.
7. Android's system APIs perform the certificate validation.
8. The result of the validation is passed back through the JNI bridge to the Java layer, then back to the C++ network stack.
9. Based on the verification result, the connection is either established or rejected, and the JavaScript `fetch` promise resolves or rejects accordingly.

**Logical Inference (Hypothetical Examples):**

While this file primarily acts as a bridge, some functions involve a degree of logical inference based on the Android system's state:

* **`IsCleartextPermitted(std::string_view host)`:**
    * **Hypothetical Input:** `host = "example.com"`
    * **Logical Inference:** The function calls the Android system to check the Network Security Configuration for the domain "example.com".
    * **Hypothetical Output:** `true` (if cleartext is allowed) or `false` (if cleartext is blocked).

* **`GetIsCaptivePortal()`:**
    * **Hypothetical Input:** (Implicit - the current network state)
    * **Logical Inference:** The function queries Android's network connectivity service to determine if the device is currently connected to a network that requires login through a captive portal.
    * **Hypothetical Output:** `true` (if a captive portal is detected) or `false` (otherwise).

**User or Programming Common Usage Errors:**

* **Calling Android version-specific functions on older devices:**
    * **Error:** Calling `GetDnsServersForNetwork()` on an Android version prior to P (Pie).
    * **Consequence:** The function will likely return an error or have undefined behavior because the underlying Android API doesn't exist.
    * **User Action Leading to Error:** A user might be using an older Android device running an application built with a newer Chromium version that attempts to use this function.

* **Incorrectly handling certificate verification results:**
    * **Error:** Not properly checking the `CertVerifyStatusAndroid` returned by `VerifyX509CertChain()` and proceeding with a connection even if the certificate is invalid.
    * **Consequence:**  Security vulnerabilities, as the application might connect to a malicious server impersonating a legitimate one.
    * **User Action Leading to Error:** A user might be visiting a website with an expired or invalid certificate. The application developer's error in handling the verification result would lead to a compromised connection.

* **Misinterpreting network state information:**
    * **Error:** Making assumptions about network connectivity based solely on `HaveOnlyLoopbackAddresses()` without considering other factors like VPNs or firewalls.
    * **Consequence:** Incorrect application behavior, such as failing to attempt network requests when a limited network connection is actually available.
    * **User Action Leading to Error:** A user might be on a network with restricted access, and the application incorrectly interprets this as a complete lack of connectivity.

* **Incorrectly using `BindToNetwork()`:**
    * **Error:** Attempting to bind a socket to a network that is no longer available.
    * **Consequence:** Network errors and connection failures.
    * **User Action Leading to Error:** A user might be on a device with multiple network interfaces (e.g., Wi-Fi and cellular) and the application attempts to force traffic through a Wi-Fi network that has just disconnected.

**User Operation Stepping Stones as Debugging Clues:**

Let's consider a few scenarios and how user actions might lead to this code being executed, serving as debugging clues:

1. **User visits an HTTPS website:**
   * **User Action:** Types a URL starting with "https://" in the address bar or clicks an HTTPS link.
   * **Path to `network_library.cc`:**
      * Browser initiates a network connection.
      * Chromium's network stack needs to verify the server's SSL/TLS certificate.
      * The C++ code (potentially in `net/ssl/ssl_client_socket_impl.cc`) will interact with the Java layer.
      * The Java layer calls the JNI method corresponding to `VerifyX509CertChain()` in `network_library.cc`.

2. **User connects to a Wi-Fi network:**
   * **User Action:** Taps on a Wi-Fi network in the Android settings or the device automatically connects to a known Wi-Fi network.
   * **Path to `network_library.cc`:**
      * The browser or an application might want to know the name of the connected Wi-Fi network.
      * Java code in Chromium (e.g., for displaying connection information or for network diagnostics) calls the JNI method for `GetWifiSSID()` in `network_library.cc`.

3. **User experiences network connectivity issues:**
   * **User Action:** Reports that a website is not loading or an app cannot connect to the internet.
   * **Path to `network_library.cc` (as part of debugging):**
      * Developers might use internal debugging tools or logging within Chromium.
      * These tools might query network status information to diagnose the problem.
      * Functions like `HaveOnlyLoopbackAddresses()`, `GetIsCaptivePortal()`, `GetCurrentDnsServers()`, or `GetIsRoaming()` might be called through the JNI bridge to gather network details.

4. **Application needs to download a file:**
   * **User Action:** Initiates a file download within a web page or application.
   * **Path to `network_library.cc`:**
      * The download process might need to determine the correct MIME type for the downloaded file based on its extension.
      * The Java download manager or related code in Chromium might call the JNI method for `GetMimeTypeFromExtension()` in `network_library.cc`.

In summary, `net/android/network_library.cc` is a vital component of Chromium on Android, acting as the crucial link between Chromium's network logic and the underlying Android system's networking capabilities. It handles a wide range of tasks, from certificate verification and network policy enforcement to retrieving network information and managing socket connections. While it doesn't directly interact with JavaScript, its functions are essential for enabling the network functionality that JavaScript code relies upon. Understanding this bridge is crucial for debugging network-related issues in Chromium-based applications on Android.

### 提示词
```
这是目录为net/android/network_library.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/android/network_library.h"

#include <dlfcn.h>

#include <string>
#include <string_view>
#include <vector>

#include "base/android/build_info.h"
#include "base/android/jni_android.h"
#include "base/android/jni_array.h"
#include "base/android/jni_string.h"
#include "base/android/scoped_java_ref.h"
#include "base/check_op.h"
#include "base/native_library.h"
#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/scoped_blocking_call.h"
#include "net/base/net_errors.h"
#include "net/dns/public/dns_protocol.h"

// Must come after all headers that specialize FromJniType() / ToJniType().
#include "net/net_jni_headers/AndroidNetworkLibrary_jni.h"
#include "net/net_jni_headers/DnsStatus_jni.h"

using base::android::AttachCurrentThread;
using base::android::ConvertJavaStringToUTF8;
using base::android::ConvertUTF8ToJavaString;
using base::android::JavaArrayOfByteArrayToStringVector;
using base::android::ScopedJavaLocalRef;
using base::android::ToJavaArrayOfByteArray;
using base::android::ToJavaByteArray;

namespace net::android {

std::vector<std::string> GetUserAddedRoots() {
  std::vector<std::string> roots;
  JNIEnv* env = AttachCurrentThread();

  ScopedJavaLocalRef<jobjectArray> roots_byte_array =
      Java_AndroidNetworkLibrary_getUserAddedRoots(env);
  JavaArrayOfByteArrayToStringVector(env, roots_byte_array, &roots);
  return roots;
}

void VerifyX509CertChain(const std::vector<std::string>& cert_chain,
                         std::string_view auth_type,
                         std::string_view host,
                         CertVerifyStatusAndroid* status,
                         bool* is_issued_by_known_root,
                         std::vector<std::string>* verified_chain) {
  JNIEnv* env = AttachCurrentThread();

  ScopedJavaLocalRef<jobjectArray> chain_byte_array =
      ToJavaArrayOfByteArray(env, cert_chain);
  DCHECK(!chain_byte_array.is_null());

  ScopedJavaLocalRef<jstring> auth_string =
      ConvertUTF8ToJavaString(env, auth_type);
  DCHECK(!auth_string.is_null());

  ScopedJavaLocalRef<jstring> host_string =
      ConvertUTF8ToJavaString(env, host);
  DCHECK(!host_string.is_null());

  ScopedJavaLocalRef<jobject> result =
      Java_AndroidNetworkLibrary_verifyServerCertificates(
          env, chain_byte_array, auth_string, host_string);

  ExtractCertVerifyResult(result, status, is_issued_by_known_root,
                          verified_chain);
}

void AddTestRootCertificate(base::span<const uint8_t> cert) {
  JNIEnv* env = AttachCurrentThread();
  ScopedJavaLocalRef<jbyteArray> cert_array = ToJavaByteArray(env, cert);
  DCHECK(!cert_array.is_null());
  Java_AndroidNetworkLibrary_addTestRootCertificate(env, cert_array);
}

void ClearTestRootCertificates() {
  JNIEnv* env = AttachCurrentThread();
  Java_AndroidNetworkLibrary_clearTestRootCertificates(env);
}

bool IsCleartextPermitted(std::string_view host) {
  JNIEnv* env = AttachCurrentThread();
  ScopedJavaLocalRef<jstring> host_string = ConvertUTF8ToJavaString(env, host);
  return Java_AndroidNetworkLibrary_isCleartextPermitted(env, host_string);
}

bool HaveOnlyLoopbackAddresses() {
  base::ScopedBlockingCall scoped_blocking_call(FROM_HERE,
                                                base::BlockingType::MAY_BLOCK);
  JNIEnv* env = AttachCurrentThread();
  return Java_AndroidNetworkLibrary_haveOnlyLoopbackAddresses(env);
}

bool GetMimeTypeFromExtension(std::string_view extension, std::string* result) {
  JNIEnv* env = AttachCurrentThread();

  ScopedJavaLocalRef<jstring> extension_string =
      ConvertUTF8ToJavaString(env, extension);
  ScopedJavaLocalRef<jstring> ret =
      Java_AndroidNetworkLibrary_getMimeTypeFromExtension(env,
                                                          extension_string);

  if (!ret.obj())
    return false;
  *result = ConvertJavaStringToUTF8(ret);
  return true;
}

std::string GetTelephonyNetworkOperator() {
  return base::android::ConvertJavaStringToUTF8(
      Java_AndroidNetworkLibrary_getNetworkOperator(
          base::android::AttachCurrentThread()));
}

bool GetIsRoaming() {
  return Java_AndroidNetworkLibrary_getIsRoaming(
      base::android::AttachCurrentThread());
}

bool GetIsCaptivePortal() {
  return Java_AndroidNetworkLibrary_getIsCaptivePortal(
      base::android::AttachCurrentThread());
}

std::string GetWifiSSID() {
  return base::android::ConvertJavaStringToUTF8(
      Java_AndroidNetworkLibrary_getWifiSSID(
          base::android::AttachCurrentThread()));
}

void SetWifiEnabledForTesting(bool enabled) {
  Java_AndroidNetworkLibrary_setWifiEnabledForTesting(
      base::android::AttachCurrentThread(), enabled);
}

std::optional<int32_t> GetWifiSignalLevel() {
  const int count_buckets = 5;
  int signal_strength = Java_AndroidNetworkLibrary_getWifiSignalLevel(
      base::android::AttachCurrentThread(), count_buckets);
  if (signal_strength < 0)
    return std::nullopt;
  DCHECK_LE(0, signal_strength);
  DCHECK_GE(count_buckets - 1, signal_strength);

  return signal_strength;
}

namespace {

bool GetDnsServersInternal(JNIEnv* env,
                           const base::android::JavaRef<jobject>& dns_status,
                           std::vector<IPEndPoint>* dns_servers,
                           bool* dns_over_tls_active,
                           std::string* dns_over_tls_hostname,
                           std::vector<std::string>* search_suffixes) {
  // Parse the DNS servers.
  std::vector<std::vector<uint8_t>> dns_servers_data;
  base::android::JavaArrayOfByteArrayToBytesVector(
      env, Java_DnsStatus_getDnsServers(env, dns_status), &dns_servers_data);
  for (const std::vector<uint8_t>& dns_address_data : dns_servers_data) {
    IPAddress dns_address(dns_address_data);
    IPEndPoint dns_server(dns_address, dns_protocol::kDefaultPort);
    dns_servers->push_back(dns_server);
  }

  *dns_over_tls_active = Java_DnsStatus_getPrivateDnsActive(env, dns_status);
  *dns_over_tls_hostname = base::android::ConvertJavaStringToUTF8(
      Java_DnsStatus_getPrivateDnsServerName(env, dns_status));

  std::string search_suffixes_str = base::android::ConvertJavaStringToUTF8(
      Java_DnsStatus_getSearchDomains(env, dns_status));
  *search_suffixes =
      base::SplitString(search_suffixes_str, ",", base::TRIM_WHITESPACE,
                        base::SPLIT_WANT_NONEMPTY);

  return !dns_servers->empty();
}

}  // namespace

bool GetCurrentDnsServers(std::vector<IPEndPoint>* dns_servers,
                          bool* dns_over_tls_active,
                          std::string* dns_over_tls_hostname,
                          std::vector<std::string>* search_suffixes) {
  DCHECK_GE(base::android::BuildInfo::GetInstance()->sdk_int(),
            base::android::SDK_VERSION_MARSHMALLOW);

  JNIEnv* env = AttachCurrentThread();
  // Get the DNS status for the current default network.
  ScopedJavaLocalRef<jobject> result =
      Java_AndroidNetworkLibrary_getCurrentDnsStatus(env);
  if (result.is_null())
    return false;
  return GetDnsServersInternal(env, result, dns_servers, dns_over_tls_active,
                               dns_over_tls_hostname, search_suffixes);
}

bool GetDnsServersForNetwork(std::vector<IPEndPoint>* dns_servers,
                             bool* dns_over_tls_active,
                             std::string* dns_over_tls_hostname,
                             std::vector<std::string>* search_suffixes,
                             handles::NetworkHandle network) {
  DCHECK_GE(base::android::BuildInfo::GetInstance()->sdk_int(),
            base::android::SDK_VERSION_P);

  JNIEnv* env = AttachCurrentThread();
  ScopedJavaLocalRef<jobject> result =
      Java_AndroidNetworkLibrary_getDnsStatusForNetwork(env, network);
  if (result.is_null())
    return false;
  return GetDnsServersInternal(env, result, dns_servers, dns_over_tls_active,
                               dns_over_tls_hostname, search_suffixes);
}

bool ReportBadDefaultNetwork() {
  return Java_AndroidNetworkLibrary_reportBadDefaultNetwork(
      AttachCurrentThread());
}

void TagSocket(SocketDescriptor socket, uid_t uid, int32_t tag) {
  Java_AndroidNetworkLibrary_tagSocket(AttachCurrentThread(), socket, uid, tag);
}

namespace {

using LollipopSetNetworkForSocket = int (*)(unsigned net_id, int socket_fd);
using MarshmallowSetNetworkForSocket = int (*)(int64_t net_id, int socket_fd);

MarshmallowSetNetworkForSocket GetMarshmallowSetNetworkForSocket() {
  // On Android M and newer releases use supported NDK API.
  base::FilePath file(base::GetNativeLibraryName("android"));
  // See declaration of android_setsocknetwork() here:
  // http://androidxref.com/6.0.0_r1/xref/development/ndk/platforms/android-M/include/android/multinetwork.h#65
  // Function cannot be called directly as it will cause app to fail to load on
  // pre-marshmallow devices.
  void* dl = dlopen(file.value().c_str(), RTLD_NOW);
  return reinterpret_cast<MarshmallowSetNetworkForSocket>(
      dlsym(dl, "android_setsocknetwork"));
}

LollipopSetNetworkForSocket GetLollipopSetNetworkForSocket() {
  // On Android L use setNetworkForSocket from libnetd_client.so. Android's netd
  // client library should always be loaded in our address space as it shims
  // socket().
  base::FilePath file(base::GetNativeLibraryName("netd_client"));
  // Use RTLD_NOW to match Android's prior loading of the library:
  // http://androidxref.com/6.0.0_r5/xref/bionic/libc/bionic/NetdClient.cpp#37
  // Use RTLD_NOLOAD to assert that the library is already loaded and avoid
  // doing any disk IO.
  void* dl = dlopen(file.value().c_str(), RTLD_NOW | RTLD_NOLOAD);
  return reinterpret_cast<LollipopSetNetworkForSocket>(
      dlsym(dl, "setNetworkForSocket"));
}

}  // namespace

int BindToNetwork(SocketDescriptor socket, handles::NetworkHandle network) {
  DCHECK_NE(socket, kInvalidSocket);
  if (network == handles::kInvalidNetworkHandle)
    return ERR_INVALID_ARGUMENT;

  // Android prior to Lollipop didn't have support for binding sockets to
  // networks.
  if (base::android::BuildInfo::GetInstance()->sdk_int() <
      base::android::SDK_VERSION_LOLLIPOP)
    return ERR_NOT_IMPLEMENTED;

  int rv;
  if (base::android::BuildInfo::GetInstance()->sdk_int() >=
      base::android::SDK_VERSION_MARSHMALLOW) {
    static MarshmallowSetNetworkForSocket marshmallow_set_network_for_socket =
        GetMarshmallowSetNetworkForSocket();
    if (!marshmallow_set_network_for_socket)
      return ERR_NOT_IMPLEMENTED;
    rv = marshmallow_set_network_for_socket(network, socket);
    if (rv)
      rv = errno;
  } else {
    static LollipopSetNetworkForSocket lollipop_set_network_for_socket =
        GetLollipopSetNetworkForSocket();
    if (!lollipop_set_network_for_socket)
      return ERR_NOT_IMPLEMENTED;
    rv = -lollipop_set_network_for_socket(network, socket);
  }
  // If |network| has since disconnected, |rv| will be ENONET.  Surface this as
  // ERR_NETWORK_CHANGED, rather than MapSystemError(ENONET) which gives back
  // the less descriptive ERR_FAILED.
  if (rv == ENONET)
    return ERR_NETWORK_CHANGED;
  return MapSystemError(rv);
}

namespace {

using MarshmallowGetAddrInfoForNetwork = int (*)(int64_t network,
                                                 const char* node,
                                                 const char* service,
                                                 const struct addrinfo* hints,
                                                 struct addrinfo** res);

MarshmallowGetAddrInfoForNetwork GetMarshmallowGetAddrInfoForNetwork() {
  // On Android M and newer releases use supported NDK API.
  base::FilePath file(base::GetNativeLibraryName("android"));
  // See declaration of android_getaddrinfofornetwork() here:
  // https://developer.android.com/ndk/reference/group/networking#android_getaddrinfofornetwork
  // Function cannot be called directly as it will cause app to fail to load on
  // pre-marshmallow devices.
  void* dl = dlopen(file.value().c_str(), RTLD_NOW);
  return reinterpret_cast<MarshmallowGetAddrInfoForNetwork>(
      dlsym(dl, "android_getaddrinfofornetwork"));
}

}  // namespace

NET_EXPORT_PRIVATE int GetAddrInfoForNetwork(handles::NetworkHandle network,
                                             const char* node,
                                             const char* service,
                                             const struct addrinfo* hints,
                                             struct addrinfo** res) {
  if (network == handles::kInvalidNetworkHandle) {
    errno = EINVAL;
    return EAI_SYSTEM;
  }
  if (base::android::BuildInfo::GetInstance()->sdk_int() <
      base::android::SDK_VERSION_MARSHMALLOW) {
    errno = ENOSYS;
    return EAI_SYSTEM;
  }

  static MarshmallowGetAddrInfoForNetwork get_addrinfo_for_network =
      GetMarshmallowGetAddrInfoForNetwork();
  if (!get_addrinfo_for_network) {
    errno = ENOSYS;
    return EAI_SYSTEM;
  }

  return get_addrinfo_for_network(network, node, service, hints, res);
}

}  // namespace net::android
```
Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for the functionality of the `storage_access_handle_test.cc` file, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, common user errors, and how a user might trigger this code.

2. **Identify the Core Subject:** The filename `storage_access_handle_test.cc` and the included header `storage_access_handle.h` strongly suggest that this file tests the `StorageAccessHandle` class.

3. **Examine the Includes:** The included headers provide crucial context:
    * `testing/gtest/include/gtest/gtest.h`: Indicates this is a unit test file using the Google Test framework.
    * `third_party/blink/...`:  Confirms this is part of the Chromium Blink rendering engine.
    * `web_heap.h`:  Deals with memory management in Blink.
    * `script_promise_tester.h`, `v8_binding_for_testing.h`, `v8_dom_exception.h`: These point to interactions with JavaScript through V8, Blink's JavaScript engine, and testing related to asynchronous operations (Promises) and DOM exceptions.
    * `v8_storage_access_types.h`, `v8_storage_estimate.h`: More evidence of JavaScript interaction, specifically with types and features related to storage access.
    * `frame_test_helpers.h`, `local_dom_window.h`, `dummy_page_holder.h`:  Tools for setting up and manipulating a testing environment that simulates a web page and its window.
    * `broadcastchannel.h`, `file_system_directory_handle.h`: These indicate specific features whose access might be governed by the `StorageAccessHandle`.
    * `scoped_mocked_url.h`, `task_environment.h`, `unit_test_helpers.h`:  Utilities for creating controlled testing scenarios.
    * `kurl.h`: Deals with URLs.

4. **Analyze the Test Structure:**
    * `StorageAccessHandleTest` class: This is the main test fixture. The `testing::TestWithParam<TestParams>` indicates parameterized testing.
    * `TestParams` tuple:  This defines the parameters for the tests, which are boolean flags for different storage access types (`all`, `cookies`, `sessionStorage`, etc.). This hints at the core functionality: controlling access to various storage mechanisms.
    * `MakeParamsWithSetBit`: A helper function to easily create test parameters where only one flag is set.
    * `LoadHandle` test: This is the main test case. It creates a `StorageAccessHandle` with different configurations and checks its behavior.
    * `StorageAccessHandleRetentionTest`: Tests the lifespan and resource management of `StorageAccessHandle`.
    * `INSTANTIATE_TEST_SUITE_P`: Sets up the parameterized tests, running `LoadHandle` with various combinations of the boolean flags.

5. **Infer the Functionality of `StorageAccessHandle`:** Based on the test setup, the `StorageAccessHandle` likely:
    * Encapsulates the permissions or capabilities granted for accessing different types of web storage (cookies, local storage, etc.).
    * Is associated with a browsing context (represented by `LocalDOMWindow`).
    * Uses `StorageAccessTypes` to define which storage mechanisms are accessible.
    * Throws security errors if access to a storage mechanism is attempted without the necessary permissions.
    * Records usage via `WebFeature` flags.

6. **Connect to Web Technologies:**
    * **JavaScript:** The test directly interacts with JavaScript concepts like Promises (`ScriptPromiseTester`), DOM exceptions (`V8DOMException`), and web APIs like `sessionStorage`, `localStorage`, `indexedDB`, `caches`, `BroadcastChannel`, `SharedWorker`, `createObjectURL`, and `revokeObjectURL`.
    * **HTML:**  While not directly manipulating HTML elements, the test sets up a basic HTML page environment using `DummyPageHolder` and `WebViewHelper`. The storage mechanisms being tested are fundamental to how web pages store data.
    * **CSS:** No direct relation to CSS in this particular test file.

7. **Logical Reasoning and Examples:** The test itself performs logical reasoning:
    * **Assumption:** If the `all` flag or a specific storage type flag (e.g., `sessionStorage`) is set to `true` when creating the `StorageAccessHandle`, then accessing that storage type through the handle should succeed (no `SecurityError`).
    * **Input (for `sessionStorage` test):**  `all() == false`, `sessionStorage() == true`.
    * **Output:** `storage_access_handle->sessionStorage(scope.GetExceptionState())` should *not* set an exception.
    * **Input (for `sessionStorage` test):** `all() == false`, `sessionStorage() == false`.
    * **Output:** `storage_access_handle->sessionStorage(scope.GetExceptionState())` should set an exception with `DOMExceptionCode::kSecurityError` and the message `StorageAccessHandle::kSessionStorageNotRequested`.

8. **Common User/Programming Errors:**
    * **Incorrectly requesting storage access:**  A website might try to access local storage without having requested it through the Storage Access API. This would lead to a `SecurityError`. The test explicitly checks for this scenario.
    * **Misunderstanding the scope of access:** A script might assume that if it has access to cookies, it automatically has access to IndexedDB, which isn't necessarily true. The `StorageAccessHandle` enforces granular permissions.

9. **User Operation and Debugging:**
    * **User interaction triggering the request:**  A user visits a website that uses the Storage Access API. The website's JavaScript code calls `document.requestStorageAccessFor()`, specifying the types of storage it needs.
    * **Browser's internal checks:** The browser (specifically the Blink rendering engine) receives this request. It checks if the necessary conditions are met (e.g., user gesture, cross-site context).
    * **`StorageAccessHandle` creation:** If the request is granted, a `StorageAccessHandle` object is created internally, reflecting the granted permissions. This is what the test simulates.
    * **Subsequent storage access attempts:** When the website's script later tries to access a specific storage mechanism (e.g., `localStorage`), the browser uses the associated `StorageAccessHandle` to determine if the access is allowed. If the test fails (e.g., a `SecurityError` is not thrown when expected), it indicates a bug in how the `StorageAccessHandle` is being created or used to enforce permissions. Developers would use debugging tools to step through the code involved in `requestStorageAccessFor()`, `StorageAccessHandle` creation, and subsequent storage access attempts to pinpoint the issue.

This detailed process of examining the code, its context, and the underlying web technologies allows for a comprehensive understanding of the test file's purpose and its implications.
这个文件 `storage_access_handle_test.cc` 是 Chromium Blink 引擎中的一个单元测试文件，专门用于测试 `StorageAccessHandle` 类的功能。 `StorageAccessHandle` 是 Blink 引擎中用来管理和控制对各种 Web 存储机制访问权限的一个类。

以下是该文件的功能分解：

**1. 测试 `StorageAccessHandle` 的创建和初始化:**

* **功能:**  测试当创建一个 `StorageAccessHandle` 对象时，它是否正确地记录了被请求的存储访问类型。
* **机制:**  通过 `StorageAccessTypes` 对象来指定需要访问的存储类型（例如：cookies, sessionStorage, localStorage, IndexedDB 等）。
* **验证:**  测试用例会检查 `StorageAccessHandle` 对象是否正确地设置了内部的标记，以及是否正确地记录了文档的 `WebFeature` 使用情况（用于统计特性使用）。
* **与 Web 技术的关系:**
    * **JavaScript:**  `StorageAccessHandle` 是通过 JavaScript 的 `document.requestStorageAccessFor()` 方法请求后创建的。测试覆盖了不同存储类型的请求场景。
    * **HTML:**  测试用例会创建一个虚拟的 `LocalDOMWindow` 和 `Document` 环境来模拟浏览器环境。存储访问的上下文是基于浏览器的文档和源。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  创建一个 `StorageAccessHandle`，并请求访问 `sessionStorage` 和 `localStorage`。
    * **预期输出:**
        * 调用 `storage_access_handle->sessionStorage()` 不会抛出异常。
        * 调用 `storage_access_handle->localStorage()` 不会抛出异常。
        * 调用 `storage_access_handle->indexedDB()` 会抛出一个 `SecurityError` 异常，因为未请求访问 IndexedDB。
        * 文档的 `WebFeature` 计数器会记录 `kStorageAccessAPI_requestStorageAccess_BeyondCookies_sessionStorage` 和 `kStorageAccessAPI_requestStorageAccess_BeyondCookies_localStorage` 的使用。

**2. 测试不同存储类型的访问权限控制:**

* **功能:**  测试 `StorageAccessHandle` 是否正确地阻止或允许访问各种 Web 存储机制，这取决于在创建时请求的类型。
* **机制:**  测试用例会尝试调用 `StorageAccessHandle` 提供的访问各种存储类型的方法（例如：`sessionStorage()`, `localStorage()`, `indexedDB()`, `caches()`, `getDirectory()`, `estimate()`, `createObjectURL()`, `revokeObjectURL()`, `BroadcastChannel()`, `SharedWorker()`）。
* **验证:**  测试用例会检查在尝试访问未被请求的存储类型时是否抛出了 `SecurityError` 异常，并且异常信息是否正确。对于允许访问的类型，则不应抛出异常。
* **与 Web 技术的关系:**
    * **JavaScript:** 这些方法对应了 JavaScript 中访问各种存储 API 的方式。例如，`sessionStorage()` 对应 `window.sessionStorage`， `localStorage()` 对应 `window.localStorage`， `indexedDB()` 对应 `window.indexedDB` 等。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 创建一个 `StorageAccessHandle`，只请求访问 `cookies`。
    * **预期输出:**
        * 调用 `storage_access_handle->sessionStorage()` 会抛出一个 `SecurityError` 异常，错误信息为 "Storage access to sessionStorage was not requested."
        * 调用 `storage_access_handle->localStorage()` 会抛出一个 `SecurityError` 异常，错误信息为 "Storage access to localStorage was not requested."
        * ... 以此类推，对于所有未请求的存储类型都会抛出 `SecurityError`。

**3. 测试 `getDirectory()` 方法的权限控制:**

* **功能:** 测试对于 Origin Private File System (OPFS) 的访问权限控制。
* **机制:**  测试用例调用 `storage_access_handle->getDirectory()` 方法，并根据是否请求了 `getDirectory` 权限来验证 Promise 的状态和抛出的异常。
* **与 Web 技术的关系:**
    * **JavaScript:** `getDirectory()` 方法对应了 JavaScript 中访问 OPFS 的 API。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 创建一个 `StorageAccessHandle`，请求访问 `getDirectory`。
    * **预期输出:** 调用 `storage_access_handle->getDirectory()` 返回的 Promise 会被 rejected，因为即使请求了权限，访问存储目录仍然可能被拒绝（错误信息为 "Storage directory access is denied."）。
    * **假设输入:** 创建一个 `StorageAccessHandle`，不请求访问 `getDirectory`。
    * **预期输出:** 调用 `storage_access_handle->getDirectory()` 返回的 Promise 会被 rejected，抛出 `SecurityError`，错误信息为 "Storage access to getDirectory was not requested."

**4. 测试 `estimate()` 方法的权限控制:**

* **功能:** 测试对于 Storage Quota API 的访问权限控制。
* **机制:** 测试用例调用 `storage_access_handle->estimate()` 方法，并根据是否请求了 `estimate` 权限来验证 Promise 的状态和抛出的异常。
* **与 Web 技术的关系:**
    * **JavaScript:** `estimate()` 方法对应了 JavaScript 中使用 Storage Quota API 获取存储空间估计值的功能。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 创建一个 `StorageAccessHandle`，请求访问 `estimate`。
    * **预期输出:** 调用 `storage_access_handle->estimate()` 返回的 Promise 不会立即 resolve 或 reject，因为实际的估计操作是异步的。
    * **假设输入:** 创建一个 `StorageAccessHandle`，不请求访问 `estimate`。
    * **预期输出:** 调用 `storage_access_handle->estimate()` 返回的 Promise 会被 rejected，抛出 `SecurityError`，错误信息为 "Storage access to estimate was not requested."

**5. 测试 `createObjectURL()` 和 `revokeObjectURL()` 方法的权限控制:**

* **功能:** 测试对于创建和撤销 Blob URL 的权限控制。
* **机制:** 测试用例调用 `storage_access_handle->createObjectURL()` 和 `storage_access_handle->revokeObjectURL()` 方法，并根据是否请求了相应的权限来验证是否抛出异常。
* **与 Web 技术的关系:**
    * **JavaScript:** 这些方法对应了 JavaScript 中 `URL.createObjectURL()` 和 `URL.revokeObjectURL()` 的功能。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 创建一个 `StorageAccessHandle`，请求访问 `createObjectURL`。
    * **预期输出:** 调用 `storage_access_handle->createObjectURL()` 不会抛出异常。
    * **假设输入:** 创建一个 `StorageAccessHandle`，不请求访问 `createObjectURL`。
    * **预期输出:** 调用 `storage_access_handle->createObjectURL()` 会抛出一个 `SecurityError` 异常，错误信息为 "Storage access to createObjectURL was not requested."
    * `revokeObjectURL()` 的测试逻辑类似。

**6. 测试 `BroadcastChannel()` 和 `SharedWorker()` 方法的权限控制:**

* **功能:** 测试对于创建 `BroadcastChannel` 和 `SharedWorker` 的权限控制。
* **机制:** 测试用例调用 `storage_access_handle->BroadcastChannel()` 和 `storage_access_handle->SharedWorker()` 方法，并根据是否请求了相应的权限来验证是否抛出异常。
* **与 Web 技术的关系:**
    * **JavaScript:** 这些方法对应了 JavaScript 中创建 `BroadcastChannel` 和 `SharedWorker` 的功能。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 创建一个 `StorageAccessHandle`，请求访问 `BroadcastChannel`。
    * **预期输出:** 调用 `storage_access_handle->BroadcastChannel()` 不会抛出异常。
    * **假设输入:** 创建一个 `StorageAccessHandle`，不请求访问 `BroadcastChannel`。
    * **预期输出:** 调用 `storage_access_handle->BroadcastChannel()` 会抛出一个 `SecurityError` 异常，错误信息为 "Storage access to BroadcastChannel was not requested."
    * 对于 `SharedWorker()`，即使请求了权限，如果当前上下文不允许创建 SharedWorker (例如，在 `null` origin 下)，仍然会抛出 `SecurityError`，错误信息会指示访问被拒绝的原因。

**7. 测试 `StorageAccessHandle` 的生命周期:**

* **功能:** 测试当 `StorageAccessHandle` 对象被垃圾回收后，相关的资源是否仍然存活。
* **机制:**  创建一个 `StorageAccessHandle` 并使用它创建一个 `BroadcastChannel`，然后释放对 `StorageAccessHandle` 的引用并进行垃圾回收。
* **验证:** 检查创建的 `BroadcastChannel` 是否仍然连接，以验证 `StorageAccessHandle` 的销毁不会意外地断开其创建的资源。
* **与 Web 技术的关系:**  涉及到 JavaScript 的垃圾回收机制和相关的 Web API 生命周期管理。

**用户或编程常见的使用错误示例:**

1. **尝试访问未请求的存储类型:**
   ```javascript
   // 在请求存储访问时，只请求了 cookies 权限
   document.requestStorageAccessFor({ topLevelOrigin: 'https://example.com', types: ['cookies'] })
     .then(handle => {
       // 错误：尝试访问 localStorage，但未在请求中包含
       handle.localStorage(); // 这会导致 SecurityError
     });
   ```
2. **误解 `getDirectory()` 的行为:** 即使请求了 `getDirectory` 权限，也并不保证一定能成功访问目录。可能会因为其他安全原因被拒绝。
3. **在错误的上下文中创建 `SharedWorker`:**  即使 `StorageAccessHandle` 允许访问 `SharedWorker`，在某些上下文中（例如 `null` origin），创建 `SharedWorker` 仍然会被阻止。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户访问一个网站:** 用户在浏览器中输入网址或点击链接访问一个网站，例如 `https://thirdparty.com`。
2. **网站尝试访问其第一方存储:**  `https://thirdparty.com` 嵌入了一个来自 `https://firstparty.com` 的 iframe。 iframe 中的 JavaScript 代码尝试访问其在 `https://firstparty.com` 域下的存储（例如 cookies, localStorage）。
3. **浏览器检测到跨站点存储访问:** 由于 `https://thirdparty.com` 和 `https://firstparty.com` 是不同的站点，浏览器会阻止直接访问。
4. **iframe 请求存储访问权限:**  iframe 中的 JavaScript 代码调用 `document.requestStorageAccessFor({ topLevelOrigin: 'https://thirdparty.com', types: ['localStorage', 'cookies'] })`。
5. **浏览器提示用户或根据配置自动处理:**  浏览器可能会弹出一个提示框询问用户是否允许 `https://thirdparty.com` 访问 `https://firstparty.com` 的存储。或者，如果浏览器有相关的自动授权配置，则会根据配置处理。
6. **权限请求被处理，`StorageAccessHandle` 被创建:** 如果权限被授予，Blink 引擎会在 iframe 的上下文中创建一个 `StorageAccessHandle` 对象，该对象允许访问请求的存储类型。
7. **iframe 使用 `StorageAccessHandle` 访问存储:** iframe 中的代码现在可以使用 `StorageAccessHandle` 对象的方法来访问其第一方存储。例如，调用 `handle.localStorage()` 或读取/设置 cookies。

**调试线索:**

* **如果在上述步骤中，存储访问失败，或者出现了意外的 `SecurityError`，开发人员可能会查看:**
    * **Network 面板:** 检查 cookie 是否被正确发送或接收。
    * **Application 面板 (Storage 部分):** 查看 localStorage, sessionStorage, IndexedDB 等存储的内容和状态。
    * **Console 面板:** 查看是否有 JavaScript 错误或异常。
    * **源代码:**  检查 `document.requestStorageAccessFor()` 的调用参数是否正确，以及后续访问存储的代码是否使用了返回的 `StorageAccessHandle`。
    * **Blink 引擎的内部日志和调试工具:** 如果是 Blink 引擎的开发者，他们可能会使用更底层的工具来跟踪 `StorageAccessHandle` 的创建和使用，查看权限检查的流程，以及 `WebFeature` 的计数情况。`storage_access_handle_test.cc` 中的测试用例就是在模拟这些内部流程，确保 `StorageAccessHandle` 的行为符合预期。

总而言之，`storage_access_handle_test.cc` 是一个非常重要的测试文件，它确保了 Blink 引擎中负责跨站点存储访问控制的核心类 `StorageAccessHandle` 的功能正确性和安全性，这对于维护 Web 平台的隐私和安全至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/storage_access/storage_access_handle_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/storage_access/storage_access_handle.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_storage_access_types.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_storage_estimate.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/modules/broadcastchannel/broadcast_channel.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_directory_handle.h"
#include "third_party/blink/renderer/platform/testing/scoped_mocked_url.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"

namespace blink {

namespace {

using TestParams = std::tuple<bool,
                              bool,
                              bool,
                              bool,
                              bool,
                              bool,
                              bool,
                              bool,
                              bool,
                              bool,
                              bool,
                              bool,
                              bool>;

template <size_t N>
TestParams MakeParamsWithSetBit() {
  TestParams params;
  std::get<N>(params) = true;
  return params;
}

}  // namespace

class StorageAccessHandleTest : public testing::TestWithParam<TestParams> {
 public:
  bool all() { return std::get<0>(GetParam()); }
  bool cookies() { return std::get<1>(GetParam()); }
  bool sessionStorage() { return std::get<2>(GetParam()); }
  bool localStorage() { return std::get<3>(GetParam()); }
  bool indexedDB() { return std::get<4>(GetParam()); }
  bool locks() { return std::get<5>(GetParam()); }
  bool caches() { return std::get<6>(GetParam()); }
  bool getDirectory() { return std::get<7>(GetParam()); }
  bool estimate() { return std::get<8>(GetParam()); }
  bool createObjectURL() { return std::get<9>(GetParam()); }
  bool revokeObjectURL() { return std::get<10>(GetParam()); }
  bool BroadcastChannel() { return std::get<11>(GetParam()); }
  bool SharedWorker() { return std::get<12>(GetParam()); }

  LocalDOMWindow* getLocalDOMWindow() {
    test::ScopedMockedURLLoad scoped_mocked_url_load_root(
        KURL(kRootString), test::CoreTestDataPath("foo.html"));
    return To<LocalDOMWindow>(web_view_helper_.InitializeAndLoad(kRootString)
                                  ->GetPage()
                                  ->MainFrame()
                                  ->DomWindow());
  }

 private:
  static constexpr char kRootString[] = "http://storage/";
  test::TaskEnvironment task_environment_;
  frame_test_helpers::WebViewHelper web_view_helper_;
};

TEST_P(StorageAccessHandleTest, LoadHandle) {
  LocalDOMWindow* window = getLocalDOMWindow();
  StorageAccessTypes* storage_access_types =
      MakeGarbageCollected<StorageAccessTypes>();
  storage_access_types->setAll(all());
  storage_access_types->setCookies(cookies());
  storage_access_types->setSessionStorage(sessionStorage());
  storage_access_types->setLocalStorage(localStorage());
  storage_access_types->setIndexedDB(indexedDB());
  storage_access_types->setLocks(locks());
  storage_access_types->setCaches(caches());
  storage_access_types->setGetDirectory(getDirectory());
  storage_access_types->setEstimate(estimate());
  storage_access_types->setCreateObjectURL(createObjectURL());
  storage_access_types->setRevokeObjectURL(revokeObjectURL());
  storage_access_types->setBroadcastChannel(BroadcastChannel());
  storage_access_types->setSharedWorker(SharedWorker());
  StorageAccessHandle* storage_access_handle =
      MakeGarbageCollected<StorageAccessHandle>(*window, storage_access_types);
  EXPECT_TRUE(window->document()->IsUseCounted(
      WebFeature::kStorageAccessAPI_requestStorageAccess_BeyondCookies));
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::kStorageAccessAPI_requestStorageAccess_BeyondCookies_all),
      all());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_cookies),
      cookies());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_sessionStorage),
      sessionStorage());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_localStorage),
      localStorage());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_indexedDB),
      indexedDB());
  EXPECT_EQ(window->document()->IsUseCounted(
                WebFeature::
                    kStorageAccessAPI_requestStorageAccess_BeyondCookies_locks),
            locks());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_caches),
      caches());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_getDirectory),
      getDirectory());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_estimate),
      estimate());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_createObjectURL),
      createObjectURL());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_revokeObjectURL),
      revokeObjectURL());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_BroadcastChannel),
      BroadcastChannel());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_SharedWorker),
      SharedWorker());
  EXPECT_FALSE(window->document()->IsUseCounted(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_sessionStorage_Use));
  EXPECT_FALSE(window->document()->IsUseCounted(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_localStorage_Use));
  EXPECT_FALSE(window->document()->IsUseCounted(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_indexedDB_Use));
  EXPECT_FALSE(window->document()->IsUseCounted(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_locks_Use));
  EXPECT_FALSE(window->document()->IsUseCounted(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_caches_Use));
  EXPECT_FALSE(window->document()->IsUseCounted(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_getDirectory_Use));
  EXPECT_FALSE(window->document()->IsUseCounted(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_estimate_Use));
  EXPECT_FALSE(window->document()->IsUseCounted(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_createObjectURL_Use));
  EXPECT_FALSE(window->document()->IsUseCounted(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_revokeObjectURL_Use));
  EXPECT_FALSE(window->document()->IsUseCounted(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_BroadcastChannel_Use));
  EXPECT_FALSE(window->document()->IsUseCounted(
      WebFeature::
          kStorageAccessAPI_requestStorageAccess_BeyondCookies_SharedWorker_Use));
  {
    V8TestingScope scope;
    storage_access_handle->sessionStorage(scope.GetExceptionState());
    EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
              (all() || sessionStorage()) ? DOMExceptionCode::kNoError
                                          : DOMExceptionCode::kSecurityError);
    EXPECT_EQ(scope.GetExceptionState().Message(),
              (all() || sessionStorage())
                  ? nullptr
                  : StorageAccessHandle::kSessionStorageNotRequested);
  }
  {
    V8TestingScope scope;
    storage_access_handle->localStorage(scope.GetExceptionState());
    EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
              (all() || localStorage()) ? DOMExceptionCode::kNoError
                                        : DOMExceptionCode::kSecurityError);
    EXPECT_EQ(scope.GetExceptionState().Message(),
              (all() || localStorage())
                  ? nullptr
                  : StorageAccessHandle::kLocalStorageNotRequested);
  }
  {
    V8TestingScope scope;
    storage_access_handle->indexedDB(scope.GetExceptionState());
    EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
              (all() || indexedDB()) ? DOMExceptionCode::kNoError
                                     : DOMExceptionCode::kSecurityError);
    EXPECT_EQ(scope.GetExceptionState().Message(),
              (all() || indexedDB())
                  ? nullptr
                  : StorageAccessHandle::kIndexedDBNotRequested);
  }
  {
    V8TestingScope scope;
    storage_access_handle->locks(scope.GetExceptionState());
    EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
              (all() || locks()) ? DOMExceptionCode::kNoError
                                 : DOMExceptionCode::kSecurityError);
    EXPECT_EQ(
        scope.GetExceptionState().Message(),
        (all() || locks()) ? nullptr : StorageAccessHandle::kLocksNotRequested);
  }
  {
    V8TestingScope scope;
    storage_access_handle->caches(scope.GetExceptionState());
    EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
              (all() || caches()) ? DOMExceptionCode::kNoError
                                  : DOMExceptionCode::kSecurityError);
    EXPECT_EQ(scope.GetExceptionState().Message(),
              (all() || caches()) ? nullptr
                                  : StorageAccessHandle::kCachesNotRequested);
  }
  {
    V8TestingScope scope;
    auto promise = storage_access_handle->getDirectory(
        scope.GetScriptState(), scope.GetExceptionState());
    ScriptPromiseTester tester(scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    EXPECT_TRUE(tester.IsRejected());
    auto* dom_exception = V8DOMException::ToWrappable(scope.GetIsolate(),
                                                      tester.Value().V8Value());
    EXPECT_EQ(dom_exception->code(),
              (uint16_t)DOMExceptionCode::kSecurityError);
    EXPECT_EQ(dom_exception->message(),
              (all() || getDirectory())
                  ? "Storage directory access is denied."
                  : StorageAccessHandle::kGetDirectoryNotRequested);
  }
  {
    V8TestingScope scope;
    auto promise = storage_access_handle->estimate(scope.GetScriptState(),
                                                   scope.GetExceptionState());
    ScriptPromiseTester tester(scope.GetScriptState(), promise);
    if (all() || estimate()) {
      EXPECT_FALSE(tester.IsFulfilled());
      EXPECT_FALSE(tester.IsRejected());
    } else {
      tester.WaitUntilSettled();
      EXPECT_TRUE(tester.IsRejected());
      auto* dom_exception = V8DOMException::ToWrappable(
          scope.GetIsolate(), tester.Value().V8Value());
      EXPECT_EQ(dom_exception->code(),
                (uint16_t)DOMExceptionCode::kSecurityError);
      EXPECT_EQ(dom_exception->message(),
                StorageAccessHandle::kEstimateNotRequested);
    }
  }
  {
    V8TestingScope scope;
    storage_access_handle->createObjectURL(
        Blob::Create(scope.GetExecutionContext()), scope.GetExceptionState());
    EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
              (all() || createObjectURL()) ? DOMExceptionCode::kNoError
                                           : DOMExceptionCode::kSecurityError);
    EXPECT_EQ(scope.GetExceptionState().Message(),
              (all() || createObjectURL())
                  ? nullptr
                  : StorageAccessHandle::kCreateObjectURLNotRequested);
  }
  {
    V8TestingScope scope;
    storage_access_handle->revokeObjectURL("", scope.GetExceptionState());
    EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
              (all() || revokeObjectURL()) ? DOMExceptionCode::kNoError
                                           : DOMExceptionCode::kSecurityError);
    EXPECT_EQ(scope.GetExceptionState().Message(),
              (all() || revokeObjectURL())
                  ? nullptr
                  : StorageAccessHandle::kRevokeObjectURLNotRequested);
  }
  {
    V8TestingScope scope;
    storage_access_handle->BroadcastChannel(scope.GetExecutionContext(), "",
                                            scope.GetExceptionState());
    EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
              (all() || BroadcastChannel()) ? DOMExceptionCode::kNoError
                                            : DOMExceptionCode::kSecurityError);
    EXPECT_EQ(scope.GetExceptionState().Message(),
              (all() || BroadcastChannel())
                  ? nullptr
                  : StorageAccessHandle::kBroadcastChannelNotRequested);
  }
  {
    V8TestingScope scope;
    storage_access_handle->SharedWorker(scope.GetExecutionContext(), "",
                                        nullptr, scope.GetExceptionState());
    EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
              DOMExceptionCode::kSecurityError);
    EXPECT_EQ(scope.GetExceptionState().Message(),
              (all() || SharedWorker())
                  ? "Access to shared workers is denied to origin 'null'."
                  : StorageAccessHandle::kSharedWorkerNotRequested);
  }
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_sessionStorage_Use),
      all() || sessionStorage());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_localStorage_Use),
      all() || localStorage());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_indexedDB_Use),
      all() || indexedDB());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_locks_Use),
      all() || locks());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_caches_Use),
      all() || caches());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_getDirectory_Use),
      all() || getDirectory());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_estimate_Use),
      all() || estimate());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_createObjectURL_Use),
      all() || createObjectURL());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_revokeObjectURL_Use),
      all() || revokeObjectURL());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_BroadcastChannel_Use),
      all() || BroadcastChannel());
  EXPECT_EQ(
      window->document()->IsUseCounted(
          WebFeature::
              kStorageAccessAPI_requestStorageAccess_BeyondCookies_SharedWorker_Use),
      all() || SharedWorker());
}

// Test all handles.
INSTANTIATE_TEST_SUITE_P(
    /*no prefix*/,
    StorageAccessHandleTest,
    testing::ValuesIn(std::vector<TestParams>{
        // Nothing:
        TestParams(),
        // All:
        MakeParamsWithSetBit<0>(),
        // Cookies:
        MakeParamsWithSetBit<1>(),
        // Session Storage:
        MakeParamsWithSetBit<2>(),
        // Local Storage:
        MakeParamsWithSetBit<3>(),
        // IndexedDB:
        MakeParamsWithSetBit<4>(),
        // Web Locks:
        MakeParamsWithSetBit<5>(),
        // Cache Storage:
        MakeParamsWithSetBit<6>(),
        // Origin Private File System:
        MakeParamsWithSetBit<7>(),
        // Quota:
        MakeParamsWithSetBit<8>(),
        // createObjectURL:
        MakeParamsWithSetBit<9>(),
        // revokeObjectURL:
        MakeParamsWithSetBit<10>(),
        // BroadcastChannel:
        MakeParamsWithSetBit<11>(),
        // SharedWorker:
        MakeParamsWithSetBit<12>(),
    }));

TEST(StorageAccessHandleRetentionTest, Lifespan) {
  test::TaskEnvironment task_environment;
  std::unique_ptr<DummyPageHolder> holder =
      DummyPageHolder::CreateAndCommitNavigation(
          KURL("https://www.example.com"));
  LocalDOMWindow* window = holder->GetFrame().DomWindow();
  StorageAccessTypes* storage_access_types =
      MakeGarbageCollected<StorageAccessTypes>();
  storage_access_types->setBroadcastChannel(true);
  StorageAccessHandle* storage_access_handle =
      MakeGarbageCollected<StorageAccessHandle>(*window, storage_access_types);
  V8TestingScope scope;
  class BroadcastChannel* channel = storage_access_handle->BroadcastChannel(
      scope.GetExecutionContext(), "foo", scope.GetExceptionState());
  EXPECT_TRUE(channel->IsRemoteClientConnectedForTesting());
  storage_access_handle = nullptr;
  WebHeap::CollectGarbageForTesting();
  EXPECT_TRUE(channel->IsRemoteClientConnectedForTesting());
}

}  // namespace blink

"""

```
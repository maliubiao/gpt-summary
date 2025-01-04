Response:
The user wants me to summarize the functionality of the provided C++ code snippet. This is part 2 of a 5-part series, implying there's a broader context.

The code defines a series of C++ unit tests for the `SharedStorageWorklet` functionality in Chromium's Blink rendering engine. Each `TEST_F` function tests a specific scenario related to how JavaScript code running within a Shared Storage worklet interacts with the underlying system.

I need to:
1. **Identify the core functionalities being tested:**  These seem to revolve around:
    - Adding modules (JavaScript code) to the worklet.
    - Registering operations within the worklet.
    - Selecting URLs using registered operations.
    - Running registered operations.
    - Accessing global scope objects and functions within the worklet.
    - Using the `sharedStorage` API (e.g., `set`).
    - Using the `interestGroups()` API.
2. **Summarize the tests in this specific part:** Focus on the tests included in this snippet.
3. **Relate to JavaScript, HTML, CSS (if applicable):**  Explain how these tests relate to web development concepts.
4. **Infer logical reasoning with input/output:**  Describe the expected behavior based on the test setup and assertions.
5. **Identify common user errors:**  Point out mistakes developers might make when using the Shared Storage API.
6. **Describe user actions leading to these tests:**  Explain the user interactions that would trigger the tested code paths.
```
**代码功能归纳（第2部分）:**

这部分代码主要集中在测试 `SharedStorageWorklet` 中 **register()** 函数的各种使用场景，以及 **selectURL()** 和 **run()** 函数在不同情况下的行为。同时也测试了在 worklet 中对全局对象和函数的访问权限。

具体来说，测试涵盖了以下功能点：

1. **register() 函数的测试:**
    *   测试 `register()` 函数缺少参数时的错误处理（缺少 operation name 或 class）。
    *   测试 `register()` 函数使用空 operation name 时的错误处理。
    *   测试 `register()` 函数的 class 参数不是函数时的错误处理。
    *   测试 `register()` 函数注册的 class 缺少 `run` 方法时的错误处理。
    *   测试 `register()` 函数注册的 class 的 prototype 不是对象时的错误处理。
    *   测试 `register()` 函数成功注册操作的情况。
    *   测试重复注册相同 operation name 时的错误处理。

2. **selectURL() 函数的测试:**
    *   测试在 `addModule()` 完成之前调用 `selectURL()` 的错误处理。
    *   测试调用未注册的 operation name 的 `selectURL()` 的错误处理。
    *   测试 `selectURL()` 调用的 JavaScript 函数内部发生错误时的处理。
    *   测试 `selectURL()` 调用的 JavaScript 函数同步返回结果的情况。
    *   测试 `selectURL()` 调用的 JavaScript 函数异步拒绝 Promise 的情况。
    *   测试 `selectURL()` 调用的 JavaScript 函数异步返回 Promise 并成功 resolve 的情况。
    *   测试 `selectURL()` 调用的 JavaScript 函数返回不同类型值（字符串、数字等）并被转换为 uint32 的情况。
    *   测试 `selectURL()` 调用的 JavaScript 函数返回超出 URL 数组索引范围的值时的错误处理。
    *   测试 `selectURL()` 调用的 JavaScript 函数返回无法转换为 uint32 的值时的错误处理。
    *   测试 `selectURL()` 函数传递的 `urls` 和 `data` 参数是否正确传递到 worklet 中的 JavaScript 代码。

3. **run() 函数的测试:**
    *   测试在 `addModule()` 完成之前调用 `run()` 的错误处理。
    *   测试调用未注册的 operation name 的 `run()` 的错误处理。
    *   测试 `run()` 调用的 JavaScript 函数内部发生错误时的处理。
    *   测试 `run()` 调用的 JavaScript 函数同步完成的情况。
    *   测试 `run()` 调用的 JavaScript 函数异步拒绝 Promise 的情况。
    *   测试 `run()` 调用的 JavaScript 函数异步完成 Promise 的情况。
    *   测试 `run()` 调用的 JavaScript 函数包含微任务的情况。
    *   测试 `run()` 函数传递的 `data` 参数是否正确传递到 worklet 中的 JavaScript 代码。

4. **全局作用域对象和函数的测试:**
    *   测试在 `addModule()` 成功后，worklet 中可以访问的全局对象和函数，例如 `console`, `sharedStorage`, `crypto`, `navigator` 及其子对象和函数。
    *   测试在 `addModule()` 失败后，worklet 中可以访问的全局对象和函数。

5. **sharedStorage API 的测试 (set 方法):**
    *   测试 `sharedStorage.set()` 缺少 key 或 value 参数时的错误处理。
    *   测试 `sharedStorage.set()` 使用无效 key（空字符串或过长字符串）时的错误处理。
    *   测试 `sharedStorage.set()` 使用无效 value（过长字符串）时的错误处理。
    *   测试 `sharedStorage.set()` 使用无效 options 参数时的错误处理。
    *   测试 `sharedStorage.set()` 调用导致客户端错误时的处理。

6. **interestGroups() API 的测试:**
    *   测试 `interestGroups()` 调用导致客户端错误时的处理。
    *   测试 `interestGroups()` 返回成功数据的情况。

**与 JavaScript, HTML, CSS 的关系：**

*   **JavaScript:**  此代码主要测试的是在 JavaScript Worklet 环境中运行的代码的行为。`register()`, `selectURL()`, 和 `run()` 都与在 JavaScript 中定义和调用函数相关。测试用例中的脚本内容就是 JavaScript 代码片段。`sharedStorage` 和 `interestGroups()` 都是在 JavaScript 中可调用的 Web API。
*   **HTML:** 虽然没有直接涉及到 HTML 元素，但 Shared Storage 的使用场景通常与用户在网页上的交互相关。例如，用户浏览某个包含广告的网页，该网页可能会使用 Shared Storage 来存储与用户兴趣相关的数据。
*   **CSS:**  CSS 与此测试的关联性较低。Shared Storage 主要用于存储数据和执行逻辑，不直接影响页面的样式。

**逻辑推理（假设输入与输出）：**

*   **假设输入 (RegisterOperation_MissingOperationNameArgument):**  JavaScript 代码 `register();` 被 `addModule()` 加载。
    *   **输出:** `addModule()` 操作失败，错误信息包含 "2 arguments required, but only 0 present"。

*   **假设输入 (SelectURL_FulfilledSynchronously):**  JavaScript 代码包含注册了名为 "test-operation" 的操作，其 `run` 函数同步返回数字 1。`selectURL("test-operation", {GURL("https://foo0.com"), GURL("https://foo1.com")}, ...)` 被调用。
    *   **输出:** `selectURL()` 操作成功，返回的 index 为 1。

*   **假设输入 (Run_RejectedAsynchronously):** JavaScript 代码包含注册了名为 "test-operation" 的操作，其 `run` 函数调用了 `sharedStorage.clear()`，且模拟的客户端操作返回错误 "error 123"。 `run("test-operation", ...)` 被调用。
    *   **输出:** `run()` 操作失败，错误信息包含 "error 123"。

**用户或编程常见的使用错误举例：**

*   **忘记注册操作:**  开发者可能尝试使用 `selectURL()` 或 `run()` 调用一个尚未通过 `register()` 注册的操作名称。例如，在 JavaScript 代码中定义了 `class MyOperation { async run() {} }` 但忘记调用 `register("my-operation", MyOperation);`。
*   **`register()` 函数参数错误:**  开发者可能在调用 `register()` 时提供错误的参数，例如，operation name 为空字符串，或者提供的 class 不是一个函数。
*   **在 `addModule()` 完成前调用操作:** 开发者可能在 Worklet 模块加载完成之前就尝试调用 `selectURL()` 或 `run()`。
*   **`selectURL()` 返回值超出范围:**  开发者可能在 `selectURL()` 的 `run` 函数中返回一个大于或等于 URL 数组长度的数字，导致索引越界。
*   **`sharedStorage.set()` 参数错误:**  开发者可能忘记提供 key 或 value 参数，或者提供的 key 或 value 长度过长。

**用户操作到达此处的调试线索：**

1. **用户操作触发了 Shared Storage 的相关功能:**  例如，用户访问了一个使用了 Shared Storage API 的网页。
2. **网站的 JavaScript 代码尝试注册一个 Worklet 模块:**  JavaScript 代码调用了类似 `navigator.sharedStorage.worklet.addModule(...)` 的方法。
3. **网站的 JavaScript 代码尝试使用注册的操作:**  JavaScript 代码调用了类似 `navigator.sharedStorage.selectURL(...)` 或 `navigator.sharedStorage.run(...)` 的方法。
4. **如果出现错误，开发者可能会查看浏览器控制台的错误信息:** 这些错误信息可能与这些单元测试中模拟的错误情况相符，例如 "Cannot find operation name" 或关于参数数量不正确的错误。
5. **开发者可能需要调试 Worklet 中的 JavaScript 代码:**  Chromium 提供了开发者工具来检查 Worklet 的执行情况，帮助定位问题。
6. **如果问题涉及到 `sharedStorage` 的读写，开发者可能会检查应用程序的存储:**  浏览器开发者工具允许查看 Shared Storage 的内容，以验证数据是否正确存储和检索。
7. **对于 `interestGroups()`，开发者可能需要检查 FLEDGE (Federated Learning of Cohorts API) 的相关设置和状态:** 因为 `interestGroups()` 返回的是与 FLEDGE 兴趣组相关的信息。

总而言之，这部分测试着重于验证 `SharedStorageWorklet` 中操作注册、执行以及全局作用域访问的正确性和健壮性，涵盖了各种正常和异常情况，为开发者在使用 Shared Storage Worklet API 时提供了保障。
```
Prompt: 
```
这是目录为blink/renderer/modules/shared_storage/shared_storage_worklet_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能

"""
ule().");
  EXPECT_EQ(test_client_->observed_console_log_messages_[2],
            "Expected async error: Failed to execute 'interestGroups' on "
            "'SharedStorageWorkletGlobalScope': interestGroups() cannot be "
            "called during addModule().");

  EXPECT_EQ(test_client_->observed_get_interest_groups_count_, 0u);
}

TEST_F(SharedStorageWorkletTest,
       RegisterOperation_MissingOperationNameArgument) {
  AddModuleResult result = AddModule(/*script_content=*/R"(
      register();
  )");

  EXPECT_FALSE(result.success);
  EXPECT_THAT(result.error_message,
              testing::HasSubstr("2 arguments required, but only 0 present"));
}

TEST_F(SharedStorageWorkletTest, RegisterOperation_MissingClassArgument) {
  AddModuleResult result = AddModule(/*script_content=*/R"(
      register("test-operation");
  )");

  EXPECT_FALSE(result.success);
  EXPECT_THAT(result.error_message,
              testing::HasSubstr("2 arguments required, but only 1 present"));
}

TEST_F(SharedStorageWorkletTest, RegisterOperation_EmptyOperationName) {
  AddModuleResult result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {}
      }

      register("", TestClass);
  )");

  EXPECT_FALSE(result.success);
  EXPECT_THAT(result.error_message,
              testing::HasSubstr("Operation name cannot be empty"));
}

TEST_F(SharedStorageWorkletTest, RegisterOperation_ClassArgumentNotAFunction) {
  AddModuleResult result = AddModule(/*script_content=*/R"(
      register("test-operation", {});
  )");

  EXPECT_FALSE(result.success);
  EXPECT_THAT(result.error_message,
              testing::HasSubstr("parameter 2 is not of type 'Function'"));
}

TEST_F(SharedStorageWorkletTest, RegisterOperation_MissingRunFunction) {
  AddModuleResult result = AddModule(/*script_content=*/R"(
      class TestClass {
        constructor() {
          this.run = 1;
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_FALSE(result.success);
  EXPECT_THAT(result.error_message,
              testing::HasSubstr("Property \"run\" doesn't exist"));
}

TEST_F(SharedStorageWorkletTest,
       RegisterOperation_ClassArgumentPrototypeNotAnObject) {
  AddModuleResult result = AddModule(/*script_content=*/R"(
      function test() {};
      test.prototype = 123;

      register("test-operation", test);
  )");

  EXPECT_FALSE(result.success);
  EXPECT_THAT(result.error_message,
              testing::HasSubstr("constructor prototype is not an object"));
}

TEST_F(SharedStorageWorkletTest, RegisterOperation_Success) {
  AddModuleResult result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {}
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(result.success);
  EXPECT_TRUE(result.error_message.empty());
}

TEST_F(SharedStorageWorkletTest, RegisterOperation_AlreadyRegistered) {
  AddModuleResult result = AddModule(/*script_content=*/R"(
    class TestClass1 {
      async run() {}
    }

    class TestClass2 {
      async run() {}
    }

    register("test-operation", TestClass1);
    register("test-operation", TestClass2);
  )");

  EXPECT_FALSE(result.success);
  EXPECT_THAT(result.error_message,
              testing::HasSubstr("Operation name already registered"));
}

TEST_F(SharedStorageWorkletTest, SelectURL_BeforeAddModuleFinish) {
  SelectURLResult select_url_result =
      SelectURL("test-operation", /*urls=*/{}, CreateSerializedUndefined());

  EXPECT_FALSE(select_url_result.success);
  EXPECT_THAT(select_url_result.error_message,
              testing::HasSubstr("The module script hasn't been loaded"));
  EXPECT_EQ(select_url_result.index, 0u);
}

TEST_F(SharedStorageWorkletTest, SelectURL_OperationNameNotRegistered) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run(urls) {}
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  SelectURLResult select_url_result = SelectURL(
      "unregistered-operation", /*urls=*/{}, CreateSerializedUndefined());

  EXPECT_FALSE(select_url_result.success);
  EXPECT_THAT(select_url_result.error_message,
              testing::HasSubstr("Cannot find operation name"));
  EXPECT_EQ(select_url_result.index, 0u);
}

TEST_F(SharedStorageWorkletTest, SelectURL_FunctionError) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run(urls) {
          a;
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  SelectURLResult select_url_result =
      SelectURL("test-operation", /*urls=*/{}, CreateSerializedUndefined());

  EXPECT_FALSE(select_url_result.success);
  EXPECT_THAT(select_url_result.error_message,
              testing::HasSubstr("ReferenceError: a is not defined"));
  EXPECT_EQ(select_url_result.index, 0u);
}

TEST_F(SharedStorageWorkletTest, SelectURL_FulfilledSynchronously) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run(urls) {
          return 1;
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  SelectURLResult select_url_result =
      SelectURL("test-operation",
                /*urls=*/{GURL("https://foo0.com"), GURL("https://foo1.com")},
                CreateSerializedUndefined());

  EXPECT_TRUE(select_url_result.success);
  EXPECT_TRUE(select_url_result.error_message.empty());
  EXPECT_EQ(select_url_result.index, 1u);
}

TEST_F(SharedStorageWorkletTest, SelectURL_RejectedAsynchronously) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run(urls) {
          return sharedStorage.length();
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  test_client_->length_result_ =
      LengthResult{.success = false, .error_message = "error 123", .length = 0};

  SelectURLResult select_url_result =
      SelectURL("test-operation",
                /*urls=*/{GURL("https://foo0.com"), GURL("https://foo1.com")},
                CreateSerializedUndefined());

  EXPECT_FALSE(select_url_result.success);
  EXPECT_THAT(select_url_result.error_message, testing::HasSubstr("error 123"));
  EXPECT_EQ(select_url_result.index, 0u);
}

TEST_F(SharedStorageWorkletTest, SelectURL_FulfilledAsynchronously) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run(urls) {
          return sharedStorage.length();
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  test_client_->length_result_ = LengthResult{
      .success = true, .error_message = std::string(), .length = 1};

  SelectURLResult select_url_result =
      SelectURL("test-operation",
                /*urls=*/{GURL("https://foo0.com"), GURL("https://foo1.com")},
                CreateSerializedUndefined());

  EXPECT_TRUE(select_url_result.success);
  EXPECT_TRUE(select_url_result.error_message.empty());
  EXPECT_EQ(select_url_result.index, 1u);
}

TEST_F(SharedStorageWorkletTest, SelectURL_StringConvertedToUint32) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run(urls) {
          return "1";
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  SelectURLResult select_url_result =
      SelectURL("test-operation",
                /*urls=*/{GURL("https://foo0.com"), GURL("https://foo1.com")},
                CreateSerializedUndefined());

  EXPECT_TRUE(select_url_result.success);
  EXPECT_TRUE(select_url_result.error_message.empty());
  EXPECT_EQ(select_url_result.index, 1u);
}

TEST_F(SharedStorageWorkletTest, SelectURL_NumberOverflow) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run(urls) {
          return -4294967295;
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  SelectURLResult select_url_result =
      SelectURL("test-operation",
                /*urls=*/{GURL("https://foo0.com"), GURL("https://foo1.com")},
                CreateSerializedUndefined());

  EXPECT_TRUE(select_url_result.success);
  EXPECT_TRUE(select_url_result.error_message.empty());
  EXPECT_EQ(select_url_result.index, 1u);
}

TEST_F(SharedStorageWorkletTest, SelectURL_NonNumericStringConvertedTo0) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run(urls) {
          return "abc";
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  SelectURLResult select_url_result =
      SelectURL("test-operation",
                /*urls=*/{GURL("https://foo0.com"), GURL("https://foo1.com")},
                CreateSerializedUndefined());

  EXPECT_TRUE(select_url_result.success);
  EXPECT_TRUE(select_url_result.error_message.empty());
  EXPECT_EQ(select_url_result.index, 0u);
}

TEST_F(SharedStorageWorkletTest, SelectURL_DefaultUndefinedResultConvertedTo0) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run(urls) {}
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  SelectURLResult select_url_result =
      SelectURL("test-operation",
                /*urls=*/{GURL("https://foo0.com"), GURL("https://foo1.com")},
                CreateSerializedUndefined());

  EXPECT_TRUE(select_url_result.success);
  EXPECT_TRUE(select_url_result.error_message.empty());
  EXPECT_EQ(select_url_result.index, 0u);
}

// For a run() member function that is not marked "async", it will still be
// treated as async.
TEST_F(SharedStorageWorkletTest, SelectURL_NoExplicitAsync) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        run(urls) {
          return 1;
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  SelectURLResult select_url_result =
      SelectURL("test-operation",
                /*urls=*/{GURL("https://foo0.com"), GURL("https://foo1.com")},
                CreateSerializedUndefined());

  EXPECT_TRUE(select_url_result.success);
  EXPECT_TRUE(select_url_result.error_message.empty());
  EXPECT_EQ(select_url_result.index, 1u);
}

TEST_F(SharedStorageWorkletTest, SelectURL_ReturnValueOutOfRange) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run(urls) {
          return 2;
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  SelectURLResult select_url_result =
      SelectURL("test-operation",
                /*urls=*/{GURL("https://foo0.com"), GURL("https://foo1.com")},
                CreateSerializedUndefined());

  EXPECT_FALSE(select_url_result.success);
  EXPECT_THAT(
      select_url_result.error_message,
      testing::HasSubstr(
          "Promise resolved to a number outside the length of the input urls"));
  EXPECT_EQ(select_url_result.index, 0u);
}

TEST_F(SharedStorageWorkletTest, SelectURL_ReturnValueToUint32Error) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run(urls) {
          class CustomClass {
            toString() { throw Error('error 123'); }
          }

          return new CustomClass();
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  SelectURLResult select_url_result =
      SelectURL("test-operation",
                /*urls=*/{GURL("https://foo0.com"), GURL("https://foo1.com")},
                CreateSerializedUndefined());

  EXPECT_FALSE(select_url_result.success);
  EXPECT_THAT(
      select_url_result.error_message,
      testing::HasSubstr("Promise did not resolve to an uint32 number"));
  EXPECT_EQ(select_url_result.index, 0u);
}

TEST_F(SharedStorageWorkletTest,
       SelectURL_ValidateUrlsAndDataParamViaConsoleLog) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run(urls, data) {
          console.log(JSON.stringify(urls, Object.keys(urls).sort()));
          console.log(JSON.stringify(data, Object.keys(data).sort()));

          return 1;
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  SelectURLResult select_url_result =
      SelectURL("test-operation",
                /*urls=*/{GURL("https://foo0.com"), GURL("https://foo1.com")},
                CreateSerializedDict({{"customField", "customValue"}}));

  EXPECT_TRUE(select_url_result.success);
  EXPECT_TRUE(select_url_result.error_message.empty());
  EXPECT_EQ(select_url_result.index, 1u);

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 2u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0],
            "[\"https://foo0.com/\",\"https://foo1.com/\"]");
  EXPECT_EQ(test_client_->observed_console_log_messages_[1],
            "{\"customField\":\"customValue\"}");
}

TEST_F(SharedStorageWorkletTest, Run_BeforeAddModuleFinish) {
  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message,
              testing::HasSubstr("The module script hasn't been loaded"));
}

TEST_F(SharedStorageWorkletTest, Run_OperationNameNotRegistered) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {}
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result =
      Run("unregistered-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message,
              testing::HasSubstr("Cannot find operation name"));
}

TEST_F(SharedStorageWorkletTest, Run_FunctionError) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          a;
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message,
              testing::HasSubstr("ReferenceError: a is not defined"));
}

TEST_F(SharedStorageWorkletTest, Run_FulfilledSynchronously) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {}
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());
}

TEST_F(SharedStorageWorkletTest, Run_RejectedAsynchronously) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          return sharedStorage.clear();
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  test_client_->update_result_error_message_ = "error 123";

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message, testing::HasSubstr("error 123"));
}

TEST_F(SharedStorageWorkletTest, Run_FulfilledAsynchronously) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          return sharedStorage.clear();
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());
}

TEST_F(SharedStorageWorkletTest, Run_Microtask) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await Promise.resolve(0);
          return 0;
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());
}

TEST_F(SharedStorageWorkletTest, Run_ValidateDataParamViaConsoleLog) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run(data) {
          console.log(JSON.stringify(data, Object.keys(data).sort()));

          return 1;
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run(
      "test-operation", CreateSerializedDict({{"customField", "customValue"}}));

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 1u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0],
            "{\"customField\":\"customValue\"}");
}

TEST_F(SharedStorageWorkletTest, SelectURLAndRunOnSameRegisteredOperation) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          return 1;
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  SelectURLResult select_url_result =
      SelectURL("test-operation",
                /*urls=*/{GURL("https://foo0.com"), GURL("https://foo1.com")},
                CreateSerializedUndefined());

  EXPECT_TRUE(select_url_result.success);
  EXPECT_TRUE(select_url_result.error_message.empty());
  EXPECT_EQ(select_url_result.index, 1u);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());
}

TEST_F(SharedStorageWorkletTest,
       GlobalScopeObjectsAndFunctions_AfterAddModuleSuccess) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          var expectedObjects = [
            "console",
            "sharedStorage",
            "crypto",
            "navigator",
            "navigator.locks"
          ];

          var expectedFunctions = [
            "SharedStorageWorkletNavigator",
            "LockManager",
            "Lock",
            "SharedStorage",
            "Crypto",
            "CryptoKey",
            "SubtleCrypto",
            "TextEncoder",
            "TextDecoder",
            "register",
            "sharedStorage.set",
            "sharedStorage.append",
            "sharedStorage.delete",
            "sharedStorage.clear",
            "sharedStorage.get",
            "sharedStorage.length",
            "sharedStorage.keys",
            "sharedStorage.entries",
            "sharedStorage.remainingBudget",
            "interestGroups",
            "navigator.locks.request"
          ];

          // Those are either not implemented yet, or should stay undefined.
          var expectedUndefinedVariables = [
            "sharedStorage.createWorklet",
            "sharedStorage.selectURL",
            "sharedStorage.run",
            "sharedStorage.worklet",
            "sharedStorage.context",
          ];

          for (let expectedObject of expectedObjects) {
            if (eval("typeof " + expectedObject) !== "object") {
              throw Error(expectedObject + " is not object type.")
            }
          }

          for (let expectedFunction of expectedFunctions) {
            if (eval("typeof " + expectedFunction) !== "function") {
              throw Error(expectedFunction + " is not function type.")
            }
          }

          for (let expectedUndefined of expectedUndefinedVariables) {
            if (eval("typeof " + expectedUndefined) !== "undefined") {
              throw Error(expectedUndefined + " is not undefined.")
            }
          }
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_EQ(run_result.error_message, "");
}

TEST_F(SharedStorageWorkletTest,
       GlobalScopeObjectsAndFunctions_AfterAddModuleFailure) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          var expectedObjects = [
            "console",
            "sharedStorage",
            "crypto",
            "navigator",
            "navigator.locks"
          ];

          var expectedFunctions = [
            "SharedStorageWorkletNavigator",
            "LockManager",
            "Lock",
            "SharedStorage",
            "Crypto",
            "CryptoKey",
            "SubtleCrypto",
            "TextEncoder",
            "TextDecoder",
            "register",
            "sharedStorage.set",
            "sharedStorage.append",
            "sharedStorage.delete",
            "sharedStorage.clear",
            "sharedStorage.get",
            "sharedStorage.length",
            "sharedStorage.keys",
            "sharedStorage.entries",
            "sharedStorage.remainingBudget",
            "interestGroups",
            "navigator.locks.request"
          ];

          // Those are either not implemented yet, or should stay undefined.
          var expectedUndefinedVariables = [
            "sharedStorage.createWorklet",
            "sharedStorage.selectURL",
            "sharedStorage.run",
            "sharedStorage.worklet",
            "sharedStorage.context",
          ];

          for (let expectedObject of expectedObjects) {
            if (eval("typeof " + expectedObject) !== "object") {
              throw Error(expectedObject + " is not object type.")
            }
          }

          for (let expectedFunction of expectedFunctions) {
            if (eval("typeof " + expectedFunction) !== "function") {
              throw Error(expectedFunction + " is not function type.")
            }
          }

          for (let expectedUndefined of expectedUndefinedVariables) {
            if (eval("typeof " + expectedUndefined) !== "undefined") {
              throw Error(expectedUndefined + " is not undefined.")
            }
          }
        }
      }

      register("test-operation", TestClass);

      // This should fail the addModule()
      a;
  )");

  EXPECT_FALSE(add_module_result.success);
  EXPECT_THAT(add_module_result.error_message,
              testing::HasSubstr("ReferenceError: a is not defined"));

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_EQ(run_result.error_message, "");
}

TEST_F(SharedStorageWorkletTest, Set_MissingKey) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.set();
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message,
              testing::HasSubstr("2 arguments required, but only 0 present"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Set_InvalidKey_Empty) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.set("", "value");
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(
      run_result.error_message,
      testing::HasSubstr("Length of the \"key\" parameter is not valid"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Set_InvalidKey_TooLong) {
  AddModuleResult add_module_result = AddModule(
      /*script_content=*/base::ReplaceStringPlaceholders(
          R"(
      class TestClass {
        async run() {
          await sharedStorage.set("a".repeat($1), "value");
        }
      }

      register("test-operation", TestClass);
  )",
          {kMaxChar16StringLengthPlusOneLiteral},
          /*offsets=*/nullptr));

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(
      run_result.error_message,
      testing::HasSubstr("Length of the \"key\" parameter is not valid"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Set_MissingValue) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.set("key");
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message,
              testing::HasSubstr("2 arguments required, but only 1 present"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Set_InvalidValue_TooLong) {
  AddModuleResult add_module_result = AddModule(
      /*script_content=*/base::ReplaceStringPlaceholders(
          R"(
      class TestClass {
        async run() {
          await sharedStorage.set("key", "a".repeat($1));
        }
      }

      register("test-operation", TestClass);
  )",
          {kMaxChar16StringLengthPlusOneLiteral},
          /*offsets=*/nullptr));

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(
      run_result.error_message,
      testing::HasSubstr("Length of the \"value\" parameter is not valid"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Set_InvalidOptions) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.set("key", "value", true);
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(
      run_result.error_message,
      testing::HasSubstr(
          "The provided value is not of type 'SharedStorageSetMethodOptions'"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Set_ClientError) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.set("key0", "value0");
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  test_client_->update_result_error_message_ = "error 123";

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message, testing::HasSubstr("error 123"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 1u);
  network::mojom::SharedStorageSetMethodPtr& observed_params =
      test_client_->observed_update_params_[0]->get_set_method();
  EXPECT_EQ(observed_params->key, u"key0");
  EXPECT_EQ(observed_params->value, u"value0");
}

TEST_F(SharedStorageWorkletTest, InterestGroups_ClientError) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          const groups = await interestGroups();
        }
      };

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  test_client_->interest_groups_result_ =
      blink::mojom::GetInterestGroupsResult::NewErrorMessage("error 123");

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_EQ(run_result.error_message, "OperationError: error 123");

  EXPECT_EQ(test_client_->observed_get_interest_groups_count_, 1u);
}

TEST_F(SharedStorageWorkletTest, InterestGroups) {
  base::Time now = base::Time::Now();

  blink::mojom::PreviousWinPtr previous_win = blink::mojom::PreviousWin::New(
      /*time=*/now - base::Seconds(500),
      /*ad_json=*/
      "{\"renderURL\":\"https://render-url.com\",\"adRenderId\":\"render-id\","
      "\"metadata\":\"{\\\"abc\\\":1,\\\"def\\\":2}\"}");

  std::vector<blink::mojom::PreviousWinPtr> prev_wins;
  prev_wins.push_back(std::move(previous_win));

  blink::mojom::BiddingBrowserSignalsPtr bidding_browser_signals =
      blink::mojom::BiddingBrowserSignals::New(
          /*join_count=*/1,
          /*bid_count=*/2, std::move(prev_wins),
          /*for_debugging_only_in_cooldown_or_lockout=*/false);

  blink::InterestGroup ig;
  ig.expiry = now + base::Seconds(3000);
  ig.owner = url::Origin::Create(GURL("https://example.org"));
  ig.name = "ig_one";
  ig.priority = 5.5;
  ig.enable_bidding_signals_prioritization = true;
  ig.priority_vector = {{"i", 1}, {"j", 2}, {"k", 4}};
  ig.priority_signals_overrides = {{"a", 0.5}, {"b", 2}};
  ig.all_sellers_capabilities = {
      blink::SellerCapabilities::kInterestGroupCounts,
      blink::SellerCapabilities::kLatencyStats};
  ig.seller_capabilities = {
      {url::Origin::Create(GURL("https://example.org")),
       {blink::SellerCapabilities::kInterestGroupCounts}}};
  ig.execution_mode = InterestGroup::ExecutionMode::kGroupedByOriginMode;
  ig.bidding_url = GURL("https://example.org/bid.js");
  ig.bidding_wasm_helper_url = GURL("https://example.org/bid.wasm");
  ig.update_url = GURL("https://example.org/ig_update.json");
  ig.trusted_bidding_signals_url = GURL("https://example.org/trust.json");
  ig.trusted_bidding_signals_keys = {"l", "m"};
  ig.trusted_bidding_signals_slot_size_mode =
      InterestGroup::TrustedBiddingSignalsSlotSizeMode::kAllSlotsRequestedSizes;
  ig.max_trusted_bidding_signals_url_length = 100;
  ig.trusted_bidding_signals_coordinator =
      url::Origin::Create(GURL("https://example.test"));
  ig.user_bidding_signals = "\"hello\"";
  ig.ads = {
      {blink::InterestGroup::Ad(
           GURL("https://example.com/train"), "\"metadata\"", "sizegroup",
           "bid", "bsid",
           std::vector<std::string>{"selectable_id1", "selectable_id2"},
           "ad_render_id",
           {{url::Origin::Create(GURL("https://reporting.example.org"))}}),
       blink::InterestGroup::Ad(GURL("https://example.com/plane"),
                                "\"meta2\"")}};
  ig.ad_components = {{
      {GURL("https://example.com/locomotive"), "\"meta3\""},
      {GURL("https://example.com/turbojet"), "\"meta4\""},
  }};
  ig.ad_sizes = {{"small", AdSize(100, AdSize::LengthUnit::kPixels, 5,
                                  AdSize::LengthUnit::kScreenHeight)}};
  ig.size_groups = {{"g1", {"small", "medium"}}, {"g2", {"large"}}};
  ig.auction_server_request_flags = {AuctionServerRequestFlagsEnum::kOmitAds};
  ig.additional_bid_key.emplace();
  ig.additional_bid_key->fill(0);
  ig.aggregation_coordinator_origin =
      url::Origin::Create(GURL("https://aggegator.example.org"));

  blink::mojom::StorageInterestGroupPtr storage_interest_group =
      blink::mojom::StorageInterestGroup::New(
          std::move(ig), std::move(bidding_browser_signals),
          /*joining_origin=*/
          url::Origin::Create(GURL("https://joining-origin.com")),
          /*join_time=*/now - base::Seconds(2000),
          /*last_updated=*/now - base::Seconds(1500),
          /*next_update_after=*/now + base::Seconds(2000),
          /*estimated_size=*/1000);

  std::vector<blink::mojom::StorageInterestGroupPtr> groups;
  groups.
"""


```
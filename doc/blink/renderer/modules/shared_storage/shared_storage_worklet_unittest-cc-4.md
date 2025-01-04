Response:
The user wants to understand the functionality of the provided C++ code file, which is a unit test file for the Shared Storage Worklet in the Chromium Blink engine. I need to analyze the test cases to identify the features being tested and how they relate to JavaScript, HTML, and CSS.

**Plan:**

1. Identify the main class being tested: `SharedStoragePrivateAggregationTest`.
2. Analyze each `TEST_F` function within this class.
3. Determine the functionality each test case is verifying.
4. Relate these functionalities to web technologies (JavaScript, HTML, CSS) if applicable.
5. Identify assumptions for inputs and expected outputs for logical reasoning.
6. Pinpoint potential user or programming errors highlighted by the tests.
7. Infer the user actions leading to these scenarios as debugging clues.
8. Summarize the overall functionality of the test file.这是第 5 部分，共 5 部分，总结一下 `blink/renderer/modules/shared_storage/shared_storage_worklet_unittest.cc` 文件的功能：

**总结：**

`blink/renderer/modules/shared_storage/shared_storage_worklet_unittest.cc` 文件主要用于测试 Shared Storage Worklet 中 Private Aggregation API 的功能。它通过一系列的单元测试来验证该 API 的各种行为，包括成功调用、错误处理、权限控制以及与调试模式和过滤 ID 的交互。此外，该文件还包含测试用于验证 `SharedStorageWorkletThread` 中 WorkerBackingThread 的管理方式。

**功能归纳:**

1. **Private Aggregation 功能测试:**
    *   测试 `privateAggregation.contributeToHistogram()` 方法在各种有效和无效输入下的行为，包括：
        *   合法的 bucket 和 value 值。
        *   零值 bucket 和 value。
        *   极大值 bucket。
        *   非整数 value（会被截断）。
        *   超出范围的 bucket 值（会被拒绝）。
        *   负数的 bucket 和 value 值（会被拒绝）。
        *   非 BigInt 类型的 bucket 值（会被拒绝）。
    *   测试 `privateAggregation.enableDebugMode()` 方法：
        *   在调用 `contributeToHistogram()` 之前和之后调用 `enableDebugMode()` 的行为。
        *   重复调用 `enableDebugMode()` 的错误处理。
        *   调试模式对后续请求的影响。
    *   测试 Filtering ID 功能：
        *   使用 `filteringId` 参数成功发送贡献。
        *   在启用调试模式下使用 `filteringId`。
        *   不指定 `filteringId` 时的默认行为。
        *   显式指定默认 `filteringId` 的行为。
        *   各种大小的 `filteringId` 的成功和失败情况。

2. **权限策略测试:**
    *   测试在 Private Aggregation 权限策略被禁用时，`contributeToHistogram()` 方法是否会被拒绝。

3. **异常处理和错误报告测试:**
    *   测试在 Worklet 脚本中发生错误（例如，未定义的变量）导致 `addModule()` 失败后，`privateAggregation` 对象是否仍然可用，但后续操作是否会成功。

4. **生命周期管理测试:**
    *   测试在 Worklet 操作仍在进行中但全局作用域被删除后，贡献是否仍然会被刷新（确保数据不会丢失）。

5. **线程管理测试 (SharedStorageWorkletThreadTest):**
    *   测试 `SharedStorageWorkletThread` 是否拥有专属的 `WorkerBackingThread`（在禁用 `kSharedStorageWorkletSharedBackingThreadImplementation` 特性时）。
    *   测试多个 `SharedStorageWorkletThread` 是否共享同一个 `WorkerBackingThread`（在启用 `kSharedStorageWorkletSharedBackingThreadImplementation` 特性时，尽管目前该测试被禁用）。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关联到 JavaScript，因为它测试的是在 Shared Storage Worklet 中可用的 JavaScript API (`privateAggregation`)。虽然它不直接涉及 HTML 或 CSS 的语法，但它测试的功能最终会影响到网站在用户浏览器中的行为。

*   **JavaScript:**  测试用例直接执行 JavaScript 代码片段，例如：
    ```javascript
    privateAggregation.contributeToHistogram({bucket: 1n, value: 2});
    privateAggregation.enableDebugMode({debugKey: 1234n});
    ```
    这些代码片段模拟了开发者在 Shared Storage Worklet 中可能使用的 JavaScript API。

*   **HTML:**  虽然测试文件本身不涉及 HTML，但 Shared Storage API 是通过 JavaScript 在网页上下文中使用的。开发者可能会在 HTML 中引用的 JavaScript 文件中使用这些 API，例如：
    ```html
    <script>
      // 在网页的 JavaScript 代码中调用 Shared Storage API (假设已注册 Worklet)
      navigator.sharedStorage.run('my-operation');
    </script>
    ```
    而 `my-operation` 这个 Worklet 内部可能就使用了 `privateAggregation.contributeToHistogram()`。

*   **CSS:**  CSS 与 Private Aggregation 的关系较为间接。Private Aggregation 主要用于在不暴露个人身份信息的情况下进行聚合数据统计。这些统计结果可能会被用于改进广告投放或其他需要用户行为分析的功能，而这些功能最终可能会影响到网站的样式和布局，但这并非直接的语法关联。

**逻辑推理的假设输入与输出:**

*   **假设输入:**  Worklet 脚本成功注册，且执行了以下 JavaScript 代码：
    ```javascript
    privateAggregation.contributeToHistogram({bucket: 100n, value: 5});
    ```
*   **预期输出:**  `mock_private_aggregation_host_` 接收到一个 `ContributeToHistogram` 的调用，其中 `contributions` 包含一个元素，其 `bucket` 为 100，`value` 为 5。

*   **假设输入:** Worklet 脚本尝试调用 `enableDebugMode()` 两次：
    ```javascript
    privateAggregation.enableDebugMode({debugKey: 1234n});
    privateAggregation.enableDebugMode();
    ```
*   **预期输出:** 第二次调用 `enableDebugMode()` 将抛出一个错误，指示该方法最多只能被调用一次。

**用户或编程常见的使用错误举例说明:**

*   **错误使用 BigInt 字面量:** 用户可能会忘记在 JavaScript 中使用 `n` 后缀来表示 BigInt，导致类型错误。例如，`{bucket: 1, value: 2}` 会导致错误，因为 `bucket` 不是 BigInt 类型。测试用例 `NonBigIntBucket_Rejected` 就是为了捕获这种错误。

*   **提供超出范围的值:** 用户可能会尝试为 `bucket` 或 `filteringId` 提供超出其允许范围的值。例如，`bucket` 的最大值是 2<sup>128</sup> - 1，超出这个范围的值会被拒绝。测试用例 `TooLargeBucket_Rejected` 和 `FilteringIdTooBigForByteSize_Error` 等就是测试这类错误。

*   **多次调用 `enableDebugMode()`:**  用户可能会错误地尝试多次调用 `enableDebugMode()`，而该方法只能被调用一次。测试用例 `EnableDebugModeCalledTwice_SecondCallFails` 检查了这种情况。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **开发者编写代码:** 网站开发者决定使用 Shared Storage API 中的 Private Aggregation 功能来收集匿名化的数据。
2. **注册 Shared Storage Worklet:** 开发者编写一个 JavaScript Worklet 脚本，并在其中使用 `privateAggregation.contributeToHistogram()` 方法来发送聚合数据。
3. **网页触发 Worklet 执行:**  用户的某些操作（例如，浏览特定页面、点击按钮）触发了网页中的 JavaScript 代码，该代码调用 `navigator.sharedStorage.run()` 来执行之前注册的 Worklet。
4. **Worklet 内部调用 Private Aggregation API:**  当 Worklet 运行时，`privateAggregation.contributeToHistogram()` 方法被调用，尝试向浏览器发送聚合数据。
5. **单元测试模拟上述流程:**  `SharedStoragePrivateAggregationTest` 中的测试用例模拟了上述步骤，通过 `AddModule()` 注册 Worklet 脚本，然后使用 `Run()` 方法模拟 Worklet 的执行，并断言 `mock_private_aggregation_host_` 是否接收到了预期的调用和参数。如果测试失败，则表明在 Shared Storage Worklet 的 Private Aggregation 功能的实现中存在问题。

通过分析这些测试用例，开发者可以确保 Private Aggregation API 在各种场景下都能正常工作，并且能够正确处理用户的错误输入，从而提高 Web 平台的稳定性和安全性。

Prompt: 
```
这是目录为blink/renderer/modules/shared_storage/shared_storage_worklet_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共5部分，请归纳一下它的功能

"""
ECT_EQ(run_result.error_message, "");
}

TEST_F(SharedStoragePrivateAggregationTest,
       InterfaceAndObjectExposure_AfterAddModuleFailure) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          PrivateAggregation;
          privateAggregation;
        }
      }

      register("test-operation", TestClass);

      // This should fail the addModule()
      a;
  )");

  EXPECT_FALSE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_EQ(run_result.error_message, "");
}

TEST_F(SharedStoragePrivateAggregationTest, BasicTest) {
  ExecuteScriptAndValidateContribution(
      "privateAggregation.contributeToHistogram({bucket: 1n, value: 2});",
      /*expected_bucket=*/1, /*expected_value=*/2);
}

TEST_F(SharedStoragePrivateAggregationTest, ZeroBucket) {
  ExecuteScriptAndValidateContribution(
      "privateAggregation.contributeToHistogram({bucket: 0n, value: 2});",
      /*expected_bucket=*/0, /*expected_value=*/2);
}

TEST_F(SharedStoragePrivateAggregationTest, ZeroValue) {
  ExecuteScriptAndValidateContribution(
      "privateAggregation.contributeToHistogram({bucket: 1n, value: 0});",
      /*expected_bucket=*/1, /*expected_value=*/0);
}

TEST_F(SharedStoragePrivateAggregationTest, LargeBucket) {
  ExecuteScriptAndValidateContribution(
      "privateAggregation.contributeToHistogram("
      "{bucket: 18446744073709551616n, value: 2});",
      /*expected_bucket=*/absl::MakeUint128(/*high=*/1, /*low=*/0),
      /*expected_value=*/2);
}

TEST_F(SharedStoragePrivateAggregationTest, MaxBucket) {
  ExecuteScriptAndValidateContribution(
      "privateAggregation.contributeToHistogram("
      "{bucket: 340282366920938463463374607431768211455n, value: 2});",
      /*expected_bucket=*/absl::Uint128Max(), /*expected_value=*/2);
}

TEST_F(SharedStoragePrivateAggregationTest, NonIntegerValue) {
  ExecuteScriptAndValidateContribution(
      "privateAggregation.contributeToHistogram({bucket: 1n, value: 2.3});",
      /*expected_bucket=*/1, /*expected_value=*/2);
}

TEST_F(SharedStoragePrivateAggregationTest,
       PrivateAggregationPermissionsPolicyNotAllowed_Rejected) {
  permissions_policy_state_ =
      blink::mojom::SharedStorageWorkletPermissionsPolicyState::New(
          /*private_aggregation_allowed=*/false,
          /*join_ad_interest_group_allowed=*/true,
          /*run_ad_auction_allowed=*/true);

  std::string error_str = ExecuteScriptReturningError(
      "privateAggregation.contributeToHistogram({bucket: 1n, value: 2});",
      /*expect_use_counters=*/{
          mojom::WebFeature::kPrivateAggregationApiAll,
          mojom::WebFeature::kPrivateAggregationApiSharedStorage});

  EXPECT_THAT(error_str, testing::HasSubstr(
                             "The \"private-aggregation\" Permissions Policy "
                             "denied the method on privateAggregation"));
}

TEST_F(SharedStoragePrivateAggregationTest, TooLargeBucket_Rejected) {
  std::string error_str = ExecuteScriptReturningError(
      "privateAggregation.contributeToHistogram({bucket: "
      "340282366920938463463374607431768211456n, value: 2});",
      /*expect_use_counters=*/{
          mojom::WebFeature::kPrivateAggregationApiAll,
          mojom::WebFeature::kPrivateAggregationApiSharedStorage});

  EXPECT_THAT(
      error_str,
      testing::HasSubstr(
          "contribution['bucket'] is negative or does not fit in 128 bits"));
}

TEST_F(SharedStoragePrivateAggregationTest, NegativeBucket_Rejected) {
  std::string error_str = ExecuteScriptReturningError(
      "privateAggregation.contributeToHistogram({bucket: -1n, value: 2});",
      /*expect_use_counters=*/{
          mojom::WebFeature::kPrivateAggregationApiAll,
          mojom::WebFeature::kPrivateAggregationApiSharedStorage});

  EXPECT_THAT(
      error_str,
      testing::HasSubstr(
          "contribution['bucket'] is negative or does not fit in 128 bits"));
}

TEST_F(SharedStoragePrivateAggregationTest, NonBigIntBucket_Rejected) {
  std::string error_str = ExecuteScriptReturningError(
      "privateAggregation.contributeToHistogram({bucket: 1, value: 2});",
      /*expect_use_counters=*/{});

  EXPECT_THAT(error_str, testing::HasSubstr("Cannot convert 1 to a BigInt"));
}

TEST_F(SharedStoragePrivateAggregationTest, NegativeValue_Rejected) {
  std::string error_str = ExecuteScriptReturningError(
      "privateAggregation.contributeToHistogram({bucket: 1n, value: -1});",
      /*expect_use_counters=*/{
          mojom::WebFeature::kPrivateAggregationApiAll,
          mojom::WebFeature::kPrivateAggregationApiSharedStorage});

  EXPECT_THAT(error_str,
              testing::HasSubstr("contribution['value'] is negative"));
}

TEST_F(SharedStoragePrivateAggregationTest,
       InvalidEnableDebugModeArgument_Rejected) {
  // The debug key is not wrapped in a dictionary.
  std::string error_str =
      ExecuteScriptReturningError("privateAggregation.enableDebugMode(1234n);",
                                  /*expect_use_counters=*/{});

  EXPECT_THAT(error_str,
              testing::HasSubstr("The provided value is not of type "
                                 "'PrivateAggregationDebugModeOptions'"));
}

TEST_F(SharedStoragePrivateAggregationTest,
       EnableDebugModeCalledTwice_SecondCallFails) {
  std::string error_str;

  // Note that the first call still applies to future requests if the error is
  // caught. Here, we rethrow it to check its value.
  ExecuteScriptAndValidateContribution(
      R"(
        let error;
        try {
          privateAggregation.enableDebugMode({debugKey: 1234n});
          privateAggregation.enableDebugMode();
        } catch (e) {
          error = e;
        }
        privateAggregation.contributeToHistogram({bucket: 1n, value: 2});
        throw error;
      )",
      /*expected_bucket=*/1,
      /*expected_value=*/2,
      /*expected_debug_mode_details=*/
      mojom::blink::DebugModeDetails::New(
          /*is_enabled=*/true,
          /*debug_key=*/mojom::blink::DebugKey::New(1234u)),
      /*filtering_id=*/std::nullopt,
      /*filtering_id_max_bytes=*/1, &error_str);

  EXPECT_THAT(error_str,
              testing::HasSubstr("enableDebugMode may be called at most once"));
}

// Note that FLEDGE worklets have different behavior in this case.
TEST_F(SharedStoragePrivateAggregationTest,
       EnableDebugModeCalledAfterRequest_DoesntApply) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class ContributeToHistogram {
        async run() {
          privateAggregation.contributeToHistogram({bucket: 1n, value: 2});
        }
      }

      class EnableDebugMode {
        async run() {
          privateAggregation.enableDebugMode({debugKey: 1234n});
        }
      }

      register("contribute-to-histogram", ContributeToHistogram);
      register("enable-debug-mode", EnableDebugMode);
  )");

  std::optional<mojo::ReceiverId> contribute_to_histogram_pipe_id;
  std::optional<mojo::ReceiverId> enable_debug_mode_pipe_id;
  base::RunLoop run_loop;
  base::RepeatingClosure closure =
      base::BarrierClosure(2, run_loop.QuitClosure());

  EXPECT_CALL(*mock_private_aggregation_host_, ContributeToHistogram)
      .WillOnce(testing::Invoke(
          [&](Vector<
              blink::mojom::blink::AggregatableReportHistogramContributionPtr>
                  contributions) {
            ASSERT_EQ(contributions.size(), 1u);
            EXPECT_EQ(contributions[0]->bucket, 1);
            EXPECT_EQ(contributions[0]->value, 2);

            contribute_to_histogram_pipe_id =
                mock_private_aggregation_host_->receiver_set()
                    .current_receiver();
            closure.Run();
          }));
  EXPECT_CALL(*mock_private_aggregation_host_, EnableDebugMode)
      .WillOnce(
          testing::Invoke([&](blink::mojom::blink::DebugKeyPtr debug_key) {
            ASSERT_FALSE(debug_key.is_null());
            EXPECT_EQ(debug_key->value, 1234u);

            enable_debug_mode_pipe_id =
                mock_private_aggregation_host_->receiver_set()
                    .current_receiver();
            closure.Run();
          }));

  RunResult run_result =
      Run("contribute-to-histogram", CreateSerializedUndefined());
  EXPECT_TRUE(run_result.success);

  RunResult run_result2 = Run("enable-debug-mode", CreateSerializedUndefined());
  EXPECT_TRUE(run_result2.success);

  mock_private_aggregation_host_->FlushForTesting();
  run_loop.Run();

  // The calls should've come on two different pipes.
  EXPECT_TRUE(contribute_to_histogram_pipe_id.has_value());
  EXPECT_TRUE(enable_debug_mode_pipe_id.has_value());
  EXPECT_NE(contribute_to_histogram_pipe_id, enable_debug_mode_pipe_id);
}

TEST_F(SharedStoragePrivateAggregationTest, MultipleDebugModeRequests) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          privateAggregation.enableDebugMode({debugKey: 1234n});
          privateAggregation.contributeToHistogram({bucket: 1n, value: 2});
          privateAggregation.contributeToHistogram({bucket: 3n, value: 4});
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_CALL(*mock_private_aggregation_host_, EnableDebugMode)
      .WillOnce(testing::Invoke([](mojom::blink::DebugKeyPtr debug_key) {
        EXPECT_EQ(debug_key, mojom::blink::DebugKey::New(1234u));
      }));

  EXPECT_CALL(*mock_private_aggregation_host_, ContributeToHistogram)
      .WillOnce(testing::Invoke(
          [](Vector<
              blink::mojom::blink::AggregatableReportHistogramContributionPtr>
                 contributions) {
            ASSERT_EQ(contributions.size(), 1u);
            EXPECT_EQ(contributions[0]->bucket, 1);
            EXPECT_EQ(contributions[0]->value, 2);
          }))
      .WillOnce(testing::Invoke(
          [](Vector<
              blink::mojom::blink::AggregatableReportHistogramContributionPtr>
                 contributions) {
            ASSERT_EQ(contributions.size(), 1u);
            EXPECT_EQ(contributions[0]->bucket, 3);
            EXPECT_EQ(contributions[0]->value, 4);
          }));

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());
  EXPECT_TRUE(run_result.success);

  mock_private_aggregation_host_->FlushForTesting();
}

// Regression test for crbug.com/1429895.
TEST_F(SharedStoragePrivateAggregationTest,
       GlobalScopeDeletedBeforeOperationCompletes_ContributionsStillFlushed) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          privateAggregation.contributeToHistogram({bucket: 1n, value: 2});
          await new Promise(() => {});
        }
      }

      register("test-operation", TestClass);
  )");

  base::RunLoop run_loop;

  EXPECT_CALL(*mock_private_aggregation_host_, EnableDebugMode).Times(0);
  EXPECT_CALL(*mock_private_aggregation_host_, ContributeToHistogram)
      .WillOnce(testing::Invoke(
          [&](Vector<
              blink::mojom::blink::AggregatableReportHistogramContributionPtr>
                  contributions) {
            ASSERT_EQ(contributions.size(), 1u);
            EXPECT_EQ(contributions[0]->bucket, 1);
            EXPECT_EQ(contributions[0]->value, 2);

            run_loop.Quit();
          }));

  shared_storage_worklet_service_->RunOperation(
      "test-operation", CreateSerializedUndefined(),
      MaybeInitPAOperationDetails(), base::DoNothing());

  // Trigger the disconnect handler.
  shared_storage_worklet_service_.reset();

  // Callback called means the worklet has terminated successfully.
  EXPECT_TRUE(worklet_terminated_future_.Wait());

  run_loop.Run();
}

TEST_F(SharedStoragePrivateAggregationTest, BasicFilteringId) {
  ExecuteScriptAndValidateContribution(
      "privateAggregation.contributeToHistogram("
      "{bucket: 1n, value: 2, filteringId: 3n});",
      /*expected_bucket=*/1, /*expected_value=*/2,
      /*expected_debug_mode_details=*/mojom::blink::DebugModeDetails::New(),
      /*filtering_id=*/3);
}

TEST_F(SharedStoragePrivateAggregationTest, FilteringIdWithDebugMode) {
  ExecuteScriptAndValidateContribution(
      R"(privateAggregation.enableDebugMode();
         privateAggregation.contributeToHistogram(
             {bucket: 1n, value: 2, filteringId: 3n});)",
      /*expected_bucket=*/1, /*expected_value=*/2,
      /*expected_debug_mode_details=*/
      mojom::blink::DebugModeDetails::New(/*is_enabled=*/true,
                                          /*debug_key=*/nullptr),
      /*filtering_id=*/3);
}

TEST_F(SharedStoragePrivateAggregationTest,
       NoFilteringIdSpecified_FilteringIdNull) {
  ExecuteScriptAndValidateContribution(
      "privateAggregation.contributeToHistogram({bucket: 1n, value: 2});",
      /*expected_bucket=*/1, /*expected_value=*/2,
      /*expected_debug_mode_details=*/mojom::blink::DebugModeDetails::New(),
      /*filtering_id=*/std::nullopt);
}

TEST_F(SharedStoragePrivateAggregationTest,
       ExplicitDefaultFilteringId_FilteringIdNotNull) {
  ExecuteScriptAndValidateContribution(
      "privateAggregation.contributeToHistogram("
      "{bucket: 1n, value: 2, filteringId: 0n});",
      /*expected_bucket=*/1, /*expected_value=*/2,
      /*expected_debug_mode_details=*/mojom::blink::DebugModeDetails::New(),
      /*filtering_id=*/0);
}

TEST_F(SharedStoragePrivateAggregationTest, MaxFilteringIdForByteSize_Success) {
  ExecuteScriptAndValidateContribution(
      "privateAggregation.contributeToHistogram("
      "{bucket: 1n, value: 2, filteringId: 255n});",
      /*expected_bucket=*/1, /*expected_value=*/2,
      /*expected_debug_mode_details=*/mojom::blink::DebugModeDetails::New(),
      /*filtering_id=*/255);
}

TEST_F(SharedStoragePrivateAggregationTest,
       FilteringIdTooBigForByteSize_Error) {
  std::string error_str = ExecuteScriptReturningError(
      "privateAggregation.contributeToHistogram("
      "{bucket: 1n, value: 2, filteringId: 256n});",
      /*expect_use_counters=*/{
          mojom::WebFeature::kPrivateAggregationApiAll,
          mojom::WebFeature::kPrivateAggregationApiSharedStorage,
          mojom::WebFeature::kPrivateAggregationApiFilteringIds});

  EXPECT_THAT(error_str,
              testing::HasSubstr("contribution['filteringId'] is negative or "
                                 "does not fit in byte size"));
}

TEST_F(SharedStoragePrivateAggregationTest, FilteringIdNegative_Error) {
  std::string error_str = ExecuteScriptReturningError(
      "privateAggregation.contributeToHistogram("
      "{bucket: 1n, value: 2, filteringId: -1n});",
      /*expect_use_counters=*/{
          mojom::WebFeature::kPrivateAggregationApiAll,
          mojom::WebFeature::kPrivateAggregationApiSharedStorage,
          mojom::WebFeature::kPrivateAggregationApiFilteringIds});

  EXPECT_THAT(error_str,
              testing::HasSubstr("contribution['filteringId'] is negative or "
                                 "does not fit in byte size"));
}

TEST_F(SharedStoragePrivateAggregationTest, NoFilteringIdWithCustomByteSize) {
  ExecuteScriptAndValidateContribution(
      "privateAggregation.contributeToHistogram({bucket: 1n, value: 2});",
      /*expected_bucket=*/1, /*expected_value=*/2,
      /*expected_debug_mode_details=*/mojom::blink::DebugModeDetails::New(),
      /*filtering_id=*/std::nullopt, /*filtering_id_max_bytes=*/3);
}

TEST_F(SharedStoragePrivateAggregationTest,
       FilteringIdWithCustomByteSize_Success) {
  ExecuteScriptAndValidateContribution(
      "privateAggregation.contributeToHistogram("
      "{bucket: 1n, value: 2, filteringId: 3n});",
      /*expected_bucket=*/1, /*expected_value=*/2,
      /*expected_debug_mode_details=*/mojom::blink::DebugModeDetails::New(),
      /*filtering_id=*/3, /*filtering_id_max_bytes=*/3);
}

TEST_F(SharedStoragePrivateAggregationTest,
       MaxFilteringIdWithCustomByteSize_Success) {
  ExecuteScriptAndValidateContribution(
      "privateAggregation.contributeToHistogram("
      "{bucket: 1n, value: 2, filteringId: 16777215n});",
      /*expected_bucket=*/1, /*expected_value=*/2,
      /*expected_debug_mode_details=*/mojom::blink::DebugModeDetails::New(),
      /*filtering_id=*/16777215, /*filtering_id_max_bytes=*/3);
}

TEST_F(SharedStoragePrivateAggregationTest,
       TooBigFilteringIdWithCustomByteSize_Error) {
  std::string error_str = ExecuteScriptReturningError(
      "privateAggregation.contributeToHistogram("
      "{bucket: 1n, value: 2, filteringId: 16777216n});",
      /*expect_use_counters=*/
      {mojom::WebFeature::kPrivateAggregationApiAll,
       mojom::WebFeature::kPrivateAggregationApiSharedStorage,
       mojom::WebFeature::kPrivateAggregationApiFilteringIds},
      /*filtering_id_max_bytes=*/3);

  EXPECT_THAT(error_str,
              testing::HasSubstr("contribution['filteringId'] is negative or "
                                 "does not fit in byte size"));
}

TEST_F(SharedStoragePrivateAggregationTest, MaxPossibleFilteringId) {
  ExecuteScriptAndValidateContribution(
      "privateAggregation.contributeToHistogram("
      "{bucket: 1n, value: 2, filteringId: (1n << 64n) - 1n});",
      /*expected_bucket=*/1, /*expected_value=*/2,
      /*expected_debug_mode_details=*/mojom::blink::DebugModeDetails::New(),
      /*filtering_id=*/std::numeric_limits<uint64_t>::max(),
      /*filtering_id_max_bytes=*/8);
}

TEST_F(SharedStoragePrivateAggregationTest,
       TooBigFilteringIdWithMaxByteSize_Error) {
  std::string error_str = ExecuteScriptReturningError(
      "privateAggregation.contributeToHistogram("
      "{bucket: 1n, value: 2, filteringId: (1n << 64n)});",
      /*expect_use_counters=*/
      {mojom::WebFeature::kPrivateAggregationApiAll,
       mojom::WebFeature::kPrivateAggregationApiSharedStorage,
       mojom::WebFeature::kPrivateAggregationApiFilteringIds},
      /*filtering_id_max_bytes=*/8);

  EXPECT_THAT(error_str,
              testing::HasSubstr("contribution['filteringId'] is negative or "
                                 "does not fit in byte size"));
}

class SharedStorageWorkletThreadTest : public testing::Test {};

// Assert that each `SharedStorageWorkletThread` owns a dedicated
// `WorkerBackingThread`.
TEST_F(SharedStorageWorkletThreadTest, DedicatedBackingThread) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(
      blink::features::kSharedStorageWorkletSharedBackingThreadImplementation);

  test::TaskEnvironment task_environment;

  MockWorkerReportingProxy reporting_proxy1;
  MockWorkerReportingProxy reporting_proxy2;
  auto thread1 = SharedStorageWorkletThread::Create(reporting_proxy1);
  auto thread2 = SharedStorageWorkletThread::Create(reporting_proxy2);
  EXPECT_NE(&thread1->GetWorkerBackingThread(),
            &thread2->GetWorkerBackingThread());

  // Start and terminate the threads, so that the test can terminate gracefully.
  auto thread_startup_data = WorkerBackingThreadStartupData::CreateDefault();
  thread_startup_data.atomics_wait_mode =
      WorkerBackingThreadStartupData::AtomicsWaitMode::kAllow;

  thread1->Start(MakeTestGlobalScopeCreationParams(), thread_startup_data,
                 std::make_unique<WorkerDevToolsParams>());
  thread2->Start(MakeTestGlobalScopeCreationParams(), thread_startup_data,
                 std::make_unique<WorkerDevToolsParams>());

  thread1->TerminateForTesting();
  thread1->WaitForShutdownForTesting();
  thread2->TerminateForTesting();
  thread2->WaitForShutdownForTesting();
}

// Assert that multiple `SharedStorageWorkletThread`s share a
// `WorkerBackingThread`.
//
// Note: Currently, this would trigger a crash due to a failure in installing
// the `v8/expose_gc` extension. Even though `--expose-gc` isn't set by default
// in production, we should still fix this.
//
// TODO(yaoxia): We're temporarily leaving this issue unfixed to facilitate our
// investigation into a crash that occurs in the wild (crbug.com/1501387). We'll
// re-enable this after investigation.
TEST_F(SharedStorageWorkletThreadTest, DISABLED_SharedBackingThread) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      blink::features::kSharedStorageWorkletSharedBackingThreadImplementation);

  test::TaskEnvironment task_environment;
  MockWorkerReportingProxy reporting_proxy1;
  MockWorkerReportingProxy reporting_proxy2;
  auto thread1 = SharedStorageWorkletThread::Create(reporting_proxy1);
  auto thread2 = SharedStorageWorkletThread::Create(reporting_proxy2);
  EXPECT_EQ(&thread1->GetWorkerBackingThread(),
            &thread2->GetWorkerBackingThread());

  // Start and terminate the threads, so that the test can terminate gracefully.
  thread1->Start(MakeTestGlobalScopeCreationParams(),
                 /*thread_startup_data=*/std::nullopt,
                 std::make_unique<WorkerDevToolsParams>());
  thread2->Start(MakeTestGlobalScopeCreationParams(),
                 /*thread_startup_data=*/std::nullopt,
                 std::make_unique<WorkerDevToolsParams>());

  thread1->TerminateForTesting();
  thread1->WaitForShutdownForTesting();
  thread2->TerminateForTesting();
  thread2->WaitForShutdownForTesting();
}

}  // namespace blink

"""


```
Response: The user wants to understand the functionality of the C++ source code file `sequence_manager_fuzzer_processor_unittest.cc`. I need to analyze the code and identify its purpose. It appears to be a unit test file for `SequenceManagerFuzzerProcessor`.

Here's a breakdown of the steps:

1. **Identify the Core Functionality:** The file contains `TEST` macros, indicating unit tests. The tests use `SequenceManagerFuzzerProcessorForTest`, a test fixture derived from `SequenceManagerFuzzerProcessor`. The tests parse a string representation of a test scenario (using protobuf) and then run it. They compare the actual executed actions and tasks with the expected ones.

2. **Relate to Web Technologies (JavaScript, HTML, CSS):** The `SequenceManager` is a core component in Blink's scheduler. It manages the execution of tasks. These tasks can be related to:
    * **JavaScript:**  JavaScript execution is often scheduled via the `SequenceManager`. For example, a `setTimeout` or a promise resolution will result in a task being added to a queue.
    * **HTML Rendering and Parsing:**  Tasks related to layout, painting, and parsing HTML are managed by the scheduler.
    * **CSS Style Calculation:** Applying styles and recalculating layout based on CSS changes also involves scheduled tasks.

3. **Identify Logical Reasoning and Provide Examples:** The tests often set up scenarios involving task queues, task posting, delays, priorities, enabling/disabling queues, and cross-thread communication. I need to select a few tests and explain the logical flow, including input and output.

4. **Highlight Potential User/Programming Errors:** The tests implicitly demonstrate common errors by testing different scheduling scenarios. I can point out examples like:
    * Posting tasks to disabled or shutdown queues.
    * Canceling tasks that haven't run yet.
    * Understanding task execution order based on delays and priorities.
    * Cross-thread communication issues.

**Pre-computation/Analysis:**

* **`SequenceManagerFuzzerProcessor`:** This class likely takes a description of actions and tasks and simulates their execution within Blink's scheduling system. The "fuzzer" part suggests it's designed to handle a wide range of inputs to find potential issues.
* **Protobuf:** The use of protobuf (`SequenceManagerTestDescription`) indicates that the test scenarios are described in a structured way. This makes the tests easier to write and parse.
* **`TaskForTest` and `ActionForTest`:** These are likely data structures to record the details of executed tasks (ID, start time, end time) and actions (type, ID, timestamp).
* **Test Structure:** The tests follow a pattern:
    1. Define a test scenario as a string (protobuf format).
    2. Parse the string using `ParseAndRun` or `ParseAndRunSingleThread`.
    3. Get the executed tasks and actions from the processor.
    4. Define the expected tasks and actions.
    5. Use `EXPECT_THAT` to compare the actual and expected results.

Now I can generate the response based on these insights.
这个C++源代码文件 `sequence_manager_fuzzer_processor_unittest.cc` 是 Chromium Blink 引擎中 `SequenceManagerFuzzerProcessor` 类的单元测试文件。它的主要功能是**测试 `SequenceManagerFuzzerProcessor` 类的各种功能和行为**。

`SequenceManagerFuzzerProcessor` 的作用是根据预定义的指令（通过 protobuf 描述）来模拟 Blink 线程和任务队列的各种操作，例如创建任务队列、发布任务、设置优先级、启用/禁用队列、关闭队列、取消任务、跨线程发布任务等。这个 fuzzer 的目的是通过大量的随机或精心设计的输入，来发现 `SequenceManager` 在处理各种复杂场景时的潜在问题。

**与 JavaScript, HTML, CSS 的功能关系：**

`SequenceManager` 是 Blink 引擎中负责任务调度的核心组件，它直接影响着 JavaScript 代码的执行、HTML 的渲染和解析、以及 CSS 样式的计算和应用。

* **JavaScript:**
    * **例子：`PostDelayedTaskWDuration` 测试** 模拟了使用 `post_delayed_task` 方法发布一个延迟执行的任务。这与 JavaScript 中的 `setTimeout` 或 `requestAnimationFrame` 等 API 非常相似。当 JavaScript 代码调用 `setTimeout(callback, delay)` 时，Blink 的调度器会创建一个任务并将其添加到相应的任务队列中，等待延迟时间到达后执行 `callback`。
    * **例子：`CancelTask` 测试** 模拟了取消一个已发布的任务。这与 JavaScript 中 `clearTimeout` 或取消 `requestAnimationFrame` 的功能对应。
    * **假设输入：** 一个 JavaScript 函数调用 `setTimeout(() => console.log("Hello"), 100);`
    * **对应的 `SequenceManagerFuzzerProcessor` 输入 (简化)：**
      ```protobuf
      initial_thread_actions {
        action_id : 1
        post_delayed_task {
          delay_ms : 100
          task {
            task_id : 1
            // 模拟执行 console.log("Hello") 的动作
          }
        }
      }
      ```
    * **输出 (假设)：**  `executed_tasks` 中会包含一个 `task_id: 1` 的任务，其执行时间会被记录。

* **HTML:**
    * **例子：`TaskDurationBlocksOtherPendingTasksPostedFromOutsideOfTask` 测试** 模拟了一个耗时任务阻塞其他任务执行的情况。这与浏览器在处理大型 HTML 文档或执行复杂的 JavaScript 计算时，可能导致页面卡顿的现象有关。渲染 HTML 的各个阶段（解析、布局、绘制）通常会作为任务被调度执行。如果一个渲染任务耗时过长，可能会延迟后续渲染任务的执行，导致页面响应缓慢。
    * **假设输入：** 浏览器需要解析一个包含大量 DOM 元素的 HTML 页面。
    * **对应的 `SequenceManagerFuzzerProcessor` 输入 (简化)：**
      ```protobuf
      initial_thread_actions {
        action_id : 1
        post_delayed_task {
          task {
            task_id : 1
            duration_ms : 50 // 模拟 HTML 解析耗时
            // 模拟 HTML 解析的动作
          }
        }
      }
      initial_thread_actions {
        action_id : 2
        post_delayed_task {
          delay_ms : 10
          task {
            task_id : 2
            // 模拟后续的布局或绘制任务
          }
        }
      }
      ```
    * **输出 (假设)：**  `executed_tasks` 中 `task_id: 1` 的任务会先执行，并且 `task_id: 2` 的任务会因为 `task_id: 1` 的耗时而被延迟执行。

* **CSS:**
    * **例子：`SetQueuePriority` 测试** 模拟了设置任务队列优先级的功能。CSS 样式的计算和应用也会被调度执行，并且可能存在不同的优先级。例如，用户交互触发的样式更新可能比初始页面加载的样式具有更高的优先级。
    * **假设输入：**  用户鼠标悬停在一个元素上，触发 CSS `:hover` 伪类的样式变化。
    * **对应的 `SequenceManagerFuzzerProcessor` 输入 (简化)：**
      ```protobuf
      initial_thread_actions {
        action_id : 1
        set_queue_priority {
          task_queue_id: 1 // 假设是负责用户交互相关任务的队列
          priority: CONTROL // 设置为高优先级
        }
      }
      initial_thread_actions {
        action_id : 2
        post_delayed_task {
          task_queue_id: 1
          task {
            task_id : 1
            // 模拟计算 hover 样式的任务
          }
        }
      }
      ```
    * **输出 (假设)：**  `executed_actions` 会记录设置队列优先级的操作，并且与用户交互相关的任务会优先执行。

**逻辑推理的假设输入与输出：**

* **测试用例： `SetQueueEnabledWDelays`**
    * **假设输入 (protobuf 描述)：**
      ```protobuf
       initial_thread_actions {
         action_id : 1
         create_task_queue {
         }
       }
       initial_thread_actions {
         action_id : 2
         post_delayed_task {
           task_queue_id: 1
           task {
             task_id : 1
           }
         }
       }
       initial_thread_actions {
         action_id : 3
         post_delayed_task {
           delay_ms : 15
           task_queue_id: 1
           task {
             task_id : 2
           }
         }
       }
       initial_thread_actions {
         action_id : 4
         post_delayed_task {
           delay_ms : 10
           task_queue_id: 1
           task {
             task_id : 3
             actions {
               action_id : 5
               set_queue_enabled {
                 task_queue_id: 1
                 enabled: false
               }
             }
           }
         }
       }
       initial_thread_actions {
         action_id : 6
         post_delayed_task {
           delay_ms : 20
           task_queue_id: 0
           task {
             task_id : 4
             actions {
               action_id : 7
               set_queue_enabled {
                 task_queue_id: 1
                 enabled: true
               }
             }
           }
         }
       }
       initial_thread_actions {
         action_id : 8
         post_delayed_task {
           task_queue_id: 1
           delay_ms : 20
           task {
             task_id : 5
           }
         }
       })
      ```
    * **逻辑推理：**
        1. 创建一个任务队列 (id: 1)。
        2. 向队列 1 发布一个立即执行的任务 (id: 1)。
        3. 向队列 1 发布一个延迟 15ms 执行的任务 (id: 2)。
        4. 向队列 1 发布一个延迟 10ms 执行的任务 (id: 3)，该任务会禁用队列 1。
        5. 向默认队列 (id: 0) 发布一个延迟 20ms 执行的任务 (id: 4)，该任务会启用队列 1。
        6. 向队列 1 发布一个延迟 20ms 执行的任务 (id: 5)。
    * **预期输出 (部分)：**
        * `executed_tasks` 会包含以下任务（及其预计的开始和结束时间）：
            * `task_id: 1`, start: 0ms, end: 0ms
            * `task_id: 3`, start: 10ms, end: 10ms (禁用队列)
            * `task_id: 4`, start: 20ms, end: 20ms (启用队列)
            * `task_id: 2`, start: 20ms, end: 20ms (原计划 15ms 执行，但队列被禁用，所以延迟到启用后执行)
            * `task_id: 5`, start: 20ms, end: 20ms
        * 注意 `task_id: 2` 因为在 15ms 时队列被禁用而无法执行，直到队列被重新启用后才执行。

**涉及用户或者编程常见的使用错误：**

* **发布任务到已禁用的队列 (`SetQueueEnabled` 测试)：** 用户或程序员可能错误地向一个已经被禁用的任务队列发布任务，导致任务无法执行。
    * **例子：** 在 JavaScript 中，如果错误地在某个事件监听器被移除后，仍然尝试使用 `setTimeout` 发布与该监听器相关的回调函数，那么该回调函数将不会执行（如果该回调函数的目标任务队列在监听器移除时被禁用）。
* **在队列关闭后发布任务 (`ShutdownTaskQueue` 测试)：**  尝试向一个已经关闭的任务队列发布任务，通常这些任务会被丢弃或者转移到其他队列。
    * **例子：** 在多线程环境中，如果一个线程的任务队列被关闭，而其他线程仍然尝试向该队列发送消息或任务，会导致消息丢失或程序行为异常。
* **取消不存在的任务 (`CancelTaskWhenNoneArePending` 测试)：**  尝试取消一个从未发布或者已经执行完毕的任务，虽然不会造成程序崩溃，但这通常表示逻辑错误。
    * **例子：** 在 JavaScript 中，错误地使用相同的 `timeoutId` 多次调用 `clearTimeout`，只有第一次调用会有效，后续调用实际上不会取消任何任务。
* **依赖任务执行的顺序，但未考虑优先级和延迟 (`OrderOfSimpleUnnestedExecutedActions` 测试)：**  程序员可能会错误地假设任务会按照发布的顺序执行，而忽略了延迟时间和任务优先级的影响。
    * **例子：**  在 JavaScript 中，如果先调用 `setTimeout(funcA, 10)`，然后调用 `setTimeout(funcB, 5)`，那么 `funcB` 很可能先于 `funcA` 执行，因为它的延迟时间更短。

总而言之，这个单元测试文件的目的是为了验证 Blink 引擎中任务调度器的正确性和健壮性，通过模拟各种可能的场景，包括与 JavaScript、HTML、CSS 功能相关的操作，来确保任务能够按照预期的方式执行，并防止潜在的错误和 bug。

### 提示词
```
这是目录为blink/renderer/platform/scheduler/test/fuzzer/sequence_manager_fuzzer_processor_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/scheduler/test/fuzzer/sequence_manager_fuzzer_processor.h"

#include <memory>

#include "base/strings/strcat.h"
#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/scheduler/test/fuzzer/proto/sequence_manager_test_description.pb.h"
#include "third_party/protobuf/src/google/protobuf/text_format.h"
#include "third_party/protobuf/src/google/protobuf/util/message_differencer.h"

namespace base {
namespace sequence_manager {

using testing::ContainerEq;
using testing::UnorderedElementsAreArray;

class SequenceManagerFuzzerProcessorForTest
    : public SequenceManagerFuzzerProcessor {
 public:
  SequenceManagerFuzzerProcessorForTest()
      : SequenceManagerFuzzerProcessor(true) {}

  static void ParseAndRun(std::string test_description,
                          Vector<Vector<TaskForTest>>* executed_tasks,
                          Vector<Vector<ActionForTest>>* executed_actions) {
    SequenceManagerTestDescription proto_description;
    google::protobuf::TextFormat::ParseFromString(test_description,
                                                  &proto_description);

    SequenceManagerFuzzerProcessorForTest processor;
    processor.RunTest(proto_description);

    if (executed_tasks)
      *executed_tasks = processor.ordered_tasks();
    if (executed_actions)
      *executed_actions = processor.ordered_actions();
  }

  static void ParseAndRunSingleThread(std::string test_description,
                                      Vector<TaskForTest>* executed_tasks,
                                      Vector<ActionForTest>* executed_actions) {
    SequenceManagerTestDescription proto_description;

    google::protobuf::TextFormat::ParseFromString(
        base::StrCat(
            {"main_thread_actions { create_thread {", test_description, "}}"}),
        &proto_description);

    SequenceManagerFuzzerProcessorForTest processor;
    processor.RunTest(proto_description);

    if (executed_tasks)
      *executed_tasks = processor.ordered_tasks()[1];
    if (executed_actions)
      *executed_actions = processor.ordered_actions()[1];
  }

  using SequenceManagerFuzzerProcessor::ordered_actions;
  using SequenceManagerFuzzerProcessor::ordered_tasks;

  using SequenceManagerFuzzerProcessor::ActionForTest;
  using SequenceManagerFuzzerProcessor::TaskForTest;
};

using ActionForTest = SequenceManagerFuzzerProcessorForTest::ActionForTest;
using TaskForTest = SequenceManagerFuzzerProcessorForTest::TaskForTest;

TEST(SequenceManagerFuzzerProcessorTest, CreateTaskQueue) {
  Vector<ActionForTest> executed_actions;

  // Describes a test that creates a task queue and posts a task to create a
  // task queue.
  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
       initial_thread_actions {
         action_id : 1
         create_task_queue {
         }
       }
       initial_thread_actions {
         action_id : 2
         post_delayed_task {
           task {
             task_id : 1
             actions {
               action_id : 3
               create_task_queue {
               }
             }
           }
         }
       })",
      nullptr, &executed_actions);

  Vector<ActionForTest> expected_actions;
  expected_actions.emplace_back(1, ActionForTest::ActionType::kCreateTaskQueue,
                                0);
  expected_actions.emplace_back(2, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(3, ActionForTest::ActionType::kCreateTaskQueue,
                                0);
  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));
}

TEST(SequenceManagerFuzzerProcessorTest, CreateQueueVoter) {
  Vector<ActionForTest> executed_actions;

  // Describes a test that creates a voter and posts a task to create a queue
  // voter.
  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
       initial_thread_actions {
         action_id : 1
         create_queue_voter {
           task_queue_id : 1
         }
       }
       initial_thread_actions {
         action_id : 2
         post_delayed_task {
           task {
             task_id : 1
             actions {
               action_id : 3
               create_queue_voter {
               }
             }
           }
         }
       })",
      nullptr, &executed_actions);

  Vector<ActionForTest> expected_actions;
  expected_actions.emplace_back(1, ActionForTest::ActionType::kCreateQueueVoter,
                                0);
  expected_actions.emplace_back(2, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(3, ActionForTest::ActionType::kCreateQueueVoter,
                                0);
  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));
}

TEST(SequenceManagerFuzzerProcessorTest, PostDelayedTaskWDuration) {
  Vector<TaskForTest> executed_tasks;
  Vector<ActionForTest> executed_actions;

  // Posts an 10 ms delayed task of duration 20 ms.
  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
      initial_thread_actions {
        action_id : 1
        post_delayed_task {
          task_queue_id : 1
          delay_ms : 10
          task {
            task_id : 1
            duration_ms : 20
          }
        }
      })",
      &executed_tasks, &executed_actions);

  Vector<TaskForTest> expected_tasks;
  expected_tasks.emplace_back(1, 10, 30);
  EXPECT_THAT(executed_tasks, ContainerEq(expected_tasks));

  Vector<ActionForTest> expected_actions;
  expected_actions.emplace_back(1, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));
}

TEST(SequenceManagerFuzzerProcessorTest, SetQueuePriority) {
  Vector<ActionForTest> executed_actions;

  // Describes a test that sets the priority of queue and posts a task to set
  // the priority of a queue.
  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
       initial_thread_actions {
          action_id : 1
          set_queue_priority {
            task_queue_id: 2
            priority: CONTROL
          }
       }
       initial_thread_actions {
         action_id : 2
         post_delayed_task {
           task {
             task_id : 1
             actions {
               action_id : 3
               set_queue_priority {
                 task_queue_id : 1
                 priority : LOW
               }
             }
           }
         }
       })",
      nullptr, &executed_actions);

  Vector<ActionForTest> expected_actions;
  expected_actions.emplace_back(1, ActionForTest::ActionType::kSetQueuePriority,
                                0);
  expected_actions.emplace_back(2, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(3, ActionForTest::ActionType::kSetQueuePriority,
                                0);

  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));
}

TEST(SequenceManagerFuzzerProcessorTest, SetQueueEnabled) {
  Vector<ActionForTest> executed_actions;
  Vector<TaskForTest> executed_tasks;

  // Describes a test that posts a number of tasks to a certain queue, disable
  // that queue, and post some more tasks to the same queue.
  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
       initial_thread_actions {
         action_id : 1
         post_delayed_task {
           task_queue_id: 1
           task {
             task_id : 1
           }
         }
       }
       initial_thread_actions {
         action_id : 2
         post_delayed_task {
           delay_ms : 10
           task_queue_id: 1
           task {
             task_id : 2
           }
         }
       }
       initial_thread_actions {
         action_id : 3
         set_queue_enabled {
           task_queue_id: 1
           enabled: false
         }
       }
      initial_thread_actions {
        action_id : 4
        post_delayed_task {
          task_queue_id: 1
          task {
            task_id : 3
          }
        }
      })",
      &executed_tasks, &executed_actions);

  Vector<ActionForTest> expected_actions;
  expected_actions.emplace_back(1, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(2, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(3, ActionForTest::ActionType::kSetQueueEnabled,
                                0);
  expected_actions.emplace_back(4, ActionForTest::ActionType::kPostDelayedTask,
                                0);

  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));

  // All the tasks posted to the task queue with id 1 do not get executed since
  // this task queue is disabled.
  EXPECT_TRUE(executed_tasks.empty());
}

TEST(SequenceManagerFuzzerProcessorTest, SetQueueEnabledWDelays) {
  Vector<TaskForTest> executed_tasks;

  // Describes a test that posts two tasks to disable and enable a queue after
  // 10ms and 20ms, respectively; and other no-op tasks in the different
  // intervals to verify that the queue is indeed being disabled/enabled
  // properly.
  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
       initial_thread_actions {
         action_id : 1
         create_task_queue {
         }
       }
       initial_thread_actions {
         action_id : 2
         post_delayed_task {
           task_queue_id: 1
           task {
             task_id : 1
           }
         }
       }
       initial_thread_actions {
         action_id : 3
         post_delayed_task {
           delay_ms : 15
           task_queue_id: 1
           task {
             task_id : 2
           }
         }
       }
       initial_thread_actions {
         action_id : 4
         post_delayed_task {
           delay_ms : 10
           task_queue_id: 1
           task {
             task_id : 3
             actions {
               action_id : 5
               set_queue_enabled {
                 task_queue_id: 1
                 enabled: false
               }
             }
           }
         }
       }
       initial_thread_actions {
         action_id : 6
         post_delayed_task {
           delay_ms : 20
           task_queue_id: 0
           task {
             task_id : 4
             actions {
               action_id : 7
               set_queue_enabled {
                 task_queue_id: 1
                 enabled: true
               }
             }
           }
         }
       }
       initial_thread_actions {
         action_id : 8
         post_delayed_task {
           task_queue_id: 1
           delay_ms : 20
           task {
             task_id : 5
           }
         }
       })",
      &executed_tasks, nullptr);

  Vector<TaskForTest> expected_tasks;

  expected_tasks.emplace_back(1, 0, 0);

  // Task that disables the queue.
  expected_tasks.emplace_back(3, 10, 10);

  // Task that enable the queue.
  expected_tasks.emplace_back(4, 20, 20);

  // Task couldn't execute at scheduled time i.e. 15ms since its queue was
  // disabled at that time.
  expected_tasks.emplace_back(2, 20, 20);
  expected_tasks.emplace_back(5, 20, 20);

  EXPECT_THAT(executed_tasks, ContainerEq(expected_tasks));
}

TEST(SequenceManagerFuzzerProcessorTest, MultipleVoters) {
  Vector<ActionForTest> executed_actions;
  Vector<TaskForTest> executed_tasks;

  // Describes a test that creates two voters for a queue, where one voter
  // enables the queue, and the other disables it.
  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
      initial_thread_actions {
         action_id : 1
         create_queue_voter {
           task_queue_id : 1
         }
       }
       initial_thread_actions {
         action_id : 2
         create_queue_voter {
           task_queue_id : 1
         }
       }
       initial_thread_actions {
         action_id : 3
         set_queue_enabled {
           voter_id : 1
           task_queue_id : 1
           enabled : true
         }
       }
       initial_thread_actions {
         action_id : 4
         set_queue_enabled {
           voter_id : 2
           task_queue_id : 1
           enabled : false
         }
       }
       initial_thread_actions {
         action_id : 5
         post_delayed_task {
           task_queue_id: 1
           task {
             task_id : 1
           }
         }
       })",
      &executed_tasks, &executed_actions);

  Vector<ActionForTest> expected_actions;
  expected_actions.emplace_back(1, ActionForTest::ActionType::kCreateQueueVoter,
                                0);
  expected_actions.emplace_back(2, ActionForTest::ActionType::kCreateQueueVoter,
                                0);
  expected_actions.emplace_back(3, ActionForTest::ActionType::kSetQueueEnabled,
                                0);
  expected_actions.emplace_back(4, ActionForTest::ActionType::kSetQueueEnabled,
                                0);
  expected_actions.emplace_back(5, ActionForTest::ActionType::kPostDelayedTask,
                                0);

  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));

  Vector<TaskForTest> expected_tasks;

  // Queue is enabled only if all voters enable it.
  EXPECT_TRUE(executed_tasks.empty());
}

TEST(SequenceManagerFuzzerProcessorTest, ShutdownTaskQueue) {
  Vector<ActionForTest> executed_actions;
  Vector<TaskForTest> executed_tasks;

  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
       initial_thread_actions {
         action_id : 1
         create_task_queue {
         }
       }
       initial_thread_actions {
         action_id : 2
         post_delayed_task {
           task_queue_id: 1
           task {
             task_id : 1
           }
         }
        }
        initial_thread_actions {
          action_id :3
          post_delayed_task {
            delay_ms : 10
            task_queue_id: 1
            task {
              task_id : 2
            }
          }
        }
        initial_thread_actions {
          action_id : 4
          post_delayed_task {
            task_queue_id: 0
            delay_ms : 10
            task {
              task_id : 3
            }
          }
        }
        initial_thread_actions {
          action_id : 5
          shutdown_task_queue {
            task_queue_id: 1
          }
        }
        initial_thread_actions {
          action_id : 6
          post_delayed_task {
            task_queue_id: 1
            task {
              task_id : 4
            }
          }
        })",
      &executed_tasks, &executed_actions);

  Vector<ActionForTest> expected_actions;
  expected_actions.emplace_back(1, ActionForTest::ActionType::kCreateTaskQueue,
                                0);
  expected_actions.emplace_back(2, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(3, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(4, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(
      5, ActionForTest::ActionType::kShutdownTaskQueue, 0);
  expected_actions.emplace_back(6, ActionForTest::ActionType::kPostDelayedTask,
                                0);

  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));

  Vector<TaskForTest> expected_tasks;

  // Note that the task with id 4 isn't posted to the queue that was shutdown,
  // since that was posted to the first available queue (Check
  // sequence_manager_test_description.proto for more details).
  expected_tasks.emplace_back(4, 0, 0);
  expected_tasks.emplace_back(3, 10, 10);

  EXPECT_THAT(executed_tasks, ContainerEq(expected_tasks));
}

TEST(SequenceManagerFuzzerProcessorTest,
     ShutdownTaskQueueWhenOneQueueAvailable) {
  Vector<TaskForTest> executed_tasks;
  Vector<ActionForTest> executed_actions;
  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
        initial_thread_actions {
          action_id : 1
          post_delayed_task {
            task {
              task_id : 1
            }
          }
        }
        initial_thread_actions {
          action_id : 2
          shutdown_task_queue {
            task_queue_id: 1
          }
        })",
      &executed_tasks, &executed_actions);

  Vector<ActionForTest> expected_actions;
  expected_actions.emplace_back(1, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(
      2, ActionForTest::ActionType::kShutdownTaskQueue, 0);

  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));

  Vector<TaskForTest> expected_tasks;

  // We always want to have a default task queue in every thread. So, if
  // we have only one queue, the shutdown action is effectively a no-op.
  expected_tasks.emplace_back(1, 0, 0);

  EXPECT_THAT(executed_tasks, ContainerEq(expected_tasks));
}

TEST(SequenceManagerFuzzerProcessorTest, ShutdownPostingTaskQueue) {
  Vector<TaskForTest> executed_tasks;
  Vector<ActionForTest> executed_actions;
  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
        initial_thread_actions {
          action_id : 1
          create_task_queue {
          }
        }
        initial_thread_actions {
          action_id : 2
          post_delayed_task {
            task_queue_id : 0
            task{
              task_id : 1
              actions {
                action_id : 3
                shutdown_task_queue {
                  task_queue_id : 0
                }
              }
            }
          }
        })",
      &executed_tasks, &executed_actions);

  Vector<ActionForTest> expected_actions;
  expected_actions.emplace_back(1, ActionForTest::ActionType::kCreateTaskQueue,
                                0);
  expected_actions.emplace_back(2, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(
      3, ActionForTest::ActionType::kShutdownTaskQueue, 0);

  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));

  Vector<TaskForTest> expected_tasks;
  expected_tasks.emplace_back(1, 0, 0);

  EXPECT_THAT(executed_tasks, ContainerEq(expected_tasks));
}

TEST(SequenceManagerFuzzerProcessorTest, CancelParentTask) {
  Vector<ActionForTest> executed_actions;
  Vector<TaskForTest> executed_tasks;

  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
    initial_thread_actions {
      action_id : 1
      post_delayed_task {
        task {
          task_id : 0
          actions {
            action_id : 2
            post_delayed_task {
              task {
                task_id : 1
              }
            }
          }
          actions {
            action_id : 3
            cancel_task {
              task_id : 0
            }
          }
          actions {
            action_id : 4
            post_delayed_task {
              task {
                task_id : 2
              }
            }
          }
        }
      }
    })",
      &executed_tasks, &executed_actions);

  Vector<ActionForTest> expected_actions;

  expected_actions.emplace_back(1, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(2, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(3, ActionForTest::ActionType::kCancelTask, 0);
  expected_actions.emplace_back(4, ActionForTest::ActionType::kPostDelayedTask,
                                0);

  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));

  Vector<TaskForTest> expected_tasks;

  expected_tasks.emplace_back(0, 0, 0);
  expected_tasks.emplace_back(1, 0, 0);
  expected_tasks.emplace_back(2, 0, 0);

  EXPECT_THAT(executed_tasks, ContainerEq(expected_tasks));
}

TEST(SequenceManagerFuzzerProcessorTest, CancelTask) {
  Vector<TaskForTest> executed_tasks;
  Vector<ActionForTest> executed_actions;

  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
    initial_thread_actions {
      action_id : 1
      post_delayed_task {
        task {
          task_id : 1
        }
      }
    }
    initial_thread_actions {
      action_id : 2
      cancel_task {
        task_id : 1
      }
    }
  )",
      &executed_tasks, &executed_actions);

  Vector<ActionForTest> expected_actions;
  expected_actions.emplace_back(1, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(2, ActionForTest::ActionType::kCancelTask, 0);
  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));

  EXPECT_TRUE(executed_tasks.empty());
}

TEST(SequenceManagerFuzzerProcessorTest, CancelTaskWhenNoneArePending) {
  Vector<ActionForTest> executed_actions;

  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
    initial_thread_actions {
      action_id : 1
      cancel_task {
        task_id : 1
      }
    }
  )",
      nullptr, &executed_actions);

  Vector<ActionForTest> expected_actions;
  expected_actions.emplace_back(1, ActionForTest::ActionType::kCancelTask, 0);
  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));
}

TEST(SequenceManagerFuzzerProcessorTest,
     TaskDurationBlocksOtherPendingTasksPostedFromOutsideOfTask) {
  Vector<TaskForTest> executed_tasks;
  Vector<ActionForTest> executed_actions;

  // Posts a task of duration 40 ms and a 10 ms delayed task of duration 20 ms.
  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
        initial_thread_actions {
          action_id : 1
          post_delayed_task {
            delay_ms : 10
            task {
              task_id : 1
              duration_ms : 20
            }
          }
        }
        initial_thread_actions {
          action_id :2
          post_delayed_task {
            delay_ms : 0
            task {
              task_id : 2
              duration_ms : 40
            }
          }
        })",
      &executed_tasks, &executed_actions);

  Vector<TaskForTest> expected_tasks;

  // Task with id 2 is expected to run first and block the other task until it
  // done.
  expected_tasks.emplace_back(2, 0, 40);
  expected_tasks.emplace_back(1, 40, 60);
  EXPECT_THAT(executed_tasks, ContainerEq(expected_tasks));

  Vector<ActionForTest> expected_actions;
  expected_actions.emplace_back(1, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(2, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));
}

TEST(SequenceManagerFuzzerProcessorTest,
     TaskDurationBlocksOtherNonNestableTaskWhenPostedFromWithinTask) {
  Vector<TaskForTest> executed_tasks;

  // Posts an instant task of duration 40 ms that posts another non-nested
  // instant task.
  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
        initial_thread_actions {
          post_delayed_task {
            task {
              task_id : 1
              duration_ms : 40
              actions {
                post_delayed_task {
                  task {
                    task_id : 2
                  }
                }
              }
            }
          }
        })",
      &executed_tasks, nullptr);

  Vector<TaskForTest> expected_tasks;

  // Task with task id 1 is expected to run for 40 ms, and block the other
  // posted task from running until its done. Note that the task with id 2 is
  // blocked since it is non-nested, so it is not supposed to run from win
  // the posting task.
  expected_tasks.emplace_back(1, 0, 40);
  expected_tasks.emplace_back(2, 40, 40);

  EXPECT_THAT(executed_tasks, ContainerEq(expected_tasks));
}

TEST(SequenceManagerFuzzerProcessorTest, PostNonEmptyTask) {
  Vector<TaskForTest> executed_tasks;
  Vector<ActionForTest> executed_actions;

  // Posts a 5 ms delayed task of duration 40 ms that creates a task queue,
  // posts a 4 ms delayed task, posts an instant task, creates a task queue,
  // and then posts a 40 ms delayed task.
  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
      initial_thread_actions {
        action_id : 1
        post_delayed_task {
          delay_ms: 5
          task {
            task_id : 1
            duration_ms : 40
            actions {
              action_id : 2
              create_task_queue {
              }
            }
            actions {
              action_id : 3
              post_delayed_task {
                delay_ms : 4
                task {
                  task_id : 2
                }
              }
            }
            actions {
              action_id: 4
              post_delayed_task {
                task {
                  task_id : 3
                }
              }
            }
            actions {
              action_id : 5
              create_task_queue {
              }
            }
            actions {
              action_id : 6
              post_delayed_task {
               delay_ms : 40
               task {
                 task_id : 4
               }
              }
            }
          }
        }
      })",
      &executed_tasks, &executed_actions);

  Vector<TaskForTest> expected_tasks;

  // Task with task id 1 is expected to run first, and block all other pending
  // tasks until its done. The remaining tasks will be executed in
  // non-decreasing order of the delay parameter with ties broken by
  // the post order.
  expected_tasks.emplace_back(1, 5, 45);
  expected_tasks.emplace_back(3, 45, 45);
  expected_tasks.emplace_back(2, 45, 45);
  expected_tasks.emplace_back(4, 45, 45);
  EXPECT_THAT(executed_tasks, ContainerEq(expected_tasks));

  Vector<ActionForTest> expected_actions;
  expected_actions.emplace_back(1, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(2, ActionForTest::ActionType::kCreateTaskQueue,
                                5);
  expected_actions.emplace_back(3, ActionForTest::ActionType::kPostDelayedTask,
                                5);
  expected_actions.emplace_back(4, ActionForTest::ActionType::kPostDelayedTask,
                                5);
  expected_actions.emplace_back(5, ActionForTest::ActionType::kCreateTaskQueue,
                                5);
  expected_actions.emplace_back(6, ActionForTest::ActionType::kPostDelayedTask,
                                5);
  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));
}

TEST(SequenceManagerFuzzerProcessorTest, OrderOfSimpleUnnestedExecutedActions) {
  Vector<TaskForTest> executed_tasks;
  Vector<ActionForTest> executed_actions;

  // Creates a task queue, posts a task after 20 ms delay, posts a 10 ms
  // duration task after 15 ms of delay, and posts a task after 100 ms of delay.
  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
      initial_thread_actions {
        action_id : 1
        create_task_queue {
        }
      }
      initial_thread_actions {
        action_id : 2
        post_delayed_task {
          delay_ms : 10
          task {
            task_id : 1
            actions {
              action_id : 3
              create_task_queue {
              }
            }
          }
        }
      }
      initial_thread_actions {
        action_id : 4
        post_delayed_task {
          delay_ms : 20
          task {
            task_id : 2
          }
        }
      }
      initial_thread_actions {
        action_id : 5
        post_delayed_task {
          delay_ms : 15
          task {
            task_id : 3
            duration_ms : 10
          }
        }
      }
      initial_thread_actions {
        action_id : 6
        post_delayed_task {
          delay_ms : 100
          task {
            task_id : 4
          }
        }
      })",
      &executed_tasks, &executed_actions);

  Vector<TaskForTest> expected_tasks;

  // Tasks are expected to run in order of non-decreasing delay with ties broken
  // by order of posting. Note that the task with id 3 will block the task with
  // id 2 from running at its scheduled time.
  expected_tasks.emplace_back(1, 10, 10);
  expected_tasks.emplace_back(3, 15, 25);
  expected_tasks.emplace_back(2, 25, 25);
  expected_tasks.emplace_back(4, 100, 100);
  EXPECT_THAT(executed_tasks, ContainerEq(expected_tasks));

  Vector<ActionForTest> expected_actions;
  expected_actions.emplace_back(1, ActionForTest::ActionType::kCreateTaskQueue,
                                0);
  expected_actions.emplace_back(2, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(4, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(5, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(6, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(3, ActionForTest::ActionType::kCreateTaskQueue,
                                10);
  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));
}

TEST(SequenceManagerFuzzerProcessorTest, InsertAndRemoveFence) {
  Vector<ActionForTest> executed_actions;
  Vector<TaskForTest> executed_tasks;

  // Describes a test that inserts a fence to a task queue after a delay of
  // 20ms, posts a task to it after a delay of 25ms, and removes the fence after
  // a delay of 30ms.
  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
       initial_thread_actions {
         action_id : 1
           create_task_queue{
           }
         }
       initial_thread_actions {
         action_id : 2
         post_delayed_task {
           delay_ms : 20
           task_queue_id : 2
           task {
             task_id : 1
             actions {
               action_id : 3
               insert_fence {
                 position: NOW
                 task_queue_id: 1
               }
             }
           }
         }
       }
       initial_thread_actions {
         action_id : 4
         post_delayed_task {
           delay_ms : 30
           task_queue_id : 2
           task {
             task_id : 2
             actions {
               action_id : 5
               remove_fence {
                 task_queue_id: 1
               }
             }
           }
         }
      }
      initial_thread_actions {
        action_id: 6
        post_delayed_task {
          delay_ms: 25
          task_queue_id: 1
          task {
            task_id: 3
          }
        }
      })",
      &executed_tasks, &executed_actions);

  Vector<ActionForTest> expected_actions;
  expected_actions.emplace_back(1, ActionForTest::ActionType::kCreateTaskQueue,
                                0);
  expected_actions.emplace_back(2, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(4, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(6, ActionForTest::ActionType::kPostDelayedTask,
                                0);
  expected_actions.emplace_back(3, ActionForTest::ActionType::kInsertFence, 20);
  expected_actions.emplace_back(5, ActionForTest::ActionType::kRemoveFence, 30);

  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));

  Vector<TaskForTest> expected_tasks;
  expected_tasks.emplace_back(1, 20, 20);
  expected_tasks.emplace_back(2, 30, 30);

  // Task with id 3 will not execute until the fence is removed from the task
  // queue it was posted to.
  expected_tasks.emplace_back(3, 30, 30);

  EXPECT_THAT(executed_tasks, ContainerEq(expected_tasks));
}

TEST(SequenceManagerFuzzerProcessorTest, ThrottleTaskQueue) {
  Vector<ActionForTest> executed_actions;
  Vector<TaskForTest> executed_tasks;

  // Describes a test that throttles a task queue, and posts a task to it.
  SequenceManagerFuzzerProcessorForTest::ParseAndRunSingleThread(
      R"(
       initial_thread_actions {
        action_id : 1
        insert_fence {
          position: BEGINNING_OF_TIME
          task_queue_id: 1
        }
       }
       initial_thread_actions {
         action_id: 2
         post_delayed_task {
           task_queue_id: 1
           task {
             task_id: 3
           }
         }
       })",
      &executed_tasks, &executed_actions);

  Vector<ActionForTest> expected_actions;
  expected_actions.emplace_back(1, ActionForTest::ActionType::kInsertFence, 0);
  expected_actions.emplace_back(2, ActionForTest::ActionType::kPostDelayedTask,
                                0);

  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));

  // Task queue with id 1 is throttled, so posted tasks will not get executed.
  EXPECT_TRUE(executed_tasks.empty());
}

TEST(SequenceManagerFuzzerProcessorTest, MultipleThreadsButNotInteracting) {
  std::string thread_actions =
      R"(
      main_thread_actions {
        action_id : 1
        create_thread {
          initial_thread_actions {
            action_id : 1
            create_task_queue {
            }
          }
          initial_thread_actions {
            action_id : 2
            post_delayed_task {
              delay_ms : 10
              task {
                task_id : 1
                actions {
                  action_id : 3
                  create_task_queue {
                  }
                }
              }
            }
          }
          initial_thread_actions {
            action_id : 4
            post_delayed_task {
              delay_ms : 20
              task {
                task_id : 2
              }
            }
          }
          initial_thread_actions {
            action_id : 5
            post_delayed_task {
              delay_ms : 15
              task {
                task_id : 3
                duration_ms : 10
              }
            }
          }
          initial_thread_actions {
            action_id : 6
            post_delayed_task {
              delay_ms : 100
              task {
                task_id : 4
              }
            }
          }
        }
      })";

  // Threads initialized with same list of actions.
  Vector<std::string> threads{thread_actions, thread_actions, thread_actions,
                              thread_actions, thread_actions};

  Vector<Vector<ActionForTest>> executed_actions;
  Vector<Vector<TaskForTest>> executed_tasks;

  SequenceManagerFuzzerProcessorForTest::ParseAndRun(
      base::StrCat(threads), &executed_tasks, &executed_actions);

  // |expected_tasks[0]| is empty since the main thread doesn't execute any
  // task.
  Vector<Vector<TaskForTest>> expected_tasks(6);

  for (int i = 1; i <= 5; i++) {
    // Created thread tasks: tasks are expected to run in order of
    // non-decreasing delay with ties broken by order of posting. Note that the
    // task with id 3 will block the task with id 2 from running at its
    // scheduled time.
    expected_tasks[i].emplace_back(1, 10, 10);
    expected_tasks[i].emplace_back(3, 15, 25);
    expected_tasks[i].emplace_back(2, 25, 25);
    expected_tasks[i].emplace_back(4, 100, 100);
  }

  EXPECT_THAT(executed_tasks, ContainerEq(expected_tasks));

  Vector<Vector<ActionForTest>> expected_actions(6);

  for (int i = 1; i <= 5; i++) {
    // Main thread action: creating the Ith thread.
    expected_actions[0].emplace_back(
        1, ActionForTest::ActionType::kCreateThread, 0);

    // Actions of the Ith thread.
    expected_actions[i].emplace_back(
        1, ActionForTest::ActionType::kCreateTaskQueue, 0);
    expected_actions[i].emplace_back(
        2, ActionForTest::ActionType::kPostDelayedTask, 0);
    expected_actions[i].emplace_back(
        4, ActionForTest::ActionType::kPostDelayedTask, 0);
    expected_actions[i].emplace_back(
        5, ActionForTest::ActionType::kPostDelayedTask, 0);
    expected_actions[i].emplace_back(
        6, ActionForTest::ActionType::kPostDelayedTask, 0);
    expected_actions[i].emplace_back(
        3, ActionForTest::ActionType::kCreateTaskQueue, 10);
  }

  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));
}

TEST(SequenceManagerFuzzerProcessorTest, CreateThreadRecursively) {
  Vector<Vector<ActionForTest>> executed_actions;

  SequenceManagerFuzzerProcessorForTest::ParseAndRun(
      R"(
      main_thread_actions {
        action_id : 1
        create_thread {
          initial_thread_actions {
            action_id : 2
            create_thread {
              initial_thread_actions {
                action_id : 3
                create_thread {}
              }
            }
          }
        }
      }
      )",
      nullptr, &executed_actions);

  // Last thread has no actions, so |expected_actions[3]| is empty.
  Vector<Vector<ActionForTest>> expected_actions(4);

  for (int i = 0; i <= 2; i++) {
    // Actions of the Ith thread.
    expected_actions[i].emplace_back(
        i + 1, ActionForTest::ActionType::kCreateThread, 0);
  }

  EXPECT_THAT(executed_actions, ContainerEq(expected_actions));
}

// Flaky. See https://crbug.com/878203.
TEST(SequenceManagerFuzzerProcessorTest, DISABLED_PostTaskToCreateThread) {
  Vector<Vector<ActionForTest>> executed_actions;
  Vector<Vector<TaskForTest>> executed_tasks;

  SequenceManagerFuzzerProcessorForTest::ParseAndRun(
      R"(
      main_thread_actions {
        action_id : 1
        create_thread {
          initial_thread_actions {
            action_id : 2
            post_delayed_task {
              task {
                task_id: 1
                actions {
                  action_id : 3
                  create_thread {
                  }
                }
              }
            }
          }
          initial_thread_actions {
            action_id : 4
            create_thread {
            }
          }
        }
      }
      main_thread_actions {
        action_id : 5
        create_thread {
          initial_thread_actions {
            action_id : 6
            post_delayed_task {
              delay_ms : 20
              task {
                task_id: 2
                duration_ms : 30
                actions {
                  action_id : 7
                  create_thread {
                  }
                }
              }
            }
          }
        }
      })",
      &executed_tasks, &executed_actions);

  // Third, Fourth and Fifth created threads execute no actions.
  Vector<Vector<ActionForTest>> expected_actions(6);

  expected_actions[0].emplace_back(1, ActionForTest::ActionType::kCreateThread,
                                   0);
  expected_actions[0].emplace_back(5, ActionForTest::ActionType::kCreateThread,
                                   0);

  expected_actions[1].emplace_back(
      2, ActionForTest::ActionType::kPostDelayedTask, 0);

  // Posted messages execute after instant actions.
  expected_actions[1].emplace_back(4, ActionForTest::ActionType::kCreateThread,
                                   0);
  expected_actions[1].emplace_back(3, ActionForTest::ActionType::kCreateThread,
                                   0);

  expected_actions[2].emplace_back(
      6, ActionForTest::ActionType::kPostDelayedTask, 0);
  expected_actions[2].emplace_back(7, ActionForTest::ActionType::kCreateThread,
                                   20);

  // Order isn't deterministic, since threads only start running once all the
  // initial threads are created, and as a result the logging order isn't
  // deterministic,
  EXPECT_THAT(executed_actions, UnorderedElementsAreArray(expected_actions));
}

TEST(SequenceManagerFuzzerProcessorTest,
     CrossThreadPostingOnlyOneThreadAvaible) {
  Vector<Vector<TaskForTest>> executed_tasks;

  SequenceManagerFuzzerProcessorForTest::ParseAndRun(
      R"(
      main_thread_actions {
        create_thread {
          initial_thread_actions{
            post_delayed_task {
              delay_ms: 30
              task {
                task_id: 1
                actions {
                  cross_thread_post {
                    thread_id : 1
                    task {
                      task_id: 2
                    }
                  }
                }
              }
            }
          }
        }
      })",
      &executed_tasks, nullptr);

  Vector<Vector<TaskForTest>> expected_tasks(2);

  expected_tasks[1].emplace_back(1, 30, 30);
  expected_tasks[1].emplace_back(2, 30, 30);

  EXPECT_THAT(executed_tasks, ContainerEq(expected_tasks));
}

TEST(SequenceManagerFuzzerProcessorTest, CrossThreadPosting) {
  Vector<Vector<TaskForTest>> executed_tasks;

  // Thread posts a 10ms delayed task of duration 20ms to another thread.
  SequenceManagerFuzzerProcessorForTest::ParseAndRun(
      R"(
      main_thread_actions {
        create_thread {
        }
      }
      main_thread_actions{
        create_thread {
          initial_thread_actions{
            cross_thread_post {
              thread_id : 0
              delay_ms: 10
              task {
                duration_ms: 20
                task_id: 1
              }
            }
          }
        }
      })",
      &executed_tasks, nullptr);

  Vector<Vector<TaskForTest>> expected_tasks(3);

  expected_tasks[1].emplace_back(1, 10, 30);

  EXPECT_THAT(executed_tasks, ContainerEq(expected_tasks));
}

TEST(SequenceManagerFuzzerProcessorTest, AdvanceThreadsClockSynchronously) {
  Vector<Vector<TaskForTest>> executed_tasks;

  // First created thread has a task posted with a delay of 30 ms. Second thread
  // posts a task to be executed on the first thread after a 10 ms delay.
  SequenceManagerFuzzerProcessorForTest::ParseAndRun(
      R"(
      main_thread_actions {
        create_thread {
          initial_thread_actions {
            post_delayed_task {
              delay_ms : 30
              task {
                task_id: 1
              }
            }
          }
        }
      }
      main_thread_actions {
        create_thread {
          initial_thread_actions{
            cross_thread_post {
              delay_ms: 10
              thread_id : 0
              task {
                task_id: 2
              }
            }
          }
        }
      })",
      &executed_tasks, nullptr);

  Vector<Vector<TaskForTest>> expected_tasks(3);

  // This test checks if the clock is correctly advanced. It does so
  // by checking if the tasks were executed at the expected times.
  expected_tasks[1].emplace_back(2, 10, 10);
  expected_tasks[1].emplace_back(1, 30, 30);

  EXPECT_THAT(executed_tasks, ContainerEq(expected_tasks));
}

TEST(SequenceManagerFuzzerProcessorTest,
     AdvanceThreadClockByTaskDurationSynchronously) {
  Vector<Vector<TaskForTest>> executed_tasks;

  // A thread has instant task posted with a duration of 50ms, which posts
  // a task with duration 20ms to be executed after 10ms on another thread.
  SequenceManagerFuzzerProcessorForTest::ParseAndRun(
      R"(
      main_thread_actions {
        create_thread {
        }
      }
      main_thread_actions {
        create_thread {
          initial_thread_actions{
            post_delayed_task {
              task {
                task_id: 1
                duration_ms: 50
                actions {
                  cross_thread_post {
                    thread_id: 0
                    delay_ms : 10
                    task {
                      task_id : 2
                      duration_ms: 20
                    }
                  }
                }
              }
            }
          }
        }
      })",
      &executed_tasks, nullptr);

  Vector<Vector<TaskForTest>> expected_tasks(3);

  // This test checks if the clock is correctly advanced when tasks have
  // durations. It does so by checking if the tasks were executed at the
  // expected times.
  expected_tasks[1].emplace_back(2, 10, 30);
  expected_tasks[2].emplace_back(1, 0, 50);

  EXPECT_THAT(executed_tasks, ContainerEq(expected_tasks));
}

TEST(SequenceManagerFuzzerProcessorTest, CrossThreadPostFromChildThreads) {
  // We do not wait for child threads to start, so their ThreadManager* might
  // not be registered by the time we cross post the task
  SequenceManagerTestDescription description;
  auto* main_thread =
      description.add_main_thread_actions()->mutable_create_thread();
  for (int i = 0; i < 100; ++i) {
    auto* child_thread =
        main_thread->add_initial_thread_actions()->mutable_create_thread();

    child_thread->add_initial_thread_actions()
        ->mutable_cross_thread_post()
        ->set_thread_id(i + 1234);
  }

  SequenceManagerFuzzerProcessor::ParseAndRun(description);
}

}  // namespace sequence_manager
}  // namespace base
```
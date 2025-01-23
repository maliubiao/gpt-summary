Response:
My thinking process to analyze the C++ code and generate the explanation involves these steps:

1. **Understand the Goal:** The request asks for the functionality of the given C++ code, explanations related to JavaScript (if applicable), code logic reasoning with examples, and common programming errors the code might help avoid.

2. **Initial Scan and Keyword Identification:** I quickly scanned the code looking for keywords and patterns related to testing, data structures, and V8 specifics. Keywords like `TEST_F`, `SnapshotTable`, `Key`, `Snapshot`, `Set`, `Get`, `StartNewSnapshot`, `Seal`, `EXPECT_EQ`, `Zone`, and `AccountingAllocator` are immediately apparent. The namespace `v8::internal::compiler::turboshaft` confirms it's part of the V8 compiler's Turboshaft pipeline.

3. **Focus on the Core Class:** The central element is `SnapshotTable`. The test cases revolve around creating instances of this class and manipulating its methods. This immediately suggests that the code is about testing the functionality of `SnapshotTable`.

4. **Analyze Individual Test Cases:** I then examine each `TEST_F` function individually to understand the specific scenarios being tested:

    * **`BasicTest`:** This test covers the fundamental operations of `SnapshotTable`: creating keys, setting and getting values within snapshots, creating and sealing snapshots, merging snapshots, and retrieving predecessor values. The series of `EXPECT_EQ` calls demonstrates the expected behavior at each step. This is the most comprehensive test and reveals the core functionality.

    * **`KeyData`:** This test checks if the `SnapshotTable` can associate additional data with keys during creation. The `Data` struct and the assertion `EXPECT_EQ(k1.data().x, 5)` confirm this.

    * **`ChangeCallback`:** This test introduces the concept of callbacks triggered when values associated with keys change. It tests both single-snapshot and multi-snapshot scenarios, including how callbacks are invoked during merges.

    * **`ChangeTrackingSnapshotTable`:** This test uses a derived class `ChangeTrackingSnapshotTable` that automatically tracks active keys based on their boolean values and utilizes callbacks. This demonstrates a more specialized use case of the snapshot table.

5. **Infer Functionality from Test Cases:** Based on the analysis of the test cases, I can infer the main functionalities of `SnapshotTable`:

    * **Storing Key-Value Pairs:** It holds data associated with keys.
    * **Snapshotting:** It allows creating snapshots of the table's state at different points in time.
    * **Rollback/Versioning:** Snapshots enable going back to previous states.
    * **Merging Snapshots:**  It supports combining multiple snapshots into a new state, potentially with conflict resolution logic via a provided function.
    * **Change Tracking (with Callbacks):** It can optionally notify when the value associated with a key changes.
    * **Associating Data with Keys:** Keys can have associated data.

6. **Address Specific Requirements of the Prompt:**

    * **Functionality Listing:** Based on the inferred functionality, I create a bulleted list summarizing the capabilities.

    * **Torque Check:** I verify that the file extension is `.cc` and not `.tq`, so it's C++ and not Torque.

    * **JavaScript Relationship:** I consider if the `SnapshotTable` concept has parallels in JavaScript. While there isn't a direct, built-in equivalent, the idea of managing state and changes over time is common. I brainstorm scenarios like undo/redo functionality, version control, or managing application state and provide a conceptual JavaScript example using object copying or a state management library to illustrate the idea. The key is the *concept* not a direct code mapping.

    * **Code Logic Reasoning:** I choose a part of the `BasicTest` (the merging of `s1` and `s2`) and provide a step-by-step breakdown with the initial state, the merge operation, the callback function, and the final expected state. This demonstrates how the merging and callback mechanisms work.

    * **Common Programming Errors:** I think about potential problems this `SnapshotTable` design could help avoid. The most prominent is the risk of inadvertently modifying shared state without proper tracking or the ability to revert. I create a JavaScript example where directly modifying an object can lead to unexpected side effects and contrast it with the safer approach offered by the `SnapshotTable` concept.

7. **Refine and Organize:**  I review the generated explanation for clarity, accuracy, and completeness, ensuring it directly addresses all parts of the prompt. I organize the information logically using headings and bullet points for readability. I double-check the C++ code to ensure my interpretations are correct.

By following this systematic approach, I can effectively analyze the C++ code and generate a comprehensive and informative explanation that addresses all aspects of the user's request.
This C++ code defines a unit test for a class called `SnapshotTable`. The `SnapshotTable` appears to be a data structure designed for managing values associated with keys, with the ability to create and manage snapshots of its state.

Here's a breakdown of its functionality based on the test cases:

**Functionality of `SnapshotTable`:**

* **Stores Key-Value Pairs:** The `SnapshotTable` holds integer values associated with unique keys of type `SnapshotTable<int>::Key`.
* **Creates New Keys:** The `NewKey()` method allows creating new keys and optionally initializing them with a default value.
* **Sets and Gets Values:** The `Set()` method updates the value associated with a key, and the `Get()` method retrieves the current value for a key.
* **Creates Snapshots:** The `StartNewSnapshot()` and `Seal()` methods are used to create and finalize snapshots of the table's state. Snapshots capture the values of all keys at a specific point in time.
* **Rollback/Versioning:** Snapshots allow going back to a previous state of the table. When a new snapshot is started, it initially reflects the state of the previous snapshot.
* **Merging Snapshots:** The `StartNewSnapshot()` method can take one or more existing snapshots as input. This allows merging the changes from those snapshots into a new state.
* **Conflict Resolution during Merging:** When merging snapshots, a callback function can be provided to resolve conflicts (i.e., when the same key has different values in the merged snapshots). This callback receives the key and a vector of values from the merged snapshots, and it returns the resolved value.
* **Ignoring Redundant Sets:** Setting a key to its existing value within a snapshot is ignored and doesn't create a new entry in the snapshot's change log.
* **Retrieving Predecessor Values:** The `GetPredecessorValue()` method allows accessing the value of a key in a specific preceding snapshot during a merge operation.
* **Change Callbacks:** The `StartNewSnapshot()` method can optionally take a callback function that is invoked whenever a key's value changes during the creation of the new snapshot. This callback provides the key, the old value, and the new value.
* **Associating Data with Keys (Optional):** The `SnapshotTable` can optionally store additional data associated with each key, as demonstrated in the `KeyData` test. This data is independent of the value stored in the table.
* **Change Tracking (Specialized Version):** The `ChangeTrackingSnapshotTable` demonstrates a specialized version that automatically tracks active keys based on their boolean values and uses callbacks to update this tracking.

**Is it a Torque source code?**

No, the file extension is `.cc`, which indicates it's a C++ source file. Torque source files typically have a `.tq` extension.

**Relationship with JavaScript and Example:**

While `SnapshotTable` is a C++ class used within the V8 JavaScript engine's compiler (Turboshaft), it doesn't directly correspond to a specific JavaScript language feature. However, the concept of managing state and tracking changes over time is relevant to JavaScript development.

Imagine you're building a JavaScript application with an undo/redo feature. You could conceptually use a system similar to `SnapshotTable` to manage the history of your application's state.

```javascript
// Conceptual JavaScript example (not a direct mapping of SnapshotTable)
class StateManager {
  constructor() {
    this.history = [];
    this.currentState = {};
  }

  getCurrentState() {
    return { ...this.currentState }; // Return a copy
  }

  setState(newState) {
    this.history.push(this.getCurrentState());
    this.currentState = { ...newState };
  }

  undo() {
    if (this.history.length > 0) {
      this.currentState = this.history.pop();
    }
  }
}

const manager = new StateManager();
manager.setState({ count: 0 });
console.log(manager.getCurrentState()); // Output: { count: 0 }
manager.setState({ count: 1 });
console.log(manager.getCurrentState()); // Output: { count: 1 }
manager.undo();
console.log(manager.getCurrentState()); // Output: { count: 0 }
```

In this simplified JavaScript example, `StateManager` conceptually keeps track of state changes, similar to how `SnapshotTable` manages snapshots. However, `SnapshotTable` is implemented in C++ and used for internal compiler optimizations in V8.

**Code Logic Reasoning with Example:**

Let's consider the following part of the `BasicTest`:

```c++
  table.StartNewSnapshot();
  EXPECT_EQ(table.Get(k1), 1);
  table.Set(k1, 10);
  Snapshot s1 = table.Seal();

  table.StartNewSnapshot();
  EXPECT_EQ(table.Get(k1), 1); // Notice it's the initial value again
  table.Set(k1, 11);
  Snapshot s2 = table.Seal();

  table.StartNewSnapshot({s1, s2},
                         [&](Key key, base::Vector<const int> values) {
                           if (key == k1) {
                             EXPECT_EQ(values[0], 10); // Value from s1
                             EXPECT_EQ(values[1], 11); // Value from s2
                           }
                           return values[0] + values[1];
                         });
  EXPECT_EQ(table.Get(k1), 21);
```

**Assumptions:**

* `k1` is a key created earlier and initially associated with the value `1`.

**Input:**

* Snapshot `s1` where the value of `k1` is `10`.
* Snapshot `s2` where the value of `k1` is `11`.

**Process:**

1. A new snapshot is started, merging `s1` and `s2`.
2. The merge operation detects that the key `k1` has different values in the two snapshots.
3. The provided lambda function (the merge conflict resolver) is called for `k1`.
4. The `values` vector passed to the lambda contains:
   * `values[0]`: The value of `k1` in `s1` (which is `10`).
   * `values[1]`: The value of `k1` in `s2` (which is `11`).
5. The lambda function returns `values[0] + values[1]`, which is `10 + 11 = 21`.

**Output:**

* The value of `k1` in the newly created snapshot after the merge is `21`.

**Common Programming Errors and How `SnapshotTable` Might Help Avoid Them:**

A common programming error related to managing state is **unintended side effects or loss of history when modifying shared data**.

**Example of a potential error in a scenario without a system like `SnapshotTable`:**

Imagine a compiler optimization pass that modifies the intermediate representation (IR) of code. If this pass directly modifies the IR without preserving the original state, it can be difficult to:

1. **Debug issues:** If a bug is introduced by the optimization, it's hard to go back to the original IR to isolate the problem.
2. **Implement rollback or try different optimizations:**  It's challenging to easily revert the changes made by an optimization or explore alternative optimization strategies.

**How `SnapshotTable` can help:**

The `SnapshotTable` structure, as used in the V8 compiler, helps mitigate these issues by:

* **Explicitly creating snapshots:**  Before an optimization pass modifies data managed by the `SnapshotTable`, a snapshot can be taken. This preserves the original state.
* **Managing changes within snapshots:** Modifications are often made within the context of a new snapshot, allowing comparison with previous states.
* **Providing a mechanism for merging changes:**  When combining the results of different analyses or optimization passes, the merging capabilities of `SnapshotTable` allow for controlled integration of changes and conflict resolution.

**Illustrative (Conceptual) C++ Example of a potential error and how `SnapshotTable` could help:**

```c++
// Without a SnapshotTable-like structure (potential for errors)
struct CodeData {
  std::string ir;
};

void optimizeCode(CodeData& data) {
  std::string original_ir = data.ir; // Attempt to save, but manual
  // Perform optimizations, directly modifying data.ir
  data.ir = applyOptimization1(data.ir);
  data.ir = applyOptimization2(data.ir);
  // If an error occurs later, reverting to original_ir might be complex
}

// With a SnapshotTable-like structure (more robust)
#include "src/compiler/turboshaft/snapshot-table.h" // Assuming this header

namespace v8::internal::compiler::turboshaft {

void optimizeCodeWithSnapshotTable(SnapshotTable<std::string>& ir_table, SnapshotTable<std::string>::Key ir_key) {
  using Key = SnapshotTable<std::string>::Key;
  using Snapshot = SnapshotTable<std::string>::Snapshot;

  ir_table.StartNewSnapshot();
  Snapshot initial_snapshot = ir_table.Seal();

  ir_table.StartNewSnapshot(initial_snapshot);
  ir_table.Set(ir_key, applyOptimization1(ir_table.Get(ir_key)));
  ir_table.Set(ir_key, applyOptimization2(ir_table.Get(ir_key)));
  Snapshot optimized_snapshot = ir_table.Seal();

  // If needed, we can revert or compare snapshots
}

} // namespace v8::internal::compiler::turboshaft
```

In the "without" example, manual copying of the `ir` is prone to errors. The `SnapshotTable` approach provides a more structured and reliable way to manage the history and changes.

### 提示词
```
这是目录为v8/test/unittests/compiler/turboshaft/snapshot-table-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/turboshaft/snapshot-table-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/turboshaft/snapshot-table.h"

#include "src/base/vector.h"
#include "test/unittests/test-utils.h"

namespace v8::internal::compiler::turboshaft {

class SnapshotTableTest : public TestWithPlatform {};

TEST_F(SnapshotTableTest, BasicTest) {
  AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);

  using Key = SnapshotTable<int>::Key;
  using Snapshot = SnapshotTable<int>::Snapshot;

  SnapshotTable<int> table(&zone);

  Key k1 = table.NewKey(1);
  Key k2 = table.NewKey(2);
  Key k3 = table.NewKey(3);
  Key k4 = table.NewKey(4);

  table.StartNewSnapshot();
  EXPECT_EQ(table.Get(k1), 1);
  EXPECT_EQ(table.Get(k2), 2);
  EXPECT_EQ(table.Get(k3), 3);
  EXPECT_EQ(table.Get(k4), 4);
  table.Set(k1, 10);
  table.Set(k2, 20);
  table.Set(k4, 4);
  EXPECT_EQ(table.Get(k1), 10);
  EXPECT_EQ(table.Get(k2), 20);
  EXPECT_EQ(table.Get(k3), 3);
  EXPECT_EQ(table.Get(k4), 4);
  Snapshot s1 = table.Seal();

  table.StartNewSnapshot();
  EXPECT_EQ(table.Get(k1), 1);
  EXPECT_EQ(table.Get(k2), 2);
  EXPECT_EQ(table.Get(k3), 3);
  EXPECT_EQ(table.Get(k4), 4);
  table.Set(k1, 11);
  table.Set(k3, 33);
  EXPECT_EQ(table.Get(k1), 11);
  EXPECT_EQ(table.Get(k2), 2);
  EXPECT_EQ(table.Get(k3), 33);
  EXPECT_EQ(table.Get(k4), 4);
  Snapshot s2 = table.Seal();

  table.StartNewSnapshot(s2);
  // Assignments of the same value are ignored.
  EXPECT_EQ(table.Get(k1), 11);
  table.Set(k1, 11);
  // Sealing an empty snapshot does not produce a new snapshot.
  EXPECT_EQ(table.Seal(), s2);

  table.StartNewSnapshot({s1, s2},
                         [&](Key key, base::Vector<const int> values) {
                           if (key == k1) {
                             EXPECT_EQ(values[0], 10);
                             EXPECT_EQ(values[1], 11);
                           } else if (key == k2) {
                             EXPECT_EQ(values[0], 20);
                             EXPECT_EQ(values[1], 2);
                           } else if (key == k3) {
                             EXPECT_EQ(values[0], 3);
                             EXPECT_EQ(values[1], 33);
                           } else {
                             EXPECT_TRUE(false);
                           }
                           return values[0] + values[1];
                         });
  EXPECT_EQ(table.Get(k1), 21);
  EXPECT_EQ(table.Get(k2), 22);
  EXPECT_EQ(table.Get(k3), 36);
  EXPECT_EQ(table.Get(k4), 4);
  table.Set(k1, 40);
  EXPECT_EQ(table.Get(k1), 40);
  EXPECT_EQ(table.Get(k2), 22);
  EXPECT_EQ(table.Get(k3), 36);
  EXPECT_EQ(table.Get(k4), 4);
  EXPECT_EQ(table.GetPredecessorValue(k1, 0), 10);
  EXPECT_EQ(table.GetPredecessorValue(k1, 1), 11);
  EXPECT_EQ(table.GetPredecessorValue(k2, 0), 20);
  EXPECT_EQ(table.GetPredecessorValue(k2, 1), 2);
  EXPECT_EQ(table.GetPredecessorValue(k3, 0), 3);
  EXPECT_EQ(table.GetPredecessorValue(k3, 1), 33);
  table.Seal();

  table.StartNewSnapshot({s1, s2});
  EXPECT_EQ(table.Get(k1), 1);
  EXPECT_EQ(table.Get(k2), 2);
  EXPECT_EQ(table.Get(k3), 3);
  EXPECT_EQ(table.Get(k4), 4);
  table.Seal();

  table.StartNewSnapshot(s2);
  EXPECT_EQ(table.Get(k1), 11);
  EXPECT_EQ(table.Get(k2), 2);
  EXPECT_EQ(table.Get(k3), 33);
  EXPECT_EQ(table.Get(k4), 4);
  table.Set(k3, 30);
  EXPECT_EQ(table.Get(k3), 30);
  Snapshot s4 = table.Seal();

  table.StartNewSnapshot({s4, s2},
                         [&](Key key, base::Vector<const int> values) {
                           if (key == k3) {
                             EXPECT_EQ(values[0], 30);
                             EXPECT_EQ(values[1], 33);
                           } else {
                             EXPECT_TRUE(false);
                           }
                           return values[0] + values[1];
                         });
  EXPECT_EQ(table.Get(k1), 11);
  EXPECT_EQ(table.Get(k2), 2);
  EXPECT_EQ(table.Get(k3), 63);
  EXPECT_EQ(table.Get(k4), 4);
  EXPECT_EQ(table.GetPredecessorValue(k3, 0), 30);
  EXPECT_EQ(table.GetPredecessorValue(k3, 1), 33);
  table.Seal();

  table.StartNewSnapshot(s2);
  table.Set(k1, 5);
  // Creating a new key while the SnapshotTable is already in use. This is the
  // same as creating the key at the beginning.
  Key k5 = table.NewKey(-1);
  EXPECT_EQ(table.Get(k5), -1);
  table.Set(k5, 42);
  EXPECT_EQ(table.Get(k5), 42);
  EXPECT_EQ(table.Get(k1), 5);
  Snapshot s6 = table.Seal();

  // We're merging {s6} and {s1}, to make sure that {s1}'s behavior is correct
  // with regard to {k5}, which wasn't created yet when {s1} was sealed.
  table.StartNewSnapshot({s6, s1},
                         [&](Key key, base::Vector<const int> values) {
                           if (key == k1) {
                             EXPECT_EQ(values[1], 10);
                             EXPECT_EQ(values[0], 5);
                           } else if (key == k2) {
                             EXPECT_EQ(values[1], 20);
                             EXPECT_EQ(values[0], 2);
                           } else if (key == k3) {
                             EXPECT_EQ(values[1], 3);
                             EXPECT_EQ(values[0], 33);
                           } else if (key == k5) {
                             EXPECT_EQ(values[0], 42);
                             EXPECT_EQ(values[1], -1);
                             return 127;
                           } else {
                             EXPECT_TRUE(false);
                           }
                           return values[0] + values[1];
                         });
  EXPECT_EQ(table.Get(k1), 15);
  EXPECT_EQ(table.Get(k2), 22);
  EXPECT_EQ(table.Get(k3), 36);
  EXPECT_EQ(table.Get(k4), 4);
  EXPECT_EQ(table.Get(k5), 127);
  EXPECT_EQ(table.GetPredecessorValue(k1, 0), 5);
  EXPECT_EQ(table.GetPredecessorValue(k1, 1), 10);
  EXPECT_EQ(table.GetPredecessorValue(k2, 0), 2);
  EXPECT_EQ(table.GetPredecessorValue(k2, 1), 20);
  EXPECT_EQ(table.GetPredecessorValue(k3, 0), 33);
  EXPECT_EQ(table.GetPredecessorValue(k3, 1), 3);
  EXPECT_EQ(table.GetPredecessorValue(k5, 0), 42);
  EXPECT_EQ(table.GetPredecessorValue(k5, 1), -1);
  // We're not setting anything else, but the merges should produce entries in
  // the log.
  Snapshot s7 = table.Seal();

  table.StartNewSnapshot(s7);
  // We're checking that {s7} did indeed capture the merge entries, despite
  // that we didn't do any explicit Set.
  EXPECT_EQ(table.Get(k1), 15);
  EXPECT_EQ(table.Get(k2), 22);
  EXPECT_EQ(table.Get(k3), 36);
  EXPECT_EQ(table.Get(k4), 4);
  EXPECT_EQ(table.Get(k5), 127);
  table.Seal();
}

TEST_F(SnapshotTableTest, KeyData) {
  AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);

  struct Data {
    int x;
  };

  using STable = SnapshotTable<int, Data>;
  using Key = STable::Key;

  STable table(&zone);

  Key k1 = table.NewKey(Data{5}, 1);

  EXPECT_EQ(k1.data().x, 5);
}

TEST_F(SnapshotTableTest, ChangeCallback) {
  AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);

  SnapshotTable<int> table(&zone);
  using Key = decltype(table)::Key;
  using Snapshot = decltype(table)::Snapshot;

  Key k1 = table.NewKey(1);
  table.StartNewSnapshot();
  table.Set(k1, 5);
  Snapshot s1 = table.Seal();

  int invoked = 0;
  table.StartNewSnapshot({}, [&](Key key, int old_value, int new_value) {
    invoked++;
    EXPECT_EQ(key, k1);
    EXPECT_EQ(old_value, 5);
    EXPECT_EQ(new_value, 1);
  });
  EXPECT_EQ(invoked, 1);
  table.Set(k1, 7);
  Snapshot s2 = table.Seal();

  invoked = 0;
  table.StartNewSnapshot(
      {s1, s2},
      [&](Key key, base::Vector<const int> values) {
        EXPECT_EQ(key, k1);
        EXPECT_EQ(values[0], 5);
        EXPECT_EQ(values[1], 7);
        return 10;
      },
      [&](Key key, int old_value, int new_value) {
        // We are invoked twice because the table is rolled back first and then
        // merged. But the only important invariant we should rely on is that
        // the updates collectively transform the table into the new state.
        switch (invoked++) {
          case 0:
            EXPECT_EQ(key, k1);
            EXPECT_EQ(old_value, 7);
            EXPECT_EQ(new_value, 1);
            break;
          case 1:
            EXPECT_EQ(key, k1);
            EXPECT_EQ(old_value, 1);
            EXPECT_EQ(new_value, 10);
            break;
          default:
            UNREACHABLE();
        }
      });
  EXPECT_EQ(invoked, 2);
  EXPECT_EQ(table.Get(k1), 10);
}

TEST_F(SnapshotTableTest, ChangeTrackingSnapshotTable) {
  AccountingAllocator allocator;
  Zone zone(&allocator, ZONE_NAME);

  struct KeyData {
    int id;
  };

  struct Table : ChangeTrackingSnapshotTable<Table, bool, KeyData> {
    using ChangeTrackingSnapshotTable::ChangeTrackingSnapshotTable;
    std::set<int> active_keys;

    void OnNewKey(Key key, bool value) {
      if (value) {
        active_keys.insert(key.data().id);
      }
    }
    void OnValueChange(Key key, bool old_value, bool new_value) {
      if (old_value && !new_value) {
        active_keys.erase(key.data().id);
      } else if (!old_value && new_value) {
        active_keys.insert(key.data().id);
      }
    }
  } table(&zone);

  using Key = Table::Key;
  using Snapshot = Table::Snapshot;

  Key k1 = table.NewKey(KeyData{5}, true);
  Key k2 = table.NewKey(KeyData{7}, false);

  table.StartNewSnapshot();
  EXPECT_EQ(table.active_keys, std::set<int>({5}));
  table.Set(k2, true);
  EXPECT_EQ(table.active_keys, std::set<int>({5, 7}));
  Snapshot s1 = table.Seal();

  table.StartNewSnapshot();
  EXPECT_EQ(table.active_keys, std::set<int>({5}));
  table.Set(k1, false);
  EXPECT_EQ(table.active_keys, std::set<int>({}));
  table.Set(k2, true);
  EXPECT_EQ(table.active_keys, std::set<int>({7}));
  Snapshot s2 = table.Seal();

  table.StartNewSnapshot({s1, s2},
                         [&](Key key, base::Vector<const bool> values) {
                           EXPECT_EQ(values.size(), 2u);
                           return values[0] ^ values[1];
                         });
  EXPECT_EQ(table.active_keys, std::set<int>({5}));
  table.Seal();

  table.StartNewSnapshot({s1, s2},
                         [&](Key key, base::Vector<const bool> values) {
                           EXPECT_EQ(values.size(), 2u);
                           return values[0] || values[1];
                         });
  EXPECT_EQ(table.active_keys, std::set<int>({5, 7}));
  table.Seal();
}

}  // namespace v8::internal::compiler::turboshaft
```
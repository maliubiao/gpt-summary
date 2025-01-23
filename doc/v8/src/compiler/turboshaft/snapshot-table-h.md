Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Understand the Request:** The core request is to explain the functionality of `snapshot-table.h`. The request also has several specific constraints/questions:  Torque file extension, relationship to JavaScript, code logic examples, and common programming errors.

2. **Initial Scan for Key Information:**  I'd start by skimming the comments at the beginning of the file. These often provide a high-level overview. The first comment block clearly states the purpose: storing key-value mappings, creating efficient snapshots, and optimizing for switching between similar snapshots. The "Complexity" section also gives valuable hints about performance characteristics.

3. **Identify Core Data Structures and Classes:** Look for the primary classes defined in the header. In this case, `SnapshotTable`, `SnapshotTableKey`, `Snapshot`, and `MaybeSnapshot` stand out. The nested `LogEntry` and `SnapshotData` structures are also important.

4. **Analyze Each Class/Structure Individually:**

   * **`SnapshotTable`:** This is the central class. Its methods (`Get`, `Set`, `Seal`, `NewKey`, `StartNewSnapshot`, `GetPredecessorValue`) are the primary interface. The comments within the class definition provide details about each method's purpose. Pay attention to template parameters (`Value`, `KeyData`). The presence of `ChangeCallback` and `MergeFun` as template parameters is significant.

   * **`SnapshotTableKey`:** This class represents a key in the table. The fact that it holds a pointer to a `SnapshotTableEntry` is crucial for understanding its identity-based nature.

   * **`Snapshot` and `MaybeSnapshot`:** These classes are directly related to the snapshotting mechanism. The comments explain that `Snapshot` is a lightweight handle to internal data. `MaybeSnapshot` is a utility for potentially having a snapshot.

   * **`SnapshotTableEntry`:**  This structure holds the actual key-value pair and additional metadata related to merging. The `merge_offset` and `last_merged_predecessor` members are key for understanding the merging logic.

   * **`LogEntry` and `SnapshotData`:** These internal structures support the snapshot implementation. `LogEntry` tracks changes, and `SnapshotData` stores metadata about each snapshot. The `CommonAncestor` method in `SnapshotData` is a strong clue about how snapshot relationships are managed.

5. **Focus on the Snapshotting Mechanism:**  The core innovation here is the snapshotting. Carefully read the comments around `StartNewSnapshot`, `Seal`, `RevertCurrentSnapshot`, and `ReplaySnapshot`. The description of how snapshots are based on predecessors and how merging works is vital. The example scenario with S0-S6 is very helpful for visualizing the process.

6. **Address the Specific Questions:**

   * **Torque:** The file extension is `.h`, so it's a C++ header, *not* a Torque file. Explicitly state this.
   * **JavaScript Relationship:**  Consider *why* V8 needs such a data structure. Think about the core functionality of a JavaScript engine: managing object properties, function scopes, etc. The snapshot table likely helps manage state during compilation and optimization. A JavaScript example demonstrating the *need* for such a mechanism in a complex engine (though not directly using the C++ class) is appropriate. Think about nested scopes and how variable values might change.
   * **Code Logic Inference:**  Choose a relatively simple but illustrative scenario. The `StartNewSnapshot` with merging is a good candidate. Define clear inputs (snapshots, a merge function) and explain the expected output (how the table state changes).
   * **Common Programming Errors:**  Think about typical mistakes when dealing with state management and snapshots. Forgetting to `Seal`, using a snapshot after sealing, and incorrect merging logic are good examples.

7. **Review and Refine:**  Read through the entire explanation. Ensure clarity, accuracy, and completeness. Check if all parts of the request have been addressed. Improve the flow and organization. For example, group related concepts together.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the `KeyData` is just for storing extra information.
* **Correction:** Realize the comment about "empty-base optimization" implies it's a way to avoid extra overhead when `KeyData` is empty.
* **Initial thought:**  Focus on the individual methods.
* **Correction:**  Shift to understanding the *interaction* between the methods, especially the snapshot lifecycle (`StartNewSnapshot` -> `Set` -> `Seal`).
* **Initial thought:**  The JavaScript example should directly map to the C++ code.
* **Correction:**  Recognize that the C++ code is an *implementation detail* within V8. The JavaScript example should illustrate the *problem* the C++ code solves at a higher level.

By following these steps and continuously refining the understanding, a comprehensive and accurate explanation of the `snapshot-table.h` file can be constructed.
这个C++头文件 `v8/src/compiler/turboshaft/snapshot-table.h` 定义了一个名为 `SnapshotTable` 的模板类，用于高效地存储键值对映射并创建快照。其主要功能可以概括如下：

**核心功能：高效的键值对存储和快照管理**

1. **键值对存储:** `SnapshotTable` 维护着一个键值对的集合。可以通过 `Set()` 方法设置键的值，通过 `Get()` 方法获取键的值。
2. **快照创建:** 允许创建当前状态的快照 (Snapshot)。快照是指向内部数据的轻量级指针，拷贝成本很低。
3. **快照回滚/切换:** 可以基于一个或多个父快照创建新的快照。在多个父快照的情况下，会执行合并操作来统一不同父快照中的值。
4. **高效的状态切换:** 针对在相似快照之间切换的场景进行了优化，特别是那些具有最近公共祖先的快照。
5. **合并操作:** 当基于多个父快照创建新快照时，可以通过提供一个合并函数 (`MergeFun`) 来定义如何合并在不同父快照中对同一键设置的不同值。
6. **变更通知:** 在切换快照和合并过程中，可以注册一个回调函数 (`ChangeCallback`)，以便在键值对发生变化时得到通知。这对于维护与主表同步的辅助索引非常有用。

**详细功能拆解：**

* **`SnapshotTable<Value, KeyData>` 类:**
    * **`Get(Key key)`:**  获取给定 `key` 对应的 `Value`。
    * **`Set(Key key, Value new_value)`:** 设置给定 `key` 的 `Value`。如果新值与旧值不同，则会记录到日志中。
    * **`Seal()`:** 封闭当前快照。封闭后，不能再修改该快照，并且会进行一些优化，例如当快照没有发生任何变化时，会丢弃该快照并使用其父快照。
    * **`NewKey(KeyData data, Value initial_value = Value{})`:** 创建一个新的键，并可以关联额外的数据 `KeyData` 和初始值 `initial_value`。 键具有唯一性。
    * **`StartNewSnapshot(...)`:**  启动一个新的快照。可以基于无父快照、单个父快照或多个父快照创建。如果提供多个父快照，还可以指定合并函数。
    * **`GetPredecessorValue(Key key, int predecessor_index)`:** 获取指定 `key` 在其第 `predecessor_index` 个父快照中的值。这个方法通常在执行了合并操作后使用。

* **`SnapshotTableKey<Value, KeyData>` 类:**
    * 表示 `SnapshotTable` 中的一个键。
    * 通过指针指向 `SnapshotTableEntry`，因此具有身份特性（identity）。
    * 可以访问关联的 `KeyData`。

* **`Snapshot` 类:**
    * 表示 `SnapshotTable` 的一个快照状态。
    * 是指向内部 `SnapshotData` 的指针，拷贝成本低。

* **`MaybeSnapshot` 类:**
    * 一个可能包含快照的包装器。

* **`SnapshotTableEntry<Value, KeyData>` 结构体:**
    * 存储实际的键值对 (`value`) 以及与键关联的额外数据 (`KeyData`)。
    * 包含用于合并操作的元数据 (`merge_offset`, `last_merged_predecessor`)。

* **`LogEntry` 结构体:**
    * 记录了对 `SnapshotTable` 的修改操作，包括被修改的条目、旧值和新值。

* **`SnapshotData` 结构体:**
    * 存储关于快照的元数据，例如父快照、日志的起始和结束位置等。
    * 包含用于查找最近公共祖先的方法 `CommonAncestor()`。

* **`ChangeTrackingSnapshotTable` 类:**
    * 继承自 `SnapshotTable`，并提供在表状态改变时自动调用 `OnNewKey` 和 `OnValueChange` 方法的能力。这使得更容易维护与 `SnapshotTable` 同步的辅助数据结构。

**关于问题中的其他点：**

* **`.tq` 结尾:** `v8/src/compiler/turboshaft/snapshot-table.h` 以 `.h` 结尾，表明它是一个 **C++ 头文件**。如果以 `.tq` 结尾，则它会是一个 **V8 Torque 源代码**。 Torque 是一种用于编写 V8 内部代码的领域特定语言，它能够生成 C++ 代码。

* **与 JavaScript 的功能关系:**  `SnapshotTable` 主要用于 V8 编译器的 Turboshaft 管道中，用于管理编译器在执行优化和生成代码时的状态。虽然它本身不是直接暴露给 JavaScript 的 API，但它支撑着 V8 执行 JavaScript 代码的功能。

    **JavaScript 例子 (说明概念，并非直接使用该 C++ 类):**

    想象一个 JavaScript 函数，在执行过程中会创建和修改局部变量：

    ```javascript
    function example() {
      let x = 10;
      console.log(x); // 输出 10

      if (true) {
        let x = 20;
        console.log(x); // 输出 20
      }

      console.log(x); // 输出 10
    }

    example();
    ```

    在 V8 编译和执行这个函数时，需要跟踪变量 `x` 在不同作用域内的值。`SnapshotTable` 这样的数据结构可以帮助编译器有效地管理不同执行阶段的状态，例如：

    * **进入新的作用域 (if 块):** 可以创建一个新的快照，记录当前变量的值。
    * **在作用域内修改变量:** 更新当前快照中的值。
    * **退出作用域:** 可以回滚到之前的快照，恢复外部作用域的变量值。

    虽然 JavaScript 开发者不会直接操作 `SnapshotTable`，但 V8 引擎内部使用它来确保代码的正确执行和进行各种优化。

* **代码逻辑推理 (假设输入与输出):**

    假设我们有一个 `SnapshotTable<int>` 实例，并执行以下操作：

    ```c++
    #include "src/compiler/turboshaft/snapshot-table.h"
    #include "src/zone/zone.h"
    #include <iostream>

    using namespace v8::internal;
    using namespace v8::internal::compiler::turboshaft;

    int main() {
      Zone zone;
      SnapshotTable<int> table(&zone);

      auto key1 = table.NewKey();
      auto key2 = table.NewKey();

      // 初始状态
      table.StartNewSnapshot();
      table.Set(key1, 1);
      table.Seal();
      Snapshot s1 = table.Seal(); // 实际上 Seal() 会返回当前的快照

      // 基于 s1 创建新的快照
      table.StartNewSnapshot(s1);
      table.Set(key1, 2);
      table.Set(key2, 3);
      table.Seal();
      Snapshot s2 = table.Seal();

      // 基于 s1 创建另一个新的快照
      table.StartNewSnapshot(s1);
      table.Set(key2, 4);
      table.Seal();
      Snapshot s3 = table.Seal();

      // 基于 s2 和 s3 合并创建新的快照
      auto merge_fn = [](SnapshotTable<int>::Key key, base::Vector<const int> values) {
        if (values.length() == 2) {
          return values[0] + values[1]; // 将两个父快照的值相加
        }
        return 0; // 默认值
      };

      table.StartNewSnapshot({s2, s3}, merge_fn);
      int merged_value_key1 = table.Get(key1); // key1 在 s2 中是 2，在 s3 中是 1 (继承自 s1) => 2 + 1 = 3
      int merged_value_key2 = table.Get(key2); // key2 在 s2 中是 3，在 s3 中是 4 => 3 + 4 = 7
      table.Seal();

      std::cout << "Merged value for key1: " << merged_value_key1 << std::endl; // 输出: Merged value for key1: 3
      std::cout << "Merged value for key2: " << merged_value_key2 << std::endl; // 输出: Merged value for key2: 7

      return 0;
    }
    ```

* **用户常见的编程错误:**

    1. **忘记 `Seal()` 快照:**  在 `StartNewSnapshot()` 之后，必须调用 `Seal()` 来完成快照的创建。如果忘记 `Seal()`，后续的 `StartNewSnapshot()` 调用可能会导致断言失败或未定义的行为。

    ```c++
    // 错误示例
    table.StartNewSnapshot();
    table.Set(key1, 1);
    // 忘记调用 table.Seal();
    table.StartNewSnapshot(); // 可能会出错
    ```

    2. **在 `Seal()` 之后修改快照:** 一旦快照被 `Seal()`，就不应该再对其进行修改（例如通过 `Set()`）。尝试这样做可能会导致程序崩溃或数据不一致。

    ```c++
    table.StartNewSnapshot();
    table.Set(key1, 1);
    Snapshot s = table.Seal();
    // 错误：尝试修改已封闭的快照（实际上是通过新的快照修改底层数据）
    table.StartNewSnapshot(s);
    table.Set(key1, 2);
    table.Seal();
    ```

    3. **不理解合并逻辑:** 在使用多个父快照创建新快照时，如果提供了错误的或不完善的 `merge_fn`，可能会导致合并后的值不符合预期。

    ```c++
    // 可能错误的合并逻辑，只返回第一个父快照的值
    auto bad_merge_fn = [](SnapshotTable<int>::Key key, base::Vector<const int> values) {
      if (values.length() > 0) {
        return values[0];
      }
      return 0;
    };
    ```

    4. **在没有启动快照的情况下使用 `Set()`:**  虽然 `Set()` 方法本身可以调用，但其效果会受到当前是否处于活跃快照的影响。最佳实践是在 `StartNewSnapshot()` 和 `Seal()` 之间执行修改操作。

    5. **混淆快照的引用:** 快照是轻量级的，但它们指向底层的状态。不小心覆盖或错误地使用快照变量可能会导致逻辑错误。

总而言之，`v8/src/compiler/turboshaft/snapshot-table.h` 定义的 `SnapshotTable` 类是 V8 编译器中用于高效管理和切换状态的关键数据结构，它通过快照机制优化了状态的存储和回溯。虽然 JavaScript 开发者不会直接使用它，但它的存在对于 V8 引擎的编译和优化至关重要。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/snapshot-table.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/snapshot-table.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_TURBOSHAFT_SNAPSHOT_TABLE_H_
#define V8_COMPILER_TURBOSHAFT_SNAPSHOT_TABLE_H_

#include <iostream>
#include <limits>

#include "src/base/iterator.h"
#include "src/base/small-vector.h"
#include "src/compiler/turboshaft/fast-hash.h"
#include "src/zone/zone-containers.h"

// A `SnapshotTable` stores a mapping from keys to values and creates snapshots,
// which capture the current state efficiently and allow us to return to a
// previous snapshot later. It is optimized for the case where we switch between
// similar snapshots with a closeby common ancestor.
//
// Complexity:
//   creating a snapshot   linear in the number of `Set` operations between the
//                         current state and the common ancestor of all
//                         predecessors and the current state, plus the `Set`
//                         operations from the common ancestor to all
//                         predecessors.
//   Get()                      O(1)
//   Set()                      O(1) + operator== for Value
//   Seal()                     O(1)
//   NewKey()                   O(1)
//   GetPredecessorValue()      O(1)
namespace v8::internal::compiler::turboshaft {

struct NoKeyData {};

struct NoChangeCallback {
  template <class Key, class Value>
  void operator()(Key key, const Value& old_value,
                  const Value& new_value) const {}
};

template <class Value, class KeyData>
class SnapshotTable;

// Place `KeyData` in a superclass to benefit from empty-base optimization.
template <class Value, class KeyData>
struct SnapshotTableEntry : KeyData {
  Value value;
  // `merge_offset` is the offset in `merge_values_` where we store the
  // merged values. It is used during merging (to know what to merge) and when
  // calling GetPredecessorValue.
  uint32_t merge_offset = kNoMergeOffset;
  // Used during merging: the index of the predecessor for which we last
  // recorded a value. This allows us to only use the last value for a given
  // predecessor and skip over all earlier ones.
  uint32_t last_merged_predecessor = kNoMergedPredecessor;

  explicit SnapshotTableEntry(Value value, KeyData data)
      : KeyData(std::move(data)), value(std::move(value)) {}

  static constexpr uint32_t kNoMergeOffset =
      std::numeric_limits<uint32_t>::max();
  static constexpr uint32_t kNoMergedPredecessor =
      std::numeric_limits<uint32_t>::max();
};

// A `SnapshotTableKey` identifies an entry in the `SnapshotTable`. For better
// performance, keys always have identity. The template parameter `KeyData` can
// be used to embed additional data in the keys. A Key is implemented as a
// pointer into the table, which also contains the `KeyData`. Therefore, keys
// have pointer-size and are cheap to copy.
template <class Value, class KeyData>
class SnapshotTableKey {
 public:
  bool operator==(SnapshotTableKey other) const {
    return entry_ == other.entry_;
  }
  const KeyData& data() const { return *entry_; }
  KeyData& data() { return *entry_; }
  SnapshotTableKey() : entry_(nullptr) {}

  bool valid() const { return entry_ != nullptr; }

 private:
  friend class SnapshotTable<Value, KeyData>;
  SnapshotTableEntry<Value, KeyData>* entry_;
  explicit SnapshotTableKey(SnapshotTableEntry<Value, KeyData>& entry)
      : entry_(&entry) {}
};

template <class Value, class KeyData = NoKeyData>
class SnapshotTable {
 private:
  struct LogEntry;
  struct SnapshotData;

 public:
  using TableEntry = SnapshotTableEntry<Value, KeyData>;
  using Key = SnapshotTableKey<Value, KeyData>;

  // A `Snapshot` captures the state of the `SnapshotTable`.
  // A `Snapshot` is implemented as a pointer to internal data and is therefore
  // cheap to copy.
  class MaybeSnapshot;
  class Snapshot {
   public:
    bool operator==(Snapshot other) const { return data_ == other.data_; }

   private:
    friend SnapshotTable;
    friend MaybeSnapshot;

    SnapshotData* data_;
    explicit Snapshot(SnapshotData& data) : data_(&data) {}
    explicit Snapshot(SnapshotData* data) : data_(data) {}
  };

  class MaybeSnapshot {
   public:
    bool has_value() const { return data_ != nullptr; }
    Snapshot value() const {
      DCHECK(has_value());
      return Snapshot{data_};
    }

    void Set(Snapshot snapshot) { data_ = snapshot.data_; }

    MaybeSnapshot() = default;
    explicit MaybeSnapshot(Snapshot snapshot) : data_(snapshot.data_) {}

   private:
    SnapshotData* data_ = nullptr;
  };

  // A new Snapshot is based on a list of predecessor Snapshots. If no
  // predecessor is given, the new Snapshot is based on the initial state of the
  // table. A single predecessor Snapshot resets the table to exactly this
  // Snapshot. In the case of multiple Snapshots, a merge function is used to
  // unify values that were set since the last common ancestor snapshot.
  // The previous Snapshot needs to be closed using Seal() before another one
  // can be created.
  // The function `change_callback` is invoked for every atomic update to a
  // table entry as part of switching to the new snapshot and merging.
  // Note that the callback might be invoked multiple times for the same key,
  // because we first roll-back changes to the common ancestor and then apply
  // the merge function. The second update will have the new value of the first
  // update as old value. We should not rely on the exact sequence of updates,
  // only on the fact that the updates collectively transform the table into the
  // new state. The motivation for this feature are secondary indices that need
  // to be kept in sync with the main table.
  template <class ChangeCallback = NoChangeCallback,
            std::enable_if_t<std::is_invocable_v<ChangeCallback, Key, Value,
                                                 Value>>* = nullptr>
  void StartNewSnapshot(base::Vector<const Snapshot> predecessors,
                        const ChangeCallback& change_callback = {}) {
    DCHECK(current_snapshot_->IsSealed());
    MoveToNewSnapshot(predecessors, change_callback);
#ifdef DEBUG
    snapshot_was_created_with_merge = false;
#endif
  }
  template <class ChangeCallback = NoChangeCallback,
            std::enable_if_t<std::is_invocable_v<ChangeCallback, Key, Value,
                                                 Value>>* = nullptr>
  void StartNewSnapshot(std::initializer_list<Snapshot> predecessors = {},
                        const ChangeCallback& change_callback = {}) {
    StartNewSnapshot(base::VectorOf(predecessors), change_callback);
  }
  template <class ChangeCallback = NoChangeCallback,
            std::enable_if_t<std::is_invocable_v<ChangeCallback, Key, Value,
                                                 Value>>* = nullptr>
  void StartNewSnapshot(Snapshot parent,
                        const ChangeCallback& change_callback = {}) {
    StartNewSnapshot({parent}, change_callback);
  }
  template <
      class MergeFun, class ChangeCallback = NoChangeCallback,
      std::enable_if_t<
          std::is_invocable_v<MergeFun, Key, base::Vector<const Value>> &&
          std::is_invocable_v<ChangeCallback, Key, Value, Value>>* = nullptr>
  void StartNewSnapshot(base::Vector<const Snapshot> predecessors,
                        const MergeFun& merge_fun,
                        const ChangeCallback& change_callback = {}) {
    StartNewSnapshot(predecessors, change_callback);
    MergePredecessors(predecessors, merge_fun, change_callback);
#ifdef DEBUG
    snapshot_was_created_with_merge = true;
#endif
  }
  template <
      class MergeFun, class ChangeCallback = NoChangeCallback,
      std::enable_if_t<
          std::is_invocable_v<MergeFun, Key, base::Vector<const Value>> &&
          std::is_invocable_v<ChangeCallback, Key, Value, Value>>* = nullptr>
  void StartNewSnapshot(std::initializer_list<Snapshot> predecessors,
                        const MergeFun& merge_fun,
                        const ChangeCallback& change_callback = {}) {
    StartNewSnapshot(base::VectorOf(predecessors), merge_fun, change_callback);
  }

  Snapshot Seal() {
    current_snapshot_->Seal(log_.size());
    // Reseting the entries' `merge_offset` and `last_merged_predecessor`
    // fields, so that they are cleared for the next Merge.
    for (TableEntry* entry : merging_entries_) {
      entry->last_merged_predecessor = kNoMergedPredecessor;
      entry->merge_offset = kNoMergeOffset;
    }
    merge_values_.clear();
    merging_entries_.clear();

    // Optimization: If nothing changed in the new snapshot, we discard it and
    // use its parent instead.
    if (current_snapshot_->log_begin == current_snapshot_->log_end) {
      SnapshotData* parent = current_snapshot_->parent;
      DCHECK_EQ(current_snapshot_, &snapshots_.back());
      snapshots_.pop_back();
      current_snapshot_ = parent;
      return Snapshot{*parent};
    }
    return Snapshot{*current_snapshot_};
  }

  const Value& Get(Key key) const { return key.entry_->value; }

  // Returns the value associated to {key} in its {predecessor_index}th
  // predecessor (where "predecessor" refers to the predecessors that were
  // passed to StartNewSnapshot when creating the current snapshot).
  // This function should only be used if the snapshot was started with a merge
  // function.
  // If {key} wasn't merged but was Set in the current snapshot, then
  // the newly set value will be returned rather than the predecessor value.
  const Value& GetPredecessorValue(Key key, int predecessor_index) {
    DCHECK(!current_snapshot_->IsSealed());
    DCHECK(snapshot_was_created_with_merge);
    if (key.entry_->merge_offset == kNoMergeOffset) return Get(key);
    return merge_values_[key.entry_->merge_offset + predecessor_index];
  }

  // {Set} returns whether the {new_value} is different from the previous value.
  bool Set(Key key, Value new_value) {
    DCHECK(!current_snapshot_->IsSealed());
    if (key.entry_->value == new_value) return false;
    log_.push_back(LogEntry{*key.entry_, key.entry_->value, new_value});
    key.entry_->value = new_value;
    return true;
  }

  explicit SnapshotTable(Zone* zone) : zone_(zone) {
    root_snapshot_ = &NewSnapshot(nullptr);
    root_snapshot_->Seal(0);
    current_snapshot_ = root_snapshot_;
  }

  // The initial value is independent of the snapshot mechanism. Creating a key
  // with a certain initial value later has the same effect as creating the key
  // before all modifications to the table.
  // Keys have identity, and the data embedded in the key is mutable.
  Key NewKey(KeyData data, Value initial_value = Value{}) {
    return Key{table_.emplace_back(
        TableEntry{std::move(initial_value), std::move(data)})};
  }
  Key NewKey(Value initial_value = Value{}) {
    return NewKey(KeyData{}, initial_value);
  }

  // Returns true if {current_snapshot_} is sealed.
  bool IsSealed() { return current_snapshot_->IsSealed(); }

 private:
  Zone* zone_;
  ZoneDeque<TableEntry> table_{zone_};
  ZoneDeque<SnapshotData> snapshots_{zone_};
  // While logically each snapshot has its own log, we allocate the memory as a
  // single global log with each snapshot pointing to a section of it to reduce
  // the number of allocations.
  ZoneVector<LogEntry> log_{zone_};
  SnapshotData* root_snapshot_;
  SnapshotData* current_snapshot_;

  // The following members are only used temporarily during a merge operation
  // or when creating a new snapshot.
  // They are declared here to recycle the memory, avoiding repeated
  // Zone-allocation.
  ZoneVector<TableEntry*> merging_entries_{zone_};
  ZoneVector<Value> merge_values_{zone_};
  ZoneVector<SnapshotData*> path_{zone_};

#ifdef DEBUG
  bool snapshot_was_created_with_merge = false;
#endif

  SnapshotData& NewSnapshot(SnapshotData* parent) {
    return snapshots_.emplace_back(parent, log_.size());
  }

  base::Vector<LogEntry> LogEntries(SnapshotData* s) {
    return base::VectorOf(&log_[s->log_begin], s->log_end - s->log_begin);
  }

  template <class ChangeCallback = NoChangeCallback>
  void RevertCurrentSnapshot(ChangeCallback& change_callback) {
    DCHECK(current_snapshot_->IsSealed());
    base::Vector<LogEntry> log_entries = LogEntries(current_snapshot_);
    for (const LogEntry& entry : base::Reversed(log_entries)) {
      DCHECK_EQ(entry.table_entry.value, entry.new_value);
      DCHECK_NE(entry.new_value, entry.old_value);
      change_callback(Key{entry.table_entry}, entry.new_value, entry.old_value);
      entry.table_entry.value = entry.old_value;
    }
    current_snapshot_ = current_snapshot_->parent;
    DCHECK_NOT_NULL(current_snapshot_);
  }

  template <class ChangeCallback = NoChangeCallback>
  void ReplaySnapshot(SnapshotData* snapshot, ChangeCallback& change_callback) {
    DCHECK_EQ(snapshot->parent, current_snapshot_);
    for (const LogEntry& entry : LogEntries(snapshot)) {
      DCHECK_EQ(entry.table_entry.value, entry.old_value);
      DCHECK_NE(entry.new_value, entry.old_value);
      change_callback(Key{entry.table_entry}, entry.old_value, entry.new_value);
      entry.table_entry.value = entry.new_value;
    }
    current_snapshot_ = snapshot;
  }

  void RecordMergeValue(TableEntry& entry, const Value& value,
                        uint32_t predecessor_index, uint32_t predecessor_count);
  template <class ChangeCallback>
  SnapshotData& MoveToNewSnapshot(base::Vector<const Snapshot> predecessors,
                                  const ChangeCallback& change_callback);
  template <class MergeFun, class ChangeCallback>
  void MergePredecessors(base::Vector<const Snapshot> predecessors,
                         const MergeFun& merge_fun,
                         const ChangeCallback& change_callback);

  static constexpr uint32_t kNoMergeOffset =
      std::numeric_limits<uint32_t>::max();
  static constexpr uint32_t kNoMergedPredecessor =
      std::numeric_limits<uint32_t>::max();
};

template <class Value, class KeyData>
struct SnapshotTable<Value, KeyData>::LogEntry {
  TableEntry& table_entry;
  Value old_value;
  Value new_value;
};

template <class Value, class KeyData>
struct SnapshotTable<Value, KeyData>::SnapshotData {
  SnapshotData* parent;

  const uint32_t depth = parent ? parent->depth + 1 : 0;
  size_t log_begin;
  size_t log_end = kInvalidOffset;

  static constexpr size_t kInvalidOffset = std::numeric_limits<size_t>::max();

  SnapshotData(SnapshotData* parent, size_t log_begin)
      : parent(parent), log_begin(log_begin) {}

  SnapshotData* CommonAncestor(SnapshotData* other) {
    SnapshotData* self = this;
    while (other->depth > self->depth) other = other->parent;
    while (self->depth > other->depth) self = self->parent;
    while (other != self) {
      self = self->parent;
      other = other->parent;
    }
    return self;
  }
  void Seal(size_t log_end) {
    DCHECK_WITH_MSG(!IsSealed(), "A Snapshot can only be sealed once");
    this->log_end = log_end;
  }

  bool IsSealed() const { return log_end != kInvalidOffset; }
};

template <class Value, class KeyData>
void SnapshotTable<Value, KeyData>::RecordMergeValue(
    TableEntry& entry, const Value& value, uint32_t predecessor_index,
    uint32_t predecessor_count) {
  if (predecessor_index == entry.last_merged_predecessor) {
    DCHECK_NE(entry.merge_offset, kNoMergeOffset);
    // We already recorded a later value for this predecessor, so we should skip
    // earlier values.
    return;
  }
  if (entry.merge_offset == kNoMergeOffset) {
    // Allocate space for the merge values. All the merge values are initialized
    // to the value from the parent snapshot. This way, we get the right value
    // for predecessors that did not change the value.
    DCHECK_EQ(entry.last_merged_predecessor, kNoMergedPredecessor);
    CHECK_LE(merge_values_.size() + predecessor_count,
             std::numeric_limits<uint32_t>::max());
    entry.merge_offset = static_cast<uint32_t>(merge_values_.size());
    merging_entries_.push_back(&entry);
    merge_values_.insert(merge_values_.end(), predecessor_count, entry.value);
  }
  merge_values_[entry.merge_offset + predecessor_index] = value;
  entry.last_merged_predecessor = predecessor_index;
}

// This function prepares the SnapshotTable to start a new snapshot whose
// predecessors are `predecessors`. To do this, it resets and replay snapshots
// in between the `current_snapshot_` and the position of the new snapshot. For
// instance:
//
//        S0
//      /    \
//     S1      S3
//     |         \
//     S2         S4
//               /  \
//              S5   S6
// If `predecessors` are S5 and S6, and `current_snapshot_` is S2, we:
//
// - First find the common ancestor of S5 and S6 (it's S4). This will be the
//   parent snapshot of the new snapshot.
// - Find the common ancestor of S4 and the current snapshot S2 (it's S0).
// - Roll back S2 and S1 to reach S0
// - Replay S3 and S4 go be in the state of S4 (the common ancestor of
//   `predecessors`).
// - Start creating a new snapshot with parent S4.
template <class Value, class KeyData>
template <class ChangeCallback>
typename SnapshotTable<Value, KeyData>::SnapshotData&
SnapshotTable<Value, KeyData>::MoveToNewSnapshot(
    base::Vector<const Snapshot> predecessors,
    const ChangeCallback& change_callback) {
  DCHECK_WITH_MSG(
      current_snapshot_->IsSealed(),
      "A new Snapshot was opened before the previous Snapshot was sealed");

  SnapshotData* common_ancestor;
  if (predecessors.empty()) {
    common_ancestor = root_snapshot_;
  } else {
    common_ancestor = predecessors.first().data_;
    for (Snapshot s : predecessors.SubVectorFrom(1)) {
      common_ancestor = common_ancestor->CommonAncestor(s.data_);
    }
  }
  SnapshotData* go_back_to = common_ancestor->CommonAncestor(current_snapshot_);
  while (current_snapshot_ != go_back_to) {
    RevertCurrentSnapshot(change_callback);
  }
  {
    // Replay to common_ancestor.
    path_.clear();
    for (SnapshotData* s = common_ancestor; s != go_back_to; s = s->parent) {
      path_.push_back(s);
    }
    for (SnapshotData* s : base::Reversed(path_)) {
      ReplaySnapshot(s, change_callback);
    }
  }

  DCHECK_EQ(current_snapshot_, common_ancestor);
  SnapshotData& new_snapshot = NewSnapshot(common_ancestor);
  current_snapshot_ = &new_snapshot;
  return new_snapshot;
}

// Merges all entries modified in `predecessors` since the last common ancestor
// by adding them to the current snapshot.
template <class Value, class KeyData>
template <class MergeFun, class ChangeCallback>
void SnapshotTable<Value, KeyData>::MergePredecessors(
    base::Vector<const Snapshot> predecessors, const MergeFun& merge_fun,
    const ChangeCallback& change_callback) {
  CHECK_LE(predecessors.size(), std::numeric_limits<uint32_t>::max());
  uint32_t predecessor_count = static_cast<uint32_t>(predecessors.size());
  if (predecessor_count < 1) return;

  // The merging works by reserving `predecessor_count` many slots in
  // `merge_values_` for every key that we find while going through the
  // predecessor logs. There, we place the values of the corresponding
  // predecessors, so that we can finally call the `merge_fun` by creating a
  // `base::Vector` pointing to the collected values inside of `merge_values_`.
  DCHECK(merge_values_.empty());
  DCHECK(merging_entries_.empty());
  SnapshotData* common_ancestor = current_snapshot_->parent;

  // Collect all the entries that require merging. For this, we walk the logs of
  // the predecessors backwards until reaching the common ancestor.
  for (uint32_t i = 0; i < predecessor_count; ++i) {
    for (SnapshotData* predecessor = predecessors[i].data_;
         predecessor != common_ancestor; predecessor = predecessor->parent) {
      base::Vector<LogEntry> log_entries = LogEntries(predecessor);
      for (const LogEntry& entry : base::Reversed(log_entries)) {
        RecordMergeValue(entry.table_entry, entry.new_value, i,
                         predecessor_count);
      }
    }
  }
  // Actually perform the merging by calling the merge function and modifying
  // the table.
  for (TableEntry* entry : merging_entries_) {
    Key key{*entry};
    Value value = merge_fun(
        key, base::VectorOf<const Value>(&merge_values_[entry->merge_offset],
                                         predecessor_count));
    Value old_value = entry->value;
    if (Set(key, std::move(value))) {
      change_callback(key, old_value, entry->value);
    }
  }
}

// ChangeTrackingSnapshotTable extends SnapshotTable by automatically invoking
// OnNewKey and OnValueChange on the subclass whenever the table state changes.
// This makes it easy to maintain consistent additional tables for faster lookup
// of the state of the snapshot table, similar to how secondary indices can
// speed-up lookups in database tables.
// For example usage, see TEST_F(SnapshotTableTest, ChangeTrackingSnapshotTable)
// in test/unittests/compiler/turboshaft/snapshot-table-unittest.cc.
template <class Derived, class Value, class KeyData = NoKeyData>
class ChangeTrackingSnapshotTable : public SnapshotTable<Value, KeyData> {
 public:
  using Super = SnapshotTable<Value, KeyData>;
  using Super::Super;
  using typename Super::Key;
  using typename Super::Snapshot;

  void StartNewSnapshot(base::Vector<const Snapshot> predecessors) {
    Super::StartNewSnapshot(
        predecessors,
        [this](Key key, const Value& old_value, const Value& new_value) {
          static_cast<Derived*>(this)->OnValueChange(key, old_value, new_value);
        });
  }
  void StartNewSnapshot(std::initializer_list<Snapshot> predecessors = {}) {
    StartNewSnapshot(base::VectorOf(predecessors));
  }
  void StartNewSnapshot(Snapshot parent) { StartNewSnapshot({parent}); }
  template <class MergeFun,
            std::enable_if_t<std::is_invocable_v<
                MergeFun, Key, base::Vector<const Value>>>* = nullptr>
  void StartNewSnapshot(base::Vector<const Snapshot> predecessors,
                        const MergeFun& merge_fun) {
    Super::StartNewSnapshot(
        predecessors, merge_fun,
        [this](Key key, const Value& old_value, const Value& new_value) {
          static_cast<Derived*>(this)->OnValueChange(key, old_value, new_value);
        });
  }
  template <class MergeFun,
            std::enable_if_t<std::is_invocable_v<
                MergeFun, Key, base::Vector<const Value>>>* = nullptr>
  void StartNewSnapshot(std::initializer_list<Snapshot> predecessors,
                        const MergeFun& merge_fun) {
    StartNewSnapshot(base::VectorOf(predecessors), merge_fun);
  }

  void Set(Key key, Value new_value) {
    Value old_value = Super::Get(key);
    if (Super::Set(key, std::move(new_value))) {
      static_cast<Derived*>(this)->OnValueChange(key, old_value,
                                                 Super::Get(key));
    }
  }

  void SetNoNotify(Key key, Value new_value) {
    Super::Set(key, std::move(new_value));
  }

  Key NewKey(KeyData data, Value initial_value = Value{}) {
    Key key = Super::NewKey(std::move(data), std::move(initial_value));
    static_cast<Derived*>(this)->OnNewKey(key, Super::Get(key));
    return key;
  }
  Key NewKey(Value initial_value = Value{}) {
    return NewKey(KeyData{}, initial_value);
  }
};

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_COMPILER_TURBOSHAFT_SNAPSHOT_TABLE_H_
```
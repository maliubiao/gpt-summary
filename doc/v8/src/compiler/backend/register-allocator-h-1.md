Response:
The user wants a functional breakdown of the C++ header file `v8/src/compiler/backend/register-allocator.h`.

Here's a plan:
1. **Identify key classes and structs:** List the major components defined in the header.
2. **Describe the purpose of each component:** Explain what each class/struct is responsible for in the register allocation process.
3. **Check for Torque:** Determine if the file is a Torque file (based on the `.tq` extension check).
4. **Relate to JavaScript:** Explain how register allocation impacts JavaScript execution. Provide a simple JavaScript example if applicable.
5. **Code Logic Inference:** If a class has methods suggesting logical operations, provide hypothetical input and output.
6. **Common Programming Errors:** Think about how the concepts in this header relate to common programming mistakes (though this might be less direct for a register allocator).
7. **Summarize Functionality:**  Provide a concise overview of the header's role.
这是 `v8/src/compiler/backend/register-allocator.h` 的第二部分，延续了第一部分的内容，主要定义了用于寄存器分配的各种数据结构和算法。以下是其中定义的主要类和结构及其功能的总结：

**核心数据结构和功能：**

* **`LiveRangeBundle`**:
    * **功能**:  将可能分配到相同寄存器或溢出槽的连接的活跃区间（`LiveRange`）分组。这是一种优化手段，尝试在分配时重用资源。
    * **成员**:
        * `ranges_`: 包含属于该 bundle 的 `TopLevelLiveRange` 列表。
        * `intervals_`: 包含属于该 bundle 的 `UseInterval` 列表。
        * `id_`: bundle 的唯一标识符。
        * `reg_`:  如果 bundle 被分配了一个寄存器，则存储寄存器编号。
    * **方法**:
        * `MergeSpillRangesAndClear()`: 合并溢出区间并清除。
        * `TryAddRange()`: 尝试将一个 `TopLevelLiveRange` 添加到 bundle。
        * `TryMerge()`: 尝试合并两个 `LiveRangeBundle`。

* **`TopLevelLiveRange`**:
    * **功能**:  表示一个虚拟寄存器的所有 `LiveRange` 片段的头部。它管理着与该虚拟寄存器相关联的所有生命周期信息，包括溢出（spill）状态。
    * **继承自**: `LiveRange` (在第一部分定义)。
    * **成员**:
        * `vreg_`: 对应的虚拟寄存器编号。
        * `spill_start_index_`: 溢出开始的指令索引。
        * `spill_operand_`/`spill_range_`: 用于存储溢出操作数或溢出区间的联合体。
        * `spill_move_insertion_locations_`/`list_of_blocks_requiring_spill_operands_`: 用于管理溢出移动插入位置的联合体。
        * `bundle_`: 指向所属的 `LiveRangeBundle`。
        * `positions_`: 存储使用位置的向量。
        * `children_`: 存储该 `TopLevelLiveRange` 分裂成的子 `LiveRange` 的向量。
        * `spilled_in_deferred_blocks_`: 标记是否只在延迟块中溢出。
        * `has_preassigned_slot_`: 标记是否已预分配槽位。
    * **方法**:
        * 管理溢出状态（`set_spill_type`, `spill_type`, `GetSpillOperand`, `GetSpillRange` 等）。
        * 管理使用区间（`EnsureInterval`, `AddUseInterval`, `AddUsePosition`）。
        * 管理子 `LiveRange`（`GetChildCovers`, `Children`）。
        * 管理溢出移动（`RecordSpillLocation`, `FilterSpillMoves`, `CommitSpillMoves`）。
        * 管理在延迟块中的溢出（`TreatAsSpilledInDeferredBlock`, `TransitionRangeToDeferredSpill`, `TransitionRangeToSpillAtDefinition`）。
        * 获取所属的 `LiveRangeBundle` (`get_bundle`, `set_bundle`)。

* **`PrintableLiveRange`**:
    * **功能**: 用于方便地打印 `LiveRange` 的调试辅助结构。

* **`SpillRange`**:
    * **功能**: 表示一个活跃区间的溢出操作数及其使用区间。在寄存器分配后，不相交的溢出区间会被合并，并分配到相同的溢出槽。
    * **成员**:
        * `ranges_`:  包含属于该溢出区间的 `TopLevelLiveRange` 列表。
        * `intervals_`: 包含属于该溢出区间的 `UseInterval` 列表。
        * `assigned_slot_`: 分配的溢出槽索引。
        * `byte_width_`: 溢出槽的字节宽度。
    * **方法**:
        * `TryMerge()`: 尝试合并两个 `SpillRange`。

**寄存器分配的各个阶段（以类表示）：**

* **`ConstraintBuilder`**:
    * **功能**: 负责处理寄存器约束。
    * **阶段 1**: 插入移动指令以满足固定寄存器操作数的要求。
    * **阶段 2**: 通过在后继块和包含 phi 节点的块的头部插入移动指令来解构 SSA 形式。

* **`LiveRangeBuilder`**:
    * **功能**: 构建所有虚拟寄存器的活跃区间。
    * **阶段 3**: 计算所有虚拟寄存器的活跃性。

* **`BundleBuilder`**:
    * **功能**: 将活跃区间分组到 `LiveRangeBundle` 中。

* **`RegisterAllocator`**:
    * **功能**: 寄存器分配的基类，定义了寄存器分配的通用接口和方法。
    * **成员**: 维护了寄存器分配的数据（`RegisterAllocationData`）、操作模式（`RegisterKind`）、可用寄存器信息等。
    * **方法**: 提供了一些辅助方法，如获取分割位置、溢出操作等。

* **`LinearScanAllocator`**:
    * **功能**: 基于线性扫描算法实现寄存器分配。
    * **继承自**: `RegisterAllocator`。
    * **阶段 4**: 计算寄存器分配。
    * **成员**: 维护了活跃区间列表（`unhandled_live_ranges_`, `active_live_ranges_`, `inactive_live_ranges_`）。
    * **方法**: 实现了线性扫描分配的核心逻辑，包括处理活跃区间、选择寄存器、溢出等。

* **`OperandAssigner`**:
    * **功能**: 负责最终的操作数分配，包括确定溢出模式和分配溢出槽。
    * **阶段 5**: 最终决定溢出模式。
    * **阶段 6**: 分配溢出槽。
    * **阶段 7**: 提交分配结果。

* **`ReferenceMapPopulator`**:
    * **功能**:  计算指针映射的值，用于垃圾回收。
    * **阶段 10**: 计算指针映射的值。

* **`LiveRangeConnector`**:
    * **功能**:  负责在分裂的活跃区间之间插入移动指令，以保证程序逻辑的正确性。
    * **阶段 8**: 当控制流简单时，连接分裂的区间。
    * **阶段 9**: 处理跨基本块的连接，并决定何时溢出，添加溢出移动指令。

**关于你的问题：**

* **v8/src/compiler/backend/register-allocator.h 以 .tq 结尾？**
    根据你提供的文件名 `v8/src/compiler/backend/register-allocator.h`，它以 `.h` 结尾，这意味着它是一个 **C++ 头文件**，而不是 v8 Torque 源代码。Torque 文件通常以 `.tq` 结尾。

* **与 JavaScript 的功能有关系吗？**
    是的，`register-allocator.h` 中定义的类和数据结构是 V8 编译器后端的核心组成部分。寄存器分配是编译器优化的关键步骤，它直接影响生成的机器代码的性能。将频繁访问的变量或值分配到寄存器中可以显著提高执行速度。

    **JavaScript 示例：**

    ```javascript
    function add(a, b) {
      let sum = a + b;
      return sum;
    }

    let result = add(5, 3);
    console.log(result);
    ```

    在这个简单的 JavaScript 函数中，V8 的寄存器分配器会尝试将变量 `a`、`b` 和 `sum` 分配到 CPU 寄存器中，以便更快地执行加法操作。如果没有有效的寄存器分配，这些变量可能需要存储在内存中，从而导致性能下降。

* **代码逻辑推理（假设输入与输出）**

    以 `LiveRangeBundle::TryMerge(LiveRangeBundle* lhs, LiveRangeBundle* rhs)` 为例：

    **假设输入：**
    * `lhs`: 一个 `LiveRangeBundle` 对象，`id_ = 1`, 包含 `TopLevelLiveRange` A 和 B。
    * `rhs`: 一个 `LiveRangeBundle` 对象，`id_ = 2`, 包含 `TopLevelLiveRange` C。
    * 假设 A、B、C 的生命周期有重叠的可能性，并且可以合并。

    **预期输出：**
    * 返回一个新的 `LiveRangeBundle` 对象（或者修改 `lhs` 或 `rhs` 并返回其中一个），其中包含 `TopLevelLiveRange` A、B 和 C。
    * 原来的 `lhs` 或 `rhs` 中被合并的那个会被清空。
    * 返回的 bundle 的 `id_` 可能是 `lhs` 或 `rhs` 的 `id_`。

    **如果输入的 `lhs` 和 `rhs` 不能合并（例如，它们被分配了互相冲突的固定寄存器），则返回 `nullptr`。**

* **涉及用户常见的编程错误？**

    虽然用户通常不会直接与寄存器分配器交互，但寄存器分配器的效率会受到 JavaScript 代码编写方式的影响。

    **示例：**

    * **过度使用全局变量:**  全局变量的生命周期通常很长，可能导致寄存器分配器难以有效地为其分配寄存器，因为寄存器是有限的资源。局部变量由于生命周期较短，更容易被分配到寄存器。

    ```javascript
    // 不好的实践
    var globalCounter = 0;
    function increment() {
      globalCounter++;
      return globalCounter;
    }

    // 更好的实践
    function incrementLocal() {
      let localCounter = 0;
      localCounter++;
      return localCounter;
    }
    ```

    * **在循环中进行大量重复计算:** 如果在循环中进行大量不必要的计算，这些中间结果可能会占用寄存器，导致真正需要寄存器的值被溢出到内存。

    ```javascript
    // 可能导致寄存器压力的代码
    function processArray(arr) {
      for (let i = 0; i < arr.length; i++) {
        let complexCalculation = Math.sqrt(arr[i] * arr[i] + 2 * arr[i] + 1); // 每次都计算
        console.log(complexCalculation);
      }
    }
    ```

**归纳功能：**

`v8/src/compiler/backend/register-allocator.h` 的第二部分继续定义了 V8 编译器后端中用于执行**寄存器分配**的关键数据结构和算法。它描述了如何组织和管理变量的生命周期信息（`LiveRange`、`LiveRangeBundle`），以及如何将虚拟寄存器映射到物理寄存器。这些类和方法共同实现了寄存器分配的各个阶段，从处理约束、构建活跃区间，到最终的寄存器分配和溢出处理，确保生成的机器代码能够高效地利用 CPU 寄存器，从而提升 JavaScript 的执行性能。

### 提示词
```
这是目录为v8/src/compiler/backend/register-allocator.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/register-allocator.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
pre-SSA information and is used as a hint to allocate the
// same spill slot or reuse the same register for connected live ranges.
class LiveRangeBundle : public ZoneObject {
 public:
  explicit LiveRangeBundle(Zone* zone, int id)
      : ranges_(zone), intervals_(zone), id_(id) {}

  int id() const { return id_; }

  int reg() const { return reg_; }
  void set_reg(int reg) {
    DCHECK_EQ(reg_, kUnassignedRegister);
    reg_ = reg;
  }

  void MergeSpillRangesAndClear();
  bool TryAddRange(TopLevelLiveRange* range);
  // If merging is possible, merge either {lhs} into {rhs} or {rhs} into
  // {lhs}, clear the source and return the result. Otherwise return nullptr.
  static LiveRangeBundle* TryMerge(LiveRangeBundle* lhs, LiveRangeBundle* rhs);

 private:
  void AddRange(TopLevelLiveRange* range);

  // A flat set, sorted by `LiveRangeOrdering`.
  ZoneVector<TopLevelLiveRange*> ranges_;
  // A flat set, sorted by their `start()` position.
  ZoneVector<UseInterval> intervals_;

  int id_;
  int reg_ = kUnassignedRegister;
};

// Register allocation splits LiveRanges so it can make more fine-grained
// allocation and spilling decisions. The LiveRanges that belong to the same
// virtual register form a linked-list, and the head of this list is a
// TopLevelLiveRange.
class V8_EXPORT_PRIVATE TopLevelLiveRange final : public LiveRange {
 public:
  explicit TopLevelLiveRange(int vreg, MachineRepresentation rep, Zone* zone);
  TopLevelLiveRange(const TopLevelLiveRange&) = delete;
  TopLevelLiveRange& operator=(const TopLevelLiveRange&) = delete;

  int spill_start_index() const { return spill_start_index_; }

  bool IsFixed() const { return vreg_ < 0; }

  bool IsDeferredFixed() const { return DeferredFixedField::decode(bits_); }
  void set_deferred_fixed() { bits_ = DeferredFixedField::update(bits_, true); }
  bool is_phi() const { return IsPhiField::decode(bits_); }
  void set_is_phi(bool value) { bits_ = IsPhiField::update(bits_, value); }

  bool is_non_loop_phi() const { return IsNonLoopPhiField::decode(bits_); }
  bool is_loop_phi() const { return is_phi() && !is_non_loop_phi(); }
  void set_is_non_loop_phi(bool value) {
    bits_ = IsNonLoopPhiField::update(bits_, value);
  }
  bool SpillAtLoopHeaderNotBeneficial() const {
    return SpillAtLoopHeaderNotBeneficialField::decode(bits_);
  }
  void set_spilling_at_loop_header_not_beneficial() {
    bits_ = SpillAtLoopHeaderNotBeneficialField::update(bits_, true);
  }

  enum SlotUseKind { kNoSlotUse, kDeferredSlotUse, kGeneralSlotUse };

  bool has_slot_use() const {
    return slot_use_kind() > SlotUseKind::kNoSlotUse;
  }

  bool has_non_deferred_slot_use() const {
    return slot_use_kind() == SlotUseKind::kGeneralSlotUse;
  }

  void reset_slot_use() {
    bits_ = HasSlotUseField::update(bits_, SlotUseKind::kNoSlotUse);
  }
  void register_slot_use(SlotUseKind value) {
    bits_ = HasSlotUseField::update(bits_, std::max(slot_use_kind(), value));
  }
  SlotUseKind slot_use_kind() const { return HasSlotUseField::decode(bits_); }

  // Add a new interval or a new use position to this live range.
  void EnsureInterval(LifetimePosition start, LifetimePosition end, Zone* zone);
  void AddUseInterval(LifetimePosition start, LifetimePosition end, Zone* zone);
  void AddUsePosition(UsePosition* pos, Zone* zone);

  // Shorten the most recently added interval by setting a new start.
  void ShortenTo(LifetimePosition start);

  // Spill range management.
  void SetSpillRange(SpillRange* spill_range);

  // Encodes whether a range is also available from a memory location:
  //   kNoSpillType: not availble in memory location.
  //   kSpillOperand: computed in a memory location at range start.
  //   kSpillRange: copied (spilled) to memory location at the definition,
  //                or at the beginning of some later blocks if
  //                LateSpillingSelected() is true.
  //   kDeferredSpillRange: copied (spilled) to memory location at entry
  //                        to deferred blocks that have a use from memory.
  //
  // Ranges either start out at kSpillOperand, which is also their final
  // state, or kNoSpillType. When spilled only in deferred code, a range
  // ends up with kDeferredSpillRange, while when spilled in regular code,
  // a range will be tagged as kSpillRange.
  enum class SpillType {
    kNoSpillType,
    kSpillOperand,
    kSpillRange,
    kDeferredSpillRange
  };
  void set_spill_type(SpillType value) {
    bits_ = SpillTypeField::update(bits_, value);
  }
  SpillType spill_type() const { return SpillTypeField::decode(bits_); }
  InstructionOperand* GetSpillOperand() const {
    DCHECK_EQ(SpillType::kSpillOperand, spill_type());
    return spill_operand_;
  }

  SpillRange* GetAllocatedSpillRange() const {
    DCHECK_NE(SpillType::kSpillOperand, spill_type());
    return spill_range_;
  }

  SpillRange* GetSpillRange() const {
    DCHECK_GE(spill_type(), SpillType::kSpillRange);
    return spill_range_;
  }
  bool HasNoSpillType() const {
    return spill_type() == SpillType::kNoSpillType;
  }
  bool HasSpillOperand() const {
    return spill_type() == SpillType::kSpillOperand;
  }
  bool HasSpillRange() const { return spill_type() >= SpillType::kSpillRange; }
  bool HasGeneralSpillRange() const {
    return spill_type() == SpillType::kSpillRange;
  }
  AllocatedOperand GetSpillRangeOperand() const;

  void RecordSpillLocation(Zone* zone, int gap_index,
                           InstructionOperand* operand);
  void SetSpillOperand(InstructionOperand* operand);
  void SetSpillStartIndex(int start) {
    spill_start_index_ = std::min(start, spill_start_index_);
  }

  // Omits any moves from spill_move_insertion_locations_ that can be skipped.
  void FilterSpillMoves(RegisterAllocationData* data,
                        const InstructionOperand& operand);

  // Writes all moves from spill_move_insertion_locations_ to the schedule.
  void CommitSpillMoves(RegisterAllocationData* data,
                        const InstructionOperand& operand);

  // If all the children of this range are spilled in deferred blocks, and if
  // for any non-spilled child with a use position requiring a slot, that range
  // is contained in a deferred block, mark the range as
  // IsSpilledOnlyInDeferredBlocks, so that we avoid spilling at definition,
  // and instead let the LiveRangeConnector perform the spills within the
  // deferred blocks. If so, we insert here spills for non-spilled ranges
  // with slot use positions.
  void TreatAsSpilledInDeferredBlock(Zone* zone) {
    spill_start_index_ = -1;
    spilled_in_deferred_blocks_ = true;
    spill_move_insertion_locations_ = nullptr;
    list_of_blocks_requiring_spill_operands_ = zone->New<SparseBitVector>(zone);
  }

  // Updates internal data structures to reflect that this range is not
  // spilled at definition but instead spilled in some blocks only.
  void TransitionRangeToDeferredSpill(Zone* zone) {
    spill_start_index_ = -1;
    spill_move_insertion_locations_ = nullptr;
    list_of_blocks_requiring_spill_operands_ = zone->New<SparseBitVector>(zone);
  }

  // Promotes this range to spill at definition if it was marked for spilling
  // in deferred blocks before.
  void TransitionRangeToSpillAtDefinition() {
    DCHECK_NOT_NULL(spill_move_insertion_locations_);
    if (spill_type() == SpillType::kDeferredSpillRange) {
      set_spill_type(SpillType::kSpillRange);
    }
  }

  bool MayRequireSpillRange() const {
    return !HasSpillOperand() && spill_range_ == nullptr;
  }
  void UpdateSpillRangePostMerge(TopLevelLiveRange* merged);
  int vreg() const { return vreg_; }

#ifdef DEBUG
  void Verify() const;
  void VerifyChildrenInOrder() const;
#endif

  // Returns the child `LiveRange` covering the given position, or `nullptr`
  // if no such range exists. Uses a binary search.
  LiveRange* GetChildCovers(LifetimePosition pos);

  const ZoneVector<LiveRange*>& Children() const { return children_; }

  int GetNextChildId() { return ++last_child_id_; }

  bool IsSpilledOnlyInDeferredBlocks(const RegisterAllocationData* data) const {
    return spill_type() == SpillType::kDeferredSpillRange;
  }

  struct SpillMoveInsertionList;

  SpillMoveInsertionList* GetSpillMoveInsertionLocations(
      const RegisterAllocationData* data) const {
    DCHECK(!IsSpilledOnlyInDeferredBlocks(data));
    return spill_move_insertion_locations_;
  }

  void MarkHasPreassignedSlot() { has_preassigned_slot_ = true; }
  bool has_preassigned_slot() const { return has_preassigned_slot_; }

  // Late spilling refers to spilling at places after the definition. These
  // spills are guaranteed to cover at least all of the sub-ranges where the
  // register allocator chose to evict the value from a register.
  void SetLateSpillingSelected(bool late_spilling_selected) {
    DCHECK(spill_type() == SpillType::kSpillRange);
    SpillRangeMode new_mode = late_spilling_selected
                                  ? SpillRangeMode::kSpillLater
                                  : SpillRangeMode::kSpillAtDefinition;
    // A single TopLevelLiveRange should never be used in both modes.
    DCHECK(SpillRangeModeField::decode(bits_) == SpillRangeMode::kNotSet ||
           SpillRangeModeField::decode(bits_) == new_mode);
    bits_ = SpillRangeModeField::update(bits_, new_mode);
  }
  bool LateSpillingSelected() const {
    // Nobody should be reading this value until it's been decided.
    DCHECK_IMPLIES(HasGeneralSpillRange(), SpillRangeModeField::decode(bits_) !=
                                               SpillRangeMode::kNotSet);
    return SpillRangeModeField::decode(bits_) == SpillRangeMode::kSpillLater;
  }

  void AddBlockRequiringSpillOperand(RpoNumber block_id,
                                     const RegisterAllocationData* data) {
    DCHECK(IsSpilledOnlyInDeferredBlocks(data));
    GetListOfBlocksRequiringSpillOperands(data)->Add(block_id.ToInt());
  }

  SparseBitVector* GetListOfBlocksRequiringSpillOperands(
      const RegisterAllocationData* data) const {
    DCHECK(IsSpilledOnlyInDeferredBlocks(data));
    return list_of_blocks_requiring_spill_operands_;
  }

  LiveRangeBundle* get_bundle() const { return bundle_; }
  void set_bundle(LiveRangeBundle* bundle) { bundle_ = bundle; }

 private:
  friend class LiveRange;

  // If spill type is kSpillRange, then this value indicates whether we've
  // chosen to spill at the definition or at some later points.
  enum class SpillRangeMode : uint8_t {
    kNotSet,
    kSpillAtDefinition,
    kSpillLater,
  };

  using HasSlotUseField = base::BitField<SlotUseKind, 1, 2>;
  using IsPhiField = base::BitField<bool, 3, 1>;
  using IsNonLoopPhiField = base::BitField<bool, 4, 1>;
  using SpillTypeField = base::BitField<SpillType, 5, 2>;
  using DeferredFixedField = base::BitField<bool, 28, 1>;
  using SpillAtLoopHeaderNotBeneficialField = base::BitField<bool, 29, 1>;
  using SpillRangeModeField = base::BitField<SpillRangeMode, 30, 2>;

  int vreg_;
  int last_child_id_;
  union {
    // Correct value determined by spill_type()
    InstructionOperand* spill_operand_;
    SpillRange* spill_range_;
  };

  union {
    SpillMoveInsertionList* spill_move_insertion_locations_;
    SparseBitVector* list_of_blocks_requiring_spill_operands_;
  };

  LiveRangeBundle* bundle_ = nullptr;

  UsePositionVector positions_;

  // This is a cache for the binary search in `GetChildCovers`.
  // The `LiveRange`s are sorted by their `Start()` position.
  ZoneVector<LiveRange*> children_;

  // TODO(mtrofin): generalize spilling after definition, currently specialized
  // just for spill in a single deferred block.
  bool spilled_in_deferred_blocks_;
  bool has_preassigned_slot_;

  int spill_start_index_;
};

struct PrintableLiveRange {
  const RegisterConfiguration* register_configuration_;
  const LiveRange* range_;
};

std::ostream& operator<<(std::ostream& os,
                         const PrintableLiveRange& printable_range);

// Represent the spill operand of a LiveRange and its use intervals. After
// register allocation, disjoint spill ranges are merged and they get assigned
// the same spill slot by OperandAssigner::AssignSpillSlots().
// TODO(dlehmann): `SpillRange`s seem awefully similar to `LiveRangeBundle`s,
// especially since both store `ranges_` and `intervals_` and check for
// intersection in exactly the same way. I wonder if we can merge those two
// concepts and save a bunch of memory by not storing ranges and intervals
// twice.
class SpillRange final : public ZoneObject {
 public:
  static const int kUnassignedSlot = -1;

  SpillRange(TopLevelLiveRange* range, Zone* zone);
  SpillRange(const SpillRange&) = delete;
  SpillRange& operator=(const SpillRange&) = delete;

  bool IsEmpty() const { return ranges_.empty(); }
  bool TryMerge(SpillRange* other);
  bool HasSlot() const { return assigned_slot_ != kUnassignedSlot; }

  void set_assigned_slot(int index) {
    DCHECK_EQ(kUnassignedSlot, assigned_slot_);
    assigned_slot_ = index;
  }
  int assigned_slot() const {
    DCHECK_NE(kUnassignedSlot, assigned_slot_);
    return assigned_slot_;
  }

  // Spill slots can be 4, 8, or 16 bytes wide.
  int byte_width() const { return byte_width_; }

  void Print() const;

 private:
  ZoneVector<TopLevelLiveRange*> ranges_;
  // A flat set, sorted by their `start()` position.
  ZoneVector<UseInterval> intervals_;

  int assigned_slot_;
  int byte_width_;
};

class ConstraintBuilder final : public ZoneObject {
 public:
  explicit ConstraintBuilder(RegisterAllocationData* data);
  ConstraintBuilder(const ConstraintBuilder&) = delete;
  ConstraintBuilder& operator=(const ConstraintBuilder&) = delete;

  // Phase 1 : insert moves to account for fixed register operands.
  void MeetRegisterConstraints();

  // Phase 2: deconstruct SSA by inserting moves in successors and the headers
  // of blocks containing phis.
  void ResolvePhis();

 private:
  RegisterAllocationData* data() const { return data_; }
  InstructionSequence* code() const { return data()->code(); }
  Zone* allocation_zone() const { return data()->allocation_zone(); }

  InstructionOperand* AllocateFixed(UnallocatedOperand* operand, int pos,
                                    bool is_tagged, bool is_input);
  void MeetRegisterConstraints(const InstructionBlock* block);
  void MeetConstraintsBefore(int index);
  void MeetConstraintsAfter(int index);
  void MeetRegisterConstraintsForLastInstructionInBlock(
      const InstructionBlock* block);
  void ResolvePhis(const InstructionBlock* block);

  RegisterAllocationData* const data_;
};

class LiveRangeBuilder final : public ZoneObject {
 public:
  explicit LiveRangeBuilder(RegisterAllocationData* data, Zone* local_zone);
  LiveRangeBuilder(const LiveRangeBuilder&) = delete;
  LiveRangeBuilder& operator=(const LiveRangeBuilder&) = delete;

  // Phase 3: compute liveness of all virtual register.
  void BuildLiveRanges();
  static SparseBitVector* ComputeLiveOut(const InstructionBlock* block,
                                         RegisterAllocationData* data);

 private:
  using SpillMode = RegisterAllocationData::SpillMode;
  static constexpr int kNumberOfFixedRangesPerRegister =
      RegisterAllocationData::kNumberOfFixedRangesPerRegister;

  RegisterAllocationData* data() const { return data_; }
  InstructionSequence* code() const { return data()->code(); }
  Zone* allocation_zone() const { return data()->allocation_zone(); }
  Zone* code_zone() const { return code()->zone(); }
  const RegisterConfiguration* config() const { return data()->config(); }
  ZoneVector<SparseBitVector*>& live_in_sets() const {
    return data()->live_in_sets();
  }

#ifdef DEBUG
  // Verification.
  void Verify() const;
  bool IntervalStartsAtBlockBoundary(UseInterval interval) const;
  bool IntervalPredecessorsCoveredByRange(UseInterval interval,
                                          TopLevelLiveRange* range) const;
  bool NextIntervalStartsInDifferentBlocks(UseInterval interval,
                                           UseInterval next) const;
#endif

  // Liveness analysis support.
  void AddInitialIntervals(const InstructionBlock* block,
                           SparseBitVector* live_out);
  void ProcessInstructions(const InstructionBlock* block,
                           SparseBitVector* live);
  void ProcessPhis(const InstructionBlock* block, SparseBitVector* live);
  void ProcessLoopHeader(const InstructionBlock* block, SparseBitVector* live);

  static int FixedLiveRangeID(int index) { return -index - 1; }
  int FixedFPLiveRangeID(int index, MachineRepresentation rep);
  TopLevelLiveRange* FixedLiveRangeFor(int index, SpillMode spill_mode);
  TopLevelLiveRange* FixedFPLiveRangeFor(int index, MachineRepresentation rep,
                                         SpillMode spill_mode);
  TopLevelLiveRange* FixedSIMD128LiveRangeFor(int index, SpillMode spill_mode);

  void MapPhiHint(InstructionOperand* operand, UsePosition* use_pos);
  void ResolvePhiHint(InstructionOperand* operand, UsePosition* use_pos);

  UsePosition* NewUsePosition(LifetimePosition pos, InstructionOperand* operand,
                              void* hint, UsePositionHintType hint_type);
  UsePosition* NewUsePosition(LifetimePosition pos) {
    return NewUsePosition(pos, nullptr, nullptr, UsePositionHintType::kNone);
  }
  TopLevelLiveRange* LiveRangeFor(InstructionOperand* operand,
                                  SpillMode spill_mode);
  // Helper methods for building intervals.
  UsePosition* Define(LifetimePosition position, InstructionOperand* operand,
                      void* hint, UsePositionHintType hint_type,
                      SpillMode spill_mode);
  void Define(LifetimePosition position, InstructionOperand* operand,
              SpillMode spill_mode) {
    Define(position, operand, nullptr, UsePositionHintType::kNone, spill_mode);
  }
  UsePosition* Use(LifetimePosition block_start, LifetimePosition position,
                   InstructionOperand* operand, void* hint,
                   UsePositionHintType hint_type, SpillMode spill_mode);
  void Use(LifetimePosition block_start, LifetimePosition position,
           InstructionOperand* operand, SpillMode spill_mode) {
    Use(block_start, position, operand, nullptr, UsePositionHintType::kNone,
        spill_mode);
  }
  SpillMode SpillModeForBlock(const InstructionBlock* block) const {
    return block->IsDeferred() ? SpillMode::kSpillDeferred
                               : SpillMode::kSpillAtDefinition;
  }
  RegisterAllocationData* const data_;
  ZoneMap<InstructionOperand*, UsePosition*> phi_hints_;
};

class BundleBuilder final : public ZoneObject {
 public:
  explicit BundleBuilder(RegisterAllocationData* data) : data_(data) {}

  void BuildBundles();

 private:
  RegisterAllocationData* data() const { return data_; }
  InstructionSequence* code() const { return data_->code(); }
  RegisterAllocationData* data_;
  int next_bundle_id_ = 0;
};

class RegisterAllocator : public ZoneObject {
 public:
  RegisterAllocator(RegisterAllocationData* data, RegisterKind kind);
  RegisterAllocator(const RegisterAllocator&) = delete;
  RegisterAllocator& operator=(const RegisterAllocator&) = delete;

 protected:
  using SpillMode = RegisterAllocationData::SpillMode;
  RegisterAllocationData* data() const { return data_; }
  InstructionSequence* code() const { return data()->code(); }
  RegisterKind mode() const { return mode_; }
  int num_registers() const { return num_registers_; }
  int num_allocatable_registers() const { return num_allocatable_registers_; }
  const int* allocatable_register_codes() const {
    return allocatable_register_codes_;
  }
  // Returns true iff. we must check float register aliasing.
  bool check_fp_aliasing() const { return check_fp_aliasing_; }

  // TODO(mtrofin): explain why splitting in gap START is always OK.
  LifetimePosition GetSplitPositionForInstruction(const LiveRange* range,
                                                  int instruction_index);

  Zone* allocation_zone() const { return data()->allocation_zone(); }

  // Find the optimal split for ranges defined by a memory operand, e.g.
  // constants or function parameters passed on the stack.
  void SplitAndSpillRangesDefinedByMemoryOperand();

  // Split the given range at the given position.
  // If range starts at or after the given position then the
  // original range is returned.
  // Otherwise returns the live range that starts at pos and contains
  // all uses from the original range that follow pos. Uses at pos will
  // still be owned by the original range after splitting.
  LiveRange* SplitRangeAt(LiveRange* range, LifetimePosition pos);

  bool CanProcessRange(LiveRange* range) const {
    return range != nullptr && !range->IsEmpty() && range->kind() == mode();
  }

  // Split the given range in a position from the interval [start, end].
  LiveRange* SplitBetween(LiveRange* range, LifetimePosition start,
                          LifetimePosition end);

  // Find a lifetime position in the interval [start, end] which
  // is optimal for splitting: it is either header of the outermost
  // loop covered by this interval or the latest possible position.
  LifetimePosition FindOptimalSplitPos(LifetimePosition start,
                                       LifetimePosition end);

  void Spill(LiveRange* range, SpillMode spill_mode);

  // If we are trying to spill a range inside the loop try to
  // hoist spill position out to the point just before the loop.
  LifetimePosition FindOptimalSpillingPos(LiveRange* range,
                                          LifetimePosition pos,
                                          SpillMode spill_mode,
                                          LiveRange** begin_spill_out);

  const ZoneVector<TopLevelLiveRange*>& GetFixedRegisters() const;
  const char* RegisterName(int allocation_index) const;

 private:
  RegisterAllocationData* const data_;
  const RegisterKind mode_;
  const int num_registers_;
  int num_allocatable_registers_;
  const int* allocatable_register_codes_;
  bool check_fp_aliasing_;

 private:
  bool no_combining_;
};

// A map from `TopLevelLiveRange`s to their expected physical register.
// Typically this is very small, e.g., on JetStream2 it has 3 elements or less
// >50% of the times it is queried, 8 elements or less >90% of the times,
// and never more than 15 elements. Hence this is backed by a `SmallZoneMap`.
using RangeRegisterSmallMap =
    SmallZoneMap<TopLevelLiveRange*, /* expected_register */ int, 16>;

class LinearScanAllocator final : public RegisterAllocator {
 public:
  LinearScanAllocator(RegisterAllocationData* data, RegisterKind kind,
                      Zone* local_zone);
  LinearScanAllocator(const LinearScanAllocator&) = delete;
  LinearScanAllocator& operator=(const LinearScanAllocator&) = delete;

  // Phase 4: compute register assignments.
  void AllocateRegisters();

 private:
  void MaybeSpillPreviousRanges(LiveRange* begin_range,
                                LifetimePosition begin_pos,
                                LiveRange* end_range);
  void MaybeUndoPreviousSplit(LiveRange* range, Zone* zone);
  void SpillNotLiveRanges(RangeRegisterSmallMap& to_be_live,
                          LifetimePosition position, SpillMode spill_mode);
  LiveRange* AssignRegisterOnReload(LiveRange* range, int reg);
  void ReloadLiveRanges(RangeRegisterSmallMap const& to_be_live,
                        LifetimePosition position);

  void UpdateDeferredFixedRanges(SpillMode spill_mode, InstructionBlock* block);
  bool BlockIsDeferredOrImmediatePredecessorIsNotDeferred(
      const InstructionBlock* block);
  bool HasNonDeferredPredecessor(InstructionBlock* block);

  struct UnhandledLiveRangeOrdering {
    bool operator()(const LiveRange* a, const LiveRange* b) const {
      return a->ShouldBeAllocatedBefore(b);
    }
  };

  struct InactiveLiveRangeOrdering {
    bool operator()(const LiveRange* a, const LiveRange* b) const {
      return a->NextStart() < b->NextStart();
    }
  };

  // NOTE: We also tried a sorted ZoneVector instead of a `ZoneMultiset`
  // (like for `InactiveLiveRangeQueue`), but it does not improve performance
  // or max memory usage.
  // TODO(dlehmann): Try `std::priority_queue`/`std::make_heap` instead.
  using UnhandledLiveRangeQueue =
      ZoneMultiset<LiveRange*, UnhandledLiveRangeOrdering>;
  // Sorted by `InactiveLiveRangeOrdering`.
  // TODO(dlehmann): Try `std::priority_queue`/`std::make_heap` instead.
  using InactiveLiveRangeQueue = ZoneVector<LiveRange*>;
  UnhandledLiveRangeQueue& unhandled_live_ranges() {
    return unhandled_live_ranges_;
  }
  ZoneVector<LiveRange*>& active_live_ranges() { return active_live_ranges_; }
  InactiveLiveRangeQueue& inactive_live_ranges(int reg) {
    return inactive_live_ranges_[reg];
  }
  // At several places in the register allocator we rely on inactive live ranges
  // being sorted. Previously, this was always true by using a std::multiset.
  // But to improve performance and in particular reduce memory usage, we
  // switched to a sorted vector.
  // Insert this to ensure we don't violate the sorted assumption, and to
  // document where we actually rely on inactive live ranges being sorted.
  void SlowDCheckInactiveLiveRangesIsSorted(int reg) {
    SLOW_DCHECK(std::is_sorted(inactive_live_ranges(reg).begin(),
                               inactive_live_ranges(reg).end(),
                               InactiveLiveRangeOrdering()));
  }

  void SetLiveRangeAssignedRegister(LiveRange* range, int reg);

  // Helper methods for updating the life range lists.
  void AddToActive(LiveRange* range);
  void AddToInactive(LiveRange* range);
  void AddToUnhandled(LiveRange* range);
  ZoneVector<LiveRange*>::iterator ActiveToHandled(
      ZoneVector<LiveRange*>::iterator it);
  ZoneVector<LiveRange*>::iterator ActiveToInactive(
      ZoneVector<LiveRange*>::iterator it, LifetimePosition position);
  InactiveLiveRangeQueue::iterator InactiveToHandled(
      InactiveLiveRangeQueue::iterator it);
  InactiveLiveRangeQueue::iterator InactiveToActive(
      InactiveLiveRangeQueue::iterator it, LifetimePosition position);

  void ForwardStateTo(LifetimePosition position);

  int LastDeferredInstructionIndex(InstructionBlock* start);

  // Helper methods for choosing state after control flow events.

  bool ConsiderBlockForControlFlow(InstructionBlock* current_block,
                                   RpoNumber predecessor);
  RpoNumber ChooseOneOfTwoPredecessorStates(InstructionBlock* current_block,
                                            LifetimePosition boundary);
  bool CheckConflict(MachineRepresentation rep, int reg,
                     const RangeRegisterSmallMap& to_be_live);
  void ComputeStateFromManyPredecessors(InstructionBlock* current_block,
                                        RangeRegisterSmallMap& to_be_live);

  // Helper methods for allocating registers.

  // Spilling a phi at range start can be beneficial when the phi input is
  // already spilled and shares the same spill slot. This function tries to
  // guess if spilling the phi is beneficial based on live range bundles and
  // spilled phi inputs.
  bool TryReuseSpillForPhi(TopLevelLiveRange* range);
  int PickRegisterThatIsAvailableLongest(
      LiveRange* current, int hint_reg,
      base::Vector<const LifetimePosition> free_until_pos);
  bool TryAllocateFreeReg(LiveRange* range,
                          base::Vector<const LifetimePosition> free_until_pos);
  bool TryAllocatePreferredReg(
      LiveRange* range, base::Vector<const LifetimePosition> free_until_pos);
  void GetFPRegisterSet(MachineRepresentation rep, int* num_regs,
                        int* num_codes, const int** codes) const;
  void GetSIMD128RegisterSet(int* num_regs, int* num_codes,
                             const int** codes) const;
  void FindFreeRegistersForRange(LiveRange* range,
                                 base::Vector<LifetimePosition> free_until_pos);
  void ProcessCurrentRange(LiveRange* current, SpillMode spill_mode);
  void AllocateBlockedReg(LiveRange* range, SpillMode spill_mode);

  // Spill the given life range after position pos.
  void SpillAfter(LiveRange* range, LifetimePosition pos, SpillMode spill_mode);

  // Spill the given life range after position [start] and up to position [end].
  void SpillBetween(LiveRange* range, LifetimePosition start,
                    LifetimePosition end, SpillMode spill_mode);

  // Spill the given life range after position [start] and up to position [end].
  // Range is guaranteed to be spilled at least until position [until].
  void SpillBetweenUntil(LiveRange* range, LifetimePosition start,
                         LifetimePosition until, LifetimePosition end,
                         SpillMode spill_mode);
  void SplitAndSpillIntersecting(LiveRange* range, SpillMode spill_mode);

  void PrintRangeRow(std::ostream& os, const TopLevelLiveRange* toplevel);

  void PrintRangeOverview();

  UnhandledLiveRangeQueue unhandled_live_ranges_;
  ZoneVector<LiveRange*> active_live_ranges_;
  ZoneVector<InactiveLiveRangeQueue> inactive_live_ranges_;

  // Approximate at what position the set of ranges will change next.
  // Used to avoid scanning for updates even if none are present.
  LifetimePosition next_active_ranges_change_;
  LifetimePosition next_inactive_ranges_change_;

#ifdef DEBUG
  LifetimePosition allocation_finger_;
#endif
};

class OperandAssigner final : public ZoneObject {
 public:
  explicit OperandAssigner(RegisterAllocationData* data);
  OperandAssigner(const OperandAssigner&) = delete;
  OperandAssigner& operator=(const OperandAssigner&) = delete;

  // Phase 5: final decision on spilling mode.
  void DecideSpillingMode();

  // Phase 6: assign spill splots.
  void AssignSpillSlots();

  // Phase 7: commit assignment.
  void CommitAssignment();

 private:
  RegisterAllocationData* data() const { return data_; }

  RegisterAllocationData* const data_;
};

class ReferenceMapPopulator final : public ZoneObject {
 public:
  explicit ReferenceMapPopulator(RegisterAllocationData* data);
  ReferenceMapPopulator(const ReferenceMapPopulator&) = delete;
  ReferenceMapPopulator& operator=(const ReferenceMapPopulator&) = delete;

  // Phase 10: compute values for pointer maps.
  void PopulateReferenceMaps();

 private:
  RegisterAllocationData* data() const { return data_; }

  bool SafePointsAreInOrder() const;

  RegisterAllocationData* const data_;
};

class LiveRangeBoundArray;
// Insert moves of the form
//
//          Operand(child_(k+1)) = Operand(child_k)
//
// where child_k and child_(k+1) are consecutive children of a range (so
// child_k->next() == child_(k+1)), and Operand(...) refers to the
// assigned operand, be it a register or a slot.
class LiveRangeConnector final : public ZoneObject {
 public:
  explicit LiveRangeConnector(RegisterAllocationData* data);
  LiveRangeConnector(const LiveRangeConnector&) = delete;
  LiveRangeConnector& operator=(const LiveRangeConnector&) = delete;

  // Phase 8: reconnect split ranges with moves, when the control flow
  // between the ranges is trivial (no branches).
  void ConnectRanges(Zone* local_zone);

  // Phase 9: insert moves to connect ranges across basic blocks, when the
  // control flow between them cannot be trivially resolved, such as joining
  // branches. Also determines whether to spill at the definition or later, and
  // adds spill moves to the gaps in the schedule.
  void ResolveControlFlow(Zone* local_zone);

 private:
  RegisterAllocationData* data() const { return data_; }
  InstructionSequence* code() const { return data()->code(); }
  Zone* code_zone() const { return code()->zone(); }

  bool CanEagerlyResolveControlFlow(const InstructionBlock* block) const;
  int ResolveControlFlow(const InstructionBlock* block,
                         const InstructionOperand& cur_op,
                         const InstructionBlock* pred,
                         const InstructionOperand& pred_op);

  void CommitSpillsInDeferredBlocks(TopLevelLiveRange* range, Zone* temp_zone);

  RegisterAllocationData* const data_;
};

}  // namespace compiler
}  // namespace internal
}  // namespace v8

#endif  // V8_COMPILER_BACKEND_REGISTER_ALLOCATOR_H_
```
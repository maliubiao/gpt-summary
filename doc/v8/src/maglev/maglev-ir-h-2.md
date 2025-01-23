Response:
The user wants a summary of the C++ header file `v8/src/maglev/maglev-ir.h`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename `maglev-ir.h` strongly suggests this file defines the Intermediate Representation (IR) for the Maglev compiler in V8. This IR likely represents the operations and data flow within a compiled JavaScript function.

2. **Examine the `NodeBase` class:** This class appears fundamental. Key observations:
    * **Templates and Inheritance:**  Heavy use of templates (`template <class Derived, typename... Args>`) and inheritance suggests a class hierarchy for different IR node types.
    * **`Opcode` and `OpProperties`:** These seem to define the kind of operation and its characteristics (e.g., whether it can deoptimize, has side effects).
    * **Inputs:** The `input()` methods and related logic indicate how nodes connect to form a graph.
    * **Temporaries and Registers:** The `temporaries()` and related methods hint at register allocation.
    * **Deoptimization:** `eager_deopt_info()` and `lazy_deopt_info()` point to how the system handles reverting to interpreted code.
    * **Bitfields:** The extensive use of bitfields (`bitfield_`) is a common optimization technique in compilers to pack data efficiently.

3. **Examine the `Node` and `ValueNode` classes:** These likely represent the two primary categories of IR nodes:
    * **`Node`:** Seems like a base class for general operations, possibly control flow. The `participate_in_cse()` method suggests involvement in common subexpression elimination.
    * **`ValueNode`:**  Specifically deals with nodes that produce a value. Key aspects:
        * **`result()`:** Stores the location (register or memory) of the computed value.
        * **`use_count_`:** Tracks how many times the node's result is used.
        * **Spilling:**  The `Spill()` method relates to moving values from registers to memory when registers are scarce.
        * **Live Ranges:** `live_range()` and related methods are crucial for register allocation.
        * **Value Representation:** `value_representation()` indicates the data type of the value (e.g., tagged, integer, float).
        * **Register Management:**  Methods like `AddRegister()` and `RemoveRegister()` manage the registers holding the node's value.

4. **Examine the Mixins (`NodeTMixin`, `FixedInputNodeTMixin`):** These are likely used to reduce code duplication and enforce structure in the IR node hierarchy. They help in defining nodes with known opcodes and a fixed number of inputs.

5. **Look for concrete node types:** `Identity`, `UnaryWithFeedbackNode`, `BinaryWithFeedbackNode` are examples of specific IR node types, showing how the generic base classes are used. The "with feedback" part suggests these nodes are involved in collecting type information during execution for optimizations.

6. **Infer overall functionality:** Based on the examined elements, the file appears to define the data structures and base functionalities for representing operations in the Maglev compiler. It handles:
    * **Operation Types:** Defining different kinds of operations via `Opcode`.
    * **Data Flow:** Connecting operations through inputs.
    * **Value Representation:** Tracking the types of values.
    * **Register Allocation:**  Managing the assignment of registers to values.
    * **Deoptimization:**  Supporting the process of reverting to slower execution.
    * **Optimization:**  Providing mechanisms for optimizations like CSE.

7. **Consider the filename ending:** The prompt mentions `.tq`. Since this file ends with `.h`, it's C++ and not Torque.

8. **Relate to JavaScript (if possible):** While the header file is C++, its purpose is directly related to optimizing JavaScript execution. Think of simple JavaScript operations that would need representation in an IR (e.g., addition, variable access).

9. **Consider code logic and examples (as per the prompt):**  The `NodeBase` methods like `set_input` and the use counters in `ValueNode` imply a graph-like structure. Think of simple scenarios, like `const a = b + c;`, and how that might be represented as nodes and inputs.

10. **Think about common programming errors:**  The deoptimization mechanisms suggest that type errors or assumptions made during compilation might be violated at runtime.

11. **Structure the answer:** Organize the findings into logical sections, addressing each part of the user's request. Start with a high-level summary, then delve into the key classes and concepts.

By following these steps, the generated answer effectively summarizes the functionality of `v8/src/maglev/maglev-ir.h`.
这是 `v8/src/maglev/maglev-ir.h` 文件的第 3 部分，主要定义了 Maglev 编译器的中间表示（Intermediate Representation, IR）中的核心类 `NodeBase` 及其子类 `Node` 和 `ValueNode`。这些类是构建和操作 Maglev IR 图的基础。

**功能归纳:**

`v8/src/maglev/maglev-ir.h` 的这部分主要负责定义了 Maglev IR 图中的基本节点类型，以及它们的一些通用操作和属性。

**更详细的功能点:**

1. **`NodeBase` 类:**
   - **作为所有 IR 节点的基类:**  定义了所有 Maglev IR 节点共有的基本属性和方法。
   - **节点标识和属性:** 包含节点的唯一 ID (`id_`)，操作码 (`opcode()`) 和操作属性 (`properties()`)，这些属性描述了节点的一些特性，例如是否是纯函数、是否可能抛出异常等。
   - **输入管理:**  提供了管理节点输入的方法 (`set_input`, `input`, `change_input`)，允许节点连接到其他节点形成数据流图。
   - **类型判断:**  提供了一系列 `Is<T>()` 和 `Cast<T>()` 模板方法，用于在运行时判断节点的具体类型。
   - **临时寄存器管理:**  包含了为节点分配和管理临时寄存器的方法 (`num_temporaries_needed`, `temporaries`, `assign_temporaries`, `RequireSpecificTemporary`).
   - **控制流信息:**  通过 `owner()` 和 `set_owner()` 方法，记录节点所属的基本块，用于控制流分析。
   - **Deopt 信息:**  包含与反优化（Deoptimization）相关的信息 (`eager_deopt_info`, `lazy_deopt_info`)，用于在运行时发生某些情况时回退到解释执行。
   - **覆盖和修改:** 提供了修改节点操作码和属性的方法 (`OverwriteWith`).

2. **`Node` 类:**
   - **继承自 `NodeBase`:**  是所有非控制流节点的基类。
   - **链表结构:** 使用 `next_` 指针将节点连接成链表，方便在基本块内遍历。
   - **CSE 参与:**  `participate_in_cse()` 方法指示节点是否可以参与公共子表达式消除优化。
   - **Epoch 检查:** `needs_epoch_check()` 方法指示节点是否需要进行 Epoch 检查，这通常与内存读取操作相关。

3. **`ValueNode` 类:**
   - **继承自 `Node`:**  表示产生一个值的节点。
   - **结果位置:**  使用 `result()` 方法返回一个 `ValueLocation` 对象，描述了节点计算结果的存储位置（例如，寄存器或栈）。
   - **使用计数:**  `use_count_` 记录了节点结果被其他节点使用的次数，用于死代码消除等优化。
   - **Hint:**  `hint_` 允许为节点指定寄存器分配的提示。
   - **Spill:**  提供了 `Spill()` 方法将节点的值溢出到栈上，用于寄存器压力过大时。
   - **Live Range:**  `live_range()` 和相关方法用于跟踪节点值的生命周期，这对寄存器分配至关重要。
   - **值表示:**  `value_representation()` 返回节点值的类型表示（例如，Tagged, Int32, Float64）。
   - **寄存器管理:**  提供了管理存储节点结果的寄存器的方法 (`AddRegister`, `RemoveRegister`, `result_registers`).
   - **Decompression (在指针压缩启用时):**  `decompresses_tagged_result()` 和 `SetTaggedResultNeedsDecompress()` 用于处理压缩指针的情况。

4. **Mixin 类 (`NodeTMixin`, `FixedInputNodeTMixin`):**
   - **代码复用:**  这些模板 mixin 类用于简化具有已知操作码和/或输入数量的节点类型的定义。
   - **类型安全:**  通过模板参数提供更强的类型检查。

5. **具体的节点类型示例:**
   - `Identity`:  一个简单的节点，直接传递其输入值。
   - `UnaryWithFeedbackNode`:  表示带反馈信息的单操作数运算。
   - `BinaryWithFeedbackNode`:  表示带反馈信息的双操作数运算。

**与 Javascript 功能的关系 (以 `Identity` 为例):**

`Identity` 节点在概念上类似于 JavaScript 中的一个简单的变量赋值或直接使用一个变量的值，而没有进行任何操作。

```javascript
// JavaScript 示例
let x = 10;
let y = x; // 这里 y 的值就是 x 的值，相当于一个 Identity 操作
```

在 Maglev IR 中，如果 `x` 对应的 IR 节点计算出值 `10`，那么 `y` 对应的 IR 节点可能就是一个 `Identity` 节点，其输入是 `x` 对应的节点，输出也是值 `10` (可能在不同的寄存器或内存位置)。

**代码逻辑推理 (以 `set_input` 为例):**

**假设输入:**

- `index`: 一个整数，表示要设置的输入的索引，例如 `0`。
- `node`: 一个指向 `ValueNode` 实例的指针，例如指向一个表示常量 `5` 的 `ValueNode`。

**代码逻辑:**

```c++
inline void NodeBase::set_input(int index, ValueNode* node) {
  DCHECK_NOT_NULL(node); // 断言，确保传入的节点指针不为空
  DCHECK_EQ(input(index).node(), nullptr); // 断言，确保当前索引的输入为空，避免覆盖
  node->add_use(); // 增加输入节点的 use count，表示它被当前节点使用
  new (&input(index)) Input(node); // 在当前节点的输入数组的指定索引处构造一个新的 Input 对象，指向传入的节点
}
```

**输出:**

- 当前 `NodeBase` 实例的输入数组中，索引为 `index` 的 `Input` 对象将指向传入的 `ValueNode`。
- 传入的 `ValueNode` 的 `use_count_` 会增加 1。

**用户常见的编程错误 (与 deopt 相关):**

用户在编写 JavaScript 代码时，一些看似无害的操作，如果 JIT 编译器基于某些假设进行了优化，但在运行时这些假设被打破，就会触发反优化（deopt）。

**例如：类型假设错误**

```javascript
function add(a, b) {
  return a + b;
}

// 第一次调用，假设 a 和 b 都是数字
add(1, 2);

// 后续调用，假设被打破
add("hello", "world");
```

Maglev 编译器可能在第一次调用 `add` 时假设 `a` 和 `b` 总是数字，并生成针对数字加法的优化代码。如果后续调用传入了字符串，这个假设就会失效，导致需要 deopt，即放弃已经生成的优化代码，回到解释执行。`maglev-ir.h` 中定义的 deopt 相关结构和方法就是为了支持这种运行时回退机制。

**总结第 3 部分的功能:**

这部分代码是 Maglev IR 的核心，定义了表示计算操作和数据流的基本构建块 (`NodeBase`, `Node`, `ValueNode`)。它提供了管理节点属性、输入、输出、临时寄存器、生命周期以及反优化信息的基础设施。通过模板 mixin 和具体的节点类型示例，展示了如何构建一个结构化的、可扩展的中间表示，用于 JavaScript 代码的优化编译。

### 提示词
```
这是目录为v8/src/maglev/maglev-ir.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-ir.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共12部分，请归纳一下它的功能
```

### 源代码
```c
manually.
  template <class Derived, typename... Args>
  static Derived* New(Zone* zone, size_t input_count, Args&&... args) {
    Derived* node =
        Allocate<Derived>(zone, input_count, std::forward<Args>(args)...);
    return node;
  }

  // Overwritten by subclasses.
  static constexpr OpProperties kProperties =
      OpProperties::Pure() | OpProperties::TaggedValue();

  constexpr Opcode opcode() const { return OpcodeField::decode(bitfield_); }
  constexpr OpProperties properties() const {
    return OpPropertiesField::decode(bitfield_);
  }
  void set_properties(OpProperties properties) {
    bitfield_ = OpPropertiesField::update(bitfield_, properties);
  }

  inline void set_input(int index, ValueNode* node);

  template <class T>
  constexpr bool Is() const;

  template <class T>
  constexpr T* Cast() {
    DCHECK(Is<T>());
    return static_cast<T*>(this);
  }
  template <class T>
  constexpr const T* Cast() const {
    DCHECK(Is<T>());
    return static_cast<const T*>(this);
  }
  template <class T>
  constexpr T* TryCast() {
    return Is<T>() ? static_cast<T*>(this) : nullptr;
  }

  template <class T>
  constexpr const T* TryCast() const {
    return Is<T>() ? static_cast<const T*>(this) : nullptr;
  }

  constexpr bool has_inputs() const { return input_count() > 0; }
  constexpr int input_count() const {
    static_assert(InputCountField::kMax <= kMaxInt);
    return static_cast<int>(InputCountField::decode(bitfield_));
  }

  constexpr Input& input(int index) {
    DCHECK_LT(index, input_count());
    return *(input_base() - index);
  }
  constexpr const Input& input(int index) const {
    DCHECK_LT(index, input_count());
    return *(input_base() - index);
  }

  // Input iterators, use like:
  //
  //  for (Input& input : *node) { ... }
  constexpr auto begin() { return std::make_reverse_iterator(&input(-1)); }
  constexpr auto end() {
    return std::make_reverse_iterator(&input(input_count() - 1));
  }

  constexpr bool has_id() const { return id_ != kInvalidNodeId; }
  constexpr NodeIdT id() const {
    DCHECK_NE(id_, kInvalidNodeId);
    return id_;
  }
  void set_id(NodeIdT id) {
    DCHECK_EQ(id_, kInvalidNodeId);
    DCHECK_NE(id, kInvalidNodeId);
    id_ = id;
  }

  template <typename RegisterT>
  uint8_t num_temporaries_needed() const {
    if constexpr (std::is_same_v<RegisterT, Register>) {
      return NumTemporariesNeededField::decode(bitfield_);
    } else {
      return NumDoubleTemporariesNeededField::decode(bitfield_);
    }
  }

  template <typename RegisterT>
  RegListBase<RegisterT>& temporaries() {
    return owner_or_temporaries_.temporaries<RegisterT>();
  }
  RegList& general_temporaries() { return temporaries<Register>(); }
  DoubleRegList& double_temporaries() { return temporaries<DoubleRegister>(); }

  template <typename RegisterT>
  void assign_temporaries(RegListBase<RegisterT> list) {
    owner_or_temporaries_.temporaries<RegisterT>() = list;
  }

  enum class InputAllocationPolicy { kFixedRegister, kArbitraryRegister, kAny };

  // Some parts of Maglev require a specific iteration order of the inputs (such
  // as UseMarkingProcessor::MarkInputUses or
  // StraightForwardRegisterAllocator::AssignInputs). For such cases,
  // `ForAllInputsInRegallocAssignmentOrder` can be called with a callback `f`
  // that will be called for each input in the "correct" order.
  template <typename Function>
  void ForAllInputsInRegallocAssignmentOrder(Function&& f);

  void Print(std::ostream& os, MaglevGraphLabeller*,
             bool skip_targets = false) const;

  // For GDB: Print any Node with `print node->Print()`.
  void Print() const;

  EagerDeoptInfo* eager_deopt_info() {
    DCHECK(properties().can_eager_deopt() ||
           properties().is_deopt_checkpoint());
    DCHECK(!properties().can_lazy_deopt());
    return reinterpret_cast<EagerDeoptInfo*>(deopt_info_address());
  }

  LazyDeoptInfo* lazy_deopt_info() {
    DCHECK(properties().can_lazy_deopt());
    DCHECK(!properties().can_eager_deopt());
    return reinterpret_cast<LazyDeoptInfo*>(deopt_info_address());
  }

  const RegisterSnapshot& register_snapshot() const {
    DCHECK(properties().needs_register_snapshot());
    return *reinterpret_cast<RegisterSnapshot*>(register_snapshot_address());
  }

  ExceptionHandlerInfo* exception_handler_info() {
    DCHECK(properties().can_throw());
    return reinterpret_cast<ExceptionHandlerInfo*>(exception_handler_address());
  }

  void set_register_snapshot(RegisterSnapshot snapshot) {
    DCHECK(properties().needs_register_snapshot());
    *reinterpret_cast<RegisterSnapshot*>(register_snapshot_address()) =
        snapshot;
  }

  inline void change_input(int index, ValueNode* node);

  void change_representation(ValueRepresentation new_repr) {
    DCHECK_EQ(opcode(), Opcode::kPhi);
    bitfield_ = OpPropertiesField::update(
        bitfield_, properties().WithNewValueRepresentation(new_repr));
  }

  void set_opcode(Opcode new_opcode) {
    bitfield_ = OpcodeField::update(bitfield_, new_opcode);
  }

  void CopyEagerDeoptInfoOf(NodeBase* other, Zone* zone) {
    new (eager_deopt_info())
        EagerDeoptInfo(zone, other->eager_deopt_info()->top_frame(),
                       other->eager_deopt_info()->feedback_to_update());
  }

  void SetEagerDeoptInfo(Zone* zone, DeoptFrame deopt_frame,
                         compiler::FeedbackSource feedback_to_update =
                             compiler::FeedbackSource()) {
    DCHECK(properties().can_eager_deopt() ||
           properties().is_deopt_checkpoint());
    new (eager_deopt_info())
        EagerDeoptInfo(zone, deopt_frame, feedback_to_update);
  }

  template <typename NodeT>
  void OverwriteWith() {
    OverwriteWith(NodeBase::opcode_of<NodeT>, NodeT::kProperties);
  }

  void OverwriteWith(
      Opcode new_opcode,
      std::optional<OpProperties> maybe_new_properties = std::nullopt) {
    OpProperties new_properties = maybe_new_properties.has_value()
                                      ? maybe_new_properties.value()
                                      : StaticPropertiesForOpcode(new_opcode);
#ifdef DEBUG
    CheckCanOverwriteWith(new_opcode, new_properties);
#endif
    set_opcode(new_opcode);
    set_properties(new_properties);
  }

  auto options() const { return std::tuple{}; }

  void ClearUnstableNodeAspects(KnownNodeAspects&);
  void ClearElementsProperties(KnownNodeAspects&);

  void set_owner(BasicBlock* block) { owner_or_temporaries_ = block; }

  BasicBlock* owner() const { return owner_or_temporaries_.owner(); }

  void InitTemporaries() { owner_or_temporaries_.InitReglist(); }

 protected:
  explicit NodeBase(uint64_t bitfield) : bitfield_(bitfield) {}

  // Allow updating bits above NextBitField from subclasses
  constexpr uint64_t bitfield() const { return bitfield_; }
  void set_bitfield(uint64_t new_bitfield) {
#ifdef DEBUG
    // Make sure that all the base bitfield bits (all bits before the next
    // bitfield start, excluding any spare bits) are equal in the new value.
    const uint64_t base_bitfield_mask =
        ((uint64_t{1} << NextBitField<bool, 1>::kShift) - 1) &
        ~ReservedField::kMask;
    DCHECK_EQ(bitfield_ & base_bitfield_mask,
              new_bitfield & base_bitfield_mask);
#endif
    bitfield_ = new_bitfield;
  }

  constexpr Input* input_base() {
    return detail::ObjectPtrBeforeAddress<Input>(this);
  }
  constexpr const Input* input_base() const {
    return detail::ObjectPtrBeforeAddress<Input>(this);
  }
  Input* last_input() { return &input(input_count() - 1); }
  const Input* last_input() const { return &input(input_count() - 1); }

  Address last_input_address() const {
    return reinterpret_cast<Address>(last_input());
  }

  inline void initialize_input_null(int index);

  // For nodes that don't have data past the input, allow trimming the input
  // count. This is used by Phis to reduce inputs when merging in dead control
  // flow.
  void reduce_input_count(int num = 1) {
    DCHECK_EQ(opcode(), Opcode::kPhi);
    DCHECK_GE(input_count(), num);
    DCHECK(!properties().can_lazy_deopt());
    DCHECK(!properties().can_eager_deopt());
    bitfield_ = InputCountField::update(bitfield_, input_count() - num);
  }

  // Specify that there need to be a certain number of registers free (i.e.
  // useable as scratch registers) on entry into this node.
  //
  // Does not include any registers requested by RequireSpecificTemporary.
  void set_temporaries_needed(uint8_t value) {
    DCHECK_EQ(num_temporaries_needed<Register>(), 0);
    bitfield_ = NumTemporariesNeededField::update(bitfield_, value);
  }

  void set_double_temporaries_needed(uint8_t value) {
    DCHECK_EQ(num_temporaries_needed<DoubleRegister>(), 0);
    bitfield_ = NumDoubleTemporariesNeededField::update(bitfield_, value);
  }

  // Require that a specific register is free (and therefore clobberable) by the
  // entry into this node.
  void RequireSpecificTemporary(Register reg) {
    general_temporaries().set(reg);
  }

  void RequireSpecificDoubleTemporary(DoubleRegister reg) {
    double_temporaries().set(reg);
  }

 private:
  template <class Derived, typename... Args>

  static Derived* Allocate(Zone* zone, size_t input_count, Args&&... args) {
    static_assert(
        !Derived::kProperties.can_eager_deopt() ||
            !Derived::kProperties.can_lazy_deopt(),
        "The current deopt info representation, at the end of inputs, requires "
        "that we cannot have both lazy and eager deopts on a node. If we ever "
        "need this, we have to update accessors to check node->properties() "
        "for which deopts are active.");
    constexpr size_t size_before_inputs =
        ExceptionHandlerInfoSize(Derived::kProperties) +
        RegisterSnapshotSize(Derived::kProperties) +
        EagerDeoptInfoSize(Derived::kProperties) +
        LazyDeoptInfoSize(Derived::kProperties);

    static_assert(IsAligned(size_before_inputs, alignof(Input)));
    const size_t size_before_node =
        size_before_inputs + input_count * sizeof(Input);

    DCHECK(IsAligned(size_before_inputs, alignof(Derived)));
    const size_t size = size_before_node + sizeof(Derived);
    intptr_t raw_buffer =
        reinterpret_cast<intptr_t>(zone->Allocate<NodeWithInlineInputs>(size));
#ifdef DEBUG
    memset(reinterpret_cast<void*>(raw_buffer), 0, size);
#endif

    void* node_buffer = reinterpret_cast<void*>(raw_buffer + size_before_node);
    uint64_t bitfield = OpcodeField::encode(opcode_of<Derived>) |
                        OpPropertiesField::encode(Derived::kProperties) |
                        InputCountField::encode(input_count);
    Derived* node =
        new (node_buffer) Derived(bitfield, std::forward<Args>(args)...);
    return node;
  }

  static constexpr size_t ExceptionHandlerInfoSize(OpProperties properties) {
    return RoundUp<alignof(Input)>(
        properties.can_throw() ? sizeof(ExceptionHandlerInfo) : 0);
  }

  static constexpr size_t RegisterSnapshotSize(OpProperties properties) {
    return RoundUp<alignof(Input)>(
        properties.needs_register_snapshot() ? sizeof(RegisterSnapshot) : 0);
  }

  static constexpr size_t EagerDeoptInfoSize(OpProperties properties) {
    return RoundUp<alignof(Input)>(
        (properties.can_eager_deopt() || properties.is_deopt_checkpoint())
            ? sizeof(EagerDeoptInfo)
            : 0);
  }

  static constexpr size_t LazyDeoptInfoSize(OpProperties properties) {
    return RoundUp<alignof(Input)>(
        properties.can_lazy_deopt() ? sizeof(LazyDeoptInfo) : 0);
  }

  // Returns the position of deopt info if it exists, otherwise returns
  // its position as if DeoptInfo size were zero.
  Address deopt_info_address() const {
    DCHECK(!properties().can_eager_deopt() || !properties().can_lazy_deopt());
    size_t extra =
        EagerDeoptInfoSize(properties()) + LazyDeoptInfoSize(properties());
    return last_input_address() - extra;
  }

  // Returns the position of register snapshot if it exists, otherwise returns
  // its position as if RegisterSnapshot size were zero.
  Address register_snapshot_address() const {
    size_t extra = RegisterSnapshotSize(properties());
    return deopt_info_address() - extra;
  }

  // Returns the position of exception handler info if it exists, otherwise
  // returns its position as if ExceptionHandlerInfo size were zero.
  Address exception_handler_address() const {
    size_t extra = ExceptionHandlerInfoSize(properties());
    return register_snapshot_address() - extra;
  }

  void CheckCanOverwriteWith(Opcode new_opcode, OpProperties new_properties);

  uint64_t bitfield_;
  NodeIdT id_ = kInvalidNodeId;

  struct OwnerOrTemporaries {
    BasicBlock* owner() const {
      DCHECK_NE(store_.owner_, nullptr);
      DCHECK_EQ(state_, State::kOwner);
      return store_.owner_;
    }

    template <typename RegisterT>
    RegListBase<RegisterT>& temporaries() {
      DCHECK_EQ(state_, State::kReglist);
      if constexpr (std::is_same_v<RegisterT, Register>) {
        return store_.regs_.temporaries_;
      } else {
        return store_.regs_.double_temporaries_;
      }
    }

    BasicBlock* operator=(BasicBlock* owner) {
#ifdef DEBUG
      DCHECK(state_ == State::kNull || state_ == State::kOwner);
      state_ = State::kOwner;
#endif
      return store_.owner_ = owner;
    }

    void InitReglist() {
#ifdef DEBUG
      DCHECK(state_ == State::kNull || state_ == State::kOwner);
      state_ = State::kReglist;
#endif
      store_.regs_.temporaries_ = RegList();
      store_.regs_.double_temporaries_ = DoubleRegList();
    }

   private:
    struct Regs {
      RegList temporaries_;
      DoubleRegList double_temporaries_;
    };
    union Store {
      Store() : owner_(nullptr) {}
      BasicBlock* owner_;
      Regs regs_;
    };
    Store store_;
#ifdef DEBUG
    enum class State{
        kNull,
        kOwner,
        kReglist,
    };
    State state_ = State::kNull;
#endif
  };

  OwnerOrTemporaries owner_or_temporaries_;

  NodeBase() = delete;
  NodeBase(const NodeBase&) = delete;
  NodeBase(NodeBase&&) = delete;
  NodeBase& operator=(const NodeBase&) = delete;
  NodeBase& operator=(NodeBase&&) = delete;
};

template <class T>
constexpr bool NodeBase::Is() const {
  return opcode() == opcode_of<T>;
}

// Specialized sub-hierarchy type checks.
template <>
constexpr bool NodeBase::Is<ValueNode>() const {
  return IsValueNode(opcode());
}
template <>
constexpr bool NodeBase::Is<ControlNode>() const {
  return IsControlNode(opcode());
}
template <>
constexpr bool NodeBase::Is<BranchControlNode>() const {
  return IsBranchControlNode(opcode());
}
template <>
constexpr bool NodeBase::Is<ConditionalControlNode>() const {
  return IsConditionalControlNode(opcode());
}
template <>
constexpr bool NodeBase::Is<UnconditionalControlNode>() const {
  return IsUnconditionalControlNode(opcode());
}
template <>
constexpr bool NodeBase::Is<TerminalControlNode>() const {
  return IsTerminalControlNode(opcode());
}

void CheckValueInputIs(const NodeBase* node, int i,
                       ValueRepresentation expected,
                       MaglevGraphLabeller* graph_labeller);

// The Node class hierarchy contains all non-control nodes.
class Node : public NodeBase {
 public:
  using List = base::ThreadedListWithUnsafeInsertions<Node>;

  inline ValueLocation& result();

  Node* NextNode() const { return next_; }

  static constexpr bool participate_in_cse(Opcode op) {
    return StaticPropertiesForOpcode(op).can_participate_in_cse() &&
           !IsConstantNode(op) && !IsControlNode(op) && !IsZeroCostNode(op) &&
           // The following are already precisely tracked by known_node_aspects
           // and tracking them with CSE would just waste time.
           op != Opcode::kCheckMaps;
  }

  static constexpr bool needs_epoch_check(Opcode op) {
    return StaticPropertiesForOpcode(op).can_read();
  }

 protected:
  using NodeBase::NodeBase;

 private:
  Node** next() { return &next_; }
  Node* next_ = nullptr;

  friend List;
  friend base::ThreadedListTraits<Node>;
};

// All non-control nodes with a result.
class ValueNode : public Node {
 private:
  using TaggedResultNeedsDecompressField = NodeBase::ReservedField;

 protected:
  using ReservedField = void;

 public:
  ValueLocation& result() { return result_; }
  const ValueLocation& result() const { return result_; }

  int use_count() const {
    // Invalid to check use_count externally once an id is allocated.
    DCHECK(!has_id());
    return use_count_;
  }
  bool is_used() const { return use_count_ > 0; }
  bool unused_inputs_were_visited() const { return use_count_ == -1; }
  void add_use() {
    // Make sure a saturated use count won't overflow.
    DCHECK_LT(use_count_, kMaxInt);
    use_count_++;
  }
  void remove_use() {
    // Make sure a saturated use count won't drop below zero.
    DCHECK_GT(use_count_, 0);
    use_count_--;
  }
  // Avoid revisiting nodes when processing an unused node's inputs, by marking
  // it as visited.
  void mark_unused_inputs_visited() {
    DCHECK_EQ(use_count_, 0);
    use_count_ = -1;
  }

  void SetHint(compiler::InstructionOperand hint);

  void ClearHint() { hint_ = compiler::InstructionOperand(); }

  bool has_hint() { return !hint_.IsInvalid(); }

  template <typename RegisterT>
  RegisterT GetRegisterHint() {
    if (hint_.IsInvalid()) return RegisterT::no_reg();
    return RegisterT::from_code(
        compiler::UnallocatedOperand::cast(hint_).fixed_register_index());
  }

  const compiler::InstructionOperand& hint() const {
    DCHECK(hint_.IsInvalid() || hint_.IsUnallocated());
    return hint_;
  }

  bool is_loadable() const {
    DCHECK_EQ(state_, kSpill);
    return spill_.IsConstant() || spill_.IsAnyStackSlot();
  }

  bool is_spilled() const {
    DCHECK_EQ(state_, kSpill);
    return spill_.IsAnyStackSlot();
  }

  void SetNoSpill();
  void SetConstantLocation();

  /* For constants only. */
  void LoadToRegister(MaglevAssembler*, Register);
  void LoadToRegister(MaglevAssembler*, DoubleRegister);
  void DoLoadToRegister(MaglevAssembler*, Register);
  void DoLoadToRegister(MaglevAssembler*, DoubleRegister);
  Handle<Object> Reify(LocalIsolate* isolate) const;

  size_t GetInputLocationsArraySize() const;

  void Spill(compiler::AllocatedOperand operand) {
#ifdef DEBUG
    if (state_ == kLastUse) {
      state_ = kSpill;
    } else {
      DCHECK(!is_loadable());
    }
#endif  // DEBUG
    DCHECK(!IsConstantNode(opcode()));
    DCHECK(operand.IsAnyStackSlot());
    spill_ = operand;
    DCHECK(spill_.IsAnyStackSlot());
  }

  compiler::AllocatedOperand spill_slot() const {
    DCHECK(is_spilled());
    return compiler::AllocatedOperand::cast(loadable_slot());
  }

  compiler::InstructionOperand loadable_slot() const {
    DCHECK_EQ(state_, kSpill);
    DCHECK(is_loadable());
    return spill_;
  }

  void record_next_use(NodeIdT id, InputLocation* input_location) {
    DCHECK_EQ(state_, kLastUse);
    DCHECK_NE(id, kInvalidNodeId);
    DCHECK_LT(start_id(), id);
    DCHECK_IMPLIES(has_valid_live_range(), id >= end_id_);
    end_id_ = id;
    *last_uses_next_use_id_ = id;
    last_uses_next_use_id_ = input_location->get_next_use_id_address();
    DCHECK_EQ(*last_uses_next_use_id_, kInvalidNodeId);
  }

  struct LiveRange {
    NodeIdT start = kInvalidNodeId;
    NodeIdT end = kInvalidNodeId;  // Inclusive.
  };

  bool has_valid_live_range() const { return end_id_ != 0; }
  LiveRange live_range() const { return {start_id(), end_id_}; }
  NodeIdT current_next_use() const { return next_use_; }

  // The following metods should only be used during register allocation, to
  // mark the _current_ state of this Node according to the register allocator.
  void advance_next_use(NodeIdT use) { next_use_ = use; }

  bool has_no_more_uses() const { return next_use_ == kInvalidNodeId; }

  constexpr bool use_double_register() const {
    return IsDoubleRepresentation(properties().value_representation());
  }

  constexpr bool is_tagged() const {
    return (properties().value_representation() ==
            ValueRepresentation::kTagged);
  }

#ifdef V8_COMPRESS_POINTERS
  constexpr bool decompresses_tagged_result() const {
    return TaggedResultNeedsDecompressField::decode(bitfield());
  }

  void SetTaggedResultNeedsDecompress() {
    static_assert(PointerCompressionIsEnabled());

    DCHECK_IMPLIES(!Is<Identity>(), is_tagged());
    DCHECK_IMPLIES(Is<Identity>(), input(0).node()->is_tagged());
    set_bitfield(TaggedResultNeedsDecompressField::update(bitfield(), true));
    if (Is<Phi>()) {
      for (Input& input : *this) {
        // Avoid endless recursion by terminating on values already marked.
        if (input.node()->decompresses_tagged_result()) continue;
        input.node()->SetTaggedResultNeedsDecompress();
      }
    } else if (Is<Identity>()) {
      DCHECK_EQ(input_count(), 0);
      input(0).node()->SetTaggedResultNeedsDecompress();
    }
  }
#else
  constexpr bool decompresses_tagged_result() const { return false; }
#endif

  constexpr ValueRepresentation value_representation() const {
    return properties().value_representation();
  }

  constexpr MachineRepresentation GetMachineRepresentation() const {
    switch (properties().value_representation()) {
      case ValueRepresentation::kTagged:
        return MachineRepresentation::kTagged;
      case ValueRepresentation::kInt32:
      case ValueRepresentation::kUint32:
        return MachineRepresentation::kWord32;
      case ValueRepresentation::kIntPtr:
        return MachineType::PointerRepresentation();
      case ValueRepresentation::kFloat64:
        return MachineRepresentation::kFloat64;
      case ValueRepresentation::kHoleyFloat64:
        return MachineRepresentation::kFloat64;
    }
  }

  void InitializeRegisterData() {
    if (use_double_register()) {
      double_registers_with_result_ = kEmptyDoubleRegList;
    } else {
      registers_with_result_ = kEmptyRegList;
    }
  }

  void AddRegister(Register reg) {
    DCHECK(!use_double_register());
    registers_with_result_.set(reg);
  }
  void AddRegister(DoubleRegister reg) {
    DCHECK(use_double_register());
    double_registers_with_result_.set(reg);
  }

  void RemoveRegister(Register reg) {
    DCHECK(!use_double_register());
    registers_with_result_.clear(reg);
  }
  void RemoveRegister(DoubleRegister reg) {
    DCHECK(use_double_register());
    double_registers_with_result_.clear(reg);
  }

  template <typename T>
  inline RegListBase<T> ClearRegisters();

  int num_registers() const {
    if (use_double_register()) {
      return double_registers_with_result_.Count();
    }
    return registers_with_result_.Count();
  }
  bool has_register() const {
    if (use_double_register()) {
      return double_registers_with_result_ != kEmptyDoubleRegList;
    }
    return registers_with_result_ != kEmptyRegList;
  }
  bool is_in_register(Register reg) const {
    DCHECK(!use_double_register());
    return registers_with_result_.has(reg);
  }
  bool is_in_register(DoubleRegister reg) const {
    DCHECK(use_double_register());
    return double_registers_with_result_.has(reg);
  }

  template <typename T>
  RegListBase<T> result_registers() {
    if constexpr (std::is_same<T, DoubleRegister>::value) {
      DCHECK(use_double_register());
      return double_registers_with_result_;
    } else {
      DCHECK(!use_double_register());
      return registers_with_result_;
    }
  }

  compiler::InstructionOperand allocation() const {
    if (has_register()) {
      return compiler::AllocatedOperand(compiler::LocationOperand::REGISTER,
                                        GetMachineRepresentation(),
                                        FirstRegisterCode());
    }
    DCHECK(is_loadable());
    return spill_;
  }

 protected:
  explicit ValueNode(uint64_t bitfield)
      : Node(bitfield),
        last_uses_next_use_id_(&next_use_),
        hint_(compiler::InstructionOperand()),
        use_count_(0)
#ifdef DEBUG
        ,
        state_(kLastUse)
#endif  // DEBUG
  {
    InitializeRegisterData();
  }

  int FirstRegisterCode() const {
    if (use_double_register()) {
      return double_registers_with_result_.first().code();
    }
    return registers_with_result_.first().code();
  }

  // Rename for better pairing with `end_id`.
  NodeIdT start_id() const { return id(); }

  NodeIdT end_id_ = kInvalidNodeId;
  NodeIdT next_use_ = kInvalidNodeId;
  ValueLocation result_;
  union {
    RegList registers_with_result_;
    DoubleRegList double_registers_with_result_;
  };
  union {
    // Pointer to the current last use's next_use_id field. Most of the time
    // this will be a pointer to an Input's next_use_id_ field, but it's
    // initialized to this node's next_use_ to track the first use.
    NodeIdT* last_uses_next_use_id_;
    compiler::InstructionOperand spill_;
  };
  compiler::InstructionOperand hint_;
  // TODO(leszeks): Union this into another field.
  int use_count_;
#ifdef DEBUG
  enum {kLastUse, kSpill} state_;
#endif  // DEBUG
};

inline void NodeBase::initialize_input_null(int index) {
  // Should already be null in debug, make sure it's null on release too.
  DCHECK_EQ(input(index).node(), nullptr);
  new (&input(index)) Input(nullptr);
}

inline void NodeBase::set_input(int index, ValueNode* node) {
  DCHECK_NOT_NULL(node);
  DCHECK_EQ(input(index).node(), nullptr);
  node->add_use();
  new (&input(index)) Input(node);
}

inline void NodeBase::change_input(int index, ValueNode* node) {
  DCHECK_NE(input(index).node(), nullptr);
  input(index).node()->remove_use();

#ifdef DEBUG
  input(index) = Input(nullptr);
#endif
  set_input(index, node);
}

template <>
inline RegList ValueNode::ClearRegisters() {
  DCHECK(!use_double_register());
  return std::exchange(registers_with_result_, kEmptyRegList);
}

template <>
inline DoubleRegList ValueNode::ClearRegisters() {
  DCHECK(use_double_register());
  return std::exchange(double_registers_with_result_, kEmptyDoubleRegList);
}

ValueLocation& Node::result() {
  DCHECK(Is<ValueNode>());
  return Cast<ValueNode>()->result();
}

// Mixin for a node with known class (and therefore known opcode and static
// properties), but possibly unknown numbers of inputs.
template <typename Base, typename Derived>
class NodeTMixin : public Base {
 public:
  // Shadowing for static knowledge.
  constexpr Opcode opcode() const { return NodeBase::opcode_of<Derived>; }
  constexpr const OpProperties& properties() const {
    return Derived::kProperties;
  }

  template <typename... Args>
  static Derived* New(Zone* zone, std::initializer_list<ValueNode*> inputs,
                      Args&&... args) {
    return NodeBase::New<Derived>(zone, inputs, std::forward<Args>...);
  }
  template <typename... Args>
  static Derived* New(Zone* zone, size_t input_count, Args&&... args) {
    return NodeBase::New<Derived>(zone, input_count, std::forward<Args>...);
  }

 protected:
  template <typename... Args>
  explicit NodeTMixin(uint64_t bitfield, Args&&... args)
      : Base(bitfield, std::forward<Args>(args)...) {
    DCHECK_EQ(this->NodeBase::opcode(), NodeBase::opcode_of<Derived>);
    DCHECK_EQ(this->NodeBase::properties(), Derived::kProperties);
  }
};

namespace detail {
// Helper class for defining input types as a std::array, but without
// accidental initialisation with the wrong sized initializer_list.
template <size_t Size>
class ArrayWrapper : public std::array<ValueRepresentation, Size> {
 public:
  template <typename... Args>
  explicit constexpr ArrayWrapper(Args&&... args)
      : std::array<ValueRepresentation, Size>({args...}) {
    static_assert(sizeof...(args) == Size);
  }
};
struct YouNeedToDefineAnInputTypesArrayInYourDerivedClass {};
}  // namespace detail

// Mixin for a node with known class (and therefore known opcode and static
// properties), and known numbers of inputs.
template <size_t InputCount, typename Base, typename Derived>
class FixedInputNodeTMixin : public NodeTMixin<Base, Derived> {
 public:
  static constexpr size_t kInputCount = InputCount;

  // Shadowing for static knowledge.
  constexpr bool has_inputs() const { return input_count() > 0; }
  constexpr uint16_t input_count() const { return kInputCount; }
  constexpr auto end() {
    return std::make_reverse_iterator(&this->input(input_count() - 1));
  }

  void VerifyInputs(MaglevGraphLabeller* graph_labeller) const {
    if constexpr (kInputCount != 0) {
      static_assert(
          std::is_same_v<const InputTypes, decltype(Derived::kInputTypes)>);
      static_assert(kInputCount == Derived::kInputTypes.size());
      for (int i = 0; i < static_cast<int>(kInputCount); ++i) {
        CheckValueInputIs(this, i, Derived::kInputTypes[i], graph_labeller);
      }
    }
  }

#ifdef V8_COMPRESS_POINTERS
  void MarkTaggedInputsAsDecompressing() const {
    if constexpr (kInputCount != 0) {
      static_assert(
          std::is_same_v<const InputTypes, decltype(Derived::kInputTypes)>);
      static_assert(kInputCount == Derived::kInputTypes.size());
      for (int i = 0; i < static_cast<int>(kInputCount); ++i) {
        if (Derived::kInputTypes[i] == ValueRepresentation::kTagged) {
          ValueNode* input_node = this->input(i).node();
          input_node->SetTaggedResultNeedsDecompress();
        }
      }
    }
  }
#endif

 protected:
  using InputTypes = detail::ArrayWrapper<kInputCount>;
  detail::YouNeedToDefineAnInputTypesArrayInYourDerivedClass kInputTypes;

  template <typename... Args>
  explicit FixedInputNodeTMixin(uint64_t bitfield, Args&&... args)
      : NodeTMixin<Base, Derived>(bitfield, std::forward<Args>(args)...) {
    DCHECK_EQ(this->NodeBase::input_count(), kInputCount);
  }
};

template <class T, class = void>
struct IsFixedInputNode : public std::false_type {};
template <class T>
struct IsFixedInputNode<T, std::void_t<decltype(T::kInputCount)>>
    : public std::true_type {};

template <class Derived>
using NodeT = NodeTMixin<Node, Derived>;

template <class Derived>
using ValueNodeT = NodeTMixin<ValueNode, Derived>;

template <size_t InputCount, class Derived>
using FixedInputNodeT =
    FixedInputNodeTMixin<InputCount, NodeT<Derived>, Derived>;

template <size_t InputCount, class Derived>
using FixedInputValueNodeT =
    FixedInputNodeTMixin<InputCount, ValueNodeT<Derived>, Derived>;

class Identity : public FixedInputValueNodeT<1, Identity> {
  using Base = FixedInputValueNodeT<1, Identity>;

 public:
  static constexpr OpProperties kProperties = OpProperties::Pure();

  explicit Identity(uint64_t bitfield) : Base(bitfield) {}

  void VerifyInputs(MaglevGraphLabeller*) const {
    // Identity is valid for all input types.
  }
#ifdef V8_COMPRESS_POINTERS
  void MarkTaggedInputsAsDecompressing() {
    // Do not mark inputs as decompressing here, since we don't yet know whether
    // this Phi needs decompression. Instead, let
    // Node::SetTaggedResultNeedsDecompress pass through phis.
  }
#endif
  void SetValueLocationConstraints() {}
  void GenerateCode(MaglevAssembler*, const ProcessingState&) {}
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

template <class Derived, Operation kOperation>
class UnaryWithFeedbackNode : public FixedInputValueNodeT<1, Derived> {
  using Base = FixedInputValueNodeT<1, Derived>;

 public:
  // The implementation currently calls runtime.
  static constexpr OpProperties kProperties = OpProperties::JSCall();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  static constexpr int kOperandIndex = 0;
  Input& operand_input() { return Node::input(kOperandIndex); }
  compiler::FeedbackSource feedback() const { return feedback_; }

 protected:
  explicit UnaryWithFeedbackNode(uint64_t bitfield,
                                 const compiler::FeedbackSource& feedback)
      : Base(bitfield), feedback_(feedback) {}

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}

  const compiler::FeedbackSource feedback_;
};

template <class Derived, Operation kOperation>
class BinaryWithFeedbackNode : public FixedInputValueNodeT<2, Derived> {
  using Base = FixedInputValueNodeT<2, Derived>;

 public:
  // The implementation currently calls runtime.
  static constexpr OpProperties kProperties = OpProperties::JSCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  static constexpr int kLeftIndex = 0;
  static constexpr int kRightIndex = 1;
  Input& left_input() { return Node::input(kLeftIndex); }
  Input& right_input() { return Node::input(kRightIndex); }
  compile
```
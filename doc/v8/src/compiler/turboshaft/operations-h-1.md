Response:
The user wants a summary of the provided C++ header file `v8/src/compiler/turboshaft/operations.h`.

Here's a breakdown of the file's contents and their purpose:

1. **`OpEffects`**: Defines the side effects an operation can have (read/write memory, allocate, call functions, etc.). This is crucial for compiler optimizations like reordering and elimination of operations.
2. **`SaturatedUint8`**: A utility class to track the number of uses of an operation, preventing overflow.
3. **`Operation`**: The base class for all Turboshaft operations. It holds information like opcode, number of inputs, and methods for accessing inputs and effects.
4. **`OperationT`**: A template class that simplifies the definition of specific operation types, providing default implementations for common methods and leveraging static information.
5. **`FixedArityOperationT`**: A template for operations with a fixed number of inputs, further simplifying their definition.
6. **Macros and Structures for Supported Operations**:  Defines a list of specific operations like floating-point arithmetic, integer operations, and bitwise operations.
7. **`DeadOp`**: A special operation to mark dead code.
8. **`AbortCSADcheckOp`**: An operation used for debugging and verification.
9. **`GenericBinopOp` and `GenericUnopOp`**: Operations for generic binary and unary operations, often used for high-level IR.
10. **`ToNumberOrNumericOp`**:  An operation related to JavaScript's type conversion.
11. **`Word32SignHintOp`**: An operation used to provide type hints during compilation.
12. **`WordBinopOp`**: Operations for word-level binary operations.

Considering this is part 2 of 11, it likely focuses on the core structure and some basic operations.

**Plan:**
* Summarize the main purpose of `operations.h`.
* Highlight the key classes and their roles.
* Explain how this part contributes to the overall Turboshaft compilation pipeline.
这是 `v8/src/compiler/turboshaft/operations.h` 源代码的第二部分，它主要定义了 **Turboshaft 编译器中间表示 (IR) 中的操作 (Operations)** 及其相关的元数据和工具类。

**主要功能归纳:**

1. **定义操作的副作用 (`OpEffects`)**:  这部分代码定义了 `OpEffects` 类，用于精确描述一个操作可能产生的副作用，例如是否可以读取内存、写入内存、分配内存、改变控制流、依赖检查等。这些信息对于编译器的各种优化（如死代码消除、指令调度等）至关重要。

2. **定义饱和计数器 (`SaturatedUint8`)**:  `SaturatedUint8` 类用于跟踪操作的使用次数，并防止计数器溢出。这有助于编译器了解哪些操作是冗余的或可以安全地移除。

3. **定义通用的操作基类 (`Operation`)**:  `Operation` 是所有 Turboshaft 操作的基类。它包含操作码 (`opcode`)、输入数量和访问输入的方法。它还提供了判断操作类型、获取操作效果等通用功能。

4. **定义操作的模板基类 (`OperationT` 和 `FixedArityOperationT`)**:  为了简化具体操作的定义，代码提供了模板基类 `OperationT` 和 `FixedArityOperationT`。`OperationT` 提供了基于模板的通用实现，而 `FixedArityOperationT` 专门用于具有固定数量输入的操作。

5. **列举和支持特定的操作**:  代码中通过 `SUPPORTED_OPERATIONS_LIST` 宏列举了一系列 Turboshaft 支持的特定操作，例如浮点数运算 (`Float32RoundDown`, `Float64RoundUp` 等)、整数运算 (`Int32DivIsSafe`)、位运算 (`Word32Ctz`) 和选择操作 (`Float32Select`) 等。`SupportedOperations` 类用于查询当前是否支持某些特定的操作。

6. **定义特殊的占位操作 (`DeadOp`)**: `DeadOp` 用于标记已被消除或不可达的操作。

7. **定义调试辅助操作 (`AbortCSADcheckOp`)**: `AbortCSADcheckOp` 似乎是一个用于在编译过程中进行断言或检查的辅助操作。

8. **定义通用算术和逻辑操作 (`GenericBinopOp`, `GenericUnopOp`)**:  `GenericBinopOp` 和 `GenericUnopOp` 定义了通用的二元和一元操作，可以代表多种具体的算术和逻辑运算。

9. **定义类型转换操作 (`ToNumberOrNumericOp`)**:  `ToNumberOrNumericOp` 用于表示将 JavaScript 对象转换为数字或数值类型的操作。

10. **定义类型提示操作 (`Word32SignHintOp`)**: `Word32SignHintOp` 用于在编译过程中提供关于 32 位值的符号信息，帮助优化。

11. **定义机器字级别的二元操作 (`WordBinopOp`)**: `WordBinopOp` 定义了机器字级别的二元操作，例如加法、乘法、位运算等。

**关于 JavaScript 功能的关系:**

虽然这个头文件本身是用 C++ 编写的，但它定义的操作直接对应于 JavaScript 代码执行过程中可能出现的各种运算和操作。例如：

* **`GenericBinopOp` 的各种 `Kind` (如 `kAdd`, `kMultiply`)**:  对应 JavaScript 中的 `+`, `*` 等二元运算符。
* **`GenericUnopOp` 的各种 `Kind` (如 `kBitwiseNot`, `kNegate`)**: 对应 JavaScript 中的 `~`, `-` 等一元运算符。
* **`ToNumberOrNumericOp`**:  对应 JavaScript 中将非数字类型转换为数字的操作，例如 `Number("123")` 或 `+"456"`.

**JavaScript 示例:**

```javascript
let a = 10;
let b = 5;
let sum = a + b; // 可能对应 Turboshaft 中的一个 GenericBinopOp，Kind 为 kAdd

let notA = ~a;  // 可能对应 Turboshaft 中的一个 GenericUnopOp，Kind 为 kBitwiseNot

let str = "789";
let num = +str; // 可能对应 Turboshaft 中的一个 ToNumberOrNumericOp
```

**代码逻辑推理 (假设输入与输出):**

考虑 `WordBinopOp` 中的 `kAdd` 操作。

**假设输入:**
* `left`:  一个表示值为 5 的 `Word32` 类型的 `OpIndex`。
* `right`: 一个表示值为 10 的 `Word32` 类型的 `OpIndex`。
* `kind`: `WordBinopOp::Kind::kAdd`
* `rep`: `RegisterRepresentation::Word32()`

**预期输出:**
该操作的结果将是一个新的 `OpIndex`，表示值为 15 的 `Word32` 类型。

**用户常见的编程错误 (与 `OpEffects` 相关):**

用户在编写 JavaScript 代码时，可能会无意中触发一些具有副作用的操作，而编译器需要正确地理解这些副作用以进行优化。一个常见的错误是**不必要的函数调用或对象创建**。

**例子:**

```javascript
function potentiallyExpensiveOperation() {
  console.log("This operation has side effects"); // 假设有副作用
  return new Date(); // 创建新对象
}

let x = 10;
// 即使 y 的值可能不会被使用，但 potentiallyExpensiveOperation 仍然会被调用
let y = (someCondition ? 1 : potentiallyExpensiveOperation());
let z = x + 5;
```

在这个例子中，即使 `someCondition` 为真，`potentiallyExpensiveOperation` 仍然可能被调用，这涉及到副作用（`console.log`）和内存分配（`new Date()`）。Turboshaft 的 `OpEffects` 机制可以帮助编译器识别和处理这些副作用，并可能进行优化，例如如果 `y` 的值没有被后续使用，并且 `potentiallyExpensiveOperation` 的副作用可以忽略，则可以考虑消除这次调用。

**总结这部分的功能:**

这部分 `operations.h` 代码是 Turboshaft 编译器的核心组成部分，它定义了 **Turboshaft IR 的基本构建块——操作 (Operations)**，并提供了描述操作属性（如副作用）的机制。它为后续的编译优化和代码生成奠定了基础。这部分代码定义了 Turboshaft 能够表示的各种计算和操作，以及它们可能产生的副作用，这是进行有效编译和优化的关键信息。

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/operations.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/operations.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共11部分，请归纳一下它的功能

"""
on previous checks to avoid deopting.
        .CanDependOnChecks();
  }
  // Producing identity doesn't prevent reorderings, but it prevents GVN from
  // de-duplicating identical operations.
  constexpr OpEffects CanCreateIdentity() const {
    OpEffects result = *this;
    result.can_create_identity = true;
    return result;
  }
  // The set of all possible effects.
  constexpr OpEffects CanCallAnything() const {
    return CanReadMemory()
        .CanWriteMemory()
        .CanAllocate()
        .CanChangeControlFlow()
        .CanDependOnChecks()
        .RequiredWhenUnused();
  }
  constexpr OpEffects RequiredWhenUnused() const {
    OpEffects result = *this;
    result.required_when_unused = true;
    return result;
  }

  // Operations that can be removed if their result is not used. Unused
  // allocations can be removed.
  constexpr bool is_required_when_unused() const {
    return required_when_unused;
  }
  // Operations that can be moved before a preceding branch or check.
  bool hoistable_before_a_branch() const {
    // Since this excludes `CanDependOnChecks()`, most loads actually cannot be
    // hoisted.
    return IsSubsetOf(OpEffects().CanReadMemory());
  }
  // Operations that can be eliminated via value numbering, which means that if
  // there are two identical operations where one dominates the other, then the
  // second can be replaced with the first one. This is safe for deopting or
  // throwing operations, because the absence of read effects guarantees
  // deterministic behavior.
  bool repetition_is_eliminatable() const {
    return IsSubsetOf(OpEffects()
                          .CanDependOnChecks()
                          .CanChangeControlFlow()
                          .CanAllocateWithoutIdentity());
  }
  bool can_read_mutable_memory() const {
    return produces.load_heap_memory | produces.load_off_heap_memory;
  }
  bool requires_consistent_heap() const {
    return produces.before_raw_heap_access | consumes.after_raw_heap_access;
  }
  bool can_write() const {
    return produces.store_heap_memory | produces.store_off_heap_memory;
  }
  bool can_be_constant_folded() const {
    // Operations that CanDependOnChecks can still be constant-folded. If they
    // did indeed depend on a check, then their result will only be used after
    // said check has been executed anyways.
    return IsSubsetOf(OpEffects().CanDependOnChecks());
  }
};
static_assert(sizeof(OpEffects) == sizeof(OpEffects::Bits));

V8_INLINE size_t hash_value(OpEffects effects) {
  return static_cast<size_t>(effects.bits());
}

inline bool CannotSwapOperations(OpEffects first, OpEffects second) {
  return first.produces.bits() & (second.consumes.bits());
}

V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           OpEffects op_effects);

// SaturatedUint8 is a wrapper around a uint8_t, which can be incremented and
// decremented with the `Incr` and `Decr` methods. These methods prevent over-
// and underflow, and saturate once the uint8_t reaches the maximum (255):
// future increment and decrement will not change the value then.
// We purposefuly do not expose the uint8_t directly, so that users go through
// Incr/Decr/SetToZero/SetToOne to manipulate it, so that the saturation and
// lack of over/underflow is always respected.
class SaturatedUint8 {
 public:
  SaturatedUint8() = default;

  void Incr() {
    if (V8_LIKELY(val != kMax)) {
      val++;
    }
  }
  void Decr() {
    if (V8_LIKELY(val != 0 && val != kMax)) {
      val--;
    }
  }

  void SetToZero() { val = 0; }
  void SetToOne() { val = 1; }

  bool IsZero() const { return val == 0; }
  bool IsOne() const { return val == 1; }
  bool IsSaturated() const { return val == kMax; }
  uint8_t Get() const { return val; }

  SaturatedUint8& operator+=(const SaturatedUint8& other) {
    uint32_t sum = val;
    sum += other.val;
    val = static_cast<uint8_t>(std::min<uint32_t>(sum, kMax));
    return *this;
  }

  static SaturatedUint8 FromSize(size_t value) {
    uint8_t val = static_cast<uint8_t>(std::min<size_t>(value, kMax));
    return SaturatedUint8{val};
  }

 private:
  explicit SaturatedUint8(uint8_t val) : val(val) {}
  uint8_t val = 0;
  static constexpr uint8_t kMax = std::numeric_limits<uint8_t>::max();
};

// underlying_operation<> is used to extract the operation type from OpMaskT
// classes used in Operation::Is<> and Operation::TryCast<>.
template <typename T>
struct underlying_operation {
  using type = T;
};
template <typename T, uint64_t M, uint64_t V>
struct underlying_operation<OpMaskT<T, M, V>> {
  using type = T;
};
template <typename T>
using underlying_operation_t = typename underlying_operation<T>::type;

// Baseclass for all Turboshaft operations.
// The `alignas(OpIndex)` is necessary because it is followed by an array of
// `OpIndex` inputs.
struct alignas(OpIndex) Operation {
  struct IdentityMapper {
    OpIndex Map(OpIndex index) { return index; }
    OptionalOpIndex Map(OptionalOpIndex index) { return index; }
    template <size_t N>
    base::SmallVector<OpIndex, N> Map(base::Vector<const OpIndex> indices) {
      return base::SmallVector<OpIndex, N>{indices};
    }
  };

  const Opcode opcode;

  // The number of uses of this operation in the current graph.
  // Instead of overflowing, we saturate the value if it reaches the maximum. In
  // this case, the true number of uses is unknown.
  // We use such a small type to save memory and because nodes with a high
  // number of uses are rare. Additionally, we usually only care if the number
  // of uses is 0, 1 or bigger than 1.
  SaturatedUint8 saturated_use_count;

  const uint16_t input_count;

  // The inputs are stored adjacent in memory, right behind the `Operation`
  // object.
  base::Vector<const OpIndex> inputs() const;
  V8_INLINE OpIndex input(size_t i) const { return inputs()[i]; }

  static size_t StorageSlotCount(Opcode opcode, size_t input_count);
  size_t StorageSlotCount() const {
    return StorageSlotCount(opcode, input_count);
  }

  base::Vector<const RegisterRepresentation> outputs_rep() const;
  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const;

  template <class Op>
  bool Is() const {
    if constexpr (std::is_base_of_v<Operation, Op>) {
      return opcode == Op::opcode;
    } else {
      // Otherwise this must be OpMaskT.
      return IsOpmask<Op>();
    }
  }
  template <class Op>
  underlying_operation_t<Op>& Cast() {
    DCHECK(Is<Op>());
    return *static_cast<underlying_operation_t<Op>*>(this);
  }
  template <class Op>
  const underlying_operation_t<Op>& Cast() const {
    DCHECK(Is<Op>());
    return *static_cast<const underlying_operation_t<Op>*>(this);
  }
  template <class Op>
  const underlying_operation_t<Op>* TryCast() const {
    if (!Is<Op>()) return nullptr;
    return static_cast<const underlying_operation_t<Op>*>(this);
  }
  template <class Op>
  underlying_operation_t<Op>* TryCast() {
    if (!Is<Op>()) return nullptr;
    return static_cast<underlying_operation_t<Op>*>(this);
  }
  OpEffects Effects() const;
  bool IsBlockTerminator() const {
    return turboshaft::IsBlockTerminator(opcode);
  }
  bool IsRequiredWhenUnused() const {
    DCHECK_IMPLIES(IsBlockTerminator(), Effects().is_required_when_unused());
    return Effects().is_required_when_unused();
  }

  std::string ToString() const;
  void PrintInputs(std::ostream& os, const std::string& op_index_prefix) const;
  void PrintOptions(std::ostream& os) const;

  // Returns true if {this} is the only operation using {value}.
  bool IsOnlyUserOf(const Operation& value, const Graph& graph) const;

  void Print() const;

 protected:
  // Operation objects store their inputs behind the object. Therefore, they can
  // only be constructed as part of a Graph.
  explicit Operation(Opcode opcode, size_t input_count)
      : opcode(opcode), input_count(input_count) {
    DCHECK_LE(input_count,
              std::numeric_limits<decltype(this->input_count)>::max());
  }

  template <class OpmaskT>
  // A Turboshaft operation can be as small as 4 Bytes while Opmasks can span up
  // to 8 Bytes. Any mask larger than the operation it is compared with will
  // always have a mismatch in the initialized memory. Still, there can be some
  // uninitialized memory being compared as part of the 8 Byte comparison that
  // this function performs.
  V8_CLANG_NO_SANITIZE("memory") bool IsOpmask() const {
    static_assert(std::is_same_v<
                  underlying_operation_t<OpmaskT>,
                  typename OpMaskT<typename OpmaskT::operation, OpmaskT::mask,
                                   OpmaskT::value>::operation>);
    // We check with the given mask.
    uint64_t b;
    memcpy(&b, this, sizeof(uint64_t));
    b &= OpmaskT::mask;
    return b == OpmaskT::value;
  }

  Operation(const Operation&) = delete;
  Operation& operator=(const Operation&) = delete;
};

struct OperationPrintStyle {
  const Operation& op;
  const char* op_index_prefix = "#";
};

V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           OperationPrintStyle op);
inline std::ostream& operator<<(std::ostream& os, const Operation& op) {
  return os << OperationPrintStyle{op};
}

V8_EXPORT_PRIVATE Zone* get_zone(Graph* graph);

OperationStorageSlot* AllocateOpStorage(Graph* graph, size_t slot_count);
V8_EXPORT_PRIVATE const Operation& Get(const Graph& graph, OpIndex index);

// Determine if an operation declares `effects`, which means that its
// effects are static and don't depend on inputs or options.
template <class Op, class = void>
struct HasStaticEffects : std::bool_constant<false> {};
template <class Op>
struct HasStaticEffects<Op, std::void_t<decltype(Op::effects)>>
    : std::bool_constant<true> {};

// This template knows the complete type of the operation and is plugged into
// the inheritance hierarchy. It removes boilerplate from the concrete
// `Operation` subclasses, defining everything that can be expressed
// generically. It overshadows many methods from `Operation` with ones that
// exploit additional static information.
template <class Derived>
struct OperationT : Operation {
  // Enable concise base-constructor call in derived struct.
  using Base = OperationT;

  static const Opcode opcode;

  static constexpr OpEffects Effects() { return Derived::effects; }
  static constexpr bool IsBlockTerminator() {
    return turboshaft::IsBlockTerminator(opcode);
  }
  bool IsRequiredWhenUnused() const {
    return IsBlockTerminator() ||
           derived_this().Effects().is_required_when_unused();
  }

  static constexpr std::optional<OpEffects> EffectsIfStatic() {
    if constexpr (HasStaticEffects<Derived>::value) {
      return Derived::Effects();
    }
    return std::nullopt;
  }

  Derived& derived_this() { return *static_cast<Derived*>(this); }
  const Derived& derived_this() const {
    return *static_cast<const Derived*>(this);
  }

  // Shadow Operation::inputs to exploit static knowledge about object size.
  base::Vector<OpIndex> inputs() {
    return {reinterpret_cast<OpIndex*>(reinterpret_cast<char*>(this) +
                                       sizeof(Derived)),
            derived_this().input_count};
  }
  base::Vector<const OpIndex> inputs() const {
    return {reinterpret_cast<const OpIndex*>(
                reinterpret_cast<const char*>(this) + sizeof(Derived)),
            derived_this().input_count};
  }

  V8_INLINE OpIndex& input(size_t i) { return derived_this().inputs()[i]; }
  // TODO(chromium:331100916): remove this V<Any> overload once all users use
  // the more specific V<T> overload.
  V8_INLINE V<Any> input(size_t i) const { return derived_this().inputs()[i]; }
  template <typename T>
  V8_INLINE V<T> input(size_t i) const {
    return V<T>::Cast(derived_this().inputs()[i]);
  }

  static size_t StorageSlotCount(size_t input_count) {
    // The operation size in bytes is:
    //   `sizeof(Derived) + input_count*sizeof(OpIndex)`.
    // This is an optimized computation of:
    //   round_up(size_in_bytes / sizeof(StorageSlot))
    constexpr size_t r = sizeof(OperationStorageSlot) / sizeof(OpIndex);
    static_assert(sizeof(OperationStorageSlot) % sizeof(OpIndex) == 0);
    static_assert(sizeof(Derived) % sizeof(OpIndex) == 0);
    size_t result = std::max<size_t>(
        2, (r - 1 + sizeof(Derived) / sizeof(OpIndex) + input_count) / r);
    DCHECK_EQ(result, Operation::StorageSlotCount(opcode, input_count));
    return result;
  }
  size_t StorageSlotCount() const { return StorageSlotCount(input_count); }

  template <class... Args>
  static Derived& New(Graph* graph, size_t input_count, Args... args) {
    OperationStorageSlot* ptr =
        AllocateOpStorage(graph, StorageSlotCount(input_count));
    Derived* result = new (ptr) Derived(args...);
#ifdef DEBUG
    result->Validate(*graph);
    ZoneVector<MaybeRegisterRepresentation> storage(get_zone(graph));
    base::Vector<const MaybeRegisterRepresentation> expected =
        result->inputs_rep(storage);
    // TODO(mliedtke): DCHECK that expected and inputs are of the same size
    // and adapt inputs_rep() to always emit a representation for all inputs.
    size_t end = std::min<size_t>(expected.size(), result->input_count);
    for (size_t i = 0; i < end; ++i) {
      if (expected[i] == MaybeRegisterRepresentation::None()) continue;
      DCHECK(ValidOpInputRep(*graph, result->inputs()[i],
                             RegisterRepresentation(expected[i])));
    }
#endif
    // If this DCHECK fails, then the number of inputs specified in the
    // operation constructor and in the static New function disagree.
    DCHECK_EQ(input_count, result->Operation::input_count);
    return *result;
  }

  template <class... Args>
  static Derived& New(Graph* graph, ShadowyOpIndexVectorWrapper inputs,
                      Args... args) {
    return New(graph, inputs.size(), inputs, args...);
  }

  explicit OperationT(size_t input_count) : Operation(opcode, input_count) {
    static_assert((std::is_base_of<OperationT, Derived>::value));
#if !V8_CC_MSVC
    static_assert(std::is_trivially_copyable<Derived>::value);
#endif  // !V8_CC_MSVC
    static_assert(std::is_trivially_destructible<Derived>::value);
  }
  explicit OperationT(ShadowyOpIndexVectorWrapper inputs)
      : OperationT(inputs.size()) {
    this->inputs().OverwriteWith(
        static_cast<base::Vector<const OpIndex>>(inputs));
  }

  bool EqualsForGVN(const Base& other) const {
    // By default, GVN only removed identical Operations. However, some
    // Operations (like DeoptimizeIf) can be GVNed when a dominating
    // similar-but-not-identical one exists. In that case, the Operation should
    // redefine EqualsForGVN, so that GVN knows which inputs or options of the
    // Operation to ignore (you should also probably redefine hash_value,
    // otherwise GVN won't even try to call EqualsForGVN).
    return derived_this() == other.derived_this();
  }
  bool operator==(const Base& other) const {
    return derived_this().inputs() == other.derived_this().inputs() &&
           derived_this().options() == other.derived_this().options();
  }
  template <typename... Args>
  size_t HashWithOptions(const Args&... args) const {
    return fast_hash_combine(opcode, derived_this().inputs(), args...);
  }
  size_t hash_value(
      HashingStrategy strategy = HashingStrategy::kDefault) const {
    return HashWithOptions(derived_this().options());
  }

  void PrintInputs(std::ostream& os, const std::string& op_index_prefix) const {
    os << "(";
    bool first = true;
    for (OpIndex input : inputs()) {
      if (!first) os << ", ";
      first = false;
      os << op_index_prefix << input.id();
    }
    os << ")";
  }

  void PrintOptions(std::ostream& os) const {
    const auto& options = derived_this().options();
    constexpr size_t options_count =
        std::tuple_size<std::remove_reference_t<decltype(options)>>::value;
    if (options_count == 0) {
      return;
    }
    PrintOptionsHelper(os, options, std::make_index_sequence<options_count>());
  }

  // Check graph invariants for this operation. Will be invoked in debug mode
  // immediately upon construction.
  // Concrete Operator classes are expected to re-define it.
  void Validate(const Graph& graph) const = delete;

 private:
  template <class... T, size_t... I>
  static void PrintOptionsHelper(std::ostream& os,
                                 const std::tuple<T...>& options,
                                 std::index_sequence<I...>) {
    os << "[";
    bool first = true;
    USE(first);
    ((first ? (first = false, os << std::get<I>(options))
            : os << ", " << std::get<I>(options)),
     ...);
    os << "]";
  }

  // All Operations have to define the outputs_rep function, to which
  // Operation::outputs_rep() will forward, based on their opcode. If you forget
  // to define it, then Operation::outputs_rep() would forward to itself,
  // resulting in an infinite loop. To avoid this, we define here in OperationT
  // a private version outputs_rep (with no implementation): if an operation
  // forgets to define outputs_rep, then Operation::outputs_rep() tries to call
  // this private version, which fails at compile time.
  base::Vector<const RegisterRepresentation> outputs_rep() const;

  // Returns a vector of the input representations.
  // The passed in {storage} can be used to store the underlying data.
  // The returned vector might be smaller than the input_count in which case the
  // additional inputs are assumed to have no register representation.
  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const;
};

template <size_t InputCount, class Derived>
struct FixedArityOperationT : OperationT<Derived> {
  // Enable concise base access in derived struct.
  using Base = FixedArityOperationT;

  // Shadow Operation::input_count to exploit static knowledge.
  static constexpr uint16_t input_count = InputCount;

  template <class... Args>
  explicit FixedArityOperationT(Args... args)
      : OperationT<Derived>(InputCount) {
    static_assert(sizeof...(Args) == InputCount, "wrong number of inputs");
    size_t i = 0;
    OpIndex* inputs = this->inputs().begin();
    ((inputs[i++] = args), ...);
  }

  // Redefine the input initialization to tell C++ about the static input size.
  template <class... Args>
  static Derived& New(Graph* graph, Args... args) {
    Derived& result =
        OperationT<Derived>::New(graph, InputCount, std::move(args)...);
    return result;
  }

  template <typename Fn, typename Mapper, size_t... InputI, size_t... OptionI>
  V8_INLINE auto ExplodeImpl(Fn fn, Mapper& mapper,
                             std::index_sequence<InputI...>,
                             std::index_sequence<OptionI...>) const {
    auto options = this->derived_this().options();
    USE(options);
    return fn(mapper.Map(this->input(InputI))...,
              std::get<OptionI>(options)...);
  }

  template <typename Fn, typename Mapper>
  V8_INLINE auto Explode(Fn fn, Mapper& mapper) const {
    return ExplodeImpl(
        fn, mapper, std::make_index_sequence<input_count>(),
        std::make_index_sequence<
            std::tuple_size_v<decltype(this->derived_this().options())>>());
  }
};

#define SUPPORTED_OPERATIONS_LIST(V)                              \
  V(float32_round_down, Float32RoundDown)                         \
  V(float64_round_down, Float64RoundDown)                         \
  V(float32_round_up, Float32RoundUp)                             \
  V(float64_round_up, Float64RoundUp)                             \
  V(float32_round_to_zero, Float32RoundTruncate)                  \
  V(float64_round_to_zero, Float64RoundTruncate)                  \
  V(float32_round_ties_even, Float32RoundTiesEven)                \
  V(float64_round_ties_even, Float64RoundTiesEven)                \
  V(float64_round_ties_away, Float64RoundTiesAway)                \
  V(int32_div_is_safe, Int32DivIsSafe)                            \
  V(uint32_div_is_safe, Uint32DivIsSafe)                          \
  V(word32_shift_is_safe, Word32ShiftIsSafe)                      \
  V(word32_ctz, Word32Ctz)                                        \
  V(word64_ctz, Word64Ctz)                                        \
  V(word64_ctz_lowerable, Word64CtzLowerable)                     \
  V(word32_popcnt, Word32Popcnt)                                  \
  V(word64_popcnt, Word64Popcnt)                                  \
  V(word32_reverse_bits, Word32ReverseBits)                       \
  V(word64_reverse_bits, Word64ReverseBits)                       \
  V(float32_select, Float32Select)                                \
  V(float64_select, Float64Select)                                \
  V(int32_abs_with_overflow, Int32AbsWithOverflow)                \
  V(int64_abs_with_overflow, Int64AbsWithOverflow)                \
  V(word32_rol, Word32Rol)                                        \
  V(word64_rol, Word64Rol)                                        \
  V(word64_rol_lowerable, Word64RolLowerable)                     \
  V(sat_conversion_is_safe, SatConversionIsSafe)                  \
  V(word32_select, Word32Select)                                  \
  V(word64_select, Word64Select)                                  \
  V(float64_to_float16_raw_bits, TruncateFloat64ToFloat16RawBits) \
  V(float16, Float16)

class V8_EXPORT_PRIVATE SupportedOperations {
#define DECLARE_FIELD(name, machine_name) bool name##_;
#define DECLARE_GETTER(name, machine_name)     \
  static bool name() {                         \
    if constexpr (DEBUG_BOOL) {                \
      base::MutexGuard lock(mutex_.Pointer()); \
      DCHECK(initialized_);                    \
    }                                          \
    return instance_.name##_;                  \
  }

 public:
  static void Initialize();
  static bool IsUnalignedLoadSupported(MemoryRepresentation repr);
  static bool IsUnalignedStoreSupported(MemoryRepresentation repr);
  SUPPORTED_OPERATIONS_LIST(DECLARE_GETTER)

 private:
  SUPPORTED_OPERATIONS_LIST(DECLARE_FIELD)

  static bool initialized_;
  static base::LazyMutex mutex_;
  static SupportedOperations instance_;

#undef DECLARE_FIELD
#undef DECLARE_GETTER
};

template <RegisterRepresentation::Enum... reps>
base::Vector<const RegisterRepresentation> RepVector() {
  static constexpr std::array<RegisterRepresentation, sizeof...(reps)>
      rep_array{RegisterRepresentation{reps}...};
  return base::VectorOf(rep_array);
}

template <MaybeRegisterRepresentation::Enum... reps>
base::Vector<const MaybeRegisterRepresentation> MaybeRepVector() {
  static constexpr std::array<MaybeRegisterRepresentation, sizeof...(reps)>
      rep_array{MaybeRegisterRepresentation{reps}...};
  return base::VectorOf(rep_array);
}

#if DEBUG
V8_EXPORT_PRIVATE bool ValidOpInputRep(
    const Graph& graph, OpIndex input,
    std::initializer_list<RegisterRepresentation> expected_rep,
    std::optional<size_t> projection_index = {});
V8_EXPORT_PRIVATE bool ValidOpInputRep(
    const Graph& graph, OpIndex input, RegisterRepresentation expected_rep,
    std::optional<size_t> projection_index = {});
#endif  // DEBUG

// DeadOp is a special operation that can be used by analyzers to mark
// operations as being dead (typically, it should be used by calling the Graph's
// KillOperation method, which will Replace the old operation by a DeadOp).
// CopyingPhase and Analyzers should ignore Dead operations. A Dead operation
// should never be the input of a non-dead operation.
struct DeadOp : FixedArityOperationT<0, DeadOp> {
  static constexpr OpEffects effects = OpEffects();

  base::Vector<const RegisterRepresentation> outputs_rep() const { return {}; }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return {};
  }

  void Validate(const Graph& graph) const {}
  auto options() const { return std::tuple{}; }
};

struct AbortCSADcheckOp : FixedArityOperationT<1, AbortCSADcheckOp> {
  static constexpr OpEffects effects =
      OpEffects().RequiredWhenUnused().CanLeaveCurrentFunction();

  base::Vector<const RegisterRepresentation> outputs_rep() const { return {}; }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Tagged()>();
  }

  V<String> message() const { return Base::input<String>(0); }

  explicit AbortCSADcheckOp(V<String> message) : Base(message) {}

  void Validate(const Graph& graph) const {}
  auto options() const { return std::tuple{}; }
};

struct GenericBinopOp : FixedArityOperationT<4, GenericBinopOp> {
#define GENERIC_BINOP_LIST(V) \
  V(Add)                      \
  V(Multiply)                 \
  V(Subtract)                 \
  V(Divide)                   \
  V(Modulus)                  \
  V(Exponentiate)             \
  V(BitwiseAnd)               \
  V(BitwiseOr)                \
  V(BitwiseXor)               \
  V(ShiftLeft)                \
  V(ShiftRight)               \
  V(ShiftRightLogical)        \
  V(Equal)                    \
  V(StrictEqual)              \
  V(LessThan)                 \
  V(LessThanOrEqual)          \
  V(GreaterThan)              \
  V(GreaterThanOrEqual)
  enum class Kind : uint8_t {
#define DEFINE_KIND(Name) k##Name,
    GENERIC_BINOP_LIST(DEFINE_KIND)
#undef DEFINE_KIND
  };
  Kind kind;

  static constexpr OpEffects effects = OpEffects().CanCallAnything();

  THROWING_OP_BOILERPLATE(RegisterRepresentation::Tagged())

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Tagged(),
                          MaybeRegisterRepresentation::Tagged()>();
  }

  V<Object> left() const { return input<Object>(0); }
  V<Object> right() const { return input<Object>(1); }
  V<FrameState> frame_state() const { return input<FrameState>(2); }
  V<Context> context() const { return input<Context>(3); }

  GenericBinopOp(V<Object> left, V<Object> right, V<FrameState> frame_state,
                 V<Context> context, Kind kind,
                 LazyDeoptOnThrow lazy_deopt_on_throw)
      : Base(left, right, frame_state, context),
        kind(kind),
        lazy_deopt_on_throw(lazy_deopt_on_throw) {}

  void Validate(const Graph& graph) const {}
  auto options() const { return std::tuple{kind, lazy_deopt_on_throw}; }
};
V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           GenericBinopOp::Kind kind);

struct GenericUnopOp : FixedArityOperationT<3, GenericUnopOp> {
#define GENERIC_UNOP_LIST(V) \
  V(BitwiseNot)              \
  V(Negate)                  \
  V(Increment)               \
  V(Decrement)
  enum class Kind : uint8_t {
#define DEFINE_KIND(Name) k##Name,
    GENERIC_UNOP_LIST(DEFINE_KIND)
#undef DEFINE_KIND
  };
  Kind kind;

  static constexpr OpEffects effects = OpEffects().CanCallAnything();

  THROWING_OP_BOILERPLATE(RegisterRepresentation::Tagged())

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Tagged()>();
  }

  V<Object> input() const { return Base::input<Object>(0); }
  V<FrameState> frame_state() const { return Base::input<FrameState>(1); }
  V<Context> context() const { return Base::input<Context>(2); }

  GenericUnopOp(V<Object> input, V<FrameState> frame_state, V<Context> context,
                Kind kind, LazyDeoptOnThrow lazy_deopt_on_throw)
      : Base(input, frame_state, context),
        kind(kind),
        lazy_deopt_on_throw(lazy_deopt_on_throw) {}

  void Validate(const Graph& graph) const {}
  auto options() const { return std::tuple{kind, lazy_deopt_on_throw}; }
};
V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           GenericUnopOp::Kind kind);

struct ToNumberOrNumericOp : FixedArityOperationT<3, ToNumberOrNumericOp> {
  Object::Conversion kind;

  static constexpr OpEffects effects = OpEffects().CanCallAnything();

  THROWING_OP_BOILERPLATE(RegisterRepresentation::Tagged())

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Tagged()>();
  }

  V<Object> input() const { return Base::input<Object>(0); }
  OpIndex frame_state() const { return Base::input(1); }
  V<Context> context() const { return Base::input<Context>(2); }

  ToNumberOrNumericOp(V<Object> input, OpIndex frame_state, V<Context> context,
                      Object::Conversion kind,
                      LazyDeoptOnThrow lazy_deopt_on_throw)
      : Base(input, frame_state, context),
        kind(kind),
        lazy_deopt_on_throw(lazy_deopt_on_throw) {}

  void Validate(const Graph& graph) const {}
  auto options() const { return std::tuple{kind, lazy_deopt_on_throw}; }
};

// Word32SignHint is a type-hint used during Maglev->Turboshaft
// translation to avoid having multiple values being used as both Int32 and
// Uint32: for such cases, Maglev has explicit conversions, and it's helpful to
// also have them in Turboshaft. Eventually, Word32SignHint is just a
// nop in Turboshaft, since as far as Machine level graph is concerned, both
// Int32 and Uint32 are just Word32 registers.
struct Word32SignHintOp : FixedArityOperationT<1, Word32SignHintOp> {
  enum class Sign : bool { kSigned, kUnsigned };
  Sign sign;

  static constexpr OpEffects effects = OpEffects();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    return RepVector<RegisterRepresentation::Word32()>();
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return MaybeRepVector<MaybeRegisterRepresentation::Word32()>();
  }

  V<Word32> input() const { return Base::input<Word32>(0); }

  Word32SignHintOp(V<Word32> input, Sign sign) : Base(input), sign(sign) {}

  void Validate(const Graph& graph) const {}
  auto options() const { return std::tuple{sign}; }
};
V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           Word32SignHintOp::Sign sign);

struct WordBinopOp : FixedArityOperationT<2, WordBinopOp> {
  enum class Kind : uint8_t {
    kAdd,
    kMul,
    kSignedMulOverflownBits,
    kUnsignedMulOverflownBits,
    kBitwiseAnd,
    kBitwiseOr,
    kBitwiseXor,
    kSub,
    kSignedDiv,
    kUnsignedDiv,
    kSignedMod,
    kUnsignedMod,
  };
  Kind kind;
  WordRepresentation rep;

  // We must avoid division by 0.
  static constexpr OpEffects effects = OpEffects().CanDependOnChecks();
  base::Vector<const RegisterRepresentation> outputs_rep() const {
    return base::VectorOf(static_cast<const RegisterRepresentation*>(&rep), 1);
  }

  base::Vector<const MaybeRegisterRepresentation> inputs_rep(
      ZoneVector<MaybeRegisterRepresentation>& storage) const {
    return InputsRepFactory::PairOf(rep);
  }

  template <class WordType = Word,
            typename = std::enable_if_t<IsWord<WordType>()>>
  V<WordType> left() const {
    return input<WordType>(0);
  }
  template <class WordType = Word,
            typename = std::enable_if_t<IsWord<WordType>()>>
  V<WordType> right() const {
    return input<WordType>(1);
  }

  bool IsCommutative() const { return IsCommutative(kind); }

  static bool IsCommutative(Kind kind) {
    switch (kind) {
      case Kind::kAdd:
      case Kind::kMul:
      case Kind::kSignedMulOverflownBits:
      case Kind::kUnsignedMulOverflownBits:
      case Kind::kBitwiseAnd:
      case Kind::kBitwiseOr:
      case Kind::kBitwiseXor:
        return true;
      case Kind::kSub:
      case Kind::kSignedDiv:
      case Kind::kUnsignedDiv:
      case Kind::kSignedMod:
      case Kind::kUnsignedMod:
        return false;
    }
  }

  static bool IsAssociative(Kind kind) {
    switch (kind) {
      case Kind::kAdd:
      case Kind::kMul:
      case Kind::kBitwiseAnd:
      case Kind::kBitwiseOr:
      case Kind::kBitwiseXor:
        return true;
      case Kind::kSignedMulOverflownBits:
      case Kind::kUnsignedMulOverflownBits:
      case Kind::kSub:
      case Kind::kSignedDiv:
      case Kind::kUnsignedDiv:
      case Kind::kSignedMod:
      case Kind::kUnsignedMod:
        return false;
    }
  }
  // The Word32 and Word64 versions of the operator compute the same result w
"""


```
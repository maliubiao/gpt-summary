Response:
Let's break down the thought process for analyzing the provided C++ header file excerpt.

**1. Initial Understanding and Context:**

The first step is to recognize this is a C++ header file (`.h`). The path `v8/src/maglev/maglev-ir.h` gives context: it's part of the V8 JavaScript engine, specifically related to the "Maglev" compiler and its intermediate representation ("IR"). This immediately suggests the file defines data structures and interfaces for representing operations within the Maglev compiler.

**2. Identifying Core Structures: Classes and their Relationships:**

The most prominent elements are the C++ classes. The `class` keyword signals these are blueprints for creating objects. Notice the inheritance pattern: many classes inherit from `FixedInputValueNodeT` or `FixedInputNodeT`. This suggests a hierarchical structure for representing different types of nodes in the IR graph. The "T" in the base class names likely indicates they are templates, allowing for parameterization (like the number of inputs).

**3. Analyzing Individual Classes: Purpose and Functionality:**

For each class, examine its members:

* **Constructor:**  What parameters does it take?  This often reveals key data associated with the operation. The `bitfield` is common, likely used for storing flags or metadata.
* **`kProperties`:** This static member of type `OpProperties` is crucial. It defines characteristics of the operation (e.g., `LazyDeopt`, `DeferredCall`, `CanRead`, `CanWrite`). Understanding these properties is key to understanding the operation's behavior during compilation and execution.
* **`kInputTypes`:**  This static member defines the expected data types of the inputs to the operation. This is important for type checking and code generation.
* **Input Accessors (e.g., `object_input()`, `index_input()`):**  These methods provide access to the inputs of the node, revealing the data the operation works on. The naming often gives clues about the input's role.
* **`GenerateCode()`:** This method is essential. It indicates how the IR node is translated into actual machine code.
* **`PrintParams()`:** This suggests debugging or logging functionality, allowing the IR to be visualized.
* **`options()`:**  Often returns a tuple of key parameters, useful for identifying specific instances of the operation.
* **Other Members:**  Look for specific data members (like `offset_`, `shared_function_info_`, `prototype_`) which provide additional context.

**4. Grouping and Categorizing Functionality:**

As you analyze the classes, look for patterns and common themes:

* **Memory Access:** Several classes deal with loading data from memory (e.g., `LoadTaggedField`, `LoadDoubleField`, `LoadFixedArrayElement`). The variations (e.g., "Tagged," "Double," "FixedArray") indicate the type of data being accessed.
* **Type Checking:** Classes like `CheckedInternalizedString` and `CheckedObjectToIndex` explicitly perform type checks.
* **Function Calls:** `FunctionEntryStackCheck` represents a function entry check.
* **String Operations:** `BuiltinStringFromCharCode` and `BuiltinStringPrototypeCharCodeOrCodePointAt` are clearly related to string manipulation.
* **Property Access:** `LoadTaggedFieldForProperty` is specific to accessing object properties.
* **Array Operations:**  Several classes deal with accessing and manipulating arrays (e.g., `LoadFixedArrayElement`, `StoreFixedArrayElementWithWriteBarrier`, `MaybeGrowFastElements`).
* **Data Views:** `LoadSignedIntDataViewElement` and `LoadDoubleDataViewElement` handle typed arrays.

**5. Identifying Key Concepts:**

Certain terms and patterns recur:

* **"Tagged":**  Indicates a value that can be either a small integer (Smi) or a pointer to an object on the heap.
* **"Deopt":**  Short for "deoptimization," a process of falling back from optimized code to a less optimized version when assumptions are violated. `EagerDeopt` and `LazyDeopt` indicate when this can happen.
* **"DeferredCall":**  Indicates that the operation might involve a call to a runtime function or builtin, which can have side effects and potentially suspend execution.
* **"Write Barrier":** A mechanism to ensure memory consistency in garbage-collected environments.
* **"ElementsKind":**  Refers to the specific type of elements stored in an array (e.g., PACKED_SMI_ELEMENTS, PACKED_DOUBLE_ELEMENTS).
* **"Feedback":**  Information gathered during execution that can be used to optimize future executions.

**6. Answering the Specific Questions:**

Now, armed with this understanding, we can address the specific points in the prompt:

* **Functionality:** Summarize the identified groups of operations (memory access, type checking, etc.).
* **`.tq` Extension:**  The prompt explicitly provides the information that a `.tq` extension signifies Torque code, so this is a direct answer.
* **JavaScript Relation:**  Connect the Maglev IR operations to their corresponding JavaScript functionalities. For example, `LoadTaggedField` is used behind the scenes when accessing object properties in JavaScript. Provide simple JavaScript examples.
* **Code Logic and Assumptions:** For operations with conditional behavior or specific requirements (like `CheckedInternalizedString`), describe what conditions are being checked and what the expected outcome is. Give examples of valid and potentially invalid inputs.
* **Common Programming Errors:**  Relate the IR operations to potential errors JavaScript developers might make. For instance, trying to access a property that doesn't exist could trigger deoptimization related to property access IR nodes.
* **Part of a Larger Whole:**  Recognize that this is a piece of the Maglev compiler's IR and fits into the overall compilation pipeline.

**7. Iteration and Refinement:**

Review the analysis. Are there any ambiguities? Can the explanations be clearer?  For example, initially, the "bitfield" might seem mysterious, but understanding it as a way to store flags associated with the operation makes its presence more logical.

By following these steps, we can systematically dissect the provided C++ header file excerpt and gain a comprehensive understanding of its purpose and functionality within the V8 JavaScript engine.
这是 V8 引擎 Maglev 编译器的中间表示（IR）头文件 `maglev-ir.h` 的一部分，定义了 Maglev IR 图中各种操作节点。让我们逐个分析这些类的功能。

**功能归纳：**

这部分代码定义了 Maglev IR 中的多种节点类型，这些节点代表了在 JavaScript 执行过程中可能发生的各种操作。主要涉及以下几个方面：

* **函数调用管理:** `FunctionEntryStackCheck` 用于处理函数入口时的栈检查。
* **类型检查:** `CheckedInternalizedString` 和 `CheckedObjectToIndex` 用于在运行时检查对象的类型，并在类型不匹配时触发反优化。
* **模板对象获取:** `GetTemplateObject` 用于获取模板对象。
* **原型链检查:** `HasInPrototypeChain` 用于检查对象是否在原型链中。
* **字符串操作:** `BuiltinStringFromCharCode` 和 `BuiltinStringPrototypeCharCodeOrCodePointAt`  代表调用内置的字符串方法。
* **属性访问:**  多种 `LoadTaggedField` 变体用于加载对象的属性值，包括普通属性、上下文变量和脚本上下文变量。`LoadDoubleField` 用于加载双精度浮点数类型的属性。 `LoadTaggedFieldByFieldIndex` 通过索引加载属性。
* **数组操作:** `LoadFixedArrayElement`, `EnsureWritableFastElements`, `ExtendPropertiesBackingStore`, `MaybeGrowFastElements`, `StoreFixedArrayElementWithWriteBarrier`, `StoreFixedArrayElementNoWriteBarrier`, `LoadFixedDoubleArrayElement`, `LoadHoleyFixedDoubleArrayElement`, `LoadHoleyFixedDoubleArrayElementCheckedNotHole`, `StoreFixedDoubleArrayElement` 等节点用于处理数组元素的加载、存储和管理。
* **Typed Array 操作:** `LoadSignedIntDataViewElement` 和 `LoadDoubleDataViewElement` 用于加载 DataView 对象的元素。
* **多态访问信息:** `PolymorphicAccessInfo` 用于存储关于属性访问的信息，用于优化多态属性的访问。

**关于文件类型：**

如果 `v8/src/maglev/maglev-ir.h` 以 `.tq` 结尾，那么它确实是 V8 Torque 源代码。 然而，通常 `.h` 结尾表示 C++ 头文件。 **因此，根据您提供的信息，`v8/src/maglev/maglev-ir.h` 是一个 C++ 头文件。** Torque 文件通常用于定义运行时函数的签名和内置函数的实现。

**与 JavaScript 功能的关系及 JavaScript 示例：**

这些 Maglev IR 节点直接对应了 JavaScript 代码在执行过程中需要进行的各种操作。以下是一些示例：

1. **`CheckedInternalizedString`**:  当 JavaScript 代码尝试使用一个字符串字面量或将变量与字符串字面量进行比较时，Maglev 可能会使用这个节点来检查该字符串是否已经被内部化（存储在字符串池中）。

   ```javascript
   function foo(str) {
     if (str === "hello") { // 这里会涉及到字符串比较，可能用到 CheckedInternalizedString
       return true;
     }
     return false;
   }
   ```

2. **`CheckedObjectToIndex`**: 当 JavaScript 代码尝试将一个对象转换为数字索引时，例如在数组访问中，会用到这个节点来检查对象是否可以安全地转换为索引。

   ```javascript
   function bar(obj) {
     const arr = [1, 2, 3];
     return arr[obj]; // 如果 obj 不是有效的数字索引，会涉及到类型检查
   }
   ```

3. **`LoadTaggedField`**: 当 JavaScript 代码访问对象的属性时，会使用 `LoadTaggedField` 系列的节点。

   ```javascript
   const obj = { x: 10 };
   console.log(obj.x); // 这里会使用 LoadTaggedField 加载属性 'x' 的值
   ```

4. **数组操作节点 (例如 `LoadFixedArrayElement`, `StoreFixedArrayElementWithWriteBarrier`)**:  这些节点对应 JavaScript 中数组元素的访问和修改。

   ```javascript
   const arr = [1, 2, 3];
   console.log(arr[1]); // LoadFixedArrayElement
   arr[0] = 4;         // StoreFixedArrayElementWithWriteBarrier
   ```

5. **`BuiltinStringFromCharCode`**: 对应 `String.fromCharCode()` 方法。

   ```javascript
   String.fromCharCode(65); // 'A'
   ```

6. **`BuiltinStringPrototypeCharCodeOrCodePointAt`**: 对应 `String.prototype.charCodeAt()` 和 `String.prototype.codePointAt()` 方法。

   ```javascript
   const str = "ABC";
   str.charCodeAt(0); // 65
   str.codePointAt(0); // 65
   ```

**代码逻辑推理和假设输入/输出：**

以 `CheckedInternalizedString` 为例：

* **假设输入:** 一个表示字符串的 Maglev IR 节点，以及期望的 `CheckType` (例如，检查是否等于某个特定的内部化字符串)。
* **代码逻辑:**  在代码生成阶段，`GenerateCode` 方法会生成汇编代码，用于检查输入字符串是否与内部化字符串池中的目标字符串相等。如果相等，则继续执行；否则，可能会触发反优化流程。
* **输出:**  该节点本身不产生直接的输出值，而是影响控制流。如果检查通过，则后续依赖该节点的指令可以继续执行，并且结果值将是输入字符串的值。如果检查失败，则会跳转到反优化代码。

以 `LoadFixedArrayElement` 为例：

* **假设输入:** 两个 Maglev IR 节点，分别表示一个固定数组和一个索引（通常是整数）。
* **代码逻辑:** `GenerateCode` 方法会生成汇编代码，用于从数组的指定索引处加载元素的值。需要进行边界检查以确保索引在数组的有效范围内。
* **输出:**  一个表示加载到的数组元素的 Maglev IR 节点。

**用户常见的编程错误举例：**

1. **类型错误导致 `CheckedInternalizedString` 或 `CheckedObjectToIndex` 失败:**

   ```javascript
   function compare(input) {
     if (input === 123) { // 假设期望的是字符串 "123"
       // ...
     }
   }
   compare("123"); // 正常执行
   compare(123);   // 类型不匹配，可能触发反优化
   ```

2. **数组越界访问导致与数组操作相关的节点执行错误:**

   ```javascript
   const arr = [1, 2, 3];
   console.log(arr[5]); // 数组越界，可能导致程序崩溃或返回 undefined
   ```
   在 Maglev 层面，这可能导致与 `LoadFixedArrayElement` 相关的操作尝试访问无效内存。

3. **尝试访问未定义或空对象的属性，可能导致与 `LoadTaggedField` 相关的错误:**

   ```javascript
   let obj;
   console.log(obj.x); // TypeError: Cannot read property 'x' of undefined
   ```
   在 Maglev 层面，尝试执行 `LoadTaggedField` 时会发现对象为空。

**总结 (针对第 8 部分)：**

这部分 `maglev-ir.h` 代码定义了 Maglev IR 中用于执行类型检查、访问对象属性、操作数组和调用内置字符串方法的各种操作节点。这些节点是 Maglev 编译器将 JavaScript 代码转换为机器码的关键组成部分。它们的设计考虑了性能和类型安全性，并在必要时支持反优化以处理动态类型带来的挑战。这些节点直接反映了 JavaScript 语言的特性和运行时行为。

**请注意：**  由于您只提供了部分代码，上述分析是基于这部分代码的功能进行的推断。完整的 `maglev-ir.h` 文件会包含更多类型的节点，涵盖更广泛的 JavaScript 操作。

Prompt: 
```
这是目录为v8/src/maglev/maglev-ir.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-ir.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共12部分，请归纳一下它的功能

"""
uint64_t bitfield) : Base(bitfield) {}

  // Although FunctionEntryStackCheck calls a builtin, we don't mark it as Call
  // here. The register allocator should not spill any live registers, since the
  // builtin already handles it. The only possible live register is
  // kJavaScriptCallNewTargetRegister.
  static constexpr OpProperties kProperties = OpProperties::LazyDeopt() |
                                              OpProperties::DeferredCall() |
                                              OpProperties::NotIdempotent();

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class CheckedInternalizedString
    : public FixedInputValueNodeT<1, CheckedInternalizedString> {
  using Base = FixedInputValueNodeT<1, CheckedInternalizedString>;

 public:
  explicit CheckedInternalizedString(uint64_t bitfield, CheckType check_type)
      : Base(CheckTypeBitField::update(bitfield, check_type)) {
    CHECK_EQ(properties().value_representation(), ValueRepresentation::kTagged);
  }

  static constexpr OpProperties kProperties =
      OpProperties::EagerDeopt() | OpProperties::TaggedValue();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  static constexpr int kObjectIndex = 0;
  Input& object_input() { return Node::input(kObjectIndex); }
  CheckType check_type() const { return CheckTypeBitField::decode(bitfield()); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}

  auto options() const { return std::tuple{check_type()}; }

 private:
  using CheckTypeBitField = NextBitField<CheckType, 1>;
};

class CheckedObjectToIndex
    : public FixedInputValueNodeT<1, CheckedObjectToIndex> {
  using Base = FixedInputValueNodeT<1, CheckedObjectToIndex>;

 public:
  explicit CheckedObjectToIndex(uint64_t bitfield, CheckType check_type)
      : Base(CheckTypeBitField::update(bitfield, check_type)) {}

  static constexpr OpProperties kProperties =
      OpProperties::EagerDeopt() | OpProperties::Int32() |
      OpProperties::DeferredCall() | OpProperties::ConversionNode();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  static constexpr int kObjectIndex = 0;
  Input& object_input() { return Node::input(kObjectIndex); }
  CheckType check_type() const { return CheckTypeBitField::decode(bitfield()); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}

  auto options() const { return std::tuple{check_type()}; }

 private:
  using CheckTypeBitField = NextBitField<CheckType, 1>;
};

class GetTemplateObject : public FixedInputValueNodeT<1, GetTemplateObject> {
  using Base = FixedInputValueNodeT<1, GetTemplateObject>;

 public:
  explicit GetTemplateObject(
      uint64_t bitfield, compiler::SharedFunctionInfoRef shared_function_info,
      const compiler::FeedbackSource& feedback)
      : Base(bitfield),
        shared_function_info_(shared_function_info),
        feedback_(feedback) {}

  // The implementation currently calls runtime.
  static constexpr OpProperties kProperties =
      OpProperties::GenericRuntimeOrBuiltinCall();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  Input& description() { return input(0); }

  compiler::SharedFunctionInfoRef shared_function_info() {
    return shared_function_info_;
  }
  compiler::FeedbackSource feedback() const { return feedback_; }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}

 private:
  compiler::SharedFunctionInfoRef shared_function_info_;
  const compiler::FeedbackSource feedback_;
};

class HasInPrototypeChain
    : public FixedInputValueNodeT<1, HasInPrototypeChain> {
  using Base = FixedInputValueNodeT<1, HasInPrototypeChain>;

 public:
  explicit HasInPrototypeChain(uint64_t bitfield,
                               compiler::HeapObjectRef prototype)
      : Base(bitfield), prototype_(prototype) {}

  // The implementation can enter user code in the deferred call (due to
  // proxied getPrototypeOf).
  static constexpr OpProperties kProperties =
      OpProperties::DeferredCall() | OpProperties::CanCallUserCode();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  Input& object() { return input(0); }

  compiler::HeapObjectRef prototype() { return prototype_; }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  compiler::HeapObjectRef prototype_;
};

class BuiltinStringFromCharCode
    : public FixedInputValueNodeT<1, BuiltinStringFromCharCode> {
  using Base = FixedInputValueNodeT<1, BuiltinStringFromCharCode>;

 public:
  explicit BuiltinStringFromCharCode(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanAllocate() | OpProperties::DeferredCall();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kInt32};

  Input& code_input() { return input(0); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class BuiltinStringPrototypeCharCodeOrCodePointAt
    : public FixedInputValueNodeT<2,
                                  BuiltinStringPrototypeCharCodeOrCodePointAt> {
  using Base =
      FixedInputValueNodeT<2, BuiltinStringPrototypeCharCodeOrCodePointAt>;

 public:
  enum Mode {
    kCharCodeAt,
    kCodePointAt,
  };

  explicit BuiltinStringPrototypeCharCodeOrCodePointAt(uint64_t bitfield,
                                                       Mode mode)
      : Base(bitfield), mode_(mode) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanAllocate() | OpProperties::CanRead() |
      OpProperties::DeferredCall() | OpProperties::Int32();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kInt32};

  static constexpr int kStringIndex = 0;
  static constexpr int kIndexIndex = 1;
  Input& string_input() { return input(kStringIndex); }
  Input& index_input() { return input(kIndexIndex); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

  auto options() const { return std::tuple{mode_}; }

  Mode mode() const { return mode_; }

 private:
  Mode mode_;
};

class PolymorphicAccessInfo {
 public:
  enum Kind {
    kNotFound,
    kConstant,
    kConstantDouble,
    kDataLoad,
    kModuleExport,
    kStringLength,
  };

  static PolymorphicAccessInfo NotFound(
      const ZoneVector<compiler::MapRef>& maps) {
    return PolymorphicAccessInfo(kNotFound, maps, Representation::Tagged());
  }
  static PolymorphicAccessInfo Constant(
      const ZoneVector<compiler::MapRef>& maps, compiler::ObjectRef constant) {
    return PolymorphicAccessInfo(kConstant, maps, Representation::Tagged(),
                                 constant);
  }
  static PolymorphicAccessInfo ConstantDouble(
      const ZoneVector<compiler::MapRef>& maps, Float64 constant) {
    return PolymorphicAccessInfo(kConstantDouble, maps, constant);
  }
  static PolymorphicAccessInfo DataLoad(
      const ZoneVector<compiler::MapRef>& maps, Representation representation,
      compiler::OptionalJSObjectRef holder, FieldIndex field_index) {
    return PolymorphicAccessInfo(kDataLoad, maps, representation, holder,
                                 field_index);
  }
  static PolymorphicAccessInfo ModuleExport(
      const ZoneVector<compiler::MapRef>& maps, compiler::CellRef cell) {
    return PolymorphicAccessInfo(kModuleExport, maps, Representation::Tagged(),
                                 cell);
  }
  static PolymorphicAccessInfo StringLength(
      const ZoneVector<compiler::MapRef>& maps) {
    return PolymorphicAccessInfo(kStringLength, maps, Representation::Smi());
  }

  Kind kind() const { return kind_; }

  const ZoneVector<compiler::MapRef>& maps() const { return maps_; }

  Handle<Object> constant() const {
    DCHECK_EQ(kind_, kConstant);
    return constant_.object();
  }

  double constant_double() const {
    DCHECK_EQ(kind_, kConstantDouble);
    return constant_double_.get_scalar();
  }

  Handle<Cell> cell() const {
    DCHECK_EQ(kind_, kModuleExport);
    return constant_.AsCell().object();
  }

  compiler::OptionalJSObjectRef holder() const {
    DCHECK_EQ(kind_, kDataLoad);
    return data_load_.holder_;
  }

  FieldIndex field_index() const {
    DCHECK_EQ(kind_, kDataLoad);
    return data_load_.field_index_;
  }

  Representation field_representation() const { return representation_; }

  bool operator==(const PolymorphicAccessInfo& other) const {
    if (kind_ != other.kind_ || !(representation_ == other.representation_)) {
      return false;
    }
    if (maps_.size() != other.maps_.size()) {
      return false;
    }
    for (size_t i = 0; i < maps_.size(); ++i) {
      if (maps_[i] != other.maps_[i]) {
        return false;
      }
    }
    switch (kind_) {
      case kNotFound:
      case kStringLength:
        return true;
      case kModuleExport:
      case kConstant:
        return constant_.equals(other.constant_);
      case kConstantDouble:
        return constant_double_ == other.constant_double_;
      case kDataLoad:
        return data_load_.holder_.equals(other.data_load_.holder_) &&
               data_load_.field_index_ == other.data_load_.field_index_;
    }
  }

  size_t hash_value() const {
    size_t hash = base::hash_value(kind_);
    hash = base::hash_combine(hash, base::hash_value(representation_.kind()));
    for (auto map : maps()) {
      hash = base::hash_combine(hash, map.hash_value());
    }
    switch (kind_) {
      case kNotFound:
      case kStringLength:
        break;
      case kModuleExport:
      case kConstant:
        hash = base::hash_combine(hash, constant_.hash_value());
        break;
      case kConstantDouble:
        hash = base::hash_combine(hash, base::hash_value(constant_double_));
        break;
      case kDataLoad:
        hash = base::hash_combine(
            hash, base::hash_value(data_load_.holder_.hash_value()));
        hash = base::hash_combine(
            hash, base::hash_value(data_load_.field_index_.index()));
        break;
    }
    return hash;
  }

 private:
  explicit PolymorphicAccessInfo(Kind kind,
                                 const ZoneVector<compiler::MapRef>& maps,
                                 Representation representation)
      : kind_(kind), maps_(maps), representation_(representation) {
    DCHECK(kind == kNotFound || kind == kStringLength);
  }

  PolymorphicAccessInfo(Kind kind, const ZoneVector<compiler::MapRef>& maps,
                        Representation representation,
                        compiler::ObjectRef constant)
      : kind_(kind),
        maps_(maps),
        representation_(representation),
        constant_(constant) {
    DCHECK(kind == kConstant || kind == kModuleExport);
  }

  PolymorphicAccessInfo(Kind kind, const ZoneVector<compiler::MapRef>& maps,
                        Float64 constant)
      : kind_(kind),
        maps_(maps),
        representation_(Representation::Double()),
        constant_double_(constant) {
    DCHECK_EQ(kind, kConstantDouble);
  }

  PolymorphicAccessInfo(Kind kind, const ZoneVector<compiler::MapRef>& maps,
                        Representation representation,
                        compiler::OptionalJSObjectRef holder,
                        FieldIndex field_index)
      : kind_(kind),
        maps_(maps),
        representation_(representation),
        data_load_{holder, field_index} {
    DCHECK_EQ(kind, kDataLoad);
  }

  const Kind kind_;
  // TODO(victorgomes): Create a PolymorphicMapChecks and avoid the maps here.
  const ZoneVector<compiler::MapRef> maps_;
  const Representation representation_;
  union {
    const compiler::ObjectRef constant_;
    const Float64 constant_double_;
    struct {
      const compiler::OptionalJSObjectRef holder_;
      const FieldIndex field_index_;
    } data_load_;
  };
};

template <typename Derived = LoadTaggedField>
class AbstractLoadTaggedField : public FixedInputValueNodeT<1, Derived> {
  using Base = FixedInputValueNodeT<1, Derived>;
  using Base::result;

 public:
  explicit AbstractLoadTaggedField(uint64_t bitfield, const int offset)
      : Base(bitfield), offset_(offset) {}

  static constexpr OpProperties kProperties = OpProperties::CanRead();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  int offset() const { return offset_; }

  using Base::input;
  static constexpr int kObjectIndex = 0;
  Input& object_input() { return input(kObjectIndex); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

  auto options() const { return std::tuple{offset()}; }

  using Base::decompresses_tagged_result;

 private:
  const int offset_;
};

class LoadTaggedField : public AbstractLoadTaggedField<LoadTaggedField> {
  using Base = AbstractLoadTaggedField<LoadTaggedField>;

 public:
  explicit LoadTaggedField(uint64_t bitfield, const int offset)
      : Base(bitfield, offset) {}
};

class LoadTaggedFieldForProperty
    : public AbstractLoadTaggedField<LoadTaggedFieldForProperty> {
  using Base = AbstractLoadTaggedField<LoadTaggedFieldForProperty>;

 public:
  explicit LoadTaggedFieldForProperty(uint64_t bitfield, const int offset,
                                      compiler::NameRef name)
      : Base(bitfield, offset), name_(name) {}
  compiler::NameRef name() { return name_; }

  auto options() const { return std::tuple{offset(), name_}; }

 private:
  compiler::NameRef name_;
};

class LoadTaggedFieldForContextSlot
    : public AbstractLoadTaggedField<LoadTaggedFieldForContextSlot> {
  using Base = AbstractLoadTaggedField<LoadTaggedFieldForContextSlot>;

 public:
  explicit LoadTaggedFieldForContextSlot(uint64_t bitfield, const int offset)
      : Base(bitfield, offset) {}
};

class LoadTaggedFieldForScriptContextSlot
    : public FixedInputValueNodeT<1, LoadTaggedFieldForScriptContextSlot> {
  using Base = FixedInputValueNodeT<1, LoadTaggedFieldForScriptContextSlot>;

 public:
  explicit LoadTaggedFieldForScriptContextSlot(uint64_t bitfield,
                                               const int index)
      : Base(bitfield), index_(index) {}

  static constexpr OpProperties kProperties = OpProperties::CanRead() |
                                              OpProperties::CanAllocate() |
                                              OpProperties::DeferredCall();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  int offset() const { return Context::OffsetOfElementAt(index_); }
  int index() const { return index_; }

  using Base::input;
  static constexpr int kContextIndex = 0;
  Input& context() { return input(kContextIndex); }

  int MaxCallStackArgs() const { return 0; }
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

  auto options() const { return std::tuple{index()}; }

  using Base::decompresses_tagged_result;

 private:
  const int index_;
};

class LoadDoubleField : public FixedInputValueNodeT<1, LoadDoubleField> {
  using Base = FixedInputValueNodeT<1, LoadDoubleField>;

 public:
  explicit LoadDoubleField(uint64_t bitfield, int offset)
      : Base(bitfield), offset_(offset) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanRead() | OpProperties::Float64();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  int offset() const { return offset_; }

  static constexpr int kObjectIndex = 0;
  Input& object_input() { return input(kObjectIndex); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

  auto options() const { return std::tuple{offset()}; }

 private:
  const int offset_;
};

class LoadTaggedFieldByFieldIndex
    : public FixedInputValueNodeT<2, LoadTaggedFieldByFieldIndex> {
  using Base = FixedInputValueNodeT<2, LoadTaggedFieldByFieldIndex>;

 public:
  explicit LoadTaggedFieldByFieldIndex(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::CanAllocate() |
                                              OpProperties::CanRead() |
                                              OpProperties::DeferredCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  static constexpr int kObjectIndex = 0;
  static constexpr int kIndexIndex = 1;
  Input& object_input() { return input(kObjectIndex); }
  Input& index_input() { return input(kIndexIndex); }

#ifdef V8_COMPRESS_POINTERS
  void MarkTaggedInputsAsDecompressing() {
    // Only need to decompress the object, the index should be a Smi.
    object_input().node()->SetTaggedResultNeedsDecompress();
  }
#endif

  int MaxCallStackArgs() const { return 0; }
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class LoadFixedArrayElement
    : public FixedInputValueNodeT<2, LoadFixedArrayElement> {
  using Base = FixedInputValueNodeT<2, LoadFixedArrayElement>;

 public:
  explicit LoadFixedArrayElement(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::CanRead();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kInt32};

  static constexpr int kElementsIndex = 0;
  static constexpr int kIndexIndex = 1;
  Input& elements_input() { return input(kElementsIndex); }
  Input& index_input() { return input(kIndexIndex); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;
};

class EnsureWritableFastElements
    : public FixedInputValueNodeT<2, EnsureWritableFastElements> {
  using Base = FixedInputValueNodeT<2, EnsureWritableFastElements>;

 public:
  explicit EnsureWritableFastElements(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::CanAllocate() |
                                              OpProperties::DeferredCall() |
                                              OpProperties::CanWrite();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  static constexpr int kElementsIndex = 0;
  static constexpr int kObjectIndex = 1;
  Input& elements_input() { return input(kElementsIndex); }
  Input& object_input() { return input(kObjectIndex); }

  int MaxCallStackArgs() const { return 0; }
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class ExtendPropertiesBackingStore
    : public FixedInputValueNodeT<2, ExtendPropertiesBackingStore> {
  using Base = FixedInputValueNodeT<2, ExtendPropertiesBackingStore>;

 public:
  explicit ExtendPropertiesBackingStore(uint64_t bitfield, int old_length)
      : Base(bitfield), old_length_(old_length) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanAllocate() | OpProperties::CanRead() |
      OpProperties::CanWrite() | OpProperties::DeferredCall() |
      OpProperties::EagerDeopt() | OpProperties::NotIdempotent();

  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  static constexpr int kPropertyArrayIndex = 0;
  static constexpr int kObjectIndex = 1;
  Input& property_array_input() { return input(kPropertyArrayIndex); }
  Input& object_input() { return input(kObjectIndex); }

  int MaxCallStackArgs() const { return 0; }
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

  int old_length() const { return old_length_; }

 private:
  const int old_length_;
};

class MaybeGrowFastElements
    : public FixedInputValueNodeT<4, MaybeGrowFastElements> {
  using Base = FixedInputValueNodeT<4, MaybeGrowFastElements>;

 public:
  explicit MaybeGrowFastElements(uint64_t bitfield, ElementsKind elements_kind)
      : Base(bitfield), elements_kind_(elements_kind) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanAllocate() | OpProperties::DeferredCall() |
      OpProperties::CanWrite() | OpProperties::EagerDeopt();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged,
      ValueRepresentation::kInt32, ValueRepresentation::kInt32};

  static constexpr int kElementsIndex = 0;
  static constexpr int kObjectIndex = 1;
  static constexpr int kIndexIndex = 2;
  static constexpr int kElementsLengthIndex = 3;
  Input& elements_input() { return input(kElementsIndex); }
  Input& object_input() { return input(kObjectIndex); }
  Input& index_input() { return input(kIndexIndex); }
  Input& elements_length_input() { return input(kElementsLengthIndex); }

  ElementsKind elements_kind() const { return elements_kind_; }

  int MaxCallStackArgs() const { return 0; }
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}

  auto options() const { return std::tuple{elements_kind()}; }

 private:
  const ElementsKind elements_kind_;
};

class StoreFixedArrayElementWithWriteBarrier
    : public FixedInputNodeT<3, StoreFixedArrayElementWithWriteBarrier> {
  using Base = FixedInputNodeT<3, StoreFixedArrayElementWithWriteBarrier>;

 public:
  explicit StoreFixedArrayElementWithWriteBarrier(uint64_t bitfield)
      : Base(bitfield) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanWrite() | OpProperties::DeferredCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kInt32,
      ValueRepresentation::kTagged};

  static constexpr int kElementsIndex = 0;
  static constexpr int kIndexIndex = 1;
  static constexpr int kValueIndex = 2;
  Input& elements_input() { return input(kElementsIndex); }
  Input& index_input() { return input(kIndexIndex); }
  Input& value_input() { return input(kValueIndex); }

  int MaxCallStackArgs() const { return 0; }
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

// StoreFixedArrayElementNoWriteBarrier never does a Deferred Call. However,
// PhiRepresentationSelector can cause some StoreFixedArrayElementNoWriteBarrier
// to become StoreFixedArrayElementWithWriteBarrier, which can do Deferred
// Calls, and thus need the register snapshot. We thus set the DeferredCall
// property in StoreFixedArrayElementNoWriteBarrier so that it's allocated with
// enough space for the register snapshot.
class StoreFixedArrayElementNoWriteBarrier
    : public FixedInputNodeT<3, StoreFixedArrayElementNoWriteBarrier> {
  using Base = FixedInputNodeT<3, StoreFixedArrayElementNoWriteBarrier>;

 public:
  explicit StoreFixedArrayElementNoWriteBarrier(uint64_t bitfield)
      : Base(bitfield) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanWrite() | OpProperties::DeferredCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kInt32,
      ValueRepresentation::kTagged};

  static constexpr int kElementsIndex = 0;
  static constexpr int kIndexIndex = 1;
  static constexpr int kValueIndex = 2;
  Input& elements_input() { return input(kElementsIndex); }
  Input& index_input() { return input(kIndexIndex); }
  Input& value_input() { return input(kValueIndex); }

  int MaxCallStackArgs() const {
    // StoreFixedArrayElementNoWriteBarrier never really does any call.
    return 0;
  }
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class LoadFixedDoubleArrayElement
    : public FixedInputValueNodeT<2, LoadFixedDoubleArrayElement> {
  using Base = FixedInputValueNodeT<2, LoadFixedDoubleArrayElement>;

 public:
  explicit LoadFixedDoubleArrayElement(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanRead() | OpProperties::Float64();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kInt32};

  static constexpr int kElementsIndex = 0;
  static constexpr int kIndexIndex = 1;
  Input& elements_input() { return input(kElementsIndex); }
  Input& index_input() { return input(kIndexIndex); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class LoadHoleyFixedDoubleArrayElement
    : public FixedInputValueNodeT<2, LoadHoleyFixedDoubleArrayElement> {
  using Base = FixedInputValueNodeT<2, LoadHoleyFixedDoubleArrayElement>;

 public:
  explicit LoadHoleyFixedDoubleArrayElement(uint64_t bitfield)
      : Base(bitfield) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanRead() | OpProperties::HoleyFloat64();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kInt32};

  static constexpr int kElementsIndex = 0;
  static constexpr int kIndexIndex = 1;
  Input& elements_input() { return input(kElementsIndex); }
  Input& index_input() { return input(kIndexIndex); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class LoadHoleyFixedDoubleArrayElementCheckedNotHole
    : public FixedInputValueNodeT<
          2, LoadHoleyFixedDoubleArrayElementCheckedNotHole> {
  using Base =
      FixedInputValueNodeT<2, LoadHoleyFixedDoubleArrayElementCheckedNotHole>;

 public:
  explicit LoadHoleyFixedDoubleArrayElementCheckedNotHole(uint64_t bitfield)
      : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::CanRead() |
                                              OpProperties::Float64() |
                                              OpProperties::EagerDeopt();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kInt32};

  static constexpr int kElementsIndex = 0;
  static constexpr int kIndexIndex = 1;
  Input& elements_input() { return input(kElementsIndex); }
  Input& index_input() { return input(kIndexIndex); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class StoreFixedDoubleArrayElement
    : public FixedInputNodeT<3, StoreFixedDoubleArrayElement> {
  using Base = FixedInputNodeT<3, StoreFixedDoubleArrayElement>;

 public:
  explicit StoreFixedDoubleArrayElement(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::CanWrite();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kInt32,
      ValueRepresentation::kHoleyFloat64};

  static constexpr int kElementsIndex = 0;
  static constexpr int kIndexIndex = 1;
  static constexpr int kValueIndex = 2;
  Input& elements_input() { return input(kElementsIndex); }
  Input& index_input() { return input(kIndexIndex); }
  Input& value_input() { return input(kValueIndex); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class LoadSignedIntDataViewElement
    : public FixedInputValueNodeT<3, LoadSignedIntDataViewElement> {
  using Base = FixedInputValueNodeT<3, LoadSignedIntDataViewElement>;

 public:
  explicit LoadSignedIntDataViewElement(uint64_t bitfield,
                                        ExternalArrayType type)
      : Base(bitfield), type_(type) {
    DCHECK(type == ExternalArrayType::kExternalInt8Array ||
           type == ExternalArrayType::kExternalInt16Array ||
           type == ExternalArrayType::kExternalInt32Array);
  }

  static constexpr OpProperties kProperties =
      OpProperties::CanRead() | OpProperties::Int32();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kInt32,
      ValueRepresentation::kTagged};

  static constexpr int kObjectIndex = 0;
  static constexpr int kIndexIndex = 1;
  static constexpr int kIsLittleEndianIndex = 2;
  Input& object_input() { return input(kObjectIndex); }
  Input& index_input() { return input(kIndexIndex); }
  Input& is_little_endian_input() { return input(kIsLittleEndianIndex); }

  bool is_little_endian_constant() {
    return IsConstantNode(is_little_endian_input().node()->opcode());
  }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}

  auto options() const { return std::tuple{type_}; }

  ExternalArrayType type() const { return type_; }

 private:
  ExternalArrayType type_;
};

class LoadDoubleDataViewElement
    : public FixedInputValueNodeT<3, LoadDoubleDataViewElement> {
  using Base = FixedInputValueNodeT<3, LoadDoubleDataViewElement>;
  static constexpr ExternalArrayType type_ =
      ExternalArrayType::kExternalFloat64Array;

 public:
  explicit LoadDoubleDataViewElement(uint64_t bitfield, ExternalArrayType type)
      : Base(bitfield) {
    DCHECK_EQ(type, type_);
  }

  static constexpr OpProperties kProperties =
      OpProperties::CanRead() | OpProperties::Float64();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kInt32,
      ValueRepresentation::kTagged};

  static constexpr int kObjectIndex = 0;
  static constexpr int kIndexIndex = 1;
  static constexpr int kIsLittleEndianIndex = 2;
  Input& object_input() { return input(kObjectIndex); }
  Input& index_input() { return input(kIndexIndex); }
  Input& is_little_endian_input() { return input(kIsLittleEndianIndex); }

  bool is_little_endian_constant() {
    return IsConstantNode(is_little_endian_input().node()->opcode());
  }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}

  auto options() const { return std::tuple{type_}; }
};

#define LOAD_TYPED_ARRAY(name, properties, ...)                        \
  class name : public FixedInputValueNodeT<2, name> {                  \
    using Base = FixedInputValueNodeT<2, name>;                        \
                                                                       \
   public:                                                             \
    explicit name(uint64_t bitfield, ElementsKind elements_kind)       \
        : Base(bitfield), elements_kind_(elements_kind) {              \
      DCHECK(elements_kind ==                                          \
             v8::internal::compiler::turboshaft::any_of(__VA_ARGS__)); \
    }                                                                  \
                                                                       \
    static constexpr OpProperties kProperties =                        \
        O
"""


```
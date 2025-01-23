Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Request:** The request asks for the functionality of the provided C++ code (part of `bytecode-generator.cc`), how it relates to JavaScript, and examples of potential programming errors. It also specifies that this is part 2 of 11, hinting that the full file is extensive. The key is to analyze the given code *only*, not speculate about the rest of the file.

2. **Initial Scan and Identification of Classes:**  The first step is to identify the main building blocks. We can see several class definitions: `TopLevelDeclarationsBuilder`, `CurrentScope`, `MultipleEntryBlockContextScope`, `FeedbackSlotCache`, `HoleCheckElisionScope`, `HoleCheckElisionMergeScope`, `IteratorRecord`, `OptionalChainNullLabelScope`, `LoopScope`, `ForInScope`, `DisposablesStackScope`, and the internal `Accessors` and `AccessorTable`.

3. **Analyze Each Class Individually:**  For each class, try to determine its purpose based on its member variables and methods.

    * **`TopLevelDeclarationsBuilder`:**  The names of the `record_*_declaration()` methods strongly suggest this class tracks declarations (variables and functions) at the top level of a script or module. The `entry_slots_` and the `k...Size` constants reinforce this idea. The `processed_` flag hints at some processing stage.

    * **`CurrentScope`:** This class seems to manage the current scope during bytecode generation. The constructor and destructor manipulating `generator_->current_scope()` are a telltale sign of a scope management helper, likely using the RAII (Resource Acquisition Is Initialization) principle.

    * **`MultipleEntryBlockContextScope`:**  This looks more complex. It deals with `Register` objects (`inner_context_`, `outer_context_`), suggesting it's related to register allocation. The `EnterScope()` and `ExitScope()` methods, along with the `current_scope_` and `context_scope_` optionals, indicate managing nested scopes or contexts, potentially for conditional execution.

    * **`FeedbackSlotCache`:** The name and the methods like `Put` and `Get` with `SlotKind` strongly suggest this class caches information about feedback slots. These slots are likely used for optimization based on runtime behavior. The `SlotKind` enum gives more clues about the types of operations being tracked (stores, loads, etc.).

    * **`HoleCheckElisionScope` and `HoleCheckElisionMergeScope`:** The names are quite descriptive. "Hole check" refers to checking for uninitialized variables (represented as "holes"). "Elision" means skipping. These classes appear to be optimizations to avoid redundant hole checks in certain control flow scenarios. The "Merge" version handles cases where control flow merges from different branches.

    * **`IteratorRecord`:**  This class clearly holds information about an iterator: the object, the `next` function, and the iterator type.

    * **`OptionalChainNullLabelScope`:** The name suggests handling the nullish coalescing operator (`??`) or optional chaining (`?.`). The `labels_` member likely stores bytecode labels for handling null/undefined values.

    * **`LoopScope`:**  This class manages the scope of a loop. The `LoopBuilder` and the manipulation of `bytecode_generator_->current_loop_scope()` are key indicators.

    * **`ForInScope`:**  This is specific to `for...in` loops and seems to track information related to the iteration, possibly for optimization (the `enum_index_` and `cache_type_` registers suggest this).

    * **`DisposablesStackScope`:** The name and the runtime call to `InitializeDisposableStack` suggest this is related to managing resources that need to be disposed of.

    * **`Accessors` and `AccessorTable`:** These are for managing getter/setter pairs, likely when dealing with object properties. The `AccessorTable` maintains insertion order.

4. **Identify Relationships and Interactions:**  Notice how some classes take a `BytecodeGenerator*` as a constructor argument. This signals that these classes are components or helpers used by the `BytecodeGenerator`. The nesting of classes (like `Branch` within `HoleCheckElisionMergeScope`) shows a clear dependency.

5. **Connect to JavaScript Concepts:**  Now, think about how these C++ constructs relate to JavaScript features:

    * **Top-level declarations:**  Directly map to variable and function declarations outside of any function in JavaScript.
    * **Scopes:** A fundamental concept in JavaScript. The C++ `Scope` class likely mirrors the lexical scoping rules of JavaScript.
    * **Closures and Contexts:** The context-related classes (`CurrentScope`, `MultipleEntryBlockContextScope`) are crucial for implementing closures in JavaScript.
    * **Property access and assignment:**  The `FeedbackSlotCache` is tied to how V8 optimizes property access (e.g., monomorphism).
    * **`for...in` loops:**  The `ForInScope` is directly related to the mechanics of this loop type in JavaScript.
    * **Iterators:** The `IteratorRecord` is directly related to the JavaScript Iterator protocol.
    * **Optional chaining:** The `OptionalChainNullLabelScope` handles the `?.` operator.
    * **Loops:** The `LoopScope` manages the bytecode generation for `for`, `while`, and `do...while` loops.

6. **Formulate Functionality Descriptions:** Based on the analysis, write down the purpose of each class. Use clear and concise language.

7. **Provide JavaScript Examples:** For features that directly correspond to JavaScript syntax (like top-level declarations, `for...in`, optional chaining), provide simple examples to illustrate the connection.

8. **Infer Code Logic and Examples (If Possible):** For classes with more intricate logic (like the hole check elision scopes), try to imagine scenarios where these optimizations would be useful. For instance, the merge scope is relevant in `if-else` statements.

9. **Consider Common Programming Errors:** Think about how the concepts represented by these classes can lead to common errors in JavaScript. For example, issues with variable scope, using uninitialized variables, or incorrect assumptions about `this`.

10. **Synthesize the Summary:** Combine the individual class functionalities into a high-level overview of what this section of the `bytecode-generator.cc` file does. Focus on the core purpose of managing scopes, declarations, and optimizations during bytecode generation. Acknowledge that this is a partial view of a larger system.

11. **Review and Refine:** Read through the entire analysis. Ensure clarity, accuracy, and consistency. Check if the JavaScript examples are correct and illustrative. Make sure the explanations are understandable without deep knowledge of V8 internals.
好的，我们来归纳一下 `v8/src/interpreter/bytecode-generator.cc` 的第 2 部分代码的功能。

这部分代码定义了一些辅助类，这些类主要用于在字节码生成过程中管理状态、作用域、优化和记录信息。以下是每个类的功能归纳：

**核心功能：辅助字节码生成过程，管理状态和优化。**

**详细功能：**

* **`TopLevelDeclarationsBuilder`**:
    * **功能**: 用于跟踪和记录顶层（全局或模块）的变量和函数声明。
    * **目的**: 在字节码生成完成后，可以根据记录的信息创建包含这些声明的数组，以便在运行时进行初始化。
    * **与 JavaScript 的关系**:  与 JavaScript 中在全局作用域或模块作用域中声明的变量和函数直接相关。
        ```javascript
        // 全局作用域
        var globalVar = 10;
        function globalFunc() {}

        // 模块作用域 (假设在模块中)
        export let moduleVar = 20;
        export function moduleFunc() {}
        ```
    * **代码逻辑推理**: 通过 `record_*_declaration()` 方法增加计数器，`has_top_level_declaration()` 检查是否有声明。假设输入一系列顶层变量和函数声明，输出是 `entry_slots_` 的累加值和 `processed_` 状态的更新。

* **`CurrentScope`**:
    * **功能**:  用于在字节码生成过程中管理当前的作用域。它通过 RAII (Resource Acquisition Is Initialization) 机制，在构造时设置当前作用域，在析构时恢复到外部作用域。
    * **目的**:  确保在生成特定作用域的代码时，`BytecodeGenerator` 能够正确地跟踪当前的作用域。
    * **与 JavaScript 的关系**: 与 JavaScript 中的词法作用域概念对应，确保变量和函数的访问遵循作用域规则。
        ```javascript
        function outer() {
          var outerVar = 1;
          function inner() {
            // 可以访问 outerVar
            console.log(outerVar);
          }
          inner();
        }
        outer();
        ```

* **`MultipleEntryBlockContextScope`**:
    * **功能**: 用于管理具有多个入口点的代码块的上下文，例如 `if` 语句。它负责在进入和退出代码块时创建和销毁局部块级作用域的上下文。
    * **目的**: 确保在条件执行的代码块中正确地创建和管理局部变量的上下文。
    * **与 JavaScript 的关系**:  与 JavaScript 中的块级作用域 (`let`, `const`) 以及控制流语句 (`if`) 相关。
        ```javascript
        function example(condition) {
          if (condition) {
            let blockVar = 5;
            console.log(blockVar);
          }
          // 这里不能访问 blockVar
        }
        ```

* **`FeedbackSlotCache`**:
    * **功能**:  用于缓存反馈槽（feedback slots）的信息。反馈槽是 V8 优化机制的一部分，用于存储运行时类型信息以进行优化。
    * **目的**:  避免重复查找和创建相同的反馈槽，提高字节码生成效率。
    * **与 JavaScript 的关系**:  与 V8 的优化机制密切相关，虽然 JavaScript 代码本身不直接操作反馈槽，但 V8 使用它们来优化诸如属性访问、函数调用等操作。
        ```javascript
        function accessProperty(obj) {
          return obj.property; // V8 可能会根据运行时 `obj` 的类型优化此访问
        }
        ```

* **`HoleCheckElisionScope`**:
    * **功能**:  用于在条件执行的基本块内省略对“hole”（未初始化变量）的检查。
    * **目的**:  优化字节码，避免在已知已检查的情况下重复进行 hole 检查。
    * **与 JavaScript 的关系**:  与 JavaScript 中变量的初始化有关。如果 V8 确定在某个代码路径上变量已经被初始化，就可以省略后续的 hole 检查。
        ```javascript
        function example(x) {
          let y;
          if (x > 0) {
            y = 10;
            console.log(y); // 第一次访问 y，可能需要 hole 检查
          }
          if (x > 0) {
            console.log(y); // 第二次访问 y，在相同条件下，可以省略 hole 检查
          }
        }
        ```
    * **用户常见的编程错误**:  在条件语句中声明变量但未在所有路径上初始化，导致访问未初始化的变量。

* **`HoleCheckElisionMergeScope`**:
    * **功能**:  类似于 `HoleCheckElisionScope`，但用于处理控制流分支合并的情况（例如 `if-else` 或三元运算符）。
    * **目的**:  确保在所有分支都检查过 hole 的变量，在合并后不再需要进行 hole 检查。
    * **与 JavaScript 的关系**:  与带有 `else` 分支的 `if` 语句或三元运算符相关。
        ```javascript
        function example(x) {
          let y;
          if (x > 0) {
            y = 10;
          } else {
            y = 20;
          }
          console.log(y); // 在 if-else 之后访问 y，由于所有路径都进行了初始化，可以省略 hole 检查
        }
        ```

* **`IteratorRecord`**:
    * **功能**:  用于存储迭代器的相关信息，包括迭代器对象和 `next` 方法的寄存器。
    * **目的**:  方便在字节码生成过程中操作迭代器。
    * **与 JavaScript 的关系**:  与 JavaScript 中的迭代器和 `for...of` 循环相关。
        ```javascript
        const arr = [1, 2, 3];
        for (const item of arr) {
          console.log(item);
        }
        ```

* **`OptionalChainNullLabelScope`**:
    * **功能**:  用于管理可选链操作符 (`?.`) 为 `null` 或 `undefined` 时跳转的标签。
    * **目的**:  正确生成可选链操作符的字节码。
    * **与 JavaScript 的关系**:  直接对应 JavaScript 的可选链操作符。
        ```javascript
        const obj = { a: { b: 1 } };
        const value = obj?.a?.b; // 如果 obj 或 obj.a 为 null/undefined，则 value 为 undefined，不会报错
        ```

* **`LoopScope`**:
    * **功能**:  用于界定循环作用域，从循环头到最终的跳转。
    * **目的**:  辅助生成循环的字节码，确保正确处理循环的跳转和作用域。
    * **与 JavaScript 的关系**:  与 JavaScript 中的各种循环结构 (`for`, `while`, `do...while`) 相关。

* **`ForInScope`**:
    * **功能**:  用于管理 `for...in` 循环的作用域，并可能包含用于优化的信息，例如枚举索引和缓存类型。
    * **目的**:  辅助生成 `for...in` 循环的字节码，并可能进行性能优化。
    * **与 JavaScript 的关系**:  直接对应 JavaScript 的 `for...in` 循环。
        ```javascript
        const obj = { a: 1, b: 2 };
        for (const key in obj) {
          console.log(key);
        }
        ```

* **`DisposablesStackScope`**:
    * **功能**:  用于管理可回收对象的堆栈。
    * **目的**:  在字节码生成过程中跟踪需要被释放或清理的对象。
    * **与 JavaScript 的关系**:  可能与 V8 的垃圾回收机制有关，用于管理需要在特定作用域结束时清理的资源。

* **内部辅助结构 `Accessors` 和 `AccessorTable`**:
    * **功能**: 用于管理属性的 getter 和 setter 函数的对。`AccessorTable` 维护一个从属性名到 `Accessors` 对象的映射，并保持插入顺序。
    * **目的**:  在处理对象字面量或类定义中的 getter 和 setter 时，能够有序地访问它们。
    * **与 JavaScript 的关系**:  与 JavaScript 中对象的 getter 和 setter 属性定义相关。
        ```javascript
        const obj = {
          get myProperty() { return this._myProperty; },
          set myProperty(value) { this._myProperty = value; }
        };
        ```

**总结第 2 部分的功能**:

这部分代码定义了一系列辅助类，它们在 `BytecodeGenerator` 类中被使用，用于管理字节码生成过程中的各种状态和优化。这些类涵盖了作用域管理、变量声明跟踪、反馈槽缓存、hole 检查优化、循环处理以及与 JavaScript 特定语法结构（如迭代器、可选链、`for...in` 循环）相关的状态管理。它们共同协作，使得 `BytecodeGenerator` 能够高效且正确地将 JavaScript 代码转换为字节码。

### 提示词
```
这是目录为v8/src/interpreter/bytecode-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/interpreter/bytecode-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
entry_slots_ += kGlobalVariableDeclarationSize;
  }
  void record_global_function_declaration() {
    entry_slots_ += kGlobalFunctionDeclarationSize;
  }
  void record_module_variable_declaration() {
    entry_slots_ += kModuleVariableDeclarationSize;
  }
  void record_module_function_declaration() {
    entry_slots_ += kModuleFunctionDeclarationSize;
  }
  bool has_top_level_declaration() { return entry_slots_ > 0; }
  bool processed() { return processed_; }
  void mark_processed() { processed_ = true; }

 private:
  const int kGlobalVariableDeclarationSize = 1;
  const int kGlobalFunctionDeclarationSize = 2;
  const int kModuleVariableDeclarationSize = 1;
  const int kModuleFunctionDeclarationSize = 3;

  size_t constant_pool_entry_ = 0;
  int entry_slots_ = 0;
  bool has_constant_pool_entry_ = false;
  bool processed_ = false;
};

class V8_NODISCARD BytecodeGenerator::CurrentScope final {
 public:
  CurrentScope(BytecodeGenerator* generator, Scope* scope)
      : generator_(generator), outer_scope_(generator->current_scope()) {
    if (scope != nullptr) {
      DCHECK_EQ(outer_scope_, scope->outer_scope());
      generator_->set_current_scope(scope);
    }
  }
  ~CurrentScope() {
    if (outer_scope_ != generator_->current_scope()) {
      generator_->set_current_scope(outer_scope_);
    }
  }
  CurrentScope(const CurrentScope&) = delete;
  CurrentScope& operator=(const CurrentScope&) = delete;

 private:
  BytecodeGenerator* generator_;
  Scope* outer_scope_;
};

class V8_NODISCARD BytecodeGenerator::MultipleEntryBlockContextScope {
 public:
  MultipleEntryBlockContextScope(BytecodeGenerator* generator, Scope* scope)
      : generator_(generator), scope_(scope), is_in_scope_(false) {
    if (scope) {
      inner_context_ = generator->register_allocator()->NewRegister();
      outer_context_ = generator->register_allocator()->NewRegister();
      generator->BuildNewLocalBlockContext(scope_);
      generator->builder()->StoreAccumulatorInRegister(inner_context_);
    }
  }

  void SetEnteredIf(bool condition) {
    RegisterAllocationScope register_scope(generator_);
    if (condition && scope_ != nullptr && !is_in_scope_) {
      EnterScope();
    } else if (!condition && is_in_scope_) {
      ExitScope();
    }
  }

  ~MultipleEntryBlockContextScope() { DCHECK(!is_in_scope_); }

  MultipleEntryBlockContextScope(const MultipleEntryBlockContextScope&) =
      delete;
  MultipleEntryBlockContextScope& operator=(
      const MultipleEntryBlockContextScope&) = delete;

 private:
  void EnterScope() {
    DCHECK(inner_context_.is_valid());
    DCHECK(outer_context_.is_valid());
    DCHECK(!is_in_scope_);
    generator_->builder()->LoadAccumulatorWithRegister(inner_context_);
    current_scope_.emplace(generator_, scope_);
    context_scope_.emplace(generator_, scope_, outer_context_);
    is_in_scope_ = true;
  }

  void ExitScope() {
    DCHECK(inner_context_.is_valid());
    DCHECK(outer_context_.is_valid());
    DCHECK(is_in_scope_);
    context_scope_ = std::nullopt;
    current_scope_ = std::nullopt;
    is_in_scope_ = false;
  }

  BytecodeGenerator* generator_;
  Scope* scope_;
  Register inner_context_;
  Register outer_context_;
  bool is_in_scope_;
  std::optional<CurrentScope> current_scope_;
  std::optional<ContextScope> context_scope_;
};

class BytecodeGenerator::FeedbackSlotCache : public ZoneObject {
 public:
  enum class SlotKind {
    kStoreGlobalSloppy,
    kStoreGlobalStrict,
    kSetNamedStrict,
    kSetNamedSloppy,
    kLoadProperty,
    kLoadSuperProperty,
    kLoadGlobalNotInsideTypeof,
    kLoadGlobalInsideTypeof,
    kClosureFeedbackCell
  };

  explicit FeedbackSlotCache(Zone* zone) : map_(zone) {}

  void Put(SlotKind slot_kind, Variable* variable, int slot_index) {
    PutImpl(slot_kind, 0, variable, slot_index);
  }
  void Put(SlotKind slot_kind, AstNode* node, int slot_index) {
    PutImpl(slot_kind, 0, node, slot_index);
  }
  void Put(SlotKind slot_kind, int variable_index, const AstRawString* name,
           int slot_index) {
    PutImpl(slot_kind, variable_index, name, slot_index);
  }
  void Put(SlotKind slot_kind, const AstRawString* name, int slot_index) {
    PutImpl(slot_kind, 0, name, slot_index);
  }

  int Get(SlotKind slot_kind, Variable* variable) const {
    return GetImpl(slot_kind, 0, variable);
  }
  int Get(SlotKind slot_kind, AstNode* node) const {
    return GetImpl(slot_kind, 0, node);
  }
  int Get(SlotKind slot_kind, int variable_index,
          const AstRawString* name) const {
    return GetImpl(slot_kind, variable_index, name);
  }
  int Get(SlotKind slot_kind, const AstRawString* name) const {
    return GetImpl(slot_kind, 0, name);
  }

 private:
  using Key = std::tuple<SlotKind, int, const void*>;

  void PutImpl(SlotKind slot_kind, int index, const void* node,
               int slot_index) {
    Key key = std::make_tuple(slot_kind, index, node);
    auto entry = std::make_pair(key, slot_index);
    map_.insert(entry);
  }

  int GetImpl(SlotKind slot_kind, int index, const void* node) const {
    Key key = std::make_tuple(slot_kind, index, node);
    auto iter = map_.find(key);
    if (iter != map_.end()) {
      return iter->second;
    }
    return -1;
  }

  ZoneMap<Key, int> map_;
};

// Scoped class to help elide hole checks within a conditionally executed basic
// block. Each conditionally executed basic block must have a scope to emit
// hole checks correctly.
//
// The duration of the scope must correspond to a basic block. Numbered
// Variables (see Variable::HoleCheckBitmap) are remembered in the bitmap when
// the first hole check is emitted. Subsequent hole checks are elided.
//
// On scope exit, the hole check state at construction time is restored.
class V8_NODISCARD BytecodeGenerator::HoleCheckElisionScope {
 public:
  explicit HoleCheckElisionScope(BytecodeGenerator* bytecode_generator)
      : HoleCheckElisionScope(&bytecode_generator->hole_check_bitmap_) {}

  ~HoleCheckElisionScope() { *bitmap_ = prev_bitmap_value_; }

 protected:
  explicit HoleCheckElisionScope(Variable::HoleCheckBitmap* bitmap)
      : bitmap_(bitmap), prev_bitmap_value_(*bitmap) {}

  Variable::HoleCheckBitmap* bitmap_;
  Variable::HoleCheckBitmap prev_bitmap_value_;
};

// Scoped class to help elide hole checks within control flow that branch and
// merge.
//
// Each such control flow construct (e.g., if-else, ternary expressions) must
// have a scope to emit hole checks correctly. Additionally, each branch must
// have a Branch.
//
// The Merge or MergeIf method must be called to merge variables that have been
// hole-checked along every branch are marked as no longer needing a hole check.
//
// Example:
//
//   HoleCheckElisionMergeScope merge_elider(this);
//   {
//      HoleCheckElisionMergeScope::Branch branch_elider(merge_elider);
//      Visit(then_branch);
//   }
//   {
//      HoleCheckElisionMergeScope::Branch branch_elider(merge_elider);
//      Visit(else_branch);
//   }
//   merge_elider.Merge();
//
// Conversely, it is incorrect to use this class for control flow constructs
// that do not merge (e.g., if without else). HoleCheckElisionScope should be
// used for those cases.
class V8_NODISCARD BytecodeGenerator::HoleCheckElisionMergeScope final {
 public:
  explicit HoleCheckElisionMergeScope(BytecodeGenerator* bytecode_generator)
      : bitmap_(&bytecode_generator->hole_check_bitmap_) {}

  ~HoleCheckElisionMergeScope() {
    // Did you forget to call Merge or MergeIf?
    DCHECK(merge_called_);
  }

  void Merge() {
    DCHECK_NE(UINT64_MAX, merge_value_);
    *bitmap_ = merge_value_;
#ifdef DEBUG
    merge_called_ = true;
#endif
  }

  void MergeIf(bool cond) {
    if (cond) Merge();
#ifdef DEBUG
    merge_called_ = true;
#endif
  }

  class V8_NODISCARD Branch final : public HoleCheckElisionScope {
   public:
    explicit Branch(HoleCheckElisionMergeScope& merge_into)
        : HoleCheckElisionScope(merge_into.bitmap_),
          merge_into_bitmap_(&merge_into.merge_value_) {}

    ~Branch() { *merge_into_bitmap_ &= *bitmap_; }

   private:
    Variable::HoleCheckBitmap* merge_into_bitmap_;
  };

 private:
  Variable::HoleCheckBitmap* bitmap_;
  Variable::HoleCheckBitmap merge_value_ = UINT64_MAX;

#ifdef DEBUG
  bool merge_called_ = false;
#endif
};

class BytecodeGenerator::IteratorRecord final {
 public:
  IteratorRecord(Register object_register, Register next_register,
                 IteratorType type = IteratorType::kNormal)
      : type_(type), object_(object_register), next_(next_register) {
    DCHECK(object_.is_valid() && next_.is_valid());
  }

  inline IteratorType type() const { return type_; }
  inline Register object() const { return object_; }
  inline Register next() const { return next_; }

 private:
  IteratorType type_;
  Register object_;
  Register next_;
};

class V8_NODISCARD BytecodeGenerator::OptionalChainNullLabelScope final {
 public:
  explicit OptionalChainNullLabelScope(BytecodeGenerator* bytecode_generator)
      : bytecode_generator_(bytecode_generator),
        labels_(bytecode_generator->zone()) {
    prev_ = bytecode_generator_->optional_chaining_null_labels_;
    bytecode_generator_->optional_chaining_null_labels_ = &labels_;
  }

  ~OptionalChainNullLabelScope() {
    bytecode_generator_->optional_chaining_null_labels_ = prev_;
  }

  BytecodeLabels* labels() { return &labels_; }

 private:
  BytecodeGenerator* bytecode_generator_;
  BytecodeLabels labels_;
  BytecodeLabels* prev_;
};

// LoopScope delimits the scope of {loop}, from its header to its final jump.
// It should be constructed iff a (conceptual) back edge should be produced. In
// the case of creating a LoopBuilder but never emitting the loop, it is valid
// to skip the creation of LoopScope.
class V8_NODISCARD BytecodeGenerator::LoopScope final {
 public:
  explicit LoopScope(BytecodeGenerator* bytecode_generator, LoopBuilder* loop)
      : bytecode_generator_(bytecode_generator),
        parent_loop_scope_(bytecode_generator_->current_loop_scope()),
        loop_builder_(loop) {
    loop_builder_->LoopHeader();
    bytecode_generator_->set_current_loop_scope(this);
    bytecode_generator_->loop_depth_++;
  }

  ~LoopScope() {
    bytecode_generator_->loop_depth_--;
    bytecode_generator_->set_current_loop_scope(parent_loop_scope_);
    DCHECK_GE(bytecode_generator_->loop_depth_, 0);
    loop_builder_->JumpToHeader(
        bytecode_generator_->loop_depth_,
        parent_loop_scope_ ? parent_loop_scope_->loop_builder_ : nullptr);
  }

 private:
  BytecodeGenerator* const bytecode_generator_;
  LoopScope* const parent_loop_scope_;
  LoopBuilder* const loop_builder_;
};

class V8_NODISCARD BytecodeGenerator::ForInScope final {
 public:
  explicit ForInScope(BytecodeGenerator* bytecode_generator,
                      ForInStatement* stmt, Register enum_index,
                      Register cache_type)
      : bytecode_generator_(bytecode_generator),
        parent_for_in_scope_(bytecode_generator_->current_for_in_scope()),
        each_var_(nullptr),
        enum_index_(enum_index),
        cache_type_(cache_type) {
    if (v8_flags.enable_enumerated_keyed_access_bytecode) {
      Expression* each = stmt->each();
      if (each->IsVariableProxy()) {
        Variable* each_var = each->AsVariableProxy()->var();
        if (each_var->IsStackLocal()) {
          each_var_ = each_var;
          bytecode_generator_->SetVariableInRegister(
              each_var_,
              bytecode_generator_->builder()->Local(each_var_->index()));
        }
      }
      bytecode_generator_->set_current_for_in_scope(this);
    }
  }

  ~ForInScope() {
    if (v8_flags.enable_enumerated_keyed_access_bytecode) {
      bytecode_generator_->set_current_for_in_scope(parent_for_in_scope_);
    }
  }

  // Get corresponding {ForInScope} for a given {each} variable.
  ForInScope* GetForInScope(Variable* each) {
    DCHECK(v8_flags.enable_enumerated_keyed_access_bytecode);
    ForInScope* scope = this;
    do {
      if (each == scope->each_var_) break;
      scope = scope->parent_for_in_scope_;
    } while (scope != nullptr);
    return scope;
  }

  Register enum_index() { return enum_index_; }
  Register cache_type() { return cache_type_; }

 private:
  BytecodeGenerator* const bytecode_generator_;
  ForInScope* const parent_for_in_scope_;
  Variable* each_var_;
  Register enum_index_;
  Register cache_type_;
};

class V8_NODISCARD BytecodeGenerator::DisposablesStackScope final {
 public:
  explicit DisposablesStackScope(BytecodeGenerator* bytecode_generator)
      : bytecode_generator_(bytecode_generator),
        prev_disposables_stack_(
            bytecode_generator_->current_disposables_stack()) {
    bytecode_generator_->current_disposables_stack_ =
        bytecode_generator->register_allocator()->NewRegister();
    bytecode_generator->builder()->CallRuntime(
        Runtime::kInitializeDisposableStack);
    bytecode_generator->builder()->StoreAccumulatorInRegister(
        bytecode_generator_->current_disposables_stack_);
  }

  ~DisposablesStackScope() {
    bytecode_generator_->set_current_disposables_stack(prev_disposables_stack_);
  }

 private:
  BytecodeGenerator* const bytecode_generator_;
  Register prev_disposables_stack_;
};

namespace {

template <typename PropertyT>
struct Accessors : public ZoneObject {
  Accessors() : getter(nullptr), setter(nullptr) {}
  PropertyT* getter;
  PropertyT* setter;
};

// A map from property names to getter/setter pairs allocated in the zone that
// also provides a way of accessing the pairs in the order they were first
// added so that the generated bytecode is always the same.
template <typename PropertyT>
class AccessorTable
    : public base::TemplateHashMap<Literal, Accessors<PropertyT>,
                                   bool (*)(void*, void*),
                                   ZoneAllocationPolicy> {
 public:
  explicit AccessorTable(Zone* zone)
      : base::TemplateHashMap<Literal, Accessors<PropertyT>,
                              bool (*)(void*, void*), ZoneAllocationPolicy>(
            Literal::Match, ZoneAllocationPolicy(zone)),
        zone_(zone) {}

  Accessors<PropertyT>* LookupOrInsert(Literal* key) {
    auto it = this->find(key, true);
    if (it->second == nullptr) {
      it->second = zone_->New<Accessors<PropertyT>>();
      ordered_accessors_.push_back({key, it->second});
    }
    return it->second;
  }

  const std::vector<std::pair<Literal*, Accessors<PropertyT>*>>&
  ordered_accessors() {
    return ordered_accessors_;
  }

 private:
  std::vector<std::pair<Literal*, Accessors<PropertyT>*>> ordered_accessors_;

  Zone* zone_;
};

}  // namespace

#ifdef DEBUG

static bool IsInEagerLiterals(
    FunctionLiteral* literal,
    const std::vector<FunctionLiteral*>& eager_literals) {
  for (FunctionLiteral* eager_literal : eager_literals) {
    if (literal == eager_literal) return true;
  }
  return false;
}

#endif  // DEBUG

BytecodeGenerator::BytecodeGenerator(
    LocalIsolate* local_isolate, Zone* compile_zone,
    UnoptimizedCompilationInfo* info,
    const AstStringConstants* ast_string_constants,
    std::vector<FunctionLiteral*>* eager_inner_literals, Handle<Script> script)
    : local_isolate_(local_isolate),
      zone_(compile_zone),
      builder_(zone(), info->num_parameters_including_this(),
               info->scope()->num_stack_slots(), info->feedback_vector_spec(),
               info->SourcePositionRecordingMode()),
      info_(info),
      ast_string_constants_(ast_string_constants),
      closure_scope_(info->scope()),
      current_scope_(info->scope()),
      eager_inner_literals_(eager_inner_literals),
      script_(script),
      feedback_slot_cache_(zone()->New<FeedbackSlotCache>(zone())),
      top_level_builder_(zone()->New<TopLevelDeclarationsBuilder>()),
      block_coverage_builder_(nullptr),
      function_literals_(0, zone()),
      native_function_literals_(0, zone()),
      object_literals_(0, zone()),
      array_literals_(0, zone()),
      class_literals_(0, zone()),
      template_objects_(0, zone()),
      vars_in_hole_check_bitmap_(0, zone()),
      execution_control_(nullptr),
      execution_context_(nullptr),
      execution_result_(nullptr),
      incoming_new_target_or_generator_(),
      current_disposables_stack_(),
      optional_chaining_null_labels_(nullptr),
      dummy_feedback_slot_(feedback_spec(), FeedbackSlotKind::kCompareOp),
      generator_jump_table_(nullptr),
      suspend_count_(0),
      loop_depth_(0),
      hole_check_bitmap_(0),
      current_loop_scope_(nullptr),
      current_for_in_scope_(nullptr),
      catch_prediction_(HandlerTable::UNCAUGHT) {
  DCHECK_EQ(closure_scope(), closure_scope()->GetClosureScope());
  if (info->has_source_range_map()) {
    block_coverage_builder_ = zone()->New<BlockCoverageBuilder>(
        zone(), builder(), info->source_range_map());
  }
}

namespace {

template <typename Isolate>
struct NullContextScopeHelper;

template <>
struct NullContextScopeHelper<Isolate> {
  using Type = NullContextScope;
};

template <>
struct NullContextScopeHelper<LocalIsolate> {
  class V8_NODISCARD DummyNullContextScope {
   public:
    explicit DummyNullContextScope(LocalIsolate*) {}
  };
  using Type = DummyNullContextScope;
};

template <typename Isolate>
using NullContextScopeFor = typename NullContextScopeHelper<Isolate>::Type;

}  // namespace

template <typename IsolateT>
Handle<BytecodeArray> BytecodeGenerator::FinalizeBytecode(
    IsolateT* isolate, Handle<Script> script) {
  DCHECK_EQ(ThreadId::Current(), isolate->thread_id());
#ifdef DEBUG
  // Unoptimized compilation should be context-independent. Verify that we don't
  // access the native context by nulling it out during finalization.
  NullContextScopeFor<IsolateT> null_context_scope(isolate);
#endif

  AllocateDeferredConstants(isolate, script);

  if (block_coverage_builder_) {
    Handle<CoverageInfo> coverage_info =
        isolate->factory()->NewCoverageInfo(block_coverage_builder_->slots());
    info()->set_coverage_info(coverage_info);
    if (v8_flags.trace_block_coverage) {
      StdoutStream os;
      coverage_info->CoverageInfoPrint(os, info()->literal()->GetDebugName());
    }
  }

  if (HasStackOverflow()) return Handle<BytecodeArray>();
  Handle<BytecodeArray> bytecode_array = builder()->ToBytecodeArray(isolate);

  if (incoming_new_target_or_generator_.is_valid()) {
    bytecode_array->set_incoming_new_target_or_generator_register(
        incoming_new_target_or_generator_);
  }

  return bytecode_array;
}

template Handle<BytecodeArray> BytecodeGenerator::FinalizeBytecode(
    Isolate* isolate, Handle<Script> script);
template Handle<BytecodeArray> BytecodeGenerator::FinalizeBytecode(
    LocalIsolate* isolate, Handle<Script> script);

template <typename IsolateT>
Handle<TrustedByteArray> BytecodeGenerator::FinalizeSourcePositionTable(
    IsolateT* isolate) {
  DCHECK_EQ(ThreadId::Current(), isolate->thread_id());
#ifdef DEBUG
  // Unoptimized compilation should be context-independent. Verify that we don't
  // access the native context by nulling it out during finalization.
  NullContextScopeFor<IsolateT> null_context_scope(isolate);
#endif

  Handle<TrustedByteArray> source_position_table =
      builder()->ToSourcePositionTable(isolate);

  LOG_CODE_EVENT(isolate,
                 CodeLinePosInfoRecordEvent(
                     info_->bytecode_array()->GetFirstBytecodeAddress(),
                     *source_position_table, JitCodeEvent::BYTE_CODE));

  return source_position_table;
}

template Handle<TrustedByteArray>
BytecodeGenerator::FinalizeSourcePositionTable(Isolate* isolate);
template Handle<TrustedByteArray>
BytecodeGenerator::FinalizeSourcePositionTable(LocalIsolate* isolate);

#ifdef DEBUG
int BytecodeGenerator::CheckBytecodeMatches(Tagged<BytecodeArray> bytecode) {
  return builder()->CheckBytecodeMatches(bytecode);
}
#endif

template <typename IsolateT>
void BytecodeGenerator::AllocateDeferredConstants(IsolateT* isolate,
                                                  Handle<Script> script) {
  if (top_level_builder()->has_top_level_declaration()) {
    // Build global declaration pair array.
    Handle<FixedArray> declarations = top_level_builder()->AllocateDeclarations(
        info(), this, script, isolate);
    if (declarations.is_null()) return SetStackOverflow();
    builder()->SetDeferredConstantPoolEntry(
        top_level_builder()->constant_pool_entry(), declarations);
  }

  // Find or build shared function infos.
  for (std::pair<FunctionLiteral*, size_t> literal : function_literals_) {
    FunctionLiteral* expr = literal.first;
    DirectHandle<SharedFunctionInfo> shared_info =
        Compiler::GetSharedFunctionInfo(expr, script, isolate);
    if (shared_info.is_null()) return SetStackOverflow();
    builder()->SetDeferredConstantPoolEntry(
        literal.second, indirect_handle(shared_info, isolate));
  }

  // Find or build shared function infos for the native function templates.
  for (std::pair<NativeFunctionLiteral*, size_t> literal :
       native_function_literals_) {
    // This should only happen for main-thread compilations.
    DCHECK((std::is_same<Isolate, v8::internal::Isolate>::value));

    NativeFunctionLiteral* expr = literal.first;
    v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);

    // Compute the function template for the native function.
    v8::Local<v8::FunctionTemplate> info =
        expr->extension()->GetNativeFunctionTemplate(
            v8_isolate, Utils::ToLocal(expr->name()));
    DCHECK(!info.IsEmpty());

    Handle<SharedFunctionInfo> shared_info =
        FunctionTemplateInfo::GetOrCreateSharedFunctionInfo(
            isolate, Utils::OpenHandle(*info), expr->name());
    DCHECK(!shared_info.is_null());
    builder()->SetDeferredConstantPoolEntry(literal.second, shared_info);
  }

  // Build object literal constant properties
  for (std::pair<ObjectLiteralBoilerplateBuilder*, size_t> literal :
       object_literals_) {
    ObjectLiteralBoilerplateBuilder* object_literal_builder = literal.first;
    if (object_literal_builder->properties_count() > 0) {
      // If constant properties is an empty fixed array, we've already added it
      // to the constant pool when visiting the object literal.
      Handle<ObjectBoilerplateDescription> constant_properties =
          object_literal_builder->GetOrBuildBoilerplateDescription(isolate);

      builder()->SetDeferredConstantPoolEntry(literal.second,
                                              constant_properties);
    }
  }

  // Build array literal constant elements
  for (std::pair<ArrayLiteralBoilerplateBuilder*, size_t> literal :
       array_literals_) {
    ArrayLiteralBoilerplateBuilder* array_literal_builder = literal.first;
    Handle<ArrayBoilerplateDescription> constant_elements =
        array_literal_builder->GetOrBuildBoilerplateDescription(isolate);
    builder()->SetDeferredConstantPoolEntry(literal.second, constant_elements);
  }

  // Build class literal boilerplates.
  for (std::pair<ClassLiteral*, size_t> literal : class_literals_) {
    ClassLiteral* class_literal = literal.first;
    Handle<ClassBoilerplate> class_boilerplate =
        ClassBoilerplate::New(isolate, class_literal, AllocationType::kOld);
    builder()->SetDeferredConstantPoolEntry(literal.second, class_boilerplate);
  }

  // Build template literals.
  for (std::pair<GetTemplateObject*, size_t> literal : template_objects_) {
    GetTemplateObject* get_template_object = literal.first;
    Handle<TemplateObjectDescription> description =
        get_template_object->GetOrBuildDescription(isolate);
    builder()->SetDeferredConstantPoolEntry(literal.second, description);
  }
}

template void BytecodeGenerator::AllocateDeferredConstants(
    Isolate* isolate, Handle<Script> script);
template void BytecodeGenerator::AllocateDeferredConstants(
    LocalIsolate* isolate, Handle<Script> script);

namespace {
bool NeedsContextInitialization(DeclarationScope* scope) {
  return scope->NeedsContext() && !scope->is_script_scope() &&
         !scope->is_module_scope();
}
}  // namespace

void BytecodeGenerator::GenerateBytecode(uintptr_t stack_limit) {
  InitializeAstVisitor(stack_limit);
  if (v8_flags.stress_lazy_compilation && local_isolate_->is_main_thread() &&
      !local_isolate_->AsIsolate()->bootstrapper()->IsActive()) {
    // Trigger stack overflow with 1/stress_lazy_compilation probability.
    // Do this only for the main thread compilations because querying random
    // numbers from background threads will make the random values dependent
    // on the thread scheduling and thus non-deterministic.
    stack_overflow_ = local_isolate_->fuzzer_rng()->NextInt(
                          v8_flags.stress_lazy_compilation) == 0;
  }

  // Initialize the incoming context.
  ContextScope incoming_context(this, closure_scope());

  // Initialize control scope.
  ControlScopeForTopLevel control(this);

  RegisterAllocationScope register_scope(this);

  AllocateTopLevelRegisters();

  builder()->EmitFunctionStartSourcePosition(
      info()->literal()->start_position());

  if (info()->literal()->CanSuspend()) {
    BuildGeneratorPrologue();
  }

  if (NeedsContextInitialization(closure_scope())) {
    // Push a new inner context scope for the function.
    BuildNewLocalActivationContext();
    ContextScope local_function_context(this, closure_scope());
    BuildLocalActivationContextInitialization();
    GenerateBytecodeBody();
  } else {
    GenerateBytecodeBody();
  }

  // Reset variables with hole check bitmap indices for subsequent compilations
  // in the same parsing zone.
  for (Variable* var : vars_in_hole_check_bitmap_) {
    var->ResetHoleCheckBitmapIndex();
  }

  // Check that we are not falling off the end.
  DCHECK(builder()->RemainderOfBlockIsDead());
}

void BytecodeGenerator::GenerateBytecodeBody() {
  GenerateBodyPrologue();

  if (IsBaseConstructor(function_kind())) {
    GenerateBaseConstructorBody();
  } else if (function_kind() == FunctionKind::kDerivedConstructor) {
    GenerateDerivedConstructorBody();
  } else if (IsAsyncFunction(function_kind()) ||
             IsModuleWithTopLevelAwait(function_kind())) {
    if (IsAsyncGeneratorFunction(function_kind())) {
      GenerateAsyncGeneratorFunctionBody();
    } else {
      GenerateAsyncFunctionBody();
    }
  } else {
    GenerateBodyStatements();
  }
}

void BytecodeGenerator::GenerateBodyPrologue() {
  // Build the arguments object if it is used.
  VisitArgumentsObject(closure_scope()->arguments());

  // Build rest arguments array if it is used.
  Variable* rest_parameter = closure_scope()->rest_parameter();
  VisitRestArgumentsArray(rest_parameter);

  // Build assignment to the function name or {.this_function}
  // variables if used.
  VisitThisFunctionVariable(closure_scope()->function_var());
  VisitThisFunctionVariable(closure_scope()->this_function_var());

  // Build assignment to {new.target} variable if it is used.
  VisitNewTargetVariable(closure_scope()->new_target_var());

  // Create a generator object if necessary and initialize the
  // {.generator_object} variable.
  FunctionLiteral* literal = info()->literal();
  if (IsResumableFunction(literal->kind())) {
    BuildGeneratorObjectVariableInitialization();
  }

  // Emit tracing call if requested to do so.
  if (v8_flags.trace) builder()->CallRuntime(Runtime::kTraceEnter);

  // Increment the function-scope block coverage counter.
  BuildIncrementBlockCoverageCounterIfEnabled(literal, SourceRangeKind::kBody);

  // Visit declarations within the function scope.
  if (closure_scope()->is_script_scope()) {
    VisitGlobalDeclarations(closure_scope()->declarations());
  } else if (closure_scope()->is_module_scope()) {
    VisitModuleDeclarations(closure_scope()->declarations());
  } else {
    VisitDeclarations(closure_scope()->declarations());
  }

  // Emit initializing assignments for module namespace imports (if any).
  VisitModuleNamespaceImports();
}

void BytecodeGenerator::GenerateBaseConstructorBody() {
  DCHECK(IsBaseConstructor(function_kind()));

  FunctionLiteral* literal = info()->literal();

  // The derived constructor case is handled in VisitCallSuper.
  if (literal->class_scope_has_private_brand()) {
    ClassScope* scope = info()->scope()->outer_scope()->AsClassScope();
    DCHECK_NOT_NULL(scope->brand());
    BuildPrivateBrandInitialization(builder()->Receiver(), scope->brand());
  }

  if (literal->requires_instance_members_initializer()) {
    BuildInstanceMemberInitialization(Register::function_closure(),
                                      builder()->Receiver());
  }

  GenerateBodyStatements();
}

void BytecodeGenerator::GenerateDerivedConstructorBody() {
  DCHECK_EQ(FunctionKind::kDerivedConstructor, function_kind());

  FunctionLiteral* literal = info()->literal();

  // Per spec, derived constructors can only return undefined or an object;
  // other primitives trigger an exception in ConstructStub.
  //
  // Since the receiver is popped by the callee, derived constructors return
  // <this> if the original return value was undefined.
  //
  // Also per spec, this return value check is done after all user code (e.g.,
  // finally blocks) are executed. For example, the following code does not
  // throw.
  //
  //   class C extends class {} {
  //     constructor() {
  //       try { throw 42; }
  //       catch(e) { return; }
  //       finally { super(); }
  //     }
  //   }
  //   new C();
  //
  // This check is implemented by jumping to the check instead of emitting a
  // return bytecode in-place inside derived constructors.
  //
  // Note that default derived constructors do not need this check as they
  // just forward a super call.

  BytecodeLabels check_return_value(zone());
  Register result = register_allocator()->NewRegister();
  ControlScopeForDerivedConstructor control(this, result, &check_return_value);

  {
    HoleCheckElisionScope elider(this);
    GenerateBodyStatementsWithoutImplicitFinalReturn();
  }

  if (check_return_value.empty()) {
    if (!builder()->RemainderOfBlockIsDead()) {
      BuildThisVariableLoad();
      BuildReturn(literal->return_position());
    }
  } else {
    BytecodeLabels return_this(zone());

    if (!builder()->RemainderOfBlockIsDead()) {
      builder()->Jump(return_this.New());
    }

    check_return_value.Bind(builder());
    builder()->LoadAccumulatorWithRegister(result);
    builder()->JumpIfUndefined(return_this.New());
    BuildReturn(literal->return_position());

    {
      return_this.Bind(builder());
      BuildThisVariableLoad();
      BuildReturn(literal->return_position());
    }
  }
}

void BytecodeGenerator::GenerateAsyncFunctionBody() {
  DCHECK((IsAsyncFunction(function_kind()) &&
          !IsAsyncGeneratorFunction(function_kind())) ||
         IsModuleWithTopLevelAwait(function_kind()));

  // Async functions always return promises. Return values fulfill that promise,
  // while synchronously thrown exceptions reject that promise. This is handled
  // by surrounding the body statements in a try-catch block as follows:
  //
  // try {
  //   <inner_block>
  // } catch (.catch) {
  //   return %_AsyncFunctionReject(.generator_object, .catch);
  // }

  FunctionLiteral* literal = info()->literal();

  HandlerTable::CatchPrediction outer_catch_prediction = catch_prediction();
  // When compiling a REPL script, use UNCAUGHT_ASYNC_AWAIT to preserve the
  // exception so DevTools can inspect it.
  set_catch_prediction(literal->scope()->is_repl_mode_scope()
                           ? HandlerTable::UNCAUGHT_ASYNC_AWAIT
                           : HandlerTable::ASYNC_AWAIT);

  BuildTryCatch(
      [&]() {
        GenerateBodyStatements();
        set_catch_prediction(outer_catch_prediction);
      },
      [&](Register context) {
        RegisterList args = register_allocator()->NewRegisterList(2);
        builder()
            ->MoveRegister(generator_object(), args[0])
            .StoreAccumulatorInRegister(args[1])  // exception
            .CallRuntime(Runtime::kInlineAsyncFunctionReject, args);
        // TODO(358404372): Should this return have a statement position?
        // Without one it is not possible to apply a debugger breakpoint.
        BuildReturn(kNoSourcePosition);
      },
      catch_prediction());
}

void BytecodeGenerator::GenerateAsyncGeneratorFunctionBody() {
  DCHECK(IsAsyncGeneratorFunction(function_kind()));
  set_catch_prediction(HandlerTable::ASYNC_AWAIT);

  // For ES2017 Async Generators, we produce:
  //
  // try {
  //   InitialYield;
  //   ...body...;
  // } catch (.catch) {
  //   %AsyncGeneratorReject(generator, .catch);
  // } finally {
  //   %_GeneratorC
```
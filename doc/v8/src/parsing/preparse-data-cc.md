Response:
Let's break down the thought process to analyze the `preparse-data.cc` file.

1. **Initial Skim and High-Level Understanding:**  The first step is to quickly read through the code, paying attention to comments and class names. Keywords like "preparse," "scope," "data," "builder," and "serialize" immediately stand out. The overall structure seems to involve building and consuming some kind of data related to parsing.

2. **Identifying Core Classes:** Focus on the major classes defined in the file: `PreparseDataBuilder`, `PreparseDataBuilder::ByteData`, `ConsumedPreparseData`, `OnHeapConsumedPreparseData`, `ZonePreparseData`, and `ZoneConsumedPreparseData`. The relationships between these classes will be key to understanding the file's purpose. Notice the `ProducedPreparseData` abstract class and its concrete implementations.

3. **Understanding `PreparseDataBuilder`:**  This class seems responsible for *creating* the preparse data. Look for methods like `Start`, `Close`, `AddChild`, `FinalizeChildren`, `SaveDataFor...`, and `Serialize`. These names strongly suggest the process of collecting and organizing information. The nested `ByteData` class likely handles the raw byte storage.

4. **Understanding `ConsumedPreparseData`:**  This class (and its derived classes) is likely responsible for *reading* the preparse data. Look for methods like `GetDataForSkippableFunction`, `RestoreScopeAllocationData`, and `RestoreDataFor...`. The different derived classes (`OnHeapConsumedPreparseData`, `ZoneConsumedPreparseData`) suggest different memory management contexts.

5. **Connecting the Builder and Consumer:** The `Serialize` methods in `PreparseDataBuilder` likely create the actual `PreparseData` objects that are then consumed by the `ConsumedPreparseData` classes. The `ProducedPreparseData` hierarchy acts as an intermediary for this transfer.

6. **Analyzing the Data Format:**  Pay close attention to the comment block describing the "Internal data format." This is crucial for understanding *what* information is being stored and *how*. The structure of skippable function data and scope allocation data is outlined. Note the debug-only sections.

7. **Identifying Key Data Points:**  Look at the types of data being saved. This includes:
    * Scope information (type, eval flags)
    * Variable information (name, assignment status, context allocation)
    * Inner function data (start/end positions, number of parameters, length, language mode, uses super)
    * Child `PreparseData` objects for inner functions

8. **Considering the "Why":**  Why is this preparse data necessary? The comments mention "skippable functions." This hints at an optimization where the parser can avoid fully parsing inner functions initially. The preparse data provides enough information for the outer function to function correctly.

9. **Relating to JavaScript:** Think about JavaScript features that might require this kind of pre-analysis. Lexical scoping, closures, and the `eval` function are strong candidates. The "uses super" flag is also relevant for classes.

10. **Considering Potential Errors:** What could go wrong in this process?  Mismatches between the builder and consumer, incorrect data offsets, or failure to handle all JavaScript language features would be potential bugs.

11. **Formulating the Functionality List:** Based on the analysis, list the key functions of the file:
    * Collect data about scopes and variables.
    * Store information about inner functions.
    * Create a hierarchical structure of preparse data.
    * Serialize this data for later use.
    * Deserialize and restore this data during parsing.
    * Support different memory contexts (heap and zone).

12. **Addressing the Specific Questions:** Now, go back to the prompt and answer the specific questions:
    * **Functionality List:**  Use the list generated above.
    * **Torque:** Check the file extension.
    * **JavaScript Relationship:**  Connect the functionality to JavaScript concepts like scoping, closures, `eval`, and classes. Provide concrete examples.
    * **Code Logic Inference:**  Choose a specific scenario (like saving data for a function with an inner function) and trace the data flow, providing hypothetical input and output.
    * **Common Programming Errors:** Think about errors that could arise from manual data manipulation or incorrect assumptions about the data format.

13. **Refine and Organize:** Review the answers for clarity, accuracy, and completeness. Ensure the JavaScript examples are clear and illustrative. Organize the information logically.

By following this structured approach, we can systematically analyze the V8 source code and understand its purpose and functionality. The key is to start with a high-level overview and progressively delve into the details, paying close attention to the code structure, comments, and class responsibilities.
好的，让我们来分析一下 `v8/src/parsing/preparse-data.cc` 这个 V8 源代码文件的功能。

**功能概述**

`preparse-data.cc` 文件的主要目的是**在 V8 的预解析（Pre-parsing）阶段收集和存储关于 JavaScript 代码结构的元数据，以便在后续的完整解析和编译阶段加速处理并支持一些优化。**  它定义了用于构建和消费这些元数据的类和方法。

更具体地说，这个文件主要负责以下几个方面：

1. **构建预解析数据 (PreparseDataBuilder)：**
   - 提供了一个 `PreparseDataBuilder` 类，用于在预解析阶段遍历抽象语法树 (AST) 时，收集关于作用域 (Scope)、变量 (Variable) 和内部函数的信息。
   - 能够记录作用域的类型、是否调用了 `eval`、变量是否被赋值、变量是否需要在上下文中分配等信息。
   - 能够存储内部函数的起始和结束位置、参数数量、长度等信息，以及内部函数的预解析数据（递归）。
   - 使用 `ByteData` 内部类来管理实际的字节数据存储。

2. **存储预解析数据 (PreparseData 及其相关结构)：**
   - 定义了用于在堆上存储预解析数据的结构 `PreparseData`。
   - 预解析数据以一种紧凑的二进制格式存储，包含了作用域信息、变量信息以及指向子 `PreparseData` 对象的指针（用于内部函数）。

3. **消费预解析数据 (ConsumedPreparseData)：**
   - 提供了一个 `ConsumedPreparseData` 抽象类及其实现（`OnHeapConsumedPreparseData` 和 `ZoneConsumedPreparseData`），用于在后续的解析和编译阶段读取和使用之前收集的元数据。
   - 可以恢复作用域的属性、变量的属性等信息。
   - 可以获取内部函数的预解析数据，以便在需要时跳过内部函数的完整解析。

4. **支持不同的内存区域：**
   - 提供了在 V8 的 Zone 分配器和堆上分配 `PreparseData` 的机制，并提供了相应的消费类。

**关于文件后缀 `.tq` 的说明**

如果 `v8/src/parsing/preparse-data.cc` 文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是 V8 用于定义运行时内置函数和类型系统的领域特定语言。  但根据您提供的文件内容，它是一个 `.cc` 文件，因此是用 C++ 编写的。

**与 JavaScript 功能的关系及 JavaScript 示例**

`preparse-data.cc` 中构建和消费的预解析数据与 JavaScript 的多个功能密切相关，主要体现在以下几个方面：

1. **作用域 (Scope) 和闭包 (Closure)：** 预解析数据存储了关于作用域的信息，例如作用域的类型（函数作用域、块级作用域等）、是否调用了 `eval`。这些信息对于理解变量的查找规则和实现闭包至关重要。

   ```javascript
   function outer() {
     let x = 10;
     function inner() {
       console.log(x); // inner 函数可以访问 outer 函数的变量 x (闭包)
     }
     return inner;
   }

   const myInner = outer();
   myInner(); // 输出 10
   ```

   预解析数据会记录 `inner` 函数的作用域信息，包括它可以访问外部作用域的变量。

2. **`eval` 函数：**  预解析数据会记录作用域内是否调用了 `eval` 函数。`eval` 的存在会影响作用域的静态分析和优化，因为它可以在运行时动态地引入新的变量。

   ```javascript
   function testEval(str) {
     let y = 20;
     eval(str); // eval 可以引入新的变量 z
     console.log(y, z);
   }

   testEval('var z = 30;'); // 输出 20, 30
   ```

   预解析阶段会标记 `testEval` 函数的作用域，表明其中调用了 `eval`。

3. **变量声明和使用：** 预解析数据会记录变量是否被赋值、是否需要在上下文中分配。这对于变量的生命周期管理和优化至关重要。

   ```javascript
   function exampleVar() {
     var a; // 声明但未赋值
     a = 5; // 赋值
     console.log(a);
   }
   ```

   预解析数据会记录变量 `a` 在其作用域内的声明和赋值情况。

4. **内部函数和性能优化：** 预解析数据存储了关于内部函数的信息，允许 V8 在某些情况下跳过内部函数的完整解析，从而提高整体解析速度。这对于包含大量内部函数的代码尤其有效。

   ```javascript
   function outerFunction() {
     function innerFunction1() {
       // 一些复杂的逻辑
     }
     function innerFunction2() {
       // 更多逻辑
     }
     // ...
   }
   ```

   预解析数据会记录 `innerFunction1` 和 `innerFunction2` 的元数据，使得 V8 可以选择延迟或跳过它们的完整解析。

5. **`super` 关键字：** 预解析数据还会记录作用域是否使用了 `super` 关键字，这与 JavaScript 的类和继承机制相关。

   ```javascript
   class Parent {
     constructor(name) {
       this.name = name;
     }
     greet() {
       console.log(`Hello, ${this.name}`);
     }
   }

   class Child extends Parent {
     constructor(name, age) {
       super(name); // 使用 super 调用父类的构造函数
       this.age = age;
     }
     greet() {
       super.greet(); // 使用 super 调用父类的方法
       console.log(`I am ${this.age} years old.`);
     }
   }
   ```

   预解析数据会标记 `Child` 类的方法作用域，表明其中使用了 `super` 关键字。

**代码逻辑推理：假设输入与输出**

假设我们有以下 JavaScript 代码片段：

```javascript
function mainFunction(p) {
  let localVar = 1;
  function innerFunction(q) {
    console.log(p + q + localVar);
  }
  return innerFunction;
}
```

**假设输入（在 `PreparseDataBuilder` 中处理）：**

- 一个表示 `mainFunction` 的 `DeclarationScope` 对象。
- 一个表示 `innerFunction` 的 `DeclarationScope` 对象。
- 变量 `p` 和 `localVar` 的 `Variable` 对象。

**预期的部分输出（存储在 `PreparseData` 中）：**

- **对于 `mainFunction` 的预解析数据：**
    - 作用域类型：函数作用域
    - 是否调用 `eval`：否
    - 变量 `localVar` 的信息：可能已被赋值，可能需要在上下文中分配（取决于 V8 的优化策略）。
    - 内部函数数量：1
    - 指向 `innerFunction` 预解析数据的指针。

- **对于 `innerFunction` 的预解析数据：**
    - 作用域类型：函数作用域
    - 是否调用 `eval`：否
    - 访问了外部变量：是 (访问了 `p` 和 `localVar`)。  （注意：具体实现可能不会直接存储“访问了外部变量”，而是通过其他信息推断出来）。
    - 参数数量：1

**假设输入（在 `ConsumedPreparseData` 中读取）：**

- 一个指向上面生成的 `PreparseData` 对象的指针。

**预期的部分输出：**

- 可以通过 `ConsumedPreparseData` 的方法获取 `mainFunction` 和 `innerFunction` 的作用域类型。
- 可以判断 `mainFunction` 中声明了一个局部变量 `localVar`。
- 可以得知 `mainFunction` 包含一个内部函数。
- 可以获取 `innerFunction` 的预解析数据并进一步分析。

**涉及用户常见的编程错误**

虽然 `preparse-data.cc` 主要处理 V8 内部逻辑，但它间接与一些常见的 JavaScript 编程错误相关，这些错误可能会影响预解析的效果或导致运行时错误：

1. **在 `eval` 中意外引入变量：**

   ```javascript
   function foo() {
     let x = 10;
     let code = 'var y = 20;';
     eval(code); // 错误：在严格模式下不允许在 eval 中声明变量
     console.log(y); // ReferenceError: y is not defined (在严格模式下)
   }
   foo();
   ```

   预解析阶段会标记包含 `eval` 的作用域，这会限制某些优化。如果在 `eval` 中引入的变量与现有变量冲突，可能会导致意外的行为。

2. **意外的全局变量：**

   ```javascript
   function bar() {
     z = 30; // 错误：未声明的变量，会成为全局变量
   }
   bar();
   console.log(z); // 输出 30
   ```

   预解析阶段可能会尝试分析变量的作用域，但对于这种未声明的全局变量，分析可能会变得复杂。

3. **闭包中的变量捕获问题：**

   ```javascript
   function createFunctions() {
     const functions = [];
     for (var i = 0; i < 5; i++) { // 注意这里使用了 var
       functions.push(function() {
         console.log(i);
       });
     }
     return functions;
   }

   const funcs = createFunctions();
   funcs[0](); // 输出 5，而不是预期的 0
   ```

   预解析数据会记录作用域和变量的信息，但这种由于 `var` 的作用域特性导致的闭包问题需要在完整的执行阶段才能完全体现。 预解析可能会注意到有闭包产生，但具体的变量捕获值需要在运行时确定。

4. **过度使用 `eval`：**  虽然 `eval` 有其用途，但过度使用会使代码难以理解和优化。预解析数据会标记 `eval` 的存在，这可能会触发 V8 中对包含 `eval` 的代码采取更保守的优化策略。

**总结**

`v8/src/parsing/preparse-data.cc` 是 V8 预解析功能的核心部分，它负责收集 JavaScript 代码的元数据，以便在后续的解析和编译阶段进行优化和功能实现。虽然开发者不会直接与这个文件交互，但了解其功能有助于理解 V8 如何处理和优化 JavaScript 代码，并能更好地理解某些 JavaScript 语言特性的实现机制。

Prompt: 
```
这是目录为v8/src/parsing/preparse-data.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/parsing/preparse-data.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/parsing/preparse-data.h"

#include <vector>

#include "src/ast/scopes.h"
#include "src/ast/variables.h"
#include "src/base/logging.h"
#include "src/handles/handles.h"
#include "src/objects/objects-inl.h"
#include "src/objects/shared-function-info.h"
#include "src/parsing/parser.h"
#include "src/parsing/preparse-data-impl.h"
#include "src/parsing/preparser.h"
#include "src/roots/roots.h"
#include "src/zone/zone-list-inl.h"  // crbug.com/v8/8816
#include "src/zone/zone-utils.h"

namespace v8 {
namespace internal {

namespace {

using ScopeSloppyEvalCanExtendVarsBit = base::BitField8<bool, 0, 1>;
using InnerScopeCallsEvalField = ScopeSloppyEvalCanExtendVarsBit::Next<bool, 1>;
using NeedsPrivateNameContextChainRecalcField =
    InnerScopeCallsEvalField::Next<bool, 1>;
using ShouldSaveClassVariableIndexField =
    NeedsPrivateNameContextChainRecalcField::Next<bool, 1>;

using VariableMaybeAssignedField = base::BitField8<bool, 0, 1>;
using VariableContextAllocatedField = VariableMaybeAssignedField::Next<bool, 1>;

using HasDataField = base::BitField<bool, 0, 1>;
using LengthEqualsParametersField = HasDataField::Next<bool, 1>;
using NumberOfParametersField = LengthEqualsParametersField::Next<uint16_t, 16>;

using LanguageField = base::BitField8<LanguageMode, 0, 1>;
using UsesSuperField = LanguageField::Next<bool, 1>;
static_assert(LanguageModeSize <= LanguageField::kNumValues);

}  // namespace

/*

  Internal data format for the backing store of PreparseDataBuilder and
  PreparseData::scope_data (on the heap):

  (Skippable function data:)
  ------------------------------------
  | scope_data_start (debug only)    |
  ------------------------------------
  | data for inner function n        |
  | ...                              |
  ------------------------------------
  | data for inner function 1        |
  | ...                              |
  ------------------------------------
  (Scope allocation data:)             << scope_data_start points here in debug
  ------------------------------------
  magic value (debug only)
  ------------------------------------
  scope positions (debug only)
  ------------------------------------
  | scope type << only in debug      |
  | eval                             |
  | ----------------------           |
  | | data for variables |           |
  | | ...                |           |
  | ----------------------           |
  ------------------------------------
  ------------------------------------
  | data for inner scope m           | << but not for function scopes
  | ...                              |
  ------------------------------------
  ...
  ------------------------------------
  | data for inner scope 1           |
  | ...                              |
  ------------------------------------

  PreparseData::child_data is an array of PreparseData objects, one
  for each skippable inner function.

  ConsumedPreparseData wraps a PreparseData and reads data from it.

 */

PreparseDataBuilder::PreparseDataBuilder(Zone* zone,
                                         PreparseDataBuilder* parent_builder,
                                         std::vector<void*>* children_buffer)
    : parent_(parent_builder),
      byte_data_(),
      children_buffer_(children_buffer),
      function_scope_(nullptr),
      function_length_(-1),
      num_inner_functions_(0),
      num_inner_with_data_(0),
      bailed_out_(false),
      has_data_(false) {}

void PreparseDataBuilder::DataGatheringScope::Start(
    DeclarationScope* function_scope) {
  Zone* main_zone = preparser_->main_zone();
  builder_ = main_zone->New<PreparseDataBuilder>(
      main_zone, preparser_->preparse_data_builder(),
      preparser_->preparse_data_builder_buffer());
  preparser_->set_preparse_data_builder(builder_);
  function_scope->set_preparse_data_builder(builder_);
}

void PreparseDataBuilder::DataGatheringScope::Close() {
  PreparseDataBuilder* parent = builder_->parent_;
  preparser_->set_preparse_data_builder(parent);
  builder_->FinalizeChildren(preparser_->main_zone());

  if (parent == nullptr) return;
  if (!builder_->HasDataForParent()) return;
  parent->AddChild(builder_);
}

void PreparseDataBuilder::ByteData::Start(std::vector<uint8_t>* buffer) {
  DCHECK(!is_finalized_);
  byte_data_ = buffer;
  DCHECK_EQ(byte_data_->size(), 0);
  DCHECK_EQ(index_, 0);
}

// This struct is just a type tag for Zone::NewArray<T>(size_t) call.
struct RawPreparseData {};

void PreparseDataBuilder::ByteData::Finalize(Zone* zone) {
  uint8_t* raw_zone_data =
      zone->AllocateArray<uint8_t, RawPreparseData>(index_);
  memcpy(raw_zone_data, byte_data_->data(), index_);
  byte_data_->resize(0);
  zone_byte_data_ = base::Vector<uint8_t>(raw_zone_data, index_);
#ifdef DEBUG
  is_finalized_ = true;
#endif
}

void PreparseDataBuilder::ByteData::Reserve(size_t bytes) {
  // Make sure we have at least {bytes} capacity left in the buffer_.
  DCHECK_LE(length(), byte_data_->size());
  size_t capacity = byte_data_->size() - length();
  if (capacity >= bytes) return;
  size_t delta = bytes - capacity;
  byte_data_->insert(byte_data_->end(), delta, 0);
}

int PreparseDataBuilder::ByteData::length() const { return index_; }

void PreparseDataBuilder::ByteData::Add(uint8_t byte) {
  DCHECK_LE(0, index_);
  DCHECK_LT(index_, byte_data_->size());
  (*byte_data_)[index_++] = byte;
}

#ifdef DEBUG
void PreparseDataBuilder::ByteData::WriteUint32(uint32_t data) {
  DCHECK(!is_finalized_);
  Add(kUint32Size);
  Add(data & 0xFF);
  Add((data >> 8) & 0xFF);
  Add((data >> 16) & 0xFF);
  Add((data >> 24) & 0xFF);
  free_quarters_in_last_byte_ = 0;
}

void PreparseDataBuilder::ByteData::SaveCurrentSizeAtFirstUint32() {
  int current_length = length();
  index_ = 0;
  CHECK_EQ(byte_data_->at(0), kUint32Size);
  WriteUint32(current_length);
  index_ = current_length;
}
#endif

void PreparseDataBuilder::ByteData::WriteVarint32(uint32_t data) {
#ifdef DEBUG
  // Save expected item size in debug mode.
  Add(kVarint32MinSize);
#endif
  // See ValueSerializer::WriteVarint.
  do {
    uint8_t next_byte = (data & 0x7F);
    data >>= 7;
    // Add continue bit.
    if (data) next_byte |= 0x80;
    Add(next_byte & 0xFF);
  } while (data);
#ifdef DEBUG
  Add(kVarint32EndMarker);
#endif
  free_quarters_in_last_byte_ = 0;
}

void PreparseDataBuilder::ByteData::WriteUint8(uint8_t data) {
  DCHECK(!is_finalized_);
#ifdef DEBUG
  // Save expected item size in debug mode.
  Add(kUint8Size);
#endif
  Add(data);
  free_quarters_in_last_byte_ = 0;
}

void PreparseDataBuilder::ByteData::WriteQuarter(uint8_t data) {
  DCHECK(!is_finalized_);
  DCHECK_LE(data, 3);
  if (free_quarters_in_last_byte_ == 0) {
#ifdef DEBUG
    // Save a marker in debug mode.
    Add(kQuarterMarker);
#endif
    Add(0);
    free_quarters_in_last_byte_ = 3;
  } else {
    --free_quarters_in_last_byte_;
  }

  uint8_t shift_amount = free_quarters_in_last_byte_ * 2;
  DCHECK_EQ(byte_data_->at(index_ - 1) & (3 << shift_amount), 0);
  (*byte_data_)[index_ - 1] |= (data << shift_amount);
}

void PreparseDataBuilder::DataGatheringScope::SetSkippableFunction(
    DeclarationScope* function_scope, int function_length,
    int num_inner_functions) {
  DCHECK_NULL(builder_->function_scope_);
  builder_->function_scope_ = function_scope;
  DCHECK_EQ(builder_->num_inner_functions_, 0);
  builder_->function_length_ = function_length;
  builder_->num_inner_functions_ = num_inner_functions;
  builder_->parent_->has_data_ = true;
}

bool PreparseDataBuilder::HasInnerFunctions() const {
  return !children_.empty();
}

bool PreparseDataBuilder::HasData() const { return !bailed_out_ && has_data_; }

bool PreparseDataBuilder::HasDataForParent() const {
  return HasData() || function_scope_ != nullptr;
}

void PreparseDataBuilder::AddChild(PreparseDataBuilder* child) {
  DCHECK(!finalized_children_);
  children_buffer_.Add(child);
}

void PreparseDataBuilder::FinalizeChildren(Zone* zone) {
  DCHECK(!finalized_children_);
  base::Vector<PreparseDataBuilder*> children =
      CloneVector(zone, children_buffer_.ToConstVector());
  children_buffer_.Rewind();
  children_ = children;
#ifdef DEBUG
  finalized_children_ = true;
#endif
}

bool PreparseDataBuilder::ScopeNeedsData(Scope* scope) {
  if (scope->is_function_scope()) {
    // Default constructors don't need data (they cannot contain inner functions
    // defined by the user). Other functions do.
    return !IsDefaultConstructor(scope->AsDeclarationScope()->function_kind());
  }
  if (!scope->is_hidden()) {
    for (Variable* var : *scope->locals()) {
      if (IsSerializableVariableMode(var->mode())) return true;
    }
  }
  for (Scope* inner = scope->inner_scope(); inner != nullptr;
       inner = inner->sibling()) {
    if (ScopeNeedsData(inner)) return true;
  }
  return false;
}

bool PreparseDataBuilder::SaveDataForSkippableFunction(
    PreparseDataBuilder* builder) {
  DeclarationScope* function_scope = builder->function_scope_;
  // Start position is used for a sanity check when consuming the data, we could
  // remove it in the future if we're very pressed for space but it's been good
  // at catching bugs in the wild so far.
  byte_data_.WriteVarint32(function_scope->start_position());
  byte_data_.WriteVarint32(function_scope->end_position());

  bool has_data = builder->HasData();
  bool length_equals_parameters =
      function_scope->num_parameters() == builder->function_length_;
  uint32_t has_data_and_num_parameters =
      HasDataField::encode(has_data) |
      LengthEqualsParametersField::encode(length_equals_parameters) |
      NumberOfParametersField::encode(function_scope->num_parameters());
  byte_data_.WriteVarint32(has_data_and_num_parameters);
  if (!length_equals_parameters) {
    byte_data_.WriteVarint32(builder->function_length_);
  }
  byte_data_.WriteVarint32(builder->num_inner_functions_);

  uint8_t language_and_super =
      LanguageField::encode(function_scope->language_mode()) |
      UsesSuperField::encode(function_scope->uses_super_property());
  byte_data_.WriteQuarter(language_and_super);
  return has_data;
}

void PreparseDataBuilder::SaveScopeAllocationData(DeclarationScope* scope,
                                                  Parser* parser) {
  if (!has_data_) return;
  DCHECK(HasInnerFunctions());

  byte_data_.Start(parser->preparse_data_buffer());

#ifdef DEBUG
  // Reserve Uint32 for scope_data_start debug info.
  byte_data_.Reserve(kUint32Size);
  byte_data_.WriteUint32(0);
#endif
  byte_data_.Reserve(children_.size() * kSkippableFunctionMaxDataSize);
  DCHECK(finalized_children_);
  for (const auto& builder : children_) {
    // Keep track of functions with inner data. {children_} contains also the
    // builders that have no inner functions at all.
    if (SaveDataForSkippableFunction(builder)) num_inner_with_data_++;
  }

  // Don't save incomplete scope information when bailed out.
  if (!bailed_out_) {
#ifdef DEBUG
  // function data items, kSkippableMinFunctionDataSize each.
  CHECK_GE(byte_data_.length(), kPlaceholderSize);
  CHECK_LE(byte_data_.length(), std::numeric_limits<uint32_t>::max());

  byte_data_.SaveCurrentSizeAtFirstUint32();
  // For a data integrity check, write a value between data about skipped
  // inner funcs and data about variables.
  byte_data_.Reserve(kUint32Size * 3);
  byte_data_.WriteUint32(kMagicValue);
  byte_data_.WriteUint32(scope->start_position());
  byte_data_.WriteUint32(scope->end_position());
#endif

  if (ScopeNeedsData(scope)) SaveDataForScope(scope);
  }
  byte_data_.Finalize(parser->factory()->zone());
}

void PreparseDataBuilder::SaveDataForScope(Scope* scope) {
  DCHECK_NE(scope->end_position(), kNoSourcePosition);
  DCHECK(ScopeNeedsData(scope));

#ifdef DEBUG
  byte_data_.Reserve(kUint8Size);
  byte_data_.WriteUint8(scope->scope_type());
#endif

  uint8_t scope_data_flags =
      ScopeSloppyEvalCanExtendVarsBit::encode(
          scope->is_declaration_scope() &&
          scope->AsDeclarationScope()->sloppy_eval_can_extend_vars()) |
      InnerScopeCallsEvalField::encode(scope->inner_scope_calls_eval()) |
      NeedsPrivateNameContextChainRecalcField::encode(
          scope->is_function_scope() &&
          scope->AsDeclarationScope()
              ->needs_private_name_context_chain_recalc()) |
      ShouldSaveClassVariableIndexField::encode(
          scope->is_class_scope() &&
          scope->AsClassScope()->should_save_class_variable_index());
  byte_data_.Reserve(kUint8Size);
  byte_data_.WriteUint8(scope_data_flags);

  if (scope->is_function_scope()) {
    Variable* function = scope->AsDeclarationScope()->function_var();
    if (function != nullptr) SaveDataForVariable(function);
  }

  for (Variable* var : *scope->locals()) {
    if (IsSerializableVariableMode(var->mode())) SaveDataForVariable(var);
  }

  SaveDataForInnerScopes(scope);
}

void PreparseDataBuilder::SaveDataForVariable(Variable* var) {
#ifdef DEBUG
  // Store the variable name in debug mode; this way we can check that we
  // restore data to the correct variable.
  const AstRawString* name = var->raw_name();
  byte_data_.Reserve(kUint32Size + (name->length() + 1) * kUint8Size);
  byte_data_.WriteUint8(name->is_one_byte());
  byte_data_.WriteUint32(name->length());
  for (int i = 0; i < name->length(); ++i) {
    byte_data_.WriteUint8(name->raw_data()[i]);
  }
#endif

  uint8_t variable_data = VariableMaybeAssignedField::encode(
                              var->maybe_assigned() == kMaybeAssigned) |
                          VariableContextAllocatedField::encode(
                              var->has_forced_context_allocation());
  byte_data_.Reserve(kUint8Size);
  byte_data_.WriteQuarter(variable_data);
}

void PreparseDataBuilder::SaveDataForInnerScopes(Scope* scope) {
  // Inner scopes are stored in the reverse order, but we'd like to write the
  // data in the logical order. There might be many inner scopes, so we don't
  // want to recurse here.
  for (Scope* inner = scope->inner_scope(); inner != nullptr;
       inner = inner->sibling()) {
    if (inner->IsSkippableFunctionScope()) {
      // Don't save data about function scopes, since they'll have their own
      // PreparseDataBuilder where their data is saved.
      DCHECK_NOT_NULL(inner->AsDeclarationScope()->preparse_data_builder());
      continue;
    }
    if (!ScopeNeedsData(inner)) continue;
    SaveDataForScope(inner);
  }
}


Handle<PreparseData> PreparseDataBuilder::ByteData::CopyToHeap(
    Isolate* isolate, int children_length) {
  DCHECK(is_finalized_);
  int data_length = zone_byte_data_.length();
  Handle<PreparseData> data =
      isolate->factory()->NewPreparseData(data_length, children_length);
  data->copy_in(0, zone_byte_data_.begin(), data_length);
  return data;
}

Handle<PreparseData> PreparseDataBuilder::ByteData::CopyToLocalHeap(
    LocalIsolate* isolate, int children_length) {
  DCHECK(is_finalized_);
  int data_length = zone_byte_data_.length();
  Handle<PreparseData> data =
      isolate->factory()->NewPreparseData(data_length, children_length);
  data->copy_in(0, zone_byte_data_.begin(), data_length);
  return data;
}

Handle<PreparseData> PreparseDataBuilder::Serialize(Isolate* isolate) {
  DCHECK(HasData());
  DCHECK(!ThisOrParentBailedOut());
  Handle<PreparseData> data =
      byte_data_.CopyToHeap(isolate, num_inner_with_data_);
  int i = 0;
  DCHECK(finalized_children_);
  for (const auto& builder : children_) {
    if (!builder->HasData()) continue;
    DirectHandle<PreparseData> child_data = builder->Serialize(isolate);
    data->set_child(i++, *child_data);
  }
  DCHECK_EQ(i, data->children_length());
  return data;
}

Handle<PreparseData> PreparseDataBuilder::Serialize(LocalIsolate* isolate) {
  DCHECK(HasData());
  DCHECK(!ThisOrParentBailedOut());
  Handle<PreparseData> data =
      byte_data_.CopyToLocalHeap(isolate, num_inner_with_data_);
  int i = 0;
  DCHECK(finalized_children_);
  for (const auto& builder : children_) {
    if (!builder->HasData()) continue;
    DirectHandle<PreparseData> child_data = builder->Serialize(isolate);
    data->set_child(i++, *child_data);
  }
  DCHECK_EQ(i, data->children_length());
  return data;
}

ZonePreparseData* PreparseDataBuilder::Serialize(Zone* zone) {
  DCHECK(HasData());
  DCHECK(!ThisOrParentBailedOut());
  ZonePreparseData* data = byte_data_.CopyToZone(zone, num_inner_with_data_);
  int i = 0;
  DCHECK(finalized_children_);
  for (const auto& builder : children_) {
    if (!builder->HasData()) continue;
    ZonePreparseData* child = builder->Serialize(zone);
    data->set_child(i++, child);
  }
  DCHECK_EQ(i, data->children_length());
  return data;
}

class BuilderProducedPreparseData final : public ProducedPreparseData {
 public:
  explicit BuilderProducedPreparseData(PreparseDataBuilder* builder)
      : builder_(builder) {
    DCHECK(builder->HasData());
  }

  Handle<PreparseData> Serialize(Isolate* isolate) final {
    return builder_->Serialize(isolate);
  }

  Handle<PreparseData> Serialize(LocalIsolate* isolate) final {
    return builder_->Serialize(isolate);
  }

  ZonePreparseData* Serialize(Zone* zone) final {
    return builder_->Serialize(zone);
  }

 private:
  PreparseDataBuilder* builder_;
};

class OnHeapProducedPreparseData final : public ProducedPreparseData {
 public:
  explicit OnHeapProducedPreparseData(Handle<PreparseData> data)
      : data_(data) {}

  Handle<PreparseData> Serialize(Isolate* isolate) final {
    DCHECK(!data_.is_null());
    return data_;
  }

  Handle<PreparseData> Serialize(LocalIsolate* isolate) final {
    DCHECK(!data_.is_null());
    DCHECK_IMPLIES(!isolate->is_main_thread(),
                   isolate->heap()->ContainsLocalHandle(data_.location()));
    return data_;
  }

  ZonePreparseData* Serialize(Zone* zone) final {
    // Not required.
    UNREACHABLE();
  }

 private:
  Handle<PreparseData> data_;
};

class ZoneProducedPreparseData final : public ProducedPreparseData {
 public:
  explicit ZoneProducedPreparseData(ZonePreparseData* data) : data_(data) {}

  Handle<PreparseData> Serialize(Isolate* isolate) final {
    return data_->Serialize(isolate);
  }

  Handle<PreparseData> Serialize(LocalIsolate* isolate) final {
    return data_->Serialize(isolate);
  }

  ZonePreparseData* Serialize(Zone* zone) final {
    base::Vector<uint8_t> data(data_->byte_data()->data(),
                               data_->byte_data()->size());
    return zone->New<ZonePreparseData>(zone, &data, data_->children_length());
  }

 private:
  ZonePreparseData* data_;
};

ProducedPreparseData* ProducedPreparseData::For(PreparseDataBuilder* builder,
                                                Zone* zone) {
  return zone->New<BuilderProducedPreparseData>(builder);
}

ProducedPreparseData* ProducedPreparseData::For(Handle<PreparseData> data,
                                                Zone* zone) {
  return zone->New<OnHeapProducedPreparseData>(data);
}

ProducedPreparseData* ProducedPreparseData::For(ZonePreparseData* data,
                                                Zone* zone) {
  return zone->New<ZoneProducedPreparseData>(data);
}

template <class Data>
ProducedPreparseData*
BaseConsumedPreparseData<Data>::GetDataForSkippableFunction(
    Zone* zone, int start_position, int* end_position, int* num_parameters,
    int* function_length, int* num_inner_functions, bool* uses_super_property,
    LanguageMode* language_mode) {
  // The skippable function *must* be the next function in the data. Use the
  // start position as a sanity check.
  typename ByteData::ReadingScope reading_scope(this);
  CHECK(scope_data_->HasRemainingBytes(
      PreparseByteDataConstants::kSkippableFunctionMinDataSize));
  int start_position_from_data = scope_data_->ReadVarint32();
  CHECK_EQ(start_position, start_position_from_data);
  *end_position = scope_data_->ReadVarint32();
  DCHECK_GT(*end_position, start_position);

  uint32_t has_data_and_num_parameters = scope_data_->ReadVarint32();
  bool has_data = HasDataField::decode(has_data_and_num_parameters);
  *num_parameters =
      NumberOfParametersField::decode(has_data_and_num_parameters);
  bool length_equals_parameters =
      LengthEqualsParametersField::decode(has_data_and_num_parameters);
  if (length_equals_parameters) {
    *function_length = *num_parameters;
  } else {
    *function_length = scope_data_->ReadVarint32();
  }
  *num_inner_functions = scope_data_->ReadVarint32();

  uint8_t language_and_super = scope_data_->ReadQuarter();
  *language_mode = LanguageMode(LanguageField::decode(language_and_super));
  *uses_super_property = UsesSuperField::decode(language_and_super);

  if (!has_data) return nullptr;

  // Retrieve the corresponding PreparseData and associate it to the
  // skipped function. If the skipped functions contains inner functions, those
  // can be skipped when the skipped function is eagerly parsed.
  return GetChildData(zone, child_index_++);
}

template <class Data>
void BaseConsumedPreparseData<Data>::RestoreScopeAllocationData(
    DeclarationScope* scope, AstValueFactory* ast_value_factory, Zone* zone) {
  DCHECK_EQ(scope->scope_type(), ScopeType::FUNCTION_SCOPE);
  typename ByteData::ReadingScope reading_scope(this);

#ifdef DEBUG
  int magic_value_from_data = scope_data_->ReadUint32();
  // Check that we've consumed all inner function data.
  DCHECK_EQ(magic_value_from_data, ByteData::kMagicValue);

  int start_position_from_data = scope_data_->ReadUint32();
  int end_position_from_data = scope_data_->ReadUint32();
  DCHECK_EQ(start_position_from_data, scope->start_position());
  DCHECK_EQ(end_position_from_data, scope->end_position());
#endif

  RestoreDataForScope(scope, ast_value_factory, zone);

  // Check that we consumed all scope data.
  DCHECK_EQ(scope_data_->RemainingBytes(), 0);
}

template <typename Data>
void BaseConsumedPreparseData<Data>::RestoreDataForScope(
    Scope* scope, AstValueFactory* ast_value_factory, Zone* zone) {
  if (scope->is_declaration_scope() &&
      scope->AsDeclarationScope()->is_skipped_function()) {
    return;
  }

  // It's possible that scope is not present in the data at all (since PreParser
  // doesn't create the corresponding scope). In this case, the Scope won't
  // contain any variables for which we need the data.
  if (!PreparseDataBuilder::ScopeNeedsData(scope)) return;

  // scope_type is stored only in debug mode.
  DCHECK_EQ(scope_data_->ReadUint8(), scope->scope_type());

  CHECK(scope_data_->HasRemainingBytes(ByteData::kUint8Size));
  uint32_t scope_data_flags = scope_data_->ReadUint8();
  if (ScopeSloppyEvalCanExtendVarsBit::decode(scope_data_flags)) {
    scope->RecordEvalCall();
  }
  if (InnerScopeCallsEvalField::decode(scope_data_flags)) {
    scope->RecordInnerScopeEvalCall();
  }
  if (NeedsPrivateNameContextChainRecalcField::decode(scope_data_flags)) {
    scope->AsDeclarationScope()->RecordNeedsPrivateNameContextChainRecalc();
  }
  if (ShouldSaveClassVariableIndexField::decode(scope_data_flags)) {
    Variable* var = scope->AsClassScope()->class_variable();
    // An anonymous class whose class variable needs to be saved might not
    // have the class variable created during reparse since we skip parsing
    // the inner scopes that contain potential access to static private
    // methods. So create it now.
    if (var == nullptr) {
      DCHECK(scope->AsClassScope()->is_anonymous_class());
      var = scope->AsClassScope()->DeclareClassVariable(
          ast_value_factory, ast_value_factory->empty_string(),
          kNoSourcePosition);
      AstNodeFactory factory(ast_value_factory, zone);
      Declaration* declaration =
          factory.NewVariableDeclaration(kNoSourcePosition);
      scope->declarations()->Add(declaration);
      declaration->set_var(var);
    }
    var->set_is_used();
    var->ForceContextAllocation();
    scope->AsClassScope()->set_should_save_class_variable_index();
  }

  if (scope->is_function_scope()) {
    Variable* function = scope->AsDeclarationScope()->function_var();
    if (function != nullptr) RestoreDataForVariable(function);
  }
  for (Variable* var : *scope->locals()) {
    if (IsSerializableVariableMode(var->mode())) RestoreDataForVariable(var);
  }

  RestoreDataForInnerScopes(scope, ast_value_factory, zone);
}

template <typename Data>
void BaseConsumedPreparseData<Data>::RestoreDataForVariable(Variable* var) {
#ifdef DEBUG
  const AstRawString* name = var->raw_name();
  bool data_one_byte = scope_data_->ReadUint8();
  DCHECK_IMPLIES(name->is_one_byte(), data_one_byte);
  DCHECK_EQ(scope_data_->ReadUint32(), static_cast<uint32_t>(name->length()));
  if (!name->is_one_byte() && data_one_byte) {
    // It's possible that "name" is a two-byte representation of the string
    // stored in the data.
    for (int i = 0; i < 2 * name->length(); i += 2) {
#if defined(V8_TARGET_LITTLE_ENDIAN)
      DCHECK_EQ(scope_data_->ReadUint8(), name->raw_data()[i]);
      DCHECK_EQ(0, name->raw_data()[i + 1]);
#else
      DCHECK_EQ(scope_data_->ReadUint8(), name->raw_data()[i + 1]);
      DCHECK_EQ(0, name->raw_data()[i]);
#endif  // V8_TARGET_LITTLE_ENDIAN
    }
  } else {
    for (int i = 0; i < name->length(); ++i) {
      DCHECK_EQ(scope_data_->ReadUint8(), name->raw_data()[i]);
    }
  }
#endif
  uint8_t variable_data = scope_data_->ReadQuarter();
  if (VariableMaybeAssignedField::decode(variable_data)) {
    var->SetMaybeAssigned();
  }
  if (VariableContextAllocatedField::decode(variable_data)) {
    var->set_is_used();
    var->ForceContextAllocation();
  }
}

template <typename Data>
void BaseConsumedPreparseData<Data>::RestoreDataForInnerScopes(
    Scope* scope, AstValueFactory* ast_value_factory, Zone* zone) {
  for (Scope* inner = scope->inner_scope(); inner != nullptr;
       inner = inner->sibling()) {
    RestoreDataForScope(inner, ast_value_factory, zone);
  }
}

#ifdef DEBUG
template <class Data>
bool BaseConsumedPreparseData<Data>::VerifyDataStart() {
  typename ByteData::ReadingScope reading_scope(this);
  // The first uint32 contains the size of the skippable function data.
  int scope_data_start = scope_data_->ReadUint32();
  scope_data_->SetPosition(scope_data_start);
  CHECK_EQ(scope_data_->ReadUint32(), ByteData::kMagicValue);
  // The first data item is scope_data_start. Skip over it.
  scope_data_->SetPosition(ByteData::kPlaceholderSize);
  return true;
}
#endif

Tagged<PreparseData> OnHeapConsumedPreparseData::GetScopeData() {
  return *data_;
}

ProducedPreparseData* OnHeapConsumedPreparseData::GetChildData(Zone* zone,
                                                               int index) {
  DisallowGarbageCollection no_gc;
  Handle<PreparseData> child_data_handle(data_->get_child(index), isolate_);
  return ProducedPreparseData::For(child_data_handle, zone);
}

OnHeapConsumedPreparseData::OnHeapConsumedPreparseData(
    LocalIsolate* isolate, Handle<PreparseData> data)
    : BaseConsumedPreparseData<Tagged<PreparseData>>(),
      isolate_(isolate),
      data_(data) {
  DCHECK_NOT_NULL(isolate);
  DCHECK(IsPreparseData(*data));
  DCHECK(VerifyDataStart());
}

ZonePreparseData::ZonePreparseData(Zone* zone, base::Vector<uint8_t>* byte_data,
                                   int children_length)
    : byte_data_(byte_data->begin(), byte_data->end(), zone),
      children_(children_length, zone) {}

Handle<PreparseData> ZonePreparseData::Serialize(Isolate* isolate) {
  int data_size = static_cast<int>(byte_data()->size());
  int child_data_length = children_length();
  Handle<PreparseData> result =
      isolate->factory()->NewPreparseData(data_size, child_data_length);
  result->copy_in(0, byte_data()->data(), data_size);

  for (int i = 0; i < child_data_length; i++) {
    ZonePreparseData* child = get_child(i);
    DCHECK_NOT_NULL(child);
    DirectHandle<PreparseData> child_data = child->Serialize(isolate);
    result->set_child(i, *child_data);
  }
  return result;
}

Handle<PreparseData> ZonePreparseData::Serialize(LocalIsolate* isolate) {
  int data_size = static_cast<int>(byte_data()->size());
  int child_data_length = children_length();
  Handle<PreparseData> result =
      isolate->factory()->NewPreparseData(data_size, child_data_length);
  result->copy_in(0, byte_data()->data(), data_size);

  for (int i = 0; i < child_data_length; i++) {
    ZonePreparseData* child = get_child(i);
    DCHECK_NOT_NULL(child);
    DirectHandle<PreparseData> child_data = child->Serialize(isolate);
    result->set_child(i, *child_data);
  }
  return result;
}

ZoneConsumedPreparseData::ZoneConsumedPreparseData(Zone* zone,
                                                   ZonePreparseData* data)
    : data_(data), scope_data_wrapper_(data_->byte_data()) {
  DCHECK(VerifyDataStart());
}

ZoneVectorWrapper ZoneConsumedPreparseData::GetScopeData() {
  return scope_data_wrapper_;
}

ProducedPreparseData* ZoneConsumedPreparseData::GetChildData(Zone* zone,
                                                             int child_index) {
  CHECK_GT(data_->children_length(), child_index);
  ZonePreparseData* child_data = data_->get_child(child_index);
  if (child_data == nullptr) return nullptr;
  return ProducedPreparseData::For(child_data, zone);
}

std::unique_ptr<ConsumedPreparseData> ConsumedPreparseData::For(
    Isolate* isolate, Handle<PreparseData> data) {
  return ConsumedPreparseData::For(isolate->main_thread_local_isolate(), data);
}

std::unique_ptr<ConsumedPreparseData> ConsumedPreparseData::For(
    LocalIsolate* isolate, Handle<PreparseData> data) {
  DCHECK(!data.is_null());
  return std::make_unique<OnHeapConsumedPreparseData>(isolate, data);
}

std::unique_ptr<ConsumedPreparseData> ConsumedPreparseData::For(
    Zone* zone, ZonePreparseData* data) {
  if (data == nullptr) return {};
  return std::make_unique<ZoneConsumedPreparseData>(zone, data);
}

}  // namespace internal
}  // namespace v8

"""

```
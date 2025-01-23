Response: Let's break down the thought process to analyze the `preparse-data.cc` file and explain its functionality with a JavaScript example.

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and its relationship to JavaScript, illustrated with an example. This means we need to understand what the C++ code *does* in the context of the V8 engine and how that relates to the JavaScript language.

2. **Initial Scan and Keywords:**  A quick scan reveals key terms: `PreparseData`, `PreparseDataBuilder`, `Scope`, `Variable`, `Function`, `ByteData`, `Serialize`, `Restore`. These immediately suggest the code is involved in some form of pre-processing or metadata storage related to JavaScript code structures (scopes, variables, functions).

3. **Data Structures – The Core Idea:**  The comments within the code provide valuable insights. The diagram outlining the `scope_data` format is crucial. It shows a hierarchical structure. The comment about `PreparseData::child_data` being an array of `PreparseData` objects reinforces this hierarchical idea – that preparse data is structured to reflect the nesting of functions.

4. **"Preparse": What does it mean?** The name "preparse" strongly hints at an optimization. It's likely that this data is collected *before* full parsing and execution to speed things up. What kind of information would be useful to collect beforehand?

5. **Key Classes and Their Roles:**

   * **`PreparseDataBuilder`:** This class seems responsible for *creating* and populating the `PreparseData`. The methods like `Start`, `Close`, `AddChild`, `SaveDataForScope`, `SaveDataForVariable`, `Serialize` all point to a building or serialization process.
   * **`PreparseData`:** This appears to be the data structure itself, holding the precomputed information. The `scope_data` and `child_data` members are central.
   * **`ConsumedPreparseData`:** This class is responsible for *reading* or *deserializing* the `PreparseData`. Methods like `GetDataForSkippableFunction`, `RestoreScopeAllocationData`, `RestoreDataForScope`, `RestoreDataForVariable` confirm this.
   * **`ByteData`:**  This handles the low-level details of writing and reading bytes to/from a buffer.

6. **Information Being Stored:** Examining the `SaveDataFor...` methods reveals the types of information being stored:
   * Function start and end positions.
   * Number of parameters.
   * Whether `eval` is used in a scope.
   * Whether a scope needs private name context chain recalculation.
   * Information about variables (maybe assigned, context allocated).
   * Information about inner functions.
   * Language mode and whether `super` is used.

7. **"Skippable Functions": A Key Concept:** The code repeatedly mentions "skippable functions." This is a crucial optimization. The idea is that V8 can initially avoid fully parsing the bodies of inner functions, as long as it has enough metadata about them. This metadata is what `PreparseData` stores.

8. **Connecting to JavaScript – The "Why":** Why is this information useful for JavaScript execution?
   * **Faster Initial Load:** By skipping full parsing of inner functions, the initial parsing of the main script or function is much faster.
   * **Optimized Scope Management:** Information about `eval` and variable allocation allows V8 to set up scopes more efficiently.
   * **Potentially Better Compilation:** Knowing if `super` is used can influence how the function is compiled.

9. **Constructing the JavaScript Example:**  To illustrate, we need a JavaScript code snippet that demonstrates the concepts of nested functions and the potential for skipping their initial parsing. A simple example with a function containing another function is sufficient. The example should highlight how V8 *might* process it differently due to preparsing.

10. **Refining the Explanation:**  Once the basic understanding is in place, the explanation can be refined by:
    * Grouping related functionalities (building, storage, consumption).
    * Explaining the optimization benefits.
    * Emphasizing the hierarchical nature of the data.
    * Clarifying the role of "skippable functions."
    * Connecting specific pieces of stored data to their potential impact on JavaScript execution.

11. **Review and Verification:**  Finally, reread the code and the explanation to ensure consistency and accuracy. Check if the JavaScript example accurately reflects the concepts discussed. Make sure the explanation is clear and avoids overly technical jargon where possible. For instance, instead of just saying "varint encoding," explaining *why* it's used (space efficiency) is helpful.

This iterative process of scanning, identifying keywords, understanding data structures, connecting to the higher-level goal (JavaScript optimization), and constructing an illustrative example is key to analyzing and explaining the functionality of such a code file.
这个C++源代码文件 `preparse-data.cc` 的主要功能是**为JavaScript代码的预解析阶段存储和管理相关数据，以加速后续的解析和编译过程。**  它定义了用于构建和消费预解析数据的类和数据结构。

更具体地说，它的作用包括：

1. **存储作用域信息 (Scope Information):**  记录了JavaScript代码中不同作用域（如函数作用域、块级作用域）的属性，例如：
   - 是否使用了 `eval`。
   - 作用域内的变量信息（是否被赋值，是否需要在上下文中分配空间）。
   - 是否需要重新计算私有名称上下文链。
   - 类作用域是否需要保存类变量索引。

2. **存储函数信息 (Function Information):**  对于可以跳过初始解析的内部函数（"skippable functions"），存储了关键信息：
   - 函数的起始和结束位置。
   - 参数的数量。
   - 函数体的长度（如果与参数数量不同）。
   - 是否使用了 `super` 关键字。
   - 函数的语言模式（严格模式或非严格模式）。
   - 该函数是否包含需要进一步预解析的数据。

3. **管理内部函数数据 (Managing Inner Function Data):**  它允许构建一个树形结构的预解析数据，其中每个节点代表一个作用域或函数，并可以包含子节点的预解析数据，用于表示内部的函数。

4. **序列化和反序列化预解析数据 (Serializing and Deserializing Preparse Data):**  提供了将预解析数据序列化到堆或本地堆，以及从已有的预解析数据中恢复信息的能力。这允许V8在不同的阶段和线程之间传递和使用预解析数据。

**它与JavaScript的功能的关系：**

这个文件直接影响了V8引擎解析和编译JavaScript代码的效率。 通过预先收集和存储关键信息，V8可以：

- **更快地跳过对某些内部函数的完整解析:**  如果在首次解析时遇到一个“可跳过的函数”，V8可以利用预解析数据中的信息，暂时避免深入解析其函数体，从而加快初始加载和解析速度。只有在真正需要执行该函数时，才会进行完整的解析。
- **优化作用域的创建和管理:**  预解析数据中的作用域信息可以帮助V8更快地创建和管理作用域，例如，知道一个作用域是否使用了 `eval` 可以影响其上下文的创建方式。
- **优化变量的分配:**  关于变量的信息（是否被赋值，是否需要在上下文中分配）可以帮助V8更有效地进行变量的分配和访问。

**JavaScript 示例：**

```javascript
function outerFunction() {
  let outerVar = 10;

  function innerFunction(param1) {
    console.log(outerVar + param1);
  }

  return innerFunction;
}

const myInnerFunction = outerFunction();
myInnerFunction(5); // 输出 15
```

在这个例子中，`innerFunction` 是 `outerFunction` 的一个内部函数，很可能被认为是一个“可跳过的函数”。

当 V8 预解析 `outerFunction` 时，`preparse-data.cc` 中的代码会执行以下类似的操作（简化描述）：

1. **为 `outerFunction` 创建 `PreparseDataBuilder`。**
2. **扫描 `outerFunction` 的作用域，并记录信息:**
   -  可能记录了 `outerVar` 的信息 (例如，它被赋值了)。
3. **遇到 `innerFunction` 的定义。**
4. **为 `innerFunction` 创建 `PreparseDataBuilder`。**
5. **收集 `innerFunction` 的关键信息并存储:**
   - 函数的起始和结束位置。
   - 参数数量（1）。
   - 是否使用了 `super` (否)。
   - 语言模式 (取决于上下文)。
   - 可能记录了 `innerFunction` 访问了外部变量 `outerVar`。
6. **将 `innerFunction` 的预解析数据作为子数据添加到 `outerFunction` 的预解析数据中。**

在初始解析阶段，V8 可能不会立即解析 `innerFunction` 的函数体 `console.log(outerVar + param1);`。  它会依赖预解析数据中的信息来了解 `innerFunction` 的基本结构和依赖关系。

只有当 `myInnerFunction(5)` 被调用时，V8 才真正需要完整地解析和编译 `innerFunction` 的代码。

**总结:**

`v8/src/parsing/preparse-data.cc` 是 V8 引擎中负责管理 JavaScript 代码预解析数据的核心组件。 它通过存储关键的作用域和函数信息，使得 V8 能够在初始解析阶段更加高效，从而提升 JavaScript 代码的加载和执行速度。 它通过构建和消费 `PreparseData` 对象来协调这一过程，这些对象包含了优化 JavaScript 解析和编译所需的重要元数据。

### 提示词
```
这是目录为v8/src/parsing/preparse-data.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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
```
Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/profiler/heap-snapshot-generator.cc`.

Here's a plan to address the request:

1. **Identify the core purpose:**  The code seems to be responsible for extracting references between objects in the V8 heap for generating heap snapshots. This involves identifying different object types and their internal structure to find related objects.

2. **Break down by function:** Analyze the purpose of each `Extract...References` function. These functions seem to handle different V8 object types (e.g., Context, Map, SharedFunctionInfo).

3. **Look for patterns:** Notice the use of `SetInternalReference`, `SetWeakReference`, and `TagObject`. These likely represent different types of relationships in the heap graph.

4. **Address specific requests:**
    - **Functionality:** List the identified functionalities.
    - **Torque:** Check if the file extension is `.tq`.
    - **JavaScript relationship:** Determine if the code relates to JavaScript concepts and provide examples if it does.
    - **Code logic reasoning:** Identify a function with clear input and output relationships and provide an example.
    - **Common programming errors:** Think about potential issues related to heap snapshots and how this code might expose them.
    - **Summary:**  Provide a concise overview of the code's role.

5. **Structure the answer:** Organize the findings according to the user's instructions (functionality, Torque, JavaScript, logic, errors, summary).
这是 `v8/src/profiler/heap-snapshot-generator.cc` 文件的一部分，它属于 V8 引擎的堆快照生成器模块。 这部分代码的主要功能是**提取不同类型 V8 堆对象的引用关系**，以便构建堆快照的图结构。

以下是更详细的功能分解：

1. **提取 Context 对象的引用:** `ExtractContextReferences` 函数负责提取 `Context` 对象的内部引用。这包括：
    - 作用域信息 (`scope_info`)
    - 上一个上下文 (`previous`)
    - 扩展对象 (`extension`)
    - 上下文中的变量和函数引用（通过 `scope_info`）
    - 原生上下文相关的引用（例如，规范化的 map 缓存，嵌入器数据）。

2. **提取 Map 对象的引用:** `ExtractMapReferences` 函数处理 `Map` 对象的引用。`Map` 对象描述了对象的结构和类型。这包括：
    - 转换信息 (`transition`)，包括强引用和弱引用。
    - 描述符数组 (`descriptors`)，包含对象的属性信息。
    - 原型对象 (`prototype`)。
    - 构造函数或后向指针 (`constructor_or_back_pointer`)。
    - 依赖代码 (`dependent_code`)。
    - 原型有效性单元 (`prototype_validity_cell`)。

3. **提取 SharedFunctionInfo 对象的引用:** `ExtractSharedFunctionInfoReferences` 函数处理共享函数信息对象，它包含了函数的元数据。这包括：
    - 代码对象 (`code`)，以及可能的指令流 (`instruction_stream`)。
    - 作用域信息 (`name_or_scope_info`)。
    - 脚本信息 (`script`)。
    - 受信任和不受信任的函数数据。
    - 外部作用域信息。

4. **提取 Script 对象的引用:** `ExtractScriptReferences` 函数提取脚本对象的引用，它代表了一段 JavaScript 代码。这包括：
    - 源代码 (`source`)。
    - 脚本名称 (`name`)。
    - 上下文数据 (`context_data`)。
    - 行尾信息 (`line_ends`)。
    - 其他脚本相关信息。

5. **提取其他各种类型对象的引用:**  代码中还有针对 `AccessorInfo`, `AccessorPair`, `JSWeakRef`, `WeakCell`, `Code`, `InstructionStream`, `Cell`, `FeedbackCell`, `PropertyCell`, `PrototypeInfo`, `AllocationSite`, `ArrayBoilerplateDescription`, `RegExpBoilerplateDescription`, `JSArrayBuffer`, `JSPromise`, `JSGeneratorObject`, `FixedArray`, `BytecodeArray`, `ScopeInfo`, `FeedbackVector`, `DescriptorArray`, `EnumCache`, `TransitionArray` 等多种 V8 堆对象的引用提取函数。每个函数都根据对象的内部结构，提取出它所引用的其他堆对象。

**关于文件类型：**

`v8/src/profiler/heap-snapshot-generator.cc` 以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**，而不是 Torque 源代码。

**与 JavaScript 功能的关系：**

这段代码直接关联到 V8 引擎如何表示和管理 JavaScript 对象。它通过分析 V8 内部的数据结构来理解 JavaScript 对象的属性、原型链、闭包、函数定义等概念。

**JavaScript 示例：**

例如，`ExtractContextReferences` 函数处理的 `Context` 对象，在 JavaScript 中代表一个执行上下文。它可以存储局部变量和闭包信息。考虑以下 JavaScript 代码：

```javascript
function outer() {
  let outerVar = 10;
  function inner() {
    console.log(outerVar); // inner 函数闭包引用了 outerVar
  }
  return inner;
}

const myInnerFunc = outer();
myInnerFunc();
```

当生成堆快照时，`ExtractContextReferences` 会识别 `inner` 函数的上下文，并提取对 `outerVar` 的引用。它还会提取对 `outer` 函数上下文的引用（通过 `previous` 字段），形成一个上下文链。

**代码逻辑推理和假设输入输出：**

以 `ExtractMapReferences` 函数为例，假设输入是一个指向 `Map` 对象的指针，该 `Map` 对象描述了一个具有原型对象的普通 JavaScript 对象。

**假设输入：** 一个指向 `Map` 对象的指针，该 `Map` 对象满足以下条件：
- 描述一个普通的 JavaScript 对象。
- 存在原型对象。
- 具有一些属性描述符。

**预期输出：** `ExtractMapReferences` 函数将会：
- 调用 `TagObject` 标记原型对象。
- 调用 `SetInternalReference` 记录从 `Map` 对象到原型对象的引用，使用 `Map::kPrototypeOffset` 作为偏移量。
- 调用 `TagObject` 标记描述符数组。
- 调用 `SetInternalReference` 记录从 `Map` 对象到描述符数组的引用，使用 `Map::kInstanceDescriptorsOffset` 作为偏移量。
- 可能会提取到转换信息 (`transition`) 的引用，具体取决于 `Map` 的状态。

**涉及用户常见的编程错误：**

这段代码本身不直接涉及用户编写 JavaScript 代码时的错误，但它可以帮助开发者分析由于内存泄漏或意外的对象引用导致的性能问题。 例如：

1. **意外的闭包引用导致内存泄漏:** 如果一个对象被意外地捕获在闭包中，导致其无法被垃圾回收，堆快照会显示上下文对象保持着对该对象的引用。`ExtractContextReferences` 和 `ExtractSharedFunctionInfoReferences` 可以帮助识别这类引用。

   ```javascript
   let detachedElement;
   function createLeak() {
     let largeObject = { data: new Array(1000000).fill(0) };
     detachedElement = document.createElement('div');
     detachedElement.data = largeObject; // 假设这里 document 未定义，导致 detachedElement 无法从 DOM 树中移除
     return function() {
       console.log(detachedElement.data); // 闭包引用了 detachedElement 和 largeObject
     };
   }

   let leakFunc = createLeak();
   // leakFunc 仍然持有对 detachedElement 和 largeObject 的引用，即使 detachedElement 不在 DOM 中
   ```

2. **全局变量导致的意外引用:** 全局变量会一直存在于全局上下文中，如果全局变量引用了大量对象，可能导致内存占用过高。堆快照可以帮助识别全局上下文中的大型对象引用。

**归纳功能 (第 3 部分)：**

这部分代码 (`v8/src/profiler/heap-snapshot-generator.cc` 的一部分) 的核心功能是 V8 堆快照生成过程中的 **对象引用提取**。它针对多种 V8 内部对象类型，根据它们的内部结构，识别并记录它们所引用的其他堆对象。这是构建堆快照图结构的关键步骤，为后续的堆分析和性能诊断提供了基础数据。通过分析这些引用关系，可以理解对象之间的依赖，识别内存泄漏，并优化 JavaScript 代码的性能。

### 提示词
```
这是目录为v8/src/profiler/heap-snapshot-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/profiler/heap-snapshot-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
{
      int idx = scope_info->ContextHeaderLength() + it->index();
      SetContextReference(entry, it->name(), context->get(idx),
                          Context::OffsetOfElementAt(idx));
    }
    if (scope_info->HasContextAllocatedFunctionName()) {
      Tagged<String> name = Cast<String>(scope_info->FunctionName());
      int idx = scope_info->FunctionContextSlotIndex(name);
      if (idx >= 0) {
        SetContextReference(entry, name, context->get(idx),
                            Context::OffsetOfElementAt(idx));
      }
    }
  }

  SetInternalReference(
      entry, "scope_info", context->get(Context::SCOPE_INFO_INDEX),
      FixedArray::OffsetOfElementAt(Context::SCOPE_INFO_INDEX));
  SetInternalReference(entry, "previous", context->get(Context::PREVIOUS_INDEX),
                       FixedArray::OffsetOfElementAt(Context::PREVIOUS_INDEX));
  if (context->has_extension()) {
    SetInternalReference(
        entry, "extension", context->get(Context::EXTENSION_INDEX),
        FixedArray::OffsetOfElementAt(Context::EXTENSION_INDEX));
  }

  if (IsNativeContext(context)) {
    TagObject(context->normalized_map_cache(), "(context norm. map cache)");
    TagObject(context->embedder_data(), "(context data)");
    for (size_t i = 0; i < arraysize(native_context_names); i++) {
      int index = native_context_names[i].index;
      const char* name = native_context_names[i].name;
      SetInternalReference(entry, name, context->get(index),
                           FixedArray::OffsetOfElementAt(index));
    }

    static_assert(Context::NEXT_CONTEXT_LINK == Context::FIRST_WEAK_SLOT);
    static_assert(Context::FIRST_WEAK_SLOT + 1 ==
                  Context::NATIVE_CONTEXT_SLOTS);
  }
}

void V8HeapExplorer::ExtractMapReferences(HeapEntry* entry, Tagged<Map> map) {
  Tagged<MaybeObject> maybe_raw_transitions_or_prototype_info =
      map->raw_transitions();
  Tagged<HeapObject> raw_transitions_or_prototype_info;
  if (maybe_raw_transitions_or_prototype_info.GetHeapObjectIfWeak(
          &raw_transitions_or_prototype_info)) {
    DCHECK(IsMap(raw_transitions_or_prototype_info));
    SetWeakReference(entry, "transition", raw_transitions_or_prototype_info,
                     Map::kTransitionsOrPrototypeInfoOffset);
  } else if (maybe_raw_transitions_or_prototype_info.GetHeapObjectIfStrong(
                 &raw_transitions_or_prototype_info)) {
    if (IsTransitionArray(raw_transitions_or_prototype_info)) {
      Tagged<TransitionArray> transitions =
          Cast<TransitionArray>(raw_transitions_or_prototype_info);
      if (map->CanTransition() && transitions->HasPrototypeTransitions()) {
        TagObject(transitions->GetPrototypeTransitions(),
                  "(prototype transitions)");
      }
      TagObject(transitions, "(transition array)");
      SetInternalReference(entry, "transitions", transitions,
                           Map::kTransitionsOrPrototypeInfoOffset);
    } else if (IsFixedArray(raw_transitions_or_prototype_info)) {
      TagObject(raw_transitions_or_prototype_info, "(transition)");
      SetInternalReference(entry, "transition",
                           raw_transitions_or_prototype_info,
                           Map::kTransitionsOrPrototypeInfoOffset);
    } else if (map->is_prototype_map()) {
      TagObject(raw_transitions_or_prototype_info, "prototype_info");
      SetInternalReference(entry, "prototype_info",
                           raw_transitions_or_prototype_info,
                           Map::kTransitionsOrPrototypeInfoOffset);
    }
  }
  Tagged<DescriptorArray> descriptors = map->instance_descriptors();
  TagObject(descriptors, "(map descriptors)");
  SetInternalReference(entry, "descriptors", descriptors,
                       Map::kInstanceDescriptorsOffset);
  SetInternalReference(entry, "prototype", map->prototype(),
                       Map::kPrototypeOffset);
  if (IsContextMap(map) || IsMapMap(map)) {
    Tagged<Object> native_context = map->native_context_or_null();
    TagObject(native_context, "(native context)");
    SetInternalReference(entry, "native_context", native_context,
                         Map::kConstructorOrBackPointerOrNativeContextOffset);
  } else {
    Tagged<Object> constructor_or_back_pointer =
        map->constructor_or_back_pointer();
    if (IsMap(constructor_or_back_pointer)) {
      TagObject(constructor_or_back_pointer, "(back pointer)");
      SetInternalReference(entry, "back_pointer", constructor_or_back_pointer,
                           Map::kConstructorOrBackPointerOrNativeContextOffset);
    } else if (IsFunctionTemplateInfo(constructor_or_back_pointer)) {
      TagObject(constructor_or_back_pointer, "(constructor function data)");
      SetInternalReference(entry, "constructor_function_data",
                           constructor_or_back_pointer,
                           Map::kConstructorOrBackPointerOrNativeContextOffset);
    } else {
      SetInternalReference(entry, "constructor", constructor_or_back_pointer,
                           Map::kConstructorOrBackPointerOrNativeContextOffset);
    }
  }
  TagObject(map->dependent_code(), "(dependent code)");
  SetInternalReference(entry, "dependent_code", map->dependent_code(),
                       Map::kDependentCodeOffset);
  TagObject(map->prototype_validity_cell(kRelaxedLoad),
            "(prototype validity cell)", HeapEntry::kObjectShape);
}

void V8HeapExplorer::ExtractSharedFunctionInfoReferences(
    HeapEntry* entry, Tagged<SharedFunctionInfo> shared) {
  TagObject(shared, "(shared function info)");
  {
    std::unique_ptr<char[]> name = shared->DebugNameCStr();
    Tagged<Code> code = shared->GetCode(isolate());
    TagObject(code, name[0] != '\0'
                        ? names_->GetFormatted("(code for %s)", name.get())
                        : names_->GetFormatted("(%s code)",
                                               CodeKindToString(code->kind())));
    if (code->has_instruction_stream()) {
      TagObject(
          code->instruction_stream(),
          name[0] != '\0'
              ? names_->GetFormatted("(instruction stream for %s)", name.get())
              : names_->GetFormatted("(%s instruction stream)",
                                     CodeKindToString(code->kind())));
    }
  }

  Tagged<Object> name_or_scope_info = shared->name_or_scope_info(kAcquireLoad);
  if (IsScopeInfo(name_or_scope_info)) {
    TagObject(name_or_scope_info, "(function scope info)");
  }
  SetInternalReference(entry, "name_or_scope_info", name_or_scope_info,
                       SharedFunctionInfo::kNameOrScopeInfoOffset);
  SetInternalReference(entry, "script", shared->script(kAcquireLoad),
                       SharedFunctionInfo::kScriptOffset);
  SetInternalReference(entry, "trusted_function_data",
                       shared->GetTrustedData(isolate()),
                       SharedFunctionInfo::kTrustedFunctionDataOffset);
  SetInternalReference(entry, "untrusted_function_data",
                       shared->GetUntrustedData(),
                       SharedFunctionInfo::kUntrustedFunctionDataOffset);
  SetInternalReference(
      entry, "raw_outer_scope_info_or_feedback_metadata",
      shared->raw_outer_scope_info_or_feedback_metadata(),
      SharedFunctionInfo::kOuterScopeInfoOrFeedbackMetadataOffset);
}

void V8HeapExplorer::ExtractScriptReferences(HeapEntry* entry,
                                             Tagged<Script> script) {
  SetInternalReference(entry, "source", script->source(),
                       Script::kSourceOffset);
  SetInternalReference(entry, "name", script->name(), Script::kNameOffset);
  SetInternalReference(entry, "context_data", script->context_data(),
                       Script::kContextDataOffset);
  TagObject(script->line_ends(), "(script line ends)", HeapEntry::kCode);
  SetInternalReference(entry, "line_ends", script->line_ends(),
                       Script::kLineEndsOffset);
  TagObject(script->infos(), "(infos)", HeapEntry::kCode);
  TagObject(script->host_defined_options(), "(host-defined options)",
            HeapEntry::kCode);
#if V8_ENABLE_WEBASSEMBLY
  if (script->type() == Script::Type::kWasm) {
    // Wasm reuses some otherwise unused fields for wasm-specific information.
    SetInternalReference(entry, "wasm_breakpoint_infos",
                         script->wasm_breakpoint_infos(),
                         Script::kEvalFromSharedOrWrappedArgumentsOffset);
    SetInternalReference(entry, "wasm_managed_native_module",
                         script->wasm_managed_native_module(),
                         Script::kEvalFromPositionOffset);
    SetInternalReference(entry, "wasm_weak_instance_list",
                         script->wasm_weak_instance_list(),
                         Script::kInfosOffset);
  }
#endif
}

void V8HeapExplorer::ExtractAccessorInfoReferences(
    HeapEntry* entry, Tagged<AccessorInfo> accessor_info) {
  SetInternalReference(entry, "name", accessor_info->name(),
                       AccessorInfo::kNameOffset);
  SetInternalReference(entry, "data", accessor_info->data(),
                       AccessorInfo::kDataOffset);
}

void V8HeapExplorer::ExtractAccessorPairReferences(
    HeapEntry* entry, Tagged<AccessorPair> accessors) {
  SetInternalReference(entry, "getter", accessors->getter(),
                       AccessorPair::kGetterOffset);
  SetInternalReference(entry, "setter", accessors->setter(),
                       AccessorPair::kSetterOffset);
}

void V8HeapExplorer::ExtractJSWeakRefReferences(HeapEntry* entry,
                                                Tagged<JSWeakRef> js_weak_ref) {
  SetWeakReference(entry, "target", js_weak_ref->target(),
                   JSWeakRef::kTargetOffset);
}

void V8HeapExplorer::ExtractWeakCellReferences(HeapEntry* entry,
                                               Tagged<WeakCell> weak_cell) {
  SetWeakReference(entry, "target", weak_cell->target(),
                   WeakCell::kTargetOffset);
  SetWeakReference(entry, "unregister_token", weak_cell->unregister_token(),
                   WeakCell::kUnregisterTokenOffset);
}

void V8HeapExplorer::TagBuiltinCodeObject(Tagged<Code> code, const char* name) {
  TagObject(code, names_->GetFormatted("(%s builtin code)", name));
  if (code->has_instruction_stream()) {
    TagObject(code->instruction_stream(),
              names_->GetFormatted("(%s builtin instruction stream)", name));
  }
}

void V8HeapExplorer::ExtractCodeReferences(HeapEntry* entry,
                                           Tagged<Code> code) {
  if (!code->has_instruction_stream()) return;

  SetInternalReference(entry, "instruction_stream", code->instruction_stream(),
                       Code::kInstructionStreamOffset);

  if (code->kind() == CodeKind::BASELINE) {
    TagObject(code->bytecode_or_interpreter_data(), "(interpreter data)");
    SetInternalReference(entry, "interpreter_data",
                         code->bytecode_or_interpreter_data(),
                         Code::kDeoptimizationDataOrInterpreterDataOffset);
    TagObject(code->bytecode_offset_table(), "(bytecode offset table)",
              HeapEntry::kCode);
    SetInternalReference(entry, "bytecode_offset_table",
                         code->bytecode_offset_table(),
                         Code::kPositionTableOffset);
  } else if (code->uses_deoptimization_data()) {
    Tagged<DeoptimizationData> deoptimization_data =
        Cast<DeoptimizationData>(code->deoptimization_data());
    TagObject(deoptimization_data, "(code deopt data)", HeapEntry::kCode);
    SetInternalReference(entry, "deoptimization_data", deoptimization_data,
                         Code::kDeoptimizationDataOrInterpreterDataOffset);
    if (deoptimization_data->length() > 0) {
      TagObject(deoptimization_data->FrameTranslation(), "(code deopt data)",
                HeapEntry::kCode);
      TagObject(deoptimization_data->LiteralArray(), "(code deopt data)",
                HeapEntry::kCode);
      TagObject(deoptimization_data->InliningPositions(), "(code deopt data)",
                HeapEntry::kCode);
    }
    TagObject(code->source_position_table(), "(source position table)",
              HeapEntry::kCode);
    SetInternalReference(entry, "source_position_table",
                         code->source_position_table(),
                         Code::kPositionTableOffset);
  }
}

void V8HeapExplorer::ExtractInstructionStreamReferences(
    HeapEntry* entry, Tagged<InstructionStream> istream) {
  Tagged<Code> code;
  if (!istream->TryGetCode(&code, kAcquireLoad))
    return;  // Not yet initialized.
  TagObject(code, "(code)", HeapEntry::kCode);
  SetInternalReference(entry, "code", code, InstructionStream::kCodeOffset);

  TagObject(istream->relocation_info(), "(code relocation info)",
            HeapEntry::kCode);
  SetInternalReference(entry, "relocation_info", istream->relocation_info(),
                       InstructionStream::kRelocationInfoOffset);
}

void V8HeapExplorer::ExtractCellReferences(HeapEntry* entry,
                                           Tagged<Cell> cell) {
  SetInternalReference(entry, "value", cell->value(), Cell::kValueOffset);
}

void V8HeapExplorer::ExtractFeedbackCellReferences(
    HeapEntry* entry, Tagged<FeedbackCell> feedback_cell) {
  TagObject(feedback_cell, "(feedback cell)");
  SetInternalReference(entry, "value", feedback_cell->value(),
                       FeedbackCell::kValueOffset);
}

void V8HeapExplorer::ExtractPropertyCellReferences(HeapEntry* entry,
                                                   Tagged<PropertyCell> cell) {
  SetInternalReference(entry, "value", cell->value(),
                       PropertyCell::kValueOffset);
  TagObject(cell->dependent_code(), "(dependent code)");
  SetInternalReference(entry, "dependent_code", cell->dependent_code(),
                       PropertyCell::kDependentCodeOffset);
}

void V8HeapExplorer::ExtractPrototypeInfoReferences(
    HeapEntry* entry, Tagged<PrototypeInfo> info) {
  TagObject(info->prototype_chain_enum_cache(), "(prototype chain enum cache)",
            HeapEntry::kObjectShape);
  TagObject(info->prototype_users(), "(prototype users)",
            HeapEntry::kObjectShape);
}

void V8HeapExplorer::ExtractAllocationSiteReferences(
    HeapEntry* entry, Tagged<AllocationSite> site) {
  SetInternalReference(entry, "transition_info",
                       site->transition_info_or_boilerplate(),
                       AllocationSite::kTransitionInfoOrBoilerplateOffset);
  SetInternalReference(entry, "nested_site", site->nested_site(),
                       AllocationSite::kNestedSiteOffset);
  TagObject(site->dependent_code(), "(dependent code)", HeapEntry::kCode);
  SetInternalReference(entry, "dependent_code", site->dependent_code(),
                       AllocationSite::kDependentCodeOffset);
}

void V8HeapExplorer::ExtractArrayBoilerplateDescriptionReferences(
    HeapEntry* entry, Tagged<ArrayBoilerplateDescription> value) {
  Tagged<FixedArrayBase> constant_elements = value->constant_elements();
  SetInternalReference(entry, "constant_elements", constant_elements,
                       ArrayBoilerplateDescription::kConstantElementsOffset);
  TagObject(constant_elements, "(constant elements)", HeapEntry::kCode);
}

void V8HeapExplorer::ExtractRegExpBoilerplateDescriptionReferences(
    HeapEntry* entry, Tagged<RegExpBoilerplateDescription> value) {
  TagObject(value->data(isolate()), "(RegExpData)", HeapEntry::kCode);
}

class JSArrayBufferDataEntryAllocator : public HeapEntriesAllocator {
 public:
  JSArrayBufferDataEntryAllocator(size_t size, V8HeapExplorer* explorer)
      : size_(size), explorer_(explorer) {}
  HeapEntry* AllocateEntry(HeapThing ptr) override {
    return explorer_->AddEntry(reinterpret_cast<Address>(ptr),
                               HeapEntry::kNative, "system / JSArrayBufferData",
                               size_);
  }
  HeapEntry* AllocateEntry(Tagged<Smi> smi) override {
    DCHECK(false);
    return nullptr;
  }

 private:
  size_t size_;
  V8HeapExplorer* explorer_;
};

void V8HeapExplorer::ExtractJSArrayBufferReferences(
    HeapEntry* entry, Tagged<JSArrayBuffer> buffer) {
  // Setup a reference to a native memory backing_store object.
  if (!buffer->backing_store()) return;
  size_t data_size = buffer->byte_length();
  JSArrayBufferDataEntryAllocator allocator(data_size, this);
  HeapEntry* data_entry =
      generator_->FindOrAddEntry(buffer->backing_store(), &allocator);
  entry->SetNamedReference(HeapGraphEdge::kInternal, "backing_store",
                           data_entry, generator_, HeapEntry::kOffHeapPointer);
}

void V8HeapExplorer::ExtractJSPromiseReferences(HeapEntry* entry,
                                                Tagged<JSPromise> promise) {
  SetInternalReference(entry, "reactions_or_result",
                       promise->reactions_or_result(),
                       JSPromise::kReactionsOrResultOffset);
}

void V8HeapExplorer::ExtractJSGeneratorObjectReferences(
    HeapEntry* entry, Tagged<JSGeneratorObject> generator) {
  SetInternalReference(entry, "function", generator->function(),
                       JSGeneratorObject::kFunctionOffset);
  SetInternalReference(entry, "context", generator->context(),
                       JSGeneratorObject::kContextOffset);
  SetInternalReference(entry, "receiver", generator->receiver(),
                       JSGeneratorObject::kReceiverOffset);
  SetInternalReference(entry, "parameters_and_registers",
                       generator->parameters_and_registers(),
                       JSGeneratorObject::kParametersAndRegistersOffset);
}

void V8HeapExplorer::ExtractFixedArrayReferences(HeapEntry* entry,
                                                 Tagged<FixedArray> array) {
  for (int i = 0, l = array->length(); i < l; ++i) {
    DCHECK(!HasWeakHeapObjectTag(array->get(i)));
    SetInternalReference(entry, i, array->get(i), array->OffsetOfElementAt(i));
  }
}

void V8HeapExplorer::ExtractNumberReference(HeapEntry* entry,
                                            Tagged<Object> number) {
  DCHECK(IsNumber(number));

  // Must be large enough to fit any double, int, or size_t.
  char arr[32];
  base::Vector<char> buffer(arr, arraysize(arr));

  const char* string;
  if (IsSmi(number)) {
    int int_value = Smi::ToInt(number);
    string = IntToCString(int_value, buffer);
  } else {
    double double_value = Cast<HeapNumber>(number)->value();
    string = DoubleToCString(double_value, buffer);
  }

  const char* name = names_->GetCopy(string);

  SnapshotObjectId id = heap_object_map_->get_next_id();
  HeapEntry* child_entry =
      snapshot_->AddEntry(HeapEntry::kString, name, id, 0, 0);
  entry->SetNamedReference(HeapGraphEdge::kInternal, "value", child_entry,
                           generator_);
}

void V8HeapExplorer::ExtractBytecodeArrayReferences(
    HeapEntry* entry, Tagged<BytecodeArray> bytecode) {
  RecursivelyTagConstantPool(bytecode->constant_pool(), "(constant pool)",
                             HeapEntry::kCode, 3);
  TagObject(bytecode->handler_table(), "(handler table)", HeapEntry::kCode);
  TagObject(bytecode->raw_source_position_table(kAcquireLoad),
            "(source position table)", HeapEntry::kCode);
}

void V8HeapExplorer::ExtractScopeInfoReferences(HeapEntry* entry,
                                                Tagged<ScopeInfo> info) {
  if (!info->HasInlinedLocalNames()) {
    TagObject(info->context_local_names_hashtable(), "(context local names)",
              HeapEntry::kCode);
  }
}

void V8HeapExplorer::ExtractFeedbackVectorReferences(
    HeapEntry* entry, Tagged<FeedbackVector> feedback_vector) {
#ifndef V8_ENABLE_LEAPTIERING
  Tagged<MaybeObject> code = feedback_vector->maybe_optimized_code();
  Tagged<HeapObject> code_heap_object;
  if (code.GetHeapObjectIfWeak(&code_heap_object)) {
    SetWeakReference(entry, "optimized code", code_heap_object,
                     FeedbackVector::kMaybeOptimizedCodeOffset);
  }
#endif  // !V8_ENABLE_LEAPTIERING
  for (int i = 0; i < feedback_vector->length(); ++i) {
    Tagged<MaybeObject> maybe_entry = *(feedback_vector->slots_start() + i);
    Tagged<HeapObject> entry;
    if (maybe_entry.GetHeapObjectIfStrong(&entry) &&
        (entry->map(isolate())->instance_type() == WEAK_FIXED_ARRAY_TYPE ||
         IsFixedArrayExact(entry))) {
      TagObject(entry, "(feedback)", HeapEntry::kCode);
    }
  }
}

void V8HeapExplorer::ExtractDescriptorArrayReferences(
    HeapEntry* entry, Tagged<DescriptorArray> array) {
  SetInternalReference(entry, "enum_cache", array->enum_cache(),
                       DescriptorArray::kEnumCacheOffset);
  MaybeObjectSlot start = MaybeObjectSlot(array->GetDescriptorSlot(0));
  MaybeObjectSlot end = MaybeObjectSlot(
      array->GetDescriptorSlot(array->number_of_all_descriptors()));
  for (int i = 0; start + i < end; ++i) {
    MaybeObjectSlot slot = start + i;
    int offset = static_cast<int>(slot.address() - array.address());
    Tagged<MaybeObject> object = *slot;
    Tagged<HeapObject> heap_object;
    if (object.GetHeapObjectIfWeak(&heap_object)) {
      SetWeakReference(entry, i, heap_object, offset);
    } else if (object.GetHeapObjectIfStrong(&heap_object)) {
      SetInternalReference(entry, i, heap_object, offset);
    }
  }
}

void V8HeapExplorer::ExtractEnumCacheReferences(HeapEntry* entry,
                                                Tagged<EnumCache> cache) {
  TagObject(cache->keys(), "(enum cache)", HeapEntry::kObjectShape);
  TagObject(cache->indices(), "(enum cache)", HeapEntry::kObjectShape);
}

void V8HeapExplorer::ExtractTransitionArrayReferences(
    HeapEntry* entry, Tagged<TransitionArray> transitions) {
  if (transitions->HasPrototypeTransitions()) {
    TagObject(transitions->GetPrototypeTransitions(), "(prototype transitions)",
              HeapEntry::kObjectShape);
  }
}

template <typename T>
void V8HeapExplorer::ExtractWeakArrayReferences(int header_size,
                                                HeapEntry* entry,
                                                Tagged<T> array) {
  for (int i = 0; i < array->length(); ++i) {
    Tagged<MaybeObject> object = array->get(i);
    Tagged<HeapObject> heap_object;
    if (object.GetHeapObjectIfWeak(&heap_object)) {
      SetWeakReference(entry, i, heap_object, header_size + i * kTaggedSize);
    } else if (object.GetHeapObjectIfStrong(&heap_object)) {
      SetInternalReference(entry, i, heap_object,
                           header_size + i * kTaggedSize);
    }
  }
}

void V8HeapExplorer::ExtractPropertyReferences(Tagged<JSObject> js_obj,
                                               HeapEntry* entry) {
  Isolate* isolate = js_obj->GetIsolate();
  if (js_obj->HasFastProperties()) {
    Tagged<DescriptorArray> descs =
        js_obj->map()->instance_descriptors(isolate);
    for (InternalIndex i : js_obj->map()->IterateOwnDescriptors()) {
      PropertyDetails details = descs->GetDetails(i);
      switch (details.location()) {
        case PropertyLocation::kField: {
          if (!snapshot_->capture_numeric_value()) {
            Representation r = details.representation();
            if (r.IsSmi() || r.IsDouble()) break;
          }

          Tagged<Name> k = descs->GetKey(i);
          FieldIndex field_index =
              FieldIndex::ForDetails(js_obj->map(), details);
          Tagged<Object> value = js_obj->RawFastPropertyAt(field_index);
          int field_offset =
              field_index.is_inobject() ? field_index.offset() : -1;

          SetDataOrAccessorPropertyReference(details.kind(), entry, k, value,
                                             nullptr, field_offset);
          break;
        }
        case PropertyLocation::kDescriptor:
          SetDataOrAccessorPropertyReference(details.kind(), entry,
                                             descs->GetKey(i),
                                             descs->GetStrongValue(i));
          break;
      }
    }
  } else if (IsJSGlobalObject(js_obj)) {
    // We assume that global objects can only have slow properties.
    Tagged<GlobalDictionary> dictionary =
        Cast<JSGlobalObject>(js_obj)->global_dictionary(kAcquireLoad);
    ReadOnlyRoots roots(isolate);
    for (InternalIndex i : dictionary->IterateEntries()) {
      if (!dictionary->IsKey(roots, dictionary->KeyAt(i))) continue;
      Tagged<PropertyCell> cell = dictionary->CellAt(i);
      Tagged<Name> name = cell->name();
      Tagged<Object> value = cell->value();
      PropertyDetails details = cell->property_details();
      SetDataOrAccessorPropertyReference(details.kind(), entry, name, value);
    }
  } else if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    // SwissNameDictionary::IterateEntries creates a Handle, which should not
    // leak out of here.
    HandleScope scope(isolate);

    Tagged<SwissNameDictionary> dictionary =
        js_obj->property_dictionary_swiss();
    ReadOnlyRoots roots(isolate);
    for (InternalIndex i : dictionary->IterateEntries()) {
      Tagged<Object> k = dictionary->KeyAt(i);
      if (!dictionary->IsKey(roots, k)) continue;
      Tagged<Object> value = dictionary->ValueAt(i);
      PropertyDetails details = dictionary->DetailsAt(i);
      SetDataOrAccessorPropertyReference(details.kind(), entry, Cast<Name>(k),
                                         value);
    }
  } else {
    Tagged<NameDictionary> dictionary = js_obj->property_dictionary();
    ReadOnlyRoots roots(isolate);
    for (InternalIndex i : dictionary->IterateEntries()) {
      Tagged<Object> k = dictionary->KeyAt(i);
      if (!dictionary->IsKey(roots, k)) continue;
      Tagged<Object> value = dictionary->ValueAt(i);
      PropertyDetails details = dictionary->DetailsAt(i);
      SetDataOrAccessorPropertyReference(details.kind(), entry, Cast<Name>(k),
                                         value);
    }
  }
}

void V8HeapExplorer::ExtractAccessorPairProperty(HeapEntry* entry,
                                                 Tagged<Name> key,
                                                 Tagged<Object> callback_obj,
                                                 int field_offset) {
  if (!IsAccessorPair(callback_obj)) return;
  Tagged<AccessorPair> accessors = Cast<AccessorPair>(callback_obj);
  SetPropertyReference(entry, key, accessors, nullptr, field_offset);
  Tagged<Object> getter = accessors->getter();
  if (!IsOddball(getter)) {
    SetPropertyReference(entry, key, getter, "get %s");
  }
  Tagged<Object> setter = accessors->setter();
  if (!IsOddball(setter)) {
    SetPropertyReference(entry, key, setter, "set %s");
  }
}

void V8HeapExplorer::ExtractElementReferences(Tagged<JSObject> js_obj,
                                              HeapEntry* entry) {
  ReadOnlyRoots roots = js_obj->GetReadOnlyRoots();
  if (js_obj->HasObjectElements()) {
    Tagged<FixedArray> elements = Cast<FixedArray>(js_obj->elements());
    int length = IsJSArray(js_obj) ? Smi::ToInt(Cast<JSArray>(js_obj)->length())
                                   : elements->length();
    for (int i = 0; i < length; ++i) {
      if (!IsTheHole(elements->get(i), roots)) {
        SetElementReference(entry, i, elements->get(i));
      }
    }
  } else if (js_obj->HasDictionaryElements()) {
    Tagged<NumberDictionary> dictionary = js_obj->element_dictionary();
    for (InternalIndex i : dictionary->IterateEntries()) {
      Tagged<Object> k = dictionary->KeyAt(i);
      if (!dictionary->IsKey(roots, k)) continue;
      uint32_t index =
          static_cast<uint32_t>(Object::NumberValue(Cast<Number>(k)));
      SetElementReference(entry, index, dictionary->ValueAt(i));
    }
  }
}

void V8HeapExplorer::ExtractInternalReferences(Tagged<JSObject> js_obj,
                                               HeapEntry* entry) {
  int length = js_obj->GetEmbedderFieldCount();
  for (int i = 0; i < length; ++i) {
    Tagged<Object> o = js_obj->GetEmbedderField(i);
    SetInternalReference(entry, i, o, js_obj->GetEmbedderFieldOffset(i));
  }
}

#if V8_ENABLE_WEBASSEMBLY

void V8HeapExplorer::ExtractWasmStructReferences(Tagged<WasmStruct> obj,
                                                 HeapEntry* entry) {
  wasm::StructType* type = obj->type();
  Tagged<WasmTypeInfo> info = obj->map()->wasm_type_info();
  // Getting the trusted data is safe; structs always have their trusted data
  // defined.
  wasm::NamesProvider* names =
      info->trusted_data(isolate())->native_module()->GetNamesProvider();
  Isolate* isolate = heap_->isolate();
  for (uint32_t i = 0; i < type->field_count(); i++) {
    wasm::StringBuilder sb;
    names->PrintFieldName(sb, info->module_type_index(), i);
    sb << '\0';
    const char* field_name = names_->GetCopy(sb.start());
    switch (type->field(i).kind()) {
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kI32:
      case wasm::kI64:
      case wasm::kF16:
      case wasm::kF32:
      case wasm::kF64:
      case wasm::kS128: {
        if (!snapshot_->capture_numeric_value()) continue;
        std::string value_string = obj->GetFieldValue(i).to_string();
        const char* value_name = names_->GetCopy(value_string.c_str());
        SnapshotObjectId id = heap_object_map_->get_next_id();
        HeapEntry* child_entry =
            snapshot_->AddEntry(HeapEntry::kString, value_name, id, 0, 0);
        entry->SetNamedReference(HeapGraphEdge::kInternal, field_name,
                                 child_entry, generator_);
        break;
      }
      case wasm::kRef:
      case wasm::kRefNull: {
        int field_offset = type->field_offset(i);
        Tagged<Object> value = obj->RawField(field_offset).load(isolate);
        // We could consider hiding {null} fields by default (like we do for
        // arrays, see below), but for now we always include them, in the hope
        // that they might help identify opportunities for struct size
        // reductions.
        HeapEntry* value_entry = GetEntry(value);
        entry->SetNamedReference(HeapGraphEdge::kProperty, field_name,
                                 value_entry, generator_);
        MarkVisitedField(WasmStruct::kHeaderSize + field_offset);
        break;
      }
      case wasm::kRtt:
      case wasm::kVoid:
      case wasm::kTop:
      case wasm::kBottom:
        UNREACHABLE();
    }
  }
}

void V8HeapExplorer::ExtractWasmArrayReferences(Tagged<WasmArray> obj,
                                                HeapEntry* entry) {
  if (!obj->type()->element_type().is_reference()) return;
  Isolate* isolate = heap_->isolate();
  ReadOnlyRoots roots(isolate);
  for (uint32_t i = 0; i < obj->length(); i++) {
    Tagged<Object> value = obj->ElementSlot(i).load(isolate);
    // By default, don't show {null} entries, to reduce noise: they can make
    // it difficult to find non-null entries in sparse arrays. We piggyback
    // on the "capture numeric values" flag as an opt-in to produce more
    // detailed/verbose snapshots, including {null} entries.
    if (value != roots.wasm_null() || snapshot_->capture_numeric_value()) {
      SetElementReference(entry, i, value);
    }
    MarkVisitedField(obj->element_offset(i));
  }
}

void V8HeapExplorer::ExtractWasmTrustedInstanceDataReferences(
    Tagged<WasmTrustedInstanceData> trusted_data, HeapEntry* entry) {
  PtrComprCageBase cage_base(heap_->isolate());
  for (size_t i = 0; i < WasmTrustedInstanceData::kTaggedFieldOffsets.size();
       i++) {
    const uint16_t offset = WasmTrustedInstanceData::kTaggedFieldOffsets[i];
    SetInternalReference(
        entry, WasmTrustedInstanceData::kTaggedFieldNames[i],
        TaggedField<Object>::load(cage_base, trusted_data, offset), offset);
  }
  for (size_t i = 0; i < WasmTrustedInstanceData::kProtectedFieldNames.size();
       i++) {
    const uint16_t offset = WasmTrustedInstanceData::kProtectedFieldOffsets[i];
    SetInternalReference(
        entry, WasmTrustedInstanceData::kProtectedFieldNames[i],
        trusted_data->RawProtectedPointerField(offset).load(heap_->isolate()),
        offset);
  }
}

#define ASSERT_FIRST_FIELD(Class, Field) \
  static_assert(Class::Super::kHeaderSize == Class::k##Field##Offset)
#define ASSERT_CONSECUTIVE_FIELDS(Class, Field, NextField) \
  static_assert(Class::k##Field##OffsetEnd + 1 == Class::k##NextField##Offset)
#define ASSERT_LAST_FIELD(Class, Field) \
  static_assert(Class::k##Field##OffsetEnd + 1 == Class::kHeaderSize)

void V8HeapExplorer::ExtractWasmInstanceObjectReferences(
    Tagged<WasmInstanceObject> instance_object, HeapEntry* entry) {
  // The static assertions verify that we do not miss any fields here when we
  // update the class definition.
  ASSERT_FIRST_FIELD(WasmInstanceObject, TrustedData);
```
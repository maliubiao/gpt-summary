Response: The user wants a summary of the C++ code functionality in `v8/src/profiler/heap-snapshot-generator.cc`. This is part 2 of a 3-part request.

Based on the code snippet, the main functionality seems to revolve around extracting references between different objects in the V8 heap during a heap snapshot generation. It iterates through various V8 object types and identifies their internal connections (references) to other objects.

Key areas of functionality visible in this part:

1. **Context References:**  Extracting references from `Context` objects, including lexical scope information and native context details.
2. **Map References:**  Handling references related to object maps, transitions, descriptors, and prototypes.
3. **SharedFunctionInfo References:** Extracting references from shared function information, including the associated code and script.
4. **Script References:**  Handling references within `Script` objects, like source, name, and context data.
5. **AccessorInfo/Pair References:**  Extracting references from accessor information and pairs (getters/setters).
6. **Weak Reference Handling:**  Processing `JSWeakRef` and `WeakCell` objects.
7. **Code Object References:** Extracting references within `Code` objects, such as instruction streams and deoptimization data.
8. **InstructionStream References.**
9. **Cell/FeedbackCell/PropertyCell References:** Handling references from various cell types.
10. **PrototypeInfo References.**
11. **AllocationSite References.**
12. **Boilerplate Description References.**
13. **JSArrayBuffer References:**  Handling the backing store of ArrayBuffers.
14. **JSPromise References.**
15. **JSGeneratorObject References.**
16. **FixedArray References:**  Iterating through elements of fixed arrays.
17. **Number References:** Treating numbers (Smis and HeapNumbers) as nodes in the graph.
18. **BytecodeArray References.**
19. **ScopeInfo References.**
20. **FeedbackVector References.**
21. **DescriptorArray References.**
22. **EnumCache References.**
23. **TransitionArray References.**
24. **WeakArray References.**
25. **Property References:**  Extracting references from object properties (fast and slow properties).
26. **Element References:**  Iterating through elements of JS objects.
27. **Internal References:** Handling internal fields of JS objects.
28. **Wasm specific references (if WASM is enabled).**

The code uses helper functions like `SetInternalReference`, `SetWeakReference`, `SetContextReference`, `SetPropertyReference`, and `SetElementReference` to establish these connections in the heap snapshot.

Regarding the relationship with JavaScript, this code is crucial for tools that analyze JavaScript heap usage and memory leaks. By understanding how JavaScript objects are interconnected in memory, developers can debug memory-related issues more effectively.

Let's create a simple JavaScript example to illustrate a connection described in the C++ code.
这是 `v8/src/profiler/heap-snapshot-generator.cc` 源代码文件的第二部分。根据这部分代码，其主要功能是 **提取 V8 堆中各种对象之间的引用关系，以便构建堆快照**。

具体来说，这部分代码定义了 `V8HeapExplorer` 类的成员函数，用于识别和记录不同类型 V8 堆对象的引用关系。 这些引用关系包括：

* **上下文 (Context) 引用:**  从 `Context` 对象中提取对作用域信息 (scope info)、前一个上下文 (previous context)、扩展 (extension) 以及原生上下文 (native context) 相关槽位的引用。
* **Map 引用:** 从 `Map` 对象中提取对转换 (transition)、描述符数组 (descriptor array)、原型 (prototype)、构造函数或后向指针 (constructor or back pointer) 等的引用。
* **SharedFunctionInfo 引用:** 从 `SharedFunctionInfo` 对象中提取对代码 (Code)、作用域信息 (scope info)、脚本 (Script) 和函数数据的引用。
* **Script 引用:** 从 `Script` 对象中提取对源代码 (source)、名称 (name)、上下文数据 (context data)、行尾信息 (line ends) 等的引用。
* **AccessorInfo 和 AccessorPair 引用:** 从访问器信息和访问器对中提取对 getter 和 setter 函数的引用。
* **弱引用:** 处理 `JSWeakRef` 和 `WeakCell` 对象，记录其指向的目标对象的弱引用。
* **代码对象 (Code) 引用:** 从 `Code` 对象中提取对指令流 (instruction stream)、反优化数据 (deoptimization data)、字节码偏移表 (bytecode offset table) 等的引用。
* **指令流 (InstructionStream) 引用:**  提取指令流对象关联的代码对象。
* **Cell、FeedbackCell 和 PropertyCell 引用:** 提取这些单元格对象存储的值以及相关的依赖代码。
* **PrototypeInfo、AllocationSite 和各种描述符对象 (BoilerplateDescription) 的引用。**
* **JSArrayBuffer 引用:**  记录 `JSArrayBuffer` 对象对其底层存储 (backing_store) 的引用。
* **JSPromise 和 JSGeneratorObject 引用:** 提取 Promise 和 Generator 对象内部状态相关的引用。
* **FixedArray 引用:** 遍历 `FixedArray` 的元素，记录对每个元素的引用。
* **数字 (Number) 引用:**  将数字 (Smi 或 HeapNumber) 的值作为一个字符串节点添加到堆快照中。
* **BytecodeArray 引用:**  提取字节码数组的常量池和处理表引用。
* **ScopeInfo 和 FeedbackVector 引用。**
* **DescriptorArray 和 EnumCache 引用。**
* **TransitionArray 引用。**
* **弱数组 (WeakArray) 引用。**
* **属性 (Property) 引用:**  提取 JS 对象的属性引用，包括快速属性和慢速属性。
* **元素 (Element) 引用:** 提取 JS 对象的元素引用。
* **内部 (Internal) 引用:** 提取 JS 对象的内部字段引用。
* **WebAssembly 相关对象 (如果启用) 的引用，例如 WasmStruct、WasmArray 和 WasmInstanceObject。**

这些函数通过调用诸如 `SetInternalReference`、`SetWeakReference`、`SetContextReference` 等辅助函数来记录这些引用关系。 这些辅助函数会将引用添加到正在生成的堆快照的相应条目中。

**与 JavaScript 的关系：**

这段 C++ 代码直接负责 V8 引擎如何理解和描述 JavaScript 对象的内存结构和相互关系。  JavaScript 对象在底层是由 V8 的堆分配和管理的。 当我们进行堆快照分析时，例如使用 Chrome 开发者工具的 Memory 面板，或者使用 `v8:Isolate.getHeapSnapshot()` API，V8 引擎会使用类似这段代码的逻辑来遍历堆，并记录对象之间的连接。

**JavaScript 示例:**

假设有以下 JavaScript 代码：

```javascript
function Person(name) {
  this.name = name;
}

let person1 = new Person("Alice");
let person2 = { friend: person1 };
```

当 V8 生成堆快照时，`V8HeapExplorer::ExtractJSObjectReferences` 或类似的处理 JSObject 的函数会被调用，并且：

* 对于 `person1` 对象，可能会调用 `V8HeapExplorer::ExtractPropertyReferences`，检测到 `name` 属性，并记录一个从 `person1` 到字符串 "Alice" 的引用。
* 对于 `person2` 对象，同样会调用 `V8HeapExplorer::ExtractPropertyReferences`，检测到 `friend` 属性，并调用 `SetInternalReference` 或类似的函数，记录一个从 `person2` 到 `person1` 对象的引用。

更具体地，当处理 `person2` 对象时，`ExtractPropertyReferences` 可能会遍历其属性，并对 `friend` 属性调用 `SetDataOrAccessorPropertyReference`。 因为 `friend` 属性存储的是一个对象 (`person1`)，所以最终会调用 `SetPropertyReference`，将 `person1` 添加为 `person2` 的一个引用。

在 `v8/src/profiler/heap-snapshot-generator.cc` 的代码中，你可能会看到类似以下的调用（简化示例）：

```c++
// 在处理 person2 对象时
void V8HeapExplorer::ExtractJSObjectReferences(HeapEntry* entry, Tagged<JSObject> js_obj) {
  // ...
  if (/* 检查到 friend 属性 */) {
    Tagged<Name> friend_name = /* 表示 "friend" 字符串的 Name 对象 */;
    Tagged<Object> friend_value = /* 指向 person1 对象的指针 */;
    SetPropertyReference(entry, friend_name, friend_value, nullptr, /* 偏移量 */);
  }
  // ...
}
```

这个 `SetPropertyReference` 函数会将 `person1` 对象添加为 `person2` 对象的引用，并在堆快照中记录下来。 这就是 C++ 代码中提取引用关系并在 JavaScript 中体现的方式。

总结来说，这部分 C++ 代码是 V8 引擎生成堆快照的核心组成部分，它负责理解 JavaScript 对象的内存布局，并提取对象之间的引用关系，为开发者进行内存分析提供了基础数据。

Prompt: 
```
这是目录为v8/src/profiler/heap-snapshot-generator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
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
  SetInternalReference(entry, "trusted_data",
                       instance_object->trusted_data(heap_->isolate()),
                       WasmInstanceObject::kTrustedDataOffset);
  ASSERT_CONSECUTIVE_FIELDS(WasmInstanceObject, TrustedData, ModuleObject);
  SetInternalReference(entry, "module_object", instance_object->module_object(),
                       WasmInstanceObject::kModuleObjectOffset);
  ASSERT_CONSECUTIVE_FIELDS(WasmInstanceObject, ModuleObject, ExportsObject);
  SetInternalReference(entry, "exports", instance_object->exports_object(),
                       WasmInstanceObject::kExportsObjectOffset);
  ASSERT_LAST_FIELD(WasmInstanceObject, ExportsObject);
}

void V8HeapExplorer::ExtractWasmModuleObjectReferences(
    Tagged<WasmModuleObject> module_object, HeapEntry* entry) {
  // The static assertions verify that we do not miss any fields here when we
  // update the class definition.
  ASSERT_FIRST_FIELD(WasmModuleObject, ManagedNativeModule);
  SetInternalReference(entry, "managed_native_module",
                       module_object->managed_native_module(),
                       WasmModuleObject::kManagedNativeModuleOffset);
  ASSERT_CONSECUTIVE_FIELDS(WasmModuleObject, ManagedNativeModule, Script);
  SetInternalReference(entry, "script", module_object->script(),
                       WasmModuleObject::kScriptOffset);
  ASSERT_LAST_FIELD(WasmModuleObject, Script);
}

#undef ASSERT_FIRST_FIELD
#undef ASSERT_CONSECUTIVE_FIELDS
#undef ASSERT_LAST_FIELD

#endif  // V8_ENABLE_WEBASSEMBLY

Tagged<JSFunction> V8HeapExplorer::GetConstructor(Isolate* isolate,
                                                  Tagged<JSReceiver> receiver) {
  DisallowGarbageCollection no_gc;
  HandleScope scope(isolate);
  MaybeHandle<JSFunction> maybe_constructor =
      JSReceiver::GetConstructor(isolate, handle(receiver, isolate));

  if (maybe_constructor.is_null()) return JSFunction();

  return *maybe_constructor.ToHandleChecked();
}

Tagged<String> V8HeapExplorer::GetConstructorName(Isolate* isolate,
                                                  Tagged<JSObject> object) {
  DisallowGarbageCollection no_gc;
  HandleScope scope(isolate);
  return *JSReceiver::GetConstructorName(isolate, handle(object, isolate));
}

HeapEntry* V8HeapExplorer::GetEntry(Tagged<Object> obj) {
  if (IsHeapObject(obj)) {
    return generator_->FindOrAddEntry(reinterpret_cast<void*>(obj.ptr()), this);
  }

  DCHECK(IsSmi(obj));
  if (!snapshot_->capture_numeric_value()) {
    return nullptr;
  }
  return generator_->FindOrAddEntry(Cast<Smi>(obj), this);
}

class RootsReferencesExtractor : public RootVisitor {
 public:
  explicit RootsReferencesExtractor(V8HeapExplorer* explorer)
      : explorer_(explorer), visiting_weak_roots_(false) {}

  void SetVisitingWeakRoots() { visiting_weak_roots_ = true; }

  void VisitRootPointer(Root root, const char* description,
                        FullObjectSlot p) override {
    Tagged<Object> object = *p;
#ifdef V8_ENABLE_DIRECT_HANDLE
    if (object.ptr() == kTaggedNullAddress) return;
#endif
    if (root == Root::kBuiltins) {
      explorer_->TagBuiltinCodeObject(Cast<Code>(object), description);
    }
    explorer_->SetGcSubrootReference(root, description, visiting_weak_roots_,
                                     object);
  }

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    for (FullObjectSlot p = start; p < end; ++p) {
      DCHECK(!MapWord::IsPacked(p.Relaxed_Load().ptr()));
      VisitRootPointer(root, description, p);
    }
  }

  void VisitRootPointers(Root root, const char* description,
                         OffHeapObjectSlot start,
                         OffHeapObjectSlot end) override {
    DCHECK_EQ(root, Root::kStringTable);
    PtrComprCageBase cage_base(explorer_->heap_->isolate());
    for (OffHeapObjectSlot p = start; p < end; ++p) {
      explorer_->SetGcSubrootReference(root, description, visiting_weak_roots_,
                                       p.load(cage_base));
    }
  }

  // Keep this synced with
  // MarkCompactCollector::RootMarkingVisitor::VisitRunningCode.
  void VisitRunningCode(FullObjectSlot code_slot,
                        FullObjectSlot istream_or_smi_zero_slot) final {
    Tagged<Object> istream_or_smi_zero = *istream_or_smi_zero_slot;
    if (istream_or_smi_zero != Smi::zero()) {
      Tagged<Code> code = Cast<Code>(*code_slot);
      code->IterateDeoptimizationLiterals(this);
      VisitRootPointer(Root::kStackRoots, nullptr, istream_or_smi_zero_slot);
    }
    VisitRootPointer(Root::kStackRoots, nullptr, code_slot);
  }

 private:
  V8HeapExplorer* explorer_;
  bool visiting_weak_roots_;
};

bool V8HeapExplorer::IterateAndExtractReferences(
    HeapSnapshotGenerator* generator) {
  generator_ = generator;

  // Create references to the synthetic roots.
  SetRootGcRootsReference();
  for (int root = 0; root < static_cast<int>(Root::kNumberOfRoots); root++) {
    SetGcRootsReference(static_cast<Root>(root));
  }

  // Make sure builtin code objects get their builtin tags
  // first. Otherwise a particular JSFunction object could set
  // its custom name to a generic builtin.
  RootsReferencesExtractor extractor(this);
  ReadOnlyRoots(heap_).Iterate(&extractor);
  heap_->IterateRoots(
      &extractor,
      base::EnumSet<SkipRoot>{SkipRoot::kWeak, SkipRoot::kTracedHandles});
  // TODO(v8:11800): The heap snapshot generator incorrectly considers the weak
  // string tables as strong retainers. Move IterateWeakRoots after
  // SetVisitingWeakRoots.
  heap_->IterateWeakRoots(&extractor, {});
  extractor.SetVisitingWeakRoots();
  heap_->IterateWeakGlobalHandles(&extractor);

  bool interrupted = false;

  CombinedHeapObjectIterator iterator(heap_);
  PtrComprCageBase cage_base(heap_->isolate());
  // Heap iteration need not be finished but progress reporting may depend on
  // it being finished.
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next(), progress_->ProgressStep()) {
    if (interrupted) continue;

    max_pointers_ = obj->Size(cage_base) / kTaggedSize;
    if (max_pointers_ > visited_fields_.size()) {
      // Reallocate to right size.
      visited_fields_.resize(max_pointers_, false);
    }

#ifdef V8_ENABLE_HEAP_SNAPSHOT_VERIFY
    std::unique_ptr<HeapEntryVerifier> verifier;
    // MarkingVisitorBase doesn't expect that we will ever visit read-only
    // objects, and fails DCHECKs if we attempt to. Read-only objects can
    // never retain read-write objects, so there is no risk in skipping
    // verification for them.
    if (v8_flags.heap_snapshot_verify &&
        !MemoryChunk::FromHeapObject(obj)->InReadOnlySpace()) {
      verifier = std::make_unique<HeapEntryVerifier>(generator, obj);
    }
#endif

    HeapEntry* entry = GetEntry(obj);
    ExtractReferences(entry, obj);
    SetInternalReference(entry, "map", obj->map(cage_base),
                         HeapObject::kMapOffset);
    // Extract unvisited fields as hidden references and restore tags
    // of visited fields.
    IndexedReferencesExtractor refs_extractor(this, obj, entry);
    VisitObject(heap_->isolate(), obj, &refs_extractor);

#if DEBUG
    // Ensure visited_fields_ doesn't leak to the next object.
    for (size_t i = 0; i < max_pointers_; ++i) {
      DCHECK(!visited_fields_[i]);
    }
#endif  // DEBUG

    // Extract location for specific object types
    ExtractLocation(entry, obj);

    if (!progress_->ProgressReport(false)) interrupted = true;
  }

  generator_ = nullptr;
  return interrupted ? false : progress_->ProgressReport(true);
}

bool V8HeapExplorer::IsEssentialObject(Tagged<Object> object) {
  if (!IsHeapObject(object)) return false;
  // Avoid comparing objects in other pointer compression cages to objects
  // inside the main cage as the comparison may only look at the lower 32 bits.
  if (HeapLayout::InCodeSpace(Cast<HeapObject>(object)) ||
      HeapLayout::InTrustedSpace(Cast<HeapObject>(object))) {
    return true;
  }
  Isolate* isolate = heap_->isolate();
  ReadOnlyRoots roots(isolate);
  return !IsOddball(object, isolate) && object != roots.the_hole_value() &&
         object != roots.empty_byte_array() &&
         object != roots.empty_fixed_array() &&
         object != roots.empty_weak_fixed_array() &&
         object != roots.empty_descriptor_array() &&
         object != roots.fixed_array_map() && object != roots.cell_map() &&
         object != roots.global_property_cell_map() &&
         object != roots.shared_function_info_map() &&
         object != roots.free_space_map() &&
         object != roots.one_pointer_filler_map() &&
         object != roots.two_pointer_filler_map();
}

bool V8HeapExplorer::IsEssentialHiddenReference(Tagged<Object> parent,
                                                int field_offset) {
  if (IsAllocationSite(parent) &&
      field_offset == AllocationSite::kWeakNextOffset)
    return false;
  if (IsContext(parent) &&
      field_offset == Context::OffsetOfElementAt(Context::NEXT_CONTEXT_LINK))
    return false;
  if (IsJSFinalizationRegistry(parent) &&
      field_offset == JSFinalizationRegistry::kNextDirtyOffset)
    return false;
  return true;
}

void V8HeapExplorer::SetContextReference(HeapEntry* parent_entry,
                                         Tagged<String> reference_name,
                                         Tagged<Object> child_obj,
                                         int field_offset) {
  HeapEntry* child_entry = GetEntry(child_obj);
  if (child_entry == nullptr) return;
  parent_entry->SetNamedReference(HeapGraphEdge::kContextVariable,
                                  names_->GetName(reference_name), child_entry,
                                  generator_);
  MarkVisitedField(field_offset);
}

void V8HeapExplorer::MarkVisitedField(int offset) {
  if (offset < 0) return;
  int index = offset / kTaggedSize;
  DCHECK_LT(index, max_pointers_);
  DCHECK(!visited_fields_[index]);
  visited_fields_[index] = true;
}

void V8HeapExplorer::SetNativeBindReference(HeapEntry* parent_entry,
                                            const char* reference_name,
                                            Tagged<Object> child_obj) {
  HeapEntry* child_entry = GetEntry(child_obj);
  if (child_entry == nullptr) return;
  parent_entry->SetNamedReference(HeapGraphEdge::kShortcut, reference_name,
                                  child_entry, generator_);
}

void V8HeapExplorer::SetElementReference(HeapEntry* parent_entry, int index,
                                         Tagged<Object> child_obj) {
  HeapEntry* child_entry = GetEntry(child_obj);
  if (child_entry == nullptr) return;
  parent_entry->SetIndexedReference(HeapGraphEdge::kElement, index, child_entry,
                                    generator_);
}

void V8HeapExplorer::SetInternalReference(HeapEntry* parent_entry,
                                          const char* reference_name,
                                          Tagged<Object> child_obj,
                                          int field_offset) {
  if (!IsEssentialObject(child_obj)) {
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  parent_entry->SetNamedReference(HeapGraphEdge::kInternal, reference_name,
                                  child_entry, generator_);
  MarkVisitedField(field_offset);
}

void V8HeapExplorer::SetInternalReference(HeapEntry* parent_entry, int index,
                                          Tagged<Object> child_obj,
                                          int field_offset) {
  if (!IsEssentialObject(child_obj)) {
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  parent_entry->SetNamedReference(HeapGraphEdge::kInternal,
                                  names_->GetName(index), child_entry,
                                  generator_);
  MarkVisitedField(field_offset);
}

void V8HeapExplorer::SetHiddenReference(Tagged<HeapObject> parent_obj,
                                        HeapEntry* parent_entry, int index,
                                        Tagged<Object> child_obj,
                                        int field_offset) {
  DCHECK_EQ(parent_entry, GetEntry(parent_obj));
  DCHECK(!MapWord::IsPacked(child_obj.ptr()));
  if (!IsEssentialObject(child_obj)) {
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  if (IsEssentialHiddenReference(parent_obj, field_offset)) {
    parent_entry->SetIndexedReference(HeapGraphEdge::kHidden, index,
                                      child_entry, generator_);
  }
}

void V8HeapExplorer::SetWeakReference(
    HeapEntry* parent_entry, const char* reference_name,
    Tagged<Object> child_obj, int field_offset,
    HeapEntry::ReferenceVerification verification) {
  if (!IsEssentialObject(child_obj)) {
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  parent_entry->SetNamedReference(HeapGraphEdge::kWeak, reference_name,
                                  child_entry, generator_, verification);
  MarkVisitedField(field_offset);
}

void V8HeapExplorer::SetWeakReference(HeapEntry* parent_entry, int index,
                                      Tagged<Object> child_obj,
                                      std::optional<int> field_offset) {
  if (!IsEssentialObject(child_obj)) {
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  parent_entry->SetNamedReference(HeapGraphEdge::kWeak,
                                  names_->GetFormatted("%d", index),
                                  child_entry, generator_);
  if (field_offset.has_value()) {
    MarkVisitedField(*field_offset);
  }
}

void V8HeapExplorer::SetDataOrAccessorPropertyReference(
    PropertyKind kind, HeapEntry* parent_entry, Tagged<Name> reference_name,
    Tagged<Object> child_obj, const char* name_format_string,
    int field_offset) {
  if (kind == PropertyKind::kAccessor) {
    ExtractAccessorPairProperty(parent_entry, reference_name, child_obj,
                                field_offset);
  } else {
    SetPropertyReference(parent_entry, reference_name, child_obj,
                         name_format_string, field_offset);
  }
}

void V8HeapExplorer::SetPropertyReference(HeapEntry* parent_entry,
                                          Tagged<Name> reference_name,
                                          Tagged<Object> child_obj,
                                          const char* name_format_string,
                                          int field_offset) {
  HeapEntry* child_entry = GetEntry(child_obj);
  if (child_entry == nullptr) return;
  HeapGraphEdge::Type type =
      IsSymbol(reference_name) || Cast<String>(reference_name)->length() > 0
          ? HeapGraphEdge::kProperty
          : HeapGraphEdge::kInternal;
  const char* name = name_format_string != nullptr && IsString(reference_name)
                         ? names_->GetFormatted(
                               name_format_string,
                               Cast<String>(reference_name)->ToCString().get())
                         : names_->GetName(reference_name);

  parent_entry->SetNamedReference(type, name, child_entry, generator_);
  MarkVisitedField(field_offset);
}

void V8HeapExplorer::SetRootGcRootsReference() {
  snapshot_->root()->SetIndexedAutoIndexReference(
      HeapGraphEdge::kElement, snapshot_->gc_roots(), generator_);
}

void V8HeapExplorer::SetUserGlobalReference(Tagged<Object> child_obj) {
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  snapshot_->root()->SetNamedAutoIndexReference(
      HeapGraphEdge::kShortcut, nullptr, child_entry, names_, generator_);
}

void V8HeapExplorer::SetGcRootsReference(Root root) {
  snapshot_->gc_roots()->SetIndexedAutoIndexReference(
      HeapGraphEdge::kElement, snapshot_->gc_subroot(root), generator_);
}

void V8HeapExplorer::SetGcSubrootReference(Root root, const char* description,
                                           bool is_weak,
                                           Tagged<Object> child_obj) {
  if (IsSmi(child_obj)) {
    // TODO(arenevier): if we handle smis here, the snapshot gets 2 to 3 times
    // slower on large heaps. According to perf, The bulk of the extra works
    // happens in TemplateHashMapImpl::Probe method, when tyring to get
    // names->GetFormatted("%d / %s", index, description)
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  if (child_entry == nullptr) return;
  auto child_heap_obj = Cast<HeapObject>(child_obj);
  const char* name = GetStrongGcSubrootName(child_heap_obj);
  HeapGraphEdge::Type edge_type =
      is_weak ? HeapGraphEdge::kWeak : HeapGraphEdge::kInternal;
  if (name != nullptr) {
    snapshot_->gc_subroot(root)->SetNamedReference(edge_type, name, child_entry,
                                                   generator_);
  } else {
    snapshot_->gc_subroot(root)->SetNamedAutoIndexReference(
        edge_type, description, child_entry, names_, generator_);
  }

  // For full heap snapshots we do not emit user roots but rather rely on
  // regular GC roots to retain objects.
  if (snapshot_->expose_internals()) return;

  // Add a shortcut to JS global object reference at snapshot root.
  // That allows the user to easily find global objects. They are
  // also used as starting points in distance calculations.
  if (is_weak || !IsNativeContext(child_heap_obj)) return;

  Tagged<JSGlobalObject> global =
      Cast<Context>(child_heap_obj)->global_object();
  if (!IsJSGlobalObject(global)) return;

  if (!user_roots_.insert(global).second) return;

  SetUserGlobalReference(global);
}

const char* V8HeapExplorer::GetStrongGcSubrootName(Tagged<HeapObject> object) {
  if (strong_gc_subroot_names_.empty()) {
    Isolate* isolate = Isolate::FromHeap(heap_);
    for (RootIndex root_index = RootIndex::kFirstStrongOrReadOnlyRoot;
         root_index <= RootIndex::kLastStrongOrReadOnlyRoot; ++root_index) {
      const char* name = RootsTable::name(root_index);
      Tagged<Object> root = isolate->root(root_index);
      CHECK(!IsSmi(root));
      strong_gc_subroot_names_.emplace(Cast<HeapObject>(root), name);
    }
    CHECK(!strong_gc_subroot_names_.empty());
  }
  auto it = strong_gc_subroot_names_.find(object);
  return it != strong_gc_subroot_names_.end() ? it->second : nullptr;
}

void V8HeapExplorer::TagObject(Tagged<Object> obj, const char* tag,
                               std::optional<HeapEntry::Type> type,
                               bool overwrite_existing_name) {
  if (IsEssentialObject(obj)) {
    HeapEntry* entry = GetEntry(obj);
    if (overwrite_existing_name || entry->name()[0] == '\0') {
      entry->set_name(tag);
    }
    if (type.has_value()) {
      entry->set_type(*type);
    }
  }
}

void V8HeapExplorer::RecursivelyTagConstantPool(Tagged<Object> obj,
                                                const char* tag,
                                                HeapEntry::Type type,
                                                int recursion_limit) {
  --recursion_limit;
  if (IsFixedArrayExact(obj, isolate())) {
    Tagged<FixedArray> arr = Cast<FixedArray>(obj);
    TagObject(arr, tag, type);
    if (recursion_limit <= 0) return;
    for (int i = 0; i < arr->length(); ++i) {
      RecursivelyTagConstantPool(arr->get(i), tag, type, recursion_limit);
    }
  } else if (IsTrustedFixedArray(obj, isolate())) {
    Tagged<TrustedFixedArray> arr = Cast<TrustedFixedArray>(obj);
    TagObject(arr, tag, type, /*overwrite_existing_name=*/true);
    if (recursion_limit <= 0) return;
    for (int i = 0; i < arr->length(); ++i) {
      RecursivelyTagConstantPool(arr->get(i), tag, type, recursion_limit);
    }
  } else if (IsNameDictionary(obj, isolate()) ||
             IsNumberDictionary(obj, isolate())) {
    TagObject(obj, tag, type);
  }
}

class GlobalObjectsEnumerator : public RootVisitor {
 public:
  GlobalObjectsEnumerator(Isolate* isolate,
                          std::function<void(Handle<JSGlobalObject>)> handler)
      : isolate_(isolate), handler_(handler) {}

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    VisitRootPointersImpl(root, description, start, end);
  }

  void VisitRootPointers(Root root, const char* description,
                         OffHeapObjectSlot start,
                         OffHeapObjectSlot end) override {
    VisitRootPointersImpl(root, description, start, end);
  }

 private:
  template <typename TSlot>
  void VisitRootPointersImpl(Root root, const char* description, TSlot start,
                             TSlot end) {
    for (TSlot p = start; p < end; ++p) {
      DCHECK(!MapWord::IsPacked(p.Relaxed_Load(isolate_).ptr()));
      Tagged<Object> o = p.load(isolate_);
      if (!IsNativeContext(o, isolate_)) continue;
      Tagged<JSObject> proxy = Cast<Context>(o)->global_proxy();
      if (!IsJSGlobalProxy(proxy, isolate_)) continue;
      Tagged<Object> global = proxy->map(isolate_)->prototype(isolate_);
      if (!IsJSGlobalObject(global, isolate_)) continue;
      handler_(handle(Cast<JSGlobalObject>(global), isolate_));
    }
  }

  Isolate* isolate_;
  std::function<void(Handle<JSGlobalObject>)> handler_;
};

V8HeapExplorer::TemporaryGlobalObjectTags
V8HeapExplorer::CollectTemporaryGlobalObjectsTags() {
  if (!global_object_name_resolver_) return {};

  Isolate* isolate = heap_->isolate();
  TemporaryGlobalObjectTags global_object_tags;
  HandleScope scope(isolate);
  GlobalObjectsEnumerator enumerator(
      isolate, [this, isolate,
                &global_object_tags](Handle<JSGlobalObject> global_object) {
        if (const char* tag = global_object_name_resolver_->GetName(
                Utils::ToLocal(Cast<JSObject>(global_object)))) {
          global_object_tags.emplace_back(
              Global<v8::Object>(reinterpret_cast<v8::Isolate*>(isolate),
                                 Utils::ToLocal(Cast<JSObject>(global_object))),
              tag);
          global_object_tags.back().first.SetWeak();
        }
      });
  isolate->global_handles()->IterateAllRoots(&enumerator);
  isolate->traced_handles()->Iterate(&enumerator);
  return global_object_tags;
}

void V8HeapExplorer::MakeGlobalObjectTagMap(
    TemporaryGlobalObjectTags&& global_object_tags) {
  HandleScope scope(heap_->isolate());
  for (const auto& pair : global_object_tags) {
    if (!pair.first.IsEmpty()) {
      // Temporary local.
      auto local = Utils::OpenPersistent(pair.first);
      global_object_tag_map_.emplace(Cast<JSGlobalObject>(*local), pair.second);
    }
  }
}

class EmbedderGraphImpl : public EmbedderGraph {
 public:
  struct Edge {
    Node* from;
    Node* to;
    const char* name;
  };

  class V8NodeImpl : public Node {
   public:
    explicit V8NodeImpl(Tagged<Object> object) : object_(object) {}
    Tagged<Object> GetObject() { return object_; }

    // Node overrides.
    bool IsEmbedderNode() override { return false; }
    const char* Name() override {
      // The name should be retrieved via GetObject().
      UNREACHABLE();
    }
    size_t SizeInBytes() override {
      // The size should be retrieved via GetObject().
      UNREACHABLE();
    }

   private:
    Tagged<Object> object_;
  };

  Node* V8Node(const v8::Local<v8::Value>& value) final {
    v8::Local<v8::Data> data = value;
    return V8Node(data);
  }

  Node* V8Node(const v8::Local<v8::Data>& data) final {
    Handle<Object> object = v8::Utils::OpenHandle(*data);
    DCHECK(!object.is_null());
    return AddNode(std::unique_ptr<Node>(new V8NodeImpl(*object)));
  }

  Node* AddNode(std::unique_ptr<Node> node) final {
    Node* result = node.get();
    nodes_.push_back(std::move(node));
    return result;
  }

  void AddEdge(Node* from, Node* to, const char* name) final {
    edges_.push_back({from, to, name});
  }

  const std::vector<std::unique_ptr<Node>>& nodes() { return nodes_; }
  const std::vector<Edge>& edges() { return edges_; }

 private:
  std::vector<std::unique_ptr<Node>> nodes_;
  std::vector<Edge> edges_;
};

class EmbedderGraphEntriesAllocator : public HeapEntriesAllocator {
 public:
  explicit EmbedderGraphEntriesAllocator(HeapSnapshot* snapshot)
      : snapshot_(snapshot),
        names_(snapshot_->profiler()->names()),
        heap_object_map_(snapshot_->profiler()->heap_object_map()) {}
  HeapEntry* AllocateEntry(HeapThing ptr) override;
  HeapEntry* AllocateEntry(Tagged<Smi> smi) override;

 private:
  HeapSnapshot* snapshot_;
  StringsStorage* names_;
  HeapObjectsMap* heap_object_map_;
};

namespace {

const char* EmbedderGraphNodeName(StringsStorage* names,
                                  EmbedderGraphImpl::Node* node) {
  const char* prefix = node->NamePrefix();
  return prefix ? names->GetFormatted("%s %s", prefix, node->Name())
                : names->GetCopy(node->Name());
}

HeapEntry::Type EmbedderGraphNodeType(EmbedderGraphImpl::Node* node) {
  return node->IsRootNode() ? HeapEntry::kSynthetic : HeapEntry::kNative;
}

// Merges the names of an embedder node and its wrapper node.
// If the wrapper node name contains a tag suffix (part after '/') then the
// result is the embedder node name concatenated with the tag suffix.
// Otherwise, the result is the embedder node name.
const char* MergeNames(StringsStorage* names, const char* embedder_name,
                       const char* wrapper_name) {
  const char* suffix = strchr(wrapper_name, '/');
  return suffix ? names->GetFormatted("%s %s", embedder_name, suffix)
                : embedder_name;
}

}  // anonymous namespace

HeapEntry* EmbedderGraphEntriesAllocator::AllocateEntry(HeapThing ptr) {
  EmbedderGraphImpl::Node* node =
      reinterpret_cast<EmbedderGraphImpl::Node*>(ptr);
  DCHECK(node->IsEmbedderNode());
  size_t size = node->SizeInBytes();
  Address lookup_address = reinterpret_cast<Address>(node->GetNativeObject());
  HeapObjectsMap::MarkEntryAccessed accessed =
      HeapObjectsMap::MarkEntryAccessed::kYes;
  HeapObjectsMap::IsNativeObject is_native_object =
      HeapObjectsMap::IsNativeObject::kNo;
  if (!lookup_address) {
    // If there is not a native object associated with this embedder object,
    // then request the address of the embedder object.
    lookup_address = reinterpret_cast<Address>(node->GetAddress());
    is_native_object = HeapObjectsMap::IsNativeObject::kYes;
  }
  if (!lookup_address) {
    // If the Node implementation did not provide either a native address or an
    // embedder address, then use the address of the Node itself for the lookup.
    // In this case, we'll set the "accessed" flag on the newly created
    // HeapEntry to false, to indicate that this entry should not persist for
    // future snapshots.
    lookup_address = reinterpret_cast<Address>(node);
    accessed = HeapObjectsMap::MarkEntryAccessed::kNo;
  }
  SnapshotObjectId id = heap_object_map_->FindOrAddEntry(
      lookup_address, 0, accessed, is_native_object);
  auto* heap_entry = snapshot_->AddEntry(EmbedderGraphNodeType(node),
                                         EmbedderGraphNodeName(names_, node),
                                         id, static_cast<int>(size), 0);
  heap_entry->set_detachedness(node->GetDetachedness());
  return heap_entry;
}

HeapEntry* EmbedderGraphEntriesAllocator::AllocateEntry(Tagged<Smi> smi) {
  DCHECK(false);
  return nullptr;
}

NativeObjectsExplorer::NativeObjectsExplorer(
    HeapSnapshot* snapshot, SnapshottingProgressReportingInterface* progress)
    : isolate_(
          Isolate::FromHeap(snapshot->profiler()->heap_object_map()->heap())),
      snapshot_(snapshot),
      names_(snapshot_->profiler()->names()),
      heap_object_map_(snapshot_->profiler()->heap_object_map()),
      embedder_graph_entries_allocator_(
          new EmbedderGraphEntriesAllocator(snapshot)) {}

void NativeObjectsExplorer::MergeNodeIntoEntry(
    HeapEntry* entry, EmbedderGraph::Node* original_node,
    EmbedderGraph::Node* wrapper_node) {
  // The wrapper node may be an embedder node (for testing purposes) or a V8
  // node (production code).
  if (!wrapper_node->IsEmbedderNode()) {
    // For V8 nodes only we can add a lookup.
    EmbedderGraphImpl::V8NodeImpl* v8_node =
        static_cast<EmbedderGraphImpl::V8NodeImpl*>(wrapper_node);
    Tagged<Object> object = v8_node->GetObject();
    DCHECK(!IsSmi(object));
    if (original_node->GetNativeObject()) {
      Tagged<HeapObject> heap_object = Cast<HeapObject>(object);
      heap_object_map_->AddMergedNativeEntry(original_node->GetNativeObject(),
                                             heap_object.address());
      DCHECK_EQ(entry->id(), heap_object_map_->FindMergedNativeEntry(
                                 original_node->GetNativeObject()));
    }
  }
  entry->set_detachedness(original_node->GetDetachedness());
  entry->set_name(MergeNames(
      names_, EmbedderGraphNodeName(names_, original_node), entry->name()));
  entry->set_type(EmbedderGraphNodeType(original_node));
  DCHECK_GE(entry->self_size() + original_node->SizeInBytes(),
            entry->self_size());
  entry->add_self_size(original_node->SizeInBytes());
}

HeapEntry* NativeObjectsExplorer::EntryForEmbedderGraphNode(
    EmbedderGraphImpl::Node* node) {
  // Return the entry for the wrapper node if present.
  if (node->WrapperNode()) {
    node = node->WrapperNode();
  }
  // Node is EmbedderNode.
  if (node->IsEmbedderNode()) {
    return generator_->FindOrAddEntry(node,
                                      embedder_graph_entries_allocator_.get());
  }
  // Node is V8NodeImpl.
  Tagged<Object> object =
      static_cast<EmbedderGraphImpl::V8NodeImpl*>(node)->GetObject();
  if (IsSmi(object)) return nullptr;
  auto* entry = generator_->FindEntry(
      reinterpret_cast<void*>(Cast<Object>(object).ptr()));
  return entry;
}

bool NativeObjectsExplorer::IterateAndExtractReferences(
    HeapSnapshotGenerator* generator) {
  generator_ = generator;

  if (v8_flags.heap_profiler_use_embedder_graph &&
      snapshot_->profiler()->HasBuildEmbedderGraphCallback()) {
    v8::HandleScope scope(reinterpret_cast<v8::Isolate*>(isolate_));
    DisallowGarbageCollection no_gc;
    EmbedderGraphImpl graph;
    snapshot_->profiler()->BuildEmbedderGraph(isolate_, &graph);
    for (const auto& node : graph.nodes()) {
      // Only add embedder nodes as V8 nodes have been added already by the
      // V8HeapExplorer.
      if (!node->IsEmbedderNode()) continue;

      if (auto* entry = EntryForEmbedderGraphNode(node.get())) {
        if (node->IsRootNode()) {
          snapshot_->root()->SetIndexedAutoIndexReference(
              HeapGraphEdge::kElement, entry, generator_,
              HeapEntry::kOffHeapPointer);
        }
        if (node->WrapperNode()) {
          MergeNodeIntoEntry(entry, node.get(), node->WrapperNode());
        }
      }
    }
    // Fill edges of the graph.
    for (const auto& edge : graph.edges()) {
      // |from| and |to| can be nullptr if the corresponding node is a V8 node
      // pointing to a Smi.
      HeapEntry* from = EntryForEmbedderGraphNode(edge.from);
      if (!from) continue;
      HeapEntry* to = EntryForEmbedderGraphNode(edge.to);
      if (!to) continue;
      if (edge.name == nullptr) {
        from->SetIndexedAutoIndexReference(HeapGraphEdge::kElement, to,
                                           generator_,
                                           HeapEntry::kOffHeapPointer);
      } else {
        from->SetNamedReference(HeapGraphEdge::kInternal,
                                names_->GetCopy(edge.name), to, generator_,
                                HeapEntry::kOffHeapPointer);
      }
    }
  }
  generator_ = nullptr;
  return true;
}

HeapSnapshotGenerator::HeapSnapshotGenerator(
    HeapSnapshot* snapshot, v8::ActivityControl* control,
    v8::HeapProfiler::ObjectNameResolver* resolver, Heap* heap,
    cppgc::EmbedderStackState stack_state)
    : snapshot_(snapshot),
      control_(control),
      v8_heap_explorer_(snapshot_, this, resolver),
      dom_explorer_(snapshot_, this),
      heap_(heap),
      stack_state_(stack_state) {}

namespace {
class V8_NODISCARD NullContextForSnapshotScope {
 public:
  explicit NullContextForSnapshotScope(Isolate* isolate)
      : isolate_(isolate), prev_(isolate->context()) {
    isolate_->set_context(Context());
  }
  ~NullContextForSnapshotScope() { isolate_->set_context(prev_); }

 private:
  Isolate* isolate_;
  Tagged<Context> prev_;
};
}  // namespace

bool HeapSnapshotGenerator::GenerateSnaps
"""


```
Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/torque/implementation-visitor.cc`.

Here's a breakdown of the code and its functionalities:

1. **Looking up and calling functions/builtins/macros**: The code handles resolving and calling various callable entities like builtins, macros, and function pointers.
2. **Managing location references**: It deals with obtaining and manipulating references to memory locations (variables, heap objects, etc.).
3. **Generating code for fetching and assigning values**:  The code includes logic for generating instructions to load values from and store values to the locations obtained through location references.
4. **Type conversions**: Implicit type conversions are performed during function calls and assignments.
5. **Handling intrinsics**:  Specific built-in functions (intrinsics) with special behaviors are handled.
6. **Inline macros**:  The code supports inlining macros for efficiency.
7. **Error reporting**:  The code includes mechanisms to report errors during compilation.

Now, I'll structure the answer according to the user's specific requests.
这是 `v8/src/torque/implementation-visitor.cc` 源代码的第 4 部分，它主要负责以下功能：

**核心功能归纳：处理函数调用和数据访问**

这部分代码的核心职责在于**处理函数调用** (包括普通函数、Builtin、宏、运行时函数等) 以及**访问和修改数据** (通过 LocationReference)。 它根据不同的表达式类型，生成相应的底层代码指令。

**详细功能列举：**

1. **获取和创建特化 (Specialization):**  `GetOrCreateSpecialization` 函数用于查找或创建泛型函数或 Builtin 的特定类型版本。这在 Torque 中实现泛型很有用。
2. **获取 Builtin 的代码:**  如果特化是一个 Builtin，`GetBuiltinCode` 函数用于获取其对应的代码对象。
3. **处理命名值 (Named Values):**  `GetLocationReference(NameExpression* expr)` 函数用于查找变量、常量或外部常量的值，并返回一个 `LocationReference`，表示该值的存储位置。
    * 它会检查是否是命名空间常量 (`NamespaceConstant`) 或外部常量 (`ExternConstant`)。
    * 对于命名空间常量，如果它是 `constexpr`，则直接返回其常量值；否则，生成指令将其加载到栈上。
    * 对于外部常量，直接返回其值。
4. **处理解引用表达式:** `GetLocationReference(DereferenceExpression* expr)` 函数用于处理解引用操作符 `*`，它期望操作数是一个引用类型 (`ReferenceGeneric`)。
5. **生成从位置获取值的代码:** `GenerateFetchFromLocation` 函数根据 `LocationReference` 的类型，生成从该位置加载值的代码。
    * **临时变量 (`Temporary`) 或局部变量 (`VariableAccess`):** 直接生成复制指令。
    * **堆引用 (`HeapReference`):** 根据引用类型生成不同的加载指令，例如 `LoadFloat64OrHole` 用于加载浮点数或空洞值，或者处理结构体字段的加载。
    * **位域访问 (`BitFieldAccess`):** 先加载包含位域的结构体，然后提取位域的值。
    * **调用访问 (`CallAccess`):** 调用与该位置关联的 getter 函数。
6. **生成向位置赋值的代码:** `GenerateAssignToLocation` 函数根据 `LocationReference` 的类型，生成向该位置存储值的代码。
    * **调用访问 (`CallAccess`):** 调用与该位置关联的 setter 函数。
    * **局部变量 (`VariableAccess`):** 生成存储指令，并将赋值操作记录下来，用于 lint 检查。
    * **堆引用 (`HeapReference`):** 根据引用类型生成不同的存储指令，例如 `StoreFloat64OrHole` 用于存储浮点数或空洞值，或者处理结构体字段的赋值。
    * **位域访问 (`BitFieldAccess`):** 先加载包含位域的结构体，更新位域的值，然后将更新后的结构体存储回去。
    * **临时变量:** 报错，因为不能给常量绑定或临时变量赋值。
7. **生成函数指针调用:** `GeneratePointerCall` 函数用于生成通过函数指针进行调用的代码。它会进行类型检查，确保参数类型匹配。
8. **添加调用参数:** `AddCallParameter` 函数用于处理函数调用的参数，包括隐式参数和显式参数，并进行必要的类型转换。
9. **生成函数调用:** `GenerateCall` 函数是这部分代码的核心，它负责生成各种类型的函数调用代码。
    * **Builtin 调用:**  生成 `CallBuiltinInstruction`。
    * **Macro 调用:**
        * 如果是 `constexpr` 宏，则在编译时计算结果。
        * 如果可以内联 (`inline_macro`)，则直接将宏的代码插入到调用处。
        * 否则，生成 `CallCsaMacroInstruction` 或 `CallCsaMacroAndBranchInstruction`。
    * **Runtime 函数调用:** 生成 `CallRuntimeInstruction`。
    * **Intrinsic 调用:**  针对不同的 Intrinsic 生成特定的代码，例如 `%SizeOf`, `%ClassHasMapConstant`, `%MinInstanceType`, `%MaxInstanceType`, `%RawConstexprCast`, `%IndexedFieldLength`, `%MakeLazy`, `%FieldSlice` 等。
10. **处理尾调用 (Tail Call):**  `is_tailcall` 参数用于指示是否是尾调用，尾调用是一种特殊的函数调用，可以优化堆栈空间。

**如果 `v8/src/torque/implementation-visitor.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**  （这个前提是不成立的，`.cc` 后缀表示这是一个 C++ 源代码文件）

**与 Javascript 的关系 (通过 Builtin 的例子):**

Torque 用于定义 V8 引擎内部的 Builtin 函数，这些 Builtin 函数最终会被 JavaScript 调用。

**JavaScript 示例:**

```javascript
// 假设存在一个 Torque 定义的 Builtin 函数，名为 'ArrayPush'，用于向数组末尾添加元素

// JavaScript 代码：
const myArray = [1, 2, 3];
myArray.push(4); // 这里会调用 V8 内部的 ArrayPush Builtin

// 在 v8/src/torque/implementation-visitor.cc 中，GenerateCall 函数会处理对 ArrayPush 的调用，
// 并生成相应的底层代码，例如调用 Array 的相关 C++ 方法来完成添加元素的操作。
```

**代码逻辑推理示例：**

**假设输入:**  一个 `NameExpression` 节点，表示一个名为 `myVariable` 的局部变量，该变量的类型是 `Int32`。

**输出:**  `GetLocationReference` 函数会返回一个 `LocationReference` 对象，该对象表示 `myVariable` 在栈上的位置。 该 `LocationReference` 的 `IsVariableAccess()` 方法会返回 `true`，并且可以通过 `variable()` 方法获取到表示该变量的 `VisitResult` 对象，其类型为 `Int32`。

**用户常见的编程错误 (与 Torque 相关):**

1. **类型不匹配:** 在调用 Builtin 或宏时，传递的参数类型与定义不一致。 Torque 编译器会进行类型检查，并在编译时报错。

   ```typescript
   // Torque 定义的 Builtin 接受一个 Int32 参数
   builtin MyBuiltin(x: Int32): void {
       // ...
   }

   // JavaScript 代码
   // @ts-ignore
   MyBuiltin("hello"); // 常见的错误：传递了字符串而不是数字
   ```

2. **尝试修改常量:** 尝试给一个声明为 `const` 的变量或常量赋值。

   ```typescript
   const myConst: Int32 = 10;
   // 编译时错误：Cannot assign to const value of type Int32
   myConst = 20;
   ```

3. **在需要特定类型时使用了错误的类型:** 例如，`GenerateFetchFromLocation` 期望解引用操作符的操作数是引用类型，如果传入的是值类型则会报错。

**第 4 部分功能归纳：**

这部分 `ImplementationVisitor` 的代码主要负责**将 Torque 语法中的函数调用和数据访问操作转换为底层的代码指令**。它处理了各种类型的调用 (Builtin, Macro, Runtime Function, Function Pointer) 和数据访问方式 (变量, 堆对象, 位域)，并进行了必要的类型检查和转换。 这是 Torque 编译器将高级语言转换为低级代码的关键步骤。

Prompt: 
```
这是目录为v8/src/torque/implementation-visitor.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/implementation-visitor.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共7部分，请归纳一下它的功能

"""
       GetOrCreateSpecialization(SpecializationKey<GenericCallable>{
            generic, TypeVisitor::ComputeTypeVector(expr->generic_arguments)});
    if (Builtin* builtin = Builtin::DynamicCast(specialization)) {
      DCHECK(!builtin->IsExternal());
      return LocationReference::Temporary(GetBuiltinCode(builtin),
                                          "builtin " + expr->name->value);
    } else {
      ReportError("cannot create function pointer for non-builtin ",
                  generic->name());
    }
  }
  Value* value = Declarations::LookupValue(name);
  CHECK(value->Position().source.IsValid());
  if (auto stream = CurrentFileStreams::Get()) {
    stream->required_builtin_includes.insert(value->Position().source);
  }
  if (GlobalContext::collect_language_server_data()) {
    LanguageServerData::AddDefinition(expr->name->pos, value->name()->pos);
  }
  if (auto* constant = NamespaceConstant::DynamicCast(value)) {
    if (GlobalContext::collect_kythe_data()) {
      KytheData::AddConstantUse(expr->name->pos, constant);
    }
    if (constant->type()->IsConstexpr()) {
      return LocationReference::Temporary(
          VisitResult(constant->type(), constant->external_name() + "(state_)"),
          "namespace constant " + expr->name->value);
    }
    assembler().Emit(NamespaceConstantInstruction{constant});
    StackRange stack_range =
        assembler().TopRange(LoweredSlotCount(constant->type()));
    return LocationReference::Temporary(
        VisitResult(constant->type(), stack_range),
        "namespace constant " + expr->name->value);
  }
  ExternConstant* constant = ExternConstant::cast(value);
  if (GlobalContext::collect_kythe_data()) {
    KytheData::AddConstantUse(expr->name->pos, constant);
  }
  return LocationReference::Temporary(constant->value(),
                                      "extern value " + expr->name->value);
}

LocationReference ImplementationVisitor::GetLocationReference(
    DereferenceExpression* expr) {
  VisitResult ref = Visit(expr->reference);
  if (!TypeOracle::MatchReferenceGeneric(ref.type())) {
    Error("Operator * expects a reference type but found a value of type ",
          *ref.type())
        .Throw();
  }
  return LocationReference::HeapReference(ref);
}

VisitResult ImplementationVisitor::GenerateFetchFromLocation(
    const LocationReference& reference) {
  if (reference.IsTemporary()) {
    return GenerateCopy(reference.temporary());
  } else if (reference.IsVariableAccess()) {
    return GenerateCopy(reference.variable());
  } else if (reference.IsHeapReference()) {
    const Type* referenced_type = *reference.ReferencedType();
    if (referenced_type == TypeOracle::GetFloat64OrHoleType()) {
      return GenerateCall(QualifiedName({TORQUE_INTERNAL_NAMESPACE_STRING},
                                        "LoadFloat64OrHole"),
                          Arguments{{reference.heap_reference()}, {}});
    } else if (auto struct_type = referenced_type->StructSupertype()) {
      StackRange result_range = assembler().TopRange(0);
      for (const Field& field : (*struct_type)->fields()) {
        StackScope scope(this);
        const std::string& fieldname = field.name_and_type.name;
        VisitResult field_value = scope.Yield(GenerateFetchFromLocation(
            GenerateFieldAccess(reference, fieldname)));
        result_range.Extend(field_value.stack_range());
      }
      return VisitResult(referenced_type, result_range);
    } else {
      GenerateCopy(reference.heap_reference());
      FieldSynchronization sync = reference.heap_reference_synchronization();
      assembler().Emit(LoadReferenceInstruction{referenced_type, sync});
      DCHECK_EQ(1, LoweredSlotCount(referenced_type));
      return VisitResult(referenced_type, assembler().TopRange(1));
    }
  } else if (reference.IsBitFieldAccess()) {
    // First fetch the bitfield struct, then get the bits out of it.
    VisitResult bit_field_struct =
        GenerateFetchFromLocation(reference.bit_field_struct_location());
    assembler().Emit(LoadBitFieldInstruction{bit_field_struct.type(),
                                             reference.bit_field()});
    return VisitResult(*reference.ReferencedType(), assembler().TopRange(1));
  } else {
    if (reference.IsHeapSlice()) {
      ReportError(
          "fetching a value directly from an indexed field isn't allowed");
    }
    DCHECK(reference.IsCallAccess());
    return GenerateCall(reference.eval_function(),
                        Arguments{reference.call_arguments(), {}});
  }
}

void ImplementationVisitor::GenerateAssignToLocation(
    const LocationReference& reference, const VisitResult& assignment_value) {
  if (reference.IsCallAccess()) {
    Arguments arguments{reference.call_arguments(), {}};
    arguments.parameters.push_back(assignment_value);
    GenerateCall(reference.assign_function(), arguments);
  } else if (reference.IsVariableAccess()) {
    VisitResult variable = reference.variable();
    VisitResult converted_value =
        GenerateImplicitConvert(variable.type(), assignment_value);
    assembler().Poke(variable.stack_range(), converted_value.stack_range(),
                     variable.type());

    // Local variables are detected by the existence of a binding. Assignment
    // to local variables is recorded to support lint errors.
    if (reference.binding()) {
      (*reference.binding())->SetWritten();
    }
  } else if (reference.IsHeapSlice()) {
    ReportError("assigning a value directly to an indexed field isn't allowed");
  } else if (reference.IsHeapReference()) {
    const Type* referenced_type = *reference.ReferencedType();
    if (reference.IsConst()) {
      Error("cannot assign to const value of type ", *referenced_type).Throw();
    }
    if (referenced_type == TypeOracle::GetFloat64OrHoleType()) {
      GenerateCall(
          QualifiedName({TORQUE_INTERNAL_NAMESPACE_STRING},
                        "StoreFloat64OrHole"),
          Arguments{{reference.heap_reference(), assignment_value}, {}});
    } else if (auto struct_type = referenced_type->StructSupertype()) {
      if (!assignment_value.type()->IsSubtypeOf(referenced_type)) {
        ReportError("Cannot assign to ", *referenced_type,
                    " with value of type ", *assignment_value.type());
      }
      for (const Field& field : (*struct_type)->fields()) {
        const std::string& fieldname = field.name_and_type.name;
        // Allow assignment of structs even if they contain const fields.
        // Const on struct fields just disallows direct writes to them.
        bool ignore_stuct_field_constness = true;
        GenerateAssignToLocation(
            GenerateFieldAccess(reference, fieldname,
                                ignore_stuct_field_constness),
            ProjectStructField(assignment_value, fieldname));
      }
    } else {
      GenerateCopy(reference.heap_reference());
      VisitResult converted_assignment_value =
          GenerateImplicitConvert(referenced_type, assignment_value);
      if (referenced_type == TypeOracle::GetFloat64Type()) {
        VisitResult silenced_float_value = GenerateCall(
            "Float64SilenceNaN", Arguments{{assignment_value}, {}});
        assembler().Poke(converted_assignment_value.stack_range(),
                         silenced_float_value.stack_range(), referenced_type);
      }
      assembler().Emit(StoreReferenceInstruction{referenced_type});
    }
  } else if (reference.IsBitFieldAccess()) {
    // First fetch the bitfield struct, then set the updated bits, then store
    // it back to where we found it.
    VisitResult bit_field_struct =
        GenerateFetchFromLocation(reference.bit_field_struct_location());
    VisitResult converted_value =
        GenerateImplicitConvert(*reference.ReferencedType(), assignment_value);
    VisitResult updated_bit_field_struct =
        GenerateSetBitField(bit_field_struct.type(), reference.bit_field(),
                            bit_field_struct, converted_value);
    GenerateAssignToLocation(reference.bit_field_struct_location(),
                             updated_bit_field_struct);
  } else {
    DCHECK(reference.IsTemporary());
    ReportError("cannot assign to const-bound or temporary ",
                reference.temporary_description());
  }
}

VisitResult ImplementationVisitor::GeneratePointerCall(
    Expression* callee, const Arguments& arguments, bool is_tailcall) {
  StackScope scope(this);
  TypeVector parameter_types(arguments.parameters.ComputeTypeVector());
  VisitResult callee_result = Visit(callee);
  if (!callee_result.type()->IsBuiltinPointerType()) {
    std::stringstream stream;
    stream << "Expected a function pointer type but found "
           << *callee_result.type();
    ReportError(stream.str());
  }
  const BuiltinPointerType* type =
      BuiltinPointerType::cast(callee_result.type());

  if (type->parameter_types().size() != parameter_types.size()) {
    std::stringstream stream;
    stream << "parameter count mismatch calling function pointer with Type: "
           << *type << " - expected "
           << std::to_string(type->parameter_types().size()) << ", found "
           << std::to_string(parameter_types.size());
    ReportError(stream.str());
  }

  ParameterTypes types{type->parameter_types(), false};
  Signature sig;
  sig.parameter_types = types;
  if (!IsCompatibleSignature(sig, parameter_types, 0)) {
    std::stringstream stream;
    stream << "parameters do not match function pointer signature. Expected: ("
           << type->parameter_types() << ") but got: (" << parameter_types
           << ")";
    ReportError(stream.str());
  }

  callee_result = GenerateCopy(callee_result);
  StackRange arg_range = assembler().TopRange(0);
  for (size_t current = 0; current < arguments.parameters.size(); ++current) {
    const Type* to_type = type->parameter_types()[current];
    arg_range.Extend(
        GenerateImplicitConvert(to_type, arguments.parameters[current])
            .stack_range());
  }

  assembler().Emit(
      CallBuiltinPointerInstruction{is_tailcall, type, arg_range.Size()});

  if (is_tailcall) {
    return VisitResult::NeverResult();
  }
  DCHECK_EQ(1, LoweredSlotCount(type->return_type()));
  return scope.Yield(VisitResult(type->return_type(), assembler().TopRange(1)));
}

void ImplementationVisitor::AddCallParameter(
    Callable* callable, VisitResult parameter, const Type* parameter_type,
    std::vector<VisitResult>* converted_arguments, StackRange* argument_range,
    std::vector<std::string>* constexpr_arguments, bool inline_macro) {
  VisitResult converted;
  if ((converted_arguments->size() < callable->signature().implicit_count) &&
      parameter.type()->IsTopType()) {
    converted = GenerateCopy(parameter);
  } else {
    converted = GenerateImplicitConvert(parameter_type, parameter);
  }
  converted_arguments->push_back(converted);
  if (!inline_macro) {
    if (converted.IsOnStack()) {
      argument_range->Extend(converted.stack_range());
    } else {
      constexpr_arguments->push_back(converted.constexpr_value());
    }
  }
}

namespace {
std::pair<std::string, std::string> GetClassInstanceTypeRange(
    const ClassType* class_type) {
  std::pair<std::string, std::string> result;
  if (class_type->InstanceTypeRange()) {
    auto instance_type_range = *class_type->InstanceTypeRange();
    std::string instance_type_string_first =
        "static_cast<InstanceType>(" +
        std::to_string(instance_type_range.first) + ")";
    std::string instance_type_string_second =
        "static_cast<InstanceType>(" +
        std::to_string(instance_type_range.second) + ")";
    result =
        std::make_pair(instance_type_string_first, instance_type_string_second);
  } else {
    ReportError(
        "%Min/MaxInstanceType must take a class type that is either a string "
        "or has a generated instance type range");
  }
  return result;
}
}  // namespace

VisitResult ImplementationVisitor::GenerateCall(
    Callable* callable, std::optional<LocationReference> this_reference,
    Arguments arguments, const TypeVector& specialization_types,
    bool is_tailcall) {
  CHECK(callable->Position().source.IsValid());
  if (auto stream = CurrentFileStreams::Get()) {
    stream->required_builtin_includes.insert(callable->Position().source);
  }

  const Type* return_type = callable->signature().return_type;

  if (is_tailcall) {
    if (Builtin* builtin = Builtin::DynamicCast(CurrentCallable::Get())) {
      const Type* outer_return_type = builtin->signature().return_type;
      if (!return_type->IsSubtypeOf(outer_return_type)) {
        Error("Cannot tailcall, type of result is ", *return_type,
              " but should be a subtype of ", *outer_return_type, ".");
      }
    } else {
      Error("Tail calls are only allowed from builtins");
    }
  }

  bool inline_macro = callable->ShouldBeInlined(output_type_);
  std::vector<VisitResult> implicit_arguments;
  for (size_t i = 0; i < callable->signature().implicit_count; ++i) {
    std::string implicit_name = callable->signature().parameter_names[i]->value;
    std::optional<Binding<LocalValue>*> val =
        TryLookupLocalValue(implicit_name);
    if (val) {
      implicit_arguments.push_back(
          GenerateFetchFromLocation((*val)->GetLocationReference(*val)));
    } else {
      VisitResult unititialized = VisitResult::TopTypeResult(
          "implicit parameter '" + implicit_name +
              "' is not defined when invoking " + callable->ReadableName() +
              " at " + PositionAsString(CurrentSourcePosition::Get()),
          callable->signature().parameter_types.types[i]);
      implicit_arguments.push_back(unititialized);
    }
    const Type* type = implicit_arguments.back().type();
    if (const TopType* top_type = TopType::DynamicCast(type)) {
      if (!callable->IsMacro() || callable->IsExternal()) {
        ReportError(
            "unititialized implicit parameters can only be passed to "
            "Torque-defined macros: the ",
            top_type->reason());
      }
      inline_macro = true;
    }
  }

  std::vector<VisitResult> converted_arguments;
  StackRange argument_range = assembler().TopRange(0);
  std::vector<std::string> constexpr_arguments;

  size_t current = 0;
  for (; current < callable->signature().implicit_count; ++current) {
    AddCallParameter(callable, implicit_arguments[current],
                     callable->signature().parameter_types.types[current],
                     &converted_arguments, &argument_range,
                     &constexpr_arguments, inline_macro);
  }

  if (this_reference) {
    DCHECK(callable->IsMethod());
    Method* method = Method::cast(callable);
    // By now, the this reference should either be a variable, a temporary or
    // a Slice. In either case the fetch of the VisitResult should succeed.
    VisitResult this_value = this_reference->GetVisitResult();
    if (inline_macro) {
      if (!this_value.type()->IsSubtypeOf(method->aggregate_type())) {
        ReportError("this parameter must be a subtype of ",
                    *method->aggregate_type(), " but it is of type ",
                    *this_value.type());
      }
    } else {
      AddCallParameter(callable, this_value, method->aggregate_type(),
                       &converted_arguments, &argument_range,
                       &constexpr_arguments, inline_macro);
    }
    ++current;
  }

  for (const auto& arg : arguments.parameters) {
    const Type* to_type = (current >= callable->signature().types().size())
                              ? TypeOracle::GetObjectType()
                              : callable->signature().types()[current++];
    AddCallParameter(callable, arg, to_type, &converted_arguments,
                     &argument_range, &constexpr_arguments, inline_macro);
  }

  size_t label_count = callable->signature().labels.size();
  if (label_count != arguments.labels.size()) {
    std::stringstream s;
    s << "unexpected number of otherwise labels for "
      << callable->ReadableName() << " (expected "
      << std::to_string(label_count) << " found "
      << std::to_string(arguments.labels.size()) << ")";
    ReportError(s.str());
  }

  if (callable->IsTransitioning()) {
    if (!CurrentCallable::Get()->IsTransitioning()) {
      std::stringstream s;
      s << *CurrentCallable::Get()
        << " isn't marked transitioning but calls the transitioning "
        << *callable;
      ReportError(s.str());
    }
  }

  if (auto* builtin = Builtin::DynamicCast(callable)) {
    std::optional<Block*> catch_block = GetCatchBlock();
    assembler().Emit(CallBuiltinInstruction{
        is_tailcall, builtin, argument_range.Size(), catch_block});
    GenerateCatchBlock(catch_block);
    if (is_tailcall) {
      return VisitResult::NeverResult();
    } else if (return_type->IsNever()) {
      assembler().Emit(AbortInstruction{AbortInstruction::Kind::kUnreachable});
      return VisitResult::NeverResult();
    } else {
      size_t slot_count = LoweredSlotCount(return_type);
      if (builtin->IsStub()) {
        if (slot_count < 1 || slot_count > 2) {
          ReportError(
              "Builtin with stub linkage is expected to return one or two "
              "values but returns ",
              slot_count);
        }
      } else {
        if (slot_count != 1) {
          ReportError(
              "Builtin with JS linkage is expected to return one value but "
              "returns ",
              slot_count);
        }
      }
      return VisitResult(return_type, assembler().TopRange(slot_count));
    }
  } else if (auto* macro = Macro::DynamicCast(callable)) {
    if (is_tailcall) {
      ReportError("can't tail call a macro");
    }

    macro->SetUsed();

    // If we're currently generating a C++ macro and it's calling another macro,
    // then we need to make sure that we also generate C++ code for the called
    // macro within the same -inl.inc file.
    if ((output_type_ == OutputType::kCC ||
         output_type_ == OutputType::kCCDebug) &&
        !inline_macro) {
      if (auto* torque_macro = TorqueMacro::DynamicCast(macro)) {
        auto* streams = CurrentFileStreams::Get();
        SourceId file = streams ? streams->file : SourceId::Invalid();
        GlobalContext::EnsureInCCOutputList(torque_macro, file);
      }
    }

    // TODO(torque-builder): Consider a function builder here.
    if (return_type->IsConstexpr()) {
      DCHECK_EQ(0, arguments.labels.size());
      std::stringstream result;
      result << "(";
      bool first = true;
      switch (output_type_) {
        case OutputType::kCSA: {
          if (auto* extern_macro = ExternMacro::DynamicCast(macro)) {
            result << extern_macro->external_assembler_name() << "(state_)."
                   << extern_macro->ExternalName() << "(";
          } else {
            result << macro->ExternalName() << "(state_";
            first = false;
          }
          break;
        }
        case OutputType::kCC: {
          auto* extern_macro = ExternMacro::DynamicCast(macro);
          CHECK_NOT_NULL(extern_macro);
          result << extern_macro->CCName() << "(";
          break;
        }
        case OutputType::kCCDebug: {
          auto* extern_macro = ExternMacro::DynamicCast(macro);
          CHECK_NOT_NULL(extern_macro);
          result << extern_macro->CCDebugName() << "(accessor";
          first = false;
          break;
        }
      }
      for (const VisitResult& arg : converted_arguments) {
        DCHECK(!arg.IsOnStack());
        if (!first) {
          result << ", ";
        }
        first = false;
        result << arg.constexpr_value();
      }
      result << "))";
      return VisitResult(return_type, result.str());
    } else if (inline_macro) {
      std::vector<Block*> label_blocks;
      label_blocks.reserve(arguments.labels.size());
      for (Binding<LocalLabel>* label : arguments.labels) {
        label_blocks.push_back(label->block);
      }
      return InlineMacro(macro, this_reference, converted_arguments,
                         std::move(label_blocks));
    } else if (arguments.labels.empty() &&
               return_type != TypeOracle::GetNeverType()) {
      std::optional<Block*> catch_block = GetCatchBlock();
      assembler().Emit(CallCsaMacroInstruction{
          macro, std::move(constexpr_arguments), catch_block});
      GenerateCatchBlock(catch_block);
      size_t return_slot_count = LoweredSlotCount(return_type);
      return VisitResult(return_type, assembler().TopRange(return_slot_count));
    } else {
      std::optional<Block*> return_continuation;
      if (return_type != TypeOracle::GetNeverType()) {
        return_continuation = assembler().NewBlock();
      }

      std::vector<Block*> label_blocks;

      for (size_t i = 0; i < label_count; ++i) {
        label_blocks.push_back(assembler().NewBlock());
      }
      std::optional<Block*> catch_block = GetCatchBlock();
      assembler().Emit(CallCsaMacroAndBranchInstruction{
          macro, constexpr_arguments, return_continuation, label_blocks,
          catch_block});
      GenerateCatchBlock(catch_block);

      for (size_t i = 0; i < label_count; ++i) {
        Binding<LocalLabel>* label = arguments.labels[i];
        size_t callee_label_parameters =
            callable->signature().labels[i].types.size();
        if (label->parameter_types.size() != callee_label_parameters) {
          std::stringstream s;
          s << "label " << label->name()
            << " doesn't have the right number of parameters (found "
            << std::to_string(label->parameter_types.size()) << " expected "
            << std::to_string(callee_label_parameters) << ")";
          ReportError(s.str());
        }
        assembler().Bind(label_blocks[i]);
        assembler().Goto(
            label->block,
            LowerParameterTypes(callable->signature().labels[i].types).size());

        size_t j = 0;
        for (auto t : callable->signature().labels[i].types) {
          const Type* parameter_type = label->parameter_types[j];
          if (!t->IsSubtypeOf(parameter_type)) {
            ReportError("mismatch of label parameters (label expects ",
                        *parameter_type, " but macro produces ", *t,
                        " for parameter ", i + 1, ")");
          }
          j++;
        }
      }

      if (return_continuation) {
        assembler().Bind(*return_continuation);
        size_t return_slot_count = LoweredSlotCount(return_type);
        return VisitResult(return_type,
                           assembler().TopRange(return_slot_count));
      } else {
        return VisitResult::NeverResult();
      }
    }
  } else if (auto* runtime_function = RuntimeFunction::DynamicCast(callable)) {
    std::optional<Block*> catch_block = GetCatchBlock();
    assembler().Emit(CallRuntimeInstruction{
        is_tailcall, runtime_function, argument_range.Size(), catch_block});
    GenerateCatchBlock(catch_block);
    if (is_tailcall || return_type == TypeOracle::GetNeverType()) {
      return VisitResult::NeverResult();
    } else {
      size_t slot_count = LoweredSlotCount(return_type);
      DCHECK_LE(slot_count, 1);
      // TODO(turbofan): Actually, runtime functions have to return a value, so
      // we should assert slot_count == 1 here.
      return VisitResult(return_type, assembler().TopRange(slot_count));
    }
  } else if (auto* intrinsic = Intrinsic::DynamicCast(callable)) {
    if (intrinsic->ExternalName() == "%SizeOf") {
      if (specialization_types.size() != 1) {
        ReportError("%SizeOf must take a single type parameter");
      }
      const Type* type = specialization_types[0];
      std::string size_string;
      if (std::optional<std::tuple<size_t, std::string>> size = SizeOf(type)) {
        size_string = std::get<1>(*size);
      } else {
        Error("size of ", *type, " is not known.");
      }
      return VisitResult(return_type, size_string);
    } else if (intrinsic->ExternalName() == "%ClassHasMapConstant") {
      const Type* type = specialization_types[0];
      const ClassType* class_type = ClassType::DynamicCast(type);
      if (!class_type) {
        ReportError("%ClassHasMapConstant must take a class type parameter");
      }
      // If the class isn't actually used as the parameter to a TNode,
      // then we can't rely on the class existing in C++ or being of the same
      // type (e.g. it could be a template), so don't use the template CSA
      // machinery for accessing the class' map.
      if (class_type->name() != class_type->GetGeneratedTNodeTypeName()) {
        return VisitResult(return_type, std::string("false"));
      } else {
        return VisitResult(
            return_type,
            std::string("CodeStubAssembler(state_).ClassHasMapConstant<") +
                class_type->name() + ">()");
      }
    } else if (intrinsic->ExternalName() == "%MinInstanceType") {
      if (specialization_types.size() != 1) {
        ReportError("%MinInstanceType must take a single type parameter");
      }
      const Type* type = specialization_types[0];
      const ClassType* class_type = ClassType::DynamicCast(type);
      if (!class_type) {
        ReportError("%MinInstanceType must take a class type parameter");
      }
      std::pair<std::string, std::string> instance_types =
          GetClassInstanceTypeRange(class_type);
      return VisitResult(return_type, instance_types.first);
    } else if (intrinsic->ExternalName() == "%MaxInstanceType") {
      if (specialization_types.size() != 1) {
        ReportError("%MaxInstanceType must take a single type parameter");
      }
      const Type* type = specialization_types[0];
      const ClassType* class_type = ClassType::DynamicCast(type);
      if (!class_type) {
        ReportError("%MaxInstanceType must take a class type parameter");
      }
      std::pair<std::string, std::string> instance_types =
          GetClassInstanceTypeRange(class_type);
      return VisitResult(return_type, instance_types.second);
    } else if (intrinsic->ExternalName() == "%RawConstexprCast") {
      if (intrinsic->signature().parameter_types.types.size() != 1 ||
          constexpr_arguments.size() != 1) {
        ReportError(
            "%RawConstexprCast must take a single parameter with constexpr "
            "type");
      }
      if (!return_type->IsConstexpr()) {
        std::stringstream s;
        s << *return_type
          << " return type for %RawConstexprCast is not constexpr";
        ReportError(s.str());
      }
      std::stringstream result;
      result << "static_cast<" << return_type->GetGeneratedTypeName() << ">(";
      result << constexpr_arguments[0];
      result << ")";
      return VisitResult(return_type, result.str());
    } else if (intrinsic->ExternalName() == "%IndexedFieldLength") {
      const Type* type = specialization_types[0];
      const ClassType* class_type = ClassType::DynamicCast(type);
      if (!class_type) {
        ReportError("%IndexedFieldLength must take a class type parameter");
      }
      const Field& field =
          class_type->LookupField(StringLiteralUnquote(constexpr_arguments[0]));
      return GenerateArrayLength(VisitResult(type, argument_range), field);
    } else if (intrinsic->ExternalName() == "%MakeLazy") {
      if (specialization_types[0]->IsStructType()) {
        ReportError("%MakeLazy can't use macros that return structs");
      }
      std::string getter_name = StringLiteralUnquote(constexpr_arguments[0]);

      // Normally the parser would split namespace names for us, but we
      // sidestepped it by putting the macro name in a string literal.
      QualifiedName qualified_getter_name = QualifiedName::Parse(getter_name);

      // converted_arguments contains all of the arguments to %MakeLazy. We're
      // looking for a function that takes all but the first.
      Arguments arguments_to_getter;
      arguments_to_getter.parameters.insert(
          arguments_to_getter.parameters.begin(),
          converted_arguments.begin() + 1, converted_arguments.end());

      Callable* callable_macro = LookupCallable(
          qualified_getter_name, Declarations::Lookup(qualified_getter_name),
          arguments_to_getter, {});
      Macro* getter = Macro::DynamicCast(callable_macro);
      if (!getter || getter->IsMethod()) {
        ReportError(
            "%MakeLazy expects a macro, not builtin or other type of callable");
      }
      if (!getter->signature().labels.empty()) {
        ReportError("%MakeLazy requires a macro with no labels");
      }
      if (!getter->signature().return_type->IsSubtypeOf(
              specialization_types[0])) {
        ReportError("%MakeLazy expected return type ", *specialization_types[0],
                    " but found ", *getter->signature().return_type);
      }
      if (getter->signature().implicit_count > 0) {
        ReportError("Implicit parameters are not yet supported in %MakeLazy");
      }

      getter->SetUsed();  // Prevent warnings about unused macros.

      // Now that we've looked up the getter macro, we have to convert the
      // arguments again, so that, for example, constexpr arguments can be
      // coerced to non-constexpr types and put on the stack.

      std::vector<VisitResult> converted_arguments_for_getter;
      StackRange argument_range_for_getter = assembler().TopRange(0);
      std::vector<std::string> constexpr_arguments_for_getter;

      size_t arg_count = 0;
      for (const auto& arg : arguments_to_getter.parameters) {
        DCHECK_LT(arg_count, getter->signature().types().size());
        const Type* to_type = getter->signature().types()[arg_count++];
        AddCallParameter(getter, arg, to_type, &converted_arguments_for_getter,
                         &argument_range_for_getter,
                         &constexpr_arguments_for_getter,
                         /*inline_macro=*/false);
      }

      // Now that the arguments are prepared, emit the instruction that consumes
      // them.
      assembler().Emit(MakeLazyNodeInstruction{
          getter, return_type, std::move(constexpr_arguments_for_getter)});
      return VisitResult(return_type, assembler().TopRange(1));
    } else if (intrinsic->ExternalName() == "%FieldSlice") {
      const Type* type = specialization_types[0];
      const ClassType* class_type = ClassType::DynamicCast(type);
      if (!class_type) {
        ReportError("The first type parameter to %FieldSlice must be a class");
      }
      const Field& field =
          class_type->LookupField(StringLiteralUnquote(constexpr_arguments[0]));
      const Type* expected_slice_type =
          field.const_qualified
              ? TypeOracle::GetConstSliceType(field.name_and_type.type)
              : TypeOracle::GetMutableSliceType(field.name_and_type.type);
      const Type* declared_slice_type = specialization_types[1];
      if (expected_slice_type != declared_slice_type) {
        Error(
            "The second type parameter to %FieldSlice must be the precise "
            "slice type for the named field");
      }
      LocationReference ref = GenerateFieldReference(
          VisitResult(type, argument_range), field, class_type,
          /*treat_optional_as_indexed=*/true);
      if (!ref.IsHeapSlice()) {
        ReportError("%FieldSlice expected an indexed or optional field");
      }
      return ref.heap_slice();
    } else {
      assembler().Emit(CallIntrinsicInstruction{intrinsic, specialization_types,
                                                constexpr_arguments});
      size_t return_slot_count =
          LoweredSlotCount(intrinsic->signature().return_type);
      return VisitResult(return_type, assembler().TopRange(return_slot_count));
    }
  } else {
    UNREACHABLE();
  }
}

VisitResult ImplementationVisitor::GenerateCall(
    const QualifiedName& callable_name, Arguments arguments,
    const TypeVector& specialization_types, bool is_tailcall) {
  Callable* callable =
      LookupCallable(callable_name, Declarations::Lookup(callable_name),
                     arguments, specialization_types);
  return GenerateCall(callable, std::nullopt, arguments, specialization_types,
                      is_tailcall);
}

VisitResult ImplementationVisitor::Visit(CallExpression* expr,
                                         bool is_tailcall) {
  StackScope scope(this);

  if (expr->callee->name->value == "&" && expr->arguments.size() == 1) {
    if (auto* loc_expr = LocationExpression::DynamicCast(expr->arguments[0])) {
      LocationReference ref = GetLocationReference(loc_expr);
      if (ref.IsHeapReference()) return scope.Yield(ref.heap_reference());
      if (ref.IsHeapSlice()
"""


```
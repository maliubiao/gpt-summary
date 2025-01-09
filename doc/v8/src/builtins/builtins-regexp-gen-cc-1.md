Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/builtins/builtins-regexp-gen.cc`.

Here's a breakdown of the code's features and how to address the user's requests:

1. **General Functionality:** The code defines assembly-level (using V8's CodeStubAssembler - CSA) implementations for various RegExp built-in functions in JavaScript. It includes fast paths for common scenarios to optimize performance.

2. **Torque Source:** The user asks if the file ends with `.tq`. The provided snippet is `.cc`, so it's not a Torque source file. I need to mention this explicitly.

3. **Relationship to JavaScript:**  The code directly implements JavaScript RegExp behavior. I need to provide JavaScript examples that correspond to the C++ functions.

4. **Code Logic Inference:** The code contains conditional logic and function calls. I can pick a function (like `RegExpExec`) and explain its flow with sample inputs and outputs.

5. **Common Programming Errors:** Since it's related to RegExp, common errors involve incorrect flags, misunderstanding RegExp behavior, and performance issues when using complex regexes.

6. **Summary of Functionality:** I need to synthesize the information from the code into a concise summary.

**Plan:**

* State that `builtins-regexp-gen.cc` is a C++ file containing CSA implementations for RegExp built-ins.
* Confirm that it's not a Torque file.
* Provide JavaScript examples for functions like `exec`, constructor (`new RegExp()`), `compile`, and flag getters.
* Explain the logic of `RegExpExec` with a simple example.
* Give examples of common RegExp programming errors in JavaScript.
* Summarize the file's purpose as providing optimized implementations of RegExp functionalities.
这是 `v8/src/builtins/builtins-regexp-gen.cc` 源代码的第二部分，延续了第一部分的内容，主要功能是使用 V8 的 CodeStubAssembler (CSA) 为 JavaScript 的正则表达式 (RegExp) 相关功能提供高效的底层实现。

**功能归纳:**

延续第一部分，此部分代码继续定义了多个 CSA 宏和内置函数，用于实现 JavaScript 中 `RegExp` 对象的各种操作。以下是此部分代码的主要功能归纳：

1. **`RegExpExecInternal` 内置函数:**
   -  这是执行正则表达式匹配的核心函数。
   -  它根据正则表达式的类型（例如，Atom、Fast、Experimental 或需要调用运行时）选择不同的执行路径。
   -  它负责调用底层的正则表达式引擎或运行时函数来执行匹配。
   -  处理匹配成功、失败、重试以及栈溢出的情况。

2. **`IsFastRegExpNoPrototype` 函数:**
   -  用于判断一个对象是否是一个“快速”的 `RegExp` 对象，即没有修改过原型链，并且 `lastIndex` 属性是一个正的 Smi。
   -  这是一种性能优化，允许 V8 对这些未修改的 `RegExp` 对象使用更快的执行路径。

3. **`BranchIfFastRegExp` 系列函数:**
   -  提供条件分支逻辑，用于检查一个 `RegExp` 对象是否满足“快速”条件，并根据结果跳转到不同的代码块。
   -  这些函数考虑了原型链的修改、`lastIndex` 的值以及特定的属性是否被修改。
   -  针对不同的 `RegExp` 方法（如 `search`、`match`）提供了不同的变体。

4. **`BranchIfRegExpResult` 函数:**
   -  检查一个对象是否是 `RegExp` 执行结果对象（包括普通的和带有 indices 的结果对象）。

5. **`RegExpExecAtom` 函数:**
   -  专门用于执行“Atom”类型的正则表达式匹配。Atom 正则表达式通常是简单的字面量字符串。
   -  它直接调用底层的 C++ 函数 `re_atom_exec_raw` 来执行匹配。

6. **`RegExpExecAtom` 内置函数:**
   -  这是 `RegExpExecAtom` 的一个快速路径实现。
   -  它使用 `StringIndexOf` 内置函数来进行字符串查找。
   -  如果匹配成功，它会更新 `RegExpMatchInfo` 对象。
   -  这是一个针对简单字符串匹配的优化。

7. **`FlagsGetter` 函数:**
   -  用于获取 `RegExp` 对象的标志字符串（例如 "gi", "m"）。
   -  提供了快速路径（直接读取 `JSRegExp` 对象的标志位）和慢速路径（通过 `GetProperty` 获取）。

8. **`RegExpInitialize` 函数:**
   -  实现了 `RegExp` 对象的初始化逻辑。
   -  负责规范化传入的 pattern 和 flags 参数，并调用运行时函数进行编译。

9. **`RegExpConstructor` 内置函数:**
   -  实现了 `RegExp` 构造函数的逻辑。
   -  处理 `new RegExp()` 的各种调用方式，包括当 pattern 是另一个 `RegExp` 对象时的情况。
   -  分配 `JSRegExp` 对象并调用 `RegExpInitialize` 进行初始化。

10. **`RegExpPrototypeCompile` 内置函数:**
    - 实现了 `RegExp.prototype.compile()` 方法。
    - 接收新的 pattern 和 flags，并重新初始化和编译正则表达式。

11. **`FastFlagGetter` 和 `SlowFlagGetter` 函数:**
    -  用于快速或慢速地获取 `RegExp` 对象的单个标志（例如 `global`, `ignoreCase`）。
    -  快速路径直接读取标志位，慢速路径通过属性访问获取。

12. **`FlagGetter` 函数:**
    -  根据是否是快速路径选择调用 `FastFlagGetter` 或 `SlowFlagGetter`。

13. **`AdvanceStringIndex` 函数:**
    -  用于根据正则表达式的 `unicode` 标志来递增字符串的索引。
    -  处理 Unicode 代理对的情况，确保索引正确移动。

14. **`CreateRegExpStringIterator` 函数:**
    -  用于创建 `RegExp String Iterator` 对象，这是 `String.prototype.matchAll()` 方法使用的迭代器。

15. **`RegExpPrototypeSplitBody` 函数:**
    -  实现了 `String.prototype.split()` 方法中当分隔符是正则表达式且该正则表达式是未修改的、非 sticky 的情况下的快速路径。
    -  它高效地执行正则表达式匹配，并将匹配结果分割成字符串数组。

**与 Javascript 功能的关系及示例:**

此部分代码中的功能直接对应于 JavaScript 中 `RegExp` 对象的各种方法和构造函数。

* **`RegExpExecInternal` 对应 `RegExp.prototype.exec()`:**
   ```javascript
   const regex = /ab*/g;
   const str = 'abbcdefabh';
   let array1;
   while ((array1 = regex.exec(str)) !== null) {
     console.log(`Found ${array1[0]}. Next starts at ${regex.lastIndex}.`);
     // Expected output: "Found abb". Next starts at 3.
     // Expected output: "Found ab". Next starts at 9.
   }
   ```

* **`RegExpConstructor` 对应 `new RegExp()`:**
   ```javascript
   const regex1 = new RegExp('ab*', 'g');
   const regex2 = /ab*/g; // 字面量创建方式
   ```

* **`RegExpPrototypeCompile` 对应 `RegExp.prototype.compile()` (已废弃，不推荐使用):**
   ```javascript
   const regex = /ab*/;
   regex.compile('cd*', 'g');
   console.log(regex.source); // 输出: "cd*"
   console.log(regex.flags);  // 输出: "g"
   ```

* **`FlagsGetter` 对应访问 `RegExp` 对象的 flags 属性:**
   ```javascript
   const regex = /abc/gi;
   console.log(regex.flags); // 输出: "gi"
   console.log(regex.global); // 输出: true
   console.log(regex.ignoreCase); // 输出: true
   ```

* **`RegExpPrototypeSplitBody` (split 的快速路径) 对应 `String.prototype.split()`:**
   ```javascript
   const str = 'hello world';
   const parts = str.split(/ /);
   console.log(parts); // 输出: ["hello", "world"]
   ```

* **`CreateRegExpStringIterator` 对应 `String.prototype.matchAll()`:**
   ```javascript
   const str = 'test1test2';
   const regex = /t(e)(st(\d?))/g;
   const iterator = str[Symbol.matchAll](regex);
   for (const match of iterator) {
     console.log(match);
   }
   ```

**代码逻辑推理 (以 `RegExpExecInternal` 为例):**

**假设输入:**

* `context`: 当前的 JavaScript 执行上下文。
* `regexp`: 一个 `JSRegExp` 对象，例如 `/ab*/g`。
* `string`: 要匹配的字符串，例如 `'abbcdefabh'`。
* `last_index`: 上次匹配结束的位置，例如 `0`。
* `result_offsets_vector`: 用于存储匹配结果偏移量的数组。
* `result_offsets_vector_length`:  `result_offsets_vector` 的长度。

**预期输出 (可能是多个分支):**

* **如果 `regexp` 是 Atom 类型的:**  调用 `RegExpExecAtom` 并返回匹配结果的偏移量。
* **如果当前线程有挂起的异常:**  跳转到 `if_exception` 并抛出栈溢出错误。
* **如果启用实验性的正则表达式引擎:** 跳转到 `retry_experimental`，调用实验性的引擎执行匹配，并返回结果。
* **否则 (通常情况):** 跳转到 `runtime`，调用标准的正则表达式运行时函数 `Runtime::kRegExpExec` 执行匹配，并返回结果。

**用户常见的编程错误:**

1. **忘记设置或错误设置 `lastIndex`:**  如果正则表达式带有 `g` 标志，多次调用 `exec()` 时会依赖 `lastIndex` 来从上次匹配的位置继续。忘记设置或错误设置 `lastIndex` 可能导致意外的结果或无限循环。
   ```javascript
   const regex = /ab*/g;
   const str = 'abbcdefabh';
   console.log(regex.exec(str)); // 找到 "abb"，regex.lastIndex 为 3
   console.log(regex.exec(str)); // 找到 "ab"， regex.lastIndex 为 9
   console.log(regex.exec(str)); // 找到 null，regex.lastIndex 为 0 (到达字符串末尾)
   console.log(regex.exec(str)); // 找到 "abb"，regex.lastIndex 为 3 (重新开始)

   const regexWithoutGlobal = /ab*/;
   console.log(regexWithoutGlobal.exec(str)); // 找到 "abb"
   console.log(regexWithoutGlobal.exec(str)); // 再次找到 "abb" (lastIndex 不会更新)
   ```

2. **在不应该使用全局匹配时使用了全局匹配:**  例如，在只需要找到第一个匹配项时使用了 `/.../g`，这可能导致不必要的多次匹配和性能损失。

3. **误解正则表达式的标志:**  例如，不理解 `^` 和 `$` 的作用范围，或者 `.` 是否匹配换行符，导致正则表达式无法按预期工作。

4. **在循环中使用字面量正则表达式:**  在循环中创建字面量正则表达式会导致每次循环都创建一个新的 `RegExp` 对象，效率较低。应该在循环外部创建 `RegExp` 对象。
   ```javascript
   const arr = ['a', 'b', 'c'];
   for (let i = 0; i < arr.length; i++) {
     const regex = /a/; // 每次循环都创建新的 RegExp 对象
     console.log(regex.test(arr[i]));
   }

   const regexOutsideLoop = /a/;
   for (let i = 0; i < arr.length; i++) {
     console.log(regexOutsideLoop.test(arr[i])); // 只创建一次 RegExp 对象
   }
   ```

**总结:**

`v8/src/builtins/builtins-regexp-gen.cc` 的第二部分继续提供了 V8 引擎中 JavaScript 正则表达式功能的底层实现。它包含了用于执行正则表达式匹配、获取标志、初始化 `RegExp` 对象以及实现 `split` 等方法的优化代码。这些代码使用 CSA 编写，旨在提供高性能的正则表达式操作。 该文件不是以 `.tq` 结尾，因此它不是一个 V8 Torque 源代码文件。

Prompt: 
```
这是目录为v8/src/builtins/builtins-regexp-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-regexp-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
rConstant(RegExp::kInternalRegExpRetry)));
    Goto(&runtime);
  }

  BIND(&if_exception);
  {
// A stack overflow was detected in RegExp code.
#ifdef DEBUG
    TNode<ExternalReference> exception_address =
        ExternalConstant(ExternalReference::Create(
            IsolateAddressId::kExceptionAddress, isolate()));
    TNode<Object> exception = LoadFullTagged(exception_address);
    CSA_DCHECK(this, IsTheHole(exception));
#endif  // DEBUG
    CallRuntime(Runtime::kThrowStackOverflow, context);
    Unreachable();
  }

  BIND(&retry_experimental);
  {
    // Set the implicit (untagged) arg.
    auto vector_arg = ExternalConstant(
        ExternalReference::Create(IsolateFieldId::kRegexpExecVectorArgument));
    StoreNoWriteBarrier(MachineType::PointerRepresentation(), vector_arg,
                        result_offsets_vector);
    static_assert(
        Internals::IsValidSmi(Isolate::kJSRegexpStaticOffsetsVectorSize));
    TNode<Smi> result_as_smi = CAST(CallRuntime(
        Runtime::kRegExpExperimentalOneshotExec, context, regexp, string,
        last_index, SmiFromInt32(result_offsets_vector_length)));
    var_result = UncheckedCast<UintPtrT>(SmiUntag(result_as_smi));
#ifdef DEBUG
    StoreNoWriteBarrier(MachineType::PointerRepresentation(), vector_arg,
                        IntPtrConstant(0));
#endif  // DEBUG
    Goto(&out);
  }

  BIND(&runtime);
  {
    // Set the implicit (untagged) arg.
    auto vector_arg = ExternalConstant(
        ExternalReference::Create(IsolateFieldId::kRegexpExecVectorArgument));
    StoreNoWriteBarrier(MachineType::PointerRepresentation(), vector_arg,
                        result_offsets_vector);
    static_assert(
        Internals::IsValidSmi(Isolate::kJSRegexpStaticOffsetsVectorSize));
    TNode<Smi> result_as_smi = CAST(
        CallRuntime(Runtime::kRegExpExec, context, regexp, string, last_index,
                    SmiFromInt32(result_offsets_vector_length)));
    var_result = UncheckedCast<UintPtrT>(SmiUntag(result_as_smi));
#ifdef DEBUG
    StoreNoWriteBarrier(MachineType::PointerRepresentation(), vector_arg,
                        IntPtrConstant(0));
#endif  // DEBUG
    Goto(&out);
  }

  BIND(&atom);
  {
    var_result =
        RegExpExecAtom(context, CAST(data), string, CAST(last_index),
                       result_offsets_vector, result_offsets_vector_length);
    Goto(&out);
  }

  BIND(&out);
  return var_result.value();
}

TNode<BoolT> RegExpBuiltinsAssembler::IsFastRegExpNoPrototype(
    TNode<Context> context, TNode<Object> object, TNode<Map> map) {
  Label out(this);
  TVARIABLE(BoolT, var_result);

  var_result = Int32FalseConstant();
  GotoIfForceSlowPath(&out);

  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<HeapObject> regexp_fun =
      CAST(LoadContextElement(native_context, Context::REGEXP_FUNCTION_INDEX));
  const TNode<Object> initial_map =
      LoadObjectField(regexp_fun, JSFunction::kPrototypeOrInitialMapOffset);
  const TNode<BoolT> has_initialmap = TaggedEqual(map, initial_map);

  var_result = has_initialmap;
  GotoIfNot(has_initialmap, &out);

  // The smi check is required to omit ToLength(lastIndex) calls with possible
  // user-code execution on the fast path.
  TNode<Object> last_index = FastLoadLastIndexBeforeSmiCheck(CAST(object));
  var_result = TaggedIsPositiveSmi(last_index);
  Goto(&out);

  BIND(&out);
  return var_result.value();
}

TNode<BoolT> RegExpBuiltinsAssembler::IsFastRegExpNoPrototype(
    TNode<Context> context, TNode<Object> object) {
  CSA_DCHECK(this, TaggedIsNotSmi(object));
  return IsFastRegExpNoPrototype(context, object, LoadMap(CAST(object)));
}

void RegExpBuiltinsAssembler::BranchIfFastRegExp(
    TNode<Context> context, TNode<HeapObject> object, TNode<Map> map,
    PrototypeCheckAssembler::Flags prototype_check_flags,
    std::optional<DescriptorIndexNameValue> additional_property_to_check,
    Label* if_isunmodified, Label* if_ismodified) {
  CSA_DCHECK(this, TaggedEqual(LoadMap(object), map));

  GotoIfForceSlowPath(if_ismodified);

  // This should only be needed for String.p.(split||matchAll), but we are
  // conservative here.
  GotoIf(IsRegExpSpeciesProtectorCellInvalid(), if_ismodified);

  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<JSFunction> regexp_fun =
      CAST(LoadContextElement(native_context, Context::REGEXP_FUNCTION_INDEX));
  TNode<Map> initial_map = CAST(
      LoadObjectField(regexp_fun, JSFunction::kPrototypeOrInitialMapOffset));
  TNode<BoolT> has_initialmap = TaggedEqual(map, initial_map);

  GotoIfNot(has_initialmap, if_ismodified);

  // The smi check is required to omit ToLength(lastIndex) calls with possible
  // user-code execution on the fast path.
  TNode<Object> last_index = FastLoadLastIndexBeforeSmiCheck(CAST(object));
  GotoIfNot(TaggedIsPositiveSmi(last_index), if_ismodified);

  // Verify the prototype.

  TNode<Map> initial_proto_initial_map = CAST(
      LoadContextElement(native_context, Context::REGEXP_PROTOTYPE_MAP_INDEX));

  DescriptorIndexNameValue properties_to_check[2];
  int property_count = 0;
  properties_to_check[property_count++] = DescriptorIndexNameValue{
      JSRegExp::kExecFunctionDescriptorIndex, RootIndex::kexec_string,
      Context::REGEXP_EXEC_FUNCTION_INDEX};
  if (additional_property_to_check) {
    properties_to_check[property_count++] = *additional_property_to_check;
  }

  PrototypeCheckAssembler prototype_check_assembler(
      state(), prototype_check_flags, native_context, initial_proto_initial_map,
      base::Vector<DescriptorIndexNameValue>(properties_to_check,
                                             property_count));

  TNode<HeapObject> prototype = LoadMapPrototype(map);
  prototype_check_assembler.CheckAndBranch(prototype, if_isunmodified,
                                           if_ismodified);
}
void RegExpBuiltinsAssembler::BranchIfFastRegExpForSearch(
    TNode<Context> context, TNode<HeapObject> object, Label* if_isunmodified,
    Label* if_ismodified) {
  BranchIfFastRegExp(
      context, object, LoadMap(object),
      PrototypeCheckAssembler::kCheckPrototypePropertyConstness,
      DescriptorIndexNameValue{JSRegExp::kSymbolSearchFunctionDescriptorIndex,
                               RootIndex::ksearch_symbol,
                               Context::REGEXP_SEARCH_FUNCTION_INDEX},
      if_isunmodified, if_ismodified);
}

void RegExpBuiltinsAssembler::BranchIfFastRegExpForMatch(
    TNode<Context> context, TNode<HeapObject> object, Label* if_isunmodified,
    Label* if_ismodified) {
  BranchIfFastRegExp(
      context, object, LoadMap(object),
      PrototypeCheckAssembler::kCheckPrototypePropertyConstness,
      DescriptorIndexNameValue{JSRegExp::kSymbolMatchFunctionDescriptorIndex,
                               RootIndex::kmatch_symbol,
                               Context::REGEXP_MATCH_FUNCTION_INDEX},
      if_isunmodified, if_ismodified);
}

void RegExpBuiltinsAssembler::BranchIfFastRegExp_Strict(
    TNode<Context> context, TNode<HeapObject> object, Label* if_isunmodified,
    Label* if_ismodified) {
  BranchIfFastRegExp(context, object, LoadMap(object),
                     PrototypeCheckAssembler::kCheckPrototypePropertyConstness,
                     std::nullopt, if_isunmodified, if_ismodified);
}

void RegExpBuiltinsAssembler::BranchIfFastRegExp_Permissive(
    TNode<Context> context, TNode<HeapObject> object, Label* if_isunmodified,
    Label* if_ismodified) {
  BranchIfFastRegExp(context, object, LoadMap(object),
                     PrototypeCheckAssembler::kCheckFull, std::nullopt,
                     if_isunmodified, if_ismodified);
}

void RegExpBuiltinsAssembler::BranchIfRegExpResult(const TNode<Context> context,
                                                   const TNode<Object> object,
                                                   Label* if_isunmodified,
                                                   Label* if_ismodified) {
  // Could be a Smi.
  const TNode<Map> map = LoadReceiverMap(object);

  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Object> initial_regexp_result_map =
      LoadContextElement(native_context, Context::REGEXP_RESULT_MAP_INDEX);

  Label maybe_result_with_indices(this);
  Branch(TaggedEqual(map, initial_regexp_result_map), if_isunmodified,
         &maybe_result_with_indices);
  BIND(&maybe_result_with_indices);
  {
    static_assert(
        std::is_base_of<JSRegExpResult, JSRegExpResultWithIndices>::value,
        "JSRegExpResultWithIndices is a subclass of JSRegExpResult");
    const TNode<Object> initial_regexp_result_with_indices_map =
        LoadContextElement(native_context,
                           Context::REGEXP_RESULT_WITH_INDICES_MAP_INDEX);
    Branch(TaggedEqual(map, initial_regexp_result_with_indices_map),
           if_isunmodified, if_ismodified);
  }
}

TNode<UintPtrT> RegExpBuiltinsAssembler::RegExpExecAtom(
    TNode<Context> context, TNode<AtomRegExpData> data,
    TNode<String> subject_string, TNode<Smi> last_index,
    TNode<RawPtrT> result_offsets_vector,
    TNode<Int32T> result_offsets_vector_length) {
  auto f = ExternalConstant(ExternalReference::re_atom_exec_raw());
  auto isolate_ptr = ExternalConstant(ExternalReference::isolate_address());
  auto result = UncheckedCast<IntPtrT>(CallCFunction(
      f, MachineType::IntPtr(),
      std::make_pair(MachineType::Pointer(), isolate_ptr),
      std::make_pair(MachineType::TaggedPointer(), data),
      std::make_pair(MachineType::TaggedPointer(), subject_string),
      std::make_pair(MachineType::Int32(), SmiToInt32(last_index)),
      std::make_pair(MachineType::Pointer(), result_offsets_vector),
      std::make_pair(MachineType::Int32(), result_offsets_vector_length)));
  return Unsigned(result);
}

// Fast path stub for ATOM regexps. String matching is done by StringIndexOf,
// and {match_info} is updated on success.
// The slow path is implemented in RegExp::AtomExec.
TF_BUILTIN(RegExpExecAtom, RegExpBuiltinsAssembler) {
  auto regexp = Parameter<JSRegExp>(Descriptor::kRegExp);
  auto subject_string = Parameter<String>(Descriptor::kString);
  auto last_index = Parameter<Smi>(Descriptor::kLastIndex);
  auto match_info = Parameter<RegExpMatchInfo>(Descriptor::kMatchInfo);
  auto context = Parameter<Context>(Descriptor::kContext);

  CSA_DCHECK(this, TaggedIsPositiveSmi(last_index));

  TNode<RegExpData> data = CAST(LoadTrustedPointerFromObject(
      regexp, JSRegExp::kDataOffset, kRegExpDataIndirectPointerTag));
  CSA_SBXCHECK(this, HasInstanceType(data, ATOM_REG_EXP_DATA_TYPE));

  // Callers ensure that last_index is in-bounds.
  CSA_DCHECK(this,
             UintPtrLessThanOrEqual(SmiUntag(last_index),
                                    LoadStringLengthAsWord(subject_string)));

  const TNode<String> needle_string =
      LoadObjectField<String>(data, AtomRegExpData::kPatternOffset);

  // ATOM patterns are guaranteed to not be the empty string (these are
  // intercepted and replaced in JSRegExp::Initialize.
  //
  // This is especially relevant for crbug.com/1075514: atom patterns are
  // non-empty and thus guaranteed not to match at the end of the string.
  CSA_DCHECK(this, IntPtrGreaterThan(LoadStringLengthAsWord(needle_string),
                                     IntPtrConstant(0)));

  const TNode<Smi> match_from =
      CAST(CallBuiltin(Builtin::kStringIndexOf, context, subject_string,
                       needle_string, last_index));

  Label if_failure(this), if_success(this);
  Branch(SmiEqual(match_from, SmiConstant(-1)), &if_failure, &if_success);

  BIND(&if_success);
  {
    CSA_DCHECK(this, TaggedIsPositiveSmi(match_from));
    CSA_DCHECK(this, UintPtrLessThan(SmiUntag(match_from),
                                     LoadStringLengthAsWord(subject_string)));

    const int kNumRegisters = 2;
    static_assert(kNumRegisters <= RegExpMatchInfo::kMinCapacity);

    const TNode<Smi> match_to =
        SmiAdd(match_from, LoadStringLengthAsSmi(needle_string));

    StoreObjectField(match_info,
                     offsetof(RegExpMatchInfo, number_of_capture_registers_),
                     SmiConstant(kNumRegisters));
    StoreObjectField(match_info, offsetof(RegExpMatchInfo, last_subject_),
                     subject_string);
    StoreObjectField(match_info, offsetof(RegExpMatchInfo, last_input_),
                     subject_string);
    UnsafeStoreArrayElement(match_info, 0, match_from,
                            UNSAFE_SKIP_WRITE_BARRIER);
    UnsafeStoreArrayElement(match_info, 1, match_to, UNSAFE_SKIP_WRITE_BARRIER);

    Return(match_info);
  }

  BIND(&if_failure);
  Return(NullConstant());
}

TNode<String> RegExpBuiltinsAssembler::FlagsGetter(TNode<Context> context,
                                                   TNode<Object> regexp,
                                                   bool is_fastpath) {
  TVARIABLE(String, result);
  Label runtime(this, Label::kDeferred), done(this, &result);
  if (is_fastpath) {
    GotoIfForceSlowPath(&runtime);
  }

  Isolate* isolate = this->isolate();

  const TNode<IntPtrT> int_one = IntPtrConstant(1);
  TVARIABLE(Uint32T, var_length, Uint32Constant(0));
  TVARIABLE(IntPtrT, var_flags);

  // First, count the number of characters we will need and check which flags
  // are set.

  if (is_fastpath) {
    // Refer to JSRegExp's flag property on the fast-path.
    CSA_DCHECK(this, IsJSRegExp(CAST(regexp)));
    const TNode<Smi> flags_smi =
        CAST(LoadObjectField(CAST(regexp), JSRegExp::kFlagsOffset));
    var_flags = SmiUntag(flags_smi);

#define CASE_FOR_FLAG(Lower, Camel, ...)                                \
  do {                                                                  \
    Label next(this);                                                   \
    GotoIfNot(IsSetWord(var_flags.value(), JSRegExp::k##Camel), &next); \
    var_length = Uint32Add(var_length.value(), Uint32Constant(1));      \
    Goto(&next);                                                        \
    BIND(&next);                                                        \
  } while (false);

    REGEXP_FLAG_LIST(CASE_FOR_FLAG)
#undef CASE_FOR_FLAG
  } else {
    DCHECK(!is_fastpath);

    // Fall back to GetProperty stub on the slow-path.
    var_flags = IntPtrZero();

#define CASE_FOR_FLAG(NAME, FLAG)                                          \
  do {                                                                     \
    Label next(this);                                                      \
    const TNode<Object> flag = GetProperty(                                \
        context, regexp, isolate->factory()->InternalizeUtf8String(NAME)); \
    Label if_isflagset(this);                                              \
    BranchIfToBooleanIsTrue(flag, &if_isflagset, &next);                   \
    BIND(&if_isflagset);                                                   \
    var_length = Uint32Add(var_length.value(), Uint32Constant(1));         \
    var_flags = Signed(WordOr(var_flags.value(), IntPtrConstant(FLAG)));   \
    Goto(&next);                                                           \
    BIND(&next);                                                           \
  } while (false)

    CASE_FOR_FLAG("hasIndices", JSRegExp::kHasIndices);
    CASE_FOR_FLAG("global", JSRegExp::kGlobal);
    CASE_FOR_FLAG("ignoreCase", JSRegExp::kIgnoreCase);
    CASE_FOR_FLAG("multiline", JSRegExp::kMultiline);
    CASE_FOR_FLAG("dotAll", JSRegExp::kDotAll);
    CASE_FOR_FLAG("unicode", JSRegExp::kUnicode);
    CASE_FOR_FLAG("sticky", JSRegExp::kSticky);
    CASE_FOR_FLAG("unicodeSets", JSRegExp::kUnicodeSets);
#undef CASE_FOR_FLAG

#define CASE_FOR_FLAG(NAME, V8_FLAG_EXTERN_REF, FLAG)                      \
  do {                                                                     \
    Label next(this);                                                      \
    TNode<Word32T> flag_value = UncheckedCast<Word32T>(                    \
        Load(MachineType::Uint8(), ExternalConstant(V8_FLAG_EXTERN_REF))); \
    GotoIf(Word32Equal(Word32And(flag_value, Int32Constant(0xFF)),         \
                       Int32Constant(0)),                                  \
           &next);                                                         \
    const TNode<Object> flag = GetProperty(                                \
        context, regexp, isolate->factory()->InternalizeUtf8String(NAME)); \
    Label if_isflagset(this);                                              \
    BranchIfToBooleanIsTrue(flag, &if_isflagset, &next);                   \
    BIND(&if_isflagset);                                                   \
    var_length = Uint32Add(var_length.value(), Uint32Constant(1));         \
    var_flags = Signed(WordOr(var_flags.value(), IntPtrConstant(FLAG)));   \
    Goto(&next);                                                           \
    BIND(&next);                                                           \
  } while (false)

    CASE_FOR_FLAG(
        "linear",
        ExternalReference::address_of_enable_experimental_regexp_engine(),
        JSRegExp::kLinear);
#undef CASE_FOR_FLAG
  }

  // Allocate a string of the required length and fill it with the
  // corresponding char for each set flag.

  {
    const TNode<SeqOneByteString> string =
        CAST(AllocateSeqOneByteString(var_length.value()));

    TVARIABLE(IntPtrT, var_offset,
              IntPtrSub(FieldSliceSeqOneByteStringChars(string).offset,
                        IntPtrConstant(1)));

#define CASE_FOR_FLAG(Lower, Camel, LowerCamel, Char, ...)              \
  do {                                                                  \
    Label next(this);                                                   \
    GotoIfNot(IsSetWord(var_flags.value(), JSRegExp::k##Camel), &next); \
    const TNode<Int32T> value = Int32Constant(Char);                    \
    StoreNoWriteBarrier(MachineRepresentation::kWord8, string,          \
                        var_offset.value(), value);                     \
    var_offset = IntPtrAdd(var_offset.value(), int_one);                \
    Goto(&next);                                                        \
    BIND(&next);                                                        \
  } while (false);

    REGEXP_FLAG_LIST(CASE_FOR_FLAG)
#undef CASE_FOR_FLAG

    if (is_fastpath) {
      result = string;
      Goto(&done);

      BIND(&runtime);
      {
        result =
            CAST(CallRuntime(Runtime::kRegExpStringFromFlags, context, regexp));
        Goto(&done);
      }

      BIND(&done);
      return result.value();
    } else {
      return string;
    }
  }
}

// ES#sec-regexpinitialize
// Runtime Semantics: RegExpInitialize ( obj, pattern, flags )
TNode<Object> RegExpBuiltinsAssembler::RegExpInitialize(
    const TNode<Context> context, const TNode<JSRegExp> regexp,
    const TNode<Object> maybe_pattern, const TNode<Object> maybe_flags) {
  // Normalize pattern.
  const TNode<Object> pattern = Select<Object>(
      IsUndefined(maybe_pattern), [=, this] { return EmptyStringConstant(); },
      [=, this] { return ToString_Inline(context, maybe_pattern); });

  // Normalize flags.
  const TNode<Object> flags = Select<Object>(
      IsUndefined(maybe_flags), [=, this] { return EmptyStringConstant(); },
      [=, this] { return ToString_Inline(context, maybe_flags); });

  // Initialize.

  return CallRuntime(Runtime::kRegExpInitializeAndCompile, context, regexp,
                     pattern, flags);
}

// ES#sec-regexp-pattern-flags
// RegExp ( pattern, flags )
TF_BUILTIN(RegExpConstructor, RegExpBuiltinsAssembler) {
  auto pattern = Parameter<Object>(Descriptor::kPattern);
  auto flags = Parameter<Object>(Descriptor::kFlags);
  auto new_target = Parameter<Object>(Descriptor::kJSNewTarget);
  auto context = Parameter<Context>(Descriptor::kContext);

  Isolate* isolate = this->isolate();

  TVARIABLE(Object, var_flags, flags);
  TVARIABLE(Object, var_pattern, pattern);
  TVARIABLE(Object, var_new_target, new_target);

  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<JSFunction> regexp_function =
      CAST(LoadContextElement(native_context, Context::REGEXP_FUNCTION_INDEX));

  TNode<BoolT> pattern_is_regexp = IsRegExp(context, pattern);

  {
    Label next(this);

    GotoIfNot(IsUndefined(new_target), &next);
    var_new_target = regexp_function;

    GotoIfNot(pattern_is_regexp, &next);
    GotoIfNot(IsUndefined(flags), &next);

    TNode<Object> value =
        GetProperty(context, pattern, isolate->factory()->constructor_string());

    GotoIfNot(TaggedEqual(value, regexp_function), &next);
    Return(pattern);

    BIND(&next);
  }

  {
    Label next(this), if_patternisfastregexp(this),
        if_patternisslowregexp(this);
    GotoIf(TaggedIsSmi(pattern), &next);

    GotoIf(IsJSRegExp(CAST(pattern)), &if_patternisfastregexp);

    Branch(pattern_is_regexp, &if_patternisslowregexp, &next);

    BIND(&if_patternisfastregexp);
    {
      TNode<Object> source =
          LoadObjectField(CAST(pattern), JSRegExp::kSourceOffset);
      var_pattern = source;

      {
        Label inner_next(this);
        GotoIfNot(IsUndefined(flags), &inner_next);

        var_flags = FlagsGetter(context, pattern, true);
        Goto(&inner_next);

        BIND(&inner_next);
      }

      Goto(&next);
    }

    BIND(&if_patternisslowregexp);
    {
      var_pattern =
          GetProperty(context, pattern, isolate->factory()->source_string());

      {
        Label inner_next(this);
        GotoIfNot(IsUndefined(flags), &inner_next);

        var_flags =
            GetProperty(context, pattern, isolate->factory()->flags_string());
        Goto(&inner_next);

        BIND(&inner_next);
      }

      Goto(&next);
    }

    BIND(&next);
  }

  // Allocate.

  TVARIABLE(JSRegExp, var_regexp);
  {
    Label allocate_jsregexp(this), allocate_generic(this, Label::kDeferred),
        next(this);
    Branch(TaggedEqual(var_new_target.value(), regexp_function),
           &allocate_jsregexp, &allocate_generic);

    BIND(&allocate_jsregexp);
    {
      const TNode<Map> initial_map = CAST(LoadObjectField(
          regexp_function, JSFunction::kPrototypeOrInitialMapOffset));
      var_regexp = CAST(AllocateJSObjectFromMap(initial_map));
      Goto(&next);
    }

    BIND(&allocate_generic);
    {
      ConstructorBuiltinsAssembler constructor_assembler(this->state());
      var_regexp = CAST(constructor_assembler.FastNewObject(
          context, regexp_function, CAST(var_new_target.value())));
      Goto(&next);
    }

    BIND(&next);
  }

  // Clear data field, as a GC can be triggered before it is initialized with a
  // correct trusted pointer handle.
  ClearTrustedPointerField(var_regexp.value(), JSRegExp::kDataOffset);

  const TNode<Object> result = RegExpInitialize(
      context, var_regexp.value(), var_pattern.value(), var_flags.value());
  Return(result);
}

// ES#sec-regexp.prototype.compile
// RegExp.prototype.compile ( pattern, flags )
TF_BUILTIN(RegExpPrototypeCompile, RegExpBuiltinsAssembler) {
  auto maybe_receiver = Parameter<Object>(Descriptor::kReceiver);
  auto maybe_pattern = Parameter<Object>(Descriptor::kPattern);
  auto maybe_flags = Parameter<Object>(Descriptor::kFlags);
  auto context = Parameter<Context>(Descriptor::kContext);

  ThrowIfNotInstanceType(context, maybe_receiver, JS_REG_EXP_TYPE,
                         "RegExp.prototype.compile");
  const TNode<JSRegExp> receiver = CAST(maybe_receiver);

  TVARIABLE(Object, var_flags, maybe_flags);
  TVARIABLE(Object, var_pattern, maybe_pattern);

  // Handle a JSRegExp pattern.
  {
    Label next(this);

    GotoIf(TaggedIsSmi(maybe_pattern), &next);
    GotoIfNot(IsJSRegExp(CAST(maybe_pattern)), &next);

    // {maybe_flags} must be undefined in this case, otherwise throw.
    {
      Label maybe_flags_is_undefined(this);
      GotoIf(IsUndefined(maybe_flags), &maybe_flags_is_undefined);

      ThrowTypeError(context, MessageTemplate::kRegExpFlags);

      BIND(&maybe_flags_is_undefined);
    }

    const TNode<JSRegExp> pattern = CAST(maybe_pattern);
    const TNode<String> new_flags = FlagsGetter(context, pattern, true);
    const TNode<Object> new_pattern =
        LoadObjectField(pattern, JSRegExp::kSourceOffset);

    var_flags = new_flags;
    var_pattern = new_pattern;

    Goto(&next);
    BIND(&next);
  }

  const TNode<Object> result = RegExpInitialize(
      context, receiver, var_pattern.value(), var_flags.value());
  Return(result);
}

// Fast-path implementation for flag checks on an unmodified JSRegExp instance.
TNode<BoolT> RegExpBuiltinsAssembler::FastFlagGetter(TNode<JSRegExp> regexp,
                                                     JSRegExp::Flag flag) {
  TNode<Smi> flags = CAST(LoadObjectField(regexp, JSRegExp::kFlagsOffset));
  TNode<Smi> mask = SmiConstant(flag);
  return ReinterpretCast<BoolT>(SmiToInt32(
      SmiShr(SmiAnd(flags, mask),
             base::bits::CountTrailingZeros(static_cast<int>(flag)))));
}

// Load through the GetProperty stub.
TNode<BoolT> RegExpBuiltinsAssembler::SlowFlagGetter(TNode<Context> context,
                                                     TNode<Object> regexp,
                                                     JSRegExp::Flag flag) {
  Label out(this), if_true(this), if_false(this);
  TVARIABLE(BoolT, var_result);

  // Only enabled based on a runtime flag.
  if (flag == JSRegExp::kLinear) {
    TNode<Word32T> flag_value = UncheckedCast<Word32T>(Load(
        MachineType::Uint8(),
        ExternalConstant(ExternalReference::
                             address_of_enable_experimental_regexp_engine())));
    GotoIf(Word32Equal(Word32And(flag_value, Int32Constant(0xFF)),
                       Int32Constant(0)),
           &if_false);
  }

  Handle<String> name;
  switch (flag) {
    case JSRegExp::kNone:
      UNREACHABLE();
#define V(Lower, Camel, LowerCamel, Char, Bit)          \
  case JSRegExp::k##Camel:                              \
    name = isolate()->factory()->LowerCamel##_string(); \
    break;
      REGEXP_FLAG_LIST(V)
#undef V
  }

  TNode<Object> value = GetProperty(context, regexp, name);
  BranchIfToBooleanIsTrue(value, &if_true, &if_false);

  BIND(&if_true);
  var_result = BoolConstant(true);
  Goto(&out);

  BIND(&if_false);
  var_result = BoolConstant(false);
  Goto(&out);

  BIND(&out);
  return var_result.value();
}

TNode<BoolT> RegExpBuiltinsAssembler::FlagGetter(TNode<Context> context,
                                                 TNode<Object> regexp,
                                                 JSRegExp::Flag flag,
                                                 bool is_fastpath) {
  return is_fastpath ? FastFlagGetter(CAST(regexp), flag)
                     : SlowFlagGetter(context, regexp, flag);
}

TNode<Number> RegExpBuiltinsAssembler::AdvanceStringIndex(
    TNode<String> string, TNode<Number> index, TNode<BoolT> is_unicode,
    bool is_fastpath) {
  CSA_DCHECK(this, IsNumberNormalized(index));
  if (is_fastpath) CSA_DCHECK(this, TaggedIsPositiveSmi(index));

  // Default to last_index + 1.
  // TODO(pwong): Consider using TrySmiAdd for the fast path to reduce generated
  // code.
  TNode<Number> index_plus_one = NumberInc(index);
  TVARIABLE(Number, var_result, index_plus_one);

  // TODO(v8:9880): Given that we have to convert index from Number to UintPtrT
  // anyway, consider using UintPtrT index to simplify the code below.

  // Advancing the index has some subtle issues involving the distinction
  // between Smis and HeapNumbers. There's three cases:
  // * {index} is a Smi, {index_plus_one} is a Smi. The standard case.
  // * {index} is a Smi, {index_plus_one} overflows into a HeapNumber.
  //   In this case we can return the result early, because
  //   {index_plus_one} > {string}.length.
  // * {index} is a HeapNumber, {index_plus_one} is a HeapNumber. This can only
  //   occur when {index} is outside the Smi range since we normalize
  //   explicitly. Again we can return early.
  if (is_fastpath) {
    // Must be in Smi range on the fast path. We control the value of {index}
    // on all call-sites and can never exceed the length of the string.
    static_assert(String::kMaxLength + 2 < Smi::kMaxValue);
    CSA_DCHECK(this, TaggedIsPositiveSmi(index_plus_one));
  }

  Label if_isunicode(this), out(this);
  GotoIfNot(is_unicode, &out);

  // Keep this unconditional (even on the fast path) just to be safe.
  Branch(TaggedIsPositiveSmi(index_plus_one), &if_isunicode, &out);

  BIND(&if_isunicode);
  {
    TNode<UintPtrT> string_length = Unsigned(LoadStringLengthAsWord(string));
    TNode<UintPtrT> untagged_plus_one =
        Unsigned(SmiUntag(CAST(index_plus_one)));
    GotoIfNot(UintPtrLessThan(untagged_plus_one, string_length), &out);

    TNode<Int32T> lead =
        StringCharCodeAt(string, Unsigned(SmiUntag(CAST(index))));
    GotoIfNot(Word32Equal(Word32And(lead, Int32Constant(0xFC00)),
                          Int32Constant(0xD800)),
              &out);

    TNode<Int32T> trail = StringCharCodeAt(string, untagged_plus_one);
    GotoIfNot(Word32Equal(Word32And(trail, Int32Constant(0xFC00)),
                          Int32Constant(0xDC00)),
              &out);

    // At a surrogate pair, return index + 2.
    TNode<Number> index_plus_two = NumberInc(index_plus_one);
    var_result = index_plus_two;

    Goto(&out);
  }

  BIND(&out);
  return var_result.value();
}

// ES#sec-createregexpstringiterator
// CreateRegExpStringIterator ( R, S, global, fullUnicode )
TNode<Object> RegExpMatchAllAssembler::CreateRegExpStringIterator(
    TNode<NativeContext> native_context, TNode<Object> regexp,
    TNode<String> string, TNode<BoolT> global, TNode<BoolT> full_unicode) {
  TNode<Map> map = CAST(LoadContextElement(
      native_context,
      Context::INITIAL_REGEXP_STRING_ITERATOR_PROTOTYPE_MAP_INDEX));

  // 4. Let iterator be ObjectCreate(%RegExpStringIteratorPrototype%, «
  // [[IteratingRegExp]], [[IteratedString]], [[Global]], [[Unicode]],
  // [[Done]] »).
  TNode<HeapObject> iterator = Allocate(JSRegExpStringIterator::kHeaderSize);
  StoreMapNoWriteBarrier(iterator, map);
  StoreObjectFieldRoot(iterator,
                       JSRegExpStringIterator::kPropertiesOrHashOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldRoot(iterator, JSRegExpStringIterator::kElementsOffset,
                       RootIndex::kEmptyFixedArray);

  // 5. Set iterator.[[IteratingRegExp]] to R.
  StoreObjectFieldNoWriteBarrier(
      iterator, JSRegExpStringIterator::kIteratingRegExpOffset, regexp);

  // 6. Set iterator.[[IteratedString]] to S.
  StoreObjectFieldNoWriteBarrier(
      iterator, JSRegExpStringIterator::kIteratedStringOffset, string);

  // 7. Set iterator.[[Global]] to global.
  // 8. Set iterator.[[Unicode]] to fullUnicode.
  // 9. Set iterator.[[Done]] to false.
  TNode<Int32T> global_flag =
      Word32Shl(ReinterpretCast<Int32T>(global),
                Int32Constant(JSRegExpStringIterator::GlobalBit::kShift));
  TNode<Int32T> unicode_flag =
      Word32Shl(ReinterpretCast<Int32T>(full_unicode),
                Int32Constant(JSRegExpStringIterator::UnicodeBit::kShift));
  TNode<Int32T> iterator_flags = Word32Or(global_flag, unicode_flag);
  StoreObjectFieldNoWriteBarrier(iterator, JSRegExpStringIterator::kFlagsOffset,
                                 SmiFromInt32(iterator_flags));

  return iterator;
}

// Generates the fast path for @@split. {regexp} is an unmodified, non-sticky
// JSRegExp, {string} is a String, and {limit} is a Smi.
TNode<JSArray> RegExpBuiltinsAssembler::RegExpPrototypeSplitBody(
    TNode<Context> context, TNode<JSRegExp> regexp, TNode<String> string,
    TNode<Smi> limit) {
  CSA_DCHECK(this, IsFastRegExpPermissive(context, regexp));
  CSA_DCHECK(this, Word32BinaryNot(FastFlagGetter(regexp, JSRegExp::kSticky)));

  TNode<IntPtrT> int_limit = SmiUntag(limit);

  const ElementsKind elements_kind = PACKED_ELEMENTS;

  Label done(this);
  Label return_empty_array(this, Label::kDeferred);
  TVARIABLE(JSArray, var_result);

  // Exception handling is necessary to free any allocated memory.
  TVARIABLE(Object, var_exception);
  Label if_exception(this, Label::kDeferred);

  // Allocate the results vector. Allocate space for exactly one result,
  // forcing the engine to return after each match. This is necessary due to
  // the specialized AdvanceStringIndex logic below.
  TNode<RegExpData> data = CAST(LoadTrustedPointerFromObject(
      regexp, JSRegExp::kDataOffset, kRegExpDataIndirectPointerTag));
  TNode<Smi> capture_count = LoadCaptureCount(data);
  TNode<Smi> register_count_p
"""


```
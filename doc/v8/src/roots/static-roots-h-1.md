Response:
Let's break down the thought process for analyzing this V8 header file.

**1. Initial Understanding & Context:**

* **File Path:** `v8/src/roots/static-roots.h`. This immediately suggests it's about "roots" within the V8 heap, specifically "static" ones. Roots are fundamental objects that the garbage collector uses to start its reachability analysis. "Static" implies these are likely constant and pre-defined.
* **`.h` extension:**  It's a C++ header file. This means it defines data structures and constants used by V8's C++ codebase.
* **Content Examination (First Pass):**  Scanning through the file, the overwhelming majority of lines look like this: `static constexpr Tagged_t ksome_string = 0x...;`. This pattern is extremely important. It tells us:
    * `static constexpr`: These are compile-time constants.
    * `Tagged_t`:  This is a V8-specific type, likely representing a pointer to an object in the V8 heap. The "Tagged" part hints at potential encoding of type information within the pointer itself.
    * `ksome_string`:  The names clearly suggest these represent string constants. The `k` prefix is a common convention for constants.
    * `0x...`:  Hexadecimal values, likely representing the memory addresses or some other encoded representation of these strings.

**2. Formulating the Core Functionality:**

Based on the initial content examination, the primary function becomes clear:  **Defining static, pre-interned strings that are fundamental to the V8 engine.**  These strings are essential for various internal operations.

**3. Connecting to JavaScript (Hypothesis and Verification):**

The names of many constants directly correlate to JavaScript concepts: `kArray_string`, `kObject_string`, `kPromise_string`, `ktoString_string`, keywords like `ktrue_string`, `knull_string`, and so on. This strongly suggests a connection to how V8 represents and manipulates JavaScript objects and code internally.

* **Hypothesis:** These constants are used to efficiently compare strings during runtime, avoid redundant string creation, and represent core JavaScript entities.
* **Verification (Conceptual):** When V8 parses JavaScript code, it needs to identify keywords, object names, and built-in methods. Having these strings readily available as constants allows for fast comparisons (likely pointer comparisons if the strings are interned). Similarly, when working with JavaScript objects, V8 needs to access property names, and these constants likely play a role.

**4. Addressing the `.tq` Question:**

The prompt raises the possibility of a `.tq` extension and Torque. Since the provided file is `.h`, this part of the prompt is a distractor for *this specific file*. However, it's important to acknowledge Torque's existence within V8 and how it *could* be related in other contexts (defining built-in functions, for example).

**5. Providing JavaScript Examples:**

To illustrate the connection to JavaScript, concrete examples are needed. The examples should showcase scenarios where these string constants would likely be used internally by V8:

* **Type checking:** `typeof myVar === 'object'`. V8 needs to compare the result of `typeof` with the string "object".
* **Accessing properties:** `obj.toString()`. V8 needs to identify the "toString" property.
* **Checking for `null`:** `myVar === null`. V8 compares `myVar` with the internal representation of `null`.
* **Working with Promises:** `new Promise(...)`. V8 needs to identify the `Promise` constructor.

**6. Considering Code Logic and Input/Output (Limited Applicability):**

This header file *primarily defines constants*. It doesn't contain complex code logic that takes input and produces output in the traditional sense. Therefore, this aspect of the prompt has limited direct relevance to *this specific file*. The "input" could be considered the request to access one of these constants, and the "output" is the `Tagged_t` value (the address or encoded representation).

**7. Identifying Common Programming Errors (Indirectly Related):**

While the header file itself doesn't *cause* common programming errors, understanding its purpose helps explain *why* certain errors manifest. For example:

* **Typos in property names:**  If you type `obj.toSting()`, the error arises because V8 can't find a property matching the *exact* string "toSting". The constants in this file emphasize the importance of precise string matching.
* **Incorrect `typeof` checks:**  Understanding that V8 internally uses these string constants clarifies why `typeof null === 'object'` (a historical quirk) works the way it does.

**8. Synthesizing the Summary:**

The summary needs to concisely capture the key takeaways:

* Defines static string constants.
* Used internally by V8.
* Relates to fundamental JavaScript concepts.
* Improves efficiency (likely through interning and fast comparisons).

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Are these *all* the static roots?  No, this file seems specifically focused on *string* roots. Other static roots likely exist for other types of objects.
* **Refinement:**  The "Tagged_t" type is important. Initially, I just thought of it as a pointer, but the "Tagged" aspect hints at more sophisticated memory management within V8. While not fully explored in the answer, it's a key detail.
* **Clarity on Torque:**  Emphasize that while the prompt mentions Torque, this specific file is a `.h` file, and the Torque connection is hypothetical for this particular piece of code.

By following this thought process, combining analysis of the code structure, naming conventions, and relating it back to JavaScript concepts, we can arrive at a comprehensive understanding of the `static-roots.h` file.
这是目录为 `v8/src/roots/static-roots.h` 的一个 V8 源代码的第 2 部分，共 3 部分。

**功能归纳：**

这部分代码定义了一系列静态常量，这些常量是 V8 引擎内部使用的预定义的字符串。每个常量都使用 `static constexpr Tagged_t k[string_name]_string = 0x[hex_value];` 的形式定义，其中 `Tagged_t` 很可能是 V8 中表示指向堆上对象的指针的类型。

**具体功能拆解：**

1. **定义静态字符串常量：**  该文件定义了大量的字符串常量，例如 `kliseconds_string`, `kminute_string`, `kModule_string`, `kNaN_string` 等。这些字符串在 V8 引擎的运行过程中会被频繁使用。

2. **使用 `Tagged_t` 类型：**  `Tagged_t` 类型暗示了这些字符串常量很可能不是简单的 C++ 字符串，而是 V8 堆上的对象。这意味着 V8 引擎在启动时或者编译时，就已经将这些字符串创建并存储在了堆上，并用一个唯一的 `Tagged_t` 值来标识它们。这样做可以提高效率，避免重复创建相同的字符串。

3. **作为 V8 引擎的内部基石：** 这些字符串常量很可能用于：
    * **标识 JavaScript 的关键字和内置对象：** 例如 `kArray_string`, `kObject_string`, `kPromise_string` 等。
    * **表示错误类型：** 例如 `kTypeError_string`, `kRangeError_string` 等。
    * **内置方法的名称：** 例如 `ktoString_string`, `kvalueOf_string` 等。
    * **内部属性的名称：** 例如 `kproto_string`, `klength_string` 等。
    * **符号（Symbols）的描述：** 例如 `kSymbol_iterator_string` 等。

**与 JavaScript 功能的关系及举例：**

这些静态字符串常量与 JavaScript 的功能息息相关。V8 引擎在解析、编译和执行 JavaScript 代码时，会用到这些常量来识别语言结构、访问对象属性、调用内置方法等。

**例如：**

当 JavaScript 代码中出现 `Array` 这个标识符时，V8 引擎会通过比较内部表示与 `kArray_string` 这个常量来确认它指的是 JavaScript 的 `Array` 构造函数。

```javascript
// JavaScript 代码
let arr = new Array(1, 2, 3);
console.log(arr.toString());
```

在 V8 引擎内部，当执行 `new Array(1, 2, 3)` 时，引擎会用到类似 `kArray_string` 的常量来查找和创建 `Array` 对象。当执行 `arr.toString()` 时，引擎会用到类似 `ktoString_string` 的常量来查找 `Array.prototype.toString` 方法。

**代码逻辑推理（有限）：**

由于这部分代码主要是常量定义，代码逻辑推理相对有限。但可以推断：

* **假设输入：** V8 引擎需要识别一个 JavaScript 标识符，例如 "Array"。
* **输出：**  V8 引擎会将该标识符的内部表示与 `kArray_string` 常量进行比较。如果匹配，则认为该标识符是 `Array`。

**用户常见的编程错误（间接相关）：**

虽然这个头文件本身不直接导致用户的编程错误，但它所定义的常量与一些常见的错误相关：

* **类型错误 (TypeError):**  如果用户尝试调用一个不存在的方法，例如 `myObject.nonExistentMethod()`，V8 引擎会抛出 `TypeError`。引擎内部会使用 `kTypeError_string` 这样的常量来创建错误对象。

```javascript
// JavaScript 代码
let obj = {};
// 常见的错误：尝试调用未定义的方法
try {
  obj.undefinedMethod();
} catch (e) {
  console.error(e.name); // 输出 "TypeError"
}
```

* **引用错误 (ReferenceError):**  如果用户尝试访问一个未声明的变量，V8 引擎会抛出 `ReferenceError`。引擎内部会使用 `kReferenceError_string` 这样的常量。

```javascript
// JavaScript 代码
try {
  console.log(undeclaredVariable); // 常见的错误：访问未声明的变量
} catch (e) {
  console.error(e.name); // 输出 "ReferenceError"
}
```

**关于 `.tq` 结尾：**

如果 `v8/src/roots/static-roots.h` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是 V8 使用的一种领域特定语言，用于生成高效的 C++ 代码，特别是用于实现 JavaScript 的内置函数和运行时功能。然而，根据提供的信息，该文件以 `.h` 结尾，所以它是标准的 C++ 头文件。

**总结：**

这部分 `v8/src/roots/static-roots.h` 代码定义了大量的静态字符串常量，这些常量是 V8 引擎内部运行的基础。它们用于标识 JavaScript 的关键字、内置对象、方法名、属性名等。虽然不直接涉及复杂的代码逻辑，但它们是 V8 引擎高效地解析、编译和执行 JavaScript 代码的关键组成部分。这些常量与用户在编写 JavaScript 代码时遇到的各种概念和错误类型息息相关。

### 提示词
```
这是目录为v8/src/roots/static-roots.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/roots/static-roots.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
liseconds_string = 0x511d;
  static constexpr Tagged_t kminute_string = 0x5135;
  static constexpr Tagged_t kminutes_string = 0x5149;
  static constexpr Tagged_t kModule_string = 0x515d;
  static constexpr Tagged_t kmonth_string = 0x5171;
  static constexpr Tagged_t kmonthDayFromFields_string = 0x5185;
  static constexpr Tagged_t kmonths_string = 0x51a5;
  static constexpr Tagged_t kmonthsInYear_string = 0x51b9;
  static constexpr Tagged_t kmonthCode_string = 0x51d1;
  static constexpr Tagged_t kmultiline_string = 0x51e9;
  static constexpr Tagged_t kNaN_string = 0x5201;
  static constexpr Tagged_t knanosecond_string = 0x5211;
  static constexpr Tagged_t knanoseconds_string = 0x5229;
  static constexpr Tagged_t knarrow_string = 0x5241;
  static constexpr Tagged_t knative_string = 0x5255;
  static constexpr Tagged_t kNFC_string = 0x5269;
  static constexpr Tagged_t kNFD_string = 0x5279;
  static constexpr Tagged_t kNFKC_string = 0x5289;
  static constexpr Tagged_t kNFKD_string = 0x5299;
  static constexpr Tagged_t knot_equal_string = 0x52a9;
  static constexpr Tagged_t knull_string = 0x52c1;
  static constexpr Tagged_t knull_to_string = 0x52d1;
  static constexpr Tagged_t kNumber_string = 0x52ed;
  static constexpr Tagged_t knumber_string = 0x5301;
  static constexpr Tagged_t knumber_to_string = 0x5315;
  static constexpr Tagged_t kObject_string = 0x5331;
  static constexpr Tagged_t kobject_string = 0x5345;
  static constexpr Tagged_t kobject_to_string = 0x5359;
  static constexpr Tagged_t kObject_prototype_string = 0x5375;
  static constexpr Tagged_t koffset_string = 0x5391;
  static constexpr Tagged_t koffsetNanoseconds_string = 0x53a5;
  static constexpr Tagged_t kok_string = 0x53c5;
  static constexpr Tagged_t kother_string = 0x53d5;
  static constexpr Tagged_t koverflow_string = 0x53e9;
  static constexpr Tagged_t kownKeys_string = 0x53fd;
  static constexpr Tagged_t kpercent_string = 0x5411;
  static constexpr Tagged_t kplainDate_string = 0x5425;
  static constexpr Tagged_t kplainTime_string = 0x543d;
  static constexpr Tagged_t kposition_string = 0x5455;
  static constexpr Tagged_t kpreventExtensions_string = 0x5469;
  static constexpr Tagged_t kprivate_constructor_string = 0x5489;
  static constexpr Tagged_t kPromise_string = 0x54a1;
  static constexpr Tagged_t kpromise_string = 0x54b5;
  static constexpr Tagged_t kproto_string = 0x54c9;
  static constexpr Tagged_t kproxy_string = 0x54e1;
  static constexpr Tagged_t kProxy_string = 0x54f5;
  static constexpr Tagged_t kquery_colon_string = 0x5509;
  static constexpr Tagged_t kRangeError_string = 0x5519;
  static constexpr Tagged_t kraw_json_string = 0x5531;
  static constexpr Tagged_t kraw_string = 0x5545;
  static constexpr Tagged_t kReferenceError_string = 0x5555;
  static constexpr Tagged_t kReflectGet_string = 0x5571;
  static constexpr Tagged_t kReflectHas_string = 0x5589;
  static constexpr Tagged_t kRegExp_string = 0x55a1;
  static constexpr Tagged_t kregexp_to_string = 0x55b5;
  static constexpr Tagged_t kreject_string = 0x55d1;
  static constexpr Tagged_t krelativeTo_string = 0x55e5;
  static constexpr Tagged_t kresizable_string = 0x55fd;
  static constexpr Tagged_t kResizableArrayBuffer_string = 0x5615;
  static constexpr Tagged_t kreturn_string = 0x5635;
  static constexpr Tagged_t krevoke_string = 0x5649;
  static constexpr Tagged_t kroundingIncrement_string = 0x565d;
  static constexpr Tagged_t kRuntimeError_string = 0x567d;
  static constexpr Tagged_t kWebAssemblyException_string = 0x5695;
  static constexpr Tagged_t kWebAssemblyModule_string = 0x56b9;
  static constexpr Tagged_t kScript_string = 0x56d9;
  static constexpr Tagged_t kscript_string = 0x56ed;
  static constexpr Tagged_t ksecond_string = 0x5701;
  static constexpr Tagged_t kseconds_string = 0x5715;
  static constexpr Tagged_t kshort_string = 0x5729;
  static constexpr Tagged_t kSet_string = 0x573d;
  static constexpr Tagged_t ksentence_string = 0x574d;
  static constexpr Tagged_t kset_space_string = 0x5761;
  static constexpr Tagged_t kset_string = 0x5771;
  static constexpr Tagged_t kSetIterator_string = 0x5781;
  static constexpr Tagged_t ksetPrototypeOf_string = 0x5799;
  static constexpr Tagged_t kShadowRealm_string = 0x57b5;
  static constexpr Tagged_t kSharedArray_string = 0x57cd;
  static constexpr Tagged_t kSharedArrayBuffer_string = 0x57e5;
  static constexpr Tagged_t kSharedStruct_string = 0x5805;
  static constexpr Tagged_t ksign_string = 0x581d;
  static constexpr Tagged_t ksize_string = 0x582d;
  static constexpr Tagged_t ksmallestUnit_string = 0x583d;
  static constexpr Tagged_t ksource_string = 0x5855;
  static constexpr Tagged_t ksourceText_string = 0x5869;
  static constexpr Tagged_t kstack_string = 0x5881;
  static constexpr Tagged_t kstackTraceLimit_string = 0x5895;
  static constexpr Tagged_t kstatic_initializer_string = 0x58b1;
  static constexpr Tagged_t ksticky_string = 0x58d1;
  static constexpr Tagged_t kString_string = 0x58e5;
  static constexpr Tagged_t kstring_string = 0x58f9;
  static constexpr Tagged_t kstring_to_string = 0x590d;
  static constexpr Tagged_t ksuppressed_string = 0x5929;
  static constexpr Tagged_t kSuppressedError_string = 0x5941;
  static constexpr Tagged_t kSymbol_iterator_string = 0x595d;
  static constexpr Tagged_t kSymbol_match_all_string = 0x5979;
  static constexpr Tagged_t kSymbol_replace_string = 0x5995;
  static constexpr Tagged_t ksymbol_species_string = 0x59b1;
  static constexpr Tagged_t kSymbol_species_string = 0x59cd;
  static constexpr Tagged_t kSymbol_split_string = 0x59e9;
  static constexpr Tagged_t kSymbol_string = 0x5a01;
  static constexpr Tagged_t ksymbol_string = 0x5a15;
  static constexpr Tagged_t kSyntaxError_string = 0x5a29;
  static constexpr Tagged_t ktarget_string = 0x5a41;
  static constexpr Tagged_t kthis_function_string = 0x5a55;
  static constexpr Tagged_t kthis_string = 0x5a71;
  static constexpr Tagged_t kthrow_string = 0x5a81;
  static constexpr Tagged_t ktimed_out_string = 0x5a95;
  static constexpr Tagged_t ktimeZone_string = 0x5aad;
  static constexpr Tagged_t ktoJSON_string = 0x5ac1;
  static constexpr Tagged_t ktoString_string = 0x5ad5;
  static constexpr Tagged_t ktrue_string = 0x5ae9;
  static constexpr Tagged_t ktotal_string = 0x5af9;
  static constexpr Tagged_t kTypeError_string = 0x5b0d;
  static constexpr Tagged_t kUint16Array_string = 0x5b25;
  static constexpr Tagged_t kUint32Array_string = 0x5b3d;
  static constexpr Tagged_t kUint8Array_string = 0x5b55;
  static constexpr Tagged_t kUint8ClampedArray_string = 0x5b6d;
  static constexpr Tagged_t kundefined_string = 0x5b8d;
  static constexpr Tagged_t kundefined_to_string = 0x5ba5;
  static constexpr Tagged_t kunicode_string = 0x5bc5;
  static constexpr Tagged_t kunicodeSets_string = 0x5bd9;
  static constexpr Tagged_t kunit_string = 0x5bf1;
  static constexpr Tagged_t kURIError_string = 0x5c01;
  static constexpr Tagged_t kUTC_string = 0x5c15;
  static constexpr Tagged_t kWeakMap_string = 0x5c25;
  static constexpr Tagged_t kWeakRef_string = 0x5c39;
  static constexpr Tagged_t kWeakSet_string = 0x5c4d;
  static constexpr Tagged_t kweek_string = 0x5c61;
  static constexpr Tagged_t kweeks_string = 0x5c71;
  static constexpr Tagged_t kweekOfYear_string = 0x5c85;
  static constexpr Tagged_t kwith_string = 0x5c9d;
  static constexpr Tagged_t kword_string = 0x5cad;
  static constexpr Tagged_t kyearMonthFromFields_string = 0x5cbd;
  static constexpr Tagged_t kyear_string = 0x5cdd;
  static constexpr Tagged_t kyears_string = 0x5ced;
  static constexpr Tagged_t kPropertyCellHoleValue = 0x5d01;
  static constexpr Tagged_t kHashTableHoleValue = 0x5d0d;
  static constexpr Tagged_t kPromiseHoleValue = 0x5d19;
  static constexpr Tagged_t kUninitializedValue = 0x5d25;
  static constexpr Tagged_t kArgumentsMarker = 0x5d31;
  static constexpr Tagged_t kTerminationException = 0x5d3d;
  static constexpr Tagged_t kException = 0x5d49;
  static constexpr Tagged_t kOptimizedOut = 0x5d55;
  static constexpr Tagged_t kStaleRegister = 0x5d61;
  static constexpr Tagged_t kSelfReferenceMarker = 0x5d6d;
  static constexpr Tagged_t kBasicBlockCountersMarker = 0x5d79;
  static constexpr Tagged_t karray_buffer_wasm_memory_symbol = 0x5d85;
  static constexpr Tagged_t kcall_site_info_symbol = 0x5d95;
  static constexpr Tagged_t kclass_fields_symbol = 0x5da5;
  static constexpr Tagged_t kclass_positions_symbol = 0x5db5;
  static constexpr Tagged_t kerror_end_pos_symbol = 0x5dc5;
  static constexpr Tagged_t kerror_message_symbol = 0x5dd5;
  static constexpr Tagged_t kerror_script_symbol = 0x5de5;
  static constexpr Tagged_t kerror_stack_symbol = 0x5df5;
  static constexpr Tagged_t kerror_start_pos_symbol = 0x5e05;
  static constexpr Tagged_t kfrozen_symbol = 0x5e15;
  static constexpr Tagged_t kinterpreter_trampoline_symbol = 0x5e25;
  static constexpr Tagged_t knative_context_index_symbol = 0x5e35;
  static constexpr Tagged_t knonextensible_symbol = 0x5e45;
  static constexpr Tagged_t kpromise_debug_message_symbol = 0x5e55;
  static constexpr Tagged_t kpromise_forwarding_handler_symbol = 0x5e65;
  static constexpr Tagged_t kpromise_handled_by_symbol = 0x5e75;
  static constexpr Tagged_t kpromise_awaited_by_symbol = 0x5e85;
  static constexpr Tagged_t kregexp_result_names_symbol = 0x5e95;
  static constexpr Tagged_t kregexp_result_regexp_input_symbol = 0x5ea5;
  static constexpr Tagged_t kregexp_result_regexp_last_index_symbol = 0x5eb5;
  static constexpr Tagged_t ksealed_symbol = 0x5ec5;
  static constexpr Tagged_t kshared_struct_map_elements_template_symbol =
      0x5ed5;
  static constexpr Tagged_t kshared_struct_map_registry_key_symbol = 0x5ee5;
  static constexpr Tagged_t kstrict_function_transition_symbol = 0x5ef5;
  static constexpr Tagged_t ktemplate_literal_function_literal_id_symbol =
      0x5f05;
  static constexpr Tagged_t ktemplate_literal_slot_id_symbol = 0x5f15;
  static constexpr Tagged_t kwasm_cross_instance_call_symbol = 0x5f25;
  static constexpr Tagged_t kwasm_exception_tag_symbol = 0x5f35;
  static constexpr Tagged_t kwasm_exception_values_symbol = 0x5f45;
  static constexpr Tagged_t kwasm_uncatchable_symbol = 0x5f55;
  static constexpr Tagged_t kwasm_debug_proxy_cache_symbol = 0x5f65;
  static constexpr Tagged_t kwasm_debug_proxy_names_symbol = 0x5f75;
  static constexpr Tagged_t kasync_iterator_symbol = 0x5f85;
  static constexpr Tagged_t kintl_fallback_symbol = 0x5fb5;
  static constexpr Tagged_t kmatch_symbol = 0x5fed;
  static constexpr Tagged_t ksearch_symbol = 0x6015;
  static constexpr Tagged_t kunscopables_symbol = 0x6041;
  static constexpr Tagged_t kdispose_symbol = 0x6071;
  static constexpr Tagged_t kasync_dispose_symbol = 0x609d;
  static constexpr Tagged_t khas_instance_symbol = 0x60cd;
  static constexpr Tagged_t kto_string_tag_symbol = 0x60fd;
  static constexpr Tagged_t kconstructor_string = 0x6175;
  static constexpr Tagged_t knext_string = 0x618d;
  static constexpr Tagged_t kresolve_string = 0x619d;
  static constexpr Tagged_t kthen_string = 0x61b1;
  static constexpr Tagged_t kvalueOf_string = 0x61c1;
  static constexpr Tagged_t kiterator_symbol = 0x61d5;
  static constexpr Tagged_t kmatch_all_symbol = 0x61e5;
  static constexpr Tagged_t kreplace_symbol = 0x61f5;
  static constexpr Tagged_t kspecies_symbol = 0x6205;
  static constexpr Tagged_t ksplit_symbol = 0x6215;
  static constexpr Tagged_t kto_primitive_symbol = 0x6225;
  static constexpr Tagged_t kis_concat_spreadable_symbol = 0x6235;
  static constexpr Tagged_t kEmptySlowElementDictionary = 0x6245;
  static constexpr Tagged_t kEmptySymbolTable = 0x6269;
  static constexpr Tagged_t kEmptyOrderedHashMap = 0x6285;
  static constexpr Tagged_t kEmptyOrderedHashSet = 0x6299;
  static constexpr Tagged_t kEmptyFeedbackMetadata = 0x62ad;
  static constexpr Tagged_t kGlobalThisBindingScopeInfo = 0x62b9;
  static constexpr Tagged_t kEmptyFunctionScopeInfo = 0x62d9;
  static constexpr Tagged_t kNativeScopeInfo = 0x62fd;
  static constexpr Tagged_t kShadowRealmScopeInfo = 0x6315;
  static constexpr Tagged_t kWasmNullPadding = 0x632d;
  static constexpr Tagged_t kWasmNull = 0xfffd;
  static constexpr Tagged_t kJSSharedArrayMap = 0x20001;
  static constexpr Tagged_t kJSAtomicsMutexMap = 0x20045;
  static constexpr Tagged_t kJSAtomicsConditionMap = 0x2006d;

  static constexpr Tagged_t kFirstAllocatedRoot = 0x11;
  static constexpr Tagged_t kLastAllocatedRoot = 0x2006d;
};

static constexpr std::array<Tagged_t, 767> StaticReadOnlyRootsPointerTable = {
    StaticReadOnlyRoot::kFreeSpaceMap,
    StaticReadOnlyRoot::kOnePointerFillerMap,
    StaticReadOnlyRoot::kTwoPointerFillerMap,
    StaticReadOnlyRoot::kUninitializedValue,
    StaticReadOnlyRoot::kUndefinedValue,
    StaticReadOnlyRoot::kTheHoleValue,
    StaticReadOnlyRoot::kNullValue,
    StaticReadOnlyRoot::kTrueValue,
    StaticReadOnlyRoot::kFalseValue,
    StaticReadOnlyRoot::kempty_string,
    StaticReadOnlyRoot::kMetaMap,
    StaticReadOnlyRoot::kByteArrayMap,
    StaticReadOnlyRoot::kFixedArrayMap,
    StaticReadOnlyRoot::kFixedCOWArrayMap,
    StaticReadOnlyRoot::kFixedDoubleArrayMap,
    StaticReadOnlyRoot::kHashTableMap,
    StaticReadOnlyRoot::kSymbolMap,
    StaticReadOnlyRoot::kSeqOneByteStringMap,
    StaticReadOnlyRoot::kInternalizedOneByteStringMap,
    StaticReadOnlyRoot::kScopeInfoMap,
    StaticReadOnlyRoot::kSharedFunctionInfoMap,
    StaticReadOnlyRoot::kInstructionStreamMap,
    StaticReadOnlyRoot::kCellMap,
    StaticReadOnlyRoot::kGlobalPropertyCellMap,
    StaticReadOnlyRoot::kForeignMap,
    StaticReadOnlyRoot::kHeapNumberMap,
    StaticReadOnlyRoot::kTransitionArrayMap,
    StaticReadOnlyRoot::kFeedbackVectorMap,
    StaticReadOnlyRoot::kEmptyScopeInfo,
    StaticReadOnlyRoot::kEmptyFixedArray,
    StaticReadOnlyRoot::kEmptyDescriptorArray,
    StaticReadOnlyRoot::kArgumentsMarker,
    StaticReadOnlyRoot::kException,
    StaticReadOnlyRoot::kTerminationException,
    StaticReadOnlyRoot::kOptimizedOut,
    StaticReadOnlyRoot::kStaleRegister,
    StaticReadOnlyRoot::kPropertyCellHoleValue,
    StaticReadOnlyRoot::kHashTableHoleValue,
    StaticReadOnlyRoot::kPromiseHoleValue,
    StaticReadOnlyRoot::kScriptContextTableMap,
    StaticReadOnlyRoot::kClosureFeedbackCellArrayMap,
    StaticReadOnlyRoot::kFeedbackMetadataArrayMap,
    StaticReadOnlyRoot::kArrayListMap,
    StaticReadOnlyRoot::kBigIntMap,
    StaticReadOnlyRoot::kObjectBoilerplateDescriptionMap,
    StaticReadOnlyRoot::kBytecodeArrayMap,
    StaticReadOnlyRoot::kCodeMap,
    StaticReadOnlyRoot::kCoverageInfoMap,
    StaticReadOnlyRoot::kDictionaryTemplateInfoMap,
    StaticReadOnlyRoot::kGlobalDictionaryMap,
    StaticReadOnlyRoot::kGlobalContextSidePropertyCellMap,
    StaticReadOnlyRoot::kManyClosuresCellMap,
    StaticReadOnlyRoot::kMegaDomHandlerMap,
    StaticReadOnlyRoot::kModuleInfoMap,
    StaticReadOnlyRoot::kNameDictionaryMap,
    StaticReadOnlyRoot::kNoClosuresCellMap,
    StaticReadOnlyRoot::kNumberDictionaryMap,
    StaticReadOnlyRoot::kOneClosureCellMap,
    StaticReadOnlyRoot::kOrderedHashMapMap,
    StaticReadOnlyRoot::kOrderedHashSetMap,
    StaticReadOnlyRoot::kNameToIndexHashTableMap,
    StaticReadOnlyRoot::kRegisteredSymbolTableMap,
    StaticReadOnlyRoot::kOrderedNameDictionaryMap,
    StaticReadOnlyRoot::kPreparseDataMap,
    StaticReadOnlyRoot::kPropertyArrayMap,
    StaticReadOnlyRoot::kAccessorInfoMap,
    StaticReadOnlyRoot::kRegExpMatchInfoMap,
    StaticReadOnlyRoot::kRegExpDataMap,
    StaticReadOnlyRoot::kAtomRegExpDataMap,
    StaticReadOnlyRoot::kIrRegExpDataMap,
    StaticReadOnlyRoot::kSimpleNumberDictionaryMap,
    StaticReadOnlyRoot::kSmallOrderedHashMapMap,
    StaticReadOnlyRoot::kSmallOrderedHashSetMap,
    StaticReadOnlyRoot::kSmallOrderedNameDictionaryMap,
    StaticReadOnlyRoot::kSourceTextModuleMap,
    StaticReadOnlyRoot::kSwissNameDictionaryMap,
    StaticReadOnlyRoot::kSyntheticModuleMap,
    StaticReadOnlyRoot::kWasmImportDataMap,
    StaticReadOnlyRoot::kWasmCapiFunctionDataMap,
    StaticReadOnlyRoot::kWasmContinuationObjectMap,
    StaticReadOnlyRoot::kWasmDispatchTableMap,
    StaticReadOnlyRoot::kWasmExportedFunctionDataMap,
    StaticReadOnlyRoot::kWasmInternalFunctionMap,
    StaticReadOnlyRoot::kWasmFuncRefMap,
    StaticReadOnlyRoot::kWasmJSFunctionDataMap,
    StaticReadOnlyRoot::kWasmNullMap,
    StaticReadOnlyRoot::kWasmResumeDataMap,
    StaticReadOnlyRoot::kWasmSuspenderObjectMap,
    StaticReadOnlyRoot::kWasmTrustedInstanceDataMap,
    StaticReadOnlyRoot::kWasmTypeInfoMap,
    StaticReadOnlyRoot::kWeakFixedArrayMap,
    StaticReadOnlyRoot::kWeakArrayListMap,
    StaticReadOnlyRoot::kEphemeronHashTableMap,
    StaticReadOnlyRoot::kEmbedderDataArrayMap,
    StaticReadOnlyRoot::kWeakCellMap,
    StaticReadOnlyRoot::kTrustedFixedArrayMap,
    StaticReadOnlyRoot::kTrustedWeakFixedArrayMap,
    StaticReadOnlyRoot::kTrustedByteArrayMap,
    StaticReadOnlyRoot::kProtectedFixedArrayMap,
    StaticReadOnlyRoot::kInterpreterDataMap,
    StaticReadOnlyRoot::kSharedFunctionInfoWrapperMap,
    StaticReadOnlyRoot::kTrustedForeignMap,
    StaticReadOnlyRoot::kSeqTwoByteStringMap,
    StaticReadOnlyRoot::kConsTwoByteStringMap,
    StaticReadOnlyRoot::kConsOneByteStringMap,
    StaticReadOnlyRoot::kThinTwoByteStringMap,
    StaticReadOnlyRoot::kThinOneByteStringMap,
    StaticReadOnlyRoot::kSlicedTwoByteStringMap,
    StaticReadOnlyRoot::kSlicedOneByteStringMap,
    StaticReadOnlyRoot::kExternalTwoByteStringMap,
    StaticReadOnlyRoot::kExternalOneByteStringMap,
    StaticReadOnlyRoot::kInternalizedTwoByteStringMap,
    StaticReadOnlyRoot::kExternalInternalizedTwoByteStringMap,
    StaticReadOnlyRoot::kExternalInternalizedOneByteStringMap,
    StaticReadOnlyRoot::kUncachedExternalInternalizedTwoByteStringMap,
    StaticReadOnlyRoot::kUncachedExternalInternalizedOneByteStringMap,
    StaticReadOnlyRoot::kUncachedExternalTwoByteStringMap,
    StaticReadOnlyRoot::kUncachedExternalOneByteStringMap,
    StaticReadOnlyRoot::kSharedSeqOneByteStringMap,
    StaticReadOnlyRoot::kSharedSeqTwoByteStringMap,
    StaticReadOnlyRoot::kSharedExternalOneByteStringMap,
    StaticReadOnlyRoot::kSharedExternalTwoByteStringMap,
    StaticReadOnlyRoot::kSharedUncachedExternalOneByteStringMap,
    StaticReadOnlyRoot::kSharedUncachedExternalTwoByteStringMap,
    StaticReadOnlyRoot::kUndefinedMap,
    StaticReadOnlyRoot::kNullMap,
    StaticReadOnlyRoot::kBooleanMap,
    StaticReadOnlyRoot::kHoleMap,
    StaticReadOnlyRoot::kJSSharedArrayMap,
    StaticReadOnlyRoot::kJSAtomicsMutexMap,
    StaticReadOnlyRoot::kJSAtomicsConditionMap,
    StaticReadOnlyRoot::kEmptyEnumCache,
    StaticReadOnlyRoot::kEmptyPropertyArray,
    StaticReadOnlyRoot::kEmptyByteArray,
    StaticReadOnlyRoot::kEmptyObjectBoilerplateDescription,
    StaticReadOnlyRoot::kEmptyArrayBoilerplateDescription,
    StaticReadOnlyRoot::kEmptyClosureFeedbackCellArray,
    StaticReadOnlyRoot::kEmptySlowElementDictionary,
    StaticReadOnlyRoot::kEmptyOrderedHashMap,
    StaticReadOnlyRoot::kEmptyOrderedHashSet,
    StaticReadOnlyRoot::kEmptyFeedbackMetadata,
    StaticReadOnlyRoot::kEmptyPropertyDictionary,
    StaticReadOnlyRoot::kEmptyOrderedPropertyDictionary,
    StaticReadOnlyRoot::kEmptySwissPropertyDictionary,
    StaticReadOnlyRoot::kNoOpInterceptorInfo,
    StaticReadOnlyRoot::kEmptyArrayList,
    StaticReadOnlyRoot::kEmptyWeakFixedArray,
    StaticReadOnlyRoot::kEmptyWeakArrayList,
    StaticReadOnlyRoot::kInvalidPrototypeValidityCell,
    StaticReadOnlyRoot::kNanValue,
    StaticReadOnlyRoot::kHoleNanValue,
    StaticReadOnlyRoot::kInfinityValue,
    StaticReadOnlyRoot::kMinusZeroValue,
    StaticReadOnlyRoot::kMinusInfinityValue,
    StaticReadOnlyRoot::kMaxSafeInteger,
    StaticReadOnlyRoot::kMaxUInt32,
    StaticReadOnlyRoot::kSmiMinValue,
    StaticReadOnlyRoot::kSmiMaxValuePlusOne,
    StaticReadOnlyRoot::kSingleCharacterStringTable,
    StaticReadOnlyRoot::kSelfReferenceMarker,
    StaticReadOnlyRoot::kBasicBlockCountersMarker,
    StaticReadOnlyRoot::kGlobalThisBindingScopeInfo,
    StaticReadOnlyRoot::kEmptyFunctionScopeInfo,
    StaticReadOnlyRoot::kNativeScopeInfo,
    StaticReadOnlyRoot::kShadowRealmScopeInfo,
    StaticReadOnlyRoot::kEmptySymbolTable,
    StaticReadOnlyRoot::kHashSeed,
    StaticReadOnlyRoot::kWasmNullPadding,
    StaticReadOnlyRoot::kWasmNull,
    StaticReadOnlyRoot::klength_string,
    StaticReadOnlyRoot::kprototype_string,
    StaticReadOnlyRoot::kname_string,
    StaticReadOnlyRoot::kenumerable_string,
    StaticReadOnlyRoot::kconfigurable_string,
    StaticReadOnlyRoot::kvalue_string,
    StaticReadOnlyRoot::kwritable_string,
    StaticReadOnlyRoot::kadoptText_string,
    StaticReadOnlyRoot::kapproximatelySign_string,
    StaticReadOnlyRoot::kbaseName_string,
    StaticReadOnlyRoot::kaccounting_string,
    StaticReadOnlyRoot::kbreakType_string,
    StaticReadOnlyRoot::kcalendars_string,
    StaticReadOnlyRoot::kcardinal_string,
    StaticReadOnlyRoot::kcaseFirst_string,
    StaticReadOnlyRoot::kceil_string,
    StaticReadOnlyRoot::kcompare_string,
    StaticReadOnlyRoot::kcollation_string,
    StaticReadOnlyRoot::kcollations_string,
    StaticReadOnlyRoot::kcompact_string,
    StaticReadOnlyRoot::kcompactDisplay_string,
    StaticReadOnlyRoot::kcurrency_string,
    StaticReadOnlyRoot::kcurrencyDisplay_string,
    StaticReadOnlyRoot::kcurrencySign_string,
    StaticReadOnlyRoot::kdateStyle_string,
    StaticReadOnlyRoot::kdateTimeField_string,
    StaticReadOnlyRoot::kdayPeriod_string,
    StaticReadOnlyRoot::kdaysDisplay_string,
    StaticReadOnlyRoot::kdecimal_string,
    StaticReadOnlyRoot::kdialect_string,
    StaticReadOnlyRoot::kdigital_string,
    StaticReadOnlyRoot::kdirection_string,
    StaticReadOnlyRoot::kendRange_string,
    StaticReadOnlyRoot::kengineering_string,
    StaticReadOnlyRoot::kexceptZero_string,
    StaticReadOnlyRoot::kexpand_string,
    StaticReadOnlyRoot::kexponentInteger_string,
    StaticReadOnlyRoot::kexponentMinusSign_string,
    StaticReadOnlyRoot::kexponentSeparator_string,
    StaticReadOnlyRoot::kfallback_string,
    StaticReadOnlyRoot::kfirst_string,
    StaticReadOnlyRoot::kfirstDay_string,
    StaticReadOnlyRoot::kfirstDayOfWeek_string,
    StaticReadOnlyRoot::kfloor_string,
    StaticReadOnlyRoot::kformat_string,
    StaticReadOnlyRoot::kfraction_string,
    StaticReadOnlyRoot::kfractionalDigits_string,
    StaticReadOnlyRoot::kfractionalSecond_string,
    StaticReadOnlyRoot::kfull_string,
    StaticReadOnlyRoot::kgranularity_string,
    StaticReadOnlyRoot::kgrapheme_string,
    StaticReadOnlyRoot::kgroup_string,
    StaticReadOnlyRoot::kh11_string,
    StaticReadOnlyRoot::kh12_string,
    StaticReadOnlyRoot::kh23_string,
    StaticReadOnlyRoot::kh24_string,
    StaticReadOnlyRoot::khalfCeil_string,
    StaticReadOnlyRoot::khalfEven_string,
    StaticReadOnlyRoot::khalfExpand_string,
    StaticReadOnlyRoot::khalfFloor_string,
    StaticReadOnlyRoot::khalfTrunc_string,
    StaticReadOnlyRoot::khour12_string,
    StaticReadOnlyRoot::khourCycle_string,
    StaticReadOnlyRoot::khourCycles_string,
    StaticReadOnlyRoot::khoursDisplay_string,
    StaticReadOnlyRoot::kideo_string,
    StaticReadOnlyRoot::kignorePunctuation_string,
    StaticReadOnlyRoot::kInvalid_Date_string,
    StaticReadOnlyRoot::kinteger_string,
    StaticReadOnlyRoot::kisWordLike_string,
    StaticReadOnlyRoot::kkana_string,
    StaticReadOnlyRoot::klanguage_string,
    StaticReadOnlyRoot::klanguageDisplay_string,
    StaticReadOnlyRoot::klessPrecision_string,
    StaticReadOnlyRoot::kletter_string,
    StaticReadOnlyRoot::klist_string,
    StaticReadOnlyRoot::kliteral_string,
    StaticReadOnlyRoot::klocale_string,
    StaticReadOnlyRoot::kloose_string,
    StaticReadOnlyRoot::klower_string,
    StaticReadOnlyRoot::kltr_string,
    StaticReadOnlyRoot::kmaximumFractionDigits_string,
    StaticReadOnlyRoot::kmaximumSignificantDigits_string,
    StaticReadOnlyRoot::kmicrosecondsDisplay_string,
    StaticReadOnlyRoot::kmillisecondsDisplay_string,
    StaticReadOnlyRoot::kmin2_string,
    StaticReadOnlyRoot::kminimalDays_string,
    StaticReadOnlyRoot::kminimumFractionDigits_string,
    StaticReadOnlyRoot::kminimumIntegerDigits_string,
    StaticReadOnlyRoot::kminimumSignificantDigits_string,
    StaticReadOnlyRoot::kminus_0,
    StaticReadOnlyRoot::kminusSign_string,
    StaticReadOnlyRoot::kminutesDisplay_string,
    StaticReadOnlyRoot::kmonthsDisplay_string,
    StaticReadOnlyRoot::kmorePrecision_string,
    StaticReadOnlyRoot::knan_string,
    StaticReadOnlyRoot::knanosecondsDisplay_string,
    StaticReadOnlyRoot::knarrowSymbol_string,
    StaticReadOnlyRoot::knegative_string,
    StaticReadOnlyRoot::knever_string,
    StaticReadOnlyRoot::knone_string,
    StaticReadOnlyRoot::knotation_string,
    StaticReadOnlyRoot::knormal_string,
    StaticReadOnlyRoot::knumberingSystem_string,
    StaticReadOnlyRoot::knumberingSystems_string,
    StaticReadOnlyRoot::knumeric_string,
    StaticReadOnlyRoot::kordinal_string,
    StaticReadOnlyRoot::kpercentSign_string,
    StaticReadOnlyRoot::kplusSign_string,
    StaticReadOnlyRoot::kquarter_string,
    StaticReadOnlyRoot::kregion_string,
    StaticReadOnlyRoot::krelatedYear_string,
    StaticReadOnlyRoot::kroundingMode_string,
    StaticReadOnlyRoot::kroundingPriority_string,
    StaticReadOnlyRoot::krtl_string,
    StaticReadOnlyRoot::kscientific_string,
    StaticReadOnlyRoot::ksecondsDisplay_string,
    StaticReadOnlyRoot::ksegment_string,
    StaticReadOnlyRoot::kSegmentIterator_string,
    StaticReadOnlyRoot::kSegments_string,
    StaticReadOnlyRoot::ksensitivity_string,
    StaticReadOnlyRoot::ksep_string,
    StaticReadOnlyRoot::kshared_string,
    StaticReadOnlyRoot::ksignDisplay_string,
    StaticReadOnlyRoot::kstandard_string,
    StaticReadOnlyRoot::kstartRange_string,
    StaticReadOnlyRoot::kstrict_string,
    StaticReadOnlyRoot::kstripIfInteger_string,
    StaticReadOnlyRoot::kstyle_string,
    StaticReadOnlyRoot::kterm_string,
    StaticReadOnlyRoot::ktextInfo_string,
    StaticReadOnlyRoot::ktimeStyle_string,
    StaticReadOnlyRoot::ktimeZones_string,
    StaticReadOnlyRoot::ktimeZoneName_string,
    StaticReadOnlyRoot::ktrailingZeroDisplay_string,
    StaticReadOnlyRoot::ktrunc_string,
    StaticReadOnlyRoot::ktwo_digit_string,
    StaticReadOnlyRoot::ktype_string,
    StaticReadOnlyRoot::kunknown_string,
    StaticReadOnlyRoot::kupper_string,
    StaticReadOnlyRoot::kusage_string,
    StaticReadOnlyRoot::kuseGrouping_string,
    StaticReadOnlyRoot::kunitDisplay_string,
    StaticReadOnlyRoot::kweekday_string,
    StaticReadOnlyRoot::kweekend_string,
    StaticReadOnlyRoot::kweeksDisplay_string,
    StaticReadOnlyRoot::kweekInfo_string,
    StaticReadOnlyRoot::kyearName_string,
    StaticReadOnlyRoot::kyearsDisplay_string,
    StaticReadOnlyRoot::kadd_string,
    StaticReadOnlyRoot::kAggregateError_string,
    StaticReadOnlyRoot::kalways_string,
    StaticReadOnlyRoot::kanonymous_string,
    StaticReadOnlyRoot::kapply_string,
    StaticReadOnlyRoot::kArguments_string,
    StaticReadOnlyRoot::karguments_string,
    StaticReadOnlyRoot::karguments_to_string,
    StaticReadOnlyRoot::kArray_string,
    StaticReadOnlyRoot::karray_to_string,
    StaticReadOnlyRoot::kArrayBuffer_string,
    StaticReadOnlyRoot::kArrayIterator_string,
    StaticReadOnlyRoot::kas_string,
    StaticReadOnlyRoot::kassert_string,
    StaticReadOnlyRoot::kasync_string,
    StaticReadOnlyRoot::kAtomicsCondition_string,
    StaticReadOnlyRoot::kAtomicsMutex_string,
    StaticReadOnlyRoot::kauto_string,
    StaticReadOnlyRoot::kBigInt_string,
    StaticReadOnlyRoot::kbigint_string,
    StaticReadOnlyRoot::kBigInt64Array_string,
    StaticReadOnlyRoot::kBigUint64Array_string,
    StaticReadOnlyRoot::kbind_string,
    StaticReadOnlyRoot::kblank_string,
    StaticReadOnlyRoot::kBoolean_string,
    StaticReadOnlyRoot::kboolean_string,
    StaticReadOnlyRoot::kboolean_to_string,
    StaticReadOnlyRoot::kbound__string,
    StaticReadOnlyRoot::kbuffer_string,
    StaticReadOnlyRoot::kbyte_length_string,
    StaticReadOnlyRoot::kbyte_offset_string,
    StaticReadOnlyRoot::kCompileError_string,
    StaticReadOnlyRoot::kcalendar_string,
    StaticReadOnlyRoot::kcallee_string,
    StaticReadOnlyRoot::kcaller_string,
    StaticReadOnlyRoot::kcause_string,
    StaticReadOnlyRoot::kcharacter_string,
    StaticReadOnlyRoot::kcode_string,
    StaticReadOnlyRoot::kcolumn_string,
    StaticReadOnlyRoot::kcomputed_string,
    StaticReadOnlyRoot::kconjunction_string,
    StaticReadOnlyRoot::kconsole_string,
    StaticReadOnlyRoot::kconstrain_string,
    StaticReadOnlyRoot::kconstruct_string,
    StaticReadOnlyRoot::kcurrent_string,
    StaticReadOnlyRoot::kDate_string,
    StaticReadOnlyRoot::kdate_to_string,
    StaticReadOnlyRoot::kdateAdd_string,
    StaticReadOnlyRoot::kdateFromFields_string,
    StaticReadOnlyRoot::kdateUntil_string,
    StaticReadOnlyRoot::kday_string,
    StaticReadOnlyRoot::kdayOfWeek_string,
    StaticReadOnlyRoot::kdayOfYear_string,
    StaticReadOnlyRoot::kdays_string,
    StaticReadOnlyRoot::kdaysInMonth_string,
    StaticReadOnlyRoot::kdaysInWeek_string,
    StaticReadOnlyRoot::kdaysInYear_string,
    StaticReadOnlyRoot::kdefault_string,
    StaticReadOnlyRoot::kdefineProperty_string,
    StaticReadOnlyRoot::kdeleteProperty_string,
    StaticReadOnlyRoot::kdetached_string,
    StaticReadOnlyRoot::kdisjunction_string,
    StaticReadOnlyRoot::kdisposed_string,
    StaticReadOnlyRoot::kdone_string,
    StaticReadOnlyRoot::kdot_brand_string,
    StaticReadOnlyRoot::kdot_catch_string,
    StaticReadOnlyRoot::kdot_default_string,
    StaticReadOnlyRoot::kdot_for_string,
    StaticReadOnlyRoot::kdot_generator_object_string,
    StaticReadOnlyRoot::kdot_home_object_string,
    StaticReadOnlyRoot::kdot_new_target_string,
    StaticReadOnlyRoot::kdot_result_string,
    StaticReadOnlyRoot::kdot_repl_result_string,
    StaticReadOnlyRoot::kdot_static_home_object_string,
    StaticReadOnlyRoot::kdot_string,
    StaticReadOnlyRoot::kdot_switch_tag_string,
    StaticReadOnlyRoot::kdotAll_string,
    StaticReadOnlyRoot::kError_string,
    StaticReadOnlyRoot::kEvalError_string,
    StaticReadOnlyRoot::kelement_string,
    StaticReadOnlyRoot::kepochMicroseconds_string,
    StaticReadOnlyRoot::kepochMilliseconds_string,
    StaticReadOnlyRoot::kepochNanoseconds_string,
    StaticReadOnlyRoot::kepochSeconds_string,
    StaticReadOnlyRoot::kera_string,
    StaticReadOnlyRoot::keraYear_string,
    StaticReadOnlyRoot::kerror_string,
    StaticReadOnlyRoot::kerrors_string,
    StaticReadOnlyRoot::kerror_to_string,
    StaticReadOnlyRoot::keval_string,
    StaticReadOnlyRoot::kexception_string,
    StaticReadOnlyRoot::kexec_string,
    StaticReadOnlyRoot::kfalse_string,
    StaticReadOnlyRoot::kfields_string,
    StaticReadOnlyRoot::kFinalizationRegistry_string,
    StaticReadOnlyRoot::kflags_string,
    StaticReadOnlyRoot::kFloat16Array_string,
    StaticReadOnlyRoot::kFloat32Array_string,
    StaticReadOnlyRoot::kFloat64Array_string,
    StaticReadOnlyRoot::kfractionalSecondDigits_string,
    StaticReadOnlyRoot::kfrom_string,
    StaticReadOnlyRoot::kFunction_string,
    StaticReadOnlyRoot::kfunction_native_code_string,
    StaticReadOnlyRoot::kfunction_string,
    StaticReadOnlyRoot::kfunction_to_string,
    StaticReadOnlyRoot::kGenerator_string,
    StaticReadOnlyRoot::kget_space_string,
    StaticReadOnlyRoot::kget_string,
    StaticReadOnlyRoot::kgetOffsetNanosecondsFor_string,
    StaticReadOnlyRoot::kgetOwnPropertyDescriptor_string,
    StaticReadOnlyRoot::kgetPossibleInstantsFor_string,
    StaticReadOnlyRoot::kgetPrototypeOf_string,
    StaticReadOnlyRoot::kglobal_string,
    StaticReadOnlyRoot::kglobalThis_string,
    StaticReadOnlyRoot::kgroups_string,
    StaticReadOnlyRoot::kgrowable_string,
    StaticReadOnlyRoot::khas_string,
    StaticReadOnlyRoot::khasIndices_string,
    StaticReadOnlyRoot::khour_string,
    StaticReadOnlyRoot::khours_string,
    StaticReadOnlyRoot::khoursInDay_string,
    StaticReadOnlyRoot::kignoreCase_string,
    StaticReadOnlyRoot::kid_string,
    StaticReadOnlyRoot::killegal_access_string,
    StaticReadOnlyRoot::killegal_argument_string,
    StaticReadOnlyRoot::kinLeapYear_string,
    StaticReadOnlyRoot::kindex_string,
    StaticReadOnlyRoot::kindices_string,
    StaticReadOnlyRoot::kInfinity_string,
    StaticReadOnlyRoot::kinfinity_string,
    StaticReadOnlyRoot::kinput_string,
    StaticReadOnlyRoot::kinstance_members_initializer_string,
    StaticReadOnlyRoot::kInt16Array_string,
    StaticReadOnlyRoot::kInt32Array_string,
    StaticReadOnlyRoot::kInt8Array_string,
    StaticReadOnlyRoot::kisExtensible_string,
    StaticReadOnlyRoot::kiso8601_string,
    StaticReadOnlyRoot::kisoDay_strin
```
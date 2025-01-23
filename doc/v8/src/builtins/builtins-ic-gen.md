Response: Let's break down the thought process for analyzing this C++ code snippet.

1. **Identify the Core Purpose:**  The filename `builtins-ic-gen.cc` immediately suggests it's related to "builtins" and "IC generation."  "IC" likely stands for Inline Cache, a common optimization technique in dynamic languages. Therefore, the file's core purpose is probably about generating built-in code related to inline caching.

2. **Scan for Keywords and Patterns:**  Quickly scan the code for recurring keywords and patterns. Notice the repeated use of:
    * `Builtins::Generate_...`
    * `compiler::CodeAssemblerState* state`
    * `AccessorAssembler assembler(state);`
    * `assembler.Generate...()`

3. **Analyze Function Names:**  The function names are very descriptive. They follow a pattern: `Generate_<Operation>IC_<Modifier>`. This tells us a lot about the specific operations being handled:
    * **`<Operation>`:** `Load`, `Store`, `DefineNamedOwn`, `DefineKeyedOwn`, `CloneObject`, `KeyedHas`, `LoadGlobal`, `LookupGlobal`, `LookupContext`, `StoreInArrayLiteral`. These are common JavaScript operations related to accessing and modifying object properties.
    * **`IC`:** Confirms the connection to Inline Caches.
    * **`<Modifier>`:**
        * `Megamorphic`: Handles cases where an object has many different shapes/types for a given property.
        * `Noninlined`:  Suggests a version of the IC that's not inlined for some reason (e.g., debugging, less frequently executed code).
        * `NoFeedback`:  Indicates the IC doesn't use feedback from past executions to optimize.
        * `Trampoline`: Often a small piece of code that jumps to the actual implementation, potentially used for lazy initialization or redirection.
        * `Baseline`:  A simpler, less optimized version of the IC, often used initially.
        * `Super`: Deals with accessing properties in the prototype chain.
        * `Keyed`: Refers to accessing properties using bracket notation (e.g., `obj[key]`).
        * `EnumeratedKeyed`: Specific to iterating over object properties.
        * `PolymorphicName`:  Similar to Megamorphic, but might focus on the *name* of the property being accessed.
        * `InsideTypeof`: Handles the specific case where the `typeof` operator is used.

4. **Connect to `AccessorAssembler`:** The `AccessorAssembler` class is instantiated in each function. This strongly suggests that this class is responsible for the low-level code generation logic for the ICs. It likely contains methods corresponding to the `Generate...()` calls within each `Builtins::Generate_...` function.

5. **Infer the Overall Functionality:** Based on the function names and the use of `AccessorAssembler`, we can deduce that this file is responsible for *generating* the built-in code that V8 uses to efficiently access and modify JavaScript object properties. It handles different scenarios and optimization levels.

6. **Relate to JavaScript:** Now, consider how these ICs relate to JavaScript code. Every time you access a property of an object in JavaScript, one of these ICs might be involved. Think about the different ways you access properties:
    * `object.property` (Named load/store)
    * `object['property']` or `object[variable]` (Keyed load/store)
    * Accessing properties in the prototype chain.
    * Using `super`.
    * Defining new properties.

7. **Construct JavaScript Examples:**  Create simple JavaScript examples that demonstrate the different scenarios implied by the C++ function names. This helps solidify the connection between the low-level C++ code and the high-level JavaScript behavior. Focus on showing the *variety* of property access patterns.

8. **Refine the Explanation:** Organize the findings into a clear and concise summary. Start with the main purpose of the file, then elaborate on the different types of ICs and their modifiers. Finally, provide the JavaScript examples to illustrate the concepts. Use terminology that is understandable to someone familiar with JavaScript, even if they don't know C++.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file *executes* the ICs. **Correction:** The `Generate_` prefix strongly implies code generation, not execution.
* **Confusion about `Trampoline`:**  Initially, I might not be sure what a "trampoline" is. **Solution:**  A quick search or prior knowledge about compiler techniques would clarify this.
* **Overly technical explanation:**  Initially, I might include too much low-level detail about `AccessorAssembler`. **Correction:** Focus on the *functional* purpose and its relation to JavaScript, keeping the C++ details at a high level.

By following these steps, we can systematically analyze the C++ code and arrive at a comprehensive understanding of its functionality and its connection to JavaScript.
这个C++源代码文件 `v8/src/builtins/builtins-ic-gen.cc` 的主要功能是 **生成（Generate）V8 JavaScript 引擎中用于优化属性访问（Property Access）的内建函数（Builtins），特别是与 Inline Caches (ICs) 相关的部分。**

更具体地说，它定义了一系列 `Builtins::Generate_...` 函数，这些函数负责生成不同类型的 **Inline Cache (IC)** 代码。IC 是 V8 引擎中一种关键的优化技术，用于加速对象属性的读取、写入和方法调用等操作。

**以下是这个文件涉及的主要功能模块：**

1. **LoadIC (加载属性 IC):**  用于优化对象属性的读取操作。
   - `LoadIC`:  基本的加载 IC。
   - `LoadIC_Megamorphic`:  处理对象属性访问模式非常多样（多态性很高）的情况。
   - `LoadIC_Noninlined`:  非内联的加载 IC。
   - `LoadIC_NoFeedback`:  不依赖反馈信息的加载 IC。
   - `LoadICTrampoline`:  加载 IC 的跳板，用于延迟或间接执行。
   - `LoadICBaseline`:  加载 IC 的基线版本，通常是性能较差但逻辑简单的版本。
   - `LoadICTrampoline_Megamorphic`:  多态加载 IC 的跳板。
   - `LoadSuperIC`:  用于访问父类（super）的属性。
   - `LoadSuperICBaseline`:  访问父类属性的基线版本。
   - `KeyedLoadIC`:  通过键（例如字符串或 Symbol）访问属性。
   - `EnumeratedKeyedLoadIC`:  用于枚举对象属性时的键加载。
   - 其他 `KeyedLoadIC` 的变种，如 `Megamorphic`, `PolymorphicName`, `Trampoline`, `Baseline` 等，针对不同的键加载场景进行优化。

2. **StoreIC (存储属性 IC):** 用于优化对象属性的写入操作。
   - `StoreIC`:  基本的存储 IC。
   - `StoreIC_Megamorphic`:  处理对象属性写入模式非常多样的情况。
   - `StoreICTrampoline`:  存储 IC 的跳板。
   - 其他 `StoreIC` 的变种，如 `Trampoline_Megamorphic`, `Baseline` 等。

3. **DefineNamedOwnIC / DefineKeyedOwnIC (定义自有属性 IC):** 用于优化对象上定义新属性的操作。
   - `DefineNamedOwnIC`:  定义命名属性。
   - `DefineKeyedOwnIC`:  定义键控属性。
   - 相关的 `Trampoline` 和 `Baseline` 版本。

4. **LoadGlobalIC / LookupGlobalIC (加载全局变量 IC):** 用于优化访问全局变量的操作。
   - `LoadGlobalIC`:  加载全局变量的值。
   - `LookupGlobalIC`:  查找全局变量。
   - 区分了 `TypeofMode`，用于处理 `typeof` 操作符。
   - 相关的 `Trampoline` 和 `Baseline` 版本。

5. **StoreGlobalIC (存储全局变量 IC):** 用于优化设置全局变量的操作。
   - 相关的 `Trampoline` 和 `Baseline` 版本。

6. **KeyedHasIC (键是否存在 IC):** 用于优化检查对象是否拥有某个键的操作（例如 `key in object`）。
   - 相关的 `Megamorphic`, `PolymorphicName`, `Baseline` 版本。

7. **LookupContextIC (查找上下文变量 IC):** 用于优化在作用域链中查找变量的操作。
   - 区分了 `ContextKind` (例如 ScriptContext)。
   - 区分了 `TypeofMode`。
   - 相关的 `Trampoline` 和 `Baseline` 版本。

8. **其他 IC:**
   - `StoreInArrayLiteralIC`:  优化数组字面量中的元素存储。
   - `CloneObjectIC`:  优化对象克隆操作。

**与 JavaScript 功能的关系及示例:**

这个文件生成的代码直接影响 JavaScript 代码的执行性能。每当 JavaScript 代码尝试访问或修改对象的属性时，V8 引擎会尝试使用这些优化的 IC 代码来执行操作，从而避免每次都进行完整的属性查找和处理。

**JavaScript 示例：**

```javascript
// 假设我们有以下 JavaScript 代码

const obj = { a: 1, b: 2 };
console.log(obj.a); // 读取属性 'a'
obj.c = 3;         // 写入属性 'c'
const key = 'b';
console.log(obj[key]); // 通过键读取属性
'a' in obj;         // 检查对象是否拥有属性 'a'

function Parent() {
  this.parentProp = 'parent';
}
function Child() {
  Parent.call(this);
  this.childProp = 'child';
}
Child.prototype = Object.create(Parent.prototype);
Child.prototype.constructor = Child;

const child = new Child();
console.log(child.parentProp); // 访问继承的属性 (可能涉及 LoadSuperIC)

globalThis.myGlobal = 10; // 设置全局变量 (涉及 StoreGlobalIC)
console.log(myGlobal);     // 读取全局变量 (涉及 LoadGlobalIC)

typeof someUndeclaredVariable; // 使用 typeof (可能涉及 LoadGlobalICInsideTypeof)
```

**这个 C++ 文件生成的代码，会在 V8 执行上述 JavaScript 代码时被调用。**

* 当执行 `console.log(obj.a);` 时，V8 可能会使用 `Generate_LoadIC` 生成的代码来快速查找和返回 `obj` 的属性 `a` 的值。如果后续多次访问 `obj.a`，IC 会变得更加专门化，以进一步提高性能。
* 当执行 `obj.c = 3;` 时，V8 可能会使用 `Generate_StoreIC` 生成的代码来快速设置 `obj` 的属性 `c` 的值。
* 当执行 `console.log(obj[key]);` 时，V8 可能会使用 `Generate_KeyedLoadIC` 生成的代码。
* 当执行 `'a' in obj;` 时，V8 可能会使用 `Generate_KeyedHasIC` 生成的代码。
* 当访问 `child.parentProp` 时，由于 `parentProp` 是继承的属性，V8 可能会使用 `Generate_LoadSuperIC` 相关的代码。
* 当操作全局变量 `myGlobal` 时，会涉及到 `Generate_StoreGlobalIC` 和 `Generate_LoadGlobalIC`。
* `typeof someUndeclaredVariable;`  会触发与 `Generate_LoadGlobalICInsideTypeof` 相关的逻辑。

**总结:**

`builtins-ic-gen.cc` 文件是 V8 引擎中至关重要的组成部分，它负责生成用于优化 JavaScript 属性访问的核心内建函数。通过针对不同的访问模式和场景生成特定的 IC 代码，V8 能够显著提高 JavaScript 代码的执行效率。`AccessorAssembler` 类是用于生成这些底层汇编代码的关键工具。 这些生成的内建函数直接服务于我们日常编写的 JavaScript 代码，使得属性访问等操作更加快速。

### 提示词
```
这是目录为v8/src/builtins/builtins-ic-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-utils-gen.h"
#include "src/builtins/builtins.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/ic/accessor-assembler.h"

namespace v8 {
namespace internal {

void Builtins::Generate_LoadIC(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLoadIC();
}
void Builtins::Generate_LoadIC_Megamorphic(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLoadIC_Megamorphic();
}
void Builtins::Generate_LoadIC_Noninlined(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLoadIC_Noninlined();
}
void Builtins::Generate_LoadIC_NoFeedback(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLoadIC_NoFeedback();
}
void Builtins::Generate_LoadICTrampoline(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLoadICTrampoline();
}
void Builtins::Generate_LoadICBaseline(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLoadICBaseline();
}
void Builtins::Generate_LoadICTrampoline_Megamorphic(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLoadICTrampoline_Megamorphic();
}
void Builtins::Generate_LoadSuperIC(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLoadSuperIC();
}
void Builtins::Generate_LoadSuperICBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLoadSuperICBaseline();
}
void Builtins::Generate_KeyedLoadIC(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateKeyedLoadIC();
}
void Builtins::Generate_EnumeratedKeyedLoadIC(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateEnumeratedKeyedLoadIC();
}
void Builtins::Generate_EnumeratedKeyedLoadICBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateEnumeratedKeyedLoadICBaseline();
}
void Builtins::Generate_KeyedLoadIC_Megamorphic(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateKeyedLoadIC_Megamorphic();
}
void Builtins::Generate_KeyedLoadIC_PolymorphicName(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateKeyedLoadIC_PolymorphicName();
}
void Builtins::Generate_KeyedLoadICTrampoline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateKeyedLoadICTrampoline();
}
void Builtins::Generate_KeyedLoadICBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateKeyedLoadICBaseline();
}
void Builtins::Generate_KeyedLoadICTrampoline_Megamorphic(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateKeyedLoadICTrampoline_Megamorphic();
}
void Builtins::Generate_LoadGlobalIC_NoFeedback(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLoadGlobalIC_NoFeedback();
}
void Builtins::Generate_StoreGlobalIC(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateStoreGlobalIC();
}
void Builtins::Generate_StoreGlobalICTrampoline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateStoreGlobalICTrampoline();
}
void Builtins::Generate_StoreGlobalICBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateStoreGlobalICBaseline();
}
void Builtins::Generate_StoreIC(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateStoreIC();
}
void Builtins::Generate_StoreIC_Megamorphic(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateStoreIC_Megamorphic();
}
void Builtins::Generate_StoreICTrampoline(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateStoreICTrampoline();
}
void Builtins::Generate_StoreICTrampoline_Megamorphic(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateStoreICTrampoline_Megamorphic();
}
void Builtins::Generate_StoreICBaseline(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateStoreICBaseline();
}
void Builtins::Generate_DefineNamedOwnIC(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateDefineNamedOwnIC();
}
void Builtins::Generate_DefineNamedOwnICTrampoline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateDefineNamedOwnICTrampoline();
}
void Builtins::Generate_DefineNamedOwnICBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateDefineNamedOwnICBaseline();
}
void Builtins::Generate_KeyedStoreIC(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateKeyedStoreIC();
}
void Builtins::Generate_KeyedStoreICTrampoline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateKeyedStoreICTrampoline();
}
void Builtins::Generate_KeyedStoreICTrampoline_Megamorphic(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateKeyedStoreICTrampoline_Megamorphic();
}
void Builtins::Generate_KeyedStoreICBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateKeyedStoreICBaseline();
}
void Builtins::Generate_DefineKeyedOwnIC(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateDefineKeyedOwnIC();
}
void Builtins::Generate_DefineKeyedOwnICTrampoline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateDefineKeyedOwnICTrampoline();
}
void Builtins::Generate_DefineKeyedOwnICBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateDefineKeyedOwnICBaseline();
}
void Builtins::Generate_StoreInArrayLiteralIC(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateStoreInArrayLiteralIC();
}
void Builtins::Generate_StoreInArrayLiteralICBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateStoreInArrayLiteralICBaseline();
}
void Builtins::Generate_CloneObjectIC(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateCloneObjectIC();
}
void Builtins::Generate_CloneObjectICBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateCloneObjectICBaseline();
}
void Builtins::Generate_CloneObjectIC_Slow(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateCloneObjectIC_Slow();
}
void Builtins::Generate_KeyedHasIC(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateKeyedHasIC();
}
void Builtins::Generate_KeyedHasICBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateKeyedHasICBaseline();
}
void Builtins::Generate_KeyedHasIC_Megamorphic(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateKeyedHasIC_Megamorphic();
}
void Builtins::Generate_KeyedHasIC_PolymorphicName(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateKeyedHasIC_PolymorphicName();
}

void Builtins::Generate_LoadGlobalIC(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLoadGlobalIC(TypeofMode::kNotInside);
}

void Builtins::Generate_LoadGlobalICInsideTypeof(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLoadGlobalIC(TypeofMode::kInside);
}

void Builtins::Generate_LoadGlobalICTrampoline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLoadGlobalICTrampoline(TypeofMode::kNotInside);
}

void Builtins::Generate_LoadGlobalICInsideTypeofTrampoline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLoadGlobalICTrampoline(TypeofMode::kInside);
}

void Builtins::Generate_LoadGlobalICBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLoadGlobalICBaseline(TypeofMode::kNotInside);
}

void Builtins::Generate_LoadGlobalICInsideTypeofBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLoadGlobalICBaseline(TypeofMode::kInside);
}

void Builtins::Generate_LookupGlobalIC(compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLookupGlobalIC(TypeofMode::kNotInside);
}

void Builtins::Generate_LookupGlobalICTrampoline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLookupGlobalICTrampoline(TypeofMode::kNotInside);
}

void Builtins::Generate_LookupGlobalICBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLookupGlobalICBaseline(TypeofMode::kNotInside);
}

void Builtins::Generate_LookupGlobalICInsideTypeof(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLookupGlobalIC(TypeofMode::kInside);
}

void Builtins::Generate_LookupGlobalICInsideTypeofTrampoline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLookupGlobalICTrampoline(TypeofMode::kInside);
}

void Builtins::Generate_LookupGlobalICInsideTypeofBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLookupGlobalICBaseline(TypeofMode::kInside);
}

void Builtins::Generate_LookupContextTrampoline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLookupContextTrampoline(TypeofMode::kNotInside,
                                            ContextKind::kDefault);
}

void Builtins::Generate_LookupScriptContextTrampoline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLookupContextTrampoline(TypeofMode::kNotInside,
                                            ContextKind::kScriptContext);
}

void Builtins::Generate_LookupContextBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLookupContextBaseline(TypeofMode::kNotInside,
                                          ContextKind::kDefault);
}

void Builtins::Generate_LookupScriptContextBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLookupContextBaseline(TypeofMode::kNotInside,
                                          ContextKind::kScriptContext);
}

void Builtins::Generate_LookupContextInsideTypeofTrampoline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLookupContextTrampoline(TypeofMode::kInside,
                                            ContextKind::kDefault);
}

void Builtins::Generate_LookupScriptContextInsideTypeofTrampoline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLookupContextTrampoline(TypeofMode::kInside,
                                            ContextKind::kScriptContext);
}

void Builtins::Generate_LookupContextInsideTypeofBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLookupContextBaseline(TypeofMode::kInside,
                                          ContextKind::kDefault);
}

void Builtins::Generate_LookupScriptContextInsideTypeofBaseline(
    compiler::CodeAssemblerState* state) {
  AccessorAssembler assembler(state);
  assembler.GenerateLookupContextBaseline(TypeofMode::kInside,
                                          ContextKind::kScriptContext);
}

}  // namespace internal
}  // namespace v8
```
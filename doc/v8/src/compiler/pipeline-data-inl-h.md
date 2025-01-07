Response:
Let's break down the thought process for analyzing the provided C++ header file and fulfilling the request.

1. **Initial Understanding of the Request:** The request asks for the functionality of the `v8/src/compiler/pipeline-data-inl.h` file, specifically within the context of the V8 JavaScript engine's compilation pipeline. Key points to address include:  Torque association, JavaScript relevance, code logic, and common programming errors.

2. **File Extension Check:** The request mentions the `.tq` extension and Torque. Immediately, I scan the filename and see `.h`. This is a standard C++ header file. Therefore, the file *is not* a Torque file. This becomes the first definitive piece of information.

3. **Purpose of Header Files:**  I know that `.h` files in C++ primarily serve to declare interfaces, classes, and inline functions. They provide the blueprints for code that will be implemented elsewhere (usually in a corresponding `.cc` file or directly within the header for `inline` functions).

4. **Analyzing the Includes:**  The `#include` directives are crucial for understanding dependencies and the general domain of the code. I start scanning these:
    * `<optional>`:  Standard C++ library for representing values that might be absent.
    * `"src/builtins/profile-data-reader.h"`:  Suggests interaction with built-in functions and performance profiling.
    * `"src/codegen/assembler.h"`, `"src/codegen/optimized-compilation-info.h"`: Clearly related to code generation within the compiler. `OptimizedCompilationInfo` is likely a central data structure holding information about the compilation process.
    * `"src/common/globals.h"`: Defines global settings and constants.
    * `"src/compiler/backend/...`:  A significant block of includes pointing to various backend components of the compiler: code generation, instruction selection, register allocation, and the representation of instructions.
    * `"src/compiler/..."`:  Includes related to the core compiler infrastructure: common operators, compilation dependencies, source position tracking, JavaScript-specific aspects (context specialization, heap broker, inlining, operators), the intermediate representation (`MachineGraph`), node management, pipeline statistics, scheduling, simplified operators, and the type system (`TurbofanTyper`). The inclusion of `turboshaft/phase.h` and `turboshaft/zone-with-name.h` indicates integration with the newer Turboshaft compiler.
    * `"src/execution/isolate.h"`: Represents the execution environment for JavaScript code.
    * `"src/handles/handles-inl.h"`, `"src/objects/objects-inl.h"`:  Deal with V8's object model and memory management.
    * `#if V8_ENABLE_WEBASSEMBLY ...`: Indicates support for WebAssembly compilation.

5. **High-Level Functionality Deduction:** Based on the includes, the file is clearly central to the **Turbofan compilation pipeline**. It appears to be a container for data and utilities needed throughout the various phases of compilation. The presence of includes related to both Turbofan and the newer Turboshaft suggests it's a point of interaction between the two.

6. **Analyzing the Code within the Header:**

    * **`GetModuleContext` function:** This function's logic is relatively straightforward. It walks up the context chain of a function to find the nearest module context. This is JavaScript-related as module contexts are a JavaScript concept. I can come up with a simple JavaScript example demonstrating module contexts.

    * **`TFPipelineData` Class:**  This is the core of the header. I analyze its members and methods:
        * **Constructors:** Multiple constructors indicate different entry points to the compilation pipeline (main JS compilation, WebAssembly, testing). The parameters to the constructors reveal the dependencies needed at the start of the pipeline.
        * **Member Variables:**  These store various data structures and objects needed during compilation: zones for memory management, the compilation info, graphs, operator builders, the heap broker, instruction sequences, register allocation data, etc. The `MaybeIndirectHandle<Code>` suggests that the output of the pipeline is machine code.
        * **Accessor Methods:**  Methods like `isolate()`, `info()`, `graph()`, etc., provide controlled access to the member variables.
        * **Initialization Methods:** Methods like `InitializeInstructionSequence`, `InitializeFrameData`, `InitializeRegisterAllocationData`, and `InitializeCodeGenerator` show the steps involved in setting up the data structures for later compilation phases.
        * **`CreateTyper`, `DeleteTyper`:** Indicate type analysis is a part of the pipeline.
        * **`BeginPhaseKind`, `EndPhaseKind`:**  Clearly for tracking compilation phases and performance analysis.
        * **`debug_name()`:** For debugging purposes.
        * The WebAssembly-related members (`wasm_module_for_inlining_`, `js_wasm_calls_sidetable_`) confirm its role in WebAssembly compilation.

7. **Connecting to JavaScript:**  The presence of `JSOperatorBuilder`, `JSGraph`, `JSHeapBroker`, and the `GetModuleContext` function directly link this file to the compilation of JavaScript code. I need to create JavaScript examples that demonstrate these concepts.

8. **Code Logic and Assumptions:** The `GetModuleContext` function has a clear logical flow. I can define input (a function with a certain context chain) and output (the module context and distance).

9. **Common Programming Errors (within the V8 context):**  Since this is internal V8 code, common *user* programming errors in JavaScript don't directly apply here. Instead, I need to think about errors that might occur during compiler development or in the interaction between compiler phases. Incorrectly managing the lifetime of objects within zones, accessing data before it's initialized, or violating assumptions about the structure of the intermediate representation are potential candidates.

10. **Structuring the Output:** I organize the information based on the request's points: functionality, Torque association, JavaScript examples, code logic, and common errors. I use clear headings and bullet points for readability.

11. **Refinement and Review:**  I reread the generated response and the original request to ensure all aspects are addressed accurately and comprehensively. I double-check the JavaScript examples and the assumptions in the code logic section. I make sure the explanation of common errors is relevant to the context of compiler development. For instance, initially, I might have thought about typical C++ errors like memory leaks, but the zone-based allocation system in V8 makes those less likely in this specific context, so I refine the error examples.
好的，让我们来分析一下 `v8/src/compiler/pipeline-data-inl.h` 这个V8源代码文件的功能。

**文件功能概述**

`v8/src/compiler/pipeline-data-inl.h` 是 V8 引擎中 Turbofan 优化编译管道的关键组成部分。它定义了一个名为 `TFPipelineData` 的类，这个类的主要作用是：

1. **作为编译管道中各个阶段共享数据的容器：**  它存储了在 Turbofan 编译的不同阶段之间传递和共享的各种数据和对象。这些数据包括：
    * **编译配置信息 (`OptimizedCompilationInfo`)**: 包含了待编译函数的各种信息，如函数句柄、上下文、优化级别等。
    * **内存分配器 (`AccountingAllocator`) 和区域 (`Zone`)**:  用于在编译过程中进行高效的内存管理。Turbofan 使用基于区域的内存管理，方便快速分配和释放内存。
    * **中间表示 (IR) 图 (`Graph`)**:  存储了函数的中间表示，这是 Turbofan 进行各种优化和转换的基础。
    * **操作符构建器 (`SimplifiedOperatorBuilder`, `MachineOperatorBuilder`, `CommonOperatorBuilder`, `JSOperatorBuilder`)**:  用于创建和操作 IR 图中的节点。
    * **JavaScript 图 (`JSGraph`)**:  一个方便的包装器，组合了 `Graph` 和各种操作符构建器，方便 JavaScript 特定的编译。
    * **调度器 (`Schedule`)**:  用于确定 IR 图中节点执行的顺序。
    * **指令序列 (`InstructionSequence`)**:  存储了选择出的机器指令序列。
    * **寄存器分配数据 (`RegisterAllocationData`)**:  存储了寄存器分配的结果。
    * **代码生成器 (`CodeGenerator`)**:  负责将指令序列转换为最终的机器码。
    * **类型推断器 (`Typer`)**:  用于进行类型分析。
    * **依赖关系 (`CompilationDependencies`)**:  跟踪编译过程中的依赖关系，用于实现增量编译和去优化。
    * **性能统计数据 (`TurbofanPipelineStatistics`)**:  用于收集编译管道各个阶段的性能数据。
    * **源代码位置信息 (`SourcePositionTable`, `NodeOriginTable`)**:  用于在生成的代码中保留源代码位置信息，方便调试和错误报告。
    * **其他辅助对象**: 如 OSR（On-Stack Replacement）助手、跳转优化信息等。

2. **提供访问和管理这些数据的方法：**  `TFPipelineData` 类提供了各种 getter 和 setter 方法，用于访问和修改其中存储的数据。

3. **管理编译管道中各个阶段的生命周期：**  它包含了用于初始化和清理各个阶段所需数据的方法，例如 `InitializeInstructionSequence`，`InitializeFrameData`，`DeleteGraphZone` 等。

4. **支持不同的编译入口点：**  该类提供了多个构造函数，以支持不同的编译场景，包括 JavaScript 函数的编译、WebAssembly 模块的编译以及测试目的的编译。

**关于文件扩展名和 Torque**

你提到如果 `v8/src/compiler/pipeline-data-inl.h` 以 `.tq` 结尾，那它就是 V8 Torque 源代码。这是正确的。

* **`.h` 结尾**: 表示这是一个 C++ 头文件。通常包含类声明、函数声明、宏定义和内联函数等。
* **`.tq` 结尾**: 表示这是一个 Torque 源代码文件。Torque 是 V8 自研的一种领域特定语言 (DSL)，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时函数。

**与 JavaScript 功能的关系及示例**

`v8/src/compiler/pipeline-data-inl.h` 中定义的 `TFPipelineData` 类是 Turbofan 编译器的核心数据结构，而 Turbofan 负责优化执行 JavaScript 代码。因此，这个文件与 JavaScript 功能有着非常直接和密切的关系。

以下是一些与 JavaScript 功能相关的方面，并用 JavaScript 举例说明：

1. **上下文 (Context) 和作用域 (Scope)**:
   - `GetModuleContext` 函数用于获取模块上下文。JavaScript 中的模块有自己的作用域。
   ```javascript
   // 这是一个模块
   const message = 'Hello from module';
   export function greet() {
     console.log(message);
   }
   ```
   在 V8 编译这个模块时，`GetModuleContext` 帮助确定当前代码所在的模块作用域。

2. **内联 (Inlining)**:
   - 类中包含 `JSInlining` 相关的头文件。Turbofan 会尝试将一些小的、频繁调用的函数内联到调用点，以减少函数调用开销。
   ```javascript
   function add(a, b) {
     return a + b;
   }

   function calculate(x) {
     const y = 5;
     return add(x, y) * 2; // Turbofan 可能会将 add 函数内联到这里
   }
   ```

3. **类型推断 (Type Inference)**:
   - 类中使用了 `TurbofanTyper`。Turbofan 会尝试推断变量的类型，以便进行更有效的优化。
   ```javascript
   function process(input) {
     if (typeof input === 'number') {
       return input * 2; // Turbofan 可以推断 input 在这里是数字
     } else {
       return input.toUpperCase();
     }
   }
   ```

4. **优化代码生成**:
   - 类中包含了与代码生成、指令选择和寄存器分配相关的组件。Turbofan 的目标是生成尽可能高效的机器码来执行 JavaScript。
   ```javascript
   function loopSum(n) {
     let sum = 0;
     for (let i = 0; i < n; i++) {
       sum += i;
     }
     return sum;
   }
   ```
   Turbofan 会分析这个循环，并尝试进行循环展开、向量化等优化，最终生成高效的机器码。

**代码逻辑推理及示例**

`GetModuleContext` 函数提供了一个简单的代码逻辑推理示例。

**假设输入:** 一个 `OptimizedCompilationInfo` 对象 `info`，其中 `info->closure()->context()` 指向一个嵌套的上下文链，例如：

```
GlobalContext -> FunctionContext1 -> FunctionContext2 -> ModuleContext
```

**输出:** `Just(OuterContext(CanonicalHandle(ModuleContext), 2))`

**推理过程:**

1. `current` 初始化为 `info->closure()->context()`，指向 `FunctionContext2`。
2. `distance` 初始化为 `0`。
3. 进入 `while` 循环，判断 `current` 是否为 NativeContext，不是。
4. 判断 `current` 是否为 ModuleContext，不是。
5. `current` 更新为 `current->previous()`，指向 `FunctionContext1`。
6. `distance` 增加为 `1`。
7. 循环继续，`current` 更新为 `GlobalContext`，`distance` 增加为 `2`。
8. 循环继续，`current` 更新为 `NativeContext` (假设 `GlobalContext` 的 `previous` 是 `NativeContext`)。
9. 循环退出，因为 `IsNativeContext(*current)` 为真。
10. 函数返回 `Nothing<OuterContext>()`  **<-- 这里是之前的理解有误，需要修正**

**修正后的推理过程:**

**假设输入:** 一个 `OptimizedCompilationInfo` 对象 `info`，其中 `info->closure()->context()` 指向一个嵌套的上下文链，例如：

```
GlobalContext -> FunctionContext1 -> ModuleContext -> FunctionContext2
```

**输出:** `Just(OuterContext(CanonicalHandle(ModuleContext), 1))`

**推理过程:**

1. `current` 初始化为 `info->closure()->context()`，指向 `FunctionContext2`。
2. `distance` 初始化为 `0`。
3. 进入 `while` 循环，判断 `current` 是否为 NativeContext，不是。
4. 判断 `current` 是否为 ModuleContext，不是。
5. `current` 更新为 `current->previous()`，指向 `ModuleContext`。
6. `distance` 增加为 `1`。
7. 再次进入 `while` 循环，判断 `current` 是否为 NativeContext，不是。
8. 判断 `current` 是否为 ModuleContext，是。
9. 返回 `Just(OuterContext(info->CanonicalHandle(current, current->GetIsolate()), distance))`，其中 `current` 指向 `ModuleContext`，`distance` 为 `1`。

**涉及用户常见的编程错误**

虽然 `v8/src/compiler/pipeline-data-inl.h` 是 V8 内部代码，但理解其背后的概念可以帮助我们避免一些常见的 JavaScript 编程错误，这些错误可能会导致性能下降，从而触发 V8 的优化管道。

1. **过度依赖动态类型:**
   - 如果 JavaScript 代码中的变量类型不稳定，频繁在不同类型之间切换，Turbofan 的类型推断就会变得困难，可能导致优化失效。
   ```javascript
   let counter = 0;
   for (let i = 0; i < 100; i++) {
     if (i % 2 === 0) {
       counter += i; // counter 是 number
     } else {
       counter = "not a number"; // counter 变成了 string
     }
   }
   ```
   这种代码会让 Turbofan 难以优化关于 `counter` 的操作。

2. **隐藏类的变化:**
   - V8 依赖于对象的“隐藏类” (hidden class) 进行优化。如果对象的属性结构在运行时发生变化，会导致隐藏类频繁更新，影响性能。
   ```javascript
   function Point(x, y) {
     this.x = x;
     this.y = y;
   }

   const p1 = new Point(1, 2);
   const p2 = new Point(3, 4);
   p2.z = 5; // 在 p2 上添加了新属性，导致 p1 和 p2 的隐藏类不同
   ```
   保持对象结构的稳定有助于 V8 的优化。

3. **函数中的控制流过于复杂:**
   - 包含大量条件分支、循环和异常处理的函数，会使 Turbofan 的分析和优化变得困难。
   ```javascript
   function complexLogic(input) {
     if (typeof input === 'number') {
       // ... 大量数字处理逻辑 ...
       for (let i = 0; i < 1000; i++) {
         // ...
       }
     } else if (typeof input === 'string') {
       // ... 大量字符串处理逻辑 ...
       try {
         // ...
       } catch (e) {
         // ...
       }
     } else {
       // ...
     }
     return result;
   }
   ```
   将复杂的函数拆分成更小的、职责单一的函数，有助于优化。

4. **未优化的内置方法使用:**
   - 虽然 V8 会优化内置方法，但某些使用方式可能仍然不够高效。例如，在循环中频繁操作 DOM，或者使用低效的字符串拼接方式。

了解 V8 编译管道的工作原理，可以帮助开发者编写更易于优化的 JavaScript 代码，从而提升应用程序的性能。`v8/src/compiler/pipeline-data-inl.h` 虽然是内部实现细节，但它所承载的数据和逻辑是理解 V8 如何优化 JavaScript 的关键。

Prompt: 
```
这是目录为v8/src/compiler/pipeline-data-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/pipeline-data-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_PIPELINE_DATA_INL_H_
#define V8_COMPILER_PIPELINE_DATA_INL_H_

#include <optional>

#include "src/builtins/profile-data-reader.h"
#include "src/codegen/assembler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/common/globals.h"
#include "src/compiler/backend/code-generator.h"
#include "src/compiler/backend/instruction-selector.h"
#include "src/compiler/backend/instruction.h"
#include "src/compiler/backend/register-allocator.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/js-context-specialization.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/js-inlining.h"
#include "src/compiler/js-operator.h"
#include "src/compiler/machine-graph.h"
#include "src/compiler/machine-operator.h"
#include "src/compiler/node-observer.h"
#include "src/compiler/node-origin-table.h"
#include "src/compiler/phase.h"
#include "src/compiler/pipeline-statistics.h"
#include "src/compiler/schedule.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/turbofan-typer.h"
#include "src/compiler/turboshaft/phase.h"
#include "src/compiler/turboshaft/zone-with-name.h"
#include "src/compiler/zone-stats.h"
#include "src/execution/isolate.h"
#include "src/handles/handles-inl.h"
#include "src/objects/objects-inl.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-engine.h"
#endif

namespace v8::internal::compiler {

inline Maybe<OuterContext> GetModuleContext(OptimizedCompilationInfo* info) {
  Tagged<Context> current = info->closure()->context();
  size_t distance = 0;
  while (!IsNativeContext(*current)) {
    if (current->IsModuleContext()) {
      return Just(OuterContext(
          info->CanonicalHandle(current, current->GetIsolate()), distance));
    }
    current = current->previous();
    distance++;
  }
  return Nothing<OuterContext>();
}

class TFPipelineData {
 public:
  // For main entry point.
  TFPipelineData(ZoneStats* zone_stats, Isolate* isolate,
                 OptimizedCompilationInfo* info,
                 TurbofanPipelineStatistics* pipeline_statistics)
      : isolate_(isolate),
        allocator_(isolate->allocator()),
        info_(info),
        debug_name_(info_->GetDebugName()),
        may_have_unverifiable_graph_(v8_flags.turboshaft),
        zone_stats_(zone_stats),
        pipeline_statistics_(pipeline_statistics),
        graph_zone_(zone_stats_, kGraphZoneName, kCompressGraphZone),
        instruction_zone_scope_(zone_stats_, kInstructionZoneName),
        instruction_zone_(instruction_zone_scope_.zone()),
        codegen_zone_scope_(zone_stats_, kCodegenZoneName),
        codegen_zone_(codegen_zone_scope_.zone()),
        broker_(new JSHeapBroker(isolate_, info_->zone(),
                                 info_->trace_heap_broker(),
                                 info->code_kind())),
        register_allocation_zone_scope_(zone_stats_,
                                        kRegisterAllocationZoneName),
        register_allocation_zone_(register_allocation_zone_scope_.zone()),
        assembler_options_(AssemblerOptions::Default(isolate)) {
    PhaseScope scope(pipeline_statistics, "V8.TFInitPipelineData");
    graph_ = graph_zone_->New<Graph>(graph_zone_);
    source_positions_ = graph_zone_->New<SourcePositionTable>(graph_);
    node_origins_ = info->trace_turbo_json()
                        ? graph_zone_->New<NodeOriginTable>(graph_)
                        : nullptr;
#if V8_ENABLE_WEBASSEMBLY
    js_wasm_calls_sidetable_ =
        graph_zone_->New<JsWasmCallsSidetable>(graph_zone_);
#endif  // V8_ENABLE_WEBASSEMBLY
    simplified_ = graph_zone_->New<SimplifiedOperatorBuilder>(graph_zone_);
    machine_ = graph_zone_->New<MachineOperatorBuilder>(
        graph_zone_, MachineType::PointerRepresentation(),
        InstructionSelector::SupportedMachineOperatorFlags(),
        InstructionSelector::AlignmentRequirements());
    common_ = graph_zone_->New<CommonOperatorBuilder>(graph_zone_);
    javascript_ = graph_zone_->New<JSOperatorBuilder>(graph_zone_);
    jsgraph_ = graph_zone_->New<JSGraph>(isolate_, graph_, common_, javascript_,
                                         simplified_, machine_);
    observe_node_manager_ =
        info->node_observer()
            ? graph_zone_->New<ObserveNodeManager>(graph_zone_)
            : nullptr;
    dependencies_ = info_->zone()->New<CompilationDependencies>(broker_.get(),
                                                                info_->zone());
  }

#if V8_ENABLE_WEBASSEMBLY
  // For WebAssembly compile entry point.
  TFPipelineData(ZoneStats* zone_stats, wasm::WasmEngine* wasm_engine,
                 OptimizedCompilationInfo* info, MachineGraph* mcgraph,
                 TurbofanPipelineStatistics* pipeline_statistics,
                 SourcePositionTable* source_positions,
                 NodeOriginTable* node_origins,
                 const AssemblerOptions& assembler_options)
      : isolate_(nullptr),
        allocator_(wasm_engine->allocator()),
        info_(info),
        debug_name_(info_->GetDebugName()),
        may_have_unverifiable_graph_(v8_flags.turboshaft_wasm),
        zone_stats_(zone_stats),
        pipeline_statistics_(pipeline_statistics),
        graph_zone_(zone_stats_, kGraphZoneName, kCompressGraphZone),
        graph_(mcgraph->graph()),
        source_positions_(source_positions),
        node_origins_(node_origins),
        machine_(mcgraph->machine()),
        common_(mcgraph->common()),
        mcgraph_(mcgraph),
        instruction_zone_scope_(zone_stats_, kInstructionZoneName),
        instruction_zone_(instruction_zone_scope_.zone()),
        codegen_zone_scope_(zone_stats_, kCodegenZoneName),
        codegen_zone_(codegen_zone_scope_.zone()),
        register_allocation_zone_scope_(zone_stats_,
                                        kRegisterAllocationZoneName),
        register_allocation_zone_(register_allocation_zone_scope_.zone()),
        assembler_options_(assembler_options) {
    simplified_ = graph_zone_->New<SimplifiedOperatorBuilder>(graph_zone_);
    javascript_ = graph_zone_->New<JSOperatorBuilder>(graph_zone_);
    jsgraph_ = graph_zone_->New<JSGraph>(isolate_, graph_, common_, javascript_,
                                         simplified_, machine_);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // For CodeStubAssembler and machine graph testing entry point.
  TFPipelineData(ZoneStats* zone_stats, OptimizedCompilationInfo* info,
                 Isolate* isolate, AccountingAllocator* allocator, Graph* graph,
                 JSGraph* jsgraph, Schedule* schedule,
                 SourcePositionTable* source_positions,
                 NodeOriginTable* node_origins, JumpOptimizationInfo* jump_opt,
                 const AssemblerOptions& assembler_options,
                 const ProfileDataFromFile* profile_data)
      : isolate_(isolate),
        allocator_(allocator),
        info_(info),
        debug_name_(info_->GetDebugName()),
        zone_stats_(zone_stats),
        graph_zone_(zone_stats_, kGraphZoneName, kCompressGraphZone),
        graph_(graph),
        source_positions_(source_positions),
        node_origins_(node_origins),
        schedule_(schedule),
        instruction_zone_scope_(zone_stats_, kInstructionZoneName),
        instruction_zone_(instruction_zone_scope_.zone()),
        codegen_zone_scope_(zone_stats_, kCodegenZoneName),
        codegen_zone_(codegen_zone_scope_.zone()),
        register_allocation_zone_scope_(zone_stats_,
                                        kRegisterAllocationZoneName),
        register_allocation_zone_(register_allocation_zone_scope_.zone()),
        jump_optimization_info_(jump_opt),
        assembler_options_(assembler_options),
        profile_data_(profile_data) {
    if (jsgraph) {
      jsgraph_ = jsgraph;
      simplified_ = jsgraph->simplified();
      machine_ = jsgraph->machine();
      common_ = jsgraph->common();
      javascript_ = jsgraph->javascript();
    } else if (graph_) {
      simplified_ = graph_zone_->New<SimplifiedOperatorBuilder>(graph_zone_);
      machine_ = graph_zone_->New<MachineOperatorBuilder>(
          graph_zone_, MachineType::PointerRepresentation(),
          InstructionSelector::SupportedMachineOperatorFlags(),
          InstructionSelector::AlignmentRequirements());
      common_ = graph_zone_->New<CommonOperatorBuilder>(graph_zone_);
      javascript_ = graph_zone_->New<JSOperatorBuilder>(graph_zone_);
      jsgraph_ = graph_zone_->New<JSGraph>(isolate_, graph_, common_,
                                           javascript_, simplified_, machine_);
    }
  }

  // For register allocation testing entry point.
  TFPipelineData(ZoneStats* zone_stats, OptimizedCompilationInfo* info,
                 Isolate* isolate, InstructionSequence* sequence)
      : isolate_(isolate),
        allocator_(isolate->allocator()),
        info_(info),
        debug_name_(info_->GetDebugName()),
        zone_stats_(zone_stats),
        graph_zone_(zone_stats_, kGraphZoneName, kCompressGraphZone),
        instruction_zone_scope_(zone_stats_, kInstructionZoneName),
        instruction_zone_(sequence->zone()),
        sequence_(sequence),
        codegen_zone_scope_(zone_stats_, kCodegenZoneName),
        codegen_zone_(codegen_zone_scope_.zone()),
        register_allocation_zone_scope_(zone_stats_,
                                        kRegisterAllocationZoneName),
        register_allocation_zone_(register_allocation_zone_scope_.zone()),
        assembler_options_(AssemblerOptions::Default(isolate)) {}

  ~TFPipelineData() {
    // Must happen before zones are destroyed.
    delete code_generator_;
    code_generator_ = nullptr;
    DeleteTyper();
    DeleteRegisterAllocationZone();
    DeleteInstructionZone();
    DeleteCodegenZone();
    DeleteGraphZone();
  }

  TFPipelineData(const TFPipelineData&) = delete;
  TFPipelineData& operator=(const TFPipelineData&) = delete;

  Isolate* isolate() const { return isolate_; }
  AccountingAllocator* allocator() const { return allocator_; }
  OptimizedCompilationInfo* info() const { return info_; }
  ZoneStats* zone_stats() const { return zone_stats_; }
  CompilationDependencies* dependencies() const { return dependencies_; }
  TurbofanPipelineStatistics* pipeline_statistics() {
    return pipeline_statistics_;
  }
  OsrHelper* osr_helper() { return osr_helper_.get(); }
  std::shared_ptr<OsrHelper> osr_helper_ptr() const { return osr_helper_; }

  bool verify_graph() const { return verify_graph_; }
  void set_verify_graph(bool value) { verify_graph_ = value; }

  MaybeIndirectHandle<Code> code() { return code_; }
  void set_code(MaybeIndirectHandle<Code> code) {
    DCHECK(code_.is_null());
    code_ = code;
  }

  CodeGenerator* code_generator() const { return code_generator_; }

  // RawMachineAssembler generally produces graphs which cannot be verified.
  bool MayHaveUnverifiableGraph() const { return may_have_unverifiable_graph_; }

  Zone* graph_zone() { return graph_zone_; }
  Graph* graph() const { return graph_; }
  void set_graph(Graph* graph) { graph_ = graph; }
  template <typename T>
  using GraphZonePointer = turboshaft::ZoneWithNamePointer<T, kGraphZoneName>;
  void InitializeWithGraphZone(
      turboshaft::ZoneWithName<kGraphZoneName> graph_zone,
      GraphZonePointer<SourcePositionTable> source_positions,
      GraphZonePointer<NodeOriginTable> node_origins,
      size_t node_count_hint = 0) {
    // Delete the old zone first.
    DeleteGraphZone();

    // Take ownership of the new zone and the existing pointers.
    graph_zone_ = std::move(graph_zone);
    source_positions_ = source_positions;
    node_origins_ = node_origins;

    // Allocate a new graph and schedule.
    graph_ = graph_zone_.New<Graph>(graph_zone_);
    schedule_ = graph_zone_.New<Schedule>(graph_zone_, node_count_hint);

    // Initialize node builders.
    javascript_ = graph_zone_.New<JSOperatorBuilder>(graph_zone_);
    common_ = graph_zone_.New<CommonOperatorBuilder>(graph_zone_);
    simplified_ = graph_zone_.New<SimplifiedOperatorBuilder>(graph_zone_);
    machine_ = graph_zone_.New<MachineOperatorBuilder>(
        graph_zone_, MachineType::PointerRepresentation(),
        InstructionSelector::SupportedMachineOperatorFlags(),
        InstructionSelector::AlignmentRequirements());
  }
  turboshaft::ZoneWithName<kGraphZoneName> ReleaseGraphZone() {
    turboshaft::ZoneWithName<kGraphZoneName> temp = std::move(graph_zone_);
    // Call `DeleteGraphZone` to reset all pointers. The actual zone is not
    // released because we moved it away.
    DeleteGraphZone();
    return temp;
  }
  SourcePositionTable* source_positions() const { return source_positions_; }
  void set_source_positions(SourcePositionTable* source_positions) {
    source_positions_ = source_positions;
  }
  NodeOriginTable* node_origins() const { return node_origins_; }
  void set_node_origins(NodeOriginTable* node_origins) {
    node_origins_ = node_origins;
  }
  MachineOperatorBuilder* machine() const { return machine_; }
  SimplifiedOperatorBuilder* simplified() const { return simplified_; }
  CommonOperatorBuilder* common() const { return common_; }
  JSOperatorBuilder* javascript() const { return javascript_; }
  JSGraph* jsgraph() const { return jsgraph_; }
  MachineGraph* mcgraph() const { return mcgraph_; }
  Handle<NativeContext> native_context() const {
    return handle(info()->native_context(), isolate());
  }
  Handle<JSGlobalObject> global_object() const {
    return handle(info()->global_object(), isolate());
  }

  JSHeapBroker* broker() const { return broker_.get(); }
  std::shared_ptr<JSHeapBroker> broker_ptr() { return broker_; }

  Schedule* schedule() const { return schedule_; }
  void set_schedule(Schedule* schedule) {
    DCHECK(!schedule_);
    schedule_ = schedule;
  }
  void reset_schedule() { schedule_ = nullptr; }

  ObserveNodeManager* observe_node_manager() const {
    return observe_node_manager_;
  }

  Zone* instruction_zone() const { return instruction_zone_; }
  Zone* codegen_zone() const { return codegen_zone_; }
  InstructionSequence* sequence() const { return sequence_; }
  Frame* frame() const { return frame_; }

  Zone* register_allocation_zone() const { return register_allocation_zone_; }

  RegisterAllocationData* register_allocation_data() const {
    return register_allocation_data_;
  }

  std::string const& source_position_output() const {
    return source_position_output_;
  }
  void set_source_position_output(std::string const& source_position_output) {
    source_position_output_ = source_position_output;
  }

  JumpOptimizationInfo* jump_optimization_info() const {
    return jump_optimization_info_;
  }

  const AssemblerOptions& assembler_options() const {
    return assembler_options_;
  }

  void ChooseSpecializationContext() {
    if (info()->function_context_specializing()) {
      DCHECK(info()->has_context());
      specialization_context_ = Just(OuterContext(
          info()->CanonicalHandle(info()->context(), isolate()), 0));
    } else {
      specialization_context_ = GetModuleContext(info());
    }
  }

  Maybe<OuterContext> specialization_context() const {
    return specialization_context_;
  }

  size_t* address_of_max_unoptimized_frame_height() {
    return &max_unoptimized_frame_height_;
  }
  size_t max_unoptimized_frame_height() const {
    return max_unoptimized_frame_height_;
  }
  size_t* address_of_max_pushed_argument_count() {
    return &max_pushed_argument_count_;
  }
  size_t max_pushed_argument_count() const {
    return max_pushed_argument_count_;
  }

  CodeTracer* GetCodeTracer() const {
#if V8_ENABLE_WEBASSEMBLY
    if (info_->IsWasm() || info_->IsWasmBuiltin()) {
      return wasm::GetWasmEngine()->GetCodeTracer();
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    return isolate_->GetCodeTracer();
  }

  Typer* CreateTyper() {
    DCHECK_NULL(typer_);
    typer_ =
        new Typer(broker(), typer_flags_, graph(), &info()->tick_counter());
    return typer_;
  }

  void AddTyperFlag(Typer::Flag flag) {
    DCHECK_NULL(typer_);
    typer_flags_ |= flag;
  }

  void DeleteTyper() {
    delete typer_;
    typer_ = nullptr;
  }

  void DeleteGraphZone() {
#ifdef V8_ENABLE_WEBASSEMBLY
    js_wasm_calls_sidetable_ = nullptr;
#endif  // V8_ENABLE_WEBASSEMBLY
    graph_ = nullptr;
    source_positions_ = nullptr;
    node_origins_ = nullptr;
    simplified_ = nullptr;
    machine_ = nullptr;
    common_ = nullptr;
    javascript_ = nullptr;
    jsgraph_ = nullptr;
    mcgraph_ = nullptr;
    schedule_ = nullptr;
    graph_zone_.Destroy();
  }

  void DeleteInstructionZone() {
    if (instruction_zone_ == nullptr) return;
    instruction_zone_scope_.Destroy();
    instruction_zone_ = nullptr;
    sequence_ = nullptr;
  }

  void DeleteCodegenZone() {
    if (codegen_zone_ == nullptr) return;
    codegen_zone_scope_.Destroy();
    codegen_zone_ = nullptr;
    dependencies_ = nullptr;
    broker_.reset();
    broker_ = nullptr;
    frame_ = nullptr;
  }

  void DeleteRegisterAllocationZone() {
    if (register_allocation_zone_ == nullptr) return;
    register_allocation_zone_scope_.Destroy();
    register_allocation_zone_ = nullptr;
    register_allocation_data_ = nullptr;
  }

  void InitializeInstructionSequence(const CallDescriptor* call_descriptor) {
    DCHECK_NULL(sequence_);
    InstructionBlocks* instruction_blocks =
        InstructionSequence::InstructionBlocksFor(instruction_zone(),
                                                  schedule());
    sequence_ = instruction_zone()->New<InstructionSequence>(
        isolate(), instruction_zone(), instruction_blocks);
    if (call_descriptor && call_descriptor->RequiresFrameAsIncoming()) {
      sequence_->instruction_blocks()[0]->mark_needs_frame();
    } else {
      DCHECK(call_descriptor->CalleeSavedFPRegisters().is_empty());
    }
  }

  void InitializeFrameData(CallDescriptor* call_descriptor) {
    DCHECK_NULL(frame_);
    int fixed_frame_size = 0;
    if (call_descriptor != nullptr) {
      fixed_frame_size =
          call_descriptor->CalculateFixedFrameSize(info()->code_kind());
    }
    frame_ = codegen_zone()->New<Frame>(fixed_frame_size, codegen_zone());
    if (osr_helper_) osr_helper()->SetupFrame(frame());
  }

  void InitializeRegisterAllocationData(const RegisterConfiguration* config,
                                        CallDescriptor* call_descriptor) {
    DCHECK_NULL(register_allocation_data_);
    register_allocation_data_ =
        register_allocation_zone()->New<RegisterAllocationData>(
            config, register_allocation_zone(), frame(), sequence(),
            &info()->tick_counter(), debug_name());
  }

  void InitializeOsrHelper() {
    DCHECK_NULL(osr_helper_);
    osr_helper_ = std::make_shared<OsrHelper>(info());
  }

  void set_start_source_position(int position) {
    DCHECK_EQ(start_source_position_, kNoSourcePosition);
    start_source_position_ = position;
  }

  int start_source_position() const { return start_source_position_; }

  void InitializeCodeGenerator(Linkage* linkage) {
    DCHECK_NULL(code_generator_);
#if V8_ENABLE_WEBASSEMBLY
    assembler_options_.is_wasm =
        this->info()->IsWasm() || this->info()->IsWasmBuiltin();
#endif
    std::optional<OsrHelper> osr_helper;
    if (osr_helper_) osr_helper = *osr_helper_;
    code_generator_ = new CodeGenerator(
        codegen_zone(), frame(), linkage, sequence(), info(), isolate(),
        std::move(osr_helper), start_source_position_, jump_optimization_info_,
        assembler_options(), info_->builtin(), max_unoptimized_frame_height(),
        max_pushed_argument_count(),
        v8_flags.trace_turbo_stack_accesses ? debug_name_.get() : nullptr);
  }

  void BeginPhaseKind(const char* phase_kind_name) {
    if (pipeline_statistics() != nullptr) {
      pipeline_statistics()->BeginPhaseKind(phase_kind_name);
    }
  }

  void EndPhaseKind() {
    if (pipeline_statistics() != nullptr) {
      pipeline_statistics()->EndPhaseKind();
    }
  }

  const char* debug_name() const { return debug_name_.get(); }

  const ProfileDataFromFile* profile_data() const { return profile_data_; }
  void set_profile_data(const ProfileDataFromFile* profile_data) {
    profile_data_ = profile_data;
  }

  // RuntimeCallStats that is only available during job execution but not
  // finalization.
  // TODO(delphick): Currently even during execution this can be nullptr, due to
  // JSToWasmWrapperCompilationUnit::Execute. Once a table can be extracted
  // there, this method can DCHECK that it is never nullptr.
  RuntimeCallStats* runtime_call_stats() const { return runtime_call_stats_; }
  void set_runtime_call_stats(RuntimeCallStats* stats) {
    runtime_call_stats_ = stats;
  }

#if V8_ENABLE_WEBASSEMBLY
  bool has_js_wasm_calls() const {
    return wasm_module_for_inlining_ != nullptr;
  }
  const wasm::WasmModule* wasm_module_for_inlining() const {
    return wasm_module_for_inlining_;
  }
  void set_wasm_module_for_inlining(const wasm::WasmModule* module) {
    // We may only inline Wasm functions from at most one module, see below.
    DCHECK_NULL(wasm_module_for_inlining_);
    wasm_module_for_inlining_ = module;
  }
  JsWasmCallsSidetable* js_wasm_calls_sidetable() {
    return js_wasm_calls_sidetable_;
  }
#endif  // V8_ENABLE_WEBASSEMBLY

 private:
  Isolate* const isolate_;
#if V8_ENABLE_WEBASSEMBLY
  // The wasm module to be used for inlining wasm functions into JS.
  // The first module wins and inlining of different modules into the same
  // JS function is not supported. This is necessary because the wasm
  // instructions use module-specific (non-canonicalized) type indices.
  // TODO(353475584): Long-term we might want to lift this restriction, i.e.,
  // support inlining Wasm functions from different Wasm modules in the
  // Turboshaft implementation to avoid a surprising performance cliff.
  const wasm::WasmModule* wasm_module_for_inlining_ = nullptr;
  // Sidetable for storing/passing information about the to-be-inlined calls to
  // Wasm functions through the JS Turbofan frontend to the Turboshaft backend.
  // This should go away once we not only inline the Wasm body in Turboshaft but
  // also the JS-to-Wasm wrapper (which is currently inlined in Turbofan still).
  // See https://crbug.com/353475584.
  JsWasmCallsSidetable* js_wasm_calls_sidetable_ = nullptr;
#endif  // V8_ENABLE_WEBASSEMBLY
  AccountingAllocator* const allocator_;
  OptimizedCompilationInfo* const info_;
  std::unique_ptr<char[]> debug_name_;
  bool may_have_unverifiable_graph_ = true;
  ZoneStats* const zone_stats_;
  TurbofanPipelineStatistics* pipeline_statistics_ = nullptr;
  bool verify_graph_ = false;
  int start_source_position_ = kNoSourcePosition;
  std::shared_ptr<OsrHelper> osr_helper_;
  MaybeIndirectHandle<Code> code_;
  CodeGenerator* code_generator_ = nullptr;
  Typer* typer_ = nullptr;
  Typer::Flags typer_flags_ = Typer::kNoFlags;

  // All objects in the following group of fields are allocated in graph_zone_.
  // They are all set to nullptr when the graph_zone_ is destroyed.
  turboshaft::ZoneWithName<kGraphZoneName> graph_zone_;
  Graph* graph_ = nullptr;
  SourcePositionTable* source_positions_ = nullptr;
  NodeOriginTable* node_origins_ = nullptr;
  SimplifiedOperatorBuilder* simplified_ = nullptr;
  MachineOperatorBuilder* machine_ = nullptr;
  CommonOperatorBuilder* common_ = nullptr;
  JSOperatorBuilder* javascript_ = nullptr;
  JSGraph* jsgraph_ = nullptr;
  MachineGraph* mcgraph_ = nullptr;
  Schedule* schedule_ = nullptr;
  ObserveNodeManager* observe_node_manager_ = nullptr;
  std::unique_ptr<turboshaft::PipelineData> ts_data_;

  // All objects in the following group of fields are allocated in
  // instruction_zone_. They are all set to nullptr when the instruction_zone_
  // is destroyed.
  ZoneStats::Scope instruction_zone_scope_;
  Zone* instruction_zone_;
  InstructionSequence* sequence_ = nullptr;

  // All objects in the following group of fields are allocated in
  // codegen_zone_. They are all set to nullptr when the codegen_zone_
  // is destroyed.
  ZoneStats::Scope codegen_zone_scope_;
  Zone* codegen_zone_;
  CompilationDependencies* dependencies_ = nullptr;
  std::shared_ptr<JSHeapBroker> broker_;
  Frame* frame_ = nullptr;

  // All objects in the following group of fields are allocated in
  // register_allocation_zone_. They are all set to nullptr when the zone is
  // destroyed.
  ZoneStats::Scope register_allocation_zone_scope_;
  Zone* register_allocation_zone_;
  RegisterAllocationData* register_allocation_data_ = nullptr;

  // Source position output for --trace-turbo.
  std::string source_position_output_;

  JumpOptimizationInfo* jump_optimization_info_ = nullptr;
  AssemblerOptions assembler_options_;
  Maybe<OuterContext> specialization_context_ = Nothing<OuterContext>();

  // The maximal combined height of all inlined frames in their unoptimized
  // state, and the maximal number of arguments pushed during function calls.
  // Calculated during instruction selection, applied during code generation.
  size_t max_unoptimized_frame_height_ = 0;
  size_t max_pushed_argument_count_ = 0;

  RuntimeCallStats* runtime_call_stats_ = nullptr;
  const ProfileDataFromFile* profile_data_ = nullptr;
};

}  // namespace v8::internal::compiler

#endif  // V8_COMPILER_PIPELINE_DATA_INL_H_

"""

```
Response:
Let's break down the thought process for analyzing the `phase.h` file.

1. **Understand the Request:** The core request is to understand the purpose of the file `v8/src/compiler/turboshaft/phase.h`. Specific points include checking if it's Torque, its relationship to JavaScript, providing examples, and noting potential programming errors.

2. **Initial Scan and Keywords:**  A quick scan of the file reveals several important keywords and structures:
    * `#ifndef`, `#define`, `#include`:  Standard C++ header file guard.
    * `namespace v8::internal::compiler::turboshaft`:  Confirms the file's location within the V8 compiler's Turboshaft pipeline.
    * `class PipelineData`: This looks like a central data structure.
    * `template <typename Phase> concept TurboshaftPhase`: This suggests the file defines concepts related to compiler phases.
    * Macros like `DECL_TURBOSHAFT_PHASE_CONSTANTS`:  Indicates a system for defining phase-related constants.
    * Mentions of `Graph`, `CodeGenerator`, `InstructionSequence`, `RegisterAllocationData`: These are components of a compiler.

3. **High-Level Purpose Deduction:** Based on the namespace and the included components, it's highly likely that `phase.h` defines the structure and constraints for different phases within the Turboshaft compiler pipeline. It's about organizing and managing the data flow and operations of the compiler.

4. **Torque Check:** The prompt specifically asks about Torque. The file extension is `.h`, not `.tq`. Therefore, it's a C++ header, not a Torque source file.

5. **JavaScript Relationship:**  Compiler phases, by their nature, are directly involved in translating JavaScript code into machine code. The presence of `OptimizedCompilationInfo`, `SourcePositionTable`, and mentions of bytecode suggest a connection to JavaScript execution.

6. **Detailed Analysis of Key Components:**

    * **`PipelineData`:**  This class appears to be a container holding all the data needed throughout the compilation process. It contains components like `GraphComponent`, `CodegenComponent`, `InstructionComponent`, and `RegisterComponent`. This reinforces the idea of managing data flow. The `Initialize...Component` methods suggest a phased initialization of these components.

    * **`TurboshaftPhase` Concept:**  This is crucial. The concept `TurboshaftPhase` enforces a specific structure for classes representing Turboshaft compiler phases. It requires a `Run` method with `PipelineData*` and `Zone*` arguments and a `kKind` member equal to `PhaseKind::kTurboshaft`. This is the core mechanism for defining and validating phases.

    * **Macros (`DECL_TURBOSHAFT_PHASE_CONSTANTS`):** These macros seem to be a convenient way to define common constants and assertions for phase classes, promoting consistency.

    * **`ComponentWithZone`:** This template suggests that many components within the pipeline have an associated memory zone for allocation management.

7. **Functionality Listing:** Now, systematically list the functionalities based on the analysis:
    * Defining the structure for Turboshaft compiler phases (`TurboshaftPhase` concept).
    * Providing a central data structure (`PipelineData`) to hold information shared between phases.
    * Defining standard components used in the compilation pipeline (Graph, Codegen, Instructions, Registers).
    * Providing mechanisms for managing memory allocation for these components (`ComponentWithZone`).
    * Defining constants and assertions for phases.
    * Supporting different pipeline kinds (JS, Wasm, etc.).
    * Offering debugging and tracing capabilities (printing graphs).

8. **JavaScript Example:** Think about a simple JavaScript snippet and how the compiler would process it. Variable declaration and usage is a good starting point, as it involves symbol resolution, type checking, and code generation.

9. **Code Logic Inference:** The `TurboshaftPhase` concept with its `Run` method suggests a sequential execution of phases. Each phase likely takes the `PipelineData` as input, performs its task, and potentially modifies the data for subsequent phases.

10. **Common Programming Errors:** Focus on potential issues related to the constraints defined in the header:
    * Not adhering to the `TurboshaftPhase` concept (missing `Run` method or incorrect signature).
    * Accessing `PipelineData` components before they are initialized.
    * Memory management issues if custom components don't properly use the provided zones.

11. **Refine and Organize:**  Structure the answer clearly with headings and bullet points for readability. Ensure the language is precise and explains the technical concepts in an understandable way. Review for clarity and completeness. For example, initially, I might have just said "manages data," but refining it to "centralized storage and management of data" is more descriptive. Similarly, explicitly mentioning the purpose of the `Zone` in `ComponentWithZone` adds clarity.

12. **Self-Correction/Refinement during the Process:**  Initially, I might have focused too much on individual components. Realizing the importance of the `TurboshaftPhase` concept and `PipelineData` as central organizing principles is crucial for a comprehensive understanding. Also, ensuring the JavaScript example clearly illustrates the compiler's role is important. Double-checking the Torque question to avoid misinterpreting the file extension is another point of self-correction.
好的，让我们来分析一下 V8 源代码文件 `v8/src/compiler/turboshaft/phase.h` 的功能。

**文件功能概述**

`v8/src/compiler/turboshaft/phase.h` 文件是 V8 引擎中 Turboshaft 编译管道的核心组成部分，它主要负责定义和管理 Turboshaft 编译器的各个阶段（phases）。  更具体地说，它做了以下几件事：

1. **定义了编译阶段的概念和约束：**  通过 `TurboshaftPhase` 这个 C++20 的 concept，它规定了 Turboshaft 编译管道中一个合法的“阶段”需要满足的条件，例如必须有一个接受 `PipelineData*` 和 `Zone*` 参数的 `Run` 方法，并且其 `kKind` 成员必须是 `PhaseKind::kTurboshaft`。这为 Turboshaft 编译器的架构提供了一致性和类型安全性。

2. **定义了 `PipelineData` 类：**  `PipelineData` 是一个关键的数据结构，它充当了整个 Turboshaft 编译管道中共享信息的载体。  它包含了编译过程中需要传递和访问的各种数据，例如抽象语法树 (AST) 的表示（通过 `Graph`），编译配置信息，优化信息，代码生成所需的组件等等。  `PipelineData` 实例在编译管道的各个阶段之间传递，使得不同的阶段可以访问和修改必要的数据。

3. **定义了编译管道中使用的各种组件：**  `PipelineData` 内部包含了许多嵌套的结构体，例如 `GraphComponent`, `CodegenComponent`, `InstructionComponent`, `RegisterComponent` 等。这些结构体封装了特定编译阶段所需的数据和对象。例如，`GraphComponent` 包含了图的表示 (`Graph`) 和源码位置信息 (`SourcePositionTable`)。

4. **提供了定义编译阶段常量的宏：**  `DECL_TURBOSHAFT_PHASE_CONSTANTS` 和相关的宏定义了一套方便的方式来声明编译阶段的名称、统计信息等常量。这有助于代码的维护和调试。

5. **支持不同类型的编译管道：**  `TurboshaftPipelineKind` 枚举定义了 Turboshaft 可以处理的不同类型的编译任务，例如 JavaScript 代码 (`kJS`)，WebAssembly 代码 (`kWasm`) 等。

6. **提供了打印调试信息的辅助函数：**  `PrintTurboshaftGraph` 和 `PrintTurboshaftGraphForTurbolizer` 函数用于在调试时打印 Turboshaft 的图结构，方便开发者理解编译器的内部工作过程。

**关于文件扩展名和 Torque**

你提到的 `.tq` 扩展名是用于 V8 的 Torque 语言的源文件。 `v8/src/compiler/turboshaft/phase.h` 的扩展名是 `.h`，这表明它是一个 **C++ 头文件**，而不是 Torque 文件。 因此，它不是 Torque 源代码。

**与 JavaScript 的关系**

`v8/src/compiler/turboshaft/phase.h` 文件是 V8 引擎编译器的核心部分，而编译器负责将 JavaScript 代码转换成可执行的机器代码。 因此，该文件与 JavaScript 的功能有着直接且重要的关系。

**JavaScript 例子**

当 V8 执行 JavaScript 代码时，Turboshaft 编译器会参与将 JavaScript 函数编译为优化的机器码。  `phase.h` 中定义的阶段和 `PipelineData` 负责管理这个编译过程。

例如，考虑以下简单的 JavaScript 函数：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 编译这个 `add` 函数时，Turboshaft 编译管道会经历多个阶段，每个阶段都由 `phase.h` 中定义的结构和约束来组织。  一些可能的阶段包括：

1. **图构建阶段 (Graph Building Phase):**  将 JavaScript 代码转换为中间表示，即图 (`Graph`)。  `PipelineData` 会包含一个 `GraphComponent` 来存储这个图。
2. **类型推断阶段 (Type Inference Phase):**  分析变量的类型信息，以便进行更有效的优化。  这个阶段可能会读取和修改 `PipelineData` 中的图信息。
3. **优化阶段 (Optimization Phases):**  执行各种优化，例如内联、常量折叠等。  每个优化都可能是一个独立的阶段。
4. **指令选择阶段 (Instruction Selection Phase):**  将图中的操作映射到目标架构的机器指令。 `PipelineData` 会包含一个 `InstructionComponent` 来存储指令序列。
5. **寄存器分配阶段 (Register Allocation Phase):**  为变量和中间结果分配寄存器。 `PipelineData` 会包含一个 `RegisterComponent` 来管理寄存器分配信息。
6. **代码生成阶段 (Code Generation Phase):**  生成最终的机器代码。

**代码逻辑推理**

假设我们有一个 Turboshaft 编译管道中的一个阶段，它需要访问当前正在编译的函数的名称。

**假设输入：**

* `PipelineData* data`:  一个指向 `PipelineData` 实例的指针，该实例代表了当前编译任务的状态。
* `Zone* zone`:  一个用于内存管理的 Zone。

**代码逻辑（在某个编译阶段的 `Run` 方法中）：**

```c++
#include "src/compiler/turboshaft/phase.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/logging/logger.h"

namespace v8::internal::compiler::turboshaft {

class MyAnalysisPhase {
 public:
  static constexpr PhaseKind kKind = PhaseKind::kTurboshaft;
  static constexpr bool kOutputIsTraceableGraph = false; // 假设这个阶段不输出可追踪的图

  void Run(PipelineData* data, Zone* zone) {
    OptimizedCompilationInfo* info = data->info();
    if (info) {
      const char* function_name = info->GetDebugName().get();
      if (v8_flags.trace_turboshaft) {
        StdoutTracer tracer(data->isolate());
        tracer << "[Turboshaft] Running MyAnalysisPhase on function: " << function_name << "\n";
      }
      // 在这里进行基于函数名的分析或处理
    }
  }
};

} // namespace v8::internal::compiler::turboshaft
```

**输出：**

如果 `v8_flags.trace_turboshaft` 开启，并且 `data->info()` 返回一个有效的 `OptimizedCompilationInfo` 对象，那么控制台会输出类似于以下的信息：

```
[Turboshaft] Running MyAnalysisPhase on function: add
```

其中 "add" 是被编译的 JavaScript 函数的名称。

**用户常见的编程错误**

在开发或维护 Turboshaft 编译器时，用户可能会犯以下编程错误：

1. **未正确初始化 `PipelineData` 中的组件：**  在编译管道的早期阶段，必须正确地初始化 `PipelineData` 中的各个组件。如果在后续阶段尝试访问未初始化的组件（例如，在 `InitializeGraphComponent` 之前访问 `data->graph()`），会导致空指针解引用或其他错误。

   **错误示例：**

   ```c++
   // 错误的顺序：在初始化图组件之前访问图
   class IncorrectPhase {
    public:
     static constexpr PhaseKind kKind = PhaseKind::kTurboshaft;
     static constexpr bool kOutputIsTraceableGraph = false;

     void Run(PipelineData* data, Zone* zone) {
       Graph& graph = data->graph(); // 错误：可能在 InitializeGraphComponent 之前调用
       // ... 使用 graph ...
     }
   };
   ```

2. **不符合 `TurboshaftPhase` concept 的要求：**  自定义的编译阶段类必须满足 `TurboshaftPhase` concept 的所有要求，例如拥有正确的 `Run` 方法签名和 `kKind` 成员。如果违反这些要求，编译器可能会在编译时或运行时报错。

   **错误示例：**

   ```c++
   // 错误的 Run 方法签名
   class IncorrectPhaseSignature {
    public:
     static constexpr PhaseKind kKind = PhaseKind::kTurboshaft;
     static constexpr bool kOutputIsTraceableGraph = false;

     void Run(PipelineData* data) { // 错误：缺少 Zone* 参数
       // ...
     }
   };
   ```

3. **在不应该修改 `PipelineData` 的阶段修改它：**  某些编译阶段可能是只读的，或者只允许修改特定的 `PipelineData` 组件。错误地修改 `PipelineData` 可能会导致后续阶段出现意想不到的行为或错误。

4. **内存管理错误：**  在编译过程中，需要在 `Zone` 上分配内存。如果在编译阶段结束时没有正确地释放或清理内存，可能会导致内存泄漏。

5. **假设特定的阶段执行顺序：**  虽然 Turboshaft 编译管道有一个大致的执行顺序，但过度依赖特定的顺序可能会导致问题。  各个阶段应该尽可能地独立，并通过 `PipelineData` 进行数据交换。

总而言之，`v8/src/compiler/turboshaft/phase.h` 是 V8 引擎 Turboshaft 编译器的蓝图，它定义了编译过程的结构和数据流，是理解 Turboshaft 内部工作原理的关键入口点。

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/phase.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/phase.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_TURBOSHAFT_PHASE_H_
#define V8_COMPILER_TURBOSHAFT_PHASE_H_

#include <optional>
#include <type_traits>

#include "src/base/contextual.h"
#include "src/base/template-meta-programming/functional.h"
#include "src/codegen/assembler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/common/globals.h"
#include "src/compiler/access-info.h"
#include "src/compiler/backend/instruction.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/node-origin-table.h"
#include "src/compiler/osr.h"
#include "src/compiler/phase.h"
#include "src/compiler/turboshaft/builtin-compiler.h"
#include "src/compiler/turboshaft/graph.h"
#include "src/compiler/turboshaft/sidetable.h"
#include "src/compiler/turboshaft/zone-with-name.h"
#include "src/logging/runtime-call-stats.h"
#include "src/zone/accounting-allocator.h"
#include "src/zone/zone.h"

#define DECL_TURBOSHAFT_PHASE_CONSTANTS_IMPL(Name, CallStatsName)             \
  DECL_PIPELINE_PHASE_CONSTANTS_HELPER(CallStatsName, PhaseKind::kTurboshaft, \
                                       RuntimeCallStats::kThreadSpecific)     \
  static constexpr char kPhaseName[] = "V8.TF" #CallStatsName;                \
  static void AssertTurboshaftPhase() {                                       \
    static_assert(TurboshaftPhase<Name##Phase>);                              \
  }

#define DECL_TURBOSHAFT_PHASE_CONSTANTS(Name) \
  DECL_TURBOSHAFT_PHASE_CONSTANTS_IMPL(Name, Turboshaft##Name)
#define DECL_TURBOSHAFT_PHASE_CONSTANTS_WITH_LEGACY_NAME(Name) \
  DECL_TURBOSHAFT_PHASE_CONSTANTS_IMPL(Name, Name)

#define DECL_TURBOSHAFT_MAIN_THREAD_PIPELINE_PHASE_CONSTANTS_WITH_LEGACY_NAME( \
    Name)                                                                      \
  DECL_PIPELINE_PHASE_CONSTANTS_HELPER(Name, PhaseKind::kTurboshaft,           \
                                       RuntimeCallStats::kExact)               \
  static constexpr char kPhaseName[] = "V8.TF" #Name;                          \
  static void AssertTurboshaftPhase() {                                        \
    static_assert(TurboshaftPhase<Name##Phase>);                               \
  }

namespace v8::internal::compiler {
class RegisterAllocationData;
class Schedule;
class TurbofanPipelineStatistics;
}  // namespace v8::internal::compiler

namespace v8::internal::compiler::turboshaft {

class PipelineData;

template <typename Phase>
struct HasProperRunMethod {
  using parameters = base::tmp::call_parameters_t<decltype(&Phase::Run)>;
  static_assert(
      base::tmp::length_v<parameters> >= 2,
      "Phase::Run needs at least two parameters (PipelineData* and Zone*)");
  using parameter0 = base::tmp::element_t<parameters, 0>;
  using parameter1 = base::tmp::element_t<parameters, 1>;
  static constexpr bool value = std::is_same_v<parameter0, PipelineData*> &&
                                std::is_same_v<parameter1, Zone*>;
};

template <typename Phase, typename... Args>
concept TurboshaftPhase =
    HasProperRunMethod<Phase>::value &&
    requires(Phase p) { p.kKind == PhaseKind::kTurboshaft; };

template <typename Phase>
concept TurbofanPhase = requires(Phase p) { p.kKind == PhaseKind::kTurbofan; };

template <typename Phase>
concept CompilerPhase = TurboshaftPhase<Phase> || TurbofanPhase<Phase>;

namespace detail {
template <typename, typename = void>
struct produces_printable_graph_impl : std::true_type {};

template <typename P>
struct produces_printable_graph_impl<
    P, std::void_t<decltype(P::kOutputIsTraceableGraph)>>
    : std::bool_constant<P::kOutputIsTraceableGraph> {};

#ifdef HAS_CPP_CLASS_TYPES_AS_TEMPLATE_ARGS
template <base::tmp::StringLiteral ZoneName>
#else
template <auto ZoneName>
#endif
struct ComponentWithZone {
  template <typename T>
  using Pointer = ZoneWithNamePointer<T, ZoneName>;

  explicit ComponentWithZone(ZoneStats* zone_stats)
      : zone(zone_stats,
#ifdef HAS_CPP_CLASS_TYPES_AS_TEMPLATE_ARGS
             ZoneName.c_str()
#else
             ZONE_NAME
#endif
        ) {
  }
  explicit ComponentWithZone(ZoneWithName<ZoneName> existing_zone)
      : zone(std::move(existing_zone)) {}

  ZoneWithName<ZoneName> zone;
};

struct BuiltinComponent {
  const CallDescriptor* call_descriptor;
  std::optional<BytecodeHandlerData> bytecode_handler_data;

  BuiltinComponent(const CallDescriptor* call_descriptor,
                   std::optional<BytecodeHandlerData> bytecode_handler_data)
      : call_descriptor(call_descriptor),
        bytecode_handler_data(std::move(bytecode_handler_data)) {}
};

struct GraphComponent : public ComponentWithZone<kGraphZoneName> {
  using ComponentWithZone::ComponentWithZone;

  Pointer<Graph> graph = nullptr;
  Pointer<SourcePositionTable> source_positions = nullptr;
  Pointer<NodeOriginTable> node_origins = nullptr;
  bool graph_has_special_rpo = false;
};

struct CodegenComponent : public ComponentWithZone<kCodegenZoneName> {
  using ComponentWithZone::ComponentWithZone;

  Pointer<Frame> frame = nullptr;
  std::unique_ptr<CodeGenerator> code_generator;
  Pointer<CompilationDependency> dependencies = nullptr;
  // TODO(nicohartmann): Make {osr_helper} an optional once TurboFan's
  // PipelineData is gone.
  std::shared_ptr<OsrHelper> osr_helper;
  JumpOptimizationInfo* jump_optimization_info = nullptr;
  size_t max_unoptimized_frame_height = 0;
  size_t max_pushed_argument_count = 0;
};

struct InstructionComponent : public ComponentWithZone<kInstructionZoneName> {
  using ComponentWithZone::ComponentWithZone;

  Pointer<InstructionSequence> sequence = nullptr;
};

struct RegisterComponent
    : public ComponentWithZone<kRegisterAllocationZoneName> {
  using ComponentWithZone::ComponentWithZone;

  Pointer<RegisterAllocationData> allocation_data = nullptr;
};
}  // namespace detail

template <typename P>
struct produces_printable_graph
    : public detail::produces_printable_graph_impl<P> {};

enum class TurboshaftPipelineKind { kJS, kWasm, kCSA, kTSABuiltin, kJSToWasm };

class LoopUnrollingAnalyzer;
class WasmRevecAnalyzer;

class V8_EXPORT_PRIVATE PipelineData {
  using BuiltinComponent = detail::BuiltinComponent;
  using GraphComponent = detail::GraphComponent;
  using CodegenComponent = detail::CodegenComponent;
  using InstructionComponent = detail::InstructionComponent;
  using RegisterComponent = detail::RegisterComponent;

 public:
  explicit PipelineData(ZoneStats* zone_stats,
                        TurboshaftPipelineKind pipeline_kind, Isolate* isolate,
                        OptimizedCompilationInfo* info,
                        const AssemblerOptions& assembler_options,
                        int start_source_position = kNoSourcePosition)
      : zone_stats_(zone_stats),
        compilation_zone_(zone_stats, kCompilationZoneName),
        pipeline_kind_(pipeline_kind),
        isolate_(isolate),
        info_(info),
        debug_name_(info_ ? info_->GetDebugName() : std::unique_ptr<char[]>{}),
        start_source_position_(start_source_position),
        assembler_options_(assembler_options) {
#if V8_ENABLE_WEBASSEMBLY
    if (info != nullptr) {
      DCHECK_EQ(assembler_options_.is_wasm,
                info->IsWasm() || info->IsWasmBuiltin());
    }
#endif
  }

  void InitializeBrokerAndDependencies(std::shared_ptr<JSHeapBroker> broker,
                                       CompilationDependencies* dependencies) {
    DCHECK_NULL(broker_.get());
    DCHECK_NULL(dependencies_);
    DCHECK_NOT_NULL(broker);
    DCHECK_NOT_NULL(dependencies);
    broker_ = std::move(broker);
    dependencies_ = dependencies;
  }

  void InitializeBuiltinComponent(
      const CallDescriptor* call_descriptor,
      std::optional<BytecodeHandlerData> bytecode_handler_data = {}) {
    DCHECK(!builtin_component_.has_value());
    builtin_component_.emplace(call_descriptor,
                               std::move(bytecode_handler_data));
  }

  void InitializeGraphComponent(SourcePositionTable* source_positions) {
    DCHECK(!graph_component_.has_value());
    graph_component_.emplace(zone_stats_);
    auto& zone = graph_component_->zone;
    graph_component_->graph = zone.New<Graph>(zone);
    graph_component_->source_positions =
        GraphComponent::Pointer<SourcePositionTable>(source_positions);
    if (info_ && info_->trace_turbo_json()) {
      graph_component_->node_origins = zone.New<NodeOriginTable>(zone);
    }
  }

  void InitializeGraphComponentWithGraphZone(
      ZoneWithName<kGraphZoneName> graph_zone,
      ZoneWithNamePointer<SourcePositionTable, kGraphZoneName> source_positions,
      ZoneWithNamePointer<NodeOriginTable, kGraphZoneName> node_origins) {
    DCHECK(!graph_component_.has_value());
    graph_component_.emplace(std::move(graph_zone));
    auto& zone = graph_component_->zone;
    graph_component_->graph = zone.New<Graph>(zone);
    graph_component_->source_positions = source_positions;
    graph_component_->node_origins = node_origins;
    if (!graph_component_->node_origins && info_ && info_->trace_turbo_json()) {
      graph_component_->node_origins = zone.New<NodeOriginTable>(zone);
    }
  }

  void ClearGraphComponent() {
    DCHECK(graph_component_.has_value());
    graph_component_.reset();
  }

  void InitializeCodegenComponent(
      std::shared_ptr<OsrHelper> osr_helper,
      JumpOptimizationInfo* jump_optimization_info = nullptr) {
    DCHECK(!codegen_component_.has_value());
    codegen_component_.emplace(zone_stats_);
    codegen_component_->osr_helper = std::move(osr_helper);
    codegen_component_->jump_optimization_info = jump_optimization_info;
  }

  void ClearCodegenComponent() {
    DCHECK(codegen_component_.has_value());
    codegen_component_.reset();
  }

  void InitializeCodeGenerator(Linkage* linkage) {
    DCHECK(codegen_component_.has_value());
    CodegenComponent& cg = *codegen_component_;
    DCHECK_NULL(codegen_component_->code_generator);
#if V8_ENABLE_WEBASSEMBLY
    DCHECK_EQ(assembler_options_.is_wasm,
              info()->IsWasm() || info()->IsWasmBuiltin());
#endif
    std::optional<OsrHelper> osr_helper;
    if (cg.osr_helper) osr_helper = *cg.osr_helper;
    cg.code_generator = std::make_unique<CodeGenerator>(
        cg.zone, cg.frame, linkage, sequence(), info_, isolate_,
        std::move(osr_helper), start_source_position_,
        cg.jump_optimization_info, assembler_options_, info_->builtin(),
        cg.max_unoptimized_frame_height, cg.max_pushed_argument_count,
        v8_flags.trace_turbo_stack_accesses ? debug_name_.get() : nullptr);
  }

  void InitializeInstructionComponent(const CallDescriptor* call_descriptor) {
    DCHECK(!instruction_component_.has_value());
    instruction_component_.emplace(zone_stats());
    auto& zone = instruction_component_->zone;
    InstructionBlocks* instruction_blocks =
        InstructionSequence::InstructionBlocksFor(zone, graph());
    instruction_component_->sequence =
        zone.New<InstructionSequence>(isolate(), zone, instruction_blocks);
    if (call_descriptor && call_descriptor->RequiresFrameAsIncoming()) {
      instruction_component_->sequence->instruction_blocks()[0]
          ->mark_needs_frame();
    } else {
      DCHECK(call_descriptor->CalleeSavedFPRegisters().is_empty());
    }
  }

  void ClearInstructionComponent() {
    DCHECK(instruction_component_.has_value());
    instruction_component_.reset();
  }

  void InitializeRegisterComponent(const RegisterConfiguration* config,
                                   CallDescriptor* call_descriptor);

  void ClearRegisterComponent() {
    DCHECK(register_component_.has_value());
    register_component_.reset();
  }

  AccountingAllocator* allocator() const;
  ZoneStats* zone_stats() const { return zone_stats_; }
  TurboshaftPipelineKind pipeline_kind() const { return pipeline_kind_; }
  Isolate* isolate() const { return isolate_; }
  OptimizedCompilationInfo* info() const { return info_; }
  const char* debug_name() const { return debug_name_.get(); }
  JSHeapBroker* broker() const { return broker_.get(); }
  CompilationDependencies* depedencies() const { return dependencies_; }
  const AssemblerOptions& assembler_options() const {
    return assembler_options_;
  }
  JumpOptimizationInfo* jump_optimization_info() {
    if (!codegen_component_.has_value()) return nullptr;
    return codegen_component_->jump_optimization_info;
  }
  const CallDescriptor* builtin_call_descriptor() const {
    DCHECK(builtin_component_.has_value());
    return builtin_component_->call_descriptor;
  }
  std::optional<BytecodeHandlerData>& bytecode_handler_data() {
    DCHECK(builtin_component_.has_value());
    return builtin_component_->bytecode_handler_data;
  }

  bool has_graph() const {
    DCHECK_IMPLIES(graph_component_.has_value(),
                   graph_component_->graph != nullptr);
    return graph_component_.has_value();
  }
  ZoneWithName<kGraphZoneName>& graph_zone() { return graph_component_->zone; }
  turboshaft::Graph& graph() const { return *graph_component_->graph; }
  GraphComponent::Pointer<SourcePositionTable> source_positions() const {
    return graph_component_->source_positions;
  }
  GraphComponent::Pointer<NodeOriginTable> node_origins() const {
    if (!graph_component_.has_value()) return nullptr;
    return graph_component_->node_origins;
  }
  RegisterAllocationData* register_allocation_data() const {
    return register_component_->allocation_data;
  }
  ZoneWithName<kRegisterAllocationZoneName>& register_allocation_zone() {
    return register_component_->zone;
  }
  CodeGenerator* code_generator() const {
    return codegen_component_->code_generator.get();
  }
  void set_code(MaybeIndirectHandle<Code> code) {
    DCHECK(code_.is_null());
    code_ = code;
  }
  MaybeIndirectHandle<Code> code() const { return code_; }
  InstructionSequence* sequence() const {
    return instruction_component_->sequence;
  }
  Frame* frame() const { return codegen_component_->frame; }
  CodeTracer* GetCodeTracer() const;
  size_t& max_unoptimized_frame_height() {
    return codegen_component_->max_unoptimized_frame_height;
  }
  size_t& max_pushed_argument_count() {
    return codegen_component_->max_pushed_argument_count;
  }
  RuntimeCallStats* runtime_call_stats() const { return runtime_call_stats_; }
  void set_runtime_call_stats(RuntimeCallStats* stats) {
    runtime_call_stats_ = stats;
  }

  // The {compilation_zone} outlives the entire compilation pipeline. It is
  // shared between all phases (including code gen where the graph zone is gone
  // already).
  ZoneWithName<kCompilationZoneName>& compilation_zone() {
    return compilation_zone_;
  }

  TurbofanPipelineStatistics* pipeline_statistics() const {
    return pipeline_statistics_;
  }
  void set_pipeline_statistics(
      TurbofanPipelineStatistics* pipeline_statistics) {
    pipeline_statistics_ = pipeline_statistics;
  }

#if V8_ENABLE_WEBASSEMBLY
  // Module-specific signature: type indices are only valid in the WasmModule*
  // they belong to.
  const wasm::FunctionSig* wasm_module_sig() const { return wasm_module_sig_; }

  // Canonicalized (module-independent) signature.
  const wasm::CanonicalSig* wasm_canonical_sig() const {
    return wasm_canonical_sig_;
  }

  const wasm::WasmModule* wasm_module() const { return wasm_module_; }

  bool wasm_shared() const { return wasm_shared_; }

  void SetIsWasmFunction(const wasm::WasmModule* module,
                         const wasm::FunctionSig* sig, bool shared) {
    wasm_module_ = module;
    wasm_module_sig_ = sig;
    wasm_shared_ = shared;
    DCHECK(pipeline_kind() == TurboshaftPipelineKind::kWasm ||
           pipeline_kind() == TurboshaftPipelineKind::kJSToWasm);
  }

  void SetIsWasmWrapper(const wasm::CanonicalSig* sig) {
    wasm_canonical_sig_ = sig;
    DCHECK(pipeline_kind() == TurboshaftPipelineKind::kWasm ||
           pipeline_kind() == TurboshaftPipelineKind::kJSToWasm);
  }

#ifdef V8_ENABLE_WASM_SIMD256_REVEC
  WasmRevecAnalyzer* wasm_revec_analyzer() const {
    DCHECK_NOT_NULL(wasm_revec_analyzer_);
    return wasm_revec_analyzer_;
  }

  void set_wasm_revec_analyzer(WasmRevecAnalyzer* wasm_revec_analyzer) {
    DCHECK_NULL(wasm_revec_analyzer_);
    wasm_revec_analyzer_ = wasm_revec_analyzer;
  }

  void clear_wasm_revec_analyzer() { wasm_revec_analyzer_ = nullptr; }
#endif  // V8_ENABLE_WASM_SIMD256_REVEC
#endif  // V8_ENABLE_WEBASSEMBLY

  bool is_wasm() const {
    return pipeline_kind() == TurboshaftPipelineKind::kWasm ||
           pipeline_kind() == TurboshaftPipelineKind::kJSToWasm;
  }
  bool is_js_to_wasm() const {
    return pipeline_kind() == TurboshaftPipelineKind::kJSToWasm;
  }

  void InitializeFrameData(CallDescriptor* call_descriptor) {
    DCHECK(codegen_component_.has_value());
    DCHECK_NULL(codegen_component_->frame);
    int fixed_frame_size = 0;
    if (call_descriptor != nullptr) {
      fixed_frame_size =
          call_descriptor->CalculateFixedFrameSize(info()->code_kind());
    }
    codegen_component_->frame = codegen_component_->zone.New<Frame>(
        fixed_frame_size, codegen_component_->zone);
    if (codegen_component_->osr_helper) {
      codegen_component_->osr_helper->SetupFrame(codegen_component_->frame);
    }
  }

  void set_source_position_output(std::string source_position_output) {
    source_position_output_ = std::move(source_position_output);
  }
  std::string source_position_output() const { return source_position_output_; }

  bool graph_has_special_rpo() const {
    return graph_component_->graph_has_special_rpo;
  }
  void set_graph_has_special_rpo() {
    graph_component_->graph_has_special_rpo = true;
  }

 private:
  ZoneStats* zone_stats_;
  // The {compilation_zone_} outlives the entire compilation pipeline. It is
  // shared between all phases (including code gen where the graph zone is gone
  // already).
  ZoneWithName<kCompilationZoneName> compilation_zone_;
  TurboshaftPipelineKind pipeline_kind_;
  Isolate* const isolate_ = nullptr;
  OptimizedCompilationInfo* info_ = nullptr;
  std::unique_ptr<char[]> debug_name_;
  // TODO(nicohartmann): Use unique_ptr once TurboFan's pipeline data is gone.
  std::shared_ptr<JSHeapBroker> broker_;
  TurbofanPipelineStatistics* pipeline_statistics_ = nullptr;
  CompilationDependencies* dependencies_ = nullptr;
  int start_source_position_ = kNoSourcePosition;
  const AssemblerOptions assembler_options_;
  MaybeIndirectHandle<Code> code_;
  std::string source_position_output_;
  RuntimeCallStats* runtime_call_stats_ = nullptr;
  // Components
  std::optional<BuiltinComponent> builtin_component_;
  std::optional<GraphComponent> graph_component_;
  std::optional<CodegenComponent> codegen_component_;
  std::optional<InstructionComponent> instruction_component_;
  std::optional<RegisterComponent> register_component_;

#if V8_ENABLE_WEBASSEMBLY
  // TODO(14108): Consider splitting wasm members into its own WasmPipelineData
  // if we need many of them.
  const wasm::FunctionSig* wasm_module_sig_ = nullptr;
  const wasm::CanonicalSig* wasm_canonical_sig_ = nullptr;
  const wasm::WasmModule* wasm_module_ = nullptr;
  bool wasm_shared_ = false;
#ifdef V8_ENABLE_WASM_SIMD256_REVEC

  WasmRevecAnalyzer* wasm_revec_analyzer_ = nullptr;
#endif  // V8_ENABLE_WASM_SIMD256_REVEC
#endif  // V8_ENABLE_WEBASSEMBLY
};

void PrintTurboshaftGraph(PipelineData* data, Zone* temp_zone,
                          CodeTracer* code_tracer, const char* phase_name);
void PrintTurboshaftGraphForTurbolizer(std::ofstream& stream,
                                       const Graph& graph,
                                       const char* phase_name,
                                       NodeOriginTable* node_origins,
                                       Zone* temp_zone);

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_COMPILER_TURBOSHAFT_PHASE_H_

"""

```
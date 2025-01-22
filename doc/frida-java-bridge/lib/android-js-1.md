Response:
### 功能归纳

`frida-java-bridge/lib/android.js` 是 Frida 工具中用于与 Android ART（Android Runtime）交互的 JavaScript 模块。它主要用于动态插桩（Dynamic Instrumentation），允许开发者在运行时修改和监控 Android 应用程序的行为。以下是该文件的主要功能归纳：

1. **ART 运行时信息获取**：
   - 获取 Android 系统的 API 级别、版本号、代号等信息。
   - 获取 ART 运行时中的关键数据结构（如 `ClassLinker`、`ArtMethod`、`ArtThread` 等）的偏移量和字段信息。

2. **ART 方法插桩**：
   - 通过解析 ART 方法的结构，获取方法的 JNI 代码、快速代码（Quick Code）等关键信息。
   - 支持替换 ART 方法的实现，允许开发者拦截和修改方法的执行逻辑。

3. **ART 线程管理**：
   - 获取当前 ART 线程的状态信息，如异常、堆栈帧等。
   - 支持挂起和恢复所有 ART 线程，以便在安全的环境中进行调试和插桩。

4. **ART 堆栈遍历**：
   - 提供堆栈遍历功能，允许开发者遍历当前线程的调用栈，获取每个栈帧的方法信息。
   - 支持获取当前栈帧的快速代码指针、方法头等信息。

5. **ART 方法替换与拦截**：
   - 提供方法替换机制，允许开发者将原始方法替换为自定义实现。
   - 支持在方法调用时进行拦截，修改方法参数或返回值。

6. **ART 快速代码解析**：
   - 解析 ART 快速代码（Quick Code）的跳转指令，获取目标地址。
   - 支持不同架构（如 ARM、ARM64、x86、x64）的快速代码解析。

7. **ART 方法调用链管理**：
   - 管理方法调用链，确保在方法替换后，调用链的正确性。
   - 提供方法调用链的检查和修复功能。

8. **ART 垃圾回收（GC）相关操作**：
   - 监控 ART 垃圾回收过程，确保在 GC 过程中方法替换的正确性。
   - 提供 GC 阶段的回调机制，允许开发者在 GC 过程中执行自定义逻辑。

### 二进制底层与 Linux 内核相关

该文件主要涉及 Android ART 运行时的内部实现，与 Linux 内核的交互较少。不过，它通过直接操作内存和指针来访问 ART 运行时的数据结构，这涉及到底层的二进制操作。例如：

- **内存读取与写入**：通过 `Memory.readPointer()` 和 `Memory.writePointer()` 等函数直接读取和写入内存中的指针数据。
- **指令解析**：解析 ARM、ARM64、x86、x64 等架构的机器指令，获取跳转目标地址。

### LLDB 调试示例

假设我们要复现 `getArtQuickEntrypointFromTrampoline` 函数的功能，即通过解析快速代码的跳转指令获取目标地址。我们可以使用 LLDB 的 Python 脚本来实现类似的功能。

```python
import lldb

def get_quick_entrypoint_from_trampoline(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 获取 trampoline 地址
    trampoline_addr = frame.FindVariable("trampoline").GetValueAsUnsigned()

    # 读取 trampoline 处的指令
    error = lldb.SBError()
    insn_bytes = process.ReadMemory(trampoline_addr, 4, error)
    if error.Fail():
        result.AppendMessage("Failed to read memory: {}".format(error.GetCString()))
        return

    # 解析指令（假设是 ARM 架构的 LDR 指令）
    if insn_bytes[0] == 0x68 and insn_bytes[1] == 0xB0:  # LDR R0, [R6, #8]
        offset = insn_bytes[2]  # 偏移量
        target_addr = trampoline_addr + offset
        result.AppendMessage("Target address: 0x{:x}".format(target_addr))
    else:
        result.AppendMessage("Unsupported instruction")

# 注册 LLDB 命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f get_quick_entrypoint_from_trampoline.get_quick_entrypoint_from_trampoline get_quick_entrypoint')
```

### 假设输入与输出

假设输入是一个快速代码的跳转指令（如 ARM 的 `LDR R0, [R6, #8]`），输出是该指令的目标地址。

- **输入**：`LDR R0, [R6, #8]`（机器码为 `0xB068`）
- **输出**：`0x12345678`（假设 `R6 + 8` 的值为 `0x12345678`）

### 常见使用错误

1. **错误的 API 级别**：如果用户提供的 Android API 级别与目标设备不匹配，可能会导致获取的偏移量错误，进而导致内存访问错误。
   - **示例**：用户在使用 `getArtClassLinkerSpec` 时，提供了错误的 API 级别，导致无法正确获取 `ClassLinker` 的偏移量。

2. **内存访问越界**：在直接操作内存时，如果偏移量计算错误，可能会导致访问越界，引发崩溃。
   - **示例**：在 `tryGetArtClassLinkerSpec` 函数中，如果 `offset` 计算错误，可能会导致访问无效的内存地址。

3. **方法替换冲突**：如果多个脚本尝试替换同一个方法，可能会导致冲突，导致替换失败或行为异常。
   - **示例**：两个不同的 Frida 脚本都尝试替换 `artQuickGenericJniTrampoline`，可能会导致其中一个脚本的替换失败。

### 用户操作路径

1. **启动 Frida**：用户启动 Frida 并附加到目标 Android 进程。
2. **加载脚本**：用户加载 `frida-java-bridge/lib/android.js` 脚本。
3. **调用 API**：用户调用脚本中的 API，如 `getArtClassLinkerSpec` 或 `getArtQuickEntrypointFromTrampoline`，以获取 ART 运行时的信息或进行方法插桩。
4. **调试与监控**：用户通过 Frida 的交互式控制台或脚本监控和修改目标进程的行为。

### 调试线索

1. **内存访问错误**：如果用户在调试过程中遇到内存访问错误，可以检查偏移量计算是否正确，或者 API 级别是否匹配。
2. **方法替换失败**：如果方法替换失败，可以检查是否有其他脚本已经替换了该方法，或者目标方法是否存在于当前 ART 运行时中。
3. **指令解析错误**：如果快速代码解析失败，可以检查目标架构是否正确，或者指令是否被修改。

通过以上步骤和调试线索，用户可以有效地使用 `frida-java-bridge/lib/android.js` 进行 Android 应用程序的动态插桩和调试。
Prompt: 
```
这是目录为frida-java-bridge/lib/android.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第2部分，共5部分，请归纳一下它的功能

"""
 } = prevInsn;

  if ((mnemonic === 'cmp' && prevMnemonic === 'ldr') || (mnemonic === 'bl' && prevMnemonic === 'str')) {
    return prevInsn.operands[1].value.disp;
  }

  return null;
}

function _getArtInstrumentationSpec () {
  const deoptimizationEnabledOffsets = {
    '4-21': 136,
    '4-22': 136,
    '4-23': 172,
    '4-24': 196,
    '4-25': 196,
    '4-26': 196,
    '4-27': 196,
    '4-28': 212,
    '4-29': 172,
    '4-30': 180,
    '8-21': 224,
    '8-22': 224,
    '8-23': 296,
    '8-24': 344,
    '8-25': 344,
    '8-26': 352,
    '8-27': 352,
    '8-28': 392,
    '8-29': 328,
    '8-30': 336
  };

  const deoptEnabledOffset = deoptimizationEnabledOffsets[`${pointerSize}-${getAndroidApiLevel()}`];
  if (deoptEnabledOffset === undefined) {
    throw new Error('Unable to determine Instrumentation field offsets');
  }

  return {
    offset: {
      forcedInterpretOnly: 4,
      deoptimizationEnabled: deoptEnabledOffset
    }
  };
}

function getArtClassLinkerSpec (runtime, runtimeSpec) {
  const spec = tryGetArtClassLinkerSpec(runtime, runtimeSpec);
  if (spec === null) {
    throw new Error('Unable to determine ClassLinker field offsets');
  }
  return spec;
}

function tryGetArtClassLinkerSpec (runtime, runtimeSpec) {
  if (cachedArtClassLinkerSpec !== null) {
    return cachedArtClassLinkerSpec;
  }

  /*
   * On Android 5.x:
   *
   * class ClassLinker {
   * ...
   * InternTable* intern_table_;                          <-- We find this then calculate our way forwards
   * const void* portable_resolution_trampoline_;
   * const void* quick_resolution_trampoline_;
   * const void* portable_imt_conflict_trampoline_;
   * const void* quick_imt_conflict_trampoline_;
   * const void* quick_generic_jni_trampoline_;           <-- ...to this
   * const void* quick_to_interpreter_bridge_trampoline_;
   * ...
   * }
   *
   * On Android 6.x and above:
   *
   * class ClassLinker {
   * ...
   * InternTable* intern_table_;                          <-- We find this then calculate our way forwards
   * const void* quick_resolution_trampoline_;
   * const void* quick_imt_conflict_trampoline_;
   * const void* quick_generic_jni_trampoline_;           <-- ...to this
   * const void* quick_to_interpreter_bridge_trampoline_;
   * ...
   * }
   */

  const { classLinker: classLinkerOffset, internTable: internTableOffset } = runtimeSpec.offset;
  const classLinker = runtime.add(classLinkerOffset).readPointer();
  const internTable = runtime.add(internTableOffset).readPointer();

  const startOffset = (pointerSize === 4) ? 100 : 200;
  const endOffset = startOffset + (100 * pointerSize);

  const apiLevel = getAndroidApiLevel();

  let spec = null;

  for (let offset = startOffset; offset !== endOffset; offset += pointerSize) {
    const value = classLinker.add(offset).readPointer();
    if (value.equals(internTable)) {
      let delta;
      if (apiLevel >= 30 || getAndroidCodename() === 'R') {
        delta = 6;
      } else if (apiLevel >= 29) {
        delta = 4;
      } else if (apiLevel >= 23) {
        delta = 3;
      } else {
        delta = 5;
      }

      const quickGenericJniTrampolineOffset = offset + (delta * pointerSize);

      let quickResolutionTrampolineOffset;
      if (apiLevel >= 23) {
        quickResolutionTrampolineOffset = quickGenericJniTrampolineOffset - (2 * pointerSize);
      } else {
        quickResolutionTrampolineOffset = quickGenericJniTrampolineOffset - (3 * pointerSize);
      }

      spec = {
        offset: {
          quickResolutionTrampoline: quickResolutionTrampolineOffset,
          quickImtConflictTrampoline: quickGenericJniTrampolineOffset - pointerSize,
          quickGenericJniTrampoline: quickGenericJniTrampolineOffset,
          quickToInterpreterBridgeTrampoline: quickGenericJniTrampolineOffset + pointerSize
        }
      };

      break;
    }
  }

  if (spec !== null) {
    cachedArtClassLinkerSpec = spec;
  }

  return spec;
}

function getArtClassSpec (vm) {
  let apiLevel;
  try {
    apiLevel = getAndroidApiLevel();
  } catch (e) {
    return null;
  }

  if (apiLevel < 24) {
    return null;
  }

  let base, cmo;
  if (apiLevel >= 26) {
    base = 40;
    cmo = 116;
  } else {
    base = 56;
    cmo = 124;
  }

  return {
    offset: {
      ifields: base,
      methods: base + 8,
      sfields: base + 16,
      copiedMethodsOffset: cmo
    }
  };
}

function _getArtMethodSpec (vm) {
  const api = getApi();
  let spec;

  vm.perform(env => {
    const process = env.findClass('android/os/Process');
    const getElapsedCpuTime = unwrapMethodId(env.getStaticMethodId(process, 'getElapsedCpuTime', '()J'));
    env.deleteLocalRef(process);

    const runtimeModule = Process.getModuleByName('libandroid_runtime.so');
    const runtimeStart = runtimeModule.base;
    const runtimeEnd = runtimeStart.add(runtimeModule.size);

    const apiLevel = getAndroidApiLevel();

    const entrypointFieldSize = (apiLevel <= 21) ? 8 : pointerSize;

    const expectedAccessFlags = kAccPublic | kAccStatic | kAccFinal | kAccNative;
    const relevantAccessFlagsMask = ~(kAccFastInterpreterToInterpreterInvoke | kAccPublicApi | kAccNterpInvokeFastPathFlag) >>> 0;

    let jniCodeOffset = null;
    let accessFlagsOffset = null;
    let remaining = 2;
    for (let offset = 0; offset !== 64 && remaining !== 0; offset += 4) {
      const field = getElapsedCpuTime.add(offset);

      if (jniCodeOffset === null) {
        const address = field.readPointer();
        if (address.compare(runtimeStart) >= 0 && address.compare(runtimeEnd) < 0) {
          jniCodeOffset = offset;
          remaining--;
        }
      }

      if (accessFlagsOffset === null) {
        const flags = field.readU32();
        if ((flags & relevantAccessFlagsMask) === expectedAccessFlags) {
          accessFlagsOffset = offset;
          remaining--;
        }
      }
    }

    if (remaining !== 0) {
      throw new Error('Unable to determine ArtMethod field offsets');
    }

    const quickCodeOffset = jniCodeOffset + entrypointFieldSize;

    const size = (apiLevel <= 21) ? (quickCodeOffset + 32) : (quickCodeOffset + pointerSize);

    spec = {
      size,
      offset: {
        jniCode: jniCodeOffset,
        quickCode: quickCodeOffset,
        accessFlags: accessFlagsOffset
      }
    };

    if ('artInterpreterToCompiledCodeBridge' in api) {
      spec.offset.interpreterCode = jniCodeOffset - entrypointFieldSize;
    }
  });

  return spec;
}

function getArtFieldSpec (vm) {
  const apiLevel = getAndroidApiLevel();

  if (apiLevel >= 23) {
    return {
      size: 16,
      offset: {
        accessFlags: 4
      }
    };
  }

  if (apiLevel >= 21) {
    return {
      size: 24,
      offset: {
        accessFlags: 12
      }
    };
  }

  return null;
}

function _getArtThreadSpec (vm) {
  /*
   * bool32_t is_exception_reported_to_instrumentation_; <-- We need this on API level <= 22
   * ...
   * mirror::Throwable* exception;                       <-- ...and this on all versions
   * uint8_t* stack_end;
   * ManagedStack managed_stack;
   * uintptr_t* suspend_trigger;
   * JNIEnvExt* jni_env;                                 <-- We find this then calculate our way backwards/forwards
   * JNIEnvExt* tmp_jni_env;                             <-- API level >= 23
   * Thread* self;
   * mirror::Object* opeer;
   * jobject jpeer;
   * uint8_t* stack_begin;
   * size_t stack_size;
   * ThrowLocation throw_location;                       <-- ...and this on API level <= 22
   * union DepsOrStackTraceSample {
   *   DepsOrStackTraceSample() {
   *     verifier_deps = nullptr;
   *     stack_trace_sample = nullptr;
   *   }
   *   std::vector<ArtMethod*>* stack_trace_sample;
   *   verifier::VerifierDeps* verifier_deps;
   * } deps_or_stack_trace_sample;
   * Thread* wait_next;
   * mirror::Object* monitor_enter_object;
   * BaseHandleScope* top_handle_scope;                  <-- ...and to this on all versions
   */

  const apiLevel = getAndroidApiLevel();

  let spec;

  vm.perform(env => {
    const threadHandle = getArtThreadFromEnv(env);
    const envHandle = env.handle;

    let isExceptionReportedOffset = null;
    let exceptionOffset = null;
    let throwLocationOffset = null;
    let topHandleScopeOffset = null;
    let managedStackOffset = null;
    let selfOffset = null;

    for (let offset = 144; offset !== 256; offset += pointerSize) {
      const field = threadHandle.add(offset);

      const value = field.readPointer();
      if (value.equals(envHandle)) {
        exceptionOffset = offset - (6 * pointerSize);
        managedStackOffset = offset - (4 * pointerSize);
        selfOffset = offset + (2 * pointerSize);
        if (apiLevel <= 22) {
          exceptionOffset -= pointerSize;

          isExceptionReportedOffset = exceptionOffset - pointerSize - (9 * 8) - (3 * 4);

          throwLocationOffset = offset + (6 * pointerSize);

          managedStackOffset -= pointerSize;

          selfOffset -= pointerSize;
        }

        topHandleScopeOffset = offset + (9 * pointerSize);
        if (apiLevel <= 22) {
          topHandleScopeOffset += (2 * pointerSize) + 4;
          if (pointerSize === 8) {
            topHandleScopeOffset += 4;
          }
        }
        if (apiLevel >= 23) {
          topHandleScopeOffset += pointerSize;
        }

        break;
      }
    }

    if (topHandleScopeOffset === null) {
      throw new Error('Unable to determine ArtThread field offsets');
    }

    spec = {
      offset: {
        isExceptionReportedToInstrumentation: isExceptionReportedOffset,
        exception: exceptionOffset,
        throwLocation: throwLocationOffset,
        topHandleScope: topHandleScopeOffset,
        managedStack: managedStackOffset,
        self: selfOffset
      }
    };
  });

  return spec;
}

function _getArtManagedStackSpec () {
  const apiLevel = getAndroidApiLevel();

  if (apiLevel >= 23) {
    return {
      offset: {
        topQuickFrame: 0,
        link: pointerSize
      }
    };
  } else {
    return {
      offset: {
        topQuickFrame: 2 * pointerSize,
        link: 0
      }
    };
  }
}

const artQuickTrampolineParsers = {
  ia32: parseArtQuickTrampolineX86,
  x64: parseArtQuickTrampolineX86,
  arm: parseArtQuickTrampolineArm,
  arm64: parseArtQuickTrampolineArm64
};

function getArtQuickEntrypointFromTrampoline (trampoline, vm) {
  let address;

  vm.perform(env => {
    const thread = getArtThreadFromEnv(env);

    const tryParse = artQuickTrampolineParsers[Process.arch];

    const insn = Instruction.parse(trampoline);

    const offset = tryParse(insn);
    if (offset !== null) {
      address = thread.add(offset).readPointer();
    } else {
      address = trampoline;
    }
  });

  return address;
}

function parseArtQuickTrampolineX86 (insn) {
  if (insn.mnemonic === 'jmp') {
    return insn.operands[0].value.disp;
  }

  return null;
}

function parseArtQuickTrampolineArm (insn) {
  if (insn.mnemonic === 'ldr.w') {
    return insn.operands[1].value.disp;
  }

  return null;
}

function parseArtQuickTrampolineArm64 (insn) {
  if (insn.mnemonic === 'ldr') {
    return insn.operands[1].value.disp;
  }

  return null;
}

function getArtThreadFromEnv (env) {
  return env.handle.add(pointerSize).readPointer();
}

function _getAndroidVersion () {
  return getAndroidSystemProperty('ro.build.version.release');
}

function _getAndroidCodename () {
  return getAndroidSystemProperty('ro.build.version.codename');
}

function _getAndroidApiLevel () {
  return parseInt(getAndroidSystemProperty('ro.build.version.sdk'), 10);
}

let systemPropertyGet = null;
const PROP_VALUE_MAX = 92;

function getAndroidSystemProperty (name) {
  if (systemPropertyGet === null) {
    systemPropertyGet = new NativeFunction(Module.getExportByName('libc.so', '__system_property_get'), 'int', ['pointer', 'pointer'], nativeFunctionOptions);
  }
  const buf = Memory.alloc(PROP_VALUE_MAX);
  systemPropertyGet(Memory.allocUtf8String(name), buf);
  return buf.readUtf8String();
}

function withRunnableArtThread (vm, env, fn) {
  const perform = getArtThreadStateTransitionImpl(vm, env);

  const id = getArtThreadFromEnv(env).toString();
  artThreadStateTransitions[id] = fn;

  perform(env.handle);

  if (artThreadStateTransitions[id] !== undefined) {
    delete artThreadStateTransitions[id];
    throw new Error('Unable to perform state transition; please file a bug');
  }
}

function _getArtThreadStateTransitionImpl (vm, env) {
  const callback = new NativeCallback(onThreadStateTransitionComplete, 'void', ['pointer']);
  return makeArtThreadStateTransitionImpl(vm, env, callback);
}

function onThreadStateTransitionComplete (thread) {
  const id = thread.toString();

  const fn = artThreadStateTransitions[id];
  delete artThreadStateTransitions[id];
  fn(thread);
}

function withAllArtThreadsSuspended (fn) {
  const api = getApi();

  const threadList = api.artThreadList;
  const longSuspend = false;
  api['art::ThreadList::SuspendAll'](threadList, Memory.allocUtf8String('frida'), longSuspend ? 1 : 0);
  try {
    fn();
  } finally {
    api['art::ThreadList::ResumeAll'](threadList);
  }
}

class ArtClassVisitor {
  constructor (visit) {
    const visitor = Memory.alloc(4 * pointerSize);

    const vtable = visitor.add(pointerSize);
    visitor.writePointer(vtable);

    const onVisit = new NativeCallback((self, klass) => {
      return visit(klass) === true ? 1 : 0;
    }, 'bool', ['pointer', 'pointer']);
    vtable.add(2 * pointerSize).writePointer(onVisit);

    this.handle = visitor;
    this._onVisit = onVisit;
  }
}

function makeArtClassVisitor (visit) {
  const api = getApi();

  if (api['art::ClassLinker::VisitClasses'] instanceof NativeFunction) {
    return new ArtClassVisitor(visit);
  }

  return new NativeCallback(klass => {
    return visit(klass) === true ? 1 : 0;
  }, 'bool', ['pointer', 'pointer']);
}

class ArtClassLoaderVisitor {
  constructor (visit) {
    const visitor = Memory.alloc(4 * pointerSize);

    const vtable = visitor.add(pointerSize);
    visitor.writePointer(vtable);

    const onVisit = new NativeCallback((self, klass) => {
      visit(klass);
    }, 'void', ['pointer', 'pointer']);
    vtable.add(2 * pointerSize).writePointer(onVisit);

    this.handle = visitor;
    this._onVisit = onVisit;
  }
}

function makeArtClassLoaderVisitor (visit) {
  return new ArtClassLoaderVisitor(visit);
}

const WalkKind = {
  'include-inlined-frames': 0,
  'skip-inlined-frames': 1
};

class ArtStackVisitor {
  constructor (thread, context, walkKind, numFrames = 0, checkSuspended = true) {
    const api = getApi();

    const baseSize = 512; /* Up to 488 bytes on 64-bit Android Q. */
    const vtableSize = 3 * pointerSize;

    const visitor = Memory.alloc(baseSize + vtableSize);

    api['art::StackVisitor::StackVisitor'](visitor, thread, context, WalkKind[walkKind], numFrames,
      checkSuspended ? 1 : 0);

    const vtable = visitor.add(baseSize);
    visitor.writePointer(vtable);

    const onVisitFrame = new NativeCallback(this._visitFrame.bind(this), 'bool', ['pointer']);
    vtable.add(2 * pointerSize).writePointer(onVisitFrame);

    this.handle = visitor;
    this._onVisitFrame = onVisitFrame;

    const curShadowFrame = visitor.add((pointerSize === 4) ? 12 : 24);
    this._curShadowFrame = curShadowFrame;
    this._curQuickFrame = curShadowFrame.add(pointerSize);
    this._curQuickFramePc = curShadowFrame.add(2 * pointerSize);
    this._curOatQuickMethodHeader = curShadowFrame.add(3 * pointerSize);

    this._getMethodImpl = api['art::StackVisitor::GetMethod'];
    this._descLocImpl = api['art::StackVisitor::DescribeLocation'];
    this._getCQFIImpl = api['art::StackVisitor::GetCurrentQuickFrameInfo'];
  }

  walkStack (includeTransitions = false) {
    getApi()['art::StackVisitor::WalkStack'](this.handle, includeTransitions ? 1 : 0);
  }

  _visitFrame () {
    return this.visitFrame() ? 1 : 0;
  }

  visitFrame () {
    throw new Error('Subclass must implement visitFrame');
  }

  getMethod () {
    const methodHandle = this._getMethodImpl(this.handle);
    if (methodHandle.isNull()) {
      return null;
    }
    return new ArtMethod(methodHandle);
  }

  getCurrentQuickFramePc () {
    return this._curQuickFramePc.readPointer();
  }

  getCurrentQuickFrame () {
    return this._curQuickFrame.readPointer();
  }

  getCurrentShadowFrame () {
    return this._curShadowFrame.readPointer();
  }

  describeLocation () {
    const result = new StdString();
    this._descLocImpl(result, this.handle);
    return result.disposeToString();
  }

  getCurrentOatQuickMethodHeader () {
    return this._curOatQuickMethodHeader.readPointer();
  }

  getCurrentQuickFrameInfo () {
    return this._getCQFIImpl(this.handle);
  }
}

class ArtMethod {
  constructor (handle) {
    this.handle = handle;
  }

  prettyMethod (withSignature = true) {
    const result = new StdString();
    getApi()['art::ArtMethod::PrettyMethod'](result, this.handle, withSignature ? 1 : 0);
    return result.disposeToString();
  }

  toString () {
    return `ArtMethod(handle=${this.handle})`;
  }
}

function makeArtQuickFrameInfoGetter (impl) {
  return function (self) {
    const result = Memory.alloc(12);

    getArtQuickFrameInfoGetterThunk(impl)(result, self);

    return {
      frameSizeInBytes: result.readU32(),
      coreSpillMask: result.add(4).readU32(),
      fpSpillMask: result.add(8).readU32()
    };
  };
}

function _getArtQuickFrameInfoGetterThunk (impl) {
  let thunk = NULL;
  switch (Process.arch) {
    case 'ia32':
      thunk = makeThunk(32, writer => {
        writer.putMovRegRegOffsetPtr('ecx', 'esp', 4); // result
        writer.putMovRegRegOffsetPtr('edx', 'esp', 8); // self
        writer.putCallAddressWithArguments(impl, ['ecx', 'edx']);

        // Restore callee's stack frame
        writer.putMovRegReg('esp', 'ebp');
        writer.putPopReg('ebp');

        writer.putRet();
      });
      break;
    case 'x64':
      thunk = makeThunk(32, writer => {
        writer.putPushReg('rdi'); // preserve result buffer pointer
        writer.putCallAddressWithArguments(impl, ['rsi']); // self
        writer.putPopReg('rdi');

        // Struct is stored by value in the rax and edx registers
        // Write struct to result buffer
        writer.putMovRegPtrReg('rdi', 'rax');
        writer.putMovRegOffsetPtrReg('rdi', 8, 'edx');

        writer.putRet();
      });
      break;
    case 'arm':
      thunk = makeThunk(16, writer => {
        // By calling convention, we pass a pointer for the result struct
        writer.putCallAddressWithArguments(impl, ['r0', 'r1']);
        writer.putPopRegs(['r0', 'lr']);
        writer.putMovRegReg('pc', 'lr');
      });
      break;
    case 'arm64':
      thunk = makeThunk(64, writer => {
        writer.putPushRegReg('x0', 'lr');
        writer.putCallAddressWithArguments(impl, ['x1']);
        writer.putPopRegReg('x2', 'lr');
        writer.putStrRegRegOffset('x0', 'x2', 0);
        writer.putStrRegRegOffset('w1', 'x2', 8);
        writer.putRet();
      });
      break;
  }
  return new NativeFunction(thunk, 'void', ['pointer', 'pointer'], nativeFunctionOptions);
}

const thunkRelocators = {
  ia32: global.X86Relocator,
  x64: global.X86Relocator,
  arm: global.ThumbRelocator,
  arm64: global.Arm64Relocator
};

const thunkWriters = {
  ia32: global.X86Writer,
  x64: global.X86Writer,
  arm: global.ThumbWriter,
  arm64: global.Arm64Writer
};

function makeThunk (size, write) {
  if (thunkPage === null) {
    thunkPage = Memory.alloc(Process.pageSize);
  }

  const thunk = thunkPage.add(thunkOffset);

  const arch = Process.arch;

  const Writer = thunkWriters[arch];
  Memory.patchCode(thunk, size, code => {
    const writer = new Writer(code, { pc: thunk });
    write(writer);
    writer.flush();
    if (writer.offset > size) {
      throw new Error(`Wrote ${writer.offset}, exceeding maximum of ${size}`);
    }
  });

  thunkOffset += size;

  return (arch === 'arm') ? thunk.or(1) : thunk;
}

function notifyArtMethodHooked (method, vm) {
  ensureArtKnowsHowToHandleMethodInstrumentation(vm);
  ensureArtKnowsHowToHandleReplacementMethods(vm);
}

function makeArtController (vm) {
  const threadOffsets = getArtThreadSpec(vm).offset;
  const managedStackOffsets = getArtManagedStackSpec().offset;

  const code = `
#include <gum/guminterceptor.h>

extern GMutex lock;
extern GHashTable * methods;
extern GHashTable * replacements;
extern gpointer last_seen_art_method;

extern gpointer get_oat_quick_method_header_impl (gpointer method, gpointer pc);

void
init (void)
{
  g_mutex_init (&lock);
  methods = g_hash_table_new_full (NULL, NULL, NULL, NULL);
  replacements = g_hash_table_new_full (NULL, NULL, NULL, NULL);
}

void
finalize (void)
{
  g_hash_table_unref (replacements);
  g_hash_table_unref (methods);
  g_mutex_clear (&lock);
}

gboolean
is_replacement_method (gpointer method)
{
  gboolean is_replacement;

  g_mutex_lock (&lock);

  is_replacement = g_hash_table_contains (replacements, method);

  g_mutex_unlock (&lock);

  return is_replacement;
}

gpointer
get_replacement_method (gpointer original_method)
{
  gpointer replacement_method;

  g_mutex_lock (&lock);

  replacement_method = g_hash_table_lookup (methods, original_method);

  g_mutex_unlock (&lock);

  return replacement_method;
}

void
set_replacement_method (gpointer original_method,
                        gpointer replacement_method)
{
  g_mutex_lock (&lock);

  g_hash_table_insert (methods, original_method, replacement_method);
  g_hash_table_insert (replacements, replacement_method, original_method);

  g_mutex_unlock (&lock);
}

void
delete_replacement_method (gpointer original_method)
{
  gpointer replacement_method;

  g_mutex_lock (&lock);

  replacement_method = g_hash_table_lookup (methods, original_method);
  if (replacement_method != NULL)
  {
    g_hash_table_remove (methods, original_method);
    g_hash_table_remove (replacements, replacement_method);
  }

  g_mutex_unlock (&lock);
}

gpointer
translate_method (gpointer method)
{
  gpointer translated_method;

  g_mutex_lock (&lock);

  translated_method = g_hash_table_lookup (replacements, method);

  g_mutex_unlock (&lock);

  return (translated_method != NULL) ? translated_method : method;
}

gpointer
find_replacement_method_from_quick_code (gpointer method,
                                         gpointer thread)
{
  gpointer replacement_method;
  gpointer managed_stack;
  gpointer top_quick_frame;
  gpointer link_managed_stack;
  gpointer * link_top_quick_frame;

  replacement_method = get_replacement_method (method);
  if (replacement_method == NULL)
    return NULL;

  /*
   * Stack check.
   *
   * Return NULL to indicate that the original method should be invoked, otherwise
   * return a pointer to the replacement ArtMethod.
   *
   * If the caller is our own JNI replacement stub, then a stack transition must
   * have been pushed onto the current thread's linked list.
   *
   * Therefore, we invoke the original method if the following conditions are met:
   *   1- The current managed stack is empty.
   *   2- The ArtMethod * inside the linked managed stack's top quick frame is the
   *      same as our replacement.
   */
  managed_stack = thread + ${threadOffsets.managedStack};
  top_quick_frame = *((gpointer *) (managed_stack + ${managedStackOffsets.topQuickFrame}));
  if (top_quick_frame != NULL)
    return replacement_method;

  link_managed_stack = *((gpointer *) (managed_stack + ${managedStackOffsets.link}));
  if (link_managed_stack == NULL)
    return replacement_method;

  link_top_quick_frame = GSIZE_TO_POINTER (*((gsize *) (link_managed_stack + ${managedStackOffsets.topQuickFrame})) & ~((gsize) 1));
  if (link_top_quick_frame == NULL || *link_top_quick_frame != replacement_method)
    return replacement_method;

  return NULL;
}

void
on_interpreter_do_call (GumInvocationContext * ic)
{
  gpointer method, replacement_method;

  method = gum_invocation_context_get_nth_argument (ic, 0);

  replacement_method = get_replacement_method (method);
  if (replacement_method != NULL)
    gum_invocation_context_replace_nth_argument (ic, 0, replacement_method);
}

gpointer
on_art_method_get_oat_quick_method_header (gpointer method,
                                           gpointer pc)
{
  if (is_replacement_method (method))
    return NULL;

  return get_oat_quick_method_header_impl (method, pc);
}

void
on_art_method_pretty_method (GumInvocationContext * ic)
{
  const guint this_arg_index = ${(Process.arch === 'arm64') ? 0 : 1};
  gpointer method;

  method = gum_invocation_context_get_nth_argument (ic, this_arg_index);
  if (method == NULL)
    gum_invocation_context_replace_nth_argument (ic, this_arg_index, last_seen_art_method);
  else
    last_seen_art_method = method;
}

void
on_leave_gc_concurrent_copying_copying_phase (GumInvocationContext * ic)
{
  GHashTableIter iter;
  gpointer hooked_method, replacement_method;

  g_mutex_lock (&lock);

  g_hash_table_iter_init (&iter, methods);
  while (g_hash_table_iter_next (&iter, &hooked_method, &replacement_method))
    *((uint32_t *) replacement_method) = *((uint32_t *) hooked_method);

  g_mutex_unlock (&lock);
}
`;

  const lockSize = 8;
  const methodsSize = pointerSize;
  const replacementsSize = pointerSize;
  const lastSeenArtMethodSize = pointerSize;

  const data = Memory.alloc(lockSize + methodsSize + replacementsSize + lastSeenArtMethodSize);

  const lock = data;
  const methods = lock.add(lockSize);
  const replacements = methods.add(methodsSize);
  const lastSeenArtMethod = replacements.add(replacementsSize);

  const getOatQuickMethodHeaderImpl = Module.findExportByName('libart.so',
    (pointerSize === 4)
      ? '_ZN3art9ArtMethod23GetOatQuickMethodHeaderEj'
      : '_ZN3art9ArtMethod23GetOatQuickMethodHeaderEm');

  const cm = new CModule(code, {
    lock,
    methods,
    replacements,
    last_seen_art_method: lastSeenArtMethod,
    get_oat_quick_method_header_impl: getOatQuickMethodHeaderImpl ?? ptr('0xdeadbeef')
  });

  const fastOptions = { exceptions: 'propagate', scheduling: 'exclusive' };

  return {
    handle: cm,
    replacedMethods: {
      isReplacement: new NativeFunction(cm.is_replacement_method, 'bool', ['pointer'], fastOptions),
      get: new NativeFunction(cm.get_replacement_method, 'pointer', ['pointer'], fastOptions),
      set: new NativeFunction(cm.set_replacement_method, 'void', ['pointer', 'pointer'], fastOptions),
      delete: new NativeFunction(cm.delete_replacement_method, 'void', ['pointer'], fastOptions),
      translate: new NativeFunction(cm.translate_method, 'pointer', ['pointer'], fastOptions),
      findReplacementFromQuickCode: cm.find_replacement_method_from_quick_code
    },
    getOatQuickMethodHeaderImpl,
    hooks: {
      Interpreter: {
        doCall: cm.on_interpreter_do_call
      },
      ArtMethod: {
        getOatQuickMethodHeader: cm.on_art_method_get_oat_quick_method_header,
        prettyMethod: cm.on_art_method_pretty_method
      },
      Gc: {
        copyingPhase: {
          onLeave: cm.on_leave_gc_concurrent_copying_copying_phase
        },
        runFlip: {
          onEnter: cm.on_leave_gc_concurrent_copying_copying_phase
        }
      }
    }
  };
}

function ensureArtKnowsHowToHandleMethodInstrumentation (vm) {
  if (taughtArtAboutMethodInstrumentation) {
    return;
  }
  taughtArtAboutMethodInstrumentation = true;

  instrumentArtQuickEntrypoints(vm);
  instrumentArtMethodInvocationFromInterpreter();
}

function instrumentArtQuickEntrypoints (vm) {
  const api = getApi();

  // Entrypoints that dispatch method invocation from the quick ABI.
  const quickEntrypoints = [
    api.artQuickGenericJniTrampoline,
    api.artQuickToInterpreterBridge,
    api.artQuickResolutionTrampoline
  ];

  quickEntrypoints.forEach(entrypoint => {
    Memory.protect(entrypoint, 32, 'rwx');

    const interceptor = new ArtQuickCodeInterceptor(entrypoint);
    interceptor.activate(vm);

    artQuickInterceptors.push(interceptor);
  });
}

function instrumentArtMethodInvocationFromInterpreter () {
  const apiLevel = getAndroidApiLevel();

  let artInterpreterDoCallExportRegex;
  if (apiLevel <= 22) {
    artInterpreterDoCallExportRegex = /^_ZN3art11interpreter6DoCallILb[0-1]ELb[0-1]EEEbPNS_6mirror9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE$/;
  } else if (apiLevel <= 33) {
    artInterpreterDoCallExportRegex = /^_ZN3art11interpreter6DoCallILb[0-1]ELb[0-1]EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE$/;
  } else {
    artInterpreterDoCallExportRegex = /^_ZN3art11interpreter6DoCallILb[0-1]EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtbPNS_6JValueE$/;
  }

  for (const exp of Module.enumerateExports('libart.so').filter(exp => artInterpreterDoCallExportRegex.test(exp.name))) {
    Interceptor.attach(exp.address, artController.hooks.Interpreter.doCall);
  }
}

function ensureArtKnowsHowToHandleReplacementMethods (vm) {
  if (taughtArtAboutReplacementMethods) {
    return;
  }
  taughtArtAboutReplacementMethods = true;

  if (!maybeInstrumentGetOatQuickMethodHeaderInlineCopies()) {
    const { getOatQuickMethodHeaderImpl } = artController;
    if (getOatQuickMethodHeaderImpl === null) {
      return;
    }

    try {
      Interceptor.replace(getOatQuickMethodHeaderImpl, artController.hooks.ArtMethod.getOatQuickMethodHeader);
    } catch (e) {
      /*
       * Already replaced by another script. For now we don't support replacing methods from multiple scripts,
       * but we'll allow users to try it if they're feeling adventurous.
       */
    }
  }

  const apiLevel = getAndroidApiLevel();

  const mayUseCollector = (apiLevel > 28)
    ? (type) => {
        const impl = Module.findExportByName('libart.so', '_ZNK3art2gc4Heap15MayUseCollectorENS0_13CollectorTypeE');
        if (impl === null) {
          return false;
        }
        return new NativeFunction(impl, 'bool', ['pointer', 'int'])(getApi().artHeap, type);
      }
    : () => false;
  const kCollectorTypeCMC = 3;

  if (mayUseCollector(kCollectorTypeCMC)) {
    Interceptor.attach(Module.getExportByName('libart.so', '_ZN3art6Thread15RunFlipFunctionEPS0_b'), artController.hooks.Gc.runFlip);
  } else {
    let copyingPhase = null;
    if (apiLevel > 28) {
      copyingPhase = Module.findExportByName('libart.so', '_ZN3art2gc9collector17ConcurrentCopying12CopyingPhaseEv');
    } else if (apiLevel > 22) {
      copyingPhase = Module.findExportByName('libart.so', '_ZN3art2gc9collector17ConcurrentCopying12MarkingPhaseEv');
    }
    if (copyingPhase !== null) {
      Interceptor.attach(copyingPhase, artController.hooks.Gc.copyingPhase);
    }
  }
}

const artGetOatQuickMethodHeaderInlinedCopyHandler = {
  arm: {
    signatures: [
      {
        pattern: [
          'b0 68', // ldr r0, [r6, #8]
          '01 30', // adds r0, #1
          '0c d0', // beq #0x16fcd4
          '1b 98', // ldr r0, [sp, #0x6c]
          ':',
          'c0 ff',
          'c0 ff',
          '00 ff',
          '00 2f'
        ],
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm
      },
      {
        pattern: [
          'd8 f8 08 00', // ldr r0, [r8, #8]
          '01 30', // adds r0, #1
          '0c d0', // beq #0x16fcd4
          '1b 98', // ldr r0, [sp, #0x6c]
          ':',
          'f0 ff ff 0f',
          'ff ff',
          '00 ff',
          '00 2f'
        ],
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm
      },
      {
        pattern: [
          'b0 68', // ldr r0, [r6, #8]
          '01 30', // adds r0, #1
          '40 f0 c3 80', // bne #0x203bf0
          '00 25', // movs r5, #0
          ':',
          'c0 ff',
          'c0 ff',
          'c0 fb 00 d0',
          'ff f8'
        ],
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm
      }
    ],
    instrument: instrumentGetOatQuickMethodHeaderInlinedCopyArm
  },
  arm64: {
    signatures: [
      {
        pattern: [
          /* e8 */ '0a 40 b9', // ldr w8, [x23, #0x8]
          '1f 05 00 31', // cmn w8, #0x1
          '40 01 00 54', // b.eq 0x2e4204
          '88 39 00 f0', // adrp x8, 0xa17000
          ':',
          /* 00 */ 'fc ff ff',
          '1f fc ff ff',
          '1f 00 00 ff',
          '00 00 00 9f'
        ],
        offset: 1,
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm64
      },
      {
        pattern: [
          /* e8 */ '0a 40 b9', // ldr w8, [x23, #0x8]
          '1f 05 00 31', // cmn w8, #0x1
          '01 34 00 54', // b.ne 0x3d8e50
          'e0 03 1f aa', // mov x0, xzr
          ':',
          /* 00 */ 'fc ff ff',
      
"""


```
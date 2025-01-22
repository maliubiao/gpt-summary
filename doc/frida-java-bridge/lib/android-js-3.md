Response:
### 功能归纳

`frida-java-bridge/lib/android.js` 是 Frida 工具中用于与 Android ART（Android Runtime）交互的核心模块。它主要用于在 Android 应用运行时动态修改和拦截 Java 方法的执行。以下是该文件的主要功能：

1. **ART 方法拦截与替换**：
   - 通过 `ArtMethodMangler` 类，实现对 ART 方法的拦截和替换。该类可以克隆 ART 方法、修改方法的访问标志、替换方法的实现代码等。
   - 通过 `ArtQuickCodeInterceptor` 类，实现对 ART 快速代码（Quick Code）的拦截和重定向。该类可以修改方法的入口点，将方法的执行重定向到自定义的 trampoline（跳板代码），从而实现方法拦截。

2. **Dalvik 方法拦截与替换**：
   - 通过 `DalvikMethodMangler` 类，实现对 Dalvik 方法的拦截和替换。该类可以修改方法的访问标志、JNI 桥接信息等，从而将方法的执行重定向到自定义的实现。

3. **ART 方法反优化**：
   - 通过 `deoptimizeMethod`、`deoptimizeEverything` 和 `deoptimizeBootImage` 函数，实现对 ART 方法的反优化。反优化可以将已编译的代码回退到解释执行模式，从而允许动态修改方法的实现。

4. **JDWP 调试支持**：
   - 通过 `JdwpSession` 类，实现对 JDWP（Java Debug Wire Protocol）的支持。该类可以启动 JDWP 调试会话，允许通过调试器与 Android 应用进行交互。

5. **ART 线程状态转换**：
   - 通过 `makeArtThreadStateTransitionImpl` 函数，实现对 ART 线程状态的转换。该函数可以确保在调用 ART 内部 API 时，线程处于正确的状态。

6. **底层代码重编译**：
   - 通过 `recompileExceptionClearForX86` 和 `recompileExceptionClearForArm` 函数，实现对 ART 内部函数（如 `ExceptionClear`）的代码重编译。这些函数可以将 ART 内部函数的代码复制并修改，从而允许在调用这些函数时执行自定义逻辑。

### 二进制底层与 Linux 内核相关

1. **代码重定向与 trampoline**：
   - `ArtQuickCodeInterceptor` 类通过修改方法的入口点，将方法的执行重定向到自定义的 trampoline。这个过程涉及到对二进制代码的直接修改，通常是通过写入跳转指令（如 `jmp`）来实现的。
   - 在 ARM64 架构中，`ArtQuickCodeInterceptor` 使用 `ADRP` 和 `ADD` 指令来计算跳转地址，并将跳转指令写入目标位置。

2. **内存操作**：
   - 通过 `Memory.dup`、`Memory.patchCode` 等函数，直接操作进程的内存空间。这些函数可以复制内存块、修改内存中的代码等。

3. **系统调用**：
   - 通过 `socketpair` 系统调用创建套接字对，用于 JDWP 调试会话的通信。

### LLDB 调试示例

假设我们想要使用 LLDB 来调试 `ArtQuickCodeInterceptor` 类的 `activate` 方法，以下是一个可能的 LLDB Python 脚本示例：

```python
import lldb

def activate_interceptor(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 获取 ArtQuickCodeInterceptor 实例的地址
    interceptor_ptr = frame.FindVariable("this").GetValueAsUnsigned()

    # 获取 quickCode 地址
    quick_code_ptr = frame.FindVariable("quickCode").GetValueAsUnsigned()

    # 获取 trampoline 地址
    trampoline_ptr = frame.FindVariable("trampoline").GetValueAsUnsigned()

    # 打印相关信息
    print(f"Interceptor instance: {hex(interceptor_ptr)}")
    print(f"Quick code address: {hex(quick_code_ptr)}")
    print(f"Trampoline address: {hex(trampoline_ptr)}")

    # 设置断点，观察 trampoline 的执行
    breakpoint = target.BreakpointCreateByAddress(trampoline_ptr)
    print(f"Breakpoint set at trampoline: {hex(trampoline_ptr)}")

# 注册 LLDB 命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f lldb_script.activate_interceptor activate_interceptor')
```

### 假设输入与输出

假设我们有一个 ART 方法 `com.example.MyClass.myMethod`，我们想要拦截并替换它的实现。

- **输入**：
  - 目标方法：`com.example.MyClass.myMethod`
  - 替换实现：自定义的 Native 函数 `my_custom_impl`

- **输出**：
  - 方法 `com.example.MyClass.myMethod` 的执行被重定向到 `my_custom_impl`。
  - 在方法执行时，`ArtQuickCodeInterceptor` 的 `activate` 方法被调用，trampoline 被成功设置。

### 用户操作与调试线索

1. **用户操作**：
   - 用户使用 Frida 脚本调用 `ArtMethodMangler.replace` 方法，传入目标方法和自定义实现。
   - Frida 脚本在目标进程中加载并执行，触发 `ArtQuickCodeInterceptor.activate` 方法。

2. **调试线索**：
   - 在 `ArtQuickCodeInterceptor.activate` 方法中，用户可以通过 LLDB 设置断点，观察 trampoline 的分配和写入过程。
   - 用户可以通过 LLDB 查看 `quickCode` 和 `trampoline` 的地址，确保代码重定向正确执行。

### 常见使用错误

1. **方法替换失败**：
   - 可能原因：目标方法的访问标志不允许替换，或者 ART 运行时版本不支持。
   - 解决方法：检查目标方法的访问标志，确保 `kAccNative` 和 `kAccCompileDontBother` 标志被正确设置。

2. **trampoline 分配失败**：
   - 可能原因：内存不足或 trampoline 分配器未初始化。
   - 解决方法：确保 trampoline 分配器已正确初始化，并检查内存分配是否成功。

3. **JDWP 调试会话启动失败**：
   - 可能原因：JDWP 端口被占用或权限不足。
   - 解决方法：检查端口配置，确保有足够的权限启动 JDWP 会话。

### 总结

`frida-java-bridge/lib/android.js` 提供了强大的功能，允许在 Android 应用运行时动态修改和拦截 Java 方法的执行。通过代码重定向、trampoline 和 JDWP 调试支持，用户可以深入分析和修改应用的运行时行为。
Prompt: 
```
这是目录为frida-java-bridge/lib/android.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第4部分，共5部分，请归纳一下它的功能

"""
,
  arm64: 16
};

class ArtQuickCodeInterceptor {
  constructor (quickCode) {
    this.quickCode = quickCode;
    this.quickCodeAddress = (Process.arch === 'arm')
      ? quickCode.and(THUMB_BIT_REMOVAL_MASK)
      : quickCode;

    this.redirectSize = 0;
    this.trampoline = null;
    this.overwrittenPrologue = null;
    this.overwrittenPrologueLength = 0;
  }

  _canRelocateCode (relocationSize, constraints) {
    const Writer = thunkWriters[Process.arch];
    const Relocator = thunkRelocators[Process.arch];

    const { quickCodeAddress } = this;

    const writer = new Writer(quickCodeAddress);
    const relocator = new Relocator(quickCodeAddress, writer);

    let offset;
    if (Process.arch === 'arm64') {
      let availableScratchRegs = new Set(['x16', 'x17']);

      do {
        const nextOffset = relocator.readOne();

        const nextScratchRegs = new Set(availableScratchRegs);
        const { read, written } = relocator.input.regsAccessed;
        for (const regs of [read, written]) {
          for (const reg of regs) {
            let name;
            if (reg.startsWith('w')) {
              name = 'x' + reg.substring(1);
            } else {
              name = reg;
            }
            nextScratchRegs.delete(name);
          }
        }
        if (nextScratchRegs.size === 0) {
          break;
        }

        offset = nextOffset;
        availableScratchRegs = nextScratchRegs;
      } while (offset < relocationSize && !relocator.eoi);

      constraints.availableScratchRegs = availableScratchRegs;
    } else {
      do {
        offset = relocator.readOne();
      } while (offset < relocationSize && !relocator.eoi);
    }

    return offset >= relocationSize;
  }

  _allocateTrampoline () {
    if (trampolineAllocator === null) {
      const trampolineSize = (pointerSize === 4) ? 128 : 256;
      trampolineAllocator = makeCodeAllocator(trampolineSize);
    }

    const maxRedirectSize = artQuickCodeHookRedirectSize[Process.arch];

    let redirectSize, spec;
    let alignment = 1;
    const constraints = {};
    if (pointerSize === 4 || this._canRelocateCode(maxRedirectSize, constraints)) {
      redirectSize = maxRedirectSize;

      spec = {};
    } else {
      let maxDistance;
      if (Process.arch === 'x64') {
        redirectSize = 5;
        maxDistance = X86_JMP_MAX_DISTANCE;
      } else if (Process.arch === 'arm64') {
        redirectSize = 8;
        maxDistance = ARM64_ADRP_MAX_DISTANCE;
        alignment = 4096;
      }

      spec = { near: this.quickCodeAddress, maxDistance };
    }

    this.redirectSize = redirectSize;
    this.trampoline = trampolineAllocator.allocateSlice(spec, alignment);

    return constraints;
  }

  _destroyTrampoline () {
    trampolineAllocator.freeSlice(this.trampoline);
  }

  activate (vm) {
    const constraints = this._allocateTrampoline();

    const { trampoline, quickCode, redirectSize } = this;

    const writeTrampoline = artQuickCodeReplacementTrampolineWriters[Process.arch];
    const prologueLength = writeTrampoline(trampoline, quickCode, redirectSize, constraints, vm);
    this.overwrittenPrologueLength = prologueLength;

    this.overwrittenPrologue = Memory.dup(this.quickCodeAddress, prologueLength);

    const writePrologue = artQuickCodePrologueWriters[Process.arch];
    writePrologue(quickCode, trampoline, redirectSize);
  }

  deactivate () {
    const { quickCodeAddress, overwrittenPrologueLength: prologueLength } = this;

    const Writer = thunkWriters[Process.arch];
    Memory.patchCode(quickCodeAddress, prologueLength, code => {
      const writer = new Writer(code, { pc: quickCodeAddress });

      const { overwrittenPrologue } = this;

      writer.putBytes(overwrittenPrologue.readByteArray(prologueLength));
      writer.flush();
    });

    this._destroyTrampoline();
  }
}

function isArtQuickEntrypoint (address) {
  const api = getApi();

  const { module: m, artClassLinker } = api;

  return address.equals(artClassLinker.quickGenericJniTrampoline) ||
      address.equals(artClassLinker.quickToInterpreterBridgeTrampoline) ||
      address.equals(artClassLinker.quickResolutionTrampoline) ||
      address.equals(artClassLinker.quickImtConflictTrampoline) ||
      (address.compare(m.base) >= 0 && address.compare(m.base.add(m.size)) < 0);
}

class ArtMethodMangler {
  constructor (opaqueMethodId) {
    const methodId = unwrapMethodId(opaqueMethodId);

    this.methodId = methodId;
    this.originalMethod = null;
    this.hookedMethodId = methodId;
    this.replacementMethodId = null;

    this.interceptor = null;
  }

  replace (impl, isInstanceMethod, argTypes, vm, api) {
    const { kAccCompileDontBother, artNterpEntryPoint } = api;

    this.originalMethod = fetchArtMethod(this.methodId, vm);

    const originalFlags = this.originalMethod.accessFlags;

    if ((originalFlags & kAccXposedHookedMethod) !== 0 && xposedIsSupported()) {
      const hookInfo = this.originalMethod.jniCode;
      this.hookedMethodId = hookInfo.add(2 * pointerSize).readPointer();
      this.originalMethod = fetchArtMethod(this.hookedMethodId, vm);
    }

    const { hookedMethodId } = this;

    const replacementMethodId = cloneArtMethod(hookedMethodId, vm);
    this.replacementMethodId = replacementMethodId;

    patchArtMethod(replacementMethodId, {
      jniCode: impl,
      accessFlags: ((originalFlags & ~(kAccCriticalNative | kAccFastNative | kAccNterpEntryPointFastPathFlag)) | kAccNative | kAccCompileDontBother) >>> 0,
      quickCode: api.artClassLinker.quickGenericJniTrampoline,
      interpreterCode: api.artInterpreterToCompiledCodeBridge
    }, vm);

    // Remove kAccFastInterpreterToInterpreterInvoke and kAccSkipAccessChecks to disable use_fast_path
    // in interpreter_common.h
    let hookedMethodRemovedFlags = kAccFastInterpreterToInterpreterInvoke | kAccSingleImplementation | kAccNterpEntryPointFastPathFlag;
    if ((originalFlags & kAccNative) === 0) {
      hookedMethodRemovedFlags |= kAccSkipAccessChecks;
    }

    patchArtMethod(hookedMethodId, {
      accessFlags: ((originalFlags & ~(hookedMethodRemovedFlags)) | kAccCompileDontBother) >>> 0
    }, vm);

    const quickCode = this.originalMethod.quickCode;

    // Replace Nterp quick entrypoints with art_quick_to_interpreter_bridge to force stepping out
    // of ART's next-generation interpreter and use the quick stub instead.
    if (artNterpEntryPoint !== undefined && quickCode.equals(artNterpEntryPoint)) {
      patchArtMethod(hookedMethodId, {
        quickCode: api.artQuickToInterpreterBridge
      }, vm);
    }

    if (!isArtQuickEntrypoint(quickCode)) {
      const interceptor = new ArtQuickCodeInterceptor(quickCode);
      interceptor.activate(vm);

      this.interceptor = interceptor;
    }

    artController.replacedMethods.set(hookedMethodId, replacementMethodId);

    notifyArtMethodHooked(hookedMethodId, vm);
  }

  revert (vm) {
    const { hookedMethodId, interceptor } = this;

    patchArtMethod(hookedMethodId, this.originalMethod, vm);

    artController.replacedMethods.delete(hookedMethodId);

    if (interceptor !== null) {
      interceptor.deactivate();

      this.interceptor = null;
    }
  }

  resolveTarget (wrapper, isInstanceMethod, env, api) {
    return this.hookedMethodId;
  }
}

function xposedIsSupported () {
  return getAndroidApiLevel() < 28;
}

function fetchArtMethod (methodId, vm) {
  const artMethodSpec = getArtMethodSpec(vm);
  const artMethodOffset = artMethodSpec.offset;
  return (['jniCode', 'accessFlags', 'quickCode', 'interpreterCode']
    .reduce((original, name) => {
      const offset = artMethodOffset[name];
      if (offset === undefined) {
        return original;
      }
      const address = methodId.add(offset);
      const read = (name === 'accessFlags') ? readU32 : readPointer;
      original[name] = read.call(address);
      return original;
    }, {}));
}

function patchArtMethod (methodId, patches, vm) {
  const artMethodSpec = getArtMethodSpec(vm);
  const artMethodOffset = artMethodSpec.offset;
  Object.keys(patches).forEach(name => {
    const offset = artMethodOffset[name];
    if (offset === undefined) {
      return;
    }
    const address = methodId.add(offset);
    const write = (name === 'accessFlags') ? writeU32 : writePointer;
    write.call(address, patches[name]);
  });
}

class DalvikMethodMangler {
  constructor (methodId) {
    this.methodId = methodId;
    this.originalMethod = null;
  }

  replace (impl, isInstanceMethod, argTypes, vm, api) {
    const { methodId } = this;

    this.originalMethod = Memory.dup(methodId, DVM_METHOD_SIZE);

    let argsSize = argTypes.reduce((acc, t) => (acc + t.size), 0);
    if (isInstanceMethod) {
      argsSize++;
    }

    /*
     * make method native (with kAccNative)
     * insSize and registersSize are set to arguments size
     */
    const accessFlags = (methodId.add(DVM_METHOD_OFFSET_ACCESS_FLAGS).readU32() | kAccNative) >>> 0;
    const registersSize = argsSize;
    const outsSize = 0;
    const insSize = argsSize;

    methodId.add(DVM_METHOD_OFFSET_ACCESS_FLAGS).writeU32(accessFlags);
    methodId.add(DVM_METHOD_OFFSET_REGISTERS_SIZE).writeU16(registersSize);
    methodId.add(DVM_METHOD_OFFSET_OUTS_SIZE).writeU16(outsSize);
    methodId.add(DVM_METHOD_OFFSET_INS_SIZE).writeU16(insSize);
    methodId.add(DVM_METHOD_OFFSET_JNI_ARG_INFO).writeU32(computeDalvikJniArgInfo(methodId));

    api.dvmUseJNIBridge(methodId, impl);
  }

  revert (vm) {
    Memory.copy(this.methodId, this.originalMethod, DVM_METHOD_SIZE);
  }

  resolveTarget (wrapper, isInstanceMethod, env, api) {
    const thread = env.handle.add(DVM_JNI_ENV_OFFSET_SELF).readPointer();

    let objectPtr;
    if (isInstanceMethod) {
      objectPtr = api.dvmDecodeIndirectRef(thread, wrapper.$h);
    } else {
      const h = wrapper.$borrowClassHandle(env);
      objectPtr = api.dvmDecodeIndirectRef(thread, h.value);
      h.unref(env);
    }

    let classObject;
    if (isInstanceMethod) {
      classObject = objectPtr.add(DVM_OBJECT_OFFSET_CLAZZ).readPointer();
    } else {
      classObject = objectPtr;
    }

    const classKey = classObject.toString(16);
    let entry = patchedClasses.get(classKey);
    if (entry === undefined) {
      const vtablePtr = classObject.add(DVM_CLASS_OBJECT_OFFSET_VTABLE);
      const vtableCountPtr = classObject.add(DVM_CLASS_OBJECT_OFFSET_VTABLE_COUNT);
      const vtable = vtablePtr.readPointer();
      const vtableCount = vtableCountPtr.readS32();

      const vtableSize = vtableCount * pointerSize;
      const shadowVtable = Memory.alloc(2 * vtableSize);
      Memory.copy(shadowVtable, vtable, vtableSize);
      vtablePtr.writePointer(shadowVtable);

      entry = {
        classObject,
        vtablePtr,
        vtableCountPtr,
        vtable,
        vtableCount,
        shadowVtable,
        shadowVtableCount: vtableCount,
        targetMethods: new Map()
      };
      patchedClasses.set(classKey, entry);
    }

    const methodKey = this.methodId.toString(16);
    let targetMethod = entry.targetMethods.get(methodKey);
    if (targetMethod === undefined) {
      targetMethod = Memory.dup(this.originalMethod, DVM_METHOD_SIZE);

      const methodIndex = entry.shadowVtableCount++;
      entry.shadowVtable.add(methodIndex * pointerSize).writePointer(targetMethod);
      targetMethod.add(DVM_METHOD_OFFSET_METHOD_INDEX).writeU16(methodIndex);
      entry.vtableCountPtr.writeS32(entry.shadowVtableCount);

      entry.targetMethods.set(methodKey, targetMethod);
    }

    return targetMethod;
  }
}

function computeDalvikJniArgInfo (methodId) {
  if (Process.arch !== 'ia32') {
    return DALVIK_JNI_NO_ARG_INFO;
  }

  // For the x86 ABI, valid hints should always be generated.
  const shorty = methodId.add(DVM_METHOD_OFFSET_SHORTY).readPointer().readCString();
  if (shorty === null || shorty.length === 0 || shorty.length > 0xffff) {
    return DALVIK_JNI_NO_ARG_INFO;
  }

  let returnType;
  switch (shorty[0]) {
    case 'V':
      returnType = DALVIK_JNI_RETURN_VOID;
      break;
    case 'F':
      returnType = DALVIK_JNI_RETURN_FLOAT;
      break;
    case 'D':
      returnType = DALVIK_JNI_RETURN_DOUBLE;
      break;
    case 'J':
      returnType = DALVIK_JNI_RETURN_S8;
      break;
    case 'Z':
    case 'B':
      returnType = DALVIK_JNI_RETURN_S1;
      break;
    case 'C':
      returnType = DALVIK_JNI_RETURN_U2;
      break;
    case 'S':
      returnType = DALVIK_JNI_RETURN_S2;
      break;
    default:
      returnType = DALVIK_JNI_RETURN_S4;
      break;
  }

  let hints = 0;
  for (let i = shorty.length - 1; i > 0; i--) {
    const ch = shorty[i];
    hints += (ch === 'D' || ch === 'J') ? 2 : 1;
  }

  return (returnType << DALVIK_JNI_RETURN_SHIFT) | hints;
}

function cloneArtMethod (method, vm) {
  const api = getApi();

  if (getAndroidApiLevel() < 23) {
    const thread = api['art::Thread::CurrentFromGdb']();
    return api['art::mirror::Object::Clone'](method, thread);
  }

  return Memory.dup(method, getArtMethodSpec(vm).size);
}

function deoptimizeMethod (vm, env, method) {
  requestDeoptimization(vm, env, kSelectiveDeoptimization, method);
}

function deoptimizeEverything (vm, env) {
  requestDeoptimization(vm, env, kFullDeoptimization);
}

function deoptimizeBootImage (vm, env) {
  const api = getApi();

  if (getAndroidApiLevel() < 26) {
    throw new Error('This API is only available on Android >= 8.0');
  }

  withRunnableArtThread(vm, env, thread => {
    api['art::Runtime::DeoptimizeBootImage'](api.artRuntime);
  });
}

function requestDeoptimization (vm, env, kind, method) {
  const api = getApi();

  if (getAndroidApiLevel() < 24) {
    throw new Error('This API is only available on Android >= 7.0');
  }

  withRunnableArtThread(vm, env, thread => {
    if (getAndroidApiLevel() < 30) {
      if (!api.isJdwpStarted()) {
        const session = startJdwp(api);
        jdwpSessions.push(session);
      }

      if (!api.isDebuggerActive()) {
        api['art::Dbg::GoActive']();
      }

      const request = Memory.alloc(8 + pointerSize);
      request.writeU32(kind);

      switch (kind) {
        case kFullDeoptimization:
          break;
        case kSelectiveDeoptimization:
          request.add(8).writePointer(method);
          break;
        default:
          throw new Error('Unsupported deoptimization kind');
      }

      api['art::Dbg::RequestDeoptimization'](request);

      api['art::Dbg::ManageDeoptimization']();
    } else {
      const instrumentation = api.artInstrumentation;
      if (instrumentation === null) {
        throw new Error('Unable to find Instrumentation class in ART; please file a bug');
      }

      const enableDeopt = api['art::Instrumentation::EnableDeoptimization'];
      if (enableDeopt !== undefined) {
        const deoptimizationEnabled = !!instrumentation.add(getArtInstrumentationSpec().offset.deoptimizationEnabled).readU8();
        if (!deoptimizationEnabled) {
          enableDeopt(instrumentation);
        }
      }

      switch (kind) {
        case kFullDeoptimization:
          api['art::Instrumentation::DeoptimizeEverything'](instrumentation, Memory.allocUtf8String('frida'));
          break;
        case kSelectiveDeoptimization:
          api['art::Instrumentation::Deoptimize'](instrumentation, method);
          break;
        default:
          throw new Error('Unsupported deoptimization kind');
      }
    }
  });
}

class JdwpSession {
  constructor () {
    /*
     * We partially stub out the ADB JDWP transport to ensure we always
     * succeed in starting JDWP. Failure will crash the process.
     */
    const acceptImpl = Module.getExportByName('libart.so', '_ZN3art4JDWP12JdwpAdbState6AcceptEv');
    const receiveClientFdImpl = Module.getExportByName('libart.so', '_ZN3art4JDWP12JdwpAdbState15ReceiveClientFdEv');

    const controlPair = makeSocketPair();
    const clientPair = makeSocketPair();

    this._controlFd = controlPair[0];
    this._clientFd = clientPair[0];

    let acceptListener = null;
    acceptListener = Interceptor.attach(acceptImpl, function (args) {
      const state = args[0];

      const controlSockPtr = Memory.scanSync(state.add(8252), 256, '00 ff ff ff ff 00')[0].address.add(1);

      /*
       * This will make JdwpAdbState::Accept() skip the control socket() and connect(),
       * and skip right to calling ReceiveClientFd(), replaced below.
       */
      controlSockPtr.writeS32(controlPair[1]);

      acceptListener.detach();
    });

    Interceptor.replace(receiveClientFdImpl, new NativeCallback(function (state) {
      Interceptor.revert(receiveClientFdImpl);

      return clientPair[1];
    }, 'int', ['pointer']));

    Interceptor.flush();

    this._handshakeRequest = this._performHandshake();
  }

  async _performHandshake () {
    const input = new UnixInputStream(this._clientFd, { autoClose: false });
    const output = new UnixOutputStream(this._clientFd, { autoClose: false });

    const handshakePacket = [0x4a, 0x44, 0x57, 0x50, 0x2d, 0x48, 0x61, 0x6e, 0x64, 0x73, 0x68, 0x61, 0x6b, 0x65];
    try {
      await output.writeAll(handshakePacket);
      await input.readAll(handshakePacket.length);
    } catch (e) {
    }
  }
}

function startJdwp (api) {
  const session = new JdwpSession();

  api['art::Dbg::SetJdwpAllowed'](1);

  const options = makeJdwpOptions();
  api['art::Dbg::ConfigureJdwp'](options);

  const startDebugger = api['art::InternalDebuggerControlCallback::StartDebugger'];
  if (startDebugger !== undefined) {
    startDebugger(NULL);
  } else {
    api['art::Dbg::StartJdwp']();
  }

  return session;
}

function makeJdwpOptions () {
  const kJdwpTransportAndroidAdb = getAndroidApiLevel() < 28 ? 2 : 3;
  const kJdwpPortFirstAvailable = 0;

  const transport = kJdwpTransportAndroidAdb;
  const server = true;
  const suspend = false;
  const port = kJdwpPortFirstAvailable;

  const size = 8 + STD_STRING_SIZE + 2;
  const result = Memory.alloc(size);
  result
    .writeU32(transport).add(4)
    .writeU8(server ? 1 : 0).add(1)
    .writeU8(suspend ? 1 : 0).add(1)
    .add(STD_STRING_SIZE) // We leave `host` zeroed, i.e. empty string
    .writeU16(port);
  return result;
}

function makeSocketPair () {
  if (socketpair === null) {
    socketpair = new NativeFunction(
      Module.getExportByName('libc.so', 'socketpair'),
      'int',
      ['int', 'int', 'int', 'pointer']);
  }

  const buf = Memory.alloc(8);
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, buf) === -1) {
    throw new Error('Unable to create socketpair for JDWP');
  }

  return [
    buf.readS32(),
    buf.add(4).readS32()
  ];
}

function makeAddGlobalRefFallbackForAndroid5 (api) {
  const offset = getArtVMSpec().offset;
  const lock = api.vm.add(offset.globalsLock);
  const table = api.vm.add(offset.globals);

  const add = api['art::IndirectReferenceTable::Add'];
  const acquire = api['art::ReaderWriterMutex::ExclusiveLock'];
  const release = api['art::ReaderWriterMutex::ExclusiveUnlock'];

  const IRT_FIRST_SEGMENT = 0;

  return function (vm, thread, obj) {
    acquire(lock, thread);
    try {
      return add(table, IRT_FIRST_SEGMENT, obj);
    } finally {
      release(lock, thread);
    }
  };
}

function makeDecodeGlobalFallback (api) {
  /*
   * Fallback for art::JavaVMExt::DecodeGlobal, which is
   * unavailable in Android versions <= 5 and >= 15.
   */
  const decode = api['art::Thread::DecodeJObject'];
  if (decode === undefined) {
    throw new Error('art::Thread::DecodeJObject is not available; please file a bug');
  }

  return function (vm, thread, ref) {
    return decode(thread, ref);
  };
}

/*
 * In order to call internal ART APIs we need to transition our native thread's
 * art::Thread to the proper state. The ScopedObjectAccess (SOA) helper that ART
 * uses internally is what we would like to use to accomplish this goal.
 *
 * There is however a challenge. The SOA implementation is fully inlined, so
 * we cannot just allocate a chunk of memory and call its constructor and
 * destructor to get the desired setup and teardown.
 *
 * We could however precompile such code using a C++ compiler, but considering
 * how many versions of ART we would need to compile it for, multiplied by the
 * number of supported architectures, we really don't want to go there.
 *
 * Reimplementing it in JavaScript is not desirable either, as we would need
 * to keep track of even more internals prone to change as ART evolves.
 *
 * So our least terrible option is to find a really simple C++ method in ART
 * that sets up a SOA object, performs as few and distinct operations as
 * possible, and then returns. If we clone that implementation we can swap
 * out the few/distinct operations with our own.
 *
 * We can accomplish this by using Frida's relocator API, and detecting the
 * few/distinct operations happening between setup and teardown of the scope.
 * We skip those when making our copy and instead put a call to a NativeCallback
 * there. Our NativeCallback is thus able to call internal ART APIs safely.
 *
 * The ExceptionClear() implementation that's part of the JNIEnv's vtable is
 * a perfect fit, as all it does is clear one field of the art::Thread.
 * (Except on older versions where it also clears a bit more... but still
 * pretty simple.)
 *
 * However, checked JNI might be enabled, making ExceptionClear() a bit more
 * complex, and essentially a wrapper around the unchecked version.
 *
 * One last thing to note is that we also look up the address of FatalError(),
 * as ExceptionClear() typically ends with a __stack_chk_fail() noreturn call
 * that's followed by the next JNIEnv vtable method, FatalError(). We don't want
 * to recompile its code as well, so we try to detect it. There might however be
 * padding between the two functions, which we need to ignore. Ideally we would
 * know that the call is to __stack_chk_fail(), so we can stop at that point,
 * but detecting that isn't trivial.
 */

const threadStateTransitionRecompilers = {
  ia32: recompileExceptionClearForX86,
  x64: recompileExceptionClearForX86,
  arm: recompileExceptionClearForArm,
  arm64: recompileExceptionClearForArm64
};

function makeArtThreadStateTransitionImpl (vm, env, callback) {
  const envVtable = env.handle.readPointer();
  const exceptionClearImpl = envVtable.add(ENV_VTABLE_OFFSET_EXCEPTION_CLEAR).readPointer();
  const nextFuncImpl = envVtable.add(ENV_VTABLE_OFFSET_FATAL_ERROR).readPointer();

  const recompile = threadStateTransitionRecompilers[Process.arch];
  if (recompile === undefined) {
    throw new Error('Not yet implemented for ' + Process.arch);
  }

  let perform = null;

  const threadOffsets = getArtThreadSpec(vm).offset;

  const exceptionOffset = threadOffsets.exception;

  const neuteredOffsets = new Set();
  const isReportedOffset = threadOffsets.isExceptionReportedToInstrumentation;
  if (isReportedOffset !== null) {
    neuteredOffsets.add(isReportedOffset);
  }
  const throwLocationStartOffset = threadOffsets.throwLocation;
  if (throwLocationStartOffset !== null) {
    neuteredOffsets.add(throwLocationStartOffset);
    neuteredOffsets.add(throwLocationStartOffset + pointerSize);
    neuteredOffsets.add(throwLocationStartOffset + (2 * pointerSize));
  }

  const codeSize = 65536;
  const code = Memory.alloc(codeSize);
  Memory.patchCode(code, codeSize, buffer => {
    perform = recompile(buffer, code, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback);
  });

  perform._code = code;
  perform._callback = callback;

  return perform;
}

function recompileExceptionClearForX86 (buffer, pc, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback) {
  const blocks = {};
  const branchTargets = new Set();

  const pending = [exceptionClearImpl];
  while (pending.length > 0) {
    let current = pending.shift();

    const alreadyCovered = Object.values(blocks).some(({ begin, end }) => current.compare(begin) >= 0 && current.compare(end) < 0);
    if (alreadyCovered) {
      continue;
    }

    const blockAddressKey = current.toString();

    let block = {
      begin: current
    };
    let lastInsn = null;

    let reachedEndOfBlock = false;
    do {
      if (current.equals(nextFuncImpl)) {
        reachedEndOfBlock = true;
        break;
      }

      const insn = Instruction.parse(current);
      lastInsn = insn;

      const existingBlock = blocks[insn.address.toString()];
      if (existingBlock !== undefined) {
        delete blocks[existingBlock.begin.toString()];
        blocks[blockAddressKey] = existingBlock;
        existingBlock.begin = block.begin;
        block = null;
        break;
      }

      let branchTarget = null;
      switch (insn.mnemonic) {
        case 'jmp':
          branchTarget = ptr(insn.operands[0].value);
          reachedEndOfBlock = true;
          break;
        case 'je':
        case 'jg':
        case 'jle':
        case 'jne':
        case 'js':
          branchTarget = ptr(insn.operands[0].value);
          break;
        case 'ret':
          reachedEndOfBlock = true;
          break;
      }

      if (branchTarget !== null) {
        branchTargets.add(branchTarget.toString());

        pending.push(branchTarget);
        pending.sort((a, b) => a.compare(b));
      }

      current = insn.next;
    } while (!reachedEndOfBlock);

    if (block !== null) {
      block.end = lastInsn.address.add(lastInsn.size);
      blocks[blockAddressKey] = block;
    }
  }

  const blocksOrdered = Object.keys(blocks).map(key => blocks[key]);
  blocksOrdered.sort((a, b) => a.begin.compare(b.begin));

  const entryBlock = blocks[exceptionClearImpl.toString()];
  blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
  blocksOrdered.unshift(entryBlock);

  const writer = new X86Writer(buffer, { pc });

  let foundCore = false;
  let threadReg = null;

  blocksOrdered.forEach(block => {
    const size = block.end.sub(block.begin).toInt32();

    const relocator = new X86Relocator(block.begin, writer);

    let offset;
    while ((offset = relocator.readOne()) !== 0) {
      const insn = relocator.input;
      const { mnemonic } = insn;

      const insnAddressId = insn.address.toString();
      if (branchTargets.has(insnAddressId)) {
        writer.putLabel(insnAddressId);
      }

      let keep = true;

      switch (mnemonic) {
        case 'jmp':
          writer.putJmpNearLabel(branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'je':
        case 'jg':
        case 'jle':
        case 'jne':
        case 'js':
          writer.putJccNearLabel(mnemonic, branchLabelFromOperand(insn.operands[0]), 'no-hint');
          keep = false;
          break;
        /*
         * JNI::ExceptionClear(), when checked JNI is off.
         */
        case 'mov': {
          const [dst, src] = insn.operands;

          if (dst.type === 'mem' && src.type === 'imm') {
            const dstValue = dst.value;
            const dstOffset = dstValue.disp;

            if (dstOffset === exceptionOffset && src.value.valueOf() === 0) {
              threadReg = dstValue.base;

              writer.putPushfx();
              writer.putPushax();
              writer.putMovRegReg('xbp', 'xsp');
              if (pointerSize === 4) {
                writer.putAndRegU32('esp', 0xfffffff0);
              } else {
                const scratchReg = (threadReg !== 'rdi') ? 'rdi' : 'rsi';
                writer.putMovRegU64(scratchReg, uint64('0xfffffffffffffff0'));
                writer.putAndRegReg('rsp', scratchReg);
              }
              writer.putCallAddressWithAlignedArguments(callback, [threadReg]);
              writer.putMovRegReg('xsp', 'xbp');
              writer.putPopax();
              writer.putPopfx();

              foundCore = true;
              keep = false;
            } else if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
              keep = false;
            }
          }

          break;
        }
        /*
         * CheckJNI::ExceptionClear, when checked JNI is on. Wrapper that calls JNI::ExceptionClear().
         */
        case 'call': {
          const target = insn.operands[0];
          if (target.type === 'mem' && target.value.disp === ENV_VTABLE_OFFSET_EXCEPTION_CLEAR) {
            /*
             * Get art::Thread * from JNIEnv *
             */
            if (pointerSize === 4) {
              writer.putPopReg('eax');
              writer.putMovRegRegOffsetPtr('eax', 'eax', 4);
              writer.putPushReg('eax');
            } else {
              writer.putMovRegRegOffsetPtr('rdi', 'rdi', 8);
            }

            writer.putCallAddressWithArguments(callback, []);

            foundCore = true;
            keep = false;
          }

          break;
        }
      }

      if (keep) {
        relocator.writeAll();
      } else {
        relocator.skipOne();
      }

      if (offset === size) {
        break;
      }
    }

    relocator.dispose();
  });

  writer.dispose();

  if (!foundCore) {
    throwThreadStateTransitionParseError();
  }

  return new NativeFunction(pc, 'void', ['pointer'], nativeFunctionOptions);
}

function recompileExceptionClearForArm (buffer, pc, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback) {
  const blocks = {};
  const branchTargets = new Set();

  const thumbBitRemovalMask = ptr(1).not();

  const pending = [exceptionClearImpl];
  while (pending.length > 0) {
    let current = pending.shift();

    const alreadyCovered = Object.values(blocks).some(({ begin, end }) => current.compare(begin) >= 0 && current.compare(end) < 0);
    if (alreadyCovered) {
      continue;
    }

    const begin = current.and(thumbBitRemovalMask);
    const blockId = begin.toString();
    const thumbBit = current.and(1);

    let block = {
      begin
    };
    let lastInsn = null;

    let reachedEndOfBlock = false;
    let ifThenBlockRemaining = 0;
    do {
      if (current.equals(nextFuncImpl)) {
        reachedEndOfBlock = true;
        break;
      }

      const insn = Instruction.parse(current);
      const { mnemonic } = insn;
      lastInsn = insn;

      const currentAddress = current.and(thumbBitRemovalMask);
      const insnId = currentAddress.toString();

      const existingBlock = blocks[insnId];
      if (existingBlock !== undefined) {
        delete blocks[existingBlock.begin.toString()];
        blocks[blockId] = existingBlock;
        existingBlock.begin = block.begin;
        block = null;
        break;
      }

      const isOutsideIfThenBlock = ifThenBlockRemaining === 0;

      let branchTarget = null;

      switch (mnemonic) {
        case 'b':
          branchTarget = ptr(insn.operands[0].value);
          reachedEndOfBlock = isOutsideIfThenBlock;
          break;
        case 'beq.w':
        case 'beq':
        case 'bne':
        case 'bgt':
          branchTarget = ptr(insn.operands[0].value);
          break;
        case 'cbz':
        case 'cbnz':
          branchTarget = ptr(insn.operands[1].value);
          break;
        case 'pop.w':
          if (isOutsideIfThenBlock) {
            reachedEndOfBlock = insn.operands.filter(op => op.value === 'pc').length === 1;
          }
          break;
      }

      switch (mnemonic) {
        case 'it':
          ifThenBlockRemaining = 1;
          break;
        case 'itt':
          ifThenBlockRemaining = 2;
          break;
        case 'ittt':
          ifThenBlockRemaining = 3;
          break;
        case 'itttt':
          ifThenBlockRemaining = 4;
          break;
        default:
          if (ifThenBlockRemaining > 0) {
            ifThenBlockRemaining--;
          }
          break;
      }

      if (branchTarget !== null) {
        branchTargets.add(branchTarget.toString());

        pending.push(branchTarget.or(thumbBit));
        pending.sort((a, b) => a.compare(b));
      }

      current = insn.next;
    } while (!reachedEndOfBlock);

    if (block !== null) {
      block.end = lastInsn.address.add(lastInsn.size);
      blocks[blockId] = block;
    }
  }

  const blocksOrdered = Object.keys(blocks).map(key => blocks[key]);
  blocksOrdered.sort((a, b) => a.begin.compare(b.begin));

  const entryBlock = blocks[exceptionClearImpl.and(thumbBitRemovalMask).toString()];
  blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
  blocksOrdered.unshift(entryBlock);

  const writer = new ThumbWriter(buffer, { pc });

  let foundCore = false;
  let threadReg = null;
  let realImplReg = null;

  blocksOrdered.forEach(block => {
    const relocator = new ThumbRelocator(block.begin, writer);

    let address = block.begin;
    const end = block.end;
    let size = 0;
  
"""


```
Response:
### 功能归纳

`class-factory.js` 是 Frida 工具中用于动态操作 Java 类的核心模块之一。它主要负责以下功能：

1. **Java 类的动态加载与操作**：
   - 通过 `ClassHandle` 类管理 Java 类的引用，确保在 JNI 环境中正确使用和释放类引用。
   - 提供 `makeBasicClassHandleGetter` 和 `makeLoaderClassHandleGetter` 函数，用于获取 Java 类的句柄，支持通过类名或类加载器加载类。

2. **构造函数与方法的重载处理**：
   - `makeConstructor` 函数用于生成 Java 类的构造函数，支持重载构造函数的处理。
   - `makeMethodFromSpec` 和 `makeMethodDispatcher` 函数用于处理 Java 方法的重载，支持根据参数类型选择合适的方法实现。

3. **字段的访问与修改**：
   - `makeFieldFromSpec` 和 `makeFieldFromParams` 函数用于生成 Java 字段的访问器，支持静态字段和实例字段的读取与写入。

4. **方法调用的动态代理**：
   - `makeMethod` 和 `makeMethodInstance` 函数用于生成 Java 方法的代理，支持方法调用的动态拦截与重写。
   - `implement` 函数用于实现方法的自定义逻辑，支持在方法调用时执行自定义代码。

5. **Dex 文件的加载与操作**：
   - `DexFile` 类用于加载和操作 Dex 文件，支持从内存中加载 Dex 文件并获取其中的类名列表。

6. **线程管理与忽略机制**：
   - `ignore` 和 `unignore` 函数用于管理线程的忽略状态，确保在多线程环境下正确处理线程的调用。

7. **类型转换与处理**：
   - `readTypeNames` 函数用于从 JNI 环境中读取类型名称，支持将 Java 类型转换为 JavaScript 类型。

### 二进制底层与 Linux 内核相关

该文件主要涉及 JNI（Java Native Interface）的使用，JNI 是 Java 与本地代码（如 C/C++）交互的接口。虽然该文件本身不直接涉及 Linux 内核或二进制底层操作，但它通过 JNI 与 Java 虚拟机（JVM）进行交互，JVM 本身可能涉及底层操作。

### LLDB 调试示例

假设我们想要调试 `makeMethod` 函数的实现，可以使用 LLDB 进行调试。以下是一个使用 LLDB Python 脚本的示例：

```python
import lldb

def makeMethod_debug(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 假设 makeMethod 函数的地址为 0x12345678
    method_address = 0x12345678

    # 设置断点
    breakpoint = target.BreakpointCreateByAddress(method_address)
    print(f"Breakpoint set at address {method_address}")

    # 继续执行程序
    process.Continue()

    # 当程序停在断点时，打印相关信息
    if thread.GetStopReason() == lldb.eStopReasonBreakpoint:
        print("Stopped at makeMethod function")
        # 打印当前寄存器的值
        for reg in frame.registers:
            print(reg)

# 注册 LLDB 命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f makeMethod_debug.makeMethod_debug makeMethod_debug')
    print('The "makeMethod_debug" LLDB command has been installed.')
```

### 假设输入与输出

假设我们有一个 Java 类 `com.example.MyClass`，并且我们想要动态加载并调用其方法 `myMethod`，输入和输出可能如下：

**输入**：
- 类名：`com.example.MyClass`
- 方法名：`myMethod`
- 参数类型：`String`, `int`

**输出**：
- 成功调用 `myMethod` 方法，并返回结果。

### 常见使用错误

1. **类名错误**：
   - 用户可能输入了错误的类名，导致无法找到类。例如，输入 `com.example.MyClasss`（多了一个 `s`），会导致 `findClass` 失败。

2. **方法签名不匹配**：
   - 用户可能提供了错误的方法签名，导致无法找到对应的方法。例如，方法签名应为 `(Ljava/lang/String;I)V`，但用户提供了 `(Ljava/lang/String;)V`。

3. **线程忽略错误**：
   - 在多线程环境下，用户可能忘记调用 `unignore`，导致某些线程的调用被错误地忽略。

### 用户操作步骤

1. **加载类**：
   - 用户通过 `makeBasicClassHandleGetter` 或 `makeLoaderClassHandleGetter` 加载目标类。

2. **获取方法**：
   - 用户通过 `makeMethodFromSpec` 获取目标方法的句柄。

3. **调用方法**：
   - 用户通过 `makeMethodDispatcher` 调用目标方法，并传入参数。

4. **处理结果**：
   - 用户处理方法的返回值，或捕获可能的异常。

### 调试线索

1. **类加载失败**：
   - 如果类加载失败，检查类名是否正确，类路径是否包含在类加载器中。

2. **方法调用失败**：
   - 如果方法调用失败，检查方法签名是否正确，参数类型是否匹配。

3. **线程忽略问题**：
   - 如果某些线程的调用被忽略，检查是否在适当的地方调用了 `unignore`。

通过这些步骤和调试线索，用户可以逐步排查问题，确保动态操作 Java 类的功能正常工作。
Prompt: 
```
这是目录为frida-java-bridge/lib/class-factory.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第2部分，共2部分，请归纳一下它的功能

"""
lassHandle (value, env) {
  this.value = env.newGlobalRef(value);
  env.deleteLocalRef(value);

  this.refs = 1;
}

ClassHandle.prototype.ref = function () {
  this.refs++;
  return this;
};

ClassHandle.prototype.unref = function (env) {
  if (--this.refs === 0) {
    env.deleteGlobalRef(this.value);
  }
};

function releaseClassHandle (handle, env) {
  handle.unref(env);
}

function makeBasicClassHandleGetter (className) {
  const canonicalClassName = className.replace(/\./g, '/');

  return function (env) {
    const tid = getCurrentThreadId();
    ignore(tid);
    try {
      return env.findClass(canonicalClassName);
    } finally {
      unignore(tid);
    }
  };
}

function makeLoaderClassHandleGetter (className, usedLoader, callerEnv) {
  if (cachedLoaderMethod === null) {
    cachedLoaderInvoke = callerEnv.vaMethod('pointer', ['pointer']);
    cachedLoaderMethod = usedLoader.loadClass.overload('java.lang.String').handle;
  }

  callerEnv = null;

  return function (env) {
    const classNameValue = env.newStringUtf(className);

    const tid = getCurrentThreadId();
    ignore(tid);
    try {
      const result = cachedLoaderInvoke(env.handle, usedLoader.$h, cachedLoaderMethod, classNameValue);
      env.throwIfExceptionPending();
      return result;
    } finally {
      unignore(tid);
      env.deleteLocalRef(classNameValue);
    }
  };
}

function makeSuperHandleGetter (classWrapper) {
  return function (env) {
    const h = classWrapper.$borrowClassHandle(env);
    try {
      return env.getSuperclass(h.value);
    } finally {
      h.unref(env);
    }
  };
}

function makeConstructor (classHandle, classWrapper, env) {
  const { $n: className, $f: factory } = classWrapper;
  const methodName = basename(className);
  const Class = env.javaLangClass();
  const Constructor = env.javaLangReflectConstructor();
  const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
  const invokeUInt8MethodNoArgs = env.vaMethod('uint8', []);

  const jsCtorMethods = [];
  const jsInitMethods = [];
  const jsRetType = factory._getType(className, false);
  const jsVoidType = factory._getType('void', false);

  const constructors = invokeObjectMethodNoArgs(env.handle, classHandle, Class.getDeclaredConstructors);
  try {
    const n = env.getArrayLength(constructors);

    if (n !== 0) {
      for (let i = 0; i !== n; i++) {
        let methodId, types;
        const constructor = env.getObjectArrayElement(constructors, i);
        try {
          methodId = env.fromReflectedMethod(constructor);
          types = invokeObjectMethodNoArgs(env.handle, constructor, Constructor.getGenericParameterTypes);
        } finally {
          env.deleteLocalRef(constructor);
        }

        let jsArgTypes;
        try {
          jsArgTypes = readTypeNames(env, types).map(name => factory._getType(name));
        } finally {
          env.deleteLocalRef(types);
        }

        jsCtorMethods.push(makeMethod(methodName, classWrapper, CONSTRUCTOR_METHOD, methodId, jsRetType, jsArgTypes, env));
        jsInitMethods.push(makeMethod(methodName, classWrapper, INSTANCE_METHOD, methodId, jsVoidType, jsArgTypes, env));
      }
    } else {
      const isInterface = invokeUInt8MethodNoArgs(env.handle, classHandle, Class.isInterface);
      if (isInterface) {
        throw new Error('cannot instantiate an interface');
      }

      const defaultClass = env.javaLangObject();
      const defaultConstructor = env.getMethodId(defaultClass, '<init>', '()V');

      jsCtorMethods.push(makeMethod(methodName, classWrapper, CONSTRUCTOR_METHOD, defaultConstructor, jsRetType, [], env));
      jsInitMethods.push(makeMethod(methodName, classWrapper, INSTANCE_METHOD, defaultConstructor, jsVoidType, [], env));
    }
  } finally {
    env.deleteLocalRef(constructors);
  }

  if (jsInitMethods.length === 0) {
    throw new Error('no supported overloads');
  }

  return {
    allocAndInit: makeMethodDispatcher(jsCtorMethods),
    initOnly: makeMethodDispatcher(jsInitMethods)
  };
}

function makeMember (name, spec, classHandle, classWrapper, env) {
  if (spec.startsWith('m')) {
    return makeMethodFromSpec(name, spec, classHandle, classWrapper, env);
  }

  return makeFieldFromSpec(name, spec, classHandle, classWrapper, env);
}

function makeMethodFromSpec (name, spec, classHandle, classWrapper, env) {
  const { $f: factory } = classWrapper;
  const overloads = spec.split(':').slice(1);

  const Method = env.javaLangReflectMethod();
  const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
  const invokeUInt8MethodNoArgs = env.vaMethod('uint8', []);

  const methods = overloads.map(params => {
    const type = (params[0] === 's') ? STATIC_METHOD : INSTANCE_METHOD;
    const methodId = ptr(params.substr(1));

    let jsRetType;
    const jsArgTypes = [];
    const handle = env.toReflectedMethod(classHandle, methodId, (type === STATIC_METHOD) ? 1 : 0);
    try {
      const isVarArgs = !!invokeUInt8MethodNoArgs(env.handle, handle, Method.isVarArgs);

      const retType = invokeObjectMethodNoArgs(env.handle, handle, Method.getGenericReturnType);
      env.throwIfExceptionPending();
      try {
        jsRetType = factory._getType(env.getTypeName(retType));
      } finally {
        env.deleteLocalRef(retType);
      }

      const argTypes = invokeObjectMethodNoArgs(env.handle, handle, Method.getParameterTypes);
      try {
        const n = env.getArrayLength(argTypes);

        for (let i = 0; i !== n; i++) {
          const t = env.getObjectArrayElement(argTypes, i);

          let argClassName;
          try {
            argClassName = (isVarArgs && i === n - 1) ? env.getArrayTypeName(t) : env.getTypeName(t);
          } finally {
            env.deleteLocalRef(t);
          }

          const argType = factory._getType(argClassName);
          jsArgTypes.push(argType);
        }
      } finally {
        env.deleteLocalRef(argTypes);
      }
    } catch (e) {
      return null;
    } finally {
      env.deleteLocalRef(handle);
    }

    return makeMethod(name, classWrapper, type, methodId, jsRetType, jsArgTypes, env);
  })
    .filter(m => m !== null);

  if (methods.length === 0) {
    throw new Error('No supported overloads');
  }

  if (name === 'valueOf') {
    ensureDefaultValueOfImplemented(methods);
  }

  const result = makeMethodDispatcher(methods);

  return function (receiver) {
    return result;
  };
}

function makeMethodDispatcher (overloads) {
  const m = makeMethodDispatcherCallable();
  Object.setPrototypeOf(m, dispatcherPrototype);
  m._o = overloads;
  return m;
}

function makeMethodDispatcherCallable () {
  const m = function () {
    return m.invoke(this, arguments);
  };
  return m;
}

dispatcherPrototype = Object.create(Function.prototype, {
  overloads: {
    enumerable: true,
    get () {
      return this._o;
    }
  },
  overload: {
    value (...args) {
      const overloads = this._o;

      const numArgs = args.length;
      const signature = args.join(':');

      for (let i = 0; i !== overloads.length; i++) {
        const method = overloads[i];
        const { argumentTypes } = method;

        if (argumentTypes.length !== numArgs) {
          continue;
        }

        const s = argumentTypes.map(t => t.className).join(':');
        if (s === signature) {
          return method;
        }
      }

      throwOverloadError(this.methodName, this.overloads, 'specified argument types do not match any of:');
    }
  },
  methodName: {
    enumerable: true,
    get () {
      return this._o[0].methodName;
    }
  },
  holder: {
    enumerable: true,
    get () {
      return this._o[0].holder;
    }
  },
  type: {
    enumerable: true,
    get () {
      return this._o[0].type;
    }
  },
  handle: {
    enumerable: true,
    get () {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].handle;
    }
  },
  implementation: {
    enumerable: true,
    get () {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].implementation;
    },
    set (fn) {
      throwIfDispatcherAmbiguous(this);
      this._o[0].implementation = fn;
    }
  },
  returnType: {
    enumerable: true,
    get () {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].returnType;
    }
  },
  argumentTypes: {
    enumerable: true,
    get () {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].argumentTypes;
    }
  },
  canInvokeWith: {
    enumerable: true,
    get (args) {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].canInvokeWith;
    }
  },
  clone: {
    enumerable: true,
    value (options) {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].clone(options);
    }
  },
  invoke: {
    value (receiver, args) {
      const overloads = this._o;

      const isInstance = receiver.$h !== null;

      for (let i = 0; i !== overloads.length; i++) {
        const method = overloads[i];

        if (!method.canInvokeWith(args)) {
          continue;
        }

        if (method.type === INSTANCE_METHOD && !isInstance) {
          const name = this.methodName;

          if (name === 'toString') {
            return `<class: ${receiver.$n}>`;
          }

          throw new Error(name + ': cannot call instance method without an instance');
        }

        return method.apply(receiver, args);
      }

      if (this.methodName === 'toString') {
        return `<class: ${receiver.$n}>`;
      }

      throwOverloadError(this.methodName, this.overloads, 'argument types do not match any of:');
    }
  }
});

function makeOverloadId (name, returnType, argumentTypes) {
  return `${returnType.className} ${name}(${argumentTypes.map(t => t.className).join(', ')})`;
}

function throwIfDispatcherAmbiguous (dispatcher) {
  const methods = dispatcher._o;
  if (methods.length > 1) {
    throwOverloadError(methods[0].methodName, methods, 'has more than one overload, use .overload(<signature>) to choose from:');
  }
}

function throwOverloadError (name, methods, message) {
  const methodsSortedByArity = methods.slice().sort((a, b) => a.argumentTypes.length - b.argumentTypes.length);
  const overloads = methodsSortedByArity.map(m => {
    const argTypes = m.argumentTypes;
    if (argTypes.length > 0) {
      return '.overload(\'' + m.argumentTypes.map(t => t.className).join('\', \'') + '\')';
    } else {
      return '.overload()';
    }
  });
  throw new Error(`${name}(): ${message}\n\t${overloads.join('\n\t')}`);
}

function makeMethod (methodName, classWrapper, type, methodId, retType, argTypes, env, invocationOptions) {
  const rawRetType = retType.type;
  const rawArgTypes = argTypes.map((t) => t.type);

  if (env === null) {
    env = vm.getEnv();
  }

  let callVirtually, callDirectly;
  if (type === INSTANCE_METHOD) {
    callVirtually = env.vaMethod(rawRetType, rawArgTypes, invocationOptions);
    callDirectly = env.nonvirtualVaMethod(rawRetType, rawArgTypes, invocationOptions);
  } else if (type === STATIC_METHOD) {
    callVirtually = env.staticVaMethod(rawRetType, rawArgTypes, invocationOptions);
    callDirectly = callVirtually;
  } else {
    callVirtually = env.constructor(rawArgTypes, invocationOptions);
    callDirectly = callVirtually;
  }

  return makeMethodInstance([methodName, classWrapper, type, methodId, retType, argTypes, callVirtually, callDirectly]);
}

function makeMethodInstance (params) {
  const m = makeMethodCallable();
  Object.setPrototypeOf(m, methodPrototype);
  m._p = params;
  return m;
}

function makeMethodCallable () {
  const m = function () {
    return m.invoke(this, arguments);
  };
  return m;
}

methodPrototype = Object.create(Function.prototype, {
  methodName: {
    enumerable: true,
    get () {
      return this._p[0];
    }
  },
  holder: {
    enumerable: true,
    get () {
      return this._p[1];
    }
  },
  type: {
    enumerable: true,
    get () {
      return this._p[2];
    }
  },
  handle: {
    enumerable: true,
    get () {
      return this._p[3];
    }
  },
  implementation: {
    enumerable: true,
    get () {
      const replacement = this._r;
      return (replacement !== undefined) ? replacement : null;
    },
    set (fn) {
      const params = this._p;
      const holder = params[1];
      const type = params[2];

      if (type === CONSTRUCTOR_METHOD) {
        throw new Error('Reimplementing $new is not possible; replace implementation of $init instead');
      }

      const existingReplacement = this._r;
      if (existingReplacement !== undefined) {
        holder.$f._patchedMethods.delete(this);

        const mangler = existingReplacement._m;
        mangler.revert(vm);

        this._r = undefined;
      }

      if (fn !== null) {
        const [methodName, classWrapper, type, methodId, retType, argTypes] = params;

        const replacement = implement(methodName, classWrapper, type, retType, argTypes, fn, this);
        const mangler = makeMethodMangler(methodId);
        replacement._m = mangler;
        this._r = replacement;

        mangler.replace(replacement, type === INSTANCE_METHOD, argTypes, vm, api);

        holder.$f._patchedMethods.add(this);
      }
    }
  },
  returnType: {
    enumerable: true,
    get () {
      return this._p[4];
    }
  },
  argumentTypes: {
    enumerable: true,
    get () {
      return this._p[5];
    }
  },
  canInvokeWith: {
    enumerable: true,
    value (args) {
      const argTypes = this._p[5];

      if (args.length !== argTypes.length) {
        return false;
      }

      return argTypes.every((t, i) => {
        return t.isCompatible(args[i]);
      });
    }
  },
  clone: {
    enumerable: true,
    value (options) {
      const params = this._p.slice(0, 6);
      return makeMethod(...params, null, options);
    }
  },
  invoke: {
    value (receiver, args) {
      const env = vm.getEnv();

      const params = this._p;
      const type = params[2];
      const retType = params[4];
      const argTypes = params[5];

      const replacement = this._r;

      const isInstanceMethod = type === INSTANCE_METHOD;
      const numArgs = args.length;

      const frameCapacity = 2 + numArgs;
      env.pushLocalFrame(frameCapacity);

      let borrowedHandle = null;
      try {
        let jniThis;
        if (isInstanceMethod) {
          jniThis = receiver.$getHandle();
        } else {
          borrowedHandle = receiver.$borrowClassHandle(env);
          jniThis = borrowedHandle.value;
        }

        let methodId;
        let strategy = receiver.$t;
        if (replacement === undefined) {
          methodId = params[3];
        } else {
          const mangler = replacement._m;
          methodId = mangler.resolveTarget(receiver, isInstanceMethod, env, api);

          if (isArtVm) {
            const pendingCalls = replacement._c;
            if (pendingCalls.has(getCurrentThreadId())) {
              strategy = STRATEGY_DIRECT;
            }
          }
        }

        const jniArgs = [
          env.handle,
          jniThis,
          methodId
        ];
        for (let i = 0; i !== numArgs; i++) {
          jniArgs.push(argTypes[i].toJni(args[i], env));
        }

        let jniCall;
        if (strategy === STRATEGY_VIRTUAL) {
          jniCall = params[6];
        } else {
          jniCall = params[7];

          if (isInstanceMethod) {
            jniArgs.splice(2, 0, receiver.$copyClassHandle(env));
          }
        }

        const jniRetval = jniCall.apply(null, jniArgs);
        env.throwIfExceptionPending();

        return retType.fromJni(jniRetval, env, true);
      } finally {
        if (borrowedHandle !== null) {
          borrowedHandle.unref(env);
        }

        env.popLocalFrame(NULL);
      }
    }
  },
  toString: {
    enumerable: true,
    value () {
      return `function ${this.methodName}(${this.argumentTypes.map(t => t.className).join(', ')}): ${this.returnType.className}`;
    }
  }
});

function implement (methodName, classWrapper, type, retType, argTypes, handler, fallback = null) {
  const pendingCalls = new Set();

  const f = makeMethodImplementation([methodName, classWrapper, type, retType, argTypes, handler, fallback, pendingCalls]);

  const impl = new NativeCallback(f, retType.type, ['pointer', 'pointer'].concat(argTypes.map(t => t.type)));
  impl._c = pendingCalls;

  return impl;
}

function makeMethodImplementation (params) {
  return function () {
    return handleMethodInvocation(arguments, params);
  };
}

function handleMethodInvocation (jniArgs, params) {
  const env = new Env(jniArgs[0], vm);

  const [methodName, classWrapper, type, retType, argTypes, handler, fallback, pendingCalls] = params;

  const ownedObjects = [];

  let self;
  if (type === INSTANCE_METHOD) {
    const C = classWrapper.$C;
    self = new C(jniArgs[1], STRATEGY_VIRTUAL, env, false);
  } else {
    self = classWrapper;
  }

  const tid = getCurrentThreadId();

  env.pushLocalFrame(3);
  let haveFrame = true;

  vm.link(tid, env);

  try {
    pendingCalls.add(tid);

    let fn;
    if (fallback === null || !ignoredThreads.has(tid)) {
      fn = handler;
    } else {
      fn = fallback;
    }

    const args = [];
    const numArgs = jniArgs.length - 2;
    for (let i = 0; i !== numArgs; i++) {
      const t = argTypes[i];

      const value = t.fromJni(jniArgs[2 + i], env, false);
      args.push(value);

      ownedObjects.push(value);
    }

    const retval = fn.apply(self, args);

    if (!retType.isCompatible(retval)) {
      throw new Error(`Implementation for ${methodName} expected return value compatible with ${retType.className}`);
    }

    let jniRetval = retType.toJni(retval, env);

    if (retType.type === 'pointer') {
      jniRetval = env.popLocalFrame(jniRetval);
      haveFrame = false;

      ownedObjects.push(retval);
    }

    return jniRetval;
  } catch (e) {
    const jniException = e.$h;
    if (jniException !== undefined) {
      env.throw(jniException);
    } else {
      Script.nextTick(() => { throw e; });
    }

    return retType.defaultValue;
  } finally {
    vm.unlink(tid);

    if (haveFrame) {
      env.popLocalFrame(NULL);
    }

    pendingCalls.delete(tid);

    ownedObjects.forEach(obj => {
      if (obj === null) {
        return;
      }

      const dispose = obj.$dispose;
      if (dispose !== undefined) {
        dispose.call(obj);
      }
    });
  }
}

function ensureDefaultValueOfImplemented (methods) {
  const { holder, type } = methods[0];

  const hasDefaultValueOf = methods.some(m => m.type === type && m.argumentTypes.length === 0);
  if (hasDefaultValueOf) {
    return;
  }

  methods.push(makeValueOfMethod([holder, type]));
}

function makeValueOfMethod (params) {
  const m = makeValueOfCallable();
  Object.setPrototypeOf(m, valueOfPrototype);
  m._p = params;
  return m;
}

function makeValueOfCallable () {
  const m = function () {
    return this;
  };
  return m;
}

valueOfPrototype = Object.create(Function.prototype, {
  methodName: {
    enumerable: true,
    get () {
      return 'valueOf';
    }
  },
  holder: {
    enumerable: true,
    get () {
      return this._p[0];
    }
  },
  type: {
    enumerable: true,
    get () {
      return this._p[1];
    }
  },
  handle: {
    enumerable: true,
    get () {
      return NULL;
    }
  },
  implementation: {
    enumerable: true,
    get () {
      return null;
    },
    set (fn) {
    }
  },
  returnType: {
    enumerable: true,
    get () {
      const classWrapper = this.holder;
      return classWrapper.$f.use(classWrapper.$n);
    }
  },
  argumentTypes: {
    enumerable: true,
    get () {
      return [];
    }
  },
  canInvokeWith: {
    enumerable: true,
    value (args) {
      return args.length === 0;
    }
  },
  clone: {
    enumerable: true,
    value (options) {
      throw new Error('Invalid operation');
    }
  }
});

function makeFieldFromSpec (name, spec, classHandle, classWrapper, env) {
  const type = (spec[2] === 's') ? STATIC_FIELD : INSTANCE_FIELD;
  const id = ptr(spec.substr(3));
  const { $f: factory } = classWrapper;

  let fieldType;
  const field = env.toReflectedField(classHandle, id, (type === STATIC_FIELD) ? 1 : 0);
  try {
    fieldType = env.vaMethod('pointer', [])(env.handle, field, env.javaLangReflectField().getGenericType);
    env.throwIfExceptionPending();
  } finally {
    env.deleteLocalRef(field);
  }

  let rtype;
  try {
    rtype = factory._getType(env.getTypeName(fieldType));
  } finally {
    env.deleteLocalRef(fieldType);
  }

  let getValue, setValue;
  const rtypeJni = rtype.type;
  if (type === STATIC_FIELD) {
    getValue = env.getStaticField(rtypeJni);
    setValue = env.setStaticField(rtypeJni);
  } else {
    getValue = env.getField(rtypeJni);
    setValue = env.setField(rtypeJni);
  }

  return makeFieldFromParams([type, rtype, id, getValue, setValue]);
}

function makeFieldFromParams (params) {
  return function (receiver) {
    return new Field([receiver].concat(params));
  };
}

function Field (params) {
  this._p = params;
}

Object.defineProperties(Field.prototype, {
  value: {
    enumerable: true,
    get () {
      const [holder, type, rtype, id, getValue] = this._p;

      const env = vm.getEnv();
      env.pushLocalFrame(4);

      let borrowedHandle = null;
      try {
        let jniThis;
        if (type === INSTANCE_FIELD) {
          jniThis = holder.$getHandle();
          if (jniThis === null) {
            throw new Error('Cannot access an instance field without an instance');
          }
        } else {
          borrowedHandle = holder.$borrowClassHandle(env);
          jniThis = borrowedHandle.value;
        }

        const jniRetval = getValue(env.handle, jniThis, id);
        env.throwIfExceptionPending();

        return rtype.fromJni(jniRetval, env, true);
      } finally {
        if (borrowedHandle !== null) {
          borrowedHandle.unref(env);
        }

        env.popLocalFrame(NULL);
      }
    },
    set (value) {
      const [holder, type, rtype, id, , setValue] = this._p;

      const env = vm.getEnv();
      env.pushLocalFrame(4);

      let borrowedHandle = null;
      try {
        let jniThis;
        if (type === INSTANCE_FIELD) {
          jniThis = holder.$getHandle();
          if (jniThis === null) {
            throw new Error('Cannot access an instance field without an instance');
          }
        } else {
          borrowedHandle = holder.$borrowClassHandle(env);
          jniThis = borrowedHandle.value;
        }

        if (!rtype.isCompatible(value)) {
          throw new Error(`Expected value compatible with ${rtype.className}`);
        }
        const jniValue = rtype.toJni(value, env);

        setValue(env.handle, jniThis, id, jniValue);
        env.throwIfExceptionPending();
      } finally {
        if (borrowedHandle !== null) {
          borrowedHandle.unref(env);
        }

        env.popLocalFrame(NULL);
      }
    }
  },
  holder: {
    enumerable: true,
    get () {
      return this._p[0];
    }
  },
  fieldType: {
    enumerable: true,
    get () {
      return this._p[1];
    }
  },
  fieldReturnType: {
    enumerable: true,
    get () {
      return this._p[2];
    }
  },
  toString: {
    enumerable: true,
    value () {
      const inlineString = `Java.Field{holder: ${this.holder}, fieldType: ${this.fieldType}, fieldReturnType: ${this.fieldReturnType}, value: ${this.value}}`;
      if (inlineString.length < 200) {
        return inlineString;
      }
      const multilineString = `Java.Field{
\tholder: ${this.holder},
\tfieldType: ${this.fieldType},
\tfieldReturnType: ${this.fieldReturnType},
\tvalue: ${this.value},
}`;
      return multilineString.split('\n').map(l => l.length > 200 ? l.slice(0, l.indexOf(' ') + 1) + '...,' : l).join('\n');
    }
  }
});

class DexFile {
  static fromBuffer (buffer, factory) {
    const fileValue = createTemporaryDex(factory);
    const filePath = fileValue.getCanonicalPath().toString();

    const file = new File(filePath, 'w');
    file.write(buffer.buffer);
    file.close();
    setReadOnlyDex(filePath, factory);

    return new DexFile(filePath, fileValue, factory);
  }

  constructor (path, file, factory) {
    this.path = path;
    this.file = file;

    this._factory = factory;
  }

  load () {
    const { _factory: factory } = this;
    const { codeCacheDir } = factory;
    const DexClassLoader = factory.use('dalvik.system.DexClassLoader');
    const JFile = factory.use('java.io.File');

    let file = this.file;
    if (file === null) {
      file = factory.use('java.io.File').$new(this.path);
    }
    if (!file.exists()) {
      throw new Error('File not found');
    }

    JFile.$new(codeCacheDir).mkdirs();

    factory.loader = DexClassLoader.$new(file.getCanonicalPath(), codeCacheDir, null, factory.loader);

    vm.preventDetachDueToClassLoader();
  }

  getClassNames () {
    const { _factory: factory } = this;
    const DexFile = factory.use('dalvik.system.DexFile');

    const optimizedDex = createTemporaryDex(factory);
    const dx = DexFile.loadDex(this.path, optimizedDex.getCanonicalPath(), 0);

    const classNames = [];
    const enumeratorClassNames = dx.entries();
    while (enumeratorClassNames.hasMoreElements()) {
      classNames.push(enumeratorClassNames.nextElement().toString());
    }
    return classNames;
  }
}

function createTemporaryDex (factory) {
  const { cacheDir, tempFileNaming } = factory;
  const JFile = factory.use('java.io.File');

  const cacheDirValue = JFile.$new(cacheDir);
  cacheDirValue.mkdirs();

  return JFile.createTempFile(tempFileNaming.prefix, tempFileNaming.suffix + '.dex', cacheDirValue);
}

function setReadOnlyDex (filePath, factory) {
  const JFile = factory.use('java.io.File');
  const file = JFile.$new(filePath);
  file.setWritable(false, false);
}

function getFactoryCache () {
  switch (factoryCache.state) {
    case 'empty': {
      factoryCache.state = 'pending';

      const defaultFactory = factoryCache.factories[0];

      const HashMap = defaultFactory.use('java.util.HashMap');
      const Integer = defaultFactory.use('java.lang.Integer');

      factoryCache.loaders = HashMap.$new();
      factoryCache.Integer = Integer;

      const loader = defaultFactory.loader;
      if (loader !== null) {
        addFactoryToCache(defaultFactory, loader);
      }

      factoryCache.state = 'ready';

      return factoryCache;
    }
    case 'pending':
      do {
        Thread.sleep(0.05);
      } while (factoryCache.state === 'pending');
      return factoryCache;
    case 'ready':
      return factoryCache;
  }
}

function addFactoryToCache (factory, loader) {
  const { factories, loaders, Integer } = factoryCache;

  const index = Integer.$new(factories.indexOf(factory));
  loaders.put(loader, index);

  for (let l = loader.getParent(); l !== null; l = l.getParent()) {
    if (loaders.containsKey(l)) {
      break;
    }

    loaders.put(l, index);
  }
}

function ignore (threadId) {
  let count = ignoredThreads.get(threadId);
  if (count === undefined) {
    count = 0;
  }
  count++;
  ignoredThreads.set(threadId, count);
}

function unignore (threadId) {
  let count = ignoredThreads.get(threadId);
  if (count === undefined) {
    throw new Error(`Thread ${threadId} is not ignored`);
  }
  count--;
  if (count === 0) {
    ignoredThreads.delete(threadId);
  } else {
    ignoredThreads.set(threadId, count);
  }
}

function basename (className) {
  return className.slice(className.lastIndexOf('.') + 1);
}

function readTypeNames (env, types) {
  const names = [];

  const n = env.getArrayLength(types);
  for (let i = 0; i !== n; i++) {
    const t = env.getObjectArrayElement(types, i);
    try {
      names.push(env.getTypeName(t));
    } finally {
      env.deleteLocalRef(t);
    }
  }

  return names;
}

function makeSourceFileName (className) {
  const tokens = className.split('.');
  return tokens[tokens.length - 1] + '.java';
}

module.exports = ClassFactory;

"""


```
Response:
### 功能归纳

`class-factory.js` 是 Frida 工具中用于动态插桩 Java 类的核心模块之一。它主要负责在运行时创建、管理和操作 Java 类的实例、方法、字段等。以下是该文件的主要功能归纳：

1. **Java 类句柄管理**：
   - `ClassHandle` 类用于管理 Java 类的全局引用和局部引用，确保在不再需要时正确释放资源。
   - `ref()` 和 `unref()` 方法用于增加和减少引用计数，防止内存泄漏。

2. **类加载器与类查找**：
   - `makeBasicClassHandleGetter` 和 `makeLoaderClassHandleGetter` 函数用于通过类名查找 Java 类，支持通过类加载器加载类。
   - `makeSuperHandleGetter` 函数用于获取类的父类句柄。

3. **构造函数与方法生成**：
   - `makeConstructor` 函数用于生成 Java 类的构造函数，支持多种重载形式。
   - `makeMethodFromSpec` 和 `makeFieldFromSpec` 函数用于根据规范生成 Java 方法和字段的访问器。

4. **方法调度与重载处理**：
   - `makeMethodDispatcher` 函数用于处理方法的重载调用，支持根据参数类型选择合适的方法实现。
   - `makeMethodInstance` 函数用于创建方法实例，支持方法的动态替换和调用。

5. **字段访问与修改**：
   - `makeFieldFromParams` 函数用于生成字段的访问器，支持静态字段和实例字段的读写操作。

6. **Dex 文件加载与类名获取**：
   - `DexFile` 类用于加载 Dex 文件并获取其中的类名列表，支持通过 DexClassLoader 动态加载类。

7. **线程管理与忽略机制**：
   - `ignore` 和 `unignore` 函数用于在特定线程中忽略某些操作，防止递归调用或死锁。

8. **类型转换与名称解析**：
   - `readTypeNames` 函数用于从 Java 类型数组中读取类型名称。
   - `basename` 函数用于从类名中提取简单名称。

### 二进制底层与 Linux 内核

该文件主要涉及 Java 虚拟机的操作，不直接涉及二进制底层或 Linux 内核。它通过 JNI（Java Native Interface）与 Java 虚拟机交互，执行类加载、方法调用、字段访问等操作。

### LLDB 调试示例

由于该文件主要涉及 Java 虚拟机的操作，使用 LLDB 调试时，通常需要结合 JNI 调用栈进行分析。以下是一个简单的 LLDB Python 脚本示例，用于跟踪 JNI 方法的调用：

```python
import lldb

def jni_method_trace(frame, bp_loc, dict):
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    
    # 获取当前方法的名称
    method_name = frame.GetFunctionName()
    
    # 打印方法名称和调用栈
    print(f"JNI Method Called: {method_name}")
    for f in thread:
        print(f"  {f.GetFunctionName()}")

# 设置断点并绑定回调函数
def __lldb_init_module(debugger, internal_dict):
    target = debugger.GetSelectedTarget()
    breakpoint = target.BreakpointCreateByName("CallStaticVoidMethod", "libart.so")
    breakpoint.SetScriptCallbackFunction("jni_method_trace")
```

### 假设输入与输出

假设输入为一个 Java 类的名称 `com.example.MyClass`，输出为该类的构造函数、方法和字段的访问器。

- **输入**：`com.example.MyClass`
- **输出**：
  - 构造函数：`MyClass()`、`MyClass(int)`
  - 方法：`void myMethod(String)`
  - 字段：`int myField`

### 用户常见错误

1. **类名错误**：
   - 用户可能输入错误的类名，导致类加载失败。例如，输入 `com.example.MyClas`（缺少最后一个字母 `s`），将抛出 `ClassNotFoundException`。

2. **方法重载选择错误**：
   - 用户可能调用方法时传入错误的参数类型，导致无法匹配到正确的重载方法。例如，调用 `myMethod(int)` 时传入 `String` 类型参数，将抛出 `NoSuchMethodError`。

3. **字段访问权限错误**：
   - 用户可能尝试访问私有字段或方法，导致权限错误。例如，尝试访问 `private int myField`，将抛出 `IllegalAccessError`。

### 调试线索

1. **用户操作步骤**：
   - 用户通过 Frida 脚本调用 `Java.use('com.example.MyClass')`。
   - Frida 内部调用 `makeBasicClassHandleGetter` 或 `makeLoaderClassHandleGetter` 查找类。
   - 找到类后，生成构造函数、方法和字段的访问器。
   - 用户调用生成的访问器进行方法调用或字段访问。

2. **调试线索**：
   - 如果类加载失败，检查类名是否正确。
   - 如果方法调用失败，检查参数类型是否匹配。
   - 如果字段访问失败，检查字段的访问权限。

通过以上分析，可以更好地理解 `class-factory.js` 的功能和使用场景，并在调试时快速定位问题。
Prompt: 
```
这是目录为frida/subprojects/frida-java-bridge/lib/class-factory.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
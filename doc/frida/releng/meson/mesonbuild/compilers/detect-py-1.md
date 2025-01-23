Response:
The user wants me to summarize the functionality of the provided Python code snippet, which is part of the `detect.py` file in the `frida` project's build system (Meson). The file seems to be responsible for automatically detecting available compilers for various programming languages.

Here's a breakdown of how I'll address each point:

1. **List the functions:** I will iterate through the code and identify the primary functions, which seem to start with `detect_`.

2. **Explain the purpose of each function:**  Based on the function names and the logic within them, I'll deduce what each function does. The core task appears to be finding and configuring compilers.

3. **Reverse engineering relevance:** I need to consider if the process of identifying and using compilers has any direct connection to reverse engineering. Frida is a dynamic instrumentation toolkit often used in reverse engineering, so the compilers it uses to build itself are indirectly related.

4. **Binary/kernel knowledge:**  Compiler detection and usage touch upon concepts related to binary formats, operating system interactions, and sometimes even kernel-level details (especially for cross-compilation).

5. **Logical reasoning with input/output:**  I will analyze the conditional statements (if/elif/else) and try to infer the expected input (compiler commands and their outputs) and the corresponding output (which compiler class is chosen).

6. **Common usage errors:** I'll think about scenarios where a user might have misconfigured their environment, leading to detection failures.

7. **User path to the code:**  I need to imagine the steps a user would take that would eventually lead to this specific part of the Frida build process being executed. This usually involves initiating the build process.

8. **Summarize the overall functionality:**  Finally, I'll synthesize all the above points into a concise summary of the code's role.

**Mental Sandbox:**

* **Function Identification:** I see functions like `detect_fortran_compiler`, `detect_objc_compiler`, `detect_java_compiler`, etc. Each seems responsible for a specific language.

* **Compiler Detection Logic:** The code heavily uses `Popen_safe_logged` to execute compiler commands (like `--version`) and then parses the output (stdout and stderr) to identify the compiler and its version. Regular expressions (`re.search`) are used for pattern matching in the output.

* **Cross-compilation:** The `for_machine` parameter suggests that the code handles cross-compilation scenarios (building for a different target architecture).

* **Linker Detection:** The code frequently calls `guess_nix_linker` and `guess_win_linker`, indicating that it also attempts to identify the appropriate linker to use with the detected compiler.

* **Reverse Engineering Link:** The compilers detected here are used to build Frida itself. When someone uses Frida for reverse engineering, they are indirectly relying on the correct functioning of this compiler detection mechanism. For example, if the C++ compiler is not correctly detected, Frida might not build properly.

* **Binary/Kernel Ties:**  The choice of linker and compiler flags directly affects the generated binary format. Cross-compilation touches upon architecture-specific details and potentially even kernel interfaces on the target system.

* **Error Handling:** The `_handle_exceptions` function and the `popen_exceptions` dictionary show that the code anticipates potential errors during compiler execution.

* **User Errors:**  A common error would be not having the necessary compilers installed or not having them in the system's PATH environment variable.

* **User Path:**  A user would typically run a command like `meson setup build` or `ninja` in the Frida source directory. This would trigger the Meson build system, which would then execute this `detect.py` script as part of its environment setup.

**Confidence Score:** 5/5 - I feel confident I understand the core functionality and can address all the user's points effectively.

Strategizing complete. I will now generate the response based on these insights.
好的，这是 `frida/releng/meson/mesonbuild/compilers/detect.py` 文件的第二部分代码。让我们继续分析其功能。

**归纳第2部分的功能**

这部分代码延续了第一部分的功能，主要负责检测各种编程语言的编译器，并创建相应的编译器对象。它通过尝试执行不同编译器的命令并分析其输出来识别编译器及其版本，并根据识别结果创建特定于编译器的类实例。

**具体功能列举 (延续第1部分)**

* **检测 Fortran 编译器:**  这部分代码主要集中在检测各种 Fortran 编译器，包括：
    * LCC (Elbrus Fortran Compiler)
    * GNU Fortran (gfortran)
    * Arm C/C++/Fortran Compiler (基于 Flang)
    * G95
    * Sun Fortran
    * Intel Fortran Compiler (ifort, ifx, 包括经典版本和基于 LLVM 的版本)
    * PathScale EKOPath
    * PGI Compilers
    * NVIDIA HPC SDK Fortran Compiler
    * Flang (包括在 Windows 环境下的处理)
    * Open64 Compiler Suite
    * NAG Fortran

* **检测 Objective-C/Objective-C++ 编译器:** 这部分代码使用 `_detect_objc_or_objcpp_compiler` 函数来检测 Objective-C (`detect_objc_compiler`) 和 Objective-C++ (`detect_objcpp_compiler`) 编译器。它主要识别 GNU GCC 和 Clang 两种编译器，并根据输出判断是否为 Apple Clang。

* **检测 Java 编译器:** `detect_java_compiler` 函数尝试执行 `java -version` 命令来检测 Java 编译器 (`javac`)。

* **检测 C# 编译器:** `detect_cs_compiler` 函数尝试执行 C# 编译器（通常是 `csc` 或 Mono 的 `mcs`）并解析其 `--version` 输出。

* **检测 Cython 编译器:** `detect_cython_compiler` 函数尝试执行 Cython 编译器并解析其 `-V` 输出。

* **检测 Vala 编译器:** `detect_vala_compiler` 函数尝试执行 `valac --version` 命令来检测 Vala 编译器。

* **检测 Rust 编译器:** `detect_rust_compiler` 函数尝试执行 `rustc --version` 命令来检测 Rust 编译器。它还特殊处理了 `clippy` 编译器，这通常是 `rustc` 的一个包装器。这个函数中还包含了复杂的逻辑来确定 Rust 编译器的链接器，它会尝试复用检测到的 C 编译器的链接器设置，或者根据用户配置 (`rust_ld`) 来选择。

* **检测 D 编译器:** `detect_d_compiler` 函数尝试检测多种 D 编译器，包括 LDC (基于 LLVM)、GDC (基于 GCC) 和 DMD (Digital Mars D Compiler)。它会根据编译器的输出和目标平台 (Windows/非 Windows) 来选择合适的链接器。

* **检测 Swift 编译器:** `detect_swift_compiler` 函数尝试执行 `swift -v` 命令来检测 Swift 编译器。

* **检测汇编编译器 (NASM):** `detect_nasm_compiler` 函数检测 NASM 和 Yasm 两种汇编编译器，以及 Metrowerks 的汇编编译器。

* **检测汇编编译器 (MASM):** `detect_masm_compiler` 函数检测 Microsoft Macro Assembler (MASM)，它会根据目标 CPU 架构 (x86, x86_64, arm, aarch64) 选择不同的编译器命令 (`ml`, `ml64`, `armasm`, `armasm64`)。

* **获取 GNU/Clang 编译器的宏定义和版本:**  `_get_gnu_compiler_defines` 和 `_get_clang_compiler_defines` 函数分别用于获取 GNU 和 Clang 编译器的预处理器宏定义。这些宏定义可以用来更精确地识别编译器类型和版本。

**与逆向方法的关联举例**

* **编译 Frida 工具本身:** 这个脚本是 Frida 构建过程的一部分。Frida 是一个动态插桩工具，广泛应用于逆向工程。这个脚本正确检测编译器是成功构建 Frida 的前提。如果编译器检测失败或选择了错误的编译器，Frida 可能无法编译或运行不正常，这将直接影响逆向分析工作。
* **支持多种语言的 Frida 模块:** Frida 允许使用多种语言（如 C, C++, Objective-C, Java 等）编写扩展模块。这个脚本负责检测这些语言的编译器，确保 Frida 能够构建和加载这些模块，从而支持更广泛的逆向分析场景。例如，如果需要分析使用了 Objective-C 的 iOS 应用，Frida 需要能够检测到 Objective-C 编译器。

**涉及二进制底层，Linux, Android 内核及框架的知识举例**

* **链接器 (Linker):** 代码中大量使用了 `guess_nix_linker` 和 `guess_win_linker` 函数。链接器是将编译后的目标文件组合成可执行文件或库的关键工具，它涉及到二进制文件的格式 (如 ELF, PE, Mach-O) 和加载过程。在 Android 这种基于 Linux 内核的系统上，链接器对于生成最终的 APK 包或 Native Library 至关重要。
* **交叉编译 (Cross-compilation):**  `for_machine` 参数表明该脚本支持交叉编译。在逆向 Android 应用时，我们通常需要在 x86 的开发机上为 ARM 架构的 Android 设备编译 Frida Agent 或其他辅助工具。正确检测目标平台的编译器和链接器是交叉编译成功的关键。
* **编译器标志 (Compiler Flags):** 虽然这段代码没有直接展示编译器标志的设置，但它检测到的编译器对象后续会被用来设置编译标志，这些标志会影响生成的二进制代码，例如代码优化级别、调试信息包含与否等。理解这些编译选项对于逆向分析理解代码行为有所帮助。
* **目标架构 (Target Architecture):** 代码中根据不同的目标架构 (如 x86, ARM) 选择不同的编译器或链接器，这体现了对底层二进制代码架构的理解。例如，检测 MASM 编译器时，会根据 `info.cpu_family` 选择 `ml` 或 `ml64`。
* **Android NDK:**  虽然代码中没有直接提及 Android NDK，但如果 Frida 需要编译用于 Android 平台的 Native 代码，这个脚本需要能够检测到 NDK 中的编译器工具链。

**逻辑推理的假设输入与输出举例**

**假设输入:**

1. **环境变量中设置了 `CC=/usr/bin/gcc`，并且系统中安装了 gfortran。**
2. **执行 `detect_fortran_compiler(env, for_machine)`。**
3. **`gfortran --version` 的输出包含 "GNU Fortran (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0"。**
4. **`gfortran -E -dM -` 的输出包含 `"#define __GNUC__ 9"` 和 `"#define __GNUC_MINOR__ 4"`。**

**预期输出:**

返回一个 `fortran.GnuFortranCompiler` 类的实例，其中：

*   `compiler` 属性为 `['gfortran']`。
*   `version` 属性为 `'9.4.0'`。
*   其他属性根据环境和配置填充。

**假设输入:**

1. **系统中只安装了 clang，没有安装 gfortran。**
2. **执行 `detect_fortran_compiler(env, for_machine)`。**
3. **`clang --version` 的输出包含 "clang version 10.0.0"。**

**预期输出:**

因为代码会优先检测 gfortran，如果没有找到，则会继续检测其他 Fortran 编译器。如果 clang 的输出中没有 Fortran 相关的标识，并且系统中没有其他被支持的 Fortran 编译器，最终会抛出一个 `EnvironmentException('Unreachable code (exception to make mypy happy)')` 异常，因为之前的 `raise EnvironmentException('Could not detect Fortran compiler.')` 分支没有被触发（因为找到了 clang）。

**涉及用户或编程常见的使用错误举例**

* **编译器未安装或不在 PATH 中:**  用户如果系统中没有安装所需的编译器，或者编译器可执行文件的路径没有添加到系统的 `PATH` 环境变量中，那么 `Popen_safe_logged` 尝试执行编译器命令时会抛出 `OSError` 异常，导致编译器检测失败。例如，如果用户尝试构建 Frida 但没有安装 gfortran，`detect_fortran_compiler` 就会失败。
* **错误的编译器配置:**  用户可能在 Meson 的配置文件中错误地指定了编译器路径，例如指定了一个不存在的可执行文件，或者指定了一个错误的编译器类型的路径。这会导致脚本尝试执行错误的命令或解析错误的输出。
* **交叉编译环境配置错误:** 在进行交叉编译时，用户可能没有正确配置交叉编译工具链，例如缺少目标平台的 sysroot 或必要的库文件，这会导致编译器检测成功，但在后续的编译或链接过程中出错。

**用户操作是如何一步步的到达这里作为调试线索**

1. **用户下载 Frida 源代码:**  用户首先需要获取 Frida 的源代码。
2. **用户创建构建目录:**  通常用户会在 Frida 源代码根目录下创建一个 `build` 目录（或其他名称）用于存放构建文件。
3. **用户运行 Meson 配置命令:**  用户在构建目录下运行 `meson setup ..` (或类似的命令) 来配置构建系统。这个命令会调用 Meson 的主程序。
4. **Meson 解析 `meson.build` 文件:** Meson 会读取项目根目录下的 `meson.build` 文件，了解项目的构建需求。
5. **Meson 执行编译器检测:**  在配置阶段，Meson 需要确定项目中使用的各种编程语言的编译器。因此，Meson 会调用 `frida/releng/meson/mesonbuild/compilers/detect.py` 脚本中的相应函数，例如当项目需要编译 C 代码时，会调用 `detect_c_compiler` 函数。
6. **执行 `detect_fortran_compiler` (假设需要检测 Fortran 编译器):** 如果 `meson.build` 文件中声明了需要 Fortran 编译器，或者某个依赖项需要 Fortran 编译器，那么 `detect_fortran_compiler` 函数会被调用。
7. **脚本尝试执行 Fortran 编译器命令:**  `detect_fortran_compiler` 函数会尝试执行一些 Fortran 编译器的命令 (如 `gfortran --version`)，并捕获其输出。
8. **分析编译器输出并创建编译器对象:**  脚本会根据命令的输出内容判断编译器的类型和版本，并创建相应的编译器类实例 (例如 `GnuFortranCompiler`)。

在调试构建问题时，如果遇到与编译器相关的错误，可以检查 Meson 的配置输出，查看编译器检测的结果是否正确。也可以手动执行脚本中尝试执行的编译器命令，查看输出是否符合预期，从而定位问题。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/compilers/detect.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```python
':
                    version = _get_lcc_version_from_defines(defines)
                    cls = fortran.ElbrusFortranCompiler
                    linker = guess_nix_linker(env, compiler, cls, version, for_machine)
                    return cls(
                        compiler, version, for_machine, is_cross, info,
                        defines, full_version=full_version, linker=linker)
                else:
                    version = _get_gnu_version_from_defines(defines)
                    cls = fortran.GnuFortranCompiler
                    linker = guess_nix_linker(env, compiler, cls, version, for_machine)
                    return cls(
                        compiler, version, for_machine, is_cross, info,
                        defines, full_version=full_version, linker=linker)

            if 'Arm C/C++/Fortran Compiler' in out:
                cls = fortran.ArmLtdFlangFortranCompiler
                arm_ver_match = re.search(r'version (\d+)\.(\d+)\.?(\d+)? \(build number (\d+)\)', out)
                assert arm_ver_match is not None, 'for mypy'  # because mypy *should* be complaining that this could be None
                version = '.'.join([x for x in arm_ver_match.groups() if x is not None])
                linker = guess_nix_linker(env, compiler, cls, version, for_machine)
                return cls(
                    compiler, version, for_machine, is_cross, info,
                    linker=linker)
            if 'G95' in out:
                cls = fortran.G95FortranCompiler
                linker = guess_nix_linker(env, compiler, cls, version, for_machine)
                return cls(
                    compiler, version, for_machine, is_cross, info,
                    full_version=full_version, linker=linker)

            if 'Sun Fortran' in err:
                version = search_version(err)
                cls = fortran.SunFortranCompiler
                linker = guess_nix_linker(env, compiler, cls, version, for_machine)
                return cls(
                    compiler, version, for_machine, is_cross, info,
                    full_version=full_version, linker=linker)

            if 'Intel(R) Fortran Compiler for applications' in err:
                version = search_version(err)
                target = 'x86' if 'IA-32' in err else 'x86_64'
                cls = fortran.IntelLLVMClFortranCompiler
                env.coredata.add_lang_args(cls.language, cls, for_machine, env)
                linker = linkers.XilinkDynamicLinker(for_machine, [], version=version)
                return cls(
                    compiler, version, for_machine, is_cross, info,
                    target, linker=linker)

            if 'Intel(R) Visual Fortran' in err or 'Intel(R) Fortran' in err:
                version = search_version(err)
                target = 'x86' if 'IA-32' in err else 'x86_64'
                cls = fortran.IntelClFortranCompiler
                env.coredata.add_lang_args(cls.language, cls, for_machine, env)
                linker = linkers.XilinkDynamicLinker(for_machine, [], version=version)
                return cls(
                    compiler, version, for_machine, is_cross, info,
                    target, linker=linker)

            if 'ifort (IFORT)' in out:
                cls = fortran.IntelFortranCompiler
                linker = guess_nix_linker(env, compiler, cls, version, for_machine)
                return cls(
                    compiler, version, for_machine, is_cross, info,
                    full_version=full_version, linker=linker)

            if 'ifx (IFORT)' in out or 'ifx (IFX)' in out:
                cls = fortran.IntelLLVMFortranCompiler
                linker = guess_nix_linker(env, compiler, cls, version, for_machine)
                return cls(
                    compiler, version, for_machine, is_cross, info,
                    full_version=full_version, linker=linker)

            if 'PathScale EKOPath(tm)' in err:
                return fortran.PathScaleFortranCompiler(
                    compiler, version, for_machine, is_cross, info,
                    full_version=full_version)

            if 'PGI Compilers' in out:
                cls = fortran.PGIFortranCompiler
                env.coredata.add_lang_args(cls.language, cls, for_machine, env)
                linker = linkers.PGIDynamicLinker(compiler, for_machine,
                                                  cls.LINKER_PREFIX, [], version=version)
                return cls(
                    compiler, version, for_machine, is_cross, info,
                    full_version=full_version, linker=linker)

            if 'NVIDIA Compilers and Tools' in out:
                cls = fortran.NvidiaHPC_FortranCompiler
                env.coredata.add_lang_args(cls.language, cls, for_machine, env)
                linker = linkers.PGIDynamicLinker(compiler, for_machine,
                                                  cls.LINKER_PREFIX, [], version=version)
                return cls(
                    compiler, version, for_machine, is_cross, info,
                    full_version=full_version, linker=linker)

            if 'flang' in out or 'clang' in out:
                cls = fortran.FlangFortranCompiler
                linker = None
                if 'windows' in out or env.machines[for_machine].is_windows():
                    # If we're in a MINGW context this actually will use a gnu
                    # style ld, but for flang on "real" windows we'll use
                    # either link.exe or lld-link.exe
                    try:
                        linker = guess_win_linker(
                            env, compiler, cls, version,
                            for_machine, invoked_directly=False
                        )
                    except MesonException:
                        pass
                if linker is None:
                    linker = guess_nix_linker(env, compiler, cls,
                                              version, for_machine)
                return cls(
                    compiler, version, for_machine, is_cross, info,
                    full_version=full_version, linker=linker)

            if 'Open64 Compiler Suite' in err:
                cls = fortran.Open64FortranCompiler
                linker = guess_nix_linker(env,
                                          compiler, cls, version, for_machine)
                return cls(
                    compiler, version, for_machine, is_cross, info,
                    full_version=full_version, linker=linker)

            if 'NAG Fortran' in err:
                full_version = err.split('\n', 1)[0]
                version = full_version.split()[-1]
                cls = fortran.NAGFortranCompiler
                env.coredata.add_lang_args(cls.language, cls, for_machine, env)
                linker = linkers.NAGDynamicLinker(
                    compiler, for_machine, cls.LINKER_PREFIX, [],
                    version=version)
                return cls(
                    compiler, version, for_machine, is_cross, info,
                    full_version=full_version, linker=linker)

    _handle_exceptions(popen_exceptions, compilers)
    raise EnvironmentException('Unreachable code (exception to make mypy happy)')

def detect_objc_compiler(env: 'Environment', for_machine: MachineChoice) -> 'Compiler':
    return _detect_objc_or_objcpp_compiler(env, 'objc', for_machine)

def detect_objcpp_compiler(env: 'Environment', for_machine: MachineChoice) -> 'Compiler':
    return _detect_objc_or_objcpp_compiler(env, 'objcpp', for_machine)

def _detect_objc_or_objcpp_compiler(env: 'Environment', lang: str, for_machine: MachineChoice) -> 'Compiler':
    from . import objc, objcpp
    popen_exceptions: T.Dict[str, T.Union[Exception, str]] = {}
    compilers, ccache = _get_compilers(env, lang, for_machine)
    is_cross = env.is_cross_build(for_machine)
    info = env.machines[for_machine]
    comp: T.Union[T.Type[objc.ObjCCompiler], T.Type[objcpp.ObjCPPCompiler]]

    for compiler in compilers:
        arg = ['--version']
        try:
            p, out, err = Popen_safe_logged(compiler + arg, msg='Detecting compiler via')
        except OSError as e:
            popen_exceptions[join_args(compiler + arg)] = e
            continue
        version = search_version(out)
        if 'Free Software Foundation' in out:
            defines = _get_gnu_compiler_defines(compiler)
            if not defines:
                popen_exceptions[join_args(compiler)] = 'no pre-processor defines'
                continue
            version = _get_gnu_version_from_defines(defines)
            comp = objc.GnuObjCCompiler if lang == 'objc' else objcpp.GnuObjCPPCompiler
            linker = guess_nix_linker(env, compiler, comp, version, for_machine)
            return comp(
                ccache, compiler, version, for_machine, is_cross, info,
                defines, linker=linker)
        if 'clang' in out:
            linker = None
            defines = _get_clang_compiler_defines(compiler)
            if not defines:
                popen_exceptions[join_args(compiler)] = 'no pre-processor defines'
                continue
            if 'Apple' in out:
                comp = objc.AppleClangObjCCompiler if lang == 'objc' else objcpp.AppleClangObjCPPCompiler
            else:
                comp = objc.ClangObjCCompiler if lang == 'objc' else objcpp.ClangObjCPPCompiler
            if 'windows' in out or env.machines[for_machine].is_windows():
                # If we're in a MINGW context this actually will use a gnu style ld
                try:
                    linker = guess_win_linker(env, compiler, comp, version, for_machine)
                except MesonException:
                    pass

            if not linker:
                linker = guess_nix_linker(env, compiler, comp, version, for_machine)
            return comp(
                ccache, compiler, version, for_machine,
                is_cross, info, linker=linker, defines=defines)
    _handle_exceptions(popen_exceptions, compilers)
    raise EnvironmentException('Unreachable code (exception to make mypy happy)')

def detect_java_compiler(env: 'Environment', for_machine: MachineChoice) -> Compiler:
    from .java import JavaCompiler
    exelist = env.lookup_binary_entry(for_machine, 'java')
    info = env.machines[for_machine]
    if exelist is None:
        # TODO support fallback
        exelist = [defaults['java'][0]]

    try:
        p, out, err = Popen_safe_logged(exelist + ['-version'], msg='Detecting compiler via')
    except OSError:
        raise EnvironmentException('Could not execute Java compiler: {}'.format(join_args(exelist)))
    if 'javac' in out or 'javac' in err:
        version = search_version(err if 'javac' in err else out)
        if not version or version == 'unknown version':
            parts = (err if 'javac' in err else out).split()
            if len(parts) > 1:
                version = parts[1]
        comp_class = JavaCompiler
        env.coredata.add_lang_args(comp_class.language, comp_class, for_machine, env)
        return comp_class(exelist, version, for_machine, info)
    raise EnvironmentException('Unknown compiler: ' + join_args(exelist))

def detect_cs_compiler(env: 'Environment', for_machine: MachineChoice) -> Compiler:
    from . import cs
    compilers, ccache = _get_compilers(env, 'cs', for_machine)
    popen_exceptions = {}
    info = env.machines[for_machine]
    for comp in compilers:
        try:
            p, out, err = Popen_safe_logged(comp + ['--version'], msg='Detecting compiler via')
        except OSError as e:
            popen_exceptions[join_args(comp + ['--version'])] = e
            continue

        version = search_version(out)
        cls: T.Type[cs.CsCompiler]
        if 'Mono' in out:
            cls = cs.MonoCompiler
        elif "Visual C#" in out:
            cls = cs.VisualStudioCsCompiler
        else:
            continue
        env.coredata.add_lang_args(cls.language, cls, for_machine, env)
        return cls(comp, version, for_machine, info)

    _handle_exceptions(popen_exceptions, compilers)
    raise EnvironmentException('Unreachable code (exception to make mypy happy)')

def detect_cython_compiler(env: 'Environment', for_machine: MachineChoice) -> Compiler:
    """Search for a cython compiler."""
    from .cython import CythonCompiler
    compilers, _ = _get_compilers(env, 'cython', MachineChoice.BUILD)
    is_cross = env.is_cross_build(for_machine)
    info = env.machines[for_machine]

    popen_exceptions: T.Dict[str, Exception] = {}
    for comp in compilers:
        try:
            _, out, err = Popen_safe_logged(comp + ['-V'], msg='Detecting compiler via')
        except OSError as e:
            popen_exceptions[join_args(comp + ['-V'])] = e
            continue

        version: T.Optional[str] = None
        # 3.0
        if 'Cython' in out:
            version = search_version(out)
        # older
        elif 'Cython' in err:
            version = search_version(err)
        if version is not None:
            comp_class = CythonCompiler
            env.coredata.add_lang_args(comp_class.language, comp_class, for_machine, env)
            return comp_class([], comp, version, for_machine, info, is_cross=is_cross)
    _handle_exceptions(popen_exceptions, compilers)
    raise EnvironmentException('Unreachable code (exception to make mypy happy)')

def detect_vala_compiler(env: 'Environment', for_machine: MachineChoice) -> Compiler:
    from .vala import ValaCompiler
    exelist = env.lookup_binary_entry(for_machine, 'vala')
    is_cross = env.is_cross_build(for_machine)
    info = env.machines[for_machine]
    if exelist is None:
        # TODO support fallback
        exelist = [defaults['vala'][0]]

    try:
        p, out = Popen_safe_logged(exelist + ['--version'], msg='Detecting compiler via')[0:2]
    except OSError:
        raise EnvironmentException('Could not execute Vala compiler: {}'.format(join_args(exelist)))
    version = search_version(out)
    if 'Vala' in out:
        comp_class = ValaCompiler
        env.coredata.add_lang_args(comp_class.language, comp_class, for_machine, env)
        return comp_class(exelist, version, for_machine, is_cross, info)
    raise EnvironmentException('Unknown compiler: ' + join_args(exelist))

def detect_rust_compiler(env: 'Environment', for_machine: MachineChoice) -> RustCompiler:
    from . import rust
    from ..linkers import linkers
    popen_exceptions: T.Dict[str, Exception] = {}
    compilers, _ = _get_compilers(env, 'rust', for_machine)
    is_cross = env.is_cross_build(for_machine)
    info = env.machines[for_machine]

    cc = detect_c_compiler(env, for_machine)
    is_link_exe = isinstance(cc.linker, linkers.VisualStudioLikeLinkerMixin)
    override = env.lookup_binary_entry(for_machine, 'rust_ld')

    for compiler in compilers:
        arg = ['--version']
        try:
            out = Popen_safe_logged(compiler + arg, msg='Detecting compiler via')[1]
        except OSError as e:
            popen_exceptions[join_args(compiler + arg)] = e
            continue

        version = search_version(out)
        cls: T.Type[RustCompiler] = rust.RustCompiler

        # Clippy is a wrapper around rustc, but it doesn't have rustc in it's
        # output. We can otherwise treat it as rustc.
        if 'clippy' in out:
            # clippy returns its own version and not the rustc version by
            # default so try harder here to get the correct version.
            # Also replace the whole output with the rustc output in
            # case this is later used for other purposes.
            arg = ['--rustc', '--version']
            try:
                out = Popen_safe(compiler + arg)[1]
            except OSError as e:
                popen_exceptions[join_args(compiler + arg)] = e
                continue
            version = search_version(out)

            cls = rust.ClippyRustCompiler

        if 'rustc' in out:
            # On Linux and mac rustc will invoke gcc (clang for mac
            # presumably) and it can do this windows, for dynamic linking.
            # this means the easiest way to C compiler for dynamic linking.
            # figure out what linker to use is to just get the value of the
            # C compiler and use that as the basis of the rust linker.
            # However, there are two things we need to change, if CC is not
            # the default use that, and second add the necessary arguments
            # to rust to use -fuse-ld

            if any(a.startswith('linker=') for a in compiler):
                mlog.warning(
                    'Please do not put -C linker= in your compiler '
                    'command, set rust_ld=command in your cross file '
                    'or use the RUSTC_LD environment variable, otherwise meson '
                    'will override your selection.')

            compiler = compiler.copy()  # avoid mutating the original list

            if override is None:
                extra_args: T.Dict[str, T.Union[str, bool]] = {}
                always_args: T.List[str] = []
                if is_link_exe:
                    compiler.extend(cls.use_linker_args(cc.linker.exelist[0], ''))
                    extra_args['direct'] = True
                    extra_args['machine'] = cc.linker.machine
                else:
                    exelist = cc.linker.exelist + cc.linker.get_always_args()
                    if os.path.basename(exelist[0]) in {'ccache', 'sccache'}:
                        del exelist[0]
                    c = exelist.pop(0)
                    compiler.extend(cls.use_linker_args(c, ''))

                    # Also ensure that we pass any extra arguments to the linker
                    for l in exelist:
                        compiler.extend(['-C', f'link-arg={l}'])

                # This trickery with type() gets us the class of the linker
                # so we can initialize a new copy for the Rust Compiler
                # TODO rewrite this without type: ignore
                assert cc.linker is not None, 'for mypy'
                if is_link_exe:
                    linker = type(cc.linker)(for_machine, always_args, exelist=cc.linker.exelist,   # type: ignore
                                             version=cc.linker.version, **extra_args)               # type: ignore
                else:
                    linker = type(cc.linker)(compiler, for_machine, cc.LINKER_PREFIX,
                                             always_args=always_args, version=cc.linker.version,
                                             **extra_args)
            elif 'link' in override[0]:
                linker = guess_win_linker(env,
                                          override, cls, version, for_machine, use_linker_prefix=False)
                # rustc takes linker arguments without a prefix, and
                # inserts the correct prefix itself.
                assert isinstance(linker, linkers.VisualStudioLikeLinkerMixin)
                linker.direct = True
                compiler.extend(cls.use_linker_args(linker.exelist[0], ''))
            else:
                # On linux and macos rust will invoke the c compiler for
                # linking, on windows it will use lld-link or link.exe.
                # we will simply ask for the C compiler that corresponds to
                # it, and use that.
                cc = _detect_c_or_cpp_compiler(env, 'c', for_machine, override_compiler=override)
                linker = cc.linker

                # Of course, we're not going to use any of that, we just
                # need it to get the proper arguments to pass to rustc
                c = linker.exelist[1] if linker.exelist[0].endswith('ccache') else linker.exelist[0]
                compiler.extend(cls.use_linker_args(c, ''))

            env.coredata.add_lang_args(cls.language, cls, for_machine, env)
            return cls(
                compiler, version, for_machine, is_cross, info,
                linker=linker)

    _handle_exceptions(popen_exceptions, compilers)
    raise EnvironmentException('Unreachable code (exception to make mypy happy)')

def detect_d_compiler(env: 'Environment', for_machine: MachineChoice) -> Compiler:
    from . import c, d
    info = env.machines[for_machine]

    # Detect the target architecture, required for proper architecture handling on Windows.
    # MSVC compiler is required for correct platform detection.
    c_compiler = {'c': detect_c_compiler(env, for_machine)}
    is_msvc = isinstance(c_compiler['c'], c.VisualStudioCCompiler)
    if not is_msvc:
        c_compiler = {}

    # Import here to avoid circular imports
    from ..environment import detect_cpu_family
    arch = detect_cpu_family(c_compiler)
    if is_msvc and arch == 'x86':
        arch = 'x86_mscoff'

    popen_exceptions = {}
    is_cross = env.is_cross_build(for_machine)
    compilers, ccache = _get_compilers(env, 'd', for_machine)
    cls: T.Type[d.DCompiler]
    for exelist in compilers:
        # Search for a D compiler.
        # We prefer LDC over GDC unless overridden with the DC
        # environment variable because LDC has a much more
        # up to date language version at time (2016).
        if os.path.basename(exelist[-1]).startswith(('ldmd', 'gdmd')):
            raise EnvironmentException(
                f'Meson does not support {exelist[-1]} as it is only a DMD frontend for another compiler.'
                'Please provide a valid value for DC or unset it so that Meson can resolve the compiler by itself.')
        try:
            p, out = Popen_safe(exelist + ['--version'])[0:2]
        except OSError as e:
            popen_exceptions[join_args(exelist + ['--version'])] = e
            continue
        version = search_version(out)
        full_version = out.split('\n', 1)[0]

        if 'LLVM D compiler' in out:
            cls = d.LLVMDCompiler
            # LDC seems to require a file
            # We cannot use NamedTemporaryFile on windows, its documented
            # to not work for our uses. So, just use mkstemp and only have
            # one path for simplicity.
            o, f = tempfile.mkstemp('.d')
            os.close(o)

            try:
                if info.is_windows() or info.is_cygwin():
                    objfile = os.path.basename(f)[:-1] + 'obj'
                    linker = guess_win_linker(env,
                                              exelist,
                                              cls, full_version, for_machine,
                                              use_linker_prefix=True, invoked_directly=False,
                                              extra_args=[f])
                else:
                    # LDC writes an object file to the current working directory.
                    # Clean it up.
                    objfile = os.path.basename(f)[:-1] + 'o'
                    linker = guess_nix_linker(env,
                                              exelist, cls, full_version, for_machine,
                                              extra_args=[f])
            finally:
                windows_proof_rm(f)
                windows_proof_rm(objfile)

            return cls(
                exelist, version, for_machine, info, arch,
                full_version=full_version, linker=linker, version_output=out)
        elif 'gdc' in out:
            cls = d.GnuDCompiler
            linker = guess_nix_linker(env, exelist, cls, version, for_machine)
            return cls(
                exelist, version, for_machine, info, arch,
                is_cross=is_cross, full_version=full_version, linker=linker)
        elif 'The D Language Foundation' in out or 'Digital Mars' in out:
            cls = d.DmdDCompiler
            # DMD seems to require a file
            # We cannot use NamedTemporaryFile on windows, its documented
            # to not work for our uses. So, just use mkstemp and only have
            # one path for simplicity.
            o, f = tempfile.mkstemp('.d')
            os.close(o)

            # DMD as different detection logic for x86 and x86_64
            arch_arg = '-m64' if arch == 'x86_64' else '-m32'

            try:
                if info.is_windows() or info.is_cygwin():
                    objfile = os.path.basename(f)[:-1] + 'obj'
                    linker = guess_win_linker(env,
                                              exelist, cls, full_version, for_machine,
                                              invoked_directly=False, extra_args=[f, arch_arg])
                else:
                    objfile = os.path.basename(f)[:-1] + 'o'
                    linker = guess_nix_linker(env,
                                              exelist, cls, full_version, for_machine,
                                              extra_args=[f, arch_arg])
            finally:
                windows_proof_rm(f)
                windows_proof_rm(objfile)

            return cls(
                exelist, version, for_machine, info, arch,
                full_version=full_version, linker=linker)
        raise EnvironmentException('Unknown compiler: ' + join_args(exelist))

    _handle_exceptions(popen_exceptions, compilers)
    raise EnvironmentException('Unreachable code (exception to make mypy happy)')

def detect_swift_compiler(env: 'Environment', for_machine: MachineChoice) -> Compiler:
    from .swift import SwiftCompiler
    exelist = env.lookup_binary_entry(for_machine, 'swift')
    is_cross = env.is_cross_build(for_machine)
    info = env.machines[for_machine]
    if exelist is None:
        # TODO support fallback
        exelist = [defaults['swift'][0]]

    try:
        p, _, err = Popen_safe_logged(exelist + ['-v'], msg='Detecting compiler via')
    except OSError:
        raise EnvironmentException('Could not execute Swift compiler: {}'.format(join_args(exelist)))
    version = search_version(err)
    if 'Swift' in err:
        # As for 5.0.1 swiftc *requires* a file to check the linker:
        with tempfile.NamedTemporaryFile(suffix='.swift') as f:
            cls = SwiftCompiler

            outhandle, outfile = tempfile.mkstemp('.out')
            os.close(outhandle)

            try:
                linker = guess_nix_linker(env,
                                          exelist, cls, version, for_machine,
                                          extra_args=[f.name, '-o', outfile])
            finally:
                windows_proof_rm(outfile)
        return cls(
            exelist, version, for_machine, is_cross, info, linker=linker)

    raise EnvironmentException('Unknown compiler: ' + join_args(exelist))

def detect_nasm_compiler(env: 'Environment', for_machine: MachineChoice) -> Compiler:
    from .asm import NasmCompiler, YasmCompiler, MetrowerksAsmCompilerARM, MetrowerksAsmCompilerEmbeddedPowerPC
    compilers, _ = _get_compilers(env, 'nasm', for_machine)
    is_cross = env.is_cross_build(for_machine)

    # We need a C compiler to properly detect the machine info and linker
    cc = detect_c_compiler(env, for_machine)
    if not is_cross:
        from ..environment import detect_machine_info
        info = detect_machine_info({'c': cc})
    else:
        info = env.machines[for_machine]

    popen_exceptions: T.Dict[str, Exception] = {}
    for comp in compilers:
        if comp == ['nasm'] and is_windows() and not shutil.which(comp[0]):
            # nasm is not in PATH on Windows by default
            default_path = os.path.join(os.environ['ProgramFiles'], 'NASM')
            comp[0] = shutil.which(comp[0], path=default_path) or comp[0]
        try:
            output = Popen_safe_logged(comp + ['--version'], msg='Detecting compiler via')[1]
        except OSError as e:
            popen_exceptions[' '.join(comp + ['--version'])] = e
            continue

        version = search_version(output)
        if 'NASM' in output:
            comp_class = NasmCompiler
            env.coredata.add_lang_args(comp_class.language, comp_class, for_machine, env)
            return comp_class([], comp, version, for_machine, info, cc.linker, is_cross=is_cross)
        elif 'yasm' in output:
            comp_class = YasmCompiler
            env.coredata.add_lang_args(comp_class.language, comp_class, for_machine, env)
            return comp_class([], comp, version, for_machine, info, cc.linker, is_cross=is_cross)
        elif 'Metrowerks' in output or 'Freescale' in output:
            if 'ARM' in output:
                comp_class_mwasmarm = MetrowerksAsmCompilerARM
                env.coredata.add_lang_args(comp_class_mwasmarm.language, comp_class_mwasmarm, for_machine, env)
                return comp_class_mwasmarm([], comp, version, for_machine, info, cc.linker, is_cross=is_cross)
            else:
                comp_class_mwasmeppc = MetrowerksAsmCompilerEmbeddedPowerPC
                env.coredata.add_lang_args(comp_class_mwasmeppc.language, comp_class_mwasmeppc, for_machine, env)
                return comp_class_mwasmeppc([], comp, version, for_machine, info, cc.linker, is_cross=is_cross)

    _handle_exceptions(popen_exceptions, compilers)
    raise EnvironmentException('Unreachable code (exception to make mypy happy)')

def detect_masm_compiler(env: 'Environment', for_machine: MachineChoice) -> Compiler:
    # We need a C compiler to properly detect the machine info and linker
    is_cross = env.is_cross_build(for_machine)
    cc = detect_c_compiler(env, for_machine)
    if not is_cross:
        from ..environment import detect_machine_info
        info = detect_machine_info({'c': cc})
    else:
        info = env.machines[for_machine]

    from .asm import MasmCompiler, MasmARMCompiler
    comp_class: T.Type[Compiler]
    if info.cpu_family == 'x86':
        comp = ['ml']
        comp_class = MasmCompiler
        arg = '/?'
    elif info.cpu_family == 'x86_64':
        comp = ['ml64']
        comp_class = MasmCompiler
        arg = '/?'
    elif info.cpu_family == 'arm':
        comp = ['armasm']
        comp_class = MasmARMCompiler
        arg = '-h'
    elif info.cpu_family == 'aarch64':
        comp = ['armasm64']
        comp_class = MasmARMCompiler
        arg = '-h'
    else:
        raise EnvironmentException(f'Platform {info.cpu_family} not supported by MASM')

    popen_exceptions: T.Dict[str, Exception] = {}
    try:
        output = Popen_safe(comp + [arg])[2]
        version = search_version(output)
        env.coredata.add_lang_args(comp_class.language, comp_class, for_machine, env)
        return comp_class([], comp, version, for_machine, info, cc.linker, is_cross=is_cross)
    except OSError as e:
        popen_exceptions[' '.join(comp + [arg])] = e
    _handle_exceptions(popen_exceptions, [comp])
    raise EnvironmentException('Unreachable code (exception to make mypy happy)')

# GNU/Clang defines and version
# =============================

def _get_gnu_compiler_defines(compiler: T.List[str]) -> T.Dict[str, str]:
    """
    Detect GNU compiler platform type (Apple, MinGW, Unix)
    """
    # Arguments to output compiler pre-processor defines to stdout
    # gcc, g++, and gfortran all support these arguments
    args = compiler + ['-E', '-dM', '-']
    mlog.debug(f'Running command: {join_args(args)}')
    p, output, error = Popen_safe(args, write='', stdin=subprocess.PIPE)
    if p.returncode != 0:
        raise EnvironmentException('Unable to detect GNU compiler type:\n'
                                   f'Compiler stdout:\n{output}\n-----\n'
                                   f'Compiler stderr:\n{error}\n-----\n')
    # Parse several lines of the type:
    # `#define ___SOME_DEF some_value`
    # and extract `___SOME_DEF`
    defines: T.Dict[str, str] = {}
    for line in output.split('\n'):
        if not line:
            continue
        d, *rest = line.split(' ', 2)
        if d != '#define':
            continue
        if len(rest) == 1:
            defines[rest[0]] = ''
        if len(rest) == 2:
            defines[rest[0]] = rest[1]
    return defines

def _get_clang_compiler_defines(compiler: T.List[str]) -> T.Dict[str, str]:
    """
    Get the list of Clang pre-processor defines
    """
    args = compiler + ['-E', '-dM', '-']
    mlog.debug(f'Running command: {join_args(args)}')
    p, output, error = Popen_safe(args, write='', stdin=subprocess.PIPE)
    if p.returncode != 0:
        raise EnvironmentException('Unable to get clang pre-processor defines:\n'
                                   f'Compiler stdout:\n{output}\n-----\n'
                                   f'Compiler stderr:\n{error}\n-----\n')
    defines: T.Dict[str, str] = {}
    for line in output.split('\n'):
```
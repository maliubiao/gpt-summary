Response:
The user wants a summary of the functionality of the provided Python code. This is the second part of a two-part file. The code defines various linker classes for different compilers, inheriting from base classes `DynamicLinker` and `StaticLinker`.

**Plan:**

1. Identify the core purpose of the code: Defining linker behavior.
2. List the different linker classes defined.
3. Summarize the common functionalities provided by the base classes and implemented by the derived classes (e.g., handling output, search paths, shared libraries, etc.).
4. Check for relationships with reverse engineering, binary/OS concepts, logical inference, and common user errors as requested in the prompt.
这是 `frida` 动态 instrumentation 工具中负责处理链接器（linker）相关操作的 Python 代码。在前一部分中，定义了基础的链接器类和一些通用的方法。这部分代码继续定义了更多特定编译器的动态链接器类。

**功能归纳:**

这部分代码的主要功能是定义了一系列针对不同编译器（如 RLink, XC16, CompCert, Texas Instruments, ARM, Clang, Qualcomm LLVM, NAG Fortran, PGI, Visual Studio, Clang-cl, Xilinx, Solaris, AIX, Optlink, CUDA, Metrowerks）的动态链接器类。

这些类继承自前一部分定义的 `DynamicLinker` 基类，并根据特定编译器的链接器特性，实现了以下通用功能：

*   **指定链接器可执行文件:**  每个类都关联着特定的链接器可执行文件名（例如 `rlink.exe`, `xc16-gcc`, `link.exe` 等）。
*   **处理输出文件名:** `get_output_args` 方法定义了如何将输出文件名传递给链接器。
*   **处理库搜索路径:** `get_search_args` 方法定义了如何指定库文件的搜索路径。一些链接器不支持独立的搜索路径参数，会抛出 `OSError`。
*   **处理共享库:** `get_std_shared_lib_args` 方法定义了生成共享库所需的参数。部分链接器不支持共享库。
*   **处理 `-soname`:** `get_soname_args` 方法定义了如何设置共享库的 soname。
*   **处理 `-rpath`:** `build_rpath_args` 方法定义了如何设置运行时库的搜索路径。
*   **处理 `-l` 前缀:** `get_lib_prefix` 方法定义了链接库文件时使用的前缀。
*   **处理 `-Wl,--whole-archive`:** `get_link_whole_for` 方法定义了强制链接器包含整个静态库的参数。
*   **处理允许未定义的符号:** `get_allow_undefined_args` 方法定义了允许存在未定义符号的参数。
*   **处理响应文件:** `get_accepts_rsp` 方法指示链接器是否接受响应文件。
*   **处理调试信息:** `get_debugfile_args` 和 `get_debugfile_name` 方法定义了如何生成和命名调试文件。
*   **处理导入库:** `import_library_args` 方法定义了生成导入库的参数（通常用于 Windows）。
*   **其他特定参数:**  一些链接器类还定义了特定的参数，例如 Visual Studio 链接器的 `/MACHINE` 和 `/SUBSYSTEM` 参数。

**与逆向方法的关系及举例说明:**

*   **动态库加载和符号解析:**  链接器的主要作用之一是将程序的不同部分（包括动态库）链接在一起。逆向工程师经常需要分析程序加载的动态库以及符号的解析过程，以理解程序的行为。这些链接器类定义了构建动态库的方式，从而影响了逆向分析的对象。例如，`get_soname_args` 定义了动态库的规范名称，这在逆向分析时用于识别库文件。`build_rpath_args` 影响运行时库的查找路径，逆向工程师可能需要了解这些路径来定位依赖库。
*   **重定位信息:** 链接过程会生成重定位信息，指示代码和数据在内存中的位置。逆向工程师会分析这些信息来理解程序的内存布局。虽然这些代码没有直接操作重定位信息，但它们控制了链接器的行为，从而影响了重定位信息的生成。
*   **符号表:** 链接器会将各个目标文件中的符号合并成最终可执行文件的符号表。逆向工程师会利用符号表来理解函数和变量的名称和地址。这些链接器类控制了链接过程中符号表的生成方式。
*   **导入导出表:** 对于动态库，链接器会生成导入导出表，列出库中导出的符号以及依赖的其他库的符号。逆向工程师会分析这些表来理解库的接口和依赖关系。 `import_library_args` 方法就与生成导入库相关。

**涉及二进制底层，Linux, Android内核及框架的知识及举例说明:**

*   **二进制文件格式 (ELF/PE):** 链接器的输出是二进制可执行文件或库文件，例如 Linux 上的 ELF 文件和 Windows 上的 PE 文件。这些类中定义的操作，例如设置 soname 和 rpath，都直接影响最终二进制文件的结构和元数据。
*   **动态链接过程:**  代码涉及到动态链接的关键概念，例如 soname, rpath, 以及共享库的生成。这些都是操作系统动态链接器（例如 Linux 的 `ld.so`）在加载和链接动态库时使用的信息。
*   **Linux 系统调用:**  虽然代码本身不涉及系统调用，但链接器的输出最终会由操作系统加载和执行，这涉及到诸如 `execve`, `mmap`, `dlopen` 等系统调用。
*   **Android 框架:**  Frida 经常用于 Android 平台的动态 instrumentation。Android 依赖于 Linux 内核和其上的 Dalvik/ART 虚拟机。链接器生成的共享库在 Android 上会被虚拟机加载。`build_rpath_args` 方法在 Android 上也有意义，尽管 Android 有其特定的库搜索机制。
*   **内核加载器:**  操作系统内核的加载器负责加载可执行文件和动态库到内存中。链接器的输出必须符合内核加载器的预期格式。

**逻辑推理及假设输入与输出:**

这些代码主要是配置链接器的参数，逻辑推理主要体现在根据不同的编译器类型，选择合适的链接器参数。

**假设输入:**

*   编译器类型: `gcc`, `clang`, `link`, `nvcc` 等。
*   目标平台: `Linux`, `Windows`, `macOS`, `Android` 等。
*   要链接的目标文件列表。
*   要链接的库文件列表。
*   输出文件名。
*   库搜索路径。
*   是否生成共享库。

**假设输出:**

*   根据编译器类型和目标平台，生成相应的链接器命令行参数列表。例如，对于 `gcc` 生成共享库，可能会输出 `['-shared', '-o', 'libxxx.so']`。对于 `link.exe` 生成 DLL，可能会输出 `['/DLL', '/OUT:xxx.dll']`。

**涉及用户或者编程常见的使用错误及举例说明:**

*   **库文件路径错误:** 用户在构建项目时，可能会指定错误的库文件路径，导致链接器找不到库文件。这些链接器类中的 `get_search_args` 方法用于配置库搜索路径，如果配置不当，就会出现链接错误。例如，如果用户忘记设置 `LIBPATH` 环境变量或 Meson 项目中未正确设置库搜索路径，链接器可能会报错。
*   **链接器参数错误:** 用户或构建系统可能会传递错误的链接器参数。例如，对于不支持共享库的编译器，尝试生成共享库会导致链接错误。代码中针对不同链接器实现了特定的参数处理，可以避免一些常见的参数错误，但用户仍然可能传递一些无效的参数。
*   **库依赖问题:**  链接共享库时，可能会出现循环依赖或者找不到依赖库的情况。虽然这些代码本身不解决依赖问题，但它们定义了链接过程，依赖问题最终会在链接阶段暴露出来。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户使用 Frida 进行动态 instrumentation:** 用户想要使用 Frida hook 目标进程或应用的函数。
2. **Frida 需要编译一些代码:**  Frida 的某些功能可能需要编译 C/C++ 代码，例如 Gadget 或自定义的 Agent。
3. **Meson 构建系统被调用:** Frida 使用 Meson 作为其构建系统。当需要编译代码时，Meson 会被调用。
4. **Meson 检测到需要链接:**  编译过程完成后，需要将目标文件链接成最终的可执行文件或共享库。
5. **Meson 选择合适的链接器:** Meson 根据配置和编译器类型，选择合适的链接器类。这个文件 `linkers.py` 就包含了这些链接器类的定义。
6. **Meson 调用链接器类的方法:** Meson 会调用所选链接器类的方法，例如 `get_output_args`, `get_search_args`, `get_std_shared_lib_args` 等，来生成链接器命令。
7. **链接器被执行:**  Meson 最终会执行生成的链接器命令。

作为调试线索，如果用户在 Frida 的使用过程中遇到链接错误，可以检查以下内容：

*   **Meson 的配置:**  确认 Meson 的配置文件中指定的编译器和链接器是否正确。
*   **库文件路径:**  确认所需的库文件路径是否正确设置。
*   **链接器参数:**  查看 Meson 生成的链接器命令，确认参数是否符合预期。
*   **编译器版本:** 某些链接器特性可能依赖于特定的编译器版本。

**归纳一下它的功能 (针对第2部分):**

这部分代码扩展了 `frida` 构建系统中链接器的支持，为更多特定的编译器定义了动态链接器类，这些类封装了与特定链接器交互所需的命令和参数，使得 `frida` 的构建过程能够适配不同的编译环境。它详细描述了各种链接器在处理输出、搜索路径、共享库、调试信息等方面的具体行为，是 `frida` 构建系统能够正确生成可执行文件和共享库的关键组成部分。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/linkers/linkers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
hineChoice,
                 *, version: str = 'unknown version'):
        super().__init__(['rlink.exe'], for_machine, '', [],
                         version=version)

    def get_accepts_rsp(self) -> bool:
        return False

    def get_lib_prefix(self) -> str:
        return '-lib='

    def get_std_shared_lib_args(self) -> T.List[str]:
        return []

    def get_output_args(self, outputname: str) -> T.List[str]:
        return [f'-output={outputname}']

    def get_search_args(self, dirname: str) -> 'T.NoReturn':
        raise OSError('rlink.exe does not have a search dir argument')

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        return []


class Xc16DynamicLinker(DynamicLinker):

    """Linker for Microchip XC16 compiler."""

    id = 'xc16-gcc'

    def __init__(self, for_machine: mesonlib.MachineChoice,
                 *, version: str = 'unknown version'):
        super().__init__(['xc16-gcc'], for_machine, '', [],
                         version=version)

    def get_link_whole_for(self, args: T.List[str]) -> T.List[str]:
        if len(args) < 2:
            return args
        return self._apply_prefix('--start-group') + args + self._apply_prefix('--end-group')

    def get_accepts_rsp(self) -> bool:
        return False

    def get_lib_prefix(self) -> str:
        return ''

    def get_std_shared_lib_args(self) -> T.List[str]:
        return []

    def get_output_args(self, outputname: str) -> T.List[str]:
        return [f'-o{outputname}']

    def get_search_args(self, dirname: str) -> 'T.NoReturn':
        raise OSError('xc16-gcc does not have a search dir argument')

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        return []

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        return ([], set())

class CompCertDynamicLinker(DynamicLinker):

    """Linker for CompCert C compiler."""

    id = 'ccomp'

    def __init__(self, for_machine: mesonlib.MachineChoice,
                 *, version: str = 'unknown version'):
        super().__init__(['ccomp'], for_machine, '', [],
                         version=version)

    def get_link_whole_for(self, args: T.List[str]) -> T.List[str]:
        if not args:
            return args
        return self._apply_prefix('-Wl,--whole-archive') + args + self._apply_prefix('-Wl,--no-whole-archive')

    def get_accepts_rsp(self) -> bool:
        return False

    def get_lib_prefix(self) -> str:
        return ''

    def get_std_shared_lib_args(self) -> T.List[str]:
        return []

    def get_output_args(self, outputname: str) -> T.List[str]:
        return [f'-o{outputname}']

    def get_search_args(self, dirname: str) -> T.List[str]:
        return [f'-L{dirname}']

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        raise MesonException(f'{self.id} does not support shared libraries.')

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        return ([], set())

class TIDynamicLinker(DynamicLinker):

    """Linker for Texas Instruments compiler family."""

    id = 'ti'

    def __init__(self, exelist: T.List[str], for_machine: mesonlib.MachineChoice,
                 *, version: str = 'unknown version'):
        super().__init__(exelist, for_machine, '', [],
                         version=version)

    def get_link_whole_for(self, args: T.List[str]) -> T.List[str]:
        if len(args) < 2:
            return args
        return self._apply_prefix('--start-group') + args + self._apply_prefix('--end-group')

    def get_accepts_rsp(self) -> bool:
        return False

    def get_lib_prefix(self) -> str:
        return '-l='

    def get_std_shared_lib_args(self) -> T.List[str]:
        return []

    def get_output_args(self, outputname: str) -> T.List[str]:
        return ['-z', f'--output_file={outputname}']

    def get_search_args(self, dirname: str) -> 'T.NoReturn':
        raise OSError('TI compilers do not have a search dir argument')

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_always_args(self) -> T.List[str]:
        return []


class C2000DynamicLinker(TIDynamicLinker):
    # Required for backwards compat with projects created before ti-cgt support existed
    id = 'cl2000'

class C6000DynamicLinker(TIDynamicLinker):
    id = 'cl6000'


class ArmDynamicLinker(PosixDynamicLinkerMixin, DynamicLinker):

    """Linker for the ARM compiler."""

    id = 'armlink'

    def __init__(self, for_machine: mesonlib.MachineChoice,
                 *, version: str = 'unknown version'):
        super().__init__(['armlink'], for_machine, '', [],
                         version=version)

    def get_accepts_rsp(self) -> bool:
        return False

    def get_std_shared_lib_args(self) -> 'T.NoReturn':
        raise MesonException('The Arm Linkers do not support shared libraries')

    def get_allow_undefined_args(self) -> T.List[str]:
        return []


class ArmClangDynamicLinker(ArmDynamicLinker):

    """Linker used with ARM's clang fork.

    The interface is similar enough to the old ARM ld that it inherits and
    extends a few things as needed.
    """

    def export_dynamic_args(self, env: 'Environment') -> T.List[str]:
        return ['--export_dynamic']

    def import_library_args(self, implibname: str) -> T.List[str]:
        return ['--symdefs=' + implibname]

class QualcommLLVMDynamicLinker(LLVMDynamicLinker):

    """ARM Linker from Snapdragon LLVM ARM Compiler."""

    id = 'ld.qcld'


class NAGDynamicLinker(PosixDynamicLinkerMixin, DynamicLinker):

    """NAG Fortran linker, ld via gcc indirection.

    Using nagfor -Wl,foo passes option foo to a backend gcc invocation.
    (This linking gathers the correct objects needed from the nagfor runtime
    system.)
    To pass gcc -Wl,foo options (i.e., to ld) one must apply indirection
    again: nagfor -Wl,-Wl,,foo
    """

    id = 'nag'

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        if not rpath_paths and not install_rpath and not build_rpath:
            return ([], set())
        args: T.List[str] = []
        origin_placeholder = '$ORIGIN'
        processed_rpaths = prepare_rpaths(rpath_paths, build_dir, from_dir)
        all_paths = mesonlib.OrderedSet([os.path.join(origin_placeholder, p) for p in processed_rpaths])
        if build_rpath != '':
            all_paths.add(build_rpath)
        for rp in all_paths:
            args.extend(self._apply_prefix('-Wl,-Wl,,-rpath,,' + rp))

        return (args, set())

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_std_shared_lib_args(self) -> T.List[str]:
        from ..compilers.fortran import NAGFortranCompiler
        return NAGFortranCompiler.get_nagfor_quiet(self.version) + ['-Wl,-shared']


class PGIDynamicLinker(PosixDynamicLinkerMixin, DynamicLinker):

    """PGI linker."""

    id = 'pgi'

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        return []

    def get_std_shared_lib_args(self) -> T.List[str]:
        # PGI -shared is Linux only.
        if mesonlib.is_windows():
            return ['-Bdynamic', '-Mmakedll']
        elif mesonlib.is_linux():
            return ['-shared']
        return []

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        if not env.machines[self.for_machine].is_windows():
            return (['-R' + os.path.join(build_dir, p) for p in rpath_paths], set())
        return ([], set())

NvidiaHPC_DynamicLinker = PGIDynamicLinker


class PGIStaticLinker(StaticLinker):
    def __init__(self, exelist: T.List[str]):
        super().__init__(exelist)
        self.id = 'ar'
        self.std_args = ['-r']

    def get_std_link_args(self, env: 'Environment', is_thin: bool) -> T.List[str]:
        return self.std_args

    def get_output_args(self, target: str) -> T.List[str]:
        return [target]

NvidiaHPC_StaticLinker = PGIStaticLinker


class VisualStudioLikeLinkerMixin(DynamicLinkerBase):

    """Mixin class for dynamic linkers that act like Microsoft's link.exe."""

    if T.TYPE_CHECKING:
        for_machine = MachineChoice.HOST
        def _apply_prefix(self, arg: T.Union[str, T.List[str]]) -> T.List[str]: ...

    _OPTIMIZATION_ARGS: T.Dict[str, T.List[str]] = {
        'plain': [],
        '0': [],
        'g': [],
        '1': [],
        '2': [],
        # The otherwise implicit REF and ICF linker optimisations are disabled by
        # /DEBUG. REF implies ICF.
        '3': ['/OPT:REF'],
        's': ['/INCREMENTAL:NO', '/OPT:REF'],
    }

    def __init__(self, exelist: T.List[str], for_machine: mesonlib.MachineChoice,
                 prefix_arg: T.Union[str, T.List[str]], always_args: T.List[str], *,
                 version: str = 'unknown version', direct: bool = True, machine: str = 'x86'):
        # There's no way I can find to make mypy understand what's going on here
        super().__init__(exelist, for_machine, prefix_arg, always_args, version=version)
        self.machine = machine
        self.direct = direct

    def invoked_by_compiler(self) -> bool:
        return not self.direct

    def get_output_args(self, outputname: str) -> T.List[str]:
        return self._apply_prefix(['/MACHINE:' + self.machine, '/OUT:' + outputname])

    def get_always_args(self) -> T.List[str]:
        parent = super().get_always_args()
        return self._apply_prefix('/nologo') + parent

    def get_search_args(self, dirname: str) -> T.List[str]:
        return self._apply_prefix('/LIBPATH:' + dirname)

    def get_std_shared_lib_args(self) -> T.List[str]:
        return self._apply_prefix('/DLL')

    def get_debugfile_name(self, targetfile: str) -> str:
        return targetfile

    def get_debugfile_args(self, targetfile: str) -> T.List[str]:
        return self._apply_prefix(['/DEBUG', '/PDB:' + self.get_debugfile_name(targetfile)])

    def get_link_whole_for(self, args: T.List[str]) -> T.List[str]:
        # Only since VS2015
        args = mesonlib.listify(args)
        l: T.List[str] = []
        for a in args:
            l.extend(self._apply_prefix('/WHOLEARCHIVE:' + a))
        return l

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        return []

    def import_library_args(self, implibname: str) -> T.List[str]:
        """The command to generate the import library."""
        return self._apply_prefix(['/IMPLIB:' + implibname])

    def rsp_file_syntax(self) -> RSPFileSyntax:
        return RSPFileSyntax.MSVC


class MSVCDynamicLinker(VisualStudioLikeLinkerMixin, DynamicLinker):

    """Microsoft's Link.exe."""

    id = 'link'

    def __init__(self, for_machine: mesonlib.MachineChoice, always_args: T.List[str], *,
                 exelist: T.Optional[T.List[str]] = None,
                 prefix: T.Union[str, T.List[str]] = '',
                 machine: str = 'x86', version: str = 'unknown version',
                 direct: bool = True):
        super().__init__(exelist or ['link.exe'], for_machine,
                         prefix, always_args, machine=machine, version=version, direct=direct)

    def get_always_args(self) -> T.List[str]:
        return self._apply_prefix(['/release']) + super().get_always_args()

    def get_win_subsystem_args(self, value: str) -> T.List[str]:
        return self._apply_prefix([f'/SUBSYSTEM:{value.upper()}'])


class ClangClDynamicLinker(VisualStudioLikeLinkerMixin, DynamicLinker):

    """Clang's lld-link.exe."""

    id = 'lld-link'

    def __init__(self, for_machine: mesonlib.MachineChoice, always_args: T.List[str], *,
                 exelist: T.Optional[T.List[str]] = None,
                 prefix: T.Union[str, T.List[str]] = '',
                 machine: str = 'x86', version: str = 'unknown version',
                 direct: bool = True):
        super().__init__(exelist or ['lld-link.exe'], for_machine,
                         prefix, always_args, machine=machine, version=version, direct=direct)

    def get_output_args(self, outputname: str) -> T.List[str]:
        # If we're being driven indirectly by clang just skip /MACHINE
        # as clang's target triple will handle the machine selection
        if self.machine is None:
            return self._apply_prefix([f"/OUT:{outputname}"])

        return super().get_output_args(outputname)

    def get_win_subsystem_args(self, value: str) -> T.List[str]:
        return self._apply_prefix([f'/SUBSYSTEM:{value.upper()}'])

    def get_thinlto_cache_args(self, path: str) -> T.List[str]:
        return ["/lldltocache:" + path]


class XilinkDynamicLinker(VisualStudioLikeLinkerMixin, DynamicLinker):

    """Intel's Xilink.exe."""

    id = 'xilink'

    def __init__(self, for_machine: mesonlib.MachineChoice, always_args: T.List[str], *,
                 exelist: T.Optional[T.List[str]] = None,
                 prefix: T.Union[str, T.List[str]] = '',
                 machine: str = 'x86', version: str = 'unknown version',
                 direct: bool = True):
        super().__init__(['xilink.exe'], for_machine, '', always_args, version=version)

    def get_win_subsystem_args(self, value: str) -> T.List[str]:
        return self._apply_prefix([f'/SUBSYSTEM:{value.upper()}'])


class SolarisDynamicLinker(PosixDynamicLinkerMixin, DynamicLinker):

    """Sys-V derived linker used on Solaris and OpenSolaris."""

    id = 'ld.solaris'

    def get_link_whole_for(self, args: T.List[str]) -> T.List[str]:
        if not args:
            return args
        return self._apply_prefix('--whole-archive') + args + self._apply_prefix('--no-whole-archive')

    def get_pie_args(self) -> T.List[str]:
        # Available in Solaris 11.2 and later
        pc, stdo, stde = mesonlib.Popen_safe(self.exelist + self._apply_prefix('-zhelp'))
        for line in (stdo + stde).split('\n'):
            if '-z type' in line:
                if 'pie' in line:
                    return ['-z', 'type=pie']
                break
        return []

    def get_asneeded_args(self) -> T.List[str]:
        return self._apply_prefix(['-z', 'ignore'])

    def no_undefined_args(self) -> T.List[str]:
        return ['-z', 'defs']

    def get_allow_undefined_args(self) -> T.List[str]:
        return ['-z', 'nodefs']

    def fatal_warnings(self) -> T.List[str]:
        return ['-z', 'fatal-warnings']

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        if not rpath_paths and not install_rpath and not build_rpath:
            return ([], set())
        processed_rpaths = prepare_rpaths(rpath_paths, build_dir, from_dir)
        all_paths = mesonlib.OrderedSet([os.path.join('$ORIGIN', p) for p in processed_rpaths])
        rpath_dirs_to_remove: T.Set[bytes] = set()
        for p in all_paths:
            rpath_dirs_to_remove.add(p.encode('utf8'))
        if build_rpath != '':
            all_paths.add(build_rpath)
            for p in build_rpath.split(':'):
                rpath_dirs_to_remove.add(p.encode('utf8'))

        # In order to avoid relinking for RPATH removal, the binary needs to contain just
        # enough space in the ELF header to hold the final installation RPATH.
        paths = ':'.join(all_paths)
        if len(paths) < len(install_rpath):
            padding = 'X' * (len(install_rpath) - len(paths))
            if not paths:
                paths = padding
            else:
                paths = paths + ':' + padding
        return (self._apply_prefix(f'-rpath,{paths}'), rpath_dirs_to_remove)

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        sostr = '' if soversion is None else '.' + soversion
        return self._apply_prefix(f'-soname,{prefix}{shlib_name}.{suffix}{sostr}')


class AIXDynamicLinker(PosixDynamicLinkerMixin, DynamicLinker):

    """Sys-V derived linker used on AIX"""

    id = 'ld.aix'

    def get_always_args(self) -> T.List[str]:
        return self._apply_prefix(['-bnoipath', '-bbigtoc']) + super().get_always_args()

    def no_undefined_args(self) -> T.List[str]:
        return self._apply_prefix(['-bernotok'])

    def get_allow_undefined_args(self) -> T.List[str]:
        return self._apply_prefix(['-berok'])

    def get_archive_name(self, filename: str) -> str:
        # In AIX we allow the shared library name to have the lt_version and so_version.
        # But the archive name must just be .a .
        # For Example shared object can have the name libgio.so.0.7200.1 but the archive
        # must have the name libgio.a having libgio.a (libgio.so.0.7200.1) in the
        # archive. This regular expression is to do the same.
        filename = re.sub('[.][a]([.]?([0-9]+))*([.]?([a-z]+))*', '.a', filename.replace('.so', '.a'))
        return filename

    def get_command_to_archive_shlib(self) -> T.List[str]:
        # Archive shared library object and remove the shared library object,
        # since it already exists in the archive.
        command = ['ar', '-q', '-v', '$out', '$in', '&&', 'rm', '-f', '$in']
        return command

    def get_link_whole_for(self, args: T.List[str]) -> T.List[str]:
        # AIX's linker always links the whole archive: "The ld command
        # processes all input files in the same manner, whether they are
        # archives or not."
        return args

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        all_paths: mesonlib.OrderedSet[str] = mesonlib.OrderedSet()
        # install_rpath first, followed by other paths, and the system path last
        if install_rpath != '':
            all_paths.add(install_rpath)
        if build_rpath != '':
            all_paths.add(build_rpath)
        for p in rpath_paths:
            all_paths.add(os.path.join(build_dir, p))
        # We should consider allowing the $LIBPATH environment variable
        # to override sys_path.
        sys_path = env.get_compiler_system_lib_dirs(self.for_machine)
        if len(sys_path) == 0:
            # get_compiler_system_lib_dirs doesn't support our compiler.
            # Use the default system library path
            all_paths.update(['/usr/lib', '/lib'])
        else:
            # Include the compiler's default library paths, but filter out paths that don't exist
            for p in sys_path:
                if os.path.isdir(p):
                    all_paths.add(p)
        return (self._apply_prefix('-blibpath:' + ':'.join(all_paths)), set())

    def thread_flags(self, env: 'Environment') -> T.List[str]:
        return ['-pthread']


class OptlinkDynamicLinker(VisualStudioLikeLinkerMixin, DynamicLinker):

    """Digital Mars dynamic linker for windows."""

    id = 'optlink'

    def __init__(self, exelist: T.List[str], for_machine: mesonlib.MachineChoice,
                 *, version: str = 'unknown version'):
        # Use optlink instead of link so we don't interfere with other link.exe
        # implementations.
        super().__init__(exelist, for_machine, '', [], version=version)

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_debugfile_args(self, targetfile: str) -> T.List[str]:
        # Optlink does not generate pdb files.
        return []

    def get_always_args(self) -> T.List[str]:
        return []


class CudaLinker(PosixDynamicLinkerMixin, DynamicLinker):
    """Cuda linker (nvlink)"""

    id = 'nvlink'

    @staticmethod
    def parse_version() -> str:
        version_cmd = ['nvlink', '--version']
        try:
            _, out, _ = mesonlib.Popen_safe(version_cmd)
        except OSError:
            return 'unknown version'
        # Output example:
        # nvlink: NVIDIA (R) Cuda linker
        # Copyright (c) 2005-2018 NVIDIA Corporation
        # Built on Sun_Sep_30_21:09:22_CDT_2018
        # Cuda compilation tools, release 10.0, V10.0.166
        # we need the most verbose version output. Luckily starting with V
        return out.strip().rsplit('V', maxsplit=1)[-1]

    def get_accepts_rsp(self) -> bool:
        # nvcc does not support response files
        return False

    def get_lib_prefix(self) -> str:
        # nvcc doesn't recognize Meson's default .a extension for static libraries on
        # Windows and passes it to cl as an object file, resulting in 'warning D9024 :
        # unrecognized source file type 'xxx.a', object file assumed'.
        #
        # nvcc's --library= option doesn't help: it takes the library name without the
        # extension and assumes that the extension on Windows is .lib; prefixing the
        # library with -Xlinker= seems to work.
        #
        # On Linux, we have to use rely on -Xlinker= too, since nvcc/nvlink chokes on
        # versioned shared libraries:
        #
        #   nvcc fatal : Don't know what to do with 'subprojects/foo/libbar.so.0.1.2'
        #
        from ..compilers.cuda import CudaCompiler
        return CudaCompiler.LINKER_PREFIX

    def fatal_warnings(self) -> T.List[str]:
        return ['--warning-as-error']

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        return []


class MetrowerksLinker(DynamicLinker):

    def __init__(self, exelist: T.List[str], for_machine: mesonlib.MachineChoice,
                 *, version: str = 'unknown version'):
        super().__init__(exelist, for_machine, '', [],
                         version=version)

    def fatal_warnings(self) -> T.List[str]:
        return ['-w', 'error']

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_accepts_rsp(self) -> bool:
        return True

    def get_lib_prefix(self) -> str:
        return ""

    def get_linker_always_args(self) -> T.List[str]:
        return []

    def get_output_args(self, outputname: str) -> T.List[str]:
        return ['-o', outputname]

    def get_search_args(self, dirname: str) -> T.List[str]:
        return self._apply_prefix('-L' + dirname)

    def invoked_by_compiler(self) -> bool:
        return False

    def rsp_file_syntax(self) -> RSPFileSyntax:
        return RSPFileSyntax.GCC


class MetrowerksLinkerARM(MetrowerksLinker):
    id = 'mwldarm'


class MetrowerksLinkerEmbeddedPowerPC(MetrowerksLinker):
    id = 'mwldeppc'
```